//! #199: the Cloudflare stand-in. An in-process relay plays the edge: it
//! terminates the OUTER TLS with its own certificate, records the outer
//! plaintext both ways (the HTTP upgrade and the WebSocket frames), and
//! forwards to kharond's public-ingress listener. The claim under test is
//! that the edge sees only inner-TLS ciphertext: neither the tunnel
//! token, nor the credential being filled, nor the canary appears in what
//! the edge sees, and an edge that tampers or impersonates the broker
//! cannot get a session.

mod api_support;
mod connector_support;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use connector_support::*;
use kharon_connector::{ClientError, Transport as Dial, WsByteStream, run_agent_once};
use kharond::api::token::TUNNEL_PREFIX;
use kharond::cdp::FillOutcome;
use kharond::connector::{AgentParams, Hub};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};

/// The outer plaintext, both ways, as the relay saw it.
#[derive(Clone, Default)]
struct Recording {
    /// Client to relay.
    c2s: Arc<Mutex<Vec<u8>>>,
    /// Relay to client.
    s2c: Arc<Mutex<Vec<u8>>>,
    /// When each chunk crossed the relay, either way.
    ticks: Arc<Mutex<Vec<Instant>>>,
}

/// Wraps the outer TLS stream: everything read from or written to it is
/// the outer plaintext, before any WebSocket decoding.
struct Rec<S> {
    inner: S,
    rec: Recording,
}

impl<S: AsyncRead + Unpin> AsyncRead for Rec<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let got = &buf.filled()[before..];
            if !got.is_empty() {
                self.rec.c2s.lock().unwrap().extend_from_slice(got);
                self.rec.ticks.lock().unwrap().push(Instant::now());
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rec<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.rec.s2c.lock().unwrap().extend_from_slice(&buf[..*n]);
            self.rec.ticks.lock().unwrap().push(Instant::now());
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum Mode {
    /// Forward bytes to kharond. With `tamper`, the first client frame
    /// sent after `armed` has a ciphertext byte flipped.
    Forward { upstream: SocketAddr, tamper: bool },
    /// Decode the WebSocket and terminate the INNER TLS with this config.
    TerminateInner(Arc<rustls::ServerConfig>),
}

struct Relay {
    addr: SocketAddr,
    roots: Arc<rustls::RootCertStore>,
    rec: Recording,
    /// Bytes the relay decrypted from an inner TLS it terminated itself.
    decrypted: Arc<Mutex<Vec<u8>>>,
    armed: Arc<AtomicBool>,
    flipped: Arc<AtomicBool>,
}

impl Relay {
    async fn start(mode: Mode) -> Relay {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = Relay {
            addr: listener.local_addr().unwrap(),
            roots: Arc::new(roots),
            rec: Recording::default(),
            decrypted: Arc::default(),
            armed: Arc::default(),
            flipped: Arc::default(),
        };
        let mode = Arc::new(mode);
        let (rec, decrypted) = (relay.rec.clone(), Arc::clone(&relay.decrypted));
        let (armed, flipped) = (Arc::clone(&relay.armed), Arc::clone(&relay.flipped));
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let (acceptor, mode, rec) = (acceptor.clone(), Arc::clone(&mode), rec.clone());
                let (decrypted, armed, flipped) = (
                    Arc::clone(&decrypted),
                    Arc::clone(&armed),
                    Arc::clone(&flipped),
                );
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let outer = Rec { inner: tls, rec };
                    match &*mode {
                        Mode::Forward { upstream, tamper } => {
                            forward(outer, *upstream, *tamper, &armed, &flipped).await
                        }
                        Mode::TerminateInner(cfg) => {
                            terminate_inner(outer, Arc::clone(cfg), &decrypted).await
                        }
                    }
                });
            }
        });
        relay
    }

    /// Dial parameters that reach `rig` through this relay.
    fn dial(&self, rig: &Rig) -> AgentParams {
        AgentParams {
            transport: Dial::Ws {
                host: "127.0.0.1".into(),
                port: self.addr.port(),
                path: "/connector".into(),
                outer_tls: true,
            },
            outer_roots: Some(Arc::clone(&self.roots)),
            ..ws_dial(rig, &rig.token)
        }
    }
}

async fn forward(
    outer: Rec<tokio_rustls::server::TlsStream<TcpStream>>,
    upstream: SocketAddr,
    tamper: bool,
    armed: &AtomicBool,
    flipped: &AtomicBool,
) {
    let Ok(up) = TcpStream::connect(upstream).await else {
        return;
    };
    let (mut cr, mut cw) = tokio::io::split(outer);
    let (mut ur, mut uw) = up.into_split();
    let c2s = async {
        if tamper {
            tamper_c2s(&mut cr, &mut uw, armed, flipped).await
        } else {
            let _ = tokio::io::copy(&mut cr, &mut uw).await;
        }
    };
    let s2c = async {
        let _ = tokio::io::copy(&mut ur, &mut cw).await;
    };
    tokio::select! { () = c2s => {}, () = s2c => {} }
}

/// `(total length, payload length)` of the first complete frame in `buf`.
fn frame_len(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let mask = if buf[1] & 0x80 != 0 { 4 } else { 0 };
    let (hdr, plen) = match buf[1] & 0x7f {
        126 if buf.len() >= 4 => (4, usize::from(u16::from_be_bytes([buf[2], buf[3]]))),
        127 if buf.len() >= 10 => (
            10,
            u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize,
        ),
        126 | 127 => return None,
        n => (2, usize::from(n)),
    };
    let total = hdr + mask + plen;
    (buf.len() >= total).then_some((total, plen))
}

/// Forward the client's bytes frame by frame. Once `armed`, flip the last
/// byte of the first payload that can hold a TLS record: inside the
/// ciphertext (the AEAD tag), not in a frame header or the mask key.
async fn tamper_c2s<R, W>(r: &mut R, w: &mut W, armed: &AtomicBool, flipped: &AtomicBool)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::new();
    let mut head_done = false;
    let mut chunk = [0u8; 8192];
    loop {
        let Ok(n) = r.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if !head_done {
            let Some(i) = buf.windows(4).position(|x| x == b"\r\n\r\n") else {
                continue;
            };
            if w.write_all(&buf[..i + 4]).await.is_err() {
                return;
            }
            buf.drain(..i + 4);
            head_done = true;
        }
        while let Some((total, plen)) = frame_len(&buf) {
            let binary = buf[0] & 0x0f == 2;
            if binary
                && plen >= 22
                && armed.load(Ordering::SeqCst)
                && !flipped.load(Ordering::SeqCst)
            {
                buf[total - 1] ^= 0x01;
                flipped.store(true, Ordering::SeqCst);
            }
            if w.write_all(&buf[..total]).await.is_err() {
                return;
            }
            buf.drain(..total);
        }
    }
}

/// The impersonating edge: accept the upgrade itself, then try to be the
/// broker for the inner TLS with its own key.
async fn terminate_inner(
    outer: Rec<tokio_rustls::server::TlsStream<TcpStream>>,
    cfg: Arc<rustls::ServerConfig>,
    decrypted: &Mutex<Vec<u8>>,
) {
    #[allow(clippy::result_large_err)]
    fn echo(_: &Request, mut resp: Response) -> Result<Response, ErrorResponse> {
        resp.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            "kharon-connector.v1".parse().unwrap(),
        );
        Ok(resp)
    }
    let Ok(ws) = tokio_tungstenite::accept_hdr_async_with_config(
        outer,
        echo,
        Some(kharon_connector::ws_config()),
    )
    .await
    else {
        return;
    };
    let Ok(mut tls) = TlsAcceptor::from(cfg).accept(WsByteStream::new(ws)).await else {
        return;
    };
    // Should the client ever go on, keep whatever it would have said.
    let mut buf = [0u8; 4096];
    if let Ok(n) = tls.read(&mut buf).await {
        decrypted.lock().unwrap().extend_from_slice(&buf[..n]);
    }
}

/// The HTTP head and the payloads of the WebSocket frames in one
/// direction's recorded bytes (a passive second parse).
fn parse_stream(bytes: &[u8]) -> (String, Vec<Vec<u8>>) {
    let i = bytes
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .expect("no HTTP head in the recording");
    let head = String::from_utf8_lossy(&bytes[..i + 4]).into_owned();
    let mut rest = &bytes[i + 4..];
    let mut payloads = Vec::new();
    while let Some((total, plen)) = frame_len(rest) {
        let masked = rest[1] & 0x80 != 0;
        let mut p = rest[total - plen..total].to_vec();
        if masked {
            let key = &rest[total - plen - 4..total - plen];
            for (j, b) in p.iter_mut().enumerate() {
                *b ^= key[j % 4];
            }
        }
        if matches!(rest[0] & 0x0f, 0..=2) {
            payloads.push(p);
        }
        rest = &rest[total..];
    }
    (head, payloads)
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

async fn try_fill(hub: &Arc<Hub>) -> Result<FillOutcome, &'static str> {
    use kharond::cdp::{Browser, CdpClient, CdpDial, CdpEndpoint, FillEngine, Tunnel};
    let endpoint =
        CdpEndpoint::validate("ws://127.0.0.1:9222", Tunnel::AgentConnector, None).unwrap();
    let dial = CdpDial::Connector {
        hub: Arc::clone(hub),
        agent_id: "assistant".into(),
    };
    let client = CdpClient::connect_via(&endpoint, &dial)
        .await
        .map_err(|_| "connect")?;
    let browser = Browser::new(client);
    let ctx = browser
        .create_agent_context("assistant")
        .await
        .map_err(|_| "context")?;
    Ok(FillEngine::new(browser).fill(&plan(), &ctx, false).await)
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_sees_neither_canary_nor_credential() {
    let rig = rig().await;
    let relay = Relay::start(Mode::Forward {
        upstream: rig.public,
        tamper: false,
    })
    .await;
    let params = relay.dial(&rig);
    let agent = tokio::spawn(async move { run_agent_once(&params).await });
    eventually("attach through the relay", || {
        rig.hub.is_connected("assistant")
    })
    .await;

    let outcome = fill_once(&rig.hub).await;
    assert_eq!(outcome.status(), "filled", "{outcome:?}");
    assert!(
        rig.received
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.to_string().contains(CANARY)),
        "the canary never reached the CDP stub, so the search below would be vacuous"
    );
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;

    let c2s = relay.rec.c2s.lock().unwrap().clone();
    let s2c = relay.rec.s2c.lock().unwrap().clone();
    let (c2s_head, c2s_msgs) = parse_stream(&c2s);
    let (s2c_head, s2c_msgs) = parse_stream(&s2c);

    // Non-vacuous: the relay saw the upgrade in the clear, and real traffic.
    assert!(
        c2s_head
            .to_ascii_lowercase()
            .contains("sec-websocket-protocol: kharon-connector.v1"),
        "{c2s_head}"
    );
    assert!(
        c2s_head.starts_with("GET /connector HTTP/1.1"),
        "{c2s_head}"
    );
    assert!(s2c_head.starts_with("HTTP/1.1 101"), "{s2c_head}");
    let payload_bytes: usize = c2s_msgs.iter().chain(&s2c_msgs).map(Vec::len).sum();
    assert!(
        c2s_msgs.len() >= 3 && s2c_msgs.len() >= 3 && payload_bytes > 2000,
        "too little recorded: {} up, {} down, {payload_bytes} bytes",
        c2s_msgs.len(),
        s2c_msgs.len()
    );
    // The inner TLS records are all the frames carry: the first up-message
    // is a ClientHello record.
    assert_eq!(
        &c2s_msgs[0][..2],
        &[0x16, 0x03],
        "first message is not a TLS record"
    );

    let bare_token = rig.token.strip_prefix(TUNNEL_PREFIX).unwrap_or(&rig.token);
    assert_ne!(
        bare_token, rig.token,
        "the test token has the tunnel prefix"
    );
    let needles: [(&str, &[u8]); 5] = [
        ("canary / password", CANARY.as_bytes()),
        ("token", rig.token.as_bytes()),
        ("token without prefix", bare_token.as_bytes()),
        ("token prefix", TUNNEL_PREFIX.as_bytes()),
        ("agent id", b"assistant"),
    ];
    let decoded_up: Vec<u8> = c2s_msgs.concat();
    let decoded_down: Vec<u8> = s2c_msgs.concat();
    for (what, needle) in needles {
        for (where_, hay) in [
            ("outer plaintext up", &c2s),
            ("outer plaintext down", &s2c),
            ("decoded messages up", &decoded_up),
            ("decoded messages down", &decoded_down),
        ] {
            assert!(
                !find(hay, needle),
                "the edge saw the {what} in the {where_}"
            );
        }
    }
    // The search itself works.
    assert!(find(
        &[b"xx".as_slice(), CANARY.as_bytes()].concat(),
        CANARY.as_bytes()
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_with_own_inner_key_gets_bad_cert_and_no_auth() {
    let rig = rig().await;
    let own = cert();
    let inner_cfg = kharon_connector::server_config_from_pem_with(
        own.pem_cert.as_bytes(),
        own.pem_key.as_bytes(),
        kharon_connector::TlsVersions::Tls13Only,
    )
    .unwrap();
    assert_ne!(own.pin, rig.pin);
    let relay = Relay::start(Mode::TerminateInner(inner_cfg)).await;
    let params = relay.dial(&rig);

    let result = tokio::time::timeout(Duration::from_secs(10), run_agent_once(&params))
        .await
        .expect("the client hung");
    assert_eq!(result, Err(ClientError::BadCert));
    assert!(!rig.hub.is_connected("assistant"));

    // Let the relay task finish what it was doing.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let c2s = relay.rec.c2s.lock().unwrap().clone();
    let s2c = relay.rec.s2c.lock().unwrap().clone();
    let decrypted = relay.decrypted.lock().unwrap().clone();
    let (head, msgs) = parse_stream(&c2s);
    assert!(
        head.to_ascii_lowercase()
            .contains("sec-websocket-protocol: kharon-connector.v1"),
        "the client never reached the upgrade: {head}"
    );
    assert!(!msgs.is_empty(), "the client sent no inner ClientHello");
    assert!(decrypted.is_empty(), "the relay decrypted a hello");
    let bare = rig.token.strip_prefix(TUNNEL_PREFIX).unwrap();
    let decoded: Vec<u8> = msgs.concat();
    for (what, needle) in [
        ("token", rig.token.as_bytes()),
        ("bare token", bare.as_bytes()),
        ("agent id", b"assistant".as_slice()),
    ] {
        for hay in [&c2s, &s2c, &decoded, &decrypted] {
            assert!(!find(hay, needle), "the impersonating edge saw the {what}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_flipping_a_ciphertext_byte_drops_the_session() {
    let rig = rig().await;
    let relay = Relay::start(Mode::Forward {
        upstream: rig.public,
        tamper: true,
    })
    .await;
    let params = relay.dial(&rig);
    let agent = tokio::spawn(async move { run_agent_once(&params).await });
    eventually("attach through the relay", || {
        rig.hub.is_connected("assistant")
    })
    .await;

    // Authenticated. The next client message gets a flipped byte.
    relay.armed.store(true, Ordering::SeqCst);
    let fill = tokio::time::timeout(Duration::from_secs(15), try_fill(&rig.hub))
        .await
        .expect("the fill hung after the tamper");
    assert!(relay.flipped.load(Ordering::SeqCst), "nothing was flipped");
    match fill {
        Err(_) => {}
        Ok(outcome) => assert_ne!(outcome.status(), "filled", "{outcome:?}"),
    }

    // The run ends (an authenticated session's end is `Ok` or `Disconnected`).
    tokio::time::timeout(Duration::from_secs(10), agent)
        .await
        .expect("the agent session outlived the tamper")
        .expect("the agent task panicked")
        .ok();
    eventually("hub drops the agent", || !rig.hub.is_connected("assistant")).await;

    // `Hub::open_stream` waits for the agent to re-attach (by design; the
    // fill deadline bounds it), so a fill with nobody attached is not an
    // error outcome. The tampering was a one-off: a fresh session through
    // the same relay carries a fill again.
    let params = relay.dial(&rig);
    let agent = tokio::spawn(async move { run_agent_once(&params).await });
    eventually("re-attach through the relay", || {
        rig.hub.is_connected("assistant")
    })
    .await;
    let outcome = tokio::time::timeout(Duration::from_secs(15), fill_once(&rig.hub))
        .await
        .expect("the fill on the new session hung");
    assert_eq!(outcome.status(), "filled", "{outcome:?}");
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
}

/// 25 s real time: with the paused clock, auto-advance would fire the 5 s
/// hello deadline or the 90 s idle timeout before the in-process IO.
/// Ignored in the default run; CI runs it in the `rust` job (#220).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "25 s real time: CI runs it in the rust job, locally use --ignored"]
async fn idle_session_keeps_messages_flowing() {
    let rig = rig().await;
    let relay = Relay::start(Mode::Forward {
        upstream: rig.public,
        tamper: false,
    })
    .await;
    let params = relay.dial(&rig);
    let agent = tokio::spawn(async move { run_agent_once(&params).await });
    eventually("attach through the relay", || {
        rig.hub.is_connected("assistant")
    })
    .await;

    let t0 = Instant::now();
    tokio::time::sleep(Duration::from_secs(25)).await;
    let end = Instant::now();

    let ticks = relay.rec.ticks.lock().unwrap().clone();
    let mut in_window: Vec<Instant> = ticks.into_iter().filter(|t| *t > t0).collect();
    in_window.sort();
    assert!(
        !in_window.is_empty(),
        "no message crossed the relay in 25 s"
    );
    // No silent gap longer than the 20 s ping interval (plus a margin).
    let mut prev = t0;
    for t in in_window.iter().copied().chain([end]) {
        assert!(
            t - prev < Duration::from_secs(22),
            "silent for {:?}",
            t - prev
        );
        prev = t;
    }
    assert!(
        rig.hub.is_connected("assistant"),
        "the idle session dropped"
    );
    let outcome = fill_once(&rig.hub).await;
    assert_eq!(outcome.status(), "filled", "{outcome:?}");
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
}
