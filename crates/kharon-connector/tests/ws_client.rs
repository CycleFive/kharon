//! #199 Task 2: the client's `ws` transport dial, leg by leg.
//!
//! The in-test server is TCP, then outer TLS (a CA-signed leaf), then a
//! WebSocket upgrade, then inner TLS 1.3 (a different, self-signed cert),
//! then the connector auth record.

#![allow(clippy::result_large_err)] // tungstenite's callback signature

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kharon_connector::{
    AUTH_OK, AgentParams, ClientError, Leg, OuterTlsClass, TlsVersions, Transport, WS_SUBPROTOCOL,
    WsByteStream, check_once, pin_of_der, read_client_hello, run_agent_once,
    server_config_from_pem, server_config_from_pem_with, spawn_broker, write_server_hello,
    ws_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey, IsCa, KeyPair, generate_simple_self_signed,
};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use zeroize::Zeroizing;

const TOKEN: &str = "kh_tunnel_assistant_ok";

struct Pki {
    outer_cert_pem: String,
    outer_key_pem: String,
    roots: Arc<RootCertStore>,
}

fn outer_pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    Pki {
        outer_cert_pem: leaf.pem(),
        outer_key_pem: leaf_key.serialize_pem(),
        roots: Arc::new(roots),
    }
}

struct Inner {
    pem_cert: String,
    pem_key: String,
    pin: [u8; 32],
}

fn inner_cert() -> Inner {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    Inner {
        pin: pin_of_der(cert.der()),
        pem_cert: cert.pem(),
        pem_key: key_pair.serialize_pem(),
    }
}

#[derive(Clone, Copy)]
enum Mode {
    /// Full upgrade, echo the subprotocol, run the auth server.
    Full,
    /// Upgrade without echoing a subprotocol.
    NoSubprotocol,
    /// Read the request head, answer this status with no body.
    Status(u16),
    /// Full upgrade and inner TLS, then read the hello and never answer.
    HelloSilent,
}

struct Server {
    addr: SocketAddr,
    roots: Arc<RootCertStore>,
    inner_pin: [u8; 32],
    inner_failed: Arc<AtomicBool>,
    hello_read: Arc<AtomicBool>,
    sessions: Arc<Mutex<Vec<kharon_connector::BrokerSession>>>,
}

async fn start_server(mode: Mode) -> Server {
    let pki = outer_pki();
    let inner = inner_cert();
    let outer_cfg =
        server_config_from_pem(pki.outer_cert_pem.as_bytes(), pki.outer_key_pem.as_bytes())
            .unwrap();
    let inner_cfg = server_config_from_pem_with(
        inner.pem_cert.as_bytes(),
        inner.pem_key.as_bytes(),
        TlsVersions::Tls13Only,
    )
    .unwrap();
    // All of 127.0.0.0/8, so a test can dial an address the outer
    // certificate does not cover.
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().unwrap().port()));
    let inner_failed = Arc::new(AtomicBool::new(false));
    let hello_read = Arc::new(AtomicBool::new(false));
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let (f2, h2, s2) = (
        Arc::clone(&inner_failed),
        Arc::clone(&hello_read),
        Arc::clone(&sessions),
    );
    let outer = tokio_rustls::TlsAcceptor::from(outer_cfg);
    let inner_acc = tokio_rustls::TlsAcceptor::from(inner_cfg);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let (outer, inner_acc) = (outer.clone(), inner_acc.clone());
            let (f, h, s) = (Arc::clone(&f2), Arc::clone(&h2), Arc::clone(&s2));
            tokio::spawn(async move {
                let Ok(mut tls) = outer.accept(tcp).await else {
                    return;
                };
                if let Mode::Status(code) = mode {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        if tls.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        buf.push(b[0]);
                    }
                    let resp = format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n");
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                    return;
                }
                let echo = matches!(mode, Mode::Full | Mode::HelloSilent);
                let cb = move |req: &Request, mut resp: Response| {
                    assert!(req.headers().get("origin").is_none());
                    assert_eq!(
                        req.headers().get("sec-websocket-protocol").unwrap(),
                        WS_SUBPROTOCOL
                    );
                    if echo {
                        resp.headers_mut()
                            .insert("sec-websocket-protocol", WS_SUBPROTOCOL.parse().unwrap());
                    }
                    Ok(resp)
                };
                let Ok(ws) =
                    tokio_tungstenite::accept_hdr_async_with_config(tls, cb, Some(ws_config()))
                        .await
                else {
                    return;
                };
                let Ok(mut inner_tls) = inner_acc.accept(WsByteStream::new(ws)).await else {
                    f.store(true, Ordering::SeqCst);
                    return;
                };
                let Ok(hello) = read_client_hello(&mut inner_tls).await else {
                    return;
                };
                h.store(true, Ordering::SeqCst);
                if matches!(mode, Mode::HelloSilent) {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    return;
                }
                if hello.token.as_str() != TOKEN {
                    return;
                }
                if write_server_hello(&mut inner_tls, AUTH_OK).await.is_err() {
                    return;
                }
                let session = spawn_broker(inner_tls);
                s.lock().unwrap().push(session.clone());
                session.closed().await;
            });
        }
    });
    Server {
        addr,
        roots: pki.roots,
        inner_pin: inner.pin,
        inner_failed,
        hello_read,
        sessions,
    }
}

async fn echo_stub() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 || sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, hits)
}

fn ws_params(srv: &Server, pin: [u8; 32], cdp: SocketAddr) -> AgentParams {
    AgentParams {
        transport: Transport::Ws {
            host: "127.0.0.1".into(),
            port: srv.addr.port(),
            path: "/connector".into(),
            outer_tls: true,
        },
        server_name: "127.0.0.1".into(),
        pin,
        agent_id: "assistant".into(),
        token: Zeroizing::new(TOKEN.into()),
        cdp,
        proxy: None,
        proxy_creds: None,
        outer_roots: Some(Arc::clone(&srv.roots)),
    }
}

async fn run(p: &AgentParams) -> Result<(), ClientError> {
    tokio::time::timeout(Duration::from_secs(15), run_agent_once(p))
        .await
        .expect("dial timed out")
}

async fn wait_session(srv: &Server) -> kharon_connector::BrokerSession {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(s) = srv.sessions.lock().unwrap().first().cloned() {
            return s;
        }
        assert!(tokio::time::Instant::now() < deadline, "no session");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn ws_dial_authenticates_and_relays() {
    let (cdp, hits) = echo_stub().await;
    let srv = start_server(Mode::Full).await;
    let p = ws_params(&srv, srv.inner_pin, cdp);
    let agent = tokio::spawn(async move { run_agent_once(&p).await });
    let session = wait_session(&srv).await;
    let mut io = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .unwrap()
        .unwrap();
    io.write_all(b"ping").await.unwrap();
    io.flush().await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"ping");
    assert!(hits.load(Ordering::SeqCst) >= 1);
    session.shutdown();
    let r = tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r, Ok(()));
}

#[tokio::test]
async fn ws_wrong_inner_pin_is_bad_cert_and_sends_no_auth() {
    let (cdp, hits) = echo_stub().await;
    let srv = start_server(Mode::Full).await;
    let p = ws_params(&srv, [7u8; 32], cdp);
    assert_eq!(run(&p).await, Err(ClientError::BadCert));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(srv.inner_failed.load(Ordering::SeqCst));
    assert!(!srv.hello_read.load(Ordering::SeqCst));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ws_untrusted_outer_cert_is_outer_tls() {
    let (cdp, _) = echo_stub().await;
    let srv = start_server(Mode::Full).await;
    let mut p = ws_params(&srv, srv.inner_pin, cdp);
    p.outer_roots = Some(Arc::new(RootCertStore::empty()));
    let err = run(&p).await.unwrap_err();
    assert_eq!(err, ClientError::OuterTls(OuterTlsClass::UntrustedIssuer));
    assert_eq!(
        err.to_string(),
        "outer TLS to the broker host failed: untrusted issuer"
    );
}

#[tokio::test]
async fn ws_server_status_is_reported_as_received() {
    let (cdp, _) = echo_stub().await;
    for code in [404u16, 502, 530] {
        let srv = start_server(Mode::Status(code)).await;
        let p = ws_params(&srv, srv.inner_pin, cdp);
        let err = run(&p).await.unwrap_err();
        assert_eq!(err, ClientError::Upgrade { status: code });
        assert_eq!(
            err.to_string(),
            format!("websocket upgrade answered {code}")
        );
    }
}

#[tokio::test]
async fn ws_server_without_subprotocol_is_refused() {
    let (cdp, _) = echo_stub().await;
    let srv = start_server(Mode::NoSubprotocol).await;
    let p = ws_params(&srv, srv.inner_pin, cdp);
    assert_eq!(run(&p).await, Err(ClientError::Upgrade { status: 101 }));
    assert!(!srv.hello_read.load(Ordering::SeqCst));
    assert_eq!(
        ClientError::Upgrade { status: 101 }.to_string(),
        "websocket upgrade answered 101 without the kharon-connector.v1 subprotocol"
    );
}

/// A broker that completes inner TLS and reads the hello but never answers:
/// the failure is on the auth leg, as an auth-leg error. Runs the real
/// 10 s leg timeout.
#[tokio::test]
async fn hello_timeout_is_an_auth_leg_error() {
    let (cdp, _) = echo_stub().await;
    let srv = start_server(Mode::HelloSilent).await;
    let p = ws_params(&srv, srv.inner_pin, cdp);
    let legs = tokio::time::timeout(Duration::from_secs(20), check_once(&p))
        .await
        .expect("check_once hung");
    assert_eq!(
        legs.last().unwrap(),
        &(Leg::Auth, Err(ClientError::Protocol))
    );
}

#[tokio::test]
async fn check_once_names_each_leg() {
    let (cdp, hits) = echo_stub().await;
    let srv = start_server(Mode::Full).await;

    let p = ws_params(&srv, srv.inner_pin, cdp);
    let legs = check_once(&p).await;
    let names: Vec<Leg> = legs.iter().map(|(l, _)| *l).collect();
    assert_eq!(
        names,
        [
            Leg::Dns,
            Leg::Tcp,
            Leg::OuterTls,
            Leg::Upgrade,
            Leg::InnerTls,
            Leg::Auth
        ]
    );
    assert!(legs.iter().all(|(_, r)| r.is_ok()), "{legs:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "check_once opens no CDP");

    let mut dns = ws_params(&srv, srv.inner_pin, cdp);
    dns.transport = Transport::Ws {
        host: "no-such-host.invalid".into(),
        port: 443,
        path: "/connector".into(),
        outer_tls: true,
    };
    assert_eq!(
        check_once(&dns).await,
        vec![(Leg::Dns, Err(ClientError::Dns))]
    );

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut tcp = ws_params(&srv, srv.inner_pin, cdp);
    tcp.transport = Transport::Ws {
        host: "127.0.0.1".into(),
        port,
        path: "/connector".into(),
        outer_tls: true,
    };
    let legs = check_once(&tcp).await;
    assert_eq!(
        legs,
        vec![
            (Leg::Dns, Ok(())),
            (
                Leg::Tcp,
                Err(ClientError::Tcp {
                    kind: std::io::ErrorKind::ConnectionRefused
                })
            )
        ]
    );

    let bad = ws_params(&srv, [7u8; 32], cdp);
    let legs = check_once(&bad).await;
    assert_eq!(
        legs.last().unwrap(),
        &(Leg::InnerTls, Err(ClientError::BadCert))
    );
}

#[tokio::test]
async fn raw_tls_transport_still_works() {
    let (cdp, _) = echo_stub().await;
    let inner = inner_cert();
    let cfg = server_config_from_pem(inner.pem_cert.as_bytes(), inner.pem_key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker = listener.local_addr().unwrap();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let slot = Arc::clone(&sessions);
    let acc = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acc.accept(tcp).await.unwrap();
        let _ = read_client_hello(&mut tls).await.unwrap();
        write_server_hello(&mut tls, AUTH_OK).await.unwrap();
        let s = spawn_broker(tls);
        slot.lock().unwrap().push(s.clone());
        s.closed().await;
    });
    let p = AgentParams {
        transport: Transport::Tls { broker, host: None },
        server_name: "127.0.0.1".into(),
        pin: inner.pin,
        agent_id: "assistant".into(),
        token: Zeroizing::new(TOKEN.into()),
        cdp,
        proxy: None,
        proxy_creds: None,
        outer_roots: None,
    };
    let agent = tokio::spawn(async move { run_agent_once(&p).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let session = loop {
        if let Some(s) = sessions.lock().unwrap().first().cloned() {
            break s;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let mut io = session.open_stream().await.unwrap();
    io.write_all(b"pong").await.unwrap();
    io.flush().await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"pong");
    session.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
}

// ---- through an HTTP CONNECT proxy ----

struct Proxy {
    addr: SocketAddr,
    head: Arc<Mutex<Vec<u8>>>,
    forwarded: Arc<Mutex<Vec<u8>>>,
}

/// `answer`: `Some(code)` replies that status and closes; `None` tunnels to
/// `upstream`; `Never` accepts and stays silent.
enum ProxyMode {
    Tunnel(SocketAddr),
    Status(u16),
    Silent,
}

async fn start_proxy(mode: ProxyMode) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let head = Arc::new(Mutex::new(Vec::new()));
    let forwarded = Arc::new(Mutex::new(Vec::new()));
    let (h2, f2) = (Arc::clone(&head), Arc::clone(&forwarded));
    tokio::spawn(async move {
        let Ok((mut c, _)) = listener.accept().await else {
            return;
        };
        if matches!(mode, ProxyMode::Silent) {
            tokio::time::sleep(Duration::from_secs(60)).await;
            return;
        }
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if c.read(&mut b).await.unwrap_or(0) == 0 {
                return;
            }
            buf.push(b[0]);
        }
        *h2.lock().unwrap() = buf;
        match mode {
            ProxyMode::Status(code) => {
                let _ = c
                    .write_all(format!("HTTP/1.1 {code} X\r\n\r\n").as_bytes())
                    .await;
            }
            ProxyMode::Tunnel(up) => {
                let Ok(mut u) = tokio::net::TcpStream::connect(up).await else {
                    return;
                };
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                let (mut cr, mut cw) = c.split();
                let (mut ur, mut uw) = u.split();
                let up_copy = async {
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = cr.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        f2.lock().unwrap().extend_from_slice(&chunk[..n]);
                        if uw.write_all(&chunk[..n]).await.is_err() {
                            break;
                        }
                    }
                };
                let down_copy = async {
                    let _ = tokio::io::copy(&mut ur, &mut cw).await;
                };
                tokio::select! { _ = up_copy => {}, _ = down_copy => {} }
            }
            ProxyMode::Silent => {}
        }
    });
    Proxy {
        addr,
        head,
        forwarded,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn ws_dial_through_proxy_authenticates() {
    let (cdp, _) = echo_stub().await;
    let srv = start_server(Mode::Full).await;
    let proxy = start_proxy(ProxyMode::Tunnel(srv.addr)).await;
    let mut p = ws_params(&srv, srv.inner_pin, cdp);
    p.proxy = Some(proxy.addr);
    p.proxy_creds = Some(Zeroizing::new(b"user:s3cretpw".to_vec()));
    let legs = check_once(&p).await;
    assert!(legs.iter().all(|(_, r)| r.is_ok()), "{legs:?}");
    assert_eq!(legs.last().unwrap().0, Leg::Auth);
    let head = String::from_utf8(proxy.head.lock().unwrap().clone()).unwrap();
    assert!(
        head.starts_with(&format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\n",
            srv.addr.port()
        )),
        "{head}"
    );
    assert!(head.contains("Proxy-Authorization: Basic "));
    let fwd = proxy.forwarded.lock().unwrap().clone();
    assert!(!fwd.is_empty());
    assert!(!contains(&fwd, b"s3cretpw"));
    assert!(!contains(&fwd, b"Proxy-Authorization"));
    assert!(!contains(&fwd, b"dXNlcjpzM2NyZXRwdw"));
}

#[tokio::test]
async fn ws_proxy_403_is_proxy_status() {
    let (cdp, _) = echo_stub().await;
    let srv = start_server(Mode::Full).await;
    let proxy = start_proxy(ProxyMode::Status(403)).await;
    let mut p = ws_params(&srv, srv.inner_pin, cdp);
    p.proxy = Some(proxy.addr);
    let legs = check_once(&p).await;
    assert_eq!(
        legs.last().unwrap(),
        &(Leg::Proxy, Err(ClientError::ProxyStatus { code: 403 }))
    );
}

/// Runs the real 10 s leg timeout: `LEG_TIMEOUT` is a const.
#[tokio::test]
async fn ws_proxy_that_never_answers_times_out() {
    let (cdp, _) = echo_stub().await;
    let srv = start_server(Mode::Full).await;
    let proxy = start_proxy(ProxyMode::Silent).await;
    let mut p = ws_params(&srv, srv.inner_pin, cdp);
    p.proxy = Some(proxy.addr);
    let legs = tokio::time::timeout(Duration::from_secs(20), check_once(&p))
        .await
        .expect("check_once hung");
    assert!(legs.contains(&(Leg::Tcp, Ok(()))), "{legs:?}");
    let (leg, err) = legs.last().unwrap();
    assert_eq!(*leg, Leg::Proxy);
    let err = err.unwrap_err();
    assert_eq!(err, ClientError::ProxyStatus { code: 0 });
    assert_eq!(err.to_string(), "proxy CONNECT got no answer");
}

/// A dead proxy is a `tcp` failure, and the CONNECT never happens.
#[tokio::test]
async fn proxy_connection_refused_is_the_tcp_leg() {
    let (cdp, _) = echo_stub().await;
    let srv = start_server(Mode::Full).await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let mut p = ws_params(&srv, srv.inner_pin, cdp);
    p.proxy = Some(dead);
    let legs = check_once(&p).await;
    assert_eq!(
        legs,
        vec![(
            Leg::Tcp,
            Err(ClientError::Tcp {
                kind: std::io::ErrorKind::ConnectionRefused
            })
        )]
    );
}

/// `transport = "tls"` through a proxy: the CONNECT names the configured
/// broker host, not the inner `server_name` override.
#[tokio::test]
async fn tls_proxy_connect_names_the_broker_host_not_server_name() {
    let (cdp, _) = echo_stub().await;
    let inner = inner_cert();
    let cfg = server_config_from_pem(inner.pem_cert.as_bytes(), inner.pem_key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker = listener.local_addr().unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acc.accept(tcp).await.unwrap();
        let _ = read_client_hello(&mut tls).await.unwrap();
        write_server_hello(&mut tls, AUTH_OK).await.unwrap();
        let s = spawn_broker(tls);
        s.closed().await;
    });
    let proxy = start_proxy(ProxyMode::Tunnel(broker)).await;
    let p = AgentParams {
        transport: Transport::Tls {
            broker,
            host: Some("broker.example".into()),
        },
        server_name: "cert-name.example".into(),
        pin: inner.pin,
        agent_id: "assistant".into(),
        token: Zeroizing::new(TOKEN.into()),
        cdp,
        proxy: Some(proxy.addr),
        proxy_creds: None,
        outer_roots: None,
    };
    let legs = check_once(&p).await;
    assert!(legs.iter().all(|(_, r)| r.is_ok()), "{legs:?}");
    let head = String::from_utf8(proxy.head.lock().unwrap().clone()).unwrap();
    assert!(
        head.starts_with(&format!(
            "CONNECT broker.example:{} HTTP/1.1\r\n",
            broker.port()
        )),
        "{head}"
    );
    assert!(!head.contains("cert-name.example"), "{head}");
}

/// The outer certificate chains to a trusted root but is not valid for the
/// host name dialed: a name mismatch, as fixed text.
#[tokio::test]
async fn ws_outer_cert_for_another_name_is_a_name_mismatch() {
    let (cdp, _) = echo_stub().await;
    let srv = start_server(Mode::Full).await;
    let mut p = ws_params(&srv, srv.inner_pin, cdp);
    // The certificate covers `localhost` and 127.0.0.1, not 127.0.0.2.
    p.transport = Transport::Ws {
        host: "127.0.0.2".into(),
        port: srv.addr.port(),
        path: "/connector".into(),
        outer_tls: true,
    };
    let err = run(&p).await.unwrap_err();
    assert_eq!(err, ClientError::OuterTls(OuterTlsClass::NameMismatch));
    assert_eq!(
        err.to_string(),
        "outer TLS to the broker host failed: name mismatch"
    );
}
