//! #199: the agent connector over a WebSocket on `[public_ingress]`.
//!
//! The router and a `Hub` run in-process, and the connector dials the
//! plain-loopback listener directly (`outer_tls: false`), so everything
//! kharond adds is on the path: the upgrade checks, the ClientHello gate,
//! the 8-slot pre-auth budget (Argon2id included), TLS 1.3 only, and the
//! shutdown of held-open sessions.

mod api_support;
mod connector_support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use connector_support::*;
use futures_util::{SinkExt, StreamExt};
use kharon_connector::Transport as Dial;
use kharon_connector::WsByteStream;
use kharond::config::Config;
use kharond::connector::{
    AgentParams, ClientError, ConnectorEvent, SessionTransport, run_agent_once,
};
use kharond::daemon::{self, PUBLIC_INGRESS_DRAIN};
use kharond::lock::StaticHardening;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use zeroize::Zeroizing;

const SUBPROTOCOL: &str = "kharon-connector.v1";
/// A valid `Sec-WebSocket-Key` (RFC 6455 section 1.3) and its accept value.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

type Edit = Box<dyn FnOnce(&mut Vec<String>)>;

/// A valid upgrade request, with `edit` applied to its header lines.
fn upgrade_request(edit: impl FnOnce(&mut Vec<String>)) -> String {
    let mut lines = vec![
        "GET /connector HTTP/1.1".to_owned(),
        "Host: 127.0.0.1".to_owned(),
        "Upgrade: websocket".to_owned(),
        "Connection: Upgrade".to_owned(),
        "Sec-WebSocket-Version: 13".to_owned(),
        format!("Sec-WebSocket-Key: {KEY}"),
        format!("Sec-WebSocket-Protocol: {SUBPROTOCOL}"),
    ];
    edit(&mut lines);
    lines.push(String::new());
    lines.push(String::new());
    lines.join("\r\n")
}

/// Send `request`, read the response head (or to EOF).
async fn http(addr: SocketAddr, request: &str) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    let read = async {
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), read)
        .await
        .expect("no response");
    String::from_utf8_lossy(&head).into_owned()
}

fn status(head: &str) -> u16 {
    head.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// A WebSocket upgraded by tungstenite itself, with no inner TLS yet.
async fn raw_ws(addr: SocketAddr) -> tokio_tungstenite::WebSocketStream<TcpStream> {
    let mut req = format!("ws://{addr}/connector")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", SUBPROTOCOL.parse().unwrap());
    let tcp = TcpStream::connect(addr).await.unwrap();
    client_async(req, tcp).await.expect("upgrade").0
}

/// The socket is closed from the far side within a few seconds, and
/// nothing readable (a TLS alert, say) arrived first.
async fn expect_close_without_bytes(ws: &mut tokio_tungstenite::WebSocketStream<TcpStream>) {
    let end = async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(other)) => panic!("expected a close, got {other:?}"),
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), end)
        .await
        .expect("the socket stayed open");
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_fill_over_public_ingress() {
    let rig = rig().await;
    let params = ws_dial(&rig, &rig.token);
    let agent = tokio::spawn(async move { run_agent_once(&params).await });
    eventually("ws attach", || rig.hub.is_connected("assistant")).await;
    {
        let events = rig.events.lock().unwrap();
        assert!(
            matches!(
                events.as_slice(),
                [ConnectorEvent::Attached {
                    transport: SessionTransport::Ws,
                    ..
                }]
            ),
            "{events:?}"
        );
        assert!(
            events[0]
                .to_string()
                .starts_with("agent connector attached: agent=assistant transport=ws peer=")
        );
    }

    let outcome = fill_once(&rig.hub).await;
    assert_eq!(outcome.status(), "filled", "{outcome:?}");
    assert!(!outcome.result_body().to_string().contains(CANARY));
    let saw_canary = rig
        .received
        .lock()
        .unwrap()
        .iter()
        .any(|m| m.to_string().contains(CANARY));
    assert!(saw_canary, "the fill did not reach the CDP stub");

    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(2), agent).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_upgrade_refusals() {
    let rig = rig().await;
    let a = rig.public;

    let ok = http(a, &upgrade_request(|_| {})).await;
    assert_eq!(status(&ok), 101, "{ok}");
    let lower = ok.to_ascii_lowercase();
    assert!(lower.contains(&format!(
        "sec-websocket-accept: {}",
        ACCEPT.to_ascii_lowercase()
    )));
    assert!(lower.contains(&format!("sec-websocket-protocol: {SUBPROTOCOL}")));

    let cases: [(&str, Edit, u16); 10] = [
        (
            "no subprotocol",
            Box::new(|l| l.retain(|h| !h.starts_with("Sec-WebSocket-Protocol"))),
            400,
        ),
        (
            "wrong subprotocol",
            Box::new(|l| {
                for h in l.iter_mut() {
                    if h.starts_with("Sec-WebSocket-Protocol") {
                        *h = "Sec-WebSocket-Protocol: other.v1".into();
                    }
                }
            }),
            400,
        ),
        (
            "subprotocol in another case",
            Box::new(|l| {
                for h in l.iter_mut() {
                    if h.starts_with("Sec-WebSocket-Protocol") {
                        *h = "Sec-WebSocket-Protocol: Kharon-Connector.V1".into();
                    }
                }
            }),
            400,
        ),
        (
            "origin",
            Box::new(|l| l.push("Origin: https://evil.example".into())),
            403,
        ),
        (
            "missing key",
            Box::new(|l| l.retain(|h| !h.starts_with("Sec-WebSocket-Key"))),
            400,
        ),
        (
            "wrong version",
            Box::new(|l| {
                for h in l.iter_mut() {
                    if h.starts_with("Sec-WebSocket-Version") {
                        *h = "Sec-WebSocket-Version: 8".into();
                    }
                }
            }),
            400,
        ),
        (
            "no upgrade header",
            Box::new(|l| l.retain(|h| !h.starts_with("Upgrade"))),
            400,
        ),
        (
            "no connection upgrade",
            Box::new(|l| {
                for h in l.iter_mut() {
                    if h.starts_with("Connection") {
                        *h = "Connection: keep-alive".into();
                    }
                }
            }),
            400,
        ),
        (
            "key not base64 of 16 bytes",
            Box::new(|l| {
                for h in l.iter_mut() {
                    if h.starts_with("Sec-WebSocket-Key") {
                        *h = "Sec-WebSocket-Key: abc".into();
                    }
                }
            }),
            400,
        ),
        (
            "POST",
            Box::new(|l| l[0] = "POST /connector HTTP/1.1".into()),
            404,
        ),
    ];
    let mut counted = 0;
    for (name, edit, want) in cases {
        let head = http(a, &upgrade_request(edit)).await;
        assert_eq!(status(&head), want, "{name}: {head}");
        if want != 404 {
            counted += 1;
        }
    }
    // Case-insensitive tokens, extensions ignored, a list of protocols.
    let head = http(
        a,
        &upgrade_request(|l| {
            for h in l.iter_mut() {
                if h.starts_with("Upgrade") {
                    *h = "Upgrade: WebSocket".into();
                }
                if h.starts_with("Connection") {
                    *h = "Connection: keep-alive, UPGRADE".into();
                }
                if h.starts_with("Sec-WebSocket-Protocol") {
                    *h = format!("Sec-WebSocket-Protocol: other, {SUBPROTOCOL}");
                }
            }
            l.push("Sec-WebSocket-Extensions: permessage-deflate".into());
        }),
    )
    .await;
    assert_eq!(status(&head), 101, "{head}");
    assert!(
        !head
            .to_ascii_lowercase()
            .contains("sec-websocket-extensions"),
        "{head}"
    );

    let line = rig.ws.take_refusal_line().expect("refusals are counted");
    assert!(
        line.contains(&format!("protocol {counted}")) && line.contains("budget 0"),
        "{line}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_text_message_closes() {
    let rig = rig().await;
    let mut ws = raw_ws(rig.public).await;
    eventually("slot taken", || rig.hub.ws_preauth_in_flight() == 1).await;
    ws.send(Message::Text("hello".into())).await.unwrap();
    expect_close_without_bytes(&mut ws).await;
    eventually("slot released", || rig.hub.ws_preauth_in_flight() == 0).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_non_clienthello_first_record_closes_before_rustls() {
    let rig = rig().await;
    // Each is a plausible first record that is not a ClientHello.
    let records: [&[u8]; 4] = [
        &[0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0, 0, 0, 0], // application data
        &[0x16, 0x03, 0x03, 0x00, 0x05, 0x02, 0, 0, 0, 0], // handshake, not type 1
        &[0x16, 0x02, 0x00, 0x00, 0x05, 0x01, 0, 0, 0, 0], // SSL 2.0 era version
        b"GET / HTTP/1.1\r\n\r\n",
    ];
    for record in records {
        let mut ws = raw_ws(rig.public).await;
        ws.send(Message::Binary(record.to_vec())).await.unwrap();
        // A TLS alert would arrive as a binary message: none may.
        expect_close_without_bytes(&mut ws).await;
    }
    let mut counted = 0;
    eventually("hello refusals counted", || {
        if let Some(line) = rig.ws.take_refusal_line() {
            assert!(line.contains("budget 0, protocol 0"), "{line}");
            assert!(line.contains("tls 0, auth 0)"), "{line}");
            let n = line.split("hello ").nth(1).unwrap();
            let n = n.split(',').next().unwrap();
            counted += n.parse::<u32>().unwrap();
        }
        counted == 4
    })
    .await;
    eventually("slots released", || rig.hub.ws_preauth_in_flight() == 0).await;
}

fn inner_client(
    rig: &Rig,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(rig.cert_der.clone()))
        .unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(versions)
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(client))
}

/// Upgrade, inner TLS 1.3, hello; `hello_sent` counts the hellos that
/// are written and flushed. Then wait for the server hello.
async fn hello_then_wait(rig: &Rig, token: String, hello_sent: Arc<AtomicUsize>) -> u8 {
    let ws = raw_ws(rig.public).await;
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = inner_client(rig, &[&rustls::version::TLS13])
        .connect(name, WsByteStream::new(ws))
        .await
        .expect("inner TLS 1.3");
    kharon_connector::write_client_hello(&mut tls, "assistant", &token)
        .await
        .unwrap();
    tls.flush().await.unwrap();
    hello_sent.fetch_add(1, Ordering::SeqCst);
    kharon_connector::read_server_hello(&mut tls).await.unwrap()
}

/// The window is the Argon2id verify: every token here costs about this
/// much, so eight of them stay in flight while the ninth knocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_preauth_budget_is_8_including_argon2() {
    // 64 MiB, 16 passes: well over a second a verify, and eight run at
    // once on the blocking pool.
    let rig = Arc::new(rig_with(argon(65536, 16)).await);
    let hello_sent = Arc::new(AtomicUsize::new(0));
    let mut clients = Vec::new();
    for _ in 0..8 {
        let hello_sent = Arc::clone(&hello_sent);
        let token = rig.token.clone();
        let rig_ref = Arc::clone(&rig);
        clients.push(tokio::spawn(async move {
            hello_then_wait(&rig_ref, token, hello_sent).await
        }));
    }
    // Every hello is on the wire, and each verify takes over a second:
    // the 8 slots are held through the Argon2id phase.
    eventually("8 hellos sent", || hello_sent.load(Ordering::SeqCst) == 8).await;
    assert_eq!(rig.hub.ws_preauth_in_flight(), 8);

    let ninth = http(rig.public, &upgrade_request(|_| {})).await;
    assert_eq!(status(&ninth), 503, "{ninth}");
    assert_eq!(rig.hub.ws_preauth_in_flight(), 8, "the 503 took no slot");

    for client in clients {
        assert_eq!(client.await.unwrap(), 0, "AUTH_OK");
    }
    eventually("slots released", || rig.hub.ws_preauth_in_flight() == 0).await;
    let line = rig.ws.take_refusal_line().unwrap();
    assert!(line.contains("budget 1"), "{line}");
}

/// More failures than slots, of every kind: a leaked permit would show
/// as a 503 at the end.
#[tokio::test(flavor = "multi_thread")]
async fn ws_slot_released_on_failure() {
    let rig = rig().await;
    for _ in 0..10 {
        // Wrong token: Argon2id says no.
        let bad = ws_dial(&rig, &format!("{}nope", rig.token));
        let err = kharon_connector::connect_and_auth(&bad).await.err();
        assert_eq!(err, Some(ClientError::Unauthorized));
        // Gate refusal.
        let mut ws = raw_ws(rig.public).await;
        ws.send(Message::Binary(vec![0x15, 3, 3, 0, 2, 1, 0]))
            .await
            .unwrap();
        expect_close_without_bytes(&mut ws).await;
        // Text message.
        let mut ws = raw_ws(rig.public).await;
        ws.send(Message::Text("x".into())).await.unwrap();
        expect_close_without_bytes(&mut ws).await;
        // Passes the gate, fails the handshake (TLS 1.2 only).
        let ws = raw_ws(rig.public).await;
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let tls12 = inner_client(&rig, &[&rustls::version::TLS12]);
        assert!(tls12.connect(name, WsByteStream::new(ws)).await.is_err());
        // Upgraded and abandoned.
        drop(raw_ws(rig.public).await);
    }
    eventually("slots released", || rig.hub.ws_preauth_in_flight() == 0).await;
    let good = ws_dial(&rig, &rig.token);
    kharon_connector::connect_and_auth(&good)
        .await
        .expect("a slot is free after the failures");
    eventually("slots released", || rig.hub.ws_preauth_in_flight() == 0).await;
}

/// The WebSocket path is TLS 1.3 only.
#[tokio::test(flavor = "multi_thread")]
async fn ws_inner_tls12_refused() {
    let rig = rig().await;
    let ws = raw_ws(rig.public).await;
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let connector = inner_client(&rig, &[&rustls::version::TLS12]);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(name, WsByteStream::new(ws)),
    )
    .await
    .expect("handshake hung");
    assert!(result.is_err(), "a TLS 1.2 handshake must not complete");
    eventually("slot released", || rig.hub.ws_preauth_in_flight() == 0).await;
    // A ClientHello passes the gate: this was a failed inner handshake,
    // counted under `tls`.
    let line = rig.ws.take_refusal_line().expect("the failure is counted");
    assert_eq!(
        line,
        "connector: refused 1 websocket connections in the last 60s \
         (budget 0, protocol 0, hello 0, tls 1, auth 0)"
    );
}

/// A refused credential on the public path is counted, never reported per
/// event: any stranger who completes inner TLS can produce one (#199).
#[tokio::test(flavor = "multi_thread")]
async fn ws_refused_credential_is_counted_not_logged() {
    let rig = rig().await;
    for _ in 0..3 {
        let bad = ws_dial(&rig, &format!("{}nope", rig.token));
        let err = kharon_connector::connect_and_auth(&bad).await.err();
        assert_eq!(err, Some(ClientError::Unauthorized));
    }
    eventually("slots released", || rig.hub.ws_preauth_in_flight() == 0).await;
    assert!(
        !rig.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ConnectorEvent::Refused { .. })),
        "no per-event line on the websocket path"
    );
    let line = rig.ws.take_refusal_line().expect("refusals are counted");
    assert_eq!(
        line,
        "connector: refused 3 websocket connections in the last 60s \
         (budget 0, protocol 0, hello 0, tls 0, auth 3)"
    );

    // The raw listener keeps its #150 line.
    let raw = AgentParams {
        token: Zeroizing::new(format!("{}nope", rig.token)),
        ..raw_dial(&rig)
    };
    assert_eq!(
        kharon_connector::connect_and_auth(&raw).await.err(),
        Some(ClientError::Unauthorized)
    );
    eventually("raw refusal logged", || {
        rig.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, ConnectorEvent::Refused { .. }))
    })
    .await;
    assert_eq!(
        rig.ws.take_refusal_line(),
        None,
        "the raw path is not counted"
    );
}

/// A malformed hello after the inner handshake counts under `auth`.
#[tokio::test(flavor = "multi_thread")]
async fn ws_malformed_hello_counts_as_auth() {
    let rig = rig().await;
    let ws = raw_ws(rig.public).await;
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = inner_client(&rig, &[&rustls::version::TLS13])
        .connect(name, WsByteStream::new(ws))
        .await
        .expect("inner TLS 1.3");
    tls.write_all(b"not a hello record\n").await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut buf)).await;
    eventually("slot released", || rig.hub.ws_preauth_in_flight() == 0).await;
    let line = rig.ws.take_refusal_line().expect("counted");
    assert!(line.ends_with("hello 0, tls 0, auth 1)"), "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_and_ws_sessions_replace_each_other() {
    let rig = rig().await;
    let detached = |rig: &Rig, transport: SessionTransport| {
        rig.events.lock().unwrap().iter().any(|e| {
            matches!(e, ConnectorEvent::Detached { transport: t, replaced: true, .. } if *t == transport)
        })
    };

    // raw first, then ws evicts it.
    let raw = raw_dial(&rig);
    let raw_task = tokio::spawn(async move { run_agent_once(&raw).await });
    eventually("raw attach", || rig.hub.is_connected("assistant")).await;
    let ws = ws_dial(&rig, &rig.token);
    let ws_task = tokio::spawn(async move { run_agent_once(&ws).await });
    eventually("raw replaced", || detached(&rig, SessionTransport::Tls)).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), raw_task)
        .await
        .expect("the evicted raw agent kept its socket");
    assert!(rig.hub.is_connected("assistant"));

    // and back: a raw dial evicts the ws session.
    let raw = raw_dial(&rig);
    let raw_task = tokio::spawn(async move { run_agent_once(&raw).await });
    eventually("ws replaced", || detached(&rig, SessionTransport::Ws)).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), ws_task)
        .await
        .expect("the evicted ws agent kept its socket");
    assert!(rig.hub.is_connected("assistant"));
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(5), raw_task).await;
}

/// A path-B daemon config on loopback ports: `[public_ingress]` plus the
/// given `[connector]` lines. Returns the config text and the tunnel token.
fn daemon_config(dir: &std::path::Path, cert: &Cert, connector: &str) -> (String, String) {
    std::fs::write(dir.join("tls.crt"), &cert.pem_cert).unwrap();
    std::fs::write(dir.join("tls.key"), &cert.pem_key).unwrap();
    let (secret, hash) = kharond::api::token::generate_tunnel("assistant");
    let token = secret.expose_secret().clone();
    let text = format!(
        r#"mode = "export"
data_dir = "{data}"

[export]
file = "{export}"

[agents.assistant]
token_hash = "{hash}"
connector_token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[public_ingress]
listen = "127.0.0.1:0"

[connector]
{connector}
tls_cert_file = "{crt}"
tls_key_file = "{key}"
"#,
        data = dir.join("data").display(),
        export = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        ),
        crt = dir.join("tls.crt").display(),
        key = dir.join("tls.key").display(),
    );
    (text, token)
}

/// The raw listener of a started daemon keeps the default version set:
/// a TLS 1.2-only client still completes the inner handshake there.
#[tokio::test(flavor = "multi_thread")]
async fn raw_listener_still_accepts_tls12() {
    let dir = tempfile::tempdir().unwrap();
    let cert = cert();
    let (text, _token) = daemon_config(
        dir.path(),
        &cert,
        "listen = \"127.0.0.1:0\"\nwebsocket = true",
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    let daemon = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let raw = daemon.connector_addr().expect("raw listener");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(daemon.run(async {
        let _ = stopped.await;
    }));

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(cert.der.clone()))
        .unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(raw).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect(name, tcp)
        .await
        .expect("TLS 1.2 on the raw listener");
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    drop(tls);
    let _ = stop.send(());
    let _ = tokio::time::timeout(PUBLIC_INGRESS_DRAIN + Duration::from_secs(2), server).await;
}

/// A held-open, authenticated session ends when the daemon stops, inside
/// the drain bound, and `run()` returns.
#[tokio::test(flavor = "multi_thread")]
async fn ws_session_ends_at_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let cert = cert();
    let (text, token) = daemon_config(dir.path(), &cert, "websocket = true");
    let cfg = Config::from_toml_str(&text).unwrap();
    let daemon = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    assert!(daemon.connector_addr().is_none(), "no raw listener");
    let public = daemon.public_ingress_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(daemon.run(async {
        let _ = stopped.await;
    }));

    let params = AgentParams {
        transport: Dial::Ws {
            host: "127.0.0.1".into(),
            port: public.port(),
            path: "/connector".into(),
            outer_tls: false,
        },
        server_name: "127.0.0.1".into(),
        pin: cert.pin,
        agent_id: "assistant".into(),
        token: Zeroizing::new(token),
        cdp: "127.0.0.1:9".parse().unwrap(),
        proxy: None,
        proxy_creds: None,
        outer_roots: None,
    };
    let session = kharon_connector::connect_and_auth(&params)
        .await
        .expect("authenticated");
    let held = tokio::spawn(session.serve());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!held.is_finished(), "the session is idle, not over");

    let started = tokio::time::Instant::now();
    let _ = stop.send(());
    let margin = Duration::from_secs(2);
    tokio::time::timeout(PUBLIC_INGRESS_DRAIN + margin, held)
        .await
        .expect("the held-open session outlived shutdown")
        .unwrap()
        .ok();
    tokio::time::timeout(PUBLIC_INGRESS_DRAIN + margin, server)
        .await
        .expect("run() did not return")
        .unwrap()
        .unwrap();
    assert!(
        started.elapsed() < PUBLIC_INGRESS_DRAIN,
        "the session ended by the abort, not by tracking: {:?}",
        started.elapsed()
    );
}
