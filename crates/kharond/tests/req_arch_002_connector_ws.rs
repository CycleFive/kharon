//! #199: the agent connector over a WebSocket on `[public_ingress]`.
//!
//! The router and a `Hub` run in-process, and the connector dials the
//! plain-loopback listener directly (`outer_tls: false`), so everything
//! kharond adds is on the path: the upgrade checks, the ClientHello gate,
//! the 8-slot pre-auth budget (Argon2id included), TLS 1.3 only, and the
//! shutdown of held-open sessions.

mod api_support;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::Harness;
use argon2::Argon2;
use futures_util::{SinkExt, StreamExt};
use kharon_connector::Transport as Dial;
use kharon_connector::WsByteStream;
use kharond::api::token::{ParamFloor, TUNNEL_PREFIX, TokenStore, generate_tunnel_with};
use kharond::cdp::{
    Browser, CdpClient, CdpDial, CdpEndpoint, FieldFill, FieldKind, FillEngine, FillPlan,
    LiveOrigin, Tunnel, ValuesSent,
};
use kharond::config::Config;
use kharond::connector::{
    AgentParams, ClientError, ConnectorEvent, Hub, Transport, WsEntry, accept, pin_of_der,
    run_agent_once, server_config_from_pem,
};
use kharond::daemon::{self, PUBLIC_INGRESS_DRAIN};
use kharond::lock::StaticHardening;
use kharond::origin::{OriginConfig, OriginMatcher};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{accept_async, client_async};
use zeroize::Zeroizing;

const CANARY: &str = "CANARY-CONNECTOR-WS-FILL-41d7";
const URL: &str = "https://example.com/login";
const SUBPROTOCOL: &str = "kharon-connector.v1";
/// A valid `Sec-WebSocket-Key` (RFC 6455 section 1.3) and its accept value.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn argon(m_cost: u32, t_cost: u32) -> Argon2<'static> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(m_cost, t_cost, 1, None).unwrap(),
    )
}

const FLOOR: ParamFloor = ParamFloor {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

struct Cert {
    pem_cert: String,
    pem_key: String,
    der: Vec<u8>,
    pin: [u8; 32],
}

fn cert() -> Cert {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    Cert {
        pin: pin_of_der(cert.der()),
        der: cert.der().to_vec(),
        pem_cert: cert.pem(),
        pem_key: key_pair.serialize_pem(),
    }
}

/// CDP stub: `/json/version` then a WebSocket that answers one fill.
async fn cdp_stub() -> (SocketAddr, Arc<Mutex<Vec<Value>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&received);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let mut peek = [0u8; 20];
            let n = sock.peek(&mut peek).await.unwrap_or(0);
            if peek[..n].starts_with(b"GET /json/version") {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body =
                    r#"{"webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/stub-id"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                continue;
            }
            let rec = Arc::clone(&rec);
            tokio::spawn(async move {
                let Ok(mut ws) = accept_async(sock).await else {
                    return;
                };
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let msg: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    rec.lock().unwrap().push(msg.clone());
                    let method = msg["method"].as_str().unwrap_or("");
                    let result = match method {
                        "Target.createBrowserContext" => json!({ "browserContextId": "ctx-A" }),
                        "Target.getTargetInfo" => json!({ "targetInfo": {
                            "targetId": "t1",
                            "browserContextId": "ctx-A",
                            "url": URL,
                            "title": "",
                            "type": "page",
                        } }),
                        "Target.attachToTarget" => json!({ "sessionId": "sess-1" }),
                        "Page.getFrameTree" => json!({ "frameTree": { "frame": {
                            "id": "f1", "loaderId": "l1", "url": URL,
                        }, "childFrames": [] } }),
                        "Page.createIsolatedWorld" => json!({ "executionContextId": 7 }),
                        "Runtime.callFunctionOn" => {
                            let kinds: Vec<Value> = msg["params"]["arguments"][1]["value"]
                                .as_array()
                                .map(|fs| fs.iter().map(|f| json!({ "kind": f["kind"] })).collect())
                                .unwrap_or_default();
                            json!({ "result": { "type": "object", "value": { "results": kinds } } })
                        }
                        _ => json!({}),
                    };
                    let mut reply = json!({ "id": msg["id"], "result": result });
                    if let Some(s) = msg.get("sessionId") {
                        reply["sessionId"] = s.clone();
                    }
                    if ws.send(Message::Text(reply.to_string())).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, received)
}

fn plan() -> FillPlan {
    FillPlan {
        target_id: "t1".into(),
        fields: vec![FieldFill {
            kind: FieldKind::Password,
            selector: None,
            value: Zeroizing::new(CANARY.into()),
        }],
        item_matchers: vec![OriginMatcher::new(URL, Some(0)).unwrap()],
        origin_cfg: OriginConfig { allow_http: false },
        cross_origin_iframe_hosts: Vec::new(),
        submit: false,
        expected_origin: Some("https://example.com".into()),
        live_origin: LiveOrigin::new(),
        deadline: None,
        values_sent: ValuesSent::new(),
    }
}

struct Rig {
    hub: Arc<Hub>,
    ws: Arc<WsEntry>,
    events: Arc<Mutex<Vec<ConnectorEvent>>>,
    token: String,
    pin: [u8; 32],
    cert_der: Vec<u8>,
    /// `[public_ingress]`, plain loopback.
    public: SocketAddr,
    /// The raw listener of the same hub.
    raw: SocketAddr,
    cdp: SocketAddr,
    received: Arc<Mutex<Vec<Value>>>,
    _harness: Harness,
}

/// `hash_argon` hashes the tunnel token (and so prices each verify).
async fn rig_with(hash_argon: Argon2<'static>) -> Rig {
    let (cdp, received) = cdp_stub().await;
    let (secret, hash) = generate_tunnel_with(&hash_argon, "assistant");
    let token = secret.expose_secret().clone();
    let store =
        TokenStore::with_floor_and_prefix([("assistant", hash.as_str())], &FLOOR, TUNNEL_PREFIX)
            .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let hub = Arc::new(Hub::with_events(
        store,
        Arc::new(move |e| sink.lock().unwrap().push(e.clone())),
    ));
    let cert = cert();
    let ws_tls = kharon_connector::server_config_from_pem_with(
        cert.pem_cert.as_bytes(),
        cert.pem_key.as_bytes(),
        kharon_connector::TlsVersions::Tls13Only,
    )
    .unwrap();
    let ws = WsEntry::new(Arc::clone(&hub), ws_tls);

    let raw_tls =
        server_config_from_pem(cert.pem_cert.as_bytes(), cert.pem_key.as_bytes()).unwrap();
    let raw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw = raw_listener.local_addr().unwrap();
    let raw_hub = Arc::clone(&hub);
    tokio::spawn(async move { accept(raw_listener, raw_tls, raw_hub).await });

    let harness = Harness::new(false);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::public::serve_with_shutdown(
        listener,
        harness.broker.clone(),
        Some(Arc::clone(&ws)),
        std::future::pending(),
    ));
    Rig {
        hub,
        ws,
        events,
        token,
        pin: cert.pin,
        cert_der: cert.der,
        public,
        raw,
        cdp,
        received,
        _harness: harness,
    }
}

async fn rig() -> Rig {
    rig_with(argon(8, 1)).await
}

fn ws_dial(rig: &Rig, token: &str) -> AgentParams {
    AgentParams {
        transport: Dial::Ws {
            host: "127.0.0.1".into(),
            port: rig.public.port(),
            path: "/connector".into(),
            outer_tls: false,
        },
        server_name: "127.0.0.1".into(),
        pin: rig.pin,
        agent_id: "assistant".into(),
        token: Zeroizing::new(token.to_owned()),
        cdp: rig.cdp,
        proxy: None,
        proxy_creds: None,
        outer_roots: None,
    }
}

fn raw_dial(rig: &Rig) -> AgentParams {
    AgentParams {
        transport: Dial::Tls { broker: rig.raw },
        ..ws_dial(rig, &rig.token)
    }
}

async fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !ok() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn fill_once(hub: &Arc<Hub>) -> kharond::cdp::FillOutcome {
    let endpoint =
        CdpEndpoint::validate("ws://127.0.0.1:9222", Tunnel::AgentConnector, None).unwrap();
    let dial = CdpDial::Connector {
        hub: Arc::clone(hub),
        agent_id: "assistant".into(),
    };
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        CdpClient::connect_via(&endpoint, &dial),
    )
    .await
    .expect("connect timed out")
    .expect("connect");
    let browser = Browser::new(client);
    let ctx = browser.create_agent_context("assistant").await.unwrap();
    FillEngine::new(browser).fill(&plan(), &ctx, false).await
}

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
                    transport: Transport::Ws,
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
            let n = line.rsplit("hello ").next().unwrap().trim_end_matches(')');
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
    // A ClientHello passes the gate: this was a version refusal.
    assert_eq!(rig.ws.take_refusal_line(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_and_ws_sessions_replace_each_other() {
    let rig = rig().await;
    let detached = |rig: &Rig, transport: Transport| {
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
    eventually("raw replaced", || detached(&rig, Transport::Tls)).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), raw_task)
        .await
        .expect("the evicted raw agent kept its socket");
    assert!(rig.hub.is_connected("assistant"));

    // and back: a raw dial evicts the ws session.
    let raw = raw_dial(&rig);
    let raw_task = tokio::spawn(async move { run_agent_once(&raw).await });
    eventually("ws replaced", || detached(&rig, Transport::Ws)).await;
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
