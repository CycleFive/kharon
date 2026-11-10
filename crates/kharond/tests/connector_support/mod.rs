//! Shared fixtures for the #199 connector-over-WebSocket tests: an
//! in-process kharond public-ingress router with the WebSocket entry and
//! a `Hub` on plain loopback, a CDP stub, and a one-field canary fill.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::api_support::Harness;
use argon2::Argon2;
use futures_util::{SinkExt, StreamExt};
use kharon_connector::Transport as Dial;
use kharond::api::token::{ParamFloor, TUNNEL_PREFIX, TokenStore, generate_tunnel_with};
use kharond::cdp::{
    Browser, CdpClient, CdpDial, CdpEndpoint, FieldFill, FieldKind, FillEngine, FillPlan,
    LiveOrigin, Tunnel, ValuesSent,
};
use kharond::connector::{
    AgentParams, ConnectorEvent, Hub, WsEntry, accept, pin_of_der, server_config_from_pem,
};
use kharond::origin::{OriginConfig, OriginMatcher};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

pub const CANARY: &str = "CANARY-CONNECTOR-WS-FILL-41d7";
pub const URL: &str = "https://example.com/login";

pub fn argon(m_cost: u32, t_cost: u32) -> Argon2<'static> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(m_cost, t_cost, 1, None).unwrap(),
    )
}

pub const FLOOR: ParamFloor = ParamFloor {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

pub struct Cert {
    pub pem_cert: String,
    pub pem_key: String,
    pub der: Vec<u8>,
    pub pin: [u8; 32],
}

pub fn cert() -> Cert {
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
pub async fn cdp_stub() -> (SocketAddr, Arc<Mutex<Vec<Value>>>) {
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

pub fn plan() -> FillPlan {
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

pub struct Rig {
    pub hub: Arc<Hub>,
    pub ws: Arc<WsEntry>,
    pub events: Arc<Mutex<Vec<ConnectorEvent>>>,
    pub token: String,
    pub pin: [u8; 32],
    pub cert_der: Vec<u8>,
    /// `[public_ingress]`, plain loopback.
    pub public: SocketAddr,
    /// The raw listener of the same hub.
    pub raw: SocketAddr,
    pub cdp: SocketAddr,
    pub received: Arc<Mutex<Vec<Value>>>,
    pub _harness: Harness,
}

/// `hash_argon` hashes the tunnel token (and so prices each verify).
pub async fn rig_with(hash_argon: Argon2<'static>) -> Rig {
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

pub async fn rig() -> Rig {
    rig_with(argon(8, 1)).await
}

pub fn ws_dial(rig: &Rig, token: &str) -> AgentParams {
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

pub fn raw_dial(rig: &Rig) -> AgentParams {
    AgentParams {
        transport: Dial::Tls {
            broker: rig.raw,
            host: None,
        },
        ..ws_dial(rig, &rig.token)
    }
}

pub async fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !ok() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn fill_once(hub: &Arc<Hub>) -> kharond::cdp::FillOutcome {
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
