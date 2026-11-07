//! REQ-ARCH-002 / REQ-API-008 path B: fill over the agent connector.
//!
//! The CDP stub listens on an ephemeral loopback port that the broker's
//! endpoint URL does not name (`ws://127.0.0.1:9222`). The only way a
//! fill can reach it is the connector dialing that port. A wrong tunnel
//! credential and a wrong broker pin never open a socket to the stub.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use argon2::Argon2;
use futures_util::{SinkExt, StreamExt};
use kharond::api::token::{ParamFloor, TUNNEL_PREFIX, TokenStore, generate_tunnel_with};
use kharond::cdp::{
    Browser, CdpClient, CdpDial, CdpEndpoint, FieldFill, FieldKind, FillEngine, FillPlan,
    LiveOrigin, Tunnel, ValuesSent,
};
use kharond::connector::{
    AgentParams, ClientError, Hub, accept, pin_of_der, run_agent_once, server_config_from_pem,
};
use kharond::origin::{OriginConfig, OriginMatcher};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

const CANARY: &str = "CANARY-CONNECTOR-FILL-9c2e";
const URL: &str = "https://example.com/login";

fn cheap() -> Argon2<'static> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(8, 1, 1, None).unwrap(),
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
    pin: [u8; 32],
}

fn cert() -> Cert {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    Cert {
        pin: pin_of_der(cert.der()),
        pem_cert: cert.pem(),
        pem_key: key_pair.serialize_pem(),
    }
}

/// CDP stub: `/json/version` then a WebSocket that answers one fill.
/// `hits` counts accepted TCP connections.
async fn cdp_stub() -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<Value>>>,
    Arc<AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicUsize::new(0));
    let rec = Arc::clone(&received);
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            hits2.fetch_add(1, Ordering::SeqCst);
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
    (addr, received, hits)
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
    token: String,
    pin: [u8; 32],
    broker: std::net::SocketAddr,
    cdp: std::net::SocketAddr,
    received: Arc<Mutex<Vec<Value>>>,
    hits: Arc<AtomicUsize>,
}

async fn rig(token_ok: bool) -> Rig {
    let (cdp, received, hits) = cdp_stub().await;
    let (secret, hash) = generate_tunnel_with(&cheap(), "assistant");
    let token = secret.expose_secret().clone();
    let store =
        TokenStore::with_floor_and_prefix([("assistant", hash.as_str())], &FLOOR, TUNNEL_PREFIX)
            .unwrap();
    let hub = Arc::new(Hub::new(store));
    let cert = cert();
    let tls = server_config_from_pem(cert.pem_cert.as_bytes(), cert.pem_key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker = listener.local_addr().unwrap();
    let accept_hub = Arc::clone(&hub);
    tokio::spawn(async move { accept(listener, tls, accept_hub).await });
    let presented = if token_ok {
        token.clone()
    } else {
        format!("{token}nope")
    };
    Rig {
        hub,
        token: presented,
        pin: cert.pin,
        broker,
        cdp,
        received,
        hits,
    }
}

fn agent_params(rig: &Rig, pin: [u8; 32]) -> AgentParams {
    AgentParams {
        broker: rig.broker,
        server_name: "127.0.0.1".into(),
        pin,
        agent_id: "assistant".into(),
        token: Zeroizing::new(rig.token.clone()),
        cdp: rig.cdp,
        proxy: None,
        proxy_creds: None,
    }
}

async fn wait_connected(hub: &Hub) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !hub.is_connected("assistant") {
        if tokio::time::Instant::now() > deadline {
            panic!("connector did not authenticate");
        }
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

#[tokio::test(flavor = "multi_thread")]
async fn req_arch_002_fill_over_agent_connector_and_reconnect() {
    let rig = rig(true).await;
    let stop = Arc::new(AtomicUsize::new(0));
    let stop2 = Arc::clone(&stop);
    let params = agent_params(&rig, rig.pin);
    let agent = tokio::spawn(async move {
        while stop2.load(Ordering::SeqCst) == 0 {
            let _ = run_agent_once(&params).await;
        }
    });
    wait_connected(&rig.hub).await;
    let outcome = fill_once(&rig.hub).await;
    assert_eq!(outcome.status(), "filled", "{outcome:?}");
    assert_eq!(outcome.fields_filled(), vec!["password"]);
    assert!(!outcome.result_body().to_string().contains(CANARY));
    let saw_canary = rig
        .received
        .lock()
        .unwrap()
        .iter()
        .any(|m| m.to_string().contains(CANARY));
    assert!(saw_canary, "the fill did not reach the CDP stub");
    assert!(
        rig.hits.load(Ordering::SeqCst) >= 2,
        "discovery and websocket"
    );

    let before = rig.hits.load(Ordering::SeqCst);
    rig.hub.disconnect("assistant");
    wait_connected(&rig.hub).await;
    let again = fill_once(&rig.hub).await;
    assert_eq!(again.status(), "filled", "{again:?}");
    assert!(rig.hits.load(Ordering::SeqCst) > before);

    stop.store(1, Ordering::SeqCst);
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(2), agent).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_arch_002_bad_connector_creds_do_not_reach_cdp() {
    let rig = rig(false).await;
    let err = run_agent_once(&agent_params(&rig, rig.pin))
        .await
        .unwrap_err();
    assert_eq!(err, ClientError::Unauthorized);
    assert_eq!(rig.hits.load(Ordering::SeqCst), 0);
    assert!(!rig.hub.is_connected("assistant"));
}

#[tokio::test(flavor = "multi_thread")]
async fn req_arch_002_wrong_broker_cert_does_not_reach_cdp() {
    let rig = rig(true).await;
    let other = cert();
    let err = run_agent_once(&agent_params(&rig, other.pin))
        .await
        .unwrap_err();
    assert_eq!(err, ClientError::BadCert);
    assert_eq!(rig.hits.load(Ordering::SeqCst), 0);
}
