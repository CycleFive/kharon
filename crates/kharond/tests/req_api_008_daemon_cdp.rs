//! REQ-API-008 / REQ-API-009 / REQ-AUD-003† / REQ-ARCH-005 on the
//! daemon's fill path: the broker over [`ConnectingCdpBackend`] built
//! from `[agents.<id>] cdp` exactly as `daemon::start` builds it, against
//! a CDP stub that counts connections.
//!
//! - Startup does no browser I/O; the first fill connects and creates
//!   the agent's browser context, after its `fill_dispatch` entry.
//! - Later fills reuse the connection and context; a connection that
//!   ended is replaced (new context) by the next fill.
//! - The fill deadline bounds the connect and the fill: on expiry the
//!   reply is `timeout`, no further CDP frame is sent, and the audit is
//!   `fill_dispatch` plus exactly one `fill_timeout`.
//! - A failed `fill_dispatch` append opens no connection at all.
//! - An unreachable endpoint is `error`/`cdp_error`, audited once.
//!
//! The browser-level E2E (a real Chromium and form) is #24.

mod api_support;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::{CHEAP_FLOOR, RawResponse, RecordingAudit, cheap_argon, get, post_json};
use futures_util::{SinkExt, StreamExt};
use kharond::api::fill::FillPolicy;
use kharond::api::token::{TokenStore, generate, generate_with};
use kharond::api::{Broker, ConnectingCdpBackend};
use kharond::config::Config;
use kharond::daemon;
use kharond::export::{ExportFile, ExportSession};
use kharond::lock::{LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

const EXPORT: &[u8] = include_bytes!("fixtures/export/password_protected.json");
const EXPORT_PASSWORD: &str = "kharon export fixture password 9";
const CANARY_PASSWORD: &str = "CANARY-EXPORT-PASSWORD-7f3a";
const URL: &str = "https://example.com/login";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Answer everything.
    Normal,
    /// Never answer this method.
    Stall(&'static str),
    /// Close the WebSocket right after answering the in-page fill.
    CloseAfterFill,
}

#[derive(Clone, Default)]
struct Stub {
    connections: Arc<AtomicUsize>,
    frames: Arc<Mutex<Vec<Value>>>,
}

impl Stub {
    fn methods(&self, name: &str) -> usize {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m["method"] == name)
            .count()
    }
    fn frame_count(&self) -> usize {
        self.frames.lock().unwrap().len()
    }
}

/// A CDP peer: every connection gets context `ctx-<n>` from
/// `createBrowserContext`, and page `t1` on `URL` lives in the latest
/// context.
async fn cdp_stub(mode: Mode) -> (String, Stub) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stub = Stub::default();
    let s = stub.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let n = s.connections.fetch_add(1, Ordering::SeqCst) + 1;
            let s = s.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = accept_async(stream).await else {
                    return;
                };
                let ctx = format!("ctx-{n}");
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    s.frames.lock().unwrap().push(msg.clone());
                    let method = msg["method"].as_str().unwrap_or_default().to_owned();
                    if matches!(mode, Mode::Stall(m) if m == method) {
                        continue;
                    }
                    let result = match method.as_str() {
                        "Target.createBrowserContext" => json!({ "browserContextId": ctx }),
                        "Target.getTargetInfo" => json!({ "targetInfo": {
                            "targetId": "t1", "browserContextId": ctx,
                            "url": URL, "title": "", "type": "page",
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
                    if let Some(sid) = msg.get("sessionId") {
                        reply["sessionId"] = sid.clone();
                    }
                    ws.send(Message::Text(reply.to_string())).await.unwrap();
                    if mode == Mode::CloseAfterFill && method == "Runtime.callFunctionOn" {
                        let _ = ws.close(None).await;
                        return;
                    }
                }
            });
        }
    });
    (format!("ws://{addr}/devtools/browser"), stub)
}

/// An export-mode config whose only agent's CDP endpoint is `cdp`.
fn config_toml(hash: &str, data_dir: &Path, cdp: &str) -> String {
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "{cdp}" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"
"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        )
    )
}

struct Run {
    addr: std::net::SocketAddr,
    token: String,
    item_id: String,
    audit: RecordingAudit,
}

/// The broker, unlocked with the export fixture, over the backend the
/// daemon builds from `[agents]`.
async fn run(cdp: &str, deadline: Duration) -> Run {
    let data = tempfile::tempdir().unwrap();
    let cfg = Config::from_toml_str(&config_toml(
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
        data.path(),
        cdp,
    ))
    .unwrap();
    let backend = ConnectingCdpBackend::from_agents(&cfg.agents);

    let session: ExportSession = ExportFile::from_bytes(EXPORT)
        .unwrap()
        .unlock(&Zeroizing::new(EXPORT_PASSWORD.to_owned()))
        .unwrap();
    let item_id = session
        .vault()
        .items()
        .find(|i| i.name() == "Example Login")
        .unwrap()
        .id()
        .to_owned();
    let mut lock = LockController::new(
        LockPolicy::default(),
        Arc::new(ManualClock::new()),
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| Ok::<_, ()>(session)).unwrap();
    let (token, hash) = generate_with(&cheap_argon(), "alpha");
    let tokens = TokenStore::with_floor([("alpha", hash.as_str())], &CHEAP_FLOOR).unwrap();
    let audit = RecordingAudit::default();
    let broker = Broker::new(
        tokens,
        lock,
        Box::new(audit.clone()),
        OriginConfig::default(),
    )
    .with_fill_policy(FillPolicy {
        deadline,
        ..FillPolicy::from(&cfg.policy)
    })
    .with_fill_backend(Box::new(backend));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::http::serve(listener, Arc::new(broker)));
    Run {
        addr,
        token: token.expose_secret().clone(),
        item_id,
        audit,
    }
}

impl Run {
    async fn fill(&self, submit: bool) -> RawResponse {
        let body = json!({
            "item_id": self.item_id,
            "target": {"cdp_target_id": "t1", "expected_origin": "https://example.com"},
            "fields": [{"kind": "username"}, {"kind": "password"}],
            "submit": submit,
        });
        post_json(self.addr, "/v1/fill", Some(&self.token), &body.to_string()).await
    }

    fn entries(&self) -> Vec<Value> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect()
    }
}

fn filled() -> Value {
    json!({"status": "filled", "fields_filled": ["username", "password"]})
}

fn dispatch_then(outcome: &str, result: &str) -> Vec<Value> {
    vec![
        json!([
            "fill_dispatch",
            "alpha",
            "https://example.com",
            "dispatched"
        ]),
        json!([outcome, "alpha", null, result]),
    ]
}

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn req_api_008_daemon_backend_connects_on_first_fill_and_reuses_it() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(stub.connections.load(Ordering::SeqCst), 0, "lazy");

    for (i, submit) in [false, true].into_iter().enumerate() {
        let resp = r.fill(submit).await;
        assert_eq!(resp.status, 200, "{}", resp.body);
        assert_eq!(resp.json(), filled());
        assert!(!resp.body.contains(CANARY_PASSWORD));
        assert_eq!(stub.methods("Runtime.callFunctionOn"), i + 1);
    }
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        stub.methods("Target.createBrowserContext"),
        1,
        "REQ-ARCH-005: one context per agent, created once"
    );
    let mut want = dispatch_then("fill", "filled");
    want.extend(dispatch_then("fill", "filled"));
    assert_eq!(r.audit.summary(), want);
    let text = serde_json::to_string(&r.entries()).unwrap();
    assert!(!text.contains(CANARY_PASSWORD));
}

#[tokio::test]
async fn req_api_008_daemon_backend_reconnects_after_the_browser_drops() {
    let (url, stub) = cdp_stub(Mode::CloseAfterFill).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.fill(false).await.json(), filled());
    // Let the client's read task see the close.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = r.fill(false).await;
    assert_eq!(resp.json(), filled(), "{}", resp.body);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
    assert_eq!(stub.methods("Target.createBrowserContext"), 2);
    assert_eq!(r.audit.summary().len(), 4);
}

/// REQ-API-009 on the daemon path: a stall anywhere (here: in the
/// connect-time context creation, and in the in-page fill) is bounded by
/// `fill_deadline`; nothing is sent after expiry and the audit is one
/// dispatch plus exactly one `fill_timeout`.
#[tokio::test]
async fn req_api_009_daemon_backend_respects_fill_deadline() {
    for stall in ["Target.createBrowserContext", "Runtime.callFunctionOn"] {
        let (url, stub) = cdp_stub(Mode::Stall(stall)).await;
        let r = run(&url, Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        let resp = r.fill(true).await;
        let took = started.elapsed();
        assert_eq!(resp.status, 200, "{stall}: {}", resp.body);
        assert_eq!(
            resp.json(),
            json!({"status": "timeout", "fields_filled": []}),
            "{stall}"
        );
        assert!(took < Duration::from_secs(5), "{stall}: {took:?}");
        let sent = stub.frame_count();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            stub.frame_count(),
            sent,
            "{stall}: no CDP frame after expiry"
        );
        let e = r.entries();
        assert_eq!(e.len(), 2, "{stall}: {e:?}");
        assert_eq!(e[0]["event"], "fill_dispatch");
        assert_eq!(e[1]["event"], "fill_timeout");
        assert_eq!(e[1]["detail_code"], "deadline_expired");
        assert_eq!(e[0]["request_id"], e[1]["request_id"]);
    }
}

/// REQ-AUD-003†: a failed `fill_dispatch` append reaches no browser —
/// not even a connection.
#[tokio::test]
async fn req_aud_003_daemon_backend_failed_dispatch_opens_no_connection() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    *r.audit.fail_event.lock().unwrap() = Some("fill_dispatch");
    let resp = r.fill(true).await;
    assert_eq!(resp.status, 500);
    assert_eq!(resp.json()["error"], "audit_failed");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(stub.connections.load(Ordering::SeqCst), 0);
    assert!(r.audit.summary().is_empty());

    *r.audit.fail_event.lock().unwrap() = None;
    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(r.audit.summary(), dispatch_then("fill", "filled"));
}

#[tokio::test]
async fn req_api_008_daemon_backend_unreachable_browser_is_cdp_error() {
    // Bind then drop: nothing listens on this port.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let r = run(&format!("ws://127.0.0.1:{port}/devtools/browser"), DEADLINE).await;
    let resp = r.fill(false).await;
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(
        resp.json(),
        json!({"status": "error", "fields_filled": [], "detail": "cdp_error"})
    );
    assert_eq!(r.audit.summary(), dispatch_then("fill", "error"));
}

/// `daemon::start` wires the backend without touching the browser: a
/// started daemon has made no CDP connection, and (booted locked,
/// REQ-MEM-005) a fill is 423 before any CDP I/O.
#[tokio::test(flavor = "multi_thread")]
async fn req_api_008_daemon_start_does_not_connect_to_the_browser() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    let data = tempfile::tempdir().unwrap();
    let cfg = Config::from_toml_str(&config_toml(&hash, data.path(), &url)).unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let addr = d.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));
    assert_eq!(get(addr, "/v1/status", Some(&token)).await.status, 200);
    let body = json!({
        "item_id": "00000000-0000-4000-8000-000000000000",
        "target": {"cdp_target_id": "t1", "expected_origin": "https://example.com"},
        "fields": [{"kind": "password"}],
    });
    let r = post_json(addr, "/v1/fill", Some(&token), &body.to_string()).await;
    assert_eq!(r.status, 423, "{}", r.body);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 0);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
