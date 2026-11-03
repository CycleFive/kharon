//! REQ-API-008 / REQ-API-007 / REQ-GOAL-001 through the agent API, end
//! to end: HTTP and MCP → broker → [`CdpFillBackend`] → the real
//! `FillEngine` → a CDP stub. The vault is the encrypted export fixture
//! (its login has a password and a TOTP seed), so the broker decrypts
//! real ciphertext per fill.
//!
//! - `submit: true` is `fill_and_submit`: the in-page call is told to
//!   submit; without it, it is not (REQ-API-008).
//! - `fill_totp` types the current code; the response never carries it
//!   (REQ-API-007).
//! - A claimed `expected_origin` that is not the live origin is
//!   `origin_mismatch` before any page code runs (REQ-ORG-002,
//!   REQ-APR-007).
//! - No response or audit entry contains a secret (REQ-GOAL-001).
//!
//! The browser-level E2E (a real Chromium and form) is #24.

mod api_support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use api_support::{
    CHEAP_FLOOR, RawResponse, RecordingAudit, cheap_argon, mcp_call, post_json, raw_request,
};
use futures_util::{SinkExt, StreamExt};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, CdpFillBackend};
use kharond::cdp::{Browser, CdpClient, CdpEndpoint, FillEngine, Tunnel};
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
const TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";
const URL: &str = "https://example.com/login";

type Received = Arc<Mutex<Vec<Value>>>;

/// A CDP peer with one page `t1` on `URL` in context `ctx-A`; acks every
/// in-page fill with the kinds asked for and records every frame.
async fn cdp_stub() -> (String, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received: Received = Arc::default();
    let rec = Arc::clone(&received);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let mut script: HashMap<&str, Value> = HashMap::new();
        script.insert(
            "Target.createBrowserContext",
            json!({ "browserContextId": "ctx-A" }),
        );
        script.insert(
            "Target.getTargetInfo",
            json!({ "targetInfo": {
                "targetId": "t1", "browserContextId": "ctx-A",
                "url": URL, "title": "", "type": "page",
            } }),
        );
        script.insert("Target.attachToTarget", json!({ "sessionId": "sess-1" }));
        script.insert(
            "Page.getFrameTree",
            json!({ "frameTree": { "frame": {
                "id": "f1", "loaderId": "l1", "url": URL,
            }, "childFrames": [] } }),
        );
        script.insert(
            "Page.createIsolatedWorld",
            json!({ "executionContextId": 7 }),
        );
        while let Some(Ok(Message::Text(text))) = ws.next().await {
            let msg: Value = serde_json::from_str(&text).unwrap();
            rec.lock().unwrap().push(msg.clone());
            let method = msg["method"].as_str().unwrap_or_default();
            let result = if method == "Runtime.callFunctionOn" {
                let kinds: Vec<Value> = msg["params"]["arguments"][1]["value"]
                    .as_array()
                    .map(|fs| fs.iter().map(|f| json!({ "kind": f["kind"] })).collect())
                    .unwrap_or_default();
                json!({ "result": { "type": "object", "value": { "results": kinds } } })
            } else {
                script.get(method).cloned().unwrap_or_else(|| json!({}))
            };
            let mut reply = json!({ "id": msg["id"], "result": result });
            if let Some(s) = msg.get("sessionId") {
                reply["sessionId"] = s.clone();
            }
            ws.send(Message::Text(reply.to_string())).await.unwrap();
        }
    });
    (format!("ws://{addr}/devtools/browser"), received)
}

struct E2e {
    addr: std::net::SocketAddr,
    token: String,
    item_id: String,
    audit: RecordingAudit,
    received: Received,
}

async fn e2e() -> E2e {
    let (url, received) = cdp_stub().await;
    let endpoint = CdpEndpoint::validate(&url, Tunnel::Direct, None).unwrap();
    let browser = Browser::new(CdpClient::connect(&endpoint).await.unwrap());
    let ctx = browser.create_agent_context("alpha").await.unwrap();
    let mut backend = CdpFillBackend::new();
    backend.register("alpha", FillEngine::new(browser), ctx);

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
    .with_fill_backend(Box::new(backend));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::http::serve(listener, Arc::new(broker)));
    E2e {
        addr,
        token: token.expose_secret().clone(),
        item_id,
        audit,
        received,
    }
}

impl E2e {
    fn fill_calls(&self) -> Vec<Value> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m["method"] == "Runtime.callFunctionOn")
            .cloned()
            .collect()
    }

    /// `(kind, value)` typed by every in-page call.
    fn typed(&self) -> Vec<(String, String)> {
        self.fill_calls()
            .iter()
            .filter_map(|m| m["params"]["arguments"][1]["value"].as_array().cloned())
            .flatten()
            .map(|f| {
                (
                    f["kind"].as_str().unwrap().to_owned(),
                    f["value"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    fn audit_text(&self) -> String {
        serde_json::to_string(&*self.audit.entries.lock().unwrap()).unwrap()
    }

    async fn fill(&self, path: &str, body: Value) -> RawResponse {
        post_json(self.addr, path, Some(&self.token), &body.to_string()).await
    }
}

fn body(item: &str, fields: Value, submit: bool, origin: &str) -> Value {
    json!({
        "item_id": item,
        "target": {"cdp_target_id": "t1", "expected_origin": origin},
        "fields": fields,
        "submit": submit,
    })
}

/// REQ-GOAL-001: no secret, and nothing but `FillResult` keys.
fn assert_secret_free(text: &str, extra: &[&str]) {
    for s in [CANARY_PASSWORD, TOTP_SEED, EXPORT_PASSWORD]
        .iter()
        .chain(extra)
    {
        assert!(!text.contains(s), "secret in output: {text}");
    }
}

#[tokio::test]
async fn req_api_008_fill_and_submit_dispatches_submit_only_when_asked() {
    for submit in [false, true] {
        let e = e2e().await;
        let fields = json!([{"kind": "username"}, {"kind": "password"}]);
        let r = e
            .fill(
                "/v1/fill",
                body(&e.item_id, fields, submit, "https://example.com"),
            )
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert_eq!(
            r.json(),
            json!({"status": "filled", "fields_filled": ["username", "password"]})
        );
        let calls = e.fill_calls();
        assert_eq!(calls.len(), 1, "one atomic in-page fill");
        assert_eq!(calls[0]["params"]["arguments"][3]["value"], json!(submit));
        assert_eq!(
            e.typed(),
            [
                ("username".into(), "fixture@example.net".into()),
                ("password".into(), CANARY_PASSWORD.into()),
            ],
            "the decrypted values reach the page, and only the page"
        );
        assert_secret_free(&r.body, &[]);
        assert_secret_free(&e.audit_text(), &[]);
        let entries = e.audit.summary();
        assert_eq!(entries, [json!(["fill", "alpha", null, "filled"])]);
    }
}

#[tokio::test]
async fn req_api_007_fill_totp_over_http_types_the_code_and_never_returns_it() {
    let e = e2e().await;
    let r = e
        .fill(
            "/v1/fill_totp",
            json!({
                "item_id": e.item_id,
                "target": {"cdp_target_id": "t1", "expected_origin": "https://example.com"},
            }),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.json(),
        json!({"status": "filled", "fields_filled": ["totp"]})
    );
    let typed = e.typed();
    assert_eq!(typed.len(), 1);
    let (kind, code) = &typed[0];
    assert_eq!(kind, "totp");
    assert!(
        code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
        "{code}"
    );
    assert_secret_free(&r.body, &[code]);
    assert_secret_free(&e.audit_text(), &[code]);
    assert_eq!(
        e.audit.summary(),
        [json!(["fill_totp", "alpha", null, "filled"])]
    );
}

#[tokio::test]
async fn req_api_007_fill_totp_over_mcp_is_the_same_result() {
    let e = e2e().await;
    let args = json!({
        "item_id": e.item_id,
        "target": {"cdp_target_id": "t1", "expected_origin": "https://example.com"},
        "submit": true,
    });
    let r = mcp_call(
        e.addr,
        Some(&e.token),
        "kharon_fill_totp",
        &args.to_string(),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!(v["result"]["isError"], json!(false));
    let inner: Value =
        serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        inner,
        json!({"status": "filled", "fields_filled": ["totp"]})
    );
    let calls = e.fill_calls();
    assert_eq!(calls[0]["params"]["arguments"][3]["value"], json!(true));
    let code = e.typed()[0].1.clone();
    assert_secret_free(&r.body, &[&code]);
}

#[tokio::test]
async fn req_org_002_claimed_origin_differs_from_live_origin_is_refused() {
    // REQ-APR-007: the agent claims A while the tab is on B. The claim
    // can only refuse; it never makes a fill happen elsewhere.
    let e = e2e().await;
    let r = e
        .fill(
            "/v1/fill",
            body(
                &e.item_id,
                json!([{"kind": "password"}]),
                true,
                "https://other.example",
            ),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json(),
        json!({"status": "origin_mismatch", "fields_filled": []})
    );
    assert!(e.fill_calls().is_empty(), "no page code ran");
    assert_eq!(
        e.audit.summary(),
        [json!(["fill", "alpha", null, "origin_mismatch"])]
    );
}

#[tokio::test]
async fn req_api_008_fill_routes_refuse_browser_origins_and_bad_bodies() {
    let e = e2e().await;
    let good = body(
        &e.item_id,
        json!([{"kind": "password"}]),
        false,
        "https://example.com",
    )
    .to_string();
    let send = |headers: String, body: String| {
        let head = format!(
            "POST /v1/fill HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            e.token,
            body.len()
        );
        async move { raw_request(e.addr, head.as_bytes()).await }
    };
    // A browser page (DNS rebinding, a malicious tab) carries Origin.
    let r = send(
        "Origin: https://evil.example\r\nContent-Type: application/json\r\n".into(),
        good.clone(),
    )
    .await;
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (403, json!("forbidden"))
    );
    // Not JSON by content type.
    let r = send("Content-Type: text/plain\r\n".into(), good.clone()).await;
    assert_eq!(r.status, 400);
    assert_eq!(r.json()["detail"], "content type must be application/json");
    // Not JSON at all.
    let r = send("Content-Type: application/json\r\n".into(), "{".into()).await;
    assert_eq!(r.json()["detail"], "request body is not valid JSON");
    // A secret-shaped field is not in the schema.
    let mut extra: Value = serde_json::from_str(&good).unwrap();
    extra["password"] = json!(CANARY_PASSWORD);
    let r = send(
        "Content-Type: application/json\r\n".into(),
        extra.to_string(),
    )
    .await;
    assert_eq!(r.json()["detail"], "fill request does not match the schema");
    assert_secret_free(&r.body, &[]);
    assert!(e.fill_calls().is_empty());
    assert!(e.audit.summary().is_empty(), "refused before the broker");
}
