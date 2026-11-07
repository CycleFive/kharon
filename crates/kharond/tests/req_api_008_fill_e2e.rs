//! REQ-API-008 / REQ-API-007 / REQ-GOAL-001 through the agent API, end
//! to end: HTTP and MCP → broker → [`CdpFillBackend`] → the real
//! `FillEngine` → a CDP stub. The vault is the encrypted export fixture
//! (its login has a password and a TOTP seed), so the broker decrypts
//! real ciphertext per fill.
//!
//! - `submit: true` is `fill_and_submit`: the in-page call is told to
//!   submit; without it, it is not (REQ-API-008). A loader change after
//!   a successful submit is that submit's own navigation (`filled`), not
//!   `navigated` (#102).
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use api_support::{
    CHEAP_FLOOR, RawResponse, RecordingAudit, cheap_argon, mcp_call, post_json, raw_request,
};
use futures_util::{SinkExt, StreamExt};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, CdpFillBackend};
use kharond::cdp::{
    Browser, CdpClient, CdpEndpoint, FieldFill, FieldKind, FillEngine, FillPlan, LiveOrigin,
    Tunnel, ValuesSent,
};
use kharond::export::{ExportFile, ExportSession};
use kharond::lock::{LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::{OriginConfig, OriginMatcher};
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
    cdp_stub_in("ctx-A").await
}

/// [`cdp_stub`] with page `t1` in browser context `t1_context` (the
/// agent's own context is always `ctx-A`).
async fn cdp_stub_in(t1_context: &'static str) -> (String, Received) {
    cdp_stub_opts(t1_context, false).await
}

/// [`cdp_stub`] that drops the socket, unanswered, as soon as the
/// in-page fill call arrives (REQ-APR-008's ambiguous send).
async fn cdp_stub_dropping_fill() -> (String, Received) {
    cdp_stub_opts("ctx-A", true).await
}

async fn cdp_stub_opts(t1_context: &'static str, drop_on_fill: bool) -> (String, Received) {
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
                "targetId": "t1", "browserContextId": t1_context,
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
            if drop_on_fill && method == "Runtime.callFunctionOn" {
                break;
            }
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

/// Like [`cdp_stub`], but the second (and later) `Page.getFrameTree`
/// replies with a new `loaderId`. Models the race where a form submit
/// commits navigation before the post-fill loader re-check (#102).
async fn cdp_stub_loader_changes_after_fill() -> (String, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received: Received = Arc::default();
    let rec = Arc::clone(&received);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let trees = AtomicUsize::new(0);
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
            "Page.createIsolatedWorld",
            json!({ "executionContextId": 7 }),
        );
        while let Some(Ok(Message::Text(text))) = ws.next().await {
            let msg: Value = serde_json::from_str(&text).unwrap();
            rec.lock().unwrap().push(msg.clone());
            let method = msg["method"].as_str().unwrap_or_default();
            let result = if method == "Page.getFrameTree" {
                let n = trees.fetch_add(1, Ordering::SeqCst);
                let loader = if n == 0 { "l1" } else { "l2" };
                json!({ "frameTree": { "frame": {
                    "id": "f1", "loaderId": loader, "url": URL,
                }, "childFrames": [] } })
            } else if method == "Runtime.callFunctionOn" {
                let decl = msg["params"]["functionDeclaration"]
                    .as_str()
                    .unwrap_or_default();
                if decl.contains("clearInPage") {
                    json!({ "result": { "type": "object", "value": { "cleared": true } } })
                } else {
                    let kinds: Vec<Value> = msg["params"]["arguments"][1]["value"]
                        .as_array()
                        .map(|fs| fs.iter().map(|f| json!({ "kind": f["kind"] })).collect())
                        .unwrap_or_default();
                    json!({ "result": { "type": "object", "value": { "results": kinds } } })
                }
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
    e2e_with(cdp_stub().await).await
}

async fn e2e_with((url, received): (String, Received)) -> E2e {
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
    // #20: fills need a grant; the export item has no collections, so
    // seed item-scope grants for both actions.
    {
        let now = kharond::lock::Clock::now(&kharond::lock::SystemClock);
        let terms = kharond::api::GrantTerms {
            scope: kharond::api::GrantScope::Item(item_id.clone()),
            kind: kharond::config::GrantKind::PerOrigin,
            ttl: Some(std::time::Duration::from_secs(24 * 3600)),
            max_uses: None,
        };
        let mut store = broker.grant_store().lock().unwrap();
        for action in [
            kharond::api::GrantAction::Fill,
            kharond::api::GrantAction::Totp,
        ] {
            store
                .issue(
                    "alpha",
                    &item_id,
                    action,
                    "https://example.com",
                    &terms,
                    kharond::api::Channel::Cli,
                    None,
                    now,
                )
                .unwrap();
        }
    }
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
        assert_eq!(
            entries,
            [
                json!([
                    "fill_dispatch",
                    "alpha",
                    "https://example.com",
                    "dispatched"
                ]),
                json!(["fill", "alpha", null, "filled"])
            ]
        );
        // #67: the outcome carries the origin the browser reported
        // (URL is `.../login`; only the origin is recorded).
        assert_eq!(
            e.audit.live_origins(),
            [
                json!(["fill_dispatch", null]),
                json!(["fill", "https://example.com"])
            ]
        );
        assert!(!e.audit_text().contains("/login"));
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
        [
            json!([
                "fill_dispatch",
                "alpha",
                "https://example.com",
                "dispatched"
            ]),
            json!(["fill_totp", "alpha", null, "filled"])
        ]
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
    // #20: the refusal creates an origin_mismatch grant request and
    // the FillResult carries its id (SPEC §4/§5, REQ-APR-007).
    let body = r.json();
    let grid = body["grant_request_id"].as_str().unwrap().to_owned();
    assert!(grid.starts_with("gr_"), "{body}");
    assert_eq!(
        body,
        json!({"status": "origin_mismatch", "fields_filled": [], "grant_request_id": grid})
    );
    assert!(e.fill_calls().is_empty(), "no page code ran");
    // #20 ordering: the grant check runs before any CDP dispatch, so
    // the audit shows the grant_request creation (observed origin,
    // origin_mismatch) and the fill outcome — no fill_dispatch, since
    // no page write was ever dispatched.
    assert_eq!(
        e.audit.summary(),
        [
            json!([
                "grant_request",
                "alpha",
                "https://example.com",
                "origin_mismatch"
            ]),
            json!(["fill", "alpha", null, "origin_mismatch"])
        ]
    );
    // #67: live origin on the outcome.
    assert_eq!(
        e.audit.live_origins()[1],
        json!(["fill", "https://example.com"])
    );
}

/// #67: a target in another browser context is `target_not_owned`, and
/// its page origin is never recorded (no window into another agent's
/// browsing).
#[tokio::test]
async fn req_aud_003_unowned_target_records_no_live_origin() {
    let e = e2e_with(cdp_stub_in("ctx-B").await).await;
    let r = e
        .fill(
            "/v1/fill",
            body(
                &e.item_id,
                json!([{"kind": "password"}]),
                false,
                "https://example.com",
            ),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["status"], "target_not_owned");
    assert!(e.fill_calls().is_empty(), "no page code ran");
    assert_eq!(
        e.audit.live_origins(),
        [json!(["fill_dispatch", null]), json!(["fill", null])]
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

/// REQ-AUD-003† with the real engine: when the `fill_dispatch` append
/// fails, the reply is `audit_failed` and the CDP stub receives not a
/// single frame for the request (no read, no write, no page code).
#[tokio::test]
async fn req_aud_003_failed_dispatch_append_reaches_no_cdp() {
    let e = e2e().await;
    let before = e.received.lock().unwrap().len();
    *e.audit.fail_event.lock().unwrap() = Some("fill_dispatch");
    let r = e
        .fill(
            "/v1/fill",
            body(
                &e.item_id,
                json!([{"kind": "password"}]),
                true,
                "https://example.com",
            ),
        )
        .await;
    assert_eq!(r.status, 500);
    assert_eq!(r.json()["error"], "audit_failed");
    assert_eq!(
        e.received.lock().unwrap().len(),
        before,
        "zero CDP calls after a failed dispatch append"
    );
    assert!(e.audit.summary().is_empty());

    // The log recovers: the next fill dispatches and is audited twice.
    *e.audit.fail_event.lock().unwrap() = None;
    let r = e
        .fill(
            "/v1/fill",
            body(
                &e.item_id,
                json!([{"kind": "password"}]),
                false,
                "https://example.com",
            ),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(e.fill_calls().len(), 1);
    assert_eq!(e.audit.summary().len(), 2);
}

/// #102 / REQ-API-008: a loader change after a successful `submit: true`
/// fill is the submit's own navigation — report `filled` with the
/// fields from the call, and do not scrub via `CLEAR_IN_PAGE`.
#[tokio::test]
async fn req_api_008_submit_true_loader_change_reports_filled() {
    let e = e2e_with(cdp_stub_loader_changes_after_fill().await).await;
    let fields = json!([{"kind": "username"}, {"kind": "password"}]);
    let r = e
        .fill(
            "/v1/fill",
            body(&e.item_id, fields, true, "https://example.com"),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.json(),
        json!({"status": "filled", "fields_filled": ["username", "password"]})
    );
    let calls = e.fill_calls();
    assert_eq!(
        calls.len(),
        1,
        "fill only; no CLEAR_IN_PAGE scrub: {calls:?}"
    );
    assert!(
        calls[0]["params"]["functionDeclaration"]
            .as_str()
            .unwrap()
            .contains("fillInPage"),
        "only the fill call"
    );
    assert_eq!(calls[0]["params"]["arguments"][3]["value"], json!(true));
}

/// #102: the same loader change with `submit: false` is still an
/// unexpected navigation — report `navigated` and attempt the clear.
#[tokio::test]
async fn req_api_008_submit_false_loader_change_reports_navigated() {
    let e = e2e_with(cdp_stub_loader_changes_after_fill().await).await;
    let fields = json!([{"kind": "username"}, {"kind": "password"}]);
    let r = e
        .fill(
            "/v1/fill",
            body(&e.item_id, fields, false, "https://example.com"),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.json(),
        json!({"status": "navigated", "fields_filled": []})
    );
    let calls = e.fill_calls();
    assert_eq!(calls.len(), 2, "fill then CLEAR_IN_PAGE: {calls:?}");
    assert!(
        calls[0]["params"]["functionDeclaration"]
            .as_str()
            .unwrap()
            .contains("fillInPage")
    );
    assert!(
        calls[1]["params"]["functionDeclaration"]
            .as_str()
            .unwrap()
            .contains("clearInPage"),
        "scrub after unexpected navigation"
    );
    assert_eq!(calls[0]["params"]["arguments"][3]["value"], json!(false));
}

/// REQ-APR-008 (#151): the real engine marks `values_sent` only when
/// it sends the in-page fill call that carries the values. A step-1
/// refusal (the claim differs from the live origin) leaves it unset
/// and sends no `Runtime.callFunctionOn`; a fill that lands sets it.
/// The broker gives the grant use back exactly when it is unset.
#[tokio::test]
async fn req_apr_008_engine_marks_values_sent_only_with_the_fill_call() {
    let (url, received) = cdp_stub().await;
    let endpoint = CdpEndpoint::validate(&url, Tunnel::Direct, None).unwrap();
    let browser = Browser::new(CdpClient::connect(&endpoint).await.unwrap());
    let ctx = browser.create_agent_context("alpha").await.unwrap();
    let engine = FillEngine::new(browser);
    let plan = |claim: &str| FillPlan {
        target_id: "t1".into(),
        fields: vec![FieldFill {
            kind: FieldKind::Password,
            selector: None,
            value: Zeroizing::new(CANARY_PASSWORD.into()),
        }],
        item_matchers: vec![OriginMatcher::new(URL, Some(0)).unwrap()],
        origin_cfg: OriginConfig::default(),
        cross_origin_iframe_hosts: Vec::new(),
        submit: false,
        expected_origin: Some(claim.into()),
        live_origin: LiveOrigin::new(),
        deadline: None,
        values_sent: ValuesSent::new(),
    };
    let fill_calls = || {
        received
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m["method"] == "Runtime.callFunctionOn")
            .count()
    };

    let refused = plan("https://other.example");
    let out = engine.fill(&refused, &ctx, false).await;
    assert_eq!(out.status(), "origin_mismatch", "{out:?}");
    assert!(!refused.values_sent.get(), "a step-1 refusal sends nothing");
    assert_eq!(fill_calls(), 0);

    let landed = plan("https://example.com");
    let out = engine.fill(&landed, &ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    assert!(landed.values_sent.get());
    assert_eq!(fill_calls(), 1);
}

/// REQ-APR-008 (#157 review): a send whose delivery is unknown keeps the
/// use spent. The stub drops the socket when the fill call arrives;
/// the fill fails, and `values_sent` is already set because the engine
/// marks it before handing the call to the transport.
#[tokio::test]
async fn req_apr_008_dropped_socket_on_the_fill_call_counts_as_sent() {
    let (url, received) = cdp_stub_dropping_fill().await;
    let endpoint = CdpEndpoint::validate(&url, Tunnel::Direct, None).unwrap();
    let browser = Browser::new(CdpClient::connect(&endpoint).await.unwrap());
    let ctx = browser.create_agent_context("alpha").await.unwrap();
    let plan = FillPlan {
        target_id: "t1".into(),
        fields: vec![FieldFill {
            kind: FieldKind::Password,
            selector: None,
            value: Zeroizing::new(CANARY_PASSWORD.into()),
        }],
        item_matchers: vec![OriginMatcher::new(URL, Some(0)).unwrap()],
        origin_cfg: OriginConfig::default(),
        cross_origin_iframe_hosts: Vec::new(),
        submit: false,
        expected_origin: Some("https://example.com".into()),
        live_origin: LiveOrigin::new(),
        deadline: None,
        values_sent: ValuesSent::new(),
    };
    let out = FillEngine::new(browser).fill(&plan, &ctx, false).await;
    assert_ne!(out.status(), "filled", "{out:?}");
    assert!(
        received
            .lock()
            .unwrap()
            .iter()
            .any(|m| m["method"] == "Runtime.callFunctionOn"),
        "the fill call reached the stub before the drop"
    );
    assert!(plan.values_sent.get(), "an unknown send counts as sent");
}
