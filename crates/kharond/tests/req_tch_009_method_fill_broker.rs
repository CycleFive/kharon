//! REQ-TCH-008 / 009 / 011 (#382): the broker side of a method fill.
//! HTTP -> `Broker` -> `CdpFillBackend` -> the real `FillEngine` -> a
//! CDP stub, with a `TeachRegistry` installed. Covers what the broker
//! adds to the engine's method path: the registry handed to the plan,
//! the rung on the reply and audit entry, the stale mark and the owner
//! notice once on drift, and the rung on approval prompts.

mod api_support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::{CHEAP_FLOOR, RawResponse, RecordingAudit, cheap_argon, post_json};
use futures_util::{SinkExt, StreamExt};
use kharon_recording::{
    Expected, FillRole, Leg, LoginMethod, MethodStep, Provenance, Rung, Shape, Site, SubmitVia,
    SuccessCheck,
};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{
    ApprovalNotifier, ApprovalPrompt, Broker, CdpFillBackend, FillPolicy, GrantTerms,
};
use kharond::cdp::{Browser, CdpClient, CdpEndpoint, FillEngine, Tunnel};
use kharond::export::{ExportFile, ExportSession};
use kharond::lock::{LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::teach::{ImportFlags, LastResult, TeachRegistry};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

const EXPORT: &[u8] = include_bytes!("fixtures/export/password_protected.json");
const EXPORT_PASSWORD: &str = "kharon export fixture password 9";
const CANARY_PASSWORD: &str = "CANARY-EXPORT-PASSWORD-7f3a";
const TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";
const PAGE: &str = "https://example.com/login";
const NOW: &str = "2026-11-24T10:00:00Z";

type Received = Arc<Mutex<Vec<Value>>>;

/// What the stub page does.
#[derive(Clone)]
struct Stub {
    url: &'static str,
    /// `description` of an in-page exception for the method fill call.
    fill_exception: Option<&'static str>,
}

impl Stub {
    fn at(url: &'static str) -> Self {
        Self {
            url,
            fill_exception: None,
        }
    }
}

async fn cdp_stub(stub: Stub) -> (String, Received) {
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
                "url": stub.url, "title": "", "type": "page",
            } }),
        );
        script.insert("Target.attachToTarget", json!({ "sessionId": "sess-1" }));
        script.insert(
            "Page.createIsolatedWorld",
            json!({ "executionContextId": 7 }),
        );
        script.insert(
            "Browser.getVersion",
            json!({ "product": "HeadlessChrome/9" }),
        );
        while let Some(Ok(Message::Text(text))) = ws.next().await {
            let msg: Value = serde_json::from_str(&text).unwrap();
            rec.lock().unwrap().push(msg.clone());
            let method = msg["method"].as_str().unwrap_or_default();
            let mut reply = if method == "Page.getFrameTree" {
                trees.fetch_add(1, Ordering::SeqCst);
                json!({ "id": msg["id"], "result": { "frameTree": { "frame": {
                    "id": "f1", "loaderId": "l1", "url": stub.url,
                }, "childFrames": [] } } })
            } else if method == "Runtime.callFunctionOn" {
                let decl = msg["params"]["functionDeclaration"]
                    .as_str()
                    .unwrap_or_default();
                let value = if decl.contains("function fillInPage") {
                    if let Some(description) = stub.fill_exception {
                        let mut r = json!({ "id": msg["id"], "result": {
                            "exceptionDetails": { "exception": { "description": description } }
                        } });
                        if let Some(s) = msg.get("sessionId") {
                            r["sessionId"] = s.clone();
                        }
                        ws.send(Message::Text(r.to_string())).await.unwrap();
                        continue;
                    }
                    let kinds: Vec<Value> = msg["params"]["arguments"][1]["value"]
                        .as_array()
                        .map(|fs| fs.iter().map(|f| json!({ "kind": f["kind"] })).collect())
                        .unwrap_or_default();
                    json!({ "results": kinds })
                } else if decl.contains("function methodProbe") {
                    json!({ "password_connected": null })
                } else if decl.contains("probeWritten") {
                    json!({ "held": 1 })
                } else if decl.contains("scrubWritten") {
                    let n = msg["params"]["arguments"][0]["value"]
                        .as_array()
                        .map(|a| a.len())
                        .unwrap_or(0);
                    json!({ "cleared": n })
                } else {
                    json!({ "cleared": true })
                };
                json!({ "id": msg["id"], "result": { "result": { "type": "object", "value": value } } })
            } else {
                json!({ "id": msg["id"], "result": script.get(method).cloned().unwrap_or_else(|| json!({})) })
            };
            if let Some(s) = msg.get("sessionId") {
                reply["sessionId"] = s.clone();
            }
            ws.send(Message::Text(reply.to_string())).await.unwrap();
        }
    });
    (format!("ws://{addr}/devtools/browser"), received)
}

/// Records what the broker tells the owner.
#[derive(Default)]
struct Notices {
    prompts: Mutex<Vec<ApprovalPrompt>>,
    drift: Mutex<Vec<(String, u32)>>,
}

impl ApprovalNotifier for Notices {
    fn notify_grant_request(&self, prompt: &ApprovalPrompt, _approve: &str, _deny: &str) {
        self.prompts.lock().unwrap().push(prompt.clone());
    }

    fn notify_method_drift(&self, domain: &str, step: u32) {
        self.drift.lock().unwrap().push((domain.to_owned(), step));
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Grants {
    PerOrigin,
    Once,
    None,
}

struct Rig {
    addr: std::net::SocketAddr,
    token: String,
    item_id: String,
    audit: RecordingAudit,
    received: Received,
    registry: Arc<TeachRegistry>,
    registry_path: std::path::PathBuf,
    notices: Arc<Notices>,
    broker: Arc<Broker<ExportSession, Arc<ManualClock>>>,
    replies: Mutex<Vec<String>>,
    _dir: tempfile::TempDir,
}

fn expect(tag: &str, input_type: Option<&str>) -> Expected {
    Expected {
        tag: tag.into(),
        input_type: input_type.map(Into::into),
        id: None,
        name: None,
        autocomplete: None,
    }
}

fn fill_step(role: FillRole, selector: &str) -> MethodStep {
    MethodStep::Fill {
        role,
        selectors: vec![selector.into()],
        expect: expect(
            "input",
            Some(if role == FillRole::Password {
                "password"
            } else {
                "text"
            }),
        ),
    }
}

/// Username + password + form submit on `/login`.
fn login_method(rung: Rung) -> LoginMethod {
    LoginMethod {
        format_version: 1,
        site: Site {
            domain: "example.com".into(),
            origin: "https://example.com".into(),
            path: "/login".into(),
        },
        shape: Shape::FormPost,
        rung,
        legs: vec![Leg {
            steps: vec![
                MethodStep::Navigate {
                    path: "/login".into(),
                },
                fill_step(FillRole::Username, "#u"),
                fill_step(FillRole::Password, "#pw"),
                MethodStep::Submit {
                    via: SubmitVia::Form {},
                },
            ],
        }],
        success: SuccessCheck::None {},
        provenance: Provenance::HandWritten {
            author: "test".into(),
        },
    }
}

fn policy() -> FillPolicy {
    FillPolicy {
        post_submit_scrub: false,
        post_submit_scrub_delay: Duration::from_millis(20),
        ..FillPolicy::default()
    }
}

/// `method`: the rung to teach for `example.com`, or `None` to leave the
/// registry empty.
async fn rig(stub: Stub, method: Option<Rung>, grants: Grants) -> Rig {
    let (url, received) = cdp_stub(stub).await;
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

    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(TeachRegistry::load(dir.path()).unwrap());
    if let Some(rung) = method {
        registry
            .import(login_method(rung), ImportFlags::default(), NOW)
            .unwrap();
    }
    let notices = Arc::new(Notices::default());
    let broker = Broker::new(
        tokens,
        lock,
        Box::new(audit.clone()),
        OriginConfig::default(),
    )
    .with_fill_backend(Box::new(backend))
    .with_fill_policy(policy())
    .with_teach_registry(Arc::clone(&registry))
    .with_approval_notifier(notices.clone());
    {
        let now = kharond::lock::Clock::now(&kharond::lock::SystemClock);
        let terms = match grants {
            Grants::PerOrigin => Some(kharond::api::GrantTerms {
                scope: kharond::api::GrantScope::Item(item_id.clone()),
                kind: kharond::config::GrantKind::PerOrigin,
                ttl: Some(Duration::from_secs(24 * 3600)),
                max_uses: None,
            }),
            Grants::Once => Some(GrantTerms::once_item(item_id.clone())),
            Grants::None => None,
        };
        if let Some(terms) = terms {
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
    }
    let broker = Arc::new(broker);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::http::serve(listener, Arc::clone(&broker)));
    let registry_path = dir.path().join("teach").join("registry.json");
    Rig {
        addr,
        token: token.expose_secret().clone(),
        item_id,
        audit,
        received,
        registry,
        registry_path,
        notices,
        broker,
        replies: Mutex::default(),
        _dir: dir,
    }
}

impl Rig {
    /// The in-page fill calls.
    fn fill_frames(&self) -> Vec<Value> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|m| {
                m["method"] == "Runtime.callFunctionOn"
                    && m["params"]["functionDeclaration"]
                        .as_str()
                        .is_some_and(|d| d.contains("function fillInPage"))
            })
            .cloned()
            .collect()
    }

    fn audit_values(&self) -> Vec<Value> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|en| serde_json::to_value(en).unwrap())
            .collect()
    }

    fn audit_text(&self) -> String {
        serde_json::to_string(&*self.audit.entries.lock().unwrap()).unwrap()
    }

    /// The fill outcome entries (`fill`), in order.
    fn fill_entries(&self) -> Vec<Value> {
        self.audit_values()
            .into_iter()
            .filter(|v| v["event"] == "fill")
            .collect()
    }

    async fn post(&self, path: &str, body: Value) -> RawResponse {
        let r = post_json(self.addr, path, Some(&self.token), &body.to_string()).await;
        self.replies.lock().unwrap().push(r.body.clone());
        r
    }

    async fn fill(&self, fields: Value, submit: bool) -> RawResponse {
        self.post(
            "/v1/fill",
            json!({
                "item_id": self.item_id,
                "target": {"cdp_target_id": "t1", "expected_origin": "https://example.com"},
                "fields": fields,
                "submit": submit,
            }),
        )
        .await
    }

    async fn login(&self, submit: bool) -> RawResponse {
        self.fill(json!([{"kind": "username"}, {"kind": "password"}]), submit)
            .await
    }

    fn registry_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.registry_path).unwrap()
    }

    fn drift_notices(&self) -> Vec<(String, u32)> {
        self.notices.drift.lock().unwrap().clone()
    }
}

/// REQ-GOAL-001: no secret in anything this file's runs produced.
fn assert_secret_free(text: &str) {
    for s in [CANARY_PASSWORD, TOTP_SEED, EXPORT_PASSWORD] {
        assert!(!text.contains(s), "secret in output: {text}");
    }
}

#[tokio::test]
async fn req_tch_008_drift_marks_stale_audits_the_step_and_notifies_once() {
    let mut stub = Stub::at(PAGE);
    stub.fill_exception = Some("Error: kharon:method_drift:2");
    let r = rig(stub, Some(Rung::Milliseconds), Grants::PerOrigin).await;

    let first = r.login(false).await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(
        first.json(),
        json!({
            "status": "field_not_found", "fields_filled": [],
            "detail": "method_drift", "rung": "milliseconds",
        })
    );
    let entry = r.registry.get("example.com").unwrap();
    assert_eq!(entry.stale.as_ref().map(|s| s.step), Some(2));
    assert_eq!(entry.last_result, Some(LastResult::Drift { step: 2 }));
    let fills = r.fill_entries();
    assert_eq!(fills.len(), 1);
    assert_eq!(fills[0]["result"], "field_not_found");
    assert_eq!(fills[0]["detail_code"], "method_drift");
    assert_eq!(fills[0]["step_index"], 2);
    assert_eq!(fills[0]["rung"], "milliseconds");
    assert_eq!(r.drift_notices(), vec![("example.com".to_owned(), 2)]);
    assert_eq!(r.fill_frames().len(), 1);

    // Stale now: refused before the page, and no second notice.
    let second = r.login(false).await;
    assert_eq!(
        second.json(),
        json!({
            "status": "field_not_found", "fields_filled": [],
            "detail": "method_stale", "rung": "milliseconds",
        })
    );
    assert_eq!(r.fill_frames().len(), 1, "a stale method sends nothing");
    assert_eq!(r.drift_notices().len(), 1);
    assert_eq!(r.fill_entries()[1]["detail_code"], "method_stale");
    assert_secret_free(&r.audit_text());
}

#[tokio::test]
async fn req_tch_008_wrong_page_marks_nothing_and_sends_no_notice() {
    // Same site, a path the method does not cover: refused before any
    // value is sent.
    let r = rig(
        Stub::at("https://example.com/other"),
        Some(Rung::AgentContinues),
        Grants::Once,
    )
    .await;
    let before = r.registry_bytes();
    let reply = r.login(false).await;
    assert_eq!(
        reply.json(),
        json!({
            "status": "field_not_found", "fields_filled": [],
            "detail": "method_wrong_page", "rung": "agent_continues",
        })
    );
    assert_eq!(r.registry_bytes(), before, "the registry file is untouched");
    assert!(r.registry.get("example.com").unwrap().stale.is_none());
    assert!(r.drift_notices().is_empty());
    let events: Vec<String> = r
        .audit_values()
        .iter()
        .map(|v| v["event"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(events, ["fill_dispatch", "fill"]);
    assert!(r.fill_frames().is_empty());
    // No value was sent, so the `once` grant's use came back: the same
    // fill is admitted again rather than asking for a grant.
    let again = r.login(false).await;
    assert_eq!(
        again.json()["detail"],
        "method_wrong_page",
        "{}",
        again.body
    );
}

#[tokio::test]
async fn req_tch_008_not_ready_is_not_stale() {
    let mut stub = Stub::at(PAGE);
    stub.fill_exception = Some("Error: kharon:method_not_ready:1");
    let r = rig(stub, Some(Rung::Milliseconds), Grants::PerOrigin).await;
    let reply = r.login(false).await;
    assert_eq!(
        reply.json(),
        json!({
            "status": "field_not_found", "fields_filled": [],
            "detail": "method_not_ready", "rung": "milliseconds",
        })
    );
    let entry = r.registry.get("example.com").unwrap();
    assert!(entry.stale.is_none());
    assert_eq!(entry.last_result, Some(LastResult::NotReady));
    assert!(r.drift_notices().is_empty());
    let fills = r.fill_entries();
    assert_eq!(fills[0]["detail_code"], "method_not_ready");
    assert_eq!(fills[0]["rung"], "milliseconds");
    assert!(fills[0].get("step_index").is_none(), "{}", fills[0]);
    // The next fill still runs the method.
    let again = r.login(false).await;
    assert_eq!(again.json()["detail"], "method_not_ready");
    assert_eq!(r.fill_frames().len(), 2);
}

#[tokio::test]
async fn req_tch_009_submit_false_still_submits_and_scrubs_on_a_taught_site() {
    let r = rig(Stub::at(PAGE), Some(Rung::Milliseconds), Grants::PerOrigin).await;
    let reply = r
        .post(
            "/v1/fill",
            json!({
                "item_id": r.item_id,
                "target": {"cdp_target_id": "t1", "expected_origin": "https://example.com"},
                "fields": [{"kind": "username"}, {"kind": "password"}],
                "submit": false,
                "post_submit_scrub": false,
            }),
        )
        .await;
    assert_eq!(
        reply.json(),
        json!({
            "status": "filled", "fields_filled": ["username", "password"],
            "rung": "milliseconds",
        })
    );
    let frames = r.fill_frames();
    assert_eq!(frames.len(), 1);
    let leg = &frames[0]["params"]["arguments"][6]["value"];
    assert!(leg.is_object(), "a method leg was sent: {leg}");
    assert_eq!(
        frames[0]["params"]["arguments"][5]["value"],
        json!(true),
        "the fill asks for submit"
    );
    let scrub: Vec<Value> = r
        .audit_values()
        .into_iter()
        .filter(|v| v["event"] == "fill_scrub")
        .collect();
    assert_eq!(scrub.len(), 1, "{:?}", r.audit_values());
    let events: Vec<String> = r
        .audit_values()
        .iter()
        .map(|v| v["event"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(events, ["fill_dispatch", "fill", "fill_scrub"]);
}

#[tokio::test]
async fn req_tch_008_method_selectors_detail() {
    let r = rig(
        Stub::at(PAGE),
        Some(Rung::AgentContinues),
        Grants::PerOrigin,
    )
    .await;
    let with = r
        .fill(
            json!([{"kind": "username", "selector": "#mine"}, {"kind": "password"}]),
            false,
        )
        .await;
    assert_eq!(
        with.json(),
        json!({
            "status": "filled", "fields_filled": ["username", "password"],
            "detail": "method_selectors", "rung": "agent_continues",
        })
    );
    assert_eq!(r.fill_entries()[0]["detail_code"], "method_selectors");
    let without = r.login(false).await;
    assert_eq!(
        without.json(),
        json!({
            "status": "filled", "fields_filled": ["username", "password"],
            "rung": "agent_continues",
        })
    );
    assert!(r.fill_entries()[1].get("detail_code").is_none());
    assert!(!r.audit_text().contains("#mine"));
}

#[tokio::test]
async fn req_tch_011_last_fill_is_recorded() {
    let r = rig(
        Stub::at(PAGE),
        Some(Rung::AgentContinues),
        Grants::PerOrigin,
    )
    .await;
    assert!(
        r.registry
            .get("example.com")
            .unwrap()
            .last_checked
            .is_none()
    );
    let reply = r.login(false).await;
    assert_eq!(reply.json()["status"], "filled", "{}", reply.body);
    let entry = r.registry.get("example.com").unwrap();
    let checked = entry.last_checked.expect("last_checked");
    assert_eq!(checked.browser.as_deref(), Some("HeadlessChrome/9"));
    assert!(
        checked.at.ends_with('Z') && checked.at.len() >= 20,
        "{}",
        checked.at
    );
    assert_ne!(checked.at, NOW, "the time is the fill's, not the import's");
    assert_eq!(entry.last_result, Some(LastResult::Unconfirmed));
    assert!(entry.stale.is_none());
}

#[tokio::test]
async fn untaught_site_fills_as_before() {
    let r = rig(Stub::at(PAGE), None, Grants::PerOrigin).await;
    let reply = r.login(true).await;
    assert_eq!(
        reply.json(),
        json!({"status": "filled", "fields_filled": ["username", "password"]})
    );
    let frames = r.fill_frames();
    assert_eq!(frames.len(), 1);
    assert!(frames[0]["params"]["arguments"][6]["value"].is_null());
    let fills = r.fill_entries();
    assert!(fills[0].get("rung").is_none() && fills[0].get("step_index").is_none());
    assert!(r.drift_notices().is_empty());
}

#[tokio::test]
async fn fill_totp_on_a_taught_site_ignores_the_method() {
    let r = rig(Stub::at(PAGE), Some(Rung::Milliseconds), Grants::PerOrigin).await;
    let reply = r
        .post(
            "/v1/fill_totp",
            json!({
                "item_id": r.item_id,
                "target": {"cdp_target_id": "t1", "expected_origin": "https://example.com"},
            }),
        )
        .await;
    assert_eq!(
        reply.json(),
        json!({"status": "filled", "fields_filled": ["totp"]})
    );
    let frames = r.fill_frames();
    assert_eq!(frames.len(), 1);
    assert!(frames[0]["params"]["arguments"][6]["value"].is_null());
    // A `fill` with only a totp kind is the same.
    let only = r.fill(json!([{"kind": "totp"}]), false).await;
    assert_eq!(
        only.json(),
        json!({"status": "filled", "fields_filled": ["totp"]})
    );
    assert!(
        r.registry
            .get("example.com")
            .unwrap()
            .last_checked
            .is_none()
    );
}

#[tokio::test]
async fn approval_prompt_names_the_rung() {
    let r = rig(Stub::at(PAGE), Some(Rung::Milliseconds), Grants::None).await;
    let reply = r.login(false).await;
    assert_eq!(reply.json()["status"], "pending_approval", "{}", reply.body);
    let prompts = r.notices.prompts.lock().unwrap().clone();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].rung, Some("milliseconds"));
    // The listings the owner reads carry it too.
    let pending = r.broker.pending_grant_requests();
    let listed = r.broker.approval_prompt(&pending[0]).unwrap();
    assert_eq!(listed.rung, Some("milliseconds"));
    assert!(r.fill_frames().is_empty());
}

#[tokio::test]
async fn approval_prompt_has_no_rung_on_an_untaught_site() {
    let r = rig(Stub::at(PAGE), None, Grants::None).await;
    let reply = r.login(false).await;
    assert_eq!(reply.json()["status"], "pending_approval");
    assert_eq!(r.notices.prompts.lock().unwrap()[0].rung, None);
}

#[tokio::test]
async fn no_reply_or_audit_entry_holds_a_secret() {
    let mut stub = Stub::at(PAGE);
    stub.fill_exception = Some("Error: kharon:method_drift:1");
    let r = rig(stub, Some(Rung::Milliseconds), Grants::PerOrigin).await;
    r.login(false).await;
    r.login(true).await;
    r.fill(
        json!([{"kind": "username", "selector": "#mine"}, {"kind": "password"}]),
        false,
    )
    .await;
    for reply in r.replies.lock().unwrap().iter() {
        assert_secret_free(reply);
        assert!(
            !reply.contains("#mine") && !reply.contains("#pw"),
            "{reply}"
        );
    }
    assert_secret_free(&r.audit_text());
    let audit = r.audit_text();
    assert!(
        !audit.contains("#mine") && !audit.contains("#pw"),
        "{audit}"
    );
    let drift = r.drift_notices();
    assert_eq!(drift, vec![("example.com".to_owned(), 1)]);
}
