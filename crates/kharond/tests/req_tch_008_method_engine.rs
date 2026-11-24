//! REQ-TCH-008 / 009 / 011 (#382): the player. When the broker holds a
//! recorded login method for the page's site, a fill runs the method's
//! steps instead of the agent's selectors. These tests drive
//! `FillEngine::fill` against a CDP stub that records every frame.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kharon_recording::{
    Expected, FillRole, Leg, LoginMethod, MethodStep, PasswordLeg, Provenance, Rung, Shape, Site,
    SubmitVia, SuccessCheck,
};
use kharond::cdp::{
    AgentContext, Browser, CdpClient, CdpEndpoint, FieldFill, FieldKind, FillEngine, FillOutcome,
    FillPlan, LiveOrigin, MethodEnd, MethodLookup, MethodNote, MethodResult, MethodSource,
    ScrubNote, Tunnel, ValuesSent,
};
use kharond::origin::{OriginConfig, OriginMatcher};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

const PAGE: &str = "https://example.com/login";
const USER_CANARY: &str = "CANARY-USER-4b1d";
const PW_CANARY: &str = "CANARY-PASSWORD-9e2c";

type Received = Arc<Mutex<Vec<Value>>>;

/// What the stub page does.
#[derive(Clone)]
struct Stub {
    url: &'static str,
    /// `(loaderId, url)` for the nth `Page.getFrameTree`; the last repeats.
    trees: Vec<(&'static str, &'static str)>,
    /// `description` of an in-page exception for the fill call.
    fill_exception: Option<&'static str>,
    /// What `methodProbe` reports.
    pw_connected: Option<bool>,
}

impl Stub {
    fn at(url: &'static str) -> Self {
        Self {
            url,
            trees: vec![("l1", url)],
            fill_exception: None,
            pw_connected: None,
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
                let n = trees
                    .fetch_add(1, Ordering::SeqCst)
                    .min(stub.trees.len() - 1);
                let (loader, url) = stub.trees[n];
                json!({ "id": msg["id"], "result": { "frameTree": { "frame": {
                    "id": "f1", "loaderId": loader, "url": url,
                }, "childFrames": [] } } })
            } else if method == "Runtime.callFunctionOn" {
                let decl = msg["params"]["functionDeclaration"]
                    .as_str()
                    .unwrap_or_default();
                let value = if decl.contains("function fillInPage") {
                    if let Some(description) = stub.fill_exception {
                        let r = json!({ "id": msg["id"], "result": {
                            "exceptionDetails": { "exception": { "description": description } }
                        } });
                        let mut r = r;
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
                    json!({ "password_connected": stub.pw_connected })
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

struct Rig {
    engine: FillEngine,
    ctx: AgentContext,
    received: Received,
}

async fn rig(stub: Stub) -> Rig {
    let (url, received) = cdp_stub(stub).await;
    let endpoint = CdpEndpoint::validate(&url, Tunnel::Direct, None).unwrap();
    let browser = Browser::new(CdpClient::connect(&endpoint).await.unwrap());
    let ctx = browser.create_agent_context("alpha").await.unwrap();
    Rig {
        engine: FillEngine::new(browser),
        ctx,
        received,
    }
}

impl Rig {
    fn frames(&self, method: &str) -> Vec<Value> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m["method"] == method)
            .cloned()
            .collect()
    }

    fn fill_frames(&self) -> Vec<Value> {
        self.frames("Runtime.callFunctionOn")
            .into_iter()
            .filter(|m| {
                m["params"]["functionDeclaration"]
                    .as_str()
                    .is_some_and(|d| d.contains("function fillInPage"))
            })
            .collect()
    }

    fn all_text(&self) -> String {
        serde_json::to_string(&*self.received.lock().unwrap()).unwrap()
    }
}

/// A source that records the URLs it is asked about.
#[derive(Debug)]
struct FixedSource {
    lookup: Option<MethodLookup>,
    asked: Mutex<Vec<String>>,
}

impl FixedSource {
    fn new(lookup: Option<MethodLookup>) -> Arc<Self> {
        Arc::new(Self {
            lookup,
            asked: Mutex::default(),
        })
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

impl MethodSource for FixedSource {
    fn lookup(&self, live_url: &str) -> Option<MethodLookup> {
        self.asked.lock().unwrap().push(live_url.to_owned());
        self.lookup.clone()
    }
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

fn navigate(path: &str) -> MethodStep {
    MethodStep::Navigate { path: path.into() }
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

fn submit_step(via: SubmitVia) -> MethodStep {
    MethodStep::Submit { via }
}

fn method(
    shape: Shape,
    rung: Rung,
    legs: Vec<Vec<MethodStep>>,
    success: SuccessCheck,
) -> LoginMethod {
    LoginMethod {
        format_version: 1,
        site: Site {
            domain: "example.com".into(),
            origin: "https://example.com".into(),
            path: "/login".into(),
        },
        shape,
        rung,
        legs: legs.into_iter().map(|steps| Leg { steps }).collect(),
        success,
        provenance: Provenance::HandWritten {
            author: "test".into(),
        },
    }
}

/// Username + password + form submit on `/login`.
fn one_leg(rung: Rung, success: SuccessCheck) -> LoginMethod {
    method(
        Shape::FormPost,
        rung,
        vec![vec![
            navigate("/login"),
            fill_step(FillRole::Username, "#u"),
            fill_step(FillRole::Password, "#pw"),
            submit_step(SubmitVia::Form {}),
        ]],
        success,
    )
}

/// Leg 0: username on `/login`; leg 1: password on `/password`.
fn two_step() -> LoginMethod {
    method(
        Shape::TwoStep {
            password_leg: PasswordLeg::FormPost,
        },
        Rung::AgentContinues,
        vec![
            vec![
                navigate("/login"),
                fill_step(FillRole::Username, "#u"),
                submit_step(SubmitVia::Enter {}),
            ],
            vec![
                navigate("/password"),
                fill_step(FillRole::Password, "#pw"),
                submit_step(SubmitVia::Form {}),
            ],
        ],
        SuccessCheck::None {},
    )
}

fn lookup(m: LoginMethod) -> MethodLookup {
    MethodLookup {
        domain: "example.com".into(),
        method: Arc::new(m),
        overrides: BTreeMap::new(),
        stale: false,
    }
}

fn field(kind: FieldKind, selector: Option<&str>, value: &str) -> FieldFill {
    FieldFill {
        kind,
        selector: selector.map(Into::into),
        value: Zeroizing::new(value.into()),
    }
}

fn both_fields() -> Vec<FieldFill> {
    vec![
        field(FieldKind::Username, None, USER_CANARY),
        field(FieldKind::Password, None, PW_CANARY),
    ]
}

fn plan(
    fields: Vec<FieldFill>,
    source: Option<Arc<FixedSource>>,
    submit: bool,
    scrub: bool,
) -> FillPlan {
    FillPlan {
        target_id: "t1".into(),
        fields,
        item_matchers: vec![OriginMatcher::new("https://example.com/login", Some(0)).unwrap()],
        origin_cfg: OriginConfig::default(),
        cross_origin_iframe_hosts: Vec::new(),
        submit,
        expected_origin: None,
        live_origin: LiveOrigin::new(),
        deadline: None,
        values_sent: ValuesSent::new(),
        post_submit_scrub: scrub,
        post_submit_scrub_delay: Duration::from_millis(20),
        scrub: ScrubNote::new(),
        method_source: source.map(|s| s as Arc<dyn MethodSource>),
        method: MethodNote::new(),
    }
}

fn arg(frame: &Value, i: usize) -> &Value {
    &frame["params"]["arguments"][i]["value"]
}

#[tokio::test]
async fn req_tch_008_lookup_uses_the_live_url_not_the_claim() {
    let rig = rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(Some(lookup(one_leg(
        Rung::AgentContinues,
        SuccessCheck::None {},
    ))));
    let mut p = plan(both_fields(), Some(source.clone()), false, false);
    p.expected_origin = Some("https://example.com".into());
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    assert_eq!(source.asked(), vec![PAGE.to_owned()]);
}

#[tokio::test]
async fn req_tch_008_agent_selectors_never_reach_the_page() {
    let rig = rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(Some(lookup(one_leg(
        Rung::AgentContinues,
        SuccessCheck::None {},
    ))));
    let p = plan(
        vec![
            field(FieldKind::Username, Some("#agent-user"), USER_CANARY),
            field(FieldKind::Password, Some("#agent-pw"), PW_CANARY),
        ],
        Some(source),
        false,
        false,
    );
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    let frames = rig.fill_frames();
    assert_eq!(frames.len(), 1);
    let fields = arg(&frames[0], 1).as_array().unwrap();
    assert_eq!(fields.len(), 2);
    assert!(fields.iter().all(|f| f["selector"].is_null()), "{fields:?}");
    let leg = arg(&frames[0], 6);
    assert_eq!(leg["fills"][0]["selectors"], json!(["#u"]));
    assert_eq!(leg["fills"][1]["selectors"], json!(["#pw"]));
    assert!(
        !rig.all_text().contains("#agent"),
        "no frame carries the agent's selector"
    );
    let used = p.method.get().expect("a method note");
    assert!(used.selectors_ignored);
    assert!(matches!(used.end, MethodEnd::Filled(_)));
}

#[tokio::test]
async fn req_tch_008_overrides_are_tried_first() {
    let rig = rig(Stub::at(PAGE)).await;
    let mut l = lookup(one_leg(Rung::AgentContinues, SuccessCheck::None {}));
    // Step 1 is the username fill (step 0 is the navigate).
    l.overrides.insert(1, vec!["#owner-user".into()]);
    let source = FixedSource::new(Some(l));
    let p = plan(both_fields(), Some(source), false, false);
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    let leg = arg(&rig.fill_frames()[0], 6).clone();
    assert_eq!(leg["fills"][0]["index"], 1);
    assert_eq!(leg["fills"][0]["selectors"], json!(["#owner-user", "#u"]));
    assert_eq!(leg["fills"][1]["selectors"], json!(["#pw"]));
    assert_eq!(leg["submit"]["index"], 3);
    assert_eq!(leg["submit"]["via"], "form");
}

#[tokio::test]
async fn req_tch_008_wrong_page_sends_nothing() {
    let rig = rig(Stub::at("https://example.com/")).await;
    let source = FixedSource::new(Some(lookup(one_leg(
        Rung::Milliseconds,
        SuccessCheck::None {},
    ))));
    let p = plan(both_fields(), Some(source), true, false);
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out, FillOutcome::MethodWrongPage);
    assert_eq!(out.status(), "field_not_found");
    assert_eq!(out.detail(), Some("method_wrong_page"));
    assert!(rig.frames("Runtime.callFunctionOn").is_empty());
    assert!(!p.values_sent.get());
    assert_eq!(p.method.get().unwrap().end, MethodEnd::WrongPage);
    assert!(!rig.all_text().contains(PW_CANARY));
}

#[tokio::test]
async fn req_tch_008_sibling_origin_is_wrong_page() {
    // Same registrable domain, different origin: the method belongs to
    // `https://example.com`.
    let rig = rig(Stub::at("https://evil.example.com/login")).await;
    let source = FixedSource::new(Some(lookup(one_leg(
        Rung::Milliseconds,
        SuccessCheck::None {},
    ))));
    let p = plan(both_fields(), Some(source), true, false);
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out, FillOutcome::MethodWrongPage);
    assert!(rig.frames("Runtime.callFunctionOn").is_empty());
    assert!(!p.values_sent.get());
    assert_eq!(p.method.get().unwrap().end, MethodEnd::WrongPage);
}

#[tokio::test]
async fn req_tch_008_stale_entry_refuses_before_any_page_call() {
    let rig = rig(Stub::at(PAGE)).await;
    let mut l = lookup(one_leg(Rung::Milliseconds, SuccessCheck::None {}));
    l.stale = true;
    let p = plan(both_fields(), Some(FixedSource::new(Some(l))), true, false);
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out, FillOutcome::MethodStale);
    assert_eq!(out.detail(), Some("method_stale"));
    assert!(rig.frames("Runtime.callFunctionOn").is_empty());
    assert!(rig.frames("Target.attachToTarget").is_empty());
    assert!(!p.values_sent.get());
    assert_eq!(p.method.get().unwrap().end, MethodEnd::Stale);
}

#[tokio::test]
async fn req_tch_008_field_not_requested() {
    let rig = rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(Some(lookup(one_leg(
        Rung::AgentContinues,
        SuccessCheck::None {},
    ))));
    let p = plan(
        vec![field(FieldKind::Password, None, PW_CANARY)],
        Some(source),
        true,
        false,
    );
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out, FillOutcome::MethodFieldNotRequested);
    assert_eq!(out.detail(), Some("method_field_not_requested"));
    assert!(rig.frames("Runtime.callFunctionOn").is_empty());
    assert!(!p.values_sent.get());
    assert_eq!(p.method.get().unwrap().end, MethodEnd::FieldNotRequested);
    assert!(!rig.all_text().contains(PW_CANARY));
}

#[tokio::test]
async fn req_tch_008_extra_requested_kind_is_not_sent() {
    let rig = rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(Some(lookup(two_step())));
    let p = plan(both_fields(), Some(source), false, false);
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(
        out,
        FillOutcome::Filled {
            kinds: vec![FieldKind::Username]
        }
    );
    let frames = rig.fill_frames();
    assert_eq!(arg(&frames[0], 1).as_array().unwrap().len(), 1);
    let text = rig.all_text();
    assert!(text.contains(USER_CANARY));
    assert!(!text.contains(PW_CANARY), "the password is not this leg's");
}

#[tokio::test]
async fn req_tch_008_in_page_codes_map() {
    for (description, want, end) in [
        (
            "Error: kharon:method_drift:2",
            FillOutcome::MethodDrift { step: 2 },
            MethodEnd::Drift { step: 2 },
        ),
        (
            "Error: kharon:method_not_ready:1",
            FillOutcome::MethodNotReady { step: 1 },
            MethodEnd::NotReady { step: 1 },
        ),
        (
            "Error: kharon:method_wrong_page",
            FillOutcome::MethodWrongPage,
            MethodEnd::WrongPage,
        ),
        (
            "Error: kharon:method_drift:x",
            FillOutcome::MethodDrift { step: 0 },
            MethodEnd::Drift { step: 0 },
        ),
    ] {
        let mut stub = Stub::at(PAGE);
        stub.fill_exception = Some(description);
        let rig = rig(stub).await;
        let source = FixedSource::new(Some(lookup(one_leg(
            Rung::Milliseconds,
            SuccessCheck::None {},
        ))));
        let p = plan(both_fields(), Some(source), true, false);
        let out = rig.engine.fill(&p, &rig.ctx, false).await;
        assert_eq!(out, want, "{description}");
        assert_eq!(out.status(), "field_not_found");
        let used = p.method.get().unwrap();
        assert_eq!(used.end, end);
        assert_eq!(used.browser_product.as_deref(), Some("HeadlessChrome/9"));
        assert_eq!(used.domain, "example.com");
        assert!(p.values_sent.get());
    }
}

#[tokio::test]
async fn req_tch_009_milliseconds_forces_submit_and_scrub() {
    let rig = rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(Some(lookup(one_leg(
        Rung::Milliseconds,
        SuccessCheck::None {},
    ))));
    let p = plan(both_fields(), Some(source), false, false);
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    let frames = rig.fill_frames();
    assert_eq!(arg(&frames[0], 3), &json!(true), "submit is forced");
    assert_eq!(arg(&frames[0], 5), &json!(true), "scrub is forced");
}

#[tokio::test]
async fn req_tch_009_agent_continues_one_leg_keeps_the_requests_submit() {
    let rig1 = rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(Some(lookup(one_leg(
        Rung::AgentContinues,
        SuccessCheck::None {},
    ))));
    let p = plan(both_fields(), Some(source), false, false);
    let out = rig1.engine.fill(&p, &rig1.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    let frames = rig1.fill_frames();
    assert_eq!(arg(&frames[0], 3), &json!(false));
    assert_eq!(arg(&frames[0], 5), &json!(false));
    assert!(
        arg(&frames[0], 6)["submit"].is_object(),
        "the leg's submit is always sent"
    );

    let rig2 = self::rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(Some(lookup(two_step())));
    let p = plan(
        vec![field(FieldKind::Username, None, USER_CANARY)],
        Some(source),
        false,
        false,
    );
    let out = rig2.engine.fill(&p, &rig2.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    let frames = rig2.fill_frames();
    assert_eq!(
        arg(&frames[0], 3),
        &json!(true),
        "a two-step leg always submits"
    );
    // The username leg has no password step: no forced scrub.
    assert_eq!(arg(&frames[0], 5), &json!(false));
}

#[tokio::test]
async fn req_tch_011_success_is_read_once_after_the_delay() {
    // The page navigated to /home by the time of the check.
    let mut stub = Stub::at(PAGE);
    stub.trees = vec![("l1", PAGE), ("l2", "https://example.com/home")];
    let rig_nav = rig(stub).await;
    let m = one_leg(
        Rung::Milliseconds,
        SuccessCheck::PathChangedTo {
            path: "/home".into(),
        },
    );
    let p = plan(
        both_fields(),
        Some(FixedSource::new(Some(lookup(m)))),
        true,
        false,
    );
    let out = rig_nav.engine.fill(&p, &rig_nav.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    assert_eq!(
        p.method.get().unwrap().end,
        MethodEnd::Filled(MethodResult::Succeeded)
    );
    assert_eq!(
        rig_nav.frames("Page.getFrameTree").len(),
        2,
        "the expected path at the first read needs no further read"
    );

    // Same document: unconfirmed, the probe and the scrub both run, one re-read.
    let mut stub = Stub::at(PAGE);
    stub.pw_connected = Some(true);
    let rig_same = rig(stub).await;
    let m = one_leg(
        Rung::Milliseconds,
        SuccessCheck::PathChangedTo {
            path: "/home".into(),
        },
    );
    let p = plan(
        both_fields(),
        Some(FixedSource::new(Some(lookup(m)))),
        true,
        false,
    );
    let out = rig_same.engine.fill(&p, &rig_same.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    assert_eq!(
        p.method.get().unwrap().end,
        MethodEnd::Filled(MethodResult::Unconfirmed)
    );
    // Before the fill, the step-4 check, and exactly one delayed re-read.
    assert_eq!(rig_same.frames("Page.getFrameTree").len(), 3);
    let calls: Vec<String> = rig_same
        .frames("Runtime.callFunctionOn")
        .iter()
        .map(|f| {
            f["params"]["functionDeclaration"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(
        !calls.iter().any(|d| d.contains("function methodProbe")),
        "a path check sends no probe"
    );
    assert!(
        calls.iter().any(|d| d.contains("scrubWritten")),
        "the forced scrub ran"
    );

    // Password field still in the document after the submit: failed.
    let mut stub = Stub::at(PAGE);
    stub.pw_connected = Some(true);
    let rig_pw = rig(stub).await;
    let m = one_leg(Rung::Milliseconds, SuccessCheck::PasswordFieldGone {});
    let p = plan(
        both_fields(),
        Some(FixedSource::new(Some(lookup(m)))),
        true,
        false,
    );
    let out = rig_pw.engine.fill(&p, &rig_pw.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    assert_eq!(
        p.method.get().unwrap().end,
        MethodEnd::Filled(MethodResult::Failed)
    );
}

#[tokio::test]
async fn req_tch_011_a_fill_that_did_not_submit_is_unconfirmed() {
    let rig = rig(Stub::at(PAGE)).await;
    let m = one_leg(Rung::AgentContinues, SuccessCheck::PasswordFieldGone {});
    let p = plan(
        both_fields(),
        Some(FixedSource::new(Some(lookup(m)))),
        false,
        false,
    );
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    assert_eq!(
        p.method.get().unwrap().end,
        MethodEnd::Filled(MethodResult::Unconfirmed)
    );
    assert_eq!(
        rig.frames("Page.getFrameTree").len(),
        2,
        "no delayed re-read"
    );
}

#[tokio::test]
async fn totp_only_fill_never_asks_the_source() {
    let rig = rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(Some(lookup(one_leg(
        Rung::Milliseconds,
        SuccessCheck::None {},
    ))));
    let p = plan(
        vec![field(FieldKind::Totp, None, "123456")],
        Some(source.clone()),
        false,
        false,
    );
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    assert!(source.asked().is_empty());
    assert!(p.method.get().is_none());
    assert!(arg(&rig.fill_frames()[0], 6).is_null());
}

#[tokio::test]
async fn plan_without_a_source_sends_a_null_leg() {
    let rig = rig(Stub::at(PAGE)).await;
    let p = plan(
        vec![field(FieldKind::Password, Some("#own"), PW_CANARY)],
        None,
        false,
        false,
    );
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    let frames = rig.fill_frames();
    assert_eq!(frames.len(), 1);
    assert!(arg(&frames[0], 6).is_null());
    assert_eq!(arg(&frames[0], 1)[0]["selector"], "#own");
    assert!(p.method.get().is_none());
    assert!(rig.frames("Browser.getVersion").is_empty());
}

#[tokio::test]
async fn a_site_without_an_entry_takes_the_normal_path() {
    let rig = rig(Stub::at(PAGE)).await;
    let source = FixedSource::new(None);
    let p = plan(
        vec![field(FieldKind::Password, Some("#own"), PW_CANARY)],
        Some(source.clone()),
        false,
        false,
    );
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    assert_eq!(source.asked().len(), 1);
    assert!(arg(&rig.fill_frames()[0], 6).is_null());
    assert!(p.method.get().is_none());
}

async fn redirect_case(
    trees: Vec<(&'static str, &'static str)>,
) -> (MethodEnd, usize, (), Vec<String>) {
    let mut stub = Stub::at(PAGE);
    stub.trees = trees;
    let rig = rig(stub).await;
    let m = one_leg(
        Rung::Milliseconds,
        SuccessCheck::PathChangedTo {
            path: "/home".into(),
        },
    );
    let p = plan(
        both_fields(),
        Some(FixedSource::new(Some(lookup(m)))),
        true,
        false,
    );
    let out = rig.engine.fill(&p, &rig.ctx, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    let calls = rig
        .frames("Runtime.callFunctionOn")
        .iter()
        .map(|f| {
            f["params"]["functionDeclaration"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    (
        p.method.get().unwrap().end,
        rig.frames("Page.getFrameTree").len(),
        (),
        calls,
    )
}

#[tokio::test]
async fn req_tch_011_an_intermediate_hop_is_not_judged() {
    // New loader at /sso on the first read, /home at the delayed one.
    let (end, trees, _, calls) = redirect_case(vec![
        ("l1", PAGE),
        ("l2", "https://example.com/sso"),
        ("l2", "https://example.com/home"),
    ])
    .await;
    assert_eq!(end, MethodEnd::Filled(MethodResult::Succeeded));
    assert_eq!(trees, 3, "one delayed re-read");
    assert!(
        !calls
            .iter()
            .any(|d| d.contains("scrubWritten") || d.contains("probeWritten")),
        "a navigated page is not scrubbed"
    );

    // Still /sso after the delay: the login did not land.
    let (end, trees, _, _) =
        redirect_case(vec![("l1", PAGE), ("l2", "https://example.com/sso")]).await;
    assert_eq!(end, MethodEnd::Filled(MethodResult::Failed));
    assert_eq!(trees, 3);
}

#[tokio::test]
async fn a_check_nothing_can_use_skips_the_wait_and_the_probe() {
    let rig1 = rig(Stub::at(PAGE)).await;
    let m = one_leg(Rung::Milliseconds, SuccessCheck::None {});
    // Milliseconds forces the scrub, which needs the re-read: it runs, the probe does not.
    let p = plan(
        both_fields(),
        Some(FixedSource::new(Some(lookup(m)))),
        true,
        false,
    );
    rig1.engine.fill(&p, &rig1.ctx, false).await;
    assert_eq!(
        p.method.get().unwrap().end,
        MethodEnd::Filled(MethodResult::Unconfirmed)
    );
    assert!(!rig1.frames("Runtime.callFunctionOn").iter().any(|f| {
        f["params"]["functionDeclaration"]
            .as_str()
            .unwrap()
            .contains("function methodProbe")
    }));

    // A path check on a submit-less (AgentContinues, no submit) fill reads nothing,
    // and with no scrub there is no re-read for a `None` check either.
    let rig2 = rig(Stub::at(PAGE)).await;
    let m = one_leg(Rung::AgentContinues, SuccessCheck::None {});
    let p = plan(
        both_fields(),
        Some(FixedSource::new(Some(lookup(m)))),
        true,
        false,
    );
    rig2.engine.fill(&p, &rig2.ctx, false).await;
    assert_eq!(
        rig2.frames("Page.getFrameTree").len(),
        2,
        "no wait, no re-read"
    );
}
