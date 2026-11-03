//! REQ-AUD-003† (#62): a fill that reaches the browser is two audited
//! transitions, through [`Broker::fill`] (shared by HTTP and MCP).
//!
//! - `fill_dispatch` (request id, item, claimed origin, field count; no
//!   value) is appended before the backend sees the plan. If that
//!   append fails the reply is `audit_failed` and the backend (and so
//!   CDP) is never called; the plan is still wiped.
//! - Exactly one outcome entry with the same `request_id` follows; if
//!   its append fails the reply is `audit_failed`.
//! - If the fill future is dropped mid-fill (client disconnect), the
//!   plan is wiped and a best-effort `fill_aborted` is appended.
//!
//! The CDP-stub variant of "no CDP write on audit failure" is in
//! `req_api_008_fill_e2e.rs`.

mod api_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::*;
use kharond::api::fill::{FillOperation, parse_fill};
use kharond::api::{ApiError, Outcome};
use serde_json::{Value, json};
use tokio::time::Instant;

const ORIGIN: &str = "https://login.example.com";

fn body() -> String {
    json!({
        "item_id": ITEM_A,
        "target": {"cdp_target_id": "T-1", "expected_origin": ORIGIN},
        "fields": [{"kind": "username"}, {"kind": "password"}],
    })
    .to_string()
}

struct Run {
    h: Harness,
    fake: FakeFill,
    wiped: Arc<Mutex<Vec<String>>>,
}

fn harness(answer: FakeAnswer) -> Run {
    let fake = FakeFill::new(answer);
    let wiped: Arc<Mutex<Vec<String>>> = Arc::default();
    let (f, w) = (fake.clone(), wiped.clone());
    let h = Harness::with(false, move |b| {
        b.with_fill_backend(Box::new(f))
            .with_plan_wiped_hook(Arc::new(move |plan| {
                w.lock()
                    .unwrap()
                    .extend(plan.fields.iter().map(|f| (*f.value).clone()));
            }))
    });
    Run { h, fake, wiped }
}

async fn fill(r: &Run) -> Result<Value, ApiError> {
    let agent = r.h.broker.authenticate(&r.h.alpha).unwrap();
    let req = parse_fill(FillOperation::Fill, body().as_bytes()).unwrap();
    r.h.broker
        .fill(&agent, req, Instant::now())
        .await
        .map(|o| match o {
            Outcome::Fill(f) => serde_json::to_value(f).unwrap(),
            other => panic!("not a fill result: {:?}", other.body()),
        })
}

fn entries(r: &Run) -> Vec<Value> {
    r.h.audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect()
}

fn assert_wiped(r: &Run) {
    let wiped = r.wiped.lock().unwrap().clone();
    assert_eq!(wiped.len(), 2, "the hook saw both values");
    assert!(wiped.iter().all(String::is_empty), "plan zeroized");
}

fn assert_dispatch(e: &Value) {
    assert_eq!(e["event"], "fill_dispatch");
    assert_eq!(e["agent_id"], "alpha");
    assert_eq!(e["item_id"], ITEM_A);
    assert_eq!(e["origin"], ORIGIN);
    assert_eq!(e["field_count"], 2);
    assert_eq!(e["result"], "dispatched");
    let rid = e["request_id"].as_str().unwrap();
    assert_eq!(rid.len(), 32);
    assert!(rid.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[tokio::test]
async fn req_aud_003_dispatch_entry_precedes_exactly_one_outcome() {
    let r = harness(FakeAnswer::Filled);
    let out = fill(&r).await.unwrap();
    assert_eq!(out["status"], "filled");
    let e = entries(&r);
    assert_eq!(e.len(), 2, "{e:?}");
    assert_dispatch(&e[0]);
    assert_eq!(e[1]["event"], "fill");
    assert_eq!(e[1]["result"], "filled");
    assert_eq!(e[1]["request_id"], e[0]["request_id"]);
    assert_no_canary(&serde_json::to_string(&e).unwrap());
    assert_wiped(&r);

    // A second fill gets a fresh request id.
    fill(&r).await.unwrap();
    let e = entries(&r);
    assert_eq!(e.len(), 4);
    assert_ne!(e[2]["request_id"], e[0]["request_id"]);
    assert_eq!(e[2]["request_id"], e[3]["request_id"]);
}

#[tokio::test]
async fn req_aud_003_dispatch_append_failure_means_no_backend_call() {
    let r = harness(FakeAnswer::Filled);
    *r.h.audit.fail_event.lock().unwrap() = Some("fill_dispatch");
    assert_eq!(fill(&r).await, Err(ApiError::AUDIT_FAILED));
    assert!(r.fake.seen().is_empty(), "no CDP write without the entry");
    assert!(entries(&r).is_empty(), "no outcome without a dispatch");
    assert_wiped(&r);

    // Every append failing (read-only log): same.
    let r = harness(FakeAnswer::Filled);
    *r.h.audit.fail.lock().unwrap() = true;
    assert_eq!(fill(&r).await, Err(ApiError::AUDIT_FAILED));
    assert!(r.fake.seen().is_empty());
    assert_wiped(&r);
}

#[tokio::test]
async fn req_aud_003_outcome_append_failure_fails_the_reply_closed() {
    let r = harness(FakeAnswer::Filled);
    *r.h.audit.fail_event.lock().unwrap() = Some("fill");
    assert_eq!(fill(&r).await, Err(ApiError::AUDIT_FAILED));
    assert_eq!(r.fake.seen().len(), 1, "dispatched");
    let e = entries(&r);
    assert_eq!(e.len(), 1, "only the dispatch reached the log: {e:?}");
    assert_dispatch(&e[0]);
    assert_wiped(&r);
}

#[tokio::test]
async fn req_aud_003_refusal_before_the_browser_writes_no_dispatch() {
    let r = harness(FakeAnswer::Filled);
    let agent = r.h.broker.authenticate(&r.h.alpha).unwrap();
    let mut v: Value = serde_json::from_str(&body()).unwrap();
    v["item_id"] = "00000000-0000-4000-8000-000000000000".into();
    let req = parse_fill(FillOperation::Fill, v.to_string().as_bytes()).unwrap();
    r.h.broker.fill(&agent, req, Instant::now()).await.unwrap();
    let e = entries(&r);
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0]["event"], "fill");
    assert_eq!(e[0]["result"], "not_found");
}

#[tokio::test(start_paused = true)]
async fn req_aud_003_dropped_fill_writes_fill_aborted_and_wipes_the_plan() {
    fixture_vault();
    let r = harness(FakeAnswer::Stall);
    let agent = r.h.broker.authenticate(&r.h.alpha).unwrap();
    let req = parse_fill(FillOperation::Fill, body().as_bytes()).unwrap();
    {
        let fut = r.h.broker.fill(&agent, req, Instant::now());
        tokio::pin!(fut);
        // Drive it into the stalled backend, then go away like a
        // disconnected client (well inside the 10 s deadline).
        tokio::select! {
            _ = &mut fut => panic!("a stalled fill cannot finish"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
        assert_eq!(r.fake.seen().len(), 1, "backend reached");
        assert!(
            r.wiped.lock().unwrap().is_empty(),
            "not wiped while in flight"
        );
    } // `fut` dropped here
    let e = entries(&r);
    assert_eq!(e.len(), 2, "{e:?}");
    assert_dispatch(&e[0]);
    assert_eq!(e[1]["event"], "fill_aborted");
    assert_eq!(e[1]["result"], "aborted");
    assert_eq!(e[1]["detail_code"], "handler_dropped");
    assert_eq!(e[1]["request_id"], e[0]["request_id"]);
    assert_no_canary(&serde_json::to_string(&e).unwrap());
    assert_wiped(&r);
}

#[tokio::test(start_paused = true)]
async fn req_aud_003_dropped_fill_with_a_failing_log_still_wipes() {
    // The abort append is best effort: a refused append is swallowed
    // (nobody is left to tell) and the orphan dispatch is the evidence.
    fixture_vault();
    let r = harness(FakeAnswer::Stall);
    *r.h.audit.fail_event.lock().unwrap() = Some("fill_aborted");
    let agent = r.h.broker.authenticate(&r.h.alpha).unwrap();
    let req = parse_fill(FillOperation::Fill, body().as_bytes()).unwrap();
    {
        let fut = r.h.broker.fill(&agent, req, Instant::now());
        tokio::pin!(fut);
        tokio::select! {
            _ = &mut fut => panic!("a stalled fill cannot finish"),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
    let e = entries(&r);
    assert_eq!(e.len(), 1);
    assert_dispatch(&e[0]);
    assert_wiped(&r);
}
