//! REQ-API-009: every fill has an end-to-end deadline (`[policy]
//! fill_deadline`, default 10 s) from the moment the request is
//! received, covering resolve and fill. On expiry the broker drops the
//! fill (no further CDP writes, submit never dispatched), zeroizes the
//! plan, writes exactly one `fill_timeout` audit entry and returns
//! `FillResult{status: "timeout"}`.
//!
//! Runs on tokio's paused clock: a stalled backend auto-advances time
//! to the deadline, so "10 s" is exact and the test is instant.

mod api_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::*;
use kharond::api::fill::{FillOperation, FillPolicy, parse_fill};
use kharond::api::{ApiError, Outcome};
use serde_json::{Value, json};
use tokio::time::Instant;

fn body() -> String {
    json!({
        "item_id": ITEM_A,
        "target": {"cdp_target_id": "T-1", "expected_origin": "https://login.example.com"},
        "fields": [{"kind": "password"}],
        "submit": true,
    })
    .to_string()
}

struct Run {
    h: Harness,
    fake: FakeFill,
    /// Every field value of every plan, as seen after the wipe.
    wiped: Arc<Mutex<Vec<String>>>,
}

fn harness(answer: FakeAnswer, deadline: Option<Duration>) -> Run {
    let fake = FakeFill::new(answer);
    let wiped: Arc<Mutex<Vec<String>>> = Arc::default();
    let (f, w) = (fake.clone(), wiped.clone());
    let h = Harness::with(false, move |b| {
        let mut policy = FillPolicy::default();
        if let Some(d) = deadline {
            policy.deadline = d;
        }
        b.with_fill_backend(Box::new(f))
            .with_fill_policy(policy)
            .with_plan_wiped_hook(Arc::new(move |plan| {
                w.lock()
                    .unwrap()
                    .extend(plan.fields.iter().map(|f| (*f.value).clone()));
            }))
    });
    // #20: fills need a grant; the fixture items' tests predate the
    // grant model, so the harness seeds collection-wide ones.
    h.grant_fixture_items();
    Run { h, fake, wiped }
}

async fn fill(r: &Run, received: Instant) -> Result<Value, ApiError> {
    let agent = r.h.broker.authenticate(&r.h.alpha).unwrap();
    let req = parse_fill(FillOperation::Fill, body().as_bytes()).unwrap();
    r.h.broker
        .fill(&agent, req, received)
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

/// Exactly one `fill_timeout` outcome entry; preceded by one
/// `fill_dispatch` (same `request_id`) iff the backend was reached
/// (REQ-AUD-003†: dispatch and outcome are separate transitions).
fn assert_one_timeout_entry(r: &Run, dispatched: bool) {
    let e = entries(r);
    let outcome = if dispatched {
        assert_eq!(e.len(), 2, "dispatch + exactly one outcome: {e:?}");
        assert_eq!(e[0]["event"], "fill_dispatch");
        assert_eq!(e[0]["agent_id"], "alpha");
        assert_eq!(e[0]["item_id"], ITEM_A);
        assert_eq!(e[0]["field_count"], 1);
        assert_eq!(e[0]["request_id"], e[1]["request_id"]);
        &e[1]
    } else {
        assert_eq!(e.len(), 1, "exactly one audit entry: {e:?}");
        &e[0]
    };
    assert_eq!(e.iter().filter(|x| x["event"] == "fill_timeout").count(), 1);
    assert_eq!(outcome["event"], "fill_timeout");
    assert_eq!(outcome["agent_id"], "alpha");
    assert_eq!(outcome["item_id"], ITEM_A);
    assert_eq!(outcome["result"], "timeout");
    assert_eq!(outcome["detail_code"], "deadline_expired");
    assert_no_canary(&serde_json::to_string(&e).unwrap());
}

const TIMEOUT: fn() -> Value = || json!({"status": "timeout", "fields_filled": []});

#[tokio::test(start_paused = true)]
async fn req_api_009_default_deadline_is_10s_and_fails_closed() {
    fixture_vault(); // unlock outside the timed region
    let r = harness(FakeAnswer::Stall, None);
    assert_eq!(r.h.broker.fill_policy().deadline, Duration::from_secs(10));
    let received = Instant::now();
    let out = fill(&r, received).await.unwrap();
    assert_eq!(out, TIMEOUT());
    assert_eq!(received.elapsed(), Duration::from_secs(10));
    assert_eq!(
        r.fake.seen().len(),
        1,
        "the backend was reached, then cut off"
    );
    let wiped = r.wiped.lock().unwrap().clone();
    assert_eq!(wiped.len(), 1);
    assert!(
        wiped.iter().all(String::is_empty),
        "plan zeroized on expiry"
    );
    assert_one_timeout_entry(&r, true);
}

/// #118: the page-side budget's abort reaches the broker as
/// `FillOutcome::Timeout` (the engine's mapping of the in-page
/// `kharon:deadline` exception) *before* the broker's own deadline.
/// The outcome is the existing one — `timeout` reply, exactly one
/// `fill_timeout` entry after the dispatch, plan zeroized — with no
/// new status value.
#[tokio::test(start_paused = true)]
async fn req_api_009_page_deadline_maps_to_timeout() {
    fixture_vault();
    let r = harness(FakeAnswer::PageDeadline, None);
    let received = Instant::now();
    assert_eq!(fill(&r, received).await.unwrap(), TIMEOUT());
    assert!(
        received.elapsed() < Duration::from_secs(10),
        "answered by the page budget, not the broker deadline"
    );
    assert_eq!(r.fake.seen().len(), 1, "the backend was reached once");
    let wiped = r.wiped.lock().unwrap().clone();
    assert_eq!(wiped.len(), 1);
    assert!(
        wiped.iter().all(String::is_empty),
        "plan zeroized on the page-deadline outcome"
    );
    assert_one_timeout_entry(&r, true);
}

#[tokio::test(start_paused = true)]
async fn req_api_009_configured_deadline_is_honoured() {
    fixture_vault();
    let r = harness(FakeAnswer::Stall, Some(Duration::from_secs(2)));
    let received = Instant::now();
    assert_eq!(fill(&r, received).await.unwrap(), TIMEOUT());
    assert_eq!(received.elapsed(), Duration::from_secs(2));
    assert_one_timeout_entry(&r, true);
}

#[tokio::test(start_paused = true)]
async fn req_api_009_deadline_runs_from_receipt_not_from_dispatch() {
    // Time spent before the fill (here: simulated by receiving 11 s
    // ago) counts: the backend is never called once the deadline is
    // gone, so not a single CDP write is made.
    fixture_vault();
    let r = harness(FakeAnswer::Filled, None);
    let received = Instant::now();
    tokio::time::advance(Duration::from_secs(11)).await;
    assert_eq!(fill(&r, received).await.unwrap(), TIMEOUT());
    assert!(r.fake.seen().is_empty(), "no CDP work after expiry");
    assert_one_timeout_entry(&r, false);
}

#[tokio::test(start_paused = true)]
async fn req_api_009_fill_inside_the_deadline_is_not_cut() {
    fixture_vault();
    let r = harness(FakeAnswer::Filled, Some(Duration::from_secs(2)));
    let out = fill(&r, Instant::now()).await.unwrap();
    assert_eq!(
        out,
        json!({"status": "filled", "fields_filled": ["password"]})
    );
    let e = entries(&r);
    assert_eq!(e.len(), 2);
    assert_eq!(e[0]["event"], "fill_dispatch");
    assert_eq!(e[1]["event"], "fill");
    assert_eq!(e[1]["result"], "filled");
    assert!(r.wiped.lock().unwrap().iter().all(String::is_empty));
}

#[tokio::test(start_paused = true)]
async fn req_api_009_timeout_with_a_failed_audit_is_audit_failed() {
    // REQ-AUD-003: no reply the audit log does not have, timeout
    // included (#46 item 1 at the API layer).
    fixture_vault();
    let r = harness(FakeAnswer::Stall, None);
    *r.h.audit.fail.lock().unwrap() = true;
    assert_eq!(fill(&r, Instant::now()).await, Err(ApiError::AUDIT_FAILED));
}

/// REQ-API-009 + REQ-AUD-003† on `fill` (#88, the Broker-path form of
/// the retired engine-level `DeadlineFiller` test): a backend that
/// stalls past the deadline with a failing `fill_timeout` append is
/// `audit_failed` exactly at the deadline, not `timeout`; the backend
/// was reached once and the plan is still zeroized.
#[tokio::test(start_paused = true)]
async fn req_api_009_timeout_append_failure_is_audit_failed_at_the_deadline() {
    fixture_vault();
    let r = harness(FakeAnswer::Stall, Some(Duration::from_secs(1)));
    *r.h.audit.fail_event.lock().unwrap() = Some("fill_timeout");
    let received = Instant::now();
    assert_eq!(fill(&r, received).await, Err(ApiError::AUDIT_FAILED));
    assert_eq!(received.elapsed(), Duration::from_secs(1));
    assert_eq!(r.fake.seen().len(), 1, "dispatched, then cut off");
    let e = entries(&r);
    assert_eq!(e.len(), 1, "only the dispatch reached the log: {e:?}");
    assert_eq!(e[0]["event"], "fill_dispatch");
    let wiped = r.wiped.lock().unwrap().clone();
    assert!(
        wiped.len() == 1 && wiped[0].is_empty(),
        "plan zeroized before the failed append"
    );
}
