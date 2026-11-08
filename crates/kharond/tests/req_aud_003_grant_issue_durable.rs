//! REQ-AUD-003 / #193: a grant must not be usable before its
//! `grant_issue` audit entry is durable.
//!
//! `approve_grant_request` used to mutate the grant store first
//! (grant live, request `Approved`) and append `grant_issue`
//! afterwards, so a fill running in that window could match and
//! consume a grant whose issuance might still fail to be audited
//! (and then be rolled back — after the fill had used it). The
//! broker now holds the grant-store lock across the append, so
//! every consuming path waits until the entry is durable.
//!
//! The gate here is the audit sink itself: its `grant_issue`
//! append blocks until the test releases it, which is exactly the
//! "store mutated, entry not yet durable" window, held open
//! deterministically.

mod api_support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use api_support::{CHEAP_FLOOR, FakeAnswer, FakeFill, ITEM_A, TestSession, cheap_argon};
use kharond::api::grant::{Channel, GrantError, GrantTerms, RequestState};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{AuditSink, Broker, Outcome, parse_fill};
use kharond::audit::{Entry, Event};
use kharond::lock::{AuditError, Clock, LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use serde_json::{Value, json};
use tokio::time::Instant;

/// Gate state for the `grant_issue` append: `started` once the
/// append has been entered (entry not yet durable), released by
/// the test.
#[derive(Default)]
struct Gate {
    started: bool,
    release: bool,
}

/// An audit sink that records entries, can hold the `grant_issue`
/// append open on a gate, and can be told to fail it.
#[derive(Clone, Default)]
struct GatedAudit {
    entries: Arc<Mutex<Vec<Entry>>>,
    gate: Arc<(Mutex<Gate>, Condvar)>,
    armed: Arc<AtomicBool>,
    fail_grant_issue: Arc<AtomicBool>,
}

impl GatedAudit {
    fn arm_gate(&self) {
        *self.gate.0.lock().unwrap() = Gate::default();
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Wait (bounded) until the gated append has been entered.
    fn wait_started(&self) -> bool {
        let (lock, cvar) = &*self.gate;
        let mut gate = lock.lock().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while !gate.started {
            let (g, timeout) = cvar.wait_timeout(gate, Duration::from_millis(200)).unwrap();
            gate = g;
            if std::time::Instant::now() >= deadline {
                return gate.started;
            }
            let _ = timeout;
        }
        true
    }

    fn release_gate(&self) {
        let (lock, cvar) = &*self.gate;
        lock.lock().unwrap().release = true;
        cvar.notify_all();
    }

    fn entries(&self) -> Vec<Entry> {
        self.entries.lock().unwrap().clone()
    }
}

impl AuditSink for GatedAudit {
    fn append(&mut self, entry: Entry) -> Result<(), AuditError> {
        if entry.event == Event::GrantIssue {
            if self.fail_grant_issue.load(Ordering::SeqCst) {
                return Err(AuditError);
            }
            if self.armed.swap(false, Ordering::SeqCst) {
                let (lock, cvar) = &*self.gate;
                let mut gate = lock.lock().unwrap();
                gate.started = true;
                cvar.notify_all();
                // Hold the append open: the entry is not durable
                // until this returns. Bounded so a broken test
                // fails instead of hanging the suite.
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                while !gate.release {
                    let (g, _) = cvar.wait_timeout(gate, Duration::from_millis(200)).unwrap();
                    gate = g;
                    if std::time::Instant::now() >= deadline {
                        return Err(AuditError);
                    }
                }
            }
        }
        self.entries.lock().unwrap().push(entry);
        Ok(())
    }
}

type GatedBroker = Broker<TestSession, Arc<ManualClock>>;

struct Rig {
    broker: Arc<GatedBroker>,
    clock: Arc<ManualClock>,
    audit: GatedAudit,
    fake: FakeFill,
    alpha: String,
}

impl Rig {
    fn new() -> Self {
        let (alpha, ha) = generate_with(&cheap_argon(), "alpha");
        let tokens = TokenStore::with_floor([("alpha", ha.as_str())], &CHEAP_FLOOR).unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut lock = LockController::new(
            LockPolicy::default(),
            clock.clone(),
            Box::new(StaticHardening::all_ok()),
        );
        lock.unlock(|| Ok::<_, ()>(TestSession::fixture())).unwrap();
        let audit = GatedAudit::default();
        let fake =
            FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/signin");
        let grant_clock: Arc<dyn Clock> = clock.clone();
        let broker = Broker::new(
            tokens,
            lock,
            Box::new(audit.clone()),
            OriginConfig::default(),
        )
        .with_grant_clock(grant_clock)
        .with_fill_backend(Box::new(fake.clone()));
        Self {
            broker: Arc::new(broker),
            clock,
            audit,
            fake,
            alpha: alpha.expose_secret().clone(),
        }
    }

    async fn fill_password(broker: &GatedBroker, alpha: &str) -> Value {
        let agent = broker.authenticate(alpha).unwrap();
        let req = parse_fill(
            kharond::api::FillOperation::Fill,
            json!({
                "item_id": ITEM_A,
                "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com"},
                "fields": [{"kind": "password"}],
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        match broker.fill(&agent, req, Instant::now()).await {
            Ok(Outcome::Fill(r)) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a fill outcome, got {other:?}"),
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn req_aud_003_concurrent_fill_cannot_consume_grant_before_grant_issue_is_durable() {
    let rig = Rig::new();
    let rt = runtime();

    // A grantless fill creates the pending request.
    let r = rt.block_on(Rig::fill_password(&rig.broker, &rig.alpha));
    assert_eq!(r["status"], "pending_approval", "{r}");
    let request_id = r["grant_request_id"].as_str().unwrap().to_owned();

    // Approve on its own thread, with the grant_issue append gated
    // open: the store is mutated, the entry is not yet durable.
    rig.audit.arm_gate();
    let (approve_tx, approve_rx) = mpsc::channel();
    let approve_thread = {
        let broker = rig.broker.clone();
        let request_id = request_id.clone();
        std::thread::spawn(move || {
            let result = broker
                .approve_grant_request(&request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli)
                .map(|view| view.id);
            let _ = approve_tx.send(result);
        })
    };
    assert!(
        rig.audit.wait_started(),
        "the grant_issue append never started"
    );
    // In the window: no grant_issue entry is durable yet, and the
    // grant store is held by the approval (it is not observable,
    // let alone consumable, from the outside).
    assert!(
        !rig.audit
            .entries()
            .iter()
            .any(|e| e.event == Event::GrantIssue),
        "grant_issue recorded before the gated append returned"
    );
    assert!(
        rig.broker.grant_store().try_lock().is_err(),
        "grant store not held across the grant_issue append"
    );

    // A concurrent fill started in the window must not consume
    // the grant (or reach the browser) while the append is gated.
    let (fill_tx, fill_rx) = mpsc::channel();
    let fill_thread = {
        let broker = rig.broker.clone();
        let alpha = rig.alpha.clone();
        std::thread::spawn(move || {
            let rt = runtime();
            let result = rt.block_on(Rig::fill_password(&broker, &alpha));
            let _ = fill_tx.send(result);
        })
    };
    match fill_rx.recv_timeout(Duration::from_secs(3)) {
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        other => panic!("the concurrent fill completed before grant_issue was durable: {other:?}"),
    }
    assert!(
        rig.fake.seen().is_empty(),
        "the concurrent fill reached the browser before grant_issue was durable"
    );

    // Release the append: the approval now completes, and only
    // then can the waiting fill consume the (once) grant.
    rig.audit.release_gate();
    let grant_id = approve_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("the approval never completed")
        .expect("the approval failed");
    approve_thread.join().unwrap();
    let r = fill_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("the concurrent fill never completed");
    fill_thread.join().unwrap();
    assert_eq!(r["status"], "filled", "{r}");
    assert_eq!(rig.fake.seen().len(), 1);

    // Exactly one use was spent, by that fill, and the audit order
    // is grant_issue before the fill's dispatch. (The spent `once`
    // grant is no longer live, so it is read by id, not via
    // `grants_for`.)
    let grant = rig
        .broker
        .grant_store()
        .lock()
        .unwrap()
        .grant(&grant_id)
        .cloned()
        .expect("the approved grant is gone");
    assert_eq!(grant.uses, 1);
    let entries = rig.audit.entries();
    let issue_at = entries
        .iter()
        .position(|e| e.event == Event::GrantIssue)
        .expect("no grant_issue entry");
    let dispatch_at = entries
        .iter()
        .position(|e| e.event == Event::FillDispatch)
        .expect("no fill_dispatch entry");
    assert!(
        issue_at < dispatch_at,
        "grant_issue (at {issue_at}) must precede fill_dispatch (at {dispatch_at})"
    );
}

#[test]
fn req_aud_003_failed_grant_issue_append_leaves_no_usable_grant_and_no_consumed_use() {
    let rig = Rig::new();
    let rt = runtime();
    let r = rt.block_on(Rig::fill_password(&rig.broker, &rig.alpha));
    assert_eq!(r["status"], "pending_approval", "{r}");
    let request_id = r["grant_request_id"].as_str().unwrap().to_owned();

    // The grant_issue append fails: the approval fails closed.
    rig.audit.fail_grant_issue.store(true, Ordering::SeqCst);
    assert_eq!(
        rig.broker
            .approve_grant_request(&request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli),
        Err(GrantError::AuditFailed)
    );
    // Rollback: the request is pending again, no grant exists, and
    // no grant_issue entry was written.
    assert_eq!(
        rig.broker.grant_request(&request_id).unwrap().state,
        RequestState::Pending
    );
    assert!(
        rig.broker
            .grant_store()
            .lock()
            .unwrap()
            .grants_for("alpha", rig.clock.now())
            .is_empty(),
        "a usable grant survived a failed grant_issue append"
    );
    assert!(
        !rig.audit
            .entries()
            .iter()
            .any(|e| e.event == Event::GrantIssue)
    );
    // A fill now is a fresh pending_approval for the same request —
    // nothing was consumed by the failed approval.
    let r = rt.block_on(Rig::fill_password(&rig.broker, &rig.alpha));
    assert_eq!(r["status"], "pending_approval", "{r}");
    assert_eq!(r["grant_request_id"].as_str().unwrap(), request_id);
    assert!(rig.fake.seen().is_empty());

    // With the sink healthy the same request approves and fills,
    // spending the grant's single use exactly once.
    rig.audit.fail_grant_issue.store(false, Ordering::SeqCst);
    let view = rig
        .broker
        .approve_grant_request(&request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli)
        .unwrap();
    let r = rt.block_on(Rig::fill_password(&rig.broker, &rig.alpha));
    assert_eq!(r["status"], "filled", "{r}");
    let grant = rig
        .broker
        .grant_store()
        .lock()
        .unwrap()
        .grant(&view.id)
        .cloned()
        .expect("the approved grant is gone");
    assert_eq!(grant.uses, 1);
}
