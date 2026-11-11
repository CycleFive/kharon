//! REQ-MEM-004 / #215: which operations reset the idle timer, and
//! when a live grant defers the lock.
//!
//! Activity is an owner unlock, a fill, or the approval that issues
//! a grant. Agent calls — status, list, search, `kharon_context`,
//! `kharon_request_grant` — do not move the timer. Tab navigation
//! never reaches the broker, so it has no way to move it either.
//! A live (unconsumed, unexpired) grant defers the idle lock until
//! that grant is consumed or its own TTL elapses. Owner lock and
//! panic are not deferred.
//!
//! Time is the manual clock shared by the lock and the grant store.
//! Nothing here sleeps for 30 minutes.

mod api_support;

use std::sync::Arc;
use std::time::Duration;

use api_support::{
    CHEAP_FLOOR, FakeAnswer, FakeFill, ITEM_A, RecordingAudit, TestSession, cheap_argon,
};
use kharond::api::grant::{Channel, GrantScope, GrantTerms};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, GrantRequestArgs, Outcome, Request, parse_fill};
use kharond::audit::Event;
use kharond::config::GrantKind;
use kharond::lock::{Clock, LockController, LockPolicy, LockReason, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use serde_json::{Value, json};
use tokio::time::Instant;

const ORIGIN: &str = "https://login.example.com";
const LIVE: &str = "https://login.example.com/signin";

type TestBroker = Broker<TestSession, Arc<ManualClock>>;

struct Rig {
    broker: Arc<TestBroker>,
    clock: Arc<ManualClock>,
    audit: RecordingAudit,
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
        let audit = RecordingAudit::default();
        let fake = FakeFill::new(FakeAnswer::Filled).with_live_url(LIVE);
        let grant_clock: Arc<dyn Clock> = clock.clone();
        let broker = Broker::new(
            tokens,
            lock,
            Box::new(audit.clone()),
            OriginConfig::default(),
        )
        .with_grant_clock(grant_clock)
        .with_fill_backend(Box::new(fake.clone()));
        broker.wire_lock_audit();
        Self {
            broker: Arc::new(broker),
            clock,
            audit,
            fake,
            alpha: alpha.expose_secret().clone(),
        }
    }

    fn agent(&self) -> kharond::api::AgentId {
        self.broker.authenticate(&self.alpha).unwrap()
    }

    fn advance(&self, secs: u64) {
        self.clock.advance(Duration::from_secs(secs));
    }

    /// Run the expiry check. `Some` is the reason this call locked.
    fn poll(&self) -> Option<LockReason> {
        let mut lock = self.broker.lock_controller().lock().unwrap();
        lock.poll()
    }

    fn is_locked(&self) -> bool {
        self.broker.lock_controller().lock().unwrap().is_locked()
    }

    fn relock_and_unlock(&self) {
        let mut lock = self.broker.lock_controller().lock().unwrap();
        assert!(lock.lock(LockReason::Manual));
        lock.unlock(|| Ok::<_, ()>(TestSession::fixture())).unwrap();
    }

    /// Status, list, search, context, and a grant request. None of
    /// these is idle activity.
    async fn agent_only(&self) {
        let agent = self.agent();
        self.broker
            .dispatch(&agent, Request::Status)
            .expect("status");
        self.broker
            .dispatch(&agent, Request::List { origin: None })
            .expect("list");
        self.broker
            .dispatch(
                &agent,
                Request::Search {
                    q: "login".into(),
                    origin: None,
                },
            )
            .expect("search");
        self.broker
            .context(&agent, Instant::now())
            .await
            .expect("context");
        let args = GrantRequestArgs {
            item_id: ITEM_A.to_owned(),
            target_id: "tab-1".into(),
            expected_origin: ORIGIN.into(),
            action: kharond::api::GrantAction::Fill,
        };
        self.broker
            .request_grant(&agent, args, Instant::now())
            .await
            .expect("grant_request");
    }

    async fn request(&self) -> String {
        let agent = self.agent();
        let args = GrantRequestArgs {
            item_id: ITEM_A.to_owned(),
            target_id: "tab-1".into(),
            expected_origin: ORIGIN.into(),
            action: kharond::api::GrantAction::Fill,
        };
        match self
            .broker
            .request_grant(&agent, args, Instant::now())
            .await
            .unwrap()
        {
            Outcome::GrantRequest(body) => body.grant_request_id.expect("request id"),
            other => panic!("expected a grant request, got {other:?}"),
        }
    }

    fn approve_once(&self, request_id: &str) {
        self.broker
            .approve_grant_request(request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli)
            .unwrap();
    }

    fn approve_for(&self, request_id: &str, ttl: Duration, max_uses: Option<u64>) {
        self.broker
            .approve_grant_request(
                request_id,
                &GrantTerms {
                    scope: GrantScope::Item(ITEM_A.to_owned()),
                    kind: GrantKind::PerOrigin,
                    ttl: Some(ttl),
                    max_uses,
                },
                Channel::Cli,
            )
            .unwrap();
    }

    async fn fill_password(&self) -> Value {
        let req = parse_fill(
            kharond::api::FillOperation::Fill,
            json!({
                "item_id": ITEM_A,
                "target": {"cdp_target_id": "tab-1", "expected_origin": ORIGIN},
                "fields": [{"kind": "password"}],
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        match self.broker.fill(&self.agent(), req, Instant::now()).await {
            Ok(Outcome::Fill(r)) => serde_json::to_value(r).unwrap(),
            Err(e) => panic!("fill failed: {e:?}"),
            other => panic!("expected a fill outcome, got {other:?}"),
        }
    }

    fn saw_lock(&self, detail: &str) -> bool {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.event == Event::Lock && e.detail_code.as_deref() == Some(detail))
    }
}

#[tokio::test]
async fn req_mem_004_agent_only_activity_does_not_extend_idle() {
    let rig = Rig::new();
    // 10, 20, and 29 minutes of agent traffic. Tab navigation is not
    // a broker call; the calls here are every agent operation the
    // ruling names.
    for step in [10 * 60, 10 * 60, 9 * 60] {
        rig.advance(step);
        rig.agent_only().await;
        assert!(!rig.is_locked(), "agent traffic locked the broker early");
        assert_eq!(rig.poll(), None);
    }
    rig.advance(60);
    assert_eq!(
        rig.poll(),
        Some(LockReason::IdleTimeout),
        "idle lock at T+30m despite status, list, search, context, and grant_request"
    );
    assert!(rig.saw_lock("idle_timeout"));
}

#[tokio::test]
async fn req_mem_004_unlock_resets_the_idle_timer() {
    let rig = Rig::new();
    rig.advance(20 * 60);
    rig.relock_and_unlock();
    // 20 minutes after the re-unlock, 40 after the first unlock.
    rig.advance(20 * 60);
    assert_eq!(rig.poll(), None, "the re-unlock restarted the idle window");
    rig.advance(10 * 60);
    assert_eq!(rig.poll(), Some(LockReason::IdleTimeout));
}

#[tokio::test]
async fn req_mem_004_grant_issue_resets_the_idle_timer() {
    let rig = Rig::new();
    rig.advance(25 * 60);
    let request_id = rig.request().await;
    rig.approve_once(&request_id);
    // The once grant expired 120 s after approval (T+27m). Deferral
    // alone would still lock at the original T+30m. The reset moves
    // the idle lock to T+55m.
    rig.advance(6 * 60);
    assert_eq!(
        rig.poll(),
        None,
        "still unlocked at T+31m, past the grant TTL"
    );
    rig.advance(23 * 60);
    assert_eq!(
        rig.poll(),
        None,
        "one minute inside the window the approval started"
    );
    rig.advance(60);
    assert_eq!(
        rig.poll(),
        Some(LockReason::IdleTimeout),
        "idle lock 30m after grant_issue"
    );
}

#[tokio::test]
async fn req_mem_004_fill_resets_the_idle_timer() {
    let rig = Rig::new();
    rig.advance(20 * 60);
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    rig.advance(29 * 60);
    assert_eq!(rig.poll(), None, "the fill restarted the idle window");
    rig.advance(60);
    assert_eq!(rig.poll(), Some(LockReason::IdleTimeout));
}

#[tokio::test]
async fn req_mem_004_live_grant_defers_idle_until_it_expires() {
    let rig = Rig::new();
    let request_id = rig.request().await;
    rig.approve_for(&request_id, Duration::from_secs(45 * 60), None);
    rig.advance(30 * 60);
    assert_eq!(
        rig.poll(),
        None,
        "T+30m idle is deferred while the grant is live"
    );
    rig.advance(15 * 60 - 1);
    assert_eq!(rig.poll(), None, "still inside the grant TTL");
    rig.advance(1);
    assert_eq!(
        rig.poll(),
        Some(LockReason::IdleTimeout),
        "the deferral ends at the grant TTL and not later"
    );
}

#[tokio::test]
async fn req_mem_004_consuming_a_live_grant_ends_the_deferral() {
    let rig = Rig::new();
    let request_id = rig.request().await;
    rig.approve_for(&request_id, Duration::from_secs(2 * 60 * 60), Some(1));
    rig.advance(40 * 60);
    assert_eq!(rig.poll(), None, "deferred past the idle window");
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "filled", "{r}");
    // The fill reset the timer and spent the only use, so the hold
    // is gone. T+70m is 30m after the fill and far short of the
    // grant's 2h TTL.
    rig.advance(30 * 60);
    assert_eq!(
        rig.poll(),
        Some(LockReason::IdleTimeout),
        "a consumed grant does not keep deferring until its old TTL"
    );
}

#[tokio::test]
async fn req_mem_004_a_refunded_grant_still_defers_idle() {
    let rig = Rig::new();
    rig.fake.script([FakeAnswer::OriginMismatch]);
    let request_id = rig.request().await;
    rig.approve_for(&request_id, Duration::from_secs(2 * 60 * 60), Some(1));
    rig.advance(40 * 60);
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    // Past the 30m the fill just started, and short of the 2h TTL.
    rig.advance(40 * 60);
    assert_eq!(
        rig.poll(),
        None,
        "the use came back, so the grant still defers the idle lock"
    );
    rig.advance(40 * 60);
    assert_eq!(
        rig.poll(),
        Some(LockReason::IdleTimeout),
        "the restored deferral still ends at the grant TTL"
    );
}

#[tokio::test]
async fn req_mem_004_owner_lock_and_panic_ignore_a_live_grant() {
    let rig = Rig::new();
    let request_id = rig.request().await;
    rig.approve_for(&request_id, Duration::from_secs(2 * 60 * 60), None);
    rig.advance(40 * 60);
    assert_eq!(rig.poll(), None, "the grant is holding the idle lock off");

    rig.relock_and_unlock();
    assert!(!rig.is_locked(), "re-unlock after an explicit lock");
    assert!(rig.saw_lock("manual"));
    // The grant survived the lock, so the deferral did too. 30m after
    // the re-unlock is still inside the grant's TTL.
    rig.advance(30 * 60);
    assert_eq!(
        rig.poll(),
        None,
        "a surviving grant still defers idle after a manual lock and re-unlock"
    );

    rig.broker.panic_lock().unwrap();
    assert!(rig.is_locked(), "panic locks at once, grant or not");
    assert!(
        rig.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.event == Event::Panic),
        "panic is the panic audit, not an idle timeout"
    );
    // Grants are gone, and so are their holds. The next unlock gets
    // a plain 30m window.
    {
        let mut lock = rig.broker.lock_controller().lock().unwrap();
        lock.unlock(|| Ok::<_, ()>(TestSession::fixture())).unwrap();
    }
    rig.advance(30 * 60);
    assert_eq!(
        rig.poll(),
        Some(LockReason::IdleTimeout),
        "panic cleared the deferral; idle is 30m after the re-unlock"
    );
}

#[tokio::test]
async fn req_mem_004_grant_issue_does_not_revive_an_expired_session() {
    let rig = Rig::new();
    // The request is created inside its 120 s lifetime, one minute
    // before the idle deadline, so approval is still a legal decision
    // when the session's idle time runs out.
    rig.advance(29 * 60);
    let request_id = rig.request().await;
    rig.advance(60);
    // The approval finds the session already past its idle deadline.
    rig.approve_once(&request_id);
    assert!(
        rig.is_locked(),
        "grant_issue must not revive a session whose idle deadline has passed"
    );
    assert!(rig.saw_lock("idle_timeout"));
    let err = rig
        .broker
        .fill(
            &rig.agent(),
            parse_fill(
                kharond::api::FillOperation::Fill,
                json!({
                    "item_id": ITEM_A,
                    "target": {"cdp_target_id": "tab-1", "expected_origin": ORIGIN},
                    "fields": [{"kind": "password"}],
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap(),
            Instant::now(),
        )
        .await
        .unwrap_err();
    assert_eq!(err, kharond::api::ApiError::LOCKED);
}
