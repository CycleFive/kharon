//! REQ-APR-008 (SPEC §5; #151, Lothrop decision 2026-11-07): a grant
//! use is spent when a fill is admitted and given back if the fill
//! ends before the broker has sent any field value to the browser.
//!
//! - A fill refused `origin_mismatch` in step 1 (the #121 pilot's tab
//!   on an SSL error page) leaves the `once` grant live; the next fill
//!   on it is `filled`, and the one after needs a new grant.
//! - A fill refused in-page, after the call carrying the values was
//!   sent, keeps the use spent.
//! - A deadline already spent at dispatch gives the use back.
//! - A refusal between admission and the fill call (a failed
//!   decrypt) gives the use back.
//! - Two concurrent fills on one `once` grant reach the backend at
//!   most once.

mod api_support;
use api_support::{
    CHEAP_FLOOR, FakeAnswer, FakeFill, ITEM_A, RecordingAudit, TestSession, cheap_argon,
};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kharond::api::grant::{Channel, GrantTerms};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, Outcome, VaultView, parse_fill};
use kharond::config::DEFAULT_FILL_DEADLINE;
use kharond::lock::{Clock, LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::sync::{SecretField, SyncError, Vault};
use serde_json::{Value, json};
use tokio::time::Instant;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A [`TestSession`] whose secret decrypts fail while `fail` is set.
struct FlakySession {
    inner: TestSession,
    fail: Arc<AtomicBool>,
}

impl ZeroizeOnDrop for FlakySession {}

impl VaultView for FlakySession {
    fn vault(&self) -> &Vault {
        self.inner.vault()
    }

    fn decrypt_secret(
        &self,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(SyncError::Malformed("test: decrypt refused"));
        }
        self.inner.decrypt_secret(item_id, field)
    }
}

struct Rig {
    broker: Arc<Broker<FlakySession, Arc<ManualClock>>>,
    fake: FakeFill,
    fail_decrypt: Arc<AtomicBool>,
    alpha: String,
}

const LIVE: &str = "https://login.example.com/signin";

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
        let fail_decrypt = Arc::new(AtomicBool::new(false));
        lock.unlock(|| {
            Ok::<_, ()>(FlakySession {
                inner: TestSession::fixture(),
                fail: fail_decrypt.clone(),
            })
        })
        .unwrap();
        let fake = FakeFill::new(FakeAnswer::Filled).with_live_url(LIVE);
        let grant_clock: Arc<dyn Clock> = clock.clone();
        let broker = Broker::new(
            tokens,
            lock,
            Box::new(RecordingAudit::default()),
            OriginConfig::default(),
        )
        .with_grant_clock(grant_clock)
        .with_fill_backend(Box::new(fake.clone()));
        Self {
            broker: Arc::new(broker),
            fake,
            fail_decrypt,
            alpha: alpha.expose_secret().clone(),
        }
    }

    /// A password fill received at `received`; its deadline is
    /// `received + DEFAULT_FILL_DEADLINE` (REQ-API-009).
    async fn fill_received(&self, received: Instant) -> Value {
        let agent = self.broker.authenticate(&self.alpha).unwrap();
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
        match self.broker.fill(&agent, req, received).await {
            Ok(Outcome::Fill(r)) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a fill outcome, got {other:?}"),
        }
    }

    async fn fill(&self) -> Value {
        self.fill_received(Instant::now()).await
    }

    /// The first fill makes a request; approve it as a `once` grant
    /// for this item and return the grant's id.
    async fn approve_once(&self) -> String {
        let r = self.fill().await;
        assert_eq!(r["status"], "pending_approval", "{r}");
        let request_id = r["grant_request_id"].as_str().unwrap().to_owned();
        self.broker
            .approve_grant_request(&request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli)
            .unwrap()
            .id
    }

    fn uses(&self, grant_id: &str) -> u64 {
        self.broker
            .grant_store()
            .lock()
            .unwrap()
            .grant(grant_id)
            .expect("grant still in the store")
            .uses
    }
}

#[tokio::test]
async fn req_apr_008_step1_origin_mismatch_gives_the_once_grant_back() {
    let rig = Rig::new();
    let gid = rig.approve_once().await;
    rig.fake
        .script([FakeAnswer::OriginMismatch, FakeAnswer::Filled]);

    // Refused in step 1: nothing was sent, so the use comes back.
    let r = rig.fill().await;
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    assert_eq!(rig.uses(&gid), 0, "a step-1 refusal leaves the use unspent");

    // The same grant still admits, and this time the fill lands.
    let r = rig.fill().await;
    assert_eq!(r["status"], "filled", "{r}");
    assert_eq!(rig.uses(&gid), 1);

    // Now it is spent: the next fill needs a new grant.
    let r = rig.fill().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
}

#[tokio::test]
async fn req_apr_008_in_page_refusal_keeps_the_use_spent() {
    let rig = Rig::new();
    let gid = rig.approve_once().await;
    rig.fake.script([FakeAnswer::OriginMismatchInPage]);

    // The fill call carrying the values was sent, then refused
    // in-page: plaintext reached the renderer, so the use stays spent.
    let r = rig.fill().await;
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    assert_eq!(rig.uses(&gid), 1);
    let r = rig.fill().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
}

#[tokio::test]
async fn req_apr_008_deadline_spent_before_dispatch_gives_the_use_back() {
    let rig = Rig::new();
    let gid = rig.approve_once().await;

    // Admitted, but the deadline is already past at dispatch: no CDP
    // write, no value sent, so the use comes back.
    let long_ago = Instant::now()
        .checked_sub(DEFAULT_FILL_DEADLINE + Duration::from_secs(1))
        .unwrap();
    let r = rig.fill_received(long_ago).await;
    assert_eq!(r["status"], "timeout", "{r}");
    assert!(rig.fake.seen().is_empty(), "nothing reached the backend");
    assert_eq!(rig.uses(&gid), 0);

    let r = rig.fill().await;
    assert_eq!(r["status"], "filled", "{r}");
}

#[tokio::test]
async fn req_apr_008_refusal_after_admission_gives_the_use_back() {
    let rig = Rig::new();
    let gid = rig.approve_once().await;

    // Admitted (the use is spent), then the decrypt fails before any
    // plan exists: the use comes back.
    rig.fail_decrypt.store(true, Ordering::SeqCst);
    let r = rig.fill().await;
    assert_eq!(r["status"], "error", "{r}");
    assert_eq!(r["detail"], "decrypt_failed", "{r}");
    assert_eq!(rig.uses(&gid), 0);

    rig.fail_decrypt.store(false, Ordering::SeqCst);
    let r = rig.fill().await;
    assert_eq!(r["status"], "filled", "{r}");
    assert_eq!(rig.uses(&gid), 1);
}

#[tokio::test]
async fn req_apr_008_concurrent_fills_on_one_once_grant_reach_the_backend_once() {
    let rig = Rig::new();
    let gid = rig.approve_once().await;
    // The first fill sends its values and then stalls in the page
    // until the broker's deadline cuts it off.
    rig.fake.script([FakeAnswer::Stall]);
    // Received so that only 200 ms of the deadline remain.
    let received = Instant::now()
        .checked_sub(DEFAULT_FILL_DEADLINE - Duration::from_millis(200))
        .unwrap();
    let (a, b) = tokio::join!(rig.fill_received(received), rig.fill_received(received));
    let mut statuses = [
        a["status"].as_str().unwrap().to_owned(),
        b["status"].as_str().unwrap().to_owned(),
    ];
    statuses.sort();
    assert_eq!(statuses, ["pending_approval", "timeout"], "{a} {b}");
    assert_eq!(rig.fake.seen().len(), 1, "one fill reached the backend");
    // The stalled fill had sent its values: the use stays spent.
    assert_eq!(rig.uses(&gid), 1);
}
