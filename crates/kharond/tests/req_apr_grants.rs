//! REQ-APR-001 / 002 / 003 / 007 (SPEC §5; issue #20): the grant
//! model and request lifecycle, at the broker.
//!
//! - **REQ-APR-001**: a fill with no matching grant returns
//!   `pending_approval` and decrypts **no** secret field before
//!   approval (a counting [`VaultView`] proves the counter stays 0);
//!   after approval the same fill runs and decrypts per fill.
//! - **REQ-APR-002**: matching is per dimension (agent, item /
//!   collection, origin, action, TTL, max_uses — the table itself is
//!   unit-tested in `api::grant`); here: an expired grant and a
//!   grant named by the wrong agent / an unknown `grant_id` at the
//!   broker.
//! - **REQ-APR-003**: with the (manual) clock at +121 s a pending
//!   request is `denied`, and the denial is in the audit log.
//! - **REQ-APR-007**: the prompt shows the live origin the backend
//!   observed; a claim that disagrees makes the fill
//!   `origin_mismatch` and the request is refused before any prompt
//!   exists.
//! - **REQ-MEM-007**: a standing grant is inert while the broker is
//!   locked (the fill returns `locked`, with no CDP write and no
//!   grant use spent) and survives the lock — the same grant admits
//!   again after unlock. (The AC's home issue is #23; the test
//!   lands here per the PR #109 review.)
//!
//! The transports carry the same bodies: the last test runs
//! `kharon_request_grant` over HTTP and MCP against one broker and
//! gets the identical `{grant_request_id, state}` — including the
//! same id, because a pending request is deduped.

mod api_support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use api_support::{
    CHEAP_FLOOR, FakeAnswer, FakeFill, Harness, ITEM_A, RecordingAudit, TestSession, cheap_argon,
    mcp_call, post_json, serve_http,
};
use kharond::api::grant::{Channel, GrantAction, GrantError, GrantTerms, RequestState};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, Outcome, VaultView, parse_fill, parse_grant};
use kharond::audit::Entry;
use kharond::lock::{Clock, LockController, LockPolicy, LockReason, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::sync::{SecretField, SyncError, Vault};
use serde_json::{Value, json};
use tokio::time::Instant;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A [`TestSession`] that counts secret-field decrypts
/// (REQ-APR-001's counter; username is metadata and never goes
/// through `decrypt_secret`).
struct CountingSession {
    inner: TestSession,
    secret_decrypts: Arc<AtomicUsize>,
}

impl ZeroizeOnDrop for CountingSession {}

impl VaultView for CountingSession {
    fn vault(&self) -> &Vault {
        self.inner.vault()
    }

    fn decrypt_secret(
        &self,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        self.secret_decrypts.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt_secret(item_id, field)
    }
}

type CountingBroker = Broker<CountingSession, Arc<ManualClock>>;

struct Rig {
    broker: Arc<CountingBroker>,
    clock: Arc<ManualClock>,
    audit: RecordingAudit,
    decrypts: Arc<AtomicUsize>,
    fake: FakeFill,
    alpha: String,
}

impl Rig {
    /// An unlocked broker whose backend observes `live_url` and
    /// fills successfully, on a manual clock shared by the lock and
    /// grant timers.
    fn new(live_url: &'static str) -> Self {
        let (alpha, ha) = generate_with(&cheap_argon(), "alpha");
        let (_beta, hb) = generate_with(&cheap_argon(), "beta");
        let tokens = TokenStore::with_floor(
            [("alpha", ha.as_str()), ("beta", hb.as_str())],
            &CHEAP_FLOOR,
        )
        .unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut lock = LockController::new(
            LockPolicy::default(),
            clock.clone(),
            Box::new(StaticHardening::all_ok()),
        );
        let decrypts = Arc::new(AtomicUsize::new(0));
        lock.unlock(|| {
            Ok::<_, ()>(CountingSession {
                inner: TestSession::fixture(),
                secret_decrypts: decrypts.clone(),
            })
        })
        .unwrap();
        let audit = RecordingAudit::default();
        let fake = FakeFill::new(FakeAnswer::Filled).with_live_url(live_url);
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
            decrypts,
            fake,
            alpha: alpha.expose_secret().clone(),
        }
    }

    fn agent(&self) -> kharond::api::AgentId {
        self.broker.authenticate(&self.alpha).unwrap()
    }

    fn decrypts(&self) -> usize {
        self.decrypts.load(Ordering::SeqCst)
    }

    async fn fill_password(&self) -> Value {
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
        match self.broker.fill(&self.agent(), req, Instant::now()).await {
            Ok(Outcome::Fill(r)) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a fill outcome, got {other:?}"),
        }
    }

    fn audit_entries(&self) -> Vec<Entry> {
        self.audit.entries.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn req_apr_001_fill_without_grant_is_pending_and_decrypts_nothing() {
    let rig = Rig::new("https://login.example.com/signin");
    // No grant: pending_approval, a request id, no decrypt, and the
    // backend never saw a plan.
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    let request_id = r["grant_request_id"].as_str().unwrap().to_owned();
    assert_eq!(rig.decrypts(), 0);
    assert!(rig.fake.seen().is_empty());
    // The request is pending, with the observed origin on it.
    let req = rig.broker.grant_request(&request_id).unwrap();
    assert_eq!(req.state, RequestState::Pending);
    assert_eq!(req.observed_origin, "https://login.example.com");
    // Audit: the creation, then the fill outcome — no fill_dispatch.
    let events: Vec<String> = rig
        .audit_entries()
        .iter()
        .map(|e| {
            serde_json::to_value(&e.event)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(events, ["grant_request", "fill"], "{events:?}");

    // Approve (once, this item): the same fill now runs, decrypting
    // the password exactly once.
    rig.broker
        .approve_grant_request(&request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli)
        .unwrap();
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "filled", "{r}");
    assert_eq!(rig.decrypts(), 1);
    assert_eq!(rig.fake.seen().len(), 1);

    // The once grant is spent: a third fill is a fresh request, and
    // still nothing is decrypted for it.
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    assert_ne!(r["grant_request_id"].as_str().unwrap(), request_id);
    assert_eq!(rig.decrypts(), 1);
}

#[tokio::test]
async fn req_apr_002_expired_grant_and_named_grant_mismatch() {
    let rig = Rig::new("https://login.example.com/signin");
    // A per-origin grant with a 60 s TTL for alpha.
    let grant_id = {
        let mut store = rig.broker.grant_store().lock().unwrap();
        store
            .issue(
                "alpha",
                ITEM_A,
                GrantAction::Fill,
                "https://login.example.com",
                &GrantTerms {
                    scope: kharond::api::GrantScope::Item(ITEM_A.to_owned()),
                    kind: kharond::config::GrantKind::PerOrigin,
                    ttl: Some(Duration::from_secs(60)),
                    max_uses: None,
                },
                Channel::Cli,
                None,
                rig.clock.now(),
            )
            .unwrap()
            .id
    };
    // Within the TTL the fill runs.
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "filled", "{r}");
    // Past it, the expired grant no longer matches: a new request.
    rig.clock.advance(Duration::from_secs(61));
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    assert_eq!(
        rig.decrypts(),
        1,
        "the expired grant fill decrypted nothing"
    );

    // Naming the (expired) grant explicitly is `denied`, as is an
    // unknown id — never a silent new request.
    for gid in [grant_id.as_str(), "g_does_not_exist"] {
        let req = parse_fill(
            kharond::api::FillOperation::Fill,
            json!({
                "item_id": ITEM_A,
                "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com"},
                "fields": [{"kind": "password"}],
                "grant_id": gid,
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let out = rig.broker.fill(&rig.agent(), req, Instant::now()).await;
        match out {
            Ok(Outcome::Fill(r)) => {
                let v = serde_json::to_value(r).unwrap();
                assert_eq!(v["status"], "denied", "{v}");
                assert_eq!(v["detail"], "grant_denied");
            }
            other => panic!("expected a fill outcome, got {other:?}"),
        }
    }
    assert_eq!(rig.decrypts(), 1);
}

#[tokio::test]
async fn req_apr_003_request_auto_denies_at_timeout_and_is_audited() {
    let rig = Rig::new("https://login.example.com/signin");
    let r = rig.fill_password().await;
    let request_id = r["grant_request_id"].as_str().unwrap().to_owned();
    // At +119 s still pending; at +121 s the expiry pass denies it.
    rig.clock.advance(Duration::from_secs(119));
    assert_eq!(rig.broker.expire_grant_requests().unwrap(), 0);
    assert_eq!(
        rig.broker.grant_request(&request_id).unwrap().state,
        RequestState::Pending
    );
    rig.clock.advance(Duration::from_secs(2));
    assert_eq!(rig.broker.expire_grant_requests().unwrap(), 1);
    assert_eq!(
        rig.broker.grant_request(&request_id).unwrap().state,
        RequestState::Denied
    );
    // The denial is audited, with the timeout as its detail.
    let entries = rig.audit_entries();
    let denials: Vec<&Entry> = entries
        .iter()
        .filter(|e| {
            e.request_id.as_deref() == Some(request_id.as_str())
                && e.result.as_deref() == Some("denied")
        })
        .collect();
    assert_eq!(denials.len(), 1, "{entries:?}");
    assert_eq!(denials[0].detail_code.as_deref(), Some("request_timeout"));
    // And a denied request cannot be approved after the fact.
    assert_eq!(
        rig.broker
            .approve_grant_request(&request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli),
        Err(GrantError::NotPending)
    );
}

#[tokio::test]
async fn req_apr_007_claim_disagreeing_with_live_origin_is_refused_before_prompt() {
    // The tab is on evil.example.com; the agent claims the item's
    // real origin.
    let rig = Rig::new("https://evil.example.com/phish");
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    let request_id = r["grant_request_id"].as_str().unwrap().to_owned();
    let req = rig.broker.grant_request(&request_id).unwrap();
    assert_eq!(req.state, RequestState::OriginMismatch);
    // No prompt exists for it, and approval is refused.
    assert!(req.prompt().is_none());
    assert_eq!(
        rig.broker
            .approve_grant_request(&request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli),
        Err(GrantError::NotPending)
    );
    assert_eq!(rig.decrypts(), 0);
}

#[tokio::test]
async fn req_apr_007_prompt_shows_the_observed_origin_not_the_claim() {
    let rig = Rig::new("https://login.example.com/signin");
    // The claim carries a path; the prompt must show the observed
    // serialized origin, not the claim's text.
    let args = parse_grant(
        json!({
            "item_id": ITEM_A,
            "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com/some/path?x=1"},
            "action": "fill",
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let out = rig
        .broker
        .request_grant(&rig.agent(), args, Instant::now())
        .await
        .unwrap();
    let Outcome::GrantRequest(body) = out else {
        panic!("expected a grant request outcome, got {out:?}");
    };
    assert_eq!(body.state, "pending");
    let req = rig
        .broker
        .grant_request(body.grant_request_id.as_deref().unwrap())
        .unwrap();
    let prompt = req.prompt().expect("a pending request prompts");
    assert_eq!(prompt.origin, "https://login.example.com");
    assert_eq!(prompt.agent_id, "alpha");
    assert_eq!(prompt.item_id, ITEM_A);
}

#[tokio::test]
async fn req_apr_001_status_lists_the_agents_live_grants() {
    let rig = Rig::new("https://login.example.com/signin");
    let r = rig.fill_password().await;
    let request_id = r["grant_request_id"].as_str().unwrap().to_owned();
    rig.broker
        .approve_grant_request(&request_id, &GrantTerms::once_item(ITEM_A), Channel::Cli)
        .unwrap();
    let out = rig
        .broker
        .dispatch(&rig.agent(), kharond::api::Request::Status)
        .unwrap();
    let Outcome::Status(status) = out else {
        panic!("expected status, got {out:?}");
    };
    assert_eq!(status.grants.len(), 1);
    let g = &status.grants[0];
    assert_eq!(g.item_id.as_deref(), Some(ITEM_A));
    assert_eq!(g.origin, "https://login.example.com");
    assert_eq!(g.actions, vec![GrantAction::Fill]);
    assert_eq!(g.max_uses, Some(1));
    assert_eq!(g.uses, 0);
    // Another agent sees none of them.
    let mut store = rig.broker.grant_store().lock().unwrap();
    assert!(store.grants_for("beta", rig.clock.now()).is_empty());
    store
        .issue(
            "beta",
            ITEM_A,
            GrantAction::Fill,
            "https://login.example.com",
            &GrantTerms::once_item(ITEM_A),
            Channel::Cli,
            None,
            rig.clock.now(),
        )
        .unwrap();
    assert_eq!(store.grants_for("beta", rig.clock.now()).len(), 1);
    assert_eq!(store.grants_for("alpha", rig.clock.now()).len(), 1);
}

#[tokio::test]
async fn req_mem_007_standing_grant_is_inert_while_locked_and_survives_lock() {
    let rig = Rig::new("https://login.example.com/signin");
    // A standing grant for alpha (the store is told standing is
    // on, as `[policy] allow_standing` would arrange).
    {
        let mut store = rig.broker.grant_store().lock().unwrap();
        store.set_allow_standing(true);
        store
            .issue(
                "alpha",
                ITEM_A,
                GrantAction::Fill,
                "https://login.example.com",
                &GrantTerms {
                    scope: kharond::api::GrantScope::Item(ITEM_A.to_owned()),
                    kind: kharond::config::GrantKind::Standing,
                    ttl: None,
                    max_uses: None,
                },
                Channel::Cli,
                None,
                rig.clock.now(),
            )
            .unwrap();
    }
    let uses = |rig: &Rig| {
        rig.broker
            .grant_store()
            .lock()
            .unwrap()
            .grants_for("alpha", rig.clock.now())[0]
            .uses
    };
    // Unlocked: the standing grant admits, spending one use.
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "filled", "{r}");
    assert_eq!(rig.fake.seen().len(), 1);
    assert_eq!(uses(&rig), 1);

    // Locked: the grant does not admit — the fill is `locked`,
    // the backend sees no plan (no CDP write), and no use is spent.
    rig.broker
        .lock_controller()
        .lock()
        .unwrap()
        .lock(LockReason::Manual);
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
    let out = rig.broker.fill(&rig.agent(), req, Instant::now()).await;
    assert!(
        matches!(out, Err(e) if e == kharond::api::ApiError::LOCKED),
        "{out:?}"
    );
    assert_eq!(rig.fake.seen().len(), 1, "a locked fill wrote to CDP");
    assert_eq!(uses(&rig), 1, "a locked fill spent a grant use");

    // Unlocked again: the same grant survived the lock and admits.
    rig.broker
        .lock_controller()
        .lock()
        .unwrap()
        .unlock(|| {
            Ok::<_, ()>(CountingSession {
                inner: TestSession::fixture(),
                secret_decrypts: rig.decrypts.clone(),
            })
        })
        .unwrap();
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "filled", "{r}");
    assert_eq!(uses(&rig), 2);
}

#[tokio::test]
async fn req_apr_request_grant_transports_agree() {
    let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/signin");
    let h = Harness::with(false, |b| b.with_fill_backend(Box::new(fake)));
    let addr = serve_http(h.broker.clone()).await;
    let body = json!({
        "item_id": ITEM_A,
        "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com"},
    })
    .to_string();
    let http = post_json(addr, "/v1/grants", Some(&h.alpha), &body).await;
    assert_eq!(http.status, 200, "{}", http.body);
    let http_body = http.json();
    assert_eq!(http_body["state"], "pending", "{http_body}");
    assert!(
        http_body["grant_request_id"]
            .as_str()
            .is_some_and(|s| s.starts_with("gr_"))
    );
    // MCP: the identical call returns the identical body — the same
    // request id, because the pending request is deduped.
    let mcp = mcp_call(addr, Some(&h.alpha), "kharon_request_grant", &body).await;
    assert_eq!(mcp.status, 200, "{}", mcp.body);
    let result = mcp.json();
    let text = result["result"]["content"][0]["text"].as_str().unwrap();
    let mcp_body: Value = serde_json::from_str(text).unwrap();
    assert_eq!(mcp_body, http_body);
    // Seven tools now (REQ-API-001's count with #20's tool).
    let list = api_support::mcp_request(addr, Some(&h.alpha), "tools/list", "{}").await;
    let tools = list.json()["result"]["tools"].as_array().unwrap().clone();
    assert_eq!(tools.len(), 7);
    assert!(tools.iter().any(|t| t["name"] == "kharon_request_grant"));
}
