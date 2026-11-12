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
//!   exists. A claim that fails §6's scheme rule (#180 item 3) is
//!   refused before a request is even created; both the fill and
//!   the explicit grant request audit that pre-refusal as
//!   `origin_mismatch` with detail `insecure_context` (#195).
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
use kharond::api::{Broker, GrantRequestArgs, Outcome, VaultView, parse_fill, parse_grant};
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
        Self::with_origin_cfg(live_url, OriginConfig::default())
    }

    /// [`Self::new`] with a non-default origin config (#180's
    /// `allow_http` cases).
    fn with_origin_cfg(live_url: &'static str, origin_cfg: OriginConfig) -> Self {
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
        let broker = Broker::new(tokens, lock, Box::new(audit.clone()), origin_cfg)
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

    /// A password fill claiming `origin` (the APR-007 / #180 cases
    /// claim something other than the fixture's https origin).
    async fn fill_claim(&self, origin: &str) -> Value {
        let req = parse_fill(
            kharond::api::FillOperation::Fill,
            json!({
                "item_id": ITEM_A,
                "target": {"cdp_target_id": "tab-1", "expected_origin": origin},
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

/// #130: expiry ran only on agent calls, so with a quiet agent an owner
/// could still approve a request long past its 120 s timeout. The owner
/// paths now expire first: the aged request is denied (and audited as a
/// timeout) before approve, deny or the pending list sees it.
#[tokio::test]
async fn req_apr_003_owner_paths_expire_first_so_an_aged_request_cannot_be_approved() {
    let rig = Rig::new("https://login.example.com/signin");
    let r = rig.fill_password().await;
    let aged = r["grant_request_id"].as_str().unwrap().to_owned();
    assert_eq!(rig.broker.pending_grant_requests().len(), 1);

    // +10 min and no agent call since: nothing has run the expiry pass.
    rig.clock.advance(Duration::from_secs(600));

    // The pending list no longer offers it.
    assert!(rig.broker.pending_grant_requests().is_empty());
    // Approve fails closed instead of issuing a grant.
    assert_eq!(
        rig.broker
            .approve_grant_request(&aged, &GrantTerms::once_item(ITEM_A), Channel::Cli),
        Err(GrantError::NotPending)
    );
    assert_eq!(
        rig.broker.grant_request(&aged).unwrap().state,
        RequestState::Denied
    );
    // Exactly one denial, audited as the timeout; no grant_issue.
    let entries = rig.audit_entries();
    let mine: Vec<&Entry> = entries
        .iter()
        .filter(|e| e.request_id.as_deref() == Some(aged.as_str()))
        .collect();
    let results: Vec<(Option<&str>, Option<&str>)> = mine
        .iter()
        .map(|e| (e.result.as_deref(), e.detail_code.as_deref()))
        .collect();
    assert_eq!(
        results,
        [
            (Some("pending"), None),
            (Some("denied"), Some("request_timeout"))
        ],
        "{entries:?}"
    );

    // Deny takes the same path: a second aged request is already
    // denied by the timeout, so the owner's deny finds it not pending.
    let r = rig.fill_password().await;
    let second = r["grant_request_id"].as_str().unwrap().to_owned();
    rig.clock.advance(Duration::from_secs(121));
    assert_eq!(
        rig.broker
            .deny_grant_request(&second, Channel::Cli)
            .map(|_| ()),
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
async fn req_apr_007_http_claim_is_refused_before_a_request_exists() {
    // #180 item 3: claim and tab agree on an http origin, but
    // `allow_http` is off, so the fill could never succeed. No
    // grant request is created and no prompt exists — the refusal
    // is the live check's `origin_mismatch` / `insecure_context`,
    // delivered before approval instead of after it.
    let rig = Rig::new("http://localhost:8080/login");
    let r = rig.fill_claim("http://localhost:8080").await;
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    assert_eq!(r["detail"], "insecure_context", "{r}");
    assert!(r.get("grant_request_id").is_none(), "{r}");
    assert_eq!(rig.decrypts(), 0);
    assert!(rig.fake.seen().is_empty());
    assert!(
        rig.broker
            .grant_store()
            .lock()
            .unwrap()
            .pending_requests()
            .is_empty()
    );
    // Audit: the fill outcome only — no grant_request creation.
    // The outcome carries the scheme refusal's detail (#195), the
    // same `insecure_context` the grants path records.
    let entries = rig.audit_entries();
    let events: Vec<String> = entries
        .iter()
        .map(|e| {
            serde_json::to_value(&e.event)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(events, ["fill"], "{events:?}");
    assert_eq!(entries[0].result.as_deref(), Some("origin_mismatch"));
    assert_eq!(entries[0].detail_code.as_deref(), Some("insecure_context"));
}

#[tokio::test]
async fn req_apr_007_http_claim_prompts_when_allow_http_is_on() {
    // The pre-refusal is the scheme rule's, not a new one: with
    // `allow_http` set, the same claim makes a normal request
    // (the live check still narrows approval to localhost/IP
    // pages whose item URI is literally http).
    let rig = Rig::with_origin_cfg(
        "http://localhost:8080/login",
        OriginConfig { allow_http: true },
    );
    let r = rig.fill_claim("http://localhost:8080").await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    let request_id = r["grant_request_id"].as_str().unwrap().to_owned();
    let req = rig.broker.grant_request(&request_id).unwrap();
    assert_eq!(req.state, RequestState::Pending);
    assert_eq!(req.observed_origin, "http://localhost:8080");
}

#[tokio::test]
async fn req_apr_007_request_grant_http_claim_creates_no_request() {
    // The explicit form (`kharon_request_grant`) pre-refuses the
    // same way: state `origin_mismatch`, no request id, nothing
    // pending.
    let rig = Rig::new("http://localhost:8080/login");
    let args = parse_grant(
        json!({
            "item_id": ITEM_A,
            "target": {"cdp_target_id": "tab-1", "expected_origin": "http://localhost:8080"},
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
    assert_eq!(body.state, "origin_mismatch");
    // The body carries the SPEC row's detail, as the fill path does.
    assert_eq!(body.detail, Some("insecure_context"));
    assert!(body.grant_request_id.is_none());
    assert!(
        rig.broker
            .grant_store()
            .lock()
            .unwrap()
            .pending_requests()
            .is_empty()
    );
    // Audit (REQ-AUD-003): exactly one entry — the refusal itself,
    // with the same `insecure_context` detail the body carries
    // (#195). A request creation would be audited with the new
    // request's id and a `pending` result; there is neither.
    let entries = rig.audit_entries();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(
        serde_json::to_value(&entries[0].event)
            .unwrap()
            .as_str()
            .unwrap(),
        "grant_request"
    );
    assert_eq!(entries[0].result.as_deref(), Some("origin_mismatch"));
    assert_eq!(entries[0].detail_code.as_deref(), Some("insecure_context"));
    assert!(entries[0].request_id.is_none());
}

#[tokio::test]
async fn req_apr_007_request_grant_non_http_scheme_claim_creates_no_request() {
    // #180 item 3, the pre-refusal's catch-all arm: a claim whose
    // scheme is neither `http` nor `https` is pre-refused the same
    // way. The wire parser rejects such claims before they reach
    // the broker, so the args are built directly — the refusal
    // holds in depth.
    let rig = Rig::new("https://login.example.com/signin");
    let args = GrantRequestArgs {
        item_id: ITEM_A.to_owned(),
        target_id: "tab-1".to_owned(),
        expected_origin: "ftp://login.example.com".to_owned(),
        action: GrantAction::Fill,
    };
    let out = rig
        .broker
        .request_grant(&rig.agent(), args, Instant::now())
        .await
        .unwrap();
    let Outcome::GrantRequest(body) = out else {
        panic!("expected a grant request outcome, got {out:?}");
    };
    assert_eq!(body.state, "origin_mismatch");
    assert_eq!(body.detail, Some("insecure_context"));
    assert!(body.grant_request_id.is_none());
    assert!(
        rig.broker
            .grant_store()
            .lock()
            .unwrap()
            .pending_requests()
            .is_empty()
    );
}

/// The audited shape shared by a scheme pre-refusal on either path:
/// exactly one entry, result `origin_mismatch`, detail
/// `insecure_context` (#195, REQ-AUD-003).
fn assert_insecure_scheme_audit(entries: &[Entry], event: &str) {
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].event.as_str(), event);
    assert_eq!(entries[0].result.as_deref(), Some("origin_mismatch"));
    assert_eq!(entries[0].detail_code.as_deref(), Some("insecure_context"));
}

#[tokio::test]
async fn req_apr_007_insecure_scheme_claim_audits_insecure_context_on_both_paths() {
    // #195 (REQ-APR-007, REQ-AUD-003): an insecure-scheme claim is
    // pre-refused before a request exists. Both the fill and the
    // explicit grant request audit that refusal as `origin_mismatch`
    // with `detail_code` `insecure_context`.
    let origin = "http://practicetestautomation.com";

    let fill = Rig::new("http://practicetestautomation.com/practice-test-login");
    let r = fill.fill_claim(origin).await;
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    assert_eq!(r["detail"], "insecure_context", "{r}");
    assert!(r.get("grant_request_id").is_none(), "{r}");
    assert_insecure_scheme_audit(&fill.audit_entries(), "fill");

    let grants = Rig::new("http://practicetestautomation.com/practice-test-login");
    let args = parse_grant(
        json!({
            "item_id": ITEM_A,
            "target": {"cdp_target_id": "tab-1", "expected_origin": origin},
            "action": "fill",
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let out = grants
        .broker
        .request_grant(&grants.agent(), args, Instant::now())
        .await
        .unwrap();
    let Outcome::GrantRequest(body) = out else {
        panic!("expected a grant request outcome, got {out:?}");
    };
    assert_eq!(body.state, "origin_mismatch");
    assert_eq!(body.detail, Some("insecure_context"));
    assert!(body.grant_request_id.is_none());
    let grant_entries = grants.audit_entries();
    assert_insecure_scheme_audit(&grant_entries, "grant_request");
    // No grant request was created, so the entry has no request id.
    assert!(grant_entries[0].request_id.is_none(), "{grant_entries:?}");
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

// ------------------------------------------------- #240: presented grant

/// A password fill on the fixture origin that presents `grant_id`.
async fn fill_presenting(rig: &Rig, grant_id: &str) -> Result<Outcome, kharond::api::ApiError> {
    let req = parse_fill(
        kharond::api::FillOperation::Fill,
        json!({
            "item_id": ITEM_A,
            "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com"},
            "fields": [{"kind": "password"}],
            "grant_id": grant_id,
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    rig.broker.fill(&rig.agent(), req, Instant::now()).await
}

/// The last `fill` outcome entry in the log.
fn last_fill_entry(rig: &Rig) -> Entry {
    rig.audit_entries()
        .into_iter()
        .rev()
        .find(|e| e.event == kharond::audit::Event::Fill)
        .expect("a fill entry")
}

/// A per-origin, 60 s grant for alpha on the fixture item and origin.
fn issue_per_origin(rig: &Rig) -> String {
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
}

/// #240 (REQ-AUD-003): a refused fill names the grant it presented,
/// so a denial traces from the log alone — the #201 restart case,
/// where the presented grant died with the restart, included.
#[tokio::test]
async fn req_aud_003_refused_fill_names_the_presented_grant() {
    let rig = Rig::new("https://login.example.com/signin");
    // An expired grant, presented by name.
    let expired = issue_per_origin(&rig);
    rig.clock.advance(Duration::from_secs(61));
    // A well-shaped id the store has never seen (a grant that died
    // with a restart looks exactly like this).
    let unknown = format!("g_{}", "0123456789abcdef".repeat(2));
    for gid in [expired.as_str(), unknown.as_str()] {
        match fill_presenting(&rig, gid).await {
            Ok(Outcome::Fill(r)) => {
                let v = serde_json::to_value(r).unwrap();
                assert_eq!(v["detail"], "grant_denied", "{v}");
            }
            other => panic!("expected a fill outcome, got {other:?}"),
        }
        let e = last_fill_entry(&rig);
        assert_eq!(e.result.as_deref(), Some("denied"));
        assert_eq!(e.detail_code.as_deref(), Some("grant_denied"));
        assert_eq!(e.grant_id.as_deref(), Some(gid), "the denial names {gid}");
    }
    assert!(rig.fake.seen().is_empty(), "no refused fill reached CDP");
}

/// #240 / REQ-AUD-004: only a value shaped like a minted grant id
/// (`g_` + 32 lowercase hex) is copied into the log. Free text in
/// `grant_id` cannot name a grant, and must not ride into the chain.
#[tokio::test]
async fn req_aud_004_a_malformed_presented_grant_id_is_not_recorded() {
    let rig = Rig::new("https://login.example.com/signin");
    for junk in [
        "g_does_not_exist",
        "hunter2-not-a-grant",
        &format!("g_{}", "A".repeat(32)),
        &format!("g_{}", "a".repeat(33)),
        &format!("gr_{}", "a".repeat(32)),
    ] {
        match fill_presenting(&rig, junk).await {
            Ok(Outcome::Fill(r)) => {
                let v = serde_json::to_value(r).unwrap();
                assert_eq!(v["detail"], "grant_denied", "{v}");
            }
            other => panic!("expected a fill outcome, got {other:?}"),
        }
        assert_eq!(last_fill_entry(&rig).grant_id, None, "{junk} was recorded");
        let log = serde_json::to_string(&rig.audit_entries()).unwrap();
        assert!(!log.contains(junk), "{junk} reached the audit log");
    }
}

/// #240: the lock gate refuses before any grant check, and its entry
/// still names the presented grant.
#[tokio::test]
async fn req_aud_003_locked_fill_names_the_presented_grant() {
    let rig = Rig::new("https://login.example.com/signin");
    let gid = issue_per_origin(&rig);
    rig.broker
        .lock_controller()
        .lock()
        .unwrap()
        .lock(LockReason::Manual);
    let out = fill_presenting(&rig, &gid).await;
    assert!(
        matches!(out, Err(ref e) if *e == kharond::api::ApiError::LOCKED),
        "{out:?}"
    );
    let e = last_fill_entry(&rig);
    assert_eq!(e.result.as_deref(), Some("locked"));
    assert_eq!(e.grant_id.as_deref(), Some(gid.as_str()));
}

/// #240: an admitted fill that presented its grant names it on both
/// transitions, as before.
#[tokio::test]
async fn req_aud_003_admitted_fill_names_the_presented_grant_on_both_entries() {
    let rig = Rig::new("https://login.example.com/signin");
    let gid = issue_per_origin(&rig);
    match fill_presenting(&rig, &gid).await {
        Ok(Outcome::Fill(r)) => {
            let v = serde_json::to_value(r).unwrap();
            assert_eq!(v["status"], "filled", "{v}");
        }
        other => panic!("expected a fill outcome, got {other:?}"),
    }
    let entries = rig.audit_entries();
    let dispatch = entries
        .iter()
        .find(|e| e.event == kharond::audit::Event::FillDispatch)
        .expect("a dispatch entry");
    assert_eq!(dispatch.grant_id.as_deref(), Some(gid.as_str()));
    assert_eq!(
        last_fill_entry(&rig).grant_id.as_deref(),
        Some(gid.as_str())
    );
}
