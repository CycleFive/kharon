//! REQ-RL-001/002/003, REQ-REV-001/002/003/004, REQ-MEM-007 (issue #23).
//!
//! Rate limits, suspension, revoke, panic, revision pinning, and
//! rollback detection at the broker. MEM-007's standing-grant/locked
//! AC already lands in `req_apr_grants.rs` (#109); this file covers
//! the rest and re-checks lock-dominates under a rate-limit load.

mod api_support;

use std::sync::Arc;
use std::time::Duration;

use api_support::{
    CHEAP_FLOOR, FakeAnswer, FakeFill, ITEM_A, RecordingAudit, TestSession, cheap_argon,
};
use kharond::api::grant::{Channel, GrantAction, GrantError, GrantScope, GrantTerms};
use kharond::api::rate::RatePolicy;
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, FillOperation, Outcome, VaultView, parse_fill};
use kharond::audit::{Event, UnresolvedRequest, unresolved_grant_requests};
use kharond::config::GrantKind;
use kharond::lock::{Clock, LockController, LockPolicy, LockReason, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::sync::{Item, SecretField, SyncError, SyncReport, Vault};
use serde_json::{Value, json};
use tokio::time::Instant;
use zeroize::{ZeroizeOnDrop, Zeroizing};

struct CountingSession {
    inner: TestSession,
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
        self.inner.decrypt_secret(item_id, field)
    }
}

/// Mutable vault session for revision / removal tests.
struct MutVaultSession {
    vault: Vault,
    inner: TestSession,
}

impl ZeroizeOnDrop for MutVaultSession {}

impl VaultView for MutVaultSession {
    fn vault(&self) -> &Vault {
        &self.vault
    }

    fn decrypt_secret(
        &self,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        self.inner.decrypt_secret(item_id, field)
    }
}

struct Rig {
    broker: Arc<Broker<CountingSession, Arc<ManualClock>>>,
    #[allow(dead_code)]
    clock: Arc<ManualClock>,
    audit: RecordingAudit,
    fake: FakeFill,
    alpha: String,
}

impl Rig {
    fn new(live_url: &'static str) -> Self {
        Self::with_policy(live_url, RatePolicy::default())
    }

    fn with_policy(live_url: &'static str, rate: RatePolicy) -> Self {
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
        lock.unlock(|| {
            Ok::<_, ()>(CountingSession {
                inner: TestSession::fixture(),
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
        .with_rate_policy(rate)
        .with_fill_backend(Box::new(fake.clone()));
        // Seed rollback high-water from the fixture vault.
        let _ = broker.observe_vault_after_sync(TestSession::fixture().vault());
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

    async fn fill_password(
        &self,
        item: &str,
        origin: &str,
    ) -> Result<Value, kharond::api::ApiError> {
        let req = parse_fill(
            FillOperation::Fill,
            json!({
                "item_id": item,
                "target": {"cdp_target_id": "tab-1", "expected_origin": origin},
                "fields": [{"kind": "password"}],
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        match self.broker.fill(&self.agent(), req, Instant::now()).await {
            Ok(Outcome::Fill(r)) => Ok(serde_json::to_value(r).unwrap()),
            Ok(other) => panic!("expected fill, got {other:?}"),
            Err(e) => Err(e),
        }
    }
}

#[tokio::test]
async fn req_rl_001_eleventh_fill_in_sixty_seconds_is_rate_limited() {
    let rig = Rig::with_policy(
        "https://login.example.com/",
        RatePolicy {
            item_fills_per_window: 100, // isolate the per-agent minute bucket
            ..RatePolicy::default()
        },
    );
    // Approve a standing-ish once grant with high uses via per-origin
    // so fills can actually run past pending_approval.
    let first = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(first["status"], "pending_approval", "{first}");
    let rid = first["grant_request_id"].as_str().unwrap();
    let terms = GrantTerms {
        scope: GrantScope::Item(ITEM_A.to_owned()),
        kind: GrantKind::PerOrigin,
        ttl: Some(Duration::from_secs(3600)),
        max_uses: Some(100),
    };
    rig.broker
        .approve_grant_request(rid, &terms, Channel::Cli)
        .unwrap();

    // The pending_approval above already spent one fill token; nine
    // more succeed (10/min), the 11th API call is rate_limited.
    for i in 0..9 {
        let r = rig
            .fill_password(ITEM_A, "https://login.example.com")
            .await
            .unwrap();
        assert_eq!(r["status"], "filled", "fill {i}: {r}");
    }
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(r["status"], "rate_limited", "{r}");
    let entries = rig.audit.entries.lock().unwrap().clone();
    assert!(
        entries.iter().any(|e| e.event == Event::RateLimit),
        "rate_limit audited"
    );
}

/// REQ-RL-004 (#152): the #121 pilot's case. Refused attempts used up
/// the agent's fill bucket, then the owner approved a `once` grant; that
/// fill must not be stranded. A per-origin grant at the same limit stays
/// under REQ-RL-001.
#[tokio::test]
async fn req_rl_004_once_grant_is_not_stranded_by_a_full_fill_bucket() {
    let rig = Rig::with_policy(
        "https://login.example.com/",
        RatePolicy {
            fills_per_minute: 3,
            item_fills_per_window: 100, // isolate the per-agent bucket
            ..RatePolicy::default()
        },
    );
    // Three refused attempts (the tab is not where the agent claims)
    // spend the whole bucket; three is under the suspension streak.
    for i in 0..3 {
        let r = rig
            .fill_password(ITEM_A, "https://elsewhere.example")
            .await
            .unwrap();
        assert_eq!(r["status"], "origin_mismatch", "attempt {i}: {r}");
    }
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(r["status"], "rate_limited", "bucket full, no grant: {r}");

    let issue = |kind: GrantKind| {
        let mut store = rig.broker.grant_store().lock().unwrap();
        store
            .issue(
                "alpha",
                ITEM_A,
                GrantAction::Fill,
                "https://login.example.com",
                &GrantTerms {
                    scope: GrantScope::Item(ITEM_A.to_owned()),
                    kind,
                    ttl: None,
                    max_uses: None,
                },
                Channel::Cli,
                None,
                rig.clock.now(),
            )
            .unwrap()
            .id
    };

    // The owner approves a once grant: its fill lands despite the
    // full bucket, and spends the grant.
    issue(GrantKind::Once);
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(r["status"], "filled", "a once grant is not stranded: {r}");
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(r["status"], "rate_limited", "the once grant is spent: {r}");

    // A per-origin grant does not bypass the bucket.
    issue(GrantKind::PerOrigin);
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(
        r["status"], "rate_limited",
        "multi-use grants stay under REQ-RL-001: {r}"
    );
}

#[tokio::test]
async fn req_rl_002_iframe_not_allowlisted_counts_toward_the_mismatch_streak() {
    // #180: the iframe-allowlist refusal got its own detail code. It is
    // still an origin_mismatch, so five in a row still suspend.
    let rig = Rig::with_policy(
        "https://login.example.com/",
        RatePolicy {
            item_fills_per_window: 100,
            fills_per_minute: 100,
            ..RatePolicy::default()
        },
    );
    rig.broker
        .grant_store()
        .lock()
        .unwrap()
        .issue(
            "alpha",
            ITEM_A,
            GrantAction::Fill,
            "https://login.example.com",
            &GrantTerms {
                scope: GrantScope::Item(ITEM_A.to_owned()),
                kind: GrantKind::PerOrigin,
                ttl: None,
                max_uses: None,
            },
            Channel::Cli,
            None,
            rig.clock.now(),
        )
        .unwrap();
    rig.fake.script([FakeAnswer::IframeNotAllowlisted; 5]);
    for i in 0..5 {
        let r = rig
            .fill_password(ITEM_A, "https://login.example.com")
            .await
            .unwrap();
        assert_eq!(r["status"], "origin_mismatch", "refusal {i}: {r}");
        assert_eq!(r["detail"], "iframe_not_allowlisted", "refusal {i}: {r}");
    }
    assert!(
        rig.broker
            .rate_limiter()
            .lock()
            .unwrap()
            .is_suspended("alpha")
    );
    let audited = rig
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|e| {
            e.event == Event::Fill && e.detail_code.as_deref() == Some("iframe_not_allowlisted")
        })
        .count();
    assert_eq!(audited, 5, "each refusal is audited with its detail code");
}

#[tokio::test]
async fn req_rl_002_fifth_consecutive_origin_mismatch_suspends_agent() {
    let rig = Rig::with_policy(
        "https://other.example.com/",
        RatePolicy {
            item_fills_per_window: 100,
            fills_per_minute: 100,
            ..RatePolicy::default()
        },
    );
    // Claim login.example.com while live is other → origin_mismatch.
    for i in 0..5 {
        let r = rig
            .fill_password(ITEM_A, "https://login.example.com")
            .await
            .unwrap();
        assert_eq!(r["status"], "origin_mismatch", "mismatch {i}: {r}");
    }
    assert!(
        rig.broker
            .rate_limiter()
            .lock()
            .unwrap()
            .is_suspended("alpha")
    );
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(r["status"], "rate_limited", "{r}");
    let suspended = rig
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.event == Event::RateLimit && e.result.as_deref() == Some("suspended"));
    assert!(suspended, "suspension audited");
    rig.broker.unsuspend_agent("alpha", Channel::Cli).unwrap();
    // After reset, mismatch is allowed again (not rate_limited).
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(r["status"], "origin_mismatch", "{r}");
}

#[tokio::test]
async fn req_rl_002_non_secure_context_neither_counts_nor_resets_the_streak() {
    // #180 item 3 review (Nyx on #188): the scheme pre-refusal
    // returns NonSecureContext, which never counted toward the
    // REQ-RL-002 streak — but it must not reset one either. A
    // grantless `http` claim costs nothing to send, so a reset
    // would be a free evasion between mismatch probes.
    let rig = Rig::with_policy(
        "https://other.example.com/",
        RatePolicy {
            item_fills_per_window: 100,
            fills_per_minute: 100,
            ..RatePolicy::default()
        },
    );
    // Build a streak of four mismatches (suspension is at five).
    for i in 0..4 {
        let r = rig
            .fill_password(ITEM_A, "https://login.example.com")
            .await
            .unwrap();
        assert_eq!(r["status"], "origin_mismatch", "mismatch {i}: {r}");
    }
    // A grantless http claim is pre-refused as insecure_context.
    let r = rig
        .fill_password(ITEM_A, "http://anything.example")
        .await
        .unwrap();
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    assert_eq!(r["detail"], "insecure_context", "{r}");
    assert!(
        !rig.broker
            .rate_limiter()
            .lock()
            .unwrap()
            .is_suspended("alpha"),
        "the insecure-context refusal itself must not suspend"
    );
    // The next mismatch is the fifth consecutive one: the streak
    // survived the pre-refusal, so the agent suspends.
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    assert!(
        rig.broker
            .rate_limiter()
            .lock()
            .unwrap()
            .is_suspended("alpha"),
        "the pre-refusal must not have reset the streak"
    );
}

#[tokio::test]
async fn req_rl_003_fourth_pending_grant_is_rate_limited_without_notification() {
    let rig = Rig::with_policy(
        "https://login.example.com/",
        RatePolicy {
            fills_per_minute: 100,
            item_fills_per_window: 100,
            ..RatePolicy::default()
        },
    );
    {
        let mut store = rig.broker.grant_store().lock().unwrap();
        let now = Duration::from_secs(0);
        for n in 0..3 {
            let (req, created) = store.create_request(
                "alpha",
                &format!("00000000-0000-0000-0000-00000000000{n}"),
                GrantAction::Fill,
                "https://login.example.com",
                "https://login.example.com",
                now,
            );
            assert!(created);
            assert_eq!(req.state, kharond::api::grant::RequestState::Pending);
        }
        assert_eq!(store.pending_count("alpha"), 3);
    }
    let before = rig
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event == Event::GrantRequest)
        .count();
    use api_support::HOST_CLONE;
    let r4 = rig
        .fill_password(HOST_CLONE, "https://login.example.com")
        .await
        .unwrap();
    assert_eq!(r4["status"], "rate_limited", "{r4}");
    let after = rig
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event == Event::GrantRequest)
        .count();
    assert_eq!(after, before, "no notification on 4th pending");
}

#[tokio::test]
async fn req_rev_001_revoke_grant_denies_next_fill() {
    let rig = Rig::new("https://login.example.com/");
    let first = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    let rid = first["grant_request_id"].as_str().unwrap();
    let gid = rig
        .broker
        .approve_grant_request(
            rid,
            &GrantTerms {
                scope: GrantScope::Item(ITEM_A.to_owned()),
                kind: GrantKind::PerOrigin,
                ttl: Some(Duration::from_secs(3600)),
                max_uses: Some(10),
            },
            Channel::Cli,
        )
        .unwrap()
        .id;
    assert!(rig.broker.revoke_grant(&gid, Channel::Cli).unwrap());
    let r = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    // Grant gone → pending again (or denied if named). Without grant_id: pending.
    assert_eq!(r["status"], "pending_approval", "{r}");
}

#[tokio::test]
async fn req_rev_001_revoke_agent_refuses_token_and_grants() {
    let rig = Rig::new("https://login.example.com/");
    let first = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    let rid = first["grant_request_id"].as_str().unwrap();
    rig.broker
        .approve_grant_request(
            rid,
            &GrantTerms {
                scope: GrantScope::Item(ITEM_A.to_owned()),
                kind: GrantKind::PerOrigin,
                ttl: Some(Duration::from_secs(3600)),
                max_uses: Some(10),
            },
            Channel::Cli,
        )
        .unwrap();
    rig.broker.revoke_agent("alpha").unwrap();
    assert!(rig.broker.authenticate(&rig.alpha).is_err());
}

#[tokio::test]
async fn req_rev_002_panic_locks_revokes_and_zeroizes() {
    let rig = Rig::new("https://login.example.com/");
    let first = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap();
    let rid = first["grant_request_id"].as_str().unwrap();
    rig.broker
        .approve_grant_request(
            rid,
            &GrantTerms {
                scope: GrantScope::Item(ITEM_A.to_owned()),
                kind: GrantKind::PerOrigin,
                ttl: Some(Duration::from_secs(3600)),
                max_uses: Some(10),
            },
            Channel::Cli,
        )
        .unwrap();
    // Same wiring as the daemon: the lock sink, not a second broker
    // append, owns the single `panic` entry (REQ-AUD-003).
    rig.broker.wire_lock_audit();
    rig.broker.panic_lock().unwrap();
    assert!(rig.broker.lock_controller().lock().unwrap().is_locked());
    let err = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap_err();
    assert_eq!(err, kharond::api::ApiError::LOCKED);
    assert!(
        rig.broker
            .grant_store()
            .lock()
            .unwrap()
            .grants_for("alpha", Duration::from_secs(0))
            .is_empty()
    );
    let panics = rig
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event == Event::Panic)
        .count();
    assert_eq!(panics, 1, "exactly one panic audit entry");
    // CDP close: FakeFill records on_lock.
    assert!(rig.fake.lock_count() >= 1, "panic closes CDP via lock hook");
}

#[tokio::test]
async fn req_rev_003_item_removal_invalidates_per_item_grants() {
    let (_alpha, ha) = generate_with(&cheap_argon(), "alpha");
    let tokens = TokenStore::with_floor([("alpha", ha.as_str())], &CHEAP_FLOOR).unwrap();
    let clock = Arc::new(ManualClock::new());
    let fixture = TestSession::fixture();
    // Build a vault clone with ITEM_A present, then remove it.
    let mut items: Vec<Item> = fixture
        .vault()
        .items()
        .map(|i| i.with_revision(Some("2026-11-05T12:00:00Z".into())))
        .collect();
    let vault = Vault::with_report(items.clone(), SyncReport::default());
    let mut lock = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| {
        Ok::<_, ()>(MutVaultSession {
            vault: vault.clone(),
            inner: fixture,
        })
    })
    .unwrap();
    let audit = RecordingAudit::default();
    let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/");
    let broker = Broker::new(
        tokens,
        lock,
        Box::new(audit.clone()),
        OriginConfig::default(),
    )
    .with_grant_clock(clock.clone())
    .with_fill_backend(Box::new(fake));
    let _ = broker.observe_vault_after_sync(&vault);
    // Issue a grant for ITEM_A directly.
    let now = Duration::from_secs(0);
    let grant = {
        let mut store = broker.grant_store().lock().unwrap();
        let g = store
            .issue(
                "alpha",
                ITEM_A,
                GrantAction::Fill,
                "login.example.com",
                &GrantTerms {
                    scope: GrantScope::Item(ITEM_A.to_owned()),
                    kind: GrantKind::PerOrigin,
                    ttl: Some(Duration::from_secs(3600)),
                    max_uses: Some(10),
                },
                Channel::Cli,
                None,
                now,
            )
            .unwrap();
        store.pin_revision(&g.id, Some("2026-11-05T12:00:00Z".into()));
        g
    };
    assert!(
        !broker
            .grant_store()
            .lock()
            .unwrap()
            .grants_for("alpha", now)
            .is_empty()
    );
    // Remove ITEM_A and observe.
    items.retain(|i| i.id() != ITEM_A);
    let vault2 = Vault::with_report(items, SyncReport::default());
    assert!(!broker.observe_vault_after_sync(&vault2).unwrap());
    assert!(
        broker
            .grant_store()
            .lock()
            .unwrap()
            .grant(&grant.id)
            .is_none()
    );
    assert!(
        audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.event == Event::GrantRevoke
                && e.detail_code.as_deref() == Some("item_revised_or_removed"))
    );
}

#[tokio::test]
async fn req_rev_003_revoke_first_a_failed_grant_revoke_append_keeps_the_grant_gone() {
    // SPEC §7 revoke-first (#135): the sync removes the grant before its
    // `grant_revoke` entry is appended, and a failed append never
    // restores it. The daemon logs the error instead of discarding it.
    let (_alpha, ha) = generate_with(&cheap_argon(), "alpha");
    let tokens = TokenStore::with_floor([("alpha", ha.as_str())], &CHEAP_FLOOR).unwrap();
    let clock = Arc::new(ManualClock::new());
    let fixture = TestSession::fixture();
    // Build a vault clone with ITEM_A present, then remove it.
    let mut items: Vec<Item> = fixture
        .vault()
        .items()
        .map(|i| i.with_revision(Some("2026-11-05T12:00:00Z".into())))
        .collect();
    let vault = Vault::with_report(items.clone(), SyncReport::default());
    let mut lock = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| {
        Ok::<_, ()>(MutVaultSession {
            vault: vault.clone(),
            inner: fixture,
        })
    })
    .unwrap();
    let audit = RecordingAudit::default();
    let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/");
    let broker = Broker::new(
        tokens,
        lock,
        Box::new(audit.clone()),
        OriginConfig::default(),
    )
    .with_grant_clock(clock.clone())
    .with_fill_backend(Box::new(fake));
    let _ = broker.observe_vault_after_sync(&vault);
    // Issue a grant for ITEM_A directly.
    let now = Duration::from_secs(0);
    let grant = {
        let mut store = broker.grant_store().lock().unwrap();
        let g = store
            .issue(
                "alpha",
                ITEM_A,
                GrantAction::Fill,
                "login.example.com",
                &GrantTerms {
                    scope: GrantScope::Item(ITEM_A.to_owned()),
                    kind: GrantKind::PerOrigin,
                    ttl: Some(Duration::from_secs(3600)),
                    max_uses: Some(10),
                },
                Channel::Cli,
                None,
                now,
            )
            .unwrap();
        store.pin_revision(&g.id, Some("2026-11-05T12:00:00Z".into()));
        g
    };
    assert!(
        !broker
            .grant_store()
            .lock()
            .unwrap()
            .grants_for("alpha", now)
            .is_empty()
    );
    // Remove ITEM_A and observe, with `grant_revoke` appends failing.
    *audit.fail_event.lock().unwrap() = Some("grant_revoke");
    items.retain(|i| i.id() != ITEM_A);
    let vault2 = Vault::with_report(items, SyncReport::default());
    assert_eq!(
        broker.observe_vault_after_sync(&vault2),
        Err(GrantError::AuditFailed)
    );
    assert!(
        broker
            .grant_store()
            .lock()
            .unwrap()
            .grant(&grant.id)
            .is_none()
    );
    assert!(
        !audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.event == Event::GrantRevoke),
        "the failed append wrote nothing"
    );
}

#[tokio::test]
async fn req_rev_004_revision_change_denies_fill_and_older_sync_locks() {
    let (alpha, ha) = generate_with(&cheap_argon(), "alpha");
    let tokens = TokenStore::with_floor([("alpha", ha.as_str())], &CHEAP_FLOOR).unwrap();
    let clock = Arc::new(ManualClock::new());
    let fixture = TestSession::fixture();
    let items: Vec<Item> = fixture
        .vault()
        .items()
        .map(|i| i.with_revision(Some("2026-11-05T12:00:00Z".into())))
        .collect();
    let vault = Vault::with_report(items.clone(), SyncReport::default());
    let mut lock = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| {
        Ok::<_, ()>(MutVaultSession {
            vault: vault.clone(),
            inner: TestSession::fixture(),
        })
    })
    .unwrap();
    let audit = RecordingAudit::default();
    let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/");
    let broker = Arc::new(
        Broker::new(
            tokens,
            lock,
            Box::new(audit.clone()),
            OriginConfig::default(),
        )
        .with_grant_clock(clock.clone())
        .with_fill_backend(Box::new(fake)),
    );
    // Same wiring as the daemon, before any rollback lock, so a
    // broker append plus the sink would show up as two entries.
    broker.wire_lock_audit();
    assert!(!broker.observe_vault_after_sync(&vault).unwrap());
    let now = Duration::from_secs(0);
    let gid = {
        let mut store = broker.grant_store().lock().unwrap();
        let g = store
            .issue(
                "alpha",
                ITEM_A,
                GrantAction::Fill,
                "login.example.com",
                &GrantTerms {
                    scope: GrantScope::Item(ITEM_A.to_owned()),
                    kind: GrantKind::PerOrigin,
                    ttl: Some(Duration::from_secs(3600)),
                    max_uses: Some(10),
                },
                Channel::Cli,
                None,
                now,
            )
            .unwrap();
        store.pin_revision(&g.id, Some("2026-11-05T12:00:00Z".into()));
        g.id
    };
    // Change revision on ITEM_A in a new vault snapshot.
    let mut items2 = items.clone();
    for i in &mut items2 {
        if i.id() == ITEM_A {
            i.set_revision(Some("2026-11-05T13:00:00Z".into()));
        }
    }
    let vault2 = Vault::with_report(items2, SyncReport::default());
    // Replace session vault so fill sees the new revision.
    {
        let mut lock = broker.lock_controller().lock().unwrap();
        lock.lock(LockReason::Manual);
        lock.unlock(|| {
            Ok::<_, ()>(MutVaultSession {
                vault: vault2.clone(),
                inner: TestSession::fixture(),
            })
        })
        .unwrap();
    }
    let _ = broker.observe_vault_after_sync(&vault2);
    // Grant may have been invalidated by REV-003 on observe; if it
    // survived (collection?) — for item scope it should be gone.
    // Re-issue with old pin against new vault to test fill denial:
    {
        let mut store = broker.grant_store().lock().unwrap();
        let g = store
            .issue(
                "alpha",
                ITEM_A,
                GrantAction::Fill,
                "login.example.com",
                &GrantTerms {
                    scope: GrantScope::Item(ITEM_A.to_owned()),
                    kind: GrantKind::PerOrigin,
                    ttl: Some(Duration::from_secs(3600)),
                    max_uses: Some(10),
                },
                Channel::Cli,
                None,
                now,
            )
            .unwrap();
        store.pin_revision(&g.id, Some("2026-11-05T12:00:00Z".into()));
    }
    let token = alpha.expose_secret().clone();
    let agent = broker.authenticate(&token).unwrap();
    let req = parse_fill(
        FillOperation::Fill,
        json!({
            "item_id": ITEM_A,
            "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com"},
            "fields": [{"kind": "password"}],
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    let r = match broker.fill(&agent, req, Instant::now()).await {
        Ok(Outcome::Fill(r)) => serde_json::to_value(r).unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(r["status"], "denied", "{r}");

    // Older cipher → rollback lock.
    let mut items3 = items;
    for i in &mut items3 {
        if i.id() == ITEM_A {
            i.set_revision(Some("2026-11-05T11:00:00Z".into()));
        }
    }
    let vault3 = Vault::with_report(items3, SyncReport::default());
    assert!(broker.observe_vault_after_sync(&vault3).unwrap());
    assert!(broker.lock_controller().lock().unwrap().is_locked());
    let rollbacks = audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event == Event::RollbackDetected)
        .count();
    assert_eq!(rollbacks, 1, "exactly one rollback_detected audit entry");
    let _ = gid;
}

#[tokio::test]
async fn req_mem_007_lock_dominates_even_under_rate_pressure() {
    // Standing grant + locked → locked (not rate_limited).
    let rig = Rig::with_policy(
        "https://login.example.com/",
        RatePolicy {
            fills_per_minute: 1, // would rate-limit a second fill
            ..RatePolicy::default()
        },
    );
    rig.broker
        .grant_store()
        .lock()
        .unwrap()
        .set_allow_standing(true);
    let now = Duration::from_secs(0);
    rig.broker
        .grant_store()
        .lock()
        .unwrap()
        .issue(
            "alpha",
            ITEM_A,
            GrantAction::Fill,
            "login.example.com",
            &GrantTerms {
                scope: GrantScope::Item(ITEM_A.to_owned()),
                kind: GrantKind::Standing,
                ttl: Some(Duration::from_secs(3600)),
                max_uses: None,
            },
            Channel::Cli,
            None,
            now,
        )
        .unwrap();
    {
        let mut lock = rig.broker.lock_controller().lock().unwrap();
        lock.lock(LockReason::Manual);
    }
    let err = rig
        .fill_password(ITEM_A, "https://login.example.com")
        .await
        .unwrap_err();
    assert_eq!(err, kharond::api::ApiError::LOCKED);
}

// #196 (REQ-AUD-003): panic and agent revoke drop pending grant
// requests. Each must end with exactly one terminal entry at the
// moment it is dropped, not an `abandoned` at the next start (#130).

/// A fill that stops at `pending_approval`; its grant request id.
async fn pending_request(rig: &Rig, item: &str, origin: &str) -> String {
    let r = rig.fill_password(item, origin).await.unwrap();
    assert_eq!(r["status"], "pending_approval", "{r}");
    r["grant_request_id"].as_str().unwrap().to_owned()
}

/// Approve `request_id` with a short per-origin grant.
fn approve(rig: &Rig, request_id: &str, item: &str) {
    rig.broker
        .approve_grant_request(
            request_id,
            &GrantTerms {
                scope: GrantScope::Item(item.to_owned()),
                kind: GrantKind::PerOrigin,
                ttl: Some(Duration::from_secs(3600)),
                max_uses: Some(10),
            },
            Channel::Cli,
        )
        .unwrap();
}

/// `(result, detail_code)` of every `grant_request` entry for
/// `request_id` other than its `pending` creation.
fn request_endings(rig: &Rig, request_id: &str) -> Vec<(Option<String>, Option<String>)> {
    rig.audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event == Event::GrantRequest)
        .filter(|e| e.request_id.as_deref() == Some(request_id))
        .filter(|e| e.result.as_deref() != Some("pending"))
        .map(|e| (e.result.clone(), e.detail_code.clone()))
        .collect()
}

/// The requests the next daemon start would audit as `abandoned`
/// (#130), read from what the rig has recorded so far.
fn abandoned_on_next_start(rig: &Rig) -> Vec<UnresolvedRequest> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = String::new();
    for entry in rig.audit.entries.lock().unwrap().iter() {
        log.push_str(&serde_json::to_string(entry).unwrap());
        log.push('\n');
    }
    std::fs::write(&path, log).unwrap();
    unresolved_grant_requests(&path).unwrap()
}

fn denied(detail: &str) -> Vec<(Option<String>, Option<String>)> {
    vec![(Some("denied".to_owned()), Some(detail.to_owned()))]
}

#[tokio::test]
async fn req_aud_003_panic_ends_each_pending_request_with_one_denial() {
    let rig = Rig::new("https://login.example.com/");
    let approved = pending_request(&rig, ITEM_A, "https://login.example.com").await;
    approve(&rig, &approved, ITEM_A);
    let pending = pending_request(&rig, api_support::HOST_CLONE, "https://login.example.com").await;

    rig.broker.wire_lock_audit();
    rig.broker.panic_lock().unwrap();

    assert_eq!(request_endings(&rig, &pending), denied("panic"));
    // Already resolved by its grant_issue: no second ending.
    assert_eq!(request_endings(&rig, &approved), []);
    assert_eq!(abandoned_on_next_start(&rig), []);
}

#[tokio::test]
async fn req_aud_003_agent_revoke_ends_each_pending_request_with_one_denial() {
    let rig = Rig::new("https://login.example.com/");
    let approved = pending_request(&rig, ITEM_A, "https://login.example.com").await;
    approve(&rig, &approved, ITEM_A);
    let pending = pending_request(&rig, api_support::HOST_CLONE, "https://login.example.com").await;

    rig.broker.revoke_agent("alpha").unwrap();

    assert_eq!(request_endings(&rig, &pending), denied("agent_revoked"));
    assert_eq!(request_endings(&rig, &approved), []);
    assert_eq!(abandoned_on_next_start(&rig), []);
}

#[tokio::test]
async fn req_aud_003_agent_revoke_failed_denial_append_does_not_restore_the_request() {
    let rig = Rig::new("https://login.example.com/");
    let pending = pending_request(&rig, api_support::HOST_CLONE, "https://login.example.com").await;
    *rig.audit.fail_event.lock().unwrap() = Some("grant_request");

    assert_eq!(
        rig.broker.revoke_agent("alpha"),
        Err(GrantError::AuditFailed)
    );

    // Not put back: a pending request for a revoked token could only
    // be approved into a grant nobody can use. It falls back to
    // `abandoned` at the next start, as before #196.
    assert_eq!(
        rig.broker
            .grant_store()
            .lock()
            .unwrap()
            .pending_count("alpha"),
        0
    );
    assert!(rig.broker.authenticate(&rig.alpha).is_err());
    assert_eq!(request_endings(&rig, &pending), []);
    let left = abandoned_on_next_start(&rig);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].request_id, pending);
}

/// Whether the log holds the entry the startup rebuild revokes
/// `alpha` from (#132).
fn token_revoke_logged(rig: &Rig) -> bool {
    rig.audit.entries.lock().unwrap().iter().any(|e| {
        e.event == Event::TokenRevoke
            && e.agent_id.as_deref() == Some("alpha")
            && e.result.as_deref() == Some("revoked")
    })
}

#[tokio::test]
async fn req_rev_001_agent_revoke_is_durable_when_a_request_denial_append_fails() {
    let rig = Rig::new("https://login.example.com/");
    pending_request(&rig, api_support::HOST_CLONE, "https://login.example.com").await;
    *rig.audit.fail_event.lock().unwrap() = Some("grant_request");

    assert_eq!(
        rig.broker.revoke_agent("alpha"),
        Err(GrantError::AuditFailed)
    );

    // The agent is refused now, and the log says so, so a restart
    // refuses it too (#242, from the #261 review).
    assert!(rig.broker.authenticate(&rig.alpha).is_err());
    assert!(
        token_revoke_logged(&rig),
        "token_revoke must be written before the entries that can fail after it"
    );
}

#[tokio::test]
async fn req_rev_001_agent_revoke_is_durable_when_a_grant_revoke_append_fails() {
    let rig = Rig::new("https://login.example.com/");
    let approved = pending_request(&rig, ITEM_A, "https://login.example.com").await;
    approve(&rig, &approved, ITEM_A);
    *rig.audit.fail_event.lock().unwrap() = Some("grant_revoke");

    assert_eq!(
        rig.broker.revoke_agent("alpha"),
        Err(GrantError::AuditFailed)
    );

    assert!(rig.broker.authenticate(&rig.alpha).is_err());
    assert!(
        token_revoke_logged(&rig),
        "token_revoke must be written before the entries that can fail after it"
    );
}
