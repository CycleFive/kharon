//! Dedicated-org scope check and live sync (issue #9; REQ-CRY-008,
//! REQ-CRY-009; SPEC §8 re-sync rules).
//!
//! [`check_dedicated_scope`] is the REQ-CRY-008 predicate on a raw
//! `/api/sync` payload: the kharon account may see the configured
//! organization and nothing else, so neither another org nor an item
//! outside it (personal or another org's) is allowed unless
//! `allow_extra_orgs`. It runs before anything is decrypted, at
//! startup ([`preflight`], API key only), at unlock, and on every
//! re-sync.
//!
//! [`LiveSync`] owns the client, the unlocked [`Session`] and the
//! current [`Vault`]. [`LiveSync::sync_now`] re-syncs and reports
//! whether the broker must lock: the scope widened (audit
//! `scope_widened`) or the org key changed (REQ-MEM-006, audit
//! `key_rotated`). [`run`] polls every `interval` (at most 5 minutes)
//! and on each nudge from its channel, until it must lock; the push
//! source (`/notifications/hub`, [`super::run_push`]) feeds that
//! channel.

use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::vault::norm_id;
use super::wire::SyncResponse;
use super::{Scope, Session, SyncClient, SyncError, Vault};
use crate::audit::{Entry, Event};

/// REQ-CRY-009 / SPEC §8: the longest gap between full syncs while
/// unlocked, and the age past which `/v1/fill` re-syncs first.
pub const MAX_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// What the REQ-CRY-008 check found. Ids only (normalized lowercase).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScopeViolation {
    /// Organizations in the profile other than the configured one.
    pub other_orgs: Vec<String>,
    /// Ciphers that are personal or belong to another organization.
    pub outside_items: Vec<String>,
}

impl ScopeViolation {
    pub fn is_empty(&self) -> bool {
        self.other_orgs.is_empty() && self.outside_items.is_empty()
    }
}

/// Everything in `sync` that a dedicated kharon account should not see.
/// Looks at ids only; decrypts nothing.
pub fn scope_violation(sync: &SyncResponse, organization_id: &str) -> ScopeViolation {
    let org = norm_id(organization_id);
    let other_orgs = sync
        .profile
        .organizations
        .iter()
        .flatten()
        .map(|o| norm_id(&o.id))
        .filter(|o| *o != org)
        .collect();
    let outside_items = sync
        .ciphers
        .iter()
        .flatten()
        .filter(|c| c.organization_id.as_deref().map(norm_id).as_deref() != Some(org.as_str()))
        .map(|c| norm_id(&c.id))
        .collect();
    ScopeViolation {
        other_orgs,
        outside_items,
    }
}

/// REQ-CRY-008: `Err(ScopeTooBroad)` if the account sees another org or
/// an item outside `organization_id`, unless `allow_extra_orgs`.
pub fn check_dedicated_scope(
    sync: &SyncResponse,
    organization_id: &str,
    allow_extra_orgs: bool,
) -> Result<(), SyncError> {
    if allow_extra_orgs {
        return Ok(());
    }
    let v = scope_violation(sync, organization_id);
    if v.is_empty() {
        Ok(())
    } else {
        Err(SyncError::ScopeTooBroad {
            other_orgs: v.other_orgs.len(),
            outside_items: v.outside_items.len(),
        })
    }
}

/// Startup check (REQ-CRY-008 "refuses to start"): log in with the API
/// key, sync, and check scope. Needs no master password.
///
/// The daemon calls this before binding listeners. `SyncError::ScopeTooBroad`
/// refuses startup. Any other error — the server was unreachable, or
/// the payload could not be judged — does not: the daemon logs a
/// warning and still starts, and unlock plus every sync run the same
/// check before they succeed.
pub async fn preflight(
    client: &mut SyncClient,
    organization_id: &str,
    allow_extra_orgs: bool,
) -> Result<(), SyncError> {
    let sync = client.sync().await?;
    check_dedicated_scope(&sync, organization_id, allow_extra_orgs)?;
    if !sync
        .profile
        .organizations
        .iter()
        .flatten()
        .any(|o| norm_id(&o.id) == norm_id(organization_id))
    {
        return Err(SyncError::OrgNotVisible);
    }
    Ok(())
}

/// Why a running sync forces a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockReason {
    /// REQ-CRY-008: the account's view widened mid-run.
    ScopeWidened(ScopeViolation),
    /// REQ-MEM-006: the configured org's protected key changed.
    KeyRotated,
}

impl LockReason {
    pub fn audit_event(&self) -> Event {
        match self {
            Self::ScopeWidened(_) => Event::ScopeWidened,
            Self::KeyRotated => Event::KeyRotated,
        }
    }

    /// The audit entry to append when locking for this reason. Carries a
    /// fixed detail code only (REQ-API-006).
    pub fn audit_entry(&self) -> Entry {
        let code = match self {
            Self::ScopeWidened(v) if !v.other_orgs.is_empty() => "other_org_visible",
            Self::ScopeWidened(_) => "item_outside_org",
            Self::KeyRotated => "org_key_changed",
        };
        Entry::new(self.audit_event()).detail_code(code)
    }
}

/// Result of one re-sync.
#[derive(Debug)]
pub enum SyncOutcome {
    /// The vault was replaced with the fresh sync.
    Synced,
    /// The broker must lock; the vault was left as it was and must be
    /// dropped with the session.
    Lock(LockReason),
}

/// Sync policy from config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncPolicy {
    pub allow_extra_orgs: bool,
    /// Poll interval, clamped to `(0, MAX_SYNC_INTERVAL]`.
    pub interval: Duration,
}

impl SyncPolicy {
    pub fn new(allow_extra_orgs: bool, interval: Duration) -> Self {
        Self {
            allow_extra_orgs,
            interval: interval.clamp(Duration::from_millis(1), MAX_SYNC_INTERVAL),
        }
    }
}

impl Default for SyncPolicy {
    fn default() -> Self {
        Self::new(false, MAX_SYNC_INTERVAL)
    }
}

/// An unlocked, live-synced vault. Dropping it is the lock: the session
/// (org key, private key) and every item go with it.
pub struct LiveSync {
    client: SyncClient,
    session: Session,
    vault: Vault,
    policy: SyncPolicy,
    organization_id: String,
    last_sync: Instant,
}

/// So the lock controller can own a `LiveSync` (the API's session,
/// `api::VaultView`): every key-bearing field wipes itself on drop.
/// `session` is `ZeroizeOnDrop` (org and user keys); the client's API
/// key secret is a `Secret` and its access token a `Zeroizing` buffer;
/// `vault` holds only item metadata and encrypted protected fields
/// (REQ-CRY-006), which are not key material.
impl ZeroizeOnDrop for LiveSync {}

/// The network half of an unlock, done before the lock controller
/// is engaged (issue #11, lock module composition note): prelogin
/// and sync carry no key material, so they run *before*
/// [`LockController::unlock`]; only [`PreparedUnlock::derive`] —
/// the part that touches the master password — runs inside the
/// controller's derivation closure.
pub struct PreparedUnlock {
    client: SyncClient,
    kdf: kharon_bwcrypto::Kdf,
    sync: SyncResponse,
    email: String,
    scope: Scope,
    policy: SyncPolicy,
    organization_id: String,
}

impl PreparedUnlock {
    /// Derive the session from the master password and build the
    /// vault. Synchronous (the KDF is CPU work): call it inside the
    /// lock controller's derivation closure, from a blocking thread.
    pub fn derive(self, password: &Zeroizing<String>) -> Result<LiveSync, SyncError> {
        let mut session =
            Session::unlock(password, &self.email, &self.kdf, &self.sync, self.scope)?;
        let vault = session.apply_sync(&self.sync)?;
        Ok(LiveSync {
            client: self.client,
            session,
            vault,
            policy: self.policy,
            organization_id: self.organization_id,
            last_sync: Instant::now(),
        })
    }
}

impl LiveSync {
    /// The network half of [`LiveSync::unlock`]: prelogin, sync, and
    /// the REQ-CRY-008 scope check (before any key is derived).
    pub async fn prepare(
        mut client: SyncClient,
        scope: Scope,
        policy: SyncPolicy,
    ) -> Result<PreparedUnlock, SyncError> {
        let kdf = client.prelogin().await?;
        let sync = client.sync().await?;
        let organization_id = scope.organization_id().to_owned();
        check_dedicated_scope(&sync, &organization_id, policy.allow_extra_orgs)?;
        let email = client.email().to_owned();
        Ok(PreparedUnlock {
            client,
            kdf,
            sync,
            email,
            scope,
            policy,
            organization_id,
        })
    }

    /// Unlock: prelogin, sync, REQ-CRY-008 check (before any key is
    /// derived), unlock the session, filter.
    pub async fn unlock(
        client: SyncClient,
        password: &Zeroizing<String>,
        scope: Scope,
        policy: SyncPolicy,
    ) -> Result<Self, SyncError> {
        Self::prepare(client, scope, policy).await?.derive(password)
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    /// The push source for this session (REQ-CRY-009): pair
    /// [`super::run_push`] on it with [`run`] on the same channel. It
    /// stops when this `LiveSync` is dropped (the lock).
    pub fn notifications_hub(&self) -> super::NotificationsHub {
        self.client.notifications_hub()
    }

    pub fn policy(&self) -> SyncPolicy {
        self.policy
    }

    /// When the current vault was synced.
    pub fn last_sync(&self) -> Instant {
        self.last_sync
    }

    /// SPEC §8: `/v1/fill` re-syncs first when the vault is older than
    /// [`MAX_SYNC_INTERVAL`].
    pub fn is_stale(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_sync) > MAX_SYNC_INTERVAL
    }

    /// Full `/api/sync`. The scope check runs on the raw payload before
    /// anything is decrypted; a changed org key also locks. Transport
    /// or server errors are returned and keep the current vault.
    pub async fn sync_now(&mut self) -> Result<SyncOutcome, SyncError> {
        let sync = self.client.sync().await?;
        self.apply(&sync)
    }

    /// The offline half of [`Self::sync_now`]: apply a `/api/sync`
    /// payload fetched elsewhere (the daemon fetches with its own
    /// client so the network round trip never runs under the lock
    /// controller's mutex). Same checks, same order: the REQ-CRY-008
    /// scope check on the raw payload before anything is decrypted,
    /// then the org-key comparison (REQ-MEM-006). Synchronous and
    /// CPU-only.
    pub fn apply(&mut self, sync: &SyncResponse) -> Result<SyncOutcome, SyncError> {
        if !self.policy.allow_extra_orgs {
            let v = scope_violation(sync, &self.organization_id);
            if !v.is_empty() {
                return Ok(SyncOutcome::Lock(LockReason::ScopeWidened(v)));
            }
        }
        let vault = self.session.apply_sync(sync)?;
        if vault.report().org_key_changed {
            return Ok(SyncOutcome::Lock(LockReason::KeyRotated));
        }
        self.vault = vault;
        self.last_sync = Instant::now();
        Ok(SyncOutcome::Synced)
    }

    /// The `/v1/fill` hook: re-sync only if stale.
    pub async fn sync_if_stale(&mut self) -> Result<SyncOutcome, SyncError> {
        if self.is_stale(Instant::now()) {
            self.sync_now().await
        } else {
            Ok(SyncOutcome::Synced)
        }
    }
}

/// Poll loop (REQ-CRY-009): a full sync every `policy.interval` (at
/// most 5 minutes) and whenever `nudge` fires (push notifications).
/// Returns when the broker must lock. Sync errors are passed to
/// `on_error` and retried at the next tick; the last good vault stays.
/// A closed `nudge` channel just leaves polling.
pub async fn run(
    live: &mut LiveSync,
    mut nudge: mpsc::Receiver<()>,
    mut on_error: impl FnMut(&SyncError),
) -> LockReason {
    let mut tick =
        tokio::time::interval_at(live.last_sync + live.policy.interval, live.policy.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut push_open = true;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            n = nudge.recv(), if push_open => {
                if n.is_none() {
                    push_open = false;
                    continue;
                }
            }
        }
        match live.sync_now().await {
            Ok(SyncOutcome::Synced) => tick.reset(),
            Ok(SyncOutcome::Lock(reason)) => return reason,
            Err(e) => on_error(&e),
        }
    }
}
