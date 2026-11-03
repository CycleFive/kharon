//! Lock state machine, unlock flow, and lock timers (issue #11;
//! SPEC §8; REQ-MEM-001..006, REQ-CRY-006).
//!
//! The broker boots locked and stays locked until the owner unlocks
//! it (REQ-MEM-005). [`LockController`] owns the one unlocked
//! session — the key material produced by an unlock — and the two
//! timers that end it: idle (default 30m since the last activity)
//! and absolute (default 12h since unlock) (REQ-MEM-004). The
//! timers are enforced at the fill gate itself
//! ([`LockController::require_unlocked`]), not only by
//! [`LockController::poll`]: an expired session is locked before it
//! can be handed out, and activity can never revive one (review
//! #50, blocking item 1). Locking, for any reason, destroys the
//! session (REQ-MEM-003): the session type is bounded by
//! [`ZeroizeOnDrop`], so dropping it wipes its keys. That bound is
//! deliberate — the real session (`sync::Session`) holds an
//! `RsaPrivateKey`, which implements `ZeroizeOnDrop` but cannot
//! implement `Zeroize` (review #50, blocking item 2).
//!
//! Unlock is deliberately ordered so key material cannot exist
//! before the host is ready for it:
//!
//! 1. `mlockall` runs first. When the policy requires it
//!    (`require_mlock = true`, the default), failure refuses the
//!    unlock with [`UnlockError::MlockUnavailable`] and the
//!    derivation closure is never called (REQ-MEM-002). When it
//!    does not, mlock is still attempted best-effort and a failure
//!    is reported as [`LockEvent::MlockBestEffortFailed`] rather
//!    than silently running swappable. Two caveats for the daemon
//!    (#14): the syscall is authoritative for *refusal* at unlock
//!    time, but with `MCL_FUTURE` and a finite memlock limit a
//!    successful `mlockall` on a small footprint can still abort
//!    the process on a later allocation past the limit — so #14
//!    must refuse unlock if *either* the config loader's
//!    `ProcfsMlockProbe` (#47) or the syscall says no. And the
//!    master password is captured by the derivation closure
//!    *before* this step runs, so #14 closes that window by calling
//!    `lock_memory()` once at startup, right after
//!    `harden_process()`, whenever `require_mlock` is set.
//! 2. The caller's derivation closure runs (prelogin → login → sync
//!    → master key → user key → private key → org key, i.e.
//!    `sync::Session::unlock`). Its contract: the master password
//!    and master key are zeroized inside the closure before it
//!    returns (REQ-MEM-003); only the session it returns may hold
//!    keys. Composition with master's async sync (review #50,
//!    item 8): run `prelogin` + `sync` — network only, no key
//!    material — *before* `unlock()`, then `Session::unlock` +
//!    `apply_sync` inside the closure. The closure runs
//!    synchronously (the KDF is CPU work) while `&mut
//!    LockController` is held, so the daemon must guard the
//!    controller with a `std::sync::Mutex` inside `spawn_blocking`,
//!    never a tokio mutex across `.await`; a `lock` request that
//!    arrives mid-unlock then serializes after it, which is
//!    correct.
//! 3. The `Unlocked` audit entry is written (REQ-AUD-003: write
//!    failure fails closed — if the sink rejects it, the fresh
//!    session is destroyed and the unlock reports
//!    [`UnlockError::Audit`]). Only then are the timers recorded
//!    as started.
//!
//! Forced locks (REQ-MEM-006, REQ-CRY-008): the sync layer reports
//! a rotated org key, an unknown crypto version, or a widened
//! dedicated-org scope, and the controller locks with the matching
//! [`LockReason`]; the audit event names are `key_rotated` and
//! `scope_widened`, as the ACs name them. A `Locked` audit entry is
//! written best-effort: the lock stands regardless of whether the
//! write succeeds (REQ-AUD-003's fail-closed rule governs the
//! request path, and there is no request left to fail once the
//! session is gone).
//!
//! Every transition is reported to an optional fallible event sink
//! as a [`LockEvent`]; the daemon wires the sink to the audit log
//! (REQ-AUD-003), tests wire it to a `Vec`.
//!
//! Lock also closes CDP sessions (SPEC §8, issue #66). Every lock
//! path (manual, idle/absolute expiry, forced) goes through
//! [`LockController::lock`], which runs the optional lock hook
//! ([`LockController::set_lock_hook`]) right after the session is
//! dropped. The broker wires the hook to its fill backend, which
//! invalidates cached browser contexts and connections and tears them
//! down in the background. The hook is infallible and must not block:
//! the lock (and the zeroization that comes with it) never depends on
//! the browser answering.
//!
//! Field classes (REQ-CRY-006) are enforced by the session type
//! (metadata decrypted at sync, secrets decrypted per fill into
//! zeroizing buffers, no plaintext secret cache); the controller's
//! part is that lock destroys the whole session at once, so no
//! decrypted state can outlive the unlock that produced it.

mod clock;
mod hardening;

use std::time::Duration;

use zeroize::ZeroizeOnDrop;

use crate::audit::{Entry, Event};
use crate::config::{MemoryConfig, PolicyConfig};
use crate::sync::LockReason as SyncLockReason;

pub use clock::{Clock, ManualClock, SystemClock};
pub use hardening::{
    HardeningError, MemoryHardening, ProcessHardening, ProcessHardeningStatus, StaticHardening,
    process_status,
};

/// SPEC §8 / §9 defaults: idle lock 30m, absolute 12h, mlock
/// required. The daemon overrides these from `[policy]` / `[memory]`
/// config via [`LockPolicy::from`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockPolicy {
    /// Lock after this much time with no fill activity.
    pub idle_lock: Duration,
    /// Lock this long after unlock, however active.
    pub max_unlocked: Duration,
    /// Refuse to unlock when `mlockall` fails (REQ-MEM-002).
    pub require_mlock: bool,
}

impl Default for LockPolicy {
    fn default() -> Self {
        Self {
            idle_lock: Duration::from_secs(30 * 60),
            max_unlocked: Duration::from_secs(12 * 60 * 60),
            require_mlock: true,
        }
    }
}

impl From<(&PolicyConfig, &MemoryConfig)> for LockPolicy {
    /// Wire the config loader's validated values (#47/#51) into the
    /// lock policy: timers from `[policy]`, `require_mlock` from
    /// `[memory]`.
    fn from((policy, memory): (&PolicyConfig, &MemoryConfig)) -> Self {
        Self {
            idle_lock: policy.idle_lock,
            max_unlocked: policy.max_unlocked,
            require_mlock: memory.require_mlock,
        }
    }
}

/// The audit sink refused an entry (REQ-AUD-003). Carries no detail:
/// the sink owns its error text, and audit payloads never carry
/// secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("audit write failed")]
pub struct AuditError;

/// Why the broker locked. Its audit entry is built by
/// [`LockReason::audit_entry`]: ordinary locks are `Event::Lock`
/// with a fixed `detail_code`, and the two forced locks whose audit
/// entries the ACs name directly are their own events —
/// `key_rotated` (REQ-MEM-006) and `scope_widened` (REQ-CRY-008).
/// (Issue #54, item 2: the previous `audit_event() -> &str` returned
/// `locked_*` strings that are not `audit::Event` names at all, and
/// `Event` deserialization rejects unknown names.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// Owner action (`kharon lock`, web UI, `kharon panic`).
    Manual,
    /// No fill activity for `idle_lock` (REQ-MEM-004).
    IdleTimeout,
    /// `max_unlocked` elapsed since unlock (REQ-MEM-004).
    AbsoluteTimeout,
    /// The server presented a different org key (REQ-MEM-006).
    KeyRotated,
    /// A payload used a crypto version kharon does not know
    /// (REQ-MEM-006).
    UnknownCryptoVersion,
    /// The account's view widened past the dedicated org mid-run
    /// (REQ-CRY-008).
    ScopeWidened,
}

impl LockReason {
    /// The audit entry for this lock (REQ-AUD-003, REQ-MEM-006,
    /// REQ-CRY-008; issue #54, item 2). Ordinary locks are
    /// `Event::Lock` plus a fixed `detail_code` (`manual`,
    /// `idle_timeout`, `absolute_timeout`,
    /// `unknown_crypto_version` — fixed strings only, never
    /// interpolated values, per REQ-API-006). The forced locks are
    /// their own events (`Event::KeyRotated` /
    /// `Event::ScopeWidened`) with no `detail_code`: the lock side
    /// does not know the finer sync-side cause, which
    /// `sync::LockReason::audit_entry` carries in its own
    /// `detail_code` (`org_key_changed` / `other_org_visible` /
    /// `item_outside_org`) when the caller has it.
    pub fn audit_entry(self) -> Entry {
        match self {
            Self::Manual => Entry::new(Event::Lock).detail_code("manual"),
            Self::IdleTimeout => Entry::new(Event::Lock).detail_code("idle_timeout"),
            Self::AbsoluteTimeout => Entry::new(Event::Lock).detail_code("absolute_timeout"),
            Self::KeyRotated => Entry::new(Event::KeyRotated),
            Self::UnknownCryptoVersion => {
                Entry::new(Event::Lock).detail_code("unknown_crypto_version")
            }
            Self::ScopeWidened => Entry::new(Event::ScopeWidened),
        }
    }
}

impl From<&SyncLockReason> for LockReason {
    /// The single conversion from the sync layer's lock reason to
    /// the controller's (issue #54, item 3): a `SyncOutcome::Lock`
    /// feeds the controller through this conversion (or through
    /// [`LockController::on_sync_lock`], which uses it), never
    /// through a second hand-mapped path. The sync side keeps its
    /// own finer `detail_code`s in its `audit_entry()`; this
    /// conversion carries only the controller-level reason.
    fn from(reason: &SyncLockReason) -> Self {
        match reason {
            SyncLockReason::ScopeWidened(_) => Self::ScopeWidened,
            SyncLockReason::KeyRotated => Self::KeyRotated,
        }
    }
}

impl From<SyncLockReason> for LockReason {
    fn from(reason: SyncLockReason) -> Self {
        Self::from(&reason)
    }
}

/// A lock-state transition, for the audit log (REQ-AUD-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEvent {
    /// Unlock succeeded; both timers started.
    Unlocked,
    /// Unlock was refused before any key derivation ran.
    UnlockRefusedMlock,
    /// `require_mlock = false` and the best-effort `mlockall` still
    /// failed: the unlock proceeds, but the session's pages are
    /// swappable and the operator should know.
    MlockBestEffortFailed,
    /// The broker locked; the session was destroyed.
    Locked {
        /// Why.
        reason: LockReason,
    },
}

impl LockEvent {
    /// The audit entry for this transition, where the audit
    /// vocabulary has one (issue #54, item 2): `Unlocked` maps to
    /// `Event::Unlock` the same way a lock maps through
    /// [`LockReason::audit_entry`]. The mlock transitions have no
    /// `audit::Event` variant and return `None` — they are operator
    /// signals, not audited events, and no new event name may be
    /// invented for them (`Event` rejects unknown names).
    pub fn audit_entry(self) -> Option<Entry> {
        match self {
            Self::Unlocked => Some(Entry::new(Event::Unlock)),
            Self::Locked { reason } => Some(reason.audit_entry()),
            Self::UnlockRefusedMlock | Self::MlockBestEffortFailed => None,
        }
    }
}

/// Why an unlock attempt failed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum UnlockError<E> {
    /// `require_mlock = true` and `mlockall` failed (REQ-MEM-002).
    /// No key derivation ran.
    #[error("mlock unavailable and require_mlock = true (REQ-MEM-002)")]
    MlockUnavailable,
    /// The broker is already unlocked; the derivation closure was
    /// not called.
    #[error("already unlocked")]
    AlreadyUnlocked,
    /// The derivation closure failed (wrong password, sync error,
    /// crypto error, …). The broker stays locked.
    #[error("unlock derivation failed: {0}")]
    DeriveFailed(#[source] E),
    /// The audit sink refused the `Unlocked` entry, so the unlock
    /// was rolled back and the fresh session destroyed
    /// (REQ-AUD-003: write failure fails closed).
    #[error("audit write failed; unlock rolled back (REQ-AUD-003)")]
    Audit(#[source] AuditError),
}

/// The broker is locked (the fill gate: REQ-MEM-007's seam — any
/// fill attempted in this state is refused `locked` before grants
/// are even consulted; issue #18 wires the endpoints).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("broker is locked")]
pub struct LockedError;

struct Unlocked<S> {
    session: S,
    unlocked_at: Duration,
    last_activity_at: Duration,
}

/// The audit sink signature: fallible, so REQ-AUD-003's fail-closed
/// rule can be enforced at the transitions it governs.
type EventSink = Box<dyn FnMut(LockEvent) -> Result<(), AuditError> + Send>;

/// Run on every lock, after the session is gone (issue #66). Cannot
/// fail and must return promptly: it runs under the controller.
pub type LockHook = Box<dyn FnMut(LockReason) + Send>;

/// Owns the lock state and (while unlocked) the session's keys.
///
/// `S` is the session type produced by an unlock (`sync::Session`
/// in the daemon). It must implement [`ZeroizeOnDrop`]: locking
/// drops the session, and the type's own drop wipes its key
/// material (REQ-MEM-003). In-place `Zeroize` is *not* required —
/// the real session's `RsaPrivateKey` cannot provide it.
pub struct LockController<S: ZeroizeOnDrop, C: Clock = SystemClock> {
    policy: LockPolicy,
    clock: C,
    hardening: Box<dyn MemoryHardening>,
    unlocked: Option<Unlocked<S>>,
    sink: Option<EventSink>,
    lock_hook: Option<LockHook>,
}

impl<S: ZeroizeOnDrop, C: Clock> LockController<S, C> {
    /// A locked controller (REQ-MEM-005: boots locked; nothing is
    /// persisted, so a restart constructs exactly this).
    pub fn new(policy: LockPolicy, clock: C, hardening: Box<dyn MemoryHardening>) -> Self {
        Self {
            policy,
            clock,
            hardening,
            unlocked: None,
            sink: None,
            lock_hook: None,
        }
    }

    /// Run `hook` on every lock, whatever the reason, right after the
    /// session is dropped and before the `Locked` audit entry (SPEC §8
    /// "lock … closes CDP sessions"; issue #66). It runs while the
    /// controller is borrowed (in the daemon: under the broker's
    /// `std::sync::Mutex`), so it must not block or `.await`; the
    /// broker's hook only signals the fill backend, which tears its
    /// CDP sessions down in the background.
    pub fn set_lock_hook(&mut self, hook: LockHook) {
        self.lock_hook = Some(hook);
    }

    /// Report every transition to `sink` (the daemon's audit log).
    /// The sink is fallible: see the module docs for which
    /// transitions fail closed on a write error (REQ-AUD-003).
    pub fn set_event_sink(&mut self, sink: EventSink) {
        self.sink = Some(sink);
    }

    fn emit(&mut self, event: LockEvent) -> Result<(), AuditError> {
        match &mut self.sink {
            Some(sink) => sink(event),
            None => Ok(()),
        }
    }

    /// Whether the broker is locked. Note this reflects the last
    /// enforced state: an expired-but-not-yet-checked session still
    /// reports unlocked until [`Self::poll`] or
    /// [`Self::require_unlocked`] runs the expiry check. The fill
    /// path always goes through `require_unlocked`, so the timers
    /// are enforced where they matter (REQ-MEM-004).
    pub fn is_locked(&self) -> bool {
        self.unlocked.is_none()
    }

    /// Whether a session is currently held. This is the only
    /// session query besides the fill gate (issue #54, item 1): the
    /// previous `session() -> Option<&S>` handed out `&S` without
    /// running the expiry check, and in-crate callers (#14/#55 live
    /// in this crate) could misuse it as a gate.
    /// [`Self::require_unlocked`] is the only way to get `&S`.
    pub fn has_session(&self) -> bool {
        self.unlocked.is_some()
    }

    /// When the current unlock began (on the controller's clock),
    /// if unlocked.
    pub fn unlocked_at(&self) -> Option<Duration> {
        self.unlocked.as_ref().map(|u| u.unlocked_at)
    }

    /// The lock reason if the held session has expired at `now`:
    /// the absolute timer dominates when both have expired.
    fn expiry_reason(&self) -> Option<LockReason> {
        let u = self.unlocked.as_ref()?;
        let now = self.clock.now();
        if now.saturating_sub(u.unlocked_at) >= self.policy.max_unlocked {
            Some(LockReason::AbsoluteTimeout)
        } else if now.saturating_sub(u.last_activity_at) >= self.policy.idle_lock {
            Some(LockReason::IdleTimeout)
        } else {
            None
        }
    }

    /// Attempt to unlock. See the module docs for the ordering:
    /// mlock first (REQ-MEM-002), derivation second (its closure
    /// zeroizes password and master key before returning,
    /// REQ-MEM-003), the `Unlocked` audit entry third (REQ-AUD-003),
    /// timers last.
    pub fn unlock<E>(
        &mut self,
        derive: impl FnOnce() -> Result<S, E>,
    ) -> Result<(), UnlockError<E>> {
        // Expiry first (issue #54, item 4): an expired-but-unpolled
        // session is locked with its expiry reason and the re-unlock
        // proceeds, instead of failing `AlreadyUnlocked` and leaving
        // the owner stuck until something happens to poll.
        if let Some(reason) = self.expiry_reason() {
            self.lock(reason);
        }
        if self.unlocked.is_some() {
            return Err(UnlockError::AlreadyUnlocked);
        }
        match self.hardening.lock_memory() {
            Ok(()) => {}
            Err(_) if self.policy.require_mlock => {
                // The refusal is itself a transition; its audit
                // entry is best-effort (the refusal stands either
                // way, exactly like a lock).
                let _ = self.emit(LockEvent::UnlockRefusedMlock);
                return Err(UnlockError::MlockUnavailable);
            }
            Err(_) => {
                // Best-effort mlock failed: proceed, but say so.
                let _ = self.emit(LockEvent::MlockBestEffortFailed);
            }
        }
        let session = derive().map_err(UnlockError::DeriveFailed)?;
        let now = self.clock.now();
        self.unlocked = Some(Unlocked {
            session,
            unlocked_at: now,
            last_activity_at: now,
        });
        if let Err(e) = self.emit(LockEvent::Unlocked) {
            // REQ-AUD-003 fail-closed: an unlock that cannot be
            // audited does not stand. Dropping the session wipes
            // its keys (ZeroizeOnDrop).
            drop(self.unlocked.take());
            return Err(UnlockError::Audit(e));
        }
        Ok(())
    }

    /// Record fill activity: resets the idle timer (REQ-MEM-004).
    /// A no-op while locked — and a no-op that *locks* on an
    /// already-expired session: activity arriving after the idle or
    /// absolute deadline must not revive the unlock (review #50,
    /// blocking item 1).
    pub fn touch_activity(&mut self) {
        if let Some(reason) = self.expiry_reason() {
            self.lock(reason);
            return;
        }
        if let Some(u) = &mut self.unlocked {
            u.last_activity_at = self.clock.now();
        }
    }

    /// Check both timers against the clock and lock if either has
    /// expired. Returns the reason when this call locked. The
    /// daemon polls this on its own cadence; the fill gate enforces
    /// the same check independently, so correctness does not depend
    /// on poll cadence (REQ-MEM-004).
    pub fn poll(&mut self) -> Option<LockReason> {
        let reason = self.expiry_reason()?;
        self.lock(reason);
        Some(reason)
    }

    /// Lock now, destroying the session (REQ-MEM-003). Returns
    /// whether there was a session to destroy. The lock hook then
    /// runs (closing CDP sessions, issue #66). The `Locked` audit
    /// entry is best-effort: the lock stands even if the write
    /// fails, because the keys are already gone.
    pub fn lock(&mut self, reason: LockReason) -> bool {
        let Some(u) = self.unlocked.take() else {
            return false;
        };
        drop(u);
        if let Some(hook) = &mut self.lock_hook {
            hook(reason);
        }
        let _ = self.emit(LockEvent::Locked { reason });
        true
    }

    /// REQ-MEM-006: the sync layer saw a different org key than the
    /// one unwrapped at unlock (`SyncReport.org_key_changed` in
    /// #49's terms). Lock with audit event `key_rotated`.
    pub fn on_org_key_changed(&mut self) -> bool {
        self.lock(LockReason::KeyRotated)
    }

    /// REQ-MEM-006: a payload used an unknown crypto version. Lock.
    pub fn on_unknown_crypto_version(&mut self) -> bool {
        self.lock(LockReason::UnknownCryptoVersion)
    }

    /// REQ-CRY-008: the sync layer's scope check saw the account's
    /// view widen past the dedicated org mid-run. Lock with audit
    /// event `scope_widened` (the same forced-lock path the sync
    /// loop's `LockReason::ScopeWidened` feeds into).
    pub fn on_scope_widened(&mut self) -> bool {
        self.lock(LockReason::ScopeWidened)
    }

    /// The one path from a sync outcome into the controller
    /// (issue #54, item 3): `SyncOutcome::Lock(reason)` is handled
    /// by `controller.on_sync_lock(&reason)`, which converts via
    /// `From<&SyncLockReason>` and locks. Callers that also
    /// write the audit entry should use the sync reason's own
    /// `audit_entry()`, which keeps its finer `detail_code`.
    pub fn on_sync_lock(&mut self, reason: &SyncLockReason) -> bool {
        self.lock(LockReason::from(reason))
    }

    /// The fill gate: the session, or [`LockedError`] — checked
    /// before any grant (REQ-MEM-007). Runs the expiry check first
    /// and locks an expired session with the right reason, so at
    /// T+30m idle (or T+12h absolute) a fill is refused `locked`
    /// even if `poll()` has not run since the deadline
    /// (REQ-MEM-004; review #50, blocking item 1).
    pub fn require_unlocked(&mut self) -> Result<&S, LockedError> {
        if let Some(reason) = self.expiry_reason() {
            self.lock(reason);
        }
        self.unlocked
            .as_ref()
            .map(|u| &u.session)
            .ok_or(LockedError)
    }
}

impl<S: ZeroizeOnDrop, C: Clock> Drop for LockController<S, C> {
    fn drop(&mut self) {
        // A controller dropped while unlocked (daemon shutdown,
        // panic path) must not release key material un-wiped: the
        // session's own Drop does the wiping (ZeroizeOnDrop).
        drop(self.unlocked.take());
    }
}

#[cfg(test)]
mod tests;
