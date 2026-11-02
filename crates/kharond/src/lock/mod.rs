//! Lock state machine, unlock flow, and lock timers (issue #11;
//! SPEC §8; REQ-MEM-001..006, REQ-CRY-006).
//!
//! The broker boots locked and stays locked until the owner unlocks
//! it (REQ-MEM-005). [`LockController`] owns the one unlocked
//! session — the key material produced by an unlock — and the two
//! timers that end it: idle (default 30m since the last activity)
//! and absolute (default 12h since unlock) (REQ-MEM-004). Locking,
//! for any reason, zeroizes the session's keys before dropping it
//! (REQ-MEM-003).
//!
//! Unlock is deliberately ordered so key material cannot exist
//! before the host is ready for it:
//!
//! 1. If the policy requires mlock (`require_mlock = true`, the
//!    default), `mlockall` must succeed first; otherwise unlock is
//!    refused with [`UnlockError::MlockUnavailable`] and the
//!    derivation closure is never called (REQ-MEM-002).
//! 2. The caller's derivation closure runs (prelogin → login → sync
//!    → master key → user key → private key → org key, i.e.
//!    `sync::Session::unlock` once #49 lands). Its contract: the
//!    master password and master key are zeroized inside the closure
//!    before it returns (REQ-MEM-003); only the session it returns
//!    may hold keys.
//! 3. The controller records the unlock instant and starts both
//!    timers.
//!
//! Forced locks (REQ-MEM-006): the sync layer reports a rotated org
//! key or an unknown crypto version and the controller locks with
//! the matching [`LockReason`]; the audit event name for the
//! rotation case is `key_rotated`, as the AC names it.
//!
//! Every transition is reported to an optional event sink as a
//! [`LockEvent`]; the daemon wires the sink to the audit log
//! (REQ-AUD-003), tests wire it to a `Vec`.
//!
//! Field classes (REQ-CRY-006) are enforced by the session type
//! (metadata decrypted at sync, secrets decrypted per fill into
//! zeroizing buffers, no plaintext secret cache); the controller's
//! part is that lock destroys the whole session at once, so no
//! decrypted state can outlive the unlock that produced it.

mod clock;
mod hardening;

use std::time::{Duration, Instant};

use zeroize::Zeroize;

pub use clock::{Clock, ManualClock, SystemClock};
pub use hardening::{
    HardeningError, MemoryHardening, ProcessHardening, ProcessHardeningStatus, StaticHardening,
    process_status,
};

/// SPEC §8 / §9 defaults: idle lock 30m, absolute 12h, mlock
/// required. The daemon overrides these from `[policy]` / `[memory]`
/// config once the config loader (#47) is wired in.
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

/// Why the broker locked. The audit event name for a lock is
/// `locked_<audit_name>`, except rotation, whose audit entry the
/// REQ-MEM-006 AC names directly: `key_rotated`.
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
}

impl LockReason {
    /// The audit event name for this lock (REQ-AUD-003, REQ-MEM-006).
    pub fn audit_event(self) -> &'static str {
        match self {
            Self::Manual => "locked_manual",
            Self::IdleTimeout => "locked_idle_timeout",
            Self::AbsoluteTimeout => "locked_absolute_timeout",
            Self::KeyRotated => "key_rotated",
            Self::UnknownCryptoVersion => "locked_unknown_crypto_version",
        }
    }
}

/// A lock-state transition, for the audit log (REQ-AUD-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockEvent {
    /// Unlock succeeded; both timers started.
    Unlocked,
    /// Unlock was refused before any key derivation ran.
    UnlockRefusedMlock,
    /// The broker locked; the session was zeroized and dropped.
    Locked {
        /// Why.
        reason: LockReason,
    },
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
}

/// The broker is locked (the fill gate: REQ-MEM-007's seam — any
/// fill attempted in this state is refused `locked` before grants
/// are even consulted; issue #18 wires the endpoints).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("broker is locked")]
pub struct LockedError;

struct Unlocked<S> {
    session: S,
    unlocked_at: Instant,
    last_activity_at: Instant,
}

/// Owns the lock state and (while unlocked) the session's keys.
///
/// `S` is the session type produced by an unlock (the sync layer's
/// session once #49 lands). It must implement [`Zeroize`]: locking
/// calls `zeroize()` on it and then drops it, so key material is
/// wiped, not merely released (REQ-MEM-003).
pub struct LockController<S: Zeroize, C: Clock = SystemClock> {
    policy: LockPolicy,
    clock: C,
    hardening: Box<dyn MemoryHardening>,
    unlocked: Option<Unlocked<S>>,
    sink: Option<Box<dyn FnMut(LockEvent) + Send>>,
}

impl<S: Zeroize, C: Clock> LockController<S, C> {
    /// A locked controller (REQ-MEM-005: boots locked; nothing is
    /// persisted, so a restart constructs exactly this).
    pub fn new(policy: LockPolicy, clock: C, hardening: Box<dyn MemoryHardening>) -> Self {
        Self {
            policy,
            clock,
            hardening,
            unlocked: None,
            sink: None,
        }
    }

    /// Report every transition to `sink` (the daemon's audit log).
    pub fn set_event_sink(&mut self, sink: Box<dyn FnMut(LockEvent) + Send>) {
        self.sink = Some(sink);
    }

    fn emit(&mut self, event: LockEvent) {
        if let Some(sink) = &mut self.sink {
            sink(event);
        }
    }

    /// Whether the broker is locked.
    pub fn is_locked(&self) -> bool {
        self.unlocked.is_none()
    }

    /// The current session, if unlocked.
    pub fn session(&self) -> Option<&S> {
        self.unlocked.as_ref().map(|u| &u.session)
    }

    /// When the current unlock began, if unlocked.
    pub fn unlocked_at(&self) -> Option<Instant> {
        self.unlocked.as_ref().map(|u| u.unlocked_at)
    }

    /// Attempt to unlock. See the module docs for the ordering:
    /// mlock first (REQ-MEM-002), derivation second (its closure
    /// zeroizes password and master key before returning,
    /// REQ-MEM-003), timers last.
    pub fn unlock<E>(
        &mut self,
        derive: impl FnOnce() -> Result<S, E>,
    ) -> Result<(), UnlockError<E>> {
        if self.unlocked.is_some() {
            return Err(UnlockError::AlreadyUnlocked);
        }
        if self.policy.require_mlock && self.hardening.lock_memory().is_err() {
            self.emit(LockEvent::UnlockRefusedMlock);
            return Err(UnlockError::MlockUnavailable);
        }
        let session = derive().map_err(UnlockError::DeriveFailed)?;
        let now = self.clock.now();
        self.unlocked = Some(Unlocked {
            session,
            unlocked_at: now,
            last_activity_at: now,
        });
        self.emit(LockEvent::Unlocked);
        Ok(())
    }

    /// Record fill activity: resets the idle timer (REQ-MEM-004).
    /// A no-op while locked.
    pub fn touch_activity(&mut self) {
        if let Some(u) = &mut self.unlocked {
            u.last_activity_at = self.clock.now();
        }
    }

    /// Check both timers against the clock and lock if either has
    /// expired. Returns the reason when this call locked. The
    /// absolute timer dominates: if both have expired, the reason
    /// is [`LockReason::AbsoluteTimeout`].
    pub fn poll(&mut self) -> Option<LockReason> {
        let u = self.unlocked.as_ref()?;
        let now = self.clock.now();
        let reason = if now.duration_since(u.unlocked_at) >= self.policy.max_unlocked {
            LockReason::AbsoluteTimeout
        } else if now.duration_since(u.last_activity_at) >= self.policy.idle_lock {
            LockReason::IdleTimeout
        } else {
            return None;
        };
        self.lock(reason);
        Some(reason)
    }

    /// Lock now, zeroizing and dropping the session (REQ-MEM-003).
    /// Returns whether there was a session to destroy.
    pub fn lock(&mut self, reason: LockReason) -> bool {
        let Some(mut u) = self.unlocked.take() else {
            return false;
        };
        u.session.zeroize();
        drop(u);
        self.emit(LockEvent::Locked { reason });
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

    /// The fill gate: the session, or [`LockedError`] — checked
    /// before any grant (REQ-MEM-007).
    pub fn require_unlocked(&self) -> Result<&S, LockedError> {
        self.session().ok_or(LockedError)
    }
}

impl<S: Zeroize, C: Clock> Drop for LockController<S, C> {
    fn drop(&mut self) {
        // A controller dropped while unlocked (daemon shutdown,
        // panic path) must not release key material un-wiped.
        if let Some(mut u) = self.unlocked.take() {
            u.session.zeroize();
        }
    }
}

#[cfg(test)]
mod tests;
