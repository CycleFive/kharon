//! Unit tests for the lock state machine. The acceptance-named
//! integration tests (child-process hardening checks, timer ACs
//! end to end) live in `crates/kharond/tests/req_mem_lock.rs`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroize;

use super::*;

/// A session whose "keys" are canary bytes behind a shared handle,
/// so a test can prove they were zeroed (not just dropped) after
/// lock: `Zeroize` wipes the buffers in place.
#[derive(Clone)]
struct CanarySession {
    org_key: Arc<Mutex<Vec<u8>>>,
    private_key: Arc<Mutex<Vec<u8>>>,
}

impl CanarySession {
    fn new() -> Self {
        Self {
            org_key: Arc::new(Mutex::new(vec![0xA5; 32])),
            private_key: Arc::new(Mutex::new(vec![0x5A; 64])),
        }
    }

    fn all_zero(&self) -> bool {
        self.org_key.lock().unwrap().iter().all(|b| *b == 0)
            && self.private_key.lock().unwrap().iter().all(|b| *b == 0)
    }

    fn untouched(&self) -> bool {
        self.org_key.lock().unwrap().iter().all(|b| *b == 0xA5)
            && self.private_key.lock().unwrap().iter().all(|b| *b == 0x5A)
    }
}

impl Zeroize for CanarySession {
    fn zeroize(&mut self) {
        self.org_key.lock().unwrap().zeroize();
        self.private_key.lock().unwrap().zeroize();
    }
}

fn controller(
    clock: ManualClock,
    hardening: StaticHardening,
) -> LockController<CanarySession, ManualClock> {
    LockController::new(LockPolicy::default(), clock, Box::new(hardening))
}

fn unlock_ok<C: Clock>(c: &mut LockController<CanarySession, C>) -> CanarySession {
    let canary = CanarySession::new();
    let probe = canary.clone();
    c.unlock(|| Ok::<_, std::io::Error>(canary)).unwrap();
    probe
}

#[test]
fn req_mem_005_boots_locked_and_lock_is_terminal_for_the_session() {
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    assert!(c.is_locked(), "boots locked");
    assert!(c.session().is_none());
    assert!(matches!(c.require_unlocked(), Err(LockedError)));

    let canary = unlock_ok(&mut c);
    assert!(!c.is_locked());
    assert!(c.lock(LockReason::Manual));
    assert!(c.is_locked());
    assert!(c.session().is_none(), "no session survives lock");
    assert!(canary.all_zero());
    // A second lock is a no-op, and re-unlock needs a fresh derive.
    assert!(!c.lock(LockReason::Manual));
}

#[test]
fn req_mem_002_unlock_refused_without_mlock_and_derivation_never_runs() {
    let mut c = controller(ManualClock::new(), StaticHardening::mlock_unavailable());
    let derived = Arc::new(Mutex::new(false));
    let flag = derived.clone();
    let err = c
        .unlock(move || {
            *flag.lock().unwrap() = true;
            Ok::<_, std::io::Error>(CanarySession::new())
        })
        .unwrap_err();
    assert!(matches!(err, UnlockError::MlockUnavailable));
    assert!(
        !*derived.lock().unwrap(),
        "no key derivation may run before mlock succeeds"
    );
    assert!(c.is_locked());

    // With require_mlock = false the same host unlocks fine.
    let policy = LockPolicy {
        require_mlock: false,
        ..LockPolicy::default()
    };
    let mut c = LockController::new(
        policy,
        ManualClock::new(),
        Box::new(StaticHardening::mlock_unavailable()),
    );
    unlock_ok(&mut c);
    assert!(!c.is_locked());
}

#[test]
fn req_mem_003_lock_zeroizes_all_key_material() {
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    let canary = unlock_ok(&mut c);
    assert!(canary.untouched());
    c.lock(LockReason::Manual);
    assert!(canary.all_zero(), "every key buffer wiped on lock");

    // Dropping the controller while unlocked also wipes.
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    let canary = unlock_ok(&mut c);
    drop(c);
    assert!(canary.all_zero(), "controller drop zeroizes the session");
}

#[test]
fn req_mem_004_idle_and_absolute_timers_with_mocked_clock() {
    // Idle: activity resets the 30m timer; 30m of silence locks.
    // (The controller owns an `Arc<ManualClock>`; the test keeps the
    // other handle to advance time.)
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    clock.advance(Duration::from_secs(29 * 60));
    assert_eq!(c.poll(), None);
    c.touch_activity();
    clock.advance(Duration::from_secs(29 * 60));
    assert_eq!(c.poll(), None, "activity reset the idle timer");
    clock.advance(Duration::from_secs(60));
    assert_eq!(c.poll(), Some(LockReason::IdleTimeout));
    assert!(c.is_locked());

    // Absolute: activity does not reset the 12h timer.
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    for _ in 0..11 {
        clock.advance(Duration::from_secs(60 * 60));
        c.touch_activity();
        assert_eq!(c.poll(), None);
    }
    clock.advance(Duration::from_secs(60 * 60));
    assert_eq!(c.poll(), Some(LockReason::AbsoluteTimeout));
}

#[test]
fn req_mem_006_forced_locks_carry_the_right_reason_and_audit_event() {
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    let canary = unlock_ok(&mut c);
    assert!(c.on_org_key_changed());
    assert!(c.is_locked());
    assert!(canary.all_zero());
    assert_eq!(LockReason::KeyRotated.audit_event(), "key_rotated");

    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    unlock_ok(&mut c);
    assert!(c.on_unknown_crypto_version());
    assert!(c.is_locked());

    // Forced lock while already locked is a no-op.
    assert!(!c.on_org_key_changed());
}

#[test]
fn req_mem_events_are_emitted_in_order() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    c.set_event_sink(Box::new(move |e| log.lock().unwrap().push(e)));
    unlock_ok(&mut c);
    c.lock(LockReason::Manual);
    assert_eq!(
        *events.lock().unwrap(),
        [
            LockEvent::Unlocked,
            LockEvent::Locked {
                reason: LockReason::Manual
            }
        ]
    );

    // A refused unlock emits UnlockRefusedMlock and nothing else.
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let mut c = controller(ManualClock::new(), StaticHardening::mlock_unavailable());
    c.set_event_sink(Box::new(move |e| log.lock().unwrap().push(e)));
    let _ = c.unlock(|| Ok::<_, std::io::Error>(CanarySession::new()));
    assert_eq!(*events.lock().unwrap(), [LockEvent::UnlockRefusedMlock]);
}

#[test]
fn req_mem_unlock_twice_and_failed_derivation_stay_consistent() {
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    let err = c
        .unlock(|| Err::<CanarySession, _>(std::io::Error::other("x")))
        .unwrap_err();
    assert!(matches!(err, UnlockError::DeriveFailed(_)));
    assert!(c.is_locked(), "failed derivation leaves the broker locked");

    unlock_ok(&mut c);
    let err = c
        .unlock(|| Ok::<_, std::io::Error>(CanarySession::new()))
        .unwrap_err();
    assert!(matches!(err, UnlockError::AlreadyUnlocked));
}
