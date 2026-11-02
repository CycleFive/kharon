//! Unit tests for the lock state machine. The acceptance-named
//! integration tests (child-process hardening checks, timer ACs
//! end to end) live in `crates/kharond/tests/req_mem_lock.rs`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// The session contract (REQ-MEM-003): the controller destroys the
/// session by dropping it, and the type's own drop wipes the keys —
/// the shape `sync::Session` has (its `RsaPrivateKey` is
/// `ZeroizeOnDrop` only, so in-place `Zeroize` is impossible there).
impl Drop for CanarySession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CanarySession {}

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
    // Activity every 10m (inside the 30m idle window — activity
    // arriving after the idle deadline would lock, per the gate
    // semantics pinned in
    // req_mem_004_expired_session_cannot_be_used_or_revived).
    for _ in 0..(12 * 6 - 1) {
        clock.advance(Duration::from_secs(10 * 60));
        c.touch_activity();
        assert_eq!(c.poll(), None);
    }
    clock.advance(Duration::from_secs(10 * 60));
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
    c.set_event_sink(Box::new(move |e| {
        log.lock().unwrap().push(e);
        Ok(())
    }));
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
    c.set_event_sink(Box::new(move |e| {
        log.lock().unwrap().push(e);
        Ok(())
    }));
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

#[test]
fn req_mem_004_expired_session_cannot_be_used_or_revived() {
    // Review #50, blocking item 1, Nyx's exact sequence: unlock ->
    // advance past idle -> the fill gate must refuse (and lock),
    // without any poll() in between.
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    clock.advance(Duration::from_secs(31 * 60));
    assert!(
        c.require_unlocked().is_err(),
        "expired session handed out by the fill gate"
    );
    assert!(c.is_locked(), "the gate locked the expired session");
    assert_eq!(c.poll(), None, "already locked; nothing left to poll");

    // touch_activity on an expired session locks it instead of
    // resetting the idle timer and reviving it.
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    clock.advance(Duration::from_secs(31 * 60));
    c.touch_activity();
    assert!(c.is_locked(), "activity revived an expired session");
    assert_eq!(c.poll(), None);

    // Absolute expiry is enforced at the gate too (T+13h, active use
    // throughout does not matter).
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    clock.advance(Duration::from_secs(13 * 60 * 60));
    assert!(c.require_unlocked().is_err());
    assert!(c.is_locked());
}

#[test]
fn req_mem_002_best_effort_mlock_failure_is_reported_not_silent() {
    // Review #50, item 3: require_mlock = false must still attempt
    // mlockall and surface its failure as an event.
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let policy = LockPolicy {
        require_mlock: false,
        ..LockPolicy::default()
    };
    let mut c = LockController::new(
        policy,
        ManualClock::new(),
        Box::new(StaticHardening::mlock_unavailable()),
    );
    c.set_event_sink(Box::new(move |e| {
        log.lock().unwrap().push(e);
        Ok(())
    }));
    unlock_ok(&mut c);
    assert!(!c.is_locked());
    assert_eq!(
        *events.lock().unwrap(),
        [LockEvent::MlockBestEffortFailed, LockEvent::Unlocked]
    );
}

#[test]
fn req_aud_003_unlock_rolls_back_when_the_audit_write_fails() {
    // Review #50, item 5: the Unlocked entry failing to write must
    // fail the unlock closed; the fresh session is destroyed.
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    c.set_event_sink(Box::new(|e| {
        if e == LockEvent::Unlocked {
            Err(AuditError)
        } else {
            Ok(())
        }
    }));
    let canary = CanarySession::new();
    let probe = canary.clone();
    let err = c.unlock(|| Ok::<_, std::io::Error>(canary)).unwrap_err();
    assert!(matches!(err, UnlockError::Audit(AuditError)));
    assert!(c.is_locked(), "unauditable unlock must not stand");
    assert!(probe.all_zero(), "rolled-back session was destroyed");

    // A Locked entry failing to write never un-locks: the lock
    // stands regardless.
    let fail = Arc::new(Mutex::new(false));
    let flag = fail.clone();
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    c.set_event_sink(Box::new(move |e| {
        if *flag.lock().unwrap() && matches!(e, LockEvent::Locked { .. }) {
            Err(AuditError)
        } else {
            Ok(())
        }
    }));
    unlock_ok(&mut c);
    *fail.lock().unwrap() = true;
    assert!(c.lock(LockReason::Manual));
    assert!(c.is_locked(), "lock stands despite the audit failure");
}

#[test]
fn req_cry_008_scope_widened_forces_a_lock() {
    // Review #50, item 6: ScopeWidened takes the same forced-lock
    // path as KeyRotated, with the AC's audit event name.
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    let canary = unlock_ok(&mut c);
    assert!(c.on_scope_widened());
    assert!(c.is_locked());
    assert!(canary.all_zero());
    assert_eq!(LockReason::ScopeWidened.audit_event(), "scope_widened");
    assert!(!c.on_scope_widened(), "already locked: no-op");
}

#[test]
fn req_mem_lock_policy_wires_from_config() {
    // Review #50, blocking item 2 (second half): LockPolicy is
    // built from the config loader's [policy] + [memory] values.
    let policy = PolicyConfig {
        idle_lock: Duration::from_secs(5 * 60),
        max_unlocked: Duration::from_secs(60 * 60),
        ..PolicyConfig::default()
    };
    let memory = MemoryConfig {
        require_mlock: false,
    };
    let lp = LockPolicy::from((&policy, &memory));
    assert_eq!(
        lp,
        LockPolicy {
            idle_lock: Duration::from_secs(5 * 60),
            max_unlocked: Duration::from_secs(60 * 60),
            require_mlock: false,
        }
    );
}

#[test]
fn req_mem_real_sync_session_composes_with_the_controller() {
    // Review #50, blocking item 2: the controller must hold master's
    // real session type. Built from #49's recorded Vaultwarden
    // fixture (no network): Session::unlock over the fixture sync
    // payload, exactly as the daemon's closure will do.
    use kharon_bwcrypto::Kdf;
    use zeroize::Zeroizing;

    use crate::sync::wire::{SyncResponse, normalize_keys};
    use crate::sync::{Scope, Session};

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kharon-bwcrypto/tests/fixtures/vaultwarden");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("fixture.json")).unwrap()).unwrap();
    let sync_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("sync_fixture.json")).unwrap())
            .unwrap();
    let sync: SyncResponse = serde_json::from_value(normalize_keys(sync_json)).unwrap();
    let org = sync.profile.organizations.as_ref().unwrap()[0].id.clone();
    let coll = sync.collections.as_ref().unwrap()[0].id.clone();
    let email = manifest["account"]["email"].as_str().unwrap().to_owned();
    let password = Zeroizing::new(manifest["account"]["password"].as_str().unwrap().to_owned());
    let kdf = Kdf::from_prelogin(0, 600_000, None, None).unwrap();

    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    c.unlock(|| {
        Session::unlock(
            &password,
            &email,
            &kdf,
            &sync,
            Scope::new(&org, [&coll]).unwrap(),
        )
    })
    .unwrap();
    assert!(!c.is_locked());
    assert!(
        c.require_unlocked().is_ok(),
        "real session at the fill gate"
    );
    // The timers destroy the real session on expiry, like any other.
    clock.advance(Duration::from_secs(31 * 60));
    assert!(c.require_unlocked().is_err());
    assert!(c.is_locked());
}
