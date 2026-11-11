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
    assert!(!c.has_session());
    assert!(matches!(c.require_unlocked(), Err(LockedError)));

    let canary = unlock_ok(&mut c);
    assert!(!c.is_locked());
    assert!(c.lock(LockReason::Manual));
    assert!(c.is_locked());
    assert!(!c.has_session(), "no session survives lock");
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
    let e = LockReason::KeyRotated.audit_entry();
    assert_eq!(e.event, crate::audit::Event::KeyRotated);
    assert_eq!(e.detail_code, None);

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

/// #134 / SPEC OQ-10: `MADV_DONTDUMP` is not applied because a
/// non-dumpable process is never dumped. That only holds while the
/// process stays non-dumpable, so unlock refuses to derive keys in a
/// process that has become dumpable again (as a credential change
/// would make it), and says so to the operator.
#[test]
fn req_mem_001_unlock_refused_when_dumpable_and_derivation_never_runs() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let mut c = controller(ManualClock::new(), StaticHardening::all_ok().dumpable());
    c.set_event_sink(Box::new(move |e| {
        log.lock().unwrap().push(e);
        Ok(())
    }));
    let derived = Arc::new(Mutex::new(false));
    let flag = derived.clone();
    let err = c
        .unlock(move || {
            *flag.lock().unwrap() = true;
            Ok::<_, std::io::Error>(CanarySession::new())
        })
        .unwrap_err();
    assert!(matches!(err, UnlockError::Dumpable), "{err:?}");
    assert!(!*derived.lock().unwrap(), "no key derivation may run");
    assert!(c.is_locked());
    assert_eq!(*events.lock().unwrap(), [LockEvent::UnlockRefusedDumpable]);
    assert!(LockEvent::UnlockRefusedDumpable.audit_entry().is_none());
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
    let e = LockReason::ScopeWidened.audit_entry();
    assert_eq!(e.event, crate::audit::Event::ScopeWidened);
    assert_eq!(e.detail_code, None);
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

#[test]
fn issue_54_audit_entries_use_the_real_audit_vocabulary() {
    // Item 2: every lock reason builds a typed audit::Entry whose
    // event is a real audit::Event (deserialization accepts it) —
    // no `locked_*` strings remain.
    use crate::audit::Event;
    let cases = [
        (LockReason::Manual, Event::Lock, Some("manual")),
        (LockReason::IdleTimeout, Event::Lock, Some("idle_timeout")),
        (
            LockReason::AbsoluteTimeout,
            Event::Lock,
            Some("absolute_timeout"),
        ),
        (LockReason::KeyRotated, Event::KeyRotated, None),
        (
            LockReason::UnknownCryptoVersion,
            Event::Lock,
            Some("unknown_crypto_version"),
        ),
        (LockReason::ScopeWidened, Event::ScopeWidened, None),
        (LockReason::Panic, Event::Panic, None),
        (LockReason::RollbackDetected, Event::RollbackDetected, None),
    ];
    for (reason, event, detail) in cases {
        let entry = reason.audit_entry();
        assert_eq!(entry.event, event, "{reason:?}");
        assert_eq!(entry.detail_code.as_deref(), detail, "{reason:?}");
        // Round-trip through JSON: an unknown event name would be a
        // deserialize error (audit::entry), so this pins the entry
        // to the real vocabulary.
        let json = serde_json::to_string(&entry).unwrap();
        let back: crate::audit::Entry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event, event);
    }
    // LockEvent::Unlocked maps to Event::Unlock the same way.
    let entry = LockEvent::Unlocked.audit_entry().unwrap();
    assert_eq!(entry.event, Event::Unlock);
    assert_eq!(
        LockEvent::Locked {
            reason: LockReason::Manual
        }
        .audit_entry()
        .unwrap()
        .detail_code
        .as_deref(),
        Some("manual")
    );
    // Mlock transitions have no audit event and invent none.
    assert!(LockEvent::UnlockRefusedMlock.audit_entry().is_none());
    assert!(LockEvent::MlockBestEffortFailed.audit_entry().is_none());
}

#[test]
fn issue_54_unlock_after_expiry_locks_the_expired_session_then_proceeds() {
    // Item 4: unlock() runs the expiry check first — an
    // expired-but-unpolled session does not block re-unlock with
    // AlreadyUnlocked; it is locked with its expiry reason (old
    // session wiped, Locked event emitted), then the new unlock
    // proceeds.
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    c.set_event_sink(Box::new(move |e| {
        log.lock().unwrap().push(e);
        Ok(())
    }));
    let first = unlock_ok(&mut c);
    clock.advance(Duration::from_secs(31 * 60));
    let second = unlock_ok(&mut c);
    assert!(!c.is_locked());
    assert!(c.has_session());
    assert!(first.all_zero(), "expired session was destroyed");
    assert!(second.untouched());
    assert_eq!(
        *events.lock().unwrap(),
        [
            LockEvent::Unlocked,
            LockEvent::Locked {
                reason: LockReason::IdleTimeout
            },
            LockEvent::Unlocked,
        ]
    );

    // A live (unexpired) session still refuses with AlreadyUnlocked.
    let err = c
        .unlock(|| Ok::<_, std::io::Error>(CanarySession::new()))
        .unwrap_err();
    assert!(matches!(err, UnlockError::AlreadyUnlocked));

    // Absolute expiry takes the same path.
    clock.advance(Duration::from_secs(13 * 60 * 60));
    unlock_ok(&mut c);
    assert!(!c.is_locked());
}

#[test]
fn issue_54_sync_lock_reason_has_one_path_into_the_controller() {
    // Item 3: From<&sync::live::LockReason> and on_sync_lock.
    use crate::sync::{LockReason as SyncLockReason, ScopeViolation};
    assert_eq!(
        LockReason::from(&SyncLockReason::KeyRotated),
        LockReason::KeyRotated
    );
    let widened = SyncLockReason::ScopeWidened(ScopeViolation {
        other_orgs: vec!["other".into()],
        outside_items: Vec::new(),
    });
    assert_eq!(LockReason::from(&widened), LockReason::ScopeWidened);
    // The sync side keeps its finer detail codes.
    assert_eq!(
        widened.audit_entry().detail_code.as_deref(),
        Some("other_org_visible")
    );
    assert_eq!(
        SyncLockReason::KeyRotated
            .audit_entry()
            .detail_code
            .as_deref(),
        Some("org_key_changed")
    );

    let mut c = controller(ManualClock::new(), StaticHardening::all_ok());
    let canary = unlock_ok(&mut c);
    assert!(c.on_sync_lock(&SyncLockReason::KeyRotated));
    assert!(c.is_locked());
    assert!(canary.all_zero());
    assert!(!c.on_sync_lock(&widened), "already locked: no-op");
}

/// SPEC §8 "lock … closes CDP sessions" (issue #66): every lock path
/// runs the lock hook exactly once, after the keys are wiped and
/// before the `Locked` audit entry; a no-op lock does not run it.
#[test]
fn req_mem_003_every_lock_path_runs_the_lock_hook_after_the_wipe() {
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let canary: Arc<Mutex<Option<CanarySession>>> = Arc::default();
    let (log, probe) = (seen.clone(), canary.clone());
    c.set_lock_hook(Box::new(move |reason| {
        let wiped = probe.lock().unwrap().as_ref().is_some_and(|s| s.all_zero());
        log.lock()
            .unwrap()
            .push(format!("hook {reason:?} wiped={wiped}"));
    }));
    let log = seen.clone();
    c.set_event_sink(Box::new(move |e| {
        if let LockEvent::Locked { reason } = e {
            log.lock().unwrap().push(format!("audit {reason:?}"));
        }
        Ok(())
    }));

    type Ctl = LockController<CanarySession, Arc<ManualClock>>;
    let lock_with = |c: &mut Ctl, how: &dyn Fn(&mut Ctl)| {
        *canary.lock().unwrap() = Some(unlock_ok(c));
        how(c);
        assert!(c.is_locked());
    };
    lock_with(&mut c, &|c| assert!(c.lock(LockReason::Manual)));
    lock_with(&mut c, &|c| {
        clock.advance(Duration::from_secs(30 * 60));
        assert!(c.require_unlocked().is_err());
    });
    lock_with(&mut c, &|c| {
        clock.advance(Duration::from_secs(30 * 60));
        assert_eq!(c.poll(), Some(LockReason::IdleTimeout));
    });
    lock_with(&mut c, &|c| assert!(c.on_org_key_changed()));
    lock_with(&mut c, &|c| assert!(c.on_scope_widened()));
    // Already locked: no hook.
    assert!(!c.lock(LockReason::Manual));

    assert_eq!(
        *seen.lock().unwrap(),
        [
            "hook Manual wiped=true",
            "audit Manual",
            "hook IdleTimeout wiped=true",
            "audit IdleTimeout",
            "hook IdleTimeout wiped=true",
            "audit IdleTimeout",
            "hook KeyRotated wiped=true",
            "audit KeyRotated",
            "hook ScopeWidened wiped=true",
            "audit ScopeWidened",
        ]
    );
}

#[test]
fn req_cry_009_background_sync_access_is_not_activity_and_respects_expiry() {
    // The daemon's live-sync loop updates the session through
    // `with_session_mut`; that must neither keep an idle session
    // alive nor reach an expired one.
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    clock.advance(Duration::from_secs(20 * 60));
    assert_eq!(c.with_session_mut(|_| 7).unwrap(), 7);
    clock.advance(Duration::from_secs(11 * 60));
    assert!(
        c.with_session_mut(|_| ()).is_err(),
        "a background sync revived an idle session"
    );
    assert!(c.is_locked(), "the expired session was locked");
}

#[test]
fn req_mem_004_live_grant_defers_idle_until_its_ttl_and_not_past_it() {
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    c.hold_idle_for_grant("g_live", Duration::from_secs(45 * 60));
    clock.advance(Duration::from_secs(30 * 60));
    assert_eq!(c.poll(), None, "idle is deferred while the grant is live");
    assert!(c.require_unlocked().is_ok());
    clock.advance(Duration::from_secs(15 * 60 - 1));
    assert_eq!(c.poll(), None, "still inside the grant TTL");
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        c.poll(),
        Some(LockReason::IdleTimeout),
        "deferral ends at the grant TTL, not later"
    );
    assert!(c.is_locked());
}

#[test]
fn req_mem_004_releasing_a_grant_hold_allows_an_elapsed_idle_lock() {
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    c.hold_idle_for_grant("g_once", Duration::from_secs(2 * 60 * 60));
    clock.advance(Duration::from_secs(40 * 60));
    assert_eq!(c.poll(), None);
    c.release_idle_hold("g_once");
    assert_eq!(
        c.poll(),
        Some(LockReason::IdleTimeout),
        "consuming the grant ends the deferral immediately"
    );
}

#[test]
fn req_mem_004_grant_hold_does_not_defer_absolute_manual_or_panic() {
    let clock = Arc::new(ManualClock::new());
    let policy = LockPolicy {
        max_unlocked: Duration::from_secs(60 * 60),
        ..LockPolicy::default()
    };
    let mut c = LockController::new(policy, clock.clone(), Box::new(StaticHardening::all_ok()));
    unlock_ok(&mut c);
    c.hold_idle_for_grant("g_long", Duration::from_secs(5 * 60 * 60));
    // Activity inside the idle window, so only the absolute timer can fire.
    clock.advance(Duration::from_secs(20 * 60));
    c.touch_activity();
    clock.advance(Duration::from_secs(40 * 60));
    assert_eq!(
        c.poll(),
        Some(LockReason::AbsoluteTimeout),
        "a live grant does not defer the absolute timer"
    );

    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    c.hold_idle_for_grant("g_long", Duration::from_secs(2 * 60 * 60));
    clock.advance(Duration::from_secs(40 * 60));
    assert_eq!(c.poll(), None, "idle would have fired; the grant holds it");
    assert!(c.lock(LockReason::Manual), "owner lock is immediate");
    assert!(c.is_locked());

    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    c.hold_idle_for_grant("g_long", Duration::from_secs(2 * 60 * 60));
    clock.advance(Duration::from_secs(40 * 60));
    assert!(c.lock(LockReason::Panic), "panic is immediate");
    assert!(c.is_locked());
}

#[test]
fn req_mem_004_activity_after_the_idle_deadline_does_not_revive() {
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock_ok(&mut c);
    clock.advance(Duration::from_secs(30 * 60));
    c.touch_activity();
    assert!(c.is_locked(), "a late fill must not revive the session");
    // Recording a hold afterwards does not unlock.
    c.hold_idle_for_grant("g_late", Duration::from_secs(60 * 60));
    assert!(c.is_locked());
    assert_eq!(c.poll(), None);
}
