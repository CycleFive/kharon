//! Acceptance tests for issue #11 (REQ-MEM-001..006, REQ-CRY-006).
//!
//! The state-machine ACs run against `LockController` with a mocked
//! clock and injected hardening. The process-level ACs (REQ-MEM-001,
//! REQ-MEM-002) re-exec this test binary as a child: hardening is
//! process-global and irreversible, so it must not run in the test
//! harness's own process.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kharond::lock::{
    LockController, LockEvent, LockPolicy, LockReason, ManualClock, MemoryHardening,
    ProcessHardening, StaticHardening, process_status,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Canary key material behind a shared handle (zeroed in place, so
/// the test can verify the wipe after lock).
#[derive(Clone)]
struct CanarySession {
    keys: Arc<Mutex<Vec<u8>>>,
}

impl CanarySession {
    fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(vec![0xC7; 48])),
        }
    }

    fn all_zero(&self) -> bool {
        self.keys.lock().unwrap().iter().all(|b| *b == 0)
    }
}

impl Zeroize for CanarySession {
    fn zeroize(&mut self) {
        self.keys.lock().unwrap().zeroize();
    }
}

/// The session contract (REQ-MEM-003): destruction is by drop, and
/// the drop wipes — the same shape as `sync::Session`.
impl Drop for CanarySession {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CanarySession {}

fn unlock(c: &mut LockController<CanarySession, Arc<ManualClock>>) -> CanarySession {
    let canary = CanarySession::new();
    let probe = canary.clone();
    c.unlock(|| Ok::<_, std::io::Error>(canary)).unwrap();
    probe
}

// ---------------------------------------------------------------- REQ-MEM-001

const CHILD_ENV: &str = "KHARON_REQ_MEM_001_CHILD";

/// Child half: harden this process, report its own status and its
/// `/proc/self/limits` core line, then wait to be killed.
fn child_main() -> ! {
    // OQ-10 (#134): unlock's dumpable check reads the real flag.
    assert!(
        !ProcessHardening.is_non_dumpable(),
        "a fresh process is dumpable"
    );
    ProcessHardening.harden_process().expect("harden");
    assert!(ProcessHardening.is_non_dumpable(), "hardened: not dumpable");
    let st = process_status();
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();
    let core_line = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap_or("")
        .to_owned();
    println!("STATUS {st}");
    println!("CORELINE {core_line}");
    println!("READY");
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn req_mem_001_process_is_non_dumpable_with_core_limit_zero() {
    if std::env::var_os(CHILD_ENV).is_some() {
        child_main();
    }
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args([
            "req_mem_001_process_is_non_dumpable_with_core_limit_zero",
            "--exact",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .stdout(Stdio::piped())
        // Inherit stderr (review #50, nit 9): if the child panics,
        // the reason must be visible in the test output, not nulled.
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    // Read with a deadline: a child that hangs before READY must
    // fail this test in 30s, not hang the suite (review #50, nit 9).
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.unwrap_or_default()).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut status = String::new();
    let mut coreline = String::new();
    loop {
        let remain = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(!remain.is_zero(), "child did not print READY within 30s");
        let line = rx
            .recv_timeout(remain)
            .expect("child did not print READY within 30s");
        if let Some(s) = line.strip_prefix("STATUS ") {
            status = s.to_owned();
        } else if let Some(s) = line.strip_prefix("CORELINE ") {
            coreline = s.to_owned();
        } else if line == "READY" {
            break;
        }
    }
    // The gcore half of the AC, as a same-uid stand-in: while the
    // hardened child is alive, opening its /proc/<pid>/mem must fail
    // (non-dumpable processes deny ptrace access) — unless this
    // parent holds CAP_SYS_PTRACE (bit 19), which overrides it.
    let cap_eff = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| u64::from_str_radix(l[7..].trim(), 16).ok())
        .unwrap_or(0);
    if cap_eff & (1 << 19) == 0 {
        let mem = std::fs::File::open(format!("/proc/{}/mem", child.id()));
        assert!(
            mem.is_err(),
            "/proc/<child>/mem must not open for a non-dumpable child"
        );
    }
    child.kill().unwrap();
    let _ = child.wait();

    assert!(
        status.contains("not_dumpable=Some(true)"),
        "PR_GET_DUMPABLE must be 0 after harden_process: {status}"
    );
    assert!(
        status.contains("core_limit_soft=Some(0)"),
        "soft RLIMIT_CORE must be 0: {status}"
    );
    assert!(
        status.contains("core_limit_hard=Some(0)"),
        "hard RLIMIT_CORE must be 0: {status}"
    );
    // /proc/self/limits agrees: "Max core file size  0  0  bytes"
    let fields: Vec<&str> = coreline.split_whitespace().collect();
    assert_eq!(fields.get(4), Some(&"0"), "limits soft core: {coreline}");
    assert_eq!(fields.get(5), Some(&"0"), "limits hard core: {coreline}");
}

// ---------------------------------------------------------------- REQ-MEM-002

#[test]
fn req_mem_002_unlock_follows_the_real_mlockall_result() {
    // The AC's refusal case (no IPC_LOCK → unlock error
    // MlockUnavailable, no derivation) is pinned deterministically at
    // the controller level in the unit tests via StaticHardening.
    // Here the controller is wired to the REAL ProcessHardening, and
    // its behaviour must follow the real syscall on this host —
    // whichever way the host answers. (A procfs prediction cannot
    // settle it: mlockall(MCL_CURRENT) also depends on the process's
    // current footprint vs RLIMIT_MEMLOCK, which is why the daemon
    // trusts the syscall, not a prediction, and fails closed.)
    // As the daemon does at startup (step 3), before any unlock: unlock
    // also refuses a dumpable process (OQ-10, #134).
    ProcessHardening.harden_process().expect("harden");
    let host = ProcessHardening.lock_memory();
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(LockPolicy::default(), clock, Box::new(ProcessHardening));
    let derived = Arc::new(Mutex::new(false));
    let flag = derived.clone();
    let result = c.unlock(move || {
        *flag.lock().unwrap() = true;
        Ok::<_, std::io::Error>(CanarySession::new())
    });
    match host {
        Ok(()) => {
            result.expect("mlockall succeeded, so unlock must proceed");
            assert!(*derived.lock().unwrap());
            assert!(!c.is_locked());
        }
        Err(e) => {
            assert!(
                matches!(result, Err(kharond::lock::UnlockError::MlockUnavailable)),
                "mlockall failed ({e}), so unlock must refuse: {result:?}"
            );
            assert!(
                !*derived.lock().unwrap(),
                "no derivation may run when mlockall fails"
            );
            assert!(c.is_locked());
        }
    }
}

// ---------------------------------------------------------------- REQ-MEM-004/005/006, REQ-CRY-006

#[test]
fn req_mem_004_state_is_locked_at_t_plus_30m_idle_and_t_plus_12h_absolute() {
    // Idle leg.
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock(&mut c);
    clock.advance(Duration::from_secs(30 * 60 - 1));
    assert_eq!(c.poll(), None, "still unlocked at T+29m59s idle");
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        c.poll(),
        Some(LockReason::IdleTimeout),
        "locked at T+30m idle"
    );

    // Absolute leg (activity every 10m cannot push past 12h).
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock.clone(),
        Box::new(StaticHardening::all_ok()),
    );
    unlock(&mut c);
    for _ in 0..(12 * 6 - 1) {
        clock.advance(Duration::from_secs(10 * 60));
        c.touch_activity();
        assert_eq!(c.poll(), None);
    }
    clock.advance(Duration::from_secs(10 * 60));
    assert_eq!(
        c.poll(),
        Some(LockReason::AbsoluteTimeout),
        "locked at T+12h despite constant activity"
    );
}

#[test]
fn req_mem_005_restart_comes_up_locked_with_nothing_persisted() {
    let clock = Arc::new(ManualClock::new());
    let canary;
    {
        let mut c = LockController::new(
            LockPolicy::default(),
            clock.clone(),
            Box::new(StaticHardening::all_ok()),
        );
        canary = unlock(&mut c);
        // "Crash": the controller is dropped without lock().
    }
    assert!(canary.all_zero(), "crash drop zeroized the session");
    let c = LockController::<CanarySession, Arc<ManualClock>>::new(
        LockPolicy::default(),
        clock,
        Box::new(StaticHardening::all_ok()),
    );
    assert!(c.is_locked(), "restart boots locked");
    assert!(!c.has_session());
}

#[test]
fn req_mem_006_rotated_org_key_locks_and_audits_key_rotated() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let log = events.clone();
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock,
        Box::new(StaticHardening::all_ok()),
    );
    c.set_event_sink(Box::new(move |e| {
        log.lock().unwrap().push(e);
        Ok(())
    }));
    let canary = unlock(&mut c);
    assert!(c.on_org_key_changed());
    assert!(c.is_locked());
    assert!(canary.all_zero());
    assert_eq!(
        *events.lock().unwrap(),
        [
            LockEvent::Unlocked,
            LockEvent::Locked {
                reason: LockReason::KeyRotated
            }
        ]
    );
    let e = LockReason::KeyRotated.audit_entry();
    assert_eq!(e.event, kharond::audit::Event::KeyRotated);
}

#[test]
fn req_cry_006_lock_leaves_no_secret_material_behind() {
    // The session a fill uses holds keys + ciphertext only; secrets
    // are decrypted per fill into transient buffers (sync layer).
    // What the lock layer guarantees — and what is asserted here —
    // is that locking destroys the entire session at once, so no
    // key (and therefore no decryptable secret state) outlives it.
    let clock = Arc::new(ManualClock::new());
    let mut c = LockController::new(
        LockPolicy::default(),
        clock,
        Box::new(StaticHardening::all_ok()),
    );
    let canary = unlock(&mut c);
    assert!(c.require_unlocked().is_ok());
    c.lock(LockReason::Manual);
    assert!(canary.all_zero());
    assert!(c.require_unlocked().is_err(), "fill gate closed after lock");
    assert!(!c.has_session());
}

/// SPEC §8 (#134): release builds abort on panic instead of unwinding.
/// That is only safe because kharond and `kharon` are non-dumpable
/// (REQ-MEM-001) before they hold anything secret: an aborting
/// non-dumpable process leaves no core dump. `panic` cannot be set per
/// package, so it lives in the workspace's `[profile.release]`.
#[test]
fn req_mem_001_release_builds_abort_on_panic() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let toml = std::fs::read_to_string(path).unwrap();
    let section = toml
        .split("\n[profile.release]\n")
        .nth(1)
        .expect("[profile.release] in the workspace Cargo.toml");
    let section = section.split("\n[").next().unwrap_or_default();
    assert!(
        section
            .lines()
            .any(|l| l.split('#').next().unwrap().replace(' ', "") == "panic=\"abort\""),
        "[profile.release] must set panic = \"abort\":\n{section}"
    );
}
