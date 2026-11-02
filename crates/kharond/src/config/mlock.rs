//! mlock availability probe (REQ-MEM-002, REQ-DEP-003 "missing mlock").
//!
//! `mlockall(MCL_CURRENT|MCL_FUTURE)` itself is issue #11 (memory
//! hardening). Config validation only needs to know, at startup, whether
//! it can succeed, so that `require_mlock = true` on a host without it is
//! refused before anything is unlocked. The check is a trait so tests
//! inject the answer instead of needing `CAP_IPC_LOCK`.

use std::fs;

/// Answers "can this process lock all of its memory?".
pub trait MlockProbe {
    /// `Ok(())` if mlock is available, else a human-readable reason
    /// (never containing secret material).
    fn mlock_available(&self) -> Result<(), String>;
}

/// Fixed answer, for tests and embedding.
#[derive(Debug, Clone)]
pub struct StaticMlockProbe(pub Result<(), String>);

impl MlockProbe for StaticMlockProbe {
    fn mlock_available(&self) -> Result<(), String> {
        self.0.clone()
    }
}

/// Linux probe from procfs, with no `unsafe` and no side effects:
/// available iff the effective capability set has `CAP_IPC_LOCK`, or the
/// soft `RLIMIT_MEMLOCK` is unlimited (compose: `ulimits: { memlock: -1 }`).
/// A finite memlock limit is treated as unavailable: `MCL_FUTURE` makes
/// every later allocation count against it. No procfs → unavailable
/// (fail closed).
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcfsMlockProbe;

/// Bit index of `CAP_IPC_LOCK` in the capability sets.
const CAP_IPC_LOCK: u32 = 14;

impl MlockProbe for ProcfsMlockProbe {
    fn mlock_available(&self) -> Result<(), String> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|e| format!("cannot read /proc/self/status: {}", e.kind()))?;
        let limits = fs::read_to_string("/proc/self/limits")
            .map_err(|e| format!("cannot read /proc/self/limits: {}", e.kind()))?;
        decide(&status, &limits)
    }
}

/// Pure decision over `/proc/self/status` and `/proc/self/limits` text.
pub(crate) fn decide(status: &str, limits: &str) -> Result<(), String> {
    if cap_eff(status).is_some_and(|caps| caps & (1u64 << CAP_IPC_LOCK) != 0) {
        return Ok(());
    }
    match memlock_soft(limits) {
        Some(MemlockLimit::Unlimited) => Ok(()),
        Some(MemlockLimit::Bytes(n)) => Err(format!(
            "no CAP_IPC_LOCK and RLIMIT_MEMLOCK soft limit is {n} bytes (needs unlimited)"
        )),
        None => Err("no CAP_IPC_LOCK and RLIMIT_MEMLOCK is unknown".to_owned()),
    }
}

fn cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
}

#[derive(Debug, PartialEq, Eq)]
enum MemlockLimit {
    Unlimited,
    Bytes(u64),
}

fn memlock_soft(limits: &str) -> Option<MemlockLimit> {
    let rest = limits
        .lines()
        .find_map(|l| l.strip_prefix("Max locked memory"))?;
    match rest.split_whitespace().next()? {
        "unlimited" => Some(MemlockLimit::Unlimited),
        n => n.parse().ok().map(MemlockLimit::Bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS_FINITE: &str = "Limit                     Soft Limit           Hard Limit           Units     \n\
Max core file size        0                    unlimited            bytes     \n\
Max locked memory         8388608              8388608              bytes     \n";
    const LIMITS_UNLIMITED: &str = "Limit                     Soft Limit           Hard Limit           Units     \n\
Max locked memory         unlimited            unlimited            bytes     \n";
    const STATUS_NO_CAP: &str = "Name:\tkharond\nCapEff:\t0000000000000000\n";
    const STATUS_IPC_LOCK: &str = "Name:\tkharond\nCapEff:\t0000000000004000\n";
    const STATUS_FULL: &str = "Name:\tkharond\nCapEff:\t000001ffffffffff\n";

    #[test]
    fn req_dep_003_mlock_probe_cap_ipc_lock_suffices() {
        assert_eq!(decide(STATUS_IPC_LOCK, LIMITS_FINITE), Ok(()));
        assert_eq!(decide(STATUS_FULL, LIMITS_FINITE), Ok(()));
    }

    #[test]
    fn req_dep_003_mlock_probe_unlimited_memlock_suffices() {
        assert_eq!(decide(STATUS_NO_CAP, LIMITS_UNLIMITED), Ok(()));
    }

    #[test]
    fn req_dep_003_mlock_probe_finite_memlock_without_cap_refused() {
        let err = decide(STATUS_NO_CAP, LIMITS_FINITE).unwrap_err();
        assert!(err.contains("8388608"), "{err}");
        assert!(decide("", "").is_err(), "unknown procfs fails closed");
    }
}
