//! Process memory hardening (SPEC §8; REQ-MEM-001, REQ-MEM-002).
//!
//! Two separate steps, because they happen at different times:
//!
//! - [`MemoryHardening::harden_process`] runs once at daemon start:
//!   the process becomes non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`)
//!   and its core limit drops to 0 (`setrlimit(RLIMIT_CORE, 0)`), so
//!   no crash can write key material to disk (REQ-MEM-001).
//! - [`MemoryHardening::lock_memory`] runs at every unlock:
//!   `mlockall(MCL_CURRENT | MCL_FUTURE)` keeps key pages out of swap.
//!   When the config requires it (`require_mlock = true`, the default)
//!   and it fails, unlock is refused with `MlockUnavailable`
//!   (REQ-MEM-002); when it does not, the attempt is still made
//!   best-effort and a failure is reported as a lock event. The lock
//!   controller calls this *before* any key derivation runs.
//!
//! Everything goes through `rustix`'s safe wrappers: this crate
//! forbids `unsafe` code. On non-Linux targets both steps report
//! [`HardeningError::Unsupported`]; the daemon targets Linux
//! (SPEC §9), and a build for another OS must fail closed rather than
//! silently skip hardening.

use std::fmt;

/// Why a hardening step failed. Carries no secret material: the
/// wrapped text is the OS error's own description (an errno string
/// from `rustix`), never anything with values interpolated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HardeningError {
    /// The OS refused the operation.
    #[error("hardening operation failed: {0}")]
    Os(String),
    /// No implementation for this platform.
    #[error("process hardening is not supported on this platform")]
    Unsupported,
}

impl HardeningError {
    /// From a `rustix` `Errno` (its `Display` is the errno's own
    /// description, e.g. "Operation not permitted").
    fn os(e: &dyn std::fmt::Display) -> Self {
        Self::Os(e.to_string())
    }
}

/// The process-hardening operations the lock controller needs,
/// injected so tests can simulate a host without `CAP_IPC_LOCK`
/// (REQ-MEM-002's acceptance case) without privileges.
pub trait MemoryHardening: Send {
    /// `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0` (REQ-MEM-001).
    /// Idempotent.
    fn harden_process(&self) -> Result<(), HardeningError>;

    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` (REQ-MEM-002). Idempotent.
    fn lock_memory(&self) -> Result<(), HardeningError>;
}

/// Fixed answers, for tests and embedding (same shape as the config
/// loader's `StaticMlockProbe`, PR #47).
#[derive(Debug, Clone)]
pub struct StaticHardening {
    /// Result of [`MemoryHardening::harden_process`].
    pub harden: Result<(), HardeningError>,
    /// Result of [`MemoryHardening::lock_memory`].
    pub mlock: Result<(), HardeningError>,
}

impl StaticHardening {
    /// A host where every hardening step succeeds.
    pub fn all_ok() -> Self {
        Self {
            harden: Ok(()),
            mlock: Ok(()),
        }
    }

    /// A host where `mlockall` fails (no `CAP_IPC_LOCK`, finite
    /// memlock limit): REQ-MEM-002's refusal case.
    pub fn mlock_unavailable() -> Self {
        Self {
            harden: Ok(()),
            mlock: Err(HardeningError::Os(
                "Operation not permitted (os error 1, simulated)".to_owned(),
            )),
        }
    }
}

impl MemoryHardening for StaticHardening {
    fn harden_process(&self) -> Result<(), HardeningError> {
        self.harden.clone()
    }

    fn lock_memory(&self) -> Result<(), HardeningError> {
        self.mlock.clone()
    }
}

/// The real Linux implementation, via `rustix`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessHardening;

#[cfg(target_os = "linux")]
impl MemoryHardening for ProcessHardening {
    fn harden_process(&self) -> Result<(), HardeningError> {
        use rustix::process::{
            DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit,
        };
        set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|e| HardeningError::os(&e))?;
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|e| HardeningError::os(&e))?;
        Ok(())
    }

    fn lock_memory(&self) -> Result<(), HardeningError> {
        use rustix::mm::{MlockAllFlags, mlockall};
        mlockall(MlockAllFlags::CURRENT | MlockAllFlags::FUTURE).map_err(|e| HardeningError::os(&e))
    }
}

#[cfg(not(target_os = "linux"))]
impl MemoryHardening for ProcessHardening {
    fn harden_process(&self) -> Result<(), HardeningError> {
        Err(HardeningError::Unsupported)
    }

    fn lock_memory(&self) -> Result<(), HardeningError> {
        Err(HardeningError::Unsupported)
    }
}

/// What the current process reports about itself, for the REQ-MEM-001
/// acceptance checks and startup logging. Linux only; `None` fields
/// mean "could not be read" (fail closed at the call site if it
/// matters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessHardeningStatus {
    /// `PR_GET_DUMPABLE == 0`.
    pub not_dumpable: Option<bool>,
    /// Soft `RLIMIT_CORE`.
    pub core_limit_soft: Option<u64>,
    /// Hard `RLIMIT_CORE`.
    pub core_limit_hard: Option<u64>,
}

impl fmt::Display for ProcessHardeningStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "not_dumpable={:?} core_limit_soft={:?} core_limit_hard={:?}",
            self.not_dumpable, self.core_limit_soft, self.core_limit_hard
        )
    }
}

/// Read the current process's dumpable flag and core limit.
#[cfg(target_os = "linux")]
pub fn process_status() -> ProcessHardeningStatus {
    use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};
    let core = getrlimit(Resource::Core);
    ProcessHardeningStatus {
        not_dumpable: dumpable_behavior()
            .ok()
            .map(|d| d == DumpableBehavior::NotDumpable),
        core_limit_soft: core.current,
        core_limit_hard: core.maximum,
    }
}

/// Read the current process's dumpable flag and core limit.
#[cfg(not(target_os = "linux"))]
pub fn process_status() -> ProcessHardeningStatus {
    ProcessHardeningStatus::default()
}
