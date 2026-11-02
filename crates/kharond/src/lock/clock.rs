//! Time source for the lock timers (REQ-MEM-004).
//!
//! The lock state machine never reads the system clock directly: a
//! [`Clock`] is injected at construction, so tests drive the idle and
//! absolute timers with [`ManualClock`] and assert the exact lock
//! instants the acceptance criteria name (T+30m idle, T+12h absolute).
//!
//! A clock reading is a [`Duration`] since an unspecified monotonic
//! epoch; only differences between readings are meaningful. The real
//! clock is `CLOCK_BOOTTIME` on Linux (via `rustix`), *not*
//! `Instant` / `CLOCK_MONOTONIC`: boottime keeps advancing while the
//! host is suspended, so a laptop that sleeps overnight still hits
//! its 12h absolute lock in wall time (review #50, item 4).
//! `CLOCK_MONOTONIC` would silently extend `max_unlocked` by the
//! suspend duration. On non-Linux targets the fallback is
//! `CLOCK_MONOTONIC`-equivalent (`Instant` since process start),
//! which lacks the suspend guarantee — the daemon targets Linux
//! (SPEC §9).

use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A source of monotonic time.
pub trait Clock: Send + Sync {
    /// The current time, as a duration since the clock's epoch.
    fn now(&self) -> Duration;
}

/// The real clock: `CLOCK_BOOTTIME` where available.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

#[cfg(target_os = "linux")]
impl Clock for SystemClock {
    fn now(&self) -> Duration {
        let ts = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        Duration::from_secs(u64::try_from(ts.tv_sec).unwrap_or(0))
            + Duration::from_nanos(u64::try_from(ts.tv_nsec).unwrap_or(0))
    }
}

#[cfg(not(target_os = "linux"))]
impl Clock for SystemClock {
    fn now(&self) -> Duration {
        use std::sync::OnceLock;
        use std::time::Instant;
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        EPOCH.get_or_init(Instant::now).elapsed()
    }
}

impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now(&self) -> Duration {
        (**self).now()
    }
}

/// A clock that only moves when told to. Starts at zero;
/// [`ManualClock::advance`] moves it forward.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<Duration>,
}

impl ManualClock {
    /// A manual clock starting at zero.
    pub fn new() -> Self {
        Self {
            now: Mutex::new(Duration::ZERO),
        }
    }

    /// Move the clock forward by `d`.
    pub fn advance(&self, d: Duration) {
        let mut now = self.now.lock().expect("manual clock poisoned");
        *now += d;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        *self.now.lock().expect("manual clock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_mem_004_manual_clock_advances_monotonically() {
        let c = ManualClock::new();
        let t0 = c.now();
        c.advance(Duration::from_secs(30 * 60));
        assert_eq!(c.now() - t0, Duration::from_secs(30 * 60));
        c.advance(Duration::ZERO);
        assert_eq!(c.now() - t0, Duration::from_secs(30 * 60));
    }

    #[test]
    fn req_mem_004_system_clock_is_monotonic() {
        let c = SystemClock;
        let t0 = c.now();
        assert!(c.now() >= t0);
    }
}
