//! Time source for the lock timers (REQ-MEM-004).
//!
//! The lock state machine never reads the system clock directly: a
//! [`Clock`] is injected at construction, so tests drive the idle and
//! absolute timers with [`ManualClock`] and assert the exact lock
//! instants the acceptance criteria name (T+30m idle, T+12h absolute).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A source of monotonic time.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The real monotonic clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now(&self) -> Instant {
        (**self).now()
    }
}

/// A clock that only moves when told to. Starts at the instant it was
/// created; [`ManualClock::advance`] moves it forward.
#[derive(Debug)]
pub struct ManualClock {
    now: Mutex<Instant>,
}

impl ManualClock {
    /// A manual clock starting now.
    pub fn new() -> Self {
        Self {
            now: Mutex::new(Instant::now()),
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
    fn now(&self) -> Instant {
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
}
