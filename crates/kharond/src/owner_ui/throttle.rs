//! A per-source throttle on failed owner-UI sign-in, enrollment and
//! unlock attempts, public mode only (#208 D5, REQ-APR-009).
//!
//! The table forgets instead of sharing a bucket: when it is full it
//! drops expired entries, then the entry whose window started earliest.
//! Forgetting a count can only un-throttle a source; it can never block
//! one. That is the opposite of `/mcp`'s overflow window, and on
//! purpose: a stranger with many addresses must not be able to throttle
//! an address they do not control.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::api::transport::ip_key;

/// Failures a source may make in one window before it is refused.
pub(crate) const MAX_FAILURES: u32 = 10;
/// A fixed window, starting at the source's first failure.
pub(crate) const FAILURE_WINDOW: Duration = Duration::from_secs(600);
/// Most sources the table holds.
pub(crate) const MAX_SOURCES: usize = 1024;
/// The routes a throttled source is refused on, and whose failures count.
pub const THROTTLED_ROUTES: &[&str] = &[
    "/owner/login/options",
    "/owner/login/finish",
    "/owner/register/options",
    "/owner/register/finish",
    "/owner/unlock/begin",
    "/owner/unlock",
];

/// Per-source failure counts.
pub(crate) struct FailureThrottle {
    /// Source key to (window start, failures in that window).
    sources: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

/// What [`FailureThrottle::record`] did to the count.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Counted {
    Under,
    /// This failure reached the limit.
    Tripped,
    /// The source was already at the limit.
    Over,
}

impl FailureThrottle {
    pub fn new() -> Self {
        Self {
            sources: Mutex::new(HashMap::new()),
        }
    }

    /// Time left in the window when `ip` has reached the limit.
    ///
    /// `blocked` and [`Self::record`] are separate steps: concurrent
    /// requests from one source can each pass this check before any of
    /// them is counted. The overshoot is bounded by the requests in
    /// flight and is accepted (D5).
    pub fn blocked(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        let sources = self.lock();
        let (start, failures) = sources.get(&ip_key(ip))?;
        let elapsed = now.saturating_duration_since(*start);
        (*failures >= MAX_FAILURES && elapsed < FAILURE_WINDOW).then(|| FAILURE_WINDOW - elapsed)
    }

    /// Count one failure. `Tripped` exactly when the count reaches the limit.
    pub fn record(&self, ip: IpAddr, now: Instant) -> Counted {
        let key = ip_key(ip);
        let mut sources = self.lock();
        if !sources.contains_key(&key) && sources.len() >= MAX_SOURCES {
            sources.retain(|_, (start, _)| now.saturating_duration_since(*start) < FAILURE_WINDOW);
            if sources.len() >= MAX_SOURCES
                && let Some(oldest) = sources
                    .iter()
                    .min_by_key(|(_, (start, _))| *start)
                    .map(|(k, _)| *k)
            {
                sources.remove(&oldest);
            }
        }
        let entry = sources.entry(key).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) >= FAILURE_WINDOW {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        match entry.1.cmp(&MAX_FAILURES) {
            std::cmp::Ordering::Less => Counted::Under,
            std::cmp::Ordering::Equal => Counted::Tripped,
            std::cmp::Ordering::Greater => Counted::Over,
        }
    }

    /// Forget `ip`'s count.
    pub fn clear(&self, ip: IpAddr) {
        self.lock().remove(&ip_key(ip));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, (Instant, u32)>> {
        self.sources.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn trip(t: &FailureThrottle, ip: IpAddr, at: Instant) {
        for _ in 0..MAX_FAILURES {
            t.record(ip, at);
        }
    }

    #[test]
    fn tenth_failure_trips_and_blocks_until_the_window_ends() {
        let t = FailureThrottle::new();
        let ip = v4("203.0.113.7");
        let start = Instant::now();
        for i in 1..MAX_FAILURES {
            assert_eq!(t.record(ip, start), Counted::Under, "failure {i}");
            assert_eq!(t.blocked(ip, start), None, "after {i}");
        }
        assert_eq!(t.record(ip, start), Counted::Tripped);
        let left = t.blocked(ip, start).expect("blocked");
        assert!(left <= FAILURE_WINDOW && left > Duration::ZERO, "{left:?}");
        assert_eq!(t.record(ip, start), Counted::Over);
        let end = start + FAILURE_WINDOW;
        assert_eq!(t.blocked(ip, end), None);
        assert_eq!(t.record(ip, end), Counted::Under);
    }

    #[test]
    fn sources_are_independent_and_v6_is_keyed_by_its_64() {
        let t = FailureThrottle::new();
        let now = Instant::now();
        trip(&t, v4("2001:db8:1:1::a"), now);
        assert!(t.blocked(v4("2001:db8:1:1::b"), now).is_some());
        assert!(t.blocked(v4("2001:db8:1:2::a"), now).is_none());
        trip(&t, v4("203.0.113.7"), now);
        assert!(t.blocked(v4("::ffff:203.0.113.7"), now).is_some());
        assert!(t.blocked(v4("203.0.113.8"), now).is_none());
    }

    #[test]
    fn clear_forgets_the_count() {
        let t = FailureThrottle::new();
        let ip = v4("203.0.113.7");
        let now = Instant::now();
        trip(&t, ip, now);
        assert!(t.blocked(ip, now).is_some());
        t.clear(ip);
        assert_eq!(t.blocked(ip, now), None);
        assert_eq!(t.record(ip, now), Counted::Under);
    }

    fn nth_v4(i: usize) -> IpAddr {
        IpAddr::from([10, (i >> 16) as u8, (i >> 8) as u8, i as u8])
    }

    #[test]
    fn a_full_table_forgets_the_oldest_and_never_blocks_a_newcomer() {
        let t = FailureThrottle::new();
        let base = Instant::now();
        for i in 0..MAX_SOURCES {
            trip(&t, nth_v4(i), base + Duration::from_millis(i as u64));
        }
        let now = base + Duration::from_secs(1);
        let newcomer = v4("203.0.113.99");
        assert_eq!(t.blocked(newcomer, now), None);
        assert_eq!(t.record(newcomer, now), Counted::Under);
        assert!(t.len() <= MAX_SOURCES, "{}", t.len());
        assert_eq!(t.blocked(nth_v4(0), now), None);
        assert!(t.blocked(nth_v4(MAX_SOURCES - 1), now).is_some());
    }

    #[test]
    fn expired_entries_go_before_live_ones() {
        let t = FailureThrottle::new();
        let base = Instant::now();
        // Source 0 started first but is the only one still live later.
        trip(&t, nth_v4(0), base + FAILURE_WINDOW);
        for i in 1..MAX_SOURCES {
            trip(&t, nth_v4(i), base);
        }
        let now = base + FAILURE_WINDOW + Duration::from_secs(1);
        assert_eq!(t.record(v4("203.0.113.99"), now), Counted::Under);
        assert!(
            t.blocked(nth_v4(0), now).is_some(),
            "a live entry went first"
        );
        assert!(t.len() < MAX_SOURCES);
    }
}
