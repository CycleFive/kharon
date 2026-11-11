//! A ceiling on the `owner_auth_fail` entries a stranger can cause,
//! public mode only (#208 D6, REQ-APR-009).
//!
//! The audit log is hash-chained and a full disk makes credential fills
//! fail closed, so the number of entries an unauthenticated caller can
//! append has to be bounded. At most [`ITEMIZED_PER_WINDOW`] are itemized
//! per [`AUDIT_WINDOW`]; the rest are counted. The count rides on the
//! next itemized entry, or leaves as a `suppressed_only` entry from the
//! daemon's flush tick, or at shutdown. The budget never refuses a
//! request: it only decides what is written.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Entries itemized in one window.
pub(crate) const ITEMIZED_PER_WINDOW: u32 = 20;
/// `throttled` trip entries itemized in one window, outside the
/// [`ITEMIZED_PER_WINDOW`] (Nyx's ruling on #253: wrong-`Origin` noise
/// must not hide a trip).
pub(crate) const TRIPS_PER_WINDOW: u32 = 5;
/// A fixed window, starting at the first admitted failure.
pub(crate) const AUDIT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Window {
    start: Option<Instant>,
    /// Entries itemized in this window.
    written: u32,
    /// Trip entries itemized in this window.
    trips: u32,
    /// Failures counted and not yet logged.
    pending: u64,
}

/// What the audit sink should do with one failure.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Itemize it. `suppressed` is the count carried from a closed window.
    Write { suppressed: Option<u64> },
    /// Count it; write nothing.
    Suppress,
}

pub(crate) struct AuditBudget {
    window: Mutex<Window>,
}

impl AuditBudget {
    pub fn new() -> Self {
        Self {
            window: Mutex::new(Window::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Window> {
        self.window.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn closed(w: &Window, now: Instant) -> bool {
        w.start
            .is_some_and(|s| now.saturating_duration_since(s) >= AUDIT_WINDOW)
    }

    /// Open a new window when `now` starts one; the previous window's
    /// count, taken once, for the first entry written in it.
    fn roll(w: &mut Window, now: Instant) -> Option<u64> {
        if w.start.is_some() && !Self::closed(w, now) {
            return None;
        }
        let carried = Some(std::mem::take(&mut w.pending)).filter(|n| *n > 0);
        w.start = Some(now);
        w.written = 0;
        w.trips = 0;
        carried
    }

    /// One session-less failure at `now`. The first `Write` of a new window
    /// carries the previous window's count, if any.
    pub fn admit(&self, now: Instant) -> Verdict {
        let mut w = self.lock();
        let carried = Self::roll(&mut w, now);
        if w.written < ITEMIZED_PER_WINDOW {
            w.written += 1;
            Verdict::Write {
                suppressed: carried,
            }
        } else {
            w.pending += 1;
            Verdict::Suppress
        }
    }

    /// One `throttled` trip entry: its own allowance of
    /// [`TRIPS_PER_WINDOW`], same window and same pending count. A trip
    /// never uses one of the 20.
    pub fn admit_trip(&self, now: Instant) -> Verdict {
        let mut w = self.lock();
        let carried = Self::roll(&mut w, now);
        if w.trips < TRIPS_PER_WINDOW {
            w.trips += 1;
            Verdict::Write {
                suppressed: carried,
            }
        } else {
            w.pending += 1;
            Verdict::Suppress
        }
    }

    /// The count of a window that has closed, once. `None` inside a window.
    pub fn flush(&self, now: Instant) -> Option<u64> {
        let mut w = self.lock();
        if !Self::closed(&w, now) {
            return None;
        }
        Some(std::mem::take(&mut w.pending)).filter(|n| *n > 0)
    }

    /// The pending count at shutdown, window closed or not.
    pub fn drain(&self) -> Option<u64> {
        let mut w = self.lock();
        Some(std::mem::take(&mut w.pending)).filter(|n| *n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 25 failures in one window: 20 itemized, 5 counted.
    fn flooded() -> (AuditBudget, Instant) {
        let b = AuditBudget::new();
        let t0 = Instant::now();
        for i in 1..=25 {
            let v = b.admit(t0);
            if i <= 20 {
                assert_eq!(v, Verdict::Write { suppressed: None }, "{i}");
            } else {
                assert_eq!(v, Verdict::Suppress, "{i}");
            }
        }
        (b, t0)
    }

    #[test]
    fn twenty_are_itemized_then_the_rest_are_counted() {
        flooded();
    }

    #[test]
    fn the_count_rides_on_the_next_windows_first_entry() {
        let (b, t0) = flooded();
        let later = t0 + AUDIT_WINDOW;
        assert_eq!(
            b.admit(later),
            Verdict::Write {
                suppressed: Some(5)
            }
        );
        assert_eq!(b.admit(later), Verdict::Write { suppressed: None });
    }

    #[test]
    fn flush_reports_a_closed_window_once() {
        let (b, t0) = flooded();
        assert_eq!(b.flush(t0 + Duration::from_secs(59)), None);
        assert_eq!(b.flush(t0 + AUDIT_WINDOW), Some(5));
        assert_eq!(b.flush(t0 + AUDIT_WINDOW), None);
        // Nothing is left to ride on the next window's first entry.
        assert_eq!(
            b.admit(t0 + AUDIT_WINDOW),
            Verdict::Write { suppressed: None }
        );
    }

    #[test]
    fn trips_have_their_own_allowance() {
        let b = AuditBudget::new();
        let t0 = Instant::now();
        for i in 1..=20 {
            assert_eq!(b.admit(t0), Verdict::Write { suppressed: None }, "{i}");
        }
        for i in 1..=5 {
            assert_eq!(b.admit_trip(t0), Verdict::Write { suppressed: None }, "{i}");
        }
        assert_eq!(b.admit_trip(t0), Verdict::Suppress);
        assert_eq!(b.admit(t0), Verdict::Suppress);
        assert_eq!(b.drain(), Some(2));
    }

    #[test]
    fn a_trip_can_open_a_window_and_carry_the_count() {
        let (b, t0) = flooded();
        let later = t0 + AUDIT_WINDOW;
        assert_eq!(
            b.admit_trip(later),
            Verdict::Write {
                suppressed: Some(5)
            }
        );
        assert_eq!(b.admit(later), Verdict::Write { suppressed: None });
    }

    #[test]
    fn drain_reports_pending_inside_a_window() {
        let (b, _) = flooded();
        assert_eq!(b.drain(), Some(5));
        assert_eq!(b.drain(), None);
    }
}
