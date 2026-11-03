//! Clock skew check for TOTP (REQ-API-007).
//!
//! A TOTP code is only as good as the clock it is computed from. At
//! startup the daemon compares the system clock with the `Date`
//! header of a Vaultwarden response ([`ClockSample`]) and feeds the
//! result to the [`ClockSkewGate`]:
//!
//! | `abs(skew)` | verdict | effect |
//! |---|---|---|
//! | ≤ `clock_skew_warn` (30 s) | [`SkewVerdict::Ok`] | none |
//! | > warn, ≤ `clock_skew_refuse` (90 s) | [`SkewVerdict::Warn`] | warning + audit `clock_skew` |
//! | > `clock_skew_refuse` | [`SkewVerdict::Refuse`] | warning + audit `clock_skew`; `fill_totp` → `error: clock_skew` |
//!
//! "Until resolved": the gate holds the latest verdict, so a later
//! sample within the refuse threshold reopens `fill_totp` (and is
//! audited as `clock_skew` / `resolved`). Password fills never consult
//! the gate. Before any sample is taken the gate is open: the check
//! guards code correctness (a wrong code just fails at the site), not
//! confidentiality, and a Vaultwarden outage at startup must not
//! disable TOTP on its own.
//!
//! `Date` has one-second resolution and is stamped when the server
//! builds the response, so a sample's error is about a second plus the
//! request's one-way latency — far below the 30 s threshold.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::audit::{Entry, Event};
use crate::config::PolicyConfig;

/// Default `clock_skew_warn`.
pub const DEFAULT_WARN: Duration = Duration::from_secs(30);
/// Default `clock_skew_refuse`.
pub const DEFAULT_REFUSE: Duration = Duration::from_secs(90);

/// The two thresholds (`[policy] clock_skew_warn`, `clock_skew_refuse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkewPolicy {
    /// Above this: warning + audit.
    pub warn: Duration,
    /// Above this: `fill_totp` refused.
    pub refuse: Duration,
}

impl Default for SkewPolicy {
    fn default() -> Self {
        Self {
            warn: DEFAULT_WARN,
            refuse: DEFAULT_REFUSE,
        }
    }
}

impl From<&PolicyConfig> for SkewPolicy {
    fn from(p: &PolicyConfig) -> Self {
        Self {
            warn: p.clock_skew_warn,
            refuse: p.clock_skew_refuse,
        }
    }
}

impl SkewPolicy {
    /// Classify an absolute skew.
    pub fn classify(&self, skew: Duration) -> SkewVerdict {
        if skew > self.refuse {
            SkewVerdict::Refuse
        } else if skew > self.warn {
            SkewVerdict::Warn
        } else {
            SkewVerdict::Ok
        }
    }
}

/// The outcome of one comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkewVerdict {
    /// Within `clock_skew_warn`.
    Ok,
    /// Above `clock_skew_warn`: warning + audit only.
    Warn,
    /// Above `clock_skew_refuse`: `fill_totp` refused.
    Refuse,
}

impl SkewVerdict {
    /// The audit `result` string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Refuse => "refuse",
        }
    }
}

/// One server-vs-local clock reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSample {
    /// The server's clock (the `Date` header).
    pub server: SystemTime,
    /// The local clock when the response arrived.
    pub local: SystemTime,
}

impl ClockSample {
    /// Parse an HTTP `Date` header value (RFC 9110 §5.6.7 IMF-fixdate,
    /// plus the obsolete forms `httpdate` accepts). `None` if it does
    /// not parse.
    pub fn from_date_header(value: &str, local: SystemTime) -> Option<Self> {
        let server = httpdate::parse_http_date(value.trim()).ok()?;
        Some(Self { server, local })
    }

    /// `local - server` in whole seconds (positive: local clock ahead).
    pub fn skew_secs(&self) -> i64 {
        match self.local.duration_since(self.server) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
        }
    }

    /// `abs(local - server)`.
    pub fn abs_skew(&self) -> Duration {
        match self.local.duration_since(self.server) {
            Ok(d) => d,
            Err(e) => e.duration(),
        }
    }
}

/// `fill_totp` refused: the last sample exceeded `clock_skew_refuse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("clock skew exceeds clock_skew_refuse")]
pub struct ClockSkewRefused;

#[derive(Debug, Default)]
struct State {
    last: Option<(SkewVerdict, i64)>,
}

/// The process-wide skew state `fill_totp` consults.
#[derive(Debug)]
pub struct ClockSkewGate {
    policy: SkewPolicy,
    state: Mutex<State>,
}

impl Default for ClockSkewGate {
    fn default() -> Self {
        Self::new(SkewPolicy::default())
    }
}

/// What [`ClockSkewGate::observe`] decided, and what to tell the owner
/// and the audit log.
#[derive(Debug, Clone)]
pub struct Observation {
    /// The verdict for this sample.
    pub verdict: SkewVerdict,
    /// `local - server`, seconds.
    pub skew_secs: i64,
    /// The `clock_skew` audit entry to append, if any: on every warn or
    /// refuse sample, and when a previous warn/refuse is resolved.
    pub audit: Option<Entry>,
    /// The operator warning line, if any (fixed text plus numbers).
    pub warning: Option<String>,
}

impl ClockSkewGate {
    /// A gate with no sample yet (open).
    pub fn new(policy: SkewPolicy) -> Self {
        Self {
            policy,
            state: Mutex::new(State::default()),
        }
    }

    /// The thresholds.
    pub fn policy(&self) -> SkewPolicy {
        self.policy
    }

    /// Record a sample and return the verdict plus the audit entry and
    /// warning the caller must emit. The caller appends the entry
    /// (the gate does not own the log).
    pub fn observe(&self, sample: ClockSample) -> Observation {
        let verdict = self.policy.classify(sample.abs_skew());
        let skew_secs = sample.skew_secs();
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let previous = st.last.map(|(v, _)| v);
        st.last = Some((verdict, skew_secs));
        drop(st);
        let detail = format!("skew_{skew_secs:+}s");
        let (audit, warning) = match verdict {
            SkewVerdict::Ok => match previous {
                Some(SkewVerdict::Warn | SkewVerdict::Refuse) => (
                    Some(
                        Entry::new(Event::ClockSkew)
                            .result("resolved")
                            .detail_code(detail),
                    ),
                    None,
                ),
                _ => (None, None),
            },
            SkewVerdict::Warn => (
                Some(
                    Entry::new(Event::ClockSkew)
                        .result(verdict.as_str())
                        .detail_code(detail),
                ),
                Some(format!(
                    "system clock differs from the Vaultwarden server by {skew_secs:+} s \
                     (clock_skew_warn = {} s); TOTP codes may be rejected",
                    self.policy.warn.as_secs()
                )),
            ),
            SkewVerdict::Refuse => (
                Some(
                    Entry::new(Event::ClockSkew)
                        .result(verdict.as_str())
                        .detail_code(detail),
                ),
                Some(format!(
                    "system clock differs from the Vaultwarden server by {skew_secs:+} s \
                     (clock_skew_refuse = {} s); fill_totp is refused until the clock is fixed",
                    self.policy.refuse.as_secs()
                )),
            ),
        };
        Observation {
            verdict,
            skew_secs,
            audit,
            warning,
        }
    }

    /// The latest verdict (`None` before the first sample).
    pub fn verdict(&self) -> Option<SkewVerdict> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last
            .map(|(v, _)| v)
    }

    /// `Err` while the latest sample is above `clock_skew_refuse`.
    pub fn check_totp(&self) -> Result<(), ClockSkewRefused> {
        match self.verdict() {
            Some(SkewVerdict::Refuse) => Err(ClockSkewRefused),
            _ => Ok(()),
        }
    }
}
