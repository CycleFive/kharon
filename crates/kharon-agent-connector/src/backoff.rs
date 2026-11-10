//! Reconnect pacing and the outage summary. Pure: the caller injects the
//! clock and the RNG, so the tests need no sleeps.

use std::time::{Duration, Instant};

use kharon_connector::ClientError;
use rand::Rng;

const FIRST: Duration = Duration::from_secs(1);
const CAP: Duration = Duration::from_secs(30);
/// First summary after this long with no authenticated session.
const SUMMARY_FIRST: Duration = Duration::from_secs(2 * 60);
/// Then one summary per this interval.
const SUMMARY_EVERY: Duration = Duration::from_secs(10 * 60);

/// Exponential backoff with full jitter: each wait is uniform in
/// `0..=delay`, and `delay` doubles up to 30 s.
#[derive(Debug, Clone)]
pub struct Backoff {
    delay: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { delay: FIRST }
    }
}

impl Backoff {
    pub fn next(&mut self, rng: &mut impl Rng) -> Duration {
        let ms = u64::try_from(self.delay.as_millis()).unwrap_or(u64::MAX);
        let wait = Duration::from_millis(rng.gen_range(0..=ms));
        self.delay = (self.delay * 2).min(CAP);
        wait
    }

    pub fn reset(&mut self) {
        self.delay = FIRST;
    }

    #[cfg(test)]
    fn delay(&self) -> Duration {
        self.delay
    }
}

/// The leg a failure belongs to, as it appears in log lines.
pub fn leg_name(err: &ClientError) -> &'static str {
    match err {
        ClientError::Dns => "dns",
        ClientError::Tcp { .. } => "tcp",
        ClientError::ProxyStatus { .. } | ClientError::ProxyAuth => "proxy",
        ClientError::OuterTls(_) => "outer-tls",
        ClientError::Upgrade { .. } => "upgrade",
        ClientError::InnerTls | ClientError::BadCert => "inner-tls",
        ClientError::Unauthorized | ClientError::Protocol => "auth",
        ClientError::Disconnected => "session",
        ClientError::CdpNotLoopback => "config",
    }
}

/// Where this process dials, for the failure lines that name a host or an
/// address. Taken from the binary's own config, never from the peer.
#[derive(Debug, Clone)]
pub struct At {
    /// The broker host (no port).
    pub host: String,
    /// `host:port` of the broker.
    pub broker: String,
    /// `host:port` of the proxy, when one is configured.
    pub proxy: Option<String>,
}

/// The fixed error text, naming the host (dns) or the address (tcp) that
/// was tried. The `tcp` leg dials the proxy when there is one.
pub fn err_text(err: &ClientError, at: &At) -> String {
    match err {
        ClientError::Dns => format!("{err} ({})", at.host),
        ClientError::Tcp { .. } => {
            format!("{err} to {}", at.proxy.as_deref().unwrap_or(&at.broker))
        }
        _ => err.to_string(),
    }
}

/// `<leg>: <fixed error text>`, naming the host or address. Never holds a
/// token, credential or peer body.
pub fn leg_line_at(err: &ClientError, at: &At) -> String {
    format!("{}: {}", leg_name(err), err_text(err, at))
}

/// Credential refusals wait a fixed 60 s; everything else is jittered.
pub fn is_fixed_wait(err: &ClientError) -> bool {
    matches!(err, ClientError::Unauthorized | ClientError::ProxyAuth)
}

/// Time without an authenticated session, for the loud summary line.
#[derive(Debug, Default)]
pub struct Outage {
    since: Option<Instant>,
    attempts: u64,
    next_summary: Option<Instant>,
}

impl Outage {
    /// Record a failed attempt. Returns the summary line when one is due:
    /// first at 2 min after the outage began, then every 10 min.
    pub fn on_failure(&mut self, now: Instant, err: &ClientError, at: &At) -> Option<String> {
        let since = *self.since.get_or_insert(now);
        self.attempts += 1;
        let due = *self.next_summary.get_or_insert(since + SUMMARY_FIRST);
        if now < due {
            return None;
        }
        self.next_summary = Some(now + SUMMARY_EVERY);
        Some(format!(
            "kharon-agent-connector: no broker session for {} ({} attempts); last failure: {}",
            fmt_dur(now.duration_since(since)),
            self.attempts,
            leg_line_at(err, at)
        ))
    }

    /// `AUTH_OK` arrived: the outage is over.
    pub fn on_auth(&mut self) {
        *self = Self::default();
    }
}

pub fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    fn at() -> At {
        At {
            host: "broker.example.net".into(),
            broker: "broker.example.net:7443".into(),
            proxy: None,
        }
    }

    #[test]
    fn backoff_is_full_jitter_and_caps_at_30s() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut b = Backoff::default();
        let mut saw_below_half = false;
        for _ in 0..200 {
            let cur = b.delay();
            let w = b.next(&mut rng);
            assert!(w <= cur, "{w:?} > {cur:?}");
            if w < cur / 2 {
                saw_below_half = true;
            }
            assert!(b.delay() <= Duration::from_secs(30));
        }
        assert_eq!(b.delay(), Duration::from_secs(30));
        assert!(saw_below_half, "no jitter observed");
        b.reset();
        assert_eq!(b.delay(), Duration::from_secs(1));
    }

    #[test]
    fn outage_summary_at_2m_then_every_10m() {
        let t0 = Instant::now();
        let e = ClientError::Upgrade { status: 502 };
        let mut o = Outage::default();
        assert!(o.on_failure(t0, &e, &at()).is_none());
        assert!(
            o.on_failure(t0 + Duration::from_secs(119), &e, &at())
                .is_none()
        );
        let line = o
            .on_failure(t0 + Duration::from_secs(120), &e, &at())
            .unwrap();
        assert_eq!(
            line,
            "kharon-agent-connector: no broker session for 2m0s (3 attempts); \
             last failure: upgrade: websocket upgrade answered 502"
        );
        assert!(
            o.on_failure(t0 + Duration::from_secs(400), &e, &at())
                .is_none()
        );
        assert!(
            o.on_failure(t0 + Duration::from_secs(719), &e, &at())
                .is_none()
        );
        let line = o
            .on_failure(t0 + Duration::from_secs(720), &e, &at())
            .unwrap();
        assert!(line.contains("12m0s (6 attempts)"), "{line}");
    }

    #[test]
    fn outage_summary_names_the_host_on_dns_failure() {
        let t0 = Instant::now();
        let e = ClientError::Dns;
        let mut o = Outage::default();
        o.on_failure(t0, &e, &at());
        let line = o
            .on_failure(t0 + Duration::from_secs(120), &e, &at())
            .unwrap();
        assert_eq!(
            line,
            "kharon-agent-connector: no broker session for 2m0s (2 attempts); \
             last failure: dns: cannot resolve the broker host (broker.example.net)"
        );
    }

    #[test]
    fn outage_resets_on_auth() {
        let t0 = Instant::now();
        let e = ClientError::Dns;
        let mut o = Outage::default();
        o.on_failure(t0, &e, &at());
        assert!(
            o.on_failure(t0 + Duration::from_secs(130), &e, &at())
                .is_some()
        );
        o.on_auth();
        let t1 = t0 + Duration::from_secs(200);
        assert!(o.on_failure(t1, &e, &at()).is_none());
        assert!(
            o.on_failure(t1 + Duration::from_secs(119), &e, &at())
                .is_none()
        );
        let line = o
            .on_failure(t1 + Duration::from_secs(120), &e, &at())
            .unwrap();
        assert!(line.contains("(3 attempts)"), "{line}");
    }
}
