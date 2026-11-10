//! Transport-level client identity and request budgets for `/mcp`
//! (#200).
//!
//! The trusted-proxy helper itself — parsing `CF-Connecting-IP`
//! under the placement trust root, with the contract that the
//! resulting address may key throttling and appear in audit but must
//! never gate auth — is [`super::public::client_ip`] (#208 reuses it
//! from there). This module holds the two things every `/mcp`
//! listener shares: the [`ClientIp`] request extension the admitting
//! listener stamps (the header's address on `[public_ingress]`, the
//! connection peer elsewhere), and [`TransportLimits`].
//!
//! # Transport budgets
//!
//! [`TransportLimits`] bounds `/mcp` above the broker's own REQ-RL
//! limits, which price fills and reads per agent but not the cost of
//! reaching them: an unauthenticated flood burns Argon2id evaluations
//! in `authenticate`, and `kharon_status` / `kharon_context` sit
//! outside the broker's per-agent read budget. Two fixed one-minute
//! windows: per client IP (checked before auth, so a bad-token flood
//! is refused before it costs a hash) and per agent (checked after
//! auth). Refusals are the existing `429 rate_limited` shape and are
//! not audited: like the connector's junk traffic (#199), a stranger
//! must not be able to grow the audit log.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// Requests per minute from one client IP, before auth.
pub const PER_IP_PER_MINUTE: u32 = 60;
/// Requests per minute from one authenticated agent.
pub const PER_AGENT_PER_MINUTE: u32 = 240;
const WINDOW: Duration = Duration::from_secs(60);
/// Above this many live keys, a check first sweeps expired windows.
const SWEEP_AT: usize = 4096;

/// Request extension: the effective client address of this request,
/// stamped by the admitting listener (see [`super::public::client_ip`]
/// for the trusted-proxy contract). Throttle keying and audit only,
/// never auth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

#[derive(Debug, Default)]
struct Window {
    start: Option<Instant>,
    count: u32,
}

/// Fixed-window counters keyed by client IP and by agent id.
#[derive(Debug, Default)]
pub struct TransportLimits {
    ips: Mutex<HashMap<IpAddr, Window>>,
    agents: Mutex<HashMap<String, Window>>,
}

impl TransportLimits {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one request from `ip` at `now`; false when over budget.
    pub fn check_ip(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.ips.lock().unwrap_or_else(|p| p.into_inner());
        sweep(&mut map, now);
        admit(map.entry(ip).or_default(), PER_IP_PER_MINUTE, now)
    }

    /// Count one request from `agent` at `now`; false when over budget.
    pub fn check_agent(&self, agent: &str, now: Instant) -> bool {
        let mut map = self.agents.lock().unwrap_or_else(|p| p.into_inner());
        sweep(&mut map, now);
        admit(
            map.entry(agent.to_owned()).or_default(),
            PER_AGENT_PER_MINUTE,
            now,
        )
    }
}

/// Drop windows that have fully expired, once the map is large.
fn sweep<K>(map: &mut HashMap<K, Window>, now: Instant) {
    if map.len() < SWEEP_AT {
        return;
    }
    map.retain(|_, w| {
        w.start
            .is_some_and(|s| now.saturating_duration_since(s) < WINDOW)
    });
}

fn admit(w: &mut Window, limit: u32, now: Instant) -> bool {
    match w.start {
        Some(s) if now.saturating_duration_since(s) < WINDOW => {}
        _ => {
            w.start = Some(now);
            w.count = 0;
        }
    }
    w.count += 1;
    w.count <= limit
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn ip_window_admits_to_the_limit_then_refuses_and_resets() {
        let limits = TransportLimits::new();
        let t0 = Instant::now();
        for _ in 0..PER_IP_PER_MINUTE {
            assert!(limits.check_ip(PEER, t0));
        }
        assert!(!limits.check_ip(PEER, t0), "over budget in the window");
        assert!(
            limits.check_ip(CLIENT, t0),
            "a different key has its own budget"
        );
        let t1 = t0 + WINDOW;
        assert!(limits.check_ip(PEER, t1), "a new window resets the count");
    }

    #[test]
    fn agent_window_is_independent_of_the_ip_window() {
        let limits = TransportLimits::new();
        let t0 = Instant::now();
        for _ in 0..PER_AGENT_PER_MINUTE {
            assert!(limits.check_agent("assistant", t0));
        }
        assert!(!limits.check_agent("assistant", t0));
        assert!(limits.check_agent("other", t0));
        assert!(limits.check_ip(PEER, t0), "separate maps, separate budgets");
    }
}
