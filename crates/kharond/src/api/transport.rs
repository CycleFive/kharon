//! Transport-level client identity and request budgets for `/mcp`
//! (#200).
//!
//! The trusted-proxy helper itself — parsing `CF-Connecting-IP`
//! under the placement trust root, with the contract that the
//! resulting address may key throttling and appear in audit but must
//! never gate auth — is [`super::public::client_ip`] (#208 reuses it
//! from there). This module holds the two things every `/mcp`
//! listener shares: the [`ClientIp`] request extension the admitting
//! listener stamps (on `[public_ingress]`, the header's address when
//! the peer is loopback or a trusted proxy, and the connection peer
//! otherwise; on `[api]`, the peer), and [`TransportLimits`].
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
//!
//! The per-IP map is keyed and bounded so a stranger cannot grow it
//! or walk it (Nyx's required fix on PR #238): an IPv6 client is
//! keyed by its /64 — the smallest prefix a host can normally be
//! assigned, so holding a /64 yields exactly one key, not 2^64 — and
//! an IPv4-mapped IPv6 address shares the IPv4 key. A map holds at
//! most [`MAX_KEYS`] keys; once full, a *new* key is counted against
//! a single shared overflow window (still one budget, so the flood
//! stays refused past the limit) instead of inserting. Expired
//! windows are reclaimed by a sweep that runs at most once per
//! [`SWEEP_INTERVAL`], and only once the map is at the cap, so a
//! check never pays a full-map `retain` on the hot path more often
//! than that.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// Requests per minute from one client IP, before auth.
pub const PER_IP_PER_MINUTE: u32 = 60;
/// Requests per minute from one authenticated agent.
pub const PER_AGENT_PER_MINUTE: u32 = 240;
const WINDOW: Duration = Duration::from_secs(60);
/// Hard cap on live keys in one budget map. At the cap, new keys
/// share the overflow window instead of inserting.
const MAX_KEYS: usize = 4096;
/// Minimum spacing between full sweeps of a capped map: the sweep is
/// O(map) under the lock, so it is amortized across checks instead of
/// running on every check once the map is large (the pre-#238-fix
/// behaviour, which got slower exactly as the flood grew).
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

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

/// One budget map: fixed-window counters per key, hard-capped, with
/// a shared overflow window for new keys at the cap and an amortized
/// expired-window sweep.
#[derive(Debug)]
struct WindowMap<K> {
    map: HashMap<K, Window>,
    overflow: Window,
    last_sweep: Option<Instant>,
}

// Manual `Default`: the derive would demand `K: Default`, which
// `IpAddr` does not implement.
impl<K> Default for WindowMap<K> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            overflow: Window::default(),
            last_sweep: None,
        }
    }
}

impl<K: Eq + Hash> WindowMap<K> {
    /// Count one request for `key` at `now`; false when over budget.
    fn check(&mut self, key: K, limit: u32, now: Instant) -> bool {
        self.maybe_sweep(now);
        if let Some(w) = self.map.get_mut(&key) {
            return admit(w, limit, now);
        }
        if self.map.len() < MAX_KEYS {
            let mut w = Window::default();
            let admitted = admit(&mut w, limit, now);
            self.map.insert(key, w);
            admitted
        } else {
            admit(&mut self.overflow, limit, now)
        }
    }

    /// Reclaim fully-expired windows, at most once per
    /// [`SWEEP_INTERVAL`] and only once the map is at the cap (below
    /// the cap expired windows are reset in place by [`admit`], so
    /// there is nothing to reclaim that costs memory).
    fn maybe_sweep(&mut self, now: Instant) {
        if self.map.len() < MAX_KEYS {
            return;
        }
        if self
            .last_sweep
            .is_some_and(|s| now.saturating_duration_since(s) < SWEEP_INTERVAL)
        {
            return;
        }
        self.last_sweep = Some(now);
        self.map.retain(|_, w| {
            w.start
                .is_some_and(|s| now.saturating_duration_since(s) < WINDOW)
        });
    }
}

/// Fixed-window counters keyed by client IP and by agent id.
#[derive(Debug, Default)]
pub struct TransportLimits {
    ips: Mutex<WindowMap<IpAddr>>,
    agents: Mutex<WindowMap<String>>,
}

impl TransportLimits {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one request from `ip` at `now`; false when over budget.
    /// `ip` is keyed by [`ip_key`]: the full address for audit is the
    /// caller's business — only the throttle key is normalized.
    pub fn check_ip(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.ips.lock().unwrap_or_else(|p| p.into_inner());
        map.check(ip_key(ip), PER_IP_PER_MINUTE, now)
    }

    /// Count one request from `agent` at `now`; false when over budget.
    pub fn check_agent(&self, agent: &str, now: Instant) -> bool {
        let mut map = self.agents.lock().unwrap_or_else(|p| p.into_inner());
        map.check(agent.to_owned(), PER_AGENT_PER_MINUTE, now)
    }
}

/// The throttle key for a client address: IPv4 unchanged, an
/// IPv4-mapped IPv6 address as its IPv4 address, any other IPv6
/// address truncated to its /64 (host bits zeroed).
pub(crate) fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::from([s[0], s[1], s[2], s[3], 0, 0, 0, 0]))
            }
        },
    }
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

    fn v6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A distinct IPv4 key per index (10.0.0.0/8 test space).
    fn v4_at(i: usize) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(
            10,
            ((i >> 16) & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
        ))
    }

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

    #[test]
    fn ipv6_clients_are_keyed_by_their_slash64() {
        let limits = TransportLimits::new();
        let t0 = Instant::now();
        let a = v6("2001:db8:1:2::1");
        let same_64 = v6("2001:db8:1:2:ffff:ffff:ffff:ffff");
        let other_64 = v6("2001:db8:1:3::1");
        for _ in 0..PER_IP_PER_MINUTE {
            assert!(limits.check_ip(a, t0));
        }
        assert!(
            !limits.check_ip(same_64, t0),
            "another host in the same /64 shares the exhausted budget"
        );
        assert!(
            limits.check_ip(other_64, t0),
            "a different /64 has its own budget"
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_shares_the_ipv4_key() {
        let limits = TransportLimits::new();
        let t0 = Instant::now();
        let mapped = v6("::ffff:203.0.113.7");
        for _ in 0..PER_IP_PER_MINUTE {
            assert!(limits.check_ip(mapped, t0));
        }
        assert!(
            !limits.check_ip(CLIENT, t0),
            "the mapped form and the plain form are one client"
        );
    }

    #[test]
    fn ip_map_is_capped_and_new_keys_share_the_overflow_window() {
        let limits = TransportLimits::new();
        let t0 = Instant::now();
        for i in 0..MAX_KEYS {
            assert!(limits.check_ip(v4_at(i), t0));
        }
        {
            let map = limits.ips.lock().unwrap();
            assert_eq!(
                map.map.len(),
                MAX_KEYS,
                "the map must not grow past the cap"
            );
        }
        // A new key is admitted against the shared overflow window…
        let new_a = v4_at(MAX_KEYS);
        for _ in 0..PER_IP_PER_MINUTE {
            assert!(limits.check_ip(new_a, t0));
        }
        // …so a second new key finds that same window exhausted,
        // instead of getting a fresh budget of its own.
        assert!(
            !limits.check_ip(v4_at(MAX_KEYS + 1), t0),
            "overflow is one shared budget, not one per new key"
        );
        // A key already in the map keeps its own window.
        assert!(limits.check_ip(v4_at(0), t0));
        {
            let map = limits.ips.lock().unwrap();
            assert_eq!(map.map.len(), MAX_KEYS, "overflow keys are never inserted");
        }
        // The overflow window resets like any other.
        let t1 = t0 + WINDOW;
        assert!(limits.check_ip(v4_at(MAX_KEYS + 1), t1));
    }

    #[test]
    fn sweep_reclaims_expired_keys_once_the_window_passes() {
        let limits = TransportLimits::new();
        let t0 = Instant::now();
        for i in 0..MAX_KEYS {
            assert!(limits.check_ip(v4_at(i), t0));
        }
        // Past the window, the first check sweeps the expired keys,
        // so new keys get their own windows again instead of the
        // shared overflow path: two distinct new keys can each
        // spend a full budget.
        let t1 = t0 + WINDOW;
        let new_a = v4_at(MAX_KEYS);
        let new_b = v4_at(MAX_KEYS + 1);
        for _ in 0..PER_IP_PER_MINUTE {
            assert!(limits.check_ip(new_a, t1));
        }
        assert!(
            limits.check_ip(new_b, t1),
            "after the sweep a new key has its own budget, not the overflow one"
        );
    }

    #[test]
    fn sweep_is_amortized_to_once_per_interval() {
        let t0 = Instant::now();
        let mut map: WindowMap<IpAddr> = WindowMap::default();
        for i in 0..MAX_KEYS {
            assert!(map.check(v4_at(i), PER_IP_PER_MINUTE, t0));
        }
        // Expire every window, then sweep once.
        let t1 = t0 + WINDOW;
        assert!(map.check(PEER, PER_IP_PER_MINUTE, t1));
        assert_eq!(map.map.len(), 1, "the sweep dropped the expired keys");
        // Refill to the cap with expired windows; a check inside
        // SWEEP_INTERVAL of the last sweep must not sweep again…
        for i in 0..MAX_KEYS - 1 {
            map.map.insert(
                v4_at(i),
                Window {
                    start: Some(t0),
                    count: 1,
                },
            );
        }
        let t2 = t1 + SWEEP_INTERVAL / 2;
        let _ = map.check(PEER, PER_IP_PER_MINUTE, t2);
        assert_eq!(
            map.map.len(),
            MAX_KEYS,
            "no second full sweep inside the interval"
        );
        // …and a check after the interval does.
        let t3 = t1 + SWEEP_INTERVAL + Duration::from_millis(1);
        let _ = map.check(PEER, PER_IP_PER_MINUTE, t3);
        assert_eq!(map.map.len(), 1, "the next sweep reclaims them");
    }
}
