//! Per-agent / per-item rate limits and agent suspension (REQ-RL-001,
//! REQ-RL-002, REQ-RL-003).
//!
//! Time is the broker's injected [`Clock`](crate::lock::Clock) reading
//! (`Duration` since an arbitrary epoch), the same source grant TTLs
//! use, so tests drive limits with one `ManualClock`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use crate::config::PolicyConfig;

/// SPEC default: fills (and `fill_totp`) share 10/min.
pub const DEFAULT_FILLS_PER_MINUTE: u32 = 10;
/// SPEC default: fills share 100/day.
pub const DEFAULT_FILLS_PER_DAY: u32 = 100;
/// SPEC default: list/search 60/min.
pub const DEFAULT_LIST_PER_MINUTE: u32 = 60;
/// SPEC default: 5 fills of one item per 10 min.
pub const DEFAULT_ITEM_FILLS_PER_WINDOW: u32 = 5;
/// SPEC default window for the per-item fill cap.
pub const DEFAULT_ITEM_FILL_WINDOW: Duration = Duration::from_secs(10 * 60);
/// SPEC default: pending grant requests per agent.
pub const DEFAULT_MAX_PENDING_GRANTS: u32 = 3;
/// SPEC default: consecutive `origin_mismatch` → suspend.
pub const DEFAULT_ORIGIN_MISMATCH_SUSPEND: u32 = 5;

const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Configurable rate / suspension thresholds (`[policy]`, REQ-RL-*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicy {
    /// Shared fill + fill_totp budget per agent per minute.
    pub fills_per_minute: u32,
    /// Shared fill + fill_totp budget per agent per day.
    pub fills_per_day: u32,
    /// List + search budget per agent per minute.
    pub list_per_minute: u32,
    /// Fills (password or TOTP) of one item inside [`Self::item_fill_window`].
    pub item_fills_per_window: u32,
    /// Window for the per-item fill cap.
    pub item_fill_window: Duration,
    /// Pending grant requests allowed per agent (REQ-RL-003).
    pub max_pending_grants: u32,
    /// Consecutive `origin_mismatch` results that suspend the agent.
    pub origin_mismatch_suspend: u32,
}

impl Default for RatePolicy {
    fn default() -> Self {
        Self {
            fills_per_minute: DEFAULT_FILLS_PER_MINUTE,
            fills_per_day: DEFAULT_FILLS_PER_DAY,
            list_per_minute: DEFAULT_LIST_PER_MINUTE,
            item_fills_per_window: DEFAULT_ITEM_FILLS_PER_WINDOW,
            item_fill_window: DEFAULT_ITEM_FILL_WINDOW,
            max_pending_grants: DEFAULT_MAX_PENDING_GRANTS,
            origin_mismatch_suspend: DEFAULT_ORIGIN_MISMATCH_SUSPEND,
        }
    }
}

impl From<&PolicyConfig> for RatePolicy {
    fn from(p: &PolicyConfig) -> Self {
        Self {
            fills_per_minute: p.fills_per_minute,
            fills_per_day: p.fills_per_day,
            list_per_minute: p.list_per_minute,
            item_fills_per_window: p.item_fills_per_window,
            item_fill_window: p.item_fill_window,
            max_pending_grants: p.max_pending_grants,
            origin_mismatch_suspend: p.origin_mismatch_suspend,
        }
    }
}

/// Sliding window of event timestamps (clock readings).
#[derive(Debug, Clone, Default)]
struct Window {
    events: VecDeque<Duration>,
}

impl Window {
    fn prune(&mut self, now: Duration, window: Duration) {
        while self
            .events
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= window)
        {
            self.events.pop_front();
        }
    }

    /// Record `now` if under `limit` inside `window`; else leave the
    /// window unchanged and return `false`.
    fn try_add(&mut self, now: Duration, limit: u32, window: Duration) -> bool {
        self.prune(now, window);
        if self.events.len() as u32 >= limit {
            return false;
        }
        self.events.push_back(now);
        true
    }

    #[allow(dead_code)]
    fn len_in(&mut self, now: Duration, window: Duration) -> usize {
        self.prune(now, window);
        self.events.len()
    }
}

#[derive(Debug, Default)]
struct AgentWindows {
    fill_minute: Window,
    fill_day: Window,
    list_minute: Window,
}

/// Why an admission was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDenied {
    /// Agent is suspended (REQ-RL-002) until the owner resets it.
    Suspended,
    /// A token-bucket / sliding-window budget was exhausted.
    Limited,
}

/// Per-agent fill/list buckets, per-item fill windows, and suspension
/// (REQ-RL-001 / 002). Pending-grant caps live on the grant store
/// (REQ-RL-003) but share this policy's `max_pending_grants`.
#[derive(Debug)]
pub struct RateLimiter {
    policy: RatePolicy,
    agents: BTreeMap<String, AgentWindows>,
    /// Per-item fill timestamps (global across agents; SPEC "per-item").
    items: BTreeMap<String, Window>,
    mismatch_streak: BTreeMap<String, u32>,
    suspended: BTreeSet<String>,
    /// Agents whose token is revoked (REQ-REV-001); authenticate fails.
    revoked: BTreeSet<String>,
}

impl RateLimiter {
    /// Empty limiter under `policy`.
    pub fn new(policy: RatePolicy) -> Self {
        Self {
            policy,
            agents: BTreeMap::new(),
            items: BTreeMap::new(),
            mismatch_streak: BTreeMap::new(),
            suspended: BTreeSet::new(),
            revoked: BTreeSet::new(),
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> &RatePolicy {
        &self.policy
    }

    /// Replace the policy (tests / config reload). Existing windows
    /// keep their history; only the thresholds change.
    pub fn set_policy(&mut self, policy: RatePolicy) {
        self.policy = policy;
    }

    /// Whether `agent` is suspended (REQ-RL-002).
    pub fn is_suspended(&self, agent: &str) -> bool {
        self.suspended.contains(agent)
    }

    /// Whether `agent`'s token has been revoked (REQ-REV-001).
    pub fn is_revoked(&self, agent: &str) -> bool {
        self.revoked.contains(agent)
    }

    /// Mark the agent revoked (token + future auth fail).
    pub fn revoke_agent(&mut self, agent: &str) {
        self.revoked.insert(agent.to_owned());
        self.suspended.insert(agent.to_owned());
        self.mismatch_streak.remove(agent);
        self.agents.remove(agent);
    }

    /// Clear revocation so a reconfigured token can authenticate
    /// again. Suspension is cleared too (owner reset). Not wired to
    /// the owner socket: `unsuspend` does not call this, so a
    /// revoked agent stays revoked until the daemon process exits.
    pub fn clear_revocation(&mut self, agent: &str) {
        self.revoked.remove(agent);
        self.unsuspend(agent);
    }

    /// Owner reset of a suspension (REQ-RL-002).
    pub fn unsuspend(&mut self, agent: &str) {
        self.suspended.remove(agent);
        self.mismatch_streak.remove(agent);
    }

    /// Admit one fill / fill_totp for `agent` against `item_id`
    /// (REQ-RL-001 share + REQ-RL-002 per-item). On `Ok(())` the
    /// counters have already been spent.
    pub fn admit_fill(
        &mut self,
        agent: &str,
        item_id: &str,
        now: Duration,
    ) -> Result<(), RateDenied> {
        if self.suspended.contains(agent) {
            return Err(RateDenied::Suspended);
        }
        let pol = self.policy.clone();
        let aw = self.agents.entry(agent.to_owned()).or_default();
        // Check both fill buckets without mutating until both pass,
        // then the item window — so a refusal spends nothing.
        aw.fill_minute.prune(now, MINUTE);
        aw.fill_day.prune(now, DAY);
        if aw.fill_minute.events.len() as u32 >= pol.fills_per_minute
            || aw.fill_day.events.len() as u32 >= pol.fills_per_day
        {
            return Err(RateDenied::Limited);
        }
        let item = self.items.entry(item_id.to_owned()).or_default();
        item.prune(now, pol.item_fill_window);
        if item.events.len() as u32 >= pol.item_fills_per_window {
            return Err(RateDenied::Limited);
        }
        // Spend.
        let aw = self.agents.entry(agent.to_owned()).or_default();
        aw.fill_minute.events.push_back(now);
        aw.fill_day.events.push_back(now);
        self.items
            .entry(item_id.to_owned())
            .or_default()
            .events
            .push_back(now);
        Ok(())
    }

    /// Admit one list or search (REQ-RL-001).
    pub fn admit_list(&mut self, agent: &str, now: Duration) -> Result<(), RateDenied> {
        if self.suspended.contains(agent) {
            return Err(RateDenied::Suspended);
        }
        let limit = self.policy.list_per_minute;
        let aw = self.agents.entry(agent.to_owned()).or_default();
        if aw.list_minute.try_add(now, limit, MINUTE) {
            Ok(())
        } else {
            Err(RateDenied::Limited)
        }
    }

    /// Record an `origin_mismatch` for `agent`. Returns `true` when
    /// this call newly suspended the agent (5th consecutive;
    /// REQ-RL-002) — the caller audits once.
    pub fn note_origin_mismatch(&mut self, agent: &str) -> bool {
        if self.suspended.contains(agent) {
            return false;
        }
        let streak = self.mismatch_streak.entry(agent.to_owned()).or_insert(0);
        *streak = streak.saturating_add(1);
        if *streak >= self.policy.origin_mismatch_suspend {
            self.suspended.insert(agent.to_owned());
            self.mismatch_streak.remove(agent);
            return true;
        }
        false
    }

    /// A non-mismatch fill outcome breaks the consecutive streak.
    pub fn note_non_mismatch(&mut self, agent: &str) {
        self.mismatch_streak.remove(agent);
    }

    /// Pending-grant cap from policy (REQ-RL-003).
    pub fn max_pending_grants(&self) -> u32 {
        self.policy.max_pending_grants
    }

    /// Test helper: fills recorded for `agent` in the last minute.
    #[cfg(test)]
    pub fn fill_minute_count(&mut self, agent: &str, now: Duration) -> usize {
        self.agents
            .get_mut(agent)
            .map(|a| a.fill_minute.len_in(now, MINUTE))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_rl_001_eleventh_fill_in_a_minute_is_limited() {
        let mut lim = RateLimiter::new(RatePolicy {
            item_fills_per_window: 100, // isolate the per-agent minute bucket
            ..RatePolicy::default()
        });
        let now = Duration::from_secs(1_000);
        for i in 0..10 {
            assert_eq!(
                lim.admit_fill("alpha", "item", now + Duration::from_millis(i)),
                Ok(())
            );
        }
        assert_eq!(
            lim.admit_fill("alpha", "item", now + Duration::from_millis(500)),
            Err(RateDenied::Limited)
        );
        // A minute later the minute-bucket refills.
        let later = now + MINUTE;
        assert_eq!(lim.admit_fill("alpha", "item", later), Ok(()));
    }

    #[test]
    fn req_rl_002_fifth_item_fill_in_window_is_limited() {
        let mut lim = RateLimiter::new(RatePolicy::default());
        let now = Duration::from_secs(5_000);
        // Use distinct agents so the per-agent minute budget is not
        // what refuses — only the per-item window.
        for i in 0..5 {
            let agent = format!("a{i}");
            assert_eq!(lim.admit_fill(&agent, "hot", now), Ok(()));
        }
        assert_eq!(lim.admit_fill("a99", "hot", now), Err(RateDenied::Limited));
    }

    #[test]
    fn req_rl_002_fifth_consecutive_mismatch_suspends() {
        let mut lim = RateLimiter::new(RatePolicy::default());
        for _ in 0..4 {
            assert!(!lim.note_origin_mismatch("alpha"));
        }
        assert!(lim.note_origin_mismatch("alpha"));
        assert!(lim.is_suspended("alpha"));
        assert_eq!(
            lim.admit_fill("alpha", "item", Duration::from_secs(1)),
            Err(RateDenied::Suspended)
        );
        lim.unsuspend("alpha");
        assert!(!lim.is_suspended("alpha"));
        assert_eq!(
            lim.admit_fill("alpha", "item", Duration::from_secs(1)),
            Ok(())
        );
    }

    #[test]
    fn req_rl_002_non_mismatch_breaks_the_streak() {
        let mut lim = RateLimiter::new(RatePolicy::default());
        for _ in 0..4 {
            assert!(!lim.note_origin_mismatch("alpha"));
        }
        lim.note_non_mismatch("alpha");
        // Streak reset: four more do not suspend.
        for _ in 0..4 {
            assert!(!lim.note_origin_mismatch("alpha"));
        }
        assert!(!lim.is_suspended("alpha"));
    }
}
