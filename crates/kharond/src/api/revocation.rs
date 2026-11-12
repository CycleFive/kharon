//! Durable revoke / suspend state (REQ-REV-001, REQ-RL-002, #132).
//!
//! Revocation and suspension used to live only in the rate limiter's
//! memory: a restart re-authenticated a revoked token whose
//! `token_hash` was still in the config, and an `origin_mismatch`
//! suspension cleared the same way. No new store is kept. Every state
//! change is already in the hash-chained audit log — `token_revoke`
//! for a revoke (carrying the `token_fingerprint` of the `token_hash`
//! at revoke time), `rate_limit` / `suspended` for a suspension,
//! `rate_limit` / `unsuspended` for the owner reset — so at startup
//! the daemon folds the log it has just verified and seeds the rate
//! limiter from it (the #130 pattern: the log is the record).
//!
//! Revocation is bound to the token, not the agent id: the rebuilt
//! set holds an agent only while its *latest* `token_revoke`
//! fingerprint equals the fingerprint of the hash configured now.
//! Rotating the token — `kharon token mint`, a new `token_hash` in
//! config, a restart — therefore lifts the revocation with no
//! un-revoke operation, while the same (possibly leaked) token stays
//! refused across any number of restarts. A `token_revoke` written
//! before fingerprints existed names no token; it is honoured under
//! its agent id alone (assumption 1 on PR #132) — anything weaker
//! would quietly un-revoke agents revoked by older daemons.
//!
//! Suspension is temporal: the agent is in the rebuilt set when its
//! latest suspension event is a `suspended` with no later
//! `unsuspended`. A `panic` entry records that the daemon locked; it
//! resets nothing here. A restart starts locked regardless, panic
//! revoked every grant before locking, and neither token nor
//! suspension state is a panic effect — both rebuild as above.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::rate::RateLimiter;
use super::token::TokenStore;

/// Hex chars of the SHA-256 kept in a token fingerprint (16 bytes).
pub const TOKEN_FINGERPRINT_HEX: usize = 32;

/// First [`TOKEN_FINGERPRINT_HEX`] lowercase hex chars of SHA-256
/// over `bytes`. Shared by [`token_fingerprint`] and the passkey
/// credential-id fingerprint (#249): same 32-hex shape, different
/// input.
pub fn truncated_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(bytes)[..TOKEN_FINGERPRINT_HEX / 2])
}

/// Fingerprint of a `token_hash` PHC string: SHA-256 of the string,
/// lowercase hex, truncated to [`TOKEN_FINGERPRINT_HEX`] chars. The
/// PHC string carries a random salt and already sits in the config
/// file (operator-readable), so the fingerprint exposes nothing
/// usable; equality is all the rebuild needs.
pub fn token_fingerprint(token_hash_phc: &str) -> String {
    truncated_sha256_hex(token_hash_phc.as_bytes())
}

/// Revoke / suspend state folded from the audit log.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DurableState {
    /// Latest `token_revoke` fingerprint per agent; `None` when the
    /// entry predates fingerprints (agent-bound, see module docs).
    revocations: BTreeMap<String, Option<String>>,
    /// Agents whose latest suspension event is `suspended`.
    suspended: BTreeSet<String>,
}

impl DurableState {
    /// The durable state implied by the log at `path`, read through
    /// the broker's audit replay (`crate::audit::replay_entries`).
    pub fn from_log(path: &Path) -> std::io::Result<Self> {
        let mut state = Self::default();
        crate::audit::replay_entries(path, |entry| state.fold(entry))?;
        Ok(state)
    }

    fn fold(&mut self, entry: &crate::audit::Entry) {
        use crate::audit::Event;
        let Some(agent) = entry.agent_id.as_deref() else {
            return;
        };
        match entry.event {
            Event::TokenRevoke if entry.result.as_deref() == Some("revoked") => {
                self.revocations
                    .insert(agent.to_owned(), entry.token_fingerprint.clone());
            }
            Event::RateLimit => match entry.result.as_deref() {
                Some("suspended") => {
                    self.suspended.insert(agent.to_owned());
                }
                Some("unsuspended") => {
                    self.suspended.remove(agent);
                }
                _ => {}
            },
            _ => {}
        }
    }

    /// Agents whose revocation binds under the currently configured
    /// hashes: the latest `token_revoke` either predates fingerprints
    /// (agent-bound) or its fingerprint equals the configured hash's.
    pub fn revoked_agents<'a>(&'a self, tokens: &TokenStore) -> impl Iterator<Item = &'a str> {
        self.revocations
            .iter()
            .filter_map(move |(agent, recorded)| {
                let still_bound = match recorded {
                    None => true,
                    Some(fp) => tokens.token_fingerprint(agent).as_deref() == Some(fp.as_str()),
                };
                still_bound.then_some(agent.as_str())
            })
    }

    /// Agents suspended at the end of the log.
    pub fn suspended_agents(&self) -> impl Iterator<Item = &str> {
        self.suspended.iter().map(String::as_str)
    }

    /// Seed `limiter` with this state (assumption 2 on PR #132:
    /// revoked agents are marked revoked, not suspended — the
    /// revocation marker is itself durable now, and revocation
    /// already implies suspension at request time).
    pub fn apply(&self, limiter: &mut RateLimiter, tokens: &TokenStore) {
        for agent in self.suspended_agents() {
            limiter.suspend(agent);
        }
        for agent in self.revoked_agents(tokens) {
            limiter.mark_revoked(agent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::token::{ParamFloor, generate_with};
    use super::*;
    use crate::audit::{AuditConfig, AuditLog, Entry, Event, NullCheckpointSink};

    fn cheap_argon() -> argon2::Argon2<'static> {
        argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(8, 1, 1, None).unwrap(),
        )
    }

    fn write_log(entries: Vec<Entry>) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let mut log = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        for e in entries {
            log.append(e).unwrap();
        }
        drop(log);
        let path = dir.path().join("audit.jsonl");
        (dir, path)
    }

    const TEST_FLOOR: ParamFloor = ParamFloor {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };

    fn store(pairs: &[(&str, &str)]) -> TokenStore {
        TokenStore::with_floor(pairs.iter().copied(), &TEST_FLOOR).unwrap()
    }

    #[test]
    fn req_rev_132_fingerprint_is_stable_short_and_hash_sensitive() {
        let phc = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";
        let fp = token_fingerprint(phc);
        assert_eq!(fp.len(), TOKEN_FINGERPRINT_HEX);
        assert_eq!(fp, truncated_sha256_hex(phc.as_bytes()));
        assert_eq!(
            fp,
            token_fingerprint("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA")
        );
        assert_ne!(
            fp,
            token_fingerprint("$argon2id$v=19$m=19456,t=2,p=1$b3RoZXI$aGFzaA")
        );
    }

    #[test]
    fn req_rev_132_revoke_binds_the_recorded_token_only() {
        let (_t1, h1) = generate_with(&cheap_argon(), "alpha");
        let (_t2, h2) = generate_with(&cheap_argon(), "alpha");
        let (_dir, path) = write_log(vec![
            Entry::new(Event::TokenRevoke)
                .agent_id("alpha")
                .result("revoked")
                .token_fingerprint(token_fingerprint(&h1)),
        ]);
        let state = DurableState::from_log(&path).unwrap();
        // Same hash configured: still revoked.
        let same = store(&[("alpha", h1.as_str())]);
        assert_eq!(state.revoked_agents(&same).collect::<Vec<_>>(), ["alpha"]);
        // Rotated hash: the revocation no longer binds.
        let rotated = store(&[("alpha", h2.as_str())]);
        assert!(state.revoked_agents(&rotated).next().is_none());
        // Agent dropped from config: nothing to bind.
        let absent = store(&[]);
        assert!(state.revoked_agents(&absent).next().is_none());
    }

    #[test]
    fn req_rev_132_pre_fingerprint_revoke_is_agent_bound() {
        let (_t1, h1) = generate_with(&cheap_argon(), "alpha");
        let (_t2, h2) = generate_with(&cheap_argon(), "alpha");
        let (_dir, path) = write_log(vec![
            Entry::new(Event::TokenRevoke)
                .agent_id("alpha")
                .result("revoked"),
        ]);
        let state = DurableState::from_log(&path).unwrap();
        for hash in [h1.as_str(), h2.as_str()] {
            let tokens = store(&[("alpha", hash)]);
            assert_eq!(
                state.revoked_agents(&tokens).collect::<Vec<_>>(),
                ["alpha"],
                "a revoke from before fingerprints binds the agent under any hash"
            );
        }
    }

    #[test]
    fn req_rev_132_latest_revoke_wins() {
        let (_t1, h1) = generate_with(&cheap_argon(), "alpha");
        let (_t2, h2) = generate_with(&cheap_argon(), "alpha");
        let (_dir, path) = write_log(vec![
            Entry::new(Event::TokenRevoke)
                .agent_id("alpha")
                .result("revoked")
                .token_fingerprint(token_fingerprint(&h1)),
            Entry::new(Event::TokenRevoke)
                .agent_id("alpha")
                .result("revoked")
                .token_fingerprint(token_fingerprint(&h2)),
        ]);
        let state = DurableState::from_log(&path).unwrap();
        let old = store(&[("alpha", h1.as_str())]);
        assert!(state.revoked_agents(&old).next().is_none());
        let new = store(&[("alpha", h2.as_str())]);
        assert_eq!(state.revoked_agents(&new).collect::<Vec<_>>(), ["alpha"]);
    }

    #[test]
    fn req_rev_132_suspension_is_the_latest_word() {
        // Suspend, unsuspend, suspend again: suspended.
        let (_d1, p1) = write_log(vec![
            Entry::new(Event::RateLimit)
                .agent_id("alpha")
                .result("suspended"),
            Entry::new(Event::RateLimit)
                .agent_id("alpha")
                .result("unsuspended"),
            Entry::new(Event::RateLimit)
                .agent_id("beta")
                .result("suspended"),
            Entry::new(Event::RateLimit)
                .agent_id("alpha")
                .result("suspended"),
        ]);
        let state = DurableState::from_log(&p1).unwrap();
        assert_eq!(
            state.suspended_agents().collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        // A mid-log unsuspended beats an earlier suspended.
        let (_d2, p2) = write_log(vec![
            Entry::new(Event::RateLimit)
                .agent_id("alpha")
                .result("suspended"),
            Entry::new(Event::RateLimit)
                .agent_id("alpha")
                .result("unsuspended"),
        ]);
        let state = DurableState::from_log(&p2).unwrap();
        assert!(state.suspended_agents().next().is_none());
    }

    #[test]
    fn req_rev_132_missing_log_is_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let state = DurableState::from_log(&dir.path().join("nope.jsonl")).unwrap();
        let (_t, h) = generate_with(&cheap_argon(), "alpha");
        let tokens = store(&[("alpha", h.as_str())]);
        assert!(state.revoked_agents(&tokens).next().is_none());
        assert!(state.suspended_agents().next().is_none());
    }
}
