//! Agent tokens (REQ-API-003; SPEC §4 "Auth").
//!
//! Format: `kh_agent_<id>_<random>`, where `<id>` is the agent id from
//! `[agents.<id>]` (`[a-z0-9-]{1,64}`, so it never contains `_`) and
//! `<random>` is 32 bytes from the OS RNG, lowercase hex (256 bits).
//!
//! Only the Argon2id PHC hash of a token is stored: it is the
//! `token_hash` of the agent's config table (SPEC §9), so the config
//! file is the token store and never holds a plaintext token. The
//! token itself is shown once at creation ([`generate`]; the owner
//! CLI command that wraps it lands with the owner channel) and handled as a [`Secret`] / [`Zeroizing`] buffer after
//! that.
//!
//! Verification ([`TokenStore::authenticate`]) parses the id out of
//! the presented token, looks up that agent's hash, and runs the
//! Argon2id verify, whose final digest comparison is constant-time
//! (`password-hash`'s `Output` equality is `subtle::ConstantTimeEq`).
//! A token naming an unknown agent, or one that does not parse, is
//! verified against a decoy hash with the configured hashes'
//! parameters, so a failure costs one Argon2id evaluation whatever
//! its cause and response timing does not reveal which agent ids
//! exist. Every failure is the same [`AuthError`], with no detail.

use std::collections::BTreeMap;

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHashString, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordVerifier};
use kharon_bwcrypto::Secret;
use zeroize::Zeroizing;

use crate::config::AgentConfig;

/// Every token starts with this.
pub const TOKEN_PREFIX: &str = "kh_agent_";
/// Random bytes per token (hex-encoded: twice as many characters).
pub const TOKEN_RANDOM_BYTES: usize = 32;

/// Authentication failed. Deliberately carries nothing: the HTTP
/// layer answers 401 with a fixed body (REQ-API-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("authentication failed")]
pub struct AuthError;

/// A `token_hash` could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenStoreError {
    /// The hash is not a parseable Argon2id PHC string.
    #[error("agents.{agent}.token_hash is not a valid Argon2id PHC string")]
    InvalidHash {
        /// Agent id (a config table name, not a secret).
        agent: String,
    },
}

/// Whether `id` is a valid agent id (`[a-z0-9-]{1,64}`, the rule the
/// config loader enforces).
pub fn valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The agent id a token claims, if it is well-formed. Says nothing
/// about whether the token is valid.
pub fn claimed_agent_id(token: &str) -> Option<&str> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    let (id, random) = rest.rsplit_once('_')?;
    let random_ok = random.len() == 2 * TOKEN_RANDOM_BYTES
        && random
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    (valid_agent_id(id) && random_ok).then_some(id)
}

/// Hash a token for storage: Argon2id, default `argon2` parameters
/// (m = 19 MiB, t = 2, p = 1), random 16-byte salt.
pub fn hash_token(token: &str) -> String {
    hash_with(&Argon2::default(), token)
}

fn hash_with(argon: &Argon2<'_>, token: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    argon
        .hash_password(token.as_bytes(), &salt)
        .expect("invariant: Argon2id hashing with a generated salt cannot fail")
        .to_string()
}

/// Mint a token for `agent_id`: the token (show it once, never store
/// it) and its Argon2id PHC hash (the `token_hash` config value).
///
/// # Panics
///
/// If `agent_id` is not a valid agent id.
pub fn generate(agent_id: &str) -> (Secret<String>, String) {
    generate_with(&Argon2::default(), agent_id)
}

/// [`generate`] with explicit Argon2 parameters (tests use cheap ones).
pub fn generate_with(argon: &Argon2<'_>, agent_id: &str) -> (Secret<String>, String) {
    assert!(valid_agent_id(agent_id), "invalid agent id");
    let mut random = Zeroizing::new([0u8; TOKEN_RANDOM_BYTES]);
    OsRng.fill_bytes(random.as_mut());
    let token = Zeroizing::new(format!(
        "{TOKEN_PREFIX}{agent_id}_{}",
        Zeroizing::new(hex::encode(random.as_ref())).as_str()
    ));
    let hash = hash_with(argon, &token);
    (Secret::from(token), hash)
}

/// Agent id → stored Argon2id hash. Built from the validated config.
pub struct TokenStore {
    hashes: BTreeMap<String, PasswordHashString>,
    decoy: PasswordHashString,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenStore")
            .field("agents", &self.hashes.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl TokenStore {
    /// From `(agent id, PHC hash)` pairs. Each hash must be Argon2id.
    pub fn new<'a>(
        hashes: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, TokenStoreError> {
        let mut map = BTreeMap::new();
        for (agent, phc) in hashes {
            let invalid = || TokenStoreError::InvalidHash {
                agent: agent.to_owned(),
            };
            let parsed = PasswordHash::new(phc).map_err(|_| invalid())?;
            if parsed.algorithm != argon2::Algorithm::Argon2id.ident() || parsed.hash.is_none() {
                return Err(invalid());
            }
            // Parameters must be ones argon2 accepts, or every verify
            // would fail at request time instead of at startup.
            argon2::Params::try_from(&parsed).map_err(|_| invalid())?;
            map.insert(agent.to_owned(), parsed.serialize());
        }
        // The decoy is a hash of a fresh random value nobody knows, with
        // the parameters of a configured hash (the default ones if none
        // is), so its verify costs what a real one does.
        let params = map
            .values()
            .next()
            .and_then(|h| argon2::Params::try_from(&h.password_hash()).ok())
            .unwrap_or_default();
        let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut nonce = Zeroizing::new([0u8; TOKEN_RANDOM_BYTES]);
        OsRng.fill_bytes(nonce.as_mut());
        let decoy_hash = hash_with(&argon, &hex::encode(nonce.as_ref()));
        let decoy = PasswordHash::new(&decoy_hash)
            .expect("invariant: freshly generated PHC parses")
            .serialize();
        Ok(Self { hashes: map, decoy })
    }

    /// From the config's `[agents.*]` tables (REQ-API-003).
    pub fn from_agents(agents: &BTreeMap<String, AgentConfig>) -> Result<Self, TokenStoreError> {
        Self::new(
            agents
                .iter()
                .map(|(id, a)| (id.as_str(), a.token_hash.expose().as_str())),
        )
    }

    /// Configured agent ids.
    pub fn agents(&self) -> impl Iterator<Item = &str> {
        self.hashes.keys().map(String::as_str)
    }

    /// Verify a presented bearer token; returns the agent id it
    /// authenticates. CPU-bound (one Argon2id evaluation): async
    /// callers run it on a blocking thread.
    pub fn authenticate(&self, token: &str) -> Result<String, AuthError> {
        let claimed = claimed_agent_id(token);
        let (stored, agent) = match claimed.and_then(|id| self.hashes.get_key_value(id)) {
            Some((id, h)) => (h, Some(id)),
            None => (&self.decoy, None),
        };
        let ok = Argon2::default()
            .verify_password(token.as_bytes(), &stored.password_hash())
            .is_ok();
        match (ok, agent) {
            (true, Some(id)) => Ok(id.clone()),
            _ => Err(AuthError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cheap() -> Argon2<'static> {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(8, 1, 1, None).unwrap(),
        )
    }

    #[test]
    fn req_api_003_token_format_round_trips() {
        let (token, hash) = generate_with(&cheap(), "assistant");
        let t = token.expose_secret();
        assert!(t.starts_with("kh_agent_assistant_"));
        assert_eq!(t.len(), "kh_agent_assistant_".len() + 64);
        assert_eq!(claimed_agent_id(t), Some("assistant"));
        assert!(hash.starts_with("$argon2id$"));
        assert!(!hash.contains(t.as_str()));
        let store = TokenStore::new([("assistant", hash.as_str())]).unwrap();
        assert_eq!(store.authenticate(t).unwrap(), "assistant");
    }

    #[test]
    fn req_api_003_rejects_wrong_unknown_and_malformed_tokens() {
        let (a, ha) = generate_with(&cheap(), "agent-a");
        let (b, hb) = generate_with(&cheap(), "agent-b");
        let store = TokenStore::new([("agent-a", ha.as_str()), ("agent-b", hb.as_str())]).unwrap();
        // A's random part under B's id, and vice versa.
        let a_rand = a.expose_secret().rsplit_once('_').unwrap().1;
        let swapped = format!("kh_agent_agent-b_{a_rand}");
        assert_eq!(store.authenticate(&swapped), Err(AuthError));
        assert_eq!(store.authenticate(b.expose_secret()).unwrap(), "agent-b");
        let unknown = format!("kh_agent_nobody_{a_rand}");
        for bad in [
            "",
            "kh_agent_",
            "Bearer x",
            unknown.as_str(),
            &a.expose_secret()[..a.expose_secret().len() - 1],
            &a.expose_secret().to_uppercase(),
        ] {
            assert_eq!(store.authenticate(bad), Err(AuthError), "{bad:?}");
        }
    }

    #[test]
    fn req_api_003_store_refuses_non_argon2id_hashes() {
        for bad in [
            "plaintext",
            "$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
            "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ",
            "$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
        ] {
            assert!(TokenStore::new([("a", bad)]).is_err(), "{bad}");
        }
    }

    #[test]
    fn req_api_003_debug_shows_ids_only() {
        let (_, h) = generate_with(&cheap(), "a");
        let store = TokenStore::new([("a", h.as_str())]).unwrap();
        let dbg = format!("{store:?}");
        assert!(!dbg.contains("argon2"), "{dbg}");
    }
}
