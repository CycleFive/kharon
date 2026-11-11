//! Agent tokens (REQ-API-003; SPEC §4 "Auth").
//!
//! Format: `kh_agent_<id>_<random>`, where `<id>` is the agent id from
//! `[agents.<id>]` (`[a-z0-9-]{1,64}`, so it never contains `_`) and
//! `<random>` is 32 bytes from the OS RNG, lowercase hex (256 bits).
//!
//! Only the Argon2id PHC hash of a token is stored: it is the
//! `token_hash` of the agent's config table (SPEC §9), so the config
//! file is the token store and never holds a plaintext token. The
//! token itself is shown once at creation ([`generate`], wrapped by
//! `kharon token mint`) and handled as a [`Secret`] / [`Zeroizing`]
//! buffer after that. Minting is out of band: the command does not
//! talk to the daemon, and the daemon does not append `token_create`
//! (SPEC §7).
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
//!
//! Parameter floor: a stored hash must cost at least what
//! `Argon2::default()` costs ([`ParamFloor::PRODUCTION`]: m = 19456 KiB,
//! t = 2, p = 1). A weaker `token_hash` is refused when the config is
//! loaded (REQ-DEP-003, `token_hash_weak_params`) and again by
//! [`TokenStore::new`] / [`TokenStore::from_agents`], so the daemon
//! never serves against a cheaply brute-forceable hash.
//! [`TokenStore::with_floor`] takes an explicit floor; only tests use a
//! lower one (debug-build Argon2id at the production cost is slow).

use std::collections::{BTreeMap, BTreeSet};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHashString, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordVerifier};
use kharon_bwcrypto::Secret;
use zeroize::Zeroizing;

use crate::config::AgentConfig;

/// Every agent API token starts with this.
pub const TOKEN_PREFIX: &str = "kh_agent_";
/// Every connector tunnel credential starts with this. Distinct from
/// [`TOKEN_PREFIX`] so a tunnel token is not an agent API token and the
/// connector refuses to load one (REQ-ARCH-001).
pub const TUNNEL_PREFIX: &str = "kh_tunnel_";
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
    /// The hash's Argon2 parameters are below the floor.
    #[error(
        "agents.{agent}.token_hash Argon2id parameters are below the minimum (m >= {m_cost} KiB, t >= {t_cost}, p >= {p_cost})"
    )]
    WeakParams {
        /// Agent id.
        agent: String,
        /// Floor memory cost (KiB).
        m_cost: u32,
        /// Floor time cost.
        t_cost: u32,
        /// Floor parallelism.
        p_cost: u32,
    },
    /// An agent's tool allow-list names a tool that does not exist.
    #[error("agents.{agent}.tools names an unknown tool '{tool}'")]
    UnknownTool {
        /// Agent id.
        agent: String,
        /// The offending tool name.
        tool: String,
    },
}

/// Minimum Argon2id cost a stored `token_hash` must have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamFloor {
    /// Memory cost, KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl ParamFloor {
    /// What `Argon2::default()` produces (OWASP's minimum Argon2id
    /// profile): m = 19456 KiB, t = 2, p = 1. The daemon's floor.
    pub const PRODUCTION: Self = Self {
        m_cost: argon2::Params::DEFAULT_M_COST,
        t_cost: argon2::Params::DEFAULT_T_COST,
        p_cost: argon2::Params::DEFAULT_P_COST,
    };

    fn admits(&self, p: &argon2::Params) -> bool {
        p.m_cost() >= self.m_cost && p.t_cost() >= self.t_cost && p.p_cost() >= self.p_cost
    }
}

/// Why a `token_hash` is unusable, without the agent id (the config
/// loader and [`TokenStore`] attach their own context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashProblem {
    /// Not a parseable Argon2id PHC string with usable parameters.
    Invalid,
    /// Parameters below the floor.
    WeakParams,
}

/// Check one stored hash: Argon2id, parseable, parameters argon2
/// accepts and at least `floor`. Cheap (no hashing).
pub fn check_token_hash(phc: &str, floor: &ParamFloor) -> Result<(), HashProblem> {
    let parsed = PasswordHash::new(phc).map_err(|_| HashProblem::Invalid)?;
    if parsed.algorithm != argon2::Algorithm::Argon2id.ident() || parsed.hash.is_none() {
        return Err(HashProblem::Invalid);
    }
    // Parameters must be ones argon2 accepts, or every verify would
    // fail at request time instead of at startup.
    let params = argon2::Params::try_from(&parsed).map_err(|_| HashProblem::Invalid)?;
    if !floor.admits(&params) {
        return Err(HashProblem::WeakParams);
    }
    Ok(())
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
    claimed_id(token, TOKEN_PREFIX)
}

/// The agent id a tunnel credential claims, if it is well-formed.
pub fn claimed_tunnel_agent_id(token: &str) -> Option<&str> {
    claimed_id(token, TUNNEL_PREFIX)
}

fn claimed_id<'a>(token: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = token.strip_prefix(prefix)?;
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
    generate_prefixed(argon, TOKEN_PREFIX, agent_id)
}

/// Mint a tunnel credential (`kh_tunnel_<id>_<random>`) and its Argon2id
/// hash (the `connector_token_hash` config value). Not an agent API token.
pub fn generate_tunnel(agent_id: &str) -> (Secret<String>, String) {
    generate_prefixed(&Argon2::default(), TUNNEL_PREFIX, agent_id)
}

/// [`generate_tunnel`] with explicit Argon2 parameters (tests use cheap ones).
pub fn generate_tunnel_with(argon: &Argon2<'_>, agent_id: &str) -> (Secret<String>, String) {
    generate_prefixed(argon, TUNNEL_PREFIX, agent_id)
}

fn generate_prefixed(argon: &Argon2<'_>, prefix: &str, agent_id: &str) -> (Secret<String>, String) {
    assert!(valid_agent_id(agent_id), "invalid agent id");
    let mut random = Zeroizing::new([0u8; TOKEN_RANDOM_BYTES]);
    OsRng.fill_bytes(random.as_mut());
    let token = Zeroizing::new(format!(
        "{prefix}{agent_id}_{}",
        Zeroizing::new(hex::encode(random.as_ref())).as_str()
    ));
    let hash = hash_with(argon, &token);
    (Secret::from(token), hash)
}

/// Agent id → stored Argon2id hash. Built from the validated config.
pub struct TokenStore {
    hashes: BTreeMap<String, PasswordHashString>,
    decoy: PasswordHashString,
    /// `kh_agent_` or `kh_tunnel_`. A token with the other prefix never
    /// verifies against this store.
    prefix: &'static str,
    /// Per-agent tool allow-lists (#200): only restricted agents are
    /// present; an absent agent may call every tool. Bound to the
    /// agent identity the token authenticates as — a token cannot act
    /// as another agent, so it cannot borrow another's list.
    allow: BTreeMap<String, BTreeSet<String>>,
}

impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenStore")
            .field("agents", &self.hashes.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl TokenStore {
    /// From `(agent id, PHC hash)` pairs. Each hash must be Argon2id
    /// at or above [`ParamFloor::PRODUCTION`].
    pub fn new<'a>(
        hashes: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, TokenStoreError> {
        Self::with_floor_and_prefix(hashes, &ParamFloor::PRODUCTION, TOKEN_PREFIX)
    }

    /// [`TokenStore::new`] with an explicit parameter floor. The daemon
    /// always uses [`ParamFloor::PRODUCTION`] (via [`TokenStore::new`] /
    /// [`TokenStore::from_agents`]); a lower floor is for tests.
    pub fn with_floor<'a>(
        hashes: impl IntoIterator<Item = (&'a str, &'a str)>,
        floor: &ParamFloor,
    ) -> Result<Self, TokenStoreError> {
        Self::with_floor_and_prefix(hashes, floor, TOKEN_PREFIX)
    }

    /// [`with_floor`] for a chosen token prefix.
    pub fn with_floor_and_prefix<'a>(
        hashes: impl IntoIterator<Item = (&'a str, &'a str)>,
        floor: &ParamFloor,
        prefix: &'static str,
    ) -> Result<Self, TokenStoreError> {
        let mut map = BTreeMap::new();
        for (agent, phc) in hashes {
            check_token_hash(phc, floor).map_err(|p| match p {
                HashProblem::Invalid => TokenStoreError::InvalidHash {
                    agent: agent.to_owned(),
                },
                HashProblem::WeakParams => TokenStoreError::WeakParams {
                    agent: agent.to_owned(),
                    m_cost: floor.m_cost,
                    t_cost: floor.t_cost,
                    p_cost: floor.p_cost,
                },
            })?;
            let parsed = PasswordHash::new(phc).expect("invariant: checked above");
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
        Ok(Self {
            hashes: map,
            decoy,
            prefix,
            allow: BTreeMap::new(),
        })
    }

    /// From the config's `[agents.*]` tables (REQ-API-003), at the
    /// production floor. `valid_tools` is the tool registry's name
    /// set: an agent's `tools` allow-list may only name those
    /// (#200). An agent without `tools` is unrestricted.
    pub fn from_agents(
        agents: &BTreeMap<String, AgentConfig>,
        valid_tools: &[&str],
    ) -> Result<Self, TokenStoreError> {
        let store = Self::new(
            agents
                .iter()
                .map(|(id, a)| (id.as_str(), a.token_hash.expose().as_str())),
        )?;
        store.with_allow_lists(
            agents
                .iter()
                .map(|(id, a)| (id.as_str(), a.tools.as_deref())),
            valid_tools,
        )
    }

    /// Attach per-agent tool allow-lists (#200). An entry of `None`
    /// leaves the agent unrestricted; `Some(names)` restricts it to
    /// exactly those tools (an empty list: none). Every name must be
    /// in `valid_tools`, so a typo in config fails at startup instead
    /// of silently widening or narrowing access at request time.
    pub fn with_allow_lists<'a>(
        mut self,
        lists: impl IntoIterator<Item = (&'a str, Option<&'a [String]>)>,
        valid_tools: &[&str],
    ) -> Result<Self, TokenStoreError> {
        for (agent, list) in lists {
            let Some(names) = list else { continue };
            let mut set = BTreeSet::new();
            for name in names {
                if !valid_tools.contains(&name.as_str()) {
                    return Err(TokenStoreError::UnknownTool {
                        agent: agent.to_owned(),
                        tool: name.clone(),
                    });
                }
                set.insert(name.clone());
            }
            self.allow.insert(agent.to_owned(), set);
        }
        Ok(self)
    }

    /// Whether `agent`'s token may call `tool` (#200). Agents with
    /// no allow-list may call every tool. Read fresh on every call:
    /// there is no cache, so a rebuilt store (or an owner's revoke,
    /// which is checked separately in `Broker::authenticate`) takes
    /// effect on the very next request.
    pub fn allows(&self, agent: &str, tool: &str) -> bool {
        match self.allow.get(agent) {
            None => true,
            Some(set) => set.contains(tool),
        }
    }

    /// Tunnel credentials for agents with `via = agent_connector`.
    pub fn from_connector_agents(
        agents: &BTreeMap<String, AgentConfig>,
    ) -> Result<Self, TokenStoreError> {
        Self::with_floor_and_prefix(
            agents.iter().filter_map(|(id, a)| {
                a.connector_token_hash
                    .as_ref()
                    .map(|h| (id.as_str(), h.expose().as_str()))
            }),
            &ParamFloor::PRODUCTION,
            TUNNEL_PREFIX,
        )
    }

    /// Configured agent ids.
    pub fn agents(&self) -> impl Iterator<Item = &str> {
        self.hashes.keys().map(String::as_str)
    }

    /// The `token_hash` fingerprint of `agent`'s configured hash
    /// (REQ-REV-001, #132): what the startup rebuild compares a
    /// `token_revoke` entry's recorded fingerprint against. `None`
    /// for an agent this store does not configure.
    pub fn token_fingerprint(&self, agent: &str) -> Option<String> {
        self.hashes
            .get(agent)
            .map(|h| super::revocation::token_fingerprint(h.as_str()))
    }

    /// Verify a presented bearer token; returns the agent id it
    /// authenticates. CPU-bound (one Argon2id evaluation): async
    /// callers run it on a blocking thread.
    pub fn authenticate(&self, token: &str) -> Result<String, AuthError> {
        let claimed = claimed_id(token, self.prefix);
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

    /// Verify `token` as the tunnel credential for exactly `agent_id`.
    /// A token whose prefix or claimed id does not match still costs one
    /// Argon2id evaluation (the decoy), and the error carries no detail.
    pub fn authenticate_for(&self, agent_id: &str, token: &str) -> Result<(), AuthError> {
        match self.authenticate(token) {
            Ok(id) if id == agent_id => Ok(()),
            _ => Err(AuthError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOOLS: [&str; 3] = ["kharon_status", "kharon_list", "kharon_fill"];

    fn store_with(list: Option<Vec<String>>) -> Result<TokenStore, TokenStoreError> {
        let (_tok, hash) = generate_with(&cheap(), "alpha");
        TokenStore::with_floor([("alpha", hash.as_str())], &TEST_FLOOR)?
            .with_allow_lists([("alpha", list.as_deref())], &TOOLS)
    }

    #[test]
    fn allow_list_restricts_and_absence_does_not() {
        let store = store_with(Some(vec!["kharon_status".to_owned()])).unwrap();
        assert!(store.allows("alpha", "kharon_status"));
        assert!(!store.allows("alpha", "kharon_fill"));
        assert!(
            store.allows("beta", "kharon_fill"),
            "no list, no restriction"
        );

        let store = store_with(None).unwrap();
        assert!(store.allows("alpha", "kharon_fill"), "None = unrestricted");

        let store = store_with(Some(vec![])).unwrap();
        assert!(!store.allows("alpha", "kharon_status"), "empty = none");
    }

    #[test]
    fn allow_list_rejects_unknown_tool_names() {
        let err = store_with(Some(vec!["kharon_fly".to_owned()])).unwrap_err();
        assert_eq!(
            err,
            TokenStoreError::UnknownTool {
                agent: "alpha".to_owned(),
                tool: "kharon_fly".to_owned(),
            }
        );
    }

    fn cheap() -> Argon2<'static> {
        Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(8, 1, 1, None).unwrap(),
        )
    }

    /// The floor the unit tests' cheap hashes clear.
    const TEST_FLOOR: ParamFloor = ParamFloor {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };

    /// `generate` (not the cheap test hasher) at [`ParamFloor::PRODUCTION`]:
    /// the PHC clears the floor, and [`TokenStore`] verifies the token.
    #[test]
    fn req_api_003_generate_round_trip_at_production_floor() {
        let (token, hash) = generate("assistant");
        let presented = token.expose_secret();
        assert_eq!(claimed_agent_id(presented), Some("assistant"));
        assert!(!hash.contains(presented.as_str()));
        check_token_hash(&hash, &ParamFloor::PRODUCTION).unwrap();
        let parsed = PasswordHash::new(&hash).unwrap();
        let params = argon2::Params::try_from(&parsed).unwrap();
        assert_eq!(
            (params.m_cost(), params.t_cost(), params.p_cost()),
            (
                ParamFloor::PRODUCTION.m_cost,
                ParamFloor::PRODUCTION.t_cost,
                ParamFloor::PRODUCTION.p_cost,
            ),
            "{hash}"
        );
        let store = TokenStore::new([("assistant", hash.as_str())]).unwrap();
        assert_eq!(store.authenticate(presented).unwrap(), "assistant");
        let mut wrong = presented.clone();
        let last = wrong.pop().unwrap();
        wrong.push(if last == 'a' { 'b' } else { 'a' });
        assert!(store.authenticate(&wrong).is_err());
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
        let store = TokenStore::with_floor([("assistant", hash.as_str())], &TEST_FLOOR).unwrap();
        assert_eq!(store.authenticate(t).unwrap(), "assistant");
    }

    #[test]
    fn req_arch_002_tunnel_credential_is_not_an_agent_token() {
        let (tunnel, hash) = generate_tunnel_with(&cheap(), "assistant");
        let presented = tunnel.expose_secret();
        assert!(presented.starts_with("kh_tunnel_assistant_"));
        assert_eq!(claimed_tunnel_agent_id(presented), Some("assistant"));
        assert_eq!(claimed_agent_id(presented), None);
        let api = TokenStore::with_floor([("assistant", hash.as_str())], &TEST_FLOOR).unwrap();
        assert!(api.authenticate(presented).is_err());
        let connector = TokenStore::with_floor_and_prefix(
            [("assistant", hash.as_str())],
            &TEST_FLOOR,
            TUNNEL_PREFIX,
        )
        .unwrap();
        assert!(connector.authenticate_for("assistant", presented).is_ok());
        assert!(connector.authenticate_for("other", presented).is_err());
        let (agent_tok, agent_hash) = generate_with(&cheap(), "assistant");
        let confused = TokenStore::with_floor_and_prefix(
            [("assistant", agent_hash.as_str())],
            &TEST_FLOOR,
            TUNNEL_PREFIX,
        )
        .unwrap();
        assert!(
            confused
                .authenticate_for("assistant", agent_tok.expose_secret())
                .is_err()
        );
    }

    #[test]
    fn req_api_003_rejects_wrong_unknown_and_malformed_tokens() {
        let (a, ha) = generate_with(&cheap(), "agent-a");
        let (b, hb) = generate_with(&cheap(), "agent-b");
        let store = TokenStore::with_floor(
            [("agent-a", ha.as_str()), ("agent-b", hb.as_str())],
            &TEST_FLOOR,
        )
        .unwrap();
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
            assert_eq!(
                TokenStore::with_floor([("a", bad)], &TEST_FLOOR).unwrap_err(),
                TokenStoreError::InvalidHash { agent: "a".into() },
                "{bad}"
            );
        }
    }

    #[test]
    fn req_api_003_debug_shows_ids_only() {
        let (_, h) = generate_with(&cheap(), "a");
        let store = TokenStore::with_floor([("a", h.as_str())], &TEST_FLOOR).unwrap();
        let dbg = format!("{store:?}");
        assert!(!dbg.contains("argon2"), "{dbg}");
    }

    #[test]
    fn req_api_003_production_floor_matches_argon2_default() {
        let d = argon2::Params::default();
        assert_eq!(
            ParamFloor::PRODUCTION,
            ParamFloor {
                m_cost: d.m_cost(),
                t_cost: d.t_cost(),
                p_cost: d.p_cost(),
            }
        );
        assert_eq!(
            (d.m_cost(), d.t_cost(), d.p_cost()),
            (19456, 2, 1),
            "SPEC floor"
        );
    }

    #[test]
    fn req_api_003_weak_params_refused_at_production_floor() {
        // Hash strings only: `check_token_hash` never hashes, so these
        // need no real digest computation.
        let salt = "c2FsdHNhbHQ";
        let out = "aGFzaGhhc2hoYXNoaGFzaA";
        for (params, ok) in [
            ("m=19456,t=2,p=1", true),
            ("m=65536,t=3,p=4", true),
            ("m=19455,t=2,p=1", false),
            ("m=19456,t=1,p=1", false),
            ("m=8,t=1,p=1", false),
            ("m=4096,t=3,p=1", false),
        ] {
            let phc = format!("$argon2id$v=19${params}${salt}${out}");
            let got = check_token_hash(&phc, &ParamFloor::PRODUCTION);
            assert_eq!(got.is_ok(), ok, "{params}");
            if !ok {
                // (Accepted rows are not built into a store: that
                // computes a decoy hash at the production cost.)
                assert_eq!(got, Err(HashProblem::WeakParams), "{params}");
                assert!(
                    matches!(
                        TokenStore::new([("a", phc.as_str())]),
                        Err(TokenStoreError::WeakParams { ref agent, .. }) if agent == "a"
                    ),
                    "{params}"
                );
            }
        }
        // A cheap generated hash is refused by the production store.
        let (_, cheap_hash) = generate_with(&cheap(), "a");
        assert!(matches!(
            TokenStore::new([("a", cheap_hash.as_str())]),
            Err(TokenStoreError::WeakParams { .. })
        ));
    }
}
