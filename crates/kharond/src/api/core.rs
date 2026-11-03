//! Transport-independent request handling (REQ-API-002).
//!
//! SPEC §4 requires the MCP and HTTP transports to have identical
//! semantics. Both are thin adapters over this module: a transport
//! extracts the bearer token and the request parameters, calls
//! [`Broker::authenticate`] and [`Broker::dispatch`], and renders the
//! [`Outcome`] or [`ApiError`]. Parameter validation
//! ([`parse_request`], over [`parse_status_query`] and
//! [`parse_items_query`]) lives here too, so a transport cannot
//! accept a request another one refuses. HTTP is the only transport
//! today (MCP is issue #15); the contract harness in
//! `tests/req_api_002_contract.rs` runs every case against the core
//! directly and against every transport, so #15 adds one adapter
//! there and inherits the suite.
//!
//! Ordering per request (SPEC §7, REQ-AUD-003): authenticate, then the
//! lock gate ([`LockController::require_unlocked`], which enforces
//! the idle/absolute timers), then build the response, then append
//! the audit entry, then reply. An audit failure turns the reply into
//! [`ApiError::AUDIT_FAILED`]; nothing is returned that was not
//! logged. Status needs no unlock and is not audited (it is not a §7
//! event).

use std::sync::Mutex;

use serde::Serialize;
use url::Url;
use zeroize::ZeroizeOnDrop;

use super::error::{ApiError, Detail};
use super::meta::{ItemMeta, matches_origin, matches_query};
use super::token::TokenStore;
use crate::audit::{AuditLog, Entry, Event};
use crate::lock::{AuditError, Clock, LockController, SystemClock};
use crate::origin::OriginConfig;
use crate::sync::{LiveSync, Vault};

/// Longest accepted `origin` (bytes).
pub const MAX_ORIGIN_LEN: usize = 2048;
/// Longest accepted `q` (bytes).
pub const MAX_QUERY_LEN: usize = 256;

/// What the lock controller holds while unlocked, as the API sees it:
/// something with a synced vault. The daemon's is [`LiveSync`].
pub trait VaultView: ZeroizeOnDrop + Send {
    /// The in-scope items.
    fn vault(&self) -> &Vault;
}

impl VaultView for LiveSync {
    fn vault(&self) -> &Vault {
        LiveSync::vault(self)
    }
}

/// Where API audit entries go. The daemon's is the [`AuditLog`].
pub trait AuditSink: Send {
    /// Append `entry`, or fail (the request then fails closed).
    fn append(&mut self, entry: Entry) -> Result<(), AuditError>;
}

impl AuditSink for AuditLog {
    fn append(&mut self, entry: Entry) -> Result<(), AuditError> {
        AuditLog::append(self, entry).map_err(|_| AuditError)
    }
}

/// An authenticated agent. Only [`Broker::authenticate`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentId(String);

impl AgentId {
    /// The agent id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `kharon_status` / `GET /v1/status`.
    Status,
    /// `kharon_list` / `GET /v1/items?origin=`.
    List {
        /// Origin filter (REQ-API-004).
        origin: Option<String>,
    },
    /// `kharon_search` / `GET /v1/items?q=&origin=`.
    Search {
        /// Search text (non-empty).
        q: String,
        /// Origin filter (REQ-API-004).
        origin: Option<String>,
    },
}

/// SPEC §4 `Grant` as status reports it. Grants arrive with issue #15's
/// grant model; until then no grant can exist, so the type is empty
/// and `grants` is always `[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum GrantView {}

/// `GET /v1/status` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusBody {
    /// Whether the broker is locked.
    pub locked: bool,
    /// The calling agent.
    pub agent_id: String,
    /// The agent's active grants.
    pub grants: Vec<GrantView>,
}

/// A successful response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Status.
    Status(StatusBody),
    /// List or search result.
    Items(Vec<ItemMeta>),
}

impl Outcome {
    /// The JSON body.
    pub fn body(&self) -> serde_json::Value {
        let v = match self {
            Self::Status(s) => serde_json::to_value(s),
            Self::Items(items) => serde_json::to_value(items),
        };
        v.expect("invariant: API bodies serialize")
    }
}

/// The read operations, before their parameters are validated: what
/// a transport recognizes from its route (HTTP path) or tool name
/// (MCP), handed to [`parse_request`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// `kharon_status` / `GET /v1/status`.
    Status,
    /// `kharon_list` and `kharon_search` / `GET /v1/items`.
    Items,
}

/// The single entry point for parameter validation: every transport
/// decodes its parameters into `(name, value)` pairs and calls this.
pub fn parse_request<'a>(
    op: Operation,
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Request, ApiError> {
    match op {
        Operation::Status => parse_status_query(pairs),
        Operation::Items => parse_items_query(pairs),
    }
}

/// Validate status parameters: there are none, so any parameter is
/// refused rather than ignored.
pub fn parse_status_query<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Request, ApiError> {
    match pairs.into_iter().next() {
        None => Ok(Request::Status),
        Some(_) => Err(ApiError::bad_request(Detail::UnknownParameter)),
    }
}

/// Validate `/v1/items` parameters (shared by every transport).
/// `q` present → search, else list. Unknown or repeated parameters
/// are refused rather than ignored.
pub fn parse_items_query<'a>(
    pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<Request, ApiError> {
    let mut q = None;
    let mut origin = None;
    for (k, v) in pairs {
        let slot = match k {
            "q" => &mut q,
            "origin" => &mut origin,
            _ => return Err(ApiError::bad_request(Detail::UnknownParameter)),
        };
        if slot.replace(v).is_some() {
            return Err(ApiError::bad_request(Detail::DuplicateParameter));
        }
    }
    let origin = origin.map(validate_origin).transpose()?;
    match q {
        None => Ok(Request::List { origin }),
        Some(q) if q.len() > MAX_QUERY_LEN => Err(ApiError::bad_request(Detail::ParameterTooLong)),
        Some(q) if q.trim().is_empty() => Err(ApiError::bad_request(Detail::EmptyQuery)),
        Some(q) => Ok(Request::Search {
            q: q.to_owned(),
            origin,
        }),
    }
}

fn validate_origin(origin: &str) -> Result<String, ApiError> {
    if origin.len() > MAX_ORIGIN_LEN {
        return Err(ApiError::bad_request(Detail::ParameterTooLong));
    }
    match Url::parse(origin) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => {
            Ok(origin.to_owned())
        }
        _ => Err(ApiError::bad_request(Detail::InvalidOrigin)),
    }
}

/// The agent-facing half of the daemon: tokens, the lock controller
/// (and through it the session), origin policy, audit.
pub struct Broker<S: VaultView, C: Clock = SystemClock> {
    tokens: TokenStore,
    lock: Mutex<LockController<S, C>>,
    audit: Mutex<Box<dyn AuditSink>>,
    origin_cfg: OriginConfig,
}

impl<S: VaultView, C: Clock> Broker<S, C> {
    /// Assemble a broker.
    pub fn new(
        tokens: TokenStore,
        lock: LockController<S, C>,
        audit: Box<dyn AuditSink>,
        origin_cfg: OriginConfig,
    ) -> Self {
        Self {
            tokens,
            lock: Mutex::new(lock),
            audit: Mutex::new(audit),
            origin_cfg,
        }
    }

    /// The lock controller (owner unlock, sync, tests). A
    /// `std::sync::Mutex`: never hold the guard across an `.await`.
    pub fn lock_controller(&self) -> &Mutex<LockController<S, C>> {
        &self.lock
    }

    /// Verify a bearer token (REQ-API-003). One Argon2id evaluation:
    /// async transports call this from a blocking thread.
    pub fn authenticate(&self, token: &str) -> Result<AgentId, ApiError> {
        self.tokens
            .authenticate(token)
            .map(AgentId)
            .map_err(|_| ApiError::INVALID_TOKEN)
    }

    /// Run `req` for `agent`.
    pub fn dispatch(&self, agent: &AgentId, req: Request) -> Result<Outcome, ApiError> {
        match req {
            Request::Status => Ok(Outcome::Status(self.status(agent))),
            Request::List { origin } => self.items(agent, Event::List, None, origin),
            Request::Search { q, origin } => self.items(agent, Event::Search, Some(q), origin),
        }
    }

    fn status(&self, agent: &AgentId) -> StatusBody {
        let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        // Run the expiry check so an expired session reports locked.
        lock.poll();
        StatusBody {
            locked: lock.is_locked(),
            agent_id: agent.0.clone(),
            grants: Vec::new(),
        }
    }

    fn items(
        &self,
        agent: &AgentId,
        event: Event,
        q: Option<String>,
        origin: Option<String>,
    ) -> Result<Outcome, ApiError> {
        let result = {
            let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            // The gate, not `session()`: it enforces the timers. Listing
            // is not fill activity, so it does not touch the idle timer.
            lock.require_unlocked().map(|session| {
                session
                    .vault()
                    .items()
                    .filter(|i| q.as_deref().is_none_or(|q| matches_query(i, q)))
                    .filter(|i| {
                        origin
                            .as_deref()
                            .is_none_or(|o| matches_origin(i, o, &self.origin_cfg))
                    })
                    .map(ItemMeta::from_item)
                    .collect::<Vec<_>>()
            })
        };
        // Same entry whichever transport carried the request (the
        // contract test compares them). `q` is not logged.
        let mut entry = Entry::new(event).agent_id(agent.0.clone());
        if let Some(o) = &origin {
            entry = entry.origin(o.clone());
        }
        entry = match &result {
            Ok(_) => entry.result("ok"),
            Err(_) => entry.result("locked"),
        };
        self.audit
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .append(entry)
            .map_err(|_| ApiError::AUDIT_FAILED)?;
        result.map(Outcome::Items).map_err(|_| ApiError::LOCKED)
    }
}
