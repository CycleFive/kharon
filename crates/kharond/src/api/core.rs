//! Transport-independent request handling (REQ-API-002).
//!
//! SPEC §4 requires the MCP and HTTP transports to have identical
//! semantics. Both are thin adapters over this module: a transport
//! extracts the bearer token and the request parameters, calls
//! [`Broker::authenticate`] and [`Broker::dispatch`], and renders the
//! [`Outcome`] or [`ApiError`]. Parameter validation
//! ([`parse_request`], over [`parse_status_query`] and
//! [`parse_items_query`]) lives here too, so a transport cannot
//! accept a request another one refuses. The transports are HTTP
//! (`super::http`, `/v1/*`) and MCP (`super::mcp`, `POST /mcp`); the
//! contract harness in `tests/req_api_002_contract.rs` runs every case
//! against the core directly and against both transports.
//!
//! Ordering per request (SPEC §7, REQ-AUD-003): authenticate, then the
//! lock gate ([`LockController::require_unlocked`], which enforces
//! the idle/absolute timers), then build the response, then append
//! the audit entry, then reply. An audit failure turns the reply into
//! [`ApiError::AUDIT_FAILED`]; nothing is returned that was not
//! logged. Status needs no unlock and is not audited (it is not a §7
//! event).
//!
//! Fills (`fill`, `fill_totp`) take the async [`Broker::fill`] instead
//! of [`Broker::dispatch`] (the browser round trip is async; the read
//! operations stay sync): authenticate, then the lock gate, then (TODO
//! #20) the grant check, then resolve the item and decrypt the values
//! into a [`FillPlan`], then the [`FillBackend`], all under one
//! wall-clock fill deadline (REQ-API-009); then zeroize the plan, then
//! append exactly one outcome entry (`fill`, `fill_totp` or
//! `fill_timeout`), then reply. A fill that reaches the browser is two
//! audited transitions (REQ-AUD-003†): a `fill_dispatch` entry is
//! appended *before* the [`FillBackend`] is called (append failure →
//! [`ApiError::AUDIT_FAILED`], no CDP write), and the outcome entry
//! after it. If the handler future is dropped in between (client
//! disconnect), a drop guard wipes the plan and appends a best-effort
//! `fill_aborted`; `kharon audit verify` flags a `fill_dispatch` that
//! has neither.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use kharon_bwcrypto::Secret;
use serde::Serialize;
use tokio::time::Instant;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::error::{ApiError, Detail};
use super::fill::{FillBackend, FillOperation, FillPolicy, FillRequest, FillResult, FillStatus};
use super::meta::{ItemMeta, matches_origin, matches_query};
use super::token::TokenStore;
use crate::audit::{AuditLog, Entry, Event};
use crate::cdp::{FieldFill, FieldKind, FillOutcome, FillPlan, LiveOrigin};
use crate::lock::{AuditError, Clock, LockController, LockEvent, SystemClock};
use crate::origin::{OriginConfig, OriginMatcher};
use crate::sync::{LiveSync, SecretField, SyncError, Vault};
use crate::totp::skew::Observation;
use crate::totp::{ClockSample, ClockSkewGate, SkewPolicy, totp_code};

/// Longest accepted `origin` (bytes).
pub const MAX_ORIGIN_LEN: usize = 2048;
/// Longest accepted `q` (bytes).
pub const MAX_QUERY_LEN: usize = 256;

/// What the lock controller holds while unlocked, as the API sees it:
/// something with a synced vault and the key to its secrets. The
/// daemon's is [`LiveSync`] (or the export loader's session).
pub trait VaultView: ZeroizeOnDrop + Send {
    /// The in-scope items.
    fn vault(&self) -> &Vault;

    /// Decrypt one secret field of one item, per fill only, into a
    /// zeroizing buffer (REQ-CRY-006).
    fn decrypt_secret(
        &self,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError>;
}

impl VaultView for LiveSync {
    fn vault(&self) -> &Vault {
        LiveSync::vault(self)
    }

    fn decrypt_secret(
        &self,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        self.session()
            .decrypt_secret(LiveSync::vault(self), item_id, field)
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

/// SPEC §4 `Grant` as status reports it. Grants arrive with issue #20's
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
    /// The agent's cached browser context (REQ-ARCH-005, #65), from the
    /// cache only: reading status never connects. `null` before the
    /// first `kharon_context` / fill, after a lock, and once the
    /// connection that owned it has ended.
    pub browser_context_id: Option<String>,
}

/// `POST /v1/context` / `kharon_context` body (REQ-ARCH-005, #65).
/// `browser_context_id` is present only on `ok`; `detail` is a fixed
/// code on `error` (`cdp_error`, `fill_unavailable`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextResult {
    /// `ok`, `timeout` or `error`.
    pub status: &'static str,
    /// The agent's `browserContextId`: open pages for the agent in it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_context_id: Option<String>,
    /// A fixed code on `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'static str>,
}

/// A successful response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Status.
    Status(StatusBody),
    /// List or search result.
    Items(Vec<ItemMeta>),
    /// `fill` / `fill_totp` result (any status, including refusals).
    Fill(FillResult),
    /// `kharon_context` result (any status).
    Context(ContextResult),
}

impl Outcome {
    /// The JSON body.
    pub fn body(&self) -> serde_json::Value {
        let v = match self {
            Self::Status(s) => serde_json::to_value(s),
            Self::Items(items) => serde_json::to_value(items),
            Self::Fill(r) => serde_json::to_value(r),
            Self::Context(r) => serde_json::to_value(r),
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
    /// `GET /v1/items`: `q` present → search, else list.
    Items,
    /// `kharon_list`: the items parameters without `q` (a `q` is an
    /// unknown parameter here, not a silent switch to search).
    List,
    /// `kharon_search`: the items parameters with `q` required.
    Search,
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
        Operation::List => {
            let pairs: Vec<_> = pairs.into_iter().collect();
            if pairs.iter().any(|(k, _)| *k == "q") {
                return Err(ApiError::bad_request(Detail::UnknownParameter));
            }
            parse_items_query(pairs)
        }
        Operation::Search => match parse_items_query(pairs)? {
            r @ Request::Search { .. } => Ok(r),
            _ => Err(ApiError::bad_request(Detail::MissingParameter)),
        },
    }
}

/// Validate a context request (`POST /v1/context` body, `kharon_context`
/// arguments; #65): there are no parameters, so the body is empty or
/// `{}`. Anything else is refused rather than ignored.
pub fn parse_context_body(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Err(_) => Err(ApiError::bad_request(Detail::InvalidJsonBody)),
        Ok(serde_json::Value::Object(m)) if m.is_empty() => Ok(()),
        Ok(serde_json::Value::Object(_)) => Err(ApiError::bad_request(Detail::UnknownParameter)),
        Ok(_) => Err(ApiError::bad_request(Detail::InvalidArguments)),
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
    audit: Arc<Mutex<Box<dyn AuditSink>>>,
    origin_cfg: OriginConfig,
    clock_skew: ClockSkewGate,
    fill_backend: Option<Arc<dyn FillBackend>>,
    fill_policy: FillPolicy,
    plan_wiped: Option<PlanWipedHook>,
}

/// Called with every resolved [`FillPlan`] after its values were
/// zeroized (tests prove the wipe; REQ-API-009).
pub type PlanWipedHook = Arc<dyn Fn(&FillPlan) + Send + Sync>;

/// A fresh broker-side request id: 128 random bits, hex. Ties a
/// `fill_dispatch` to its outcome entry (REQ-AUD-003†).
fn new_request_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Owns a resolved [`FillPlan`] for the rest of [`Broker::fill`]. On
/// drop, on every path (normal return, `?`, or the handler future being
/// dropped mid-fill), the plan's values are zeroized and the wipe hook
/// runs; if `abort_entry` is still set (dispatched, no outcome yet) it
/// is appended best effort: the request is already gone, so there is
/// nobody to fail, and a lost append leaves the orphan `fill_dispatch`
/// for the verifier.
struct DispatchGuard<'b> {
    plan: FillPlan,
    plan_wiped: Option<&'b PlanWipedHook>,
    audit: &'b Arc<Mutex<Box<dyn AuditSink>>>,
    abort_entry: Option<Entry>,
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        for f in &mut self.plan.fields {
            f.value.zeroize();
        }
        if let Some(hook) = self.plan_wiped {
            hook(&self.plan);
        }
        if let Some(mut entry) = self.abort_entry.take() {
            entry.live_origin = self.plan.live_origin.get();
            let _ = self
                .audit
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .append(entry);
        }
    }
}

/// Appends a context request's `aborted` outcome if the handler is
/// dropped between `context_open` and its outcome (best effort, like
/// `fill_aborted`).
struct ContextGuard<'b> {
    audit: &'b Mutex<Box<dyn AuditSink>>,
    abort_entry: Option<Entry>,
}

impl Drop for ContextGuard<'_> {
    fn drop(&mut self) {
        if let Some(entry) = self.abort_entry.take() {
            let _ = self
                .audit
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .append(entry);
        }
    }
}

/// Why a fill stopped before the browser.
enum Unresolved {
    /// The lock gate refused: `423 locked`, like list/search.
    Locked,
    /// A `FillResult` refusal.
    Refused(FillStatus),
}

/// Move decrypted bytes into a zeroizing `String`; non-UTF-8 is wiped
/// and refused.
fn into_text(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, FillStatus> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(FillStatus::DecryptFailed)
        }
    }
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
            audit: Arc::new(Mutex::new(audit)),
            origin_cfg,
            clock_skew: ClockSkewGate::default(),
            fill_backend: None,
            fill_policy: FillPolicy::default(),
            plan_wiped: None,
        }
    }

    /// Fill through `backend` (without one every fill is
    /// `error`/`fill_unavailable`).
    ///
    /// Also installs the lock controller's lock hook (replacing any
    /// earlier one): every lock, whatever its path, calls
    /// [`FillBackend::on_lock`], which closes the backend's CDP sessions
    /// (SPEC §8; issue #66).
    pub fn with_fill_backend(mut self, backend: Box<dyn FillBackend>) -> Self {
        let backend: Arc<dyn FillBackend> = Arc::from(backend);
        let hook = Arc::clone(&backend);
        self.lock
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .set_lock_hook(Box::new(move |_| hook.on_lock()));
        self.fill_backend = Some(backend);
        self
    }

    /// Use `[policy] fill_deadline`, `allow_default_context` and
    /// `allow_cross_origin_iframe_hosts` (default: 10 s, false, none).
    pub fn with_fill_policy(mut self, policy: FillPolicy) -> Self {
        self.fill_policy = policy;
        self
    }

    /// Observe every fill plan after its values were wiped (tests).
    pub fn with_plan_wiped_hook(mut self, hook: PlanWipedHook) -> Self {
        self.plan_wiped = Some(hook);
        self
    }

    /// The fill policy in force.
    pub fn fill_policy(&self) -> &FillPolicy {
        &self.fill_policy
    }

    /// Use `[policy] clock_skew_warn` / `clock_skew_refuse` instead of
    /// the 30 s / 90 s defaults (REQ-API-007).
    pub fn with_clock_skew_policy(mut self, policy: SkewPolicy) -> Self {
        self.clock_skew = ClockSkewGate::new(policy);
        self
    }

    /// The REQ-API-007 clock gate `fill_totp` consults.
    pub fn clock_skew(&self) -> &ClockSkewGate {
        &self.clock_skew
    }

    /// Record a server clock sample (REQ-API-007): update the gate and
    /// append the `clock_skew` audit entry if the sample warrants one.
    /// The gate is updated even if the append fails (a refusal must not
    /// depend on the log being writable); the append result is returned
    /// alongside so the caller can report it.
    pub fn observe_clock(&self, sample: ClockSample) -> (Observation, Result<(), ApiError>) {
        let obs = self.clock_skew.observe(sample);
        let appended = match obs.audit.clone() {
            Some(entry) => self
                .audit
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .append(entry)
                .map_err(|_| ApiError::AUDIT_FAILED),
            None => Ok(()),
        };
        (obs, appended)
    }

    /// The lock controller (owner unlock, sync, tests). A
    /// `std::sync::Mutex`: never hold the guard across an `.await`.
    pub fn lock_controller(&self) -> &Mutex<LockController<S, C>> {
        &self.lock
    }

    /// Append an entry to the broker's audit log (owner actions:
    /// the `export_loaded` entry of an export-mode unlock,
    /// REQ-EXP-004). Fails as [`ApiError::AUDIT_FAILED`], like every
    /// audited path (REQ-AUD-003).
    pub fn append_audit(&self, entry: Entry) -> Result<(), ApiError> {
        self.append(entry)
    }

    /// Route the lock controller's transitions into the audit log
    /// (REQ-AUD-003): `Unlocked` → `unlock`, locks → `lock` /
    /// `key_rotated` / `scope_widened` (via
    /// [`LockEvent::audit_entry`]). The daemon calls this at
    /// startup; until it is called, transitions are unaudited (the
    /// state machine's unit tests wire their own sink instead).
    /// Because the controller enforces REQ-AUD-003 fail-closed on
    /// the `Unlocked` entry, an audit failure rolls the unlock
    /// back — exactly as if the sink had been wired by hand.
    pub fn wire_lock_audit(&self) {
        let audit = Arc::clone(&self.audit);
        let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        lock.set_event_sink(Box::new(move |event: LockEvent| {
            let Some(entry) = event.audit_entry() else {
                return Ok(());
            };
            audit
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .append(entry)
                .map_err(|_| AuditError)
        }));
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
            browser_context_id: self
                .fill_backend
                .as_ref()
                .and_then(|b| b.cached_context_id(agent.as_str())),
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
            // The gate (`require_unlocked` is the only way to get
            // `&S`, #54): it enforces the timers. Listing
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
    fn append(&self, entry: Entry) -> Result<(), ApiError> {
        self.audit
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .append(entry)
            .map_err(|_| ApiError::AUDIT_FAILED)
    }

    /// Run a `fill` / `fill_totp` for `agent` (SPEC §4, REQ-API-008).
    ///
    /// `received` is when the transport received the request: the
    /// REQ-API-009 deadline (`[policy] fill_deadline`, default 10 s)
    /// runs from there over resolve and fill.
    ///
    /// Audit (REQ-AUD-003†): a resolved plan is announced by a
    /// `fill_dispatch` entry (request id, item, claimed origin, field
    /// count; no value) before the backend sees it. If that append
    /// fails the plan is wiped and the call is
    /// [`ApiError::AUDIT_FAILED`] with no CDP write. After the backend,
    /// exactly one outcome entry (`fill` / `fill_totp` / `fill_timeout`,
    /// same `request_id`, plus the `live_origin` the engine read if the
    /// fill got that far, #67) is appended; its failure is also
    /// [`ApiError::AUDIT_FAILED`]. A refusal before the browser (locked,
    /// unknown item, ...) writes only the outcome entry.
    ///
    /// On expiry the backend future is dropped (no further broker-side
    /// CDP writes), the plan is zeroized, a `fill_timeout` entry is
    /// appended, and the result is `timeout`. A `Runtime.callFunctionOn`
    /// already dispatched is not recalled: the in-page function may
    /// still fill, and submit, after the timeout reply (#46; REQ-API-009
    /// is enforced broker-side only).
    ///
    /// If this future is dropped after `fill_dispatch` (the client went
    /// away), the plan is still wiped and a `fill_aborted` entry is
    /// appended best effort. A locked broker is [`ApiError::LOCKED`], as
    /// for list/search.
    pub async fn fill(
        &self,
        agent: &AgentId,
        req: FillRequest,
        received: Instant,
    ) -> Result<Outcome, ApiError> {
        let deadline = received + self.fill_policy.deadline;
        let request_id = new_request_id();
        let event = match req.operation {
            FillOperation::Fill => Event::Fill,
            FillOperation::FillTotp => Event::FillTotp,
        };
        let base = |e: Event| {
            Entry::new(e)
                .agent_id(agent.0.clone())
                .item_id(req.item_id.clone())
                .request_id(request_id.clone())
        };
        // The live origin the engine read, if the fill got that far
        // (REQ-AUD-003†, #67); copied into the outcome entry.
        let mut live_origin = None;
        let status = match self.resolve_fill(agent, &req) {
            Err(Unresolved::Locked) => {
                self.append(base(event).result("locked"))?;
                return Err(ApiError::LOCKED);
            }
            Err(Unresolved::Refused(status)) => status,
            Ok((plan, generation)) => {
                let field_count = plan.fields.len() as u64;
                // Owns the plan from here: every way out of this arm,
                // including this future being dropped, wipes it.
                let mut guard = DispatchGuard {
                    plan,
                    plan_wiped: self.plan_wiped.as_ref(),
                    audit: &self.audit,
                    abort_entry: None,
                };
                if Instant::now() >= deadline {
                    // Expired before dispatch: no CDP write, no
                    // dispatch entry, just the `fill_timeout` outcome.
                    drop(guard);
                    FillStatus::Engine(FillOutcome::Timeout)
                } else {
                    self.append(
                        base(Event::FillDispatch)
                            .origin(req.expected_origin.clone())
                            .field_count(field_count)
                            .result("dispatched"),
                    )?;
                    guard.abort_entry = Some(
                        base(Event::FillAborted)
                            .result("aborted")
                            .detail_code("handler_dropped"),
                    );
                    let status = self
                        .run_fill(agent, &guard.plan, generation, deadline)
                        .await;
                    guard.abort_entry = None;
                    live_origin = guard.plan.live_origin.get();
                    drop(guard);
                    status
                }
            }
        };
        let entry = if status == FillStatus::Engine(FillOutcome::Timeout) {
            base(Event::FillTimeout)
                .result("timeout")
                .detail_code("deadline_expired")
        } else {
            let mut e = base(event).result(status.status());
            if let Some(d) = status.detail() {
                e = e.detail_code(d);
            }
            e
        };
        let entry = match live_origin {
            Some(o) => entry.live_origin(o),
            None => entry,
        };
        self.append(entry)?;
        Ok(Outcome::Fill(status.result()))
    }

    /// Hand `agent` its browser context id (REQ-ARCH-005, #65): connect
    /// if needed, create or return the agent's cached context.
    /// Idempotent while the connection lives; a reconnect (browser
    /// restart, lock then unlock) gives a new id.
    ///
    /// Same machinery as [`Self::fill`]: lock-gated (`423` while
    /// locked, a `context` entry with result `locked`), bounded by the
    /// fill deadline from `received`, and audited as two transitions:
    /// `context_open` (request id) is appended before any CDP I/O (a
    /// failed append is [`ApiError::AUDIT_FAILED`] with no connect), and
    /// exactly one `context` outcome entry (same request id; result
    /// `ok`, `timeout`/`deadline_expired` or `error`/`cdp_error`) before
    /// the reply. A dropped handler appends `aborted`/`handler_dropped`
    /// best effort. A refusal before the browser (no backend for the
    /// agent, expired before dispatch) writes only the outcome entry.
    /// Not fill activity: does not reset the idle timer.
    pub async fn context(&self, agent: &AgentId, received: Instant) -> Result<Outcome, ApiError> {
        let deadline = received + self.fill_policy.deadline;
        let request_id = new_request_id();
        let base = |e: Event| {
            Entry::new(e)
                .agent_id(agent.0.clone())
                .request_id(request_id.clone())
        };
        let generation = {
            let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            if lock.require_unlocked().is_err() {
                drop(lock);
                self.append(base(Event::Context).result("locked"))?;
                return Err(ApiError::LOCKED);
            }
            // Read under the gate's mutex, as for a fill (#66).
            match &self.fill_backend {
                Some(b) if b.has_agent(agent.as_str()) => Some((Arc::clone(b), b.generation())),
                _ => None,
            }
        };
        let result: Result<String, FillStatus> = match generation {
            None => Err(FillStatus::Unavailable),
            Some(_) if Instant::now() >= deadline => Err(FillStatus::Engine(FillOutcome::Timeout)),
            Some((backend, generation)) => {
                self.append(base(Event::ContextOpen).result("dispatched"))?;
                let mut guard = ContextGuard {
                    audit: &self.audit,
                    abort_entry: Some(
                        base(Event::Context)
                            .result("aborted")
                            .detail_code("handler_dropped"),
                    ),
                };
                let open = backend.context_in_generation(agent.as_str(), generation);
                let r = match tokio::time::timeout_at(deadline, open).await {
                    Ok(Ok(id)) => Ok(id),
                    Ok(Err(outcome)) => Err(FillStatus::Engine(outcome)),
                    Err(_) => Err(FillStatus::Engine(FillOutcome::Timeout)),
                };
                guard.abort_entry = None;
                r
            }
        };
        let (entry, body) = match result {
            Ok(id) => (
                base(Event::Context).result("ok"),
                ContextResult {
                    status: "ok",
                    browser_context_id: Some(id),
                    detail: None,
                },
            ),
            Err(FillStatus::Engine(FillOutcome::Timeout)) => (
                base(Event::Context)
                    .result("timeout")
                    .detail_code("deadline_expired"),
                ContextResult {
                    status: "timeout",
                    browser_context_id: None,
                    detail: None,
                },
            ),
            Err(status) => {
                // `cdp_error` or `fill_unavailable`.
                let detail = status.detail().unwrap_or("cdp_error");
                (
                    base(Event::Context).result("error").detail_code(detail),
                    ContextResult {
                        status: "error",
                        browser_context_id: None,
                        detail: Some(detail),
                    },
                )
            }
        };
        self.append(entry)?;
        Ok(Outcome::Context(body))
    }

    async fn run_fill(
        &self,
        agent: &AgentId,
        plan: &FillPlan,
        generation: u64,
        deadline: Instant,
    ) -> FillStatus {
        let Some(backend) = &self.fill_backend else {
            return FillStatus::Unavailable;
        };
        let fill = backend.fill_in_generation(
            agent.as_str(),
            plan,
            self.fill_policy.allow_default_context,
            generation,
        );
        match tokio::time::timeout_at(deadline, fill).await {
            Ok(outcome) => FillStatus::Engine(outcome),
            Err(_) => FillStatus::Engine(FillOutcome::Timeout),
        }
    }

    /// The sync half: lock gate, grant seam, item, values. Holds the
    /// lock mutex for the duration (no `.await` here). Also returns the
    /// backend's unlock generation, read under the same mutex as the
    /// gate: a lock after this point advances it (the lock hook runs
    /// under this mutex), so the backend can refuse to cache or write for
    /// this fill (issue #66).
    fn resolve_fill(
        &self,
        agent: &AgentId,
        req: &FillRequest,
    ) -> Result<(FillPlan, u64), Unresolved> {
        let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        // The fill gate first (REQ-MEM-007), then fill activity resets
        // the idle timer (REQ-MEM-004; a no-op that locks if expired).
        if lock.require_unlocked().is_err() {
            return Err(Unresolved::Locked);
        }
        lock.touch_activity();
        let session = lock.require_unlocked().map_err(|_| Unresolved::Locked)?;
        let refuse = |s| Err(Unresolved::Refused(s));

        let Ok(item) = session.vault().get(&req.item_id) else {
            return refuse(FillStatus::UnknownItem);
        };

        // TODO(#20): grant enforcement goes here, before any secret is
        // decrypted: `req.grant_id` (accepted, length-checked, not yet
        // consulted) or a standing grant for (agent, item, live origin,
        // operation) → proceed; else `pending_approval` / `denied`.
        let _ = &req.grant_id;

        let generation = match &self.fill_backend {
            Some(b) if b.has_agent(agent.as_str()) => b.generation(),
            _ => return refuse(FillStatus::Unavailable),
        };

        // Every requested kind must exist before anything is decrypted.
        for (kind, _) in &req.fields {
            let present = match kind {
                FieldKind::Username => item.username().is_some(),
                FieldKind::Password => item.has_password(),
                FieldKind::Totp => item.has_totp(),
            };
            if !present {
                return refuse(FillStatus::ItemFieldMissing);
            }
        }
        // REQ-API-007: the clock gate before the TOTP seed is decrypted.
        if req.fields.iter().any(|(k, _)| *k == FieldKind::Totp)
            && self.clock_skew.check_totp().is_err()
        {
            return refuse(FillStatus::Engine(FillOutcome::ClockSkew));
        }

        let mut fields = Vec::with_capacity(req.fields.len());
        for (kind, selector) in &req.fields {
            let value = match kind {
                FieldKind::Username => {
                    Zeroizing::new(item.username().unwrap_or_default().to_owned())
                }
                FieldKind::Password => {
                    match session.decrypt_secret(&req.item_id, SecretField::Password) {
                        Ok(b) => into_text(b).map_err(Unresolved::Refused)?,
                        Err(_) => return refuse(FillStatus::DecryptFailed),
                    }
                }
                FieldKind::Totp => {
                    let mut seed = match session.decrypt_secret(&req.item_id, SecretField::Totp) {
                        Ok(b) => into_text(b).map_err(Unresolved::Refused)?,
                        Err(_) => return refuse(FillStatus::DecryptFailed),
                    };
                    let seed = Secret::new(std::mem::take(&mut *seed));
                    totp_code(&self.clock_skew, seed, SystemTime::now())
                        .map_err(|o| Unresolved::Refused(FillStatus::Engine(o)))?
                }
            };
            fields.push(FieldFill {
                kind: *kind,
                selector: selector.clone(),
                value,
            });
        }

        let plan = FillPlan {
            target_id: req.target_id.clone(),
            fields,
            item_matchers: item
                .uris()
                .iter()
                .filter_map(|u| OriginMatcher::new(&u.uri, u.match_type).ok())
                .collect(),
            origin_cfg: self.origin_cfg.clone(),
            cross_origin_iframe_hosts: self.fill_policy.cross_origin_iframe_hosts.clone(),
            submit: req.submit,
            expected_origin: Some(req.expected_origin.clone()),
            live_origin: LiveOrigin::new(),
        };
        Ok((plan, generation))
    }
}
