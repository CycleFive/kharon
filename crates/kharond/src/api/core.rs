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
//! operations stay sync): authenticate, then the lock gate, then the
//! SPEC §8 fill-time re-sync of a stale vault ([`FillSync`]), then
//! resolve the item and — before any secret is decrypted — the grant
//! check (SPEC §5, REQ-APR-001/002; [`super::grant`]): a matching live
//! grant is consumed and the fill proceeds; an explicitly named grant
//! that fails its terms is `denied`; no grant at all makes a
//! [`GrantRequest`](super::grant::GrantRequest) from the live origin
//! the backend observes (REQ-APR-007) and reports `pending_approval`
//! (or `origin_mismatch`, when the tab is not where the agent
//! claimed). An admitted fill decrypts the values into a
//! [`FillPlan`], then the [`FillBackend`], all under one
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

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use kharon_bwcrypto::Secret;
use schemars::JsonSchema;
use serde::Serialize;
use tokio::time::Instant;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::approval::{ApprovalAction, ApprovalTokenStore, TokenGone};
use super::error::{ApiError, Detail};
use super::fill::{FillBackend, FillOperation, FillPolicy, FillRequest, FillResult, FillStatus};
use super::grant::{
    Channel, Grant, GrantAction, GrantError, GrantPolicy, GrantRequest, GrantRequestArgs,
    GrantRequestBody, GrantScope, GrantStore, GrantTerms, GrantView, RequestState,
};
use super::meta::{ItemMeta, matches_origin, matches_query};
use super::rate::{RateDenied, RateLimiter, RatePolicy};
use super::rollback::RollbackGuard;
use super::token::TokenStore;
use crate::audit::{AuditLog, Entry, Event};
use crate::cdp::{FieldFill, FieldKind, FillOutcome, FillPlan, LiveOrigin};
use crate::lock::{AuditError, Clock, LockController, LockEvent, LockReason, SystemClock};
use crate::origin::{OriginConfig, OriginMatcher};
use crate::sync::wire::SyncResponse;
use crate::sync::{LiveSync, SecretField, SyncError, SyncOutcome, Vault};
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

    /// SPEC §8: whether a fill must re-sync first (the vault is older
    /// than [`crate::sync::MAX_SYNC_INTERVAL`] at `now`). A session
    /// that never re-syncs (an export snapshot) is never stale.
    fn is_stale(&self, _now: Instant) -> bool {
        false
    }

    /// Apply a `/api/sync` payload fetched by the broker's
    /// [`FillSync`] (fill-time re-sync, SPEC §8). Only called when
    /// [`Self::is_stale`] said so; the default never is.
    fn apply_sync(&mut self, _sync: &SyncResponse) -> Result<SyncOutcome, SyncError> {
        Ok(SyncOutcome::Synced)
    }
}

/// A boxed fill-time `/api/sync` fetch.
pub type SyncFetch<'a> = Pin<Box<dyn Future<Output = Result<SyncResponse, SyncError>> + Send + 'a>>;

/// Where the fill path fetches a fresh `/api/sync` when the vault is
/// stale (SPEC §8, issue #100). The fetch runs outside the lock
/// controller's mutex; only the CPU-only [`VaultView::apply_sync`]
/// runs under it, as for the background sync.
pub trait FillSync: Send + Sync {
    /// Fetch one full `/api/sync` payload.
    fn fetch(&self) -> SyncFetch<'_>;
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

    fn is_stale(&self, now: Instant) -> bool {
        LiveSync::is_stale(self, now)
    }

    fn apply_sync(&mut self, sync: &SyncResponse) -> Result<SyncOutcome, SyncError> {
        self.apply(sync)
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

/// `GET /v1/status` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
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
    /// `kharon_request_grant` result (any state, including refusals).
    GrantRequest(GrantRequestBody),
}

impl Outcome {
    /// The JSON body.
    pub fn body(&self) -> serde_json::Value {
        let v = match self {
            Self::Status(s) => serde_json::to_value(s),
            Self::Items(items) => serde_json::to_value(items),
            Self::Fill(r) => serde_json::to_value(r),
            Self::Context(r) => serde_json::to_value(r),
            Self::GrantRequest(r) => serde_json::to_value(r),
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

pub(crate) fn validate_origin(origin: &str) -> Result<String, ApiError> {
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
    fill_sync: Option<Arc<dyn FillSync>>,
    /// The grant model (SPEC §5, #20): grants and requests, guarded
    /// separately from the session so owner operations never hold
    /// the lock controller.
    grants: Mutex<GrantStore>,
    /// Time source for grant TTLs and the request timeout: the
    /// broker's injected clock in tests, [`SystemClock`] in the
    /// daemon (whose lock controller runs on the same clock).
    grant_clock: Arc<dyn Clock>,
    /// One-time ntfy approval tokens (REQ-APR-004, #21): a pair is
    /// minted for every pending grant request when it is created.
    approval_tokens: Mutex<ApprovalTokenStore>,
    /// Rate limits, suspension, and agent revocation (REQ-RL-*,
    /// REQ-REV-001). Separate from the lock controller so owner
    /// revoke/panic never needs the session.
    rates: Mutex<RateLimiter>,
    /// Sync rollback high-water marks since unlock (REQ-REV-004).
    rollback: Mutex<RollbackGuard>,
}

/// Called with every resolved [`FillPlan`] after its values were
/// zeroized (tests prove the wipe; REQ-API-009).
pub type PlanWipedHook = Arc<dyn Fn(&FillPlan) + Send + Sync>;

/// A fresh broker-side request id: 128 random bits, hex. Ties a
/// `fill_dispatch` to its outcome entry (REQ-AUD-003†).
fn new_request_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// The grant action of a fill operation (SPEC §5's `actions`).
fn grant_action(op: FillOperation) -> GrantAction {
    match op {
        FillOperation::Fill => GrantAction::Fill,
        FillOperation::FillTotp => GrantAction::Totp,
    }
}

/// The item an audit entry names for a grant: the item of an
/// item-scoped grant. A collection grant names no single item.
fn grant_item_id(grant: &Grant) -> Option<String> {
    match &grant.scope {
        GrantScope::Item(id) => Some(id.clone()),
        GrantScope::Collection(_) => None,
    }
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
    /// REQ-APR-001: the item exists and a browser is wired, but no
    /// live grant matches. The async half of [`Broker::fill`] makes
    /// the grant request (it needs the backend's live-origin
    /// observation, which is a browser round trip).
    NeedsApproval,
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
            fill_sync: None,
            grants: Mutex::new(GrantStore::new(false)),
            grant_clock: Arc::new(SystemClock),
            approval_tokens: Mutex::new(ApprovalTokenStore::new()),
            rates: Mutex::new(RateLimiter::new(RatePolicy::default())),
            rollback: Mutex::new(RollbackGuard::new()),
        }
    }

    /// Use `clock` for grant TTLs and the request timeout instead of
    /// the system clock (tests drive both lock and grant timers with
    /// one `ManualClock`).
    pub fn with_grant_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.grant_clock = clock;
        self
    }

    /// Apply `[policy]` to the grant store (standing grants on/off).
    pub fn with_grant_policy(mut self, policy: GrantPolicy) -> Self {
        self.grants
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .set_allow_standing(policy.allow_standing);
        self
    }

    /// Apply `[policy]` rate-limit / suspension thresholds (REQ-RL-*).
    pub fn with_rate_policy(mut self, policy: RatePolicy) -> Self {
        self.rates
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .set_policy(policy);
        self
    }

    /// The rate / suspension gate (tests seed and inspect).
    pub fn rate_limiter(&self) -> &Mutex<RateLimiter> {
        &self.rates
    }

    /// The grant store (owner operations below; tests seed and
    /// inspect through it).
    pub fn grant_store(&self) -> &Mutex<GrantStore> {
        &self.grants
    }

    /// The grant clock's current reading.
    fn grant_now(&self) -> std::time::Duration {
        self.grant_clock.now()
    }

    /// Re-sync a stale vault through `source` before a fill resolves
    /// its item (SPEC §8). Without one, a fill against a stale session
    /// is refused `error`/`sync_failed`.
    pub fn with_fill_sync(mut self, source: Arc<dyn FillSync>) -> Self {
        self.fill_sync = Some(source);
        self
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
    /// `key_rotated` / `scope_widened` / `panic` /
    /// `rollback_detected` (via [`LockEvent::audit_entry`]). The
    /// daemon calls this at startup; until it is called, transitions
    /// are unaudited (the state machine's unit tests wire their own
    /// sink instead). Panic and rollback have no separate broker
    /// append — this sink is their only entry, so a second append
    /// would double-write (REQ-AUD-003). Because the controller
    /// enforces REQ-AUD-003 fail-closed on the `Unlocked` entry, an
    /// audit failure rolls the unlock back — exactly as if the sink
    /// had been wired by hand.
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
        let id = self
            .tokens
            .authenticate(token)
            .map_err(|_| ApiError::INVALID_TOKEN)?;
        if self
            .rates
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_revoked(&id)
        {
            return Err(ApiError::INVALID_TOKEN);
        }
        Ok(AgentId(id))
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
        let now = self.grant_now();
        StatusBody {
            locked: lock.is_locked(),
            agent_id: agent.0.clone(),
            // The agent's live grants (SPEC §4). Status is unaudited
            // and never transitions anything: grants past their TTL
            // simply stop being live, and timed-out requests deny on
            // the next expiry pass, not here.
            grants: self
                .grants
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .grants_for(agent.as_str(), now)
                .iter()
                .map(|g| g.view(now))
                .collect(),
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
        // REQ-RL-001 list/search bucket (and suspension).
        let now = self.grant_now();
        if let Err(denied) = self
            .rates
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .admit_list(agent.as_str(), now)
        {
            let detail = match denied {
                RateDenied::Suspended => "agent_suspended",
                RateDenied::Limited => "list_rate_limited",
            };
            self.append(
                Entry::new(Event::RateLimit)
                    .agent_id(agent.0.clone())
                    .result("rate_limited")
                    .detail_code(detail),
            )?;
            return Err(ApiError::RATE_LIMITED);
        }
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
    /// still complete a step already running after the timeout reply
    /// (#46). Since #118 the dispatched call also carries a page-side
    /// relative budget (`deadline` on the plan), so an honest-but-slow
    /// page aborts itself at the next step boundary — fields cleared,
    /// submit never dispatched — and its `kharon:deadline` reply maps
    /// to this same `timeout` / `fill_timeout` outcome.
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
        // The grant request a `pending_approval` outcome created
        // (#20), and the grant an admitted fill spent.
        let mut grant_request_id: Option<String> = None;
        let mut admitted_grant: Option<String> = None;
        // REQ-APR-003: requests past their timeout deny themselves
        // before this fill's own grant check runs.
        self.expire_grant_requests()
            .map_err(|_| ApiError::AUDIT_FAILED)?;
        // REQ-MEM-007: lock dominates every other fill refusal,
        // including rate limits — check it before spending a bucket.
        {
            let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            lock.poll();
            if lock.is_locked() {
                self.append(base(event).result("locked"))?;
                return Err(ApiError::LOCKED);
            }
        }
        // REQ-RL-001/002: fill bucket + per-item window + suspension.
        // Spent up front so a refused fill still counts (anti-hammer).
        {
            let now = self.grant_now();
            let admit = self
                .rates
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .admit_fill(agent.as_str(), &req.item_id, now);
            if let Err(denied) = admit {
                let detail = match denied {
                    RateDenied::Suspended => "agent_suspended",
                    RateDenied::Limited => "fill_rate_limited",
                };
                self.append(base(event).result("rate_limited").detail_code(detail))?;
                self.append(
                    Entry::new(Event::RateLimit)
                        .agent_id(agent.0.clone())
                        .item_id(req.item_id.clone())
                        .result("rate_limited")
                        .detail_code(detail),
                )?;
                return Ok(Outcome::Fill(FillStatus::RateLimited.result()));
            }
        }
        let resolved = match self.resync_if_stale(deadline).await {
            Ok(()) => self.resolve_fill(agent, &req),
            Err(u) => Err(u),
        };
        let status = match resolved {
            Err(Unresolved::Locked) => {
                self.append(base(event).result("locked"))?;
                return Err(ApiError::LOCKED);
            }
            Err(Unresolved::Refused(status)) => status,
            Err(Unresolved::NeedsApproval) => {
                let (status, id, observed) = self.pending_for_fill(agent, &req, deadline).await?;
                grant_request_id = id;
                // #67: the observed origin is the outcome entry's
                // live_origin, as when the engine reads it.
                live_origin = observed;
                status
            }
            Ok((plan, generation, grant_id)) => {
                admitted_grant = Some(grant_id.clone());
                let field_count = plan.fields.len() as u64;
                // Owns the plan from here: every way out of this arm,
                // including this future being dropped, wipes it.
                let mut guard = DispatchGuard {
                    plan,
                    plan_wiped: self.plan_wiped.as_ref(),
                    audit: &self.audit,
                    abort_entry: None,
                };
                // #118: the engine converts what remains of this
                // deadline into the page-side relative budget at
                // dispatch (see `FillPlan::deadline`). The plan
                // carries a std-clock instant: the remaining duration
                // is mapped onto it here, so a paused tokio clock in
                // tests still yields the full remaining budget.
                guard.plan.deadline = Some(
                    std::time::Instant::now() + deadline.saturating_duration_since(Instant::now()),
                );
                if Instant::now() >= deadline {
                    // Expired before dispatch: no CDP write, no
                    // dispatch entry, just the `fill_timeout` outcome.
                    drop(guard);
                    FillStatus::Engine(FillOutcome::Timeout)
                } else {
                    self.append(
                        base(Event::FillDispatch)
                            .origin(req.expected_origin.clone())
                            .grant_id(grant_id.clone())
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
        let entry = match &admitted_grant {
            Some(g) => entry.grant_id(g.clone()),
            None => entry,
        };
        self.append(entry)?;
        // REQ-RL-002: consecutive origin_mismatch → suspend.
        match &status {
            FillStatus::Engine(FillOutcome::OriginMismatch) => {
                let newly = self
                    .rates
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .note_origin_mismatch(agent.as_str());
                if newly {
                    let _ = self.append(
                        Entry::new(Event::RateLimit)
                            .agent_id(agent.0.clone())
                            .result("suspended")
                            .detail_code("origin_mismatch_streak"),
                    );
                }
            }
            _ => {
                self.rates
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .note_non_mismatch(agent.as_str());
            }
        }
        let mut result = status.result();
        result.grant_request_id = grant_request_id;
        Ok(Outcome::Fill(result))
    }

    /// The `grant_request` audit entry for a request's creation:
    /// result `pending`, or `origin_mismatch` for a request born
    /// refused (REQ-APR-007). The entry's `origin` is the observed
    /// live origin — the evidence, as on fill outcome entries (#67) —
    /// and its `request_id` is the grant request's id.
    fn grant_creation_entry(req: &GrantRequest) -> Entry {
        let entry = Entry::new(Event::GrantRequest)
            .agent_id(req.agent_id.clone())
            .item_id(req.item_id.clone())
            .origin(req.observed_origin.clone())
            .request_id(req.id.clone());
        match req.state {
            RequestState::OriginMismatch => entry.result("origin_mismatch"),
            _ => entry.result("pending"),
        }
    }

    /// A grantless fill's second half (REQ-APR-001/007): observe the
    /// target's live origin through the backend (bounded by the fill
    /// deadline), make the grant request, audit its creation, and
    /// report `pending_approval` — or `origin_mismatch` when the tab
    /// is not where the agent claimed, or `target_not_owned` when
    /// there is nothing to observe. Nothing has been decrypted.
    /// Also returns the observed origin (when one was read) so the
    /// caller's outcome entry carries it as `live_origin` (#67).
    async fn pending_for_fill(
        &self,
        agent: &AgentId,
        req: &FillRequest,
        deadline: Instant,
    ) -> Result<(FillStatus, Option<String>, Option<String>), ApiError> {
        let observed = match &self.fill_backend {
            Some(b) => {
                match tokio::time::timeout_at(
                    deadline,
                    b.observe_origin(
                        agent.as_str(),
                        &req.target_id,
                        self.fill_policy.allow_default_context,
                    ),
                )
                .await
                {
                    Ok(o) => o,
                    Err(_) => {
                        return Ok((FillStatus::Engine(FillOutcome::Timeout), None, None));
                    }
                }
            }
            None => None,
        };
        let Some(observed) = observed else {
            return Ok((FillStatus::Engine(FillOutcome::TargetNotOwned), None, None));
        };
        // REQ-RL-003: ≤ max pending per agent; a 4th distinct request
        // is rate_limited with no notification (no grant_request
        // entry, no prompt). Deduped retries of an existing pending
        // triple still succeed.
        {
            let store = self.grants.lock().unwrap_or_else(|p| p.into_inner());
            let max = self
                .rates
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .max_pending_grants() as usize;
            let claim_ok = crate::api::grant::serialized_origin(&req.expected_origin)
                == crate::api::grant::serialized_origin(&observed);
            let deduped = claim_ok
                && store.pending_requests().iter().any(|r| {
                    r.agent_id == agent.as_str()
                        && r.item_id == req.item_id
                        && r.action == grant_action(req.operation)
                });
            if claim_ok && !deduped && store.pending_count(agent.as_str()) >= max {
                drop(store);
                let _ = self.append(
                    Entry::new(Event::RateLimit)
                        .agent_id(agent.0.clone())
                        .item_id(req.item_id.clone())
                        .result("rate_limited")
                        .detail_code("pending_grant_cap"),
                );
                return Ok((FillStatus::RateLimited, None, Some(observed)));
            }
        }
        let (greq, created) = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .create_request(
                agent.as_str(),
                &req.item_id,
                grant_action(req.operation),
                &req.expected_origin,
                &observed,
                self.grant_now(),
            );
        if created {
            self.append(Self::grant_creation_entry(&greq))?;
            if greq.state == RequestState::Pending {
                self.mint_approval_tokens(&greq.id);
            }
        }
        let status = match greq.state {
            RequestState::OriginMismatch => FillStatus::Engine(FillOutcome::OriginMismatch),
            _ => FillStatus::PendingApproval,
        };
        Ok((status, Some(greq.id), Some(observed)))
    }

    /// Run a `kharon_request_grant` / `POST /v1/grants` for `agent`
    /// (SPEC §4, #20): the explicit form of the request a grantless
    /// fill makes implicitly. Lock-gated like a fill (`423` while
    /// locked, audited as a `grant_request` entry with result
    /// `locked`); an unknown item is `not_found` and a target the
    /// broker cannot observe is `target_not_owned` — both as
    /// [`GrantRequestBody`] states with no request created, mirroring
    /// how fills report refusals in-band. A created request is
    /// audited before the reply (REQ-AUD-003). Bounded by the fill
    /// deadline from `received`, like fills and context calls.
    pub async fn request_grant(
        &self,
        agent: &AgentId,
        args: GrantRequestArgs,
        received: Instant,
    ) -> Result<Outcome, ApiError> {
        let deadline = received + self.fill_policy.deadline;
        self.expire_grant_requests()
            .map_err(|_| ApiError::AUDIT_FAILED)?;
        let base = |result: &'static str| {
            Entry::new(Event::GrantRequest)
                .agent_id(agent.0.clone())
                .item_id(args.item_id.clone())
                .result(result)
        };
        let known = {
            let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            match lock.require_unlocked() {
                Ok(session) => session.vault().get(&args.item_id).is_ok(),
                Err(_) => {
                    drop(lock);
                    self.append(base("locked"))?;
                    return Err(ApiError::LOCKED);
                }
            }
        };
        if !known {
            self.append(base("not_found"))?;
            return Ok(Outcome::GrantRequest(GrantRequestBody::refused(
                "not_found",
            )));
        }
        let observed = match &self.fill_backend {
            Some(b) => {
                match tokio::time::timeout_at(
                    deadline,
                    b.observe_origin(
                        agent.as_str(),
                        &args.target_id,
                        self.fill_policy.allow_default_context,
                    ),
                )
                .await
                {
                    Ok(o) => o,
                    Err(_) => {
                        self.append(base("timeout"))?;
                        return Ok(Outcome::GrantRequest(GrantRequestBody::refused("timeout")));
                    }
                }
            }
            None => None,
        };
        let Some(observed) = observed else {
            self.append(base("target_not_owned"))?;
            return Ok(Outcome::GrantRequest(GrantRequestBody::refused(
                "target_not_owned",
            )));
        };
        let (greq, created) = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .create_request(
                agent.as_str(),
                &args.item_id,
                args.action,
                &args.expected_origin,
                &observed,
                self.grant_now(),
            );
        if created {
            self.append(Self::grant_creation_entry(&greq))?;
            if greq.state == RequestState::Pending {
                self.mint_approval_tokens(&greq.id);
            }
        }
        Ok(Outcome::GrantRequest(GrantRequestBody::of(&greq)))
    }

    /// REQ-APR-003: deny every grant request that has been pending
    /// for at least [`REQUEST_TIMEOUT`](super::grant::REQUEST_TIMEOUT),
    /// auditing each denial (`grant_request`, result `denied`, detail
    /// `request_timeout`). Each denial transitions under the store
    /// lock *before* its audit append: an owner approval that lands
    /// after the expiry snapshot wins, and no timeout denial is ever
    /// audited for a request that was in fact approved (PR #109
    /// review). If the append fails the transition is rolled back —
    /// the request is pending again (REQ-AUD-003 fail-closed, as for
    /// owner denials). Runs at the head of every fill and grant
    /// request; the daemon may also call it on its own cadence.
    /// Returns how many requests transitioned.
    pub fn expire_grant_requests(&self) -> Result<usize, GrantError> {
        let now = self.grant_now();
        let expired = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .expired_pending(now);
        let mut count = 0;
        for req in expired {
            let Some(req) = self
                .grants
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .deny_expired(&req.id)
            else {
                // Approved (or otherwise resolved) since the
                // snapshot: not a timeout denial, nothing to audit.
                continue;
            };
            let entry = Entry::new(Event::GrantRequest)
                .agent_id(req.agent_id.clone())
                .item_id(req.item_id.clone())
                .origin(req.observed_origin.clone())
                .request_id(req.id.clone())
                .result("denied")
                .detail_code("request_timeout");
            if self.append(entry).is_err() {
                self.grants
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .restore_pending(&req.id);
                return Err(GrantError::AuditFailed);
            }
            count += 1;
        }
        Ok(count)
    }

    /// Approve a pending grant request on `channel`, issuing its
    /// grant under `terms` (the owner surface for #16/#17 to call).
    /// The `grant_issue` entry is appended before the approval is
    /// reported; if the append fails the approval is rolled back —
    /// the request is pending again and no grant exists
    /// (REQ-AUD-003 fail-closed, as for unlock).
    pub fn approve_grant_request(
        &self,
        request_id: &str,
        terms: &GrantTerms,
        channel: Channel,
    ) -> Result<GrantView, GrantError> {
        let now = self.grant_now();
        let grant = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .approve(request_id, terms, channel, now)?;
        // REQ-REV-004: pin the item revision at issuance.
        if let GrantScope::Item(ref item_id) = grant.scope {
            let rev = {
                let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
                lock.require_unlocked()
                    .ok()
                    .and_then(|s| s.vault().get(item_id).ok())
                    .and_then(|i| i.revision().map(str::to_owned))
            };
            self.grants
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pin_revision(&grant.id, rev);
        }
        let grant = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .grant(&grant.id)
            .cloned()
            .unwrap_or(grant);
        let entry = Entry::new(Event::GrantIssue)
            .agent_id(grant.agent_id.clone())
            .grant_id(grant.id.clone())
            .channel(channel.as_str())
            .request_id(request_id)
            .result("issued");
        let entry = match grant_item_id(&grant) {
            Some(id) => entry.item_id(id),
            None => entry,
        };
        if self.append(entry).is_err() {
            self.grants
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .rollback_approval(request_id, &grant.id);
            return Err(GrantError::AuditFailed);
        }
        Ok(grant.view(now))
    }

    /// Deny a pending grant request (owner action). Audited
    /// (`grant_request`, result `denied`, detail `owner_denied`);
    /// an audit failure restores the request to pending.
    pub fn deny_grant_request(&self, request_id: &str) -> Result<GrantRequest, GrantError> {
        let req = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .deny(request_id)?;
        let entry = Entry::new(Event::GrantRequest)
            .agent_id(req.agent_id.clone())
            .item_id(req.item_id.clone())
            .origin(req.observed_origin.clone())
            .request_id(req.id.clone())
            .result("denied")
            .detail_code("owner_denied");
        if self.append(entry).is_err() {
            self.grants
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .restore_pending(request_id);
            return Err(GrantError::AuditFailed);
        }
        Ok(req)
    }

    /// Mint the one-time approve/deny token pair for a freshly
    /// created pending request (REQ-APR-004). The plaintext pair is
    /// retrievable exactly while the tokens are live, via
    /// [`Self::approval_token_paths`], for the owner surfaces that
    /// render or send the ntfy action URLs.
    fn mint_approval_tokens(&self, request_id: &str) {
        let now = self.grant_now();
        let mut store = self
            .approval_tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        store.mint(request_id, ApprovalAction::Approve, now);
        store.mint(request_id, ApprovalAction::Deny, now);
    }

    /// The live ntfy action paths for `request_id`
    /// (`/owner/approve/<token>`, `/owner/deny/<token>`), or `None`
    /// when no live pair exists (REQ-APR-004, #21). Owner surfaces
    /// only: the paths carry bearer-grade tokens.
    ///
    /// Follow-up #128: the publisher joins these paths to the owner
    /// listener (`[owner_ui] listen`, loopback). That listener is
    /// where redeem is served (REQ-DEP-006, #136). The URL host is
    /// that address.
    pub fn approval_token_paths(&self, request_id: &str) -> Option<(String, String)> {
        self.approval_tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .paths_for(request_id, self.grant_now())
    }

    /// The approval prompt a token's GET confirm page renders
    /// (REQ-APR-004): peeking never consumes the token and never
    /// mutates grant state. The action the token carries is checked
    /// against the endpoint it was presented on by the caller.
    pub fn approval_token_prompt(
        &self,
        token: &str,
    ) -> Result<(super::grant::ApprovalPrompt, ApprovalAction), TokenGone> {
        let (request_id, action) = self
            .approval_tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .peek(token, self.grant_now())?;
        let req = self.grant_request(&request_id).ok_or(TokenGone::Unknown)?;
        let prompt = req.prompt().ok_or(TokenGone::Used)?;
        Ok((prompt, action))
    }

    /// Redeem a one-time approval token (REQ-APR-004): approve
    /// issues a `once` grant on the ntfy channel (SPEC §5: ntfy
    /// `http` actions approve `once` grants only; wider terms need
    /// the CLI or the WebAuthn web UI), deny denies the request.
    /// A token for a request that is no longer pending is `Used`
    /// (410): it can never take effect.
    pub fn redeem_approval_token(&self, token: &str) -> Result<ApprovalAction, TokenGone> {
        // Peek first so a decided-elsewhere request does not burn
        // the distinction between replay and expiry in the store;
        // the redeem below is the single consumption point.
        let (request_id, action) = self
            .approval_tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .peek(token, self.grant_now())?;
        let req = self.grant_request(&request_id).ok_or(TokenGone::Unknown)?;
        if req.state != RequestState::Pending {
            return Err(TokenGone::Used);
        }
        self.approval_tokens
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .redeem(token, self.grant_now())?;
        let decided = match action {
            ApprovalAction::Approve => self
                .approve_grant_request(
                    &request_id,
                    &GrantTerms::once_item(req.item_id.clone()),
                    Channel::Ntfy,
                )
                .map(|_| ()),
            ApprovalAction::Deny => self.deny_grant_request(&request_id).map(|_| ()),
        };
        decided.map_err(|_| TokenGone::Used)?;
        Ok(action)
    }

    /// Revoke a grant (REQ-REV-001's broker primitive; effective for
    /// the next fill). Audited (`grant_revoke`); an audit failure
    /// restores the grant. `false` when no such grant exists.
    pub fn revoke_grant(&self, grant_id: &str) -> Result<bool, GrantError> {
        let Some(grant) = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .grant(grant_id)
            .cloned()
        else {
            return Ok(false);
        };
        self.grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revoke(grant_id);
        let entry = Entry::new(Event::GrantRevoke)
            .agent_id(grant.agent_id.clone())
            .grant_id(grant.id.clone())
            .result("revoked");
        let entry = match grant_item_id(&grant) {
            Some(id) => entry.item_id(id),
            None => entry,
        };
        if self.append(entry).is_err() {
            self.grants
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .restore_grant(grant);
            return Err(GrantError::AuditFailed);
        }
        Ok(true)
    }

    /// Revoke an agent: drop its grants/requests and refuse its
    /// token until the daemon process exits (REQ-REV-001). The flag
    /// is in-memory; [`Self::unsuspend_agent`] does not clear it,
    /// and there is no un-revoke op. The token hash stays in the
    /// store, so a restart accepts the token again. Audited as
    /// `token_revoke` + per-grant `grant_revoke`.
    pub fn revoke_agent(&self, agent_id: &str) -> Result<usize, GrantError> {
        let removed = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revoke_agent(agent_id);
        self.rates
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revoke_agent(agent_id);
        for grant in &removed {
            let entry = Entry::new(Event::GrantRevoke)
                .agent_id(grant.agent_id.clone())
                .grant_id(grant.id.clone())
                .result("revoked")
                .detail_code("agent_revoked");
            let entry = match grant_item_id(grant) {
                Some(id) => entry.item_id(id),
                None => entry,
            };
            if self.append(entry).is_err() {
                // Best-effort restore of this one grant; the agent
                // stays revoked (fail closed on the token).
                self.grants
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .restore_grant(grant.clone());
                return Err(GrantError::AuditFailed);
            }
        }
        let entry = Entry::new(Event::TokenRevoke)
            .agent_id(agent_id.to_owned())
            .result("revoked");
        self.append(entry).map_err(|_| GrantError::AuditFailed)?;
        Ok(removed.len())
    }

    /// Clear an agent's suspension (REQ-RL-002 owner reset). Does
    /// not restore a revoked token; revocation lasts until the
    /// daemon process exits.
    pub fn unsuspend_agent(&self, agent_id: &str) -> Result<(), GrantError> {
        self.rates
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .unsuspend(agent_id);
        self.append(
            Entry::new(Event::RateLimit)
                .agent_id(agent_id.to_owned())
                .result("unsuspended")
                .detail_code("owner_reset"),
        )
        .map_err(|_| GrantError::AuditFailed)
    }

    /// `kharon panic` (REQ-REV-002): revoke every grant, then lock
    /// (zeroize + CDP close via the lock hook). The single `panic`
    /// audit entry is that lock ([`LockReason::Panic`] through
    /// [`Self::wire_lock_audit`]); appending it here as well would
    /// record the transition twice (REQ-AUD-003). Notify is
    /// best-effort via the audit/ntfy checkpoint path; a dedicated
    /// ntfy push is not yet wired (#16).
    pub fn panic_lock(&self) -> Result<(), GrantError> {
        let removed = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .revoke_all();
        for grant in &removed {
            let entry = Entry::new(Event::GrantRevoke)
                .agent_id(grant.agent_id.clone())
                .grant_id(grant.id.clone())
                .result("revoked")
                .detail_code("panic");
            let entry = match grant_item_id(grant) {
                Some(id) => entry.item_id(id),
                None => entry,
            };
            let _ = self.append(entry);
        }
        self.rollback
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .reset();
        self.lock_audited(LockReason::Panic);
        Ok(())
    }

    /// Lock for `reason`. [`LockReason::Panic`] and
    /// [`LockReason::RollbackDetected`] have no other audit entry:
    /// the lock sink writes [`LockReason::audit_entry`] when this
    /// call actually transitions to locked. If the broker is already
    /// locked the sink does not run, so that same entry is appended
    /// here — exactly one of the two paths, never both (REQ-AUD-003).
    fn lock_audited(&self, reason: LockReason) {
        let transitioned = {
            let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            lock.lock(reason)
        };
        if !transitioned && matches!(reason, LockReason::Panic | LockReason::RollbackDetected) {
            let _ = self.append(reason.audit_entry());
        }
    }

    /// Observe a freshly applied vault for rollback (REQ-REV-004).
    /// On `Err`, the caller must lock with [`LockReason::RollbackDetected`]
    /// (and may already hold the controller — this method never takes
    /// the lock). That lock is the single `rollback_detected` audit
    /// entry; this method does not append one, or a wired lock sink
    /// would record a second (REQ-AUD-003). Resets the high-water
    /// marks after a detected rollback so the next unlock starts clean.
    pub fn detect_rollback(
        &self,
        vault: &Vault,
    ) -> Result<(), crate::api::rollback::RollbackReason> {
        let result = self
            .rollback
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe(vault);
        if result.is_err() {
            self.rollback
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .reset();
        }
        result
    }

    /// Invalidate per-item grants whose item is gone or whose pinned
    /// revision no longer matches (REQ-REV-003). Audited per grant.
    pub fn invalidate_grants_for_vault(&self, vault: &Vault) -> Result<usize, GrantError> {
        let removed = self
            .grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .invalidate_for_vault(vault);
        for grant in &removed {
            let entry = Entry::new(Event::GrantRevoke)
                .agent_id(grant.agent_id.clone())
                .grant_id(grant.id.clone())
                .result("revoked")
                .detail_code("item_revised_or_removed");
            let entry = match grant_item_id(grant) {
                Some(id) => entry.item_id(id),
                None => entry,
            };
            self.append(entry).map_err(|_| GrantError::AuditFailed)?;
        }
        Ok(removed.len())
    }

    /// Convenience for callers that do not already hold the lock
    /// controller: detect rollback (locking if needed) then invalidate
    /// grants. Returns whether a rollback forced a lock. The single
    /// `rollback_detected` entry is that lock's, not a second append.
    pub fn observe_vault_after_sync(&self, vault: &Vault) -> Result<bool, GrantError> {
        if self.detect_rollback(vault).is_err() {
            self.lock_audited(LockReason::RollbackDetected);
            return Ok(true);
        }
        self.invalidate_grants_for_vault(vault)?;
        Ok(false)
    }

    /// Reset rollback marks on unlock (fresh high-water).
    pub fn reset_rollback_guard(&self) {
        self.rollback
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .reset();
    }

    /// A grant request by id (owner surfaces, tests).
    pub fn grant_request(&self, request_id: &str) -> Option<GrantRequest> {
        self.grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .request(request_id)
            .cloned()
    }

    /// Every pending grant request (the approval channels' queue).
    pub fn pending_grant_requests(&self) -> Vec<GrantRequest> {
        self.grants
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pending_requests()
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

    /// SPEC §8 (REQ-CRY-009, issue #100): if the unlocked vault is
    /// older than [`crate::sync::MAX_SYNC_INTERVAL`], fetch a fresh
    /// `/api/sync` (outside the mutex, within the fill deadline) and
    /// apply it before the item is resolved. `Ok(())` means "go on to
    /// [`Self::resolve_fill`]", which runs the lock gate again (so a
    /// lock meanwhile is still reported `locked`). Fails closed: a
    /// stale vault is never filled from when the re-sync fails
    /// (`error`/`sync_failed`) or runs past the deadline (`timeout`);
    /// a payload that widens the scope or rotates the org key locks,
    /// exactly as the background sync does (`scope_widened` /
    /// `key_rotated`), and the fill is `locked`.
    async fn resync_if_stale(&self, deadline: Instant) -> Result<(), Unresolved> {
        let generation = {
            let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
            match lock.require_unlocked() {
                Ok(session) if session.is_stale(Instant::now()) => lock.unlocked_at(),
                // Fresh, or locked (the gate in `resolve_fill` says so).
                _ => return Ok(()),
            }
        };
        let refuse = |s| Err(Unresolved::Refused(s));
        let Some(source) = &self.fill_sync else {
            return refuse(FillStatus::SyncFailed);
        };
        let sync = match tokio::time::timeout_at(deadline, source.fetch()).await {
            Ok(Ok(sync)) => sync,
            Ok(Err(_)) => return refuse(FillStatus::SyncFailed),
            Err(_) => return refuse(FillStatus::Engine(FillOutcome::Timeout)),
        };
        let mut lock = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        if lock.unlocked_at() != generation {
            // Locked, or re-unlocked (a fresh sync), while fetching.
            return Ok(());
        }
        match lock.with_session_mut(|session| session.apply_sync(&sync)) {
            Ok(Ok(SyncOutcome::Synced)) | Err(_) => Ok(()),
            Ok(Ok(SyncOutcome::Lock(reason))) => {
                lock.on_sync_lock(&reason);
                Err(Unresolved::Locked)
            }
            Ok(Err(_)) => refuse(FillStatus::SyncFailed),
        }
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
    ) -> Result<(FillPlan, u64, String), Unresolved> {
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

        // REQ-APR-001/002 (SPEC §5, #20): the grant gate — after the
        // item, the browser and every other pre-decrypt refusal, and
        // before anything is decrypted. A matching live grant is
        // consumed (one use, spent at admission). An explicitly named
        // grant that fails any dimension (agent, item/collection,
        // origin, action, TTL, uses) is `denied`: naming a grant and
        // missing its terms is a refusal, not a fresh request. No
        // grant at all is `NeedsApproval`: [`Broker::fill`] makes the
        // request from the observed live origin, still decrypting
        // nothing.
        let action = match req.operation {
            FillOperation::Fill => GrantAction::Fill,
            FillOperation::FillTotp => GrantAction::Totp,
        };
        let now = self.grant_now();
        let admitted = {
            let mut store = self.grants.lock().unwrap_or_else(|p| p.into_inner());
            match &req.grant_id {
                Some(gid) => {
                    let rev = item.revision();
                    let ok = store.grant(gid).is_some_and(|g| {
                        g.matches(
                            agent.as_str(),
                            &req.item_id,
                            item.collection_ids(),
                            &req.expected_origin,
                            action,
                            now,
                        ) && g.revision_matches(rev)
                    }) && store.consume(gid, now);
                    if !ok {
                        return refuse(FillStatus::GrantDenied);
                    }
                    gid.clone()
                }
                None => {
                    let rev = item.revision();
                    let found = store
                        .grants_for(agent.as_str(), now)
                        .into_iter()
                        .find(|g| {
                            g.matches(
                                agent.as_str(),
                                &req.item_id,
                                item.collection_ids(),
                                &req.expected_origin,
                                action,
                                now,
                            ) && g.revision_matches(rev)
                        })
                        .map(|g| g.id);
                    match found {
                        Some(gid) => {
                            let consumed = store.consume(&gid, now);
                            debug_assert!(consumed);
                            gid
                        }
                        None => {
                            // A live grant that fails only on revision
                            // is denied (re-approval), not a fresh
                            // request (REQ-REV-004).
                            let revision_miss = store
                                .matching_grant(
                                    agent.as_str(),
                                    &req.item_id,
                                    item.collection_ids(),
                                    &req.expected_origin,
                                    action,
                                    now,
                                )
                                .is_some_and(|g| !g.revision_matches(rev));
                            if revision_miss {
                                return refuse(FillStatus::GrantDenied);
                            }
                            return Err(Unresolved::NeedsApproval);
                        }
                    }
                }
            }
        };

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
            // Set by `Broker::fill` once the plan is admitted (it owns
            // the deadline); `resolve_fill` runs without one in scope.
            deadline: None,
        };
        Ok((plan, generation, admitted))
    }
}
