//! `fill` / `fill_totp` (SPEC §4; issues #18, #19).
//!
//! The request side is shared by both transports, as the read
//! operations' parameters are ([`super::core::parse_request`]): HTTP
//! (`POST /v1/fill`, `POST /v1/fill_totp`) and MCP (`kharon_fill`,
//! `kharon_fill_totp`) hand the JSON body / tool arguments to
//! [`parse_fill`], and the broker runs the validated [`FillRequest`]
//! ([`super::Broker::fill`]). There is no separate `fill_and_submit`
//! route: `submit: true` is `fill_and_submit` (SPEC §4).
//!
//! The response is [`FillResult`]: a status, the kinds filled and a
//! fixed detail code, all `&'static str`. No response type can carry a
//! value (REQ-GOAL-001): secrets travel only broker → [`FillBackend`] in
//! a [`FillPlan`] whose buffers are zeroized when the call returns.
//!
//! The browser side is a [`FillBackend`] over the [`FillEngine`] (one
//! CDP browser context per agent, REQ-ARCH-005): the daemon runs
//! [`ConnectingCdpBackend`] (configured endpoints, connected on first
//! fill); [`CdpFillBackend`] takes pre-built engines; tests substitute
//! a stub.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use super::error::{ApiError, Detail};
use crate::cdp::fill::DEFAULT_FILL_DEADLINE;
use crate::cdp::{
    AgentContext, Browser, CdpClient, CdpEndpoint, FieldKind, FillEngine, FillOutcome, FillPlan,
};
use crate::config::{AgentConfig, PolicyConfig};

/// Longest accepted `cdp_target_id` / `frame_id` (bytes). Chrome's are
/// 32 hex digits.
pub const MAX_TARGET_ID_LEN: usize = 128;
/// Longest accepted `selector` (bytes).
pub const MAX_SELECTOR_LEN: usize = 1024;
/// Longest accepted `grant_id` (bytes).
pub const MAX_GRANT_ID_LEN: usize = 128;
/// Longest accepted `expected_origin` (bytes); same cap as `origin`.
pub const MAX_EXPECTED_ORIGIN_LEN: usize = super::core::MAX_ORIGIN_LEN;
/// Length of a canonical UUID `item_id`.
pub const ITEM_ID_LEN: usize = 36;

/// Which fill operation a route / tool names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillOperation {
    /// `POST /v1/fill` / `kharon_fill`.
    Fill,
    /// `POST /v1/fill_totp` / `kharon_fill_totp`.
    FillTotp,
}

// ------------------------------------------------------------ wire types

/// SPEC §4 `FillRequest`: the `POST /v1/fill` body and the
/// `kharon_fill` arguments.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FillArgs {
    /// The item to fill from (an `id` from `kharon_list` /
    /// `kharon_search`).
    #[schemars(length(min = 36, max = 36), extend("format" = "uuid"))]
    pub item_id: String,
    /// The tab (or out-of-process frame) to fill.
    pub target: TargetArgs,
    /// The fields to fill, at most one per kind. `selector` overrides
    /// the broker's heuristic for that field.
    #[schemars(length(min = 1, max = 3))]
    pub fields: Vec<FieldArgs>,
    /// Submit the form after every field filled (`fill_and_submit`).
    /// Never dispatched on any failure or timeout.
    #[serde(default)]
    pub submit: bool,
    /// An approved grant to fill under (REQ-APR-*; issue #20).
    #[serde(default)]
    #[schemars(length(max = MAX_GRANT_ID_LEN))]
    pub grant_id: Option<String>,
}

/// SPEC §4 `FillTotpRequest`: `FillRequest` with `fields =
/// [{kind: "totp", selector?}]` (the default when omitted).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FillTotpArgs {
    /// The item whose TOTP code to fill.
    #[schemars(length(min = 36, max = 36), extend("format" = "uuid"))]
    pub item_id: String,
    /// The tab (or out-of-process frame) to fill.
    pub target: TargetArgs,
    /// Exactly one `totp` field. Omitted: `[{"kind": "totp"}]`.
    #[serde(default)]
    #[schemars(length(min = 1, max = 1))]
    pub fields: Option<Vec<TotpFieldArgs>>,
    /// Submit the form after the code filled.
    #[serde(default)]
    pub submit: bool,
    /// An approved grant to fill under (issue #20).
    #[serde(default)]
    #[schemars(length(max = MAX_GRANT_ID_LEN))]
    pub grant_id: Option<String>,
}

/// SPEC §4 `target`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetArgs {
    /// CDP target id of a tab in the agent's own browser context.
    #[schemars(length(min = 1, max = MAX_TARGET_ID_LEN))]
    pub cdp_target_id: String,
    /// Not supported: must be omitted or null. Address an
    /// out-of-process frame by its own `cdp_target_id`.
    #[serde(default)]
    #[schemars(length(max = MAX_TARGET_ID_LEN))]
    pub frame_id: Option<String>,
    /// The origin the agent believes the tab is on. Never trusted: the
    /// live origin decides, and a mismatch is `origin_mismatch`
    /// (REQ-ORG-002, REQ-APR-007).
    #[schemars(length(max = MAX_EXPECTED_ORIGIN_LEN), extend("format" = "uri"))]
    pub expected_origin: String,
}

/// One `fields[]` entry of `fill`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FieldArgs {
    /// Which item field.
    pub kind: FieldKindArg,
    /// CSS selector of the input; omitted: the broker finds it.
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_SELECTOR_LEN))]
    pub selector: Option<String>,
}

/// One `fields[]` entry of `fill_totp`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TotpFieldArgs {
    /// Always `totp`.
    pub kind: TotpKindArg,
    /// CSS selector of the input; omitted: the broker finds it.
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_SELECTOR_LEN))]
    pub selector: Option<String>,
}

/// SPEC §4 field kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldKindArg {
    Username,
    Password,
    Totp,
}

/// The one kind `fill_totp` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TotpKindArg {
    Totp,
}

impl From<FieldKindArg> for FieldKind {
    fn from(k: FieldKindArg) -> Self {
        match k {
            FieldKindArg::Username => Self::Username,
            FieldKindArg::Password => Self::Password,
            FieldKindArg::Totp => Self::Totp,
        }
    }
}

// ------------------------------------------------------- validated request

/// A validated fill request (no secrets: values are looked up by the
/// broker after the lock gate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillRequest {
    /// Which operation (audit event, and later grant action, #20).
    pub operation: FillOperation,
    /// Canonical (lowercase) UUID.
    pub item_id: String,
    /// CDP target id.
    pub target_id: String,
    /// The agent's claimed origin, as given (validated absolute
    /// http(s) URL).
    pub expected_origin: String,
    /// `(kind, selector)` per field, distinct kinds, request order.
    pub fields: Vec<(FieldKind, Option<String>)>,
    /// `fill_and_submit`.
    pub submit: bool,
    /// Accepted and length-checked; not yet enforced (issue #20).
    pub grant_id: Option<String>,
}

/// Validate a `fill` / `fill_totp` JSON body (HTTP) or tool arguments
/// (MCP). The single entry point for both transports.
pub fn parse_fill(op: FillOperation, json: &[u8]) -> Result<FillRequest, ApiError> {
    let (item_id, target, fields, submit, grant_id) = match op {
        FillOperation::Fill => {
            let a: FillArgs = from_json(json)?;
            let fields: Vec<_> = a
                .fields
                .into_iter()
                .map(|f| (FieldKind::from(f.kind), f.selector))
                .collect();
            (a.item_id, a.target, fields, a.submit, a.grant_id)
        }
        FillOperation::FillTotp => {
            let a: FillTotpArgs = from_json(json)?;
            let fields = match a.fields {
                None => vec![(FieldKind::Totp, None)],
                Some(f) if f.len() == 1 => f
                    .into_iter()
                    .map(|f| (FieldKind::Totp, f.selector))
                    .collect(),
                Some(f) if f.is_empty() => {
                    return Err(ApiError::bad_request(Detail::NoFillFields));
                }
                Some(_) => return Err(ApiError::bad_request(Detail::DuplicateFillField)),
            };
            (a.item_id, a.target, fields, a.submit, a.grant_id)
        }
    };

    let item_id = canonical_uuid(&item_id)?;
    if target.cdp_target_id.is_empty() {
        return Err(ApiError::bad_request(Detail::InvalidFillRequest));
    }
    if target.cdp_target_id.len() > MAX_TARGET_ID_LEN {
        return Err(ApiError::bad_request(Detail::FieldTooLong));
    }
    if target.frame_id.is_some() {
        return Err(ApiError::bad_request(Detail::FrameIdUnsupported));
    }
    let expected_origin = validate_expected_origin(&target.expected_origin)?;
    if fields.is_empty() {
        return Err(ApiError::bad_request(Detail::NoFillFields));
    }
    for (i, (kind, selector)) in fields.iter().enumerate() {
        if fields[..i].iter().any(|(k, _)| k == kind) {
            return Err(ApiError::bad_request(Detail::DuplicateFillField));
        }
        match selector {
            Some(s) if s.len() > MAX_SELECTOR_LEN => {
                return Err(ApiError::bad_request(Detail::FieldTooLong));
            }
            Some(s) if s.trim().is_empty() => {
                return Err(ApiError::bad_request(Detail::InvalidFillRequest));
            }
            _ => {}
        }
    }
    if grant_id
        .as_ref()
        .is_some_and(|g| g.len() > MAX_GRANT_ID_LEN)
    {
        return Err(ApiError::bad_request(Detail::FieldTooLong));
    }
    Ok(FillRequest {
        operation: op,
        item_id,
        target_id: target.cdp_target_id,
        expected_origin,
        fields,
        submit,
        grant_id,
    })
}

fn from_json<T: for<'de> Deserialize<'de>>(json: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(json).map_err(|e| match e.classify() {
        serde_json::error::Category::Data => ApiError::bad_request(Detail::InvalidFillRequest),
        _ => ApiError::bad_request(Detail::InvalidJsonBody),
    })
}

/// `8-4-4-4-12` hex digits; returned lowercase (vault ids are).
fn canonical_uuid(id: &str) -> Result<String, ApiError> {
    let ok = id.len() == ITEM_ID_LEN
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if ok {
        Ok(id.to_ascii_lowercase())
    } else {
        Err(ApiError::bad_request(Detail::InvalidItemId))
    }
}

fn validate_expected_origin(origin: &str) -> Result<String, ApiError> {
    if origin.len() > MAX_EXPECTED_ORIGIN_LEN {
        return Err(ApiError::bad_request(Detail::FieldTooLong));
    }
    match Url::parse(origin) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => {
            Ok(origin.to_owned())
        }
        _ => Err(ApiError::bad_request(Detail::InvalidOrigin)),
    }
}

// ---------------------------------------------------------------- result

/// SPEC §4 `FillResult`. Every field is a fixed string: nothing from the
/// vault or the page can reach a response (REQ-GOAL-001, REQ-API-006).
/// `grant_request_id` arrives with #20; `audit_seq` is not reported
/// (see the PR's spec questions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FillResult {
    /// `filled`, `origin_mismatch`, `target_not_owned`, `navigated`,
    /// `field_not_found`, `timeout`, `not_found` or `error`.
    pub status: &'static str,
    /// Kinds filled (only on `filled`).
    pub fields_filled: Vec<&'static str>,
    /// A fixed code, e.g. `unknown_item`, `clock_skew`, `cdp_error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'static str>,
}

/// What a fill came to, before it is a [`FillResult`]: the engine's
/// outcome, or a refusal the broker made before reaching the browser.
#[derive(Debug, PartialEq, Eq)]
pub enum FillStatus {
    /// The engine ran (or the deadline/clock gate stopped it).
    Engine(FillOutcome),
    /// `item_id` is not in the vault.
    UnknownItem,
    /// The item has no value for a requested kind.
    ItemFieldMissing,
    /// The item's secret did not decrypt (or is not UTF-8).
    DecryptFailed,
    /// No browser is wired for this agent.
    Unavailable,
}

impl FillStatus {
    /// `FillResult.status`.
    pub fn status(&self) -> &'static str {
        match self {
            Self::Engine(o) => o.status(),
            Self::UnknownItem => "not_found",
            Self::ItemFieldMissing | Self::DecryptFailed | Self::Unavailable => "error",
        }
    }

    /// `FillResult.detail`, and the audit `detail_code`.
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            Self::Engine(o) => o.detail(),
            Self::UnknownItem => Some("unknown_item"),
            Self::ItemFieldMissing => Some("item_field_missing"),
            Self::DecryptFailed => Some("decrypt_failed"),
            Self::Unavailable => Some("fill_unavailable"),
        }
    }

    /// The response.
    pub fn result(&self) -> FillResult {
        FillResult {
            status: self.status(),
            fields_filled: match self {
                Self::Engine(o) => o.fields_filled(),
                _ => Vec::new(),
            },
            detail: self.detail(),
        }
    }
}

// --------------------------------------------------------------- backend

/// A boxed fill future.
pub type FillFuture<'a> = Pin<Box<dyn Future<Output = FillOutcome> + Send + 'a>>;

/// Where fills go: per agent, a browser context to fill in.
pub trait FillBackend: Send + Sync {
    /// Whether `agent_id` has a browser context (checked before any
    /// secret is decrypted).
    fn has_agent(&self, agent_id: &str) -> bool;

    /// Run `plan` in `agent_id`'s context. The broker bounds this with
    /// the fill deadline and drops the future on expiry, so an
    /// implementation must make no CDP write once dropped.
    fn fill<'a>(
        &'a self,
        agent_id: &'a str,
        plan: &'a FillPlan,
        allow_default: bool,
    ) -> FillFuture<'a>;

    /// The backend's unlock generation: a counter that
    /// [`Self::on_lock`] advances (issue #66). The broker reads it under
    /// the lock controller, in the same critical section as the fill
    /// gate, and hands it to [`Self::fill_in_generation`], so a backend
    /// can tell a fill that was admitted before a lock from one admitted
    /// after it. Backends that cache nothing keep the default.
    fn generation(&self) -> u64 {
        0
    }

    /// [`Self::fill`] for a fill admitted in unlock generation
    /// `generation` (see [`Self::generation`]). A backend that caches
    /// browser state must not cache anything for, or write to the page
    /// on behalf of, a generation that has since been locked.
    fn fill_in_generation<'a>(
        &'a self,
        agent_id: &'a str,
        plan: &'a FillPlan,
        allow_default: bool,
        generation: u64,
    ) -> FillFuture<'a> {
        let _ = generation;
        self.fill(agent_id, plan, allow_default)
    }

    /// The broker locked (SPEC §8: "Lock zeroizes keys and closes CDP
    /// sessions"; issue #66). Called from the lock controller's hook on
    /// every lock path, with the controller borrowed: it must not block
    /// and cannot fail. Teardown that needs the browser runs in the
    /// background, best effort.
    fn on_lock(&self) {}
}

/// The production backend: the CDP [`FillEngine`], one [`AgentContext`]
/// per agent.
#[derive(Clone, Default)]
pub struct CdpFillBackend {
    agents: HashMap<String, (FillEngine, AgentContext)>,
}

impl CdpFillBackend {
    /// An empty backend (every agent is `fill_unavailable`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Fill for `agent_id` through `engine` in `ctx`.
    pub fn register(&mut self, agent_id: &str, engine: FillEngine, ctx: AgentContext) {
        self.agents.insert(agent_id.to_owned(), (engine, ctx));
    }
}

impl FillBackend for CdpFillBackend {
    fn has_agent(&self, agent_id: &str) -> bool {
        self.agents.contains_key(agent_id)
    }

    fn fill<'a>(
        &'a self,
        agent_id: &'a str,
        plan: &'a FillPlan,
        allow_default: bool,
    ) -> FillFuture<'a> {
        Box::pin(async move {
            match self.agents.get(agent_id) {
                Some((engine, ctx)) => engine.fill(plan, ctx, allow_default).await,
                None => FillOutcome::TargetNotOwned,
            }
        })
    }
}

/// The daemon's backend: one configured CDP endpoint per agent
/// (`[agents.<id>] cdp`, REQ-ARCH-002), connected on demand.
///
/// Startup never touches the browser: the first fill for an agent (after
/// its `fill_dispatch` entry, inside the fill deadline) connects, creates
/// the agent's own browser context (REQ-ARCH-005) and keeps both. A
/// connection that has ended (browser restart, tunnel drop) is replaced
/// by the next fill, with a fresh context; the fill that saw it end
/// reports `cdp_error`.
///
/// The connect step (TCP/TLS/WebSocket plus `Target.createBrowserContext`)
/// runs as its own task, bounded by [`DEFAULT_CONNECT_TIMEOUT`], and is
/// not cancelled by the fill deadline (issue #68). A fill whose deadline
/// fires mid-connect returns `timeout` at once, but the connect finishes
/// in the background: if the context arrives it is adopted (cached) for
/// the next fill instead of being leaked, and no CDP command is sent on
/// the dead fill's behalf (REQ-API-009). If the connect fails or runs out
/// of budget after the socket opened, the connection is closed, which
/// makes the browser dispose any context it created for it.
///
/// Lock closes CDP sessions (SPEC §8, issue #66). [`FillBackend::on_lock`]
/// advances the unlock generation and, in the background, takes every
/// cached connection, sends `Target.disposeBrowserContext` for its
/// context (bounded by [`DEFAULT_TEARDOWN_TIMEOUT`]) and closes the
/// connection. Nothing in the lock waits for the browser. Every cached
/// entry is tagged with the generation it was connected in, and a fill
/// carries the generation the broker admitted it in, so:
///
/// - a connect that finishes after a lock disposes and closes what it
///   opened instead of caching it, and its fill makes no page write;
/// - a cached entry from an earlier generation is never reused, even if
///   its background teardown has not run yet;
/// - a fill admitted before the lock that reaches the backend after it
///   is refused (`cdp_error`) before any CDP I/O.
///
/// The first fill after unlock therefore reconnects and creates a fresh
/// context.
///
/// Fills for one agent are serialised on the connect step only; the
/// fill itself runs on a clone of the engine.
pub struct ConnectingCdpBackend {
    agents: HashMap<String, AgentBrowser>,
    connect_timeout: Duration,
    teardown_timeout: Duration,
    generation: Arc<AtomicU64>,
}

/// Budget for one background connect (socket, handshake and
/// `createBrowserContext`); matches the per-request CDP hang-guard.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Budget for `Target.disposeBrowserContext` when a lock tears an
/// agent's session down (issue #66). The connection is closed after it
/// either way, and closing makes the browser dispose the context too.
pub const DEFAULT_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// One agent's live connection and context, and the unlock generation
/// it was opened in.
#[derive(Clone)]
struct Cached {
    browser: Browser,
    engine: FillEngine,
    ctx: AgentContext,
    generation: u64,
}

type Live = Option<Cached>;

struct AgentBrowser {
    endpoint: CdpEndpoint,
    live: Arc<tokio::sync::Mutex<Live>>,
}

/// Why the backend refused a fill admitted before a lock.
const LOCKED_DURING_FILL: &str = "broker locked during fill";

impl ConnectingCdpBackend {
    /// One lazily-connected browser per `(agent id, endpoint)`.
    pub fn new<I, S>(agents: I) -> Self
    where
        I: IntoIterator<Item = (S, CdpEndpoint)>,
        S: Into<String>,
    {
        Self {
            agents: agents
                .into_iter()
                .map(|(id, endpoint)| {
                    (
                        id.into(),
                        AgentBrowser {
                            endpoint,
                            live: Arc::new(tokio::sync::Mutex::new(None)),
                        },
                    )
                })
                .collect(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            teardown_timeout: DEFAULT_TEARDOWN_TIMEOUT,
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Override the background connect budget (tests).
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override the lock-time `disposeBrowserContext` budget (tests).
    pub fn with_teardown_timeout(mut self, timeout: Duration) -> Self {
        self.teardown_timeout = timeout;
        self
    }

    /// Every `[agents.<id>]` with its validated `cdp` endpoint.
    pub fn from_agents(agents: &BTreeMap<String, AgentConfig>) -> Self {
        Self::new(agents.iter().map(|(id, a)| (id.clone(), a.cdp.clone())))
    }
}

impl AgentBrowser {
    /// The live engine and context for a fill admitted in `generation`,
    /// connecting first if there is none, the last connection ended, or
    /// the cached one belongs to an earlier (locked) generation.
    ///
    /// The connect runs in a spawned task that holds the lock and stores
    /// its result itself, so dropping this future (the fill deadline)
    /// neither cancels a `createBrowserContext` already on the wire nor
    /// loses its reply: the context is adopted by the next fill — unless
    /// the broker locked meanwhile, in which case the task disposes it
    /// and closes the connection (issue #66).
    async fn engine(
        &self,
        agent_id: &str,
        budget: Duration,
        teardown_budget: Duration,
        generation: u64,
        current: &Arc<AtomicU64>,
    ) -> Result<Cached, FillOutcome> {
        let mut live = Arc::clone(&self.live).lock_owned().await;
        if current.load(Ordering::Acquire) != generation {
            return Err(FillOutcome::Error(LOCKED_DURING_FILL.into()));
        }
        if let Some(c) = &*live
            && c.generation == generation
            && !c.engine.is_closed()
        {
            return Ok(c.clone());
        }
        if let Some(stale) = live.take()
            && !stale.engine.is_closed()
        {
            // Normally the lock's own teardown got here first; this only
            // covers a lock that ran without a runtime to spawn it on.
            let agent = agent_id.to_owned();
            tokio::spawn(async move { teardown(stale, &agent, teardown_budget).await });
        }
        let endpoint = self.endpoint.clone();
        let agent_id = agent_id.to_owned();
        let current = Arc::clone(current);
        let connect = tokio::spawn(async move {
            let opened = open_agent_browser(&endpoint, &agent_id, budget, generation).await?;
            // Checked while holding the agent's lock: a lock that bumps
            // the generation after this point queues its teardown behind
            // us and finds the entry we store.
            if current.load(Ordering::Acquire) != generation {
                teardown(opened, &agent_id, teardown_budget).await;
                return Err(LOCKED_DURING_FILL.to_owned());
            }
            *live = Some(opened.clone());
            Ok::<_, String>(opened)
        });
        match connect.await {
            Ok(Ok(opened)) => Ok(opened),
            Ok(Err(e)) => Err(FillOutcome::Error(e)),
            Err(e) => Err(FillOutcome::Error(format!("cdp connect task: {e}"))),
        }
    }
}

/// Take `agent_id`'s cached session if it was opened before the lock that
/// moved the generation to `lock_generation`, and tear it down (issue
/// #66). Waits for an in-flight connect for this agent to finish first
/// (that connect sees the new generation and tears down its own). A
/// session opened after the lock (an unlock and a fill can overtake this
/// task) is left alone.
async fn close_cached(
    live: Arc<tokio::sync::Mutex<Live>>,
    agent_id: String,
    lock_generation: u64,
    budget: Duration,
) {
    let taken = {
        let mut live = live.lock().await;
        match &*live {
            Some(c) if c.generation < lock_generation => live.take(),
            _ => None,
        }
    };
    if let Some(c) = taken {
        teardown(c, &agent_id, budget).await;
    }
}

/// Dispose `c`'s browser context (best effort, within `budget`) and close
/// its connection. Failures are reported as `kharond: warning:` lines,
/// never returned: a lock must not depend on the browser (issue #66).
async fn teardown(c: Cached, agent_id: &str, budget: Duration) {
    if !c.engine.is_closed() {
        match tokio::time::timeout(budget, c.browser.close_agent_context(&c.ctx)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!(
                "kharond: warning: lock: disposing agent {agent_id}'s browser context failed \
                 ({e}); closing the connection"
            ),
            Err(_) => eprintln!(
                "kharond: warning: lock: disposing agent {agent_id}'s browser context timed out \
                 after {} ms; closing the connection",
                budget.as_millis()
            ),
        }
    }
    c.browser.client().close().await;
}

/// Connect to `endpoint` and create `agent_id`'s browser context within
/// `budget`. On any failure after the socket opened the connection is
/// closed, so a context whose reply was lost or late is disposed by the
/// browser rather than left behind.
async fn open_agent_browser(
    endpoint: &CdpEndpoint,
    agent_id: &str,
    budget: Duration,
    generation: u64,
) -> Result<Cached, String> {
    let until = tokio::time::Instant::now() + budget;
    let client = match tokio::time::timeout_at(until, CdpClient::connect(endpoint)).await {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("cdp connect timed out".into()),
    };
    let browser = Browser::new(client.clone());
    let error = match tokio::time::timeout_at(until, browser.create_agent_context(agent_id)).await {
        Ok(Ok(ctx)) => {
            return Ok(Cached {
                engine: FillEngine::new(browser.clone()),
                browser,
                ctx,
                generation,
            });
        }
        Ok(Err(e)) => e.to_string(),
        Err(_) => "cdp createBrowserContext timed out".to_owned(),
    };
    client.close().await;
    Err(error)
}

impl FillBackend for ConnectingCdpBackend {
    fn has_agent(&self, agent_id: &str) -> bool {
        self.agents.contains_key(agent_id)
    }

    fn fill<'a>(
        &'a self,
        agent_id: &'a str,
        plan: &'a FillPlan,
        allow_default: bool,
    ) -> FillFuture<'a> {
        self.fill_in_generation(agent_id, plan, allow_default, self.generation())
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn fill_in_generation<'a>(
        &'a self,
        agent_id: &'a str,
        plan: &'a FillPlan,
        allow_default: bool,
        generation: u64,
    ) -> FillFuture<'a> {
        Box::pin(async move {
            let Some(agent) = self.agents.get(agent_id) else {
                return FillOutcome::TargetNotOwned;
            };
            let c = match agent
                .engine(
                    agent_id,
                    self.connect_timeout,
                    self.teardown_timeout,
                    generation,
                    &self.generation,
                )
                .await
            {
                Ok(c) => c,
                Err(outcome) => return outcome,
            };
            // Last check before the first page-level CDP command: a lock
            // after this point disposes the context under the fill, whose
            // next command then fails (`cdp_error`).
            if self.generation() != generation {
                return FillOutcome::Error(LOCKED_DURING_FILL.into());
            }
            c.engine.fill(plan, &c.ctx, allow_default).await
        })
    }

    /// Advance the generation (so nothing opened before this lock is
    /// reused or cached) and tear every cached session down in the
    /// background. Without a tokio runtime (sync callers) only the
    /// generation moves; stale entries are then torn down by the next
    /// fill that meets them.
    fn on_lock(&self) {
        let lock_generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        for (agent_id, agent) in &self.agents {
            rt.spawn(close_cached(
                Arc::clone(&agent.live),
                agent_id.clone(),
                lock_generation,
                self.teardown_timeout,
            ));
        }
    }
}

// ---------------------------------------------------------------- policy

/// The `[policy]` settings a fill uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FillPolicy {
    /// REQ-API-009 end-to-end bound (resolve + fill). Default 10 s.
    pub deadline: Duration,
    /// REQ-ARCH-005 single-agent escape hatch.
    pub allow_default_context: bool,
    /// REQ-ORG-001 cross-origin iframe allow-list.
    pub cross_origin_iframe_hosts: Vec<String>,
}

impl Default for FillPolicy {
    fn default() -> Self {
        Self {
            deadline: DEFAULT_FILL_DEADLINE,
            allow_default_context: false,
            cross_origin_iframe_hosts: Vec::new(),
        }
    }
}

impl From<&PolicyConfig> for FillPolicy {
    fn from(p: &PolicyConfig) -> Self {
        Self {
            deadline: p.fill_deadline,
            allow_default_context: p.allow_default_context,
            cross_origin_iframe_hosts: p.allow_cross_origin_iframe_hosts.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "5d38619a-0591-4d2d-ab79-3d34e7a88f66";

    fn body(v: serde_json::Value) -> Vec<u8> {
        v.to_string().into_bytes()
    }

    fn fill(v: serde_json::Value) -> Result<FillRequest, ApiError> {
        parse_fill(FillOperation::Fill, &body(v))
    }

    fn detail(r: Result<FillRequest, ApiError>) -> Detail {
        r.unwrap_err().detail
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "item_id": ID,
            "target": { "cdp_target_id": "t1", "expected_origin": "https://login.example.com" },
            "fields": [{ "kind": "username" }, { "kind": "password", "selector": "#pw" }],
        })
    }

    #[test]
    fn parses_a_full_request() {
        let r = fill(base()).unwrap();
        assert_eq!(r.item_id, ID);
        assert_eq!(r.target_id, "t1");
        assert_eq!(
            r.fields,
            vec![
                (FieldKind::Username, None),
                (FieldKind::Password, Some("#pw".to_string()))
            ]
        );
        assert!(!r.submit);
        assert_eq!(r.grant_id, None);
        let mut v = base();
        v["submit"] = true.into();
        v["item_id"] = ID.to_ascii_uppercase().into();
        let r = fill(v).unwrap();
        assert!(r.submit);
        assert_eq!(r.item_id, ID, "canonicalized");
    }

    #[test]
    fn refuses_malformed_requests_with_fixed_details() {
        assert_eq!(
            detail(parse_fill(FillOperation::Fill, b"{not json")),
            Detail::InvalidJsonBody
        );
        let mut v = base();
        v["extra"] = 1.into();
        assert_eq!(detail(fill(v)), Detail::InvalidFillRequest);
        let mut v = base();
        v["target"]["frame_id"] = "f1".into();
        assert_eq!(detail(fill(v)), Detail::FrameIdUnsupported);
        let mut v = base();
        v["target"]["frame_id"] = serde_json::Value::Null;
        assert!(fill(v).is_ok(), "null frame_id is omitted");
        let mut v = base();
        v["item_id"] = "not-a-uuid".into();
        assert_eq!(detail(fill(v)), Detail::InvalidItemId);
        let mut v = base();
        v["fields"] = serde_json::json!([]);
        assert_eq!(detail(fill(v)), Detail::NoFillFields);
        let mut v = base();
        v["fields"] = serde_json::json!([{ "kind": "password" }, { "kind": "password" }]);
        assert_eq!(detail(fill(v)), Detail::DuplicateFillField);
        let mut v = base();
        v["fields"] = serde_json::json!([{ "kind": "secret" }]);
        assert_eq!(detail(fill(v)), Detail::InvalidFillRequest);
        let mut v = base();
        v["target"]["expected_origin"] = "javascript:alert(1)".into();
        assert_eq!(detail(fill(v)), Detail::InvalidOrigin);
        let mut v = base();
        v["target"]["cdp_target_id"] = "x".repeat(MAX_TARGET_ID_LEN + 1).into();
        assert_eq!(detail(fill(v)), Detail::FieldTooLong);
        let mut v = base();
        v["grant_id"] = "g".repeat(MAX_GRANT_ID_LEN + 1).into();
        assert_eq!(detail(fill(v)), Detail::FieldTooLong);
    }

    #[test]
    fn fill_totp_defaults_to_one_totp_field() {
        let mut v = base();
        v.as_object_mut().unwrap().remove("fields");
        let r = parse_fill(FillOperation::FillTotp, &body(v)).unwrap();
        assert_eq!(r.fields, vec![(FieldKind::Totp, None)]);
        assert_eq!(r.operation, FillOperation::FillTotp);
        let mut v = base();
        v["fields"] = serde_json::json!([{ "kind": "totp", "selector": "#otp" }]);
        let r = parse_fill(FillOperation::FillTotp, &body(v)).unwrap();
        assert_eq!(r.fields, vec![(FieldKind::Totp, Some("#otp".to_string()))]);
        // A password is not a TOTP field.
        let v = base();
        assert_eq!(
            detail(parse_fill(FillOperation::FillTotp, &body(v))),
            Detail::InvalidFillRequest
        );
    }

    #[test]
    fn statuses_are_spec_values() {
        assert_eq!(FillStatus::UnknownItem.result().status, "not_found");
        assert_eq!(
            FillStatus::Unavailable.result().detail,
            Some("fill_unavailable")
        );
        let filled = FillStatus::Engine(FillOutcome::Filled {
            kinds: vec![FieldKind::Password],
        })
        .result();
        assert_eq!(
            serde_json::to_value(filled).unwrap(),
            serde_json::json!({ "status": "filled", "fields_filled": ["password"] })
        );
    }
}
