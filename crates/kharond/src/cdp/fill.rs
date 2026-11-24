//! The broker-side half of the isolated-world atomic fill (SPEC §6).
//!
//! Implements the spec's four steps against one CDP connection:
//!
//! 1. Read the page's live origin from the browser's own frame tree /
//!    target info — never from agent input (REQ-ORG-002) — and decide
//!    the item's matchers against it. Out-of-origin and insecure pages
//!    are refused here, before any page code runs (REQ-ORG-005).
//! 2. `Page.createIsolatedWorld` in the target's main frame, then one
//!    synchronous `Runtime.callFunctionOn` of [`FILL_IN_PAGE`]. The
//!    check-and-set is atomic because the whole thing is one JS task
//!    (REQ-ORG-003).
//! 3. A destroyed execution context surfaces as a CDP error naming the
//!    missing context — reported as `navigated` per the spec's mapping.
//! 4. Re-read the loader via `Page.getFrameTree`; if it changed and the
//!    in-page call did not itself dispatch submit, run [`CLEAR_IN_PAGE`]
//!    in the old world (best effort) and report `navigated`. A loader
//!    change after a successful `submit: true` call is that submit's own
//!    navigation: report `filled` with `fields_filled` (REQ-API-008, #102).
//!    When the post-submit scrub is on (#355) and that navigation has
//!    not happened, the engine waits and clears the elements this fill
//!    wrote if they still hold its values. The wait and the clear are
//!    inside this future, so a drop sends no clear.
//!
//! Ownership (REQ-ARCH-005) gates step 1: the target must live in the
//! requesting agent's browser context, or the default context when
//! `allow_default` is set.
//!
//! This module is the fill engine. It writes no audit entry — the
//! daemon's one fill path, `fill` and `fill_totp` alike, is
//! [`crate::api::Broker::fill`], which owns the REQ-AUD-003† dispatch /
//! outcome audit pair around [`FillEngine::fill`] (#73, #77, #88).
//! REQ-API-009's end-to-end deadline is still owned by the broker, but
//! the engine converts the remainder into a page-side relative budget
//! at dispatch (`FillPlan.deadline` / [`page_budget`], #118) so a
//! single in-page step can abort ahead of the broker's cut-off.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::origin::{MismatchReason, OriginConfig, OriginMatcher};

use super::browser::{AgentContext, Browser, OwnershipError};
use super::client::CdpError;
use super::method::{
    MethodEnd, MethodNote, MethodResult, MethodSource, MethodUse, Prepared, judge, prepare,
};
use super::page_js::{
    CLEAR_IN_PAGE, FILL_IN_PAGE, METHOD_PROBE_IN_PAGE, PROBE_WRITTEN_IN_PAGE, SCRUB_WRITTEN_IN_PAGE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Username,
    Password,
    Totp,
}

impl FieldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
        }
    }
}

/// One field of one fill. `value` is secret material; it is wrapped in
/// [`Zeroizing`] so the broker zeroes it on drop.
#[derive(Debug, Clone)]
pub struct FieldFill {
    pub kind: FieldKind,
    pub selector: Option<String>,
    pub value: Zeroizing<String>,
}

/// Everything the broker needs for one atomic fill attempt.
#[derive(Debug, Clone)]
pub struct FillPlan {
    pub target_id: String,
    pub fields: Vec<FieldFill>,
    /// Decrypted item URIs as matchers; any match allows (mirrors the
    /// vault's per-URI semantics).
    pub item_matchers: Vec<OriginMatcher>,
    pub origin_cfg: OriginConfig,
    /// Hosts permitted for cross-origin iframe targets (REQ-ORG-004).
    /// Empty list refuses every cross-origin iframe fill.
    pub cross_origin_iframe_hosts: Vec<String>,
    /// REQ-API-008: dispatch submit (Enter on the last field, or
    /// `form.requestSubmit()` in the isolated world) after every field
    /// fills successfully. Never dispatched on a fill failure; on a
    /// timeout the broker sends nothing further, but an in-page call
    /// already dispatched still submits (see [`FillEngine::fill`], #46).
    pub submit: bool,
    /// The agent's claimed origin (`FillRequest.target.expected_origin`).
    /// Never evidence (REQ-ORG-002): the live origin decides. It can
    /// only refuse: a claim that differs from the live origin of the
    /// target is `origin_mismatch` before any page code runs
    /// (REQ-APR-007's "claims A while the tab is on B"). `None` skips
    /// the comparison (engine-level callers).
    pub expected_origin: Option<String>,
    /// Where the engine records the target's live origin once it has
    /// read it from the browser (REQ-AUD-003†, #67). The broker copies
    /// it into the fill's outcome audit entry.
    pub live_origin: LiveOrigin,
    /// The REQ-API-009 end-to-end deadline for this fill, when the
    /// caller runs under one (the broker sets it; engine-level callers
    /// leave `None`). At dispatch the engine converts what remains of
    /// it into the page-side relative budget (#118): the in-page call
    /// gets `remaining − RETURN_MARGIN` as `budgetMs` (margin capped
    /// at half the remainder), and a remainder that is already gone
    /// is not dispatched at all — the fill is
    /// [`FillOutcome::Timeout`] before the call is sent.
    pub deadline: Option<Instant>,
    /// Set by the engine just before it sends the single in-page fill
    /// call that carries the field values (REQ-APR-008, #151). The
    /// broker gives the grant use back when a fill ends with this
    /// still unset: no value ever left the broker.
    pub values_sent: ValuesSent,
    /// Opt-in post-submit scrub (#355, REQ-API-013). The broker sets
    /// the effective value: the per-fill override if the fill named
    /// one, otherwise `[policy] post_submit_scrub` (default false).
    /// Ignored unless [`Self::submit`] is set. When it runs, the
    /// engine records the outcome on [`Self::scrub`].
    pub post_submit_scrub: bool,
    /// How long to wait before the one re-read. `[policy]
    /// post_submit_scrub_delay`, default [`DEFAULT_POST_SUBMIT_SCRUB_DELAY`].
    pub post_submit_scrub_delay: Duration,
    /// What the post-submit scrub observed, if it was attempted.
    /// Shared by every clone of the plan, like [`LiveOrigin`].
    pub scrub: ScrubNote,
    /// Where to look up the site's taught login method (#382). `None`
    /// never consults a registry. The lookup uses the live URL the
    /// browser reports, never the agent's claim.
    pub method_source: Option<Arc<dyn MethodSource>>,
    /// How this fill used a method, if it consulted one. Write-once,
    /// shared by every clone of the plan.
    pub method: MethodNote,
}

/// The live origin one fill observed (REQ-AUD-003†, #67): the
/// serialized origin (`scheme://host[:port]`, or `null` for an opaque
/// origin such as `about:blank`) of the target's URL as the browser
/// reported it in step 1, after the ownership check passed. Never the
/// full URL: path, query and fragment can carry tokens.
///
/// A write-once slot shared by every clone of the [`FillPlan`] that
/// carries it, so the broker can still read what was observed when the
/// fill future was dropped (deadline, client disconnect). Empty when
/// the fill stopped before the read or the target was not the agent's
/// (another context's page is never recorded).
#[derive(Debug, Clone, Default)]
pub struct LiveOrigin(Arc<OnceLock<String>>);

impl LiveOrigin {
    /// An empty slot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the origin of `href` (first write wins; an unparsable
    /// URL records nothing).
    pub fn record_href(&self, href: &str) {
        if let Ok(u) = url::Url::parse(href) {
            let _ = self.0.set(u.origin().ascii_serialization());
        }
    }

    /// The recorded origin, if any.
    pub fn get(&self) -> Option<String> {
        self.0.get().cloned()
    }
}

/// Whether a fill sent its field values to the browser (REQ-APR-008,
/// #151). Shared by every clone of the [`FillPlan`] that carries it, so
/// the broker can read it after the fill future was dropped. It is set
/// before the in-page call is sent, not after it is delivered: a call
/// caught mid-send counts as sent, which keeps the grant use spent.
#[derive(Debug, Clone, Default)]
pub struct ValuesSent(Arc<AtomicBool>);

impl ValuesSent {
    /// Not sent yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The values are about to leave the broker.
    pub fn mark(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`Self::mark`] ran.
    pub fn get(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What one post-submit scrub did (#355). Counts only: a value never
/// fits in here. `Cleared`'s number is how many recorded elements the
/// in-page call reported blanking, already capped at the field count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubObservation {
    /// At least one recorded element was blanked.
    Cleared(u64),
    /// The page was still the filled document, and nothing was blanked
    /// (the values had changed, the nodes were gone, or the clear
    /// could not be confirmed).
    Nothing,
    /// The loader changed, or the filled world was gone. Nothing was
    /// cleared: the page had left the form.
    Navigated,
}

impl ScrubObservation {
    /// Audit `result` for a `fill_scrub` entry.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cleared(_) => "cleared",
            Self::Nothing => "nothing",
            Self::Navigated => "navigated",
        }
    }

    /// How many elements were blanked, when that number is worth
    /// recording. `None` for a scrub that blanked nothing.
    pub fn cleared(self) -> Option<u64> {
        match self {
            Self::Cleared(n) if n > 0 => Some(n),
            _ => None,
        }
    }
}

/// The scrub observation for one fill (REQ-API-013, #355). Write-once,
/// shared by every clone of the [`FillPlan`] that carries it, so the
/// broker can read it after the engine returns. Empty when the scrub
/// was not attempted: it is off, the deadline could not cover the
/// delay, or this future was dropped before the check finished.
#[derive(Debug, Clone, Default)]
pub struct ScrubNote(Arc<OnceLock<ScrubObservation>>);

impl ScrubNote {
    /// An empty slot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the observation (first write wins).
    pub fn record(&self, obs: ScrubObservation) {
        let _ = self.0.set(obs);
    }

    /// The recorded observation, if the scrub was attempted.
    pub fn get(&self) -> Option<ScrubObservation> {
        self.0.get().copied()
    }
}

/// The outcome of one fill attempt, one-to-one with `FillResult.status`
/// in SPEC §6.
#[derive(Debug, PartialEq, Eq)]
pub enum FillOutcome {
    Filled {
        kinds: Vec<FieldKind>,
    },
    OriginMismatch,
    NonSecureContext,
    /// REQ-ORG-004: the target is an out-of-process iframe whose host
    /// is not in `allow_cross_origin_iframe_hosts`. Reported as
    /// `origin_mismatch` with its own detail code (#180), decided in
    /// step 1, before any value is sent.
    IframeNotAllowlisted,
    Navigated,
    FieldNotFound {
        kinds: Vec<FieldKind>,
    },
    TargetNotOwned,
    DefaultContextRefused,
    UnknownTarget,
    /// REQ-API-009: the end-to-end fill deadline expired. Reported by
    /// [`crate::api::Broker::fill`] after dropping the engine future
    /// (no further broker-side CDP writes) and zeroizing the plan, and
    /// also returned by [`FillEngine::fill`] itself when the page-side
    /// budget (#118) ends the fill: the in-page call threw
    /// `kharon:deadline`, or the remainder at dispatch was already
    /// zero so the call was never sent (`PageBudget::Exhausted`). Under
    /// the half-cap margin (`margin = min(250ms, remaining/2)`) a
    /// positive remainder always yields a usable budget of at least
    /// 1 ms — only a zero remainder refuses dispatch here. Not a
    /// guarantee that nothing happened in the page: an in-page fill
    /// call dispatched before expiry may still complete a step already
    /// running (see [`FillEngine::fill`], #46).
    Timeout,
    /// REQ-API-007: `fill_totp` refused because the last clock sample
    /// exceeded `clock_skew_refuse`. No CDP call was made.
    ClockSkew,
    /// REQ-API-007: the item's TOTP field is not a supported
    /// `otpauth://totp`, `steam://` or base32 secret. No CDP call was
    /// made.
    TotpUnsupported,
    /// #382: a method fill ended before or in the page, with status
    /// `field_not_found` and these fixed details. The first three end
    /// before anything is sent to the page.
    MethodWrongPage,
    MethodStale,
    MethodFieldNotRequested,
    /// The page no longer matches the recorded step (flat step index).
    MethodDrift {
        step: u32,
    },
    /// The recorded element is there but disabled.
    MethodNotReady {
        step: u32,
    },
    Error(String),
}

impl FillOutcome {
    /// SPEC §4 `FillResult.status`.
    pub fn status(&self) -> &'static str {
        match self {
            Self::Filled { .. } => "filled",
            Self::OriginMismatch | Self::NonSecureContext | Self::IframeNotAllowlisted => {
                "origin_mismatch"
            }
            Self::Navigated => "navigated",
            Self::FieldNotFound { .. }
            | Self::MethodWrongPage
            | Self::MethodStale
            | Self::MethodFieldNotRequested
            | Self::MethodDrift { .. }
            | Self::MethodNotReady { .. } => "field_not_found",
            Self::TargetNotOwned | Self::DefaultContextRefused => "target_not_owned",
            Self::UnknownTarget => "not_found",
            Self::Timeout => "timeout",
            Self::ClockSkew | Self::TotpUnsupported | Self::Error(_) => "error",
        }
    }

    /// SPEC §4 `FillResult.detail`: fixed codes only, never a value
    /// (REQ-API-006). `Error`'s CDP message is not exposed.
    pub fn detail(&self) -> Option<&'static str> {
        match self {
            Self::NonSecureContext => Some("insecure_context"),
            Self::IframeNotAllowlisted => Some("iframe_not_allowlisted"),
            Self::DefaultContextRefused => Some("default_context_refused"),
            Self::UnknownTarget => Some("unknown_target"),
            Self::ClockSkew => Some("clock_skew"),
            Self::TotpUnsupported => Some("totp_unsupported"),
            Self::MethodWrongPage => Some("method_wrong_page"),
            Self::MethodStale => Some("method_stale"),
            Self::MethodFieldNotRequested => Some("method_field_not_requested"),
            Self::MethodDrift { .. } => Some("method_drift"),
            Self::MethodNotReady { .. } => Some("method_not_ready"),
            Self::Error(_) => Some("cdp_error"),
            _ => None,
        }
    }

    /// SPEC §4 `FillResult.fields_filled`: kinds only.
    pub fn fields_filled(&self) -> Vec<&'static str> {
        match self {
            Self::Filled { kinds } => kinds.iter().map(|k| k.as_str()).collect(),
            _ => Vec::new(),
        }
    }

    /// The SPEC §4 `FillResult` body for this outcome (`status`,
    /// `fields_filled`, optional `detail`). Built from kinds and fixed
    /// strings only: there is no field a value could travel in
    /// (REQ-API-007 "the code is never returned"; G1).
    pub fn result_body(&self) -> Value {
        let mut body = json!({
            "status": self.status(),
            "fields_filled": self.fields_filled(),
        });
        if let Some(d) = self.detail() {
            body["detail"] = json!(d);
        }
        body
    }
}

impl From<OwnershipError> for FillOutcome {
    fn from(e: OwnershipError) -> Self {
        match e {
            OwnershipError::TargetNotOwned => Self::TargetNotOwned,
            OwnershipError::DefaultContextRefused => Self::DefaultContextRefused,
            OwnershipError::UnknownTarget => Self::UnknownTarget,
            OwnershipError::Cdp(msg) => Self::Error(msg),
        }
    }
}

#[derive(Clone)]
pub struct FillEngine {
    browser: Browser,
}

impl FillEngine {
    pub fn new(browser: Browser) -> Self {
        Self { browser }
    }

    /// Whether the engine's CDP connection has ended (see
    /// [`super::CdpClient::is_closed`]).
    pub fn is_closed(&self) -> bool {
        self.browser.client().is_closed()
    }

    /// Open `url` in a new tab and return `(target_id, live origin)`.
    /// The URL is not copied into the error (REQ-API-012).
    pub async fn open_login(
        &self,
        url: &str,
        agent_ctx: &AgentContext,
        allow_default: bool,
    ) -> Result<(String, String), OwnershipError> {
        self.browser
            .open_login_tab(agent_ctx, allow_default, url)
            .await
    }

    /// The live serialized origin of `target_id` (REQ-APR-007, #20):
    /// the ownership check a fill runs in its step 1, and nothing
    /// else — no attach, no page code. Grant requests observe through
    /// this so a prompt can show where the tab actually is, never
    /// the agent's claim (REQ-ORG-002). An opaque origin (e.g.
    /// `about:blank`) reports as `null`, like [`LiveOrigin`].
    pub async fn observe_origin(
        &self,
        target_id: &str,
        agent_ctx: &AgentContext,
        allow_default: bool,
    ) -> Result<String, OwnershipError> {
        let info = self
            .browser
            .check_ownership(target_id, agent_ctx, allow_default)
            .await?;
        Ok(url::Url::parse(&info.url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_else(|_| "null".to_owned()))
    }

    /// Run one fill attempt (SPEC §6 steps 1–4) and classify it.
    ///
    /// The engine writes no audit entry. The daemon's only fill path,
    /// `fill` and `fill_totp` alike, is [`crate::api::Broker::fill`]
    /// (through its [`crate::api::FillBackend`]), which owns the
    /// REQ-AUD-003† `fill_dispatch` / outcome pair and the REQ-API-009
    /// end-to-end deadline; on expiry it drops this future, zeroizes
    /// the plan and appends `fill_timeout`. At dispatch the engine
    /// still converts the deadline remainder into a page-side budget
    /// (`FillPlan.deadline` / [`page_budget`], #118).
    ///
    /// # Cancellation: what "fails closed" does *not* cover (#46)
    ///
    /// REQ-API-009 reads "no further CDP writes, submit not dispatched".
    /// Dropping this future enforces only the first half, and only
    /// broker-side: the broker stops *sending*, but it cannot recall a
    /// frame the browser already has. A `Runtime.callFunctionOn` of
    /// `FILL_IN_PAGE` dispatched before the deadline runs the in-page
    /// function to completion: it fills every field **and, when
    /// `plan.submit` is set, submits the form**, possibly *after* the
    /// broker has replied `timeout`. The page-side relative budget
    /// (#118) narrows this for an honest-but-slow page: the in-page
    /// function checks its budget before each field write and before
    /// the submit dispatch, and aborts (fields cleared) at the first
    /// step boundary past it — but a single step already running (a
    /// page handler that never returns) still cannot be preempted.
    /// "Submit not dispatched" holds in the
    /// strong sense only when the deadline expires before the fill call
    /// is sent (ownership check, attach, frame tree, isolated world);
    /// after that it means "no *separate* submit write is sent", which is
    /// vacuous here because submit rides inside the one in-page call
    /// (REQ-ORG-003's atomic check-and-set). The `timeout` reply is thus
    /// "the broker could not confirm the fill in time", not "nothing
    /// happened in the page". Likewise the post-fill loader re-check,
    /// the `CLEAR_IN_PAGE` scrub (step 4), and the post-submit scrub
    /// (#355) never run after a drop: the delay and the clear sit in
    /// this future, and a drop sends no clear.
    ///
    /// "Dispatched" has a crisp boundary (#76): a frame is on the wire
    /// once its `send` returned. If the future is dropped while the fill
    /// frame is still mid-`send` on the shared websocket sink, the
    /// connection is poisoned ([`super::CdpError::Poisoned`]): the sink is
    /// dropped with whatever it buffered unflushed, so no later write on
    /// that connection (another request's, or the close frame) can carry
    /// the frame out after expiry. Bytes the kernel already accepted may
    /// still reach the browser, but a truncated frame is not a command.
    /// The engine then reports [`FillEngine::is_closed`] and the daemon
    /// reconnects on the next fill.
    ///
    /// Secrets live canonically in `plan.fields[*].value`
    /// (`Zeroizing<String>`). Copies inside a dropped fill future are
    /// freed by the allocator unzeroed — the same documented class as
    /// tungstenite's internal send buffer (see [`crate::cdp::client`]).
    pub async fn fill(
        &self,
        plan: &FillPlan,
        agent_ctx: &AgentContext,
        allow_default: bool,
    ) -> FillOutcome {
        // Step 1: live page state, ownership, broker-side origin and
        // secure-context decisions. No page code has run yet.
        let info = match self
            .browser
            .check_ownership(&plan.target_id, agent_ctx, allow_default)
            .await
        {
            Ok(info) => info,
            Err(e) => return FillOutcome::from(e),
        };
        // Owned target: its live origin is audit evidence from here on,
        // whatever the outcome (REQ-AUD-003†, #67).
        plan.live_origin.record_href(&info.url);

        // The agent's claim can only narrow: claim ≠ live → refuse.
        if let Some(claimed) = &plan.expected_origin
            && !claim_matches(claimed, &info.url)
        {
            return FillOutcome::OriginMismatch;
        }

        if info.type_ == "iframe" {
            let host = match url_host(&info.url) {
                Some(h) => h,
                None => return FillOutcome::IframeNotAllowlisted,
            };
            if !plan
                .cross_origin_iframe_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&host))
            {
                return FillOutcome::IframeNotAllowlisted;
            }
        }

        // REQ-ORG-002: the page URL the browser reports is the only
        // origin evidence. Decide every matcher; remember the closest
        // refusal to report.
        let mut best: Option<Decision_> = None;
        let mut allowed = false;
        for m in &plan.item_matchers {
            let decision = m.decide(&info.url, &plan.origin_cfg);
            if decision.allowed {
                allowed = true;
                break;
            }
            best = Some(Decision_(decision.reason));
        }
        if !allowed {
            return match best.and_then(|b| b.0) {
                Some(MismatchReason::SchemeNotHttps) | Some(MismatchReason::HttpNotAllowed) => {
                    FillOutcome::NonSecureContext
                }
                _ => FillOutcome::OriginMismatch,
            };
        }

        // #382: a site with a taught login method is filled by the
        // method's steps. The lookup uses the URL read above.
        let requested: Vec<FieldKind> = plan.fields.iter().map(|f| f.kind).collect();
        let lookup = plan
            .method_source
            .as_ref()
            .filter(|_| {
                requested
                    .iter()
                    .any(|k| matches!(k, FieldKind::Username | FieldKind::Password))
            })
            .and_then(|source| source.lookup(&info.url));
        let selectors_ignored = plan.fields.iter().any(|f| f.selector.is_some());
        let mut prepared: Option<Prepared> = None;
        if let Some(lookup) = &lookup {
            match prepare(
                lookup,
                &info.url,
                &requested,
                plan.submit,
                plan.post_submit_scrub,
            ) {
                Ok(p) => prepared = Some(p),
                Err(end) => {
                    // Nothing was sent to the browser.
                    plan.method.record(MethodUse {
                        domain: lookup.domain.clone(),
                        rung: lookup.method.rung,
                        end,
                        selectors_ignored,
                        browser_product: None,
                    });
                    return match end {
                        MethodEnd::Stale => FillOutcome::MethodStale,
                        MethodEnd::FieldNotRequested => FillOutcome::MethodFieldNotRequested,
                        _ => FillOutcome::MethodWrongPage,
                    };
                }
            }
        }
        // Read once per connection, before the values are anywhere near
        // the wire, so a slow browser cannot eat the deadline afterwards.
        let product = match prepared {
            Some(_) => self.browser.product().await,
            None => None,
        };
        let is_method = prepared.is_some();
        // The leg decides which values go to the page, and in what order.
        let ordered: Vec<&FieldFill> = match &prepared {
            Some(p) => p
                .order
                .iter()
                .filter_map(|k| plan.fields.iter().find(|f| f.kind == *k))
                .collect(),
            None => plan.fields.iter().collect(),
        };
        // The leg argument holds selectors and shape checks only.
        let leg_arg = match &prepared {
            Some(p) => serde_json::to_value(&p.leg).expect("leg serializes"),
            None => Value::Null,
        };

        let specs: Vec<Value> = plan
            .item_matchers
            .iter()
            .map(|m| serde_json::to_value(m.in_page_spec()).expect("spec serializes"))
            .collect();
        // In leg mode the agent's selector is dropped here: the page
        // only ever sees the method's.
        let selector_of = |f: &FieldFill| if is_method { None } else { f.selector.clone() };
        let mut field_args: Vec<Value> = ordered
            .iter()
            .map(|f| {
                json!({
                    "kind": f.kind.as_str(),
                    "selector": selector_of(f),
                    "value": &*f.value,
                })
            })
            .collect();
        let clear_args: Vec<Value> = ordered
            .iter()
            .map(|f| json!({ "kind": f.kind.as_str(), "selector": selector_of(f) }))
            .collect();

        let session = match self.browser.client().attach(&plan.target_id).await {
            Ok(s) => s,
            Err(CdpError::Protocol { code: -32000, .. }) => return FillOutcome::UnknownTarget,
            Err(e) => return FillOutcome::Error(e.to_string()),
        };

        // `submit` is checked here, not only by the broker: a plan that
        // sets the scrub flag on a non-submit fill must not wait or
        // send the values again (#355 review).
        let (submit, scrub_on) = match &prepared {
            Some(p) => (p.submit, p.scrub),
            None => (plan.submit, plan.submit && plan.post_submit_scrub),
        };
        let scrub = scrub_on.then_some((&plan.scrub, plan.post_submit_scrub_delay));
        let mut run = prepared.as_ref().map(|prepared| MethodRun {
            prepared,
            delay: plan.post_submit_scrub_delay,
            result: None,
        });
        let outcome = self
            .fill_attached(
                &session,
                &specs,
                &field_args,
                &clear_args,
                &info.url,
                submit,
                plan.deadline,
                &plan.values_sent,
                scrub,
                &leg_arg,
                run.as_mut(),
            )
            .await;

        // REQ-CRY-006: the plan's values are Zeroizing and the wire
        // copy is zeroized in `request_inner`; these serde_json copies
        // are the broker's remaining plaintext secrets — wipe them
        // before the Vec drops.
        for arg in &mut field_args {
            if let Some(obj) = arg.as_object_mut() {
                if let Some(Value::String(s)) = obj.get_mut("value") {
                    s.zeroize();
                }
                if let Some(v) = obj.get_mut("value") {
                    *v = Value::Null;
                }
            }
        }

        session.detach().await;

        if let (Some(lookup), Some(run)) = (&lookup, &run) {
            let end = match &outcome {
                FillOutcome::Filled { .. } => {
                    MethodEnd::Filled(run.result.unwrap_or(MethodResult::Unconfirmed))
                }
                FillOutcome::MethodWrongPage => MethodEnd::WrongPage,
                FillOutcome::MethodDrift { step } => MethodEnd::Drift { step: *step },
                FillOutcome::MethodNotReady { step } => MethodEnd::NotReady { step: *step },
                _ => MethodEnd::Other,
            };
            let reached = !matches!(end, MethodEnd::Other);
            plan.method.record(MethodUse {
                domain: lookup.domain.clone(),
                rung: run.prepared.rung,
                end,
                selectors_ignored,
                browser_product: if reached { product } else { None },
            });
        }
        outcome
    }

    /// Steps 2–4 with the session attached.
    #[allow(clippy::too_many_arguments)]
    async fn fill_attached(
        &self,
        session: &super::client::CdpSession,
        specs: &[Value],
        field_args: &[Value],
        clear_args: &[Value],
        live_url: &str,
        submit: bool,
        deadline: Option<Instant>,
        values_sent: &ValuesSent,
        scrub: Option<(&ScrubNote, Duration)>,
        leg: &Value,
        mut method: Option<&mut MethodRun<'_>>,
    ) -> FillOutcome {
        // Step 1's frame-tree read: the loader id we'll re-check against.
        let tree = match session.request("Page.getFrameTree", json!({})).await {
            Ok(t) => t,
            Err(CdpError::Protocol { code: -32000, .. }) => return FillOutcome::Navigated,
            Err(e) => return FillOutcome::Error(e.to_string()),
        };
        let frame = match tree_frame(&tree) {
            Some(f) => f.clone(),
            None => return FillOutcome::Error("frame tree missing main frame".into()),
        };
        let frame_id = match frame.get("id").and_then(Value::as_str) {
            Some(id) => id.to_string(),
            None => return FillOutcome::Error("frame has no id".into()),
        };
        let loader_before = frame
            .get("loaderId")
            .and_then(Value::as_str)
            .map(String::from);
        let expected_top_origin = expected_origin(live_url);

        // Step 2: isolated world + one synchronous check-and-set call.
        let world = match session
            .request(
                "Page.createIsolatedWorld",
                json!({ "frameId": frame_id, "worldName": "kharon_fill" }),
            )
            .await
        {
            Ok(w) => w,
            Err(CdpError::Protocol { code: -32000, .. }) => return FillOutcome::Navigated,
            Err(e) => return FillOutcome::Error(e.to_string()),
        };
        let context_id = match world.get("executionContextId").and_then(Value::as_u64) {
            Some(id) => id,
            None => return FillOutcome::Error("createIsolatedWorld lacked context id".into()),
        };

        // #118: convert what is left of the REQ-API-009 deadline into
        // the page-side relative budget at the last moment, so the
        // setup above is charged against it. Only a zero remainder is
        // refused here (`PageBudget::Exhausted`); under the half-cap
        // margin a positive remainder always yields ≥1 ms. The broker
        // maps Exhausted to the same `timeout` outcome as an expiry it
        // observed itself.
        let budget_ms = match page_budget(deadline, Instant::now()) {
            PageBudget::Exhausted => return FillOutcome::Timeout,
            PageBudget::Budget(ms) => ms,
            PageBudget::NoCheck => 0,
        };

        // REQ-APR-008 (#151): the values leave the broker with this
        // call. Marked before the send, so a call caught mid-send
        // still counts as sent and the grant use stays spent.
        values_sent.mark();
        let call = session
            .request_with_timeout(
                "Runtime.callFunctionOn",
                json!({
                    "functionDeclaration": FILL_IN_PAGE,
                    "executionContextId": context_id,
                    "arguments": [
                        { "value": specs },
                        { "value": field_args },
                        { "value": expected_top_origin },
                        { "value": submit },
                        { "value": budget_ms },
                        { "value": scrub.is_some() },
                        { "value": leg },
                    ],
                    "returnByValue": true,
                    "awaitPromise": false,
                }),
                std::time::Duration::from_secs(10),
            )
            .await;

        let result = match call {
            Err(CdpError::Protocol { code, message }) => return map_context_error(code, &message),
            Err(CdpError::Timeout) => return FillOutcome::Error("fill call timed out".into()),
            Err(e) => return FillOutcome::Error(e.to_string()),
            Ok(r) => r,
        };

        if let Some(exception) = result.get("exceptionDetails") {
            let description = exception
                .get("exception")
                .and_then(|e| e.get("description"))
                .and_then(Value::as_str)
                .unwrap_or("");
            return classify_exception(description);
        }

        // Step 4: loader re-check.
        let tree_after = match session.request("Page.getFrameTree", json!({})).await {
            Ok(t) => t,
            Err(_) => {
                let outcome = parse_fill_results(&result);
                if let (Some(run), FillOutcome::Filled { .. }) = (method.as_deref_mut(), &outcome) {
                    run.result = Some(MethodResult::Unconfirmed);
                }
                return outcome;
            }
        };
        let loader_after = tree_frame(&tree_after)
            .and_then(|f| f.get("loaderId"))
            .and_then(Value::as_str)
            .map(String::from);
        // Fail closed (per review): a missing loaderId on either side
        // is not a pass. Real frame trees carry one; absence means the
        // tree we are reading is not the tree we filled.
        match (&loader_before, &loader_after) {
            (Some(before), Some(after)) if before != after => {
                // REQ-API-008 / #102: with `submit: true` the in-page call
                // itself dispatches the form submit, so a loader change
                // after a successful call (exceptions return earlier) is
                // that submit's own navigation — report `filled` with
                // `fields_filled`, do not scrub as navigated-away. A
                // change after `submit: false`, or any failure path, is
                // still `Navigated` / the failure.
                if submit {
                    let outcome = parse_fill_results(&result);
                    if let (Some(run), FillOutcome::Filled { .. }) =
                        (method.as_deref_mut(), &outcome)
                    {
                        // A new document is already committed: its
                        // URL is the path the submit led to.
                        run.result = Some(judge(
                            &run.prepared.success,
                            run.prepared.has_password,
                            true,
                            frame_path(&tree_after).as_deref(),
                            None,
                        ));
                    }
                    // The page already left. The delayed re-read would
                    // see the same thing and must not clear a new
                    // document, so record it and do not wait (#355).
                    if let (Some((note, _)), FillOutcome::Filled { .. }) = (scrub, &outcome) {
                        note.record(ScrubObservation::Navigated);
                    }
                    return outcome;
                }
                // Best-effort scrub in the old world (SPEC step 4).
                let _ = session
                    .request_with_timeout(
                        "Runtime.callFunctionOn",
                        json!({
                            "functionDeclaration": CLEAR_IN_PAGE,
                            "executionContextId": context_id,
                            "arguments": [ { "value": clear_args } ],
                            "returnByValue": true,
                        }),
                        std::time::Duration::from_secs(5),
                    )
                    .await;
                FillOutcome::Navigated
            }
            (Some(before), Some(_)) => {
                let outcome = parse_fill_results(&result);
                if let FillOutcome::Filled { .. } = &outcome {
                    if let Some(run) = method.as_mut() {
                        run.result = Some(
                            self.method_success(
                                session,
                                context_id,
                                field_args,
                                before,
                                deadline,
                                run.prepared,
                                run.delay,
                                scrub.map(|(note, _)| note),
                            )
                            .await,
                        );
                    } else if let Some((note, delay)) = scrub {
                        self.post_submit_scrub(
                            session, context_id, field_args, before, deadline, delay, note,
                        )
                        .await;
                    }
                }
                outcome
            }
            _ => FillOutcome::Error("frame tree loader id missing after fill".into()),
        }
    }

    /// Read a submitted method fill's success once (#382): after the
    /// delay, the one re-read decides whether the loader changed and
    /// where the page is; on the same document the password element is
    /// asked about too. The scrub, when it is on, rides the same
    /// re-read. A fill that did not submit is `Unconfirmed` and reads
    /// nothing.
    #[allow(clippy::too_many_arguments)]
    async fn method_success(
        &self,
        session: &super::client::CdpSession,
        context_id: u64,
        field_args: &[Value],
        loader_before: &str,
        deadline: Option<Instant>,
        prepared: &Prepared,
        delay: Duration,
        scrub: Option<&ScrubNote>,
    ) -> MethodResult {
        if !prepared.submit {
            return MethodResult::Unconfirmed;
        }
        let tree = match reread_frame_tree(session, deadline, delay).await {
            Reread::NoRoom => return MethodResult::Unconfirmed,
            Reread::TimedOut => {
                if let Some(note) = scrub {
                    note.record(ScrubObservation::Nothing);
                }
                return MethodResult::Unconfirmed;
            }
            Reread::Failed => {
                if let Some(note) = scrub {
                    note.record(ScrubObservation::Navigated);
                }
                return MethodResult::Unconfirmed;
            }
            Reread::Tree(t) => t,
        };
        let loader_now = tree_frame(&tree)
            .and_then(|f| f.get("loaderId"))
            .and_then(Value::as_str);
        let loader_changed = loader_now != Some(loader_before);
        let path_now = frame_path(&tree);
        let mut password_connected = None;
        if loader_changed {
            if let Some(note) = scrub {
                note.record(ScrubObservation::Navigated);
            }
        } else {
            if scrub_room(deadline, Duration::ZERO, Instant::now()) {
                let probe = session
                    .request_with_timeout(
                        "Runtime.callFunctionOn",
                        json!({
                            "functionDeclaration": METHOD_PROBE_IN_PAGE,
                            "executionContextId": context_id,
                            "arguments": [],
                            "returnByValue": true,
                            "awaitPromise": false,
                        }),
                        scrub_call_timeout(deadline, Instant::now()),
                    )
                    .await;
                if let Ok(reply) = probe
                    && reply.get("exceptionDetails").is_none()
                {
                    password_connected = reply
                        .pointer("/result/value/password_connected")
                        .and_then(Value::as_bool);
                }
            }
            if let Some(note) = scrub {
                self.clear_if_held(session, context_id, field_args, deadline, note)
                    .await;
            }
        }
        judge(
            &prepared.success,
            prepared.has_password,
            loader_changed,
            path_now.as_deref(),
            password_connected,
        )
    }

    /// One re-read after `delay`, then a clear of the recorded elements
    /// whose values are unchanged (#355). No-op — and no audit note —
    /// when the remaining deadline cannot cover the delay plus
    /// [`RETURN_MARGIN`], so a successful fill is not turned into a
    /// timeout and a clear is never sent once the deadline is too
    /// close. A drop during the wait sends nothing.
    #[allow(clippy::too_many_arguments)]
    async fn post_submit_scrub(
        &self,
        session: &super::client::CdpSession,
        context_id: u64,
        field_args: &[Value],
        loader_before: &str,
        deadline: Option<Instant>,
        delay: Duration,
        note: &ScrubNote,
    ) {
        let tree = match reread_frame_tree(session, deadline, delay).await {
            Reread::NoRoom => return,
            Reread::TimedOut => {
                note.record(ScrubObservation::Nothing);
                return;
            }
            Reread::Failed => {
                note.record(ScrubObservation::Navigated);
                return;
            }
            Reread::Tree(t) => t,
        };
        let loader_now = tree_frame(&tree)
            .and_then(|f| f.get("loaderId"))
            .and_then(Value::as_str);
        if loader_now != Some(loader_before) {
            note.record(ScrubObservation::Navigated);
            return;
        }
        self.clear_if_held(session, context_id, field_args, deadline, note)
            .await;
    }

    /// The tail of the scrub once the page is known to be the filled
    /// document: probe, then clear what is still held.
    async fn clear_if_held(
        &self,
        session: &super::client::CdpSession,
        context_id: u64,
        field_args: &[Value],
        deadline: Option<Instant>,
        note: &ScrubNote,
    ) {
        if !scrub_room(deadline, Duration::ZERO, Instant::now()) {
            return;
        }
        // Value-free probe. The written values go out only when a
        // recorded element is still connected and non-empty. A site
        // that already cleared its form does not see the secret again.
        let probe = session
            .request_with_timeout(
                "Runtime.callFunctionOn",
                json!({
                    "functionDeclaration": PROBE_WRITTEN_IN_PAGE,
                    "executionContextId": context_id,
                    "arguments": [],
                    "returnByValue": true,
                    "awaitPromise": false,
                }),
                scrub_call_timeout(deadline, Instant::now()),
            )
            .await;
        let held = match probe {
            Ok(result) => match probe_held(&result) {
                Ok(n) => n,
                Err(obs) => {
                    note.record(obs);
                    return;
                }
            },
            Err(e) if context_gone(&e.to_string()) => {
                note.record(ScrubObservation::Navigated);
                return;
            }
            Err(_) => {
                note.record(ScrubObservation::Nothing);
                return;
            }
        };
        if held == 0 {
            note.record(ScrubObservation::Nothing);
            return;
        }
        // The probe can take the margin we had. Recheck before the
        // call that carries the values.
        if !scrub_room(deadline, Duration::ZERO, Instant::now()) {
            return;
        }
        let Some(mut values) = field_values(field_args) else {
            note.record(ScrubObservation::Nothing);
            return;
        };
        let n_fields = values.len() as u64;
        let params = json!({
            "functionDeclaration": SCRUB_WRITTEN_IN_PAGE,
            "executionContextId": context_id,
            "arguments": [ { "value": values } ],
            "returnByValue": true,
            "awaitPromise": false,
        });
        for s in &mut values {
            s.zeroize();
        }
        let call = session
            .request_with_timeout(
                "Runtime.callFunctionOn",
                params,
                scrub_call_timeout(deadline, Instant::now()),
            )
            .await;
        note.record(match call {
            Ok(result) => scrub_observation(&result, n_fields),
            Err(e) if context_gone(&e.to_string()) => ScrubObservation::Navigated,
            Err(_) => ScrubObservation::Nothing,
        });
    }
}

/// A method fill's view of the engine's tail: what the fill planned,
/// and where its success reading goes.
struct MethodRun<'a> {
    prepared: &'a Prepared,
    delay: Duration,
    result: Option<MethodResult>,
}

/// The one delayed `Page.getFrameTree` read.
enum Reread {
    /// The deadline cannot cover the delay (or no longer has room).
    NoRoom,
    TimedOut,
    Failed,
    Tree(Value),
}

/// Wait `delay`, then read the frame tree once, bounded as the scrub's
/// own call is. Never runs when the deadline cannot cover the delay plus
/// [`RETURN_MARGIN`]; a drop during the wait sends nothing.
async fn reread_frame_tree(
    session: &super::client::CdpSession,
    deadline: Option<Instant>,
    delay: Duration,
) -> Reread {
    if !scrub_room(deadline, delay, Instant::now()) {
        return Reread::NoRoom;
    }
    tokio::time::sleep(delay).await;
    if !scrub_room(deadline, Duration::ZERO, Instant::now()) {
        return Reread::NoRoom;
    }
    // Bounded: an unanswered re-read must not turn a `filled` reply
    // into the broker's `timeout`, and an engine caller with no
    // deadline must not wait forever (#355 review).
    let timeout = scrub_call_timeout(deadline, Instant::now());
    match session
        .request_with_timeout("Page.getFrameTree", json!({}), timeout)
        .await
    {
        Ok(t) => Reread::Tree(t),
        Err(CdpError::Timeout) => Reread::TimedOut,
        Err(_) => Reread::Failed,
    }
}

/// The path of the main frame's URL in a `Page.getFrameTree` reply.
fn frame_path(tree: &Value) -> Option<String> {
    let href = tree_frame(tree)?.get("url")?.as_str()?;
    url::Url::parse(href).ok().map(|u| u.path().to_owned())
}

// Private newtype so `fill` can hold Option<MismatchReason> without
// exposing it in the public API.
struct Decision_(Option<MismatchReason>);

fn tree_frame(tree: &Value) -> Option<&Value> {
    tree.get("frameTree")?
        .get("frame")
        .or_else(|| tree.pointer("/frameTree/frame"))
}

fn parse_fill_results(result: &Value) -> FillOutcome {
    // `Runtime.callFunctionOn` with returnByValue replies
    // `{ result: RemoteObject, exceptionDetails? }`; the returned JS
    // object lives at RemoteObject.value. Muse's review caught the
    // first version reading `result.results` off the RemoteObject
    // itself, which can never exist — every successful fill was
    // misreported as an error. The envelope test below pins this.
    let results = match result
        .get("result")
        .and_then(|remote| remote.get("value"))
        .and_then(|value| value.get("results"))
        .and_then(Value::as_array)
    {
        Some(a) => a,
        None => return FillOutcome::Error("fill reply lacked results".into()),
    };
    let kinds: Vec<FieldKind> = results
        .iter()
        .filter_map(|r| match r.get("kind").and_then(Value::as_str) {
            Some("username") => Some(FieldKind::Username),
            Some("password") => Some(FieldKind::Password),
            Some("totp") => Some(FieldKind::Totp),
            _ => None,
        })
        .collect();
    FillOutcome::Filled { kinds }
}

fn classify_exception(description: &str) -> FillOutcome {
    if description.contains("kharon:deadline") {
        // #118: the page-side budget expired and the in-page call
        // aborted itself (fields cleared, submit not dispatched).
        // The broker maps this to `timeout` + `fill_timeout`, exactly
        // as for a deadline it observed itself — no new status value.
        FillOutcome::Timeout
    } else if description.contains("kharon:origin_mismatch") {
        FillOutcome::OriginMismatch
    } else if description.contains("kharon:non_secure") {
        FillOutcome::NonSecureContext
    } else if description.contains("kharon:method_wrong_page") {
        FillOutcome::MethodWrongPage
    } else if let Some(step) = method_step(description, "kharon:method_drift:") {
        FillOutcome::MethodDrift { step }
    } else if let Some(step) = method_step(description, "kharon:method_not_ready:") {
        FillOutcome::MethodNotReady { step }
    } else if description.contains("kharon:field_not_found") {
        let kinds = if description.contains(":password") {
            vec![FieldKind::Password]
        } else if description.contains(":totp") {
            vec![FieldKind::Totp]
        } else {
            vec![FieldKind::Username]
        };
        FillOutcome::FieldNotFound { kinds }
    } else {
        FillOutcome::Error(format!("in-page exception: {description}"))
    }
}

/// The step number after `prefix` in an in-page failure description;
/// an unparsable number is step 0.
fn method_step(description: &str, prefix: &str) -> Option<u32> {
    let rest = description.split_once(prefix)?.1;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some(digits.parse().unwrap_or(0))
}

fn map_context_error(code: i64, message: &str) -> FillOutcome {
    let _ = code;
    if context_gone(message) {
        FillOutcome::Navigated
    } else {
        FillOutcome::Error(format!("cdp: {message}"))
    }
}

/// A CDP error that means the filled world is gone (navigation).
fn context_gone(message: &str) -> bool {
    message.contains("Cannot find context")
        || message.contains("context was destroyed")
        || message.contains("Inspected target navigated")
        || message.contains("No execution context")
}

/// The field values, in write order. `None` if a value is missing:
/// the scrub then sends nothing rather than a partial list.
fn field_values(fields: &[Value]) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(fields.len());
    for f in fields {
        out.push(f.get("value").and_then(Value::as_str)?.to_owned());
    }
    Some(out)
}

/// Whether `deadline` still has room for `delay` plus the return
/// margin. No deadline (an engine caller) always has room. A delay
/// that cannot be added to the margin does not.
fn scrub_room(deadline: Option<Instant>, delay: Duration, now: Instant) -> bool {
    let Some(deadline) = deadline else {
        return true;
    };
    let Some(need) = delay.checked_add(RETURN_MARGIN) else {
        return false;
    };
    deadline.saturating_duration_since(now) > need
}

/// How long the clear call may take. Short of the broker's deadline
/// so the reply lands while the broker is still waiting; five seconds
/// when the plan has no deadline.
fn scrub_call_timeout(deadline: Option<Instant>, now: Instant) -> Duration {
    match deadline {
        Some(deadline) => deadline
            .saturating_duration_since(now)
            .saturating_sub(Duration::from_millis(50))
            .min(Duration::from_secs(5)),
        None => Duration::from_secs(5),
    }
}

/// How many recorded elements the value-free probe says are still
/// connected and non-empty. `Err` is the observation to record when
/// the call itself failed: a destroyed world is `navigated`, anything
/// else is `nothing` (the values are not sent).
fn probe_held(result: &Value) -> Result<u64, ScrubObservation> {
    if let Some(exception) = result.get("exceptionDetails") {
        let description = exception
            .get("exception")
            .and_then(|e| e.get("description"))
            .and_then(Value::as_str)
            .or_else(|| exception.get("text").and_then(Value::as_str))
            .unwrap_or("");
        return Err(if context_gone(description) {
            ScrubObservation::Navigated
        } else {
            ScrubObservation::Nothing
        });
    }
    Ok(result
        .pointer("/result/value/held")
        .and_then(Value::as_u64)
        .unwrap_or(0))
}

/// The scrub observation from one in-page reply. The reported count
/// is capped at `max` (the number of fields this fill wrote). A
/// destroyed world is `navigated`; any other failure is `nothing`,
/// and the fill stays `filled`.
fn scrub_observation(result: &Value, max: u64) -> ScrubObservation {
    if let Some(exception) = result.get("exceptionDetails") {
        let description = exception
            .get("exception")
            .and_then(|e| e.get("description"))
            .and_then(Value::as_str)
            .or_else(|| exception.get("text").and_then(Value::as_str))
            .unwrap_or("");
        return if context_gone(description) {
            ScrubObservation::Navigated
        } else {
            ScrubObservation::Nothing
        };
    }
    let n = result
        .pointer("/result/value/cleared")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(max);
    if n > 0 {
        ScrubObservation::Cleared(n)
    } else {
        ScrubObservation::Nothing
    }
}

fn url_host(href: &str) -> Option<String> {
    // Trust boundary (per review): parse, don't string-split — the
    // hand-rolled split mishandled userinfo ("https://user@host/").
    url::Url::parse(href)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
}

/// Whether the agent's claimed origin is the live page's origin
/// (scheme, host, port; path and query ignored). An unparsable claim
/// or page URL never matches.
fn claim_matches(claimed: &str, live_href: &str) -> bool {
    match (url::Url::parse(claimed), url::Url::parse(live_href)) {
        (Ok(c), Ok(l)) => {
            let c = c.origin();
            c.is_tuple() && c == l.origin()
        }
        _ => false,
    }
}

fn expected_origin(href: &str) -> String {
    match url::Url::parse(href) {
        Ok(u) => u.origin().ascii_serialization(),
        Err(_) => String::new(),
    }
}

/// REQ-API-009: the default end-to-end fill deadline, from request receipt
/// to the final CDP result. Configurable (`[policy] fill_deadline`);
/// enforced by [`crate::api::Broker::fill`], not by the engine.
pub const DEFAULT_FILL_DEADLINE: Duration = Duration::from_secs(10);

/// #355: how long a post-submit scrub waits before its one re-read.
/// Configurable (`[policy] post_submit_scrub_delay`). Short on purpose:
/// the wait sits inside the fill deadline, and the scrub is skipped
/// when the remainder cannot cover this plus [`RETURN_MARGIN`].
pub const DEFAULT_POST_SUBMIT_SCRUB_DELAY: Duration = Duration::from_millis(500);

/// #118: the fixed slice of the remaining deadline the broker keeps
/// for the fill call's return trip when it converts the remainder
/// into the page-side budget. A named constant, not config (design
/// locked in #117 §4): the page aborts this far ahead of the broker's
/// own deadline, so its `kharon:deadline` reply normally lands before
/// the broker stops waiting. For a remainder too short to spare the
/// full margin the margin is capped at half of it (see
/// [`page_budget`]), so a short-deadline fill still gets a usable
/// budget instead of none.
pub const RETURN_MARGIN: Duration = Duration::from_millis(250);

/// The page-side budget for one dispatch (#118).
#[derive(Debug, PartialEq, Eq)]
enum PageBudget {
    /// No deadline on the plan: pass `0` (no page-side check).
    NoCheck,
    /// Milliseconds the in-page task may spend.
    Budget(u64),
    /// The remainder is already gone: do not dispatch; the fill is a
    /// timeout before the call is sent.
    Exhausted,
}

fn page_budget(deadline: Option<Instant>, now: Instant) -> PageBudget {
    let Some(deadline) = deadline else {
        return PageBudget::NoCheck;
    };
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        return PageBudget::Exhausted;
    }
    // The budget never exceeds what remains (a submit is never
    // dispatched past the broker's deadline on the page's clock), and
    // never collapses to 0 — which the in-page contract reads as "no
    // check". The margin comes off first, capped at half the
    // remainder so short deadlines keep a usable budget.
    let margin = RETURN_MARGIN.min(remaining / 2);
    PageBudget::Budget(((remaining - margin).as_millis() as u64).max(1))
}

#[cfg(test)]
mod tests {
    #[test]
    fn req_org_004_iframe_refusal_is_origin_mismatch_with_its_own_detail() {
        let o = super::FillOutcome::IframeNotAllowlisted;
        assert_eq!(o.status(), "origin_mismatch");
        assert_eq!(o.detail(), Some("iframe_not_allowlisted"));
        assert!(o.fields_filled().is_empty());
    }

    use super::*;

    #[test]
    fn classify_exception_codes() {
        assert_eq!(
            classify_exception("Error: kharon:origin_mismatch\n    at fillInPage"),
            FillOutcome::OriginMismatch
        );
        assert_eq!(
            classify_exception("Error: kharon:non_secure"),
            FillOutcome::NonSecureContext
        );
        assert_eq!(
            classify_exception("Error: kharon:field_not_found:password"),
            FillOutcome::FieldNotFound {
                kinds: vec![FieldKind::Password]
            }
        );
        assert!(matches!(
            classify_exception("Error: boom"),
            FillOutcome::Error(_)
        ));
        // #118: the page-side budget's own code maps to Timeout.
        assert_eq!(
            classify_exception("Error: kharon:deadline\n    at fillInPage"),
            FillOutcome::Timeout
        );
    }

    /// #118: the budget conversion — no deadline means no page-side
    /// check; the margin comes off the remainder (capped at half of
    /// it, so short deadlines keep a usable budget); only a remainder
    /// that is already gone is exhausted and must not be dispatched.
    #[test]
    fn req_api_009_page_budget_conversion() {
        let now = Instant::now();
        assert_eq!(page_budget(None, now), PageBudget::NoCheck);
        assert_eq!(
            page_budget(Some(now + Duration::from_secs(10)), now),
            PageBudget::Budget(9750)
        );
        assert_eq!(
            page_budget(Some(now + RETURN_MARGIN), now),
            PageBudget::Budget(125)
        );
        assert_eq!(
            page_budget(Some(now + Duration::from_millis(200)), now),
            PageBudget::Budget(100)
        );
        assert_eq!(
            page_budget(Some(now + Duration::from_millis(1)), now),
            PageBudget::Budget(1)
        );
        assert_eq!(
            page_budget(Some(now - Duration::from_secs(1)), now),
            PageBudget::Exhausted
        );
        assert_eq!(RETURN_MARGIN, Duration::from_millis(250));
    }

    /// #355: the scrub waits only when the remainder covers the delay
    /// and the return margin. Equal to that sum is not enough — the
    /// clear call needs the margin after the wait.
    #[test]
    fn req_api_013_scrub_room_needs_the_delay_and_the_margin() {
        let now = Instant::now();
        let delay = DEFAULT_POST_SUBMIT_SCRUB_DELAY;
        assert!(scrub_room(None, delay, now));
        assert!(scrub_room(Some(now + Duration::from_secs(10)), delay, now));
        assert!(!scrub_room(Some(now + delay + RETURN_MARGIN), delay, now));
        assert!(scrub_room(
            Some(now + delay + RETURN_MARGIN + Duration::from_millis(1)),
            delay,
            now
        ));
        assert!(!scrub_room(
            Some(now + Duration::from_millis(100)),
            delay,
            now
        ));
        assert!(!scrub_room(Some(now + RETURN_MARGIN), Duration::ZERO, now));
        assert!(scrub_room(
            Some(now + RETURN_MARGIN + Duration::from_millis(1)),
            Duration::ZERO,
            now
        ));
        assert_eq!(
            scrub_observation(
                &json!({"result": {"type": "object", "value": {"cleared": 99}}}),
                2
            ),
            ScrubObservation::Cleared(2)
        );
        assert_eq!(
            scrub_observation(
                &json!({"result": {"type": "object", "value": {"cleared": 0}}}),
                2
            ),
            ScrubObservation::Nothing
        );
        assert_eq!(
            scrub_observation(
                &json!({"exceptionDetails": {"text": "Cannot find context with given id"}}),
                2
            ),
            ScrubObservation::Navigated
        );
    }

    #[test]
    fn helper_urls() {
        assert_eq!(
            url_host("https://sub.example.com/x?y#z"),
            Some("sub.example.com".into())
        );
        assert_eq!(
            url_host("https://example.com:8443/a"),
            Some("example.com".into())
        );
        // userinfo must not confuse the host extraction (per review).
        assert_eq!(
            url_host("https://user@example.com/"),
            Some("example.com".into())
        );
        assert_eq!(
            expected_origin("https://a.b.example.com/p"),
            "https://a.b.example.com"
        );
        assert_eq!(expected_origin("not a url"), "");
        // REQ-APR-007: the claim is compared by origin only.
        assert!(claim_matches(
            "https://accounts.example.com",
            "https://accounts.example.com/login?x=1"
        ));
        assert!(claim_matches(
            "https://accounts.example.com/other",
            "https://accounts.example.com/login"
        ));
        assert!(!claim_matches(
            "https://accounts.example.com",
            "https://evil.test/login"
        ));
        assert!(!claim_matches(
            "http://accounts.example.com",
            "https://accounts.example.com/"
        ));
        assert!(!claim_matches(
            "https://accounts.example.com:8443",
            "https://accounts.example.com/"
        ));
        assert!(!claim_matches("not a url", "https://a.example/"));
        assert!(!claim_matches("data:text/html,x", "data:text/html,x"));
    }

    /// Regression (review finding 1): the callFunctionOn reply carries
    /// the returned object at `result.result.value` — the first parser
    /// read `result.result.results`, so no successful fill could ever
    /// report `Filled`. This feeds a realistic envelope through the
    /// parser, which no test did before.
    #[test]
    fn req_org_003_fill_reply_envelope() {
        let envelope = json!({
            "result": {
                "type": "object",
                "value": {
                    "results": [
                        { "kind": "username", "filled": true },
                        { "kind": "password", "filled": true },
                    ],
                },
            },
        });
        assert_eq!(
            parse_fill_results(&envelope),
            FillOutcome::Filled {
                kinds: vec![FieldKind::Username, FieldKind::Password],
            }
        );
        // exceptionDetails rides next to RemoteObject, not inside it.
        let exceptional = json!({
            "result": { "type": "object", "value": null },
            "exceptionDetails": {
                "exception": { "description": "Error: kharon:non_secure" },
            },
        });
        assert!(matches!(
            classify_exception(
                exceptional
                    .get("exceptionDetails")
                    .and_then(|e| e.get("exception"))
                    .and_then(|e| e.get("description"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ),
            FillOutcome::NonSecureContext
        ));
    }

    /// #67: the live origin is recorded as a serialized origin only
    /// (no path, query, fragment or userinfo), keeps a non-default
    /// port, is `null` for an opaque origin, ignores an unparsable URL,
    /// is shared by plan clones, and the first observation wins.
    #[test]
    fn req_aud_003_live_origin_slot() {
        let o = LiveOrigin::new();
        assert_eq!(o.get(), None);
        o.record_href("not a url");
        assert_eq!(o.get(), None, "unparsable records nothing");
        let shared = o.clone();
        o.record_href("https://user:pw@Login.Example.com:8443/a/b?token=t#frag");
        assert_eq!(
            shared.get().as_deref(),
            Some("https://login.example.com:8443"),
            "clones share the slot"
        );
        o.record_href("https://evil.test/");
        assert_eq!(
            o.get().as_deref(),
            Some("https://login.example.com:8443"),
            "first write wins"
        );
        let o = LiveOrigin::new();
        o.record_href("https://example.com:443/x");
        assert_eq!(o.get().as_deref(), Some("https://example.com"));
        let o = LiveOrigin::new();
        o.record_href("about:blank");
        assert_eq!(o.get().as_deref(), Some("null"), "opaque origin");
    }

    #[test]
    fn req_api_009_default_deadline() {
        assert_eq!(DEFAULT_FILL_DEADLINE, Duration::from_secs(10));
    }
}
