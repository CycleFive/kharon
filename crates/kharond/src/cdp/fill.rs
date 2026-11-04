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
//! 4. Re-read the loader via `Page.getFrameTree`; if it changed, run
//!    [`CLEAR_IN_PAGE`] in the old world (best effort) and report
//!    `navigated`.
//!
//! Ownership (REQ-ARCH-005) gates step 1: the target must live in the
//! requesting agent's browser context, or the default context when
//! `allow_default` is set.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::audit::{AuditLog, Entry, Event};
use crate::origin::{MismatchReason, OriginConfig, OriginMatcher};

use super::browser::{AgentContext, Browser, OwnershipError};
use super::client::CdpError;
use super::page_js::{CLEAR_IN_PAGE, FILL_IN_PAGE};

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
    /// already dispatched still submits (see [`DeadlineFiller`], #46).
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

/// The outcome of one fill attempt, one-to-one with `FillResult.status`
/// in SPEC §6.
#[derive(Debug, PartialEq, Eq)]
pub enum FillOutcome {
    Filled {
        kinds: Vec<FieldKind>,
    },
    OriginMismatch,
    NonSecureContext,
    Navigated,
    FieldNotFound {
        kinds: Vec<FieldKind>,
    },
    TargetNotOwned,
    DefaultContextRefused,
    UnknownTarget,
    /// REQ-API-009: the end-to-end fill deadline expired. Fails closed:
    /// the broker sent no further CDP writes after expiry and the
    /// caller's secret buffers are zeroized by [`DeadlineFiller`] before
    /// this is returned. Not a guarantee that nothing happened in the
    /// page: an in-page fill call dispatched before expiry may still
    /// fill (and submit) afterwards (see [`DeadlineFiller`], #46).
    Timeout,
    /// REQ-API-007: `fill_totp` refused because the last clock sample
    /// exceeded `clock_skew_refuse`. No CDP call was made.
    ClockSkew,
    /// REQ-API-007: the item's TOTP field is not a supported
    /// `otpauth://totp`, `steam://` or base32 secret. No CDP call was
    /// made.
    TotpUnsupported,
    Error(String),
}

impl FillOutcome {
    /// SPEC §4 `FillResult.status`.
    pub fn status(&self) -> &'static str {
        match self {
            Self::Filled { .. } => "filled",
            Self::OriginMismatch | Self::NonSecureContext => "origin_mismatch",
            Self::Navigated => "navigated",
            Self::FieldNotFound { .. } => "field_not_found",
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
            Self::DefaultContextRefused => Some("default_context_refused"),
            Self::UnknownTarget => Some("unknown_target"),
            Self::ClockSkew => Some("clock_skew"),
            Self::TotpUnsupported => Some("totp_unsupported"),
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
                None => return FillOutcome::OriginMismatch,
            };
            if !plan
                .cross_origin_iframe_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&host))
            {
                return FillOutcome::OriginMismatch;
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

        let specs: Vec<Value> = plan
            .item_matchers
            .iter()
            .map(|m| serde_json::to_value(m.in_page_spec()).expect("spec serializes"))
            .collect();
        let mut field_args: Vec<Value> = plan
            .fields
            .iter()
            .map(|f| {
                json!({
                    "kind": f.kind.as_str(),
                    "selector": f.selector,
                    "value": &*f.value,
                })
            })
            .collect();
        let clear_args: Vec<Value> = plan
            .fields
            .iter()
            .map(|f| json!({ "kind": f.kind.as_str(), "selector": f.selector }))
            .collect();

        let session = match self.browser.client().attach(&plan.target_id).await {
            Ok(s) => s,
            Err(CdpError::Protocol { code: -32000, .. }) => return FillOutcome::UnknownTarget,
            Err(e) => return FillOutcome::Error(e.to_string()),
        };

        let outcome = self
            .fill_attached(
                &session,
                &specs,
                &field_args,
                &clear_args,
                &info.url,
                plan.submit,
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
        outcome
    }

    /// Steps 2–4 with the session attached.
    async fn fill_attached(
        &self,
        session: &super::client::CdpSession,
        specs: &[Value],
        field_args: &[Value],
        clear_args: &[Value],
        live_url: &str,
        submit: bool,
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
            Err(_) => return parse_fill_results(&result),
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
            (Some(_), Some(_)) => parse_fill_results(&result),
            _ => FillOutcome::Error("frame tree loader id missing after fill".into()),
        }
    }
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
    if description.contains("kharon:origin_mismatch") {
        FillOutcome::OriginMismatch
    } else if description.contains("kharon:non_secure") {
        FillOutcome::NonSecureContext
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

fn map_context_error(code: i64, message: &str) -> FillOutcome {
    let _ = code;
    if message.contains("Cannot find context")
        || message.contains("context was destroyed")
        || message.contains("Inspected target navigated")
        || message.contains("No execution context")
    {
        FillOutcome::Navigated
    } else {
        FillOutcome::Error(format!("cdp: {message}"))
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
/// to the final CDP result. Configurable (`fill_deadline`); the config
/// loader wires this in when it lands (#5).
pub const DEFAULT_FILL_DEADLINE: Duration = Duration::from_secs(10);

/// REQ-API-009: wraps one `fill` / `fill_totp` / `fill_and_submit` in an
/// end-to-end deadline. On expiry the fill fails closed:
///
/// - the in-flight fill future is dropped, so **no further CDP writes**
///   are sent by the broker for this fill after expiry,
/// - the caller-owned secret buffers in the returned [`FillPlan`] are
///   zeroized **before** the outcome is returned,
/// - one `fill_timeout` audit entry is appended before the response; if
///   that append fails, the result is [`AuditFailed`] instead of
///   [`FillOutcome::Timeout`] (REQ-AUD-003†, see below).
///
/// # What "fails closed" does *not* cover (#46)
///
/// REQ-API-009 reads "no further CDP writes, submit not dispatched".
/// At this layer only the first half is enforceable, and only
/// broker-side: dropping the future stops the broker from *sending*
/// anything more, but it cannot recall a frame the browser already has.
/// A `Runtime.callFunctionOn` of `FILL_IN_PAGE` that was dispatched
/// before the deadline runs the in-page function to completion in the
/// page: it fills every field **and, when `plan.submit` is set, submits
/// the form**, possibly *after* the broker has replied `timeout`. A
/// stall after dispatch (slow page, slow transport, a browser that
/// executes but answers late) therefore can still fill and submit
/// post-timeout. "Submit not dispatched" holds in the strong sense only
/// when the deadline expires before the fill call is sent (ownership
/// check, attach, frame tree, isolated world); after that it means "no
/// *separate* submit write is sent by the broker", which is vacuous
/// here because submit rides inside the one in-page call
/// (REQ-ORG-003's atomic check-and-set). The `timeout` reply is thus
/// "the broker could not confirm the fill in time", not "nothing
/// happened in the page". Likewise the post-fill loader re-check and
/// the `CLEAR_IN_PAGE` scrub (step 4) never run after expiry.
///
/// "Dispatched" is also fuzzier than it looks: if the deadline fires
/// while the fill frame is mid-`send` on the shared websocket sink, the
/// frame can sit in the sink's buffer and go out with the next write
/// on that connection (another request's), i.e. after expiry. No
/// *new* write is issued for this fill, but the bytes of the one
/// already handed to the transport are not withdrawn.
///
/// # Audit
///
/// This is the engine-level wrapper (used by [`crate::totp::TotpFill`]
/// and tests). The daemon's fill path is [`crate::api::Broker::fill`],
/// which owns the REQ-AUD-003† dispatch / outcome pair: a
/// `fill_dispatch` entry before any CDP write (append failure →
/// `audit_failed`, no write) and one outcome entry after. This wrapper
/// writes only the `fill_timeout` outcome entry, and treats its append
/// exactly as the daemon does: a failed append is surfaced to the caller
/// as `Err(AuditFailed)` (the API's `audit_failed`), never swallowed. The
/// non-timeout outcomes are returned unaudited for the caller to record.
///
/// Ownership note: secrets live canonically in `plan.fields[*].value`
/// (`Zeroizing<String>`). Copies inside the cancelled fill future are freed
/// by the allocator unzeroed — the same documented class as tungstenite's
/// internal send buffer (see [`crate::cdp::client`]).
pub struct DeadlineFiller<'a> {
    engine: &'a FillEngine,
    audit: &'a mut AuditLog,
    deadline: Duration,
}

impl<'a> DeadlineFiller<'a> {
    pub fn new(engine: &'a FillEngine, audit: &'a mut AuditLog) -> Self {
        Self {
            engine,
            audit,
            deadline: DEFAULT_FILL_DEADLINE,
        }
    }

    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Run the fill under the deadline. Returns the plan (secrets zeroized
    /// on the timeout path, whatever the audit result) alongside the
    /// outcome.
    ///
    /// `Err(AuditFailed)` only on the timeout path, when the
    /// `fill_timeout` entry could not be appended (REQ-AUD-003†: "a
    /// failed outcome append turns the reply into `audit_failed`"). The
    /// deadline is unaffected: the append runs after expiry and the
    /// zeroize, and a failing log fails immediately (a poisoned handle
    /// refuses without I/O).
    pub async fn run(
        self,
        mut plan: FillPlan,
        agent_ctx: &AgentContext,
        allow_default: bool,
    ) -> (FillPlan, Result<FillOutcome, AuditFailed>) {
        let fill = self.engine.fill(&plan, agent_ctx, allow_default);
        match tokio::time::timeout(self.deadline, fill).await {
            Ok(outcome) => (plan, Ok(outcome)),
            Err(_elapsed) => {
                // REQ-API-009: zeroize first, so an audit failure below
                // cannot leave plaintext behind.
                for f in &mut plan.fields {
                    f.value.zeroize();
                }
                let mut entry = Entry::new(Event::FillTimeout)
                    .agent_id(agent_ctx.agent_id())
                    .result("timeout")
                    .detail_code("deadline_expired");
                entry.live_origin = plan.live_origin.get();
                // REQ-AUD-003†: no reply the audit log does not have.
                // Same rule as `Broker::fill` (#46 item 2): the reply
                // becomes `audit_failed`. The append error itself is
                // dropped (an I/O error or `Poisoned`; it carries no
                // secret, but nothing above needs it).
                match self.audit.append(entry) {
                    Ok(()) => (plan, Ok(FillOutcome::Timeout)),
                    Err(_) => (plan, Err(AuditFailed)),
                }
            }
        }
    }
}

/// REQ-AUD-003†: an outcome audit entry could not be appended, so the
/// fill's result must not be reported (the API maps this to
/// `audit_failed`, [`crate::api::ApiError::AUDIT_FAILED`]). Carries no
/// detail: the underlying [`crate::audit::AppendError`] is an I/O error
/// or `Poisoned`, and the reply is the fixed code either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("audit append failed (fail closed)")]
pub struct AuditFailed;

/// Shared fixtures for the REQ-API-009 / REQ-AUD-003 deadline tests
/// (here and in [`crate::totp`]).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A CDP peer on a fresh port plus an engine and agent context
    /// connected to it. The peer answers the session-setup protocol and
    /// records every frame; `Runtime.callFunctionOn` is recorded but
    /// never answered (REQ-API-009's stall).
    pub(crate) async fn stalling_engine() -> (
        FillEngine,
        AgentContext,
        std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use crate::cdp::client::CdpClient;
        use crate::cdp::endpoint::{CdpEndpoint, Tunnel};
        use futures_util::{SinkExt, StreamExt};
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        use tokio::net::TcpListener;
        use tokio_tungstenite::accept_async;

        // A CDP peer that answers the session-setup protocol and then
        // records every `Runtime.callFunctionOn` without replying. The
        // join handle is kept alive for the test's lifetime.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_task = Arc::clone(&received);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            let mut script: HashMap<String, Value> = HashMap::new();
            script.insert(
                "Target.createBrowserContext".to_string(),
                json!({ "browserContextId": "ctx-A" }),
            );
            script.insert(
                "Target.getTargetInfo".to_string(),
                json!({ "targetInfo": {
                    "targetId": "t1",
                    "browserContextId": "ctx-A",
                    "url": "https://accounts.example.com/login",
                    "title": "",
                    "type": "page",
                } }),
            );
            script.insert(
                "Target.attachToTarget".to_string(),
                json!({ "sessionId": "sess-1" }),
            );
            script.insert(
                "Page.getFrameTree".to_string(),
                json!({ "frameTree": { "frame": {
                    "id": "f1",
                    "loaderId": "l1",
                    "url": "https://accounts.example.com/login",
                }, "childFrames": [] } }),
            );
            script.insert(
                "Page.createIsolatedWorld".to_string(),
                json!({ "executionContextId": 7 }),
            );
            while let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) =
                ws.next().await
            {
                let msg: Value = serde_json::from_str(&text).unwrap();
                received_task.lock().unwrap().push(msg.clone());
                let method = msg["method"].as_str().unwrap();
                // REQ-API-009's stall: the in-page fill call never gets a
                // reply, so the deadline is the only thing that can end it.
                if method == "Runtime.callFunctionOn" {
                    continue;
                }
                let result = script.get(method).cloned().unwrap_or_else(|| json!({}));
                let mut reply = json!({ "id": msg["id"], "result": result });
                if let Some(session_id) = msg.get("sessionId") {
                    reply["sessionId"] = session_id.clone();
                }
                ws.send(tokio_tungstenite::tungstenite::Message::Text(
                    reply.to_string(),
                ))
                .await
                .unwrap();
            }
        });

        let endpoint = CdpEndpoint::validate(
            &format!("ws://{}/devtools/browser", addr),
            Tunnel::Direct,
            None,
        )
        .unwrap();
        let client = CdpClient::connect(&endpoint).await.unwrap();
        let browser = crate::cdp::browser::Browser::new(client);
        let ctx = browser.create_agent_context("agent-A").await.unwrap();
        let engine = FillEngine::new(browser);
        (engine, ctx, received, task)
    }

    /// One password field carrying a canary, `submit: true` (even a
    /// requested submit must never get a broker-side write after expiry).
    pub(crate) fn canary_plan() -> FillPlan {
        FillPlan {
            target_id: "t1".to_string(),
            fields: vec![FieldFill {
                kind: FieldKind::Password,
                selector: None,
                value: Zeroizing::new("CANARY-fill-secret-9f3d".to_string()),
            }],
            item_matchers: vec![
                OriginMatcher::new("https://accounts.example.com/login", None).unwrap(),
            ],
            origin_cfg: OriginConfig::default(),
            cross_origin_iframe_hosts: Vec::new(),
            submit: true,
            expected_origin: None,
            live_origin: LiveOrigin::new(),
        }
    }

    /// A writer whose durability barrier always fails: the first append
    /// errors (and poisons the handle), every later one is refused.
    pub(crate) struct SyncFails;

    impl std::io::Write for SyncFails {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::audit::AuditWriter for SyncFails {
        fn sync(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("simulated fdatasync failure"))
        }
    }

    pub(crate) fn failing_audit() -> (tempfile::TempDir, AuditLog) {
        use crate::audit::{AuditConfig, AuditKeys, NullCheckpointSink};
        let dir = tempfile::tempdir().unwrap();
        let keys = AuditKeys::load_or_generate(&dir.path().join("keys")).unwrap();
        let log = AuditLog::open_for_test(
            SyncFails,
            keys,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        );
        (dir, log)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{canary_plan, failing_audit, stalling_engine};
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

    /// REQ-API-009 (configurable deadline row): a CDP stub that stalls
    /// `Runtime.callFunctionOn` makes the whole fill fail closed at the
    /// configured deadline: outcome `timeout`, caller-owned secret
    /// buffers zeroized, exactly one `fill_timeout` audit entry written
    /// before the response, and no CDP frame reaches the stub after the
    /// deadline. Uses `fill_deadline=2s` (the AC's configurable row); the
    /// 10 s default is pinned by `req_api_009_default_deadline`.
    #[tokio::test]
    async fn req_api_009_timeout_fails_closed() {
        use crate::audit::NullCheckpointSink;
        use crate::audit::{AuditConfig, AuditLog};
        use std::time::Instant;

        let (engine, ctx, received, _peer_task) = stalling_engine().await;

        let dir = std::env::temp_dir().join(format!("kharon_audit_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut audit =
            AuditLog::open(&dir, AuditConfig::default(), Box::new(NullCheckpointSink)).unwrap();

        let mut plan = canary_plan();
        let secret = plan.fields[0].value.clone();

        let start = Instant::now();
        let (returned_plan, outcome) = DeadlineFiller::new(&engine, &mut audit)
            .with_deadline(Duration::from_secs(2))
            .run(plan, &ctx, false)
            .await;
        let elapsed = start.elapsed();
        plan = returned_plan;

        assert_eq!(outcome, Ok(FillOutcome::Timeout));
        // AC: timeout at the configured deadline (±0.5 s; tokio fires at
        // the deadline, the window guards against clock slop).
        assert!(
            elapsed >= Duration::from_secs(2) && elapsed < Duration::from_millis(2600),
            "elapsed {elapsed:?}"
        );
        // Zeroize hook observed on the caller-owned secret buffer.
        assert!(plan.fields.iter().all(|f| f.value.is_empty()));
        // The original clone still holds the canary — the engine's copy is
        // what got wiped; compare to prove zeroization really happened.
        assert_eq!(&*secret, "CANARY-fill-secret-9f3d");

        // Exactly one fill_timeout entry, written before the response.
        let audit_text = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert_eq!(
            audit_text.matches("\"event\":\"fill_timeout\"").count(),
            1,
            "audit tail: {audit_text}"
        );
        // REQ-GOAL-001 (partial, for this path): no canary bytes in the
        // audit log or anywhere in the response-reachable state.
        assert!(!audit_text.contains("CANARY"));
        // #67: the live origin read before the stall is on the timeout
        // entry, as an origin (the page path is not recorded).
        assert_eq!(
            plan.live_origin.get().as_deref(),
            Some("https://accounts.example.com")
        );
        assert!(
            audit_text.contains("\"live_origin\":\"https://accounts.example.com\""),
            "audit tail: {audit_text}"
        );
        assert!(!audit_text.contains("/login"), "no path in the log");

        // No later write reaches the stub after the deadline: the fill
        // future is dropped, so nothing further is sent. Give the peer a
        // moment to deliver anything in flight, then freeze the count.
        let count_at_return = received.lock().unwrap().len();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let count_after = received.lock().unwrap().len();
        assert_eq!(
            count_at_return, count_after,
            "frames kept arriving after the deadline: {count_at_return} -> {count_after}"
        );
        // Exactly one in-page call was ever attempted (the stalled fill);
        // the clear-scrub never ran.
        let calls = received.lock().unwrap();
        let call_count = calls
            .iter()
            .filter(|m| m["method"] == "Runtime.callFunctionOn")
            .count();
        assert_eq!(call_count, 1, "unexpected extra CDP writes: {calls:?}");
        drop(calls);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REQ-AUD-003† ("a failed outcome append turns the reply into
    /// `audit_failed`") on REQ-API-009's timeout path (#46 item 2): a
    /// `fill_timeout` append that fails is surfaced as
    /// `Err(AuditFailed)`, not swallowed into `Timeout`. The REQ-API-009
    /// guarantees still hold: the reply comes at the deadline, the
    /// caller's secret buffer is zeroized, and no further CDP write
    /// reaches the stub.
    #[tokio::test]
    async fn req_aud_003_timeout_append_failure_is_audit_failed() {
        use std::time::Instant;

        let (engine, ctx, received, _peer_task) = stalling_engine().await;
        let (_dir, mut audit) = failing_audit();

        let start = Instant::now();
        let (plan, outcome) = DeadlineFiller::new(&engine, &mut audit)
            .with_deadline(Duration::from_secs(1))
            .run(canary_plan(), &ctx, false)
            .await;
        let elapsed = start.elapsed();

        assert_eq!(outcome, Err(AuditFailed));
        // REQ-API-009 timing: the failed append adds nothing measurable.
        assert!(
            elapsed >= Duration::from_secs(1) && elapsed < Duration::from_millis(1600),
            "elapsed {elapsed:?}"
        );
        // Zeroized before the append, so an audit failure leaves no
        // plaintext in the returned plan.
        assert!(plan.fields.iter().all(|f| f.value.is_empty()));
        // The error carries no detail a secret could ride in.
        assert_eq!(AuditFailed.to_string(), "audit append failed (fail closed)");
        // And maps to the API's fixed `audit_failed` reply.
        assert_eq!(
            crate::api::ApiError::from(AuditFailed),
            crate::api::ApiError::AUDIT_FAILED
        );

        let count_at_return = received.lock().unwrap().len();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(count_at_return, received.lock().unwrap().len());
        let calls = received.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|m| m["method"] == "Runtime.callFunctionOn")
                .count(),
            1,
            "unexpected extra CDP writes: {calls:?}"
        );
    }

    /// REQ-AUD-003† with a handle already poisoned by an earlier failed
    /// append (the audit module refuses every later append without I/O):
    /// the timeout path still reports `Err(AuditFailed)` at the deadline.
    #[tokio::test]
    async fn req_api_009_timeout_on_poisoned_log_is_audit_failed() {
        let (engine, ctx, _received, _peer_task) = stalling_engine().await;
        let (_dir, mut audit) = failing_audit();
        audit
            .append(Entry::new(Event::Fill))
            .expect_err("first append fails and poisons");

        let (plan, outcome) = DeadlineFiller::new(&engine, &mut audit)
            .with_deadline(Duration::from_millis(500))
            .run(canary_plan(), &ctx, false)
            .await;
        assert_eq!(outcome, Err(AuditFailed));
        assert!(plan.fields.iter().all(|f| f.value.is_empty()));
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
