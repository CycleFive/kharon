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

use serde_json::{Value, json};
use zeroize::{Zeroize, Zeroizing};

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
    fn as_str(self) -> &'static str {
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
}

/// The outcome of one fill attempt, one-to-one with `FillResult.status`
/// in SPEC §6.
#[derive(Debug, PartialEq, Eq)]
pub enum FillOutcome {
    Filled { kinds: Vec<FieldKind> },
    OriginMismatch,
    NonSecureContext,
    Navigated,
    FieldNotFound { kinds: Vec<FieldKind> },
    TargetNotOwned,
    DefaultContextRefused,
    UnknownTarget,
    Error(String),
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
            .fill_attached(&session, &specs, &field_args, &clear_args, &info.url)
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

fn expected_origin(href: &str) -> String {
    match url::Url::parse(href) {
        Ok(u) => u.origin().ascii_serialization(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
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
}
