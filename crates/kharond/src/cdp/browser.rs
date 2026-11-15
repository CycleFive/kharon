//! Per-agent browser contexts and target ownership (REQ-ARCH-005).
//!
//! The broker creates one `Target.createBrowserContext` per agent and
//! hands the agent its `browserContextId`; tabs the agent opens land in
//! its context. Before any fill, the broker re-checks the target's live
//! `browserContextId`: a fill is accepted only when the target lives in
//! the requesting agent's context. Default-context targets (the
//! browser's shared context) are refused unless `allow_default_context`
//! is set — the single-agent escape hatch from the spec.
//!
//! Chromium puts a `browserContextId` on every target, the default
//! context's included (#342), so "default" is decided by that id: the
//! one `Target.getBrowserContexts` names as `defaultBrowserContextId`,
//! or, on a browser that does not report it, any id that is not a
//! created context. A context someone else created is never default.

use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;

use super::client::{CdpClient, CdpError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OwnershipError {
    /// The target id is not attached to this browser right now.
    #[error("unknown target")]
    UnknownTarget,
    /// The target lives in another agent's browser context.
    #[error("target not owned by this agent's context")]
    TargetNotOwned,
    /// The target is in the browser's default context and
    /// `allow_default_context` is false.
    #[error("default-context targets are refused unless allow_default_context")]
    DefaultContextRefused,
    /// A CDP failure while resolving the target.
    #[error("cdp: {0}")]
    Cdp(String),
}

impl OwnershipError {
    /// A fixed name for the variant, for logs. [`Self::Cdp`]'s text comes
    /// from the browser (a protocol `message`, a transport error), which a
    /// hostile or buggy page can make echo anything it was sent, so broker
    /// logs use this instead of `Display` (REQ-GOAL-001).
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownTarget => "unknown_target",
            Self::TargetNotOwned => "target_not_owned",
            Self::DefaultContextRefused => "default_context_refused",
            Self::Cdp(_) => "cdp_error",
        }
    }
}

impl From<CdpError> for OwnershipError {
    fn from(e: CdpError) -> Self {
        match e {
            CdpError::Protocol {
                code: -32000,
                message,
            } => Self::Cdp(format!("{message} (is the target gone?)")),
            other => Self::Cdp(other.to_string()),
        }
    }
}

/// A `Target.createBrowserContext` id owned by one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentContext {
    browser_context_id: String,
    agent_id: String,
}

impl AgentContext {
    pub fn browser_context_id(&self) -> &str {
        &self.browser_context_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

/// The `Target.getBrowserContexts` reply.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserContexts {
    /// Every context created with `Target.createBrowserContext`, by any
    /// client. Absent only from a peer that is not a real browser.
    browser_context_ids: Option<Vec<String>>,
    /// The default context's id. Older Chromium does not send it.
    default_browser_context_id: Option<String>,
}

/// A live target the broker knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    pub target_id: String,
    /// The target's context. Chromium sets it for the default context
    /// too (#342); `None` (a stub, or a browser that omits the field)
    /// is treated as the default context.
    pub browser_context_id: Option<String>,
    pub url: String,
    pub title: String,
    /// `iframe` targets are out-of-process subframes; the broker can
    /// attach to them directly (used for the REQ-ORG-004 iframe path).
    pub type_: String,
}

/// Browser-level context/target management on top of a [`CdpClient`].
#[derive(Clone)]
pub struct Browser {
    client: CdpClient,
}

impl Browser {
    pub fn new(client: CdpClient) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &CdpClient {
        &self.client
    }

    /// Create a fresh browser context for `agent_id`. Cookies, storage,
    /// and credentials are isolated per context.
    pub async fn create_agent_context(
        &self,
        agent_id: &str,
    ) -> Result<AgentContext, OwnershipError> {
        let result = self
            .client
            .request("Target.createBrowserContext", json!({}))
            .await?;
        let id = result
            .get("browserContextId")
            .and_then(Value::as_str)
            .ok_or_else(|| OwnershipError::Cdp("createBrowserContext lacked an id".into()))?;
        Ok(AgentContext {
            browser_context_id: id.to_string(),
            agent_id: agent_id.to_string(),
        })
    }

    pub async fn close_agent_context(&self, ctx: &AgentContext) -> Result<(), OwnershipError> {
        self.client
            .request(
                "Target.disposeBrowserContext",
                json!({ "browserContextId": ctx.browser_context_id() }),
            )
            .await?;
        Ok(())
    }

    async fn browser_contexts(&self) -> Result<BrowserContexts, OwnershipError> {
        let result = self
            .client
            .request(
                "Target.getBrowserContexts",
                Value::Object(Default::default()),
            )
            .await?;
        serde_json::from_value(result)
            .map_err(|_| OwnershipError::Cdp("malformed getBrowserContexts reply".into()))
    }

    /// Whether `context_id`, which is not the requesting agent's own
    /// context, is the browser's default context (#342). Asked of the
    /// browser at each such check, so a fill into the agent's own
    /// context costs nothing extra and no answer can go stale.
    async fn is_default_context(&self, context_id: &str) -> Result<bool, OwnershipError> {
        let contexts = self.browser_contexts().await?;
        Ok(
            match (
                contexts.default_browser_context_id,
                contexts.browser_context_ids,
            ) {
                (Some(default), _) => context_id == default,
                // Older Chromium: the default context is the one nobody
                // created.
                (None, Some(created)) => !created.iter().any(|c| c == context_id),
                // Nothing to tell the default context by.
                (None, None) => false,
            },
        )
    }

    /// Live info for one target (never from agent input — REQ-ORG-002).
    pub async fn target_info(&self, target_id: &str) -> Result<TargetInfo, OwnershipError> {
        let result = self
            .client
            .request("Target.getTargetInfo", json!({ "targetId": target_id }))
            .await
            .map_err(|e| match &e {
                CdpError::Protocol {
                    code: -32000,
                    message,
                } if message.contains("No target") => OwnershipError::UnknownTarget,
                _ => OwnershipError::from(e),
            })?;
        let info = &result["targetInfo"];
        Ok(TargetInfo {
            target_id: info["targetId"]
                .as_str()
                .ok_or_else(|| OwnershipError::Cdp("targetInfo lacked targetId".into()))?
                .to_string(),
            browser_context_id: info["browserContextId"].as_str().map(String::from),
            url: info["url"].as_str().unwrap_or("").to_string(),
            title: info["title"].as_str().unwrap_or("").to_string(),
            type_: info["type"].as_str().unwrap_or("").to_string(),
        })
    }

    /// The ownership check that gates every fill: `target_id` must be in
    /// `agent_ctx`, or in the default context when `allow_default`.
    pub async fn check_ownership(
        &self,
        target_id: &str,
        agent_ctx: &AgentContext,
        allow_default: bool,
    ) -> Result<TargetInfo, OwnershipError> {
        let info = self.target_info(target_id).await?;
        let in_default_context = match info.browser_context_id.as_deref() {
            Some(id) if id == agent_ctx.browser_context_id() => return Ok(info),
            Some(id) => self.is_default_context(id).await?,
            None => true,
        };
        if !in_default_context {
            Err(OwnershipError::TargetNotOwned)
        } else if allow_default {
            Ok(info)
        } else {
            Err(OwnershipError::DefaultContextRefused)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    /// Mock browser peer scripted per method.
    struct MockBrowser {
        addr: std::net::SocketAddr,
        _task: tokio::task::JoinHandle<()>,
    }

    impl MockBrowser {
        async fn start(script: HashMap<String, Value>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let _task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws = accept_async(stream).await.unwrap();
                let mut next_id = 1u64;
                while let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) =
                    ws.next().await
                {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    let method = msg["method"].as_str().unwrap();
                    let result = script.get(method).cloned().unwrap_or_else(|| json!({}));
                    let reply = json!({ "id": next_id, "result": result });
                    next_id += 1;
                    ws.send(tokio_tungstenite::tungstenite::Message::Text(
                        reply.to_string(),
                    ))
                    .await
                    .unwrap();
                }
            });
            Self { addr, _task }
        }

        async fn client(&self) -> CdpClient {
            let endpoint = super::super::endpoint::CdpEndpoint::validate(
                &format!("ws://{}/devtools/browser", self.addr),
                super::super::endpoint::Tunnel::Direct,
                None,
            )
            .unwrap();
            CdpClient::connect(&endpoint).await.unwrap()
        }
    }

    fn target_info_json(context: Option<&str>, url: &str) -> Value {
        let mut ti = json!({
            "targetId": "t-1",
            "url": url,
            "title": "",
            "type": "page",
        });
        if let Some(c) = context {
            ti["browserContextId"] = Value::String(c.to_string());
        }
        json!({ "targetInfo": ti })
    }

    #[tokio::test]
    async fn req_arch_005_fill_into_own_context_allowed() {
        let mut script = HashMap::new();
        script.insert(
            "Target.createBrowserContext".to_string(),
            json!({ "browserContextId": "ctx-A" }),
        );
        script.insert(
            "Target.getTargetInfo".to_string(),
            target_info_json(Some("ctx-A"), "https://accounts.example.com/login"),
        );
        let mock = MockBrowser::start(script).await;
        let browser = Browser::new(mock.client().await);
        let ctx = browser.create_agent_context("agent-A").await.unwrap();
        let info = browser.check_ownership("t-1", &ctx, false).await.unwrap();
        assert_eq!(info.url, "https://accounts.example.com/login");
    }

    #[tokio::test]
    async fn req_arch_005_fill_into_another_agents_context_refused() {
        let mut script = HashMap::new();
        script.insert(
            "Target.createBrowserContext".to_string(),
            json!({ "browserContextId": "ctx-A" }),
        );
        script.insert(
            "Target.getTargetInfo".to_string(),
            target_info_json(Some("ctx-B"), "https://b.example/"),
        );
        let mock = MockBrowser::start(script).await;
        let browser = Browser::new(mock.client().await);
        let ctx_a = browser.create_agent_context("agent-A").await.unwrap();
        let err = browser
            .check_ownership("t-1", &ctx_a, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
    }

    #[tokio::test]
    async fn req_arch_005_default_context_refused_unless_allowed() {
        let mut script = HashMap::new();
        script.insert(
            "Target.createBrowserContext".to_string(),
            json!({ "browserContextId": "ctx-A" }),
        );
        script.insert(
            "Target.getTargetInfo".to_string(),
            target_info_json(None, "https://default.example/"),
        );
        let mock = MockBrowser::start(script).await;
        let browser = Browser::new(mock.client().await);
        let ctx = browser.create_agent_context("agent-A").await.unwrap();

        let err = browser
            .check_ownership("t-1", &ctx, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::DefaultContextRefused);

        // allow_default_context = true: single-agent setups may fill
        // the default context.
        let info = browser.check_ownership("t-1", &ctx, true).await.unwrap();
        assert_eq!(info.browser_context_id, None);
    }

    /// A browser whose agent context is `ctx-A`, whose one target `t-1`
    /// is in `target_context`, and whose `Target.getBrowserContexts`
    /// reply is `contexts`.
    async fn browser_with_contexts(
        target_context: &str,
        contexts: Value,
    ) -> (MockBrowser, Browser, AgentContext) {
        let mut script = HashMap::new();
        script.insert(
            "Target.createBrowserContext".to_string(),
            json!({ "browserContextId": "ctx-A" }),
        );
        script.insert(
            "Target.getTargetInfo".to_string(),
            target_info_json(Some(target_context), "https://default.example/"),
        );
        script.insert("Target.getBrowserContexts".to_string(), contexts);
        let mock = MockBrowser::start(script).await;
        let browser = Browser::new(mock.client().await);
        let ctx = browser.create_agent_context("agent-A").await.unwrap();
        (mock, browser, ctx)
    }

    // #342: real Chromium puts a `browserContextId` on default-context
    // targets too, and names that id in `Target.getBrowserContexts`.
    #[tokio::test]
    async fn req_arch_005_default_context_with_its_own_id_refused_unless_allowed() {
        let (_mock, browser, ctx) = browser_with_contexts(
            "ctx-default",
            json!({ "browserContextIds": ["ctx-A"], "defaultBrowserContextId": "ctx-default" }),
        )
        .await;

        let err = browser
            .check_ownership("t-1", &ctx, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::DefaultContextRefused);

        let info = browser.check_ownership("t-1", &ctx, true).await.unwrap();
        assert_eq!(info.browser_context_id.as_deref(), Some("ctx-default"));
    }

    // #342: a context someone else created (another agent's, or the
    // host runtime's own isolated one) is never the default context,
    // whatever `allow_default_context` says.
    #[tokio::test]
    async fn req_arch_005_another_created_context_is_not_the_default() {
        let (_mock, browser, ctx) = browser_with_contexts(
            "ctx-other",
            json!({
                "browserContextIds": ["ctx-A", "ctx-other"],
                "defaultBrowserContextId": "ctx-default",
            }),
        )
        .await;
        for allow_default in [false, true] {
            let err = browser
                .check_ownership("t-1", &ctx, allow_default)
                .await
                .unwrap_err();
            assert_eq!(err, OwnershipError::TargetNotOwned);
        }
    }

    // #342, older Chromium: no `defaultBrowserContextId` in the reply.
    // A target whose context nobody created is in the default context.
    #[tokio::test]
    async fn req_arch_005_unreported_default_is_the_context_nobody_created() {
        let (_mock, browser, ctx) = browser_with_contexts(
            "ctx-unlisted",
            json!({ "browserContextIds": ["ctx-A", "ctx-other"] }),
        )
        .await;

        let err = browser
            .check_ownership("t-1", &ctx, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::DefaultContextRefused);
        browser.check_ownership("t-1", &ctx, true).await.unwrap();
    }

    // #342, older Chromium: a created context stays `target_not_owned`.
    #[tokio::test]
    async fn req_arch_005_unreported_default_never_admits_a_created_context() {
        let (_mock, browser, ctx) = browser_with_contexts(
            "ctx-other",
            json!({ "browserContextIds": ["ctx-A", "ctx-other"] }),
        )
        .await;
        let err = browser
            .check_ownership("t-1", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
    }

    // #342: a browser that lists no contexts at all gives nothing to
    // tell the default context by, so an unknown id stays refused.
    #[tokio::test]
    async fn req_arch_005_no_context_list_keeps_an_unknown_context_refused() {
        let (_mock, browser, ctx) = browser_with_contexts("ctx-B", json!({})).await;
        let err = browser
            .check_ownership("t-1", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
    }
}
