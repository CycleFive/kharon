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
//! Chromium names that shared context with a `browserContextId` like
//! any other (#342). Each connection learns the id from
//! `Target.getBrowserContexts` (`defaultBrowserContextId`) the first
//! time it has to classify a target, and keeps it on the [`Browser`].
//! A reconnect builds a new `Browser`, so it learns the id again and
//! cannot reuse the previous browser's. A peer that omits the id
//! (stubs, older Chromium) still treats a missing `browserContextId`
//! as the default. An older Chromium that only returns
//! `browserContextIds` treats a target id as the default when it is
//! neither one of those created contexts nor a context this connection
//! created. An id that misses that list is checked against one fresh
//! `Target.getBrowserContexts` before it is called the default, so a
//! context another client creates later is not (#344). A failed
//! re-read is not the default and is not cached.

use std::sync::{Arc, Mutex};

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

/// What `Target.getBrowserContexts` said about the default context,
/// for one connection (#342).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultContext {
    /// `defaultBrowserContextId`, when the browser sent one.
    id: Option<String>,
    /// `browserContextIds`, when the reply included the field. `None`
    /// means the peer did not list created contexts, so an id is not
    /// guessed to be the default.
    created: Option<Vec<String>>,
}

impl DefaultContext {
    async fn resolve(client: &CdpClient) -> Result<Self, OwnershipError> {
        let result = client
            .request("Target.getBrowserContexts", json!({}))
            .await?;
        Ok(Self::from_reply(&result))
    }

    fn from_reply(result: &Value) -> Self {
        let id = result
            .get("defaultBrowserContextId")
            .and_then(Value::as_str)
            .map(String::from);
        let created = result.get("browserContextIds").and_then(|value| {
            value.as_array().map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
        });
        Self { id, created }
    }

    /// The browser sent `defaultBrowserContextId`. The fallback list
    /// is not consulted once this is set.
    fn named(&self) -> bool {
        self.id.is_some()
    }

    /// Whether `id` is this browser's default context.
    ///
    /// A named default is that id and no other. Without one, `id` is
    /// the default only when the browser listed the contexts it
    /// created and `id` is neither in that list nor a context this
    /// connection created (`agent_owned`). A reply with neither field
    /// is not a guess. A fallback miss is not trusted on its own:
    /// [`Browser::is_default_context`] re-reads the list once first
    /// (#344).
    fn is_default(&self, id: &str, agent_owned: bool) -> bool {
        if let Some(default_id) = &self.id {
            return id == default_id;
        }
        let Some(created) = &self.created else {
            return false;
        };
        !agent_owned && !created.iter().any(|created_id| created_id == id)
    }
}

/// A live target the broker knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    pub target_id: String,
    /// `browserContextId` as the browser reported it. `None` when the
    /// field was omitted, which stubs and some peers do for the default
    /// context. Chromium sets it for the default context too; that id
    /// is recognized in [`Browser::check_ownership`].
    pub browser_context_id: Option<String>,
    pub url: String,
    pub title: String,
    /// `iframe` targets are out-of-process subframes; the broker can
    /// attach to them directly (used for the REQ-ORG-004 iframe path).
    pub type_: String,
}

/// Browser-level context/target management on top of a [`CdpClient`].
///
/// Clones share one connection's default-context resolution. A
/// reconnect does not clone: it constructs a new [`Browser`], which
/// resolves again (#342).
#[derive(Clone)]
pub struct Browser {
    client: CdpClient,
    /// Contexts this connection created. An id here is never the
    /// default, including when the context list was read before the
    /// create returned.
    ///
    /// Lifetime is the connection. Dispose does not prune: the vec
    /// only ever holds ids this connection created, and a browser
    /// does not reuse a context id, so it stays bounded by that
    /// connection's own creates (#344).
    agent_contexts: Arc<Mutex<Vec<String>>>,
    /// Filled on the first ownership check that needs it. Empty on a
    /// new connection, so a restarted browser's id cannot linger.
    default_context: Arc<Mutex<Option<DefaultContext>>>,
    /// The `product` of the first `Browser.getVersion` reply that had
    /// one, read for a method fill's note (#382).
    product: Arc<Mutex<Option<String>>>,
}

impl Browser {
    pub fn new(client: CdpClient) -> Self {
        Self {
            client,
            agent_contexts: Arc::new(Mutex::new(Vec::new())),
            default_context: Arc::new(Mutex::new(None)),
            product: Arc::new(Mutex::new(None)),
        }
    }

    /// The browser's product string (`Browser.getVersion`), asked once
    /// per connection. `None` when the browser does not answer within a
    /// second; the next call asks again.
    pub async fn product(&self) -> Option<String> {
        if let Some(p) = self.product.lock().expect("product lock").clone() {
            return Some(p);
        }
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.client.request("Browser.getVersion", json!({})),
        )
        .await
        .ok()?
        .ok()?;
        let product = reply.get("product")?.as_str()?.to_owned();
        *self.product.lock().expect("product lock") = Some(product.clone());
        Some(product)
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
        self.agent_contexts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(id.to_string());
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
    ///
    /// The default context is a target that omitted `browserContextId`,
    /// or whose id is the `defaultBrowserContextId` this connection
    /// learned from `Target.getBrowserContexts`. When the browser did
    /// not name one, a present id is the default only if it is neither
    /// an agent context nor in the returned `browserContextIds`. A
    /// miss re-reads that list once before the id is the default
    /// (#344).
    pub async fn check_ownership(
        &self,
        target_id: &str,
        agent_ctx: &AgentContext,
        allow_default: bool,
    ) -> Result<TargetInfo, OwnershipError> {
        let info = self.target_info(target_id).await?;
        match info.browser_context_id.as_deref() {
            Some(id) if id == agent_ctx.browser_context_id() => Ok(info),
            Some(id) => {
                if self.is_default_context(id).await? {
                    default_context_gate(allow_default, info)
                } else {
                    Err(OwnershipError::TargetNotOwned)
                }
            }
            None => default_context_gate(allow_default, info),
        }
    }

    async fn is_default_context(&self, id: &str) -> Result<bool, OwnershipError> {
        let resolved = self.default_context().await?;
        let owned = self.agent_owned(id);
        // Named-id mode is settled by the snapshot. Fallback mode
        // re-reads once when the id misses it, before calling the id
        // the default (#344).
        if resolved.named() || !resolved.is_default(id, owned) {
            return Ok(resolved.is_default(id, owned));
        }
        self.reread_fallback(id).await
    }

    /// One fresh `Target.getBrowserContexts` before a fallback miss is
    /// the default (#344).
    ///
    /// The std mutex is taken only to publish a successful reply, never
    /// across this await. A failed read is not stored and is not the
    /// default: the fill is refused, and the next check tries again
    /// against the snapshot already cached.
    async fn reread_fallback(&self, id: &str) -> Result<bool, OwnershipError> {
        let fresh = match DefaultContext::resolve(&self.client).await {
            Ok(fresh) => fresh,
            Err(_) => return Ok(false),
        };
        self.store_default(fresh.clone());
        Ok(fresh.is_default(id, self.agent_owned(id)))
    }

    fn store_default(&self, resolved: DefaultContext) {
        *self
            .default_context
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(resolved);
    }

    /// The default-context snapshot for this connection.
    ///
    /// Learned on the first check that needs it. A failed read is not
    /// cached: the next check tries again. A cancelled check (the fill
    /// deadline dropping this future) stores nothing, because the value
    /// is written only after the reply arrives. A fallback miss may
    /// replace a stored snapshot ([`Self::reread_fallback`]); that
    /// refresh follows the same "store only a reply we received" rule.
    async fn default_context(&self) -> Result<DefaultContext, OwnershipError> {
        if let Some(resolved) = self.cached_default() {
            return Ok(resolved);
        }
        let resolved = DefaultContext::resolve(&self.client).await?;
        let mut slot = self
            .default_context
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = slot.clone() {
            return Ok(existing);
        }
        *slot = Some(resolved.clone());
        Ok(resolved)
    }

    fn cached_default(&self) -> Option<DefaultContext> {
        self.default_context
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn agent_owned(&self, id: &str) -> bool {
        self.agent_contexts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|created| created == id)
    }

    /// Open `url` in a new tab in the agent's context and return the
    /// target id plus the tab's live https origin (REQ-API-012).
    ///
    /// `allow_default` creates the tab in the browser's default context
    /// (the single-agent escape hatch, the same one fills accept).
    /// Otherwise the tab is created in `agent_ctx`. The new target is
    /// checked with [`Self::check_ownership`] before navigation; a tab
    /// that would not belong to the agent is closed and not navigated.
    ///
    /// `url` is sent only as the `Page.navigate` parameter. It is not
    /// logged, and it is not copied into the error text: a browser
    /// message can echo it (REQ-API-012). The returned origin is
    /// scheme, host and port.
    pub async fn open_login_tab(
        &self,
        agent_ctx: &AgentContext,
        allow_default: bool,
        url: &str,
    ) -> Result<(String, String), OwnershipError> {
        let mut params = json!({ "url": "about:blank" });
        if !allow_default {
            params["browserContextId"] = json!(agent_ctx.browser_context_id());
        }
        let created = self
            .client
            .request("Target.createTarget", params)
            .await
            .map_err(|_| OwnershipError::Cdp("create_target_failed".into()))?;
        let target_id = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| OwnershipError::Cdp("create_target_failed".into()))?
            .to_string();
        // Armed until the open succeeds. A drop (the fill deadline
        // cancelling this future mid-navigate) closes the tab, so a
        // timeout does not leave the full URL open in the agent's
        // context (REQ-API-012).
        let mut guard = TabGuard::arm(self.client.clone(), target_id.clone());
        if let Err(e) = self
            .check_ownership(&target_id, agent_ctx, allow_default)
            .await
        {
            self.close_guard(&mut guard).await;
            return Err(e);
        }
        let attached = self.client.attach(&target_id).await;
        let session = match attached {
            Ok(session) => session,
            Err(_) => {
                self.close_guard(&mut guard).await;
                return Err(OwnershipError::Cdp("navigate_failed".into()));
            }
        };
        let navigated = session
            .request("Page.navigate", json!({ "url": url }))
            .await;
        session.detach().await;
        if navigated.is_err() {
            self.close_guard(&mut guard).await;
            return Err(OwnershipError::Cdp("navigate_failed".into()));
        }
        match self.wait_https_origin(&target_id).await {
            Ok(origin) => {
                guard.disarm();
                Ok((target_id, origin))
            }
            Err(e) => {
                self.close_guard(&mut guard).await;
                Err(e)
            }
        }
    }

    /// Close the guarded tab and disarm, so `Drop` does not close it
    /// again. If this future is cancelled mid-close, `Drop` still
    /// closes.
    async fn close_guard(&self, guard: &mut TabGuard) {
        let Some(id) = guard.target_id.clone() else {
            return;
        };
        let _ = self
            .client
            .request("Target.closeTarget", json!({ "targetId": id }))
            .await;
        guard.disarm();
    }

    /// Poll the target until its live URL has an https origin, or the
    /// navigation has clearly failed. The URL itself is never returned.
    async fn wait_https_origin(&self, target_id: &str) -> Result<String, OwnershipError> {
        let started = tokio::time::Instant::now();
        loop {
            let info = self
                .target_info(target_id)
                .await
                .map_err(|_| OwnershipError::Cdp("navigate_failed".into()))?;
            if let Some(origin) = https_origin_only(&info.url) {
                return Ok(origin);
            }
            if !is_blank_url(&info.url) {
                return Err(OwnershipError::Cdp("navigate_failed".into()));
            }
            if started.elapsed() > std::time::Duration::from_secs(8) {
                return Err(OwnershipError::Cdp("navigate_failed".into()));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

/// Closes `target_id` if this open is dropped before it succeeds.
///
/// The broker bounds `kharon_open` with `timeout_at`, which drops the
/// future. Without this, a deadline during `Page.navigate` or the
/// origin poll would leave the tab at the full login URL (REQ-API-012).
struct TabGuard {
    client: CdpClient,
    target_id: Option<String>,
}

impl TabGuard {
    fn arm(client: CdpClient, target_id: String) -> Self {
        Self {
            client,
            target_id: Some(target_id),
        }
    }

    fn disarm(&mut self) {
        self.target_id = None;
    }
}

impl Drop for TabGuard {
    fn drop(&mut self) {
        let Some(target_id) = self.target_id.take() else {
            return;
        };
        let client = self.client.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = client
                    .request("Target.closeTarget", json!({ "targetId": target_id }))
                    .await;
            });
        }
    }
}

/// `about:blank` and the empty URL, which a new tab reports before
/// navigation commits.
fn is_blank_url(href: &str) -> bool {
    href.is_empty() || href == "about:blank" || href.starts_with("about:blank#")
}

/// Scheme, host and port of an https URL. `None` when `href` is not
/// https, or when the origin serialization still carries a path,
/// query, fragment or userinfo.
fn https_origin_only(href: &str) -> Option<String> {
    let url = url::Url::parse(href).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    if origin == "null" || origin.contains('?') || origin.contains('#') || origin.contains('@') {
        return None;
    }
    let parsed = url::Url::parse(&origin).ok()?;
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return None;
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return None;
    }
    Some(origin)
}

/// `allow_default` admits a target the broker has classified as the
/// browser's default context; otherwise the fill is refused.
fn default_context_gate(
    allow_default: bool,
    info: TargetInfo,
) -> Result<TargetInfo, OwnershipError> {
    if allow_default {
        Ok(info)
    } else {
        Err(OwnershipError::DefaultContextRefused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    /// Mock browser peer. `start` answers each method with one fixed
    /// result; `start_with` sees the request, so a test can vary by
    /// target id.
    struct MockBrowser {
        addr: std::net::SocketAddr,
        _task: tokio::task::JoinHandle<()>,
    }

    impl MockBrowser {
        async fn start(script: HashMap<String, Value>) -> Self {
            let script = Arc::new(script);
            Self::start_with(move |msg| {
                let method = msg["method"].as_str().unwrap_or("");
                script.get(method).cloned().unwrap_or_else(|| json!({}))
            })
            .await
        }

        async fn start_with(script: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Self {
            Self::start_messages(move |msg| json!({ "id": msg["id"], "result": script(msg) })).await
        }

        /// `script` returns the whole reply, including the echoed `id`,
        /// so a test can answer with an `error` object instead of a
        /// `result`.
        async fn start_messages(script: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let script = Arc::new(script);
            let _task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws = accept_async(stream).await.unwrap();
                while let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) =
                    ws.next().await
                {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    let reply = script(&msg);
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

    fn target_info_json(target_id: &str, context: Option<&str>, url: &str) -> Value {
        let mut ti = json!({
            "targetId": target_id,
            "url": url,
            "title": "",
            "type": "page",
        });
        if let Some(c) = context {
            ti["browserContextId"] = Value::String(c.to_string());
        }
        json!({ "targetInfo": ti })
    }

    async fn connect(
        script: impl Fn(&Value) -> Value + Send + Sync + 'static,
    ) -> (MockBrowser, Browser) {
        let mock = MockBrowser::start_with(script).await;
        let browser = Browser::new(mock.client().await);
        (mock, browser)
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
            target_info_json("t-1", Some("ctx-A"), "https://accounts.example.com/login"),
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
            target_info_json("t-1", Some("ctx-B"), "https://b.example/"),
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
            target_info_json("t-1", None, "https://default.example/"),
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

    /// #342: Chromium sets `browserContextId` on a default-context tab.
    /// The stub names that id. The flag still decides, and a context
    /// the browser created (not the default) stays unowned.
    #[tokio::test]
    async fn req_arch_005_named_default_context_follows_the_flag() {
        let (_mock, browser) = connect(|msg| match msg["method"].as_str() {
            Some("Target.createBrowserContext") => json!({ "browserContextId": "ctx-A" }),
            Some("Target.getBrowserContexts") => json!({
                "browserContextIds": ["ctx-A", "ctx-other"],
                "defaultBrowserContextId": "def-1",
            }),
            Some("Target.getTargetInfo") => {
                let (id, ctx) = match msg["params"]["targetId"].as_str() {
                    Some("t-other") => ("t-other", Some("ctx-other")),
                    Some("t-stray") => ("t-stray", Some("ctx-stray")),
                    Some("t-omit") => ("t-omit", None),
                    _ => ("t-default", Some("def-1")),
                };
                target_info_json(id, ctx, "https://default.example/")
            }
            _ => json!({}),
        })
        .await;
        let ctx = browser.create_agent_context("agent-A").await.unwrap();

        let err = browser
            .check_ownership("t-default", &ctx, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::DefaultContextRefused);
        let info = browser
            .check_ownership("t-default", &ctx, true)
            .await
            .unwrap();
        assert_eq!(info.browser_context_id.as_deref(), Some("def-1"));

        // Another created context, even with the flag on.
        let err = browser
            .check_ownership("t-other", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);

        // Knowing the default id, an id that merely fails to appear in
        // `browserContextIds` is not the default. The older-Chromium
        // fallback does not run once the browser named one.
        let err = browser
            .check_ownership("t-stray", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);

        // Peers that omit the field are still the default context.
        let err = browser
            .check_ownership("t-omit", &ctx, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::DefaultContextRefused);
        let info = browser.check_ownership("t-omit", &ctx, true).await.unwrap();
        assert_eq!(info.browser_context_id, None);
    }

    /// #342: older Chromium returns `browserContextIds` and no
    /// `defaultBrowserContextId`. An id in neither that list nor the
    /// contexts this connection created is the default. A created
    /// context (OpenClaw's dashboard, or another agent context) is not.
    #[tokio::test]
    async fn req_arch_005_unlisted_context_is_default_without_a_named_id() {
        let creates = Arc::new(AtomicUsize::new(0));
        let (_mock, browser) = connect(move |msg| match msg["method"].as_str() {
            Some("Target.createBrowserContext") => {
                let n = creates.fetch_add(1, Ordering::SeqCst);
                json!({ "browserContextId": if n == 0 { "ctx-A" } else { "ctx-B" } })
            }
            Some("Target.getBrowserContexts") => json!({
                "browserContextIds": ["ctx-dash"],
            }),
            Some("Target.getTargetInfo") => {
                let (id, ctx) = match msg["params"]["targetId"].as_str() {
                    Some("t-dash") => ("t-dash", Some("ctx-dash")),
                    Some("t-agent") => ("t-agent", Some("ctx-B")),
                    Some("t-own") => ("t-own", Some("ctx-A")),
                    _ => ("t-plain", Some("ctx-plain")),
                };
                target_info_json(id, ctx, "https://old.example/")
            }
            _ => json!({}),
        })
        .await;
        let ctx = browser.create_agent_context("agent-A").await.unwrap();
        // Created on this connection, and absent from `browserContextIds`.
        let _other = browser.create_agent_context("agent-B").await.unwrap();

        let own = browser.check_ownership("t-own", &ctx, false).await.unwrap();
        assert_eq!(own.browser_context_id.as_deref(), Some("ctx-A"));

        let err = browser
            .check_ownership("t-plain", &ctx, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::DefaultContextRefused);
        let info = browser
            .check_ownership("t-plain", &ctx, true)
            .await
            .unwrap();
        assert_eq!(info.browser_context_id.as_deref(), Some("ctx-plain"));

        let err = browser
            .check_ownership("t-dash", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
        let err = browser
            .check_ownership("t-agent", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
    }

    /// #342: the resolved id belongs to the connection. A reconnect
    /// (a new [`Browser`]) learns the new browser's id; the previous
    /// default id is not still the default.
    #[tokio::test]
    async fn req_arch_005_default_context_id_refreshes_on_reconnect() {
        async fn open(default_id: &'static str) -> (MockBrowser, Browser, AgentContext) {
            let (mock, browser) = connect(move |msg| match msg["method"].as_str() {
                Some("Target.createBrowserContext") => json!({ "browserContextId": "ctx-A" }),
                Some("Target.getBrowserContexts") => json!({
                    "browserContextIds": ["ctx-A"],
                    "defaultBrowserContextId": default_id,
                }),
                Some("Target.getTargetInfo") => {
                    let id = msg["params"]["targetId"].as_str().unwrap_or("t-new");
                    let ctx = if id == "t-old" { "def-1" } else { default_id };
                    target_info_json(id, Some(ctx), "https://default.example/")
                }
                _ => json!({}),
            })
            .await;
            let ctx = browser.create_agent_context("agent-A").await.unwrap();
            (mock, browser, ctx)
        }

        let (mock, browser, ctx) = open("def-1").await;
        let err = browser
            .check_ownership("t-new", &ctx, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::DefaultContextRefused);
        drop(browser);
        drop(ctx);
        drop(mock);

        let (_mock, browser, ctx) = open("def-2").await;
        let err = browser
            .check_ownership("t-old", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
        let info = browser.check_ownership("t-new", &ctx, true).await.unwrap();
        assert_eq!(info.browser_context_id.as_deref(), Some("def-2"));
        let err = browser
            .check_ownership("t-new", &ctx, false)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::DefaultContextRefused);
    }

    /// #344: fallback mode. The `browserContextIds` snapshot is taken
    /// on the first ownership check. A context another CDP client
    /// creates after that is not the default: the miss re-reads
    /// `Target.getBrowserContexts` once before the classification.
    #[tokio::test]
    async fn req_arch_005_fallback_rereads_a_context_created_after_the_snapshot() {
        let contexts = Arc::new(std::sync::Mutex::new(vec!["ctx-A".to_string()]));
        let listed = Arc::clone(&contexts);
        let reads = Arc::new(AtomicUsize::new(0));
        let reads_script = Arc::clone(&reads);
        let (_mock, browser) = connect(move |msg| match msg["method"].as_str() {
            Some("Target.createBrowserContext") => json!({ "browserContextId": "ctx-A" }),
            Some("Target.getBrowserContexts") => {
                let _ = reads_script.fetch_add(1, Ordering::SeqCst);
                let ids = listed.lock().unwrap_or_else(|p| p.into_inner()).clone();
                json!({ "browserContextIds": ids })
            }
            Some("Target.getTargetInfo") => {
                let (id, ctx) = match msg["params"]["targetId"].as_str() {
                    Some("t-later") => ("t-later", Some("ctx-later")),
                    _ => ("t-plain", Some("ctx-plain")),
                };
                target_info_json(id, ctx, "https://old.example/")
            }
            _ => json!({}),
        })
        .await;
        let ctx = browser.create_agent_context("agent-A").await.unwrap();

        // First check caches [ctx-A]. ctx-plain misses it, so this
        // also re-reads once, and the id is still the default.
        let info = browser
            .check_ownership("t-plain", &ctx, true)
            .await
            .unwrap();
        assert_eq!(info.browser_context_id.as_deref(), Some("ctx-plain"));
        let after_first = reads.load(Ordering::SeqCst);
        assert!(after_first >= 1, "the snapshot was read");

        // Another client creates a context. The cached list does not
        // have it until the re-read.
        contexts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push("ctx-later".to_string());

        let err = browser
            .check_ownership("t-later", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            after_first + 1,
            "a fallback miss re-reads getBrowserContexts once"
        );

        // An id that is still on neither list stays the default.
        let info = browser
            .check_ownership("t-plain", &ctx, true)
            .await
            .unwrap();
        assert_eq!(info.browser_context_id.as_deref(), Some("ctx-plain"));
    }

    /// #344: a failed fallback re-read is not the default and is not
    /// cached. The next check asks the browser again.
    #[tokio::test]
    async fn req_arch_005_fallback_reread_failure_is_not_default_and_not_cached() {
        // 0: list without the late context. 1: the re-read fails.
        // 2: the browser answers again, now including that context.
        let phase = Arc::new(AtomicUsize::new(0));
        let phase_script = Arc::clone(&phase);
        let reads = Arc::new(AtomicUsize::new(0));
        let reads_script = Arc::clone(&reads);
        let mock = MockBrowser::start_messages(move |msg| {
            let result = match msg["method"].as_str() {
                Some("Target.createBrowserContext") => json!({ "browserContextId": "ctx-A" }),
                Some("Target.getBrowserContexts") => {
                    let _ = reads_script.fetch_add(1, Ordering::SeqCst);
                    if phase_script.load(Ordering::SeqCst) == 1 {
                        return json!({
                            "id": msg["id"],
                            "error": { "code": -32000, "message": "unavailable" },
                        });
                    }
                    let ids = if phase_script.load(Ordering::SeqCst) == 0 {
                        vec!["ctx-A", "ctx-known"]
                    } else {
                        vec!["ctx-A", "ctx-known", "ctx-later"]
                    };
                    json!({ "browserContextIds": ids })
                }
                Some("Target.getTargetInfo") => {
                    let (id, ctx) = match msg["params"]["targetId"].as_str() {
                        Some("t-known") => ("t-known", Some("ctx-known")),
                        Some("t-later") => ("t-later", Some("ctx-later")),
                        _ => ("t-plain", Some("ctx-plain")),
                    };
                    target_info_json(id, ctx, "https://old.example/")
                }
                _ => json!({}),
            };
            json!({ "id": msg["id"], "result": result })
        })
        .await;
        let browser = Browser::new(mock.client().await);
        let ctx = browser.create_agent_context("agent-A").await.unwrap();

        // In the snapshot, so this primes the cache and does not re-read.
        let err = browser
            .check_ownership("t-known", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        phase.store(1, Ordering::SeqCst);
        let err = browser
            .check_ownership("t-later", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "the miss re-reads once and does not retry the failure"
        );

        // The failure was not cached: a later read sees the context
        // the other client created, and an id still missing the list
        // is the default.
        phase.store(2, Ordering::SeqCst);
        let err = browser
            .check_ownership("t-later", &ctx, true)
            .await
            .unwrap_err();
        assert_eq!(err, OwnershipError::TargetNotOwned);
        let info = browser
            .check_ownership("t-plain", &ctx, true)
            .await
            .unwrap();
        assert_eq!(info.browser_context_id.as_deref(), Some("ctx-plain"));
    }

    /// A navigate that never replies, dropped by the fill deadline,
    /// still closes the tab (REQ-API-012).
    #[tokio::test]
    async fn req_api_012_dropped_navigate_closes_the_tab() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let closed = Arc::new(AtomicBool::new(false));
        let methods = Arc::new(Mutex::new(Vec::<String>::new()));
        let closed_peer = Arc::clone(&closed);
        let methods_peer = Arc::clone(&methods);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            while let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) =
                ws.next().await
            {
                let msg: Value = serde_json::from_str(&text).unwrap();
                let method = msg["method"].as_str().unwrap_or("").to_string();
                methods_peer.lock().unwrap().push(method.clone());
                if method == "Page.navigate" {
                    continue;
                }
                if method == "Target.closeTarget" {
                    closed_peer.store(true, Ordering::SeqCst);
                }
                let result = match method.as_str() {
                    "Target.createBrowserContext" => json!({ "browserContextId": "ctx-A" }),
                    "Target.createTarget" => json!({ "targetId": "tab-1" }),
                    "Target.getTargetInfo" => {
                        target_info_json("tab-1", Some("ctx-A"), "about:blank")
                    }
                    "Target.attachToTarget" => json!({ "sessionId": "sess-1" }),
                    _ => json!({}),
                };
                let reply = json!({ "id": msg["id"], "result": result });
                ws.send(tokio_tungstenite::tungstenite::Message::Text(
                    reply.to_string(),
                ))
                .await
                .unwrap();
            }
        });
        let endpoint = super::super::endpoint::CdpEndpoint::validate(
            &format!("ws://{addr}/devtools/browser"),
            super::super::endpoint::Tunnel::Direct,
            None,
        )
        .unwrap();
        let browser = Browser::new(CdpClient::connect(&endpoint).await.unwrap());
        let ctx = browser.create_agent_context("agent-A").await.unwrap();
        let open = browser.open_login_tab(
            &ctx,
            false,
            "https://login.example.com/KHARON_OPEN_PATH_CANARY?q=1",
        );
        let timed = tokio::time::timeout(std::time::Duration::from_millis(300), open).await;
        assert!(timed.is_err(), "a stalled navigate must still be pending");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while !closed.load(Ordering::SeqCst) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "dropped navigate did not close the tab: {:?}",
                methods.lock().unwrap()
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}
