//! HTTP transport: `/v1/*` (REQ-API-002; SPEC §4), and the listener
//! the MCP transport (`POST /mcp`, [`super::mcp`]) shares.
//!
//! A single fallback handler routes by hand so that every response
//! body is one this crate wrote: axum's extractors produce rejection
//! bodies that interpolate request data, and REQ-API-006 allows only
//! fixed details. Routes:
//!
//! | Route | Auth | |
//! |---|---|---|
//! | `GET /v1/status` | bearer | `StatusBody` |
//! | `GET /v1/items[?origin=]` | bearer | list, `[ItemMeta]` |
//! | `GET /v1/items?q=[&origin=]` | bearer | search, `[ItemMeta]` |
//! | `POST /v1/fill` | bearer | `FillRequest` → `FillResult` (`submit: true` is `fill_and_submit`) |
//! | `POST /v1/fill_totp` | bearer | `FillTotpRequest` → `FillResult` |
//! | `POST /v1/context` | bearer | empty or `{}` → `ContextResult` (the agent's `browserContextId`, #65) |
//! | `POST /v1/grants` | bearer | `GrantRequest` → `GrantRequestBody` (`{grant_request_id, state}`, #20) |
//! | `GET /v1/openapi.json` | none | the OpenAPI document |
//! | `POST /mcp` | bearer | MCP over Streamable HTTP ([`super::mcp`]) |
//!
//! ntfy redeem (`GET`/`POST` `/owner/approve/<token>` and
//! `/owner/deny/<token>`, REQ-APR-004) is served on the owner UI
//! listener (loopback). [`serve_owner`] binds that surface on its
//! own for tests. The agent router leaves those paths unrouted
//! (REQ-DEP-006, #136).
//!
//! Order: route (404), method (405), bearer token (401), parameters
//! (400), then [`Broker::dispatch`]. The fill routes take a JSON body
//! instead of a query: route (404), method (405, `Allow: POST`), a
//! browser `Origin` (403, as on `/mcp`), bearer token (401), content
//! type and size (400), [`parse_fill`] (400), then [`Broker::fill`],
//! whose REQ-API-009 deadline runs from when the handler was entered.
//! `POST /v1/context` has the same order, with an optional body (empty or
//! `{}`; JSON content type required only when non-empty), then
//! [`Broker::context`] under the same deadline. Token verification is one
//! Argon2id evaluation (~19 MiB, tens of ms); it runs on the blocking
//! pool behind a semaphore so concurrent bad tokens cannot exhaust
//! memory or starve the runtime.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use axum::serve::IncomingStream;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use axum::body::to_bytes;
use tokio::time::Instant;

use super::approval::{ApprovalAction, TokenGone};
use super::core::{
    AgentId, Broker, Operation, Request as ApiRequest, VaultView, parse_context_body, parse_request,
};
use super::error::{ApiError, Detail, ErrorCode};
use super::fill::{FillOperation, parse_fill};
use super::grant::{ApprovalPrompt, parse_grant};
use super::mcp::{MAX_BODY_BYTES, is_json};
use super::transport::ClientIp;
use crate::lock::Clock;

/// The OpenAPI 3.1 document for this transport.
pub const OPENAPI_JSON: &str = include_str!("../../../../docs/api/openapi.json");

/// Concurrent token verifications.
const MAX_CONCURRENT_AUTH: usize = 4;

pub(super) struct AppState<S: VaultView, C: Clock> {
    pub(super) broker: Arc<Broker<S, C>>,
    auth_permits: Semaphore,
}

impl<S: VaultView, C: Clock> AppState<S, C> {
    /// Per-listener state: each listener gets its own token-verification
    /// semaphore, so a flood of bad tokens on one listener (the public
    /// ingress, #198) cannot starve another (the tailnet `[api]`).
    pub(super) fn new(broker: Arc<Broker<S, C>>) -> Arc<Self> {
        Arc::new(Self {
            broker,
            auth_permits: Semaphore::new(MAX_CONCURRENT_AUTH),
        })
    }
}

/// The TCP peer of an `[api]` connection: the client itself (the
/// tailnet authenticates the path). Mirrors the one in
/// [`super::public`]; the two listeners name their own peers.
#[derive(Debug, Clone, Copy)]
pub(super) struct Peer(std::net::SocketAddr);

impl Connected<IncomingStream<'_, TcpListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

/// The `/v1` router over `broker`.
pub fn router<S, C>(broker: Arc<Broker<S, C>>) -> Router
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    Router::new()
        .fallback(handle::<S, C>)
        .with_state(AppState::new(broker))
}

/// Serve the API on `listener` until the future is dropped.
pub async fn serve<S, C>(listener: TcpListener, broker: Arc<Broker<S, C>>) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    axum::serve(
        listener,
        router(broker).into_make_service_with_connect_info::<Peer>(),
    )
    .await
}

/// [`serve`], returning once `shutdown` resolves and in-flight
/// requests have finished (the daemon's SIGTERM/SIGINT path).
pub async fn serve_with_shutdown<S, C, F>(
    listener: TcpListener,
    broker: Arc<Broker<S, C>>,
    shutdown: F,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        router(broker).into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Path B agent API (REQ-DEP-006): the same router over TLS. Plain HTTP
/// bytes on this listener fail the handshake and are not dispatched.
pub async fn serve_tls_with_shutdown<S, C, F>(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    broker: Arc<Broker<S, C>>,
    shutdown: F,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        TlsListener::new(listener, tls),
        router(broker).into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// TCP listener that completes a TLS handshake before axum sees the stream.
pub(super) struct TlsListener {
    tcp: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    pub(super) fn new(tcp: TcpListener, tls: Arc<rustls::ServerConfig>) -> Self {
        Self {
            tcp,
            acceptor: tokio_rustls::TlsAcceptor::from(tls),
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (sock, addr) = match self.tcp.accept().await {
                Ok(pair) => pair,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    continue;
                }
            };
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.acceptor.accept(sock),
            )
            .await
            {
                Ok(Ok(tls)) => return (tls, addr),
                _ => continue,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// Serve the ntfy redeem routes on `listener`.
///
/// This is the owner-listener surface (REQ-DEP-006, #136): `GET`/`POST`
/// [`OWNER_APPROVE_PREFIX`] and [`OWNER_DENY_PREFIX`]. The daemon
/// mounts the same handler on the owner UI listener; tests bind it
/// here when they do not need the rest of the UI. The agent router
/// ([`router`]) does not include it.
pub async fn serve_owner<S, C>(
    listener: TcpListener,
    broker: Arc<Broker<S, C>>,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    axum::serve(listener, owner_router(broker)).await
}

fn owner_router<S, C>(broker: Arc<Broker<S, C>>) -> Router
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    Router::new()
        .fallback(handle_owner_redeem::<S, C>)
        .with_state(broker)
}

async fn handle_owner_redeem<S, C>(
    State(broker): State<Arc<Broker<S, C>>>,
    req: Request,
) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    dispatch_owner_approval(broker, method, path).await
}

/// Broker calls the owner listener needs to render and redeem an
/// ntfy one-time token (REQ-APR-004). [`Broker`] implements this.
pub trait ApprovalRedeemer: Send + Sync + 'static {
    /// Peek the token. Does not consume it and does not change
    /// grant state.
    fn prompt(&self, token: &str) -> Result<(ApprovalPrompt, ApprovalAction), TokenGone>;

    /// Consume the token and decide the request.
    fn redeem(&self, token: &str) -> Result<ApprovalAction, TokenGone>;
}

impl<S, C> ApprovalRedeemer for Broker<S, C>
where
    S: VaultView + 'static,
    C: Clock + 'static,
{
    fn prompt(&self, token: &str) -> Result<(ApprovalPrompt, ApprovalAction), TokenGone> {
        self.approval_token_prompt(token)
    }

    fn redeem(&self, token: &str) -> Result<ApprovalAction, TokenGone> {
        self.redeem_approval_token(token)
    }
}

/// Run the redeem response off the async worker. A panicked worker
/// answers 410, the same as an unknown token: the caller learns
/// nothing about the failure.
pub(crate) async fn dispatch_owner_approval(
    redeem: Arc<dyn ApprovalRedeemer>,
    method: Method,
    path: String,
) -> Response {
    tokio::task::spawn_blocking(move || owner_approval_response(redeem.as_ref(), &method, &path))
        .await
        .unwrap_or_else(|_| token_gone())
}

enum Route {
    Status,
    Items,
    OpenApi,
}

/// `POST /v1/fill`.
pub const FILL_PATH: &str = "/v1/fill";
/// `POST /v1/fill_totp`.
pub const FILL_TOTP_PATH: &str = "/v1/fill_totp";
/// `POST /v1/context` (#65).
pub const CONTEXT_PATH: &str = "/v1/context";
/// `POST /v1/grants` (#20).
pub const GRANTS_PATH: &str = "/v1/grants";

async fn handle<S, C>(
    State(state): State<Arc<AppState<S, C>>>,
    ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
    mut req: Request,
) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    // This listener's peer is the client (#200). CF-Connecting-IP is
    // honoured only on [public_ingress]; here a spoofed header is
    // ignored by construction — the extension is the peer, full stop.
    req.extensions_mut().insert(ClientIp(peer.ip()));
    let received = Instant::now();
    let route = match req.uri().path() {
        "/v1/status" => Route::Status,
        "/v1/items" => Route::Items,
        "/v1/openapi.json" => Route::OpenApi,
        FILL_PATH => return handle_fill(state, req, FillOperation::Fill, received).await,
        FILL_TOTP_PATH => {
            return handle_fill(state, req, FillOperation::FillTotp, received).await;
        }
        CONTEXT_PATH => return handle_context(state, req, received).await,
        GRANTS_PATH => return handle_grants(state, req, received).await,
        super::mcp::MCP_PATH => return super::mcp::handle(state, req).await,
        _ => return error(ApiError::new(ErrorCode::NotFound, Detail::NoSuchRoute)),
    };
    if req.method() != Method::GET {
        return error(ApiError::new(
            ErrorCode::MethodNotAllowed,
            Detail::MethodNotAllowed,
        ));
    }
    if let Route::OpenApi = route {
        return json_response(StatusCode::OK, OPENAPI_JSON.to_owned());
    }
    // Pull everything out of `req` before awaiting: `Request` is not
    // `Sync`, so a borrow held across the await would make the future
    // `!Send`.
    let token = bearer_token(&req);
    let query = req.uri().query().map(str::to_owned);
    drop(req);
    let agent = match authenticate(&state, token).await {
        Ok(a) => a,
        Err(e) => return error(e),
    };
    let op = match route {
        Route::Status => Operation::Status,
        Route::Items => Operation::Items,
        Route::OpenApi => unreachable!("handled above"),
    };
    let api_req = parse_query(op, query.as_deref().unwrap_or(""));
    let outcome = api_req.and_then(|r| state.broker.dispatch(&agent, r));
    match outcome {
        Ok(o) => json_response(StatusCode::OK, o.body().to_string()),
        Err(e) => error(e),
    }
}

async fn handle_fill<S, C>(
    state: Arc<AppState<S, C>>,
    req: Request,
    op: FillOperation,
    received: Instant,
) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    if req.method() != Method::POST {
        return method_not_allowed("POST");
    }
    if req.headers().contains_key(header::ORIGIN) {
        return error(ApiError::new(
            ErrorCode::Forbidden,
            Detail::BrowserOriginRefused,
        ));
    }
    let token = bearer_token(&req);
    let (parts, body) = req.into_parts();
    let agent = match authenticate(&state, token).await {
        Ok(a) => a,
        Err(e) => return error(e),
    };
    if !is_json(&parts.headers) {
        return error(ApiError::bad_request(Detail::UnsupportedContentType));
    }
    drop(parts);
    let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return error(ApiError::BODY_TOO_LARGE);
    };
    let fill_req = match parse_fill(op, &bytes) {
        Ok(r) => r,
        Err(e) => return error(e),
    };
    drop(bytes);
    match state.broker.fill(&agent, fill_req, received).await {
        Ok(o) => json_response(StatusCode::OK, o.body().to_string()),
        Err(e) => error(e),
    }
}

async fn handle_context<S, C>(
    state: Arc<AppState<S, C>>,
    req: Request,
    received: Instant,
) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    if req.method() != Method::POST {
        return method_not_allowed("POST");
    }
    if req.headers().contains_key(header::ORIGIN) {
        return error(ApiError::new(
            ErrorCode::Forbidden,
            Detail::BrowserOriginRefused,
        ));
    }
    let token = bearer_token(&req);
    let (parts, body) = req.into_parts();
    let agent = match authenticate(&state, token).await {
        Ok(a) => a,
        Err(e) => return error(e),
    };
    let json = is_json(&parts.headers);
    drop(parts);
    let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return error(ApiError::BODY_TOO_LARGE);
    };
    if !bytes.is_empty() && !json {
        return error(ApiError::bad_request(Detail::UnsupportedContentType));
    }
    if let Err(e) = parse_context_body(&bytes) {
        return error(e);
    }
    match state.broker.context(&agent, received).await {
        Ok(o) => json_response(StatusCode::OK, o.body().to_string()),
        Err(e) => error(e),
    }
}

/// `/owner/approve/<token>` prefix (REQ-APR-004, #21).
pub const OWNER_APPROVE_PREFIX: &str = "/owner/approve/";
/// `/owner/deny/<token>` prefix (REQ-APR-004, #21).
pub const OWNER_DENY_PREFIX: &str = "/owner/deny/";

fn html_response(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .expect("invariant: static headers are valid")
}

/// 410 for a used, expired or unknown approval token (REQ-APR-004).
fn token_gone() -> Response {
    html_response(
        StatusCode::GONE,
        "<!doctype html><title>kharon</title><p>This approval link is no longer valid.</p>"
            .to_owned(),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The ntfy one-time approval endpoints (REQ-APR-004, #21), served on
/// the owner listener. No bearer <redacted>: the 256-bit token in the path
/// *is* the credential, which is why it is single-use and lives 120 s.
/// GET renders a confirm page and never mutates grant state; POST
/// redeems the token and decides the request. A token presented to
/// the wrong action's endpoint is treated as gone.
fn owner_approval_response(redeem: &dyn ApprovalRedeemer, method: &Method, path: &str) -> Response {
    let (expected, token) = if let Some(t) = path.strip_prefix(OWNER_APPROVE_PREFIX) {
        (ApprovalAction::Approve, t)
    } else if let Some(t) = path.strip_prefix(OWNER_DENY_PREFIX) {
        (ApprovalAction::Deny, t)
    } else {
        return error(ApiError::new(ErrorCode::NotFound, Detail::NoSuchRoute));
    };
    if token.is_empty() || token.contains('/') {
        return token_gone();
    }
    if method == Method::GET {
        return match redeem.prompt(token) {
            Ok((prompt, action)) if action == expected => {
                let verb = match action {
                    ApprovalAction::Approve => "approve",
                    ApprovalAction::Deny => "deny",
                };
                let body = format!(
                    "<!doctype html><title>kharon — {verb} request</title>\
                     <h1>{verb} this grant request?</h1>\
                     <p>Agent: {agent}</p><p>Item: {item}</p>\
                     <p>Action: {act}</p><p>Origin: {origin}</p>\
                     <form method=\"post\" action=\"{path}\">\
                     <button type=\"submit\">{verb}</button></form>",
                    agent = html_escape(&prompt.agent_id),
                    item = html_escape(&prompt.item_id),
                    act = prompt.action.as_str(),
                    origin = html_escape(&prompt.origin),
                    path = html_escape(path),
                );
                html_response(StatusCode::OK, body)
            }
            _ => token_gone(),
        };
    }
    if method == Method::POST {
        let decided = (|| {
            let (_, action) = redeem.prompt(token)?;
            if action != expected {
                return Err(TokenGone::Unknown);
            }
            redeem.redeem(token)
        })();
        return match decided {
            Ok(action) => {
                let done = match action {
                    ApprovalAction::Approve => "approved",
                    ApprovalAction::Deny => "denied",
                };
                html_response(
                    StatusCode::OK,
                    format!("<!doctype html><title>kharon</title><p>Request {done}.</p>"),
                )
            }
            Err(_) => token_gone(),
        };
    }
    let mut resp = error(ApiError::new(
        ErrorCode::MethodNotAllowed,
        Detail::MethodNotAllowed,
    ));
    resp.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET, POST"));
    resp
}

/// `POST /v1/grants` (#20): same order as the fill routes — method,
/// browser `Origin`, bearer token, content type and size,
/// [`parse_grant`], then [`Broker::request_grant`] under the fill
/// deadline from when the handler was entered.
async fn handle_grants<S, C>(
    state: Arc<AppState<S, C>>,
    req: Request,
    received: Instant,
) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    if req.method() != Method::POST {
        return method_not_allowed("POST");
    }
    if req.headers().contains_key(header::ORIGIN) {
        return error(ApiError::new(
            ErrorCode::Forbidden,
            Detail::BrowserOriginRefused,
        ));
    }
    let token = bearer_token(&req);
    let (parts, body) = req.into_parts();
    let agent = match authenticate(&state, token).await {
        Ok(a) => a,
        Err(e) => return error(e),
    };
    if !is_json(&parts.headers) {
        return error(ApiError::bad_request(Detail::UnsupportedContentType));
    }
    drop(parts);
    let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return error(ApiError::BODY_TOO_LARGE);
    };
    let grant_req = match parse_grant(&bytes) {
        Ok(r) => r,
        Err(e) => return error(e),
    };
    drop(bytes);
    match state
        .broker
        .request_grant(&agent, grant_req, received)
        .await
    {
        Ok(o) => json_response(StatusCode::OK, o.body().to_string()),
        Err(e) => error(e),
    }
}

/// 405 with `Allow: <allow>`.
pub(super) fn method_not_allowed(allow: &'static str) -> Response {
    let mut resp = error(ApiError::new(
        ErrorCode::MethodNotAllowed,
        Detail::MethodNotAllowed,
    ));
    resp.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    resp
}

fn parse_query(op: Operation, raw: &str) -> Result<ApiRequest, ApiError> {
    // Decode strictly: `form_urlencoded` replaces invalid UTF-8 with
    // U+FFFD, which would silently change a search, so refuse it.
    let mut pairs = Vec::new();
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        if k.contains('\u{fffd}') || v.contains('\u{fffd}') {
            return Err(ApiError::bad_request(Detail::InvalidQueryEncoding));
        }
        pairs.push((k, v));
    }
    parse_request(op, pairs.iter().map(|(k, v)| (k.as_ref(), v.as_ref())))
}

/// The bearer token, if exactly one well-formed `Authorization:
/// Bearer` header is present.
pub(super) fn bearer_token(req: &Request) -> Option<Zeroizing<String>> {
    let mut values = req.headers().get_all(header::AUTHORIZATION).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => bearer(value),
        _ => None,
    }
}

pub(super) async fn authenticate<S, C>(
    state: &Arc<AppState<S, C>>,
    token: Option<Zeroizing<String>>,
) -> Result<AgentId, ApiError>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    let token = token.ok_or(ApiError::MISSING_TOKEN)?;
    let _permit = state
        .auth_permits
        .acquire()
        .await
        .expect("invariant: the semaphore is never closed");
    let broker = Arc::clone(&state.broker);
    tokio::task::spawn_blocking(move || broker.authenticate(&token))
        .await
        .unwrap_or(Err(ApiError::INVALID_TOKEN))
}

/// The credentials of `Bearer <token>` (scheme case-insensitive,
/// RFC 9110 §11.1), copied into a zeroizing buffer.
fn bearer(value: &HeaderValue) -> Option<Zeroizing<String>> {
    let v = value.to_str().ok()?;
    let (scheme, cred) = v.split_once(' ')?;
    let cred = cred.trim_matches(' ');
    (scheme.eq_ignore_ascii_case("bearer") && !cred.is_empty())
        .then(|| Zeroizing::new(cred.to_owned()))
}

pub(super) fn json_response(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .expect("invariant: static headers are valid")
}

pub(super) fn error(e: ApiError) -> Response {
    let status = StatusCode::from_u16(e.code.http_status())
        .expect("invariant: ErrorCode maps to valid statuses");
    let mut resp = json_response(status, e.body().to_string());
    let headers = resp.headers_mut();
    match e.code {
        ErrorCode::Unauthorized => {
            headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"kharon\""),
            );
        }
        ErrorCode::MethodNotAllowed => {
            headers.insert(header::ALLOW, HeaderValue::from_static("GET"));
        }
        _ => {}
    }
    resp
}
