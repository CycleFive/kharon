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
//! | `GET /v1/openapi.json` | none | the OpenAPI document |
//! | `POST /mcp` | bearer | MCP over Streamable HTTP ([`super::mcp`]) |
//!
//! Order: route (404), method (405), bearer token (401), parameters
//! (400), then [`Broker::dispatch`]. Token verification is one
//! Argon2id evaluation (~19 MiB, tens of ms); it runs on the blocking
//! pool behind a semaphore so concurrent bad tokens cannot exhaust
//! memory or starve the runtime.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use super::core::{AgentId, Broker, Operation, Request as ApiRequest, VaultView, parse_request};
use super::error::{ApiError, Detail, ErrorCode};
use crate::lock::Clock;

/// The OpenAPI 3.1 document for this transport.
pub const OPENAPI_JSON: &str = include_str!("../../../../docs/api/openapi.json");

/// Concurrent token verifications.
const MAX_CONCURRENT_AUTH: usize = 4;

pub(super) struct AppState<S: VaultView, C: Clock> {
    pub(super) broker: Arc<Broker<S, C>>,
    auth_permits: Semaphore,
}

/// The `/v1` router over `broker`.
pub fn router<S, C>(broker: Arc<Broker<S, C>>) -> Router
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    let state = Arc::new(AppState {
        broker,
        auth_permits: Semaphore::new(MAX_CONCURRENT_AUTH),
    });
    Router::new().fallback(handle::<S, C>).with_state(state)
}

/// Serve the API on `listener` until the future is dropped.
pub async fn serve<S, C>(listener: TcpListener, broker: Arc<Broker<S, C>>) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    axum::serve(listener, router(broker)).await
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
    axum::serve(listener, router(broker))
        .with_graceful_shutdown(shutdown)
        .await
}

enum Route {
    Status,
    Items,
    OpenApi,
}

async fn handle<S, C>(State(state): State<Arc<AppState<S, C>>>, req: Request) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    let route = match req.uri().path() {
        "/v1/status" => Route::Status,
        "/v1/items" => Route::Items,
        "/v1/openapi.json" => Route::OpenApi,
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
