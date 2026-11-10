//! Public-ingress listener (#198; decision record on #197).
//!
//! The origin a public edge (a Cloudflare Tunnel for `kharon.twkr.io`)
//! forwards to. It is a separate listener from `[api]`, with a fixed
//! allow-list, so the daemon itself refuses everything the public may
//! not reach, whatever the edge's ingress rules say:
//!
//! | Request | Answer |
//! |---|---|
//! | `POST /mcp` | the MCP transport ([`super::mcp`]), exactly as on `[api]`: same bearer auth, rate limits, audit |
//! | `GET /connector` | the agent-connector WebSocket upgrade (#199) when `[connector] websocket = true`; 404 otherwise |
//! | anything else | 404 `not_found` / `no_such_route` |
//!
//! "Anything else" includes `/v1/*` and `/v1/openapi.json` (the tailnet
//! API), `/owner/*` (the owner UI and ntfy redeem routes live on the
//! loopback owner listener), `/`, `/healthz`, and other methods on
//! `/mcp`: a public client has no business reaching any of them, and a
//! 404 says nothing about which exist on another listener.
//!
//! Requests admitted here carry a [`PublicIngress`] extension, so the
//! MCP handler can tell a public request from a tailnet one (#200 keys
//! its trusted-proxy and client-IP handling on it). The extension is the
//! only such signal: the TCP peer here is always the edge, so it says
//! nothing about the client. The listener has its
//! own token-verification semaphore ([`AppState::new`]): a flood of bad
//! tokens from the internet cannot starve tailnet agents of Argon2id
//! permits.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::Method;
use axum::response::Response;
use axum::serve::IncomingStream;
use tokio::net::TcpListener;

use super::core::{Broker, VaultView};
use super::error::{ApiError, Detail, ErrorCode};
use super::http::{AppState, TlsListener, error};
use super::mcp::MCP_PATH;
use crate::connector::WsEntry;
use crate::lock::Clock;

/// `GET /connector`: the agent-connector WebSocket upgrade (#199).
pub const CONNECTOR_PATH: &str = "/connector";

/// Request extension: this request arrived on the public-ingress
/// listener (#198), not the tailnet `[api]` listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicIngress;

/// The TCP peer of a public-ingress connection: the edge, not the client.
#[derive(Debug, Clone, Copy)]
struct Peer(SocketAddr);

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

/// The public-ingress router over `broker`. `ws` mounts `GET /connector`;
/// without it the route answers 404.
pub fn router<S, C>(broker: Arc<Broker<S, C>>, ws: Option<Arc<WsEntry>>) -> Router
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    Router::new()
        .fallback(
            move |state: State<Arc<AppState<S, C>>>,
                  ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
                  req: Request| { handle(state, ws.clone(), peer, req) },
        )
        .with_state(AppState::new(broker))
}

/// Serve the public-ingress surface on `listener` (plain HTTP: only
/// for a loopback listener, where the edge runs on the same host).
pub async fn serve_with_shutdown<S, C, F>(
    listener: TcpListener,
    broker: Arc<Broker<S, C>>,
    ws: Option<Arc<WsEntry>>,
    shutdown: F,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        router(broker, ws).into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Serve the public-ingress surface over TLS. The edge pins this
/// certificate (`originRequest.caPool`), so the hop from the edge to
/// kharond is authenticated without trusting the network in between.
pub async fn serve_tls_with_shutdown<S, C, F>(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    broker: Arc<Broker<S, C>>,
    ws: Option<Arc<WsEntry>>,
    shutdown: F,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        TlsListener::new(listener, tls),
        router(broker, ws).into_make_service_with_connect_info::<Peer>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

/// Which allow-listed route a request is, if any.
#[derive(Debug, PartialEq, Eq)]
enum Admit {
    Mcp,
    /// `GET /connector`: the connector WebSocket (#199).
    Connector,
}

fn admit(method: &Method, path: &str) -> Option<Admit> {
    match (method, path) {
        (&Method::POST, MCP_PATH) => Some(Admit::Mcp),
        (&Method::GET, CONNECTOR_PATH) => Some(Admit::Connector),
        _ => None,
    }
}

async fn handle<S, C>(
    State(state): State<Arc<AppState<S, C>>>,
    ws: Option<Arc<WsEntry>>,
    peer: SocketAddr,
    mut req: Request,
) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    match admit(req.method(), req.uri().path()) {
        Some(Admit::Mcp) => {
            req.extensions_mut().insert(PublicIngress);
            super::mcp::handle(state, req).await
        }
        // Without `[connector] websocket = true` the route is
        // indistinguishable from an unknown one.
        Some(Admit::Connector) => match ws {
            Some(ws) => ws.upgrade(req, peer),
            None => not_found(),
        },
        None => not_found(),
    }
}

fn not_found() -> Response {
    error(ApiError::new(ErrorCode::NotFound, Detail::NoSuchRoute))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_post_mcp_and_get_connector_are_admitted() {
        assert_eq!(admit(&Method::POST, "/mcp"), Some(Admit::Mcp));
        assert_eq!(admit(&Method::GET, "/connector"), Some(Admit::Connector));
        for (method, path) in [
            (Method::GET, "/mcp"),
            (Method::DELETE, "/mcp"),
            (Method::OPTIONS, "/mcp"),
            (Method::POST, "/mcp/"),
            (Method::POST, "/MCP"),
            (Method::POST, "//mcp"),
            (Method::POST, "/connector"),
            (Method::GET, "/connector/"),
            (Method::GET, "/"),
            (Method::GET, "/ui"),
            (Method::GET, "/healthz"),
            (Method::GET, "/v1/status"),
            (Method::GET, "/v1/items"),
            (Method::GET, "/v1/openapi.json"),
            (Method::POST, "/v1/fill"),
            (Method::POST, "/v1/grants"),
            (Method::GET, "/owner/session"),
            (Method::GET, "/owner/approve/x"),
        ] {
            assert_eq!(admit(&method, path), None, "{method} {path}");
        }
    }
}
