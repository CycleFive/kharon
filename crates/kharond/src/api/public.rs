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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::extract::connect_info::Connected;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, Method};
use axum::response::Response;
use axum::serve::IncomingStream;
use tokio::net::TcpListener;

use super::core::{Broker, VaultView};
use super::error::{ApiError, Detail, ErrorCode};
use super::http::{AppState, TlsListener, error};
use super::mcp::MCP_PATH;
use super::transport::ClientIp;
use crate::connector::WsEntry;
use crate::lock::Clock;

/// `GET /connector`: the agent-connector WebSocket upgrade (#199).
pub const CONNECTOR_PATH: &str = "/connector";

/// The header Cloudflare sets for the client address of a request it
/// proxied (`CF-Connecting-IP`).
pub const CF_CONNECTING_IP: &str = "cf-connecting-ip";

/// The client address of a request, taken from
/// [`CF_CONNECTING_IP`] — the trusted-proxy helper (#200; the
/// contract below is the one recorded on #206, and #208 reuses this
/// helper for the owner UI).
///
/// **The trust root is placement.** The header is honoured *only*
/// on a public-ingress request ([`PublicIngress`]): that listener's
/// loopback is one only cloudflared shares by placement (a shared
/// network-namespace holder in compose; host networking on VM 125).
/// On any other listener the header is ignored — there the peer
/// identity comes from the connection itself, and a client must not
/// be able to name its own address. On a host-networked deploy every
/// local process shares that loopback and could set the header; that
/// residual is accepted for single-purpose hosts, and it is
/// acceptable only because of the next paragraph.
///
/// **What the result may decide: nothing next to auth.** An address
/// taken from this helper may key throttling and may appear in
/// audit. It must never gate authentication or any decision beside
/// it: no allow-list, no exemption from a token or the passkey, no
/// choice of mode.
///
/// Returns `None` when the request is not public-ingress, the
/// header is absent, appears more than once, or does not parse as
/// one IP address (v4 or v6).
pub fn client_ip(headers: &HeaderMap, public_ingress: bool) -> Option<IpAddr> {
    if !public_ingress {
        return None;
    }
    let mut values = headers.get_all(CF_CONNECTING_IP).iter();
    let value = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok()?,
        _ => return None,
    };
    value.trim().parse().ok()
}

/// True when the request carries exactly one `Host` header equal, ASCII
/// case-insensitively, to `host` or `host:port`. `host` is lower-case.
///
/// Both HTTP/1.1-only listeners (the owner UI and `[public_ingress]`)
/// use this in public mode (#208): a request the edge did not route
/// for the published name is refused before anything else looks at it.
pub fn host_matches(headers: &HeaderMap, host: &str, port: u16) -> bool {
    let mut values = headers.get_all(axum::http::header::HOST).iter();
    let value = match (values.next(), values.next()) {
        (Some(v), None) => match v.to_str() {
            Ok(v) => v,
            Err(_) => return false,
        },
        _ => return false,
    };
    let value = value.to_ascii_lowercase();
    match value.strip_prefix(host) {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix(':')
            .is_some_and(|p| p == port.to_string()),
        None => false,
    }
}

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
/// without it the route answers 404. With `public_host` set, a request
/// whose `Host` is not that host (bare or `:443`) gets the same 404.
pub fn router<S, C>(
    broker: Arc<Broker<S, C>>,
    ws: Option<Arc<WsEntry>>,
    public_host: Option<Arc<str>>,
) -> Router
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    Router::new()
        .fallback(
            move |state: State<Arc<AppState<S, C>>>,
                  ConnectInfo(Peer(peer)): ConnectInfo<Peer>,
                  req: Request| {
                handle(state, ws.clone(), public_host.clone(), peer, req)
            },
        )
        .with_state(AppState::new(broker))
}

/// Serve the public-ingress surface on `listener` (plain HTTP: only
/// for a loopback listener, where the edge runs on the same host).
pub async fn serve_with_shutdown<S, C, F>(
    listener: TcpListener,
    broker: Arc<Broker<S, C>>,
    ws: Option<Arc<WsEntry>>,
    public_host: Option<Arc<str>>,
    shutdown: F,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        router(broker, ws, public_host).into_make_service_with_connect_info::<Peer>(),
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
    public_host: Option<Arc<str>>,
    shutdown: F,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        TlsListener::new(listener, tls),
        router(broker, ws, public_host).into_make_service_with_connect_info::<Peer>(),
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
    public_host: Option<Arc<str>>,
    peer: SocketAddr,
    mut req: Request,
) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    // Before routing, auth, audit or the body: a foreign Host is an
    // unknown route.
    if let Some(host) = &public_host
        && !host_matches(req.headers(), host, 443)
    {
        return not_found();
    }
    match admit(req.method(), req.uri().path()) {
        Some(Admit::Mcp) => {
            req.extensions_mut().insert(PublicIngress);
            // This listener is the trusted-proxy trust root (#200):
            // only here may CF-Connecting-IP name the client. No
            // usable header value: the edge peer is the key.
            let ip = client_ip(req.headers(), true).unwrap_or_else(|| peer.ip());
            req.extensions_mut().insert(ClientIp(ip));
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
    fn host_matches_one_exact_host() {
        let with = |values: &[&str]| {
            let mut h = HeaderMap::new();
            for v in values {
                h.append(axum::http::header::HOST, v.parse().unwrap());
            }
            h
        };
        let m = |h: &HeaderMap| host_matches(h, "kharon.example.com", 443);
        assert!(!m(&HeaderMap::new()), "no header");
        assert!(!m(&with(&["kharon.example.com", "kharon.example.com"])));
        assert!(m(&with(&["kharon.example.com"])));
        assert!(m(&with(&["KHARON.example.com"])));
        assert!(m(&with(&["kharon.example.com:443"])));
        assert!(!m(&with(&["kharon.example.com:8790"])));
        assert!(!m(&with(&["kharon.example.com."])));
        assert!(!m(&with(&["evil.example.com"])));
    }

    #[test]
    fn client_ip_is_honoured_only_on_public_ingress() {
        let mut h = HeaderMap::new();
        h.insert(CF_CONNECTING_IP, "203.0.113.7".parse().unwrap());
        assert_eq!(
            client_ip(&h, false),
            None,
            "spoofed on the private listener"
        );
        assert_eq!(
            client_ip(&h, true),
            Some("203.0.113.7".parse::<IpAddr>().unwrap())
        );
        let mut h = HeaderMap::new();
        h.insert(CF_CONNECTING_IP, "2001:db8::1".parse().unwrap());
        assert_eq!(
            client_ip(&h, true),
            Some("2001:db8::1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(client_ip(&HeaderMap::new(), true), None);
        let mut h = HeaderMap::new();
        h.insert(CF_CONNECTING_IP, "not-an-ip".parse().unwrap());
        assert_eq!(client_ip(&h, true), None);
        let mut h = HeaderMap::new();
        h.append(CF_CONNECTING_IP, "203.0.113.7".parse().unwrap());
        h.append(CF_CONNECTING_IP, "203.0.113.8".parse().unwrap());
        assert_eq!(client_ip(&h, true), None, "two values is not one address");
    }

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
