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
//! | `GET /.well-known/oauth-protected-resource[/mcp]` | RFC 9728 protected-resource metadata (REQ-OAU-001) when `[oauth]` is set; 404 otherwise |
//! | `GET /.well-known/oauth-protected-resource/connector` | RFC 9728 connector metadata with the inner pin (#235 D1, REQ-OAU-009) when `[oauth]` and a connector certificate are both set; 404 otherwise |
//! | anything else | 404 `not_found` / `no_such_route` |
//!
//! "Anything else" includes `/v1/*` and `/v1/openapi.json` (the tailnet
//! API), `/owner/*` (the owner UI and ntfy redeem routes live on the
//! loopback owner listener), `/`, `/healthz`, and other methods on
//! `/mcp`: a public client has no business reaching any of them, and a
//! 404 says nothing about which exist on another listener.
//!
//! Requests admitted here carry a [`PublicIngress`] extension, so the
//! MCP handler can tell a public request from a tailnet one. The client
//! address is [`effective_client_ip`]: `CF-Connecting-IP` only when the
//! TCP peer is loopback or listed in `trusted_proxies`, and the peer
//! itself otherwise (#200, #239). That address keys throttling and
//! stamps audit `client_ip`; it never gates auth. The listener has its
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
use super::http::{AppState, TlsListener, error, json_response};
use super::mcp::MCP_PATH;
use super::oauth::{
    PROTECTED_RESOURCE_CONNECTOR_PATH, PROTECTED_RESOURCE_MCP_PATH, PROTECTED_RESOURCE_PATH,
};
use super::transport::ClientIp;
use crate::connector::WsEntry;
use crate::lock::Clock;

/// `GET /connector`: the agent-connector WebSocket upgrade (#199).
pub const CONNECTOR_PATH: &str = "/connector";

/// The header Cloudflare sets for the client address of a request it
/// proxied (`CF-Connecting-IP`).
pub const CF_CONNECTING_IP: &str = "cf-connecting-ip";

/// Canonical form of an address for proxy comparison. An IPv4-mapped
/// IPv6 address is its IPv4 address; everything else is unchanged.
pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
    }
}

/// Whether `peer` may name the client via [`CF_CONNECTING_IP`].
///
/// Loopback — `127.0.0.0/8`, `::1`, and those addresses in IPv4-mapped
/// form — is trusted by placement: the edge shares it (B6). Any other
/// peer is trusted only when its canonical address is in
/// `trusted_proxies`.
pub fn peer_trusts_connecting_ip(peer: IpAddr, trusted_proxies: &[IpAddr]) -> bool {
    let peer = canonical_ip(peer);
    peer.is_loopback()
        || trusted_proxies
            .iter()
            .copied()
            .any(|p| canonical_ip(p) == peer)
}

/// Parse one [`CF_CONNECTING_IP`] value. `None` when the header is
/// absent, appears more than once, or is not a single IP address.
fn connecting_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let mut values = headers.get_all(CF_CONNECTING_IP).iter();
    let value = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok()?,
        _ => return None,
    };
    value.trim().parse().ok()
}

/// The client address taken from [`CF_CONNECTING_IP`], when it may
/// be honoured (#200; the contract below is the one recorded on
/// #206, and #208 reuses this helper for the owner UI).
///
/// **When the header is read.** `honour` is true on `[public_ingress]`
/// and on the owner UI in public mode. Even then the header is
/// honoured only when [`peer_trusts_connecting_ip`]: the peer is
/// loopback, or it is listed in `trusted_proxies`. A non-loopback
/// peer that is not listed does not get to choose an address. The
/// `[api]` listener does not call this helper; its peer is the
/// client by construction.
///
/// **The trust root is placement, plus that list.** A loopback
/// listener is one only the edge shares by placement (a shared
/// network-namespace holder in compose; host networking on a
/// single-purpose host). `trusted_proxies` is the same idea for a
/// non-loopback listen: the edge's address, named explicitly. On a
/// host-networked deploy every local process shares loopback and
/// could set the header; that residual is accepted for
/// single-purpose hosts, and it is acceptable only because of the
/// next paragraph.
///
/// **What the result may decide: nothing next to auth.** An address
/// taken from this helper may key throttling and may appear in
/// audit. It must never gate authentication or any decision beside
/// it: no allow-list, no exemption from a token or the passkey, no
/// choice of mode.
///
/// A `None` is not a throttle key. The owner UI audits such a
/// request with its TCP peer and does not throttle it (REQ-APR-009):
/// behind the tunnel every header-less request shares one peer, and
/// one shared bucket would let a stranger lock the owner out. A
/// non-trusted peer also gets `None`, and the caller uses that peer.
///
/// Returns `None` when the header must not be honoured, is absent,
/// appears more than once, or does not parse as one IP address
/// (v4 or v6).
pub fn client_ip(
    headers: &HeaderMap,
    honour: bool,
    peer: IpAddr,
    trusted_proxies: &[IpAddr],
) -> Option<IpAddr> {
    if !honour || !peer_trusts_connecting_ip(peer, trusted_proxies) {
        return None;
    }
    connecting_ip(headers)
}

/// The effective client address of a `[public_ingress]` request.
///
/// The honoured header when [`client_ip`] returns one, otherwise
/// `peer`. This is the throttle key and the audit `client_ip`. It
/// is never an auth input.
pub fn effective_client_ip(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted_proxies: &[IpAddr],
) -> IpAddr {
    client_ip(headers, true, peer, trusted_proxies).unwrap_or(peer)
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

/// The TCP peer of a public-ingress connection: the edge, not the client,
/// when the edge dials a trusted address.
///
/// Axum's [`ConnectInfo`] carries this. Tests inject one to exercise a
/// peer the sandbox cannot bind.
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub SocketAddr);

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
    trusted_proxies: Arc<[IpAddr]>,
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
                handle(
                    state,
                    ws.clone(),
                    public_host.clone(),
                    trusted_proxies.clone(),
                    peer,
                    req,
                )
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
    trusted_proxies: Arc<[IpAddr]>,
    shutdown: F,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        listener,
        router(broker, ws, public_host, trusted_proxies)
            .into_make_service_with_connect_info::<Peer>(),
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
    trusted_proxies: Arc<[IpAddr]>,
    shutdown: F,
) -> std::io::Result<()>
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(
        TlsListener::new(listener, tls),
        router(broker, ws, public_host, trusted_proxies)
            .into_make_service_with_connect_info::<Peer>(),
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
    /// `GET /.well-known/oauth-protected-resource[/mcp]`: RFC 9728
    /// discovery (REQ-OAU-001). Admitted by shape; the handler
    /// answers 404 when `[oauth]` is not configured, so the route's
    /// existence never leaks the config.
    ProtectedResource,
    /// `GET /.well-known/oauth-protected-resource/connector`: the
    /// connector document with the pin (#235 D1, REQ-OAU-009).
    /// Admitted by shape; the handler answers 404 unless `[oauth]`
    /// and a connector certificate are both configured. This is a
    /// GET metadata path, not the WebSocket: `GET /connector` stays
    /// the upgrade.
    ProtectedResourceConnector,
}

fn admit(method: &Method, path: &str) -> Option<Admit> {
    match (method, path) {
        (&Method::POST, MCP_PATH) => Some(Admit::Mcp),
        (&Method::GET, CONNECTOR_PATH) => Some(Admit::Connector),
        (&Method::GET, PROTECTED_RESOURCE_PATH | PROTECTED_RESOURCE_MCP_PATH) => {
            Some(Admit::ProtectedResource)
        }
        (&Method::GET, PROTECTED_RESOURCE_CONNECTOR_PATH) => {
            Some(Admit::ProtectedResourceConnector)
        }
        _ => None,
    }
}

async fn handle<S, C>(
    State(state): State<Arc<AppState<S, C>>>,
    ws: Option<Arc<WsEntry>>,
    public_host: Option<Arc<str>>,
    trusted_proxies: Arc<[IpAddr]>,
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
            // The only place a public-ingress client address is chosen
            // (#239). A loopback peer or a listed proxy may set
            // CF-Connecting-IP; every other peer is its own key. The
            // result is the throttle key and the audit client_ip, and
            // nothing else.
            let ip = effective_client_ip(req.headers(), peer.ip(), &trusted_proxies);
            req.extensions_mut().insert(ClientIp(ip));
            super::mcp::handle(state, req).await
        }
        // Without `[connector] websocket = true` the route is
        // indistinguishable from an unknown one.
        Some(Admit::Connector) => match ws {
            Some(ws) => ws.upgrade(req, peer),
            None => not_found(),
        },
        // RFC 9728 discovery (REQ-OAU-001): a pure function of the
        // config, served unauthenticated — discovery is how an
        // unauthenticated client finds out how to authenticate.
        // Without `[oauth]` the route is indistinguishable from an
        // unknown one.
        Some(Admit::ProtectedResource) => match state.broker.oauth_discovery() {
            Some(discovery) => json_response(
                axum::http::StatusCode::OK,
                discovery.protected_resource_metadata().to_string(),
            ),
            None => not_found(),
        },
        // The connector document (#235 D1): same unauthenticated
        // discovery shape, but it exists only when a connector
        // certificate pin is configured. `json_response` carries
        // `Cache-Control: no-store`, so no cache can freeze a pin
        // across a certificate rotation.
        Some(Admit::ProtectedResourceConnector) => {
            match state
                .broker
                .oauth_discovery()
                .and_then(|d| d.connector_protected_resource_metadata())
            {
                Some(doc) => json_response(axum::http::StatusCode::OK, doc.to_string()),
                None => not_found(),
            }
        }
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

    fn v4(o: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, o))
    }

    fn header(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(CF_CONNECTING_IP, value.parse().unwrap());
        h
    }

    #[test]
    fn client_ip_is_honoured_only_from_a_trusted_peer() {
        let loopback = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let edge = v4(9);
        let claimed = header("203.0.113.7");
        let listed = [edge];
        assert_eq!(
            client_ip(&claimed, false, loopback, &listed),
            None,
            "a listener that does not honour the header ignores it"
        );
        assert_eq!(
            client_ip(&claimed, true, loopback, &[]),
            Some(v4(7)),
            "loopback is trusted with an empty list"
        );
        assert_eq!(
            client_ip(
                &claimed,
                true,
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                &[]
            ),
            Some(v4(7))
        );
        assert_eq!(
            client_ip(&claimed, true, "127.1.2.3".parse().unwrap(), &[]),
            Some(v4(7)),
            "the whole 127.0.0.0/8 is loopback"
        );
        assert_eq!(
            client_ip(&claimed, true, "::ffff:127.0.0.1".parse().unwrap(), &[]),
            Some(v4(7)),
            "an IPv4-mapped loopback is loopback"
        );
        assert_eq!(
            client_ip(&claimed, true, edge, &[]),
            None,
            "a non-loopback peer is not trusted just because it connected"
        );
        assert_eq!(
            effective_client_ip(&claimed, edge, &[]),
            edge,
            "the untrusted peer is the client address"
        );
        assert_eq!(client_ip(&claimed, true, edge, &listed), Some(v4(7)));
        assert_eq!(
            client_ip(
                &claimed,
                true,
                "::ffff:203.0.113.9".parse().unwrap(),
                &listed
            ),
            Some(v4(7)),
            "the mapped form of a listed proxy is that proxy"
        );
        assert_eq!(
            client_ip(&header("2001:db8::1"), true, loopback, &[]),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(client_ip(&HeaderMap::new(), true, loopback, &[]), None);
        assert_eq!(
            effective_client_ip(&HeaderMap::new(), loopback, &[]),
            loopback,
            "no usable header: the trusted peer itself"
        );
        assert_eq!(client_ip(&header("not-an-ip"), true, loopback, &[]), None);
        let mut two = HeaderMap::new();
        two.append(CF_CONNECTING_IP, "203.0.113.7".parse().unwrap());
        two.append(CF_CONNECTING_IP, "203.0.113.8".parse().unwrap());
        assert_eq!(
            client_ip(&two, true, loopback, &[]),
            None,
            "two values is not one address"
        );
    }

    #[test]
    fn only_post_mcp_get_connector_and_get_discovery_are_admitted() {
        assert_eq!(admit(&Method::POST, "/mcp"), Some(Admit::Mcp));
        assert_eq!(admit(&Method::GET, "/connector"), Some(Admit::Connector));
        // RFC 9728 discovery (REQ-OAU-001): both shapes clients try.
        for path in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            assert_eq!(
                admit(&Method::GET, path),
                Some(Admit::ProtectedResource),
                "GET {path}"
            );
        }
        // The connector document (#235 D1) is its own route, not
        // the WebSocket upgrade and not the /mcp document.
        assert_eq!(
            admit(
                &Method::GET,
                "/.well-known/oauth-protected-resource/connector"
            ),
            Some(Admit::ProtectedResourceConnector)
        );
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
            // Discovery is GET-only, exact-path, and the AS document
            // lives on the owner hostname, not here.
            (Method::POST, "/.well-known/oauth-protected-resource"),
            (Method::POST, "/.well-known/oauth-protected-resource/mcp"),
            (
                Method::POST,
                "/.well-known/oauth-protected-resource/connector",
            ),
            (Method::GET, "/.well-known/oauth-protected-resource/"),
            (Method::GET, "/.well-known/oauth-protected-resource/mcp/"),
            (
                Method::GET,
                "/.well-known/oauth-protected-resource/connector/",
            ),
            (Method::GET, "/.well-known/oauth-authorization-server"),
            (Method::GET, "/.well-known/openid-configuration"),
        ] {
            assert_eq!(admit(&method, path), None, "{method} {path}");
        }
    }
}
