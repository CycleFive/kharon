//! One agent dial: TCP (or HTTP CONNECT), optional outer TLS and WebSocket
//! upgrade, pinned inner TLS, auth, then relay.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use zeroize::Zeroizing;

use crate::auth::{read_server_hello, write_client_hello};
use crate::mux::serve_agent;
use crate::proxy::http_connect;
use crate::tls::{TlsVersions, connect_pinned_stream, is_pin_mismatch};
use crate::ws::{WsByteStream, ws_config};
use crate::{
    AUTH_OK, AUTH_PROTOCOL, AUTH_UNAUTHORIZED, ClientError, OuterTlsClass, WS_SUBPROTOCOL,
};

/// How the agent reaches the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Raw pinned TLS to a broker address (the `:8789` listener). `host` is
    /// the configured broker host name: an HTTP CONNECT proxy is asked for
    /// it (never for the inner `server_name`, which may differ). `None`
    /// names the `broker` address itself.
    Tls {
        broker: SocketAddr,
        host: Option<String>,
    },
    /// The same inner stack inside a WebSocket at `path` on `host:port`.
    Ws {
        host: String,
        port: u16,
        path: String,
        /// Outer TLS (`wss://`). It is `true` in every production config
        /// and the binary always sets it. `false` is for in-process tests
        /// that dial kharond's plain-loopback `[public_ingress]` directly.
        outer_tls: bool,
    },
}

/// A leg of the dial, in order. [`check_once`] reports one result per leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    Dns,
    Tcp,
    Proxy,
    OuterTls,
    Upgrade,
    InnerTls,
    Auth,
}

/// What one agent connection needs. `token` is zeroized on drop.
///
/// `server_name` is the inner TLS name (a DNS name or an IP literal).
/// `transport` says where to dial. `proxy`, when set, is an HTTP CONNECT
/// proxy with no userinfo. `proxy_creds`, when set with `proxy`, is the raw
/// `user:password` line sent only as `Proxy-Authorization` on that
/// CONNECT. It is not sent to the broker. `outer_roots` are the roots for
/// the outer TLS of a `ws` transport; `None` means the system roots. It is
/// meant for tests and ops only.
#[derive(Clone)]
pub struct AgentParams {
    pub transport: Transport,
    pub server_name: String,
    pub pin: crate::CertSha256,
    pub agent_id: String,
    pub token: Zeroizing<String>,
    pub cdp: SocketAddr,
    pub proxy: Option<SocketAddr>,
    pub proxy_creds: Option<Zeroizing<Vec<u8>>>,
    pub outer_roots: Option<Arc<rustls::RootCertStore>>,
}

trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

type DynStream = Box<dyn AsyncStream>;

/// An authenticated inner stream, ready for [`serve_agent`].
pub struct AuthedSession {
    stream: DynStream,
    cdp: SocketAddr,
}

impl AuthedSession {
    /// Relay until the session ends.
    pub async fn serve(self) -> Result<(), ClientError> {
        serve_agent(self.stream, self.cdp).await
    }
}

type Legs = Vec<(Leg, Result<(), ClientError>)>;

const LEG_TIMEOUT: Duration = Duration::from_secs(10);

/// Dial the broker once and relay until the session ends.
///
/// [`Ok`] means the session was authenticated and then ended (the caller
/// reconnects). [`ClientError::Unauthorized`] and [`ClientError::BadCert`]
/// mean the broker refused the credential or the pin did not match; no
/// CDP dial is made in either case.
pub async fn run_agent_once(params: &AgentParams) -> Result<(), ClientError> {
    connect_and_auth(params).await?.serve().await
}

/// Dial and authenticate, without relaying.
pub async fn connect_and_auth(params: &AgentParams) -> Result<AuthedSession, ClientError> {
    dial(params, &mut Vec::new()).await
}

/// Walk the legs up to `AUTH_OK`, then close without opening CDP. The
/// list ends at the first failing leg.
pub async fn check_once(params: &AgentParams) -> Vec<(Leg, Result<(), ClientError>)> {
    let mut legs = Vec::new();
    let _ = dial(params, &mut legs).await;
    legs
}

fn note(legs: &mut Legs, leg: Leg, r: Result<(), ClientError>) {
    legs.push((leg, r));
}

async fn dial(params: &AgentParams, legs: &mut Legs) -> Result<AuthedSession, ClientError> {
    if !params.cdp.ip().is_loopback() || params.cdp.port() == 0 {
        return Err(ClientError::CdpNotLoopback);
    }
    match &params.transport {
        Transport::Tls { broker, host } => {
            let tcp = tcp_leg(params, legs, Target::Addr(*broker, host.as_deref())).await?;
            finish(params, tcp, TlsVersions::Default, legs).await
        }
        Transport::Ws {
            host,
            port,
            path,
            outer_tls,
        } => {
            let tcp = tcp_leg(params, legs, Target::Host(host, *port)).await?;
            if *outer_tls {
                let outer = outer_tls_leg(params, host, tcp, legs).await?;
                let ws = upgrade_leg(host, *port, path, true, outer, legs).await?;
                finish(params, ws, TlsVersions::Tls13Only, legs).await
            } else {
                let ws = upgrade_leg(host, *port, path, false, tcp, legs).await?;
                finish(params, ws, TlsVersions::Tls13Only, legs).await
            }
        }
    }
}

enum Target<'a> {
    /// A resolved address and the configured broker host name, if any.
    Addr(SocketAddr, Option<&'a str>),
    Host(&'a str, u16),
}

/// Resolve (when dialing directly), then TCP or an HTTP CONNECT.
///
/// Through a proxy the broker host is the proxy's to resolve, so there is
/// no local DNS leg: that is the case where local DNS often cannot work.
async fn tcp_leg(
    params: &AgentParams,
    legs: &mut Legs,
    target: Target<'_>,
) -> Result<TcpStream, ClientError> {
    if let Some(proxy) = params.proxy {
        let (name, port) = match target {
            Target::Addr(a, Some(host)) => (connect_name(host), a.port()),
            Target::Addr(a, None) => (connect_host(a), a.port()),
            Target::Host(h, p) => (connect_name(h), p),
        };
        return proxy_leg(params, legs, proxy, &name, port).await;
    }
    let addrs: Vec<SocketAddr> = match target {
        Target::Addr(a, _) => vec![a],
        Target::Host(host, port) => {
            let found =
                tokio::time::timeout(LEG_TIMEOUT, tokio::net::lookup_host((host, port))).await;
            match found {
                Ok(Ok(it)) => {
                    let v: Vec<SocketAddr> = it.collect();
                    if v.is_empty() {
                        note(legs, Leg::Dns, Err(ClientError::Dns));
                        return Err(ClientError::Dns);
                    }
                    note(legs, Leg::Dns, Ok(()));
                    v
                }
                _ => {
                    note(legs, Leg::Dns, Err(ClientError::Dns));
                    return Err(ClientError::Dns);
                }
            }
        }
    };
    let mut last = std::io::ErrorKind::Other;
    for addr in addrs {
        match tokio::time::timeout(LEG_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                note(legs, Leg::Tcp, Ok(()));
                return Ok(s);
            }
            Ok(Err(e)) => last = e.kind(),
            Err(_) => last = std::io::ErrorKind::TimedOut,
        }
    }
    let e = ClientError::Tcp { kind: last };
    note(legs, Leg::Tcp, Err(e));
    Err(e)
}

/// The CONNECT host for a configured host name: an IPv6 literal (the config
/// parser strips its brackets) is bracketed again; anything else is as is.
fn connect_name(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// The CONNECT host for a bare address: an IPv6 literal is bracketed.
fn connect_host(addr: SocketAddr) -> String {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

/// TCP to the proxy (the `tcp` leg), then the CONNECT exchange (the
/// `proxy` leg), each with its own timeout.
async fn proxy_leg(
    params: &AgentParams,
    legs: &mut Legs,
    proxy: SocketAddr,
    name: &str,
    port: u16,
) -> Result<TcpStream, ClientError> {
    let mut stream = match tokio::time::timeout(LEG_TIMEOUT, TcpStream::connect(proxy)).await {
        Ok(Ok(s)) => s,
        other => {
            let kind = match other {
                Ok(Err(e)) => e.kind(),
                _ => std::io::ErrorKind::TimedOut,
            };
            let e = ClientError::Tcp { kind };
            note(legs, Leg::Tcp, Err(e));
            return Err(e);
        }
    };
    let _ = stream.set_nodelay(true);
    note(legs, Leg::Tcp, Ok(()));
    let exchange = http_connect(
        &mut stream,
        name,
        port,
        params.proxy_creds.as_deref().map(Vec::as_slice),
    );
    let result = tokio::time::timeout(LEG_TIMEOUT, exchange)
        .await
        .unwrap_or(Err(ClientError::ProxyStatus { code: 0 }));
    note(legs, Leg::Proxy, result);
    result?;
    Ok(stream)
}

fn outer_config(roots: Option<&Arc<rustls::RootCertStore>>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let store = match roots {
        Some(r) => Arc::clone(r),
        None => {
            let mut store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = store.add(cert);
            }
            Arc::new(store)
        }
    };
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .expect("aws-lc-rs supports the default versions")
        .with_root_certificates(store)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}

async fn outer_tls_leg(
    params: &AgentParams,
    host: &str,
    tcp: TcpStream,
    legs: &mut Legs,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ClientError> {
    let fail = |legs: &mut Legs, class: OuterTlsClass| {
        let e = ClientError::OuterTls(class);
        note(legs, Leg::OuterTls, Err(e));
        e
    };
    let Ok(name) = rustls::pki_types::ServerName::try_from(host.to_owned()) else {
        return Err(fail(legs, OuterTlsClass::HandshakeFailed));
    };
    let connector =
        tokio_rustls::TlsConnector::from(Arc::new(outer_config(params.outer_roots.as_ref())));
    match tokio::time::timeout(LEG_TIMEOUT, connector.connect(name, tcp)).await {
        Ok(Ok(tls)) => {
            note(legs, Leg::OuterTls, Ok(()));
            Ok(tls)
        }
        Ok(Err(e)) => Err(fail(legs, OuterTlsClass::of_io(&e))),
        Err(_) => Err(fail(legs, OuterTlsClass::HandshakeFailed)),
    }
}

async fn upgrade_leg<S>(
    host: &str,
    port: u16,
    path: &str,
    secure: bool,
    stream: S,
    legs: &mut Legs,
) -> Result<WsByteStream<S>, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let result = upgrade(host, port, path, secure, stream).await;
    note(
        legs,
        Leg::Upgrade,
        result.as_ref().map(|_| ()).map_err(|e| *e),
    );
    result
}

async fn upgrade<S>(
    host: &str,
    port: u16,
    path: &str,
    secure: bool,
    stream: S,
) -> Result<WsByteStream<S>, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let none = ClientError::Upgrade { status: 0 };
    let scheme = if secure { "wss" } else { "ws" };
    let host_part = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let mut request = format!("{scheme}://{host_part}:{port}{path}")
        .into_client_request()
        .map_err(|_| none)?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_SUBPROTOCOL),
    );
    let handshake = tokio_tungstenite::client_async_with_config(request, stream, Some(ws_config()));
    let (ws, response) = match tokio::time::timeout(LEG_TIMEOUT, handshake).await {
        Ok(Ok(ok)) => ok,
        Ok(Err(WsError::Http(resp))) => {
            return Err(ClientError::Upgrade {
                status: resp.status().as_u16(),
            });
        }
        Ok(Err(WsError::Protocol(ProtocolError::SecWebSocketSubProtocolError(_)))) => {
            return Err(ClientError::Upgrade { status: 101 });
        }
        _ => return Err(none),
    };
    let echoed = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok());
    if echoed != Some(WS_SUBPROTOCOL) {
        return Err(ClientError::Upgrade { status: 101 });
    }
    Ok(WsByteStream::new(ws))
}

/// Inner pinned TLS, then the auth record.
async fn finish<S>(
    params: &AgentParams,
    stream: S,
    versions: TlsVersions,
    legs: &mut Legs,
) -> Result<AuthedSession, ClientError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let hs = tokio::time::timeout(
        LEG_TIMEOUT,
        connect_pinned_stream(&params.server_name, params.pin, stream, versions),
    )
    .await;
    let mut tls = match hs {
        Ok(Ok(tls)) => {
            note(legs, Leg::InnerTls, Ok(()));
            tls
        }
        Ok(Err(e)) if is_pin_mismatch(&e) => {
            note(legs, Leg::InnerTls, Err(ClientError::BadCert));
            return Err(ClientError::BadCert);
        }
        _ => {
            note(legs, Leg::InnerTls, Err(ClientError::InnerTls));
            return Err(ClientError::InnerTls);
        }
    };
    let result = auth(params, &mut tls).await;
    note(legs, Leg::Auth, result);
    result?;
    Ok(AuthedSession {
        stream: Box::new(tls),
        cdp: params.cdp,
    })
}

async fn auth<S>(params: &AgentParams, tls: &mut S) -> Result<(), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let exchange = async {
        write_client_hello(tls, &params.agent_id, params.token.as_str())
            .await
            .map_err(|_| ClientError::Protocol)?;
        match read_server_hello(tls).await {
            Ok(status) => Ok(status),
            Err(_) => Err(ClientError::Protocol),
        }
    };
    let status = match tokio::time::timeout(LEG_TIMEOUT, exchange).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(ClientError::Protocol),
    };
    match status {
        AUTH_OK => Ok(()),
        AUTH_UNAUTHORIZED => Err(ClientError::Unauthorized),
        AUTH_PROTOCOL => Err(ClientError::Protocol),
        _ => Err(ClientError::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_name_brackets_an_ipv6_literal_only() {
        assert_eq!(connect_name("::1"), "[::1]");
        assert_eq!(connect_name("[::1]"), "[::1]");
        assert_eq!(connect_name("2001:db8::7"), "[2001:db8::7]");
        assert_eq!(connect_name("192.0.2.7"), "192.0.2.7");
        assert_eq!(connect_name("broker.example.net"), "broker.example.net");
    }

    #[tokio::test]
    async fn direct_tcp_leg_sets_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let broker = listener.local_addr().unwrap();
        let params = AgentParams {
            transport: Transport::Tls { broker, host: None },
            server_name: "127.0.0.1".into(),
            pin: [0; 32],
            agent_id: "a".into(),
            token: Zeroizing::new(String::new()),
            cdp: "127.0.0.1:9".parse().unwrap(),
            proxy: None,
            proxy_creds: None,
            outer_roots: None,
        };
        let tcp = tcp_leg(&params, &mut Vec::new(), Target::Addr(broker, None))
            .await
            .unwrap();
        assert!(tcp.nodelay().unwrap());
    }
}
