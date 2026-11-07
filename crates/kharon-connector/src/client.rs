//! One agent dial: TCP (or HTTP CONNECT), pinned TLS, auth, then relay.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::auth::{read_server_hello, write_client_hello};
use crate::mux::serve_agent;
use crate::proxy::connect_http_proxy;
use crate::tls::{connect_pinned, is_pin_mismatch};
use crate::{AUTH_OK, AUTH_PROTOCOL, AUTH_UNAUTHORIZED, ClientError};

/// What one agent connection needs. `token` is zeroized on drop.
///
/// `server_name` is the TLS name (a DNS name or an IP literal). `broker`
/// is the address actually dialed, which may be the proxy's target
/// resolved by the caller. `proxy`, when set, is an HTTP CONNECT proxy
/// address (no userinfo). `proxy_auth`, when set, is the raw
/// `user:password` bytes for Basic `Proxy-Authorization` on CONNECT.
#[derive(Clone)]
pub struct AgentParams {
    pub broker: SocketAddr,
    pub server_name: String,
    pub pin: crate::CertSha256,
    pub agent_id: String,
    pub token: Zeroizing<String>,
    pub cdp: SocketAddr,
    pub proxy: Option<SocketAddr>,
    pub proxy_auth: Option<Zeroizing<Vec<u8>>>,
}

/// Dial the broker once and relay until the session ends.
///
/// [`Ok`] means the session was authenticated and then ended (the caller
/// reconnects). [`ClientError::Unauthorized`] and [`ClientError::BadCert`]
/// mean the broker refused the credential or the pin did not match; no
/// CDP dial is made in either case.
pub async fn run_agent_once(params: &AgentParams) -> Result<(), ClientError> {
    if !params.cdp.ip().is_loopback() || params.cdp.port() == 0 {
        return Err(ClientError::CdpNotLoopback);
    }
    let tcp = match params.proxy {
        Some(proxy) => {
            let auth = params.proxy_auth.as_ref().map(|v| v.as_slice());
            connect_http_proxy(proxy, &params.server_name, params.broker.port(), auth).await?
        }
        None => TcpStream::connect(params.broker)
            .await
            .map_err(|_| ClientError::Transport { context: "tcp" })?,
    };
    let _ = tcp.set_nodelay(true);
    let mut tls = match connect_pinned(&params.server_name, params.pin, tcp).await {
        Ok(tls) => tls,
        Err(e) if is_pin_mismatch(&e) => return Err(ClientError::BadCert),
        Err(_) => return Err(ClientError::Transport { context: "tls" }),
    };
    write_client_hello(&mut tls, &params.agent_id, params.token.as_str())
        .await
        .map_err(|_| ClientError::Protocol)?;
    let status =
        match tokio::time::timeout(Duration::from_secs(10), read_server_hello(&mut tls)).await {
            Ok(Ok(status)) => status,
            Ok(Err(_)) => return Err(ClientError::Protocol),
            Err(_) => return Err(ClientError::Transport { context: "tls" }),
        };
    match status {
        AUTH_OK => {}
        AUTH_UNAUTHORIZED => return Err(ClientError::Unauthorized),
        AUTH_PROTOCOL => return Err(ClientError::Protocol),
        _ => return Err(ClientError::Protocol),
    }
    serve_agent(tls, params.cdp).await?;
    Ok(())
}
