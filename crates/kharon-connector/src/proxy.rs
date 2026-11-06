//! HTTP/1.1 `CONNECT` in front of the broker TLS handshake.
//!
//! v1 has no proxy authentication. A proxy URL with userinfo is refused
//! by the agent binary so a password is not placed on the command line
//! or in the config the process would otherwise log. Add auth only with
//! a story for where the secret lives (a file, like the tunnel token).

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ClientError;

/// Dial `proxy` and ask it to connect to `target_host:target_port`.
/// The returned stream is ready for the TLS handshake to that target.
pub async fn connect_http_proxy(
    proxy: SocketAddr,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, ClientError> {
    if target_host.is_empty() || target_host.len() > 253 || target_host.contains([' ', '\r', '\n'])
    {
        return Err(ClientError::Protocol);
    }
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|_| ClientError::Transport { context: "proxy" })?;
    let _ = stream.set_nodelay(true);
    let req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|_| ClientError::Transport { context: "proxy" })?;
    let head = read_proxy_head(&mut stream).await?;
    let status = head
        .split("\r\n")
        .next()
        .ok_or(ClientError::Transport { context: "proxy" })?;
    let mut parts = status.split(' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") || code != "200" {
        return Err(ClientError::Transport { context: "proxy" });
    }
    Ok(stream)
}

async fn read_proxy_head(stream: &mut TcpStream) -> Result<String, ClientError> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while buf.len() < 8 * 1024 {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|_| ClientError::Transport { context: "proxy" })?;
        if n == 0 {
            return Err(ClientError::Transport { context: "proxy" });
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buf).map_err(|_| ClientError::Transport { context: "proxy" });
        }
    }
    Err(ClientError::Transport { context: "proxy" })
}
