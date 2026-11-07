//! HTTP/1.1 `CONNECT` in front of the broker TLS handshake.
//!
//! Proxy authentication is optional and file-backed: the agent binary
//! still refuses a proxy URL with userinfo so a password is never on
//! the command line or in a logged config value. When a credential is
//! supplied, the CONNECT request carries `Proxy-Authorization: Basic`
//! built from that credential; a `407` is reported as
//! [`ClientError::ProxyAuth`] without echoing the credential or the
//! response body.

use std::net::SocketAddr;

use base64ct::{Base64, Encoding};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ClientError;

/// Dial `proxy` and ask it to connect to `target_host:target_port`.
///
/// `basic_userinfo`, when set, is the raw `user:password` bytes used to
/// build a Basic `Proxy-Authorization` header. It is never logged.
/// The returned stream is ready for the TLS handshake to that target.
pub async fn connect_http_proxy(
    proxy: SocketAddr,
    target_host: &str,
    target_port: u16,
    basic_userinfo: Option<&[u8]>,
) -> Result<TcpStream, ClientError> {
    if target_host.is_empty() || target_host.len() > 253 || target_host.contains([' ', '\r', '\n'])
    {
        return Err(ClientError::Protocol);
    }
    if let Some(cred) = basic_userinfo {
        // Reject CR/LF so a malicious file cannot inject headers.
        if cred.is_empty() || cred.iter().any(|b| *b == b'\r' || *b == b'\n') {
            return Err(ClientError::Protocol);
        }
    }
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|_| ClientError::Transport { context: "proxy" })?;
    let _ = stream.set_nodelay(true);
    let mut req = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(cred) = basic_userinfo {
        let b64 = Base64::encode_string(cred);
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&b64);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
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
    if !version.starts_with("HTTP/1.") {
        return Err(ClientError::Transport { context: "proxy" });
    }
    if code == "407" {
        return Err(ClientError::ProxyAuth);
    }
    if code != "200" {
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
