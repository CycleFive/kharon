//! HTTP/1.1 `CONNECT` in front of the broker TLS handshake.
//!
//! Proxy authentication is optional and hop-local. When the caller
//! passes `user:password` bytes, the CONNECT request carries
//! `Proxy-Authorization: Basic …` (standard base64 of those bytes).
//! Those bytes come from a file with mode `0400` or `0600`, the same
//! posture as the tunnel token — never from the proxy URL, argv, or an
//! error string. A proxy URL with userinfo is refused by the agent
//! binary.
//!
//! With no credential the request is the historical unauthenticated
//! form, byte for byte: request line, `Host`, `Proxy-Connection`, and
//! a blank line. The credential is not written on the broker TLS
//! session. HTTP 407 is [`ClientError::ProxyAuth`]; that error includes
//! neither the credential nor the proxy's response.

use std::net::SocketAddr;

use base64ct::Encoding;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

use crate::ClientError;

/// Largest `user:password` line accepted from the credential file.
/// A trailing newline is not counted.
const PROXY_CREDS_MAX: usize = 4096;

/// Dial `proxy` and ask it to connect to `target_host:target_port`.
///
/// `basic` is the raw `user:password` line (no trailing newline), or
/// `None` for an unauthenticated proxy. The returned stream is ready
/// for the TLS handshake to that target.
pub async fn connect_http_proxy(
    proxy: SocketAddr,
    target_host: &str,
    target_port: u16,
    basic: Option<&[u8]>,
) -> Result<TcpStream, ClientError> {
    if target_host.is_empty() || target_host.len() > 253 || target_host.contains([' ', '\r', '\n'])
    {
        return Err(ClientError::Protocol);
    }
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|e| ClientError::Tcp { kind: e.kind() })?;
    let _ = stream.set_nodelay(true);
    {
        let req = connect_request(target_host, target_port, basic);
        stream
            .write_all(&req)
            .await
            .map_err(|_| ClientError::ProxyStatus { code: 0 })?;
    }
    let head = read_proxy_head(&mut stream).await?;
    let status = head
        .split("\r\n")
        .next()
        .ok_or(ClientError::ProxyStatus { code: 0 })?;
    let mut parts = status.split(' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(ClientError::ProxyStatus { code: 0 });
    }
    match code {
        "200" => Ok(stream),
        "407" => Err(ClientError::ProxyAuth),
        other => Err(ClientError::ProxyStatus {
            code: other.parse().unwrap_or(0),
        }),
    }
}

/// `basic`, when set, is inserted between `Host` and `Proxy-Connection`
/// so the `None` path stays the historical request.
fn connect_request(
    target_host: &str,
    target_port: u16,
    basic: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    let head = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    let mut req = Zeroizing::new(Vec::with_capacity(head.len() + 96));
    req.extend_from_slice(head.as_bytes());
    if let Some(creds) = basic {
        let b64 = Zeroizing::new(base64ct::Base64::encode_string(creds));
        req.extend_from_slice(b"Proxy-Authorization: Basic ");
        req.extend_from_slice(b64.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"Proxy-Connection: keep-alive\r\n\r\n");
    req
}

/// One credential-file line: trim trailing CR/LF only, require
/// `user:password` (password may be empty), reject a second line.
/// The returned bytes are what Basic encodes; they are not logged.
pub fn proxy_creds_line(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut end = raw.len();
    while end > 0 && matches!(raw[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    let line = &raw[..end];
    if line.is_empty() || line.len() > PROXY_CREDS_MAX {
        return Err("proxy credential file must be one line of user:password");
    }
    if line.contains(&b'\n') || line.contains(&b'\r') || line.contains(&b'\0') {
        return Err("proxy credential file must be one line of user:password");
    }
    match line.iter().position(|b| *b == b':') {
        Some(0) | None => Err("proxy credential file must be one line of user:password"),
        Some(_) => Ok(Zeroizing::new(line.to_vec())),
    }
}

async fn read_proxy_head(stream: &mut TcpStream) -> Result<String, ClientError> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while buf.len() < 8 * 1024 {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|_| ClientError::ProxyStatus { code: 0 })?;
        if n == 0 {
            return Err(ClientError::ProxyStatus { code: 0 });
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buf).map_err(|_| ClientError::ProxyStatus { code: 0 });
        }
    }
    Err(ClientError::ProxyStatus { code: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const UNAUTHENTICATED: &str = "\
CONNECT broker.example:8788 HTTP/1.1\r\n\
Host: broker.example:8788\r\n\
Proxy-Connection: keep-alive\r\n\
\r\n";

    /// RFC 7617 §2: `Aladdin:open sesame`.
    const BASIC_CREDS: &[u8] = b"Aladdin:open sesame";
    const BASIC_B64: &str = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";

    async fn exchange(
        response: &'static [u8],
        basic: Option<&'static [u8]>,
    ) -> (Result<(), ClientError>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                let n = sock.read(&mut byte).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let _ = sock.write_all(response).await;
            let _ = tx.send(buf);
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connect_http_proxy(addr, "broker.example", 8788, basic),
        )
        .await
        .expect("proxy connect timed out")
        .map(|_| ());
        let req = rx.await.unwrap();
        (result, req)
    }

    #[test]
    fn basic_encoding_matches_rfc7617() {
        assert_eq!(base64ct::Base64::encode_string(BASIC_CREDS), BASIC_B64);
    }

    #[tokio::test]
    async fn connect_without_credentials_is_the_historical_request() {
        let (result, req) = exchange(b"HTTP/1.1 200 Connection Established\r\n\r\n", None).await;
        assert!(result.is_ok());
        assert_eq!(req, UNAUTHENTICATED.as_bytes());
        assert!(
            !req.windows(b"Proxy-Authorization".len())
                .any(|w| w == b"Proxy-Authorization")
        );
    }

    #[tokio::test]
    async fn connect_with_credentials_sends_basic_and_is_accepted() {
        let (result, req) = exchange(
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
            Some(BASIC_CREDS),
        )
        .await;
        assert!(result.is_ok());
        let expected = format!(
            "\
CONNECT broker.example:8788 HTTP/1.1\r\n\
Host: broker.example:8788\r\n\
Proxy-Authorization: Basic {BASIC_B64}\r\n\
Proxy-Connection: keep-alive\r\n\
\r\n"
        );
        assert_eq!(req, expected.as_bytes());
        assert!(
            !req.windows(b"open sesame".len())
                .any(|w| w == b"open sesame")
        );
        assert!(!req.windows(b"Aladdin".len()).any(|w| w == b"Aladdin"));
    }

    #[tokio::test]
    async fn proxy_407_is_its_own_error_and_leaks_nothing() {
        let response = b"\
HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"Aladdin\"\r\n\
\r\n\
open sesame";
        let (result, _) = exchange(response, Some(BASIC_CREDS)).await;
        let err = result.unwrap_err();
        assert_eq!(err, ClientError::ProxyAuth);
        assert_eq!(err.to_string(), "proxy authentication was refused");
        let shown = format!("{err:?} {err}");
        assert!(!shown.contains("open sesame"));
        assert!(!shown.contains("Aladdin"));
        assert!(!shown.contains(BASIC_B64));
    }

    #[tokio::test]
    async fn proxy_407_without_credentials_is_the_same_error() {
        let (result, req) =
            exchange(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", None).await;
        assert_eq!(result.unwrap_err(), ClientError::ProxyAuth);
        assert_eq!(req, UNAUTHENTICATED.as_bytes());
    }

    #[tokio::test]
    async fn other_proxy_status_is_reported_as_received() {
        let (result, _) = exchange(b"HTTP/1.1 502 Bad Gateway\r\n\r\n", None).await;
        let err = result.unwrap_err();
        assert_eq!(err, ClientError::ProxyStatus { code: 502 });
        assert_eq!(err.to_string(), "proxy CONNECT answered 502");
    }

    #[test]
    fn credential_line_trims_a_trailing_newline_only() {
        let line = proxy_creds_line(b"user:p@ss word\n").unwrap();
        assert_eq!(line.as_slice(), b"user:p@ss word");
        let crlf = proxy_creds_line(b"user:p@ss word\r\n").unwrap();
        assert_eq!(crlf.as_slice(), b"user:p@ss word");
        let empty_pass = proxy_creds_line(b"user:\n").unwrap();
        assert_eq!(empty_pass.as_slice(), b"user:");
    }

    #[test]
    fn credential_line_rejects_a_shape_that_is_not_one_line() {
        for raw in [
            b"".as_slice(),
            b"\n",
            b"nopassword\n",
            b":only-password\n",
            b"user:pass\nsecond\n",
            b"user:pass\0\n",
        ] {
            assert!(proxy_creds_line(raw).is_err(), "{raw:?}");
        }
    }
}
