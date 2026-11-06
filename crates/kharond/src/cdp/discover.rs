//! Resolving a CDP base address to the browser's WebSocket URL (issue
//! #113).
//!
//! Chromium serves its browser-level DevTools socket at
//! `/devtools/browser/<id>`, and makes up a new `<id>` every time it
//! starts. Its HTTP side answers `GET /json/version` with the current
//! URL in `webSocketDebuggerUrl`. With a base address configured
//! (`cdp = { endpoint = "ws://10.66.0.2:9222", ... }`), kharond asks for
//! it on every connect, so a browser restart needs no config edit: the
//! connection to the old browser ends, and the next fill reconnects and
//! resolves again ([`super::CdpClient::connect`]).
//!
//! Only the **path** of `webSocketDebuggerUrl` is used. The scheme, host
//! and port stay the configured ones, for two reasons:
//!
//! - Chromium builds the URL from the request's `Host` header or the
//!   address it binds (`127.0.0.1` on the agent host), not from the
//!   address kharond dialled through the WireGuard relay or ssh tunnel,
//!   and a TLS terminator in front of it still makes it say `ws://`.
//! - The browser must not be able to point kharond somewhere else.
//!   REQ-ARCH-002 is checked on the configured URL at config load, and
//!   that is the URL kharond connects to.
//!
//! The path must look like `/devtools/browser/<id>` with `<id>` made of
//! ASCII letters, digits and `-` (Chromium's ids are UUIDs).
//!
//! The request goes over the same transport as the WebSocket (plain TCP,
//! or pinned TLS for `wss://`), with a hand-rolled HTTP/1.1 `GET` like
//! the rest of the CDP client: one request, `Connection: close`, a
//! bounded response read. Chromium refuses DevTools HTTP requests whose
//! `Host` is neither an IP literal nor `localhost` (a DNS-rebinding
//! guard), so for a DNS-named endpoint the header says `localhost`.
//!
//! Errors carry kharond's own wording only; no response text reaches a
//! log or a reply (REQ-GOAL-001).

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::{Host, Url};

use super::client::{CdpError, open_stream};
use super::endpoint::CdpEndpoint;

/// Upper bound on the whole `/json/version` response (head and body).
/// Chromium's is well under 1 KiB.
pub const MAX_RESPONSE: usize = 64 * 1024;

/// The path Chromium serves the browser-level socket under.
const BROWSER_PATH_PREFIX: &str = "/devtools/browser/";

/// The browser's current WebSocket URL for a base-address `endpoint`:
/// the configured scheme, host and port with the path from
/// `/json/version`.
///
/// No timeout of its own: callers bound the whole connect (the daemon's
/// connect budget, `DEFAULT_CONNECT_TIMEOUT`).
pub async fn browser_url(endpoint: &CdpEndpoint) -> Result<Url, CdpError> {
    let mut stream = open_stream(endpoint).await?;
    let request = format!(
        "GET /json/version HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        host_header(&endpoint.url, true)
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| CdpError::Transport(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| CdpError::Transport(e.to_string()))?;
    let body = read_response(&mut stream).await?;
    let path = browser_path(&body)?;
    let mut url = endpoint.url.clone();
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// The `Host` header for a request to `url`: its host (with the port
/// when `with_port`) if that is an IP literal or `localhost`, else
/// `localhost` — Chromium answers DevTools requests only for those.
pub fn host_header(url: &Url, with_port: bool) -> String {
    let host = match url.host() {
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => format!("[{ip}]"),
        Some(Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => d.to_owned(),
        _ => "localhost".to_owned(),
    };
    match (with_port, url.port_or_known_default()) {
        (true, Some(port)) => format!("{host}:{port}"),
        _ => host,
    }
}

/// Read one HTTP/1.1 response and return its body, or an error if it is
/// not a `200` or runs past [`MAX_RESPONSE`]. The body ends at
/// `Content-Length` (Chromium keeps the socket open past it even with
/// `Connection: close`) or, without one, at EOF.
async fn read_response<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>, CdpError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let mut head: Option<(usize, Option<usize>)> = None;
    loop {
        if head.is_none()
            && let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n")
        {
            head = Some((end + 4, parse_head(&buf[..end])?));
        }
        if let Some((start, Some(len))) = head {
            if start + len > MAX_RESPONSE {
                return Err(CdpError::Discovery("response too large"));
            }
            if buf.len() >= start + len {
                return Ok(buf[start..start + len].to_vec());
            }
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| CdpError::Transport(e.to_string()))?;
        if n == 0 {
            return match head {
                Some((start, None)) => Ok(buf[start..].to_vec()),
                Some((_, Some(_))) => Err(CdpError::Discovery("response cut short")),
                None => Err(CdpError::Discovery("no HTTP response")),
            };
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_RESPONSE {
            return Err(CdpError::Discovery("response too large"));
        }
    }
}

/// Check the status line and return `Content-Length`, if any.
fn parse_head(head: &[u8]) -> Result<Option<usize>, CdpError> {
    let head = std::str::from_utf8(head).map_err(|_| CdpError::Discovery("bad HTTP response"))?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.split(' ');
    match (parts.next(), parts.next()) {
        (Some(v), Some("200")) if v.starts_with("HTTP/1.") => {}
        (Some(v), Some(_)) if v.starts_with("HTTP/1.") => {
            return Err(CdpError::Discovery("browser refused the request"));
        }
        _ => return Err(CdpError::Discovery("bad HTTP response")),
    }
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(CdpError::Discovery("unsupported transfer encoding"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let n = value
                .trim()
                .parse::<usize>()
                .map_err(|_| CdpError::Discovery("bad content length"))?;
            length = Some(n);
        }
    }
    Ok(length)
}

/// The `/devtools/browser/<id>` path from a `/json/version` body.
fn browser_path(body: &[u8]) -> Result<String, CdpError> {
    let v: Value = serde_json::from_slice(body).map_err(|_| CdpError::Discovery("not JSON"))?;
    let ws = v
        .get("webSocketDebuggerUrl")
        .and_then(Value::as_str)
        .ok_or(CdpError::Discovery("no webSocketDebuggerUrl"))?;
    let url = Url::parse(ws).map_err(|_| CdpError::Discovery("bad webSocketDebuggerUrl"))?;
    let path = url.path();
    let id = path
        .strip_prefix(BROWSER_PATH_PREFIX)
        .ok_or(CdpError::Discovery("not a browser endpoint"))?;
    if id.is_empty()
        || id.len() > 128
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(CdpError::Discovery("not a browser endpoint"));
    }
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f0b2c1e-9a7d-4e43-b1a2-6f9c0d8e7a65";

    fn version(ws: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "Browser": "Chrome/157.0.8103.27",
            "Protocol-Version": "1.3",
            "webSocketDebuggerUrl": ws,
        }))
        .unwrap()
    }

    #[test]
    fn path_is_taken_whatever_host_chromium_names() {
        for ws in [
            format!("ws://127.0.0.1:9222/devtools/browser/{ID}"),
            format!("ws://localhost:9222/devtools/browser/{ID}"),
            format!("ws://evil.example:1/devtools/browser/{ID}"),
        ] {
            assert_eq!(
                browser_path(&version(&ws)).unwrap(),
                format!("/devtools/browser/{ID}")
            );
        }
    }

    #[test]
    fn only_browser_paths_are_accepted() {
        for ws in [
            "ws://127.0.0.1:9222/devtools/page/ABC".to_owned(),
            "ws://127.0.0.1:9222/devtools/browser/".to_owned(),
            "ws://127.0.0.1:9222/devtools/browser/a/b".to_owned(),
            "ws://127.0.0.1:9222/devtools/browser/a%2Fb".to_owned(),
            "ws://127.0.0.1:9222/devtools/browser/../../x".to_owned(),
            format!("ws://127.0.0.1:9222/devtools/browser/{}", "a".repeat(129)),
            "not a url".to_owned(),
        ] {
            assert!(
                matches!(browser_path(&version(&ws)), Err(CdpError::Discovery(_))),
                "{ws}"
            );
        }
        assert!(matches!(
            browser_path(b"{}"),
            Err(CdpError::Discovery("no webSocketDebuggerUrl"))
        ));
        assert!(matches!(
            browser_path(b"<html>"),
            Err(CdpError::Discovery("not JSON"))
        ));
    }

    #[test]
    fn host_header_names_ips_and_localhost_else_localhost() {
        let h = |u: &str, p| host_header(&Url::parse(u).unwrap(), p);
        assert_eq!(h("ws://10.66.0.2:9222", true), "10.66.0.2:9222");
        assert_eq!(h("ws://10.66.0.2:9222", false), "10.66.0.2");
        assert_eq!(h("ws://[::1]:9222", true), "[::1]:9222");
        assert_eq!(h("ws://localhost:9222", true), "localhost:9222");
        assert_eq!(h("ws://agent-host:9222", true), "localhost:9222");
        assert_eq!(h("wss://agent-host.example", true), "localhost:443");
    }

    async fn read(raw: &[u8]) -> Result<Vec<u8>, CdpError> {
        read_response(&mut &raw[..]).await
    }

    #[tokio::test]
    async fn response_body_ends_at_content_length() {
        let body = version(&format!("ws://127.0.0.1:9222/devtools/browser/{ID}"));
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Length:{}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(&body);
        raw.extend_from_slice(b"trailing bytes are ignored");
        assert_eq!(read(&raw).await.unwrap(), body);

        // No Content-Length: the body runs to EOF.
        let mut raw = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        raw.extend_from_slice(&body);
        assert_eq!(read(&raw).await.unwrap(), body);
    }

    #[tokio::test]
    async fn bad_responses_are_discovery_errors() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\nno",
                "browser refused the request",
            ),
            (b"SSH-2.0-OpenSSH\r\n\r\n", "bad HTTP response"),
            (b"", "no HTTP response"),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
                "response cut short",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                "unsupported transfer encoding",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n",
                "response too large",
            ),
        ];
        for (raw, want) in cases {
            match read(raw).await {
                Err(CdpError::Discovery(got)) => assert_eq!(got, *want),
                other => panic!("{want}: got {other:?}"),
            }
        }
        // Endless headers are cut off too.
        let raw = vec![b'a'; MAX_RESPONSE + 10];
        assert!(matches!(
            read(&raw).await,
            Err(CdpError::Discovery("response too large"))
        ));
    }
}
