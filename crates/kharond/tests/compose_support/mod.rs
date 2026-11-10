//! Helpers shared by the compose E2Es (`req_dep_002_compose_e2e`, the
//! path-B WebSocket variant). Project, container, volume and address
//! names are parameters; the page, fixture and host constants are shared.

#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::docker_support::{docker, docker_raw};
use base64ct::{Base64, Encoding};
use futures_util::{SinkExt, StreamExt};
use kharond::sync::{ApiKey, SyncClient, TlsTrust};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use url::Url;

pub const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);

pub const PAGE_HOST: &str = "canary.example.test";

pub const PAGE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>kharon compose E2E login</title></head>
<body>
<form id="login" action="/submitted" method="post">
  <input id="username" name="username" type="email" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
</body></html>
"#;

pub const WELCOME: &str =
    "<!doctype html><html><head><title>welcome</title></head><body>signed in</body></html>";

pub fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set (see image.yml)"))
}

pub fn manifest() -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURE_DIR}/fixture.json")).unwrap())
        .unwrap()
}

pub fn write_public(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
    // Read by the containers' own uids (bind mounts keep host modes).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// A container's ID and start time: changes if it was restarted or
/// recreated.
pub fn identity(container: &str) -> String {
    docker(&["inspect", "-f", "{{.Id}} {{.State.StartedAt}}", container])
        .trim()
        .to_owned()
}

/// The container ID part of an `identity` string.
pub fn id_of(identity: &str) -> &str {
    identity.split(' ').next().unwrap_or("")
}

/// 32 random bytes, hex-encoded: the REQ-GOAL-002 canary.
pub fn random_hex32() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Adds the canary login to the fixture collection through the web
/// vault's API (mutate.py); the password goes via the environment.
pub fn add_canary_item(base: &Url, ca: &Path, name: &str, canary: &str) {
    let out = Command::new("python3")
        .arg(format!("{FIXTURE_DIR}/mutate.py"))
        .args(["--base-url", base.as_str().trim_end_matches('/')])
        .arg("--ca-cert")
        .arg(ca)
        .args([
            "add",
            "--name",
            name,
            "--username",
            "canary-user@example.test",
            "--uri",
            &format!("https://{PAGE_HOST}/login"),
            "--password-env",
            "KHARON_E2E_CANARY",
        ])
        .env("KHARON_E2E_CANARY", canary)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "mutate.py add: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

pub async fn fixture_scope(base: &Url, email: &str, ca: &Path, api_key: &Path) -> (String, String) {
    let trust = TlsTrust {
        extra_ca_pem: Some(std::fs::read(ca).unwrap()),
    };
    let key = ApiKey::from_file(api_key).unwrap();
    let mut c = SyncClient::new(base, email, key, &trust).unwrap();
    let raw = c.sync().await.unwrap();
    let org = raw.profile.organizations.as_ref().unwrap()[0].id.clone();
    let coll = raw.collections.as_ref().unwrap()[0].id.clone();
    (org, coll)
}

/// The test page's throwaway TLS identity for [`PAGE_HOST`]: the
/// acceptor and the certificate's SPKI SHA-256 (base64), which is all
/// the agent host's Chromium is told to trust beyond its system store.
pub fn page_tls() -> (tokio_rustls::TlsAcceptor, String) {
    let ck = rcgen::generate_simple_self_signed(vec![PAGE_HOST.to_string()]).unwrap();
    let spki = Base64::encode_string(&Sha256::digest(ck.key_pair.public_key_der()));
    let cert = ck.cert.der().clone();
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    (tokio_rustls::TlsAcceptor::from(Arc::new(tls)), spki)
}

/// Serves the test page on `bind_ip`, an address of the docker host
/// (a compose network's gateway, where the agent host's Chromium maps
/// the page's hostname).
/// Returns the port and, per form POST, whether its password field
/// carried the canary (nothing else of the body is kept).
pub async fn serve_page(
    bind_ip: &str,
    acceptor: tokio_rustls::TlsAcceptor,
    canary: &str,
) -> (u16, Arc<Mutex<Vec<bool>>>) {
    let listener = TcpListener::bind(format!("{bind_ip}:0"))
        .await
        .unwrap_or_else(|e| panic!("cannot bind the test page on {bind_ip}: {e}"));
    let port = listener.local_addr().unwrap().port();
    // One entry per POST: did its password field carry the canary?
    let submits = Arc::new(Mutex::new(Vec::new()));
    let seen = submits.clone();
    let want = format!("password={canary}");
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            let want = want.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let mut parts = head.split_whitespace();
                let method = parts.next().unwrap_or("").to_owned();
                let path = parts.next().unwrap_or("/").to_owned();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + len {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let (status, body) = match (method.as_str(), path.as_str()) {
                    ("POST", "/submitted") => {
                        let form = String::from_utf8_lossy(&buf[head_end..head_end + len]);
                        seen.lock()
                            .unwrap()
                            .push(form.split('&').any(|kv| kv == want));
                        ("200 OK", WELCOME)
                    }
                    (_, "/favicon.ico") => ("404 Not Found", ""),
                    _ => ("200 OK", PAGE),
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (port, submits)
}

/// The agent host's browser-level DevTools URL, via its wg relay.
pub async fn browser_ws_url(cdp: std::net::SocketAddr) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(Some(ws)) =
            tokio::time::timeout(Duration::from_secs(5), json_version_ws_url(cdp)).await
        {
            return ws;
        }
        assert!(
            Instant::now() < deadline,
            "agent host CDP never answered on {cdp}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// One `GET /json/version`. Chromium keeps the connection open, so
/// the body is read up to its `Content-Length`.
pub async fn json_version_ws_url(cdp: std::net::SocketAddr) -> Option<String> {
    let mut s = TcpStream::connect(cdp).await.ok()?;
    let req = format!("GET /json/version HTTP/1.1\r\nHost: {cdp}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))?
                .trim()
                .parse()
                .ok()?;
            if buf.len() >= i + 4 + len {
                let v: Value = serde_json::from_slice(&buf[i + 4..i + 4 + len]).ok()?;
                return v["webSocketDebuggerUrl"].as_str().map(str::to_owned);
            }
        }
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The agent's own CDP client (flat sessions).
pub struct Cdp {
    pub ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    pub next: u64,
}

impl Cdp {
    pub async fn connect(url: &str) -> Self {
        let (ws, _) = connect_async(url).await.unwrap();
        Self { ws, next: 0 }
    }

    pub async fn call(&mut self, session: Option<&str>, method: &str, params: Value) -> Value {
        self.next += 1;
        let id = self.next;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.ws.send(Message::Text(msg.to_string())).await.unwrap();
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(30), self.ws.next())
                .await
                .unwrap_or_else(|_| panic!("no reply to {method}"))
                .expect("CDP connection closed")
                .unwrap();
            let Message::Text(text) = frame else {
                continue;
            };
            let v: Value = serde_json::from_str(&text).unwrap();
            if v["id"] == json!(id) {
                assert!(v.get("error").is_none(), "{method}: {v}");
                return v["result"].clone();
            }
        }
    }

    pub async fn eval(&mut self, session: &str, expression: &str) -> Value {
        let r = self
            .call(
                Some(session),
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
            )
            .await;
        r["result"]["value"].clone()
    }

    /// Opens `url` in a new tab (in `context`, or the default one) and
    /// waits until `ready` (a JS expression) is true.
    pub async fn open(
        &mut self,
        context: Option<&str>,
        url: &str,
        ready: &str,
    ) -> (String, String) {
        let mut params = json!({"url": url});
        if let Some(c) = context {
            params["browserContextId"] = json!(c);
        }
        let r = self.call(None, "Target.createTarget", params).await;
        let target = r["targetId"].as_str().unwrap().to_owned();
        let r = self
            .call(
                None,
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
            )
            .await;
        let session = r["sessionId"].as_str().unwrap().to_owned();
        self.wait(&session, ready, url).await;
        (target, session)
    }

    pub async fn wait(&mut self, session: &str, ready: &str, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.eval(session, ready).await != json!(true) {
            assert!(
                Instant::now() < deadline,
                "{what}: never became ready ({ready})"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// `ss <args>` inside the network namespace of `container`. `Err` carries
/// the sudo/nsenter failure text (no passwordless sudo, for one).
pub fn ss_in(container: &str, args: &str) -> Result<String, String> {
    let pid = docker(&["inspect", "--format", "{{.State.Pid}}", container]);
    let pid = pid.trim();
    let mut cmd = if rustix::process::geteuid().is_root() {
        Command::new("nsenter")
    } else {
        let mut c = Command::new("sudo");
        c.args(["-n", "nsenter"]);
        c
    };
    let out = cmd
        .args(["-t", pid, "-n", "ss", args])
        .output()
        .map_err(|e| format!("ss {args}: cannot run nsenter: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ss {args}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The name of the volume mounted at `/data` in `container`.
pub fn data_volume_of(container: &str) -> String {
    let mounts = docker(&[
        "inspect",
        "--format",
        "{{range .Mounts}}{{if eq .Destination \"/data\"}}{{.Name}}{{end}}{{end}}",
        container,
    ]);
    let volume = mounts.trim();
    assert!(!volume.is_empty(), "no volume mounted at /data");
    volume.to_owned()
}

/// Owner-approve a grant request for the compose daemon (#20,
/// REQ-APR-001).
///
/// kharond's owner socket lives in its data volume (`data_volume`, from
/// [`data_volume_of`]), and
/// the daemon accepts only its own uid (10001) as a peer
/// (REQ-APR-006). The test host has no client for it yet (the
/// `kharon` CLI's approve surface is #21), so the approval rides a
/// one-off container: the agent-host image (it carries `socat`),
/// run as the daemon's uid with the volume mounted — the
/// operator-with-docker-access move, mirroring how setup unlocks
/// through `docker exec`. Nothing in the running deployment is
/// touched: the helper container is gone before the fill retries.
pub fn owner_approve(data_volume: &str, image: &str, request_id: &str) {
    let line = format!(
        "{}\n",
        json!({"op": "approve", "request_id": request_id, "kind": "per-origin"})
    );
    let out = docker_raw(
        &[
            "run",
            "--rm",
            "-i",
            "--user",
            "10001:10001",
            "--entrypoint",
            "socat",
            "-v",
            &format!("{data_volume}:/data"),
            image,
            "-",
            "UNIX-CONNECT:/data/owner.sock",
        ],
        Some(line.as_bytes()),
    );
    assert!(
        out.status.success(),
        "owner approve container failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reply: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
        panic!(
            "bad approve reply: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(reply["ok"], json!(true), "approve: {reply}");
}

// ------------------------------------------------- MCP over TLS

/// `_meta` of a 2026-07-28 MCP request.
#[derive(serde::Serialize)]
struct McpMeta {
    #[serde(rename = "io.modelcontextprotocol/protocolVersion")]
    protocol_version: &'static str,
}

#[derive(serde::Serialize)]
struct McpToolCall<'a, A> {
    name: &'a str,
    arguments: &'a A,
    #[serde(rename = "_meta")]
    meta: McpMeta,
}

#[derive(serde::Serialize)]
struct McpRequest<P> {
    jsonrpc: &'static str,
    id: u32,
    method: &'static str,
    params: P,
}

#[derive(serde::Deserialize)]
struct McpResponse {
    result: Option<McpToolResult>,
    error: Option<McpRpcError>,
}

#[derive(serde::Deserialize)]
struct McpRpcError {
    code: i64,
    message: String,
}

#[derive(serde::Deserialize)]
struct McpToolResult {
    content: Vec<McpContent>,
    #[serde(rename = "isError")]
    is_error: bool,
}

#[derive(serde::Deserialize)]
struct McpContent {
    text: String,
}

/// A TLS client config trusting only `ca_pem` (one CA certificate).
fn tls_client(ca_pem: &str) -> tokio_rustls::TlsConnector {
    use rustls_pki_types::{CertificateDer, pem::PemObject};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).expect("edge CA pem"))
        .unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

/// `tools/call` of `tool` through `POST /mcp` over TLS to `addr` (SNI
/// and `Host` `sni`, trusting `ca_pem`), with the headers and body of
/// `api_support::mcp_request`. Returns the tool result's text (the
/// `ApiError`/`FillResult` JSON). `Err` carries a transport, HTTP,
/// JSON-RPC or `isError: true` failure, never the bearer token.
pub async fn mcp_tool_tls<A: serde::Serialize>(
    addr: std::net::SocketAddr,
    sni: &str,
    ca_pem: &str,
    token: &str,
    tool: &str,
    arguments: &A,
) -> Result<String, String> {
    // One overall bound, so a stalled relay cannot hang the job.
    tokio::time::timeout(
        Duration::from_secs(30),
        mcp_tool_tls_inner(addr, sni, ca_pem, token, tool, arguments),
    )
    .await
    .map_err(|_| format!("{tool}: no complete reply from {addr} within 30 s"))?
}

async fn mcp_tool_tls_inner<A: serde::Serialize>(
    addr: std::net::SocketAddr,
    sni: &str,
    ca_pem: &str,
    token: &str,
    tool: &str,
    arguments: &A,
) -> Result<String, String> {
    const VERSION: &str = "2026-07-28";
    let body = serde_json::to_string(&McpRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: McpToolCall {
            name: tool,
            arguments,
            meta: McpMeta {
                protocol_version: VERSION,
            },
        },
    })
    .unwrap();
    let head = format!(
        "POST /mcp HTTP/1.1\r\nHost: {sni}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
         MCP-Protocol-Version: {VERSION}\r\nMcp-Method: tools/call\r\nMcp-Name: {tool}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect {addr}: {e}"))?;
    let name = rustls_pki_types::ServerName::try_from(sni.to_owned()).unwrap();
    let mut tls = tls_client(ca_pem)
        .connect(name, tcp)
        .await
        .map_err(|e| format!("TLS to {addr} as {sni}: {e}"))?;
    tls.write_all(head.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    // The edge may close without a TLS close_notify: keep what arrived.
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read from {addr}: {e}")),
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (resp_head, resp_body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("no HTTP response ({} bytes)", buf.len()))?;
    let status = resp_head.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        return Err(format!("{status}; body: {resp_body}"));
    }
    let parsed: McpResponse = serde_json::from_str(resp_body)
        .map_err(|e| format!("bad MCP reply ({e}); body: {resp_body}"))?;
    if let Some(e) = parsed.error {
        return Err(format!("JSON-RPC error {}: {}", e.code, e.message));
    }
    let result = parsed
        .result
        .ok_or("MCP reply has neither result nor error")?;
    let text = result
        .content
        .into_iter()
        .next()
        .map(|c| c.text)
        .unwrap_or_default();
    if result.is_error {
        return Err(format!("tool error: {text}"));
    }
    Ok(text)
}
