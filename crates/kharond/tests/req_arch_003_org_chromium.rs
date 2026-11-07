//! #133: browser-level ACs against a real Chromium, with no live
//! fixture. kharond runs in export mode (the bundled export, whose
//! `Example Login` item is for `example.com`). Its agent `alpha` drives
//! a headless Chromium, and the test serves a login page for
//! `example.com` on loopback. Chromium resolves `example.com` to
//! `127.0.0.1` (`--host-resolver-rules`) and trusts only the throwaway
//! certificate's SPKI hash, so the HTTPS page is a real secure context.
//!
//! - **REQ-ARCH-003.** A second CDP client is attached to the agent's
//!   tab with `Runtime`, `Log`, `Network` and `Page` enabled while the
//!   broker fills it. Every frame it receives is recorded, and the
//!   transcript holds no secret from the item: the password, the hidden
//!   field, or the TOTP seed. The page's password field does hold the
//!   password afterwards (read back once recording has stopped), so the
//!   secret reached the browser and the absence means something. As a
//!   positive control, the transcript must show the broker's
//!   `kharon_fill` isolated world being created. SPEC says the second
//!   client sees that, so it was really subscribed during the fill.
//! - **REQ-ORG-005.** The same page served over plain HTTP, with the
//!   item's URI on `https`. The grant gate runs first, so the owner
//!   approves the request. The fill is still `origin_mismatch`, audited
//!   with `detail_code: insecure_context` and the live `http` origin,
//!   and the page's fields stay empty.
//! - **REQ-ORG-004.** A relying party on another site
//!   (`rp.example.org`) frames the item's login page. Site isolation
//!   makes that frame an `iframe` target of its own, which the agent
//!   fills by its target id. By default the fill is `origin_mismatch`
//!   and the frame's fields stay empty. With
//!   `allow_cross_origin_iframe_hosts = ["example.com"]` the same fill
//!   is `filled`, even though the top-level page matches none of the
//!   item's URIs: the allowlist admits the frame on its own origin.
//!
//! Skips when no Chromium binary is found (as `req_apr_005` does);
//! `KHARON_CHROMIUM` names one, and `KHARON_REQUIRE_CHROMIUM=1` turns
//! the skip into a failure. The Chromium flags are for this throwaway
//! test browser only, not the agent-host launch profile (REQ-DEP-005).

mod api_support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api_support::{get, post_json, raw_request};
use base64ct::{Base64, Encoding};
use futures_util::{SinkExt, StreamExt};
use kharond::api::token::generate;
use kharond::audit::{Entry, Event};
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

const EXPORT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/export/password_protected.json"
);
const EXPORT_PASSWORD: &str = "kharon export fixture password 9";
const ITEM_NAME: &str = "Example Login";
const ITEM_USERNAME: &str = "fixture@example.net";
const HOST: &str = "example.com";
/// A relying party on another site (eTLD+1 `example.org`) that frames
/// the item's login page (REQ-ORG-004).
const RP_HOST: &str = "rp.example.org";
/// The item's secrets (`tests/fixtures/gen/gen_export_fixture.py`):
/// password, hidden custom field, TOTP seed.
const SECRETS: [&str; 3] = [
    "CANARY-EXPORT-PASSWORD-7f3a",
    "CANARY-HIDDEN-FIELD-9c1d",
    "JBSWY3DPEHPK3PXP",
];

/// The test login page. It reads no value; it only counts submits and
/// cancels them, so the fill (`submit: false`) leaves it in place.
const PAGE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>kharon #133 test login</title></head>
<body>
<form id="login" action="/submitted" method="post">
  <input id="username" name="username" type="email" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
<script>
  window.__submits = 0;
  document.getElementById("login").addEventListener("submit", (e) => {
    e.preventDefault();
    window.__submits += 1;
  });
</script>
</body></html>
"#;

/// The relying party's page: it frames [`PAGE`] from [`HOST`] on the same
/// port. Chromium's site isolation puts that cross-site frame in its own
/// process, so it is an `iframe` CDP target of its own.
const RP_PAGE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>kharon #133 relying party</title></head>
<body>
<script>
  const f = document.createElement("iframe");
  f.src = "https://example.com:" + location.port + "/login";
  document.body.appendChild(f);
</script>
</body></html>
"#;

// ------------------------------------------------------------ wire types

/// `POST /v1/fill` body (SPEC §4 `FillRequest`).
#[derive(Serialize)]
struct FillBody<'a> {
    item_id: &'a str,
    target: FillTarget<'a>,
    fields: [FieldArg; 2],
    submit: bool,
}

#[derive(Serialize)]
struct FillTarget<'a> {
    cdp_target_id: &'a str,
    expected_origin: &'a str,
}

#[derive(Serialize)]
struct FieldArg {
    kind: &'static str,
}

const USERNAME_AND_PASSWORD: [FieldArg; 2] =
    [FieldArg { kind: "username" }, FieldArg { kind: "password" }];

/// `POST /v1/fill` reply (SPEC §4 `FillResult`), the parts asserted.
#[derive(Debug, Deserialize)]
struct FillReply {
    status: String,
    #[serde(default)]
    fields_filled: Vec<String>,
    grant_request_id: Option<String>,
    detail: Option<String>,
}

#[derive(Deserialize)]
struct ItemMeta {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct ContextReply {
    browser_context_id: String,
}

/// Owner-socket requests used here.
#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum OwnerOp<'a> {
    Unlock { password: &'a str },
    Approve { request_id: &'a str, kind: &'a str },
}

#[derive(Debug, Deserialize)]
struct OwnerReply {
    ok: bool,
}

// ------------------------------------------------------------ test pages

/// Answer every request on `s`: [`RP_PAGE`] under `/rp`, otherwise
/// [`PAGE`] (404 for the favicon).
async fn serve_one<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let path = String::from_utf8_lossy(&buf)
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    let (status, body) = if path == "/favicon.ico" {
        ("404 Not Found", "")
    } else if path.starts_with("/rp") {
        ("200 OK", RP_PAGE)
    } else {
        ("200 OK", PAGE)
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(reply.as_bytes()).await;
    let _ = s.shutdown().await;
}

/// [`PAGE`] over HTTPS on an ephemeral loopback port, with a throwaway
/// certificate for [`HOST`] and [`RP_HOST`]. Returns the port and the certificate's
/// SPKI SHA-256 (base64), which is all Chromium is told to trust.
async fn serve_https() -> (u16, String) {
    let ck = rcgen::generate_simple_self_signed(vec![HOST.to_owned(), RP_HOST.to_owned()]).unwrap();
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
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(s) = acceptor.accept(tcp).await {
                    serve_one(s).await;
                }
            });
        }
    });
    (port, spki)
}

/// [`PAGE`] over plain HTTP on an ephemeral loopback port.
async fn serve_http() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve_one(tcp));
        }
    });
    port
}

// ------------------------------------------------------------ Chromium

fn chromium_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KHARON_CHROMIUM") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/local/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// The Chromium binary, or `None` to skip (unless a run requires it).
fn chromium_or_skip(test: &str) -> Option<PathBuf> {
    let bin = chromium_bin();
    if bin.is_none() {
        if std::env::var_os("KHARON_REQUIRE_CHROMIUM").is_some() {
            panic!("KHARON_REQUIRE_CHROMIUM is set but no Chromium binary was found");
        }
        eprintln!("SKIP {test}: no Chromium binary");
    }
    bin
}

/// A headless Chromium child, killed on drop.
struct Chromium {
    child: Child,
    /// Browser-level DevTools websocket URL.
    ws: String,
    _profile: tempfile::TempDir,
}

impl Drop for Chromium {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn launch_chromium(bin: &Path, spki: Option<&str>) -> Chromium {
    let profile = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(bin);
    cmd.args([
        "--headless=new",
        // CI runners restrict the user namespaces the sandbox needs;
        // this browser only ever loads the loopback test page.
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--password-store=basic",
        "--no-proxy-server",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=0",
    ])
    .arg(format!("--user-data-dir={}", profile.path().display()))
    .arg(format!(
        "--host-resolver-rules=MAP {HOST} 127.0.0.1,MAP {RP_HOST} 127.0.0.1"
    ));
    if let Some(spki) = spki {
        // Trusts exactly the test page's key (needs --user-data-dir).
        cmd.arg(format!("--ignore-certificate-errors-spki-list={spki}"));
    }
    let child = cmd
        .arg("about:blank")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot launch Chromium at {}: {e}", bin.display()));
    let port_file = profile.path().join("DevToolsActivePort");
    let deadline = Instant::now() + Duration::from_secs(30);
    let ws = loop {
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                break format!("ws://127.0.0.1:{port}{path}");
            }
        }
        assert!(Instant::now() < deadline, "Chromium never opened DevTools");
        std::thread::sleep(Duration::from_millis(50));
    };
    Chromium {
        child,
        ws,
        _profile: profile,
    }
}

/// A CDP client on its own websocket (flat sessions). Every text frame
/// it receives, replies and events alike, is kept in `transcript`.
struct Cdp {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next: u64,
    transcript: Vec<String>,
}

impl Cdp {
    async fn connect(url: &str) -> Self {
        let (ws, _) = connect_async(url).await.unwrap();
        Self {
            ws,
            next: 0,
            transcript: Vec::new(),
        }
    }

    async fn call(&mut self, session: Option<&str>, method: &str, params: Value) -> Value {
        match self.try_call(session, method, params).await {
            Ok(result) => result,
            Err(error) => panic!("{method}: {error}"),
        }
    }

    /// One CDP round trip. `Err` carries the reply's `error` object.
    async fn try_call(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, Value> {
        self.next += 1;
        let id = self.next;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.ws.send(Message::Text(msg.to_string())).await.unwrap();
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(20), self.ws.next())
                .await
                .unwrap_or_else(|_| panic!("no reply to {method}"))
                .unwrap()
                .unwrap();
            let Message::Text(text) = frame else { continue };
            let v: Value = serde_json::from_str(&text).unwrap();
            self.transcript.push(text.to_string());
            if v["id"] == json!(id) {
                return match v.get("error") {
                    Some(error) => Err(error.clone()),
                    None => Ok(v["result"].clone()),
                };
            }
        }
    }

    async fn eval(&mut self, session: &str, expression: &str) -> Value {
        match self.try_eval(session, expression).await {
            Ok(value) => value,
            Err(error) => panic!("Runtime.evaluate: {error}"),
        }
    }

    async fn try_eval(&mut self, session: &str, expression: &str) -> Result<Value, Value> {
        let r = self
            .try_call(
                Some(session),
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
            )
            .await?;
        Ok(r["result"]["value"].clone())
    }

    /// Open `url` in a new tab in `context`. Returns (target, session)
    /// once the page has loaded.
    async fn open(&mut self, context: &str, url: &str) -> (String, String) {
        let r = self
            .call(
                None,
                "Target.createTarget",
                json!({"url": url, "browserContextId": context}),
            )
            .await;
        let target = r["targetId"].as_str().unwrap().to_owned();
        let session = self.attach_loaded(&target, url).await;
        (target, session)
    }

    /// The out-of-process `iframe` target showing `url`, once it exists.
    async fn iframe_target(&mut self, url: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let r = self.call(None, "Target.getTargets", json!({})).await;
            let found = r["targetInfos"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["type"] == "iframe" && t["url"] == json!(url))
                .map(|t| t["targetId"].as_str().unwrap().to_owned());
            if let Some(target) = found {
                return target;
            }
            assert!(
                Instant::now() < deadline,
                "no out-of-process iframe target for {url}: {r}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Attach to `target` and wait until it has loaded `url`. A
    /// `Runtime.evaluate` that a navigation overtakes (#167) just means
    /// "not loaded yet".
    async fn attach_loaded(&mut self, target: &str, url: &str) -> String {
        let r = self
            .call(
                None,
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
            )
            .await;
        let session = r["sessionId"].as_str().unwrap().to_owned();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let state = match self
                .try_eval(
                    &session,
                    "JSON.stringify([location.href, document.readyState])",
                )
                .await
            {
                Ok(v) => v,
                Err(error) if is_navigation_race(&error) => Value::Null,
                Err(error) => panic!("Runtime.evaluate: {error}"),
            };
            let state: Value = serde_json::from_str(state.as_str().unwrap_or("[]")).unwrap();
            if state[0] == json!(url) && state[1] == json!("complete") {
                return session;
            }
            assert!(Instant::now() < deadline, "{url} never loaded: {state}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The page's two fields, read from its main world.
    async fn fields(&mut self, session: &str) -> (String, String) {
        let got = self
            .eval(
                session,
                "JSON.stringify([document.getElementById('username').value, \
                 document.getElementById('password').value])",
            )
            .await;
        let got: (String, String) = serde_json::from_str(got.as_str().unwrap()).unwrap();
        got
    }
}

/// A CDP error that only means "the page navigated under this call":
/// the messages the fill engine maps to `navigated` (`cdp/fill.rs`).
fn is_navigation_race(error: &Value) -> bool {
    let message = error["message"].as_str().unwrap_or("");
    message.contains("Cannot find context")
        || message.contains("context was destroyed")
        || message.contains("Inspected target navigated")
        || message.contains("No execution context")
}

/// REQ-ARCH-003's second client: attached to `target` on its own
/// websocket, with `Runtime`, `Log`, `Network` and `Page` enabled,
/// recording every frame it receives until [`Observer::finish`].
struct Observer {
    frames: Arc<Mutex<Vec<String>>>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Observer {
    async fn attach(browser_ws: &str, target: &str) -> Self {
        let mut cdp = Cdp::connect(browser_ws).await;
        let r = cdp
            .call(
                None,
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
            )
            .await;
        let session = r["sessionId"].as_str().unwrap().to_owned();
        for domain in ["Runtime", "Log", "Network", "Page"] {
            cdp.call(Some(&session), &format!("{domain}.enable"), json!({}))
                .await;
        }
        let frames = Arc::new(Mutex::new(std::mem::take(&mut cdp.transcript)));
        let (stop, mut stopped) = tokio::sync::oneshot::channel::<()>();
        let sink = frames.clone();
        let mut ws = cdp.ws;
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stopped => return,
                    frame = ws.next() => match frame {
                        Some(Ok(Message::Text(text))) => sink.lock().unwrap().push(text.to_string()),
                        Some(Ok(_)) => {}
                        _ => return,
                    },
                }
            }
        });
        Self { frames, stop, task }
    }

    /// Stop recording; the full transcript.
    async fn finish(self) -> Vec<String> {
        let _ = self.stop.send(());
        self.task.await.unwrap();
        std::mem::take(&mut *self.frames.lock().unwrap())
    }
}

// ------------------------------------------------------------ daemon

fn owner_op(socket: &Path, op: &OwnerOp<'_>) -> OwnerReply {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stream = loop {
        match UnixStream::connect(socket) {
            Ok(s) => break s,
            Err(e) => {
                assert!(Instant::now() < deadline, "owner socket never came up: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
        .write_all(serde_json::to_string(op).unwrap().as_bytes())
        .unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    serde_json::from_str(reply.trim()).unwrap_or_else(|_| panic!("bad owner reply: {reply}"))
}

/// kharond in export mode with agent `alpha` on `chromium`, unlocked,
/// with the agent's browser context and the item's id.
struct Running {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    addr: std::net::SocketAddr,
    socket: PathBuf,
    data: tempfile::TempDir,
    token: String,
    item_id: String,
    context: String,
}

impl Running {
    /// `policy` is extra `[policy]` TOML (empty for the defaults).
    async fn start(chromium: &Chromium, policy: &str) -> Self {
        let (token, hash) = generate("alpha");
        let token = token.expose_secret().clone();
        let data = tempfile::tempdir().unwrap();
        let toml = format!(
            r#"mode = "export"
data_dir = "{data}"

[export]
file = "{EXPORT}"

[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "{cdp}" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"

[policy]
{policy}
"#,
            data = data.path().display(),
            cdp = chromium.ws,
        );
        let cfg = Config::from_toml_str(&toml).unwrap();
        let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
            .await
            .unwrap();
        let addr = d.local_addr().unwrap();
        let socket = d.owner_socket().to_path_buf();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(d.run(async {
            let _ = stopped.await;
        }));

        let s = socket.clone();
        let reply = tokio::task::spawn_blocking(move || {
            owner_op(
                &s,
                &OwnerOp::Unlock {
                    password: EXPORT_PASSWORD,
                },
            )
        })
        .await
        .unwrap();
        assert!(reply.ok, "unlock: {reply:?}");

        let list = get(addr, "/v1/items", Some(&token)).await;
        assert_eq!(list.status, 200, "{}", list.body);
        let items: Vec<ItemMeta> = serde_json::from_str(&list.body).unwrap();
        let item_id = items
            .into_iter()
            .find(|i| i.name == ITEM_NAME)
            .unwrap_or_else(|| panic!("{ITEM_NAME} not listed: {}", list.body))
            .id;

        // The agent's browser context (REQ-ARCH-005).
        let head = format!(
            "POST /v1/context HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let ctx = raw_request(addr, head.as_bytes()).await;
        assert_eq!(ctx.status, 200, "{}", ctx.body);
        let context = serde_json::from_str::<ContextReply>(&ctx.body)
            .unwrap()
            .browser_context_id;

        Self {
            stop: Some(stop),
            server,
            addr,
            socket,
            data,
            token,
            item_id,
            context,
        }
    }

    async fn fill(&self, target: &str, origin: &str) -> FillReply {
        let body = FillBody {
            item_id: &self.item_id,
            target: FillTarget {
                cdp_target_id: target,
                expected_origin: origin,
            },
            fields: USERNAME_AND_PASSWORD,
            submit: false,
        };
        let r = post_json(
            self.addr,
            "/v1/fill",
            Some(&self.token),
            &serde_json::to_string(&body).unwrap(),
        )
        .await;
        assert_eq!(r.status, 200, "{}", r.body);
        for secret in SECRETS {
            assert!(!r.body.contains(secret), "a secret is in the fill reply");
        }
        serde_json::from_str(&r.body).unwrap()
    }

    async fn approve_once(&self, request_id: &str) {
        let socket = self.socket.clone();
        let request_id = request_id.to_owned();
        let reply = tokio::task::spawn_blocking(move || {
            owner_op(
                &socket,
                &OwnerOp::Approve {
                    request_id: &request_id,
                    kind: "once",
                },
            )
        })
        .await
        .unwrap();
        assert!(reply.ok, "approve: {reply:?}");
    }

    fn audit(&self) -> Vec<Entry> {
        std::fs::read_to_string(self.data.path().join("audit").join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Entry>(l).unwrap())
            .collect()
    }

    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
    }
}

// ------------------------------------------------------------ the tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn req_arch_003_second_cdp_client_receives_no_secret_during_a_fill() {
    let Some(bin) =
        chromium_or_skip("req_arch_003_second_cdp_client_receives_no_secret_during_a_fill")
    else {
        return;
    };
    let (port, spki) = serve_https().await;
    let chromium = launch_chromium(&bin, Some(&spki));
    let run = Running::start(&chromium, "").await;

    let url = format!("https://{HOST}:{port}/login");
    let origin = format!("https://{HOST}:{port}");
    let mut cdp = Cdp::connect(&chromium.ws).await;
    let (target, session) = cdp.open(&run.context, &url).await;
    assert_eq!(
        cdp.eval(&session, "window.isSecureContext").await,
        json!(true),
        "the HTTPS test page must be a secure context"
    );

    // The second client subscribes before the broker touches the tab.
    let observer = Observer::attach(&chromium.ws, &target).await;

    // No grant yet → pending; the owner approves once; the retry fills.
    let first = run.fill(&target, &origin).await;
    assert_eq!(first.status, "pending_approval", "{first:?}");
    run.approve_once(first.grant_request_id.as_deref().unwrap())
        .await;
    let filled = run.fill(&target, &origin).await;
    assert_eq!(filled.status, "filled", "{filled:?}");
    assert_eq!(filled.fields_filled, ["username", "password"]);

    // Let any trailing event land, then stop recording.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let transcript = observer.finish().await;

    // Positive control: the observer saw the broker's isolated world
    // being created (SPEC: expected, context creation is visible).
    let frames: Vec<Value> = transcript
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    assert!(
        frames
            .iter()
            .any(|f| f["method"] == "Runtime.executionContextCreated"
                && f["params"]["context"]["name"] == "kharon_fill"),
        "the second client never saw the broker's isolated world, so it \
         was not subscribed during the fill ({} frames)",
        frames.len()
    );

    // REQ-ARCH-003: zero secret bytes anywhere in what it received.
    let bytes = transcript.concat();
    for secret in SECRETS {
        assert!(
            !bytes.contains(secret),
            "the second CDP client received an item secret"
        );
    }

    // The fill really delivered the secret to the page, so the absence
    // above is meaningful. Read back only now, recording stopped.
    let (username, password) = cdp.fields(&session).await;
    assert_eq!(username, ITEM_USERNAME);
    assert!(
        password == SECRETS[0],
        "the page's password field does not hold the item's password"
    );

    drop(cdp);
    run.shutdown().await;
    drop(chromium);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn req_org_005_http_page_with_an_https_item_is_refused() {
    let Some(bin) = chromium_or_skip("req_org_005_http_page_with_an_https_item_is_refused") else {
        return;
    };
    let port = serve_http().await;
    let chromium = launch_chromium(&bin, None);
    let run = Running::start(&chromium, "").await;

    // Same host and path as the item's `https` URI, over plain HTTP.
    let url = format!("http://{HOST}:{port}/login");
    let origin = format!("http://{HOST}:{port}");
    let mut cdp = Cdp::connect(&chromium.ws).await;
    let (target, session) = cdp.open(&run.context, &url).await;
    assert_eq!(
        cdp.eval(&session, "window.isSecureContext").await,
        json!(false),
        "the HTTP test page must not be a secure context"
    );

    // The grant gate runs first, so with no grant the fill is pending,
    // and the owner approves it. Even with a grant, the live check
    // refuses the page before any value is sent.
    let first = run.fill(&target, &origin).await;
    assert_eq!(first.status, "pending_approval", "{first:?}");
    run.approve_once(first.grant_request_id.as_deref().unwrap())
        .await;
    let refused = run.fill(&target, &origin).await;
    assert_eq!(refused.status, "origin_mismatch", "{refused:?}");
    assert!(refused.fields_filled.is_empty(), "{refused:?}");

    // Audited as REQ-ORG-005's refusal, with the live origin.
    let audit = run.audit();
    let outcome = audit
        .iter()
        .rev()
        .find(|e| matches!(e.event, Event::Fill))
        .unwrap();
    assert_eq!(outcome.result.as_deref(), Some("origin_mismatch"));
    assert_eq!(outcome.detail_code.as_deref(), Some("insecure_context"));
    assert_eq!(outcome.live_origin.as_deref(), Some(origin.as_str()));

    assert_eq!(
        cdp.fields(&session).await,
        (String::new(), String::new()),
        "the HTTP page's fields must stay empty"
    );

    drop(cdp);
    run.shutdown().await;
    drop(chromium);
}

/// REQ-ORG-004: the item's login form framed by a relying party on
/// another site. The agent fills the frame's own target. The grant gate
/// runs first, so the owner approves each request.
async fn req_org_004(test: &str, allowlisted: bool) {
    let Some(bin) = chromium_or_skip(test) else {
        return;
    };
    let (port, spki) = serve_https().await;
    let chromium = launch_chromium(&bin, Some(&spki));
    let policy = if allowlisted {
        format!("allow_cross_origin_iframe_hosts = [\"{HOST}\"]")
    } else {
        String::new()
    };
    let run = Running::start(&chromium, &policy).await;

    let rp = format!("https://{RP_HOST}:{port}/rp");
    let login = format!("https://{HOST}:{port}/login");
    let origin = format!("https://{HOST}:{port}");
    let mut cdp = Cdp::connect(&chromium.ws).await;
    let (_top, _top_session) = cdp.open(&run.context, &rp).await;
    let frame = cdp.iframe_target(&login).await;
    let session = cdp.attach_loaded(&frame, &login).await;

    let first = run.fill(&frame, &origin).await;
    assert_eq!(first.status, "pending_approval", "{first:?}");
    run.approve_once(first.grant_request_id.as_deref().unwrap())
        .await;
    let outcome = run.fill(&frame, &origin).await;
    let (username, password) = cdp.fields(&session).await;
    if allowlisted {
        // The allowlisted IdP frame is filled. Note that the top-level
        // page (`example.org`) matches no URI of the item: the
        // allowlist admits the frame on its own origin.
        assert_eq!(outcome.status, "filled", "{outcome:?}");
        assert_eq!(outcome.fields_filled, ["username", "password"]);
        assert_eq!(username, ITEM_USERNAME);
        assert!(
            password == SECRETS[0],
            "the frame's password field does not hold the item's password"
        );
    } else {
        assert_eq!(outcome.status, "origin_mismatch", "{outcome:?}");
        assert!(outcome.fields_filled.is_empty(), "{outcome:?}");
        // Audited as a refusal on the frame's own live origin.
        let audit = run.audit();
        let last = audit
            .iter()
            .rev()
            .find(|e| matches!(e.event, Event::Fill))
            .unwrap();
        assert_eq!(last.result.as_deref(), Some("origin_mismatch"));
        assert_eq!(last.live_origin.as_deref(), Some(origin.as_str()));
        // Its own detail code (#180), in the reply and the audit.
        assert_eq!(outcome.detail.as_deref(), Some("iframe_not_allowlisted"));
        assert_eq!(last.detail_code.as_deref(), Some("iframe_not_allowlisted"));
        assert_eq!(
            (username, password),
            (String::new(), String::new()),
            "a refused frame's fields must stay empty"
        );
    }

    drop(cdp);
    run.shutdown().await;
    drop(chromium);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn req_org_004_cross_site_iframe_fill_is_refused_by_default() {
    req_org_004(
        "req_org_004_cross_site_iframe_fill_is_refused_by_default",
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn req_org_004_allowlisted_iframe_host_is_filled() {
    req_org_004("req_org_004_allowlisted_iframe_host_is_filled", true).await;
}
