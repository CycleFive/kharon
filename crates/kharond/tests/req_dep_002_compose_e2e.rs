//! The compose E2E (issue #24): the compose example
//! (`deploy/compose/docker-compose.yml`) with the CI overlay
//! (`deploy/compose/e2e/compose.e2e.yml`) runs kharond from the
//! built image against the seeded Vaultwarden fixture, and fills a
//! test page through the agent host's headless Chromium.
//!
//! One shared run (`run()`, set up once per test binary) backs four
//! tests, one per acceptance criterion:
//!
//! - **REQ-DEP-002**: compose up, then a seeded item fills a test page
//!   through headless Chromium; here 10 times, each fill followed by
//!   a real form submit (a POST the page server checks).
//! - **REQ-DEP-006**: `ss -ltn` in kharond's network namespace shows
//!   only the configured wg address (10.66.0.1:8787) for kharond, and
//!   the owner API is a unix socket.
//! - **REQ-ARCH-004**: after the 10 fills, the agent-host profile's
//!   `Login Data` has 0 rows, and Chromium reports the password
//!   manager and autofill saving off by managed policy. The fills run
//!   in the agent's own browser context, which Chromium does not
//!   persist, so the policy readback is the part that would catch a
//!   misconfigured agent host; the row count guards the on-disk store.
//! - **REQ-GOAL-002**: the item's password is a 32-byte random canary
//!   (hex), and `grep -r` across the agent host's `/` (excluding
//!   `/proc`, and `/sys`, whose files hold no stored data and can
//!   block) and the browser profile finds it nowhere, ASCII or
//!   UTF-16LE, both while Chromium runs and after it shuts down.
//!
//! The run, in order:
//!
//! 1. `image.yml` has built `kharon:e2e` and the agent-host image,
//!    brought up the fixture `vaultwarden` service, and seeded it
//!    (`seed.py --live`, the same as `fixture.yml`).
//! 2. The canary item is added through `mutate.py add` (password via
//!    the environment, never argv).
//! 3. The agent host starts with the test page's certificate SPKI;
//!    its Chromium is reachable at 10.66.0.2:9222 on the wg network.
//! 4. The test writes `kharon.toml` and the API key to
//!    `deploy/compose/e2e/run/` and starts `kharon`, which binds its
//!    agent API on 10.66.0.1:8787 only. The owner unlocks with
//!    `docker exec kharon unlock` (master password on stdin).
//! 5. The agent (this test) asks for its browser context and fills.
//!
//! Ignored by default. Env: `KHARON_FIXTURE_BASE_URL`,
//! `KHARON_FIXTURE_CA_CERT`, `KHARON_FIXTURE_API_KEY_JSON` (as for
//! the other live tests). `ss` runs under `nsenter`, via `sudo -n`
//! unless the test runs as root.

mod api_support;
mod docker_support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api_support::{assert_no_canary, get, post_json, raw_request};
use base64ct::{Base64, Encoding};
use docker_support::{docker, docker_raw, wait_for_log};
use futures_util::{SinkExt, StreamExt};
use kharond::api::token::generate;
use kharond::sync::{ApiKey, SyncClient, TlsTrust};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use url::Url;

const COMPOSE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/compose");
const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);
const PROJECT: &str = "kharon-e2e";
const KHAROND: &str = "kharon-e2e-kharond";
const AGENT_HOST: &str = "kharon-e2e-agent-host";

/// Addresses on the compose `wg` network (stand-in for the tunnel).
const AGENT_API: &str = "10.66.0.1:8787";
const AGENT_HOST_CDP: &str = "10.66.0.2:9222";
/// The docker host's address on `wg`, where the test page is served.
const PAGE_ADDR: &str = "10.66.0.254";
const PAGE_HOST: &str = "canary.example.test";
const PROFILE: &str = "/home/browser/profile";

const FILLS: usize = 10;

const PAGE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>kharon compose E2E login</title></head>
<body>
<form id="login" action="/submitted" method="post">
  <input id="username" name="username" type="email" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
</body></html>
"#;

const WELCOME: &str =
    "<!doctype html><html><head><title>welcome</title></head><body>signed in</body></html>";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set (see image.yml)"))
}

fn manifest() -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURE_DIR}/fixture.json")).unwrap())
        .unwrap()
}

fn compose(args: &[&str]) -> String {
    let base = [
        "compose",
        "-f",
        &format!("{COMPOSE_DIR}/docker-compose.yml"),
        "-f",
        &format!("{COMPOSE_DIR}/e2e/compose.e2e.yml"),
        "-p",
        PROJECT,
    ]
    .map(String::from);
    let all: Vec<&str> = base
        .iter()
        .map(String::as_str)
        .chain(args.iter().copied())
        .collect();
    docker(&all)
}

fn write_public(path: &Path, contents: &[u8]) {
    std::fs::write(path, contents).unwrap();
    // Read by the containers' own uids (bind mounts keep host modes).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

// ------------------------------------------------------------ the run

/// What the shared run observed, for the per-REQ tests to assert on.
struct Run {
    /// `ss -ltnpH` in kharond's network namespace.
    ss_tcp: String,
    /// `ss -lxpH` in the same namespace.
    ss_unix: String,
    /// `chrome://prefs-internals` entries for the policy-managed prefs.
    prefs: Value,
    /// `select count(*) from logins` in the profile's `Login Data`.
    login_rows: String,
    /// Files holding the canary (ASCII, UTF-16LE): Chromium running.
    hits_running: Vec<String>,
    /// The same after Chromium shut down cleanly.
    hits_after_close: Vec<String>,
    /// Positive control: profile files holding a marker visited in the
    /// default (persistent) context.
    control_hits: Vec<String>,
}

static RUN: Mutex<Option<Result<Arc<Run>, String>>> = Mutex::new(None);

/// The shared run, set up on first use. A failed setup fails every
/// test with the same message instead of re-running compose.
fn run() -> Arc<Run> {
    let mut slot = RUN.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_none() {
        let result = std::panic::catch_unwind(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .unwrap()
                .block_on(setup())
        });
        *slot = Some(match result {
            Ok(run) => Ok(Arc::new(run)),
            Err(e) => Err(e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "setup panicked".into())),
        });
    }
    match slot.as_ref().unwrap() {
        Ok(run) => run.clone(),
        Err(msg) => panic!("compose E2E setup failed: {msg}"),
    }
}

/// 32 random bytes, hex-encoded: the REQ-GOAL-002 canary.
fn random_hex32() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Adds the canary login to the fixture collection through the web
/// vault's API (mutate.py); the password goes via the environment.
fn add_canary_item(base: &Url, ca: &Path, name: &str, canary: &str) {
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

async fn fixture_scope(base: &Url, email: &str, ca: &Path, api_key: &Path) -> (String, String) {
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
fn page_tls() -> (tokio_rustls::TlsAcceptor, String) {
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

/// Serves the test page on the wg gateway address (the docker host).
/// Returns the port and, per form POST, whether its password field
/// carried the canary (nothing else of the body is kept).
async fn serve_page(
    acceptor: tokio_rustls::TlsAcceptor,
    canary: &str,
) -> (u16, Arc<Mutex<Vec<bool>>>) {
    let listener = TcpListener::bind(format!("{PAGE_ADDR}:0"))
        .await
        .unwrap_or_else(|e| panic!("cannot bind the test page on {PAGE_ADDR}: {e}"));
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
async fn browser_ws_url() -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(Some(ws)) =
            tokio::time::timeout(Duration::from_secs(5), json_version_ws_url()).await
        {
            return ws;
        }
        assert!(
            Instant::now() < deadline,
            "agent host CDP never answered on {AGENT_HOST_CDP}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// One `GET /json/version`. Chromium keeps the connection open, so
/// the body is read up to its `Content-Length`.
async fn json_version_ws_url() -> Option<String> {
    let mut s = TcpStream::connect(AGENT_HOST_CDP).await.ok()?;
    let req = format!(
        "GET /json/version HTTP/1.1\r\nHost: {AGENT_HOST_CDP}\r\nConnection: close\r\n\r\n"
    );
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
struct Cdp {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next: u64,
}

impl Cdp {
    async fn connect(url: &str) -> Self {
        let (ws, _) = connect_async(url).await.unwrap();
        Self { ws, next: 0 }
    }

    async fn call(&mut self, session: Option<&str>, method: &str, params: Value) -> Value {
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

    async fn eval(&mut self, session: &str, expression: &str) -> Value {
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
    async fn open(&mut self, context: Option<&str>, url: &str, ready: &str) -> (String, String) {
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

    async fn wait(&mut self, session: &str, ready: &str, what: &str) {
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

/// Files on the agent host holding `needle`, as ASCII and as UTF-16LE:
/// `grep -r` across `/` (excluding `/proc` and `/sys`) and the profile.
/// The ASCII needle goes in on stdin; the UTF-16 pattern is in grep's
/// argv, which lives only under the excluded `/proc`.
fn agent_host_files_containing(needle: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let ascii = docker_raw(
        &[
            "exec",
            "-i",
            "-u",
            "0",
            "-e",
            "LC_ALL=C",
            AGENT_HOST,
            "grep",
            "-rlF",
            "-D",
            "skip",
            "--exclude-dir=proc",
            "--exclude-dir=sys",
            "-f",
            "-",
            "/",
            PROFILE,
        ],
        Some(format!("{needle}\n").as_bytes()),
    );
    let utf16: String = needle.chars().map(|c| format!("{c}\\x00")).collect();
    let wide = docker_raw(
        &[
            "exec",
            "-u",
            "0",
            "-e",
            "LC_ALL=C",
            AGENT_HOST,
            "grep",
            "-rlP",
            "-D",
            "skip",
            "--exclude-dir=proc",
            "--exclude-dir=sys",
            "-e",
            &utf16,
            "/",
            PROFILE,
        ],
        None,
    );
    for (what, out) in [("ascii", ascii), ("utf-16le", wide)] {
        let code = out.status.code();
        assert!(
            code == Some(0) || code == Some(1),
            "agent-host grep ({what}) failed ({code:?}): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        hits.extend(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|l| format!("{what}: {l}")),
        );
    }
    hits
}

/// `ss <args>` inside the network namespace of `container`.
fn ss_in(container: &str, args: &str) -> String {
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
        .expect("nsenter/ss");
    assert!(
        out.status.success(),
        "ss {args}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

async fn setup() -> Run {
    let base = Url::parse(&env("KHARON_FIXTURE_BASE_URL")).unwrap();
    let ca = PathBuf::from(env("KHARON_FIXTURE_CA_CERT"));
    let m = manifest();
    let email = m["account"]["email"].as_str().unwrap().to_owned();
    let master = m["account"]["password"].as_str().unwrap().to_owned();

    let run_dir = PathBuf::from(format!("{COMPOSE_DIR}/e2e/run"));
    let page_dir = run_dir.join("page");
    std::fs::create_dir_all(&page_dir).unwrap();

    // The canary item, then the scope (org + collection) to sync.
    let canary = random_hex32();
    // Unique per run, so a reused fixture never hands back an older
    // run's item (the name carries nothing of the canary).
    let item_name = format!(
        "kharon-e2e-canary-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    add_canary_item(&base, &ca, &item_name, &canary);
    let api_key = run_dir.join("api-key.json");
    write_public(
        &api_key,
        &std::fs::read(env("KHARON_FIXTURE_API_KEY_JSON")).unwrap(),
    );
    let (org, coll) = fixture_scope(&base, &email, &ca, &api_key).await;

    // The agent host, trusting the test page's key by SPKI; the page
    // is served once the wg network (and the gateway address) exists.
    let (acceptor, spki) = page_tls();
    write_public(&page_dir.join("page-spki"), spki.as_bytes());
    compose(&["up", "-d", "--no-build", "agent-host"]);
    let (port, submits) = serve_page(acceptor, &canary).await;
    let browser_ws = browser_ws_url().await;

    // kharond: sync mode against the fixture over the vw network,
    // agent API on the wg address, CDP to the agent host over wg.
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    let toml = format!(
        r#"mode = "sync"

[bitwarden]
server = "https://vaultwarden"
email = "{email}"
api_key_file = "/run/secrets/kharon_bw_api_key"
organization_id = "{org}"
collection_ids = ["{coll}"]
ca_file = "/etc/kharon/vault-ca.pem"

[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "{browser_ws}", via = "wireguard" }}

[audit]
checkpoint_local_only = true

[api]
listen = "{AGENT_API}"
"#
    );
    write_public(&run_dir.join("kharon.toml"), toml.as_bytes());
    compose(&["up", "-d", "--no-build", "kharon"]);
    wait_for_log(
        KHAROND,
        &format!("agent API listening on {AGENT_API} (locked)"),
        Duration::from_secs(60),
    );

    // The owner unlocks through the CLI in the container (stdin, one
    // line), as an operator would.
    let unlock = docker_raw(
        &["exec", "-i", KHAROND, "kharon", "unlock"],
        Some(format!("{master}\n").as_bytes()),
    );
    assert!(
        unlock.status.success(),
        "kharon unlock: {}{}",
        String::from_utf8_lossy(&unlock.stdout),
        String::from_utf8_lossy(&unlock.stderr)
    );

    // REQ-DEP-006: listeners in kharond's network namespace.
    let ss_tcp = ss_in(KHAROND, "-ltnpH");
    let ss_unix = ss_in(KHAROND, "-lxpH");

    // The canary item, by name, from the agent API.
    let api: std::net::SocketAddr = AGENT_API.parse().unwrap();
    let list = get(api, "/v1/items", Some(&token)).await;
    assert_eq!(list.status, 200, "{}", list.body);
    assert_no_canary(&list.body);
    assert!(!list.body.contains(&canary), "canary in /v1/items");
    let item_id = list
        .json()
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == json!(item_name))
        .unwrap_or_else(|| panic!("canary item not listed: {}", list.body))["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // The agent's browser context (REQ-ARCH-005).
    let head = format!(
        "POST /v1/context HTTP/1.1\r\nHost: {AGENT_API}\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let ctx = raw_request(api, head.as_bytes()).await;
    assert_eq!(ctx.status, 200, "{}", ctx.body);
    let context = ctx.json()["browser_context_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no browser_context_id: {}", ctx.body))
        .to_owned();

    // REQ-DEP-002 / REQ-ARCH-004: ten fills, each followed by a submit.
    let mut cdp = Cdp::connect(&browser_ws).await;
    let url = format!("https://{PAGE_HOST}:{port}/login");
    let origin = format!("https://{PAGE_HOST}:{port}");
    for n in 0..FILLS {
        let ready = format!(
            "location.href === {} && document.readyState === 'complete'",
            json!(url)
        );
        let (target, session) = cdp.open(Some(&context), &url, &ready).await;
        let secure = cdp.eval(&session, "window.isSecureContext").await;
        assert_eq!(secure, json!(true), "test page must be a secure context");
        let body = json!({
            "item_id": item_id,
            "target": {"cdp_target_id": target, "expected_origin": origin},
            "fields": [{"kind": "username"}, {"kind": "password"}],
            // REQ-API-008 / #102: submit:true on a navigating form must
            // report `filled` with fields_filled, not `navigated`.
            "submit": true,
        });
        let r = post_json(api, "/v1/fill", Some(&token), &body.to_string()).await;
        assert_eq!(r.status, 200, "fill {n}: {}", r.body);
        assert!(!r.body.contains(&canary), "canary in a fill reply");
        assert_no_canary(&r.body);
        let res = r.json();
        assert_eq!(res["status"], json!("filled"), "fill {n}: {res}");
        assert_eq!(res["fields_filled"], json!(["username", "password"]));
        // The in-page submit posted the canary (a real navigation).
        let deadline = Instant::now() + Duration::from_secs(30);
        while submits.lock().unwrap().len() < n + 1 {
            assert!(Instant::now() < deadline, "fill {n}: the form never posted");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            submits.lock().unwrap()[n],
            "fill {n}: the posted password is not the seeded canary"
        );
        cdp.wait(
            &session,
            "location.pathname === '/submitted' && document.readyState === 'complete'",
            "post-submit page",
        )
        .await;
        cdp.call(None, "Target.closeTarget", json!({"targetId": target}))
            .await;
    }
    assert_eq!(submits.lock().unwrap().len(), FILLS, "one POST per fill");

    // Let any deferred profile writes land, then look while running.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let hits_running = agent_host_files_containing(&canary);

    // REQ-ARCH-004: Chromium's own view of the policy-managed prefs.
    let (target, session) = cdp
        .open(
            None,
            "chrome://prefs-internals/",
            "document.readyState === 'complete' && document.body !== null && document.body.innerText.length > 0",
        )
        .await;
    let text = cdp.eval(&session, "document.body.innerText").await;
    let all: Value = serde_json::from_str(text.as_str().unwrap()).unwrap();
    let prefs = json!({
        "credentials_enable_service": all["credentials_enable_service"],
        "autofill.profile_enabled": all["autofill"]["profile_enabled"],
        "autofill.credit_card_enabled": all["autofill"]["credit_card_enabled"],
    });
    cdp.call(None, "Target.closeTarget", json!({"targetId": target}))
        .await;

    // Positive control for the grep: a second random 64-hex marker,
    // visited in the default (on-disk) profile so History keeps it.
    // The agent's own context is not persisted, so finding this one
    // and not the canary shows the grep can see what Chromium stores.
    let marker = random_hex32();
    let control_url = format!("https://{PAGE_HOST}:{port}/login?control={marker}");
    let ready = format!(
        "location.href === {} && document.readyState === 'complete'",
        json!(control_url)
    );
    let (target, _) = cdp.open(None, &control_url, &ready).await;
    cdp.call(None, "Target.closeTarget", json!({"targetId": target}))
        .await;

    // Clean browser shutdown flushes the profile; then look again.
    // Chromium may drop the connection before it answers; don't wait.
    cdp.next += 1;
    let close = json!({"id": cdp.next, "method": "Browser.close", "params": {}});
    let _ = cdp.ws.send(Message::Text(close.to_string())).await;
    drop(cdp);
    wait_for_log(
        AGENT_HOST,
        "agent-host: chromium exited",
        Duration::from_secs(30),
    );
    let hits_after_close = agent_host_files_containing(&canary);
    let control = docker_raw(
        &[
            "exec", "-u", "0", AGENT_HOST, "grep", "-rlF", "-D", "skip", &marker, PROFILE,
        ],
        None,
    );
    let control_hits = String::from_utf8_lossy(&control.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    let login_rows = docker(&[
        "exec",
        AGENT_HOST,
        "sqlite3",
        &format!("file:{PROFILE}/Default/Login Data?mode=ro"),
        "select count(*) from logins;",
    ])
    .trim()
    .to_owned();

    // kharond logged nothing secret; lock it.
    let logs = docker_raw(&["logs", KHAROND], None);
    for stream in [&logs.stdout, &logs.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(&canary),
            "canary in kharond's logs"
        );
    }
    let lock = docker_raw(&["exec", KHAROND, "kharon", "lock"], None);
    assert!(lock.status.success(), "kharon lock");

    Run {
        ss_tcp,
        ss_unix,
        prefs,
        login_rows,
        hits_running,
        hits_after_close,
        control_hits,
    }
}

// ------------------------------------------------------------ tests

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_dep_002_compose_up_seeded_fixture_fills_test_page_through_headless_chromium() {
    // The fills themselves (status, POSTed canary, no secret in any
    // reply) are asserted inside the run; reaching here means all
    // FILLS of them passed.
    run();
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_dep_006_ss_ltn_shows_only_the_wg_listen_address() {
    let r = run();
    eprintln!("ss -ltnp:\n{}", r.ss_tcp);
    let mut kharond = Vec::new();
    for line in r.ss_tcp.lines().filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let local = cols[3];
        if line.contains("\"kharond\"") {
            kharond.push(local.to_owned());
        } else {
            // Docker's embedded DNS resolver listens in every container
            // on a user-defined network, on 127.0.0.11 only.
            assert!(
                local.starts_with("127.0.0.11:"),
                "unexpected listener in kharond's netns: {line}"
            );
        }
    }
    assert_eq!(kharond, vec![AGENT_API.to_owned()], "{}", r.ss_tcp);
    // The owner API is the unix socket in /data, not a TCP port.
    assert!(
        r.ss_unix
            .lines()
            .any(|l| l.contains("/data/owner.sock") && l.contains("\"kharond\"")),
        "no kharond owner socket in ss -lx:\n{}",
        r.ss_unix
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_arch_004_login_data_has_0_rows_after_10_fills() {
    let r = run();
    assert_eq!(r.login_rows, "0", "Login Data rows after {FILLS} fills");
    // Saving is off by managed policy, as Chromium itself reports.
    let off = json!({"metadata": ["managed"], "value": false});
    for (pref, got) in r.prefs.as_object().unwrap() {
        assert_eq!(got, &off, "{pref}: {got}");
    }
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_goal_002_canary_not_on_agent_host_filesystem() {
    let r = run();
    assert!(
        r.hits_running.is_empty(),
        "canary on the agent host while Chromium runs: {:?}",
        r.hits_running
    );
    assert!(
        r.hits_after_close.is_empty(),
        "canary on the agent host after Chromium shut down: {:?}",
        r.hits_after_close
    );
    // The same grep does find a 64-hex marker the browser was given
    // in its persistent profile, so a clean result is not a blind grep.
    assert!(
        !r.control_hits.is_empty(),
        "control grep found nothing in the profile"
    );
}
