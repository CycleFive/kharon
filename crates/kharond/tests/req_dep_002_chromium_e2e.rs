//! REQ-DEP-002, the browser half (issue #10): the seeded Vaultwarden
//! fixture fills a test page through headless Chromium.
//!
//! The harness half (compose up, seed, `bw` oracle, live decrypt) is
//! #44; this test runs after it in `fixture.yml`, against the same
//! seeded server:
//!
//! 1. A static login page is served over HTTPS on loopback under the
//!    seeded items' hosts (`login.example.com`, `app.example.com`).
//!    Chromium resolves both to `127.0.0.1` (`--host-resolver-rules`)
//!    and trusts the page's throwaway certificate by its SPKI hash
//!    only (`--ignore-certificate-errors-spki-list`), so the page is
//!    a real secure context without touching any trust store.
//! 2. `daemon::start` assembles kharond exactly as the binary does,
//!    in `mode = "sync"` against the fixture (API-key login, scoped
//!    sync), with agent `alpha`'s `cdp` endpoint on that Chromium.
//!    It is unlocked through the owner socket with the fixture
//!    account's master password.
//! 3. The agent asks for its browser context (`POST /v1/context`,
//!    REQ-ARCH-005), opens a tab in it, and fills each seeded item
//!    through `POST /v1/fill` (the second with `submit: true`).
//!
//! Asserted: the page's fields hold the seeded username and password
//! (read back from the page's main world over a second CDP client);
//! the submit fired exactly once and only for the `submit: true` fill
//! (REQ-API-008); no API reply carries a secret (REQ-GOAL-001); and
//! the on-disk audit log has one `fill_dispatch` → `fill` pair per
//! fill with the live origin and no secret in it (REQ-AUD-003†).
//!
//! Ignored by default: it needs the live fixture plus a Chromium
//! binary. `fixture.yml` runs it with
//!
//! - `KHARON_FIXTURE_BASE_URL`, `KHARON_FIXTURE_CA_CERT`,
//!   `KHARON_FIXTURE_API_KEY_JSON` — as for the other live tests;
//! - `KHARON_FIXTURE_CHROMIUM` — path to a headless-capable Chromium
//!   (the job pins `chrome-headless-shell` by image digest).
//!
//! The Chromium flags below are for this throwaway test browser only;
//! they are not the agent-host launch profile (REQ-DEP-005, #24).

mod api_support;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use api_support::{assert_no_canary, get, post_json, raw_request};
use base64ct::{Base64, Encoding};
use futures_util::{SinkExt, StreamExt};
use kharond::api::token::generate;
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use kharond::sync::{ApiKey, SyncClient, TlsTrust};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use url::Url;

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);

/// The test login page. Field ids are recorded on `input`, submits are
/// counted and then cancelled; nothing on the page reads a value.
const PAGE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>kharon REQ-DEP-002 test login</title></head>
<body>
<form id="login" action="/submitted" method="post">
  <input id="username" name="username" type="email" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
<script>
  window.__inputs = [];
  window.__submits = 0;
  document.addEventListener("input", (e) => window.__inputs.push(e.target.id));
  document.getElementById("login").addEventListener("submit", (e) => {
    e.preventDefault();
    window.__submits += 1;
  });
</script>
</body></html>
"#;

fn manifest() -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURE_DIR}/fixture.json")).unwrap())
        .unwrap()
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set (see fixture.yml)"))
}

// ------------------------------------------------------------ test page

/// The HTTPS test page on an ephemeral loopback port, with a throwaway
/// certificate for `hosts`. Returns the port and the certificate's
/// SPKI SHA-256 (base64), which is all Chromium is told to trust.
async fn serve_page(hosts: &[&str]) -> (u16, String) {
    let ck =
        rcgen::generate_simple_self_signed(hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>())
            .unwrap();
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
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
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
                } else {
                    ("200 OK", PAGE)
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
    (port, spki)
}

// ------------------------------------------------------------ Chromium

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

fn launch_chromium(bin: &str, hosts: &[&str], spki: &str) -> Chromium {
    let profile = tempfile::tempdir().unwrap();
    let rules = hosts
        .iter()
        .map(|h| format!("MAP {h} 127.0.0.1"))
        .collect::<Vec<_>>()
        .join(",");
    let child = Command::new(bin)
        .args([
            "--headless",
            // CI runners (Ubuntu 24.04) restrict unprivileged user
            // namespaces, which the sandbox needs; this browser only
            // ever loads the loopback test page.
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--password-store=basic",
            // Straight to loopback, whatever proxy the environment sets.
            "--no-proxy-server",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg(format!("--host-resolver-rules={rules}"))
        // Trusts exactly the test page's key (needs --user-data-dir).
        .arg(format!("--ignore-certificate-errors-spki-list={spki}"))
        .arg("about:blank")
        // headless-shell takes proxy settings from the environment
        // even with --no-proxy-server; the page is on loopback.
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
        .unwrap_or_else(|e| panic!("cannot launch Chromium at {bin}: {e}"));
    // With port 0, Chromium writes the chosen port and the browser
    // target's path to <profile>/DevToolsActivePort.
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
        std::thread::sleep(Duration::from_millis(100));
    };
    Chromium {
        child,
        ws,
        _profile: profile,
    }
}

/// The test's own CDP client (flat sessions): opens tabs and reads the
/// page back. It enables no domain, so it receives only replies and
/// the attach event.
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
                .unwrap()
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

    /// Open `url` in a new tab in `context`; returns (target, session)
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
        let r = self
            .call(
                None,
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
            )
            .await;
        let session = r["sessionId"].as_str().unwrap().to_owned();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let state = self
                .eval(
                    &session,
                    "JSON.stringify([location.href, document.readyState, window.isSecureContext, \
                     (document.body ? document.body.innerText : '').slice(0, 200)])",
                )
                .await;
            let state: Value = serde_json::from_str(state.as_str().unwrap_or("[]")).unwrap();
            if state[0] == json!(url) && state[1] == json!("complete") {
                assert_eq!(state[2], json!(true), "test page must be a secure context");
                break;
            }
            assert!(Instant::now() < deadline, "{url} never loaded: {state}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        (target, session)
    }
}

// ------------------------------------------------------------ daemon

/// One owner-socket round trip (blocking; connect retries while the
/// daemon starts). A sync-mode unlock does prelogin, the KDF and a
/// full sync, so the read timeout is generous.
fn owner_op(socket: &Path, request: &Value) -> Value {
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
        .set_read_timeout(Some(Duration::from_secs(180)))
        .unwrap();
    stream.write_all(request.to_string().as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    serde_json::from_str(reply.trim()).unwrap_or_else(|_| panic!("bad owner reply: {reply}"))
}

/// The fixture's dedicated org and collection, discovered from a raw
/// sync the way the live REQ-CRY-005 test does.
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

struct Daemon {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    addr: std::net::SocketAddr,
    socket: PathBuf,
}

// ------------------------------------------------------------ the test

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the live Vaultwarden fixture and Chromium (fixture.yml)"]
async fn req_dep_002_seeded_fixture_fills_test_page_through_headless_chromium() {
    let base = Url::parse(&env("KHARON_FIXTURE_BASE_URL")).unwrap();
    let ca = PathBuf::from(env("KHARON_FIXTURE_CA_CERT"));
    let chromium_bin = env("KHARON_FIXTURE_CHROMIUM");
    let m = manifest();
    let email = m["account"]["email"].as_str().unwrap().to_owned();
    let master = m["account"]["password"].as_str().unwrap().to_owned();

    // The API key file, as an operator would keep it (REQ-DEP-008:
    // owned by kharond's uid, not group/world-readable).
    let data = tempfile::tempdir().unwrap();
    let api_key = data.path().join("api-key.json");
    std::fs::copy(env("KHARON_FIXTURE_API_KEY_JSON"), &api_key).unwrap();
    std::fs::set_permissions(&api_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (org, coll) = fixture_scope(&base, &email, &ca, &api_key).await;

    // Test page + Chromium, under every seeded item's host.
    let items: Vec<Value> = m["items"].as_array().unwrap().clone();
    let urls: Vec<Url> = items
        .iter()
        .map(|i| Url::parse(i["uri"].as_str().unwrap()).unwrap())
        .collect();
    let hosts: Vec<&str> = urls.iter().map(|u| u.host_str().unwrap()).collect();
    let (port, spki) = serve_page(&hosts).await;
    let chromium = launch_chromium(&chromium_bin, &hosts, &spki);

    // kharond, sync mode, against the fixture; agent alpha on Chromium.
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    let daemon_data = data.path().join("kharond");
    std::fs::create_dir(&daemon_data).unwrap();
    let toml = format!(
        r#"mode = "sync"
data_dir = "{data_dir}"

[bitwarden]
server = "{base}"
email = "{email}"
api_key_file = "{api_key}"
organization_id = "{org}"
collection_ids = ["{coll}"]
ca_file = "{ca}"

[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "{cdp}" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"
"#,
        data_dir = daemon_data.display(),
        api_key = api_key.display(),
        ca = ca.display(),
        cdp = chromium.ws,
    );
    let cfg = Config::from_toml_str(&toml).unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let mut run = Daemon {
        addr: d.local_addr().unwrap(),
        socket: d.owner_socket().to_path_buf(),
        stop: Some(stop),
        server: tokio::spawn(d.run(async {
            let _ = stopped.await;
        })),
    };

    // Unlock through the owner socket with the account master password.
    let socket = run.socket.clone();
    let unlock = json!({"op": "unlock", "password": master});
    let reply = tokio::task::spawn_blocking(move || owner_op(&socket, &unlock))
        .await
        .unwrap();
    assert_eq!(reply["ok"], json!(true), "unlock: {reply}");

    // The seeded items, by name, from the agent API (metadata only).
    let list = get(run.addr, "/v1/items", Some(&token)).await;
    assert_eq!(list.status, 200, "{}", list.body);
    assert_no_canary(&list.body);
    let listed = list.json();
    let id_of = |name: &str| -> String {
        listed
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == json!(name))
            .unwrap_or_else(|| panic!("{name} not listed: {listed}"))["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    // The agent's browser context (REQ-ARCH-005).
    let head = format!(
        "POST /v1/context HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let ctx = raw_request(run.addr, head.as_bytes()).await;
    assert_eq!(ctx.status, 200, "{}", ctx.body);
    let context = ctx.json()["browser_context_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no browser_context_id: {}", ctx.body))
        .to_owned();

    let mut cdp = Cdp::connect(&chromium.ws).await;
    let mut request_ids = Vec::new();
    for (n, (item, url)) in items.iter().zip(&urls).enumerate() {
        // Same host and path as the seeded URI, on the test port.
        let mut page = url.clone();
        page.set_port(Some(port)).unwrap();
        let origin = page.origin().ascii_serialization();
        let (target, session) = cdp.open(&context, page.as_str()).await;

        // The second fill also submits (REQ-API-008).
        let submit = n == 1;
        let body = json!({
            "item_id": id_of(item["name"].as_str().unwrap()),
            "target": {"cdp_target_id": target, "expected_origin": origin},
            "fields": [{"kind": "username"}, {"kind": "password"}],
            "submit": submit,
        });
        let r = post_json(run.addr, "/v1/fill", Some(&token), &body.to_string()).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_no_canary(&r.body);
        let res = r.json();
        assert_eq!(res["status"], json!("filled"), "{}: {res}", item["name"]);
        assert_eq!(res["fields_filled"], json!(["username", "password"]));

        // The page got the seeded credential.
        let got = cdp
            .eval(
                &session,
                "JSON.stringify([document.getElementById('username').value, \
                 document.getElementById('password').value, window.__inputs, window.__submits])",
            )
            .await;
        let got: Value = serde_json::from_str(got.as_str().unwrap()).unwrap();
        assert!(
            got[0] == item["username"] && got[1] == item["password"],
            "{}: page fields do not hold the seeded credential",
            item["name"]
        );
        for id in ["username", "password"] {
            assert!(
                got[2].as_array().unwrap().contains(&json!(id)),
                "no input event on #{id}"
            );
        }
        assert_eq!(got[3], json!(if submit { 1 } else { 0 }), "submit count");

        // The audit pair for this fill, from the on-disk log.
        let audit = std::fs::read_to_string(daemon_data.join("audit").join("audit.jsonl")).unwrap();
        assert_no_canary(&audit);
        let entries: Vec<Value> = audit
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let dispatch: Vec<&Value> = entries
            .iter()
            .filter(|e| e["event"] == json!("fill_dispatch"))
            .filter(|e| !request_ids.contains(&e["request_id"]))
            .collect();
        assert_eq!(dispatch.len(), 1, "one new fill_dispatch: {audit}");
        let rid = dispatch[0]["request_id"].clone();
        assert!(rid.is_string(), "{}", dispatch[0]);
        assert_eq!(dispatch[0]["origin"], json!(origin));
        assert_eq!(dispatch[0]["field_count"], json!(2));
        let outcome: Vec<&Value> = entries
            .iter()
            .filter(|e| e["request_id"] == rid && e["event"] != json!("fill_dispatch"))
            .collect();
        assert_eq!(outcome.len(), 1, "exactly one outcome: {audit}");
        assert_eq!(outcome[0]["event"], json!("fill"), "{}", outcome[0]);
        assert_eq!(outcome[0]["live_origin"], json!(origin), "{}", outcome[0]);
        assert!(
            outcome[0]["seq"].as_u64() > dispatch[0]["seq"].as_u64(),
            "dispatch is written before the outcome"
        );
        request_ids.push(rid);
    }

    // Lock, then stop the daemon and the browser.
    let socket = run.socket.clone();
    let reply = tokio::task::spawn_blocking(move || owner_op(&socket, &json!({"op": "lock"})))
        .await
        .unwrap();
    assert_eq!(reply["ok"], json!(true), "lock: {reply}");
    run.stop.take().unwrap().send(()).unwrap();
    (&mut run.server).await.unwrap().unwrap();
    drop(cdp);
    drop(chromium);
}
