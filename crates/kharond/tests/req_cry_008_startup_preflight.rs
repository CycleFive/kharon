//! REQ-CRY-008 at daemon startup (#245). `sync::preflight` is the
//! scope check; these tests drive `daemon::start` and the `kharond`
//! binary, not the function on its own.
//!
//! 1. A reachable account that can see a second org, or a personal
//!    item, makes `daemon::start` return `ScopeTooBroad` before any
//!    listener exists. The binary's last log line is that error and
//!    names counts only.
//! 2. A dedicated-org account, and `allow_extra_orgs = true`, start
//!    and serve.
//! 3. An unreachable server at boot logs a warning and starts. When
//!    that server later comes up too broad, the first unlock refuses
//!    `scope_too_broad` (audit `owner_auth_fail` / `unlock_failed`,
//!    the #243 owner path). `scope_widened` is the mid-run lock once
//!    a session exists; `req_cry_008_daemon_second_org_while_unlocked_locks_scope_widened`
//!    covers it.

mod api_support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api_support::get;
use kharond::api::token::generate;
use kharond::config::Config;
use kharond::daemon::{self, EX_CONFIG, StartupError};
use kharond::lock::StaticHardening;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);
const CLIENT_ID: &str = "user.11111111-2222-4333-8444-555555555555";
const CLIENT_SECRET: &str = "mock-client-secret";
const OTHER_ORG: &str = "0d9f4c1e-0000-4000-8000-00000000beef";
/// Must not appear in the startup error (counts only, no names).
const ORG_NAME: &str = "second-org-name-should-not-appear";
const PERSONAL_ITEM: &str = "cccccccc-0000-4000-8000-000000000001";

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}")).unwrap())
        .unwrap()
}

fn fixture() -> (Value, String, String) {
    let s = load("sync_fixture.json");
    let org = s["profile"]["organizations"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let coll = s["collections"][0]["id"].as_str().unwrap().to_owned();
    (s, org, coll)
}

fn with_second_org(mut s: Value) -> Value {
    let key = s["profile"]["organizations"][0]["key"].clone();
    s["profile"]["organizations"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": OTHER_ORG,
            "name": ORG_NAME,
            "key": key
        }));
    s
}

fn with_personal_item(mut s: Value) -> Value {
    let mut c = s["ciphers"][0].clone();
    c["id"] = json!(PERSONAL_ITEM);
    c["organizationId"] = Value::Null;
    c["collectionIds"] = json!([]);
    s["ciphers"].as_array_mut().unwrap().push(c);
    s
}

struct Req {
    method: String,
    path: String,
    body: String,
}

async fn read_req(sock: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.parse().unwrap())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string();
    Some(Req { method, path, body })
}

fn respond(req: &Req, manifest: &Value, sync: &Value) -> (u16, String) {
    let acct = &manifest["account"];
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/identity/accounts/prelogin") => (
            200,
            json!({
                "kdf": acct["kdf"],
                "kdfIterations": acct["kdf_iterations"],
                "kdfMemory": null,
                "kdfParallelism": null
            })
            .to_string(),
        ),
        ("POST", "/identity/connect/token") => {
            if !req.body.contains(CLIENT_SECRET) {
                return (400, json!({"error": "invalid_client"}).to_string());
            }
            (
                200,
                json!({
                    "access_token": "tok",
                    "expires_in": 7200,
                    "token_type": "Bearer",
                    "scope": "api"
                })
                .to_string(),
            )
        }
        ("GET", p) if p.starts_with("/api/sync") => (200, sync.to_string()),
        _ => (404, "{}".into()),
    }
}

/// Serve the fixture's identity and sync endpoints. The sync payload
/// can be swapped after startup (the deferred-check test).
struct Mock {
    url: String,
}

async fn serve(sync: Value) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    spawn_mock(listener, Arc::new(Mutex::new(sync)));
    Mock {
        url: format!("http://{addr}"),
    }
}

/// Bind `addr` (a port that was closed at daemon startup) and serve.
async fn serve_on(addr: SocketAddr, sync: Value) -> Mock {
    let listener = TcpListener::bind(addr).await.unwrap();
    spawn_mock(listener, Arc::new(Mutex::new(sync)));
    Mock {
        url: format!("http://{addr}"),
    }
}

fn spawn_mock(listener: TcpListener, sync: Arc<Mutex<Value>>) {
    let manifest = load("fixture.json");
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let sync = Arc::clone(&sync);
            let manifest = manifest.clone();
            tokio::spawn(async move {
                while let Some(req) = read_req(&mut sock).await {
                    let payload = sync.lock().unwrap().clone();
                    let (status, body) = respond(&req, &manifest, &payload);
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
}

struct Layout {
    /// Temp dir; kept so the files stay put.
    _dir: tempfile::TempDir,
    data: PathBuf,
    api_key: PathBuf,
    token: String,
    hash: String,
    org: String,
    coll: String,
    email: String,
}

fn layout() -> Layout {
    let dir = tempfile::tempdir().unwrap();
    let api_key = dir.path().join("api-key.json");
    std::fs::write(
        &api_key,
        json!({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}).to_string(),
    )
    .unwrap();
    std::fs::set_permissions(&api_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let (token, hash) = generate("alpha");
    let (_, org, coll) = fixture();
    let email = load("fixture.json")["account"]["email"]
        .as_str()
        .unwrap()
        .to_owned();
    Layout {
        _dir: dir,
        data,
        api_key,
        token: token.expose_secret().clone(),
        hash,
        org,
        coll,
        email,
    }
}

fn config_text(lay: &Layout, server: &str, listen: &str, allow_extra_orgs: bool) -> String {
    let extra = if allow_extra_orgs {
        "allow_extra_orgs = true\n"
    } else {
        ""
    };
    format!(
        r#"mode = "sync"
data_dir = "{data}"

[bitwarden]
server = "{server}"
email = "{email}"
api_key_file = "{api_key}"
organization_id = "{org}"
collection_ids = ["{coll}"]
{extra}
[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "{listen}"
"#,
        data = lay.data.display(),
        email = lay.email,
        api_key = lay.api_key.display(),
        org = lay.org,
        coll = lay.coll,
        hash = lay.hash,
    )
}

fn config(lay: &Layout, server: &str, listen: &str, allow_extra_orgs: bool) -> Config {
    Config::from_toml_str(&config_text(lay, server, listen, allow_extra_orgs)).unwrap()
}

fn owner_sock(lay: &Layout) -> PathBuf {
    lay.data.join("owner.sock")
}

/// A port nothing is bound to, for "this listen never came up".
async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn assert_scope_too_broad(err: &StartupError, other_orgs: usize, outside_items: usize) {
    assert!(
        matches!(
            err,
            StartupError::ScopeTooBroad {
                other_orgs: o,
                outside_items: i,
            } if *o == other_orgs && *i == outside_items
        ),
        "{err:?}"
    );
    assert_eq!(err.code(), "scope_too_broad");
    assert_eq!(err.exit_code(), EX_CONFIG);
    let msg = err.to_string();
    assert!(
        msg.contains(&format!("{other_orgs} other organization")),
        "{msg}"
    );
    assert!(msg.contains(&format!("{outside_items} item")), "{msg}");
    assert!(!msg.contains(OTHER_ORG), "{msg}");
    assert!(!msg.contains(ORG_NAME), "{msg}");
    assert!(!msg.contains(PERSONAL_ITEM), "{msg}");
    assert!(!msg.contains(CLIENT_SECRET), "{msg}");
}

struct Running {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    addr: SocketAddr,
}

async fn start_serving(cfg: &Config) -> Running {
    let d = match daemon::start(cfg, Box::new(StaticHardening::all_ok())).await {
        Ok(d) => d,
        Err(e) => panic!("dedicated scope must start: {e}"),
    };
    let addr = d.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));
    Running {
        stop: Some(stop),
        server,
        addr,
    }
}

impl Running {
    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
    }
}

fn owner_op(socket: &Path, request: &Value) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match UnixStream::connect(socket) {
            Ok(s) => break s,
            Err(e) => {
                assert!(Instant::now() < deadline, "owner socket never came up: {e}");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream.write_all(request.to_string().as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    serde_json::from_str(reply.trim()).unwrap_or_else(|_| panic!("bad owner reply: {reply}"))
}

async fn owner(socket: &Path, request: Value) -> Value {
    let socket = socket.to_path_buf();
    tokio::task::spawn_blocking(move || owner_op(&socket, &request))
        .await
        .unwrap()
}

fn audit_entries(data: &Path) -> Vec<Value> {
    let path = data.join("audit/audit.jsonl");
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Spawned `kharond`. Killed on drop. Stderr is forwarded and kept.
struct Bin {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Drop for Bin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Bin {
    fn spawn(config_path: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kharond"))
            .args(["--config", config_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    fn wait_line(&mut self, needle: &str, within: Duration) -> String {
        if let Some(l) = self.seen.iter().find(|l| l.contains(needle)) {
            return l.clone();
        }
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(l) => {
                    self.seen.push(l.clone());
                    if l.contains(needle) {
                        return l;
                    }
                }
                Err(_) => panic!("kharond never logged {needle:?}; saw {:?}", self.seen),
            }
        }
    }

    /// Read until the process exits. `within` bounds a hang.
    fn wait_exit(&mut self, within: Duration) -> (Option<i32>, String) {
        let deadline = Instant::now() + within;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            match self.lines.recv_timeout(Duration::from_millis(50)) {
                Ok(l) => self.seen.push(l),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    assert!(
                        Instant::now() < deadline,
                        "kharond did not exit; saw {:?}",
                        self.seen
                    );
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // Stderr closed. The process should follow.
                    match self.child.wait() {
                        Ok(status) => break status,
                        Err(e) => {
                            panic!(
                                "kharond stderr closed and wait failed: {e}; saw {:?}",
                                self.seen
                            )
                        }
                    }
                }
            }
        };
        let drain_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.lines.recv_timeout(Duration::from_millis(50)) {
                Ok(l) => self.seen.push(l),
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() > drain_deadline {
                        break;
                    }
                }
            }
        }
        (status.code(), self.seen.join("\n"))
    }
}

fn write_config(lay: &Layout, text: &str) -> PathBuf {
    let path = lay.data.parent().unwrap().join("kharon.toml");
    std::fs::write(&path, text).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread")]
async fn req_cry_008_daemon_start_refuses_second_org_and_nothing_listens() {
    let mock = serve(with_second_org(fixture().0)).await;
    let lay = layout();
    let agent = closed_port().await;
    let cfg = config(&lay, &mock.url, &agent.to_string(), false);
    let err = match daemon::start(&cfg, Box::new(StaticHardening::all_ok())).await {
        Err(e) => e,
        Ok(_) => panic!("a second org must refuse startup"),
    };
    assert_scope_too_broad(&err, 1, 0);
    assert!(
        !owner_sock(&lay).exists(),
        "owner socket was bound before the scope refusal"
    );
    assert!(
        tokio::net::TcpStream::connect(agent).await.is_err(),
        "agent API is still listening on {agent}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn req_cry_008_daemon_start_refuses_personal_item() {
    let mock = serve(with_personal_item(fixture().0)).await;
    let lay = layout();
    let cfg = config(&lay, &mock.url, "127.0.0.1:0", false);
    let err = match daemon::start(&cfg, Box::new(StaticHardening::all_ok())).await {
        Err(e) => e,
        Ok(_) => panic!("a personal item must refuse startup"),
    };
    assert_scope_too_broad(&err, 0, 1);
    assert!(!owner_sock(&lay).exists());
}

/// Compose crash-loop: the startup error is the last log line and
/// carries the org/item counts, never an id or a name.
#[tokio::test(flavor = "multi_thread")]
async fn req_cry_008_daemon_binary_scope_too_broad_is_the_last_log_line() {
    let mock = serve(with_second_org(fixture().0)).await;
    let lay = layout();
    let text = config_text(&lay, &mock.url, "127.0.0.1:0", false);
    let path = write_config(&lay, &text);
    let mut bin = Bin::spawn(&path);
    let (code, stderr) = bin.wait_exit(Duration::from_secs(20));
    assert_eq!(code, Some(EX_CONFIG as i32), "{stderr}");
    let last = stderr.lines().rev().find(|l| !l.is_empty()).unwrap_or("");
    assert!(
        last.contains("startup error [scope_too_broad]"),
        "last line {last:?}; all:\n{stderr}"
    );
    assert!(
        last.contains("1 other organization(s) and 0 item(s)"),
        "{last}"
    );
    assert!(!stderr.contains("listening"), "{stderr}");
    assert!(!stderr.contains(OTHER_ORG), "{stderr}");
    assert!(!stderr.contains(ORG_NAME), "{stderr}");
    assert!(!stderr.contains(CLIENT_SECRET), "{stderr}");
    assert!(!owner_sock(&lay).exists());
    drop(mock);
}

#[tokio::test(flavor = "multi_thread")]
async fn req_cry_008_daemon_start_accepts_dedicated_org() {
    let (sync, _, _) = fixture();
    let mock = serve(sync).await;
    let lay = layout();
    let cfg = config(&lay, &mock.url, "127.0.0.1:0", false);
    let run = start_serving(&cfg).await;
    let r = get(run.addr, "/v1/status", Some(&lay.token)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["locked"], json!(true), "{}", r.body);
    assert!(owner_sock(&lay).exists());
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_cry_008_daemon_start_allow_extra_orgs() {
    let mock = serve(with_personal_item(with_second_org(fixture().0))).await;
    let lay = layout();
    let cfg = config(&lay, &mock.url, "127.0.0.1:0", true);
    let run = start_serving(&cfg).await;
    let r = get(run.addr, "/v1/status", Some(&lay.token)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["locked"], json!(true), "{}", r.body);
    run.shutdown().await;
}

/// Server down at boot: a loud warning, then the process listens.
#[tokio::test(flavor = "multi_thread")]
async fn req_cry_008_daemon_start_unreachable_server_warns_and_starts() {
    let lay = layout();
    let down = closed_port().await;
    let text = config_text(&lay, &format!("http://{down}"), "127.0.0.1:0", false);
    let path = write_config(&lay, &text);
    let mut bin = Bin::spawn(&path);
    let listening = bin.wait_line("agent API listening on ", Duration::from_secs(20));
    let warn_at = bin.seen.iter().position(|l| {
        l.contains("kharond: warning: REQ-CRY-008 startup scope check skipped")
            && l.contains("the Bitwarden server is unreachable")
    });
    let listen_at = bin
        .seen
        .iter()
        .position(|l| l.contains("agent API listening"));
    assert!(
        warn_at.is_some(),
        "no unreachable warning in {:?}",
        bin.seen
    );
    assert!(warn_at < listen_at, "{:?}", bin.seen);
    assert!(
        !bin.seen.iter().any(|l| l.contains(CLIENT_SECRET)),
        "{:?}",
        bin.seen
    );
    let addr: SocketAddr = listening
        .trim_end()
        .strip_prefix("kharond: agent API listening on ")
        .unwrap()
        .strip_suffix(" (locked)")
        .unwrap()
        .parse()
        .unwrap();
    let r = get(addr, "/v1/status", Some(&lay.token)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["locked"], json!(true));
}

/// The check that could not run at boot still runs before the first
/// unlock succeeds. A wrong password would be `unlock_failed` if the
/// scope check did not come first.
#[tokio::test(flavor = "multi_thread")]
async fn req_cry_008_deferred_preflight_refuses_unlock_when_server_comes_up_too_broad() {
    let lay = layout();
    let down = closed_port().await;
    let cfg = config(&lay, &format!("http://{down}"), "127.0.0.1:0", false);
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .expect("an unreachable server must not refuse startup");
    let addr = d.local_addr().unwrap();
    let socket = d.owner_socket().to_path_buf();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));

    // The port was closed during start. Bring the server up too broad.
    let _mock = serve_on(down, with_second_org(fixture().0)).await;
    let reply = owner(
        &socket,
        json!({"op": "unlock", "password": "not the password"}),
    )
    .await;
    assert_eq!(reply["ok"], json!(false), "{reply}");
    assert_eq!(reply["error"], json!("scope_too_broad"), "{reply}");
    assert_eq!(
        owner(&socket, json!({"op": "status"})).await["locked"],
        json!(true)
    );
    let items = get(addr, "/v1/items", Some(&lay.token)).await;
    assert_eq!(items.status, 423, "{}", items.body);

    let entries = audit_entries(&lay.data);
    let auth: Vec<&Value> = entries
        .iter()
        .filter(|e| e["event"] == json!("owner_auth_fail"))
        .collect();
    assert_eq!(auth.len(), 1, "{entries:?}");
    assert_eq!(auth[0]["detail_code"], json!("unlock_failed"));
    assert!(
        !entries.iter().any(|e| e["event"] == json!("unlock")),
        "a refused unlock must not install a session: {entries:?}"
    );
    assert!(
        !entries.iter().any(|e| e["event"] == json!("scope_widened")),
        "no session existed to widen: {entries:?}"
    );

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
