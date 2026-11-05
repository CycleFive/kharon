//! REQ-CRY-009 daemon-level live E2E (issue #9): the real `kharond`
//! binary, `mode = "sync"` against the live Vaultwarden 1.33 fixture
//! (`fixture.yml`), unlocked once through the owner socket. Items are
//! added, renamed and deleted the way the web vault does it
//! (`mutate.py`, official API endpoints, so Vaultwarden emits its
//! notifications-hub pushes); the agent API's `list`
//! (`GET /v1/items`) must reflect each change within 10 s, and the
//! process must be the same one throughout (pid and `/proc` start
//! time unchanged, still unlocked: no restart, no re-unlock).
//!
//! The 5-minute poll floor is covered without a live server by
//! `req_cry_008_009_live_sync` (`req_cry_009_poll_loop_*`,
//! `req_cry_009_interval_capped_*`).

mod api_support;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use api_support::{assert_no_canary, get, manifest};
use kharond::api::token::generate;
use kharond::sync::{ApiKey, SyncClient, TlsTrust};
use serde_json::{Value, json};
use url::Url;

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);
/// "Changes land within ~10 s" with push (REQ-CRY-009 AC).
const PUSH_DEADLINE: Duration = Duration::from_secs(10);

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set (fixture.yml)"))
}

/// The dedicated org and its collection, as an operator would read
/// them off the web vault.
async fn fixture_scope(base: &Url, email: &str, ca: &Path, api_key: &Path) -> (String, String) {
    let trust = TlsTrust {
        extra_ca_pem: Some(std::fs::read(ca).unwrap()),
    };
    let key = ApiKey::from_file(api_key).unwrap();
    let mut c = SyncClient::new(base, email, key, &trust).unwrap();
    let raw = c.sync().await.unwrap();
    let orgs = raw.profile.organizations.as_ref().unwrap();
    assert_eq!(orgs.len(), 1, "run before the fixture is widened");
    let coll = raw.collections.as_ref().unwrap()[0].id.clone();
    (orgs[0].id.clone(), coll)
}

/// The spawned binary; killed on drop. Its stderr is forwarded to
/// the test's and scanned for the lines the test waits on.
struct DaemonChild {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DaemonChild {
    fn spawn(config: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kharond"))
            .args(["--config", config.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { return };
                eprintln!("{line}");
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

    /// Wait for a stderr line containing `needle`; the line.
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

    /// pid and `/proc/<pid>/stat` start time (field 22): together
    /// they identify the process even across pid reuse.
    fn identity(&mut self) -> (u32, u64) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "kharond exited; saw {:?}",
            self.seen
        );
        let pid = self.child.id();
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let after_comm = &stat[stat.rfind(')').unwrap() + 2..];
        let start = after_comm.split(' ').nth(19).unwrap().parse().unwrap();
        (pid, start)
    }
}

fn owner_op(socket: &Path, request: &Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
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

async fn mutate(args: &[&str]) -> String {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let out = tokio::task::spawn_blocking(move || {
        Command::new("python3")
            .arg(format!("{FIXTURE_DIR}/mutate.py"))
            .args(&args)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "mutate.py failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    v["id"].as_str().unwrap().to_owned()
}

async fn list(addr: std::net::SocketAddr, token: &str) -> BTreeMap<String, String> {
    let r = get(addr, "/v1/items", Some(token)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_no_canary(&r.body);
    r.json()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["id"].as_str().unwrap().to_owned(),
                i["name"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// Poll `list` until `want` holds, measured from `since` (just
/// before the change was made); fails past 10 s.
async fn until_listed(
    addr: std::net::SocketAddr,
    token: &str,
    what: &str,
    since: Instant,
    want: impl Fn(&BTreeMap<String, String>) -> bool,
) -> Duration {
    loop {
        let l = list(addr, token).await;
        if want(&l) {
            return since.elapsed();
        }
        assert!(
            since.elapsed() < PUSH_DEADLINE,
            "{what}: list did not reflect the change within 10 s: {l:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the live Vaultwarden fixture (fixture.yml)"]
async fn req_cry_009_daemon_live_list_reflects_add_edit_delete_pid_unchanged() {
    let base = Url::parse(&env("KHARON_FIXTURE_BASE_URL")).unwrap();
    let ca = PathBuf::from(env("KHARON_FIXTURE_CA_CERT"));
    let m = manifest();
    let email = m["account"]["email"].as_str().unwrap().to_owned();
    let master = m["account"]["password"].as_str().unwrap().to_owned();

    let data = tempfile::tempdir().unwrap();
    let api_key = data.path().join("api-key.json");
    std::fs::copy(env("KHARON_FIXTURE_API_KEY_JSON"), &api_key).unwrap();
    std::fs::set_permissions(&api_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (org, coll) = fixture_scope(&base, &email, &ca, &api_key).await;
    let daemon_data = data.path().join("kharond");
    std::fs::create_dir(&daemon_data).unwrap();
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    let config = data.path().join("kharond.toml");
    std::fs::write(
        &config,
        format!(
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
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}

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
        ),
    )
    .unwrap();

    let mut d = DaemonChild::spawn(&config);
    let line = d.wait_line("agent API listening on", Duration::from_secs(30));
    let addr: std::net::SocketAddr = line
        .split("listening on ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let socket = daemon_data.join("owner.sock");
    d.wait_line("owner socket", Duration::from_secs(5));
    let reply = owner(&socket, json!({"op": "unlock", "password": master})).await;
    assert_eq!(reply["ok"], json!(true), "unlock: {reply}");
    let started = d.identity();

    // Push is up (Vaultwarden 1.33 serves /notifications/hub over the
    // fixture's TLS port), so the 5-minute poll cannot explain the
    // timings below.
    d.wait_line("notifications hub connected", PUSH_DEADLINE);
    let before = list(addr, &token).await;
    assert!(!before.is_empty());

    let suffix = std::process::id();
    let name = format!("kharon-daemon-live-{suffix}");
    let renamed = format!("{name}-renamed");

    let t = Instant::now();
    let id = mutate(&["add", "--name", &name]).await;
    let took = until_listed(addr, &token, "add", t, |l| l.get(&id) == Some(&name)).await;
    eprintln!("add reflected in {took:?}");

    let t = Instant::now();
    mutate(&["edit", "--id", &id, "--name", &renamed]).await;
    let took = until_listed(addr, &token, "edit", t, |l| l.get(&id) == Some(&renamed)).await;
    eprintln!("edit reflected in {took:?}");

    let t = Instant::now();
    mutate(&["delete", "--id", &id]).await;
    let took = until_listed(addr, &token, "delete", t, |l| !l.contains_key(&id)).await;
    eprintln!("delete reflected in {took:?}");
    assert_eq!(list(addr, &token).await, before);

    // Same process, same unlock throughout.
    assert_eq!(d.identity(), started, "kharond was restarted");
    assert_eq!(
        owner(&socket, json!({"op": "status"})).await["locked"],
        json!(false)
    );
    let audit = std::fs::read_to_string(daemon_data.join("audit").join("audit.jsonl")).unwrap();
    assert_no_canary(&audit);
    let events: Vec<String> = audit
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["event"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        events.iter().filter(|e| *e == "unlock").count(),
        1,
        "{events:?}"
    );
    assert!(!events.iter().any(|e| e == "lock"), "{events:?}");
}
