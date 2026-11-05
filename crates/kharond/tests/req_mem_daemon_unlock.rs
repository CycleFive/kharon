//! Daemon-level acceptance tests for the owner unlock channel
//! (issue #11) and the export-mode ACs that hang on it (issue #12):
//!
//! - REQ-EXP-003: unlock happens only through the owner socket;
//!   restart → `locked`.
//! - REQ-EXP-004 (restart level): replacing the export file does
//!   nothing until a restart; after restart + unlock the audit log
//!   holds a new `export_loaded` hash.
//! - REQ-MEM-003: `canary-scan`-feature canary scan of the real
//!   daemon's memory (read via `process_vm_readv`, since a hardened
//!   daemon's `/proc/self/mem` is not openable by its own uid) —
//!   the export password occurs 0 times after unlock, the
//!   item-secret canary 0 times after unlock and after lock, and
//!   the export-derived key (a non-UTF-8 needle, sent hex-encoded)
//!   0 times after lock (REQ-CRY-006).
//! - REQ-MEM-005: kill -9 → restart comes up `locked`; `strings`
//!   over `data_dir` finds no password or canary.
//! - REQ-EXP-001: export mode fully works inside a network
//!   namespace with no egress (loopback only).
//!
//! The in-process tests drive `daemon::start`; the canary tests
//! drive the real `kharond` binary (the scan must run against a
//! process that does not share the test harness's memory, and the
//! binary is the thing that will be deployed).

mod api_support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use api_support::get;
use kharond::api::token::generate;
use kharond::config::Config;
use kharond::daemon;
use kharond::export::ExportFile;
use kharond::lock::StaticHardening;
use serde_json::{Value, json};

const FIXTURE_A: &[u8] = include_bytes!("fixtures/export/password_protected.json");
const FIXTURE_B: &[u8] = include_bytes!("fixtures/export/password_protected_replaced.json");
const FIXTURE_ESC: &[u8] = include_bytes!("fixtures/export/password_protected_escaped.json");
const PASSWORD: &str = "kharon export fixture password 9";
/// The escaped fixture's password: contains `"` and `\`, so its
/// JSON wire form is full of escapes (see the generator).
const ESCAPED_PASSWORD: &str = "kharon \"escape\" \\ fixture 9";
const CANARY: &str = "CANARY-EXPORT-PASSWORD-7f3a";

fn fixture_path(name: &str) -> PathBuf {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/export"
    ))
    .join(name)
}

fn config_toml(hash: &str, data_dir: &Path, export_file: &Path, listen: &str) -> String {
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

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
        data_dir.display(),
        export_file.display()
    )
}

/// One owner-socket round trip (blocking), with connect retries
/// while the daemon is still starting.
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
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream.write_all(request.to_string().as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    serde_json::from_str(reply.trim()).unwrap_or_else(|_| panic!("bad owner reply: {reply}"))
}

fn owner_unlock(socket: &Path, password: &str) -> Value {
    owner_op(socket, &json!({"op": "unlock", "password": password}))
}

fn owner_status(socket: &Path) -> Value {
    owner_op(socket, &json!({"op": "status"}))
}

fn owner_scan(socket: &Path, needle: &str) -> usize {
    let reply = owner_op(socket, &json!({"op": "scan", "needle": needle}));
    // A `scan_unavailable` reply fails here, loudly: a scanner that
    // could not read must never be read as "0 hits" (item 2).
    assert_eq!(reply["ok"], json!(true), "scan reply: {reply}");
    reply["hits"].as_u64().unwrap() as usize
}

fn owner_scan_hex(socket: &Path, needle: &[u8]) -> usize {
    let reply = owner_op(
        socket,
        &json!({"op": "scan", "needle_hex": hex::encode(needle)}),
    );
    assert_eq!(reply["ok"], json!(true), "hex scan reply: {reply}");
    reply["hits"].as_u64().unwrap() as usize
}

/// Retry a positive-control scan briefly (mapping churn under
/// parallel load), then return the best count seen.
fn scan_until_hit(socket: &Path, needle: &str) -> usize {
    let mut best = 0;
    for _ in 0..10 {
        best = owner_scan(socket, needle);
        if best >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    best
}

/// The fixture's 64-byte export key, derived *independently* here
/// (PBKDF2-HMAC-SHA256 over the file's verbatim salt string, then
/// the HKDF `enc`/`mac` stretch — the REQ-EXP-001 derivation, same
/// shape as the fixture generator) so the test can scan for raw
/// key bytes without kharon-bwcrypto exposing them.
fn derive_fixture_export_key(fixture: &[u8]) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let v: Value = serde_json::from_slice(fixture).unwrap();
    let salt = v["salt"].as_str().unwrap();
    let iterations = v["kdfIterations"].as_u64().unwrap() as u32;
    let mut master = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        PASSWORD.as_bytes(),
        salt.as_bytes(),
        iterations,
        &mut master,
    );
    let hk = Hkdf::<Sha256>::from_prk(&master).unwrap();
    let mut key = vec![0u8; 64];
    hk.expand(b"enc", &mut key[..32]).unwrap();
    hk.expand(b"mac", &mut key[32..]).unwrap();
    key
}

struct Running {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    addr: std::net::SocketAddr,
    socket: PathBuf,
}

async fn start_daemon(cfg: &Config) -> Running {
    let d = daemon::start(cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let addr = d.local_addr().unwrap();
    let socket = d.owner_socket().to_path_buf();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));
    Running {
        stop: Some(stop),
        server,
        addr,
        socket,
    }
}

impl Running {
    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
    }
}

fn audit_text(data_dir: &Path) -> String {
    std::fs::read_to_string(data_dir.join("audit").join("audit.jsonl")).unwrap_or_default()
}

// ------------------------------------------------------------ REQ-EXP-003

#[tokio::test(flavor = "multi_thread")]
async fn req_exp_003_unlock_only_via_owner_socket_and_restart_boots_locked() {
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    let data = tempfile::tempdir().unwrap();
    let cfg = Config::from_toml_str(&config_toml(
        &hash,
        data.path(),
        &fixture_path("password_protected.json"),
        "127.0.0.1:0",
    ))
    .unwrap();

    let run = start_daemon(&cfg).await;
    // Boots locked: status says so on both surfaces, list is 423.
    assert_eq!(
        get(run.addr, "/v1/status", Some(&token)).await.json()["locked"],
        json!(true)
    );
    assert_eq!(get(run.addr, "/v1/items", Some(&token)).await.status, 423);
    assert_eq!(owner_status(&run.socket)["locked"], json!(true));

    // Wrong password: refused with the fixed code, still locked.
    let bad = owner_unlock(&run.socket, "kharon export fixture password 8");
    assert_eq!(bad["ok"], json!(false));
    assert_eq!(bad["error"], json!("unlock_failed"));
    assert_eq!(owner_status(&run.socket)["locked"], json!(true));

    // Right password via the owner socket: unlocked, list works,
    // and the audit gained the unlock + export_loaded entries.
    let ok = owner_unlock(&run.socket, PASSWORD);
    assert_eq!(ok["ok"], json!(true), "{ok}");
    assert_eq!(ok["locked"], json!(false));
    let items = get(run.addr, "/v1/items", Some(&token)).await;
    assert_eq!(items.status, 200, "{}", items.body);
    assert!(items.body.contains("Example Login"), "{}", items.body);
    assert!(!items.body.contains(CANARY), "no plaintext secret in list");
    let audit = audit_text(data.path());
    assert!(audit.contains("\"export_loaded\""), "{audit}");
    assert!(audit.contains("\"unlock\""), "{audit}");
    let sha = ExportFile::from_bytes(FIXTURE_A)
        .unwrap()
        .sha256_hex()
        .to_owned();
    assert!(audit.contains(&sha), "export_loaded carries the file hash");

    // Lock via the owner socket: list is 423 again.
    assert_eq!(
        owner_op(&run.socket, &json!({"op": "lock"}))["ok"],
        json!(true)
    );
    assert_eq!(owner_status(&run.socket)["locked"], json!(true));
    assert_eq!(get(run.addr, "/v1/items", Some(&token)).await.status, 423);
    run.shutdown().await;

    // Restart with the same data dir: locked again (REQ-MEM-005's
    // boot state), nothing about the unlock persisted.
    let run = start_daemon(&cfg).await;
    assert_eq!(owner_status(&run.socket)["locked"], json!(true));
    assert_eq!(get(run.addr, "/v1/items", Some(&token)).await.status, 423);
    run.shutdown().await;
}

// ------------------------------------------------------------ REQ-EXP-004

#[tokio::test(flavor = "multi_thread")]
async fn req_exp_004_restart_level_replace_file_and_new_audit_hash() {
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    let data = tempfile::tempdir().unwrap();
    let export_file = data.path().join("export.json");
    std::fs::write(&export_file, FIXTURE_A).unwrap();
    let cfg = Config::from_toml_str(&config_toml(
        &hash,
        data.path(),
        &export_file,
        "127.0.0.1:0",
    ))
    .unwrap();

    let run = start_daemon(&cfg).await;
    assert_eq!(owner_unlock(&run.socket, PASSWORD)["ok"], json!(true));
    let items = get(run.addr, "/v1/items", Some(&token)).await;
    assert!(items.body.contains("Example Login"), "{}", items.body);

    // Replace the file under the running daemon: list must not
    // change (no sync, no re-read — the startup load is the load).
    std::fs::write(&export_file, FIXTURE_B).unwrap();
    let items = get(run.addr, "/v1/items", Some(&token)).await;
    assert!(items.body.contains("Example Login"), "{}", items.body);
    assert!(!items.body.contains("Replaced Login"), "{}", items.body);
    run.shutdown().await;

    // Restart: the new file is loaded, and the audit's
    // export_loaded entries show both hashes, oldest first.
    let run = start_daemon(&cfg).await;
    assert_eq!(owner_unlock(&run.socket, PASSWORD)["ok"], json!(true));
    let items = get(run.addr, "/v1/items", Some(&token)).await;
    assert!(items.body.contains("Replaced Login"), "{}", items.body);
    assert!(!items.body.contains("Example Login"), "{}", items.body);
    run.shutdown().await;

    let audit = audit_text(data.path());
    let hashes: Vec<String> = audit
        .lines()
        .filter(|l| l.contains("\"export_loaded\""))
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["file_sha256"].as_str().unwrap().to_owned()
        })
        .collect();
    let sha_a = ExportFile::from_bytes(FIXTURE_A)
        .unwrap()
        .sha256_hex()
        .to_owned();
    let sha_b = ExportFile::from_bytes(FIXTURE_B)
        .unwrap()
        .sha256_hex()
        .to_owned();
    assert_eq!(hashes, [sha_a, sha_b]);
}

// --------------------------------------- REQ-MEM-003 / REQ-MEM-005 (binary)

struct DaemonChild {
    child: Child,
    socket: PathBuf,
}

impl Drop for DaemonChild {
    fn drop(&mut self) {
        // Never leak a daemon: it inherits this test's stdio, and a
        // leaked child would hold the harness's output pipes open.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Probe the owner socket with a short timeout (the file appears
/// at bind time, slightly before the serve loop starts accepting).
fn probe_status(socket: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    if stream.write_all(b"{\"op\":\"status\"}\n").is_err() {
        return false;
    }
    let mut reply = String::new();
    stream.read_to_string(&mut reply).is_ok() && reply.contains("\"ok\":true")
}

fn spawn_kharond(config_path: &Path, data_dir: &Path) -> DaemonChild {
    let child = Command::new(env!("CARGO_BIN_EXE_kharond"))
        .args(["--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let socket = data_dir.join("owner.sock");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !probe_status(&socket) {
        assert!(Instant::now() < deadline, "kharond did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    DaemonChild { child, socket }
}

fn write_binary_config(dir: &Path) -> (PathBuf, String) {
    write_binary_config_for(dir, "password_protected.json")
}

fn write_binary_config_for(dir: &Path, fixture: &str) -> (PathBuf, String) {
    let (token, hash) = generate("alpha");
    let data_dir = dir.join("data");
    let cfg = config_toml(&hash, &data_dir, &fixture_path(fixture), "127.0.0.1:0");
    let path = dir.join("kharon.toml");
    std::fs::write(&path, cfg).unwrap();
    (path, token.expose_secret().clone())
}

/// The canary scan runs against the real binary: the password and
/// the item secret must not be findable in the daemon's memory
/// after unlock, nor the secret after lock.
#[test]
fn req_mem_003_canary_scan_of_the_running_daemon_finds_zero_hits() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _token) = write_binary_config(dir.path());
    let mut d = spawn_kharond(&cfg, &dir.path().join("data"));

    assert_eq!(owner_status(&d.socket)["locked"], json!(true));
    assert_eq!(owner_unlock(&d.socket, PASSWORD)["ok"], json!(true));
    assert_eq!(owner_status(&d.socket)["locked"], json!(false));

    // Positive control (PR #81 review, item 3): the needle must be
    // something that lives ONLY in the daemon's heap, so a scanner
    // reading only file-backed mappings cannot pass it. The export
    // file's SHA-256 hex is held as a `String` in the daemon's
    // `ExportFile` (and in the session), computed here from the
    // fixture. Retried briefly for mapping churn under parallel
    // load; a scanner that never finds it is broken and still
    // fails here. (The zero-hit assertions below are single-shot —
    // they are the AC.)
    let sha_hex = ExportFile::from_bytes(FIXTURE_A)
        .unwrap()
        .sha256_hex()
        .to_owned();
    let control = scan_until_hit(&d.socket, &sha_hex);
    assert!(control >= 1, "heap scanner control: hits={control}");
    // The export password was zeroized after derivation.
    assert_eq!(owner_scan(&d.socket, PASSWORD), 0, "password after unlock");
    // No plaintext secret cache while unlocked (REQ-CRY-006).
    assert_eq!(owner_scan(&d.socket, CANARY), 0, "item canary after unlock");
    // Key material (item 4): the export-derived key, scanned as
    // raw bytes via the hex needle. It is dropped inside
    // `ExportFile::unlock` before the session is installed, so 0
    // is expected here too — the "≥1 while unlocked" heap-control
    // role is served by the SHA-256 hex above (the session's
    // per-unlock wrap key is random and known to no one, by
    // design: a scan op that could reveal it would be the oracle
    // item 5 forbids).
    let export_key = derive_fixture_export_key(FIXTURE_A);
    assert_eq!(
        owner_scan_hex(&d.socket, &export_key),
        0,
        "export key after unlock"
    );

    assert_eq!(
        owner_op(&d.socket, &json!({"op": "lock"}))["ok"],
        json!(true)
    );
    // The control must STILL hit after lock (the `ExportFile` is
    // daemon-lifetime), so the zeros below are measured by a
    // scanner proven live in the locked state too.
    let control = scan_until_hit(&d.socket, &sha_hex);
    assert!(control >= 1, "heap control after lock: hits={control}");
    assert_eq!(owner_scan(&d.socket, CANARY), 0, "item canary after lock");
    assert_eq!(owner_scan(&d.socket, PASSWORD), 0, "password after lock");
    // REQ-MEM-003's "after lock (keys)": the derived key is gone.
    assert_eq!(
        owner_scan_hex(&d.socket, &export_key),
        0,
        "export key after lock"
    );

    d.child.kill().unwrap();
    let _ = d.child.wait();
}

/// Item 7's canary case: an unlock whose password contains `"` and
/// `\` (so the wire JSON is escape-laden) must leave zero copies of
/// the decoded password in daemon memory — a serde escape-decoding
/// scratch copy would be caught here. The daemon hand-decodes the
/// password field, so no such copy is ever made.
#[test]
fn req_mem_003_canary_scan_with_an_escaped_password() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _token) = write_binary_config_for(dir.path(), "password_protected_escaped.json");
    let mut d = spawn_kharond(&cfg, &dir.path().join("data"));

    assert_eq!(owner_unlock(&d.socket, ESCAPED_PASSWORD)["ok"], json!(true));
    assert_eq!(owner_status(&d.socket)["locked"], json!(false));
    let sha_hex = ExportFile::from_bytes(FIXTURE_ESC)
        .unwrap()
        .sha256_hex()
        .to_owned();
    let control = scan_until_hit(&d.socket, &sha_hex);
    assert!(control >= 1, "heap scanner control: hits={control}");
    assert_eq!(
        owner_scan(&d.socket, ESCAPED_PASSWORD),
        0,
        "escaped password after unlock"
    );
    assert_eq!(owner_scan(&d.socket, CANARY), 0, "item canary after unlock");

    d.child.kill().unwrap();
    let _ = d.child.wait();
}

/// REQ-MEM-005: kill -9 leaves nothing behind — the restart boots
/// locked, and no file under `data_dir` contains a secret.
#[test]
fn req_mem_005_kill9_restart_locked_and_no_secret_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _token) = write_binary_config(dir.path());
    let data_dir = dir.path().join("data");
    let mut d = spawn_kharond(&cfg, &data_dir);
    assert_eq!(owner_unlock(&d.socket, PASSWORD)["ok"], json!(true));
    assert_eq!(owner_status(&d.socket)["locked"], json!(false));

    // kill -9 while unlocked: no shutdown path runs at all.
    d.child.kill().unwrap();
    let _ = d.child.wait();

    // strings over data_dir: neither the password nor the canary.
    let mut files = Vec::new();
    collect_files(&data_dir, &mut files);
    assert!(!files.is_empty(), "daemon wrote state under data_dir");
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        assert!(
            !contains(&bytes, PASSWORD.as_bytes()),
            "password persisted in {f:?}"
        );
        assert!(
            !contains(&bytes, CANARY.as_bytes()),
            "item canary persisted in {f:?}"
        );
    }

    // Restart (the stale owner socket must not block it): locked.
    let mut d = spawn_kharond(&cfg, &data_dir);
    assert_eq!(owner_status(&d.socket)["locked"], json!(true));
    d.child.kill().unwrap();
    let _ = d.child.wait();
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        let kind = e.file_type().unwrap();
        if kind.is_dir() {
            collect_files(&p, out);
        } else if kind.is_file() {
            // Regular files only: the stale owner socket is not
            // readable state (and a socket has no contents to leak).
            out.push(p);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------------ REQ-EXP-001

const NETNS_CHILD_ENV: &str = "KHARON_REQ_EXP_001_CHILD";
const NETNS_ADDR: &str = "127.0.0.1:18741";
/// Set (to anything) to turn the "namespaces unavailable" skip into a
/// failure. CI sets it on the privileged step (#85) so a runner change
/// can never silently re-mask REQ-EXP-001 as a pass.
const REQUIRE_NETNS_ENV: &str = "KHARON_REQUIRE_NETNS";

/// Skip loudly, or fail if `KHARON_REQUIRE_NETNS` is set.
fn netns_skip(reason: &str) {
    let msg = format!(
        "SKIPPED req_exp_001: {reason}; the no-egress AC is NOT exercised in this environment"
    );
    assert!(
        std::env::var_os(REQUIRE_NETNS_ENV).is_none(),
        "{REQUIRE_NETNS_ENV} is set but {msg}"
    );
    eprintln!("{msg}");
}

/// Inside `unshare -rn`: loopback only, no egress, no Bitwarden
/// server anywhere in the config — export mode must still unlock
/// and serve `list`.
fn netns_child() {
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let cfg = config_toml(
        &hash,
        &data_dir,
        &fixture_path("password_protected.json"),
        NETNS_ADDR,
    );
    let cfg_path = dir.path().join("kharon.toml");
    std::fs::write(&cfg_path, cfg).unwrap();
    let mut d = spawn_kharond(&cfg_path, &data_dir);
    assert_eq!(owner_unlock(&d.socket, PASSWORD)["ok"], json!(true));

    // Raw HTTP over loopback: GET /v1/items with the agent token.
    let mut stream = std::net::TcpStream::connect(NETNS_ADDR).unwrap();
    let req = format!(
        "GET /v1/items HTTP/1.1\r\nhost: {NETNS_ADDR}\r\nauthorization: Bearer {token}\r\nconnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert!(body.contains("200"), "list in netns: {body}");
    assert!(body.contains("Example Login"), "list in netns: {body}");
    d.child.kill().unwrap();
    let _ = d.child.wait();
    println!("NETNS_OK");
}

#[test]
fn req_exp_001_export_mode_works_with_no_network_egress() {
    if std::env::var_os(NETNS_CHILD_ENV).is_some() {
        netns_child();
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let script = format!(
        "ip link set lo up || {{ echo LO_UP_FAILED; exit 3; }}; exec {} req_exp_001_export_mode_works_with_no_network_egress --exact --nocapture",
        exe.display()
    );
    // Already root (the privileged CI step, #85): a plain netns is
    // enough, and a child userns would lose DAC override on files
    // owned by unmapped uids (e.g. the runner's 0750 $HOME).
    let flags = if rustix::process::geteuid().is_root() {
        "-n"
    } else {
        "-rn"
    };
    let out = match Command::new("unshare")
        .args([flags, "sh", "-c", &script])
        .env(NETNS_CHILD_ENV, "1")
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            // Skip LOUDLY (PR #81 review, item 1): the environment
            // cannot run the AC at all; that must be visible in the
            // test output, never a quiet pass or a confusing fail.
            netns_skip(&format!("cannot spawn `unshare` ({e})"));
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success()
        && (stderr.contains("Operation not permitted")
            || stdout.contains("LO_UP_FAILED")
            || stderr.contains("LO_UP_FAILED"))
    {
        // Hosted CI runners refuse unprivileged user namespaces
        // (`unshare: write failed /proc/self/uid_map: Operation
        // not permitted`), so `unshare -rn` cannot work there.
        // Skip loudly with the reason; the AC still runs wherever
        // userns is allowed (dev boxes), which is where it was
        // verified for this PR.
        let stage = if stdout.contains("LO_UP_FAILED") || stderr.contains("LO_UP_FAILED") {
            "`ip link set lo up` inside the netns"
        } else {
            "namespace creation"
        };
        netns_skip(&format!(
            "`unshare {flags}` failed at {stage} (status={}, stderr={})",
            out.status,
            stderr.trim()
        ));
        return;
    }
    assert!(
        out.status.success() && stdout.contains("NETNS_OK"),
        "netns child failed: status={} stdout={stdout} stderr={stderr}",
        out.status
    );
    eprintln!("EXERCISED req_exp_001: export mode served `list` inside a no-egress netns");
}
