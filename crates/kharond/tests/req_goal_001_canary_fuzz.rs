//! REQ-GOAL-001 (#18), fuzz leg: "A fuzzed fill run with canary secrets
//! finds 0 canary bytes in responses, broker logs, and audit log."
//!
//! The real `kharond` binary runs in export mode over the canary export
//! fixture, with stderr (its only log) captured to a file, against an
//! adversarial CDP peer. The peer records every secret value it is sent
//! (passwords, usernames, TOTP codes) and then echoes them back
//! everywhere a browser controls text: exception descriptions, protocol
//! error messages, malformed fill results, unsolicited events, page and
//! frame URLs (path, query, fragment, userinfo), loader ids, and the
//! `disposeBrowserContext` error a lock logs. It also stalls calls past
//! the fill deadline, drops connections and reports navigations.
//!
//! A seeded mix of status, list, search, context, fill and fill_totp
//! requests over HTTP and MCP (none of which carries a secret) drives
//! fills of every item, then the owner locks (teardown) and the daemon
//! shuts down. Then:
//!
//! - positive control: the peer did receive the canaries (so the scan
//!   below is not vacuous);
//! - every response body, the whole stderr log, and every file in the
//!   data dir (the audit log and its checkpoints) contain none of them.
//!
//! The seed is fixed for reproducibility; `KHARON_FUZZ_SEED` overrides
//! it and `KHARON_FUZZ_ROUNDS` the request count.

mod api_support;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api_support::{RawResponse, get, mcp_call, post_json};
use futures_util::{SinkExt, StreamExt};
use kharond::api::token::generate;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

const EXPORT_PASSWORD: &str = "kharon export fixture password 9";
const CANARY_PASSWORD: &str = "CANARY-EXPORT-PASSWORD-7f3a";
const TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";
const USERNAME: &str = "fixture@example.net";
const URL: &str = "https://example.com/login";

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

fn seed() -> u64 {
    std::env::var("KHARON_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x6b68_6172_6f6e_0001)
}

// ------------------------------------------------------------ CDP peer

/// What the adversarial peer has seen.
#[derive(Default)]
struct Peer {
    /// Every field value sent to it by a fill call.
    received: Mutex<BTreeSet<String>>,
    /// Fill calls answered so far (the first few are honest, so the
    /// positive control always has material).
    fills: AtomicUsize,
    connections: AtomicUsize,
    /// Per-peer RNG state for the adversarial choices.
    rng: AtomicU64,
}

impl Peer {
    fn roll(&self, n: u64) -> u64 {
        let mut s = self.rng.load(Ordering::SeqCst);
        let mut r = Rng(s | 1);
        let v = r.below(n);
        s = r.0;
        self.rng.store(s, Ordering::SeqCst);
        v
    }

    /// Everything it has been sent, joined: the text it echoes back.
    fn echo(&self) -> String {
        let got = self.received.lock().unwrap();
        if got.is_empty() {
            "nothing-yet".to_owned()
        } else {
            got.iter().cloned().collect::<Vec<_>>().join(" | ")
        }
    }

    /// A URL on the fill origin whose path, query, fragment and
    /// userinfo carry the echo.
    fn echo_url(&self) -> String {
        let e: String = self
            .echo()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        match self.roll(3) {
            0 => URL.to_owned(),
            1 => format!("https://example.com/login/{e}?leak={e}#{e}"),
            _ => format!("https://u:{e}@example.com/login?{e}"),
        }
    }
}

/// Collect every string in `v` (recursively) into `out`.
fn strings(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) if !s.is_empty() => {
            out.insert(s.clone());
        }
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

async fn adversarial_peer(seed: u64) -> (String, Arc<Peer>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = Arc::new(Peer {
        rng: AtomicU64::new(seed ^ 0x9e37_79b9_7f4a_7c15),
        ..Peer::default()
    });
    let p = Arc::clone(&peer);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let n = p.connections.fetch_add(1, Ordering::SeqCst) + 1;
            let p = Arc::clone(&p);
            tokio::spawn(async move {
                let Ok(mut ws) = accept_async(stream).await else {
                    return;
                };
                let ctx = format!("ctx-{n}");
                let mut frame_trees = 0u32;
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    let method = msg["method"].as_str().unwrap_or_default().to_owned();
                    let sid = msg.get("sessionId").cloned();
                    let mut reply = json!({ "id": msg["id"] });
                    let result = match method.as_str() {
                        "Target.createBrowserContext" => json!({ "browserContextId": ctx }),
                        "Target.getTargetInfo" => {
                            let target = msg["params"]["targetId"].as_str().unwrap_or_default();
                            let context = match target {
                                "t1" => ctx.clone(),
                                "t-foreign" => "ctx-someone-else".to_owned(),
                                _ => {
                                    reply["error"] = json!({
                                        "code": -32602,
                                        "message": format!("No target with given id: {}", p.echo()),
                                    });
                                    String::new()
                                }
                            };
                            json!({ "targetInfo": {
                                "targetId": target, "browserContextId": context,
                                "url": p.echo_url(), "title": p.echo(), "type": "page",
                            } })
                        }
                        "Target.attachToTarget" => json!({ "sessionId": format!("sess-{n}") }),
                        "Page.getFrameTree" => {
                            frame_trees += 1;
                            // Sometimes the loader changes between the
                            // pre- and post-fill reads (a navigation).
                            let loader = if frame_trees.is_multiple_of(2) && p.roll(4) == 0 {
                                format!("l-{}", p.echo())
                            } else {
                                "l1".to_owned()
                            };
                            json!({ "frameTree": { "frame": {
                                "id": "f1", "loaderId": loader, "url": p.echo_url(),
                            }, "childFrames": [] } })
                        }
                        "Page.createIsolatedWorld" => json!({ "executionContextId": 7 }),
                        "Runtime.callFunctionOn" => {
                            // The secrets: each field's `value` (not the
                            // kinds, selectors or origin rules beside it).
                            if let Some(fs) = msg["params"]["arguments"][1]["value"].as_array() {
                                let mut got = p.received.lock().unwrap();
                                for f in fs {
                                    strings(&f["value"], &mut got);
                                }
                            }
                            let honest = p.fills.fetch_add(1, Ordering::SeqCst) < 3;
                            let kinds: Vec<Value> = msg["params"]["arguments"][1]["value"]
                                .as_array()
                                .map(|fs| fs.iter().map(|f| json!({ "kind": f["kind"] })).collect())
                                .unwrap_or_default();
                            let e = p.echo();
                            match if honest { 0 } else { p.roll(8) } {
                                0 => json!({ "result": { "type": "object",
                                    "value": { "results": kinds } } }),
                                1 => json!({
                                    "result": { "type": "object", "description": e },
                                    "exceptionDetails": { "text": e, "exception": {
                                        "type": "object", "description": format!("Error: {e}"),
                                    } },
                                }),
                                2 => {
                                    reply["error"] = json!({ "code": -32000, "message": e });
                                    Value::Null
                                }
                                3 => json!({ "result": { "type": "string", "value": e } }),
                                4 => json!({ "result": { "type": "object", "value": {
                                    "results": [{ "kind": e, "error": e }], "echo": e,
                                } } }),
                                5 => {
                                    // Stall past the fill deadline.
                                    tokio::time::sleep(Duration::from_millis(2500)).await;
                                    json!({ "result": { "type": "object",
                                        "value": { "results": kinds } } })
                                }
                                6 => {
                                    // An event first, then drop the socket.
                                    let _ = ws
                                        .send(Message::Text(
                                            json!({ "method": "Runtime.consoleAPICalled",
                                                "params": { "type": "log",
                                                    "args": [{ "type": "string", "value": e }] } })
                                            .to_string(),
                                        ))
                                        .await;
                                    let _ = ws.close(None).await;
                                    return;
                                }
                                _ => json!({ "result": { "type": "object",
                                    "value": { "results": kinds, "typed": e } } }),
                            }
                        }
                        "Target.disposeBrowserContext" => {
                            reply["error"] = json!({
                                "code": -32000,
                                "message": format!("Failed to dispose: {}", p.echo()),
                            });
                            Value::Null
                        }
                        _ => json!({}),
                    };
                    // Unsolicited events carrying the echo, now and then.
                    if p.roll(3) == 0 {
                        let mut ev = json!({ "method": "Runtime.exceptionThrown", "params": {
                            "exceptionDetails": { "text": p.echo() } } });
                        if let Some(s) = &sid {
                            ev["sessionId"] = s.clone();
                        }
                        let _ = ws.send(Message::Text(ev.to_string())).await;
                    }
                    if reply.get("error").is_none() {
                        reply["result"] = result;
                    }
                    if let Some(s) = sid {
                        reply["sessionId"] = s;
                    }
                    if ws.send(Message::Text(reply.to_string())).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (format!("ws://{addr}/devtools/browser"), peer)
}

// ------------------------------------------------------------ daemon

struct Daemon {
    child: Child,
    socket: PathBuf,
    stderr: PathBuf,
    addr: SocketAddr,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn owner_op(socket: &Path, request: &Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream.write_all(request.to_string().as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    serde_json::from_str(reply.trim()).unwrap_or_else(|_| panic!("bad owner reply: {reply}"))
}

fn spawn(dir: &Path, cdp: &str) -> (Daemon, String) {
    let (token, hash) = generate("alpha");
    let data_dir = dir.join("data");
    let config = format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "{cdp}" }}

[policy]
fill_deadline = "2s"

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"
"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        ),
    );
    let config_path = dir.join("kharon.toml");
    std::fs::write(&config_path, config).unwrap();
    let stderr = dir.join("kharond.stderr");
    let child = Command::new(env!("CARGO_BIN_EXE_kharond"))
        .args(["--config", config_path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let addr = loop {
        let log = std::fs::read_to_string(&stderr).unwrap_or_default();
        if let Some(rest) = log.split("agent API listening on ").nth(1) {
            break rest.split_whitespace().next().unwrap().parse().unwrap();
        }
        assert!(Instant::now() < deadline, "kharond did not start: {log}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let socket = data_dir.join("owner.sock");
    while UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < deadline, "owner socket never came up");
        std::thread::sleep(Duration::from_millis(50));
    }
    let token = token.expose_secret().clone();
    (
        Daemon {
            child,
            socket,
            stderr,
            addr,
        },
        token,
    )
}

// ------------------------------------------------------------ requests

/// One fuzzed request, over HTTP or MCP.
async fn request(rng: &mut Rng, addr: SocketAddr, token: &str, items: &[String]) -> RawResponse {
    let item = match rng.below(10) {
        0 => "00000000-0000-4000-8000-000000000000".to_owned(),
        1 => "not-a-uuid".to_owned(),
        _ => rng.pick(items).clone(),
    };
    let target = *rng.pick(&["t1", "t1", "t1", "t-foreign", "t-gone"]);
    let origin = *rng.pick(&[
        "https://example.com",
        "https://example.com",
        "https://example.com",
        "https://evil.example",
        "http://example.com",
    ]);
    let kinds: &[&[&str]] = &[
        &["password"],
        &["username", "password"],
        &["username", "password", "totp"],
        &["totp"],
        &["username"],
    ];
    let fields: Vec<Value> = rng
        .pick(kinds)
        .iter()
        .map(|k| match rng.below(3) {
            0 => json!({ "kind": k, "selector": format!("#{k}") }),
            _ => json!({ "kind": k }),
        })
        .collect();
    let submit = rng.below(2) == 0;
    let target_args = json!({ "cdp_target_id": target, "expected_origin": origin });
    let fill =
        json!({ "item_id": item, "target": target_args, "fields": fields, "submit": submit });
    let totp = json!({ "item_id": item, "target": target_args, "submit": submit });
    let mcp = rng.below(2) == 0;
    match rng.below(10) {
        0 if mcp => mcp_call(addr, Some(token), "kharon_status", "{}").await,
        0 => get(addr, "/v1/status", Some(token)).await,
        1 if mcp => mcp_call(addr, Some(token), "kharon_search", r#"{"q":"example"}"#).await,
        1 => {
            get(
                addr,
                "/v1/items?q=example&origin=https://example.com",
                Some(token),
            )
            .await
        }
        2 if mcp => mcp_call(addr, Some(token), "kharon_context", "{}").await,
        2 => post_json(addr, "/v1/context", Some(token), "{}").await,
        3..=5 if mcp => mcp_call(addr, Some(token), "kharon_fill_totp", &totp.to_string()).await,
        3..=5 => post_json(addr, "/v1/fill_totp", Some(token), &totp.to_string()).await,
        _ if mcp => mcp_call(addr, Some(token), "kharon_fill", &fill.to_string()).await,
        _ => post_json(addr, "/v1/fill", Some(token), &fill.to_string()).await,
    }
}

// ------------------------------------------------------------ scan

/// The canaries: the fixture's known secrets plus everything the peer
/// was actually sent.
fn needles(peer: &Peer) -> Vec<String> {
    let mut n: BTreeSet<String> = [CANARY_PASSWORD, TOTP_SEED, EXPORT_PASSWORD, USERNAME]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    n.extend(peer.received.lock().unwrap().iter().cloned());
    n.into_iter().collect()
}

/// Whether `needle` occurs in `hay`. A TOTP code (all digits) only
/// counts as a standalone token, so timestamps and hashes in the audit
/// log cannot false-positive.
fn contains(hay: &str, needle: &str) -> bool {
    if !needle.bytes().all(|b| b.is_ascii_digit()) {
        return hay.contains(needle);
    }
    hay.match_indices(needle).any(|(i, _)| {
        let before = hay[..i].bytes().next_back();
        let after = hay[i + needle.len()..].bytes().next();
        !before.is_some_and(|b| b.is_ascii_alphanumeric())
            && !after.is_some_and(|b| b.is_ascii_alphanumeric())
    })
}

fn data_files(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        if meta.is_dir() {
            data_files(&path, out);
        } else if meta.is_file() {
            let bytes = std::fs::read(&path).unwrap();
            out.push((path, String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn req_goal_001_fuzzed_fill_run_leaks_no_canary() {
    let seed = seed();
    let rounds: usize = std::env::var("KHARON_FUZZ_ROUNDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let dir = tempfile::tempdir().unwrap();
    let (cdp, peer) = adversarial_peer(seed).await;
    let (mut daemon, token) = spawn(dir.path(), &cdp);
    let socket = daemon.socket.clone();
    let unlocked = tokio::task::spawn_blocking(move || {
        owner_op(
            &socket,
            &json!({ "op": "unlock", "password": EXPORT_PASSWORD }),
        )
    })
    .await
    .unwrap();
    assert_eq!(unlocked["ok"], json!(true), "{unlocked}");

    let mut responses: Vec<String> = Vec::new();
    let listing = get(daemon.addr, "/v1/items", Some(&token)).await;
    assert_eq!(listing.status, 200, "{}", listing.body);
    let items: Vec<String> = listing
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_owned())
        .collect();
    let example = listing
        .json()
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "Example Login")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    responses.push(listing.body);

    // Honest warm-up fills so the peer holds the password, username and
    // a TOTP code before the adversarial mix starts.
    let target = json!({ "cdp_target_id": "t1", "expected_origin": "https://example.com" });
    for (path, body) in [
        (
            "/v1/fill",
            json!({ "item_id": example, "target": target,
                "fields": [{ "kind": "username" }, { "kind": "password" }] }),
        ),
        (
            "/v1/fill_totp",
            json!({ "item_id": example, "target": target }),
        ),
    ] {
        let r = post_json(daemon.addr, path, Some(&token), &body.to_string()).await;
        assert_eq!(r.status, 200, "{path}: {}", r.body);
        responses.push(r.body.clone());
        // #20: a grantless fill is `pending_approval`. Approve the
        // request over the owner socket (per-origin, test-lived) and
        // retry the same fill so the warm-up actually fills.
        if r.json()["status"] == json!("pending_approval") {
            let grid = r.json()["grant_request_id"]
                .as_str()
                .expect("pending_approval carries a grant_request_id")
                .to_owned();
            let socket = daemon.socket.clone();
            let approved = tokio::task::spawn_blocking(move || {
                owner_op(
                    &socket,
                    &json!({ "op": "approve", "request_id": grid,
                             "kind": "per-origin", "ttl_s": 86400 }),
                )
            })
            .await
            .unwrap();
            assert_eq!(approved["ok"], json!(true), "{approved}");
            let r = post_json(daemon.addr, path, Some(&token), &body.to_string()).await;
            assert_eq!(r.status, 200, "{path}: {}", r.body);
            assert_eq!(r.json()["status"], json!("filled"), "{path}: {}", r.body);
            responses.push(r.body);
        }
    }

    let mut rng = Rng(seed | 1);
    let mut statuses = BTreeSet::new();
    for _ in 0..rounds {
        let r = request(&mut rng, daemon.addr, &token, &items).await;
        statuses.insert(r.status);
        responses.push(r.body);
    }

    // Make sure a live connection holds a context, then lock: teardown
    // disposes it, the peer refuses with an echoing error, and the
    // daemon logs that. Then stop.
    let r = post_json(daemon.addr, "/v1/context", Some(&token), "{}").await;
    assert_eq!(r.json()["status"], "ok", "{}", r.body);
    responses.push(r.body);
    let socket = daemon.socket.clone();
    let locked = tokio::task::spawn_blocking(move || owner_op(&socket, &json!({ "op": "lock" })))
        .await
        .unwrap();
    assert_eq!(locked["ok"], json!(true), "{locked}");
    let r = get(daemon.addr, "/v1/status", Some(&token)).await;
    responses.push(r.body);
    let _ = Command::new("kill")
        .args(["-TERM", &daemon.child.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "kharond did not stop on SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Positive control: the peer got real secrets (and echoed them).
    let got = peer.received.lock().unwrap().clone();
    assert!(got.contains(CANARY_PASSWORD), "peer never got the password");
    assert!(got.contains(USERNAME), "peer never got the username");
    assert!(
        got.iter()
            .any(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit())),
        "peer never got a TOTP code"
    );
    assert!(peer.connections.load(Ordering::SeqCst) >= 1);
    assert!(statuses.contains(&200), "no fill ran: {statuses:?}");

    let needles = needles(&peer);
    let log = std::fs::read_to_string(&daemon.stderr).unwrap();
    assert!(log.contains("shut down"), "daemon log incomplete: {log}");
    let mut files = Vec::new();
    data_files(&dir.path().join("data"), &mut files);
    assert!(
        files
            .iter()
            .any(|(p, t)| p.ends_with("audit.jsonl") && t.contains("fill")),
        "no audit log of the fills"
    );
    for needle in &needles {
        for (i, body) in responses.iter().enumerate() {
            assert!(
                !contains(body, needle),
                "response {i} carries a canary: {body}"
            );
        }
        assert!(
            !contains(&log, needle),
            "broker log carries a canary:\n{log}"
        );
        for (path, text) in &files {
            assert!(
                !contains(text, needle),
                "{} carries a canary",
                path.display()
            );
        }
    }
    // The teardown leg ran: the warning was logged (by code, not the
    // peer's text).
    assert!(
        log.contains("browser context failed (cdp_error)"),
        "no teardown warning: {log}"
    );
}
