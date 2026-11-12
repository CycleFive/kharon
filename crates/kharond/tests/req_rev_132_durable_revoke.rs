//! REQ-REV-001 / REQ-RL-002 durability (issue #132): agent
//! revocation and suspension live in the audit log, not in daemon
//! memory. Startup folds the verified log (`DurableState`) and
//! rebuilds both into the rate limiter before anything is served:
//!
//! - a `token_revoke` binds to the fingerprint of the agent's
//!   configured `token_hash` written on the entry — the same token
//!   stays refused across restarts, and recovery is rotating the
//!   token (mint, replace `token_hash`, restart); there is no
//!   un-revoke op;
//! - a suspension stands until the log's latest word for the agent
//!   is the owner's `unsuspended` reset.
//!
//! Its own test binary on purpose: the daemon tests drop a daemon
//! and start another on the same audit log, and a concurrent fork
//! elsewhere in the binary could hold the log's `flock` across that
//! gap (#162, same reasoning as `req_aud_130_abandoned_on_start`).

mod api_support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use api_support::{CHEAP_FLOOR, ITEM_A, TestSession, cheap_argon, get};
use kharond::api::grant::Channel;
use kharond::api::revocation::DurableState;
use kharond::api::token::{TokenStore, generate, generate_with};
use kharond::api::{ApiError, Broker, FillOperation, Outcome, Request, parse_fill};
use kharond::audit::{AuditConfig, AuditLog, Entry, Event, NullCheckpointSink};
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::{LockController, LockPolicy, StaticHardening, SystemClock};
use kharond::origin::OriginConfig;
use serde_json::{Value, json};

const EXPORT_PASSWORD: &str = "kharon export fixture password 9";

/// A broker over a real audit log, unlocked on the fixture vault,
/// with the production (system) clock so grant TTLs run in real
/// time like the daemon's.
fn unlocked_broker(tokens: TokenStore, audit: AuditLog) -> Broker<TestSession, SystemClock> {
    let mut lock = LockController::new(
        LockPolicy::default(),
        SystemClock,
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| Ok::<_, ()>(TestSession::fixture())).unwrap();
    Broker::new(tokens, lock, Box::new(audit), OriginConfig::default())
}

/// Broker-level rebuild over one real log, through three "restarts"
/// (fresh brokers seeded from `DurableState::from_log`, exactly as
/// `daemon::start` seeds its own): a prior run's suspension is
/// restored, the owner's in-run reset is appended to the same log
/// and wins on the next rebuild, a revocation is durable, and
/// rotating the revoked agent's token lifts it.
#[tokio::test]
async fn req_rev_132_rebuild_restores_revocation_and_latest_suspension_word() {
    let dir = tempfile::tempdir().unwrap();
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();
    let log_path = audit_dir.join("audit.jsonl");

    let (alpha, alpha_hash) = generate_with(&cheap_argon(), "alpha");
    let alpha = alpha.expose_secret().clone();
    let (beta, beta_hash) = generate_with(&cheap_argon(), "beta");
    let beta = beta.expose_secret().clone();
    let tokens = || {
        TokenStore::with_floor(
            [("alpha", alpha_hash.as_str()), ("beta", beta_hash.as_str())],
            &CHEAP_FLOOR,
        )
        .unwrap()
    };
    let open_log = || {
        AuditLog::open(
            &audit_dir,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap()
    };

    // A previous run suspended alpha (the REQ-RL-002 streak entry).
    {
        let mut log = open_log();
        log.append(
            Entry::new(Event::RateLimit)
                .agent_id("alpha")
                .result("suspended")
                .detail_code("origin_mismatch_streak"),
        )
        .unwrap();
    }

    // Restart 1: the suspension is rebuilt before anything is
    // served — list and fill both hit the rate gate — then the
    // owner reset and a revocation land in the same log.
    let broker = unlocked_broker(tokens(), open_log())
        .with_durable_state(DurableState::from_log(&log_path).unwrap());
    let alpha_id = broker.authenticate(&alpha).unwrap();
    assert_eq!(
        broker.dispatch(&alpha_id, Request::List { origin: None }),
        Err(ApiError::RATE_LIMITED)
    );
    let fill = parse_fill(
        FillOperation::Fill,
        json!({
            "item_id": ITEM_A,
            "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com"},
            "fields": [{"kind": "password"}],
        })
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    match broker
        .fill(
            &alpha_id,
            fill,
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
    {
        Ok(Outcome::Fill(r)) => assert_eq!(r.status, "rate_limited"),
        other => panic!("suspended fill: {other:?}"),
    }
    broker.unsuspend_agent("alpha", Channel::Cli).unwrap();
    assert!(
        matches!(
            broker.dispatch(&alpha_id, Request::List { origin: None }),
            Ok(Outcome::Items(items)) if !items.is_empty()
        ),
        "owner reset clears the suspension in-run"
    );
    broker.revoke_agent("beta").unwrap();
    assert_eq!(broker.authenticate(&beta), Err(ApiError::INVALID_TOKEN));
    drop(broker);

    // Restart 2 on the same log: the `unsuspended` entry (later)
    // beats the earlier `suspended`; beta's revocation is durable.
    let broker = unlocked_broker(tokens(), open_log())
        .with_durable_state(DurableState::from_log(&log_path).unwrap());
    let alpha_id = broker.authenticate(&alpha).unwrap();
    assert!(
        matches!(
            broker.dispatch(&alpha_id, Request::List { origin: None }),
            Ok(Outcome::Items(_))
        ),
        "mid-log unsuspend beats the earlier suspension after rebuild"
    );
    assert_eq!(broker.authenticate(&beta), Err(ApiError::INVALID_TOKEN));
    drop(broker);

    // Restart 3 with beta's token rotated in config: the recorded
    // fingerprint no longer matches, so the revocation lifts — the
    // only recovery REQ-REV-001 offers.
    let (beta2, beta2_hash) = generate_with(&cheap_argon(), "beta");
    let beta2 = beta2.expose_secret().clone();
    let tokens = TokenStore::with_floor(
        [
            ("alpha", alpha_hash.as_str()),
            ("beta", beta2_hash.as_str()),
        ],
        &CHEAP_FLOOR,
    )
    .unwrap();
    let broker = unlocked_broker(tokens, open_log())
        .with_durable_state(DurableState::from_log(&log_path).unwrap());
    assert!(
        broker.authenticate(&beta2).is_ok(),
        "rotated token must authenticate after restart"
    );
}

fn config(hash: &str, data_dir: &Path) -> String {
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.assistant]
token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9222" }}

[api]
listen = "127.0.0.1:0"

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false
"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        )
    )
}

/// One owner-socket op (one JSON object per line, one reply line) —
/// the same seam the `kharon` CLI drives.
fn owner_op(socket: &Path, request: &Value) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let mut stream = loop {
        match UnixStream::connect(socket) {
            Ok(s) => break s,
            Err(e) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "owner socket never came up: {e}"
                );
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

struct Running {
    addr: std::net::SocketAddr,
    socket: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn serve(cfg: &Config) -> Running {
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
        addr,
        socket,
        stop: Some(stop),
        server,
    }
}

impl Running {
    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
    }
}

/// Daemon level, REQ-REV-001: revoke through the owner socket,
/// restart the daemon on the same data dir — the same token is
/// still refused. Rotate the token in config and restart — the
/// agent is back. That rotation is the documented recovery; no
/// restart alone clears a revocation any more.
#[tokio::test(flavor = "multi_thread")]
async fn req_rev_132_revocation_survives_restart_until_token_rotated() {
    let (token, hash) = generate("assistant");
    let token = token.expose_secret().clone();
    let data = tempfile::tempdir().unwrap();
    let cfg = Config::from_toml_str(&config(&hash, data.path())).unwrap();

    let run = serve(&cfg).await;
    let reply = owner_op(
        &run.socket,
        &json!({"op": "unlock", "password": EXPORT_PASSWORD}),
    );
    assert_eq!(reply["ok"], json!(true), "unlock reply: {reply}");
    let res = get(run.addr, "/v1/status", Some(&token)).await;
    assert_eq!(res.status, 200, "{}", res.body);
    assert!(res.body.contains("\"locked\":false"), "{}", res.body);
    let reply = owner_op(
        &run.socket,
        &json!({"op": "revoke_agent", "agent_id": "assistant"}),
    );
    assert_eq!(reply["ok"], json!(true), "revoke reply: {reply}");
    let res = get(run.addr, "/v1/status", Some(&token)).await;
    assert_eq!(res.status, 401, "revoked in-run: {}", res.body);
    run.shutdown().await;

    // Restart with the same config: still refused.
    let run = serve(&cfg).await;
    let res = get(run.addr, "/v1/status", Some(&token)).await;
    assert_eq!(res.status, 401, "revoked after restart: {}", res.body);
    run.shutdown().await;

    // Rotate the token (new mint, new hash in config) and restart:
    // accepted again.
    let (token2, hash2) = generate("assistant");
    let token2 = token2.expose_secret().clone();
    let cfg = Config::from_toml_str(&config(&hash2, data.path())).unwrap();
    let run = serve(&cfg).await;
    let res = get(run.addr, "/v1/status", Some(&token2)).await;
    assert_eq!(res.status, 200, "rotated token: {}", res.body);
    run.shutdown().await;
}

/// Daemon level, REQ-RL-002: a suspension recorded in the log
/// survives a restart (the token still authenticates; the rate
/// gate refuses), and only the owner's reset — itself a log entry
/// — clears it, durably.
#[tokio::test(flavor = "multi_thread")]
async fn req_rev_132_suspension_survives_restart_until_owner_reset() {
    let (token, hash) = generate("assistant");
    let token = token.expose_secret().clone();
    let data = tempfile::tempdir().unwrap();
    let audit_dir = data.path().join("audit");
    let cfg = Config::from_toml_str(&config(&hash, data.path())).unwrap();

    // A first start creates the log and its keys; the suspension
    // lands in it the way a mismatch streak would have written it.
    drop(
        daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
            .await
            .unwrap(),
    );
    {
        let mut log = AuditLog::open(
            &audit_dir,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        log.append(
            Entry::new(Event::RateLimit)
                .agent_id("assistant")
                .result("suspended")
                .detail_code("origin_mismatch_streak"),
        )
        .unwrap();
    }

    // Restart: status still answers (suspension is not revocation)
    // but the rate gate refuses the list; the owner resets it.
    let run = serve(&cfg).await;
    let res = get(run.addr, "/v1/status", Some(&token)).await;
    assert_eq!(res.status, 200, "{}", res.body);
    let res = get(run.addr, "/v1/items", Some(&token)).await;
    assert_eq!(res.status, 429, "suspended after restart: {}", res.body);
    let reply = owner_op(
        &run.socket,
        &json!({"op": "unsuspend", "agent_id": "assistant"}),
    );
    assert_eq!(reply["ok"], json!(true), "unsuspend reply: {reply}");
    run.shutdown().await;

    // Restart again: the reset is the log's latest word, so the
    // suspension stays cleared.
    let run = serve(&cfg).await;
    let reply = owner_op(
        &run.socket,
        &json!({"op": "unlock", "password": EXPORT_PASSWORD}),
    );
    assert_eq!(reply["ok"], json!(true), "unlock reply: {reply}");
    let res = get(run.addr, "/v1/items", Some(&token)).await;
    assert_eq!(res.status, 200, "unsuspended after restart: {}", res.body);
    run.shutdown().await;
}
