//! REQ-AUD-002 off-host checkpoints (#127): the SPEC-default daemon
//! publishes signed checkpoints to the configured ntfy topic, and
//! refuses to start (fail closed) when that sink cannot be built.
//!
//! - `daemon::check` accepts an off-host config with `[approval].ntfy`
//!   (it was refused as unimplemented before #127).
//! - A running daemon anchored by an owner unlock publishes a
//!   checkpoint to a stub ntfy server on shutdown; the checkpoint
//!   parses and its Ed25519 signature verifies against the audit key.
//! - A sink that answers HTTP 500 does not count the checkpoint as
//!   delivered: the next attempt retries and delivers the head.
//! - An unreadable ntfy token file fails `daemon::start` with
//!   `audit_checkpoint_sink_setup`, not a silent local-only downgrade.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kharond::api::token::generate;
use kharond::audit::{AuditKeys, Checkpoint};
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use serde_json::json;

const PASSWORD: &str = "kharon export fixture password 9";

/// Stub ntfy server: records every request body, replies with the
/// status in `status` (mutable, so a test can flip 500 → 200).
struct StubNtfy {
    port: u16,
    bodies: Arc<Mutex<Vec<String>>>,
    status: Arc<Mutex<u16>>,
}

fn stub_ntfy(status: u16) -> StubNtfy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let status = Arc::new(Mutex::new(status));
    let bodies2 = Arc::clone(&bodies);
    let status2 = Arc::clone(&status);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let bodies3 = Arc::clone(&bodies2);
            let status3 = Arc::clone(&status2);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream);
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line.to_ascii_lowercase().starts_with("content-length:") {
                        content_length =
                            line.split(':').nth(1).unwrap().trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; content_length];
                if reader.read_exact(&mut body).is_ok() {
                    bodies3
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&body).into_owned());
                }
                let status = *status3.lock().unwrap();
                let mut stream = reader.into_inner();
                let _ = write!(stream, "HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n");
            });
        }
    });
    StubNtfy {
        port,
        bodies,
        status,
    }
}

/// Export-mode config in SPEC-default audit posture: no
/// `checkpoint_local_only`, ntfy pointing at the stub.
fn config(hash: &str, data_dir: &Path, ntfy_port: u16, extra_approval: &str) -> String {
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.assistant]
token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9222" }}

[approval]
ntfy = {{ url = "http://127.0.0.1:{ntfy_port}", topic = "kharon-audit"{extra_approval} }}

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"
"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        )
    )
}

fn owner_op(socket: &Path, request: &serde_json::Value) -> serde_json::Value {
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

#[test]
fn req_aud_002_check_accepts_offhost_ntfy_config() {
    let stub = stub_ntfy(200);
    let data = tempfile::tempdir().unwrap();
    let (_token, hash) = generate("assistant");
    let cfg = Config::from_toml_str(&config(&hash, data.path(), stub.port, "")).unwrap();
    let listen = daemon::check(&cfg).expect("off-host ntfy config must pass check");
    assert_eq!(listen.port(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn req_aud_002_daemon_publishes_signed_checkpoint_on_shutdown() {
    let stub = stub_ntfy(200);
    let data = tempfile::tempdir().unwrap();
    let (_token, hash) = generate("assistant");
    let cfg = Config::from_toml_str(&config(&hash, data.path(), stub.port, "")).unwrap();
    let daemon = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .expect("daemon must start in SPEC-default (off-host) posture");
    let socket = daemon.owner_socket().to_path_buf();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(daemon.run(async move {
        let _ = rx.await;
    }));

    // An unlock appends the audit entries the shutdown checkpoint
    // anchors (REQ-AUD-003 lock wiring).
    let reply = owner_op(&socket, &json!({"op": "unlock", "password": PASSWORD}));
    assert_eq!(reply["ok"], json!(true), "unlock reply: {reply}");

    tx.send(()).unwrap();
    run.await.unwrap().unwrap();

    let bodies = stub.bodies.lock().unwrap();
    assert_eq!(
        bodies.len(),
        1,
        "exactly one shutdown checkpoint: {bodies:?}"
    );
    let cp: Checkpoint = serde_json::from_str(&bodies[0]).unwrap();
    assert!(cp.seq >= 1, "checkpoint anchors the unlock: {cp:?}");
    let keys = AuditKeys::load_or_generate(&data.path().join("audit").join("keys")).unwrap();
    assert!(
        cp.verify_signature(&keys.verifying_key()),
        "checkpoint signature must verify against the audit key"
    );
    assert_eq!(cp.log_id, keys.log_id());
}

#[tokio::test(flavor = "multi_thread")]
async fn req_aud_002_start_fails_closed_on_unreadable_token_file() {
    let stub = stub_ntfy(200);
    let data = tempfile::tempdir().unwrap();
    let (_token, hash) = generate("assistant");
    let missing = data.path().join("no-such-ntfy-token");
    let extra = format!(", token_file = \"{}\"", missing.display());
    let cfg = Config::from_toml_str(&config(&hash, data.path(), stub.port, &extra)).unwrap();
    // --check does not touch the token file; start must fail closed.
    daemon::check(&cfg).unwrap();
    let err = match daemon::start(&cfg, Box::new(StaticHardening::all_ok())).await {
        Ok(_) => panic!("unreadable ntfy token file must refuse startup"),
        Err(e) => e,
    };
    assert_eq!(err.code(), "audit_checkpoint_sink_setup", "{err}");
}

#[test]
fn req_aud_002_sink_failure_is_retried_not_counted_delivered() {
    use kharond::audit::{AuditConfig, AuditLog, Entry, Event, NtfyCheckpointSink};
    let stub = stub_ntfy(500);
    let base = url::Url::parse(&format!("http://127.0.0.1:{}", stub.port)).unwrap();
    let sink = NtfyCheckpointSink::new(&base, "kharon-audit", None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut log = AuditLog::open(dir.path(), AuditConfig::default(), Box::new(sink)).unwrap();
    log.append(Entry::new(Event::Unlock)).unwrap();

    assert!(
        !log.checkpoint_now(),
        "a 500 from the sink must not count as delivered"
    );
    *stub.status.lock().unwrap() = 200;
    assert!(
        log.checkpoint_now(),
        "the retry must deliver the current head once the sink recovers"
    );
    {
        let bodies = stub.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 2, "one failed attempt + one delivery");
        let cp: Checkpoint = serde_json::from_str(&bodies[1]).unwrap();
        assert_eq!(cp.seq, 1);
    }
    // Nothing new to anchor: no further publish.
    assert!(!log.checkpoint_now());
    assert_eq!(stub.bodies.lock().unwrap().len(), 2);
}
