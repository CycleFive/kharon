//! #249: minting an enrollment code and storing a passkey each write
//! an audit entry, with no code and no credential id in the log.
//! A failed append refuses the action. `kharon audit verify` is the
//! `audit::verify` call below, on the pubkey file the command reads.
//!
//! Its own test binary on purpose. The success case shuts a daemon
//! down and then reads that run's audit log; a concurrent fork in a
//! shared binary can hold the log's `flock` across that gap (#162,
//! same reasoning as `req_aud_130_abandoned_on_start`).

mod api_support;
mod owner_ui_support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kharond::api::approval::{ApprovalAction, TokenGone};
use kharond::api::grant::ApprovalPrompt;
use kharond::api::http::ApprovalRedeemer;
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use kharond::owner_ui::{
    AuthFailure, NoApprovals, OwnerAudit, OwnerAuditError, OwnerUi, PasskeyEnrolled, ShellView,
    StaticShell,
};
use owner_ui_support::{Http, VirtAuth, b64url, b64url_dec, http};
use serde_json::{Value as Json, json};

const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";
const ID_A: &[u8] = &[0x11; 16];
const ID_B: &[u8] = &[0x22; 16];

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/export/password_protected.json")
}

struct Running {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    ui: std::net::SocketAddr,
    origin: String,
    socket: PathBuf,
    data: tempfile::TempDir,
}

async fn start() -> Running {
    let data = tempfile::tempdir().unwrap();
    let text = format!(
        r#"mode = "export"
data_dir = "{data}"
[export]
file = "{export}"
[agents.alpha]
token_hash = "{TOKEN_HASH}"
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}
[audit]
checkpoint_local_only = true
[memory]
require_mlock = false
[api]
listen = "127.0.0.1:0"
[owner_ui]
listen = "127.0.0.1:0"
rp_id = "localhost"
origin = "http://localhost:1"
"#,
        data = data.path().display(),
        export = fixture().display(),
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let ui = d.owner_ui_addr().unwrap();
    let origin = d.owner_ui_origin().unwrap().to_owned();
    let socket = d.owner_socket().to_path_buf();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));
    Running {
        stop: Some(stop),
        server,
        ui,
        origin,
        socket,
        data,
    }
}

impl Running {
    async fn shutdown(mut self) -> tempfile::TempDir {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
        self.data
    }
}

fn owner_op(socket: &std::path::Path, request: &Json) -> Json {
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
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.to_string().as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    serde_json::from_str(reply.trim()).unwrap_or_else(|_| panic!("bad owner reply: {reply}"))
}

fn mint(socket: &std::path::Path) -> String {
    let minted = owner_op(socket, &json!({"op": "passkey_enroll"}));
    assert_eq!(minted["ok"], json!(true), "{minted}");
    minted["enroll_token"].as_str().unwrap().to_owned()
}

/// Register `cred_id` with `token`. Returns the finish status and body.
async fn register(
    ui: std::net::SocketAddr,
    origin: &str,
    token: &str,
    cred_id: &[u8],
) -> (u16, String) {
    let mut auth = VirtAuth::new();
    auth.cred_id = cred_id.to_vec();
    let opts = http(
        ui,
        origin,
        Http::post("/owner/register/options", None, "").bearer(token),
    )
    .await;
    assert_eq!(opts.status, 200, "{}", opts.body);
    let opts: Json = serde_json::from_str(&opts.body).unwrap();
    auth.user_handle = b64url_dec(opts["publicKey"]["user"]["id"].as_str().unwrap());
    let ceremony = opts["ceremony_id"].as_str().unwrap();
    let challenge = opts["publicKey"]["challenge"].as_str().unwrap();
    let reg = auth.registration(challenge, origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": reg}).to_string();
    let registered = http(
        ui,
        origin,
        Http::post("/owner/register/finish", Some("application/json"), &body),
    )
    .await;
    (registered.status, registered.body)
}

#[tokio::test(flavor = "multi_thread")]
async fn req_aud_249_mint_and_store_are_audited_and_the_log_verifies() {
    let run = start().await;
    let origin = run.origin.clone();
    let token_a = mint(&run.socket);
    let (status_a, body_a) = register(run.ui, &origin, &token_a, ID_A).await;
    assert_eq!(status_a, 200, "{body_a}");
    let token_b = mint(&run.socket);
    let (status_b, body_b) = register(run.ui, &origin, &token_b, ID_B).await;
    assert_eq!(status_b, 200, "{body_b}");

    let data = run.shutdown().await;
    let audit = std::fs::read_to_string(data.path().join("audit/audit.jsonl")).unwrap();
    let store = std::fs::read_to_string(data.path().join("owner/passkeys.json")).unwrap();
    let id_a = b64url(ID_A);
    let id_b = b64url(ID_B);
    // The store holds the ids. The log must not, in either encoding.
    assert!(store.contains(&id_a) && store.contains(&id_b), "{store}");
    for secret in [
        token_a.as_str(),
        token_b.as_str(),
        id_a.as_str(),
        id_b.as_str(),
        hex::encode(ID_A).as_str(),
        hex::encode(ID_B).as_str(),
    ] {
        assert!(
            !audit.contains(secret),
            "audit log contains {secret}: {audit}"
        );
    }

    let entries: Vec<Json> = audit
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let names: Vec<&str> = entries
        .iter()
        .filter_map(|e| e["event"].as_str())
        .filter(|n| *n == "passkey_enroll_code" || *n == "passkey_enrolled")
        .collect();
    assert_eq!(
        names,
        [
            "passkey_enroll_code",
            "passkey_enrolled",
            "passkey_enroll_code",
            "passkey_enrolled",
        ]
    );
    let codes: Vec<&Json> = entries
        .iter()
        .filter(|e| e["event"] == "passkey_enroll_code")
        .collect();
    let stored: Vec<&Json> = entries
        .iter()
        .filter(|e| e["event"] == "passkey_enrolled")
        .collect();
    for code in &codes {
        assert_eq!(code["channel"], "cli");
        assert_eq!(code["result"], "minted");
        assert!(code.get("credential_fingerprint").is_none());
        assert!(code.get("passkey_count").is_none());
    }
    let fp = kharond::api::revocation::truncated_sha256_hex;
    assert_eq!(stored[0]["channel"], "web_ui");
    assert_eq!(stored[1]["channel"], "web_ui");
    assert_eq!(stored[0]["result"], "enrolled");
    assert_eq!(stored[1]["result"], "enrolled");
    assert_eq!(stored[0]["credential_fingerprint"], fp(ID_A));
    assert_eq!(stored[1]["credential_fingerprint"], fp(ID_B));
    assert_eq!(
        stored[0]["credential_fingerprint"].as_str().unwrap().len(),
        32
    );
    assert_eq!(stored[0]["passkey_count"], 1);
    assert_eq!(stored[1]["passkey_count"], 2);
    let on_disk: Json = serde_json::from_str(&store).unwrap();
    assert_eq!(on_disk["credentials"].as_array().unwrap().len(), 2);

    let raw = std::fs::read(data.path().join("audit/keys/audit_sign.pub")).unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(raw.as_slice().try_into().unwrap()).unwrap();
    let outcome = kharond::audit::verify(&data.path().join("audit/audit.jsonl"), &[], &vk).unwrap();
    assert!(
        matches!(outcome, kharond::audit::VerifyOutcome::Ok { head_seq } if head_seq >= 4),
        "{outcome}"
    );
}

/// Audit sink that can refuse either enrollment append.
struct Gate {
    fail_mint: AtomicBool,
    fail_store: AtomicBool,
}

impl OwnerAudit for Gate {
    fn auth_failed(&self, _failure: AuthFailure) {}
    fn suppressed_only(&self, _count: u64) {}
    fn passkey_enroll_code(&self) -> Result<(), OwnerAuditError> {
        if self.fail_mint.load(Ordering::SeqCst) {
            Err(OwnerAuditError)
        } else {
            Ok(())
        }
    }
    fn passkey_enrolled(&self, _enrolled: PasskeyEnrolled) -> Result<(), OwnerAuditError> {
        if self.fail_store.load(Ordering::SeqCst) {
            Err(OwnerAuditError)
        } else {
            Ok(())
        }
    }
}

struct NoRedeem;

impl ApprovalRedeemer for NoRedeem {
    fn prompt(&self, _token: &str) -> Result<(ApprovalPrompt, ApprovalAction), TokenGone> {
        Err(TokenGone::Unknown)
    }
    fn redeem(&self, _token: &str) -> Result<ApprovalAction, TokenGone> {
        Err(TokenGone::Unknown)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn req_aud_249_failed_append_refuses_the_code_and_the_passkey() {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("http://localhost:{}", addr.port());
    let gate = Arc::new(Gate {
        fail_mint: AtomicBool::new(true),
        fail_store: AtomicBool::new(false),
    });
    let ui = OwnerUi::open(
        dir.path(),
        "localhost",
        origin.clone(),
        Arc::new(StaticShell(ShellView {
            locked: true,
            pending: 0,
        })),
        gate.clone(),
        Arc::new(NoApprovals),
    )
    .unwrap();
    tokio::spawn(kharond::owner_ui::serve(
        listener,
        ui.clone(),
        Arc::new(NoRedeem),
    ));

    assert!(
        ui.mint_enroll_token().is_err(),
        "a failed mint append must not return a code"
    );
    gate.fail_mint.store(false, Ordering::SeqCst);
    let token = ui.mint_enroll_token().unwrap();
    gate.fail_store.store(true, Ordering::SeqCst);
    let (status, body) = register(addr, &origin, &token, ID_A).await;
    assert_eq!(status, 500, "{body}");
    assert!(body.contains("audit_failed"), "{body}");
    assert!(!body.contains(&b64url(ID_A)), "{body}");
    let path = dir.path().join("owner/passkeys.json");
    assert!(
        !path.exists(),
        "a failed enrolled append must not store the passkey"
    );
}
