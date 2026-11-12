//! #258: `kharon passkey list` and `kharon passkey remove <id>` over the
//! owner socket, and the same list with a remove button on the
//! signed-in owner page.
//!
//! After a remove, an assertion from that passkey is `401
//! bad_assertion` and a session opened with it is gone. Another
//! passkey still signs in. The CLI (this socket) may remove the last
//! passkey; the page refuses. Each op writes `passkey_listed` or
//! `passkey_removed` on channel `cli` or `web_ui`, fingerprint only.
//! A store file from before `enrolled_at` / `last_used_at` still loads.
//!
//! Its own test binary on purpose. The success case shuts a daemon
//! down and then reads that run's audit log; a concurrent fork in a
//! shared binary can hold the log's `flock` across that gap (#162).

mod api_support;
mod owner_ui_support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use owner_ui_support::{Http, VirtAuth, b64url, b64url_dec, http, session_cookie};
use serde_json::{Value as Json, json};

const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";

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

fn config_text(data: &std::path::Path) -> String {
    format!(
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
        data = data.display(),
        export = fixture().display(),
    )
}

async fn start_in(data: tempfile::TempDir) -> Running {
    let cfg = Config::from_toml_str(&config_text(data.path())).unwrap();
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

async fn start() -> Running {
    start_in(tempfile::tempdir().unwrap()).await
}

impl Running {
    async fn shutdown(mut self) -> tempfile::TempDir {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
        self.data
    }
}

/// The owner socket, same peer-uid gate as every other owner op
/// (REQ-APR-006): `handle` checks the peer before dispatch.
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

async fn register(ui: std::net::SocketAddr, origin: &str, token: &str, auth: &mut VirtAuth) {
    let opts = http(
        ui,
        origin,
        Http::post("/owner/register/options", None, "").bearer(token),
    )
    .await;
    assert_eq!(opts.status, 200, "{}", opts.body);
    let opts: Json = serde_json::from_str(&opts.body).unwrap();
    auth.user_handle = b64url_dec(opts["publicKey"]["user"]["id"].as_str().unwrap());
    let ceremony = opts["ceremony_id"].as_str().unwrap().to_owned();
    let challenge = opts["publicKey"]["challenge"].as_str().unwrap().to_owned();
    let reg = auth.registration(&challenge, origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": reg}).to_string();
    let registered = http(
        ui,
        origin,
        Http::post("/owner/register/finish", Some("application/json"), &body),
    )
    .await;
    assert_eq!(registered.status, 200, "{}", registered.body);
    assert!(session_cookie(&registered).is_none());
}

/// Sign in with `auth`. Returns `(status, body, session cookie)`.
async fn sign_in(
    ui: std::net::SocketAddr,
    origin: &str,
    auth: &mut VirtAuth,
) -> (u16, String, Option<String>) {
    let opts = http(ui, origin, Http::post("/owner/login/options", None, "")).await;
    if opts.status != 200 {
        return (opts.status, opts.body, None);
    }
    let opts: Json = serde_json::from_str(&opts.body).unwrap();
    let ceremony = opts["ceremony_id"].as_str().unwrap();
    let challenge = opts["publicKey"]["challenge"].as_str().unwrap();
    let assertion = auth.assertion(challenge, origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": assertion}).to_string();
    let done = http(
        ui,
        origin,
        Http::post("/owner/login/finish", Some("application/json"), &body),
    )
    .await;
    let cookie = session_cookie(&done);
    (done.status, done.body, cookie)
}

fn short_id(id: &[u8]) -> String {
    kharond::api::revocation::truncated_sha256_hex(id)[..8].to_owned()
}

fn row<'a>(list: &'a Json, id: &str) -> &'a Json {
    list["passkeys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap_or_else(|| panic!("no row {id} in {list}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_258_remove_kills_that_passkey_and_its_sessions() {
    let run = start().await;
    let origin = run.origin.clone();
    let mut auth_a = VirtAuth::new();
    auth_a.cred_id = vec![0x11; 16];
    let mut auth_b = VirtAuth::new();
    auth_b.cred_id = vec![0x22; 16];
    register(run.ui, &origin, &mint(&run.socket), &mut auth_a).await;
    register(run.ui, &origin, &mint(&run.socket), &mut auth_b).await;

    let (status, body, cookie_a) = sign_in(run.ui, &origin, &mut auth_a).await;
    assert_eq!(status, 200, "{body}");
    let cookie_a = cookie_a.expect("session from A");
    // Captured while both passkeys are still enrolled. The audit log
    // must not contain either credential id or either public key.
    let enrolled: Json = serde_json::from_str(
        &std::fs::read_to_string(run.data.path().join("owner/passkeys.json")).unwrap(),
    )
    .unwrap();
    let public_keys: Vec<String> = enrolled["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["public_key"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(public_keys.len(), 2);

    let id_a = short_id(&auth_a.cred_id);
    let id_b = short_id(&auth_b.cred_id);
    let fp_a = kharond::api::revocation::truncated_sha256_hex(&auth_a.cred_id);
    let fp_b = kharond::api::revocation::truncated_sha256_hex(&auth_b.cred_id);
    assert_eq!(&fp_a[..8], id_a);
    assert_ne!(id_a, id_b);

    // The socket list is what `kharon passkey list` prints from.
    let listed = owner_op(&run.socket, &json!({"op": "passkey_list"}));
    assert_eq!(listed["ok"], json!(true), "{listed}");
    let a = row(&listed, &id_a);
    let b = row(&listed, &id_b);
    assert!(a["enrolled_at"].as_str().is_some(), "{a}");
    assert!(a["last_used_at"].as_str().is_some(), "A signed in: {a}");
    assert!(b["enrolled_at"].as_str().is_some(), "{b}");
    assert!(b["last_used_at"].is_null(), "B has not signed in: {b}");
    let listed_text = listed.to_string();
    assert!(
        !listed_text.contains(&fp_a),
        "list must not carry the full fingerprint"
    );
    assert!(!listed_text.contains(&b64url(&auth_a.cred_id)));
    assert!(!listed_text.contains(&b64url(&auth_b.cred_id)));

    let home = http(run.ui, &origin, Http::get("/").cookie(&cookie_a)).await;
    assert_eq!(home.status, 200, "{}", home.body);
    assert!(home.body.contains("<h2>Passkeys</h2>"), "{}", home.body);
    assert!(
        home.body.contains("/owner/passkeys/remove"),
        "{}",
        home.body
    );
    let unsigned = http(run.ui, &origin, Http::get("/")).await;
    assert!(
        !unsigned.body.contains("/owner/passkeys/remove"),
        "login page"
    );

    let page = http(
        run.ui,
        &origin,
        Http::get("/owner/passkeys").cookie(&cookie_a),
    )
    .await;
    assert_eq!(page.status, 200, "{}", page.body);
    let page_json: Json = serde_json::from_str(&page.body).unwrap();
    assert!(row(&page_json, &id_a)["id"] == id_a);
    assert!(
        !page.body.contains(&b64url(&auth_a.cred_id)),
        "{}",
        page.body
    );
    let no_session = http(run.ui, &origin, Http::get("/owner/passkeys")).await;
    assert_eq!(no_session.status, 401, "{}", no_session.body);

    let stray = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/passkeys/remove",
            Some("application/json"),
            &json!({"id": id_b}).to_string(),
        )
        .cookie(&cookie_a)
        .without_origin(),
    )
    .await;
    assert_eq!(stray.status, 403, "{}", stray.body);

    let bad = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/passkeys/remove",
            Some("application/json"),
            r#"{"id":"not-an-id"}"#,
        )
        .cookie(&cookie_a),
    )
    .await;
    assert_eq!(bad.status, 400, "{}", bad.body);

    // Remove B from the page. A keeps working. B's assertion is refused.
    let removed_b = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/passkeys/remove",
            Some("application/json"),
            &json!({"id": id_b}).to_string(),
        )
        .cookie(&cookie_a),
    )
    .await;
    assert_eq!(removed_b.status, 200, "{}", removed_b.body);
    let still = http(
        run.ui,
        &origin,
        Http::get("/owner/session").cookie(&cookie_a),
    )
    .await;
    assert_eq!(still.status, 200, "{}", still.body);
    let (status_b, body_b, cookie_b) = sign_in(run.ui, &origin, &mut auth_b).await;
    assert_eq!(status_b, 401, "{body_b}");
    assert!(body_b.contains("bad_assertion"), "{body_b}");
    assert!(cookie_b.is_none());

    // The page refuses to remove the last passkey. The socket allows it.
    let last = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/passkeys/remove",
            Some("application/json"),
            &json!({"id": id_a}).to_string(),
        )
        .cookie(&cookie_a),
    )
    .await;
    assert_eq!(last.status, 409, "{}", last.body);
    assert!(last.body.contains("last_passkey"), "{}", last.body);
    let (status_a, body_a, cookie_a2) = sign_in(run.ui, &origin, &mut auth_a).await;
    assert_eq!(status_a, 200, "{body_a}");
    let cookie_a2 = cookie_a2.expect("A still signs in");

    let gone = owner_op(&run.socket, &json!({"op": "passkey_remove", "id": id_a}));
    assert_eq!(gone["ok"], json!(true), "{gone}");
    let dead = http(
        run.ui,
        &origin,
        Http::get("/owner/session").cookie(&cookie_a),
    )
    .await;
    assert_eq!(dead.status, 401, "session opened with A: {}", dead.body);
    let dead2 = http(
        run.ui,
        &origin,
        Http::get("/owner/session").cookie(&cookie_a2),
    )
    .await;
    assert_eq!(
        dead2.status, 401,
        "later session opened with A: {}",
        dead2.body
    );
    // Nothing is enrolled, so options refuses before a ceremony. A
    // finish that still presents an assertion is `401 bad_assertion`.
    let opts = http(
        run.ui,
        &origin,
        Http::post("/owner/login/options", None, ""),
    )
    .await;
    assert_eq!(opts.status, 409, "{}", opts.body);
    assert!(opts.body.contains("no_credential"), "{}", opts.body);
    let finish = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/login/finish",
            Some("application/json"),
            r#"{"ceremony_id":"gone","credential":{"id":"AQ","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"e30","signature":"e30"}}}"#,
        ),
    )
    .await;
    assert_eq!(finish.status, 401, "{}", finish.body);
    assert!(finish.body.contains("bad_assertion"), "{}", finish.body);

    let empty = owner_op(&run.socket, &json!({"op": "passkey_list"}));
    assert_eq!(empty["passkeys"].as_array().unwrap().len(), 0, "{empty}");

    let data = run.shutdown().await;
    let audit = std::fs::read_to_string(data.path().join("audit/audit.jsonl")).unwrap();
    let id_a_b64 = b64url(&auth_a.cred_id);
    let id_b_b64 = b64url(&auth_b.cred_id);
    for secret in [
        id_a_b64.as_str(),
        id_b_b64.as_str(),
        hex::encode(&auth_a.cred_id).as_str(),
        hex::encode(&auth_b.cred_id).as_str(),
    ] {
        assert!(!audit.contains(secret), "audit log contains {secret}");
    }
    for pk in &public_keys {
        assert!(pk.len() > 20, "{pk}");
        assert!(!audit.contains(pk), "audit log contains a public key");
    }
    assert!(audit.contains(&fp_a), "{audit}");
    assert!(audit.contains(&fp_b), "{audit}");

    let entries: Vec<Json> = audit
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let listed: Vec<&Json> = entries
        .iter()
        .filter(|e| e["event"] == "passkey_listed")
        .collect();
    let removed: Vec<&Json> = entries
        .iter()
        .filter(|e| e["event"] == "passkey_removed")
        .collect();
    assert!(
        listed
            .iter()
            .any(|e| e["channel"] == "cli" && e["result"] == "listed"),
        "{listed:?}"
    );
    assert!(
        listed
            .iter()
            .any(|e| e["channel"] == "web_ui" && e["result"] == "listed"),
        "{listed:?}"
    );
    let web_remove = removed
        .iter()
        .find(|e| e["channel"] == "web_ui")
        .expect("web remove");
    assert_eq!(web_remove["result"], "removed");
    assert_eq!(web_remove["credential_fingerprint"], fp_b);
    assert_eq!(web_remove["passkey_count"], 1);
    assert!(web_remove.get("credential_fingerprints").is_none());
    let cli_remove = removed
        .iter()
        .find(|e| e["channel"] == "cli")
        .expect("cli remove");
    assert_eq!(cli_remove["credential_fingerprint"], fp_a);
    assert_eq!(cli_remove["passkey_count"], 0);
    assert_eq!(cli_remove["result"], "removed");
    // The refused last-passkey removal wrote no entry.
    assert_eq!(removed.len(), 2, "{removed:?}");
    let cli_full = listed
        .iter()
        .find(|e| e["channel"] == "cli" && e["passkey_count"] == 2)
        .expect("cli list of both");
    let fps = cli_full["credential_fingerprints"].as_array().unwrap();
    assert!(fps.iter().any(|f| f == &fp_a));
    assert!(fps.iter().any(|f| f == &fp_b));

    let raw = std::fs::read(data.path().join("audit/keys/audit_sign.pub")).unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(raw.as_slice().try_into().unwrap()).unwrap();
    let outcome = kharond::audit::verify(&data.path().join("audit/audit.jsonl"), &[], &vk).unwrap();
    assert!(
        matches!(outcome, kharond::audit::VerifyOutcome::Ok { .. }),
        "{outcome}"
    );
}

/// #258: a passkey file written before enrolled-at and last-used
/// existed still loads. A later assertion fills in last-used only.
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_258_old_passkey_store_still_loads() {
    let run = start().await;
    let origin = run.origin.clone();
    let mut auth = VirtAuth::new();
    auth.cred_id = vec![0x44; 16];
    register(run.ui, &origin, &mint(&run.socket), &mut auth).await;
    let data = run.shutdown().await;

    let path = data.path().join("owner/passkeys.json");
    let mut file: Json = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for cred in file["credentials"].as_array_mut().unwrap() {
        cred.as_object_mut().unwrap().remove("enrolled_at");
        cred.as_object_mut().unwrap().remove("last_used_at");
    }
    std::fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();

    let run = start_in(data).await;
    let origin = run.origin.clone();
    let listed = owner_op(&run.socket, &json!({"op": "passkey_list"}));
    assert_eq!(listed["ok"], json!(true), "{listed}");
    let row = &listed["passkeys"][0];
    assert_eq!(row["id"], short_id(&auth.cred_id));
    assert!(row["enrolled_at"].is_null(), "{row}");
    assert!(row["last_used_at"].is_null(), "{row}");

    let (status, body, _) = sign_in(run.ui, &origin, &mut auth).await;
    assert_eq!(status, 200, "{body}");
    let listed = owner_op(&run.socket, &json!({"op": "passkey_list"}));
    let row = &listed["passkeys"][0];
    assert!(row["enrolled_at"].is_null(), "{row}");
    assert!(row["last_used_at"].as_str().is_some(), "{row}");
    run.shutdown().await;
}
