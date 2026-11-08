//! REQ-APR-005: owner web UI, WebAuthn-only login.
//!
//! The software virtual authenticator drives the real daemon: an
//! enrollment code from the owner socket, a `navigator.credentials`
//! shaped registration, then an assertion that is the only way to
//! obtain a session. A separate case launches headless Chrome with
//! its CDP virtual authenticator when a browser is on the machine
//! (`KHARON_CHROMIUM`, or `google-chrome` / `chromium` on `PATH`).
//! Set `KHARON_REQUIRE_WEBAUTHN=1` to fail instead of skipping that
//! case.
//!
//! The approvals cases (#131 slice 1) serve the same UI over a test
//! broker with a real pending request: list, approve and deny need the
//! passkey session and our `Origin`, decide through the broker's own
//! approve and deny (the fill then runs), write the CLI's audit
//! entries on the `web_ui` channel, and fail closed for a request past
//! its 120 s timeout (REQ-APR-003, #130).

mod api_support;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use api_support::{
    CHEAP_FLOOR, FakeAnswer, FakeFill, ITEM_A, RawResponse, RecordingAudit, TestBroker,
    TestSession, cheap_argon, raw_request,
};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value;
use futures_util::{SinkExt, StreamExt};
use kharond::api::grant::{Channel, GrantTerms, RequestState};
use kharond::api::http::ApprovalRedeemer;
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, Outcome, Request, parse_fill};
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use kharond::lock::{Clock, LockController, LockPolicy, ManualClock};
use kharond::origin::OriginConfig;
use kharond::owner_ui::{NoAudit, OwnerApprovals, OwnerUi, ROUTES, ShellView, StaticShell};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

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

async fn start(with_ui: bool) -> Running {
    let data = tempfile::tempdir().unwrap();
    let ui = if with_ui {
        r#"
[owner_ui]
listen = "127.0.0.1:0"
rp_id = "localhost"
origin = "http://localhost:1"
"#
    } else {
        ""
    };
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
{ui}"#,
        data = data.path().display(),
        export = fixture().display(),
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let ui_addr = d.owner_ui_addr().unwrap_or(d.local_addr().unwrap());
    let origin = d.owner_ui_origin().unwrap_or("http://localhost").to_owned();
    let socket = d.owner_socket().to_path_buf();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));
    Running {
        stop: Some(stop),
        server,
        ui: ui_addr,
        origin,
        socket,
        data,
    }
}

impl Running {
    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
    }
}

fn owner_op(socket: &Path, request: &Json) -> Json {
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

struct Http<'a> {
    method: &'a str,
    path: &'a str,
    cookie: Option<&'a str>,
    bearer: Option<&'a str>,
    content_type: Option<&'a str>,
    body: &'a str,
}

impl<'a> Http<'a> {
    fn get(path: &'a str) -> Self {
        Self {
            method: "GET",
            path,
            cookie: None,
            bearer: None,
            content_type: None,
            body: "",
        }
    }

    fn post(path: &'a str, content_type: Option<&'a str>, body: &'a str) -> Self {
        Self {
            method: "POST",
            path,
            cookie: None,
            bearer: None,
            content_type,
            body,
        }
    }

    fn cookie(mut self, cookie: &'a str) -> Self {
        self.cookie = Some(cookie);
        self
    }

    fn bearer(mut self, bearer: &'a str) -> Self {
        self.bearer = Some(bearer);
        self
    }
}

async fn http(addr: std::net::SocketAddr, origin: &str, req: Http<'_>) -> RawResponse {
    let method = req.method;
    let path = req.path;
    let body = req.body;
    let cookie = req
        .cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    let bearer = req
        .bearer
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let ctype = req
        .content_type
        .map(|t| format!("Content-Type: {t}\r\nContent-Length: {}\r\n", body.len()))
        .unwrap_or_default();
    let origin = if method == "POST" {
        format!("Origin: {origin}\r\n")
    } else {
        String::new()
    };
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{origin}{cookie}{bearer}{ctype}Connection: close\r\n\r\n{body}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => break,
            Err(e) => {
                assert!(Instant::now() < deadline, "owner UI never came up: {e}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    raw_request(addr, head.as_bytes()).await
}

fn session_cookie(resp: &RawResponse) -> Option<String> {
    resp.headers.iter().find_map(|(k, v)| {
        (k.eq_ignore_ascii_case("set-cookie") && v.starts_with("kharon_owner="))
            .then(|| v.split(';').next().unwrap().to_owned())
    })
}

fn b64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn b64url_dec(s: &str) -> Vec<u8> {
    let mut buf = vec![0u8; s.len()];
    let n = Base64UrlUnpadded::decode(s, &mut buf).unwrap().len();
    buf.truncate(n);
    buf
}

/// A software passkey: ES256, `none` attestation, UV+UP. The same
/// shape Chrome's WebAuthn virtual authenticator produces.
struct VirtAuth {
    key: EcdsaKeyPair,
    /// PKCS#8 of the private key, kept only to prove it never hits disk.
    pkcs8: Vec<u8>,
    cred_id: Vec<u8>,
    sign_count: u32,
    user_handle: Vec<u8>,
}

impl VirtAuth {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pkcs8 = doc.as_ref().to_vec();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).unwrap();
        Self {
            key,
            pkcs8,
            cred_id: vec![0x11; 16],
            sign_count: 0,
            user_handle: Vec::new(),
        }
    }

    fn public_point(&self) -> [u8; 65] {
        let raw = self.key.public_key().as_ref();
        assert_eq!(
            raw.len(),
            65,
            "uncompressed P-256 point, got {} bytes",
            raw.len()
        );
        raw.try_into().unwrap()
    }

    fn cose(&self) -> Vec<u8> {
        let point = self.public_point();
        let map = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (
                Value::Integer((-2i64).into()),
                Value::Bytes(point[1..33].to_vec()),
            ),
            (
                Value::Integer((-3i64).into()),
                Value::Bytes(point[33..65].to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        out
    }

    fn auth_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(if attested {
            0x01 | 0x04 | 0x40
        } else {
            0x01 | 0x04
        });
        data.extend_from_slice(&self.sign_count.to_be_bytes());
        if attested {
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.cred_id);
            data.extend_from_slice(&self.cose());
        }
        data
    }

    fn client_data(&self, kind: &str, challenge_b64: &str, origin: &str) -> String {
        format!(
            r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
        )
    }

    fn registration(&self, challenge_b64: &str, origin: &str, rp_id: &str) -> Json {
        let client = self.client_data("webauthn.create", challenge_b64, origin);
        let auth = self.auth_data(rp_id, true);
        let map = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth)),
        ]);
        let mut attestation = Vec::new();
        ciborium::into_writer(&map, &mut attestation).unwrap();
        json!({
            "id": b64url(&self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client.as_bytes()),
                "attestationObject": b64url(&attestation),
            }
        })
    }

    fn assertion(&mut self, challenge_b64: &str, origin: &str, rp_id: &str) -> Json {
        self.sign_count += 1;
        let client = self.client_data("webauthn.get", challenge_b64, origin);
        let auth = self.auth_data(rp_id, false);
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let sig = self
            .key
            .sign(&SystemRandom::new(), &message)
            .unwrap()
            .as_ref()
            .to_vec();
        let mut response = json!({
            "clientDataJSON": b64url(client.as_bytes()),
            "authenticatorData": b64url(&auth),
            "signature": b64url(&sig),
        });
        if !self.user_handle.is_empty() {
            response["userHandle"] = json!(b64url(&self.user_handle));
        }
        json!({
            "id": b64url(&self.cred_id),
            "type": "public-key",
            "response": response,
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_no_password_route() {
    for (method, path) in ROUTES {
        let blob = format!("{method} {path}").to_ascii_lowercase();
        assert!(!blob.contains("password"), "{blob}");
        assert!(!blob.contains("unlock"), "{blob}");
    }

    let run = start(true).await;
    let origin = run.origin.clone();
    let page = http(run.ui, &origin, Http::get("/")).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let lower = page.body.to_ascii_lowercase();
    assert!(!lower.contains("password"), "login page:\n{}", page.body);
    assert!(!lower.contains("<input"), "login page has a field");
    assert!(page.body.contains("Sign in with a passkey"));

    let enroll = http(run.ui, &origin, Http::get("/enroll")).await;
    assert_eq!(enroll.status, 200);
    let enroll_l = enroll.body.to_ascii_lowercase();
    assert!(!enroll_l.contains("password"));
    assert!(enroll_l.contains("type=\"text\""));
    assert!(!enroll_l.contains("type=\"password\""));

    for path in [
        "/login",
        "/owner/login",
        "/owner/password",
        "/password",
        "/unlock",
        "/owner/unlock",
    ] {
        let resp = http(
            run.ui,
            &origin,
            Http::post(path, Some("application/json"), r#"{"password":"hunter2"}"#),
        )
        .await;
        assert_eq!(resp.status, 404, "{path}: {}", resp.body);
        assert!(session_cookie(&resp).is_none(), "{path} set a session");
        assert!(!resp.body.contains("hunter2"), "{path} echoed the secret");
    }

    let rejected = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/login/finish",
            Some("application/json"),
            r#"{"password":"hunter2","ceremony_id":"x","credential":{"type":"public-key"}}"#,
        ),
    )
    .await;
    assert_eq!(rejected.status, 400, "{}", rejected.body);
    assert!(
        rejected.body.contains("password_rejected"),
        "{}",
        rejected.body
    );
    assert!(session_cookie(&rejected).is_none());

    let form = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/login/finish",
            Some("application/x-www-form-urlencoded"),
            "password=hunter2",
        ),
    )
    .await;
    assert_ne!(form.status, 200);
    assert!(session_cookie(&form).is_none());
    assert!(!form.body.contains("hunter2"));

    // No owner UI: the socket will not mint an enrollment code, and
    // there is still no password login hiding on the agent API.
    let bare = start(false).await;
    let reply = owner_op(&bare.socket, &json!({"op":"passkey_enroll"}));
    assert_eq!(reply["ok"], json!(false));
    assert_eq!(reply["error"], json!("unknown_op"));
    bare.shutdown().await;
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_login_without_assertion_refused() {
    let run = start(true).await;
    let origin = run.origin.clone();
    for (body, ctype) in [
        ("", None),
        ("{}", Some("application/json")),
        (
            r#"{"ceremony_id":"nope","credential":{"id":"AA","type":"public-key","response":{"clientDataJSON":"e30"}}}"#,
            Some("application/json"),
        ),
    ] {
        let resp = http(
            run.ui,
            &origin,
            Http::post("/owner/login/finish", ctype, body),
        )
        .await;
        assert_eq!(resp.status, 401, "{body:?} -> {}", resp.body);
        assert!(
            resp.body.contains("no_assertion"),
            "{body:?} -> {}",
            resp.body
        );
        assert!(session_cookie(&resp).is_none(), "{body:?} issued a session");
    }
    let session = http(run.ui, &origin, Http::get("/owner/session")).await;
    assert_eq!(session.status, 401, "{}", session.body);
    let home = http(run.ui, &origin, Http::get("/")).await;
    assert!(!home.body.contains("signed-in"));

    let audit = std::fs::read_to_string(run.data.path().join("audit/audit.jsonl")).unwrap();
    assert!(audit.contains("owner_auth_fail"), "{audit}");
    assert!(audit.contains("no_assertion"), "{audit}");
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_virtual_authenticator_login() {
    let run = start(true).await;
    let origin = run.origin.clone();
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    assert_eq!(minted["ok"], json!(true), "{minted}");
    let token = minted["enroll_token"].as_str().unwrap().to_owned();
    assert!(token.len() > 40);

    // The code alone is not a session.
    let session = http(run.ui, &origin, Http::get("/owner/session").bearer(&token)).await;
    assert_eq!(session.status, 401, "enrollment code must not sign in");

    let mut auth = VirtAuth::new();
    let opts = http(
        run.ui,
        &origin,
        Http::post("/owner/register/options", None, "").bearer(&token),
    )
    .await;
    assert_eq!(opts.status, 200, "{}", opts.body);
    let opts: Json = serde_json::from_str(&opts.body).unwrap();
    auth.user_handle = b64url_dec(opts["publicKey"]["user"]["id"].as_str().unwrap());
    let ceremony = opts["ceremony_id"].as_str().unwrap();
    let challenge = opts["publicKey"]["challenge"].as_str().unwrap();
    let reg = auth.registration(challenge, &origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": reg}).to_string();
    let registered = http(
        run.ui,
        &origin,
        Http::post("/owner/register/finish", Some("application/json"), &body),
    )
    .await;
    assert_eq!(registered.status, 200, "{}", registered.body);
    assert!(
        registered.body.contains("\"signed_in\":false"),
        "{}",
        registered.body
    );
    assert!(
        session_cookie(&registered).is_none(),
        "registration must not log in"
    );

    // A second use of the enrollment code is refused.
    let again = http(
        run.ui,
        &origin,
        Http::post("/owner/register/options", None, "").bearer(&token),
    )
    .await;
    assert_eq!(again.status, 401, "{}", again.body);
    assert!(again.body.contains("bad_enroll_token"));

    // Login without a real assertion, now that a credential exists.
    let missing = http(
        run.ui,
        &origin,
        Http::post("/owner/login/finish", Some("application/json"), "{}"),
    )
    .await;
    assert_eq!(missing.status, 401);
    assert!(missing.body.contains("no_assertion"));
    assert!(session_cookie(&missing).is_none());

    let login_opts = http(
        run.ui,
        &origin,
        Http::post("/owner/login/options", None, ""),
    )
    .await;
    assert_eq!(login_opts.status, 200, "{}", login_opts.body);
    let login_opts: Json = serde_json::from_str(&login_opts.body).unwrap();
    let ceremony = login_opts["ceremony_id"].as_str().unwrap();
    let challenge = login_opts["publicKey"]["challenge"].as_str().unwrap();
    let assertion = auth.assertion(challenge, &origin, "localhost");

    // Same ceremony, signature replaced: refused, no cookie.
    let mut forged = json!({"ceremony_id": ceremony, "credential": assertion});
    forged["credential"]["response"]["signature"] = json!(b64url(&[1, 2, 3, 4]));
    let bad = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/login/finish",
            Some("application/json"),
            &forged.to_string(),
        ),
    )
    .await;
    assert_eq!(bad.status, 401, "{}", bad.body);
    assert!(bad.body.contains("bad_assertion"), "{}", bad.body);
    assert!(session_cookie(&bad).is_none());

    // The ceremony was single-use. A fresh one accepts the real assertion.
    let login_opts = http(
        run.ui,
        &origin,
        Http::post("/owner/login/options", None, ""),
    )
    .await;
    let login_opts: Json = serde_json::from_str(&login_opts.body).unwrap();
    let ceremony = login_opts["ceremony_id"].as_str().unwrap();
    let challenge = login_opts["publicKey"]["challenge"].as_str().unwrap();
    let assertion = auth.assertion(challenge, &origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": assertion}).to_string();
    let ok = http(
        run.ui,
        &origin,
        Http::post("/owner/login/finish", Some("application/json"), &body),
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    let cookie = session_cookie(&ok).expect("session cookie");
    let cookie_header = ok.header("set-cookie").unwrap().to_owned();
    assert!(cookie_header.contains("HttpOnly"));
    assert!(cookie_header.contains("SameSite=Strict"));
    assert!(cookie_header.contains("Max-Age=900"));
    assert!(
        !cookie_header.contains("Secure"),
        "http origin is not Secure"
    );

    let home = http(run.ui, &origin, Http::get("/").cookie(&cookie)).await;
    assert!(home.body.contains("signed-in"), "{}", home.body);
    assert!(home.body.contains("id=\"locked\">locked"), "{}", home.body);
    let who = http(run.ui, &origin, Http::get("/owner/session").cookie(&cookie)).await;
    assert_eq!(who.status, 200, "{}", who.body);
    let who: Json = serde_json::from_str(&who.body).unwrap();
    assert_eq!(who["locked"], json!(true));
    assert_eq!(who["pending"], json!(0));

    // Replaying the assertion body does not mint another session.
    let replay = http(
        run.ui,
        &origin,
        Http::post("/owner/login/finish", Some("application/json"), &body),
    )
    .await;
    assert_eq!(replay.status, 401, "{}", replay.body);
    assert!(session_cookie(&replay).is_none());

    let store = std::fs::read(run.data.path().join("owner/passkeys.json")).unwrap();
    let mode = std::fs::metadata(run.data.path().join("owner/passkeys.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "passkey file mode {mode:o}");
    assert!(
        !store.windows(auth.pkcs8.len()).any(|w| w == auth.pkcs8),
        "private key must not be stored"
    );
    assert!(!store.windows(token.len()).any(|w| w == token.as_bytes()));
    let audit = std::fs::read_to_string(run.data.path().join("audit/audit.jsonl")).unwrap();
    assert!(
        !audit.contains(&token),
        "enrollment code landed in the audit log"
    );
    assert!(audit.contains("owner_auth_fail"));
    assert!(!audit.contains("hunter2"));

    run.shutdown().await;
}

/// Enroll a software passkey and sign in. Returns the `Cookie` value.
async fn enroll_and_sign_in(run: &Running) -> String {
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    assert_eq!(minted["ok"], json!(true), "{minted}");
    let token = minted["enroll_token"].as_str().unwrap();
    register_and_sign_in(run.ui, &run.origin, token).await
}

/// Register a software passkey with the enrollment code `token`, then
/// sign in with an assertion. Returns the `Cookie` value.
async fn register_and_sign_in(ui: std::net::SocketAddr, origin: &str, token: &str) -> String {
    let mut auth = VirtAuth::new();
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
    assert_eq!(registered.status, 200, "{}", registered.body);
    assert!(session_cookie(&registered).is_none());

    let login_opts = http(ui, origin, Http::post("/owner/login/options", None, "")).await;
    assert_eq!(login_opts.status, 200, "{}", login_opts.body);
    let login_opts: Json = serde_json::from_str(&login_opts.body).unwrap();
    let ceremony = login_opts["ceremony_id"].as_str().unwrap();
    let challenge = login_opts["publicKey"]["challenge"].as_str().unwrap();
    let assertion = auth.assertion(challenge, origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": assertion}).to_string();
    let ok = http(
        ui,
        origin,
        Http::post("/owner/login/finish", Some("application/json"), &body),
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    session_cookie(&ok).expect("session cookie")
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_logout_replay_is_refused() {
    let run = start(true).await;
    let origin = run.origin.clone();
    let cookie = enroll_and_sign_in(&run).await;

    let who = http(run.ui, &origin, Http::get("/owner/session").cookie(&cookie)).await;
    assert_eq!(who.status, 200, "login did not stick: {}", who.body);

    let out = http(
        run.ui,
        &origin,
        Http::post("/owner/logout", None, "").cookie(&cookie),
    )
    .await;
    assert_eq!(out.status, 200, "{}", out.body);
    let cleared = out.header("set-cookie").unwrap();
    assert!(
        cleared.starts_with("kharon_owner=") && cleared.contains("Max-Age=0"),
        "{cleared}"
    );

    // The browser may have dropped the cookie. A copy of the old one
    // must still be refused: logout removed the session, not only the
    // Set-Cookie.
    let replay = http(run.ui, &origin, Http::get("/owner/session").cookie(&cookie)).await;
    assert_eq!(
        replay.status, 401,
        "revoked cookie still worked: {}",
        replay.body
    );
    assert!(replay.body.contains("unauthenticated"), "{}", replay.body);
    let home = http(run.ui, &origin, Http::get("/").cookie(&cookie)).await;
    assert!(
        !home.body.contains("signed-in"),
        "revoked cookie still rendered the shell"
    );

    run.shutdown().await;
}

fn chromium_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KHARON_CHROMIUM") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/local/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

struct Chromium {
    child: Child,
    ws: String,
    _profile: tempfile::TempDir,
}

impl Drop for Chromium {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn launch_chromium(bin: &Path) -> Chromium {
    let profile = tempfile::tempdir().unwrap();
    let child = Command::new(bin)
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--no-proxy-server",
            "--host-resolver-rules=MAP localhost 127.0.0.1",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot launch Chromium at {}: {e}", bin.display()));
    let port_file = profile.path().join("DevToolsActivePort");
    let deadline = Instant::now() + Duration::from_secs(20);
    let ws = loop {
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                break format!("ws://127.0.0.1:{port}{path}");
            }
        }
        assert!(Instant::now() < deadline, "Chromium never opened DevTools");
        std::thread::sleep(Duration::from_millis(50));
    };
    Chromium {
        child,
        ws,
        _profile: profile,
    }
}

struct Cdp {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next: u64,
}

impl Cdp {
    async fn connect(url: &str) -> Self {
        let (ws, _) = connect_async(url).await.unwrap();
        Self { ws, next: 0 }
    }

    async fn call(&mut self, session: Option<&str>, method: &str, params: Json) -> Json {
        match self.try_call(session, method, params).await {
            Ok(result) => result,
            Err(error) => panic!("{method}: {error}"),
        }
    }

    /// One CDP round trip. `Err` carries the reply's `error` object.
    async fn try_call(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Json,
    ) -> Result<Json, Json> {
        self.next += 1;
        let id = self.next;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        self.ws.send(Message::Text(msg.to_string())).await.unwrap();
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(20), self.ws.next())
                .await
                .unwrap_or_else(|_| panic!("no reply to {method}"))
                .unwrap()
                .unwrap();
            let Message::Text(text) = frame else { continue };
            let v: Json = serde_json::from_str(&text).unwrap();
            if v["id"] == json!(id) {
                return match v.get("error") {
                    Some(error) => Err(error.clone()),
                    None => Ok(v["result"].clone()),
                };
            }
        }
    }

    async fn open(&mut self, url: &str) -> String {
        let r = self
            .call(None, "Target.createTarget", json!({"url": url}))
            .await;
        let target = r["targetId"].as_str().unwrap();
        let r = self
            .call(
                None,
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
            )
            .await;
        let session = r["sessionId"].as_str().unwrap().to_owned();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let state = self
                .eval_navigating(
                    &session,
                    "JSON.stringify([location.href, document.readyState, window.isSecureContext])",
                )
                .await
                .unwrap_or(Json::Null);
            let state: Json = serde_json::from_str(state.as_str().unwrap_or("[]")).unwrap();
            if state[1] == json!("complete") && state[0] == json!(url) {
                assert_eq!(state[2], json!(true), "owner UI must be a secure context");
                break;
            }
            assert!(Instant::now() < deadline, "{url} never loaded: {state}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        session
    }

    async fn eval(&mut self, session: &str, expression: &str) -> Json {
        match self.try_eval(session, expression).await {
            Ok(value) => value,
            Err(error) => panic!("Runtime.evaluate: {error}"),
        }
    }

    /// `Runtime.evaluate` on a page that may be navigating (#167).
    /// `None` when a navigation took the execution context away, so a
    /// poll loop tries again on the next tick. Any other error still
    /// fails the test.
    async fn eval_navigating(&mut self, session: &str, expression: &str) -> Option<Json> {
        match self.try_eval(session, expression).await {
            Ok(value) => Some(value),
            Err(error) if is_navigation_race(&error) => None,
            Err(error) => panic!("Runtime.evaluate: {error}"),
        }
    }

    async fn try_eval(&mut self, session: &str, expression: &str) -> Result<Json, Json> {
        let r = self
            .try_call(
                Some(session),
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true, "awaitPromise": true}),
            )
            .await?;
        if let Some(ex) = r.get("exceptionDetails") {
            panic!("eval failed: {ex} for {expression}");
        }
        Ok(r["result"]["value"].clone())
    }
}

/// A CDP error that only means "the page navigated under this call":
/// the messages the fill engine maps to `navigated` (`cdp/fill.rs`).
fn is_navigation_race(error: &Json) -> bool {
    let message = error["message"].as_str().unwrap_or("");
    message.contains("Cannot find context")
        || message.contains("context was destroyed")
        || message.contains("Inspected target navigated")
        || message.contains("No execution context")
}

/// In a fresh tab: add a CTAP2 virtual authenticator, register it
/// with the enrollment code `token` on `/enroll`, then sign in on `/`.
/// Returns the tab's CDP session and the authenticator id.
async fn browser_register_and_sign_in(
    cdp: &mut Cdp,
    origin: &str,
    token: &str,
) -> (String, String) {
    let session = cdp.open(&format!("{origin}/enroll")).await;
    cdp.call(Some(&session), "WebAuthn.enable", json!({})).await;
    let added = cdp
        .call(
            Some(&session),
            "WebAuthn.addVirtualAuthenticator",
            json!({
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": true,
                    "hasUserVerification": true,
                    "isUserVerified": true,
                    "automaticPresenceSimulation": true,
                }
            }),
        )
        .await;
    let authenticator_id = added["authenticatorId"].as_str().unwrap().to_owned();

    // The enrollment code is passed as a JS string, then the page
    // calls `credentials.create` against the virtual authenticator.
    let token_js = serde_json::to_string(&token).unwrap();
    cdp.eval(&session, &format!("window.__enroll = {token_js};"))
        .await;
    let registered = cdp
        .eval(&session, "window.kharonRegister(window.__enroll)")
        .await;
    assert_eq!(
        registered,
        json!(true),
        "virtual authenticator did not register"
    );

    // Registration must not have signed the page in.
    let still = cdp
        .eval(
            &session,
            "fetch('/owner/session', {credentials:'same-origin'}).then(r => r.status)",
        )
        .await;
    assert_eq!(still, json!(401));

    // Same target, so the virtual authenticator (and its new
    // credential) is still attached. The login page's button is
    // `kharonSignIn`.
    // The navigation can take the context away before the reply.
    let _ = cdp
        .eval_navigating(&session, &format!("location.assign({origin:?})"))
        .await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let ready = cdp
            .eval_navigating(
                &session,
                "JSON.stringify([location.pathname, typeof window.kharonSignIn])",
            )
            .await
            .unwrap_or(Json::Null);
        let ready: Json = serde_json::from_str(ready.as_str().unwrap_or("[]")).unwrap();
        if ready[0] == json!("/") && ready[1] == json!("function") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "login page never loaded: {ready}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = cdp.call(Some(&session), "WebAuthn.enable", json!({})).await;
    let signed_in = cdp.eval(&session, "window.kharonSignIn()").await;
    assert_eq!(
        signed_in,
        json!(true),
        "virtual authenticator did not sign in"
    );
    (session, authenticator_id)
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_chromium_virtual_authenticator() {
    let Some(bin) = chromium_bin() else {
        if std::env::var_os("KHARON_REQUIRE_WEBAUTHN").is_some() {
            panic!("KHARON_REQUIRE_WEBAUTHN is set but no Chromium binary was found");
        }
        eprintln!("SKIP req_apr_005_chromium_virtual_authenticator: no Chromium binary");
        return;
    };
    let run = start(true).await;
    let origin = run.origin.clone();
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    let token = minted["enroll_token"].as_str().unwrap().to_owned();

    let chromium = launch_chromium(&bin);
    let mut cdp = Cdp::connect(&chromium.ws).await;
    let (session, authenticator_id) = browser_register_and_sign_in(&mut cdp, &origin, &token).await;

    let authed = cdp
        .eval(
            &session,
            "fetch('/owner/session',{credentials:'same-origin'}).then(r => r.status)",
        )
        .await;
    assert_eq!(authed, json!(200), "session cookie was not set");

    // Without an assertion the same page cannot sign in again.
    cdp.eval(
        &session,
        "fetch('/owner/logout',{method:'POST',credentials:'same-origin'})",
    )
    .await;
    cdp.call(
        Some(&session),
        "WebAuthn.removeVirtualAuthenticator",
        json!({"authenticatorId": authenticator_id}),
    )
    .await;
    let refused = cdp
        .eval(
            &session,
            r#"
        fetch('/owner/login/finish', {
          method:'POST', credentials:'same-origin',
          headers:{'content-type':'application/json'},
          body:'{}'
        }).then(r => r.status)
    "#,
        )
        .await;
    assert_eq!(refused, json!(401));
    let after = cdp
        .eval(
            &session,
            "fetch('/owner/session',{credentials:'same-origin'}).then(r => r.status)",
        )
        .await;
    assert_eq!(
        after,
        json!(401),
        "logout + empty finish must not leave a session"
    );

    drop(cdp);
    drop(chromium);
    run.shutdown().await;
}

// ---- #131 slice 1: the approvals queue ----

/// The owner UI over a test broker that has a pending grant request
/// to decide. The broker backs the approvals routes and the ntfy
/// redeem paths, as the daemon wires it.
struct ApprovalsRig {
    broker: Arc<TestBroker>,
    clock: Arc<ManualClock>,
    audit: RecordingAudit,
    alpha: String,
    ui: std::net::SocketAddr,
    owner: Arc<OwnerUi>,
    origin: String,
    cookie: String,
    _data: tempfile::TempDir,
    /// The real audit log's directory, when the rig runs on one.
    _log: Option<tempfile::TempDir>,
}

impl ApprovalsRig {
    async fn new() -> Self {
        Self::build(false).await
    }

    /// The same rig over a real hash-chained [`AuditLog`] in a temp
    /// directory instead of [`RecordingAudit`] (#131 slice 4: the
    /// audit tail reads the log's own in-memory tail).
    ///
    /// [`AuditLog`]: kharond::audit::AuditLog
    async fn with_audit_log() -> Self {
        Self::build(true).await
    }

    async fn build(real_log: bool) -> Self {
        let (alpha, ha) = generate_with(&cheap_argon(), "alpha");
        let tokens = TokenStore::with_floor([("alpha", ha.as_str())], &CHEAP_FLOOR).unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut lock = LockController::new(
            LockPolicy::default(),
            clock.clone(),
            Box::new(StaticHardening::all_ok()),
        );
        lock.unlock(|| Ok::<_, ()>(TestSession::fixture())).unwrap();
        let audit = RecordingAudit::default();
        let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/");
        let grant_clock: Arc<dyn Clock> = clock.clone();
        let log_dir = real_log.then(|| tempfile::tempdir().unwrap());
        let sink: Box<dyn kharond::api::AuditSink> = match &log_dir {
            Some(dir) => Box::new(
                kharond::audit::AuditLog::open(
                    dir.path(),
                    kharond::audit::AuditConfig::default(),
                    Box::new(kharond::audit::NullCheckpointSink),
                )
                .unwrap(),
            ),
            None => Box::new(audit.clone()),
        };
        let broker = Arc::new(
            Broker::new(tokens, lock, sink, OriginConfig::default())
                .with_grant_clock(grant_clock)
                .with_fill_backend(Box::new(fake)),
        );

        let data = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = listener.local_addr().unwrap();
        let origin = format!("http://localhost:{}", ui_addr.port());
        let ui = OwnerUi::open(
            data.path(),
            "localhost",
            origin.clone(),
            Arc::new(StaticShell(ShellView {
                locked: false,
                pending: 0,
            })),
            Arc::new(NoAudit),
            broker.clone() as Arc<dyn OwnerApprovals>,
        )
        .unwrap();
        let token = ui.mint_enroll_token();
        let redeem: Arc<dyn ApprovalRedeemer> = broker.clone();
        tokio::spawn(kharond::owner_ui::serve(listener, ui.clone(), redeem));
        let cookie = register_and_sign_in(ui_addr, &origin, &token).await;
        Self {
            broker,
            clock,
            audit,
            alpha: alpha.expose_secret().clone(),
            ui: ui_addr,
            owner: ui,
            origin,
            cookie,
            _data: data,
            _log: log_dir,
        }
    }

    /// A password fill with no grant: returns its fill outcome.
    async fn fill(&self) -> Json {
        let req = parse_fill(
            kharond::api::FillOperation::Fill,
            json!({
                "item_id": ITEM_A,
                "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com"},
                "fields": [{"kind": "password"}],
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let agent = self.broker.authenticate(&self.alpha).unwrap();
        match self
            .broker
            .fill(&agent, req, tokio::time::Instant::now())
            .await
        {
            Ok(Outcome::Fill(r)) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a fill outcome, got {other:?}"),
        }
    }

    /// A fresh pending request's id.
    async fn pending_request(&self) -> String {
        let r = self.fill().await;
        assert_eq!(r["status"], "pending_approval", "{r}");
        r["grant_request_id"].as_str().unwrap().to_owned()
    }

    async fn list(&self) -> RawResponse {
        http(
            self.ui,
            &self.origin,
            Http::get("/owner/approvals").cookie(&self.cookie),
        )
        .await
    }

    async fn decide(&self, path: &str, body: &Json) -> RawResponse {
        let body = body.to_string();
        http(
            self.ui,
            &self.origin,
            Http::post(path, Some("application/json"), &body).cookie(&self.cookie),
        )
        .await
    }

    /// Audit entries about `request_id` (and the grant it issued).
    fn entries_for(&self, request_id: &str) -> Vec<kharond::audit::Entry> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.request_id.as_deref() == Some(request_id))
            .cloned()
            .collect()
    }

    fn state(&self, request_id: &str) -> RequestState {
        self.broker.grant_request(request_id).unwrap().state
    }

    /// Approve a fresh request as `per-origin` (1 h, unlimited uses)
    /// over the CLI path. Returns the grant id.
    async fn per_origin_grant(&self) -> String {
        let request = self.pending_request().await;
        let terms = GrantTerms {
            kind: kharond::config::GrantKind::PerOrigin,
            ..GrantTerms::once_item(ITEM_A)
        };
        self.broker
            .approve_grant_request(&request, &terms, Channel::Cli)
            .unwrap()
            .id
    }

    async fn grants(&self) -> RawResponse {
        http(
            self.ui,
            &self.origin,
            Http::get("/owner/grants").cookie(&self.cookie),
        )
        .await
    }

    async fn audit(&self) -> RawResponse {
        http(
            self.ui,
            &self.origin,
            Http::get("/owner/audit").cookie(&self.cookie),
        )
        .await
    }

    /// `grant_revoke` entries for `grant_id`.
    fn revokes_of(&self, grant_id: &str) -> Vec<kharond::audit::Entry> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.event == kharond::audit::Event::GrantRevoke
                    && e.grant_id.as_deref() == Some(grant_id)
            })
            .cloned()
            .collect()
    }

    /// The agent's own `kharon_status` grants.
    fn status_grants(&self) -> Json {
        let agent = self.broker.authenticate(&self.alpha).unwrap();
        match self.broker.dispatch(&agent, Request::Status).unwrap() {
            Outcome::Status(s) => serde_json::to_value(s).unwrap()["grants"].clone(),
            other => panic!("expected a status, got {other:?}"),
        }
    }
}

/// An entry with the per-request fields blanked, so a web entry and a
/// CLI entry for two different requests can be compared.
fn shape(e: &kharond::audit::Entry) -> Json {
    let mut v = serde_json::to_value(e).unwrap();
    let map = v.as_object_mut().unwrap();
    for k in [
        "seq",
        "ts",
        "prev_hash",
        "log_id",
        "request_id",
        "grant_id",
        "channel",
    ] {
        map.remove(k);
    }
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_approvals_list_approve_deny_through_the_cli_path() {
    let rig = ApprovalsRig::new().await;
    let web = rig.pending_request().await;

    // The queue needs the passkey session.
    let anon = http(rig.ui, &rig.origin, Http::get("/owner/approvals")).await;
    assert_eq!(anon.status, 401, "{}", anon.body);
    let list = rig.list().await;
    assert_eq!(list.status, 200, "{}", list.body);
    let rows = list.json()["pending"].clone();
    assert_eq!(rows.as_array().unwrap().len(), 1, "{rows}");
    assert_eq!(rows[0]["request_id"], json!(web));
    assert_eq!(rows[0]["agent_id"], "alpha");
    assert_eq!(rows[0]["item_id"], ITEM_A);
    assert_eq!(rows[0]["action"], "fill");
    assert_eq!(rows[0]["origin"], "https://login.example.com");

    // A cross-site POST carrying the session cookie changes nothing.
    let forged = http(
        rig.ui,
        "https://evil.example",
        Http::post(
            "/owner/approvals/approve",
            Some("application/json"),
            &json!({"request_id": web}).to_string(),
        )
        .cookie(&rig.cookie),
    )
    .await;
    assert_eq!(forged.status, 403, "{}", forged.body);
    let form = http(
        rig.ui,
        &rig.origin,
        Http::post(
            "/owner/approvals/approve",
            Some("application/x-www-form-urlencoded"),
            &format!("request_id={web}"),
        )
        .cookie(&rig.cookie),
    )
    .await;
    assert_eq!(form.status, 400, "{}", form.body);
    assert_eq!(rig.state(&web), RequestState::Pending);

    // Approve once from the web: the same fill now runs, and the once
    // grant is spent by it.
    let approved = rig
        .decide(
            "/owner/approvals/approve",
            &json!({"request_id": web, "kind": "once"}),
        )
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    let grant_id = approved.json()["grant_id"].as_str().unwrap().to_owned();
    assert_eq!(rig.state(&web), RequestState::Approved);
    let r = rig.fill().await;
    assert_eq!(r["status"], "filled", "{r}");
    // Deciding it again is refused.
    let again = rig
        .decide("/owner/approvals/approve", &json!({"request_id": web}))
        .await;
    assert_eq!(again.status, 409, "{}", again.body);
    assert!(again.body.contains("not_pending"), "{}", again.body);

    // The CLI approves the next request through the same broker call.
    let cli = rig.pending_request().await;
    rig.broker
        .approve_grant_request(&cli, &GrantTerms::once_item(ITEM_A), Channel::Cli)
        .unwrap();
    let web_issue: Vec<_> = rig
        .entries_for(&web)
        .into_iter()
        .filter(|e| e.result.as_deref() == Some("issued"))
        .collect();
    let cli_issue: Vec<_> = rig
        .entries_for(&cli)
        .into_iter()
        .filter(|e| e.result.as_deref() == Some("issued"))
        .collect();
    assert_eq!(web_issue.len(), 1, "{web_issue:?}");
    assert_eq!(cli_issue.len(), 1, "{cli_issue:?}");
    assert_eq!(web_issue[0].channel.as_deref(), Some("web_ui"));
    assert_eq!(web_issue[0].grant_id.as_deref(), Some(grant_id.as_str()));
    assert_eq!(cli_issue[0].channel.as_deref(), Some("cli"));
    assert_eq!(shape(&web_issue[0]), shape(&cli_issue[0]));
}

/// Deny from the web and from the CLI write the same entry, apart
/// from the channel. (A separate rig: one item's fills are capped at
/// five per ten minutes, REQ-RL-001.)
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_deny_writes_the_cli_entry_on_the_web_channel() {
    let rig = ApprovalsRig::new().await;
    let web_deny = rig.pending_request().await;
    let denied = rig
        .decide("/owner/approvals/deny", &json!({"request_id": web_deny}))
        .await;
    assert_eq!(denied.status, 200, "{}", denied.body);
    assert_eq!(rig.state(&web_deny), RequestState::Denied);
    let cli_deny = rig.pending_request().await;
    rig.broker
        .deny_grant_request(&cli_deny, Channel::Cli)
        .unwrap();
    let pick = |id: &str| {
        rig.entries_for(id)
            .into_iter()
            .filter(|e| e.result.as_deref() == Some("denied"))
            .collect::<Vec<_>>()
    };
    let (w, c) = (pick(&web_deny), pick(&cli_deny));
    assert_eq!((w.len(), c.len()), (1, 1), "{w:?} {c:?}");
    assert_eq!(w[0].detail_code.as_deref(), Some("owner_denied"));
    assert_eq!(w[0].channel.as_deref(), Some("web_ui"));
    assert_eq!(c[0].channel.as_deref(), Some("cli"));
    assert_eq!(shape(&w[0]), shape(&c[0]));

    // The queue is empty again.
    let list = rig.list().await;
    assert_eq!(list.json()["pending"], json!([]), "{}", list.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_decision_on_an_aged_request_fails_closed() {
    let rig = ApprovalsRig::new().await;
    let aged = rig.pending_request().await;
    // Past the 120 s timeout, with no agent call since.
    rig.clock.advance(Duration::from_secs(121));
    let list = rig.list().await;
    assert_eq!(list.json()["pending"], json!([]), "{}", list.body);
    let approved = rig
        .decide("/owner/approvals/approve", &json!({"request_id": aged}))
        .await;
    assert_eq!(approved.status, 409, "{}", approved.body);
    assert!(approved.body.contains("not_pending"), "{}", approved.body);
    assert_eq!(rig.state(&aged), RequestState::Denied);
    let results: Vec<(Option<String>, Option<String>)> = rig
        .entries_for(&aged)
        .into_iter()
        .map(|e| (e.result, e.detail_code))
        .collect();
    assert_eq!(
        results,
        [
            (Some("pending".into()), None),
            (Some("denied".into()), Some("request_timeout".into())),
        ]
    );
    let r = rig.fill().await;
    assert_eq!(r["status"], "pending_approval", "no grant was issued: {r}");

    // Deny takes the same path: the timeout decides first.
    let second = r["grant_request_id"].as_str().unwrap().to_owned();
    rig.clock.advance(Duration::from_secs(121));
    let denied = rig
        .decide("/owner/approvals/deny", &json!({"request_id": second}))
        .await;
    assert_eq!(denied.status, 409, "{}", denied.body);
    let details: Vec<Option<String>> = rig
        .entries_for(&second)
        .into_iter()
        .filter(|e| e.result.as_deref() == Some("denied"))
        .map(|e| e.detail_code)
        .collect();
    assert_eq!(details, [Some("request_timeout".to_owned())]);

    // Unknown ids are not found.
    let unknown = rig
        .decide("/owner/approvals/deny", &json!({"request_id": "gr_nope"}))
        .await;
    assert_eq!(unknown.status, 404, "{}", unknown.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_approve_rolls_back_when_the_audit_append_fails() {
    let rig = ApprovalsRig::new().await;
    let id = rig.pending_request().await;
    *rig.audit.fail_event.lock().unwrap() = Some("grant_issue");
    let approved = rig
        .decide("/owner/approvals/approve", &json!({"request_id": id}))
        .await;
    assert_eq!(approved.status, 500, "{}", approved.body);
    assert!(approved.body.contains("audit_failed"), "{}", approved.body);
    assert_eq!(rig.state(&id), RequestState::Pending);
    *rig.audit.fail_event.lock().unwrap() = None;
    let r = rig.fill().await;
    assert_eq!(r["status"], "pending_approval", "a grant survived: {r}");
}

/// The shell page's own buttons, in a real browser: the row shows the
/// observed origin, and "Approve once" issues the grant over the
/// `web_ui` channel (the browser's fetch carries our `Origin` and a
/// JSON body, so it passes the CSRF checks a forged request fails).
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_chromium_approve_click() {
    let Some(bin) = chromium_bin() else {
        if std::env::var_os("KHARON_REQUIRE_WEBAUTHN").is_some() {
            panic!("KHARON_REQUIRE_WEBAUTHN is set but no Chromium binary was found");
        }
        eprintln!("SKIP req_apr_005_chromium_approve_click: no Chromium binary");
        return;
    };
    let rig = ApprovalsRig::new().await;
    let approve = rig.pending_request().await;
    let token = rig.owner.mint_enroll_token();

    let chromium = launch_chromium(&bin);
    let mut cdp = Cdp::connect(&chromium.ws).await;
    let (session, _authenticator) =
        browser_register_and_sign_in(&mut cdp, &rig.origin, &token).await;
    let _ = cdp
        .eval_navigating(&session, &format!("location.assign({:?})", rig.origin))
        .await;
    let row = format!(
        "tr[data-request-id={}]",
        serde_json::to_string(&approve).unwrap()
    );
    let probe = format!(
        "JSON.stringify((() => {{ const r = document.querySelector({sel}); \
         return r ? Array.from(r.cells, c => c.textContent) : null; }})())",
        sel = serde_json::to_string(&row).unwrap()
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let cells = loop {
        let got = cdp
            .eval_navigating(&session, &probe)
            .await
            .unwrap_or(Json::Null);
        let cells: Json = serde_json::from_str(got.as_str().unwrap_or("null")).unwrap();
        if cells.is_array() {
            break cells;
        }
        assert!(
            Instant::now() < deadline,
            "the queue never showed the request"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(cells[0], "alpha", "{cells}");
    assert_eq!(cells[1], "fill", "{cells}");
    assert_eq!(cells[2], "https://login.example.com", "{cells}");
    assert_eq!(cells[3], ITEM_A, "{cells}");

    let click = format!(
        "(() => {{ const b = Array.from(document.querySelector({sel}).querySelectorAll('button')) \
         .find(b => b.textContent === 'Approve once'); b.click(); return true; }})()",
        sel = serde_json::to_string(&row).unwrap()
    );
    assert_eq!(cdp.eval(&session, &click).await, json!(true));
    // Wait for the `issued` entry, not the request state: the broker
    // marks the request approved before it appends that entry (and
    // rolls the approval back if the append fails), so the state can
    // flip while the append is still waiting on the audit lock.
    let deadline = Instant::now() + Duration::from_secs(10);
    let issued = loop {
        let issued: Vec<_> = rig
            .entries_for(&approve)
            .into_iter()
            .filter(|e| e.result.as_deref() == Some("issued"))
            .collect();
        if !issued.is_empty() {
            break issued;
        }
        assert!(Instant::now() < deadline, "the click never approved");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(rig.state(&approve), RequestState::Approved);
    assert_eq!(issued.len(), 1, "{issued:?}");
    assert_eq!(issued[0].channel.as_deref(), Some("web_ui"));
    assert_eq!(rig.fill().await["status"], "filled");

    // The page refreshed its queue after the decision.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let empty = cdp
            .eval(&session, "document.getElementById('rows').children.length")
            .await;
        if empty == json!(0) {
            break;
        }
        assert!(Instant::now() < deadline, "the approved row stayed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(cdp);
    drop(chromium);
}

// ---- #131 slice 2: grants ----

/// Grant views with the wall-clock expiry blanked: two renders a
/// moment apart can differ by a second.
fn without_expiry(mut v: Json) -> Json {
    for g in v.as_array_mut().unwrap() {
        g.as_object_mut().unwrap().remove("expires_at");
    }
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_grants_list_and_revoke_through_the_cli_path() {
    let rig = ApprovalsRig::new().await;
    let web = rig.per_origin_grant().await;

    // The list needs the passkey session, and shows what the agent's
    // own status shows.
    let anon = http(rig.ui, &rig.origin, Http::get("/owner/grants")).await;
    assert_eq!(anon.status, 401, "{}", anon.body);
    let list = rig.grants().await;
    assert_eq!(list.status, 200, "{}", list.body);
    let grants = list.json()["grants"].clone();
    assert_eq!(grants.as_array().unwrap().len(), 1, "{grants}");
    assert_eq!(grants[0]["id"], json!(web));
    assert_eq!(grants[0]["agent_id"], "alpha");
    assert_eq!(grants[0]["item_id"], ITEM_A);
    assert_eq!(grants[0]["actions"], json!(["fill"]));
    assert_eq!(grants[0]["created_by_channel"], "cli");
    assert_eq!(
        without_expiry(grants.clone()),
        without_expiry(rig.status_grants())
    );

    // A cross-site POST with the session cookie, and a form post,
    // change nothing: the grant still fills.
    let body = json!({"grant_id": web}).to_string();
    let forged = http(
        rig.ui,
        "https://evil.example",
        Http::post("/owner/grants/revoke", Some("application/json"), &body).cookie(&rig.cookie),
    )
    .await;
    assert_eq!(forged.status, 403, "{}", forged.body);
    let form = http(
        rig.ui,
        &rig.origin,
        Http::post(
            "/owner/grants/revoke",
            Some("application/x-www-form-urlencoded"),
            &format!("grant_id={web}"),
        )
        .cookie(&rig.cookie),
    )
    .await;
    assert_eq!(form.status, 400, "{}", form.body);
    assert_eq!(rig.fill().await["status"], "filled");

    // A web revoke is effective for the next request (REQ-REV-001).
    let revoked = rig
        .decide("/owner/grants/revoke", &json!({"grant_id": web}))
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);
    assert_eq!(rig.grants().await.json()["grants"], json!([]));
    let r = rig.fill().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    let again = rig
        .decide("/owner/grants/revoke", &json!({"grant_id": web}))
        .await;
    assert_eq!(again.status, 404, "{}", again.body);
    assert!(again.body.contains("not_found"), "{}", again.body);

    // The CLI revokes the next grant through the same broker call:
    // the entries match apart from the channel.
    let cli = rig.per_origin_grant().await;
    assert!(rig.broker.revoke_grant(&cli, Channel::Cli).unwrap());
    let (w, c) = (rig.revokes_of(&web), rig.revokes_of(&cli));
    assert_eq!((w.len(), c.len()), (1, 1), "{w:?} {c:?}");
    assert_eq!(w[0].channel.as_deref(), Some("web_ui"));
    assert_eq!(w[0].result.as_deref(), Some("revoked"));
    assert_eq!(w[0].item_id.as_deref(), Some(ITEM_A));
    assert_eq!(c[0].channel.as_deref(), Some("cli"));
    assert_eq!(shape(&w[0]), shape(&c[0]));
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_revoke_keeps_the_grant_when_the_audit_append_fails() {
    let rig = ApprovalsRig::new().await;
    let id = rig.per_origin_grant().await;
    *rig.audit.fail_event.lock().unwrap() = Some("grant_revoke");
    let revoked = rig
        .decide("/owner/grants/revoke", &json!({"grant_id": id}))
        .await;
    assert_eq!(revoked.status, 500, "{}", revoked.body);
    assert!(revoked.body.contains("audit_failed"), "{}", revoked.body);
    *rig.audit.fail_event.lock().unwrap() = None;
    let grants = rig.grants().await.json()["grants"].clone();
    assert_eq!(grants[0]["id"], json!(id), "{grants}");
    assert_eq!(rig.fill().await["status"], "filled");
}

// ---- #131 slice 4: the audit tail ----

/// The audit tail over the real hash-chained log: it needs the passkey
/// session, it is GET-only, and it shows the web revoke the owner just
/// made, newest first, with the chain's own seq numbers. Item names
/// and chain hashes stay out of the page.
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_audit_tail_reads_the_real_log() {
    let rig = ApprovalsRig::with_audit_log().await;
    let anon = http(rig.ui, &rig.origin, Http::get("/owner/audit")).await;
    assert_eq!(anon.status, 401, "{}", anon.body);
    let post = rig.decide("/owner/audit", &json!({})).await;
    assert_eq!(post.status, 405, "{}", post.body);

    let grant = rig.per_origin_grant().await;
    let revoked = rig
        .decide("/owner/grants/revoke", &json!({"grant_id": grant}))
        .await;
    assert_eq!(revoked.status, 200, "{}", revoked.body);

    let tail = rig.audit().await;
    assert_eq!(tail.status, 200, "{}", tail.body);
    let v = tail.json();
    assert_eq!(v["ok"], true);
    let entries = v["entries"].as_array().unwrap();
    let events: Vec<&str> = entries
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        events,
        ["grant_revoke", "grant_issue", "fill", "grant_request"],
        "{entries:?}"
    );
    let seqs: Vec<u64> = entries.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, [4, 3, 2, 1]);
    let newest = &entries[0];
    assert_eq!(newest["grant_id"], json!(grant));
    assert_eq!(newest["channel"], "web_ui");
    assert_eq!(newest["result"], "revoked");
    assert_eq!(newest["agent_id"], "alpha");
    assert!(newest["ts"].as_str().is_some_and(|t| !t.is_empty()));
    assert_eq!(entries[1]["channel"], "cli");
    for e in entries {
        for absent in ["item_name", "item_name_hash", "prev_hash", "hash", "log_id"] {
            assert!(e.get(absent).is_none(), "{absent} in {e}");
        }
    }

    // Reading the tail is not itself audited.
    let again = rig.audit().await.json();
    assert_eq!(again["entries"].as_array().unwrap().len(), 4, "{again}");
}

/// The shell page's Revoke button, in a real browser: the grant row
/// shows the grant, and the click revokes it over `web_ui`.
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_chromium_revoke_click() {
    let Some(bin) = chromium_bin() else {
        if std::env::var_os("KHARON_REQUIRE_WEBAUTHN").is_some() {
            panic!("KHARON_REQUIRE_WEBAUTHN is set but no Chromium binary was found");
        }
        eprintln!("SKIP req_apr_005_chromium_revoke_click: no Chromium binary");
        return;
    };
    let rig = ApprovalsRig::new().await;
    let grant = rig.per_origin_grant().await;
    let token = rig.owner.mint_enroll_token();

    let chromium = launch_chromium(&bin);
    let mut cdp = Cdp::connect(&chromium.ws).await;
    let (session, _authenticator) =
        browser_register_and_sign_in(&mut cdp, &rig.origin, &token).await;
    let _ = cdp
        .eval_navigating(&session, &format!("location.assign({:?})", rig.origin))
        .await;
    let row = format!(
        "tr[data-grant-id={}]",
        serde_json::to_string(&grant).unwrap()
    );
    let sel = serde_json::to_string(&row).unwrap();
    let probe = format!(
        "JSON.stringify((() => {{ const r = document.querySelector({sel}); \
         return r ? Array.from(r.cells, c => c.textContent) : null; }})())"
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let cells = loop {
        let got = cdp
            .eval_navigating(&session, &probe)
            .await
            .unwrap_or(Json::Null);
        let cells: Json = serde_json::from_str(got.as_str().unwrap_or("null")).unwrap();
        if cells.is_array() {
            break cells;
        }
        assert!(
            Instant::now() < deadline,
            "the grants list never showed the grant"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(cells[0], "alpha", "{cells}");
    assert_eq!(cells[1], format!("item {ITEM_A}"), "{cells}");
    assert_eq!(cells[3], "fill", "{cells}");

    let click = format!(
        "(() => {{ const b = Array.from(document.querySelector({sel}).querySelectorAll('button')) \
         .find(b => b.textContent === 'Revoke'); b.click(); return true; }})()"
    );
    assert_eq!(cdp.eval(&session, &click).await, json!(true));
    let deadline = Instant::now() + Duration::from_secs(10);
    while rig.revokes_of(&grant).is_empty() {
        assert!(Instant::now() < deadline, "the click never revoked");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let revokes = rig.revokes_of(&grant);
    assert_eq!(revokes.len(), 1, "{revokes:?}");
    assert_eq!(revokes[0].channel.as_deref(), Some("web_ui"));
    assert_eq!(rig.fill().await["status"], "pending_approval");

    // The page refreshed its list after the revoke.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let n = cdp
            .eval(
                &session,
                "document.getElementById('grant-rows').children.length",
            )
            .await;
        if n == json!(0) {
            break;
        }
        assert!(Instant::now() < deadline, "the revoked row stayed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ... and its audit tail (#131 slice 4) shows the revoke on the
    // web channel. Not necessarily as the newest row: the fill above
    // appends after it, and the page may have refreshed in between.
    let probe = "JSON.stringify(Array.from(document.querySelectorAll('#audit-rows tr'), \
                 r => Array.from(r.cells, c => c.textContent)))";
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = cdp.eval(&session, probe).await;
        let rows: Json = serde_json::from_str(got.as_str().unwrap_or("[]")).unwrap();
        let revoke = rows
            .as_array()
            .into_iter()
            .flatten()
            .find(|cells| cells[2] == "grant_revoke");
        if let Some(cells) = revoke {
            assert_eq!(cells[3], "alpha", "{cells}");
            assert_eq!(cells[6], "web_ui", "{cells}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the audit tail never showed the revoke: {rows}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(cdp);
    drop(chromium);
}
