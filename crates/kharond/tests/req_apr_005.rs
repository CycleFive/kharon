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

mod api_support;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use api_support::{RawResponse, raw_request};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value;
use futures_util::{SinkExt, StreamExt};
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use kharond::owner_ui::ROUTES;
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
    let origin = &run.origin;
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    assert_eq!(minted["ok"], json!(true), "{minted}");
    let token = minted["enroll_token"].as_str().unwrap();
    let mut auth = VirtAuth::new();
    let opts = http(
        run.ui,
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
        run.ui,
        origin,
        Http::post("/owner/register/finish", Some("application/json"), &body),
    )
    .await;
    assert_eq!(registered.status, 200, "{}", registered.body);
    assert!(session_cookie(&registered).is_none());

    let login_opts = http(run.ui, origin, Http::post("/owner/login/options", None, "")).await;
    assert_eq!(login_opts.status, 200, "{}", login_opts.body);
    let login_opts: Json = serde_json::from_str(&login_opts.body).unwrap();
    let ceremony = login_opts["ceremony_id"].as_str().unwrap();
    let challenge = login_opts["publicKey"]["challenge"].as_str().unwrap();
    let assertion = auth.assertion(challenge, origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": assertion}).to_string();
    let ok = http(
        run.ui,
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
