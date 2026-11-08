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
//!
//! The panic cases (#131 slice 3) drive the same UI's
//! `POST /owner/panic`: session, `Origin` and a `{"confirm": true}`
//! body gate the broker's own `panic_lock` (REQ-REV-002), which
//! revokes every grant and locks; a failed `grant_revoke` append
//! does not undo the revocations (revoke-first, #135).

mod api_support;
mod owner_ui_support;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use api_support::{
    CHEAP_FLOOR, FakeAnswer, FakeFill, ITEM_A, RawResponse, RecordingAudit, TestBroker,
    TestSession, cheap_argon,
};
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
use kharond::owner_ui::unlock::seal_password;
use kharond::owner_ui::{NoAudit, OwnerApprovals, OwnerUi, ROUTES, ShellView, StaticShell};
use owner_ui_support::{
    Http, VirtAuth, b64url, b64url_dec, http, register_and_sign_in, session_cookie,
};
use serde_json::{Value as Json, json};
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

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_no_password_route() {
    // No password route. The only unlock routes are slice 5b's pair:
    // a live passkey session first, and ciphertext only on the wire
    // (`req_apr_005_web_unlock_*` below).
    for (method, path) in ROUTES {
        let blob = format!("{method} {path}").to_ascii_lowercase();
        assert!(!blob.contains("password"), "{blob}");
        assert!(
            !blob.contains("unlock")
                || blob == "post /owner/unlock/begin"
                || blob == "post /owner/unlock",
            "{blob}"
        );
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

    // The web unlock is no way in: without a session it is 401, and
    // no session is ever issued by it.
    let unlock = http(
        run.ui,
        &origin,
        Http::post(
            "/owner/unlock",
            Some("application/json"),
            r#"{"password":"hunter2"}"#,
        ),
    )
    .await;
    assert_eq!(unlock.status, 401, "{}", unlock.body);
    assert!(session_cookie(&unlock).is_none());
    assert!(!unlock.body.contains("hunter2"));

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

    /// The agent's own `kharon_status`, whole body.
    fn status(&self) -> Json {
        let agent = self.broker.authenticate(&self.alpha).unwrap();
        match self.broker.dispatch(&agent, Request::Status).unwrap() {
            Outcome::Status(s) => serde_json::to_value(s).unwrap(),
            other => panic!("expected a status, got {other:?}"),
        }
    }

    /// Whether the broker's lock controller reports locked.
    fn locked(&self) -> bool {
        self.broker.lock_controller().lock().unwrap().is_locked()
    }

    /// The `panic` audit entries (the lock sink's, when wired).
    fn panics(&self) -> Vec<kharond::audit::Entry> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event == kharond::audit::Event::Panic)
            .cloned()
            .collect()
    }

    /// `grant_revoke` entries written by a panic (`detail_code`).
    fn panic_revokes(&self) -> Vec<kharond::audit::Entry> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.event == kharond::audit::Event::GrantRevoke
                    && e.detail_code.as_deref() == Some("panic")
            })
            .cloned()
            .collect()
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

// ---- #131 slice 3: panic ----

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_panic_locks_and_revokes_everything() {
    let rig = ApprovalsRig::new().await;
    // Same wiring as the daemon: the lock sink owns the single
    // `panic` entry (REQ-AUD-003).
    rig.broker.wire_lock_audit();
    let grant = rig.per_origin_grant().await;
    assert_eq!(rig.fill().await["status"], "filled");

    // No session: refused, and nothing changes.
    let anon = http(
        rig.ui,
        &rig.origin,
        Http::post(
            "/owner/panic",
            Some("application/json"),
            &json!({"confirm": true}).to_string(),
        ),
    )
    .await;
    assert_eq!(anon.status, 401, "{}", anon.body);
    // A cross-site POST with the session cookie: refused too.
    let forged = http(
        rig.ui,
        "https://evil.example",
        Http::post(
            "/owner/panic",
            Some("application/json"),
            &json!({"confirm": true}).to_string(),
        )
        .cookie(&rig.cookie),
    )
    .await;
    assert_eq!(forged.status, 403, "{}", forged.body);
    // A form post, and a POST without the confirm step: refused.
    let form = http(
        rig.ui,
        &rig.origin,
        Http::post(
            "/owner/panic",
            Some("application/x-www-form-urlencoded"),
            "confirm=true",
        )
        .cookie(&rig.cookie),
    )
    .await;
    assert_eq!(form.status, 400, "{}", form.body);
    let unconfirmed = rig.decide("/owner/panic", &json!({"confirm": false})).await;
    assert_eq!(unconfirmed.status, 400, "{}", unconfirmed.body);
    assert!(!rig.locked());
    assert_eq!(rig.fill().await["status"], "filled");

    // The confirmed panic: every grant revoked, then locked.
    let panicked = rig.decide("/owner/panic", &json!({"confirm": true})).await;
    assert_eq!(panicked.status, 200, "{}", panicked.body);
    assert!(rig.locked());
    let status = rig.status();
    assert_eq!(status["locked"], json!(true), "{status}");
    assert_eq!(status["grants"], json!([]), "{status}");
    assert_eq!(rig.grants().await.json()["grants"], json!([]));

    // Exactly one `panic` entry, and the grant's revoke is the
    // panic's own (`detail_code: panic`), as the CLI path writes it.
    let panics = rig.panics();
    assert_eq!(panics.len(), 1, "{panics:?}");
    let revokes = rig.panic_revokes();
    assert_eq!(revokes.len(), 1, "{revokes:?}");
    assert_eq!(revokes[0].grant_id.as_deref(), Some(grant.as_str()));
    assert_eq!(revokes[0].result.as_deref(), Some("revoked"));

    // A fill now fails closed as `locked` (REQ-REV-002).
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
    let agent = rig.broker.authenticate(&rig.alpha).unwrap();
    let err = rig
        .broker
        .fill(&agent, req, tokio::time::Instant::now())
        .await
        .unwrap_err();
    assert_eq!(err, kharond::api::ApiError::LOCKED);
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_panic_keeps_grants_revoked_when_the_audit_append_fails() {
    let rig = ApprovalsRig::new().await;
    let _grant = rig.per_origin_grant().await;
    // Revoke-first (#135): a restriction's audit failure must never
    // undo it. The panic proceeds, the grants stay gone, the broker
    // locks, and the call still succeeds.
    *rig.audit.fail_event.lock().unwrap() = Some("grant_revoke");
    let panicked = rig.decide("/owner/panic", &json!({"confirm": true})).await;
    assert_eq!(panicked.status, 200, "{}", panicked.body);
    *rig.audit.fail_event.lock().unwrap() = None;
    assert!(rig.locked());
    assert_eq!(rig.status()["grants"], json!([]));
    assert_eq!(rig.grants().await.json()["grants"], json!([]));
}

/// The shell page's Panic button, in a real browser: the first
/// click only arms it, the second panics the broker.
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_chromium_panic_click() {
    let Some(bin) = chromium_bin() else {
        if std::env::var_os("KHARON_REQUIRE_WEBAUTHN").is_some() {
            panic!("KHARON_REQUIRE_WEBAUTHN is set but no Chromium binary was found");
        }
        eprintln!("SKIP req_apr_005_chromium_panic_click: no Chromium binary");
        return;
    };
    let rig = ApprovalsRig::new().await;
    let _grant = rig.per_origin_grant().await;
    let token = rig.owner.mint_enroll_token();

    let chromium = launch_chromium(&bin);
    let mut cdp = Cdp::connect(&chromium.ws).await;
    let (session, _authenticator) =
        browser_register_and_sign_in(&mut cdp, &rig.origin, &token).await;
    let _ = cdp
        .eval_navigating(&session, &format!("location.assign({:?})", rig.origin))
        .await;
    // Wait for the shell (the grants list shows the grant).
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let n = cdp
            .eval_navigating(
                &session,
                "document.getElementById('grant-rows').children.length",
            )
            .await
            .unwrap_or(Json::Null);
        if n == json!(1) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the grants list never showed the grant"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // First click arms the button and nothing else happens.
    assert_eq!(
        cdp.eval(&session, "document.getElementById('panic').click(); true")
            .await,
        json!(true)
    );
    let label = cdp
        .eval(&session, "document.getElementById('panic').textContent")
        .await;
    assert!(
        label.as_str().unwrap_or("").contains("Confirm panic"),
        "{label}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!rig.locked(), "the arming click panicked the broker");

    // Second click fires the panic.
    assert_eq!(
        cdp.eval(&session, "document.getElementById('panic').click(); true")
            .await,
        json!(true)
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !rig.locked() {
        assert!(Instant::now() < deadline, "the click never panicked");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(rig.status()["grants"], json!([]));

    // The page refreshed its grants list and shows the locked broker.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state = cdp
            .eval(
                &session,
                "JSON.stringify([document.getElementById('grant-rows').children.length, \
                 document.getElementById('locked').textContent])",
            )
            .await;
        let state: Json = serde_json::from_str(state.as_str().unwrap_or("[]")).unwrap();
        if state == json!([0, "locked"]) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the page never showed the panic: {state}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(cdp);
    drop(chromium);
}

// ---- #131 slice 5b: web unlock ----

/// The export fixture's password (the daemon in [`start`] runs in
/// export mode on that fixture).
const EXPORT_PASSWORD: &str = "kharon export fixture password 9";

/// One web unlock through the real listener: begin, seal `password`
/// to the attempt's key exactly as the shell does, finish.
async fn web_unlock(run: &Running, cookie: &str, password: &str) -> RawResponse {
    let begun = http(
        run.ui,
        &run.origin,
        Http::post("/owner/unlock/begin", Some("application/json"), "{}").cookie(cookie),
    )
    .await;
    assert_eq!(begun.status, 200, "{}", begun.body);
    let begun: Json = serde_json::from_str(&begun.body).unwrap();
    let server_pub = b64url_dec(begun["server_pub"].as_str().unwrap());
    let (client_pub, nonce, ciphertext) = seal_password(&server_pub, password).unwrap();
    let body = json!({
        "attempt_id": begun["attempt_id"],
        "client_pub": b64url(&client_pub),
        "nonce": b64url(&nonce),
        "ciphertext": b64url(&ciphertext),
    })
    .to_string();
    assert!(!body.contains(password), "the wire carries ciphertext only");
    http(
        run.ui,
        &run.origin,
        Http::post("/owner/unlock", Some("application/json"), &body).cookie(cookie),
    )
    .await
}

/// SPEC §8 "web UI after WebAuthn": the daemon's own unlock behind a
/// passkey session. A wrong password is `owner_auth_fail`
/// (`unlock_failed`, `web_ui`) and leaves the broker locked; the
/// right one unlocks it through the owner socket's path (the
/// `export_loaded` entry is that path's); a second is
/// `already_unlocked` and is not an auth failure.
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_unlock_through_the_owner_unlock_path() {
    let run = start(true).await;
    let cookie = enroll_and_sign_in(&run).await;
    assert_eq!(
        owner_op(&run.socket, &json!({"op":"status"}))["locked"],
        json!(true)
    );

    let wrong = web_unlock(&run, &cookie, "not the password").await;
    assert_eq!(wrong.status, 400, "{}", wrong.body);
    assert!(wrong.body.contains("unlock_failed"), "{}", wrong.body);
    assert_eq!(
        owner_op(&run.socket, &json!({"op":"status"}))["locked"],
        json!(true)
    );

    let right = web_unlock(&run, &cookie, EXPORT_PASSWORD).await;
    assert_eq!(right.status, 200, "{}", right.body);
    assert_eq!(
        owner_op(&run.socket, &json!({"op":"status"}))["locked"],
        json!(false)
    );
    let session = http(
        run.ui,
        &run.origin,
        Http::get("/owner/session").cookie(&cookie),
    )
    .await;
    let session: Json = serde_json::from_str(&session.body).unwrap();
    assert_eq!(session["locked"], json!(false), "{session}");

    let again = web_unlock(&run, &cookie, EXPORT_PASSWORD).await;
    assert_eq!(again.status, 409, "{}", again.body);
    assert!(again.body.contains("already_unlocked"), "{}", again.body);

    let audit = std::fs::read_to_string(run.data.path().join("audit/audit.jsonl")).unwrap();
    let entries: Vec<Json> = audit
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let fails: Vec<&Json> = entries
        .iter()
        .filter(|e| e["event"] == "owner_auth_fail" && e["detail_code"] == "unlock_failed")
        .collect();
    assert_eq!(fails.len(), 1, "{audit}");
    assert_eq!(fails[0]["channel"], "web_ui", "{audit}");
    assert_eq!(
        entries
            .iter()
            .filter(|e| e["event"] == "export_loaded")
            .count(),
        1,
        "{audit}"
    );
    assert!(!audit.contains(EXPORT_PASSWORD) && !audit.contains("not the password"));

    run.shutdown().await;
}

/// A cross-site POST and a spent attempt never reach the unlock
/// (session binding is covered by the unit tests).
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_web_unlock_refusals_change_nothing() {
    let run = start(true).await;
    let cookie = enroll_and_sign_in(&run).await;

    let forged = http(
        run.ui,
        "https://evil.example",
        Http::post("/owner/unlock/begin", Some("application/json"), "{}").cookie(&cookie),
    )
    .await;
    assert_eq!(forged.status, 403, "{}", forged.body);

    // An attempt begun by one session, spent by another.
    let begun = http(
        run.ui,
        &run.origin,
        Http::post("/owner/unlock/begin", Some("application/json"), "{}").cookie(&cookie),
    )
    .await;
    let begun: Json = serde_json::from_str(&begun.body).unwrap();
    let server_pub = b64url_dec(begun["server_pub"].as_str().unwrap());
    let (client_pub, nonce, ciphertext) = seal_password(&server_pub, EXPORT_PASSWORD).unwrap();
    let body = json!({
        "attempt_id": begun["attempt_id"],
        "client_pub": b64url(&client_pub),
        "nonce": b64url(&nonce),
        "ciphertext": b64url(&ciphertext),
    })
    .to_string();
    // A tampered ciphertext does not open, and spends the attempt.
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;
    let bad = json!({
        "attempt_id": begun["attempt_id"],
        "client_pub": b64url(&client_pub),
        "nonce": b64url(&nonce),
        "ciphertext": b64url(&tampered),
    })
    .to_string();
    let stolen = http(
        run.ui,
        &run.origin,
        Http::post("/owner/unlock", Some("application/json"), &bad).cookie(&cookie),
    )
    .await;
    assert_eq!(stolen.status, 400, "{}", stolen.body);
    // Burned: the intact ciphertext cannot spend it afterwards.
    let late = http(
        run.ui,
        &run.origin,
        Http::post("/owner/unlock", Some("application/json"), &body).cookie(&cookie),
    )
    .await;
    assert_eq!(late.status, 400, "{}", late.body);
    assert_eq!(
        owner_op(&run.socket, &json!({"op":"status"}))["locked"],
        json!(true)
    );

    run.shutdown().await;
}

/// The shell's unlock form in a real browser: WebCrypto seals the
/// master password to the attempt's key, so no request body the page
/// sends carries it. A wrong password shows `unlock_failed` and the
/// broker stays locked; the right one unlocks it and hides the form.
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_005_chromium_unlock_form() {
    let Some(bin) = chromium_bin() else {
        if std::env::var_os("KHARON_REQUIRE_WEBAUTHN").is_some() {
            panic!("KHARON_REQUIRE_WEBAUTHN is set but no Chromium binary was found");
        }
        eprintln!("SKIP req_apr_005_chromium_unlock_form: no Chromium binary");
        return;
    };
    let run = start(true).await;
    let origin = run.origin.clone();
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    let token = minted["enroll_token"].as_str().unwrap().to_owned();

    let chromium = launch_chromium(&bin);
    let mut cdp = Cdp::connect(&chromium.ws).await;
    let (session, _authenticator) = browser_register_and_sign_in(&mut cdp, &origin, &token).await;
    let _ = cdp
        .eval_navigating(&session, &format!("location.assign({origin:?})"))
        .await;
    // The shell renders the locked broker with the form shown.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let shown = cdp
            .eval_navigating(
                &session,
                "(() => { const f = document.getElementById('unlock'); return !!f && !f.hidden; })()",
            )
            .await
            .unwrap_or(Json::Null);
        if shown == json!(true) {
            break;
        }
        assert!(Instant::now() < deadline, "the unlock form never showed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Record every request body the page sends from here on.
    cdp.eval(
        &session,
        "window.__bodies = []; const f0 = window.fetch; \
         window.fetch = (u, o) => { window.__bodies.push(String((o && o.body) || '')); return f0(u, o); }; true",
    )
    .await;

    let submit = |pw: &str| {
        format!(
            "document.getElementById('unlock-master').value = {pw:?}; \
             document.getElementById('unlock').requestSubmit(); true"
        )
    };
    assert_eq!(
        cdp.eval(&session, &submit("not the password")).await,
        json!(true)
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let err = cdp
            .eval(&session, "document.getElementById('err').textContent")
            .await;
        if err.as_str().unwrap_or("").contains("unlock_failed") {
            break;
        }
        assert!(Instant::now() < deadline, "no unlock_failed shown: {err}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        owner_op(&run.socket, &json!({"op":"status"}))["locked"],
        json!(true)
    );

    assert_eq!(
        cdp.eval(&session, &submit(EXPORT_PASSWORD)).await,
        json!(true)
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while owner_op(&run.socket, &json!({"op":"status"}))["locked"] != json!(false) {
        assert!(
            Instant::now() < deadline,
            "the form never unlocked the broker"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state = cdp
            .eval(
                &session,
                "JSON.stringify([document.getElementById('locked').textContent, \
                 document.getElementById('unlock').hidden, \
                 document.getElementById('unlock-master').value])",
            )
            .await;
        let state: Json = serde_json::from_str(state.as_str().unwrap_or("[]")).unwrap();
        if state == json!(["unlocked", true, ""]) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the page never showed the unlock: {state}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let bodies = cdp.eval(&session, "JSON.stringify(window.__bodies)").await;
    let bodies: Vec<String> = serde_json::from_str(bodies.as_str().unwrap()).unwrap();
    assert!(
        bodies.iter().filter(|b| b.contains("ciphertext")).count() >= 2,
        "{bodies:?}"
    );
    for b in &bodies {
        assert!(
            !b.contains(EXPORT_PASSWORD) && !b.contains("not the password"),
            "a request carried the password: {b}"
        );
    }
    drop(cdp);
    drop(chromium);
    run.shutdown().await;
}
