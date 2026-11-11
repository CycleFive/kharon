//! REQ-APR-009 (#208): the owner web UI behind a public edge.
//!
//! `[owner_ui] public_origin` switches the UI to public mode. These
//! cases drive the real daemon with the raw HTTP client the other
//! owner-UI tests use.

mod api_support;
mod owner_ui_support;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kharond::audit::{Entry, Event};
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use owner_ui_support::{Http, VirtAuth, b64url_dec, http};
use serde_json::{Value as Json, json};

const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";
const PUBLIC_ORIGIN: &str = "https://kharon-owner.example.com";
const PUBLIC_HOST: &str = "kharon-owner.example.com";

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

/// A daemon whose owner UI is behind the edge (`public_origin`).
async fn start_public() -> Running {
    start_with(&format!(
        "[owner_ui]\nlisten = \"127.0.0.1:0\"\nrp_id = \"{PUBLIC_HOST}\"\npublic_origin = \"{PUBLIC_ORIGIN}\"\n"
    ))
    .await
}

/// A daemon with today's local owner UI.
async fn start_local() -> Running {
    start_with(
        "[owner_ui]\nlisten = \"127.0.0.1:0\"\nrp_id = \"localhost\"\norigin = \"http://localhost:1\"\n",
    )
    .await
}

async fn start_with(owner_ui: &str) -> Running {
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
{owner_ui}"#,
        data = data.path().display(),
        export = fixture().display(),
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let ui = d.owner_ui_addr().expect("owner UI bound");
    let origin = d.owner_ui_origin().expect("owner UI origin").to_owned();
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
    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
    }

    /// The raw audit log (empty when nothing was written yet).
    fn audit(&self) -> String {
        std::fs::read_to_string(self.data.path().join("audit/audit.jsonl")).unwrap_or_default()
    }

    /// Every `owner_auth_fail` entry so far, oldest first.
    fn auth_fails(&self) -> Vec<Entry> {
        self.audit()
            .lines()
            .map(|l| serde_json::from_str::<Entry>(l).unwrap())
            .filter(|e| e.event == Event::OwnerAuthFail)
            .collect()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_foreign_host_is_misdirected() {
    let run = start_public().await;
    assert_eq!(run.origin, PUBLIC_ORIGIN);
    let port_host = format!("{PUBLIC_HOST}:{}", run.ui.port());
    let upper = PUBLIC_HOST.to_ascii_uppercase();
    let with_443 = format!("{PUBLIC_HOST}:443");

    for host in [PUBLIC_HOST, with_443.as_str(), upper.as_str()] {
        let r = http(run.ui, &run.origin, Http::get("/").host(host)).await;
        assert_eq!(r.status, 200, "{host}: {}", r.body);
    }
    for (host, path) in [
        ("evil.example.com", "/"),
        (port_host.as_str(), "/"),
        ("evil.example.com", "/owner/approve/x"),
        ("evil.example.com", "/owner/deny/x"),
    ] {
        let r = http(run.ui, &run.origin, Http::get(path).host(host)).await;
        assert_eq!(r.status, 421, "{host} {path}: {}", r.body);
        assert!(r.body.contains(r#""error":"misdirected""#), "{}", r.body);
    }
    let audit = run.audit();
    assert!(!audit.contains("owner_auth_fail"), "{audit}");
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_local_mode_has_no_host_check() {
    let run = start_local().await;
    let r = http(run.ui, &run.origin, Http::get("/").host("anything.example")).await;
    assert_eq!(r.status, 200, "{}", r.body);
    run.shutdown().await;
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

const EVIL: &str = "https://evil.example";
const POSTS: [&str; 5] = [
    "/owner/login/options",
    "/owner/login/finish",
    "/owner/register/options",
    "/owner/register/finish",
    "/owner/logout",
];

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_public_posts_need_the_public_origin() {
    let run = start_public().await;
    for path in POSTS {
        let before = run.auth_fails().len();
        let none = http(
            run.ui,
            &run.origin,
            Http::post(path, None, "")
                .host(PUBLIC_HOST)
                .without_origin(),
        )
        .await;
        assert_eq!(none.status, 403, "{path} no Origin: {}", none.body);
        assert!(none.body.contains(r#""error":"origin""#), "{}", none.body);
        let evil = http(run.ui, EVIL, Http::post(path, None, "").host(PUBLIC_HOST)).await;
        assert_eq!(evil.status, 403, "{path} evil Origin: {}", evil.body);
        assert!(evil.body.contains(r#""error":"origin""#), "{}", evil.body);
        let fails = run.auth_fails();
        assert_eq!(fails.len(), before + 2, "{path}: one entry per refusal");
        for f in &fails[before..] {
            assert_eq!(f.detail_code.as_deref(), Some("origin"), "{f:?}");
        }
        let ok = http(
            run.ui,
            PUBLIC_ORIGIN,
            Http::post(path, None, "").host(PUBLIC_HOST),
        )
        .await;
        assert_ne!(ok.status, 403, "{path} public Origin: {}", ok.body);
        let origin_entries = run
            .auth_fails()
            .iter()
            .filter(|f| f.detail_code.as_deref() == Some("origin"))
            .count();
        assert_eq!(
            origin_entries,
            2 * (POSTS.iter().position(|p| *p == path).unwrap() + 1),
            "{path}: the right Origin adds no origin entry"
        );
    }
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_local_posts_without_origin_still_pass() {
    let run = start_local().await;
    let r = http(
        run.ui,
        &run.origin,
        Http::post("/owner/login/options", None, "").without_origin(),
    )
    .await;
    assert_eq!(r.status, 409, "{}", r.body);
    assert!(r.body.contains("no_credential"), "{}", r.body);
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_ntfy_redeem_takes_no_origin() {
    let run = start_public().await;
    let r = http(
        run.ui,
        &run.origin,
        Http::post("/owner/approve/AAAA", None, "")
            .host(PUBLIC_HOST)
            .without_origin(),
    )
    .await;
    assert_eq!(r.status, 410, "{}", r.body);
    assert!(run.auth_fails().is_empty());
    run.shutdown().await;
}

async fn garbage_finish(run: &Running, host: &str, headers: &[(&str, &str)]) {
    let mut req = Http::post("/owner/login/finish", Some("application/json"), "{}").host(host);
    for (n, v) in headers {
        req = req.header(n, v);
    }
    let r = http(run.ui, &run.origin, req).await;
    assert_ne!(r.status, 200, "{}", r.body);
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_auth_failures_carry_the_source_address() {
    let run = start_public().await;
    let ip = |run: &Running| run.auth_fails().last().map(|f| f.client_ip.clone());

    garbage_finish(&run, PUBLIC_HOST, &[("CF-Connecting-IP", "203.0.113.7")]).await;
    assert_eq!(ip(&run), Some(Some("203.0.113.7".to_owned())));
    garbage_finish(&run, PUBLIC_HOST, &[]).await;
    assert_eq!(ip(&run), Some(Some("127.0.0.1".to_owned())));
    garbage_finish(
        &run,
        PUBLIC_HOST,
        &[
            ("CF-Connecting-IP", "203.0.113.7"),
            ("CF-Connecting-IP", "203.0.113.8"),
        ],
    )
    .await;
    assert_eq!(ip(&run), Some(Some("127.0.0.1".to_owned())));
    assert_eq!(run.auth_fails().len(), 3);
    run.shutdown().await;

    let local = start_local().await;
    garbage_finish(&local, "localhost", &[("CF-Connecting-IP", "203.0.113.7")]).await;
    let fails = local.auth_fails();
    assert_eq!(fails.len(), 1, "{fails:?}");
    assert!(fails[0].client_ip.is_none(), "{:?}", fails[0]);
    local.shutdown().await;
}

/// The whole `Set-Cookie` value, when it sets a cookie called `name`.
fn set_cookie(resp: &api_support::RawResponse, name: &str) -> Option<String> {
    resp.headers.iter().find_map(|(k, v)| {
        (k.eq_ignore_ascii_case("set-cookie") && v.starts_with(&format!("{name}=")))
            .then(|| v.clone())
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_public_session_cookie_is_host_prefixed() {
    let run = start_public().await;
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    let enroll = minted["enroll_token"].as_str().unwrap().to_owned();
    let post = |path: &'static str, body: &str| {
        let body = body.to_owned();
        let ui = run.ui;
        async move {
            let b = body.as_str();
            let ct = (!b.is_empty()).then_some("application/json");
            http(ui, PUBLIC_ORIGIN, Http::post(path, ct, b).host(PUBLIC_HOST)).await
        }
    };

    let mut auth = VirtAuth::new();
    let opts = http(
        run.ui,
        PUBLIC_ORIGIN,
        Http::post("/owner/register/options", None, "")
            .host(PUBLIC_HOST)
            .bearer(&enroll),
    )
    .await;
    assert_eq!(opts.status, 200, "{}", opts.body);
    let opts: Json = serde_json::from_str(&opts.body).unwrap();
    auth.user_handle = b64url_dec(opts["publicKey"]["user"]["id"].as_str().unwrap());
    let reg = auth.registration(
        opts["publicKey"]["challenge"].as_str().unwrap(),
        PUBLIC_ORIGIN,
        PUBLIC_HOST,
    );
    let body = json!({"ceremony_id": opts["ceremony_id"], "credential": reg}).to_string();
    assert_eq!(post("/owner/register/finish", &body).await.status, 200);

    let lo = post("/owner/login/options", "").await;
    assert_eq!(lo.status, 200, "{}", lo.body);
    let lo: Json = serde_json::from_str(&lo.body).unwrap();
    let assertion = auth.assertion(
        lo["publicKey"]["challenge"].as_str().unwrap(),
        PUBLIC_ORIGIN,
        PUBLIC_HOST,
    );
    let body = json!({"ceremony_id": lo["ceremony_id"], "credential": assertion}).to_string();
    let ok = post("/owner/login/finish", &body).await;
    assert_eq!(ok.status, 200, "{}", ok.body);

    let header = set_cookie(&ok, "__Host-kharon_owner").expect("__Host- session cookie");
    assert!(set_cookie(&ok, "kharon_owner").is_none());
    for attr in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(header.contains(attr), "{attr} missing: {header}");
    }
    assert!(!header.to_ascii_lowercase().contains("domain"), "{header}");
    let token = header.split(';').next().unwrap().split_once('=').unwrap().1;

    let get = |cookie: String| {
        let ui = run.ui;
        async move {
            http(
                ui,
                PUBLIC_ORIGIN,
                Http::get("/owner/session")
                    .host(PUBLIC_HOST)
                    .cookie(&cookie),
            )
            .await
        }
    };
    assert_eq!(
        get(format!("__Host-kharon_owner={token}")).await.status,
        200
    );
    assert_eq!(get(format!("kharon_owner={token}")).await.status, 401);
    // A sibling subdomain can plant a part with no `=`; it must not
    // hide the session.
    assert_eq!(
        get(format!("x; __Host-kharon_owner={token}")).await.status,
        200
    );
    assert_eq!(
        get(format!("kharon_owner=junk; __Host-kharon_owner={token}"))
            .await
            .status,
        200
    );

    let out = http(
        run.ui,
        PUBLIC_ORIGIN,
        Http::post("/owner/logout", None, "")
            .host(PUBLIC_HOST)
            .cookie(&format!("__Host-kharon_owner={token}")),
    )
    .await;
    let cleared = set_cookie(&out, "__Host-kharon_owner").expect("logout clears the cookie");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    run.shutdown().await;
}

// ---- Sealed ceremonies (D7, AC5) ----

/// The `Origin` and `Host` of every call in this section.
fn pub_post<'a>(path: &'a str, body: &'a str) -> Http<'a> {
    let ct = (!body.is_empty()).then_some("application/json");
    Http::post(path, ct, body).host(PUBLIC_HOST)
}

/// Enrol a software passkey through the owner socket's code. Returns it
/// with the user handle already set.
async fn enroll_public(run: &Running) -> VirtAuth {
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    let enroll = minted["enroll_token"].as_str().unwrap().to_owned();
    let mut auth = VirtAuth::new();
    let opts = http(
        run.ui,
        PUBLIC_ORIGIN,
        pub_post("/owner/register/options", "").bearer(&enroll),
    )
    .await;
    assert_eq!(opts.status, 200, "{}", opts.body);
    let opts: Json = serde_json::from_str(&opts.body).unwrap();
    auth.user_handle = b64url_dec(opts["publicKey"]["user"]["id"].as_str().unwrap());
    let reg = auth.registration(
        opts["publicKey"]["challenge"].as_str().unwrap(),
        PUBLIC_ORIGIN,
        PUBLIC_HOST,
    );
    let body = json!({"ceremony_id": opts["ceremony_id"], "credential": reg}).to_string();
    let done = http(
        run.ui,
        PUBLIC_ORIGIN,
        pub_post("/owner/register/finish", &body),
    )
    .await;
    assert_eq!(done.status, 200, "{}", done.body);
    auth
}

/// `login/options` from `ip`: the whole reply.
async fn login_options(run: &Running, ip: &str) -> Json {
    let r = http(
        run.ui,
        PUBLIC_ORIGIN,
        pub_post("/owner/login/options", "").header("CF-Connecting-IP", ip),
    )
    .await;
    assert_eq!(r.status, 200, "{ip}: {}", r.body);
    serde_json::from_str(&r.body).unwrap()
}

fn login_body(auth: &mut VirtAuth, opts: &Json) -> String {
    let assertion = auth.assertion(
        opts["publicKey"]["challenge"].as_str().unwrap(),
        PUBLIC_ORIGIN,
        PUBLIC_HOST,
    );
    json!({"ceremony_id": opts["ceremony_id"], "credential": assertion}).to_string()
}

async fn finish(run: &Running, body: &str) -> api_support::RawResponse {
    http(run.ui, PUBLIC_ORIGIN, pub_post("/owner/login/finish", body)).await
}

fn has_session_cookie(r: &api_support::RawResponse) -> bool {
    set_cookie(r, "__Host-kharon_owner").is_some()
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_login_survives_a_flood_of_login_options() {
    let run = start_public().await;
    let mut auth = enroll_public(&run).await;
    let owner = login_options(&run, "198.51.100.1").await;

    for i in 0..2_000u32 {
        let ip = if i % 2 == 0 {
            format!("203.0.{}.{}", i / 256, i % 256)
        } else {
            format!("2001:db8:{i:x}::1")
        };
        login_options(&run, &ip).await;
    }
    for _ in 0..500 {
        login_options(&run, "192.0.2.9").await;
    }

    let ok = finish(&run, &login_body(&mut auth, &owner)).await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert!(has_session_cookie(&ok), "no session cookie");
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_a_used_ceremony_cannot_be_replayed() {
    let run = start_public().await;
    let mut auth = enroll_public(&run).await;
    let opts = login_options(&run, "198.51.100.1").await;
    let body = login_body(&mut auth, &opts);

    let first = finish(&run, &body).await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert!(has_session_cookie(&first));

    let again = finish(&run, &body).await;
    assert_eq!(again.status, 401, "{}", again.body);
    assert!(
        again.body.contains(r#""error":"bad_assertion""#),
        "{}",
        again.body
    );
    assert!(!has_session_cookie(&again), "a replay minted a session");
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_a_failed_finish_does_not_burn_the_ceremony() {
    let run = start_public().await;
    let mut auth = enroll_public(&run).await;
    let opts = login_options(&run, "198.51.100.1").await;
    let good = login_body(&mut auth, &opts);

    // One signature byte flipped.
    let mut value: Json = serde_json::from_str(&good).unwrap();
    let sig = value["credential"]["response"]["signature"]
        .as_str()
        .unwrap();
    let mut raw = b64url_dec(sig);
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    value["credential"]["response"]["signature"] = json!(owner_ui_support::b64url(&raw));
    let bad = finish(&run, &value.to_string()).await;
    assert_eq!(bad.status, 401, "{}", bad.body);
    assert!(
        bad.body.contains(r#""error":"bad_assertion""#),
        "{}",
        bad.body
    );
    assert!(!has_session_cookie(&bad));

    let ok = finish(&run, &good).await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert!(has_session_cookie(&ok));
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_ceremony_kinds_do_not_cross() {
    let run = start_public().await;
    let mut auth = enroll_public(&run).await;
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    let enroll = minted["enroll_token"].as_str().unwrap().to_owned();
    let reg = http(
        run.ui,
        PUBLIC_ORIGIN,
        pub_post("/owner/register/options", "").bearer(&enroll),
    )
    .await;
    assert_eq!(reg.status, 200, "{}", reg.body);
    let reg: Json = serde_json::from_str(&reg.body).unwrap();

    // A register ceremony's id, with an assertion over its challenge.
    let body = login_body(&mut auth, &reg);
    let r = finish(&run, &body).await;
    assert_eq!(r.status, 401, "{}", r.body);
    assert!(r.body.contains(r#""error":"bad_assertion""#), "{}", r.body);
    assert!(!has_session_cookie(&r));

    // And a login ceremony's id sent to register/finish.
    let opts = login_options(&run, "198.51.100.1").await;
    let attestation = auth.registration(
        opts["publicKey"]["challenge"].as_str().unwrap(),
        PUBLIC_ORIGIN,
        PUBLIC_HOST,
    );
    let body = json!({"ceremony_id": opts["ceremony_id"], "credential": attestation}).to_string();
    let r = http(
        run.ui,
        PUBLIC_ORIGIN,
        pub_post("/owner/register/finish", &body),
    )
    .await;
    assert_eq!(r.status, 401, "{}", r.body);
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_panic_ends_ceremonies_in_flight() {
    let run = start_public().await;
    let mut auth = enroll_public(&run).await;

    // The owner socket's panic.
    let opts = login_options(&run, "198.51.100.1").await;
    let body = login_body(&mut auth, &opts);
    let panicked = owner_op(&run.socket, &json!({"op":"panic"}));
    assert_eq!(panicked["ok"], json!(true), "{panicked}");
    let r = finish(&run, &body).await;
    assert_eq!(r.status, 401, "{}", r.body);
    assert!(r.body.contains(r#""error":"bad_assertion""#), "{}", r.body);
    let fresh = login_options(&run, "198.51.100.1").await;
    let signed_in = finish(&run, &login_body(&mut auth, &fresh)).await;
    assert_eq!(signed_in.status, 200, "{}", signed_in.body);
    let cookie = set_cookie(&signed_in, "__Host-kharon_owner").expect("session cookie");
    let cookie = cookie.split(';').next().unwrap().to_owned();

    // The web route.
    let opts = login_options(&run, "198.51.100.1").await;
    let body = login_body(&mut auth, &opts);
    let r = http(
        run.ui,
        PUBLIC_ORIGIN,
        pub_post("/owner/panic", r#"{"confirm":true}"#).cookie(&cookie),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = finish(&run, &body).await;
    assert_eq!(r.status, 401, "{}", r.body);
    assert!(r.body.contains(r#""error":"bad_assertion""#), "{}", r.body);
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_odd_ceremony_ids_are_refused_cleanly() {
    let run = start_public().await;
    let mut auth = enroll_public(&run).await;
    let opts = login_options(&run, "198.51.100.1").await;
    let assertion = auth.assertion(
        opts["publicKey"]["challenge"].as_str().unwrap(),
        PUBLIC_ORIGIN,
        PUBLIC_HOST,
    );
    let old_style = "A".repeat(43);
    let long = "a".repeat(5_000);
    for id in [long.as_str(), "é.é", old_style.as_str()] {
        let body = json!({"ceremony_id": id, "credential": assertion}).to_string();
        let r = finish(&run, &body).await;
        assert_eq!(r.status, 401, "{}", r.body);
        assert!(r.body.contains(r#""error":"bad_assertion""#), "{}", r.body);
    }
    run.shutdown().await;
}

/// A `webauthn.get` assertion with the counter at 0, the way a synced
/// passkey signs. `VirtAuth::assertion` always bumps the counter, which
/// would let the WebAuthn counter rule refuse a replay on its own.
fn zero_count_assertion(auth: &mut VirtAuth, challenge: &str) -> Json {
    use aws_lc_rs::rand::SystemRandom;
    use sha2::{Digest, Sha256};
    auth.sign_count = 0;
    let client = auth.client_data("webauthn.get", challenge, PUBLIC_ORIGIN);
    let data = auth.auth_data(PUBLIC_HOST, false);
    let mut message = data.clone();
    message.extend_from_slice(&Sha256::digest(client.as_bytes()));
    let sig = auth.key.sign(&SystemRandom::new(), &message).unwrap();
    json!({
        "id": owner_ui_support::b64url(&auth.cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": owner_ui_support::b64url(client.as_bytes()),
            "authenticatorData": owner_ui_support::b64url(&data),
            "signature": owner_ui_support::b64url(sig.as_ref()),
            "userHandle": owner_ui_support::b64url(&auth.user_handle),
        },
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_only_the_used_set_refuses_a_replay() {
    let run = start_public().await;
    let mut auth = enroll_public(&run).await;

    // Login: the counter stays 0, so the WebAuthn counter rule accepts
    // the replay and only the used-set can refuse it.
    let opts = login_options(&run, "198.51.100.1").await;
    let assertion =
        zero_count_assertion(&mut auth, opts["publicKey"]["challenge"].as_str().unwrap());
    let body = json!({"ceremony_id": opts["ceremony_id"], "credential": assertion}).to_string();
    let first = finish(&run, &body).await;
    assert_eq!(first.status, 200, "{}", first.body);
    let again = finish(&run, &body).await;
    assert_eq!(again.status, 401, "{}", again.body);
    assert!(
        again.body.contains(r#""error":"bad_assertion""#),
        "{}",
        again.body
    );
    assert!(!has_session_cookie(&again));

    // Register: a replayed finish must not store the credential again.
    let minted = owner_op(&run.socket, &json!({"op":"passkey_enroll"}));
    let enroll = minted["enroll_token"].as_str().unwrap().to_owned();
    let opts = http(
        run.ui,
        PUBLIC_ORIGIN,
        pub_post("/owner/register/options", "").bearer(&enroll),
    )
    .await;
    assert_eq!(opts.status, 200, "{}", opts.body);
    let opts: Json = serde_json::from_str(&opts.body).unwrap();
    let mut second = VirtAuth::new();
    second.cred_id = vec![0x22; 16];
    second.user_handle = auth.user_handle.clone();
    let reg = second.registration(
        opts["publicKey"]["challenge"].as_str().unwrap(),
        PUBLIC_ORIGIN,
        PUBLIC_HOST,
    );
    let body = json!({"ceremony_id": opts["ceremony_id"], "credential": reg}).to_string();
    let post = |body: String| {
        let ui = run.ui;
        async move { http(ui, PUBLIC_ORIGIN, pub_post("/owner/register/finish", &body)).await }
    };
    let first = post(body.clone()).await;
    assert_eq!(first.status, 200, "{}", first.body);
    let again = post(body).await;
    assert_eq!(again.status, 401, "{}", again.body);
    assert!(
        again.body.contains(r#""error":"bad_assertion""#),
        "{}",
        again.body
    );
    run.shutdown().await;
}
