//! REQ-API-012 on real Chromium: `kharon_open` navigates the saved
//! login URL, a following fill still needs its grant, and an item
//! with no verifiable URL is `no_login_url` with no new tab.
//!
//! Skips when no Chromium binary is found (as
//! `req_arch_005_default_context_tab_on_real_chromium` does).
//! `KHARON_CHROMIUM` names one, and `KHARON_REQUIRE_CHROMIUM=1` turns
//! the skip into a failure. The Chromium flags are for this
//! throwaway test browser only.

mod api_support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use api_support::{
    CHEAP_FLOOR, ITEM_A, ITEM_B, RecordingAudit, TestSession, cheap_argon, fixture, mcp_call,
    post_json, serve_http,
};
use base64ct::{Base64, Encoding};
use kharond::api::fill::FillPolicy;
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, Channel, GrantScope, GrantTerms};
use kharond::cdp::{CdpClient, CdpEndpoint, Tunnel};
use kharond::config::GrantKind;
use kharond::lock::{LockController, LockPolicy, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::sync::{ItemUri, SecretField, SyncReport, Vault};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PATH_CANARY: &str = "KHARON_OPEN_PATH_CANARY";
const QUERY_CANARY: &str = "KHARON_OPEN_QUERY_CANARY";
const FRAG_CANARY: &str = "KHARON_OPEN_FRAG_CANARY";

const PAGE: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>kharon open</title></head>
<body>
<form id="login" action="/submitted" method="post">
  <input id="username" name="username" type="email" autocomplete="username">
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
<script>
  document.getElementById("login").addEventListener("submit", (e) => e.preventDefault());
</script>
</body></html>
"#;

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

fn chromium_or_skip(test: &str) -> Option<PathBuf> {
    let bin = chromium_bin();
    if bin.is_none() {
        if std::env::var_os("KHARON_REQUIRE_CHROMIUM").is_some() {
            panic!("KHARON_REQUIRE_CHROMIUM is set but no Chromium binary was found");
        }
        eprintln!("SKIP {test}: no Chromium binary");
    }
    bin
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

fn launch_chromium(bin: &Path, host: &str, spki: &str) -> Chromium {
    let profile = tempfile::tempdir().unwrap();
    let mut child = Command::new(bin)
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--password-store=basic",
            "--no-proxy-server",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg(format!("--host-resolver-rules=MAP {host} 127.0.0.1"))
        .arg(format!("--ignore-certificate-errors-spki-list={spki}"))
        .arg("about:blank")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot launch Chromium at {}: {e}", bin.display()));
    let port_file = profile.path().join("DevToolsActivePort");
    let deadline = Instant::now() + Duration::from_secs(30);
    let ws = loop {
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                break format!("ws://127.0.0.1:{port}{path}");
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("Chromium exited {status} before DevTools opened");
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

async fn serve_page(host: &str) -> (u16, String) {
    let ck = rcgen::generate_simple_self_signed(vec![host.to_string()]).unwrap();
    let spki = Base64::encode_string(&Sha256::digest(ck.key_pair.public_key_der()));
    let cert = ck.cert.der().clone();
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PAGE}",
                    PAGE.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            });
        }
    });
    (port, spki)
}

fn no_canary(text: &str) {
    assert!(!text.contains(PATH_CANARY), "path canary leaked: {text}");
    assert!(!text.contains(QUERY_CANARY), "query canary leaked: {text}");
    assert!(
        !text.contains(FRAG_CANARY),
        "fragment canary leaked: {text}"
    );
}

async fn page_targets(ws: &str) -> usize {
    let endpoint = CdpEndpoint::validate(ws, Tunnel::Direct, None).unwrap();
    let client = CdpClient::connect(&endpoint).await.unwrap();
    let listed = client
        .request("Target.getTargets", json!({}))
        .await
        .unwrap();
    listed["targetInfos"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["type"] == "page")
        .count()
}

async fn wait_for_form(ws: &str, target: &str) {
    let endpoint = CdpEndpoint::validate(ws, Tunnel::Direct, None).unwrap();
    let client = CdpClient::connect(&endpoint).await.unwrap();
    let session = client.attach(target).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let ready = session
            .request(
                "Runtime.evaluate",
                json!({
                    "expression": "!!document.getElementById('username')",
                    "returnByValue": true,
                }),
            )
            .await
            .unwrap();
        if ready["result"]["value"] == json!(true) {
            session.detach().await;
            return;
        }
        assert!(Instant::now() < deadline, "login form did not appear");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn eval_fields(ws: &str, target: &str) -> (String, String) {
    let endpoint = CdpEndpoint::validate(ws, Tunnel::Direct, None).unwrap();
    let client = CdpClient::connect(&endpoint).await.unwrap();
    let session = client.attach(target).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let ready = session
            .request(
                "Runtime.evaluate",
                json!({
                    "expression": "!!document.getElementById('username')",
                    "returnByValue": true,
                }),
            )
            .await
            .unwrap();
        if ready["result"]["value"] == json!(true) {
            break;
        }
        assert!(Instant::now() < deadline, "login form did not appear");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = session
        .request(
            "Runtime.evaluate",
            json!({
                "expression": "JSON.stringify([document.getElementById('username').value, document.getElementById('password').value])",
                "returnByValue": true,
            }),
        )
        .await
        .unwrap();
    session.detach().await;
    let text = got["result"]["value"].as_str().unwrap();
    let v: Value = serde_json::from_str(text).unwrap();
    (
        v[0].as_str().unwrap().to_owned(),
        v[1].as_str().unwrap().to_owned(),
    )
}

fn broker_for(
    ws: &str,
    uris: Vec<ItemUri>,
    item_id: &str,
) -> (
    Arc<kharond::api::Broker<TestSession, Arc<kharond::lock::ManualClock>>>,
    String,
    RecordingAudit,
) {
    let (session, vault) = fixture();
    let item = vault.get(item_id).unwrap().with_uris(uris);
    let vault = Vault::with_report(vec![item], SyncReport::default());
    let (alpha, hash) = generate_with(&cheap_argon(), "alpha");
    let tokens = TokenStore::with_floor([("alpha", hash.as_str())], &CHEAP_FLOOR).unwrap();
    let endpoint = CdpEndpoint::validate(ws, Tunnel::Direct, None).unwrap();
    let backend = kharond::api::ConnectingCdpBackend::new([("alpha", endpoint)]);
    let clock = Arc::new(kharond::lock::ManualClock::new());
    let mut lock = LockController::new(
        LockPolicy::default(),
        clock,
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| Ok::<_, ()>(TestSession(Arc::new(vault), session.clone())))
        .unwrap();
    let audit = RecordingAudit::default();
    let broker = Broker::new(
        tokens,
        lock,
        Box::new(audit.clone()),
        OriginConfig::default(),
    )
    .with_fill_policy(FillPolicy {
        deadline: Duration::from_secs(45),
        ..FillPolicy::default()
    })
    .with_fill_backend(Box::new(backend));
    (Arc::new(broker), alpha.expose_secret().clone(), audit)
}

#[tokio::test]
async fn req_api_012_open_then_fill_on_real_chromium() {
    let Some(bin) = chromium_or_skip("req_api_012_open_then_fill_on_real_chromium") else {
        return;
    };
    let host = "app.example.com";
    let (port, spki) = serve_page(host).await;
    let chromium = launch_chromium(&bin, host, &spki);
    let saved = format!("https://{host}:{port}/{PATH_CANARY}?q={QUERY_CANARY}#{FRAG_CANARY}");
    let (broker, alpha, audit) = broker_for(
        &chromium.ws,
        vec![ItemUri {
            uri: saved,
            match_type: None,
        }],
        ITEM_B,
    );
    let addr = serve_http(broker.clone()).await;
    let body = format!(r#"{{"item_id":"{ITEM_B}"}}"#);
    let opened = post_json(addr, "/v1/open", Some(&alpha), &body).await;
    assert_eq!(opened.status, 200, "{}", opened.body);
    no_canary(&opened.body);
    let opened = opened.json();
    let target = opened["target_id"].as_str().unwrap().to_owned();
    let origin = opened["origin"].as_str().unwrap().to_owned();
    assert_eq!(origin, format!("https://{host}:{port}"));
    assert!(!origin.contains(PATH_CANARY));
    let audit_text = serde_json::to_string(&*audit.entries.lock().unwrap()).unwrap();
    no_canary(&audit_text);

    let (session, base) = fixture();
    let username = base.get(ITEM_B).unwrap().username().unwrap().to_owned();
    let password = session
        .decrypt_secret(base, ITEM_B, SecretField::Password)
        .unwrap();
    let password = String::from_utf8(password.to_vec()).unwrap();

    wait_for_form(&chromium.ws, &target).await;
    let fill = json!({
        "item_id": ITEM_B,
        "target": {"cdp_target_id": target, "expected_origin": origin},
        "fields": [{"kind": "username"}, {"kind": "password"}],
    });
    let first = post_json(addr, "/v1/fill", Some(&alpha), &fill.to_string()).await;
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(first.json()["status"], "pending_approval", "{}", first.body);
    let request_id = first.json()["grant_request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    broker
        .approve_grant_request(
            &request_id,
            &GrantTerms {
                scope: GrantScope::Item(ITEM_B.to_owned()),
                kind: GrantKind::PerOrigin,
                ttl: Some(Duration::from_secs(3600)),
                max_uses: Some(2),
            },
            Channel::Cli,
        )
        .unwrap();
    let second = post_json(addr, "/v1/fill", Some(&alpha), &fill.to_string()).await;
    assert_eq!(second.status, 200, "{}", second.body);
    assert_eq!(second.json()["status"], "filled", "{}", second.body);
    no_canary(&second.body);

    let (got_user, got_pass) = eval_fields(&chromium.ws, &target).await;
    assert!(
        got_user == username && got_pass == password,
        "the opened tab was not filled"
    );
}

#[tokio::test]
async fn req_api_012_no_login_url_does_not_navigate_on_real_chromium() {
    let Some(bin) = chromium_or_skip("req_api_012_no_login_url_does_not_navigate_on_real_chromium")
    else {
        return;
    };
    let host = "login.example.com";
    let (port, spki) = serve_page(host).await;
    let _ = port;
    let chromium = launch_chromium(&bin, host, &spki);
    let before = page_targets(&chromium.ws).await;
    let (broker, alpha, audit) = broker_for(
        &chromium.ws,
        vec![
            ItemUri {
                uri: format!("{host}/{PATH_CANARY}?q={QUERY_CANARY}"),
                match_type: None,
            },
            ItemUri {
                uri: format!("https://{host}/{PATH_CANARY}?q={QUERY_CANARY}#{FRAG_CANARY}"),
                match_type: Some(4),
            },
        ],
        ITEM_A,
    );
    let addr = serve_http(broker).await;
    let body = format!(r#"{{"item_id":"{ITEM_A}"}}"#);
    let refused = mcp_call(addr, Some(&alpha), "kharon_open", &body).await;
    assert_eq!(refused.status, 200, "{}", refused.body);
    let v = refused.json();
    assert_eq!(v["result"]["isError"], true, "{v}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"error\":\"no_login_url\""), "{text}");
    no_canary(text);
    no_canary(&refused.body);
    let audit_text = serde_json::to_string(&*audit.entries.lock().unwrap()).unwrap();
    no_canary(&audit_text);
    assert!(
        !audit_text.contains("open_dispatch"),
        "a refusal must not reach the browser: {audit_text}"
    );
    let after = page_targets(&chromium.ws).await;
    assert_eq!(before, after, "no_login_url created a tab");
}
