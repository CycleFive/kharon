//! #404: `kharon setup` end to end through the binary, against an
//! in-process mock Bitwarden server that serves the recorded Vaultwarden
//! sync fixture (`crates/kharon-bwcrypto/tests/fixtures/vaultwarden/`).
//!
//! - The non-interactive path: answers file plus flags, no terminal.
//! - The prompt path: the binary under `script(1)`, which gives it a
//!   pseudo terminal, with the answers typed into it.
//! - An `organization.` key: refused on entry with #403's message,
//!   before any request reaches the server.
//!
//! In every case the written config must load with kharond's own
//! startup checks, and neither the client secret nor the agent token may
//! appear on stdout or stderr.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);
// Placeholders and canaries; nothing here is a real key.
const CLIENT_ID: &str = "user.11111111-2222-4333-8444-555555555555";
const ORG_CLIENT_ID: &str = "organization.11111111-2222-4333-8444-555555555555";
const SECRET: &str = "CANARYmockSECRET";

fn sync_fixture() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(format!("{FIXTURE_DIR}/sync_fixture.json")).unwrap(),
    )
    .unwrap()
}

fn fixture_email() -> String {
    sync_fixture()["profile"]["email"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn fixture_org_and_coll() -> (String, String) {
    let s = sync_fixture();
    (
        s["profile"]["organizations"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned(),
        s["collections"][0]["id"].as_str().unwrap().to_owned(),
    )
}

/// Minimal Bitwarden: `connect/token` (checks the key) and `/api/sync`.
/// Returns the base URL and the log of request paths.
async fn serve() -> (String, Arc<Mutex<Vec<String>>>) {
    let sync = sync_fixture();
    let log = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log2 = log.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let sync = sync.clone();
            let log = log2.clone();
            tokio::spawn(async move {
                while let Some((method, path, body)) = read_req(&mut sock).await {
                    log.lock().unwrap().push(path.clone());
                    let (status, body) = match (method.as_str(), path.as_str()) {
                        ("POST", "/identity/connect/token") => {
                            let form: Vec<(String, String)> =
                                url::form_urlencoded::parse(body.as_bytes())
                                    .into_owned()
                                    .collect();
                            let get = |k: &str| {
                                form.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
                            };
                            if get("client_id") == Some(CLIENT_ID)
                                && get("client_secret") == Some(SECRET)
                            {
                                (
                                    200,
                                    serde_json::json!({"access_token": "tok", "expires_in": 3600,
                                    "token_type": "Bearer"})
                                    .to_string(),
                                )
                            } else {
                                (400, "{\"error\":\"invalid_client\"}".to_owned())
                            }
                        }
                        ("GET", p) if p.starts_with("/api/sync") => (200, sync.to_string()),
                        _ => (404, "{}".to_owned()),
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (format!("http://{addr}"), log)
}

async fn read_req(sock: &mut tokio::net::TcpStream) -> Option<(String, String, String)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut first = head.lines().next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let len: usize = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.trim().parse().unwrap())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    Some((
        method,
        path,
        String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string(),
    ))
}

fn me() -> String {
    format!(
        "{}:{}",
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw()
    )
}

fn key_json(dir: &Path, client_id: &str) -> PathBuf {
    let p = dir.join("in-key.json");
    std::fs::write(
        &p,
        format!(r#"{{"client_id":"{client_id}","client_secret":"{SECRET}"}}"#),
    )
    .unwrap();
    p
}

/// The host-layout flags that keep every file in `dir`, owned by us.
fn path_flags(dir: &Path) -> Vec<String> {
    vec![
        "--layout".into(),
        "host".into(),
        "--config".into(),
        dir.join("kharon.toml").display().to_string(),
        "--key-file".into(),
        dir.join("bw_api_key.json").display().to_string(),
        "--key-owner".into(),
        me(),
    ]
}

/// The config loads with kharond's startup checks; the token matches.
fn assert_config_ok(dir: &Path, agent: &str, token: &str) -> String {
    let path = dir.join("kharon.toml");
    let (cfg, _) =
        kharond::config::load_for_startup(&path, &kharond::config::StaticMlockProbe(Ok(())))
            .unwrap();
    kharond::daemon::check(&cfg).unwrap();
    let hash = cfg.agents[agent].token_hash.expose().clone();
    let store = kharond::api::token::TokenStore::new([(agent, hash.as_str())]).unwrap();
    assert_eq!(store.authenticate(token).unwrap(), agent);
    let (org, coll) = fixture_org_and_coll();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains(&format!("organization_id = \"{org}\"")),
        "{text}"
    );
    assert!(
        text.contains(&format!("collection_ids = [\"{coll}\"]")),
        "{text}"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.join("bw_api_key.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o400);
    text
}

#[tokio::test(flavor = "multi_thread")]
async fn req_404_non_interactive_setup_through_the_binary() {
    let (server, log) = serve().await;
    let dir = tempfile::tempdir().unwrap();
    let answers = dir.path().join("answers.toml");
    std::fs::write(
        &answers,
        format!(
            "server = \"{server}\"\nemail = \"{}\"\napi-key-json = \"{}\"\n\
             public-host = \"kharon.example.com\"\nntfy-topic = \"kharon-approvals\"\n",
            fixture_email(),
            key_json(dir.path(), CLIENT_ID).display()
        ),
    )
    .unwrap();
    let token_file = dir.path().join("agent-token");
    let out = tokio::task::spawn_blocking({
        let dir = dir.path().to_owned();
        let answers = answers.clone();
        let token_file = token_file.clone();
        move || {
            Command::new(env!("CARGO_BIN_EXE_kharon"))
                .arg("setup")
                .arg("--non-interactive")
                .arg("--answers")
                .arg(&answers)
                .args(path_flags(&dir))
                .arg("--agent-token-file")
                .arg(&token_file)
                // No controlling terminal: the token must go to the file.
                .stdin(Stdio::null())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "stderr: {stderr}");
    let token = std::fs::read_to_string(&token_file)
        .unwrap()
        .trim()
        .to_owned();
    assert!(token.starts_with("kh_agent_assistant_"));
    let text = assert_config_ok(dir.path(), "assistant", &token);
    assert!(text.contains("topic = \"kharon-approvals\""));
    for s in [SECRET, token.as_str()] {
        assert!(!stdout.contains(s) && !stderr.contains(s), "leaked");
        assert!(!text.contains(s));
    }
    assert!(
        stderr.contains("Organization: kharon-fixture-org"),
        "{stderr}"
    );
    let log = log.lock().unwrap().clone();
    assert_eq!(log[0], "/identity/connect/token");
    assert!(log[1].starts_with("/api/sync"));
}

#[tokio::test(flavor = "multi_thread")]
async fn req_404_org_key_refused_before_any_request() {
    let (server, log) = serve().await;
    let dir = tempfile::tempdir().unwrap();
    let key = key_json(dir.path(), ORG_CLIENT_ID);
    let out = tokio::task::spawn_blocking({
        let dir = dir.path().to_owned();
        move || {
            Command::new(env!("CARGO_BIN_EXE_kharon"))
                .args(["setup", "--non-interactive", "--server", &server, "--email"])
                .arg(fixture_email())
                .arg("--api-key-json")
                .arg(&key)
                .args(["--public-host", "kharon.example.com"])
                .args(path_flags(&dir))
                .arg("--agent-token-file")
                .arg(dir.join("agent-token"))
                .stdin(Stdio::null())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(kharond::sync::KeyTypeError::Organization.message()),
        "{stderr}"
    );
    assert!(!stderr.contains(SECRET));
    assert!(log.lock().unwrap().is_empty(), "no request with an org key");
    let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(left.len(), 1, "only the input key file");
}

fn sh_quote(p: &str) -> String {
    format!("'{}'", p.replace('\'', r"'\''"))
}

#[tokio::test(flavor = "multi_thread")]
async fn req_404_prompt_path_on_a_terminal() {
    let (server, _log) = serve().await;
    let dir = tempfile::tempdir().unwrap();
    let out_file = dir.path().join("stdout");
    let err_file = dir.path().join("stderr");
    let mut inner = vec![sh_quote(env!("CARGO_BIN_EXE_kharon")), "setup".into()];
    inner.extend(
        ["--account-exists", "--server", &server]
            .iter()
            .map(|s| sh_quote(s)),
    );
    inner.extend(path_flags(dir.path()).iter().map(|s| sh_quote(s)));
    let inner = format!(
        "{} >{} 2>{}",
        inner.join(" "),
        sh_quote(&out_file.display().to_string()),
        sh_quote(&err_file.display().to_string())
    );
    // One line per prompt, in order: email, client_id, client_secret,
    // agent id, cdp via, endpoint, public host, owner origin, ntfy url,
    // topic, ntfy token file.
    let typed = format!(
        "{}\n{CLIENT_ID}\n{SECRET}\nhermes\n\n\nkharon.example.com\n\n\nkharon-typed\n\n",
        fixture_email()
    );
    let run = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut child = Command::new("script")
            .args(["--quiet", "--return", "--command", &inner, "/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("script(1) from util-linux is needed for this test");
        let mut stdin = child.stdin.take().unwrap();
        for line in typed.split_inclusive('\n') {
            stdin.write_all(line.as_bytes()).unwrap();
            stdin.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
        // Keep stdin open until the child is done, so script(1) does not
        // hang up the terminal early.
        let out = child.wait_with_output().unwrap();
        drop(stdin);
        out
    })
    .await
    .unwrap();
    let tty = String::from_utf8_lossy(&run.stdout).into_owned();
    let stdout = std::fs::read_to_string(&out_file).unwrap_or_default();
    let stderr = std::fs::read_to_string(&err_file).unwrap_or_default();
    assert!(run.status.success(), "tty: {tty}\nstderr: {stderr}");
    // The token was on the terminal only.
    let token = tty
        .split_whitespace()
        .find(|w| w.starts_with("kh_agent_hermes_"))
        .unwrap_or_else(|| panic!("no token on the tty: {tty}"))
        .to_owned();
    let text = assert_config_ok(dir.path(), "hermes", &token);
    assert!(text.contains("topic = \"kharon-typed\""));
    for s in [SECRET, token.as_str()] {
        assert!(
            !stdout.contains(s) && !stderr.contains(s),
            "leaked to a file"
        );
        assert!(!text.contains(s));
    }
    // The questions went to the terminal, not to stdout or stderr.
    assert!(tty.contains("API key client_secret (not shown)"), "{tty}");
    assert!(!stdout.contains("client_secret") && !stderr.contains("client_secret"));
}
