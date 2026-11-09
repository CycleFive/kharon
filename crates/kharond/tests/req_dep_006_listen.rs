//! REQ-DEP-006: the agent API binds only the configured address and
//! wildcard binds are refused; plus the daemon serve path (#14): a
//! configured loopback listen serves `/v1/status`, booted locked
//! (REQ-MEM-005), so vault calls answer 423.

mod api_support;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};

use api_support::get;
use kharond::api::token::{generate, generate_tunnel};
use kharond::config::{Config, StaticMlockProbe};
use kharond::connector::connect_pinned;
use kharond::daemon::{self, StartupError};
use kharond::lock::{HardeningError, StaticHardening};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOKEN_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo";

/// A servable export-mode config: local-only checkpoints (the
/// off-host ntfy sink is exercised in req_aud_002_offhost), no mlock
/// requirement, `data_dir` and `[api]` as given.
/// The export file is the real password-protected fixture from #12:
/// since REQ-EXP-002 the daemon classifies the export file at
/// startup, so a dummy path no longer boots.
fn config(hash: &str, data_dir: &Path, api: &str) -> String {
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.assistant]
token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9222" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

{api}"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        )
    )
}

/// Tests that bind listeners hold this, so the listener-set diff in
/// `req_dep_006_binary_without_api_serves_public_mcp` sees only its own.
static LISTENERS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn listen(addr: &str) -> String {
    format!("[api]\nlisten = \"{addr}\"\n")
}

const WILDCARDS: [&str; 5] = [
    "0.0.0.0:8787",
    "0.0.0.0:0",
    "[::]:8787",
    "[::]:0",
    "[::ffff:0.0.0.0]:8787",
];

#[test]
fn req_dep_006_wildcard_listen_refused() {
    for addr in WILDCARDS {
        let err = Config::from_toml_str(&config(TOKEN_HASH, Path::new("/data"), &listen(addr)))
            .expect_err(addr);
        assert_eq!(err.code(), "api_wildcard_bind", "{addr}: {err:?}");
    }
}

#[test]
fn req_dep_006_non_unicast_or_non_literal_listen_refused() {
    for (addr, code) in [
        ("224.0.0.1:8787", "api_listen_not_unicast"),
        ("255.255.255.255:8787", "api_listen_not_unicast"),
        ("[ff02::1]:8787", "api_listen_not_unicast"),
        ("localhost:8787", "api_listen_invalid"),
        ("10.66.0.1", "api_listen_invalid"),
        ("*:8787", "api_listen_invalid"),
        ("", "api_listen_invalid"),
    ] {
        let err = Config::from_toml_str(&config(TOKEN_HASH, Path::new("/data"), &listen(addr)))
            .expect_err(addr);
        assert_eq!(err.code(), code, "{addr}: {err:?}");
    }
}

#[test]
fn req_dep_006_specific_addresses_accepted() {
    for addr in [
        "10.66.0.1:8787",
        "127.0.0.1:0",
        "[::1]:8787",
        "[fd00:66::1]:8787",
    ] {
        let cfg = Config::from_toml_str(&config(TOKEN_HASH, Path::new("/data"), &listen(addr)))
            .unwrap_or_else(|e| panic!("{addr}: {e}"));
        assert_eq!(cfg.api.unwrap().listen, addr.parse::<SocketAddr>().unwrap());
    }
}

#[test]
fn req_dep_006_data_dir_defaults_to_compose_volume() {
    let text = config(TOKEN_HASH, Path::new("/x"), "").replace("data_dir = \"/x\"\n", "");
    let cfg = Config::from_toml_str(&text).unwrap();
    assert_eq!(cfg.data_dir, Path::new("/data"));
    assert!(cfg.api.is_none());
}

fn run(args: &[&str], text: &str) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kharon.toml");
    std::fs::write(&path, text).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_kharond"))
        .args(args)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The binary's serve path (no `--check`) refuses before binding.
#[test]
fn req_dep_006_daemon_refuses_wildcard_bind() {
    let data = tempfile::tempdir().unwrap();
    for addr in WILDCARDS {
        let text = config(TOKEN_HASH, data.path(), &listen(addr));
        for args in [&[][..], &["--check"][..]] {
            let (code, stderr) = run(args, &text);
            assert_eq!(code, Some(78), "{addr} {args:?}: {stderr}");
            assert!(
                stderr.contains("config error [api_wildcard_bind]"),
                "{addr}: {stderr}"
            );
            assert!(!stderr.contains("listening"), "{stderr}");
        }
    }
    // Refused at config load: nothing was written under data_dir.
    assert_eq!(std::fs::read_dir(data.path()).unwrap().count(), 0);
}

/// Neither `[api]` nor `[public_ingress]`: agents have no way in, so the
/// daemon refuses (an `[owner_ui]` alone is not an agent listener).
#[test]
fn req_dep_006_daemon_refuses_no_agent_listener() {
    let data = tempfile::tempdir().unwrap();
    let text = config(
        TOKEN_HASH,
        data.path(),
        "[owner_ui]\nlisten = \"127.0.0.1:8788\"\norigin = \"http://localhost:8788\"\n",
    );
    for args in [&[][..], &["--check"][..]] {
        let (code, stderr) = run(args, &text);
        assert_eq!(code, Some(78), "{args:?}: {stderr}");
        assert!(
            stderr.contains("startup error [no_agent_listener]"),
            "{stderr}"
        );
    }
}

fn public(listen: &str) -> String {
    format!("[public_ingress]\nlisten = \"{listen}\"\n")
}

/// `[public_ingress]` alone is an agent listener: `--check` passes and
/// says the agent API is off.
#[test]
fn req_dep_006_check_reports_agent_api_off() {
    let data = tempfile::tempdir().unwrap();
    let (code, stderr) = run(
        &["--check"],
        &config(TOKEN_HASH, data.path(), &public("127.0.0.1:0")),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains("config ok (1 agent(s), agent API off)"),
        "{stderr}"
    );
    assert_eq!(std::fs::read_dir(data.path()).unwrap().count(), 0);
}

/// Path B (`via = "agent_connector"`) with `[connector]` and no `[api]`.
#[test]
fn req_dep_006_check_path_b_without_api() {
    let dir = tempfile::tempdir().unwrap();
    let (_pin, cert, key) = write_cert(dir.path());
    let data = dir.path().join("data");
    let text = path_b_config(
        TOKEN_HASH,
        TOKEN_HASH,
        &data,
        "127.0.0.1:0",
        Some((&cert, &key)),
        "127.0.0.2:0",
    );
    // Drop the [api] block entirely: its listen line and its tls keys.
    let start = text.find("[api]").unwrap();
    let end = text.find("[connector]").unwrap();
    let text = format!(
        "{}{}{}",
        &text[..start],
        public("127.0.0.1:0"),
        &text[end..]
    );
    assert!(!text.contains("[api]"), "{text}");
    let (code, stderr) = run(&["--check"], &text);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains("config ok (1 agent(s), agent API off)"),
        "{stderr}"
    );
}

/// Local addresses of every TCP listener on the host.
fn listeners() -> Vec<String> {
    let ss = Command::new("ss")
        .arg("-ltnH")
        .output()
        .expect("`ss` (iproute2) is required for this test");
    assert!(ss.status.success(), "ss failed: {ss:?}");
    String::from_utf8_lossy(&ss.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().nth(3).map(str::to_owned))
        .collect()
}

/// Binary path with no `[api]`: only the public ingress listens, it
/// serves `/mcp`, and SIGTERM still exits 0 (nothing else awaits the
/// shutdown future).
#[tokio::test(flavor = "multi_thread")]
async fn req_dep_006_binary_without_api_serves_public_mcp() {
    let _bind_lock = LISTENERS.lock().await;
    let (token, hash) = generate("assistant");
    let token = token.expose_secret().clone();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let path = dir.path().join("kharon.toml");
    std::fs::write(&path, config(&hash, &data, &public("127.0.0.1:0"))).unwrap();
    let before = listeners();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kharond"))
        .arg("--config")
        .arg(&path)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let addr: SocketAddr = tokio::task::spawn_blocking(move || {
        let mut seen = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(stderr.read_line(&mut line).unwrap(), 0, "exited: {seen}");
            if let Some(rest) = line.strip_prefix("kharond: public ingress listening on ") {
                assert!(
                    seen.contains(
                        "kharond: agent API off (no [api]; agents reach POST /mcp on [public_ingress])\n"
                    ),
                    "{seen}"
                );
                assert!(!seen.contains("agent API listening"), "{seen}");
                let addr = rest.split(" (").next().unwrap();
                std::thread::spawn(move || std::io::copy(&mut stderr, &mut std::io::sink()));
                return addr.parse().unwrap();
            }
            seen.push_str(&line);
        }
    })
    .await
    .unwrap();

    let init = r#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;
    let json_ct = ("Content-Type", "application/json");
    let r = api_support::post_mcp_raw(addr, None, &[json_ct], init).await;
    assert_eq!(r.status, 401, "{}", r.body);
    let r = api_support::post_mcp_raw(addr, Some(&token), &[json_ct], init).await;
    assert_eq!(r.status, 200, "{}", r.body);

    // kharond is non-dumpable (REQ-MEM-001), so `ss -p` cannot name its
    // sockets; diff the listener set against the baseline instead.
    let new: Vec<String> = listeners()
        .into_iter()
        .filter(|l| !before.contains(l))
        .collect();
    assert_eq!(new, vec![addr.to_string()], "new TCP listeners");

    let st = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .unwrap();
    assert!(st.success());
    let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    assert_eq!(status.code(), Some(0), "{status:?}");
}

/// Off-host checkpoints (the SPEC default) are served by the ntfy
/// checkpoint sink since #127: a config with `[approval].ntfy` and no
/// local-only opt-out passes `--check`. (Before #127 this was refused
/// as unimplemented; sink construction failures still fail closed at
/// serve time — see req_aud_002_offhost.)
#[test]
fn req_dep_006_daemon_accepts_ntfy_off_host_checkpoints() {
    let data = tempfile::tempdir().unwrap();
    let text = config(TOKEN_HASH, data.path(), &listen("127.0.0.1:0")).replace(
        "[audit]\ncheckpoint_local_only = true\n",
        "[approval]\nntfy = { url = \"https://ntfy.example.net\", topic = \"kharon\" }\n",
    );
    let (code, stderr) = run(&["--check"], &text);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("config ok"), "{stderr}");
}

#[test]
fn req_dep_006_check_reports_listen_address() {
    let data = tempfile::tempdir().unwrap();
    let (code, stderr) = run(
        &["--check"],
        &config(TOKEN_HASH, data.path(), &listen("10.66.0.1:8787")),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains("config ok (1 agent(s), agent API on 10.66.0.1:8787)"),
        "{stderr}"
    );
    // --check neither binds nor touches data_dir.
    assert_eq!(std::fs::read_dir(data.path()).unwrap().count(), 0);
}

/// Library path: a configured loopback listen on port 0 serves
/// `/v1/status`, locked, and only on the configured address.
#[tokio::test(flavor = "multi_thread")]
async fn req_dep_006_loopback_listen_serves_status() {
    let _bind_lock = LISTENERS.lock().await;
    let (token, hash) = generate("assistant");
    let token = token.expose_secret().clone();
    let data = tempfile::tempdir().unwrap();
    let cfg = Config::from_toml_str(&config(&hash, data.path(), &listen("127.0.0.1:0"))).unwrap();

    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let addr = d.local_addr().unwrap();
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
    assert_ne!(addr.port(), 0);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));

    let r = get(addr, "/v1/status", Some(&token)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.json(),
        json!({"locked": true, "agent_id": "assistant", "grants": [], "browser_context_id": null})
    );
    // REQ-MEM-005: booted locked, so vault calls are 423.
    let r = get(addr, "/v1/items", Some(&token)).await;
    assert_eq!(r.status, 423, "{}", r.body);
    assert_eq!(get(addr, "/v1/status", None).await.status, 401);

    // Audit state lives under <data_dir>/audit, owner-only.
    let audit = data.path().join("audit");
    assert!(audit.join("audit.jsonl").is_file());
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&audit).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// Hardening failures refuse startup before anything is bound.
#[tokio::test]
async fn req_dep_006_hardening_failure_refuses_start() {
    let data = tempfile::tempdir().unwrap();
    let mut text = config(TOKEN_HASH, data.path(), &listen("127.0.0.1:0"));
    let cfg = Config::from_toml_str(&text).unwrap();
    let err = daemon::start(
        &cfg,
        Box::new(StaticHardening {
            harden: Err(HardeningError::Unsupported),
            mlock: Ok(()),
            non_dumpable: true,
        }),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, StartupError::Harden(_)), "{err:?}");
    assert_eq!(err.exit_code(), 71);

    text = text.replace("require_mlock = false", "require_mlock = true");
    let cfg = Config::from_toml_str(&text).unwrap();
    let err = daemon::start(
        &cfg,
        Box::new(StaticHardening {
            harden: Ok(()),
            mlock: Err(HardeningError::Os("EPERM".into())),
            non_dumpable: true,
        }),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.code(), "mlock_failed");
    assert_eq!(std::fs::read_dir(data.path()).unwrap().count(), 0);
}

/// Binary path, end to end: `kharond --config` with a loopback port-0
/// listen announces its address, serves `/v1/status` locked, and exits
/// 0 on SIGTERM.
#[tokio::test(flavor = "multi_thread")]
async fn req_dep_006_daemon_binary_serves_status_on_loopback() {
    let _bind_lock = LISTENERS.lock().await;
    let (token, hash) = generate("assistant");
    let token = token.expose_secret().clone();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let path = dir.path().join("kharon.toml");
    std::fs::write(&path, config(&hash, &data, &listen("127.0.0.1:0"))).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kharond"))
        .arg("--config")
        .arg(&path)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let addr: SocketAddr = tokio::task::spawn_blocking(move || {
        let mut seen = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(stderr.read_line(&mut line).unwrap(), 0, "exited: {seen}");
            if let Some(rest) = line.strip_prefix("kharond: agent API listening on ") {
                let addr = rest.trim_end().strip_suffix(" (locked)").unwrap();
                // Keep draining so the child never blocks on a full pipe.
                std::thread::spawn(move || std::io::copy(&mut stderr, &mut std::io::sink()));
                return addr.parse().unwrap();
            }
            seen.push_str(&line);
        }
    })
    .await
    .unwrap();
    assert!(addr.ip().is_loopback(), "{addr}");

    let r = get(addr, "/v1/status", Some(&token)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.json(),
        json!({"locked": true, "agent_id": "assistant", "grants": [], "browser_context_id": null})
    );
    assert_eq!(get(addr, "/v1/items?q=x", Some(&token)).await.status, 423);

    let st = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(st.success());
    let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    assert_eq!(status.code(), Some(0), "{status:?}");
}

fn path_b_config(
    api_hash: &str,
    tunnel_hash: &str,
    data_dir: &Path,
    api_listen: &str,
    tls: Option<(&Path, &Path)>,
    connector_listen: &str,
) -> String {
    let tls_keys = match tls {
        Some((cert, key)) => format!(
            "tls_cert_file = \"{}\"\ntls_key_file = \"{}\"\n",
            cert.display(),
            key.display()
        ),
        None => String::new(),
    };
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.assistant]
token_hash = "{api_hash}"
connector_token_hash = "{tunnel_hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "{api_listen}"
{tls_keys}
[connector]
listen = "{connector_listen}"
tls_cert_file = "{cert}"
tls_key_file = "{key}"
"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        ),
        cert = tls
            .map(|(c, _)| c.display().to_string())
            .unwrap_or_else(|| "/tmp/missing-cert.pem".into()),
        key = tls
            .map(|(_, k)| k.display().to_string())
            .unwrap_or_else(|| "/tmp/missing-key.pem".into()),
    )
}

fn write_cert(dir: &Path) -> ([u8; 32], std::path::PathBuf, std::path::PathBuf) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let pin = kharond::connector::pin_of_der(cert.der());
    let cert_path = dir.join("tls.crt");
    let key_path = dir.join("tls.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (pin, cert_path, key_path)
}

#[test]
fn req_dep_006_path_b_refuses_wildcard_and_plain_http_non_loopback() {
    let data = Path::new("/data");
    let base = path_b_config(
        TOKEN_HASH,
        TOKEN_HASH,
        data,
        "10.66.0.1:8787",
        None,
        "10.66.0.1:8788",
    );
    let err = Config::from_toml_str(&base).expect_err("plain http");
    assert_eq!(err.code(), "api_plain_http_non_loopback");
    for addr in WILDCARDS {
        let text = path_b_config(TOKEN_HASH, TOKEN_HASH, data, addr, None, "10.66.0.1:8788");
        let err = Config::from_toml_str(&text).expect_err(addr);
        assert_eq!(err.code(), "api_wildcard_bind", "{addr}: {err:?}");
    }
    let text = path_b_config(
        TOKEN_HASH,
        TOKEN_HASH,
        data,
        "10.66.0.1:8787",
        Some((Path::new("/tmp/c.pem"), Path::new("/tmp/k.pem"))),
        "0.0.0.0:8788",
    );
    let err = Config::from_toml_str(&text).expect_err("connector wildcard");
    assert_eq!(err.code(), "connector_wildcard_bind");
    let agents_only = config(TOKEN_HASH, data, &listen("127.0.0.1:8787")).replace(
        "cdp = { endpoint = \"ws://127.0.0.1:9222\" }",
        "cdp = { endpoint = \"ws://127.0.0.1:9222\", via = \"agent_connector\" }",
    );
    let err = Config::from_toml_str(&agents_only).expect_err("no connector token");
    assert_eq!(err.code(), "connector_token_missing", "{err}");
}

#[test]
fn req_dep_006_path_b_tls_material_checked_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let (_pin, cert, key) = write_cert(dir.path());
    let data = dir.path().join("data");
    let text = path_b_config(
        TOKEN_HASH,
        TOKEN_HASH,
        &data,
        "203.0.113.4:8787",
        Some((&cert, &key)),
        "203.0.113.4:8788",
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    assert!(cfg.api.as_ref().unwrap().tls.is_some());
    assert!(cfg.connector.is_some());
    cfg.check_startup(&StaticMlockProbe(Ok(())))
        .expect("cert and key parse");
    let broken = text.replace(&cert.display().to_string(), "/tmp/does-not-exist.pem");
    let cfg = Config::from_toml_str(&broken).unwrap();
    let err = cfg.check_startup(&StaticMlockProbe(Ok(()))).unwrap_err();
    assert_eq!(err.code(), "tls_material");
}

#[tokio::test(flavor = "multi_thread")]
async fn req_dep_006_path_b_agent_api_over_tls() {
    let _bind_lock = LISTENERS.lock().await;
    let (api_token, api_hash) = generate("assistant");
    let api_token = api_token.expose_secret().clone();
    let (_tunnel, tunnel_hash) = generate_tunnel("assistant");
    let dir = tempfile::tempdir().unwrap();
    let (pin, cert, key) = write_cert(dir.path());
    let data = dir.path().join("data");
    let text = path_b_config(
        &api_hash,
        &tunnel_hash,
        &data,
        "127.0.0.1:0",
        Some((&cert, &key)),
        "127.0.0.2:0",
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    let daemon = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let addr = daemon.local_addr().unwrap();
    assert!(daemon.agent_api_tls());
    assert!(daemon.connector_addr().unwrap().ip().is_loopback());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(daemon.run(async {
        let _ = stopped.await;
    }));

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connect_pinned("127.0.0.1", pin, tcp).await.unwrap();
    let req = format!(
        "GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {api_token}\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut body = Vec::new();
    tls.read_to_end(&mut body).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("HTTP/1.1 200"), "{body}");
    assert!(body.contains("\"locked\":true"), "{body}");

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connect_pinned("127.0.0.1", pin, tcp).await.unwrap();
    let req = "GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer kh_agent_assistant_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nConnection: close\r\n\r\n";
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut body = Vec::new();
    tls.read_to_end(&mut body).await.unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("HTTP/1.1 401"), "{body}");

    let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
    plain
        .write_all(b"GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = plain.read(&mut buf).await.unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]);
    assert!(!text.contains("HTTP/1.1 200"), "{text}");

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
