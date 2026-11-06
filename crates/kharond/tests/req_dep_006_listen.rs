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
use kharond::api::token::generate;
use kharond::config::Config;
use kharond::daemon::{self, StartupError};
use kharond::lock::{HardeningError, StaticHardening};
use serde_json::json;

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

/// No `[api]`: the daemon refuses rather than pick an address.
#[test]
fn req_dep_006_daemon_refuses_missing_listen() {
    let data = tempfile::tempdir().unwrap();
    let text = config(TOKEN_HASH, data.path(), "");
    for args in [&[][..], &["--check"][..]] {
        let (code, stderr) = run(args, &text);
        assert_eq!(code, Some(78), "{args:?}: {stderr}");
        assert!(
            stderr.contains("startup error [api_listen_missing]"),
            "{stderr}"
        );
    }
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
