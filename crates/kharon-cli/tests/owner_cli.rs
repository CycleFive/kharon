//! The `kharon` CLI against a real daemon's owner socket
//! (issue #11; SPEC §3.2/§8): `status` / `unlock` / `lock` round
//! trips, the password arriving on stdin (the non-tty path; the
//! tty path disables echo and reads the same way), and a wrong
//! password refused with the daemon's fixed code.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;

const PASSWORD: &str = "kharon export fixture password 9";

fn run_cli(socket: &PathBuf, args: &[&str], stdin_text: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kharon"));
    cmd.args(args).arg("--socket").arg(socket);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_text.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd.spawn().unwrap();
    if let Some(text) = stdin_text {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn kharon_cli_unlock_lock_status_round_trip() {
    let data = tempfile::tempdir().unwrap();
    let export = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kharond/tests/fixtures/export/password_protected.json"
    ));
    let (token, hash) = kharond::api::token::generate("alpha");
    drop(token);
    let cfg = Config::from_toml_str(&format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"
"#,
        data.path().display(),
        export.display()
    ))
    .unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let socket = d.owner_socket().to_path_buf();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));

    let (ok, out, _) = run_cli(&socket, &["status"], None);
    assert!(ok);
    assert_eq!(out, "locked");

    // Wrong password: non-zero exit, fixed code, still locked.
    let (ok, _, err) = run_cli(&socket, &["unlock"], Some("wrong password\n"));
    assert!(!ok);
    assert!(err.contains("unlock_failed"), "{err}");
    let (ok, out, _) = run_cli(&socket, &["status"], None);
    assert!(ok);
    assert_eq!(out, "locked");

    // Right password on stdin: unlocked.
    let (ok, out, err) = run_cli(&socket, &["unlock"], Some(&format!("{PASSWORD}\n")));
    assert!(ok, "{err}");
    assert_eq!(out, "unlocked");
    let (ok, out, _) = run_cli(&socket, &["status"], None);
    assert!(ok);
    assert_eq!(out, "unlocked");

    // Lock: back to locked.
    let (ok, out, _) = run_cli(&socket, &["lock"], None);
    assert!(ok);
    assert_eq!(out, "locked");
    let (ok, out, _) = run_cli(&socket, &["status"], None);
    assert!(ok);
    assert_eq!(out, "locked");

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
