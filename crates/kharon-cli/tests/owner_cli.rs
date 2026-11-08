//! The `kharon` CLI against a real daemon's owner socket
//! (issue #11; SPEC §3.2/§8): `status` / `unlock` / `lock` round
//! trips with the password typed on a terminal (a pty driven by
//! util-linux `script`, written only once the echo-off prompt is
//! up), a wrong password refused with the daemon's fixed code, and
//! a password piped or redirected into stdin refused before it is
//! read (#131 slice 5, SPEC §8 "CLI (tty, no echo)").

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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

/// The unlock prompt, as `kharon unlock` writes it to the terminal.
const PROMPT: &str = "kharon master password:";

/// Run `kharon unlock` on a pty, as an owner at a terminal would:
/// `script` gives the CLI a controlling terminal, the password is
/// written once the prompt (and so echo-off) is up, and the exit
/// status is the CLI's (`script -e`). Returns success and what the
/// terminal showed.
fn unlock_on_tty(socket: &Path, password: &str) -> (bool, String) {
    let line = format!(
        "'{}' unlock --socket '{}'",
        env!("CARGO_BIN_EXE_kharon"),
        socket.display()
    );
    let mut child = Command::new("script")
        .args(["-qfec", &line, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("util-linux `script` is needed for the tty tests");
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !String::from_utf8_lossy(&seen).contains(PROMPT) {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(chunk) => seen.extend(chunk),
            Err(_) => panic!(
                "no unlock prompt on the tty: {}",
                String::from_utf8_lossy(&seen)
            ),
        }
    }
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(format!("{password}\n").as_bytes()).unwrap();
    stdin.flush().unwrap();
    // Keep script's stdin open until the CLI exits: an early EOF
    // would reach the pty as end-of-input.
    let status = child.wait().unwrap();
    drop(stdin);
    reader.join().unwrap();
    seen.extend(rx.try_iter().flatten());
    (
        status.success(),
        String::from_utf8_lossy(&seen).replace('\r', ""),
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

    // The right password piped, redirected, or absent on stdin is
    // refused before it is read: exit 2, fixed text, still locked.
    for stdin in [Some(format!("{PASSWORD}\n")), None] {
        let (ok, out, err) = run_cli(&socket, &["unlock"], stdin.as_deref());
        assert!(!ok, "{out}");
        assert!(err.contains("unlock needs a terminal"), "{err}");
        assert!(!err.contains(PASSWORD) && !out.contains(PASSWORD), "{err}");
    }
    let (ok, out, _) = run_cli(&socket, &["status"], None);
    assert!(ok);
    assert_eq!(out, "locked");

    // Wrong password on the tty: non-zero exit, fixed code, still
    // locked. Echo is off, so the terminal never shows it.
    let (ok, tty) = unlock_on_tty(&socket, "wrong password");
    assert!(!ok, "{tty}");
    assert!(tty.contains("unlock_failed"), "{tty}");
    assert!(!tty.contains("wrong password"), "echoed: {tty}");
    let (ok, out, _) = run_cli(&socket, &["status"], None);
    assert!(ok);
    assert_eq!(out, "locked");

    // Right password on the tty: unlocked.
    let (ok, tty) = unlock_on_tty(&socket, PASSWORD);
    assert!(ok, "{tty}");
    assert!(tty.lines().any(|l| l.trim() == "unlocked"), "{tty}");
    assert!(!tty.contains(PASSWORD), "echoed: {tty}");
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
