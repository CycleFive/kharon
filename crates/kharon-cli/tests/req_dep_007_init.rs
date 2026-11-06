//! REQ-DEP-007 (issue #24): `kharon init` generates the kharon
//! account's master password and prints it once, to the tty.
//!
//! The binary runs under `script(1)`, which gives it a pseudo
//! terminal as its controlling tty, with its stdout and stderr
//! redirected to files. The password must show on the terminal and
//! in neither file. Without a controlling terminal (`setsid`) the
//! command must refuse and print no password anywhere.

use std::path::Path;
use std::process::{Command, Stdio};

const BASE32: &str = "0123456789abcdefghjkmnpqrstvwxyz";

/// Every `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx` group string of
/// Crockford base32 in `text`.
fn passwords_in(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace())
        .filter(|w| {
            let groups: Vec<&str> = w.split('-').collect();
            groups.len() == 8
                && groups
                    .iter()
                    .all(|g| g.len() == 4 && g.chars().all(|c| BASE32.contains(c)))
        })
        .map(str::to_owned)
        .collect()
}

fn sh_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', r"'\''"))
}

/// Run `kharon init` on a fresh pty; return (exit ok, tty text,
/// stdout file, stderr file).
fn init_on_a_tty() -> (bool, String, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("stdout");
    let err = dir.path().join("stderr");
    let inner = format!(
        "{} init >{} 2>{}",
        sh_quote(Path::new(env!("CARGO_BIN_EXE_kharon"))),
        sh_quote(&out),
        sh_quote(&err)
    );
    let run = Command::new("script")
        .args(["--quiet", "--return", "--command", &inner, "/dev/null"])
        .stdin(Stdio::null())
        .output()
        .expect("script(1) from util-linux is needed for this test");
    (
        run.status.success(),
        String::from_utf8_lossy(&run.stdout).into_owned(),
        std::fs::read_to_string(&out).unwrap(),
        std::fs::read_to_string(&err).unwrap(),
    )
}

#[test]
fn req_dep_007_init_prints_the_password_once_to_the_tty_only() {
    let (ok, tty, stdout, stderr) = init_on_a_tty();
    assert!(ok, "kharon init failed; tty: {tty}\nstderr: {stderr}");
    let shown = passwords_in(&tty);
    assert_eq!(shown.len(), 1, "expected one password on the tty: {tty}");
    assert!(stdout.is_empty(), "stdout must stay empty: {stdout}");
    assert!(stderr.is_empty(), "stderr must stay empty: {stderr}");
    // 32 symbols of 5 bits each.
    assert_eq!(shown[0].replace('-', "").len() * 5, 160);
    assert!(tty.contains("outside the kharon organization"), "{tty}");
}

#[test]
fn req_dep_007_init_generates_a_new_password_each_run() {
    let (_, a, _, _) = init_on_a_tty();
    let (_, b, _, _) = init_on_a_tty();
    assert_ne!(passwords_in(&a), passwords_in(&b));
}

#[test]
fn req_dep_007_init_refuses_without_a_tty() {
    let run = Command::new("setsid")
        .arg(env!("CARGO_BIN_EXE_kharon"))
        .arg("init")
        .stdin(Stdio::null())
        .output()
        .expect("setsid(1) from util-linux is needed for this test");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "init must refuse without a tty");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(passwords_in(&stderr).is_empty(), "{stderr}");
    assert!(stderr.contains("terminal"), "{stderr}");
}
