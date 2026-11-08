//! Docker CLI helpers for the image and compose E2E tests (issue #24:
//! `req_dep_001_image`, `req_dep_002_compose_e2e`). Both are ignored
//! by default and run from `.github/workflows/image.yml`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// `docker <args>`, with `stdin` fed to it when given.
pub fn docker_raw(args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut cmd = Command::new("docker");
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run docker {args:?}: {e}"));
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(input).unwrap();
    }
    child.wait_with_output().unwrap()
}

/// `docker <args>` on a terminal, as an operator types it: util-linux
/// `script` gives `docker exec -it` a pty, and `input` (plus a
/// newline) is written only once `prompt` shows on it, so a program
/// that turns echo off before prompting never echoes it. `script -e`
/// passes the exit status through. Returns success and what the
/// terminal showed (`\r` stripped). The args are joined into a
/// `sh -c` line, single-quoted, so they must not contain `'`.
pub fn docker_on_tty(args: &[&str], prompt: &str, input: &str) -> (bool, String) {
    let line = std::iter::once("docker")
        .chain(args.iter().copied())
        .map(|a| {
            assert!(!a.contains('\''), "quote in {a:?}");
            format!("'{a}'")
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut child = Command::new("script")
        .args(["-qfec", &line, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run script for docker {args:?}: {e}"));
    let mut out = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        while let Ok(n) = out.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut seen = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !String::from_utf8_lossy(&seen).contains(prompt) {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(chunk) => seen.extend(chunk),
            Err(_) => {
                let _ = child.kill();
                panic!(
                    "no {prompt:?} on the tty for docker {args:?}: {}",
                    String::from_utf8_lossy(&seen)
                );
            }
        }
    }
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(format!("{input}\n").as_bytes()).unwrap();
    stdin.flush().unwrap();
    // Hold script's stdin open until the command exits: an early EOF
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

/// `docker <args>`; panics unless it exits 0. Returns stdout.
pub fn docker(args: &[&str]) -> String {
    let out = docker_raw(args, None);
    assert!(
        out.status.success(),
        "docker {args:?} failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Polls `docker logs <container>` (stdout + stderr) until it
/// contains `needle`; panics with the logs after `timeout`.
pub fn wait_for_log(container: &str, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let out = docker_raw(&["logs", container], None);
        let mut logs = String::from_utf8_lossy(&out.stdout).into_owned();
        logs.push_str(&String::from_utf8_lossy(&out.stderr));
        if logs.contains(needle) {
            return logs;
        }
        assert!(
            Instant::now() < deadline,
            "{container} never logged {needle:?}; logs:\n{logs}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}
