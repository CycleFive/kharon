//! Docker CLI helpers for the image and compose E2E tests (issue #24:
//! `req_dep_001_image`, `req_dep_002_compose_e2e`). Both are ignored
//! by default and run from `.github/workflows/image.yml`.

#![allow(dead_code)]

use std::io::Write;
use std::process::{Command, Output, Stdio};
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
