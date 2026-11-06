//! REQ-APR-006 (SPEC §5; issue #21): the `kharon grants` /
//! `kharon approve` / `kharon deny` CLI commands talk to the
//! daemon's owner socket with the grant ops the owner channel
//! defines (#20), and print the outcome for the owner.
//!
//! The daemon side here is a one-shot fake socket that records the
//! request line and replies with the fixed shape `owner.rs`
//! produces; the peer-uid gate on both ends is exercised for real
//! (the CLI refuses a peer that is not its own uid, and vice versa
//! — the server half is covered in kharond's `req_apr_006_*`).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;

fn fake_owner(reply: &'static str) -> (PathBuf, mpsc::Receiver<String>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owner.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        tx.send(line.trim().to_owned()).unwrap();
        let mut stream = stream;
        stream.write_all(reply.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        // Keep the temp dir alive until the reply is written.
        drop(dir);
    });
    (path, rx)
}

fn run_cli(socket: &PathBuf, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_kharon"))
        .args(args)
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    )
}

#[test]
fn req_apr_006_cli_grants_lists_pending_requests() {
    let (socket, rx) = fake_owner(
        r#"{"ok":true,"pending":[{"request_id":"gr_1","agent_id":"alpha","item_id":"item-a","action":"fill","origin":"https://login.example.com"}]}"#,
    );
    let (ok, stdout, _) = run_cli(&socket, &["grants"]);
    assert!(ok, "{stdout}");
    assert!(stdout.contains("gr_1"), "{stdout}");
    assert!(stdout.contains("alpha"), "{stdout}");
    let sent: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
    assert_eq!(sent["op"], "grants");
}

#[test]
fn req_apr_006_cli_approve_sends_the_owner_terms() {
    let (socket, rx) = fake_owner(r#"{"ok":true,"grant_id":"g_1"}"#);
    let (ok, stdout, _) = run_cli(
        &socket,
        &[
            "approve",
            "gr_1",
            "--kind",
            "per-origin",
            "--ttl",
            "3600",
            "--max-uses",
            "5",
        ],
    );
    assert!(ok, "{stdout}");
    assert_eq!(stdout, "grant g_1");
    let sent: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
    assert_eq!(sent["op"], "approve");
    assert_eq!(sent["request_id"], "gr_1");
    assert_eq!(sent["kind"], "per-origin");
    assert_eq!(sent["ttl_s"], 3600);
    assert_eq!(sent["max_uses"], 5);
}

#[test]
fn req_apr_006_cli_deny_sends_the_request_id() {
    let (socket, rx) = fake_owner(r#"{"ok":true}"#);
    let (ok, stdout, _) = run_cli(&socket, &["deny", "gr_9"]);
    assert!(ok, "{stdout}");
    let sent: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
    assert_eq!(sent["op"], "deny");
    assert_eq!(sent["request_id"], "gr_9");
}
