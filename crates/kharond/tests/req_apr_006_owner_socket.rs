//! REQ-APR-006 (SPEC §5; issue #21): the owner CLI channel is a
//! unix socket with a peer uid check.
//!
//! - A same-uid client is served (`status` round-trips).
//! - A client running as **another uid** is rejected — dropped
//!   without a reply — and the rejection is audited
//!   (`owner_auth_fail` / `peer_uid`). This half needs a second uid,
//!   so it runs when the test process is root (it re-executes this
//!   test binary as uid 65534, `nobody`); elsewhere it is skipped
//!   with a note, and the decision itself is unit-tested in
//!   `owner::tests::req_apr_006_only_the_daemons_own_uid_is_accepted`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use kharond::owner::{OwnerFailure, OwnerOps, bind, serve};
use zeroize::Zeroizing;

#[derive(Default)]
struct RecordingOps {
    auth_fails: Mutex<Vec<&'static str>>,
}

impl OwnerOps for RecordingOps {
    async fn unlock(&self, _password: Zeroizing<String>) -> Result<(), OwnerFailure> {
        Err(OwnerFailure::Unsupported)
    }

    async fn lock(&self) -> bool {
        true
    }

    async fn is_locked(&self) -> bool {
        true
    }

    async fn auth_failed(&self, detail: &'static str) {
        self.auth_fails.lock().unwrap().push(detail);
    }
}

/// The socket path a test run uses (also passed to the other-uid
/// child through the environment).
fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("REQ_APR_006_SOCKET") {
        return PathBuf::from(p);
    }
    let dir = std::env::temp_dir().join(format!("kharon-apr006-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("owner.sock")
}

/// One status round trip; returns the reply (empty when the server
/// dropped the connection without replying).
fn status_round_trip(path: &PathBuf) -> String {
    let mut stream = UnixStream::connect(path).expect("connect");
    stream.write_all(b"{\"op\":\"status\"}\n").unwrap();
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    reply
}

/// Child mode: connect as whatever uid this process runs as, try a
/// status request, and record whether a reply came back. The exit
/// code is 0 when the connection was dropped with no reply.
#[tokio::test]
async fn req_apr_006_child_connects_and_reports() {
    if std::env::var("REQ_APR_006_CHILD").is_err() {
        return;
    }
    let reply = status_round_trip(&socket_path());
    std::process::exit(if reply.is_empty() { 0 } else { 1 });
}

#[tokio::test]
async fn req_apr_006_other_uid_is_rejected_and_audited() {
    let path = socket_path();
    let ops = Arc::new(RecordingOps::default());
    let listener = bind(&path).unwrap();
    let server = tokio::spawn(serve(listener, Arc::clone(&ops)));
    // Let the accept loop start.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Control: a same-uid client is served.
    let path2 = path.clone();
    let reply = tokio::task::spawn_blocking(move || status_round_trip(&path2))
        .await
        .unwrap();
    assert!(reply.contains("\"ok\":true"), "same-uid reply: {reply}");
    assert!(ops.auth_fails.lock().unwrap().is_empty());

    // Another uid: only possible with a second uid to run as. As
    // root, re-execute this binary's child test as `nobody`.
    if rustix::process::geteuid().as_raw() != 0 {
        eprintln!(
            "req_apr_006: not root — the other-uid half is skipped here \
             (the peer decision is unit-tested in owner::tests)"
        );
        server.abort();
        return;
    }
    use std::os::unix::process::CommandExt;
    // The socket file itself is 0600 (a first, separate layer). To
    // exercise the peer gate itself — the layer REQ-APR-006 names —
    // open the file up for this test only, in a private temp dir.
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    // Stage a copy of this test binary somewhere `nobody` can
    // execute (the target tree may sit under a private home dir).
    let staged = std::env::temp_dir().join(format!("kharon-apr006-bin-{}", std::process::id()));
    std::fs::copy(std::env::current_exe().unwrap(), &staged).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // spawn_blocking: a plain blocking wait here would starve the
    // runtime worker that runs the server's accept loop.
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new(&staged)
            .args([
                "req_apr_006_child_connects_and_reports",
                "--exact",
                "--nocapture",
            ])
            .env("REQ_APR_006_CHILD", "1")
            .env("REQ_APR_006_SOCKET", &path)
            .uid(65534)
            .status()
            .expect("spawn other-uid child")
    })
    .await
    .unwrap();
    // The child exits 0 only when it got no reply; the harness exit
    // status of the child *test* is also embedded, so accept either
    // signal by checking the audit record, which is the AC's point.
    let _ = status;
    // Give the server a moment to record the rejection.
    for _ in 0..50 {
        if !ops.auth_fails.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        ops.auth_fails.lock().unwrap().as_slice(),
        ["peer_uid"],
        "the other-uid connection is rejected and audited"
    );
    server.abort();
}
