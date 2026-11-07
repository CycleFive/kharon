//! REQ-MEM-001 for the `kharon` CLI (SPEC §8, #134): like kharond, the
//! CLI makes itself non-dumpable with core limit 0 before it does
//! anything else. It holds the master password (`init`, `unlock`) and
//! fresh tokens (`token mint`, `tunnel mint`), and the release build
//! aborts on panic, so without this an abort could core-dump them.
//!
//! The test points `kharon status` at an owner socket that accepts and
//! never replies, which holds the real binary alive while the parent
//! inspects it:
//!
//! - its `/proc/<pid>` files are owned by root (proc(5): the ownership
//!   becomes `root:root` when a process is not dumpable);
//! - `/proc/<pid>/limits` shows a core limit of 0;
//! - opening `/proc/<pid>/mem` fails (non-dumpable processes deny
//!   same-uid ptrace access), unless the test holds `CAP_SYS_PTRACE`.

use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn has_cap_sys_ptrace() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .and_then(|l| u64::from_str_radix(l[7..].trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << 19) != 0)
}

#[test]
fn req_mem_001_cli_is_non_dumpable_with_core_limit_zero() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("owner.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kharon"))
        .args(["status", "--socket"])
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let pid = child.id();

    // The CLI hardens before parsing its arguments, so once it has
    // connected it is hardened. It then waits for a reply that never
    // comes, until we kill it.
    let deadline = Instant::now() + Duration::from_secs(30);
    let _conn = loop {
        match listener.accept() {
            Ok((conn, _)) => break conn,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Ok(Some(status)) = child.try_wait() {
                    panic!("kharon exited before connecting: {status}");
                }
                assert!(
                    Instant::now() < deadline,
                    "kharon did not connect within 30s"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept: {e}"),
        }
    };

    let euid = rustix::process::geteuid().as_raw();
    let owner = std::fs::metadata(format!("/proc/{pid}/status"))
        .unwrap()
        .uid();
    if euid != 0 {
        assert_eq!(owner, 0, "a non-dumpable process's /proc files are root's");
    }

    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap_or_default();
    let fields: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(
        fields.get(4..6),
        Some(&["0", "0"][..]),
        "soft and hard core limit 0: {core:?}"
    );

    if !has_cap_sys_ptrace() {
        assert!(
            std::fs::File::open(format!("/proc/{pid}/mem")).is_err(),
            "same-uid /proc/<pid>/mem must be refused"
        );
    }

    child.kill().unwrap();
    child.wait().unwrap();
}
