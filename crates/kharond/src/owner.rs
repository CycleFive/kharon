//! Owner API: the daemon's unlock channel (issue #11; SPEC §3.2,
//! §8; REQ-MEM-003/005, REQ-EXP-003).
//!
//! SPEC §3.2 puts the owner surface on a **unix socket** driven by
//! the `kharon` CLI, separate from the agent API: agents hold bearer
//! tokens and must never be able to unlock the broker. The socket
//! lives under `data_dir` (`owner.sock`, mode 0600, and the
//! directory the daemon creates for it is 0700), and every
//! connection's peer uid must equal the daemon's effective uid —
//! the socket is an owner-only channel on the owner's own host.
//!
//! Protocol: one request per connection, one JSON object on one
//! line, one JSON response line, then the daemon closes. Requests:
//!
//! - `{"op":"unlock","password":"…"}` — the password is used for
//!   key derivation only and zeroized after it (REQ-MEM-003). It is
//!   never in config, env, or argv (REQ-EXP-003); this socket (or
//!   the future web UI) is the only way in.
//! - `{"op":"lock"}` — lock now, destroying the session.
//! - `{"op":"status"}` — `{"ok":true,"locked":<bool>}`.
//! - `{"op":"scan","needle":"…"}` — **debug builds only**: the
//!   REQ-MEM-003 canary scan of this process's memory
//!   ([`crate::memscan`]); replies `{"ok":true,"hits":<n>}`. In
//!   release builds the op is refused like any unknown op — a
//!   memory-scanning surface has no place in the shipped daemon.
//!
//! Responses never echo the password or any key material, and
//! failures carry fixed codes only (REQ-API-006): `bad_request`,
//! `unknown_op`, `forbidden`, `already_unlocked`,
//! `mlock_unavailable` (REQ-MEM-002), `audit_failed` (REQ-AUD-003),
//! `unlock_failed` (wrong password, unreachable server, bad export
//! — deliberately indistinguishable).
//!
//! Buffers that held the request (and with it, possibly, the
//! password) are zeroizing: the read buffer is wiped right after
//! parsing, and the parsed password lives in a
//! [`Zeroizing<String>`] until the derivation returns.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::{Zeroize, Zeroizing};

use crate::memscan;

/// Longest accepted request line. A password plus JSON framing
/// fits comfortably; anything longer is refused without parsing.
pub const MAX_REQUEST_BYTES: usize = 8192;

/// The owner operations the daemon provides. Implemented by
/// `daemon::DaemonOwner`; the transport in this module owns no
/// policy, it only authenticates the peer, parses, and dispatches.
pub trait OwnerOps: Send + Sync + 'static {
    /// Unlock with the owner's password (zeroized by the caller
    /// after this returns; implementations must not retain it).
    fn unlock(
        &self,
        password: Zeroizing<String>,
    ) -> impl Future<Output = Result<(), OwnerFailure>> + Send;

    /// Lock now. Returns whether a session was destroyed.
    fn lock(&self) -> impl Future<Output = bool> + Send;

    /// Whether the broker is currently locked.
    fn is_locked(&self) -> impl Future<Output = bool> + Send;
}

/// Why an owner operation failed. Fixed codes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFailure {
    /// Unlock attempted while already unlocked.
    AlreadyUnlocked,
    /// `require_mlock = true` and `mlockall` failed (REQ-MEM-002).
    MlockUnavailable,
    /// The `Unlocked` audit entry could not be written, so the
    /// unlock was rolled back (REQ-AUD-003).
    AuditFailed,
    /// Derivation failed (wrong password, sync error, export auth
    /// failure — not distinguished, REQ-API-006).
    UnlockFailed,
}

impl OwnerFailure {
    /// Stable machine-readable code for the response line.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AlreadyUnlocked => "already_unlocked",
            Self::MlockUnavailable => "mlock_unavailable",
            Self::AuditFailed => "audit_failed",
            Self::UnlockFailed => "unlock_failed",
        }
    }
}

#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    password: Option<Zeroizing<String>>,
    #[serde(default)]
    needle: Option<Zeroizing<String>>,
}

/// The socket path for a daemon with this `data_dir`.
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("owner.sock")
}

/// Bind the owner socket at `path`: a stale socket file from a
/// previous (possibly kill -9'd, REQ-MEM-005) run is unlinked
/// first, and the socket is mode 0600.
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

/// Serve owner requests until the returned future is dropped (the
/// daemon aborts it at shutdown).
pub async fn serve<O: OwnerOps>(listener: UnixListener, ops: Arc<O>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let ops = Arc::clone(&ops);
        tokio::spawn(async move {
            let _ = handle(stream, ops).await;
        });
    }
}

async fn handle<O: OwnerOps>(mut stream: UnixStream, ops: Arc<O>) -> std::io::Result<()> {
    // Owner-only: the peer must be a process running as the same
    // effective uid as the daemon.
    let peer_ok = stream
        .peer_cred()
        .map(|c| c.uid() == rustix::process::geteuid().as_raw())
        .unwrap_or(false);
    if !peer_ok {
        return Ok(());
    }

    let mut raw = Zeroizing::new(Vec::new());
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        chunk.zeroize();
        if raw.len() > MAX_REQUEST_BYTES || raw.contains(&b'\n') {
            break;
        }
    }
    let line_end = raw.iter().position(|b| *b == b'\n').unwrap_or(raw.len());
    let request: Result<Request, _> = serde_json::from_slice(&raw[..line_end]);
    // The request bytes held the password: wipe them now that the
    // parsed copy (itself zeroizing) exists.
    raw.zeroize();

    let response = match request {
        Ok(req) => dispatch(req, ops).await,
        Err(_) => error_response("bad_request"),
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn dispatch<O: OwnerOps>(req: Request, ops: Arc<O>) -> String {
    match req.op.as_str() {
        "unlock" => {
            let Some(password) = req.password else {
                return error_response("bad_request");
            };
            match ops.unlock(password).await {
                Ok(()) => ok_response(Some(false)),
                Err(e) => error_response(e.code()),
            }
        }
        "lock" => {
            ops.lock().await;
            ok_response(Some(true))
        }
        "status" => ok_response(Some(ops.is_locked().await)),
        "scan" => scan_response(req),
        _ => error_response("unknown_op"),
    }
}

/// The debug-build canary scan (REQ-MEM-003). The needle's own
/// buffer is excluded from the scan (it is, necessarily, in
/// memory); see [`crate::memscan`].
#[cfg(debug_assertions)]
fn scan_response(req: Request) -> String {
    let Some(needle) = req.needle else {
        return error_response("bad_request");
    };
    if needle.is_empty() || needle.len() > 256 {
        return error_response("bad_request");
    }
    let bytes = needle.as_bytes();
    let range = (bytes.as_ptr() as usize)..(bytes.as_ptr() as usize + bytes.len());
    let hits = memscan::count_occurrences(bytes, &[range]);
    format!("{{\"ok\":true,\"hits\":{hits}}}\n")
}

#[cfg(not(debug_assertions))]
fn scan_response(_req: Request) -> String {
    error_response("unknown_op")
}

fn ok_response(locked: Option<bool>) -> String {
    match locked {
        Some(locked) => format!("{{\"ok\":true,\"locked\":{locked}}}\n"),
        None => "{\"ok\":true}\n".to_owned(),
    }
}

fn error_response(code: &str) -> String {
    format!("{{\"ok\":false,\"error\":\"{code}\"}}\n")
}
