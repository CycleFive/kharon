//! Owner API: the daemon's unlock channel (issue #11; SPEC §3.2,
//! §8; REQ-MEM-003/005, REQ-EXP-003).
//!
//! SPEC §3.2 puts the owner surface on a **unix socket** driven by
//! the `kharon` CLI, separate from the agent API: agents hold bearer
//! tokens and must never be able to unlock the broker. The socket
//! lives under `data_dir` (`owner.sock`, mode 0600 once bound; the
//! `audit/` directory below `data_dir` is created 0700, `data_dir`
//! itself is the operator's), and every connection's peer uid must
//! equal the daemon's effective uid — the socket is an owner-only
//! channel on the owner's own host.
//!
//! Protocol: one request per connection, one JSON object on one
//! line, one JSON response line, then the daemon closes. Requests:
//!
//! - `{"op":"unlock","password":"…"}` — the password is used for
//!   key derivation only and zeroized after it (REQ-MEM-003). It is
//!   never in config, env, or argv (REQ-EXP-003); this socket and
//!   the owner web UI's unlock (`owner_ui::unlock`, behind a passkey
//!   session, password sealed to a per-attempt key) are the only ways
//!   in, and both reach the same `OwnerOps::unlock`.
//! - `{"op":"lock"}` — lock now, destroying the session.
//! - `{"op":"status"}` — `{"ok":true,"locked":<bool>}`, plus
//!   `"owner_ui_without_edge_address":<n>` when a public owner UI is
//!   configured: how many of its requests arrived without a usable
//!   `CF-Connecting-IP` (they are not throttled; a count that grows
//!   means the edge is not sending the header).
//! - `{"op":"revoke_grant","grant_id":"g_…"}` — REQ-REV-001.
//! - `{"op":"revoke_agent","agent_id":"…"}` — REQ-REV-001 (token +
//!   grants). Durable (#132): the `token_revoke` entry binds the
//!   revocation to the configured token's fingerprint, so a restart
//!   keeps refusing the same token; `unsuspend` does not clear it,
//!   and there is no un-revoke op. Recovery is token rotation.
//! - `{"op":"unsuspend","agent_id":"…"}` — REQ-RL-002 owner reset of
//!   a suspension. Does not restore a revoked token.
//! - `{"op":"panic"}` — REQ-REV-002.
//! - `{"op":"grants"}` — `{"ok":true,"pending":[…]}`: the pending
//!   grant requests (SPEC §5, #20), each as the approval prompt an
//!   owner decides on — the request id, agent, item, action, and the
//!   **observed** origin (REQ-APR-007), never the claimed one.
//! - `{"op":"approve","request_id":"gr_…","kind":"once",
//!   "ttl_s":120,"max_uses":1,"scope_collection":"<uuid>"}` — approve
//!   a pending request under owner-chosen terms (kind defaults to
//!   `once`, scope to the request's item); replies
//!   `{"ok":true,"grant_id":"g_…"}`. Term bounds are SPEC §5's,
//!   enforced by the broker.
//! - `{"op":"deny","request_id":"gr_…"}` — deny a pending request.
//! - `{"op":"passkey_enroll"}` — mint a single-use enrollment code
//!   for the owner web UI (REQ-APR-005). The reply is
//!   `{"ok":true,"enroll_token":"<base64url>"}`. The code is not a
//!   password and cannot sign in; it only authorizes registering a
//!   passkey. It is zeroized with the reply buffer. Without an
//!   owner UI configured the op is `unknown_op`.
//!
//!   The CLI/ntfy presentation of the grant ops is #16; this socket
//!   is the broker-side seam they drive. The web UI never accepts
//!   the master password.
//! - `{"op":"scan","needle":"…"}` or
//!   `{"op":"scan","needle_hex":"…"}` — only in builds with the
//!   non-default cargo feature `canary-scan` (enabled by the test
//!   target, never for a shipped daemon): the REQ-MEM-003 canary
//!   scan of this process's memory ([`crate::memscan`]); replies
//!   `{"ok":true,"hits":<n>}`, or `scan_unavailable` when the scan
//!   itself could not read (a failed scan never reports 0 hits).
//!   `needle_hex` carries non-UTF-8 needles (key material). Without
//!   the feature the op is refused like any unknown op — a
//!   memory-scanning surface is a key-material oracle and has no
//!   place in the shipped daemon.
//!
//! Responses never echo the password or any key material, and
//! failures carry fixed codes only (REQ-API-006): `bad_request`,
//! `unknown_op`, `forbidden`, `already_unlocked`,
//! `mlock_unavailable` (REQ-MEM-002), `audit_failed` (REQ-AUD-003),
//! `scan_unavailable`, `unlock_failed` (wrong password,
//! unreachable server, bad export — deliberately indistinguishable),
//! and for the grant ops `not_found`, `not_pending`,
//! `standing_disabled`, `invalid_terms`.
//!
//! The codes are indistinguishable; the *timing* is not, in sync
//! mode: an unreachable server fails during `prepare`, before any
//! derivation, while a wrong password fails only after the network
//! round trip and the KDF. That is accepted here (PR #81 review):
//! this channel is reachable only by a same-uid peer on the
//! owner's own host, so a timing oracle on it tells that peer
//! nothing it could not learn from its own client.
//!
//! Rejected peers (uid mismatch or unreadable credentials) and
//! failed unlock attempts are audited as `owner_auth_fail`
//! (REQ-AUD-003 counts owner actions; the event name is SPEC §7's)
//! through [`OwnerOps::auth_failed`], best effort: the connection
//! is dropped / the refusal stands either way, and a failed append
//! never turns a refusal into a success.
//!
//! Buffers that held the request (and with it, possibly, the
//! password) are zeroizing: the read buffer is pre-sized so it
//! never reallocates while holding a password prefix, and is wiped
//! right after parsing. The password field is *hand-decoded* from
//! the raw line into a [`Zeroizing<String>`] (see
//! [`decode_json_string`]): serde_json's escape-decoding scratch
//! buffer would otherwise keep an unwiped copy of any password
//! containing `\"` or `\\` (PR #81 review, item 7).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "canary-scan")]
use crate::memscan;

/// Longest accepted request line. A password plus JSON framing
/// fits comfortably; anything longer is refused without parsing.
pub const MAX_REQUEST_BYTES: usize = 8192;

/// Read chunk size; the request buffer is pre-sized to
/// `MAX_REQUEST_BYTES + READ_CHUNK` so it never grows (a grow would
/// free a buffer holding a password prefix without wiping it —
/// PR #81 review, item 7).
const READ_CHUNK: usize = 1024;

/// How long a connection may take to deliver its one request line
/// before the daemon drops it (PR #81 review: the owner connection
/// previously had no read timeout and no cap beyond one task per
/// connection, so a same-uid peer could hold tasks open forever).
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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

    /// A public owner UI's count of requests without a usable
    /// `CF-Connecting-IP`; `None` when there is no public owner UI.
    fn owner_ui_without_edge_address(&self) -> Option<u64> {
        None
    }

    /// Record an `owner_auth_fail` audit entry (rejected peer or
    /// failed unlock attempt), best effort. `detail` is a fixed
    /// code (`peer_uid`, `unlock_failed`), never peer-supplied
    /// text. Default: no audit attached (test doubles).
    fn auth_failed(&self, detail: &'static str) -> impl Future<Output = ()> + Send {
        let _ = detail;
        async {}
    }

    /// Approve a pending grant request (SPEC §5, #20) under the
    /// owner's terms; returns the issued grant's id. Default: the
    /// op is not supported (`unknown_op`) — test doubles predate
    /// grants.
    fn approve(
        &self,
        args: ApproveArgs,
    ) -> impl Future<Output = Result<String, OwnerFailure>> + Send {
        let _ = args;
        async { Err(OwnerFailure::Unsupported) }
    }

    /// Deny a pending grant request. Default: unsupported.
    fn deny(&self, request_id: String) -> impl Future<Output = Result<(), OwnerFailure>> + Send {
        let _ = request_id;
        async { Err(OwnerFailure::Unsupported) }
    }

    /// The pending grant requests, as approval prompts (observed
    /// origin only, REQ-APR-007). Default: none.
    fn pending_grants(&self) -> impl Future<Output = Vec<crate::api::ApprovalPrompt>> + Send {
        async { Vec::new() }
    }

    /// Mint a one-time passkey enrollment code (REQ-APR-005).
    /// Default: the owner UI is not attached (`unknown_op`).
    fn passkey_enroll(
        &self,
    ) -> impl Future<Output = Result<Zeroizing<String>, OwnerFailure>> + Send {
        async { Err(OwnerFailure::Unsupported) }
    }

    /// Revoke one grant (REQ-REV-001). Default: unsupported.
    fn revoke_grant(
        &self,
        grant_id: String,
    ) -> impl Future<Output = Result<bool, OwnerFailure>> + Send {
        let _ = grant_id;
        async { Err(OwnerFailure::Unsupported) }
    }

    /// Revoke an agent (token + grants; REQ-REV-001). Default: unsupported.
    fn revoke_agent(
        &self,
        agent_id: String,
    ) -> impl Future<Output = Result<usize, OwnerFailure>> + Send {
        let _ = agent_id;
        async { Err(OwnerFailure::Unsupported) }
    }

    /// Clear suspension (REQ-RL-002). Default: unsupported.
    fn unsuspend(&self, agent_id: String) -> impl Future<Output = Result<(), OwnerFailure>> + Send {
        let _ = agent_id;
        async { Err(OwnerFailure::Unsupported) }
    }

    /// Panic lock (REQ-REV-002). Default: unsupported.
    fn panic_lock(&self) -> impl Future<Output = Result<(), OwnerFailure>> + Send {
        async { Err(OwnerFailure::Unsupported) }
    }
}

/// Owner-chosen approval terms from an `approve` request line.
/// `kind: None` is the SPEC §5 default (`once`); scope defaults to
/// the request's item unless `scope_collection` names a collection.
#[derive(Debug, Clone, Default)]
pub struct ApproveArgs {
    /// The `gr_…` request to approve.
    pub request_id: String,
    /// Grant kind override.
    pub kind: Option<crate::config::GrantKind>,
    /// Collection scope override.
    pub scope_collection: Option<String>,
    /// TTL override, seconds.
    pub ttl_s: Option<u64>,
    /// Use-cap override.
    pub max_uses: Option<u64>,
}

/// Why an owner operation failed. Fixed codes only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFailure {
    /// Unlock attempted while already unlocked.
    AlreadyUnlocked,
    /// `require_mlock = true` and `mlockall` failed (REQ-MEM-002).
    MlockUnavailable,
    /// The process is dumpable again; unlock refused before any key
    /// was derived (#134, SPEC OQ-10).
    ProcessDumpable,
    /// The `Unlocked` audit entry could not be written, so the
    /// unlock was rolled back (REQ-AUD-003).
    AuditFailed,
    /// Derivation failed (wrong password, sync error, export auth
    /// failure — not distinguished, REQ-API-006).
    UnlockFailed,
    /// The account sees items or organizations outside the kharon
    /// organization (REQ-CRY-008), so unlock was refused before the
    /// password was used. Owner surfaces name it (#243). The audit
    /// records it exactly like [`Self::UnlockFailed`] (see
    /// [`Self::is_auth_failure`]).
    ScopeTooBroad,
    /// The op is not implemented by this owner (test doubles).
    Unsupported,
    /// No grant request with that id (grant ops, #20).
    NotFound,
    /// The grant request is no longer pending (grant ops, #20).
    NotPending,
    /// Standing terms while standing grants are disabled (#20).
    StandingDisabled,
    /// Grant terms outside SPEC §5's bounds (grant ops, #20).
    InvalidTerms,
}

impl OwnerFailure {
    /// Stable machine-readable code for the response line.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AlreadyUnlocked => "already_unlocked",
            Self::MlockUnavailable => "mlock_unavailable",
            Self::ProcessDumpable => "process_dumpable",
            Self::AuditFailed => "audit_failed",
            Self::UnlockFailed => "unlock_failed",
            Self::ScopeTooBroad => "scope_too_broad",
            Self::Unsupported => "unknown_op",
            Self::NotFound => "not_found",
            Self::NotPending => "not_pending",
            Self::StandingDisabled => "standing_disabled",
            Self::InvalidTerms => "invalid_terms",
        }
    }

    /// Whether this unlock failure is audited as `owner_auth_fail`
    /// (`unlock_failed`). A scope refusal is, exactly like a wrong
    /// password: only the owner-facing code differs (#243), so the
    /// log and the agent side learn nothing new. State refusals
    /// (already unlocked, mlock, audit) are not auth failures.
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Self::UnlockFailed | Self::ScopeTooBroad)
    }
}

/// The owner-facing hint for [`OwnerFailure::ScopeTooBroad`] (#243),
/// shared by the CLI and the owner UI's unlock page.
pub const SCOPE_TOO_BROAD_HINT: &str = "the kharon account can see items or organizations outside its kharon organization (personal-vault items count). Move or delete them in Bitwarden, then unlock again.";

/// A parsed request line. The `password` field is deliberately
/// *not* in this struct: it is hand-decoded from the raw line (see
/// [`parse_request`]) so no serde scratch copy of it ever exists.
#[derive(Deserialize)]
struct Request {
    op: String,
    /// Read only by the `canary-scan`-gated scan op.
    #[cfg_attr(not(feature = "canary-scan"), allow(dead_code))]
    #[serde(default)]
    needle: Option<Zeroizing<String>>,
    /// Read only by the `canary-scan`-gated scan op.
    #[cfg_attr(not(feature = "canary-scan"), allow(dead_code))]
    #[serde(default)]
    needle_hex: Option<Zeroizing<String>>,
    /// Grant ops (#20): the `gr_…` request to decide.
    #[serde(default)]
    request_id: Option<String>,
    /// Grant ops: `once` | `per-origin` | `standing`.
    #[serde(default)]
    kind: Option<String>,
    /// Grant ops: approve with collection scope instead of item.
    #[serde(default)]
    scope_collection: Option<String>,
    /// Grant ops: TTL override, seconds.
    #[serde(default)]
    ttl_s: Option<u64>,
    /// Grant ops: use-cap override.
    #[serde(default)]
    max_uses: Option<u64>,
    /// Revoke / unsuspend: grant id.
    #[serde(default)]
    grant_id: Option<String>,
    /// Revoke agent / unsuspend: agent id.
    #[serde(default)]
    agent_id: Option<String>,
}

/// The socket path for a daemon with this `data_dir`.
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("owner.sock")
}

/// Bind the owner socket at `path`: a stale socket file from a
/// previous (possibly kill -9'd, REQ-MEM-005) run is unlinked
/// first, and the socket is mode 0600.
///
/// The unconditional unlink is safe only because of a load-bearing
/// ordering in `daemon::start`: the audit log is opened
/// *exclusively* before the owner socket is bound, so a second
/// daemon pointed at the same `data_dir` dies at the audit open
/// and can never reach this unlink while the first daemon's socket
/// is live. Do not reorder those steps.
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

/// The owner socket's peer gate (REQ-APR-006): a connection is
/// served only when its peer credentials were readable *and* the
/// peer's uid is the daemon's own effective uid. Anything else —
/// another uid, or credentials the kernel would not give us — is
/// rejected (and audited by the caller as `owner_auth_fail` /
/// `peer_uid`).
pub fn peer_uid_accepted(peer_uid: Option<u32>, own_uid: u32) -> bool {
    peer_uid == Some(own_uid)
}

async fn handle<O: OwnerOps>(mut stream: UnixStream, ops: Arc<O>) -> std::io::Result<()> {
    // Owner-only: the peer must be a process running as the same
    // effective uid as the daemon.
    let peer_ok = peer_uid_accepted(
        stream.peer_cred().ok().map(|c| c.uid()),
        rustix::process::geteuid().as_raw(),
    );
    if !peer_ok {
        // Rejected peers are audited (REQ-AUD-003), then dropped
        // without a reply, as before.
        ops.auth_failed("peer_uid").await;
        return Ok(());
    }

    // Pre-sized to the cap plus one chunk, so the buffer NEVER
    // reallocates while it may hold a password prefix (a realloc
    // frees the old allocation unwiped; `Zeroizing` only wipes the
    // final one — PR #81 review, item 7). The chunk lives in a
    // `Zeroizing` buffer so the `?` error paths wipe it too.
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_BYTES + READ_CHUNK));
    let mut chunk = Zeroizing::new([0u8; READ_CHUNK]);
    let read = tokio::time::timeout(READ_TIMEOUT, async {
        loop {
            let n = stream.read(&mut chunk[..]).await?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            chunk[..].fill(0);
            if raw.len() > MAX_REQUEST_BYTES {
                // Refused WITHOUT parsing (the previous code broke
                // out and parsed the truncated buffer anyway).
                return Ok::<bool, std::io::Error>(true);
            }
            if raw.contains(&b'\n') {
                break;
            }
        }
        Ok(false)
    })
    .await;
    let too_long = match read {
        Ok(Ok(too_long)) => too_long,
        // I/O error or the read timeout: drop the connection
        // without a reply.
        _ => return Ok(()),
    };
    if too_long {
        stream
            .write_all(error_response("bad_request").as_bytes())
            .await?;
        return Ok(());
    }
    let line_end = raw.iter().position(|b| *b == b'\n').unwrap_or(raw.len());
    let parsed = parse_request(&raw[..line_end]);
    // The request bytes held the password: wipe them now that the
    // parsed copies (themselves zeroizing) exist.
    raw.zeroize();

    let response = match parsed {
        Ok((req, password)) => dispatch(req, password, ops).await,
        Err(()) => Zeroizing::new(error_response("bad_request")),
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Parse one request line. The `password` field's raw string
/// content is located by byte scan and hand-decoded into a
/// zeroizing buffer ([`decode_json_string`]); the copy serde sees
/// has that content overwritten with `x`s, so serde's internal
/// escape-decoding scratch never holds the real password.
fn parse_request(line: &[u8]) -> Result<(Request, Option<Zeroizing<String>>), ()> {
    let mut password = None;
    let mut redacted = Zeroizing::new(line.to_vec());
    if let Some(content) = find_string_field(line, b"password") {
        password = Some(decode_json_string(&line[content.clone()]).ok_or(())?);
        redacted[content].fill(b'x');
    }
    let req: Request = serde_json::from_slice(&redacted).map_err(|_| ())?;
    Ok((req, password))
}

/// The content range (between the quotes) of the first
/// `"<field>": "<string>"` value among the **top-level keys** of a
/// JSON object line, or `None` if the field is absent or not a
/// plain string value.
///
/// Only depth-1 keys match (PR #81 re-review, nit 5): a
/// `"password"` byte sequence inside another string value, or a
/// `password` key of a nested object, is *not* the field — the
/// earlier byte-scan took the first match anywhere, which a
/// crafted value could have shadowed. The scan is a small state
/// machine over string tokens and brace depth; escape-aware
/// throughout (a `\"` inside a string neither ends it nor counts
/// as a key). Key comparison is on the raw content bytes, so a key
/// spelled with `\u` escapes is not recognized — the owner's own
/// client never spells it that way, and an unrecognized key simply
/// leaves the request without a password (`bad_request`).
fn find_string_field(line: &[u8], field: &[u8]) -> Option<std::ops::Range<usize>> {
    let skip_ws = |mut i: usize| {
        while i < line.len() && line[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    // End (index of the closing quote) of the string token whose
    // content starts at `start`, or None if unterminated.
    let string_end = |start: usize| {
        let mut j = start;
        while j < line.len() {
            match line[j] {
                b'\\' => j += 2,
                b'"' => return Some(j),
                _ => j += 1,
            }
        }
        None
    };
    let mut depth = 0usize;
    let mut i = 0;
    while i < line.len() {
        match line[i] {
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'"' => {
                let start = i + 1;
                let end = string_end(start)?;
                if depth == 1 && &line[start..end] == field {
                    // A key: `<field> : "value"`.
                    let colon = skip_ws(end + 1);
                    if line.get(colon) == Some(&b':') {
                        let value = skip_ws(colon + 1);
                        if line.get(value) == Some(&b'"') {
                            let vstart = value + 1;
                            let vend = string_end(vstart)?;
                            return Some(vstart..vend);
                        }
                        return None;
                    }
                }
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Decode a JSON string's raw content (the bytes between the
/// quotes, escapes intact) into a zeroizing `String`, without any
/// intermediate unwiped copy: decoding writes straight into the
/// zeroizing buffer, and `String::from_utf8` takes that buffer's
/// allocation over without copying. `None` on a malformed escape
/// or invalid UTF-8.
fn decode_json_string(content: &[u8]) -> Option<Zeroizing<String>> {
    fn hex4(content: &[u8], at: usize) -> Option<u32> {
        let s = content.get(at..at + 4)?;
        std::str::from_utf8(s)
            .ok()
            .and_then(|s| u32::from_str_radix(s, 16).ok())
    }
    let mut out = Zeroizing::new(Vec::with_capacity(content.len()));
    let mut i = 0;
    while i < content.len() {
        if content[i] != b'\\' {
            out.push(content[i]);
            i += 1;
            continue;
        }
        let esc = *content.get(i + 1)?;
        i += 2;
        match esc {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b'/' => out.push(b'/'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'u' => {
                let mut cp = hex4(content, i)?;
                i += 4;
                if (0xd800..0xdc00).contains(&cp) {
                    // High surrogate: a `\uXXXX` low surrogate must
                    // follow.
                    if content.get(i) != Some(&b'\\') || content.get(i + 1) != Some(&b'u') {
                        return None;
                    }
                    let lo = hex4(content, i + 2)?;
                    if !(0xdc00..0xe000).contains(&lo) {
                        return None;
                    }
                    i += 6;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                }
                let ch = char::from_u32(cp)?;
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            _ => return None,
        }
    }
    // Take the allocation over (no copy); the emptied zeroizing
    // Vec drops harmlessly. On invalid UTF-8 the error owns the
    // decoded buffer: wipe it explicitly before dropping it
    // (PR #81 re-review, nit 4 — `.ok()` would drop it unwiped).
    let bytes = std::mem::take(&mut *out);
    match String::from_utf8(bytes) {
        Ok(s) => Some(Zeroizing::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            None
        }
    }
}

async fn dispatch<O: OwnerOps>(
    req: Request,
    password: Option<Zeroizing<String>>,
    ops: Arc<O>,
) -> Zeroizing<String> {
    // The reply moves into a zeroizing buffer (the enrollment code
    // is the one secret a reply can carry). Moving the `String`
    // does not copy its bytes.
    Zeroizing::new(dispatch_line(req, password, ops).await)
}

async fn dispatch_line<O: OwnerOps>(
    req: Request,
    password: Option<Zeroizing<String>>,
    ops: Arc<O>,
) -> String {
    match req.op.as_str() {
        "unlock" => {
            let Some(password) = password else {
                return error_response("bad_request");
            };
            match ops.unlock(password).await {
                Ok(()) => ok_response(Some(false)),
                Err(e) => {
                    // A failed *authentication* (wrong password,
                    // unreachable server, bad export — the one
                    // indistinguishable bucket — and the scope
                    // refusal, #243) is audited as `owner_auth_fail`.
                    // State refusals (already unlocked, mlock, audit)
                    // are not auth failures and are not recorded as one.
                    if e.is_auth_failure() {
                        ops.auth_failed("unlock_failed").await;
                    }
                    error_response(e.code())
                }
            }
        }
        "lock" => {
            ops.lock().await;
            ok_response(Some(true))
        }
        "status" => status_response(ops.is_locked().await, ops.owner_ui_without_edge_address()),
        "grants" => {
            let pending: Vec<serde_json::Value> = ops
                .pending_grants()
                .await
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "request_id": p.request_id,
                        "agent_id": p.agent_id,
                        "item_id": p.item_id,
                        "action": p.action,
                        "origin": p.origin,
                    })
                })
                .collect();
            let mut out = serde_json::json!({ "ok": true, "pending": pending }).to_string();
            out.push('\n');
            out
        }
        "approve" => {
            let Some(request_id) = req.request_id.clone() else {
                return error_response("bad_request");
            };
            let kind = match req.kind.as_deref() {
                None => None,
                Some("once") => Some(crate::config::GrantKind::Once),
                Some("per-origin") => Some(crate::config::GrantKind::PerOrigin),
                Some("standing") => Some(crate::config::GrantKind::Standing),
                Some(_) => return error_response("bad_request"),
            };
            let args = ApproveArgs {
                request_id,
                kind,
                scope_collection: req.scope_collection.clone(),
                ttl_s: req.ttl_s,
                max_uses: req.max_uses,
            };
            match ops.approve(args).await {
                Ok(grant_id) => {
                    let mut out =
                        serde_json::json!({ "ok": true, "grant_id": grant_id }).to_string();
                    out.push('\n');
                    out
                }
                Err(e) => error_response(e.code()),
            }
        }
        "deny" => {
            let Some(request_id) = req.request_id.clone() else {
                return error_response("bad_request");
            };
            match ops.deny(request_id).await {
                Ok(()) => ok_response(None),
                Err(e) => error_response(e.code()),
            }
        }
        "revoke_grant" => {
            let Some(grant_id) = req.grant_id.clone() else {
                return error_response("bad_request");
            };
            match ops.revoke_grant(grant_id).await {
                Ok(true) => ok_response(None),
                Ok(false) => error_response("not_found"),
                Err(e) => error_response(e.code()),
            }
        }
        "revoke_agent" => {
            let Some(agent_id) = req.agent_id.clone() else {
                return error_response("bad_request");
            };
            match ops.revoke_agent(agent_id).await {
                Ok(n) => {
                    let mut out =
                        serde_json::json!({ "ok": true, "grants_revoked": n }).to_string();
                    out.push('\n');
                    out
                }
                Err(e) => error_response(e.code()),
            }
        }
        "unsuspend" => {
            let Some(agent_id) = req.agent_id.clone() else {
                return error_response("bad_request");
            };
            match ops.unsuspend(agent_id).await {
                Ok(()) => ok_response(None),
                Err(e) => error_response(e.code()),
            }
        }
        "panic" => match ops.panic_lock().await {
            Ok(()) => ok_response(Some(true)),
            Err(e) => error_response(e.code()),
        },
        "scan" => scan_response(req),
        "passkey_enroll" => match ops.passkey_enroll().await {
            Ok(token) => format!("{{\"ok\":true,\"enroll_token\":\"{}\"}}\n", token.as_str()),
            Err(e) => error_response(e.code()),
        },
        _ => error_response("unknown_op"),
    }
}

/// The canary scan (REQ-MEM-003), gated on the non-default
/// `canary-scan` cargo feature (PR #81 review, item 5): a plain
/// `debug_assertions` gate would hand every debug build a
/// memory-content oracle for its own uid.
fn scan_response(req: Request) -> String {
    scan_response_gated(cfg!(feature = "canary-scan"), &req)
}

fn scan_response_gated(enabled: bool, req: &Request) -> String {
    if !enabled {
        return error_response("unknown_op");
    }
    #[cfg(feature = "canary-scan")]
    {
        scan_response_enabled(req)
    }
    #[cfg(not(feature = "canary-scan"))]
    {
        let _ = req;
        error_response("unknown_op")
    }
}

/// The scan itself (feature builds only). The needle's own buffer
/// is excluded from the scan (it is, necessarily, in memory); see
/// [`crate::memscan`]. A scan that cannot read answers
/// `scan_unavailable`, never `hits:0`.
#[cfg(feature = "canary-scan")]
fn scan_response_enabled(req: &Request) -> String {
    // The needle bytes the scan runs on, and the buffer(s) holding
    // those exact bytes in this process — all of them are excluded
    // from the count (the needle is, necessarily, in memory).
    // Text path: scan the request's own buffer in place (copying
    // it and excluding only the copy would count the original —
    // a self-hit on every scan). Hex path: the decoded buffer is
    // the only raw copy (the request holds hex text, not bytes).
    let decoded: Zeroizing<Vec<u8>>;
    let bytes: &[u8] = if let Some(hex) = &req.needle_hex {
        match hex::decode(hex.as_str()) {
            Ok(bytes) => decoded = Zeroizing::new(bytes),
            Err(_) => return error_response("bad_request"),
        }
        &decoded
    } else if let Some(needle) = &req.needle {
        needle.as_bytes()
    } else {
        return error_response("bad_request");
    };
    if bytes.is_empty() || bytes.len() > 256 {
        return error_response("bad_request");
    }
    let range = (bytes.as_ptr() as usize)..(bytes.as_ptr() as usize + bytes.len());
    match memscan::count_occurrences(bytes, &[range]) {
        Ok(hits) => format!("{{\"ok\":true,\"hits\":{hits}}}\n"),
        Err(_) => error_response("scan_unavailable"),
    }
}

fn ok_response(locked: Option<bool>) -> String {
    match locked {
        Some(locked) => format!("{{\"ok\":true,\"locked\":{locked}}}\n"),
        None => "{\"ok\":true}\n".to_owned(),
    }
}

/// The `status` reply.
#[derive(Serialize)]
struct StatusReply {
    ok: bool,
    locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_ui_without_edge_address: Option<u64>,
}

fn status_response(locked: bool, without_edge_address: Option<u64>) -> String {
    let reply = StatusReply {
        ok: true,
        locked,
        owner_ui_without_edge_address: without_edge_address,
    };
    // Plain fields: serializing cannot fail.
    let mut line = serde_json::to_string(&reply).unwrap_or_else(|_| "{\"ok\":true}".to_owned());
    line.push('\n');
    line
}

fn error_response(code: &str) -> String {
    format!("{{\"ok\":false,\"error\":\"{code}\"}}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(line: &[u8]) -> (Request, Option<Zeroizing<String>>) {
        parse_request(line).expect("request parses")
    }

    #[test]
    fn password_is_hand_decoded_with_escapes_intact() {
        // A password containing `\"`, `\\` and `\n` must arrive
        // byte-exact — and serde never decodes it (item 7): the
        // redacted copy parse would yield `xxx…` if it did.
        let line = br#"{"op":"unlock","password":"a\"b\\c\nd"}"#;
        let (req, password) = request(line);
        assert_eq!(req.op, "unlock");
        assert_eq!(password.as_deref().map(String::as_str), Some("a\"b\\c\nd"));
    }

    #[test]
    fn password_unicode_escapes_and_surrogate_pairs_decode() {
        let line = br#"{"op":"unlock","password":"\u00e9\ud83d\ude00"}"#;
        let (_, password) = request(line);
        assert_eq!(
            password.as_deref().map(String::as_str),
            Some("\u{e9}\u{1f600}")
        );
    }

    #[test]
    fn password_field_with_whitespace_and_other_fields() {
        let line = br#"{"op" : "unlock" , "password" : "plain" }"#;
        let (_, password) = request(line);
        assert_eq!(password.as_deref().map(String::as_str), Some("plain"));
        let (req, password) = request(br#"{"op":"status"}"#);
        assert_eq!(req.op, "status");
        assert!(password.is_none());
    }

    #[test]
    fn password_key_inside_a_string_value_does_not_shadow_the_field() {
        // Nit 5: the first `"password"` bytes sit inside the
        // `note` string value; the depth-1 key must win.
        let line = br#"{"op":"unlock","note":"x \"password\": \"decoy\" y","password":"real"}"#;
        let (_, password) = request(line);
        assert_eq!(password.as_deref().map(String::as_str), Some("real"));
    }

    #[test]
    fn password_key_in_a_nested_object_does_not_shadow_the_field() {
        // Nit 5: a nested object's `password` key is depth 2.
        let line = br#"{"op":"unlock","nested":{"password":"inner"},"password":"outer"}"#;
        let (_, password) = request(line);
        assert_eq!(password.as_deref().map(String::as_str), Some("outer"));
        // And with no depth-1 key at all, there is no password.
        let (_, password) = request(br#"{"op":"unlock","nested":{"password":"inner"}}"#);
        assert!(password.is_none());
    }

    /// OwnerOps double recording `owner_auth_fail` details.
    #[derive(Default)]
    struct MockOps {
        auth_failed: std::sync::Mutex<Vec<&'static str>>,
        unlock_err: Option<OwnerFailure>,
    }

    impl OwnerOps for MockOps {
        async fn unlock(&self, _password: Zeroizing<String>) -> Result<(), OwnerFailure> {
            self.unlock_err.map_or(Ok(()), Err)
        }

        async fn lock(&self) -> bool {
            true
        }

        async fn is_locked(&self) -> bool {
            true
        }

        async fn auth_failed(&self, detail: &'static str) {
            self.auth_failed.lock().unwrap().push(detail);
        }
    }

    #[tokio::test]
    async fn failed_unlock_is_audited_as_owner_auth_fail_state_refusals_are_not() {
        let (req, password) = request(br#"{"op":"unlock","password":"x"}"#);
        let ops = Arc::new(MockOps {
            unlock_err: Some(OwnerFailure::UnlockFailed),
            ..MockOps::default()
        });
        let reply = dispatch(req, password, Arc::clone(&ops)).await;
        assert_eq!(&*reply, &error_response("unlock_failed"));
        assert_eq!(*ops.auth_failed.lock().unwrap(), ["unlock_failed"]);

        let (req, password) = request(br#"{"op":"unlock","password":"x"}"#);
        let ops = Arc::new(MockOps {
            unlock_err: Some(OwnerFailure::AlreadyUnlocked),
            ..MockOps::default()
        });
        let reply = dispatch(req, password, ops.clone()).await;
        assert_eq!(&*reply, &error_response("already_unlocked"));
        assert!(ops.auth_failed.lock().unwrap().is_empty());
    }

    /// #243: the owner learns the unlock was refused for scope
    /// (REQ-CRY-008), while the audit records it exactly as before,
    /// as `owner_auth_fail` / `unlock_failed`.
    #[tokio::test]
    async fn scope_refusal_has_its_own_owner_code_and_the_same_audit() {
        let (req, password) = request(br#"{"op":"unlock","password":"x"}"#);
        let ops = Arc::new(MockOps {
            unlock_err: Some(OwnerFailure::ScopeTooBroad),
            ..MockOps::default()
        });
        let reply = dispatch(req, password, Arc::clone(&ops)).await;
        assert_eq!(&*reply, &error_response("scope_too_broad"));
        assert_eq!(*ops.auth_failed.lock().unwrap(), ["unlock_failed"]);
    }

    #[test]
    fn scan_op_is_refused_when_the_feature_is_off() {
        // The gate decision itself (item 5): with the feature off
        // the op must be indistinguishable from an unknown op.
        let (req, _) = request(br#"{"op":"scan","needle":"x"}"#);
        assert_eq!(
            scan_response_gated(false, &req),
            error_response("unknown_op")
        );
    }

    #[test]
    fn req_apr_006_only_the_daemons_own_uid_is_accepted() {
        assert!(peer_uid_accepted(Some(1000), 1000));
        assert!(!peer_uid_accepted(Some(1001), 1000));
        assert!(!peer_uid_accepted(Some(0), 1000));
        // Unreadable credentials are a rejection, never a pass.
        assert!(!peer_uid_accepted(None, 1000));
    }

    #[cfg(feature = "canary-scan")]
    #[test]
    fn scan_op_accepts_hex_needles_and_finds_a_planted_canary() {
        // Plant a non-UTF-8 canary in this process's heap, then
        // find it through the hex needle path (item 4).
        let canary: &[u8] =
            Box::leak(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0x42, 0x24].into_boxed_slice());
        let line = format!(
            "{{\"op\":\"scan\",\"needle_hex\":\"{}\"}}",
            hex::encode(canary)
        );
        let (req, _) = request(line.as_bytes());
        let reply = scan_response_gated(true, &req);
        let hits: usize = reply
            .split("\"hits\":")
            .nth(1)
            .and_then(|s| s.trim_end_matches(['}', '\n']).parse().ok())
            .expect("scan reply carries hits");
        assert!(hits >= 1, "hex-needle canary must be found: {reply}");
        // Bad hex is a bad request, not a scan.
        let (req, _) = request(br#"{"op":"scan","needle_hex":"zz"}"#);
        assert_eq!(
            scan_response_gated(true, &req),
            error_response("bad_request")
        );
    }
}
