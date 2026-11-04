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
//!   never in config, env, or argv (REQ-EXP-003); this socket (or
//!   the future web UI) is the only way in.
//! - `{"op":"lock"}` — lock now, destroying the session.
//! - `{"op":"status"}` — `{"ok":true,"locked":<bool>}`.
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
//! unreachable server, bad export — deliberately indistinguishable).
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

use serde::Deserialize;
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
        Err(()) => error_response("bad_request"),
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
/// `"<field>": "<string>"` value in a flat JSON object line, or
/// `None` if the field is absent or not a plain string value.
/// Escape-aware: a `\"` inside the string does not end it.
fn find_string_field(line: &[u8], field: &[u8]) -> Option<std::ops::Range<usize>> {
    let mut needle = Vec::with_capacity(field.len() + 2);
    needle.push(b'"');
    needle.extend_from_slice(field);
    needle.push(b'"');
    let at = line
        .windows(needle.len())
        .position(|w| w == needle.as_slice())?;
    let mut i = at + needle.len();
    let skip_ws = |mut i: usize| {
        while i < line.len() && line[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    i = skip_ws(i);
    if line.get(i) != Some(&b':') {
        return None;
    }
    i = skip_ws(i + 1);
    if line.get(i) != Some(&b'"') {
        return None;
    }
    let start = i + 1;
    let mut j = start;
    while j < line.len() {
        match line[j] {
            b'\\' => j += 2,
            b'"' => return Some(start..j),
            _ => j += 1,
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
    // Vec drops harmlessly.
    let bytes = std::mem::take(&mut *out);
    String::from_utf8(bytes).ok().map(Zeroizing::new)
}

async fn dispatch<O: OwnerOps>(
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
    fn scan_op_is_refused_when_the_feature_is_off() {
        // The gate decision itself (item 5): with the feature off
        // the op must be indistinguishable from an unknown op.
        let (req, _) = request(br#"{"op":"scan","needle":"x"}"#);
        assert_eq!(
            scan_response_gated(false, &req),
            error_response("unknown_op")
        );
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
