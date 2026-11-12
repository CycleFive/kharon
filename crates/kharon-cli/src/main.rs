//! kharon owner CLI.
//!
//! Owner tool over the daemon's owner socket: unlock/lock/status,
//! grants/approve/deny (REQ-APR-006), revoke/unsuspend/panic
//! (REQ-REV-001/002, REQ-RL-002), plus `init`; this binary also
//! provides the
//! audit verifier, REQ-AUD-001/002's "owner or offline tool can
//! check the log", and the owner unlock channel (issue #11, SPEC
//! §8): `kharon unlock` / `kharon lock` / `kharon status` talk to
//! the daemon's unix owner socket. `kharon passkey-enroll` prints a
//! one-time WebAuthn enrollment code (REQ-APR-005); it is not a
//! password and does not sign in. `kharon passkey list` and
//! `kharon passkey remove <id>` list and remove enrolled passkeys
//! over the same socket (#258). The unlock password is read
//! from the terminal with echo disabled — never from argv, env,
//! or a file (REQ-EXP-003). A non-terminal stdin is refused, not
//! read (SPEC §8 "CLI (tty, no echo)"): a piped password would sit
//! in a script or another process's pipe buffer. `kharon init` generates the kharon account's
//! master password and prints it once to the terminal
//! (REQ-DEP-007). `kharon token mint` mints an agent token the
//! same way (once, on the terminal only) and prints the Argon2id
//! PHC `token_hash` on stdout for the config (REQ-API-003). That
//! mint is out of band: it does not talk to the daemon and does
//! not append `token_create` (SPEC §7).
//!
//! Password hygiene in this short-lived CLI (#86, closing the
//! PR #81 carry-overs): the password is read with `rustix::io::read`
//! into a fixed zeroizing buffer (no `BufReader` / `read_line`
//! std-internal copies), the JSON request frame is built by hand
//! into a pre-sized zeroizing buffer (no `serde_json::Value` copy
//! of the password, no growth reallocations), and a SIGINT during
//! the tty prompt restores the terminal's echo before exiting
//! (130) — `Drop` alone never runs on a signal. The daemon side
//! remains where REQ-MEM-003 is enforced and scanned for; these
//! measures keep the CLI from being the weakest copy.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zeroize::{Zeroize, Zeroizing};

/// The owner socket of a daemon with the SPEC §9 default
/// `data_dir` (`/data`). Override with `--socket`.
const DEFAULT_OWNER_SOCKET: &str = "/data/owner.sock";

#[derive(Parser)]
#[command(name = "kharon", about = "kharon owner CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Unlock the broker with the master/export password.
    Unlock {
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Lock the broker now, destroying the session.
    Lock {
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Print whether the broker is locked.
    Status {
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Print a one-time passkey enrollment code for the owner web UI.
    /// The code authorizes registration only; signing in still
    /// requires a passkey assertion.
    PasskeyEnroll {
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// List enrolled passkeys, or remove one (#258).
    #[command(subcommand)]
    Passkey(PasskeyCommand),
    /// List pending grant requests (REQ-APR-006).
    Grants {
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Revoke a grant, or an agent durably (REQ-REV-001).
    #[command(subcommand)]
    Revoke(RevokeCommand),
    /// Clear an agent's suspension (REQ-RL-002). Does not un-revoke.
    Unsuspend {
        /// Agent id.
        agent_id: String,
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Approve a pending grant request (REQ-APR-006; SPEC §5 CLI).
    Approve {
        /// The `gr_…` grant request id.
        request_id: String,
        /// Grant kind: `once` (default), `per-origin` or `standing`.
        #[arg(long)]
        kind: Option<String>,
        /// Grant TTL in seconds (SPEC §5's `--ttl`; bounded per kind
        /// by the daemon).
        #[arg(long)]
        ttl: Option<u64>,
        /// Use cap for the grant.
        #[arg(long)]
        max_uses: Option<u64>,
        /// Scope the grant to a collection instead of the item.
        #[arg(long)]
        scope_collection: Option<String>,
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Deny a pending grant request (REQ-APR-006).
    Deny {
        /// The `gr_…` grant request id.
        request_id: String,
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Panic: lock, zeroize, revoke all grants, close CDP (REQ-REV-002).
    Panic {
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Generate the kharon account's master password (REQ-DEP-007)
    /// and print it once to the terminal.
    Init,
    /// Mint an agent bearer token (REQ-API-003). Offline: the daemon
    /// is not contacted, and no `token_create` audit entry is written.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Mint a path-B tunnel credential (`connector_token_hash`).
    ///
    /// Shown once, on the terminal only. This is not an agent API token:
    /// the connector must not be given a token that can call `fill`.
    #[command(subcommand)]
    Tunnel(TunnelCommand),
}

/// `kharon passkey` — list or remove an enrolled owner passkey (#258).
#[derive(Subcommand)]
enum PasskeyCommand {
    /// List passkeys: short id, when it was enrolled, when it was last used.
    List {
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Remove one passkey by the short id from `passkey list`.
    ///
    /// Ends every live owner session opened with that passkey.
    /// Removing the last passkey is allowed; enroll again afterwards.
    /// The signed-in owner page refuses that last removal.
    Remove {
        /// The 8-character id printed by `passkey list`.
        id: String,
        /// The daemon's owner socket.
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
}

/// `kharon token` — out-of-band agent token provisioning (REQ-API-003).
#[derive(Subcommand)]
enum TokenCommand {
    /// Mint a token for one agent.
    ///
    /// The token is shown once, on the terminal only. The Argon2id PHC
    /// string (the `[agents.<id>]` `token_hash`) is printed on stdout.
    Mint {
        /// Agent id: `[a-z0-9-]{1,64}`, the `[agents.<id>]` table name.
        agent_id: String,
    },
}

/// `kharon tunnel` — out-of-band connector credential (path B).
#[derive(Subcommand)]
enum TunnelCommand {
    /// Mint a tunnel credential for one agent.
    ///
    /// The credential is shown once, on the terminal only. The Argon2id
    /// PHC string (`connector_token_hash`) is printed on stdout.
    Mint {
        /// Agent id: `[a-z0-9-]{1,64}`, the `[agents.<id>]` table name.
        agent_id: String,
    },
}

#[derive(Subcommand)]
enum RevokeCommand {
    /// Revoke one grant by id.
    Grant {
        /// `g_…` grant id.
        id: String,
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
    /// Revoke an agent's token and grants, durably (REQ-REV-001).
    ///
    /// The revocation is recorded in the audit log, bound to the
    /// fingerprint of the agent's configured token hash, and is
    /// rebuilt at every daemon start: restarting does not clear
    /// it. `kharon unsuspend` does not clear it either, and there
    /// is no un-revoke command. To restore an agent, rotate its
    /// token: `kharon token mint`, replace `token_hash` in the
    /// config, and restart.
    Agent {
        /// Agent id.
        id: String,
        #[arg(long, default_value = DEFAULT_OWNER_SOCKET)]
        socket: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Verify the hash-chained audit log against the off-host checkpoint stream.
    Verify {
        /// The audit directory, `<data_dir>/audit` (it holds `audit.jsonl` and
        /// `keys/`), for example `/data/audit` in the compose example.
        #[arg(long)]
        data: PathBuf,
        /// Off-host checkpoint stream (JSONL, one checkpoint per line). This
        /// is the load-bearing input: only a checkpoint the attacker can't
        /// rewrite detects tail truncation. Without it, verification is
        /// self-consistency against a key read from the same directory —
        /// useful, but it assumes that directory is intact. Pin the public
        /// key from a second source for stronger assurance.
        #[arg(long)]
        checkpoints: Option<PathBuf>,
    },
}

/// One owner-socket round trip: send `request` (which may hold a
/// zeroizing password buffer), return the parsed response.
///
/// Before anything is written, the peer's uid is checked against
/// our own effective uid (PR #81 review): the password must only
/// ever go to a daemon running as us, never to whatever happens to
/// be listening at `--socket`.
fn owner_request(
    socket: &PathBuf,
    request: &Zeroizing<String>,
) -> Result<serde_json::Value, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| format!("cannot connect to owner socket {socket:?}: {e}"))?;
    let peer_uid = {
        use std::os::fd::AsFd;
        rustix::net::sockopt::socket_peercred(stream.as_fd())
            .map(|c| c.uid.as_raw())
            .map_err(|e| format!("cannot read owner socket peer credentials: {e}"))?
    };
    if peer_uid != rustix::process::geteuid().as_raw() {
        return Err(format!(
            "owner socket peer uid {peer_uid} is not our euid; refusing to send to it"
        ));
    }
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|e| format!("cannot write to owner socket: {e}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("cannot read owner socket reply: {e}"))?;
    serde_json::from_str(&response).map_err(|_| "malformed reply from daemon".to_owned())
}

/// Longest password accepted, in bytes. The daemon's whole
/// request line is capped at 8192 bytes; a password near this cap
/// plus framing still fits comfortably.
const MAX_PASSWORD_BYTES: usize = 1024;

/// Read the unlock password from the terminal with echo off (SPEC
/// §8: "CLI (tty, no echo)"). A password piped or redirected into
/// stdin is refused before anything is read: it would sit in shell
/// history, a script, or another process's pipe buffer, and the
/// owner's terminal is the only CLI channel the spec allows.
fn read_password() -> Result<Zeroizing<String>, String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(STDIN_NOT_A_TERMINAL.to_owned());
    }
    read_password_tty()
}

/// The refusal for a non-terminal stdin. Fixed text: nothing from
/// the input is echoed back.
const STDIN_NOT_A_TERMINAL: &str = "unlock needs a terminal: the master password is read \
     from the tty with echo off, never from a pipe or a file";

/// Unbuffered [`Read`] over a borrowed fd: each `read` is exactly
/// one `rustix::io::read`, with no intermediate buffer of its own
/// (unlike `Stdin`, whose `BufReader` would hold a copy).
struct FdReader<'fd>(std::os::fd::BorrowedFd<'fd>);

impl Read for FdReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        rustix::io::read(self.0, buf).map_err(std::io::Error::from)
    }
}

/// Read one password line from `reader` into a **fixed** zeroizing
/// buffer (#86): `reader` is unbuffered ([`FdReader`] in the
/// binary), so there is no `BufReader` (whose 8 KiB heap buffer
/// would hold an unwiped copy) and no `read_line` (whose growth
/// reallocations would free unwiped prefixes). Stops at the first
/// `\n` anywhere in what has been read, or at EOF; a trailing `\r`
/// is stripped. On a pipe a single read can return `pw\nextra`
/// (#92): only `pw` is the password, the rest is ignored (and
/// wiped with the buffer). Overlong input is an error, never a
/// truncation.
fn read_password_line(reader: &mut impl Read, source: &str) -> Result<Zeroizing<String>, String> {
    let mut buf = Zeroizing::new([0u8; MAX_PASSWORD_BYTES]);
    let mut n = 0usize;
    loop {
        if n == buf.len() {
            return Err(format!(
                "password from {source} is too long (over {MAX_PASSWORD_BYTES} bytes)"
            ));
        }
        match reader.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(m) => {
                // Only the new bytes can hold the first newline.
                if let Some(i) = buf[n..n + m].iter().position(|b| *b == b'\n') {
                    n += i;
                    break;
                }
                n += m;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("cannot read password from {source}: {e}")),
        }
    }
    if n > 0 && buf[n - 1] == b'\r' {
        n -= 1;
    }
    // Take the bytes over into the String without a copy; on
    // invalid UTF-8 the error owns the buffer, so wipe it first
    // (same nit as kharond's owner decoder).
    let mut bytes = Zeroizing::new(buf[..n].to_vec());
    let bytes = std::mem::take(&mut *bytes);
    match String::from_utf8(bytes) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(format!("password from {source} is not valid UTF-8"))
        }
    }
}

/// Restore the terminal on SIGINT (#86). `EchoOff`'s `Drop`
/// cannot run when the process dies on a signal, so a watcher
/// thread waits on a tokio SIGINT stream (handled in a normal
/// thread, not a signal handler) and, if it fires, restores the
/// saved termios itself and exits with the conventional
/// 128+SIGINT.
///
/// The SIGINT handler is registered **synchronously, before this
/// returns** (#92): the caller turns echo off only afterwards, so
/// there is no window in which a SIGINT kills the process with
/// echo still off. (Registering inside the spawned thread, as
/// before, raced the prompt.) Best effort: if the watcher cannot
/// be installed the prompt still works; only the interrupt path
/// degrades.
fn watch_for_sigint(original: rustix::termios::Termios) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    // `signal()` installs the process-level handler right here,
    // not on first poll.
    let sigint = {
        let _ctx = rt.enter();
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    };
    let Ok(mut sigint) = sigint else {
        return;
    };
    std::thread::spawn(move || {
        let interrupted = rt.block_on(sigint.recv()).is_some();
        if interrupted {
            if let Ok(tty) = std::fs::File::open("/dev/tty") {
                use std::os::fd::AsFd;
                let _ = rustix::termios::tcsetattr(
                    tty.as_fd(),
                    rustix::termios::OptionalActions::Now,
                    &original,
                );
            }
            std::process::exit(130);
        }
    });
}

/// Disable echo on `/dev/tty` for the duration of the guard.
struct EchoOff(rustix::termios::Termios);

impl EchoOff {
    /// Turn echo off on `fd`, remembering `original` (from
    /// `tcgetattr`) for `Drop` to restore.
    fn new(
        fd: std::os::fd::BorrowedFd<'_>,
        original: rustix::termios::Termios,
    ) -> Result<Self, String> {
        let mut quiet = original.clone();
        quiet.local_modes &= !rustix::termios::LocalModes::ECHO;
        rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Now, &quiet)
            .map_err(|e| format!("cannot disable terminal echo: {e}"))?;
        Ok(Self(original))
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if let Ok(tty) = std::fs::File::open("/dev/tty") {
            use std::os::fd::AsFd;
            let _ = rustix::termios::tcsetattr(
                tty.as_fd(),
                rustix::termios::OptionalActions::Now,
                &self.0,
            );
        }
    }
}

fn read_password_tty() -> Result<Zeroizing<String>, String> {
    let tty = std::fs::File::open("/dev/tty").map_err(|e| format!("cannot open /dev/tty: {e}"))?;
    {
        use std::os::fd::AsFd;
        let original = rustix::termios::tcgetattr(tty.as_fd())
            .map_err(|e| format!("cannot read terminal settings: {e}"))?;
        // SIGINT watcher first, echo off second (#92).
        watch_for_sigint(original.clone());
        let _guard = EchoOff::new(tty.as_fd(), original)?;
        eprint!("kharon master password: ");
        let password = read_password_line(&mut FdReader(tty.as_fd()), "the terminal");
        eprintln!();
        password
    }
}

/// The unlock request frame, built by hand into a pre-sized
/// zeroizing buffer (#86): `serde_json::json!` would first copy
/// the password into a `Value::String`, and serializing that into
/// a growing `String` would free unwiped prefixes on reallocation.
/// The capacity covers the worst case (every password byte a
/// control character, at 6 bytes per `\u00XX` escape) plus the
/// framing, so the buffer never grows. JSON string escaping:
/// `"` and `\` escaped, the short escapes for `\n`/`\r`/`\t`,
/// other control characters as `\u00XX`, everything else raw
/// UTF-8. That is valid JSON that serde_json parses back to the
/// same password (tested below), but not byte-identical to
/// serde_json's own output, which uses the short `\b`/`\f`
/// escapes where this writes `\u0008`/`\u000c`.
fn unlock_frame(password: &str) -> Zeroizing<String> {
    use std::fmt::Write as _;
    let mut frame = Zeroizing::new(String::with_capacity(password.len() * 6 + 32));
    frame.push_str("{\"op\":\"unlock\",\"password\":\"");
    for ch in password.chars() {
        match ch {
            '"' => frame.push_str("\\\""),
            '\\' => frame.push_str("\\\\"),
            '\n' => frame.push_str("\\n"),
            '\r' => frame.push_str("\\r"),
            '\t' => frame.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Straight into the zeroizing buffer: no `format!`
                // heap temporary holding the escape (#92). Writing
                // to a `String` cannot fail.
                let _ = write!(frame, "\\u{:04x}", c as u32);
            }
            c => frame.push(c),
        }
    }
    frame.push_str("\"}");
    frame
}

/// Print one line per passkey: short id, enrolled-at, last-used-at.
/// A missing timestamp is `-`. Stdout is the list; stderr is refusals.
fn passkey_list(socket: &PathBuf) -> ExitCode {
    let request = Zeroizing::new("{\"op\":\"passkey_list\"}".to_owned());
    match owner_request(socket, &request) {
        Ok(reply) if reply.get("ok") == Some(&serde_json::Value::Bool(true)) => {
            let Some(rows) = reply.get("passkeys").and_then(|v| v.as_array()) else {
                eprintln!("kharon: daemon reply had no passkey list");
                return ExitCode::FAILURE;
            };
            if rows.is_empty() {
                println!("no passkeys");
                return ExitCode::SUCCESS;
            }
            for row in rows {
                let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let enrolled = row
                    .get("enrolled_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let used = row
                    .get("last_used_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                println!("{id}\tenrolled={enrolled}\tlast_used={used}");
            }
            ExitCode::SUCCESS
        }
        Ok(reply) => {
            let code = reply["error"].as_str().unwrap_or("unknown");
            eprintln!("{}", refusal_line(code));
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("kharon: {e}");
            ExitCode::from(2)
        }
    }
}

/// Remove one passkey. The id is the owner's own short id, echoed
/// only on success.
fn passkey_remove(socket: &PathBuf, id: &str) -> ExitCode {
    let request =
        Zeroizing::new(serde_json::json!({ "op": "passkey_remove", "id": id }).to_string());
    match owner_request(socket, &request) {
        Ok(reply) if reply.get("ok") == Some(&serde_json::Value::Bool(true)) => {
            println!("removed {id}");
            ExitCode::SUCCESS
        }
        Ok(reply) => {
            let code = reply["error"].as_str().unwrap_or("unknown");
            eprintln!("{}", refusal_line(code));
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("kharon: {e}");
            ExitCode::from(2)
        }
    }
}

/// Print the enrollment code once, to stdout only. Stderr is for
/// refusals, which do not include the code.
fn passkey_enroll(socket: &PathBuf) -> ExitCode {
    let request = Zeroizing::new("{\"op\":\"passkey_enroll\"}".to_owned());
    match owner_request(socket, &request) {
        Ok(reply) if reply.get("ok") == Some(&serde_json::Value::Bool(true)) => {
            match reply.get("enroll_token").and_then(|v| v.as_str()) {
                Some(token) if !token.is_empty() => {
                    println!("{token}");
                    ExitCode::SUCCESS
                }
                _ => {
                    eprintln!("kharon: daemon reply had no enrollment code");
                    ExitCode::FAILURE
                }
            }
        }
        Ok(reply) => {
            let code = reply["error"].as_str().unwrap_or("unknown");
            eprintln!("kharon: daemon refused [{code}]");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("kharon: {e}");
            ExitCode::from(2)
        }
    }
}

/// Run an owner command; print the outcome for the owner.
fn owner_command(command: &Command) -> ExitCode {
    let (socket, request) = match command {
        Command::Unlock { socket } => {
            let password = match read_password() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("kharon: {e}");
                    return ExitCode::from(2);
                }
            };
            if password.is_empty() {
                eprintln!("kharon: empty password");
                return ExitCode::from(2);
            }
            let request = unlock_frame(password.as_str());
            (socket, request)
        }
        Command::Lock { socket } => (socket, Zeroizing::new("{\"op\":\"lock\"}".to_owned())),
        Command::Status { socket } => (socket, Zeroizing::new("{\"op\":\"status\"}".to_owned())),
        Command::Grants { socket } => (socket, Zeroizing::new("{\"op\":\"grants\"}".to_owned())),
        Command::Approve {
            request_id,
            kind,
            ttl,
            max_uses,
            scope_collection,
            socket,
        } => (
            socket,
            Zeroizing::new(
                serde_json::json!({
                    "op": "approve",
                    "request_id": request_id,
                    "kind": kind,
                    "ttl_s": ttl,
                    "max_uses": max_uses,
                    "scope_collection": scope_collection,
                })
                .to_string(),
            ),
        ),
        Command::Deny { request_id, socket } => (
            socket,
            Zeroizing::new(
                serde_json::json!({ "op": "deny", "request_id": request_id }).to_string(),
            ),
        ),
        Command::Revoke(RevokeCommand::Grant { id, socket }) => (
            socket,
            Zeroizing::new(format!(
                "{{\"op\":\"revoke_grant\",\"grant_id\":{}}}",
                serde_json::to_string(id).expect("string")
            )),
        ),
        Command::Revoke(RevokeCommand::Agent { id, socket }) => (
            socket,
            Zeroizing::new(format!(
                "{{\"op\":\"revoke_agent\",\"agent_id\":{}}}",
                serde_json::to_string(id).expect("string")
            )),
        ),
        Command::Unsuspend { agent_id, socket } => (
            socket,
            Zeroizing::new(format!(
                "{{\"op\":\"unsuspend\",\"agent_id\":{}}}",
                serde_json::to_string(agent_id).expect("string")
            )),
        ),
        Command::Panic { socket } => (socket, Zeroizing::new("{\"op\":\"panic\"}".to_owned())),
        Command::Audit(_)
        | Command::Init
        | Command::Token(_)
        | Command::Tunnel(_)
        | Command::PasskeyEnroll { .. }
        | Command::Passkey(_) => {
            unreachable!()
        }
    };
    match owner_request(socket, &request) {
        Ok(reply) if reply["ok"] == serde_json::Value::Bool(true) => {
            match reply["locked"].as_bool() {
                Some(true) => println!("locked"),
                Some(false) => println!("unlocked"),
                None => {
                    if let Some(pending) = reply["pending"].as_array() {
                        for p in pending {
                            println!(
                                "{} agent={} item={} action={} origin={}",
                                p["request_id"].as_str().unwrap_or("?"),
                                p["agent_id"].as_str().unwrap_or("?"),
                                p["item_id"].as_str().unwrap_or("?"),
                                p["action"].as_str().unwrap_or("?"),
                                p["origin"].as_str().unwrap_or("?"),
                            );
                        }
                        if pending.is_empty() {
                            println!("no pending requests");
                        }
                    } else if let Some(gid) = reply["grant_id"].as_str() {
                        println!("grant {gid}");
                    } else {
                        println!("ok");
                    }
                }
            }
            if let Some(n) = reply["owner_ui_without_edge_address"]
                .as_u64()
                .filter(|n| *n > 0)
            {
                println!(
                    "owner UI: {n} requests without a usable CF-Connecting-IP (not throttled)"
                );
            }
            ExitCode::SUCCESS
        }
        Ok(reply) => {
            let code = reply["error"].as_str().unwrap_or("unknown");
            eprintln!("{}", refusal_line(code));
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("kharon: {e}");
            ExitCode::from(2)
        }
    }
}

/// The stderr line for a daemon refusal: the fixed code, plus a hint
/// for the codes the owner can act on (#243). The code comes from the
/// daemon's fixed set, never from a peer.
fn refusal_line(code: &str) -> String {
    match code {
        "scope_too_broad" => format!(
            "kharon: daemon refused [{code}]: {}",
            kharond::owner::SCOPE_TOO_BROAD_HINT
        ),
        _ => format!("kharon: daemon refused [{code}]"),
    }
}

/// Random bytes in a generated master password: 160 bits, above
/// REQ-DEP-007's 128-bit floor.
const MASTER_PASSWORD_BYTES: usize = 20;
/// Characters per group in the printed password.
const MASTER_PASSWORD_GROUP: usize = 4;
/// Crockford's base32 alphabet, lowercase: no `i`, `l`, `o` or `u`,
/// so the password survives being read aloud or copied by hand.
const BASE32: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// A fresh master password: [`MASTER_PASSWORD_BYTES`] from the OS
/// RNG, base32 (5 bits a character, so 32 characters with no
/// padding), in hyphen-separated groups of four. Every buffer that
/// holds it zeroizes on drop.
fn generate_master_password() -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0u8; MASTER_PASSWORD_BYTES]);
    let mut filled = 0;
    while filled < MASTER_PASSWORD_BYTES {
        match rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(format!("OS RNG: {e}")),
        }
    }
    let chars = MASTER_PASSWORD_BYTES * 8 / 5;
    let mut out = Zeroizing::new(String::with_capacity(chars + chars / MASTER_PASSWORD_GROUP));
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut written = 0;
    for &b in bytes.iter() {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if written > 0 && written % MASTER_PASSWORD_GROUP == 0 {
                out.push('-');
            }
            out.push(char::from(BASE32[((acc >> bits) & 31) as usize]));
            written += 1;
        }
        acc &= (1 << bits) - 1;
    }
    Ok(out)
}

/// `kharon token mint`: print a new agent token once, to the
/// controlling terminal only, and its Argon2id PHC hash to stdout
/// (the `token_hash` config value). The token never goes to stdout,
/// stderr, a file or the daemon. Without a terminal the command
/// refuses and mints nothing. Provisioning is out of band (SPEC §7):
/// this does not append `token_create`.
fn mint_tunnel_command(agent_id: &str) -> ExitCode {
    mint_secret(agent_id, MintKind::Tunnel)
}

fn mint_token_command(agent_id: &str) -> ExitCode {
    mint_secret(agent_id, MintKind::Agent)
}

enum MintKind {
    Agent,
    Tunnel,
}

fn mint_secret(agent_id: &str, kind: MintKind) -> ExitCode {
    if !kharond::api::token::valid_agent_id(agent_id) {
        eprintln!("kharon: agent id must match [a-z0-9-]{{1,64}} (the [agents.<id>] table name)");
        return ExitCode::from(2);
    }
    let mut tty = match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "kharon: token mint shows the token only on a terminal, and /dev/tty is \
                 unavailable ({e}); run it in an interactive shell"
            );
            return ExitCode::from(2);
        }
    };
    let (token, hash) = match kind {
        MintKind::Agent => kharond::api::token::generate(agent_id),
        MintKind::Tunnel => kharond::api::token::generate_tunnel(agent_id),
    };
    let secret = token.expose_secret();
    let mut text = Zeroizing::new(String::with_capacity(secret.len() + 800));
    match kind {
        MintKind::Agent => {
            text.push_str("\nAgent token for `");
            text.push_str(agent_id);
            text.push_str("` (shown once; store it outside kharon):\n\n    ");
            text.push_str(secret);
            text.push_str("\n\ntoken_hash for [agents.");
            text.push_str(agent_id);
            text.push_str(
                "] is the next line of stdout (one Argon2id PHC line). Paste that\n\
                 line into the config and never put this token there. kharon does\n\
                 not keep the token, the daemon is not contacted, and this mint is not\n\
                 an audit event (SPEC §7).\n\n",
            );
        }
        MintKind::Tunnel => {
            text.push_str("\nTunnel credential for `");
            text.push_str(agent_id);
            text.push_str("` (shown once; this is not an agent API token):\n\n    ");
            text.push_str(secret);
            text.push_str("\n\nconnector_token_hash for [agents.");
            text.push_str(agent_id);
            text.push_str(
                "] is the next line of stdout (one Argon2id PHC line). Paste that\n\
                 line into the broker config. Put the credential only in the connector's\n\
                 token file on the agent host. It cannot call fill. kharon does not keep\n\
                 it, the daemon is not contacted, and this mint is not an audit event.\n\n",
            );
        }
    }
    if let Err(e) = tty.write_all(text.as_bytes()).and_then(|()| tty.flush()) {
        eprintln!("kharon: cannot write to the terminal: {e}");
        return ExitCode::from(2);
    }
    // The token-bearing buffer is dropped before the hash is written,
    // so a failure while printing the hash has nothing left to leak.
    drop(text);
    drop(token);
    let mut stdout = std::io::stdout().lock();
    match writeln!(stdout, "{hash}").and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "kharon: the token was shown, but the token_hash could not be written ({e}); \
                 discard that token and run the command again"
            );
            ExitCode::from(2)
        }
    }
}

/// `kharon init`: print a new master password once, to the
/// controlling terminal only. It never goes to stdout, stderr, a
/// file or the daemon, so it cannot end up in a pipe, a log or a
/// shell redirect; without a terminal the command refuses.
fn init_command() -> ExitCode {
    let mut tty = match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "kharon: init prints the password only to a terminal, and /dev/tty is \
                 unavailable ({e}); run it in an interactive shell"
            );
            return ExitCode::from(2);
        }
    };
    let password = match generate_master_password() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kharon: {e}");
            return ExitCode::from(2);
        }
    };
    let mut text = Zeroizing::new(String::with_capacity(1024));
    text.push_str("\nMaster password for the kharon Bitwarden account (160 bits):\n\n    ");
    text.push_str(password.as_str());
    text.push_str(
        "\n\n\
         Use it when you create the kharon account, then store it in your own\n\
         vault, outside the kharon organization. kharon does not keep it and\n\
         this is the only time it is shown. Anyone holding the API-key file and\n\
         a copy of the server's data is left with an offline attack on this\n\
         password, which is why it is long and random (SPEC REQ-DEP-007).\n\n",
    );
    match tty.write_all(text.as_bytes()).and_then(|()| tty.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kharon: cannot write to the terminal: {e}");
            ExitCode::from(2)
        }
    }
}

/// SPEC §8 / #134: make this process non-dumpable with core limit 0,
/// as kharond does at startup (REQ-MEM-001). `kharon` holds the master
/// password (`init`, `unlock`) and fresh tokens (`token mint`, `tunnel
/// mint`), and the release build aborts on panic: without this, an
/// abort could leave a core dump with those secrets in it. A
/// non-dumpable process gets no dump at all, whatever the host's
/// `core_pattern`, and same-uid processes cannot ptrace it.
fn harden_process() -> rustix::io::Result<()> {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
}

fn main() -> ExitCode {
    if let Err(e) = harden_process() {
        eprintln!("kharon: cannot make the process non-dumpable: {e}");
        return ExitCode::from(2);
    }
    let cli = Cli::parse();
    match cli.command {
        Command::Init => init_command(),
        Command::Token(TokenCommand::Mint { agent_id }) => mint_token_command(&agent_id),
        Command::Tunnel(TunnelCommand::Mint { agent_id }) => mint_tunnel_command(&agent_id),
        Command::Unlock { .. }
        | Command::Lock { .. }
        | Command::Status { .. }
        | Command::Grants { .. }
        | Command::Approve { .. }
        | Command::Deny { .. } => owner_command(&cli.command),
        Command::Revoke(_) | Command::Unsuspend { .. } | Command::Panic { .. } => {
            owner_command(&cli.command)
        }
        Command::PasskeyEnroll { socket } => passkey_enroll(&socket),
        Command::Passkey(PasskeyCommand::List { socket }) => passkey_list(&socket),
        Command::Passkey(PasskeyCommand::Remove { id, socket }) => passkey_remove(&socket, &id),
        Command::Audit(AuditCommand::Verify { data, checkpoints }) => {
            let key_path = data.join("keys").join("audit_sign.pub");
            let key_bytes = match std::fs::read(&key_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("cannot read audit public key {key_path:?}: {e}");
                    return ExitCode::from(2);
                }
            };
            let key_arr: [u8; 32] = match key_bytes.try_into() {
                Ok(a) => a,
                Err(_) => {
                    eprintln!("{key_path:?}: not a 32-byte Ed25519 verifying key");
                    return ExitCode::from(2);
                }
            };
            let vk = match ed25519_dalek::VerifyingKey::from_bytes(&key_arr) {
                Ok(vk) => vk,
                Err(e) => {
                    eprintln!("{key_path:?}: {e}");
                    return ExitCode::from(2);
                }
            };

            let cps = match &checkpoints {
                Some(p) => match std::fs::read_to_string(p) {
                    Ok(text) => {
                        let mut out = Vec::new();
                        for (i, line) in text.lines().enumerate() {
                            if line.trim().is_empty() {
                                continue;
                            }
                            match serde_json::from_str(line) {
                                Ok(cp) => out.push(cp),
                                Err(e) => {
                                    eprintln!("{p:?} line {}: {e}", i + 1);
                                    return ExitCode::from(2);
                                }
                            }
                        }
                        out
                    }
                    Err(e) => {
                        eprintln!("cannot read checkpoints {p:?}: {e}");
                        return ExitCode::from(2);
                    }
                },
                None => {
                    eprintln!(
                        "warning: no --checkpoints given; this checks self-consistency only \
                         and cannot detect tail truncation (see --help)"
                    );
                    Vec::new()
                }
            };

            match kharond::audit::verify(&data.join("audit.jsonl"), &cps, &vk) {
                Ok(outcome) => {
                    println!("{outcome}");
                    if matches!(outcome, kharond::audit::VerifyOutcome::Ok { .. }) {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    println!("{e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn scope_refusal_line_carries_the_owner_hint_other_codes_do_not() {
        let line = refusal_line("scope_too_broad");
        assert!(
            line.starts_with("kharon: daemon refused [scope_too_broad]: "),
            "{line}"
        );
        assert!(
            line.ends_with(kharond::owner::SCOPE_TOO_BROAD_HINT),
            "{line}"
        );
        assert_eq!(
            refusal_line("unlock_failed"),
            "kharon: daemon refused [unlock_failed]",
            "a wrong password gets no hint: it stays indistinguishable"
        );
    }

    #[test]
    fn req_dep_007_master_password_has_at_least_128_bits() {
        let p = generate_master_password().unwrap();
        let symbols: Vec<char> = p.chars().filter(|&c| c != '-').collect();
        assert_eq!(symbols.len(), 32, "{}", p.as_str());
        assert!(symbols.iter().all(|c| BASE32.contains(&(*c as u8))));
        // Each symbol is one of 32 equally likely values.
        assert!(symbols.len() * 5 >= 128);
        let groups: Vec<&str> = p.split('-').collect();
        assert_eq!(groups.len(), 8);
        assert!(groups.iter().all(|g| g.len() == MASTER_PASSWORD_GROUP));
    }

    #[test]
    fn req_dep_007_master_passwords_differ() {
        let a = generate_master_password().unwrap();
        let b = generate_master_password().unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn req_dep_007_base32_uses_every_bit() {
        // 20 bytes are exactly 32 base32 symbols: the encoder must
        // consume all 160 bits with none left over or dropped. A
        // stuck symbol position would show as one value across many
        // draws.
        let draws: Vec<Zeroizing<String>> = (0..64)
            .map(|_| generate_master_password().unwrap())
            .collect();
        for pos in 0..39 {
            let first = draws[0].as_bytes()[pos];
            if first == b'-' {
                continue;
            }
            assert!(
                draws.iter().any(|d| d.as_bytes()[pos] != first),
                "symbol {pos} never varies"
            );
        }
    }

    /// A pipe double: each `read` returns at most the next queued
    /// chunk (split if the caller's buffer is smaller), `None`
    /// entries are one `Interrupted` error, and an empty queue is
    /// EOF.
    struct Chunks(VecDeque<Option<Vec<u8>>>);

    impl Chunks {
        fn new(chunks: &[Option<&[u8]>]) -> Self {
            Self(chunks.iter().map(|c| c.map(<[u8]>::to_vec)).collect())
        }
    }

    impl Read for Chunks {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(None) => Err(std::io::ErrorKind::Interrupted.into()),
                Some(Some(mut chunk)) => {
                    let m = chunk.len().min(buf.len());
                    buf[..m].copy_from_slice(&chunk[..m]);
                    if m < chunk.len() {
                        self.0.push_front(Some(chunk.split_off(m)));
                    }
                    Ok(m)
                }
            }
        }
    }

    fn line(chunks: &[Option<&[u8]>]) -> Result<String, String> {
        read_password_line(&mut Chunks::new(chunks), "test").map(|p| p.as_str().to_owned())
    }

    #[test]
    fn read_password_line_stops_at_first_newline_within_one_read() {
        // #92 item 1: one pipe read returning `pw\nextra`.
        assert_eq!(line(&[Some(b"pw\nextra")]).unwrap(), "pw");
        assert_eq!(line(&[Some(b"pw\nextra\n")]).unwrap(), "pw");
        assert_eq!(line(&[Some(b"pw\r\nextra")]).unwrap(), "pw");
        assert_eq!(line(&[Some(b"pw"), Some(b"\nextra")]).unwrap(), "pw");
    }

    #[test]
    fn read_password_line_newline_split_across_reads() {
        assert_eq!(line(&[Some(b"p"), Some(b"w"), Some(b"\n")]).unwrap(), "pw");
        assert_eq!(line(&[Some(b"pw\r"), Some(b"\n")]).unwrap(), "pw");
        assert_eq!(line(&[Some(b"pw"), None, Some(b"\n")]).unwrap(), "pw");
    }

    #[test]
    fn read_password_line_eof_without_newline() {
        assert_eq!(line(&[Some(b"pw")]).unwrap(), "pw");
        assert_eq!(line(&[Some(b"pw\r")]).unwrap(), "pw");
    }

    #[test]
    fn read_password_line_empty() {
        assert_eq!(line(&[]).unwrap(), "");
        assert_eq!(line(&[Some(b"\n")]).unwrap(), "");
        assert_eq!(line(&[Some(b"\r\n")]).unwrap(), "");
        assert_eq!(line(&[Some(b"\npw\n")]).unwrap(), "");
    }

    #[test]
    fn read_password_line_overlong_is_an_error_not_a_truncation() {
        let long = vec![b'a'; MAX_PASSWORD_BYTES + 1];
        let err = line(&[Some(&long)]).unwrap_err();
        assert!(err.contains("too long"), "{err}");
        // Exactly the cap fits only if the newline comes within it.
        let mut at_cap = vec![b'a'; MAX_PASSWORD_BYTES - 1];
        at_cap.push(b'\n');
        assert_eq!(
            line(&[Some(&at_cap)]).unwrap().len(),
            MAX_PASSWORD_BYTES - 1
        );
        let mut over = vec![b'a'; MAX_PASSWORD_BYTES];
        over.push(b'\n');
        assert!(line(&[Some(&over)]).is_err());
        // A newline after the cap, in pieces, is still overlong.
        assert!(line(&[Some(&long[..600]), Some(&long[600..]), Some(b"\n")]).is_err());
    }

    #[test]
    fn read_password_line_rejects_invalid_utf8() {
        let err = line(&[Some(b"\xff\xfe\n")]).unwrap_err();
        assert!(err.contains("UTF-8"), "{err}");
    }

    #[test]
    fn read_password_line_propagates_read_errors() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        let err = read_password_line(&mut Broken, "test").unwrap_err();
        assert!(err.starts_with("cannot read password from test"), "{err}");
    }

    fn round_trip(password: &str) {
        let frame = unlock_frame(password);
        assert!(
            frame.len() <= password.len() * 6 + 32,
            "frame outgrew its pre-sized buffer"
        );
        let v: serde_json::Value = serde_json::from_str(&frame)
            .unwrap_or_else(|e| panic!("invalid JSON for {password:?}: {e}: {}", *frame));
        assert_eq!(v["op"], "unlock");
        assert_eq!(v["password"].as_str(), Some(password), "frame {}", *frame);
        assert_eq!(v.as_object().unwrap().len(), 2);
    }

    #[test]
    fn unlock_frame_round_trips_every_control_and_escape_char() {
        // Each char on its own, and all of them in one password.
        let mut all = String::new();
        for c in (0u32..0x20)
            .chain([0x22, 0x5c, 0x2f, 0x7f])
            .filter_map(char::from_u32)
        {
            round_trip(&c.to_string());
            round_trip(&format!("a{c}b"));
            all.push(c);
        }
        round_trip(&all);
        // Worst case for the capacity bound: all `\u00XX` escapes.
        round_trip(&"\u{1}".repeat(MAX_PASSWORD_BYTES));
    }

    #[test]
    fn unlock_frame_passes_non_ascii_through_raw() {
        for pw in [
            "",
            "plain",
            "pässwörd",
            "密码",
            "🔑\u{2028}\u{2029}",
            "\u{80}\u{ffff}",
        ] {
            round_trip(pw);
        }
        assert_eq!(
            unlock_frame("é\u{8}").as_str(),
            "{\"op\":\"unlock\",\"password\":\"é\\u0008\"}"
        );
    }
}
