//! kharon owner CLI.
//!
//! Owner tool: unlock/lock/status, audit verify, revoke, unsuspend, panic.
//! (Approve/deny also land via the owner socket; CLI approve/deny land
//! with the web/ntfy surfaces.)
//! The full surface (approve/deny, grants, revoke, panic, …) lands
//! with the daemon milestones; this binary currently provides the
//! audit verifier, REQ-AUD-001/002's "owner or offline tool can
//! check the log", and the owner unlock channel (issue #11, SPEC
//! §8): `kharon unlock` / `kharon lock` / `kharon status` talk to
//! the daemon's unix owner socket. The unlock password is read
//! from the terminal with echo disabled — never from argv, env,
//! or a file (REQ-EXP-003); when stdin is not a terminal it is
//! read from stdin instead (one line), which is what automation
//! and tests use.
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
    /// Revoke a grant or an agent (REQ-REV-001).
    #[command(subcommand)]
    Revoke(RevokeCommand),
    /// Clear an agent's suspension (REQ-RL-002).
    Unsuspend {
        /// Agent id.
        agent_id: String,
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
    /// Revoke an agent (token + grants).
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
        /// Data directory holding `audit.jsonl` and `keys/`.
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

/// Read the unlock password: from the terminal with echo off when
/// stdin is a terminal, else one line from stdin.
fn read_password() -> Result<Zeroizing<String>, String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        read_password_tty()
    } else {
        use std::os::fd::AsFd;
        let stdin = std::io::stdin();
        read_password_line(&mut FdReader(stdin.as_fd()), "stdin")
    }
}

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
        Command::Audit(_) => unreachable!(),
    };
    match owner_request(socket, &request) {
        Ok(reply) if reply["ok"] == serde_json::Value::Bool(true) => {
            match reply["locked"].as_bool() {
                Some(true) => println!("locked"),
                Some(false) => println!("unlocked"),
                None => println!("ok"),
            }
            ExitCode::SUCCESS
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Unlock { .. }
        | Command::Lock { .. }
        | Command::Status { .. }
        | Command::Revoke(_)
        | Command::Unsuspend { .. }
        | Command::Panic { .. } => owner_command(&cli.command),
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
