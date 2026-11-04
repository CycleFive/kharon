//! kharon owner CLI.
//!
//! The full surface (approve/deny, grants, revoke, panic, …) lands
//! with the daemon milestones; this binary currently provides the
//! audit verifier, REQ-AUD-001/002's "owner or offline tool can
//! check the log", and the owner unlock channel (issue #11, SPEC
//! §8): `kharon unlock` / `kharon lock` / `kharon status` talk to
//! the daemon's unix owner socket. The unlock password is read
//! from the terminal with echo disabled — never from argv, env,
//! or a file (REQ-EXP-003) — and its dedicated buffers are
//! zeroized after use; when stdin is not a terminal it is read
//! from stdin instead (one line), which is what automation and
//! tests use. (Narrowed, PR #81 review: the JSON request frame is
//! built with serde_json into a zeroizing buffer that is wiped
//! whole, but serde's internal growth copies and the tty/stdin
//! read buffers are std internals this short-lived CLI cannot
//! wipe — the daemon side, the long-lived process, is where
//! REQ-MEM-003's zeroization is enforced and scanned for.)

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

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

/// Read the unlock password: from the terminal with echo off when
/// stdin is a terminal, else one line from stdin.
fn read_password() -> Result<Zeroizing<String>, String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        read_password_tty()
    } else {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("cannot read password from stdin: {e}"))?;
        while line.ends_with(['\n', '\r']) {
            line.pop();
        }
        Ok(line)
    }
}

/// Disable echo on `/dev/tty` for the duration of the guard.
struct EchoOff(rustix::termios::Termios);

impl EchoOff {
    fn new(fd: std::os::fd::BorrowedFd<'_>) -> Result<Self, String> {
        let original = rustix::termios::tcgetattr(fd)
            .map_err(|e| format!("cannot read terminal settings: {e}"))?;
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
    use std::io::BufRead;
    let mut tty =
        std::fs::File::open("/dev/tty").map_err(|e| format!("cannot open /dev/tty: {e}"))?;
    {
        use std::os::fd::AsFd;
        let _guard = EchoOff::new(tty.as_fd())?;
        eprint!("kharon master password: ");
        let mut line = Zeroizing::new(String::new());
        let mut reader = std::io::BufReader::new(&mut tty);
        reader
            .read_line(&mut line)
            .map_err(|e| format!("cannot read password: {e}"))?;
        eprintln!();
        while line.ends_with(['\n', '\r']) {
            line.pop();
        }
        Ok(line)
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
            let request = Zeroizing::new(
                serde_json::json!({"op": "unlock", "password": password.as_str()}).to_string(),
            );
            (socket, request)
        }
        Command::Lock { socket } => (
            socket,
            Zeroizing::new(serde_json::json!({"op": "lock"}).to_string()),
        ),
        Command::Status { socket } => (
            socket,
            Zeroizing::new(serde_json::json!({"op": "status"}).to_string()),
        ),
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
        Command::Unlock { .. } | Command::Lock { .. } | Command::Status { .. } => {
            owner_command(&cli.command)
        }
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
