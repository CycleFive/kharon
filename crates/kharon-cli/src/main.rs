//! kharon owner CLI.
//!
//! The full surface (approve/deny, grants, revoke, panic, audit, …) lands
//! with the daemon milestones; this binary currently provides the audit
//! verifier, REQ-AUD-001/002's "owner or offline tool can check the log".

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
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
