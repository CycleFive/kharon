//! kharon broker daemon.
//!
//! Today the binary loads and validates its config (REQ-DEP-003) and
//! exits; the broker proper lands with the lock state machine (#11) and
//! the API (#14). A refused config exits with status 78 (`EX_CONFIG`) and
//! prints `kharond: config error [<code>]: <message>` to stderr.
//!
//! Usage: `kharond [--config <path>]` (default `/etc/kharon.toml`).

use std::path::PathBuf;
use std::process::ExitCode;

use kharond::config::{self, DEFAULT_CONFIG_PATH, ProcfsMlockProbe};

/// sysexits.h `EX_CONFIG`.
const EX_CONFIG: u8 = 78;
/// sysexits.h `EX_USAGE`.
const EX_USAGE: u8 = 64;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let mut path = PathBuf::from(DEFAULT_CONFIG_PATH);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config" | "-c") => match args.next() {
                Some(p) => path = PathBuf::from(p),
                None => return usage(),
            },
            _ => return usage(),
        }
    }

    match config::load_for_startup(&path, &ProcfsMlockProbe) {
        Ok(cfg) => {
            for w in cfg.warnings() {
                eprintln!("kharond: warning: {w}");
            }
            eprintln!(
                "kharond: config ok ({} agent(s)); broker not implemented yet (#11)",
                cfg.agents.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("kharond: config error [{}]: {e}", e.code());
            ExitCode::from(EX_CONFIG)
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: kharond [--config <path>]");
    ExitCode::from(EX_USAGE)
}
