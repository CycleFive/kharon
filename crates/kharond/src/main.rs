//! kharon broker daemon.
//!
//! `kharond [--config <path>]` loads and validates its config
//! (REQ-DEP-003), hardens the process, assembles the broker **locked**
//! (REQ-MEM-005) and serves the agent API (REQ-API-002) on `[api]
//! listen` until SIGTERM or SIGINT. Once bound it prints
//! `kharond: agent API listening on <addr> (locked)` to stderr.
//!
//! `kharond --check [--config <path>]` runs every config-level startup
//! check (the loader plus the daemon's own, e.g. a missing `[api]`),
//! prints `kharond: config ok (...)`, and exits without hardening,
//! touching `data_dir`, or binding.
//!
//! Refusals print `kharond: config error [<code>]: <message>` (loader,
//! exit 78 `EX_CONFIG`) or `kharond: startup error [<code>]: <message>`
//! (exit status per [`StartupError::exit_code`]). The default config
//! path is `/etc/kharon.toml`.

use std::path::PathBuf;
use std::process::ExitCode;

use kharond::config::{self, Config, DEFAULT_CONFIG_PATH, ProcfsMlockProbe};
use kharond::daemon::{self, EX_CONFIG, StartupError};
use kharond::lock::ProcessHardening;

/// sysexits.h `EX_USAGE`.
const EX_USAGE: u8 = 64;
/// sysexits.h `EX_SOFTWARE`: the runtime or server failed.
const EX_SOFTWARE: u8 = 70;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let mut path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut check_only = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config" | "-c") => match args.next() {
                Some(p) => path = PathBuf::from(p),
                None => return usage(),
            },
            Some("--check") => check_only = true,
            _ => return usage(),
        }
    }

    let cfg = match config::load_for_startup(&path, &ProcfsMlockProbe) {
        Ok((cfg, warnings)) => {
            for w in warnings {
                eprintln!("kharond: warning: {w}");
            }
            cfg
        }
        Err(e) => {
            eprintln!("kharond: config error [{}]: {e}", e.code());
            return ExitCode::from(EX_CONFIG);
        }
    };

    if check_only {
        return match daemon::check(&cfg) {
            Ok(listen) => {
                eprintln!(
                    "kharond: config ok ({} agent(s), agent API on {listen})",
                    cfg.agents.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => startup_error(&e),
        };
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("kharond: cannot start runtime: {}", e.kind());
            return ExitCode::from(EX_SOFTWARE);
        }
    };
    rt.block_on(serve(cfg))
}

async fn serve(cfg: Config) -> ExitCode {
    let daemon = match daemon::start(&cfg, Box::new(ProcessHardening)).await {
        Ok(d) => d,
        Err(e) => return startup_error(&e),
    };
    drop(cfg);
    match daemon.local_addr() {
        Ok(addr) => {
            eprintln!("kharond: agent API listening on {addr} (locked)");
            eprintln!("kharond: owner socket {}", daemon.owner_socket().display());
            if let Some(ui) = daemon.owner_ui_addr() {
                let origin = daemon.owner_ui_origin().unwrap_or("");
                eprintln!("kharond: owner UI listening on {ui} (origin {origin})");
            }
        }
        Err(e) => {
            eprintln!("kharond: cannot read listen address: {}", e.kind());
            return ExitCode::from(EX_SOFTWARE);
        }
    }
    match daemon.run(shutdown_signal()).await {
        Ok(()) => {
            eprintln!("kharond: shut down");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("kharond: server error: {}", e.kind());
            ExitCode::from(EX_SOFTWARE)
        }
    }
}

/// Resolves on SIGTERM (container stop) or SIGINT. If a handler cannot
/// be installed the daemon keeps the default disposition for it, which
/// still terminates the process.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let term = signal(SignalKind::terminate());
    let int = signal(SignalKind::interrupt());
    match (term, int) {
        (Ok(mut t), Ok(mut i)) => {
            tokio::select! {
                _ = t.recv() => {}
                _ = i.recv() => {}
            }
        }
        (Ok(mut t), Err(_)) => {
            t.recv().await;
        }
        (Err(_), Ok(mut i)) => {
            i.recv().await;
        }
        (Err(_), Err(_)) => std::future::pending().await,
    }
}

fn startup_error(e: &StartupError) -> ExitCode {
    eprintln!("kharond: startup error [{}]: {e}", e.code());
    ExitCode::from(e.exit_code())
}

fn usage() -> ExitCode {
    eprintln!("usage: kharond [--check] [--config <path>]");
    ExitCode::from(EX_USAGE)
}
