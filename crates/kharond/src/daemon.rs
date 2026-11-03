//! Daemon assembly (#14): config → hardened process → locked broker →
//! bound agent API listener.
//!
//! [`start`] does everything that can fail before the first request,
//! in an order chosen so that a listening socket implies a fully
//! assembled, locked broker:
//!
//! 1. `[api] listen` must be configured (the daemon never picks an
//!    address; REQ-DEP-006 refused wildcards at config load).
//! 2. The audit checkpoint sink must be one this build can provide
//!    (see [`StartupError::OffHostCheckpointUnimplemented`]).
//! 3. Process hardening: `harden_process()` (REQ-MEM-001), then
//!    `lock_memory()` when `require_mlock` is set (REQ-MEM-002; the
//!    lock module asks for this at startup so the master password is
//!    locked from the moment it is typed). Either failing refuses
//!    startup.
//! 4. Agent token store (REQ-API-003; production parameter floor).
//! 5. Audit log under `<data_dir>/audit` (REQ-AUD-001), exclusive.
//! 6. Lock controller, **locked** (REQ-MEM-005): there is no unlock
//!    channel yet, so every vault-touching call answers 423.
//! 7. Bind the listener last.
//!
//! [`Daemon::run`] serves until the shutdown future resolves; dropping
//! the broker drops the lock controller, which zeroizes any session.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::api::core::Broker;
use crate::api::http;
use crate::api::token::{TokenStore, TokenStoreError};
use crate::audit::{AuditConfig as LogConfig, AuditLog, FileCheckpointSink, OpenError};
use crate::config::Config;
use crate::lock::{HardeningError, LockController, LockPolicy, MemoryHardening, SystemClock};
use crate::sync::LiveSync;

/// `sysexits.h` `EX_CONFIG`: a configuration refusal.
pub const EX_CONFIG: u8 = 78;
/// `sysexits.h` `EX_OSERR`: the OS refused hardening.
pub const EX_OSERR: u8 = 71;
/// `sysexits.h` `EX_CANTCREAT`: state under `data_dir` unusable.
pub const EX_CANTCREAT: u8 = 73;
/// `sysexits.h` `EX_UNAVAILABLE`: the listen address cannot be bound.
pub const EX_UNAVAILABLE: u8 = 69;

/// The daemon's broker type: live sync session, wall clock.
pub type DaemonBroker = Broker<LiveSync, SystemClock>;

/// Why the daemon refused to start after the config was accepted.
/// Like `ConfigError`, every variant has a stable [`code`](Self::code)
/// and no message echoes secret material.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// No `[api]` section: refuse rather than guess an address.
    #[error("no `[api] listen` configured; set it to the WireGuard interface address")]
    ApiListenMissing,
    /// `audit.checkpoint_local_only = false` needs the off-host (ntfy)
    /// checkpoint sink, which is not implemented yet. Refused rather
    /// than silently downgraded to local-only.
    #[error(
        "off-host audit checkpoints (ntfy) are not implemented yet; \
         set audit.checkpoint_local_only = true to run with local checkpoints"
    )]
    OffHostCheckpointUnimplemented,
    /// `harden_process()` failed (REQ-MEM-001).
    #[error("process hardening failed: {0}")]
    Harden(HardeningError),
    /// `require_mlock = true` and `mlockall` failed (REQ-MEM-002).
    #[error("require_mlock = true but mlockall failed: {0}")]
    Mlock(HardeningError),
    /// The token store refused a hash (the config loader should have).
    #[error(transparent)]
    Tokens(#[from] TokenStoreError),
    /// `<data_dir>/audit` could not be created.
    #[error("cannot create {path}: {kind}")]
    DataDir {
        /// Directory that failed.
        path: PathBuf,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
    /// The audit log could not be opened.
    #[error("cannot open audit log: {0}")]
    Audit(#[from] OpenError),
    /// The listen address could not be bound.
    #[error("cannot bind agent API on {addr}: {kind}")]
    Bind {
        /// Configured address.
        addr: SocketAddr,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
}

impl StartupError {
    /// Stable machine-readable code, printed by the daemon on refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ApiListenMissing => "api_listen_missing",
            Self::OffHostCheckpointUnimplemented => "audit_off_host_unimplemented",
            Self::Harden(_) => "harden_failed",
            Self::Mlock(_) => "mlock_failed",
            Self::Tokens(_) => "token_store",
            Self::DataDir { .. } => "data_dir",
            Self::Audit(_) => "audit_open",
            Self::Bind { .. } => "bind",
        }
    }

    /// Process exit status (`sysexits.h`).
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::ApiListenMissing | Self::OffHostCheckpointUnimplemented | Self::Tokens(_) => {
                EX_CONFIG
            }
            Self::Harden(_) | Self::Mlock(_) => EX_OSERR,
            Self::DataDir { .. } | Self::Audit(_) => EX_CANTCREAT,
            Self::Bind { .. } => EX_UNAVAILABLE,
        }
    }
}

/// The config checks [`start`] adds on top of the loader, without
/// side effects: what `kharond --check` runs after `load_for_startup`.
pub fn check(cfg: &Config) -> Result<SocketAddr, StartupError> {
    let api = cfg.api.ok_or(StartupError::ApiListenMissing)?;
    if !cfg.audit.checkpoint_local_only {
        return Err(StartupError::OffHostCheckpointUnimplemented);
    }
    Ok(api.listen)
}

/// An assembled daemon: locked broker plus bound listener.
pub struct Daemon {
    listener: TcpListener,
    broker: Arc<DaemonBroker>,
}

/// Assemble the daemon (see the module docs for the order). Must run
/// inside a tokio runtime (it binds a tokio listener).
pub async fn start(
    cfg: &Config,
    hardening: Box<dyn MemoryHardening>,
) -> Result<Daemon, StartupError> {
    let listen = check(cfg)?;

    hardening.harden_process().map_err(StartupError::Harden)?;
    if cfg.memory.require_mlock {
        hardening.lock_memory().map_err(StartupError::Mlock)?;
    }

    let tokens = TokenStore::from_agents(&cfg.agents)?;

    let audit_dir = cfg.data_dir.join("audit");
    create_private_dir(&audit_dir).map_err(|e| StartupError::DataDir {
        path: audit_dir.clone(),
        kind: e.kind().to_string(),
    })?;
    let sink =
        FileCheckpointSink::create(&audit_dir.join("checkpoints.jsonl")).map_err(OpenError::Io)?;
    let audit = AuditLog::open(
        &audit_dir,
        LogConfig {
            plaintext_item_names: cfg.audit.item_names,
            ..LogConfig::default()
        },
        Box::new(sink),
    )?;

    let lock = LockController::new(
        LockPolicy::from((&cfg.policy, &cfg.memory)),
        SystemClock,
        hardening,
    );
    let broker = Arc::new(Broker::new(
        tokens,
        lock,
        Box::new(audit),
        cfg.policy.origin_config(),
    ));

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| StartupError::Bind {
            addr: listen,
            kind: e.kind().to_string(),
        })?;
    Ok(Daemon { listener, broker })
}

impl Daemon {
    /// The bound address (resolves a configured port 0).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serve the agent API until `shutdown` resolves.
    pub async fn run<F>(self, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        http::serve_with_shutdown(self.listener, self.broker, shutdown).await
    }
}

/// `mkdir -p` with mode 0700 on the leaf (audit keys live below it).
fn create_private_dir(path: &std::path::Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}
