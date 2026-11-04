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
//! 6. Lock controller, **locked** (REQ-MEM-005), with its
//!    transitions wired to the audit log (REQ-AUD-003). In export
//!    mode the startup [`ExportFile`] is loaded here, once, and
//!    kept for every unlock (REQ-EXP-004 load-once: re-reading the
//!    file at unlock would let a replaced file take effect without
//!    a restart).
//! 7. Fill backend: each agent's `cdp` endpoint (REQ-API-008). No
//!    browser I/O here: an agent's connection and browser context
//!    (REQ-ARCH-005) are made by its first fill, so startup does not
//!    depend on the browser being reachable.
//! 8. Owner socket (issue #11): the unix-socket unlock channel
//!    ([`crate::owner`]) is bound under `data_dir`, and the agent
//!    API listener is bound last.
//!
//! [`Daemon::run`] serves until the shutdown future resolves; dropping
//! the broker drops the lock controller, which zeroizes any session.
//! In `mode = "sync"` it also runs the REQ-API-007 clock probe in the
//! background (see [`clock_probe`]): startup is not delayed by, and
//! does not depend on, the Vaultwarden server being reachable.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, UnixListener};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::api::core::{Broker, VaultView};
use crate::api::fill::{ConnectingCdpBackend, FillPolicy};
use crate::api::http;
use crate::api::token::{TokenStore, TokenStoreError};
use crate::audit::{AuditConfig as LogConfig, AuditLog, Entry, Event, FileCheckpointSink, OpenError};
use crate::config::{BitwardenConfig, Config, Source};
use crate::export::{ExportError, ExportFile, ExportSession};
use crate::lock::{
    HardeningError, LockController, LockPolicy, LockReason, MemoryHardening, SystemClock,
    UnlockError,
};
use crate::owner::{OwnerFailure, OwnerOps};
use crate::sync::{LiveSync, SecretField, SyncClient, SyncError, Vault};
use crate::totp::{SkewPolicy, SkewVerdict};

/// `sysexits.h` `EX_CONFIG`: a configuration refusal.
pub const EX_CONFIG: u8 = 78;
/// `sysexits.h` `EX_OSERR`: the OS refused hardening.
pub const EX_OSERR: u8 = 71;
/// `sysexits.h` `EX_CANTCREAT`: state under `data_dir` unusable.
pub const EX_CANTCREAT: u8 = 73;
/// `sysexits.h` `EX_UNAVAILABLE`: the listen address cannot be bound.
pub const EX_UNAVAILABLE: u8 = 69;

/// The daemon's broker type: daemon session, wall clock.
pub type DaemonBroker = Broker<DaemonSession, SystemClock>;

/// The session a daemon unlock produces, by source mode. Behind
/// the API's [`VaultView`] seam both modes look identical; dropping
/// either variant wipes its key material (REQ-MEM-003).
pub enum DaemonSession {
    /// `mode = "sync"`: a live-synced Vaultwarden session.
    Sync(LiveSync),
    /// `mode = "export"`: the startup export file's snapshot.
    Export(ExportSession),
}

impl ZeroizeOnDrop for DaemonSession {}

impl VaultView for DaemonSession {
    fn vault(&self) -> &Vault {
        match self {
            Self::Sync(s) => s.vault(),
            Self::Export(s) => s.vault(),
        }
    }

    fn decrypt_secret(
        &self,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        match self {
            Self::Sync(s) => VaultView::decrypt_secret(s, item_id, field),
            Self::Export(s) => VaultView::decrypt_secret(s, item_id, field),
        }
    }
}

/// Where an unlock gets its session (the daemon's half of the
/// source config, with everything unlock needs kept from startup).
enum UnlockSource {
    /// Sync mode: build a fresh client per unlock.
    Sync(BitwardenConfig),
    /// Export mode: the startup [`ExportFile`], loaded **once** in
    /// [`start`] and used for every unlock (REQ-EXP-004 load-once).
    Export(Arc<ExportFile>),
}

/// The daemon's [`OwnerOps`]: unlock / lock / status against the
/// broker's lock controller, following the lock module's ordering
/// (network before the controller, derivation inside its closure,
/// on a blocking thread — never holding the controller's
/// `std::sync::Mutex` across an `.await`).
struct DaemonOwner {
    broker: Arc<DaemonBroker>,
    source: UnlockSource,
}

impl DaemonOwner {
    fn map_unlock_error<E>(e: UnlockError<E>) -> OwnerFailure {
        match e {
            UnlockError::AlreadyUnlocked => OwnerFailure::AlreadyUnlocked,
            UnlockError::MlockUnavailable => OwnerFailure::MlockUnavailable,
            UnlockError::Audit(_) => OwnerFailure::AuditFailed,
            UnlockError::DeriveFailed(_) => OwnerFailure::UnlockFailed,
        }
    }
}

impl OwnerOps for DaemonOwner {
    async fn unlock(&self, password: Zeroizing<String>) -> Result<(), OwnerFailure> {
        match &self.source {
            UnlockSource::Export(file) => {
                let file = Arc::clone(file);
                let broker = Arc::clone(&self.broker);
                let sha256 = file.sha256_hex().to_owned();
                tokio::task::spawn_blocking(move || {
                    let mut lock = broker
                        .lock_controller()
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    lock.unlock(|| file.unlock(&password).map(DaemonSession::Export))
                        .map_err(Self::map_unlock_error)
                })
                .await
                .map_err(|_| OwnerFailure::UnlockFailed)??;
                // REQ-EXP-004: the load is incomplete until its
                // `export_loaded` entry (with the file's SHA-256)
                // is in the audit log. If the append fails, lock
                // again and report the failure rather than run
                // with an unaudited load (REQ-AUD-003).
                let entry = Entry::new(Event::ExportLoaded).file_sha256(sha256);
                if self.broker.append_audit(entry).is_err() {
                    let mut lock = self
                        .broker
                        .lock_controller()
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    lock.lock(LockReason::Manual);
                    return Err(OwnerFailure::AuditFailed);
                }
                Ok(())
            }
            UnlockSource::Sync(bw) => {
                // Network first, with no password involved:
                // prelogin + sync + the REQ-CRY-008 scope check.
                let client = bw
                    .sync_client()
                    .map_err(|_| OwnerFailure::UnlockFailed)?;
                let prepared = LiveSync::prepare(client, bw.scope(), bw.sync_policy())
                    .await
                    .map_err(|_| OwnerFailure::UnlockFailed)?;
                let broker = Arc::clone(&self.broker);
                tokio::task::spawn_blocking(move || {
                    let mut lock = broker
                        .lock_controller()
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    lock.unlock(|| prepared.derive(&password).map(DaemonSession::Sync))
                        .map_err(Self::map_unlock_error)
                })
                .await
                .map_err(|_| OwnerFailure::UnlockFailed)??;
                Ok(())
            }
        }
    }

    async fn lock(&self) -> bool {
        let mut lock = self
            .broker
            .lock_controller()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        lock.lock(LockReason::Manual)
    }

    async fn is_locked(&self) -> bool {
        let mut lock = self
            .broker
            .lock_controller()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Run the expiry check so an expired session reports locked.
        lock.poll();
        lock.is_locked()
    }
}

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
    /// The export file could not be loaded at startup (export
    /// mode): classification refusals keep their REQ-EXP-002 codes.
    #[error("cannot load export file: {0}")]
    Export(#[from] ExportError),
    /// The owner socket could not be bound.
    #[error("cannot bind owner socket at {path}: {kind}")]
    OwnerBind {
        /// Socket path that failed.
        path: PathBuf,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
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
            Self::Export(e) => e.code(),
            Self::OwnerBind { .. } => "owner_bind",
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
            Self::Export(_) => EX_CONFIG,
            Self::DataDir { .. } | Self::Audit(_) | Self::OwnerBind { .. } => EX_CANTCREAT,
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
    clock: Option<SyncClient>,
    owner_listener: UnixListener,
    owner_ops: Arc<DaemonOwner>,
    owner_path: PathBuf,
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

    // The unlock source, assembled at startup: sync mode keeps the
    // source config (a client is built per unlock); export mode
    // loads the export file ONCE, here — every unlock uses this
    // instance, never a re-read (REQ-EXP-004 load-once).
    let source = match &cfg.source {
        Source::Sync(bw) => UnlockSource::Sync(bw.clone()),
        Source::Export(exp) => UnlockSource::Export(Arc::new(ExportFile::load(&exp.file)?)),
    };

    let lock = LockController::new(
        LockPolicy::from((&cfg.policy, &cfg.memory)),
        SystemClock,
        hardening,
    );
    let broker = Arc::new(
        Broker::new(tokens, lock, Box::new(audit), cfg.policy.origin_config())
            .with_clock_skew_policy(SkewPolicy::from(&cfg.policy))
            // REQ-API-009 `fill_deadline` and the fill origin policy.
            .with_fill_policy(FillPolicy::from(&cfg.policy))
            // REQ-API-008: each agent's configured CDP endpoint,
            // connected (and its browser context created, REQ-ARCH-005)
            // on its first fill or `kharon_context` call, after that
            // call's `fill_dispatch`/`context_open` entry and inside the
            // deadline. Startup does not need the browser.
            .with_fill_backend(Box::new(ConnectingCdpBackend::from_agents(&cfg.agents))),
    );
    // Lock/unlock transitions belong in the audit log (REQ-AUD-003).
    broker.wire_lock_audit();
    // REQ-API-007: the server whose `Date` the clock is checked
    // against. Building the client does no I/O; config validation has
    // already read both files, so a failure here only skips the probe.
    let clock = match &cfg.source {
        Source::Sync(bw) => bw.sync_client().ok(),
        _ => None,
    };

    let owner_path = crate::owner::socket_path(&cfg.data_dir);
    let owner_listener = crate::owner::bind(&owner_path).map_err(|e| StartupError::OwnerBind {
        path: owner_path.clone(),
        kind: e.kind().to_string(),
    })?;
    let owner_ops = Arc::new(DaemonOwner {
        broker: Arc::clone(&broker),
        source,
    });

    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| StartupError::Bind {
            addr: listen,
            kind: e.kind().to_string(),
        })?;
    Ok(Daemon {
        listener,
        broker,
        clock,
        owner_listener,
        owner_ops,
        owner_path,
    })
}

impl Daemon {
    /// The bound address (resolves a configured port 0).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The owner socket path (`kharon unlock` / `lock` connect here).
    pub fn owner_socket(&self) -> &std::path::Path {
        &self.owner_path
    }

    /// Serve the agent API until `shutdown` resolves.
    pub async fn run<F>(self, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let probe = self
            .clock
            .map(|client| tokio::spawn(clock_probe(client, Arc::clone(&self.broker))));
        let owner = tokio::spawn(crate::owner::serve(self.owner_listener, self.owner_ops));
        let served = http::serve_with_shutdown(self.listener, self.broker, shutdown).await;
        owner.abort();
        if let Some(p) = probe {
            p.abort();
        }
        served
    }
}

/// How often the clock probe retries while the server is unreachable
/// or the skew is above `clock_skew_refuse` ("until resolved").
pub const CLOCK_PROBE_RETRY: std::time::Duration = std::time::Duration::from_secs(60);

/// REQ-API-007 startup clock check: compare the system clock with the
/// Vaultwarden `Date` header and feed the broker's gate. One sample at
/// startup; repeated every [`CLOCK_PROBE_RETRY`] while the server is
/// unreachable or the verdict is `refuse`, so fixing the clock reopens
/// `fill_totp` without a restart. Warnings go to stderr in the same
/// `kharond: warning:` form as config warnings, once per change.
pub async fn clock_probe(client: SyncClient, broker: Arc<DaemonBroker>) {
    let mut reported_unreachable = false;
    let mut last_warning: Option<SkewVerdict> = None;
    loop {
        match client.clock_sample().await {
            Ok(sample) => {
                let (obs, appended) = broker.observe_clock(sample);
                if appended.is_err() {
                    eprintln!("kharond: warning: clock_skew audit entry could not be written");
                }
                if let Some(w) = &obs.warning
                    && last_warning != Some(obs.verdict)
                {
                    eprintln!("kharond: warning: {w}");
                }
                if obs.verdict == SkewVerdict::Ok && last_warning.is_some() {
                    eprintln!("kharond: clock skew resolved ({:+} s)", obs.skew_secs);
                }
                last_warning = (obs.verdict != SkewVerdict::Ok).then_some(obs.verdict);
                if obs.verdict != SkewVerdict::Refuse {
                    return;
                }
            }
            Err(e) => {
                if !reported_unreachable {
                    eprintln!(
                        "kharond: warning: clock skew check against the server failed ({e}); \
                         retrying every {} s",
                        CLOCK_PROBE_RETRY.as_secs()
                    );
                    reported_unreachable = true;
                }
            }
        }
        tokio::time::sleep(CLOCK_PROBE_RETRY).await;
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
