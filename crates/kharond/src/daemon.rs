//! Daemon assembly (#14): config → hardened process → locked broker →
//! bound agent API listener.
//!
//! [`start`] does everything that can fail before the first request,
//! in an order chosen so that a listening socket implies a fully
//! assembled, locked broker:
//!
//! 1. `[api] listen` must be configured (the daemon never picks an
//!    address; REQ-DEP-006 refused wildcards at config load).
//! 2. The audit checkpoint sink must be resolvable: local-only, or
//!    the off-host ntfy sink when `[approval].ntfy` is configured
//!    (REQ-AUD-002, #127; the loader already refuses off-host mode
//!    with no ntfy channel, and [`start`] fails closed if the sink
//!    cannot be built, e.g. an unreadable ntfy token file).
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
//!    ([`crate::owner`]) is bound under `data_dir`. When `[owner_ui]`
//!    is set, that loopback listener also serves ntfy redeem
//!    (`/owner/approve/<token>`, `/owner/deny/<token>`; REQ-DEP-006,
//!    #136). The agent API listener is bound last and leaves those
//!    paths unrouted.
//! 9. Public ingress (#198), when `[public_ingress]` is set: a
//!    separate listener for a public edge (cloudflared) that serves
//!    `POST /mcp` only ([`crate::api::public`]), bound just before the
//!    agent API.
//!
//! [`Daemon::run`] serves until the shutdown future resolves; dropping
//! the broker drops the lock controller, which zeroizes any session.
//! In `mode = "sync"` every unlock also starts the REQ-CRY-009 live
//! sync ([`live_sync`]: poll ≤ 5 min plus notifications-hub push,
//! applied in place, ending with the session), and the daemon runs
//! the REQ-API-007 clock probe in the
//! background (see [`clock_probe`]): startup is not delayed by, and
//! does not depend on, the Vaultwarden server being reachable.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, UnixListener};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::api::core::{Broker, FillSync, SyncFetch, VaultView};
use crate::api::fill::{ConnectingCdpBackend, FillPolicy};
use crate::api::http;
use crate::api::token::{TokenStore, TokenStoreError};
use crate::api::{Channel, GrantError, GrantScope, GrantTerms};
use crate::audit::{
    AuditConfig as LogConfig, AuditLog, CheckpointSink, Entry, Event, FileCheckpointSink,
    NtfyCheckpointSink, OpenError,
};
use crate::config::{BitwardenConfig, Config, Source};
use crate::export::{ExportError, ExportFile, ExportSession};
use crate::lock::{
    HardeningError, LockController, LockPolicy, LockReason, MemoryHardening, SystemClock,
    UnlockError,
};
use crate::owner::{ApproveArgs, OwnerFailure, OwnerOps};
use crate::sync::wire::SyncResponse;
use crate::sync::{
    HubStatus, LiveSync, SecretField, SyncClient, SyncError, SyncOutcome, Vault, run_push,
};
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
    /// `mode = "sync"`: a live-synced Vaultwarden session. Boxed:
    /// `LiveSync` is over a kilobyte and the export variant is not.
    Sync(Box<LiveSync>),
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
            Self::Sync(s) => VaultView::decrypt_secret(&**s, item_id, field),
            Self::Export(s) => VaultView::decrypt_secret(s, item_id, field),
        }
    }

    fn is_stale(&self, now: tokio::time::Instant) -> bool {
        match self {
            Self::Sync(s) => s.is_stale(now),
            Self::Export(_) => false,
        }
    }

    fn apply_sync(&mut self, sync: &SyncResponse) -> Result<SyncOutcome, SyncError> {
        match self {
            Self::Sync(s) => s.apply(sync),
            // Never stale, so never asked.
            Self::Export(_) => Ok(SyncOutcome::Synced),
        }
    }
}

/// SPEC §8 fill-time re-sync source (issue #100), sync mode only: a
/// fresh client per fetch, built as an unlock builds one, and
/// dropped with its access token once the payload is in. Only used
/// when the vault is already past the 5-minute bound, i.e. the
/// background poll has been failing, so the extra login is rare.
struct DaemonFillSync(Box<BitwardenConfig>);

impl FillSync for DaemonFillSync {
    fn fetch(&self) -> SyncFetch<'_> {
        Box::pin(async move {
            let result = match self.0.sync_client() {
                Ok(mut client) => client.sync().await,
                Err(_) => Err(SyncError::ApiKey("fill-time sync client")),
            };
            if let Err(e) = &result {
                // Fixed-text errors only (no secrets in `SyncError`).
                eprintln!("kharond: warning: fill-time re-sync failed ({e}); fill refused");
            }
            result
        })
    }
}

/// Where an unlock gets its session (the daemon's half of the
/// source config, with everything unlock needs kept from startup).
enum UnlockSource {
    /// Sync mode: build a fresh client per unlock. Boxed for the
    /// same size reason as [`DaemonSession::Sync`].
    Sync(Box<BitwardenConfig>),
    /// Export mode: the startup [`ExportFile`], loaded **once** in
    /// [`start`] and used for every unlock (REQ-EXP-004 load-once).
    Export(Arc<ExportFile>),
}

/// The daemon's [`OwnerOps`]: unlock / lock / status against the
/// broker's lock controller, following the lock module's ordering
/// (network before the controller, derivation inside its closure,
/// on a blocking thread — never holding the controller's
/// `std::sync::Mutex` across an `.await`). Lock and status run
/// through `spawn_blocking` too (PR #81 review carry-over): they
/// take the same controller mutex an unlock's KDF holds, so on a
/// runtime worker a `kharon status` during an Argon2id unlock
/// would park that worker for the whole derivation.
struct DaemonOwner {
    broker: Arc<DaemonBroker>,
    source: UnlockSource,
    /// The current unlock's background sync task (REQ-CRY-009), if
    /// any. Replaced on every sync-mode unlock; it also ends by
    /// itself once its session is gone.
    sync_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Owner web UI, when `[owner_ui]` is configured (REQ-APR-005).
    /// `passkey_enroll` mints into this; absent → `unknown_op`.
    owner_ui: Option<Arc<crate::owner_ui::OwnerUi>>,
}

impl DaemonOwner {
    /// REQ-CRY-009: start the live sync for the session just
    /// installed. The session is identified by its unlock instant
    /// (the controller's `unlocked_at`), so the task stops when that
    /// session is locked even if a later unlock installs another.
    /// A client that cannot be built (config was validated at
    /// startup, so this is not expected) leaves the session without
    /// live sync, and says so.
    fn start_live_sync(&self, bw: &BitwardenConfig) {
        let generation = {
            let lock = self
                .broker
                .lock_controller()
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            lock.unlocked_at()
        };
        let Some(generation) = generation else {
            return;
        };
        let client = match bw.sync_client() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("kharond: warning: live sync disabled for this unlock: {e}");
                return;
            }
        };
        let task = tokio::spawn(live_sync(
            Arc::clone(&self.broker),
            client,
            generation,
            bw.sync_policy().interval,
        ));
        let mut slot = self.sync_task.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(old) = slot.replace(task) {
            old.abort();
        }
    }

    /// Stop the background sync (daemon shutdown).
    fn stop_live_sync(&self) {
        let mut slot = self.sync_task.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(task) = slot.take() {
            task.abort();
        }
    }

    fn map_unlock_error<E>(e: UnlockError<E>) -> OwnerFailure {
        match e {
            UnlockError::AlreadyUnlocked => OwnerFailure::AlreadyUnlocked,
            UnlockError::MlockUnavailable => OwnerFailure::MlockUnavailable,
            UnlockError::Dumpable => OwnerFailure::ProcessDumpable,
            UnlockError::Audit(_) => OwnerFailure::AuditFailed,
            UnlockError::DeriveFailed(_) => OwnerFailure::UnlockFailed,
        }
    }
}

/// Why an export-mode derivation closure failed: the export
/// itself, or the `export_loaded` audit append that is part of the
/// load (kept distinct so the append maps to `audit_failed`, not
/// to the indistinguishable `unlock_failed`). Unit variants: the
/// underlying error is deliberately not carried, per REQ-API-006.
enum ExportUnlockError {
    Export,
    Audit,
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
                    // REQ-EXP-004 / REQ-AUD-003 (PR #81 review,
                    // item 6): the `export_loaded` entry is
                    // appended INSIDE the derivation closure —
                    // after `file.unlock` succeeds, before the
                    // session is returned and installed. The
                    // controller mutex is held throughout and the
                    // lock→audit mutex order is the existing one,
                    // so there is no window where the agent API
                    // can serve a load with no audit record, and
                    // no re-acquire that could lock a *different*
                    // (concurrent) session on failure. A failed
                    // append is a derivation failure: no session
                    // is ever installed.
                    let audit_broker = Arc::clone(&broker);
                    lock.unlock(|| {
                        let session = file
                            .unlock(&password)
                            .map_err(|_| ExportUnlockError::Export)?;
                        let entry = Entry::new(Event::ExportLoaded).file_sha256(sha256.clone());
                        audit_broker
                            .append_audit(entry)
                            .map_err(|_| ExportUnlockError::Audit)?;
                        Ok(DaemonSession::Export(session))
                    })
                    .map_err(|e| match e {
                        UnlockError::AlreadyUnlocked => OwnerFailure::AlreadyUnlocked,
                        UnlockError::MlockUnavailable => OwnerFailure::MlockUnavailable,
                        UnlockError::Dumpable => OwnerFailure::ProcessDumpable,
                        UnlockError::Audit(_) => OwnerFailure::AuditFailed,
                        UnlockError::DeriveFailed(ExportUnlockError::Audit) => {
                            OwnerFailure::AuditFailed
                        }
                        UnlockError::DeriveFailed(ExportUnlockError::Export) => {
                            OwnerFailure::UnlockFailed
                        }
                    })
                })
                .await
                .map_err(|_| OwnerFailure::UnlockFailed)?
            }
            UnlockSource::Sync(bw) => {
                // Network first, with no password involved:
                // prelogin + sync + the REQ-CRY-008 scope check.
                let client = bw.sync_client().map_err(|_| OwnerFailure::UnlockFailed)?;
                let prepared = LiveSync::prepare(client, bw.scope(), bw.sync_policy())
                    .await
                    .map_err(|_| OwnerFailure::UnlockFailed)?;
                let broker = Arc::clone(&self.broker);
                tokio::task::spawn_blocking(move || {
                    let mut lock = broker
                        .lock_controller()
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    lock.unlock(|| {
                        prepared
                            .derive(&password)
                            .map(|s| DaemonSession::Sync(Box::new(s)))
                    })
                    .map_err(Self::map_unlock_error)
                })
                .await
                .map_err(|_| OwnerFailure::UnlockFailed)??;
                self.broker.reset_rollback_guard();
                self.start_live_sync(bw);
                Ok(())
            }
        }
    }

    async fn lock(&self) -> bool {
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || {
            let mut lock = broker
                .lock_controller()
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            lock.lock(LockReason::Manual)
        })
        .await
        .unwrap_or(false)
    }

    async fn is_locked(&self) -> bool {
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || {
            let mut lock = broker
                .lock_controller()
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            // Run the expiry check so an expired session reports locked.
            lock.poll();
            lock.is_locked()
        })
        .await
        // A panicked blocking task must not read as "unlocked".
        .unwrap_or(true)
    }

    async fn auth_failed(&self, detail: &'static str) {
        // `owner_auth_fail` (SPEC §7's event list, REQ-AUD-003):
        // fixed detail codes only (`peer_uid`, `unlock_failed`),
        // best effort — the refusal it records stands either way.
        let entry = Entry::new(Event::OwnerAuthFail)
            .channel("owner")
            .detail_code(detail);
        let _ = self.broker.append_audit(entry);
    }

    async fn approve(&self, args: ApproveArgs) -> Result<String, OwnerFailure> {
        // Broker grant ops are sync and append audit (file IO):
        // spawn_blocking, like lock/status (PR #81 carry-over).
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || {
            let Some(req) = broker.grant_request(&args.request_id) else {
                return Err(OwnerFailure::NotFound);
            };
            let scope = match &args.scope_collection {
                Some(c) => GrantScope::Collection(c.clone()),
                None => GrantScope::Item(req.item_id.clone()),
            };
            let terms = GrantTerms {
                scope,
                kind: args.kind.unwrap_or(crate::config::GrantKind::Once),
                ttl: args.ttl_s.map(std::time::Duration::from_secs),
                max_uses: args.max_uses,
            };
            broker
                .approve_grant_request(&args.request_id, &terms, Channel::Cli)
                .map(|view| view.id)
                .map_err(map_grant_error)
        })
        .await
        // A panicked blocking task is an internal failure; the
        // audit-failed code is the closest fixed code (the grant
        // state is unknown, so approval must not be reported).
        .map_err(|_| OwnerFailure::AuditFailed)?
    }

    async fn deny(&self, request_id: String) -> Result<(), OwnerFailure> {
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || {
            broker
                .deny_grant_request(&request_id, Channel::Cli)
                .map(|_| ())
                .map_err(map_grant_error)
        })
        .await
        .map_err(|_| OwnerFailure::AuditFailed)?
    }

    async fn pending_grants(&self) -> Vec<crate::api::ApprovalPrompt> {
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || {
            broker
                .pending_grant_requests()
                .iter()
                .filter_map(|r| r.prompt())
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    async fn passkey_enroll(&self) -> Result<Zeroizing<String>, OwnerFailure> {
        match &self.owner_ui {
            Some(ui) => Ok(ui.mint_enroll_token()),
            None => Err(OwnerFailure::Unsupported),
        }
    }

    async fn revoke_grant(&self, grant_id: String) -> Result<bool, OwnerFailure> {
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || {
            broker
                .revoke_grant(&grant_id, crate::api::grant::Channel::Cli)
                .map_err(map_grant_error)
        })
        .await
        .map_err(|_| OwnerFailure::AuditFailed)?
    }

    async fn revoke_agent(&self, agent_id: String) -> Result<usize, OwnerFailure> {
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || broker.revoke_agent(&agent_id).map_err(map_grant_error))
            .await
            .map_err(|_| OwnerFailure::AuditFailed)?
    }

    async fn unsuspend(&self, agent_id: String) -> Result<(), OwnerFailure> {
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || {
            broker.unsuspend_agent(&agent_id).map_err(map_grant_error)
        })
        .await
        .map_err(|_| OwnerFailure::AuditFailed)?
    }

    async fn panic_lock(&self) -> Result<(), OwnerFailure> {
        let broker = Arc::clone(&self.broker);
        tokio::task::spawn_blocking(move || broker.panic_lock().map_err(map_grant_error))
            .await
            .map_err(|_| OwnerFailure::AuditFailed)?
    }
}

/// Map a broker grant refusal onto the owner channel's fixed codes.
fn map_grant_error(e: GrantError) -> OwnerFailure {
    match e {
        GrantError::NotFound => OwnerFailure::NotFound,
        GrantError::NotPending => OwnerFailure::NotPending,
        GrantError::StandingDisabled => OwnerFailure::StandingDisabled,
        GrantError::InvalidTerms(_) => OwnerFailure::InvalidTerms,
        GrantError::AuditFailed => OwnerFailure::AuditFailed,
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
    /// `audit.checkpoint_local_only = false` but no `[approval].ntfy`
    /// channel is configured. The config loader refuses this first
    /// (`audit_no_off_host_sink`); this is defence in depth so the
    /// daemon never silently downgrades to local-only checkpoints.
    #[error(
        "audit checkpoints need an off-host sink ([approval].ntfy) \
         or audit.checkpoint_local_only = true"
    )]
    OffHostCheckpointNotConfigured,
    /// The off-host checkpoint sink could not be built at startup
    /// (e.g. the ntfy token file is unreadable). Fail closed rather
    /// than run with checkpoints going nowhere (REQ-AUD-002, #127).
    #[error("cannot set up off-host audit checkpoint sink: {kind}")]
    CheckpointSinkSetup {
        /// `std::io::ErrorKind` rendering. No file contents.
        kind: String,
    },
    /// The approval-prompt ntfy publisher could not be built at
    /// startup (e.g. the ntfy token file is unreadable, when
    /// `[approval].ntfy` and `[owner_ui]` are both configured). Fail
    /// closed rather than run with prompts going nowhere
    /// (REQ-APR-004, #128) — the same posture as the checkpoint sink.
    #[error("cannot set up approval ntfy publisher: {kind}")]
    ApprovalNotifierSetup {
        /// `std::io::ErrorKind` rendering. No file contents.
        kind: String,
    },
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
    /// The owner UI listen address could not be bound.
    #[error("cannot bind owner UI on {addr}: {kind}")]
    OwnerUiBind {
        /// Configured address.
        addr: SocketAddr,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
    /// The passkey store under `data_dir/owner` could not be opened.
    #[error("cannot open owner passkey store: {kind}")]
    OwnerUiStore {
        /// `std::io::ErrorKind` rendering. No file contents.
        kind: String,
    },
    /// A configured TLS certificate or key could not be loaded.
    #[error("tls material: {reason}")]
    TlsMaterial {
        /// Fixed-text reason.
        reason: &'static str,
    },
    /// The connector listen address could not be bound.
    #[error("cannot bind agent connector on {addr}: {kind}")]
    ConnectorBind {
        /// Configured address.
        addr: SocketAddr,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
    /// The public-ingress listen address could not be bound (#198).
    #[error("cannot bind public ingress on {addr}: {kind}")]
    PublicIngressBind {
        /// Configured address.
        addr: SocketAddr,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
}

/// Path B accept task plus the hub the CDP backend dials through.
struct ConnectorRuntime {
    task: tokio::task::JoinHandle<()>,
    addr: SocketAddr,
    hub: Arc<crate::connector::Hub>,
}

impl StartupError {
    /// Stable machine-readable code, printed by the daemon on refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ApiListenMissing => "api_listen_missing",
            Self::OffHostCheckpointNotConfigured => "audit_off_host_not_configured",
            Self::CheckpointSinkSetup { .. } => "audit_checkpoint_sink_setup",
            Self::ApprovalNotifierSetup { .. } => "approval_notifier_setup",
            Self::Harden(_) => "harden_failed",
            Self::Mlock(_) => "mlock_failed",
            Self::Tokens(_) => "token_store",
            Self::DataDir { .. } => "data_dir",
            Self::Audit(_) => "audit_open",
            Self::Export(e) => e.code(),
            Self::OwnerBind { .. } => "owner_bind",
            Self::Bind { .. } => "bind",
            Self::OwnerUiBind { .. } => "owner_ui_bind",
            Self::OwnerUiStore { .. } => "owner_ui_store",
            Self::TlsMaterial { .. } => "tls_material",
            Self::ConnectorBind { .. } => "connector_bind",
            Self::PublicIngressBind { .. } => "public_ingress_bind",
        }
    }

    /// Process exit status (`sysexits.h`).
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::ApiListenMissing
            | Self::OffHostCheckpointNotConfigured
            | Self::CheckpointSinkSetup { .. }
            | Self::ApprovalNotifierSetup { .. }
            | Self::Tokens(_) => EX_CONFIG,
            Self::Harden(_) | Self::Mlock(_) => EX_OSERR,
            Self::Export(_) => EX_CONFIG,
            Self::DataDir { .. }
            | Self::Audit(_)
            | Self::OwnerBind { .. }
            | Self::OwnerUiStore { .. } => EX_CANTCREAT,
            Self::Bind { .. }
            | Self::OwnerUiBind { .. }
            | Self::ConnectorBind { .. }
            | Self::PublicIngressBind { .. } => EX_UNAVAILABLE,
            Self::TlsMaterial { .. } => EX_CONFIG,
        }
    }
}

/// The config checks [`start`] adds on top of the loader, without
/// side effects: what `kharond --check` runs after `load_for_startup`.
pub fn check(cfg: &Config) -> Result<SocketAddr, StartupError> {
    let api = cfg.api.as_ref().ok_or(StartupError::ApiListenMissing)?;
    // REQ-AUD-002 (#127): off-host checkpoints are served by the ntfy
    // sink; the loader already guarantees the channel exists in this
    // mode, and `--check` must not read the token file or touch the
    // network, so presence is all that is verified here. Sink
    // construction (fail-closed) happens in `start`.
    if !cfg.audit.checkpoint_local_only && cfg.approval.ntfy.is_none() {
        return Err(StartupError::OffHostCheckpointNotConfigured);
    }
    Ok(api.listen)
}

/// An assembled daemon: locked broker plus bound listener.
pub struct Daemon {
    listener: TcpListener,
    /// Set when the agent API speaks TLS (path B, and path A if configured).
    api_tls: Option<Arc<rustls::ServerConfig>>,
    /// Path B accept loop, if any agent uses `via = agent_connector`.
    connector: Option<ConnectorRuntime>,
    broker: Arc<DaemonBroker>,
    clock: Option<SyncClient>,
    owner_listener: UnixListener,
    owner_ops: Arc<DaemonOwner>,
    owner_path: PathBuf,
    /// Bound owner UI, when `[owner_ui]` is set (REQ-APR-005).
    owner_ui: Option<(TcpListener, Arc<crate::owner_ui::OwnerUi>)>,
    owner_ui_addr: Option<SocketAddr>,
    owner_ui_origin: Option<String>,
    /// Bound public-ingress listener, when `[public_ingress]` is set
    /// (#198), with its TLS config when it speaks TLS.
    public_ingress: Option<PublicIngressRuntime>,
}

/// `[public_ingress]` bound at startup (#198).
struct PublicIngressRuntime {
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    addr: SocketAddr,
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
    // REQ-AUD-002 (#127): local-only runs keep the file checkpoint
    // stream; SPEC-default runs publish checkpoints to the configured
    // ntfy topic (the off-host stream). Building the ntfy sink reads
    // its token file eagerly — an unreadable token refuses startup
    // here instead of silently downgrading.
    let sink: Box<dyn CheckpointSink> = if cfg.audit.checkpoint_local_only {
        Box::new(
            FileCheckpointSink::create(&audit_dir.join("checkpoints.jsonl"))
                .map_err(OpenError::Io)?,
        )
    } else {
        let ntfy = cfg
            .approval
            .ntfy
            .as_ref()
            .ok_or(StartupError::OffHostCheckpointNotConfigured)?;
        Box::new(
            NtfyCheckpointSink::new(&ntfy.url, &ntfy.topic, ntfy.token_file.as_deref()).map_err(
                |e| StartupError::CheckpointSinkSetup {
                    kind: e.kind().to_string(),
                },
            )?,
        )
    };
    let mut audit = AuditLog::open(
        &audit_dir,
        LogConfig {
            plaintext_item_names: cfg.audit.item_names,
            ..LogConfig::default()
        },
        sink,
    )?;
    // SPEC §8 (#130): grant requests live in memory, so the last run's
    // pending ones died with it. Record each as `abandoned` now, before
    // anything is served, from the log just verified.
    for request in crate::audit::unresolved_grant_requests(&audit_dir.join("audit.jsonl"))
        .map_err(OpenError::Io)?
    {
        audit
            .append(request.abandoned_entry())
            .map_err(OpenError::Recovery)?;
    }

    // The unlock source, assembled at startup: sync mode keeps the
    // source config (a client is built per unlock); export mode
    // loads the export file ONCE, here — every unlock uses this
    // instance, never a re-read (REQ-EXP-004 load-once).
    let source = match &cfg.source {
        Source::Sync(bw) => UnlockSource::Sync(Box::new(bw.clone())),
        Source::Export(exp) => UnlockSource::Export(Arc::new(ExportFile::load(&exp.file)?)),
    };

    let lock = LockController::new(
        LockPolicy::from((&cfg.policy, &cfg.memory)),
        SystemClock,
        hardening,
    );
    let connector = bind_connector(cfg).await?;
    let api_tls = match cfg.api.as_ref().and_then(|api| api.tls.as_ref()) {
        Some(material) => Some(load_tls_material(material)?),
        None => None,
    };
    let mut cdp_backend = ConnectingCdpBackend::from_agents(&cfg.agents);
    if let Some(rt) = &connector {
        cdp_backend = cdp_backend.with_connector(Arc::clone(&rt.hub));
    }
    let broker = Broker::new(tokens, lock, Box::new(audit), cfg.policy.origin_config())
        .with_clock_skew_policy(SkewPolicy::from(&cfg.policy))
        // SPEC §5 (#20): standing grants only when `[policy]
        // allow_standing` says so.
        .with_grant_policy(crate::api::GrantPolicy::from(&cfg.policy))
        .with_rate_policy(crate::api::rate::RatePolicy::from(&cfg.policy))
        // REQ-API-009 `fill_deadline` and the fill origin policy.
        .with_fill_policy(FillPolicy::from(&cfg.policy))
        // REQ-API-008: each agent's configured CDP endpoint,
        // connected (and its browser context created, REQ-ARCH-005)
        // on its first fill or `kharon_context` call, after that
        // call's `fill_dispatch`/`context_open` entry and inside the
        // deadline. Startup does not need the browser. Path B attaches
        // the connector hub below, once the listener exists.
        .with_fill_backend(Box::new(cdp_backend));
    // REQ-APR-004 send half (#128): publish approval prompts to the
    // configured ntfy topic, with action URLs on the owner listener.
    // Needs both halves: no `[approval].ntfy` → no channel; no
    // `[owner_ui]` → the redeem routes are served nowhere, so the
    // action URLs would be dead. A configured owner port of 0 is an
    // ephemeral test address — no stable redeem base exists to
    // publish, so prompts stay unpublished in that shape. Building
    // the notifier reads its token file eagerly — an unreadable
    // token refuses startup here instead of silently never prompting.
    let broker = match (&cfg.approval.ntfy, &cfg.owner_ui) {
        (Some(ntfy), Some(ui)) if ui.listen.port() != 0 => {
            let notifier = crate::api::NtfyApprovalNotifier::new(
                &ntfy.url,
                &ntfy.topic,
                ntfy.token_file.as_deref(),
                format!("http://{}", ui.listen),
            )
            .map_err(|e| StartupError::ApprovalNotifierSetup {
                kind: e.kind().to_string(),
            })?;
            broker.with_approval_notifier(Arc::new(notifier))
        }
        _ => broker,
    };
    // SPEC §8: a fill against a vault older than 5 min re-syncs first.
    let broker = Arc::new(match &cfg.source {
        Source::Sync(bw) => broker.with_fill_sync(Arc::new(DaemonFillSync(Box::new(bw.clone())))),
        Source::Export(_) => broker,
    });
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
    let (owner_ui, owner_ui_addr, owner_ui_origin) = bind_owner_ui(cfg, &broker).await?;
    let owner_ops = Arc::new(DaemonOwner {
        broker: Arc::clone(&broker),
        source,
        sync_task: std::sync::Mutex::new(None),
        owner_ui: owner_ui.as_ref().map(|(_, ui)| Arc::clone(ui)),
    });
    if let Some((_, ui)) = &owner_ui {
        // Web unlock (#131 slice 5b): the UI reaches the owner
        // socket's own unlock. `Weak`, because the owner ops already
        // hold the UI.
        ui.set_unlocker(Arc::new(DaemonUiUnlock {
            owner: Arc::downgrade(&owner_ops),
            runtime: tokio::runtime::Handle::current(),
        }));
    }

    let public_ingress = bind_public_ingress(cfg).await?;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|e| StartupError::Bind {
            addr: listen,
            kind: e.kind().to_string(),
        })?;
    Ok(Daemon {
        listener,
        api_tls,
        connector,
        broker,
        clock,
        owner_listener,
        owner_ops,
        owner_path,
        owner_ui,
        owner_ui_addr,
        owner_ui_origin,
        public_ingress,
    })
}

/// Bind `[public_ingress]` when it is configured (#198).
async fn bind_public_ingress(cfg: &Config) -> Result<Option<PublicIngressRuntime>, StartupError> {
    let Some(public) = &cfg.public_ingress else {
        return Ok(None);
    };
    let tls = match &public.tls {
        Some(material) => Some(load_tls_material(material)?),
        None => None,
    };
    let bind_err = |e: io::Error| StartupError::PublicIngressBind {
        addr: public.listen,
        kind: e.kind().to_string(),
    };
    let listener = TcpListener::bind(public.listen).await.map_err(bind_err)?;
    let addr = listener.local_addr().map_err(bind_err)?;
    Ok(Some(PublicIngressRuntime {
        listener,
        tls,
        addr,
    }))
}

fn load_tls_material(
    material: &crate::config::TlsMaterial,
) -> Result<Arc<rustls::ServerConfig>, StartupError> {
    crate::config::load_tls(material).map_err(|e| StartupError::TlsMaterial {
        reason: match e {
            crate::config::ConfigError::TlsMaterial { reason } => reason,
            _ => "unreadable certificate",
        },
    })
}

async fn bind_connector(cfg: &Config) -> Result<Option<ConnectorRuntime>, StartupError> {
    let Some(connector) = &cfg.connector else {
        return Ok(None);
    };
    let tls = load_tls_material(&connector.tls)?;
    let listener =
        TcpListener::bind(connector.listen)
            .await
            .map_err(|e| StartupError::ConnectorBind {
                addr: connector.listen,
                kind: e.kind().to_string(),
            })?;
    let addr = listener
        .local_addr()
        .map_err(|e| StartupError::ConnectorBind {
            addr: connector.listen,
            kind: e.kind().to_string(),
        })?;
    let tokens = TokenStore::from_connector_agents(&cfg.agents)?;
    let hub = Arc::new(crate::connector::Hub::new(tokens));
    let accept_hub = Arc::clone(&hub);
    let task = tokio::spawn(async move {
        crate::connector::accept(listener, tls, accept_hub).await;
    });
    Ok(Some(ConnectorRuntime { task, addr, hub }))
}

/// Bind `[owner_ui]` when it is configured. The origin uses the
/// port the kernel actually assigned (load-bearing when the file
/// says port 0).
async fn bind_owner_ui(
    cfg: &Config,
    broker: &Arc<DaemonBroker>,
) -> Result<
    (
        Option<(TcpListener, Arc<crate::owner_ui::OwnerUi>)>,
        Option<SocketAddr>,
        Option<String>,
    ),
    StartupError,
> {
    let Some(ui_cfg) = &cfg.owner_ui else {
        return Ok((None, None, None));
    };
    let listener =
        TcpListener::bind(ui_cfg.listen)
            .await
            .map_err(|e| StartupError::OwnerUiBind {
                addr: ui_cfg.listen,
                kind: e.kind().to_string(),
            })?;
    let addr = listener
        .local_addr()
        .map_err(|e| StartupError::OwnerUiBind {
            addr: ui_cfg.listen,
            kind: e.kind().to_string(),
        })?;
    let origin = ui_cfg.origin_for_bound_port(addr.port());
    let ui = crate::owner_ui::OwnerUi::open(
        &cfg.data_dir,
        ui_cfg.rp_id.clone(),
        origin.clone(),
        Arc::new(DaemonShell {
            broker: Arc::clone(broker),
        }),
        Arc::new(DaemonUiAudit {
            broker: Arc::clone(broker),
        }),
        Arc::clone(broker) as Arc<dyn crate::owner_ui::OwnerApprovals>,
    )
    .map_err(|e| StartupError::OwnerUiStore {
        kind: e.kind().to_string(),
    })?;
    Ok((Some((listener, ui)), Some(addr), Some(origin)))
}

/// Shell facts from the live broker. Called on the UI's blocking
/// thread: it takes the lock-controller mutex.
struct DaemonShell {
    broker: Arc<DaemonBroker>,
}

impl crate::owner_ui::OwnerShell for DaemonShell {
    fn view(&self) -> crate::owner_ui::ShellView {
        let locked = {
            let mut lock = self
                .broker
                .lock_controller()
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            lock.poll();
            lock.is_locked()
        };
        let pending = self.broker.pending_grant_requests().len();
        crate::owner_ui::ShellView { locked, pending }
    }
}

struct DaemonUiAudit {
    broker: Arc<DaemonBroker>,
}

impl crate::owner_ui::OwnerAudit for DaemonUiAudit {
    fn auth_failed(&self, detail: &'static str) {
        let entry = Entry::new(Event::OwnerAuthFail)
            .channel("web_ui")
            .result("denied")
            .detail_code(detail);
        let _ = self.broker.append_audit(entry);
    }
}

/// Web unlock backend (#131 slice 5b): the owner socket's own
/// [`OwnerOps::unlock`], so the derivation, the mlock and dumpable
/// checks, the `unlocked` / `export_loaded` audit entries and the
/// live sync start are exactly the CLI's. Runs on the UI's blocking
/// thread, where blocking on the runtime is allowed.
struct DaemonUiUnlock {
    owner: std::sync::Weak<DaemonOwner>,
    runtime: tokio::runtime::Handle,
}

impl crate::owner_ui::OwnerUnlock for DaemonUiUnlock {
    fn unlock(&self, password: Zeroizing<String>) -> Result<(), OwnerFailure> {
        let Some(owner) = self.owner.upgrade() else {
            return Err(OwnerFailure::Unsupported);
        };
        self.runtime.block_on(OwnerOps::unlock(&*owner, password))
    }
}

impl Daemon {
    /// The bound address (resolves a configured port 0).
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Whether the agent API listener speaks TLS.
    pub fn agent_api_tls(&self) -> bool {
        self.api_tls.is_some()
    }

    /// The connector listen address, when path B is configured.
    pub fn connector_addr(&self) -> Option<SocketAddr> {
        self.connector.as_ref().map(|rt| rt.addr)
    }

    /// The owner socket path (`kharon unlock` / `lock` connect here).
    pub fn owner_socket(&self) -> &std::path::Path {
        &self.owner_path
    }

    /// The owner UI's bound address, when `[owner_ui]` is set.
    pub fn owner_ui_addr(&self) -> Option<SocketAddr> {
        self.owner_ui_addr
    }

    /// The WebAuthn origin the owner UI expects (`clientDataJSON`).
    pub fn owner_ui_origin(&self) -> Option<&str> {
        self.owner_ui_origin.as_deref()
    }

    /// The public-ingress listener's bound address, when
    /// `[public_ingress]` is set (#198).
    pub fn public_ingress_addr(&self) -> Option<SocketAddr> {
        self.public_ingress.as_ref().map(|rt| rt.addr)
    }

    /// Whether the public-ingress listener speaks TLS.
    pub fn public_ingress_tls(&self) -> bool {
        self.public_ingress
            .as_ref()
            .is_some_and(|rt| rt.tls.is_some())
    }

    /// Serve the agent API until `shutdown` resolves.
    pub async fn run<F>(self, shutdown: F) -> io::Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let probe = self
            .clock
            .map(|client| tokio::spawn(clock_probe(client, Arc::clone(&self.broker))));
        // REQ-AUD-002 10-minute leg (#127): appends piggy-back the
        // checkpoint cadence, but a quiet broker appends nothing — this
        // timer asks the log to anchor its tail once the configured
        // period (10 min by default) has elapsed. The push itself is
        // network I/O on a blocking thread.
        let timer_broker = Arc::clone(&self.broker);
        let checkpoint_timer = tokio::spawn(async move {
            loop {
                tokio::time::sleep(CHECKPOINT_TIMER_TICK).await;
                let broker = Arc::clone(&timer_broker);
                let _ = tokio::task::spawn_blocking(move || broker.checkpoint_audit_if_due()).await;
            }
        });
        // REQ-APR-003 (#130): deny requests past their 120 s timeout on
        // a cadence too, so the denial is audited close to the timeout
        // even when no agent or owner call comes along to trigger it.
        let expiry_broker = Arc::clone(&self.broker);
        let request_expiry = tokio::spawn(async move {
            loop {
                tokio::time::sleep(REQUEST_EXPIRY_TICK).await;
                let broker = Arc::clone(&expiry_broker);
                let _ = tokio::task::spawn_blocking(move || broker.expire_grant_requests()).await;
            }
        });
        let owner_ops = Arc::clone(&self.owner_ops);
        let owner = tokio::spawn(crate::owner::serve(self.owner_listener, self.owner_ops));
        let owner_ui = self.owner_ui.map(|(listener, ui)| {
            let broker = Arc::clone(&self.broker);
            let redeem: Arc<dyn crate::api::http::ApprovalRedeemer> = broker;
            tokio::spawn(async move {
                let _ = crate::owner_ui::serve(listener, ui, redeem).await;
            })
        });
        // #198: the public-ingress listener stops with the agent API,
        // after at most PUBLIC_INGRESS_DRAIN of graceful drain.
        let (public_stop, public_stopped) = tokio::sync::oneshot::channel::<()>();
        let public_ingress = self.public_ingress.map(|rt| {
            let broker = Arc::clone(&self.broker);
            let stopped = async move {
                let _ = public_stopped.await;
            };
            tokio::spawn(async move {
                let _ = match rt.tls {
                    Some(tls) => {
                        crate::api::public::serve_tls_with_shutdown(
                            rt.listener,
                            tls,
                            broker,
                            stopped,
                        )
                        .await
                    }
                    None => {
                        crate::api::public::serve_with_shutdown(rt.listener, broker, stopped).await
                    }
                };
            })
        });
        let shutdown_broker = Arc::clone(&self.broker);
        let connector_task = self.connector.as_ref().map(|rt| rt.task.abort_handle());
        let served = match self.api_tls {
            Some(tls) => {
                http::serve_tls_with_shutdown(self.listener, tls, self.broker, shutdown).await
            }
            None => http::serve_with_shutdown(self.listener, self.broker, shutdown).await,
        };
        if let Some(task) = connector_task {
            task.abort();
        }
        // Graceful drain, bounded: an open public connection must not
        // hold shutdown (#198 review; #199 puts a WebSocket here).
        let _ = public_stop.send(());
        if let Some(mut task) = public_ingress
            && tokio::time::timeout(PUBLIC_INGRESS_DRAIN, &mut task)
                .await
                .is_err()
        {
            task.abort();
        }
        checkpoint_timer.abort();
        request_expiry.abort();
        owner.abort();
        if let Some(task) = owner_ui {
            task.abort();
        }
        owner_ops.stop_live_sync();
        if let Some(p) = probe {
            p.abort();
        }
        // Anchor the tail before exiting (#127): whatever was appended
        // since the last checkpoint (the final lock, say) leaves the
        // host with the daemon, not at the next start. Best effort —
        // a dead sink must not hang or fail the shutdown; the cadence
        // counters were not reset, so the next run retries.
        let _ = tokio::task::spawn_blocking(move || shutdown_broker.checkpoint_audit_now()).await;
        served
    }
}

/// How long the public-ingress listener (#198) may drain open
/// connections at shutdown before it is aborted. A public client that
/// never finishes a request, or a WebSocket on `/connector` (#199) that
/// never closes, cannot hold daemon shutdown open past this.
pub const PUBLIC_INGRESS_DRAIN: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the daemon's checkpoint timer wakes to ask the audit log
/// whether its 10-minute checkpoint is due (REQ-AUD-002, #127). The
/// due decision itself lives in the log (`AuditConfig::checkpoint_period`),
/// so this only bounds how late a due checkpoint can be.
pub const CHECKPOINT_TIMER_TICK: std::time::Duration = std::time::Duration::from_secs(30);

/// How often the daemon denies grant requests past their timeout
/// (REQ-APR-003, #130). Agent and owner calls also expire first; this
/// bounds how late a quiet broker audits a timeout denial.
pub const REQUEST_EXPIRY_TICK: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the live sync re-checks that its session still exists
/// (and enforces the idle/absolute timers, REQ-MEM-004) between
/// syncs, so a lock tears down the hub connection and the sync
/// client's access token promptly instead of at the next poll.
pub const LIVE_SYNC_LOCK_CHECK: std::time::Duration = std::time::Duration::from_secs(5);

/// What one step of [`live_sync`] decided.
enum LiveStep {
    /// Keep going.
    Continue,
    /// The session this task serves is gone: stop.
    Stop,
    /// The fetched payload could not be applied; the vault is kept.
    Failed(SyncError),
}

/// Run `f` on the controller if the session this task serves (by
/// unlock instant) is still the one held; [`LiveStep::Stop`] if not.
async fn with_generation(
    broker: &Arc<DaemonBroker>,
    generation: std::time::Duration,
    f: impl FnOnce(&mut crate::lock::LockController<DaemonSession, SystemClock>) -> LiveStep
    + Send
    + 'static,
) -> LiveStep {
    let broker = Arc::clone(broker);
    tokio::task::spawn_blocking(move || {
        let mut lock = broker
            .lock_controller()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // Enforce the timers first (not activity), so an expired
        // session is locked with its reason and this task stops.
        lock.poll();
        if lock.unlocked_at() != Some(generation) {
            return LiveStep::Stop;
        }
        f(&mut lock)
    })
    .await
    .unwrap_or(LiveStep::Stop)
}

/// REQ-CRY-009 live sync for one sync-mode unlock: a full
/// `/api/sync` every `interval` (≤ [`crate::sync::MAX_SYNC_INTERVAL`])
/// and on every notifications-hub push, applied to the unlocked
/// session in place, so agent `list` reflects web-vault changes
/// without a restart. The network round trip runs on this task's
/// own client, never under the controller's mutex; only the
/// CPU-only apply does (on a blocking thread). A payload that
/// widens the account's scope (REQ-CRY-008) or rotates the org key
/// (REQ-MEM-006) locks via `on_sync_lock`, whose audit entry the
/// lock wiring writes (`scope_widened` / `key_rotated`). Transport
/// and apply errors keep the last good vault and retry on the next
/// tick or push. Ends when the session it serves is locked; the
/// client (and with it the hub connection and its access token) is
/// dropped then.
async fn live_sync(
    broker: Arc<DaemonBroker>,
    mut client: SyncClient,
    generation: std::time::Duration,
    interval: std::time::Duration,
) {
    let (nudge_tx, mut nudge) = tokio::sync::mpsc::channel(1);
    let mut hub_state: Option<&'static str> = None;
    let push = tokio::spawn(run_push(
        client.notifications_hub(),
        nudge_tx,
        move |status| {
            // Operator signal on transitions only (no secrets in
            // `HubStatus`; tokens are never Debug-printed).
            let now = match status {
                HubStatus::Connected => Some("connected"),
                HubStatus::Unsupported { .. } => Some("unsupported"),
                HubStatus::Disconnected(_) => Some("disconnected"),
                _ => None,
            };
            if let Some(now) = now
                && hub_state != Some(now)
            {
                match now {
                    "connected" => eprintln!("kharond: notifications hub connected"),
                    "unsupported" => eprintln!(
                        "kharond: notifications hub not supported by the server; polling only"
                    ),
                    _ => eprintln!("kharond: notifications hub disconnected; reconnecting"),
                }
                hub_state = Some(now);
            }
        },
    ));
    let start = tokio::time::Instant::now();
    let mut tick = tokio::time::interval_at(start + interval, interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut check = tokio::time::interval_at(start + LIVE_SYNC_LOCK_CHECK, LIVE_SYNC_LOCK_CHECK);
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut push_open = true;
    let mut last_error: Option<String> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            n = nudge.recv(), if push_open => {
                if n.is_none() {
                    push_open = false;
                    continue;
                }
            }
            _ = check.tick() => {
                match with_generation(&broker, generation, |_| LiveStep::Continue).await {
                    LiveStep::Stop => break,
                    _ => continue,
                }
            }
        }
        let step = match client.sync().await {
            Ok(sync) => {
                let broker_sync = Arc::clone(&broker);
                tokio::task::spawn_blocking(move || {
                    let mut lock = broker_sync
                        .lock_controller()
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    lock.poll();
                    if lock.unlocked_at() != Some(generation) {
                        return LiveStep::Stop;
                    }
                    let outcome = lock.with_session_mut(|session| match session {
                        DaemonSession::Sync(live) => live.apply(&sync),
                        DaemonSession::Export(_) => Ok(SyncOutcome::Synced),
                    });
                    match outcome {
                        Err(_locked) => LiveStep::Stop,
                        Ok(Ok(SyncOutcome::Synced)) => {
                            // REQ-REV-003/004 under the same lock hold.
                            let vault = match lock.require_unlocked() {
                                Ok(s) => s.vault().clone(),
                                Err(_) => return LiveStep::Stop,
                            };
                            if broker_sync.detect_rollback(&vault).is_err() {
                                // The session is unlocked here, so this
                                // lock transitions and the sink
                                // (`wire_lock_audit`) writes the one
                                // `rollback_detected` entry.
                                // `detect_rollback` does not append one.
                                lock.lock(crate::lock::LockReason::RollbackDetected);
                                return LiveStep::Stop;
                            }
                            if let Err(e) = broker_sync.invalidate_grants_for_vault(&vault) {
                                // Revoke-first (SPEC §7, #135): the grants
                                // are already gone from memory and stay
                                // gone; only their `grant_revoke` entries
                                // are missing. Say so, rather than leave
                                // an unexplained gap in the log.
                                eprintln!(
                                    "kharond: error: a sync revoked grants, but their grant_revoke audit entries could not all be written ({e}); the grants stay revoked"
                                );
                            }
                            LiveStep::Continue
                        }
                        Ok(Ok(SyncOutcome::Lock(reason))) => {
                            lock.on_sync_lock(&reason);
                            LiveStep::Stop
                        }
                        Ok(Err(e)) => LiveStep::Failed(e),
                    }
                })
                .await
                .unwrap_or(LiveStep::Stop)
            }
            Err(e) => {
                // The session may have gone while the request ran.
                match with_generation(&broker, generation, |_| LiveStep::Continue).await {
                    LiveStep::Stop => LiveStep::Stop,
                    _ => LiveStep::Failed(e),
                }
            }
        };
        match step {
            LiveStep::Stop => break,
            LiveStep::Continue => {
                tick.reset();
                if last_error.take().is_some() {
                    eprintln!("kharond: live sync recovered");
                }
            }
            LiveStep::Failed(e) => {
                // Once per distinct error; the last good vault stays.
                let msg = e.to_string();
                if last_error.as_deref() != Some(msg.as_str()) {
                    eprintln!(
                        "kharond: warning: live sync failed ({msg}); keeping the last synced vault"
                    );
                    last_error = Some(msg);
                }
            }
        }
    }
    // Dropping the client drops its token source, which ends the
    // push task; abort covers a task parked in a connect.
    drop(client);
    push.abort();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::core::{AuditSink, Request};
    use crate::lock::{AuditError, StaticHardening};
    use std::sync::Mutex;

    /// An audit sink that records event names and can be told to
    /// refuse `export_loaded` appends (PR #81 review, item 6's
    /// failing-sink test).
    struct TestSink {
        events: Arc<Mutex<Vec<String>>>,
        fail_export_loaded: bool,
    }

    impl AuditSink for TestSink {
        fn append(&mut self, entry: Entry) -> Result<(), AuditError> {
            let name = serde_json::to_value(&entry.event)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            if self.fail_export_loaded && name == "export_loaded" {
                return Err(AuditError);
            }
            self.events.lock().unwrap().push(name);
            Ok(())
        }
    }

    fn export_owner(
        fail_export_loaded: bool,
    ) -> (
        DaemonOwner,
        Arc<Mutex<Vec<String>>>,
        Arc<DaemonBroker>,
        String,
    ) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = TestSink {
            events: Arc::clone(&events),
            fail_export_loaded,
        };
        // One real agent, so tests can drive the broker's agent
        // surface (nit 6's explicit 423 assertion).
        let (token, hash) = crate::api::token::generate("alpha");
        let token = token.expose_secret().clone();
        let tokens = TokenStore::new([("alpha", hash.as_str())]).unwrap();
        let lock = LockController::new(
            LockPolicy {
                require_mlock: false,
                ..LockPolicy::default()
            },
            SystemClock,
            Box::new(StaticHardening::all_ok()),
        );
        let broker = Arc::new(Broker::new(
            tokens,
            lock,
            Box::new(sink),
            crate::origin::OriginConfig { allow_http: false },
        ));
        broker.wire_lock_audit();
        let file = ExportFile::from_bytes(
            include_bytes!("../tests/fixtures/export/password_protected.json").as_slice(),
        )
        .unwrap();
        (
            DaemonOwner {
                broker: Arc::clone(&broker),
                source: UnlockSource::Export(Arc::new(file)),
                sync_task: std::sync::Mutex::new(None),
                owner_ui: None,
            },
            events,
            broker,
            token,
        )
    }

    const EXPORT_PASSWORD: &str = "kharon export fixture password 9";

    #[tokio::test]
    async fn export_loaded_append_failure_means_no_session_is_installed() {
        let (owner, events, broker, token) = export_owner(true);
        let err = owner
            .unlock(Zeroizing::new(EXPORT_PASSWORD.to_owned()))
            .await
            .unwrap_err();
        assert_eq!(err, OwnerFailure::AuditFailed);
        assert!(owner.is_locked().await, "status stays locked");
        // Nit 6: `list` is refused 423 while no session is
        // installed, not just `is_locked()` in substance.
        let agent = broker.authenticate(&token).unwrap();
        let err = broker
            .dispatch(&agent, Request::List { origin: None })
            .unwrap_err();
        assert_eq!(err, crate::api::ApiError::LOCKED);
        assert_eq!(err.code.http_status(), 423);
        assert!(
            !events.lock().unwrap().iter().any(|e| e == "unlock"),
            "no unlock entry may stand for an uninstalled session: {:?}",
            events.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn failed_unlock_appends_owner_auth_fail_and_no_unlock() {
        let (owner, events, _broker, _token) = export_owner(false);
        let err = owner
            .unlock(Zeroizing::new(
                "kharon export fixture password 8".to_owned(),
            ))
            .await
            .unwrap_err();
        assert_eq!(err, OwnerFailure::UnlockFailed);
        // The transport records `owner_auth_fail` for this failure
        // class (owner::dispatch); drive that hook the way it does.
        owner.auth_failed("unlock_failed").await;
        let events = events.lock().unwrap();
        assert!(
            events.iter().any(|e| e == "owner_auth_fail"),
            "owner_auth_fail recorded: {events:?}"
        );
        assert!(
            !events.iter().any(|e| e == "unlock"),
            "no unlock entry for a failed unlock: {events:?}"
        );
    }

    #[tokio::test]
    async fn export_loaded_is_recorded_before_the_unlock_entry() {
        let (owner, events, _broker, _token) = export_owner(false);
        owner
            .unlock(Zeroizing::new(EXPORT_PASSWORD.to_owned()))
            .await
            .unwrap();
        assert!(!owner.is_locked().await);
        let events = events.lock().unwrap();
        let loaded = events.iter().position(|e| e == "export_loaded").unwrap();
        let unlock = events.iter().position(|e| e == "unlock").unwrap();
        assert!(loaded < unlock, "export_loaded precedes unlock: {events:?}");
    }
}
