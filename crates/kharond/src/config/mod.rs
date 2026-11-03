//! Daemon configuration: TOML loader, typed config with spec defaults, and
//! startup validation (REQ-DEP-003).
//!
//! Loading is two-phase:
//!
//! 1. [`Config::from_toml_str`] / [`Config::load`] parse the file, refuse
//!    unknown keys and secret-shaped keys, apply SPEC defaults, and check
//!    every self-contained rule (CDP transport per REQ-ARCH-002, standing
//!    grants need `allow_standing`, durations, IDs, …).
//! 2. [`Config::check_startup`] checks the config against the host: the
//!    mlock rule (`require_mlock = true`, the default, with mlock
//!    unavailable is refused, REQ-MEM-002; the probe is injected via
//!    [`MlockProbe`] so tests need no `CAP_IPC_LOCK`); in export mode
//!    that the export file classifies as a password-protected
//!    encrypted export (REQ-EXP-002, refused at startup); and in sync mode
//!    that the sync client can be built: `api_key_file` passes the
//!    SPEC §8 permission check (REQ-DEP-008: a regular file, not group-
//!    or world-writable; group/world-readable or foreign-owned only
//!    warns), is readable, and holds a personal API key, and `ca_file` (if set) is PEM with at
//!    least one certificate. No network I/O happens here.
//!
//! Every refusal is a distinct [`ConfigError`] variant with a stable
//! [`ConfigError::code`]; the daemon prints the code and exits non-zero.
//! Error text never echoes config values that could be secret: secret
//! keys are refused by name, and TOML parse messages have their quoted
//! string literals redacted.
//!
//! The file format follows SPEC §9:
//!
//! ```toml
//! [bitwarden]
//! server = "http://vaultwarden:80"
//! email = "kharon@example.net"
//! api_key_file = "/run/secrets/kharon_bw_api_key"
//! organization_id = "00000000-0000-0000-0000-000000000001"
//! collection_ids = ["00000000-0000-0000-0000-000000000002"]
//! # ca_file = "/etc/kharon/vault-ca.pem"   # optional extra trust anchor
//!
//! [agents.assistant]
//! token_hash = "$argon2id$..."
//! cdp = { endpoint = "ws://10.66.0.2:9222", via = "wireguard" }
//!
//! [policy]
//! idle_lock = "30m"
//! max_unlocked = "12h"
//! default_grant = "once"
//! allow_standing = false
//!
//! [approval]
//! ntfy = { url = "https://ntfy.example.net", topic = "kharon", token_file = "/run/secrets/ntfy" }
//! ```
//!
//! plus two keys the SPEC §9 example does not show yet (#14):
//!
//! ```toml
//! data_dir = "/data"          # top level; absolute; default "/data" (§9 compose volume)
//!
//! [api]
//! listen = "10.66.0.1:8787"   # agent API; an IP literal, never a wildcard (REQ-DEP-006)
//! ```
//!
//! `[api]` is optional at parse time (so `kharond --check` can validate a
//! file before the bind address is decided), but the daemon refuses to
//! serve without it rather than guess an address.

mod duration;
mod keyfile;
mod mlock;
mod raw;

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use url::Url;

use crate::cdp::{CdpEndpoint, EndpointError, Tunnel};
use crate::origin::OriginConfig;
use crate::sync::{ApiKey, Scope, SyncClient, SyncError, SyncPolicy, TlsTrust};

pub use duration::parse_duration;
pub use mlock::{MlockProbe, ProcfsMlockProbe, StaticMlockProbe};

/// Default path of the daemon config (the compose example mounts it here).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/kharon.toml";

/// SPEC §8: idle lock since the last fill.
pub const DEFAULT_IDLE_LOCK: Duration = Duration::from_secs(30 * 60);
/// SPEC §8: absolute unlocked lifetime.
pub const DEFAULT_MAX_UNLOCKED: Duration = Duration::from_secs(12 * 60 * 60);
/// REQ-API-009: end-to-end fill deadline (same constant the fill engine uses).
pub const DEFAULT_FILL_DEADLINE: Duration = crate::cdp::fill::DEFAULT_FILL_DEADLINE;
/// REQ-API-007: clock skew above this warns.
pub const DEFAULT_CLOCK_SKEW_WARN: Duration = Duration::from_secs(30);
/// REQ-API-007: clock skew above this refuses `fill_totp`.
pub const DEFAULT_CLOCK_SKEW_REFUSE: Duration = Duration::from_secs(90);

/// Config keys that would hold a secret inline. The master password and
/// export password are supplied only at unlock (SPEC §8, REQ-EXP-003);
/// API keys and tokens live in files referenced by `*_file` keys. Matched
/// against the key name at any depth, case-insensitively.
pub const FORBIDDEN_SECRET_KEYS: &[&str] = &[
    "password",
    "master_password",
    "export_password",
    "client_secret",
    "api_key",
    "token",
    "secret",
];

/// Why a config was refused. Each variant is one specific, testable
/// refusal; [`ConfigError::code`] is its stable machine-readable name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The config file could not be read.
    #[error("cannot read config file {path}: {kind}")]
    Read {
        /// Path that failed.
        path: PathBuf,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
    /// TOML syntax error, wrong type, or unknown key.
    #[error("config parse error at line {line}, column {column}: {message}")]
    Parse {
        /// 1-based line (0 if unknown).
        line: usize,
        /// 1-based column (0 if unknown).
        column: usize,
        /// Parser message with quoted string literals redacted.
        message: String,
    },
    /// A key that would hold a secret inline (REQ-EXP-003, SPEC §8).
    #[error(
        "config key `{key}` would hold a secret inline; secrets are supplied at unlock or via *_file keys"
    )]
    SecretInConfig {
        /// Dotted key path.
        key: String,
    },
    /// A section required by the selected mode is absent.
    #[error("missing required section [{section}]")]
    MissingSection {
        /// Section name.
        section: &'static str,
    },
    /// `mode = "export"` together with `[bitwarden]`, or `mode = "sync"`
    /// together with `[export]`: ambiguous source of items.
    #[error("[{section}] is not allowed in mode = \"{mode}\"")]
    SectionNotAllowedInMode {
        /// Offending section.
        section: &'static str,
        /// Selected mode.
        mode: &'static str,
    },
    /// A URL key is not an absolute http(s) URL.
    #[error("`{key}` must be an absolute http:// or https:// URL")]
    InvalidUrl {
        /// Dotted key path.
        key: String,
    },
    /// An ID key is not a UUID.
    #[error("`{key}` must be a UUID")]
    InvalidUuid {
        /// Dotted key path.
        key: String,
    },
    /// `bitwarden.email` is not an address.
    #[error("`bitwarden.email` must be an email address")]
    InvalidEmail,
    /// `bitwarden.collection_ids` is empty (REQ-CRY-007: the item set is
    /// restricted to configured collections; empty would be ambiguous).
    #[error("`bitwarden.collection_ids` must list at least one collection")]
    NoCollections,
    /// No `[agents.*]` configured.
    #[error("no agents configured; add at least one [agents.<id>] table")]
    NoAgents,
    /// Agent ID outside `[a-z0-9-]{1,64}` (it is embedded in
    /// `kh_agent_<id>_<random32>` tokens).
    #[error("agent id `{id}` must match [a-z0-9-]{{1,64}}")]
    InvalidAgentId {
        /// The offending id (a table name, not a secret).
        id: String,
    },
    /// `token_hash` is not an Argon2id PHC string (REQ-API-003).
    #[error("agents.{agent}.token_hash must be an Argon2id PHC string ($argon2id$...)")]
    TokenHashNotArgon2id {
        /// Agent id.
        agent: String,
    },
    /// `cdp.via` is not one of direct, wireguard, ssh, mtls.
    #[error("agents.{agent}.cdp.via `{via}` is not one of direct, wireguard, ssh, mtls")]
    UnknownTunnel {
        /// Agent id.
        agent: String,
        /// Offending value.
        via: String,
    },
    /// `cdp.peer_cert_sha256` is not 64 hex characters.
    #[error("agents.{agent}.cdp.peer_cert_sha256 must be 64 hex characters (SHA-256 of DER)")]
    InvalidPeerPin {
        /// Agent id.
        agent: String,
    },
    /// The CDP endpoint was refused (REQ-ARCH-002), e.g. plain `ws://`
    /// to a non-loopback address with `via = "direct"`.
    #[error("agents.{agent}.cdp: {source}")]
    Cdp {
        /// Agent id.
        agent: String,
        /// Endpoint validation failure.
        source: EndpointError,
    },
    /// A duration string did not parse (`<int><ms|s|m|h|d>`).
    #[error("`{key}` must be a duration like \"10s\", \"30m\", \"12h\"")]
    InvalidDuration {
        /// Dotted key path.
        key: String,
    },
    /// A duration that must be positive is zero.
    #[error("`{key}` must be greater than zero")]
    ZeroDuration {
        /// Dotted key path.
        key: String,
    },
    /// `clock_skew_warn` exceeds `clock_skew_refuse`.
    #[error("`policy.clock_skew_warn` must not exceed `policy.clock_skew_refuse`")]
    ClockSkewThresholdsInverted,
    /// `default_grant = "standing"` without `allow_standing = true`
    /// (SPEC §5: standing grants are off by default, require a flag).
    #[error("default_grant = \"standing\" requires policy.allow_standing = true")]
    StandingGrantsDisabled,
    /// `allow_default_context = true` with more than one agent (SPEC
    /// REQ-ARCH-005: the escape hatch is for single-agent setups; with
    /// several agents a default-context tab is not attributable).
    #[error("policy.allow_default_context = true is only allowed with exactly one agent")]
    DefaultContextMultiAgent,
    /// Audit checkpoints must go off-host by default (SPEC §7) but no
    /// off-host sink is configured and `audit.checkpoint_local_only` is
    /// not set.
    #[error(
        "audit checkpoints need an off-host sink ([approval].ntfy) or audit.checkpoint_local_only = true"
    )]
    AuditNoOffHostSink,
    /// `bitwarden.api_key_file` is unreadable or not a personal API key
    /// (`{"client_id": "user.<uuid>", "client_secret": ...}`). The
    /// reason is fixed text; file content is never echoed.
    #[error("bitwarden.api_key_file: {reason}")]
    ApiKeyFile {
        /// Fixed-text reason.
        reason: &'static str,
    },
    /// `bitwarden.ca_file` is unreadable or holds no PEM certificate.
    #[error("bitwarden.ca_file: {reason}")]
    CaFile {
        /// Fixed-text reason.
        reason: &'static str,
    },
    /// `require_mlock = true` but mlock is not available (REQ-MEM-002).
    #[error("require_mlock = true but mlock is unavailable: {reason}")]
    MlockUnavailable {
        /// Why the probe failed (no secret content).
        reason: String,
    },
    /// An agent's `token_hash` is Argon2id but below the parameter floor
    /// (REQ-API-003: m ≥ 19456 KiB, t ≥ 2, p ≥ 1).
    #[error(
        "agent `{agent}`: token_hash Argon2id parameters are below the floor \
         (need m >= 19456, t >= 2, p >= 1); regenerate the token"
    )]
    TokenHashWeakParams {
        /// The agent whose hash is weak.
        agent: String,
    },
    /// `api.listen` is not `<ip>:<port>` with an IP literal.
    #[error(
        "`api.listen` must be an IP literal and port, e.g. \"10.66.0.1:8787\" or \"[fd00::1]:8787\""
    )]
    ApiListenInvalid,
    /// `api.listen` is a wildcard (unspecified) address (REQ-DEP-006).
    #[error("`api.listen` is a wildcard address; bind the WireGuard interface address instead")]
    ApiWildcardBind,
    /// `api.listen` is a multicast or broadcast address.
    #[error("`api.listen` must be a unicast address")]
    ApiListenNotUnicast,
    /// `data_dir` is not an absolute path.
    #[error("`data_dir` must be an absolute path")]
    DataDirNotAbsolute,
    /// The export file is not a password-protected encrypted export
    /// (REQ-EXP-002: plaintext JSON, CSV, and account-restricted
    /// exports are refused at startup).
    #[error(
        "export file is not a password-protected encrypted Bitwarden export (ExportNotPasswordEncrypted)"
    )]
    ExportNotPasswordEncrypted,
    /// The export file's KDF parameters are unsupported or out of range.
    #[error("export file KDF parameters are invalid")]
    ExportKdfInvalid,
    /// Startup classification returned the unlock-only auth failure:
    /// unreachable in practice (classification never authenticates),
    /// but a typed error instead of a panic in the startup path
    /// (PR #59 review, non-blocking b).
    #[error("export startup classification failed authentication (ExportAuthFailed)")]
    ExportAuthFailed,
    /// The export file could not be read.
    #[error("cannot read export file {path}: {kind}")]
    ExportRead {
        /// Path that failed.
        path: PathBuf,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
}

impl ConfigError {
    /// Stable machine-readable code, printed by the daemon on refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read { .. } => "read",
            Self::Parse { .. } => "parse",
            Self::SecretInConfig { .. } => "secret_in_config",
            Self::MissingSection { .. } => "missing_section",
            Self::SectionNotAllowedInMode { .. } => "section_not_allowed_in_mode",
            Self::InvalidUrl { .. } => "invalid_url",
            Self::InvalidUuid { .. } => "invalid_uuid",
            Self::InvalidEmail => "invalid_email",
            Self::NoCollections => "no_collections",
            Self::NoAgents => "no_agents",
            Self::InvalidAgentId { .. } => "invalid_agent_id",
            Self::TokenHashNotArgon2id { .. } => "token_hash_not_argon2id",
            Self::UnknownTunnel { .. } => "unknown_tunnel",
            Self::InvalidPeerPin { .. } => "invalid_peer_pin",
            Self::Cdp { source, .. } => match source {
                EndpointError::NotWebSocketUrl => "cdp_not_websocket_url",
                EndpointError::PlainWsNonLoopback => "cdp_plain_ws_non_loopback",
                EndpointError::MtlsRequiresWss => "cdp_mtls_requires_wss",
                EndpointError::WssRequiresPeerPin => "cdp_wss_requires_peer_pin",
                EndpointError::UnknownTunnel(_) => "unknown_tunnel",
                EndpointError::BadHost => "cdp_bad_host",
            },
            Self::InvalidDuration { .. } => "invalid_duration",
            Self::ZeroDuration { .. } => "zero_duration",
            Self::ClockSkewThresholdsInverted => "clock_skew_thresholds_inverted",
            Self::StandingGrantsDisabled => "standing_grants_disabled",
            Self::DefaultContextMultiAgent => "default_context_multi_agent",
            Self::AuditNoOffHostSink => "audit_no_off_host_sink",
            Self::ApiKeyFile { .. } => "api_key_file",
            Self::CaFile { .. } => "ca_file",
            Self::MlockUnavailable { .. } => "mlock_unavailable",
            Self::TokenHashWeakParams { .. } => "token_hash_weak_params",
            Self::ApiListenInvalid => "api_listen_invalid",
            Self::ApiWildcardBind => "api_wildcard_bind",
            Self::ApiListenNotUnicast => "api_listen_not_unicast",
            Self::DataDirNotAbsolute => "data_dir_not_absolute",
            Self::ExportNotPasswordEncrypted => "export_not_password_encrypted",
            Self::ExportKdfInvalid => "export_kdf_invalid",
            Self::ExportAuthFailed => "export_auth_failed",
            Self::ExportRead { .. } => "export_read",
        }
    }
}

/// Non-fatal findings, printed at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigWarning {
    /// `audit.checkpoint_local_only = true` (SPEC §7 requires a startup warning).
    AuditCheckpointLocalOnly,
    /// `memory.require_mlock = false`: keys may be swapped to disk.
    MlockNotRequired,
    /// `policy.allow_standing = true`.
    StandingGrantsAllowed,
    /// `policy.allow_http = true`.
    HttpAllowed,
    /// `bitwarden.allow_extra_orgs = true` (REQ-CRY-008 escape hatch).
    ExtraOrgsAllowed,
    /// `bitwarden.api_key_file` is group- or world-readable (REQ-DEP-008;
    /// tolerated for Docker secrets mounted 0444).
    ApiKeyFileReadableByOthers,
    /// `bitwarden.api_key_file` is not owned by kharond's effective uid
    /// (REQ-DEP-008).
    ApiKeyFileForeignOwner,
}

impl fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AuditCheckpointLocalOnly => {
                "audit.checkpoint_local_only = true: checkpoints are not pushed off-host"
            }
            Self::MlockNotRequired => {
                "memory.require_mlock = false: key material may be swapped to disk"
            }
            Self::StandingGrantsAllowed => "policy.allow_standing = true: standing grants enabled",
            Self::HttpAllowed => "policy.allow_http = true: http:// localhost/IP fills permitted",
            Self::ExtraOrgsAllowed => {
                "bitwarden.allow_extra_orgs = true: dedicated-org scope check disabled"
            }
            Self::ApiKeyFileReadableByOthers => {
                "bitwarden.api_key_file is group- or world-readable; use mode 0400 or 0600 unless it is a container-private secret"
            }
            Self::ApiKeyFileForeignOwner => {
                "bitwarden.api_key_file is not owned by kharond's effective uid"
            }
        })
    }
}

/// Where items come from (SPEC §3.1 / §3.1a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Live sync against a Bitwarden/Vaultwarden server.
    Sync(BitwardenConfig),
    /// Offline password-protected encrypted export.
    Export(ExportConfig),
}

/// `[bitwarden]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenConfig {
    /// Server base URL (http allowed: compose network, SPEC §9).
    pub server: Url,
    /// kharon account email (KDF salt; not secret).
    pub email: String,
    /// File holding the personal API key: owned by kharond's euid, mode
    /// 0400/0600 (SPEC §8, REQ-DEP-008).
    pub api_key_file: PathBuf,
    /// The dedicated kharon org (REQ-CRY-008).
    pub organization_id: String,
    /// Collections the item set is restricted to (REQ-CRY-007).
    pub collection_ids: Vec<String>,
    /// REQ-CRY-008 escape hatch. Default false.
    pub allow_extra_orgs: bool,
    /// Extra PEM trust anchor(s) for `server`, in addition to the OS
    /// roots (self-hosted server with a private CA). Not in the SPEC §9
    /// example; optional.
    pub ca_file: Option<PathBuf>,
}

impl BitwardenConfig {
    /// The REQ-CRY-007 item scope.
    pub fn scope(&self) -> Scope {
        Scope::new(&self.organization_id, &self.collection_ids)
            .expect("invariant: validated non-empty org and collections")
    }

    /// REQ-CRY-008/009 live-sync policy: `allow_extra_orgs` and the
    /// 5-minute poll ([`crate::sync::MAX_SYNC_INTERVAL`]).
    pub fn sync_policy(&self) -> SyncPolicy {
        SyncPolicy::new(self.allow_extra_orgs, crate::sync::MAX_SYNC_INTERVAL)
    }

    /// Read and parse `api_key_file`.
    pub fn api_key(&self) -> Result<ApiKey, ConfigError> {
        ApiKey::from_file(&self.api_key_file).map_err(|e| ConfigError::ApiKeyFile {
            reason: match e {
                SyncError::ApiKey(r) => r,
                _ => "unusable",
            },
        })
    }

    /// TLS trust: OS roots plus `ca_file`, which must hold at least one
    /// PEM certificate.
    pub fn tls_trust(&self) -> Result<TlsTrust, ConfigError> {
        let Some(path) = &self.ca_file else {
            return Ok(TlsTrust::default());
        };
        let pem = std::fs::read(path).map_err(|_| ConfigError::CaFile {
            reason: "unreadable",
        })?;
        use rustls_pki_types::pem::PemObject;
        let mut n = 0;
        for c in rustls_pki_types::CertificateDer::pem_slice_iter(&pem) {
            c.map_err(|_| ConfigError::CaFile {
                reason: "not valid PEM",
            })?;
            n += 1;
        }
        if n == 0 {
            return Err(ConfigError::CaFile {
                reason: "no PEM certificate found",
            });
        }
        Ok(TlsTrust {
            extra_ca_pem: Some(pem),
        })
    }

    /// Build the sync client (#8) for this config. Reads both files;
    /// does no network I/O.
    pub fn sync_client(&self) -> Result<SyncClient, ConfigError> {
        let trust = self.tls_trust()?;
        let key = self.api_key()?;
        SyncClient::new(&self.server, &self.email, key, &trust).map_err(|e| match e {
            SyncError::Tls(reason) => ConfigError::CaFile { reason },
            SyncError::ApiKey(reason) => ConfigError::ApiKeyFile { reason },
            _ => ConfigError::InvalidUrl {
                key: "bitwarden.server".to_owned(),
            },
        })
    }
}

/// `[export]` (mode = "export").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportConfig {
    /// Path of the password-protected encrypted export.
    pub file: PathBuf,
}

/// A value that must never appear in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a value.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Access the wrapped value.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// `[agents.<id>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// Argon2id PHC hash of the agent token (REQ-API-003). Not the token,
    /// but still redacted from `Debug` (offline-attackable).
    pub token_hash: Redacted<String>,
    /// Validated CDP endpoint (REQ-ARCH-002).
    pub cdp: CdpEndpoint,
}

/// Grant type for new grants (SPEC §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantKind {
    /// 120 s, max_uses = 1.
    Once,
    /// 1 h (max 24 h).
    PerOrigin,
    /// Off unless `allow_standing`.
    Standing,
}

/// `[policy]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Idle lock since last fill. Default 30m.
    pub idle_lock: Duration,
    /// Absolute unlocked lifetime. Default 12h.
    pub max_unlocked: Duration,
    /// Default grant type. Default `once`.
    pub default_grant: GrantKind,
    /// Standing grants permitted. Default false.
    pub allow_standing: bool,
    /// End-to-end fill deadline (REQ-API-009). Default 10s.
    pub fill_deadline: Duration,
    /// SPEC §6 http exception. Default false.
    pub allow_http: bool,
    /// Named IdP iframe hosts (REQ-ORG-004). Default empty.
    pub allow_cross_origin_iframe_hosts: Vec<String>,
    /// REQ-ARCH-005 single-agent escape hatch. Default false.
    pub allow_default_context: bool,
    /// REQ-API-007 warn threshold. Default 30s.
    pub clock_skew_warn: Duration,
    /// REQ-API-007 refuse threshold. Default 90s.
    pub clock_skew_refuse: Duration,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            idle_lock: DEFAULT_IDLE_LOCK,
            max_unlocked: DEFAULT_MAX_UNLOCKED,
            default_grant: GrantKind::Once,
            allow_standing: false,
            fill_deadline: DEFAULT_FILL_DEADLINE,
            allow_http: false,
            allow_cross_origin_iframe_hosts: Vec::new(),
            allow_default_context: false,
            clock_skew_warn: DEFAULT_CLOCK_SKEW_WARN,
            clock_skew_refuse: DEFAULT_CLOCK_SKEW_REFUSE,
        }
    }
}

impl PolicyConfig {
    /// Origin-binding knobs (SPEC §6).
    pub fn origin_config(&self) -> OriginConfig {
        OriginConfig {
            allow_http: self.allow_http,
        }
    }
}

/// `[approval].ntfy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfyConfig {
    /// ntfy server URL.
    pub url: Url,
    /// Access-controlled topic.
    pub topic: String,
    /// File holding the ntfy access token, if any.
    pub token_file: Option<PathBuf>,
}

/// `[approval]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalConfig {
    /// ntfy channel (also the off-host audit checkpoint sink).
    pub ntfy: Option<NtfyConfig>,
}

/// `[audit]`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditConfig {
    /// SPEC §7 `audit_checkpoint_local_only`. Default false.
    pub checkpoint_local_only: bool,
    /// REQ-AUD-004 `audit_item_names`. Default false.
    pub item_names: bool,
}

/// `[memory]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryConfig {
    /// REQ-MEM-002. Default true.
    pub require_mlock: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            require_mlock: true,
        }
    }
}

/// Validated daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Item source (`mode`).
    pub source: Source,
    /// Agents by id.
    pub agents: BTreeMap<String, AgentConfig>,
    /// Policy knobs.
    pub policy: PolicyConfig,
    /// Approval channels.
    pub approval: ApprovalConfig,
    /// Audit knobs.
    pub audit: AuditConfig,
    /// Memory hardening knobs.
    pub memory: MemoryConfig,
    /// `[api]`: the agent API listener. `None` = not configured; the
    /// daemon refuses to serve (it never picks an address itself).
    pub api: Option<ApiConfig>,
    /// `data_dir`: persistent state (audit log and keys under `audit/`).
    pub data_dir: PathBuf,
}

/// Default `data_dir`: the SPEC §9 compose volume (`./kharon/data:/data`).
pub const DEFAULT_DATA_DIR: &str = "/data";

/// `[api]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiConfig {
    /// Agent API listen address (REQ-DEP-006): a specific unicast IP —
    /// the WireGuard interface address in deployment, loopback in dev.
    /// Never a wildcard; port 0 (ephemeral) is accepted.
    pub listen: SocketAddr,
}

impl Config {
    /// Read and validate a config file (phase 1).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_owned(),
            kind: e.kind().to_string(),
        })?;
        Self::from_toml_str(&text)
    }

    /// Parse and validate config text (phase 1).
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        raw::parse(text)
    }

    /// Host-dependent startup checks (phase 2): REQ-MEM-002 mlock and,
    /// in sync mode, the REQ-DEP-008 `api_key_file` permission check.
    /// Returns host-dependent warnings (in addition to
    /// [`Config::warnings`]) for the daemon to print.
    pub fn check_startup(&self, probe: &dyn MlockProbe) -> Result<Vec<ConfigWarning>, ConfigError> {
        if self.memory.require_mlock {
            probe
                .mlock_available()
                .map_err(|reason| ConfigError::MlockUnavailable { reason })?;
        }
        let mut warnings = Vec::new();
        if let Source::Sync(bw) = &self.source {
            warnings = keyfile::check_api_key_file(&bw.api_key_file)
                .map_err(|reason| ConfigError::ApiKeyFile { reason })?;
            bw.sync_client()?;
        }
        if let Source::Export(exp) = &self.source {
            // REQ-EXP-002: the export file must classify as a
            // password-protected encrypted export at startup, before
            // any unlock exists. This call is classification only,
            // and dropping the parsed envelope here is safe ONLY
            // because no unlock path exists yet: under the
            // REQ-EXP-004 load-once contract, when the unlock channel
            // lands the daemon must keep the startup `ExportFile`
            // and use it for every unlock — re-reading the file at
            // unlock would let a replaced file take effect without a
            // restart, and would reopen a classify/use gap
            // (PR #59 review, non-blocking a).
            crate::export::ExportFile::load(&exp.file).map_err(|e| match e {
                crate::export::ExportError::NotPasswordEncrypted => {
                    ConfigError::ExportNotPasswordEncrypted
                }
                crate::export::ExportError::Kdf(_) => ConfigError::ExportKdfInvalid,
                crate::export::ExportError::Read { path, kind } => {
                    ConfigError::ExportRead { path, kind }
                }
                crate::export::ExportError::AuthFailed => ConfigError::ExportAuthFailed,
            })?;
        }
        Ok(warnings)
    }

    /// Startup warnings to print (never fatal).
    pub fn warnings(&self) -> Vec<ConfigWarning> {
        let mut w = Vec::new();
        if self.audit.checkpoint_local_only {
            w.push(ConfigWarning::AuditCheckpointLocalOnly);
        }
        if !self.memory.require_mlock {
            w.push(ConfigWarning::MlockNotRequired);
        }
        if self.policy.allow_standing {
            w.push(ConfigWarning::StandingGrantsAllowed);
        }
        if self.policy.allow_http {
            w.push(ConfigWarning::HttpAllowed);
        }
        if let Source::Sync(bw) = &self.source
            && bw.allow_extra_orgs
        {
            w.push(ConfigWarning::ExtraOrgsAllowed);
        }
        w
    }
}

/// Load, validate, and run startup checks: what the daemon does at boot.
/// Returns the config and every startup warning (config and host).
pub fn load_for_startup(
    path: &Path,
    probe: &dyn MlockProbe,
) -> Result<(Config, Vec<ConfigWarning>), ConfigError> {
    let cfg = Config::load(path)?;
    let mut warnings = cfg.warnings();
    warnings.extend(cfg.check_startup(probe)?);
    Ok((cfg, warnings))
}

/// Re-exported for [`raw`]: a `Tunnel` from its config string.
fn tunnel_from_config(agent: &str, via: &str) -> Result<Tunnel, ConfigError> {
    Tunnel::from_config(via).ok_or_else(|| ConfigError::UnknownTunnel {
        agent: agent.to_owned(),
        via: via.to_owned(),
    })
}

#[cfg(test)]
mod tests;
