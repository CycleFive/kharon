//! Audit log entry types.

use serde::{Deserialize, Serialize};

/// `prev_hash` of the first entry. Also the value an empty log's head reports.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Audited event. Serialized as its snake_case name.
///
/// Unknown event names are a **deserialize error**: an unrecognized event in
/// a verified chain is itself suspicious, and an open `Other(String)` bucket
/// would be an arbitrary-string interpolation channel (REQ-API-006 forbids
/// value interpolation in everything the daemon emits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Unlock,
    Lock,
    Sync,
    List,
    Search,
    Fill,
    FillTotp,
    GrantRequest,
    GrantIssue,
    GrantRevoke,
    TokenCreate,
    TokenRevoke,
    OwnerAuthFail,
    RateLimit,
    Panic,
    ScopeWidened,
    RollbackDetected,
    KeyRotated,
    ExportLoaded,
    Abandoned,
    /// The log itself truncated a torn (partially written) tail line during
    /// open and recovered to `recovered_seq`. See [`crate::audit::AuditLog`].
    LogTruncated,
}

impl Event {
    fn as_str(&self) -> &str {
        match self {
            Event::Unlock => "unlock",
            Event::Lock => "lock",
            Event::Sync => "sync",
            Event::List => "list",
            Event::Search => "search",
            Event::Fill => "fill",
            Event::FillTotp => "fill_totp",
            Event::GrantRequest => "grant_request",
            Event::GrantIssue => "grant_issue",
            Event::GrantRevoke => "grant_revoke",
            Event::TokenCreate => "token_create",
            Event::TokenRevoke => "token_revoke",
            Event::OwnerAuthFail => "owner_auth_fail",
            Event::RateLimit => "rate_limit",
            Event::Panic => "panic",
            Event::ScopeWidened => "scope_widened",
            Event::RollbackDetected => "rollback_detected",
            Event::KeyRotated => "key_rotated",
            Event::ExportLoaded => "export_loaded",
            Event::Abandoned => "abandoned",
            Event::LogTruncated => "log_truncated",
        }
    }
}

impl Serialize for Event {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "unlock" => Event::Unlock,
            "lock" => Event::Lock,
            "sync" => Event::Sync,
            "list" => Event::List,
            "search" => Event::Search,
            "fill" => Event::Fill,
            "fill_totp" => Event::FillTotp,
            "grant_request" => Event::GrantRequest,
            "grant_issue" => Event::GrantIssue,
            "grant_revoke" => Event::GrantRevoke,
            "token_create" => Event::TokenCreate,
            "token_revoke" => Event::TokenRevoke,
            "owner_auth_fail" => Event::OwnerAuthFail,
            "rate_limit" => Event::RateLimit,
            "panic" => Event::Panic,
            "scope_widened" => Event::ScopeWidened,
            "rollback_detected" => Event::RollbackDetected,
            "key_rotated" => Event::KeyRotated,
            "export_loaded" => Event::ExportLoaded,
            "abandoned" => Event::Abandoned,
            "log_truncated" => Event::LogTruncated,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown audit event `{other}`"
                )));
            }
        })
    }
}

/// One audit entry. `seq`, `ts`, `prev_hash`, `hash`, and `log_id` are
/// assigned by [`crate::audit::AuditLog::append`]; callers set the rest via
/// builder methods.
///
/// Item naming (REQ-AUD-004): by default [`Entry::item_name`] is HMAC-SHA256'd
/// under the `audit_name_key` into `item_name_hash`. With
/// `plaintext_item_names = true` the name is stored verbatim in the separate
/// `item_name` field instead. The two fields never carry data at once, so a
/// reader can always tell which mode produced a line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    /// RFC 3339 timestamp, assigned on append.
    pub ts: String,
    /// Hex SHA-256 of the previous entry, or [`GENESIS_PREV_HASH`] for seq 1.
    pub prev_hash: String,
    /// Random instance id, generated at genesis and written on every entry.
    /// Binds the chain and its checkpoints to one deployment.
    pub log_id: String,
    pub event: Event,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    /// HMAC-SHA256 of the item name under `audit_name_key` (hashed-name mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_name_hash: Option<String>,
    /// Plaintext item name (only when the log runs `plaintext_item_names =
    /// true`). Never set alongside `item_name_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
    /// Head seq recovered from a torn tail line (only on `LogTruncated`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_seq: Option<u64>,
}

impl Entry {
    pub fn new(event: Event) -> Self {
        Self {
            seq: 0,
            ts: String::new(),
            prev_hash: GENESIS_PREV_HASH.to_string(),
            log_id: String::new(),
            event,
            agent_id: None,
            item_id: None,
            item_name_hash: None,
            item_name: None,
            origin: None,
            grant_id: None,
            channel: None,
            result: None,
            detail_code: None,
            recovered_seq: None,
        }
    }

    pub fn agent_id(mut self, v: impl Into<String>) -> Self {
        self.agent_id = Some(v.into());
        self
    }

    pub fn item_id(mut self, v: impl Into<String>) -> Self {
        self.item_id = Some(v.into());
        self
    }

    /// Set the item name. Stored per REQ-AUD-004 (HMAC'd unless the log is
    /// configured for plaintext names).
    pub fn item_name(mut self, v: impl Into<String>) -> Self {
        self.item_name = Some(v.into());
        self
    }

    pub fn origin(mut self, v: impl Into<String>) -> Self {
        self.origin = Some(v.into());
        self
    }

    pub fn grant_id(mut self, v: impl Into<String>) -> Self {
        self.grant_id = Some(v.into());
        self
    }

    pub fn channel(mut self, v: impl Into<String>) -> Self {
        self.channel = Some(v.into());
        self
    }

    pub fn result(mut self, v: impl Into<String>) -> Self {
        self.result = Some(v.into());
        self
    }

    /// Head seq recovered from a torn tail line (only set on
    /// `Event::LogTruncated` entries, which the writer emits itself).
    pub fn recovered_seq(mut self, v: u64) -> Self {
        self.recovered_seq = Some(v);
        self
    }

    /// Machine-readable detail code. Never interpolate values here
    /// (REQ-API-006 applies to everything the daemon emits).
    pub fn detail_code(mut self, v: impl Into<String>) -> Self {
        self.detail_code = Some(v.into());
        self
    }
}
