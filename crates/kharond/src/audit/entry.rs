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
    /// Recognized, but not emitted for v1. Agent tokens are minted out
    /// of band (`kharon token mint`); the daemon never sees the plaintext,
    /// so it does not append this event (SPEC §7). The name stays so a
    /// later in-daemon rotation can use it. [`Event::TokenRevoke`] is emitted.
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
    /// REQ-API-009: a fill, fill_totp, or fill_and_submit exceeded its
    /// end-to-end deadline. Written before the timeout response is
    /// returned, after the plaintext buffers are zeroized.
    FillTimeout,
    /// REQ-AUD-003†: a fill is about to make its first CDP write. Appended
    /// before anything touches the page; if the append fails the fill is
    /// refused and no CDP write occurs. Carries the request id, item ref,
    /// claimed origin and field count, never a value. Exactly one outcome
    /// entry (`fill`, `fill_totp`, `fill_timeout` or `fill_aborted`) with
    /// the same `request_id` follows it.
    FillDispatch,
    /// REQ-AUD-003†: the request handler was dropped after `fill_dispatch`
    /// and before the outcome (e.g. the client disconnected mid-fill).
    /// Best effort: written from a drop guard, so a lost append leaves the
    /// orphan `fill_dispatch` as the evidence.
    FillAborted,
    /// REQ-ARCH-005 / REQ-AUD-003† (#65): `kharon_context` /
    /// `POST /v1/context` is about to connect to the agent's browser or
    /// return its cached context. Appended before any CDP write; if the
    /// append fails the call is refused and the browser is not touched.
    /// Carries the request id. Exactly one `context` outcome entry with
    /// the same `request_id` follows it.
    ContextOpen,
    /// REQ-ARCH-005 / REQ-AUD-003† (#65): the outcome of a context
    /// request: result `ok`, `timeout` (`deadline_expired`), `error`
    /// (`cdp_error`, `fill_unavailable`), `locked`, or `aborted`
    /// (`handler_dropped`, best effort from a drop guard).
    Context,
    /// REQ-API-007: the system clock differs from the Vaultwarden
    /// server's `Date` by more than `clock_skew_warn` (result `warn` or
    /// `refuse`), or a previous skew was resolved (result `resolved`).
    ClockSkew,
    /// The log itself truncated a torn (partially written) tail line during
    /// open and recovered to `recovered_seq`. See [`crate::audit::AuditLog`].
    LogTruncated,
    /// #199: a connector hello named a configured agent but the tunnel
    /// credential did not verify. Carries `agent_id`, `transport`,
    /// `detail_code` (always `unauthorized`) and `suppressed`; at
    /// most one per agent per 60 s. Best effort.
    ConnectorAuthFail,
    /// #199: a new connector session evicted a live one. Carries
    /// `agent_id`, the new session's `transport`, `old_session_secs` and
    /// `suppressed`; at most one per agent per 60 s. Best effort.
    ConnectorReplaced,
    /// #249: the owner socket minted an enrollment code. Channel
    /// `cli`, result `minted`. Carries no code. Appended before the
    /// code exists; a failed append mints nothing (REQ-APR-005,
    /// REQ-AUD-003).
    PasskeyEnrollCode,
    /// #249: a passkey is about to be stored. Channel `web_ui`,
    /// result `enrolled`. Carries `credential_fingerprint` and
    /// `passkey_count`, never the credential id. Appended before the
    /// store; a failed append stores nothing (REQ-APR-005,
    /// REQ-AUD-003).
    PasskeyEnrolled,
    /// #258: passkeys are about to be listed. Channel `cli` or
    /// `web_ui`, result `listed`. Carries `credential_fingerprints`
    /// and `passkey_count`, never a credential id or public key.
    /// Appended before the list is returned; a failed append returns
    /// no list (REQ-APR-005, REQ-AUD-003).
    PasskeyListed,
    /// #258: a passkey is about to be removed. Channel `cli` or
    /// `web_ui`, result `removed`. Carries `credential_fingerprint`
    /// and `passkey_count` (the count after removal), never the
    /// credential id or public key. Appended before the store
    /// changes; a failed append removes nothing (REQ-APR-005,
    /// REQ-AUD-003).
    PasskeyRemoved,
    /// REQ-OAU-002 (#229): an authorize request's client was refused
    /// at admission — not on the `[oauth] clients` allow-list, its
    /// CIMD could not be fetched, the document was invalid, or the
    /// requested `redirect_uri` is not one of the document's. No
    /// `agent_id`; `origin` is the client's CIMD hostname and
    /// `detail_code` is one of `not_allowlisted`, `cimd_unavailable`,
    /// `cimd_invalid` or `redirect_mismatch` (SPEC §7, #226 I7).
    /// Best effort, like [`Event::ConnectorAuthFail`]: a failed
    /// append never turns the refusal into an admission.
    OauthClientRefused,
}

impl Event {
    /// The wire name (`grant_revoke`, `fill_dispatch`, ...).
    pub fn as_str(&self) -> &'static str {
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
            Event::FillTimeout => "fill_timeout",
            Event::FillDispatch => "fill_dispatch",
            Event::FillAborted => "fill_aborted",
            Event::ContextOpen => "context_open",
            Event::Context => "context",
            Event::ClockSkew => "clock_skew",
            Event::LogTruncated => "log_truncated",
            Event::ConnectorAuthFail => "connector_auth_fail",
            Event::ConnectorReplaced => "connector_replaced",
            Event::PasskeyEnrollCode => "passkey_enroll_code",
            Event::PasskeyEnrolled => "passkey_enrolled",
            Event::PasskeyListed => "passkey_listed",
            Event::PasskeyRemoved => "passkey_removed",
            Event::OauthClientRefused => "oauth_client_refused",
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
            "fill_timeout" => Event::FillTimeout,
            "fill_dispatch" => Event::FillDispatch,
            "fill_aborted" => Event::FillAborted,
            "context_open" => Event::ContextOpen,
            "context" => Event::Context,
            "clock_skew" => Event::ClockSkew,
            "log_truncated" => Event::LogTruncated,
            "connector_auth_fail" => Event::ConnectorAuthFail,
            "connector_replaced" => Event::ConnectorReplaced,
            "passkey_enroll_code" => Event::PasskeyEnrollCode,
            "passkey_enrolled" => Event::PasskeyEnrolled,
            "passkey_listed" => Event::PasskeyListed,
            "passkey_removed" => Event::PasskeyRemoved,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown audit event `{other}`"
                )));
            }
        })
    }
}

/// How a connector session reached the broker (#199). Serialized as
/// `"tls"` / `"ws"`; `Display` prints the same text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionTransport {
    /// The raw pinned-TLS listener (`[connector].listen`).
    Tls,
    /// A WebSocket on `[public_ingress]` (`GET /connector`, #199).
    Ws,
}

impl std::fmt::Display for SessionTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tls => "tls",
            Self::Ws => "ws",
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
    /// Hex SHA-256 of the loaded export file (only on `ExportLoaded`,
    /// REQ-EXP-004: replacing the file and restarting produces a new
    /// `export_loaded` entry whose hash differs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    /// Broker-generated random id tying a `fill_dispatch` to its single
    /// outcome entry (REQ-AUD-003†). Not a secret and not agent-supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Number of fields a `fill_dispatch` is about to fill (1..=3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_count: Option<u64>,
    /// The target's live origin as the browser reported it during the
    /// fill (only on fill outcome entries: `fill`, `fill_totp`,
    /// `fill_timeout`, `fill_aborted`; REQ-AUD-003†, #67). Absent when
    /// the fill never got that far. `origin` on `fill_dispatch` is the
    /// agent's claim; this is the evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_origin: Option<String>,
    /// How a connector session reached the broker: `tls` or `ws` (only on
    /// `connector_auth_fail` / `connector_replaced`, #199).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<SessionTransport>,
    /// Effective client address of the call that produced this entry
    /// (only on agent-call entries written by a network transport,
    /// #200). On `[public_ingress]` it is the `CF-Connecting-IP`
    /// address — audit is one of its two sanctioned uses (see
    /// `api::public::client_ip`); on `[api]`, the connection peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Events of this kind and agent dropped by the rate limiter since the
    /// previous entry (only on the connector events, #199).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<u64>,
    /// Age in whole seconds of the session a `connector_replaced` evicted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_session_secs: Option<u64>,
    /// Fingerprint of the agent's `token_hash` (the Argon2id PHC string)
    /// at revoke time: SHA-256 of the PHC string, hex, truncated to 32
    /// chars (only on `token_revoke`, #132). The startup rebuild
    /// (REQ-REV-001) revokes the agent only while the configured hash
    /// still fingerprints the same; rotating the hash lifts it. The PHC
    /// string carries a random salt and already sits in the config file,
    /// so the fingerprint exposes nothing usable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_fingerprint: Option<String>,
    /// Fingerprint of a passkey's credential id (`passkey_enrolled`
    /// and `passkey_removed`, #249, #258): SHA-256 of the raw id,
    /// lowercase hex, truncated to 32 chars — the same shape as
    /// `token_fingerprint`. The id itself is never stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprint: Option<String>,
    /// Every fingerprint a `passkey_listed` entry names (#258), in
    /// list order. Each element is a `credential_fingerprint`. Absent
    /// when the store was empty. Never credential ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprints: Option<Vec<String>>,
    /// Enrolled passkeys after the store this entry records
    /// (`passkey_enrolled`, `passkey_listed`, `passkey_removed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_count: Option<u64>,
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
            file_sha256: None,
            request_id: None,
            field_count: None,
            live_origin: None,
            transport: None,
            client_ip: None,
            suppressed: None,
            old_session_secs: None,
            token_fingerprint: None,
            credential_fingerprint: None,
            credential_fingerprints: None,
            passkey_count: None,
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

    /// Hex SHA-256 of the loaded export file (only set on
    /// `Event::ExportLoaded` entries, REQ-EXP-004).
    pub fn file_sha256(mut self, v: impl Into<String>) -> Self {
        self.file_sha256 = Some(v.into());
        self
    }

    /// The broker's id for one fill request (REQ-AUD-003†).
    pub fn request_id(mut self, v: impl Into<String>) -> Self {
        self.request_id = Some(v.into());
        self
    }

    /// Fields a `fill_dispatch` is about to fill.
    pub fn field_count(mut self, v: u64) -> Self {
        self.field_count = Some(v);
        self
    }

    /// The live origin a fill observed (outcome entries, #67).
    pub fn live_origin(mut self, v: impl Into<String>) -> Self {
        self.live_origin = Some(v.into());
        self
    }

    /// The connector transport (`tls` or `ws`).
    pub fn transport(mut self, v: SessionTransport) -> Self {
        self.transport = Some(v);
        self
    }

    pub fn client_ip(mut self, v: impl Into<String>) -> Self {
        self.client_ip = Some(v.into());
        self
    }

    /// Connector events dropped by the rate limiter since the last entry.
    pub fn suppressed(mut self, v: u64) -> Self {
        self.suppressed = Some(v);
        self
    }

    /// Age in seconds of the session a `connector_replaced` evicted.
    pub fn old_session_secs(mut self, v: u64) -> Self {
        self.old_session_secs = Some(v);
        self
    }

    /// Fingerprint of the revoked token's `token_hash` (only on
    /// `token_revoke`, #132).
    pub fn token_fingerprint(mut self, v: impl Into<String>) -> Self {
        self.token_fingerprint = Some(v.into());
        self
    }

    /// Fingerprint of one passkey's credential id (`passkey_enrolled`,
    /// `passkey_removed`).
    pub fn credential_fingerprint(mut self, v: impl Into<String>) -> Self {
        self.credential_fingerprint = Some(v.into());
        self
    }

    /// Fingerprints a `passkey_listed` entry names (#258).
    pub fn credential_fingerprints(mut self, v: Vec<String>) -> Self {
        self.credential_fingerprints = Some(v);
        self
    }

    /// Enrolled passkeys after the step this entry records.
    pub fn passkey_count(mut self, v: u64) -> Self {
        self.passkey_count = Some(v);
        self
    }

    /// Machine-readable detail code. Never interpolate values here
    /// (REQ-API-006 applies to everything the daemon emits).
    pub fn detail_code(mut self, v: impl Into<String>) -> Self {
        self.detail_code = Some(v.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #67: `live_origin` serializes only when set, so entries written
    /// before it existed hash and verify unchanged.
    #[test]
    fn live_origin_is_omitted_when_unset() {
        let e = Entry::new(Event::Fill).result("filled");
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("live_origin").is_none());
        let e = e.live_origin("https://login.example.com");
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["live_origin"], "https://login.example.com");
        let back: Entry = serde_json::from_value(v).unwrap();
        assert_eq!(
            back.live_origin.as_deref(),
            Some("https://login.example.com")
        );
    }

    /// #249: the passkey fields stay off every other event, and a
    /// `passkey_enrolled` entry round-trips its fingerprint and count.
    #[test]
    fn passkey_enrollment_fields_are_omitted_when_unset() {
        let e = Entry::new(Event::PasskeyEnrollCode)
            .channel("cli")
            .result("minted");
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["event"], "passkey_enroll_code");
        assert!(v.get("credential_fingerprint").is_none());
        assert!(v.get("passkey_count").is_none());
        let fp = "ab".repeat(16);
        let e = Entry::new(Event::PasskeyEnrolled)
            .channel("web_ui")
            .result("enrolled")
            .credential_fingerprint(fp.clone())
            .passkey_count(2);
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["credential_fingerprint"], fp);
        assert_eq!(v["passkey_count"], 2);
        let back: Entry = serde_json::from_value(v).unwrap();
        assert_eq!(back.credential_fingerprint.as_deref(), Some(fp.as_str()));
        assert_eq!(back.passkey_count, Some(2));
    }

    /// #258: a list entry carries every fingerprint and nothing else
    /// about the passkey; a remove entry carries the one fingerprint.
    #[test]
    fn passkey_list_and_remove_fields_round_trip() {
        let bare = Entry::new(Event::PasskeyListed)
            .channel("cli")
            .result("listed")
            .passkey_count(0);
        let v = serde_json::to_value(&bare).unwrap();
        assert_eq!(v["event"], "passkey_listed");
        assert!(v.get("credential_fingerprint").is_none());
        assert!(v.get("credential_fingerprints").is_none());
        assert_eq!(v["passkey_count"], 0);
        let fps = vec!["ab".repeat(16), "cd".repeat(16)];
        let listed = Entry::new(Event::PasskeyListed)
            .channel("web_ui")
            .result("listed")
            .credential_fingerprints(fps.clone())
            .passkey_count(2);
        let v = serde_json::to_value(&listed).unwrap();
        assert_eq!(v["credential_fingerprints"], serde_json::json!(fps));
        let back: Entry = serde_json::from_value(v).unwrap();
        assert_eq!(back.credential_fingerprints, Some(fps));
        let removed = Entry::new(Event::PasskeyRemoved)
            .channel("cli")
            .result("removed")
            .credential_fingerprint("ef".repeat(16))
            .passkey_count(1);
        let v = serde_json::to_value(&removed).unwrap();
        assert!(v.get("credential_fingerprints").is_none());
        assert_eq!(v["credential_fingerprint"], "ef".repeat(16));
        assert_eq!(v["result"], "removed");
    }
}
