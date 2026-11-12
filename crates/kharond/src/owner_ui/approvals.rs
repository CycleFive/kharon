//! The owner web UI's approvals queue (#131 slice 1), grants list
//! (#131 slice 2), panic button (#131 slice 3) and audit tail
//! (#131 slice 4; SPEC §5's web UI channel, REQ-APR-005,
//! REQ-REV-001, REQ-REV-002; the audit tail is SPEC §5 "audit
//! tail", §7).
//!
//! The UI decides requests through the same broker calls the CLI
//! uses: [`Broker::approve_grant_request`] and
//! [`Broker::deny_grant_request`], on [`Channel::WebUi`]. Both run the
//! REQ-APR-003 expiry pass first (#130), so a request past its 120 s
//! timeout is denied as a timeout and the owner's decision fails
//! closed as [`DecideError::NotPending`]. A revoke is the owner
//! socket's [`Broker::revoke_grant`], on the same channel. A panic is
//! [`Broker::panic_lock`], the `kharon panic` primitive itself. The UI
//! adds no grant logic of its own. The audit tail is read-only: the
//! last [`AUDIT_TAIL_LEN`] durable entries from the log's in-memory
//! tail, projected to [`AuditRow`].
//!
//! The Connections page (#233) is the same shape: the list is the
//! broker's live Connect identities, Disconnect is
//! [`Broker::disconnect_connect`] and Unsuspend is
//! [`Broker::unsuspend_agent`]. Rows that name an agent — pending,
//! grants, audit — carry the Connect's `client_name` alongside the
//! id (D9), resolved through the broker's OAuth store.

use crate::api::Broker;
use crate::api::VaultView;
use crate::api::grant::{Channel, GrantError, GrantTerms, GrantView};
use crate::audit::Entry;
use crate::config::GrantKind;
use crate::lock::Clock;

/// One row of the pending queue. Metadata only: no secret field is
/// decrypted for a pending request (REQ-APR-001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRow {
    /// The request to decide (`gr_…`).
    pub request_id: String,
    /// The requesting agent.
    pub agent_id: String,
    /// The display name when the agent is a Connect: its
    /// `client_name` (D9, #233). The page names the Connect by it
    /// and falls back to the raw id. `None` for config agents.
    pub agent_name: Option<String>,
    /// The item the fill wants.
    pub item_id: String,
    /// `fill` or `totp`.
    pub action: &'static str,
    /// The live origin observed at request time (REQ-APR-007).
    pub origin: String,
    /// Seconds since the request was created.
    pub age_s: u64,
}

/// How many audit entries the web UI shows, newest first.
pub const AUDIT_TAIL_LEN: usize = 50;

/// One row of the audit tail: a typed projection of an [`Entry`]
/// (SPEC §7). It carries what an owner reads a tail for (who, what,
/// where, how it ended) and drops the rest: no item name in either
/// form (REQ-AUD-004 hashes it by default, and a plaintext name is a
/// choice made for the log file, not for a browser page), no chain
/// hashes and no `log_id`. Absent fields are omitted, as in the log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditRow {
    pub seq: u64,
    /// RFC 3339, as written.
    pub ts: String,
    /// The event's wire name (`grant_revoke`, `fill`, ...).
    pub event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// The `client_name` when `agent_id` is a Connect identity
    /// (D9, #233), filled by the broker's `audit_tail`, not by the
    /// projection: an entry alone does not know the name. The audit
    /// view names the Connect by it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl From<&Entry> for AuditRow {
    fn from(e: &Entry) -> Self {
        Self {
            seq: e.seq,
            ts: e.ts.clone(),
            event: e.event.as_str(),
            agent_id: e.agent_id.clone(),
            agent_name: None,
            item_id: e.item_id.clone(),
            origin: e.origin.clone(),
            live_origin: e.live_origin.clone(),
            grant_id: e.grant_id.clone(),
            channel: e.channel.clone(),
            result: e.result.clone(),
            detail_code: e.detail_code.clone(),
            request_id: e.request_id.clone(),
        }
    }
}

/// One row of the Connections page (#233, D3): a live Connect
/// identity as the owner reads it. Metadata only — the state file
/// holds token hashes, and no hash is projected here either.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ConnectionRow {
    /// The `c-…` identity.
    pub agent_id: String,
    /// The `client_name` as shown at consent.
    pub client_name: String,
    /// The CIMD hostname (the `client_id` URL's host), when it
    /// parses. The same host the identity's audit entries name as
    /// `origin` (I7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// RFC 3339, when the identity was created (code redemption).
    pub connected_at: String,
    /// How the Connect arrived (`oauth`, D3).
    pub channel: String,
    /// REQ-RL-002 suspension in force: the page offers Unsuspend.
    pub suspended: bool,
}

/// One row of the grants list: the grant's status view, plus the
/// display name of its agent when the agent is a Connect (D9,
/// #233). Flattened, so the wire shape is the view's own fields
/// plus `agent_name` when present.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GrantRow {
    #[serde(flatten)]
    pub view: GrantView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

/// The grant kinds the web UI can approve. `standing` stays with the
/// CLI in this slice: it needs a config flag and explicit TTL terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebGrantKind {
    /// SPEC §5 default: 120 s, one use.
    Once,
    /// The kind default TTL (1 h).
    PerOrigin,
}

impl WebGrantKind {
    /// Parse the wire string. The spelling matches the CLI's
    /// `--kind` (`once`, `per-origin`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "once" => Some(Self::Once),
            "per-origin" => Some(Self::PerOrigin),
            _ => None,
        }
    }

    fn grant_kind(self) -> GrantKind {
        match self {
            Self::Once => GrantKind::Once,
            Self::PerOrigin => GrantKind::PerOrigin,
        }
    }
}

/// Why a web decision was refused. Each maps to one fixed error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecideError {
    /// No request with that id.
    NotFound,
    /// Already decided, timed out, or born `origin_mismatch`.
    NotPending,
    /// The terms were refused.
    InvalidTerms,
    /// The audit append failed; nothing changed (REQ-AUD-003).
    AuditFailed,
}

impl DecideError {
    /// The fixed wire code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotPending => "not_pending",
            Self::InvalidTerms => "invalid_terms",
            Self::AuditFailed => "audit_failed",
        }
    }
}

impl From<GrantError> for DecideError {
    fn from(e: GrantError) -> Self {
        match e {
            GrantError::NotFound => Self::NotFound,
            GrantError::NotPending => Self::NotPending,
            GrantError::StandingDisabled | GrantError::InvalidTerms(_) => Self::InvalidTerms,
            GrantError::AuditFailed => Self::AuditFailed,
        }
    }
}

/// Broker calls behind the approvals routes. [`Broker`] implements
/// this; the UI calls it on a blocking thread (the calls append
/// audit entries).
pub trait OwnerApprovals: Send + Sync + 'static {
    /// The pending queue, oldest first. Aged requests are expired
    /// before the list is taken.
    fn pending(&self) -> Vec<PendingRow>;

    /// Approve `request_id` for its own item with `kind`'s default
    /// terms. Returns the issued grant's id.
    fn approve(&self, request_id: &str, kind: WebGrantKind) -> Result<String, DecideError>;

    /// Deny `request_id`.
    fn deny(&self, request_id: &str) -> Result<(), DecideError>;

    /// Every live grant, across agents, oldest first (#131 slice 2).
    /// Default: none.
    fn grants(&self) -> Vec<GrantRow> {
        Vec::new()
    }

    /// The live Connect identities for the Connections page (#233,
    /// D3), in creation order. Default: none.
    fn connections(&self) -> Vec<ConnectionRow> {
        Vec::new()
    }

    /// Disconnect a Connect identity (REQ-OAU-005, #233): the
    /// identity, its tokens and its live grants end at once.
    /// [`DecideError::NotFound`] when no live Connect has that id.
    /// Default: no Connect is ever found.
    fn disconnect(&self, agent_id: &str) -> Result<(), DecideError> {
        let _ = agent_id;
        Err(DecideError::NotFound)
    }

    /// Clear an agent's suspension from the Connections page
    /// (REQ-RL-002 owner reset, #233): the broker's own
    /// `unsuspend_agent`, the socket op's other face. Default:
    /// refused, like [`Self::panic`], so a backend without the
    /// slice cannot silently report a reset that never happened.
    fn unsuspend(&self, agent_id: &str) -> Result<(), DecideError> {
        let _ = agent_id;
        Err(DecideError::AuditFailed)
    }

    /// Revoke `grant_id` (REQ-REV-001). [`DecideError::NotFound`] when
    /// there is no such grant. Default: no grant is ever found.
    fn revoke(&self, grant_id: &str) -> Result<(), DecideError> {
        let _ = grant_id;
        Err(DecideError::NotFound)
    }

    /// The last [`AUDIT_TAIL_LEN`] audit entries, newest first (#131
    /// slice 4). Default: none.
    fn audit_tail(&self) -> Vec<AuditRow> {
        Vec::new()
    }

    /// Panic (REQ-REV-002): revoke every grant, then lock. The one
    /// `panic` audit entry is the lock's, written by the lock sink —
    /// the broker appends no second one (REQ-AUD-003). Default:
    /// refused, so a backend without the slice cannot silently
    /// report a panic that never happened.
    fn panic(&self) -> Result<(), DecideError> {
        Err(DecideError::AuditFailed)
    }
}

/// No approvals backend: an empty queue, and every decision is
/// `not_found`. For tests and for a UI built without a broker.
pub struct NoApprovals;

impl OwnerApprovals for NoApprovals {
    fn pending(&self) -> Vec<PendingRow> {
        Vec::new()
    }

    fn approve(&self, _request_id: &str, _kind: WebGrantKind) -> Result<String, DecideError> {
        Err(DecideError::NotFound)
    }

    fn deny(&self, _request_id: &str) -> Result<(), DecideError> {
        Err(DecideError::NotFound)
    }
}

impl<S, C> OwnerApprovals for Broker<S, C>
where
    S: VaultView + 'static,
    C: Clock + 'static,
{
    fn pending(&self) -> Vec<PendingRow> {
        let now = self.grant_now();
        let mut rows: Vec<(std::time::Duration, PendingRow)> = self
            .pending_grant_requests()
            .iter()
            .filter_map(|r| {
                let prompt = r.prompt()?;
                Some((
                    r.created_at,
                    PendingRow {
                        request_id: prompt.request_id,
                        agent_name: self.connect_client_name(&prompt.agent_id),
                        agent_id: prompt.agent_id,
                        item_id: prompt.item_id,
                        action: prompt.action.as_str(),
                        origin: prompt.origin,
                        age_s: now.saturating_sub(r.created_at).as_secs(),
                    },
                ))
            })
            .collect();
        rows.sort_by_key(|(created, _)| *created);
        rows.into_iter().map(|(_, row)| row).collect()
    }

    fn approve(&self, request_id: &str, kind: WebGrantKind) -> Result<String, DecideError> {
        // The CLI's default scope: the request's own item.
        let req = self
            .grant_request(request_id)
            .ok_or(DecideError::NotFound)?;
        let terms = GrantTerms {
            kind: kind.grant_kind(),
            ..GrantTerms::once_item(req.item_id)
        };
        self.approve_grant_request(request_id, &terms, Channel::WebUi)
            .map(|view| view.id)
            .map_err(DecideError::from)
    }

    fn deny(&self, request_id: &str) -> Result<(), DecideError> {
        self.deny_grant_request(request_id, Channel::WebUi)
            .map(|_| ())
            .map_err(DecideError::from)
    }

    fn grants(&self) -> Vec<GrantRow> {
        self.live_grants()
            .into_iter()
            .map(|view| {
                let agent_name = self.connect_client_name(&view.agent_id);
                GrantRow { view, agent_name }
            })
            .collect()
    }

    fn connections(&self) -> Vec<ConnectionRow> {
        self.connect_identities()
            .into_iter()
            .map(|identity| ConnectionRow {
                suspended: self.agent_suspended(&identity.id),
                host: identity.audit_origin(),
                connected_at: rfc3339_unix(identity.created_at),
                channel: identity.connected_via.clone(),
                agent_id: identity.id,
                client_name: identity.client_name,
                scopes: identity.scopes,
            })
            .collect()
    }

    fn disconnect(&self, agent_id: &str) -> Result<(), DecideError> {
        match self.disconnect_connect(agent_id) {
            Ok(true) => Ok(()),
            Ok(false) => Err(DecideError::NotFound),
            Err(e) => Err(DecideError::from(e)),
        }
    }

    fn unsuspend(&self, agent_id: &str) -> Result<(), DecideError> {
        self.unsuspend_agent(agent_id).map_err(DecideError::from)
    }

    fn revoke(&self, grant_id: &str) -> Result<(), DecideError> {
        match self.revoke_grant(grant_id, Channel::WebUi) {
            Ok(true) => Ok(()),
            Ok(false) => Err(DecideError::NotFound),
            Err(e) => Err(DecideError::from(e)),
        }
    }

    fn audit_tail(&self) -> Vec<AuditRow> {
        self.recent_audit(AUDIT_TAIL_LEN)
            .iter()
            .map(|e| {
                let mut row = AuditRow::from(e);
                row.agent_name = row
                    .agent_id
                    .as_deref()
                    .and_then(|id| self.connect_client_name(id));
                row
            })
            .collect()
    }

    fn panic(&self) -> Result<(), DecideError> {
        // The same primitive the owner socket's `panic` op and the
        // ntfy action reach. Its per-grant `grant_revoke` entries
        // are revoke-first (#135): a failed append never restores a
        // grant, and the lock proceeds — the closed state is the
        // safe one.
        self.panic_lock().map_err(DecideError::from)
    }
}

/// Format unix seconds as RFC 3339 UTC, the shape the grants list
/// already uses for expiries. A value `time` cannot represent
/// (never, for a stored `created_at`) renders empty rather than
/// failing the page.
fn rfc3339_unix(secs: u64) -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    i64::try_from(secs)
        .ok()
        .and_then(|s| OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}
