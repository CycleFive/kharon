//! The owner web UI's approvals queue (#131 slice 1; SPEC §5's web UI
//! channel, REQ-APR-005).
//!
//! The UI decides requests through the same broker calls the CLI
//! uses: [`Broker::approve_grant_request`] and
//! [`Broker::deny_grant_request`], on [`Channel::WebUi`]. Both run the
//! REQ-APR-003 expiry pass first (#130), so a request past its 120 s
//! timeout is denied as a timeout and the owner's decision fails
//! closed as [`DecideError::NotPending`]. The UI adds no grant logic
//! of its own.

use crate::api::Broker;
use crate::api::VaultView;
use crate::api::grant::{Channel, GrantError, GrantTerms};
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
    /// The item the fill wants.
    pub item_id: String,
    /// `fill` or `totp`.
    pub action: &'static str,
    /// The live origin observed at request time (REQ-APR-007).
    pub origin: String,
    /// Seconds since the request was created.
    pub age_s: u64,
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
}
