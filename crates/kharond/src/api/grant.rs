//! Grant model and request lifecycle (SPEC §5; issue #20).
//!
//! A [`Grant`] is the owner's permission for one agent to run one
//! action (`fill` / `totp`) on one item (or every item of one
//! collection) at one origin, bounded by a TTL and a use count
//! (REQ-APR-002). A fill with no matching live grant does not decrypt
//! anything (REQ-APR-001): it creates a [`GrantRequest`] and reports
//! `pending_approval`. The owner approves or denies the request
//! through an approval channel (SPEC §5; the channels themselves are
//! issues #16/#17 — this module is the model they act on, exposed on
//! the [`Broker`](super::Broker) as `approve_grant_request` /
//! `deny_grant_request`). Approval issues a grant whose terms the
//! owner picks: a [`GrantKind`] default plus explicit overrides.
//!
//! A request carries two origins (REQ-APR-007): the agent's claim
//! (`expected_origin`) and the **live origin the broker observed** in
//! the agent's own browser at request time (through
//! [`FillBackend::observe_origin`](super::fill::FillBackend::observe_origin),
//! never from agent input — REQ-ORG-002's rule applied to prompts).
//! If they differ, the request is `origin_mismatch` from birth: it is
//! never pending, and no prompt is ever built for it. The approval
//! prompt ([`GrantRequest::prompt`]) shows the observed origin only.
//!
//! Requests deny themselves (REQ-APR-003): a request still pending
//! [`REQUEST_TIMEOUT`] after creation becomes `denied` on the next
//! expiry pass ([`GrantStore::expire`], driven by
//! [`Broker::expire_grant_requests`](super::Broker::expire_grant_requests)
//! and at the head of every fill / grant request), and the broker
//! audits the transition. Defaults deny: nothing in this module ever
//! approves on its own.
//!
//! Time is the broker's injected [`Clock`](crate::lock::Clock)
//! reading (a monotonic [`Duration`]), passed into every store
//! method, so tests drive TTLs and the request timeout with the same
//! `ManualClock` as the lock timers. [`GrantView::expires_at`] is the
//! one wall-clock rendering: the remaining TTL added to the current
//! system time at read time.
//!
//! Grants are memory-only (SPEC §5 has no persistence requirement;
//! a restart is a lock, and REQ-MEM-007 already makes grants inert
//! while locked — the daemon's store starts empty at boot and is
//! dropped with the process). Grant *use* is consumed at admission:
//! a fill admitted under a grant spends one use even if the browser
//! side then fails, so a flaky page cannot launder extra fills out
//! of a `once` grant.

use std::collections::BTreeSet;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

use super::error::{ApiError, Detail};
use super::fill::{MAX_GRANT_ID_LEN, MAX_TARGET_ID_LEN};
use crate::config::GrantKind;
use crate::origin::registrable_domain;

/// How long a request stays pending before it denies itself
/// (SPEC §5: "Requests time out after 120 s").
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// `once` grant TTL (SPEC §5).
pub const ONCE_TTL: Duration = Duration::from_secs(120);
/// `per-origin` grant default TTL (SPEC §5: 1 h, max 24 h).
pub const PER_ORIGIN_TTL: Duration = Duration::from_secs(60 * 60);
/// `per-origin` grant maximum TTL (SPEC §5).
pub const PER_ORIGIN_MAX_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// `standing` grant maximum TTL (SPEC §5: max 30 d). Also the default
/// when the owner approves a standing grant without naming a TTL:
/// the terms are still bounded by the cap, and a shorter TTL is one
/// field away at the channel.
pub const STANDING_MAX_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Longest accepted grant-request `item_id` (a canonical UUID).
const ITEM_ID_LEN: usize = 36;

/// The action a grant covers: one element of SPEC §5's
/// `actions ⊆ {fill, totp}`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GrantAction {
    /// `kharon_fill` / `POST /v1/fill`.
    Fill,
    /// `kharon_fill_totp` / `POST /v1/fill_totp`.
    Totp,
}

impl GrantAction {
    /// Wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fill => "fill",
            Self::Totp => "totp",
        }
    }
}

/// What a grant is scoped to (SPEC §5's `item_id|*collection`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantScope {
    /// One item, by id.
    Item(String),
    /// Every item in one collection, by collection id.
    Collection(String),
}

impl GrantScope {
    /// Whether an item (id plus the collections it sits in) is in
    /// scope. Ids compare case-insensitively (UUIDs are compared
    /// lowercase everywhere else in the broker).
    pub fn covers(&self, item_id: &str, item_collections: &[String]) -> bool {
        match self {
            Self::Item(id) => id.eq_ignore_ascii_case(item_id),
            Self::Collection(id) => item_collections.iter().any(|c| c.eq_ignore_ascii_case(id)),
        }
    }
}

/// The owner channel a grant was created through (SPEC §5's
/// `created_by_channel`). The channels land in #16/#17; the model
/// records which one acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// `kharon approve` over the owner socket.
    Cli,
    /// The owner web UI (WebAuthn).
    WebUi,
    /// An ntfy approve action.
    Ntfy,
}

impl Channel {
    /// Wire / audit string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::WebUi => "web_ui",
            Self::Ntfy => "ntfy",
        }
    }
}

/// The terms an owner approves a request with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantTerms {
    /// Item or collection scope.
    pub scope: GrantScope,
    /// Grant type (drives the defaults and caps below).
    pub kind: GrantKind,
    /// TTL override. `None`: the kind default (`once` 120 s,
    /// `per-origin` 1 h, `standing` 30 d). Capped per kind at
    /// approval: an over-cap TTL is refused, never silently clamped.
    pub ttl: Option<Duration>,
    /// Use-count override. `None`: the kind default (`once` 1,
    /// others unlimited). `Some(0)` is refused (a grant that can
    /// never be used is a typo, not a policy).
    pub max_uses: Option<u64>,
}

impl GrantTerms {
    /// `once` terms for one item (the SPEC §5 default grant).
    pub fn once_item(item_id: impl Into<String>) -> Self {
        Self {
            scope: GrantScope::Item(item_id.into()),
            kind: GrantKind::Once,
            ttl: None,
            max_uses: None,
        }
    }

    /// Resolve to `(expires_at, max_uses)` for a grant created at
    /// `now`, or refuse terms SPEC §5 does not allow.
    fn resolve(
        &self,
        now: Duration,
        allow_standing: bool,
    ) -> Result<(Duration, Option<u64>), GrantError> {
        let (default_ttl, max_ttl, default_uses) = match self.kind {
            GrantKind::Once => (ONCE_TTL, ONCE_TTL, Some(1)),
            GrantKind::PerOrigin => (PER_ORIGIN_TTL, PER_ORIGIN_MAX_TTL, None),
            GrantKind::Standing => {
                if !allow_standing {
                    return Err(GrantError::StandingDisabled);
                }
                (STANDING_MAX_TTL, STANDING_MAX_TTL, None)
            }
        };
        let ttl = self.ttl.unwrap_or(default_ttl);
        if ttl.is_zero() || ttl > max_ttl {
            return Err(GrantError::InvalidTerms("ttl_out_of_range"));
        }
        let max_uses = match self.max_uses {
            Some(0) => return Err(GrantError::InvalidTerms("max_uses_zero")),
            Some(n) => Some(n),
            None => default_uses,
        };
        if self.kind == GrantKind::Once && max_uses != Some(1) {
            // A `once` grant with more than one use is a per-origin
            // grant wearing the wrong name; make the owner say so.
            return Err(GrantError::InvalidTerms("once_max_uses"));
        }
        Ok((now + ttl, max_uses))
    }
}

/// Why a grant operation was refused. Codes are fixed strings
/// (REQ-API-006's rule, applied to the owner surface too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// No request or grant with that id.
    #[error("no such grant request or grant")]
    NotFound,
    /// The request is not pending (already decided, or born
    /// `origin_mismatch`).
    #[error("grant request is not pending")]
    NotPending,
    /// `standing` terms while standing grants are disabled
    /// (SPEC §5: off by default, config flag required).
    #[error("standing grants are disabled")]
    StandingDisabled,
    /// Terms outside the kind's bounds; the code says which field.
    #[error("invalid grant terms: {0}")]
    InvalidTerms(&'static str),
    /// The audit append failed; the operation was refused
    /// (REQ-AUD-003 fail-closed).
    #[error("audit write failed; operation refused")]
    AuditFailed,
}

/// SPEC §5 `Grant`, as the store keeps it. Times are clock readings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// `g_…` id.
    pub id: String,
    /// The agent the grant belongs to.
    pub agent_id: String,
    /// Item or collection scope.
    pub scope: GrantScope,
    /// The granted origin: a host, or a registrable domain (then it
    /// covers its subdomains too — see [`origin_matches`]).
    pub origin: String,
    /// Actions the grant covers.
    pub actions: BTreeSet<GrantAction>,
    /// Clock reading the grant was created at.
    pub created_at: Duration,
    /// Clock reading the grant stops matching at.
    pub expires_at: Duration,
    /// Use cap; `None` is unlimited within the TTL.
    pub max_uses: Option<u64>,
    /// Uses spent (at admission; see the module docs).
    pub uses: u64,
    /// Grant type the owner approved.
    pub kind: GrantKind,
    /// Channel the approval came through.
    pub created_by_channel: Channel,
    /// The request this grant was issued from, if any.
    pub request_id: Option<String>,
}

impl Grant {
    /// Live at `now`: unexpired and with uses left.
    pub fn is_live(&self, now: Duration) -> bool {
        now < self.expires_at && self.max_uses.is_none_or(|max| self.uses < max)
    }

    /// REQ-APR-002 matching: every dimension must agree — agent,
    /// item (directly or through a collection), origin, action —
    /// and the grant must be live (TTL and `max_uses`).
    pub fn matches(
        &self,
        agent_id: &str,
        item_id: &str,
        item_collections: &[String],
        origin: &str,
        action: GrantAction,
        now: Duration,
    ) -> bool {
        self.agent_id == agent_id
            && self.scope.covers(item_id, item_collections)
            && self.actions.contains(&action)
            && origin_matches(&self.origin, origin)
            && self.is_live(now)
    }

    /// The status view (SPEC §4 `Grant`).
    pub fn view(&self, now: Duration) -> GrantView {
        let (item_id, collection_id) = match &self.scope {
            GrantScope::Item(id) => (Some(id.clone()), None),
            GrantScope::Collection(id) => (None, Some(id.clone())),
        };
        // Wall-clock rendering of the remaining TTL (see module docs).
        let remaining = self.expires_at.saturating_sub(now);
        let expires = (OffsetDateTime::now_utc() + remaining)
            .format(&Rfc3339)
            .unwrap_or_default();
        GrantView {
            id: self.id.clone(),
            agent_id: self.agent_id.clone(),
            item_id,
            collection_id,
            origin: self.origin.clone(),
            actions: self.actions.iter().copied().collect(),
            expires_at: expires,
            max_uses: self.max_uses,
            uses: self.uses,
            created_by_channel: self.created_by_channel,
        }
    }
}

/// SPEC §4 `Grant` as `kharon_status` reports it: one live grant of
/// the calling agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GrantView {
    /// `g_…` id.
    pub id: String,
    /// The agent the grant belongs to.
    pub agent_id: String,
    /// Item scope (exactly one of this and `collection_id` is set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    /// Collection scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<String>,
    /// The granted origin (host, or registrable domain covering its
    /// subdomains).
    pub origin: String,
    /// Actions covered.
    pub actions: Vec<GrantAction>,
    /// RFC 3339 expiry (remaining TTL from when the status was read).
    pub expires_at: String,
    /// Use cap; absent is unlimited within the TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
    /// Uses spent.
    pub uses: u64,
    /// Channel the approval came through.
    pub created_by_channel: Channel,
}

/// Whether a fill at `fill_origin` (a serialized origin or URL, as
/// the agent claims it and the item's URIs state it) is inside a
/// grant's `grant_origin` (a host, a serialized origin, or a
/// registrable domain).
///
/// The comparison is on hosts: equal hosts match; a grant naming the
/// fill host's registrable domain (eTLD+1, per the vendored PSL)
/// also matches its subdomains. A grant naming anything else — a
/// deeper subdomain, a public suffix, another domain — does not.
/// The grant check never widens the fill: the in-page origin check
/// (REQ-ORG-*) still decides against the live tab afterwards.
pub fn origin_matches(grant_origin: &str, fill_origin: &str) -> bool {
    let Some(host) = host_of(fill_origin) else {
        return false;
    };
    let grant_host = host_of(grant_origin).unwrap_or_else(|| grant_origin.to_ascii_lowercase());
    if grant_host == host {
        return true;
    }
    registrable_domain(&host).is_some_and(|d| d == grant_host)
}

/// The lowercase host of a URL or serialized origin; `None` if the
/// string does not parse as an absolute URL with a host.
fn host_of(s: &str) -> Option<String> {
    Url::parse(s).ok()?.host_str().map(str::to_ascii_lowercase)
}

/// The serialized origin (`scheme://host[:port]`, `null` for opaque)
/// of a URL — the form live origins and claims are compared in
/// (REQ-APR-007). An unparsable string serializes to itself, so it
/// can only ever equal an identical claim.
pub fn serialized_origin(url: &str) -> String {
    match Url::parse(url) {
        Ok(u) => u.origin().ascii_serialization(),
        Err(_) => url.to_owned(),
    }
}

/// A grant request's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// Waiting on the owner.
    Pending,
    /// The owner approved; a grant was issued.
    Approved,
    /// The owner denied, or the request timed out (REQ-APR-003).
    Denied,
    /// Born refused: the observed live origin differed from the
    /// agent's claim, so no prompt was ever shown (REQ-APR-007).
    OriginMismatch,
}

impl RequestState {
    /// Wire string (the `state` of SPEC §4's `{grant_request_id,
    /// state}` and of [`GrantRequestBody`]).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::OriginMismatch => "origin_mismatch",
        }
    }
}

/// One request for a grant (SPEC §5 `GrantRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    /// `gr_…` id.
    pub id: String,
    /// The requesting agent.
    pub agent_id: String,
    /// The item the fill wants.
    pub item_id: String,
    /// The action the fill wants to run.
    pub action: GrantAction,
    /// The origin the agent claimed (`expected_origin`).
    pub claimed_origin: String,
    /// The live origin the broker observed in the agent's browser at
    /// request time. The prompt shows this one (REQ-APR-007).
    pub observed_origin: String,
    /// Lifecycle state.
    pub state: RequestState,
    /// Clock reading the request was created at.
    pub created_at: Duration,
    /// The grant approval issued, once approved.
    pub grant_id: Option<String>,
}

/// What an approval channel shows the owner (ntfy message, web UI
/// row, CLI listing — #16/#17 render this). Built only for pending
/// requests, and its origin is the **observed** one (REQ-APR-007):
/// a request whose tab was not where the agent claimed has no
/// prompt at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPrompt {
    /// The request to decide.
    pub request_id: String,
    /// The requesting agent.
    pub agent_id: String,
    /// The item the fill wants.
    pub item_id: String,
    /// The action the fill wants to run.
    pub action: GrantAction,
    /// The live origin observed at request time.
    pub origin: String,
}

impl GrantRequest {
    /// The approval prompt for this request, or `None` once it has
    /// left `pending` — including `origin_mismatch` requests, which
    /// are refused before prompting (REQ-APR-007).
    pub fn prompt(&self) -> Option<ApprovalPrompt> {
        (self.state == RequestState::Pending).then(|| ApprovalPrompt {
            request_id: self.id.clone(),
            agent_id: self.agent_id.clone(),
            item_id: self.item_id.clone(),
            action: self.action,
            origin: self.observed_origin.clone(),
        })
    }
}

/// The grants and requests the broker holds. Pure state: every
/// method takes the clock reading, and the broker owns the audit
/// side effects of the transitions it drives.
#[derive(Debug, Default)]
pub struct GrantStore {
    grants: Vec<Grant>,
    requests: Vec<GrantRequest>,
    allow_standing: bool,
}

impl GrantStore {
    /// An empty store. `allow_standing` is `[policy] allow_standing`
    /// (SPEC §5: standing grants are off by default).
    pub fn new(allow_standing: bool) -> Self {
        Self {
            grants: Vec::new(),
            requests: Vec::new(),
            allow_standing,
        }
    }

    /// Whether standing grants may be issued.
    pub fn allow_standing(&self) -> bool {
        self.allow_standing
    }

    /// Set whether standing grants may be issued (the broker's
    /// policy builder; the store is not yet shared at that point).
    pub fn set_allow_standing(&mut self, allow: bool) {
        self.allow_standing = allow;
    }

    /// The live grant matching every dimension of a fill
    /// (REQ-APR-002), if one exists.
    pub fn matching_grant(
        &self,
        agent_id: &str,
        item_id: &str,
        item_collections: &[String],
        origin: &str,
        action: GrantAction,
        now: Duration,
    ) -> Option<&Grant> {
        self.grants
            .iter()
            .find(|g| g.matches(agent_id, item_id, item_collections, origin, action, now))
    }

    /// A grant by id.
    pub fn grant(&self, grant_id: &str) -> Option<&Grant> {
        self.grants.iter().find(|g| g.id == grant_id)
    }

    /// The agent's live grants at `now` (status).
    pub fn grants_for(&self, agent_id: &str, now: Duration) -> Vec<Grant> {
        self.grants
            .iter()
            .filter(|g| g.agent_id == agent_id && g.is_live(now))
            .cloned()
            .collect()
    }

    /// Spend one use of `grant_id`. Refuses (returns `false`) a
    /// grant that is no longer live — the caller re-checks under the
    /// same lock, so a use is never spent twice for one admission.
    pub fn consume(&mut self, grant_id: &str, now: Duration) -> bool {
        match self.grants.iter_mut().find(|g| g.id == grant_id) {
            Some(g) if g.is_live(now) => {
                g.uses += 1;
                true
            }
            _ => false,
        }
    }

    /// Revoke a grant (REQ-REV-001's primitive; the owner surface
    /// that calls it is #16). Effective immediately.
    pub fn revoke(&mut self, grant_id: &str) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| g.id != grant_id);
        self.grants.len() != before
    }

    /// A request by id.
    pub fn request(&self, request_id: &str) -> Option<&GrantRequest> {
        self.requests.iter().find(|r| r.id == request_id)
    }

    /// Every pending request (the channels' queue).
    pub fn pending_requests(&self) -> Vec<GrantRequest> {
        self.requests
            .iter()
            .filter(|r| r.state == RequestState::Pending)
            .cloned()
            .collect()
    }

    /// Create the request a grantless fill makes, or return the
    /// identical request already pending for `(agent, item, action)`
    /// — a retrying agent must not stack prompts (approval fatigue
    /// is REQ-RL-003's concern; one pending request per triple is
    /// this model's floor). A claim that disagrees with the observed
    /// live origin makes an `origin_mismatch` request (REQ-APR-007),
    /// which is never deduped into a pending one and never prompts.
    /// The `bool` is `true` when this call created the request (the
    /// broker audits creation exactly once).
    pub fn create_request(
        &mut self,
        agent_id: &str,
        item_id: &str,
        action: GrantAction,
        claimed_origin: &str,
        observed_origin: &str,
        now: Duration,
    ) -> (GrantRequest, bool) {
        if serialized_origin(claimed_origin) == serialized_origin(observed_origin)
            && let Some(r) = self.requests.iter().find(|r| {
                r.state == RequestState::Pending
                    && r.agent_id == agent_id
                    && r.item_id == item_id
                    && r.action == action
            })
        {
            return (r.clone(), false);
        }
        let state = if serialized_origin(claimed_origin) == serialized_origin(observed_origin) {
            RequestState::Pending
        } else {
            RequestState::OriginMismatch
        };
        let req = GrantRequest {
            id: new_id("gr"),
            agent_id: agent_id.to_owned(),
            item_id: item_id.to_owned(),
            action,
            claimed_origin: claimed_origin.to_owned(),
            observed_origin: observed_origin.to_owned(),
            state,
            created_at: now,
            grant_id: None,
        };
        self.requests.push(req.clone());
        (req, true)
    }

    /// Approve a pending request: issue its grant under `terms` on
    /// `channel`. The grant's origin is the request's **observed**
    /// origin and its action set starts as the requested action —
    /// the owner widens terms (scope, TTL, uses), never the origin
    /// or the action the prompt showed.
    pub fn approve(
        &mut self,
        request_id: &str,
        terms: &GrantTerms,
        channel: Channel,
        now: Duration,
    ) -> Result<Grant, GrantError> {
        let req = self
            .requests
            .iter()
            .find(|r| r.id == request_id)
            .ok_or(GrantError::NotFound)?;
        if req.state != RequestState::Pending {
            return Err(GrantError::NotPending);
        }
        let (agent_id, item_id, action, observed) = (
            req.agent_id.clone(),
            req.item_id.clone(),
            req.action,
            req.observed_origin.clone(),
        );
        let grant = self.issue(
            &agent_id,
            &item_id,
            action,
            &observed,
            terms,
            channel,
            Some(request_id),
            now,
        )?;
        let req = self
            .requests
            .iter_mut()
            .find(|r| r.id == request_id)
            .expect("invariant: request checked above");
        req.state = RequestState::Approved;
        req.grant_id = Some(grant.id.clone());
        Ok(grant)
    }

    /// Issue a grant directly (approval of `request_id`, or an
    /// owner's standing arrangement made out of band).
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &mut self,
        agent_id: &str,
        item_id: &str,
        action: GrantAction,
        origin: &str,
        terms: &GrantTerms,
        channel: Channel,
        request_id: Option<&str>,
        now: Duration,
    ) -> Result<Grant, GrantError> {
        let (expires_at, max_uses) = terms.resolve(now, self.allow_standing)?;
        if !terms.scope.covers(item_id, &[]) && matches!(terms.scope, GrantScope::Item(_)) {
            // An item-scoped grant for a different item than the
            // request's is a channel bug; refuse it here rather than
            // issue a grant the requester cannot use.
            return Err(GrantError::InvalidTerms("scope_item_mismatch"));
        }
        let grant = Grant {
            id: new_id("g"),
            agent_id: agent_id.to_owned(),
            scope: terms.scope.clone(),
            origin: origin.to_owned(),
            actions: [action].into_iter().collect(),
            created_at: now,
            expires_at,
            max_uses,
            uses: 0,
            kind: terms.kind,
            created_by_channel: channel,
            request_id: request_id.map(str::to_owned),
        };
        self.grants.push(grant.clone());
        Ok(grant)
    }

    /// Deny a pending request (owner action).
    pub fn deny(&mut self, request_id: &str) -> Result<GrantRequest, GrantError> {
        let req = self
            .requests
            .iter_mut()
            .find(|r| r.id == request_id)
            .ok_or(GrantError::NotFound)?;
        if req.state != RequestState::Pending {
            return Err(GrantError::NotPending);
        }
        req.state = RequestState::Denied;
        Ok(req.clone())
    }

    /// REQ-APR-003: deny every request pending for at least
    /// [`REQUEST_TIMEOUT`]. Returns the requests that transitioned,
    /// so the broker can audit each denial exactly once.
    pub fn expire(&mut self, now: Duration) -> Vec<GrantRequest> {
        let mut denied = Vec::new();
        for req in &mut self.requests {
            if req.state == RequestState::Pending
                && now.saturating_sub(req.created_at) >= REQUEST_TIMEOUT
            {
                req.state = RequestState::Denied;
                denied.push(req.clone());
            }
        }
        denied
    }

    /// Requests an expiry pass at `now` would deny, without
    /// transitioning them: the broker transitions each through
    /// [`Self::deny_expired`] (so an approval that lands after this
    /// snapshot wins) and audits the denial, rolling the transition
    /// back if the audit append fails (REQ-AUD-003).
    pub fn expired_pending(&self, now: Duration) -> Vec<GrantRequest> {
        self.requests
            .iter()
            .filter(|r| {
                r.state == RequestState::Pending
                    && now.saturating_sub(r.created_at) >= REQUEST_TIMEOUT
            })
            .cloned()
            .collect()
    }

    /// Transition one request to `denied` for the expiry pass.
    /// `None` if it left `pending` meanwhile.
    pub fn deny_expired(&mut self, request_id: &str) -> Option<GrantRequest> {
        let req = self.requests.iter_mut().find(|r| r.id == request_id)?;
        if req.state != RequestState::Pending {
            return None;
        }
        req.state = RequestState::Denied;
        Some(req.clone())
    }

    /// Undo an approval whose audit append failed (the broker's
    /// fail-closed rollback): drop the grant and return the request
    /// to `pending`, exactly as if the approval had not run.
    pub fn rollback_approval(&mut self, request_id: &str, grant_id: &str) {
        self.grants.retain(|g| g.id != grant_id);
        if let Some(req) = self.requests.iter_mut().find(|r| r.id == request_id) {
            req.state = RequestState::Pending;
            req.grant_id = None;
        }
    }

    /// Undo a denial whose audit append failed: back to `pending`.
    pub fn restore_pending(&mut self, request_id: &str) {
        if let Some(req) = self.requests.iter_mut().find(|r| r.id == request_id) {
            req.state = RequestState::Pending;
        }
    }

    /// Re-insert a revoked grant whose audit append failed.
    pub fn restore_grant(&mut self, grant: Grant) {
        if !self.grants.iter().any(|g| g.id == grant.id) {
            self.grants.push(grant);
        }
    }
}

/// The broker's grant policy, from `[policy]` (SPEC §5, §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GrantPolicy {
    /// Standing grants permitted. Default false; `default_grant =
    /// "standing"` in config is refused without it (REQ-DEP-003).
    pub allow_standing: bool,
}

impl From<&crate::config::PolicyConfig> for GrantPolicy {
    fn from(p: &crate::config::PolicyConfig) -> Self {
        Self {
            allow_standing: p.allow_standing,
        }
    }
}

/// `g_…` / `gr_…`: 128 random bits, hex.
fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", hex::encode(rand::random::<[u8; 16]>()))
}

// ------------------------------------------------------------ wire types

/// SPEC §4 `kharon_request_grant` arguments / `POST /v1/grants`
/// body: the same JSON on both transports, like the fill tools'.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantArgs {
    /// The item to fill from.
    #[schemars(length(min = 36, max = 36), extend("format" = "uuid"))]
    pub item_id: String,
    /// The tab the fill would target: the broker reads the live
    /// origin from it for the prompt (REQ-APR-007).
    pub target: super::fill::TargetArgs,
    /// The action to grant (`fill` default, or `totp`).
    #[serde(default)]
    pub action: Option<GrantAction>,
}

/// A validated grant request (see [`parse_grant`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequestArgs {
    /// Canonical (lowercase) UUID.
    pub item_id: String,
    /// CDP target id.
    pub target_id: String,
    /// The agent's claimed origin (validated absolute http(s) URL).
    pub expected_origin: String,
    /// The action to grant.
    pub action: GrantAction,
}

/// Validate a `kharon_request_grant` body / arguments. The single
/// entry point for both transports, as [`super::fill::parse_fill`]
/// is for fills.
pub fn parse_grant(json: &[u8]) -> Result<GrantRequestArgs, ApiError> {
    let a: GrantArgs = serde_json::from_slice(json).map_err(|e| match e.classify() {
        serde_json::error::Category::Data => ApiError::bad_request(Detail::InvalidGrantRequest),
        _ => ApiError::bad_request(Detail::InvalidJsonBody),
    })?;
    if a.item_id.len() != ITEM_ID_LEN
        || !a.item_id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
    {
        return Err(ApiError::bad_request(Detail::InvalidItemId));
    }
    if a.target.cdp_target_id.is_empty() {
        return Err(ApiError::bad_request(Detail::InvalidGrantRequest));
    }
    if a.target.cdp_target_id.len() > MAX_TARGET_ID_LEN {
        return Err(ApiError::bad_request(Detail::FieldTooLong));
    }
    if a.target.frame_id.is_some() {
        return Err(ApiError::bad_request(Detail::FrameIdUnsupported));
    }
    let expected_origin = super::core::validate_origin(&a.target.expected_origin)
        .map_err(|_| ApiError::bad_request(Detail::InvalidOrigin))?;
    Ok(GrantRequestArgs {
        item_id: a.item_id.to_ascii_lowercase(),
        target_id: a.target.cdp_target_id,
        expected_origin,
        action: a.action.unwrap_or(GrantAction::Fill),
    })
}

/// SPEC §4: the `kharon_request_grant` / `POST /v1/grants` body,
/// `{grant_request_id, state}`. `grant_request_id` is null when no
/// request was created (`not_found`, `target_not_owned`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct GrantRequestBody {
    /// The created (or already pending) request, if any.
    pub grant_request_id: Option<String>,
    /// `pending`, `origin_mismatch`, `not_found` or
    /// `target_not_owned`.
    pub state: &'static str,
}

impl GrantRequestBody {
    /// The body for a created request.
    pub fn of(req: &GrantRequest) -> Self {
        Self {
            grant_request_id: Some(req.id.clone()),
            state: req.state.as_str(),
        }
    }

    /// The body for a refusal that created no request.
    pub fn refused(state: &'static str) -> Self {
        Self {
            grant_request_id: None,
            state,
        }
    }
}

/// Guard: broker-assigned ids stay well under the wire cap agents
/// echo back as `grant_id`.
const _: () = assert!(MAX_GRANT_ID_LEN >= 40);

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Duration = Duration::from_secs(1_000);

    fn store() -> GrantStore {
        GrantStore::new(true)
    }

    #[test]
    fn origin_matches_host_and_registrable_domain_only() {
        assert!(origin_matches(
            "login.example.com",
            "https://login.example.com/signin"
        ));
        assert!(origin_matches("example.com", "https://login.example.com"));
        assert!(origin_matches(
            "https://example.com",
            "https://deep.login.example.com"
        ));
        assert!(!origin_matches("example.com", "https://example.org"));
        assert!(!origin_matches("login.example.com", "https://example.com"));
        assert!(!origin_matches("ample.com", "https://example.com"));
        assert!(!origin_matches("co.uk", "https://example.co.uk"));
        assert!(origin_matches("example.co.uk", "https://www.example.co.uk"));
    }

    #[test]
    fn req_apr_002_matching_dimensions() {
        let mut s = store();
        let terms = GrantTerms {
            scope: GrantScope::Item("item-1".into()),
            kind: GrantKind::PerOrigin,
            ttl: None,
            max_uses: Some(2),
        };
        let g = s
            .issue(
                "alpha",
                "item-1",
                GrantAction::Fill,
                "https://login.example.com",
                &terms,
                Channel::Cli,
                None,
                NOW,
            )
            .unwrap();
        fn m(
            s: &GrantStore,
            agent: &str,
            item: &str,
            colls: &[String],
            origin: &str,
            action: GrantAction,
            now: Duration,
        ) -> Option<String> {
            s.matching_grant(agent, item, colls, origin, action, now)
                .map(|g| g.id.clone())
        }
        let none: &[String] = &[];
        assert_eq!(
            m(
                &s,
                "alpha",
                "item-1",
                none,
                "https://login.example.com",
                GrantAction::Fill,
                NOW
            ),
            Some(g.id.clone())
        );
        // Each single dimension mismatching loses the match.
        assert_eq!(
            m(
                &s,
                "beta",
                "item-1",
                none,
                "https://login.example.com",
                GrantAction::Fill,
                NOW
            ),
            None
        );
        assert_eq!(
            m(
                &s,
                "alpha",
                "item-2",
                none,
                "https://login.example.com",
                GrantAction::Fill,
                NOW
            ),
            None
        );
        assert_eq!(
            m(
                &s,
                "alpha",
                "item-1",
                none,
                "https://other.example.com",
                GrantAction::Fill,
                NOW
            ),
            None
        );
        assert_eq!(
            m(
                &s,
                "alpha",
                "item-1",
                none,
                "https://login.example.com",
                GrantAction::Totp,
                NOW
            ),
            None
        );
        // Expired (per-origin default TTL is 1 h).
        assert_eq!(
            m(
                &s,
                "alpha",
                "item-1",
                none,
                "https://login.example.com",
                GrantAction::Fill,
                NOW + PER_ORIGIN_TTL
            ),
            None
        );
        // Uses exhausted.
        assert!(s.consume(&g.id, NOW));
        assert!(s.consume(&g.id, NOW));
        assert!(!s.consume(&g.id, NOW));
        assert_eq!(
            m(
                &s,
                "alpha",
                "item-1",
                none,
                "https://login.example.com",
                GrantAction::Fill,
                NOW
            ),
            None
        );
    }

    #[test]
    fn req_apr_002_collection_scope_covers_member_items() {
        let mut s = store();
        let terms = GrantTerms {
            scope: GrantScope::Collection("coll-1".into()),
            kind: GrantKind::PerOrigin,
            ttl: None,
            max_uses: None,
        };
        s.issue(
            "alpha",
            "item-1",
            GrantAction::Fill,
            "example.com",
            &terms,
            Channel::Cli,
            None,
            NOW,
        )
        .unwrap();
        let colls = ["coll-1".to_string()];
        assert!(
            s.matching_grant(
                "alpha",
                "item-9",
                &colls,
                "https://app.example.com",
                GrantAction::Fill,
                NOW
            )
            .is_some()
        );
        assert!(
            s.matching_grant(
                "alpha",
                "item-9",
                &[],
                "https://app.example.com",
                GrantAction::Fill,
                NOW
            )
            .is_none()
        );
    }

    #[test]
    fn req_apr_003_expire_denies_at_timeout() {
        let mut s = store();
        let (r, _) = s.create_request(
            "alpha",
            "item-1",
            GrantAction::Fill,
            "https://login.example.com",
            "https://login.example.com",
            NOW,
        );
        assert_eq!(r.state, RequestState::Pending);
        assert!(
            s.expire(NOW + REQUEST_TIMEOUT - Duration::from_secs(1))
                .is_empty()
        );
        let denied = s.expire(NOW + REQUEST_TIMEOUT + Duration::from_secs(1));
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].id, r.id);
        assert_eq!(s.request(&r.id).unwrap().state, RequestState::Denied);
        // A second pass transitions nothing (audited exactly once).
        assert!(s.expire(NOW + REQUEST_TIMEOUT * 3).is_empty());
    }

    #[test]
    fn req_apr_007_mismatch_request_never_prompts() {
        let mut s = store();
        let (r, _) = s.create_request(
            "alpha",
            "item-1",
            GrantAction::Fill,
            "https://claimed.example.com",
            "https://live.example.com",
            NOW,
        );
        assert_eq!(r.state, RequestState::OriginMismatch);
        assert!(r.prompt().is_none());
        // Approving a mismatch is refused: it is not pending.
        assert_eq!(
            s.approve(&r.id, &GrantTerms::once_item("item-1"), Channel::Cli, NOW),
            Err(GrantError::NotPending)
        );
        // A matching claim prompts with the observed origin.
        let (r2, _) = s.create_request(
            "alpha",
            "item-1",
            GrantAction::Fill,
            "https://live.example.com/login",
            "https://live.example.com",
            NOW,
        );
        assert_eq!(r2.state, RequestState::Pending);
        assert_eq!(r2.prompt().unwrap().origin, "https://live.example.com");
    }

    #[test]
    fn approve_issues_grant_bound_to_observed_origin() {
        let mut s = store();
        let (r, _) = s.create_request(
            "alpha",
            "item-1",
            GrantAction::Totp,
            "https://login.example.com",
            "https://login.example.com",
            NOW,
        );
        let g = s
            .approve(&r.id, &GrantTerms::once_item("item-1"), Channel::Ntfy, NOW)
            .unwrap();
        assert_eq!(g.origin, "https://login.example.com");
        assert_eq!(g.actions, [GrantAction::Totp].into_iter().collect());
        assert_eq!(g.max_uses, Some(1));
        assert_eq!(g.expires_at, NOW + ONCE_TTL);
        assert_eq!(s.request(&r.id).unwrap().state, RequestState::Approved);
        assert_eq!(
            s.approve(&r.id, &GrantTerms::once_item("item-1"), Channel::Ntfy, NOW),
            Err(GrantError::NotPending)
        );
    }

    #[test]
    fn standing_terms_need_the_flag_and_ttl_caps_hold() {
        let mut s = GrantStore::new(false);
        let terms = GrantTerms {
            scope: GrantScope::Item("item-1".into()),
            kind: GrantKind::Standing,
            ttl: None,
            max_uses: None,
        };
        assert_eq!(
            s.issue(
                "alpha",
                "item-1",
                GrantAction::Fill,
                "example.com",
                &terms,
                Channel::Cli,
                None,
                NOW
            ),
            Err(GrantError::StandingDisabled)
        );
        let mut s = store();
        let too_long = GrantTerms {
            ttl: Some(PER_ORIGIN_MAX_TTL + Duration::from_secs(1)),
            kind: GrantKind::PerOrigin,
            ..GrantTerms::once_item("item-1")
        };
        assert_eq!(
            s.issue(
                "alpha",
                "item-1",
                GrantAction::Fill,
                "example.com",
                &too_long,
                Channel::Cli,
                None,
                NOW
            ),
            Err(GrantError::InvalidTerms("ttl_out_of_range"))
        );
    }
}
