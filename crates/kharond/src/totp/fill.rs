//! `fill_totp` over the fill engine (REQ-API-007, REQ-API-009).
//!
//! Order per call:
//!
//! 1. The clock gate ([`ClockSkewGate::check_totp`]): above
//!    `clock_skew_refuse` the call ends here with
//!    [`FillOutcome::ClockSkew`] (`status: error`, `detail:
//!    clock_skew`) and a `fill_totp` audit entry; no CDP call is made.
//!    Callers that decrypt per fill should consult the gate before
//!    decrypting the item's TOTP field, too, so a refused call
//!    decrypts nothing.
//! 2. Parse the decrypted field ([`TotpKey::parse`]). An unsupported
//!    field → [`FillOutcome::TotpUnsupported`], audited, no CDP call.
//! 3. Compute the code for the current time step and fill it as a
//!    `totp` field through [`DeadlineFiller`] (the same engine,
//!    origin checks, ownership checks and deadline as a password
//!    fill). The code lives only in the plan's `Zeroizing` buffer,
//!    which is dropped (wiped) before this returns.
//!
//! The outcome carries kinds only; [`FillOutcome::result_body`] is the
//! SPEC §4 `FillResult` and has no field the code could travel in.
//!
//! Authorization: grants (#20) do not exist yet, so this layer takes
//! an already-authorized request, exactly like
//! [`DeadlineFiller`]/[`FillEngine::fill`] for passwords; the API
//! layer (#18 for `fill`, this issue's follow-up for `fill_totp`) will
//! put the grant check (action `totp`) in front of it.

use std::time::{Duration, SystemTime};

use kharon_bwcrypto::Secret;
use zeroize::Zeroizing;

use super::TotpKey;
use super::skew::ClockSkewGate;
use crate::audit::{AuditLog, Entry, Event};
use crate::cdp::fill::{DEFAULT_FILL_DEADLINE, DeadlineFiller};
use crate::cdp::{AgentContext, FieldFill, FieldKind, FillEngine, FillOutcome, FillPlan};
use crate::origin::{OriginConfig, OriginMatcher};

/// Steps 1–3 without the fill: the clock gate, then parse `field` (the
/// item's decrypted `login.totp`) and compute the code for `now`. The
/// field is dropped (wiped) before this returns; the code lives only in
/// the returned `Zeroizing` buffer. A refusal is
/// [`FillOutcome::ClockSkew`] or [`FillOutcome::TotpUnsupported`]; the
/// caller audits it. Shared by [`TotpFill`] and the API's `fill_totp`
/// (`crate::api::fill`), which consults the gate itself before
/// decrypting and then calls this.
pub fn totp_code(
    gate: &ClockSkewGate,
    field: Secret<String>,
    now: SystemTime,
) -> Result<Zeroizing<String>, FillOutcome> {
    if gate.check_totp().is_err() {
        drop(field);
        return Err(FillOutcome::ClockSkew);
    }
    let key = match TotpKey::parse(&field) {
        Ok(k) => k,
        Err(_) => {
            drop(field);
            return Err(FillOutcome::TotpUnsupported);
        }
    };
    drop(field);
    key.code_now(now).map_err(|_| FillOutcome::ClockSkew)
}

/// Where a TOTP code goes: [`FillPlan`] without the field values.
#[derive(Debug, Clone)]
pub struct TotpTarget {
    /// Tab, from the agent's own CDP session.
    pub target_id: String,
    /// Optional CSS selector for the code field (heuristic otherwise).
    pub selector: Option<String>,
    /// The item's URIs as matchers.
    pub item_matchers: Vec<OriginMatcher>,
    /// Origin policy.
    pub origin_cfg: OriginConfig,
    /// REQ-ORG-004 iframe allow-list.
    pub cross_origin_iframe_hosts: Vec<String>,
    /// REQ-API-008 submit after the fill.
    pub submit: bool,
}

/// One `fill_totp` call.
pub struct TotpFill<'a> {
    engine: &'a FillEngine,
    audit: &'a mut AuditLog,
    gate: &'a ClockSkewGate,
    deadline: Duration,
    now: Option<SystemTime>,
}

impl<'a> TotpFill<'a> {
    /// A `fill_totp` over `engine`, auditing to `audit`, gated by
    /// `gate`, with the default deadline and the system clock.
    pub fn new(engine: &'a FillEngine, audit: &'a mut AuditLog, gate: &'a ClockSkewGate) -> Self {
        Self {
            engine,
            audit,
            gate,
            deadline: DEFAULT_FILL_DEADLINE,
            now: None,
        }
    }

    /// `[policy] fill_deadline` (REQ-API-009).
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Compute the code for `now` instead of the system clock (tests).
    pub fn at(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Run the fill. `field` is the item's decrypted `login.totp`.
    pub async fn run(
        self,
        target: TotpTarget,
        field: Secret<String>,
        agent_ctx: &AgentContext,
        allow_default: bool,
    ) -> FillOutcome {
        let now = self.now.unwrap_or_else(SystemTime::now);
        let code = match totp_code(self.gate, field, now) {
            Ok(c) => c,
            Err(refusal) => return self.refuse(agent_ctx, refusal),
        };
        let plan = FillPlan {
            target_id: target.target_id,
            fields: vec![FieldFill {
                kind: FieldKind::Totp,
                selector: target.selector,
                value: code,
            }],
            item_matchers: target.item_matchers,
            origin_cfg: target.origin_cfg,
            cross_origin_iframe_hosts: target.cross_origin_iframe_hosts,
            submit: target.submit,
            expected_origin: None,
            live_origin: crate::cdp::LiveOrigin::new(),
        };
        let (plan, outcome) = DeadlineFiller::new(self.engine, self.audit)
            .with_deadline(self.deadline)
            .run(plan, agent_ctx, allow_default)
            .await;
        // The code's only buffer: wiped here (Zeroizing) on drop.
        drop(plan);
        outcome
    }

    /// Audit a refusal made before any CDP call and return it. The
    /// refusal stands even if the append fails: no write was made and
    /// none will be (cf. the `fill_timeout` path).
    fn refuse(self, agent_ctx: &AgentContext, outcome: FillOutcome) -> FillOutcome {
        let mut entry = Entry::new(Event::FillTotp)
            .agent_id(agent_ctx.agent_id())
            .result(outcome.status());
        if let Some(d) = outcome.detail() {
            entry = entry.detail_code(d);
        }
        let _ = self.audit.append(entry);
        outcome
    }
}
