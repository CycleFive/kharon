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
use crate::cdp::fill::{AuditFailed, DEFAULT_FILL_DEADLINE, DeadlineFiller};
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
    ///
    /// `Err(AuditFailed)` when an outcome entry this layer writes (the
    /// refusal's `fill_totp`, or the deadline's `fill_timeout`) could
    /// not be appended: REQ-AUD-003†, the reply is `audit_failed`, as in
    /// the daemon path (#46).
    ///
    /// # Audit
    ///
    /// This layer audits the pre-fill refusals itself (`clock_skew`,
    /// unsupported field: their `fill_totp` entry is written by
    /// `refuse()`, see above) and the deadline's `fill_timeout`. Every
    /// other outcome of the fill itself is returned **unaudited**: this
    /// layer writes no `fill_dispatch` and no outcome entry for it, so
    /// the caller must append the `fill_totp` outcome entry itself, and
    /// must not append one for a refusal or a timeout (exactly one entry
    /// per outcome), mirroring [`crate::cdp::fill::DeadlineFiller`]'s
    /// Audit section (REQ-AUD-003†; retiring this path is #77).
    pub async fn run(
        self,
        target: TotpTarget,
        field: Secret<String>,
        agent_ctx: &AgentContext,
        allow_default: bool,
    ) -> Result<FillOutcome, AuditFailed> {
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

    /// Audit a refusal made before any CDP call and return it. No CDP
    /// write was made and none will be, but the refusal is still an
    /// outcome the log must have before it is reported: a failed append
    /// is `Err(AuditFailed)` (REQ-AUD-003†; same as the `fill_timeout`
    /// path, #46).
    fn refuse(
        self,
        agent_ctx: &AgentContext,
        outcome: FillOutcome,
    ) -> Result<FillOutcome, AuditFailed> {
        let mut entry = Entry::new(Event::FillTotp)
            .agent_id(agent_ctx.agent_id())
            .result(outcome.status());
        if let Some(d) = outcome.detail() {
            entry = entry.detail_code(d);
        }
        self.audit.append(entry).map_err(|_| AuditFailed)?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdp::fill::test_support::{failing_audit, stalling_engine};

    fn target() -> TotpTarget {
        TotpTarget {
            target_id: "t1".to_string(),
            selector: None,
            item_matchers: vec![
                OriginMatcher::new("https://accounts.example.com/login", None).unwrap(),
            ],
            origin_cfg: OriginConfig::default(),
            cross_origin_iframe_hosts: Vec::new(),
            submit: false,
        }
    }

    /// REQ-AUD-003†: a refusal made before any CDP call (here an
    /// unsupported TOTP field, REQ-API-007) is still an outcome; when
    /// its `fill_totp` entry cannot be appended the call is
    /// `Err(AuditFailed)`, not the refusal (#46), and no fill call is
    /// made.
    #[tokio::test]
    async fn req_aud_003_totp_refusal_append_failure_is_audit_failed() {
        let (engine, ctx, received, _peer) = stalling_engine().await;
        let (_dir, mut audit) = failing_audit();
        let gate = ClockSkewGate::default();
        let out = TotpFill::new(&engine, &mut audit, &gate)
            .run(
                target(),
                Secret::new("otpauth://hotp/x?secret=GEZDGNBV".to_string()),
                &ctx,
                false,
            )
            .await;
        assert_eq!(out, Err(AuditFailed));
        assert!(
            received
                .lock()
                .unwrap()
                .iter()
                .all(|m| m["method"] != "Runtime.callFunctionOn"),
            "no fill call on a refusal"
        );
    }

    /// REQ-API-009 + REQ-AUD-003†: `fill_totp` through the deadline
    /// with a failing log is `Err(AuditFailed)` at the deadline, not
    /// `Timeout`.
    #[tokio::test]
    async fn req_api_009_totp_timeout_append_failure_is_audit_failed() {
        let (engine, ctx, _received, _peer) = stalling_engine().await;
        let (_dir, mut audit) = failing_audit();
        let gate = ClockSkewGate::default();
        let start = std::time::Instant::now();
        let out = TotpFill::new(&engine, &mut audit, &gate)
            .with_deadline(Duration::from_millis(500))
            .run(
                target(),
                Secret::new("JBSWY3DPEHPK3PXP".to_string()),
                &ctx,
                false,
            )
            .await;
        assert_eq!(out, Err(AuditFailed));
        assert!(start.elapsed() < Duration::from_millis(1100));
    }
}
