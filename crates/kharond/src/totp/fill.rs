//! The code step of `fill_totp` (REQ-API-007).
//!
//! `fill_totp` has one path, [`crate::api::Broker::fill`] (HTTP and
//! MCP both call it), which owns the REQ-API-009 deadline and the
//! REQ-AUD-003† `fill_dispatch` / outcome audit pair, exactly as for a
//! password fill. Order per call:
//!
//! 1. The clock gate ([`ClockSkewGate::check_totp`]): above
//!    `clock_skew_refuse` the call ends with [`FillOutcome::ClockSkew`]
//!    (`status: error`, `detail: clock_skew`) and a `fill_totp` audit
//!    entry; no CDP call is made. The broker consults the gate before
//!    decrypting the item's TOTP field, so a refused call decrypts
//!    nothing; [`totp_code`] checks it again.
//! 2. Parse the decrypted field ([`TotpKey::parse`]). An unsupported
//!    field → [`FillOutcome::TotpUnsupported`], audited, no CDP call.
//! 3. Compute the code for the current time step ([`totp_code`]); the
//!    broker fills it as a `totp` field through the same engine, origin
//!    checks, ownership checks and deadline as a password fill. The code
//!    lives only in the plan's `Zeroizing` buffer, which the broker
//!    wipes before it replies.
//!
//! The outcome carries kinds only; [`FillOutcome::result_body`] is the
//! SPEC §4 `FillResult` and has no field the code could travel in.
//!
//! (The engine-level `TotpFill` wrapper, which returned non-timeout
//! outcomes unaudited, was retired in #77.)

use std::time::SystemTime;

use kharon_bwcrypto::Secret;
use zeroize::Zeroizing;

use super::TotpKey;
use super::skew::ClockSkewGate;
use crate::cdp::FillOutcome;

/// Steps 1–3: the clock gate, then parse `field` (the item's decrypted
/// `login.totp`) and compute the code for `now`. The field is dropped
/// (wiped) before this returns; the code lives only in the returned
/// `Zeroizing` buffer. A refusal is [`FillOutcome::ClockSkew`] or
/// [`FillOutcome::TotpUnsupported`]; the caller audits it.
/// [`crate::api::Broker::fill`] consults the gate itself before
/// decrypting, then calls this.
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
