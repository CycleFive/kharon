//! The in-page half of the atomic fill (SPEC §6 step 2).
//!
//! `FILL_IN_PAGE` runs via `Runtime.callFunctionOn` inside the isolated
//! world created by `Page.createIsolatedWorld`. It is one synchronous
//! function: origin re-check, secure-context check, top-frame liveness
//! check, element resolution, native value set, and event dispatch all
//! happen in a single renderer task, so by JS run-to-completion no
//! navigation can commit between the check and the write (REQ-ORG-003).
//!
//! The match table here is the JSON-serialized mirror of
//! [`crate::origin`]'s `InPageSpec` — the broker derives both from the
//! same `OriginMatcher`, so the tables cannot drift (the divergence was
//! the blocking finding of the PR #35 review).
//!
//! Failure contract: every refusal throws `Error` whose message is
//! `kharon:<code>`; the broker reads the code out of
//! `exceptionDetails.exception.description`. Codes:
//! `origin_mismatch`, `non_secure`, `field_not_found`, `deadline`, and
//! in leg mode (#382) `method_wrong_page`, `method_drift:<index>`,
//! `method_not_ready:<index>`.

/// Fill function. Arguments, in order:
/// 1. `specs` — array of `InPageSpec` (any may match; mirrors the
///    broker's any-URI-allows decision).
/// 2. `fields` — array of `{ kind: "username"|"password"|"totp",
///    selector: string|null, value: string }`.
/// 3. `expectedTopOrigin` — the top frame origin the broker observed in
///    step 1's frame-tree read; when the top frame is same-origin
///    accessible it must still equal this, pinning the top against a
///    navigation race. Cross-origin tops throw and are skipped: the
///    broker's frame-tree origin check already gated the fill, and
///    REQ-ORG-004's allowlist governs whether we are in this frame at
///    all.
/// 4. `submitRequested` — REQ-API-008: after every field fills
///    successfully, dispatch submit (`form.requestSubmit()` on the
///    last element's form, else Enter key events). Never reached on
///    any refusal: failures throw before this point.
/// 5. `budgetMs` — REQ-API-009 page-side relative budget (#118,
///    design in #75/#117): milliseconds the in-page task may spend,
///    measured with `performance.now()` sampled at entry in this
///    isolated world — a relative duration, never a wall clock, and
///    never a page-reported value the broker trusts (the broker's own
///    deadline still governs the reply). `0`/absent = no page-side
///    check. The budget is checked before each field write and
///    immediately before the submit dispatch; on expiry the written
///    fields are cleared (as for any failure) and the call throws
///    `kharon:deadline`, which the broker maps to `timeout`. One
///    step's overshoot is the residual: a single field write whose
///    synchronous page handlers never return cannot be preempted.
/// 6. `scrubRequested` — #355: when this fill will submit and the
///    post-submit scrub is on, remember the elements this call wrote
///    (`globalThis.__kharonWritten`, this isolated world only) so a
///    later [`SCRUB_WRITTEN_IN_PAGE`] can clear those nodes. Element
///    references only; the values are not copied. Absent or false
///    leaves nothing behind.
///
/// 7. `leg` — #382 leg mode, `null`/absent for a normal fill. When the
///    broker holds a recorded login method: `{ path, fills: [{ index,
///    selectors, password, expect }], submit: null | { index, via:
///    "form"|"enter"|"click", selectors, expect } }`. `fields[i]` is the
///    value for `leg.fills[i]` and `fields[i].selector` is ignored.
///    Every step is checked against the live page before the first
///    write (path, then resolve + shape for each step, then the form for
///    a `form` submit, then readiness); `click` submits the recorded
///    button once, after every field and the budget check. Leaves
///    `globalThis.__kharonMethodPw` for [`METHOD_PROBE_IN_PAGE`].
///
/// Clear-on-failure (SPEC §2, #101): when a field fails after earlier
/// fields were written, every element this call wrote is blanked
/// (native setter, `input` + `change`, as for the write) before the
/// error is rethrown, so a partial fill leaves no value behind and,
/// since the throw precedes step 4, never submits.
///
/// Returns `{ results: [{ kind, filled: true }] }` by value.
pub const FILL_IN_PAGE: &str = r#"
function fillInPage(specs, fields, expectedTopOrigin, submitRequested, budgetMs, scrubRequested, leg) {
  "use strict";

  function fail(code) {
    const e = new Error("kharon:" + code);
    e.kharonCode = code;
    throw e;
  }

  // REQ-API-009 page-side budget (#118): relative milliseconds from
  // entry, on the isolated world's own monotonic clock. 0/absent
  // disables the check entirely (performance.now is not even read).
  const budget = typeof budgetMs === "number" && budgetMs > 0 ? budgetMs : 0;
  const startedAt = budget ? performance.now() : 0;
  function checkBudget() {
    if (budget && performance.now() - startedAt >= budget) fail("deadline");
  }

  function matchOne(spec, loc) {
    if (spec.kind === "refused") return false;
    if (loc.protocol !== spec.scheme + ":") return false;
    switch (spec.kind) {
      case "domain": {
        const d = spec.domain;
        if (spec.host_equal) return loc.hostname === d;
        return loc.hostname === d || loc.hostname.endsWith("." + d);
      }
      case "host":
        return loc.origin === spec.origin;
      case "starts_with":
        return loc.origin === spec.origin && loc.href.startsWith(spec.href);
      case "exact":
        return loc.href === spec.href;
      default:
        return false;
    }
  }

  const loc = {
    protocol: location.protocol,
    hostname: location.hostname,
    origin: location.origin,
    href: location.href,
  };
  if (!specs.some((s) => matchOne(s, loc))) fail("origin_mismatch");
  if (!window.isSecureContext) fail("non_secure");

  // Top-frame liveness (SPEC §6 step 2): when the top is readable it
  // must still be the origin the broker saw. A SecurityError means a
  // cross-origin top — the broker's step-1 frame-tree check stands.
  // Coded refusals raised by fail() inside the try must propagate:
  // without the rethrow, the catch below swallows the origin_mismatch
  // the comparison just raised (review finding 2 — this check was
  // dead code until the rethrow landed).
  try {
    if (window.top && window.top.location) {
      const topOrigin = window.top.location.origin;
      if (topOrigin !== expectedTopOrigin) fail("origin_mismatch");
    }
  } catch (e) {
    if (e && e.kharonCode) throw e;
    /* cross-origin top: see doc comment */
  }

  function resolveField(kind, selector) {
    if (selector) return document.querySelector(selector);
    if (kind === "password") return document.querySelector('input[type="password"]');
    // Keep in step with is_otp_descriptor in crates/kharon-recording/src/classify.rs.
    if (kind === "totp") {
      return document.querySelector(
        'input[autocomplete*="one-time"], input[name*="otp" i], input[type="tel"]'
      );
    }
    if (kind === "username") {
      const byHint = document.querySelector(
        'input[type="email"], input[autocomplete*="username"], input[name*="user" i]'
      );
      if (byHint) return byHint;
      const inputs = Array.from(document.querySelectorAll("input"));
      return (
        inputs.find(
          (i) => !i.disabled && !["hidden", "password", "checkbox", "radio", "submit", "button"].includes(i.type)
        ) || null
      );
    }
    return null;
  }

  function setNativeValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
    descriptor.set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // SPEC §2 clear-on-failure (#101): if any field fails after earlier
  // ones were written, blank every element this call wrote before the
  // error leaves the function, so a partial fill leaves no secret in
  // the page. Same task as the writes: no other page task can run in
  // between (input/change listeners still see the value, per N1).
  // Each element is recorded before its write, so a set that throws
  // midway is cleared too; one failed clear does not stop the rest,
  // and the original refusal is what propagates.
  function clearWritten(elements) {
    for (const el of elements) {
      try {
        setNativeValue(el, "");
      } catch (_) {
        /* best effort: keep clearing the others */
      }
    }
  }

  // Leg mode (#382): the broker holds a recorded login method for this
  // page. Every step is checked against the live page here, before the
  // first write; the agent's selectors are never used. Codes carry the
  // step's index, never a value.
  function legResolve(step) {
    for (const sel of step.selectors || []) {
      let found;
      try {
        found = document.querySelectorAll(sel);
      } catch (_) {
        continue; // an invalid selector skips the candidate
      }
      if (found && found.length === 1) return found[0];
    }
    return null;
  }

  function legMatches(el, step) {
    if (!el.isConnected) return false;
    if (!(el.getClientRects().length > 0)) return false;
    if (getComputedStyle(el).visibility === "hidden") return false;
    const want = step.expect;
    if (want) {
      if (String(el.tagName).toLowerCase() !== want.tag) return false;
      if (want.input_type !== null && want.input_type !== undefined &&
          String(el.type).toLowerCase() !== want.input_type) return false;
      if (want.id !== null && want.id !== undefined && el.id !== want.id) return false;
      if (want.name !== null && want.name !== undefined && el.getAttribute("name") !== want.name) return false;
      if (want.autocomplete !== null && want.autocomplete !== undefined &&
          el.getAttribute("autocomplete") !== want.autocomplete) return false;
    }
    if (step.password === true && el.type !== "password") return false;
    return true;
  }

  const legSubmit = leg && submitRequested && leg.submit ? leg.submit : null;
  const legEls = [];
  let legClickEl = null;
  if (leg) {
    // A leg fill that throws must never leave an earlier fill's element
    // for the probe.
    try { delete globalThis.__kharonMethodPw; } catch (_) { /* already gone */ }
    if (location.pathname !== leg.path) fail("method_wrong_page");
    if (fields.length !== leg.fills.length) {
      fail("method_drift:" + (leg.fills[0] ? leg.fills[0].index : 0));
    }
    const resolved = [];
    const steps = leg.fills.slice();
    if (legSubmit && legSubmit.via === "click") steps.push(legSubmit);
    for (const step of steps) {
      const el = legResolve(step);
      if (!el || !legMatches(el, step) || resolved.includes(el)) {
        fail("method_drift:" + step.index);
      }
      resolved.push(el);
    }
    for (let i = 0; i < leg.fills.length; i++) legEls.push(resolved[i]);
    if (legSubmit && legSubmit.via === "click") legClickEl = resolved[leg.fills.length];
    if (legSubmit && !["form", "enter", "click"].includes(legSubmit.via)) {
      fail("method_drift:" + legSubmit.index);
    }
    if (legSubmit && legSubmit.via === "form") {
      const lastEl = legEls[legEls.length - 1];
      const form = lastEl ? lastEl.form || (lastEl.closest ? lastEl.closest("form") : null) : null;
      if (!form || typeof form.requestSubmit !== "function") fail("method_drift:" + legSubmit.index);
    }
    // Readiness only after every drift check has passed.
    for (let i = 0; i < legEls.length; i++) {
      if (legEls[i].matches(":disabled")) fail("method_not_ready:" + leg.fills[i].index);
    }
    if (legClickEl && legClickEl.matches(":disabled")) fail("method_not_ready:" + legSubmit.index);
  }

  const results = [];
  const written = [];
  let lastFilledElement = null;
  try {
    for (let i = 0; i < fields.length; i++) {
      const f = fields[i];
      checkBudget();
      const el = leg ? legEls[i] : resolveField(f.kind, f.selector);
      if (!el) fail("field_not_found:" + f.kind);
      // Leg mode: an earlier field's page handlers may have changed
      // this element since the pre-check.
      if (leg && (!el.isConnected || (leg.fills[i].password === true && el.type !== "password"))) {
        fail("method_drift:" + leg.fills[i].index);
      }
      written.push(el);
      setNativeValue(el, f.value);
      results.push({ kind: f.kind, filled: true });
      lastFilledElement = el;
    }
  } catch (e) {
    clearWritten(written);
    throw e;
  }

  // REQ-API-008: reachable only after every field filled — any
  // failure above threw out of the function. `requestSubmit` honors
  // constraint validation and fires one submit event; the Enter
  // fallback synthesizes what a real keyboard press delivers.
  if (leg ? legSubmit : submitRequested && lastFilledElement) {
    // The important check (#118): a submit is never *dispatched*
    // after the budget expires. Expiry here is a failure like any
    // other — the written fields are cleared before the throw.
    try {
      checkBudget();
    } catch (e) {
      clearWritten(written);
      throw e;
    }
    const last = lastFilledElement;
    const form = last ? last.form || (last.closest ? last.closest("form") : null) : null;
    if (leg && legSubmit.via === "click") {
      // Page handlers ran during the writes: re-check the target.
      if (!legClickEl.isConnected) {
        clearWritten(written);
        fail("method_drift:" + legSubmit.index);
      }
      legClickEl.click();
    } else if (leg && legSubmit.via === "form") {
      if (!form || typeof form.requestSubmit !== "function") {
        clearWritten(written);
        fail("method_drift:" + legSubmit.index);
      }
      form.requestSubmit();
    } else if (!leg && form && typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else if (last) {
      for (const type of ["keydown", "keypress", "keyup"]) {
        last.dispatchEvent(
          new KeyboardEvent(type, {
            key: "Enter",
            code: "Enter",
            keyCode: 13,
            which: 13,
            bubbles: true,
          })
        );
      }
    }
  }
  // #355: the elements this call wrote, for one later scrub in this
  // same isolated world. The page's main world cannot see this
  // global. References only — the values stay in the fields.
  if (submitRequested && scrubRequested) {
    globalThis.__kharonWritten = written.slice();
  }
  // Leg mode only: the first password element, for the loader re-read
  // to ask whether it is still in the page (METHOD_PROBE_IN_PAGE).
  if (leg) {
    let pwEl = null;
    for (let i = 0; i < leg.fills.length; i++) {
      if (leg.fills[i].password === true) { pwEl = legEls[i]; break; }
    }
    globalThis.__kharonMethodPw = pwEl;
  }
  return { results };
}
"#;

/// Leg-mode probe (#382): did the password element the last leg-mode
/// fill wrote survive the submit? Reads and deletes
/// `globalThis.__kharonMethodPw`; no value in, no value out.
///
/// Returns `{ password_connected: true | false | null }`; `null` when
/// nothing was recorded (no leg fill, or already probed).
pub const METHOD_PROBE_IN_PAGE: &str = r#"
function methodProbe() {
  "use strict";
  const el = globalThis.__kharonMethodPw;
  try { delete globalThis.__kharonMethodPw; } catch (_) { /* already gone */ }
  if (!el) return { password_connected: null };
  return { password_connected: el.isConnected === true };
}
"#;

/// Best-effort scrub of the fields a fill wrote (SPEC §6 step 4: when
/// the loader changed after a non-submit write, clear before reporting
/// `navigated`). Not used when `submit: true` caused the loader change
/// (#102). Runs in the same isolated world when it still exists;
/// failures are ignored by the caller.
pub const CLEAR_IN_PAGE: &str = r#"
function clearInPage(fields) {
  "use strict";
  function resolveField(kind, selector) {
    if (selector) return document.querySelector(selector);
    if (kind === "password") return document.querySelector('input[type="password"]');
    // Keep in step with is_otp_descriptor in crates/kharon-recording/src/classify.rs.
    if (kind === "totp") {
      return document.querySelector(
        'input[autocomplete*="one-time"], input[name*="otp" i], input[type="tel"]'
      );
    }
    if (kind === "username") {
      return (
        document.querySelector(
          'input[type="email"], input[autocomplete*="username"], input[name*="user" i]'
        ) || null
      );
    }
    return null;
  }
  for (const f of fields) {
    const el = resolveField(f.kind, f.selector);
    if (!el) continue;
    const proto = el instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, "");
  }
  return { cleared: true };
}
"#;

/// One post-submit clear of the elements [`FILL_IN_PAGE`] recorded
/// (#355, REQ-API-013). Runs in the same isolated world, once, after
/// the broker's delay.
///
/// Argument: `expected`, the values this fill wrote, in write order.
/// An element is cleared only when it is still connected and its
/// current value is still exactly `expected[i]` — a value the page or
/// the user has changed is left alone. The clear is the native setter
/// plus `input` and `change`, the same shape as clear-on-failure, so a
/// framework that listened to the write also sees the clear. The
/// recorded list is dropped, so a second call clears nothing.
///
/// Returns `{ cleared, checked }`. `cleared` is how many elements were
/// blanked; `checked` is how many were recorded. Neither is a value.
pub const SCRUB_WRITTEN_IN_PAGE: &str = r#"
function scrubWritten(expected) {
  "use strict";
  const written = Array.isArray(globalThis.__kharonWritten) ? globalThis.__kharonWritten : [];
  try { delete globalThis.__kharonWritten; } catch (_) { /* already gone */ }

  function setNativeValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
    if (!descriptor || typeof descriptor.set !== "function") return false;
    descriptor.set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  }

  const list = Array.isArray(expected) ? expected : [];
  let cleared = 0;
  for (let i = 0; i < written.length; i++) {
    const el = written[i];
    if (!el || el.isConnected === false) continue;
    if (typeof el.value !== "string" || typeof list[i] !== "string") continue;
    if (el.value !== list[i]) continue;
    try {
      if (setNativeValue(el, "")) cleared++;
    } catch (_) {
      /* best effort: keep clearing the others */
    }
  }
  for (let i = 0; i < list.length; i++) list[i] = "";
  return { cleared: cleared, checked: written.length };
}
"#;

/// Value-free count of recorded elements that are still connected and
/// non-empty (#355 review). The broker sends the written values only
/// when this count is above zero. Does not clear and does not drop the
/// recorded list: [`SCRUB_WRITTEN_IN_PAGE`] still owns that.
///
/// Returns `{ held }`. No values in, no values out.
pub const PROBE_WRITTEN_IN_PAGE: &str = r#"
function probeWritten() {
  "use strict";
  const written = Array.isArray(globalThis.__kharonWritten) ? globalThis.__kharonWritten : [];
  let held = 0;
  for (const el of written) {
    if (!el || el.isConnected === false) continue;
    if (typeof el.value === "string" && el.value !== "") held++;
  }
  return { held: held };
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// The fill function must be a self-contained function declaration
    /// (callFunctionOn needs a parseable expression) and must never
    /// leak the secret into a global.
    #[test]
    fn fill_script_is_function_declaration() {
        let trimmed = FILL_IN_PAGE.trim_start();
        assert!(trimmed.starts_with("function fillInPage("), "{trimmed:.60}");
        assert!(!FILL_IN_PAGE.contains("document.title ="), "leak probe");
        // Codes the broker depends on (message is "kharon:" + code):
        for code in [
            "origin_mismatch",
            "non_secure",
            "field_not_found",
            "deadline",
            "method_wrong_page",
            "method_drift",
            "method_not_ready",
        ] {
            assert!(FILL_IN_PAGE.contains(code), "missing {code}");
        }
    }

    /// Regression (review finding 2): the top-frame origin check must
    /// actually fire. Executes the shipped `FILL_IN_PAGE` verbatim in
    /// node against a stubbed DOM: a same-origin-readable top frame
    /// whose origin differs from the broker-observed one must refuse
    /// with `origin_mismatch` and write nothing; a matching top must
    /// fill. Skipped (with a note) when node is not on PATH.
    #[test]
    fn req_org_003_top_frame_check_pins() {
        let mut script = String::new();
        script.push_str(
            r#"
class HTMLInputElement { constructor() { this._v = ""; } dispatchEvent() {} }
Object.defineProperty(HTMLInputElement.prototype, "value", {
  get() { return this._v; },
  set(v) { this._v = v; },
});
class HTMLTextAreaElement extends HTMLInputElement {}
class Event { constructor(type, opts) { this.type = type; this.bubbles = !!(opts && opts.bubbles); } }
"#,
        );
        script.push_str(FILL_IN_PAGE);
        script.push_str(
            r#"
const specs = [{ kind: "host", scheme: "https", origin: "https://accounts.example.com" }];
const fields = [{ kind: "password", selector: null, value: "s3cret" }];

function setEnv(topOrigin) {
  const el = new HTMLInputElement();
  globalThis.window = { isSecureContext: true, top: { location: { origin: topOrigin } } };
  globalThis.location = {
    protocol: "https:",
    hostname: "accounts.example.com",
    origin: "https://accounts.example.com",
    href: "https://accounts.example.com/login",
  };
  globalThis.document = {
    querySelector: (sel) => (sel.includes("password") ? el : null),
  };
  return el;
}

// 1. Readable top with a wrong origin: must refuse, must not write.
let el = setEnv("https://evil.example");
let outcome = "returned";
try {
  fillInPage(specs, fields, "https://accounts.example.com");
} catch (e) {
  outcome = (e && e.kharonCode) || e.message;
}
if (outcome !== "origin_mismatch") {
  throw new Error(`top-check did not fire: got ${outcome}`);
}
if (el._v !== "") throw new Error("secret was written despite refusal");

// 2. Matching top origin: must fill and report both fields.
el = setEnv("https://accounts.example.com");
const r = fillInPage(specs, fields, "https://accounts.example.com");
if (r.results.length !== 1 || r.results[0].kind !== "password" || r.results[0].filled !== true) {
  throw new Error(`unexpected results: ${JSON.stringify(r)}`);
}
if (el._v !== "s3cret") throw new Error(`value not set: ${el._v}`);
console.log("ok");
"#,
        );

        let mut path = std::env::temp_dir();
        path.push(format!("kharon_fill_topcheck_{}.js", std::process::id()));
        std::fs::write(&path, &script).expect("write harness");
        let output = std::process::Command::new("node").arg(&path).output();
        let _ = std::fs::remove_file(&path);
        let output = match output {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("node not on PATH; skipping top-frame harness test");
                return;
            }
            Err(e) => panic!("spawn node: {e}"),
        };
        assert!(
            output.status.success(),
            "harness failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("ok"));
    }

    /// REQ-API-008: submit is dispatched exactly once, and only when
    /// every field filled. Executes the shipped `FILL_IN_PAGE`
    /// verbatim against a stubbed DOM, covering three cases:
    ///   A. all fields present + submit=true → one requestSubmit,
    ///      after both values are written (event order checked);
    ///   B. a field missing + submit=true → no submit at all, and the
    ///      field written before the miss is cleared again (SPEC §2
    ///      clear-on-failure, #101);
    ///   C. no form on the last element → Enter fallback delivers
    ///      keydown/keypress/keyup on that element.
    #[test]
    fn req_api_008_submit_once_after_all_filled() {
        let mut script = String::new();
        script.push_str(
            r#"
class HTMLInputElement {
  constructor(name) {
    this._v = "";
    this.name = name;
    this.events = [];
    this.form = null;
  }
  dispatchEvent(ev) { this.events.push(ev); return true; }
  closest() { return null; }
}
Object.defineProperty(HTMLInputElement.prototype, "value", {
  get() { return this._v; },
  set(v) { this._v = v; },
});
class HTMLTextAreaElement extends HTMLInputElement {}
class Event { constructor(type, opts) { this.type = type; this.bubbles = !!(opts && opts.bubbles); } }
class KeyboardEvent extends Event {
  constructor(type, opts) { super(type, opts);
    this.key = opts.key; this.code = opts.code; this.keyCode = opts.keyCode; this.which = opts.which;
  }
}
"#,
        );
        script.push_str(FILL_IN_PAGE);
        script.push_str(
            r#"
const specs = [{ kind: "host", scheme: "https", origin: "https://accounts.example.com" }];
const origin = "https://accounts.example.com";
const originEnv = () => {
  globalThis.window = { isSecureContext: true, top: { location: { origin: origin } } };
  globalThis.location = {
    protocol: "https:", hostname: "accounts.example.com", origin, href: origin + "/login",
  };
};

// A. requestSubmit once, after all fills.
{
  originEnv();
  const userEl = new HTMLInputElement("user");
  const passEl = new HTMLInputElement("pass");
  let submits = 0;
  const form = { requestSubmit: () => { submits += 1; } };
  userEl.form = form;
  passEl.form = form;
  globalThis.document = {
    querySelector: (sel) => {
      if (sel.includes("password")) return passEl;
      if (sel.includes("email") || sel.includes("username")) return userEl;
      return null;
    },
  };
  const fields = [
    { kind: "username", selector: null, value: "alice" },
    { kind: "password", selector: null, value: "s3cret" },
  ];
  const r = fillInPage(specs, fields, origin, true);
  if (submits !== 1) throw new Error(`expected exactly one submit, got ${submits}`);
  if (r.results.length !== 2) throw new Error(`expected two results: ${JSON.stringify(r)}`);
  if (userEl._v !== "alice" || passEl._v !== "s3cret") throw new Error("values not written before submit");
  console.log("case A ok");
}

// B. missing field: no submit.
{
  originEnv();
  const userEl = new HTMLInputElement("user");
  let submits = 0;
  const form = { requestSubmit: () => { submits += 1; } };
  userEl.form = form;
  globalThis.document = {
    querySelector: (sel) =>
      sel.includes("email") || sel.includes("username") ? userEl : null,
  };
  const fields = [
    { kind: "username", selector: null, value: "alice" },
    { kind: "password", selector: null, value: "s3cret" },
  ];
  let code = "none";
  try {
    fillInPage(specs, fields, origin, true);
  } catch (e) { code = (e && e.kharonCode) || e.message; }
  if (code !== "field_not_found:password") throw new Error(`expected field_not_found, got ${code}`);
  if (submits !== 0) throw new Error("submit dispatched despite missing field");
  // SPEC §2 clear-on-failure (#101): the username written before the
  // missing password must be blanked, with events so page state sees it.
  if (userEl._v !== "") throw new Error(`partial fill left a value: ${userEl._v}`);
  const seq = userEl.events.map((e) => e.type).join(",");
  if (seq !== "input,change,input,change") throw new Error(`unexpected clear events: ${seq}`);
  console.log("case B ok");
}

// C. no form: Enter fallback on the last element.
{
  originEnv();
  const passEl = new HTMLInputElement("pass"); // form stays null
  globalThis.document = { querySelector: (sel) => (sel.includes("password") ? passEl : null) };
  const fields = [{ kind: "password", selector: null, value: "s3cret" }];
  const r = fillInPage(specs, fields, origin, true);
  const types = passEl.events.map((e) => e.type).join(",");
  if (types !== "input,change,keydown,keypress,keyup")
    throw new Error(`unexpected event sequence: ${types}`);
  for (const ev of passEl.events) {
    if (ev.type.startsWith("key") && (ev.key !== "Enter" || ev.keyCode !== 13 || !ev.bubbles))
      throw new Error(`bad keyboard event: ${JSON.stringify(ev)}`);
  }
  if (r.results.length !== 1) throw new Error(`unexpected results: ${JSON.stringify(r)}`);
  console.log("case C ok");
}
console.log("ok");
"#,
        );

        let mut path = std::env::temp_dir();
        path.push(format!("kharon_fill_submit_{}.js", std::process::id()));
        std::fs::write(&path, &script).expect("write harness");
        let output = std::process::Command::new("node").arg(&path).output();
        let _ = std::fs::remove_file(&path);
        let output = match output {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("node not on PATH; skipping submit harness test");
                return;
            }
            Err(e) => panic!("spawn node: {e}"),
        };
        assert!(
            output.status.success(),
            "harness failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for case in ["case A ok", "case B ok", "case C ok"] {
            assert!(stdout.contains(case), "missing {case} in {stdout}");
        }
    }

    /// REQ-API-009 page-side budget (#118, test plan in #117 §6):
    /// executes the shipped `FILL_IN_PAGE` verbatim in node against a
    /// stubbed DOM whose `performance.now()` is fake. The first
    /// field's `input` handler advances the clock (a slow page handler
    /// runs inside the fill task — the window this budget narrows).
    ///   A. handler pushes the clock past the budget mid-fill → the
    ///      later field is never written, the written field is
    ///      cleared, submit is never dispatched, code is `deadline`;
    ///   B. clock held under budget → fill + submit complete;
    ///   C. budget exhausted only after the last write (handler on
    ///      the last field) → the pre-submit check fires: fields
    ///      cleared, no submit, code is `deadline`;
    ///   D. no budget argument (0) → no check at all, however far the
    ///      clock has run.
    #[test]
    fn req_api_009_page_side_budget() {
        let mut script = String::new();
        script.push_str(
            r#"
class HTMLInputElement {
  constructor(name) {
    this._v = "";
    this.name = name;
    this.events = [];
    this.form = null;
    this.onInput = null;
  }
  dispatchEvent(ev) {
    this.events.push(ev);
    if (ev.type === "input" && this.onInput) this.onInput();
    return true;
  }
  closest() { return null; }
}
Object.defineProperty(HTMLInputElement.prototype, "value", {
  get() { return this._v; },
  set(v) { this._v = v; },
});
class HTMLTextAreaElement extends HTMLInputElement {}
class Event { constructor(type, opts) { this.type = type; this.bubbles = !!(opts && opts.bubbles); } }
class KeyboardEvent extends Event {
  constructor(type, opts) { super(type, opts);
    this.key = opts.key; this.code = opts.code; this.keyCode = opts.keyCode; this.which = opts.which;
  }
}
"#,
        );
        script.push_str(FILL_IN_PAGE);
        script.push_str(
            r#"
const specs = [{ kind: "host", scheme: "https", origin: "https://accounts.example.com" }];
const origin = "https://accounts.example.com";
let now = 0;
globalThis.performance = { now: () => now };

function setEnv(advanceOn, advanceBy) {
  now = 0;
  globalThis.window = { isSecureContext: true, top: { location: { origin } } };
  globalThis.location = {
    protocol: "https:", hostname: "accounts.example.com", origin, href: origin + "/login",
  };
  const userEl = new HTMLInputElement("user");
  const passEl = new HTMLInputElement("pass");
  let submits = 0;
  const form = { requestSubmit: () => { submits += 1; } };
  userEl.form = form;
  passEl.form = form;
  if (advanceOn === "user") userEl.onInput = () => { now += advanceBy; };
  if (advanceOn === "pass") passEl.onInput = () => { now += advanceBy; };
  globalThis.document = {
    querySelector: (sel) => {
      if (sel.includes("password")) return passEl;
      if (sel.includes("email") || sel.includes("username")) return userEl;
      return null;
    },
  };
  return { userEl, passEl, submits: () => submits };
}
const fields = [
  { kind: "username", selector: null, value: "alice" },
  { kind: "password", selector: null, value: "s3cret" },
];
function attempt(budget) {
  try {
    const r = fillInPage(specs, fields, origin, true, budget);
    return { code: "returned", results: r.results.length };
  } catch (e) {
    return { code: (e && e.kharonCode) || e.message, results: 0 };
  }
}

// A. First field's handler runs the clock past the budget.
{
  const env = setEnv("user", 1000);
  const out = attempt(100);
  if (out.code !== "deadline") throw new Error(`A: expected deadline, got ${out.code}`);
  if (env.passEl._v !== "") throw new Error(`A: later field written: ${env.passEl._v}`);
  if (env.userEl._v !== "") throw new Error(`A: written field not cleared: ${env.userEl._v}`);
  if (env.submits() !== 0) throw new Error("A: submit dispatched after expiry");
  console.log("case A ok");
}

// B. Under budget: fill and submit complete.
{
  const env = setEnv("user", 10);
  const out = attempt(1000);
  if (out.code !== "returned" || out.results !== 2) throw new Error(`B: ${JSON.stringify(out)}`);
  if (env.userEl._v !== "alice" || env.passEl._v !== "s3cret") throw new Error("B: values missing");
  if (env.submits() !== 1) throw new Error(`B: submits ${env.submits()}`);
  console.log("case B ok");
}

// C. Budget expires during the last field's handler: pre-submit check.
{
  const env = setEnv("pass", 1000);
  const out = attempt(100);
  if (out.code !== "deadline") throw new Error(`C: expected deadline, got ${out.code}`);
  if (env.submits() !== 0) throw new Error("C: submit dispatched after expiry");
  if (env.userEl._v !== "" || env.passEl._v !== "") throw new Error("C: fields not cleared");
  console.log("case C ok");
}

// D. No budget: the clock is irrelevant.
{
  const env = setEnv("user", 100000);
  const out = attempt(0);
  if (out.code !== "returned" || out.results !== 2) throw new Error(`D: ${JSON.stringify(out)}`);
  if (env.submits() !== 1) throw new Error(`D: submits ${env.submits()}`);
  console.log("case D ok");
}
console.log("ok");
"#,
        );

        let mut path = std::env::temp_dir();
        path.push(format!("kharon_fill_budget_{}.js", std::process::id()));
        std::fs::write(&path, &script).expect("write harness");
        let output = std::process::Command::new("node").arg(&path).output();
        let _ = std::fs::remove_file(&path);
        let output = match output {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("node not on PATH; skipping budget harness test");
                return;
            }
            Err(e) => panic!("spawn node: {e}"),
        };
        assert!(
            output.status.success(),
            "harness failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for case in ["case A ok", "case B ok", "case C ok", "case D ok"] {
            assert!(stdout.contains(case), "missing {case} in {stdout}");
        }
    }

    /// #355: the scrub clears only the elements this fill recorded,
    /// only while they still hold the written value, and dispatches
    /// `input` and `change`. A second call is a no-op (the list is
    /// dropped). A fill that did not ask to record leaves the fields.
    #[test]
    fn req_api_013_scrub_clears_recorded_elements_only() {
        let mut script = String::new();
        script.push_str(
            r#"
class HTMLInputElement {
  constructor(name) {
    this._v = "";
    this.name = name;
    this.events = [];
    this.form = null;
    this.isConnected = true;
  }
  dispatchEvent(ev) { this.events.push(ev.type); return true; }
  closest() { return null; }
}
Object.defineProperty(HTMLInputElement.prototype, "value", {
  get() { return this._v; },
  set(v) { this._v = v; },
});
class HTMLTextAreaElement extends HTMLInputElement {}
class Event { constructor(type, opts) { this.type = type; this.bubbles = !!(opts && opts.bubbles); } }
class KeyboardEvent extends Event {
  constructor(type, opts) { super(type, opts); this.key = opts.key; this.keyCode = opts.keyCode; }
}
"#,
        );
        script.push_str(FILL_IN_PAGE);
        script.push_str(SCRUB_WRITTEN_IN_PAGE);
        script.push_str(PROBE_WRITTEN_IN_PAGE);
        script.push_str(
            r#"
const specs = [{ kind: "host", scheme: "https", origin: "https://accounts.example.com" }];
const origin = "https://accounts.example.com";
function originEnv() {
  globalThis.window = { isSecureContext: true, top: { location: { origin } } };
  globalThis.location = {
    protocol: "https:", hostname: "accounts.example.com", origin, href: origin + "/login",
  };
}
function eventsOf(el) { return el.events.join(","); }

// A. Both written fields still hold the value: both clear, with
//    input+change. A decoy password the fill did not write stays.
{
  originEnv();
  delete globalThis.__kharonWritten;
  const userEl = new HTMLInputElement("user");
  const passEl = new HTMLInputElement("pass");
  const decoy = new HTMLInputElement("decoy");
  decoy._v = "s3cret";
  const form = { requestSubmit() {} };
  userEl.form = form;
  passEl.form = form;
  globalThis.document = {
    querySelector: (sel) => {
      if (sel.includes("password")) return passEl;
      if (sel.includes("email") || sel.includes("username")) return userEl;
      return null;
    },
  };
  fillInPage(specs, [
    { kind: "username", selector: null, value: "alice" },
    { kind: "password", selector: null, value: "s3cret" },
  ], origin, true, 0, true);
  const before = eventsOf(passEl);
  const r = scrubWritten(["alice", "s3cret"]);
  if (r.cleared !== 2 || r.checked !== 2) throw new Error("A: " + JSON.stringify(r));
  if (userEl._v !== "" || passEl._v !== "") throw new Error("A: values left");
  if (decoy._v !== "s3cret") throw new Error("A: decoy was cleared");
  if (eventsOf(userEl) !== "input,change,input,change") throw new Error("A user events: " + eventsOf(userEl));
  if (eventsOf(passEl) !== before + ",input,change") throw new Error("A pass events: " + eventsOf(passEl));
  // The user types the password back. A second scrub must not clear it.
  passEl._v = "s3cret";
  const again = scrubWritten(["alice", "s3cret"]);
  if (again.cleared !== 0 || again.checked !== 0) throw new Error("A second: " + JSON.stringify(again));
  if (passEl._v !== "s3cret") throw new Error("A: second scrub cleared");
  console.log("case A ok");
}

// B. The password was edited after the fill: leave it, clear the
//    username that still matches. No events on the edited field.
{
  originEnv();
  delete globalThis.__kharonWritten;
  const userEl = new HTMLInputElement("user");
  const passEl = new HTMLInputElement("pass");
  const form = { requestSubmit() {} };
  userEl.form = form;
  passEl.form = form;
  globalThis.document = {
    querySelector: (sel) => {
      if (sel.includes("password")) return passEl;
      if (sel.includes("email") || sel.includes("username")) return userEl;
      return null;
    },
  };
  fillInPage(specs, [
    { kind: "username", selector: null, value: "alice" },
    { kind: "password", selector: null, value: "s3cret" },
  ], origin, true, 0, true);
  passEl._v = "s3cret-edited";
  passEl.events = [];
  const r = scrubWritten(["alice", "s3cret"]);
  if (r.cleared !== 1) throw new Error("B: " + JSON.stringify(r));
  if (userEl._v !== "") throw new Error("B: username left");
  if (passEl._v !== "s3cret-edited") throw new Error("B: edited password cleared");
  if (passEl.events.length !== 0) throw new Error("B: events on the edited field");
  console.log("case B ok");
}

// C. A disconnected node is not cleared (the page replaced it).
{
  originEnv();
  delete globalThis.__kharonWritten;
  const passEl = new HTMLInputElement("pass");
  const form = { requestSubmit() {} };
  passEl.form = form;
  globalThis.document = { querySelector: (sel) => (sel.includes("password") ? passEl : null) };
  fillInPage(specs, [{ kind: "password", selector: null, value: "s3cret" }], origin, true, 0, true);
  passEl.isConnected = false;
  const r = scrubWritten(["s3cret"]);
  if (r.cleared !== 0) throw new Error("C: " + JSON.stringify(r));
  if (passEl._v !== "s3cret") throw new Error("C: detached node cleared");
  console.log("case C ok");
}

// D. scrubRequested false: nothing is recorded, so the scrub clears nothing.
{
  originEnv();
  delete globalThis.__kharonWritten;
  const passEl = new HTMLInputElement("pass");
  const form = { requestSubmit() {} };
  passEl.form = form;
  globalThis.document = { querySelector: (sel) => (sel.includes("password") ? passEl : null) };
  fillInPage(specs, [{ kind: "password", selector: null, value: "s3cret" }], origin, true, 0, false);
  const r = scrubWritten(["s3cret"]);
  if (r.cleared !== 0 || r.checked !== 0) throw new Error("D: " + JSON.stringify(r));
  if (passEl._v !== "s3cret") throw new Error("D: unrecorded field cleared");
  console.log("case D ok");
}

// E. The probe counts connected non-empty fields and does not clear
//    or drop the recorded list. An emptied form reports zero, so the
//    broker need not send the values again.
{
  originEnv();
  delete globalThis.__kharonWritten;
  const userEl = new HTMLInputElement("user");
  const passEl = new HTMLInputElement("pass");
  const form = { requestSubmit() {} };
  userEl.form = form;
  passEl.form = form;
  globalThis.document = {
    querySelector: (sel) => {
      if (sel.includes("password")) return passEl;
      if (sel.includes("email") || sel.includes("username")) return userEl;
      return null;
    },
  };
  fillInPage(specs, [
    { kind: "username", selector: null, value: "alice" },
    { kind: "password", selector: null, value: "s3cret" },
  ], origin, true, 0, true);
  if (probeWritten().held !== 2) throw new Error("E: expected two held");
  userEl._v = "";
  passEl._v = "";
  const events = passEl.events.length;
  if (probeWritten().held !== 0) throw new Error("E: emptied form still held");
  if (passEl.events.length !== events) throw new Error("E: probe dispatched an event");
  if (userEl._v !== "" || passEl._v !== "") throw new Error("E: probe wrote a value");
  passEl._v = "s3cret";
  const r = scrubWritten(["alice", "s3cret"]);
  if (r.cleared !== 1 || passEl._v !== "") throw new Error("E: list was dropped by the probe");
  console.log("case E ok");
}
console.log("ok");
"#,
        );

        let mut path = std::env::temp_dir();
        path.push(format!("kharon_fill_scrub_{}.js", std::process::id()));
        std::fs::write(&path, &script).expect("write harness");
        let output = std::process::Command::new("node").arg(&path).output();
        let _ = std::fs::remove_file(&path);
        let output = match output {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("node not on PATH; skipping scrub harness test");
                return;
            }
            Err(e) => panic!("spawn node: {e}"),
        };
        assert!(
            output.status.success(),
            "harness failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        for case in [
            "case A ok",
            "case B ok",
            "case C ok",
            "case D ok",
            "case E ok",
        ] {
            assert!(stdout.contains(case), "missing {case} in {stdout}");
        }
    }

    // ---- leg mode (teach mode piece 2, #382) -------------------------

    /// DOM stub shared by the leg-mode harness cases. Elements carry
    /// what the pre-check reads; `document.querySelectorAll` is backed
    /// by a map and throws for selectors registered as invalid.
    const LEG_PRELUDE: &str = r##"
const LOG = [];
class HTMLInputElement {
  constructor(o) {
    o = o || {};
    this._v = "";
    this.tagName = (o.tag || "INPUT").toUpperCase();
    this.type = o.type || "text";
    this.id = o.id || "";
    this._attrs = { name: o.name === undefined ? null : o.name, autocomplete: o.autocomplete === undefined ? null : o.autocomplete };
    this.isConnected = true;
    this.disabled = !!o.disabled;
    this.form = o.form || null;
    this.rects = o.rects === undefined ? 1 : o.rects;
    this.visibility = "visible";
    this.events = [];
    this.clicks = 0;
    this.label = o.label || this.id;
    this.onInput = null;
  }
  get name() { return this._attrs.name; }
  set name(v) { this._attrs.name = v; }
  getAttribute(n) { return Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
  getClientRects() { return { length: this.rects }; }
  matches(s) { return s === ":disabled" ? this.disabled : false; }
  click() { this.clicks += 1; LOG.push("click:" + this.label); }
  closest() { return null; }
  dispatchEvent(ev) {
    this.events.push(ev);
    if (ev.type === "input") { LOG.push("input:" + this.label); if (this.onInput) this.onInput(); }
    return true;
  }
}
Object.defineProperty(HTMLInputElement.prototype, "value", {
  get() { return this._v; },
  set(v) { this._v = v; },
});
class HTMLTextAreaElement extends HTMLInputElement {}
class Event { constructor(type, opts) { this.type = type; this.bubbles = !!(opts && opts.bubbles); } }
class KeyboardEvent extends Event {
  constructor(type, opts) { super(type, opts); this.key = opts.key; }
}
let CLOCK = 0;
globalThis.performance = { now: () => CLOCK };
globalThis.getComputedStyle = (el) => ({ visibility: el.visibility });
const origin = "https://accounts.example.com";
const specs = [{ kind: "host", scheme: "https", origin }];
function env(pathname, map, invalid) {
  globalThis.window = { isSecureContext: true, top: { location: { origin } } };
  globalThis.location = { protocol: "https:", hostname: "accounts.example.com", origin, href: origin + pathname, pathname };
  globalThis.document = {
    querySelectorAll: (sel) => {
      if (invalid && invalid.includes(sel)) throw new Error("SyntaxError " + sel);
      return map.get(sel) || [];
    },
    querySelector: () => null,
  };
}
const ex = (tag, type, id, name) => ({ tag, input_type: type, id, name, autocomplete: null });
class Page {
  constructor() {
    this.form = { submits: 0, requestSubmit() { this.submits += 1; } };
    this.u = new HTMLInputElement({ id: "u", name: "user", type: "text", form: this.form });
    this.pw = new HTMLInputElement({ id: "pw", name: "pass", type: "password", form: this.form });
    this.btn = new HTMLInputElement({ tag: "button", id: "go", type: "submit", form: this.form });
    this.map = new Map([["#u", [this.u]], ["#pw", [this.pw]], ["#go", [this.btn]]]);
    this.fills = [
      { index: 0, selectors: ["#u"], password: false, expect: ex("input", "text", "u", "user") },
      { index: 1, selectors: ["#pw"], password: true, expect: ex("input", "password", "pw", "pass") },
    ];
    this.submit = { index: 2, via: "form", selectors: [], expect: null };
    this.path = "/login";
  }
  leg() { return { path: this.path, fills: this.fills, submit: this.submit }; }
  fields() {
    return [
      { kind: "username", selector: null, value: "alice" },
      { kind: "password", selector: null, value: "s3cret" },
    ];
  }
  run(submit, budget) {
    env("/login", this.map, this.invalid);
    return fillInPage(specs, this.fields(), origin, submit, budget || 0, false, this.leg());
  }
  code(submit, budget) {
    try { this.run(submit, budget); } catch (e) { return (e && e.kharonCode) || e.message; }
    return "returned";
  }
  untouched() {
    for (const el of [this.u, this.pw, this.btn]) {
      if (el._v !== "") throw new Error("value written on " + el.id);
      if (el.events.length) throw new Error("event on " + el.id);
      if (el.clicks) throw new Error("click on " + el.id);
    }
    if (this.form.submits) throw new Error("submit dispatched");
  }
}
function eq(a, b, what) { if (a !== b) throw new Error(`${what}: expected ${b}, got ${a}`); }
"##;

    fn run_leg_harness(tag: &str, cases: &str) {
        let mut script = String::new();
        script.push_str(LEG_PRELUDE);
        script.push_str(FILL_IN_PAGE);
        script.push_str(METHOD_PROBE_IN_PAGE);
        script.push_str(cases);
        script.push_str("\nconsole.log(\"ok\");\n");
        let mut path = std::env::temp_dir();
        path.push(format!("kharon_leg_{tag}_{}.js", std::process::id()));
        std::fs::write(&path, &script).expect("write harness");
        let output = std::process::Command::new("node").arg(&path).output();
        let _ = std::fs::remove_file(&path);
        let output = match output {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("node not on PATH; skipping leg harness test {tag}");
                return;
            }
            Err(e) => panic!("spawn node: {e}"),
        };
        assert!(
            output.status.success(),
            "harness {tag} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("ok"));
    }

    #[test]
    fn req_tch_008_precheck_passes_and_fills_on_a_matching_page() {
        run_leg_harness(
            "pass",
            r##"
const p = new Page();
const r = p.run(true);
eq(p.u._v, "alice", "user"); eq(p.pw._v, "s3cret", "pw");
eq(p.form.submits, 1, "submits");
eq(r.results.map((x) => x.kind).join(","), "username,password", "order");
eq(globalThis.__kharonMethodPw, p.pw, "recorded pw element");
"##,
        );
    }

    #[test]
    fn req_tch_008_each_drift_case_throws_before_any_write() {
        run_leg_harness(
            "drift",
            r##"
const cases = {
  gone: [(p) => p.map.delete("#pw"), "method_drift:1"],
  two_matches: [(p) => p.map.set("#pw", [p.pw, new HTMLInputElement({ type: "password" })]), "method_drift:1"],
  renamed: [(p) => { p.pw.name = "pw2"; }, "method_drift:1"],
  changed_type: [(p) => { p.pw.type = "text"; }, "method_drift:1"],
  no_rects: [(p) => { p.u.rects = 0; }, "method_drift:0"],
  visibility: [(p) => { p.pw.visibility = "hidden"; }, "method_drift:1"],
  wrong_tag: [(p) => { p.u.tagName = "TEXTAREA"; }, "method_drift:0"],
  disconnected: [(p) => { p.pw.isConnected = false; }, "method_drift:1"],
  same_element: [(p) => {
    p.map.set("#u", [p.pw]);
    p.fills[0].expect = ex("input", null, null, null);
  }, "method_drift:1"],
  form_missing: [(p) => { p.pw.form = null; }, "method_drift:2"],
};
for (const [name, [mutate, want]] of Object.entries(cases)) {
  const p = new Page();
  mutate(p);
  eq(p.code(true), want, name);
  p.untouched();
}
// a password step whose element is not a password field drifts even
// when the recorded expectation says otherwise
{
  const p = new Page();
  p.fills[1].expect = ex("input", null, "pw", "pass");
  p.pw.type = "text";
  eq(p.code(true), "method_drift:1", "password:true forces type");
  p.untouched();
}
"##,
        );
    }

    #[test]
    fn req_tch_008_second_candidate_selector_is_used() {
        run_leg_harness(
            "second",
            r##"
const p = new Page();
const other = new HTMLInputElement({ id: "x" });
p.map.set("#a", [p.pw, other]);
p.map.set("#b", [p.pw]);
p.fills[1].selectors = ["#a", "#b"];
p.run(false);
eq(p.pw._v, "s3cret", "second candidate's element filled");
eq(other._v, "", "ambiguous candidate untouched");
"##,
        );
    }

    #[test]
    fn req_tch_008_an_invalid_selector_is_skipped_not_an_error() {
        run_leg_harness(
            "invalid",
            r##"
{
  const p = new Page();
  p.invalid = ["!!bad"];
  p.fills[1].selectors = ["!!bad", "#pw"];
  p.run(false);
  eq(p.pw._v, "s3cret", "next candidate used");
}
{
  const p = new Page();
  p.invalid = ["!!bad", "??bad"];
  p.fills[1].selectors = ["!!bad", "??bad"];
  eq(p.code(false), "method_drift:1", "all throw");
  p.untouched();
}
"##,
        );
    }

    #[test]
    fn req_tch_008_wrong_path_throws_method_wrong_page_before_any_write() {
        run_leg_harness(
            "path",
            r##"
const p = new Page();
p.path = "/other";
eq(p.code(true), "method_wrong_page", "wrong page");
p.untouched();
"##,
        );
    }

    #[test]
    fn req_tch_008_disabled_field_is_not_ready_and_drift_wins() {
        run_leg_harness(
            "ready",
            r##"
{
  const p = new Page();
  p.pw.disabled = true;
  eq(p.code(true), "method_not_ready:1", "disabled");
  p.untouched();
}
{
  const p = new Page();
  p.u.rects = 0;      // step 0 drifted
  p.pw.disabled = true; // step 1 not ready
  eq(p.code(true), "method_drift:0", "drift wins");
  p.untouched();
}
"##,
        );
    }

    #[test]
    fn req_api_008_click_submit_fires_once_and_only_after_every_field() {
        run_leg_harness(
            "click",
            r##"
{
  const p = new Page();
  p.submit = { index: 2, via: "click", selectors: ["#go"], expect: ex("button", "submit", "go", null) };
  p.run(true);
  eq(p.btn.clicks, 1, "click count");
  eq(p.form.submits, 0, "no requestSubmit for click");
  const log = LOG.join(",");
  eq(log, "input:u,input:pw,click:go", "order");
}
{
  const p = new Page();
  p.submit = { index: 2, via: "click", selectors: ["#go"], expect: null };
  p.pw.onInput = () => { CLOCK += 1000; };
  eq(p.code(true, 100), "deadline", "budget on last field");
  eq(p.btn.clicks, 0, "no click after expiry");
  eq(p.u._v, "", "user cleared"); eq(p.pw._v, "", "pw cleared");
}
{
  // submit not requested: neither dispatched nor pre-checked
  const p = new Page();
  p.submit = { index: 2, via: "click", selectors: ["#missing"], expect: null };
  p.run(false);
  eq(p.btn.clicks, 0, "no click");
}
{
  // click target gone: drift at the submit index
  const p = new Page();
  p.submit = { index: 2, via: "click", selectors: ["#missing"], expect: null };
  eq(p.code(true), "method_drift:2", "click target gone");
  p.untouched();
}
"##,
        );
    }

    #[test]
    fn req_tch_008_agent_selector_is_not_used_in_leg_mode() {
        run_leg_harness(
            "decoy",
            r##"
const p = new Page();
const decoy = new HTMLInputElement({ id: "decoy" });
p.map.set("#decoy", [decoy]);
env("/login", p.map);
const fields = p.fields();
fields[0].selector = "#decoy";
fields[1].selector = "#decoy";
fillInPage(specs, fields, origin, false, 0, false, p.leg());
eq(decoy._v, "", "decoy untouched");
eq(p.u._v, "alice", "recorded user");
eq(p.pw._v, "s3cret", "recorded pw");
"##,
        );
    }

    #[test]
    fn method_probe_reports_and_forgets() {
        run_leg_harness(
            "probe",
            r##"
eq(methodProbe().password_connected, null, "nothing recorded");
{
  const p = new Page();
  p.run(false);
  eq(methodProbe().password_connected, true, "connected");
  eq(methodProbe().password_connected, null, "forgotten");
}
{
  const p = new Page();
  p.run(false);
  p.pw.isConnected = false;
  eq(methodProbe().password_connected, false, "disconnected");
  eq(methodProbe().password_connected, null, "forgotten again");
}
"##,
        );
    }

    #[test]
    fn req_tch_008_page_handlers_cannot_defeat_the_precheck_mid_fill() {
        run_leg_harness(
            "midfill",
            r##"
{
  // the form is detached by the password field's input handler
  const p = new Page();
  p.pw.onInput = () => { p.pw.form = null; p.u.form = null; };
  eq(p.code(true), "method_drift:2", "form detached");
  eq(p.u._v, "", "user cleared"); eq(p.pw._v, "", "pw cleared");
  eq(p.form.submits, 0, "no submit");
}
{
  // requestSubmit clobbered
  const p = new Page();
  p.pw.onInput = () => { p.form.requestSubmit = undefined; };
  eq(p.code(true), "method_drift:2", "requestSubmit gone");
  eq(p.pw._v, "", "pw cleared");
}
{
  // click target detached
  const p = new Page();
  p.submit = { index: 2, via: "click", selectors: ["#go"], expect: null };
  p.pw.onInput = () => { p.btn.isConnected = false; };
  eq(p.code(true), "method_drift:2", "button detached");
  eq(p.btn.clicks, 0, "no click"); eq(p.pw._v, "", "pw cleared");
}
{
  // the user field's handler flips the password element's type
  const p = new Page();
  p.u.onInput = () => { p.pw.type = "text"; };
  eq(p.code(true), "method_drift:1", "type swapped");
  eq(p.pw._v, "", "password never written");
  eq(p.pw.events.length, 0, "no event on pw");
  eq(p.u._v, "", "user cleared");
  eq(p.form.submits, 0, "no submit");
}
"##,
        );
    }

    #[test]
    fn req_tch_008_probe_global_is_reset_and_unknown_via_is_drift() {
        run_leg_harness(
            "reset",
            r##"
{
  const p = new Page();
  p.run(false);
  const q = new Page();
  q.pw.rects = 0;
  eq(q.code(false), "method_drift:1", "second fill drifts");
  eq(methodProbe().password_connected, null, "stale element not left behind");
}
{
  const p = new Page();
  p.submit = { index: 2, via: "teleport", selectors: [], expect: null };
  eq(p.code(true), "method_drift:2", "unknown via");
  p.untouched();
  eq(p.u.events.length + p.pw.events.length, 0, "no key events");
}
"##,
        );
    }

    #[test]
    fn req_tch_008_enter_submit_and_unrequested_submit() {
        run_leg_harness(
            "enter",
            r##"
{
  const p = new Page();
  p.submit = { index: 2, via: "enter", selectors: [], expect: null };
  p.run(true);
  const seq = p.pw.events.map((e) => e.type).join(",");
  eq(seq, "input,change,keydown,keypress,keyup", "enter on last element");
  eq(p.u.events.map((e) => e.type).join(","), "input,change", "user got no keys");
  eq(p.form.submits, 0, "no requestSubmit");
}
{
  // submit not requested: nothing dispatched, a missing form is not drift
  const p = new Page();
  p.pw.form = null;
  p.run(false);
  eq(p.pw.events.map((e) => e.type).join(","), "input,change", "no submit events");
  eq(p.form.submits, 0, "no submit");
  eq(p.pw._v, "s3cret", "still filled");
}
"##,
        );
    }
}
