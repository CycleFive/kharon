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
//! `origin_mismatch`, `non_secure`, `field_not_found`.

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
///
/// Returns `{ results: [{ kind, filled: true }] }` by value.
pub const FILL_IN_PAGE: &str = r#"
function fillInPage(specs, fields, expectedTopOrigin, submitRequested) {
  "use strict";

  function fail(code) {
    const e = new Error("kharon:" + code);
    e.kharonCode = code;
    throw e;
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

  const results = [];
  let lastFilledElement = null;
  for (const f of fields) {
    const el = resolveField(f.kind, f.selector);
    if (!el) fail("field_not_found:" + f.kind);
    setNativeValue(el, f.value);
    results.push({ kind: f.kind, filled: true });
    lastFilledElement = el;
  }

  // REQ-API-008: reachable only after every field filled — any
  // failure above threw out of the function. `requestSubmit` honors
  // constraint validation and fires one submit event; the Enter
  // fallback synthesizes what a real keyboard press delivers.
  if (submitRequested && lastFilledElement) {
    const last = lastFilledElement;
    const form = last.form || (last.closest ? last.closest("form") : null);
    if (form && typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
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
  return { results };
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
        for code in ["origin_mismatch", "non_secure", "field_not_found"] {
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
    ///   B. a field missing + submit=true → no submit at all;
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
}
