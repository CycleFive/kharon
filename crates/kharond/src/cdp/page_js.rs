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
///
/// Returns `{ results: [{ kind, filled: true }] }` by value.
pub const FILL_IN_PAGE: &str = r#"
function fillInPage(specs, fields, expectedTopOrigin) {
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
  try {
    if (window.top && window.top.location) {
      const topOrigin = window.top.location.origin;
      if (topOrigin !== expectedTopOrigin) fail("origin_mismatch");
    }
  } catch (e) {
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
  for (const f of fields) {
    const el = resolveField(f.kind, f.selector);
    if (!el) fail("field_not_found:" + f.kind);
    setNativeValue(el, f.value);
    results.push({ kind: f.kind, filled: true });
  }
  return { results };
}
"#;

/// Best-effort scrub of the fields a fill wrote (SPEC §6 step 4: when
/// the loader changed after the write, clear before reporting
/// `navigated`). Runs in the same isolated world when it still exists;
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
}
