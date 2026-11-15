# Post-fill exposure: what happens to a secret after kharon fills it

> Design record for #354, 2026-11-15. Checked against the code and
> the live runs cited per row. Lothrop has final say on any scope
> cut; this page proposes none beyond the cuts SPEC already makes.

kharon's guarantee ends at delivery: the right secret, typed into
the right field, on the right origin, with approval. This page
models what happens to the secret *after* that point — the class
we call **post-fill exposure**: the broker delivers correctly, then
the secret stays readable somewhere the agent or the page can
reach.

SPEC §2.4 already carries the one-row version ("does NOT protect
against: agent reading the field after fill"). This page is the
full model behind that row.

## What kharon does at the boundary

These properties of the fill path bound every row below. All are
in the code today (`crates/kharond/src/cdp/fill.rs`,
`page_js.rs`).

- **One in-page call.** A fill runs as a single
  `Runtime.callFunctionOn` in an isolated world: origin re-checked
  in-page, fields written, and — when the agent asked for it —
  submit dispatched inside the same call (`form.requestSubmit()`,
  else Enter). There is no separate submit write to intercept or
  to forget.
- **Clear-on-failure (SPEC §2, #101).** If anything fails after a
  write — a later field misses, the origin recheck fails, the
  page-side budget (REQ-API-009, #118) expires — every element the
  call wrote is blanked before the error propagates, and submit is
  never dispatched.
- **Step-4 scrub.** After a non-submit fill, the broker re-reads
  the loader; if the page navigated on its own, it clears the
  written fields in the old world (best effort) and reports
  `navigated`. A navigation the fill's own submit caused is not
  scrubbed (#102): the page consumed the value.
- **Password values go to password fields.** By default
  resolution a `password` field is `input[type="password"]`, and
  username resolution excludes password inputs.
- **kharon's outputs carry no values.** Fill returns status and
  field names; there is no read endpoint; audit entries carry
  ids, origins and field counts, never values. kharon's own CDP
  client does not enable the Network domain and never captures
  screenshots.

## The model

Classification is one of: **kharon** (kharon mitigates it today),
**host** (a host or harness setting mitigates it), **scope**
(out of scope, with the reason), or **gap** (kharon should own a
mitigation it does not have yet — a follow-up is filed). "Tested"
names the evidence, or says unverified.

### A. Leftovers on the page

| # | Path | Class | Tested |
|---|---|---|---|
| A1 | Fill fails partway (field miss, origin recheck, budget expiry): earlier fields already written | **kharon** — clear-on-failure blanks every written field before the error propagates; submit never dispatched | Yes: `req_api_008` suite and `page_js` tests |
| A2 | Non-submit fill, then the page navigates by itself | **kharon** — step-4 loader recheck scrubs the old world's fields, reports `navigated` | Yes: daemon-CDP tests |
| A3 | Submit dispatched, page stays: rejected login, MFA step, SPA keeps the form mounted. The value sits in the field indefinitely | **gap** — no mitigation today; kharon reports `filled` and never looks again. Filed as #355 (post-submit scrub, with the mid-flow-clearing tension stated on the issue) | The behaviour is the current code's, read directly; no test asserts a scrub because none exists |
| A4 | `submit: false`: the value stays in the field because the agent's flow continues from there | **scope** — by design; the agent owns the page after delivery. What the agent can then read is row D1 | n/a |
| A5 | Multi-step login (username page, then password page) | Each step is its own fill; the secret is only ever written on its own step. The final step inherits A3/A4 | n/a |
| A6 | "Show password" toggle | **scope** — cosmetic; the value is in the DOM either way (D1) | n/a |
| A7 | Broker timeout after the fill frame was dispatched (#46): the in-page call runs to completion and may have filled *and submitted*; the step-4 scrub never runs after a drop | **scope** — inherent to one-way dispatch; the page-side budget narrows the window for an honest-but-slow page. Agents must treat a timed-out fill as *possibly delivered*, never as "nothing happened" | Documented in `fill.rs`; the budget half is covered by the REQ-API-009 tests |

### B. The page's own scripts

| # | Path | Class | Tested |
|---|---|---|---|
| B1 | Scripts on the bound origin: input listeners, session-replay and analytics SDKs, keyloggers | **scope** — the origin receives its own credential by design (SPEC §2.4). No fill mechanism can type into a page and hide the value from that page | n/a |
| B2 | Third-party scripts/iframes from other origins | **scope** — the same-origin policy keeps them out of the login DOM; an origin that embeds one with access has folded it into B1 | n/a |
| B3 | XSS'd or compromised origin | **scope** — SPEC §2.4 row; the origin check binds where the secret goes, not what the origin does with it | n/a |

### C. What the browser keeps

| # | Path | Class | Tested |
|---|---|---|---|
| C1 | Password-save prompt and saved logins in the profile | **host** — managed policy disables the password manager and autofill save ([`agent-runtime-setup.md`](agent-runtime-setup.md) step 2; for Hermes's Chrome for Testing the policy directory is the non-obvious `/etc/opt/chrome_for_testing/policies/managed/`, [`hermes-end-to-end.md`](hermes-end-to-end.md) §1). kharon's own acceptance rig holds the same line as REQ-ARCH-004 | Yes: #201 sweep (`Login Data` 0 rows); #353 run (policy visible in `chrome://policy`) |
| C2 | Autofill form-data memory in a persistent profile | **host** — the same policy, plus profile lifetime. Hermes deletes its throwaway profile at session exit; OpenClaw's managed profile persists, so policy is the whole mitigation there | Hermes: yes (#353). OpenClaw: unverified until its canary (#336) |
| C3 | Back/forward cache and form restore re-presenting a filled form | **scope** — browser behaviour after navigation; kharon has no post-navigation control of the page | Unverified |
| C4 | The profile folder on disk | **host** — a value reaches disk only through C1/C2; Hermes profile dirs are mode `0700` and deleted at exit (#353) | Hermes: yes. OpenClaw: unverified |
| C5 | Browser crash dumps | **host** — the browser is the platform's process. (kharond's own memory hygiene is REQ-MEM-* and covers the broker, not the browser) | Unverified |

### D. What the agent can watch (shared CDP)

| # | Path | Class | Tested |
|---|---|---|---|
| D1 | Agent reads `input.value` via `js()` / `Runtime.evaluate` / `callFunctionOn` after a fill | **host** — kharon cannot mitigate this: the plaintext must exist in the renderer for the form to submit (SPEC §2.4). The mitigation is the agent harness policy (SPEC OQ-3, [`deployment.md`](deployment.md#agent-harness-policy-spec-oq-3)): no JavaScript evaluation in pages | Yes, negatively: stock Hermes does **not** meet the policy — its agent read the filled fields' lengths and could read the values (#353). OpenClaw: unverified |
| D2 | DOM or accessibility-tree snapshots that include field values | **host** — same policy: the harness returns text and structure, never `value` attributes or form data | Hermes: the exposure is via `js()` (D1); snapshot tooling itself unverified |
| D3 | Screenshots while a login form is on screen | **host** — password inputs render masked by the browser, so the residual is the username and any show-password state (A6); the harness policy still recommends masking or none during login | Unverified |
| D4 | Agent enables the Network domain and captures the login POST body | **host** — the POST goes to the bound origin by design; watching it needs raw CDP, the same capability as D1, and is a harness question. kharon's own client never enables Network | Unverified |
| D5 | Observation *during* the fill window, before submit | **kharon**, in part — fill-and-submit is one in-page call on a millisecond budget, so with `submit: true` the readable window is the page's own submit handling. With `submit: false` there is no window to shrink (A4) | The budget is tested (REQ-API-009); a concurrent-observer race test does not exist — unverified as a race |
| D6 | kharon's own outputs: tool results, audit log, broker/connector journals, agent transcripts | **kharon** — status and names only, no values anywhere (above) | Yes: #201 filesystem sweep (0 hits) and the #353 leak check (canary absent from audit, journals, transcripts, sessions) |

## Per-host notes

- **Hermes** ([#347](https://github.com/CycleFive/kharon/issues/347)):
  the D rows are live-exposed on the stock harness (D1 tested,
  #353) — Hermes is the host that prompted this model. The C
  rows are comparatively strong: ephemeral `0700` profiles,
  deleted at session exit; the one trap is the Chrome for
  Testing policy directory (C1).
- **OpenClaw** ([#346](https://github.com/CycleFive/kharon/issues/346)):
  the persistent managed profile puts C1/C2 entirely on managed
  policy. Whether its model-facing tools can read field values
  (D1/D2) is unverified until the OpenClaw canary (#336); fills
  there use the platform's own tab under `allow_default_context`
  (one agent, #334), which is A4 by design.

## Follow-ups

- **#355** — the one kharon-owned gap (A3): post-submit leftover
  scrub, filed as `type:feat` with its design tension stated.
- **Verified, no issue needed** — this issue's first candidate
  ("verify the fill path submits in one step and scrubs the
  field on failure") closes by verification: one-step submit and
  clear-on-failure are both in the code and tested (A1, and
  "What kharon does at the boundary").
- **Already filed** — the per-host "tested" column fills in via
  the OpenClaw canary (#336) and the Hermes canary (#339); this
  page's unverified cells name them.
- **No new scope cuts proposed.** The scope rows above restate
  cuts SPEC §2.4 already makes. Anything further is Lothrop's
  call, per the issue.
