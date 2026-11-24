# Post-fill exposure: what happens to a secret after kharon fills it

> Design record for #354, 2026-11-15. Checked against the code and
> the live runs cited per row. Lothrop has final say on any scope
> cut; this page proposes none beyond the cuts SPEC already makes.
> The "tested" column was updated on 2026-11-18 with the results of
> the OpenClaw (#336) and Hermes (#339) canaries. A3 was updated
> on 2026-11-19 when the opt-in post-submit scrub landed (#355,
> REQ-API-013). C1, C2, C4 and A3 were updated on 2026-11-24 with
> the submitted-fill canary (#369, milestone M1).

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
- **Step-4 scrub.** After a non-submit fill, the broker
  immediately re-reads the loader; if the page navigated on its
  own before that read, it attempts a scrub in the old world and
  reports `navigated`. The scrub is narrower than the fill: it
  re-resolves fields by kind instead of reusing the written
  elements, its username resolution has no fallback scan (so a
  username the fill wrote through its own fallback is not
  found), and it sets `value` without dispatching
  `input`/`change`, so framework-held state can keep the value.
  A navigation that commits after the re-read is not caught at
  all (row A2). A navigation the fill's own submit caused is
  not scrubbed (#102): the page consumed the value.
- **Post-submit scrub (REQ-API-013, #355), opt-in, default off.**
  After a `submit: true` fill that returned `filled`, if the
  deploy (`[policy] post_submit_scrub`) or that fill
  (`post_submit_scrub`) turned it on, the broker waits
  `post_submit_scrub_delay` (default 500 ms) and re-reads the
  loader once, bounded by the time left in the fill deadline. If
  that read does not answer, the scrub records `nothing` and the
  reply stays `filled`. If the loader is unchanged, a value-free
  call counts recorded elements that are still connected and
  non-empty. The written values are sent again only when that
  count is above zero; otherwise the scrub records `nothing`.
  The clear touches only the elements that fill wrote, and only
  where the field still holds exactly the value written, using
  the native setter and `input`/`change` — the clear-on-failure
  shape, not `CLEAR_IN_PAGE`'s re-resolve. The comparison is in
  the page and the call returns a count, never a value. The fill
  reply stays `filled`.
  This is one check, not a watch. A loader that already changed,
  or that changes at the re-read, is left alone. The scrub is
  not started when the remaining fill deadline cannot cover the
  delay, and it never runs after a `timeout` (A7).
- **Password values go to password fields.** By default
  resolution a `password` field is `input[type="password"]`.
  Username resolution is weaker: its hint query
  (`input[type="email"]`, `input[autocomplete*="username"]`,
  `input[name*="user" i]`) has no type filter, so it can match
  a password input whose name contains "user"; only the
  fallback scan excludes password inputs, and an explicit
  selector in the fill plan is used as given. A username in a
  password field is not a secret exposure — the password value
  still only goes to a password field — but the stronger claim
  would be false.
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
| A2 | Non-submit fill, then the page navigates by itself | **kharon**, narrowly — the loader recheck catches only a navigation committed before the immediate post-call read (a few-ms window); a later navigation is A4, or C3 if the cache keeps the form. The scrub itself can miss a fallback-written username and cannot clear framework-held state (see "What kharon does at the boundary") | Yes: daemon-CDP tests, for the committed-before-read case |
| A3 | Submit dispatched, page stays: rejected login, MFA step, SPA keeps the form mounted | **kharon, opt-in** — off unless `[policy] post_submit_scrub` or that fill's `post_submit_scrub` is true (default off, so a retry-in-place form or a streaming MFA step is not cleared under the user). When on: one re-read after the delay; if the loader is unchanged and a field still holds exactly the value this fill wrote, that recorded element is cleared and `input`/`change` are dispatched. A later navigation, a replaced node, or a value the page or the user has since changed is not cleared. The reply stays `filled`. The wait runs inside the fill, so when a navigation is not yet visible at the broker's immediate post-fill loader read the reply arrives up to `post_submit_scrub_delay` later (#369: 572 ms and 622 ms on a navigating page against 113 ms and 140 ms in the first round, when the navigation was already visible) | Yes: the `req_api_013` suite (daemon CDP stub) and the `page_js` scrub harness. Live in #369 (scrub on, both hosts): `cleared` on a page that keeps its filled form, `nothing` on a page that removes it, `navigated` on a page that navigates |
| A4 | `submit: false`: the value stays in the field because the agent's flow continues from there | **scope** — by design; the agent owns the page after delivery. What the agent can then read is row D1 | n/a |
| A5 | Multi-step login (username page, then password page) | Each step is its own fill; the secret is only ever written on its own step. The final step inherits A3/A4 | n/a |
| A6 | "Show password" toggle | **scope** — cosmetic; the value is in the DOM either way (D1) | n/a |
| A7 | Broker timeout after the fill frame was dispatched (#46): the in-page call runs to completion and may have filled *and submitted*; the step-4 scrub never runs after a drop, and neither does the post-submit scrub (it is the same future, so a drop sends no clear) | **scope** — inherent to one-way dispatch; the page-side budget narrows the window for an honest-but-slow page. Agents must treat a timed-out fill as *possibly delivered*, never as "nothing happened" | Documented in `fill.rs`; the budget half is covered by the REQ-API-009 tests, and the scrub-not-sent half by `req_api_013` |

### B. The page's own scripts

| # | Path | Class | Tested |
|---|---|---|---|
| B1 | Scripts on the bound origin: input listeners, session-replay and analytics SDKs, keyloggers | **scope** — the origin receives its own credential by design (SPEC §2.4). No fill mechanism can type into a page and hide the value from that page | n/a |
| B2 | Third-party scripts/iframes from other origins | **scope** — the same-origin policy keeps them out of the login DOM; an origin that embeds one with access has folded it into B1 | n/a |
| B3 | XSS'd or compromised origin | **scope** — SPEC §2.4 row; the origin check binds where the secret goes, not what the origin does with it | n/a |

### C. What the browser keeps

| # | Path | Class | Tested |
|---|---|---|---|
| C1 | Password-save prompt and saved logins in the profile | **host** — managed policy disables the password manager and autofill save ([`agent-runtime-setup.md`](agent-runtime-setup.md) step 2; for Hermes's Chrome for Testing the policy directory is the non-obvious `/etc/opt/chrome_for_testing/policies/managed/`, [`hermes-end-to-end.md`](hermes-end-to-end.md) §1). kharon's own acceptance rig holds the same line as REQ-ARCH-004 | Yes: #201 sweep (`Login Data` 0 rows); #353 run (policy visible in `chrome://policy`). Both canaries, with the form filled and not submitted: `Login Data` 0 rows on Hermes (#339) and on OpenClaw (#336). Submitted fill (#369, 2026-11-23, master `ead6a9f`): `Login Data` `logins` and `stats` 0 on both hosts with the policy on. With the policy lifted, the same fill gave `stats` 1 (the browser offered to save) on both hosts, so the policy is what holds the line. `logins` stays 0 either way unless someone accepts the offer, so `stats` is the signal |
| C2 | Autofill form-data memory in a persistent profile | **host** — the same policy, plus profile lifetime. Hermes deletes its throwaway profile at session exit; OpenClaw's managed profile persists, so policy is the whole mitigation there | Both hosts, submitted fill (#369): `Web Data` `autofill` 0 rows with the policy on; with the policy lifted, the same fill gave 1 row on each host. Hermes also #353. Earlier, unsubmitted fills on OpenClaw (#336) read 0 |
| C3 | Back/forward cache and form restore re-presenting a filled form | **scope** — browser behaviour after navigation; kharon has no post-navigation control of the page | Unverified |
| C4 | The profile folder on disk | **host** — a value reaches disk only through C1/C2; Hermes profile dirs are mode `0700` and deleted at exit (#353) | Hermes: yes (#353; #339 swept the live profile with the form filled, 0 files; #369 after a submitted fill: profile 0 of 205 files, whole filesystem 0). OpenClaw: yes (#336, unsubmitted: a whole-filesystem sweep with two forms filled found 0 files, the persistent profile included; #369, submitted: whole-filesystem sweep 0 files) |
| C5 | Browser crash dumps | **host** — the browser is the platform's process. (kharond's own memory hygiene is REQ-MEM-* and covers the broker, not the browser) | Unverified |

### D. What the agent can watch (shared CDP)

| # | Path | Class | Tested |
|---|---|---|---|
| D1 | Agent reads `input.value` via `js()` / `Runtime.evaluate` / `callFunctionOn` after a fill | **host** — kharon cannot mitigate this: the plaintext must exist in the renderer for the form to submit (SPEC §2.4). The mitigation is the agent harness policy (SPEC OQ-3, [`deployment.md`](deployment.md#agent-harness-policy-spec-oq-3)): no JavaScript evaluation in pages | Yes, negatively: stock Hermes does **not** meet the policy — its agent read the filled fields' lengths and could read the values (#353). In #339 the agent was told not to read the fields and did not; nothing in the harness enforces that. OpenClaw: with `browser.evaluateEnabled = false`, `act:evaluate` is refused (#336). The default is on (read from source), so stock OpenClaw does not meet the policy until the operator sets it |
| D2 | DOM or accessibility-tree snapshots that include field values | **host** — same policy: the harness returns text and structure, never `value` attributes or form data | Hermes: the exposure is via `js()` (D1); snapshot tooling itself unverified. OpenClaw: yes, negatively: on 2026.11.3, `openclaw browser snapshot` returned a filled password in clear (#334). #336 repeated it by match count: the default `ai` format contained the canary, and the `aria` format did not in that run. OpenClaw `main` masks password-type fields in snapshots (`da41e7de`), in no release as of 2026-11-15 ([agent-runtime-setup.md](agent-runtime-setup.md#harness-policy-on-stock-openclaw)) |
| D3 | Screenshots while a login form is on screen | **host** — password inputs render masked by the browser, so the residual is the username and any show-password state (A6); the harness policy still recommends masking or none during login | Unverified |
| D4 | Agent enables the Network domain and captures the login POST body | **host** — the POST goes to the bound origin by design; watching it needs raw CDP, the same capability as D1, and is a harness question. kharon's own client never enables Network | Unverified |
| D5 | Observation *during* the fill window, before submit | **kharon**, in part — fill-and-submit is one in-page call on a millisecond budget, so with `submit: true` the readable window is the page's own submit handling. With `submit: false` there is no window to shrink (A4) | The budget is tested (REQ-API-009); a concurrent-observer race test does not exist — unverified as a race |
| D6 | kharon's own outputs: tool results, audit log, broker/connector journals, agent transcripts | **kharon** — status and names only, no values anywhere (above) | Yes: #201 filesystem sweep (0 hits) and the #353 leak check (canary absent from audit, journals, transcripts, sessions). Both canaries on master `13b2d53`: 0 files on the agent host and on the broker host, 0 journal lines, 0 in the audit logs, 0 in the agents' transcripts and session stores (#339, #336) |
| D7 | `kharon_open` (#357) navigates a broker-owned tab to the item's saved login URL; on the shared CDP the agent can read the tab's full URL — path, query and fragment included — not just the origin the tool result returns | **host** — kharon's own APIs withhold the full URL: `kharon_list`/`kharon_search` return `UriMeta` (`{host, match}`) only (REQ-API-004; the #357 test asserts the URL canaries are absent from search), and the tool result is exactly `{target_id, origin}` (REQ-API-012). Navigation strips userinfo but retains path, query and fragment, so sensitive URL components remain readable on the shared CDP; whether the model sees them is the harness policy (SPEC §2.4, OQ-3), which controls or redacts model-facing target and snapshot URLs | Unverified as a read path — no canary step reads a tab URL back; the tool-result shape is covered by the #357 tests |

## Per-host notes

- **Hermes** ([#347](https://github.com/CycleFive/kharon/issues/347)):
  the D rows are live-exposed on the stock harness (D1 tested,
  #353) — Hermes is the host that prompted this model. The C
  rows are comparatively strong: ephemeral `0700` profiles,
  deleted at session exit; the one trap is the Chrome for
  Testing policy directory (C1).
- **OpenClaw** ([#346](https://github.com/CycleFive/kharon/issues/346)):
  the persistent managed profile puts C1/C2 entirely on managed
  policy. Its page-JavaScript action (D1) is on by default and is
  refused once `browser.evaluateEnabled` is `false` (#336); stock
  2026.11.3 snapshots expose a filled password in the default
  format (D2, #334 and #336); fills
  there use the platform's own tab under `allow_default_context`
  (one agent, #334), which is A4 by design.

## Follow-ups

- **#355** — implemented (REQ-API-013). Opt-in, default off.
  The mid-flow tension is why a deploy or a fill has to turn it
  on. A timeout still does not scrub (A7).
- **Verified, no issue needed** — this issue's first candidate
  ("verify the fill path submits in one step and scrubs the
  field on failure") closes by verification: one-step submit and
  clear-on-failure are both in the code and tested (A1, and
  "What kharon does at the boundary").
- **Canaries run** — the OpenClaw canary (#336) and the Hermes
  canary (#339) ran on 2026-11-18, and the "tested" column above
  carries what they showed. Neither submitted a form.
- **Submitted-fill canary run** — #369 (milestone M1) ran on
  2026-11-23 on master `ead6a9f` with the post-submit scrub on,
  one submitted fill per host. It closed the save-on-submit half
  of C1 and C2 on both hosts: 0 stored rows with the policy on,
  and policy-lifted controls (`stats` 1, `autofill` 1) showing
  that the policy is the mitigation.
- **No new scope cuts proposed.** The scope rows above restate
  cuts SPEC §2.4 already makes. Anything further is Lothrop's
  call, per the issue.
