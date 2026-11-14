# Roadmap: agent platform support

Status: proposal, 2026-11-14. This page is the plan. Milestones and
issues for v0.5.0 and later are filed after it merges. v0.4.0 stays
the milestone already on the tracker, with one owner decision applied:
[#327](https://github.com/CycleFive/kharon/issues/327) is parked and
is not part of that plan.

Direction the same day, from Lothrop: kharon stays on the
agent-connector. It grabs a CDP endpoint the agent platform already
exposes, fills, and hands the browser back. The next platforms are
OpenClaw, then Hermes, then other hosts that expose CDP the same way.
After v0.4.0, one minor release per platform.

## Current state

v0.3.0 was released on 2026-11-14 (dashboard connector auth, N3 phase
2). A dashboard runtime attaches its browser with a connector-audience
token. The agent still never receives the filled values.

The live test on Muse's agent host (VM 125) passed the same day
([#322](https://github.com/CycleFive/kharon/issues/322)): Connect,
attach over the WebSocket, an approved canary fill, and Disconnect.
The two product findings from that run are already closed on v0.4.0:
[#323](https://github.com/CycleFive/kharon/issues/323) (MCP renders
`no_browser`) and
[#324](https://github.com/CycleFive/kharon/issues/324) (the consent
sentence when the client declares the connector grant). This roadmap
found no separate Grok Bot live-test issue. SPEC §4.1 names Muse and
Grok as the dashboard Connect clients the shipped connector serves,
and Muse's run is the written pass.

The v0.3.0 soak is open as
[#326](https://github.com/CycleFive/kharon/issues/326), for the week
of 2026-11-14. Muse's host is checked. OpenClaw's install is
[#328](https://github.com/CycleFive/kharon/issues/328), unclaimed.
The Duet host line on #326 pointed at #327, which is parked (see
[Parked / not planned](#parked--not-planned)).

Rolling doc nits from v0.3.0 sit on
[#286](https://github.com/CycleFive/kharon/issues/286). They do not
gate a release.

## Principles

These hold for every milestone on this page.

- **The connector is CDP, on the browser the agent already has.**
  Path B: `kharon-agent-connector` dials the broker over an outbound
  WebSocket (`wss://<host>/connector`, wire v1 inside). The broker
  opens its own CDP session to the platform's Chromium, fills, and
  drops that session. The platform keeps the browser. kharon does not
  launch a browser, host one, or ship an extension that fills in the
  platform's place. Install steps for a hosted runtime stay
  [`docs/agent-runtime-setup.md`](agent-runtime-setup.md).
- **The broker sits in front of a Bitwarden vault it does not own.**
  One dedicated account, one organization, the configured collections.
  The customer holds the master password. kharon syncs and decrypts
  that collection. It does not write the vault (SPEC N3, G3).
- **One managed deploy per customer.** One broker, one customer
  vault, one gateway hostname, one owner hostname
  ([runbook](managed-deploy-runbook.md)). Multi-tenant operation
  stays a non-goal (SPEC N5).
- **The customer approves every fill.** The default grant is `once`,
  and standing grants stay off. The agent can request a fill and
  cannot approve it. The operator CLI remains the break-glass path
  already in SPEC. Restricting that socket to lock, panic, and
  passkey re-enrolment is the parked [#236](https://github.com/CycleFive/kharon/issues/236).

A second host uses its own agent id. Two connectors on one agent id
evict each other; that case is the parked
[#281](https://github.com/CycleFive/kharon/issues/281).

## Order

v0.5.0 is OpenClaw. v0.6.0 is Hermes. Further minors follow, one host
each, in an order this page does not set.

That order is kept. OpenClaw's default managed profile already
publishes a local CDP port, and #328 is the soak install of the
connector that ships today. Hermes's documented way for a second
client to share the browser is an explicit CDP URL, and the default
packaged Chromium does not offer its raw CDP tool (details under
v0.6.0; the listen port there is unverified). The published order
stays.

## v0.4.0 — soak and carry-over

The open milestone. Description on the tracker: carry-over from
v0.3.0 (rolling nits) and next work. Nothing here adds a platform.

### Goal

Finish the v0.3.0 soak week and the carry-over already filed.
OpenClaw in this milestone is the soak install of the current
connector (#328). The supported-platform release is v0.5.0.

### Exit criteria

- #323 and #324 stay merged.
- #326 closes when the soak week ends (about 2026-11-21) and every
  break has its own issue. Muse's host and OpenClaw (#328) are
  the soak hosts. #327 is parked, so the Duet checkbox on #326 is
  leftover tracker text. This page leaves the tracker as it is.
  Clearing #327's milestone field, and striking that checkbox, is
  a separate tracker edit.
- #328 meets the acceptance already written on it: the connector
  attaches with the pin checked, Connect completes, `kharon_context`
  returns ok, one approved canary fills, Disconnect makes the next
  fill refuse, and any doc gap is fixed or filed under v0.4.0.
  It is unclaimed.
- #286 stays the nit list. Nits do not gate the milestone.

### Issues

Filed. None proposed. Proposing new v0.4.0 issues would rescope it.

| Issue | State | Scope |
|---|---|---|
| #323 | closed | MCP tool results render `no_browser` for that refusal. |
| #324 | closed | Consent names the dashboard browser when the client declares the connector grant. |
| #286 | open | Rolling doc nits. Does not gate. |
| #326 | open | Soak tracking for the week of 2026-11-14. |
| #328 | open, unclaimed | Soak install of the v0.3.0 connector on OpenClaw. Stays here. v0.5.0 does not absorb it. |

#327 is open, labelled `parked`, and still has milestone v0.4.0 in
the tracker. It is listed under
[Parked / not planned](#parked--not-planned), not in the table.

## v0.5.0 — OpenClaw

### How OpenClaw exposes a browser

Read from OpenClaw's docs on 2026-11-14
([configuration](https://docs.openclaw.ai/tools/browser/configuration),
[remote browsers](https://docs.openclaw.ai/tools/browser/remote),
[Linux troubleshooting](https://docs.openclaw.ai/tools/browser-linux-troubleshooting)).
Nothing in this section was checked by installing OpenClaw.

The default profile, `openclaw`, is a Chromium OpenClaw launches
itself: its own user-data directory, headless unless configured
otherwise, and a CDP port. Local profiles take that port from
18800–18899 (nine above the control port). The control service is a
different loopback port, default 18791, derived from `gateway.port`.
Creating a profile writes the chosen `cdpPort` into config. A profile
declared by hand sets `cdpPort` or `cdpUrl`. Readiness checks talk
about the launched **loopback** endpoint. The troubleshooting page
starts Chromium with `--remote-debugging-port=18800` and omits
`--remote-debugging-address`. The docs call the launched endpoint
loopback. That the child binds 127.0.0.1 specifically was not
confirmed from OpenClaw's source.

Other profiles, and what they mean for the connector:

- **Managed `openclaw` driver.** This is the v0.5.0 browser. The
  connector's `cdp` is `127.0.0.1:<cdpPort>` on that host. It is not
  the control port, and it is not assumed to be 9222.
- **`attachOnly` to a loopback CDP URL.** OpenClaw attaches and does
  not launch. In this release only when the connector runs on that
  same host and dials the same loopback port. The browser still
  belongs to whoever started it.
- **`driver: "extension"`.** The relay drives the signed-in Chrome.
  These profiles reject `cdpUrl`. There is no CDP port for the
  connector to grab. Out of this release, same family as
  [#331](https://github.com/CycleFive/kharon/issues/331).
- **`driver: "existing-session"`.** Chrome DevTools MCP, including
  auto-connect to the user's Chrome. The docs do not show a stable
  raw CDP port the connector can share. Treated as out of this
  release. Unverified whether some `cdpUrl` setups in this driver
  publish one.
- **Remote `cdpUrl`.** Browserless, Browserbase, Browser Use, Notte,
  and any other off-host browser. The connector dials a loopback
  `host:port` on the agent host. Out of this release.

### What the connector install needs

On the OpenClaw host, the same connector binary and `connector.toml`
as [`docs/agent-runtime-setup.md`](agent-runtime-setup.md): outbound
WebSocket, `broker_pin` compared and never adopted, `cdp` set to the
managed profile's loopback port. The password-manager policy from
that page applies to whichever Chromium binary the profile launches.
kharon does not start a second browser. The platform keeps driving
its own CDP session after the fill (REQ-ARCH-003). The host gets its
own agent id (#281).

Which tab the fill uses is undecided. See
[Open questions](#open-questions). SPEC gives the agent a browser
context from `kharon_context` and refuses a default-context target
unless `allow_default_context` is set, and that flag is legal only
with exactly one agent. OpenClaw's docs show no setting for a Chrome
`browserContextId` kharon created. That gap was not verified past
those docs.

### Goal

A managed customer attaches kharon to the Chromium OpenClaw already
runs, approves one fill into that browser, and OpenClaw keeps the
browser when the connector lets go.

### Exit criteria

- The tab-ownership decision is written down before the install
  steps freeze.
- The agent-host docs grow an OpenClaw section: managed profile,
  `cdpPort` versus the control port, connector `cdp`, the managed
  policy, Connect, the canary, and the profiles this release does
  not cover.
- One recorded canary on a managed OpenClaw browser: approved fill,
  then Disconnect, OpenClaw still driving that browser, and the next
  fill refusing with `no_browser`.
- No new transport. Path B stays as shipped.

### Proposed issues

Filed after this page merges. None of them absorb #328.

1. **design: which tab an OpenClaw fill uses** — On one managed
   profile, see whether the canary can target the context
   `kharon_context` returns, or only a tab OpenClaw already opened
   (`allow_default_context`, one agent on that deploy). Record the
   decision. No SPEC edit until it is decided.
2. **docs(dep): OpenClaw connector install for the managed local
   browser** — The repeatable steps from the decision above, plus
   the out-of-release profiles. Follows whatever #328 learned.
3. **test: OpenClaw canary on the managed browser** — The v0.5.0
   evidence: one approved fill, Disconnect, the platform still
   driving the browser, versions recorded. #328 remains the v0.4.0
   soak attempt.

## v0.6.0 — Hermes

Hermes here is Hermes Agent (Nous Research). Read from its browser
docs on 2026-11-14
([Browser automation](https://hermes-agent.nousresearch.com/docs/user-guide/features/browser)).
Nothing in this section was checked by installing Hermes.

### How Hermes exposes a browser

`browser_exec` drives a browser over CDP, through the browser-harness
engine. Where that browser comes from is a separate choice:

- **Local Chromium, the default.** Hermes launches a packaged
  Chromium, headless, one browser per session, throwaway profile
  unless `browser.user_data_dir` is set. The docs say this path does
  not touch the installed Chrome and does not raise the remote
  debugging approval dialog. The raw `browser_cdp` tool is offered
  only when a CDP endpoint is configured. So the default launch is
  CDP inside the harness, and it is **unverified** whether that
  Chromium listens on a stable loopback port a second client can
  open.
- **Explicit CDP attach.** `browser.cdp_url` or `BROWSER_CDP_URL`.
  The CLI command `/browser connect` uses `http://127.0.0.1:9222`,
  or a `ws://` URL passed to it. If nothing is listening, Hermes
  auto-launches a Chromium-family browser with
  `--remote-debugging-port=9222`. The documented manual launch also
  passes a dedicated `--user-data-dir`, because since Chrome 136 a
  debugging port on the default profile directory is ignored. That
  Chrome behavior is Hermes's documentation of Chrome; it was not
  re-tested here. `/browser connect` is a CLI slash command. The
  docs say a gateway, WebUI, or chat platform will not run it; the
  message goes to the model as text. Persistent attach for those
  sessions is `browser.cdp_url`.
- **Cloud browsers.** Nous subscription, Browserbase, Browser Use,
  Firecrawl, or another provider plugin. The browser is off the
  host. Same exclusion as OpenClaw's remote `cdpUrl`.
- **Lightpanda.** `lightpanda serve --host 127.0.0.1`. Not Chromium.
  kharon's fill path is Chromium CDP. Out of this release.
- **`browser.use_real_profile`.** A snapshot of the user's profile,
  launched by Hermes. Whether that launch publishes a loopback CDP
  port for a second client is unverified. Out of the first slice
  until the default-launch question is answered.

`browser_vault` fills logins Hermes stored, into the same browser
session. kharon does not call it. The customer vault stays the
Bitwarden collection on the broker.

### What the connector install needs

The planned slice is the explicit local endpoint. Hermes is
configured with `browser.cdp_url` (or the CLI `/browser connect`) at
a loopback Chromium, and `connector.toml` `cdp` names that same
`host:port`. The docs' example port is 9222, which matches the
connector examples already in the agent-runtime guide. The browser
process is Hermes's, or one the operator started for Hermes. kharon
does not launch it. Policy, pin, agent id, and the tab-ownership
question are the same as v0.5.0.

The default packaged Chromium joins this release only if the design
issue shows a stable loopback port the connector can open while
`browser_exec` is attached. Until that check, it stays out of the
install doc.

### Goal

A managed customer attaches kharon to a loopback Chromium Hermes is
already configured to drive, approves one fill, and Hermes keeps
that browser.

### Exit criteria

- The default-launch check is recorded, and the install doc matches
  it.
- The agent-host docs grow a Hermes section for `browser.cdp_url` /
  `BROWSER_CDP_URL`, with the CLI-only note on `/browser connect`,
  the shared loopback port, and the modes this release does not
  cover (default packaged Chromium until the check passes, cloud
  providers, Lightpanda, `browser_vault`).
- One recorded canary on that shared browser: approved fill,
  Disconnect, Hermes still driving it, next fill `no_browser`.
- No new transport.

### Proposed issues

Filed after this page merges. Nothing existing to absorb.

1. **design: does Hermes's default local Chromium publish a loopback
   CDP port?** — With a stock session and no `browser.cdp_url`, see
   whether a second client can open the debugging port while
   `browser_exec` is driving. A no keeps v0.6.0 on the explicit
   endpoint only.
2. **docs(dep): Hermes connector install on an explicit local CDP
   endpoint** — `browser.cdp_url` and the connector on the same
   loopback port, CLI `/browser connect` called out as not a gateway
   command, cloud and Lightpanda excluded. Depends on the v0.5.0
   tab-ownership decision; Hermes gets the same rule unless this
   check shows it cannot.
3. **test: Hermes canary on the shared loopback browser** — The
   v0.6.0 evidence, same shape as the OpenClaw canary.

## Later CDP hosts

### Goal

After v0.6.0, each further CDP-capable agent host gets its own minor
release. A host qualifies when it already exposes Chromium CDP on
loopback on a machine where `kharon-agent-connector` can run, and
kharon can fill and let go. The survey below picks the order. This
page does not.

### Exit criteria

For whichever host the survey names first, the same bar as v0.5.0
and v0.6.0: a written install, one approved canary, Disconnect
leaves the platform driving the browser, and the modes that are not
loopback Chromium CDP stated as out of that minor. One host per
release.

### Proposed issues

None named, and none filed from this page. When a host is chosen,
the set is the same three: a short design check for anything the
docs leave unverified, the install doc, and the canary report.

### Placeholder: platform priority after v0.6.0

> **Placeholder.** Claude Duet (cycle-five-duet) will share a kharon
> adoption survey. Platform priority after v0.6.0 will be informed
> by that survey. This section stays empty of a ranked list until
> that survey is in. Do not file the later minors, and do not invent
> an order, ahead of it.

## Parked / not planned

- **1Password integration.** A dev partnership between 1Password and
  Anthropic blocks kharon from filling Claude's cloud browser. No
  custom connector can fill that browser in any meaningful way.
  Background on 1Password's own shape:
  [`docs/1password-agent-model.md`](1password-agent-model.md).
- **Running our own Chrome.** kharon does not launch or host a
  browser for an agent. It grabs CDP the agent already has, fills,
  and hands the browser back.
- **[#327](https://github.com/CycleFive/kharon/issues/327), Duet's
  standing host.** Parked 2026-11-14. A standing host for Duet would
  mean running a whole browser for that agent, which is the line
  above. The issue is open, labelled `parked`, and still carries
  milestone v0.4.0 in the tracker until that field is cleared. It is
  not soak work and not a platform release.
- **[#331](https://github.com/CycleFive/kharon/issues/331), Claude
  in Chrome extension.** Maybe later. Design only, parked, no
  milestone: an extension would fill in the user's Chrome when
  Claude drives it. That is not a CDP grab. It stays parked until
  Lothrop says otherwise.
- **[#281](https://github.com/CycleFive/kharon/issues/281), two
  connectors, one agent id.** Parked. They evict each other. One
  agent id per host is the working rule. A broker change waits on
  Lothrop.
- **[#236](https://github.com/CycleFive/kharon/issues/236),
  customer-only approvals on the owner socket.** Parked optional
  design. The operator CLI keeps its current powers. Not scheduled.

## Open questions

1. **Which tab is filled?** `kharon_context` creates a browser
   context the agent is expected to use. `allow_default_context`
   allows the tab the platform already opened, and only on a deploy
   with one agent. Neither OpenClaw nor Hermes documents a way to
   pass a `browserContextId` kharon created (unverified past the
   docs read on 2026-11-14). v0.5.0's design issue answers it for
   OpenClaw; v0.6.0 reuses that answer unless Hermes cannot.
2. **Which OpenClaw profile does the soak host actually run?**
   v0.5.0 targets the managed profile that has a CDP port. If #328's
   host is on the extension relay, that profile has no CDP URL and
   stays out with #331. The order of releases stays OpenClaw, then
   Hermes.
3. **Is Hermes's default packaged Chromium in v0.6.0?** The plan
   excludes it until a second client can open a stable loopback
   port while `browser_exec` is attached. Cloud providers,
   Lightpanda, and `browser_vault` stay out either way. Confirm that
   cut.

The release order is settled: OpenClaw, then Hermes. The research
above leaves it there.

## Sources

OpenClaw, fetched 2026-11-14:

- <https://docs.openclaw.ai/tools/browser/configuration>
- <https://docs.openclaw.ai/tools/browser/remote>
- <https://docs.openclaw.ai/tools/browser-linux-troubleshooting>
- <https://docs.openclaw.ai/cli/browser>

Hermes Agent, fetched 2026-11-14:

- <https://hermes-agent.nousresearch.com/docs/user-guide/features/browser>
- <https://github.com/NousResearch/hermes-agent/pull/1549>
  (`/browser connect`, merged)

Tracker, same day: milestone v0.4.0; issues #236, #281, #286, #322,
#323, #324, #326, #327, #328, #331.
