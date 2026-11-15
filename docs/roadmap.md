# Roadmap: agent platform support

Status: updated 2026-11-15. This page is the plan. Lothrop switched
versioning to rolling releases that day (see
[Versioning](#versioning)).
[#327](https://github.com/CycleFive/kharon/issues/327) is parked and
is not part of that plan.

Direction from Lothrop, 2026-11-14: kharon stays on the
agent-connector. It grabs a CDP endpoint the agent platform already
exposes, fills, and hands the browser back. The next platforms are
OpenClaw, then Hermes, then other hosts that expose CDP the same way.

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

These hold for every platform on this page.

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

## Versioning

Lothrop, 2026-11-15: releases are rolling trains.

- A minor release ships whatever has passed its gate since the last
  one. It is cut when master is green and at least one user-visible
  change has landed. There is no fixed platform per version. Releases
  are still tagged and published as the `cycle-five` identity.
- Platform goals stay OpenClaw first, then Hermes, then other CDP
  hosts. They are tracked with the `platform:openclaw` /
  `platform:hermes` labels and a `tracking: <platform> support` issue
  each
  ([#346](https://github.com/CycleFive/kharon/issues/346),
  [#347](https://github.com/CycleFive/kharon/issues/347)), not with
  milestones. Work on platforms runs in parallel, because it is gated
  on external live checks.
- A platform counts as supported in a release only once its canary
  test and live check pass. Release notes list the supported
  platforms.
- The open milestone is `next`. The old v0.4.0, v0.5.0, and v0.6.0
  milestones are closed.

The platform order is kept. OpenClaw's default managed profile
already publishes a local CDP port, and #328 is the soak install of
the connector that ships today. Hermes's documented way for a second
client to share the browser is an explicit CDP URL. The default
packaged Chromium's loopback port was checked live on
[#337](https://github.com/CycleFive/kharon/issues/337) (2026-11-15):
it is ephemeral, and the issue stays open (details under
[Hermes](#hermes)). The published order stays.

## Soak and carry-over

The v0.3.0 soak and the carry-over already filed. Nothing here adds
a platform. These issues sit on milestone `next`.

### Goal

Finish the v0.3.0 soak week and the carry-over already filed.
OpenClaw here is the soak install of the current connector (#328).
OpenClaw counts as supported only once its canary test and live
check pass.

### Exit criteria

- #323 and #324 stay merged.
- #326 closes when the soak week ends (about 2026-11-21) and every
  break has its own issue. Muse's host and OpenClaw (#328) are
  the soak hosts. #327 is parked and on no milestone, so it is not
  a soak host. The Duet line on #326 is already struck.
- #328 meets the acceptance already written on it: the connector
  attaches with the pin checked, Connect completes, `kharon_context`
  returns ok, one approved canary fills, Disconnect makes the next
  fill refuse, and any doc gap is fixed or filed on milestone `next`.
  It is unclaimed.
- #286 stays the nit list. Nits do not gate a release.

### Issues

Filed. None proposed. Proposing new soak issues would rescope it.

| Issue | State | Scope |
|---|---|---|
| #323 | closed | MCP tool results render `no_browser` for that refusal. |
| #324 | closed | Consent names the dashboard browser when the client declares the connector grant. |
| #286 | open | Rolling doc nits. Does not gate. |
| #326 | open | Soak tracking for the week of 2026-11-14. |
| #328 | open, unclaimed | Soak install of the v0.3.0 connector on OpenClaw. Stays here. OpenClaw support does not absorb it. |

#327 is open, labelled `parked`, and on no milestone. It is listed
under [Parked / not planned](#parked--not-planned), not in the table.

## OpenClaw

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

- **Managed `openclaw` driver.** This is the browser OpenClaw
  support uses. The connector's `cdp` is `127.0.0.1:<cdpPort>` on
  that host. It is not the control port, and it is not assumed to
  be 9222.
- **`attachOnly` to a loopback CDP URL.** OpenClaw attaches and does
  not launch. In OpenClaw support only when the connector runs on
  that same host and dials the same loopback port. The browser still
  belongs to whoever started it.
- **`driver: "extension"`.** The relay drives the signed-in Chrome.
  These profiles reject `cdpUrl`. There is no CDP port for the
  connector to grab. Out of OpenClaw support, same family as
  [#331](https://github.com/CycleFive/kharon/issues/331).
- **`driver: "existing-session"`.** Chrome DevTools MCP, including
  auto-connect to the user's Chrome. The docs do not show a stable
  raw CDP port the connector can share. Treated as out of OpenClaw
  support. Unverified whether some `cdpUrl` setups in this driver
  publish one.
- **Remote `cdpUrl`.** Browserless, Browserbase, Browser Use, Notte,
  and any other off-host browser. The connector dials a loopback
  `host:port` on the agent host. Out of OpenClaw support.

### What the connector install needs

On the OpenClaw host, the same connector binary and `connector.toml`
as [`docs/agent-runtime-setup.md`](agent-runtime-setup.md): outbound
WebSocket, `broker_pin` compared and never adopted, `cdp` set to the
managed profile's loopback port. The password-manager policy from
that page applies to whichever Chromium binary the profile launches.
kharon does not start a second browser. The platform keeps driving
its own CDP session after the fill (REQ-ARCH-003). The host gets its
own agent id (#281).

Which tab the fill uses is decided on
[#334](https://github.com/CycleFive/kharon/issues/334): option (b),
the tab OpenClaw already opened, under `allow_default_context` with
one agent. [#343](https://github.com/CycleFive/kharon/pull/343)
fixed the bug that blocked it.

### Goal

A managed customer attaches kharon to the Chromium OpenClaw already
runs, approves one fill into that browser, and OpenClaw keeps the
browser when the connector lets go.

### Exit criteria

- The tab-ownership decision is written down before the install
  steps freeze.
- The agent-host docs grow an OpenClaw section: managed profile,
  `cdpPort` versus the control port, connector `cdp`, the managed
  policy, Connect, the canary, and the profiles OpenClaw support
  does not cover.
- One recorded canary on a managed OpenClaw browser: approved fill,
  then Disconnect, OpenClaw still driving that browser, and the next
  fill refusing with `no_browser`.
- No new transport. Path B stays as shipped.

### Proposed issues

Filed
([#334](https://github.com/CycleFive/kharon/issues/334),
[#335](https://github.com/CycleFive/kharon/issues/335),
[#336](https://github.com/CycleFive/kharon/issues/336)). None of
them absorb #328. They sit on milestone `next`, labelled
`platform:openclaw`, and are listed on
[#346](https://github.com/CycleFive/kharon/issues/346).

1. **design: which tab an OpenClaw fill uses** — Decided on #334
   (2026-11-15): option (b), the tab OpenClaw already opened, under
   `allow_default_context` with one agent.
   [#343](https://github.com/CycleFive/kharon/pull/343) fixed the
   bug that blocked it.
2. **docs(dep): OpenClaw connector install for the managed local
   browser** — The repeatable steps from the decision above, plus
   the profiles OpenClaw support does not cover. Follows whatever
   #328 learned.
3. **test: OpenClaw canary on the managed browser** — The OpenClaw
   evidence: one approved fill, Disconnect, the platform still
   driving the browser, versions recorded. #328 remains the soak
   attempt.

## Hermes

Hermes here is Hermes Agent (Nous Research). Read from its browser
docs on 2026-11-14
([Browser automation](https://hermes-agent.nousresearch.com/docs/user-guide/features/browser)).
The default-launch live check is on
[#337](https://github.com/CycleFive/kharon/issues/337) (2026-11-15).
The other modes in this section were not checked by installing
Hermes.

### How Hermes exposes a browser

`browser_exec` drives a browser over CDP, through the browser-harness
engine. Where that browser comes from is a separate choice:

- **Local Chromium, the default.** Hermes launches a packaged
  Chromium, headless, one browser per session, throwaway profile
  unless `browser.user_data_dir` is set. The docs say this path does
  not touch the installed Chrome and does not raise the remote
  debugging approval dialog. The raw `browser_cdp` tool is offered
  only when a CDP endpoint is configured. The default launch is CDP
  inside the harness. On 2026-11-15 the
  [#337](https://github.com/CycleFive/kharon/issues/337) live check
  passed on the VM 126 Hermes host: a stock session's packaged
  Chromium (Chrome for Testing 145) published a loopback DevTools
  port, ephemeral, discovered from `DevToolsActivePort`, and a second
  client attached while `browser_exec` drove. The port is not a fixed
  configured endpoint. #337 stays open on whether that ephemeral port
  is stable enough for the connector.
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
  kharon's fill path is Chromium CDP. Out of Hermes support.
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
question are the same as for OpenClaw.

The [#337](https://github.com/CycleFive/kharon/issues/337) live check
passed on 2026-11-15, as above. Whether that ephemeral port is a
stable one the connector can open is still open on #337. Until that
call, the install doc stays on the explicit endpoint.

### Goal

A managed customer attaches kharon to a loopback Chromium Hermes is
already configured to drive, approves one fill, and Hermes keeps
that browser.

### Exit criteria

- The default-launch check is recorded, and the install doc matches
  it.
- The agent-host docs grow a Hermes section for `browser.cdp_url` /
  `BROWSER_CDP_URL`, with the CLI-only note on `/browser connect`,
  the shared loopback port, and the modes Hermes support does not
  cover (default packaged Chromium until #337's stable-port call,
  cloud providers, Lightpanda, `browser_vault`).
- One recorded canary on that shared browser: approved fill,
  Disconnect, Hermes still driving it, next fill `no_browser`.
- No new transport.

### Proposed issues

Filed
([#337](https://github.com/CycleFive/kharon/issues/337),
[#338](https://github.com/CycleFive/kharon/issues/338),
[#339](https://github.com/CycleFive/kharon/issues/339)). They are
labelled `platform:hermes` and listed on
[#347](https://github.com/CycleFive/kharon/issues/347).

1. **design: does Hermes's default local Chromium publish a loopback
   CDP port?** — The live sub-checks passed on 2026-11-15: an
   ephemeral loopback port, discovered from `DevToolsActivePort`,
   and a second client attached while `browser_exec` drove. #337
   stays open on whether that counts as stable. A no keeps Hermes
   support on the explicit endpoint only.
2. **docs(dep): Hermes connector install on an explicit local CDP
   endpoint** — `browser.cdp_url` and the connector on the same
   loopback port, CLI `/browser connect` called out as not a gateway
   command, cloud and Lightpanda excluded. Depends on the OpenClaw
   tab-ownership decision; Hermes gets the same rule unless this
   check shows it cannot.
3. **test: Hermes canary on the shared loopback browser** — The
   Hermes evidence, same shape as the OpenClaw canary.

## Later CDP hosts

### Goal

After Hermes, each further CDP-capable agent host is tracked the
same way: a platform label and a `tracking: <platform> support`
issue, not a milestone. A host qualifies when it already exposes
Chromium CDP on loopback on a machine where
`kharon-agent-connector` can run, and kharon can fill and let go.
The survey below names the order. The work runs in parallel with
OpenClaw and Hermes, because it is gated on external live checks,
and it ships in whichever rolling release has its canary test and
live check.

### Exit criteria

For browser-use, the first host that survey names after Hermes, the
same bar as OpenClaw and Hermes: a written install, one approved
canary, Disconnect leaves the platform driving the browser, and the
modes that are not loopback Chromium CDP stated as out of that
platform. The host counts as supported only once the canary test
and live check pass.

### Proposed issues

None named, and none filed from this page. When a host is chosen,
the set is the same three: a short design check for anything the
docs leave unverified, the install doc, and the canary report.

### Platform priority after Hermes

The survey is
[`docs/agent-adoption-survey.md`](agent-adoption-survey.md) (#340).
After OpenClaw and Hermes it ranks browser-use, then Playwright MCP
and Chrome DevTools MCP.

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
  above. The issue is open, labelled `parked`, and on no milestone.
  It is not soak work and not a platform release.
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

**Which tab is filled?** Closed on
[#334](https://github.com/CycleFive/kharon/issues/334) (2026-11-15):
option (b), under `allow_default_context` with one agent.
[#343](https://github.com/CycleFive/kharon/pull/343) fixed the bug
that blocked it;
[#345](https://github.com/CycleFive/kharon/pull/345) added the
follow-ups.

## Open questions

1. **Which OpenClaw profile does the soak host actually run?**
   OpenClaw support targets the managed profile that has a CDP port.
   If #328's host is on the extension relay, that profile has no CDP
   URL and stays out with #331. The platform order stays OpenClaw,
   then Hermes.
2. **Is Hermes's default packaged Chromium included?** The
   [#337](https://github.com/CycleFive/kharon/issues/337) live check
   passed on 2026-11-15 (VM 126, Chrome for Testing 145): an
   ephemeral loopback DevTools port, discovered from
   `DevToolsActivePort`, and a second client attached while
   `browser_exec` drove. #337 stays open on whether that port is
   stable enough to join Hermes support. Until that call, the
   install doc stays on the explicit endpoint. Cloud providers,
   Lightpanda, and `browser_vault` stay out either way.

The platform order is settled: OpenClaw, then Hermes. The research
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

Tracker, 2026-11-15: the open milestone is `next`. Milestones
v0.4.0, v0.5.0, and v0.6.0 are closed. Platform tracking is
[#346](https://github.com/CycleFive/kharon/issues/346) (OpenClaw)
and [#347](https://github.com/CycleFive/kharon/issues/347) (Hermes).
