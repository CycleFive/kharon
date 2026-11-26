# Roadmap

Status: updated 2026-11-26. kharon ships on rolling releases. The
latest release is
[v0.5.0](https://github.com/CycleFive/kharon/releases/tag/v0.5.0)
(teach mode). OpenClaw and Hermes have been supported since
[v0.4.0](https://github.com/CycleFive/kharon/releases/tag/v0.4.0).
This page doesn't promise a platform or a feature for any particular
version.

Direction from Lothrop, 2026-11-14: kharon stays on the
agent-connector. It grabs a CDP endpoint the agent platform already
exposes, fills, and hands the browser back.

## How work and releases are organised

Lothrop moved to rolling releases on 2026-11-15, and on 2026-11-26
confirmed that the roadmap follows them too. The old
one-minor-per-platform plan (v0.5.0 OpenClaw, v0.6.0 Hermes, then one
minor per CDP host) is retired. Both of those platforms shipped
together in v0.4.0.

- **Milestones are themed scope.** Each one (`M1 — submitted-fill
  canary`, `M2 — teach mode`, …) has a goal, exit criteria and a due
  date, and carries the Groom, Scope check and Close-out chores. See
  [`milestone-chores.md`](milestone-chores.md). The open milestone,
  plus the `next` backlog, is the current plan, so this page doesn't
  repeat it.
- **Releases are cut when user-visible work lands.** A minor version
  ships whatever has merged and passed its gate since the last one. It
  is cut when master is green and at least one user-visible change
  has landed, any number of times per milestone, as an annotated tag
  and a GitHub release published by the `cycle-five` identity. The
  release notes list what shipped and the supported platforms.
- **Platforms are tracked by label and tracking issue, not by
  version.** Each one gets a `platform:<name>` label and a `tracking:
  <platform> support` issue. A platform counts as supported in a
  release only once its canary test and live check pass. Platform
  work runs alongside the milestones, because it is gated on external
  live checks.
- The version-named milestones `v0.2.0` through `v0.6.0` are closed
  and kept as history. The `v0.5.0` and `v0.6.0` milestones were the
  old OpenClaw and Hermes slots. Their issues shipped in v0.4.0, and
  the v0.5.0 tag is teach mode.

## Shipped so far

| Release | Date | Headline |
|---|---|---|
| v0.3.0 | 2026-11-14 | Dashboard connector auth (N3 phase 2). |
| v0.4.0 | 2026-11-23 | `kharon_open`, zero-config Hermes (`DevToolsActivePort`), opt-in post-submit scrub. **OpenClaw and Hermes supported.** |
| v0.5.0 | 2026-11-26 | Teach mode: login methods, the player and the per-site registry (M2). Test pages only until [#393](https://github.com/CycleFive/kharon/issues/393) lands. |

The release notes on GitHub are the full record.

## Principles

These hold for every platform and every feature.

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

## Supported platforms

Both shipped in v0.4.0, after their canary tests and live checks
passed on 2026-11-17 (recorded in
[#360](https://github.com/CycleFive/kharon/issues/360)). Install
steps are in [`docs/agent-runtime-setup.md`](agent-runtime-setup.md),
and Hermes end to end is in
[`docs/hermes-end-to-end.md`](hermes-end-to-end.md). The tracking
issues are [#346](https://github.com/CycleFive/kharon/issues/346)
(OpenClaw) and [#347](https://github.com/CycleFive/kharon/issues/347)
(Hermes), both closed. The notes below are the platform background
the install docs link to.

## OpenClaw

Supported since v0.4.0. kharon fills the managed `openclaw` profile's
Chromium through its loopback `cdpPort`, using the tab OpenClaw
already opened, under `allow_default_context` with one agent. That
was decided on [#334](https://github.com/CycleFive/kharon/issues/334),
and [#343](https://github.com/CycleFive/kharon/pull/343) fixed the
bug that blocked it.

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

## Hermes

Hermes here is Hermes Agent (Nous Research). It has been supported
since v0.4.0, including stock Hermes with no config: the connector
discovers the packaged Chromium's loopback port from
`DevToolsActivePort`
([#349](https://github.com/CycleFive/kharon/issues/349)), and an
explicit `cdp_url` still wins. Read from its browser docs on
2026-11-14
([Browser automation](https://hermes-agent.nousresearch.com/docs/user-guide/features/browser)).

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
  client attached while `browser_exec` drove. Lothrop and Nyx decided
  that check is sufficient: the ephemeral port counts, and stock
  Hermes works with no config. Hermes support includes this Chromium
  through `DevToolsActivePort` discovery
  ([#349](https://github.com/CycleFive/kharon/issues/349)): the
  connector re-reads the file on each reconnect, and an explicit
  `cdp_url` still wins. #337 is closed as decided.
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
  port for a second client is unverified. Out of Hermes support. The
  default-launch question is decided for the packaged Chromium; this
  mode was not in that check.

`browser_vault` fills logins Hermes stored, into the same browser
session. kharon does not call it. The customer vault stays the
Bitwarden collection on the broker.

## Later CDP hosts

Each further CDP-capable agent host is tracked the same way as
OpenClaw and Hermes: a platform label and a `tracking: <platform>
support` issue. A host qualifies when it already exposes Chromium CDP
on loopback, on a machine where `kharon-agent-connector` can run, and
kharon can fill and let go. Its bar is the same: a written install,
one approved canary, Disconnect leaving the platform driving the
browser, and a statement of which modes are not loopback Chromium CDP
and so are out of that platform's support. It ships in whichever
release follows its canary test and live check. No host is scheduled.
When one is chosen, its issues go into `next`, or into a milestone if
the Groom pulls them in.

### Platform priority after Hermes

The survey is
[`docs/agent-adoption-survey.md`](agent-adoption-survey.md) (#340).
After OpenClaw and Hermes it ranks browser-use, then Playwright MCP
and Chrome DevTools MCP.

## Teach mode

Teach mode turns a login a person demonstrates into a login method
the broker can replay ([#361](https://github.com/CycleFive/kharon/issues/361),
user docs [`teach-mode.md`](teach-mode.md)). Pieces 1 (the recorder)
and 2 (methods, the player, and the per-site registry) shipped in
v0.4.0 and v0.5.0. Piece 3, the never-in-the-page rung, was taken to
a design decision in M2 and rejected
([note](superpowers/specs/2026-11-25-teach-never-in-page-design.md)).
The ladder tops out at `milliseconds` for agent replay.

Before teach mode is used on real sites,
[#393](https://github.com/CycleFive/kharon/issues/393) has to land
(Lothrop, 2026-11-25). It makes a first `method_drift` refuse only
that fill, marks the entry stale only when drift repeats or comes
from another agent, and adds a value-free pre-check so a drift
doesn't spend the grant. Until then, teach mode is for the test pages
only.

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
  standing host.** Parked 2026-11-14 and closed as not planned
  2026-11-25. A standing host for Duet would mean running a whole
  browser for that agent, which is the line above.
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

Tracker, 2026-11-26: the open milestones are `next` and the current
M-numbered milestone. The version-named milestones v0.2.0 through
v0.6.0 are closed. The earlier, platform-per-version version of this
page is in git history (#332, #348).
