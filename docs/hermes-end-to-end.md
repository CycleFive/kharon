# Hermes end to end: from the MCP client to an approved fill

> Point-in-time record from Claude Duet, Nov 15, 2026 (#352). Every
> statement below was seen in the live run described here unless it
> says **not tested**. Check it against current code before relying
> on it.

[`agent-runtime-setup.md`](agent-runtime-setup.md) covers the
connector on a Hermes host. This page covers the rest of the Hermes
side: the MCP client, what to tell the agent, what the agent then
does, what the owner does, and what each failure looks like.

## What was run

- Hermes Agent v0.23.1 (2026.9.24) on a Debian 13 VM, driven from
  its CLI (`hermes chat`), with a model that supports tool calling.
- Hermes's stock browser: the Chrome for Testing 145 build it
  bundles, launched by Hermes with `--remote-debugging-port=0`. No
  `browser.cdp_url`.
- A throwaway kharon broker with one static agent, a fixture vault
  holding one canary login, and `allow_default_context = true`. The
  owner approved over the CLI.
- The connector was a build of #350 (discovery from
  `DevToolsActivePort`), running as the Hermes user.

The fixed-port install on master was checked the same day only as
far as `kharon_context` returning `ok` and a fill driven by hand
(#337). Sections 2 to 6 do not depend on how the connector finds the
browser.

## 1. Managed policy for Hermes's browser

Hermes's bundled browser is Chrome for Testing, at
`~/.hermes/tools/chromium-<n>/chrome-linux64/chrome`. It reads
managed policy from

```text
/etc/opt/chrome_for_testing/policies/managed/
```

That is neither of the two directories step 2 of
[`agent-runtime-setup.md`](agent-runtime-setup.md) names. Put
`no-password-manager.json` there. With the file in place,
`chrome://policy` showed the password manager and autofill off by
managed policy.

## 2. The MCP client

Add kharon to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  kharon:
    url: "https://<host>/mcp"
    headers:
      Authorization: "Bearer ${KHARON_AGENT_TOKEN}"
```

Put the agent token in `~/.hermes/.env`, mode `0600`:

```text
KHARON_AGENT_TOKEN=kh_agent_<id>_<64 hex>
```

Hermes renders `${VAR}` in MCP server entries from that file. A
broker behind a private CA also needs `ssl_verify: "/path/to/ca.pem"`
in the entry; a public edge does not.

Check it before starting a session:

```text
$ hermes mcp test kharon
  Transport: HTTP → https://<host>/mcp
    Authorization: ***
  ✓ Connected (620ms)
  ✓ Tools discovered: 7
```

The model sees the tools as `mcp__kharon__kharon_status`,
`mcp__kharon__kharon_fill` and so on. Start Hermes after editing the
config. Whether a running session picks up a change is **not
tested**.

Two things to know about this setup:

- Step 8 of the install page says the token belongs in a secret
  setting, "never in a file the model reads". `~/.hermes/.env` is
  owned by the Hermes user, and Hermes runs shell commands as that
  user. Whether Hermes's tools refuse to read that file is **not
  tested**.
- `hermes mcp add` has an `--auth oauth` option. kharon's Connect
  flow with Hermes as the client is **not tested**; this run used
  the static agent token.

## 3. What to tell the agent

The prompt that worked:

```text
Please log in to https://<site>/login.html for me using the browser.

The login is stored in my kharon vault. Use the kharon tools to fill
the username and password into the page. Never type, guess or ask me
for a password. Filling needs my approval, which I will give when
the request shows up, so wait for it.
```

It has to carry three things:

- **The full login URL.** `kharon_search` returns only the host of
  an item's URI, so an agent that takes its destination from the
  vault goes to the site root (#351).
- **Use the kharon tools, never a typed password.**
- **Approval is coming.** Without that line the agent has no reason
  to wait.

## 4. What the agent does

From the transcripts. The order of the first steps varied between
runs. Hermes's `browser_exec` tool runs short Python with browser
helpers; the ones used here are `new_tab`, `wait_for_load`,
`page_info`, `cdp` and `js`.

1. `kharon_status`:
   `{"agent_id":"<id>","browser_context_id":null,"grants":[],"locked":false}`.
2. `kharon_search` with part of the host. One item comes back, with
   `"uris":[{"host":"<host>","match":"domain"}]` and a
   `username_hint`.
3. `browser_exec`: `new_tab("<login URL>")`, `wait_for_load()`,
   `print(page_info())`. This is what launches Hermes's browser.
4. `browser_exec`: `cdp('Target.getTargets')`, to read the tab's
   `targetId` and `browserContextId`. No kharon tool returns the
   target id; the agent has to get it from its own browser tool.
5. One of two tab choices. The model picked each of them in
   different runs of the same prompt.
   - **Its own tab.** Hermes opens tabs in the browser's default
     context, so kharon fills them only when
     `allow_default_context = true`, which is legal only with one
     agent on the deploy (REQ-ARCH-005). With the flag off the
     result was `target_not_owned` (seen earlier the same day on
     the fixed-port install, #337).
   - **A tab in kharon's context.** `kharon_context` returns
     `{"browser_context_id":"<ctx>","status":"ok"}`. The agent then
     runs
     `cdp('Target.createTarget', url='<login URL>', browserContextId='<ctx>')`
     and uses the `targetId` that returns. This run had the flag on;
     this path with the flag off, and whether Hermes's click and
     type helpers work on a tab opened this way, are **not tested**.
6. `kharon_fill` with `item_id`, `target` (`cdp_target_id`,
   `expected_origin`), `fields` and `submit: false`:
   `{"fields_filled":[],"grant_request_id":"gr_…","status":"pending_approval"}`.
   Some runs called `kharon_request_grant` first and got
   `{"grant_request_id":"gr_…","state":"pending"}`.
7. Waiting. There is no tool that blocks until the owner answers.
   The agent polled `kharon_status`, where a pending request does
   not appear; only an issued grant does. After three identical
   calls Hermes told the model to stop repeating itself. With no
   approval, the agent slept 60 seconds, checked once more, and
   handed back to the user with the request id.
8. After approval `kharon_status` lists the grant:
   `{"id":"g_…","actions":["fill"],"max_uses":1,"uses":0,"expires_at":"…"}`.
   The agent called `kharon_fill` again with that `grant_id`:
   `{"fields_filled":["username","password"],"status":"filled"}`.

A second CDP client then read the password field, and its SHA-256
matched the canary's. `submit: true` is **not tested** here.

## 5. What the owner does

Approve inside two windows:

- A pending request is denied after 120 seconds. That is from the
  `kharon_request_grant` description; no request was left to expire
  in this run.
- A `once` grant lasts 120 seconds and one fill (SPEC §5). The
  `expires_at` on each grant here was 120 seconds after approval.

Over the CLI, which is what this run used:

```text
$ kharon grants
gr_… agent=<id> item=<item id> action=fill origin=https://<host>
$ kharon approve gr_…
grant g_…
```

The owner UI and ntfy approval were not part of this run.

A test broker left alone locked itself. While it is locked,
`kharon_status` reports `"locked": true` and the other tools answer
HTTP 423 ([`deployment.md`](deployment.md#mcp-client)). `kharon
unlock` needs a terminal.

## 6. When it does not work

What the agent got back, and what caused it in this run:

| Result | Cause seen |
|---|---|
| `kharon_context`: `{"status":"error","detail":"cdp_error"}` | The connector is attached but reaches no browser: Hermes has not opened one yet, or the connector's user cannot read Hermes's profile directory. The connector logged nothing. |
| `kharon_fill`: `{"status":"error","detail":"cdp_error"}` | The same. |
| `kharon_request_grant`: `{"state":"target_not_owned"}` (a fill with no grant returns the same status) | Three different causes. The tab is in the default context and the flag is off. Or the connector reached no browser, right after a `cdp_error`. Or the connector reached a different browser from the one holding the tab (see Limits). |
| `kharon_context`, `kharon_fill`, `kharon_request_grant`: `timeout` | The connector is not attached to the broker. |
| `kharon_fill`: `{"status":"denied","detail":"grant_denied"}` | The call named a `grant_id` that was already spent. |

`no_browser` never reached the agent in this run, for a static
agent with a minted tunnel credential.

## Limits seen in this run

- **One live Hermes browser.** With two `hermes chat` sessions at
  once there were two Chromium processes. Both sessions' tabs were
  in the older one, and the newer one sat on `about:blank`. The
  #350 connector dialed the newer one, so the fill target was
  `target_not_owned`.
- **The browser ends with the CLI session.** Each `hermes chat`
  exit removed the browser and its profile directory, so every turn
  was a new launch on a new port. A long-lived gateway session is
  **not tested**.
- **`browser_exec` runs JavaScript in the page.** The agent used
  `js()` to read the lengths of the two fields after the fill.
  Nothing in the harness stops it reading the values, so stock
  Hermes does not meet the first item of the
  [agent harness policy](deployment.md#agent-harness-policy-spec-oq-3).
- **The connector's user.** Hermes creates each profile directory
  mode `0700`. The connector found the browser only when it ran as
  the Hermes user, which also lets the agent read the tunnel
  credential. The options are in the Hermes section of
  [`agent-runtime-setup.md`](agent-runtime-setup.md) once #350
  lands.
- **Leak check.** The canary was in none of the audit log, the
  broker and connector journals, the agent's transcripts, or
  Hermes's sessions and logs.
