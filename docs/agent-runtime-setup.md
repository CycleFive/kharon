# Agent side: hosted and root runtimes, and handing over credentials

This page covers the agent host on a managed deploy when it is not a
Debian machine you can run
[`provision-connector.sh`](../deploy/agent-host/provision-connector.sh)
on. That is usually a hosted agent runtime: a container or VM that a
dashboard or a third party runs, where the agent is root and the
operator has no shell. The #121/#201 pilot ran that way. It also
covers how the operator hands the agent its three values without
ever putting a secret in chat or on a command line.

Read [Agent host](deployment.md#agent-host-req-dep-005) first. It
explains path (B), the connector config and `--check`. Everything
there still applies; this page only replaces the script with manual
steps and says what changes when the agent is root.

## What the agent side needs

| Value | Secret? | Where it goes | Made by |
|---|---|---|---|
| Tunnel credential | Yes | A file the connector reads (`token_file`), mode `0400` or `0600` | `kharon tunnel mint <agent>` on the broker |
| Agent token (`kh_agent_<id>_…`) | Yes | The agent's MCP client, as the bearer for `POST https://<host>/mcp` | `kharon token mint <agent>` |
| `broker_pin` | No, but it must arrive unaltered | `connector.toml` | `openssl x509 -outform DER \| sha256sum` on the inner `[connector]` certificate |

Plus the connector binary (`kharon-agent-connector`, built from this
repo) and, with an authenticating egress proxy, a proxy credential
file. The connector never holds the agent token, and the MCP client
never holds the tunnel credential (REQ-ARCH-001).

## Hosted or root runtime, step by step

Do these in the runtime, as whoever can install software there
(often the agent itself, or the runtime's setup script). None of them
needs a secret except step 5.

1. **Chromium with CDP on loopback.** Run Chromium (or Chrome) with
   `--remote-debugging-address=127.0.0.1 --remote-debugging-port=9222`
   and its own `--user-data-dir`. Headless is fine. A runtime that
   cannot give Chromium a user namespace needs `--no-sandbox`; the
   pilot ran that way under an AppArmor user-namespace restriction.
   Keep it running with whatever supervisor the runtime has (systemd,
   s6, a process manager, the runtime's own restart policy).
2. **The managed policy.** Write the same JSON the script writes,
   with password manager, leak detection, autofill, payment-method
   query, sync and metrics off, to the policy directory of the
   browser you run: `/etc/chromium/policies/managed/` for Debian's
   `chromium`, `/etc/opt/chrome/policies/managed/` for Google Chrome.
   The file is in
   [`provision-connector.sh`](../deploy/agent-host/provision-connector.sh)
   (`no-password-manager.json`). Check it took effect: open
   `chrome://policy` through CDP and look for the seven policies with
   status OK. Without it Chromium may offer to save a filled password
   (REQ-ARCH-004).
3. **`ptrace_scope`.** Set `kernel.yama.ptrace_scope = 1` if the
   runtime lets you. In most containers it is the host's setting and
   you can't. Either way it doesn't stop root (see below).
4. **The connector binary.** Copy `kharon-agent-connector` to
   `/usr/local/bin/` (mode `0755`). It has no secret in it, so any file transfer the runtime offers is
   fine. Build it on a machine with this repo:
   `cargo build --release -p kharon-agent-connector`.
5. **The tunnel credential file.** Put it at
   `/etc/kharon-connector/token`, mode `0400`, owned by the uid that
   runs the connector. See [Handing over the secrets](#handing-over-the-secrets)
   for how it gets there. The connector refuses a file readable by
   group or others. The connector reads the file only when it starts:
   after replacing the credential, restart the connector.
6. **`connector.toml`.** Write `/etc/kharon-connector/connector.toml`
   as in [Connector config over WebSocket](deployment.md#connector-config-over-websocket):
   `transport = "ws"`, `broker_url = "wss://<host>/connector"`,
   `broker_pin`, `agent_id`, `token_file` and `cdp = "127.0.0.1:9222"`.
   This file holds no secret; mode `0644` is fine.
7. **Check, then run.** With nothing else running as this agent, run
   `kharon-agent-connector --config /etc/kharon-connector/connector.toml --check`
   and expect `check: ok`. A successful check replaces any live session
   for this agent, so don't run it as a health probe. Then run the
   connector under the runtime's supervisor with the same `--config`
   and no other arguments. Expect `agent connector attached: …
   transport=ws` in kharond's log.
8. **The MCP client.** Point it at `https://<host>/mcp` with the agent
   token as `Authorization: Bearer kh_agent_<id>_…`, stored in the
   client's or the runtime's secret setting, never in a prompt or a
   file the model reads. A worked config is in
   [MCP client](deployment.md#mcp-client). Tool names and schemas are
   [`docs/api/mcp-tools.json`](api/mcp-tools.json).
   Apply the [agent harness policy](deployment.md#agent-harness-policy-spec-oq-3).

### What a root agent costs (G1)

Every isolation boundary on the agent host is a Unix permission, and
root is exempt from all of them. A root agent can read Chromium's
profile, read the tunnel credential file, and attach to Chromium to
read `/proc/<pid>/mem`, where filled values live briefly. So on a
root runtime the steps above give you path (B)'s transport, the
approval flow and the audit log, but not REQ-GOAL-002's isolation.
Running the connector and Chromium as separate non-root users inside
the runtime helps only if the agent itself is not root. Tell the
customer which one they are getting.

### Dashboard runtimes and `/connector`

Since v0.3.0 (#235 phase 2), a dashboard Connect can also spawn the
connector. The dashboard's client metadata document must declare the
connector grant type; at consent the broker records that, and the
client redeems the extension grant for a connector token pair scoped
`kharon:connector`. The spawned connector's `token_file` then holds
the connector access token (`kh_at_…`) instead of a minted tunnel
credential — REQ-ARCH-002 makes a connector-audience `kh_at_` a
tunnel credential on wire v1, and the broker enforces the audience at
authenticate time. The connector binary must be built from v0.3.0 or
later to accept that token file (#320). A connector token is refused
on `/mcp` (401): the two legs stay separate (#304).

A standalone agent host — one that does not arrive through a
dashboard — still uses the hand-provisioned path on this page: a
minted tunnel credential, a `connector_token_hash` in
`[agents.<id>]`, and the file handed over out of band.

### Verify the install

The install is done when the identity has a live session:

- The owner's Connections page shows the identity with a live
  browser session (and since when).
- From the agent side, an MCP `kharon_context` call with the agent
  token returns the browser context id with status `ok`. Fills
  refuse until a session is live (REQ-OAU-007), so a refused fill
  with a "no browser attached" detail means the connector is not
  attached, whatever the MCP leg is doing.

## Hermes: connector on an explicit local CDP endpoint

Hermes Agent (Nous Research) drives its browser over CDP, so the
connector can share a browser Hermes is already attached to. This
section is the v0.6.0 slice (#338): an **explicit** local CDP
endpoint only. It adds no transport — the connector still dials a
loopback `host:port` on the agent host and attaches over the
WebSocket as above. kharon does not launch the browser; Hermes, or
an operator who started one for Hermes, owns it, and Hermes keeps
driving it after a fill (REQ-ARCH-003).

Hermes facts below are from its browser docs and the upstream
source pass on #337 (`NousResearch/hermes-agent` `main` @
`f578714`, 2026-11-15), not from a live Hermes install.

### Set up the shared endpoint

1. **Give Hermes a loopback Chromium on a fixed port.** The
   operator starts a Chromium with
   `--remote-debugging-address=127.0.0.1
   --remote-debugging-port=9222` and a dedicated `--user-data-dir`
   (since Chrome 136 a debugging port on the default profile
   directory is ignored), and keeps it running under a supervisor
   — for any non-CLI session this operator-started browser is the
   only path: nothing else will launch one for it, and a
   `browser.cdp_url` pointing at a port where nothing is
   listening attaches to nothing. The auto-launch in step 2 is a
   CLI-only convenience, and even there the browser it launches
   lives only as long as the CLI session that launched it, so it
   is not a stable target for a supervised connector.
   The examples use 9222, Hermes's documented default; any free
   loopback port works if both sides use it.
2. **Point Hermes at it, persistently.** In Hermes's `config.yaml`
   (`$HERMES_HOME/config.yaml`):

   ```yaml
   browser:
     cdp_url: "http://127.0.0.1:9222"
   ```

   or set `BROWSER_CDP_URL=http://127.0.0.1:9222` in Hermes's
   environment. Hermes resolves its CDP override in the order:
   a live `/browser connect` > `BROWSER_CDP_URL` >
   `browser.cdp_url`.

   `/browser connect` is a **CLI slash command only**. A gateway,
   WebUI, or chat-platform session will not run it — the message
   goes to the model as text — so never write an install or a
   runbook that tells a gateway/WebUI operator to type it. Typed in
   the CLI with no argument it attaches to
   `http://127.0.0.1:9222` (or a `ws://` URL passed to it), and if
   nothing is listening there it auto-launches a Chromium-family
   browser with `--remote-debugging-port=9222` and a dedicated
   user-data dir. For any non-CLI session, `browser.cdp_url` /
   `BROWSER_CDP_URL` is the attach mechanism.
3. **Point the connector at the same port.** Steps 3–8 above apply
   unchanged (`ptrace_scope`, binary, tunnel credential file,
   MCP client), with
   `connector.toml` naming that same loopback endpoint:

   ```toml
   cdp = "127.0.0.1:9222"
   ```

   The host gets its own agent id (#281). The managed policy from
   step 2 above must be in the policy directory of the Chromium
   Hermes drives — including an operator-launched one — or that
   browser may offer to save a filled password (REQ-ARCH-004).
   Run `--check` and start the connector as in step 7, and verify
   the install the same way: `kharon_context` returns `ok` with a
   live session on the owner's Connections page.

**Assumption (tab rule, pending #334).** Which tab a fill uses
follows the same rule proposed for OpenClaw, as an explicit
assumption until #334 decides it on a real profile: the fill
targets the browser context `kharon_context` returns, and a
default-context target is refused unless `allow_default_context`
is set, which is legal only with exactly one agent on the deploy.
If #334 or the Hermes canary (#339) shows Hermes cannot honour
that, this section changes before v0.6.0 ships — it is not a
settled Hermes fact.

### Modes this section does not cover

- **Default packaged Chromium (no `browser.cdp_url`).** The #337
  source pass found that the stock launch does publish a loopback
  DevTools port — `--remote-debugging-port=0`, an ephemeral port
  discoverable from the profile's `DevToolsActivePort` file — but
  the four live sub-checks on a real Hermes install are still
  open, and the connector has no discovery step for an ephemeral
  port. Until #337's live check passes, the default launch is
  **not** a supported install; use the explicit endpoint above.
- **Cloud providers** (Nous subscription, Browserbase, Browser
  Use, Firecrawl, another provider plugin). The browser is off
  the host; the connector dials loopback only.
- **Lightpanda** (`browser.engine: lightpanda`). Not Chromium;
  kharon's fill path is Chromium CDP.
- **`browser_vault`.** Hermes's own login store and fill tool.
  kharon does not call it; the customer vault stays the
  Bitwarden collection on the broker.
- **`browser.use_real_profile`.** A Hermes-managed snapshot of
  the user's real profile. Whether that launch can share its
  browser the way this section needs is unverified; out of this
  slice.

## Handing over the secrets

The tunnel credential and the agent token are each printed once, on
the operator's terminal, by the mint command. From there they go to
the runtime by one of these routes, in order of preference:

1. **The runtime's own secret setting.** Many hosted runtimes have a
   secrets or environment page that writes a value to a file or an
   environment variable inside the runtime. The person who minted the
   value pastes it there directly. For the tunnel credential, the
   runtime's setup step then writes it to the token file at mode
   `0400` (for example `install -m 0400 /dev/stdin
   /etc/kharon-connector/token` reading from that variable), and the
   variable is unset afterwards.
2. **Encrypted to the runtime.** The runtime generates a key pair
   (for example `age-keygen -o /root/handover.key`) and publishes only
   the public key. The operator encrypts the credential to it on the
   minting machine and sends the ciphertext any way they like; the
   runtime decrypts it straight into the token file
   (`age -d -i /root/handover.key | install -m 0400 /dev/stdin
   /etc/kharon-connector/token`) and deletes the key. `install` creates
   the file at mode `0400`, the same way route 1 does.
3. **The customer types it.** When the customer has a terminal in
   the runtime and the operator doesn't, the operator reads the value
   to them over a call. The customer types it at a hidden prompt
   straight into the token file, the way the canary is typed (#121):
   `( IFS= read -rs T; printf '%s' "$T" | install -m 0400 /dev/stdin
   /etc/kharon-connector/token; unset T )`. That writes mode `0400`
   and skips an editor's swap and backup files. Slow, but nothing
   stores it in transit.

Never:

- paste a secret into a chat, an issue, a PR, Discord, or the agent's
  conversation, where the model or a log keeps it;
- put it on a command line or in a URL (argv shows up in `ps` and
  shell history);
- commit it, or bake it into an image or a runtime template;
- reuse one credential for two agents.

`broker_pin` is not secret, so chat is fine, but a swapped pin points
the connector at someone else's broker. Send it one way and confirm
the first and last eight hex digits another way (a call, or the
owner UI).

### Who does what

| Step | Who |
|---|---|
| Mint the agent token and the tunnel credential, put both hashes in `[agents.<id>]`, restart kharond | Operator, on the broker |
| Compute and send `broker_pin` | Operator |
| Steps 1–4 and 6–8 above | Whoever can install in the runtime |
| Step 5, and putting the agent token in the MCP client's secret setting | Whoever holds the value, by a route above |

## Rotating after a leak

If either secret may have been seen by anyone who shouldn't have it
(a paste into chat counts):

- **Agent token.** On the broker, `kharon revoke agent <id>` while
  kharond is running (durable; it also revokes the agent's grants).
  Mint a new token, replace `token_hash` in `[agents.<id>]`, restart
  kharond, and hand the new token over by a route above. See
  [Agent tokens](deployment.md#agent-tokens-req-api-003).
- **Tunnel credential.** Run `kharon tunnel mint <id>`, replace
  `connector_token_hash` in `[agents.<id>]`, and restart kharond; the
  old credential stops authenticating. Hand the new one over, write
  it to the token file, and restart the connector.
- **The runtime itself** (root compromised, image leaked): rotate
  both, and if the agent may have read a filled value, treat that
  login's password as exposed and change it in the vault.
