# Duet kharon connector host: requirements

> Point-in-time research record from Claude Duet, Nov 14, 2026. Check claims against current code and the linked sources before relying on them.

Nov 14, 2026.

A small Debian 12 or 13 VM on Proxmox can run kharon-agent-connector and Chromium exactly as the repo's provision-connector.sh sets them up. The hard part is not the host: it is how Duet drives that Chromium, because Duet's cloud sessions can reach neither the host's loopback CDP nor kharon.twkr.io.

Tags: **\[repo\]** = confirmed in CycleFive/kharon at master 30ecd56 (v0.3.0) or in #kharon. **\[inferred\]** = my reading, not stated anywhere.

## How the pieces fit

The connector does not serve /mcp, so Duet would not be an /mcp client of this host. **\[repo\]**

1. kharond's /mcp lives on the broker, at https://kharon.twkr.io/mcp. The agent calls it with its agent token (kh\_agent\_…) or a Connect access token (kh\_at\_…).
2. The connector on this host dials out to wss://kharon.twkr.io/connector, authenticates with its own tunnel credential, and relays the broker's CDP traffic to Chromium on 127.0.0.1:9222. It never holds the agent token.
3. The agent also needs its own CDP session to the same Chromium. kharon\_context returns its browser\_context\_id; the agent opens and navigates tabs in that context (Target.createTarget), then calls kharon\_fill with the tab's cdp\_target\_id and expected\_origin. Tabs outside that context are target\_not\_owned.

So Duet needs two paths: one to kharon's /mcp, and one to this host's CDP. The section on Duet's side covers both.

## Host

| Item | Requirement | Basis |
| --- | --- | --- |
| OS | Debian 12 or 13; the script refuses anything without /etc/debian\_version | \[repo\] provision-connector.sh |
| Platform | A Proxmox VM, not an unprivileged LXC. The script sets kernel.yama.ptrace\_scope, which a container can't, and Chromium's sandbox needs user namespaces or else --no-sandbox | \[inferred\] from agent-runtime-setup.md |
| Arch | x86\_64. arm64 should also work (Debian ships chromium for it; the connector is plain Rust) | \[inferred\] |
| CPU, RAM, disk | 2 vCPU, 4 GB RAM, 20 GB disk. Headless Chromium is nearly all of it; the connector is one small process | \[inferred\], the repo gives no sizing |
| Packages | chromium and fonts-liberation; from kharon, only the connector binary | \[repo\] |
| Users | browser runs Chromium (profile /var/lib/browser, mode 0700); connector runs the connector; whatever drives the browser for Duet runs as a third, non-root user. A root agent can read the profile, the token file and Chromium's memory | \[repo\] deployment.md, Running the agent |
| Chromium | --headless=new, CDP on 127.0.0.1:9222 only, its own --user-data-dir, --password-store=basic, plus the managed policy no-password-manager.json (password manager, leak check, address and card autofill, payment query, sync, metrics all off) | \[repo\] |
| Connector binary | Built from master at 30ecd56 or later, which has #321 so a kh\_at\_ token file loads: cargo build --release -p kharon-agent-connector, installed 0755 at /usr/local/bin | \[repo\] #321, #322 |
| Clock | NTP on; the outer TLS to Cloudflare is checked against system roots and validity dates | \[inferred\] |

## Network

- **Out:** TCP 443 to kharon.twkr.io for the WebSocket (subprotocol kharon-connector.v1). Mux pings every 20 s keep it alive through Cloudflare. **\[repo\]**
- **Out:** HTTP and HTTPS to whatever sites Chromium signs in to. **\[inferred\]**
- **In:** nothing. No open port, no UDP, no WireGuard, no CAP\_NET\_ADMIN. **\[repo\]** path (B)
- **Tailnet:** not needed on the ws path. Muse's host sends the connector through a tailnet HTTP proxy; that is optional (proxy = "http://host:port", plus proxy\_creds\_file if it needs auth). **\[repo\]** and Muse in #kharon
- **Edge:** the /connector rate limit (5 per 10 s, Free plan) has been live since Nov 12. A connector that crash-loops can hit one 429 and recovers alone. Nothing may add an Origin header to /connector, or the upgrade gets 403. **\[repo\]**

## Files and credentials

| File | Mode, owner | Holds | Secret |
| --- | --- | --- | --- |
| /etc/kharon-connector/connector.toml | 0644 root | transport = "ws", broker\_url = "wss://kharon.twkr.io/connector", broker\_pin, agent\_id, token\_file, cdp = "127.0.0.1:9222" | No |
| /etc/kharon-connector/token | 0400 connector (0600 also accepted) | One credential: kh\_tunnel\_… from kharon tunnel mint, or kh\_at\_… from a Connect connector grant. Anything else is refused before dialing | Yes |
| /etc/kharon-connector/proxy-creds | 0400 connector | One user:password line, only if the proxy needs auth | Yes |
| Agent token kh\_agent\_… | Never on the connector | Lives with whatever MCP client Duet uses | Yes |

- **Broker side:** \[agents.\<id>\] gets token\_hash, connector\_token\_hash and cdp = { endpoint = "ws://127.0.0.1:9222", via = "agent\_connector" }, then kharond restarts. **\[repo\]**
- **broker\_pin:** the SHA-256 of the \[connector\] certificate's DER. Not secret, but send it one way and confirm its first and last 8 hex digits another way. Compare against /.well-known/oauth-protected-resource/connector, never adopt it from there. **\[repo\]**
- **Handover:** by a secret setting, age-encrypted to the host, or typed at a hidden prompt into the file. Never in chat, Discord, an issue, argv or an image. **\[repo\]** agent-runtime-setup.md

## Process supervision

- provision-connector.sh writes two systemd units **\[repo\]**: browser.service (Restart=on-failure) and kharon-agent-connector.service (Restart=always, RestartSec=1, ProtectSystem=strict, the config dir read-only).
- The connector retries with jittered backoff from 1 s to a 30 s cap, and waits a fixed 60 s after a refused credential. **\[repo\]**
- Alert on its log line "no broker session for …", printed after 2 minutes and every 10 minutes after. **\[repo\]**
- Run --check only with the service stopped: a passing check takes over the agent's one live session. Never use it as a health probe. **\[repo\]**
- The broker locks 30 minutes after the last fill, unlock or grant approval. A lock closes the browser context, so the agent calls kharon\_context again after the owner unlocks. **\[repo\]**

## Duet's side

What Duet has today (checked this morning): each session is a fresh Ubuntu 24.04 x86\_64 container that is reclaimed when idle; outbound HTTPS goes through an allowlisted proxy that refuses kharon.twkr.io (CONNECT 403); it is not on the tailnet; and it controls no CDP browser on any host of yours. Four ways to close the gap:

| Option | What it takes | Trade-off |
| --- | --- | --- |
| A. Remote Control on the box | Claude Code installed on this host under a non-root agent user, signed in to your account, with Remote Control on. Duet's kharon work runs there, with local CDP and direct HTTPS to /mcp | Fastest, little new code. That session has full CDP, so it could run page JS and read filled values; the harness policy isn't enforced. The session only takes work while it's connected |
| B. MCP bridge on the box | A small MCP server on this host, as the agent user: browser tools scoped to Duet's context (open tab, navigate, read text, click, list tabs; no JS eval, no input values) plus a pass-through to /mcp holding the agent token. Published through a Cloudflare Tunnel with OAuth, like the GitHub and Discord brokers, and added as a claude.ai connector | Works from any Duet session, since connector calls come from claude.ai rather than the sandbox proxy \[inferred, from the brokers working today\]. Enforces the harness policy. Needs new code |
| C. kharon /mcp as its own claude.ai connector | claude.ai would have to present a client\_id metadata document (kharon has no dynamic registration), that URL listed in \[oauth\].clients, and Cloudflare's bot rule letting its client through | Gives kharon tools but no browser, so it only pairs with B's browser half. Each consent mints a new c- identity, and claude.ai won't run the connector grant that identity's connector needs |
| D. Widen the sandbox egress | kharon.twkr.io allowlisted for the cloud environment, if environment settings allow it \[unverified\] | Solves /mcp only. CDP stays on loopback by design |

My pick: A for this week's soak with throwaway accounts, then B if Duet should fill for real.

## Browser pools

No off-the-shelf pool gives persistent and one-off Chromium sessions under one free, permissive license. For kharon, each agent needs its own Chromium with CDP on loopback, and a profile can be open in only one browser at a time. So any pool here comes down to one container per persistent profile, plus throwaway containers for one-off work.

| Option | License | Pool and queue | Persistent sessions | How clients attach | Fit for kharon |
| --- | --- | --- | --- | --- | --- |
| Steel Browser | Apache-2.0, public beta | Manages sessions; describes no pool or cap, so one container per concurrent session \[inferred\] | Keeps cookies and local storage across requests; no documented profile directory | REST sessions API, then Puppeteer or Playwright over CDP | Good agent API; its CDP port behind the connector is untested |
| Browserless | SSPL-1.0 or commercial | Built-in queueing and concurrency limits | Persistent sessions and user-data-dir are Enterprise only | Puppeteer or Playwright WebSocket on its own port | Most complete pool, but the license and paid persistence |
| Selenium Grid 4 | Apache-2.0 | Router and session queue; Dynamic Grid starts a fresh container per session and throws it away | Not documented; a mounted profile volume should work \[inferred\] | WebDriver first; CDP per session through se:cdp \[unverified\] | Strong for one-off sessions; WebDriver-shaped |
| kernel-images | Apache-2.0 | None: one sandboxed Chrome per image | Unikernel build can snapshot and restore state; no profile option documented | Raw CDP with /json/version on 9222 | Exactly the shape the connector expects; you write the allocator |

My pick: plain Chromium containers (kernel-images, or the browser.service unit in a container) with one named volume per persistent profile, and a small allocator that hands each caller a CDP endpoint. Use Steel instead if you want a sessions API without building one, and Browserless if SSPL and paying for persistence are fine. Facts above are from each project's README and docs, read today.

## Open questions

**Decided by Lothrop (Nov 14)**

- [x] Box: a new Proxmox VM.
- [x] Duet's browser path: option A, Remote Control on the box.
- [x] Identity: a static agent in \[agents.\<id>\], not a Connect identity. The id itself (for example duet) is still open.

**For Nyx**

- [ ] Can a hand-minted tunnel credential attach for a Connect identity (c-…), or only for a static \[agents.\<id>\]? This decides whether C can ever carry the browser.
- [ ] Does Muse's install write-up, promised in #kharon, add anything missing here, such as the loopback proxy her host runs?
- [ ] Is there a CDP-limited browser MCP server the project would rather adopt than build for B?

**Unverified on Duet's side**

- [ ] Whether claude.ai's connector client uses client\_id metadata documents, and whether its user agent passes the zone's bot rule (#322 saw error 1010 for a default Python client).

## Sources

All in CycleFive/kharon at master 30ecd56, read today: docs/deployment.md (Path (B) broker, Public gateway, OAuth discovery, Agent host, Running the agent, MCP client), docs/agent-runtime-setup.md, docs/api/mcp-tools.json, deploy/agent-host/provision-connector.sh, crates/kharon-agent-connector/src/main.rs, issues #321 and #322, and #kharon on Lothrop Muses (Nov 14, 12:00 to 12:22 UTC).
