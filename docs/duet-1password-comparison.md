# 1Password in Duet vs kharon

> Point-in-time research record from Claude Duet, Nov 14, 2026. Check claims against current code and the linked sources before relying on them.

Nov 14, 2026.

## Verdict

No: kharon can't reproduce this shape as a custom connector, so #327's VM is still needed for the soak.

- **Why:** Duet's 1Password fill is a platform feature. Its two tools are the app's own and act on the app's own cloud browser. A custom MCP connector gets tool calls and nothing else: it gets no tab handle, no CDP endpoint and no way to install an extension in that browser.
- **What would make it work:** Anthropic opening that password-manager slot to a Bitwarden-backed provider. kharon's broker could be that provider, but that integration is Anthropic's call, not something kharon can ship on its own.
- **The one real alternative to #327:** a browser hosted on the kharon side, which Duet threads drive through MCP tools (navigate, read, click, fill). That removes the Claude Code VM, but you still need a Chromium host, and Duet's built-in browser features don't carry over (inferred).
- **Where kharon is already ahead:** its grants are one-shot and expire after 120 s, and decryption stays on owner hardware. The trade is reach: 1Password works in every Duet thread with no setup.

## What Duet actually exposes

A Duet thread sees two password-manager tools, and both belong to the app. Searching the tool list for "1password" finds no separate 1Password connector. Everything in this section is from the tool descriptions this thread loaded on 2026-11-14 (observed). I called neither tool.

| Tool | Takes | Returns |
| --- | --- | --- |
| `browser_credentials_request` | `goal` (≤140 chars), `logins[]` (≤5 of `website`, `reason`, `keywords[1-5]`), or `request` to poll a request already made | A request name, then a status: asked, waiting, approved (with the websites granted and not granted), denied, expired, needs\_user\_message, access\_ran\_out and others |
| `browser_credential_fill` | `request`, `website` | A status only: filled, fillFailed, autosubmitFailed, may\_have\_filled, not\_run with a reason |

What the descriptions say about the design:

- **No values pass through the model.** "You receive only a status; no credential value ever passes through you." The fill types the username, the password and any one-time code saved with the login, then submits.
- **It fills the session's own cloud browser.** It fills "the page that is open in your browser", picked by website, with no tab id. A request returns `not_run` with `no_browser` or `worker_not_found` until that browser is running, which ties the request to the browser worker.
- **Approval happens in 1Password's app.** A card in the chat opens the request, and the user approves in 1Password's own app, which must be open, unlocked and signed in. A grant serves only the session that asked, for an hour from the ask.
- **Duet adds a human-presence gate.** `needs_user_message` means 1Password works only after the user types a new message in their own words. A tapped suggested reply doesn't count.
- **The page is still in the agent's environment.** The app's own rules tell the model that a password box is hidden from it "but not perfectly", and that if a filled value shows in a snapshot, it must not be copied or repeated.

## Side by side

The two designs agree on the security core and differ on who owns the browser. Labels: **obs** = seen in this thread's tool descriptions, **doc** = from 1Password's docs or press (often via kharon's research notes), **repo** = kharon's SPEC and docs at master.

|  | 1Password in Duet | kharon v0.3.0 |
| --- | --- | --- |
| Where the credential lives | The user's 1Password vault. Decrypted per fill in an attested AWS Nitro enclave at 1Password, over a Noise session from the executor (doc) | A dedicated Bitwarden or Vaultwarden collection. kharond decrypts it on owner hardware after the owner unlocks, holding keys in mlocked RAM (repo) |
| What the agent sees | A status and which websites were granted. Never the value (obs) | Item metadata, a fill status and the kinds filled. Never the value (repo) |
| What is still exposed | The filled page sits in the agent's browser, and 1Password's "don't read the page during a fill" rule is a partner contract (doc) | Same N1 limit. During the fill the broker holds the CDP session, so the rule is enforced by structure, not by contract (repo) |
| How approval works | A card in Duet opens the request, and the user approves in the 1Password app, with a biometric prompt (obs, doc) | ntfy push with one-time approve and deny links, the owner web UI behind a passkey, or the CLI (repo) |
| What approval covers | Named websites, for the session that asked, for one hour (obs). 1Password's partner model allows standing grants; per-session approval is the integrator's choice (doc) | One item, one live origin, one agent, one action. Pending for 120 s, then denied. Grants are short-lived and scoped (repo) |
| Origin check | The executor fills by website, so the platform or the extension picks the tab (obs; how it is matched is not visible) | eTLD+1 or host binding against the frame's live origin, checked atomically; `expected_origin` is never trusted (repo) |
| Which browser | The Duet session's own cloud browser, through an executor the platform runs in it (obs; the extension placement is doc) | A Chromium that kharond reaches over CDP and that the agent drives too: one of the agent's own browser contexts, addressed by `cdp_target_id` (repo) |
| Transport | Executor and owner app both dial out to 1Password's cloud, which relays and can't read the payload (doc) | The agent host's connector dials out over WSS to `/connector`, with a pinned inner TLS that is never adopted. Broker CDP rides back down that tunnel. The agent calls MCP at `/mcp` with its own token (repo) |
| Setup per agent | None after the user connects 1Password once (obs) | A Chromium, the connector, `broker_pin` and a token file on each agent host, or a dashboard Connect that spawns the connector (repo) |
| Who integrates | 1Password and the agent platform, as partners (doc) | The operator, on hosts they control (repo) |

## Why the shape doesn't transfer, and the options

1Password works in every Duet thread because its executor sits inside the browser the platform already runs. kharon's executor is its broker's CDP session, and that needs a browser the broker can reach. A Duet cloud browser isn't one: custom connectors run on their own hosts, get only tool calls, and receive no tab id or debugging endpoint (obs from this thread's tools). `kharon_fill` needs a `cdp_target_id` in a browser context the broker opened, and Duet's browser tools don't expose CDP target ids to the model either (obs).

| Option | Who can fill | What it needs | Cost |
| --- | --- | --- | --- |
| **A. #327 as planned**: Proxmox VM running a Remote Control Claude Code session, Chromium with CDP on loopback, and the connector | Only the session on the VM. Cloud threads hand work to it | The VM, an always-on Remote Control session, and a working handoff from cloud threads (untested) | Works with kharon v0.3.0 unchanged. Fills are tied to one box |
| **B. kharon-hosted browser**: a Chromium pool beside the broker (the connector-host doc already picks plain Chromium containers and a small CDP allocator), with browse tools added to kharon's MCP | Any Duet thread, through a custom connector over HTTPS, the way GitHub Broker works | New MCP tools (open, navigate, snapshot, click, type non-secret text) and a host for the pool | No Claude Code VM. A new public tool surface. Duet's own browser features don't apply there (takeover, bot-check cards, cart pictures) (inferred) |
| **C. Platform provider slot**: Anthropic or Bitwarden adds a Bitwarden-backed provider next to 1Password | Any Duet thread, in its own browser | An open provider protocol. The press says 1Password's framework is meant for other platforms "as the market develops"; no public route is documented (doc) | Not in your hands. kharon's broker is close to a reference backend if the slot opens |
| **D. Pass the value to Duet's browser** | Any thread | Nothing new | Ruled out: it breaks G1, and Duet's own rules forbid the model handling a password |

Recommendation: keep A for the v0.3.0 soak, because it tests kharon as shipped. If the soak shows that handing work from cloud threads to the VM is the painful part, B is the next spec; it removes the VM and the handoff, not the host.

## Live test, 2026-11-14

No fill happened. 1Password approved both requests but granted no login, and it didn't say why. Up to that point, only statuses and request names crossed the tool boundary. No username or password reached the session.

The target was the Login Test Page on login.page.twkr.io, opened in this thread's cloud browser. The page reports field lengths, never values. The bare twkr.io domain didn't load (tunnel failure).

| Time (ET) | Call | Arguments | Result |
| --- | --- | --- | --- |
| 4:27 PM | `browser_credentials_request` | goal, one login: website login.page.twkr.io, reason, 5 keywords | `needs_user_message`: Lothrop's address message in the main chat, passed along by the main session, didn't count |
| 4:29 PM | same, after he typed "go ahead" in this task's conversation | same | `asked`, with a request name and a 10-minute expiry |
| 4:29 to 4:31 PM | same, polling by request name | request name | `waiting` three times, then `approved` with login.page.twkr.io under `not_granted` |
| 4:32 to 4:34 PM | second request, on his "Yes" | same login, reworded keywords | `waiting` three times, then the same `approved`, nothing granted |

What this shows and doesn't show:

- **Shown (obs):** the request leg carries no secret. Its results are statuses, site names and an expiry. The platform also gates the request on a message the user types in the asking task's own conversation; a relayed message doesn't count.
- **Not shown:** whether the fill leg keeps the value out of the session (`browser_credential_fill` was never called), and what the page looks like after a fill.
- **No change to the verdict:** nothing in this test touched the custom-connector question, so #327's VM is still needed for the soak.

### Rerun after the vault was shared (4:38 PM ET)

The password stayed out of the session, and Duet hid it a second time on top of that. 1Password granted the login and filled it, but couldn't confirm the submit. From then on, every page read that would have contained the password was withheld.

| Time (ET) | Call | Result |
| --- | --- | --- |
| 4:38 PM | `browser_credentials_request`, same login | `asked`; approved on the first poll, with login.page.twkr.io granted |
| 4:39 PM | `browser_credential_fill` (request name, website) | `manager_error` with `autosubmitFailed`. No value in the result |
| 4:39 PM | page snapshot | Whole result withheld: Duet's browser says it held "a password or another value that must stay hidden" |
| 4:39 PM | snapshot of the status line only | First it said the page had changed, then the result was withheld again |

- **The value reached the page and was redacted from the model (obs).** Before the fill, the same page read came back in full. After the fill, any read whose text held the filled value was withheld. That means the browser layer knew the exact value 1Password wrote and filtered it out of the model's tool results.
- **Why every read was withheld (obs):** the test page prints its own public test credentials. If the saved item uses the same password, that table matches the filled value, so the whole page read is hidden. I couldn't read the status line to see whether the login worked.
- **Submit unconfirmed:** the tools' rules say not to retry a fill after `autosubmitFailed`, so I didn't.
- **For kharon:** Duet's redaction belongs to its own browser tools. A kharon-hosted browser (option B) would have to scrub filled values from its own snapshot and screenshot tools. Today kharon doesn't need that, because the agent drives its own browser and kharon only fills.
- **To finish the test:** take the public credentials table off the page, or keep it out of the default view. Then a read after the fill shows the status line and the field lengths.

## Gaps and open questions

- **Enclave and transport claims weren't re-checked today.** The Nitro enclave, Noise session and standing-grant points come from kharon's own research notes (2026-11-06), which cite 1Password's partner security page. The two pages read today don't cover them.
- **Grant lifetime differs by source, but the sources fit together.** Duet's tools say one hour for the asking session, the press says one session, and 1Password's partner model allows standing grants. That's consistent if Duet chose per-session grants.
- **How the executor gets into Duet's browser isn't visible.** It could be an extension the platform installs or an injection by the browser worker (inferred either way).
- **Option A is untested.** Nobody has tried a cloud thread handing work to the VM's Remote Control session, and the agent id "duet" is unconfirmed.
- **Option B has open questions.** Would Duet's rules let a thread browse through a custom connector instead of its own browser? It would also need per-agent context isolation and rate limits on public browse tools, and bot checks against a homelab IP are a likely problem.
- **Bitwarden wasn't checked.** I didn't look for any agent-fill partner program from Bitwarden.

## Sources

- Duet thread tool descriptions for the two password-manager tools, read in this thread on 2026-11-14 (not a web page)
- [1Password Developer: Agentic Autofill](https://www.1password.dev/agentic-autofill.md)
- [IT Brief: 1Password launches Claude browser login for AI agents](https://itbrief.com.au/story/1password-launches-claude-browser-login-for-ai-agents)
- [1Password Developer: Agentic Autofill partner security model](https://www.1password.dev/agentic-autofill/partners/security), via kharon's notes, not opened today
- [kharon docs/1password-agent-model.md](https://github.com/CycleFive/kharon/blob/master/docs/1password-agent-model.md)
- [kharon SPEC.md](https://github.com/CycleFive/kharon/blob/master/SPEC.md)
- [kharon docs/agent-runtime-setup.md](https://github.com/CycleFive/kharon/blob/master/docs/agent-runtime-setup.md)
- [kharon docs/api/mcp-tools.json](https://github.com/CycleFive/kharon/blob/master/docs/api/mcp-tools.json)
- [kharon #327](https://github.com/CycleFive/kharon/issues/327), the issue and its three comments
