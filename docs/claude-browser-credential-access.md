# How 1Password got into Claude's browser, and what kharon would need

> Point-in-time research record from Claude Duet, Nov 14, 2026. Check claims against current code and the linked sources before relying on them.

Research for kharon, Nov 14, 2026. Read only: no vault reads, fills, sign-ins or posts. Facts are cited; anything marked **Inference** is my reading, not a source's.

## Verdict

1Password's fill is a first-party, co-built integration with Anthropic, not an open mechanism. Anthropic ships the request and fill tools inside its own clients (Claude Desktop, Claude in Chrome, Cowork, Claude Duet) and the admin switch that turns it on. 1Password supplies the approval flow and a private, Noise-based delivery protocol that pushes the secret from the user's 1Password app straight into a 1Password component in the browser. There is no public spec, no self-serve partner program, and no extension point a third-party MCP connector can use to put a secret into Claude's browser. A connector like kharon cannot reach Claude's cloud browser today. Only Anthropic can open that.

The one route that needs nobody's permission is Claude in Chrome on Lothrop's own machine: Claude drives his real Chrome, and anything installed in that Chrome can fill it. That is "a browser Claude controls" without kharon hosting one. It has a real leak risk, covered below.

## 1. What special access 1Password got

- **Named Anthropic partner since March 2026.** 1Password's Unified Access launch lists Anthropic among its AI partners and says Anthropic "will integrate 1Password to securely autofill vault items through the Claude browser extension, Cowork, and Claude Code." Other named partners: OpenAI, Cursor, GitHub, Vercel, Browserbase, Anchor Browser, KERNEL, Perplexity Comet, and others. ([1Password press, Mar 17, 2026](https://1password.com/press/2026/mar/1password-unified-access))
- **Joint launch July 16, 2026.** The release is titled "1Password and Anthropic Bring Secure Credential Access to Claude" and calls it "powered by Anthropic"; 1Password's CTO speaks of "the foundation we're building with Anthropic." It says the framework "is designed to extend to any browser-based agent or platform," which is about more agents using 1Password, not more password managers using Claude. ([Business Wire via Yahoo Finance](https://finance.yahoo.com/technology/ai/articles/1password-anthropic-bring-secure-credential-130000549.html); [1Password blog](https://1password.com/blog/1password-for-claude); [MacRumors](https://www.macrumors.com/2026/07/16/1password-claude-integration/))
- **Anthropic lists it as a pre-built connector, in beta for paid plans.** ([Claude Help Center](https://support.claude.com/en/articles/15936181-get-started-with-1password-for-claude))
- **Anthropic built an admin control just for it.** The Claude in Chrome admin page has a section "Control password manager access" that names only 1Password; it's off by default for Team and Enterprise. Nothing there names or implies any other manager. ([Claude in Chrome admin controls](https://support.claude.com/en/articles/13065128-claude-in-chrome-admin-controls))
- **A Duet-specific setup page exists.** In Claude Duet you connect 1Password under Settings > Credentials (web) or Settings > Connections (mobile). The 1Password prompt shows the request "is from Claude Duet"; approvals expire after 30 days; only Login items in Personal or Private vaults; no shared vaults, passkeys or business accounts. ([1Password support: Claude Duet](https://support.1password.com/1password-claude-duet/))

**Inference:** "Special access" is three things: Anthropic wrote the client-side tools (the two app-built-in tools we saw in Duet), Anthropic runs or permits a 1Password receiver inside its browsers, and Anthropic added the browser-side redaction we hit in the live test. None of that is exposed to other connectors.

## 2. How the fill actually works

- **Protocol.** For Browserbase (Oct 2025), 1Password "developed a new protocol to securely request and deliver credentials directly into the browser context," built on the Noise Framework, an "end-to-end encrypted channel between the approving 1Password device and remote instance of 1Password's extension in the browser." The agent and model "never need to see nor handle the credentials." ([1Password blog, Oct 8, 2025](https://1password.com/blog/closing-the-credential-risk-gap-for-browser-use-ai-agents))
- **Partner-only.** 1Password's developer docs describe the Browserbase integration as "For partners: let agents running in Browserbase sign in to websites." No public spec or SDK for the delivery protocol; the public SDKs are for agents that read secrets themselves. ([1password.dev agentic autofill](https://www.1password.dev/agentic-autofill.md))
- **Desktop and Chrome.** On Mac, the 1Password browser extension in the user's own Chrome fills the login; when Claude takes control of the browser, the extension enters an "Agentic Mode" that locks down to approved items. Requires 1Password 8.12.28+, Claude Desktop and Claude in Chrome, Mac only. ([1Password support: Claude](https://support.1password.com/1password-claude/))
- **Duet cloud browser.** Our own live test (thread "1Password vs kharon design") showed the fill landing in the thread's cloud browser, with only statuses returned and page reads containing the filled value withheld. **Inference:** Anthropic's cloud browser carries the Browserbase pattern: a 1Password extension instance (or equivalent receiver) inside Anthropic's browser, fed over 1Password's Noise channel, plus Anthropic-side redaction of reads that would expose the value. No public page describes Duet's browser internals.

## 3. Is there any open way in for a third party?

No documented one. What I checked:

- **Custom MCP connectors.** They run outside the browser and return data to the model. Nothing lets a connector address a tab in Claude's cloud browser or deliver a value the model can't see. (From our earlier comparison plus the absence of any such API in the pages above.)
- **Claude in Chrome admin controls.** One password-manager toggle, 1Password only.
- **Duet Settings > Credentials.** Documented for 1Password only. **Inference:** the name suggests a provider slot that could hold others later, but nothing says so.
- **MCP elicitation / MCP Apps.** These ask the user for input or render UI; they don't write into the agent's browser. Not a fill path.
- **WebMCP.** A browser-native way for sites to expose tools to agents. Bitwarden's own write-up treats it as an exposure risk and recommends keeping credentials out of model context, not as a fill channel. ([Bitwarden: Browser WebMCP](https://bitwarden.com/resources/browser-webmcp-security/))
- **User demand.** There's a public feature request asking for Bitwarden extension support in Claude's desktop browser pane (issue 100140, seen in search results; the mirror site refused automated reads, so I couldn't confirm details or any response).

## 4. Bitwarden's position

- **Agent Access SDK** (Mar 24, 2026): "a new open protocol and standalone development toolkit" for agents to talk to password managers. Apache-2.0, Rust with Python and WASM bindings, Noise-encrypted tunnel with pairing tokens (`aac listen` / `aac connect`), early preview with unstable APIs. Today it injects secrets as environment variables into a child process, so it's a CLI/workload path, not a browser fill. "A native integration with Browserbase is also in development" and a browser extension is "coming soon." No mention of Anthropic or Claude. ([Bitwarden blog](https://bitwarden.com/blog/introducing-agent-access-sdk/); [bitwarden/agent-access](https://github.com/bitwarden/agent-access))
- **Bitwarden MCP server**: local, wraps the CLI, returns passwords and TOTP to the model; Bitwarden recommends a local LLM with it. ([Bitwarden blog](https://bitwarden.com/blog/bitwarden-mcp-server/))
- **warden-mcp** (community, MIT): Vaultwarden-tested MCP server, redacts by default but returns values with `reveal: true`; no browser fill. ([icoretech/warden-mcp](https://github.com/icoretech/warden-mcp))

**Inference:** Bitwarden is building the same shape as 1Password (Noise tunnel, approval, Browserbase as first browser host) but in the open. If it ships a browser-side receiver, that's the most likely open standard to emerge, and the one closest to kharon's Vaultwarden target.

## 5. What kharon would need

### Route A: Claude's cloud browser (Duet threads)

Needs Anthropic. Concretely:

1. A credential-provider slot in Claude's browser, the way Settings > Credentials holds 1Password.
2. A receiver inside Anthropic's browser that accepts kharon's encrypted delivery (kharon's own extension, or a standard such as Bitwarden's protocol if Anthropic adopts it).
3. App-side request/fill tools for that provider, and the same read redaction 1Password gets.

Who grants it: only Anthropic. Realistic paths are a feature request (the card already drafted for Lothrop covers part of this), or Anthropic adopting Bitwarden's open protocol, after which kharon could speak it against Vaultwarden. Neither is in our hands.

### Route B: Claude in Chrome on Lothrop's own Chrome (no hosted browser)

Needs nobody's permission. Concretely:

1. A small kharon browser extension in Lothrop's Chrome that holds a pairing with kharond (native messaging or a local websocket).
2. kharon's MCP connector gets a tool like `request_fill(host)`; kharond asks for approval on his phone (the existing ntfy path), then tells the extension to fill the matching login form on the tab Claude in Chrome is driving. Only a status returns to the model.
3. Target selection by host plus the active tab in Claude's tab group. **Inference:** the extension can't see Claude in Chrome's internal tab ids, so matching would be by URL and focus.

Cost and risk:

- Works only while his machine and Chrome are on, and Duet threads use his Chrome only when it shows as connected.
- **Leak risk:** Claude in Chrome can read page DOM and run page JavaScript, so it could read a filled password field. 1Password handles this with an extension "Agentic Mode" lockdown and Anthropic-side redaction; kharon would get neither. A mitigation is fill-and-submit in one step with the field cleared right after, but that is weaker than 1Password's guarantee. (Inference.)

### Route C: #327 as planned

kharon's own Chromium on the Duet VM. Lothrop has ruled this out for now.

## Recommendation

Route B is the only one that meets "fill a browser Claude controls" without hosting a browser, and it can be prototyped against his test page. It is weaker on secrecy than 1Password because nothing stops Claude reading the field back. For the cloud browser, file the request with Anthropic and watch Bitwarden's Agent Access browser extension; if Anthropic ever opens a provider slot, an open Noise-based protocol is the likely shape and kharon's design already matches it.

## Not checked

- Bitwarden's protocol-v0.md (approval details).
- 1Password's partnerships page.
- The GitHub originals of the two Claude issues (mirror refused automated reads).
