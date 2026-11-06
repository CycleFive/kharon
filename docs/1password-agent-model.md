# How 1Password serves agents — research notes

Input to the agent-initiated transport revision (issue #121, owner
decision C, 2026-11-06). Lothrop asked how 1Password — the system
kharon is modeled on ("add it as a connector… the way I can for
1Password") — actually works for agents. Researched 2026-11-06 from
1Password's developer documentation and press material; sources at
the end. Claims are 1Password's own unless marked reported.

## Three surfaces — only one is kharon's shape

1Password has three distinct agent/automation offerings. Two of them
are **not** the kharon model:

- **Connect Server** — a self-hosted pair of containers
  (`connect-sync`, `connect-api`). The sync container keeps an
  encrypted local cache in step with 1Password cloud; clients call
  the REST API with a scoped JWT access token (per-vault READ/WRITE,
  30/90/180-day expiry). It **returns plaintext secrets to the
  caller**. The trust model is "the calling code is trusted
  infrastructure."
- **Service accounts** — a machine identity whose single token
  (`ops_…`) carries the material to authenticate *and decrypt* its
  assigned vaults, used by the `op` CLI / SDKs against 1Password
  cloud. Also plaintext-to-holder, vault-scoped and revocable.

Both are **client-initiated HTTPS** throughout — but they distribute
secrets to trusted code. kharon's premise (the agent must never hold
plaintext) rules them out as the model. They remain relevant as
plumbing references only.

## Agentic Autofill — the true analog

Launched for cloud-browser agents as *Secure Agentic Autofill*
(Browserbase early access, Oct 2025) and generalized as *1Password
for Agents* (Oct 2026; reported launch integrations include Meta
Muse and Grok Bot). Per 1Password's developer security model:

- **The fill executor lives in the agent's browser.** A 1Password
  extension inside the agent's browser performs the fill
  (`fillCredential`). Nothing at 1Password dials into the agent's
  network: the extension and the owner's apps reach *out* to
  1Password's cloud, which acts as rendezvous/relay — and the
  relaying services cannot read what they carry.
- **Approval is a cryptographic grant, not a UI courtesy.** Only the
  owner's app holds the vault key, and creating a grant requires it:
  "nothing you hold can create a grant — not your tokens, not your
  integration key, not a reference." The integration's OAuth token
  can only create access requests, check their status, and fetch
  logins already granted. It cannot list the owner's items or
  approve requests.
- **Decryption happens in an attested enclave, at fill time.** The
  extension verifies an AWS Nitro Enclaves attestation for
  1Password's credential broker (including that the enclave runs
  released code), opens a session using the Noise Protocol
  Framework, and the enclave decrypts exactly the one granted login
  into that session.
- **Plaintext lifetime is minimal.** The value exists in the enclave
  and in the page between fill and submit; the extension removes it
  before `fillCredential` returns, including on failure.
- **The weakest joint is contractual.** The agent must not read the
  page, take screenshots, or send CDP commands to the tab during a
  fill — enforced as a *partner requirement*, not by construction.
  1Password also requires partners to phrase claims precisely:
  "your platform and the model don't handle the values," **not**
  "credentials can never reach the agent's environment" — the filled
  page *is* in the agent's environment.

## Where kharon is already stricter

- **Grant lifetime.** 1Password grants are *standing*: approval
  limits *which* logins an integration can use, not how often; a
  granted login is usable without the owner present until the grant
  ends. (Per-session approval is the integrator's own choice.)
  kharon's fill grants are scoped, short-lived, and one-shot.
- **Per-agent isolation.** All of a person's agents share one OAuth
  token and one integration key; 1Password explicitly makes
  per-agent isolation the integrator's problem. kharon issues
  per-agent tokens.
- **No-observe during fill.** 1Password relies on partner
  discipline. kharon's broker-driven CDP fill makes the rule
  structural: during a fill the broker holds the CDP session and
  the agent holds nothing that can read the page (modulo the N1
  limit in SPEC §2.4, which both designs share).

## Design inputs for the agent-connector revision (#121)

1. **Rendezvous shape.** Every 1Password surface is client-initiated
   against a rendezvous both sides dial out to. For kharon the
   broker host is the rendezvous — no cloud component needed. This
   validates option C's `cdp.via = "agent_connector"` direction.
2. **Keep broker-driven CDP.** 1Password places the executor in the
   browser because a remote cloud cannot safely drive CDP. kharon's
   broker can — over the agent's outbound channel — which converts
   1Password's contractual no-observe rule into a structural one.
   The spec should claim this explicitly.
3. **Token discipline** (1Password's integration requirements,
   directly applicable to agent tokens and tunnel credentials):
   session-scoped, in memory only, dropped when the task ends;
   never on the agent VM's filesystem, never in logs, never exposed
   to the model. Out-of-band delivery of the agent token matches
   this rule.
4. **Approval-payload hygiene.** 1Password's approval links carry
   readable request text (base64url JSON): don't log them, keep
   personal data out of request text. The same caution applies to
   kharon's ntfy approval path (REQ-APR-004).
5. **Honest claims.** Follow 1Password's phrasing rule in docs and
   COMPAT: "the agent and the model never handle the values" —
   never "credentials never reach the agent host."

## Sources

- 1Password Developer, *Agentic Autofill security model* —
  https://www.1password.dev/agentic-autofill/partners/security
- 1Password Developer, *Connect concepts* —
  https://www.1password.dev/connect/concepts
- 1Password press release, *1Password and Browserbase Partner to
  Secure AI Browser Automation* (2025-10-08) —
  http://1password.com/press/2025/oct/browserbase-ai-security-partnership
- Launch facts for 1Password for Agents (2026-10-22) as reported by
  TechCrunch-covered announcement summaries; treat partner/rollout
  status as reported, not verified.
