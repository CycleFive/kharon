# N3: connect kharon from the dashboard (MCP OAuth)

Status: design, 2026-11-10, for #213 (the "N3" item of #197). Builder: Duet.

Owner decisions:
- Lothrop's calls of 2026-11-09, recorded on #197 and #206, plus the target-user note on #213.
- Nyx's ruling of 2026-11-10 07:12Z in `#general`. It closed the question rounds and settled Q2–Q5 and Q7 from the managed single-tenant model.

Anything those don't cover is a **stated assumption** (A1…), collected at the end, for the reviewers to accept or overturn.

Reviewers: Muse and Nyx (lead), then Lothrop, per #213 "Done when".

## Why

Today a customer connects an agent to kharon by pasting a bearer token, `kh_agent_<id>_…`, minted out of band with `kharon token mint` and written into `kharon.toml`.

The target user (Lothrop, on #213):
- is "at least a little tech savvy but maybe not Linux command line savvy";
- already uses Bitwarden;
- wants their agents to log in to their accounts with those credentials.

That user will never run `kharon token mint`, and should never handle a long-lived secret at all.

They should click **Connect** on the Muse or Grok dashboard, sign in to their own kharon deploy with their passkey, say yes to a plain-words consent screen, and land back on the dashboard connected. After that, every fill is approved or denied in the published owner UI, exactly as now.

That button is the MCP authorization flow: OAuth 2.1 with PKCE, in the MCP 2026-07-28 revision. The deployment model is the managed single-tenant one from the #197 amendment: one deploy per customer, run by us. The customer hosts nothing, and the vault is their own Bitwarden account.

## Goals

1. **A standard Connect button.** Any MCP client that implements the 2026-07-28 authorization spec can Connect, provided it is on the deploy's allow-list. No kharon-specific client code is needed.
2. **The owner's passkey is the only login.** No third-party IdP sits in the trust path.
3. **A token can request but never approve.** No token kharon issues can approve a grant, a fill, an unlock or a Connect.
4. **One revocable identity per Connect.** Each Connect gets its own identity, with its own rate limits, grants and audit trail, listed in the owner UI and disconnected with one click.
5. **Short-lived credentials.** No credential the dashboard holds lives long unattended: access tokens expire, refresh tokens rotate, and a stolen refresh token used twice kills the connection.
6. **Single-tenant now, multi-tenant later,** with nothing in this design that multi-tenant would have to undo.

## Non-goals

- Dynamic Client Registration (RFC 7591). The 2026-07-28 spec deprecates it, and an allow-list makes it unnecessary.
- An external IdP or federated login: Cloudflare Access, OIDC, social login.
- Browser-based MCP clients calling `/mcp` directly. `/mcp` keeps refusing any `Origin` header (REQ-API-003, `BrowserOriginRefused`). Dashboards call it server to server.
- Self-serve sign-up and multi-tenant hosting. Those come later, and this design only keeps the door open.
- Replacing `kharon token mint`. Pasted tokens stay for self-hosters and tests.

## Anti-goals

These would make the work a failure even if it technically works.

- **A Connect that approves something.** Consent creates a connection; it never pre-approves fills, items, origins or standing grants. Every fill still lands in the owner UI as `pending_approval`.
- **A customer-facing CLI step** anywhere in the Connect or enrolment flow.
- **Credentials at rest in plaintext.** Tokens, codes and refresh tokens must not appear in logs, audit entries or state files.
- **A path where kharond fetches arbitrary URLs** on an unauthenticated request. Client Identity Metadata Document (CIMD) fetches are the classic server-side request forgery (SSRF) here, and are confined to the allow-list.

## Decisions

### D1. Roles: kharond is both the authorization server and the resource server, on two hostnames

Lothrop's Q2 answer, and Nyx's ruling: "each deploy is its own authorization server with passkey sign-in".

| Role | Hostname (managed deploy) | Listener | Serves |
|---|---|---|---|
| Resource server (RS) | `kharon.twkr.io` (the agent hostname) | `[public_ingress]` | `POST /mcp`, `GET /connector`, **new:** `GET /.well-known/oauth-protected-resource/mcp` (RFC 9728) |
| Authorization server (AS) | `kharon-owner.twkr.io` (the owner hostname, N2 #208) | `[owner_ui]` | **new:** `GET /.well-known/oauth-authorization-server` (RFC 8414), `GET /oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke` (RFC 7009) |

Why the AS sits on the owner hostname:
- The consent must run under the owner's passkey session.
- The passkey's RP ID is the owner hostname, and a passkey binds to one RP ID (the gateway design's Decision 7).
- The 2026-07-28 spec lets the RS name a separate AS: "It may be hosted with the resource server or a separate entity".

So the RS's metadata points at the owner hostname, and nothing about passkeys moves.

**The issuer** is `https://kharon-owner.twkr.io`, the owner origin with no path. That makes it "one issuer per deploy hostname" (Nyx). The AS metadata is served at the exact well-known URL the spec derives from that issuer.

**Protected-resource metadata** (on the agent hostname) contains:

```json
{
  "resource": "https://kharon.twkr.io/mcp",
  "authorization_servers": ["https://kharon-owner.twkr.io"],
  "scopes_supported": ["kharon:read", "kharon:fill", "kharon:request"],
  "bearer_methods_supported": ["header"],
  "resource_name": "kharon"
}
```

It is served both at the path-inserted URL `/.well-known/oauth-protected-resource/mcp` and at the root `/.well-known/oauth-protected-resource`, because clients try both.

**The 401 on `/mcp`** gains the spec's discovery parameters. Today it sends only `realm`; when `[oauth]` is configured it becomes:

```
WWW-Authenticate: Bearer realm="kharon", resource_metadata="https://kharon.twkr.io/.well-known/oauth-protected-resource/mcp", scope="kharon:read kharon:fill kharon:request"
```

A token that lacks a needed scope gets 403 with `error="insufficient_scope"` and the full `scope` the call needs, in a single challenge, as the spec asks.

**AS metadata** contains:
- `issuer`, `authorization_endpoint`, `token_endpoint`, `revocation_endpoint`;
- `response_types_supported: ["code"]`;
- `grant_types_supported: ["authorization_code", "refresh_token"]`;
- `code_challenge_methods_supported: ["S256"]` (clients MUST refuse an AS without this field);
- `token_endpoint_auth_methods_supported: ["none"]`;
- `client_id_metadata_document_supported: true`;
- `authorization_response_iss_parameter_supported: true`;
- `scopes_supported`.

It has **no** `registration_endpoint`, because Dynamic Client Registration is off.

### D2. Clients: CIMD URLs on an operator allow-list, plus consent every time

From Q3 and Nyx's ruling.

**How a client identifies itself.** A client's `client_id` is the HTTPS URL of its Client ID Metadata Document (CIMD), the 2026-07-28 spec's preferred registration. The deploy's `kharon.toml` lists the client ids it accepts:

```toml
[oauth]
# The owner hostname is the issuer; [owner_ui] origin must equal it.
clients = [
  "https://dashboard.muse.example/.well-known/kharon-client.json",
  "https://grok.example/mcp/client-metadata.json",
]
```

Any other `client_id` is refused on the authorize page, with a plain message. kharond never redirects in that case, so this is not an open redirect.

**Fetching the CIMD.** On an authorize request from an allow-listed client, kharond fetches the CIMD.

Fetch rules:
- HTTPS only, verified against the system's native roots.
- No redirects followed.
- A 5 s timeout and a 16 KiB body cap.
- The resolved address must not be loopback, private, link-local or the deploy's own. This is defence in depth: only allow-listed URLs are ever fetched, which is what closes SSRF.
- The response is cached for its `Cache-Control` max-age, clamped to 1 h–24 h.
- The cache is per process and never persisted, so a restart re-fetches.

Validation rules:
- `client_id` in the document must equal the URL exactly.
- `client_name` must be present (it is shown on the consent screen).
- `redirect_uris` must be non-empty, and every one must be `https`. `localhost` redirect URIs are refused: dashboards are web services (A3).
- `token_endpoint_auth_method` must be absent or `none`. Clients are public; PKCE binds the code (A4).

**The redirect URI** in the authorize request must string-equal one of the document's `redirect_uris`.

**Why an allow-list as well as consent.** Q3 offered "any client with a valid metadata document, gated only by owner consent". Nyx's ruling took the allow-list plus consent. For a non-CLI user, a consent screen naming an unknown site is a phishing surface. The allow-list means the only screens they ever see are for dashboards we vetted.

**Pre-registration.** The spec's "pre-registered client" path is just an allow-list entry. There is no separate mechanism.

### D3. What a Connect creates: a stored agent identity, not a `kharon.toml` entry

From Q4 and Nyx's ruling.

**The identity.** Each completed consent creates one agent identity, with id `c-<10 lowercase base32>`. It matches the existing `[a-z0-9-]{1,64}`, so the audit and rate-limit code is unchanged. It carries:
- the `client_id` and the `client_name` as shown at consent;
- the granted scopes;
- `created_at`, and `connected_via = "oauth"`;
- `cdp`: none at first (D7).

Connecting the same dashboard again creates another identity; nothing is merged (A5). The owner UI's new **Connections** page lists the identities, each with a **Disconnect** button.

**Persistence.** Identities and token records persist in a new owner-only state file, `data_dir/oauth/state.json` (mode 0600, written atomically with write-then-rename, like `owner/passkeys.json`).

The state file holds:
- the identities;
- for each live token, its SHA-256 hash, kind (access or refresh), expiry, refresh family id and parent;
- the revoked flag.

It holds no plaintext token and no code. Tokens are 256-bit random values (`kh_at_…`, `kh_rt_…`), so a hash at rest reveals nothing usable. SHA-256, not Argon2id, is right for high-entropy random tokens, and it keeps the per-request check cheap.

**This departs from #132's accepted "no new store, rebuild from audit".**
- That position is about agents that exist in `kharon.toml`: their revoke state can be recomputed from the config hash plus the audit log.
- A Connect identity exists *only* at runtime. A refresh token's current generation can't be rebuilt from an append-only log without putting token hashes in the audit chain, which goes off-host in checkpoints.
- So OAuth state gets its own small file. Config agents keep #132's scheme.

### D4. Tokens: opaque, 1 h access, rotating refresh

From Q5 and Nyx's ruling.

**Access tokens.**
- An access token is `kh_at_<64 hex>`: opaque, looked up by hash, and live for **1 h**.
- It is bound to its identity, its scopes and its audience, the RFC 8707 `resource` from the token request.
- The audience must be exactly `https://kharon.twkr.io/mcp`. Anything else, `/connector` included, is refused at the token endpoint until phase 2 (D7) is designed.
- On `/mcp`, a token whose audience isn't `/mcp` gets 401, and there is no passthrough to anything.

**Refresh tokens.**
- A refresh token is `kh_rt_<64 hex>` and rotates on every use: each refresh returns a new pair and retires the old refresh token. The spec requires rotation for public clients.
- Its lifetime is a **30-day** idle limit inside a **90-day** absolute limit, counted from consent (A6). After 90 days the customer clicks Connect again.
- **Reuse detection.** Presenting a retired refresh token revokes the whole Connect: every token of that identity, and the identity itself. It writes `oauth_refresh_reuse` and needs a new Connect. This follows the OAuth 2.1 / Security BCP pattern for public clients.

**Authorization codes.**
- 32 random bytes, single use, valid for 60 s.
- Bound to the `client_id`, `redirect_uri`, `code_challenge` (S256 only), `resource`, scopes and the identity being created.
- A second redemption revokes everything issued from the first.

**Revocation.**
- **Disconnect** in the owner UI, `kharon revoke agent <c-id>` on the owner socket, or a client's call to `POST /oauth/revoke` with its refresh token, revokes the identity's tokens at once. Disconnect and the socket revoke also revoke the identity's live grants, as REQ-REV-001 does for "token + grants".
- It takes effect on the next request (REQ-REV-001) and is durable, because the state file records it.
- Panic (REQ-REV-002) revokes every Connect identity as well as locking.

**Where Argon2id stays.** `kh_agent_` tokens keep it; nothing changes for config agents.

**Dispatch.** The `/mcp` auth path dispatches on prefix: `kh_agent_` goes to the existing `TokenStore`, `kh_at_` to the OAuth store. Both produce the same `AgentId`, now carrying a scope set (D5).

**Dependency on #132.** Nyx's ruling ties token lifetimes to #132. Connect identities get durable revocation from D3 on their own. #132 should still land first, so that "Disconnected" in the Connections page and "Revoked" for a config agent mean the same thing everywhere. That is a sequencing dependency, not a technical one.

### D5. Scopes map onto #200's per-agent tool allow-list

#200 (open, Muse) gives each agent identity a tool allow-list. N3's scopes are named bundles of those tools:

| Scope | Tools | Consent wording (plain) |
|---|---|---|
| `kharon:read` | `kharon_status`, `kharon_list`, `kharon_search` | "See the names and websites of the logins you share with kharon. Never the passwords." |
| `kharon:fill` | `kharon_context`, `kharon_fill`, `kharon_fill_totp` | "Ask to sign in to a website for you. You approve every sign-in here first." |
| `kharon:request` | `kharon_request_grant` | "Ask you ahead of time for permission to sign in to a site." |

Rules:
- A Connect asks for all three by default, which is the spec's "all of `scopes_supported`".
- The owner can untick `kharon:fill` or `kharon:request` on the consent screen. `kharon:read` is always granted, because without it nothing else works.
- **No scope approves anything, and none ever will.** That is the structural guarantee behind "a token can request but never approve":
  - approval lives only on owner surfaces (passkey UI, ntfy, owner socket; REQ-APR-001/-004/-005/-006);
  - none of those surfaces accepts a bearer token;
  - the AS never mints a token for the owner hostname's own APIs.
- An `AgentId` built from an OAuth token carries its scope set. Dispatch checks it with the same allow-list check #200 adds for config agents. A missing scope gets 403 `insufficient_scope`, as in D1.

### D6. Consent requires a fresh passkey assertion on the owner hostname

The flow, after the dashboard's MCP client has discovered the AS through D1:

1. The browser opens `GET https://kharon-owner.twkr.io/oauth/authorize?response_type=code&client_id=<CIMD URL>&redirect_uri=…&code_challenge=…&code_challenge_method=S256&state=…&resource=https://kharon.twkr.io/mcp&scope=…`
2. kharond checks the request in this order:
   1. `client_id` is on the allow-list.
   2. The CIMD fetches and validates.
   3. `redirect_uri` exactly matches.
   4. `code_challenge_method` is `S256`.
   5. `resource` is this deploy's `/mcp`.

   Any failure up to and including the redirect check renders an error page and **never redirects**. After it, errors go back to the redirect URI with `error`, `state` and `iss`.
3. **Sign-in.** With no live owner session, the page runs the existing passkey sign-in (REQ-APR-005, #208), then returns to the consent screen.
4. **The consent screen** is plain words, in the language of #213's target user. It shows:
   - the dashboard's `client_name`, and its CIMD hostname in full, because the spec says to display the redirect hostname;
   - the redirect hostname;
   - the scopes, as the table in D5 words them, with the optional ones as checkboxes;
   - a fixed line: **"Connecting does not let it sign in anywhere on its own. Every sign-in still needs your approval on this page."**
5. **Approve.** The Approve button runs a fresh passkey assertion (user verification required), even inside a live session.
   - A Connect creates a credential that outlives the 15-minute session, so it gets the same weight as an unlock.
   - The POST carries the ceremony result and a one-time consent nonce bound to the authorize request.
   - It needs `Origin` equal to the owner origin and the `SameSite=Strict` session cookie, as every owner POST does today.
6. On success, kharond creates the identity (D3), writes `oauth_connect`, issues the code, and redirects `302` to `redirect_uri?code=…&state=…&iss=https://kharon-owner.twkr.io`.
7. **Deny** redirects with `error=access_denied`, `state` and `iss`, and creates nothing.
8. **Token exchange.** The dashboard backend sends `POST /oauth/token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` and `resource`.
   - This endpoint is on **#208's named exemption list**. Like the ntfy redeem routes, it can pass neither the owner `Origin` rule nor a Cloudflare Access login.
   - It answers JSON, `Cache-Control: no-store`, with this body:

     ```json
     {
       "access_token": "kh_at_…",
       "token_type": "Bearer",
       "expires_in": 3600,
       "refresh_token": "kh_rt_…",
       "scope": "…"
     }
     ```

**Headers and limits.**
- The authorize and consent pages send `Content-Security-Policy: frame-ancestors 'none'` and `X-Frame-Options: DENY`.
- `/oauth/token` and `/oauth/revoke` are rate-limited per trusted source, using #200's `CF-Connecting-IP` helper. Per that helper's rule, it keys the throttle and the audit entry but never gates auth. Each source gets its own bucket and there is no global bucket, so one source's flood can't lock out a legitimate Connect, following #208 AC4/5.

### D7. Fills for dashboard agents: MCP and grants first, the browser path second

From Q1 and the target-user note: the dashboard's own runtime holds the browser, so the customer runs nothing.

**Phase 1** ships with N3.
- A Connect identity has `cdp = none`.
- `kharon_status`, `kharon_list`, `kharon_search` and `kharon_request_grant` work.
- `kharon_context`, `kharon_fill` and `kharon_fill_totp` answer a typed error, `no_browser`, with the plain message "this connection has no browser attached yet".
- They never fall back to any configured CDP endpoint.

**Phase 2** is the browser through the connector, sketched here and to be designed in its own follow-up issue.
- The dashboard runtime runs `kharon-agent-connector` (#199) for the Connect identity.
- It authenticates with an access token of the **same Connect**, issued for `resource = https://kharon.twkr.io/connector` (scope `kharon:connector`).
- The token travels in the existing wire-v1 hello's token field (A7).
- kharond checks the token's audience and that the hello's agent id equals the token's identity. It then attaches the session exactly as today, with the pinned inner TLS unchanged.
- The connector refreshes through `/oauth/token` and re-attaches as the hourly token expires.
- With that session attached, the identity's `cdp` is the hub, and fills work.

Open in phase 2: how the dashboard runtime is told the inner pin. That will likely be a field in the token response, or the protected-resource metadata, for the `/connector` resource. Phase 2 is not part of this design's approval.

### D8. Single-tenant now, multi-tenant later

**Today:** one deploy, one issuer (its owner hostname), one state file, one allow-list. Nothing is shared between deploys. The client allow-list is per deploy and set by us as operator.

**Multi-tenant later:** each tenant gets its own owner hostname, and so its own issuer, state, keys and allow-list. That is Q7's recommendation, which Nyx ruled. Nothing in D1–D7 assumes one tenant per process, except the file path, which becomes per tenant.

The one-RP-ID-per-passkey rule (gateway Decision 7) keeps working, because each tenant's passkey binds to its own owner hostname. Self-serve sign-up replaces the operator-issued first-passkey link (Q8, A8). Its design belongs to multi-tenant.

### D9. The operator's owner socket keeps its powers, and is made visible

#197 left this to N3: "Whether the operator's CLI keeps owner powers on a managed deploy".

**Decision for N3 (A9):** on a managed deploy, the owner socket keeps its powers. We are the operator, and it is the break-glass path, including re-enrolling a lost passkey.

What N3 adds is visibility:
- Every socket action that touches a Connect (approve, deny, disconnect) is audited on channel `cli`.
- The Connections page and the audit view show the channel. A customer can therefore see any approval that didn't come from their passkey.

A "customer-only approvals" mode, where the socket can only lock, panic or re-enrol, is a follow-up issue, not part of N3.

## Implementation decisions

A builder read this design cold, and asked these questions. Each answer is the design's call (A13 onwards in the assumptions).

**I1. The consent ceremony and how the authorize request survives sign-in.**
- `/oauth/authorize` validates the request (D6 step 2), stores it server-side as a **pending authorization**, and redirects to `/oauth/consent/<id>`. `<id>` is 128 random bits.
- The record holds the parsed request: client, redirect, challenge, state, resource and scopes. It lives for 10 minutes and is single use.
- These records sit in the bounded, non-evictable ceremony table from #208 AC5, capped per source. Nothing about the request rides in a cookie or survives a restart.
- The consent page follows the existing owner UI's pattern: the shell page plus inline JS calling JSON endpoints. WebAuthn needs JS anyway.
- The fresh assertion is a new ceremony kind, `consent`. Its WebAuthn challenge is `SHA-256(pending-id ‖ consent-nonce ‖ 32 random bytes)`, so the assertion commits to that one authorize request.
- The consent POST returns `{"redirect": "<url>"}`, and the page navigates there. kharond never puts a code in a `Location` header that the browser follows on its own.

**I2. Rate limits, suspension and restart.**
- A Connect identity gets the deploy's `[policy]` defaults, keyed on its `c-…` id, exactly like a config agent. Per-client limits are not in N3.
- REQ-RL-002 suspension applies. The owner resets it from the Connections page, or with the socket's existing `unsuspend`.
- At start, kharond loads `oauth/state.json` before any listener opens. If it can't parse the file while `[oauth]` is set, kharond refuses to start, so a bad state file fails closed.
- A revoked identity's tokens are gone from the store, so it can't authenticate after a restart.
- The socket's `revoke_agent` accepts `c-…` ids, and means Disconnect.

**I3. #200, the `/v1` surface, and how scopes are carried.**
- The N3 implementation lands **after #200**, against its real tool allow-list, with no stub.
- The check is by MCP tool name, mapped to the broker request it dispatches.
- **`kh_at_` tokens are accepted only on `POST /mcp`.** They are refused on every `/v1/*` route, because that REST surface is for config agents and self-hosters, and a managed deploy has no `[api]` anyway.
- `AgentId` gains a scope set: none for config agents, meaning all tools until #200 says otherwise. The builder threads it through dispatch.
- `no_browser` is a new `Detail` variant (REQ-API-006 enum), under the existing `ErrorCode::Forbidden` (403): this connection may not fill yet. The SPEC PR adds it.
- A `c-…` identity has no CDP endpoint, so resolution stops there and never falls back.

**I4. The CIMD fetch: client, pinning, failure.**
- The fetch reuses kharond's existing outbound HTTPS stack, the one the Bitwarden sync uses: `reqwest` on rustls, with the system's native roots (`sync/client.rs`). No new HTTP client dependency is added.
- kharond resolves the host once, refuses the address classes in D2, then connects to that IP with SNI and `Host` from the URL. That makes DNS rebinding moot.
- A cache miss fetches inside the authorize request, under the per-source throttle.
- A failed fetch with no cached copy fails closed, with a plain page: "We couldn't check this dashboard. Try again in a minute." Stale copies aren't used.
- Egress is already open on a managed deploy, for Bitwarden and for cloudflared.

**I5. Ordering against REQ-AUD-003, and the refresh race.**
- **Connect:** append `oauth_connect` first, then persist the identity and the code, then answer. If the audit append fails, consent fails closed with an error.
- **Disconnect, panic and refresh reuse:** revoke first, in memory and in the state file, then audit. This is the revoke-first precedent of #135.
- **Token issue:** a failed state-file write fails the request (500, no tokens). The store is written before the response.
- **The refresh race (A13).** A client can lose the response to a refresh (a network blip), then present the just-retired refresh token again.
  - Within **30 s** of rotation, that is treated as a retry. It rotates again and retires the pair issued moments before, without tripping reuse detection.
  - After 30 s, presenting a retired token is reuse, and kills the Connect.
  - The cost: a thief racing inside those 30 s gets one pair. The legitimate client's next refresh then presents a retired token, which trips the kill. Detection is delayed, never lost.

**I6. Sequencing against #208.** N3 is implemented **after #208 merges**. It builds on #208's public origin, its `__Host-` cookie, its named exemption list and its ceremony table, with no interim loopback-only variant. The E2E (follow-up 8) extends #225's fake-edge pattern to both hostnames.

**I7. The audit field mapping.**
- New events use the existing `Entry` fields: `agent_id` = the `c-…` id, `origin` = the client's CIMD hostname, `channel` = `web_ui` or `cli`, `detail_code` from an enum.
- `oauth_client_refused` has no `agent_id`. Its `detail_code` is one of `not_allowlisted`, `cimd_unavailable`, `cimd_invalid` or `redirect_mismatch`.
- No new free-form field is added.

## Threat model notes

These extend SPEC §2. The actors are §2's, plus the operator as #208 adds them.

- **Cloudflare as a TLS terminator.** The edge sees, in plaintext:
  - the authorize query (code challenge, state);
  - the code, and the code verifier at exchange;
  - access and refresh tokens on the token endpoint and on `/mcp`.

  This is accepted. A managed deploy already trusts the edge with the bearer token on `/mcp` today. The limits on what that buys an attacker:
  - access tokens live 1 h;
  - refresh reuse kills the Connect;
  - Disconnect is immediate;
  - **CDP stays end to end inside the connector's pinned inner TLS** (#199), so the edge never sees page contents or filled credentials.

  The consent's passkey assertion is origin-bound, so a terminator can relay it within the live session but can't replay it elsewhere. The same applies to every owner action under N2.
- **Token leakage.**
  - Tokens and codes never enter logs or the audit log. Audit entries carry the identity id only, and #200's log redaction covers `kh_at_` and `kh_rt_`.
  - The state file holds SHA-256 hashes only, mode 0600.
  - Token responses send `Cache-Control: no-store`.
  - A leaked access token is good for at most 1 h, only for `/mcp`, and only to *request*.
- **Redirect URI validation.**
  - Exact string match against `redirect_uris` from the CIMD of an allow-listed client.
  - HTTPS only; no `localhost`.
  - Errors before the redirect is validated never redirect.
- **Replay.**
  - Codes are single use and valid for 60 s, bound to PKCE S256, the client, the redirect and the resource. A second use revokes everything issued from the first.
  - Refresh tokens rotate, with reuse detection.
  - The consent POST carries a single-use nonce.
- **Mix-up and phishing.**
  - The authorization response includes `iss`, and clients compare it exactly.
  - Only allow-listed dashboards can show a consent screen.
  - The screen names the client and its hostname.
- **CSRF and clickjacking on consent.**
  - `SameSite=Strict`, `Secure`, `__Host-` session cookie (#208 AC6).
  - `Origin` check.
  - A per-request nonce.
  - `frame-ancestors 'none'`.
- **SSRF.**
  - The only outbound fetch is a CIMD URL already on the allow-list.
  - No redirects; address-class refusal; size and time limits.
- **Denial of service.**
  - `/oauth/token`, `/oauth/revoke` and the authorize page are unauthenticated and on the internet, so they are throttled per source as in D6.
  - The token check on `/mcp` for `kh_at_` is a hash lookup, so it can't be used to exhaust the Argon2id permits.
- **A compromised dashboard.** It holds tokens for its own Connect only. It can request grants and ask for fills, and every one still needs the owner's approval in the UI (REQ-APR-001). The owner disconnects it in one click.

## What changes where

| Component | Change |
|---|---|
| `kharond` config | New `[oauth]` section (`clients`, the issuer derived from `[owner_ui] origin`). It requires `[public_ingress]` and a public `[owner_ui]` origin (#208). |
| `[public_ingress]` (`api/public.rs`) | `admit()` gains `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-protected-resource/mcp` when `[oauth]` is set. The 401 gains `resource_metadata` and `scope`. The Cloudflare tunnel's path allow-list grows by those two paths. |
| `[owner_ui]` | New AS metadata, `/oauth/authorize`, consent POST, `/oauth/token`, `/oauth/revoke` and the Connections page. `/oauth/token` and `/oauth/revoke` join #208's named exemption list, and need an Access bypass if Access is on. |
| `api/core.rs` auth | Prefix dispatch: `kh_agent_` goes to `TokenStore`, `kh_at_` to the OAuth store. `AgentId` carries a scope set, checked against #200's allow-list. |
| State | New `data_dir/oauth/state.json` (D3). |
| Audit (§7) | New events: `oauth_connect`, `oauth_disconnect`, `oauth_refresh_reuse`, `oauth_client_refused`. All carry the identity id and the client hostname; none carries a token. Token issue and refresh are not audited one by one. |
| Owner UI | Consent screen and Connections page. Approvals, grants and the audit view show Connect identities by `client_name`. |
| Docs | `docs/deployment.md`: the `[oauth]` config, the two tunnel paths, the exemption and the Access bypass, and what a customer sees. |

## Dependencies and order

1. **#200** (Muse): per-agent tool allow-list, `CF-Connecting-IP` helper, log redaction. N3's scopes and throttling sit on it.
2. **#208** (N2): the public owner hostname, `__Host-` cookies, the named exemption list, per-source throttling. N3's AS lives there.
3. **#132:** a sequencing dependency, so that revoke semantics match (D4).
4. **N3 implementation** (the issues below).
5. **Phase 2,** the browser through the connector: its own design and issue.

## Follow-up issues to file once this design is approved

1. **SPEC.** A `docs(spec)` PR:
   - REQ-API-003 gains OAuth access tokens beside `kh_agent_`;
   - new REQ-OAU-001… for D1, D2, D4, D5 and D6;
   - REQ-DEP-006 gains the well-known paths and the owner-hostname AS routes;
   - §7 gains the events, and REQ-REV-001/-002 cover Connect identities;
   - §2 gains the threat-model notes above.
2. **Discovery.** Protected-resource metadata, AS metadata, the 401/403 challenge headers, and the `[oauth]` config with its errors.
3. **Client admission.** CIMD fetch, validation and cache, behind the allow-list, with the SSRF rules.
4. **Authorize, consent and code** (D6), on the owner hostname.
5. **The token side.** Token and revoke endpoints, the state file, rotation and reuse detection (D3, D4).
6. **Scope enforcement and the `no_browser` error** (D5, D7 phase 1), on #200's allow-list.
7. **The Connections page,** Disconnect, the panic hook, and the audit events (D9).
8. **An E2E.** A fake dashboard client (a CIMD served by the test) runs the full Connect, refresh, reuse-kill and Disconnect cycle against the compose stack.
9. **Phase 2 design:** a dashboard runtime's connector authenticating with a Connect token (D7).
10. **Optional:** a "customer-only approvals" mode for the owner socket (D9).

## Assumptions (not settled by Lothrop or Nyx)

Each one is the design's call. Overturn any in review.

- **A1:** the issuer is the owner origin with no path. The AS endpoints live under `/oauth/` on the owner hostname.
- **A2:** the allow-list is operator config in `kharon.toml` (`[oauth] clients`). The customer doesn't edit it. Adding a dashboard is an operator change.
- **A3:** redirect URIs must be `https`, and `localhost` is refused. Desktop MCP clients that need loopback redirects aren't the target user's path. They can use a pasted token or a later relaxation.
- **A4:** public clients only (`token_endpoint_auth_method = none`), with PKCE S256 required. Confidential clients (`private_key_jwt`) aren't supported in N3.
- **A5:** every Connect creates a new identity, even from the same dashboard. Old ones stay until disconnected, or until their refresh token's 90-day absolute limit (A6).
- **A6:** refresh tokens have a 30-day idle limit and a 90-day absolute limit. The spec gives no numbers.
- **A7:** phase 2 reuses wire v1's hello token field for a Connect access token, rather than adding a wire version. That is to be confirmed by the phase 2 design.
- **A8:** the first passkey is still an operator-issued single-use enrolment code, delivered as a one-time link (Q8). No CLI step falls to the customer.
- **A9:** the owner socket keeps owner powers on a managed deploy, made visible on channel `cli` (D9).
- **A10:** `kharon:read` is always granted. `kharon:fill` and `kharon:request` can be unticked at consent.
- **A11:** a fresh passkey assertion is required to approve a Connect, even inside a live owner session.
- **A12:** token issue and refresh aren't audited one by one: they would flood the chain hourly per Connect. Connect, Disconnect, reuse and refused-client are audited.
- **A13:** a 30 s retry grace after a refresh rotation (I5). Without it, one lost response kills a Connect.
- **A14:** `kh_at_` tokens work only on `POST /mcp`, never on `/v1/*` (I3).
- **A15:** N3 is implemented after both #200 and #208 merge. There's no stub and no loopback interim (I3, I6).
- **A16:** a failed CIMD fetch fails closed. There's no stale-on-error (I4).
