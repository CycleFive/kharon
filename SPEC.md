# kharon — spec (draft)

Status: draft, 2026-10-30. Repo: `CycleFive/kharon`. Name decided: kharon. Language: Rust.

kharon is a broker that runs beside Vaultwarden on owner-controlled hardware. It decrypts a dedicated Bitwarden collection client-side and fills credentials into a browser tab over CDP. Agents get metadata and fill status. They never get plaintext.

Requirement IDs are `REQ-<AREA>-NNN`. Each has one testable acceptance criterion (AC). Areas: GOAL, CRY, EXP, ARCH, API, APR, ORG, AUD, RL, REV, MEM, DEP.

## 1. Goals and non-goals

Goals
- G1. A fill never puts a secret (password, TOTP seed, TOTP code, card number, custom hidden field) into agent context, MCP/HTTP responses, logs, the agent host's disk, or any process running as the agent's OS user other than the browser renderer that owns the target field.
- G2. Every fill is bound to an item, an origin, an agent identity, and a grant. Every fill is audited.
- G3. Blast radius is one Bitwarden collection, not the owner's vault.
- G4. Works against Vaultwarden and official Bitwarden (cloud or self-hosted) using only the public client API.

Non-goals
- N1. Protecting a secret after it lands in a DOM field from code running in that page or from an actor holding full CDP/JS on that tab (§2.4).
- N2. Running inside Vaultwarden or patching its server code.
- N3. Writing to the vault: creating, editing, or rotating items. v1 is read-only.
- N4. Passkeys/WebAuthn assertions, SSH keys, and card or identity autofill in v1 (OQ-6).
- N5. Multi-owner or multi-tenant operation.

| ID | Requirement | AC |
|---|---|---|
| REQ-GOAL-001 | No API surface returns secret-bearing fields. | A schema test enumerates every MCP tool and HTTP route response type. None contains a type marked `Secret<…>`. A fuzzed fill run with canary secrets finds 0 canary bytes in responses, broker logs, and audit log. |
| REQ-GOAL-002 | Canary secrets never reach the agent host filesystem. | E2E: fill a 32-byte random canary. `grep -r` across the agent host's `/` (excluding `/proc`) and the browser profile dir after the fill finds 0 hits. Chromium password saving is disabled. |

## 2. Threat model

### 2.1 Actors

| Actor | Trust | Capabilities assumed |
|---|---|---|
| Agent (LLM + tool harness) | Untrusted: curious or compromised, including via prompt injection | Calls kharon API with its token. Drives the browser: navigates, clicks, reads DOM and screenshots, and may run JS in pages. Reads anything its OS user can. |
| Agent host (Linux box with Chromium) | Partially trusted. Assume the agent's OS user is compromised. Root is not compromised, otherwise G1 is lost (§2.4). | Runs Chromium and the CDP tunnel endpoint. |
| Network (LAN/WAN between hosts) | Untrusted | Passive and active MitM. |
| Vaultwarden server | Honest-but-curious about ciphertext (Bitwarden's model). May serve stale or malicious ciphertext or org keys. | Sees ciphertext, the master-password hash, and API key use. Never sees plaintext. |
| Broker host (owner hardware) | Trusted | Holds decrypted keys in RAM. |
| Owner | Trusted | Unlocks and approves. Holds the master password of the kharon Bitwarden account. |
| Web origin being filled | Untrusted for everything except receiving its own credential | Can redirect, iframe, and race navigations. |

### 2.2 Assets

A1: plaintext secrets of items in the kharon collection. A2: kharon account master password, master key, user key, RSA private key, org key(s). A3: agent tokens and grants. A4: audit log integrity. A5: the owner's other vault items. kharon never holds keys to these, by construction.

### 2.3 Trust boundaries

B1 agent ↔ broker API: authN with agent token, authZ with grants. B2 broker ↔ Chromium: mTLS/WireGuard tunnel, CDP. B3 broker ↔ Vaultwarden: TLS, Bitwarden API. B4 owner ↔ broker: approval channel with owner authN. B5 renderer page ↔ field value: not enforceable by kharon.

### 2.4 Protects / does not protect

| Protects against | Mechanism |
|---|---|
| Secret in LLM context, tool output, shell history, agent logs | No read endpoint. Fill returns status only. (REQ-API-*) |
| Agent filling credential X on attacker origin Y (phishing or prompt injection) | eTLD+1/host binding checked atomically in the live frame (REQ-ORG-*) |
| Unapproved or excessive use | Grants, TTL, rate limits (REQ-APR-*, REQ-RL-*) |
| Silent misuse / after-the-fact denial | Hash-chained audit with signed checkpoints (REQ-AUD-*) |
| Theft of agent host disk | Nothing secret is persisted there |
| Vaultwarden DB compromise | Standard Bitwarden E2EE. kharon adds no server-side plaintext. |
| Broker restart or crash dump leaking keys | mlock, no core dumps, starts locked (REQ-MEM-*) |

| Does NOT protect against | Why |
|---|---|
| Agent reading the field after fill (`input.value`, `Runtime.evaluate`, DOM snapshot, page JS) when the agent has JS/CDP on the same tab | The plaintext must exist in the renderer for the form to submit. 1Password's agent fill has the same property. Mitigations, which reduce exposure but do not remove it: `fill_and_submit`, clear-on-failure, password-type fields only, and an optional agent tool profile with no `evaluate` (OQ-3). |
| Root on agent host | Can read Chromium memory and tunnel keys |
| Malicious or XSS'd page on a correctly bound origin | Page receives its own credential by design |
| Owner approving a bad request | The human is the oracle. kharon shows origin, item, and agent in the prompt. |
| Compromised broker host | Holds keys |
| Malicious Vaultwarden swapping ciphertext under the org key | Undetected item substitution within the collection is possible because Bitwarden cipher fields are not bound to the item ID. The URI binding uses the decrypted item URIs, so a swapped item still fails the origin check unless the attacker controls both. See OQ-7. |

## 3. Architecture

```
 owner hw                                     agent host
┌──────────────────────────┐   WireGuard/mTLS   ┌─────────────────────────┐
│ vaultwarden  ◄─TLS─ kharond ├──── CDP (ws) ─────►│ chromium (user: browser) │
│                 │  ▲  ▲   │                    │   ▲ CDP (agent session)  │
│                 │  │  └─ approvals (ntfy/web/CLI)  │ agent (user: agent)     │
│                 │  └── MCP/HTTP (agent token) ◄──┤                         │
└──────────────────────────┘                    └─────────────────────────┘
```

### 3.1 Bitwarden account and crypto model

kharon logs in as a dedicated Bitwarden user, e.g. `kharon@<domain>`. That user is the only non-owner member of a dedicated Vaultwarden organization, `kharon`, created for this purpose. It has Can view access to that org's collection(s) and to nothing else. The owner adds new items to that org, or moves or clones existing personal items into it, through the web vault. kharon sees exactly the items in that org and its configured collections. Edits, additions, and removals made in the web vault reach kharon through periodic `/api/sync` (and the notifications hub when available), with no restart. A Bitwarden item has exactly one owner, so an item kept in both places is two copies. The owner keeps agent-usable credentials only in the kharon org (OQ-5, resolved).

Login uses the account's personal API key, `client_credentials` grant with `client_id=user.<uuid>` and `scope=api`. This authenticates to the server but does not decrypt. Decryption needs the master password. An organization API key cannot be used: it reaches the Public API only and yields no vault keys.

Key derivation chain, per the Bitwarden Security Whitepaper. Verify each line against the whitepaper and sdk-internal `bitwarden-crypto` during M1 (REQ-CRY-010).

| Step | Construction |
|---|---|
| KDF params | `POST /identity/accounts/prelogin` → `{kdf, kdfIterations, kdfMemory, kdfParallelism}` |
| Master key (32 B) | PBKDF2-HMAC-SHA256(password, salt=lowercase(email), iters; default 600 000), or Argon2id(password, salt=SHA-256(lowercase(email)), m=64 MiB, t=3, p=4 defaults) |
| Stretched master key (64 B) | HKDF-Expand-SHA256(masterKey, info="enc", 32) ‖ HKDF-Expand-SHA256(masterKey, info="mac", 32) |
| Server auth hash | PBKDF2-HMAC-SHA256(masterKey, salt=password, 1). Not needed for API-key login, but needed for password login and `/accounts/verify-password`. |
| User key (64 B: enc‖mac) | Token/sync response `Key`: EncString type 2 = AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC over iv‖ct), under the stretched master key |
| RSA private key | `PrivateKey`: PKCS#8 RSA-2048, EncString type 2 under the user key |
| Org key (64 B) | `profile.organizations[].key`: EncString type 4 = RSA-2048-OAEP-SHA1 under the user's public key |
| Cipher key (optional, per item) | `cipher.key`: EncString type 2 under the org key. If present, fields are under it. Newer clients set it. |
| Fields | `login.username`, `login.password`, `login.totp`, `login.uris[].uri`, `name`, `notes`, `fields[]`: EncString type 2 |

Known uncertainty: Bitwarden is rolling out "account cryptography v2" (COSE-encoded keys, XChaCha20-Poly1305 EncString type 7, signing keys). Whether Vaultwarden serves v2 material, and when official cloud migrates existing accounts, is unverified (OQ-8). kharon must fail closed on unknown EncString types.

Implementation options:

| Option | Pros | Cons |
|---|---|---|
| `bitwarden-crypto` / `bitwarden-vault` crates from `bitwarden/sdk-internal` | Canonical. Tracks v2 crypto and cipher keys. | License is the Bitwarden SDK License for some crates, possibly not compatible with intended use (OQ-2). API unstable ("internal"). Large dep tree. |
| Own minimal implementation, rbw-style (rbw, MIT, implements prelogin → identity → sync → decrypt in Rust) | Small and auditable. License clean. Controls zeroization. | Must track crypto changes. Needs test vectors. |

Recommendation: own minimal crate `kharon-bwcrypto` using RustCrypto (`aes`, `cbc`, `hmac`, `sha2`, `hkdf`, `pbkdf2`, `argon2`, `rsa`). Write it from the whitepaper, with test vectors generated by the official CLI (`bw`) against a Vaultwarden fixture. Keep sdk-internal as a reference only, unless OQ-2 resolves favorably.

| ID | Requirement | AC |
|---|---|---|
| REQ-CRY-001 | Derive the master key for PBKDF2 and Argon2id from prelogin params. | Vectors from `bw` for both KDFs at non-default params match byte-for-byte. |
| REQ-CRY-002 | Parse and decrypt EncString types 2 and 4. Reject every other type with a typed error. | Unit tests: valid 2/4 decrypt. Types 0,1,3,5,6,7 and malformed input return `UnsupportedEncType`/`Malformed`, with no panic (`cargo fuzz` 10 min, 0 crashes). |
| REQ-CRY-003 | Verify MAC in constant time before decrypting. Never decrypt on MAC failure. | A flipped bit in ct, iv, or mac yields `MacMismatch`. The test asserts the CBC decryptor was not invoked. |
| REQ-CRY-004 | Unwrap user key → private key → org key → optional cipher key. | Fixture account in Vaultwarden: decrypt a known item with and without `cipher.key`, matching `bw get item`. |
| REQ-CRY-005 | Log in with personal API key, then sync. | Against Vaultwarden 1.3x and a Bitwarden cloud test account: `GET /api/sync` returns 200 and the collection items decrypt. |
| REQ-CRY-006 | Field classes: metadata = name, URIs, username (decrypted at sync, held in memory for list/match). Secret = password, TOTP, hidden custom fields, notes (decrypted per fill only). Keep no plaintext secret cache. | A heap snapshot (debug feature) after sync contains no canary plaintext. After a fill completes, the canary is absent within 1 s. |
| REQ-CRY-007 | Restrict the item set to configured org and collection IDs. | Items in other collections or orgs visible to the account are absent from `list` and rejected by `fill` (`ItemNotFound`). |
| REQ-CRY-008 | Dedicated org: the broker refuses to start if the kharon account can see any org other than `organization_id`, or any item outside it, unless `allow_extra_orgs=true`. | Fixture with the account added to a second org → startup error `ScopeTooBroad`. The check reruns on every sync: widening mid-run → lock + audit `scope_widened`. E2E adds a second org while unlocked and the next sync locks. |
| REQ-CRY-009 | Live sync: web-vault changes reach the broker without restart. Full `/api/sync` runs every ≤ 5 min while unlocked. If the server supports the notifications hub (`/notifications/hub`, SignalR), sync runs on push. | E2E: add, edit, and delete an item in the web vault. Within 5 min (≤ 10 s with push), `list` reflects each change with no process restart (PID unchanged). |
| REQ-CRY-010 | Document each crypto step with a whitepaper/sdk citation. | `docs/crypto.md` exists. Each table row links a source. Reviewed. |

### 3.1a Export mode (optional, offline)

For air-gapped use, kharon can run with no Vaultwarden account. It loads a password-protected encrypted Bitwarden JSON export (`"encrypted": true, "passwordProtected": true`) at startup. In that format the export is under a key derived with the export's KDF params and a salt, and `encKeyValidation_DO_NOT_EDIT` checks the password. Verify the exact format against the official clients during implementation. Account-restricted encrypted exports are refused because they need the account's user key. Updating means replacing the file and restarting. There is no sync. All grant, origin, audit, and memory rules apply unchanged.

Risks:
- Plaintext JSON or CSV exports are never accepted. The broker refuses them at load.
- The export password must be held somewhere. It is supplied at unlock like the master password, never in config, env, or disk. An unattended restart therefore stays locked.
- The export file is a full offline-attackable copy of the items. Its strength is the export password and KDF. Item revocation requires replacing the file.
- Staleness: a rotated password in the real vault is not reflected until the file is replaced.

| ID | Requirement | AC |
|---|---|---|
| REQ-EXP-001 | `mode = "export"` loads a password-protected encrypted Bitwarden export. No network to any Bitwarden server. | Fixture produced by `bw export --format encrypted_json --password …` loads. `list` matches the source. Network namespace with no egress: works. |
| REQ-EXP-002 | Refuse plaintext JSON, CSV, and account-restricted exports. | Each fixture → startup error `ExportNotPasswordEncrypted`. No item parsed or logged. |
| REQ-EXP-003 | Export password supplied only at unlock (CLI/web), zeroized after key derivation. Boots locked. | Config/env keys for the password are rejected. Canary scan after unlock finds 0 hits. Restart → `locked`. |
| REQ-EXP-004 | No sync in export mode. Update = replace file + restart. File SHA-256 recorded in an audit `export_loaded` entry. | Changing the file without a restart does not change `list`. After restart, the audit has a new hash. |
| REQ-EXP-005 | Wrong password or a failed validation field → refuse without partial load. | A bad-password fixture → `ExportAuthFailed`, 0 items. |

### 3.2 Components

- `kharond`: broker daemon on owner hardware. It holds keys, enforces grants and origin binding, drives CDP, and writes audit. It exposes MCP (streamable HTTP) and an HTTP API to agents, and a separate owner API: unix socket for the CLI, plus web UI.
- `kharon` CLI: owner tool for unlock, lock, approve, revoke, and audit verify.
- Fill transport on the agent host: Chromium plus a tunnel endpoint.

### 3.3 How secrets reach the page

| | (a) Broker drives Chromium over CDP via tunnel | (b) Fill helper on agent host as separate OS user |
|---|---|---|
| Plaintext path | broker RAM → TLS/WG → Chromium browser process → renderer | broker → helper process (agent host) → CDP/native messaging → renderer |
| New agent-host process holding plaintext | None (Chromium already must) | Helper. Ptrace-protected only if `kernel.yama.ptrace_scope≥1` and the users differ. Its sockets/IPC are reachable by the agent user. |
| Agent-host secrets at rest | Tunnel client key only, which grants CDP to the browser the agent already controls | Helper credentials to the broker (a bearer that can request fills); config files root-owned |
| Attack surface reachable by the agent user | Chromium's CDP endpoint (already reachable) | Plus the helper IPC: parser bugs, confused deputy |
| Origin check runs | In broker, against the frame's live origin via CDP | In helper. Separation depends on host user isolation. |
| Install footprint | Chromium flag plus a tunnel. No kharon code on the agent host. | Package, service user, sudo/systemd setup |

(a) is the stronger boundary. Plaintext and all policy code stay on owner hardware. The only new thing on the agent host is a path into a browser the agent already drives, so it adds no agent-reachable component that holds secrets or credentials to the broker. (b) adds a local privileged peer whose isolation depends on the agent host's Unix permissions, which the threat model assumes are partly compromised. Both share the N1 limit.

Recommendation: (a). Chromium runs as OS user `browser` with `--remote-debugging-port` bound to 127.0.0.1, or `--remote-debugging-pipe` behind a small root-owned relay. The broker reaches it through WireGuard (preferred) or an `ssh -R`/mTLS stunnel. The agent keeps its own CDP session (Playwright/puppeteer `connectOverCDP`). kharon opens a separate CDP session. Running as a separate user does not stop the agent attaching to CDP, because it does that already. It does stop the agent reading the profile dir and `/proc/<pid>/mem` (`ptrace_scope`).

| ID | Requirement | AC |
|---|---|---|
| REQ-ARCH-001 | No kharon binary or secret-bearing config on the agent host. | The deployment guide's agent-host steps install only Chromium flags and tunnel config. CI checks the docs. |
| REQ-ARCH-002 | Broker ↔ CDP traffic is authenticated and encrypted. | Plain `ws://` to a non-loopback address is refused at config load. A tunnel test with a wrong peer key fails to connect. |
| REQ-ARCH-003 | Broker uses its own CDP session and never enables domains that echo secrets to other sessions. | In an E2E with a second CDP client subscribed to `Runtime`, `Log`, `Network`, and `Page`, the canary is not received by the second client during fill. Mutation observers in page JS are excluded per N1. |
| REQ-ARCH-005 | Target ownership. The broker creates one browser context per agent (`Target.createBrowserContext`) and hands the agent its `browserContextId`. `fill` is accepted only if `cdp_target_id` is in the requesting agent's context. Targets in the default context are refused unless `allow_default_context=true`, for single-agent setups. | E2E: agent A fills into a tab in agent B's context → `target_not_owned`. Default-context tab with the flag off → refused. |
| REQ-ARCH-004 | Chromium launched with password manager and autofill save disabled. | Profile `Login Data` contains 0 rows after 10 fills. |

## 4. Agent-facing API

Exposed as MCP (tools below) and HTTP `/v1/*`, with identical semantics. Auth: `Authorization: Bearer kh_agent_<id>_<random32>`. Only the Argon2id hash of the token is stored. One token per agent identity.

| MCP tool | HTTP | Returns |
|---|---|---|
| `kharon_status` | `GET /v1/status` | `{locked: bool, agent_id, grants:[Grant]}` |
| `kharon_list` | `GET /v1/items?origin=` | `[ItemMeta]` |
| `kharon_search` | `GET /v1/items?q=&origin=` | `[ItemMeta]` |
| `kharon_fill` | `POST /v1/fill` | `FillResult` |
| `kharon_fill_totp` | `POST /v1/fill_totp` | `FillResult` |
| `kharon_request_grant` | `POST /v1/grants` | `{grant_request_id, state}` |

There is no read-secret, export, or reveal route, and no `include_secret` flag. This is permanent, enforced by REQ-GOAL-001 and REQ-API-005.

```jsonc
// ItemMeta
{ "id": "uuid", "name": "string", "username_hint": "j***@example.com", // masked; OQ-4
  "uris": [{"host": "accounts.example.com", "match": "domain|host|exact|starts_with"}],
  "has_password": true, "has_totp": true, "revision": "rfc3339" }

// FillRequest
{ "item_id": "uuid",
  "target": { "cdp_target_id": "string",           // tab, from agent's own CDP session
              "frame_id": "string?",               // default: top frame
              "expected_origin": "https://accounts.example.com" },
  "fields": [ { "kind": "username|password|totp", "selector": "css?" } ], // selector optional → heuristic
  "submit": false,                                 // true = fill_and_submit
  "grant_id": "string?" }

// FillTotpRequest = FillRequest with fields=[{kind:"totp", selector?}]

// FillResult
{ "status": "filled|pending_approval|denied|origin_mismatch|target_not_owned|navigated|field_not_found|locked|rate_limited|not_found|error",
  "fields_filled": ["username","password"],        // kinds only
  "grant_request_id": "string?", "audit_seq": 1234, "detail": "string?" } // detail never contains values
```

| ID | Requirement | AC |
|---|---|---|
| REQ-API-001 | MCP server (streamable HTTP) exposing the six tools with JSON Schemas generated from Rust types (`schemars`). | `mcp-inspector` lists 6 tools. Schemas match the snapshot test. |
| REQ-API-002 | HTTP API with identical semantics and OpenAPI doc. | A contract test runs each case against both transports with identical results. |
| REQ-API-003 | Agent token auth. Hash stored with Argon2id. Constant-time compare. | Bad token → 401. The token store file has no plaintext token (grep). |
| REQ-API-004 | `list`/`search` return `ItemMeta` only, filtered by `origin` if given. | Golden test: response keys ⊆ the ItemMeta schema. Canary absent. |
| REQ-API-005 | Secret types (`Secret<String>`) do not implement `Serialize`/`Debug`/`Display`. | A compile-fail test (`trybuild`) shows serializing a `Secret` fails to compile. |
| REQ-API-006 | Error `detail` strings are built from an enum, never interpolated with field values. | A lint/test asserts no `format!` in `detail` constructors takes `Secret`. Fuzz finds no canary in details. |
| REQ-API-007 | `fill_totp` computes RFC 6238 (SHA1/256/512, digits, period from `otpauth://` or bare base32; `steam://` 5-char) and fills the code. The code is never returned. | RFC 6238 test vectors pass. Steam vector passes. Response has no digits field. |
| REQ-API-008 | `submit:true` dispatches submit (Enter on last field, or `form.requestSubmit()` in the isolated world) only after all fields fill successfully. | E2E: a test page records the submit event exactly once, and only when all fields filled. |

## 5. Approval flow

Grant = `{id, agent_id, item_id|*collection, origin (eTLD+1 or host), actions ⊆ {fill, totp}, expires_at, max_uses, uses, created_by_channel}`. A fill without a matching live grant creates a `GrantRequest` and returns `pending_approval`. The agent may poll `kharon_status`, or call with `wait_s ≤ 60`. Requests time out after 120 s and are denied by default.

| Grant type | Default TTL | Use |
|---|---|---|
| once | 120 s, max_uses=1 | Default |
| per-origin | 1 h (max 24 h) | Repeated logins to one site |
| standing | Off by default. Requires config flag. Max 30 d. | Unattended jobs |

| Channel | Owner authN | Notes |
|---|---|---|
| ntfy (self-hosted beside Vaultwarden) | `once` grants: an ntfy `http` action, which the ntfy app sends as a POST on tap (ntfy default; not a link, so no prefetch), to `/owner/approve/<one-time token>`. The token is single-use, 120 s, and 256-bit. per-origin and standing grants: a `view` action opens a confirm page (GET renders only) and the confirm needs WebAuthn. The approve endpoint is POST-only. GET never mutates. | ntfy topic is access-controlled. The message contains agent, item name, origin, and action, never secrets. |
| Web UI | WebAuthn passkey (owner), session ≤ 15 min | Shows pending requests, grants, audit tail |
| CLI | Unix socket `0600` owned by kharon user. `SO_PEERCRED` uid check. | `kharon approve <id> [--ttl 1h --scope origin]`, `kharon deny`, `kharon grants` |

| ID | Requirement | AC |
|---|---|---|
| REQ-APR-001 | Fill without a grant → `pending_approval`. No secret-bearing field (password, TOTP seed, hidden custom field, notes) is decrypted before approval. Match metadata (name, URIs, username) is decrypted at sync. | Test: the secret-field decrypt counter stays 0 until approval. The metadata counter is unconstrained. |
| REQ-APR-002 | Grants match on agent, item, origin, and action, plus TTL and max_uses. | Table-driven tests: each dimension mismatch → new request. Expired grant → new request. |
| REQ-APR-003 | Request auto-denies at timeout. | With the clock mocked at +121 s the state is `denied` and audited. |
| REQ-APR-004 | ntfy channel with single-use approve/deny tokens. Approve and deny are POST-only. | Replay of a used token → 410. A token older than 120 s → 410. GET on the approve URL → confirm page, grant state unchanged. |
| REQ-APR-005 | Web UI with WebAuthn-only owner login. | A login without passkey assertion is impossible (no password route). E2E with a virtual authenticator. |
| REQ-APR-006 | CLI over unix socket with peer uid check. | Connect as another uid → rejected and audited. |
| REQ-APR-007 | Approval prompt shows the live origin observed at request time, not the agent's claim. | Test: agent claims origin A while the tab is on B. The prompt shows B and the request is `origin_mismatch` before prompting. |

## 6. Origin binding

The match is computed from the decrypted `login.uris[]` and their Bitwarden match type (`uri.match`, or the account default, `Domain`):

| BW match | kharon v1 |
|---|---|
| Domain (0) | eTLD+1 via the Public Suffix List (`publicsuffix` crate, PSL snapshot pinned and updated in release) equal |
| Host (1) | host and port equal |
| StartsWith (2) | Origin must also be Host-equal. Prefix check on full URL. |
| Exact (3) | full URL equal (origin + path) |
| RegularExpression (4) | Refused (`origin_mismatch`). Fail closed. |
| Never (5) | Refused |

Rules: scheme must be `https`, except `http://localhost`/IP only if the item URI is literally http and `allow_http=true`. The page must be a secure context. Frame origin and top-level origin must both match (default). Config `allow_cross_origin_iframe_hosts` permits named IdP iframes. Origins in the IDN and punycode form are compared after `idna` normalization. A PSL private-section entry, such as `github.io`, makes the eTLD+1 the user's subdomain, which is intended.

Redirect-race defense. The check and the write happen in one renderer task:
1. `Page.createIsolatedWorld(frameId)` → contextId. Record `loaderId`.
2. `Runtime.callFunctionOn` in that context with args `(matchers, kind, selector, secret)`. Comparand per match type: Domain → `location.protocol` plus `location.hostname` equal to or ending in `.`+d, where the broker PSL-reduced d (no PSL in-page). Host → `location.origin`. Exact → `location.href` equal. StartsWith → `location.origin` equal and `location.href` prefix. The function checks these and `window.top.location.origin` if same-origin-accessible (else uses step 1's frame-tree origin check). It resolves the field, sets the value via the native `HTMLInputElement.prototype.value` setter, and dispatches `input` and `change`. All of this runs synchronously, so JS run-to-completion means no navigation can commit mid-function.
3. If the document navigates, the isolated world context is destroyed and the call fails (`navigated`). It cannot land in the new document.
4. After the call: check that `loaderId` is unchanged. If it changed, attempt a clear in the old context (best effort) and report `navigated`.

The fallback path, `Input.insertText` for sites that ignore programmatic value sets, is gated by a pre-check plus a post-check of `loaderId` and origin. It is weaker: there is a race window between focus and insert. It is off by default (OQ-9).

| ID | Requirement | AC |
|---|---|---|
| REQ-ORG-001 | Implement the match table above with PSL. | Table tests ≥ 40 cases, including `co.uk`, `github.io`, IDN, ports, `http`, RegEx refused. In-page E2E for Exact and StartsWith: matching origin with a non-matching href → `origin_mismatch`. |
| REQ-ORG-002 | Origin read from the live frame via CDP, never from agent input. | Test: the agent passes `expected_origin` = item origin while the tab is evil.test → `origin_mismatch`. |
| REQ-ORG-003 | Atomic check-and-set in an isolated world. Context destruction → `navigated`. | E2E: the page schedules `location = evil` on the `focus` event and in a microtask, 1000 iterations. 0 fills land on evil.test (server logs). |
| REQ-ORG-004 | Cross-origin iframe fill refused unless allowlisted. | E2E: the login form in an iframe from another eTLD+1 → `origin_mismatch`. Allowlisted → filled. |
| REQ-ORG-005 | Non-secure context refused. | E2E: an http page with an https item → refused. |

## 7. Audit, rate limits, revocation

Audit: append-only JSONL at `/data/audit/audit.jsonl`, opened `O_APPEND`, with `chattr +a` recommended. Entry:
`{seq, ts, prev_hash, event, agent_id, item_id, item_name_hash, origin, grant_id, channel, result, detail_code}`, with `hash = SHA-256(prev_hash ‖ JCS(entry without hash))` (RFC 8785 canonical JSON). Every N=100 entries or 10 min, a checkpoint `{seq, hash}` is signed with the broker's Ed25519 audit key and pushed off-host (ntfy or remote syslog) by default. Local-only checkpoints require `audit_checkpoint_local_only=true`, which is logged as a startup warning. Events: unlock, lock, sync, list, search, fill_*, grant_request, grant_issue, grant_revoke, token_create/revoke, owner_auth_fail, rate_limit, panic.

| ID | Requirement | AC |
|---|---|---|
| REQ-AUD-001 | Hash-chained JSONL with JCS canonicalization. | `kharon audit verify` passes on a clean log. Editing any byte of entry k reports the first bad seq = k. |
| REQ-AUD-002 | Signed checkpoints pushed off-host by default. Verifier, given the off-host checkpoint stream, detects truncation. | Delete the last 150 entries → verify reports `truncated after checkpoint seq=…`. |
| REQ-AUD-003 | Every state transition (request, grant_request, fill, owner action) produces exactly one entry, all written before the response is sent. Write failure → request fails closed. | Test with a read-only audit file → fill returns `error`. No CDP write occurred. |
| REQ-AUD-004 | No secrets or usernames in audit. Item name stored as HMAC-SHA256 under `audit_name_key`, a random 32-byte key generated at first start in `/data/keys/` (0600), separate from the Ed25519 audit key and never logged. It is not rotated: rotating breaks correlation, and its exposure reveals only names guessable by dictionary. Cleartext name only if `audit_item_names=true`. | Canary scan of the log = 0. |
| REQ-RL-001 | Per-agent token bucket (`fill` and `fill_totp` share it): fills 10/min and 100/day, list/search 60/min (configurable). | Load test: the 11th fill in 60 s → `rate_limited`. |
| REQ-RL-002 | Per-item: 5 fills (password or TOTP) per 10 min. Per-agent: 5 consecutive `origin_mismatch` → agent suspended until owner reset. | Tests for both thresholds. Suspension audited. |
| REQ-RL-003 | Pending grant requests ≤ 3 per agent (anti-approval-fatigue). | The 4th request → `rate_limited` without notification. |
| REQ-REV-001 | `kharon revoke grant <id>`, `revoke agent <id>` (token + grants), effective for the next request. | Revoke then fill within 10 ms → denied. |
| REQ-REV-002 | `kharon panic`: lock, zeroize keys, revoke all grants, close CDP sessions, notify. Also via ntfy action and web UI. | After panic, the heap scan shows no key canary. `status.locked=true`. Fill → `locked`. |
| REQ-REV-004 | Rollback detection: keep a per-item high-water `revisionDate` and an item-set hash in memory since unlock. A sync that regresses either → lock + audit `rollback_detected`. Grants pin the item revision at issuance; a fill against a different revision → `denied` (re-approval). Closes OQ-7 for v1. | Fixture serves an older cipher → lock. Changing an item revision after grant → fill denied. |
| REQ-REV-003 | Item removed from the collection, or revision changed, invalidates per-item grants on next sync. | Move an item out, sync → its grants are gone and audited. |

## 8. Unlock and key lifecycle

- Start state is always `locked`. The master password is supplied only by the owner via CLI (tty, no echo) or web UI after WebAuthn. It is never stored on disk, in env, or in config.
- Unlock derives the master key, decrypts the user key, then zeroizes the master key and password immediately. In memory it keeps the user key, the RSA private key (zeroized once org keys are unwrapped), and the org key(s). Cipher fields are decrypted per fill into `Zeroizing` buffers and dropped after CDP write.
- The API key (`client_id`/`client_secret`) is in a root-only file or Docker secret. On its own it yields ciphertext only.
- Process hardening: `prctl(PR_SET_DUMPABLE,0)`, `setrlimit(RLIMIT_CORE,0)`, `mlockall(MCL_CURRENT|MCL_FUTURE)` (needs `CAP_IPC_LOCK`, or memlock ulimit), `madvise(MADV_DONTDUMP)` on key arenas, `secrecy` + `zeroize` crates, `panic = "abort"`, no swap or encrypted swap, seccomp profile. Allocations holding key material live in a dedicated mlocked arena (OQ-10: `memsec`/custom allocator).
- Idle lock: `idle_lock = 30m` since last fill (configurable), plus `max_unlocked = 12h` absolute. Lock zeroizes keys and closes CDP sessions.
- Restart, crash, or OOM → locked. Pending requests are dropped and audited on next start as `abandoned`.
- Re-sync every 5 min while unlocked, and on `/v1/fill` if revision is older than 5 min. Server-side key rotation, which changes the org key, forces lock.

| ID | Requirement | AC |
|---|---|---|
| REQ-MEM-001 | Process is non-dumpable with core limit 0. | Test reads `/proc/self/status` (`CoreDumping`/dumpable), `prlimit` shows core 0. `gcore` as same uid fails. |
| REQ-MEM-002 | mlockall succeeds or the daemon refuses to unlock (`require_mlock=true` default). | Without IPC_LOCK, unlock → error `MlockUnavailable`. |
| REQ-MEM-003 | Password and master key zeroized after unlock. Keys zeroized on lock. | Debug-build canary scan of `/proc/self/mem` after unlock (password) and after lock (keys) = 0 hits. |
| REQ-MEM-004 | Idle and absolute lock timers. | With the clock mocked, state = locked at T+30m idle and T+12h absolute. |
| REQ-MEM-007 | Lock dominates grants: any fill while locked returns `locked`, regardless of standing or per-origin grants. Grants survive lock but are inert until unlock. | Standing grant + locked broker → `locked`, no CDP write. |
| REQ-MEM-005 | Boots locked. No secret persisted. | Kill -9 and restart → `locked`. `strings` on `/data` finds no canary or key. |
| REQ-MEM-006 | Unknown crypto version or org key change forces lock. | A fixture with a rotated org key → lock + audit `key_rotated`. |

## 9. Deployment

```yaml
services:
  vaultwarden: { image: vaultwarden/server:latest, networks: [vw] }
  kharon:
    image: ghcr.io/cyclefive/kharon:0.1
    user: "10001:10001"
    read_only: true
    cap_drop: [ALL]
    cap_add: [IPC_LOCK]
    ulimits: { memlock: -1, core: 0 }
    security_opt: ["no-new-privileges:true", "seccomp=./kharon-seccomp.json"]
    volumes: ["./kharon/data:/data", "./kharon/kharon.toml:/etc/kharon.toml:ro"]
    secrets: [kharon_bw_api_key]
    networks: [vw, wg]       # wg: to agent-host tunnel
    ports: ["127.0.0.1:8787:8787"]  # owner UI behind reverse proxy; agent API on wg iface only
```

```toml
[bitwarden]
server = "http://vaultwarden:80"          # or https://vault.bitwarden.com / self-hosted
email = "kharon@example.net"
api_key_file = "/run/secrets/kharon_bw_api_key"
organization_id = "uuid"
collection_ids = ["uuid"]
[agents.assistant]
token_hash = "$argon2id$..."
cdp = { endpoint = "ws://10.66.0.2:9222", via = "wireguard" }
[policy]
idle_lock = "30m"; max_unlocked = "12h"; default_grant = "once"; allow_standing = false
[approval]
ntfy = { url = "https://ntfy.example.net", topic = "kharon", token_file = "/run/secrets/ntfy" }
```

Compatibility: v1 uses only the endpoints official clients use: `/identity/accounts/prelogin`, `/identity/connect/token`, `/api/sync`. Requests send `Device-Type`, `Bitwarden-Client-Name`, and `Bitwarden-Client-Version` headers. Official cloud may enforce new-device verification and client-version checks. Behavior for API-key logins is unverified (OQ-11).

| ID | Requirement | AC |
|---|---|---|
| REQ-DEP-001 | Distroless/static image, non-root, read-only rootfs. | `docker run --read-only` works. Trivy reports 0 high/critical. Image < 30 MB. |
| REQ-DEP-002 | Compose example runs E2E against Vaultwarden. | CI job: compose up, then a seeded fixture fills a test page through headless Chromium. |
| REQ-DEP-003 | Config validated at startup. Unsafe combos refused (non-loopback plain CDP, standing grants without flag, missing mlock). | Table of bad configs → each exits non-zero with a specific error. |
| REQ-DEP-004 | Official Bitwarden compatibility tested. | A manual or nightly job against a cloud test account passes REQ-CRY-005. Result recorded in `COMPAT.md`. |
| REQ-DEP-006 | Agent API binds only to the configured WireGuard interface address. Owner API binds to loopback or a unix socket. Wildcard binds are refused. | Config with `0.0.0.0` → startup error. `ss -ltn` in E2E shows only the expected addresses. |
| REQ-DEP-007 | The kharon account master password is generated with ≥ 128 bits of entropy and stored by the owner outside the kharon org. The API-key file plus server access reduces to an offline attack on it. | Guide documents it. `kharon init` generates the password and prints it once to the tty. |
| REQ-DEP-005 | Agent-host guide: Chromium as `browser` user, `ptrace_scope=1`, WireGuard peer, password manager disabled. | The doc exists and an Ansible/shell snippet is tested in a VM. |

## 10. Open questions

| ID | Question |
|---|---|
| OQ-1 | Resolved: name is `kharon`. |
| OQ-2 | `bitwarden/sdk-internal` license per crate (`bitwarden-crypto`): is it usable in a GPL/MIT/Apache tool? Unverified. Defaults to own impl. |
| OQ-3 | Resolved: a recommended harness policy in the deployment guide (no `evaluate` or value reads), not a kharon feature. |
| OQ-4 | Is the masked username in metadata acceptable, or is it itself sensitive (account enumeration)? Default masked. Config to hide. |
| OQ-5 | Resolved: a dedicated `kharon` org. The owner adds or moves items there via the web vault, and live sync picks them up (REQ-CRY-008/009). |
| OQ-6 | Passkey (FIDO2 credential in vault) assertion via CDP WebAuthn virtual authenticator: feasible for v2? |
| OQ-7 | Resolved for v1: revision pinning plus high-water mark (REQ-REV-004). Cryptographic binding remains out of scope. |
| OQ-8 | Account crypto v2 (type 7 EncStrings, COSE keys): timeline on cloud and Vaultwarden support. |
| OQ-9 | Fallback stays off. The M2 fixture suite includes 2–3 realistic controlled-input pages (React, Vue, and a trusted-event-only page) to measure need. |
| OQ-10 | Resolved: `mlockall` + `MADV_DONTDUMP` for v1. No custom arena. |
| OQ-11 | Official cloud: new-device verification / captcha on API-key login, `Bitwarden-Client-Version` minimums. |
| OQ-12 | Resolved: per-agent browser contexts are v1 (REQ-ARCH-005). |
| OQ-13 | Resolved: dual `MIT OR Apache-2.0` (Lothrop). |

## 11. Milestones and issues

M0 skeleton · M1 vault read path · M2 fill path · M3 policy and approvals · M4 hardening and release.

| # | Issue | Covers | Depends |
|---|---|---|---|
| 1 | Workspace skeleton: crates `kharon-bwcrypto`, `kharond`, `kharon-cli`. CI (fmt, clippy, deny, test). `Secret` type. | REQ-API-005 | — |
| 2 | Config loader and validation | REQ-DEP-003 | 1 |
| 3 | EncString parser and type 2/4 decrypt with constant-time MAC. Fuzz target. | REQ-CRY-002, 003 | 1 |
| 4 | KDFs (PBKDF2, Argon2id), stretch, key unwrap chain incl. cipher key. `bw` vectors. | REQ-CRY-001, 004, 010 | 3 |
| 5 | Identity/sync client (prelogin, API-key token, sync), collection filter | REQ-CRY-005, 007 | 4 |
| 5b | Dedicated-org scope check and live sync (poll + notifications hub) | REQ-CRY-008, 009 | 5 |
| 6 | Vaultwarden fixture harness (compose, seeded org/collection/items via `bw`) | REQ-DEP-002 (part) | 5 |
| 7 | Lock state machine, unlock flow, idle/absolute timers, memory hardening | REQ-MEM-001..006, REQ-CRY-006 | 4 |
| 8 | Audit log: hash chain, JCS, checkpoints, `audit verify` | REQ-AUD-001..004 | 1 |
| 9 | Agent auth tokens and HTTP API (status/list/search) | REQ-API-002, 003, 004, 006 | 5, 8 |
| 10 | MCP server over the same core | REQ-API-001 | 9 |
| 11 | Origin matcher (PSL, BW match types) | REQ-ORG-001 | 1 |
| 12 | CDP client and tunnel transport. Per-agent browser contexts. Isolated-world atomic fill. Navigation detection. | REQ-ARCH-002, 003, 005, REQ-ORG-002..005 | 11 |
| 13 | Fill and fill_and_submit endpoints | REQ-API-008, REQ-GOAL-001 | 7, 9, 12 |
| 14 | TOTP generation and `fill_totp` | REQ-API-007 | 13 |
| 15 | Grant model and request lifecycle | REQ-APR-001, 002, 003, 007 | 9, 8 |
| 16 | Approval channels: CLI socket, ntfy one-time actions | REQ-APR-004, 006 | 15 |
| 17 | Owner web UI with WebAuthn (approvals, grants, audit tail, unlock) | REQ-APR-005 | 15, 7 |
| 18 | Rate limits, suspension, revocation, panic | REQ-RL-001..003, REQ-REV-001..004, REQ-MEM-007 | 13, 15 |
| 19 | Docker image, compose, agent-host guide, canary E2E suite | REQ-DEP-001, 002, 005, 006, 007, REQ-ARCH-001, 004, REQ-GOAL-002 | 13, 16 |
| 20 | Official Bitwarden compat run plus `COMPAT.md` | REQ-DEP-004 | 5 |
| 21 | Export mode loader | REQ-EXP-001..005 | 4, 7 |

Parallelizable from day 1: 2, 3, 8, 11. After 4: 5, 7. Critical path: 1→3→4→5→9→13→18/19.
