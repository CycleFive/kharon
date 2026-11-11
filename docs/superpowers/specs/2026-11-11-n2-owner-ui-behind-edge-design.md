# N2: the owner UI behind the edge (#208)

Status: design, for review by Nyx and Muse before any code. Builder: Duet.
Parent: the portable gateway design
([`2026-11-09-portable-gateway-design.md`](2026-11-09-portable-gateway-design.md)
› *New work* › N2). Depends on #200 (merged as `1eb50af`). N3
([`2026-11-10-n3-mcp-oauth-connect-design.md`](2026-11-10-n3-mcp-oauth-connect-design.md))
builds on this.

This document records the calls #208 leaves to the builder. Where it says
"Duet's call", that is an assumption made while working autonomously, not
something the owner decided. The implementation plan is
[`../plans/2026-11-11-n2-owner-ui-behind-edge.md`](../plans/2026-11-11-n2-owner-ui-behind-edge.md).

Revised after Nyx's review of PR #253: D4 and D5 (a request without a usable
`CF-Connecting-IP` has no throttle key and is exempt from the throttle) and D6
(`throttled` entries have their own allowance of 5 a minute).

## What this is for

Today the owner UI only works on loopback: the owner reaches it over an SSH
forward, signs in with a passkey, and unlocks, approves, revokes and panics
from there. A managed customer has no shell on the box, so for them the UI has
to be reachable on its own public hostname (`https://kharon-owner.<domain>`),
through the same Cloudflare tunnel that already carries `/mcp`.

Publishing it changes who can send it requests. On loopback, only the owner
can. On a public hostname, anyone on the internet can. The passkey still
decides who gets in, so this work is about everything a stranger can do
*without* getting in:

- reach the UI through a hostname it was never meant to answer on;
- make the owner's browser send it a request from another site;
- keep the owner from signing in, by filling a table or tripping a limit;
- grow the audit log until the disk fills, which makes every fill fail closed.

## Goals

1. The owner UI works behind the edge on a declared public origin, with the
   listener still on loopback.
2. No unauthenticated request, from any number of sources, can stop the owner
   signing in (#208 AC5, must-have).
3. A stranger's failed attempts are slowed per source, recorded with the
   source address, and can't grow the audit log without bound.
4. Local mode (loopback plus an SSH forward) behaves exactly as it does today.
5. N3 can add its endpoints without reopening any decision here.

## Non-goals

- Changing who the owner is, or adding a second factor. The passkey stays the
  only way in.
- A general request-rate limit on the owner UI. Cloudflare sits in front, and
  the calls a stranger can make without failing are cheap (see D7).
- Multi-tenant anything. One deploy, one owner.
- Automating Cloudflare Access setup. The docs describe it.
- Auditing passkey enrollment. It is a real gap in the managed case and is
  listed under *Follow-ups*, not built here.

## The switch: local mode and public mode

Everything below hangs on one config choice (D1). **Local mode** is today's
behaviour, untouched. **Public mode** is on when `[owner_ui] public_origin` is
set, and only then do the Host check, the stricter Origin rule, the trusted
source address, throttling, the audit ceiling, the `__Host-` cookie and the
optional Access check apply.

| | Local mode | Public mode |
|---|---|---|
| Config | `origin = "http://localhost:8788"` | `public_origin = "https://kharon-owner.example.com"` |
| Listener | loopback | loopback (the edge reaches it by placement) |
| `Host` check | none | must be the public host, else 421 |
| `Origin` on POST | refused if present and different | required and equal on every POST, bar the exemption list |
| Source address | not recorded | `CF-Connecting-IP`, else the TCP peer |
| Throttle | none | 10 failures per 10 min per source |
| Audit of failures | every one | 20 itemized per minute plus 5 throttle trips, the rest counted |
| Session cookie | `kharon_owner` | `__Host-kharon_owner`, `Secure` |
| Access check | n/a | optional |

## Decisions

### D1. Config shape

```toml
[owner_ui]
listen = "127.0.0.1:8788"
public_origin = "https://kharon-owner.example.com"
# rp_id defaults to the public origin's host

[owner_ui.access]                 # optional second line (D9)
team_domain = "myteam.cloudflareaccess.com"
audience = "4f1c…"                # the Access application's AUD tag

[public_ingress]
listen = "127.0.0.1:8790"
public_host = "kharon.example.com"   # optional (D2)
```

- **Exactly one of `origin` and `public_origin`.** Both, or neither, is a
  config error (`owner_ui_origin_choice`). `origin` keeps every rule it has
  today, including origin port = listen port.
- **`public_origin` must be `https`.** A public origin over plain http has no
  use, and `__Host-` cookies need `Secure`. It follows the same shape rules as
  `origin` (no userinfo, path, query or fragment; the host is a domain, not an
  IP, and equals `rp_id`). A non-default port is allowed and kept. The listen
  port is unrelated to it, so port 0 works in tests. Error:
  `owner_ui_public_origin`.
- **`rp_id` defaults to the public origin's host** in public mode. If given it
  must equal that host. A parent-domain RP ID is legal WebAuthn but nothing
  needs it.
- **`[owner_ui.access]` needs public mode** (`owner_ui_access_needs_public_origin`).
  `team_domain` must be a hostname ending in `.cloudflareaccess.com`, and
  `audience` 1–128 ASCII alphanumerics (`owner_ui_access`).
- **`[public_ingress] public_host`** is a bare hostname, optional
  (`public_ingress_public_host`).
- `listen` stays loopback-only in both modes (REQ-DEP-006).

*Duet's call:* `public_origin` as a second key, not a `mode =` switch plus
`origin`. One key that is either present or absent can't disagree with itself.

### D2. Host check

In public mode every request to the owner listener must carry exactly one
`Host` header naming the public host: `host` or `host:port`, where `port` is
the public origin's port (so `kharon-owner.example.com` and
`kharon-owner.example.com:443` both pass). Comparison is ASCII
case-insensitive. This runs first, before routing, before the body is read,
and covers every route including the ntfy redeem routes.

- **Refusal on the owner UI: `421 Misdirected Request`, code `misdirected`.**
  It is the exact meaning, and the only way to see it is to point a hostname
  at the wrong port in the dashboard. An operator debugging that should get a
  clear answer.
- **Refusal on `[public_ingress]`: its existing `404 not_found`.** That
  listener already answers everything it doesn't serve with one uniform 404,
  and a new error code there would change the published API contract.
- Neither refusal is audited or counted. A stranger must not be able to write
  to the log this way.
- `[public_ingress]` checks only when `public_host` is set. It is optional so
  existing deploys and the compose E2E keep working unchanged. N3 can require
  it when `[oauth]` is set, since it needs the resource URL anyway.
- The edge passes the client's `Host` through unless a route sets
  `httpHostHeader`. `deployment.md` says never to set it.

- Both listeners speak HTTP/1.1 only (axum is built with `http1` alone), so
  `Host` is always a header. `deployment.md` says not to set `http2Origin`
  on these routes.

One helper serves both listeners, next to `client_ip` in `api/public.rs`.

### D3. Origin on every POST, and one exemption list

In public mode every POST must carry `Origin` equal to the public origin.
Missing counts as wrong. Today login, register and logout pass with no
`Origin`; in public mode they don't. The refusal is the existing `403 origin`.

**Exemptions live in one named list**, checked by one function:

```rust
/// Routes that take no `Origin` and no Access login, because their caller
/// is not the owner's browser. Each is protected by its own credential.
pub const EDGE_EXEMPT: &[EdgeExempt] = &[
    EdgeExempt::Prefix(OWNER_APPROVE_PREFIX),   // ntfy action POST, single-use 120 s token
    EdgeExempt::Prefix(OWNER_DENY_PREFIX),
];
```

N3 adds `Exact("/oauth/token")` and `Exact("/oauth/revoke")` there and nowhere
else. The list exempts a route from the Origin rule and from the Access check
(D9). It never exempts a route from the Host check.

Local mode keeps today's rule.

**Order of checks in public mode**, each refusing before the next runs:

1. `Host` (421), before the body is read.
2. Access, if configured and the route isn't exempt (403), before the body
   is read.
3. `Origin` on a POST (403).
4. The throttle (429), on the throttled routes.
5. The route's own checks.

### D4. Source address

In public mode the source address of an owner-UI request is `CF-Connecting-IP`
as parsed by #200's `api::public::client_ip`, and the TCP peer when that
header is absent or unusable. In local mode there is none.

Behind the tunnel the TCP peer is always loopback. A request with no usable
header is audited with that peer address but has **no throttle key**: it is
exempt from the throttle (Nyx's ruling on PR #253). If the edge ever strips
the header (Cloudflare offers a "remove visitor IP headers" transform), every
visitor would otherwise share the tunnel's key, and any stranger could lock
the owner out of web sign-in. The owner listener has no peer address today;
this adds it.

It is used for two things only, as that helper's contract requires: the
throttle key (D5), when the edge supplied it, and the `client_ip` field on
`owner_auth_fail` audit entries. It never decides whether a request is
authenticated.

### D5. Throttling failed attempts

Public mode only. Local mode has no throttle.

- **What counts.** A failure on one of six routes: `/owner/login/options`,
  `/owner/login/finish`, `/owner/register/options`, `/owner/register/finish`,
  `/owner/unlock/begin`, `/owner/unlock`. A "failure" is an outcome that
  writes `owner_auth_fail` today **and got past the `Origin` check**: a
  password-shaped body, a bad enrollment code, a missing or bad assertion, no
  session on an unlock route, or a wrong master password.
- **A wrong or missing `Origin` is refused and audited, but never counted.**
  Otherwise any web page the owner visits could make their browser send ten
  cross-site POSTs, which arrive from the owner's own address, and lock the
  owner out of signing in for as long as the page stays open. A page can't
  forge `Origin`, so everything that does count was sent either by the real
  UI or by a client that isn't a browser, from its own address. The throttle
  check runs after the `Origin` check for the same reason.
- **Only an address the edge named is throttled.** The key is a usable
  `CF-Connecting-IP`. A request without one (D4) is not checked, counted or
  cleared, so a stripped header cannot turn D5 into one shared bucket. It is
  still audited (inside D6's ceiling). To keep it visible to operations,
  the daemon prints one warning per process, and `OwnerUi` counts such
  requests; the owner socket's `status` op reports the count as
  `owner_ui_without_edge_address` when a public UI is configured, and
  `kharon status` prints it when it is non-zero.
- **The limit.** 10 failures in a fixed 10-minute window, per source. The
  window starts at the first failure, and `Retry-After` counts to its end. Sources are
  keyed as #200 keys them: an IPv4 address, or an IPv6 /64.
- **What a throttled source gets.** `429 rate_limited` with `Retry-After` on
  those six routes until its window ends. Nothing else is refused: pages
  load, and a signed-in owner can still approve, deny, revoke, panic and log
  out.
- **A success clears the count** for that source (a completed sign-in or
  unlock). An owner who mistypes nine times and then gets in starts fresh.
- **The table is bounded** at 1024 sources. When it is full it first drops
  expired entries, then forgets the entry whose window started earliest.
  Forgetting a count can only un-throttle someone. It can never block anyone.
- **No shared bucket.** #200's `WindowMap` sends new keys to one shared
  overflow window once its map is full. That is right for `/mcp`, where the
  goal is to refuse a flood. Here it would let a stranger with many addresses
  throttle a source they don't control, so this table is separate and forgets
  instead.
- **Recovery** is always the CLI over the owner socket, which this never
  touches, or another network.
- **One list names the throttled routes.** N3 adds `/oauth/token` and
  `/oauth/revoke` to it, with its own definition of a failure there
  (REQ-OAU-008).

Two limits worth stating plainly:
- An attacker with more than 1024 /64s can cycle through them to reset their
  own counts. They gain nothing: each source still gets ten tries, and a
  passkey assertion can't be guessed.
- Someone who shares the owner's address (carrier NAT, an office) can throttle
  that address for ten minutes by failing ten times. Per-source throttling
  can't avoid this. The CLI and a second network remain.

*Duet's call:* unlock failures count even though unlock needs a session,
because AC4 lists them and a stolen session cookie shouldn't buy unlimited
master-password guesses.

### D6. A ceiling on audit entries a stranger can cause

AC3 wants owner auth failures audited with the source address. On a public
hostname that hands a stranger a way to append to the hash-chained log, and a
full disk makes every fill fail closed (`audit_failed`). D5 doesn't bound this:
it never counts a wrong `Origin`, and sources are cheap anyway.

So in public mode at most **20 `owner_auth_fail` entries are itemized per
minute**, across all sources. Twenty, not ten, so that one source running
into its throttle (ten failures) is itemized in full; its `throttled` trip entry has its own allowance (below). Failures past that are still refused, still
counted toward D5, and tallied. The tally is written as `suppressed` on the
next itemized entry, or within 75 seconds by a `suppressed_only` entry from the
daemon's existing 15-second flush tick, and at shutdown. This is the mechanism
#219 built for the connector, applied to one more event.

- It caps log writes. It never refuses a request, so it is not a global
  auth bucket.
- **A failure that got past the `Origin` check on a request with a live
  session is always itemized** and sits outside the ceiling. A stranger
  can't produce one, so they can't grow the log with it, and it is the
  entry that matters most: a wrong master password typed behind a stolen
  session cookie must not be hidden by a flood started for that purpose. D5
  bounds these per source, because everything past the `Origin` check counts.
- **A wrong `Origin` always goes through the ceiling, session or not**
  (Nyx's review). `SameSite=Strict` is per site, not per origin. A page on
  any sibling host under the same registrable domain is same-site, so the
  owner's browser attaches the session cookie to its POSTs. They arrive with
  the sibling's `Origin`, are refused, and D5 never counts them. Itemizing
  them all would give one open tab an unbounded way to grow the log.
- One source sending wrong-`Origin` requests can use the whole itemized
  budget for a minute and crowd out other sources' detail. The ceiling
  still holds and the count is kept.
- The cost: during a flood, a session-less failure of the owner's own (a bad
  assertion, say) may be counted and not itemized. Nothing is lost but the
  detail.
- At most one `suppressed_only` entry is written per closed window.
- When a source trips its throttle, one `owner_auth_fail` with detail
  `throttled` is written, so the log shows the throttle engaging. Trips have
  their own allowance of **5 per window**, outside the 20 (Nyx's ruling on
  PR #253), so wrong-`Origin` noise cannot spend the budget and hide a trip.
  Past 5 they are counted like any other entry. This answers Nyx's note on #208 that public probing is otherwise
  visible only in Cloudflare's logs.
- Worst case under a sustained flood is 26 entries a minute (20, 5 trips and
  one `suppressed_only`): about 37,000 a day, roughly 12 MB. Filling a disk that way takes years, and the operator can add an
  edge rate-limit rule long before.

### D7. Sign-in ceremonies carry their own state (AC5)

**The problem.** `login/options` creates a challenge and stores it in a table
of eight; a new one evicts the oldest. Anyone who can call it can keep
evicting the owner's challenge.

**Why not a per-source table.** Capping each source stops one source. But the
table still needs a global bound, and with many sources that bound is reached:
then either new sources are refused (the owner is blocked) or old entries are
evicted (the owner is evicted). An IPv6 /48 holds 65,536 /64s. AC5 says "from
any number of sources", and a bounded table can't meet it.

**The design: no table.** The server holds a random 32-byte key, made at start
and kept only in memory.

- `login/options` picks a random 32-byte challenge and returns it together
  with a **sealed token**: `base64url(payload) "." base64url(HMAC-SHA256(key, payload))`,
  where the payload is a small typed JSON record: purpose (`login` or
  `register`), expiry, and the challenge.
- The page sends the token back on `finish`, in the same `ceremony_id` field
  it echoes today. The page's JavaScript doesn't change.
- `finish` checks the MAC, the purpose and the expiry, then verifies the
  WebAuthn response against the challenge from the token.
- Nothing is stored at `options`, so there is nothing for a stranger to fill
  or evict.

**Single use.** A captured assertion must not mint a second session. So a
*successful* finish records the token's SHA-256 until the token expires, and a
second finish with the same token is refused. The record is one atomic
"insert if absent" under a single lock, made after the WebAuthn response
verifies and before the session is issued or the passkey stored. Two
concurrent finishes with one captured assertion therefore can't both win.
This set is the only replay guard for synced passkeys, whose signature
counter stays at zero. Only successes are recorded, and
a stranger can't produce one, so a stranger can't fill this set either. It
holds 64 entries. If the owner somehow completes 64 ceremonies in two minutes,
the 65th gets `429`.

**What changes for the owner.** Today a failed `finish` burns the challenge.
Now it doesn't: the same token can be tried again until it expires in 120
seconds. That is safe, because each try is a failure D5 counts and the
challenge alone is worth nothing without the passkey.

**A panic replaces the key** (Nyx's review). `REQ-OAU-005` and `REQ-REV-002`
say a panic clears every pending authorization, and a sealed token can't be
found and deleted. So a panic makes a new key and empties the used-set, which
kills every outstanding token at once: sign-in and enrollment ceremonies in
flight, and N3's pending authorizations. Both panic paths do it, the web
route and the CLI's, and they do it whether or not the panic's own audit
append succeeds, as a panic keeps grants revoked in that case. An owner who
was mid-sign-in during a panic starts the ceremony again.

**The register token is the proof that `register/options` was authorized.**
`register/finish` checks no enrollment code and no session of its own: today
the table row stands for that, and now the MAC and the `register` purpose do.
So a token made for `login` must never open as `register`, and the purpose is
inside the MAC. The enrollment code is consumed at `register/options`
(`registration_authorized` → `take_enroll`), so one code mints one register
token. That check stays at `options`: moving it to `finish` would let one
code be tried against many ceremonies. A failed `register/finish` leaves the token usable until it
expires, so the owner can retry without a new code; a successful one burns
it.

**Details.**
- Expiry is measured in milliseconds since the process started, on the
  monotonic clock. The key dies with the process, so nothing outside it ever
  needs to read the time, and a wall-clock step can't extend a token.
- A restart invalidates in-flight ceremonies, as it does today. So does a
  panic, which is new.
- Enrollment codes, sessions and unlock attempts keep their small tables.
  Filling them needs the owner socket, a completed sign-in, or a live
  session, which a stranger doesn't have.
- `login/options` stays unthrottled for a source with no failures. It costs
  one HMAC and never fails.

**The sealing code is generic over its payload**, because N3 needs the same
thing (next section).

### D8. Cookie

Public mode: `__Host-kharon_owner=…; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=900`.
The `__Host-` prefix makes the browser refuse the cookie unless it is `Secure`,
has `Path=/` and no `Domain`, so a sibling subdomain can't set or shadow it.
Local mode keeps `kharon_owner`.

Moving a deploy from local to public mode changes the RP ID, so the owner
re-enrolls their passkey. That was already true and is in the gateway design.

### D9. Optional Access check

Off unless `[owner_ui.access]` is set. When on, every owner-UI request that is
not on the exemption list must carry a valid `Cf-Access-Jwt-Assertion`:

- exactly one header; three dot-separated parts; `alg` is `RS256` and nothing
  else;
- the signature verifies against the key with that `kid` in the team's JWKS
  (`https://<team_domain>/cdn-cgi/access/certs`);
- `iss` is `https://<team_domain>`, `aud` contains the configured audience,
  `exp` is in the future and `nbf`, if present, is not, each with 60 seconds'
  leeway.

Refusal is `403 access_denied`, audited as `owner_auth_fail` / `access` within
D6's ceiling. It does not count toward D5: it isn't a sign-in attempt.

**Keys.** Fetched on first need, not at startup, so kharond never fails to
start because Cloudflare is unreachable. An unknown `kid`, or a cache older
than 24 hours, triggers a refetch, at most one per 60 seconds. If a refetch
fails the old keys stay in use, so a JWKS outage doesn't lock the owner out.
The fetch has a 5-second timeout, follows no redirects and reads at most
64 KiB.

**The test override can't be set from a file.** The JWKS source is a field of
the validated config (`JwksSource::TeamCerts`, the default, or
`JwksSource::TestStatic(json)`). The TOML schema has no key for it, and unknown
keys are already refused, so no line in `kharon.toml` can select it. Tests
start the daemon in-process and set the field in Rust. Requiring the
`.cloudflareaccess.com` suffix also means a stray `team_domain` can't point
verification at an arbitrary host.

**No new dependency.** RS256 is verified with `aws-lc-rs`, already in the
tree with `ring-sig-verify` (`RsaPublicKeyComponents`), and the fetch uses the
existing `reqwest` with the OS roots, built as the Bitwarden client is.

**Cost to a stranger's flood.** The header's shape, `alg` and `kid` are
checked first, so a token naming an unknown key costs no signature check. One
naming a real key costs one RSA-2048 verification, tens of microseconds. With
Access on, a request with no valid token has also bypassed Cloudflare's own
Access, which the tunnel doesn't allow from outside. The audit write for a
refusal runs on the blocking pool, as every audit append does.

The Access check runs in the async request handler, before the body is read.
It is a second line behind the dashboard's own policy. Signing in still takes
the passkey.

### D10. ntfy approve and deny

In public mode the action URLs in an ntfy prompt are built on the public
origin (`https://kharon-owner.example.com/owner/approve/<token>`), not on the
listen address. The "port 0 means no stable address, so publish nothing" rule
then applies to local mode only.

With Access on, Access would block ntfy's background POST. `deployment.md`
gives the bypass policy for `/owner/approve/*` and `/owner/deny/*`, whose
single-use 120-second tokens already protect them. Those routes are on D3's
list, so kharond's own Access check skips them too.

### D11. SPEC

Rows ship with their code (#protocol), so each implementation PR carries its
own lines. The shape:

- **New `REQ-APR-009`, the owner UI behind the edge:** the public origin, the
  Host check, Origin on every POST with the named exemption list, the source
  address, the throttle, the audit ceiling, sealed ceremonies, the cookie and
  the Access check, each with its acceptance test.
- **`REQ-APR-005`** gains one sentence pointing at it. Its own text stays.
- **`REQ-API-010`** gains the `[public_ingress] public_host` check.
- **`REQ-DEP-006`** names the owner hostname as edge-reached by placement.
- **§7** records `client_ip` and `suppressed` on `owner_auth_fail`, and the
  new detail codes `throttled` and `access`.
- **§2 threat model**, in the last PR and needing both non-author reviewers:
  - §2.1 *Internet stranger* is extended to the owner hostname: what they
    can reach, and that they can add at most twenty itemized audit entries
    a minute.
  - §2.1 gains **Operator (managed deploy)**: trusted exactly as the broker
    host is. They have root, the owner socket and the edge dashboard, so
    they can mint an enrollment code, approve over the CLI, and read memory
    after an unlock. The passkey and Access do not constrain them. What the
    customer keeps is the master password, which is never stored, and the
    ability to see CLI-channel actions in the audit log.
  - §2.3 B4 names both owner paths (the socket by peer uid; the web UI by
    passkey, behind the edge by placement).
  - §2.4 gains the protections above and two limits: a shared source
    address can be throttled by a neighbour, and the edge terminates TLS so
    it sees the session cookie.

### D12. Compose package and docs

- `deploy/compose/kharon.toml.example` turns `[owner_ui]` on with
  `public_origin`.
- The compose README replaces "Owner actions until #208" with: the tunnel
  route for the owner hostname, enrolling the first passkey
  (`docker compose exec kharon kharon passkey-enroll`, then open `/enroll`),
  and the CLI as the fallback.
- `docs/deployment.md` gains the owner-hostname section: never set
  `httpHostHeader`; optional Access and the ntfy bypass; the throttle and how
  to recover; re-enrolling after a change of RP ID. It also says to set
  `[public_ingress] public_host` on any published deploy (Muse's review), so
  the check isn't left off by omission where it matters most.
- The compose E2E gains three fake-edge probes: the login page with the right
  `Host` is 200, a foreign `Host` is 421, a POST with no `Origin` is 403.

## What this changes for N3

N3's design (I1) and `REQ-OAU-003` keep a *pending authorization* "in the
bounded non-evictable ceremony table (#208)". With D7 there is no such table.

**Proposed amendment, in this PR:** a pending authorization is a sealed token
made with D7's code, carried in the consent URL. It holds what the table row
would have held (client, redirect URI, PKCE challenge, state, resource,
scopes), lasts 10 minutes, and is recorded as used when the owner approves
**or denies** (Nyx's review). A deny is a decision: with the table it deleted
the row, and without this a denied request would stay approvable for the rest
of its ten minutes. Deny needs the owner's session, so a stranger can't use it
to fill the used-set.
Every value in it came from the authorize URL in the same browser, so it
needs integrity, which the MAC gives, and not secrecy.

This is strictly stronger than "capped per source": no number of strangers
can block a Connect. It keeps N3's rule that nothing rides in a cookie and
nothing survives a restart.

What N3 takes from D7, and decides for itself:
- **N3's panic path needs nothing of its own for pending authorizations.**
  The key replacement in D7 already ends them, which keeps `REQ-OAU-005`'s
  acceptance line true: a consent page opened before a panic can't be
  approved after it. Unredeemed codes are N3's own state and N3 clears them.
- The consent assertion is a third purpose, `consent`, sealed the same way.
- The used-set is keyed by the token's hash and holds an entry until that
  token expires, so a 10-minute pending authorization holds its slot for up
  to 10 minutes. Only a consent the owner completed is recorded, so 64 slots
  still means 64 Connects in ten minutes. N3 may give itself a separate set.
- The token rides in the consent URL and is about 1 KB. Field and path names
  are N3's.

**Nyx and Muse: this edits reviewed N3 text.** These places change, all in
this PR: N3 design I1 (the pending-authorization bullets), I6 ("its ceremony
table"), D4's note on what lives in memory, D5's panic bullet and follow-up 7
(the panic hook), and D6 step 7 (deny); and in SPEC.md, `REQ-OAU-003` and
`REQ-OAU-005`. Please
check those specifically.

Everything else N3 asked of N2 is here as asked: the public origin, the
`__Host-` cookie, the named exemption list (D3), and per-source throttling
with no global bucket (D5).

## Left to the implementer

Private names inside modules, test helper shapes, the wording of doc comments
and log lines, and the exact README prose. The plan fixes everything that
crosses a module boundary or appears on the wire.

## Follow-ups (not built here)

1. **Passkey enrollment is unaudited.** Minting an enrollment code
   (`passkey_enroll`) and storing a passkey (`register/finish`) write no audit
   entry. On a managed deploy the operator can enroll a passkey of their own
   with no trace. Proposed: two new events. Needs an issue and a §7 row. Duet
   files it when this merges and links it from #208 (Nyx, Muse).
2. **Host check in local mode.** It would close DNS rebinding against the
   loopback listener. The Origin rule and the RP ID already stop the damaging
   cases, and it is outside #208.
3. **Security headers** (`frame-ancestors 'none'`, `X-Frame-Options`) on every
   owner page. N3 adds them to its own pages; doing all of them is small.

## Assumptions

| # | Assumption | If wrong |
|---|---|---|
| A1 | `public_origin` is https-only. | Add an http form; cookies lose `__Host-`. |
| A2 | 421 on the owner UI, 404 on `[public_ingress]`. | One status constant each. |
| A3 | 10 failures / 10 min / source; table of 1024. | Constants. |
| A4 | Unlock failures count toward the throttle. | Drop two routes from a list. |
| A5 | 20 itemized audit entries a minute in public mode, plus 5 throttle trips. | Two constants. |
| A6 | Ceremonies are sealed tokens; N3's pending authorization follows. | A per-source table, which can't meet AC5 as written. |
| A7 | Access refusals are audited but don't count toward the throttle. | One call. |
| A8 | The JWKS test override is code-only, with no TOML key. | A test-named key. |
| A9 | `[public_ingress] public_host` is optional. | Make it required; update compose and E2E configs. |
| A10 | Enrollment auditing is a follow-up, not N2. | Add a task. |
