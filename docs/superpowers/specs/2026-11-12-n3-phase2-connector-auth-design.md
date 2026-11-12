# N3 phase 2: a dashboard runtime's connector authenticates with a Connect token

Status: design, 2026-11-12, for #235. Follow-up 9 of the N3 design
([`2026-11-10-n3-mcp-oauth-connect-design.md`](2026-11-10-n3-mcp-oauth-connect-design.md),
#213, #226), section D7. Builder: Nyx. Reviewers: Muse and Duet.

This note is the phase 2 design D7 deferred. Where it and the D7 sketch
disagree, this note is the one to implement. It confirms assumption A7
(the wire-v1 hello token field carries the Connect access token).

No code and no SPEC change land with this note. Until the implementation
that follows, `POST /oauth/token` keeps refusing `resource` equal to the
deploy's `/connector` URL on every grant, `authorization_code` and
`refresh_token` alike (REQ-OAU-004). A code presented with that resource
is not spent, and a refresh token presented with it is not retired.

Phase 1 is what #274 and #279 shipped, and this note does not reopen it:

- #274 (`c4e8044` via #232): scope bundles on `AgentId`, `tools/list`
  filtered by scope, `insufficient_scope` as a 403 step-up on `/mcp`,
  and `no_browser` for every `c-…` identity before the lock, the rate
  buckets, the grant, and the fill backend.
- #279: an `Authorization` of `kh_at_` or `kh_rt_` is refused on every
  owner surface (REQ-OAU-006 as amended). A session cookie does not
  override it. Nothing in phase 2 exempts a connector-audience token
  from that refusal.

## Why

Phase 1 answers `no_browser`. A Connect can list, search, and request
grants, and it cannot fill, because a `c-…` identity has no browser.
D7's integration milestone is the opposite: the dashboard runtime, which
already holds the customer's browser, runs `kharon-agent-connector`
(#199) for that Connect, and fills go through the pinned inner tunnel
exactly as they do for a config agent.

The customer still clicks Connect and still approves every fill in the
owner UI. They do not install a connector, and they do not see a pin or
a token. That is the target user from #213.

## What this note decides

| # | Question from #235 | Recommendation |
|---|---|---|
| 1 | How the runtime learns the inner key pin | The pin is **provisioned** with the runtime, the same `broker_pin` a tailnet connector has today. The `/connector` protected-resource metadata **publishes** the pin so the runtime can detect substitution or rotation. The runtime never adopts a pin it learned from HTTP. A token-response field is the wrong document for it. |
| 2 | Whether wire v1 suffices | **Wire v1 suffices.** No `WIRE_VERSION` bump, no new hello field, no new server-hello status, no subprotocol change. |
| 3 | Who owns refresh | **Two refresh families, one Connect.** The dashboard backend owns the MCP family and performs one spawn. The runtime owns the connector family and is the only component that rotates it. `kharon-agent-connector` does not become an OAuth client. |

Three things are not decided here. They need Lothrop, and they are
written as open questions at the end rather than as assumptions: the
operational acceptance of provisioning the pin, the consent-screen
words, and the residual that a malicious TLS-terminating edge can use a
connector credential it sees on the token endpoint.

## Goals

1. A Connect that has been granted `kharon:fill` can attach the
   dashboard runtime's browser over `GET /connector`, and fills then
   take the existing CDP path.
2. The tunnel credential is a 1 h access token, audience-bound to this
   deploy's `/connector` URL, scope `kharon:connector`, for that one
   `c-…` identity.
3. A token for `/mcp` cannot open the tunnel. A token for `/connector`
   cannot call `/mcp`, `/v1`, or any owner surface.
4. Config agents, `kh_tunnel_` credentials, raw pinned TLS on `:8789`,
   and the wire-v1 mux are unchanged.
5. Revocation, panic, and refresh reuse drop a live connector session
   for that identity. The session does not outlive the access token
   that authenticated it.

## Non-goals

- A new mux, credit window, or wire version. OQ-14 stands: #199 added a
  carrier, not a second wire.
- Teaching `kharon-agent-connector` to speak OAuth. The binary keeps
  reading a token and dialing. The dashboard runtime is the OAuth client
  for the connector family.
- Dynamic client registration, a new consent scope in
  `scopes_supported`, or a second authorize `resource`. Authorize stays
  `resource` = this deploy's `/mcp` URL (REQ-OAU-003 step 6).
- Sender-constraining the connector token (DPoP, mTLS client auth). The
  threat model says why that does not hold against the edge that
  terminates the token endpoint.
- Multi-tenant. Resource URLs and the pin stay per deploy, as D8.

## Anti-goals

These would make the work a failure even if a fill succeeded.

- Adopting an inner pin from any HTTP response. The edge terminates TLS
  on both hostnames and can rewrite the body. The pin is what stops
  that edge impersonating the broker (REQ-ARCH-002, #199).
- One refresh token rotated by both the backend and the runtime. The
  second presenter trips reuse and kills the Connect (REQ-OAU-004, I5).
- A connector access token that `authenticate_access` accepts on
  `/mcp`. Today that function returns the identity's scopes and stores
  no audience. Phase 2 has to add the audience check before this can
  ship.
- A `kh_at_` hello that takes an Argon2id permit. The public connector
  path is reachable from the internet. Hash lookup only, as on `/mcp`
  (REQ-OAU-008).
- A Connect fill falling back to a configured CDP endpoint when the
  session is down. `no_browser` stays the answer (REQ-OAU-007).
- A wire bump that makes every tailnet connector and the broker move
  on the same day, in exchange for no new bit on the wire.

## Decisions

### D1. The inner pin: provisioned, published, never adopted from HTTP

The pin is the SHA-256 of the `[connector]` end-entity certificate DER,
lowercase hex, 64 characters. `kharon-agent-connector` already requires
it as `broker_pin`. The handshake checks it before the hello, and a
mismatch is `BadCert`: no auth record is sent (#199). That order is
load-bearing, so the runtime has to know the pin before it dials.

#### Option A — a field on the token response

The spawn and refresh responses would carry, for example,
`kharon_connector_pin`. Whoever redeems would forward it to the runtime.

It fails as a root of trust. The token endpoint is on the owner
hostname, and the edge terminates that TLS. N3 already accepts that the
edge sees token responses. Seeing a pin is harmless, because the pin is
not a secret. Rewriting it is not harmless: the runtime would pin the
edge's key, complete the inner handshake with the edge, and send the
access token. That is the impersonation #199 exists to prevent.

It is also the wrong document. The pin is a property of the connector
certificate, not of a grant. It would be repeated on every hourly
refresh, it would arrive only after a token request (the runtime needs
it before the first hello), and it would sit in a JSON body next to
credentials an MCP token store might parse.

#### Option B — protected-resource metadata for `/connector`

RFC 9728 path insertion for `https://<public host>/connector` is:

```text
GET https://<public host>/.well-known/oauth-protected-resource/connector
```

Served on `[public_ingress]` when `[oauth]` is set and `[connector]` has
a certificate to pin. Otherwise 404, so a phase 1 deploy that has not
configured the connector does not advertise one. The document:

```json
{
  "resource": "https://kharon.twkr.io/connector",
  "authorization_servers": ["https://kharon-owner.twkr.io"],
  "scopes_supported": ["kharon:connector"],
  "resource_name": "kharon",
  "kharon_connector_pin": "<64 lowercase hex, SHA-256 of the connector cert DER>"
}
```

`bearer_methods_supported` is omitted. RFC 9728's methods are `header`,
`body`, and `query`. This resource takes the credential in the wire-v1
hello, after the inner TLS, and a metadata lie that said `header` would
send generic clients at a WebSocket with an `Authorization` header.
`kharon_connector_pin` is an extension member. Clients that do not know
it ignore it, which is what RFC 9728 requires.

The document is `Cache-Control: no-store`. A cache must not freeze a
pin across a certificate rotation, and must not freeze a rewritten one
either. `no-store` does not stop the edge rewriting the live response.

This path is a GET. It is not the WebSocket. `admit()` has to send it
to the metadata handler, and `GET /connector` stays the upgrade.

The root document `/.well-known/oauth-protected-resource` and the `/mcp`
document stay as REQ-OAU-001 specifies them. They do not gain the pin
or `kharon:connector`. The MCP 401 keeps pointing at the `/mcp`
metadata.

This is the right publication. It is not a root of trust. The same edge
terminates the agent hostname. An unauthenticated document is the
easiest one to rewrite, and adopting `kharon_connector_pin` from it is
the same impersonation as option A.

#### Option C — operator-provisioned pin (the trust anchor)

When a tenant is stood up, the operator already has the connector
certificate. The dashboard runtime's config for that deploy gets
`broker_pin`, the same value a tailnet `connector.toml` gets. The
customer never sees it and never pastes it. Rotation is an operator
action on both sides: the new certificate and the dashboard's pin move
together.

The runtime fetches option B's document and compares. A mismatch is a
hard stop: it does not dial, and it does not replace its configured
pin with the published one. A failed fetch is not a mismatch. The
runtime dials with the configured pin, because a missing document is
availability and a substituted document is integrity. The edge can
already refuse the connection; a rewritten document must not become a
new pin.

There is no trust-on-first-use. A runtime with no configured pin does
not adopt the published one and does not dial.

#### Recommendation

**C is how the runtime knows the pin. B is how it checks that knowledge.
A is not used.**

The chicken-and-egg is the point of the pin. The inner TLS is the only
channel the edge cannot rewrite, and the runtime cannot have that
channel until it has the pin. So the pin's first hop cannot be an HTTP
response from either hostname. DPoP or a signature on the metadata does
not remove the hop: the edge that terminates the registration can
substitute its own key, and the runtime cannot detect that without a
trust anchor it already holds. That anchor would be another provisioned
pin. This design provisions the pin itself and stops there.

Whether the dashboard will store a per-deploy pin is open question Q1.
Kharond's half does not depend on the answer: it publishes the pin and
never treats HTTP as the root of trust.

### D2. Wire v1 suffices

The client hello (connector crate, wire v1) is magic `KHCN`, version
`1`, a `u16` agent id, and a `u16` token string. The token cap in the
codec is 512 bytes. The auth body cap is `AUTH_MAX` (1024). A Connect
access token is `kh_at_` plus 64 hex characters, 70 bytes. A Connect id
`c-<10 lowercase base32>` matches the hello's agent-id grammar
(`[a-z0-9-]{1,64}`), the same grammar REQ-OAU-003 already relies on.

The server hello is magic, version, and a status: `AUTH_OK`,
`AUTH_UNAUTHORIZED`, `AUTH_PROTOCOL`. The codec rejects a status above
2. The subprotocol stays `kharon-connector.v1`. The mux, the ping
interval, and the frame caps are untouched.

The broker tells the two credentials apart by prefix, after the inner
TLS and after the hello parses, the way `/mcp` tells `kh_agent_` from
`kh_at_`:

1. A malformed hello is `AUTH_PROTOCOL`. It names no agent id, so it is
   not audited. Unchanged.
2. A token that starts with `kh_at_` takes the OAuth path. SHA-256
   lookup, no Argon2id permit. The rules are D4. Every failure is
   `AUTH_UNAUTHORIZED`. The detail code is audit-only (see Audit).
3. A token that starts with `kh_rt_` is `AUTH_UNAUTHORIZED` with no
   Argon2id permit and no OAuth lookup. A refresh token is not a
   session credential, and it must not be able to spend the Argon2id
   permits the pre-auth budget exists to protect.
4. Anything else takes today's tunnel path, Argon2id permit included.
   `kh_tunnel_` behavior, including the connector binary's fixed 60 s
   wait on `AUTH_UNAUTHORIZED`, is unchanged.

`WIRE_VERSION` stays 1 because an auth body that carries a `kh_at_`
token is still readable as v1. The crate's rule is to bump when a body
or a frame stops being readable as v1, not when the broker learns a
second prefix. A bump would be a flag day for every tailnet connector,
and OQ-14 would become two wires. Old brokers treat a `kh_at_` hello as
a bad tunnel credential and answer `AUTH_UNAUTHORIZED`, which is the
right failure until this design is implemented.

A new status byte, for "refresh and retry" against "this Connect is
dead", would be a protocol change. `read_server_hello` treats a status
above 2 as a protocol error, so every current binary would jitter-retry
it and not understand it. The runtime already knows whether the token
it just wrote should have worked (D3). The wire does not need to say it.

What would force a later bump: a new hello field, a token longer than
512 bytes, or a status the peer has to parse. None of those is this
design. Opaque `kh_at_` / `kh_rt_` tokens stay inside the 512-byte cap.
An implementation that switches the access token to a JWT, or appends a
proof, has left this note.

**A7 is confirmed.**

### D3. Refresh ownership: two families, the runtime rotates only its own

A Connect has one refresh rotation today. Presenting a retired refresh
token kills the whole Connect (REQ-OAU-004, I5). Two components that
both refresh the same token will kill it, including a legitimate
backend and a legitimate runtime that each thought they were the
holder. That constraint decides the shape.

#### Option A — the runtime holds the MCP refresh token and refreshes both audiences

The backend's MCP client also has to refresh, or `/mcp` dies at one
hour. Two holders, one family. Rejected.

#### Option B — the backend holds the only refresh token and pushes connector access tokens

The runtime would hold a 1 h tunnel credential and nothing long-lived,
which matches REQ-ARCH-001's "the connector holds only a tunnel
credential" more closely than a 90-day refresh token does.

The minting path that makes this work is token exchange: the backend
presents the current `/mcp` access token and receives a `/connector`
access token. That path is rejected. N3 accepts that the edge sees
`/mcp` access tokens on every call and on the token endpoint. If those
tokens can be exchanged for a tunnel credential, the edge can open the
tunnel. Audience separation would be cosmetic. The same rejection
applies to "refresh the MCP family with `resource=/connector` and hand
the runtime the access token": that rotation also turns the MCP
credential, which the edge already sees, into the tunnel credential,
and it fights the MCP client's own refresh.

#### Option C — two families (recommended)

The MCP family is born at code redemption, unchanged: `resource` is the
deploy's `/mcp` URL, the access token's audience is `/mcp`, and the
refresh token is the one the dashboard's MCP client stores. Code
redemption with `resource` equal to the `/connector` URL stays
`invalid_target`, and the code is not spent.

The connector family is born later, by a grant the MCP client will not
send:

```text
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:kharon:oauth:grant-type:connector
&refresh_token=<live MCP-family refresh token>
&client_id=<the Connect's CIMD URL>
&resource=https://<public host>/connector
```

RFC 6749 §4.5 wants an extension grant type to be a URI. This one is
only meaningful to a kharon-aware caller. `grant_types_supported` gains
it and keeps `authorization_code` and `refresh_token`. A stock MCP
client does not send a grant type it does not implement, and so it will
not store this response in place of its MCP tokens. That is the reason
for a separate grant rather than a `resource` switch on
`refresh_token`: an MCP library that echoed `resource=/connector` and
then replaced its stored refresh token with the response would lose the
MCP family and start presenting the connector one.

Spawn rules, checked in this order, with `client_id` first (a mismatch
is `invalid_grant` and is not reuse, as `refresh` already does):

1. `resource` is the deploy's `/connector` URL, and `[connector]` has a
   certificate. Anything else, including a missing connector config, is
   `invalid_target`. The presented refresh token is not retired.
2. The presented token is a live MCP-family refresh token for that
   client. A connector-family refresh token, an access token, an
   expired or revoked token, or an unknown token is `invalid_grant`.
   Nothing is retired.
3. The identity's granted scopes include `kharon:fill`. A read-only
   Connect gets `invalid_grant` and no family. There is nothing for a
   browser to do.
4. No connector family exists yet. The presented MCP refresh token
   stays live. The response is a normal token response,
   `Cache-Control: no-store`: `kh_at_…` audience `/connector`, scope
   exactly `kharon:connector`, `expires_in` 3600, and a new `kh_rt_…`
   that is the connector family's refresh token. Audit
   `oauth_connector_grant` before the persist (below).
5. A connector family already exists. Within 30 s of that spawn, one
   retry is a lost-response grace: it revokes the access token and
   retires the refresh token of the pair just issued, and issues a new
   pair, the same shape as I5's one retry. That retry is a rotation,
   not a second grant, so it does not write another
   `oauth_connector_grant`. A further spawn is `invalid_grant`. The
   Connect stays up, the MCP family stays live, and the latest
   connector family stays as it is. Two lost spawn responses are
   recovered by Disconnect and a new Connect, not by killing a healthy
   MCP client.

The backend is the mailman for that one response. It forwards the
connector refresh token, the connector access token, and the `c-…` id
to the runtime over the dashboard's own channel, and it does not write
them into the MCP token store. After that forward, the backend does not
present the connector refresh token again. If it does, and the runtime
also presents it, reuse kills the Connect. That failure is the
enforcement. There is no cryptographic binding of a refresh token to a
process.

From then on the runtime is the only refresher of the connector family.
It uses ordinary `grant_type=refresh_token`, `client_id` set to its own
CIMD URL, `resource` set to the deploy's `/connector` URL. That rotates
only the connector family and returns a new connector-audience access
token plus a new connector refresh token. I5's 30 s one-retry grace
applies inside the family: the superseded pair is retired, access token
included, and a second presentation of the same retired token is reuse
of the **whole Connect**, both families, the live session, and
`oauth_refresh_reuse`. A stolen connector refresh token means that
client is compromised. Leaving the MCP family alive would keep a
compromised runtime's tool access up after we had noticed.

The other direction is the same rule. Reuse of the MCP refresh token
kills the connector family and drops the session too. One client, one
Connect.

A refresh that names the wrong resource for its family is
`invalid_target`, and the presented token is not retired:

| Presented refresh token | `resource` | Result |
|---|---|---|
| MCP family, live | absent, or the deploy's `/mcp` URL | Today's rotation. New access token's audience is `/mcp`. Connector family untouched. Phase 1 clients that omit `resource` keep working. |
| MCP family, live | the deploy's `/connector` URL | `invalid_target`. Not a spawn. Spawn is only the extension grant. |
| Connector family, live | the deploy's `/connector` URL | Rotate the connector family only. |
| Connector family, live | absent, the `/mcp` URL, or anything else | `invalid_target`. Token not retired. |
| Either family, retired, outside its grace | the resource that family mints | Reuse. Whole Connect ends. |
| Either family, retired, inside 30 s, grace unused, successor live | the resource that family mints | One retry, that family only. |

Rotation does not revoke the previous access token of that family,
except on the grace retry, which revokes the superseded access token.
That is how MCP access tokens already work in `oauth_store::refresh`.
The runtime may attach with the new access token while the old one is
still inside its hour. Both can complete a hello. The later session
replaces the earlier one.

`kharon-agent-connector` reads the token once, at process start, and
holds it. The runtime refreshes, writes the new access token the way
`token_file` is written today, and starts a new process (or an
implementation adds a reload the binary does not have yet). The new
process dials, and the new session replaces the old. The binary does
not learn the owner hostname, `client_id`, or refresh. The runtime
refreshes at `expires_in - 5 minutes`, or immediately when the
remaining life is already under 5 minutes. Five minutes is the lead
that absorbs a slow token request. It is the runtime's clock, taken
from `expires_in`, not a second expiry the server trusts.

On `AUTH_UNAUTHORIZED` for a token the runtime has just minted, the
runtime stops. It does not adopt the tunnel binary's 60 s retry loop
with a dead token. A process left running on a dead token will retry,
and the audit rate limit bounds the damage; the runtime is what shuts
it down. That policy lives in the runtime because the wire does not
grow a status for it (D2).

### D4. What the broker checks, and what a token is

An access-token record gains an audience: `mcp` or `connector`. A
refresh-token record gains the family it belongs to, the same two
values. A missing audience on a state file written by phase 1 means
`mcp`, so `oauth/state.json` from a deploy that has not seen phase 2
loads, and every existing access token stays an `/mcp` token. Tokens
remain SHA-256 hashes at rest. No plaintext, no new store.

`kharon:connector` is not a consent scope.

- It is not in the AS metadata `scopes_supported`, and not in the `/mcp`
  resource metadata. Absent `scope` on authorize keeps meaning the three
  bundles in REQ-OAU-003. A client that asks for `kharon:connector` at
  authorize fails step 7 (`invalid_scope`) and is redirected, as any
  unknown scope is.
- It is not stored on the identity. The identity's scopes stay
  `kharon:read`, `kharon:fill`, and `kharon:request`.
- It is the scope of a connector-audience access token, and the only
  scope that token carries. The token response says
  `scope=kharon:connector`. An MCP refresh response keeps returning the
  identity's granted scopes.
- It is issued only when the identity holds `kharon:fill` (D3).
  Unticking fill at consent is what refuses the browser path.

The connector hello, for a `kh_at_` token, after the prefix dispatch:

1. Hash lookup. Unknown, not an access token, expired, revoked, or the
   identity revoked: `AUTH_UNAUTHORIZED`, audit detail `unauthorized`
   when the claimed id is auditable.
2. Audience is not `connector`: detail `audience`. This is the `/mcp`
   token presented to the tunnel.
3. `hello.agent_id` is not the token's identity: detail `identity`.
4. The token's scope does not include `kharon:connector`: detail
   `scope`. A token this design issued will not fail here. The check
   stays so a record that lost its scope fails closed.
5. Otherwise `AUTH_OK`. The session is bound to that identity and to
   the access token's stored `expires_at`.

`/mcp` is the mirror, and it is a 401, not a step-up. A connector
audience presented to `authenticate_on_mcp` is `invalid_token`. It is
not `insufficient_scope`. A step-up would invite the MCP client to
re-authorize with `kharon:connector` added to its tool scopes, which is
the confusion this split exists to prevent. The 401 keeps the existing
`WWW-Authenticate` for the `/mcp` resource. `/v1/*` keeps refusing
`kh_at_` entirely (N3 I3).

Owner surfaces keep #279's refusal for every `kh_at_` and `kh_rt_`,
audience irrelevant. The gate matches the prefix. Phase 2 must not grow
an exemption for connector tokens.

Spawn's audit ordering follows the issue side of I5, not the revoke
side. Append `oauth_connector_grant`, then persist the new family, then
answer. A failed append answers 500 and stores nothing. A failed
persist rolls the in-memory family back (the snapshot refresh already
uses), answers 500, and appends a best-effort compensating
`oauth_connector_grant` with `result = persist_failed` and
`detail_code = persist_failed`. That compensation is not
`oauth_disconnect`: the Connect is still there. Hourly refresh stays
unaudited (A12).

### D5. The session, expiry, and `no_browser`

`AUTH_OK` registers the session on the hub for the `c-…` id, the same
`insert` a config agent uses. A second session for that id replaces the
first and shuts it down. In-flight CDP on the old session dies. A fill
that was between `fill_dispatch` and its outcome takes the existing
abort path (`fill_aborted`). Phase 2 does not change grant consumption
or REQ-APR-008.

The hub remembers `expires_at` from the token record, the server's
timestamp, not anything in the hello. The token is opaque and carries
no expiry the client could assert. A timer drops the session when that
timestamp passes, and the fill path treats a session past `expires_at`
as absent even if the timer has not run. There is no grace past
`expires_at`. A runtime that refreshed at the five-minute lead has
already replaced the session by then, so a healthy attach does not fill
across the drop. A runtime that failed to refresh holds the tunnel only
until the token's hour, and then fills answer `no_browser` again.

`require_browser` changes from "every Connect" to "a Connect with no
live, unexpired connector session". The check stays where #274 put it:
after the scope gate, before the lock, the rate buckets, the grant, and
the fill backend. A Connect whose session is down does not fall through
to a configured endpoint. Config agents are not consulted here.
`kharon_status`, `kharon_list`, `kharon_search`, and
`kharon_request_grant` do not need the session.

An ordinary lock leaves the session up, as D4 leaves the Connect up. A
locked vault cannot fill anyway, and unlock should not require a fresh
attach. Panic, Disconnect, `revoke agent`, `/oauth/revoke` of a refresh
token, code reuse, and refresh reuse all end the Connect through the
existing `end_connect` path, and that path also shuts the live
connector session for the identity. Panic shuts every Connect session.
The next hello with any token of that identity is `AUTH_UNAUTHORIZED`.

The Connections page (#233) shows whether that identity has a live
connector session, and since when, from the hub. It shows no pin and no
token. The first attach stays a log line, as #199 left attach. The
page is how the owner sees "a browser is attached" without an audit
entry per attach.

## Threat model and failure modes

This extends N3's threat model and #199's. The actors are unchanged.
The new capability is that a Connect's browser is the dashboard
runtime, reached over the public `/connector` WebSocket.

**The edge, passive.** Unchanged from #199. On the connector WebSocket
it sees sizes and timing. The inner TLS still hides the hello, the
access token, CDP, and filled values. A relay that presents its own
inner key still gets `BadCert` before any auth byte, provided the
runtime is using its provisioned pin (D1). A rewritten metadata
document that does not match the pin is a refusal to dial, which is a
denial of service the edge can already cause by dropping the socket.

**The edge, malicious, on the token endpoint.** Open question Q3. N3
accepts that the edge sees access and refresh tokens, and says CDP
stays inside the inner TLS so the edge never sees page contents or
filled credentials.
Phase 2 puts a connector refresh token on that same token response,
hourly. An edge that rewrites HTTP can do more than read it:

- It can copy the connector refresh token, refresh first, and return an
  error to the runtime. Reuse detection does not fire, because the
  runtime never presents the retired token. The edge holds the new
  family.
- It can open its own `/connector` session with the new access token.
  The pin does not stop a client. The pin stops a fake broker.
- If the owner then approves a fill, the filled values are written into
  the browser at the other end of that session, which is the edge's.

Bounds this design does put on that residual, and why they are the
ones that hold:

- An `/mcp` access token cannot be exchanged for a connector token
  (D3, option B rejected). The edge sees `/mcp` tokens on every tool
  call. Those must not be tunnel credentials. Stealing the tunnel
  requires the connector family, which appears only on the spawn
  response and on connector-family refreshes.
- The access token dies at `expires_at`, and the session dies with it
  (D5). A stolen access token, without the refresh token, cannot hold
  the tunnel past its hour, including when the legitimate runtime is
  down. That is the case a session that lived until disconnect would
  get wrong.
- The legitimate runtime's re-attach replaces the attacker's session.
  `connector_replaced` records it, under the existing per-agent
  per-minute bound.
- Disconnect, panic, and reuse drop the session (D5).
- The pin is not taken from the edge (D1), so the edge still cannot
  impersonate the broker to the real runtime, and the real runtime
  still will not send its token to the edge's inner key.

Sender-constraining does not close this residual, and it is not in the
design. DPoP or a client certificate registered at spawn time is
registered over the same terminated HTTP. The edge can substitute its
own key in that request and pass the runtime a token bound to the
substituted key. Detecting the substitution needs a trust anchor the
runtime already has. D1 spends that anchor on the pin. A second
provisioned key, plus a hello proof, would be a wire change for a
threat the pin does not cover, and this note does not half-specify it.

**Expiry mid-session.** The server drops the session at the token's
stored `expires_at`. The runtime's five-minute lead is what makes a
healthy hour a replace rather than a drop. If the refresh fails, the
old session continues until `expires_at`, then `no_browser`. The MCP
family is not affected. An in-flight fill on the dropped session aborts
as D5 says.

**Revocation.** Disconnect, `revoke agent`, refresh reuse, panic, and
code reuse end the tokens and the session together. A hello after that
is `AUTH_UNAUTHORIZED`. Owner surfaces still refuse the bearer (#279).
Grants still drop through `connect_ended` (REQ-REV-001).

**Audience confusion.**

- A live `/mcp` token in the hello: `AUTH_UNAUTHORIZED`, detail
  `audience`, no session, no Argon2id permit. Fills stay `no_browser`.
- A live `/connector` token on `POST /mcp`: 401 `invalid_token`, the
  `/mcp` challenge, not 403 `insufficient_scope`.
- A `/connector` token on the owner UI, the ntfy listener, or the owner
  socket: #279's 403, 410, or `forbidden` / `unlock_failed`. Unchanged.
- A refresh or a spawn that names the wrong resource: `invalid_target`,
  and the presented refresh token is not retired (D3's table).
- Code redemption with the `/connector` resource: `invalid_target`,
  code not spent. Unchanged, including in the implementation. The
  connector family is never born from a code.

**Identity mismatch.** A valid connector token with another id in the
hello does not attach. Detail `identity`. The session that belongs to
the token's real identity is left alone.

**Replay.** The inner TLS is 1.3, with no early data and a fresh
handshake per dial (#199). A captured hello does not replay. Presenting
a live access token on a new dial is a new session, and it replaces the
old one. That is use of a bearer, bounded by `expires_at` and by
revocation, the same shape as a stolen `kh_tunnel_` credential. Refresh
reuse is the replay that kills the Connect. The 30 s grace is one
retry per rotation per family, and one retry per spawn.

**Two refreshers.** The backend and the runtime both present the
connector refresh token. The second presentation, outside the grace, is
reuse. The Connect ends, the session drops, `oauth_refresh_reuse` is
written, and the customer clicks Connect again. Loud on purpose.

**Spawn race.** Two spawns: one wins, one is the grace retry or
`invalid_grant`. The MCP refresh token is not retired either way. A
third spawn does not kill the Connect (D3).

**Argon2.** A flood of `kh_at_`-shaped hellos, after inner TLS, is a
hash lookup under the existing pre-auth slot budget and deadlines. It
does not take the shared Argon2id permits those deadlines protect.
Unknown prefixes on the tunnel path still do, as today.

**Compromised dashboard.** Intended capability, named so it is not a
surprise: the runtime is the browser. A connector credential plus an
owner approval deposits a fill into that browser, on the live origin,
under the existing origin check (REQ-ORG-002). Phase 1 could request
the fill and could not receive it. Disconnect remains one click
(REQ-OAU-005). A stolen MCP access token, without the connector family,
still cannot attach.

**Clock.** Expiry is the server's stored unix time. The runtime's lead
uses `expires_in` from the token response. The server does not extend
a session because the runtime's clock is behind.

## Audit

No new free-form field (N3 I7). Tokens and pins never appear in an
entry or a log line. #200's redaction already covers `kh_at_` and
`kh_rt_`.

**`connector_auth_fail`** keeps its event, its transport, its
per-(agent, event) 60 s window, and its `suppressed` count. Phase 2
adds two things.

The claimed id is auditable when it is a configured agent, as today, or
a Connect identity in the store, revoked included. Any other claimed id
stays a count in the once-a-minute log line. A stranger does not grow
the chain by inventing `c-…` ids. Those ids are 50 bits, and a miss
writes nothing.

`detail_code`, in check order, sharing one window so a burst cannot
multiply entries:

| Detail | When |
|---|---|
| `unauthorized` | No live connector access token for the presented value. Today's tunnel refusals stay this detail. |
| `audience` | The token is live and its audience is not `connector`. |
| `identity` | Audience matches, and the hello's agent id is not the token's identity. |
| `scope` | Audience and identity match, and the token does not carry `kharon:connector`. |

`agent_id` on the entry is the claimed hello id, as #199 specified. The
token's real identity is not a second field.

**`connector_replaced`** is unchanged, including the hourly re-attach.
One entry an hour per attached Connect is the eviction signal #199
added, and the rate bound still collapses a flap inside a minute.
Scheduled rotation and a stolen-token eviction look the same on the
wire (the new token is also live, D4). The Connections page is the
"browser attached" signal; this event is the "something replaced the
session" signal. Token issue and refresh stay unaudited, one by one
(A12).

**`oauth_connector_grant`** is new, written once per successful spawn
and on the persist-failure compensation (D4). `agent_id` is the `c-…`
id. `origin` is the CIMD hostname. No channel: the client's own
request, like `oauth_connect`. No token, no pin. `result` is `issued`
or `persist_failed`.

**`oauth_refresh_reuse`** and **`oauth_disconnect`** are unchanged.
Ending the connector family because the Connect ended does not grow a
second event. An expiry drop is the existing detach log line, not an
audit entry.

## What the implementation changes

This note changes none of it. The list is the map for the follow-up.

| Component | Change |
|---|---|
| `POST /oauth/token` | The extension grant, the per-family `resource` rules, audiences on new records. Code redemption's refusal of `/connector` stays. |
| `oauth/state.json` | Audience on token records. Missing means `mcp`. |
| Connector hello | Prefix dispatch. `kh_at_` never takes an Argon2id permit. |
| Hub | Session `expires_at`, drop at expiry, `end_connect` and panic close Connect sessions. |
| `require_browser` | `no_browser` only when a Connect has no live, unexpired session. |
| `authenticate_on_mcp` | Connector audience is 401, before scopes. |
| `[public_ingress]` | `GET /.well-known/oauth-protected-resource/connector` when `[oauth]` and a connector certificate are both set. The tunnel path allow-list in `docs/deployment.md` gains that path. |
| AS metadata | `grant_types_supported` gains the extension grant and keeps the two it has. |
| Connections page | Live session, and since when. |
| Owner surfaces | No change. #279's refusal covers the new tokens because they are still `kh_at_` / `kh_rt_`. |
| `kharon-agent-connector` | No OAuth. A reload of `token_file` is allowed and not required. |
| SPEC | The rows below, in the implementation PR, not in this one. |

SPEC rows the implementation adds or amends:

- **REQ-OAU-004** — audience stored on the access token; the extension
  grant; refresh `resource` per family; `/connector` on
  `authorization_code` still refused and the code still unspent; a
  missing audience in an older state file means `/mcp`.
- **REQ-OAU-007** — `no_browser` when a Connect has no live unexpired
  connector session; still no fallback to a configured endpoint; a
  session does not skip the scope gate.
- **REQ-OAU-009** (new) — the hello rules, the pin publication and the
  "never adopt" rule, session expiry, and the refusal of a connector
  token on `/mcp`.
- **REQ-ARCH-002** — a `kh_at_` of audience `connector` is a tunnel
  credential on wire v1. `kh_tunnel_` is unchanged. The inner pin is
  still what the client checks.
- **§7** — `oauth_connector_grant`, and the new `connector_auth_fail`
  detail codes. The auditable-id rule covers a known Connect id.
- **REQ-OAU-001** — the connector protected-resource document, and the
  statement that the `/mcp` and root documents do not carry the pin.
- **REQ-OAU-006** — one sentence that a connector-audience token is
  still refused on every owner surface. No new exemption.

## Test plan and acceptance

The implementation is accepted when the following hold. Names are the
suites to extend or add; the builder can split files, not assertions.
No assertion logs a token, a refresh token, or a pin's private key.
The pin's hex may appear in the metadata assertion, because it is
public.

**Metadata (`req_oau_009`).** With `[oauth]` and a connector
certificate, `GET /.well-known/oauth-protected-resource/connector`
returns the document in D1, `Cache-Control: no-store`, and
`kharon_connector_pin` equals the SHA-256 of that certificate's DER.
The `/mcp` document and the root document are byte-for-byte the phase 1
documents. Without a connector certificate the connector document is
404. `GET /connector` is still the WebSocket upgrade, not this
document.

**Code grant, unchanged.** `authorization_code` with `resource` equal
to the `/connector` URL is `invalid_target`, and a following redemption
with the `/mcp` URL still succeeds. The code was not spent.

**Spawn.** A live MCP refresh token, `kharon:fill` granted, the
extension grant, the connector resource: response scope is
`kharon:connector`, the access token is refused on `/mcp` with 401, and
the MCP refresh token still rotates afterward with `resource` omitted.
A second spawn inside 30 s returns a new pair and the first connector
access token no longer authenticates a hello. A third is
`invalid_grant`, and the second pair still works. A Connect without
`kharon:fill` gets `invalid_grant` and no family. A spawn that presents
the connector refresh token is `invalid_grant`, and that token is not
retired.

**Family isolation.** Refreshing the connector family does not retire
the MCP refresh token, and the reverse. Each wrong-resource cell of
D3's table is `invalid_target` with the presented refresh token still
live. A phase 1 state file with no audience field still authenticates
its access token on `/mcp`.

**Reuse.** Presenting a retired connector refresh token outside the
grace writes `oauth_refresh_reuse`, rejects the MCP refresh token, and
drops a live session for that id. Inside the grace, one retry rotates
again and the superseded connector access token is refused. A second
presentation inside the 30 s is reuse.

**Hello (`req_arch_002` and `req_oau_009`).** A connector access token
and a matching `c-…` id reach `AUTH_OK` on the WebSocket path and on
raw TLS, and a following fill or context call reaches the CDP stub
where a phase 1 Connect would have been `no_browser`. The same token
on `/mcp` is 401, not 403 `insufficient_scope`, and the body is not a
200 tool result. An `/mcp` access token in the hello is
`AUTH_UNAUTHORIZED` with audit detail `audience`, and the tunnel
verifier (`TokenStore::authenticate_for`) is not called. The fill stays
`no_browser` with the fill backend uncalled. A `kh_rt_` in the hello is
`AUTH_UNAUTHORIZED` with detail `unauthorized`, and it does not call
the tunnel verifier either. The right token with the wrong agent id is detail
`identity` and does not evict a session that belongs to the token's
real id. An expired token does not attach. A session attached with a
token whose `expires_at` has passed does not fill, even if the socket
is still open.

**Wire version.** The hello round-trips through `write_client_hello` /
`read_client_hello` with `WIRE_VERSION == 1`. No new status byte is
written.

**Config agents.** A `kh_tunnel_` credential still attaches, still
takes Argon2id, and still fills. A Connect session does not satisfy a
config agent's CDP lookup, or the reverse.

**Revocation.** Disconnect and panic close the session. The next hello
fails. The same `kh_at_` on every owner-UI route, the ntfy path, and
the owner socket still fails as REQ-OAU-006 states (#279's tests keep
passing, and one of them is repeated with a connector-audience token).

**`no_browser` order.** A Connect with `kharon:fill` and no session:
context, fill, and fill-totp are `forbidden` / `no_browser`, backend
untouched. A read-only Connect calling `kharon_fill` is still
`insufficient_scope`, and that still precedes `no_browser`.

**Pin.** The existing relay test still holds: a TLS terminator's
recording of a fill contains neither the canary nor the access token,
and a relay that presents its own inner key gets `BadCert` with no
hello on the recording. One new assertion: the metadata pin equals the
certificate the successful client pinned. The "do not adopt a
mismatch" rule is the runtime's; kharon's test is that the published
pin is the real certificate's, not that a client library obeys it. The
dashboard's integration test owns the adopt-never assertion, and the
implementation issue should say so rather than stub it inside kharond.

**Audit.** An `audience` refusal for a known `c-…` writes one
`connector_auth_fail` per minute with that detail and a `suppressed`
count, and the token is absent from the entry and the log. An unknown
id writes none. Spawn writes one `oauth_connector_grant` and no token.
A persist failure writes the compensating `persist_failed` result and
leaves the MCP refresh token live. A replace writes
`connector_replaced` as today.

**Relay, in process.** This is the acceptance bar for "the edge does
not see the credential on the WebSocket". A compose job is not
required on top of it if this test runs under `cargo test`. The
recording assertion is the one above.

## Open questions for Lothrop

These are not decided. Reviewers should not treat a recommendation as
his answer. None of them changes the token endpoint, which keeps
refusing `/connector` until an implementation he has accepted.

**Q1. Provisioning the pin.** D1's recommendation is that the dashboard
runtime is given `broker_pin` out of band, operator to operator, when
the tenant is stood up, and that the customer never sees a pin. The
alternative he might want — a dashboard that can attach with nothing
provisioned except the Connect — needs a trust anchor in the dashboard
build and a design this note does not contain. Kharond can publish the
pin either way. Please confirm that storing the pin in the dashboard's
per-deploy config is acceptable.

**Q2. Consent-screen words.** The recommendation is to change nothing
the customer reads. `kharon:fill` already says the dashboard may ask to
sign in, and that every sign-in is approved in kharon. `kharon:connector`
is not a checkbox and not a fourth bundle. Unticking fill is what
refuses the browser. If the screen should name the dashboard's browser
in its own sentence, that sentence is his. This note does not draft it.

**Q3. A malicious edge that steals the connector refresh token.** The
recommendation is to accept the residual in the threat model: a passive
edge still sees no CDP, and a malicious edge that rewrites the token
endpoint can become the browser, with every fill still owner-approved.
Rejecting the residual means phase 2 does not ship on the public token
endpoint. There is no other token path in the managed model. Please
confirm the residual is accepted. Until he does, this question stays
open, and the implementation should not treat N3's sentence "the edge
never sees page contents or filled credentials" as still literally true
of a malicious edge.

## Assumptions

The design's call, for Muse and Duet to overturn. They are not
substitutes for Q1–Q3.

- **A1.** The extension grant type is `urn:kharon:oauth:grant-type:connector`. Advertising it does not remove `authorization_code` or `refresh_token` from AS metadata.
- **A2.** Spawn's lost-response grace is 30 s and one retry, the same window as I5. A further spawn is `invalid_grant` and does not end the Connect.
- **A3.** Reuse of either refresh family ends the whole Connect and the live session.
- **A4.** The runtime refreshes at `expires_in - 5 minutes`. The server drops the session at `expires_at` with no extension.
- **A5.** `kharon:connector` is a token scope, not a consent scope, and it is issued only together with `kharon:fill`.
- **A6.** A missing audience in `oauth/state.json` means `mcp`.
- **A7 (of this note, not N3's A7).** The connector binary does not speak OAuth. Restarting it with a new `token_file` is a sufficient re-attach. N3's A7, the wire-v1 token field, is confirmed in D2.
- **A8.** `connector_replaced` is written for the hourly re-attach. The Connections page, not a new event, is what shows "browser attached".
- **A9.** An ordinary lock does not drop the connector session. Panic does.
- **A10.** Metadata fetch failure is not a pin mismatch. The runtime dials with the configured pin. A fetched pin that differs is a refusal to dial.
