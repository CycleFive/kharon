# Agent connector over WebSocket (`/connector`)

Status: design for #199 (part of #197). Builder: Duet. Reviewers: Nyx and
Muse. No code until this is approved (Nyx, `#general` 11-09).

## Why

#206 put kharond and cloudflared on one host with no inbound port. #207 (N1)
packages that, and `kharon.twkr.io/mcp` is live (step 1). MCP calls, grants
and approvals work without a VPN.

**Fills don't yet.** The broker reaches the agent's browser either over
WireGuard (path A) or through `kharon-agent-connector` dialing the
`[connector]` listener with raw pinned TLS on `:8789` (path B). Both need a
network path from the agent host to the broker, which today is the tailnet.
Cloudflare Tunnel carries HTTP and WebSockets, not raw TLS, and Spectrum is
out (#197).

#199 moves path B's dial onto `wss://kharon.twkr.io/connector`, so a hosted
agent with nothing but outbound HTTPS can be filled. That makes #201's
"broker host with no VPN" true.

## Goals

- The connector dials `wss://<public host>/connector` through the same
  Cloudflare Tunnel as `/mcp`, optionally through an HTTP CONNECT proxy, as
  today.
- **What Cloudflare (or any party terminating the outer TLS) can and can't
  do.** It sees TLS ciphertext and frame sizes. It can't:
  - read CDP traffic, which carries filled values;
  - learn the tunnel credential;
  - impersonate the broker to the connector;
  - complete the connector's handshake with a key other than the pinned one.
- Raw pinned TLS on `[connector].listen` stays supported for the tailnet
  path, and the transport is chosen in config. Existing tests keep passing.
- Failures are loud and specific: each log line names the leg that failed,
  never with a secret or a peer's body. A reconnect loop is visible from one
  log line, with the leg named.
- Keepalive survives Cloudflare's WebSocket idle timeout (about 100 s).
  Frames and messages have hard size limits.
- A stranger who reaches `/connector` without a credential can cost us a
  bounded amount of work, and nothing else. Refused credentials for real
  agents are audited, rate-limited.

## Non-goals

- A new mux, credit window or wire version: the inner protocol stays
  connector wire v1, unchanged.
- WebSocket compression (`permessage-deflate`). It is refused: compressing
  ciphertext is useless, and compression oracles are a known class of bug.
- Several agents on one WebSocket, or WebSockets over HTTP/2. cloudflared
  speaks HTTP/1.1 to the origin.
- Moving `/mcp` or any agent API onto the WebSocket.
- Source-address throttling. #200's trusted-proxy helper brings
  `CF-Connecting-IP`; this design uses it for log and audit context once it
  lands, under its contract, and never to gate.

## Anti-goals (failure even if it works)

- Any secret (the tunnel credential, CDP payloads, filled values) readable at
  the edge.
- The connector trusting the outer TLS (WebPKI) for anything but reaching
  the edge.
- An unauthenticated stranger able to evict, block or slow a live agent
  session, or to fill the audit log. Delaying a *reconnect* is bounded and
  named under *Pre-auth budget*.
- A silent reconnect loop.

## The decision: pinned TLS inside the WebSocket

```
agent host                                Cloudflare edge            broker host (one netns)
kharon-agent-connector                                                cloudflared ─▶ kharond
  │ TCP (or HTTP CONNECT proxy)                                                       [public_ingress]
  │ outer TLS ── WebPKI, SNI kharon.twkr.io ─▶ terminates ─ tunnel ─▶ http://127.0.0.1:8790
  │ HTTP/1.1 Upgrade: websocket, Sec-WebSocket-Protocol: kharon-connector.v1    GET /connector
  │ WebSocket binary messages = one opaque byte stream
  │   └─ inner TLS 1.3 ── broker cert pinned (SHA-256 of DER), as on :8789 ──▶ inner TLS server
  │        └─ connector wire v1: auth record (agent id + tunnel credential) ─▶ Hub (Argon2id)
  │             └─ mux frames (OPEN/DATA/CLOSE/PING/PONG) ─▶ broker opens CDP streams
  ▼
127.0.0.1:9222 (Chromium)
```

The WebSocket carries a byte stream. Inside it run the same pinned TLS, the
same auth record and the same mux that `:8789` carries today. Both ends wrap
the WebSocket in an `AsyncRead + AsyncWrite` adapter and hand it to the
existing code:
- the connector side to `connect_pinned` (made generic over the stream);
- the broker side to the `[connector]` `TlsAcceptor` and the `Hub`.

**Why this and not Noise or a bespoke handshake:**
- It reuses the pin check, the credential check, the mux and their tests,
  which are reviewed and in production on the tailnet path.
- It adds no new cryptographic construction or dependency.
- The connector is configured with the same `broker_pin` and the same
  tunnel credential on both transports.
- A review of OQ-14 still changes one place.

**What holds, and why:**
- **Confidentiality.** The inner TLS is end to end: connector to kharond.
  The edge holds the outer TLS keys only. CDP bytes, the auth record and the
  credential exist in plaintext only inside the inner session.
- **Broker authentication.** The connector accepts the inner handshake only
  if the end-entity certificate's SHA-256 matches `broker_pin`. No WebPKI,
  SAN or expiry check, exactly as today. An edge, a DNS change or a hijacked
  tunnel without the broker's private key gets `BadCert`, before any auth
  byte is sent.
- **Client authentication.** It stays the tunnel credential, checked with
  Argon2id by the `Hub`, and sent only after the pinned handshake completes.
- **Replay.** The inner TLS is 1.3 only for this transport. Each dial does a
  full handshake with fresh ephemeral keys:
  - the client keeps no session store, as today, because `connect_pinned`
    builds a fresh config;
  - the server never accepts early data (rustls' default, asserted in a test).

  A recorded session replays nothing. The credential is a bearer secret
  inside a fresh channel, so replay is not where it is exposed; theft from
  the agent host is (see *Threats*).
- **Outer TLS** is transport only. The connector verifies it with WebPKI
  against the system roots, through `rustls-native-certs`, as kharond's own
  outbound TLS does. That way an agent host behind a TLS-inspecting proxy
  works when its CA is in the system store. Accepting an inspecting proxy
  gives it what Cloudflare already has, which is ciphertext.

## `/connector` on the broker

`[public_ingress]` already routes `GET /connector` to a 404 placeholder
(`Admit::Connector`, #198). #199 mounts the upgrade there. These checks run
before upgrading, all cheap:

- **`Upgrade: websocket`, `Sec-WebSocket-Version: 13`, and the subprotocol
  `kharon-connector.v1`.** Anything else gets 400. The subprotocol versions
  the outer binding; the inner `WIRE_VERSION` versions the wire.
- **No `Origin` header.** A request that carries one gets 403. That keeps
  browsers out: no web page can open this socket in someone's browser.
  `/mcp` refuses `Origin` the same way.
- **No compression.** The `Sec-WebSocket-Extensions` offer is ignored.

After the upgrade:

- **Message limits.** Binary messages only; a text message closes the
  socket. Messages and frames are capped at 64 KiB, which is well above one
  inner TLS record (16 KiB plus overhead). Unmasked client frames are
  refused, as RFC 6455 requires. The adapter writes at most one TLS record's
  worth per message.
- **Pre-auth budget.** The inner TLS handshake and the auth record keep the
  existing deadlines: 10 s for the handshake and 5 s for the hello.
  - Today the raw listener's `Semaphore(4)` covers its whole pre-auth phase.
    The WebSocket path gets its own budget, separate from that one: at most
    **8** upgraded sockets that haven't reached `AUTH_OK`.
  - When it's full, a new upgrade gets 503 before the 101.
  - So internet strangers can't starve tailnet path-B dials, and each one
    costs a socket for at most about 15 s.
  - The budget is global, though. A stranger who keeps all 8 slots busy can
    delay a *reconnecting* agent; live sessions are untouched. Mitigations:
    - the short deadlines;
    - a Cloudflare rate-limiting rule on `/connector` (documented next to
      the `/mcp` one);
    - once #200 lands, a per-source cap of 2 pre-auth sockets, keyed on
      `CF-Connecting-IP` (per /64 for IPv6). Keying a throttle is what the
      helper's contract allows; it never gates auth.
- **After `AUTH_OK`**, the session is a `BrokerSession`, exactly as on
  `:8789`. A new session for the same agent replaces the old one (existing
  behaviour). The `Hub` doesn't care which transport the session came from.
- **Shutdown.** `[public_ingress]` drains for at most `PUBLIC_INGRESS_DRAIN`
  on shutdown (#204). The WebSocket task stops with it, and the agent
  reconnects to the next kharond.

### Config

The broker needs the inner TLS key without necessarily listening on
`:8789`.

```toml
[connector]
tls_cert_file = "/etc/kharon/connector.crt"   # the pinned broker key, for both transports
tls_key_file  = "/etc/kharon/connector.key"
listen = "100.64.0.10:8789"   # optional now: raw pinned TLS, the tailnet path
websocket = true              # serve GET /connector on [public_ingress]
```

- `listen` becomes optional.
- `websocket = true` requires `[public_ingress]`.
- At least one of the two must be set, or there's nothing to dial, and
  `--check` says which.
- `[connector]` is still required exactly when some agent uses
  `via = "agent_connector"` (today's rule).
- The names are the builder's call. The shape is the decision.

On the agent host (`connector.toml`):

```toml
transport = "ws"                                  # or "tls" (default, today)
broker_url = "wss://kharon.twkr.io/connector"     # ws only
broker_pin = "<64 hex>"                           # unchanged; the inner cert's pin
agent_id = "assistant"
token_file = "/etc/kharon-connector/tunnel.token"
cdp = "127.0.0.1:9222"
# proxy = "http://proxy.example:3128"             # optional, as today
```

The inner TLS server name is the URL's host. It isn't checked, because the
pin is, as today.

## Keepalive and timeouts

- **Cloudflare closes a proxied WebSocket after about 100 s with no
  traffic.** The mux already sends `PING` every 20 s when idle and drops the
  connection after 90 s of silence. Each `PING` is an inner TLS record and so
  a WebSocket message. That keeps the edge's idle timer reset with margin.
  No WebSocket-level ping is needed, though answering one is harmless and
  required.
- **Cloudflare also drops long-lived WebSockets during edge restarts and
  deploys.** This is normal and takes the reconnect path below. Tests treat
  an outer close as `Disconnected`, not an error.

## Reconnect and backoff: loud by default

Muse saw reconnect loops through a bad proxy leg. Today the agent logs
"connection failed; reconnecting", and `ClientError::Transport { context }`
carries only `tcp`, `tls` or `proxy`, which the main loop then drops.

**Each failure names its leg** in a fixed-text log line, with no secret,
token, credential, proxy body or peer body:

| Leg | Example line (after `kharon-agent-connector: `) |
|---|---|
| DNS | `cannot resolve kharon.twkr.io` |
| TCP | `tcp connect to 104.18.x.y:443 failed (refused)` (the `io::ErrorKind`) |
| proxy | `proxy CONNECT answered 403`, `proxy authentication refused (407)` |
| outer TLS | `outer TLS to kharon.twkr.io failed: certificate not trusted` (a WebPKI error class) |
| upgrade | `websocket upgrade answered 404` (route missing at the edge or kharond), `… 502` (origin down), `… 503` (pre-auth budget full) |
| inner TLS | `broker certificate did not match broker_pin` (today's text), `inner TLS handshake failed` |
| auth | `tunnel credentials refused` (today's text, 60 s wait) |
| session | `session ended after 3h12m (broker closed / edge closed / idle 90s)` |

**Backoff** is exponential with full jitter, from 1 s to a 30 s cap, for
transport legs (DNS through inner TLS). Jitter keeps a Cloudflare reconnect
wave from synchronising every agent. The auth and proxy-auth failures keep
their fixed 60 s. A session that authenticated and lived for at least 10 s
resets the delay, as today.

**Escalation.** If no session has authenticated for **2 minutes**, the
connector logs one summary line, and repeats it every **10 minutes** while
the outage lasts:

```text
no broker session for 2m10s (14 attempts); last failure: websocket upgrade answered 502
```

A supervisor or log alert can key on it. The per-attempt lines above stay at
the normal level, and the summary is the alert.

**`kharon-agent-connector --check`** dials once, walks every leg up to
`AUTH_OK`, prints one line per leg (`ok` or the failure), and exits 0 only
if auth succeeded. It doesn't open CDP. This is the first thing to run on a
"bad proxy leg".

**On the broker**, attach and detach lines name the transport:

```text
agent connector attached: agent=assistant transport=ws peer=127.0.0.1:41822 client=<CF-Connecting-IP once #200 lands>
```

Pre-auth refusals are counted. kharond logs one line per minute with the
counts, rather than a line per stranger:

```text
connector: refused 37 websocket upgrades in the last 60s (budget 12, protocol 25)
```

## Audit of rejected handshakes

#199 says "rejected handshakes audited". Today a refusal is a log line only
(#150): the audit chain records requests, grants, fills and owner actions.
Auditing every refusal from the internet would let anyone grow the hash chain
and the off-host checkpoint stream.

- **A refused credential for a configured agent id** writes one audit entry,
  `connector_auth_fail`, with:
  - `agent_id`;
  - the `transport`;
  - `detail_code` (`unauthorized` or `protocol`);
  - a `suppressed` count.

  The rate is at most **one entry per agent per minute**. Further refusals in
  the window add to `suppressed` on the next entry. An attempt against a real
  agent's tunnel is what the owner wants to see. The bound is the number of
  agents per minute.
- **A refusal for an unknown agent id**, a malformed hello, a failed inner
  handshake or a refused upgrade is **log-counted only** (above). The claimed
  id is unauthenticated input; it isn't written to the audit log or echoed.
- Attach and detach stay log lines (#150's reasoning holds).
- A SPEC change names the event and its bound (see *SPEC and docs*).

## Threats this changes

- **The edge (Cloudflare) can see:** connection times, durations, message
  sizes and the agent host's IP. That's traffic analysis: a fill is visible
  as a burst. It can't see content or the credential, and it can't
  impersonate the broker (pin).
  - It can drop, delay or reset connections, which is denial of service.
  - It can't inject: the inner TLS is integrity-protected.
- **A stolen tunnel credential (from the agent host)** works from anywhere
  now, not only from the tailnet. On the tailnet, a credential alone wasn't
  enough; it also took tailnet membership (`tag:kharon-agent`).
  - **With the credential alone,** an attacker can attach as that agent and
    evict the real session, which breaks fills. Fills don't land in their
    browser: a fill names a `cdp_target_id` in the agent's browser, and the
    attacker's browser doesn't hold those targets.
  - **With the agent's API token as well, or a compromised agent that
    cooperates,** an attacker could aim fills at targets in their own
    browser. The broker would then fill real credentials there, on
    owner-approved origins only, with the page's real origin checked.
  - **This is the main new risk.** The two secrets sit with different users
    on the agent host (the connector's 0400 file, the agent's token), so
    stealing both is a fuller compromise than either alone.
  - **Mitigations:**
    - Grants are already per-origin and owner-approved, and the fill checks
      the page's real origin, so the attacker's browser must actually be on
      the approved site.
    - The attach and replace log lines make an eviction visible.
    - The owner can revoke with `kharon revoke agent` / panic.
    - Credential storage on the agent host is unchanged (a 0400 file).
  - **Proposed for this issue:**
    - A **replace is audited**. When a session evicts a live one for the
      same agent, the connector replacement writes a `connector_replaced`
      audit entry (rate-limited like `connector_auth_fail`).
    - The owner UI's status shows the agent's session start time. A
      flapping or stolen tunnel then shows up where the owner approves.
  - **Not proposed:** binding the credential to a device key (mTLS client
    certs), as follow-up material if review wants it.
- **A stranger** can open up to 8 pre-auth sockets, then gets 503s. Each
  costs at most one inner handshake and one Argon2id check, under deadlines.
  A stranger can't touch a live session, but can delay a reconnecting agent
  while holding the whole budget. See *Pre-auth budget* for the mitigations,
  and the per-source cap once #200 lands.
- **The vault and raw CDP stay unreachable** from the public host. The broker
  is the CDP client. The agent dials only its own loopback (an `OPEN` frame
  with a payload is still a protocol error), and the WebSocket carries the
  mux, never a CDP listener.

## How this maps onto #201

| #201 AC | What #199 provides |
|---|---|
| `fill` succeeds through the WebSocket connector | `transport = "ws"` end to end through `kharon.twkr.io/connector` |
| Restart of kharond and cloudflared: connector reconnects, no stale grants | A WebSocket close takes the reconnect path. N1's holder keeps cloudflared's path across kharond restarts. A kharond restart comes back locked, with grants in memory only (existing) |
| Canary sweep: no canary in Cloudflare-visible traffic | Fills travel only inside the inner TLS. CI proves it with a recording, TLS-terminating relay (below) |
| Owner UI on its own hostname; vault and raw CDP unreachable | `/connector` is the only new public path, and it carries the mux, not CDP |
| Broker host with no VPN | `[connector] websocket = true` with no `listen`. With #210, also no `[api]`. Nothing on the host needs a tailnet |

## Tests (the builder plans the details)

- **Adapter.** The adapter over WebSocket binary messages is tested for:
  partial reads across messages; one write per message and none over the cap;
  a text message closing the socket; an oversize message closing it; close
  frames giving EOF.
- **End to end in process.** Connector `transport = "ws"` → kharond
  `[public_ingress]` `/connector` → fill through the mux, as the path-B tests
  do today over `:8789`.
- **The Cloudflare stand-in.** A relay that terminates an outer TLS (its own
  WebPKI-style cert, trusted by the test client) and forwards WebSocket
  messages both ways, recording every byte it sees:
  - after a fill of a canary value, the recording holds neither the canary
    nor the tunnel credential;
  - a relay variant that also tries to terminate the *inner* TLS with its own
    key gets `BadCert` at the connector, and no auth record is sent (the
    recording holds no credential);
  - a relay variant that flips one byte of inner ciphertext gets a TLS
    alert, and the session drops.
- **Upgrade refusals.** These cases get 400 or 403: no subprotocol, the wrong
  subprotocol, an `Origin` header, the wrong method or path. A full pre-auth
  budget gets 503. A text frame closes the socket.
- **Audit.** A refused credential for a configured agent writes one
  `connector_auth_fail` per minute with a `suppressed` count. An unknown
  agent id writes none. A replace writes `connector_replaced`. No entry and
  no log line contains the credential.
- **Loud failures.** Each leg's failure produces its fixed log line. The
  escalation line appears after 2 minutes, tested with a paused or mock
  clock. `--check` exits non-zero and names the leg.
- **Keepalive.** With shortened intervals under test, an idle session sends
  `PING` inside the interval, and the relay sees a message at least every
  20 s.
- **Regression.** The existing path-B tests over `:8789` pass unchanged.
- **Compose E2E.** Builder's call: a no-VPN fill variant in CI. It would mean
  the fake-edge relaying `/connector` and the agent host dialing it instead of
  `wg`. If it's too heavy for this issue, #201's live run is the proof and a
  follow-up adds the CI variant.

## SPEC and docs

These go in a separate `docs(spec)` PR, reviewed by both Nyx and Muse:

- **REQ-ARCH-002 / OQ-14.** The connector may also run over a WebSocket,
  with the pinned TLS and the wire v1 inside; the outer TLS is transport,
  not trust.
- **REQ-DEP-006 (B).** Under the edge the connector listener is
  `[public_ingress]` `/connector` (consistent with #212's edge clause).
- **The audit vocabulary.** `connector_auth_fail` and `connector_replaced`,
  with their rate bounds.

`docs/deployment.md` (path B and *Public gateway*) and the agent-host guide
(REQ-DEP-005, path B install) gain the `transport = "ws"` setup. The
`^/connector$` route already exists in the tunnel docs. Cloudflare's
WebSockets setting must be on for the zone; it is on by default.

## Order of work

1. This design, reviewed.
2. `kharon-connector`:
   - `connect_pinned` and the acceptor path become generic over the stream;
   - the WebSocket byte-stream adapter;
   - the agent-side `ws` dial (TCP or proxy, then outer TLS, then upgrade);
   - leg-specific `ClientError`s;
   - backoff with jitter, escalation, `--check`.
3. kharond:
   - the `[connector]` config shape;
   - the `/connector` upgrade on `[public_ingress]` with its checks and
     pre-auth budget;
   - the `Hub` takes WebSocket sessions;
   - the audit events;
   - transport in the attach logs.
4. Tests as above, the docs, and then the SPEC PR.
5. #201's live run on our instance. The homelab session moves Muse's
   connector to `transport = "ws"` and retires the tailnet ACL
   (`tag:kharon-agent → tag:kharon-broker:8787,8789`) once fills pass.

## Left to the builder

- Config key names.
- The adapter's buffer sizes.
- The exact log wording, within the leg classes above.
- Whether the WebSocket server comes from axum's `ws` feature or from
  `tokio-tungstenite` over hyper's upgrade. The decision is to use one
  WebSocket implementation in the tree; `tokio-tungstenite` is already there.
- The 8-socket budget and the 2- and 10-minute escalation times, if testing
  says otherwise.
- Whether the compose E2E grows the no-VPN variant now or in a follow-up.
