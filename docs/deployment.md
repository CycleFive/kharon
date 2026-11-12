# Deploying kharon

kharon runs on two machines (SPEC §3.3, option (a)):

- **Broker host.** Your hardware. It runs kharond and, if you
  self-host, Vaultwarden. It holds the vault credentials and the
  decrypted items while unlocked.
- **Agent host.** Where the agent and its Chromium run. It is
  partially trusted (SPEC §2): the agent may be curious or
  compromised, but root on this host is not. It holds no vault-secret-bearing
  kharon binary or config and no vault credential (REQ-ARCH-001).

kharond reaches the agent host's Chromium over CDP through an
authenticated tunnel and fills forms there. Two transport classes
(SPEC §3, REQ-ARCH-002 / REQ-DEP-005):

- **(A) WireGuard / mTLS** — broker dials the agent host (capable hosts).
- **(B) Agent-initiated connector** — the agent host dials the broker
  over outbound HTTPS/TLS; CDP rides the reverse path (egress-shaped
  hosts: no UDP egress / no `CAP_NET_ADMIN`).

The agent keeps its own CDP session to the same browser; kharond
never hands it the filled values (see the harness policy below for
what the agent should not read back from the page).

```
 Path (A) — WireGuard
 broker host (10.66.0.1)                      agent host (10.66.0.2)
 ┌──────────────────────┐   WireGuard   ┌──────────────────────────────┐
 │ kharond ─────────────┼───────────────┼─▶ cdp-relay ─▶ 127.0.0.1:9222│
 │ Vaultwarden          │               │                Chromium      │
 │ owner CLI            │               │ agent ──────▶ (user browser) │
 └──────────────────────┘               └──────────────────────────────┘

 Path (B) — agent-connector (egress-shaped)
 broker host                                  agent host
 ┌──────────────────────┐   TLS (agent    ┌──────────────────────────────┐
 │ kharond ◄────────────┼──── dials out) ─┼─ connector ─▶ 127.0.0.1:9222│
 │ Vaultwarden          │                 │                Chromium      │
 │ owner CLI            │   HTTPS API ◄───┼─ agent ────▶ (user browser) │
 └──────────────────────┘                 └──────────────────────────────┘
```

## Broker host

Start from the Compose example in
[`deploy/compose`](../deploy/compose/README.md). It runs kharond
from this repository's image beside cloudflared, with the vault the
customer already has: their own Bitwarden Password Manager on
Bitwarden cloud, unlocked by the customer, with the keys held only in
memory. A self-hoster can add the `vaultwarden` profile instead. The
agent API exists only when `[api]` is configured. Under path (A) it
binds to the WireGuard address only; under path (B) it binds to a
TLS-capable listen address the agent reaches over outbound HTTPS
(REQ-DEP-006).

### Audit checkpoints off-host (REQ-AUD-002)

By default kharond pushes a signed audit checkpoint to the
`[approval].ntfy` topic every 100 entries or 10 minutes (and once
more at shutdown), so truncating the local audit log is detectable
against a stream the broker host does not control. Point
`[approval].ntfy` at an ntfy server you trust (self-hosted is fine)
and keep the topic access-controlled; `token_file` supplies the
bearer token when the topic requires one, and startup refuses to
run if a configured token file cannot be read. The checkpoint
stream is one JSON checkpoint per ntfy message — save it (ntfy
server logs or a subscriber) and feed it to
`kharon audit verify --data <data_dir>/audit --checkpoints <file>`.
`--data` takes the audit directory (it holds `audit.jsonl` and
`keys/`), not `<data_dir>`.

Setting `[audit] checkpoint_local_only = true` instead keeps
checkpoints in `<data_dir>/audit/checkpoints.jsonl` and logs a
startup warning. That is a temporary pilot posture, not the
release one: nothing leaves the host, so a host compromise can
rewrite both the log and its checkpoints.

### The kharon account and its master password (REQ-DEP-007)

On a managed deploy the customer runs the `init` step below on their own
machine and creates the account themselves: whoever runs `kharon init`
sees the password.

kharond logs in to a dedicated Bitwarden account with an API key and
reads one organization (SPEC OQ-5). The API-key file sits on the
broker host. Anyone who gets that file and a copy of the server's
data (a backup, a compromised Vaultwarden) can fetch the account's
encrypted keys and is then left with an offline attack on its
master password. So the master password must be long and random,
not something a person chose:

1. Generate it with `kharon init`, in an interactive terminal on
   any machine that has the CLI, for example from the Compose
   example's image:

   ```sh
   docker compose build kharon
   docker run --rm -it --entrypoint kharon kharon:local init
   ```

   It prints a 160-bit password (32 base32 characters in groups of
   four) to the terminal once. It never writes it to stdout, a file
   or a log, and it refuses to run without a terminal.
2. Create the kharon account with that password.
3. Store the password in your own vault, outside the kharon
   organization. kharon does not keep it, and the API key cannot
   recover it.
4. Create the kharon organization and collection, then create the
   account's API key and save it as
   `deploy/compose/secrets/kharon_bw_api_key.json`. Give it to
   kharond's uid (REQ-DEP-008):

   ```sh
   sudo chown 10001:10001 deploy/compose/secrets/kharon_bw_api_key.json
   sudo chmod 0400 deploy/compose/secrets/kharon_bw_api_key.json
   ```

   Without Swarm, Compose mounts a `secrets:` file as a bind mount
   that keeps the host file's owner and mode. It ignores a secret's
   `uid`, `gid` and `mode` (with a warning). kharond runs as uid
   10001, so a `0400` file owned by your own uid is unreadable to it,
   and `--check` and startup refuse with `config error
   [api_key_file]: … not readable by kharond (euid 10001; …)`.

### Agent tokens (REQ-API-003)

Each agent has one bearer token, `kh_agent_<id>_<64 hex>`. kharond
stores only its Argon2id PHC hash (`token_hash`). Mint the token on
any machine that has the CLI, in an interactive terminal, for
example from the Compose example's image:

```sh
docker compose build kharon
docker run --rm -it --entrypoint kharon kharon:local token mint assistant
```

The command prints the token once, to the terminal only, and writes
the `token_hash` to stdout: one line beginning `$argon2id$`. Paste
that line into `[agents.assistant]`. Put the token in the agent's
own secret store. kharon does not keep either, and the command
refuses to run without a terminal.

With a terminal and stdout redirected, the hash goes to the file and
the token stays on the terminal:

```sh
kharon token mint assistant > assistant.token_hash
```

Do not redirect a `docker run -it` session the same way: Docker's
tty is the client's stdout, so the redirect would capture the token
too. Copy the hash by hand from that session.

Provisioning is out of band. The daemon is not running yet and is
not contacted, so this mint does not append `token_create` to the
audit log (SPEC §7). `kharon revoke agent` still appends
`token_revoke` while the daemon is running.

Revocation and suspension are durable (REQ-REV-001, REQ-RL-002):
both live in the audit log and are rebuilt at every daemon start,
so restarting the daemon clears neither. A revocation is bound to
the fingerprint of the agent's `token_hash` at revoke time. To
restore a revoked agent, rotate its token — mint a new one as
above, replace `[agents.<id>] token_hash` with the new hash, and
restart; the new token authenticates and the old one stays
refused. There is no un-revoke operation. A suspension (five
consecutive `origin_mismatch` fills) likewise survives restarts
and clears only when the owner runs `kharon unsuspend <id>`; that
reset is itself a log entry, so it survives restarts too.

The hash must meet the production Argon2id floor (m = 19456 KiB,
t = 2, p = 1). `kharon token mint` uses that floor. A weaker
`token_hash` is refused at startup (`token_hash_weak_params`).

### The broker's WireGuard peer

Give the broker host a WireGuard interface at `10.66.0.1` with the
agent host as its only peer:

```ini
[Interface]
Address = 10.66.0.1/32
PrivateKey = <broker private key>

[Peer]
PublicKey = <printed by provision.sh on the agent host>
AllowedIPs = 10.66.0.2/32
Endpoint = <agent host>:51820
PersistentKeepalive = 25
```

The agent host listens on UDP 51820, so the broker dials it and the
agent host needs no address for the broker. If the broker should be
the one listening, set `BROKER_ENDPOINT` when you run
`provision.sh` and drop `Endpoint` here.

kharond binds `10.66.0.1`. If it binds it on the host rather than in
a bridge-network container, add the input filter in
[Tunnel-only listeners](#tunnel-only-listeners-req-dep-006).

### Pointing kharond at the browser

Give kharond the agent host's CDP address through the tunnel, with no
path:

```toml
[agents.assistant]
cdp = { endpoint = "ws://10.66.0.2:9222", via = "wireguard" }
```

Chromium serves its DevTools socket at `/devtools/browser/<id>` and
picks a new `<id>` each time it starts. kharond asks
`http://10.66.0.2:9222/json/version` for the current one every time it
connects, so a restart of the agent host's `browser.service` needs no
config change: the next fill reconnects to the new browser. kharond
takes only the path from Chromium's answer and keeps the configured
address and transport, so the answer can never send kharond to
another host.

To check the tunnel by hand:

```sh
curl -s http://10.66.0.2:9222/json/version | jq -r .webSocketDebuggerUrl
# ws://10.66.0.2:9222/devtools/browser/<id>
```

A full `ws://10.66.0.2:9222/devtools/browser/<id>` endpoint still
works and is used as written, but it goes stale when Chromium
restarts.

### Path (B) broker (agent connector)

Use this when the agent host can open outbound TCP/TLS and nothing
else (no UDP, no `CAP_NET_ADMIN`). The broker grows two TLS listeners,
both on a specific address, never `0.0.0.0` or `::` (REQ-DEP-006):

- `[api]` — the agent API, HTTPS, bearer agent token. Plain HTTP on a
  non-loopback address is refused when any agent uses
  `via = "agent_connector"`.
- `[connector]` — the raw TLS accept the connector dials. Different
  port from `[api]`. Same certificate is fine.

On the broker host, mint a tunnel credential. It is not an agent API
token and cannot call `fill`:

```sh
kharon tunnel mint assistant
```

The credential is printed on the terminal only. stdout is one Argon2id
line: `connector_token_hash`. Put that line in the broker config. Copy
the credential into a file on the agent host (mode `0400`); do not put
it in the broker config and do not give it to the connector as an
agent API token.

```toml
[agents.assistant]
token_hash = "<kharon token mint stdout>"
connector_token_hash = "<kharon tunnel mint stdout>"
cdp = { endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }

[api]
listen = "203.0.113.4:8787"
tls_cert_file = "/etc/kharon/tls.crt"
tls_key_file = "/etc/kharon/tls.key"

[connector]
listen = "203.0.113.4:8789"
tls_cert_file = "/etc/kharon/tls.crt"
tls_key_file = "/etc/kharon/tls.key"
```

kharond reads both files as its own uid. With the Compose example,
bind-mount them read-only and give the private key to uid 10001 with
mode `0400`, as with the API key file (step 4 of
[the kharon account](#the-kharon-account-and-its-master-password-req-dep-007)):

```yaml
# docker-compose.override.yml
services:
  kharon:
    volumes:
      - ./tls/tls.crt:/etc/kharon/tls.crt:ro
      - ./tls/tls.key:/etc/kharon/tls.key:ro
```

```sh
sudo chown 10001:10001 tls/tls.key && sudo chmod 0400 tls/tls.key
```

`203.0.113.4` stands for the broker's reachable address. A self-signed
certificate is enough: the connector pins the SHA-256 of the
certificate's DER, and it does not use WebPKI or the certificate's
expiry. The agent process that calls the API has to trust the same
certificate (its own CA bundle or pin). The owner UI stays on loopback.

```sh
openssl x509 -in /etc/kharon/tls.crt -outform DER | sha256sum
```

The hex digest is `BROKER_PIN` on the agent host. Build the connector
on a machine that has this repo, not on the agent host:

```sh
cargo build --release -p kharon-agent-connector
```

The binary is `target/release/kharon-agent-connector`. Copy it and the
tunnel credential file to the agent host, then follow path (B) under
Agent host. Open inbound TCP `8787` and `8789` on the broker only. The
agent host accepts nothing. If kharond binds a host address, also add
the input filter in
[Tunnel-only listeners](#tunnel-only-listeners-req-dep-006).

kharond still reads `/json/version` on each connect, over the
connector, so a Chromium restart needs no config edit.

#### Over WebSocket, through the public gateway (#199)

When the agent host cannot reach the broker on a raw TCP port (no VPN,
no open inbound port), the connector can dial
`wss://<public host>/connector` through the Cloudflare Tunnel
instead (see [Public gateway](#public-gateway-197-198)). Inside
WebSocket binary messages it runs the same pinned inner TLS, the same
auth record and the same mux, so the edge carries only ciphertext. On
this path the inner TLS is 1.3 only; the raw `:8789` listener keeps
its TLS version set.

```toml
[connector]
tls_cert_file = "/etc/kharon/tls.crt"         # the pinned key, both transports
tls_key_file  = "/etc/kharon/tls.key"
websocket = true                               # serve GET /connector on [public_ingress]
# listen = "100.64.0.10:8789"                  # optional: also keep the raw pinned-TLS listener
```

- With the Compose example nothing is mounted at `/etc/kharon/tls.crt`
  and `tls.key`: bind-mount them with the `docker-compose.override.yml`
  shown under Path (B) above (read-only, key `0400`, uid 10001).
- `websocket = true` requires `[public_ingress]`; kharond refuses to
  start without it (`connector_websocket_needs_public_ingress`).
- `listen` is optional. Set at least one of `listen` and
  `websocket = true`, or there is nothing for the connector to dial
  (`connector_no_transport`). Behind the tunnel on a Compose
  deployment, leave `listen` out: nothing needs a raw port.
- An existing raw-TLS path-B config (`listen` set, `websocket`
  absent, default `false`) keeps working unchanged.
- `[connector]` is still required exactly when some agent uses
  `via = "agent_connector"`.
- `BROKER_PIN` is the SHA-256 of the `[connector]` certificate's DER,
  as above, not of anything Cloudflare presents. The pin is the
  authentication of the broker; the outer TLS to Cloudflare is only
  transport.

The upgrade is accepted only for `GET /connector` with
`Upgrade: websocket`, `Sec-WebSocket-Version: 13`, a
`Sec-WebSocket-Key` and the subprotocol `kharon-connector.v1`. A
missing or wrong item gets 400, any `Origin` header gets 403, and a
full pre-auth budget (8 sockets that have not authenticated yet,
separate from the raw listener's) gets 503. Compression is never
negotiated. The first inner bytes must look like a TLS ClientHello or
the socket is closed.

A socket has one pre-auth deadline: 10 seconds from the moment it takes
a pre-auth slot (before the 101) to the start of its credential check,
covering the upgrade, the inner TLS handshake and the hello; a raw
listener socket gets 15 seconds from accept. At most 2 Argon2id
credential checks run at once, counted across both transports. A check
that cannot start before the deadline closes the socket with no
answer, so a legitimate agent sees a disconnect and retries with
jitter. On the WebSocket path it is counted as `auth`; the raw listener
prints `agent connector busy: credential check did not start in time`
(not audited, because no credential was refused). On the agent a busy
close shows as `auth: connector protocol error`; that line can mean the
broker's credential check could not start in time (a busy broker), not
only a version mismatch. Every WebSocket socket frees its pre-auth slot
by its deadline. A refusal's closing answer (the server hello that says
why) gets at most 1 second after the slot is freed, so a peer that never
reads cannot hold anything longer.

A Cloudflare Worker or Transform Rule must not add an `Origin` header
to `/connector`, or every upgrade gets 403.

kharond writes log lines, not one per stranger:

```text
agent connector attached: agent=assistant transport=ws peer=127.0.0.1:41822
agent connector detached: agent=assistant transport=ws peer=127.0.0.1:41822 after=3600s
connector: refused 37 websocket connections in the last 60s (budget 12, protocol 10, hello 5, tls 4, auth 6)
```

The last line appears at most once a minute, plus once at shutdown for
the last partial minute, and only when something was refused. A refusal on the WebSocket path is counted, never logged
one by one: `budget` is a full pre-auth budget (503), `protocol` a bad
upgrade request, `hello` a first inner record that is not a TLS
ClientHello, `tls` an inner TLS handshake that failed or timed out, and
`auth` a hello record that was malformed or timed out, a tunnel
credential that was refused, or no Argon2id permit coming free before the
deadline. (The raw `[connector].listen` listener still
logs `agent connector refused a credential` once per refusal.) Two events are audit entries (`kharon audit verify`
covers them), each at most once per agent per minute, with a
`suppressed` count for the events folded into the next entry, or into a
`suppressed_only` summary:

- `connector_auth_fail`: a hello named a configured agent id and the
  tunnel credential was refused. Fields: `agent_id`, `transport`
  (`tls` or `ws`), `detail_code` (`unauthorized`) and `suppressed`.
  Unknown agent ids and junk are only counted in the log line above
  (`auth`).
- `connector_replaced`: a new session evicted a live one for the same
  agent. Fields: `agent_id`, the new session's `transport`,
  `old_session_secs` and `suppressed`. Unexpected replacement means
  someone else holds the tunnel credential: mint a new one. First rule
  out your own `kharon-agent-connector --check`: a successful check
  authenticates, so it replaces the running connector's session (a fill
  in flight fails) and writes one `connector_replaced`.

When a window closes with events still folded in and no later event
arrives, kharond writes a summary entry for them: the same event with
`agent_id`, `suppressed` and `result = "suppressed_only"`, and no
`transport`, `detail_code` or `old_session_secs`. Closed windows are
flushed every 15 seconds, so a count reaches the log within 75 seconds of
a burst's last written entry (one 60 s window plus one tick). At shutdown
every window with a pending count is flushed, open ones too.

Both appends are best effort; a failed append is logged and never
blocks authentication.

### Tunnel-only listeners (REQ-DEP-006)

kharond refuses a wildcard bind, and `ss -ltn` shows the agent API
(and `[connector]`) on one address only. On Linux that alone does not
make a listener tunnel-only. Linux follows the weak host model: it
accepts a packet for any local address, whichever interface it
arrives on. A host on the broker's LAN that adds one route
(`ip route add 10.66.0.1/32 via <broker LAN address>`) reaches the
listener without the tunnel, and so does any container on the broker
host. The bearer token still guards the API, but the "only through
the tunnel" layer is gone. Whether you have to close it depends on
where kharond binds:

- **kharond in a container on a Docker bridge** (the VPN overlay's
  `wg` network, `compose.vpn.yml`; the base Compose example binds
  loopback inside the holder's namespace and needs no filter): Docker Engine 28 and later already drop
  packets for a container address that arrive on any other interface,
  with one `raw` PREROUTING rule per container
  (`ip daddr <container> iifname != "<bridge>" drop`). Nothing to add.
- **kharond on a host address** (Compose with `network_mode: host`,
  or kharond installed on the host): add an input filter that drops
  traffic to the listen address unless it arrives on the tunnel
  interface or loopback.

Use a table of its own, so Docker's rules and anything else in the
ruleset survive (no `flush ruleset`). Add one line per listen
address. Under path (A) the interface is `wg0`. Under path (B) it is
the interface the agent's connection arrives on, for example
`tailscale0` when the listen address is a tailnet address.

```nft
# /etc/kharon-guard.nft
# The first line creates the table if it is missing, so the delete
# never fails and `nft -f` replaces the table in one transaction.
table inet kharon_guard
delete table inet kharon_guard
table inet kharon_guard {
	chain input {
		type filter hook input priority filter - 10; policy accept;
		ip daddr 10.66.0.1 iifname != { "wg0", "lo" } counter drop
	}
}
```

`iifname` matches by name, so the rule loads before `wg0` exists.
Load it at boot, before the network comes up:

```ini
# /etc/systemd/system/kharon-guard.service
[Unit]
Description=kharon broker: agent API answers only on the tunnel (REQ-DEP-006)
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/kharon-guard.nft
ExecReload=/usr/sbin/nft -f /etc/kharon-guard.nft
ExecStop=/usr/sbin/nft delete table inet kharon_guard

[Install]
WantedBy=sysinit.target
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now kharon-guard.service
```

Then check it with a **negative probe**. `ss` cannot show this. From
another host on the broker's LAN:

```sh
sudo ip route add 10.66.0.1/32 via <broker LAN address>
curl -m 3 -sS -o /dev/null -w '%{http_code}\n' http://10.66.0.1:8787/   # must time out
sudo ip route del 10.66.0.1/32 via <broker LAN address>
```

From a container on the broker host
(`docker run --rm busybox nc -z -w 3 <listen address> 8787` must
fail), and with `sudo nft list table inet kharon_guard` the drop
counter must have gone up. The same request through the tunnel still
gets an HTTP answer (`401` without a token).

### ntfy approve and deny (REQ-APR-004, REQ-DEP-006)

Under the Compose package the owner UI is published on its own
hostname (see [Publishing the owner UI](#publishing-the-owner-ui)), and
in public mode the action URLs are built on that public origin. What
follows describes the loopback address, which is what a host-networked
kharond in local mode uses.

`GET` and `POST` on `/owner/approve/<token>` and `/owner/deny/<token>`
are served on the owner UI listener, `[owner_ui] listen` (loopback).
Configure `[owner_ui]` or kharond has no HTTP listener for them. The
agent API (`[api] listen`) leaves those paths unrouted.

An ntfy `http` action is the POST the ntfy client sends when the owner
taps it. The action URL's host is that owner listen address:

```text
http://127.0.0.1:8788/owner/approve/<token>
http://127.0.0.1:8788/owner/deny/<token>
```

`8788` is whatever `[owner_ui] listen` uses. Loopback is reachable from
the broker host: open the ntfy web app there, or forward the owner port
to the device that taps the action (an SSH local forward to the broker
host's owner port). Publish that port on the broker host's loopback
when a forward needs it. The agent API address (`[api] listen`, which
is the `wg` address only with the VPN overlay) is not the owner
address; the action URL uses the owner listen address.

Inside Compose the process binds `127.0.0.1` in the holder's
namespace. A published host port does not reach it, and neither does
an SSH forward on the host. Use the public origin there: with
`[owner_ui] public_origin` set, the action URL is
`https://kharon-owner.example.com/owner/approve/<token>`, and
`/owner/approve/*` and `/owner/deny/*` are the routes the separate
bypass application leaves open (step 5 of the Access section below).

In public mode an action URL works from anywhere, and its single-use
token is the only credential. Whoever can read the ntfy topic can
approve a pending request from the internet within its 120 seconds. Use
a topic only the owner can read: an ntfy access token (`token_file`),
and a reserved or self-hosted topic, never a guessable public one.

The owner unix socket remains the CLI channel (`kharon unlock`,
`kharon approve`). It does not speak this HTTP.

The publisher (#128) emits exactly those absolute action URLs. When
a grant request is created and both `[approval].ntfy` and
`[owner_ui]` are configured, kharond publishes one message to the
ntfy topic naming the agent, the item and the origin observed at
request time, with single-use Approve / Deny `http` actions (POST)
on the URLs above. Publishing is best-effort and off the grant path:
a dead ntfy server never blocks or fails a request, which stays
pending for the CLI and web UI channels. `kharon panic` publishes a
plain notice (no actions) to the same topic. With no
`[approval].ntfy` nothing is published and the CLI path is
unchanged; with no `[owner_ui]` there is no redeem listener, so
nothing is published either. In local mode, an `[owner_ui] listen`
port of 0 (ephemeral, a test shape) likewise publishes nothing — the
action URLs need the stable configured address. In public mode they
are built on `public_origin`, so the port does not matter.

## Publishing the owner UI

This section is for the operator. It puts the owner's web UI (passkey
sign-in, unlock, approve and deny, panic) on its own public hostname,
through the same Cloudflare tunnel as the gateway, so the owner needs no
shell on the box. kharond's owner listener stays on loopback; the tunnel
reaches it because cloudflared shares kharond's network namespace.

The examples use `kharon-owner.example.com`. Use a hostname of its own,
not a path under the gateway hostname.

This needs cloudflared running beside kharond, in the same network
namespace (the compose package does this). A tunnel on a separate guest
cannot reach the loopback owner listener. Stopping cloudflared, as in
Rollback below, also takes the owner UI offline.

### Two modes

The config key decides which mode the UI runs in:

- **Public mode**, `public_origin = "https://kharon-owner.example.com"`:
  for a published UI. It checks the `Host` header, requires a matching
  `Origin` on every POST, throttles failed sign-ins per address, caps how
  much a stranger can write to the audit log, and uses a `__Host-`
  session cookie.
- **Local mode**, `origin = "http://localhost:8788"`: the loopback UI
  reached over an SSH forward. None of the checks above apply.

Exactly one of the two keys is allowed (`owner_ui_origin_choice`).
Set `public_origin` to publish; it is the only way to run the published
UI. **Never point a tunnel route at a UI configured with `origin`.**
Local mode has no Host check, no `Origin` requirement, no failure
throttle and no audit ceiling, so a stranger could write to the audit
log without limit and fill the disk. The public URL does not load as
local mode anyway: `origin = "https://kharon-owner.example.com"` with
`listen = "127.0.0.1:8788"` is refused at startup (`owner_ui_origin`,
because local mode wants `rp_id` to be that host, and it defaults to
`localhost`; with `rp_id` set it is refused as `owner_ui_origin_port`,
because the origin's port must equal the listen port). kharond's
startup line says which mode it is in: `owner UI listening on
127.0.0.1:8788 (public origin https://…, behind the edge; …)` in public
mode, `(origin …; …)` in local mode.

### Steps

1. **Config.** In `kharon.toml`:

   ```toml
   [owner_ui]
   listen = "127.0.0.1:8788"
   public_origin = "https://kharon-owner.example.com"
   ```

   `listen` must be a loopback address. `public_origin` must be `https`
   and a bare hostname (no path, no IP address). `rp_id`, the name
   passkeys are bound to, defaults to its host; if you set it, it has to
   match.

2. **Gateway Host check.** In the same file, set `public_host` under
   `[public_ingress]` (see
   [the `[public_ingress]` listener](#kharond-the-public_ingress-listener)).
   Do this on any published deploy.

3. **Tunnel route.** In the Cloudflare dashboard, go to Networking,
   Tunnels, your tunnel, Routes, Add route, Published application.
   Hostname `kharon-owner.example.com`, leave the path empty, and set
   **Service URL** to `http://127.0.0.1:8788`. Leave the additional
   application settings empty. In particular:

   - **Never set `httpHostHeader`** (the "HTTP Host Header" setting).
     It rewrites the `Host` the browser sent, and kharond refuses any
     `Host` that is not the public hostname.
   - **Never set `http2Origin`** ("HTTP/2 to origin", under TLS).
     kharond speaks HTTP/1.1 only, so cloudflared's HTTP/2 to it fails.

   The dashboard creates the proxied DNS record.

4. **Cloudflare settings that break the throttle.** Do not turn on the
   "Remove visitor IP headers" Managed Transform, and do not add a
   header rule that removes `cf-connecting-ip`, on the owner hostname.
   The throttle keys on that header. Without it a request is still
   served and still audited (with the tunnel's loopback address), but it
   is not throttled. See "Watching it" below.

   Also leave Cloudflare features that rewrite HTML or challenge
   requests (Rocket Loader, Bot Fight Mode) off for the owner hostname
   until tested: the page's script and the phone's approve request must
   pass unmodified.

5. **Restart and enroll.** Restart kharond (`docker compose restart
   kharon`). Have the owner open
   `https://kharon-owner.example.com/enroll` first. The code works once
   and for 120 seconds, so it must not wait for a page to load. Then,
   on the box:

   ```sh
   docker compose exec kharon kharon passkey-enroll
   ```

   Give the owner the code it prints (43 characters). Send it as a
   message they can paste from, not by voice and not in a shared
   channel: whoever uses it first registers a passkey. They paste it
   into the page and follow the browser's passkey prompt. If it expires, run the command
   again. Registering does not sign you in; the owner goes to
   `https://kharon-owner.example.com/` and signs in with the passkey.

6. **Check.** `curl -s -o /dev/null -w '%{http_code}\n' https://kharon-owner.example.com/`
   (a GET: the page answers GET only, so `curl -I` gets 405 even when
   all is well). What the answer means:

   - **200**: healthy.
   - **421**: the Host check refused it. Look for an `httpHostHeader` on
     the tunnel route, or a hostname that differs from `public_origin`.
   - **403** with Access on: see
     [Optional: Cloudflare Access in front](#optional-cloudflare-access-in-front).

### If the RP ID changes

A passkey is bound to the RP ID (by default, the hostname in
`public_origin`). Moving a deploy from local to public mode, or to
another hostname, changes it, and the old passkey stops working. Run
`kharon passkey-enroll` again and register a new passkey at `/enroll`.
A new hostname also needs its own tunnel route and Access application.
Remove the old passkey with `kharon passkey remove` (see the next section).

### A lost passkey

List the passkeys, then remove the one that was lost. The id is the
short prefix of that passkey's credential fingerprint. Removing it
ends every live owner session that was opened with it. The others
keep working.

```sh
docker compose exec kharon kharon passkey list
docker compose exec kharon kharon passkey remove <id>
```

Removing the last passkey is allowed from this command. The owner
can enroll again (`kharon passkey-enroll`, then `/enroll`, as in
step 5). The signed-in owner page lists the same passkeys and can
remove one, but it refuses to remove the last: that would end the
session the page is using. Use the command above for that.

Both commands write an audit entry (`passkey_listed`,
`passkey_removed`) on channel `cli`. The page writes the same
events on channel `web_ui`. The entries carry the credential
fingerprint, not the credential id or the public key. A failed
audit append does not list or remove.

The store is `<data_dir>/owner/passkeys.json` (`/data` under
compose). kharond keeps it loaded; these commands change it
without a restart, and without deleting the file. A store written
before last-used was recorded still loads. Last-used stays blank
until that passkey signs in again. Enrolled-at stays blank for a
passkey stored before it was recorded.

### Unlocking from the browser

The unlock form encrypts the master password in the page before it is
sent, so it never appears in a request body or a log. The page itself,
and the key it encrypts to, come through Cloudflare, so the unlock
trusts the edge and whoever administers the Cloudflare account: they
could change the page and read the password.

To protect against a lookalike site, the owner opens the UI from a
bookmark, never from a link. A password manager helps only if it is
set up for it: save a login item for the owner hostname in Bitwarden
with URI match detection set to **Host** (the default, base domain,
also matches sibling hostnames), and try it once. The unlock field
is marked `autocomplete="off"`, so a browser's built-in manager may
not offer to fill it. The passkey sign-in is bound to the real
hostname, but the unlock form is an ordinary password field: a copied
page can ask for the master password.

Unlocking over the CLI (`kharon unlock` on the box) avoids the edge.
On a managed deploy the terminal is the operator's, so it means
trusting the operator with the password instead.

### Optional: Cloudflare Access in front

Access asks the visitor to log in to Cloudflare before the request
reaches kharond. It is a second line. A valid Access token is not a
sign-in: the passkey is still required.

1. In Zero Trust, Access, Applications, add a self-hosted application
   for `kharon-owner.example.com` with a policy that allows the owner.
2. Open the application and copy its **Application Audience (AUD) Tag**.
   This is not the Client ID.
3. Add to `kharon.toml`:

   ```toml
   [owner_ui.access]
   team_domain = "myteam.cloudflareaccess.com"
   audience = "the AUD tag"
   ```

   `team_domain` is your Zero Trust team name plus `.cloudflareaccess.com`.
   The block only works with `public_origin`. Then restart kharond
   (`docker compose restart kharon`; this locks the vault). Cloudflare
   Access works without it, but kharond's own second check is loaded
   only at start.

4. kharond needs outbound HTTPS to `<team_domain>`: it fetches the
   signing keys from `https://<team_domain>/cdn-cgi/access/certs`. It
   starts the first fetch in the background at startup, so a blocked
   network does not stop kharond from starting. Until one fetch has
   succeeded, every route behind Access answers 403. The same happens
   for a moment when Cloudflare rotates its signing keys: requests that
   arrive while a key fetch is in flight are refused. A 403 in the
   first seconds after kharond starts, or right after a rotation, is
   expected and clears on reload.

5. **ntfy bypass.** The approve and deny buttons in an ntfy message
   are HTTP actions that the ntfy app on the owner's phone sends when
   tapped (not ntfy's server), and that app has no Access session. If
   `[approval].ntfy` is on, create a **second, separate** self-hosted
   Access application with two destinations,
   `kharon-owner.example.com/owner/approve/*` and
   `kharon-owner.example.com/owner/deny/*`, and give it one policy:
   action **Bypass**, Include **Everyone**. Access uses the most
   specific application for each request, so these two paths skip the
   login and every other path stays behind the first application.
   **Do not add a Bypass policy to the owner application itself.** A
   policy has no path: it covers every path of its application, so that
   would turn Access off for the whole hostname. What goes wrong each
   way:

   - No bypass application: Cloudflare Access stops the phone's
     approve tap at the edge. The request never reaches kharond, so
     its log shows nothing, with or without `[owner_ui.access]`.
   - A hostname-wide bypass: no Access login at the edge. With
     `[owner_ui.access]` set, every request reaches kharond without a
     token and everyone gets 403. Without it, nothing shows: the UI is
     simply open, with no Access in front of the passkey.

   kharond's own Access check skips these two routes too. They are
   protected by single-use tokens that last 120 seconds, and anyone who
   can read the ntfy topic holds those tokens (see
   [ntfy approve and deny](#ntfy-approve-and-deny-req-apr-004-req-dep-006)).
   Check it: an approve link works with no Access login, and
   `https://kharon-owner.example.com/` in a private window still goes to
   the Access login.

When everyone gets 403, read the kharond log first
(`docker compose logs kharon | grep 'owner UI Access'`). There is one
line per failed key fetch, with a fixed failure class
(`kharond: owner UI Access keys fetch failed: <class>`), and one line
the first time each kind of refusal is seen
(`kharond: owner UI Access refused a request: <class> (logged once)`).

| Class | Likely cause |
|---|---|
| fetch `connect_or_timeout` | The box has no outbound HTTPS to `<team>.cloudflareaccess.com`, or it timed out. |
| fetch `http_4xx` | The certs endpoint refused the request. |
| fetch `http_5xx`, `http_other` | Cloudflare side; retried automatically. |
| fetch `too_large`, `unparseable`, `no_usable_keys` | The reply was not a usable key set; check `team_domain`. |
| `missing_token` | The request did not come through an Access application covering this path, or the hostname bypasses Access. |
| `malformed_token`, `bad_signature`, `claims` | Not a token from this team's Access. |
| `audience` | `audience` is not this application's AUD tag. Often the Client ID was pasted. |
| `issuer` | The signature is this team's, but the token's `iss` is not exactly `https://<team_domain>` (for example a trailing slash). |
| `unknown_key` | kharond has no key with that id. Right after start or a key rotation it clears within a minute. If it persists, either the key fetch is failing (read the fetch-failure line) or the token comes from a different team than `team_domain`. |
| `expired`, `not_yet_valid` | The token or the box's clock is off. |

### Checks on the first live deploy

These checks can fail. Run the first two from `deploy/compose`, inside
the holder's network namespace, with the public `Host` and no Access
token:

```sh
N='--network container:'"$(docker compose ps -q holder)"
docker run --rm $N alpine:3.22 wget -qSO- --header 'Host: kharon-owner.example.com' http://127.0.0.1:8788/   # 200 before [owner_ui.access] is loaded, 403 after
docker run --rm $N alpine:3.22 wget -qSO- --header 'Host: wrong.example' http://127.0.0.1:8788/            # 421
```

`wget` exits 1 on a non-2xx status and `-S` prints the status line.

- With Access on, the first command gives 403: kharond's own check is
  loaded. A 200 means kharond was not restarted after adding
  `[owner_ui.access]`.
- The second gives 421 (the edge cannot test this: it routes only the
  configured hostname).
- A signed-in owner reaches `/`. The log has no `owner UI Access …:
  issuer` line (the token's `iss` must be
  `https://<team>.cloudflareaccess.com`, no trailing slash) and no
  fetch failure `http_4xx` (kharond's key fetch sends no `User-Agent`;
  if Cloudflare ever refuses that, it shows here).
- `kharon status` prints no `owner UI: N requests without a usable
  CF-Connecting-IP (not throttled)` line after real traffic. If it
  does, the edge is not sending the header.
- With ntfy on, an approve link works with no Access login.

### The throttle, and getting back in

In public mode a source address that fails 10 times in 10 minutes is
refused on the sign-in, enroll and unlock routes until its window ends.
A visitor sees "Too many failed attempts from this network. Try again in
N min." on the sign-in and enroll pages. Pages still load, and an owner
who is already signed in can still approve, deny, revoke and panic.
A successful sign-in or unlock clears the count.

The count is per address (an IPv4 address, or an IPv6 /64) and is kept
in memory. The refusal lasts until ten minutes after that address's
first counted failure. An owner with no shell on the box has, in order:
wait for the time the page shows; sign in from another network (a
phone off Wi-Fi); or ask the operator to act on the box. The operator
can approve, deny, revoke or panic over the CLI on the owner's
instruction (`docker compose exec kharon kharon grants`, `approve`,
`deny`, `panic`; see the
[compose README](../deploy/compose/README.md#owner-web-ui)). A CLI
unlock needs the master password typed on the box, which means giving
it to the operator: a last resort, so wait instead. Restarting kharond
clears every count, but it also locks the vault and ends every session.
Anyone who shares the owner's address (an office, a mobile carrier) can
trip it for them; this is the cost of per-address limits.

The audit log keeps the first 20 `owner_auth_fail` entries a minute from
requests with no session (and every refused `Origin`), plus 5 `throttled` entries; the rest are
counted, not written, so the worst case is 26 entries a minute
(20 + 5 + one count entry).

### Watching it

The throttle works only when the edge sends `CF-Connecting-IP`. The owner
socket's `status` reply carries `owner_ui_without_edge_address`, the
number of owner-UI requests that arrived without a usable one, and
`kharon status` prints it when it is not zero:

```text
owner UI: 3 requests without a usable CF-Connecting-IP (not throttled)
```

The first such request also logs one line:
`kharond: owner UI request without a usable CF-Connecting-IP; such requests are not throttled until the edge sends it`.

Alert when that number rises. It means the edge is not sending the
header (usually the Managed Transform or a header rule from step 4), so
sign-in and unlock have lost their per-address throttle. The passkey
still decides who gets in.

## Public gateway (#197, #198)

The public gateway puts two kharond routes on the internet at
`kharon.twkr.io`, through a Cloudflare Tunnel, so MCP clients that
cannot join the tailnet can still reach the broker:

| Public request | Reaches |
|---|---|
| `POST /mcp` | the MCP transport, with the same bearer token, audit and limits as on `[api]` |
| `GET /connector` | the agent-connector WebSocket (#199): 404 unless `[connector] websocket = true`, subprotocol `kharon-connector.v1` |
| anything else | 404 |

Nothing else is reachable through the hostname: not the owner UI,
not `/v1/*` or `/healthz`, not raw CDP, not the `[connector]` port.
Two layers hold that line:

1. **The edge.** The tunnel's ingress rules route only `^/mcp$` and
   `^/connector$`. The last rule is `http_status:404`.
2. **kharond.** The tunnel's origin is a listener of its own,
   `[public_ingress]`, that serves `POST /mcp` and `GET /connector`
   and answers 404 to everything else, whatever the edge forwards.
   This layer applies only to traffic routed to it.
   With a VPN (tailnet or `compose.vpn.yml`) the `[api]` listener is
   unchanged. The compose base has no `[api]`; kharond runs with
   `[public_ingress]` alone. Token checks on the
   public listener have their own concurrency limit, so a flood of
   bad tokens from the internet cannot slow tailnet agents down.

Cloudflare TLS ends at the edge. By default cloudflared runs beside
kharond and the hop to it is loopback, so there is no TLS on it. The
broker has no WAN port forward.

With a token-managed tunnel the Cloudflare dashboard route list is
the edge allow-list. Point routes only at `http://127.0.0.1:8790`
and the owner UI route, `http://127.0.0.1:8788` (see
[Publishing the owner UI](#publishing-the-owner-ui)). `[public_ingress]`'s
allow-list holds for those routes alone. When cloudflared runs beside
kharond it shares kharond's loopback, so a route to any other port
bypasses it and reaches, with none of the public-side limits:

- cloudflared's own metrics on `127.0.0.1:20241` (`/config`,
  `/diag`, pprof);
- `vaultwarden:80`, with that profile;
- `[api]`, only when you configured it (the compose base has none).
  `/v1/openapi.json` answers 200 unauthenticated; `/v1/*` and `/mcp`
  need a token.

Don't set *HTTP Host Header* on a route.

`/connector` is a WebSocket, so the zone's **Network → WebSockets**
setting must be on (it is by default: Cloudflare supports proxied
WebSocket connections without additional configuration). Cloudflare
closes idle WebSockets after a period it does not publish; the
connector's mux pings every 20 seconds, which keeps the connection
busy. Cloudflare also drops long-lived
WebSockets during edge restarts, and the connector reconnects.

**Cloudflare-side changes (the tunnel, its DNS record, WAF and rate
limit rules) are applied by the owner, not by implementers.**

### kharond: the `[public_ingress]` listener

The listener follows the same rules as the others (REQ-DEP-006): an
IP literal, never `0.0.0.0` or `::`, a port of its own. TLS is
required on any address but loopback. The default is loopback, with
cloudflared beside kharond:

```toml
[public_ingress]
listen = "127.0.0.1:8790"
```

The TLS variant is for the alternative with cloudflared on a separate
guest, which reaches kharond over the tailnet:

```toml
[public_ingress]
listen = "100.64.0.10:8790"
tls_cert_file = "/etc/kharon/tls.crt"
tls_key_file = "/etc/kharon/tls.key"
```

`100.64.0.10` stands for the broker's own tailnet address; use yours.
The same certificate as `[api]` is fine. It must carry the listen
address as an IP SAN, because cloudflared checks it against the
address in the tunnel's `service` URL.

At start kharond prints which one it bound:

```text
kharond: public ingress listening on 127.0.0.1:8790 (plain HTTP, loopback; POST /mcp only)
```

With `[connector] websocket = true` the line ends
`POST /mcp and GET /connector)` instead.

Set `public_host` on any published deploy:

```toml
[public_ingress]
listen = "127.0.0.1:8790"
public_host = "kharon.twkr.io"
```

A request whose `Host` is anything else gets the listener's usual 404.
Without the key kharond answers on whatever hostname the edge forwards,
so a stray route or a second hostname on the tunnel would reach `/mcp`.
Use your gateway hostname, bare (no scheme, no port).

On a host address, the input filter in
[Tunnel-only listeners](#tunnel-only-listeners-req-dep-006) already
covers it when it shares an address with `[api]`. Otherwise add one
line for it, with the interface cloudflared arrives on (for example
`tailscale0`).

### OAuth discovery (N3, #228)

With `[oauth]` set, kharond is also an OAuth authorization server
(N3 Connect, REQ-OAU-001) and serves discovery on both hostnames.
The tunnel needs two new paths (the owner applies Cloudflare-side
changes, as everywhere in this guide):

| Hostname | New tunnel path | Reaches |
|---|---|---|
| `kharon.twkr.io` | `^/.well-known/oauth-protected-resource$` and `^/.well-known/oauth-protected-resource/mcp$` | RFC 9728 protected-resource metadata on `[public_ingress]`, unauthenticated |
| `kharon-owner.twkr.io` | `^/.well-known/oauth-authorization-server$` | RFC 8414 authorization-server metadata on the owner UI listener |

If the owner hostname sits behind a Cloudflare Access application
(the `[owner_ui.access]` shape), that application also needs a
**Bypass** policy for the exact path
`/.well-known/oauth-authorization-server`. MCP clients fetch the
RFC 8414 document before any sign-in and hold no Access token, so
without the bypass discovery is refused at the edge — kharond
itself exempts the path from its own Access check, but it never
sees the request if the edge stops it first.

```toml
[oauth]
# client_id URLs (CIMD) this deploy accepts for Connect; see
# REQ-OAU-002. Discovery is served whether or not any are listed.
clients = ["https://dashboard.example.com/.well-known/kharon-client.json"]
```

`[oauth]` requires `[public_ingress]` with `public_host` set and
an https `[owner_ui]` origin; kharond refuses to start otherwise
(`oauth_needs_public_ingress`, `oauth_needs_public_host`,
`oauth_needs_owner_ui`, `oauth_owner_origin_not_https`). The
issuer is the owner origin. The metadata names the `/oauth/*`
endpoints on the owner hostname; they arrive with the rest of N3
(#230, #231). With `[oauth]` set, a `401` from `/mcp` also carries
the discovery challenge (`resource_metadata`, `scope`). Without
`[oauth]`, both well-known paths answer the usual 404 on both
listeners and the `401` keeps its bare challenge.

### Where cloudflared runs

1. **Compose `edge` profile (default).** cloudflared joins the
   holder container's network namespace, next to kharond. Both see
   the same `127.0.0.1`, and nothing is published. See
   [`deploy/compose`](../deploy/compose/README.md).
2. **Host-networked, beside a host-networked kharond.** One namespace,
   so every local process shares the loopback and can reach
   `[public_ingress]`. That is acceptable on a single-purpose host.
   The kharon pilot broker is this shape: kharond and cloudflared
   `2026.10.4` both on the host network, started from a tunnel token,
   `[public_ingress]` on `127.0.0.1:8790`.
3. **Alternative: a separate guest over the tailnet.** An LXC
   container or VM on the same Proxmox host, joined to the tailnet,
   with outbound HTTPS to Cloudflare and a route to
   `100.64.0.10:8790`. It uses the TLS `[public_ingress]` above and
   holds no kharon secret. The locally managed
   [`deploy/cloudflared/config.yml`](../deploy/cloudflared/config.yml)
   assumes this shape; see
   [the locally managed alternative](#alternative-a-locally-managed-tunnel).

### Creating the tunnel (owner)

In the Cloudflare dashboard (Zero Trust, Networks, Tunnels), create a
dashboard-managed tunnel. Add public-hostname routes for
`kharon.twkr.io`:

| Path | Service |
|---|---|
| `^/mcp$` | `http://127.0.0.1:8790` |
| `^/connector$` | `http://127.0.0.1:8790` |
| (catch-all) | `HTTP Status: 404` |

The dashboard creates the proxied DNS record. Copy the tunnel token
into the secret file without echoing it or putting it in argv, as in
the [compose README](../deploy/compose/README.md#run-it): `umask 077`,
then `cloudflared tunnel token <name> > secrets/cloudflared_tunnel_token`
(or `read -rs`), owned `65532:65532`, mode `0400`. For a host unit,
the file is `/etc/cloudflared/kharon.token`, owned by the
`cloudflared` user, mode `0400`. The token is the tunnel's secret: it
never goes in this repository, a config template or a container
image.

### Running it

In Compose, put `COMPOSE_PROFILES=edge` in `.env` (or
`edge,vaultwarden`), then `docker compose up -d`. The cloudflared
command is `tunnel --metrics 127.0.0.1:20241 run --token-file
/run/secrets/cloudflared_tunnel_token`.

`--metrics 127.0.0.1:20241` matters. With no `--metrics`, the
cloudflared container build binds its metrics server to every
interface, and that server serves `/metrics`, `/ready`, `/config`,
`/diag` and Go pprof under `/debug/pprof` to the LAN and tailnet.

For the host-networked shape, a systemd unit:

```ini
# /etc/systemd/system/cloudflared-kharon.service
[Unit]
Description=cloudflared tunnel for kharon.twkr.io (#198)
After=network-online.target
Wants=network-online.target

[Service]
User=cloudflared
Group=cloudflared
ExecStart=/usr/local/bin/cloudflared --no-autoupdate tunnel --metrics 127.0.0.1:20241 run --token-file /etc/cloudflared/kharon.token
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now cloudflared-kharon.service
```

`--no-autoupdate` keeps cloudflared from rewriting itself; update it
by replacing the binary or the pinned image.

### Verifying

From the internet, off the tailnet:

```sh
for p in / /ui /healthz /v1/status /v1/items /v1/openapi.json /owner/session /owner/approve/x /json/version; do
  printf '%s %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "https://kharon.twkr.io$p")" "$p"
done                                                         # every line: 404
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://kharon.twkr.io/v1/fill   # 404
curl -s -o /dev/null -w '%{http_code}\n' https://kharon.twkr.io/mcp               # 404 (GET)
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://kharon.twkr.io/mcp \
  -H 'Content-Type: application/json' -d '{}'                                     # 401, no token
```

`401` on the last line means the request reached kharond and was
refused for want of a token. A tool call with a real agent token
then behaves as it does on `[api]`.

Then the origin on its own, bypassing the edge. This is the second
layer: kharond's own 404. From the compose holder's namespace, run
from `deploy/compose`:

```sh
docker run --rm --network "container:$(docker compose ps -q holder)" alpine:3.22 wget -qSO- http://127.0.0.1:8790/v1/status
```

That prints `HTTP/1.1 404 Not Found` and exits 1, which is expected
(busybox `wget` prints no body on a 404). `POST /mcp` gets 401. On a
host-networked kharond, run `curl` against `http://127.0.0.1:8790`
on the host.

### Owner hostname

The owner UI gets its own hostname, `kharon-owner.twkr.io`, not a path
on the gateway hostname. See
[Publishing the owner UI](#publishing-the-owner-ui). The MCP
authorization work (N3) serves its discovery from both hostnames —
see [OAuth discovery](#oauth-discovery-n3-228) — and adds the
`/oauth/*` endpoints here as it lands.

### Alternative: a locally managed tunnel

For cloudflared on a separate guest, over TLS, use
[`deploy/cloudflared/config.yml`](../deploy/cloudflared/config.yml)
with a credentials file instead of a token. On a machine where you
can sign in to Cloudflare:

```sh
cloudflared tunnel login                   # writes ~/.cloudflared/cert.pem
cloudflared tunnel create kharon           # prints the tunnel UUID and writes <UUID>.json
cloudflared tunnel route dns kharon kharon.twkr.io
```

The last command creates a proxied CNAME, `kharon.twkr.io` to
`<UUID>.cfargotunnel.com`. Then, on the cloudflared guest:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared
sudo install -d -o root -g cloudflared -m 0750 /etc/cloudflared
sudo install -o cloudflared -g cloudflared -m 0400 <UUID>.json /etc/cloudflared/
sudo install -o root -g cloudflared -m 0640 deploy/cloudflared/config.yml /etc/cloudflared/config.yml
sudo install -o root -g cloudflared -m 0644 /etc/kharon/tls.crt /etc/cloudflared/kharon-broker.crt
```

Replace `<TUNNEL-UUID>` in `config.yml` with the UUID and
`<BROKER-TAILNET-IP>` with the `[public_ingress]` listen address. The
credentials file is the tunnel's secret and `cert.pem` is needed only
to create, route or delete tunnels; keep it off the guest and delete
it where you made the tunnel. `kharon-broker.crt` is the broker's
public certificate (not its key). Never set `noTLSVerify: true`; if
cloudflared logs `x509: certificate is valid for ...`, the
certificate's IP SAN does not match the `service` address.

The unit is the one above with this `ExecStart` (the config file
carries `metrics: 127.0.0.1:20241`, so the server stays on loopback):

```ini
ExecStart=/usr/local/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run
```

Check the rules offline before (re)starting, on the guest. Each line
names the rule that would answer:

```sh
cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
for p in /mcp /connector / /ui /healthz /v1/status /v1/openapi.json /owner/session; do
  cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule "https://kharon.twkr.io$p"
done
```

Only `/mcp` and `/connector` may match rules 1 and 2; every other
path must match the last rule (`http_status:404`). The origin check
from a tailnet host:

```sh
curl -s --cacert /etc/kharon/tls.crt https://100.64.0.10:8790/v1/status   # 404, JSON body
curl -s -o /dev/null -w '%{http_code}\n' --cacert /etc/kharon/tls.crt \
  -X POST https://100.64.0.10:8790/mcp -H 'Content-Type: application/json' -d '{}'   # 401
```

### Optional: WAF and rate limits for `/mcp` and `/connector`

These cost little and stop junk at the edge, before it reaches the
tunnel. Suggestions, for the owner to apply in the zone's Security
rules:

- **Custom rule, block:** `http.host eq "kharon.twkr.io" and not
  (http.request.uri.path in {"/mcp" "/connector"})`. The tunnel would
  404 these anyway; this keeps them off it.
- **Custom rule, block:** `http.host eq "kharon.twkr.io" and
  http.request.uri.path eq "/mcp" and http.request.method ne "POST"`.
- **Rate limiting rule:** on `http.request.uri.path eq "/mcp"`,
  counted per IP, for example 120 requests per minute, then block for
  ten minutes. An agent filling forms makes a few calls a minute.
- **Rate limiting rule, `/connector`:** on
  `http.request.uri.path eq "/connector"`, counted per IP, for example
  20 requests per minute, then block for ten minutes. A healthy
  connector dials once and holds the socket; even a flapping one backs
  off to 30-second retries. kharond's pre-auth budget (8 sockets, shared by
  everyone) is global, so a stranger who keeps it full can delay a
  *reconnecting* agent; this rule is what protects those 8 pre-auth
  slots from starvation. Live sessions are untouched.
- **Bot Fight Mode and "I'm Under Attack":** keep them off for this
  hostname. MCP clients and the connector cannot answer a browser
  challenge.

kharond's own limits (fill rate per agent, token-check concurrency)
apply regardless. #200 adds the `/mcp` hardening that depends on the
client's address.

### Rollback

Take the public path away in either order; each step alone closes it.

```sh
# Compose: stop serving the hostname, and drop `edge` from .env.
docker compose stop cloudflared      # also takes the owner UI offline
# Host-networked or guest:
sudo systemctl disable --now cloudflared-kharon.service
# On the broker: remove [public_ingress] from the config, then restart kharond.
```

If `[public_ingress]` is the only agent listener (the compose base has no
`[api]`), removing it leaves kharond with none, and it refuses to start
(`no_agent_listener`, exit 78). `restart: unless-stopped` then crash-loops
it, and `docker compose exec kharon kharon status` or `panic` fails
because the owner socket is gone. In that case stop it instead:
`docker compose stop kharon`, or `docker compose stop cloudflared` to
close only the edge. Or add `[api]` on a VPN address first, then remove
`[public_ingress]`.

To remove the tunnel for good, delete it in the dashboard, or (owner,
for a locally managed tunnel, where `cert.pem` is):

```sh
cloudflared tunnel delete kharon
```

and delete the `kharon.twkr.io` CNAME in the zone's DNS. The tailnet
`[api]` listener, when configured, is untouched throughout (with a VPN:
tailnet or `compose.vpn.yml`), so VPN agents keep working.

## Agent host (REQ-DEP-005)

Transport is dual-path (SPEC REQ-DEP-005 / REQ-ARCH-002):

- **Path (A)** — WireGuard peer + cdp-relay (this section's historical
  default). Use when the agent host can peer WG (UDP 51820, or a
  site-to-site path that lands the same).
- **Path (B)** — agent-connector: install a minimal outbound TLS
  dialer that authenticates to the broker and relays CDP to
  `127.0.0.1:9222`. No `wg0`, no UDP listen, no `CAP_NET_ADMIN`.
  Use when the agent host is egress-shaped. Config:
  `cdp = { endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }`.
  The connector binary holds only tunnel credentials (REQ-ARCH-001);
  Chromium/`browser`/`ptrace_scope`/password-manager rules below still
  apply.

Path (A) provisioning follows. Path (B) is the section after it.
Path (A) installs no kharon binary. Path (B) installs only
`kharon-agent-connector`, which holds the tunnel credential and not
an agent API token, a vault key, or the account password
(REQ-ARCH-001).

The agent host needs four things, and on path (A) nothing else from
kharon (REQ-ARCH-001):

| What | Why |
|---|---|
| Chromium runs as its own OS user, `browser`, with its profile in `/var/lib/browser` (mode 0700) | The agent runs as a different, non-root user, so it cannot read the profile directory (see [Running the agent](#running-the-agent)). |
| `kernel.yama.ptrace_scope = 1` | The agent's user cannot attach to Chromium or read `/proc/<pid>/mem`, where filled values live briefly. |
| Password manager, leak check, autofill and sync off by managed policy | Chromium never stores a filled password (REQ-ARCH-004). |
| CDP on `127.0.0.1:9222`, exposed to the broker only through WireGuard | The agent uses CDP on loopback as before. The broker reaches it at `10.66.0.2:9222`, and nothing else can. |

[`deploy/agent-host/provision.sh`](../deploy/agent-host/provision.sh)
does all of it on Debian 12 or 13. Copy it to the agent host and run
it as root with the broker's WireGuard public key:

```sh
sudo BROKER_WG_PUBKEY='<broker public key>' ./provision.sh
```

It:

- installs `chromium`, `fonts-liberation`, `wireguard-tools` and
  `socat`;
- creates the `browser` system user and `/var/lib/browser` (0700);
- writes `/etc/sysctl.d/60-ptrace-scope.conf`;
- writes the managed policy
  `/etc/chromium/policies/managed/no-password-manager.json`;
- writes `browser.service`, which runs headless Chromium as
  `browser` with CDP on `127.0.0.1:9222`;
- generates the host's WireGuard key in `/etc/wireguard/wg0.key`
  (0600) and writes `/etc/wireguard/wg0.conf` with the broker as the
  only peer;
- writes `cdp-relay.service`, a `socat` relay from `10.66.0.2:9222`
  to `127.0.0.1:9222` that accepts only the broker's tunnel address
  and runs as a throwaway uid;
- prints the host's WireGuard public key for the broker's peer
  entry.

`AGENT_WG_ADDR`, `BROKER_WG_ADDR`, `WG_LISTEN_PORT`, `CDP_PORT` and
`BROKER_ENDPOINT` override the defaults. Re-running it is safe: it
keeps the WireGuard key and rewrites everything else.

The WireGuard private key is the only secret on the agent host, and
only root can read it. Someone holding it could pose as the agent
host to the broker and receive fills meant for its Chromium, so
treat it like an SSH host key: never copy it off the host, and
replace it (re-run with the old key file removed, then update the
broker's peer entry) if the host is rebuilt or root is compromised.

CI runs the script in a fresh Debian VM and checks the result
(`.github/workflows/agent-host.yml`), and checks that it installs
only Chromium flags and tunnel config
(`crates/kharond/tests/req_arch_001_agent_host_docs.rs`).

### Path (B) — agent-connector

Same Chromium user, ptrace scope, and password-manager policy as path
(A). No WireGuard, no `cdp-relay`, no UDP listen.
[`deploy/agent-host/provision-connector.sh`](../deploy/agent-host/provision-connector.sh)
installs that, plus the connector, on Debian 12 or 13. The binary and
the tunnel credential file are produced on the broker side (above);
this host only receives them.

```sh
sudo CONNECTOR_BIN=./kharon-agent-connector \
  BROKER_ADDR=203.0.113.4:8789 \
  BROKER_PIN=<64 hex sha256 of the broker certificate DER> \
  AGENT_ID=assistant \
  TUNNEL_TOKEN_FILE=./tunnel.token \
  ./provision-connector.sh
```

Set exactly one of `BROKER_ADDR` (`host:port`, the raw `[connector]
listen`) and `BROKER_URL` (`wss://broker.example.net/connector`, the
public gateway; see
[Over WebSocket](#over-websocket-through-the-public-gateway-199)).
The script refuses both or neither, and refuses a `BROKER_URL` that
does not start with `wss://` or that contains `?`, `#` or `@` (a
query, a fragment or userinfo, which the connector's own `broker_url`
parser refuses too). With `BROKER_URL` it writes
`transport = "ws"` and `broker_url` to the connector config instead
of `broker`. `BROKER_PIN` is required either way.

It:

- installs `chromium` and `fonts-liberation` (not `wireguard-tools`,
  not `socat`);
- creates the `browser` user and `/var/lib/browser` (0700);
- writes `/etc/sysctl.d/60-ptrace-scope.conf`;
- writes `/etc/chromium/policies/managed/no-password-manager.json`;
- writes `browser.service` (CDP on `127.0.0.1:9222`);
- creates a `connector` user that is neither `browser` nor the agent;
- installs the binary at `/usr/local/bin/kharon-agent-connector`;
- writes `/etc/kharon-connector/connector.toml` and
  `/etc/kharon-connector/token` (mode `0400`, owner `connector`),
  and, when `PROXY_CREDS_FILE` is set,
  `/etc/kharon-connector/proxy-creds` (same mode and owner);
- writes `kharon-agent-connector.service`, which dials the broker and
  relays to `127.0.0.1:9222`, and restarts itself if the process
  exits. The process also reconnects on its own.

`CDP_PORT` defaults to `9222`. `PROXY=http://proxy-host:3128` is an
optional HTTP CONNECT proxy. The URL stays `http://host:port` with no
userinfo; this script and the connector both refuse a proxy URL that
embeds a password. When that proxy requires authentication, set
`PROXY_CREDS_FILE` to a file of one line, `user:password` (a trailing
newline is ignored, and the line is at most 4096 bytes). The script
installs it at `/etc/kharon-connector/proxy-creds` (mode `0400`, owner
`connector`) and sets `proxy_creds_file` in the connector config. The
connector sends that line only as `Proxy-Authorization: Basic …` on
the CONNECT to the proxy. It does not put the credential in the proxy
URL, on the command line, in logs, or on the broker TLS session. A
re-run that omits `PROXY_CREDS_FILE` removes the installed file.
Re-running the script is safe.

The tunnel credential is the only kharon secret on this host, and
only the `connector` user can read it. It is not the agent API token.
Someone holding it could attach a connector and receive the CDP
session the broker opens, so treat it like an SSH key: do not copy it
further, and mint a new one (`kharon tunnel mint` on the broker, then
re-run with the new file) if this host is rebuilt. The broker
certificate pin is not a secret. The proxy credential, when set, is
the egress proxy's secret: the connector presents it to that proxy
and nowhere else.

#### Connector config over WebSocket

`/etc/kharon-connector/connector.toml` as the script writes it with
`BROKER_URL`:

```toml
transport = "ws"                                  # "tls" (default) dials broker
broker_url = "wss://broker.example.net/connector"  # wss:// only; port defaults to 443
broker_pin = "<64 hex>"                           # the inner [connector] cert, as for tls
agent_id = "assistant"
token_file = "/etc/kharon-connector/token"
cdp = "127.0.0.1:9222"
# proxy = "http://proxy.example:3128"             # optional, as for tls
# server_name = "broker.internal"                 # optional
# outer_ca_file = "/etc/kharon-connector/edge-ca.pem"   # tests and private edges only
```

- `transport = "tls"` takes `broker = "host:port"` and refuses
  `broker_url` and `outer_ca_file`; `transport = "ws"` takes
  `broker_url` and refuses `broker`. A config that mixes them is a
  config error (exit 78).
- The connector verifies the outer TLS to the edge against the system
  roots. `outer_ca_file` is for tests and private edges only: it
  *replaces* the system roots for the outer TLS and never turns
  verification off.
- `server_name` sets the inner TLS server name on both transports; it
  defaults to the broker host (or the URL's host). The server name is
  not what authenticates the broker, `broker_pin` is.
- An existing raw-TLS config (`broker`, no `transport`) keeps working
  unchanged.

`kharon-agent-connector --config /etc/kharon-connector/connector.toml
--check` dials once, walks each leg up to `AUTH_OK` and prints one line
per leg, never opening CDP. Run it first on a failing host:

```text
ok dns
ok tcp
ok outer-tls
fail upgrade: websocket upgrade answered 502
check: failed
```

A successful check ends with a fixed note:

```text
ok auth
note: a successful check replaces this agent's live broker session
check: ok
```

`--check` authenticates for real, and the broker keeps one session per
agent. A successful check therefore replaces the running connector's
session on that broker: a fill in flight fails, the running connector
reconnects by itself, and the broker writes one `connector_replaced`
audit entry (see above). Run `--check` while the service is stopped, or
accept the reconnect. Do not put it in a health probe.

Exit codes: 0 when auth succeeded, 69 when a leg failed, 78 for a
config error. The legs are `dns`, `tcp`, `proxy`, `outer-tls`,
`upgrade`, `inner-tls` and `auth`. Log lines are fixed text and never
carry the token, a proxy credential or a peer's response body. The
`dns` line names the host that did not resolve
(`cannot resolve the broker host (broker.example.net)`, or `the proxy
host`), the `tcp` line names the address dialed (the proxy's when one
is configured), and the `outer-tls` line names a certificate class:
`untrusted issuer`, `name mismatch`, `expired or not yet valid`,
`other certificate error` or `handshake failed`. A name lookup that
takes longer than 10 seconds is reported as the `dns` leg. When the
service ends a session it logs `session ended after <duration>;
reconnecting`.

The service retries with exponential backoff and full jitter, from 1
second to a 30-second cap. A rejected tunnel credential and a proxy
authentication failure wait a fixed 60 seconds. With no authenticated
session for 2 minutes the connector logs one summary line, and repeats it
every 10 minutes while the outage lasts. Alert on it:

```text
kharon-agent-connector: no broker session for 2m10s (14 attempts); last failure: upgrade: websocket upgrade answered 502
```

When the failing leg is `upgrade`, the status is printed as received:

| Agent log | Meaning |
|---|---|
| `websocket upgrade answered 404` | the route is missing at the edge, or kharond has `websocket` off or no `[public_ingress]` |
| `websocket upgrade answered 502` | the origin is down (kharond or cloudflared); also 52x from Cloudflare |
| `websocket upgrade answered 503` | kharond's pre-auth budget is full; retry, and see the rate-limit rule |
| `websocket upgrade answered 400` / `403` | the request was malformed, or something added an `Origin` header |
| `websocket upgrade answered 101 without the kharon-connector.v1 subprotocol` | the upgrade succeeded, but whatever answered is not kharond's `/connector` (or is an older build): check the route |

Point the agent harness at `https://203.0.113.4:8787` with its agent
API token, and trust the broker certificate there. The connector does
not carry that token. The idle-lock contract in
[Running the agent](#running-the-agent) applies on this path too: the
broker locks 30 minutes after the latest fill, unlock, or grant
approval, and a re-unlock needs a new browser context. CI checks this
script the same way as path (A) (`req_arch_001_agent_host_docs`) and
fills through the connector against a CDP stub
(`req_arch_002_agent_connector`).

### Running the agent

The broker locks 30 minutes after the latest of a fill, the owner
unlocking, or the owner approving a grant. `kharon_context`, status,
list, search, `kharon_request_grant`, and moving between tabs do not
postpone that. A grant the owner has issued, and that the agent has
not used up and that has not expired, holds the lock off until that
grant is used up or its own lifetime ends, whichever comes first, and
not beyond that. The owner's lock and panic still take effect at once.

A lock closes the browser context. After the owner unlocks again, call
`kharon_context` and use the new `browser_context_id`. A fill aimed at
the previous context comes back `target_not_owned`.

Run the agent as its own user, not `browser` and not in the
`browser` group, and have it connect to CDP on loopback, for example
with Playwright's `chromium.connectOverCDP("http://127.0.0.1:9222")`.

That user must not be root, and on path (B) must not be `connector`
either. Every boundary in the table above is a Unix permission, and
root is exempt from all of them. A root agent:

- reads Chromium's profile in `/var/lib/browser`;
- reads the tunnel credential in `/etc/kharon-connector/token` (path
  (B)) and the WireGuard key in `/etc/wireguard/wg0.key` (path (A));
- attaches to Chromium and reads `/proc/<pid>/mem`, where filled
  values live briefly, because `kernel.yama.ptrace_scope = 1` does
  not restrict root.

kharon cannot check this: the provision scripts run as root and do
not know which uid the agent will use. A host that only offers a root
agent, as some hosted agent runtimes do, still gets the transport,
the approval flow and the audit log, but not this isolation (G1).
The #121 live pilot ran that way: a root agent, with Chromium on
`--no-sandbox` under an AppArmor user-namespace restriction. It
proves path (B)'s transport, auth and fill, not isolation.

For a visible browser instead of a headless one, change
`browser.service`'s `ExecStart`: drop `--headless=new` and give it a
display. Without `--headless`, Chromium binds CDP to loopback
whatever `--remote-debugging-address` says.

### Agent harness policy (SPEC OQ-3)

kharond fills inside an isolated world and hands the agent only a
result, but a page's DOM is shared. An agent that reads input values
after a fill can read what kharond typed. kharon cannot stop a
compromised agent from doing that; the harness can stop a curious
one. We recommend that the agent's tool harness:

- does not expose `Runtime.evaluate`, `Runtime.callFunctionOn` or
  any other way to run JavaScript in pages;
- does not return input values, `value` attributes or form data to
  the model, only the page's text and structure;
- masks password fields in screenshots, or takes none while a
  login form is on screen.
