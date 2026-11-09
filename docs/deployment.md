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
memory. A self-hoster can add the `vaultwarden` profile instead. Under
path (A) the agent API binds to the WireGuard address only; under
path (B) it binds to a TLS-capable listen address the agent reaches
over outbound HTTPS (REQ-DEP-006).

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

Under the Compose package this waits for #208: the owner UI's
loopback is inside the holder's namespace and is not reachable until
#208 publishes it, so the owner uses the CLI meanwhile. What follows
applies to a host-networked kharond.

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
an SSH forward on the host. Run kharond on the host network until
#208, and keep the action URL on that owner address.

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
nothing is published either. An `[owner_ui] listen` port of 0
(ephemeral, a test shape) likewise publishes nothing — the action
URLs need the stable configured address.

## Public gateway (#197, #198)

The public gateway puts two kharond routes on the internet at
`kharon.twkr.io`, through a Cloudflare Tunnel, so MCP clients that
cannot join the tailnet can still reach the broker:

| Public request | Reaches |
|---|---|
| `POST /mcp` | the MCP transport, with the same bearer token, audit and limits as on `[api]` |
| `GET /connector` | the agent-connector WebSocket (#199; 404 until it lands) |
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
   unchanged. Token checks on the
   public listener have their own concurrency limit, so a flood of
   bad tokens from the internet cannot slow tailnet agents down.

Cloudflare TLS ends at the edge. By default cloudflared runs beside
kharond and the hop to it is loopback, so there is no TLS on it. The
broker has no WAN port forward.

With a token-managed tunnel the Cloudflare dashboard route list is
the edge allow-list. Point routes only at `http://127.0.0.1:8790`
(and `http://127.0.0.1:8788` after #208). `[public_ingress]`'s
allow-list holds for those routes alone. When cloudflared runs beside
kharond it shares kharond's loopback, so a route to any other port
bypasses it and reaches, with none of the public-side limits:

- base `[api]` on `127.0.0.1:8787` (`/v1/openapi.json` answers 200
  unauthenticated; `/v1/*` and `/mcp` need a token);
- cloudflared's own metrics on `127.0.0.1:20241` (`/config`,
  `/diag`, pprof);
- `vaultwarden:80`, with that profile.

Don't set *HTTP Host Header* on a route.

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

On a host address, the input filter in
[Tunnel-only listeners](#tunnel-only-listeners-req-dep-006) already
covers it when it shares an address with `[api]`. Otherwise add one
line for it, with the interface cloudflared arrives on (for example
`tailscale0`).

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

`kharon-owner.twkr.io` pointing at `http://127.0.0.1:8788` comes
with #208, which adds the public origin, Host and Origin checks,
throttling and optional Cloudflare Access. Until then, don't route
it. The MCP authorization work (N3) adds routes later, such as
`/.well-known/oauth-protected-resource` and the token endpoint.

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

### Optional: WAF and rate limits for `/mcp`

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
- **Bot Fight Mode and "I'm Under Attack":** keep them off for this
  hostname. MCP clients cannot answer a browser challenge.

kharond's own limits (fill rate per agent, token-check concurrency)
apply regardless. #200 adds the `/mcp` hardening that depends on the
client's address.

### Rollback

Take the public path away in either order; each step alone closes it.

```sh
# Compose: stop serving the hostname, and drop `edge` from .env.
docker compose stop cloudflared
# Host-networked or guest:
sudo systemctl disable --now cloudflared-kharon.service
# On the broker: remove [public_ingress] from the config, then restart kharond.
```

To remove the tunnel for good, delete it in the dashboard, or (owner,
for a locally managed tunnel, where `cert.pem` is):

```sh
cloudflared tunnel delete kharon
```

and delete the `kharon.twkr.io` CNAME in the zone's DNS. The tailnet
`[api]` listener is untouched throughout (with a VPN: tailnet or
`compose.vpn.yml`), so VPN agents keep working.

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

Point the agent harness at `https://203.0.113.4:8787` with its agent
API token, and trust the broker certificate there. The connector does
not carry that token. CI checks this script the same way as path (A)
(`req_arch_001_agent_host_docs`) and fills through the connector
against a CDP stub (`req_arch_002_agent_connector`).

### Running the agent

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
