# kharond with Docker Compose

`docker-compose.yml` runs kharond from the repository's `Dockerfile`
beside cloudflared, against the customer's own Bitwarden vault, with
no inbound port on the host (#207, REQ-DEP-001, REQ-DEP-002). It is an
example to adapt, not a hardened deployment. The
[deployment guide](../../docs/deployment.md) covers the rest: the
kharon account's master password, agent tokens, the public gateway,
the WireGuard link, and setting up the agent host. Host install,
backup and restore of `/data`, upgrades and the secrets inventory are
in [Broker lifecycle](../../docs/broker-lifecycle.md).

## Run it

```sh
cd deploy/compose
printf 'COMPOSE_PROFILES=edge\n' > .env          # git-ignored; see below for other profiles
docker compose build kharon
docker run --rm -it --entrypoint kharon kharon:local init  # the account's master password, shown once
# create the kharon account with it, then its org, collection and API key (see the guide)
docker run --rm -it --entrypoint kharon kharon:local token mint assistant
# token once on the terminal; paste the $argon2id$ token_hash line into kharon.toml
cp kharon.toml.example kharon.toml        # then edit: public_host, org, collections, agents, CDP endpoint, token_hash
cp /path/to/bw-api-key.json secrets/kharon_bw_api_key.json
sudo chown 10001:10001 secrets/kharon_bw_api_key.json   # kharond's uid; see below
sudo chmod 0400 secrets/kharon_bw_api_key.json
# the tunnel token, from a token-managed tunnel: not echoed, not in argv
( umask 077; cloudflared tunnel token kharon > secrets/cloudflared_tunnel_token )
# or: read -rs T; ( umask 077; printf '%s' "$T" > secrets/cloudflared_tunnel_token ); unset T
sudo chown 65532:65532 secrets/cloudflared_tunnel_token  # cloudflared's uid
sudo chmod 0400 secrets/cloudflared_tunnel_token
docker compose up -d
docker compose exec kharon kharon unlock  # owner unlock, master password on the tty
docker compose exec kharon kharon status
```

`COMPOSE_PROFILES=edge` turns cloudflared on. A self-hoster with the
bundled vault uses `edge,vaultwarden`. To reach an agent host over a
VPN, also add `COMPOSE_FILE=docker-compose.yml:compose.vpn.yml` to
`.env`. With `edge` on and no token file, `up` fails with "bind source
path does not exist". That is intended: the tunnel never starts
without its token.

Creating the tunnel and its routes is covered in the
[deployment guide](../../docs/deployment.md#creating-the-tunnel-owner).

`secrets/` is git-ignored. kharond reads the API key from
`/run/secrets/kharon_bw_api_key`. Without Swarm, Compose mounts that
file as a bind mount that keeps the host file's owner and mode. It
ignores a secret's `uid`, `gid` and `mode`, with a warning. So the
file must belong to uid 10001, which kharond runs as. If it is a
`0400` file owned by you, kharond refuses to start with `config error
[api_key_file]: … not readable by kharond (euid 10001; …)`
(REQ-DEP-008). The same goes for a TLS private key you bind-mount for
path B.

## What the example sets

- The image is distroless `static`, runs as uid 10001 with a
  read-only root filesystem; state lives in the `kharon-data` volume
  at `/data`, which also holds the owner socket.
- `holder` is a do-nothing container that owns the network
  namespace. kharond and cloudflared join it with
  `network_mode: "service:holder"`. A container that joined
  `service:kharon` would be stranded whenever kharond restarts; the
  holder never restarts for that, so the tunnel keeps its namespace.
  Don't restart or recreate the holder alone (`docker restart
  <holder>`, `docker compose up -d --force-recreate holder`): that
  strands kharond and cloudflared in a dead namespace. Restart the
  whole stack (`docker compose restart`) or run `docker compose up -d`.
- The base has no `[api]`: the agent API is off, and agents reach
  `POST /mcp` on `[public_ingress]`. Every kharond listener is on
  loopback (`[public_ingress]` 127.0.0.1:8790), and nothing is published.
  Only cloudflared, in the same namespace, reaches them: the tunnel's
  routes point at `http://127.0.0.1:8790`. Point routes only there:
  cloudflared shares the loopback, so a route to any other port
  bypasses `[public_ingress]`: cloudflared's `:20241`, `vaultwarden:80`
  with that profile, and `[api]` only if you configured it.
  kharond refuses a wildcard listen address (REQ-DEP-006).
- cloudflared's metrics are pinned to `127.0.0.1:20241`. Without
  `--metrics` the container build binds every interface and serves
  `/metrics`, `/config`, `/diag` and pprof.
- The default vault is the customer's own Bitwarden Password Manager
  on Bitwarden cloud. The customer unlocks it (from the owner web UI, or `kharon unlock` on the box), and
  kharond keeps the keys only in memory. The `vaultwarden` profile is
  for self-hosters: set `[bitwarden] server = "http://vaultwarden:80"`.
  Bitwarden Secrets Manager is not the default.
- Fills need a path to the agent host's browser. Path B over
  WebSocket needs no VPN: set `[connector] websocket = true` (with
  `[public_ingress]`, no `listen`), and the agent host dials
  `wss://<public host>/connector` through the tunnel (see "Over
  WebSocket" in `docs/deployment.md`). The certificate and key it
  names are not mounted by the compose base: add the read-only
  bind-mount from the `docker-compose.override.yml` shown under "Path
  (B) broker" in that guide. `via = "wireguard"` still needs
  `compose.vpn.yml`: kharond reaches the browser over the `wg` network
  (holder 10.66.0.1, agent host 10.66.0.2), and `[api]` over a VPN
  binds that address (add `[api]` with `listen = "10.66.0.1:8787"`; the
  base has none). Swap the network for your real tunnel.
- If you copied the N1 example (#211) before #210, your `kharon.toml`
  still has `[api] listen = "127.0.0.1:8787"`. Delete that block: a
  dashboard mis-route could reach it. For liveness use
  `docker compose exec kharon kharon status`, or expect `401` from
  `POST /mcp` on `127.0.0.1:8790` inside the namespace when the request
  carries your `public_host`
  (`curl -H 'Host: kharon.example.com' -X POST http://127.0.0.1:8790/mcp`);
  any other `Host` gets `404`. Nothing listens on 8787 now.
- The owner UI is published on its own hostname, `kharon-owner.<domain>`.
  See "Owner web UI" below. Its loopback address is inside the holder's
  namespace, so an SSH forward does not reach it; the tunnel does.
- ntfy approve/deny (`/owner/approve/<token>`, `/owner/deny/<token>`)
  go through the same hostname. See the
  [deployment guide](../../docs/deployment.md#ntfy-approve-and-deny-req-apr-004-req-dep-006).
- `memlock` is unlimited so `require_mlock` holds, and core dumps are
  off. `cap_add: IPC_LOCK` has no effect for a non-root uid; the
  ulimit is what makes `mlock` succeed.
- The example config sets `[approval].ntfy`, which is also the
  off-host audit checkpoint sink (REQ-AUD-002): signed checkpoints
  are published to that topic every 100 entries or 10 minutes.
  Fill in a real ntfy server/topic before starting — with no
  `[approval].ntfy` section kharond refuses to start unless
  `[audit] checkpoint_local_only = true` is set instead (a temporary
  pilot posture; see the deployment guide). `[audit] checkpoint_ntfy`
  moves the checkpoints to a topic of their own, so the checkpoint
  keeper does not read approval prompts (#302; see
  [A separate checkpoint topic](../../docs/deployment.md#a-separate-checkpoint-topic-302)).
- All capabilities are dropped and `no-new-privileges` is set.
  `security_opt` also points at [`kharon-seccomp.json`](./kharon-seccomp.json)
  (SPEC §9). That file is the Docker/moby **default** seccomp profile
  checked in under the SPEC path so the example matches §9 and CI
  exercises the same filter the daemon would get from Docker's
  built-in default (source: docker/engine `profiles/seccomp/default.json`,
  fetched 2026-11-06); fork it to tighten later.

The CDP endpoint in `kharon.toml` is the agent host's CDP address
(`ws://10.66.0.2:9222`). kharond looks up the browser's current
`/devtools/browser/<id>` from `/json/version` each time it connects,
so restarting Chromium needs no config change (see the
[deployment guide](../../docs/deployment.md#pointing-kharond-at-the-browser)).

## Owner web UI

The example `kharon.toml` turns on `[owner_ui]` with
`public_origin = "https://kharon-owner.example.com"`. Use your own
hostname there. Then:

1. In the Cloudflare dashboard (Networking, Tunnels, your tunnel,
   Routes, Add route, Published application), publish
   `kharon-owner.<domain>` with Service URL `http://127.0.0.1:8788`.
   Set nothing under additional settings: no HTTP Host Header, no
   HTTP/2 to origin. See "Publishing the owner UI" in the
   [deployment guide](../../docs/deployment.md#publishing-the-owner-ui).
2. Restart kharond so it reads the config: `docker compose restart kharon`.
3. Enroll the first passkey. Open `https://kharon-owner.<domain>/enroll`
   first. The code works once and for 120 seconds, so have the page
   ready, then run:

   ```sh
   docker compose exec kharon kharon passkey-enroll
   ```

   Send the owner the code it prints (43 characters) as a message they
   can paste from. They enter it and follow the browser's passkey
   prompt (run the command again if it expired). After that, sign in at
   `https://kharon-owner.<domain>/`.

The CLI stays as the fallback for whoever has a shell on the box. On a
managed deploy that is the operator, who can approve, deny, revoke or
panic on the owner's instruction. A throttled owner waits out the window
the page shows, or signs in from another network. A CLI unlock means
the owner giving the operator the master password: a last resort. A
lost passkey is removed with `kharon passkey list`, then
`kharon passkey remove <id>`; see "A lost passkey" in the
[deployment guide](../../docs/deployment.md#a-lost-passkey). The CLI
talks to the owner socket inside the container:

```sh
docker compose exec kharon kharon grants                       # pending requests
docker compose exec kharon kharon approve gr_… [--kind once|per-origin|standing]
docker compose exec kharon kharon deny gr_…
docker compose exec kharon kharon panic                        # lock, zeroize, revoke all
docker compose exec kharon kharon status                       # also prints the owner-UI counter below
```

If `kharon status` prints `owner UI: N requests without a usable
CF-Connecting-IP (not throttled)` and N keeps growing, the edge is not
sending that header and sign-in has lost its per-address throttle. See
the deployment guide.

Verify the audit log with `--data` set to the audit directory,
`<data_dir>/audit`, not `<data_dir>` (`--data /data` fails on
`keys/audit_sign.pub`):

```sh
docker compose exec kharon kharon audit verify --data /data/audit \
  --checkpoints /data/audit/checkpoints.jsonl   # when [audit] checkpoint_local_only = true
```

Otherwise pass `--checkpoints` the saved ntfy checkpoint stream, or
omit it for a self-consistency check only.

## The E2E overlay

CI layers three files: `docker-compose.yml`, `compose.vpn.yml` and
`e2e/compose.e2e.yml`, run with `--profile vaultwarden`. The overlay
adds the fixture Vaultwarden, a headless Chromium agent host, and the
paths the compose E2E test
(`crates/kharond/tests/req_dep_002_compose_e2e.rs`) writes into
`e2e/run/`. It also adds `fake-edge`, which joins the holder's
namespace as cloudflared does and probes kharond's two loopback
listeners across kharond restarts. CI runs it from
`.github/workflows/image.yml`.

A second variant covers path B over WebSocket with no VPN. It layers
`docker-compose.yml` and `e2e/compose.e2e-ws.yml` (no `compose.vpn.yml`,
no `wg` network, no `[api]`), and
`crates/kharond/tests/req_arch_002_compose_ws_e2e.rs` drives it. Its
`fake-edge` is a TLS-terminating socat in the holder's namespace
(standing in for Cloudflare), and the agent host's
`kharon-agent-connector` dials `wss://kharon.e2e.test:8443/connector`
through it. Fills go through `POST /mcp` by way of that edge. The test
needs the host to accept connections from the compose bridges (it serves
its test page on the `edge` gateway, `10.67.0.254`). The `compose-e2e-ws`
job in `.github/workflows/image.yml` runs it.
