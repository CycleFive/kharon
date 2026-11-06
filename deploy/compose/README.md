# kharond with Docker Compose

`docker-compose.yml` runs kharond from the repository's `Dockerfile`
next to a Vaultwarden server (REQ-DEP-001, REQ-DEP-002). It is an
example to adapt, not a hardened deployment. The
[deployment guide](../../docs/deployment.md) covers the rest: the
kharon account's master password, the WireGuard link, and setting up
the agent host.

## Run it

```sh
cd deploy/compose
docker compose build kharon
docker run --rm -it --entrypoint kharon kharon:local init  # the account's master password, shown once
# create the kharon account with it, then its org, collection and API key (see the guide)
cp kharon.toml.example kharon.toml        # then edit: org, collections, agents, CDP endpoint
cp /path/to/bw-api-key.json secrets/kharon_bw_api_key.json
docker compose up -d
docker compose exec kharon kharon unlock  # owner unlock, master password on the tty
docker compose exec kharon kharon status
```

`secrets/` is git-ignored. kharond reads the API key from
`/run/secrets/kharon_bw_api_key`.

## What the example sets

- The image is distroless `static`, runs as uid 10001 with a
  read-only root filesystem; state lives in the `kharon-data` volume
  at `/data`, which also holds the owner socket.
- No ports are published. The agent API listens on `10.66.0.1:8787`
  on the `wg` network, which stands in for the WireGuard interface to
  the agent host; kharond refuses a wildcard `[api] listen`
  (REQ-DEP-006). ntfy approve/deny
  (`/owner/approve/<token>`, `/owner/deny/<token>`) is on the owner
  UI listen address once `[owner_ui]` is set. The action URL uses
  that loopback address; see the
  [deployment guide](../../docs/deployment.md#ntfy-approve-and-deny-req-apr-004-req-dep-006).
- `memlock` is unlimited so `require_mlock` holds, and core dumps are
  off. `cap_add: IPC_LOCK` has no effect for a non-root uid; the
  ulimit is what makes `mlock` succeed.
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

## The E2E overlay

`e2e/compose.e2e.yml` adds the fixture Vaultwarden, a headless
Chromium agent host, and the paths the compose E2E test
(`crates/kharond/tests/req_dep_002_compose_e2e.rs`) writes into
`e2e/run/`. CI runs it from `.github/workflows/image.yml`.
