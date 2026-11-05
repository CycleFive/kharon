# kharond with Docker Compose

`docker-compose.yml` runs kharond from the repository's `Dockerfile`
next to a Vaultwarden server (REQ-DEP-001, REQ-DEP-002). It is an
example to adapt, not a hardened deployment.

## Run it

```sh
cd deploy/compose
cp kharon.toml.example kharon.toml        # then edit: org, collections, agents, CDP endpoint
cp /path/to/bw-api-key.json secrets/kharon_bw_api_key.json
docker compose up -d --build
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
  (REQ-DEP-006).
- `memlock` is unlimited so `require_mlock` holds, and core dumps are
  off. `cap_add: IPC_LOCK` has no effect for a non-root uid; the
  ulimit is what makes `mlock` succeed.
- All capabilities are dropped and `no-new-privileges` is set. A
  seccomp profile (SPEC §9) is not written yet.

The CDP endpoint in `kharon.toml` is used as written, so it must be
the agent host's full browser WebSocket URL
(`ws://<agent-host>:9222/devtools/browser/<id>`), which changes each
time Chromium starts.

## The E2E overlay

`e2e/compose.e2e.yml` adds the fixture Vaultwarden, a headless
Chromium agent host, and the paths the compose E2E test
(`crates/kharond/tests/req_dep_002_compose_e2e.rs`) writes into
`e2e/run/`. CI runs it from `.github/workflows/image.yml`.
