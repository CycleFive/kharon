# N1 portable compose package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Change `deploy/compose` so kharond and cloudflared share one network namespace owned by a do-nothing holder container. Every kharond listener is on loopback. There's no inbound port and no VPN in the base case, and the CI compose E2E proves the edge outlives kharond restarts (#207).

**Architecture:** A pinned `pause` holder owns the namespace. `kharon` and (profile `edge`) `cloudflared` join it with `network_mode: "service:holder"`, so a kharond restart or recreate never strands the tunnel. Vaultwarden moves under a `vaultwarden` profile; the base vault is the customer's Bitwarden cloud account. WireGuard becomes an overlay (`compose.vpn.yml`) that puts the holder on `wg`. The CI overlay adds a `fake-edge` container in the holder's namespace that probes both loopback listeners across restarts.

**Tech Stack:** Docker Compose (v2 file format, profiles, `!override`), Rust integration tests (`crates/kharond/tests`), serde, GitHub Actions (`image.yml`).

**Spec:** `docs/superpowers/specs/2026-11-09-portable-gateway-design.md` (N1, *Duet's calls*, *The shape*), issue #207's ACs, and the claim comment https://github.com/CycleFive/kharon/issues/207#issuecomment-6750107887 (the builder's calls and measurements).

## Global Constraints

- Holder image: `registry.k8s.io/pause:3.10@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a`.
- cloudflared image: `cloudflare/cloudflared:2026.10.4@sha256:c6c7ae1d5dfdcb094ad344ed68ccffc26635c9c6be80965664c33baf064b0515`. The image's user is uid 65532, and its entrypoint is `cloudflared --no-autoupdate`.
- The cloudflared command is exactly `["tunnel", "--metrics", "127.0.0.1:20241", "run", "--token-file", "/run/secrets/cloudflared_tunnel_token"]`. Without `--metrics`, cloudflared in a container binds `0.0.0.0:20241` (measured).
- The tunnel token is the compose secret `cloudflared_tunnel_token`, file `./secrets/cloudflared_tunnel_token`. On the host it is owned by `65532:65532` with mode `0400`. It is never in `environment` (`TUNNEL_TOKEN`), never in argv (`--token`), and never in the repo or an image.
- Listeners:
  - base `[api]`: `127.0.0.1:8787`;
  - `[public_ingress]`: `127.0.0.1:8790`;
  - `[owner_ui]` in the E2E: `127.0.0.1:8788`, origin `http://localhost:8788`;
  - VPN overlay `[api]`: `10.66.0.1:8787`.
- `wg` network: subnet `10.66.0.0/24`, gateway `10.66.0.254`, holder `10.66.0.1`, agent host `10.66.0.2` (unchanged values, new file).
- Profiles: `edge` (cloudflared) and `vaultwarden` (Vaultwarden). Overlay file: `deploy/compose/compose.vpn.yml`.
- Tunnel routes in docs say `http://127.0.0.1:8790`, never `localhost`.
- Rust: typed serde structs for any JSON this code reads or writes. No `serde_json::json!`/`Value` in new code. Existing CDP code in the E2E keeps its `Value` use.
- Gates: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Commits end with these two lines, in this order:

  ```
  Claude-Session: https://claude.ai/code/session_017zqkE9gtxZrLyEWBDCjXMG
  Co-Authored-By: Claude & Lothrop (cycle.five@proton.me)
  ```

  No other `Co-Authored-By` line.
- No version bump (the workspace is `0.0.0`).

## Review Focus

1. **Compose on the CI runner recreates the holder on `up --force-recreate kharon`** (a different compose version from the local 5.7), stranding fake-edge. Task 2's restart checks compare the holder and fake-edge container IDs and start times, so this fails loudly instead of passing by accident.
2. **The probe passes before kharond is back.** `compose restart` returns after the start, while kharond binds a moment later. Task 2 polls each probe up to 60 s, and the recreate check asserts kharond's container ID changed, so a check can't pass by racing the old process.
3. **A stray listener in the shared namespace** (cloudflared metrics, or any future joiner) is reachable from the bridge. Task 1 pins `--metrics 127.0.0.1:20241` in a test. Task 2's `ss` check refuses any non-loopback listener other than kharond's `wg` address.
4. **The fake edge or the `wg` network leaks into the base file.** Task 1 asserts the base config's services are exactly `{holder, kharon, cloudflared, vaultwarden}` and the base holder's networks are exactly `{default}`.
5. **The example config drifts from what kharond accepts.** Task 1 parses `kharon.toml.example` (placeholder hash swapped for a real one) with `Config::from_toml_str` in the normal `cargo test` run.

---

### Task 1: The compose package, the VPN overlay and the example config

**Files:**
- Modify: `deploy/compose/docker-compose.yml` (rewrite)
- Create: `deploy/compose/compose.vpn.yml`
- Modify: `deploy/compose/kharon.toml.example` (rewrite)
- Create: `deploy/compose/.gitignore` (one line: `/.env`)
- Create: `crates/kharond/tests/req_dep_006_compose_package.rs`

**Interfaces:**
- Produces:
  - `docker-compose.yml` services `holder`, `kharon`, `cloudflared` (profile `edge`) and `vaultwarden` (profile `vaultwarden`). There is no top-level `vw` or `wg` network; the holder declares `networks: { default: {} }`, in mapping form so overlays can merge.
  - The secret `cloudflared_tunnel_token` and the existing `kharon_bw_api_key`.
  - `compose.vpn.yml`, which adds `wg` (`10.66.0.1`) to `holder` and defines the `wg` network. Task 2 layers it under the E2E overlay.

**`docker-compose.yml` content decisions:**
- **`holder`**:
  - `restart: unless-stopped`, `read_only: true`, `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`;
  - no ports.
- **`kharon`**:
  - keeps today's `build`, `image`, `restart`, `user`, `read_only`, `cap_drop`/`cap_add`, `ulimits`, `security_opt`, `volumes` and `secrets`;
  - replaces `networks:` with `network_mode: "service:holder"`;
  - no ports.
- **`cloudflared`**:
  - the Global Constraints image and command;
  - `profiles: [edge]`, `restart: unless-stopped`, `network_mode: "service:holder"`;
  - `read_only: true`, `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]`;
  - `secrets: [cloudflared_tunnel_token]`.
- **`vaultwarden`**:
  - today's image and volume;
  - `profiles: [vaultwarden]`;
  - no `networks` key, so it is on `default`.
- **The header comment** is rewritten to say:
  - the managed default: the customer's Bitwarden cloud vault, cloudflared beside kharond, no inbound port;
  - why there is a holder: a joiner of `service:kharon` is stranded when kharond restarts;
  - that the profiles and the VPN overlay exist;
  - the E2E overlay order.

  Keep it under about 30 lines; the README carries the walkthrough.

**`kharon.toml.example` content decisions:**
- `[bitwarden] server = "https://vault.bitwarden.com"`, with a comment: `.eu` for EU accounts, or `"http://vaultwarden:80"` with the `vaultwarden` profile.
- `[agents.assistant]` keeps `token_hash = "$argon2id$..."` and `cdp = { endpoint = "ws://10.66.0.2:9222", via = "wireguard" }`. The comment says fills need a path to the agent's browser: until #199, that path is a VPN (`compose.vpn.yml`). Without one, MCP calls, grants and approvals still work.
- `[api] listen = "127.0.0.1:8787"`, with a comment: the daemon needs it. It is on loopback, so nothing outside the namespace reaches it. The VPN overlay moves it to `10.66.0.1:8787`.
- `[public_ingress] listen = "127.0.0.1:8790"`, uncommented, with a comment: only what shares the holder's namespace (cloudflared) reaches it. Tunnel route: `http://127.0.0.1:8790`.
- `[approval]` ntfy unchanged.
- `[owner_ui]` stays commented out. The comment says that under compose its loopback is inside the holder's namespace, out of reach of an SSH forward. Use the CLI (`docker compose exec kharon kharon …`). Publishing it behind the edge is #208.
- The path-B `[connector]` lines stay commented, under a note that they belong with a VPN or public address (overlay).

- [ ] **Step 1: Write the tests** in `crates/kharond/tests/req_dep_006_compose_package.rs`

  The module doc names #207, REQ-DEP-002 and REQ-DEP-006, and says the docker-gated tests run from `image.yml`. Use `std::process::Command` directly, not `docker_support`.

  Typed structs, deserialized from `docker compose … config --format json`. Unknown fields are ignored; don't use `deny_unknown_fields`.

  ```rust
  #[derive(Deserialize)] struct Compose { services: BTreeMap<String, Service>, #[serde(default)] secrets: BTreeMap<String, TopSecret> }
  #[derive(Deserialize)] struct Service {
      image: Option<String>, network_mode: Option<String>,
      #[serde(default)] ports: Vec<serde::de::IgnoredAny>,
      #[serde(default)] networks: BTreeMap<String, Option<ServiceNetwork>>,
      #[serde(default)] command: Vec<String>,
      #[serde(default)] environment: BTreeMap<String, Option<String>>,
      #[serde(default)] secrets: Vec<ServiceSecret>,
      #[serde(default)] profiles: Vec<String>,
      #[serde(default)] read_only: bool,
      #[serde(default)] cap_drop: Vec<String>,
  }
  #[derive(Deserialize)] struct ServiceNetwork { ipv4_address: Option<String> }
  #[derive(Deserialize)] struct ServiceSecret { source: String }
  #[derive(Deserialize)] struct TopSecret { file: Option<String> }
  ```

  `fn config(overlays: &[&str]) -> Compose` runs these and asserts success:

  ```
  docker compose -f <deploy/compose>/docker-compose.yml [-f <deploy/compose>/<overlay>]… --profile edge --profile vaultwarden config --format json
  ```

  The tests:
  - `n1_example_config_is_loopback_only` (**not** ignored).
    - Read `deploy/compose/kharon.toml.example`.
    - Replace `"$argon2id$..."` with `format!("{:?}", kharond::api::token::generate("assistant").1)`, a quoted TOML string.
    - `Config::from_toml_str` must succeed.
    - Assert:
      - `api.listen == "127.0.0.1:8787"`;
      - `public_ingress.listen == "127.0.0.1:8790"` and `public_ingress.tls.is_none()`;
      - `connector.is_none()` and `owner_ui.is_none()`;
      - `Source::Sync(bw)` with `bw.server.as_str() == "https://vault.bitwarden.com/"`.
  - `n1_base_compose_publishes_nothing_and_shares_the_holder_netns` (`#[ignore = "needs docker (image.yml)"]`). On `config(&[])`, assert:
    - the service keys are exactly `holder, cloudflared, kharon, vaultwarden`;
    - every `ports` is empty;
    - `kharon.network_mode` and `cloudflared.network_mode` are `Some("service:holder")`;
    - `kharon.networks` is empty;
    - `holder.network_mode` is `None`, and its `networks` keys are exactly `["default"]`.
  - `n1_holder_and_cloudflared_are_pinned` (ignored): `holder.image` and `cloudflared.image` equal the two Global Constraints strings, and both have `read_only` and `"ALL"` in `cap_drop`.
  - `n1_cloudflared_reads_its_token_from_a_secret_file` (ignored). Assert:
    - `cloudflared.command` equals the Global Constraints command;
    - no element equals `"--token"`;
    - `environment` has no `TUNNEL_TOKEN` key;
    - `secrets` has `source == "cloudflared_tunnel_token"`;
    - the top-level `secrets["cloudflared_tunnel_token"].file` ends with `/secrets/cloudflared_tunnel_token`;
    - `profiles == ["edge"]`, and `vaultwarden.profiles == ["vaultwarden"]`.
  - `n1_vpn_overlay_puts_the_holder_on_wg` (ignored): `config(&["compose.vpn.yml"])` gives holder networks with keys `default` and `wg`, `wg.ipv4_address == Some("10.66.0.1")`, and `kharon.network_mode` still `service:holder`.

- [ ] **Step 2: Run them against the current files and watch them fail**

  ```
  cargo test -p kharond --test req_dep_006_compose_package -- --include-ignored
  ```

  Expected: FAIL. The example config has no `[public_ingress]`, and the base compose has `networks` on `kharon` and no `holder`.

- [ ] **Step 3: Write the four files** per the content decisions above.

- [ ] **Step 4: Run the tests and watch them pass**

  ```
  cargo test -p kharond --test req_dep_006_compose_package -- --include-ignored
  ```

  Expected: 5 passed. Also run `docker compose -f deploy/compose/docker-compose.yml --profile edge config -q`, which must exit 0 with no token file present.

- [ ] **Step 5: Gates, then commit**

  Run `cargo fmt --all --check` and `cargo clippy -p kharond --all-targets -- -D warnings`.

  Commit message: `feat(dep): compose netns holder, cloudflared edge profile, loopback-only base (#207)`.

---

### Task 2: The CI compose E2E on the new package, and the edge-survives-restarts check

**Files:**
- Modify: `deploy/compose/e2e/compose.e2e.yml`
- Modify: `.github/workflows/image.yml` (the `COMPOSE` env, the trigger `paths`, and a step for the Task 1 tests)
- Modify: `crates/kharond/tests/req_dep_002_compose_e2e.rs`

**Interfaces:**
- Consumes: Task 1's services, `compose.vpn.yml`, and the profile `vaultwarden`.
- Produces: the container names `kharon-e2e-holder` and `kharon-e2e-fake-edge`, and `Run.edge: Vec<EdgeCheck>`.

**Content decisions:**
- **`compose.e2e.yml`**:
  - `holder` gets `container_name: kharon-e2e-holder` and `restart: "no"`.
  - A new `fake-edge` service:
    - `image: kharon-e2e-agent-host:local` (it carries socat and is already built in that job);
    - `container_name: kharon-e2e-fake-edge`, `restart: "no"`;
    - `network_mode: "service:holder"`;
    - `entrypoint: ["sleep", "infinity"]`;
    - no volumes or networks.
  - The `agent-host` service still sits on `wg` (now defined in `compose.vpn.yml`).
  - The header comment adds the fake-edge and the file order.
- **`image.yml`**:
  - `COMPOSE` becomes `docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/compose.vpn.yml -f deploy/compose/e2e/compose.e2e.yml -p kharon-e2e --profile vaultwarden`.
  - Add `crates/kharond/tests/req_dep_006_compose_package.rs` to `paths`.
  - Add a step before the E2E step, "N1 compose package (REQ-DEP-006)", which runs `cargo test -p kharond --test req_dep_006_compose_package -- --ignored`.
- **The E2E test**:
  - The `compose()` helper uses the same three files plus `--profile vaultwarden`.
  - `kharond_toml` appends `[public_ingress] listen = "127.0.0.1:8790"`, and `[owner_ui]` with `listen = "127.0.0.1:8788"` and `origin = "http://localhost:8788"`.
  - Constants: `PUBLIC_INGRESS = "127.0.0.1:8790"`, `OWNER_UI = "127.0.0.1:8788"`, `HOLDER = "kharon-e2e-holder"`, `FAKE_EDGE = "kharon-e2e-fake-edge"`.
  - The module doc gains the fourth AC paragraph (N1, #207).

**Probe and checks (new code in the E2E file):**
- `struct EdgeProbe { mcp: u16, owner_home: u16 }`, where 0 means no HTTP status line came back.
- `fn edge_probe() -> EdgeProbe` makes two `docker exec -i kharon-e2e-fake-edge socat -t 5 - TCP:<addr>` calls through `docker_support::docker_raw`, with the raw request on stdin, and parses the status code from the first line:
  - to `PUBLIC_INGRESS`: `POST /mcp HTTP/1.1`, `Host: kharon.twkr.io`, `Content-Type: application/json`, `Content-Length: 2`, `Connection: close`, body `{}`. Expect 401.
  - to `OWNER_UI`: `GET / HTTP/1.1`, `Host: localhost:8788`, `Connection: close`. Expect 200.
- `fn wait_edge() -> EdgeProbe` polls `edge_probe` every 500 ms until it returns (401, 200), or 60 s pass. Either way it returns the last probe.
- `fn identity(container: &str) -> String` is `docker inspect -f '{{.Id}} {{.State.StartedAt}}'`.
- `struct EdgeCheck { after: &'static str, probe: EdgeProbe, holder_kept: bool, edge_kept: bool, kharond_replaced: bool }`.
- In `setup()`:
  - Start fake-edge right after kharond is up: `compose(["up", "-d", "--no-build", "fake-edge"])`.
  - After `kharon lock`, and before building `Run`, record:
    1. `"start"`: `wait_edge`, then take the holder and fake-edge identities and kharond's ID.
    2. `"restart kharon"`: `compose(["restart", "kharon"])`, then `wait_edge`. Compare identities; `kharond_replaced` is false and expected false.
    3. `"up --force-recreate kharon"`: `compose(["up", "-d", "--no-build", "--force-recreate", "kharon"])`, then `wait_edge`. Compare identities; `kharond_replaced` compares kharond's container ID with step 1's.
    4. `"restart (whole stack)"`: `compose(["restart"])`, then `wait_edge`. Identities are not compared.
- `req_dep_006_ss_ltn_shows_only_the_wg_listen_address` becomes `req_dep_006_ss_ltn_shows_only_wg_and_loopback_listeners`:
  - kharond's sorted listeners equal sorted `[AGENT_API, OWNER_UI, PUBLIC_INGRESS]`;
  - every other listener starts with `127.0.0.11:`;
  - the owner-socket assertion is unchanged.
- `compose_harness_fill_budget_covers_arch_004_and_leaves_other_defaults` also asserts `public_ingress.listen` and `owner_ui.listen` against the new constants.

- [ ] **Step 1: Write the new test**, `n1_edge_reaches_both_loopback_listeners_across_kharond_restarts` (`#[ignore = "needs the compose E2E stack (image.yml)"]`).
  - `r.edge` has 4 entries, in the order above.
  - Every `probe` is `EdgeProbe { mcp: 401, owner_home: 200 }`. Derive `PartialEq, Debug`.
  - Entries 2 and 3 have `holder_kept && edge_kept`.
  - Entry 3 has `kharond_replaced`.

  Update the `ss` test and the harness-config test as above.

- [ ] **Step 2: Watch the harness-config test fail**

  Run `cargo test -p kharond --test req_dep_002_compose_e2e compose_harness`. Expected: FAIL, because there's no `public_ingress` yet. Then implement the TOML, the overlay, the `compose()` helper, the probes and the `setup()` sequence.

- [ ] **Step 3: Verify what can run locally**
  - `cargo test -p kharond --test req_dep_002_compose_e2e` passes the non-ignored test.
  - `cargo test -p kharond --test req_dep_002_compose_e2e -- --ignored --list` lists the five ignored tests.
  - This exits 0:

    ```
    docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/compose.vpn.yml -f deploy/compose/e2e/compose.e2e.yml -p kharon-e2e --profile vaultwarden config -q
    ```

  The full E2E needs passwordless `sudo nsenter` and the seeded fixture, so it runs in CI (`compose-e2e`), not locally.

- [ ] **Step 4: Gates, then commit**

  Run `cargo fmt --all --check`, `cargo clippy -p kharond --all-targets -- -D warnings` and `cargo test --workspace`.

  Commit message: `test(dep): compose E2E on the holder netns; edge survives kharond restarts (#207)`.

---

### Task 3: Docs: README, deployment guide, cloudflared example

**Files:**
- Modify: `deploy/compose/README.md` (rewrite)
- Modify: `docs/deployment.md` (*Broker host* intro, *Public gateway* section)
- Modify: `deploy/cloudflared/config.yml` (header comment only)
- Modify: `crates/kharond/tests/req_dep_006_compose_package.rs` (one test)

**Interfaces:**
- Consumes: Task 1's names (profiles, secret file, overlay, listener addresses) and Task 2's fake-edge description.

**Content decisions:**
- **`README.md` › Run it.** The default run:
  - `cd deploy/compose`;
  - `printf 'COMPOSE_PROFILES=edge\n' > .env` (a self-hoster with the bundled vault uses `edge,vaultwarden`; a VPN user adds `COMPOSE_FILE=docker-compose.yml:compose.vpn.yml`);
  - the existing init / token mint / API-key steps;
  - write the tunnel token without echoing it or putting it in argv (`umask 077`; `cloudflared tunnel token <name> > secrets/cloudflared_tunnel_token`, or `read -rs T` then `printf '%s' "$T" > …`);
  - `sudo chown 65532:65532` and `chmod 0400` on it;
  - `docker compose up -d`, unlock, status.

  It also says that with `edge` on and no token file, `up` fails with "bind source path does not exist", and that this is intended.
- **`README.md` › What the example sets.**
  - The holder and why it exists (kharond restarts never strand the tunnel).
  - Every kharond listener is on loopback, and nothing is published.
  - cloudflared's metrics are pinned to loopback.
  - The default vault is the customer's own Bitwarden Password Manager on Bitwarden cloud. The customer unlocks it, and kharond keeps the keys only in memory. The Vaultwarden profile is for self-hosters. Bitwarden Secrets Manager is not the default (at most an optional adapter later).
  - The owner UI note: CLI now, published with #208.
  - Fills need `compose.vpn.yml` until #199.
  - Keep the existing seccomp, `memlock` and API-key-ownership paragraphs.
- **`README.md` › The E2E overlay.** The three files, and the fake-edge.
- **`deployment.md` › Broker host.**
  - The vault is the customer's own Bitwarden Password Manager by default, with Vaultwarden as the self-host profile.
  - It points to the compose README.
- **`deployment.md` › Public gateway, rewritten** as the default "cloudflared beside kharond, from a tunnel token":
  - **Intro:** the hop to kharond is loopback, so there's no TLS on it. kharond's own allow-list is the line that holds, because with a token-managed tunnel the dashboard is the only edge allow-list. Don't set *HTTP Host Header* on a route.
  - **`[public_ingress]`:** `127.0.0.1:8790` by default. The TLS variant is for the separate-guest alternative.
  - **Where cloudflared runs:**
    1. compose `edge` profile, in the holder namespace (default);
    2. host-networked beside a host-networked kharond: one namespace, every local process shares the loopback, acceptable on a single-purpose host;
    3. alternative: a separate guest over the tailnet, with TLS and `caPool`, using the locally managed `deploy/cloudflared/config.yml`.
  - **Creating the tunnel (owner):**
    - dashboard-managed;
    - public-hostname routes `kharon.twkr.io` `^/mcp$` and `^/connector$`, both to `http://127.0.0.1:8790`, plus a catch-all 404;
    - getting the token into the secret file as in the README.
    - Keep the `cloudflared tunnel create/route dns` commands under the locally-managed alternative.
  - **Running it:**
    - compose: `docker compose up -d`, with `edge` in `.env`;
    - host-networked: a systemd unit with `tunnel --metrics 127.0.0.1:20241 run --token-file /etc/cloudflared/kharon.token` plus the existing hardening lines;
    - the existing `config.yml` unit stays under the alternative.
  - **Verifying:**
    - keep the internet-side `curl` loop;
    - the origin-side check becomes:

      ```
      docker run --rm --network "container:$(docker compose ps -q holder)" alpine:3.22 wget -qSO- http://127.0.0.1:8790/v1/status
      ```

      which gets a 404 with the JSON body. `POST /mcp` gets 401.
  - **Owner hostname:** one short paragraph. `kharon-owner.twkr.io` → `http://127.0.0.1:8788` comes with #208 (public origin, Host/Origin checks, throttling, optional Access); until then, don't route it. N3's MCP authorization adds routes (`/.well-known/oauth-protected-resource`, the token endpoint) later.
  - **Rollback:**
    - compose: `docker compose stop cloudflared`, and drop `edge` from `.env`;
    - host: `systemctl disable --now`;
    - keep the tunnel-delete text.
  - The WAF section stays.
- **`deploy/cloudflared/config.yml` header:** this file is the locally managed alternative for cloudflared on a separate guest. The default is a token-managed tunnel beside kharond (`deploy/compose`, profile `edge`), whose routes point at `http://127.0.0.1:8790`.

- [ ] **Step 1: Write the test** `n1_tunnel_routes_in_docs_use_127_0_0_1` (not ignored), in `req_dep_006_compose_package.rs`.
  - It reads `docs/deployment.md`, `deploy/compose/README.md`, `deploy/cloudflared/config.yml`, `deploy/compose/docker-compose.yml` and `deploy/compose/kharon.toml.example`.
  - Assert no line contains both `localhost` and `8790`.
  - Assert no line containing `service:`, `→` or `route` also contains `localhost`.
  - Also assert `deploy/compose/README.md` contains `COMPOSE_PROFILES=edge`, `65532:65532` and `compose.vpn.yml`, and `docs/deployment.md` contains `http://127.0.0.1:8790` and `--token-file`.

- [ ] **Step 2: Run it and watch it fail**

  Run `cargo test -p kharond --test req_dep_006_compose_package n1_tunnel_routes`. Expected: FAIL, because the README lacks `COMPOSE_PROFILES=edge`.

- [ ] **Step 3: Write the docs** per the content decisions above.

- [ ] **Step 4: Run the tests and watch them pass**

  Run that test, plus `cargo test -p kharond --test req_arch_001_agent_host_docs` (the README must still link `docs/deployment.md`, and the agent-host section checks still pass).

- [ ] **Step 5: Gates, then commit**

  Run `cargo fmt --all --check` and `cargo test --workspace`.

  Commit message: `docs(dep): compose package and public gateway default to cloudflared beside kharond (#207)`.
