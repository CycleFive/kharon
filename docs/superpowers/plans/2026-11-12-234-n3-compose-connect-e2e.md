# N3 compose E2E: a fake dashboard runs Connect, refresh, reuse-kill and Disconnect — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A compose E2E in which the test binary plays an allow-listed dashboard and the owner's browser, and drives kharond's real HTTP OAuth surface through two fake TLS edges: discovery, authorize, passkey consent, code, tokens, an `/mcp` call, refresh rotation, the single 30 s retry, the reuse kill, Disconnect, `no_browser`, and no token in any log or state file.

**Architecture:**
- A new overlay, `deploy/compose/e2e/compose.e2e-oauth.yml`, on the **base** `deploy/compose/docker-compose.yml`. No VPN overlay, no agent host, no connector, no Chromium session.
- Two fake edges (socat terminating TLS in the holder's netns, as the ws E2E does): the agent hostname to kharond's public ingress, the owner hostname to the owner UI.
- The test binary runs on the docker host and plays three parts:
  - **the dashboard's web server**: an HTTPS listener on the edge network's gateway address that serves the client metadata document (CIMD) kharond fetches;
  - **the dashboard's backend**: discovery, `/oauth/token`, `/mcp`;
  - **the owner's browser**: passkey enrolment and sign-in, the consent ceremony, Disconnect, with the software authenticator `owner_ui_support::VirtAuth`.
- No existing test drives the OAuth flow over real HTTP; all of it is in-process today. This test is the first, so request shapes come from the handlers, not from another test.

**Tech stack:** Docker Compose overlay, socat (OpenSSL), rcgen, tokio/rustls test code, GitHub Actions (`image.yml`).

**Spec:** issue #234 (the nine assertions in its body). Behaviour under test: SPEC REQ-OAU-001 to REQ-OAU-008, and `docs/superpowers/specs/2026-11-10-n3-mcp-oauth-connect-design.md` (D1, D2, D6, I1, I5). Where this plan and those disagree, they win.

## Global Constraints

- **Test, CI and compose-overlay change only.** Do not edit `crates/*/src/**`, the root `Dockerfile`, `deploy/compose/docker-compose.yml`, `deploy/compose/compose.vpn.yml`, `deploy/compose/e2e/compose.e2e.yml`, `deploy/compose/e2e/compose.e2e-ws.yml`, `deploy/compose/kharon.toml.example`, `SPEC.md` or `docs/deployment.md`. If the product is wrong, stop and report it; do not work around it in the test.
- **The existing tests must behave the same.** `req_arch_002_compose_ws_e2e`, `req_dep_002_compose_e2e`, `req_apr_009_edge`, `req_oau_005_connections` compile and pass as before. Code moved in Task 1 is moved, not rewritten.
- **Names:** compose project `kharon-e2e-oauth`; container names prefixed `kharon-e2e-oauth-`; run directory `deploy/compose/e2e/run-oauth/` (add it to `deploy/compose/e2e/.gitignore`); test file `crates/kharond/tests/req_oau_234_compose_connect_e2e.rs`; CI job `compose-e2e-oauth`.
- **Hostnames:** agent `kharon.e2e.test`, owner `kharon-owner.e2e.test`, dashboard `dashboard.e2e.test`. Issuer and owner origin are exactly `https://kharon-owner.e2e.test`. The resource is exactly `https://kharon.e2e.test/mcp`. Neither carries a port: kharond cannot express one (`Discovery::new`, `api/oauth.rs`).
- **Addresses:** one network, `edge`, subnet `203.0.113.0/24` (TEST-NET-3), gateway `203.0.113.254` (the docker host). Holder `203.0.113.1`. The fake edges listen on `203.0.113.1:8443` (agent, to `127.0.0.1:8790`) and `203.0.113.1:8444` (owner, to `127.0.0.1:8788`). The dashboard listener binds `203.0.113.254` on a port the OS picks.
  - Why TEST-NET: kharond refuses to fetch a CIMD from a loopback, RFC 1918, CGNAT or link-local address, or from an address of its own netns (`cimd.rs` `address_refused`). `203.0.113.254` is none of those.
- **Host and Origin headers.** Every request to the agent edge carries `Host: kharon.e2e.test`; every request to the owner edge carries `Host: kharon-owner.e2e.test`; every owner POST that the UI gates carries `Origin: https://kharon-owner.e2e.test`. The test dials the socket address and sets SNI and `Host` itself, so the edge ports never appear in a header.
- **`CF-Connecting-IP`.** The test adds it, as the real edge would: `198.51.100.10` on the owner-browser requests, `198.51.100.20` on the dashboard-backend requests (`/oauth/token`, `/mcp`). The token endpoint counts 4xx answers per source and throttles at 10 in 600 s (`owner_ui/throttle.rs`); the scenario makes at most 3 on purpose. Do not add more.
- **The dashboard backend sends no `Authorization` header to `/oauth/token` or `/oauth/revoke`.** A public client does not, and PR #279 makes kharond refuse one there.
- **Secrets.** Tokens, codes, the enrolment code, the session cookie and TLS keys are generated fresh each run, never passed on a command line, and never printed: every assert message and error string that could hold one goes through `compose_support::redact`.
- **No host `sudo`.** Files kharond reads are written with `compose_support::write_public` (0644), as the ws E2E does. State files are read from the data volume by a one-off container running as `10001:10001` (the pattern in `compose_support::owner_approve`).
- **Typed serde for new code:** structs deriving `Serialize`/`Deserialize` for every JSON body the test builds or reads (metadata documents, the CIMD, consent bodies, the token answer, audit lines). No `serde_json::json!`, no `serde_json::Value`, except where an existing helper's signature already takes one (`VirtAuth` returns `Json`).
- **Every cargo command** uses `CARGO_TARGET_DIR=/home/lothrop/projects/kharon-234/target`.
- **The compose stack cannot run on the dev box** (its firewall rejects container-to-host TCP, and this test needs kharond to reach the host). Locally you run the non-ignored tests, `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `docker compose … config`. The `#[ignore]`d tests run only in CI; the controller pushes and reads the job.
- **Commit trailer.** Every commit ends with exactly these two lines, and no other `Co-Authored-By`:
  ```
  Claude-Session: https://claude.ai/code/session_017zqkE9gtxZrLyEWBDCjXMG
  Co-Authored-By: Claude & Lothrop (cycle.five@proton.me)
  ```

## Review Focus

1. **Stale state from an earlier run.** Leftover `kharon-e2e-oauth` containers, the `kharon-e2e-oauth_kharon-data` volume or a `run-oauth/` directory must not break or skew a run. Setup starts by removing them, as `setup()` in the ws E2E does (lines 540–572). Test: none locally; the setup code is reviewed against the ws one.
2. **Short lifetimes.** The enrolment code and each WebAuthn ceremony live 120 s, an authorization code 60 s, and the refresh retry window is 30 s of wall-clock time. No step sleeps between obtaining one of these and using it. The scenario records `Instant`s around the rotation, the retry and the reuse, and fails with "runner too slow, not a product failure" if the retry was sent more than 20 s after the rotation.
3. **The CIMD fetch has three ways to fail that look alike** (name resolution through the holder's `/etc/hosts`, trust through `SSL_CERT_FILE`, the address class). All three answer `/oauth/authorize` with a 400 HTML page. When authorize does not answer 302, the error carries: the status, the redacted body, the dashboard listener's request count, and the last 50 lines of kharond's log.
4. **Vacuous secret scans.** A scan of an empty log or a missing file passes. Each scanned text has a positive control first: kharond's log contains its public-ingress listening line, `state.json` contains both Connect ids, the audit log contains `oauth_connect`.
5. **The throttle.** The three intended 4xx answers on `/oauth/token` come from `198.51.100.20`. A fourth unintended one is a bug in the test; a `429` anywhere fails the run with the source address in the message.

---

### Task 1: Shared transport helpers (no behaviour change)

**Files:**
- Modify: `crates/kharond/tests/compose_support/mod.rs`
- Modify: `crates/kharond/tests/owner_ui_support/mod.rs`
- Modify: `crates/kharond/tests/api_support/mod.rs` (only if step 4 needs it)
- Modify: `crates/kharond/tests/req_arch_002_compose_ws_e2e.rs` (call sites only)
- Create: `crates/kharond/tests/req_oau_234_compose_connect_e2e.rs` (the helper tests; Task 2 and 3 fill it)

**Interfaces:**
- Produces, in `compose_support`:
  - `pub fn edge_pki(hosts: &[&str]) -> (String, String, String)` returning `(ca_pem, leaf_pem, leaf_key_pem)`: one fresh CA and one leaf whose SANs are `hosts`. This is `edge_pki` from `req_arch_002_compose_ws_e2e.rs:416`, moved and given a slice; the ws test calls `edge_pki(&["kharon.e2e.test"])`.
  - `pub async fn https_raw(addr: SocketAddr, sni: &str, ca_pem: &str, request: &[u8]) -> Result<RawResponse, String>`: one TLS connection trusting only `ca_pem`, write `request`, read to EOF, parse with the parser `api_support::raw_request` uses. 30 s overall timeout. `RawResponse` is `api_support`'s.
- Produces, in `owner_ui_support`:
  - `pub fn request_bytes(origin: &str, req: &Http<'_>) -> Vec<u8>`: exactly the bytes `http()` sends today (it adds `Origin` to POSTs unless `no_origin`, `Connection: close`, `Content-Length`). `http()` becomes `raw_request(addr, &request_bytes(origin, &req))`.
- Produces, where the MCP request is built today (`api_support::mcp_request` / `mcp_call`, lines 504–550):
  - `pub fn mcp_call_bytes(host: &str, token: Option<&str>, tool: &str, arguments_json: &str) -> Vec<u8>`: the bytes of one `tools/call` POST with the given `Host`. Extract it from the existing function if the bytes are built inline; if a builder already exists, use that and add nothing.

- [ ] **Step 1: Write the failing test** in the new test file (not `#[ignore]`d):

```rust
#[tokio::test]
async fn https_raw_round_trips_through_a_tls_listener() {
    // A rustls listener on 127.0.0.1 with a leaf for "edge.test" from
    // edge_pki(&["edge.test"]). It answers every request with
    // "HTTP/1.1 418 I'm a teapot\r\nX-Probe: yes\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".
    let r = compose_support::https_raw(addr, "edge.test", &ca_pem,
        b"GET /x HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n\r\n").await.unwrap();
    assert_eq!(r.status, 418);
    assert_eq!(r.header("x-probe"), Some("yes"));
    assert_eq!(r.body, "ok");
    // A CA that did not sign the leaf is refused.
    let (other_ca, _, _) = compose_support::edge_pki(&["edge.test"]);
    assert!(compose_support::https_raw(addr, "edge.test", &other_ca, b"GET / HTTP/1.1\r\nHost: edge.test\r\n\r\n").await.is_err());
}

#[test]
fn request_bytes_matches_what_http_sends() {
    let req = owner_ui_support::Http::post("/owner/logout", Some("application/json"), "{}")
        .host("kharon-owner.e2e.test").cookie("__Host-kharon_owner=abc").header("CF-Connecting-IP", "198.51.100.10");
    let text = String::from_utf8(owner_ui_support::request_bytes("https://kharon-owner.e2e.test", &req)).unwrap();
    assert!(text.starts_with("POST /owner/logout HTTP/1.1\r\n"));
    for line in ["Host: kharon-owner.e2e.test\r\n", "Origin: https://kharon-owner.e2e.test\r\n",
                 "Cookie: __Host-kharon_owner=abc\r\n", "CF-Connecting-IP: 198.51.100.10\r\n", "Content-Length: 2\r\n"] {
        assert!(text.to_ascii_lowercase().contains(&line.to_ascii_lowercase()), "missing {line:?}");
    }
    assert!(text.ends_with("\r\n\r\n{}"));
}
```

- [ ] **Step 2: Run them, expect a compile failure** (`https_raw`, `edge_pki`, `request_bytes` not found):
  `cargo test -p kharond --test req_oau_234_compose_connect_e2e`
- [ ] **Step 3: Move `edge_pki`, add `https_raw`** (reuse the private `tls_client` at `compose_support:494`), **extract `request_bytes`**.
- [ ] **Step 4: Extract `mcp_call_bytes`** as described under Interfaces.
- [ ] **Step 5: Run** the new file (both tests pass), then `cargo test -p kharond --test req_arch_002_compose_ws_e2e --test req_apr_009_edge --test req_oau_005_connections --test req_oau_006_007_scopes` (pass, same counts as on `origin/master`), then fmt and clippy as in Global Constraints.
- [ ] **Step 6: Commit** `test(e2e): shared TLS request helpers for the compose tests (#234)`.

---

### Task 2: The stack, the dashboard's metadata server, sign-in through the owner edge, discovery, CI

**Files:**
- Create: `deploy/compose/e2e/compose.e2e-oauth.yml`
- Modify: `deploy/compose/e2e/.gitignore`
- Modify: `crates/kharond/tests/req_oau_234_compose_connect_e2e.rs`
- Modify: `.github/workflows/image.yml`

**Interfaces:**
- Consumes: Task 1's `edge_pki`, `https_raw`, `request_bytes`, `mcp_call_bytes`; `owner_ui_support::{Http, VirtAuth, b64url}`; `compose_support::{env, manifest, write_public, fixture_scope, data_volume_of, redact}`; `docker_support::{docker, docker_raw, wait_for_log}`.
- Produces, in the test file, for Task 3:
  - `struct Run` (behind the same `run()` / `static RUN` pattern as `req_arch_002_compose_ws_e2e.rs:359–363`) holding at least: `edge_ca: String`, `cookie: String` (the `__Host-kharon_owner=…` pair), `auth: Mutex<VirtAuth>`, `dashboard: Dashboard`, `client_id: String`, `redirect_uri: String`, `discovery: Discovered`.
  - `struct Dashboard { port: u16, fetches: Arc<AtomicUsize> }`.
  - `struct Discovered { resource: String, issuer: String, authorization_endpoint: String, token_endpoint: String, revocation_endpoint: String }`.
  - `async fn owner(run_edge_ca: &str, req: Http<'_>) -> RawResponse`: `https_raw("203.0.113.1:8444", "kharon-owner.e2e.test", ca, &request_bytes(OWNER_ORIGIN, &req.host(OWNER_HOST).header("CF-Connecting-IP", "198.51.100.10")))`.
  - `async fn agent_edge(ca: &str, request: &[u8]) -> RawResponse`: the same to `203.0.113.1:8443` with SNI `kharon.e2e.test`.

**The overlay.** Copy `compose.e2e-ws.yml` and change only this:
- container names and the header comment to the `kharon-e2e-oauth` names;
- drop `agent-host`, `connector` and the `harness` network;
- `holder`: `networks: edge: { ipv4_address: 203.0.113.1 }` and `extra_hosts: ["dashboard.e2e.test:203.0.113.254"]`. kharond joins the holder's netns, and Docker gives a container in `network_mode: service:x` the target's `/etc/hosts`; that is how kharond resolves the dashboard's name;
- `fake-edge`: `bind=203.0.113.1`, port 8443, to `TCP:127.0.0.1:8790`, mount `./e2e/run-oauth/edge:/edge:ro`;
- add `fake-edge-owner`: the same service on port 8444 to `TCP:127.0.0.1:8788`, container `kharon-e2e-oauth-fake-edge-owner`;
- `kharon`: mounts `./e2e/run-oauth/kharon.toml` and the vault CA as the ws overlay does (no connector cert or key), plus `./e2e/run-oauth/dashboard-ca.pem:/etc/kharon/e2e-roots.pem:ro` and `environment: { SSL_CERT_FILE: /etc/kharon/e2e-roots.pem }`. kharond's CIMD fetch trusts the native roots, and `rustls-native-certs` reads that variable; there is no config key for it;
- `secrets` and `volumes` as the ws overlay, with `run-oauth` and the `kharon-e2e-oauth-` volume name;
- `networks: edge: ipam: { config: [{ subnet: 203.0.113.0/24, gateway: 203.0.113.254 }] }`.
- Both fake edges use `image: kharon-e2e-agent-host:local` (it has socat). No service here builds it; CI builds it with `docker build` (below).

**kharond's config** (`fn kharond_toml(email, org, coll, token_hash, client_id) -> String`):

```toml
mode = "sync"

[bitwarden]
server = "https://vaultwarden"
email = "{email}"
api_key_file = "/run/secrets/kharon_bw_api_key"
organization_id = "{org}"
collection_ids = ["{coll}"]
ca_file = "/etc/kharon/vault-ca.pem"

# kharond refuses a config with no agent (config/raw.rs:340). This one is
# never used: the test's agents are Connect identities.
[agents.alpha]
token_hash = "{token_hash}"

[audit]
checkpoint_local_only = true

[public_ingress]
listen = "127.0.0.1:8790"
public_host = "kharon.e2e.test"

[owner_ui]
listen = "127.0.0.1:8788"
public_origin = "https://kharon-owner.e2e.test"

[oauth]
clients = ["{client_id}"]
```

If `[agents.alpha]` needs a `cdp` key to parse, copy the ws harness's line. The broker stays **locked** for the whole test: nothing here needs the vault, and `kharon_status` and the `no_browser` refusal both answer while locked.

**The dashboard's metadata server** (`async fn serve_dashboard(bind_ip: &str, leaf_pem, key_pem) -> Dashboard`, modelled on `compose_support::serve_page`): a rustls listener that reads one request head, and
- for `GET /client.json` answers `200`, `Content-Type: application/json`, `Cache-Control: max-age=3600`, `Connection: close`, with the typed document `{ client_id, client_name: "E2E Dashboard", redirect_uris: [redirect_uri], token_endpoint_auth_method: "none" }`, and adds one to `fetches`;
- for anything else answers `404`.
- `client_id` is `https://dashboard.e2e.test:{port}/client.json` and `redirect_uri` is `https://dashboard.e2e.test:{port}/callback`. The port is known only after the bind, so the listener is started **before** `kharon.toml` is written. Nothing ever requests `/callback`: the test reads the code out of the consent answer.

**`setup()`, in order:**
1. Stale cleanup and the run directory, as ws `setup()` lines 540–572 with the oauth names (subdirectory `edge` only).
2. Copy the API key JSON to `run-oauth/api-key.json`; `fixture_scope` for `org` and `coll`; `email` from `manifest()`.
3. `edge_pki(&["kharon.e2e.test", "kharon-owner.e2e.test"])`: leaf and key to `run-oauth/edge/{cert,key}.pem`, the CA kept as `edge_ca`. `edge_pki(&["dashboard.e2e.test"])`: the CA to `run-oauth/dashboard-ca.pem`, leaf and key to the dashboard listener.
4. `serve_dashboard("203.0.113.254", …)`. The address exists only once the network does, so first `compose up -d --no-build holder`.
5. Write `kharon.toml` (a throwaway `kharond::api::token::generate("alpha")` for the hash).
6. `compose up -d --no-build kharon fake-edge fake-edge-owner`; wait for `kharond: public ingress listening on 127.0.0.1:8790 (plain HTTP, loopback; POST /mcp only)` (`daemon.rs:752`), then poll `GET /` on the owner edge until it answers 200 (60 s, 500 ms).
7. Enrol and sign in through the owner edge, following `req_apr_009_edge.rs` `enroll_public_via` (:468) and `sign_in_from` (:933), with `owner()` as the transport, rp id `kharon-owner.e2e.test`, origin `https://kharon-owner.e2e.test`:
   - the enrolment code is the stdout of `docker exec kharon-e2e-oauth-kharond kharon passkey-enroll`, trimmed;
   - the session cookie is the `__Host-kharon_owner` pair from `Set-Cookie`.
8. Discovery (below), stored in `Run`.

**Discovery, as a client would do it.** Each document is read into a typed struct.
1. `POST /mcp` on the agent edge with no token (`mcp_call_bytes("kharon.e2e.test", None, "kharon_status", "{}")`): status 401, and `WWW-Authenticate` contains `resource_metadata="https://kharon.e2e.test/.well-known/oauth-protected-resource/mcp"`.
2. `GET` that path on the agent edge: `resource == "https://kharon.e2e.test/mcp"`, `authorization_servers == ["https://kharon-owner.e2e.test"]`, `scopes_supported` holds `kharon:read`, `kharon:fill`, `kharon:request`, `bearer_methods_supported == ["header"]`.
3. `GET /.well-known/oauth-authorization-server` on the owner edge: `issuer == "https://kharon-owner.e2e.test"`; the three endpoints are `{issuer}/oauth/authorize`, `/oauth/token`, `/oauth/revoke`; `code_challenge_methods_supported == ["S256"]`; `token_endpoint_auth_methods_supported == ["none"]`; `client_id_metadata_document_supported == true`.
4. Task 3 uses the **paths of the discovered endpoints**, not literals.

- [ ] **Step 1: Write the failing non-ignored tests:**

```rust
#[test]
fn oauth_harness_config_is_public_mode_with_one_client() {
    let cfg = kharond::config::Config::from_toml_str(&kharond_toml(
        "a@b.test", "org", "coll", &"0".repeat(64), "https://dashboard.e2e.test:4443/client.json")).unwrap();
    // No [api], no [connector]; [oauth] lists exactly the dashboard; the owner
    // origin and the public host are the two e2e names. Assert each through
    // the parsed Config's fields, as ws_harness_config_is_path_b_with_no_api does.
}

#[tokio::test]
async fn dashboard_serves_its_metadata_document_and_counts_fetches() {
    // serve_dashboard on 127.0.0.1 with a leaf for dashboard.e2e.test.
    // GET /client.json via https_raw: 200, application/json, max-age=3600,
    // client_id == "https://dashboard.e2e.test:{port}/client.json",
    // redirect_uris == ["https://dashboard.e2e.test:{port}/callback"],
    // token_endpoint_auth_method == "none"; fetches == 1.
    // GET /other: 404; fetches still 1.
}
```

  Use the real token-hash format if `"0".repeat(64)` does not parse; the ws config test shows it.
- [ ] **Step 2: Run, expect failure** (functions missing).
- [ ] **Step 3: Write** `kharond_toml`, `serve_dashboard`, the overlay and the `.gitignore` line. Run the two tests: pass. Run `docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/e2e/compose.e2e-oauth.yml -p kharon-e2e-oauth --profile vaultwarden config >/dev/null` after creating the files the overlay mounts as empty placeholders in `run-oauth/` (then delete them): exit 0.
- [ ] **Step 4: Write `setup()`, `run()`, `owner()`, `agent_edge()` and the ignored tests:**
  - `req_oau_001_compose_discovery_chain_leads_from_mcp_to_the_owner_hostname` asserts the three discovery steps from `Run`.
  - `req_apr_009_compose_owner_signs_in_with_a_passkey_through_the_edge` asserts `GET /owner/session` with the cookie is 200 and without it 401.
  - Both carry `#[ignore = "needs the compose E2E stack (image.yml)"]`.
- [ ] **Step 5: CI.** In `.github/workflows/image.yml`:
  - add to `pull_request.paths`: `crates/kharond/tests/req_oau_234_compose_connect_e2e.rs` and `crates/kharond/tests/owner_ui_support/**`;
  - add job `compose-e2e-oauth`, a copy of `compose-e2e-ws` with: `COMPOSE` using `compose.e2e-oauth.yml` and `-p kharon-e2e-oauth`; the build step `docker build -t "$KHARON_IMAGE" .` and `docker build -t kharon-e2e-agent-host:local deploy/compose/e2e/agent-host`; the same fixture start-and-seed step; the test step `cargo test -p kharond --test req_oau_234_compose_connect_e2e -- --ignored` with the same three `KHARON_FIXTURE_*` variables; the same log and teardown steps; add the new job to the header comment.
- [ ] **Step 6: Run** the non-ignored tests, fmt, clippy. **Commit** `test(e2e): N3 compose stack with two fake edges, discovery and passkey sign-in (#234)`. Report `DONE`; the controller pushes and reads the `compose-e2e-oauth` job before Task 3 starts.

---

### Task 3: Connect, tokens, `/mcp`, refresh, the retry, the reuse kill, Disconnect, audit and the secret scan

**Files:**
- Modify: `crates/kharond/tests/req_oau_234_compose_connect_e2e.rs`

**Interfaces:**
- Consumes: Task 2's `Run`, `owner()`, `agent_edge()`, `Discovered`, `Dashboard`.
- Produces: a `Scenario` record in `Run`, filled once by `async fn scenario(run: &…) -> Result<Scenario, String>` called at the end of `setup()`. Each step that gets an unexpected status returns `Err` with the step's name, the status and the redacted body, so every test reports the same first failure.

**Request shapes** (read the handler before writing each call; file and line are from master `2c92533`):
- `GET {authorization_endpoint path}?response_type=code&client_id=…&redirect_uri=…&code_challenge=…&code_challenge_method=S256&state=…&resource=https%3A%2F%2Fkharon.e2e.test%2Fmcp` on the owner edge, percent-encoded, no `scope` (absent means all three). Success is `302` with a relative `Location: /oauth/consent/<pending>` (`owner_ui/oauth.rs:362–404`). `code_challenge` is base64url of SHA-256 of a fresh 43-character verifier.
- `POST /oauth/consent/view` body `{"pending"}`: `client_name`, `client_host`, `redirect_host`, `scopes: [{id, words, optional}]` (:444).
- `POST /oauth/consent/options` body `{"pending"}`: `ceremony_id`, `nonce`, `publicKey.challenge` (:485).
- `POST /oauth/consent/approve` body `{"pending","ceremony_id","nonce","credential","scopes"}` with `deny_unknown_fields` (:547, `ApproveBody` :750). `credential` is `VirtAuth::assertion(challenge, OWNER_ORIGIN, OWNER_HOST)`; `scopes` is every `id` the view listed. Success is `200 {"redirect": "<redirect_uri>?code=…&state=…&iss=…"}` and **no `Location` header**.
- All three consent POSTs carry the session cookie, `Origin`, `Content-Type: application/json`.
- `POST {token_endpoint path}`, `Content-Type: application/x-www-form-urlencoded`, `CF-Connecting-IP: 198.51.100.20`, no cookie, no `Origin`, no `Authorization` (`owner_ui/oauth_token.rs`):
  - code grant: `grant_type=authorization_code&code=…&client_id=…&redirect_uri=…&code_verifier=…&resource=…`;
  - refresh grant: `grant_type=refresh_token&refresh_token=…&client_id=…`;
  - success: `200`, `Cache-Control: no-store`, `{access_token: "kh_at_"+64 hex, token_type: "Bearer", expires_in: 3600, refresh_token: "kh_rt_"+64 hex, scope}`; failure: `400 {"error": "invalid_grant"}`.
- `/mcp`: `mcp_call_bytes("kharon.e2e.test", Some(token), tool, args)` plus `CF-Connecting-IP: 198.51.100.20`, through `agent_edge()`. A tool error is HTTP 200 with `result.isError == true` and `result.content[0].text` holding `{"error","detail"}` (`api/mcp.rs:631`).
- `GET /owner/connections` and `POST /owner/connections/disconnect` body `{"agent_id"}` with the cookie and `Origin` (`owner_ui/mod.rs`, routes list at :218).

**The scenario, in order.** Connect A proves rotation, the retry and the kill; Connect B proves Disconnect.

1. **Connect A.** Authorize, view, options, approve, redeem.
   - Record: the consent view's `client_name` and `client_host`; the redirect's `state` and `iss`; that approve had no `Location`; the token answer's fields and `Cache-Control`; `dashboard.fetches` after authorize.
   - Tokens: `at0`, `rt0`.
   - Connect A's id: the one row of `GET /owner/connections` now.
2. **An `/mcp` call.** `kharon_status` with `at0`: 200, not an error.
3. **`no_browser`.** `kharon_context` with `{}` and `at0`: HTTP 200, `isError`, `error == "forbidden"`, `detail == "this connection has no browser attached yet"`, no `WWW-Authenticate` (as `req_oau_006_007_scopes.rs:349–353` asserts in-process). Then `kharon_fill` with well-formed arguments (the shape the ws E2E's fill uses, any item id): the same error.
4. **Rotation.** Refresh `rt0`: 200 with `at1`, `rt1`, both different from the first pair. `kharon_status` with `at1`: 200. Record `Instant` `rotated_at`.
5. **The single retry.** Refresh `rt0` again at once: 200 with `at2`, `rt2`. Then `kharon_status` with `at1`: 401 (the pair the retry superseded is dead), and with `at2`: 200. Record the time since `rotated_at`.
6. **Reuse kills the Connect.** Refresh `rt0` a third time: `400 invalid_grant`. Then `kharon_status` with `at2`: 401, and refresh `rt2`: `400 invalid_grant`. (Intended 4xx answers so far: two.)
7. **Connect B.** A second authorize and consent with a new verifier and `state`, redeemed to `atB`, `rtB`. Record `dashboard.fetches` again.
8. **Disconnect.** `GET /owner/connections`: exactly one row (A is ended, and the page lists live Connects only), with `client_name == "E2E Dashboard"`; take its id. `POST /owner/connections/disconnect`: 200. Then `kharon_status` with `atB`: 401; refresh `rtB`: `400 invalid_grant` (the third and last intended 4xx); `GET /owner/connections`: no rows.
9. **Evidence.** After the scenario:
   - kharond's log (`docker logs`, stdout and stderr);
   - `/data/oauth/state.json` and `/data/audit/audit.jsonl`, read with `docker run --rm --user 10001:10001 --entrypoint cat -v <data volume>:/data:ro kharon-e2e-agent-host:local <path>` (`compose_support::data_volume_of`);
   - the stdout of `docker exec kharon-e2e-oauth-kharond kharon audit verify --data /data/audit`.

**The ignored tests** (each asserts recorded facts; names are the deliverable):
- `req_oau_002_compose_kharond_fetches_the_dashboard_document_once`: `fetches == 1` after Connect A's authorize and still `1` after Connect B's (the document is cached for at least an hour); the consent view shows `E2E Dashboard` and a `client_host` that contains `dashboard.e2e.test`.
- `req_oau_003_compose_consent_returns_the_code_in_json_with_state_and_iss`: step 1's redirect facts.
- `req_oau_004_compose_code_redeems_to_a_token_pair`: prefixes, lengths, `Bearer`, `3600`, `no-store`, scope holds all three.
- `req_oau_004_compose_refresh_rotates_and_allows_one_retry`: steps 4 and 5, and the retry was sent within 20 s of the rotation (else the "runner too slow" failure).
- `req_oau_004_compose_reusing_a_retired_refresh_token_ends_the_connect`: step 6, and the audit log has one `oauth_refresh_reuse` for Connect A's id.
- `req_oau_005_compose_disconnect_from_the_owner_page_ends_the_connect`: step 8, and the audit log has `oauth_disconnect` with `detail_code == "owner"` and `channel == "web_ui"` for Connect B's id.
- `req_oau_007_compose_a_connect_has_no_browser`: steps 2 and 3.
- `req_oau_compose_audit_chain_records_both_connects_and_verifies`: two `oauth_connect` entries (`result == "connected"`, `origin` containing `dashboard.e2e.test`), in order before their endings; the `audit verify` output says the log is OK. Audit lines are read into a typed struct with `event`, `agent_id`, `result`, `detail_code`, `channel`, `origin`, all optional but `event`.
- `req_goal_002_compose_oauth_secrets_stay_out_of_logs_and_state`: after the positive controls in Review Focus 4, none of `at0 at1 at2 atB rt0 rt1 rt2 rtB`, the two codes, the enrolment code and the session cookie's value appears in kharond's log, `state.json` or `audit.jsonl`. `state.json` holds no string that starts with `kh_at_` or `kh_rt_` at all (tokens are stored as hashes).

- [ ] **Step 1: Write the nine ignored tests first**, against a `Scenario` struct with the fields they need. They compile and are skipped locally.
- [ ] **Step 2: Write `scenario()`** and call it from `setup()`.
- [ ] **Step 3: Run** the non-ignored tests, fmt, clippy; `cargo test -p kharond --test req_oau_234_compose_connect_e2e -- --list` shows the nine new names plus Task 2's two as ignored.
- [ ] **Step 4: Commit** `test(e2e): fake dashboard runs Connect, refresh, reuse-kill and Disconnect through the edges (#234)`. Report `DONE`; the controller pushes and reads the job.

## If CI shows the CIMD fetch failing

The first CI run of Task 3 is where name resolution, trust and the address class meet. If authorize answers 400 and the dashboard's count is 0, the request never arrived:
- `oauth_client_refused` with `cimd_unavailable` in the audit log and a refused-address line in kharond's log means the address class or the own-address check; the gateway address is wrong.
- A connect or DNS error means `/etc/hosts` did not reach kharond. Fallback: serve the document from a container on the `edge` network with the network alias `dashboard.e2e.test` (socat with `OPENSSL-LISTEN` and a response file the test writes), and drop `extra_hosts`.
- A count of 1 with a 400 means kharond fetched and rejected the document; compare it with `cimd.rs` validation (:575–610).

These are for the controller to rule on, not for an implementer to guess at.
