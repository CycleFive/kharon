# #219: connector pre-auth hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound what a stranger on the public `/connector` can cost the broker before authenticating. That means:
- at most 2 Argon2id evaluations at once, counted across both connector transports;
- one pre-auth deadline per socket;
- suppressed audit counts that reach the log even when no later event comes.

**Architecture:**
- **Shared Argon2id permits.** `Hub` gains a 2-permit Argon2id semaphore. `authenticate` waits for a permit within the socket's deadline and moves it into the blocking task, so the hash holds it until it finishes.
- **Absolute deadlines.** `authenticate` takes an absolute `Instant` deadline instead of per-phase `Duration`s.
  - The ws path sets its deadline when the slot is taken, before the 101. It covers the upgrade, the ClientHello gate, the inner TLS, the hello and the permit wait.
  - The raw path sets its deadline at accept.
- **Audit flush.** A connector housekeeping task flushes closed audit-limiter windows. The daemon flushes everything at shutdown, before the exit checkpoint.

**Tech Stack:** Rust (tokio, tokio-rustls), kharond integration tests.

**Spec:**
- issue #219, its body and both comments: Muse's three-timer note and Muse's per-(agent, event) wording;
- Nyx's Discord ruling 1569589079635525654: build before the #201 live run, with one 2-permit semaphore shared by both transports;
- the #199 design, `docs/superpowers/specs/2026-11-09-connector-websocket-design.md`, for everything this plan doesn't change.

## Global Constraints

- **Unchanged:**
  - connector wire v1, byte for byte;
  - `TlsVersions` on both paths: `Tls13Only` for ws, `Default` for raw;
  - the 8-slot ws budget (`WS_PREAUTH_SLOTS`) and its 503;
  - the raw listener's `Semaphore(4)`;
  - the raw path's #150 attach, detach and refused lines;
  - the per-minute ws refusal line's text;
  - the audit fields and events already shipped.
- **New constants** in `crates/kharond/src/connector.rs`, each `pub`:
  - `ARGON2_CONCURRENCY: usize = 2`;
  - `WS_PREAUTH_DEADLINE: Duration = 10 s`;
  - `RAW_PREAUTH_DEADLINE: Duration = 15 s`, which equals the raw path's old 10 s TLS plus 5 s hello maximum.

  And in `daemon.rs`: `CONNECTOR_AUDIT_FLUSH_PERIOD: Duration = 15 s`.
- **When the Argon2id wait times out:**
  - The broker writes **no** server hello and closes the stream.
  - So a legitimate client sees a disconnect and retries with jitter, not the fixed 60 s `Unauthorized` wait.
  - The ws path counts it as `auth`.
  - The raw path reports a new event, `ConnectorEvent::Busy { peer }`, which displays exactly `agent connector busy: credential check did not start in time`. The daemon prints it with its usual `kharond: ` prefix.
  - It is **not** audited, because no credential was refused.
- **A summary entry for flushed counts** is the same event (`connector_auth_fail` or `connector_replaced`) with:
  - `agent_id`, `suppressed = N` (N > 0) and `result = "suppressed_only"`;
  - no `transport`, `detail_code` or `old_session_secs`.
- **Rust:** typed serde only; no `serde_json::json!`/`Value` in non-test code.
- **Gates:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`. `cargo deny` isn't installed locally, and CI runs it.
- **Every cargo command sets `CARGO_TARGET_DIR=/home/lothrop/projects/kharon-219/target`**, because the workstation shares one target dir across checkouts.
- **Commits** end with exactly these two lines, and no other `Co-Authored-By` line:

  ```
  Claude-Session: https://claude.ai/code/session_017zqkE9gtxZrLyEWBDCjXMG
  Co-Authored-By: Claude & Lothrop (cycle.five@proton.me)
  ```

- **No version bump:** the workspace is still `0.0.0`.
- **No SPEC.md edits in this branch.** The SPEC wording goes in a separate `docs(spec)` PR after this one.

## Review Focus

1. **A legit agent reconnecting during a stranger flood.** The tokio `Semaphore` is FIFO, so a raw (VPN) hello queued behind up to 8 ws hellos still starts within its 15 s deadline. Task 1 test: `raw_hello_gets_a_permit_behind_queued_ws_hellos`.
2. **Permits must not leak** when the deadline fires mid-wait or shutdown cancels `authenticate`. Task 1 test: `argon_permit_released_after_wait_timeout_and_shutdown`, which asserts `argon_in_flight() == 0` afterwards.
3. **A client that disconnects mid-hash** must not free the permit early. The cap has to count the evaluation that is still running. Task 1 test: `argon_permit_held_until_the_hash_finishes`.
4. **A slow client chaining phase timers.** With per-phase timers, a client that takes just under each one could hold a slot for their sum. Task 1 test: `ws_slow_client_cannot_chain_phase_timers`.
5. **A failing audit sink during the shutdown flush** must not hang or fail shutdown. Task 2 test: `shutdown_flush_with_failing_sink_still_exits`.

---

### Task 1: The shared Argon2id cap and one pre-auth deadline

**Files:**
- Modify: `crates/kharond/src/connector.rs`, in `Hub`, `accept` (~390-405), `authenticate` (~424-480), `authenticate_and_serve` and `ConnectorEvent`.
- Modify: `crates/kharond/src/connector/ws.rs`, in `WsEntry`, `upgrade` and `session`; `WS_DEADLINE` is removed.
- Test: `crates/kharond/tests/req_arch_002_connector_ws.rs`, using `crates/kharond/tests/connector_support/mod.rs`.

**Interfaces:**
- **Produces:**
  - `Hub::argon_in_flight(&self) -> usize`, which is `ARGON2_CONCURRENCY - available permits`;
  - `ConnectorEvent::Busy { peer: SocketAddr }`;
  - `WsEntry::with_preauth_deadline(hub: Arc<Hub>, tls: Arc<rustls::ServerConfig>, deadline: Duration) -> Arc<Self>`, where `WsEntry::new` calls it with `WS_PREAUTH_DEADLINE`;
  - `authenticate(..., deadline: tokio::time::Instant, ...)` and `authenticate_and_serve(..., deadline: tokio::time::Instant, ...)`, replacing the `Duration` parameter.
- **Ruling:** a configurable deadline on `WsEntry` is a real constructor parameter, not a test hook. Production uses the constant. The raw `accept` keeps its signature and uses `RAW_PREAUTH_DEADLINE`.

- [ ] **Step 1: Write the failing tests** (kharond integration tests; real sockets, no paused clock):
  - `argon2_runs_at_most_two_at_once_across_transports`.
    - Use a hub whose `TokenStore` has slow Argon2 params: each verify takes ≥ 1 s.
    - Start 2 raw hellos and wait (`eventually`) until `argon_in_flight() == 2`.
    - Then start 1 ws hello. Assert `ws_preauth_in_flight() == 1` while `argon_in_flight()` stays `2` until a raw verify finishes.
    - All three end `AUTH_OK`.
  - `argon_wait_timeout_counts_auth_and_sends_no_server_hello`.
    - 2 raw hellos hold both permits; their verify must outlast the waiter's deadline by ≥ 1 s.
    - A ws hello goes through a `WsEntry::with_preauth_deadline(.., 1 s)`.
    - That client reads **no** server-hello record before EOF. Its `connect_and_auth` error is not `ClientError::Unauthorized`.
    - The refusal line has `auth 1`. No `connector_auth_fail` entry is written.
  - `raw_hello_gets_a_permit_behind_queued_ws_hellos` (Review Focus 1). With 8 ws hellos queued at the default deadline, a raw hello reaches `AUTH_OK` within `RAW_PREAUTH_DEADLINE`.
  - `argon_permit_released_after_wait_timeout_and_shutdown` (Review Focus 2). After the wait-timeout case, and after `begin_shutdown` while a ws hello waits for a permit, `argon_in_flight()` returns to `0` (poll with a deadline).
  - `argon_permit_held_until_the_hash_finishes` (Review Focus 3).
    - A raw client sends its hello and drops the socket at once.
    - `argon_in_flight()` stays `1` until that verify completes, then `0`.
  - `ws_slow_client_cannot_chain_phase_timers` (Review Focus 4).
    - Use a `WsEntry` with a 1.5 s deadline. The client upgrades, sends its ClientHello at about 0.6 s, finishes inner TLS, then sends its hello at about 1.7 s.
    - Expected: no `AUTH_OK`, and the slot is released by about 1.6 s (`ws_preauth_in_flight() == 0`).
    - Before this change, the per-phase 5 s timers would let that client through.
  - **Adjust `ws_preauth_budget_is_8_including_argon2`.** With the cap, its 8 verifies run in 4 rounds. Lower its Argon2 cost so 4 rounds finish well inside `WS_PREAUTH_DEADLINE`, aiming at 300–600 ms per verify on the dev box. Keep the 9th upgrade's 503 window wide, and keep every assertion as it is.
- [ ] **Step 2:** Run `cargo test -p kharond --test req_arch_002_connector_ws` and watch the new tests fail. Keep the output for the report.
- [ ] **Step 3: Implement.**
  - **`Hub.argon: Arc<Semaphore>`** with `ARGON2_CONCURRENCY` permits.
  - **In `authenticate`:**
    - `timeout_at(deadline, …)` bounds the TLS accept, the hello read and `argon.clone().acquire_owned()`.
    - The Argon2id permit moves into the `spawn_blocking` closure and drops when the hash returns.
    - Awaiting a hash that has already started is not bounded by the deadline; the Argon2 params bound it.
    - The slot `permit` is dropped right after the Argon2id result, as today, and on every earlier exit.
  - **On a wait timeout:** no server hello. The ws path does `ws_refused_auth += 1`; the raw path does `report(ConnectorEvent::Busy { peer })`.
  - **ws, in `upgrade`:** `let deadline = Instant::now() + self.deadline` right after the slot is taken, before the 101, passed into `session`.
  - **ws, in `session`:** `on_upgrade.await`, `from_raw_socket` and `ClientHelloGate::check` each run under `timeout_at(deadline, …)`. A gate timeout still counts `hello`. Then `authenticate_and_serve(.., deadline, ..)`.
  - **raw, in `accept`:** `deadline = Instant::now() + RAW_PREAUTH_DEADLINE` at accept.
  - **Docs:** update the module docs and `Hub`'s field docs.
- [ ] **Step 4:** Run the test file three times, then the raw-path tests (`--test req_arch_002_agent_connector`, `--test req_aud_150_connector_attach_log`), then `cargo test --workspace`.
- [ ] **Step 5:** Gates, then commit `fix(rev): one 2-permit Argon2id cap across connector transports; one pre-auth deadline (#219)`.

---

### Task 2: Flush suppressed counts on a ticker and at shutdown

**Files:**
- Modify: `crates/kharond/src/connector.rs`, in `Limits`/`admit` and new `Hub` methods.
- Modify: `crates/kharond/src/daemon.rs`, in the refusal-log task (~1223) and the shutdown sequence (~1250-1290).
- Modify: `crates/kharond/src/audit/entry.rs`, only if `Entry` has no `result` builder yet.
- Test: `crates/kharond/tests/req_aud_199_connector_audit.rs` and `req_arch_002_connector_ws.rs` (the daemon-level test).

**Interfaces:**
- **Consumes:** Task 1's `Hub`.
- **Produces:**
  - **`Hub::flush_audit(&self, now: tokio::time::Instant)`.** For each window in both maps where `now - start >= AUDIT_WINDOW`:
    - with `pending > 0`, it writes a summary entry (Global Constraints);
    - every expired window is then **removed**, so the agent's next event writes at once with `suppressed = 0`.
  - **`Hub::flush_audit_all(&self)`.** It writes a summary entry for every window with `pending > 0`, open or not, then clears both maps.
  - Both collect entries under the `limits` lock and `emit` them after releasing it.
- **Rulings:**
  - **Placement.** The housekeeping task exists whenever `[connector]` exists, raw or ws.
    - Every `CONNECTOR_AUDIT_FLUSH_PERIOD` it calls `flush_audit(now)`.
    - Every `WS_REFUSAL_LOG_PERIOD` (unchanged, 60 s) it prints the ws refusal line when there is a ws entry.
  - **Shutdown order.** After the ws drain and the connector task abort, and **before** `checkpoint_audit_now()`:
    1. print the final `take_refusal_line()` if there is one;
    2. call `hub.flush_audit_all()`.

    That way the flushed entries are anchored in the exit checkpoint.
  - **Timing.** A burst's count reaches the log within one window plus one tick, at most 75 s after its first event. #219's "within 60 s of a burst ending" is amended to that.

- [ ] **Step 1: Write the failing tests.** Use a paused clock with direct `Hub` calls for the limiter, and a real daemon for the shutdown case.
  - `flush_writes_a_summary_for_a_closed_window`:
    - an event at t0 (entry, `suppressed 0`), then 3 more at t0+10 s;
    - `flush_audit(t0+59 s)` writes nothing;
    - `flush_audit(t0+60 s)` writes exactly one entry with `suppressed == 3`, `result == "suppressed_only"` and `transport == None`;
    - the next event at t0+61 s writes immediately with `suppressed == 0`.
  - `flush_is_per_agent_and_event`. `auth_fail` and `replaced` windows for one agent, and windows for two agents, flush independently, with one summary each where pending > 0.
  - `expired_empty_window_writes_nothing`. After `flush_audit(t0+60 s)` with pending 0, no entry is written and the next event writes with `suppressed 0`.
  - `flush_all_writes_pending_of_open_windows`. With pending 2 at t0+5 s, `flush_audit_all()` writes one summary with `suppressed 2`.
  - `daemon_shutdown_flushes_pending_audit_counts`:
    - in-process `daemon::start` via the `daemon_config` rig, then two wrong-token ws dials for the configured agent within a second;
    - shut down;
    - `audit.jsonl` has the `connector_auth_fail` with `suppressed 0` and then a summary with `"suppressed":1` and `"result":"suppressed_only"`;
    - `audit verify` (the in-crate verifier) still passes.
  - `shutdown_flush_with_failing_sink_still_exits` (Review Focus 5). With a failing sink and pending counts, `flush_audit_all()` returns, and the daemon-level shutdown completes.
- [ ] **Step 2:** Run them and watch them fail.
- [ ] **Step 3: Implement** per the Interfaces and Rulings.
- [ ] **Step 4:** Run the two test files three times, then `cargo test -p kharond audit`, then `cargo test --workspace`.
- [ ] **Step 5:** Gates, then commit `fix(aud): flush suppressed connector audit counts on a ticker and at shutdown (#219)`.

---

### Task 3: The outage summary names the host, plus the operator docs

**Files:**
- Modify: `crates/kharon-agent-connector/src/backoff.rs` (`Outage::on_failure` and its unit test ~182) and `src/main.rs` (its call site ~558).
- Modify: `docs/deployment.md`, in the `/connector` edge section, the rate-limit section and the connector audit section.
- Test: the backoff unit test, plus the docs test `crates/kharond/tests/req_dep_006_compose_package.rs` › `n1_tunnel_routes_in_docs_use_127_0_0_1` (extend it).

**Interfaces:**
- **Consumes:** Task 1 (the busy line, the deadlines) and Task 2 (`suppressed_only`) for the docs.
- **Produces:** `Outage::on_failure(&mut self, now: Instant, err: &ClientError, at: &At) -> Option<String>`. Its summary ends `last failure: {leg_line_at(err, at)}`.

- [ ] **Step 1: Write the failing tests.**
  - Change the backoff unit test so a `Dns` failure's summary reads `…; last failure: dns: cannot resolve the broker host (broker.example.net)`. Use the exact `err_text` output and an `At` with that host.
  - The docs test also asserts that `docs/deployment.md` contains `Origin`, together with `Worker` or `Transform Rule`, plus `suppressed_only`, `2 Argon2id` and `credential check did not start in time`.
- [ ] **Step 2:** Run them and watch them fail.
- [ ] **Step 3: Implement.**
  - Thread `&At` through to `on_failure`; `main.rs` already builds one (`fn at`).
  - **Docs, as short additions in the existing sections:**
    - A Cloudflare Worker or Transform Rule must not add an `Origin` header to `/connector`, or every upgrade gets 403.
    - The `/connector` rate-limit rule is what protects the 8 pre-auth slots from starvation.
    - At most 2 Argon2id checks run at once across both transports. A ws socket has 10 s from the upgrade to its credential result, and a raw socket 15 s.
    - A check that doesn't start in time closes with no answer: it counts as `auth` on ws, and on raw it prints the `busy` line.
    - Summary audit entries (`result = "suppressed_only"`) carry counts from a closed window.
- [ ] **Step 4:** Run `cargo test -p kharon-agent-connector`, `cargo test -p kharond --test req_dep_006_compose_package`, then `cargo test --workspace`.
- [ ] **Step 5:** Gates, then commit `fix(rev): outage summary names the host; docs for the pre-auth bounds (#219)`.

---

## After the branch (the controller, not a task)

- **The `docs(spec)` PR** goes from master once this merges, and needs both Nyx and Muse:
  - §7's connector paragraph: the window is **per (agent, event)**, and summary entries carry `result = "suppressed_only"`, written when a window closes and at shutdown;
  - REQ-DEP-006 (B): at most 2 Argon2id evaluations across both transports, and one pre-auth deadline per socket (10 s ws, 15 s raw).
- **Tell the homelab session** once #219 merges, so #201's path-B-over-ws live run can go ahead.
