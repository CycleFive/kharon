# N2: Owner UI Behind the Edge — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the owner web UI safe to publish on its own hostname behind the Cloudflare edge (#208), without changing how it behaves on loopback.

**Architecture:** One config key, `[owner_ui] public_origin`, turns on *public mode*. In public mode the owner listener checks `Host`, requires `Origin` on every POST, takes the client address from `CF-Connecting-IP`, throttles failed attempts per source, caps the audit entries a stranger can cause, uses a `__Host-` cookie, and can verify a Cloudflare Access JWT. In both modes, sign-in challenges stop living in a server table and travel as HMAC-sealed tokens.

**Tech Stack:** Rust, axum 0.8 (HTTP/1.1 only), `hmac` + `sha2`, `aws-lc-rs` (RS256 verify), `reqwest` (JWKS fetch). **No new dependencies.**

**Spec:** [`docs/superpowers/specs/2026-11-11-n2-owner-ui-behind-edge-design.md`](../specs/2026-11-11-n2-owner-ui-behind-edge-design.md) (decisions D1–D12). Issue: #208 (AC1–AC10). Read the design section a task names before starting that task.

## Global Constraints

- **Local mode is unchanged.** Every existing test passes with at most a mechanical signature update. If an existing local-mode assertion has to change, stop: that is a design conflict, not a test fix.
- **Typed serde only** in new code: structs and enums deriving `Serialize` / `Deserialize`. No `serde_json::json!` and no `serde_json::Value` for data kharond owns. `owner_ui/mod.rs` has old `json!` bodies; leave them, don't add to them. Third-party JSON (the JWKS, the JWT) is also parsed into typed structs, without `deny_unknown_fields`.
- **Fixed codes only** in responses and audit (`REQ-API-006`, `REQ-AUD-004`): no request text, header value or hostname in an error body or a `detail_code`. A client address goes in the audit `client_ip` field and nowhere else.
- **The source address never decides authentication** (`api::public::client_ip`'s contract). It keys the throttle and appears in audit.
- **SPEC rows ship with their code:** each PR adds the SPEC sentences its tasks list.
- **Per-worktree build dir:** every cargo command runs with `CARGO_TARGET_DIR=<worktree>/target`.
- **Before each PR:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, all clean.
- **No version bump** (the workspace is `0.0.0`). No new crates. No force-push.
- **Commits** end with `Claude-Session: <session url>` then `Co-Authored-By: Claude & Lothrop (cycle.five@proton.me)`, and no other `Co-Authored-By`.
- **Values fixed by the design:** throttle 10 failures / 600 s / source, table 1024; audit ceiling 20 itemized / 60 s; throttle trips 5 itemized / 60 s; ceremony TTL 120 s (existing `CEREMONY_TTL`); used-set 64; sealed token ≤ 4096 bytes; JWKS refetch spacing 60 s (5 s while the cache is empty), max age 24 h, timeout 5 s, body ≤ 64 KiB; JWT clock leeway 60 s.

## Pull requests

| PR | Tasks | Reviewer | Closes ACs |
|---|---|---|---|
| A | 1, 2, 3 | Muse | 1, 2, 3, 6, 8 (code) |
| B | 4 | Nyx **and** Muse (it replaces sign-in in both modes) | 5 |
| C | 5, 6 | Muse | 4 |
| D | 7 | Muse | 7 |
| E | 8, 9 | Nyx **and** Muse (SPEC §2) | 9, 10, docs of 2 and 8 |

Tasks run in order. Each PR branches from master after the previous one merges.

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `crates/kharond/src/config/raw.rs`, `config/mod.rs`, `config/tests.rs` | Parse and validate the new keys | 1 |
| `crates/kharond/src/api/public.rs` | `host_matches`; `[public_ingress]` Host check | 2 |
| `crates/kharond/src/owner_ui/mod.rs` | Request handling: Host, Origin, exemptions, client address, cookie, the `fail` choke point | 2–7 |
| `crates/kharond/src/owner_ui/sealed.rs` (new) | `Sealer`, `UsedOnce` | 4 |
| `crates/kharond/src/owner_ui/throttle.rs` (new) | `FailureThrottle` | 5 |
| `crates/kharond/src/owner_ui/audit_budget.rs` (new) | `AuditBudget` | 6 |
| `crates/kharond/src/owner_ui/access.rs` (new) | `AccessVerifier` | 7 |
| `crates/kharond/src/api/transport.rs` | `ip_key` becomes `pub(crate)` | 5 |
| `crates/kharond/src/daemon.rs`, `crates/kharond/src/main.rs` | Wiring, ntfy redeem base, housekeeping tick, startup line | 2, 3, 6, 7 |
| `crates/kharond/tests/req_apr_009_edge.rs` (new) | Public-mode integration tests | 2–7 |
| `crates/kharond/tests/owner_ui_support/mod.rs` | `Http` gains host, extra headers, no-origin | 2 |
| `deploy/compose/*`, `docs/deployment.md`, `SPEC.md` | Package, docs, threat model | 8, 9 |

## Review Focus

Inputs the design implies that are easy to miss. Each has a test in the task named.

1. **A `Host` that is nearly right**: upper case, with `:443`, with the listen port, with a trailing dot, sent twice. Only the first two pass. (Task 2)
2. **A cross-site POST from the owner's own browser** (right address, wrong `Origin`): refused, and it must not move the owner's address toward a throttle. (Task 5)
3. **An IPv4-mapped IPv6 `CF-Connecting-IP`** (`::ffff:203.0.113.7`) and two addresses in one /64: each pair is one throttle key. (Task 5)
4. **A `ceremony_id` that is huge, not ASCII, or an old table-style id:** `401 bad_assertion`, never a 500 or a panic. (Task 4)
5. **A cookie header carrying both `kharon_owner` and `__Host-kharon_owner`:** only the mode's own name is read. (Task 3)

---

### Task 1: Config keys

Design: D1. **Files:** modify `config/raw.rs` (`RawOwnerUi` ~l.96, `RawPublicIngress` ~l.86, `validate_owner_ui` ~l.515, `canonical_origin` ~l.550, `validate_public_ingress` ~l.417), `config/mod.rs` (`OwnerUiConfig` ~l.892, `PublicIngressConfig` ~l.952, `ConfigError` + its code table ~l.421/527); test in `config/tests.rs`.

**Interfaces — Produces:**

```rust
// config/mod.rs
pub struct OwnerUiConfig {
    pub listen: SocketAddr,
    pub rp_id: String,
    /// Canonical browser origin. In public mode this is the public origin.
    pub origin: String,
    /// True when `public_origin` was set: the UI is behind the edge.
    pub public: bool,
    pub access: Option<AccessConfig>,
}
pub struct AccessConfig { pub team_domain: String, pub audience: String, pub jwks: JwksSource }
/// Where Access signing keys come from. No config key selects `TestStatic`.
pub enum JwksSource { TeamCerts, TestStatic(String) }
impl OwnerUiConfig {
    /// Host and port of `origin` (port is the scheme default when absent).
    pub fn authority(&self) -> (String, u16);
    /// Public mode: returns `origin` unchanged, whatever `port` is.
    pub fn origin_for_bound_port(&self, port: u16) -> String;
}
pub struct PublicIngressConfig { pub listen: SocketAddr, pub tls: Option<TlsMaterial>, pub public_host: Option<String> }
```

New `ConfigError` variants and their codes: `OwnerUiOriginChoice` → `owner_ui_origin_choice`; `OwnerUiPublicOrigin` → `owner_ui_public_origin`; `OwnerUiAccessNeedsPublicOrigin` → `owner_ui_access_needs_public_origin`; `OwnerUiAccess` → `owner_ui_access`; `PublicIngressPublicHost` → `public_ingress_public_host`.

Raw shape: `RawOwnerUi { listen, rp_id: Option, origin: Option<String>, public_origin: Option<String>, access: Option<RawAccess> }`, `RawAccess { team_domain: String, audience: String }` (both `deny_unknown_fields`), `RawPublicIngress { …, public_host: Option<String> }`.

Rules: exactly one of `origin` / `public_origin`. `public_origin` is https, has no userinfo, path (other than `/`), query or fragment, its host is a domain (`valid_rp_id`) and equals `rp_id`, which defaults to that host in public mode. It is stored through `serialize_origin`, so a default port is dropped and another is kept. The listen port is not compared. `team_domain` passes `valid_rp_id` and ends with `.cloudflareaccess.com`; `audience` is 1–128 ASCII alphanumerics. `public_host` passes `valid_rp_id` and is stored lower-case. Validated `jwks` is always `TeamCerts`.

- [ ] **Step 1: Write the failing tests** in `config/tests.rs`, following that file's existing owner-UI tests:
  - `owner_ui_public_origin_enables_public_mode`: `listen = "127.0.0.1:8788"`, `public_origin = "https://kharon-owner.example.com"` → `public == true`, `origin == "https://kharon-owner.example.com"`, `rp_id == "kharon-owner.example.com"`, `authority() == ("kharon-owner.example.com", 443)`, `access == None`.
  - `owner_ui_public_origin_normalizes_ports`: `https://o.example.com:443` → origin `https://o.example.com`; `https://o.example.com:8443` → origin kept, `authority().1 == 8443`.
  - `owner_ui_public_mode_ignores_the_listen_port`: `listen` `:0` and `:8788` both load; `origin_for_bound_port(54321)` returns the public origin.
  - `owner_ui_needs_exactly_one_origin`: both keys → `OwnerUiOriginChoice`; neither → `OwnerUiOriginChoice`.
  - `owner_ui_public_origin_must_be_https_and_bare`: each of `http://o.example.com`, `https://203.0.113.7`, `https://o.example.com/x`, `https://u@o.example.com`, `https://o.example.com?x=1`, and `https://o.example.com` with `rp_id = "example.com"` → `OwnerUiPublicOrigin`.
  - `owner_ui_access_needs_public_mode`: `[owner_ui.access]` beside `origin = …` → `OwnerUiAccessNeedsPublicOrigin`.
  - `owner_ui_access_is_validated`: `team_domain = "evil.example.com"` → `OwnerUiAccess`; `audience = ""` and `audience = "a b"` → `OwnerUiAccess`; `team_domain = "t.cloudflareaccess.com"`, `audience = "abc123"` → `Some(AccessConfig { jwks: JwksSource::TeamCerts, .. })`.
  - `owner_ui_access_has_no_jwks_key`: adding `jwks = "{}"`, or `jwks_url = "https://x"`, under `[owner_ui.access]` fails to load (unknown field).
  - `public_ingress_public_host_is_optional_and_validated`: absent → `None`; `"Kharon.Example.com"` → `Some("kharon.example.com")`; `"https://x"`, `"203.0.113.7"`, `"a b"` → `PublicIngressPublicHost`.
- [ ] **Step 2:** Run `cargo test -p kharond --lib config::` — the new tests fail to compile or fail.
- [ ] **Step 3: Implement.** Split `canonical_origin` so the listen-port rule stays on the local path only. Update every `OwnerUiConfig { … }` / `PublicIngressConfig { … }` literal the compiler reports.
- [ ] **Step 4:** `cargo test -p kharond --lib config::` passes; `cargo test -p kharond --test req_dep_003_config` passes.
- [ ] **Step 5: Commit** `feat(config): [owner_ui] public_origin, [owner_ui.access], [public_ingress] public_host (#208)`.

---

### Task 2: Host check on both listeners

Design: D2. **Files:** `api/public.rs`; `owner_ui/mod.rs` (`OwnerUi` fields ~l.188, `open` ~l.235, `OwnerServer` ~l.309, `handle` ~l.347); `daemon.rs` (`bind_owner_ui` ~l.1045, `bind_public_ingress` ~l.966 and where its router is built); `tests/owner_ui_support/mod.rs`; `tests/public_ingress.rs`; create `tests/req_apr_009_edge.rs`.

**Interfaces — Consumes:** `OwnerUiConfig::{public, authority}`, `PublicIngressConfig::public_host` (Task 1).

**Produces:**

```rust
// api/public.rs
/// True when the request carries exactly one `Host` header equal, ASCII
/// case-insensitively, to `host` or `host:port`. `host` is lower-case.
pub fn host_matches(headers: &HeaderMap, host: &str, port: u16) -> bool;
// router / serve_with_shutdown / serve_tls_with_shutdown gain a trailing
// `public_host: Option<Arc<str>>`; a set host that doesn't match (port 443) → `not_found()`.

// owner_ui/mod.rs
pub struct OwnerUiOptions { pub rp_id: String, pub origin: String, pub public: bool }
impl OwnerUi {
    pub fn open_with(data_dir: &Path, opts: OwnerUiOptions, shell: Arc<dyn OwnerShell>,
        audit: Arc<dyn OwnerAudit>, approvals: Arc<dyn OwnerApprovals>) -> std::io::Result<Arc<Self>>;
    pub fn is_public(&self) -> bool;
}
// `OwnerUi::open(...)` keeps its signature and calls `open_with` with `public: false`.

// tests/owner_ui_support/mod.rs — builder methods on `Http`
pub fn host(self, host: &'a str) -> Self;            // default stays "localhost"
pub fn header(self, name: &'a str, value: &'a str) -> Self;
pub fn without_origin(self) -> Self;                 // POST with no Origin header
```

Owner UI: in public mode `handle` refuses a non-matching `Host` first — before the ntfy redeem branch and before the body is read — with `respond(StatusCode::MISDIRECTED_REQUEST, "misdirected", None)`. No audit. The expected host and port come from `OwnerUiConfig::authority()`; `OwnerUi` keeps them.

`tests/req_apr_009_edge.rs` gets a `start_public()` harness copied from `req_apr_005.rs::start` (l.75), with `[owner_ui] listen = "127.0.0.1:0"` and `public_origin = "https://kharon-owner.example.com"`, plus constants `PUBLIC_ORIGIN` and `PUBLIC_HOST`. It returns the same `Running` shape. Later tasks add tests to this file.

- [ ] **Step 1: Write the failing tests.**
  - `api/public.rs` unit `host_matches_one_exact_host`: no header → false; two headers → false; `kharon.example.com` → true; `KHARON.example.com` → true; `kharon.example.com:443` with port 443 → true; `kharon.example.com:8790` → false; `kharon.example.com.` → false; `evil.example.com` → false.
  - `tests/public_ingress.rs` `public_host_refuses_a_foreign_host_with_the_uniform_404`: with `public_host = "kharon.example.com"`, `POST /mcp` with `Host: evil.example.com` → 404 with the same body as `GET /nope`; with the right `Host` and no token → 401. With no `public_host`, any `Host` → 401.
  - `req_apr_009_edge.rs` `req_apr_009_foreign_host_is_misdirected`: `GET /` with `Host` = public host → 200; with `:443` → 200; upper-cased → 200; `evil.example.com` → 421 and body code `misdirected`; public host with the listen port → 421; `GET /owner/approve/x` with a foreign `Host` → 421. After all of these the audit log has no `owner_auth_fail`.
  - `req_apr_009_edge.rs` `req_apr_009_local_mode_has_no_host_check`: a local-mode daemon answers `GET /` with `Host: anything.example` with 200.
- [ ] **Step 2:** Run those three targets; they fail.
- [ ] **Step 3: Implement** `host_matches`, the `[public_ingress]` check, `OwnerUiOptions` / `open_with`, and the owner-UI check. `bind_owner_ui` calls `open_with`.
- [ ] **Step 4:** The three targets pass; `cargo test -p kharond --test req_apr_005` still passes.
- [ ] **Step 5: Commit** `feat(apr): Host check on the owner UI and [public_ingress] in public mode (#208)`.

**SPEC (this PR):** `REQ-API-010` gains: "With `[public_ingress] public_host` set, a request whose `Host` is not that host (bare or `:443`) gets the listener's uniform 404." AC: the `public_ingress.rs` test above.

---

### Task 3: Public-mode request context

Design: D3, D4, D8, D10. **Files:** `owner_ui/mod.rs` (`OwnerAudit` ~l.173, `handle`, `Incoming` ~l.383, `dispatch` ~l.394, every `self.audit.auth_failed(` call, cookie helpers ~l.1251–1285, `serve*` ~l.319–340); `daemon.rs` (ntfy notifier ~l.876, `DaemonUiAudit` ~l.1117); `main.rs` (~l.118); tests in `req_apr_009_edge.rs`, `req_apr_004_ntfy_publish.rs`, and the unit tests in `mod.rs`.

**Produces:**

```rust
// owner_ui/mod.rs
pub enum EdgeExempt { Prefix(&'static str), Exact(&'static str) }
/// The one list of routes that take no `Origin` and no Access login.
pub const EDGE_EXEMPT: &[EdgeExempt] =
    &[EdgeExempt::Prefix(OWNER_APPROVE_PREFIX), EdgeExempt::Prefix(OWNER_DENY_PREFIX)];
pub fn edge_exempt(path: &str) -> bool;

pub struct AuthFailure {
    pub detail: &'static str,
    pub client_ip: Option<std::net::IpAddr>,
    pub suppressed: Option<u64>,           // always None until Task 6
}
pub trait OwnerAudit: Send + Sync + 'static { fn auth_failed(&self, failure: AuthFailure); }

struct Incoming { /* existing fields */ client_ip: Option<IpAddr> }
impl OwnerUi {
    /// The only place an owner-UI auth failure is recorded.
    fn fail(&self, req: &Incoming, detail: &'static str);
    /// Same, for failures raised before an `Incoming` exists (Task 7 uses it).
    /// `fail` builds the context from the request and calls this.
    fn record_failure(&self, ctx: FailureCtx, detail: &'static str);
}
struct FailureCtx {
    client_ip: Option<IpAddr>,
    has_session: bool,       // the request carried a live session (Task 6 reads it)
    throttled_route: bool,   // the path is one the throttle covers (Task 5 reads it)
}
```

- **Origin:** in public mode `dispatch` refuses a POST whose `Origin` is absent or not `self.origin`, unless `edge_exempt(path)`: `fail(req, "origin")`, `403 origin`. Local mode keeps the existing "present and different" rule.
- **Client address:** `serve` and `serve_with_shutdown` use `into_make_service_with_connect_info::<SocketAddr>()` and `handle` takes `ConnectInfo<SocketAddr>`. `client_ip` is `api::public::client_ip(&headers, true)`, else the peer's IP, in public mode; `None` in local mode.
- **Audit:** every `self.audit.auth_failed("…")` becomes `self.fail(req, "…")`. `DaemonUiAudit` adds `.client_ip(ip.to_string())` when present. Update the three impls (`NoAudit`, the test `FailCodes` ~l.2069, `DaemonUiAudit`).
- **Cookie:** `OwnerUi` holds `cookie_name: &'static str`: `"__Host-kharon_owner"` in public mode, else `"kharon_owner"`. `session_cookie`, `clear_cookie` and `session_hash` take it. `secure_cookie` is unchanged.
- **ntfy:** in `daemon.rs` the notifier is built when `ui.public || ui.listen.port() != 0`, with redeem base `ui.origin` in public mode and `http://{listen}` otherwise.
- **Startup line** (`main.rs`): in public mode, `kharond: owner UI listening on {addr} (public origin {origin}, behind the edge; ntfy approve/deny on that origin)`. `Daemon` exposes what `main.rs` needs.

- [ ] **Step 1: Write the failing tests** (public daemon via `start_public()`; requests send the right `Host`).
  - unit `edge_exempt_lists_only_the_ntfy_redeem_routes`: `/owner/approve/abc` and `/owner/deny/abc` → true; `/owner/approvals/approve`, `/owner/login/finish`, `/`, `/oauth/token` → false.
  - `req_apr_009_public_posts_need_the_public_origin`: for each of `/owner/login/options`, `/owner/login/finish`, `/owner/register/options`, `/owner/register/finish`, `/owner/logout`: no `Origin` → 403 `origin`; `Origin: https://evil.example` → 403 `origin`; `Origin: PUBLIC_ORIGIN` → not 403. Each 403 adds one `owner_auth_fail` with `detail_code` `origin`.
  - `req_apr_009_local_posts_without_origin_still_pass`: local mode, `POST /owner/login/options` with no `Origin` → 409 `no_credential`.
  - `req_apr_009_ntfy_redeem_takes_no_origin`: `POST /owner/approve/AAAA` with no `Origin` → 410.
  - `req_apr_009_auth_failures_carry_the_source_address`: a garbage `POST /owner/login/finish` with `CF-Connecting-IP: 203.0.113.7` → the new `owner_auth_fail` has `client_ip == "203.0.113.7"`; with no such header → `"127.0.0.1"`; with the header twice → `"127.0.0.1"`. In local mode with the header → the entry has no `client_ip`.
  - `req_apr_009_public_session_cookie_is_host_prefixed`: enroll and sign in with `VirtAuth` against `PUBLIC_ORIGIN` and `PUBLIC_HOST` as RP ID. `Set-Cookie` starts `__Host-kharon_owner=`, has `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` and no `Domain`. With it, `GET /owner/session` → 200. Sending the same token as `kharon_owner=<token>` → 401. Sending `kharon_owner=junk; __Host-kharon_owner=<token>` → 200. Logout's `Set-Cookie` clears `__Host-kharon_owner`.
  - `req_apr_004_ntfy_publish.rs` `req_apr_004_public_mode_action_urls_use_the_public_origin`: with a public owner UI on port 0 and that file's ntfy stub, a published prompt's approve and deny URLs start with `https://kharon-owner.example.com/owner/`.
- [ ] **Step 2:** Run `cargo test -p kharond --test req_apr_009_edge --test req_apr_004_ntfy_publish` and `--lib owner_ui::`; the new tests fail.
- [ ] **Step 3: Implement.** The unit tests in `mod.rs` build `Incoming` in 7 places; add `client_ip: None` there.
- [ ] **Step 4:** Those targets and `--test req_apr_005` pass.
- [ ] **Step 5: Commit** `feat(apr): public-mode Origin rule, exemption list, source address, __Host- cookie, ntfy on the public origin (#208)`.

**SPEC (this PR):** add row `REQ-APR-009` with the sentences tagged A in the appendix; §7 gains "`owner_auth_fail` carries `client_ip` in public mode"; `REQ-APR-004` gains "In public mode the action URLs use the public origin."

---

### Task 4: Sealed ceremonies (AC5)

Design: D7. **Files:** create `owner_ui/sealed.rs`; modify `owner_ui/mod.rs` (remove `Ceremony`, the `ceremonies` field, `MAX_CEREMONIES`, the table bodies of `begin` ~l.976 and `take_ceremony` ~l.1002; change `login_options`, `register_options`, `login_finish`, `register_finish`).

**Produces:**

```rust
// owner_ui/sealed.rs
pub(crate) const MAX_TOKEN_LEN: usize = 4096;
pub(crate) const MAX_USED: usize = 64;

pub(crate) struct Sealer { /* key: Zeroizing<[u8; 32]>, epoch: Instant */ }
pub(crate) struct Opened<T> { pub claims: T, pub id: [u8; 32], pub expires: Instant }
impl Sealer {
    pub fn new() -> Self;   // key from OsRng; epoch = Instant::now()
    /// Replace the key: every token sealed before this stops opening.
    /// Takes `&self`, so the key sits behind a lock.
    pub fn rotate(&self);
    pub fn seal<T: Serialize>(&self, purpose: &str, claims: &T, ttl: Duration, now: Instant) -> String;
    pub fn open<T: DeserializeOwned>(&self, purpose: &str, token: &str, now: Instant) -> Option<Opened<T>>;
}

pub(crate) struct UsedOnce { /* Mutex<Vec<([u8; 32], Instant)>> */ }
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Burn { Fresh, Replayed, Full }
impl UsedOnce {
    pub fn new() -> Self;
    /// Drop expired entries, then insert `id` if absent — one lock, one step.
    pub fn burn(&self, id: [u8; 32], expires: Instant, now: Instant) -> Burn;
    pub fn clear(&self);
}

// owner_ui/mod.rs
#[derive(Serialize, Deserialize)]
struct CeremonyClaims { challenge: String }      // base64url of 32 random bytes
impl CeremonyKind { fn purpose(self) -> &'static str }   // "login" | "register"
impl OwnerUi {
    /// A panic happened: rotate the sealing key and clear the used-set.
    pub fn invalidate_sealed(&self);
}
```

**Token format.** `payload = JSON {"p": <purpose>, "exp": <u64 ms since the Sealer's epoch>, "c": <claims>}` from a typed envelope struct. `token = b64url(payload) + "." + b64url(HMAC-SHA256(key, payload))`. `id = SHA-256(token)`.

**`open` returns `None`** when the token is longer than `MAX_TOKEN_LEN`, doesn't split into exactly two parts on `.`, either part isn't base64url, the MAC doesn't verify, the payload doesn't parse, the purpose differs, or `exp` is not after `now`. Verify the MAC with `hmac::Mac::verify_slice` (constant time) **before** parsing the payload.

**Flow.** `login_options` / `register_options` return the token as `ceremony_id` and the challenge as before: the wire shape doesn't change. `login_finish`: open the token (`None` → `fail("bad_assertion")`, 401) → verify the assertion against the token's challenge (failure → `fail("bad_assertion")`, 401, **token not burned**) → `used.burn(id, expires, now)`: `Replayed` → `fail("bad_assertion")`, 401; `Full` → 429 `rate_limited`, no audit; `Fresh` → store the sign count and issue the session. `register_finish` is the same, with `burn` before `store_credential`. This applies in both modes.

**Panic.** Both panic paths call `invalidate_sealed()`, whether the panic itself returned `Ok` or `Err`: the web route (`OwnerUi::panic`, `mod.rs` ~l.610, after `self.approvals.panic()`), and the CLI's (`DaemonOwner::panic_lock`, `daemon.rs` ~l.492, when `owner_ui` is `Some`). `register/options` keeps consuming the enrollment code; do not move that check to `finish`.

- [ ] **Step 1: Write the failing tests.**
  - `sealed.rs` unit `rotate_kills_every_outstanding_token`: a token sealed before `rotate()` → `None`; one sealed after → opens.
  - `sealed.rs` units: `sealed_round_trips_and_checks_purpose` (opens as `login` with equal claims; as `register` → `None`); `sealed_expires` (`Some` at `now + ttl − 1 ms`, `None` at `now + ttl`); `sealed_rejects_tampering` (a changed character in each part; payload of one token with MAC of another; truncated; a third `.`-part; 4097 bytes; non-ASCII → all `None`); `sealed_tokens_from_another_key_do_not_open`; `used_once_burns_once` (`Fresh` then `Replayed`); `used_once_forgets_expired_entries_and_reports_full` (64 live ids → the 65th is `Full`; once they expire, `Fresh`).
  - `mod.rs` unit `req_apr_009_ceremony_creation_stores_nothing`: 100,000 `POST /owner/login/options` through `dispatch` (a passkey is enrolled) all return 200, and a ceremony obtained before them still finishes: the following `login/finish` with a valid assertion → 200.
  - `req_apr_009_edge.rs`:
    - `req_apr_009_login_survives_a_flood_of_login_options` (AC5): the owner calls `login/options` from `198.51.100.1`. Then 2,000 `login/options` arrive, each from a different source (`CF-Connecting-IP` alternating `203.0.{i/256}.{i%256}` and `2001:db8:{i:x}::1`), then 500 from one source. All return 200. The owner's `login/finish` with the first `ceremony_id` → 200 and a session cookie.
    - `req_apr_009_a_used_ceremony_cannot_be_replayed`: after a successful sign-in, the identical `login/finish` body → 401 `bad_assertion` and no `Set-Cookie`.
    - `req_apr_009_a_failed_finish_does_not_burn_the_ceremony`: a finish with one signature byte flipped → 401; a correct finish with the same `ceremony_id` → 200.
    - `req_apr_009_ceremony_kinds_do_not_cross`: a `register` ceremony's id sent to `login/finish` → 401 `bad_assertion`.
    - `req_apr_009_panic_ends_ceremonies_in_flight`: the owner calls `login/options`, then a panic runs through the owner socket (the `panic` op, sent as `req_apr_005.rs::owner_op` sends ops). `login/finish` with a valid assertion for that ceremony → 401 `bad_assertion`. A new ceremony then signs in → 200. Repeat with the web route: a signed-in session starts a second ceremony, sends `POST /owner/panic` with `{"confirm": true}`, and that ceremony's finish → 401.
    - `req_apr_009_odd_ceremony_ids_are_refused_cleanly`: `ceremony_id` of 5,000 `a`s, of `"é.é"`, and of a 43-character old-style id → each 401 `bad_assertion`.
- [ ] **Step 2:** `cargo test -p kharond --lib owner_ui::` and `--test req_apr_009_edge`; the new tests fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Those pass, and `--test req_apr_005` passes unmodified. `git grep -n "MAX_CEREMONIES\|take_ceremony" crates/` prints nothing.
- [ ] **Step 5: Commit** `feat(apr): sign-in ceremonies are sealed tokens, not a table (#208 AC5)`.

**SPEC (this PR):** the appendix sentences tagged B.

---

### Task 5: Failure throttle (AC4)

Design: D5. **Files:** create `owner_ui/throttle.rs`; modify `owner_ui/mod.rs` (`dispatch`, `record_failure`, the success paths of `login_finish` and `unlock_finish`); `api/transport.rs` (`ip_key` → `pub(crate)`).

**Produces:**

```rust
// owner_ui/throttle.rs
pub(crate) const MAX_FAILURES: u32 = 10;
pub(crate) const FAILURE_WINDOW: Duration = Duration::from_secs(600);
pub(crate) const MAX_SOURCES: usize = 1024;
/// The routes a throttled source is refused on, and whose failures count.
pub const THROTTLED_ROUTES: &[&str] = &["/owner/login/options", "/owner/login/finish",
    "/owner/register/options", "/owner/register/finish", "/owner/unlock/begin", "/owner/unlock"];

pub(crate) struct FailureThrottle { /* Mutex<HashMap<IpAddr, (Instant /*window start*/, u32)>> */ }
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Counted { Under, Tripped, Over }
impl FailureThrottle {
    pub fn new() -> Self;
    /// Time left in the window when `ip` has reached the limit.
    pub fn blocked(&self, ip: IpAddr, now: Instant) -> Option<Duration>;
    /// Count one failure. `Tripped` exactly when the count reaches the limit.
    pub fn record(&self, ip: IpAddr, now: Instant) -> Counted;
    pub fn clear(&self, ip: IpAddr);
}
```

Keys go through `api::transport::ip_key`. A window is fixed and starts at the first failure. Inserting into a full table first drops expired entries, then removes the entry with the earliest window start.

**In `dispatch`, public mode, after the `Origin` check:** if the path is in `THROTTLED_ROUTES` and `blocked(ip)` is `Some(d)` → `429 rate_limited` with `Retry-After: <d in seconds, rounded up, at least 1>`. Not audited.

**In `record_failure`:** a failure counts when the UI is public, `ctx.throttled_route` is true (`fail` sets it from `THROTTLED_ROUTES`), and `detail != "origin"`. On `Tripped`, record one more `owner_auth_fail` with detail `throttled`. `login_finish` and `unlock_finish` call `clear(ip)` on success.

- [ ] **Step 1: Write the failing tests.**
  - `throttle.rs` units:
    - `tenth_failure_trips_and_blocks_until_the_window_ends`: failures 1–9 → `Under`, `blocked` `None`; the 10th → `Tripped`, `blocked` `Some(d)` with `d ≤ 600 s`; the 11th → `Over`; at window start + 600 s `blocked` is `None` and `record` is `Under`.
    - `sources_are_independent_and_v6_is_keyed_by_its_64`: ten failures from `2001:db8:1:1::a` block `2001:db8:1:1::b` and not `2001:db8:1:2::a`; ten from `203.0.113.7` block `::ffff:203.0.113.7`.
    - `clear_forgets_the_count`.
    - `a_full_table_forgets_the_oldest_and_never_blocks_a_newcomer`: 1024 sources tripped at increasing times; a new source is not blocked and its `record` is `Under`; the table still holds ≤ 1024; the first source is no longer blocked; the last still is.
    - `expired_entries_go_before_live_ones`.
  - `req_apr_009_edge.rs`:
    - `req_apr_009_ten_failures_throttle_that_source_only`: from A, ten garbage `login/finish` → 401 each; the 11th → 429 `rate_limited` with a `Retry-After` between 1 and 600. A's `GET /` → 200. From B, `login/options` → 200. The log holds ten `owner_auth_fail` for A plus one `throttled`, and the 429 added none.
    - `req_apr_009_wrong_origin_never_counts` (Review Focus 2): from A, 30 `POST /owner/login/finish` with `Origin: https://evil.example` → 403 each. Then A enrolls and signs in → 200.
    - `req_apr_009_signed_in_actions_are_never_throttled`: sign in from A, then throttle A. With the cookie: `GET /owner/approvals` → 200, `POST /owner/logout` → 200. `POST /owner/unlock/begin` → 429.
    - `req_apr_009_a_success_clears_the_count`: nine failures from A, a successful sign-in from A, nine more failures → none is 429.
    - `req_apr_009_local_mode_is_never_throttled`: 30 garbage `login/finish` in local mode → 401 each.
- [ ] **Step 2:** Run; the new tests fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `--lib owner_ui::`, `--test req_apr_009_edge`, `--test req_apr_005` and `--test req_api_200_transport` pass.
- [ ] **Step 5: Commit** `feat(apr): per-source throttle on failed owner sign-in, enroll and unlock (#208 AC4)`.

**SPEC (this PR):** appendix sentences tagged C; §7 lists detail `throttled`.

---

### Task 6: Audit ceiling

Design: D6. **Files:** create `owner_ui/audit_budget.rs`; modify `owner_ui/mod.rs` (`record_failure`, `OwnerAudit`); `daemon.rs` (`DaemonUiAudit`; a housekeeping task modeled on `connector_housekeeping` ~l.1370; shutdown order in `Daemon::run` ~l.1198).

**Produces:**

```rust
// owner_ui/audit_budget.rs
pub(crate) const ITEMIZED_PER_WINDOW: u32 = 20;
pub(crate) const AUDIT_WINDOW: Duration = Duration::from_secs(60);
pub(crate) struct AuditBudget { /* Mutex<{ start: Option<Instant>, written: u32, pending: u64 }> */ }
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict { Write { suppressed: Option<u64> }, Suppress }
impl AuditBudget {
    pub fn new() -> Self;
    /// One session-less failure at `now`. The first `Write` of a new window
    /// carries the previous window's count, if any.
    pub fn admit(&self, now: Instant) -> Verdict;
    /// The count of a window that has closed, once. `None` inside a window.
    pub fn flush(&self, now: Instant) -> Option<u64>;
    /// The pending count at shutdown, window closed or not.
    pub fn drain(&self) -> Option<u64>;
}

// owner_ui/mod.rs
pub trait OwnerAudit { fn auth_failed(&self, failure: AuthFailure); fn suppressed_only(&self, count: u64); }
impl OwnerUi { pub fn flush_audit(&self, now: Instant); pub fn drain_audit(&self); }

// daemon.rs
pub const OWNER_UI_AUDIT_FLUSH_PERIOD: Duration = Duration::from_secs(15);
pub async fn owner_ui_housekeeping(ui: Arc<OwnerUi>, stop: tokio::sync::watch::Receiver<bool>);
```

`record_failure`, public mode: `ctx.has_session && detail != "origin"` → write, outside the budget. Otherwise — every session-less failure, and every `origin` failure with or without a session — `admit`: `Write { suppressed }` → `auth_failed(AuthFailure { suppressed, .. })`; `Suppress` → write nothing. A suppressed failure still counts toward the throttle. Local mode writes every failure.

`DaemonUiAudit::auth_failed` adds `.suppressed(n)` when set. `suppressed_only` writes `Entry::new(Event::OwnerAuthFail).channel("web_ui").result("suppressed_only").suppressed(count)`.

`owner_ui_housekeeping` runs only for a public UI. Each tick calls `flush_audit` on the blocking pool. Shutdown stops and awaits it, then calls `drain_audit()`, before the daemon's final audit flush — the same order `connector_housekeeping` uses.

- [ ] **Step 1: Write the failing tests.**
  - `audit_budget.rs` units: `twenty_are_itemized_then_the_rest_are_counted` (admits 1–20 → `Write { suppressed: None }`; 21–25 → `Suppress`); `the_count_rides_on_the_next_windows_first_entry` (after those, an admit at +60 s → `Write { suppressed: Some(5) }`, the next → `Write { suppressed: None }`); `flush_reports_a_closed_window_once` (inside the window → `None`; at +60 s → `Some(5)`; again → `None`); `drain_reports_pending_inside_a_window`.
  - `mod.rs` unit `req_apr_009_session_failures_are_always_itemized`: with a recording `OwnerAudit`, public UI: 40 session-less failures, then one failure on a request with a live session → the recorder holds 20 + 1 entries.
  - `mod.rs` unit `req_apr_009_wrong_origin_with_a_session_is_still_capped`: public UI, 40 POSTs to `/owner/approvals/approve` carrying a live session and `Origin: https://sibling.example.com` → each 403 `origin`; the recorder holds 20 entries.
  - `req_apr_009_edge.rs`:
    - `req_apr_009_a_flood_of_failures_is_itemized_twenty_a_minute`: 200 garbage `login/finish` from 200 different sources → exactly 20 `owner_auth_fail` with result `denied`. Shut the daemon down. The log's last `owner_auth_fail` has result `suppressed_only` and `suppressed == 180`. (The 200 requests finish well inside one 60 s window.)
    - `req_apr_009_local_mode_itemizes_every_failure`: 30 failures in local mode → 30 entries, none with `suppressed`.
- [ ] **Step 2:** Run; the new tests fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `--lib owner_ui::`, `--test req_apr_009_edge`, `--test req_apr_005`, `--test req_aud_199_connector_audit` pass. Task 5's `ten_failures` test still passes (11 entries fit under 20).
- [ ] **Step 5: Commit** `feat(aud): cap the owner_auth_fail entries a stranger can cause; count the rest (#208)`.

**SPEC (this PR):** appendix sentences tagged D; §7: `owner_auth_fail` may carry `suppressed`, and result `suppressed_only`. §2.1 *Internet stranger* is left for Task 9.

---

### Task 7: Optional Access check (AC7)

Design: D9. **Files:** create `owner_ui/access.rs`; modify `owner_ui/mod.rs` (`OwnerUiOptions`, `handle`); `daemon.rs` (`bind_owner_ui`).

**Consumes:** `AccessConfig`, `JwksSource` (Task 1); `edge_exempt`, `record_failure` (Task 3).

**Produces:**

```rust
// owner_ui/access.rs
pub const CF_ACCESS_JWT: &str = "cf-access-jwt-assertion";
pub(crate) const JWKS_REFETCH_SPACING: Duration = Duration::from_secs(60);
pub(crate) const JWKS_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
pub(crate) const JWKS_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const JWKS_MAX_BYTES: usize = 64 * 1024;
pub(crate) const CLOCK_LEEWAY: Duration = Duration::from_secs(60);

pub struct AccessVerifier { /* issuer, audience, key source, cache */ }
#[derive(Debug, PartialEq, Eq)]
pub enum AccessRefusal { Missing, Malformed, UnknownKey, BadSignature, Claims }
impl AccessVerifier {
    pub fn new(cfg: &crate::config::AccessConfig) -> std::io::Result<Arc<Self>>;
    pub async fn verify(&self, headers: &HeaderMap, now: SystemTime) -> Result<(), AccessRefusal>;
}
// OwnerUiOptions gains `pub access: Option<Arc<AccessVerifier>>`.
```

**Typed inputs** (no `deny_unknown_fields`): `JwtHeader { alg: String, kid: String }`; `Claims { iss: String, aud: Audience, exp: u64, nbf: Option<u64> }` with `#[serde(untagged)] enum Audience { One(String), Many(Vec<String>) }`; `Jwks { keys: Vec<Jwk> }`; `Jwk { kid: String, kty: String, n: String, e: String }`. Keys whose `kty` isn't `RSA` are skipped.

**`verify`, in this order:** exactly one header → three `.`-parts, each base64url → header parses and `alg == "RS256"` → the `kid` is in the cache (if not, refetch when allowed, then look again; still absent → `UnknownKey`) → the signature verifies over `header.payload` → `iss == "https://{team_domain}"`, `aud` contains the audience, `exp + 60 s > now`, `nbf`, if present, `≤ now + 60 s`.

**Signature:** `aws_lc_rs::signature::RsaPublicKeyComponents { n, e }.verify(&aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256, message, signature)`. The `ring-sig-verify` feature is already on (`Cargo.toml` l.91). If that API doesn't compile as written, verify through `UnparsedPublicKey` with a DER `RSAPublicKey` built from `n` and `e`. Do not add a crate.

**Keys:** `TestStatic(json)` parses once and never fetches. `TeamCerts` fetches `https://{team_domain}/cdn-cgi/access/certs` with a `reqwest::Client` built like `sync/client.rs`'s (`tls_config`, l.197: aws-lc provider, OS roots), `redirect(Policy::none())`, 5 s timeout, reading at most 64 KiB. A fetch is allowed when the cache is empty, the `kid` is unknown, or the cache is older than 24 h, **and** the last attempt was at least 60 s ago. Record the attempt time under the lock before fetching, and fetch outside the lock. A failed fetch keeps the old keys. Put the fetch behind a private seam so unit tests can count calls and return canned bodies.

**In `handle`, public mode, after the Host check and before the body is read:** if a verifier is set and `!edge_exempt(path)`, call `verify`. On `Err`: `record_failure(FailureCtx { client_ip, has_session: false, throttled_route: false }, "access")` on the blocking pool, then `403 access_denied`. With `throttled_route: false` it is never counted by the throttle.

**Test keys:** generate an RSA-2048 key in the test with `aws-lc-rs` if its key type exposes the modulus and exponent. If not, commit a fixed key under `crates/kharond/tests/fixtures/access/` named `TEST-ONLY-…`. Share a `sign_jwt(kid, claims)` helper through `tests/owner_ui_support`.

- [ ] **Step 1: Write the failing tests.**
  - `access.rs` units:
    - `a_valid_token_passes`.
    - `refusals`, a table: no header → `Missing`; two headers → `Malformed`; two parts → `Malformed`; `alg` `HS256` and `none` → `Malformed`; unknown `kid` → `UnknownKey`; signed by another key under a known `kid` → `BadSignature`; wrong `iss`, `aud` without ours, `exp` 61 s past, `nbf` 61 s ahead → `Claims`.
    - `leeway_is_sixty_seconds`: `exp` 59 s past → passes.
    - `aud_may_be_a_string_or_a_list`.
    - `an_unknown_kid_refetches_at_most_once_a_minute`: unknown `kid` at t0 → one fetch; at t0 + 10 s → none; at t0 + 61 s → one more, and a key that fetch returns makes its token pass.
    - `a_failed_refetch_keeps_the_old_keys`.
    - `an_unknown_kid_costs_no_signature_check`: garbage in the signature part with an unknown `kid` → `UnknownKey`, not `BadSignature`.
  - `req_apr_009_edge.rs`, daemon started with `access = Some(AccessConfig { team_domain: "test.cloudflareaccess.com".into(), audience: "aud123".into(), jwks: JwksSource::TestStatic(jwks) })` set in Rust on the loaded `Config`:
    - `req_apr_009_access_gates_every_route_but_the_exempt_ones`: `GET /` with no token → 403 `access_denied`; with a valid token → 200; `POST /owner/login/options` with no token → 403; `POST /owner/approve/AAAA` with no token → 410; a valid token with a foreign `Host` → 421.
    - `req_apr_009_access_is_not_a_login`: a valid token and no session: `GET /owner/session` → 401.
    - `req_apr_009_access_refusals_are_audited_not_throttled`: 15 token-less `POST /owner/login/finish` from one source → 403 each, never 429; the log has `owner_auth_fail` with detail `access` and that `client_ip`.
- [ ] **Step 2:** Run; the new tests fail.
- [ ] **Step 3: Implement.** `bind_owner_ui` builds the verifier from `ui_cfg.access`.
- [ ] **Step 4:** `--lib owner_ui::`, `--test req_apr_009_edge`, `--test req_apr_005` pass.
- [ ] **Step 5: Commit** `feat(apr): optional Cloudflare Access JWT check on the owner UI (#208 AC7)`.

**SPEC (this PR):** appendix sentences tagged E; §7 lists detail `access`.

---

### Task 8: Compose package, docs, E2E (AC10; docs for AC2 and AC8)

Design: D12. **Files:** `deploy/compose/kharon.toml.example` (~l.68–77), `deploy/compose/README.md` (~l.104–109 and the "Owner actions until #208" section ~l.134), `docs/deployment.md` (owner UI and ntfy sections ~l.500–565), `deploy/compose/e2e/` (the kharond config both E2E stacks use), `crates/kharond/tests/req_dep_002_compose_e2e.rs`, `crates/kharond/tests/req_dep_006_compose_package.rs`.

- **Example config:** `[owner_ui]` on, with `listen = "127.0.0.1:8788"` and `public_origin = "https://kharon-owner.example.com"`; a commented `[owner_ui.access]` block; a commented `public_host` under `[public_ingress]`.
- **README:** replace "Owner actions until #208" with "Owner web UI": the tunnel route `kharon-owner.<domain>` → `http://127.0.0.1:8788`; first passkey (`docker compose exec kharon kharon passkey-enroll`, then open `https://kharon-owner.<domain>/enroll`); the CLI commands kept as the fallback. Remove both "waits for #208" notes.
- **`deployment.md`**, a new section "Publishing the owner UI": the two modes; never set `httpHostHeader` or `http2Origin` on these routes; optional Access (application on the owner hostname, where the AUD tag is, the two config keys); the Access **bypass** policy for `/owner/approve/*` and `/owner/deny/*` when ntfy is on; the throttle (10 failures, 10 minutes, per address) and recovery through the CLI; re-enroll the passkey when the RP ID changes; and "set `[public_ingress] public_host` on any published deploy".
- **E2E:** the E2E kharond config turns on `[owner_ui]` with `public_origin = "https://kharon-owner.e2e.test"`. Three probes from the fake-edge container, written the way that test's existing `/mcp` probes are.

- [ ] **Step 1: Write the failing tests.**
  - `req_dep_006_compose_package.rs` `req_dep_006_compose_example_publishes_the_owner_ui`: the example, loaded the way that file already loads it, has `owner_ui.public == true` and `owner_ui.listen == 127.0.0.1:8788`.
  - the same file, `compose_docs_no_longer_wait_for_208`: `README.md` contains neither `until #208` nor `waits for #208`; `docs/deployment.md` contains `httpHostHeader`, `/owner/approve/*` and `public_host`.
  - `req_dep_002_compose_e2e.rs`, in the existing probe step: `GET http://127.0.0.1:8788/` with `Host: kharon-owner.e2e.test` → 200; with `Host: other.test` → 421; `POST /owner/login/options` with the right `Host` and no `Origin` → 403.
- [ ] **Step 2:** `cargo test -p kharond --test req_dep_006_compose_package` fails.
- [ ] **Step 3: Write** the config, README and docs, and the E2E config and probes.
- [ ] **Step 4:** `--test req_dep_006_compose_package` passes locally. The compose E2E cannot run on the dev box (its firewall rejects container-to-host TCP): push and let the PR's `compose-e2e` and `compose-e2e-ws` jobs run it.
- [ ] **Step 5: Commit** `feat(dep): compose package publishes the owner UI; deployment guide for the owner hostname (#208 AC10)`.

---

### Task 9: SPEC threat model (AC9)

Design: D11. **Files:** `SPEC.md` only. Needs **both** Nyx's and Muse's approval.

- [ ] **Step 1:** §2.1 *Internet stranger*: extend to the owner hostname. They can load the sign-in and enroll pages and call the unauthenticated owner routes. They are bounded by the per-source throttle and can add at most 20 itemized audit entries a minute plus one count entry (`REQ-APR-009`).
- [ ] **Step 2:** §2.1, add **Operator (managed deploy)**. Trust: as the broker host. Capabilities: root on the box, the owner socket, the edge dashboard; can mint an enrollment code, approve over the CLI, and read process memory after an unlock. The passkey and Access do not constrain them. The customer keeps the master password, which is never stored, and CLI-channel actions are in the audit log.
- [ ] **Step 3:** §2.3 **B4**: name both owner paths: the socket (peer uid) and the web UI (passkey; in public mode behind the edge by placement, as B6).
- [ ] **Step 4:** §2.4: add to *protects* — a stranger evicting or blocking the owner's sign-in (sealed ceremonies); a cross-site page locking the owner out (wrong `Origin` never counts); a hostname mis-pointed at the owner listener (Host check). Add to *does not protect* — someone sharing the owner's address can throttle it for ten minutes (the CLI is the way back); the edge terminates TLS and sees the owner's session cookie.
- [ ] **Step 5:** `REQ-APR-005` gains "Behind the edge, `REQ-APR-009` applies." `REQ-DEP-006` names the owner hostname as edge-reached by placement.
- [ ] **Step 6:** `cargo test --workspace` (some tests read SPEC.md). Commit `docs(spec): threat model for the published owner UI — operator actor, B4, §2.4 (#208 AC9)`.

---

## Appendix: `REQ-APR-009`

Add the row after `REQ-APR-008`. Each PR adds its tagged sentences to both columns.

**Requirement column**

- **A (Task 3):** "**Owner UI behind the edge (#208).** With `[owner_ui] public_origin` set (https; exactly one of `origin` and `public_origin`), the UI is in public mode: it still listens on loopback and the edge reaches it by placement (REQ-DEP-006). **Host:** every request carries one `Host` naming the public host, bare or with the origin's port, else `421 misdirected`, unaudited. **Origin:** every POST carries `Origin` equal to the public origin, else `403 origin`. The only exemptions are on one named list: the ntfy redeem routes (REQ-APR-004), and REQ-OAU-008's two. **Source:** the client address is `CF-Connecting-IP` under REQ-API-010's rule (throttling and audit only, never auth), else the TCP peer; `owner_auth_fail` records it as `client_ip`. **Cookie:** `__Host-kharon_owner`, `Secure; HttpOnly; SameSite=Strict; Path=/`. Local mode (`origin`) has none of these."
- **B (Task 4):** "**Ceremonies (both modes):** a sign-in or enrollment challenge is not stored. The client carries it as a token authenticated with an HMAC under a key made at start and kept in memory, holding the purpose, an expiry 120 s ahead and the challenge. No unauthenticated request, from any number of sources, can evict or block another client's ceremony. A ceremony that completed cannot complete again. A panic replaces the key, ending every ceremony in flight."
- **C (Task 5):** "**Throttle:** a source (an IPv4 address or an IPv6 /64) with 10 failures in 10 minutes on the sign-in, enroll and unlock routes gets `429 rate_limited` on those routes until the window ends. A refused `Origin` never counts, so a cross-site page cannot throttle the owner's own address. A success clears the count. The table holds 1024 sources and forgets the oldest when full; there is no shared bucket. Signed-in actions are never throttled."
- **D (Task 6):** "**Audit ceiling:** at most 20 `owner_auth_fail` entries a minute are itemized for requests without a live session; the rest are counted and the count is logged (`suppressed`) within 75 s. A failure behind a live session that passed the `Origin` check is always itemized; a refused `Origin` is never exempt, because a same-site sibling page can send one with the owner's cookie."
- **E (Task 7):** "**Access (optional, `[owner_ui.access]`):** every route not on the exemption list requires a `Cf-Access-Jwt-Assertion` that verifies (RS256) against the team's keys, with `iss`, `aud` and `exp` checked. An unknown key id triggers at most one refetch a minute. No config key can replace the key source."

**Acceptance column**

- **A:** "Foreign `Host` → 421 on every route, redeem included. POST without the public `Origin` → 403 on login, register and logout; the redeem routes take none. `owner_auth_fail` carries the `CF-Connecting-IP` address. The session cookie is `__Host-`-prefixed and `Secure`."
- **B:** "The owner signs in after thousands of `login/options` from other sources. Replaying a completed finish → 401. A ceremony begun before a panic → 401 after it."
- **C:** "The 11th failure from one source → 429 there, while another source signs in. Thirty wrong-`Origin` POSTs do not throttle. A throttled source's live session still approves."
- **D:** "200 failures from 200 sources → 20 itemized entries and a count of 180. 40 wrong-`Origin` POSTs with a live session → 20 itemized."
- **E:** "No token → 403 on owner routes and not on the redeem routes; a valid token is not a session; a `jwks` key in the file is refused."
