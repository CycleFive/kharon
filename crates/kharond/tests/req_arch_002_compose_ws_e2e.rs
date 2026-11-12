//! The compose E2E for path B over WebSocket with no VPN (issue #220,
//! REQ-ARCH-002): the agent host's `kharon-agent-connector` dials
//! `wss://kharon.e2e.test:8443/connector` through a fake TLS-terminating
//! edge (socat in the holder's network namespace, standing in for
//! Cloudflare) into kharond's public ingress, the way production
//! reaches the broker. The stack is `deploy/compose/docker-compose.yml`
//! plus `deploy/compose/e2e/compose.e2e-ws.yml`: no `compose.vpn.yml`,
//! no `wg` network, no kharond `[api]`.
//!
//! One shared run (`run()`, set up once per test binary) backs the tests:
//!
//! - the connector's `--check` through the fake edge, run before the
//!   long-running connector starts so there is no live session to evict;
//! - the long-running connector attaches over ws, and the stack has the
//!   `edge` and `harness` networks and no `wg`.
//!
//! Ignored by default. Env: `KHARON_FIXTURE_BASE_URL`,
//! `KHARON_FIXTURE_CA_CERT`, `KHARON_FIXTURE_API_KEY_JSON`, as for the
//! other compose E2E. `docker compose` and the images `kharon:e2e`,
//! `kharon-e2e-agent-host:local` and `kharon-e2e-connector:local` must
//! exist (`image.yml`).

mod api_support;
mod compose_support;
mod docker_support;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use compose_support::{
    Cdp, add_canary_item, browser_ws_url, data_volume_of, env, fixture_scope, manifest,
    mcp_tool_tls, owner_approve, page_tls, random_hex32, redact, serve_page, ss_in, write_public,
};
use docker_support::{docker, docker_on_tty, docker_raw, wait_for_log};
use kharond::api::token::{generate, generate_tunnel};
use sha2::{Digest, Sha256};
use url::Url;

const COMPOSE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/compose");
const PROJECT: &str = "kharon-e2e-ws";
const KHAROND: &str = "kharon-e2e-ws-kharond";

/// The docker host's address on `edge`, where the test page is served.
const PAGE_ADDR: &str = "10.67.0.254";
/// Chromium's CDP relay on the `harness` network.
const AGENT_HOST_CDP: &str = "10.68.0.2:9222";
const BROKER_URL: &str = "wss://kharon.e2e.test:8443/connector";
const PUBLIC_INGRESS: &str = "127.0.0.1:8790";
const OWNER_UI: &str = "127.0.0.1:8788";
const AGENT_HOST_IMAGE: &str = "kharon-e2e-agent-host:local";
const FAKE_EDGE: &str = "kharon-e2e-ws-fake-edge";
const CONNECTOR: &str = "kharon-e2e-ws-connector";
/// The fake edge's listener, as the host reaches it.
const EDGE_ADDR: &str = "10.67.0.1:8443";
const EDGE_SNI: &str = "kharon.e2e.test";
const CONNECTOR_CONFIG: &str = "/etc/kharon-connector/connector.toml";

const FILLS: usize = 2;
/// Admissions one agent and one item need: [`FILLS`] successes plus the
/// first call's `pending_approval` (its retry is a second admission).
/// Production defaults (10/min, 5/item/10min) would stop at fill 4.
const FILL_ADMISSIONS: u32 = FILLS as u32 + 1;

/// `kharon-e2e-ws` compose arguments for `args`, in the order the
/// overlay's header documents.
fn compose_args(args: &[&str]) -> Vec<String> {
    let mut all: Vec<String> = [
        "compose",
        "--env-file",
        &format!("{COMPOSE_DIR}/e2e/run-ws/env"),
        "-f",
        &format!("{COMPOSE_DIR}/docker-compose.yml"),
        "-f",
        &format!("{COMPOSE_DIR}/e2e/compose.e2e-ws.yml"),
        "-p",
        PROJECT,
        "--profile",
        "vaultwarden",
    ]
    .map(String::from)
    .to_vec();
    all.extend(args.iter().map(|a| a.to_string()));
    all
}

fn compose(args: &[&str]) -> String {
    let all = compose_args(args);
    docker(&all.iter().map(String::as_str).collect::<Vec<_>>())
}

fn compose_raw(args: &[&str]) -> std::process::Output {
    let all = compose_args(args);
    docker_raw(&all.iter().map(String::as_str).collect::<Vec<_>>(), None)
}

/// Compose-harness daemon config for path B over ws: no `[api]`, the
/// public ingress on loopback, the connector's ws listener on it.
fn kharond_toml(email: &str, org: &str, coll: &str, token_hash: &str, tunnel_hash: &str) -> String {
    format!(
        r#"mode = "sync"

[bitwarden]
server = "https://vaultwarden"
email = "{email}"
api_key_file = "/run/secrets/kharon_bw_api_key"
organization_id = "{org}"
collection_ids = ["{coll}"]
ca_file = "/etc/kharon/vault-ca.pem"

[agents.alpha]
token_hash = "{token_hash}"
connector_token_hash = "{tunnel_hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }}

[policy]
# Harness only: {FILL_ADMISSIONS} admissions of one item inside a minute
# ({FILLS} fills, and the pending_approval retry). Production stays 10/min
# and 5/item/10min.
fills_per_minute = {FILL_ADMISSIONS}
item_fills_per_window = {FILL_ADMISSIONS}

[audit]
checkpoint_local_only = true

[public_ingress]
listen = "{PUBLIC_INGRESS}"

[owner_ui]
listen = "{OWNER_UI}"
public_origin = "https://kharon-owner.e2e.test"

[connector]
websocket = true
tls_cert_file = "/etc/kharon/connector-cert.pem"
tls_key_file = "/etc/kharon/connector-key.pem"
"#
    )
}

/// The connector's config (the agent host's side of the link).
fn connector_toml(pin: &str) -> String {
    format!(
        r#"transport = "ws"
broker_url = "{BROKER_URL}"
broker_pin = "{pin}"
agent_id = "alpha"
token_file = "/etc/kharon-connector/token"
cdp = "127.0.0.1:9222"
outer_ca_file = "/etc/kharon-connector/edge-ca.pem"
"#
    )
}

/// Writes `contents` at `path` with `mode`.
fn write_mode(path: &Path, contents: &[u8], mode: u32) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

// ------------------------------------------------------------ the run

/// What the shared run observed, for the tests to assert on.
struct Run {
    /// Exit code and stdout/stderr of `connector --check`.
    check_code: Option<i32>,
    check_stdout: String,
    check_stderr: String,
    /// The tunnel token, for "never printed" assertions.
    tunnel_token: String,
    /// kharond's log once the long-running connector attached, and how
    /// many attach lines it had before that (the `--check` session's).
    attach_logs: String,
    attaches_before: usize,
    /// The agent token and the canary, for "never logged" assertions.
    agent_token: String,
    canary: String,
    /// One record per fill, in order.
    fills: Result<Vec<FillRecord>, String>,
    /// Per POST the page server saw: did its password carry the canary?
    page_posts: Vec<bool>,
    /// The route probes: `socat` from the holder's netns to the
    /// browser's CDP (must fail), and the host's `GET /json/version`.
    probe_negative: ProbeNegative,
    probe_positive: Result<u16, String>,
    /// `ss -ltnpH` and `ss -lxpH` in kharond's netns. `Err` when
    /// `sudo -n nsenter` is unavailable; only the listener test unwraps.
    ss_tcp: Result<String, String>,
    ss_unix: Result<String, String>,
    /// `docker logs` of kharond, the fake edge and the connector.
    logs: Vec<(&'static str, String)>,
    /// The edge and inner TLS private-key PEMs, for "never logged".
    tls_keys: Vec<String>,
}

/// What one fill came to.
struct FillRecord {
    /// Statuses in order: `["pending_approval", "filled"]` for the first.
    statuses: Vec<String>,
    fields_filled: Vec<String>,
}

/// One `docker exec fake-edge socat ...` attempt: exit code and stderr.
struct SocatProbe {
    code: Option<i32>,
    stderr: String,
}

struct ProbeNegative {
    /// Control: the same invocation to kharond's own ingress, in the
    /// same netns. Must succeed, proving exec, binary and netns work.
    control: SocatProbe,
    /// The agent host's address on the shared `edge` network. kharond's
    /// netns reaches it by design, but nothing listens on 9222 there
    /// (the relay binds the harness address, Chromium 127.0.0.1), so the
    /// right answer is `Connection refused`. A relay rebound to 0.0.0.0
    /// would flip this.
    edge_side: SocatProbe,
    /// The browser's CDP port across the harness network.
    target: SocatProbe,
}

fn socat_probe(addr: &str) -> SocatProbe {
    let out = docker_raw(
        &[
            "exec",
            FAKE_EDGE,
            "socat",
            "-T",
            "3",
            "-",
            &format!("TCP:{addr},connect-timeout=3"),
        ],
        None,
    );
    SocatProbe {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    }
}

// ------------------------------------------------------------ MCP

#[derive(serde::Serialize)]
struct NoArgs {}

#[derive(serde::Serialize)]
struct SearchArgs<'a> {
    q: &'a str,
}

#[derive(serde::Deserialize)]
struct ItemMeta {
    id: String,
    name: String,
}

#[derive(serde::Deserialize)]
struct ContextReply {
    browser_context_id: String,
}

#[derive(serde::Serialize)]
struct FillArgs<'a> {
    item_id: &'a str,
    target: FillTarget<'a>,
    fields: [FieldSpec; 2],
    submit: bool,
}

#[derive(serde::Serialize)]
struct FillTarget<'a> {
    cdp_target_id: &'a str,
    expected_origin: &'a str,
}

#[derive(serde::Serialize)]
struct FieldSpec {
    kind: &'static str,
}

#[derive(serde::Deserialize)]
struct FillReply {
    status: String,
    grant_request_id: Option<String>,
    fields_filled: Option<Vec<String>>,
}

#[derive(serde::Serialize)]
struct CloseTarget<'a> {
    #[serde(rename = "targetId")]
    target_id: &'a str,
}

/// One MCP tool call through the fake edge, the result text parsed as `R`.
async fn mcp<A: serde::Serialize, R: serde::de::DeserializeOwned>(
    canary: &str,
    edge_ca: &str,
    token: &str,
    tool: &str,
    args: &A,
) -> R {
    let hex_canary = hex::encode(canary.as_bytes());
    let secrets = [canary, hex_canary.as_str(), token];
    let text = mcp_tool_tls(
        EDGE_ADDR.parse().unwrap(),
        EDGE_SNI,
        edge_ca,
        token,
        tool,
        args,
    )
    .await
    .unwrap_or_else(|e| panic!("{tool} through the fake edge: {}", redact(&e, &secrets)));
    // REQ-GOAL-002: no reply carries the canary, raw or hex.
    assert!(
        !text.contains(canary) && !text.contains(&hex::encode(canary.as_bytes())),
        "the canary is in a {tool} reply"
    );
    api_support::assert_no_canary(&text);
    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{tool} reply ({e}): {}", redact(&text, &secrets)))
}

/// `GET /json/version` status from the host, over HTTP to the CDP relay.
async fn cdp_http_status() -> Result<u16, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(AGENT_HOST_CDP),
    )
    .await
    .map_err(|_| "connect timed out".to_owned())?
    .map_err(|e| e.to_string())?;
    let req = format!(
        "GET /json/version HTTP/1.1\r\nHost: {AGENT_HOST_CDP}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(2).any(|w| w == b"\r\n") {
        let n = s.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line = String::from_utf8_lossy(&buf);
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| format!("no status line: {line}"))
}

static RUN: Mutex<Option<Result<Arc<Run>, String>>> = Mutex::new(None);

/// The shared run, set up on first use. A failed setup fails every
/// test with the same message instead of re-running compose.
fn run() -> Arc<Run> {
    let mut slot = RUN.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_none() {
        let result = std::panic::catch_unwind(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .unwrap()
                .block_on(setup())
        });
        *slot = Some(match result {
            Ok(run) => Ok(Arc::new(run)),
            Err(e) => Err(e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "setup panicked".into())),
        });
    }
    match slot.as_ref().unwrap() {
        Ok(run) => run.clone(),
        Err(msg) => panic!("compose ws E2E setup failed: {msg}"),
    }
}

fn kharond_logs() -> String {
    let out = docker_raw(&["logs", KHAROND], None);
    let mut logs = String::from_utf8_lossy(&out.stdout).into_owned();
    logs.push_str(&String::from_utf8_lossy(&out.stderr));
    logs
}

/// The parts of `docker compose config --format json` the tests read.
#[derive(serde::Deserialize)]
struct ComposeConfig {
    #[serde(default)]
    services: std::collections::HashMap<String, ComposeService>,
    #[serde(default)]
    networks: std::collections::HashMap<String, serde::de::IgnoredAny>,
}

#[derive(serde::Deserialize)]
struct ComposeService {
    #[serde(default)]
    networks: std::collections::HashMap<String, serde::de::IgnoredAny>,
}

const DETACH: &str = "agent connector detached: agent=alpha transport=ws";
const ATTACH: &str = "agent connector attached: agent=alpha transport=ws";

/// The agent's browser context (created by kharond through the
/// connector), then `FILLS` fills of the canary item, each followed by
/// the in-page submit. Runs inside `setup()`, so the page server's
/// runtime is alive.
async fn fill_phase(
    edge_ca: String,
    agent_token: String,
    item_name: String,
    canary: String,
    browser_ws: String,
    page_port: u16,
    submits: Arc<Mutex<Vec<bool>>>,
) -> Vec<FillRecord> {
    let ctx: ContextReply = mcp(
        &canary,
        &edge_ca,
        &agent_token,
        "kharon_context",
        &NoArgs {},
    )
    .await;
    let items: Vec<ItemMeta> = mcp(
        &canary,
        &edge_ca,
        &agent_token,
        "kharon_search",
        &SearchArgs { q: &item_name },
    )
    .await;
    let item_id = items
        .iter()
        .find(|i| i.name == item_name)
        .unwrap_or_else(|| panic!("the canary item is not listed ({} items)", items.len()))
        .id
        .clone();

    let mut cdp = Cdp::connect(&browser_ws).await;
    let url = format!("https://{}:{page_port}/login", compose_support::PAGE_HOST);
    let origin = format!("https://{}:{page_port}", compose_support::PAGE_HOST);
    let mut fills = Vec::new();
    for n in 0..FILLS {
        let ready = format!(
            "location.href === {} && document.readyState === 'complete'",
            serde_json::to_string(&url).unwrap()
        );
        let (target, session) = cdp.open(Some(&ctx.browser_context_id), &url, &ready).await;
        let secure = cdp.eval(&session, "window.isSecureContext").await;
        assert_eq!(
            secure,
            serde_json::Value::Bool(true),
            "test page must be a secure context"
        );
        let args = FillArgs {
            item_id: &item_id,
            target: FillTarget {
                cdp_target_id: &target,
                expected_origin: &origin,
            },
            fields: [
                FieldSpec { kind: "username" },
                FieldSpec { kind: "password" },
            ],
            submit: true,
        };
        let mut statuses = Vec::new();
        let mut reply: FillReply = mcp(&canary, &edge_ca, &agent_token, "kharon_fill", &args).await;
        statuses.push(reply.status.clone());
        if reply.status == "pending_approval" {
            let grid = reply
                .grant_request_id
                .clone()
                .unwrap_or_else(|| panic!("pending_approval without a grant_request_id"));
            owner_approve(&data_volume_of(KHAROND), AGENT_HOST_IMAGE, &grid);
            reply = mcp(&canary, &edge_ca, &agent_token, "kharon_fill", &args).await;
            statuses.push(reply.status.clone());
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while submits.lock().unwrap().len() < n + 1 {
            assert!(
                Instant::now() < deadline,
                "fill {n}: the form never posted (fill statuses {statuses:?})"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        fills.push(FillRecord {
            statuses,
            fields_filled: reply.fields_filled.unwrap_or_default(),
        });
        cdp.wait(
            &session,
            "location.pathname === '/submitted' && document.readyState === 'complete'",
            "post-submit page",
        )
        .await;
        cdp.call(
            None,
            "Target.closeTarget",
            serde_json::to_value(CloseTarget { target_id: &target }).unwrap(),
        )
        .await;
    }
    fills
}

async fn setup() -> Run {
    let base = Url::parse(&env("KHARON_FIXTURE_BASE_URL")).unwrap();
    let ca = PathBuf::from(env("KHARON_FIXTURE_CA_CERT"));
    let m = manifest();
    let email = m["account"]["email"].as_str().unwrap().to_owned();
    let master = m["account"]["password"].as_str().unwrap().to_owned();

    // 1. Stale state from an earlier run: compose needs the env file to
    // parse the overlay, so write it first, clear the stack, start over.
    let run_dir = PathBuf::from(format!("{COMPOSE_DIR}/e2e/run-ws"));
    std::fs::create_dir_all(&run_dir).unwrap();
    // The connector container runs as the host user, so the 0600 token
    // file is readable by it and needs no host sudo.
    let ids = format!(
        "KHARON_E2E_UID={}\nKHARON_E2E_GID={}\n",
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw()
    );
    write_public(&run_dir.join("env"), ids.as_bytes());
    // The seeded Vaultwarden fixture lives in this same project and must
    // survive (image.yml seeds it before the test runs), so `down -v`
    // would wipe it. Remove every other service instead, and the daemon's
    // data volume (a stale audit chain and unlock state would skew the
    // run). Networks stay: `up` reuses them.
    let services = compose(&["config", "--services"]);
    let mut rm = vec!["rm", "-sf"];
    rm.extend(services.lines().filter(|s| *s != "vaultwarden"));
    compose(&rm);
    let volume = format!("{PROJECT}_kharon-data");
    let gone = docker_raw(&["volume", "rm", &volume], None);
    let gone_err = String::from_utf8_lossy(&gone.stderr).to_lowercase();
    assert!(
        gone.status.success() || gone_err.contains("no such volume"),
        "could not remove the stale volume {volume}: {gone_err}"
    );
    std::fs::remove_dir_all(&run_dir).unwrap();
    for sub in ["page", "edge", "inner", "connector"] {
        std::fs::create_dir_all(run_dir.join(sub)).unwrap();
    }
    write_public(&run_dir.join("env"), ids.as_bytes());

    // 2. The canary item, then the scope (org + collection) to sync.
    let canary = random_hex32();
    let item_name = format!(
        "kharon-e2e-ws-canary-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    add_canary_item(&base, &ca, &item_name, &canary);
    let api_key = run_dir.join("api-key.json");
    write_public(
        &api_key,
        &std::fs::read(env("KHARON_FIXTURE_API_KEY_JSON")).unwrap(),
    );
    let (org, coll) = fixture_scope(&base, &email, &ca, &api_key).await;

    // 3. TLS material: the page's, the fake edge's (its own CA and a
    // leaf for the broker host) and the inner [connector] identity,
    // which the connector pins by the SHA-256 of its DER.
    let (acceptor, spki) = page_tls();
    write_public(&run_dir.join("page").join("page-spki"), spki.as_bytes());
    let (edge_ca, edge_cert, edge_key) = compose_support::edge_pki(&["kharon.e2e.test"]);
    // Keys are throwaway, and the daemons that read them run as other
    // uids than the host user (socat as 10002, kharond as 10001), so
    // these two are mode 0644 (kharond only requires readability).
    write_public(&run_dir.join("edge").join("cert.pem"), edge_cert.as_bytes());
    write_public(&run_dir.join("edge").join("key.pem"), edge_key.as_bytes());
    let inner = rcgen::generate_simple_self_signed(vec!["kharond".into()]).unwrap();
    write_public(
        &run_dir.join("inner").join("cert.pem"),
        inner.cert.pem().as_bytes(),
    );
    write_public(
        &run_dir.join("inner").join("key.pem"),
        inner.key_pair.serialize_pem().as_bytes(),
    );
    let pin = hex::encode(Sha256::digest(inner.cert.der()));
    let tls_keys = vec![edge_key.clone(), inner.key_pair.serialize_pem()];

    // 4. The agent host creates the networks; then the test page can be
    // served on the edge gateway and the browser is reachable.
    compose(&["up", "-d", "--no-build", "agent-host"]);
    // Chromium answers on the harness network (Task 3 drives it).
    let browser_ws = browser_ws_url(AGENT_HOST_CDP.parse().unwrap()).await;
    let (page_port, submits) = serve_page(PAGE_ADDR, acceptor, &canary).await;

    // 5. The agent and tunnel tokens, and the two configs.
    let (token, hash) = generate("alpha");
    let agent_token = token.expose_secret().clone();
    let (tunnel, tunnel_hash) = generate_tunnel("alpha");
    let tunnel_token = tunnel.expose_secret().clone();
    write_public(
        &run_dir.join("kharon.toml"),
        kharond_toml(&email, &org, &coll, &hash, &tunnel_hash).as_bytes(),
    );

    // 6. The connector side. The token file must be mode 0400/0600.
    let conn_dir = run_dir.join("connector");
    write_public(
        &conn_dir.join("connector.toml"),
        connector_toml(&pin).as_bytes(),
    );
    write_public(&conn_dir.join("edge-ca.pem"), edge_ca.as_bytes());
    write_mode(
        &conn_dir.join("token"),
        format!("{tunnel_token}\n").as_bytes(),
        0o600,
    );

    // 7. kharond and the fake edge.
    compose(&["up", "-d", "--no-build", "kharon", "fake-edge"]);
    wait_for_log(
        KHAROND,
        &format!(
            "kharond: public ingress listening on {PUBLIC_INGRESS} \
             (plain HTTP, loopback; POST /mcp and GET /connector)"
        ),
        Duration::from_secs(60),
    );

    // 8. The owner unlocks through the CLI on a terminal, as an operator
    // would (the CLI refuses a piped password).
    let (unlocked, tty) = docker_on_tty(
        &["exec", "-it", KHAROND, "kharon", "unlock"],
        "kharon master password:",
        &master,
    );
    assert!(!tty.contains(&master), "the master password was echoed");
    assert!(unlocked, "kharon unlock: {tty}");

    // 9. --check first: a successful check replaces the agent's live
    // session, so nothing long-running exists yet to evict.
    let check = compose_raw(&[
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "connector",
        "--config",
        CONNECTOR_CONFIG,
        "--check",
    ]);
    let check_stdout = String::from_utf8_lossy(&check.stdout).into_owned();
    let check_stderr = String::from_utf8_lossy(&check.stderr).into_owned();

    // 10. The long-running connector. It backs off with full jitter up
    // to 30 s if it starts before kharond is ready, so allow 90 s. The
    // `--check` session logged an attach line too, so wait for one more.
    // Wait for the `--check` session's detach line first, so its attach
    // line is certainly logged and the count below is deterministic.
    // Only a passing check attaches and detaches. A failing one is
    // reported by its own test (and in the attach-wait message below).
    if check.status.code() == Some(0) {
        wait_for_log(KHAROND, DETACH, Duration::from_secs(30));
    }
    let redactions = [tunnel_token.as_str(), agent_token.as_str(), canary.as_str()];
    let attaches_before = kharond_logs().matches(ATTACH).count();
    compose(&["up", "-d", "--no-build", "connector"]);
    let deadline = Instant::now() + Duration::from_secs(90);
    let attach_logs = loop {
        let logs = kharond_logs();
        if logs.matches(ATTACH).count() > attaches_before {
            break logs;
        }
        assert!(
            Instant::now() < deadline,
            "the connector never attached over ws; --check exit {:?}, stdout:\n{}\nstderr:\n{}\n\
             kharond logs:\n{logs}\nconnector logs:\n{}",
            check.status.code(),
            redact(&check_stdout, &redactions),
            redact(&check_stderr, &redactions),
            redact(&compose(&["logs", "--no-color", "connector"]), &redactions)
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    // 11-12. Context and fills, in a spawned task: a failure (the page
    // unreachable from the browser, say) is recorded as an Err so the
    // tests that do not need the fills still run.
    let fills = tokio::spawn(fill_phase(
        edge_ca.clone(),
        agent_token.clone(),
        item_name.clone(),
        canary.clone(),
        browser_ws,
        page_port,
        submits.clone(),
    ))
    .await
    .map_err(|e| match e.try_into_panic() {
        Ok(p) => p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "the fill phase panicked".into()),
        Err(e) => e.to_string(),
    });
    let page_posts = submits.lock().unwrap().clone();

    // 13. Routes: the holder's netns (where kharond lives) must have no
    // path to the browser's CDP port; the host must (positive control).
    let probe_negative = ProbeNegative {
        control: socat_probe(PUBLIC_INGRESS),
        edge_side: socat_probe("10.67.0.2:9222"),
        target: socat_probe("10.68.0.2:9222"),
    };
    let probe_positive = cdp_http_status().await;

    // 14. Listeners, after the fills: without sudo these are Errs and
    // only the listener test fails.
    let ss_tcp = ss_in(KHAROND, "-ltnpH");
    let ss_unix = ss_in(KHAROND, "-lxpH");

    // 15. Logs, then lock.
    let logs: Vec<(&'static str, String)> = [("kharon", KHAROND), ("connector", CONNECTOR)]
        .iter()
        .map(|(label, c)| {
            let out = docker_raw(&["logs", c], None);
            let mut l = String::from_utf8_lossy(&out.stdout).into_owned();
            l.push_str(&String::from_utf8_lossy(&out.stderr));
            (*label, l)
        })
        .collect();
    docker(&["exec", KHAROND, "kharon", "lock"]);

    Run {
        check_code: check.status.code(),
        check_stdout,
        check_stderr,
        tunnel_token,
        attach_logs,
        attaches_before,
        agent_token,
        canary,
        fills,
        page_posts,
        probe_negative,
        probe_positive,
        ss_tcp,
        ss_unix,
        logs,
        tls_keys,
    }
}

// ------------------------------------------------------------ tests

/// The harness config parses as a path-B-over-ws kharond config.
#[test]
fn ws_harness_config_is_path_b_with_no_api() {
    let toml = kharond_toml(
        "kharon@example.net",
        "0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6",
        "11111111-2222-3333-4444-555555555555",
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash",
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$TUNNELhashTUNNELhash",
    );
    let cfg = kharond::config::Config::from_toml_str(&toml).unwrap();
    assert!(cfg.api.is_none(), "the ws variant has no [api]");
    assert_eq!(
        cfg.agents["alpha"].cdp.tunnel,
        kharond::cdp::Tunnel::AgentConnector,
        "nothing but the connector can carry CDP"
    );
    assert_eq!(
        cfg.public_ingress.as_ref().unwrap().listen.to_string(),
        PUBLIC_INGRESS
    );
    let ui = cfg.owner_ui.as_ref().unwrap();
    assert_eq!(ui.listen.to_string(), OWNER_UI);
    assert!(ui.public, "the ws harness owner UI is in public mode");
    assert_eq!(ui.origin, "https://kharon-owner.e2e.test");
    assert!(cfg.connector.as_ref().unwrap().websocket);
    assert!(cfg.connector.as_ref().unwrap().listen.is_none());
    assert_eq!(cfg.policy.fills_per_minute, FILL_ADMISSIONS);
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_arch_002_compose_ws_connector_check_passes_through_the_fake_edge() {
    let r = run();
    // First, so a connector that printed its token fails here and the
    // later messages (which print the output) never see it.
    assert!(
        !r.check_stdout.contains(&r.tunnel_token) && !r.check_stderr.contains(&r.tunnel_token),
        "the tunnel token is in the --check output"
    );
    let secrets = [
        r.tunnel_token.as_str(),
        r.agent_token.as_str(),
        r.canary.as_str(),
    ];
    assert_eq!(
        r.check_code,
        Some(0),
        "connector --check failed; stdout:\n{}\nstderr:\n{}",
        redact(&r.check_stdout, &secrets),
        redact(&r.check_stderr, &secrets)
    );
    // `leg_label` in kharon-agent-connector, in order; the `note:` line
    // follows a successful auth leg (wire v1 has no probe that spares
    // a live session).
    assert_eq!(
        r.check_stdout,
        "ok dns\nok tcp\nok outer-tls\nok upgrade\nok inner-tls\nok auth\n\
         note: a successful check replaces this agent's live broker session\n\
         check: ok\n"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_arch_002_compose_ws_connector_attaches_over_ws() {
    let r = run();
    assert!(
        r.attach_logs.matches(ATTACH).count() > r.attaches_before,
        "no attach line for the long-running connector:\n{}",
        r.attach_logs
    );
    assert!(r.attaches_before >= 1, "--check should have attached once");
    let networks = docker(&[
        "network",
        "ls",
        "--filter",
        &format!("label=com.docker.compose.project={PROJECT}"),
        "--format",
        "{{.Name}}",
    ]);
    let names: Vec<&str> = networks.lines().collect();
    for want in ["edge", "harness"] {
        assert!(
            names.contains(&format!("{PROJECT}_{want}").as_str()),
            "no {want} network in {names:?}"
        );
    }
    assert!(
        !names.iter().any(|n| n.ends_with("_wg")),
        "a wg network exists: {names:?}"
    );
    // Docker records the files the project was started with.
    let files = docker(&[
        "inspect",
        "--format",
        r#"{{ index .Config.Labels "com.docker.compose.project.config_files" }}"#,
        KHAROND,
    ]);
    let files: Vec<&str> = files.trim().split(',').collect();
    assert!(
        files.len() == 2
            && files[0].ends_with("/docker-compose.yml")
            && files[1].ends_with("/e2e/compose.e2e-ws.yml"),
        "kharond was not started from exactly docker-compose.yml + e2e/compose.e2e-ws.yml: {files:?}"
    );
    let config = compose(&["config", "--format", "json"]);
    assert!(
        !config.contains("10.66.0."),
        "the compose config names the VPN subnet:\n{config}"
    );
    let parsed: ComposeConfig = serde_json::from_str(&config).unwrap();
    assert!(
        !parsed.networks.contains_key("wg"),
        "the compose config defines a wg network"
    );
    for (name, svc) in &parsed.services {
        assert!(
            !svc.networks.contains_key("wg"),
            "service {name} is on the wg network"
        );
    }
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_arch_002_compose_ws_fills_over_the_connector() {
    let r = run();
    let fills = r
        .fills
        .as_ref()
        .unwrap_or_else(|e| panic!("the fill phase failed: {e}"));
    assert_eq!(fills.len(), FILLS);
    for (n, f) in fills.iter().enumerate() {
        assert_eq!(
            f.statuses.last().map(String::as_str),
            Some("filled"),
            "fill {n}: statuses {:?}",
            f.statuses
        );
        assert_eq!(f.fields_filled, ["username", "password"], "fill {n}");
    }
    assert_eq!(
        fills[0].statuses,
        ["pending_approval", "filled"],
        "the first fill goes through owner approval"
    );
    assert_eq!(
        fills[1].statuses,
        ["filled"],
        "the per-origin grant covers the second fill"
    );
    assert_eq!(r.page_posts.len(), FILLS, "one page POST per fill");
    assert!(
        r.page_posts.iter().all(|&c| c),
        "a posted password was not the seeded canary: {:?}",
        r.page_posts
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml); ss needs sudo -n"]
fn req_dep_006_compose_ws_kharond_listens_on_loopback_only() {
    let r = run();
    let tcp = r
        .ss_tcp
        .as_ref()
        .unwrap_or_else(|e| panic!("ss -ltnpH in kharond's netns: {e}"));
    let unix = r
        .ss_unix
        .as_ref()
        .unwrap_or_else(|e| panic!("ss -lxpH in kharond's netns: {e}"));
    let mut kharond_listeners = Vec::new();
    for line in tcp.lines() {
        let local = line.split_whitespace().nth(3).unwrap_or("");
        if local.starts_with("127.0.0.11:") {
            continue; // docker's embedded DNS
        }
        if local == EDGE_ADDR {
            assert!(line.contains("socat"), "{EDGE_ADDR} is not socat: {line}");
            continue;
        }
        assert!(
            line.contains("kharond"),
            "listener {local} is not owned by kharond: {line}"
        );
        kharond_listeners.push(local.to_owned());
    }
    kharond_listeners.sort();
    assert_eq!(
        kharond_listeners,
        [OWNER_UI, PUBLIC_INGRESS],
        "kharond's TCP listeners; full ss output:\n{tcp}"
    );
    assert!(
        unix.contains("/data/owner.sock"),
        "no owner socket in:\n{unix}"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_arch_002_compose_ws_kharond_has_no_direct_route_to_cdp() {
    let r = run();
    let c = &r.probe_negative.control;
    assert_eq!(
        c.code,
        Some(0),
        "negative probe CONTROL failed: socat from the fake-edge container to kharond's own \
         ingress {PUBLIC_INGRESS} (same netns) did not succeed, so the exec, the binary or \
         the netns is broken and the CDP probe proves nothing; exit {:?}, stderr: {}",
        c.code,
        c.stderr
    );
    let e = &r.probe_negative.edge_side;
    assert!(
        e.code == Some(1) && e.stderr.contains("Connection refused"),
        "negative probe (edge side): 10.67.0.2:9222, the agent host's address on the shared \
         edge network, should refuse the connection (the relay must bind the harness address \
         only); exit {:?}, stderr: {}",
        e.code,
        e.stderr
    );
    let t = &r.probe_negative.target;
    assert_ne!(
        t.code,
        Some(0),
        "negative probe: the holder's netns (kharond) reached the browser's CDP port \
         10.68.0.2:9222 directly"
    );
    assert!(
        !t.stderr.contains("Connection refused"),
        "negative probe: the CDP port was reachable (connection refused is an answer from \
         the host, not a missing route); exit {:?}, stderr: {}",
        t.code,
        t.stderr
    );
    assert_eq!(
        t.code,
        Some(1),
        "negative probe: socat did not fail as a connect failure (exit 125/126 is a dead \
         container or exec); exit {:?}, stderr: {}",
        t.code,
        t.stderr
    );
    assert!(
        ["timed out", "No route to host", "Network is unreachable"]
            .iter()
            .any(|m| t.stderr.contains(m)),
        "negative probe: socat failed, but not with a routing failure; stderr: {}",
        t.stderr
    );
    assert_eq!(
        r.probe_positive,
        Ok(200),
        "positive control: the host could not GET http://{AGENT_HOST_CDP}/json/version"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_goal_002_compose_ws_secrets_stay_out_of_logs() {
    let r = run();
    // The scan means something only if the canary actually moved.
    assert!(
        r.fills.is_ok(),
        "the fills did not run: {:?}",
        r.fills.as_ref().err()
    );
    assert_eq!(r.page_posts.len(), FILLS, "the canary reached the page");
    let mut secrets = vec![
        ("canary".to_owned(), r.canary.clone()),
        (
            "canary (hex of its text)".to_owned(),
            hex::encode(r.canary.as_bytes()),
        ),
        ("agent token".to_owned(), r.agent_token.clone()),
        ("tunnel token".to_owned(), r.tunnel_token.clone()),
    ];
    for (n, pem) in r.tls_keys.iter().enumerate() {
        // The base64 body, which a log would carry with or without the
        // armor lines and line breaks.
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        secrets.push((format!("TLS private key {n}"), body));
        if let Some(first) = pem.lines().nth(1) {
            secrets.push((
                format!("TLS private key {n} (first line)"),
                first.to_owned(),
            ));
        }
    }
    // kharond and the connector only: the fake edge is socat, which logs
    // nothing at default verbosity. The relay-plaintext clause is covered
    // in-process by req_arch_002_ws_relay.rs::relay_sees_neither_canary_nor_credential.
    assert_eq!(r.logs.len(), 2);
    for (container, logs) in &r.logs {
        assert!(!logs.is_empty(), "no {container} logs were collected");
        for (what, secret) in &secrets {
            assert!(
                !logs.contains(secret.as_str()),
                "the {what} is in the {container} logs"
            );
        }
        api_support::assert_no_canary(logs);
    }
}
