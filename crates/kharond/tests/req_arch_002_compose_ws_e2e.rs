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
    add_canary_item, browser_ws_url, env, fixture_scope, manifest, page_tls, random_hex32,
    serve_page, write_public,
};
use docker_support::{docker, docker_on_tty, docker_raw, wait_for_log};
use kharond::api::token::{generate, generate_tunnel};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
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
const CONNECTOR_CONFIG: &str = "/etc/kharon-connector/connector.toml";

const FILLS: usize = 10;
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
# (ten fills, and the pending_approval retry). Production stays 10/min
# and 5/item/10min.
fills_per_minute = {FILL_ADMISSIONS}
item_fills_per_window = {FILL_ADMISSIONS}

[audit]
checkpoint_local_only = true

[public_ingress]
listen = "{PUBLIC_INGRESS}"

[owner_ui]
listen = "{OWNER_UI}"
origin = "http://localhost:8788"

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
    /// The test page server (Task 3 drives fills against it).
    #[allow(dead_code)]
    page_port: u16,
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

/// A CA and a server leaf for `host` signed by it: (ca pem, leaf cert
/// pem, leaf key pem).
fn edge_pki(host: &str) -> (String, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![host.to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    (ca.pem(), leaf.pem(), leaf_key.serialize_pem())
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
    compose(&[
        "rm",
        "-sf",
        "holder",
        "fake-edge",
        "kharon",
        "agent-host",
        "connector",
    ]);
    docker_raw(&["volume", "rm", &format!("{PROJECT}_kharon-data")], None);
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
    let (edge_ca, edge_cert, edge_key) = edge_pki("kharon.e2e.test");
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

    // 4. The agent host creates the networks; then the test page can be
    // served on the edge gateway and the browser is reachable.
    compose(&["up", "-d", "--no-build", "agent-host"]);
    // Chromium answers on the harness network (Task 3 drives it).
    let _browser_ws = browser_ws_url(AGENT_HOST_CDP.parse().unwrap()).await;
    let (page_port, _submits) = serve_page(PAGE_ADDR, acceptor, &canary).await;

    // 5. The agent and tunnel tokens, and the two configs.
    let (_token, hash) = generate("alpha");
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
        &format!("kharond: public ingress listening on {PUBLIC_INGRESS}"),
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
    wait_for_log(KHAROND, DETACH, Duration::from_secs(30));
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
            "the connector never attached over ws; kharond logs:\n{logs}\nconnector logs:\n{}",
            compose(&["logs", "--no-color", "connector"])
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    Run {
        check_code: check.status.code(),
        check_stdout,
        check_stderr,
        tunnel_token,
        attach_logs,
        attaches_before,
        page_port,
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
        cfg.public_ingress.as_ref().unwrap().listen.to_string(),
        PUBLIC_INGRESS
    );
    assert_eq!(cfg.owner_ui.as_ref().unwrap().listen.to_string(), OWNER_UI);
    assert!(cfg.connector.as_ref().unwrap().websocket);
    assert!(cfg.connector.as_ref().unwrap().listen.is_none());
    assert_eq!(cfg.policy.fills_per_minute, FILL_ADMISSIONS);
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_arch_002_compose_ws_connector_check_passes_through_the_fake_edge() {
    let r = run();
    assert_eq!(
        r.check_code,
        Some(0),
        "connector --check failed; stdout:\n{}\nstderr:\n{}",
        r.check_stdout,
        r.check_stderr
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
    assert!(
        !r.check_stdout.contains(&r.tunnel_token) && !r.check_stderr.contains(&r.tunnel_token),
        "the tunnel token is in the --check output"
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
