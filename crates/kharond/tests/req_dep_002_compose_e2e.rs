//! The compose E2E (issue #24): the compose example
//! (`deploy/compose/docker-compose.yml`, plus `compose.vpn.yml`) with
//! the CI overlay (`deploy/compose/e2e/compose.e2e.yml`) runs kharond from the
//! built image against the seeded Vaultwarden fixture, and fills a
//! test page through the agent host's headless Chromium.
//!
//! One shared run (`run()`, set up once per test binary) backs five
//! tests, one per acceptance criterion:
//!
//! - **REQ-DEP-002**: compose up, then a seeded item fills a test page
//!   through headless Chromium; here 10 times, each fill followed by
//!   a real form submit (a POST the page server checks).
//! - **REQ-DEP-006**: `ss -ltn` in kharond's network namespace shows
//!   only the configured wg address (10.66.0.1:8787) and the two
//!   loopback listeners (public ingress 127.0.0.1:8790, owner UI
//!   127.0.0.1:8788) for kharond, and the owner API is a unix socket.
//! - **REQ-ARCH-004**: after the 10 fills, the agent-host profile's
//!   `Login Data` has 0 rows, and Chromium reports the password
//!   manager and autofill saving off by managed policy. The fills run
//!   in the agent's own browser context, which Chromium does not
//!   persist, so the policy readback is the part that would catch a
//!   misconfigured agent host; the row count guards the on-disk store.
//! - **REQ-GOAL-002**: the item's password is a 32-byte random canary
//!   (hex), and `grep -r` across the agent host's `/` (excluding
//!   `/proc`, and `/sys`, whose files hold no stored data and can
//!   block) and the browser profile finds it nowhere, ASCII or
//!   UTF-16LE, both while Chromium runs and after it shuts down.
//! - **N1 (#207)**: kharond shares the `holder` container's network
//!   namespace, so a `fake-edge` container joined to the holder (a
//!   stand-in for cloudflared, with socat) reaches kharond's two
//!   loopback listeners: `POST /mcp` on the public ingress answers 401
//!   and `GET /` on the owner UI answers 200. The owner UI runs in
//!   public mode (#208), so it also answers 421 to a foreign `Host` and
//!   403 to a POST with no `Origin`. It does so at the start
//!   and after `restart kharon`, `up --force-recreate kharon` (kharond
//!   really replaced, holder and fake-edge not) and a whole-stack
//!   `restart`.
//!
//! The run, in order:
//!
//! 1. `image.yml` has built `kharon:e2e` and the agent-host image,
//!    brought up the fixture `vaultwarden` service, and seeded it
//!    (`seed.py --live`, the same as `fixture.yml`).
//! 2. The canary item is added through `mutate.py add` (password via
//!    the environment, never argv).
//! 3. The agent host starts with the test page's certificate SPKI;
//!    its Chromium is reachable at 10.66.0.2:9222 on the wg network.
//! 4. The fake edge starts in the holder's namespace. The test writes `kharon.toml` and the API key to
//!    `deploy/compose/e2e/run/` and starts `kharon`, which binds its
//!    agent API on 10.66.0.1:8787 only. The owner unlocks with
//!    `docker exec -it kharon unlock`, typing the master password at
//!    the echo-off prompt on a pty (the CLI refuses a piped one).
//! 5. The agent (this test) asks for its browser context and fills.
//!    The first fill is `pending_approval` (#20, REQ-APR-001); the
//!    owner approves it (per-origin) through the owner socket and
//!    the fill is retried — see `owner_approve`. Both that call and
//!    the retry spend a fill admission, so the harness `[policy]`
//!    raises the fill budgets above the production defaults
//!    (`FILL_ADMISSIONS`). The daemon defaults themselves stay.
//!
//! Ignored by default. Env: `KHARON_FIXTURE_BASE_URL`,
//! `KHARON_FIXTURE_CA_CERT`, `KHARON_FIXTURE_API_KEY_JSON` (as for
//! the other live tests). `ss` runs under `nsenter`, via `sudo -n`
//! unless the test runs as root.

mod api_support;
mod compose_support;
mod docker_support;

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api_support::{assert_no_canary, get, post_json, raw_request};
use compose_support::{
    Cdp, PAGE_HOST, add_canary_item, browser_ws_url, data_volume_of, env, fixture_scope, id_of,
    identity, manifest, owner_approve, page_tls, random_hex32, serve_page, ss_in, write_public,
};
use docker_support::{docker, docker_on_tty, docker_raw, wait_for_log};
use futures_util::SinkExt;
use kharond::api::token::generate;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;
use url::Url;

const COMPOSE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/compose");
const PROJECT: &str = "kharon-e2e";
const KHAROND: &str = "kharon-e2e-kharond";
const AGENT_HOST: &str = "kharon-e2e-agent-host";
/// The network-namespace holder and the stand-in for cloudflared.
const HOLDER: &str = "kharon-e2e-holder";
const FAKE_EDGE: &str = "kharon-e2e-fake-edge";
/// The agent-host image (compose.e2e.yml): Debian + socat, which
/// the owner-approve helper below borrows for its socket client.
const AGENT_HOST_IMAGE: &str = "kharon-e2e-agent-host:local";

/// Addresses on the compose `wg` network (stand-in for the tunnel).
const AGENT_API: &str = "10.66.0.1:8787";
/// kharond's loopback listeners, in the holder's namespace.
const PUBLIC_INGRESS: &str = "127.0.0.1:8790";
const OWNER_UI: &str = "127.0.0.1:8788";
/// The owner UI's public origin (#208): the Host the fake edge sends,
/// as the tunnel would pass the browser's.
const OWNER_PUBLIC_HOST: &str = "kharon-owner.e2e.test";
const OWNER_PUBLIC_ORIGIN: &str = "https://kharon-owner.e2e.test";
const AGENT_HOST_CDP: &str = "10.66.0.2:9222";
/// The docker host's address on `wg`, where the test page is served.
const PAGE_ADDR: &str = "10.66.0.254";
const PROFILE: &str = "/home/browser/profile";

const FILLS: usize = 10;
/// Admissions the shared setup spends on one agent and one item:
/// [`FILLS`] successes, plus the first call's `pending_approval`
/// (the retry is a second `admit_fill`, and a refusal still counts).
/// Production defaults are 10/min and 5/item/10min, which stop this
/// run at fill 4.
const FILL_ADMISSIONS: u32 = FILLS as u32 + 1;

fn compose(args: &[&str]) -> String {
    let base = [
        "compose",
        "-f",
        &format!("{COMPOSE_DIR}/docker-compose.yml"),
        "-f",
        &format!("{COMPOSE_DIR}/compose.vpn.yml"),
        "-f",
        &format!("{COMPOSE_DIR}/e2e/compose.e2e.yml"),
        "-p",
        PROJECT,
        "--profile",
        "vaultwarden",
    ]
    .map(String::from);
    let all: Vec<&str> = base
        .iter()
        .map(String::as_str)
        .chain(args.iter().copied())
        .collect();
    docker(&all)
}

/// Compose-harness daemon config. Fill budgets cover [`FILL_ADMISSIONS`];
/// every other `[policy]` knob is omitted so it stays at the production
/// default.
fn kharond_toml(email: &str, org: &str, coll: &str, hash: &str, cdp: &str) -> String {
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
token_hash = "{hash}"
cdp = {{ endpoint = "{cdp}", via = "wireguard" }}

[policy]
# Harness only: {FILL_ADMISSIONS} admissions of one item inside a minute
# (ten fills, and the pending_approval retry). Production stays 10/min
# and 5/item/10min.
fills_per_minute = {FILL_ADMISSIONS}
item_fills_per_window = {FILL_ADMISSIONS}

[audit]
checkpoint_local_only = true

[api]
listen = "{AGENT_API}"

[public_ingress]
listen = "{PUBLIC_INGRESS}"

[owner_ui]
listen = "{OWNER_UI}"
public_origin = "{OWNER_PUBLIC_ORIGIN}"
"#
    )
}

// ------------------------------------------------------------ the run

/// What the shared run observed, for the per-REQ tests to assert on.
struct Run {
    /// `ss -ltnpH` in kharond's network namespace.
    ss_tcp: String,
    /// `ss -lxpH` in the same namespace.
    ss_unix: String,
    /// `chrome://prefs-internals` entries for the policy-managed prefs.
    prefs: Value,
    /// `select count(*) from logins` in the profile's `Login Data`.
    login_rows: String,
    /// Files holding the canary (ASCII, UTF-16LE): Chromium running.
    hits_running: Vec<String>,
    /// The same after Chromium shut down cleanly.
    hits_after_close: Vec<String>,
    /// Positive control: profile files holding a marker visited in the
    /// default (persistent) context.
    control_hits: Vec<String>,
    /// The fake edge's probes of kharond's loopback listeners, at the
    /// start and after each restart (N1, #207).
    edge: Vec<EdgeCheck>,
}

/// HTTP statuses the fake edge got from kharond's two loopback
/// listeners; 0 means no HTTP status line came back.
#[derive(Debug, PartialEq)]
struct EdgeProbe {
    /// `POST /mcp` without credentials, on the public ingress.
    mcp: u16,
    /// `GET /` on the owner UI, signed out, with the public Host.
    owner_home: u16,
    /// The same with a Host that is not the public host (#208).
    owner_wrong_host: u16,
    /// `POST /owner/login/options` with the public Host and no `Origin`.
    owner_no_origin: u16,
    /// `POST /owner/approve/AAAA` with the public Host and no `Origin`:
    /// the ntfy redeem route takes none (an unknown token is 410).
    owner_redeem_no_origin: u16,
    /// `POST /owner/login/options` with the public Host and the right
    /// `Origin`: past the Origin rule; no passkey is enrolled (409).
    owner_right_origin: u16,
}

impl EdgeProbe {
    /// What a healthy stack answers (#207, #208).
    const EXPECTED: EdgeProbe = EdgeProbe {
        mcp: 401,
        owner_home: 200,
        owner_wrong_host: 421,
        owner_no_origin: 403,
        owner_redeem_no_origin: 410,
        owner_right_origin: 409,
    };
}

/// One probe, and what survived the step that preceded it.
struct EdgeCheck {
    after: &'static str,
    probe: EdgeProbe,
    /// Holder / fake-edge identity unchanged. `None` where the step
    /// does not compare identities (start; whole-stack restart, which
    /// restarts both); `shared_netns` covers those.
    holder_kept: Option<bool>,
    edge_kept: Option<bool>,
    /// kharond's container ID changed.
    kharond_replaced: bool,
    /// kharond's ID or start time changed.
    kharond_restarted: bool,
    /// Holder, kharond and fake-edge are in one network namespace.
    shared_netns: bool,
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
        Err(msg) => panic!("compose E2E setup failed: {msg}"),
    }
}

/// Sends `request` to `addr` from the fake edge (socat in the holder's
/// namespace) and returns the status of the reply's first line.
fn edge_status(addr: &str, request: &str) -> u16 {
    let out = docker_raw(
        &[
            "exec",
            "-i",
            FAKE_EDGE,
            "socat",
            "-t",
            "5",
            "-",
            // shut-none: socat's default half-close on stdin EOF makes
            // hyper abort before it answers (measured 8/40 vs 40/40).
            &format!("TCP:{addr},shut-none"),
        ],
        Some(request.as_bytes()),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut parts = stdout.lines().next().unwrap_or("").split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(version), Some(code)) if version.starts_with("HTTP/") => code.parse().unwrap_or(0),
        _ => 0,
    }
}

fn edge_probe() -> EdgeProbe {
    EdgeProbe {
        mcp: edge_status(
            PUBLIC_INGRESS,
            "POST /mcp HTTP/1.1\r\nHost: kharon.twkr.io\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        ),
        owner_home: edge_status(
            OWNER_UI,
            &format!("GET / HTTP/1.1\r\nHost: {OWNER_PUBLIC_HOST}\r\nConnection: close\r\n\r\n"),
        ),
        owner_wrong_host: edge_status(
            OWNER_UI,
            "GET / HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n",
        ),
        owner_no_origin: edge_status(
            OWNER_UI,
            &format!(
                "POST /owner/login/options HTTP/1.1\r\nHost: {OWNER_PUBLIC_HOST}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        ),
        owner_redeem_no_origin: edge_status(
            OWNER_UI,
            &format!(
                "POST /owner/approve/AAAA HTTP/1.1\r\nHost: {OWNER_PUBLIC_HOST}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
        ),
        owner_right_origin: edge_status(
            OWNER_UI,
            &format!(
                "POST /owner/login/options HTTP/1.1\r\nHost: {OWNER_PUBLIC_HOST}\r\nOrigin: {OWNER_PUBLIC_ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        ),
    }
}

/// Polls [`edge_probe`] until the listeners answer as expected
/// ([`EdgeProbe::EXPECTED`]), or 60 s pass; either way, returns the last probe.
fn wait_edge() -> EdgeProbe {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let probe = edge_probe();
        if probe == EdgeProbe::EXPECTED || Instant::now() >= deadline {
            return probe;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Files on the agent host holding `needle`, as ASCII and as UTF-16LE:
/// `grep -r` across `/` (excluding `/proc` and `/sys`) and the profile.
/// The ASCII needle goes in on stdin; the UTF-16 pattern is in grep's
/// argv, which lives only under the excluded `/proc`.
fn agent_host_files_containing(needle: &str) -> Vec<String> {
    let mut hits = Vec::new();
    let ascii = docker_raw(
        &[
            "exec",
            "-i",
            "-u",
            "0",
            "-e",
            "LC_ALL=C",
            AGENT_HOST,
            "grep",
            "-rlF",
            "-D",
            "skip",
            "--exclude-dir=proc",
            "--exclude-dir=sys",
            "-f",
            "-",
            "/",
            PROFILE,
        ],
        Some(format!("{needle}\n").as_bytes()),
    );
    let utf16: String = needle.chars().map(|c| format!("{c}\\x00")).collect();
    let wide = docker_raw(
        &[
            "exec",
            "-u",
            "0",
            "-e",
            "LC_ALL=C",
            AGENT_HOST,
            "grep",
            "-rlP",
            "-D",
            "skip",
            "--exclude-dir=proc",
            "--exclude-dir=sys",
            "-e",
            &utf16,
            "/",
            PROFILE,
        ],
        None,
    );
    for (what, out) in [("ascii", ascii), ("utf-16le", wide)] {
        let code = out.status.code();
        assert!(
            code == Some(0) || code == Some(1),
            "agent-host grep ({what}) failed ({code:?}): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        hits.extend(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|l| format!("{what}: {l}")),
        );
    }
    hits
}

/// The network namespace of `container`, read from the host
/// (`/proc/<pid>/ns/net`).
fn netns(container: &str) -> String {
    let pid = docker(&["inspect", "--format", "{{.State.Pid}}", container]);
    let pid = pid.trim();
    let mut cmd = if rustix::process::geteuid().is_root() {
        Command::new("readlink")
    } else {
        let mut c = Command::new("sudo");
        c.args(["-n", "readlink"]);
        c
    };
    let out = cmd
        .arg(format!("/proc/{pid}/ns/net"))
        .output()
        .expect("readlink");
    assert!(
        out.status.success(),
        "readlink netns of {container}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Holder, kharond and the fake edge share one network namespace.
fn shared_netns() -> bool {
    let holder = netns(HOLDER);
    holder == netns(KHAROND) && holder == netns(FAKE_EDGE)
}

async fn setup() -> Run {
    let base = Url::parse(&env("KHARON_FIXTURE_BASE_URL")).unwrap();
    let ca = PathBuf::from(env("KHARON_FIXTURE_CA_CERT"));
    let m = manifest();
    let email = m["account"]["email"].as_str().unwrap().to_owned();
    let master = m["account"]["password"].as_str().unwrap().to_owned();

    let run_dir = PathBuf::from(format!("{COMPOSE_DIR}/e2e/run"));
    let page_dir = run_dir.join("page");
    std::fs::create_dir_all(&page_dir).unwrap();

    // The canary item, then the scope (org + collection) to sync.
    let canary = random_hex32();
    // Unique per run, so a reused fixture never hands back an older
    // run's item (the name carries nothing of the canary).
    let item_name = format!(
        "kharon-e2e-canary-{}",
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

    // The agent host, trusting the test page's key by SPKI; the page
    // is served once the wg network (and the gateway address) exists.
    let (acceptor, spki) = page_tls();
    write_public(&page_dir.join("page-spki"), spki.as_bytes());
    compose(&["up", "-d", "--no-build", "agent-host"]);
    let (port, submits) = serve_page(PAGE_ADDR, acceptor, &canary).await;
    let browser_ws = browser_ws_url(AGENT_HOST_CDP.parse().unwrap()).await;

    // kharond: sync mode against the fixture over the vw network,
    // agent API on the wg address, CDP to the agent host over wg.
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    // The base address, as the deployment guide configures it: kharond
    // resolves the browser id through the relay itself (issue #113).
    let toml = kharond_toml(
        &email,
        &org,
        &coll,
        &hash,
        &format!("ws://{AGENT_HOST_CDP}"),
    );
    write_public(&run_dir.join("kharon.toml"), toml.as_bytes());
    compose(&["up", "-d", "--no-build", "kharon"]);
    compose(&["up", "-d", "--no-build", "fake-edge"]);
    wait_for_log(
        KHAROND,
        &format!("agent API listening on {AGENT_API} (locked)"),
        Duration::from_secs(60),
    );

    // The owner unlocks through the CLI in the container, typing the
    // password at its prompt on a terminal, as an operator would. The
    // CLI refuses a piped password (#131 slice 5a, SPEC §8).
    let (unlocked, tty) = docker_on_tty(
        &["exec", "-it", KHAROND, "kharon", "unlock"],
        "kharon master password:",
        &master,
    );
    assert!(!tty.contains(&master), "the master password was echoed");
    assert!(unlocked, "kharon unlock: {tty}");

    // REQ-DEP-006: listeners in kharond's network namespace.
    let ss_tcp = ss_in(KHAROND, "-ltnpH").expect("ss -ltnpH in kharond");
    let ss_unix = ss_in(KHAROND, "-lxpH").expect("ss -lxpH in kharond");

    // The canary item, by name, from the agent API.
    let api: std::net::SocketAddr = AGENT_API.parse().unwrap();
    let list = get(api, "/v1/items", Some(&token)).await;
    assert_eq!(list.status, 200, "{}", list.body);
    assert_no_canary(&list.body);
    assert!(!list.body.contains(&canary), "canary in /v1/items");
    let item_id = list
        .json()
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == json!(item_name))
        .unwrap_or_else(|| panic!("canary item not listed: {}", list.body))["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // The agent's browser context (REQ-ARCH-005).
    let head = format!(
        "POST /v1/context HTTP/1.1\r\nHost: {AGENT_API}\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let ctx = raw_request(api, head.as_bytes()).await;
    assert_eq!(ctx.status, 200, "{}", ctx.body);
    let context = ctx.json()["browser_context_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no browser_context_id: {}", ctx.body))
        .to_owned();

    // REQ-DEP-002 / REQ-ARCH-004: ten fills, each followed by a submit.
    let mut cdp = Cdp::connect(&browser_ws).await;
    let url = format!("https://{PAGE_HOST}:{port}/login");
    let origin = format!("https://{PAGE_HOST}:{port}");
    for n in 0..FILLS {
        let ready = format!(
            "location.href === {} && document.readyState === 'complete'",
            json!(url)
        );
        let (target, session) = cdp.open(Some(&context), &url, &ready).await;
        let secure = cdp.eval(&session, "window.isSecureContext").await;
        assert_eq!(secure, json!(true), "test page must be a secure context");
        let body = json!({
            "item_id": item_id,
            "target": {"cdp_target_id": target, "expected_origin": origin},
            "fields": [{"kind": "username"}, {"kind": "password"}],
            // REQ-API-008 / #102: submit:true on a navigating form must
            // report `filled` with fields_filled, not `navigated`.
            "submit": true,
        });
        let r = post_json(api, "/v1/fill", Some(&token), &body.to_string()).await;
        assert_eq!(r.status, 200, "fill {n}: {}", r.body);
        assert!(!r.body.contains(&canary), "canary in a fill reply");
        assert_no_canary(&r.body);
        let res = r.json();
        // REQ-APR-001 (#20): with no grant yet, a fill is
        // `pending_approval` and nothing is decrypted. The owner
        // approves the request (per-origin: this item at this
        // origin, so the remaining fills are admitted) and the
        // same fill is retried.
        let res = if res["status"] == json!("pending_approval") {
            let grid = res["grant_request_id"]
                .as_str()
                .unwrap_or_else(|| panic!("pending_approval without a grant_request_id: {res}"))
                .to_owned();
            owner_approve(&data_volume_of(KHAROND), AGENT_HOST_IMAGE, &grid);
            let r = post_json(api, "/v1/fill", Some(&token), &body.to_string()).await;
            assert_eq!(r.status, 200, "fill {n} retry: {}", r.body);
            assert!(!r.body.contains(&canary), "canary in a fill reply");
            assert_no_canary(&r.body);
            r.json()
        } else {
            res
        };
        assert_eq!(res["status"], json!("filled"), "fill {n}: {res}");
        assert_eq!(res["fields_filled"], json!(["username", "password"]));
        // The in-page submit posted the canary (a real navigation).
        let deadline = Instant::now() + Duration::from_secs(30);
        while submits.lock().unwrap().len() < n + 1 {
            assert!(Instant::now() < deadline, "fill {n}: the form never posted");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            submits.lock().unwrap()[n],
            "fill {n}: the posted password is not the seeded canary"
        );
        cdp.wait(
            &session,
            "location.pathname === '/submitted' && document.readyState === 'complete'",
            "post-submit page",
        )
        .await;
        cdp.call(None, "Target.closeTarget", json!({"targetId": target}))
            .await;
    }
    assert_eq!(submits.lock().unwrap().len(), FILLS, "one POST per fill");

    // Let any deferred profile writes land, then look while running.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let hits_running = agent_host_files_containing(&canary);

    // REQ-ARCH-004: Chromium's own view of the policy-managed prefs.
    let (target, session) = cdp
        .open(
            None,
            "chrome://prefs-internals/",
            "document.readyState === 'complete' && document.body !== null && document.body.innerText.length > 0",
        )
        .await;
    let text = cdp.eval(&session, "document.body.innerText").await;
    let all: Value = serde_json::from_str(text.as_str().unwrap()).unwrap();
    let prefs = json!({
        "credentials_enable_service": all["credentials_enable_service"],
        "autofill.profile_enabled": all["autofill"]["profile_enabled"],
        "autofill.credit_card_enabled": all["autofill"]["credit_card_enabled"],
    });
    cdp.call(None, "Target.closeTarget", json!({"targetId": target}))
        .await;

    // Positive control for the grep: a second random 64-hex marker,
    // visited in the default (on-disk) profile so History keeps it.
    // The agent's own context is not persisted, so finding this one
    // and not the canary shows the grep can see what Chromium stores.
    let marker = random_hex32();
    let control_url = format!("https://{PAGE_HOST}:{port}/login?control={marker}");
    let ready = format!(
        "location.href === {} && document.readyState === 'complete'",
        json!(control_url)
    );
    let (target, _) = cdp.open(None, &control_url, &ready).await;
    cdp.call(None, "Target.closeTarget", json!({"targetId": target}))
        .await;

    // Clean browser shutdown flushes the profile; then look again.
    // Chromium may drop the connection before it answers; don't wait.
    cdp.next += 1;
    let close = json!({"id": cdp.next, "method": "Browser.close", "params": {}});
    let _ = cdp.ws.send(Message::Text(close.to_string())).await;
    drop(cdp);
    wait_for_log(
        AGENT_HOST,
        "agent-host: chromium exited",
        Duration::from_secs(30),
    );
    let hits_after_close = agent_host_files_containing(&canary);
    let control = docker_raw(
        &[
            "exec", "-u", "0", AGENT_HOST, "grep", "-rlF", "-D", "skip", &marker, PROFILE,
        ],
        None,
    );
    let control_hits = String::from_utf8_lossy(&control.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    let login_rows = docker(&[
        "exec",
        AGENT_HOST,
        "sqlite3",
        &format!("file:{PROFILE}/Default/Login Data?mode=ro"),
        "select count(*) from logins;",
    ])
    .trim()
    .to_owned();

    // kharond logged nothing secret; lock it.
    let logs = docker_raw(&["logs", KHAROND], None);
    for stream in [&logs.stdout, &logs.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(&canary),
            "canary in kharond's logs"
        );
    }
    let lock = docker_raw(&["exec", KHAROND, "kharon", "lock"], None);
    assert!(lock.status.success(), "kharon lock");

    // N1 (#207): the edge keeps reaching kharond's loopback listeners
    // while kharond restarts around the holder.
    let mut edge = vec![EdgeCheck {
        after: "start",
        probe: wait_edge(),
        holder_kept: None,
        edge_kept: None,
        kharond_replaced: false,
        kharond_restarted: false,
        shared_netns: shared_netns(),
    }];
    let holder0 = identity(HOLDER);
    let edge0 = identity(FAKE_EDGE);
    for (after, args) in [
        ("restart kharon", &["restart", "kharon"][..]),
        (
            "up --force-recreate kharon",
            &["up", "-d", "--no-build", "--force-recreate", "kharon"][..],
        ),
        ("restart (whole stack)", &["restart"][..]),
    ] {
        let kharond_before = identity(KHAROND);
        compose(args);
        let probe = wait_edge();
        let whole = args == ["restart"];
        let kharond_after = identity(KHAROND);
        // Identities are compared against the start only on the steps
        // that leave holder and fake-edge running.
        edge.push(EdgeCheck {
            after,
            probe,
            holder_kept: (!whole).then(|| identity(HOLDER) == holder0),
            edge_kept: (!whole).then(|| identity(FAKE_EDGE) == edge0),
            kharond_replaced: id_of(&kharond_after) != id_of(&kharond_before),
            kharond_restarted: kharond_after != kharond_before,
            shared_netns: shared_netns(),
        });
    }

    Run {
        ss_tcp,
        ss_unix,
        prefs,
        login_rows,
        hits_running,
        hits_after_close,
        control_hits,
        edge,
    }
}

// ------------------------------------------------------------ tests

/// The harness config parses, covers the 10-fill path, and does not
/// rewrite the other production policy defaults.
#[test]
fn compose_harness_fill_budget_covers_arch_004_and_leaves_other_defaults() {
    let toml = kharond_toml(
        "kharon@example.net",
        "0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6",
        "11111111-2222-3333-4444-555555555555",
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash",
        "ws://10.66.0.2:9222",
    );
    let cfg = kharond::config::Config::from_toml_str(&toml).unwrap();
    let production = kharond::config::PolicyConfig::default();
    assert!(FILL_ADMISSIONS > production.fills_per_minute);
    assert!(FILL_ADMISSIONS > production.item_fills_per_window);
    assert_eq!(cfg.policy.fills_per_minute, FILL_ADMISSIONS);
    assert_eq!(cfg.policy.item_fills_per_window, FILL_ADMISSIONS);
    assert_eq!(cfg.policy.fills_per_day, production.fills_per_day);
    assert_eq!(cfg.policy.list_per_minute, production.list_per_minute);
    assert_eq!(cfg.policy.item_fill_window, production.item_fill_window);
    assert_eq!(cfg.policy.max_pending_grants, production.max_pending_grants);
    assert_eq!(
        cfg.policy.origin_mismatch_suspend,
        production.origin_mismatch_suspend
    );
    assert_eq!(cfg.policy.idle_lock, production.idle_lock);
    assert_eq!(cfg.policy.fill_deadline, production.fill_deadline);
    assert_eq!(cfg.policy.default_grant, production.default_grant);
    assert!(!cfg.policy.allow_standing);
    assert_eq!(
        cfg.public_ingress.as_ref().unwrap().listen.to_string(),
        PUBLIC_INGRESS
    );
    let ui = cfg.owner_ui.as_ref().unwrap();
    assert_eq!(ui.listen.to_string(), OWNER_UI);
    assert!(ui.public, "the harness owner UI is in public mode");
    assert_eq!(ui.origin, OWNER_PUBLIC_ORIGIN);
    assert_eq!(ui.rp_id, OWNER_PUBLIC_HOST);
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_dep_002_compose_up_seeded_fixture_fills_test_page_through_headless_chromium() {
    // The fills themselves (status, POSTed canary, no secret in any
    // reply) are asserted inside the run; reaching here means all
    // FILLS of them passed.
    run();
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_dep_006_ss_ltn_shows_only_wg_and_loopback_listeners() {
    let r = run();
    eprintln!("ss -ltnp:\n{}", r.ss_tcp);
    let mut kharond = Vec::new();
    for line in r.ss_tcp.lines().filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let local = cols[3];
        if line.contains("\"kharond\"") {
            kharond.push(local.to_owned());
        } else {
            // Docker's embedded DNS resolver listens in every container
            // on a user-defined network, on 127.0.0.11 only.
            assert!(
                local.starts_with("127.0.0.11:"),
                "unexpected listener in kharond's netns: {line}"
            );
        }
    }
    kharond.sort();
    let mut want = vec![AGENT_API, OWNER_UI, PUBLIC_INGRESS];
    want.sort();
    assert_eq!(kharond, want, "{}", r.ss_tcp);
    // The owner API is the unix socket in /data, not a TCP port.
    assert!(
        r.ss_unix
            .lines()
            .any(|l| l.contains("/data/owner.sock") && l.contains("\"kharond\"")),
        "no kharond owner socket in ss -lx:\n{}",
        r.ss_unix
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn n1_edge_reaches_both_loopback_listeners_across_kharond_restarts() {
    let r = run();
    let steps: Vec<&str> = r.edge.iter().map(|c| c.after).collect();
    assert_eq!(
        steps,
        [
            "start",
            "restart kharon",
            "up --force-recreate kharon",
            "restart (whole stack)"
        ]
    );
    for c in &r.edge {
        assert_eq!(c.probe, EdgeProbe::EXPECTED, "edge probe after {}", c.after);
    }
    for c in &r.edge[1..3] {
        assert_eq!(c.holder_kept, Some(true), "holder replaced by {}", c.after);
        assert_eq!(c.edge_kept, Some(true), "fake-edge replaced by {}", c.after);
    }
    for c in &r.edge {
        assert!(
            c.shared_netns,
            "holder, kharond and fake-edge do not share a netns after {}",
            c.after
        );
    }
    assert!(
        r.edge[1].kharond_restarted && !r.edge[1].kharond_replaced,
        "restart kharon must restart the same container"
    );
    assert!(
        r.edge[2].kharond_replaced,
        "--force-recreate did not replace kharond"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_arch_004_login_data_has_0_rows_after_10_fills() {
    let r = run();
    assert_eq!(r.login_rows, "0", "Login Data rows after {FILLS} fills");
    // Saving is off by managed policy, as Chromium itself reports.
    let off = json!({"metadata": ["managed"], "value": false});
    for (pref, got) in r.prefs.as_object().unwrap() {
        assert_eq!(got, &off, "{pref}: {got}");
    }
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_goal_002_canary_not_on_agent_host_filesystem() {
    let r = run();
    assert!(
        r.hits_running.is_empty(),
        "canary on the agent host while Chromium runs: {:?}",
        r.hits_running
    );
    assert!(
        r.hits_after_close.is_empty(),
        "canary on the agent host after Chromium shut down: {:?}",
        r.hits_after_close
    );
    // The same grep does find a 64-hex marker the browser was given
    // in its persistent profile, so a clean result is not a blind grep.
    assert!(
        !r.control_hits.is_empty(),
        "control grep found nothing in the profile"
    );
}
