//! The compose E2E for the OAuth Connect flow (issue #234, N3).
//!
//! The stack is `deploy/compose/docker-compose.yml` plus
//! `deploy/compose/e2e/compose.e2e-oauth.yml`: kharond in public mode
//! behind two fake TLS-terminating edges (socat in the holder's network
//! namespace), one for the agent hostname `kharon.e2e.test` and one for
//! the owner hostname `kharon-owner.e2e.test`, plus a dashboard whose
//! Client ID Metadata Document this test serves from the docker host.
//! The broker stays locked for the whole run.
//!
//! One shared run (`run()`, set up once per test binary) backs the tests:
//! it enrols a software passkey and signs in through the owner edge, then
//! walks discovery the way an MCP client would. Ignored by default. Env:
//! `KHARON_FIXTURE_BASE_URL`, `KHARON_FIXTURE_CA_CERT`,
//! `KHARON_FIXTURE_API_KEY_JSON`, as for the other compose E2E. `docker
//! compose` and the images `kharon:e2e` and `kharon-e2e-agent-host:local`
//! (the fake edges use its socat) must exist (`image.yml`).
//!
//! Every secret (the enrolment code, the session cookie) is generated
//! fresh and never printed: each error string that could hold one goes
//! through `compose_support::redact`.

mod api_support;
mod compose_support;
mod docker_support;
mod owner_ui_support;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use api_support::{RawResponse, mcp_call_bytes};
use compose_support::{edge_pki, env, fixture_scope, https_raw, manifest, redact, write_public};
use docker_support::{docker, docker_raw, wait_for_log};
use owner_ui_support::{Http, VirtAuth, b64url_dec, request_bytes};
use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

const COMPOSE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/compose");
const PROJECT: &str = "kharon-e2e-oauth";
const KHAROND: &str = "kharon-e2e-oauth-kharond";

const AGENT_HOST: &str = "kharon.e2e.test";
const OWNER_HOST: &str = "kharon-owner.e2e.test";
const DASHBOARD_HOST: &str = "dashboard.e2e.test";
/// The issuer and the owner origin: no port, kharond cannot express one.
const OWNER_ORIGIN: &str = "https://kharon-owner.e2e.test";
const RESOURCE: &str = "https://kharon.e2e.test/mcp";
const RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const AS_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";

/// The fake edges' listeners, as the host reaches them.
const AGENT_EDGE_ADDR: &str = "203.0.113.1:8443";
const OWNER_EDGE_ADDR: &str = "203.0.113.1:8444";
/// The docker host's address on `edge`, where the dashboard is served.
const DASHBOARD_BIND: &str = "203.0.113.254";
const PUBLIC_INGRESS: &str = "127.0.0.1:8790";
const OWNER_UI: &str = "127.0.0.1:8788";
/// `CF-Connecting-IP`, as the real edge would add it.
const OWNER_SRC_IP: &str = "198.51.100.10";
const SESSION_COOKIE: &str = "__Host-kharon_owner";

/// `kharon-e2e-oauth` compose arguments for `args`, in the order the
/// overlay's header documents.
fn compose_args(args: &[&str]) -> Vec<String> {
    let mut all: Vec<String> = [
        "compose",
        "-f",
        &format!("{COMPOSE_DIR}/docker-compose.yml"),
        "-f",
        &format!("{COMPOSE_DIR}/e2e/compose.e2e-oauth.yml"),
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

/// Compose-harness daemon config: public mode with the agent hostname,
/// the owner origin and one allow-listed Connect client. No `[api]`, no
/// `[connector]`.
fn kharond_toml(email: &str, org: &str, coll: &str, token_hash: &str, client_id: &str) -> String {
    format!(
        r#"mode = "sync"

[bitwarden]
server = "https://vaultwarden"
email = "{email}"
api_key_file = "/run/secrets/kharon_bw_api_key"
organization_id = "{org}"
collection_ids = ["{coll}"]
ca_file = "/etc/kharon/vault-ca.pem"

# kharond refuses a config with no agent (config/raw.rs:340). This one is
# never used: the test's agents are Connect identities, and no browser
# is attached (its cdp endpoint is never dialled).
[agents.alpha]
token_hash = "{token_hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}

[audit]
checkpoint_local_only = true

[public_ingress]
listen = "{PUBLIC_INGRESS}"
public_host = "{AGENT_HOST}"

[owner_ui]
listen = "{OWNER_UI}"
public_origin = "{OWNER_ORIGIN}"

[oauth]
clients = ["{client_id}"]
"#
    )
}

// ------------------------------------------------------------ typed documents

/// The dashboard's Client ID Metadata Document.
#[derive(Serialize, Deserialize)]
struct ClientDoc {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
}

/// RFC 9728 protected-resource metadata, as kharond serves it.
#[derive(Deserialize)]
struct ProtectedResource {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    bearer_methods_supported: Vec<String>,
}

/// RFC 8414 authorization-server metadata, as kharond serves it.
#[derive(Deserialize)]
struct AuthServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    client_id_metadata_document_supported: bool,
}

/// What discovery found, for the scenario to use (by the endpoints'
/// paths, not literals).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Discovered {
    resource: String,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

/// A WebAuthn ceremony's options (`register/options`, `login/options`).
#[derive(Deserialize)]
struct Ceremony {
    ceremony_id: String,
    #[serde(rename = "publicKey")]
    public_key: PublicKeyOptions,
}

#[derive(Deserialize)]
struct PublicKeyOptions {
    challenge: String,
    user: Option<UserOptions>,
}

#[derive(Deserialize)]
struct UserOptions {
    id: String,
}

/// `register/finish` and `login/finish`. The credential is what
/// `VirtAuth` builds (it returns a `Json`, an existing helper's shape).
#[derive(Serialize)]
struct FinishBody<'a> {
    ceremony_id: &'a str,
    credential: &'a serde_json::Value,
}

// ------------------------------------------------------------ the dashboard

/// The dashboard's metadata server.
#[derive(Clone)]
struct Dashboard {
    port: u16,
    /// How many times `GET /client.json` was answered.
    fetches: Arc<AtomicUsize>,
}

/// Serves the dashboard's CIMD over TLS (`leaf_pem` / `key_pem` for
/// [`DASHBOARD_HOST`]) on `bind_ip`, a port the OS picks. `GET
/// /client.json` is answered (and counted); anything else is a 404.
async fn serve_dashboard(bind_ip: &str, leaf_pem: &str, key_pem: &str) -> Dashboard {
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(leaf_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind(format!("{bind_ip}:0"))
        .await
        .unwrap_or_else(|e| panic!("cannot bind the dashboard on {bind_ip}: {e}"));
    let port = listener.local_addr().unwrap().port();
    let doc = serde_json::to_string(&ClientDoc {
        client_id: format!("https://{DASHBOARD_HOST}:{port}/client.json"),
        client_name: "E2E Dashboard".to_owned(),
        redirect_uris: vec![format!("https://{DASHBOARD_HOST}:{port}/callback")],
        token_endpoint_auth_method: "none".to_owned(),
    })
    .unwrap();
    let fetches = Arc::new(AtomicUsize::new(0));
    let counted = fetches.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let counted = counted.clone();
            let doc = doc.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    if buf.len() > 16 * 1024 {
                        return;
                    }
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let mut line = head.lines().next().unwrap_or("").split_whitespace();
                let reply = match (line.next(), line.next()) {
                    (Some("GET"), Some("/client.json")) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Cache-Control: max-age=3600\r\nContent-Length: {}\r\n\
                             Connection: close\r\n\r\n{doc}",
                            doc.len()
                        )
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned(),
                };
                let _ = s.write_all(reply.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Dashboard { port, fetches }
}

// ------------------------------------------------------------ transport

fn socket(addr: &str) -> SocketAddr {
    addr.parse().unwrap()
}

/// `req` to the owner edge (`Host` and `CF-Connecting-IP` set as the
/// real edge would, `Origin` on the POSTs the UI gates), trusting `ca`.
async fn owner(ca: &str, req: Http<'_>) -> Result<RawResponse, String> {
    let req = req
        .host(OWNER_HOST)
        .header("CF-Connecting-IP", OWNER_SRC_IP);
    let bytes = request_bytes(OWNER_ORIGIN, &req);
    https_raw(socket(OWNER_EDGE_ADDR), OWNER_HOST, ca, &bytes).await
}

/// Raw `request` bytes to the agent edge (SNI `kharon.e2e.test`).
async fn agent_edge(ca: &str, request: &[u8]) -> Result<RawResponse, String> {
    https_raw(socket(AGENT_EDGE_ADDR), AGENT_HOST, ca, request).await
}

/// `GET path` on the agent edge, with the agent hostname as `Host`.
async fn agent_get(ca: &str, path: &str) -> Result<RawResponse, String> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {AGENT_HOST}\r\nConnection: close\r\n\r\n");
    agent_edge(ca, request.as_bytes()).await
}

/// `r` must be `Ok` with status `want`; otherwise an error naming `step`,
/// the status and the body, passed through `redact(secrets)`.
fn expect(
    step: &str,
    r: Result<RawResponse, String>,
    want: u16,
    secrets: &[&str],
) -> Result<RawResponse, String> {
    let r = r.map_err(|e| format!("{step}: {}", redact(&e, secrets)))?;
    if r.status != want {
        return Err(format!(
            "{step}: expected HTTP {want}, got {}: {}",
            r.status,
            redact(&r.body, secrets)
        ));
    }
    Ok(r)
}

/// The body of `r` as a `T`.
fn parse<T: serde::de::DeserializeOwned>(
    step: &str,
    r: &RawResponse,
    secrets: &[&str],
) -> Result<T, String> {
    serde_json::from_str(&r.body)
        .map_err(|e| format!("{step}: bad JSON ({e}): {}", redact(&r.body, secrets)))
}

/// `check` as an error naming `step` and `what`.
fn ensure(ok: bool, step: &str, what: impl FnOnce() -> String) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("{step}: {}", what()))
    }
}

/// The `name=value` pair of the `Set-Cookie` that sets `name`.
fn cookie_pair(r: &RawResponse, name: &str) -> Option<String> {
    r.headers.iter().find_map(|(k, v)| {
        (k.eq_ignore_ascii_case("set-cookie") && v.starts_with(&format!("{name}=")))
            .then(|| v.split(';').next().unwrap().to_owned())
    })
}

// ------------------------------------------------------------ sign-in

/// Polls `GET /` on the owner edge until it answers 200.
async fn wait_owner_edge(ca: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last;
    loop {
        match owner(ca, Http::get("/")).await {
            Ok(r) if r.status == 200 => return Ok(()),
            Ok(r) => last = format!("HTTP {}", r.status),
            Err(e) => last = e,
        }
        if Instant::now() > deadline {
            return Err(format!(
                "the owner edge never answered GET / with 200 within 60 s (last: {last})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Enrols a software passkey with the one-time `code` and signs in, all
/// through the owner edge (rp id = the owner hostname). Returns the
/// passkey and the session cookie pair.
async fn enroll_and_sign_in(ca: &str, code: &str) -> Result<(VirtAuth, String), String> {
    let secrets = [code];
    let mut auth = VirtAuth::new();
    let opts = expect(
        "register/options",
        owner(
            ca,
            Http::post("/owner/register/options", None, "").bearer(code),
        )
        .await,
        200,
        &secrets,
    )?;
    let opts: Ceremony = parse("register/options", &opts, &secrets)?;
    let user = opts
        .public_key
        .user
        .ok_or("register/options: no publicKey.user")?;
    auth.user_handle = b64url_dec(&user.id);
    let credential = auth.registration(&opts.public_key.challenge, OWNER_ORIGIN, OWNER_HOST);
    let body = serde_json::to_string(&FinishBody {
        ceremony_id: &opts.ceremony_id,
        credential: &credential,
    })
    .unwrap();
    expect(
        "register/finish",
        owner(
            ca,
            Http::post("/owner/register/finish", Some("application/json"), &body),
        )
        .await,
        200,
        &secrets,
    )?;

    let cookie = sign_in(ca, &mut auth).await?;
    Ok((auth, cookie))
}

/// Signs in with `auth`; returns the session cookie pair.
async fn sign_in(ca: &str, auth: &mut VirtAuth) -> Result<String, String> {
    let opts = expect(
        "login/options",
        owner(ca, Http::post("/owner/login/options", None, "")).await,
        200,
        &[],
    )?;
    let opts: Ceremony = parse("login/options", &opts, &[])?;
    let credential = auth.assertion(&opts.public_key.challenge, OWNER_ORIGIN, OWNER_HOST);
    let body = serde_json::to_string(&FinishBody {
        ceremony_id: &opts.ceremony_id,
        credential: &credential,
    })
    .unwrap();
    let done = expect(
        "login/finish",
        owner(
            ca,
            Http::post("/owner/login/finish", Some("application/json"), &body),
        )
        .await,
        200,
        &[],
    )?;
    let cookie = cookie_pair(&done, SESSION_COOKIE)
        .ok_or_else(|| format!("login/finish: no {SESSION_COOKIE} Set-Cookie"))?;
    Ok(cookie)
}

// ------------------------------------------------------------ discovery

/// Discovery as a client would do it: the `/mcp` 401, the protected-
/// resource document it names, then the authorization server's.
async fn discover(ca: &str) -> Result<Discovered, String> {
    // 1. The 401 challenge points at the resource metadata.
    let step = "POST /mcp without a token";
    let r = expect(
        step,
        agent_edge(ca, &mcp_call_bytes(AGENT_HOST, None, "kharon_status", "{}")).await,
        401,
        &[],
    )?;
    let challenge = r.header("www-authenticate").unwrap_or("");
    let want = format!("resource_metadata=\"https://{AGENT_HOST}{RESOURCE_METADATA_PATH}\"");
    ensure(challenge.contains(&want), step, || {
        format!("WWW-Authenticate {challenge:?} lacks {want}")
    })?;

    // 2. The protected-resource document.
    let step = "GET the protected-resource metadata";
    let r = expect(step, agent_get(ca, RESOURCE_METADATA_PATH).await, 200, &[])?;
    let prm: ProtectedResource = parse(step, &r, &[])?;
    ensure(prm.resource == RESOURCE, step, || {
        format!("resource is {:?}", prm.resource)
    })?;
    ensure(prm.authorization_servers == [OWNER_ORIGIN], step, || {
        format!("authorization_servers is {:?}", prm.authorization_servers)
    })?;
    for scope in ["kharon:read", "kharon:fill", "kharon:request"] {
        ensure(
            prm.scopes_supported.iter().any(|s| s == scope),
            step,
            || format!("scopes_supported {:?} lacks {scope}", prm.scopes_supported),
        )?;
    }
    ensure(prm.bearer_methods_supported == ["header"], step, || {
        format!(
            "bearer_methods_supported is {:?}",
            prm.bearer_methods_supported
        )
    })?;

    // 3. The authorization server's document, on the owner hostname.
    let step = "GET the authorization-server metadata";
    let r = expect(step, owner(ca, Http::get(AS_METADATA_PATH)).await, 200, &[])?;
    let meta: AuthServerMetadata = parse(step, &r, &[])?;
    ensure(meta.issuer == OWNER_ORIGIN, step, || {
        format!("issuer is {:?}", meta.issuer)
    })?;
    for (name, got, path) in [
        (
            "authorization_endpoint",
            &meta.authorization_endpoint,
            "/oauth/authorize",
        ),
        ("token_endpoint", &meta.token_endpoint, "/oauth/token"),
        (
            "revocation_endpoint",
            &meta.revocation_endpoint,
            "/oauth/revoke",
        ),
    ] {
        let want = format!("{}{path}", meta.issuer);
        ensure(*got == want, step, || {
            format!("{name} is {got:?}, want {want:?}")
        })?;
    }
    ensure(
        meta.code_challenge_methods_supported == ["S256"],
        step,
        || {
            format!(
                "code_challenge_methods_supported is {:?}",
                meta.code_challenge_methods_supported
            )
        },
    )?;
    ensure(
        meta.token_endpoint_auth_methods_supported == ["none"],
        step,
        || {
            format!(
                "token_endpoint_auth_methods_supported is {:?}",
                meta.token_endpoint_auth_methods_supported
            )
        },
    )?;
    ensure(meta.client_id_metadata_document_supported, step, || {
        "client_id_metadata_document_supported is not true".to_owned()
    })?;

    Ok(Discovered {
        resource: prm.resource,
        issuer: meta.issuer,
        authorization_endpoint: meta.authorization_endpoint,
        token_endpoint: meta.token_endpoint,
        revocation_endpoint: meta.revocation_endpoint,
    })
}

// ------------------------------------------------------------ the run

/// What the shared run set up, for the tests to use.
#[allow(dead_code)]
struct Run {
    /// The edges' CA: the only root the test trusts.
    edge_ca: String,
    /// The `__Host-kharon_owner=…` pair of the signed-in owner session.
    cookie: String,
    /// The owner's passkey (its signature counter advances per sign-in).
    auth: Mutex<VirtAuth>,
    dashboard: Dashboard,
    /// The dashboard's `client_id` (its CIMD URL) and `redirect_uri`.
    client_id: String,
    redirect_uri: String,
    discovery: Discovered,
    /// The enrolment code and the cookie, for `redact`.
    secrets: Vec<String>,
}

/// One runtime for the whole binary: the dashboard's listener lives on
/// it, so it must outlive `setup()`.
static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
});

/// Runs `fut` on the shared runtime, from a synchronous test.
fn block_on<F: Future>(fut: F) -> F::Output {
    RT.block_on(fut)
}

static RUN: Mutex<Option<Result<Arc<Run>, String>>> = Mutex::new(None);

/// The shared run, set up on first use. A failed setup fails every
/// test with the same message instead of re-running compose.
fn run() -> Arc<Run> {
    let mut slot = RUN.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_none() {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| RT.block_on(setup())));
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
        Err(msg) => panic!("compose oauth E2E setup failed: {msg}"),
    }
}

/// Unwraps a setup step, failing the run with its message.
fn must<T>(r: Result<T, String>) -> T {
    r.unwrap_or_else(|e| panic!("{e}"))
}

async fn setup() -> Run {
    let base = Url::parse(&env("KHARON_FIXTURE_BASE_URL")).unwrap();
    let ca = PathBuf::from(env("KHARON_FIXTURE_CA_CERT"));
    let m = manifest();
    let email = m["account"]["email"].as_str().unwrap().to_owned();

    // 1. Stale state from an earlier run. The seeded Vaultwarden fixture
    // lives in this same project and must survive (image.yml seeds it
    // before the test runs), so `down -v` would wipe it. Remove every
    // other service instead, and the daemon's data volume (a stale audit
    // chain and passkeys would skew the run). Networks stay: `up`
    // reuses them.
    let run_dir = PathBuf::from(format!("{COMPOSE_DIR}/e2e/run-oauth"));
    std::fs::create_dir_all(&run_dir).unwrap();
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
    std::fs::create_dir_all(run_dir.join("edge")).unwrap();

    // 2. The vault's scope (org + collection) to sync.
    let api_key = run_dir.join("api-key.json");
    write_public(
        &api_key,
        &std::fs::read(env("KHARON_FIXTURE_API_KEY_JSON")).unwrap(),
    );
    let (org, coll) = fixture_scope(&base, &email, &ca, &api_key).await;

    // 3. TLS material. The daemons that read it run as other uids than
    // the host user (socat as 10002, kharond as 10001), so the keys are
    // mode 0644; they are throwaway.
    let (edge_ca, edge_cert, edge_key) = edge_pki(&[AGENT_HOST, OWNER_HOST]);
    write_public(&run_dir.join("edge").join("cert.pem"), edge_cert.as_bytes());
    write_public(&run_dir.join("edge").join("key.pem"), edge_key.as_bytes());
    let (dash_ca, dash_cert, dash_key) = edge_pki(&[DASHBOARD_HOST]);
    write_public(&run_dir.join("dashboard-ca.pem"), dash_ca.as_bytes());

    // 4. The holder creates the network, so the docker host has
    // DASHBOARD_BIND; then the dashboard's metadata can be served there.
    compose(&["up", "-d", "--no-build", "holder"]);
    let dashboard = serve_dashboard(DASHBOARD_BIND, &dash_cert, &dash_key).await;
    let client_id = format!("https://{DASHBOARD_HOST}:{}/client.json", dashboard.port);
    let redirect_uri = format!("https://{DASHBOARD_HOST}:{}/callback", dashboard.port);

    // 5. kharond's config (the dummy agent's token is thrown away).
    let (_token, hash) = kharond::api::token::generate("alpha");
    write_public(
        &run_dir.join("kharon.toml"),
        kharond_toml(&email, &org, &coll, &hash, &client_id).as_bytes(),
    );

    // 6. kharond and the two fake edges.
    compose(&[
        "up",
        "-d",
        "--no-build",
        "kharon",
        "fake-edge",
        "fake-edge-owner",
    ]);
    wait_for_log(
        KHAROND,
        &format!(
            "kharond: public ingress listening on {PUBLIC_INGRESS} \
             (plain HTTP, loopback; POST /mcp only)"
        ),
        Duration::from_secs(60),
    );
    must(wait_owner_edge(&edge_ca).await);

    // 7. Enrol a passkey with the CLI's one-time code and sign in, both
    // through the owner edge.
    let code = docker(&["exec", KHAROND, "kharon", "passkey-enroll"])
        .trim()
        .to_owned();
    assert!(!code.is_empty(), "kharon passkey-enroll printed no code");
    let (auth, cookie) = must(enroll_and_sign_in(&edge_ca, &code).await);

    // 8. Discovery.
    let discovery = must(discover(&edge_ca).await);

    Run {
        edge_ca,
        secrets: vec![code, cookie.clone()],
        cookie,
        auth: Mutex::new(auth),
        dashboard,
        client_id,
        redirect_uri,
        discovery,
    }
}

// ------------------------------------------------------------ the tests

#[tokio::test]
async fn https_raw_round_trips_through_a_tls_listener() {
    let (ca_pem, leaf_pem, leaf_key_pem) = compose_support::edge_pki(&["edge.test"]);
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(leaf_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(leaf_key_pem.as_bytes()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 418 I'm a teapot\r\nX-Probe: yes\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });

    let r = compose_support::https_raw(
        addr,
        "edge.test",
        &ca_pem,
        b"GET /x HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(r.status, 418);
    assert_eq!(r.header("x-probe"), Some("yes"));
    assert_eq!(r.body, "ok");
    // A CA that did not sign the leaf is refused.
    let (other_ca, _, _) = compose_support::edge_pki(&["edge.test"]);
    assert!(
        compose_support::https_raw(
            addr,
            "edge.test",
            &other_ca,
            b"GET / HTTP/1.1\r\nHost: edge.test\r\n\r\n"
        )
        .await
        .is_err()
    );
}

#[test]
fn request_bytes_matches_what_http_sends() {
    let req = owner_ui_support::Http::post("/owner/logout", Some("application/json"), "{}")
        .host("kharon-owner.e2e.test")
        .cookie("__Host-kharon_owner=abc")
        .header("CF-Connecting-IP", "198.51.100.10");
    let text = String::from_utf8(owner_ui_support::request_bytes(
        "https://kharon-owner.e2e.test",
        &req,
    ))
    .unwrap();
    assert!(text.starts_with("POST /owner/logout HTTP/1.1\r\n"));
    for line in [
        "Host: kharon-owner.e2e.test\r\n",
        "Origin: https://kharon-owner.e2e.test\r\n",
        "Cookie: __Host-kharon_owner=abc\r\n",
        "CF-Connecting-IP: 198.51.100.10\r\n",
        "Content-Length: 2\r\n",
    ] {
        assert!(
            text.to_ascii_lowercase()
                .contains(&line.to_ascii_lowercase()),
            "missing {line:?}"
        );
    }
    assert!(text.ends_with("\r\n\r\n{}"));
}

#[test]
fn oauth_harness_config_is_public_mode_with_one_client() {
    let client = "https://dashboard.e2e.test:4443/client.json";
    let cfg = kharond::config::Config::from_toml_str(&kharond_toml(
        "a@b.test",
        "0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6",
        "11111111-2222-3333-4444-555555555555",
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash",
        client,
    ))
    .unwrap();
    assert!(cfg.api.is_none(), "no [api]");
    assert!(cfg.connector.is_none(), "no [connector]");
    assert_eq!(cfg.oauth.as_ref().unwrap().clients, [client]);
    let ingress = cfg.public_ingress.as_ref().unwrap();
    assert_eq!(ingress.listen.to_string(), PUBLIC_INGRESS);
    assert_eq!(ingress.public_host.as_deref(), Some(AGENT_HOST));
    let ui = cfg.owner_ui.as_ref().unwrap();
    assert_eq!(ui.listen.to_string(), OWNER_UI);
    assert!(ui.public, "the owner UI is in public mode");
    assert_eq!(ui.origin, OWNER_ORIGIN);
    assert_eq!(cfg.agents.len(), 1, "only the dummy agent");
}

#[tokio::test]
async fn dashboard_serves_its_metadata_document_and_counts_fetches() {
    let (ca, leaf, key) = compose_support::edge_pki(&["dashboard.e2e.test"]);
    let dash = serve_dashboard("127.0.0.1", &leaf, &key).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{}", dash.port).parse().unwrap();
    let get = |path: &str| {
        format!("GET {path} HTTP/1.1\r\nHost: dashboard.e2e.test\r\nConnection: close\r\n\r\n")
    };

    let r = compose_support::https_raw(
        addr,
        "dashboard.e2e.test",
        &ca,
        get("/client.json").as_bytes(),
    )
    .await
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("cache-control"), Some("max-age=3600"));
    let doc: ClientDoc = serde_json::from_str(&r.body).unwrap();
    assert_eq!(
        doc.client_id,
        format!("https://dashboard.e2e.test:{}/client.json", dash.port)
    );
    assert_eq!(doc.client_name, "E2E Dashboard");
    assert_eq!(
        doc.redirect_uris,
        [format!("https://dashboard.e2e.test:{}/callback", dash.port)]
    );
    assert_eq!(doc.token_endpoint_auth_method, "none");
    assert_eq!(dash.fetches.load(Ordering::SeqCst), 1);

    let r = compose_support::https_raw(addr, "dashboard.e2e.test", &ca, get("/other").as_bytes())
        .await
        .unwrap();
    assert_eq!(r.status, 404);
    assert_eq!(dash.fetches.load(Ordering::SeqCst), 1);
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_001_compose_discovery_chain_leads_from_mcp_to_the_owner_hostname() {
    let r = run();
    // The run walked it once in setup; walk it again from the test, so a
    // failure here names the step, and check what the run kept.
    let d = block_on(discover(&r.edge_ca)).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d, r.discovery);
    assert_eq!(d.resource, RESOURCE);
    assert_eq!(d.issuer, OWNER_ORIGIN);
    assert_eq!(
        d.authorization_endpoint,
        format!("{OWNER_ORIGIN}/oauth/authorize")
    );
    assert_eq!(d.token_endpoint, format!("{OWNER_ORIGIN}/oauth/token"));
    assert_eq!(
        d.revocation_endpoint,
        format!("{OWNER_ORIGIN}/oauth/revoke")
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_apr_009_compose_owner_signs_in_with_a_passkey_through_the_edge() {
    let r = run();
    let secrets: Vec<&str> = r.secrets.iter().map(String::as_str).collect();
    let with = block_on(owner(
        &r.edge_ca,
        Http::get("/owner/session").cookie(&r.cookie),
    ));
    expect("GET /owner/session with the cookie", with, 200, &secrets)
        .unwrap_or_else(|e| panic!("{e}"));
    let without = block_on(owner(&r.edge_ca, Http::get("/owner/session")));
    expect(
        "GET /owner/session without a cookie",
        without,
        401,
        &secrets,
    )
    .unwrap_or_else(|e| panic!("{e}"));
}
