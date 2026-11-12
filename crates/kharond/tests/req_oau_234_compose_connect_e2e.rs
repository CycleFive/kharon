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
//! walks discovery the way an MCP client would, then plays a dashboard
//! (`scenario()`): Connect, tokens, `/mcp`, refresh, the single retry,
//! the reuse kill, Disconnect, and the evidence the tests assert on.
//! Ignored by default. Env:
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
use compose_support::{
    data_volume_of, edge_pki, env, fixture_scope, https_raw, manifest, redact, write_public,
};
use docker_support::{docker, docker_raw, wait_for_log};
use owner_ui_support::{Http, VirtAuth, b64url, b64url_dec, request_bytes};
use rand::RngCore;
use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
/// `CF-Connecting-IP` of the dashboard's backend (`/oauth/token`, `/mcp`).
const DASHBOARD_SRC_IP: &str = "198.51.100.20";
const SESSION_COOKIE: &str = "__Host-kharon_owner";
/// The image the one-off containers run (it has `cat` and `socat`).
const AGENT_HOST_IMAGE: &str = "kharon-e2e-agent-host:local";

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

// ------------------------------------------------------------ the scenario

/// The token endpoint's success answer.
#[derive(Clone, Deserialize)]
struct TokenAnswer {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
    scope: String,
}

/// The token endpoint's failure answer.
#[derive(Deserialize)]
struct TokenError {
    error: String,
}

/// `{"pending"}`: the body of `consent/view` and `consent/options`.
#[derive(Serialize)]
struct PendingRequest<'a> {
    pending: &'a str,
}

#[derive(Deserialize)]
struct ConsentScope {
    id: String,
}

/// `consent/view`'s answer.
#[derive(Deserialize)]
struct ConsentView {
    client_name: String,
    client_host: String,
    redirect_host: String,
    scopes: Vec<ConsentScope>,
}

#[derive(Deserialize)]
struct ConsentChallenge {
    challenge: String,
}

/// `consent/options`' answer.
#[derive(Deserialize)]
struct ConsentOptions {
    ceremony_id: String,
    nonce: String,
    #[serde(rename = "publicKey")]
    public_key: ConsentChallenge,
}

/// `consent/approve`'s body (`ApproveBody` in `owner_ui/oauth.rs`, which
/// refuses unknown fields). The credential is what `VirtAuth` builds.
#[derive(Serialize)]
struct ApproveRequest<'a> {
    pending: &'a str,
    ceremony_id: &'a str,
    nonce: &'a str,
    credential: &'a serde_json::Value,
    scopes: &'a [String],
}

#[derive(Deserialize)]
struct ApproveReply {
    redirect: String,
}

/// `GET /owner/connections`.
#[derive(Deserialize)]
struct ConnectionsReply {
    connections: Vec<ConnectionRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectionRow {
    agent_id: String,
    client_name: String,
}

#[derive(Serialize)]
struct AgentRequest<'a> {
    agent_id: &'a str,
}

/// `kharon_fill`'s arguments, well-formed (the ws E2E's shape).
#[derive(Serialize)]
struct FillArgs<'a> {
    item_id: &'a str,
    target: FillTarget<'a>,
    fields: [FieldSpec; 2],
    submit: bool,
}

#[derive(Serialize)]
struct FillTarget<'a> {
    cdp_target_id: &'a str,
    expected_origin: &'a str,
}

#[derive(Serialize)]
struct FieldSpec {
    kind: &'static str,
}

/// A JSON-RPC reply to `tools/call`.
#[derive(Deserialize)]
struct McpReply {
    result: Option<McpResult>,
}

#[derive(Deserialize)]
struct McpResult {
    #[serde(rename = "isError", default)]
    is_error: bool,
    #[serde(default)]
    content: Vec<McpText>,
}

#[derive(Deserialize)]
struct McpText {
    text: String,
}

/// A tool error's text.
#[derive(Deserialize)]
struct ToolError {
    error: String,
    detail: Option<String>,
}

/// What a `/mcp` call answered with.
#[derive(Debug, Clone)]
struct ToolOutcome {
    status: u16,
    www_authenticate: bool,
    is_error: bool,
    error: Option<String>,
    detail: Option<String>,
}

/// One audit line, as far as the test reads it.
#[derive(Debug, Clone, Deserialize)]
struct AuditLine {
    event: String,
    agent_id: Option<String>,
    result: Option<String>,
    detail_code: Option<String>,
    channel: Option<String>,
    origin: Option<String>,
}

/// What one Connect (authorize, consent, redemption) recorded.
#[derive(Clone)]
struct Connect {
    client_name: String,
    client_host: String,
    redirect_host: String,
    /// The scope ids the consent view listed (all granted).
    scope_ids: Vec<String>,
    state_sent: String,
    state_returned: Option<String>,
    iss: Option<String>,
    /// The approve answer's redirect without its query.
    redirect_base: String,
    approve_had_location: bool,
    code: String,
    token: TokenAnswer,
    cache_control: Option<String>,
    /// The dashboard's fetch count right after authorize.
    fetches_after_authorize: usize,
}

/// Step 4.
struct Rotation {
    pair: TokenAnswer,
    status_with_new_access: ToolOutcome,
}

/// Step 5.
struct Retry {
    pair: TokenAnswer,
    old_access_status: u16,
    new_access: ToolOutcome,
    /// From just before the rotation was sent to the retry's answer: an
    /// upper bound on the time the retry spent in the 30 s window.
    since_rotation: Duration,
}

/// Step 6.
#[derive(Debug)]
struct Kill {
    third_presentation_error: String,
    access_status: u16,
    successor_refresh_error: String,
}

/// Step 8.
#[derive(Debug)]
struct Disconnection {
    rows_before: Vec<ConnectionRow>,
    disconnect_status: u16,
    access_status: u16,
    refresh_error: String,
    rows_after: usize,
}

/// Step 9.
struct Evidence {
    log: String,
    state_json: String,
    audit_raw: String,
    audit: Vec<AuditLine>,
    verify_out: String,
}

/// Everything the scenario recorded, for the tests to assert on.
struct Scenario {
    a: Connect,
    a_agent_id: String,
    b: Connect,
    b_agent_id: String,
    status_call: ToolOutcome,
    no_browser_context: ToolOutcome,
    no_browser_fill: ToolOutcome,
    rotation: Rotation,
    retry: Retry,
    kill: Kill,
    disconnection: Disconnection,
    /// The 4xx answers `/oauth/token` gave (three on purpose; the
    /// endpoint throttles one source at 10 in 600 s).
    token_4xx: usize,
    evidence: Evidence,
}

/// `text` with every `kh_at_…` / `kh_rt_…` token replaced: a body that
/// was not supposed to hold tokens may, if the product is wrong.
fn scrub_tokens(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = ["kh_at_", "kh_rt_"]
        .iter()
        .filter_map(|p| rest.find(p))
        .min()
    {
        out.push_str(&rest[..i]);
        out.push_str("<token>");
        let after = &rest[i + "kh_at_".len()..];
        let n = after
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(after.len());
        rest = &after[n..];
    }
    out.push_str(rest);
    out
}

/// [`expect`] with tokens scrubbed from the body it would print; on
/// success the original response comes back.
fn expect_scrubbed(
    step: &str,
    r: Result<RawResponse, String>,
    want: u16,
    secrets: &[&str],
) -> Result<RawResponse, String> {
    let shown = match &r {
        Ok(x) => Ok(RawResponse {
            status: x.status,
            headers: Vec::new(),
            body: scrub_tokens(&x.body),
        }),
        Err(e) => Err(e.clone()),
    };
    expect(step, shown, want, secrets)?;
    r
}

/// A 429 is the per-source throttle answering: a bug in the test, so it
/// fails the run naming the source.
fn throttled(
    step: &str,
    path: &str,
    r: Result<RawResponse, String>,
) -> Result<RawResponse, String> {
    match r {
        Ok(x) if x.status == 429 => Err(format!(
            "{step}: 429 from {DASHBOARD_SRC_IP} on {path}: this source is throttled \
             (10 failures in 600 s); a bug in the test, not a product failure"
        )),
        other => other,
    }
}

/// `bytes` (an HTTP request) with the header `line` added.
fn with_header(bytes: Vec<u8>, line: &str) -> Vec<u8> {
    let text = String::from_utf8(bytes).expect("request is UTF-8");
    let (head, body) = text.split_once("\r\n\r\n").expect("request has a head");
    format!("{head}\r\n{line}\r\n\r\n{body}").into_bytes()
}

/// The path of `url`.
fn path_of(url: &str) -> Result<String, String> {
    Url::parse(url)
        .map(|u| u.path().to_owned())
        .map_err(|e| format!("{url:?} is not a URL: {e}"))
}

fn random_b64url() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    b64url(&bytes)
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

/// kharond's log, stdout and stderr.
fn kharond_log(tail: Option<usize>) -> String {
    let mut args = vec!["logs".to_owned()];
    if let Some(n) = tail {
        args.push("--tail".to_owned());
        args.push(n.to_string());
    }
    args.push(KHAROND.to_owned());
    let out = docker_raw(&args.iter().map(String::as_str).collect::<Vec<_>>(), None);
    let mut log = String::from_utf8_lossy(&out.stdout).into_owned();
    log.push_str(&String::from_utf8_lossy(&out.stderr));
    log
}

/// `path` in kharond's data volume, read by a one-off container running
/// as the daemon's uid (the files are 0600).
fn read_data_file(volume: &str, path: &str) -> Result<String, String> {
    let mount = format!("{volume}:/data:ro");
    let out = docker_raw(
        &[
            "run",
            "--rm",
            "--user",
            "10001:10001",
            "--entrypoint",
            "cat",
            "-v",
            &mount,
            AGENT_HOST_IMAGE,
            path,
        ],
        None,
    );
    if !out.status.success() {
        return Err(format!(
            "reading {path} from the data volume: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The dashboard's backend: plays the real HTTP OAuth surface.
struct Driver<'a> {
    ca: &'a str,
    cookie: &'a str,
    auth: &'a mut VirtAuth,
    dashboard: &'a Dashboard,
    client_id: &'a str,
    redirect_uri: &'a str,
    discovery: &'a Discovered,
    /// Every secret seen so far (the enrolment code, the cookie, codes,
    /// verifiers, tokens): what `redact` hides.
    secrets: Vec<String>,
    token_4xx: usize,
}

impl Driver<'_> {
    fn sec(&self) -> Vec<&str> {
        self.secrets.iter().map(String::as_str).collect()
    }

    /// `POST path` with a JSON `body`, the session cookie and `Origin`.
    async fn owner_post<B: Serialize>(
        &self,
        step: &str,
        path: &str,
        body: &B,
    ) -> Result<RawResponse, String> {
        let body = serde_json::to_string(body).unwrap();
        let r = owner(
            self.ca,
            Http::post(path, Some("application/json"), &body).cookie(self.cookie),
        )
        .await;
        expect_scrubbed(step, r, 200, &self.sec())
    }

    /// `GET /owner/connections`.
    async fn connections(&self, step: &str) -> Result<Vec<ConnectionRow>, String> {
        let r = owner(self.ca, Http::get("/owner/connections").cookie(self.cookie)).await;
        let r = expect_scrubbed(step, r, 200, &self.sec())?;
        let reply: ConnectionsReply = parse(step, &r, &self.sec())?;
        Ok(reply.connections)
    }

    /// The authorize request; returns the pending token. A refusal here
    /// has three look-alike causes, so the error carries what tells them
    /// apart: the dashboard's fetch count and kharond's log.
    async fn authorize(&self, challenge: &str, state: &str) -> Result<String, String> {
        let step = "GET /oauth/authorize";
        let query = form(&[
            ("response_type", "code"),
            ("client_id", self.client_id),
            ("redirect_uri", self.redirect_uri),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
            ("state", state),
            ("resource", RESOURCE),
        ]);
        let path = format!(
            "{}?{query}",
            path_of(&self.discovery.authorization_endpoint)?
        );
        let r = owner(self.ca, Http::get(&path)).await;
        let r = expect(step, r, 302, &self.sec()).map_err(|e| {
            format!(
                "{e}\nthe dashboard's document was fetched {} time(s)\n\
                 kharond's log, last 50 lines:\n{}",
                self.dashboard.fetches.load(Ordering::SeqCst),
                redact(&kharond_log(Some(50)), &self.sec())
            )
        })?;
        let location = r.header("location").unwrap_or("");
        location
            .strip_prefix("/oauth/consent/")
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                format!("{step}: Location is {location:?}, not /oauth/consent/<pending>")
            })
    }

    /// `POST` to the token endpoint as the dashboard's backend: no
    /// cookie, no `Origin`, no `Authorization` (a public client sends
    /// none; kharond refuses one there).
    async fn token_post(&self, step: &str, pairs: &[(&str, &str)]) -> Result<RawResponse, String> {
        let body = form(pairs);
        let path = path_of(&self.discovery.token_endpoint)?;
        let req = Http::post(&path, Some("application/x-www-form-urlencoded"), &body)
            .host(OWNER_HOST)
            .without_origin()
            .header("CF-Connecting-IP", DASHBOARD_SRC_IP);
        let bytes = request_bytes(OWNER_ORIGIN, &req);
        let r = https_raw(socket(OWNER_EDGE_ADDR), OWNER_HOST, self.ca, &bytes).await;
        throttled(step, "/oauth/token", r)
    }

    /// The token answer in `r`, its tokens added to the secrets.
    fn take_tokens(&mut self, step: &str, r: &RawResponse) -> Result<TokenAnswer, String> {
        let t: TokenAnswer = serde_json::from_str(&r.body).map_err(|e| {
            format!(
                "{step}: token answer is not the expected JSON ({})",
                scrub_tokens(&redact(&e.to_string(), &self.sec()))
            )
        })?;
        self.secrets.push(t.access_token.clone());
        self.secrets.push(t.refresh_token.clone());
        Ok(t)
    }

    /// A refresh that must succeed.
    async fn refresh_ok(&mut self, step: &str, refresh_token: &str) -> Result<TokenAnswer, String> {
        let r = self
            .token_post(
                step,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", self.client_id),
                ],
            )
            .await;
        let r = expect_scrubbed(step, r, 200, &self.sec())?;
        self.take_tokens(step, &r)
    }

    /// A refresh that must be refused: `400 invalid_grant`. One of the
    /// three intended 4xx answers.
    async fn refresh_refused(&mut self, step: &str, refresh_token: &str) -> Result<String, String> {
        let r = self
            .token_post(
                step,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", self.client_id),
                ],
            )
            .await;
        self.token_4xx += 1;
        let r = expect_scrubbed(step, r, 400, &self.sec())?;
        let e: TokenError = parse(step, &r, &self.sec())?;
        ensure(e.error == "invalid_grant", step, || {
            format!("error is {:?}, want invalid_grant", e.error)
        })?;
        Ok(e.error)
    }

    /// `tools/call` of `tool` as the dashboard's backend.
    async fn mcp(
        &self,
        step: &str,
        token: &str,
        tool: &str,
        arguments: &str,
    ) -> Result<RawResponse, String> {
        let bytes = with_header(
            mcp_call_bytes(AGENT_HOST, Some(token), tool, arguments),
            &format!("CF-Connecting-IP: {DASHBOARD_SRC_IP}"),
        );
        throttled(step, "/mcp", agent_edge(self.ca, &bytes).await)
    }

    /// A `/mcp` call that must answer 200; a tool error is parsed.
    async fn mcp_ok(
        &self,
        step: &str,
        token: &str,
        tool: &str,
        arguments: &str,
    ) -> Result<ToolOutcome, String> {
        let r = self.mcp(step, token, tool, arguments).await;
        let r = expect_scrubbed(step, r, 200, &self.sec())?;
        let reply: McpReply = parse(step, &r, &self.sec())?;
        let result = reply
            .result
            .ok_or_else(|| format!("{step}: the reply has no result"))?;
        let (error, detail) = if result.is_error {
            let text = result
                .content
                .first()
                .map(|c| c.text.as_str())
                .unwrap_or("");
            let e: ToolError = serde_json::from_str(text).map_err(|e| {
                format!(
                    "{step}: tool error text is not {{error, detail}} ({e}): {}",
                    scrub_tokens(text)
                )
            })?;
            (Some(e.error), e.detail)
        } else {
            (None, None)
        };
        Ok(ToolOutcome {
            status: r.status,
            www_authenticate: r.header("www-authenticate").is_some(),
            is_error: result.is_error,
            error,
            detail,
        })
    }

    /// `kharon_status` with a token that must be accepted.
    async fn status_accepted(&self, step: &str, token: &str) -> Result<ToolOutcome, String> {
        let o = self.mcp_ok(step, token, "kharon_status", "{}").await?;
        ensure(!o.is_error, step, || {
            format!("kharon_status answered a tool error: {:?}", o.error)
        })?;
        Ok(o)
    }

    /// `kharon_status` with a token that must be refused: 401.
    async fn status_refused(&self, step: &str, token: &str) -> Result<u16, String> {
        let r = self.mcp(step, token, "kharon_status", "{}").await;
        Ok(expect_scrubbed(step, r, 401, &self.sec())?.status)
    }

    /// One Connect: authorize, consent view, options, approve, redeem.
    async fn connect(&mut self, label: &str) -> Result<Connect, String> {
        let verifier = random_b64url();
        self.secrets.push(verifier.clone());
        let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
        let mut state_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut state_bytes);
        let state_sent = hex::encode(state_bytes);

        let pending = self.authorize(&challenge, &state_sent).await?;
        let fetches_after_authorize = self.dashboard.fetches.load(Ordering::SeqCst);

        let step = format!("{label}: POST /oauth/consent/view");
        let r = self
            .owner_post(
                &step,
                "/oauth/consent/view",
                &PendingRequest { pending: &pending },
            )
            .await?;
        let view: ConsentView = parse(&step, &r, &self.sec())?;

        let step = format!("{label}: POST /oauth/consent/options");
        let r = self
            .owner_post(
                &step,
                "/oauth/consent/options",
                &PendingRequest { pending: &pending },
            )
            .await?;
        let options: ConsentOptions = parse(&step, &r, &self.sec())?;

        let step = format!("{label}: POST /oauth/consent/approve");
        let credential =
            self.auth
                .assertion(&options.public_key.challenge, OWNER_ORIGIN, OWNER_HOST);
        let scope_ids: Vec<String> = view.scopes.iter().map(|s| s.id.clone()).collect();
        let r = self
            .owner_post(
                &step,
                "/oauth/consent/approve",
                &ApproveRequest {
                    pending: &pending,
                    ceremony_id: &options.ceremony_id,
                    nonce: &options.nonce,
                    credential: &credential,
                    scopes: &scope_ids,
                },
            )
            .await?;
        let approve_had_location = r.header("location").is_some();
        let reply: ApproveReply = serde_json::from_str(&r.body).map_err(|e| {
            format!(
                "{step}: answer is not {{redirect}} ({})",
                scrub_tokens(&redact(&e.to_string(), &self.sec()))
            )
        })?;
        let redirect = Url::parse(&reply.redirect)
            .map_err(|e| format!("{step}: redirect is not a URL ({e})"))?;
        let query = |name: &str| {
            redirect
                .query_pairs()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
        };
        let code = query("code").ok_or_else(|| format!("{step}: the redirect has no code"))?;
        self.secrets.push(code.clone());
        let mut base = redirect.clone();
        base.set_query(None);

        let step = format!("{label}: POST /oauth/token (code)");
        let r = self
            .token_post(
                &step,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("client_id", self.client_id),
                    ("redirect_uri", self.redirect_uri),
                    ("code_verifier", &verifier),
                    ("resource", RESOURCE),
                ],
            )
            .await;
        let r = expect_scrubbed(&step, r, 200, &self.sec())?;
        let cache_control = r.header("cache-control").map(str::to_owned);
        let token = self.take_tokens(&step, &r)?;

        Ok(Connect {
            client_name: view.client_name,
            client_host: view.client_host,
            redirect_host: view.redirect_host,
            scope_ids,
            state_sent,
            state_returned: query("state"),
            iss: query("iss"),
            redirect_base: base.to_string(),
            approve_had_location,
            code,
            token,
            cache_control,
            fetches_after_authorize,
        })
    }
}

/// Plays a dashboard against the stack: Connect A proves rotation, the
/// retry and the kill; Connect B proves Disconnect; then the evidence
/// is collected. The first unexpected answer is an `Err` naming the step.
async fn scenario(d: &mut Driver<'_>) -> Result<Scenario, String> {
    // 1. Connect A.
    let a = d.connect("Connect A").await?;
    let rows = d.connections("Connect A: GET /owner/connections").await?;
    ensure(rows.len() == 1, "Connect A: GET /owner/connections", || {
        format!("expected one row, got {}", rows.len())
    })?;
    let a_agent_id = rows[0].agent_id.clone();
    let at0 = a.token.access_token.clone();
    let rt0 = a.token.refresh_token.clone();

    // 2. An /mcp call.
    let status_call = d.status_accepted("kharon_status with at0", &at0).await?;

    // 3. no_browser: a Connect has no browser attached.
    let no_browser_context = d
        .mcp_ok("kharon_context with at0", &at0, "kharon_context", "{}")
        .await?;
    let fill = serde_json::to_string(&FillArgs {
        item_id: "00000000-0000-4000-8000-000000000000",
        target: FillTarget {
            cdp_target_id: "E2E-TARGET",
            expected_origin: "https://dashboard.e2e.test",
        },
        fields: [
            FieldSpec { kind: "username" },
            FieldSpec { kind: "password" },
        ],
        submit: false,
    })
    .unwrap();
    let no_browser_fill = d
        .mcp_ok("kharon_fill with at0", &at0, "kharon_fill", &fill)
        .await?;

    // 4. Rotation.
    let rotated_at = Instant::now();
    let pair1 = d.refresh_ok("refresh rt0 (rotation)", &rt0).await?;
    ensure(
        pair1.access_token != at0 && pair1.refresh_token != rt0,
        "refresh rt0 (rotation)",
        || "the rotation returned a token it had issued before".to_owned(),
    )?;
    let status_with_new_access = d
        .status_accepted("kharon_status with at1", &pair1.access_token)
        .await?;
    let rotation = Rotation {
        pair: pair1.clone(),
        status_with_new_access,
    };

    // 5. The single retry: the retired rt0 once more, inside the grace.
    ensure(
        rotated_at.elapsed() <= Duration::from_secs(20),
        "refresh rt0 (the single retry)",
        || {
            format!(
                "runner too slow, not a product failure: {} s since the rotation, the retry \
                 must go out within 20 s (the grace window is 30 s)",
                rotated_at.elapsed().as_secs()
            )
        },
    )?;
    let pair2 = d.refresh_ok("refresh rt0 (the single retry)", &rt0).await?;
    let since_rotation = rotated_at.elapsed();
    let old_access_status = d
        .status_refused(
            "kharon_status with at1 after the retry",
            &pair1.access_token,
        )
        .await?;
    let new_access = d
        .status_accepted("kharon_status with at2", &pair2.access_token)
        .await?;
    let retry = Retry {
        pair: pair2.clone(),
        old_access_status,
        new_access,
        since_rotation,
    };

    // 6. Reuse kills the Connect.
    let third_presentation_error = d
        .refresh_refused("refresh rt0 (third presentation)", &rt0)
        .await?;
    let access_status = d
        .status_refused("kharon_status with at2 after reuse", &pair2.access_token)
        .await?;
    let successor_refresh_error = d
        .refresh_refused("refresh rt2 after reuse", &pair2.refresh_token)
        .await?;
    let kill = Kill {
        third_presentation_error,
        access_status,
        successor_refresh_error,
    };

    // 7. Connect B.
    let b = d.connect("Connect B").await?;

    // 8. Disconnect.
    let step = "Connect B: GET /owner/connections";
    let rows_before = d.connections(step).await?;
    ensure(rows_before.len() == 1, step, || {
        format!(
            "expected one live Connect (A is ended), got {}",
            rows_before.len()
        )
    })?;
    ensure(rows_before[0].client_name == "E2E Dashboard", step, || {
        format!("client_name is {:?}", rows_before[0].client_name)
    })?;
    let b_agent_id = rows_before[0].agent_id.clone();
    ensure(b_agent_id != a_agent_id, step, || {
        "the listed Connect is A's, not B's".to_owned()
    })?;
    let step = "POST /owner/connections/disconnect";
    let r = d
        .owner_post(
            step,
            "/owner/connections/disconnect",
            &AgentRequest {
                agent_id: &b_agent_id,
            },
        )
        .await?;
    let disconnect_status = r.status;
    let access_status = d
        .status_refused(
            "kharon_status with atB after Disconnect",
            &b.token.access_token,
        )
        .await?;
    let refresh_error = d
        .refresh_refused("refresh rtB after Disconnect", &b.token.refresh_token)
        .await?;
    let rows_after = d
        .connections("GET /owner/connections after Disconnect")
        .await?
        .len();
    let disconnection = Disconnection {
        rows_before,
        disconnect_status,
        access_status,
        refresh_error,
        rows_after,
    };

    ensure(d.token_4xx == 3, "the scenario", || {
        format!(
            "{} intended 4xx answers on /oauth/token, expected 3",
            d.token_4xx
        )
    })?;

    // 9. Evidence.
    let volume = data_volume_of(KHAROND);
    let state_json = read_data_file(&volume, "/data/oauth/state.json")?;
    let audit_raw = read_data_file(&volume, "/data/audit/audit.jsonl")?;
    let audit = audit_raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<AuditLine>(l)
                .map_err(|e| format!("audit.jsonl: a line is not an audit entry ({e})"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let verify = docker_raw(
        &[
            "exec",
            KHAROND,
            "kharon",
            "audit",
            "verify",
            "--data",
            "/data/audit",
        ],
        None,
    );
    let verify_out = String::from_utf8_lossy(&verify.stdout).into_owned();
    ensure(verify.status.success(), "kharon audit verify", || {
        format!("{verify_out}{}", String::from_utf8_lossy(&verify.stderr))
    })?;
    let log = kharond_log(None);

    Ok(Scenario {
        a,
        a_agent_id,
        b,
        b_agent_id,
        status_call,
        no_browser_context,
        no_browser_fill,
        rotation,
        retry,
        kill,
        disconnection,
        token_4xx: d.token_4xx,
        evidence: Evidence {
            log,
            state_json,
            audit_raw,
            audit,
            verify_out,
        },
    })
}

// ------------------------------------------------------------ the run

/// What the shared run set up, for the tests to use.
struct Run {
    /// The edges' CA: the only root the test trusts.
    edge_ca: String,
    /// The `__Host-kharon_owner=…` pair of the signed-in owner session.
    cookie: String,
    /// The owner's passkey (its signature counter advances per sign-in).
    /// Kept for the tests that sign in again; none does yet.
    #[allow(dead_code)]
    auth: Mutex<VirtAuth>,
    dashboard: Dashboard,
    /// The dashboard's `client_id` (its CIMD URL) and `redirect_uri`.
    client_id: String,
    redirect_uri: String,
    discovery: Discovered,
    /// The enrolment code and the cookie, for `redact`.
    secrets: Vec<String>,
    /// What the dashboard scenario recorded.
    scenario: Scenario,
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

    // 9. The dashboard scenario. Its driver keeps its own list of
    // secrets (the codes and tokens it obtains join it); the run keeps
    // the enrolment code and the cookie.
    let cookie_value = cookie
        .split_once('=')
        .map_or(cookie.as_str(), |(_, v)| v)
        .to_owned();
    let mut auth = auth;
    let mut driver = Driver {
        ca: &edge_ca,
        cookie: &cookie,
        auth: &mut auth,
        dashboard: &dashboard,
        client_id: &client_id,
        redirect_uri: &redirect_uri,
        discovery: &discovery,
        secrets: vec![code.clone(), cookie.clone(), cookie_value],
        token_4xx: 0,
    };
    let scenario = must(scenario(&mut driver).await);
    drop(driver);

    Run {
        edge_ca,
        secrets: vec![code, cookie.clone()],
        cookie,
        auth: Mutex::new(auth),
        dashboard,
        client_id,
        redirect_uri,
        discovery,
        scenario,
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

// ------------------------------------------------------------ the scenario's tests
//
// Assertion messages name the fact, never a token, code or cookie: a
// token compared with `assert_eq!` would be printed on failure.

/// `kh_at_` / `kh_rt_` followed by 64 hex digits.
fn is_token(t: &str, prefix: &str) -> bool {
    t.strip_prefix(prefix)
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn assert_pair(what: &str, t: &TokenAnswer) {
    assert!(
        is_token(&t.access_token, "kh_at_"),
        "{what}: access_token is not kh_at_ + 64 hex"
    );
    assert!(
        is_token(&t.refresh_token, "kh_rt_"),
        "{what}: refresh_token is not kh_rt_ + 64 hex"
    );
}

/// The audit entries of `event`, in log order.
fn audit_events<'a>(s: &'a Scenario, event: &str) -> Vec<(usize, &'a AuditLine)> {
    s.evidence
        .audit
        .iter()
        .enumerate()
        .filter(|(_, l)| l.event == event)
        .collect()
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_002_compose_kharond_fetches_the_dashboard_document_once() {
    let r = run();
    let s = &r.scenario;
    assert_eq!(
        s.a.fetches_after_authorize, 1,
        "the dashboard's document was fetched once for Connect A's authorize"
    );
    assert_eq!(
        s.b.fetches_after_authorize, 1,
        "Connect B's authorize was answered from the cache (the document is cached for an hour)"
    );
    assert_eq!(
        r.dashboard.fetches.load(Ordering::SeqCst),
        1,
        "the document was fetched exactly once in the whole run"
    );
    for (name, c) in [("A", &s.a), ("B", &s.b)] {
        assert_eq!(
            c.client_name, "E2E Dashboard",
            "Connect {name}'s client_name"
        );
        assert!(
            c.client_host.contains(DASHBOARD_HOST),
            "Connect {name}'s client_host {:?} lacks {DASHBOARD_HOST}",
            c.client_host
        );
    }
    assert!(
        r.client_id.contains(DASHBOARD_HOST),
        "the test's client_id names the dashboard host"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_003_compose_consent_returns_the_code_in_json_with_state_and_iss() {
    let r = run();
    for (name, c) in [("A", &r.scenario.a), ("B", &r.scenario.b)] {
        assert!(
            !c.approve_had_location,
            "Connect {name}: approve answered with a Location header (the code travels in the JSON)"
        );
        assert_eq!(
            c.redirect_base, r.redirect_uri,
            "Connect {name}: the redirect goes to the registered redirect_uri"
        );
        assert!(
            !c.code.is_empty(),
            "Connect {name}: the redirect has a code"
        );
        assert_eq!(
            c.state_returned.as_deref(),
            Some(c.state_sent.as_str()),
            "Connect {name}: state is returned unchanged"
        );
        assert_eq!(
            c.iss.as_deref(),
            Some(OWNER_ORIGIN),
            "Connect {name}: iss is the issuer"
        );
        assert!(
            c.redirect_host.contains(DASHBOARD_HOST),
            "Connect {name}: redirect_host {:?}",
            c.redirect_host
        );
    }
    assert!(
        r.scenario.a.state_sent != r.scenario.b.state_sent,
        "the two Connects used different state values"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_004_compose_code_redeems_to_a_token_pair() {
    let r = run();
    for (name, c) in [("A", &r.scenario.a), ("B", &r.scenario.b)] {
        let what = format!("Connect {name}");
        assert_pair(&what, &c.token);
        assert_eq!(c.token.token_type, "Bearer", "{what}: token_type");
        assert_eq!(c.token.expires_in, 3600, "{what}: expires_in");
        assert_eq!(
            c.cache_control.as_deref(),
            Some("no-store"),
            "{what}: Cache-Control on the token answer"
        );
        for scope in ["kharon:read", "kharon:fill", "kharon:request"] {
            assert!(
                c.token.scope.split(' ').any(|s| s == scope),
                "{what}: scope {:?} lacks {scope}",
                c.token.scope
            );
            assert!(
                c.scope_ids.iter().any(|s| s == scope),
                "{what}: the consent view did not list {scope}"
            );
        }
    }
    assert!(
        r.scenario.a.token.access_token != r.scenario.b.token.access_token
            && r.scenario.a.token.refresh_token != r.scenario.b.token.refresh_token,
        "the two Connects hold different tokens"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_004_compose_refresh_rotates_and_allows_one_retry() {
    let r = run();
    let s = &r.scenario;
    let a = &s.a.token;
    assert_pair("rotation", &s.rotation.pair);
    assert_pair("retry", &s.retry.pair);
    let (p1, p2) = (&s.rotation.pair, &s.retry.pair);
    assert!(
        p1.access_token != a.access_token && p1.refresh_token != a.refresh_token,
        "the rotation issued a new pair"
    );
    assert!(
        p2.access_token != a.access_token
            && p2.refresh_token != a.refresh_token
            && p2.access_token != p1.access_token
            && p2.refresh_token != p1.refresh_token,
        "the retry issued a third pair"
    );
    assert_eq!(s.status_call.status, 200, "kharon_status with at0");
    assert_eq!(
        s.rotation.status_with_new_access.status, 200,
        "kharon_status with the rotated access token"
    );
    assert_eq!(
        s.retry.old_access_status, 401,
        "the access token the retry superseded is dead"
    );
    assert_eq!(
        s.retry.new_access.status, 200,
        "the retry's access token works"
    );
    assert!(
        !s.retry.new_access.is_error,
        "kharon_status with the retry's access token is not a tool error"
    );
    assert!(
        s.retry.since_rotation < Duration::from_secs(20),
        "the retry was sent {:?} after the rotation, outside the 20 s the test allows \
         (the grace window is 30 s): the runner was too slow",
        s.retry.since_rotation
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_004_compose_reusing_a_retired_refresh_token_ends_the_connect() {
    let r = run();
    let s = &r.scenario;
    assert_eq!(
        s.kill.third_presentation_error, "invalid_grant",
        "the third presentation of the retired refresh token"
    );
    assert_eq!(
        s.kill.access_status, 401,
        "the retry's access token after the reuse"
    );
    assert_eq!(
        s.kill.successor_refresh_error, "invalid_grant",
        "the retry's refresh token after the reuse"
    );
    let reuse: Vec<_> = audit_events(s, "oauth_refresh_reuse")
        .into_iter()
        .filter(|(_, l)| l.agent_id.as_deref() == Some(s.a_agent_id.as_str()))
        .collect();
    assert_eq!(
        reuse.len(),
        1,
        "one oauth_refresh_reuse entry for Connect A ({})",
        s.a_agent_id
    );
    assert_eq!(reuse[0].1.result.as_deref(), Some("revoked"));
    assert!(
        audit_events(s, "oauth_refresh_reuse")
            .iter()
            .all(|(_, l)| l.agent_id.as_deref() == Some(s.a_agent_id.as_str())),
        "no other Connect saw a reuse"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_005_compose_disconnect_from_the_owner_page_ends_the_connect() {
    let r = run();
    let s = &r.scenario;
    let d = &s.disconnection;
    assert_eq!(
        d.rows_before.len(),
        1,
        "the page lists live Connects only (A is ended)"
    );
    assert_eq!(d.rows_before[0].client_name, "E2E Dashboard");
    assert_eq!(d.rows_before[0].agent_id, s.b_agent_id);
    assert!(s.b_agent_id != s.a_agent_id, "B is a new identity");
    assert_eq!(
        d.disconnect_status, 200,
        "POST /owner/connections/disconnect"
    );
    assert_eq!(d.access_status, 401, "atB after Disconnect");
    assert_eq!(d.refresh_error, "invalid_grant", "rtB after Disconnect");
    assert_eq!(d.rows_after, 0, "the page lists no Connect afterwards");
    let ended: Vec<_> = audit_events(s, "oauth_disconnect")
        .into_iter()
        .filter(|(_, l)| l.agent_id.as_deref() == Some(s.b_agent_id.as_str()))
        .collect();
    assert_eq!(
        ended.len(),
        1,
        "one oauth_disconnect entry for Connect B ({})",
        s.b_agent_id
    );
    assert_eq!(ended[0].1.detail_code.as_deref(), Some("owner"));
    assert_eq!(ended[0].1.channel.as_deref(), Some("web_ui"));
    assert_eq!(
        s.token_4xx, 3,
        "the scenario made its three intended 4xx on /oauth/token"
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_007_compose_a_connect_has_no_browser() {
    let r = run();
    let s = &r.scenario;
    assert_eq!(
        s.status_call.status, 200,
        "kharon_status answers (the broker is locked)"
    );
    assert!(!s.status_call.is_error, "kharon_status is not a tool error");
    for (tool, o) in [
        ("kharon_context", &s.no_browser_context),
        ("kharon_fill", &s.no_browser_fill),
    ] {
        assert_eq!(o.status, 200, "{tool}: HTTP status");
        assert!(o.is_error, "{tool}: isError");
        assert_eq!(o.error.as_deref(), Some("forbidden"), "{tool}: error");
        assert_eq!(
            o.detail.as_deref(),
            Some("this connection has no browser attached yet"),
            "{tool}: detail"
        );
        assert!(!o.www_authenticate, "{tool}: no step-up challenge");
    }
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_oau_compose_audit_chain_records_both_connects_and_verifies() {
    let r = run();
    let s = &r.scenario;
    let connects = audit_events(s, "oauth_connect");
    assert_eq!(connects.len(), 2, "two oauth_connect entries");
    for (_, l) in &connects {
        assert_eq!(l.result.as_deref(), Some("connected"));
        assert!(
            l.origin
                .as_deref()
                .is_some_and(|o| o.contains(DASHBOARD_HOST)),
            "origin {:?} names the dashboard host",
            l.origin
        );
    }
    assert_eq!(
        connects[0].1.agent_id.as_deref(),
        Some(s.a_agent_id.as_str())
    );
    assert_eq!(
        connects[1].1.agent_id.as_deref(),
        Some(s.b_agent_id.as_str())
    );
    let reuse = audit_events(s, "oauth_refresh_reuse");
    let ended = audit_events(s, "oauth_disconnect");
    assert!(
        reuse.iter().all(|(i, _)| *i > connects[0].0),
        "A's connect precedes A's ending"
    );
    assert!(
        ended
            .iter()
            .filter(|(_, l)| l.agent_id.as_deref() == Some(s.b_agent_id.as_str()))
            .all(|(i, _)| *i > connects[1].0),
        "B's connect precedes B's ending"
    );
    assert!(connects[0].0 < connects[1].0, "A connected before B");
    assert!(
        s.evidence.verify_out.contains("audit log OK"),
        "kharon audit verify said: {}",
        s.evidence.verify_out
    );
}

#[test]
#[ignore = "needs the compose E2E stack (image.yml)"]
fn req_goal_002_compose_oauth_secrets_stay_out_of_logs_and_state() {
    let r = run();
    let s = &r.scenario;
    let e = &s.evidence;

    // Positive controls: the files were read and are the right ones, and
    // the state file holds the tokens' hashes (so the scan below looks
    // where a leak would be).
    assert!(
        e.log.contains("public ingress listening"),
        "kharond's log was read (no startup line)"
    );
    assert!(
        e.audit_raw.contains(&s.a_agent_id) && e.audit_raw.contains(&s.b_agent_id),
        "audit.jsonl names both Connects"
    );
    assert!(
        e.state_json.contains(&s.a_agent_id)
            && e.state_json.contains(&s.b_agent_id)
            && e.state_json.contains("E2E Dashboard"),
        "state.json was read and holds both Connect identities"
    );
    assert!(
        e.audit_raw.contains("oauth_connect"),
        "audit.jsonl holds oauth_connect entries"
    );
    let tokens: Vec<(&str, &str)> = vec![
        ("at0", &s.a.token.access_token),
        ("rt0", &s.a.token.refresh_token),
        ("at1", &s.rotation.pair.access_token),
        ("rt1", &s.rotation.pair.refresh_token),
        ("at2", &s.retry.pair.access_token),
        ("rt2", &s.retry.pair.refresh_token),
        ("atB", &s.b.token.access_token),
        ("rtB", &s.b.token.refresh_token),
    ];
    assert!(
        tokens.iter().any(|(_, t)| e
            .state_json
            .contains(&hex::encode(Sha256::digest(t.as_bytes())))),
        "state.json holds no token hash: tokens are stored as hashes, so one must be there"
    );

    let cookie_value = r
        .cookie
        .split_once('=')
        .map_or(r.cookie.as_str(), |(_, v)| v);
    let mut secrets = tokens;
    secrets.extend([
        ("code A", s.a.code.as_str()),
        ("code B", s.b.code.as_str()),
        ("the enrolment code", r.secrets[0].as_str()),
        ("the session cookie value", cookie_value),
    ]);
    for (what, secret) in &secrets {
        assert!(secret.len() >= 16, "{what} is a real secret (not empty)");
    }
    for (file, text) in [
        ("kharond's log", &e.log),
        ("state.json", &e.state_json),
        ("audit.jsonl", &e.audit_raw),
    ] {
        for (what, secret) in &secrets {
            assert!(!text.contains(secret), "{what} appears in {file}");
        }
    }
    assert!(
        !e.state_json.contains("\"kh_at_") && !e.state_json.contains("\"kh_rt_"),
        "state.json holds a string that starts with kh_at_ or kh_rt_"
    );
}
