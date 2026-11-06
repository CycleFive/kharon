//! REQ-API-008 / REQ-API-009 / REQ-AUD-003† / REQ-ARCH-005 on the
//! daemon's fill path: the broker over [`ConnectingCdpBackend`] built
//! from `[agents.<id>] cdp` exactly as `daemon::start` builds it, against
//! a CDP stub that counts connections.
//!
//! - Startup does no browser I/O; the first fill connects and creates
//!   the agent's browser context, after its `fill_dispatch` entry.
//! - Later fills reuse the connection and context; a connection that
//!   ended is replaced (new context) by the next fill.
//! - The fill deadline bounds the connect and the fill: on expiry the
//!   reply is `timeout`, no further CDP frame is sent, and the audit is
//!   `fill_dispatch` plus exactly one `fill_timeout`.
//! - A deadline that fires mid-`createBrowserContext` does not leak the
//!   context (#68): a late reply is adopted by the next fill (one
//!   connection, one context), and a reply that never comes ends the
//!   connection after the connect budget so the browser disposes it.
//! - A failed `fill_dispatch` append opens no connection at all.
//! - An unreachable endpoint is `error`/`cdp_error`, audited once.
//! - Lock closes CDP sessions (SPEC §8, REQ-MEM-003/004, #66): every
//!   lock path disposes each cached context and closes its connection,
//!   in the background and bounded, so the lock itself never waits on
//!   the browser; the first fill after unlock reconnects with a fresh
//!   context; a fill racing a lock leaves nothing cached.
//!
//! - The context handoff (REQ-ARCH-005, #65): `POST /v1/context`
//!   connects lazily and returns the agent's cached context id
//!   (idempotent: one connection, one `createBrowserContext`); status
//!   reports it from the cache only (`null` before and after
//!   invalidation, never connecting); a reconnect or a lock gives a new
//!   id, tabs of the old context stay `target_not_owned`; `context_open`
//!   is written before any CDP I/O and the deadline bounds the call.
//! - A base-address endpoint (`ws://host:port`, issue #113) asks
//!   `/json/version` on each connect, so the fill after a browser
//!   restart finds the new `<id>`; a full URL is used as written.
//!
//! The browser-level E2E (a real Chromium and form) is #24.

mod api_support;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::{CHEAP_FLOOR, RawResponse, RecordingAudit, cheap_argon, get, post_json};
use futures_util::{SinkExt, StreamExt};
use kharond::api::fill::FillPolicy;
use kharond::api::token::{TokenStore, generate, generate_with};
use kharond::api::{Broker, ConnectingCdpBackend};
use kharond::config::Config;
use kharond::daemon;
use kharond::export::{ExportFile, ExportSession};
use kharond::lock::{LockController, LockPolicy, LockReason, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::{WebSocketStream, accept_async, accept_hdr_async};
use zeroize::Zeroizing;

const EXPORT: &[u8] = include_bytes!("fixtures/export/password_protected.json");
const EXPORT_PASSWORD: &str = "kharon export fixture password 9";
const CANARY_PASSWORD: &str = "CANARY-EXPORT-PASSWORD-7f3a";
const URL: &str = "https://example.com/login";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Answer everything.
    Normal,
    /// Never answer this method.
    Stall(&'static str),
    /// Answer this method only after a delay.
    Delay(&'static str, Duration),
    /// Close the WebSocket right after answering the in-page fill.
    CloseAfterFill,
    /// Answer the in-page fill with a `kharon:deadline` exception
    /// (#118: the page-side budget aborted the fill in-page).
    PageDeadline,
}

#[derive(Clone, Default)]
struct Stub {
    connections: Arc<AtomicUsize>,
    /// Connections that have ended (the client closed or dropped them).
    closed: Arc<AtomicUsize>,
    frames: Arc<Mutex<Vec<Value>>>,
}

impl Stub {
    fn methods(&self, name: &str) -> usize {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m["method"] == name)
            .count()
    }
    fn frame_count(&self) -> usize {
        self.frames.lock().unwrap().len()
    }
    /// The `arguments` array of the first `Runtime.callFunctionOn`
    /// frame, if any was sent.
    fn fill_arguments(&self) -> Option<Value> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .find(|m| m["method"] == "Runtime.callFunctionOn")
            .map(|m| m["params"]["arguments"].clone())
    }
}

/// A CDP peer: every connection gets context `ctx-<n>` from
/// `createBrowserContext`, and page `t1` on `URL` lives in the latest
/// context; page `t-ctx1` on `URL` always lives in `ctx-1` (a tab the
/// agent opened in its first context).
async fn cdp_stub(mode: Mode) -> (String, Stub) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stub = Stub::default();
    let s = stub.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let n = s.connections.fetch_add(1, Ordering::SeqCst) + 1;
            let s = s.clone();
            tokio::spawn(async move {
                let Ok(ws) = accept_async(stream).await else {
                    return;
                };
                serve_cdp(ws, &s, mode, n).await;
            });
        }
    });
    (format!("ws://{addr}/devtools/browser"), stub)
}

/// Answer CDP on one accepted WebSocket until it ends (see [`cdp_stub`]).
async fn serve_cdp(mut ws: WebSocketStream<TcpStream>, s: &Stub, mode: Mode, n: usize) {
    let ctx = format!("ctx-{n}");
    while let Some(Ok(Message::Text(text))) = ws.next().await {
        let msg: Value = serde_json::from_str(&text).unwrap();
        s.frames.lock().unwrap().push(msg.clone());
        let method = msg["method"].as_str().unwrap_or_default().to_owned();
        if matches!(mode, Mode::Stall(m) if m == method) {
            continue;
        }
        if let Mode::Delay(m, delay) = mode
            && m == method
        {
            tokio::time::sleep(delay).await;
        }
        let result = match method.as_str() {
            "Target.createBrowserContext" => json!({ "browserContextId": ctx }),
            "Target.getTargetInfo" if msg["params"]["targetId"] == "t-ctx1" => {
                json!({ "targetInfo": {
                    "targetId": "t-ctx1", "browserContextId": "ctx-1",
                    "url": URL, "title": "", "type": "page",
                } })
            }
            "Target.getTargetInfo" => json!({ "targetInfo": {
                "targetId": "t1", "browserContextId": ctx,
                "url": URL, "title": "", "type": "page",
            } }),
            "Target.attachToTarget" => json!({ "sessionId": "sess-1" }),
            "Page.getFrameTree" => json!({ "frameTree": { "frame": {
                "id": "f1", "loaderId": "l1", "url": URL,
            }, "childFrames": [] } }),
            "Page.createIsolatedWorld" => json!({ "executionContextId": 7 }),
            "Runtime.callFunctionOn" if mode == Mode::PageDeadline => {
                json!({
                    "result": { "type": "object" },
                    "exceptionDetails": { "exception": { "description":
                        "Error: kharon:deadline\n    at fillInPage (<anonymous>:1:1)" } },
                })
            }
            "Runtime.callFunctionOn" => {
                let kinds: Vec<Value> = msg["params"]["arguments"][1]["value"]
                    .as_array()
                    .map(|fs| fs.iter().map(|f| json!({ "kind": f["kind"] })).collect())
                    .unwrap_or_default();
                json!({ "result": { "type": "object", "value": { "results": kinds } } })
            }
            _ => json!({}),
        };
        let mut reply = json!({ "id": msg["id"], "result": result });
        if let Some(sid) = msg.get("sessionId") {
            reply["sessionId"] = sid.clone();
        }
        ws.send(Message::Text(reply.to_string())).await.unwrap();
        if mode == Mode::CloseAfterFill && method == "Runtime.callFunctionOn" {
            let _ = ws.close(None).await;
            s.closed.fetch_add(1, Ordering::SeqCst);
            return;
        }
    }
    s.closed.fetch_add(1, Ordering::SeqCst);
}

/// What the Chromium-like stub ([`chromium_stub`]) saw on its HTTP side.
#[derive(Clone, Default)]
struct Discovery {
    /// The current browser id; a restart bumps it.
    browser: Arc<AtomicUsize>,
    /// `Host` header of each `GET /json/version`.
    version_hosts: Arc<Mutex<Vec<String>>>,
    /// Path of each WebSocket upgrade, accepted or not.
    upgrades: Arc<Mutex<Vec<String>>>,
}

impl Discovery {
    fn browser_path(&self) -> String {
        format!(
            "/devtools/browser/b{}-0000-4000-8000-000000000000",
            self.browser.load(Ordering::SeqCst)
        )
    }

    /// Chromium restarts: a new `<id>`, and the live socket is gone.
    fn restart(&self) {
        self.browser.fetch_add(1, Ordering::SeqCst);
    }
}

/// A CDP peer shaped like Chromium behind the agent host's relay (issue
/// #113): `GET /json/version` names the current browser socket as
/// `ws://127.0.0.1:9222/devtools/browser/<id>` (the address Chromium
/// binds, not the one dialled), a `Host` that is neither an IP nor
/// `localhost` gets a 500, and only the current `<id>` upgrades. With
/// `Mode::CloseAfterFill`, closing after a fill is a browser restart.
async fn chromium_stub(mode: Mode) -> (String, Stub, Discovery) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stub = Stub::default();
    let disc = Discovery {
        browser: Arc::new(AtomicUsize::new(1)),
        ..Discovery::default()
    };
    let (s, d) = (stub.clone(), disc.clone());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let s = s.clone();
            let d = d.clone();
            tokio::spawn(async move {
                let mut peek = [0u8; 64];
                let Ok(k) = stream.peek(&mut peek).await else {
                    return;
                };
                if peek[..k].starts_with(b"GET /json/version ") {
                    answer_json_version(&mut stream, &d).await;
                    return;
                }
                let path = Arc::new(Mutex::new(String::new()));
                let p = Arc::clone(&path);
                let current = d.browser_path();
                // tungstenite's callback type returns the whole error response.
                #[allow(clippy::result_large_err)]
                let check = move |req: &Request, resp: Response| {
                    let got = req.uri().path().to_owned();
                    *p.lock().unwrap() = got.clone();
                    if got == current {
                        Ok(resp)
                    } else {
                        let mut e = ErrorResponse::new(None);
                        *e.status_mut() = StatusCode::NOT_FOUND;
                        Err(e)
                    }
                };
                let accepted = accept_hdr_async(stream, check).await;
                d.upgrades
                    .lock()
                    .unwrap()
                    .push(path.lock().unwrap().clone());
                let Ok(ws) = accepted else {
                    return;
                };
                let n = s.connections.fetch_add(1, Ordering::SeqCst) + 1;
                serve_cdp(ws, &s, mode, n).await;
                if mode == Mode::CloseAfterFill {
                    d.restart();
                }
            });
        }
    });
    (format!("ws://{addr}"), stub, disc)
}

/// One `GET /json/version`, answered the way Chromium does (keeping the
/// socket open after the body).
async fn answer_json_version(stream: &mut TcpStream, d: &Discovery) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).await.is_err() {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let host = head
        .lines()
        .find_map(|l| l.strip_prefix("Host: "))
        .unwrap_or_default()
        .to_owned();
    d.version_hosts.lock().unwrap().push(host.clone());
    let name = host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h);
    let safe = name == "localhost"
        || name.parse::<std::net::IpAddr>().is_ok()
        || name
            .trim_matches(['[', ']'])
            .parse::<std::net::Ipv6Addr>()
            .is_ok();
    let (status, body) = if safe {
        let ws = format!("ws://127.0.0.1:9222{}", d.browser_path());
        (
            "200 OK",
            json!({ "Browser": "HeadlessChrome/157.0.8103.27", "webSocketDebuggerUrl": ws })
                .to_string(),
        )
    } else {
        (
            "500 Internal Server Error",
            "Host header is specified and is not an IP address or localhost.".to_owned(),
        )
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes()).await;
    // Chromium leaves the connection open; the client must not wait for EOF.
    tokio::time::sleep(Duration::from_secs(5)).await;
}

/// An export-mode config whose only agent's CDP endpoint is `cdp`.
fn config_toml(hash: &str, data_dir: &Path, cdp: &str) -> String {
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "{cdp}" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"
"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        )
    )
}

type TestBroker = Broker<ExportSession, Arc<ManualClock>>;

struct Run {
    addr: std::net::SocketAddr,
    token: String,
    item_id: String,
    audit: RecordingAudit,
    broker: Arc<TestBroker>,
    clock: Arc<ManualClock>,
}

fn export_session() -> ExportSession {
    ExportFile::from_bytes(EXPORT)
        .unwrap()
        .unlock(&Zeroizing::new(EXPORT_PASSWORD.to_owned()))
        .unwrap()
}

/// The broker, unlocked with the export fixture, over the backend the
/// daemon builds from `[agents]`.
async fn run(cdp: &str, deadline: Duration) -> Run {
    run_with(cdp, deadline, None).await
}

/// [`run`] with an optional background connect budget override.
async fn run_with(cdp: &str, deadline: Duration, connect_timeout: Option<Duration>) -> Run {
    run_with_backend(cdp, deadline, |b| match connect_timeout {
        Some(t) => b.with_connect_timeout(t),
        None => b,
    })
    .await
}

/// [`run`] with the backend adjusted by `tune`.
async fn run_with_backend(
    cdp: &str,
    deadline: Duration,
    tune: impl FnOnce(ConnectingCdpBackend) -> ConnectingCdpBackend,
) -> Run {
    let data = tempfile::tempdir().unwrap();
    let cfg = Config::from_toml_str(&config_toml(
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
        data.path(),
        cdp,
    ))
    .unwrap();
    let backend = tune(ConnectingCdpBackend::from_agents(&cfg.agents));

    let session = export_session();
    let item_id = session
        .vault()
        .items()
        .find(|i| i.name() == "Example Login")
        .unwrap()
        .id()
        .to_owned();
    let clock = Arc::new(ManualClock::new());
    let mut lock = LockController::new(
        LockPolicy::default(),
        Arc::clone(&clock),
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| Ok::<_, ()>(session)).unwrap();
    let (token, hash) = generate_with(&cheap_argon(), "alpha");
    let tokens = TokenStore::with_floor([("alpha", hash.as_str())], &CHEAP_FLOOR).unwrap();
    let audit = RecordingAudit::default();
    let broker = Broker::new(
        tokens,
        lock,
        Box::new(audit.clone()),
        OriginConfig::default(),
    )
    .with_fill_policy(FillPolicy {
        deadline,
        ..FillPolicy::from(&cfg.policy)
    })
    .with_fill_backend(Box::new(backend));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let broker = Arc::new(broker);
    // #20: fills need a grant; the export item has no collections, so
    // seed item-scope grants for both actions.
    {
        let now = kharond::lock::Clock::now(&kharond::lock::SystemClock);
        let terms = kharond::api::GrantTerms {
            scope: kharond::api::GrantScope::Item(item_id.clone()),
            kind: kharond::config::GrantKind::PerOrigin,
            ttl: Some(std::time::Duration::from_secs(24 * 3600)),
            max_uses: None,
        };
        let mut store = broker.grant_store().lock().unwrap();
        for action in [
            kharond::api::GrantAction::Fill,
            kharond::api::GrantAction::Totp,
        ] {
            store
                .issue(
                    "alpha",
                    &item_id,
                    action,
                    "https://example.com",
                    &terms,
                    kharond::api::Channel::Cli,
                    None,
                    now,
                )
                .unwrap();
        }
    }
    tokio::spawn(kharond::api::http::serve(listener, Arc::clone(&broker)));
    Run {
        addr,
        token: token.expose_secret().clone(),
        item_id,
        audit,
        broker,
        clock,
    }
}

impl Run {
    async fn fill(&self, submit: bool) -> RawResponse {
        self.fill_target("t1", submit).await
    }

    async fn fill_target(&self, target: &str, submit: bool) -> RawResponse {
        let body = json!({
            "item_id": self.item_id,
            "target": {"cdp_target_id": target, "expected_origin": "https://example.com"},
            "fields": [{"kind": "username"}, {"kind": "password"}],
            "submit": submit,
        });
        post_json(self.addr, "/v1/fill", Some(&self.token), &body.to_string()).await
    }

    /// `POST /v1/context` with an empty body (#65).
    async fn context(&self) -> RawResponse {
        let head = format!(
            "POST /v1/context HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            self.token
        );
        api_support::raw_request(self.addr, head.as_bytes()).await
    }

    /// `browser_context_id` from `GET /v1/status`.
    async fn status_context(&self) -> Value {
        let r = get(self.addr, "/v1/status", Some(&self.token)).await;
        assert_eq!(r.status, 200, "{}", r.body);
        r.json()["browser_context_id"].clone()
    }

    /// Owner lock (`kharon lock`): returns whether a session was
    /// destroyed.
    fn lock(&self) -> bool {
        self.broker
            .lock_controller()
            .lock()
            .unwrap()
            .lock(LockReason::Manual)
    }

    fn is_locked(&self) -> bool {
        self.broker.lock_controller().lock().unwrap().is_locked()
    }

    fn unlock(&self) {
        self.broker
            .lock_controller()
            .lock()
            .unwrap()
            .unlock(|| Ok::<_, ()>(export_session()))
            .unwrap();
    }

    fn entries(&self) -> Vec<Value> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect()
    }
}

fn filled() -> Value {
    json!({"status": "filled", "fields_filled": ["username", "password"]})
}

fn dispatch_then(outcome: &str, result: &str) -> Vec<Value> {
    vec![
        json!([
            "fill_dispatch",
            "alpha",
            "https://example.com",
            "dispatched"
        ]),
        json!([outcome, "alpha", null, result]),
    ]
}

const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test]
async fn req_api_008_daemon_backend_connects_on_first_fill_and_reuses_it() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(stub.connections.load(Ordering::SeqCst), 0, "lazy");

    for (i, submit) in [false, true].into_iter().enumerate() {
        let resp = r.fill(submit).await;
        assert_eq!(resp.status, 200, "{}", resp.body);
        assert_eq!(resp.json(), filled());
        assert!(!resp.body.contains(CANARY_PASSWORD));
        assert_eq!(stub.methods("Runtime.callFunctionOn"), i + 1);
    }
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        stub.methods("Target.createBrowserContext"),
        1,
        "REQ-ARCH-005: one context per agent, created once"
    );
    let mut want = dispatch_then("fill", "filled");
    want.extend(dispatch_then("fill", "filled"));
    assert_eq!(r.audit.summary(), want);
    let text = serde_json::to_string(&r.entries()).unwrap();
    assert!(!text.contains(CANARY_PASSWORD));
}

#[tokio::test]
async fn req_api_008_daemon_backend_reconnects_after_the_browser_drops() {
    let (url, stub) = cdp_stub(Mode::CloseAfterFill).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.fill(false).await.json(), filled());
    // Let the client's read task see the close.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let resp = r.fill(false).await;
    assert_eq!(resp.json(), filled(), "{}", resp.body);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
    assert_eq!(stub.methods("Target.createBrowserContext"), 2);
    assert_eq!(r.audit.summary().len(), 4);
}

/// Issue #113: with a base address (`ws://host:port`) the backend asks
/// `/json/version` for the browser socket on each connect, so after a
/// Chromium restart (new `<id>`, old socket gone) the next fill finds the
/// new one with no config change. Only the path of
/// `webSocketDebuggerUrl` is used: the stub names `127.0.0.1:9222`, as
/// Chromium behind the agent host's relay does, and the backend still
/// dials the configured address. Startup asks nothing.
#[tokio::test]
async fn req_arch_002_base_address_resolves_the_browser_id_again_after_a_restart() {
    let (base, stub, disc) = chromium_stub(Mode::CloseAfterFill).await;
    let first = disc.browser_path();
    let r = run(&base, DEADLINE).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(disc.version_hosts.lock().unwrap().is_empty(), "lazy");

    assert_eq!(r.fill(false).await.json(), filled());
    // The stub closed after the fill and "restarted" with a new id.
    eventually("browser restart", || disc.browser_path() != first).await;
    let second = disc.browser_path();
    let resp = r.fill(false).await;
    assert_eq!(resp.json(), filled(), "{}", resp.body);

    assert_eq!(*disc.upgrades.lock().unwrap(), vec![first, second]);
    let authority = base.strip_prefix("ws://").unwrap().to_owned();
    assert_eq!(
        *disc.version_hosts.lock().unwrap(),
        vec![authority.clone(), authority]
    );
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
    assert_eq!(stub.methods("Target.createBrowserContext"), 2);
    assert_eq!(
        r.audit.summary(),
        [
            dispatch_then("fill", "filled"),
            dispatch_then("fill", "filled")
        ]
        .concat()
    );
}

/// The full-URL form is still used as written (no `/json/version`), so
/// it goes stale when Chromium restarts: the problem #113 fixes for base
/// addresses.
#[tokio::test]
async fn req_arch_002_full_url_is_used_as_written_and_goes_stale_on_restart() {
    let (base, _stub, disc) = chromium_stub(Mode::CloseAfterFill).await;
    let first = disc.browser_path();
    let r = run(&format!("{base}{first}"), DEADLINE).await;
    assert_eq!(r.fill(false).await.json(), filled());
    eventually("browser restart", || disc.browser_path() != first).await;
    assert_eq!(
        r.fill(false).await.json(),
        json!({"status": "error", "fields_filled": [], "detail": "cdp_error"})
    );
    assert!(disc.version_hosts.lock().unwrap().is_empty());
    assert_eq!(*disc.upgrades.lock().unwrap(), vec![first.clone(), first]);
}

/// REQ-API-009 on the daemon path: a stall anywhere (here: in the
/// connect-time context creation, and in the in-page fill) is bounded by
/// `fill_deadline`; nothing is sent after expiry and the audit is one
/// dispatch plus exactly one `fill_timeout`.
///
/// For the in-page stall (the engine-level `DeadlineFiller` tests moved
/// here in #88): exactly one `Runtime.callFunctionOn` was ever sent, even
/// with `submit: true` (no clear-scrub, no separate submit write), the
/// `fill_timeout` entry carries the live origin read before the stall
/// (origin only, no path, #67), and no canary reaches the log or reply.
#[tokio::test]
async fn req_api_009_daemon_backend_respects_fill_deadline() {
    for stall in ["Target.createBrowserContext", "Runtime.callFunctionOn"] {
        let (url, stub) = cdp_stub(Mode::Stall(stall)).await;
        let r = run(&url, Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        let resp = r.fill(true).await;
        let took = started.elapsed();
        assert_eq!(resp.status, 200, "{stall}: {}", resp.body);
        assert_eq!(
            resp.json(),
            json!({"status": "timeout", "fields_filled": []}),
            "{stall}"
        );
        assert!(took < Duration::from_secs(5), "{stall}: {took:?}");
        let sent = stub.frame_count();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            stub.frame_count(),
            sent,
            "{stall}: no CDP frame after expiry"
        );
        let e = r.entries();
        assert_eq!(e.len(), 2, "{stall}: {e:?}");
        assert_eq!(e[0]["event"], "fill_dispatch");
        assert_eq!(e[1]["event"], "fill_timeout");
        assert_eq!(e[1]["detail_code"], "deadline_expired");
        assert_eq!(e[0]["request_id"], e[1]["request_id"]);
        assert!(took >= Duration::from_millis(300), "{stall}: {took:?}");
        let text = serde_json::to_string(&e).unwrap();
        assert!(!text.contains(CANARY_PASSWORD), "{stall}: canary in log");
        assert!(!resp.body.contains(CANARY_PASSWORD), "{stall}");
        assert!(!text.contains("/login"), "{stall}: no path in the log");
        if stall == "Runtime.callFunctionOn" {
            assert_eq!(
                stub.methods("Runtime.callFunctionOn"),
                1,
                "the stalled fill call only: no scrub, no submit write"
            );
            assert_eq!(e[1]["live_origin"], "https://example.com");
        } else {
            assert_eq!(stub.methods("Runtime.callFunctionOn"), 0, "{stall}");
            assert!(e[1].get("live_origin").is_none(), "{stall}: {e:?}");
        }
    }
}

/// #118 on the daemon path: the in-page call carries the page-side
/// relative budget as its fifth argument (remaining deadline minus
/// the 250 ms return margin), and a `kharon:deadline` exception reply
/// — the page aborting itself before the broker's deadline — maps to
/// the existing outcome: `timeout` reply, `fill_dispatch` plus exactly
/// one `fill_timeout`, no new status value, no further CDP write.
#[tokio::test]
async fn req_api_009_page_deadline_exception_is_timeout() {
    let (url, stub) = cdp_stub(Mode::PageDeadline).await;
    let r = run(&url, DEADLINE).await;
    let started = std::time::Instant::now();
    let resp = r.fill(true).await;
    let took = started.elapsed();
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(
        resp.json(),
        json!({"status": "timeout", "fields_filled": []})
    );
    assert!(
        took < Duration::from_secs(5),
        "page deadline answered well before the 10 s broker deadline: {took:?}"
    );
    assert_eq!(stub.methods("Runtime.callFunctionOn"), 1);
    let args = stub.fill_arguments().expect("the fill call was sent");
    let args = args.as_array().expect("arguments array");
    assert_eq!(args.len(), 5, "specs, fields, top origin, submit, budget");
    let budget = args[4]["value"].as_u64().expect("budgetMs is a number");
    assert!(
        budget > 0 && budget <= 9750,
        "budget is the remaining 10 s minus the 250 ms margin: {budget}"
    );
    let e = r.entries();
    assert_eq!(e.len(), 2, "{e:?}");
    assert_eq!(e[0]["event"], "fill_dispatch");
    assert_eq!(e[1]["event"], "fill_timeout");
    assert_eq!(e[1]["detail_code"], "deadline_expired");
    assert_eq!(e[0]["request_id"], e[1]["request_id"]);
    assert_eq!(e[1]["live_origin"], "https://example.com");
    assert!(!resp.body.contains(CANARY_PASSWORD));
}

/// #68: the deadline fires after `createBrowserContext` was sent but
/// before its reply. The fill is `timeout` with nothing sent after
/// expiry, and the late context is adopted by the next fill rather than
/// orphaned: still one connection and one `createBrowserContext`, and the
/// second fill lands in that context.
#[tokio::test]
async fn req_api_009_context_created_after_deadline_is_adopted_not_leaked() {
    let (url, stub) = cdp_stub(Mode::Delay(
        "Target.createBrowserContext",
        Duration::from_millis(600),
    ))
    .await;
    let r = run(&url, Duration::from_millis(200)).await;
    let resp = r.fill(true).await;
    assert_eq!(
        resp.json(),
        json!({"status": "timeout", "fields_filled": []}),
        "{}",
        resp.body
    );
    let sent = stub.frame_count();
    assert_eq!(stub.methods("Target.createBrowserContext"), 1);
    // The reply arrives after the deadline; the background connect keeps
    // it. No CDP frame goes out on the timed-out fill's behalf.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(stub.frame_count(), sent, "no CDP frame after expiry");
    assert_eq!(stub.closed.load(Ordering::SeqCst), 0, "connection kept");

    let r2 = r.fill(false).await;
    assert_eq!(r2.json(), filled(), "{}", r2.body);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        stub.methods("Target.createBrowserContext"),
        1,
        "the orphan was adopted, not replaced"
    );
    assert_eq!(stub.methods("Target.disposeBrowserContext"), 0);
    let mut want = vec![
        json!([
            "fill_dispatch",
            "alpha",
            "https://example.com",
            "dispatched"
        ]),
        json!(["fill_timeout", "alpha", null, "timeout"]),
    ];
    want.extend(dispatch_then("fill", "filled"));
    assert_eq!(r.audit.summary(), want);
}

/// #68, reply never arrives: the background connect gives up after its
/// budget and closes the connection (the browser disposes contexts with
/// their connection) without sending any CDP command. The next fill
/// starts over on a fresh connection.
#[tokio::test]
async fn req_api_009_unanswered_create_context_closes_the_connection() {
    let (url, stub) = cdp_stub(Mode::Stall("Target.createBrowserContext")).await;
    let r = run_with(
        &url,
        Duration::from_millis(200),
        Some(Duration::from_millis(500)),
    )
    .await;
    let resp = r.fill(false).await;
    assert_eq!(resp.json()["status"], "timeout", "{}", resp.body);
    let sent = stub.frame_count();
    let mut waited = Duration::ZERO;
    while stub.closed.load(Ordering::SeqCst) == 0 && waited < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += Duration::from_millis(50);
    }
    assert_eq!(
        stub.closed.load(Ordering::SeqCst),
        1,
        "connection closed after the connect budget"
    );
    assert_eq!(stub.frame_count(), sent, "closing sends no CDP command");

    let resp = r.fill(false).await;
    assert_eq!(resp.json()["status"], "timeout", "{}", resp.body);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
}

/// REQ-AUD-003†: a failed `fill_dispatch` append reaches no browser —
/// not even a connection.
#[tokio::test]
async fn req_aud_003_daemon_backend_failed_dispatch_opens_no_connection() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    *r.audit.fail_event.lock().unwrap() = Some("fill_dispatch");
    let resp = r.fill(true).await;
    assert_eq!(resp.status, 500);
    assert_eq!(resp.json()["error"], "audit_failed");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(stub.connections.load(Ordering::SeqCst), 0);
    assert!(r.audit.summary().is_empty());

    *r.audit.fail_event.lock().unwrap() = None;
    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(r.audit.summary(), dispatch_then("fill", "filled"));
}

#[tokio::test]
async fn req_api_008_daemon_backend_unreachable_browser_is_cdp_error() {
    // Bind then drop: nothing listens on this port.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let r = run(&format!("ws://127.0.0.1:{port}/devtools/browser"), DEADLINE).await;
    let resp = r.fill(false).await;
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(
        resp.json(),
        json!({"status": "error", "fields_filled": [], "detail": "cdp_error"})
    );
    assert_eq!(r.audit.summary(), dispatch_then("fill", "error"));
}

/// `daemon::start` wires the backend without touching the browser: a
/// started daemon has made no CDP connection, and (booted locked,
/// REQ-MEM-005) a fill is 423 before any CDP I/O.
#[tokio::test(flavor = "multi_thread")]
async fn req_api_008_daemon_start_does_not_connect_to_the_browser() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let (token, hash) = generate("alpha");
    let token = token.expose_secret().clone();
    let data = tempfile::tempdir().unwrap();
    let cfg = Config::from_toml_str(&config_toml(&hash, data.path(), &url)).unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let addr = d.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));
    assert_eq!(get(addr, "/v1/status", Some(&token)).await.status, 200);
    let body = json!({
        "item_id": "00000000-0000-4000-8000-000000000000",
        "target": {"cdp_target_id": "t1", "expected_origin": "https://example.com"},
        "fields": [{"kind": "password"}],
    });
    let r = post_json(addr, "/v1/fill", Some(&token), &body.to_string()).await;
    assert_eq!(r.status, 423, "{}", r.body);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 0);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// Poll `cond` every 20 ms for up to 5 s.
async fn eventually(what: &str, cond: impl Fn() -> bool) {
    let started = std::time::Instant::now();
    while !cond() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// SPEC §8 "Lock zeroizes keys and closes CDP sessions" (REQ-MEM-003,
/// #66): an owner lock disposes the agent's cached browser context
/// (`Target.disposeBrowserContext` for exactly that id) and closes the
/// connection. Nothing is sent to the browser after that.
#[tokio::test]
async fn req_mem_003_lock_disposes_contexts_and_closes_connections() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(stub.closed.load(Ordering::SeqCst), 0);

    assert!(r.lock());
    assert!(r.is_locked(), "keys gone");
    eventually("connection closed", || {
        stub.closed.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(stub.methods("Target.disposeBrowserContext"), 1);
    let dispose = stub
        .frames
        .lock()
        .unwrap()
        .iter()
        .find(|m| m["method"] == "Target.disposeBrowserContext")
        .cloned()
        .unwrap();
    assert_eq!(dispose["params"]["browserContextId"], "ctx-1");
    let sent = stub.frame_count();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stub.frame_count(), sent);

    // Locked: a fill is 423 and reaches no browser (REQ-MEM-007).
    assert_eq!(r.fill(false).await.status, 423);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
}

/// REQ-MEM-003 / REQ-ARCH-005 (#66): the first fill after unlock
/// reconnects and creates a fresh context; the old one is never reused.
#[tokio::test]
async fn req_mem_003_fill_after_unlock_reconnects_with_a_fresh_context() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.fill(false).await.json(), filled());
    assert!(r.lock());
    eventually("connection closed", || {
        stub.closed.load(Ordering::SeqCst) == 1
    })
    .await;
    r.unlock();

    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
    assert_eq!(stub.methods("Target.createBrowserContext"), 2);
    // The second fill's ownership check ran against the new context's
    // connection (the stub answers `ctx-2` there), and a third fill
    // reuses it.
    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
    assert_eq!(stub.methods("Target.disposeBrowserContext"), 1);
    assert_eq!(r.audit.summary().len(), 6);
}

/// REQ-MEM-003 (#66): an unlock and fill that overtake the lock's
/// background teardown get a fresh session, and the teardown does not
/// touch it: only the pre-lock context is disposed.
#[tokio::test]
async fn req_mem_003_unlock_and_fill_right_after_lock_keep_the_new_session() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.fill(false).await.json(), filled());
    // Lock and unlock with no await in between: the teardown task has
    // not run yet when the next fill starts.
    assert!(r.lock());
    r.unlock();
    assert_eq!(r.fill(false).await.json(), filled());
    eventually("old connection closed", || {
        stub.closed.load(Ordering::SeqCst) == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stub.closed.load(Ordering::SeqCst), 1, "new one kept");
    let disposed: Vec<Value> = stub
        .frames
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m["method"] == "Target.disposeBrowserContext")
        .map(|m| m["params"]["browserContextId"].clone())
        .collect();
    assert_eq!(disposed, [json!("ctx-1")]);
    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
}

/// REQ-MEM-003 / REQ-MEM-004 (#66): a browser that never answers
/// `disposeBrowserContext` cannot hold up the lock. The lock returns at
/// once with the keys gone; the teardown gives up after its budget and
/// closes the connection anyway, and the next unlock starts over.
#[tokio::test]
async fn req_mem_003_lock_succeeds_when_the_browser_is_stalled() {
    let (url, stub) = cdp_stub(Mode::Stall("Target.disposeBrowserContext")).await;
    let r = run_with_backend(&url, DEADLINE, |b| {
        b.with_teardown_timeout(Duration::from_millis(300))
    })
    .await;
    assert_eq!(r.fill(false).await.json(), filled());

    let started = std::time::Instant::now();
    assert!(r.lock());
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "lock waited on the browser: {:?}",
        started.elapsed()
    );
    assert!(r.is_locked());
    eventually("dispose sent", || {
        stub.methods("Target.disposeBrowserContext") == 1
    })
    .await;
    eventually("connection closed after the teardown budget", || {
        stub.closed.load(Ordering::SeqCst) == 1
    })
    .await;

    r.unlock();
    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
}

/// REQ-MEM-003 (#66): a browser that is already gone (connection ended)
/// does not fail the lock, and no CDP command is attempted for it.
#[tokio::test]
async fn req_mem_003_lock_succeeds_when_the_browser_is_unreachable() {
    let (url, stub) = cdp_stub(Mode::CloseAfterFill).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.fill(false).await.json(), filled());
    eventually("browser gone", || stub.closed.load(Ordering::SeqCst) == 1).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let sent = stub.frame_count();

    assert!(r.lock());
    assert!(r.is_locked());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stub.frame_count(), sent, "nothing sent to a dead browser");
    assert_eq!(stub.methods("Target.disposeBrowserContext"), 0);
    // Lock is audited as usual (the controller's sink is not wired here;
    // the API audit has just the one fill).
    assert_eq!(r.audit.summary(), dispatch_then("fill", "filled"));
}

/// REQ-MEM-004 (#66): the idle timer's lock closes CDP sessions too
/// (here enforced by the fill gate on the next request).
#[tokio::test]
async fn req_mem_004_idle_lock_closes_cdp_sessions() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.fill(false).await.json(), filled());
    r.clock.advance(Duration::from_secs(30 * 60));
    assert_eq!(r.fill(false).await.status, 423, "idle lock");
    eventually("connection closed", || {
        stub.closed.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(stub.methods("Target.disposeBrowserContext"), 1);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
}

/// REQ-MEM-007 / REQ-MEM-003 (#66): a fill admitted before a lock whose
/// connect finishes after it caches nothing and writes nothing to the
/// page: the late context is disposed and its connection closed, the
/// fill is `error`/`cdp_error` (audited as one outcome), and the next
/// fill after unlock opens a fresh session.
#[tokio::test]
async fn req_mem_007_fill_racing_a_lock_leaves_no_cached_context() {
    let (url, stub) = cdp_stub(Mode::Delay(
        "Target.createBrowserContext",
        Duration::from_millis(400),
    ))
    .await;
    let r = run(&url, DEADLINE).await;
    let fill = r.fill(true);
    let lock = async {
        eventually("connect in flight", || {
            stub.methods("Target.createBrowserContext") == 1
        })
        .await;
        assert!(r.lock());
    };
    let (resp, ()) = tokio::join!(fill, lock);
    assert_eq!(
        resp.json(),
        json!({"status": "error", "fields_filled": [], "detail": "cdp_error"}),
        "{}",
        resp.body
    );
    eventually("late connection closed", || {
        stub.closed.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(stub.methods("Target.disposeBrowserContext"), 1);
    assert_eq!(stub.methods("Target.getTargetInfo"), 0, "no fill step ran");
    assert_eq!(stub.methods("Runtime.callFunctionOn"), 0);
    assert_eq!(r.audit.summary(), dispatch_then("fill", "error"));

    r.unlock();
    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
    assert_eq!(stub.methods("Target.createBrowserContext"), 2);
}

// ---- context handoff (REQ-ARCH-005, #65) ------------------------------

fn context_ok(id: &str) -> Value {
    json!({"status": "ok", "browser_context_id": id})
}

fn context_pair(result: &str) -> Vec<Value> {
    vec![
        json!(["context_open", "alpha", null, "dispatched"]),
        json!(["context", "alpha", null, result]),
    ]
}

/// Each `context_open` and the outcome after it share a request id.
fn assert_paired(e: &[Value]) {
    for (i, x) in e.iter().enumerate() {
        if x["event"] == "context_open" {
            assert_eq!(e[i + 1]["event"], "context", "{e:?}");
            assert_eq!(x["request_id"], e[i + 1]["request_id"], "{e:?}");
            assert!(x["request_id"].is_string());
        }
    }
}

/// #65: lazy until the first call; the call connects and creates the
/// context; a second call returns the same id over the same connection
/// (one `createBrowserContext`); status reads the cache only, `null`
/// before; a fill then lands in that context without a second one.
#[tokio::test]
async fn req_arch_005_context_is_lazy_idempotent_and_in_status() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(r.status_context().await, Value::Null);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        stub.connections.load(Ordering::SeqCst),
        0,
        "status never connects"
    );

    for _ in 0..2 {
        let resp = r.context().await;
        assert_eq!(resp.status, 200, "{}", resp.body);
        assert_eq!(resp.header("cache-control"), Some("no-store"));
        assert_eq!(resp.json(), context_ok("ctx-1"));
    }
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
    assert_eq!(stub.methods("Target.createBrowserContext"), 1);
    assert_eq!(stub.frame_count(), 1, "nothing but createBrowserContext");
    assert_eq!(r.status_context().await, json!("ctx-1"));

    assert_eq!(r.fill(false).await.json(), filled());
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
    assert_eq!(stub.methods("Target.createBrowserContext"), 1);
    let mut want = context_pair("ok");
    want.extend(context_pair("ok"));
    want.extend(dispatch_then("fill", "filled"));
    assert_eq!(r.audit.summary(), want);
    assert_paired(&r.entries());
}

/// #65: a reconnect invalidates the id (status `null` once the
/// connection ended), the next call returns the new context's id, and a
/// tab of the old context is `target_not_owned`.
#[tokio::test]
async fn req_arch_005_reconnect_gives_a_new_id() {
    let (url, stub) = cdp_stub(Mode::CloseAfterFill).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.context().await.json(), context_ok("ctx-1"));
    // The old-context tab is owned while ctx-1 is live.
    assert_eq!(r.fill_target("t-ctx1", false).await.json(), filled());
    eventually("connection closed", || {
        stub.closed.load(Ordering::SeqCst) == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(r.status_context().await, Value::Null, "invalidated");

    assert_eq!(r.context().await.json(), context_ok("ctx-2"));
    assert_eq!(r.status_context().await, json!("ctx-2"));
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
    let resp = r.fill_target("t-ctx1", false).await;
    assert_eq!(
        resp.json(),
        json!({"status": "target_not_owned", "fields_filled": []}),
        "{}",
        resp.body
    );
    assert_eq!(
        r.context().await.json(),
        context_ok("ctx-2"),
        "still cached"
    );
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
}

/// #65 + #66: a lock invalidates the id at once (status `null`), the
/// call is 423 while locked (one `context`/`locked` entry, no
/// `context_open`, no CDP), and after unlock a new context is created.
#[tokio::test]
async fn req_arch_005_lock_gates_and_invalidates_the_context() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;
    assert_eq!(r.context().await.json(), context_ok("ctx-1"));
    assert!(r.lock());
    assert_eq!(r.status_context().await, Value::Null, "invalidated by lock");
    eventually("connection closed", || {
        stub.closed.load(Ordering::SeqCst) == 1
    })
    .await;
    let sent = stub.frame_count();
    let resp = r.context().await;
    assert_eq!(resp.status, 423, "{}", resp.body);
    assert_eq!(resp.json()["error"], "locked");
    assert_eq!(stub.frame_count(), sent);
    assert_eq!(stub.connections.load(Ordering::SeqCst), 1);
    let mut want = context_pair("ok");
    want.push(json!(["context", "alpha", null, "locked"]));
    assert_eq!(r.audit.summary(), want);

    r.unlock();
    assert_eq!(r.status_context().await, Value::Null);
    assert_eq!(r.context().await.json(), context_ok("ctx-2"));
    assert_eq!(r.status_context().await, json!("ctx-2"));
    assert_eq!(stub.connections.load(Ordering::SeqCst), 2);
    assert_eq!(stub.methods("Target.createBrowserContext"), 2);
}

/// REQ-AUD-003† for the handoff: `context_open` is appended before any
/// CDP I/O (no connection, no frame at that moment), and a failed
/// append is `audit_failed` with no connection at all.
#[tokio::test]
async fn req_aud_003_context_open_precedes_any_cdp_io() {
    let (url, stub) = cdp_stub(Mode::Normal).await;
    let r = run(&url, DEADLINE).await;

    *r.audit.fail_event.lock().unwrap() = Some("context_open");
    let resp = r.context().await;
    assert_eq!(resp.status, 500, "{}", resp.body);
    assert_eq!(resp.json()["error"], "audit_failed");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(stub.connections.load(Ordering::SeqCst), 0);
    assert!(r.audit.summary().is_empty());
    *r.audit.fail_event.lock().unwrap() = None;

    let seen: Arc<Mutex<Vec<(String, usize, usize)>>> = Arc::default();
    let (s, st) = (Arc::clone(&seen), stub.clone());
    *r.audit.on_append.lock().unwrap() = Some(Box::new(move |e| {
        let ev = serde_json::to_value(&e.event).unwrap();
        s.lock().unwrap().push((
            ev.as_str().unwrap().to_owned(),
            st.connections.load(Ordering::SeqCst),
            st.frame_count(),
        ));
    }));
    assert_eq!(r.context().await.json(), context_ok("ctx-1"));
    assert_eq!(
        *seen.lock().unwrap(),
        [
            ("context_open".to_owned(), 0, 0),
            ("context".to_owned(), 1, 1)
        ]
    );
    assert_paired(&r.entries());
}

/// REQ-API-009 for the handoff: a stalled `createBrowserContext` is cut
/// off at the fill deadline: `timeout`, no CDP frame after expiry, and
/// `context_open` plus exactly one `context`/`timeout`
/// (`deadline_expired`, same request id). Status stays `null`.
#[tokio::test]
async fn req_api_009_context_respects_fill_deadline() {
    let (url, stub) = cdp_stub(Mode::Stall("Target.createBrowserContext")).await;
    let r = run(&url, Duration::from_millis(300)).await;
    let started = std::time::Instant::now();
    let resp = r.context().await;
    let took = started.elapsed();
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(resp.json(), json!({"status": "timeout"}));
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_secs(5),
        "{took:?}"
    );
    let sent = stub.frame_count();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(stub.frame_count(), sent, "no CDP frame after expiry");
    let e = r.entries();
    assert_eq!(e.len(), 2, "{e:?}");
    assert_eq!(e[0]["event"], "context_open");
    assert_eq!(e[1]["event"], "context");
    assert_eq!(e[1]["result"], "timeout");
    assert_eq!(e[1]["detail_code"], "deadline_expired");
    assert_paired(&e);
    assert_eq!(r.status_context().await, Value::Null);
}
