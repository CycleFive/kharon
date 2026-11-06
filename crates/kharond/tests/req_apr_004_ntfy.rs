//! REQ-APR-004 (SPEC §5; issue #21): the ntfy approval channel —
//! one-time approve/deny tokens, POST-only mutation, over HTTP on
//! the owner listener (REQ-DEP-006, #136). The agent API listener
//! leaves `/owner/approve/<token>` and `/owner/deny/<token>` unrouted.
//!
//! - GET on an approve URL renders a confirm page and leaves the
//!   grant state unchanged (still pending, token still redeemable).
//! - POST redeems the token: approve issues a `once` grant on the
//!   ntfy channel (the fill then runs), deny denies the request.
//! - Replaying a used token → 410; a token older than 120 s → 410;
//!   an unknown token → 410; a token presented to the wrong action's
//!   endpoint → 410.
//! - PUT on an approve URL → 405 (approve/deny are POST-only).

mod api_support;

use std::sync::Arc;
use std::time::Duration;

use api_support::{
    CHEAP_FLOOR, FakeAnswer, FakeFill, ITEM_A, RawResponse, RecordingAudit, TestBroker,
    TestSession, cheap_argon, raw_request, serve_http, serve_owner,
};
use kharond::api::grant::{Channel, RequestState};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, Outcome, parse_fill};
use kharond::lock::{Clock, LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use serde_json::{Value, json};
use tokio::time::Instant;

struct Rig {
    broker: Arc<TestBroker>,
    clock: Arc<ManualClock>,
    alpha: String,
}

impl Rig {
    fn new() -> Self {
        let (alpha, ha) = generate_with(&cheap_argon(), "alpha");
        let tokens = TokenStore::with_floor([("alpha", ha.as_str())], &CHEAP_FLOOR).unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut lock = LockController::new(
            LockPolicy::default(),
            clock.clone(),
            Box::new(StaticHardening::all_ok()),
        );
        lock.unlock(|| Ok::<_, ()>(TestSession::fixture())).unwrap();
        let audit = RecordingAudit::default();
        let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/");
        let grant_clock: Arc<dyn Clock> = clock.clone();
        let broker = Broker::new(tokens, lock, Box::new(audit), OriginConfig::default())
            .with_grant_clock(grant_clock)
            .with_fill_backend(Box::new(fake));
        Self {
            broker: Arc::new(broker),
            clock,
            alpha: alpha.expose_secret().clone(),
        }
    }

    async fn fill_password(&self) -> Value {
        let req = parse_fill(
            kharond::api::FillOperation::Fill,
            json!({
                "item_id": ITEM_A,
                "target": {"cdp_target_id": "tab-1", "expected_origin": "https://login.example.com"},
                "fields": [{"kind": "password"}],
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let agent = self.broker.authenticate(&self.alpha).unwrap();
        match self.broker.fill(&agent, req, Instant::now()).await {
            Ok(Outcome::Fill(r)) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a fill outcome, got {other:?}"),
        }
    }

    /// Create a pending request and return its id plus its live
    /// (approve, deny) token paths.
    async fn pending_request(&self) -> (String, String, String) {
        let r = self.fill_password().await;
        assert_eq!(r["status"], "pending_approval", "{r}");
        let id = r["grant_request_id"].as_str().unwrap().to_owned();
        let (approve, deny) = self
            .broker
            .approval_token_paths(&id)
            .expect("a pending request has a live token pair");
        (id, approve, deny)
    }
}

async fn http(addr: std::net::SocketAddr, method: &str, path: &str) -> RawResponse {
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    raw_request(addr, head.as_bytes()).await
}

#[tokio::test]
async fn req_apr_004_get_confirm_page_leaves_grant_state_unchanged() {
    let rig = Rig::new();
    let (id, approve, _deny) = rig.pending_request().await;
    let addr = serve_owner(rig.broker.clone()).await;

    let page = http(addr, "GET", &approve).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("approve"), "{}", page.body);
    assert!(
        page.body.contains("login.example.com"),
        "confirm page shows the observed origin: {}",
        page.body
    );
    // State unchanged: still pending, and the token still redeems.
    assert_eq!(
        rig.broker.grant_request(&id).unwrap().state,
        RequestState::Pending
    );
    let post = http(addr, "POST", &approve).await;
    assert_eq!(post.status, 200, "{}", post.body);
}

#[tokio::test]
async fn req_apr_004_post_approve_issues_a_once_grant_and_the_fill_runs() {
    let rig = Rig::new();
    let (id, approve, _deny) = rig.pending_request().await;
    let addr = serve_owner(rig.broker.clone()).await;

    let post = http(addr, "POST", &approve).await;
    assert_eq!(post.status, 200, "{}", post.body);
    let req = rig.broker.grant_request(&id).unwrap();
    assert_eq!(req.state, RequestState::Approved);
    let grant_id = req.grant_id.clone().unwrap();
    let (channel, max_uses) = {
        let store = rig.broker.grant_store().lock().unwrap();
        let grant = store.grant(&grant_id).unwrap();
        (grant.created_by_channel, grant.max_uses)
    };
    assert_eq!(channel, Channel::Ntfy);
    assert_eq!(max_uses, Some(1), "ntfy approves once grants");

    let r = rig.fill_password().await;
    assert_eq!(r["status"], "filled", "{r}");
}

#[tokio::test]
async fn req_apr_004_post_deny_denies_the_request() {
    let rig = Rig::new();
    let (id, _approve, deny) = rig.pending_request().await;
    let addr = serve_owner(rig.broker.clone()).await;

    let post = http(addr, "POST", &deny).await;
    assert_eq!(post.status, 200, "{}", post.body);
    assert_eq!(
        rig.broker.grant_request(&id).unwrap().state,
        RequestState::Denied
    );
}

#[tokio::test]
async fn req_apr_004_replay_of_a_used_token_is_410() {
    let rig = Rig::new();
    let (_id, approve, _deny) = rig.pending_request().await;
    let addr = serve_owner(rig.broker.clone()).await;

    assert_eq!(http(addr, "POST", &approve).await.status, 200);
    assert_eq!(http(addr, "POST", &approve).await.status, 410);
    assert_eq!(http(addr, "GET", &approve).await.status, 410);
}

#[tokio::test]
async fn req_apr_004_token_older_than_120s_is_410() {
    let rig = Rig::new();
    let (id, approve, _deny) = rig.pending_request().await;
    let addr = serve_owner(rig.broker.clone()).await;

    rig.clock.advance(Duration::from_secs(121));
    assert_eq!(http(addr, "GET", &approve).await.status, 410);
    assert_eq!(http(addr, "POST", &approve).await.status, 410);
    // The request itself was not decided by the stale token.
    assert_eq!(
        rig.broker.grant_request(&id).unwrap().state,
        RequestState::Pending
    );
}

#[tokio::test]
async fn req_apr_004_unknown_token_and_wrong_endpoint_are_410() {
    let rig = Rig::new();
    let (_id, approve, _deny) = rig.pending_request().await;
    let addr = serve_owner(rig.broker.clone()).await;

    let unknown = format!("/owner/approve/{}", "0".repeat(64));
    assert_eq!(http(addr, "POST", &unknown).await.status, 410);
    // The approve token presented to the deny endpoint decides
    // nothing.
    let deny_path = approve.replacen("/owner/approve/", "/owner/deny/", 1);
    assert_eq!(http(addr, "POST", &deny_path).await.status, 410);
    // And it is still live on its own endpoint afterwards.
    assert_eq!(http(addr, "POST", &approve).await.status, 200);
}

#[tokio::test]
async fn req_apr_004_approve_and_deny_are_post_only() {
    let rig = Rig::new();
    let (_id, approve, _deny) = rig.pending_request().await;
    let addr = serve_owner(rig.broker.clone()).await;

    let put = http(addr, "PUT", &approve).await;
    assert_eq!(put.status, 405, "{}", put.body);
    let delete = http(addr, "DELETE", &approve).await;
    assert_eq!(delete.status, 405, "{}", delete.body);
}

/// REQ-DEP-006: the agent router leaves the redeem paths unrouted.
/// The owner listener still confirms with GET and decides with POST.
#[tokio::test]
async fn req_apr_004_agent_listener_does_not_redeem() {
    let rig = Rig::new();
    let (_id, approve, deny) = rig.pending_request().await;
    let agent = serve_http(rig.broker.clone()).await;
    let owner = serve_owner(rig.broker.clone()).await;

    for path in [&approve, &deny] {
        let get = http(agent, "GET", path).await;
        assert_eq!(get.status, 404, "{path}: {}", get.body);
        assert!(get.body.contains("no such route"), "{path}: {}", get.body);
        assert_eq!(http(agent, "POST", path).await.status, 404, "{path}");
        let page = http(owner, "GET", path).await;
        assert_eq!(page.status, 200, "{path}: {}", page.body);
    }
    // The confirm GETs left the token redeemable.
    assert_eq!(http(owner, "POST", &approve).await.status, 200);
}

const DAEMON_TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";

/// The running daemon serves redeem on `[owner_ui] listen` and leaves
/// it off `[api] listen`. An `Origin` from outside the owner UI still
/// reaches the token handler (the ntfy client supplies its own).
#[tokio::test(flavor = "multi_thread")]
async fn req_apr_004_daemon_serves_redeem_only_on_the_owner_listener() {
    let data = tempfile::tempdir().unwrap();
    let text = format!(
        r#"mode = "export"
data_dir = "{data}"
[export]
file = "{export}"
[agents.assistant]
token_hash = "{DAEMON_TOKEN_HASH}"
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}
[audit]
checkpoint_local_only = true
[memory]
require_mlock = false
[api]
listen = "127.0.0.1:0"
[owner_ui]
listen = "127.0.0.1:0"
rp_id = "localhost"
origin = "http://localhost:1"
"#,
        data = data.path().display(),
        export = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        ),
    );
    let cfg = kharond::config::Config::from_toml_str(&text).unwrap();
    let daemon = kharond::daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let agent = daemon.local_addr().unwrap();
    let owner = daemon.owner_ui_addr().expect("owner UI listener");
    assert_ne!(agent, owner);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(daemon.run(async {
        let _ = stopped.await;
    }));

    let path = format!("/owner/approve/{}", "0".repeat(64));
    let on_agent = http(agent, "GET", &path).await;
    assert_eq!(on_agent.status, 404, "{}", on_agent.body);
    assert!(
        on_agent
            .header("content-type")
            .unwrap_or("")
            .starts_with("application/json"),
        "{on_agent:?}"
    );
    assert!(on_agent.body.contains("no such route"), "{}", on_agent.body);
    assert_eq!(http(agent, "POST", &path).await.status, 404);

    let on_owner = http(owner, "GET", &path).await;
    assert_eq!(on_owner.status, 410, "{}", on_owner.body);
    assert!(
        on_owner
            .header("content-type")
            .unwrap_or("")
            .starts_with("text/html"),
        "{on_owner:?}"
    );
    assert!(
        on_owner.body.contains("no longer valid"),
        "{}",
        on_owner.body
    );
    assert_eq!(http(owner, "POST", &path).await.status, 410);

    let deny = path.replacen("/owner/approve/", "/owner/deny/", 1);
    assert_eq!(http(agent, "GET", &deny).await.status, 404);
    assert_eq!(http(owner, "GET", &deny).await.status, 410);

    let foreign = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\n\
         Connection: close\r\nContent-Length: 0\r\n\r\n"
    );
    let posted = raw_request(owner, foreign.as_bytes()).await;
    assert_eq!(posted.status, 410, "{}", posted.body);
    assert!(posted.body.contains("no longer valid"), "{}", posted.body);

    let home = http(owner, "GET", "/").await;
    assert_eq!(home.status, 200, "{}", home.body);
    assert!(home.body.contains("passkey"), "{}", home.body);

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
