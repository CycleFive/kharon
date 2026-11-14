//! REQ-OAU-007 (#235 slice 6, #309): a Connect's browser is its
//! live connector session.
//!
//! Phase 1 (#232) refused every Connect `no_browser`. With phase
//! 2's hello (slice 5) a Connect identity can hold a session on
//! the hub, bound to the connector-audience access token that
//! authenticated it (D5). This suite wires the whole path in
//! process — OAuth store, hub, a real connector client, the
//! production fill backend and a broker — and checks the slice's
//! acceptance: `no_browser` only without a live, unexpired
//! session (scope first, backend untouched), a granted fill
//! reaching the CDP stub over the session, the session ending
//! with the Connect (Disconnect, panic, reuse) but not with an
//! ordinary lock, a session whose token record is revoked
//! stopping at once, and the Connections page's live-session row.
//! The lifecycle below mirrors the daemon's (`DaemonOauthLifecycle`
//! in `daemon.rs`): an ended Connect drops its hub session and its
//! grants.

mod api_support;
mod connector_support;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use api_support::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use connector_support::*;
use kharon_connector::run_agent_once;
use kharond::api::fill::{ConnectingCdpBackend, FillBackend};
use kharond::api::grant::{Channel, GrantAction, GrantScope, GrantTerms};
use kharond::api::oauth_store::{
    CodeGrant, ConnectLifecycle, IssuedPair, OauthStore, RefreshResource, SpawnRequest,
};
use kharond::api::{AgentId, ApiError, FillOperation, FillRequest, Outcome};
use kharond::audit::Entry;
use kharond::cdp::CdpEndpoint;
use kharond::cdp::fill::FieldKind;
use kharond::config::GrantKind;
use kharond::connector::{ConnectTokens, ConnectorSessions, Hub};
use kharond::lock::{Clock, SystemClock};
use kharond::owner_ui::OwnerApprovals;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const CLIENT_ID: &str = "https://dashboard.example/.well-known/kharon-client.json";
const MCP_URL: &str = "https://kharon.example/mcp";
const CONNECTOR_URL: &str = "https://kharon.example/connector";
const ALL_SCOPES: [&str; 3] = ["kharon:read", "kharon:fill", "kharon:request"];

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The daemon's lifecycle, in miniature: audit appends are
/// accepted; an ended Connect drops its live session on the hub
/// and its grants on the broker.
struct LiveLifecycle {
    hub: Arc<Hub>,
    broker: Arc<TestBroker>,
}

impl ConnectLifecycle for LiveLifecycle {
    fn append(&self, _entry: Entry) -> bool {
        true
    }

    fn connect_ended(&self, agent_id: &str) {
        self.hub.disconnect(agent_id);
        self.broker.revoke_connect_grants(agent_id);
    }
}

/// One Connect, fully wired: the connector rig (hub, WebSocket
/// entry, CDP stub), its OAuth store, and a broker carrying the
/// store, the production backend over the hub, and the hub's
/// sessions. The Connect holds every scope, declared the
/// connector grant at consent, and has a standing per-origin
/// grant over the fixture items — the precondition a fill needs,
/// seeded exactly as `grant_fixture_items` seeds config agents.
struct LiveRig {
    rig: Rig,
    store: Arc<OauthStore>,
    h: Harness,
    id: String,
    mcp_access: String,
    mcp_refresh: String,
    agent: AgentId,
}

async fn live_rig() -> LiveRig {
    let rig = rig().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(OauthStore::load(dir.path()).unwrap());
    std::mem::forget(dir);
    rig.hub
        .set_connect_tokens(Arc::clone(&store) as Arc<dyn ConnectTokens>);
    let backend = ConnectingCdpBackend::new(Vec::<(String, CdpEndpoint)>::new())
        .with_connector(Arc::clone(&rig.hub));
    let sessions: Arc<dyn ConnectorSessions> = rig.hub.clone();
    let h = Harness::with(false, |b| {
        b.with_oauth_store(Arc::clone(&store))
            .with_fill_backend(Box::new(backend))
            .with_connector_sessions(sessions)
    });
    store.set_lifecycle(Arc::new(LiveLifecycle {
        hub: Arc::clone(&rig.hub),
        broker: Arc::clone(&h.broker),
    }));

    let (mcp, id) = add_connect(&store, "slice6");
    {
        let mut grants = h.broker.grant_store().lock().unwrap();
        grants
            .issue(
                &id,
                ITEM_A,
                GrantAction::Fill,
                "example.com",
                &GrantTerms {
                    scope: GrantScope::Collection(fixture_collection_id()),
                    kind: GrantKind::PerOrigin,
                    ttl: Some(Duration::from_secs(24 * 60 * 60)),
                    max_uses: None,
                },
                Channel::Cli,
                None,
                SystemClock.now(),
            )
            .unwrap();
    }
    let agent = h.broker.authenticate_on_mcp(&mcp.access_token).unwrap();
    assert_eq!(agent.as_str(), id);
    LiveRig {
        rig,
        store,
        h,
        id,
        mcp_access: mcp.access_token,
        mcp_refresh: mcp.refresh_token,
        agent,
    }
}

/// Consent + code redemption on `store`: a Connect with every
/// scope that declared the connector extension grant.
fn add_connect(store: &OauthStore, tag: &str) -> (IssuedPair, String) {
    let verifier = format!("verifier-{tag}");
    let grant = CodeGrant {
        client_id: CLIENT_ID.to_owned(),
        client_name: "Dashboard".to_owned(),
        code_challenge: Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes())),
        scopes: ALL_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
        consented_at: unix_now(),
        connector_grant_declared: true,
    };
    let code_hash: [u8; 32] = Sha256::digest(format!("code-{tag}").as_bytes()).into();
    let pair = store
        .connect(&grant, &verifier, code_hash, unix_now())
        .unwrap();
    let id = store
        .authenticate_access(&pair.access_token, unix_now())
        .unwrap()
        .agent_id;
    (pair, id)
}

/// The connector extension grant: the Connect's connector family.
fn spawn(lr: &LiveRig) -> IssuedPair {
    lr.store
        .spawn(
            SpawnRequest {
                refresh_token: &lr.mcp_refresh,
                client_id: CLIENT_ID,
                resource: CONNECTOR_URL,
                connector_resource: CONNECTOR_URL,
                connector_configured: true,
            },
            unix_now(),
        )
        .unwrap()
}

/// Rotate `lr`'s connector family with `presented` (D3's table:
/// the connector resource, and only it).
fn rotate(lr: &LiveRig, presented: &str) -> IssuedPair {
    lr.store
        .refresh_for(
            presented,
            CLIENT_ID,
            Some(RefreshResource {
                presented: Some(CONNECTOR_URL),
                mcp: MCP_URL,
                connector: CONNECTOR_URL,
            }),
            unix_now(),
        )
        .unwrap()
}

/// Attach a connector client for `id` with `token`; returns when
/// the hub holds the session.
async fn attach(lr: &LiveRig, token: &str) -> tokio::task::JoinHandle<()> {
    let params = kharond::connector::AgentParams {
        agent_id: lr.id.clone(),
        token: Zeroizing::new(token.to_owned()),
        ..ws_dial(&lr.rig, token)
    };
    let handle = tokio::spawn(async move {
        let _ = run_agent_once(&params).await;
    });
    let hub = Arc::clone(&lr.rig.hub);
    let id = lr.id.clone();
    eventually("Connect session attached", move || hub.is_connected(&id)).await;
    handle
}

/// Stop an attached client: drop its session and let its task end.
async fn detach(lr: &LiveRig, handle: tokio::task::JoinHandle<()>) {
    lr.rig.hub.disconnect(&lr.id);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

fn fill_req() -> FillRequest {
    FillRequest {
        operation: FillOperation::Fill,
        item_id: ITEM_A.to_owned(),
        target_id: "t1".to_owned(),
        expected_origin: "https://example.com".to_owned(),
        fields: vec![(FieldKind::Password, None)],
        submit: false,
        grant_id: None,
    }
}

async fn fill(lr: &LiveRig) -> Result<Outcome, ApiError> {
    lr.h.broker
        .fill_from(&lr.agent, fill_req(), tokio::time::Instant::now(), None)
        .await
}

async fn context(lr: &LiveRig) -> Result<Outcome, ApiError> {
    lr.h.broker
        .context_from(&lr.agent, tokio::time::Instant::now(), None)
        .await
}

/// The slice's core: no session is `no_browser` with the backend
/// untouched; a live session carries the context call and a
/// granted fill to the CDP stub; the Connections row tracks the
/// session; Disconnect ends both.
#[tokio::test(flavor = "multi_thread")]
async fn fills_ride_the_live_session_and_disconnect_ends_it() {
    let lr = live_rig().await;

    // No session yet: all three browser tools refuse, and nothing
    // reached the stub (no configured endpoint is a fallback).
    assert_eq!(context(&lr).await, Err(ApiError::NO_BROWSER));
    assert_eq!(fill(&lr).await, Err(ApiError::NO_BROWSER));
    let totp = FillRequest {
        operation: FillOperation::FillTotp,
        fields: vec![(FieldKind::Totp, None)],
        ..fill_req()
    };
    assert_eq!(
        lr.h.broker
            .fill_from(&lr.agent, totp, tokio::time::Instant::now(), None)
            .await,
        Err(ApiError::NO_BROWSER)
    );
    assert!(lr.rig.received.lock().unwrap().is_empty());
    let rows = lr.h.broker.connections();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].browser);
    assert_eq!(rows[0].browser_since, None);

    // Attach: the row flips, the context call answers over the
    // session, and the fill reaches the stub.
    let pair = spawn(&lr);
    let handle = attach(&lr, &pair.access_token).await;
    let rows = lr.h.broker.connections();
    assert!(rows[0].browser, "{rows:?}");
    assert!(rows[0].browser_since.is_some(), "{rows:?}");

    let outcome = context(&lr).await.unwrap();
    let Outcome::Context(body) = outcome else {
        panic!("expected a context outcome: {outcome:?}");
    };
    assert_eq!(body.status, "ok");
    assert_eq!(body.browser_context_id.as_deref(), Some("ctx-A"));

    lr.rig.received.lock().unwrap().clear();
    let outcome = fill(&lr).await.unwrap();
    let Outcome::Fill(result) = outcome else {
        panic!("expected a fill outcome: {outcome:?}");
    };
    assert_eq!(result.status, "filled", "{result:?}");
    assert!(
        lr.rig
            .received
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.to_string().contains("Runtime.callFunctionOn")),
        "the fill never reached the CDP stub"
    );

    // Disconnect (the owner UI's button, through the broker) ends
    // the Connect and shuts its session in the same call.
    assert!(lr.h.broker.disconnect_connect(&lr.id).unwrap());
    assert!(!lr.rig.hub.is_connected(&lr.id));
    assert_eq!(fill(&lr).await, Err(ApiError::NO_BROWSER));
    let rows = lr.h.broker.connections();
    assert!(rows.is_empty(), "an ended Connect leaves the page");
    detach(&lr, handle).await;
}

/// D5's record binding: revoking the access token the session
/// attached with ends the session at once — the socket is still
/// open, the Connect itself is still live, and a fresh connector
/// token re-attaches.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_access_token_ends_its_session_at_once() {
    let lr = live_rig().await;
    let pair = spawn(&lr);
    let handle = attach(&lr, &pair.access_token).await;

    lr.store.revoke(&pair.access_token, unix_now()).unwrap();
    assert!(
        !lr.rig.hub.is_connected(&lr.id),
        "the session outlived its token record"
    );
    assert_eq!(fill(&lr).await, Err(ApiError::NO_BROWSER));

    // The Connect lives: its /mcp token still authenticates, the
    // family rotates, and the new token's session fills.
    assert!(
        lr.store
            .authenticate_access(&lr.mcp_access, unix_now())
            .is_some()
    );
    detach(&lr, handle).await;
    let pair2 = rotate(&lr, &pair.refresh_token);
    let handle = attach(&lr, &pair2.access_token).await;
    let outcome = fill(&lr).await.unwrap();
    let Outcome::Fill(result) = outcome else {
        panic!("expected a fill outcome: {outcome:?}");
    };
    assert_eq!(result.status, "filled", "{result:?}");
    detach(&lr, handle).await;
}

/// D5 via D3: an ordinary rotation leaves the attached session
/// alone (its token is still live), the runtime's re-attach
/// replaces it, and the grace retry that revokes the superseded
/// access token drops the session it authenticated.
#[tokio::test(flavor = "multi_thread")]
async fn the_grace_retry_revocation_drops_the_session() {
    let lr = live_rig().await;
    let pair1 = spawn(&lr);
    let first = attach(&lr, &pair1.access_token).await;

    // Ordinary rotation: pair 1's access token is not revoked, so
    // its session stands.
    let pair2 = rotate(&lr, &pair1.refresh_token);
    assert!(lr.rig.hub.is_connected(&lr.id));

    // The runtime re-attaches with the new token, replacing the
    // session (the first client's task ends with its session).
    let second = attach(&lr, &pair2.access_token).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), first).await;
    assert!(lr.rig.hub.is_connected(&lr.id));

    // The lost-response retry: presenting pair 1's retired refresh
    // token inside its grace rotates again and revokes pair 2's
    // access token — the record the live session is bound to.
    let _pair3 = rotate(&lr, &pair1.refresh_token);
    assert!(
        !lr.rig.hub.is_connected(&lr.id),
        "the session outlived pair 2's revoked access token"
    );
    assert_eq!(fill(&lr).await, Err(ApiError::NO_BROWSER));
    detach(&lr, second).await;
}

/// Revocation acceptance: panic shuts every Connect session (and
/// ends the Connect); an ordinary lock leaves the session up.
#[tokio::test(flavor = "multi_thread")]
async fn panic_drops_the_session_and_a_lock_does_not() {
    let lr = live_rig().await;
    let (other_pair, other_id) = add_connect(&lr.store, "bystander");
    let pair = spawn(&lr);
    let handle = attach(&lr, &pair.access_token).await;

    // A locked broker over the same store and hub: the session is
    // not the lock's to drop. With a session the call reaches the
    // lock gate; without one `no_browser` still precedes it.
    let locked_backend = ConnectingCdpBackend::new(Vec::<(String, CdpEndpoint)>::new())
        .with_connector(Arc::clone(&lr.rig.hub));
    let locked_sessions: Arc<dyn ConnectorSessions> = lr.rig.hub.clone();
    let store = Arc::clone(&lr.store);
    let locked = Harness::with(true, |b| {
        b.with_oauth_store(store)
            .with_fill_backend(Box::new(locked_backend))
            .with_connector_sessions(locked_sessions)
    });
    assert_eq!(
        locked
            .broker
            .context_from(&lr.agent, tokio::time::Instant::now(), None)
            .await,
        Err(ApiError::LOCKED)
    );
    let other = locked
        .broker
        .authenticate_on_mcp(&other_pair.access_token)
        .unwrap();
    assert_eq!(other.as_str(), other_id);
    assert_eq!(
        locked
            .broker
            .context_from(&other, tokio::time::Instant::now(), None)
            .await,
        Err(ApiError::NO_BROWSER)
    );
    assert!(
        lr.rig.hub.is_connected(&lr.id),
        "a lock dropped the connector session"
    );
    drop(locked);

    // Panic: the Connect ends and its session is shut with it.
    lr.h.broker.panic_lock().unwrap();
    assert!(!lr.rig.hub.is_connected(&lr.id));
    assert_eq!(lr.h.broker.connector_session_since(&lr.id), None);
    assert!(
        lr.store
            .authenticate_access(&lr.mcp_access, unix_now())
            .is_none(),
        "the Connect itself ended"
    );
    detach(&lr, handle).await;
}

/// The backend's two namespaces never substitute (REQ-OAU-007):
/// a Connect id is served only by its own live session, and an
/// id the config names is answered from the config alone.
#[tokio::test(flavor = "multi_thread")]
async fn backend_namespaces_never_substitute() {
    let lr = live_rig().await;
    let backend = ConnectingCdpBackend::new([("configured", ws_endpoint())])
        .with_connector(Arc::clone(&lr.rig.hub));

    // No session: the Connect id is not served; the configured id
    // is, on its own entry.
    assert!(!backend.has_agent(&lr.id));
    assert!(backend.has_agent("configured"));
    assert!(!backend.has_agent("unconfigured"));

    let pair = spawn(&lr);
    let handle = attach(&lr, &pair.access_token).await;
    assert!(backend.has_agent(&lr.id));
    // The Connect's session does not leak onto other ids.
    assert!(!backend.has_agent("unconfigured"));
    assert!(!backend.has_agent(&lr.id.replacen('c', "x", 1)));
    detach(&lr, handle).await;
    assert!(!backend.has_agent(&lr.id));
}

/// A configured `via = agent_connector` endpoint for the backend
/// namespace test: the address on the agent host, never dialed
/// here.
fn ws_endpoint() -> CdpEndpoint {
    CdpEndpoint::validate(
        "ws://127.0.0.1:9222",
        kharond::cdp::Tunnel::AgentConnector,
        None,
    )
    .unwrap()
}
