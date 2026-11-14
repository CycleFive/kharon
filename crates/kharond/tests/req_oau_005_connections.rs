//! REQ-OAU-005 / REQ-REV-001 / REQ-REV-002, D9 (#233): the
//! Connections page, Disconnect, the owner socket's `revoke_agent`
//! on a `c-…` id, panic ending every Connect, and `client_name`
//! display on the owner surfaces.
//!
//! The rig is the approvals rig's shape (a real broker behind the
//! real owner UI, a software passkey session) plus an OAuth store
//! wired the way the daemon wires it: the broker carries the store,
//! and the store's lifecycle appends through the broker's audit log
//! and drops ended Connects' grants on the broker
//! (`DaemonOauthLifecycle`'s two lines). Connects are created by
//! redeeming a code directly at the store, the seam the token-side
//! suites use.

mod api_support;
mod owner_ui_support;

use std::sync::Arc;

use api_support::{
    FakeAnswer, FakeFill, Harness, ITEM_A, RecordingAudit, TestBroker, mcp_call, serve_http,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use kharond::api::grant::{Channel, GrantAction, GrantRequestArgs, GrantTerms};
use kharond::api::http::ApprovalRedeemer;
use kharond::api::oauth_store::{CodeGrant, ConnectLifecycle, OauthStore};
use kharond::audit::Entry;
use kharond::owner_ui::{NoAudit, OwnerApprovals, OwnerUi, ShellView, StaticShell};
use owner_ui_support::{Http, http, register_and_sign_in};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

const DASHBOARD: &str = "https://dashboard.example/.well-known/kharon-client.json";
const OTHER: &str = "https://other.example/client.json";
const ALL_SCOPES: [&str; 3] = ["kharon:read", "kharon:fill", "kharon:request"];

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The daemon's lifecycle wiring, verbatim in miniature.
struct BrokerLifecycle(Arc<TestBroker>);

impl ConnectLifecycle for BrokerLifecycle {
    fn append(&self, entry: Entry) -> bool {
        self.0.append_audit(entry).is_ok()
    }

    fn connect_ended(&self, agent_id: &str) {
        self.0.revoke_connect_grants(agent_id);
    }
}

struct Rig {
    broker: Arc<TestBroker>,
    store: Arc<OauthStore>,
    audit: RecordingAudit,
    ui: std::net::SocketAddr,
    origin: String,
    cookie: String,
    api: std::net::SocketAddr,
    _store_dir: tempfile::TempDir,
    _ui_dir: tempfile::TempDir,
}

impl Rig {
    async fn new() -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(OauthStore::load(store_dir.path()).unwrap());
        // The fake fill backend observes an origin for any agent,
        // the phase-2 shape (a Connect with a browser attached):
        // it is what lets the Connect's grant request be created
        // and approved, so Disconnect has a live grant to revoke.
        let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/");
        let h = Harness::with(false, |b| {
            b.with_oauth_store(Arc::clone(&store))
                .with_fill_backend(Box::new(fake))
        });
        store.set_lifecycle(Arc::new(BrokerLifecycle(Arc::clone(&h.broker))));

        let ui_dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ui_addr = listener.local_addr().unwrap();
        let origin = format!("http://localhost:{}", ui_addr.port());
        let ui = OwnerUi::open(
            ui_dir.path(),
            "localhost",
            origin.clone(),
            Arc::new(StaticShell(ShellView {
                locked: false,
                pending: 0,
            })),
            Arc::new(NoAudit),
            h.broker.clone() as Arc<dyn OwnerApprovals>,
        )
        .unwrap();
        let token = ui.mint_enroll_token().unwrap();
        let redeem: Arc<dyn ApprovalRedeemer> = h.broker.clone();
        tokio::spawn(kharond::owner_ui::serve(listener, ui, redeem));
        let cookie = register_and_sign_in(ui_addr, &origin, &token).await;
        let api = serve_http(h.broker.clone()).await;
        Self {
            broker: h.broker,
            store,
            audit: h.audit,
            ui: ui_addr,
            origin,
            cookie,
            api,
            _store_dir: store_dir,
            _ui_dir: ui_dir,
        }
    }

    /// Redeem a code at the store: a live Connect, its access token
    /// and its `c-…` id.
    fn connect(&self, client_id: &str, client_name: &str) -> (String, String) {
        let verifier = "connections-test-verifier";
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
        let grant = CodeGrant {
            client_id: client_id.to_owned(),
            client_name: client_name.to_owned(),
            code_challenge: challenge,
            scopes: ALL_SCOPES.iter().map(|s| s.to_string()).collect(),
            consented_at: unix_now(),
            connector_grant_declared: false,
        };
        let code_hash: [u8; 32] = Sha256::digest(format!("code for {client_id}").as_bytes()).into();
        let pair = self
            .store
            .connect(&grant, verifier, code_hash, unix_now())
            .unwrap();
        let auth = self
            .store
            .authenticate_access(&pair.access_token, unix_now())
            .unwrap();
        (pair.access_token, auth.agent_id)
    }

    /// A pending grant request from the Connect, approved through
    /// the broker on `channel`. Returns the grant id.
    async fn grant_for(&self, access: &str, channel: Channel) -> String {
        let agent = self.broker.authenticate_on_mcp(access).unwrap();
        let args = GrantRequestArgs {
            item_id: ITEM_A.to_owned(),
            target_id: "target-1".to_owned(),
            expected_origin: "https://login.example.com".to_owned(),
            action: GrantAction::Fill,
        };
        self.broker
            .request_grant(&agent, args, tokio::time::Instant::now())
            .await
            .unwrap();
        let pending = self.broker.pending_grant_requests();
        let req = pending
            .iter()
            .find(|r| r.agent_id == agent.as_str())
            .expect("the Connect's request is pending");
        let terms = GrantTerms {
            kind: kharond::config::GrantKind::Once,
            ..GrantTerms::once_item(ITEM_A)
        };
        self.broker
            .approve_grant_request(&req.id, &terms, channel)
            .unwrap()
            .id
    }

    async fn get(&self, path: &str) -> (u16, Json) {
        let r = http(self.ui, &self.origin, Http::get(path).cookie(&self.cookie)).await;
        (r.status, r.json())
    }

    async fn post(&self, path: &str, body: &Json) -> (u16, Json) {
        let body = body.to_string();
        let r = http(
            self.ui,
            &self.origin,
            Http::post(path, Some("application/json"), &body).cookie(&self.cookie),
        )
        .await;
        (r.status, r.json())
    }

    /// Audit entries about one agent, oldest first.
    fn entries_for(&self, agent_id: &str) -> Vec<Entry> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.agent_id.as_deref() == Some(agent_id))
            .cloned()
            .collect()
    }

    async fn mcp_status(&self, access: &str) -> u16 {
        mcp_call(self.api, Some(access), "kharon_status", "{}")
            .await
            .status
    }
}

#[tokio::test]
async fn connections_page_lists_live_connects_with_their_fields() {
    let rig = Rig::new().await;
    let (_, dash_id) = rig.connect(DASHBOARD, "Muse");
    let (_, other_id) = rig.connect(OTHER, "Other App");

    let (status, body) = rig.get("/owner/connections").await;
    assert_eq!(status, 200, "{body}");
    let rows = body["connections"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{body}");
    let dash = &rows[0];
    assert_eq!(dash["agent_id"], dash_id);
    assert_eq!(dash["client_name"], "Muse");
    assert_eq!(dash["host"], "dashboard.example");
    assert_eq!(
        dash["scopes"],
        json!(["kharon:read", "kharon:fill", "kharon:request"])
    );
    assert_eq!(dash["channel"], "oauth");
    assert!(
        dash["connected_at"].as_str().unwrap().ends_with('Z'),
        "{dash}"
    );
    assert_eq!(dash["suspended"], false);
    assert_eq!(rows[1]["agent_id"], other_id);
    assert_eq!(rows[1]["host"], "other.example");

    // An ended Connect leaves the list.
    rig.store
        .disconnect(
            &other_id,
            kharond::api::oauth_store::DisconnectDetail::Owner,
            "cli",
            unix_now(),
        )
        .unwrap();
    let (_, body) = rig.get("/owner/connections").await;
    let rows = body["connections"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{body}");
    assert_eq!(rows[0]["agent_id"], dash_id);
}

#[tokio::test]
async fn connections_routes_need_a_session() {
    let rig = Rig::new().await;
    let r = http(rig.ui, &rig.origin, Http::get("/owner/connections")).await;
    assert_eq!(r.status, 401, "{}", r.body);
    let body = json!({"agent_id": "c-abcdefghij"}).to_string();
    let r = http(
        rig.ui,
        &rig.origin,
        Http::post(
            "/owner/connections/disconnect",
            Some("application/json"),
            &body,
        ),
    )
    .await;
    assert_eq!(r.status, 401, "{}", r.body);
}

#[tokio::test]
async fn disconnect_from_the_page_ends_the_connect_and_its_grants() {
    let rig = Rig::new().await;
    let (access, id) = rig.connect(DASHBOARD, "Muse");
    assert_eq!(rig.mcp_status(&access).await, 200);

    // The pending queue names the Connect by its client_name.
    let agent = rig.broker.authenticate_on_mcp(&access).unwrap();
    let args = GrantRequestArgs {
        item_id: ITEM_A.to_owned(),
        target_id: "target-1".to_owned(),
        expected_origin: "https://login.example.com".to_owned(),
        action: GrantAction::Fill,
    };
    rig.broker
        .request_grant(&agent, args, tokio::time::Instant::now())
        .await
        .unwrap();
    let (status, body) = rig.get("/owner/approvals").await;
    assert_eq!(status, 200, "{body}");
    let pending = &body["pending"][0];
    assert_eq!(pending["agent_id"], id, "{body}");
    assert_eq!(pending["agent_name"], "Muse", "{body}");
    let request_id = pending["request_id"].as_str().unwrap().to_owned();

    // Approve on the page; the grants list names it too.
    let (status, body) = rig
        .post(
            "/owner/approvals/approve",
            &json!({"request_id": request_id, "kind": "once"}),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = rig.get("/owner/grants").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["grants"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(body["grants"][0]["agent_id"], id, "{body}");
    assert_eq!(body["grants"][0]["agent_name"], "Muse", "{body}");

    // Disconnect from the page.
    let (status, body) = rig
        .post("/owner/connections/disconnect", &json!({"agent_id": id}))
        .await;
    assert_eq!(status, 200, "{body}");

    // The token is refused on the next request, the grant is gone,
    // and the ending is audited on the web_ui channel.
    assert_eq!(rig.mcp_status(&access).await, 401);
    assert!(rig.broker.live_grants().is_empty());
    let entries = rig.entries_for(&id);
    let disconnect = entries
        .iter()
        .find(|e| e.event.as_str() == "oauth_disconnect")
        .expect("an oauth_disconnect entry");
    assert_eq!(disconnect.channel.as_deref(), Some("web_ui"));
    assert_eq!(disconnect.detail_code.as_deref(), Some("owner"));
    assert_eq!(disconnect.origin.as_deref(), Some("dashboard.example"));
    assert!(
        entries.iter().any(|e| e.event.as_str() == "grant_revoke"),
        "the live grant was revoked: {entries:?}"
    );

    // A second Disconnect finds nothing.
    let (status, body) = rig
        .post("/owner/connections/disconnect", &json!({"agent_id": id}))
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"], "not_found");
}

#[tokio::test]
async fn socket_revoke_agent_ends_a_connect_on_the_cli_channel() {
    let rig = Rig::new().await;
    let (access, id) = rig.connect(DASHBOARD, "Muse");
    rig.grant_for(&access, Channel::Cli).await;

    // The exact broker call the owner socket's `revoke_agent` op
    // makes (owner::OwnerOps through DaemonOwner).
    let revoked = rig.broker.revoke_agent(&id).unwrap();
    assert_eq!(revoked, 1, "the Connect's one live grant");
    assert_eq!(rig.mcp_status(&access).await, 401);
    assert!(rig.broker.live_grants().is_empty());

    let entries = rig.entries_for(&id);
    let disconnect = entries
        .iter()
        .find(|e| e.event.as_str() == "oauth_disconnect")
        .expect("an oauth_disconnect entry");
    assert_eq!(disconnect.channel.as_deref(), Some("cli"));
    assert_eq!(disconnect.detail_code.as_deref(), Some("owner"));
    assert!(
        !entries.iter().any(|e| e.event.as_str() == "token_revoke"),
        "a Connect has no configured token to bind a token_revoke to"
    );

    // The config-agent path is unchanged: token_revoke, durable.
    rig.broker.revoke_agent("alpha").unwrap();
    let alpha = rig.entries_for("alpha");
    assert!(
        alpha.iter().any(|e| e.event.as_str() == "token_revoke"),
        "config agents still revoke by token: {alpha:?}"
    );
}

#[tokio::test]
async fn unsuspend_from_the_page_writes_the_owner_reset() {
    let rig = Rig::new().await;
    let (_, id) = rig.connect(DASHBOARD, "Muse");
    let (status, body) = rig
        .post("/owner/connections/unsuspend", &json!({"agent_id": id}))
        .await;
    assert_eq!(status, 200, "{body}");
    let entries = rig.entries_for(&id);
    let reset = entries
        .iter()
        .find(|e| e.event.as_str() == "rate_limit")
        .expect("a rate_limit entry");
    assert_eq!(reset.result.as_deref(), Some("unsuspended"));
    assert_eq!(reset.detail_code.as_deref(), Some("owner_reset"));
    // The page did it, and the entry says so (#233 review): a
    // reset from the owner's passkey is `web_ui`, not channel-less.
    assert_eq!(reset.channel.as_deref(), Some("web_ui"));
    assert!(!rig.broker.agent_suspended(&id));

    // The web route refuses a config agent: clearing a config
    // agent's suspension stays socket-only.
    let (status, body) = rig
        .post(
            "/owner/connections/unsuspend",
            &json!({"agent_id": "alpha"}),
        )
        .await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"], "not_found");
    assert!(
        !rig.entries_for("alpha")
            .iter()
            .any(|e| e.event.as_str() == "rate_limit"),
        "no reset was written for the config agent"
    );
}

#[tokio::test]
async fn unsuspend_from_the_socket_writes_the_cli_channel() {
    let rig = Rig::new().await;
    let (_, id) = rig.connect(DASHBOARD, "Muse");
    // The exact broker call the owner socket's `unsuspend` op
    // makes (owner::OwnerOps through DaemonOwner).
    rig.broker.unsuspend_agent(&id, Channel::Cli).unwrap();
    let entries = rig.entries_for(&id);
    let reset = entries
        .iter()
        .find(|e| e.event.as_str() == "rate_limit")
        .expect("a rate_limit entry");
    assert_eq!(reset.result.as_deref(), Some("unsuspended"));
    assert_eq!(reset.detail_code.as_deref(), Some("owner_reset"));
    assert_eq!(reset.channel.as_deref(), Some("cli"));
}

#[tokio::test]
async fn owner_rows_render_a_connect_name_with_its_id() {
    // `client_name` is a string the client chose, so no row may
    // show it instead of the `c-…` id (#233 review): the pending,
    // grants and audit renderers all build `name (id)`.
    let rig = Rig::new().await;
    let r = http(rig.ui, &rig.origin, Http::get("/").cookie(&rig.cookie)).await;
    assert_eq!(r.status, 200);
    for expr in [
        "p.agent_name ? p.agent_name + \" (\" + p.agent_id + \")\" : p.agent_id",
        "g.agent_name ? g.agent_name + \" (\" + g.agent_id + \")\" : g.agent_id",
        "e.agent_name ? e.agent_name + \" (\" + (e.agent_id || \"\") + \")\" : (e.agent_id || \"\")",
    ] {
        assert!(r.body.contains(expr), "row renderer missing: {expr}");
    }
    assert!(
        !r.body.contains("agent_name ||"),
        "no row falls back to name-instead-of-id"
    );
}

#[tokio::test]
async fn panic_from_the_page_ends_every_connect() {
    let rig = Rig::new().await;
    let (access_a, id_a) = rig.connect(DASHBOARD, "Muse");
    let (access_b, id_b) = rig.connect(OTHER, "Other App");
    assert_eq!(rig.mcp_status(&access_a).await, 200);
    assert_eq!(rig.mcp_status(&access_b).await, 200);

    let (status, body) = rig.post("/owner/panic", &json!({"confirm": true})).await;
    assert_eq!(status, 200, "{body}");

    assert_eq!(rig.mcp_status(&access_a).await, 401);
    assert_eq!(rig.mcp_status(&access_b).await, 401);
    for id in [&id_a, &id_b] {
        let entries = rig.entries_for(id);
        let disconnect = entries
            .iter()
            .find(|e| e.event.as_str() == "oauth_disconnect")
            .expect("an oauth_disconnect entry");
        assert_eq!(disconnect.detail_code.as_deref(), Some("panic"));
    }
    let (_, body) = rig.get("/owner/connections").await;
    assert_eq!(body["connections"], json!([]), "{body}");

    // The shell's panic text says what a panic costs a dashboard.
    let r = http(rig.ui, &rig.origin, Http::get("/").cookie(&rig.cookie)).await;
    assert_eq!(r.status, 200);
    assert!(
        r.body.contains("click Connect again"),
        "the panic confirmation must say dashboards re-click Connect"
    );
}

#[tokio::test]
async fn audit_tail_names_connects_by_client_name() {
    let rig = Rig::new().await;
    let (access, id) = rig.connect(DASHBOARD, "Muse");
    rig.grant_for(&access, Channel::WebUi).await;
    rig.broker.revoke_agent("alpha").unwrap();

    let (status, body) = rig.get("/owner/audit").await;
    assert_eq!(status, 200, "{body}");
    let entries = body["entries"].as_array().unwrap();
    let connect_entry = entries
        .iter()
        .find(|e| e["agent_id"] == id)
        .expect("an entry about the Connect");
    assert_eq!(connect_entry["agent_name"], "Muse", "{connect_entry}");
    let alpha_entry = entries
        .iter()
        .find(|e| e["agent_id"] == "alpha")
        .expect("an entry about the config agent");
    assert!(
        alpha_entry.get("agent_name").is_none(),
        "config agents carry no client_name: {alpha_entry}"
    );
}
