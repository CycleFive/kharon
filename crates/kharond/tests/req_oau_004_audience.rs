//! REQ-OAU-004 (#304): an OAuth token record stores its audience in
//! its own field. A phase-1 `oauth/state.json` has no audience key
//! and still authenticates on `POST /mcp` (the record loads as
//! `mcp`). A connector-audience access token round-trips, and on
//! `/mcp` it is 401 before the scope gate — the same body as any
//! other auth failure, never 403 `insufficient_scope`, never a
//! tool result. No assertion prints a token.

mod api_support;

use std::sync::Arc;

use api_support::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use kharond::api::ApiError;
use kharond::api::oauth::Discovery;
use kharond::api::oauth_store::{
    CodeGrant, ConnectLifecycle, IssuedPair, OauthStore, TokenAudience,
};
use kharond::audit::Entry;
use sha2::{Digest, Sha256};

/// The lifecycle seam, permissive: these tests exercise the
/// audience field, not the audit contents.
struct AllowAll;

impl ConnectLifecycle for AllowAll {
    fn append(&self, _entry: Entry) -> bool {
        true
    }
    fn connect_ended(&self, _agent_id: &str) {}
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// One Connect with `kharon:read` only, so an authenticated
/// `kharon_status` is in scope and `kharon_context` is not.
fn connect_read(store: &OauthStore) -> (IssuedPair, String) {
    let verifier = "audience-verifier";
    let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
    let now = unix_now();
    let grant = CodeGrant {
        client_id: "https://dashboard.example/.well-known/kharon-client.json".to_owned(),
        client_name: "Dashboard".to_owned(),
        code_challenge: challenge,
        scopes: vec!["kharon:read".to_owned()],
        consented_at: now,
        connector_grant_declared: false,
    };
    let pair = store
        .connect(
            &grant,
            verifier,
            Sha256::digest(b"audience-code").into(),
            now,
        )
        .unwrap();
    let id = store
        .authenticate_access(&pair.access_token, now)
        .unwrap()
        .agent_id;
    (pair, id)
}

fn open_store(dir: &std::path::Path) -> Arc<OauthStore> {
    let store = OauthStore::load(dir).unwrap();
    store.set_lifecycle(Arc::new(AllowAll));
    Arc::new(store)
}

/// 401, the invalid-token body, and the same `WWW-Authenticate` as
/// an unknown token. Not a tool result and not a scope step-up.
fn assert_same_auth_failure(got: &RawResponse, unknown: &RawResponse) {
    assert_eq!(got.status, 401);
    assert_eq!(got.json(), ApiError::INVALID_TOKEN.body());
    assert_eq!(got.json(), unknown.json());
    assert_eq!(
        got.header("www-authenticate"),
        unknown.header("www-authenticate")
    );
    let challenge = got.header("www-authenticate").unwrap();
    assert!(!challenge.contains("insufficient_scope"));
    assert!(!got.body.contains("\"result\""));
    assert!(!got.body.contains("insufficient_scope"));
}

#[tokio::test]
async fn req_oau_004_phase1_state_without_audience_authenticates_on_mcp() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());
    let (pair, agent_id) = connect_read(&store);
    let path = dir.path().join("oauth/state.json");
    let text = std::fs::read_to_string(&path).unwrap();
    // The writer now emits the field. A phase-1 file is that
    // document with the key removed, still at version 1, so the
    // existing version refusal does not trip.
    assert!(text.contains("\"version\":1"));
    assert!(text.contains("\"audience\":\"mcp\""));
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let tokens = value["tokens"].as_array_mut().unwrap();
    assert!(!tokens.is_empty());
    for token in tokens.iter_mut() {
        assert!(token.as_object_mut().unwrap().remove("audience").is_some());
    }
    assert_eq!(value["version"], 1);
    let stripped = serde_json::to_string(&value).unwrap();
    assert!(!stripped.contains("audience"));
    std::fs::write(&path, &stripped).unwrap();
    drop(store);

    let loaded = Arc::new(OauthStore::load(dir.path()).unwrap());
    assert_eq!(
        loaded.token_audience(&pair.access_token),
        Some(TokenAudience::Mcp)
    );
    assert_eq!(
        loaded.token_audience(&pair.refresh_token),
        Some(TokenAudience::Mcp)
    );
    let h = Harness::with(false, |b| b.with_oauth_store(Arc::clone(&loaded)));
    let addr = serve_http(h.broker.clone()).await;
    let r = mcp_call(addr, Some(&pair.access_token), "kharon_status", "{}").await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["result"]["isError"], false);
    let agent = h.broker.authenticate_on_mcp(&pair.access_token).unwrap();
    assert_eq!(agent.as_str(), agent_id);
}

#[test]
fn req_oau_004_connector_audience_record_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());
    let (mcp, id) = connect_read(&store);
    let connector = store.insert_connector_audience(&id, unix_now()).unwrap();
    assert_eq!(
        store.token_audience(&mcp.access_token),
        Some(TokenAudience::Mcp)
    );
    assert_eq!(
        store.token_audience(&mcp.refresh_token),
        Some(TokenAudience::Mcp)
    );
    assert_eq!(
        store.token_audience(&connector.access_token),
        Some(TokenAudience::Connector)
    );
    assert_eq!(
        store.token_audience(&connector.refresh_token),
        Some(TokenAudience::Connector)
    );
    drop(store);

    let loaded = OauthStore::load(dir.path()).unwrap();
    assert_eq!(
        loaded.token_audience(&connector.access_token),
        Some(TokenAudience::Connector)
    );
    assert_eq!(
        loaded.token_audience(&connector.refresh_token),
        Some(TokenAudience::Connector)
    );
    assert_eq!(
        loaded.token_audience(&mcp.access_token),
        Some(TokenAudience::Mcp)
    );
    assert_eq!(
        loaded.token_audience(&mcp.refresh_token),
        Some(TokenAudience::Mcp)
    );
    let auth = loaded
        .authenticate_access(&connector.access_token, unix_now())
        .unwrap();
    assert_eq!(auth.audience, TokenAudience::Connector);
    assert_eq!(auth.agent_id, id);

    let text = std::fs::read_to_string(dir.path().join("oauth/state.json")).unwrap();
    assert!(!text.contains(&connector.access_token));
    assert!(!text.contains(&connector.refresh_token));
    assert!(!text.contains(&mcp.access_token));
    assert!(!text.contains(&mcp.refresh_token));
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["version"], 1);
    let mut audiences: Vec<&str> = value["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|token| token["audience"].as_str().unwrap())
        .collect();
    audiences.sort_unstable();
    assert_eq!(audiences, ["connector", "connector", "mcp", "mcp"]);
}

#[tokio::test]
async fn req_oau_004_connector_audience_on_mcp_is_401_before_scopes() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(dir.path());
    let (mcp, id) = connect_read(&store);
    let connector = store.insert_connector_audience(&id, unix_now()).unwrap();
    assert_eq!(
        store.token_audience(&connector.access_token),
        Some(TokenAudience::Connector)
    );
    // Read-only: status is in scope, context is not. If the
    // audience check ran after the scope gate, context would be
    // 403 insufficient_scope and status would be a 200 tool result.
    let discovery = Discovery::new("https://kharon-owner.example".to_owned(), "kharon.example");
    let h = Harness::with(false, |b| {
        b.with_oauth_store(Arc::clone(&store))
            .with_oauth(discovery.clone())
    });
    let addr = serve_http(h.broker.clone()).await;

    assert_eq!(
        h.broker
            .authenticate_on_mcp(&connector.access_token)
            .unwrap_err(),
        ApiError::INVALID_TOKEN
    );
    assert!(h.broker.authenticate_on_mcp(&mcp.access_token).is_ok());

    let unknown_token = format!("kh_at_{}", "a".repeat(64));
    let unknown = mcp_call(addr, Some(&unknown_token), "kharon_status", "{}").await;
    assert_eq!(unknown.status, 401);
    assert_eq!(
        unknown.header("www-authenticate"),
        Some(discovery.challenge().as_str())
    );

    let mcp_status = mcp_call(addr, Some(&mcp.access_token), "kharon_status", "{}").await;
    assert_eq!(mcp_status.status, 200);
    assert_eq!(mcp_status.json()["result"]["isError"], false);

    let connector_status =
        mcp_call(addr, Some(&connector.access_token), "kharon_status", "{}").await;
    assert_same_auth_failure(&connector_status, &unknown);

    let mcp_context = mcp_call(addr, Some(&mcp.access_token), "kharon_context", "{}").await;
    assert_eq!(mcp_context.status, 403);
    assert!(
        mcp_context
            .header("www-authenticate")
            .unwrap()
            .contains("insufficient_scope")
    );

    let connector_context =
        mcp_call(addr, Some(&connector.access_token), "kharon_context", "{}").await;
    assert_same_auth_failure(&connector_context, &unknown);
}
