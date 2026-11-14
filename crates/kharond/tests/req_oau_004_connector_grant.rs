//! REQ-OAU-004 (#307): a connector access token spawned from the
//! extension grant is refused on `POST /mcp` with 401, before the
//! scope gate, and the MCP family still rotates afterwards. No
//! assertion prints a token.

mod api_support;

use std::sync::Arc;

use api_support::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use kharond::api::oauth_store::{
    CodeGrant, ConnectLifecycle, IssuedPair, OauthStore, SpawnRequest, TokenAudience,
};
use kharond::audit::Entry;
use sha2::{Digest, Sha256};

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

const CLIENT: &str = "https://dashboard.example/.well-known/kharon-client.json";
const CONNECTOR: &str = "https://kharon.example.com/connector";

fn connect_fill(store: &OauthStore) -> (IssuedPair, String) {
    let verifier = "spawn-verifier";
    let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
    let now = unix_now();
    let grant = CodeGrant {
        client_id: CLIENT.to_owned(),
        client_name: "Dashboard".to_owned(),
        code_challenge: challenge,
        scopes: vec!["kharon:read".to_owned(), "kharon:fill".to_owned()],
        consented_at: now,
        connector_grant_declared: true,
    };
    let pair = store
        .connect(&grant, verifier, Sha256::digest(b"spawn-code").into(), now)
        .unwrap();
    let id = store
        .authenticate_access(&pair.access_token, now)
        .unwrap()
        .agent_id;
    (pair, id)
}

#[tokio::test]
async fn req_oau_004_spawned_connector_token_is_401_on_mcp_and_the_mcp_family_still_rotates() {
    let dir = tempfile::tempdir().unwrap();
    let store = OauthStore::load(dir.path()).unwrap();
    store.set_lifecycle(Arc::new(AllowAll));
    let store = Arc::new(store);
    let (mcp, id) = connect_fill(&store);
    let now = unix_now();
    let connector = store
        .spawn(
            SpawnRequest {
                refresh_token: &mcp.refresh_token,
                client_id: CLIENT,
                resource: CONNECTOR,
                connector_resource: CONNECTOR,
                connector_configured: true,
            },
            now,
        )
        .unwrap();
    assert_eq!(connector.scope, "kharon:connector");
    assert_eq!(
        store.token_audience(&connector.access_token),
        Some(TokenAudience::Connector)
    );

    let h = Harness::with(false, |b| b.with_oauth_store(Arc::clone(&store)));
    let addr = serve_http(h.broker.clone()).await;
    let refused = mcp_call(addr, Some(&connector.access_token), "kharon_status", "{}").await;
    assert_eq!(refused.status, 401);
    assert!(!refused.body.contains("insufficient_scope"));
    assert!(!refused.body.contains("\"result\""));
    let ok = mcp_call(addr, Some(&mcp.access_token), "kharon_status", "{}").await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert_eq!(ok.json()["result"]["isError"], false);

    let rotated = store
        .refresh(&mcp.refresh_token, CLIENT, unix_now())
        .unwrap();
    assert_eq!(
        store.token_audience(&rotated.access_token),
        Some(TokenAudience::Mcp)
    );
    let ok = mcp_call(addr, Some(&rotated.access_token), "kharon_status", "{}").await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    let still = mcp_call(addr, Some(&connector.access_token), "kharon_status", "{}").await;
    assert_eq!(still.status, 401);
    assert!(!still.body.contains("insufficient_scope"));
    let agent = h.broker.authenticate_on_mcp(&rotated.access_token).unwrap();
    assert_eq!(agent.as_str(), id);
    assert!(
        h.broker
            .authenticate_on_mcp(&connector.access_token)
            .is_err()
    );
}
