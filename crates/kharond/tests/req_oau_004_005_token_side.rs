//! REQ-OAU-004/-005/-008 (#231): prefix dispatch on the agent
//! API. A `kh_at_` OAuth access token authenticates `POST /mcp`
//! only — never a `/v1/*` route — while `kh_agent_` tokens keep
//! working on both, and ending the Connect refuses the token at
//! once. The `kh_at_` check is a hash lookup: it answers even
//! while the broker is locked, where an Argon2id check could not
//! be the thing standing in front of `kharon_status`.

mod api_support;

use std::sync::Arc;

use api_support::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use kharond::api::oauth_store::{CodeGrant, ConnectLifecycle, OauthStore};
use kharond::audit::Entry;
use sha2::{Digest, Sha256};

/// The lifecycle seam, permissive: these tests exercise auth, not
/// the audit contents (covered in `api::oauth_store`'s tests).
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

/// A store with one live Connect, plus its access token and the
/// identity it authenticates as.
fn live_connect() -> (Arc<OauthStore>, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let store = OauthStore::load(dir.path()).unwrap();
    // The store outlives the tempdir handle in these tests only as
    // an in-memory image; keep the dir alive by leaking it (test
    // processes are short-lived).
    let dir_path = dir.path().to_path_buf();
    std::mem::forget(dir);
    let _ = &dir_path;
    store.set_lifecycle(Arc::new(AllowAll));
    let verifier = "integration-verifier";
    let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
    let grant = CodeGrant {
        client_id: "https://dashboard.example/.well-known/kharon-client.json".to_owned(),
        client_name: "Dashboard".to_owned(),
        code_challenge: challenge,
        scopes: vec!["kharon:read".to_owned()],
        consented_at: unix_now(),
    };
    let code_hash = Sha256::digest(b"integration-code").into();
    let pair = store
        .connect(&grant, verifier, code_hash, unix_now())
        .unwrap();
    let auth = store
        .authenticate_access(&pair.access_token, unix_now())
        .unwrap();
    (Arc::new(store), pair.access_token, auth.agent_id)
}

#[tokio::test]
async fn kh_at_authenticates_mcp_only() {
    let (store, access, agent_id) = live_connect();
    assert!(agent_id.starts_with("c-"), "{agent_id}");
    let h = Harness::with(false, |b| b.with_oauth_store(store));
    let addr = serve_http(h.broker.clone()).await;

    // The OAuth token works on POST /mcp…
    let r = mcp_call(addr, Some(&access), "kharon_status", "{}").await;
    assert_eq!(r.status, 200, "kh_at_ on /mcp: {}", r.body);
    // …and names the Connect identity as the caller (the status
    // answer is per-agent state).
    // Never on /v1/* — the same refusal as any bad token there.
    for target in ["/v1/status", "/v1/items"] {
        let r = get(addr, target, Some(&access)).await;
        assert_eq!(r.status, 401, "kh_at_ on {target}");
    }
    // A forged kh_at_ is refused on /mcp too.
    let forged = format!("kh_at_{}", "A".repeat(43));
    let r = mcp_call(addr, Some(&forged), "kharon_status", "{}").await;
    assert_eq!(r.status, 401);
    // The static agent token is unchanged on both surfaces.
    let r = mcp_call(addr, Some(&h.alpha), "kharon_status", "{}").await;
    assert_eq!(r.status, 200, "kh_agent_ on /mcp");
    let r = get(addr, "/v1/status", Some(&h.alpha)).await;
    assert_eq!(r.status, 200, "kh_agent_ on /v1/status");
}

#[tokio::test]
async fn ending_the_connect_refuses_the_token() {
    let (store, access, agent_id) = live_connect();
    let h = Harness::with(false, |b| b.with_oauth_store(Arc::clone(&store)));
    let addr = serve_http(h.broker.clone()).await;
    let r = mcp_call(addr, Some(&access), "kharon_status", "{}").await;
    assert_eq!(r.status, 200);
    store
        .disconnect(
            &agent_id,
            kharond::api::oauth_store::DisconnectDetail::Owner,
            "cli",
            unix_now(),
        )
        .unwrap();
    let r = mcp_call(addr, Some(&access), "kharon_status", "{}").await;
    assert_eq!(
        r.status, 401,
        "a dead Connect's token must not authenticate"
    );
}
