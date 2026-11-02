//! Sync client against an in-process mock Bitwarden server serving the
//! recorded Vaultwarden fixture (`crates/kharon-bwcrypto/tests/fixtures/
//! vaultwarden/`), extended with out-of-scope ciphers that must never
//! be decrypted (REQ-CRY-005, REQ-CRY-007, REQ-CRY-011).
//!
//! The live half (real Vaultwarden over HTTPS) is
//! `req_cry_005_live_vaultwarden_api_key_sync`, run by `fixture.yml`.

use std::sync::{Arc, Mutex};

use kharond::sync::{
    ApiKey, Scope, SecretField, SyncClient, SyncError, TlsTrust, resync, unlock_and_sync,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;
use zeroize::Zeroizing;

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);
const CLIENT_ID: &str = "user.11111111-2222-4333-8444-555555555555";
const CLIENT_SECRET: &str = "mock-client-secret";
const OTHER_ORG: &str = "0d9f4c1e-0000-4000-8000-00000000beef";
const OTHER_COLL: &str = "0d9f4c1e-0000-4000-8000-00000000c011";

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}")).unwrap())
        .unwrap()
}

#[derive(Debug, Clone)]
struct Req {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct MockState {
    log: Vec<Req>,
    /// Answer the next N `/api/sync` calls with 401.
    reject_sync: usize,
    token_n: usize,
}

/// Fixture sync plus decoys: other collection, other org, personal,
/// trashed, and a non-login item in scope. PascalCase top level, as
/// some Vaultwarden versions and Bitwarden cloud send.
fn extended_sync() -> (Value, String, String) {
    let mut s = load("sync_fixture.json");
    let org = s["profile"]["organizations"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let coll = s["collections"][0]["id"].as_str().unwrap().to_owned();
    let org_key = s["profile"]["organizations"][0]["key"].clone();
    let base = s["ciphers"][0].clone();
    let mut decoy = |id: &str, f: &dyn Fn(&mut Value)| {
        let mut c = base.clone();
        c["id"] = json!(id);
        f(&mut c);
        s["ciphers"].as_array_mut().unwrap().push(c);
    };
    decoy("aaaaaaaa-0000-4000-8000-000000000001", &|c| {
        c["collectionIds"] = json!([OTHER_COLL])
    });
    decoy("aaaaaaaa-0000-4000-8000-000000000002", &|c| {
        c["organizationId"] = json!(OTHER_ORG);
        c["collectionIds"] = json!([coll.clone()]);
    });
    decoy("aaaaaaaa-0000-4000-8000-000000000003", &|c| {
        c["organizationId"] = Value::Null;
        c["collectionIds"] = json!([]);
    });
    decoy("aaaaaaaa-0000-4000-8000-000000000004", &|c| {
        c["deletedDate"] = json!("2026-10-01T00:00:00Z")
    });
    decoy("aaaaaaaa-0000-4000-8000-000000000005", &|c| {
        c["type"] = json!(2)
    });
    s["profile"]["organizations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": OTHER_ORG, "name": "other", "key": org_key}));
    s["collections"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": OTHER_COLL, "organizationId": org}));
    let pascal = json!({
        "Profile": s["profile"],
        "Collections": s["collections"],
        "Ciphers": s["ciphers"],
        "Object": "sync",
    });
    (pascal, org, coll)
}

async fn serve(sync: Value, state: Arc<Mutex<MockState>>) -> Url {
    let manifest = load("fixture.json");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let sync = sync.clone();
            let state = state.clone();
            let manifest = manifest.clone();
            tokio::spawn(async move {
                loop {
                    let Some(req) = read_req(&mut sock).await else {
                        return;
                    };
                    let (status, body) = respond(&req, &sync, &manifest, &state);
                    state.lock().unwrap().log.push(req);
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Url::parse(&format!("http://{addr}")).unwrap()
}

async fn read_req(sock: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.parse().unwrap())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string();
    Some(Req {
        method,
        path,
        headers,
        body,
    })
}

fn respond(req: &Req, sync: &Value, manifest: &Value, state: &Mutex<MockState>) -> (u16, String) {
    let acct = &manifest["account"];
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/identity/accounts/prelogin") => (
            200,
            json!({"kdf": acct["kdf"], "kdfIterations": acct["kdf_iterations"],
                   "kdfMemory": null, "kdfParallelism": null})
            .to_string(),
        ),
        ("POST", "/identity/connect/token") => {
            let form: Vec<(String, String)> = url::form_urlencoded::parse(req.body.as_bytes())
                .into_owned()
                .collect();
            let get = |k: &str| form.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str());
            if get("client_secret") != Some(CLIENT_SECRET) || get("client_id") != Some(CLIENT_ID) {
                return (400, json!({"error": "invalid_client"}).to_string());
            }
            let mut st = state.lock().unwrap();
            st.token_n += 1;
            (
                200,
                json!({"access_token": format!("tok-{}", st.token_n), "expires_in": 7200,
                       "token_type": "Bearer", "scope": "api"})
                .to_string(),
            )
        }
        ("GET", p) if p.starts_with("/api/sync") => {
            let mut st = state.lock().unwrap();
            let want = format!("Bearer tok-{}", st.token_n);
            if st.reject_sync > 0 {
                st.reject_sync -= 1;
                return (401, "{}".into());
            }
            if req.header("authorization") != Some(want.as_str()) {
                return (401, "{}".into());
            }
            (200, sync.to_string())
        }
        _ => (404, "{}".into()),
    }
}

fn client(server: &Url, secret: &str) -> SyncClient {
    let email = load("fixture.json")["account"]["email"]
        .as_str()
        .unwrap()
        .to_owned();
    let key = ApiKey::new(CLIENT_ID, Zeroizing::new(secret.to_owned())).unwrap();
    SyncClient::new(server, &email, key, &TlsTrust::default()).unwrap()
}

fn password() -> Zeroizing<String> {
    Zeroizing::new(
        load("fixture.json")["account"]["password"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

#[tokio::test]
async fn req_cry_005_api_key_login_sync_and_decrypt_fixture() {
    let (sync, org, coll) = extended_sync();
    let state = Arc::new(Mutex::new(MockState::default()));
    let server = serve(sync, state.clone()).await;
    let mut c = client(&server, CLIENT_SECRET);
    let (session, vault) = unlock_and_sync(&mut c, &password(), Scope::new(&org, [&coll]).unwrap())
        .await
        .unwrap();

    let manifest = load("fixture.json");
    let want = manifest["items"].as_array().unwrap();
    assert_eq!(vault.len(), want.len());
    for w in want {
        let item = vault
            .items()
            .find(|i| i.name() == w["name"].as_str().unwrap())
            .expect("fixture item listed");
        assert_eq!(item.username(), w["username"].as_str());
        assert_eq!(item.uris()[0].uri, w["uri"].as_str().unwrap());
        assert!(item.has_password());
        let pw = session
            .decrypt_secret(&vault, item.id(), SecretField::Password)
            .unwrap();
        assert_eq!(&pw[..], w["password"].as_str().unwrap().as_bytes());
        assert!(matches!(
            session.decrypt_secret(&vault, item.id(), SecretField::Totp),
            Err(SyncError::FieldMissing)
        ));
    }

    // Request shapes and the §9 compatibility headers.
    let log = state.lock().unwrap().log.clone();
    let paths: Vec<_> = log.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/identity/accounts/prelogin",
            "/identity/connect/token",
            "/api/sync?excludeDomains=true"
        ]
    );
    for r in &log {
        assert_eq!(r.header("device-type"), Some("25"));
        assert_eq!(r.header("bitwarden-client-name"), Some("cli"));
        assert!(r.header("bitwarden-client-version").is_some());
    }
    let form: Vec<(String, String)> = url::form_urlencoded::parse(log[1].body.as_bytes())
        .into_owned()
        .collect();
    let get = |k: &str| form.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone());
    assert_eq!(get("grant_type").as_deref(), Some("client_credentials"));
    assert_eq!(get("scope").as_deref(), Some("api"));
    assert_eq!(get("deviceType").as_deref(), Some("25"));
    assert_eq!(get("deviceIdentifier").unwrap().len(), 36);
    assert!(log[0].body.contains("kharon-fixture@example.com"));
}

#[tokio::test]
async fn req_cry_007_out_of_scope_items_absent_and_never_decrypted() {
    let (sync, org, coll) = extended_sync();
    let state = Arc::new(Mutex::new(MockState::default()));
    let server = serve(sync, state).await;
    let mut c = client(&server, CLIENT_SECRET);
    let (session, vault) = unlock_and_sync(
        &mut c,
        &password(),
        // Upper case and a configured-but-absent collection.
        Scope::new(
            &org.to_uppercase(),
            [coll.as_str(), "99999999-0000-4000-8000-000000000000"],
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let r = vault.report();
    assert_eq!(r.kept, 2);
    assert_eq!(r.out_of_scope, 3, "other collection, other org, personal");
    assert_eq!(r.skipped, 2, "trashed and non-login");
    assert!(r.undecryptable.is_empty());
    assert_eq!(
        r.missing_collections,
        ["99999999-0000-4000-8000-000000000000"]
    );
    assert_eq!(r.other_orgs, [OTHER_ORG]);
    assert!(!r.org_key_changed);
    // Only the configured org's key was ever RSA-decrypted.
    assert_eq!(session.org_key_decrypts(), 1);

    for n in 1..=5 {
        let id = format!("aaaaaaaa-0000-4000-8000-00000000000{n}");
        assert!(vault.items().all(|i| i.id() != id));
        assert!(matches!(vault.get(&id), Err(SyncError::ItemNotFound)));
        assert!(matches!(
            session.decrypt_secret(&vault, &id, SecretField::Password),
            Err(SyncError::ItemNotFound)
        ));
    }
    assert!(matches!(
        vault.get("not-an-id"),
        Err(SyncError::ItemNotFound)
    ));
}

#[tokio::test]
async fn req_cry_007_unknown_org_fails_closed() {
    let (sync, _org, coll) = extended_sync();
    let server = serve(sync, Arc::new(Mutex::new(MockState::default()))).await;
    let mut c = client(&server, CLIENT_SECRET);
    let err = unlock_and_sync(
        &mut c,
        &password(),
        Scope::new("12345678-0000-4000-8000-000000000000", [&coll]).unwrap(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, SyncError::OrgNotVisible));
}

#[tokio::test]
async fn req_cry_005_relogin_once_on_401_and_resync_reuses_org_key() {
    let (sync, org, coll) = extended_sync();
    let state = Arc::new(Mutex::new(MockState::default()));
    let server = serve(sync, state.clone()).await;
    let mut c = client(&server, CLIENT_SECRET);
    let (mut session, _) = unlock_and_sync(&mut c, &password(), Scope::new(&org, [&coll]).unwrap())
        .await
        .unwrap();
    state.lock().unwrap().reject_sync = 1;
    let vault = resync(&mut c, &mut session).await.unwrap();
    assert_eq!(vault.len(), 2);
    assert_eq!(session.org_key_decrypts(), 1);
    assert_eq!(state.lock().unwrap().token_n, 2);
    // Two 401s in a row: one re-login only, then fail.
    state.lock().unwrap().reject_sync = 2;
    let err = resync(&mut c, &mut session).await.err().unwrap();
    assert!(matches!(err, SyncError::Status { status: 401, .. }));
    assert_eq!(state.lock().unwrap().token_n, 3);
}

#[tokio::test]
async fn req_cry_005_bad_secret_and_wrong_password_errors_carry_no_secrets() {
    let (sync, org, coll) = extended_sync();
    let server = serve(sync, Arc::new(Mutex::new(MockState::default()))).await;
    let mut c = client(&server, "wrong-secret");
    let err = unlock_and_sync(&mut c, &password(), Scope::new(&org, [&coll]).unwrap())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, SyncError::Status { status: 400, .. }));
    assert!(!format!("{err} {err:?}").contains("wrong-secret"));

    let mut c = client(&server, CLIENT_SECRET);
    let bad = Zeroizing::new("not the password".to_owned());
    let err = unlock_and_sync(&mut c, &bad, Scope::new(&org, [&coll]).unwrap())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, SyncError::Crypto(_)));
    assert!(!format!("{err} {err:?}").contains("not the password"));
}

/// Live: real Vaultwarden over HTTPS, personal API key minted by
/// `seed.py --api-key-out`. Run by `.github/workflows/fixture.yml`.
#[tokio::test]
#[ignore = "needs the live Vaultwarden fixture (fixture.yml)"]
async fn req_cry_005_live_vaultwarden_api_key_sync() {
    let base = Url::parse(&std::env::var("KHARON_FIXTURE_BASE_URL").unwrap()).unwrap();
    let ca = std::fs::read(std::env::var("KHARON_FIXTURE_CA_CERT").unwrap()).unwrap();
    let key = ApiKey::from_file(
        std::env::var("KHARON_FIXTURE_API_KEY_JSON")
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let manifest = load("fixture.json");
    let email = manifest["account"]["email"].as_str().unwrap();
    let trust = TlsTrust {
        extra_ca_pem: Some(ca),
    };
    let mut c = SyncClient::new(&base, email, key, &trust).unwrap();
    // Discover org/collection from a raw sync, then scope to them.
    let raw = c.sync().await.unwrap();
    let org = raw.profile.organizations.as_ref().unwrap()[0].id.clone();
    let coll = raw.collections.as_ref().unwrap()[0].id.clone();
    let (session, vault) = unlock_and_sync(&mut c, &password(), Scope::new(&org, [&coll]).unwrap())
        .await
        .unwrap();
    let want = manifest["items"].as_array().unwrap();
    assert_eq!(vault.len(), want.len());
    for w in want {
        let item = vault
            .items()
            .find(|i| i.name() == w["name"].as_str().unwrap())
            .unwrap();
        assert_eq!(item.username(), w["username"].as_str());
        let pw = session
            .decrypt_secret(&vault, item.id(), SecretField::Password)
            .unwrap();
        assert_eq!(&pw[..], w["password"].as_str().unwrap().as_bytes());
    }
}
