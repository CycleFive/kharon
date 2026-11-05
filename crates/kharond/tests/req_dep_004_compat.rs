//! Official Bitwarden cloud compatibility (REQ-DEP-004 / REQ-CRY-005).
//!
//! Live half only: personal API-key login against a cloud test account,
//! then decrypt at least one scoped collection login. Run by
//! `.github/workflows/compat.yml` after `mint_api_key.py` writes the
//! API-key JSON from `BW_COMPAT_EMAIL` / `BW_COMPAT_PASSWORD`.
//!
//! Env (set by the workflow):
//! - `KHARON_COMPAT_BASE_URL` — default `https://vault.bitwarden.com`
//! - `KHARON_COMPAT_EMAIL`
//! - `KHARON_COMPAT_PASSWORD`
//! - `KHARON_COMPAT_API_KEY_JSON` — path from mint_api_key.py
//! - optional `KHARON_COMPAT_ORG_ID` / `KHARON_COMPAT_COLLECTION_ID`
//!   to pin scope; otherwise the first org + first collection of that
//!   org from sync are used.

use kharond::sync::{ApiKey, Scope, SecretField, SyncClient, TlsTrust, unlock_and_sync};
use url::Url;
use zeroize::Zeroizing;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the compat live test"))
}

/// REQ-DEP-004: cloud account passes REQ-CRY-005 (API-key sync + decrypt).
#[tokio::test]
#[ignore = "needs Bitwarden cloud secrets (compat.yml)"]
async fn req_dep_004_live_bitwarden_cloud_api_key_sync_decrypts() {
    let base = Url::parse(
        &std::env::var("KHARON_COMPAT_BASE_URL")
            .unwrap_or_else(|_| "https://vault.bitwarden.com".into()),
    )
    .unwrap();
    let email = env("KHARON_COMPAT_EMAIL");
    let password = Zeroizing::new(env("KHARON_COMPAT_PASSWORD"));
    let key = ApiKey::from_file(env("KHARON_COMPAT_API_KEY_JSON").as_ref()).unwrap();

    let mut client = SyncClient::new(&base, &email, key, &TlsTrust { extra_ca_pem: None }).unwrap();
    let raw = client.sync().await.expect("GET /api/sync (REQ-CRY-005)");

    let orgs = raw.profile.organizations.as_deref().unwrap_or(&[]);
    assert!(
        !orgs.is_empty(),
        "cloud test account has no organizations; kharon scopes to a dedicated org collection \
         (REQ-CRY-007). Create one org + collection with at least one login item."
    );

    let org = std::env::var("KHARON_COMPAT_ORG_ID").unwrap_or_else(|_| orgs[0].id.clone());
    let collections = raw.collections.as_deref().unwrap_or(&[]);
    let coll = std::env::var("KHARON_COMPAT_COLLECTION_ID").unwrap_or_else(|_| {
        collections
            .iter()
            .find(|c| c.organization_id.as_deref() == Some(org.as_str()))
            .map(|c| c.id.clone())
            .unwrap_or_else(|| {
                panic!(
                    "no collection for org {org}; set KHARON_COMPAT_COLLECTION_ID or seed the account"
                )
            })
    });

    let (session, vault) =
        unlock_and_sync(&mut client, &password, Scope::new(&org, [&coll]).unwrap())
            .await
            .expect("unlock_and_sync against Bitwarden cloud");

    assert!(
        !vault.is_empty(),
        "scoped vault is empty for org={org} collection={coll}; add a login item to that collection"
    );

    let mut decrypted = 0usize;
    for item in vault.items() {
        if !item.has_password() {
            continue;
        }
        let pw = session
            .decrypt_secret(&vault, item.id(), SecretField::Password)
            .expect("decrypt password (REQ-CRY-005)");
        assert!(
            !pw.is_empty(),
            "password plaintext empty for item {}",
            item.id()
        );
        decrypted += 1;
    }
    assert!(
        decrypted > 0,
        "no login with a password field in the scoped collection"
    );
    eprintln!(
        "EXERCISED req_dep_004: sync ok, decrypted {decrypted} password(s) in org={org} collection={coll}"
    );
}
