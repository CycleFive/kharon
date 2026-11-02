//! Wire types for the three endpoints the sync client uses (SPEC §9
//! "Compatibility"): prelogin, the OAuth token endpoint, and
//! `/api/sync`.
//!
//! Vaultwarden 1.3x and current Bitwarden cloud send camelCase JSON;
//! older servers sent PascalCase (`Key`, `PrivateKey`, `Organizations`).
//! [`normalize_keys`] lowercases the first letter of every object key
//! before typed deserialization, so both spellings land on the same
//! fields. Everything here is ciphertext or public metadata; secret
//! fields stay as EncString text until a fill asks for them
//! (REQ-CRY-006).

use serde::Deserialize;
use serde_json::Value;

/// Lowercase the first character of every object key, recursively.
pub(crate) fn normalize_keys(v: Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    let mut chars = k.chars();
                    let k = match chars.next() {
                        Some(c) => c.to_lowercase().chain(chars).collect(),
                        None => k,
                    };
                    (k, normalize_keys(v))
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(normalize_keys).collect()),
        other => other,
    }
}

/// `POST /identity/accounts/prelogin` response.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf: u32,
    pub kdf_iterations: u32,
    #[serde(default)]
    pub kdf_memory: Option<u32>,
    #[serde(default)]
    pub kdf_parallelism: Option<u32>,
}

/// `POST /identity/connect/token` response (OAuth: snake_case keys).
/// The vault-key fields the token response may carry are ignored:
/// unlock uses the ones in `/api/sync`'s profile, so there is one
/// source for them.
#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub token_type: Option<String>,
}

/// `GET /api/sync` response, reduced to what kharon reads.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    #[serde(default)]
    pub collections: Option<Vec<Collection>>,
    #[serde(default)]
    pub ciphers: Option<Vec<Cipher>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub email: String,
    /// Protected user key (EncString type 2 under the stretched master key).
    pub key: Option<String>,
    /// Protected RSA private key (EncString type 2 under the user key).
    pub private_key: Option<String>,
    #[serde(default)]
    pub organizations: Option<Vec<ProfileOrganization>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileOrganization {
    pub id: String,
    /// Protected org key (EncString type 4 under the user's public key).
    pub key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: String,
    pub organization_id: Option<String>,
}

/// Bitwarden cipher type 1.
pub const CIPHER_TYPE_LOGIN: u8 = 1;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: u8,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub collection_ids: Option<Vec<String>>,
    pub name: Option<String>,
    /// Optional per-cipher key (EncString type 2 under the org key).
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub login: Option<Login>,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub uris: Option<Vec<LoginUri>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginUri {
    #[serde(default)]
    pub uri: Option<String>,
    /// Bitwarden URI match type (0 domain, 1 host, 2 starts with,
    /// 3 exact, 4 regex, 5 never); `None` = account default.
    #[serde(default, rename = "match")]
    pub match_type: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_cry_005_pascal_and_camel_case_parse_alike() {
        let pascal = serde_json::json!({
            "Profile": {"Id": "u", "Email": "a@b", "Key": "k", "PrivateKey": "p",
                        "Organizations": [{"Id": "o", "Key": "4.x"}]},
            "Ciphers": [{"Id": "c", "Type": 1, "OrganizationId": "o", "CollectionIds": ["x"],
                         "Name": "n", "Login": {"Uris": [{"Uri": "u", "Match": null}]}}]
        });
        let s: SyncResponse = serde_json::from_value(normalize_keys(pascal)).unwrap();
        assert_eq!(s.profile.private_key.as_deref(), Some("p"));
        assert_eq!(s.profile.organizations.unwrap()[0].id, "o");
        let c = &s.ciphers.unwrap()[0];
        assert_eq!(c.collection_ids.as_deref(), Some(&["x".to_owned()][..]));
        assert!(c.login.as_ref().unwrap().uris.is_some());
    }
}
