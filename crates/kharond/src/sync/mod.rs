//! Identity/sync client and collection filter (issue #8; SPEC §3.1,
//! §9 "Compatibility"; REQ-CRY-005, REQ-CRY-007).
//!
//! Flow: [`SyncClient::prelogin`] → [`SyncClient::sync`] (which logs in
//! with the personal API key) → [`Session::unlock`] with the owner's
//! master password → [`Session::apply_sync`] for the scoped
//! [`Vault`]. Re-syncs reuse the session: `client.sync()` then
//! `session.apply_sync()`, so the org key is never unwrapped again
//! (REQ-CRY-011).

mod client;
mod live;
mod vault;
pub mod wire;

pub use client::{
    ApiKey, CLIENT_NAME, CLIENT_VERSION, DEVICE_NAME, DEVICE_TYPE, Endpoints, MAX_RESPONSE_BYTES,
    SyncClient, TlsTrust, device_identifier,
};
pub use live::{
    LiveSync, LockReason, MAX_SYNC_INTERVAL, ScopeViolation, SyncOutcome, SyncPolicy,
    check_dedicated_scope, preflight, run, scope_violation,
};
pub use vault::{Item, ItemUri, Scope, SecretField, Session, SyncReport, Vault};

use kharon_bwcrypto::{EncError, KdfError};
use zeroize::Zeroizing;

/// Sync errors. Messages carry endpoint names, status codes and fixed
/// text only: never response bodies, field values or key material
/// (REQ-API-006).
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("server URL must be http(s) with a host")]
    InvalidServerUrl,
    #[error("TLS setup: {0}")]
    Tls(&'static str),
    #[error("API key: {0}")]
    ApiKey(&'static str),
    #[error("transport error on {0}")]
    Transport(&'static str),
    #[error("{endpoint} returned HTTP {status}")]
    Status { endpoint: &'static str, status: u16 },
    #[error("{0} response too large")]
    TooLarge(&'static str),
    #[error("malformed {0} response")]
    Malformed(&'static str),
    #[error("KDF: {0}")]
    Kdf(#[from] KdfError),
    #[error("crypto: {0}")]
    Crypto(EncError),
    #[error("sync profile is for a different account than the configured email")]
    AccountMismatch,
    #[error("configured organization is not visible to the account")]
    OrgNotVisible,
    /// REQ-CRY-008: the account sees more than the configured org.
    #[error(
        "ScopeTooBroad: account sees {other_orgs} other organization(s) and {outside_items} item(s) outside organization_id"
    )]
    ScopeTooBroad {
        other_orgs: usize,
        outside_items: usize,
    },
    #[error("organization_id and collection_ids must be non-empty")]
    EmptyScope,
    #[error("item not found")]
    ItemNotFound,
    #[error("item has no such field")]
    FieldMissing,
}

/// Unlock: prelogin, API-key login, sync, derive keys, filter.
pub async fn unlock_and_sync(
    client: &mut SyncClient,
    password: &Zeroizing<String>,
    scope: Scope,
) -> Result<(Session, Vault), SyncError> {
    let kdf = client.prelogin().await?;
    let sync = client.sync().await?;
    let email = client.email().to_owned();
    let mut session = Session::unlock(password, &email, &kdf, &sync, scope)?;
    let vault = session.apply_sync(&sync)?;
    Ok((session, vault))
}

/// Re-sync within an unlocked session.
pub async fn resync(client: &mut SyncClient, session: &mut Session) -> Result<Vault, SyncError> {
    let sync = client.sync().await?;
    session.apply_sync(&sync)
}
