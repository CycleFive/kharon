//! Export mode loader (issue #12; SPEC §3.1a; REQ-EXP-001..005).
//!
//! In export mode kharon has no Vaultwarden account and talks to no
//! server: it loads a **password-protected encrypted** Bitwarden JSON
//! export (`bw export --format encrypted_json --password …`). The
//! envelope format, verified against the official clients (Bitwarden
//! help centre, "Encrypted Exports"): the specified password is
//! salted with the file's `salt` string, used to derive a key with
//! the file's KDF settings, and stretched with HKDF into the
//! encryption + MAC keys — i.e. the clients' derive-then-stretch path
//! with the salt string in place of the account email
//! ([`kharon_bwcrypto::derive_export_key`]). `encKeyValidation_DO_NOT_EDIT`
//! is a type-2 EncString of a GUID under that key (the password
//! check); `data` is a type-2 EncString of the plaintext export JSON.
//!
//! Two phases, matching the two moments the spec gives the loader:
//!
//! - [`ExportFile::load`] runs at startup with **no password**: it
//!   reads the file once, records its SHA-256, and classifies the
//!   envelope. Anything that is not a password-protected encrypted
//!   export — plaintext JSON, CSV, an account-restricted export
//!   (`passwordProtected` absent or false: it needs the account's
//!   user key, which export mode does not have) — is refused with
//!   [`ExportError::NotPasswordEncrypted`] before any item is looked
//!   at (REQ-EXP-002). The config loader's startup check calls it, so
//!   the refusal is a startup error. The parsed envelope is what
//!   unlock later uses: replacing the file afterwards has no effect
//!   until a restart reloads it (REQ-EXP-004, "update = replace file
//!   + restart").
//! - [`ExportFile::unlock`] runs at unlock, with the export password
//!   supplied only there (REQ-EXP-003: the config loader already
//!   refuses password-shaped config keys, and nothing here reads an
//!   environment variable). The password arrives in a
//!   [`Zeroizing<String>`] and is never copied into an un-wiped
//!   buffer; the derived key is dropped with the validation/decrypt
//!   step. A wrong password, or a tampered validation or data field,
//!   fails the MAC/decrypt check and returns
//!   [`ExportError::AuthFailed`] with **no** partial vault
//!   (REQ-EXP-005): the session is only built after every decrypt and
//!   parse has succeeded.
//!
//! Field classes (REQ-CRY-006) survive the plaintext source: the
//! decrypted export is held in a zeroizing buffer only for the
//! duration of `unlock`. Name, username and URIs are metadata and are
//! held as such; password and TOTP are immediately re-wrapped as
//! type-2 EncStrings under a fresh per-unlock symmetric key
//! ([`ExportSession`]'s wrap key, OS-random, zeroized on drop), so
//! the vault holds no plaintext secret — the same `Item` shape the
//! sync path produces. Notes and custom fields are not carried into
//! the vault in either mode today (the sync wire type does not model
//! them); if they are ever added, they must be re-wrapped the same
//! way, never stored as plaintext.
//!
//! There is deliberately no sync, refresh, or re-read API on
//! [`ExportSession`] (REQ-EXP-004): the vault is the snapshot taken
//! at unlock, and `list` cannot change under a running broker.

use std::path::{Path, PathBuf};

use kharon_bwcrypto::{EncString, Kdf, SymmetricKey, decrypt_item_field, derive_export_key};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::api::VaultView;
use crate::audit::{Entry, Event};
use crate::sync::{Item, ItemUri, SecretField, SyncError, SyncReport, Vault};

/// Why an export load or unlock was refused. Messages carry fixed
/// text and the configured file path only — never file contents,
/// item values, or the password (REQ-API-006).
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The file is not a password-protected encrypted export:
    /// plaintext JSON, CSV, account-restricted, or an envelope whose
    /// required fields are missing or not type-2 EncStrings
    /// (REQ-EXP-002).
    #[error(
        "ExportNotPasswordEncrypted: file is not a password-protected encrypted Bitwarden export"
    )]
    NotPasswordEncrypted,
    /// The password did not validate, or the decrypted payload failed
    /// validation (REQ-EXP-005). Deliberately does not distinguish a
    /// wrong password from tampering.
    #[error("ExportAuthFailed: export password validation failed")]
    AuthFailed,
    /// The export file could not be read.
    #[error("cannot read export file {path}: {kind}")]
    Read {
        /// Path that failed.
        path: PathBuf,
        /// `std::io::ErrorKind` rendering.
        kind: String,
    },
    /// The file's KDF parameters are unsupported or out of range
    /// (the same client bounds the prelogin path enforces).
    #[error("export KDF parameters are invalid: {0}")]
    Kdf(#[from] kharon_bwcrypto::KdfError),
}

impl ExportError {
    /// Stable machine-readable code. The two spec-named refusals keep
    /// the exact names their acceptance criteria use.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotPasswordEncrypted => "ExportNotPasswordEncrypted",
            Self::AuthFailed => "ExportAuthFailed",
            Self::Read { .. } => "export_read",
            Self::Kdf(_) => "export_kdf_invalid",
        }
    }
}

/// The envelope fields of a password-protected export, as the clients
/// write them. Unknown fields are ignored; every field the loader
/// needs must be present and well-formed or the file is refused as
/// [`ExportError::NotPasswordEncrypted`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEnvelope {
    encrypted: Option<bool>,
    password_protected: Option<bool>,
    salt: Option<String>,
    kdf_type: Option<u32>,
    kdf_iterations: Option<u32>,
    #[serde(default)]
    kdf_memory: Option<u32>,
    #[serde(default)]
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    validation: Option<String>,
    data: Option<String>,
}

/// The decrypted plaintext export, reduced to what the vault models.
/// Item `id` and `type` are required by the format; a login item
/// without them is a corrupt export, and the whole load fails rather
/// than partially loading (REQ-EXP-005).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaintextExport {
    #[serde(default)]
    items: Option<Vec<PlaintextItem>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaintextItem {
    id: String,
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    login: Option<PlaintextLogin>,
    #[serde(default)]
    revision_date: Option<String>,
    #[serde(default)]
    deleted_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaintextLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<PlaintextUri>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlaintextUri {
    #[serde(default)]
    uri: Option<String>,
    #[serde(default, rename = "match")]
    match_type: Option<u8>,
}

/// Bitwarden cipher type 1 (login), as in `sync::wire`.
const CIPHER_TYPE_LOGIN: u8 = 1;

/// A password-protected export file, loaded and classified at
/// startup. Holds the parsed envelope and the file's SHA-256 — not
/// the items, which stay encrypted until [`ExportFile::unlock`].
/// `Debug` prints the hash only — never envelope contents.
pub struct ExportFile {
    sha256_hex: String,
    salt: String,
    kdf: Kdf,
    validation: EncString,
    data: EncString,
}

impl std::fmt::Debug for ExportFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportFile")
            .field("sha256_hex", &self.sha256_hex)
            .finish_non_exhaustive()
    }
}

impl ExportFile {
    /// Read, hash, and classify the export file at `path`
    /// (REQ-EXP-002/004). No password is involved and no item is
    /// decrypted or parsed.
    pub fn load(path: &Path) -> Result<Self, ExportError> {
        let bytes = std::fs::read(path).map_err(|e| ExportError::Read {
            path: path.to_owned(),
            kind: e.kind().to_string(),
        })?;
        Self::from_bytes(&bytes)
    }

    /// Classify export bytes already in memory ([`ExportFile::load`]
    /// without the read). The SHA-256 is over exactly these bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ExportError> {
        let sha256_hex = hex_lower(&Sha256::digest(bytes));
        // Not JSON at all (CSV, random bytes) and JSON that is not a
        // password-protected envelope land in the same refusal: the
        // loader never sniffs a second format.
        let raw: RawEnvelope =
            serde_json::from_slice(bytes).map_err(|_| ExportError::NotPasswordEncrypted)?;
        if raw.encrypted != Some(true) || raw.password_protected != Some(true) {
            return Err(ExportError::NotPasswordEncrypted);
        }
        let (Some(salt), Some(kdf_type), Some(kdf_iterations), Some(validation), Some(data)) = (
            raw.salt,
            raw.kdf_type,
            raw.kdf_iterations,
            raw.validation,
            raw.data,
        ) else {
            return Err(ExportError::NotPasswordEncrypted);
        };
        let kdf = Kdf::from_prelogin(
            kdf_type,
            kdf_iterations,
            raw.kdf_memory,
            raw.kdf_parallelism,
        )?;
        let validation = type2(&validation)?;
        let data = type2(&data)?;
        Ok(Self {
            sha256_hex,
            salt,
            kdf,
            validation,
            data,
        })
    }

    /// Hex SHA-256 of the file as loaded (REQ-EXP-004).
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }

    /// The KDF parameters stored in the file.
    pub fn kdf(&self) -> &Kdf {
        &self.kdf
    }

    /// Unlock with the export password (REQ-EXP-001/003/005).
    ///
    /// The password is used for key derivation only and stays in the
    /// caller's zeroizing buffer. On success the returned
    /// [`ExportSession`] holds the vault snapshot and the per-unlock
    /// wrap key; on failure nothing item-shaped has been built.
    pub fn unlock(&self, password: &Zeroizing<String>) -> Result<ExportSession, ExportError> {
        let key = derive_export_key(password, &self.salt, &self.kdf)?;
        // Password check first: any failure here — MAC, padding,
        // non-UTF-8 — is AuthFailed, with no oracle detail.
        let validation = self
            .validation
            .decrypt_symmetric(&key)
            .map_err(|_| ExportError::AuthFailed)?;
        if std::str::from_utf8(&validation).is_err() {
            return Err(ExportError::AuthFailed);
        }
        drop(validation);
        let data = self
            .data
            .decrypt_symmetric(&key)
            .map_err(|_| ExportError::AuthFailed)?;
        drop(key);
        let text =
            Zeroizing::new(String::from_utf8(data.to_vec()).map_err(|_| ExportError::AuthFailed)?);
        drop(data);
        let plain: PlaintextExport =
            serde_json::from_str(&text).map_err(|_| ExportError::AuthFailed)?;
        build_session(plain, &self.sha256_hex)
    }
}

/// Parse a required envelope EncString; anything but a well-formed
/// type-2 string means the file is not the format REQ-EXP-002 names.
fn type2(s: &str) -> Result<EncString, ExportError> {
    let enc = EncString::parse(s).map_err(|_| ExportError::NotPasswordEncrypted)?;
    if enc.enc_type() != 2 {
        return Err(ExportError::NotPasswordEncrypted);
    }
    Ok(enc)
}

/// Turn a decrypted export into the session vault: metadata in the
/// clear, secrets re-wrapped under a fresh per-unlock key.
fn build_session(plain: PlaintextExport, sha256_hex: &str) -> Result<ExportSession, ExportError> {
    // The per-unlock wrap key: the export analogue of the sync path's
    // org key. Random per unlock, held only by the session, wiped on
    // drop (SymmetricKey is a Zeroizing buffer).
    let mut key_bytes = Zeroizing::new([0u8; 64]);
    rand::rngs::OsRng.fill_bytes(key_bytes.as_mut());
    let wrap_key = SymmetricKey::from_slice(&key_bytes[..])
        .expect("invariant: 64 random bytes are a valid symmetric key");
    drop(key_bytes);
    let wrap = |secret: &str| -> String {
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        EncString::encrypt_symmetric(secret.as_bytes(), &wrap_key, &iv).to_wire_string()
    };
    let nonempty = |s: Option<String>| s.filter(|s| !s.is_empty());

    let mut report = SyncReport::default();
    let mut items = Vec::new();
    for raw in plain.items.into_iter().flatten() {
        if raw.kind != CIPHER_TYPE_LOGIN || raw.deleted_date.is_some() {
            report.skipped += 1;
            continue;
        }
        // A login item without a name is a corrupt export: fail the
        // whole load rather than emit a partial vault (REQ-EXP-005).
        let name = raw.name.ok_or(ExportError::AuthFailed)?;
        let login = raw.login;
        let username = login.as_ref().and_then(|l| l.username.clone());
        let uris = login
            .as_ref()
            .and_then(|l| l.uris.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|u| {
                u.uri.as_ref().map(|uri| ItemUri {
                    uri: uri.clone(),
                    match_type: u.match_type,
                })
            })
            .collect();
        let protected_password =
            nonempty(login.as_ref().and_then(|l| l.password.clone())).map(|p| wrap(&p));
        let protected_totp =
            nonempty(login.as_ref().and_then(|l| l.totp.clone())).map(|t| wrap(&t));
        items.push(Item::from_parts(
            crate::sync::norm_id(&raw.id),
            name,
            username,
            uris,
            raw.revision_date,
            protected_password,
            protected_totp,
        ));
    }
    report.kept = items.len();
    Ok(ExportSession {
        wrap_key,
        vault: Vault::with_report(items, report),
        sha256_hex: sha256_hex.to_owned(),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An unlocked export-mode session: the vault snapshot plus the
/// per-unlock wrap key. Dropping it is the lock.
///
/// `wrap_key` wipes itself on drop ([`SymmetricKey`] is a
/// `Zeroizing` buffer); `vault` holds only metadata and re-wrapped
/// ciphertext (REQ-CRY-006), which is not key material — the same
/// split [`crate::sync::LiveSync`] documents.
pub struct ExportSession {
    wrap_key: SymmetricKey,
    vault: Vault,
    sha256_hex: String,
}

impl ZeroizeOnDrop for ExportSession {}

impl std::fmt::Debug for ExportSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportSession")
            .field("items", &self.vault.len())
            .field("sha256_hex", &self.sha256_hex)
            .finish_non_exhaustive()
    }
}

impl ExportSession {
    /// The item snapshot taken at unlock. It never changes: there is
    /// no sync in export mode (REQ-EXP-004).
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Hex SHA-256 of the export file this session was loaded from.
    pub fn file_sha256(&self) -> &str {
        &self.sha256_hex
    }

    /// The audit entry for this load (REQ-EXP-004): `export_loaded`
    /// with the file's SHA-256. The unlock path appends it through
    /// its audit sink (REQ-AUD-003 fail-closed applies as usual).
    pub fn audit_entry(&self) -> Entry {
        Entry::new(Event::ExportLoaded).file_sha256(self.sha256_hex.clone())
    }

    /// Decrypt one secret field of an item for a fill — per fill
    /// only, into a zeroizing buffer, mirroring
    /// [`crate::sync::Session::decrypt_secret`] with the wrap key in
    /// place of the org key (export items have no cipher key).
    pub fn decrypt_secret(
        &self,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        let item = self.vault.get(item_id)?;
        let protected = match field {
            SecretField::Password => item.protected_password(),
            SecretField::Totp => item.protected_totp(),
        }
        .ok_or(SyncError::FieldMissing)?;
        let enc = EncString::parse(protected).map_err(SyncError::Crypto)?;
        decrypt_item_field(&enc, &self.wrap_key, None).map_err(SyncError::Crypto)
    }
}

impl VaultView for ExportSession {
    fn vault(&self) -> &Vault {
        ExportSession::vault(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/export/password_protected.json");
    const PASSWORD: &str = "kharon export fixture password 9";
    const CANARY_PASSWORD: &str = "CANARY-EXPORT-PASSWORD-7f3a";

    fn load() -> ExportFile {
        ExportFile::from_bytes(FIXTURE.as_bytes()).unwrap()
    }

    fn password() -> Zeroizing<String> {
        Zeroizing::new(PASSWORD.to_string())
    }

    #[test]
    fn req_exp_001_fixture_unlocks_and_secrets_are_rewrapped() {
        let session = load().unlock(&password()).unwrap();
        assert_eq!(session.vault().len(), 2);
        // The stored form decrypts through the wrap key (so it is an
        // EncString, not the plaintext), and yields the canary.
        let item = session
            .vault()
            .items()
            .find(|i| i.name() == "Example Login")
            .unwrap();
        let pt = session
            .decrypt_secret(item.id(), SecretField::Password)
            .unwrap();
        assert_eq!(&pt[..], CANARY_PASSWORD.as_bytes());
        // The vault's Debug surface (id only, per `Item`) carries no
        // plaintext secret.
        assert!(!format!("{:?}", session.vault()).contains(CANARY_PASSWORD));
    }

    #[test]
    fn req_exp_005_wrong_password_is_auth_failed() {
        let wrong = Zeroizing::new("not the export password".to_string());
        assert!(matches!(
            load().unlock(&wrong),
            Err(ExportError::AuthFailed)
        ));
    }
}
