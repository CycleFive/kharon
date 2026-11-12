//! Persisted owner passkeys (REQ-APR-005).
//!
//! `<data_dir>/owner/passkeys.json`, mode 0600. The file holds the
//! credential id, the uncompressed P-256 public point, the signature
//! counter, and (since #258) when the passkey was enrolled and last
//! used. Those two timestamps are optional: a file written before
//! they existed still loads. It never holds a private key, a session
//! cookie, or an enrollment token.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::webauthn::{self, P256_POINT_LEN};

/// Hex length of the owner-facing passkey id: the first characters of
/// the credential fingerprint (#258). Stable, so a listed id still
/// names the same passkey after a restart.
pub(crate) const PASSKEY_SHORT_ID_LEN: usize = 8;

/// One registered passkey.
pub(crate) struct Credential {
    pub id: Vec<u8>,
    pub public_key: [u8; P256_POINT_LEN],
    pub sign_count: u32,
    /// Unix seconds when this passkey was stored. `None` on a store
    /// written before #258 recorded it.
    pub enrolled_at: Option<i64>,
    /// Unix seconds of the last successful assertion. `None` until one
    /// has been recorded.
    pub last_used_at: Option<i64>,
}

/// The 32-hex credential fingerprint (#249): SHA-256 of the raw id.
pub(crate) fn fingerprint(credential_id: &[u8]) -> String {
    crate::api::revocation::truncated_sha256_hex(credential_id)
}

/// The short id an owner types: the first [`PASSKEY_SHORT_ID_LEN`]
/// lowercase hex chars of [`fingerprint`].
pub(crate) fn short_id(credential_id: &[u8]) -> String {
    fingerprint(credential_id)[..PASSKEY_SHORT_ID_LEN].to_owned()
}

/// `true` when `id` is exactly one short id (lowercase hex, fixed length).
pub(crate) fn valid_short_id(id: &str) -> bool {
    id.len() == PASSKEY_SHORT_ID_LEN && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The on-disk passkey set for this daemon.
pub(crate) struct PasskeyStore {
    path: PathBuf,
    user_handle: Vec<u8>,
    credentials: Vec<Credential>,
}

#[derive(Serialize, Deserialize)]
struct File {
    user_handle: String,
    credentials: Vec<FileCred>,
}

#[derive(Serialize, Deserialize)]
struct FileCred {
    id: String,
    public_key: String,
    sign_count: u32,
    /// Absent on a store written before #258. Omitted again when still unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enrolled_at: Option<i64>,
    /// Absent until a successful assertion has been recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_used_at: Option<i64>,
}

impl PasskeyStore {
    /// Load the store, or an empty one when the file is absent.
    /// A group- or world-writable file is refused.
    pub(crate) fn load(data_dir: &Path) -> io::Result<Self> {
        let path = data_dir.join("owner").join("passkeys.json");
        if !path.exists() {
            return Ok(Self {
                path,
                user_handle: random_handle(),
                credentials: Vec::new(),
            });
        }
        check_mode(&path)?;
        let text = std::fs::read_to_string(&path)?;
        let file: File = serde_json::from_str(&text).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("passkey store: {e}"))
        })?;
        let user_handle = webauthn::b64url_decode(&file.user_handle).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "passkey store: user handle")
        })?;
        if user_handle.is_empty() || user_handle.len() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "passkey store: user handle",
            ));
        }
        let mut credentials = Vec::with_capacity(file.credentials.len());
        for c in file.credentials {
            let id = webauthn::b64url_decode(&c.id)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "passkey store: id"))?;
            let pk = webauthn::b64url_decode(&c.public_key).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "passkey store: public key")
            })?;
            if pk.len() != P256_POINT_LEN || pk[0] != 0x04 || id.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "passkey store: public key",
                ));
            }
            let mut public_key = [0u8; P256_POINT_LEN];
            public_key.copy_from_slice(&pk);
            credentials.push(Credential {
                id,
                public_key,
                sign_count: c.sign_count,
                enrolled_at: c.enrolled_at,
                last_used_at: c.last_used_at,
            });
        }
        Ok(Self {
            path,
            user_handle,
            credentials,
        })
    }

    pub(crate) fn user_handle(&self) -> &[u8] {
        &self.user_handle
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub(crate) fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    pub(crate) fn insert(&mut self, cred: Credential) -> io::Result<()> {
        if self.credentials.iter().any(|c| c.id == cred.id) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "duplicate credential",
            ));
        }
        self.credentials.push(cred);
        if let Err(e) = self.persist() {
            // The audit entry, when there is one, was written against
            // a store that does not hold this id. Drop the in-memory
            // copy so a failed write cannot sign in.
            self.credentials.pop();
            return Err(e);
        }
        Ok(())
    }

    /// Record a signature counter and last-used after a verified
    /// assertion. Unknown ids are an error and write nothing.
    pub(crate) fn set_sign_count(&mut self, id: &[u8], sign_count: u32) -> io::Result<()> {
        let Some(cred) = self.credentials.iter_mut().find(|c| c.id == id) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no credential"));
        };
        let previous_count = cred.sign_count;
        let previous_used = cred.last_used_at;
        cred.sign_count = sign_count;
        cred.last_used_at = Some(unix_now());
        if let Err(e) = self.persist() {
            if let Some(cred) = self.credentials.iter_mut().find(|c| c.id == id) {
                cred.sign_count = previous_count;
                cred.last_used_at = previous_used;
            }
            return Err(e);
        }
        Ok(())
    }

    /// Drop the credential with this raw id and persist. A failed
    /// write puts the credential back, so the memory copy cannot
    /// disagree with the file.
    pub(crate) fn remove(&mut self, id: &[u8]) -> io::Result<()> {
        let Some(index) = self.credentials.iter().position(|c| c.id == id) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no credential"));
        };
        let removed = self.credentials.remove(index);
        if let Err(e) = self.persist() {
            self.credentials.insert(index, removed);
            return Err(e);
        }
        Ok(())
    }

    fn persist(&mut self) -> io::Result<()> {
        let file = File {
            user_handle: webauthn::b64url_encode(&self.user_handle),
            credentials: self
                .credentials
                .iter()
                .map(|c| FileCred {
                    id: webauthn::b64url_encode(&c.id),
                    public_key: webauthn::b64url_encode(&c.public_key),
                    sign_count: c.sign_count,
                    enrolled_at: c.enrolled_at,
                    last_used_at: c.last_used_at,
                })
                .collect(),
        };
        let text = serde_json::to_string(&file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_private(&self.path, text.as_bytes())?;
        Ok(())
    }
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn random_handle() -> Vec<u8> {
    let mut b = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}

fn check_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "passkey store is group- or world-writable",
        ));
    }
    Ok(())
}

/// Write `bytes` to `path` as mode 0600, replacing any previous file.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
        b.create(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point() -> [u8; P256_POINT_LEN] {
        let mut pk = [0u8; P256_POINT_LEN];
        pk[0] = 0x04;
        pk[1] = 0x11;
        pk
    }

    /// #258: a store file from before `enrolled_at` / `last_used_at`
    /// existed still loads, and a later assertion records last-used
    /// without inventing an enrolled-at.
    #[test]
    fn old_store_file_loads_and_gains_last_used() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id = webauthn::b64url_encode(&[0xab; 16]);
        let pk = webauthn::b64url_encode(&point());
        let handle = webauthn::b64url_encode(&[0x22; 32]);
        let path = dir.path().join("owner");
        std::fs::create_dir_all(&path).unwrap();
        let file = path.join("passkeys.json");
        std::fs::write(
            &file,
            format!(
                r#"{{"user_handle":"{handle}","credentials":[{{"id":"{id}","public_key":"{pk}","sign_count":0}}]}}"#
            ),
        )
        .unwrap();
        // `write` follows the umask. A 0660 file (umask 007) is refused
        // as group-writable, so pin the mode the store requires.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut store = PasskeyStore::load(dir.path()).unwrap();
        assert_eq!(store.credentials().len(), 1);
        assert!(store.credentials()[0].enrolled_at.is_none());
        assert!(store.credentials()[0].last_used_at.is_none());
        let raw_id = store.credentials()[0].id.clone();
        store.set_sign_count(&raw_id, 1).unwrap();
        assert_eq!(store.credentials()[0].sign_count, 1);
        assert!(store.credentials()[0].last_used_at.is_some());
        assert!(store.credentials()[0].enrolled_at.is_none());

        let again = PasskeyStore::load(dir.path()).unwrap();
        assert_eq!(again.credentials()[0].sign_count, 1);
        assert_eq!(
            again.credentials()[0].last_used_at,
            store.credentials()[0].last_used_at
        );
        assert!(again.credentials()[0].enrolled_at.is_none());
        let text = std::fs::read_to_string(path.join("passkeys.json")).unwrap();
        assert!(!text.contains("enrolled_at"), "{text}");
        assert!(text.contains("last_used_at"), "{text}");
    }

    #[test]
    fn short_id_is_a_stable_prefix_of_the_fingerprint() {
        let id = [0x11u8; 16];
        let fp = fingerprint(&id);
        assert_eq!(fp.len(), 32);
        assert_eq!(short_id(&id), &fp[..PASSKEY_SHORT_ID_LEN]);
        assert_eq!(short_id(&id), short_id(&id));
        assert_ne!(short_id(&id), short_id(&[0x22; 16]));
        assert!(valid_short_id(&short_id(&id)));
        assert!(!valid_short_id(&fp));
        assert!(!valid_short_id("ABCDEF12"));
        assert!(!valid_short_id("abc"));
    }
}
