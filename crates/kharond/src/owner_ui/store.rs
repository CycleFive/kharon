//! Persisted owner passkeys (REQ-APR-005).
//!
//! `<data_dir>/owner/passkeys.json`, mode 0600. The file holds the
//! credential id, the uncompressed P-256 public point, and the
//! signature counter. It never holds a private key, a session
//! cookie, or an enrollment token.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::webauthn::{self, P256_POINT_LEN};

/// One registered passkey.
pub(crate) struct Credential {
    pub id: Vec<u8>,
    pub public_key: [u8; P256_POINT_LEN],
    pub sign_count: u32,
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

    /// Record a signature counter after a verified assertion.
    /// Unknown ids are an error and write nothing.
    pub(crate) fn set_sign_count(&mut self, id: &[u8], sign_count: u32) -> io::Result<()> {
        let Some(cred) = self.credentials.iter_mut().find(|c| c.id == id) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no credential"));
        };
        let previous = cred.sign_count;
        cred.sign_count = sign_count;
        if let Err(e) = self.persist() {
            if let Some(cred) = self.credentials.iter_mut().find(|c| c.id == id) {
                cred.sign_count = previous;
            }
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
                })
                .collect(),
        };
        let text = serde_json::to_string(&file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_private(&self.path, text.as_bytes())?;
        Ok(())
    }
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
