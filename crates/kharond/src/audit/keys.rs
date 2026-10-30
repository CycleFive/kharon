//! Audit key material: the item-name HMAC key, the Ed25519 checkpoint
//! signing key (REQ-AUD-004: separate keys, never logged, 0600 on disk), and
//! the random log instance id that binds checkpoints to this deployment.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum KeysError {
    #[error("key io error: {0}")]
    Io(#[from] io::Error),
    #[error("key file {0} has length {1}, want {2}")]
    BadLength(std::path::PathBuf, usize, usize),
    #[error("log id file {0} has length {1}, want {2}")]
    BadLogIdLength(std::path::PathBuf, usize, usize),
}

type HmacSha256 = Hmac<Sha256>;

/// Keys live in `<dir>/audit_name_key` (32 random bytes), `audit_sign_key`
/// (32-byte Ed25519 seed), `audit_sign.pub` (32-byte verify key), and
/// `audit_log_id` (16 random bytes, hex). Generated on first use with mode
/// 0600; the public key may be world-readable and is the only key a verifier
/// needs.
pub struct AuditKeys {
    name_key: [u8; 32],
    sign_key: SigningKey,
    log_id: String,
}

impl AuditKeys {
    pub fn load_or_generate(dir: &Path) -> Result<Self, KeysError> {
        fs::create_dir_all(dir)?;
        let name_path = dir.join("audit_name_key");
        let sign_path = dir.join("audit_sign_key");
        let pub_path = dir.join("audit_sign.pub");
        let log_id_path = dir.join("audit_log_id");

        let name_key: [u8; 32] = match fs::read(&name_path) {
            Ok(bytes) => bytes
                .try_into()
                .map_err(|b: Vec<u8>| KeysError::BadLength(name_path.clone(), b.len(), 32))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut key = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
                write_mode(&name_path, &key, 0o600)?;
                key
            }
            Err(e) => return Err(e.into()),
        };

        let sign_key: SigningKey = match fs::read(&sign_path) {
            Ok(bytes) => {
                let seed: [u8; 32] = bytes
                    .try_into()
                    .map_err(|b: Vec<u8>| KeysError::BadLength(sign_path.clone(), b.len(), 32))?;
                SigningKey::from_bytes(&seed)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
                write_mode(&sign_path, &seed, 0o600)?;
                SigningKey::from_bytes(&seed)
            }
            Err(e) => return Err(e.into()),
        };

        // Self-heal the pub key: if the private key was regenerated (lost key
        // file) the stale pub must not silently stay, or verification would
        // use the wrong key. The derived key is authoritative.
        let derived_pub = sign_key.verifying_key().to_bytes();
        match fs::read(&pub_path) {
            Ok(bytes) if bytes == derived_pub => {}
            _ => write_mode(&pub_path, &derived_pub, 0o644)?,
        }

        let log_id: String = match fs::read(&log_id_path) {
            Ok(bytes) => {
                let s = String::from_utf8_lossy(&bytes).into_owned();
                let trimmed = s.trim().to_string();
                if trimmed.len() != 32 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(KeysError::BadLogIdLength(
                        log_id_path.clone(),
                        trimmed.len(),
                        32,
                    ));
                }
                trimmed
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut id = [0u8; 16];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
                let id = hex::encode(id);
                write_mode(&log_id_path, id.as_bytes(), 0o600)?;
                id
            }
            Err(e) => return Err(e.into()),
        };

        Ok(Self {
            name_key,
            sign_key,
            log_id,
        })
    }

    /// HMAC-SHA256 of an item name, hex-encoded (REQ-AUD-004).
    pub fn hash_name(&self, name: &str) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.name_key)
            .expect("HMAC-SHA256 accepts keys of any length");
        mac.update(name.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.sign_key.sign(msg)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.sign_key.verifying_key()
    }

    /// Random instance id, generated once per deployment. Written on every
    /// entry and signed into every checkpoint so neither can be replayed
    /// against a different deployment that shares a key.
    pub fn log_id(&self) -> &str {
        &self.log_id
    }
}

/// Write via a same-directory temp file + rename so a crash never leaves a
/// truncated key file. A stale temp from a previous crash is removed first;
/// otherwise its presence would make `create_new` fail forever.
fn write_mode(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    // Best-effort cleanup of a temp left by a crash; any real problem
    // surfaces as the create_new error below.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {}
    }
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut f = opts.open(&tmp)?;
        io::Write::write_all(&mut f, bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
