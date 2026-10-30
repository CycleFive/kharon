//! Signed checkpoints and the sink through which they leave the host
//! (REQ-AUD-002).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use super::keys::AuditKeys;

/// `{seq, hash, log_id}` of the log head, signed with the audit Ed25519 key
/// over the JCS canonicalization of that triple. `log_id` binds the
/// checkpoint to one deployment: a checkpoint from another log sharing the
/// same key can never satisfy truncation detection here.
///
/// The checkpoint stream lives off-host; truncation of the local log is
/// detected by comparing the local head against the highest signed
/// checkpoint (REQ-AUD-002).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub seq: u64,
    pub hash: String,
    /// Instance id of the log this checkpoint attests (entry `log_id`).
    pub log_id: String,
    /// Hex-encoded Ed25519 signature over `JCS({seq, hash, log_id})`.
    pub sig: String,
}

impl Checkpoint {
    pub fn new(seq: u64, hash: String, keys: &AuditKeys) -> Self {
        let sig = keys.sign(&payload_jcs(seq, &hash, keys.log_id()));
        Self {
            seq,
            hash,
            log_id: keys.log_id().to_string(),
            sig: hex::encode(sig.to_bytes()),
        }
    }

    pub fn verify_signature(&self, vk: &VerifyingKey) -> bool {
        let Ok(bytes) = hex::decode(&self.sig) else {
            return false;
        };
        let Ok(sig) = Signature::try_from(bytes.as_slice()) else {
            return false;
        };
        vk.verify(&payload_jcs(self.seq, &self.hash, &self.log_id), &sig)
            .is_ok()
    }
}

fn payload_jcs(seq: u64, hash: &str, log_id: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct Payload<'a> {
        seq: u64,
        hash: &'a str,
        log_id: &'a str,
    }
    serde_jcs::to_vec(&Payload { seq, hash, log_id })
        .expect("JCS of a u64 and two strings cannot fail")
}

#[cfg(test)]
impl Checkpoint {
    /// Sign a checkpoint for an explicit (possibly foreign) `log_id`, to test
    /// cross-deployment replay rejection.
    pub(crate) fn new_with_log_id(seq: u64, hash: String, log_id: &str, keys: &AuditKeys) -> Self {
        let sig = keys.sign(&payload_jcs(seq, &hash, log_id));
        Self {
            seq,
            hash,
            log_id: log_id.to_string(),
            sig: hex::encode(sig.to_bytes()),
        }
    }
}

/// Where checkpoints go. Production pushes to ntfy or remote syslog
/// (deployment wiring is a later milestone); tests and dev runs use
/// [`FileCheckpointSink`].
pub trait CheckpointSink {
    fn push(&mut self, cp: &Checkpoint) -> io::Result<()>;
}

/// Discards checkpoints. Only for tests that do not exercise truncation
/// detection, and for deployments that explicitly accept the risk.
pub struct NullCheckpointSink;

impl CheckpointSink for NullCheckpointSink {
    fn push(&mut self, _cp: &Checkpoint) -> io::Result<()> {
        Ok(())
    }
}

/// Appends checkpoints as JSONL to a file — the stand-in for "off-host" in
/// tests and single-host deployments.
pub struct FileCheckpointSink {
    file: File,
}

impl FileCheckpointSink {
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }
}

impl CheckpointSink for FileCheckpointSink {
    fn push(&mut self, cp: &Checkpoint) -> io::Result<()> {
        let line = serde_json::to_string(cp)?;
        writeln!(self.file, "{line}")?;
        self.file.sync_all()
    }
}
