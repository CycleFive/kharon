//! Offline verifier for the hash-chained audit log + off-host checkpoint
//! stream (REQ-AUD-001, REQ-AUD-002).

use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::Path;

use super::checkpoint::Checkpoint;
use super::entry::{Entry, GENESIS_PREV_HASH};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("line {0}: invalid JSON: {1}")]
    Json(usize, String),
    /// Recomputed hash of the entry (over its contents and prev_hash) does not
    /// match the hash stored in the line. The seq is the edited entry's own.
    #[error("entry seq {0}: recomputed hash does not match stored hash")]
    BadHash(u64),
    /// The entry's prev_hash does not match the stored hash of its predecessor.
    #[error("entry seq {0}: prev_hash does not match previous entry's hash")]
    BadLink(u64),
    /// Seq is not exactly `position + 1` — an entry was deleted or reordered.
    #[error("expected entry seq {0}")]
    BadSeq(u64),
    /// An entry's `log_id` differs from entry 1's. The per-entry hash would
    /// catch an edit, but this also catches a wholesale swap of the log file
    /// for another's — the rest of such a chain would otherwise verify clean.
    #[error("entry seq {0}: log_id differs from entry 1")]
    LogIdMismatch(u64),
}

/// Result of a successful structural scan plus the checkpoint-stream check.
/// Distinct from [`VerifyError`]: corruption of the chain is an error,
/// problems visible in the checkpoint stream are findings.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Chain intact, every checkpoint ≤ head matches, none beyond head.
    Ok { head_seq: u64 },
    /// Local log ends below a signed checkpoint's seq: entries were deleted
    /// from the tail after that checkpoint left the host.
    Truncated {
        local_head: u64,
        checkpoint_seq: u64,
    },
    /// A checkpoint's hash does not match the recomputed chain hash at its seq.
    CheckpointMismatch { seq: u64 },
    /// A checkpoint does not verify under the audit public key.
    CheckpointBadSig { seq: u64 },
    /// A well-signed checkpoint whose `log_id` belongs to a different
    /// deployment — replayed across logs that share a key.
    CheckpointWrongLog { seq: u64 },
}

impl fmt::Display for VerifyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyOutcome::Ok { head_seq } => write!(f, "audit log OK, head seq {head_seq}"),
            VerifyOutcome::Truncated {
                local_head,
                checkpoint_seq,
            } => write!(
                f,
                "truncated after local seq {local_head}: signed checkpoint exists for seq {checkpoint_seq}"
            ),
            VerifyOutcome::CheckpointMismatch { seq } => {
                write!(f, "checkpoint at seq {seq} does not match the log")
            }
            VerifyOutcome::CheckpointBadSig { seq } => {
                write!(f, "checkpoint at seq {seq} has an invalid signature")
            }
            VerifyOutcome::CheckpointWrongLog { seq } => {
                write!(f, "checkpoint at seq {seq} belongs to a different log")
            }
        }
    }
}

pub(crate) struct Chain {
    /// Recomputed/stored hash per entry, index `seq - 1`.
    hashes: Vec<String>,
    /// Instance id from entry 1 (`None` for an empty log). Checkpoints must
    /// match it: a checkpoint from another deployment sharing the signing key
    /// must never satisfy truncation detection here.
    log_id: Option<String>,
}

impl Chain {
    pub(crate) fn len(&self) -> usize {
        self.hashes.len()
    }

    pub(crate) fn head_hash(&self) -> Option<String> {
        self.hashes.last().cloned()
    }
}
/// Scan and verify the local chain: parse every line, recompute each hash
/// (self-consistency) and check the link to the previous line.
pub(crate) fn read_chain(path: &Path) -> Result<Chain, VerifyError> {
    let data = fs::read_to_string(path)?;
    let mut hashes: Vec<String> = Vec::new();
    let mut log_id: Option<String> = None;
    for (i, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_no = i + 1;
        let mut value: Value =
            serde_json::from_str(line).map_err(|e| VerifyError::Json(line_no, e.to_string()))?;
        let obj = value
            .as_object_mut()
            .ok_or_else(|| VerifyError::Json(line_no, "line is not a JSON object".into()))?;
        let hash = obj
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| VerifyError::Json(line_no, "missing string field `hash`".into()))?
            .to_string();
        obj.remove("hash");
        let entry: Entry =
            serde_json::from_value(value).map_err(|e| VerifyError::Json(line_no, e.to_string()))?;

        let expect_seq = hashes.len() as u64 + 1;
        if entry.seq != expect_seq {
            return Err(VerifyError::BadSeq(expect_seq));
        }
        if expect_seq == 1 {
            log_id = Some(entry.log_id.clone());
        } else if Some(&entry.log_id) != log_id.as_ref() {
            return Err(VerifyError::LogIdMismatch(entry.seq));
        }
        match hashes.last() {
            Some(prev) => {
                if entry.prev_hash != *prev {
                    return Err(VerifyError::BadLink(entry.seq));
                }
            }
            None => {
                if entry.prev_hash != GENESIS_PREV_HASH {
                    return Err(VerifyError::BadLink(1));
                }
            }
        }

        let entry_jcs =
            serde_jcs::to_vec(&entry).map_err(|e| VerifyError::Json(line_no, e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(entry.prev_hash.as_bytes());
        hasher.update(&entry_jcs);
        let recomputed = hex::encode(hasher.finalize());
        if recomputed != hash {
            return Err(VerifyError::BadHash(entry.seq));
        }
        hashes.push(hash);
    }
    Ok(Chain { hashes, log_id })
}

/// Verify `log_path` against the checkpoint stream from the off-host sink.
///
/// * Structural corruption (any edited byte, deleted/reordered entry) →
///   [`VerifyError`] naming the first bad seq.
/// * Tail deletion after a checkpoint left the host →
///   [`VerifyOutcome::Truncated`].
/// * Forged or mismatched checkpoints → [`VerifyOutcome::CheckpointBadSig`] /
///   [`VerifyOutcome::CheckpointMismatch`].
pub fn verify(
    log_path: &Path,
    checkpoints: &[Checkpoint],
    verify_key: &VerifyingKey,
) -> Result<VerifyOutcome, VerifyError> {
    let chain = read_chain(log_path)?;
    let head = chain.len() as u64;

    for cp in checkpoints {
        if !cp.verify_signature(verify_key) {
            return Ok(VerifyOutcome::CheckpointBadSig { seq: cp.seq });
        }
        if let Some(id) = &chain.log_id
            && cp.log_id != *id
        {
            return Ok(VerifyOutcome::CheckpointWrongLog { seq: cp.seq });
        }
        if cp.seq > head {
            return Ok(VerifyOutcome::Truncated {
                local_head: head,
                checkpoint_seq: cp.seq,
            });
        }
        if chain.hashes[cp.seq as usize - 1] != cp.hash {
            return Ok(VerifyOutcome::CheckpointMismatch { seq: cp.seq });
        }
    }
    Ok(VerifyOutcome::Ok { head_seq: head })
}

#[cfg(test)]
mod tests {
    use super::super::log::AuditConfig;
    use super::super::{
        AuditLog, Checkpoint, Entry, Event, FileCheckpointSink, NullCheckpointSink,
    };
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn open(dir: &std::path::Path) -> AuditLog {
        AuditLog::open(dir, AuditConfig::default(), Box::new(NullCheckpointSink)).unwrap()
    }

    /// The verify key, without going through `AuditLog::open` — opening a
    /// *tampered* log must (and does) fail closed, and these tests tamper on
    /// purpose.
    fn vk_of(
        dir: &std::path::Path,
    ) -> (crate::audit::keys::AuditKeys, ed25519_dalek::VerifyingKey) {
        let keys = crate::audit::keys::AuditKeys::load_or_generate(&dir.join("keys")).unwrap();
        let vk = keys.verifying_key();
        (keys, vk)
    }

    /// Fail-closed startup: a tampered log cannot be opened for append.
    fn assert_open_fails_closed(dir: &std::path::Path) {
        let err = AuditLog::open(dir, AuditConfig::default(), Box::new(NullCheckpointSink))
            .expect_err("open of a corrupt log must fail closed");
        assert!(
            matches!(err, super::super::OpenError::Corrupt(_)),
            "got {err}"
        );
    }

    fn append_n(log: &mut AuditLog, n: u64) {
        for i in 0..n {
            log.append(Entry::new(Event::Fill).agent_id(format!("agent-{i}")))
                .unwrap();
        }
    }

    fn read_cps(path: &Path) -> Vec<Checkpoint> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn req_aud_001_clean_log_verifies() {
        let dir = tempdir();
        let mut log = open(dir.path());
        append_n(&mut log, 50);
        let vk = log.keys().verifying_key();
        let outcome = verify(&dir.path().join("audit.jsonl"), &[], &vk).unwrap();
        assert_eq!(outcome, VerifyOutcome::Ok { head_seq: 50 });
    }

    #[test]
    fn req_aud_001_edit_any_byte_reports_first_bad_seq() {
        for edited in [1usize, 7, 20] {
            let dir = tempdir();
            let mut log = open(dir.path());
            append_n(&mut log, 20);
            drop(log);
            let path = dir.path().join("audit.jsonl");
            let mut lines: Vec<String> = std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .map(String::from)
                .collect();
            let line = &mut lines[edited - 1];
            // Flip one byte inside the JSON, keeping it valid.
            let pos = line.find("agent-").map(|p| p + 2).unwrap();
            let mut bytes = line.clone().into_bytes();
            bytes[pos] = if bytes[pos] == b'a' { b'b' } else { b'a' };
            *line = String::from_utf8(bytes).unwrap();
            std::fs::write(&path, lines.join("\n") + "\n").unwrap();

            let (_keys, vk) = vk_of(dir.path());
            let err = verify(&path, &[], &vk).unwrap_err();
            assert!(
                matches!(err, VerifyError::BadHash(seq) if seq == edited as u64),
                "edit at line {edited}: got {err}"
            );
            assert_open_fails_closed(dir.path());
        }
    }

    #[test]
    fn req_aud_001_edit_prev_hash_reports_bad_link() {
        let dir = tempdir();
        let mut log = open(dir.path());
        append_n(&mut log, 10);
        drop(log);
        let path = dir.path().join("audit.jsonl");
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        let line = &mut lines[4];
        let pos = line.find("\"prev_hash\":\"").unwrap() + 14;
        let mut bytes = line.clone().into_bytes();
        bytes[pos] = if bytes[pos] == b'0' { b'1' } else { b'0' };
        *line = String::from_utf8(bytes).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let (_keys, vk) = vk_of(dir.path());
        let err = verify(&path, &[], &vk).unwrap_err();
        assert!(
            matches!(err, VerifyError::BadLink(5)),
            "prev_hash edit breaks the link to entry 4's stored hash: got {err}"
        );
        assert_open_fails_closed(dir.path());
    }

    #[test]
    fn req_aud_001_delete_entry_reports_bad_seq() {
        let dir = tempdir();
        let mut log = open(dir.path());
        append_n(&mut log, 10);
        drop(log);
        let path = dir.path().join("audit.jsonl");
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        lines.remove(4); // delete entry seq 5
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let (_keys, vk) = vk_of(dir.path());
        let err = verify(&path, &[], &vk).unwrap_err();
        assert!(
            matches!(err, VerifyError::BadSeq(5)),
            "deletion reported at the gap: got {err}"
        );
        assert_open_fails_closed(dir.path());
    }

    #[test]
    fn req_aud_001_empty_log_verifies() {
        let dir = tempdir();
        let log = open(dir.path());
        let vk = log.keys().verifying_key();
        let outcome = verify(&dir.path().join("audit.jsonl"), &[], &vk).unwrap();
        assert_eq!(outcome, VerifyOutcome::Ok { head_seq: 0 });
    }

    #[test]
    fn req_aud_002_signed_checkpoints_verify_and_detect_truncation() {
        let dir = tempdir();
        let cp_path = dir.path().join("checkpoints.jsonl");
        let cfg = AuditConfig {
            checkpoint_every: 100,
            ..AuditConfig::default()
        };
        let mut log = AuditLog::open(
            dir.path(),
            cfg,
            Box::new(FileCheckpointSink::create(&cp_path).unwrap()),
        )
        .unwrap();
        append_n(&mut log, 350);
        drop(log);

        let cps = read_cps(&cp_path);
        assert_eq!(cps.len(), 3);
        let log = open(dir.path());
        let vk = log.keys().verifying_key();
        let outcome = verify(&dir.path().join("audit.jsonl"), &cps, &vk).unwrap();
        assert_eq!(outcome, VerifyOutcome::Ok { head_seq: 350 });

        // Attacker deletes the last 150 entries: head drops to 200 while a
        // signed checkpoint for seq 300 is already off-host.
        let path = dir.path().join("audit.jsonl");
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        lines.truncate(200);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let outcome = verify(&path, &cps, &vk).unwrap();
        assert_eq!(
            outcome,
            VerifyOutcome::Truncated {
                local_head: 200,
                checkpoint_seq: 300
            },
            "{outcome}"
        );
        assert!(outcome.to_string().contains("truncated"));
    }

    #[test]
    fn req_aud_002_forged_checkpoint_detected() {
        let dir = tempdir();
        let cp_path = dir.path().join("checkpoints.jsonl");
        let cfg = AuditConfig {
            checkpoint_every: 2,
            ..AuditConfig::default()
        };
        let mut log = AuditLog::open(
            dir.path(),
            cfg,
            Box::new(FileCheckpointSink::create(&cp_path).unwrap()),
        )
        .unwrap();
        append_n(&mut log, 4);
        let vk = log.keys().verifying_key();
        drop(log);

        let mut cps = read_cps(&cp_path);
        assert_eq!(cps.len(), 2);
        let bad_sig = cps[0].sig.clone();
        let mut chars: Vec<char> = bad_sig.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        cps[0].sig = chars.into_iter().collect();
        let outcome = verify(&dir.path().join("audit.jsonl"), &cps, &vk).unwrap();
        assert_eq!(outcome, VerifyOutcome::CheckpointBadSig { seq: 2 });
    }

    #[test]
    fn req_aud_001_whole_log_swap_detected_by_log_id_consistency() {
        let dir = tempdir();
        let mut log = open(dir.path());
        append_n(&mut log, 3);
        drop(log);
        let path = dir.path().join("audit.jsonl");

        // Rewrite entry 2 with a *different* log_id and recompute its hash so
        // the per-entry hash check passes. Only the cross-entry consistency
        // check can catch this.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        lines[1].as_object_mut().unwrap().remove("hash");
        lines[1]["log_id"] = Value::String("e".repeat(32));
        let prev_hash = lines[0]["hash"].as_str().unwrap();
        let entry_jcs = serde_jcs::to_vec(&lines[1]).unwrap();
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest as _;
        hasher.update(prev_hash.as_bytes());
        hasher.update(&entry_jcs);
        lines[1]["hash"] = Value::String(hex::encode(hasher.finalize()));
        std::fs::write(
            &path,
            lines
                .iter()
                .map(|v| serde_json::to_string(v).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();

        let (_keys, vk) = vk_of(dir.path());
        let err = verify(&path, &[], &vk).unwrap_err();
        assert!(matches!(err, VerifyError::LogIdMismatch(2)), "got {err}");
        assert_open_fails_closed(dir.path());
    }

    #[test]
    fn req_aud_002_checkpoint_from_another_log_rejected() {
        let dir = tempdir();
        let mut log = open(dir.path());
        append_n(&mut log, 4);
        let keys =
            crate::audit::keys::AuditKeys::load_or_generate(&dir.path().join("keys")).unwrap();
        let vk = keys.verifying_key();
        let path = dir.path().join("audit.jsonl");

        // Same signing key, same hash — but a checkpoint signed for a
        // different deployment's log_id. Valid signature, foreign instance.
        let text = std::fs::read_to_string(&path).unwrap();
        let hash4 = serde_json::from_str::<Value>(text.lines().nth(3).unwrap()).unwrap()["hash"]
            .as_str()
            .unwrap()
            .to_string();
        let foreign = Checkpoint::new_with_log_id(4, hash4, "f".repeat(32).as_str(), &keys);
        let outcome = verify(&path, &[foreign], &vk).unwrap();
        assert_eq!(outcome, VerifyOutcome::CheckpointWrongLog { seq: 4 });
    }

    #[test]
    fn req_aud_002_mismatched_checkpoint_detected_with_valid_sig() {
        let dir = tempdir();
        let cp_path = dir.path().join("checkpoints.jsonl");
        let mut log = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(FileCheckpointSink::create(&cp_path).unwrap()),
        )
        .unwrap();
        append_n(&mut log, 150); // one checkpoint at seq 100
        drop(log);

        // The off-host copy of checkpoint 100 is replaced by a *validly signed*
        // checkpoint for seq 100 whose hash is actually the seq-99 hash.
        let cps = read_cps(&cp_path);
        assert_eq!(cps.len(), 1);
        let log = open(dir.path());
        let keys = log.keys();
        let vk = keys.verifying_key();

        // Build a checkpoint signed by the real key, but whose `hash` field is
        // actually the hash of seq 99. Signature is valid; content is wrong.
        let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let line99 = text.lines().nth(98).unwrap();
        let v99: Value = serde_json::from_str(line99).unwrap();
        let wrong_hash = v99["hash"].as_str().unwrap().to_string();
        let cp = Checkpoint::new(100, wrong_hash, keys);
        let outcome = verify(&dir.path().join("audit.jsonl"), &[cp], &vk).unwrap();
        assert_eq!(outcome, VerifyOutcome::CheckpointMismatch { seq: 100 });
    }
}
