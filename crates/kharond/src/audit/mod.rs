//! Append-only, hash-chained audit log (REQ-AUD-001..004).
//!
//! # Log format
//!
//! `<dir>/audit.jsonl` holds one JSON object per line, JCS-canonicalized
//! (RFC 8785 via `serde_jcs`). Line shape:
//!
//! ```json
//! {"seq":1,"ts":"2026-10-30T12:00:00.000000000Z","prev_hash":"0000…0","hash":"abcd…","event":"unlock","agent_id":"…","…}
//! ```
//!
//! * `prev_hash` — hex SHA-256 of the previous line's `Entry` (genesis: 64 zeros).
//! * `hash` — hex SHA-256 over `prev_hash` (as UTF-8 hex bytes) concatenated with
//!   the JCS serialization of the entry *without* the `hash` field. Every line
//!   carries its own hash, so any edited byte is reported at that entry's seq.
//! * Optional fields are omitted, never null.
//!
//! Because the hash binds both the entry contents and the chain predecessor,
//! editing entry `k` is detected at `k` (stored hash mismatch), and deletion or
//! substitution is detected no later than `k+1` (link mismatch). The tail after
//! the last checkpoint is covered by the signed off-host checkpoint stream
//! (REQ-AUD-002).
//!
//! # Item names
//!
//! Per REQ-AUD-004, `item_name` passed to [`Entry`] is never written verbatim:
//! the log stores `item_name_hash` = HMAC-SHA256 under `audit_name_key`, unless
//! [`AuditConfig::plaintext_item_names`] is explicitly enabled.
//!
//! # Fail-closed behavior (REQ-AUD-003)
//!
//! [`AuditLog::append`] is synchronous: the entry is written with `O_APPEND`
//! and `fsync`ed before it returns. Any I/O error is returned to the caller,
//! which must fail the operation it was about to acknowledge — the daemon must
//! not perform a CDP write for a request whose audit entry did not reach disk.

mod checkpoint;
mod entry;
mod keys;
mod log;
mod verify;

pub use checkpoint::{Checkpoint, CheckpointSink, FileCheckpointSink, NullCheckpointSink};
pub use entry::{Entry, Event, GENESIS_PREV_HASH};
pub use keys::{AuditKeys, KeysError};
pub use log::{
    AppendError, AuditConfig, AuditLog, DEFAULT_CHECKPOINT_EVERY, DEFAULT_CHECKPOINT_PERIOD,
    OpenError,
};
pub use verify::{VerifyError, VerifyOutcome, verify};
