//! The audit log writer.

use fs2::FileExt;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::checkpoint::{Checkpoint, CheckpointSink};
use super::entry::{Entry, Event, GENESIS_PREV_HASH};
use super::keys::{AuditKeys, KeysError};
use super::verify::{self, TAIL_KEEP, VerifyError};

/// Default: checkpoint after this many entries (spec §7, N=100).
pub const DEFAULT_CHECKPOINT_EVERY: u64 = 100;
/// Default: checkpoint at least this often, even with fewer entries (spec §7).
pub const DEFAULT_CHECKPOINT_PERIOD: Duration = Duration::from_secs(600);

#[derive(Clone, Debug)]
pub struct AuditConfig {
    /// REQ-AUD-004: store item names in cleartext. Off by default.
    pub plaintext_item_names: bool,
    pub checkpoint_every: u64,
    pub checkpoint_period: Duration,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            plaintext_item_names: false,
            checkpoint_every: DEFAULT_CHECKPOINT_EVERY,
            checkpoint_period: DEFAULT_CHECKPOINT_PERIOD,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Keys(#[from] KeysError),
    #[error("existing audit log is corrupt at seq {0}")]
    Corrupt(u64),
    #[error("existing audit log has invalid JSON at line {0}: {1}")]
    Json(usize, String),
    /// Another live process holds the audit log lock. Two writers on one log
    /// would interleave lines and fork the chain, so this is refused.
    #[error("audit log is locked by another process")]
    Locked,
    /// Writing the torn-write recovery record failed.
    #[error("recovery append failed: {0}")]
    Recovery(#[from] AppendError),
}

#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    #[error("audit write failed (fail closed): {0}")]
    Io(#[from] io::Error),
    /// A previous append failed mid-write; this handle is poisoned and refuses
    /// further appends until the log is reopened (and the torn tail, if any,
    /// has been truncated). Guarantees we never append seq N twice with
    /// different contents after a partial write.
    #[error("audit log is poisoned by a previous failed append; reopen it")]
    Poisoned,
}

/// Writable plus a durability barrier. `append` requires that a line is
/// durable before it returns (REQ-AUD-003); `Write::flush` on a `File` is a
/// no-op (std files are unbuffered), so syncing is a separate operation.
/// `File` implements it with `fdatasync` — append-only data, enough metadata
/// to retrieve the file after a crash. Test doubles can fail either half
/// independently.
pub(crate) trait AuditWriter: Write + Send {
    fn sync(&mut self) -> io::Result<()>;
}

impl AuditWriter for File {
    fn sync(&mut self) -> io::Result<()> {
        self.sync_data()
    }
}

/// Append-only, hash-chained audit log. See the [module docs](self) for the
/// exact line format and chaining rule.
pub struct AuditLog {
    writer: Box<dyn AuditWriter>,
    keys: AuditKeys,
    config: AuditConfig,
    sink: Box<dyn CheckpointSink>,
    head_seq: u64,
    head_hash: String,
    since_checkpoint: u64,
    last_checkpoint_at: OffsetDateTime,
    poisoned: bool,
    /// The last [`TAIL_KEEP`] durable entries, oldest first, as written
    /// (item names already hashed unless plaintext mode is on). Seeded
    /// from the verified chain at open; the owner web UI's audit tail
    /// reads it (#131 slice 4) so a view never re-reads the file.
    recent: VecDeque<Entry>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("head_seq", &self.head_seq)
            .field("poisoned", &self.poisoned)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Open (or create) the log in `dir`. An existing log is re-verified
    /// before use; corruption is an error, not a warning — the daemon must
    /// not keep appending to a broken chain.
    ///
    /// Crash recovery: a trailing line without its terminating `\n` is a torn
    /// (partially acknowledged) write. It is truncated and the recovery is
    /// itself recorded as the new head entry (`Event::LogTruncated`), so the
    /// fact of the crash is auditable. A complete last line is valid even if
    /// the writer crashed before returning — it stays.
    ///
    /// Single writer: an exclusive `flock` is taken for the life of the
    /// handle; a second opener gets [`OpenError::Locked`].
    pub fn open(
        dir: &Path,
        config: AuditConfig,
        sink: Box<dyn CheckpointSink>,
    ) -> Result<Self, OpenError> {
        let keys = AuditKeys::load_or_generate(&dir.join("keys"))?;
        let path = dir.join("audit.jsonl");
        let file = open_append(&path)?;
        file.try_lock_exclusive().map_err(|_| OpenError::Locked)?;
        // Torn-tail recovery (see doc comment): a trailing line without its
        // terminating `\n` is a torn (partially acknowledged) write. It is
        // truncated *before* the chain is verified, and the recovery is itself
        // recorded as the new head entry (`Event::LogTruncated`) so the fact
        // of the crash is auditable. A complete last line is valid even if the
        // writer crashed before returning — it stays.
        let mut torn_tail = false;
        let bytes = fs::read(&path)?;
        if !bytes.is_empty() && *bytes.last().unwrap() != b'\n' {
            let keep = bytes
                .iter()
                .rposition(|&b| b == b'\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            file.set_len(keep as u64)?;
            torn_tail = true;
        }

        let mut chain = verify::read_chain(&path).map_err(|e| match e {
            VerifyError::Io(e) => OpenError::Io(e),
            VerifyError::Json(line, msg) => OpenError::Json(line, msg),
            VerifyError::BadHash(seq)
            | VerifyError::BadLink(seq)
            | VerifyError::BadSeq(seq)
            | VerifyError::LogIdMismatch(seq) => OpenError::Corrupt(seq),
        })?;

        let head_seq = chain.len() as u64;
        let torn_recovered = torn_tail.then_some(head_seq);
        let head_hash = chain
            .head_hash()
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        let recent = chain.take_tail();
        let mut log = Self {
            writer: Box::new(file),
            keys,
            config,
            sink,
            head_seq,
            head_hash,
            since_checkpoint: 0,
            last_checkpoint_at: OffsetDateTime::now_utc(),
            poisoned: false,
            recent,
        };
        if let Some(recovered_seq) = torn_recovered {
            log.append(Entry::new(Event::LogTruncated).recovered_seq(recovered_seq))?;
        }
        Ok(log)
    }

    /// Append one entry. Synchronous: the line is durable (fdatasync) before
    /// this returns. Any error must fail the caller's operation (REQ-AUD-
    /// 003), and any write error poisons this handle: the head may be a torn
    /// prefix on disk, so no further append is attempted until a reopen
    /// truncates and recovers (a transient EIO/ENOSPC must not brick the log
    /// by writing seq N twice).
    pub fn append(&mut self, mut entry: Entry) -> Result<(), AppendError> {
        if self.poisoned {
            return Err(AppendError::Poisoned);
        }
        let now = OffsetDateTime::now_utc();
        entry.seq = self.head_seq + 1;
        entry.ts = now
            .format(&Rfc3339)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        entry.prev_hash = self.head_hash.clone();
        entry.log_id = self.keys.log_id().to_string();
        if let Some(name) = entry.item_name.take() {
            if self.config.plaintext_item_names {
                entry.item_name = Some(name);
            } else {
                entry.item_name_hash = Some(self.keys.hash_name(&name));
            }
        }

        let entry_jcs =
            serde_jcs::to_vec(&entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut hasher = Sha256::new();
        hasher.update(entry.prev_hash.as_bytes());
        hasher.update(&entry_jcs);
        let hash = hex::encode(hasher.finalize());

        let mut line = serde_json::to_value(&entry)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line["hash"] = serde_json::Value::String(hash.clone());
        let mut line = serde_jcs::to_string(&line)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        if let Err(e) = self
            .writer
            .write_all(line.as_bytes())
            .and_then(|()| self.writer.sync())
        {
            self.poisoned = true;
            return Err(e.into());
        }

        self.head_seq += 1;
        self.head_hash = hash;
        if self.recent.len() == TAIL_KEEP {
            self.recent.pop_front();
        }
        self.recent.push_back(entry);
        self.since_checkpoint += 1;
        if self.since_checkpoint >= self.config.checkpoint_every
            || now - self.last_checkpoint_at >= self.config.checkpoint_period
        {
            self.emit_checkpoint();
        }
        Ok(())
    }

    /// Emit a signed checkpoint of the current head. A sink failure is
    /// deliberately not fatal to the append that triggered it: the entry is
    /// already durable locally; a dead off-host sink is a deployment problem
    /// to alarm on, not a reason to keep accepting fills unaudited upstream.
    /// The cadence counters are only reset on a *successful* push, so the
    /// next append retries instead of silently skipping a checkpoint window.
    /// Returns whether a checkpoint was delivered.
    fn emit_checkpoint(&mut self) -> bool {
        if self.head_seq == 0 || self.since_checkpoint == 0 {
            return false;
        }
        let cp = Checkpoint::new(self.head_seq, self.head_hash.clone(), &self.keys);
        if self.sink.push(&cp).is_ok() {
            self.since_checkpoint = 0;
            self.last_checkpoint_at = OffsetDateTime::now_utc();
            true
        } else {
            false
        }
    }

    /// The 10-minute leg of REQ-AUD-002 (#127): emit a checkpoint if
    /// the configured period has elapsed since the last delivered one
    /// and entries appended since then are still unanchored. Called by
    /// the daemon's timer task, so a quiet broker — no appends to piggy
    /// back on — still anchors its tail within roughly one period.
    /// Returns whether a checkpoint was delivered.
    pub fn checkpoint_if_due(&mut self) -> bool {
        if self.since_checkpoint == 0
            || OffsetDateTime::now_utc() - self.last_checkpoint_at < self.config.checkpoint_period
        {
            return false;
        }
        self.emit_checkpoint()
    }

    /// Emit a checkpoint of the current head right now, if any entry
    /// is unanchored — the shutdown/lock anchor (#127). A no-op when
    /// the head is already checkpointed. Returns whether a checkpoint
    /// was delivered.
    pub fn checkpoint_now(&mut self) -> bool {
        self.emit_checkpoint()
    }

    pub fn head_seq(&self) -> u64 {
        self.head_seq
    }

    pub fn keys(&self) -> &AuditKeys {
        &self.keys
    }

    /// The last `n` durable entries (at most [`TAIL_KEEP`]), newest
    /// first. Only entries whose append returned `Ok` are here: a failed
    /// or poisoned append never shows (REQ-AUD-003).
    pub fn tail(&self, n: usize) -> Vec<Entry> {
        self.recent.iter().rev().take(n).cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        writer: impl AuditWriter + 'static,
        keys: AuditKeys,
        config: AuditConfig,
        sink: Box<dyn CheckpointSink>,
    ) -> Self {
        Self {
            writer: Box::new(writer),
            keys,
            config,
            sink,
            head_seq: 0,
            head_hash: GENESIS_PREV_HASH.to_string(),
            since_checkpoint: 0,
            last_checkpoint_at: OffsetDateTime::now_utc(),
            poisoned: false,
            recent: VecDeque::new(),
        }
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Test-only: [`AuditLog::open`], waiting out a transient `Locked`
/// (#162). A test that drops a log and reopens it can see `Locked` when
/// another test thread in the same binary forks a child in between (the
/// `node` harnesses in `cdp::page_js`): the child shares the open file
/// description, and so the `flock`, until it execs. Any other error, or
/// `Locked` that lasts 5 s, is returned as is.
#[cfg(test)]
pub(crate) fn open_retrying(
    dir: &Path,
    config: AuditConfig,
    sink: impl Fn() -> Box<dyn CheckpointSink>,
) -> Result<AuditLog, OpenError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match AuditLog::open(dir, config.clone(), sink()) {
            Err(OpenError::Locked) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{NullCheckpointSink, verify::VerifyOutcome};

    fn canary() -> &'static str {
        "CANARY_9f2c7a51d48e66b33c01aa90ee1d4c17"
    }

    /// A writer that accepts a few bytes, then fails: simulates a partial
    /// write followed by an error (disk full, EIO).
    struct ShortThenFail {
        budget: usize,
        calls: usize,
    }

    impl Write for ShortThenFail {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                let n = self.budget.min(buf.len());
                Ok(n)
            } else {
                Err(io::Error::other("simulated write failure"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl AuditWriter for ShortThenFail {
        fn sync(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Writes succeed; the durability barrier fails (e.g. fdatasync returns
    /// EIO after the data reached the page cache).
    struct SyncFails;

    impl Write for SyncFails {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl AuditWriter for SyncFails {
        fn sync(&mut self) -> io::Result<()> {
            Err(io::Error::other("simulated fdatasync failure"))
        }
    }

    #[test]
    fn append_sync_error_poisons_handle() {
        let dir = tempfile::tempdir().unwrap();
        let keys = AuditKeys::load_or_generate(&dir.path().join("keys")).unwrap();
        let mut log = AuditLog::open_for_test(
            SyncFails,
            keys,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        );
        let err = log
            .append(Entry::new(Event::Fill))
            .expect_err("a failed sync must fail the append");
        assert!(matches!(err, AppendError::Io(_)), "got {err}");
        assert_eq!(log.head_seq(), 0, "head must not advance on sync failure");
        let err = log
            .append(Entry::new(Event::Fill))
            .expect_err("poisoned handle must refuse further appends");
        assert!(matches!(err, AppendError::Poisoned), "got {err}");
    }

    #[test]
    fn append_write_error_poisons_handle() {
        let dir = tempfile::tempdir().unwrap();
        let keys = AuditKeys::load_or_generate(&dir.path().join("keys")).unwrap();
        let mut log = AuditLog::open_for_test(
            ShortThenFail {
                budget: 7,
                calls: 0,
            },
            keys,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        );
        let err = log
            .append(Entry::new(Event::Fill))
            .expect_err("short write must fail the append");
        assert!(matches!(err, AppendError::Io(_)), "got {err}");
        assert_eq!(log.head_seq(), 0, "head must not advance on failure");
        let err = log
            .append(Entry::new(Event::Fill))
            .expect_err("poisoned handle must refuse further appends");
        assert!(matches!(err, AppendError::Poisoned), "got {err}");
    }

    #[test]
    fn open_truncates_torn_tail_and_records_recovery() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = AuditLog::open(
                dir.path(),
                AuditConfig::default(),
                Box::new(NullCheckpointSink),
            )
            .unwrap();
            for _ in 0..5 {
                log.append(Entry::new(Event::List).agent_id("a")).unwrap();
            }
        }
        // Simulate a crash mid-line: append half a JSON object, no newline.
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new()
                .append(true)
                .open(dir.path().join("audit.jsonl"))
                .unwrap();
            f.write_all(b"{\"seq\":6,\"ts\":\"").unwrap();
        }
        let log = open_retrying(dir.path(), AuditConfig::default(), || {
            Box::new(NullCheckpointSink)
        })
        .expect("open must recover a torn tail");
        assert_eq!(log.head_seq(), 6, "5 entries + the recovery record");
        drop(log);

        let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(text.ends_with('\n'), "tail must be terminated");
        let last: serde_json::Value = text.lines().last().unwrap().parse().unwrap();
        assert_eq!(last["event"], "log_truncated");
        assert_eq!(last["recovered_seq"].as_u64().unwrap(), 5);
        let (_keys, vk) = {
            let keys =
                crate::audit::keys::AuditKeys::load_or_generate(&dir.path().join("keys")).unwrap();
            let vk = keys.verifying_key();
            (keys, vk)
        };
        let outcome = verify::verify(&dir.path().join("audit.jsonl"), &[], &vk)
            .expect("recovered chain verifies");
        assert!(
            matches!(outcome, VerifyOutcome::Ok { .. }),
            "got {outcome:?}"
        );
    }

    #[test]
    fn open_refuses_second_writer() {
        let dir = tempfile::tempdir().unwrap();
        let _first = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        let err = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .expect_err("second writer must be refused");
        assert!(matches!(err, OpenError::Locked), "got {err}");
    }

    #[test]
    fn req_aud_003_write_failure_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        // A directory at the log path cannot be opened for append, even as
        // root — a deterministic write failure.
        std::fs::create_dir(dir.path().join("audit.jsonl")).unwrap();
        let err = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .expect_err("open must fail closed");
        assert!(matches!(err, OpenError::Io(_)), "got {err}");
    }

    #[test]
    fn req_aud_003_append_error_surfaces_and_advances_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let keys = AuditKeys::load_or_generate(&dir.path().join("keys")).unwrap();
        // A File opened on a directory is read-only: writes fail for any uid.
        let bad = File::open(dir.path()).unwrap();
        let mut log = AuditLog::open_for_test(
            bad,
            keys,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        );
        let err = log
            .append(Entry::new(Event::Fill))
            .expect_err("append must fail closed");
        assert!(matches!(err, AppendError::Io(_)), "got {err}");
        assert_eq!(log.head_seq(), 0);
        // And the handle is now poisoned.
        let err = log
            .append(Entry::new(Event::Fill))
            .expect_err("must stay poisoned");
        assert!(matches!(err, AppendError::Poisoned), "got {err}");
    }

    #[test]
    fn req_aud_004_canary_absent_from_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        log.append(
            Entry::new(Event::Fill)
                .agent_id("agent-1")
                .item_name(canary())
                .result("filled"),
        )
        .unwrap();
        drop(log);
        let bytes = std::fs::read(dir.path().join("audit.jsonl")).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(canary()), "canary leaked into log: {text}");
        // The field is present with a 64-hex-char HMAC value.
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        let hash = line["item_name_hash"].as_str().unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            line.get("item_name").is_none(),
            "hash mode must not set item_name"
        );
    }

    #[test]
    fn req_aud_004_name_hash_stable_across_reopen_and_distinct_from_other_dir() {
        let dir = tempfile::tempdir().unwrap();
        let h1 = {
            let log = AuditLog::open(
                dir.path(),
                AuditConfig::default(),
                Box::new(NullCheckpointSink),
            )
            .unwrap();
            log.keys().hash_name("github.com")
        };
        let log2 = open_retrying(dir.path(), AuditConfig::default(), || {
            Box::new(NullCheckpointSink)
        })
        .unwrap();
        assert_eq!(h1, log2.keys().hash_name("github.com"));

        let other = tempfile::tempdir().unwrap();
        let log3 = AuditLog::open(
            other.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        assert_ne!(h1, log3.keys().hash_name("github.com"));
    }

    #[test]
    fn req_aud_004_plaintext_mode_writes_separate_name_field() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = AuditConfig {
            plaintext_item_names: true,
            ..AuditConfig::default()
        };
        let mut log = AuditLog::open(dir.path(), cfg, Box::new(NullCheckpointSink)).unwrap();
        log.append(Entry::new(Event::Fill).item_name(canary()))
            .unwrap();
        drop(log);
        let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(text.contains(canary()));
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(line["item_name"].as_str().unwrap(), canary());
        assert!(
            line.get("item_name_hash").is_none(),
            "plaintext mode must not set item_name_hash"
        );
    }

    #[test]
    fn unknown_event_name_is_deserialize_error() {
        let json = r#"{"seq":1,"ts":"2026-10-30T00:00:00Z","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","log_id":"abc","event":"definitely_not_an_event"}"#;
        let err = serde_json::from_str::<Entry>(json).expect_err("unknown event must not parse");
        assert!(err.to_string().contains("definitely_not_an_event"), "{err}");
    }

    /// #162: a reopen right after a drop can find the `flock` held by a
    /// forked child (another test thread's `node` spawn) until it execs.
    /// A second descriptor holding the lock stands in for that child.
    #[test]
    fn open_retrying_waits_out_a_briefly_held_lock() {
        let dir = tempfile::tempdir().unwrap();
        drop(
            AuditLog::open(
                dir.path(),
                AuditConfig::default(),
                Box::new(NullCheckpointSink),
            )
            .unwrap(),
        );
        let holder = File::open(dir.path().join("audit.jsonl")).unwrap();
        holder.lock_exclusive().unwrap();
        let plain = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        );
        assert!(
            matches!(plain, Err(OpenError::Locked)),
            "a held lock refuses a plain open"
        );
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(holder);
        });
        let log = open_retrying(dir.path(), AuditConfig::default(), || {
            Box::new(NullCheckpointSink)
        })
        .expect("opens once the holder lets go");
        release.join().unwrap();
        assert_eq!(log.head_seq(), 0, "the same empty log, reopened");
    }

    #[test]
    fn keys_pub_self_heals_to_match_signing_key() {
        let dir = tempfile::tempdir().unwrap();
        let _log = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        let pub_path = dir.path().join("keys").join("audit_sign.pub");
        std::fs::write(&pub_path, [0xAAu8; 32]).unwrap();
        drop(_log);
        let log = open_retrying(dir.path(), AuditConfig::default(), || {
            Box::new(NullCheckpointSink)
        })
        .unwrap();
        let on_disk = std::fs::read(&pub_path).unwrap();
        assert_eq!(on_disk, log.keys().verifying_key().to_bytes());
    }

    #[test]
    fn keys_stale_temp_file_does_not_brick_load() {
        let dir = tempfile::tempdir().unwrap();
        let _log = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        // A crash between temp creation and rename leaves this behind; the
        // next load must clean it instead of failing on create_new forever.
        std::fs::write(
            dir.path().join("keys").join("audit_sign_key.tmp"),
            b"garbage",
        )
        .unwrap();
        drop(_log);
        let _log2 = open_retrying(dir.path(), AuditConfig::default(), || {
            Box::new(NullCheckpointSink)
        })
        .unwrap();
    }

    #[test]
    fn every_entry_carries_log_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        let id = log.keys().log_id().to_string();
        log.append(Entry::new(Event::List)).unwrap();
        log.append(Entry::new(Event::Search)).unwrap();
        drop(log);
        let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["log_id"].as_str().unwrap(), id);
        }
    }

    #[test]
    fn checkpoint_sink_failure_keeps_cadence_and_retries() {
        /// Fails the first N pushes, then delegates to an inner file sink;
        /// records every attempt.
        struct FlakySink {
            inner: super::super::FileCheckpointSink,
            fail_left: usize,
            attempts: std::cell::Cell<usize>,
        }
        impl CheckpointSink for FlakySink {
            fn push(&mut self, cp: &Checkpoint) -> io::Result<()> {
                let n = self.attempts.get() + 1;
                self.attempts.set(n);
                if self.fail_left > 0 {
                    self.fail_left -= 1;
                    Err(io::Error::other("sink down"))
                } else {
                    self.inner.push(cp)
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let cp_path = dir.path().join("checkpoints.jsonl");
        let cfg = AuditConfig {
            checkpoint_every: 3,
            ..AuditConfig::default()
        };
        let sink = FlakySink {
            inner: super::super::FileCheckpointSink::create(&cp_path).unwrap(),
            fail_left: 1,
            attempts: std::cell::Cell::new(0),
        };
        let mut log = AuditLog::open(dir.path(), cfg, Box::new(sink)).unwrap();
        for _ in 0..4 {
            log.append(Entry::new(Event::List).agent_id("a")).unwrap();
        }
        let text = std::fs::read_to_string(&cp_path).unwrap();
        let cps: Vec<serde_json::Value> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        // seq 3's checkpoint failed on the sink; the cadence counter was not
        // reset, so the very next append retried and delivered it — now
        // attesting seq 4.
        assert_eq!(cps.len(), 1, "one delivered checkpoint: {text}");
        assert_eq!(cps[0]["seq"], 4);
    }

    #[test]
    fn req_aud_004_key_files_are_0600_and_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let _log = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        let keys = dir.path().join("keys");
        let name = std::fs::read(keys.join("audit_name_key")).unwrap();
        let sign = std::fs::read(keys.join("audit_sign_key")).unwrap();
        assert_ne!(name, sign);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(keys.join("audit_name_key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn checkpoint_timer_anchors_quiet_tail() {
        // REQ-AUD-002 10-minute leg (#127): with the count cadence far
        // away, appends alone deliver nothing; once the period has
        // elapsed, `checkpoint_if_due` anchors the tail without any
        // new append, and is a no-op until more entries land.
        //
        // No wall-clock sleep (#165): the period is an hour, so "not
        // elapsed" can't flip under load (neither here nor in `append`'s
        // own period check), and the period is made to elapse by moving
        // the last checkpoint time back past it.
        let dir = tempfile::tempdir().unwrap();
        let cp_path = dir.path().join("checkpoints.jsonl");
        let period = Duration::from_secs(3600);
        let cfg = AuditConfig {
            checkpoint_every: 100,
            checkpoint_period: period,
            ..AuditConfig::default()
        };
        let mut log = AuditLog::open(
            dir.path(),
            cfg,
            Box::new(super::super::FileCheckpointSink::create(&cp_path).unwrap()),
        )
        .unwrap();
        log.append(Entry::new(Event::List).agent_id("a")).unwrap();
        log.append(Entry::new(Event::List).agent_id("a")).unwrap();
        assert!(!log.checkpoint_if_due(), "period has not elapsed yet");
        assert!(!cp_path.exists() || std::fs::read_to_string(&cp_path).unwrap().is_empty());

        log.last_checkpoint_at -= period + Duration::from_secs(1);
        assert!(log.checkpoint_if_due(), "due checkpoint must be delivered");
        let text = std::fs::read_to_string(&cp_path).unwrap();
        let cps: Vec<super::super::Checkpoint> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(cps.len(), 1);
        assert_eq!(cps[0].seq, 2, "the quiet tail (both entries) is anchored");

        assert!(!log.checkpoint_if_due(), "nothing new to anchor");
        assert!(!log.checkpoint_now(), "head already checkpointed");

        log.append(Entry::new(Event::List).agent_id("a")).unwrap();
        assert!(
            log.checkpoint_now(),
            "shutdown anchor delivers the new head"
        );
        let text = std::fs::read_to_string(&cp_path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().last().unwrap().contains("\"seq\":3"));
    }

    #[test]
    fn checkpoints_emit_on_count_cadence() {
        let dir = tempfile::tempdir().unwrap();
        let cp_path = dir.path().join("checkpoints.jsonl");
        let cfg = AuditConfig {
            checkpoint_every: 3,
            ..AuditConfig::default()
        };
        let mut log = AuditLog::open(
            dir.path(),
            cfg,
            Box::new(super::super::FileCheckpointSink::create(&cp_path).unwrap()),
        )
        .unwrap();
        for _ in 0..7 {
            log.append(Entry::new(Event::List).agent_id("a")).unwrap();
        }
        let text = std::fs::read_to_string(&cp_path).unwrap();
        let cps: Vec<super::super::Checkpoint> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(cps.len(), 2, "checkpoints at seq 3 and 6: {text}");
        assert!(
            cps.iter()
                .all(|cp| cp.verify_signature(&log.keys().verifying_key()))
        );
    }

    // ---- #131 slice 4: the in-memory tail ----

    #[test]
    fn tail_follows_appends_newest_first_and_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = open_retrying(dir.path(), AuditConfig::default(), || {
            Box::new(NullCheckpointSink)
        })
        .unwrap();
        assert!(log.tail(10).is_empty());
        for i in 0..(TAIL_KEEP + 5) {
            log.append(Entry::new(Event::List).agent_id(format!("a{i}")))
                .unwrap();
        }
        let all = log.tail(usize::MAX);
        assert_eq!(all.len(), TAIL_KEEP);
        assert_eq!(all[0].seq, (TAIL_KEEP + 5) as u64);
        assert_eq!(all[TAIL_KEEP - 1].seq, 6);
        let three: Vec<u64> = log.tail(3).iter().map(|e| e.seq).collect();
        let head = (TAIL_KEEP + 5) as u64;
        assert_eq!(three, [head, head - 1, head - 2]);
    }

    #[test]
    fn tail_is_seeded_from_the_chain_at_open_with_names_as_written() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = open_retrying(dir.path(), AuditConfig::default(), || {
                Box::new(NullCheckpointSink)
            })
            .unwrap();
            log.append(Entry::new(Event::Unlock)).unwrap();
            log.append(
                Entry::new(Event::Fill)
                    .item_id("item-1")
                    .item_name("Bank of Example"),
            )
            .unwrap();
        }
        let log = open_retrying(dir.path(), AuditConfig::default(), || {
            Box::new(NullCheckpointSink)
        })
        .unwrap();
        let tail = log.tail(10);
        assert_eq!(tail.iter().map(|e| e.seq).collect::<Vec<_>>(), [2, 1]);
        assert_eq!(tail[0].event, Event::Fill);
        assert!(tail[0].item_name.is_none(), "the name is hashed on disk");
        assert!(tail[0].item_name_hash.is_some());
    }

    #[test]
    fn a_failed_append_never_reaches_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let keys = AuditKeys::load_or_generate(&dir.path().join("keys")).unwrap();
        let mut log = AuditLog::open_for_test(
            SyncFails,
            keys,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        );
        assert!(log.append(Entry::new(Event::Unlock)).is_err());
        assert!(log.append(Entry::new(Event::Lock)).is_err());
        assert!(log.tail(10).is_empty());
    }
}
