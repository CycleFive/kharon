//! Acceptance tests for issue #12 (REQ-EXP-001..005).
//!
//! The fixtures are real password-protected Bitwarden exports,
//! produced by an independent Python implementation of the clients'
//! export format (`fixtures/gen/gen_export_fixture.py`): password
//! `kharon export fixture password 9`, PBKDF2-HMAC-SHA256 with
//! 123 456 iterations, salt `a2hhcm9uLWV4cG9ydC0xNg==`.
//!
//! Fixture A holds two logins and one secure note:
//! - "Example Login" — username `fixture@example.net`, URIs
//!   `https://example.com/login` (default match) and
//!   `https://example.com/` (host match), password canary
//!   `CANARY-EXPORT-PASSWORD-7f3a`, a TOTP secret, a hidden custom
//!   field, and a note (the last two are not carried into the vault,
//!   as in sync mode).
//! - "Second Login" — password only.
//!
//! Fixture B ("replaced") holds one different login and backs the
//! REQ-EXP-004 replace-file test.

use std::path::{Path, PathBuf};

use kharond::audit::{AuditConfig, AuditLog, Entry, Event, NullCheckpointSink};
use kharond::config::{Config, StaticMlockProbe};
use kharond::export::{ExportError, ExportFile};
use kharond::sync::{SecretField, SyncError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const FIXTURE_A: &str = include_str!("fixtures/export/password_protected.json");
const FIXTURE_B: &str = include_str!("fixtures/export/password_protected_replaced.json");
const PASSWORD: &str = "kharon export fixture password 9";
const CANARY: &str = "CANARY-EXPORT-PASSWORD-7f3a";

fn password() -> Zeroizing<String> {
    Zeroizing::new(PASSWORD.to_string())
}

fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn req_exp_001_loads_and_list_matches_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "export.json", FIXTURE_A);
    let file = ExportFile::load(&path).unwrap();
    assert_eq!(file.sha256_hex(), sha256_hex(FIXTURE_A.as_bytes()));

    let session = file.unlock(&password()).unwrap();
    let vault = session.vault();
    // The secure note is skipped; both logins are present.
    assert_eq!(vault.len(), 2);
    assert_eq!(vault.report().kept, 2);
    assert_eq!(vault.report().skipped, 1);

    let names: Vec<&str> = vault.items().map(|i| i.name()).collect();
    assert_eq!(names, ["Example Login", "Second Login"]);

    let first = vault.items().find(|i| i.name() == "Example Login").unwrap();
    assert_eq!(first.username(), Some("fixture@example.net"));
    let uris: Vec<(&str, Option<u8>)> = first
        .uris()
        .iter()
        .map(|u| (u.uri.as_str(), u.match_type))
        .collect();
    assert_eq!(
        uris,
        [
            ("https://example.com/login", None),
            ("https://example.com/", Some(1))
        ]
    );
    assert_eq!(first.revision(), Some("2026-01-02T03:04:05.000Z"));
    assert!(first.has_password());
    assert!(first.has_totp());

    // Secrets decrypt per fill, through the wrap key.
    let pw = session
        .decrypt_secret(first.id(), SecretField::Password)
        .unwrap();
    assert_eq!(&pw[..], CANARY.as_bytes());
    let totp = session
        .decrypt_secret(first.id(), SecretField::Totp)
        .unwrap();
    assert_eq!(&totp[..], b"JBSWY3DPEHPK3PXP");

    let second = vault.items().find(|i| i.name() == "Second Login").unwrap();
    assert_eq!(second.username(), None);
    assert!(!second.has_totp());
    assert!(matches!(
        session.decrypt_secret(second.id(), SecretField::Totp),
        Err(SyncError::FieldMissing)
    ));
    assert!(matches!(
        session.decrypt_secret("no-such-id", SecretField::Password),
        Err(SyncError::ItemNotFound)
    ));
}

#[test]
fn req_exp_001_loads_from_file_bytes_with_no_server_anywhere() {
    // The whole flow — classify, derive, validate, decrypt — runs on
    // the file bytes alone. There is no client, server config, or
    // network type anywhere in the export module's API.
    let file = ExportFile::from_bytes(FIXTURE_A.as_bytes()).unwrap();
    let session = file.unlock(&password()).unwrap();
    assert_eq!(session.vault().len(), 2);
}

#[test]
fn req_exp_002_refuses_plaintext_json_csv_and_account_restricted() {
    let plaintext = r#"{"folders": [], "items": [{"id": "x", "type": 1, "name": "plain"}]}"#;
    let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,plain,,,,,,\n";
    // Account-restricted: encrypted under the account's user key,
    // `passwordProtected` false, no salt/KDF/validation envelope.
    let account_restricted =
        r#"{"encrypted": true, "passwordProtected": false, "data": "2.AAAA|BBBB|CCCC"}"#;
    // Account-restricted, the real shape users actually have
    // (PR #59 review, non-blocking g): the validation EncString at
    // top level, folders/items in the clear, no `passwordProtected`
    // and no `data` at all.
    let account_restricted_real = r#"{"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.AAAA|BBBB|CCCC", "folders": [], "items": []}"#;
    // Encrypted but the passwordProtected flag is absent entirely.
    let flag_absent = r#"{"encrypted": true, "salt": "x", "data": "2.AAAA|BBBB|CCCC"}"#;
    // Envelope flags set, but the data field is not an EncString.
    let data_not_encstring = r#"{"encrypted": true, "passwordProtected": true, "salt": "a2hhcm9uLWV4cG9ydC0xNg==", "kdfType": 0, "kdfIterations": 123456, "encKeyValidation_DO_NOT_EDIT": "2.AAAA|BBBB|CCCC", "data": "not-an-encstring"}"#;

    for (name, contents) in [
        ("plaintext json", plaintext),
        ("csv", csv),
        ("account-restricted", account_restricted),
        ("account-restricted (real shape)", account_restricted_real),
        ("passwordProtected absent", flag_absent),
        ("data not an encstring", data_not_encstring),
    ] {
        let err = ExportFile::from_bytes(contents.as_bytes()).unwrap_err();
        assert!(
            matches!(err, ExportError::NotPasswordEncrypted),
            "{name}: expected ExportNotPasswordEncrypted, got {err:?}"
        );
        assert_eq!(err.code(), "ExportNotPasswordEncrypted");
    }
}

fn export_mode_config(file: &Path) -> String {
    format!(
        r#"mode = "export"
[export]
file = "{}"
[agents.solo]
token_hash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash"
cdp = {{ endpoint = "ws://127.0.0.1:9222" }}
[policy]
allow_default_context = true
[audit]
checkpoint_local_only = true
"#,
        file.display()
    )
}

#[test]
fn req_exp_002_refusal_is_a_startup_error() {
    let dir = tempfile::tempdir().unwrap();

    // A plaintext export where the config points: startup refuses.
    let plain = write(dir.path(), "plain.json", "{\"items\": []}");
    let cfg = Config::from_toml_str(&export_mode_config(&plain)).unwrap();
    let err = cfg.check_startup(&StaticMlockProbe(Ok(()))).unwrap_err();
    assert_eq!(err.code(), "export_not_password_encrypted");

    // A missing export file is a startup read error, not a pass.
    let missing = dir.path().join("nope.json");
    let cfg = Config::from_toml_str(&export_mode_config(&missing)).unwrap();
    let err = cfg.check_startup(&StaticMlockProbe(Ok(()))).unwrap_err();
    assert_eq!(err.code(), "export_read");

    // The real fixture passes the startup classification.
    let good = write(dir.path(), "export.json", FIXTURE_A);
    let cfg = Config::from_toml_str(&export_mode_config(&good)).unwrap();
    cfg.check_startup(&StaticMlockProbe(Ok(()))).unwrap();
}

#[test]
fn req_exp_003_password_in_config_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let good = write(dir.path(), "export.json", FIXTURE_A);
    // The export password in the config — at any depth — is refused
    // by the loader's secret-key rule (REQ-EXP-003: unlock only).
    let text = export_mode_config(&good).replacen(
        "[export]\n",
        &format!("[export]\nexport_password = \"{PASSWORD}\"\n"),
        1,
    );
    let err = Config::from_toml_str(&text).unwrap_err();
    assert_eq!(err.code(), "secret_in_config");
}

#[test]
fn req_exp_003_session_carries_no_plaintext_password_or_secret() {
    let file = ExportFile::from_bytes(FIXTURE_A.as_bytes()).unwrap();
    let session = file.unlock(&password()).unwrap();
    // Nothing printable about the session or its audit entry carries
    // the export password or an item secret in the clear.
    let audit = format!("{:?}", session.audit_entry());
    assert!(!audit.contains(PASSWORD));
    assert!(!audit.contains(CANARY));
    assert!(!format!("{:?}", session.vault()).contains(CANARY));
    // The stored password field is an EncString, not the plaintext:
    // it decrypts through the session's wrap key (and only there) —
    // `Item::protected_password` is crate-private (PR #59 review,
    // non-blocking e), so the check goes through `decrypt_secret`.
    let item = session
        .vault()
        .items()
        .find(|i| i.name() == "Example Login")
        .unwrap();
    let pt = session
        .decrypt_secret(item.id(), SecretField::Password)
        .unwrap();
    assert_eq!(&pt[..], CANARY.as_bytes());
}

#[test]
fn req_exp_004_file_hash_in_audit_and_replace_needs_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "export.json", FIXTURE_A);

    // Unlock from the file as loaded; the audit entry records the
    // SHA-256 of exactly those bytes.
    let loaded = ExportFile::load(&path).unwrap();
    let session = loaded.unlock(&password()).unwrap();
    let entry = session.audit_entry();
    assert_eq!(entry.event, Event::ExportLoaded);
    assert_eq!(
        entry.file_sha256.as_deref(),
        Some(sha256_hex(FIXTURE_A.as_bytes()).as_str())
    );

    // The entry survives a real audit log round trip, hash intact.
    let audit_dir = tempfile::tempdir().unwrap();
    {
        let mut log = AuditLog::open(
            audit_dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        log.append(entry).unwrap();
    }
    let text = std::fs::read_to_string(audit_dir.path().join("audit.jsonl")).unwrap();
    let line: serde_json::Value = text.lines().last().unwrap().parse().unwrap();
    assert_eq!(line["event"], "export_loaded");
    assert_eq!(
        line["file_sha256"],
        sha256_hex(FIXTURE_A.as_bytes()).as_str()
    );

    // Replace the file on disk: the already-loaded envelope and the
    // live session's list do not change (no sync, no re-read).
    std::fs::write(&path, FIXTURE_B).unwrap();
    let names: Vec<&str> = session.vault().items().map(|i| i.name()).collect();
    assert_eq!(names, ["Example Login", "Second Login"]);
    let again = loaded.unlock(&password()).unwrap();
    assert_eq!(again.vault().len(), 2);

    // Only a fresh load (the restart) sees the new file — with a new
    // hash for the next `export_loaded` entry.
    let reloaded = ExportFile::load(&path).unwrap();
    assert_eq!(reloaded.sha256_hex(), sha256_hex(FIXTURE_B.as_bytes()));
    assert_ne!(reloaded.sha256_hex(), loaded.sha256_hex());
    let session_b = reloaded.unlock(&password()).unwrap();
    let names_b: Vec<&str> = session_b.vault().items().map(|i| i.name()).collect();
    assert_eq!(names_b, ["Replaced Login"]);
}

#[test]
fn req_exp_005_wrong_password_and_tampered_fields_fail_without_partial_load() {
    let file = ExportFile::from_bytes(FIXTURE_A.as_bytes()).unwrap();

    // Wrong password.
    let wrong = Zeroizing::new("kharon export fixture password 8".to_string());
    assert!(matches!(file.unlock(&wrong), Err(ExportError::AuthFailed)));

    // Tampered validation string (one base64 character flipped in the
    // ciphertext segment): classification still passes, unlock fails.
    let tampered_validation = FIXTURE_A.replacen(
        "+bC1+Pmp1VsFfOO2zNi7GsJ1fUIkIk94qtrPCBWJtRO7Qygpe5A6C0ZYSgaf8aTg",
        "+bC1+Pmp1VsFfOO2zNi7GsJ1fUIkIk94qtrPCBWJtRO7Qygpe5A6C0ZYSgaf8aTh",
        1,
    );
    assert_ne!(tampered_validation, FIXTURE_A);
    let file = ExportFile::from_bytes(tampered_validation.as_bytes()).unwrap();
    assert!(matches!(
        file.unlock(&password()),
        Err(ExportError::AuthFailed)
    ));

    // Tampered data, MAC segment (the correct password, one flipped
    // character near the end of the file, which lands inside the
    // data EncString's MAC segment): AuthFailed.
    let mut bytes = FIXTURE_A.as_bytes().to_vec();
    let pos = bytes.len() - 30;
    bytes[pos] = if bytes[pos] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    let file = ExportFile::from_bytes(tampered.as_bytes()).unwrap();
    assert!(matches!(
        file.unlock(&password()),
        Err(ExportError::AuthFailed)
    ));

    // Tampered data, ciphertext segment (PR #59 review, non-blocking
    // c: the case above flips the MAC, not the ct): flip one base64
    // character inside the data EncString's ct segment itself.
    // AuthFailed, and by construction no session — hence no partial
    // item set — is ever returned on this path.
    let mut v: serde_json::Value = serde_json::from_str(FIXTURE_A).unwrap();
    let data = v["data"].as_str().unwrap().to_owned();
    let mut segs: Vec<String> = data.split('|').map(str::to_owned).collect();
    assert_eq!(segs.len(), 3, "type-2 wire form is iv|ct|mac");
    let ct_first = segs[1].as_bytes()[0];
    segs[1].replace_range(..1, if ct_first == b'A' { "B" } else { "A" });
    v["data"] = serde_json::Value::String(segs.join("|"));
    let tampered = v.to_string();
    assert_ne!(tampered, FIXTURE_A);
    let file = ExportFile::from_bytes(tampered.as_bytes()).unwrap();
    let err = file.unlock(&password()).unwrap_err();
    assert!(matches!(err, ExportError::AuthFailed));
    assert_eq!(err.code(), "ExportAuthFailed");
}

#[test]
fn entry_builder_defaults_file_sha256_to_none() {
    // Other events' entries are unchanged: the new field is omitted.
    let e = Entry::new(Event::Unlock);
    assert_eq!(e.file_sha256, None);
    let j = serde_json::to_string(&e).unwrap();
    assert!(!j.contains("file_sha256"));
}
