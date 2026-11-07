//! `bitwarden.api_key_file` permission check (SPEC §8, REQ-DEP-008).
//!
//! The API key authenticates as the kharon account and syncs ciphertext
//! and metadata; it cannot decrypt without the master password. A file
//! others can *write* lets them swap in their own key (point kharond at
//! an attacker account), so that is fatal. A file others can *read*, or
//! one owned by another uid, only warns: a Swarm secret is mounted 0444
//! and root-owned inside a single-purpose container where kharond runs
//! as a non-root uid.
//!
//! Plain Docker Compose (no Swarm) mounts a `secrets: file:` entry as a
//! bind mount that keeps the host file's owner and mode, and ignores the
//! secret's `uid`, `gid` and `mode`. A 0400 file owned by the operator
//! is then unreadable to kharond (uid 10001 in the Compose example), so
//! the check opens the file and, if that is refused, says whose uid and
//! which mode are in the way (#149).

use std::fs::Metadata;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::{ConfigError, ConfigWarning};

const GROUP_OTHER_WRITE: u32 = 0o022;
const GROUP_OTHER_READ: u32 = 0o044;

/// Check the file at `path` (symlinks followed) against kharond's
/// effective uid, then open it (without reading) to prove that uid can.
/// Errors carry fixed text, uids and the mode; never file content.
pub(super) fn check_api_key_file(path: &Path) -> Result<Vec<ConfigWarning>, ConfigError> {
    let fixed = |reason| ConfigError::ApiKeyFile { reason };
    let meta = std::fs::metadata(path).map_err(|_| fixed("unreadable"))?;
    let euid = rustix::process::geteuid().as_raw();
    let warnings = check_metadata(&meta, euid).map_err(fixed)?;
    check_openable(path, &meta, euid)?;
    Ok(warnings)
}

pub(super) fn check_metadata(
    meta: &Metadata,
    euid: u32,
) -> Result<Vec<ConfigWarning>, &'static str> {
    if !meta.file_type().is_file() {
        return Err("not a regular file");
    }
    let mode = meta.mode();
    if mode & GROUP_OTHER_WRITE != 0 {
        return Err("group- or world-writable (use mode 0400 or 0600)");
    }
    let mut w = Vec::new();
    if mode & GROUP_OTHER_READ != 0 {
        w.push(ConfigWarning::ApiKeyFileReadableByOthers);
    }
    if meta.uid() != euid {
        w.push(ConfigWarning::ApiKeyFileForeignOwner);
    }
    Ok(w)
}

fn check_openable(path: &Path, meta: &Metadata, euid: u32) -> Result<(), ConfigError> {
    match std::fs::File::open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            Err(ConfigError::ApiKeyFileNotReadable {
                euid,
                owner: meta.uid(),
                mode: meta.mode() & 0o7777,
            })
        }
        Err(_) => Err(ConfigError::ApiKeyFile {
            reason: "unreadable",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn key_with_mode(mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("key.json");
        std::fs::write(&p, b"{}").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        (dir, p)
    }

    fn fixed(reason: &'static str) -> ConfigError {
        ConfigError::ApiKeyFile { reason }
    }

    #[test]
    fn req_dep_008_mode_0600_and_0400_ok() {
        for m in [0o600, 0o400] {
            let (_d, p) = key_with_mode(m);
            assert_eq!(check_api_key_file(&p), Ok(vec![]), "mode {m:o}");
        }
    }

    #[test]
    fn req_dep_008_mode_0444_warns() {
        let (_d, p) = key_with_mode(0o444);
        assert_eq!(
            check_api_key_file(&p),
            Ok(vec![ConfigWarning::ApiKeyFileReadableByOthers])
        );
    }

    #[test]
    fn req_dep_008_group_or_world_writable_refused() {
        for m in [0o620, 0o602, 0o666] {
            let (_d, p) = key_with_mode(m);
            assert_eq!(
                check_api_key_file(&p),
                Err(fixed("group- or world-writable (use mode 0400 or 0600)")),
                "mode {m:o}"
            );
        }
    }

    #[test]
    fn req_dep_008_non_regular_file_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check_api_key_file(dir.path()),
            Err(fixed("not a regular file"))
        );
    }

    #[test]
    fn req_dep_008_foreign_owner_warns() {
        let (_d, p) = key_with_mode(0o600);
        let meta = std::fs::metadata(&p).unwrap();
        let other = meta.uid().wrapping_add(1);
        assert_eq!(
            check_metadata(&meta, other),
            Ok(vec![ConfigWarning::ApiKeyFileForeignOwner])
        );
    }

    #[test]
    fn req_dep_008_missing_file_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check_api_key_file(&dir.path().join("nope")),
            Err(fixed("unreadable"))
        );
    }

    /// #149: a file kharond's uid may not open (the plain-Compose bind
    /// mount of an operator-owned 0400 file) is refused with the uid,
    /// owner and mode in the message, not a bare "unreadable". Root
    /// opens anything, so this needs an unprivileged test run.
    #[test]
    fn req_dep_008_not_openable_by_euid_names_uid_owner_and_mode() {
        let euid = rustix::process::geteuid().as_raw();
        if euid == 0 {
            eprintln!("req_dep_008: running as root, which can open any file; skipped");
            return;
        }
        let (_d, p) = key_with_mode(0o000);
        let err = check_api_key_file(&p).unwrap_err();
        assert_eq!(
            err,
            ConfigError::ApiKeyFileNotReadable {
                euid,
                owner: euid,
                mode: 0
            }
        );
        assert_eq!(err.code(), "api_key_file");
        let msg = err.to_string();
        assert!(msg.contains(&format!("euid {euid}")), "{msg}");
        assert!(msg.contains("mode 0000"), "{msg}");
        assert!(msg.contains("0400"), "{msg}");
    }
}
