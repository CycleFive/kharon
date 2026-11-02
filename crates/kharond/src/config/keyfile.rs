//! `bitwarden.api_key_file` permission check (SPEC §8, REQ-DEP-008).
//!
//! The API key authenticates as the kharon account and syncs ciphertext
//! and metadata; it cannot decrypt without the master password. A file
//! others can *write* lets them swap in their own key (point kharond at
//! an attacker account), so that is fatal. A file others can *read*, or
//! one owned by another uid, only warns: Docker secrets are mounted 0444
//! (root-owned) inside a single-purpose container where kharond runs as
//! a non-root uid.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::ConfigWarning;

const GROUP_OTHER_WRITE: u32 = 0o022;
const GROUP_OTHER_READ: u32 = 0o044;

/// Check the file at `path` (symlinks followed) against kharond's
/// effective uid. `Err` carries fixed text (never file content).
pub(super) fn check_api_key_file(path: &Path) -> Result<Vec<ConfigWarning>, &'static str> {
    let meta = std::fs::metadata(path).map_err(|_| "unreadable")?;
    check_metadata(&meta, rustix::process::geteuid().as_raw())
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
                Err("group- or world-writable (use mode 0400 or 0600)"),
                "mode {m:o}"
            );
        }
    }

    #[test]
    fn req_dep_008_non_regular_file_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(check_api_key_file(dir.path()), Err("not a regular file"));
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
            Err("unreadable")
        );
    }
}
