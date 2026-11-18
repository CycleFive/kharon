//! Find a Chromium-family browser, give it a private throwaway profile, and
//! guarantee the profile is deleted.

use serde::Serialize;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("no Chromium-family browser found; pass --browser <path>")]
    NotFound,
    #[error("browser not found at {0}")]
    BadPath(PathBuf),
    #[error("the browser did not start: {0}")]
    Launch(String),
}

pub const PROFILE_PREFIX: &str = "kharon-teach-";
/// Written into every profile: the pid of the recorder that owns it.
pub const OWNER_FILE: &str = "kharon-teach.owner";

const SEARCH_ORDER: [&str; 6] = [
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "microsoft-edge",
    "brave-browser",
];

/// The browser to launch: `explicit` if given, else the first of the known
/// names found on `$PATH`.
pub fn find_browser(explicit: Option<&Path>) -> Result<PathBuf, BrowserError> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    find_browser_in(explicit, &path_var)
}

pub fn find_browser_in(explicit: Option<&Path>, path_var: &OsStr) -> Result<PathBuf, BrowserError> {
    if let Some(p) = explicit {
        return if p.is_file() {
            Ok(p.to_owned())
        } else {
            Err(BrowserError::BadPath(p.to_owned()))
        };
    }
    for name in SEARCH_ORDER {
        for dir in std::env::split_paths(path_var) {
            let cand = dir.join(name);
            if is_executable_file(&cand) {
                return Ok(cand);
            }
        }
    }
    Err(BrowserError::NotFound)
}

fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// A private throwaway browser profile directory, deleted on drop.
pub struct Profile {
    path: PathBuf,
}

#[derive(Serialize)]
struct Preferences {
    credentials_enable_service: bool,
    profile: ProfilePrefs,
    autofill: AutofillPrefs,
}

#[derive(Serialize)]
struct ProfilePrefs {
    password_manager_enabled: bool,
}

#[derive(Serialize)]
struct AutofillPrefs {
    profile_enabled: bool,
    credit_card_enabled: bool,
}

const PREFERENCES: Preferences = Preferences {
    credentials_enable_service: false,
    profile: ProfilePrefs {
        password_manager_enabled: false,
    },
    autofill: AutofillPrefs {
        profile_enabled: false,
        credit_card_enabled: false,
    },
};

fn private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

impl Profile {
    /// `<temp>/kharon-teach-<random>`, mode 0700, holding an owner file with
    /// this process's pid. It is built under a name the sweep never matches
    /// and renamed into place, so a sweep cannot see it half-made. A crash
    /// between the mkdir and the rename leaves a `.kharon-teach-new-*`
    /// directory that nothing sweeps; the window is microseconds.
    pub fn create() -> std::io::Result<Self> {
        use rand::Rng;
        use rand::distributions::Alphanumeric;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let temp = std::env::temp_dir();
        for _ in 0..16 {
            let suffix: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(20)
                .map(char::from)
                .collect();
            let staging = temp.join(format!(".{PROFILE_PREFIX}new-{suffix}"));
            match private_dir(&staging) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
            let made = (|| {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(staging.join(OWNER_FILE))?;
                f.write_all(std::process::id().to_string().as_bytes())
            })();
            if let Err(e) = made {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(e);
            }
            let path = temp.join(format!("{PROFILE_PREFIX}{suffix}"));
            // rename onto an existing non-empty directory fails; an existing
            // empty one would be replaced, so check first.
            if std::fs::symlink_metadata(&path).is_ok() {
                let _ = std::fs::remove_dir_all(&staging);
                continue;
            }
            match std::fs::rename(&staging, &path) {
                Ok(()) => return Ok(Profile { path }),
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&staging);
                    if path.exists() {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not find an unused profile directory name",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the profile now and report a failure. Also runs on drop,
    /// where errors are ignored.
    pub fn remove(self) -> std::io::Result<()> {
        remove_tree(&self.path)
    }

    /// Removes leftover PROFILE_PREFIX directories in the temp location owned by this user. Returns how many.
    pub fn sweep_stale() -> std::io::Result<usize> {
        use std::os::unix::fs::MetadataExt;
        // /proc/self is owned by this process's effective uid.
        let me = std::fs::metadata("/proc/self")?.uid();
        let mut n = 0;
        for entry in std::fs::read_dir(std::env::temp_dir())? {
            let Ok(entry) = entry else { continue };
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(PROFILE_PREFIX)
            {
                continue;
            }
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.file_type().is_dir()
                || meta.uid() != me
                || owner_is_alive(&path)
                || browser_is_alive(&path)
            {
                continue;
            }
            if remove_tree(&path).is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        let _ = remove_tree(&self.path);
    }
}

/// `remove_dir_all` does not follow symlinks. A just-killed browser's helper
/// processes can still be writing, so retry a few times.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    let mut last = Ok(());
    for _ in 0..5 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => last = Err(e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    last
}

/// The owner file names a live pid. A missing, symlinked, non-regular,
/// over-32-byte or unparseable owner file counts as no live owner.
fn owner_is_alive(dir: &Path) -> bool {
    let file = dir.join(OWNER_FILE);
    let Ok(meta) = std::fs::symlink_metadata(&file) else {
        return false;
    };
    if !meta.file_type().is_file() || meta.len() > 32 {
        return false;
    }
    std::fs::read_to_string(&file)
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
        .is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
}

/// Chromium's `SingletonLock` is a symlink whose target text is
/// `<hostname>-<pid>`; the profile is live when that pid exists.
fn browser_is_alive(dir: &Path) -> bool {
    let Ok(target) = std::fs::read_link(dir.join("SingletonLock")) else {
        return false;
    };
    target
        .to_string_lossy()
        .rsplit('-')
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
}

pub struct Launch<'a> {
    pub browser: &'a Path,
    pub profile: &'a Profile,
    pub first_url: &'a str,
    pub headless: bool,
}

/// The browser process. Killed when dropped.
pub struct Browser {
    child: tokio::process::Child,
}

pub struct DevTools {
    pub port: u16,
    pub ws_path: String,
}

const START_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(50);

impl Browser {
    /// Start the browser on the profile and wait up to 20 s for its
    /// `DevToolsActivePort` file.
    pub async fn launch(l: Launch<'_>) -> Result<(Browser, DevTools), BrowserError> {
        use std::process::Stdio;
        let launch_err = |e: std::io::Error| BrowserError::Launch(e.to_string());
        let profile = l.profile.path();
        let default = profile.join("Default");
        private_dir(&default).map_err(launch_err)?;
        let prefs =
            serde_json::to_string(&PREFERENCES).map_err(|e| BrowserError::Launch(e.to_string()))?;
        std::fs::write(default.join("Preferences"), prefs).map_err(launch_err)?;

        let mut cmd = tokio::process::Command::new(l.browser);
        cmd.arg(format!("--user-data-dir={}", profile.display()))
            .arg("--remote-debugging-port=0")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disk-cache-size=1")
            .arg("--disable-sync")
            .arg("--password-store=basic")
            .arg("--disable-features=AutofillServerCommunication,PasswordManagerOnboarding");
        if l.headless {
            cmd.arg("--headless=new");
        }
        cmd.arg(l.first_url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(launch_err)?;

        let file = profile.join("DevToolsActivePort");
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait().map_err(launch_err)? {
                return Err(BrowserError::Launch(status.to_string()));
            }
            if let Some(dt) = std::fs::read_to_string(&file)
                .ok()
                .and_then(|t| parse_devtools_active_port(&t))
            {
                return Ok((Browser { child }, dt));
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = child.kill().await;
                return Err(BrowserError::Launch(
                    "no DevTools port after 20 s".to_owned(),
                ));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id().unwrap_or(0)
    }

    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }

    /// Kill the browser and wait until it is reaped.
    pub async fn close(mut self) -> std::io::Result<()> {
        self.child.kill().await
    }
}

/// A copy of the rules in `parse_devtools_active_port` in
/// `crates/kharon-connector/src/devtools.rs`: two lines, a port of 1 to 5
/// digits that is not 0, and a `/devtools/browser/<id>` path. The host is
/// never taken from the file.
pub fn parse_devtools_active_port(text: &str) -> Option<DevTools> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.lines();
    let port_line = lines.next()?.trim();
    let path = lines.next()?.trim();
    if port_line.is_empty() || port_line.len() > 5 || !port_line.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let port: u16 = port_line.parse().ok()?;
    if port == 0 {
        return None;
    }
    let id = path.strip_prefix("/devtools/browser/")?;
    if id.is_empty()
        || id.len() > 128
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    Some(DevTools {
        port,
        ws_path: path.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn unique(tag: &str) -> String {
        format!(
            "{PROFILE_PREFIX}{tag}-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        )
    }

    #[test]
    fn profile_is_private_and_removed() {
        let p = Profile::create().unwrap();
        let path = p.path().to_owned();
        assert!(
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(PROFILE_PREFIX)
        );
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::read_to_string(path.join(OWNER_FILE)).unwrap(),
            std::process::id().to_string()
        );
        p.remove().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn profile_is_removed_on_drop() {
        let p = Profile::create().unwrap();
        let path = p.path().to_owned();
        std::fs::write(path.join("f"), b"x").unwrap();
        drop(p);
        assert!(!path.exists());
    }

    #[test]
    fn sweep_removes_a_leftover_and_counts_it() {
        let d = std::env::temp_dir().join(unique("stale"));
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("f"), b"x").unwrap();
        assert!(Profile::sweep_stale().unwrap() >= 1);
        assert!(!d.exists());
    }

    #[test]
    fn sweep_leaves_other_directories() {
        let d = std::env::temp_dir().join(format!("other-{}", unique("keep")));
        std::fs::create_dir(&d).unwrap();
        Profile::sweep_stale().unwrap();
        assert!(d.exists());
        std::fs::remove_dir(&d).unwrap();
    }

    #[test]
    fn sweep_leaves_a_symlink_and_its_target() {
        let target = std::env::temp_dir().join(format!("other-{}", unique("tgt")));
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("f"), b"x").unwrap();
        let link = std::env::temp_dir().join(unique("link"));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        Profile::sweep_stale().unwrap();
        assert!(target.join("f").exists());
        assert!(std::fs::symlink_metadata(&link).is_ok());
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_dir_all(&target).unwrap();
    }

    // An addition to the brief: a profile whose SingletonLock names a live
    // process is a running recorder's profile and must survive a sweep.
    #[test]
    fn sweep_skips_a_profile_whose_browser_is_alive() {
        let d = std::env::temp_dir().join(unique("live"));
        std::fs::create_dir(&d).unwrap();
        std::os::unix::fs::symlink(
            format!("host-{}", std::process::id()),
            d.join("SingletonLock"),
        )
        .unwrap();
        Profile::sweep_stale().unwrap();
        assert!(d.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn dead_pid() -> u32 {
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let pid = c.id();
        c.wait().unwrap();
        pid
    }

    fn dir_with_owner(tag: &str, owner: &str) -> PathBuf {
        let d = std::env::temp_dir().join(unique(tag));
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join(OWNER_FILE), owner).unwrap();
        d
    }

    #[test]
    fn sweep_skips_a_profile_owned_by_this_process() {
        let d = dir_with_owner("mine", &std::process::id().to_string());
        Profile::sweep_stale().unwrap();
        assert!(d.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn sweep_removes_a_profile_owned_by_a_dead_process() {
        let d = dir_with_owner("dead", &dead_pid().to_string());
        assert!(Profile::sweep_stale().unwrap() >= 1);
        assert!(!d.exists());
    }

    #[test]
    fn sweep_treats_an_owner_symlink_as_no_owner() {
        let d = std::env::temp_dir().join(unique("ownlink"));
        std::fs::create_dir(&d).unwrap();
        let real = d.join("real");
        std::fs::write(&real, std::process::id().to_string()).unwrap();
        std::os::unix::fs::symlink(&real, d.join(OWNER_FILE)).unwrap();
        assert!(Profile::sweep_stale().unwrap() >= 1);
        assert!(!d.exists());
    }

    #[test]
    fn sweep_treats_a_junk_or_oversized_owner_as_no_owner() {
        let a = dir_with_owner("junk", "not a pid");
        let b = dir_with_owner("big", &format!("{}{}", std::process::id(), " ".repeat(40)));
        assert!(Profile::sweep_stale().unwrap() >= 2);
        assert!(!a.exists() && !b.exists());
    }

    #[test]
    fn no_browser_on_an_empty_path_is_not_found() {
        assert!(matches!(
            find_browser_in(None, OsStr::new("")),
            Err(BrowserError::NotFound)
        ));
    }

    #[test]
    fn finds_the_first_name_in_search_order() {
        let dir = std::env::temp_dir().join(unique("bin"));
        std::fs::create_dir(&dir).unwrap();
        for n in ["google-chrome", "chromium"] {
            let f = dir.join(n);
            std::fs::write(&f, b"#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let found = find_browser_in(None, dir.as_os_str()).unwrap();
        assert_eq!(found, dir.join("chromium"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn explicit_missing_browser_is_bad_path() {
        assert!(matches!(
            find_browser(Some(Path::new("/nonexistent/chrome"))),
            Err(BrowserError::BadPath(_))
        ));
    }

    #[test]
    fn parses_the_two_line_file() {
        let d = parse_devtools_active_port("45123\n/devtools/browser/abc-123\n").unwrap();
        assert_eq!(d.port, 45123);
        assert_eq!(d.ws_path, "/devtools/browser/abc-123");
    }

    #[test]
    fn rejects_port_zero_garbage_and_a_foreign_path() {
        for bad in [
            "0\n/devtools/browser/abc\n",
            "123456\n/devtools/browser/abc\n",
            "12x\n/devtools/browser/abc\n",
            "",
            "45123\n",
            "45123\n/evil/browser/abc\n",
            "45123\n/devtools/browser/\n",
            "45123\n/devtools/browser/a/b\n",
        ] {
            assert!(parse_devtools_active_port(bad).is_none(), "{bad:?}");
        }
    }
}
