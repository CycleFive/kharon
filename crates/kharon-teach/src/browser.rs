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
    #[error(
        "the only browser found is a snap package, which cannot use the recorder's profile folder; install Google Chrome or pass --browser <path>"
    )]
    SnapOnly,
    #[error("browser not found at {0}")]
    BadPath(PathBuf),
    #[error("the browser did not start: {0}")]
    Launch(String),
}

pub const PROFILE_PREFIX: &str = "kharon-teach-";
/// The random part of a profile's name: this many ASCII alphanumerics.
const SUFFIX_LEN: usize = 20;
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
    find_browser_with(explicit, path_var, &is_snap_browser)
}

/// [`find_browser_in`] with the snap test given, so a test can stand in for the file system.
/// An explicit path is used as given, snap or not: the person chose it.
pub(crate) fn find_browser_with(
    explicit: Option<&Path>,
    path_var: &OsStr,
    is_snap: &dyn Fn(&Path) -> bool,
) -> Result<PathBuf, BrowserError> {
    if let Some(p) = explicit {
        return if p.is_file() {
            Ok(p.to_owned())
        } else {
            Err(BrowserError::BadPath(p.to_owned()))
        };
    }
    let mut saw_snap = false;
    for name in SEARCH_ORDER {
        for dir in std::env::split_paths(path_var) {
            let cand = dir.join(name);
            if !is_executable_file(&cand) {
                continue;
            }
            // A snap browser gets a private /tmp, so it never sees the recorder's profile.
            if is_snap(&cand) {
                saw_snap = true;
                continue;
            }
            return Ok(cand);
        }
    }
    Err(if saw_snap {
        BrowserError::SnapOnly
    } else {
        BrowserError::NotFound
    })
}

/// Whether a path is inside a snap package: under `/snap`, or the `snap` launcher that a
/// `/snap/bin/<name>` link resolves to.
pub(crate) fn is_snap_path(path: &Path) -> bool {
    path.starts_with("/snap") || path.file_name().is_some_and(|n| n == "snap")
}

/// Whether the candidate browser is a snap: its path or its canonical path is a snap path, or it
/// is a short wrapper script that starts one (Ubuntu's `chromium-browser`).
fn is_snap_browser(cand: &Path) -> bool {
    use std::io::Read;
    if is_snap_path(cand) || std::fs::canonicalize(cand).is_ok_and(|c| is_snap_path(&c)) {
        return true;
    }
    let mut head = Vec::new();
    let read = std::fs::File::open(cand).and_then(|f| f.take(4096).read_to_end(&mut head));
    read.is_ok() && head.starts_with(b"#!") && head.windows(6).any(|w| w == b"/snap/")
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
        Self::create_in(&std::env::temp_dir())
    }

    /// [`Profile::create`] in `temp`.
    pub(crate) fn create_in(temp: &Path) -> std::io::Result<Self> {
        use rand::Rng;
        use rand::distributions::Alphanumeric;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        for _ in 0..16 {
            let suffix: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(SUFFIX_LEN)
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

    /// Removes profiles an earlier run of this program left in the temp location. A directory is
    /// removed only when ALL hold: its name is exactly what [`Profile::create`] makes, it is a
    /// real directory owned by this user, its owner file names a pid, that pid is gone, and its
    /// browser is gone. Anything else, such as a folder someone made by hand, is left alone.
    /// Returns how many were removed.
    pub fn sweep_stale() -> std::io::Result<usize> {
        Self::sweep_stale_in(&std::env::temp_dir())
    }

    /// [`Profile::sweep_stale`] over `dir`.
    pub(crate) fn sweep_stale_in(dir: &Path) -> std::io::Result<usize> {
        use std::os::unix::fs::MetadataExt;
        // Not /proc/self: a non-dumpable process's /proc entries belong to root.
        let me = rustix::process::geteuid().as_raw();
        let mut n = 0;
        for entry in std::fs::read_dir(dir)? {
            let Ok(entry) = entry else { continue };
            if !is_profile_name(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.file_type().is_dir() || meta.uid() != me {
                continue;
            }
            // No owner file, or one that does not parse, means this program did not make it.
            let Some(owner) = owner_pid(&path) else {
                continue;
            };
            if pid_is_alive(owner) || browser_is_alive(&path) {
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

/// `<profile>/Default/Preferences`: password manager and autofill off.
fn write_preferences(profile: &Path) -> std::io::Result<()> {
    let default = profile.join("Default");
    private_dir(&default)?;
    let prefs = serde_json::to_string(&PREFERENCES).map_err(std::io::Error::other)?;
    std::fs::write(default.join("Preferences"), prefs)
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

/// `kharon-teach-` and exactly the random suffix `Profile::create` makes.
fn is_profile_name(name: &str) -> bool {
    name.strip_prefix(PROFILE_PREFIX)
        .is_some_and(|s| s.len() == SUFFIX_LEN && s.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The pid in the owner file. A missing, symlinked, non-regular, over-32-byte or unparseable
/// owner file gives `None`.
fn owner_pid(dir: &Path) -> Option<u32> {
    let file = dir.join(OWNER_FILE);
    let meta = std::fs::symlink_metadata(&file).ok()?;
    if !meta.file_type().is_file() || meta.len() > 32 {
        return None;
    }
    std::fs::read_to_string(&file)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

fn pid_is_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
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
        .is_some_and(pid_is_alive)
}

pub struct Launch<'a> {
    pub browser: &'a Path,
    pub profile: &'a Profile,
    pub first_url: &'a str,
    pub headless: bool,
}

/// The browser process and the process group it leads. Killing it kills the whole group, and a
/// drop kills it.
pub struct Browser {
    child: tokio::process::Child,
    /// The group id (the browser's own pid: it is launched as a group leader).
    #[cfg(unix)]
    group: Option<rustix::process::Pid>,
}

/// How long to wait for a killed group to be empty.
const GROUP_WAIT: Duration = Duration::from_secs(3);
const GROUP_POLL: Duration = Duration::from_millis(20);

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
        if l.first_url.starts_with('-') {
            // It would be read as a browser switch. Do not echo the value.
            return Err(BrowserError::Launch(
                "the first URL must not start with '-'".to_owned(),
            ));
        }
        let profile = l.profile.path();
        write_preferences(profile).map_err(launch_err)?;

        let mut user_data_dir = std::ffi::OsString::from("--user-data-dir=");
        user_data_dir.push(profile.as_os_str());
        let mut cmd = tokio::process::Command::new(l.browser);
        cmd.arg(user_data_dir)
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
        // Its own process group, so that "kill the browser" means the helpers too.
        #[cfg(unix)]
        cmd.process_group(0);
        let child = cmd.spawn().map_err(launch_err)?;
        #[cfg(unix)]
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw);
        // From here on a drop (including every early return) kills the group.
        let mut browser = Browser {
            child,
            #[cfg(unix)]
            group,
        };

        let file = profile.join("DevToolsActivePort");
        let deadline = tokio::time::Instant::now() + START_TIMEOUT;
        loop {
            match browser.child.try_wait() {
                Ok(Some(status)) => return Err(BrowserError::Launch(status.to_string())),
                Ok(None) => {}
                Err(e) => return Err(launch_err(e)),
            }
            if let Some(dt) = std::fs::read_to_string(&file)
                .ok()
                .and_then(|t| parse_devtools_active_port(&t))
            {
                return Ok((browser, dt));
            }
            if tokio::time::Instant::now() >= deadline {
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

    /// SIGKILL to every process in the browser's group. Safe to repeat.
    pub fn kill_group(&self) {
        #[cfg(unix)]
        if let Some(g) = self.group {
            let _ = rustix::process::kill_process_group(g, rustix::process::Signal::KILL);
        }
    }

    /// True once no process is left in the browser's group. A group that was never made counts
    /// as empty. Once the group has been seen empty the id is forgotten, so that no later signal
    /// can reach a group id the system has given to something else.
    pub fn group_is_empty(&mut self) -> bool {
        #[cfg(unix)]
        if let Some(g) = self.group {
            let empty = matches!(
                rustix::process::test_kill_process_group(g),
                Err(rustix::io::Errno::SRCH)
            );
            if empty {
                self.group = None;
            }
            return empty;
        }
        true
    }

    /// Kill the whole group, reap the browser, and wait up to 3 s for the group to be empty.
    pub async fn close(mut self) -> std::io::Result<()> {
        self.shut().await
    }

    /// The body of [`Browser::close`], on a borrow so a test can look at the browser afterwards.
    async fn shut(&mut self) -> std::io::Result<()> {
        self.kill_group();
        let reaped = self.child.wait().await.map(|_| ());
        let deadline = tokio::time::Instant::now() + GROUP_WAIT;
        while !self.group_is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(GROUP_POLL).await;
        }
        reaped
    }

    /// [`Browser::close`] for a place that cannot await (a `Drop`): it blocks the calling thread
    /// for at most 3 s.
    pub fn close_blocking(&mut self) {
        self.kill_group();
        let deadline = std::time::Instant::now() + GROUP_WAIT;
        loop {
            // Reaps the leader, which would otherwise stay a zombie and keep the group non-empty.
            let _ = self.child.try_wait();
            if self.group_is_empty() || std::time::Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(GROUP_POLL);
        }
    }
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.kill_group();
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

    /// A private directory for one test, removed when dropped. Its name does
    /// not start with the profile prefix, and nothing else sweeps it.
    struct Sandbox(PathBuf);

    impl Sandbox {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!(
                "kharon-sandbox-{tag}-{}-{:08x}",
                std::process::id(),
                rand::random::<u32>()
            ));
            std::fs::create_dir(&d).unwrap();
            Sandbox(d)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn mkdir(&self, name: &str) -> PathBuf {
            let d = self.0.join(name);
            std::fs::create_dir(&d).unwrap();
            d
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn profile_is_private_and_removed() {
        let sb = Sandbox::new("create");
        let p = Profile::create_in(sb.path()).unwrap();
        let path = p.path().to_owned();
        assert_eq!(path.parent().unwrap(), sb.path());
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
        // No staging directory is left behind.
        assert_eq!(std::fs::read_dir(sb.path()).unwrap().count(), 1);
        p.remove().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn profile_is_removed_on_drop() {
        let sb = Sandbox::new("drop");
        let p = Profile::create_in(sb.path()).unwrap();
        let path = p.path().to_owned();
        std::fs::write(path.join("f"), b"x").unwrap();
        drop(p);
        assert!(!path.exists());
    }

    /// A name of the shape `Profile::create` makes.
    const A: &str = "kharon-teach-aaaaaaaaaaaaaaaaaaaa";
    const B: &str = "kharon-teach-bbbbbbbbbbbbbbbbbbbb";
    const DEAD: &str = "4294967295";

    #[test]
    fn sweep_removes_a_leftover_and_counts_it() {
        let sb = Sandbox::new("stale");
        let d = dir_with_owner(&sb, A, DEAD);
        std::fs::write(d.join("f"), b"x").unwrap();
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 1);
        assert!(!d.exists());
    }

    #[test]
    fn sweep_leaves_a_directory_this_program_did_not_make() {
        let sb = Sandbox::new("foreign");
        // Owner-less, whatever the name.
        let foo = sb.mkdir("kharon-teach-foo");
        std::fs::write(foo.join("f"), b"x").unwrap();
        let versioned = sb.mkdir("kharon-teach-0.1.0-x86_64-linux");
        // The right name shape, but no owner file.
        let shaped = sb.mkdir(A);
        // The right shape and a junk owner file.
        let junk = dir_with_owner(&sb, B, "hello");
        // An owner file with a dead pid but a name this program never makes.
        let odd = dir_with_owner(&sb, "kharon-teach-scratch", DEAD);
        let short = dir_with_owner(&sb, "kharon-teach-aaaaaaaaaaaaaaaaaaa", DEAD);
        let punct = dir_with_owner(&sb, "kharon-teach-aaaaaaaaaaaaaaaaaa_-", DEAD);
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 0);
        for d in [foo, versioned, shaped, junk, odd, short, punct] {
            assert!(d.exists(), "{} was removed", d.display());
        }
    }

    #[test]
    fn profile_name_shape() {
        assert!(is_profile_name(A));
        assert!(!is_profile_name("kharon-teach-"));
        assert!(!is_profile_name("kharon-teach-aaaaaaaaaaaaaaaaaaaaa"));
        assert!(!is_profile_name(".kharon-teach-new-aaaaaaaaaaaaaaaaaaaa"));
        assert!(!is_profile_name("other-aaaaaaaaaaaaaaaaaaaa"));
        // Whatever `create` makes passes.
        let sb = Sandbox::new("shape");
        let p = Profile::create_in(sb.path()).unwrap();
        assert!(is_profile_name(
            &p.path().file_name().unwrap().to_string_lossy()
        ));
    }

    #[test]
    fn sweep_leaves_other_directories() {
        let sb = Sandbox::new("other");
        let d = sb.mkdir("other-keep");
        let staging = sb.mkdir(".kharon-teach-new-x");
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 0);
        assert!(d.exists() && staging.exists());
    }

    #[test]
    fn sweep_leaves_a_symlink_and_its_target() {
        let sb = Sandbox::new("link");
        let target = sb.mkdir("other-tgt");
        std::fs::write(target.join("f"), b"x").unwrap();
        let link = sb.path().join(A);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 0);
        assert!(target.join("f").exists());
        assert!(std::fs::symlink_metadata(&link).is_ok());
    }

    // An addition to the brief: a profile whose SingletonLock names a live
    // process is a running recorder's profile and must survive a sweep.
    #[test]
    fn sweep_skips_a_profile_whose_browser_is_alive() {
        let sb = Sandbox::new("live");
        let d = dir_with_owner(&sb, A, DEAD);
        std::os::unix::fs::symlink(
            format!("host-{}", std::process::id()),
            d.join("SingletonLock"),
        )
        .unwrap();
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 0);
        assert!(d.exists());
    }

    fn dead_pid() -> u32 {
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let pid = c.id();
        c.wait().unwrap();
        pid
    }

    fn dir_with_owner(sb: &Sandbox, name: &str, owner: &str) -> PathBuf {
        let d = sb.mkdir(name);
        std::fs::write(d.join(OWNER_FILE), owner).unwrap();
        d
    }

    #[test]
    fn sweep_skips_a_profile_owned_by_this_process() {
        let sb = Sandbox::new("mine");
        let d = dir_with_owner(&sb, A, &std::process::id().to_string());
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 0);
        assert!(d.exists());
    }

    #[test]
    fn sweep_removes_a_profile_owned_by_a_dead_process() {
        let sb = Sandbox::new("dead");
        let d = dir_with_owner(&sb, A, &dead_pid().to_string());
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 1);
        assert!(!d.exists());
    }

    #[test]
    fn sweep_treats_an_owner_symlink_as_no_owner() {
        let sb = Sandbox::new("ownlink");
        let d = sb.mkdir(A);
        let real = d.join("real");
        std::fs::write(&real, DEAD).unwrap();
        std::os::unix::fs::symlink(&real, d.join(OWNER_FILE)).unwrap();
        // No owner is not a stale owner: it is a directory this program cannot vouch for.
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 0);
        assert!(d.exists());
    }

    #[test]
    fn sweep_leaves_a_junk_or_oversized_owner_alone() {
        let sb = Sandbox::new("junk");
        let a = dir_with_owner(&sb, A, "not a pid");
        let big = format!("{DEAD}{}", " ".repeat(40));
        let b = dir_with_owner(&sb, B, &big);
        assert_eq!(Profile::sweep_stale_in(sb.path()).unwrap(), 0);
        assert!(a.exists() && b.exists());
    }

    /// A non-dumpable process's `/proc/self` belongs to root, so a sweep that learned its uid
    /// from there would compare against 0 and never remove anything. The check runs in a child
    /// process (this test binary again) so the parent stays dumpable. On newer kernels
    /// `/proc/self` stays owned by the user after that call, so the old code passes this test
    /// too: it exercises the sweep under `PR_SET_DUMPABLE 0` and is not proof of the fix.
    #[test]
    fn sweep_still_removes_a_leftover_when_the_process_is_non_dumpable() {
        const MARK: &str = "KHARON_TEACH_SWEEP_NONDUMPABLE_DIR";
        if let Some(dir) = std::env::var_os(MARK) {
            use rustix::process::{DumpableBehavior, set_dumpable_behavior};
            set_dumpable_behavior(DumpableBehavior::NotDumpable).unwrap();
            let removed = Profile::sweep_stale_in(Path::new(&dir)).unwrap();
            assert_eq!(removed, 1, "the sweep did not remove the leftover");
            return;
        }
        let sb = Sandbox::new("nondump");
        let d = dir_with_owner(&sb, A, DEAD);
        std::fs::write(d.join("f"), b"x").unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser::tests::sweep_still_removes_a_leftover_when_the_process_is_non_dumpable",
                "--test-threads=1",
            ])
            .env(MARK, sb.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(!d.exists());
    }

    /// A browser stand-in: a `sleep` that leads its own process group.
    fn fake_browser() -> Browser {
        let mut cmd = tokio::process::Command::new("sleep");
        cmd.arg("30").kill_on_drop(true);
        cmd.process_group(0);
        let child = cmd.spawn().unwrap();
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw);
        assert!(group.is_some());
        Browser { child, group }
    }

    #[tokio::test]
    async fn the_group_id_is_forgotten_once_the_group_is_closed_and_empty() {
        let mut b = fake_browser();
        assert!(b.group.is_some());
        assert!(!b.group_is_empty(), "a live group is not empty");
        assert!(b.group.is_some(), "a live group's id is kept");
        b.shut().await.unwrap();
        assert!(b.group.is_none(), "the id of an empty group is dropped");
        // Nothing is signalled any more: kill_group has no id to signal.
        b.kill_group();
        assert!(b.group_is_empty());
    }

    #[tokio::test]
    async fn close_blocking_also_forgets_the_group_id() {
        let mut b = fake_browser();
        b.close_blocking();
        assert!(b.group.is_none());
    }

    #[test]
    fn preferences_turn_off_the_password_manager_and_autofill() {
        let sb = Sandbox::new("prefs");
        write_preferences(sb.path()).unwrap();
        assert_eq!(
            std::fs::metadata(sb.path().join("Default")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read_to_string(sb.path().join("Default/Preferences")).unwrap(),
            r#"{"credentials_enable_service":false,"profile":{"password_manager_enabled":false},"autofill":{"profile_enabled":false,"credit_card_enabled":false}}"#
        );
    }

    #[tokio::test]
    async fn a_first_url_that_looks_like_a_switch_is_refused() {
        let sb = Sandbox::new("url");
        let profile = Profile::create_in(sb.path()).unwrap();
        let err = match Browser::launch(Launch {
            browser: Path::new("/nonexistent/chrome"),
            profile: &profile,
            first_url: "--secret-switch",
            headless: true,
        })
        .await
        {
            Err(e) => e,
            Ok(_) => panic!("launched"),
        };
        let BrowserError::Launch(msg) = err else {
            panic!("wrong error");
        };
        assert_eq!(msg, "the first URL must not start with '-'");
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
        let sb = Sandbox::new("bin");
        let dir = sb.path().to_owned();
        for n in ["google-chrome", "chromium"] {
            let f = dir.join(n);
            std::fs::write(&f, b"#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let found = find_browser_in(None, dir.as_os_str()).unwrap();
        assert_eq!(found, dir.join("chromium"));
    }

    #[test]
    fn snap_paths_are_recognised() {
        for snap in [
            "/snap/bin/chromium",
            "/snap/chromium/current/usr/lib/chromium-browser/chrome",
            // What `/snap/bin/chromium` resolves to once canonicalised.
            "/usr/bin/snap",
        ] {
            assert!(is_snap_path(Path::new(snap)), "{snap}");
        }
        for other in [
            "/usr/bin/chromium",
            "/usr/bin/google-chrome",
            "/opt/google/chrome/chrome",
            "/home/me/snapshots/chrome",
            "/usr/bin/snapd",
        ] {
            assert!(!is_snap_path(Path::new(other)), "{other}");
        }
    }

    fn executable(dir: &Path, name: &str, body: &str) -> PathBuf {
        let f = dir.join(name);
        std::fs::write(&f, body).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        f
    }

    #[test]
    fn a_snap_candidate_is_skipped_for_the_next_one_in_order() {
        let sb = Sandbox::new("snaporder");
        let a = sb.mkdir("a");
        let b = sb.mkdir("b");
        executable(&a, "chromium", "#!/bin/sh\n");
        let chrome = executable(&b, "google-chrome", "#!/bin/sh\n");
        let path = std::env::join_paths([&a, &b]).unwrap();
        // The stub calls only the first candidate a snap.
        let is_snap = |p: &Path| p == a.join("chromium");
        assert_eq!(find_browser_with(None, &path, &is_snap).unwrap(), chrome);
        // With nothing to fall back on, the error says why.
        let only_a = std::env::join_paths([&a]).unwrap();
        assert!(matches!(
            find_browser_with(None, &only_a, &is_snap),
            Err(BrowserError::SnapOnly)
        ));
        // No candidate at all is still NotFound.
        let empty = std::env::join_paths([sb.mkdir("empty")]).unwrap();
        assert!(matches!(
            find_browser_with(None, &empty, &is_snap),
            Err(BrowserError::NotFound)
        ));
    }

    #[test]
    fn an_explicit_snap_browser_is_used_as_given() {
        let sb = Sandbox::new("snapexplicit");
        let f = executable(sb.path(), "chromium", "#!/bin/sh\n");
        let always = |_: &Path| true;
        assert_eq!(
            find_browser_with(Some(&f), OsStr::new(""), &always).unwrap(),
            f
        );
    }

    #[test]
    fn the_snap_only_message_says_what_to_do() {
        assert_eq!(
            BrowserError::SnapOnly.to_string(),
            "the only browser found is a snap package, which cannot use the recorder's profile folder; install Google Chrome or pass --browser <path>"
        );
    }

    #[test]
    fn a_wrapper_script_that_starts_a_snap_is_a_snap_and_a_plain_script_is_not() {
        let sb = Sandbox::new("snapwrap");
        let wrapper = executable(
            sb.path(),
            "chromium-browser",
            "#!/bin/sh\nexec /snap/bin/chromium \"$@\"\n",
        );
        let plain = executable(
            sb.path(),
            "chromium",
            "#!/bin/sh\nexec /opt/chrome \"$@\"\n",
        );
        assert!(is_snap_browser(&wrapper));
        assert!(!is_snap_browser(&plain));
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
    fn accepts_a_bom_and_rejects_a_port_over_u16() {
        assert_eq!(
            parse_devtools_active_port("\u{feff}45123\n/devtools/browser/abc\n")
                .unwrap()
                .port,
            45123
        );
        assert!(parse_devtools_active_port("99999\n/devtools/browser/abc\n").is_none());
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
