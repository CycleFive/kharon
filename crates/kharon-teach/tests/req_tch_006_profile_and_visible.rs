//! SPEC req_tch_006: the browser keeps nothing from a login, and the profile is always removed.

mod support;

use kharon_recording::EndedBy;
use kharon_teach::session::{End, Outcome};
use std::path::{Path, PathBuf};
use std::time::Duration;
use support::{PASS, Run, USER};

/// Row counts of `tables` in a copy of the SQLite file at `db`; a missing table counts as 0.
/// `None` when `python3` is absent.
fn row_counts(db: &Path, tables: &[&str]) -> Option<Vec<u64>> {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let copy = std::env::temp_dir().join(format!(
        "kharon-teach-test-copy-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&copy);
    std::fs::copy(db, &copy).unwrap();
    // A write-ahead log or journal beside the database holds rows the main file does not yet.
    let siblings: Vec<PathBuf> = ["-wal", "-journal"]
        .iter()
        .map(|suffix| {
            let mut from = db.as_os_str().to_owned();
            from.push(suffix);
            let mut to = copy.as_os_str().to_owned();
            to.push(suffix);
            let (from, to) = (PathBuf::from(from), PathBuf::from(to));
            if from.exists() {
                let _ = std::fs::copy(&from, &to);
            }
            to
        })
        .collect();
    let script = [
        "import sqlite3,sys",
        "c=sqlite3.connect(sys.argv[1])",
        "for t in sys.argv[2:]:",
        "    try:",
        "        print(c.execute('select count(*) from ' + t).fetchone()[0])",
        "    except sqlite3.Error:",
        "        print(0)",
    ]
    .join("\n");
    let out = std::process::Command::new("python3")
        .args(["-I", "-c", &script])
        .arg(&copy)
        .args(tables)
        .output();
    let _ = std::fs::remove_file(&copy);
    for sib in &siblings {
        let _ = std::fs::remove_file(sib);
    }
    let out = match out {
        Ok(o) if o.status.success() => o,
        Ok(o) => panic!(
            "python3 failed reading {}: {} {}",
            db.display(),
            o.status,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(_) => {
            eprintln!("SKIP: python3 is not installed");
            return None;
        }
    };
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().parse().unwrap())
            .collect(),
    )
}

/// True when `path` goes away and stays away: a second look a second later, because a helper
/// process of a killed browser can recreate files in a directory that was just removed.
async fn gone(path: &Path) -> bool {
    for _ in 0..100 {
        if !path.exists() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            return !path.exists();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn type_a_login(run: &Run) {
    run.begin("/form").await;
    run.person.type_into("input[name=user]", USER).await;
    run.person.type_into("input[name=pass]", PASS).await;
}

#[tokio::test]
async fn nothing_is_saved_in_the_profile_during_a_login() {
    let Some(run) = Run::start("nothing_saved", "/form").await else {
        return;
    };
    type_a_login(&run).await;
    run.person.click("#go").await;
    run.person.wait_for_path("/home").await;
    let profile = run.ready.profile_dir.clone();
    assert!(profile.is_dir(), "the profile directory exists");
    // At least one of the two databases is there to be looked at (Chromium makes them lazily).
    let dbs = ["Login Data", "Web Data"].map(|f| profile.join("Default").join(f));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !dbs.iter().any(|d| d.exists()) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "neither Login Data nor Web Data appeared in the profile"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for (db, tables) in dbs.iter().zip([
        &["logins"][..],
        &["autofill", "autofill_profiles", "credit_cards"][..],
    ]) {
        if !db.exists() {
            continue;
        }
        if let Some(counts) = row_counts(db, tables) {
            assert!(
                counts.iter().all(|n| *n == 0),
                "{}: {counts:?}",
                db.display()
            );
        }
    }
    // The preferences the recorder wrote are still in force after the login.
    #[derive(serde::Deserialize)]
    struct Prefs {
        credentials_enable_service: bool,
    }
    let prefs: Prefs = serde_json::from_str(
        &std::fs::read_to_string(profile.join("Default").join("Preferences")).unwrap(),
    )
    .unwrap();
    assert!(!prefs.credentials_enable_service);
    let _ = run.finish(End::Discard).await;
}

#[tokio::test]
async fn profile_is_gone_after_confirm() {
    let Some(run) = Run::start("gone_after_confirm", "/form").await else {
        return;
    };
    let profile = run.ready.profile_dir.clone();
    type_a_login(&run).await;
    run.person.click("#go").await;
    run.person.wait_for_path("/home").await;
    assert!(matches!(
        run.finish(End::Confirmed).await,
        Outcome::Recorded(_)
    ));
    assert!(gone(&profile).await, "the profile is still there");
}

#[tokio::test]
async fn profile_is_gone_after_discard() {
    let Some(run) = Run::start("gone_after_discard", "/form").await else {
        return;
    };
    let profile = run.ready.profile_dir.clone();
    type_a_login(&run).await;
    assert!(matches!(run.finish(End::Discard).await, Outcome::Discarded));
    assert!(gone(&profile).await, "the profile is still there");
}

#[tokio::test]
async fn closing_the_window_ends_unconfirmed() {
    let Some(mut run) = Run::start("close_mid_login", "/form").await else {
        return;
    };
    let profile = run.ready.profile_dir.clone();
    type_a_login(&run).await;
    let begun = std::time::Instant::now();
    run.person.close_all_pages().await;
    match run.wait().await {
        Outcome::Recorded(r) => {
            assert_eq!(r.ended_by, EndedBy::WindowClosed);
            assert!(!r.success_confirmed);
        }
        _ => panic!("expected a recording"),
    }
    assert!(begun.elapsed() < Duration::from_secs(10));
    assert!(gone(&profile).await, "the profile is still there");
}

#[tokio::test]
async fn closing_before_start_is_never_started() {
    let Some(mut run) = Run::start("close_before_start", "/form").await else {
        return;
    };
    let profile = run.ready.profile_dir.clone();
    run.person.close_all_pages().await;
    assert!(matches!(run.wait().await, Outcome::NeverStarted));
    assert!(gone(&profile).await, "the profile is still there");
}

#[tokio::test]
async fn dropping_the_future_removes_the_profile() {
    let Some(run) = Run::start("drop_future", "/form").await else {
        return;
    };
    let profile = run.ready.profile_dir.clone();
    let port = run.ready.devtools_port;
    type_a_login(&run).await;
    // The Ctrl-C path: the task is dropped mid-recording.
    run.abort();
    assert!(gone(&profile).await, "the profile is still there");
    // The browser went with it: its DevTools port stops answering.
    let mut closed = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            closed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(closed, "the browser is still listening");
}

#[tokio::test]
async fn a_stale_profile_is_swept_at_the_next_start() {
    // What an earlier, killed run leaves: the name this program makes, and an owner file naming
    // a pid that is gone.
    let stale: PathBuf =
        std::env::temp_dir().join(format!("kharon-teach-{:020}", std::process::id()));
    std::fs::create_dir_all(stale.join("Default")).unwrap();
    std::fs::write(stale.join("Default").join("Preferences"), "{}").unwrap();
    std::fs::write(stale.join("kharon-teach.owner"), "4294967295").unwrap();
    let Some(run) = Run::start("stale_swept", "/form").await else {
        let _ = std::fs::remove_dir_all(&stale);
        return;
    };
    // Tests in this file start at the same time, and any of them may have done the sweep.
    assert!(!stale.exists(), "the stale profile was not swept");
    let _ = run.finish(End::Discard).await;
}

#[tokio::test]
async fn a_directory_the_program_did_not_make_survives_the_sweep() {
    // Same prefix, but no owner file, a junk owner file, or a name of another shape.
    let id = std::process::id();
    let base = std::env::temp_dir();
    let ownerless = base.join(format!("kharon-teach-foo-{id}"));
    let shaped = base.join(format!(
        "kharon-teach-{:020}",
        u64::from(id) + 1_000_000_000_000
    ));
    let junk = base.join(format!(
        "kharon-teach-{:020}",
        u64::from(id) + 2_000_000_000_000
    ));
    for d in [&ownerless, &shaped, &junk] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("keep"), "x").unwrap();
    }
    std::fs::write(junk.join("kharon-teach.owner"), "not a pid").unwrap();
    let kept = |d: &Path| d.join("keep").exists();
    let ran = match Run::start("sweep_keeps_foreign", "/form").await {
        Some(run) => {
            let _ = run.finish(End::Discard).await;
            true
        }
        None => false,
    };
    let all_kept = [&ownerless, &shaped, &junk].iter().all(|d| kept(d));
    for d in [&ownerless, &shaped, &junk] {
        let _ = std::fs::remove_dir_all(d);
    }
    if ran {
        assert!(all_kept, "a directory the program did not make was swept");
    }
}

#[test]
fn the_shipped_main_never_asks_for_headless() {
    let sources = support::shipped_sources();
    let mut env_reads = Vec::new();
    for (p, shipped) in &sources {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            !shipped.contains("headless: true"),
            "{} asks for headless",
            p.display()
        );
        // Every `headless:` initializer outside the session and the browser launcher is the
        // literal `false` or a pass-through of the hook inside `run_with`.
        if name != "session.rs" && name != "browser.rs" {
            for (n, line) in shipped.lines().enumerate() {
                let t = line.trim();
                if t.starts_with("//") || !t.contains("headless:") {
                    continue;
                }
                let ok = t == "headless: false," || t == "headless: hooks.headless,";
                let decl = t.starts_with("pub headless: bool");
                assert!(ok || decl, "{}:{}: {t}", p.display(), n + 1);
            }
        }
        for pat in [
            "env::var(",
            "env::var_os(",
            "env::vars(",
            "env::vars_os(",
            "use std::env::{",
            "use std::env::var",
            "use std::env;",
        ] {
            for (n, line) in shipped.lines().enumerate() {
                if !line.trim_start().starts_with("//") && line.contains(pat) {
                    env_reads.push(format!("{name}:{}: {}", n + 1, line.trim()));
                }
            }
        }
    }
    // Browser discovery reads PATH, and that is the only read of the environment.
    assert_eq!(env_reads.len(), 1, "{env_reads:?}");
    assert!(
        env_reads[0].starts_with("browser.rs:") && env_reads[0].contains("var_os(\"PATH\")"),
        "{env_reads:?}"
    );
}

/// A `kharon-teach-*` profile directory in the temp directory whose owner file holds `pid`.
fn profile_of(pid: u32) -> Option<PathBuf> {
    std::fs::read_dir(std::env::temp_dir())
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("kharon-teach-"))
        .map(|e| e.path())
        .find(|p| {
            std::fs::read_to_string(p.join("kharon-teach.owner"))
                .is_ok_and(|t| t.trim() == pid.to_string())
        })
}

/// Runs the built program against a browser that never opens a DevTools port, sends it `signal`,
/// and checks: exit code 1, the profile removed, no file written, all within 10 s.
fn interrupted_by(signal: &str) {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "kharon-sig-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let fake = dir.join("fake-browser");
    // The shell stays, with the switches on its command line, as a real browser's would be.
    std::fs::write(
        &fake,
        "#!/bin/sh\nexec sh -c 'sleep 30; true' fake-browser \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = dir.join("login.kharon-recording.json");
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kharon-teach"))
        .args(["--yes", "https://ex.test/login", "--browser"])
        .arg(&fake)
        .arg("--out")
        .arg(&out)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let limit = std::time::Instant::now() + Duration::from_secs(10);
    let profile = loop {
        if let Some(p) = profile_of(pid) {
            break p;
        }
        assert!(
            std::time::Instant::now() < limit,
            "the program made no profile in 10 s"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let sent = std::process::Command::new("kill")
        .args([&format!("-{signal}"), &pid.to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if std::time::Instant::now() >= limit + Duration::from_secs(10) {
            let _ = child.kill();
            panic!("the program did not stop after {signal}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(1), "exit status after {signal}");
    let mut err = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).unwrap();
    assert!(err.contains("Interrupted. Nothing was saved."), "{err}");
    assert!(!profile.exists(), "the profile is still there");
    assert!(!out.exists(), "a file was written");
    assert!(
        no_process_on(&profile),
        "a process on the profile is still running after {signal}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// True when no process has `--user-data-dir=<profile>` on its command line. Polls up to 5 s.
fn no_process_on(profile: &Path) -> bool {
    let needle = format!("--user-data-dir={}", profile.display());
    let limit = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let any = std::fs::read_dir("/proc").unwrap().flatten().any(|e| {
            std::fs::read(e.path().join("cmdline"))
                .is_ok_and(|c| c.split(|b| *b == 0).any(|arg| arg == needle.as_bytes()))
        });
        if !any {
            return true;
        }
        if std::time::Instant::now() >= limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn sigint_exits_1_and_removes_the_profile() {
    interrupted_by("INT");
}

#[test]
fn sigterm_exits_1_and_removes_the_profile() {
    interrupted_by("TERM");
}

#[test]
fn sighup_exits_1_and_removes_the_profile() {
    interrupted_by("HUP");
}

#[test]
fn sigquit_exits_1_and_removes_the_profile() {
    interrupted_by("QUIT");
}

async fn outcome_is_unconfirmed_or_never_started(outcome: Outcome) {
    match outcome {
        Outcome::Recorded(r) => {
            assert_eq!(r.ended_by, EndedBy::WindowClosed);
            assert!(!r.success_confirmed);
        }
        Outcome::NeverStarted => {}
        Outcome::Discarded => panic!("a dead browser is not a discard"),
    }
}

#[tokio::test]
async fn a_browser_killed_from_outside_ends_the_session_and_the_profile_stays_gone() {
    let Some(mut run) = Run::start("killed_outside", "/form").await else {
        return;
    };
    let profile = run.ready.profile_dir.clone();
    type_a_login(&run).await;
    let pid = support::Person::browser_pid(&profile).expect("the browser process");
    let status = std::process::Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    outcome_is_unconfirmed_or_never_started(run.wait().await).await;
    assert!(gone(&profile).await, "the profile is still there");
}

#[tokio::test]
async fn a_browser_that_quits_by_itself_ends_the_session_and_the_profile_stays_gone() {
    let Some(mut run) = Run::start("quits_itself", "/form").await else {
        return;
    };
    let profile = run.ready.profile_dir.clone();
    type_a_login(&run).await;
    run.person.close_browser().await;
    outcome_is_unconfirmed_or_never_started(run.wait().await).await;
    assert!(gone(&profile).await, "the profile is still there");
}

/// The shipped binary, past `Ready`, in a browser without a display.
struct Live {
    child: std::process::Child,
    /// Held open and never written to: end of input must not end the recording.
    _stdin: std::process::ChildStdin,
    stdout: std::sync::Arc<std::sync::Mutex<String>>,
    dir: PathBuf,
    out: PathBuf,
    profile: PathBuf,
    _fixture: support::Fixture,
    _permit: tokio::sync::SemaphorePermit<'static>,
}

impl Live {
    /// `None` when there is no browser and none is required.
    async fn start(test: &str) -> Option<Live> {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let chromium = support::chromium_or_skip(test)?;
        let permit = support::browser_permit().await;
        let fixture = support::Fixture::start().await;
        let dir = std::env::temp_dir().join(format!(
            "kharon-live-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir(&dir).unwrap();
        // Only this test wrapper adds the switch; the program believes it launched a visible browser.
        let wrapper = dir.join("browser");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexec {} --headless=new \"$@\"\n",
                chromium.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = dir.join("login.kharon-recording.json");
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kharon-teach"))
            .args(["--yes", fixture.url("/form").as_str(), "--browser"])
            .arg(&wrapper)
            .arg("--out")
            .arg(&out)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let mut pipe = child.stdout.take().unwrap();
        let sink = stdout.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock()
                    .unwrap()
                    .push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        let live = Live {
            profile: PathBuf::new(),
            child,
            _stdin: stdin,
            stdout,
            dir,
            out,
            _fixture: fixture,
            _permit: permit,
        };
        let mut live = live;
        let limit = std::time::Instant::now() + Duration::from_secs(40);
        while !live
            .printed()
            .contains("Press Enter once you are logged in")
        {
            assert!(
                std::time::Instant::now() < limit,
                "the end prompt never showed"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        live.profile = profile_of(live.child.id()).expect("the profile exists");
        Some(live)
    }

    fn printed(&self) -> String {
        self.stdout.lock().unwrap().clone()
    }

    /// The exit code, or `None` when the program is still running after `secs`.
    async fn exit_within(&mut self, secs: u64) -> Option<Option<i32>> {
        let limit = std::time::Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return Some(s.code());
            }
            if std::time::Instant::now() >= limit {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// After the prompt: send `signal`, expect exit 1 without Enter, no file, no profile and no
/// browser process left.
async fn signal_after_the_prompt(signal: &str, test: &str) {
    let Some(mut live) = Live::start(test).await else {
        return;
    };
    let pid = live.child.id().to_string();
    assert!(
        std::process::Command::new("kill")
            .args([&format!("-{signal}"), &pid])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        live.exit_within(10).await,
        Some(Some(1)),
        "the program did not exit on SIG{signal} without Enter"
    );
    assert!(!live.out.exists(), "a file was written");
    assert!(gone(&live.profile).await, "the profile is still there");
    assert!(
        no_process_on(&live.profile),
        "a browser process is still running after SIG{signal}"
    );
}

#[tokio::test]
async fn sigint_after_the_prompt_exits_1_without_enter() {
    signal_after_the_prompt("INT", "sigint_after_prompt").await;
}

#[tokio::test]
async fn sighup_after_the_prompt_exits_1_and_leaves_no_browser() {
    signal_after_the_prompt("HUP", "sighup_after_prompt").await;
}

#[tokio::test]
async fn sigquit_after_the_prompt_exits_1_and_leaves_no_browser() {
    signal_after_the_prompt("QUIT", "sigquit_after_prompt").await;
}

#[tokio::test]
async fn closing_the_window_after_the_prompt_saves_and_exits_without_enter() {
    use std::os::unix::fs::PermissionsExt;
    let Some(mut live) = Live::start("close_after_prompt").await else {
        return;
    };
    let port: u16 = std::fs::read_to_string(live.profile.join("DevToolsActivePort"))
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let person = support::Person::connect(port).await;
    person.click("a").await;
    person.wait_for_path("/form").await;
    person.type_into("input[name=user]", USER).await;
    person.type_into("input[name=pass]", PASS).await;
    person.close_all_pages().await;
    assert_eq!(
        live.exit_within(10).await,
        Some(Some(0)),
        "the program did not exit after the window closed"
    );
    assert!(live.printed().contains("Saved:"), "{}", live.printed());
    let mode = std::fs::metadata(&live.out).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let rec = kharon_recording::Recording::from_json(&std::fs::read_to_string(&live.out).unwrap())
        .unwrap();
    assert_eq!(rec.ended_by, EndedBy::WindowClosed);
    assert!(!rec.success_confirmed);
}
