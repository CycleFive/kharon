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

async fn gone(path: &Path) -> bool {
    for _ in 0..100 {
        if !path.exists() {
            return true;
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
    for (file, tables) in [
        ("Login Data", &["logins"][..]),
        (
            "Web Data",
            &["autofill", "autofill_profiles", "credit_cards"][..],
        ),
    ] {
        let db = profile.join("Default").join(file);
        if !db.exists() {
            eprintln!("no {file} in the profile: nothing was saved");
            continue;
        }
        if let Some(counts) = row_counts(&db, tables) {
            assert!(counts.iter().all(|n| *n == 0), "{file}: {counts:?}");
        }
    }
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
    let stale: PathBuf =
        std::env::temp_dir().join(format!("kharon-teach-stale-test-{}", std::process::id()));
    std::fs::create_dir_all(stale.join("Default")).unwrap();
    std::fs::write(stale.join("Default").join("Preferences"), "{}").unwrap();
    let Some(run) = Run::start("stale_swept", "/form").await else {
        let _ = std::fs::remove_dir_all(&stale);
        return;
    };
    // Tests in this file start at the same time, and any of them may have done the sweep.
    assert!(!stale.exists(), "the stale profile was not swept");
    let _ = run.finish(End::Discard).await;
}

#[test]
fn the_shipped_main_never_asks_for_headless() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    for p in files {
        let text = std::fs::read_to_string(&p).unwrap();
        let shipped = text.split("#[cfg(test)]").next().unwrap();
        assert!(
            !shipped.contains("headless: true"),
            "{} asks for headless",
            p.display()
        );
        // Browser discovery reads PATH; nothing else reads the environment.
        if !p.ends_with("browser.rs") {
            assert!(
                !shipped.contains("env::var"),
                "{} reads the environment",
                p.display()
            );
        }
    }
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
    std::fs::write(&fake, "#!/bin/sh\nexec sleep 30\n").unwrap();
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
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sigint_exits_1_and_removes_the_profile() {
    interrupted_by("INT");
}

#[test]
fn sigterm_exits_1_and_removes_the_profile() {
    interrupted_by("TERM");
}
