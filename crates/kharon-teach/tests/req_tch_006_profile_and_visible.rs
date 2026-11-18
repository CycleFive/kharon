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
