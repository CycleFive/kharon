//! Teach-mode recorder for kharon (#361).

pub mod body;
pub mod browser;
pub mod capture;
pub mod cdp;
pub mod cli;
pub mod events;
pub mod marker;
pub mod notice;
pub mod session;
pub mod site;
pub mod strip;
#[doc(hidden)]
pub mod testing;

use cli::{
    Cli, Command, Refusal, check_dir_writable, check_out_path, default_file_name,
    default_file_name_at, summary, validate_login_url,
};
use kharon_recording::Recording;
use session::{End, Outcome, Ready, RecordOptions, record};
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::oneshot;

/// How a run ended; the process exit code is its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// A file was written, or the recording was discarded, or nothing was asked for.
    Done = 0,
    /// Anything else.
    Failed = 1,
    /// A refusal: nothing was started.
    Refused = 2,
}

impl From<Exit> for std::process::ExitCode {
    fn from(e: Exit) -> Self {
        std::process::ExitCode::from(e as u8)
    }
}

/// What tests may change. The shipped program never does: there is no flag and no environment
/// variable for it.
#[doc(hidden)]
pub struct Hooks {
    pub headless: bool,
    /// Receives a copy of the session's `Ready` once the notice page is showing.
    pub ready: Option<oneshot::Sender<Ready>>,
}

/// The whole program. Prompts and results go to `stdout`; refusals and errors to `stderr`, one
/// line each, starting `kharon-teach: `.
pub async fn run(
    cli: Cli,
    stdin: impl AsyncBufRead + Unpin,
    stdout: impl Write,
    stderr: impl Write,
) -> Exit {
    run_with(
        cli,
        stdin,
        stdout,
        stderr,
        Hooks {
            headless: false,
            ready: None,
        },
    )
    .await
}

fn fail(stderr: &mut impl Write, what: &dyn std::fmt::Display, exit: Exit) -> Exit {
    let _ = writeln!(stderr, "kharon-teach: {what}");
    exit
}

/// Where the recording goes.
enum Target {
    /// `--out`: exactly this path.
    Explicit(PathBuf),
    /// No `--out`: a generated name in the current directory.
    Here,
}

#[doc(hidden)]
#[derive(Clone, Copy)]
pub enum Naming {
    Default,
    Explicit,
}

/// Creates `first` (mode 0600, never replacing a file). If it exists, the same name with `.1`
/// to `.9` added (before the `.kharon-recording.json` ending for a generated name, at the end
/// for an `--out` name) is tried, so a demonstration is not lost to a name clash.
#[doc(hidden)]
pub fn write_new(
    first: &Path,
    naming: Naming,
    text: &str,
) -> Result<PathBuf, (PathBuf, std::io::Error)> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = first
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    for n in 0..10 {
        let path = if n == 0 {
            first.to_owned()
        } else {
            let numbered = match (naming, name.strip_suffix(cli::FILE_SUFFIX)) {
                (Naming::Default, Some(stem)) => format!("{stem}.{n}{}", cli::FILE_SUFFIX),
                _ => format!("{name}.{n}"),
            };
            first.with_file_name(numbered)
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut f) => {
                return match f.write_all(text.as_bytes()).and_then(|()| f.flush()) {
                    Ok(()) => Ok(path),
                    Err(e) => {
                        // Never leave a truncated file where the next run would refuse to write.
                        drop(f);
                        let _ = std::fs::remove_file(&path);
                        Err((path, e))
                    }
                };
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err((path, e)),
        }
    }
    Err((
        first.to_owned(),
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "ten files of that name already exist",
        ),
    ))
}

/// `kharon-teach show <file>`.
fn show(file: &Path, stdout: &mut impl Write, stderr: &mut impl Write) -> Exit {
    use std::io::Read;
    const CAP: u64 = 16 * 1024 * 1024;
    let read = || -> Result<Recording, Refusal> {
        let unreadable = |e: std::io::Error| Refusal::Unreadable(file.to_owned(), e.to_string());
        let f = std::fs::File::open(file).map_err(unreadable)?;
        let mut bytes = Vec::new();
        f.take(CAP + 1)
            .read_to_end(&mut bytes)
            .map_err(unreadable)?;
        if bytes.len() as u64 > CAP {
            return Err(Refusal::TooLarge(file.to_owned()));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| Refusal::NotARecording(file.to_owned(), "not text".to_owned()))?;
        Recording::from_json(&text)
            .map_err(|e| Refusal::NotARecording(file.to_owned(), e.to_string()))
    };
    match read() {
        Ok(r) => {
            let _ = stdout.write_all(summary(&r).as_bytes());
            Exit::Done
        }
        Err(e) => fail(stderr, &e, Exit::Refused),
    }
}

/// Everything checked before the notice.
struct Prepared {
    url: url::Url,
    browser: PathBuf,
    target: Target,
}

fn prepare(cli: &Cli) -> Result<Prepared, Refusal> {
    let url = validate_login_url(cli.login_url.as_deref().ok_or(Refusal::NoUrl)?)?;
    let browser = browser::find_browser(cli.browser.as_deref())
        .map_err(|e| Refusal::NoBrowser(e.to_string()))?;
    let target = match &cli.out {
        Some(p) => {
            check_out_path(p)?;
            Target::Explicit(p.clone())
        }
        None => {
            check_dir_writable(Path::new("."))?;
            Target::Here
        }
    };
    Ok(Prepared {
        url,
        browser,
        target,
    })
}

/// Linux: no core dump and no ptrace by another process, as `kharon` does (REQ-MEM-001).
#[cfg(target_os = "linux")]
fn harden_process() -> Result<(), String> {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
    set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|e| e.to_string())?;
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn harden_process() -> Result<(), String> {
    Ok(())
}

enum Ended {
    Finished(Result<Outcome, session::SessionError>),
    Interrupted,
}

#[doc(hidden)]
pub async fn run_with(
    cli: Cli,
    mut stdin: impl AsyncBufRead + Unpin,
    mut stdout: impl Write,
    mut stderr: impl Write,
    hooks: Hooks,
) -> Exit {
    use tokio::signal::unix::{SignalKind, signal};
    if let Some(Command::Show { file }) = &cli.command {
        return show(file, &mut stdout, &mut stderr);
    }
    let prep = match prepare(&cli) {
        Ok(p) => p,
        Err(r) => return fail(&mut stderr, &r, Exit::Refused),
    };
    let _ = stdout.write_all(notice::NOTICE.as_bytes());
    if !cli.yes {
        let _ = stdout.write_all(notice::CONSENT_PROMPT.as_bytes());
        let _ = stdout.flush();
        let mut line = String::new();
        let n = stdin.read_line(&mut line).await.unwrap_or(0);
        if n == 0 || line.trim() != "yes" {
            let _ = writeln!(stdout, "{}", notice::NOTHING_RECORDED);
            return Exit::Done;
        }
    }
    if let Err(e) = harden_process() {
        return fail(
            &mut stderr,
            &format_args!("cannot make the process non-dumpable: {e}"),
            Exit::Failed,
        );
    }
    // Ctrl-C, a stop request, the terminal going away, and Ctrl-\: every way the program can be
    // told to stop. The browser is in its own process group, so none of them reaches it by
    // itself.
    let (Ok(mut sigint), Ok(mut sigterm), Ok(mut sighup), Ok(mut sigquit)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
        signal(SignalKind::quit()),
    ) else {
        return fail(&mut stderr, &"cannot watch for Ctrl-C", Exit::Failed);
    };

    let (ready_tx, mut ready_rx) = oneshot::channel();
    let (end_tx, end_rx) = oneshot::channel();
    let mut end_tx = Some(end_tx);
    let mut rec = Box::pin(record(
        RecordOptions {
            login_url: &prep.url,
            browser: &prep.browser,
            headless: hooks.headless,
            tool_version: env!("CARGO_PKG_VERSION"),
        },
        ready_tx,
        end_rx,
    ));
    let mut forward = hooks.ready;
    let (mut got_ready, mut stdin_done) = (false, false);
    let stdin_line = async {
        let mut line = String::new();
        let read = stdin.read_line(&mut line).await;
        (line, read)
    };
    tokio::pin!(stdin_line);
    let ended = loop {
        tokio::select! {
            r = &mut rec => break Ended::Finished(r),
            r = &mut ready_rx, if !got_ready => {
                got_ready = true;
                if let Ok(ready) = r {
                    if ready.stale_profiles_removed > 0 {
                        let _ = writeln!(
                            stdout,
                            "Removed {} leftover browser profile(s) from an earlier run.",
                            ready.stale_profiles_removed
                        );
                    }
                    let _ = writeln!(stdout, "{}", notice::END_PROMPT);
                    let _ = stdout.flush();
                    if let Some(tx) = forward.take() {
                        let _ = tx.send(Ready {
                            devtools_port: ready.devtools_port,
                            profile_dir: ready.profile_dir,
                            stale_profiles_removed: ready.stale_profiles_removed,
                        });
                    }
                }
            }
            (line, read) = &mut stdin_line, if got_ready && !stdin_done => {
                stdin_done = true;
                // End of input is neither answer: keep recording until the window closes.
                if matches!(read, Ok(n) if n > 0) {
                    let how = if line.trim().eq_ignore_ascii_case("q") {
                        End::Discard
                    } else {
                        End::Confirmed
                    };
                    if let Some(tx) = end_tx.take() {
                        let _ = tx.send(how);
                    }
                }
            }
            _ = sigint.recv() => break Ended::Interrupted,
            _ = sigterm.recv() => break Ended::Interrupted,
            _ = sighup.recv() => break Ended::Interrupted,
            _ = sigquit.recv() => break Ended::Interrupted,
        }
    };
    let outcome = match ended {
        Ended::Finished(r) => r,
        Ended::Interrupted => {
            // Dropping the session closes the browser and removes its profile.
            drop(rec);
            return fail(
                &mut stderr,
                &"Interrupted. Nothing was saved.",
                Exit::Failed,
            );
        }
    };
    drop(rec);
    match outcome {
        Ok(Outcome::Recorded(r)) => {
            let first =
                match &prep.target {
                    Target::Explicit(p) => p.clone(),
                    Target::Here => {
                        let host = prep.url.host_str().unwrap_or("login");
                        // The name carries the instant the recording ended, not the time of the write.
                        PathBuf::from(default_file_name_at(host, &r.ended_at).unwrap_or_else(
                            || default_file_name(host, std::time::SystemTime::now()),
                        ))
                    }
                };
            let naming = match prep.target {
                Target::Explicit(_) => Naming::Explicit,
                Target::Here => Naming::Default,
            };
            match write_new(&first, naming, &r.to_json()) {
                Ok(path) => {
                    let _ = writeln!(stdout, "\n{}", summary(&r));
                    let _ = writeln!(stdout, "Saved: {}", path.display());
                    Exit::Done
                }
                Err((at, e)) => fail(
                    &mut stderr,
                    &format_args!("cannot write {}: {e}", at.display()),
                    Exit::Failed,
                ),
            }
        }
        Ok(Outcome::Discarded) => {
            let _ = writeln!(stdout, "Discarded. Nothing was saved.");
            Exit::Done
        }
        Ok(Outcome::NeverStarted) => {
            let _ = writeln!(
                stdout,
                "The window was closed before the login page opened. Nothing was saved."
            );
            Exit::Done
        }
        Err(e) => fail(&mut stderr, &e, Exit::Failed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("kharon-teach").chain(args.iter().copied())).unwrap()
    }

    /// Profile directories in the temp directory that name THIS process as their owner. Other
    /// tests and other processes make profiles too; only ours can come from `run_with` here.
    fn my_profiles() -> Vec<std::path::PathBuf> {
        let me = std::process::id().to_string();
        std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("kharon-teach-"))
            .map(|e| e.path())
            .filter(|p| {
                std::fs::read_to_string(p.join(browser::OWNER_FILE)).is_ok_and(|t| t.trim() == me)
            })
            .collect()
    }

    struct Ran {
        exit: Exit,
        out: String,
        err: String,
    }

    async fn go(args: &[&str], stdin: &str) -> Ran {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let exit = run(cli(args), stdin.as_bytes(), &mut out, &mut err).await;
        Ran {
            exit,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    fn private_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kharon-run-test-{tag}-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir(&d).unwrap();
        d
    }

    /// An executable that exists, so browser discovery passes. It is never started in these tests.
    fn fake_browser(dir: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("fake-browser");
        std::fs::write(&p, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[tokio::test]
    async fn refusals_exit_2_before_the_notice() {
        let before = my_profiles();
        let d = private_dir("refuse");
        let browser = fake_browser(&d);
        let existing = d.join("taken.json");
        std::fs::write(&existing, b"x").unwrap();
        let b = browser.to_str().unwrap();
        let missing = d.join("no-such-browser");
        let cases: Vec<Vec<&str>> = vec![
            vec!["http://ex.test/", "--browser", b],
            vec!["https://u:p@ex.test/", "--browser", b],
            vec!["https://ex.test/", "--browser", missing.to_str().unwrap()],
            vec![
                "https://ex.test/",
                "--browser",
                b,
                "--out",
                existing.to_str().unwrap(),
            ],
            vec![
                "https://ex.test/",
                "--browser",
                b,
                "--out",
                "/no/such/dir/a.json",
            ],
            vec![],
        ];
        for args in cases {
            let r = go(&args, "yes\n").await;
            assert_eq!(r.exit, Exit::Refused, "{args:?}");
            assert!(!r.out.contains("THROWAWAY"), "{args:?}");
            assert!(r.out.is_empty(), "{args:?}: {}", r.out);
            assert!(r.err.starts_with("kharon-teach: "), "{}", r.err);
            assert_eq!(r.err.lines().count(), 1, "{}", r.err);
        }
        let after = my_profiles();
        assert!(
            after.iter().all(|p| before.contains(p)),
            "a refusal created a profile directory"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn anything_but_yes_records_nothing() {
        let d = private_dir("consent");
        let browser = fake_browser(&d);
        let b = browser.to_str().unwrap();
        for input in ["no\n", "y\n", "YES\n", "\n", ""] {
            let r = go(&["https://ex.test/", "--browser", b], input).await;
            assert_eq!(r.exit, Exit::Done, "{input:?}");
            assert!(r.out.contains("THROWAWAY"));
            assert!(r.out.contains("Nothing was recorded."), "{input:?}");
            assert!(r.err.is_empty());
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn show_prints_the_summary_and_refuses_a_bad_file() {
        let d = private_dir("show");
        let bad = d.join("bad.json");
        std::fs::write(&bad, b"{}").unwrap();
        let r = go(&["show", bad.to_str().unwrap()], "").await;
        assert_eq!(r.exit, Exit::Refused);
        assert!(r.out.is_empty());
        assert!(r.err.starts_with("kharon-teach: ") && r.err.lines().count() == 1);
        let r = go(&["show", d.join("missing").to_str().unwrap()], "").await;
        assert_eq!(r.exit, Exit::Refused);
        let big = d.join("big.json");
        std::fs::write(&big, vec![b' '; 16 * 1024 * 1024 + 1]).unwrap();
        let r = go(&["show", big.to_str().unwrap()], "").await;
        assert_eq!(r.exit, Exit::Refused);
        assert!(r.err.contains("16 MiB"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn show_prints_the_summary_of_a_good_file() {
        let d = private_dir("show-ok");
        let good = d.join("good.json");
        std::fs::write(&good, cli::tests::recording().to_json()).unwrap();
        let r = go(&["show", good.to_str().unwrap()], "").await;
        assert_eq!(r.exit, Exit::Done, "{}", r.err);
        assert!(r.out.contains("Site: https://ex.test/login"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_write_picks_a_numbered_name_when_the_file_appears() {
        let d = private_dir("numbered");
        let first = d.join(default_file_name("ex.test", std::time::UNIX_EPOCH));
        let a = write_new(&first, Naming::Default, "a").unwrap();
        let b = write_new(&first, Naming::Default, "b").unwrap();
        assert_eq!(a, first);
        assert!(
            b.to_string_lossy().ends_with(".1.kharon-recording.json"),
            "{b:?}"
        );
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "a");
        let ex = d.join("mine.json");
        write_new(&ex, Naming::Explicit, "x").unwrap();
        let y = write_new(&ex, Naming::Explicit, "y").unwrap();
        assert_eq!(y, d.join("mine.json.1"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&y).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&d).unwrap();
    }
}
