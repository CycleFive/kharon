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
    Cli, Command, Refusal, SuccessArg, check_dir_writable, check_out_path, default_file_name,
    default_file_name_at, default_method_name, method_summary, summary, validate_login_url,
};
use kharon_recording::{ConvertOptions, LoginMethod, Recording};
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

/// The bytes of a file a person pointed us at, never more than 16 MiB.
fn read_capped(file: &Path) -> Result<Vec<u8>, Refusal> {
    use std::io::Read;
    const CAP: u64 = 16 * 1024 * 1024;
    let unreadable = |e: std::io::Error| Refusal::Unreadable(file.to_owned(), e.to_string());
    let f = std::fs::File::open(file).map_err(unreadable)?;
    let mut bytes = Vec::new();
    f.take(CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() as u64 > CAP {
        return Err(Refusal::TooLarge(file.to_owned()));
    }
    Ok(bytes)
}

/// `kharon-teach show <file>`: a recording, or else a method.
fn show(file: &Path, stdout: &mut impl Write, stderr: &mut impl Write) -> Exit {
    let read = || -> Result<String, Refusal> {
        let text = String::from_utf8(read_capped(file)?)
            .map_err(|_| Refusal::NotARecording(file.to_owned(), "not text".to_owned()))?;
        match Recording::from_json(&text) {
            Ok(r) => Ok(summary(&r)),
            Err(rec_err) => LoginMethod::from_json(&text)
                .map(|m| method_summary(&m))
                .map_err(|_| Refusal::NotARecording(file.to_owned(), rec_err.to_string())),
        }
    };
    match read() {
        Ok(text) => {
            let _ = stdout.write_all(text.as_bytes());
            Exit::Done
        }
        Err(e) => fail(stderr, &e, Exit::Refused),
    }
}

/// `kharon-teach method <recording>`: convert, and write the method in `dir` (or at `out`).
/// Returns the path written. The recording is read once; its bytes are what the method's
/// digest covers. This starts no browser.
fn method_command(
    recording: &Path,
    out: Option<&Path>,
    unconfirmed: bool,
    success: Option<SuccessArg>,
    dir: &Path,
) -> Result<(PathBuf, LoginMethod), Refusal> {
    let bytes = read_capped(recording)?;
    let not_a = |why: String| Refusal::NotARecording(recording.to_owned(), why);
    let rec = Recording::from_json(
        std::str::from_utf8(&bytes).map_err(|_| not_a("not text".to_owned()))?,
    )
    .map_err(|e| not_a(e.to_string()))?;
    let origin = url::Url::parse(&rec.start_url.origin)
        .map_err(|_| not_a("its login address is not a web address".to_owned()))?;
    let host = origin
        .host_str()
        .ok_or_else(|| not_a("its login address has no host".to_owned()))?;
    let domain = site::registrable_domain(host);
    let method = LoginMethod::from_recording(
        &rec,
        &bytes,
        &domain,
        ConvertOptions {
            allow_unconfirmed: unconfirmed,
            success: success.map(Into::into),
        },
    )
    .map_err(|e| Refusal::NotConvertible(e.to_string()))?;
    let target = out.map_or_else(|| dir.join(default_method_name(&domain)), Path::to_owned);
    check_out_path(&target)?;
    let path = write_new(&target, Naming::Explicit, &method.to_json())
        .map_err(|(at, e)| Refusal::Unwritable(at, e.to_string()))?;
    Ok((path, method))
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

/// One line from the person, with the reader handed back so the caller can ask again.
async fn read_answer<R: AsyncBufRead + Unpin>(mut stdin: R) -> (String, std::io::Result<usize>, R) {
    let mut line = String::new();
    let read = stdin.read_line(&mut line).await;
    (line, read, stdin)
}

/// The answer a line at the end prompt gives: an empty line confirms, `q` or `quit` (any case)
/// discards, anything else is no answer and the prompt is repeated.
fn end_choice(line: &str) -> Option<End> {
    let answer = line.trim();
    if answer.is_empty() {
        Some(End::Confirmed)
    } else if answer.eq_ignore_ascii_case("q") || answer.eq_ignore_ascii_case("quit") {
        Some(End::Discard)
    } else {
        None
    }
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
    if let Some(Command::Method {
        recording,
        out,
        unconfirmed,
        success,
    }) = &cli.command
    {
        return match method_command(
            recording,
            out.as_deref(),
            *unconfirmed,
            *success,
            Path::new("."),
        ) {
            Ok((path, method)) => {
                let _ = writeln!(stdout, "Saved: {}\n", path.display());
                let _ = stdout.write_all(method_summary(&method).as_bytes());
                Exit::Done
            }
            Err(e) => fail(&mut stderr, &e, Exit::Refused),
        };
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
    // The reader goes into the future and comes back with the line, so another line can be
    // asked for without a second read ever being dropped half way (a read is not cancel safe).
    let stdin_line = read_answer(stdin);
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
            (line, read, back) = &mut stdin_line, if got_ready && !stdin_done => {
                // End of input is neither answer: keep recording until the window closes.
                if matches!(read, Ok(n) if n > 0) {
                    match end_choice(&line) {
                        Some(how) => {
                            stdin_done = true;
                            if let Some(tx) = end_tx.take() {
                                let _ = tx.send(how);
                            }
                        }
                        None => {
                            let _ = writeln!(stdout, "{}", notice::END_RETRY);
                            let _ = stdout.flush();
                            stdin_line.set(read_answer(back));
                        }
                    }
                } else {
                    stdin_done = true;
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
            let _ = writeln!(stdout, "{}", notice::NEVER_STARTED);
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

    fn method_args(rec: &std::path::Path) -> (std::path::PathBuf, bool, Option<cli::SuccessArg>) {
        (rec.to_owned(), false, None)
    }

    fn write_recording(dir: &std::path::Path, r: &Recording) -> std::path::PathBuf {
        let p = dir.join("in.kharon-recording.json");
        std::fs::write(&p, r.to_json()).unwrap();
        p
    }

    #[test]
    fn method_command_writes_a_0600_file_named_for_the_domain() {
        use std::os::unix::fs::PermissionsExt;
        let d = private_dir("method-ok");
        let rec = write_recording(&d, &cli::tests::convertible_recording());
        let (r, un, su) = method_args(&rec);
        let (path, _) = method_command(&r, None, un, su, &d).unwrap();
        assert_eq!(path, d.join("ex.test.kharon-method.json"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let m = kharon_recording::LoginMethod::from_json(&std::fs::read_to_string(&path).unwrap())
            .unwrap();
        use sha2::{Digest, Sha256};
        let want: String = Sha256::digest(std::fs::read(&rec).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(m.digest(), Some(want.as_str()));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn method_command_refuses_and_says_why() {
        let d = private_dir("method-no");
        let mut r = cli::tests::convertible_recording();
        r.classification.shape = kharon_recording::Shape::Unrecognized;
        r.classification.rung_ceiling = kharon_recording::RungCeiling::NeedsPerson;
        let rec = write_recording(&d, &r);
        let out = d.join("o.json");
        let e = method_command(&rec, Some(&out), false, None, &d).unwrap_err();
        let want = kharon_recording::NotConvertible::NeedsPerson.to_string();
        assert!(e.to_string().contains(&want), "{e}");
        assert!(!out.exists());
        assert!(!d.join("ex.test.kharon-method.json").exists());
        // Through `run`, it is one line on stderr and exit 2.
        let (mut o, mut er) = (Vec::new(), Vec::new());
        let exit = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(run(
                cli(&[
                    "method",
                    rec.to_str().unwrap(),
                    "--out",
                    out.to_str().unwrap(),
                ]),
                &b""[..],
                &mut o,
                &mut er,
            ));
        assert_eq!(exit, Exit::Refused);
        assert!(o.is_empty());
        let er = String::from_utf8(er).unwrap();
        assert!(er.starts_with("kharon-teach: ") && er.contains(&want) && er.lines().count() == 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn method_command_refuses_an_existing_out_file() {
        let d = private_dir("method-exists");
        let rec = write_recording(&d, &cli::tests::convertible_recording());
        let out = d.join("taken.json");
        std::fs::write(&out, b"x").unwrap();
        let e = method_command(&rec, Some(&out), false, None, &d).unwrap_err();
        assert!(matches!(e, Refusal::OutExists(_)), "{e}");
        assert_eq!(std::fs::read(&out).unwrap(), b"x");
        // The default name is refused the same way.
        std::fs::write(d.join("ex.test.kharon-method.json"), b"y").unwrap();
        let e = method_command(&rec, None, false, None, &d).unwrap_err();
        assert!(matches!(e, Refusal::OutExists(_)), "{e}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn method_command_honours_unconfirmed_and_success() {
        let d = private_dir("method-opts");
        let mut r = cli::tests::convertible_recording();
        r.success_confirmed = false;
        let rec = write_recording(&d, &r);
        let e = method_command(&rec, None, false, None, &d).unwrap_err();
        assert!(matches!(e, Refusal::NotConvertible(_)), "{e}");
        let (path, _) = method_command(&rec, None, true, Some(cli::SuccessArg::None), &d).unwrap();
        let m = kharon_recording::LoginMethod::from_json(&std::fs::read_to_string(path).unwrap())
            .unwrap();
        assert_eq!(m.success, kharon_recording::SuccessCheck::None {});
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn show_reads_a_method_file_too() {
        let d = private_dir("show-method");
        let rec = write_recording(&d, &cli::tests::convertible_recording());
        let out = d.join("m.json");
        let r = go(
            &[
                "method",
                rec.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ],
            "",
        )
        .await;
        assert_eq!(r.exit, Exit::Done, "{}", r.err);
        assert!(
            r.out.contains(out.to_str().unwrap()) && r.out.contains("step 2: fill the password")
        );
        let r = go(&["show", out.to_str().unwrap()], "").await;
        assert_eq!(r.exit, Exit::Done, "{}", r.err);
        assert!(r.out.contains("step 3: submit the form"), "{}", r.out);
        let bad = d.join("bad.json");
        std::fs::write(&bad, b"{}").unwrap();
        assert_eq!(
            go(&["show", bad.to_str().unwrap()], "").await.exit,
            Exit::Refused
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_end_prompt_reads_enter_q_and_quit_and_asks_again_otherwise() {
        assert!(matches!(end_choice("\n"), Some(End::Confirmed)));
        assert!(matches!(end_choice("  \r\n"), Some(End::Confirmed)));
        for discard in ["q\n", "Q", " quit ", "QUIT\n", "Quit"] {
            assert!(
                matches!(end_choice(discard), Some(End::Discard)),
                "{discard:?}"
            );
        }
        for again in ["no\n", "n", "discard", "qq", "y", "quit now", "exit"] {
            assert!(end_choice(again).is_none(), "{again:?}");
        }
    }

    #[test]
    fn the_never_started_message_says_what_happened() {
        assert_eq!(
            notice::NEVER_STARTED,
            "Recording never started: the login page was not opened in the first tab. Nothing was saved."
        );
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
