//! The command line: arguments, the refusals, the file name, the output path and the plain-words
//! summary of a recording.

use kharon_recording::{
    EndedBy, ListenerWorld, PasswordLeg, Recording, RungCeiling, Shape, StrippedUrl,
};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// How a recording file's name ends.
pub const FILE_SUFFIX: &str = ".kharon-recording.json";

#[derive(clap::Parser)]
#[command(
    name = "kharon-teach",
    version,
    about = "Record how a login works so kharon can learn it",
    args_conflicts_with_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// The login page to record (https, or http on this computer)
    pub login_url: Option<String>,
    /// Where to write the recording (must not exist yet)
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// The Chromium-family browser to use, instead of searching PATH
    #[arg(long)]
    pub browser: Option<PathBuf>,
    /// Skip the question after the notice; the notice is still shown
    #[arg(long)]
    pub yes: bool,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Print what a recording file says, in plain words
    Show { file: PathBuf },
}

/// Why the program will not start. One line each.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    #[error("give the login page's address, or `show <file>`")]
    NoUrl,
    #[error("that is not a web address")]
    NotAUrl,
    #[error("the address must start with https:// (plain http only for this computer)")]
    NotHttps,
    #[error("the address must not hold a user name or password")]
    Userinfo,
    #[error("{0}")]
    NoBrowser(String),
    #[error("{} already exists; pick another --out", .0.display())]
    OutExists(PathBuf),
    #[error("cannot write in {}; it must be an existing directory you can write to", .0.display())]
    OutDir(PathBuf),
    #[error("cannot read {}: {}", .0.display(), .1)]
    Unreadable(PathBuf, String),
    #[error("{} is larger than 16 MiB, so it is not a recording", .0.display())]
    TooLarge(PathBuf),
    #[error("{} is not a recording kharon-teach can read: {}", .0.display(), .1)]
    NotARecording(PathBuf, String),
}

/// `https`, or `http` when the host is `localhost` or a loopback address; no user name or
/// password in it.
pub fn validate_login_url(s: &str) -> Result<url::Url, Refusal> {
    let u = url::Url::parse(s).map_err(|_| Refusal::NotAUrl)?;
    if !u.username().is_empty() || u.password().is_some() {
        return Err(Refusal::Userinfo);
    }
    let Some(host) = u.host() else {
        return Err(Refusal::NotHttps);
    };
    match u.scheme() {
        "https" => Ok(u),
        "http" => {
            let local = match host {
                url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
                url::Host::Ipv4(a) => a.is_loopback(),
                url::Host::Ipv6(a) => a.is_loopback(),
            };
            if local { Ok(u) } else { Err(Refusal::NotHttps) }
        }
        _ => Err(Refusal::NotHttps),
    }
}

fn sanitize_host(host: &str) -> String {
    host.to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// `<host>-<YYYYMMDDTHHMMSSZ>.kharon-recording.json`. Every character of the host outside
/// `[a-z0-9.-]` becomes `_`, so an IPv6 host puts no `[`, `]` or `:` in a file name.
pub fn default_file_name(host: &str, utc: SystemTime) -> String {
    let t = time::OffsetDateTime::from(utc);
    format!(
        "{}-{:04}{:02}{:02}T{:02}{:02}{:02}Z{FILE_SUFFIX}",
        sanitize_host(host),
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// [`default_file_name`] for the instant a recording says it ended (`ended_at`, UTC RFC 3339
/// as `session::utc_rfc3339` writes it). `None` when the text is not in that shape.
pub fn default_file_name_at(host: &str, ended_at: &str) -> Option<String> {
    let digits: Vec<char> = ended_at
        .chars()
        .take(19)
        .filter(char::is_ascii_digit)
        .collect();
    if digits.len() != 14 || !ended_at.is_ascii() {
        return None;
    }
    let d: String = digits.into_iter().collect();
    Some(format!(
        "{}-{}T{}Z{FILE_SUFFIX}",
        sanitize_host(host),
        &d[..8],
        &d[8..]
    ))
}

/// `dir` is an existing directory this user can create files in. Tried, not read from
/// permission bits: a temporary file is created and removed.
pub fn check_dir_writable(dir: &Path) -> Result<(), Refusal> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let bad = || Refusal::OutDir(dir.to_owned());
    if !std::fs::metadata(dir).is_ok_and(|m| m.is_dir()) {
        return Err(bad());
    }
    for _ in 0..4 {
        let probe = dir.join(format!(
            ".kharon-teach-probe-{:016x}",
            rand::random::<u64>()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe)
        {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe);
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(bad()),
        }
    }
    Err(bad())
}

/// The file must not exist (a dangling symlink counts as existing) and its directory must be
/// writable.
pub fn check_out_path(p: &Path) -> Result<(), Refusal> {
    if std::fs::symlink_metadata(p).is_ok() {
        return Err(Refusal::OutExists(p.to_owned()));
    }
    check_dir_writable(p.parent().unwrap_or(Path::new("")))
}

fn site(u: &StrippedUrl) -> String {
    format!("{}{}", u.origin, u.path)
}

/// What a recording says, in plain words, one fact per line. It is built from the recording
/// only and holds no JSON.
pub fn summary(r: &Recording) -> String {
    let mut out: Vec<String> = Vec::new();
    out.push(format!("Site: {}", site(&r.start_url)));
    out.push(
        match r.ended_by {
            EndedBy::Confirmed => "How it ended: you pressed Enter to say the login worked.",
            EndedBy::WindowClosed => "How it ended: the window was closed before you confirmed.",
        }
        .to_owned(),
    );
    out.push(format!(
        "How the login works: {}",
        match &r.classification.shape {
            Shape::FormPost => "One page; the form sends the password to the site as typed.".to_owned(),
            Shape::ScriptPost =>
                "One page; the page's script sends the password to the site as typed.".to_owned(),
            Shape::TwoStep { password_leg } => format!(
                "Two steps; the user name goes first, then the password, which {}.",
                match password_leg {
                    PasswordLeg::FormPost => "a form sends to the site as typed",
                    PasswordLeg::ScriptPost => "the page's script sends to the site as typed",
                    PasswordLeg::Transformed => "the page changes before it sends it",
                }
            ),
            Shape::Transformed { digest } => match digest {
                Some(d) => format!(
                    "The page changes the password ({d} digest) before it sends it, so kharon cannot send it as typed."
                ),
                None => "The page changes the password before it sends it, so kharon cannot send it as typed.".to_owned(),
            },
            Shape::Unrecognized =>
                "kharon-teach did not recognize how this login sends the password.".to_owned(),
        }
    ));
    out.push(format!(
        "Strongest protection: {}.",
        match r.classification.rung_ceiling {
            RungCeiling::Milliseconds =>
                "kharon can fill and submit in one step, so the password is in the page for milliseconds",
            RungCeiling::AgentContinues => "the agent has to continue after the fill",
            RungCeiling::NeedsPerson => "a person has to look at this recording",
        }
    ));
    out.push(
        if r.classification.network_swap_candidate {
            "Network swap: this login looks like one where the password can be put in at the network level."
        } else {
            "Network swap: this login does not look like a candidate."
        }
        .to_owned(),
    );
    let f = &r.flags;
    for (set, words) in [
        (f.captcha, "A captcha was on the page."),
        (f.otp_step, "There was a one-time-code step."),
        (f.cross_site, "The login went through another site."),
        (f.popup, "The login opened a pop-up window."),
        (f.framed_login, "The login form was inside a frame."),
        (f.shadow_dom, "The login form was inside a shadow root."),
        (
            f.multiple_passwords,
            "The page had more than one password field.",
        ),
        (
            f.body_unavailable,
            "Some request bodies could not be read, so the shape may be incomplete.",
        ),
    ] {
        if set {
            out.push(format!("Flag: {words}"));
        }
    }
    for n in &r.classification.notes {
        out.push(format!("Note: {n}"));
    }
    if r.listener_world == ListenerWorld::Main {
        out.push(
            "Caution: the page listener ran in the page's own script world, where the site's scripts can see and fake what it reports. Trust this recording less."
                .to_owned(),
        );
    }
    let s = &r.stripped;
    out.push(format!(
        "Removed before saving: {} typed value(s), {} query value(s), {} path segment(s); {} of {} request(s) kept, {} body(ies) reduced to a shape.",
        s.typed_values_removed,
        s.query_values_removed,
        s.path_segments_replaced,
        s.requests_stored,
        s.requests_seen,
        s.request_bodies_reduced
    ));
    if s.steps_dropped > 0 {
        out.push(format!(
            "Not recorded: {} step(s) past the recorder's limit.",
            s.steps_dropped
        ));
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use clap::CommandFactory;
    use kharon_recording::{BrowserInfo, Classification, Flags, StrippedCounts, Viewport};
    use std::time::Duration;

    #[test]
    fn accepts_https_and_loopback_http() {
        for ok in [
            "https://ex.test/login",
            "http://localhost:8080/",
            "http://127.0.0.1:1/",
            "http://[::1]:1/",
        ] {
            assert!(validate_login_url(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn refuses_plain_http_userinfo_and_other_schemes() {
        for bad in [
            "http://ex.test",
            "https://u:p@ex.test",
            "https://u@ex.test",
            "file:///x",
            "ex.test",
            "ftp://ex.test/",
        ] {
            assert!(validate_login_url(bad).is_err(), "{bad}");
        }
        assert!(matches!(
            validate_login_url("https://u:p@ex.test"),
            Err(Refusal::Userinfo)
        ));
    }

    #[test]
    fn a_refusal_never_echoes_the_address() {
        let e = validate_login_url("https://user:secret-pass@ex.test/").unwrap_err();
        assert!(!e.to_string().contains("secret-pass"));
    }

    #[test]
    fn file_name_shape() {
        assert_eq!(
            default_file_name(
                "ex.test",
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_974_640)
            ),
            "ex.test-20261118T040400Z.kharon-recording.json"
        );
    }

    #[test]
    fn file_name_follows_the_recordings_end_time() {
        assert_eq!(
            default_file_name_at("Ex.test", "2026-11-18T04:04:00.123Z").unwrap(),
            "ex.test-20261118T040400Z.kharon-recording.json"
        );
        assert!(default_file_name_at("ex.test", "yesterday").is_none());
    }

    #[test]
    fn file_name_sanitizes_the_host() {
        let n = default_file_name("[::1]", SystemTime::UNIX_EPOCH);
        assert!(n.starts_with("___1_-19700101T000000Z"), "{n}");
        assert!(!n.contains(['[', ']', ':', '/']));
    }

    fn private_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kharon-cli-test-{tag}-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir(&d).unwrap();
        d
    }

    #[test]
    fn refuses_an_existing_out_file() {
        let d = private_dir("exists");
        let f = d.join("a.json");
        assert!(check_out_path(&f).is_ok());
        std::fs::write(&f, b"x").unwrap();
        assert!(matches!(check_out_path(&f), Err(Refusal::OutExists(_))));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn refuses_a_missing_or_read_only_directory() {
        use std::os::unix::fs::PermissionsExt;
        let d = private_dir("dirs");
        assert!(matches!(
            check_out_path(&d.join("nope").join("a.json")),
            Err(Refusal::OutDir(_))
        ));
        let ro = d.join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(matches!(
            check_out_path(&ro.join("a.json")),
            Err(Refusal::OutDir(_))
        ));
        // A file is not a directory.
        let file = d.join("f");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            check_out_path(&file.join("a.json")),
            Err(Refusal::OutDir(_))
        ));
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    pub(crate) fn recording() -> Recording {
        Recording {
            format_version: 1,
            tool_version: "t".into(),
            browser: BrowserInfo {
                product: "Chrome/1".into(),
                user_agent: "UA".into(),
                viewport: Viewport {
                    width: 1,
                    height: 1,
                },
            },
            listener_world: ListenerWorld::Isolated,
            started_at: "2026-11-18T00:00:00Z".into(),
            ended_at: "2026-11-18T00:01:00Z".into(),
            ended_by: EndedBy::Confirmed,
            success_confirmed: true,
            start_url: StrippedUrl {
                origin: "https://ex.test".into(),
                path: "/login".into(),
                query_keys: vec![],
            },
            final_url: None,
            steps: vec![],
            requests: vec![],
            flags: Flags::default(),
            classification: Classification {
                shape: Shape::FormPost,
                rung_ceiling: RungCeiling::Milliseconds,
                network_swap_candidate: false,
                notes: vec![],
            },
            stripped: StrippedCounts {
                requests_seen: 9,
                requests_stored: 4,
                request_bodies_reduced: 2,
                query_values_removed: 3,
                path_segments_replaced: 1,
                typed_values_removed: 5,
                steps_dropped: 0,
            },
        }
    }

    #[test]
    fn summary_names_shape_ceiling_flags_and_counts() {
        let mut r = recording();
        r.flags.captcha = true;
        r.classification.network_swap_candidate = true;
        r.classification.notes = vec!["a classifier note".into()];
        r.listener_world = ListenerWorld::Main;
        let s = summary(&r);
        assert!(s.contains("https://ex.test/login"));
        assert!(s.contains("One page; the form sends the password to the site as typed."));
        assert!(s.contains("password is in the page for milliseconds"));
        assert!(s.contains("A captcha"));
        assert!(s.contains("Network swap: this login looks like"));
        assert!(s.contains("Note: a classifier note"));
        assert!(s.contains("Caution"));
        assert!(s.contains("5 typed value(s)"));
        assert!(s.contains("4 of 9 request(s) kept"));
        assert!(!s.contains('{') && !s.contains('"'));
        let quiet = summary(&recording());
        assert!(!quiet.contains("Caution") && !quiet.contains("Flag:"));
        assert!(!quiet.contains("Not recorded"));
        let mut capped = recording();
        capped.stripped.steps_dropped = 7;
        assert!(summary(&capped).contains("Not recorded: 7 step(s) past the recorder's limit."));
        assert!(quiet.contains("does not look like a candidate"));
    }

    #[test]
    fn cli_has_no_headless_or_attach_option() {
        let names: Vec<_> = Cli::command()
            .get_arguments()
            .map(|a| a.get_id().to_string())
            .collect();
        for banned in [
            "headless",
            "attach",
            "port",
            "profile",
            "user-data-dir",
            "endpoint",
        ] {
            assert!(!names.iter().any(|n| n.contains(banned)), "{banned}");
        }
    }
}
