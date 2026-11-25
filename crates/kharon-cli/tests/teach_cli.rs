//! `kharon teach …` against a fake owner socket (#382). The fake accepts one
//! connection, records the request line, and writes a canned reply that the
//! test built from typed values.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::JoinHandle;

use kharon_recording::{
    Expected, FillRole, Leg, ListenerWorld, LoginMethod, METHOD_FORMAT_VERSION, MethodStep,
    Provenance, Rung, RungCeiling, Shape, Site, SubmitVia, SuccessCheck,
};
use kharond::owner::TeachRow;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ListReply {
    ok: bool,
    entries: Vec<TeachRow>,
}

#[derive(Serialize)]
struct ShowReply<'a> {
    ok: bool,
    entry: TeachRow,
    method: &'a LoginMethod,
}

#[derive(Serialize)]
struct EntryReply {
    ok: bool,
    entry: TeachRow,
}

#[derive(Serialize)]
struct Refusal {
    ok: bool,
    error: &'static str,
}

#[derive(Deserialize)]
struct ImportLine {
    op: String,
    method: LoginMethod,
    #[serde(default)]
    replace: bool,
    #[serde(default)]
    accept_main_world: bool,
}

#[derive(Deserialize)]
struct OverrideLine {
    op: String,
    domain: String,
    step: u32,
    selector: String,
}

fn expected(input_type: &str) -> Expected {
    Expected {
        tag: "input".into(),
        input_type: Some(input_type.into()),
        id: None,
        name: None,
        autocomplete: None,
    }
}

fn method(domain: &str, hand_written: bool) -> LoginMethod {
    LoginMethod {
        format_version: METHOD_FORMAT_VERSION,
        site: Site {
            domain: domain.into(),
            origin: format!("https://{domain}"),
            path: "/login".into(),
        },
        shape: Shape::FormPost,
        rung: Rung::Milliseconds,
        legs: vec![Leg {
            steps: vec![
                MethodStep::Navigate {
                    path: "/login".into(),
                },
                MethodStep::Fill {
                    role: FillRole::Username,
                    selectors: vec!["#user".into()],
                    expect: expected("text"),
                },
                MethodStep::Fill {
                    role: FillRole::Password,
                    selectors: vec!["#pw".into(), "[name=pass]".into()],
                    expect: expected("password"),
                },
                MethodStep::Submit {
                    via: SubmitVia::Form {},
                },
            ],
        }],
        success: SuccessCheck::None {},
        provenance: if hand_written {
            Provenance::HandWritten {
                author: "me".into(),
            }
        } else {
            Provenance::Recording {
                sha256: "ab12".into(),
                tool_version: "0.0.0".into(),
                browser_product: "Chrome/1".into(),
                listener_world: ListenerWorld::Isolated,
                rung_ceiling: RungCeiling::Milliseconds,
            }
        },
    }
}

fn row(m: &LoginMethod) -> TeachRow {
    TeachRow {
        domain: m.site.domain.clone(),
        rung: m.rung,
        shape: m.shape.clone(),
        hand_written: m.digest().is_none(),
        digest: m.digest().map(str::to_owned),
        stale: None,
        overrides: Default::default(),
        imported_at: "2026-11-24T10:00:00Z".into(),
        last_checked: None,
        last_result: None,
    }
}

fn to_line<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

/// A socket that serves one connection: returns the request line it saw.
fn fake_socket(dir: &Path, reply: String) -> (PathBuf, JoinHandle<String>) {
    let path = dir.join("owner.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        (&stream).write_all(reply.as_bytes()).unwrap();
        (&stream).write_all(b"\n").unwrap();
        line
    });
    (path, handle)
}

struct Run {
    code: Option<i32>,
    out: String,
    err: String,
}

fn kharon(args: &[&str], socket: &Path) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_kharon"))
        .args(args)
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Run {
        code: out.status.code(),
        out: String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        err: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    }
}

#[test]
fn teach_list_prints_one_line_per_site() {
    let dir = tempfile::tempdir().unwrap();
    let a = method("a.example", false);
    let b = method("b.example", true);
    let mut ra = row(&a);
    ra.stale = Some(kharond::teach::Stale {
        step: 2,
        at: "2026-11-24T11:00:00Z".into(),
    });
    let rb = row(&b);
    let (sock, server) = fake_socket(
        dir.path(),
        to_line(&ListReply {
            ok: true,
            entries: vec![ra, rb],
        }),
    );
    let run = kharon(&["teach", "list"], &sock);
    assert_eq!(run.code, Some(0), "{}", run.err);
    assert_eq!(
        run.out,
        "a.example\trung=milliseconds\tshape=form_post\tconverted\tstale=step 2 since 2026-11-24T11:00:00Z\tlast=- @ - (-)\n\
         b.example\trung=milliseconds\tshape=form_post\thand-written\tstale=no\tlast=- @ - (-)"
    );
    assert_eq!(server.join().unwrap().trim(), r#"{"op":"teach_list"}"#);
}

#[test]
fn teach_list_empty_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let (sock, _server) = fake_socket(
        dir.path(),
        to_line(&ListReply {
            ok: true,
            entries: vec![],
        }),
    );
    let run = kharon(&["teach", "list"], &sock);
    assert_eq!(run.code, Some(0), "{}", run.err);
    assert_eq!(run.out, "no methods");
}

#[test]
fn teach_show_prints_the_row_and_numbered_steps() {
    let dir = tempfile::tempdir().unwrap();
    let m = method("a.example", false);
    let mut r = row(&m);
    r.overrides.insert(2, vec!["#pw2".into()]);
    let (sock, server) = fake_socket(
        dir.path(),
        to_line(&ShowReply {
            ok: true,
            entry: r,
            method: &m,
        }),
    );
    let run = kharon(&["teach", "show", "a.example"], &sock);
    assert_eq!(run.code, Some(0), "{}", run.err);
    let lines: Vec<&str> = run.out.lines().collect();
    assert_eq!(
        lines,
        [
            "a.example\trung=milliseconds\tshape=form_post\tconverted\tstale=no\tlast=- @ - (-)",
            "0\tnavigate\t/login",
            "1\tfill username\t#user\texpects input type=text",
            "2\tfill password\t[override] #pw2, #pw, [name=pass]\texpects input type=password",
            "3\tsubmit\tform",
        ]
    );
    let sent = server.join().unwrap();
    assert_eq!(sent.trim(), r#"{"op":"teach_show","domain":"a.example"}"#);
}

#[test]
fn teach_import_sends_the_method_and_flags() {
    let dir = tempfile::tempdir().unwrap();
    let m = method("a.example", false);
    let file = dir.path().join("a.kharon-method.json");
    std::fs::write(&file, m.to_json()).unwrap();
    let sock_dir = tempfile::tempdir().unwrap();
    let (sock, server) = fake_socket(
        sock_dir.path(),
        to_line(&EntryReply {
            ok: true,
            entry: row(&m),
        }),
    );
    let run = kharon(
        &[
            "teach",
            "import",
            file.to_str().unwrap(),
            "--replace",
            "--accept-main-world",
        ],
        &sock,
    );
    assert_eq!(run.code, Some(0), "{}", run.err);
    let lines: Vec<&str> = run.out.lines().collect();
    assert_eq!(
        lines,
        [
            "domain: a.example",
            "rung: milliseconds",
            "hand-written: no",
            "fills on other addresses of a.example will be refused while this method is imported",
            "imported a.example"
        ]
    );
    let sent = server.join().unwrap();
    assert_eq!(sent.matches('\n').count(), 1, "one request line");
    let got: ImportLine = serde_json::from_str(&sent).unwrap();
    assert_eq!(got.op, "teach_import");
    assert_eq!(got.method, m);
    assert!(got.replace);
    assert!(got.accept_main_world);
}

#[test]
fn teach_refusal_goes_to_stderr_as_a_plain_sentence() {
    let dir = tempfile::tempdir().unwrap();
    let m = method("a.example", true);
    let file = dir.path().join("a.kharon-method.json");
    std::fs::write(&file, m.to_json()).unwrap();
    let sock_dir = tempfile::tempdir().unwrap();
    let (sock, server) = fake_socket(
        sock_dir.path(),
        to_line(&Refusal {
            ok: false,
            error: "method_exists",
        }),
    );
    let run = kharon(&["teach", "import", file.to_str().unwrap()], &sock);
    assert_eq!(run.code, Some(1));
    assert_eq!(
        run.err,
        "kharon: that site already has a method; use --replace"
    );
    assert!(!run.out.contains("imported"), "{}", run.out);
    let got: ImportLine = serde_json::from_str(&server.join().unwrap()).unwrap();
    assert!(!got.replace && !got.accept_main_world);
}

#[test]
fn teach_with_no_socket_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let run = kharon(&["teach", "list"], &dir.path().join("missing.sock"));
    assert_eq!(run.code, Some(2));
    assert!(run.err.contains("cannot connect"), "{}", run.err);
}

#[test]
fn teach_import_of_a_malformed_file_never_connects() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("bad.kharon-method.json");
    std::fs::write(&file, "{ not a method").unwrap();
    let sock_dir = tempfile::tempdir().unwrap();
    let sock = sock_dir.path().join("owner.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    let run = kharon(&["teach", "import", file.to_str().unwrap()], &sock);
    assert_eq!(run.code, Some(2), "{}", run.err);
    assert!(run.err.starts_with("kharon: "), "{}", run.err);
    let err = listener.accept().expect_err("no connection was made");
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
fn teach_override_sends_domain_step_and_selector() {
    let dir = tempfile::tempdir().unwrap();
    let m = method("example.com", false);
    let (sock, server) = fake_socket(
        dir.path(),
        to_line(&EntryReply {
            ok: true,
            entry: row(&m),
        }),
    );
    let run = kharon(&["teach", "override", "example.com", "2", "#pw2"], &sock);
    assert_eq!(run.code, Some(0), "{}", run.err);
    let got: OverrideLine = serde_json::from_str(&server.join().unwrap()).unwrap();
    assert_eq!(got.op, "teach_override");
    assert_eq!(got.domain, "example.com");
    assert_eq!(got.step, 2);
    assert_eq!(got.selector, "#pw2");
}
