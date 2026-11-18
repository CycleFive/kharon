// Shared by several test files; each uses only some of these items.
#![allow(dead_code)]

use std::path::PathBuf;

pub fn chromium_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KHARON_CHROMIUM") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/local/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// The Chromium binary, or `None` to skip (unless a run requires it).
/// Same search as `chromium_bin` in `crates/kharond/tests/req_arch_003_org_chromium.rs`.
pub fn chromium_or_skip(test: &str) -> Option<PathBuf> {
    let bin = chromium_bin();
    if bin.is_none() {
        if std::env::var_os("KHARON_REQUIRE_CHROMIUM").is_some() {
            panic!("KHARON_REQUIRE_CHROMIUM is set but no Chromium binary was found");
        }
        eprintln!("SKIP {test}: no Chromium binary");
    }
    bin
}

// ---- the fixture login server, the person at the keyboard, and one recording run ----

use kharon_teach::browser::DevTools;
use kharon_teach::cdp::Cdp;
use kharon_teach::session::{End, Outcome, Ready, RecordOptions, SessionError, record};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;

pub const USER: &str = "kh.throwaway7";
pub const PASS: &str = "Tr0ub4dor-9x";
/// Set by the fixture on a successful login; must never reach a recording.
pub const COOKIE_VALUE: &str = "COOKIEVALUE123";

/// Browsers running at once. Parallel Chromium instances on a small machine make timing flaky.
static GATE: Semaphore = Semaphore::const_new(2);

const FORM: &str = "<!doctype html><title>form</title><form method=post action=/form-login>\
<input name=user><input name=pass type=password><button type=submit id=go>Sign in</button></form>";

const SCRIPT: &str = "<!doctype html><title>script</title><input name=user><input name=pass type=password>\
<button type=button id=go>Sign in</button><script>\
document.getElementById('go').addEventListener('click', async () => {\
 const user = document.querySelector('[name=user]').value;\
 const pass = document.querySelector('[name=pass]').value;\
 await fetch('/api/login', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({user, pass})});\
 location = '/home';\
});</script>";

const HASHED: &str = "<!doctype html><title>hashed</title><input name=user><input name=pass type=password>\
<button type=button id=go>Sign in</button><script>\
document.getElementById('go').addEventListener('click', async () => {\
 const user = document.querySelector('[name=user]').value;\
 const pass = document.querySelector('[name=pass]').value;\
 const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pass));\
 const digest = Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');\
 await fetch('/api/login', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({user, digest})});\
 location = '/home';\
});</script>";

const TWO_STEP: &str = "<!doctype html><title>step one</title><form method=post action=/two-step/password>\
<input name=user><button type=submit id=go>Next</button></form>";

const TWO_STEP_PASSWORD: &str = "<!doctype html><title>step two</title><form method=post action=/form-login>\
<input name=pass type=password><button type=submit id=go>Sign in</button></form>";

const HOME: &str = "<!doctype html><title>home</title><p>signed in</p>";

fn response(status: &str, extra: &str, body: &str, ctype: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn route(method: &str, path: &str) -> String {
    let html = "text/html; charset=utf-8";
    match (method, path) {
        ("GET", "/form") => response("200 OK", "", FORM, html),
        ("POST", "/form-login") => response(
            "302 Found",
            &format!("Location: /home\r\nSet-Cookie: sid={COOKIE_VALUE}; Path=/\r\n"),
            "",
            html,
        ),
        ("GET", "/script") => response("200 OK", "", SCRIPT, html),
        ("POST", "/api/login") => response("200 OK", "", "{\"ok\":true}", "application/json"),
        ("GET", "/two-step") => response("200 OK", "", TWO_STEP, html),
        ("POST", "/two-step/password") => response("200 OK", "", TWO_STEP_PASSWORD, html),
        ("GET", "/hashed") => response("200 OK", "", HASHED, html),
        ("GET", "/home") => response("200 OK", "", HOME, html),
        _ => response("404 Not Found", "", "not found", "text/plain"),
    }
}

async fn serve_one(mut sock: tokio::net::TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
    let want: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);
    while buf.len() < head_end + want {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let path = path.split('?').next().unwrap_or("");
    let _ = sock.write_all(route(method, path).as_bytes()).await;
    let _ = sock.shutdown().await;
}

pub struct Fixture {
    pub port: u16,
    task: JoinHandle<()>,
}

impl Fixture {
    pub async fn start() -> Fixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(serve_one(sock));
            }
        });
        Fixture { port, task }
    }

    pub fn url(&self, path: &str) -> url::Url {
        url::Url::parse(&format!("http://127.0.0.1:{}{path}", self.port)).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ---- the person ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionDoc {
    web_socket_debugger_url: String,
}

#[derive(Deserialize)]
struct Targets {
    #[serde(rename = "targetInfos")]
    infos: Vec<TargetRow>,
}

#[derive(Deserialize)]
struct TargetRow {
    #[serde(rename = "targetId")]
    id: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetIdParam<'a> {
    target_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachParam<'a> {
    target_id: &'a str,
    flatten: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Attached {
    session_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvalParam<'a> {
    expression: &'a str,
    return_by_value: bool,
}

#[derive(Deserialize)]
struct EvalResult {
    result: EvalValue,
}

#[derive(Deserialize)]
struct EvalValue {
    #[serde(default)]
    value: Option<String>,
}

#[derive(Serialize)]
struct TextParam<'a> {
    text: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MouseParam {
    #[serde(rename = "type")]
    kind: &'static str,
    x: f64,
    y: f64,
    button: &'static str,
    click_count: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyParam {
    #[serde(rename = "type")]
    kind: &'static str,
    key: &'static str,
    code: &'static str,
    windows_virtual_key_code: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'static str>,
}

#[derive(Serialize)]
struct UrlParam<'a> {
    url: &'a str,
}

#[derive(Deserialize)]
struct Ignored {}

async fn get_version_doc(port: u16) -> VersionDoc {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut text = String::new();
    let mut buf = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(10), async {
        while !text.trim_end().ends_with('}') {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "closed early");
            text.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    })
    .await
    .expect("no /json/version answer");
    let body = &text[text.find("\r\n\r\n").unwrap() + 4..];
    serde_json::from_str(body).unwrap()
}

/// A second DevTools connection that does what a person does in the window.
pub struct Person {
    cdp: Cdp,
    session: String,
}

impl Person {
    pub async fn connect(port: u16) -> Person {
        let doc = get_version_doc(port).await;
        let at = doc.web_socket_debugger_url.find("/devtools/").unwrap();
        let dev = DevTools {
            port,
            ws_path: doc.web_socket_debugger_url[at..].to_owned(),
        };
        let (cdp, rx) = Cdp::connect(&dev).await.unwrap();
        // Nobody reads this connection's events; keep the channel open.
        std::mem::forget(rx);
        let page = Self::first_page(&cdp).await.expect("no page target");
        let session: Attached = cdp
            .call(
                "Target.attachToTarget",
                &AttachParam {
                    target_id: &page,
                    flatten: true,
                },
                None,
            )
            .await
            .unwrap();
        Person {
            cdp,
            session: session.session_id,
        }
    }

    async fn first_page(cdp: &Cdp) -> Option<String> {
        let t: Targets = cdp
            .call("Target.getTargets", &Ignored2 {}, None)
            .await
            .ok()?;
        t.infos.into_iter().find(|t| t.kind == "page").map(|t| t.id)
    }

    async fn eval(&self, expression: &str) -> Option<String> {
        let r: EvalResult = self
            .cdp
            .call(
                "Runtime.evaluate",
                &EvalParam {
                    expression,
                    return_by_value: true,
                },
                Some(&self.session),
            )
            .await
            .ok()?;
        r.result.value
    }

    pub async fn goto(&self, url: &str) {
        let _: Ignored = self
            .cdp
            .call("Page.navigate", &UrlParam { url }, Some(&self.session))
            .await
            .unwrap();
    }

    pub async fn type_into(&self, css: &str, text: &str) {
        let sel = serde_json::to_string(css).unwrap();
        let focus = format!("(()=>{{document.querySelector({sel}).focus();return 'ok'}})()");
        assert_eq!(
            self.eval(&focus).await.as_deref(),
            Some("ok"),
            "focus {css}"
        );
        let _: Ignored = self
            .cdp
            .call("Input.insertText", &TextParam { text }, Some(&self.session))
            .await
            .unwrap();
    }

    pub async fn press_enter(&self) {
        for (kind, text) in [("keyDown", Some("\r")), ("keyUp", None)] {
            let _: Ignored = self
                .cdp
                .call(
                    "Input.dispatchKeyEvent",
                    &KeyParam {
                        kind,
                        key: "Enter",
                        code: "Enter",
                        windows_virtual_key_code: 13,
                        text,
                    },
                    Some(&self.session),
                )
                .await
                .unwrap();
        }
    }

    pub async fn click(&self, css: &str) {
        let sel = serde_json::to_string(css).unwrap();
        let centre = format!(
            "(()=>{{const r=document.querySelector({sel}).getBoundingClientRect();\
             return (r.x+r.width/2)+','+(r.y+r.height/2)}})()"
        );
        let at = self.eval(&centre).await.expect("element centre");
        let (x, y) = at.split_once(',').unwrap();
        let (x, y): (f64, f64) = (x.parse().unwrap(), y.parse().unwrap());
        for (kind, count) in [("mousePressed", 1), ("mouseReleased", 1)] {
            let _: Ignored = self
                .cdp
                .call(
                    "Input.dispatchMouseEvent",
                    &MouseParam {
                        kind,
                        x,
                        y,
                        button: "left",
                        click_count: count,
                    },
                    Some(&self.session),
                )
                .await
                .unwrap();
        }
    }

    pub async fn wait_for_path(&self, path: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self.eval("location.pathname").await.as_deref() == Some(path) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the page never reached {path}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    pub async fn close_all_pages(&self) {
        let t: Targets = self
            .cdp
            .call("Target.getTargets", &Ignored2 {}, None)
            .await
            .unwrap();
        for p in t.infos.into_iter().filter(|t| t.kind == "page") {
            let _: Result<Ignored, _> = self
                .cdp
                .call(
                    "Target.closeTarget",
                    &TargetIdParam { target_id: &p.id },
                    None,
                )
                .await;
        }
    }
}

#[derive(Serialize)]
struct Ignored2 {}

// ---- one recording run ----

pub struct Run {
    pub fixture: Fixture,
    pub person: Person,
    pub ready: Ready,
    end: Option<oneshot::Sender<End>>,
    task: JoinHandle<Result<Outcome, SessionError>>,
    _permit: tokio::sync::SemaphorePermit<'static>,
}

impl Run {
    /// Starts `record` headless on the fixture's `login_path` and waits until the notice page is
    /// showing. `None` when there is no browser and the run does not require one.
    pub async fn start(test: &str, login_path: &str) -> Option<Run> {
        let bin = chromium_or_skip(test)?;
        let permit = GATE.acquire().await.unwrap();
        let fixture = Fixture::start().await;
        let login = fixture.url(login_path);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (end_tx, end_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            record(
                RecordOptions {
                    login_url: &login,
                    browser: &bin,
                    headless: true,
                    tool_version: "test",
                },
                ready_tx,
                end_rx,
            )
            .await
        });
        let ready = match tokio::time::timeout(Duration::from_secs(40), ready_rx)
            .await
            .expect("the session was not ready in 40 s")
        {
            Ok(r) => r,
            Err(_) => {
                let ended = task.await.expect("the session task panicked");
                match ended {
                    Err(e) => panic!("the session failed before it was ready: {e:?}"),
                    Ok(Outcome::NeverStarted) => panic!("the window closed before it was ready"),
                    Ok(_) => panic!("the session ended before it was ready"),
                }
            }
        };
        let person = Person::connect(ready.devtools_port).await;
        Some(Run {
            fixture,
            person,
            ready,
            end: Some(end_tx),
            task,
            _permit: permit,
        })
    }

    /// What a person does: click the notice page's link, then the login page is open.
    pub async fn begin(&self, login_path: &str) {
        self.person.click("a").await;
        self.person.wait_for_path(login_path).await;
    }

    pub async fn finish(mut self, how: End) -> Outcome {
        if let Some(tx) = self.end.take() {
            let _ = tx.send(how);
        }
        self.wait().await
    }

    /// The outcome of a session that ends by itself (the window closing).
    pub async fn wait(&mut self) -> Outcome {
        tokio::time::timeout(Duration::from_secs(10), &mut self.task)
            .await
            .expect("the session did not end in 10 s")
            .expect("the session task panicked")
            .expect("the session failed")
    }

    pub fn abort(&self) {
        self.task.abort();
    }
}

/// The four fixture logins.
#[derive(Clone, Copy)]
pub enum Login {
    Form,
    Script,
    TwoStep,
    Hashed,
}

impl Login {
    pub fn path(self) -> &'static str {
        match self {
            Login::Form => "/form",
            Login::Script => "/script",
            Login::TwoStep => "/two-step",
            Login::Hashed => "/hashed",
        }
    }
}

/// Starts a run, does what a person does on `which`, confirms, and hands back the recording.
/// `None` when the run is skipped for want of a browser.
pub async fn record_login(test: &str, which: Login) -> Option<kharon_recording::Recording> {
    let run = Run::start(test, which.path()).await?;
    run.begin(which.path()).await;
    let p = &run.person;
    match which {
        Login::Form | Login::Script | Login::Hashed => {
            p.type_into("input[name=user]", USER).await;
            p.type_into("input[name=pass]", PASS).await;
            p.click("#go").await;
        }
        Login::TwoStep => {
            p.type_into("input[name=user]", USER).await;
            p.click("#go").await;
            p.wait_for_path("/two-step/password").await;
            p.type_into("input[name=pass]", PASS).await;
            p.click("#go").await;
        }
    }
    p.wait_for_path("/home").await;
    match run.finish(End::Confirmed).await {
        Outcome::Recorded(r) => Some(*r),
        _ => panic!("expected a recording"),
    }
}

impl Person {
    /// The `attr` attribute of the element `css` matches, or `None` when it matches nothing.
    pub async fn attr_of(&self, css: &str, attr: &str) -> Option<String> {
        let sel = serde_json::to_string(css).unwrap();
        let attr = serde_json::to_string(attr).unwrap();
        self.eval(&format!(
            "(()=>{{const e=document.querySelector({sel});return e?e.getAttribute({attr}):null}})()"
        ))
        .await
    }
}

// ---- the whole program, driven through `run_with` ----

/// A cloneable in-memory writer; the program gets one clone and the test reads the other.
#[derive(Clone, Default)]
pub struct Shared(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl Shared {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for Shared {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What a whole run of the program left behind.
pub struct Program {
    pub exit: kharon_teach::Exit,
    pub path: PathBuf,
    pub file_text: String,
    pub file_mode: u32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs the program headless against the fixture's `/form` login (the path may carry a query),
/// as a person would: says `yes`, opens the login page from the notice, types the throwaway
/// values, signs in, presses Enter. `None` when there is no browser and none is required.
pub async fn run_program(test: &str, form_path_and_query: &str) -> Option<Program> {
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt;
    let bin = chromium_or_skip(test)?;
    let _permit = GATE.acquire().await.unwrap();
    let fixture = Fixture::start().await;
    let login = fixture.url(form_path_and_query);
    let dir = std::env::temp_dir().join(format!(
        "kharon-prog-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let out = dir.join("login.kharon-recording.json");
    let cli = kharon_teach::cli::Cli::try_parse_from([
        "kharon-teach",
        login.as_str(),
        "--browser",
        bin.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ])
    .unwrap();
    let (stdout, stderr) = (Shared::default(), Shared::default());
    let (ready_tx, ready_rx) = oneshot::channel();
    let (mut keys, stdin) = tokio::io::duplex(1024);
    let task = tokio::spawn({
        let (stdout, stderr) = (stdout.clone(), stderr.clone());
        async move {
            kharon_teach::run_with(
                cli,
                tokio::io::BufReader::new(stdin),
                stdout,
                stderr,
                kharon_teach::Hooks {
                    headless: true,
                    ready: Some(ready_tx),
                },
            )
            .await
        }
    });
    keys.write_all(b"yes\n").await.unwrap();
    let ready = tokio::time::timeout(Duration::from_secs(40), ready_rx)
        .await
        .expect("the program was not ready in 40 s")
        .expect("the program ended before it was ready");
    let person = Person::connect(ready.devtools_port).await;
    person.click("a").await;
    person.wait_for_path(path_of(form_path_and_query)).await;
    person.type_into("input[name=user]", USER).await;
    person.type_into("input[name=pass]", PASS).await;
    person.click("#go").await;
    person.wait_for_path("/home").await;
    keys.write_all(b"\n").await.unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .expect("the program did not end in 20 s")
        .expect("the program panicked");
    let file_text = std::fs::read_to_string(&out).unwrap_or_default();
    let file_mode = std::fs::metadata(&out)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0);
    let _ = std::fs::remove_dir_all(&dir);
    Some(Program {
        exit,
        path: out,
        file_text,
        file_mode,
        stdout: stdout.text(),
        stderr: stderr.text(),
    })
}

fn path_of(path_and_query: &str) -> &str {
    path_and_query.split('?').next().unwrap_or("")
}
