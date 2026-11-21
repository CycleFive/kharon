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
use kharon_teach::session::{
    End, Outcome, Ready, RecordOptions, SessionError, WorldProbe, record_with,
};
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
<input name=user><input name=pass type=password><input type=checkbox name=remember id=rem>\
<button type=submit id=go>Sign in</button></form>";

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

const SCRIPT_FORMDATA: &str = "<!doctype html><title>formdata</title><input name=user><input name=pass type=password>\
<button type=button id=go>Sign in</button><script>\
document.getElementById('go').addEventListener('click', async () => {\
 const fd = new FormData();\
 fd.append('user', document.querySelector('[name=user]').value);\
 fd.append('pass', document.querySelector('[name=pass]').value);\
 await fetch('/api/login-form', {method:'POST', body: fd});\
 location = '/home';\
});</script>";

const SCRIPT_BLOB: &str = "<!doctype html><title>blob</title><input name=user><input name=pass type=password>\
<button type=button id=go>Sign in</button><script>\
document.getElementById('go').addEventListener('click', async () => {\
 const user = document.querySelector('[name=user]').value;\
 const pass = document.querySelector('[name=pass]').value;\
 const body = new Blob([JSON.stringify({user, pass})], {type:'application/json'});\
 await fetch('/api/login-blob', {method:'POST', headers:{'content-type':'application/json'}, body});\
 location = '/home';\
});</script>";

/// A form that copies what is typed into the user field into the field's own `id`.
const MIRROR: &str = "<!doctype html><title>mirror</title><form method=post action=/form-login>\
<input name=user><input name=pass type=password><button type=submit id=go>Sign in</button></form>\
<script>for (const f of document.querySelectorAll('input')) {\
 f.addEventListener('input', () => { f.id = f.value; });\
}</script>";

/// A form whose children replace `action`, `method`, `id` and `tagName` on the form element.
const CLOBBER: &str = "<!doctype html><title>clobber</title><form id=f method=post action=/form-login>\
<input name=action><input name=method><input name=id><input name=tagName><input name=getAttribute>\
<input name=user><input name=pass type=password><button type=submit id=go>Sign in</button></form>";

const POPUP: &str = "<!doctype html><title>popup</title>\
<button type=button id=go onclick=\"window.open('/form')\">Sign in elsewhere</button>";

/// `{HOST}` is the same server under another host name, so it is another origin.
const FRAME_OUTER: &str = "<!doctype html><title>outer</title>\
<iframe id=fr width=600 height=300 src=\"http://{HOST}/form\"></iframe>";

/// Puts the typed values into text the recording keeps: a JSON key, and the next URL's path and
/// query key.
const TYPED_IN_TEXT: &str = "<!doctype html><title>typed</title><input name=user><input name=pass type=password>\
<button type=button id=go>Sign in</button><script>\
document.getElementById('go').addEventListener('click', async () => {\
 const user = document.querySelector('[name=user]').value;\
 const pass = document.querySelector('[name=pass]').value;\
 await fetch('/api/typed', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({[user]: pass})});\
 location = '/u/' + encodeURIComponent(user) + '?' + encodeURIComponent(user) + '=1';\
});</script>";

const HOME: &str = "<!doctype html><title>home</title><p>signed in</p>";

fn response(status: &str, extra: &str, body: &str, ctype: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn route(method: &str, path: &str, host: &str) -> String {
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
        ("GET", "/script-formdata") => response("200 OK", "", SCRIPT_FORMDATA, html),
        ("POST", "/api/login-form") => response("200 OK", "", "{\"ok\":true}", "application/json"),
        ("GET", "/script-blob") => response("200 OK", "", SCRIPT_BLOB, html),
        ("POST", "/api/login-blob") => response("200 OK", "", "{\"ok\":true}", "application/json"),
        ("GET", "/mirror") => response("200 OK", "", MIRROR, html),
        ("GET", "/clobber") => response("200 OK", "", CLOBBER, html),
        ("GET", "/popup") => response("200 OK", "", POPUP, html),
        ("GET", "/frame-outer") => {
            // Same server, another host name: a different origin.
            let other = host.replace("127.0.0.1", "localhost");
            response("200 OK", "", &FRAME_OUTER.replace("{HOST}", &other), html)
        }
        ("GET", "/hashed") => response("200 OK", "", HASHED, html),
        ("GET", "/typed") => response("200 OK", "", TYPED_IN_TEXT, html),
        ("POST", "/api/typed") => response("200 OK", "", "{\"ok\":true}", "application/json"),
        ("GET", p) if p.starts_with("/u/") => response("200 OK", "", HOME, html),
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
    let host = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .starts_with("host:")
                .then(|| l[5..].trim().to_owned())
        })
        .unwrap_or_default();
    let _ = sock.write_all(route(method, path, &host).as_bytes()).await;
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
    #[serde(default)]
    url: String,
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

    pub async fn eval(&self, expression: &str) -> Option<String> {
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
        let focus = format!(
            "(()=>{{const e=document.querySelector({sel});if(!e)return 'no';e.focus();return 'ok'}})()"
        );
        // The page may still be loading: wait for the field, as `type_into_frame` does.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while self.eval(&focus).await.as_deref() != Some("ok") {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the field {css} never appeared"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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
        // The page may still be loading, or its context may be torn down mid-navigation (eval
        // then gives None): wait for the element to exist and have a box.
        let centre = format!(
            "(()=>{{const e=document.querySelector({sel});if(!e)return null;\
             const r=e.getBoundingClientRect();if(!r.width||!r.height)return null;\
             return (r.x+r.width/2)+','+(r.y+r.height/2)}})()"
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let at = loop {
            if let Some(at) = self.eval(&centre).await {
                break at;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no clickable {css} in 15 s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
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
        Self::start_with(test, login_path, WorldProbe::Normal).await
    }

    /// [`Run::start`] with a way to make the isolated world fail.
    pub async fn start_with(test: &str, login_path: &str, probe: WorldProbe) -> Option<Run> {
        let bin = chromium_or_skip(test)?;
        let permit = GATE.acquire().await.unwrap();
        let fixture = Fixture::start().await;
        let login = fixture.url(login_path);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (end_tx, end_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            record_with(
                RecordOptions {
                    login_url: &login,
                    browser: &bin,
                    headless: true,
                    tool_version: "test",
                },
                ready_tx,
                end_rx,
                probe,
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
    ScriptFormData,
    ScriptBlob,
    Mirror,
    Clobber,
}

impl Login {
    pub fn path(self) -> &'static str {
        match self {
            Login::Form => "/form",
            Login::Script => "/script",
            Login::TwoStep => "/two-step",
            Login::Hashed => "/hashed",
            Login::ScriptFormData => "/script-formdata",
            Login::ScriptBlob => "/script-blob",
            Login::Mirror => "/mirror",
            Login::Clobber => "/clobber",
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
        Login::Mirror => {
            p.type_into("input[name=user]", USER).await;
            p.type_into("input[name=pass]", PASS).await;
            p.press_enter().await;
        }
        Login::Form
        | Login::Script
        | Login::Hashed
        | Login::ScriptFormData
        | Login::ScriptBlob
        | Login::Clobber => {
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

#[derive(Serialize)]
struct FlattenAttach<'a> {
    #[serde(rename = "targetId")]
    target_id: &'a str,
    flatten: bool,
}

impl Person {
    /// How many page targets the browser has.
    pub async fn page_count(&self) -> usize {
        let t: Targets = self
            .cdp
            .call("Target.getTargets", &Ignored2 {}, None)
            .await
            .unwrap();
        t.infos.iter().filter(|t| t.kind == "page").count()
    }

    pub async fn wait_for_pages(&self, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while self.page_count().await < n {
            assert!(tokio::time::Instant::now() < deadline, "no page number {n}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The browser closes itself, as when someone quits it from its menu.
    pub async fn close_browser(&self) {
        let _: Result<Ignored, _> = self.cdp.call("Browser.close", &Ignored2 {}, None).await;
    }

    /// A session on the page's embedded frame whose URL is on `host`, waiting for it to exist.
    /// The frame is in another process, so the page's own session cannot reach into it.
    pub async fn attach_frame(&self, host: &str) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            let t: Targets = self
                .cdp
                .call("Target.getTargets", &Ignored2 {}, None)
                .await
                .unwrap();
            if let Some(f) = t
                .infos
                .iter()
                .find(|t| t.kind == "iframe" && t.url.contains(host))
            {
                let a: Attached = self
                    .cdp
                    .call(
                        "Target.attachToTarget",
                        &FlattenAttach {
                            target_id: &f.id,
                            flatten: true,
                        },
                        None,
                    )
                    .await
                    .unwrap();
                return a.session_id;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no frame target for {host}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn eval_in(&self, session: &str, expression: &str) -> Option<String> {
        let r: EvalResult = self
            .cdp
            .call(
                "Runtime.evaluate",
                &EvalParam {
                    expression,
                    return_by_value: true,
                },
                Some(session),
            )
            .await
            .ok()?;
        r.result.value
    }

    /// Focus `css` inside the frame, then type into it.
    pub async fn type_into_frame(&self, frame: &str, css: &str, text: &str) {
        let sel = serde_json::to_string(css).unwrap();
        let focus = format!(
            "(()=>{{const e=document.querySelector({sel});if(!e)return 'no';e.focus();return 'ok'}})()"
        );
        // The frame's document may not be there yet when its target first appears.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while self.eval_in(frame, &focus).await.as_deref() != Some("ok") {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the field {css} never appeared in the frame"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _: Ignored = self
            .cdp
            .call("Input.insertText", &TextParam { text }, Some(frame))
            .await
            .unwrap();
    }

    pub async fn wait_for_frame_path(&self, frame: &str, path: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if self.eval_in(frame, "location.pathname").await.as_deref() == Some(path) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the frame never reached {path}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The pid of the main browser process of the profile at `profile`, found through `/proc`.
    pub fn browser_pid(profile: &std::path::Path) -> Option<u32> {
        let want = format!("--user-data-dir={}", profile.display());
        for e in std::fs::read_dir("/proc").ok()?.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(cmd) = std::fs::read(e.path().join("cmdline")) else {
                continue;
            };
            // Chrome rewrites its own argv into one space-separated string; no path here has a space.
            let args: Vec<&[u8]> = cmd.split(|b| *b == 0 || *b == b' ').collect();
            if args.contains(&want.as_bytes()) && !args.iter().any(|a| a.starts_with(b"--type=")) {
                return Some(pid);
            }
        }
        None
    }
}

// ---- shared by tests that drive or scan the shipped program ----

/// Waits for one of the browser slots (see `GATE`); hold the permit while a browser runs.
pub async fn browser_permit() -> tokio::sync::SemaphorePermit<'static> {
    GATE.acquire().await.unwrap()
}

/// Every `.rs` file under `dir`.
pub fn rust_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(rust_files(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

/// The shipped part of a source file: the text before its test MODULE (`#[cfg(test)]` followed
/// by `mod tests`, with any visibility). A `#[cfg(test)]` item anywhere before it would hide
/// shipped code from every scan, so that is an error.
pub fn split_shipped(text: &str) -> Result<&str, String> {
    let mut from = 0;
    while let Some(at) = text[from..].find("#[cfg(test)]") {
        let at = from + at;
        let after = text[at + "#[cfg(test)]".len()..].trim_start();
        let is_module = ["mod tests", "pub mod tests", "pub(crate) mod tests"]
            .iter()
            .any(|m| after.starts_with(m));
        if is_module {
            return if text[..at].contains("#[cfg(test)]") {
                Err("a #[cfg(test)] item sits above the test module".to_owned())
            } else {
                Ok(&text[..at])
            };
        }
        from = at + 1;
    }
    // No test module: the whole file is shipped, so it must have no test-only item either.
    if text.contains("#[cfg(test)]") {
        Err("a #[cfg(test)] item with no test module after it".to_owned())
    } else {
        Ok(text)
    }
}

/// Shipped code only: for each file under `crates/kharon-teach/src`, the text before its test
/// module (see [`split_shipped`]). Panics when a `#[cfg(test)]` item sits above that module.
pub fn shipped_sources() -> Vec<(PathBuf, String)> {
    let files = rust_files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    assert!(!files.is_empty());
    files
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap();
            let shipped = match split_shipped(&text) {
                Ok(s) => s.to_owned(),
                Err(why) => panic!("{}: {why}", p.display()),
            };
            (p, shipped)
        })
        .collect()
}
