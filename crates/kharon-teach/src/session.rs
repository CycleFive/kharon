//! One recording session: a launched browser, a CDP connection and the capture state machine,
//! wired so that what a person does in the window becomes a [`Recording`].
//!
//! Nothing in this file writes to stdout or stderr, and nothing from a frame reaches an error.

use crate::browser::{Browser, BrowserError, Launch, Profile};
use crate::capture::{
    Capture, CaptureEvent, EndInfo, PageEventKind, RawBody, RawElement, RawForm, RawFrame,
};
use crate::cdp::{Cdp, CdpError, Event, parse_quiet};
use crate::events::{
    AddBinding, AddScriptToEvaluateOnNewDocument, AttachedToTarget, BindingCalled, Empty,
    FrameNavigated, GetRequestPostData, Hello, LayoutMetrics, ListenerReport, Navigate, PostData,
    RemoveScript, ReportKind, RequestWillBeSent, ResponseReceived, ResponseReceivedExtraInfo,
    ScriptId, SetAutoAttach, SetDiscoverTargets, TargetDestroyed, VersionInfo,
};
use crate::notice::notice_page_url;
use kharon_recording::{BrowserInfo, EndedBy, ListenerWorld, Recording, ResourceKind, Viewport};
use serde::Serialize;
use serde::de::IgnoredAny;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc::UnboundedReceiver, oneshot};
use zeroize::Zeroizing;

/// The page script, run in every frame at document start.
pub const LISTENER_JS: &str = include_str!("listener.js");
const BINDING: &str = "__kharonTeach";
const WORLD: &str = "kharon-teach";
/// How long the listener may take to announce itself on the notice page.
const HELLO_WAIT: Duration = Duration::from_secs(3);
/// How long to keep taking events after the person confirms.
const LATE_WAIT: Duration = Duration::from_millis(300);
/// How long the browser may take to show its first page.
const FIRST_PAGE_WAIT: Duration = Duration::from_secs(10);

pub enum End {
    Confirmed,
    Discard,
}

pub struct RecordOptions<'a> {
    pub login_url: &'a url::Url,
    pub browser: &'a std::path::Path,
    pub headless: bool,
    pub tool_version: &'a str,
}

pub struct Ready {
    pub devtools_port: u16,
    pub profile_dir: PathBuf,
    pub stale_profiles_removed: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Browser(#[from] BrowserError),
    #[error(transparent)]
    Cdp(#[from] CdpError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("the browser showed no page")]
    NoPage,
    #[error("the page script did not start in the browser")]
    ListenerNotRunning,
}

pub enum Outcome {
    Recorded(Box<Recording>),
    Discarded,
    NeverStarted,
}

/// RFC 3339, UTC.
pub fn utc_rfc3339(t: SystemTime) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from(t)
        .format(&Rfc3339)
        .unwrap_or_default()
}

struct Sess {
    target_id: String,
    /// The id of the injected script, so the world can be changed once.
    script_id: Option<String>,
}

/// One hop of a request. Chromium reuses a request id across redirects, and the raw headers of a
/// hop (`Set-Cookie`) can arrive after the next hop's `requestWillBeSent`.
#[derive(Default)]
struct Hop {
    /// The raw-header event for this hop has been taken.
    extra_seen: bool,
    status: Option<u16>,
    content_type: Option<String>,
    set_cookie: bool,
}

enum Flow {
    Continue,
    WindowClosed,
}

struct Rec {
    cdp: Cdp,
    notice: String,
    world: ListenerWorld,
    sessions: HashMap<String, Sess>,
    page_targets: HashSet<String>,
    first_session: Option<String>,
    first_main_frame: Option<String>,
    capture: Capture,
    clock: Option<(Instant, SystemTime)>,
    hops: HashMap<String, Vec<Hop>>,
    hello: bool,
}

async fn send<P: Serialize>(
    cdp: &Cdp,
    method: &str,
    params: &P,
    session: Option<&str>,
) -> Result<(), CdpError> {
    cdp.call::<P, IgnoredAny>(method, params, session)
        .await
        .map(|_| ())
}

/// Sweeps stale profiles, launches, records until `end` fires or the window closes, cleans up.
/// `ready` fires once the browser is up and the notice page is showing. Dropping the future
/// (Ctrl-C) still removes the profile.
pub async fn record(
    opts: RecordOptions<'_>,
    ready: oneshot::Sender<Ready>,
    end: oneshot::Receiver<End>,
) -> Result<Outcome, SessionError> {
    let stale = Profile::sweep_stale().unwrap_or(0);
    let profile = Profile::create()?;
    let profile_dir = profile.path().to_owned();
    let notice = notice_page_url(opts.login_url);
    let (browser, dev) = Browser::launch(Launch {
        browser: opts.browser,
        profile: &profile,
        first_url: "about:blank",
        headless: opts.headless,
    })
    .await?;
    let mut guard = Cleanup {
        browser: Some(browser),
        profile: Some(profile),
    };
    let Some(browser) = guard.browser.as_mut() else {
        return Err(SessionError::NoPage);
    };
    let result = run(
        browser,
        &dev,
        &opts,
        &notice,
        Ready {
            devtools_port: dev.port,
            profile_dir,
            stale_profiles_removed: stale,
        },
        ready,
        end,
    )
    .await;
    guard.finish().await;
    result
}

/// Owns the browser and its profile. However the session ends, including the future being
/// dropped, the browser is killed and the profile removed.
struct Cleanup {
    browser: Option<Browser>,
    profile: Option<Profile>,
}

/// A just-killed browser's helper processes can still be writing into the profile for a moment.
const REMOVE_TRIES: u32 = 60;
const REMOVE_PAUSE: Duration = Duration::from_millis(50);

/// Removes the profile; true once it is gone.
fn try_remove(path: &std::path::Path) -> bool {
    let _ = std::fs::remove_dir_all(path);
    !path.exists()
}

/// The browser's process and everything below it. A killed browser's helper processes (the
/// network service above all) outlive it for a moment and recreate files in a profile that was
/// just removed, so the profile is removed only after they are gone.
#[cfg(target_os = "linux")]
fn family(root: u32) -> Vec<u32> {
    let mut parent_of: Vec<(u32, u32)> = Vec::new();
    if let Ok(procs) = std::fs::read_dir("/proc") {
        for e in procs.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if let Some((_, ppid)) = stat_of(pid) {
                parent_of.push((pid, ppid));
            }
        }
    }
    let mut out = vec![root];
    let mut i = 0;
    while i < out.len() {
        let at = out[i];
        out.extend(
            parent_of
                .iter()
                .filter(|(_, pp)| *pp == at)
                .map(|(p, _)| *p),
        );
        i += 1;
    }
    out
}

/// A process's state letter and parent pid, from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn stat_of(pid: u32) -> Option<(char, u32)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is in parentheses and may hold spaces and parentheses itself.
    let rest = &text[text.rfind(')')? + 1..];
    let mut f = rest.split_whitespace();
    let state = f.next()?.chars().next()?;
    let ppid = f.next()?.parse().ok()?;
    Some((state, ppid))
}

#[cfg(target_os = "linux")]
fn any_alive(pids: &[u32]) -> bool {
    pids.iter()
        .any(|p| stat_of(*p).is_some_and(|(state, _)| state != 'Z' && state != 'X'))
}

#[cfg(not(target_os = "linux"))]
fn family(root: u32) -> Vec<u32> {
    vec![root]
}

#[cfg(not(target_os = "linux"))]
fn any_alive(_pids: &[u32]) -> bool {
    false
}

impl Cleanup {
    fn family(&self) -> Vec<u32> {
        self.browser
            .as_ref()
            .map(|b| family(b.pid()))
            .unwrap_or_default()
    }

    /// The normal end: wait for the browser to be gone, then remove the profile.
    async fn finish(&mut self) {
        let procs = self.family();
        if let Some(b) = self.browser.take() {
            let _ = b.close().await;
        }
        for _ in 0..REMOVE_TRIES {
            if !any_alive(&procs) {
                break;
            }
            tokio::time::sleep(REMOVE_PAUSE).await;
        }
        if let Some(p) = self.profile.take() {
            let path = p.path().to_owned();
            for _ in 0..REMOVE_TRIES {
                if try_remove(&path) {
                    break;
                }
                tokio::time::sleep(REMOVE_PAUSE).await;
            }
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let procs = self.family();
        // Dropping the browser kills it.
        drop(self.browser.take());
        for _ in 0..REMOVE_TRIES {
            if !any_alive(&procs) {
                break;
            }
            std::thread::sleep(REMOVE_PAUSE);
        }
        if let Some(p) = self.profile.take() {
            let path = p.path().to_owned();
            for _ in 0..REMOVE_TRIES {
                if try_remove(&path) {
                    break;
                }
                std::thread::sleep(REMOVE_PAUSE);
            }
        }
    }
}

async fn run(
    browser: &mut Browser,
    dev: &crate::browser::DevTools,
    opts: &RecordOptions<'_>,
    notice: &str,
    info: Ready,
    ready: oneshot::Sender<Ready>,
    mut end: oneshot::Receiver<End>,
) -> Result<Outcome, SessionError> {
    let (cdp, mut rx) = Cdp::connect(dev).await?;
    let mut rec = Rec {
        cdp: cdp.clone(),
        notice: notice.to_owned(),
        world: ListenerWorld::Isolated,
        sessions: HashMap::new(),
        page_targets: HashSet::new(),
        first_session: None,
        first_main_frame: None,
        capture: Capture::new(opts.login_url.as_str(), opts.tool_version),
        clock: None,
        hops: HashMap::new(),
        hello: false,
    };

    send(
        &cdp,
        "Target.setDiscoverTargets",
        &SetDiscoverTargets { discover: true },
        None,
    )
    .await?;
    send(&cdp, "Target.setAutoAttach", &auto_attach(), None).await?;

    // The browser's first page.
    let deadline = tokio::time::Instant::now() + FIRST_PAGE_WAIT;
    while rec.first_session.is_none() {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(ev)) => {
                if let Flow::WindowClosed = rec.on_event(ev).await {
                    return Ok(Outcome::NeverStarted);
                }
            }
            Ok(None) | Err(_) => return Err(SessionError::NoPage),
        }
    }

    match rec.choose_world(&mut rx).await? {
        Choice::Done => {}
        Choice::Closed => return Ok(Outcome::NeverStarted),
    }
    let _ = ready.send(info);

    let mut closed = false;
    let confirmed = loop {
        tokio::select! {
            biased;
            e = &mut end => break matches!(e, Ok(End::Confirmed)),
            ev = rx.recv() => match ev {
                Some(ev) => {
                    if let Flow::WindowClosed = rec.on_event(ev).await {
                        closed = true;
                        break false;
                    }
                }
                None => { closed = true; break false; }
            },
            _ = browser.wait() => { closed = true; break false; }
        }
    };

    if !confirmed && !closed {
        return Ok(Outcome::Discarded);
    }
    // Everything already queued, then a short wait for the last navigation and its response.
    while let Ok(ev) = rx.try_recv() {
        if closed {
            rec.on_event(ev).await;
        } else if let Flow::WindowClosed = rec.on_event(ev).await {
            closed = true;
        }
    }
    if !closed {
        let deadline = tokio::time::Instant::now() + LATE_WAIT;
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            rec.on_event(ev).await;
        }
    }
    Ok(rec.finish(confirmed))
}

fn auto_attach() -> SetAutoAttach {
    SetAutoAttach {
        auto_attach: true,
        wait_for_debugger_on_start: true,
        flatten: true,
    }
}

enum Choice {
    Done,
    Closed,
}

enum Wait {
    Hello,
    Timeout,
    Closed,
}

impl Rec {
    fn t_ms(&self) -> u64 {
        self.clock.map_or(0, |(t0, _)| {
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
        })
    }

    /// Show the notice page and find out which world the listener runs in. The world is never
    /// switched after this.
    async fn choose_world(
        &mut self,
        rx: &mut UnboundedReceiver<Event>,
    ) -> Result<Choice, SessionError> {
        let Some(first) = self.first_session.clone() else {
            return Err(SessionError::NoPage);
        };
        let notice = self.notice.clone();
        send(
            &self.cdp,
            "Page.navigate",
            &Navigate { url: &notice },
            Some(&first),
        )
        .await?;
        match self.wait_hello(rx).await {
            Wait::Hello => return Ok(Choice::Done),
            Wait::Closed => return Ok(Choice::Closed),
            Wait::Timeout => {}
        }
        // The isolated world did not deliver: install in the main world instead.
        if let Some(id) = self
            .sessions
            .get_mut(&first)
            .and_then(|s| s.script_id.take())
        {
            send(
                &self.cdp,
                "Page.removeScriptToEvaluateOnNewDocument",
                &RemoveScript { identifier: &id },
                Some(&first),
            )
            .await?;
        }
        self.world = ListenerWorld::Main;
        self.install(&first).await?;
        send(
            &self.cdp,
            "Page.navigate",
            &Navigate { url: &notice },
            Some(&first),
        )
        .await?;
        match self.wait_hello(rx).await {
            Wait::Hello => Ok(Choice::Done),
            Wait::Closed => Ok(Choice::Closed),
            Wait::Timeout => Err(SessionError::ListenerNotRunning),
        }
    }

    async fn wait_hello(&mut self, rx: &mut UnboundedReceiver<Event>) -> Wait {
        self.hello = false;
        let deadline = tokio::time::Instant::now() + HELLO_WAIT;
        while !self.hello {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(ev)) => {
                    if let Flow::WindowClosed = self.on_event(ev).await {
                        return Wait::Closed;
                    }
                }
                Ok(None) => return Wait::Closed,
                Err(_) => return Wait::Timeout,
            }
        }
        Wait::Hello
    }

    /// The binding and the script, in the world chosen now.
    async fn install(&mut self, session: &str) -> Result<(), CdpError> {
        let isolated = self.world == ListenerWorld::Isolated;
        send(
            &self.cdp,
            "Runtime.addBinding",
            &AddBinding {
                name: BINDING,
                execution_context_name: isolated.then_some(WORLD),
            },
            Some(session),
        )
        .await?;
        let id: ScriptId = self
            .cdp
            .call(
                "Page.addScriptToEvaluateOnNewDocument",
                &AddScriptToEvaluateOnNewDocument {
                    source: LISTENER_JS,
                    world_name: isolated.then_some(WORLD),
                },
                Some(session),
            )
            .await?;
        if let Some(s) = self.sessions.get_mut(session) {
            s.script_id = Some(id.identifier);
        }
        Ok(())
    }

    async fn setup(&mut self, session: &str) -> Result<(), CdpError> {
        send(
            &self.cdp,
            "Target.setAutoAttach",
            &auto_attach(),
            Some(session),
        )
        .await?;
        send(&self.cdp, "Page.enable", &Empty {}, Some(session)).await?;
        send(&self.cdp, "Network.enable", &Empty {}, Some(session)).await?;
        send(&self.cdp, "Runtime.enable", &Empty {}, Some(session)).await?;
        self.install(session).await?;
        Ok(())
    }

    async fn on_event(&mut self, ev: Event) -> Flow {
        let session = ev.session_id.as_deref();
        match ev.method.as_str() {
            "Target.attachedToTarget" => {
                if let Ok(p) = parse_quiet::<AttachedToTarget>(&ev.params) {
                    self.attached(p).await;
                }
            }
            "Target.targetDestroyed" => {
                if let Ok(p) = parse_quiet::<TargetDestroyed>(&ev.params) {
                    self.sessions.retain(|_, s| s.target_id != p.target_id);
                    if self.page_targets.remove(&p.target_id) && self.page_targets.is_empty() {
                        return Flow::WindowClosed;
                    }
                }
            }
            _ => {
                let Some(session) = session else {
                    return Flow::Continue;
                };
                if !self.sessions.contains_key(session) {
                    return Flow::Continue;
                }
                match ev.method.as_str() {
                    "Page.frameNavigated" => {
                        if let Ok(p) = parse_quiet::<FrameNavigated>(&ev.params) {
                            self.navigated(session, p).await;
                        }
                    }
                    "Runtime.bindingCalled" => {
                        if let Ok(p) = parse_quiet::<BindingCalled>(&ev.params) {
                            self.binding(session, &p);
                        }
                    }
                    "Network.requestWillBeSent" => {
                        if let Ok(p) = parse_quiet::<RequestWillBeSent>(&ev.params) {
                            self.request(session, p).await;
                        }
                    }
                    "Network.responseReceived" => {
                        if let Ok(p) = parse_quiet::<ResponseReceived>(&ev.params) {
                            let hops = self.hops.entry(p.request_id.clone()).or_default();
                            if hops.is_empty() {
                                hops.push(Hop::default());
                            }
                            let n = hops.len() - 1;
                            let hop = &mut hops[n];
                            hop.status = Some(p.response.status);
                            hop.content_type = p.response.headers.content_type().map(str::to_owned);
                            hop.set_cookie |= p.response.headers.has_set_cookie();
                            self.push_response(&p.request_id, n);
                        }
                    }
                    "Network.responseReceivedExtraInfo" => {
                        if let Ok(p) = parse_quiet::<ResponseReceivedExtraInfo>(&ev.params) {
                            let hops = self.hops.entry(p.request_id.clone()).or_default();
                            if hops.is_empty() {
                                hops.push(Hop::default());
                            }
                            // One per hop, in order: the first hop that has not had its own and
                            // does not contradict this one's status.
                            let n = hops
                                .iter()
                                .position(|h| {
                                    !h.extra_seen
                                        && (h.status.is_none()
                                            || p.status_code.is_none()
                                            || h.status == p.status_code)
                                })
                                .unwrap_or(hops.len() - 1);
                            let hop = &mut hops[n];
                            hop.extra_seen = true;
                            hop.status = hop.status.or(p.status_code);
                            if hop.content_type.is_none() {
                                hop.content_type = p.headers.content_type().map(str::to_owned);
                            }
                            hop.set_cookie |= p.headers.has_set_cookie();
                            self.push_response(&p.request_id, n);
                        }
                    }
                    _ => {}
                }
            }
        }
        Flow::Continue
    }

    async fn attached(&mut self, p: AttachedToTarget) {
        let is_page = match p.target_info.kind.as_str() {
            "page" => true,
            "iframe" => false,
            _ => {
                // Workers and the rest: let them run, record nothing from them.
                let _ = send(
                    &self.cdp,
                    "Runtime.runIfWaitingForDebugger",
                    &Empty {},
                    Some(&p.session_id),
                )
                .await;
                return;
            }
        };
        let is_first = is_page && self.first_session.is_none();
        if is_page {
            self.page_targets.insert(p.target_info.target_id.clone());
            if is_first {
                self.first_session = Some(p.session_id.clone());
            } else {
                self.capture.push(CaptureEvent::Popup);
            }
        }
        self.sessions.insert(
            p.session_id.clone(),
            Sess {
                target_id: p.target_info.target_id,
                script_id: None,
            },
        );
        // A page that vanishes while it is being set up is not an error for the session.
        let _ = self.setup(&p.session_id).await;
        let _ = send(
            &self.cdp,
            "Runtime.runIfWaitingForDebugger",
            &Empty {},
            Some(&p.session_id),
        )
        .await;
    }

    fn is_first_main(&self, session: &str, parent: Option<&str>) -> bool {
        self.first_session.as_deref() == Some(session) && parent.is_none()
    }

    async fn navigated(&mut self, session: &str, p: FrameNavigated) {
        let main = self.is_first_main(session, p.frame.parent_id.as_deref());
        if main {
            self.first_main_frame = Some(p.frame.id.clone());
            if self.clock.is_none() {
                let url = p.frame.url.as_str();
                if url == self.notice || url.starts_with("data:") || url == "about:blank" {
                    return;
                }
                self.start(session).await;
            }
        }
        if self.clock.is_some() {
            self.capture.push(CaptureEvent::Navigation {
                t_ms: self.t_ms(),
                frame: RawFrame {
                    main,
                    url: p.frame.url,
                },
            });
        }
    }

    /// The main frame left the notice page.
    async fn start(&mut self, session: &str) {
        self.clock = Some((Instant::now(), SystemTime::now()));
        let version: Result<VersionInfo, _> =
            self.cdp.call("Browser.getVersion", &Empty {}, None).await;
        let metrics: Result<LayoutMetrics, _> = self
            .cdp
            .call("Page.getLayoutMetrics", &Empty {}, Some(session))
            .await;
        let (product, user_agent) = version
            .map(|v| (v.product, v.user_agent))
            .unwrap_or_default();
        let (width, height) = metrics.map_or((0, 0), |m| {
            (
                m.css_visual_viewport.client_width.round() as u32,
                m.css_visual_viewport.client_height.round() as u32,
            )
        });
        self.capture.push(CaptureEvent::Started {
            browser: BrowserInfo {
                product,
                user_agent,
                viewport: Viewport { width, height },
            },
            listener_world: self.world,
        });
    }

    fn binding(&mut self, session: &str, p: &BindingCalled) {
        if p.name != BINDING {
            return;
        }
        if parse_quiet::<Hello>(&p.payload).is_ok_and(|h| h.hello) {
            self.hello = true;
            return;
        }
        let Ok(r) = parse_quiet::<ListenerReport>(&p.payload) else {
            return;
        };
        if !r.within_limits() || self.clock.is_none() || !self.sessions.contains_key(session) {
            return;
        }
        let kind = match r.kind {
            ReportKind::Input => PageEventKind::Input,
            ReportKind::Change => PageEventKind::Change,
            ReportKind::Click => PageEventKind::Click,
            ReportKind::Submit => PageEventKind::Submit,
            ReportKind::EnterKey => PageEventKind::EnterKey,
        };
        let e = r.element;
        let element = RawElement {
            element_id: e.element_id,
            document_id: r.document_id,
            tag: e.tag,
            input_type: e.input_type,
            id: e.id,
            name: e.name,
            autocomplete: e.autocomplete,
            placeholder: e.placeholder,
            aria_label: e.aria_label,
            is_password_now: e.is_password_now,
            form: e.form.map(|f| RawForm {
                index: f.index,
                action: f.action,
                method: f.method,
            }),
            selectors: e.selectors,
            in_shadow_root: e.in_shadow_root,
        };
        let value = match kind {
            PageEventKind::Input | PageEventKind::Change => r.value,
            _ => None,
        };
        self.capture.push(CaptureEvent::Page {
            t_ms: self.t_ms(),
            kind,
            frame: RawFrame {
                main: r.is_top,
                url: r.frame_url,
            },
            element,
            value,
        });
    }

    fn push_response(&mut self, id: &str, n: usize) {
        let Some(hop) = self.hops.get(id).and_then(|h| h.get(n)) else {
            return;
        };
        let Some(status) = hop.status else { return };
        self.capture.push(CaptureEvent::Response {
            request_id: format!("{id}#{n}"),
            status,
            content_type: hop.content_type.clone(),
            set_cookie: hop.set_cookie,
        });
    }

    async fn request(&mut self, session: &str, p: RequestWillBeSent) {
        let id = p.request_id.clone();
        if let Some(prev) = p.redirect_response {
            let hops = self.hops.entry(id.clone()).or_default();
            if hops.is_empty() {
                hops.push(Hop::default());
            }
            let last = hops.len() - 1;
            let hop = &mut hops[last];
            hop.status = Some(prev.status);
            if hop.content_type.is_none() {
                hop.content_type = prev.headers.content_type().map(str::to_owned);
            }
            hop.set_cookie |= prev.headers.has_set_cookie();
            hops.push(Hop::default());
            self.push_response(&id, last);
        } else {
            self.hops.insert(id.clone(), vec![Hop::default()]);
        }
        let n = self.hops.get(&id).map_or(0, |h| h.len() - 1);
        if self.clock.is_none() {
            return;
        }

        let resource = match p.resource.as_deref() {
            Some("Document") => ResourceKind::Document,
            Some("XHR") => ResourceKind::Xhr,
            Some("Fetch") => ResourceKind::Fetch,
            _ => ResourceKind::Other,
        };
        let main_frame_navigation = resource == ResourceKind::Document
            && p.frame_id.is_some()
            && p.frame_id == self.first_main_frame
            && p.request_id == p.loader_id;
        let body = match (&p.request.post_data, p.request.has_post_data) {
            (Some(d), _) => RawBody::Bytes(Zeroizing::new(d.as_bytes().to_vec())),
            (None, Some(true)) => {
                match self
                    .cdp
                    .call::<_, PostData>(
                        "Network.getRequestPostData",
                        &GetRequestPostData { request_id: &id },
                        Some(session),
                    )
                    .await
                {
                    Ok(d) => RawBody::Bytes(Zeroizing::new(d.post_data.as_bytes().to_vec())),
                    Err(_) => RawBody::Unavailable,
                }
            }
            _ => RawBody::None,
        };
        self.capture.push(CaptureEvent::Request {
            request_id: format!("{id}#{n}"),
            t_ms: self.t_ms(),
            method: p.request.method.clone(),
            url: p.request.url.clone(),
            resource,
            main_frame_navigation,
            content_type: p.request.headers.content_type().map(str::to_owned),
            authorization: p
                .request
                .headers
                .authorization()
                .map(|a| Zeroizing::new(a.as_bytes().to_vec())),
            body,
            frame_url: p.document_url.clone(),
        });
    }

    fn finish(self, confirmed: bool) -> Outcome {
        let Some((_, started)) = self.clock else {
            return Outcome::NeverStarted;
        };
        let info = EndInfo {
            ended_by: if confirmed {
                EndedBy::Confirmed
            } else {
                EndedBy::WindowClosed
            },
            success_confirmed: confirmed,
            started_at: utc_rfc3339(started),
            ended_at: utc_rfc3339(SystemTime::now()),
        };
        Outcome::Recorded(Box::new(self.capture.finish(info)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_rfc3339_utc() {
        assert_eq!(utc_rfc3339(SystemTime::UNIX_EPOCH), "1970-01-01T00:00:00Z");
        let now = utc_rfc3339(SystemTime::now());
        assert!(now.ends_with('Z') && now.len() >= 20, "{now}");
    }

    #[test]
    fn the_listener_script_is_embedded_and_names_the_binding() {
        assert!(LISTENER_JS.contains(BINDING));
    }
}
