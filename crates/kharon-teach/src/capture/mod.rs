//! The capture state machine: events from a recorded login go in, and `finish` returns a
//! `Recording` that says how the login works and holds nothing the person typed.
//!
//! Pure: no browser, no I/O, no logging. Requests are buffered with their bodies in `Zeroizing`
//! buffers and analysed in `finish`, after the typed values are known.

mod build;
mod resolve;
mod types;

use kharon_recording::{
    BrowserInfo, Deciding, Flags, ListenerWorld, Recording, Role, Step, StoredRequest,
    StrippedCounts, Viewport, classify, is_otp_descriptor,
};
pub use types::{CaptureEvent, EndInfo, PageEventKind, RawBody, RawElement, RawForm, RawFrame};
use url::Url;
use zeroize::Zeroizing;

use crate::body::MAX_BODY_BYTES;
use crate::site::{is_captcha_host, registrable_domain};
use build::{Ctx, Tally, describe, form_ref, frame_ref, raw_hits, reduce_request, stripped_url};
use resolve::{Elem, resolve};

/// Once this many body bytes are buffered, every further body is buffered as `Unavailable`.
pub const MAX_BUFFERED_BODY_BYTES: usize = 32 << 20;
/// Steps kept. Later ones are counted in `StrippedCounts::steps_dropped` and not recorded. Typed
/// values are still tracked: only the step list stops growing.
pub const MAX_STEPS: usize = 10_000;
/// Requests buffered. Later ones are counted in `requests_seen` and not buffered.
pub const MAX_BUFFERED_REQUESTS: usize = 5_000;

/// A frame as it was when an event arrived.
struct FrameInfo {
    main: bool,
    url: String,
    cross_origin: bool,
}

enum What {
    Navigation(String),
    Input(usize),
    Click(RawElement),
    Submit(RawForm),
    EnterKey(RawElement),
}

struct Pending {
    t_ms: u64,
    frame: FrameInfo,
    what: What,
}

struct BufferedResponse {
    status: u16,
    content_type: Option<String>,
    set_cookie: bool,
}

/// A request waiting for `finish`, with its bytes in zeroizing buffers.
struct Buffered {
    request_id: String,
    t_ms: u64,
    method: String,
    url: String,
    resource: kharon_recording::ResourceKind,
    main_frame_navigation: bool,
    content_type: Option<String>,
    authorization: Option<Zeroizing<Vec<u8>>>,
    body: RawBody,
    /// A non-GET request to the login site made after the first `Input`.
    login_site_write: bool,
    response: Option<BufferedResponse>,
}

pub struct Capture {
    start_url: String,
    tool_version: String,
    login_site: String,
    started: bool,
    browser: Option<BrowserInfo>,
    listener_world: ListenerWorld,
    main_origin: Option<String>,
    final_url: Option<String>,
    steps: Vec<Pending>,
    steps_dropped: u64,
    max_steps: usize,
    max_requests: usize,
    /// The first sequence number of the first element known to be a password.
    first_password_seq: Option<u64>,
    elems: Vec<Elem>,
    reqs: Vec<Buffered>,
    seq: u64,
    inputs_seen: bool,
    requests_seen: u64,
    popup: bool,
    captcha: bool,
    /// When the first main-frame navigation to another registrable domain happened.
    first_cross_site_ms: Option<u64>,
    framed_login: bool,
    body_unavailable: bool,
    body_budget: usize,
    buffered_body_bytes: usize,
}

fn host_of(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
}

fn raw_origin(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .map(|u| u.origin().ascii_serialization())
}

/// A CAPTCHA host, or `www.google.com/recaptcha/…`.
fn is_captcha_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    is_captcha_host(host)
        || (matches!(host, "www.google.com" | "google.com")
            && parsed.path().starts_with("/recaptcha/"))
}

fn same_element(e: &Elem, raw: &RawElement) -> bool {
    e.raw.document_id == raw.document_id && e.raw.element_id == raw.element_id
}

impl Capture {
    pub fn new(start_url: &str, tool_version: &str) -> Self {
        let login_site = host_of(start_url).map(|h| registrable_domain(&h));
        Self {
            start_url: start_url.to_owned(),
            tool_version: tool_version.to_owned(),
            login_site: login_site.unwrap_or_default(),
            started: false,
            browser: None,
            listener_world: ListenerWorld::Isolated,
            main_origin: raw_origin(start_url),
            final_url: None,
            steps: Vec::new(),
            steps_dropped: 0,
            max_steps: MAX_STEPS,
            max_requests: MAX_BUFFERED_REQUESTS,
            first_password_seq: None,
            elems: Vec::new(),
            reqs: Vec::new(),
            seq: 0,
            inputs_seen: false,
            requests_seen: 0,
            popup: false,
            captcha: false,
            first_cross_site_ms: None,
            framed_login: false,
            body_unavailable: false,
            body_budget: MAX_BUFFERED_BODY_BYTES,
            buffered_body_bytes: 0,
        }
    }

    pub fn started(&self) -> bool {
        self.started
    }

    /// Takes one event. Everything but `Popup` is ignored until `Started` arrives.
    pub fn push(&mut self, ev: CaptureEvent) {
        match ev {
            CaptureEvent::Popup => self.popup = true,
            CaptureEvent::Started {
                browser,
                listener_world,
            } => {
                if !self.started {
                    self.started = true;
                    self.browser = Some(browser);
                    self.listener_world = listener_world;
                }
            }
            _ if !self.started => {}
            CaptureEvent::Navigation { t_ms, frame } => self.navigation(t_ms, &frame),
            CaptureEvent::Page {
                t_ms,
                kind,
                frame,
                element,
                value,
            } => self.page(t_ms, kind, &frame, element, value),
            CaptureEvent::Request {
                request_id,
                t_ms,
                method,
                url,
                resource,
                main_frame_navigation,
                content_type,
                authorization,
                body,
                frame_url: _,
            } => self.request(Buffered {
                request_id,
                t_ms,
                method,
                url,
                resource,
                main_frame_navigation,
                content_type,
                authorization,
                body,
                login_site_write: false,
                response: None,
            }),
            CaptureEvent::Response {
                request_id,
                status,
                content_type,
                set_cookie,
            } => {
                if let Some(r) = self
                    .reqs
                    .iter_mut()
                    .rev()
                    .find(|r| r.request_id == request_id)
                {
                    r.response = Some(BufferedResponse {
                        status,
                        content_type,
                        set_cookie,
                    });
                }
            }
        }
    }

    fn frame_info(&self, frame: &RawFrame) -> FrameInfo {
        let cross_origin = !frame.main && raw_origin(&frame.url) != self.main_origin;
        FrameInfo {
            main: frame.main,
            url: frame.url.clone(),
            cross_origin,
        }
    }

    fn navigation(&mut self, t_ms: u64, frame: &RawFrame) {
        if is_captcha_url(&frame.url) {
            self.captcha = true;
        }
        if frame.main {
            self.main_origin = raw_origin(&frame.url);
            self.final_url = Some(frame.url.clone());
            // Only web pages count: an error page (`chrome-error://`) is not another site.
            let other_site = Url::parse(&frame.url).is_ok_and(|u| {
                matches!(u.scheme(), "http" | "https")
                    && u.host_str()
                        .is_some_and(|h| registrable_domain(h) != self.login_site)
            });
            if other_site {
                self.first_cross_site_ms.get_or_insert(t_ms);
            }
        }
        let info = self.frame_info(frame);
        self.add_step(Pending {
            t_ms,
            frame: info,
            what: What::Navigation(frame.url.clone()),
        });
    }

    /// Keeps the step, or counts it when the step list is full.
    fn add_step(&mut self, step: Pending) {
        if self.steps.len() < self.max_steps {
            self.steps.push(step);
        } else {
            self.steps_dropped += 1;
        }
    }

    fn page(
        &mut self,
        t_ms: u64,
        kind: PageEventKind,
        frame: &RawFrame,
        element: RawElement,
        value: Option<Zeroizing<String>>,
    ) {
        let info = self.frame_info(frame);
        let known = self.elems.iter().position(|e| same_element(e, &element));
        if let Some(i) = known {
            self.note_report(i, &element, &info);
        }
        let what = match kind {
            PageEventKind::Input | PageEventKind::Change => {
                let i = match known {
                    Some(i) => i,
                    None => {
                        self.elems.push(Elem {
                            raw: element.clone(),
                            value: Zeroizing::new(String::new()),
                            was_password: false,
                            shadow: false,
                            has_step: false,
                            first_seq: self.seq + 1,
                            last_seq: 0,
                            last_before_password: None,
                        });
                        let i = self.elems.len() - 1;
                        self.note_report(i, &element, &info);
                        i
                    }
                };
                self.seq += 1;
                self.elems[i].last_seq = self.seq;
                if self.first_password_seq.is_none_or(|s| self.seq < s) {
                    self.elems[i].last_before_password = Some(self.seq);
                }
                if let Some(v) = value {
                    self.elems[i].value = v;
                }
                if kind == PageEventKind::Change || self.elems[i].has_step {
                    if kind == PageEventKind::Input {
                        self.inputs_seen = true;
                    }
                    return;
                }
                self.elems[i].has_step = true;
                self.inputs_seen = true;
                What::Input(i)
            }
            PageEventKind::Click => What::Click(element),
            PageEventKind::EnterKey => What::EnterKey(element),
            PageEventKind::Submit => match element.form {
                Some(form) => What::Submit(form),
                None => return,
            },
        };
        self.add_step(Pending {
            t_ms,
            frame: info,
            what,
        });
    }

    fn note_report(&mut self, i: usize, element: &RawElement, info: &FrameInfo) {
        let e = &mut self.elems[i];
        e.was_password |= element.is_password_now;
        if e.was_password {
            let first = e.first_seq;
            self.first_password_seq = Some(self.first_password_seq.map_or(first, |s| s.min(first)));
        }
        let e = &mut self.elems[i];
        e.shadow |= element.in_shadow_root;
        if e.was_password && !info.main && info.cross_origin {
            self.framed_login = true;
        }
    }

    fn request(&mut self, mut b: Buffered) {
        self.requests_seen += 1;
        if is_captcha_url(&b.url) {
            self.captcha = true;
        }
        if self.reqs.len() >= self.max_requests {
            return;
        }
        if let RawBody::Bytes(bytes) = &b.body {
            if bytes.len() > MAX_BODY_BYTES
                || self.buffered_body_bytes.saturating_add(bytes.len()) > self.body_budget
            {
                b.body = RawBody::Unavailable;
            } else {
                self.buffered_body_bytes += bytes.len();
            }
        }
        let to_login_site =
            host_of(&b.url).is_some_and(|h| registrable_domain(&h) == self.login_site);
        let write = !b.method.eq_ignore_ascii_case("GET") && to_login_site;
        if write && matches!(b.body, RawBody::Unavailable) {
            self.body_unavailable = true;
        }
        b.login_site_write = write && self.inputs_seen;
        self.reqs.push(b);
    }

    /// Resolves the typed values, searches the buffered requests, strips, sets the flags and
    /// classifies. Consumes the capture, so every buffered value is dropped (and zeroed) here.
    pub fn finish(self, end: EndInfo) -> Recording {
        let resolved = resolve(&self.elems, &self.reqs);
        let ctx = Ctx {
            markers: &resolved.markers,
            pair: resolved.pair(),
        };
        let mut tally = Tally::default();

        let start_url = stripped_url(&self.start_url, ctx, &mut tally);
        let final_url = self
            .final_url
            .as_deref()
            .map(|u| stripped_url(u, ctx, &mut tally));
        let steps = self.build_steps(&resolved, ctx, &mut tally);

        // Which requests are kept is decided on the raw bytes, before any body is shaped. A weak
        // (short-value) hit counts only when no confident hit of its role exists anywhere.
        let hits: Vec<Vec<kharon_recording::MarkerHit>> =
            self.reqs.iter().map(|b| raw_hits(b, ctx)).collect();
        let deciding = Deciding::from_hits(hits.iter().flatten());
        let mut requests: Vec<StoredRequest> = Vec::new();
        let mut bodies_reduced = 0;
        for (b, hs) in self.reqs.iter().zip(&hits) {
            let telling = hs.iter().any(|h| deciding.counts(h));
            if !(b.main_frame_navigation || telling || b.login_site_write) {
                continue;
            }
            let Some((stored, t, reduced)) = reduce_request(b, ctx) else {
                continue;
            };
            tally.add(t);
            bodies_reduced += u64::from(reduced);
            requests.push(stored);
        }

        // The login is over once the password has been sent: the last request carrying it, or
        // when none does, the last typing. A move to another site after that is not part of it.
        let credentials_sent = self
            .reqs
            .iter()
            .zip(&hits)
            .filter(|(_, hs)| {
                hs.iter()
                    .any(|h| h.role == Role::Password && deciding.counts(h))
            })
            .map(|(b, _)| b.t_ms)
            .max()
            .or_else(|| {
                steps
                    .iter()
                    .filter_map(|s| match s {
                        Step::Input { t_ms, .. } => Some(*t_ms),
                        _ => None,
                    })
                    .max()
            });
        let cross_site = self
            .first_cross_site_ms
            .is_some_and(|t| credentials_sent.is_none_or(|c| t < c));
        let went_on_after_login = self.first_cross_site_ms.is_some() && !cross_site;

        let flags =
            Flags {
                captcha: self.captcha,
                otp_step: self.otp_step(),
                cross_site,
                popup: self.popup,
                framed_login: self.framed_login,
                shadow_dom: self.elems.iter().enumerate().any(|(i, e)| {
                    e.shadow && (e.was_password || Some(i) == resolved.username_elem)
                }),
                multiple_passwords: resolved.multiple_passwords,
                body_unavailable: self.body_unavailable,
            };
        let mut classification = classify(&steps, &requests, &flags);
        if went_on_after_login {
            classification
                .notes
                .push("After the login the browser went on to another site.".to_owned());
        }
        Recording {
            format_version: kharon_recording::FORMAT_VERSION,
            tool_version: self.tool_version.clone(),
            browser: self.browser.clone().unwrap_or(BrowserInfo {
                product: String::new(),
                user_agent: String::new(),
                viewport: Viewport {
                    width: 0,
                    height: 0,
                },
            }),
            listener_world: self.listener_world,
            started_at: end.started_at,
            ended_at: end.ended_at,
            ended_by: end.ended_by,
            success_confirmed: end.success_confirmed,
            start_url,
            final_url,
            steps,
            flags,
            classification,
            stripped: StrippedCounts {
                requests_seen: self.requests_seen,
                requests_stored: requests.len() as u64,
                request_bodies_reduced: bodies_reduced,
                query_values_removed: tally.query_values_removed,
                path_segments_replaced: tally.path_segments_replaced,
                typed_values_removed: resolved.markers.len() as u64,
                steps_dropped: self.steps_dropped,
            },
            requests,
        }
    }

    /// An `Input` step after the first password input whose element looks like a one-time code
    /// field. Judged on the element as the page described it, before any attribute is dropped.
    fn otp_step(&self) -> bool {
        let none = Ctx {
            markers: &[],
            pair: None,
        };
        let mut seen_password = false;
        for p in &self.steps {
            let What::Input(i) = p.what else { continue };
            let e = &self.elems[i];
            if seen_password
                && is_otp_descriptor(&describe(
                    &e.raw,
                    e.was_password,
                    none,
                    &mut Tally::default(),
                ))
            {
                return true;
            }
            seen_password |= e.was_password;
        }
        false
    }

    fn build_steps(
        &self,
        resolved: &resolve::Resolved,
        ctx: Ctx<'_>,
        tally: &mut Tally,
    ) -> Vec<Step> {
        self.steps
            .iter()
            .map(|p| {
                let frame = frame_ref(&p.frame, ctx);
                let t_ms = p.t_ms;
                match &p.what {
                    What::Navigation(url) => Step::Navigation {
                        t_ms,
                        frame,
                        url: stripped_url(url, ctx, tally),
                    },
                    What::Input(i) => {
                        let e = &self.elems[*i];
                        let role = if e.was_password {
                            Role::Password
                        } else if Some(*i) == resolved.username_elem {
                            Role::Username
                        } else {
                            Role::None
                        };
                        Step::Input {
                            t_ms,
                            frame,
                            element: describe(&e.raw, e.was_password, ctx, tally),
                            value_len: u32::try_from(e.value.chars().count()).unwrap_or(u32::MAX),
                            role,
                        }
                    }
                    What::Click(raw) => Step::Click {
                        t_ms,
                        frame,
                        element: self.describe_known(raw, ctx, tally),
                    },
                    What::EnterKey(raw) => Step::EnterKey {
                        t_ms,
                        frame,
                        element: self.describe_known(raw, ctx, tally),
                    },
                    What::Submit(form) => Step::Submit {
                        t_ms,
                        frame,
                        form: form_ref(form, ctx, tally),
                    },
                }
            })
            .collect()
    }

    fn describe_known(
        &self,
        raw: &RawElement,
        ctx: Ctx<'_>,
        tally: &mut Tally,
    ) -> kharon_recording::ElementDescriptor {
        let was_password = raw.is_password_now
            || self
                .elems
                .iter()
                .any(|e| same_element(e, raw) && e.was_password);
        describe(raw, was_password, ctx, tally)
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use kharon_recording::{
        BodyShape, BrowserInfo, EndedBy, ListenerWorld, MarkerHit, PasswordLeg, Recording,
        ResourceKind, Role, Shape, Step, StoredRequest, Viewport,
    };
    use zeroize::Zeroizing;

    use super::*;
    use crate::body::MAX_BODY_BYTES;
    use crate::testing::assert_holds_no_typed_value;

    const LOGIN: &str = "https://ex.test/login";
    const USER: &str = "kh.throwaway7";
    const PASS: &str = "Tr0ub4dor-9x";
    const PASS2: &str = "Qx7!other-pass";
    const OTP: &str = "482913";
    const TENANT: &str = "acme-corp-77";
    /// Every value typed in any scenario below.
    const ALL_VALUES: [&str; 5] = [USER, PASS, PASS2, OTP, TENANT];
    const FORM: &str = "application/x-www-form-urlencoded";

    fn el(id: u32, name: &str, ty: &str) -> RawElement {
        RawElement {
            element_id: id,
            document_id: "doc1".into(),
            tag: "INPUT".into(),
            input_type: Some(ty.to_uppercase()),
            id: Some(name.into()),
            name: Some(name.into()),
            autocomplete: None,
            placeholder: None,
            aria_label: None,
            is_password_now: ty == "password",
            form: Some(RawForm {
                index: 0,
                action: Some("https://ex.test/login".into()),
                method: "post".into(),
            }),
            selectors: vec![format!("#{name}")],
            in_shadow_root: false,
        }
    }

    fn user_el() -> RawElement {
        el(1, "username", "text")
    }

    fn pw_el() -> RawElement {
        el(2, "password", "password")
    }

    fn no_form(mut e: RawElement) -> RawElement {
        e.form = None;
        e
    }

    fn button() -> RawElement {
        let mut b = el(9, "go", "submit");
        b.tag = "button".into();
        b
    }

    struct Session {
        cap: Capture,
        t: u64,
        rid: u32,
        url: String,
    }

    impl Session {
        fn unstarted(url: &str) -> Self {
            Session {
                cap: Capture::new(url, "0.0.0"),
                t: 0,
                rid: 0,
                url: url.into(),
            }
        }

        fn new(url: &str) -> Self {
            let mut s = Self::unstarted(url);
            s.start();
            s
        }

        fn start(&mut self) {
            self.cap.push(CaptureEvent::Started {
                browser: BrowserInfo {
                    product: "Chrome/1".into(),
                    user_agent: "UA".into(),
                    viewport: Viewport {
                        width: 1280,
                        height: 800,
                    },
                },
                listener_world: ListenerWorld::Isolated,
            });
            let url = self.url.clone();
            self.nav_to(&url);
        }

        fn tick(&mut self) -> u64 {
            self.t += 10;
            self.t
        }

        fn frame(&self) -> RawFrame {
            RawFrame {
                main: true,
                url: self.url.clone(),
            }
        }

        fn nav_to(&mut self, url: &str) {
            self.url = url.into();
            let (t_ms, frame) = (self.tick(), self.frame());
            self.cap.push(CaptureEvent::Navigation { t_ms, frame });
        }

        fn nav(mut self, url: &str) -> Self {
            self.nav_to(url);
            self
        }

        fn child_nav(mut self, url: &str) -> Self {
            let t_ms = self.tick();
            self.cap.push(CaptureEvent::Navigation {
                t_ms,
                frame: RawFrame {
                    main: false,
                    url: url.into(),
                },
            });
            self
        }

        fn page(&mut self, kind: PageEventKind, e: &RawElement, value: Option<&str>) {
            let (t_ms, frame) = (self.tick(), self.frame());
            self.cap.push(CaptureEvent::Page {
                t_ms,
                kind,
                frame,
                element: e.clone(),
                value: value.map(|v| Zeroizing::new(v.to_owned())),
            });
        }

        fn type_into(mut self, e: &RawElement, text: &str) -> Self {
            self.page(PageEventKind::Input, e, Some(text));
            self
        }

        /// One Input event per character, each carrying the value so far.
        fn typing(mut self, e: &RawElement, text: &str) -> Self {
            let ends: Vec<usize> = text.char_indices().map(|(i, c)| i + c.len_utf8()).collect();
            for end in ends {
                self.page(PageEventKind::Input, e, Some(&text[..end]));
            }
            self
        }

        fn change(mut self, e: &RawElement, text: &str) -> Self {
            self.page(PageEventKind::Change, e, Some(text));
            self
        }

        fn click(mut self, e: &RawElement) -> Self {
            self.page(PageEventKind::Click, e, None);
            self
        }

        fn submit(mut self, e: &RawElement) -> Self {
            self.page(PageEventKind::Submit, e, None);
            self
        }

        fn enter(mut self, e: &RawElement) -> Self {
            self.page(PageEventKind::EnterKey, e, None);
            self
        }

        fn popup(mut self) -> Self {
            self.cap.push(CaptureEvent::Popup);
            self
        }

        fn request(
            mut self,
            method: &str,
            url: &str,
            resource: ResourceKind,
            main: bool,
            content_type: Option<&str>,
            body: RawBody,
        ) -> Self {
            self.rid += 1;
            let (t_ms, request_id) = (self.tick(), format!("r{}", self.rid));
            self.cap.push(CaptureEvent::Request {
                request_id: request_id.clone(),
                t_ms,
                method: method.into(),
                url: url.into(),
                resource,
                main_frame_navigation: main,
                content_type: content_type.map(str::to_owned),
                authorization: None,
                body,
                frame_url: self.url.clone(),
            });
            self.cap.push(CaptureEvent::Response {
                request_id,
                status: 200,
                content_type: Some("text/html; charset=utf-8".into()),
                set_cookie: false,
            });
            self
        }

        fn post_form(self, url: &str, body: &str) -> Self {
            self.request(
                "POST",
                url,
                ResourceKind::Document,
                true,
                Some(FORM),
                RawBody::Bytes(Zeroizing::new(body.as_bytes().to_vec())),
            )
        }

        fn post_json(self, url: &str, body: &str) -> Self {
            self.request(
                "POST",
                url,
                ResourceKind::Fetch,
                false,
                Some("application/json"),
                RawBody::Bytes(Zeroizing::new(body.as_bytes().to_vec())),
            )
        }

        fn get(self, url: &str, resource: ResourceKind) -> Self {
            self.request("GET", url, resource, false, None, RawBody::None)
        }

        fn finish(self) -> Recording {
            self.cap.finish(EndInfo {
                ended_by: EndedBy::Confirmed,
                success_confirmed: true,
                started_at: "2026-11-18T00:00:00Z".into(),
                ended_at: "2026-11-18T00:01:00Z".into(),
            })
        }
    }

    fn inputs(rec: &Recording) -> Vec<(&kharon_recording::ElementDescriptor, u32, Role)> {
        rec.steps
            .iter()
            .filter_map(|s| match s {
                Step::Input {
                    element,
                    value_len,
                    role,
                    ..
                } => Some((element, *value_len, *role)),
                _ => None,
            })
            .collect()
    }

    fn role_of(rec: &Recording, element_id: u32) -> Option<Role> {
        inputs(rec)
            .into_iter()
            .find(|(e, _, _)| e.element_id == element_id)
            .map(|(_, _, r)| r)
    }

    // ---- scenarios, each a complete recording; the leak test walks the whole list ----

    fn sc_form_post() -> Recording {
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .click(&button())
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}&csrf=abc"),
            )
            .get("https://ex.test/logo.png", ResourceKind::Other)
            .nav("https://ex.test/home")
            .finish()
    }

    fn sc_keystrokes() -> Recording {
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .typing(&pw_el(), PASS)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .finish()
    }

    fn sc_show_toggle() -> Recording {
        let mut shown = pw_el();
        shown.is_password_now = false;
        shown.input_type = Some("text".into());
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), "Tr0ub4")
            .type_into(&shown, PASS)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .finish()
    }

    fn sc_confirm_field() -> Recording {
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .type_into(&el(3, "confirm", "password"), PASS)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}&confirm={PASS}"),
            )
            .finish()
    }

    fn sc_two_passwords() -> Recording {
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .type_into(&el(3, "confirm", "password"), PASS2)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}&confirm={PASS2}"),
            )
            .finish()
    }

    fn sc_two_step() -> Recording {
        let mut pw = pw_el();
        pw.document_id = "doc2".into();
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .post_form("https://ex.test/identify", &format!("username={USER}"))
            .nav("https://ex.test/password")
            .type_into(&pw, PASS)
            .post_form("https://ex.test/login", &format!("password={PASS}"))
            .finish()
    }

    fn sc_username_fallback() -> Recording {
        let tenant = no_form(el(4, "tenant", "text"));
        Session::new(LOGIN)
            .type_into(&tenant, TENANT)
            .type_into(&no_form(user_el()), USER)
            .type_into(&no_form(pw_el()), PASS)
            .enter(&no_form(pw_el()))
            .post_json(
                "https://ex.test/api/login",
                &format!(r#"{{"tenant":"{TENANT}","user":"{USER}","pass":"{PASS}"}}"#),
            )
            .finish()
    }

    fn sc_cross_site() -> Recording {
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .nav("https://idp.other.test/auth")
            .type_into(&pw_el(), PASS)
            .post_form("https://idp.other.test/auth", &format!("u={USER}&p={PASS}"))
            .finish()
    }

    fn sc_subdomain() -> Recording {
        Session::new(LOGIN)
            .nav("https://login.ex.test/sso")
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .post_form("https://login.ex.test/sso", &format!("u={USER}&p={PASS}"))
            .finish()
    }

    fn sc_captcha() -> Recording {
        Session::new(LOGIN)
            .child_nav("https://newassets.hcaptcha.com/captcha/v1/frame.html")
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .finish()
    }

    fn sc_recaptcha_request() -> Recording {
        Session::new(LOGIN)
            .get(
                "https://www.google.com/recaptcha/api2/anchor?k=site",
                ResourceKind::Other,
            )
            .finish()
    }

    fn sc_google_search() -> Recording {
        Session::new(LOGIN)
            .get("https://www.google.com/search?q=x", ResourceKind::Other)
            .child_nav("https://www.google.com/maps")
            .finish()
    }

    fn sc_otp_after() -> Recording {
        let mut otp = el(5, "code", "text");
        otp.autocomplete = Some("one-time-code".into());
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .nav("https://ex.test/verify")
            .type_into(&otp, OTP)
            .post_form("https://ex.test/verify", &format!("code={OTP}"))
            .finish()
    }

    fn sc_otp_before() -> Recording {
        let mut otp = el(5, "code", "text");
        otp.autocomplete = Some("one-time-code".into());
        Session::new(LOGIN)
            .type_into(&otp, OTP)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}&code={OTP}"),
            )
            .finish()
    }

    fn sc_oversized() -> Recording {
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .request(
                "POST",
                "https://ex.test/login",
                ResourceKind::Fetch,
                false,
                Some("application/octet-stream"),
                RawBody::Bytes(Zeroizing::new(vec![b'a'; MAX_BODY_BYTES + 1])),
            )
            .finish()
    }

    fn sc_combined_base64() -> Recording {
        let combined = Base64::encode_string(format!("{USER}:{PASS}").as_bytes());
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .post_json(
                "https://ex.test/api/login",
                &format!(r#"{{"auth":"{combined}","remember":true}}"#),
            )
            .finish()
    }

    fn sc_which_requests() -> Recording {
        Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .get("https://ex.test/logo.png", ResourceKind::Other)
            .post_json("https://ads.other.test/collect", r#"{"event":"view"}"#)
            .post_json("https://ex.test/api/beacon", r#"{"event":"typed"}"#)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .finish()
    }

    fn sc_values_everywhere() -> Recording {
        let tenant = no_form(el(4, "tenant", "text"));
        let basic = Base64::encode_string(format!("{USER}:{PASS}").as_bytes());
        let mut s = Session::new(&format!("https://ex.test/login?tenant={TENANT}"))
            .type_into(&tenant, TENANT)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .get(
                &format!("https://{TENANT}.ex.test/u/{USER}/profile?name={USER}&{PASS}=1"),
                ResourceKind::Xhr,
            );
        s.rid += 1;
        s.cap.push(CaptureEvent::Request {
            request_id: "auth".into(),
            t_ms: 500,
            method: "POST".into(),
            url: format!("https://ex.test/api/session/{PASS}"),
            resource: ResourceKind::Fetch,
            main_frame_navigation: false,
            content_type: Some(format!("multipart/form-data; boundary={TENANT}")),
            authorization: Some(Zeroizing::new(format!("Basic {basic}").into_bytes())),
            body: RawBody::Bytes(Zeroizing::new(
                format!("--{TENANT}\r\nContent-Disposition: form-data; name=\"{USER}\"\r\n\r\n{PASS}\r\n--{TENANT}--\r\n")
                    .into_bytes(),
            )),
            frame_url: LOGIN.into(),
        });
        s.nav(&format!("https://ex.test/home?welcome={USER}"))
            .finish()
    }

    type Build = fn() -> Recording;

    const SCENARIOS: &[(&str, Build)] = &[
        ("form_post", sc_form_post),
        ("keystrokes", sc_keystrokes),
        ("show_toggle", sc_show_toggle),
        ("confirm_field", sc_confirm_field),
        ("two_passwords", sc_two_passwords),
        ("two_step", sc_two_step),
        ("username_fallback", sc_username_fallback),
        ("cross_site", sc_cross_site),
        ("subdomain", sc_subdomain),
        ("captcha", sc_captcha),
        ("recaptcha_request", sc_recaptcha_request),
        ("google_search", sc_google_search),
        ("otp_after", sc_otp_after),
        ("otp_before", sc_otp_before),
        ("oversized", sc_oversized),
        ("combined_base64", sc_combined_base64),
        ("which_requests", sc_which_requests),
        ("values_everywhere", sc_values_everywhere),
    ];

    fn scenario(name: &str) -> Recording {
        SCENARIOS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, build)| build())
            .unwrap_or_else(|| panic!("no scenario named {name}"))
    }

    #[test]
    fn the_serialized_recording_holds_no_typed_value() {
        for (name, build) in SCENARIOS {
            let rec = build();
            let json = rec.to_json();
            std::panic::catch_unwind(|| assert_holds_no_typed_value(&json, &ALL_VALUES))
                .unwrap_or_else(|_| panic!("scenario {name} leaked a typed value"));
        }
    }

    #[test]
    fn form_post_end_to_end() {
        let rec = scenario("form_post");
        assert_eq!(rec.classification.shape, Shape::FormPost);
        let ins = inputs(&rec);
        assert_eq!(ins.len(), 2);
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert_eq!(role_of(&rec, 2), Some(Role::Password));
        assert_eq!(rec.stripped.typed_values_removed, 2);
        assert_eq!(
            rec.final_url.as_ref().map(|u| u.path.as_str()),
            Some("/home")
        );
        // Types are lowercased, the descriptor keeps the shape of the element.
        assert_eq!(ins[0].0.tag, "input");
        assert_eq!(ins[1].0.input_type.as_deref(), Some("password"));
        assert!(ins[1].0.was_password);
        assert_eq!(rec.browser.product, "Chrome/1");
    }

    #[test]
    fn keystrokes_collapse_to_one_input_step() {
        let rec = scenario("keystrokes");
        let pw: Vec<_> = inputs(&rec)
            .into_iter()
            .filter(|(e, _, _)| e.element_id == 2)
            .collect();
        assert_eq!(pw.len(), 1);
        assert_eq!(pw[0].1, 12);
    }

    #[test]
    fn show_password_toggle_keeps_the_password() {
        let rec = scenario("show_toggle");
        assert_eq!(role_of(&rec, 2), Some(Role::Password));
        assert_eq!(rec.classification.shape, Shape::FormPost);
        assert!(!rec.flags.multiple_passwords);
    }

    #[test]
    fn confirm_field_with_the_same_value_is_one_password() {
        let rec = scenario("confirm_field");
        assert!(!rec.flags.multiple_passwords);
        assert_eq!(role_of(&rec, 3), Some(Role::Password));
        assert_eq!(rec.classification.shape, Shape::FormPost);
    }

    #[test]
    fn two_different_passwords_set_the_flag_and_block() {
        let rec = scenario("two_passwords");
        assert!(rec.flags.multiple_passwords);
        assert_eq!(rec.classification.shape, Shape::Unrecognized);
    }

    #[test]
    fn two_step_by_navigation() {
        let rec = scenario("two_step");
        assert_eq!(
            rec.classification.shape,
            Shape::TwoStep {
                password_leg: PasswordLeg::FormPost
            }
        );
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert!(!rec.flags.cross_site);
    }

    #[test]
    fn username_falls_back_to_the_value_sent_with_the_password() {
        let rec = scenario("username_fallback");
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert_eq!(role_of(&rec, 4), Some(Role::None));
        assert_eq!(rec.classification.shape, Shape::ScriptPost);
        // The tenant's hit stays in the file, with no role.
        let sent_tenant = rec
            .requests
            .iter()
            .flat_map(StoredRequest::hits)
            .any(|h: &MarkerHit| h.role == Role::None);
        assert!(sent_tenant);
    }

    #[test]
    fn cross_site_navigation_sets_the_flag() {
        assert!(scenario("cross_site").flags.cross_site);
    }

    const WENT_ON: &str = "After the login the browser went on to another site.";

    #[test]
    fn a_move_to_another_site_after_the_login_is_a_note_and_no_flag() {
        let rec = Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .click(&button())
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .nav("https://app.other.test/home")
            .finish();
        assert!(!rec.flags.cross_site);
        assert_eq!(rec.classification.shape, Shape::FormPost);
        assert!(
            rec.classification.notes.iter().any(|n| n == WENT_ON),
            "{:?}",
            rec.classification.notes
        );
    }

    #[test]
    fn a_move_to_another_site_before_the_password_is_sent_is_cross_site() {
        let rec = scenario("cross_site");
        assert!(rec.flags.cross_site);
        assert_eq!(rec.classification.shape, Shape::Unrecognized);
        assert!(!rec.classification.notes.iter().any(|n| n == WENT_ON));
    }

    #[test]
    fn with_no_request_carrying_the_password_the_last_typing_is_the_mark() {
        // Typing, then a move to another site, then nothing sent that holds the password.
        let after = Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .nav("https://app.other.test/home")
            .finish();
        assert!(!after.flags.cross_site);
        let before = Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .nav("https://app.other.test/home")
            .type_into(&pw_el(), PASS)
            .finish();
        assert!(before.flags.cross_site);
    }

    #[test]
    fn a_browser_error_page_is_not_another_site() {
        let rec = Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .nav("chrome-error://chromewebdata/")
            .type_into(&pw_el(), PASS)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .finish();
        assert!(!rec.flags.cross_site);
        assert!(!rec.classification.notes.iter().any(|n| n == WENT_ON));
    }

    #[test]
    fn same_site_subdomain_is_not_cross_site() {
        assert!(!scenario("subdomain").flags.cross_site);
    }

    #[test]
    fn captcha_frame_sets_the_flag() {
        assert!(scenario("captcha").flags.captcha);
        assert!(scenario("recaptcha_request").flags.captcha);
        assert!(!scenario("google_search").flags.captcha);
        assert!(!scenario("form_post").flags.captcha);
    }

    #[test]
    fn otp_input_after_the_password_sets_the_flag() {
        assert!(scenario("otp_after").flags.otp_step);
        assert!(!scenario("otp_before").flags.otp_step);
        assert!(!scenario("form_post").flags.otp_step);
    }

    #[test]
    fn oversized_body_is_unavailable_and_flagged() {
        let rec = scenario("oversized");
        assert!(rec.flags.body_unavailable);
        assert_eq!(rec.requests.len(), 1);
        assert_eq!(rec.requests[0].body, BodyShape::Unavailable);
        assert_eq!(rec.classification.shape, Shape::Unrecognized);
    }

    #[test]
    fn a_combined_base64_credential_in_a_json_body_is_a_plain_hit() {
        let rec = scenario("combined_base64");
        assert_eq!(rec.classification.shape, Shape::ScriptPost);
    }

    #[test]
    fn a_json_login_under_a_urlencoded_header_is_a_script_post() {
        // jQuery: $.post(url, JSON.stringify({user, pass})) sends JSON text under the default
        // urlencoded content type. It must not read as a form whose one key is the JSON.
        let rec = Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .click(&button())
            .request(
                "POST",
                "https://ex.test/api/login",
                ResourceKind::Xhr,
                false,
                Some(FORM),
                RawBody::Bytes(Zeroizing::new(
                    format!(r#"{{"user":"{USER}","pass":"{PASS}"}}"#).into_bytes(),
                )),
            )
            .nav("https://ex.test/home")
            .finish();
        assert_eq!(rec.classification.shape, Shape::ScriptPost);
        assert_eq!(rec.requests.len(), 1);
        let login = &rec.requests[0];
        assert!(matches!(&login.body, BodyShape::Opaque { .. }));
        assert!(
            login
                .hits()
                .iter()
                .any(|h| h.role == Role::Password && !h.low_confidence)
        );
    }

    #[test]
    fn a_weak_hit_does_not_store_a_request_or_pick_the_leg_when_a_confident_one_exists() {
        // The password is five characters, so on its own it matches by chance. The combined
        // credential is long enough to be a confident hit for both roles.
        let (user, pass) = ("alice1", "abcde");
        let combined = Base64::encode_string(format!("{user}:{pass}").as_bytes());
        let rec = Session::new(LOGIN)
            .type_into(&user_el(), user)
            .type_into(&pw_el(), pass)
            .post_json("https://ads.other.test/collect", r#"{"note":"abcde"}"#)
            .post_json(
                "https://ex.test/api/login",
                &format!(r#"{{"auth":"{combined}"}}"#),
            )
            .nav("https://ex.test/home")
            .finish();
        let paths: Vec<&str> = rec.requests.iter().map(|r| r.url.path.as_str()).collect();
        assert_eq!(paths, ["/api/login"], "the chance match was stored");
        assert_eq!(rec.classification.shape, Shape::ScriptPost);
        assert!(rec.classification.network_swap_candidate);
        // With nothing confident anywhere, a weak hit still keeps its request.
        let rec = Session::new(LOGIN)
            .type_into(&user_el(), "bob")
            .type_into(&pw_el(), "abcde")
            .post_json("https://ads.other.test/collect", r#"{"note":"abcde"}"#)
            .finish();
        assert_eq!(rec.requests.len(), 1);
    }

    #[test]
    fn only_the_three_kinds_of_request_are_stored() {
        let rec = scenario("which_requests");
        // The image GET and the third-party POST are counted, not stored.
        assert_eq!(rec.stripped.requests_seen, 4);
        let urls: Vec<&str> = rec.requests.iter().map(|r| r.url.path.as_str()).collect();
        assert!(
            urls.contains(&"/login"),
            "the navigation, kept as a document: {urls:?}"
        );
        assert!(
            urls.contains(&"/api/beacon"),
            "a POST to the login site after the first input"
        );
        assert!(!urls.contains(&"/logo.png"));
        assert!(!urls.contains(&"/collect"));
        assert_eq!(rec.stripped.requests_stored, rec.requests.len() as u64);
        assert_eq!(rec.stripped.request_bodies_reduced, 2);
    }

    #[test]
    fn requests_with_a_hit_are_stored_even_when_third_party() {
        let rec = Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .post_json(
                "https://sso.other.test/token",
                &format!(r#"{{"p":"{PASS}"}}"#),
            )
            .finish();
        assert_eq!(rec.requests.len(), 1);
        assert_eq!(rec.requests[0].url.origin, "https://sso.other.test");
    }

    #[test]
    fn events_before_started_are_ignored_for_steps() {
        let mut s = Session::unstarted(LOGIN);
        s = s
            .type_into(&user_el(), USER)
            .click(&button())
            .post_form("https://ex.test/login", "a=b")
            .popup();
        assert!(!s.cap.started());
        s.start();
        assert!(s.cap.started());
        let rec = s
            .type_into(&pw_el(), PASS)
            .post_form("https://ex.test/login", &format!("password={PASS}"))
            .finish();
        assert_eq!(rec.stripped.requests_seen, 1);
        assert_eq!(inputs(&rec).len(), 1);
        assert!(!rec.steps.iter().any(|s| matches!(s, Step::Click { .. })));
        // A pop-up is remembered whenever it arrives, and the earlier typing never counted.
        assert!(rec.flags.popup);
        assert_eq!(rec.stripped.typed_values_removed, 1);
    }

    #[test]
    fn a_second_started_is_ignored_and_unknown_responses_too() {
        let mut s = Session::new(LOGIN);
        s.start();
        s.cap.push(CaptureEvent::Response {
            request_id: "nope".into(),
            status: 500,
            content_type: None,
            set_cookie: true,
        });
        let rec = s.finish();
        assert_eq!(rec.browser.product, "Chrome/1");
        assert!(rec.requests.is_empty());
    }

    #[test]
    fn finish_on_a_capture_that_never_started_still_returns_a_recording() {
        let rec = Session::unstarted(LOGIN).finish();
        assert!(rec.steps.is_empty() && rec.requests.is_empty());
        assert_eq!(rec.browser.product, "");
        assert_eq!(rec.browser.viewport.width, 0);
        assert_eq!(rec.listener_world, ListenerWorld::Isolated);
        assert_eq!(rec.stripped.requests_seen, 0);
    }

    #[test]
    fn change_adds_no_step_and_click_adds_one_every_time() {
        let rec = Session::new(LOGIN)
            .change(&user_el(), USER)
            .click(&button())
            .click(&button())
            .submit(&no_form(button()))
            .submit(&pw_el())
            .finish();
        assert!(inputs(&rec).is_empty());
        let clicks = rec
            .steps
            .iter()
            .filter(|s| matches!(s, Step::Click { .. }))
            .count();
        let submits = rec
            .steps
            .iter()
            .filter(|s| matches!(s, Step::Submit { .. }))
            .count();
        assert_eq!((clicks, submits), (2, 1));
        // The changed value still counts as typed.
        assert_eq!(rec.stripped.typed_values_removed, 1);
        assert_holds_no_typed_value(&rec.to_json(), &[USER]);
    }

    #[test]
    fn an_element_attribute_holding_a_typed_value_is_dropped() {
        let mut e = user_el();
        e.id = Some(format!("user-{USER}"));
        e.placeholder = Some(format!("e.g. {USER}"));
        e.selectors = vec![
            format!(r"#user-{}", USER.replace('.', r"\.")),
            "input[name=username]".into(),
        ];
        let rec = Session::new(LOGIN).type_into(&e, USER).finish();
        let (descriptor, _, _) = inputs(&rec)[0];
        assert_eq!(descriptor.id, None);
        assert_eq!(descriptor.placeholder, None);
        assert_eq!(descriptor.name.as_deref(), Some("username"));
        assert_eq!(
            descriptor.selectors,
            vec!["input[name=username]".to_owned()]
        );
        assert_holds_no_typed_value(&rec.to_json(), &[USER]);
    }

    #[test]
    fn child_frames_are_cross_origin_and_a_framed_login_is_flagged() {
        let mut s = Session::new(LOGIN);
        let frame = RawFrame {
            main: false,
            url: "https://pay.other.test/frame".into(),
        };
        let (t_ms, element) = (50, pw_el());
        s.cap.push(CaptureEvent::Page {
            t_ms,
            kind: PageEventKind::Input,
            frame,
            element,
            value: Some(Zeroizing::new(PASS.to_owned())),
        });
        let rec = s.finish();
        assert!(rec.flags.framed_login);
        match &rec.steps[1] {
            Step::Input { frame, .. } => {
                assert!(!frame.main && frame.cross_origin);
                assert_eq!(frame.origin, "https://pay.other.test");
            }
            other => panic!("expected an input step, got {other:?}"),
        }
    }

    #[test]
    fn shadow_dom_and_popup_flags() {
        let mut shadowed = pw_el();
        shadowed.in_shadow_root = true;
        let rec = Session::new(LOGIN)
            .type_into(&shadowed, PASS)
            .popup()
            .finish();
        assert!(rec.flags.shadow_dom && rec.flags.popup);
    }

    #[test]
    fn hostile_event_order_does_not_panic() {
        let mut cap = Capture::new("not a url", "0.0.0");
        let response = |id: &str| CaptureEvent::Response {
            request_id: id.into(),
            status: 200,
            content_type: None,
            set_cookie: false,
        };
        cap.push(response("ghost"));
        cap.push(CaptureEvent::Popup);
        cap.push(CaptureEvent::Started {
            browser: BrowserInfo {
                product: String::new(),
                user_agent: String::new(),
                viewport: Viewport {
                    width: 0,
                    height: 0,
                },
            },
            listener_world: ListenerWorld::Main,
        });
        cap.push(response("ghost"));
        cap.push(CaptureEvent::Navigation {
            t_ms: 0,
            frame: RawFrame {
                main: false,
                url: "::::".into(),
            },
        });
        let mut empty_doc = pw_el();
        empty_doc.document_id = String::new();
        empty_doc.form = Some(RawForm {
            index: u32::MAX,
            action: Some("%%%".into()),
            method: "\u{0}".into(),
        });
        for kind in [
            PageEventKind::Input,
            PageEventKind::Submit,
            PageEventKind::Click,
        ] {
            cap.push(CaptureEvent::Page {
                t_ms: u64::MAX,
                kind,
                frame: RawFrame {
                    main: false,
                    url: String::new(),
                },
                element: empty_doc.clone(),
                value: Some(Zeroizing::new(String::new())),
            });
        }
        for url in ["", "http://", "data:text/html,x", "http://[::1", "\u{0}"] {
            cap.push(CaptureEvent::Request {
                request_id: "r".into(),
                t_ms: 0,
                method: "".into(),
                url: url.into(),
                resource: ResourceKind::Other,
                main_frame_navigation: true,
                content_type: Some("multipart/form-data".into()),
                authorization: Some(Zeroizing::new(vec![0xff, 0x00])),
                body: RawBody::Bytes(Zeroizing::new(vec![0xff, 0xfe])),
                frame_url: "????".into(),
            });
        }
        cap.push(response("r"));
        let rec = cap.finish(EndInfo {
            ended_by: EndedBy::WindowClosed,
            success_confirmed: false,
            started_at: String::new(),
            ended_at: String::new(),
        });
        assert!(rec.flags.popup);
        assert_eq!(rec.stripped.requests_seen, 5);
        let _ = rec.to_json();
    }

    impl Capture {
        /// A capture with a small body budget, for the test of that budget.
        fn with_body_budget(start_url: &str, tool_version: &str, budget: usize) -> Self {
            Self {
                body_budget: budget,
                ..Self::new(start_url, tool_version)
            }
        }

        /// A capture with small step and request limits, for the tests of those limits.
        fn with_limits(start_url: &str, max_steps: usize, max_requests: usize) -> Self {
            Self {
                max_steps,
                max_requests,
                ..Self::new(start_url, "0.0.0")
            }
        }
    }

    fn session_with_limits(max_steps: usize, max_requests: usize) -> Session {
        let mut s = Session::unstarted(LOGIN);
        s.cap = Capture::with_limits(LOGIN, max_steps, max_requests);
        s.start();
        s
    }

    #[test]
    fn steps_past_the_limit_are_counted_but_their_values_still_count_as_typed() {
        // Step 1 is the first navigation, step 2 the user name; the password input and the
        // clicks after them do not fit.
        let rec = session_with_limits(2, MAX_BUFFERED_REQUESTS)
            .type_into(&user_el(), USER)
            .type_into(&pw_el(), PASS)
            .click(&button())
            .click(&button())
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .finish();
        assert_eq!(rec.steps.len(), 2);
        assert_eq!(rec.stripped.steps_dropped, 3);
        // The dropped password input is still a typed value: it is found and never written.
        assert_eq!(rec.stripped.typed_values_removed, 2);
        assert!(
            rec.requests
                .iter()
                .flat_map(StoredRequest::hits)
                .any(|h| h.role == Role::Password)
        );
        assert_holds_no_typed_value(&rec.to_json(), &[USER, PASS]);
        // Below the limit nothing is dropped.
        assert_eq!(scenario("form_post").stripped.steps_dropped, 0);
        assert_eq!(MAX_STEPS, 10_000);
    }

    #[test]
    fn requests_past_the_limit_are_counted_and_not_buffered() {
        let mut s = session_with_limits(MAX_STEPS, 3).type_into(&user_el(), USER);
        for i in 0..6 {
            s = s.post_form(&format!("https://ex.test/p{i}"), "a=1");
        }
        let rec = s.finish();
        assert_eq!(rec.stripped.requests_seen, 6);
        // Main-frame navigations are always stored, so what is stored is what was buffered.
        let paths: Vec<&str> = rec.requests.iter().map(|r| r.url.path.as_str()).collect();
        assert_eq!(paths, ["/p0", "/p1", "/p2"]);
        assert_eq!(MAX_BUFFERED_REQUESTS, 5_000);
    }

    #[test]
    fn an_element_typed_into_endlessly_keeps_its_place_in_the_username_choice() {
        // Thousands of events on one field, then the password: the user name is still found
        // from the last thing typed before the password, with no per-event record kept.
        let mut s = Session::new(LOGIN);
        for _ in 0..5_000 {
            s = s.type_into(&user_el(), USER);
        }
        let rec = s
            .type_into(&pw_el(), PASS)
            .post_form(
                "https://ex.test/login",
                &format!("username={USER}&password={PASS}"),
            )
            .finish();
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert_eq!(rec.classification.shape, Shape::FormPost);
    }

    fn session_with_budget(budget: usize) -> Session {
        let mut s = Session::unstarted(LOGIN);
        s.cap = Capture::with_body_budget(LOGIN, "0.0.0", budget);
        s.start();
        s
    }

    #[test]
    fn bodies_past_the_buffer_limit_are_unavailable() {
        let big = |n: usize| RawBody::Bytes(Zeroizing::new(vec![b'a'; n]));
        let rec = session_with_budget(100)
            .type_into(&user_el(), USER)
            .request(
                "POST",
                "https://ex.test/a",
                ResourceKind::Fetch,
                false,
                Some("text/plain"),
                big(80),
            )
            .request(
                "POST",
                "https://ex.test/b",
                ResourceKind::Fetch,
                false,
                Some("text/plain"),
                big(80),
            )
            .finish();
        assert_eq!(rec.requests.len(), 2);
        assert!(matches!(
            rec.requests[0].body,
            BodyShape::Opaque { len: 80, .. }
        ));
        assert_eq!(rec.requests[1].body, BodyShape::Unavailable);
        assert!(rec.flags.body_unavailable);
        assert_eq!(rec.stripped.request_bodies_reduced, 1);
        assert_eq!(MAX_BUFFERED_BODY_BYTES, 32 << 20);
    }

    #[test]
    fn a_combined_credential_alone_picks_the_username() {
        let combined = Base64::encode_string(format!("{USER}:{PASS}").as_bytes());
        let tenant = no_form(el(4, "tenant", "text"));
        let rec = Session::new(LOGIN)
            .type_into(&no_form(user_el()), USER)
            .type_into(&tenant, TENANT)
            .type_into(&no_form(pw_el()), PASS)
            .post_json(
                "https://ex.test/api/login",
                &format!(r#"{{"auth":"{combined}"}}"#),
            )
            .finish();
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert_eq!(role_of(&rec, 4), Some(Role::None));
        assert_holds_no_typed_value(&rec.to_json(), &ALL_VALUES);
    }

    #[test]
    fn the_same_form_beats_a_later_typed_candidate() {
        let tenant = no_form(el(4, "tenant", "text"));
        let rec = Session::new(LOGIN)
            .type_into(&user_el(), USER)
            .type_into(&tenant, TENANT)
            .type_into(&pw_el(), PASS)
            .post_form("https://ex.test/login", &format!("t={TENANT}&p={PASS}"))
            .finish();
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert_eq!(role_of(&rec, 4), Some(Role::None));
    }

    #[test]
    fn a_value_found_in_any_request_beats_a_later_typed_one() {
        let tenant = no_form(el(4, "tenant", "text"));
        let rec = Session::new(LOGIN)
            .type_into(&no_form(user_el()), USER)
            .type_into(&tenant, TENANT)
            .type_into(&no_form(pw_el()), PASS)
            .post_form("https://ex.test/identify", &format!("u={USER}"))
            .post_form("https://ex.test/login", &format!("p={PASS}"))
            .finish();
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert_eq!(role_of(&rec, 4), Some(Role::None));
    }

    #[test]
    fn with_no_other_evidence_the_last_typed_before_the_password_wins() {
        let tenant = no_form(el(4, "tenant", "text"));
        let rec = Session::new(LOGIN)
            .type_into(&tenant, TENANT)
            .type_into(&no_form(user_el()), USER)
            .type_into(&no_form(pw_el()), PASS)
            .finish();
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert_eq!(role_of(&rec, 4), Some(Role::None));
    }

    #[test]
    fn an_edit_after_the_password_does_not_beat_the_last_field_typed_before_it() {
        let first = no_form(el(4, "tenant", "text"));
        let rec = Session::new(LOGIN)
            .type_into(&first, TENANT)
            .type_into(&no_form(user_el()), USER)
            .type_into(&no_form(pw_el()), PASS)
            .type_into(&first, TENANT)
            .finish();
        assert_eq!(role_of(&rec, 1), Some(Role::Username));
        assert_eq!(role_of(&rec, 4), Some(Role::None));
    }

    #[test]
    fn typed_values_in_every_kept_attribute_are_dropped() {
        let mut e = user_el();
        e.name = Some(format!("n-{USER}"));
        e.autocomplete = Some(format!("x-{USER}"));
        e.aria_label = Some(format!("for {USER}"));
        e.form = Some(RawForm {
            index: 0,
            action: Some(format!("https://ex.test/login?who={USER}&{USER}=1")),
            method: "post".into(),
        });
        let mut clicked = button();
        clicked.id = Some(format!("go-{USER}"));
        clicked.selectors = vec![format!("#go-{USER}"), "button[type=submit]".into()];
        let rec = Session::new(LOGIN)
            .type_into(&e, USER)
            .click(&clicked)
            .finish();
        let (d, _, _) = inputs(&rec)[0];
        assert_eq!(
            (&d.name, &d.autocomplete, &d.aria_label),
            (&None, &None, &None)
        );
        let action = d.form.as_ref().and_then(|f| f.action.as_ref());
        assert!(action.is_some_and(|a| a.query_keys.iter().all(|k| k != USER)));
        match &rec.steps[2] {
            Step::Click { element, .. } => {
                assert_eq!(element.id, None);
                assert_eq!(element.selectors, vec!["button[type=submit]".to_owned()]);
            }
            other => panic!("expected a click, got {other:?}"),
        }
        assert_holds_no_typed_value(&rec.to_json(), &[USER]);
    }

    #[test]
    fn page_derived_tag_and_type_are_checked() {
        let mut odd = user_el();
        odd.tag = "x.weird".into();
        odd.input_type = Some("weird".into());
        let mut custom = el(6, "c", "TEL");
        custom.tag = "My-Widget".into();
        let mut typed = el(7, "d", "text");
        typed.tag = format!("x-{USER}");
        let rec = Session::new(LOGIN)
            .type_into(&odd, USER)
            .type_into(&custom, "1")
            .type_into(&typed, "2")
            .finish();
        let ins = inputs(&rec);
        assert_eq!(ins[0].0.tag, "{other}");
        assert_eq!(ins[0].0.input_type.as_deref(), Some("{other}"));
        assert_eq!(ins[1].0.tag, "my-widget");
        assert_eq!(ins[1].0.input_type.as_deref(), Some("tel"));
        assert_eq!(ins[2].0.tag, "{other}");
    }

    #[test]
    fn the_show_password_scenario_keeps_both_lengths() {
        let rec = scenario("show_toggle");
        let lens: Vec<(u32, u32)> = inputs(&rec)
            .into_iter()
            .map(|(e, len, _)| (e.element_id, len))
            .collect();
        assert_eq!(lens, vec![(1, 13), (2, 12)]);
    }
}
