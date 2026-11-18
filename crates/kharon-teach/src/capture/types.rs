//! The events a capture takes and the description it ends with. None of these types derives
//! `Debug`: some hold a typed value.

use kharon_recording::{BrowserInfo, EndedBy, ListenerWorld, ResourceKind};
use zeroize::Zeroizing;

/// An element as the page script described it. No value: that travels beside it.
#[derive(Clone)]
pub struct RawElement {
    pub element_id: u32,
    pub document_id: String,
    pub tag: String,
    pub input_type: Option<String>,
    pub id: Option<String>,
    pub name: Option<String>,
    pub autocomplete: Option<String>,
    pub placeholder: Option<String>,
    pub aria_label: Option<String>,
    pub is_password_now: bool,
    pub form: Option<RawForm>,
    pub selectors: Vec<String>,
    pub in_shadow_root: bool,
}

#[derive(Clone)]
pub struct RawForm {
    pub index: u32,
    /// The resolved absolute `form.action` DOM property, not the attribute text.
    pub action: Option<String>,
    pub method: String,
}

#[derive(Clone)]
pub struct RawFrame {
    pub main: bool,
    pub url: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PageEventKind {
    Input,
    Change,
    Click,
    Submit,
    EnterKey,
}

pub enum RawBody {
    None,
    Unavailable,
    Bytes(Zeroizing<Vec<u8>>),
}

pub enum CaptureEvent {
    /// The main frame left the notice page.
    Started {
        browser: BrowserInfo,
        listener_world: ListenerWorld,
    },
    /// Main and child frames alike.
    Navigation {
        t_ms: u64,
        frame: RawFrame,
    },
    /// `value` is set only for `Input` and `Change`.
    Page {
        t_ms: u64,
        kind: PageEventKind,
        frame: RawFrame,
        element: RawElement,
        value: Option<Zeroizing<String>>,
    },
    Request {
        request_id: String,
        t_ms: u64,
        method: String,
        url: String,
        resource: ResourceKind,
        main_frame_navigation: bool,
        content_type: Option<String>,
        authorization: Option<Zeroizing<Vec<u8>>>,
        body: RawBody,
        frame_url: String,
    },
    Response {
        request_id: String,
        status: u16,
        content_type: Option<String>,
        set_cookie: bool,
    },
    Popup,
}

pub struct EndInfo {
    pub ended_by: EndedBy,
    pub success_confirmed: bool,
    pub started_at: String,
    pub ended_at: String,
}
