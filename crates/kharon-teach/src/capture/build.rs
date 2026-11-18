//! Turning buffered events into the value-free parts of a `Recording`.

use kharon_recording::{
    BodyShape, ElementDescriptor, FormRef, FrameRef, MarkerHit, ResponseShape, StoredRequest,
    StrippedUrl,
};

use super::{Buffered, FrameInfo, RawBody, RawElement, RawForm};
use crate::body::shape_of_body;
use crate::marker::Marker;
use crate::strip::{TYPED, dedup_hits, hits_in, holds_typed, reduce_authorization, strip_url};

/// What is known while stripping: every typed value, and the credential pair once chosen.
#[derive(Clone, Copy)]
pub(super) struct Ctx<'a> {
    pub markers: &'a [Marker],
    pub pair: Option<(&'a Marker, &'a Marker)>,
}

impl Ctx<'_> {
    fn holds_typed(&self, text: &str) -> bool {
        holds_typed(text.as_bytes(), self.markers, self.pair)
    }
}

/// Counts of what stripping removed, for URLs that are written to the file.
#[derive(Default, Clone, Copy)]
pub(super) struct Tally {
    pub query_values_removed: u64,
    pub path_segments_replaced: u64,
}

impl Tally {
    pub fn add(&mut self, other: Tally) {
        self.query_values_removed += other.query_values_removed;
        self.path_segments_replaced += other.path_segments_replaced;
    }
}

const OTHER_ORIGIN: &str = "{other}:";

/// `Some` when the URL parses. The tally is the URL's own counts.
fn strip(url: &str, ctx: Ctx<'_>) -> Option<(StrippedUrl, Tally)> {
    strip_url(url, ctx.markers, ctx.pair).map(|s| {
        (
            s.value,
            Tally {
                query_values_removed: s.query_values_removed,
                path_segments_replaced: s.path_segments_replaced,
            },
        )
    })
}

/// A URL for the file; one that does not parse becomes an empty `{other}:` origin.
pub(super) fn stripped_url(url: &str, ctx: Ctx<'_>, tally: &mut Tally) -> StrippedUrl {
    match strip(url, ctx) {
        Some((u, t)) => {
            tally.add(t);
            u
        }
        None => StrippedUrl {
            origin: OTHER_ORIGIN.to_owned(),
            path: String::new(),
            query_keys: Vec::new(),
        },
    }
}

pub(super) fn frame_ref(info: &FrameInfo, ctx: Ctx<'_>) -> FrameRef {
    FrameRef {
        main: info.main,
        origin: strip(&info.url, ctx).map_or_else(|| OTHER_ORIGIN.to_owned(), |(u, _)| u.origin),
        cross_origin: info.cross_origin,
    }
}

/// An attribute is kept only when it holds no typed value.
fn clean(attr: Option<&String>, ctx: Ctx<'_>) -> Option<String> {
    attr.filter(|a| !ctx.holds_typed(a)).cloned()
}

/// A selector holding a typed value, also once CSS escapes (`\.`) are undone, is removed.
fn selector_is_clean(selector: &str, ctx: Ctx<'_>) -> bool {
    let unescaped: String = selector.chars().filter(|c| *c != '\\').collect();
    !ctx.holds_typed(selector) && !ctx.holds_typed(&unescaped)
}

const INPUT_TYPES: [&str; 22] = [
    "text",
    "password",
    "email",
    "tel",
    "number",
    "search",
    "url",
    "hidden",
    "checkbox",
    "radio",
    "submit",
    "button",
    "reset",
    "file",
    "date",
    "datetime-local",
    "month",
    "week",
    "time",
    "color",
    "range",
    "image",
];

/// An HTML input type keyword, lowercased; anything else is `{other}`.
fn input_type_keyword(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if INPUT_TYPES.contains(&lower.as_str()) {
        lower
    } else {
        "{other}".to_owned()
    }
}

/// A tag name, lowercased, when it is ASCII letters, digits and `-` and holds no typed value.
fn tag_name(raw: &str, ctx: Ctx<'_>) -> String {
    let lower = raw.to_ascii_lowercase();
    let plain = !lower.is_empty()
        && lower
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if plain && !ctx.holds_typed(&lower) {
        lower
    } else {
        "{other}".to_owned()
    }
}

fn known_method(method: &str, lowercase: bool) -> String {
    let upper = method.to_ascii_uppercase();
    let known = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    if !known.contains(&upper.as_str()) {
        return "{other}".to_owned();
    }
    if lowercase {
        upper.to_lowercase()
    } else {
        upper
    }
}

pub(super) fn form_ref(form: &RawForm, ctx: Ctx<'_>, tally: &mut Tally) -> FormRef {
    FormRef {
        index: form.index,
        action: form
            .action
            .as_deref()
            .and_then(|a| strip(a, ctx))
            .map(|(u, t)| {
                tally.add(t);
                u
            }),
        method: known_method(&form.method, true),
    }
}

pub(super) fn describe(
    raw: &RawElement,
    was_password: bool,
    ctx: Ctx<'_>,
    tally: &mut Tally,
) -> ElementDescriptor {
    ElementDescriptor {
        element_id: raw.element_id,
        tag: tag_name(&raw.tag, ctx),
        input_type: raw.input_type.as_deref().map(input_type_keyword),
        id: clean(raw.id.as_ref(), ctx),
        name: clean(raw.name.as_ref(), ctx),
        autocomplete: clean(raw.autocomplete.as_ref(), ctx),
        placeholder: clean(raw.placeholder.as_ref(), ctx),
        aria_label: clean(raw.aria_label.as_ref(), ctx),
        was_password,
        form: raw.form.as_ref().map(|f| form_ref(f, ctx, tally)),
        selectors: raw
            .selectors
            .iter()
            .filter(|s| selector_is_clean(s, ctx))
            .cloned()
            .collect(),
        in_shadow_root: raw.in_shadow_root,
    }
}

/// The media type alone, lowercased: parameters (a multipart boundary) are not kept. One that
/// holds a typed value is `{typed}`.
fn media_type(content_type: Option<&str>, ctx: Ctx<'_>) -> Option<String> {
    let essence = content_type?
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    Some(if ctx.holds_typed(&essence) {
        TYPED.to_owned()
    } else {
        essence
    })
}

pub(super) fn response_shape(r: &super::BufferedResponse, ctx: Ctx<'_>) -> ResponseShape {
    ResponseShape {
        status: r.status,
        content_type: media_type(r.content_type.as_deref(), ctx),
        set_cookie: r.set_cookie,
    }
}

/// Every marker hit in the request's raw bytes: its URL, its Authorization header and its whole
/// body, with no shape built. What decides whether the request is kept.
pub(super) fn raw_hits(b: &Buffered, ctx: Ctx<'_>) -> Vec<MarkerHit> {
    let mut out = hits_in(b.url.as_bytes(), ctx.markers, ctx.pair);
    if let Some(a) = &b.authorization {
        out.extend(reduce_authorization(a, ctx.markers, ctx.pair).markers);
    }
    if let RawBody::Bytes(bytes) = &b.body {
        out.extend(hits_in(bytes, ctx.markers, ctx.pair));
    }
    dedup_hits(out)
}

/// The reduced request, with the counts of what stripping its URL removed and whether its body
/// was reduced to a shape. `None` when the URL does not parse. Whether to keep it is decided by
/// the caller BEFORE this is called, so only kept requests are shaped.
pub(super) fn reduce_request(b: &Buffered, ctx: Ctx<'_>) -> Option<(StoredRequest, Tally, bool)> {
    let (url, tally) = strip(&b.url, ctx)?;
    let reduced_body = matches!(b.body, RawBody::Bytes(_));
    let body = match &b.body {
        RawBody::None => BodyShape::None,
        RawBody::Unavailable => BodyShape::Unavailable,
        RawBody::Bytes(bytes) => {
            shape_of_body(b.content_type.as_deref(), bytes, ctx.markers, ctx.pair)
        }
    };
    let stored = StoredRequest {
        t_ms: b.t_ms,
        method: known_method(&b.method, false),
        url,
        resource: b.resource,
        main_frame_navigation: b.main_frame_navigation,
        content_type: media_type(b.content_type.as_deref(), ctx),
        authorization: b
            .authorization
            .as_ref()
            .map(|a| reduce_authorization(a, ctx.markers, ctx.pair)),
        url_markers: hits_in(b.url.as_bytes(), ctx.markers, ctx.pair),
        body,
        response: b.response.as_ref().map(|r| response_shape(r, ctx)),
    };
    Some((stored, tally, reduced_body))
}
