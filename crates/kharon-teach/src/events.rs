//! Typed CDP messages: the event parameters the recorder reads, the parameters
//! it sends, and the report the page script passes through the binding.
//!
//! Anything that can hold page data (what a person typed, a request body, a
//! header value) is held in `Zeroizing` and has no `Debug` impl: a derive would
//! print the content.

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroizing;

// ---- events the recorder reads ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachedToTarget {
    pub session_id: String,
    pub target_info: TargetInfo,
    pub waiting_for_debugger: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    pub target_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    #[serde(default)]
    pub opener_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetDestroyed {
    pub target_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetachedFromTarget {
    pub session_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameNavigated {
    pub frame: Frame,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    pub id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    pub url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindingCalled {
    pub name: String,
    pub payload: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestWillBeSent {
    pub request_id: String,
    pub loader_id: String,
    #[serde(default)]
    pub frame_id: Option<String>,
    #[serde(rename = "documentURL")]
    pub document_url: String,
    pub request: Request,
    #[serde(rename = "type", default)]
    pub resource: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub url: String,
    pub method: String,
    #[serde(default)]
    pub headers: Headers,
    #[serde(default)]
    pub post_data: Option<Zeroizing<String>>,
    #[serde(default)]
    pub has_post_data: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseReceived {
    pub request_id: String,
    pub response: Response,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    #[serde(deserialize_with = "lenient_status")]
    pub status: u16,
    #[serde(default)]
    pub headers: Headers,
}

/// A status outside `u16` (or fractional) must not fail the whole event.
fn lenient_status<'de, D: Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
    let v = f64::deserialize(d)?;
    // `as` saturates and maps NaN to 0.
    Ok(v.clamp(0.0, f64::from(u16::MAX)) as u16)
}

// ---- results ----

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub product: String,
    pub user_agent: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayoutMetrics {
    pub css_visual_viewport: VisualViewport,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VisualViewport {
    pub client_width: f64,
    pub client_height: f64,
}

/// The result of `Network.getRequestPostData`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostData {
    pub post_data: Zeroizing<String>,
}

// ---- headers ----

/// Header map. Values are `Zeroizing` and there is no `Debug`.
#[derive(Default)]
pub struct Headers(HashMap<String, Zeroizing<String>>);

impl Headers {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn content_type(&self) -> Option<&str> {
        self.get("content-type")
    }

    pub fn authorization(&self) -> Option<&str> {
        self.get("authorization")
    }

    pub fn has_set_cookie(&self) -> bool {
        self.0.keys().any(|k| k.eq_ignore_ascii_case("set-cookie"))
    }
}

/// A header value that is a string, or anything else (skipped).
struct MaybeString(Option<Zeroizing<String>>);

impl<'de> Deserialize<'de> for MaybeString {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = MaybeString;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a header value")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(MaybeString(Some(Zeroizing::new(v.to_owned()))))
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(MaybeString(Some(Zeroizing::new(v))))
            }
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(MaybeString(None))
            }
            fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
                Ok(MaybeString(None))
            }
            fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
                Ok(MaybeString(None))
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(MaybeString(None))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(MaybeString(None))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(MaybeString(None))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(MaybeString(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(MaybeString(None))
            }
        }
        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for Headers {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Headers;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a header object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Headers, A::Error> {
                let mut out = HashMap::new();
                while let Some((k, v)) = map.next_entry::<String, MaybeString>()? {
                    if let Some(v) = v.0 {
                        out.insert(k, v);
                    }
                }
                Ok(Headers(out))
            }
        }
        d.deserialize_map(V)
    }
}

// ---- parameters the recorder sends ----

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetAutoAttach {
    pub auto_attach: bool,
    pub wait_for_debugger_on_start: bool,
    pub flatten: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddBinding<'a> {
    pub name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_context_name: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddScriptToEvaluateOnNewDocument<'a> {
    pub source: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub world_name: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRequestPostData<'a> {
    pub request_id: &'a str,
}

/// Parameters for a call that takes none: serializes as `{}`.
#[derive(Serialize)]
pub struct Empty {}

// ---- the page script's report ----

const MAX_FIELD_CHARS: usize = 4096;
const MAX_SELECTORS: usize = 16;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    Input,
    Change,
    Click,
    Submit,
    EnterKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ListenerReport {
    pub kind: ReportKind,
    pub document_id: String,
    pub frame_url: String,
    pub is_top: bool,
    pub element: ReportElement,
    #[serde(default)]
    pub value: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReportElement {
    pub element_id: u32,
    pub tag: String,
    #[serde(default)]
    pub input_type: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub autocomplete: Option<String>,
    #[serde(default)]
    pub placeholder: Option<String>,
    #[serde(default)]
    pub aria_label: Option<String>,
    #[serde(default)]
    pub is_password_now: bool,
    #[serde(default)]
    pub form: Option<ReportForm>,
    #[serde(default)]
    pub selectors: Vec<String>,
    #[serde(default)]
    pub in_shadow_root: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReportForm {
    pub index: u32,
    #[serde(default)]
    pub action: Option<String>,
    pub method: String,
}

fn short(s: &str) -> bool {
    s.chars().take(MAX_FIELD_CHARS + 1).count() <= MAX_FIELD_CHARS
}

fn short_opt(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(short)
}

impl ListenerReport {
    /// False when a hostile page sent more than the recorder will hold: any
    /// string over 4,096 characters, or more than 16 selectors.
    pub fn within_limits(&self) -> bool {
        let e = &self.element;
        short(&self.document_id)
            && short(&self.frame_url)
            && self.value.as_ref().is_none_or(|v| short(v))
            && short(&e.tag)
            && short_opt(&e.input_type)
            && short_opt(&e.id)
            && short_opt(&e.name)
            && short_opt(&e.autocomplete)
            && short_opt(&e.placeholder)
            && short_opt(&e.aria_label)
            && e.selectors.len() <= MAX_SELECTORS
            && e.selectors.iter().all(|s| short(s))
            && e.form
                .as_ref()
                .is_none_or(|f| short_opt(&f.action) && short(&f.method))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdp::parse_quiet;

    const REPORT: &str = r##"{
        "kind": "input", "document_id": "d1", "frame_url": "https://a.test/login",
        "is_top": true, "value": "Tr0ub4dor-9x",
        "element": {
            "element_id": 3, "tag": "input", "input_type": "password", "id": "pw",
            "name": "password", "autocomplete": "current-password",
            "is_password_now": true,
            "form": {"index": 0, "action": "/session", "method": "post"},
            "selectors": ["#pw", "input[name=password]"], "in_shadow_root": false
        }
    }"##;

    #[test]
    fn listener_report_parses_and_value_is_zeroizing() {
        let r: ListenerReport = parse_quiet(REPORT).unwrap();
        assert!(matches!(r.kind, ReportKind::Input));
        let v: &Zeroizing<String> = r.value.as_ref().unwrap();
        assert_eq!(v.as_str(), "Tr0ub4dor-9x");
        assert_eq!(r.element.element_id, 3);
        assert_eq!(r.element.input_type.as_deref(), Some("password"));
        assert!(r.element.is_password_now);
        let f = r.element.form.as_ref().unwrap();
        assert_eq!(
            (f.index, f.action.as_deref(), f.method.as_str()),
            (0, Some("/session"), "post")
        );
        assert_eq!(r.element.selectors.len(), 2);
        assert!(r.within_limits());
    }

    #[test]
    fn a_sparse_report_parses() {
        let raw = r#"{"kind":"enter_key","document_id":"d","frame_url":"u","is_top":false,
            "element":{"element_id":1,"tag":"input"}}"#;
        let r: ListenerReport = parse_quiet(raw).unwrap();
        assert!(matches!(r.kind, ReportKind::EnterKey));
        assert!(r.value.is_none() && r.element.selectors.is_empty() && r.element.form.is_none());
        assert!(!r.element.is_password_now && !r.element.in_shadow_root);
    }

    #[test]
    fn oversized_reports_are_out_of_limits() {
        let mut r: ListenerReport = parse_quiet(REPORT).unwrap();
        r.value = Some(Zeroizing::new("x".repeat(4097)));
        assert!(!r.within_limits());
        r.value = Some(Zeroizing::new("x".repeat(4096)));
        assert!(r.within_limits());

        let mut r: ListenerReport = parse_quiet(REPORT).unwrap();
        r.element.selectors = vec!["a".to_owned(); 17];
        assert!(!r.within_limits());
        r.element.selectors = vec!["a".to_owned(); 16];
        assert!(r.within_limits());

        let mut r: ListenerReport = parse_quiet(REPORT).unwrap();
        r.element.name = Some("n".repeat(5000));
        assert!(!r.within_limits());

        let mut r: ListenerReport = parse_quiet(REPORT).unwrap();
        r.frame_url = "u".repeat(4097);
        assert!(!r.within_limits());

        let mut r: ListenerReport = parse_quiet(REPORT).unwrap();
        r.element.form.as_mut().unwrap().action = Some("a".repeat(4097));
        assert!(!r.within_limits());
    }

    #[test]
    fn headers_are_read_case_insensitively() {
        let h: Headers = parse_quiet(
            r#"{"Content-Type":"application/json","AUTHORIZATION":"Bearer x","Set-Cookie":"a=b"}"#,
        )
        .unwrap();
        assert_eq!(h.content_type(), Some("application/json"));
        assert_eq!(h.authorization(), Some("Bearer x"));
        assert!(h.has_set_cookie());

        let h: Headers = parse_quiet(r#"{"content-type":"text/html"}"#).unwrap();
        assert_eq!(h.content_type(), Some("text/html"));
        assert_eq!(h.authorization(), None);
        assert!(!h.has_set_cookie());
    }

    #[test]
    fn a_non_string_header_is_skipped_not_fatal() {
        let h: Headers =
            parse_quiet(r#"{"x-n":5,"x-a":["a"],"x-o":{"k":1},"x-z":null,"content-type":"t"}"#)
                .unwrap();
        assert_eq!(h.content_type(), Some("t"));
    }

    #[test]
    fn a_wild_status_does_not_fail_the_event() {
        let r: ResponseReceived =
            parse_quiet(r#"{"requestId":"1","response":{"status":99999,"headers":{}}}"#).unwrap();
        assert_eq!(r.response.status, u16::MAX);
        let r: ResponseReceived =
            parse_quiet(r#"{"requestId":"1","response":{"status":-3,"headers":{}}}"#).unwrap();
        assert_eq!(r.response.status, 0);
        let r: ResponseReceived = parse_quiet(
            r#"{"requestId":"1","response":{"status":302,"headers":{"Set-Cookie":"s"}}}"#,
        )
        .unwrap();
        assert_eq!(r.response.status, 302);
        assert!(r.response.headers.has_set_cookie());
    }

    #[test]
    fn a_request_event_parses_with_unknown_fields_ignored() {
        let raw = r#"{"requestId":"r","loaderId":"l","frameId":"f","documentURL":"https://a.test/",
            "request":{"url":"https://a.test/s","method":"POST","headers":{"Content-Type":"x"},
              "postData":"user=a&pass=b","hasPostData":true,"initialPriority":"High"},
            "type":"Document","timestamp":1.5}"#;
        let e: RequestWillBeSent = parse_quiet(raw).unwrap();
        assert_eq!(e.request.method, "POST");
        assert_eq!(
            e.request.post_data.as_ref().map(|p| p.as_str()),
            Some("user=a&pass=b")
        );
        assert_eq!(e.resource.as_deref(), Some("Document"));
        assert_eq!(e.request.headers.content_type(), Some("x"));
    }

    #[test]
    fn sent_params_serialize_in_camel_case_and_skip_none() {
        let s = serde_json::to_string(&AddBinding {
            name: "b",
            execution_context_name: None,
        })
        .unwrap();
        assert_eq!(s, r#"{"name":"b"}"#);
        let s = serde_json::to_string(&SetAutoAttach {
            auto_attach: true,
            wait_for_debugger_on_start: true,
            flatten: true,
        })
        .unwrap();
        assert_eq!(
            s,
            r#"{"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true}"#
        );
        assert_eq!(serde_json::to_string(&Empty {}).unwrap(), "{}");
        let s = serde_json::to_string(&AddScriptToEvaluateOnNewDocument {
            source: "1",
            world_name: Some("w"),
        })
        .unwrap();
        assert_eq!(s, r#"{"source":"1","worldName":"w"}"#);
    }
}
