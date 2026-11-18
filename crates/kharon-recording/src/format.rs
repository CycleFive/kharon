//! The recording file: a typed, value-free record of a demonstrated login.

use serde::{Deserialize, Serialize};

use crate::classify::{Classification, Flags};
use crate::request::{Role, StoredRequest};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrippedUrl {
    /// scheme://host[:port]
    pub origin: String,
    pub path: String,
    pub query_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameRef {
    pub main: bool,
    pub origin: String,
    pub cross_origin: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FormRef {
    pub index: u32,
    pub action: Option<StrippedUrl>,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElementDescriptor {
    pub element_id: u32,
    pub tag: String,
    pub input_type: Option<String>,
    pub id: Option<String>,
    pub name: Option<String>,
    pub autocomplete: Option<String>,
    pub placeholder: Option<String>,
    pub aria_label: Option<String>,
    /// True when the element was a password input (type=password) when recorded.
    pub was_password: bool,
    pub form: Option<FormRef>,
    /// Candidate CSS selectors, most stable first.
    pub selectors: Vec<String>,
    pub in_shadow_root: bool,
}

/// Every `t_ms` is milliseconds since the recording started.
///
/// An `Input` step is recorded once per element, at its first input event, and
/// its `value_len` is updated in place as the value changes. `change` events
/// add no step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    Navigation {
        t_ms: u64,
        frame: FrameRef,
        url: StrippedUrl,
    },
    Input {
        t_ms: u64,
        frame: FrameRef,
        element: ElementDescriptor,
        /// Characters typed so far.
        value_len: u32,
        role: Role,
    },
    Click {
        t_ms: u64,
        frame: FrameRef,
        element: ElementDescriptor,
    },
    Submit {
        t_ms: u64,
        frame: FrameRef,
        form: FormRef,
    },
    EnterKey {
        t_ms: u64,
        frame: FrameRef,
        element: ElementDescriptor,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndedBy {
    Confirmed,
    WindowClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerWorld {
    Isolated,
    Main,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BrowserInfo {
    pub product: String,
    pub user_agent: String,
    pub viewport: Viewport,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrippedCounts {
    /// Requests observed on the wire.
    pub requests_seen: u64,
    /// Requests kept in the file.
    pub requests_stored: u64,
    /// Request bodies replaced by a value-free shape.
    pub request_bodies_reduced: u64,
    /// URL query values dropped (keys are kept).
    pub query_values_removed: u64,
    /// URL path segments replaced by a placeholder.
    pub path_segments_replaced: u64,
    /// Typed input values discarded (only lengths are kept).
    pub typed_values_removed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recording {
    /// `to_json` always writes `FORMAT_VERSION`, whatever this field holds.
    pub format_version: u32,
    pub tool_version: String,
    pub browser: BrowserInfo,
    pub listener_world: ListenerWorld,
    /// RFC 3339, UTC.
    pub started_at: String,
    /// RFC 3339, UTC.
    pub ended_at: String,
    pub ended_by: EndedBy,
    pub success_confirmed: bool,
    pub start_url: StrippedUrl,
    pub final_url: Option<StrippedUrl>,
    pub steps: Vec<Step>,
    pub requests: Vec<StoredRequest>,
    pub flags: Flags,
    pub classification: Classification,
    pub stripped: StrippedCounts,
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("unsupported recording format_version {0}")]
    UnsupportedVersion(u32),
    #[error("not a kharon recording: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Deserialize)]
struct VersionProbe {
    format_version: u32,
}

impl Recording {
    /// Pretty JSON with a trailing newline.
    pub fn to_json(&self) -> String {
        let mut copy = self.clone();
        copy.format_version = FORMAT_VERSION;
        let mut text = serde_json::to_string_pretty(&copy)
            .expect("a Recording is plain data and always serializes");
        text.push('\n');
        text
    }

    /// The version is checked before the full parse.
    pub fn from_json(text: &str) -> Result<Self, FormatError> {
        let probe: VersionProbe = serde_json::from_str(text)?;
        if probe.format_version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(probe.format_version));
        }
        Ok(serde_json::from_str(text)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{PasswordLeg, RungCeiling, Shape};
    use crate::request::{
        AuthShape, BodyShape, Encoding, FieldShape, JsonField, JsonShape, MarkerHit, ResourceKind,
        ValueKind, ValueShape,
    };

    fn url(path: &str) -> StrippedUrl {
        StrippedUrl {
            origin: "https://example.test".into(),
            path: path.into(),
            query_keys: vec![],
        }
    }

    fn frame() -> FrameRef {
        FrameRef {
            main: true,
            origin: "https://example.test".into(),
            cross_origin: false,
        }
    }

    fn hit(role: Role) -> MarkerHit {
        MarkerHit {
            role,
            encoding: Encoding::AsTyped,
            low_confidence: false,
        }
    }

    fn value(markers: Vec<MarkerHit>) -> ValueShape {
        ValueShape {
            kind: ValueKind::String,
            len: 8,
            markers,
        }
    }

    fn request(body: BodyShape) -> StoredRequest {
        StoredRequest {
            t_ms: 120,
            method: "POST".into(),
            url: url("/login"),
            resource: ResourceKind::Document,
            main_frame_navigation: true,
            content_type: Some("application/x-www-form-urlencoded".into()),
            authorization: None,
            url_markers: vec![],
            body,
            response: None,
        }
    }

    fn sample() -> Recording {
        let element = ElementDescriptor {
            element_id: 2,
            tag: "input".into(),
            input_type: Some("password".into()),
            id: Some("pw".into()),
            name: Some("password".into()),
            autocomplete: None,
            placeholder: None,
            aria_label: None,
            was_password: true,
            form: Some(FormRef {
                index: 0,
                action: Some(url("/login")),
                method: "post".into(),
            }),
            selectors: vec!["#pw".into()],
            in_shadow_root: false,
        };
        let body = BodyShape::Urlencoded {
            fields: vec![FieldShape {
                key: "password".into(),
                value: value(vec![hit(Role::Password)]),
            }],
        };
        Recording {
            format_version: FORMAT_VERSION,
            tool_version: "0.0.0".into(),
            browser: BrowserInfo {
                product: "Chrome/1".into(),
                user_agent: "UA".into(),
                viewport: Viewport {
                    width: 1280,
                    height: 800,
                },
            },
            listener_world: ListenerWorld::Isolated,
            started_at: "2026-11-18T00:00:00Z".into(),
            ended_at: "2026-11-18T00:01:00Z".into(),
            ended_by: EndedBy::Confirmed,
            success_confirmed: true,
            start_url: url("/login"),
            final_url: Some(url("/home")),
            steps: vec![
                Step::Navigation {
                    t_ms: 0,
                    frame: frame(),
                    url: url("/login"),
                },
                Step::Input {
                    t_ms: 50,
                    frame: frame(),
                    element,
                    value_len: 8,
                    role: Role::Password,
                },
            ],
            requests: vec![request(body)],
            flags: Flags::default(),
            classification: Classification {
                shape: Shape::TwoStep {
                    password_leg: PasswordLeg::FormPost,
                },
                rung_ceiling: RungCeiling::Milliseconds,
                network_swap_candidate: false,
                notes: vec![],
            },
            stripped: StrippedCounts {
                requests_seen: 3,
                requests_stored: 1,
                request_bodies_reduced: 1,
                query_values_removed: 0,
                path_segments_replaced: 0,
                typed_values_removed: 2,
            },
        }
    }

    fn request_with_three_hits() -> StoredRequest {
        let nested = JsonShape::Object {
            fields: vec![JsonField {
                key: "auth".into(),
                value: JsonShape::Array {
                    items: vec![JsonShape::Object {
                        fields: vec![JsonField {
                            key: "p".into(),
                            value: JsonShape::Value {
                                value: value(vec![hit(Role::Password)]),
                            },
                        }],
                    }],
                },
            }],
        };
        let mut r = request(BodyShape::Json { root: nested });
        r.url_markers = vec![hit(Role::Username)];
        r.authorization = Some(AuthShape {
            scheme: "Bearer".into(),
            markers: vec![hit(Role::Password)],
        });
        r
    }

    #[test]
    fn round_trips() {
        let r = sample();
        assert_eq!(Recording::from_json(&r.to_json()).unwrap(), r);
    }

    #[test]
    fn round_trips_nested_classification_shape() {
        let c = Classification {
            shape: Shape::Transformed {
                digest: Some("sha256".into()),
            },
            rung_ceiling: RungCeiling::NeedsPerson,
            network_swap_candidate: true,
            notes: vec!["n".into()],
        };
        let text = serde_json::to_string(&c).unwrap();
        assert!(
            text.contains("\"shape\":{\"kind\":\"transformed\""),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<Classification>(&text).unwrap(), c);
    }

    #[test]
    fn refuses_an_unknown_version() {
        let text = sample()
            .to_json()
            .replace("\"format_version\": 1", "\"format_version\": 2");
        assert!(matches!(
            Recording::from_json(&text),
            Err(FormatError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn refuses_a_file_with_no_version() {
        assert!(matches!(
            Recording::from_json("{}"),
            Err(FormatError::Parse(_))
        ));
    }

    #[test]
    fn wire_names_are_snake_case_and_tagged() {
        let j = sample().to_json();
        for needle in [
            "\"kind\": \"navigation\"",
            "\"role\": \"password\"",
            "\"kind\": \"urlencoded\"",
            "\"encoding\": \"as_typed\"",
            "\"ended_by\": \"confirmed\"",
        ] {
            assert!(j.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn hits_walks_url_authorization_and_nested_json() {
        assert_eq!(request_with_three_hits().hits().len(), 3);
    }

    #[test]
    fn digest_names() {
        assert!(Encoding::Sha256Hex.is_digest());
        assert_eq!(Encoding::Md5Base64.digest_name(), Some("md5"));
        assert!(!Encoding::Hex.is_digest());
    }

    #[test]
    fn to_json_always_writes_the_current_version() {
        let mut r = sample();
        r.format_version = 99;
        let back = Recording::from_json(&r.to_json()).unwrap();
        assert_eq!(back.format_version, FORMAT_VERSION);
    }

    #[test]
    fn every_variant_round_trips() {
        let mut r = sample();
        let Step::Input { element, .. } = r.steps[1].clone() else {
            unreachable!()
        };
        let form = element.form.clone().unwrap();
        r.steps.extend([
            Step::Click {
                t_ms: 60,
                frame: frame(),
                element: element.clone(),
            },
            Step::Submit {
                t_ms: 70,
                frame: frame(),
                form,
            },
            Step::EnterKey {
                t_ms: 80,
                frame: frame(),
                element,
            },
        ]);
        let json_root = JsonShape::Object {
            fields: vec![JsonField {
                key: "p".into(),
                value: JsonShape::Value {
                    value: value(vec![hit(Role::Password)]),
                },
            }],
        };
        let bodies = [
            BodyShape::None,
            BodyShape::Unavailable,
            BodyShape::Json { root: json_root },
            BodyShape::Multipart {
                parts: vec![FieldShape {
                    key: "f".into(),
                    value: value(vec![hit(Role::Username)]),
                }],
            },
            BodyShape::Opaque {
                len: 9,
                markers: vec![hit(Role::Password)],
            },
        ];
        r.requests = bodies.into_iter().map(request).collect();
        let shapes = [
            Shape::FormPost,
            Shape::ScriptPost,
            Shape::TwoStep {
                password_leg: PasswordLeg::ScriptPost,
            },
            Shape::TwoStep {
                password_leg: PasswordLeg::Transformed,
            },
            Shape::Transformed { digest: None },
            Shape::Transformed {
                digest: Some("md5".into()),
            },
            Shape::Unrecognized,
        ];
        for shape in shapes {
            r.classification.shape = shape;
            assert_eq!(Recording::from_json(&r.to_json()).unwrap(), r);
        }
    }

    #[test]
    fn two_step_wire_form() {
        let c = sample().classification;
        let text = serde_json::to_string(&c).unwrap();
        assert!(
            text.contains(r#""shape":{"kind":"two_step","password_leg":"form_post"}"#),
            "{text}"
        );
    }

    #[test]
    fn hits_covers_multipart_and_opaque() {
        let m = request(BodyShape::Multipart {
            parts: vec![
                FieldShape {
                    key: "a".into(),
                    value: value(vec![hit(Role::Username)]),
                },
                FieldShape {
                    key: "b".into(),
                    value: value(vec![hit(Role::Password)]),
                },
            ],
        });
        assert_eq!(m.hits().len(), 2);
        let o = request(BodyShape::Opaque {
            len: 4,
            markers: vec![hit(Role::Password)],
        });
        assert_eq!(o.hits().len(), 1);
    }
}
