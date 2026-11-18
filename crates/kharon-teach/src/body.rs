//! Request bodies reduced to shapes: where a typed value sat, never what it was.
//!
//! The site's JSON body is read as a `serde_json::Value` here, the one place a site payload may
//! be, while its shape is extracted. Known limit: the parsed `Value` holds typed values in
//! ordinary `String`s that serde_json does not zeroize.

use kharon_recording::{BodyShape, FieldShape, JsonField, JsonShape, ValueKind, ValueShape};
use memchr::memmem;
use zeroize::Zeroizing;

use crate::marker::Marker;
use crate::strip::{TYPED, decode_percent, hits_in, holds_typed};

/// Bodies larger than this are not parsed: they are `Opaque`.
pub const MAX_BODY_BYTES: usize = 1 << 20;

/// `content_type` picks the reader: application/x-www-form-urlencoded, application/json (and any +json),
/// multipart/form-data; anything else, or a body that fails to parse as its declared type, is Opaque.
/// `pair` is (username, password) once both are known; see below.
///
/// Values are searched after decoding (percent-decoded urlencoded value with `+` as space, a JSON
/// string's content, a JSON number's text, a multipart text part's bytes). An `Opaque` body is
/// searched as raw bytes. A name (key, part name) holding a typed value is written as `{typed}`.
/// Never returns `None` or `Unavailable`.
pub fn shape_of_body(
    content_type: Option<&str>,
    body: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> BodyShape {
    let parsed = match content_type.map(ContentType::parse) {
        Some(ct) if body.len() <= MAX_BODY_BYTES => match ct.essence.as_str() {
            "application/x-www-form-urlencoded" => Some(BodyShape::Urlencoded {
                fields: urlencoded_fields(body, markers, pair),
            }),
            "multipart/form-data" => ct
                .boundary
                .as_deref()
                .and_then(|b| multipart_parts(body, b, markers, pair))
                .map(|parts| BodyShape::Multipart { parts }),
            e if e == "application/json" || e.ends_with("+json") => {
                // The one permitted use of `serde_json::Value`: a site's JSON body while its shape is extracted.
                serde_json::from_slice::<serde_json::Value>(body)
                    .ok()
                    .map(|v| BodyShape::Json {
                        root: json_shape(&v, markers, pair),
                    })
            }
            _ => None,
        },
        _ => None,
    };
    parsed.unwrap_or_else(|| BodyShape::Opaque {
        len: u64::try_from(body.len()).unwrap_or(u64::MAX),
        markers: hits_in(body, markers, pair),
    })
}

struct ContentType {
    /// Lowercased, without parameters.
    essence: String,
    boundary: Option<String>,
}

impl ContentType {
    fn parse(raw: &str) -> Self {
        let (essence, params) = raw.split_once(';').unwrap_or((raw, ""));
        let boundary = parameters(params)
            .into_iter()
            .find(|(k, _)| k == "boundary")
            .map(|(_, v)| v)
            .filter(|v| !v.is_empty());
        Self {
            essence: essence.trim().to_ascii_lowercase(),
            boundary,
        }
    }
}

/// `; key=value; key="quoted value"` pairs, keys lowercased. Quotes may hold `;` and `\`-escapes.
fn parameters(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        let mut key = String::new();
        while let Some(c) = chars.next_if(|c| *c != '=' && *c != ';') {
            key.push(c);
        }
        let mut value = String::new();
        if chars.next_if_eq(&'=').is_some() {
            if chars.next_if_eq(&'"').is_some() {
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => value.extend(chars.next()),
                        c => value.push(c),
                    }
                }
                // Anything up to the next `;` after the closing quote is ignored.
                while chars.next_if(|c| *c != ';').is_some() {}
            } else {
                while let Some(c) = chars.next_if(|c| *c != ';') {
                    value.push(c);
                }
            }
        }
        let key = key.trim().to_ascii_lowercase();
        if !key.is_empty() {
            out.push((key, value.trim().to_owned()));
        }
        if chars.next().is_none() {
            return out;
        }
    }
}

/// Characters in `bytes` read as UTF-8, each invalid run counting as one. Makes no copy.
fn char_len(bytes: &[u8]) -> u32 {
    let n: usize = bytes
        .utf8_chunks()
        .map(|c| c.valid().chars().count() + usize::from(!c.invalid().is_empty()))
        .sum();
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn byte_len(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap_or(u32::MAX)
}

fn value_shape(
    kind: ValueKind,
    len: u32,
    searched: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> ValueShape {
    ValueShape {
        kind,
        len,
        markers: hits_in(searched, markers, pair),
    }
}

fn text_value(bytes: &[u8], markers: &[Marker], pair: Option<(&Marker, &Marker)>) -> ValueShape {
    value_shape(ValueKind::String, char_len(bytes), bytes, markers, pair)
}

/// A name that is kept only when it holds no typed value (any encoding, or the text in any
/// letter case, raw or percent-decoded; see `strip::holds_typed`).
fn name(bytes: &[u8], markers: &[Marker], pair: Option<(&Marker, &Marker)>) -> String {
    if holds_typed(bytes, markers, pair) {
        TYPED.to_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn urlencoded_fields(
    body: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> Vec<FieldShape> {
    body.split(|b| *b == b'&')
        .filter(|piece| !piece.is_empty())
        .map(|piece| {
            let (k, v) = match piece.iter().position(|b| *b == b'=') {
                Some(i) => (&piece[..i], &piece[i + 1..]),
                None => (piece, &piece[..0]),
            };
            let key = decode_percent(k, true);
            let value = decode_percent(v, true);
            FieldShape {
                key: name(&key, markers, pair),
                value: text_value(&value, markers, pair),
            }
        })
        .collect()
}

fn json_shape(
    v: &serde_json::Value,
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> JsonShape {
    use serde_json::Value;
    // Depth is bounded by serde_json's own recursion limit (128) at parse time.
    match v {
        Value::Object(map) => JsonShape::Object {
            fields: map
                .iter()
                .map(|(k, v)| JsonField {
                    key: name(k.as_bytes(), markers, pair),
                    value: json_shape(v, markers, pair),
                })
                .collect(),
        },
        Value::Array(items) => JsonShape::Array {
            items: items.iter().map(|i| json_shape(i, markers, pair)).collect(),
        },
        Value::String(s) => JsonShape::Value {
            value: text_value(s.as_bytes(), markers, pair),
        },
        Value::Number(n) => {
            let text = Zeroizing::new(n.to_string());
            JsonShape::Value {
                value: value_shape(
                    ValueKind::Number,
                    char_len(text.as_bytes()),
                    text.as_bytes(),
                    markers,
                    pair,
                ),
            }
        }
        Value::Bool(b) => JsonShape::Value {
            value: value_shape(
                ValueKind::Bool,
                0,
                if *b { b"true" } else { b"false" },
                markers,
                pair,
            ),
        },
        Value::Null => JsonShape::Value {
            value: value_shape(ValueKind::Null, 0, b"null", markers, pair),
        },
    }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    memmem::find(&haystack[from..], needle).map(|i| from + i)
}

/// Parts of a `multipart/form-data` body, or `None` when it is not well formed (no opening
/// delimiter, a part with no header end, or a part not closed by a delimiter).
///
/// The line ending (CRLF or LF) is read once, from the first delimiter line, and used for every
/// part, so each search stops at its own terminator and the whole parse is linear in the body.
fn multipart_parts(
    body: &[u8],
    boundary: &str,
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> Option<Vec<FieldShape>> {
    let mut delim = b"--".to_vec();
    delim.extend_from_slice(boundary.as_bytes());

    let mut pos = find(body, &delim, 0)? + delim.len();
    let first_newline = pos + body[pos..].iter().position(|b| *b == b'\n')?;
    let eol: &[u8] = if first_newline > pos && body[first_newline - 1] == b'\r' {
        b"\r\n"
    } else {
        b"\n"
    };
    let blank_line = [eol, eol].concat();
    // The delimiter that closes a part is preceded by a line break.
    let closing = [eol, delim.as_slice()].concat();

    let mut parts = Vec::new();
    loop {
        if body[pos..].starts_with(b"--") {
            return Some(parts);
        }
        // Rest of the delimiter line (transport padding), then the headers.
        let headers_start = pos + body[pos..].iter().position(|b| *b == b'\n')? + 1;
        let headers_end = find(body, &blank_line, headers_start)?;
        let content_start = headers_end + blank_line.len();
        let headers = &body[headers_start..headers_end];
        // The line break that ends an empty content is the blank line's own.
        let content_end = find(body, &closing, content_start - eol.len())?;
        let content = body.get(content_start..content_end).unwrap_or(&[]);
        parts.push(part_shape(headers, content, markers, pair));
        pos = content_end + closing.len();
    }
}

fn part_shape(
    headers: &[u8],
    content: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> FieldShape {
    let mut part_name = Vec::new();
    let mut is_file = false;
    for line in headers.split(|b| *b == b'\n') {
        let line = String::from_utf8_lossy(line);
        let Some((header, rest)) = line.split_once(':') else {
            continue;
        };
        if !header.trim().eq_ignore_ascii_case("content-disposition") {
            continue;
        }
        for (key, value) in parameters(rest) {
            match key.as_str() {
                "name" => part_name = value.into_bytes(),
                "filename" | "filename*" => is_file = true,
                _ => {}
            }
        }
    }
    let value = if is_file {
        ValueShape {
            kind: ValueKind::File,
            len: byte_len(content),
            markers: Vec::new(),
        }
    } else {
        text_value(content, markers, pair)
    };
    FieldShape {
        key: name(&part_name, markers, pair),
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strip::{reduce_authorization, strip_url};
    use crate::testing::{assert_holds_no_typed_value, pw, user};
    use base64ct::{Base64, Encoding as B64};
    use kharon_recording::{Encoding, MarkerHit, Role};

    fn markers() -> Vec<Marker> {
        vec![user("kh.throwaway7"), pw("Tr0ub4dor-9x")]
    }
    fn hit(role: Role, encoding: Encoding) -> MarkerHit {
        MarkerHit {
            role,
            encoding,
            low_confidence: false,
        }
    }
    fn shape(ct: &str, body: &[u8]) -> BodyShape {
        shape_of_body(Some(ct), body, &markers(), None)
    }
    fn vs(kind: ValueKind, len: u32, markers: Vec<MarkerHit>) -> ValueShape {
        ValueShape { kind, len, markers }
    }
    fn field(key: &str, value: ValueShape) -> FieldShape {
        FieldShape {
            key: key.into(),
            value,
        }
    }
    fn leaf(value: ValueShape) -> JsonShape {
        JsonShape::Value { value }
    }
    fn jf(key: &str, value: JsonShape) -> JsonField {
        JsonField {
            key: key.into(),
            value,
        }
    }
    const URLENC: &str = "application/x-www-form-urlencoded";

    #[test]
    fn urlencoded_fields_with_roles() {
        let s = shape(
            URLENC,
            b"user=kh.throwaway7&password=Tr0ub4dor-9x&remember=1",
        );
        assert_eq!(
            s,
            BodyShape::Urlencoded {
                fields: vec![
                    field(
                        "user",
                        vs(
                            ValueKind::String,
                            13,
                            vec![hit(Role::Username, Encoding::AsTyped)]
                        )
                    ),
                    field(
                        "password",
                        vs(
                            ValueKind::String,
                            12,
                            vec![hit(Role::Password, Encoding::AsTyped)]
                        )
                    ),
                    field("remember", vs(ValueKind::String, 1, vec![])),
                ]
            }
        );
    }

    #[test]
    fn urlencoded_value_is_searched_after_decoding() {
        let s = shape(URLENC, b"password=Tr0ub4dor%2D9x&q=a+b%zz");
        let BodyShape::Urlencoded { fields } = s else {
            panic!("not urlencoded")
        };
        assert_eq!(
            fields[0].value.markers,
            [hit(Role::Password, Encoding::AsTyped)]
        );
        // "+" is a space; a lone "%zz" stays as typed: "a b%zz" is 6 characters.
        assert_eq!(fields[1].value.len, 6);
    }

    #[test]
    fn json_nested() {
        let s = shape(
            "Application/JSON; charset=utf-8",
            br#"{"auth":{"id":"kh.throwaway7","secret":"Tr0ub4dor-9x"},"n":3,"ok":true,"z":null}"#,
        );
        let BodyShape::Json { root } = s else {
            panic!("not json")
        };
        let JsonShape::Object { mut fields } = root else {
            panic!("not an object")
        };
        fields.sort_by(|a, b| a.key.cmp(&b.key));
        let want = vec![
            jf(
                "auth",
                JsonShape::Object {
                    fields: vec![
                        jf(
                            "id",
                            leaf(vs(
                                ValueKind::String,
                                13,
                                vec![hit(Role::Username, Encoding::AsTyped)],
                            )),
                        ),
                        jf(
                            "secret",
                            leaf(vs(
                                ValueKind::String,
                                12,
                                vec![hit(Role::Password, Encoding::AsTyped)],
                            )),
                        ),
                    ],
                },
            ),
            jf("n", leaf(vs(ValueKind::Number, 1, vec![]))),
            jf("ok", leaf(vs(ValueKind::Bool, 0, vec![]))),
            jf("z", leaf(vs(ValueKind::Null, 0, vec![]))),
        ];
        let JsonShape::Object { fields: mut inner } = fields[0].value.clone() else {
            panic!()
        };
        inner.sort_by(|a, b| a.key.cmp(&b.key));
        fields[0].value = JsonShape::Object { fields: inner };
        assert_eq!(fields, want);
    }

    #[test]
    fn json_arrays_and_scalars_and_plus_json() {
        let s = shape("application/vnd.api+json", br#"["Tr0ub4dor-9x", 12]"#);
        assert_eq!(
            s,
            BodyShape::Json {
                root: JsonShape::Array {
                    items: vec![
                        leaf(vs(
                            ValueKind::String,
                            12,
                            vec![hit(Role::Password, Encoding::AsTyped)]
                        )),
                        leaf(vs(ValueKind::Number, 2, vec![])),
                    ]
                }
            }
        );
    }

    #[test]
    fn a_json_number_holding_a_typed_value_is_a_hit() {
        let m = [pw("424242")];
        let s = shape_of_body(Some("application/json"), br#"{"pin":424242}"#, &m, None);
        let BodyShape::Json {
            root: JsonShape::Object { fields },
        } = s
        else {
            panic!()
        };
        assert_eq!(
            fields[0].value,
            leaf(vs(
                ValueKind::Number,
                6,
                vec![hit(Role::Password, Encoding::AsTyped)]
            ))
        );
    }

    #[test]
    fn graphql_is_json() {
        let s = shape(
            "application/json",
            br#"{"query":"mutation Login($password: String!) { login(password: $password) }","variables":{"password":"Tr0ub4dor-9x"}}"#,
        );
        let BodyShape::Json {
            root: JsonShape::Object { fields },
        } = s
        else {
            panic!()
        };
        let vars = fields.iter().find(|f| f.key == "variables").unwrap();
        let JsonShape::Object { fields: inner } = &vars.value else {
            panic!()
        };
        assert_eq!(inner[0].key, "password");
        assert_eq!(
            inner[0].value,
            leaf(vs(
                ValueKind::String,
                12,
                vec![hit(Role::Password, Encoding::AsTyped)]
            ))
        );
    }

    #[test]
    fn a_json_key_that_holds_a_typed_value_is_not_kept() {
        let s = shape(
            "application/json",
            br#"{"users":{"kh.throwaway7":{"secret":"Tr0ub4dor-9x"}}}"#,
        );
        let BodyShape::Json { root } = s else {
            panic!()
        };
        let text = serde_json::to_string(&root).unwrap();
        assert!(text.contains(r#""key":"{typed}""#), "{text}");
        assert!(text.contains(r#""key":"secret""#), "{text}");
        assert!(!text.contains("throwaway"), "{text}");
        assert!(text.contains("password"), "{text}");
    }

    #[test]
    fn multipart_text_and_file() {
        let body = b"--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nTr0ub4dor-9x\r\n--XyZ\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"\r\nContent-Type: image/png\r\n\r\nkh.throwaway7\r\n--XyZ--\r\n";
        let s = shape("multipart/form-data; boundary=XyZ", body);
        assert_eq!(
            s,
            BodyShape::Multipart {
                parts: vec![
                    field(
                        "password",
                        vs(
                            ValueKind::String,
                            12,
                            vec![hit(Role::Password, Encoding::AsTyped)]
                        )
                    ),
                    field("avatar", vs(ValueKind::File, 13, vec![])),
                ]
            }
        );
    }

    #[test]
    fn a_multipart_part_name_that_holds_a_typed_value_is_not_kept() {
        let body =
            b"--b\r\nContent-Disposition: form-data; name=\"kh.throwaway7\"\r\n\r\nx\r\n--b--";
        let s = shape("multipart/form-data; boundary=\"b\"", body);
        let BodyShape::Multipart { parts } = s else {
            panic!()
        };
        assert_eq!(parts[0].key, "{typed}");
    }

    #[test]
    fn urlencoded_key_that_holds_a_typed_value_is_not_kept() {
        let s = shape(URLENC, b"kh.throwaway7=1");
        let BodyShape::Urlencoded { fields } = s else {
            panic!()
        };
        assert_eq!(fields[0].key, "{typed}");
    }

    #[test]
    fn unknown_type_is_opaque_with_whole_body_hit() {
        let s = shape("application/octet-stream", b"xx Tr0ub4dor-9x yy");
        assert_eq!(
            s,
            BodyShape::Opaque {
                len: 18,
                markers: vec![hit(Role::Password, Encoding::AsTyped)]
            }
        );
        assert!(matches!(
            shape_of_body(None, b"a=b", &[], None),
            BodyShape::Opaque { len: 3, .. }
        ));
    }

    #[test]
    fn bad_json_falls_back_to_opaque() {
        assert!(matches!(
            shape("application/json", b"{not json"),
            BodyShape::Opaque { len: 9, .. }
        ));
        assert!(matches!(
            shape("application/json", b""),
            BodyShape::Opaque { len: 0, .. }
        ));
        assert_eq!(shape(URLENC, b""), BodyShape::Urlencoded { fields: vec![] });
    }

    #[test]
    fn a_combined_credential_lands_on_the_value_that_holds_it() {
        let b64 = Base64::encode_string(b"kh.throwaway7:Tr0ub4dor-9x");
        let body = format!(r#"{{"auth":"{b64}","n":1}}"#);
        let (u, p) = (user("kh.throwaway7"), pw("Tr0ub4dor-9x"));
        let with = shape_of_body(
            Some("application/json"),
            body.as_bytes(),
            &markers(),
            Some((&u, &p)),
        );
        let BodyShape::Json {
            root: JsonShape::Object { fields },
        } = with
        else {
            panic!()
        };
        let auth = fields.iter().find(|f| f.key == "auth").unwrap();
        assert_eq!(
            auth.value,
            leaf(vs(
                ValueKind::String,
                u32::try_from(b64.len()).unwrap(),
                vec![
                    hit(Role::Username, Encoding::Base64),
                    hit(Role::Password, Encoding::Base64)
                ]
            ))
        );
        let without = shape("application/json", body.as_bytes());
        let BodyShape::Json {
            root: JsonShape::Object { fields },
        } = without
        else {
            panic!()
        };
        let auth = fields.iter().find(|f| f.key == "auth").unwrap();
        let JsonShape::Value { value } = &auth.value else {
            panic!()
        };
        assert!(value.markers.is_empty());
    }

    #[test]
    fn an_opaque_body_holds_a_combined_credential_at_whole_body_level() {
        let b64 = Base64::encode_string(b"kh.throwaway7:Tr0ub4dor-9x");
        let (u, p) = (user("kh.throwaway7"), pw("Tr0ub4dor-9x"));
        let s = shape_of_body(None, b64.as_bytes(), &[], Some((&u, &p)));
        let BodyShape::Opaque { markers, .. } = s else {
            panic!()
        };
        assert_eq!(markers.len(), 2);
    }

    #[test]
    fn oversized_bodies_are_opaque() {
        let big = vec![b'a'; MAX_BODY_BYTES + 1];
        assert!(matches!(
            shape("application/json", &big),
            BodyShape::Opaque { .. }
        ));
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut nested = "[".repeat(200);
        nested.push_str(&"]".repeat(200));
        assert!(matches!(
            shape("application/json", nested.as_bytes()),
            BodyShape::Opaque { .. }
        ));
        for ct in [
            "multipart/form-data; boundary=XyZ",
            "multipart/form-data; boundary=",
            "multipart/form-data",
            "multipart/form-data; boundary=\"unterminated",
            URLENC,
            "application/json",
        ] {
            for body in [
                &b"--XyZ\r\nContent-Disposition: form-data; name=\"a"[..],
                b"--XyZ\r\n\r\n",
                b"--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue",
                b"--XyZ--",
                b"%",
                b"a=%&b=%4&c=%zz",
                b"\xff\xfe=\xc3\x28&\xf0\x9f",
                b"{\"a\":\"\xff\"}",
                b"",
            ] {
                let _ = shape(ct, body);
            }
        }
        let _ = strip_url("https://ex.test/%", &markers(), None);
        let _ = strip_url("https://ex.test/%zz?%=%&%ff", &markers(), None);
        let _ = strip_url("data:text/plain,Tr0ub4dor-9x", &markers(), None);
        let _ = reduce_authorization(b"Basic \xff\xfe", &markers(), None);
        let _ = reduce_authorization(b"", &markers(), None);
        let _ = reduce_authorization(b" ", &markers(), None);
    }

    #[test]
    fn a_site_cased_key_and_name_is_not_kept() {
        let m = [user("Bob.Smith@Ex.Test")];
        let s = shape_of_body(
            Some(URLENC),
            b"bob.smith%40ex.test=1&BOB.SMITH@EX.TEST=2",
            &m,
            None,
        );
        let BodyShape::Urlencoded { fields } = s else {
            panic!()
        };
        assert!(fields.iter().all(|f| f.key == "{typed}"));
        let s = shape_of_body(
            Some("application/json"),
            br#"{"bob.smith@ex.test":1}"#,
            &m,
            None,
        );
        let BodyShape::Json {
            root: JsonShape::Object { fields },
        } = s
        else {
            panic!()
        };
        assert_eq!(fields[0].key, "{typed}");
        let body =
            b"--b\r\nContent-Disposition: form-data; name=\"BOB.smith@ex.test\"\r\n\r\nx\r\n--b--";
        let s = shape_of_body(Some("multipart/form-data; boundary=b"), body, &m, None);
        let BodyShape::Multipart { parts } = s else {
            panic!()
        };
        assert_eq!(parts[0].key, "{typed}");
    }

    #[test]
    fn a_name_holding_the_combined_credential_is_not_kept() {
        let b64 = Base64::encode_string(b"kh.throwaway7:Tr0ub4dor-9x");
        let (u, p) = (user("kh.throwaway7"), pw("Tr0ub4dor-9x"));
        let body = format!("{b64}=1");
        let s = shape_of_body(Some(URLENC), body.as_bytes(), &[], Some((&u, &p)));
        let BodyShape::Urlencoded { fields } = s else {
            panic!()
        };
        assert_eq!(fields[0].key, "{typed}");
    }

    #[test]
    fn many_crlf_parts_are_read_in_linear_time() {
        let mut body = Vec::new();
        for i in 0..5000 {
            body.extend_from_slice(
                format!("--b\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nv\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(b"--b--\r\n");
        let s = shape("multipart/form-data; boundary=b", &body);
        let BodyShape::Multipart { parts } = s else {
            panic!("not multipart")
        };
        assert_eq!(parts.len(), 5000);
        // LF-only bodies too.
        let lf = String::from_utf8_lossy(&body).replace("\r\n", "\n");
        let s = shape("multipart/form-data; boundary=b", lf.as_bytes());
        let BodyShape::Multipart { parts } = s else {
            panic!("not multipart")
        };
        assert_eq!(parts.len(), 5000);
    }

    #[test]
    fn serialized_shapes_never_contain_a_marker() {
        let b64 = Base64::encode_string(b"kh.throwaway7:Tr0ub4dor-9x");
        let values = [
            "kh.throwaway7",
            "Tr0ub4dor-9x",
            "Tr0ub4/dor",
            "Bob.Smith@Ex.Test",
        ];
        let m: Vec<Marker> = vec![
            user(values[0]),
            pw(values[1]),
            pw(values[2]),
            user(values[3]),
        ];
        let (u, p) = (user(values[0]), pw(values[1]));
        let pair = Some((&u, &p));
        let json_pair = format!(r#"{{"auth":"{b64}","n":1}}"#);
        let multipart = b"--XyZ\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nTr0ub4dor-9x\r\n--XyZ\r\nContent-Disposition: form-data; name=\"kh.throwaway7\"; filename=\"kh.throwaway7\"\r\n\r\nkh.throwaway7\r\n--XyZ\r\nContent-Disposition: form-data; name=\"bob.smith@ex.test\"\r\n\r\nTr0ub4/dor\r\n--XyZ--\r\n";
        let body = |ct: &str, bytes: &[u8]| shape_of_body(Some(ct), bytes, &m, pair);
        let bodies: Vec<BodyShape> =
            vec![
            body(URLENC, b"user=kh.throwaway7&password=Tr0ub4dor-9x&remember=1"),
            body(URLENC, b"password=Tr0ub4dor%2D9x&kh.throwaway7=1&p=Tr0ub4%2Fdor"),
            body(URLENC, b"bob.smith%40ex.test=1&BOB.SMITH@EX.TEST=2"),
            body(URLENC, format!("{b64}=1").as_bytes()),
            body(
                "application/json",
                br#"{"auth":{"id":"kh.throwaway7","secret":"Tr0ub4dor-9x"},"n":3}"#,
            ),
            body(
                "application/json",
                br#"{"query":"x","variables":{"password":"Tr0ub4dor-9x"}}"#,
            ),
            body(
                "application/json",
                br#"{"users":{"kh.throwaway7":{"secret":"Tr0ub4dor-9x"},"bob.smith@ex.test":1}}"#,
            ),
            body("application/json", json_pair.as_bytes()),
            body("application/json", b"{Tr0ub4dor-9x"),
            body("multipart/form-data; boundary=XyZ", multipart),
            body("application/octet-stream", b"Tr0ub4dor-9x kh.throwaway7"),
        ];
        let mut outputs: Vec<String> = bodies
            .iter()
            .map(|b| serde_json::to_string(b).unwrap())
            .collect();
        let urls = [
            "https://kh.throwaway7.ex.test/login",
            "https://Bob.Smith@Ex.Test.ex.test/login",
            "https://a.kh.throwaway7.ex.kh.throwaway7.test/",
            "https://ex.test/u/kh.throwaway7/dash?kh.throwaway7=1&password=Tr0ub4dor-9x",
            "https://ex.test/u/kh%2Ethrow%61way7/x?kh%2Ethrowaway7=1",
            "https://ex.test/Tr0ub4dor-9x?x=Tr0ub4dor-9x#Tr0ub4dor-9x",
            "https://kh.throwaway7:Tr0ub4dor-9x@ex.test/",
            "https://ex.test/a/Tr0ub4/dor/z",
            "https://ex.test/a/Tr0ub4%2Fdor/z?Tr0ub4%2Fdor=1",
            "https://ex.test/u/bob.smith@ex.test/x?BOB.SMITH%40EX.TEST=1",
            "data:text/plain,Tr0ub4dor-9x,kh.throwaway7",
            "kh.throwaway7://ex.test/",
        ];
        for url in urls {
            let s = strip_url(url, &m, pair).unwrap();
            outputs.push(serde_json::to_string(&s.value).unwrap());
        }
        let in_path = format!("https://ex.test/{b64}/x?{b64}=1");
        outputs
            .push(serde_json::to_string(&strip_url(&in_path, &[], pair).unwrap().value).unwrap());
        for header in [
            format!("Basic {b64}"),
            "Bearer Tr0ub4dor-9x".to_owned(),
            "Tr0ub4dor-9x".to_owned(),
            "kh.throwaway7".to_owned(),
            "Basic Tr0ub4dor-9x".to_owned(),
        ] {
            let a = reduce_authorization(header.as_bytes(), &m, pair);
            outputs.push(serde_json::to_string(&a).unwrap());
        }
        for text in outputs {
            assert_holds_no_typed_value(&text, &values);
        }
    }
}
