//! Stripping: a URL or an `Authorization` header reduced to structure only.
//!
//! Everything this module KEEPS (origin, path, query keys, scheme) is tested for typed values as a
//! whole string, never piece by piece, and with ASCII letter case ignored, because a site may
//! lowercase what was typed and a typed value may itself hold a separator.

use std::ops::Range;

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding as B64};
use kharon_recording::{AuthShape, Encoding, MarkerHit, StrippedUrl};
use percent_encoding::percent_decode;
use url::Url;
use zeroize::Zeroizing;

use crate::marker::{Marker, search, search_pair};

/// Written in place of a name (key, part name, host labels) that held a typed value.
pub const TYPED: &str = "{typed}";
/// Written in place of a path segment that is an identifier or held a typed value.
pub const ID: &str = "{id}";
const OTHER: &str = "{other}";

/// URL schemes that are kept; any other is written `{other}`.
const URL_SCHEMES: [&str; 11] = [
    "http",
    "https",
    "ws",
    "wss",
    "data",
    "blob",
    "about",
    "file",
    "chrome",
    "chrome-extension",
    "devtools",
];

/// Authorization schemes that are kept (compared lowercased); any other is written `{other}`.
const AUTH_SCHEMES: [&str; 12] = [
    "basic",
    "bearer",
    "digest",
    "negotiate",
    "ntlm",
    "hoba",
    "mutual",
    "token",
    "apikey",
    "oauth",
    "hawk",
    "aws4-hmac-sha256",
];

pub struct Stripped<T> {
    pub value: T,
    pub query_values_removed: u64,
    pub path_segments_replaced: u64,
}

/// Every hit of every marker in `haystack`, plus the pair, without repeats of (role, encoding).
pub(crate) fn hits_in(
    haystack: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> Vec<MarkerHit> {
    let mut out = Vec::new();
    for m in markers {
        out.extend(search(haystack, m));
    }
    if let Some((u, p)) = pair {
        out.extend(search_pair(haystack, u, p));
    }
    dedup_hits(out)
}

/// One hit per (role, encoding), in first-seen order. When two share a key the result is
/// `low_confidence: false` if either is.
pub(crate) fn dedup_hits(hits: Vec<MarkerHit>) -> Vec<MarkerHit> {
    let mut out: Vec<MarkerHit> = Vec::with_capacity(hits.len());
    for h in hits {
        match out
            .iter_mut()
            .find(|k| k.role == h.role && k.encoding == h.encoding)
        {
            Some(known) => known.low_confidence &= h.low_confidence,
            None => out.push(h),
        }
    }
    out
}

/// Whether any marker (or the pair) occurs in `haystack` under any encoding.
pub(crate) fn any_hit(
    haystack: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> bool {
    !hits_in(haystack, markers, pair).is_empty()
}

/// Percent-decodes `raw`, with `+` as a space first when `plus_is_space`. A lone `%` stays.
pub(crate) fn decode_percent(raw: &[u8], plus_is_space: bool) -> Zeroizing<Vec<u8>> {
    if plus_is_space {
        let spaced: Zeroizing<Vec<u8>> = Zeroizing::new(
            raw.iter()
                .map(|b| if *b == b'+' { b' ' } else { *b })
                .collect(),
        );
        return Zeroizing::new(percent_decode(&spaced).collect());
    }
    Zeroizing::new(percent_decode(raw).collect())
}

/// `bytes` as text of the SAME byte length: every invalid UTF-8 byte becomes `?`, so byte
/// offsets in the text are offsets in `bytes`.
fn text_same_len(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len()));
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(std::iter::repeat_n('?', chunk.invalid().len()));
    }
    out
}

/// Byte ranges of every occurrence (overlapping ones too) of every marker in `text`, ignoring
/// ASCII letter case.
fn occurrences(text: &str, markers: &[Marker]) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    for m in markers {
        let mut from = 0;
        while let Some(r) = text
            .get(from..)
            .and_then(|rest| m.find_ignore_ascii_case(rest))
        {
            let (start, end) = (from + r.start, from + r.end);
            out.push(start..end);
            // Resume one character after the start so overlapping occurrences are found.
            from = start + text[start..].chars().next().map_or(1, char::len_utf8);
        }
    }
    out
}

/// For each span, whether any range overlaps it.
fn touched(ranges: &[Range<usize>], spans: &[Range<usize>]) -> Vec<bool> {
    spans
        .iter()
        .map(|s| ranges.iter().any(|r| r.start < s.end && r.end > s.start))
        .collect()
}

/// Whether kept text `bytes` holds a typed value: `search` finds any hit (any encoding, the pair
/// too), or the value occurs ignoring ASCII case in the text or in its percent-decoded forms.
pub(crate) fn holds_typed(
    bytes: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> bool {
    if any_hit(bytes, markers, pair) || !occurrences(&text_same_len(bytes), markers).is_empty() {
        return true;
    }
    [false, true].into_iter().any(|plus| {
        let decoded = decode_percent(bytes, plus);
        decoded.as_slice() != bytes && !occurrences(&text_same_len(&decoded), markers).is_empty()
    })
}

/// Origin, path and query keys of `url`. A path segment becomes "{id}" when it is all ASCII digits,
/// a UUID, 16 or more hex characters, or any match of a marker (see below) touches it.
///
/// Userinfo and fragment are dropped. A query key or host label holding a typed value is written
/// as "{typed}". Matching is over the WHOLE path, query and host (raw and percent-decoded, ASCII
/// case ignored; the path also with `/` read as `\`, which the parser rewrites), and every
/// segment, key or label a match touches is replaced, so a typed value holding a separator
/// leaves no piece behind. A combined credential (`pair`) found in a segment or key replaces it.
///
/// A URL that cannot be a base (`data:`, `blob:`, `about:`, `mailto:`) keeps only its scheme.
/// The scheme is kept only when it is in a short known list, else it is `{other}`.
/// Known limits: an internationalised host is compared in its punycode form, so a non-ASCII
/// typed value inside such a label is not recognised; the port is not tested.
pub fn strip_url(
    url: &str,
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> Option<Stripped<StrippedUrl>> {
    let parsed = Url::parse(url).ok()?;
    let scheme = if URL_SCHEMES.contains(&parsed.scheme()) {
        parsed.scheme()
    } else {
        OTHER
    };
    if parsed.cannot_be_a_base() {
        return Some(Stripped {
            value: StrippedUrl {
                origin: format!("{scheme}:"),
                path: String::new(),
                query_keys: Vec::new(),
            },
            query_values_removed: 0,
            path_segments_replaced: 0,
        });
    }
    let origin = match parsed.host_str() {
        Some(host) => {
            let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{scheme}://{}{port}", strip_host(host, markers))
        }
        None => format!("{scheme}:"),
    };
    let (path, path_segments_replaced) = strip_path(parsed.path(), markers, pair);
    let (query_keys, query_values_removed) =
        strip_query(parsed.query().unwrap_or(""), markers, pair);
    Some(Stripped {
        value: StrippedUrl {
            origin,
            path,
            query_keys,
        },
        query_values_removed,
        path_segments_replaced,
    })
}

/// Replaces host labels that hold a typed value. Every occurrence of every marker is located
/// (ASCII case-insensitively: the parser lowercases hosts) and every label the occurrence touches is
/// replaced. Adjacent replaced labels become ONE `{typed}` label, so a value that spans labels
/// (`kh.throwaway7`) leaves no part of itself behind.
fn strip_host(host: &str, markers: &[Marker]) -> String {
    let ranges = occurrences(host, markers);
    let mut spans = Vec::new();
    let mut offset = 0;
    for label in host.split('.') {
        spans.push(offset..offset + label.len());
        offset += label.len() + 1;
    }
    let typed = touched(&ranges, &spans);
    let mut labels: Vec<&str> = Vec::new();
    let mut previous_typed = false;
    for (label, is_typed) in host.split('.').zip(typed) {
        if is_typed {
            if !previous_typed {
                labels.push(TYPED);
            }
        } else {
            labels.push(label);
        }
        previous_typed = is_typed;
    }
    labels.join(".")
}

/// Segments of `path` are replaced when they look like an identifier or a match touches them.
fn strip_path(path: &str, markers: &[Marker], pair: Option<(&Marker, &Marker)>) -> (String, u64) {
    let segments: Vec<&str> = path.split('/').collect();
    let decoded: Vec<Zeroizing<Vec<u8>>> = segments
        .iter()
        .map(|s| decode_percent(s.as_bytes(), false))
        .collect();
    let decoded_text: Vec<Zeroizing<String>> = decoded.iter().map(|d| text_same_len(d)).collect();

    let spans_of = |lens: Vec<usize>| -> Vec<Range<usize>> {
        let mut offset = 0;
        lens.into_iter()
            .map(|len| {
                let span = offset..offset + len;
                offset += len + 1;
                span
            })
            .collect()
    };
    let raw_spans = spans_of(segments.iter().map(|s| s.len()).collect());
    let decoded_spans = spans_of(decoded_text.iter().map(|t| t.len()).collect());
    let mut decoded_path = Zeroizing::new(String::with_capacity(path.len()));
    for (i, t) in decoded_text.iter().enumerate() {
        if i > 0 {
            decoded_path.push('/');
        }
        decoded_path.push_str(t);
    }

    // The raw and decoded whole path, each also with `/` read as `\` (same byte length, so the
    // same spans apply).
    let mut typed = vec![false; segments.len()];
    for (text, spans) in [(path, &raw_spans), (decoded_path.as_str(), &decoded_spans)] {
        let backslashed = Zeroizing::new(text.replace('/', "\\"));
        for variant in [text, backslashed.as_str()] {
            let hit = touched(&occurrences(variant, markers), spans);
            typed.iter_mut().zip(hit).for_each(|(t, h)| *t |= h);
        }
    }
    for (i, seg) in segments.iter().enumerate() {
        typed[i] |= any_hit(seg.as_bytes(), markers, pair) || any_hit(&decoded[i], markers, pair);
    }
    // A hit over the whole path that no segment explains (an encoded value that spans a `/`):
    // every non-empty segment goes.
    if !typed.iter().any(|t| *t)
        && (any_hit(path.as_bytes(), markers, pair)
            || any_hit(decoded_path.as_bytes(), markers, pair))
    {
        typed = segments.iter().map(|s| !s.is_empty()).collect();
    }

    let mut replaced = 0u64;
    let kept: Vec<&str> = segments
        .iter()
        .zip(typed)
        .map(|(seg, is_typed)| {
            if is_typed || segment_is_id(seg) {
                replaced += 1;
                ID
            } else {
                seg
            }
        })
        .collect();
    (kept.join("/"), replaced)
}

fn segment_is_id(seg: &str) -> bool {
    !seg.is_empty()
        && (seg.bytes().all(|b| b.is_ascii_digit())
            || (seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit()))
            || is_uuid(seg))
}

fn is_uuid(seg: &str) -> bool {
    let b = seg.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Query keys, in order, with a key a match touches written `{typed}`. The raw query string and a
/// decoded copy (`+` as space, `%XX`) are each searched whole; a match touching a key's bytes
/// (separators included) marks the key. A match inside a value alone costs nothing.
fn strip_query(
    query: &str,
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> (Vec<String>, u64) {
    struct Piece<'a> {
        raw_key: &'a str,
        raw_span: Range<usize>,
        key: Zeroizing<Vec<u8>>,
        decoded_span: Range<usize>,
    }
    let mut pieces: Vec<Piece> = Vec::new();
    let mut decoded_query = Zeroizing::new(String::with_capacity(query.len()));
    let mut offset = 0;
    for piece in query.split('&') {
        let start = offset;
        offset += piece.len() + 1;
        if piece.is_empty() {
            continue;
        }
        let (raw_key, value) = match piece.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (piece, None),
        };
        let key = decode_percent(raw_key.as_bytes(), true);
        let key_text = text_same_len(&key);
        if !decoded_query.is_empty() {
            decoded_query.push('&');
        }
        let decoded_start = decoded_query.len();
        decoded_query.push_str(&key_text);
        let decoded_span = decoded_start..decoded_query.len();
        if let Some(v) = value {
            decoded_query.push('=');
            decoded_query.push_str(&text_same_len(&decode_percent(v.as_bytes(), true)));
        }
        pieces.push(Piece {
            raw_key,
            raw_span: start..start + raw_key.len(),
            key,
            decoded_span,
        });
    }
    let raw_spans: Vec<Range<usize>> = pieces.iter().map(|p| p.raw_span.clone()).collect();
    let decoded_spans: Vec<Range<usize>> = pieces.iter().map(|p| p.decoded_span.clone()).collect();
    let by_raw = touched(&occurrences(query, markers), &raw_spans);
    let by_decoded = touched(&occurrences(&decoded_query, markers), &decoded_spans);
    let keys = pieces
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if by_raw[i]
                || by_decoded[i]
                || any_hit(p.raw_key.as_bytes(), markers, pair)
                || any_hit(&p.key, markers, pair)
            {
                TYPED.to_owned()
            } else {
                String::from_utf8_lossy(&p.key).into_owned()
            }
        })
        .collect();
    (keys, u64::try_from(pieces.len()).unwrap_or(u64::MAX))
}

/// scheme = first token, lowercased. For `basic`, the credentials are base64-decoded and the decoded bytes
/// are searched; a marker found there is reported with `Encoding::Base64`. Other schemes are searched as sent.
/// When `pair` is given the value is also searched with `search_pair`. No (role, encoding) is listed twice.
///
/// The value as sent is always searched too. The scheme is kept only when it is one of a short
/// known list (`AUTH_SCHEMES`); a scheme holding a typed value is `{typed}`; anything else,
/// including a header with no space (a bare credential), is `{other}`.
pub fn reduce_authorization(
    header_value: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> AuthShape {
    let (scheme_bytes, credentials) = match header_value.iter().position(|b| *b == b' ') {
        Some(i) => (&header_value[..i], &header_value[i + 1..]),
        None => (header_value, &header_value[..0]),
    };
    let has_credentials = scheme_bytes.len() < header_value.len();
    let mut hits = hits_in(header_value, markers, pair);

    let scheme_lower = scheme_bytes.to_ascii_lowercase();
    if scheme_lower == b"basic"
        && let Some(decoded) = decode_basic(credentials)
    {
        let decoded_hits = hits_in(&decoded, markers, None);
        hits.extend(decoded_hits.into_iter().map(|h| MarkerHit {
            encoding: Encoding::Base64,
            ..h
        }));
    }

    let known = std::str::from_utf8(&scheme_lower)
        .ok()
        .filter(|s| has_credentials && AUTH_SCHEMES.contains(s));
    let scheme = if holds_typed(scheme_bytes, markers, pair) {
        TYPED.to_owned()
    } else {
        known.map_or_else(|| OTHER.to_owned(), str::to_owned)
    };

    AuthShape {
        scheme,
        markers: dedup_hits(hits),
    }
}

/// The decoded `user:password` bytes, or `None` when the credentials are not base64.
fn decode_basic(credentials: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(credentials).ok()?.trim();
    type Decoder = fn(&str) -> Option<Vec<u8>>;
    let decoders: [Decoder; 4] = [
        |t| Base64::decode_vec(t).ok(),
        |t| Base64Unpadded::decode_vec(t).ok(),
        |t| Base64Url::decode_vec(t).ok(),
        |t| Base64UrlUnpadded::decode_vec(t).ok(),
    ];
    decoders
        .iter()
        .find_map(|decode| decode(text))
        .map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{assert_holds_no_typed_value, pw, user};
    use kharon_recording::Role;

    fn hit(role: Role, encoding: Encoding) -> MarkerHit {
        MarkerHit {
            role,
            encoding,
            low_confidence: false,
        }
    }

    #[test]
    fn keeps_origin_path_and_query_keys() {
        let s = strip_url(
            "https://ex.test/login/step?next=%2Fhome&lang=en#frag",
            &[],
            None,
        )
        .unwrap();
        assert_eq!(
            s.value,
            StrippedUrl {
                origin: "https://ex.test".into(),
                path: "/login/step".into(),
                query_keys: vec!["next".into(), "lang".into()]
            }
        );
        assert_eq!(s.query_values_removed, 2);
        assert_eq!(s.path_segments_replaced, 0);
    }

    #[test]
    fn origin_has_no_userinfo_keeps_a_port_and_duplicate_keys() {
        let s = strip_url("http://bob:s3cret@ex.test:8080/a?k=1&k=2", &[], None).unwrap();
        assert_eq!(s.value.origin, "http://ex.test:8080");
        assert_eq!(s.value.query_keys, ["k", "k"]);
    }

    #[test]
    fn replaces_id_like_segments() {
        for (path, want, n) in [
            ("/users/12345/home", "/users/{id}/home", 1),
            ("/s/3f2b8c1e-9a4d-4c1b-8e2f-0a1b2c3d4e5f", "/s/{id}", 1),
            ("/s/3F2B8C1E-9A4D-4C1B-8E2F-0A1B2C3D4E5F", "/s/{id}", 1),
            ("/t/0123456789abcdef0123", "/t/{id}", 1),
            ("/v2/login", "/v2/login", 0),
            ("/a/b/", "/a/b/", 0),
        ] {
            let s = strip_url(&format!("https://ex.test{path}"), &[], None).unwrap();
            assert_eq!(s.value.path, want);
            assert_eq!(s.path_segments_replaced, n);
        }
    }

    #[test]
    fn replaces_a_segment_that_contains_a_marker() {
        let m = [user("kh.throwaway7")];
        let s = strip_url("https://ex.test/u/kh.throwaway7/dash", &m, None).unwrap();
        assert_eq!(s.value.path, "/u/{id}/dash");
        let s = strip_url("https://ex.test/u/kh%2Ethrow%61way7/dash", &m, None).unwrap();
        assert_eq!(s.value.path, "/u/{id}/dash");
        assert_eq!(s.path_segments_replaced, 1);
    }

    #[test]
    fn unparseable_url_is_none() {
        assert!(strip_url("not a url", &[], None).is_none());
    }

    #[test]
    fn a_query_key_that_holds_a_typed_value_is_not_kept() {
        let m = [user("kh.throwaway7")];
        let s = strip_url("https://ex.test/x?kh.throwaway7=1&ok=2", &m, None).unwrap();
        assert_eq!(s.value.query_keys, ["{typed}", "ok"]);
        let s = strip_url("https://ex.test/x?kh%2Ethrowaway7=1", &m, None).unwrap();
        assert_eq!(s.value.query_keys, ["{typed}"]);
    }

    #[test]
    fn a_host_label_that_holds_a_typed_value_is_replaced() {
        let m = [user("kh.throwaway7")];
        // The value spans two labels: the whole run of labels the match covers is one `{typed}`.
        let s = strip_url("https://kh.throwaway7.ex.test/login", &m, None).unwrap();
        assert_eq!(s.value.origin, "https://{typed}.ex.test");
        // Case-insensitive, and a partial label is replaced whole.
        let m = [user("Kh.Throwaway7")];
        let s = strip_url("https://x-kh.throwaway7-y.ex.test:81/", &m, None).unwrap();
        assert_eq!(s.value.origin, "https://{typed}.ex.test:81");
        // Every occurrence.
        let m = [user("bob12")];
        let s = strip_url("https://bob12.ex.bob12.test/", &m, None).unwrap();
        assert_eq!(s.value.origin, "https://{typed}.ex.{typed}.test");
    }

    #[test]
    fn basic_auth_is_reduced_to_scheme_and_hits() {
        let b64 = Base64::encode_string(b"kh.throwaway7:Tr0ub4dor-9x");
        let a = reduce_authorization(
            format!("Basic {b64}").as_bytes(),
            &[user("kh.throwaway7"), pw("Tr0ub4dor-9x")],
            None,
        );
        assert_eq!(a.scheme, "basic");
        assert_eq!(
            a.markers,
            [
                hit(Role::Username, Encoding::Base64),
                hit(Role::Password, Encoding::Base64)
            ]
        );
    }

    #[test]
    fn basic_auth_with_the_pair_lists_each_hit_once() {
        let b64 = Base64::encode_string(b"kh.throwaway7:Tr0ub4dor-9x");
        let (u, p) = (user("kh.throwaway7"), pw("Tr0ub4dor-9x"));
        let a = reduce_authorization(
            format!("Basic {b64}").as_bytes(),
            &[user("kh.throwaway7"), pw("Tr0ub4dor-9x")],
            Some((&u, &p)),
        );
        assert_eq!(
            a.markers,
            [
                hit(Role::Username, Encoding::Base64),
                hit(Role::Password, Encoding::Base64)
            ]
        );
    }

    #[test]
    fn bearer_keeps_no_token() {
        let a = reduce_authorization(
            b"Bearer eyJhbGciOiJIUzI1NiJ9.abc.def",
            &[pw("Tr0ub4dor-9x")],
            None,
        );
        assert_eq!(
            a,
            AuthShape {
                scheme: "bearer".into(),
                markers: vec![]
            }
        );
        assert!(!serde_json::to_string(&a).unwrap().contains("eyJ"));
    }

    #[test]
    fn a_typed_password_sent_as_a_bearer_token_is_a_hit() {
        let a = reduce_authorization(b"Bearer Tr0ub4dor-9x", &[pw("Tr0ub4dor-9x")], None);
        assert_eq!(a.markers, [hit(Role::Password, Encoding::AsTyped)]);
    }

    #[test]
    fn no_space_is_a_scheme_with_no_credentials() {
        let a = reduce_authorization(b"Negotiate", &[], None);
        assert_eq!(
            a,
            AuthShape {
                scheme: "{other}".into(),
                markers: vec![]
            }
        );
        // A bare typed value never becomes the scheme.
        let a = reduce_authorization(b"Tr0ub4dor-9x", &[pw("Tr0ub4dor-9x")], None);
        assert_eq!(a.scheme, "{typed}");
        assert_eq!(a.markers, [hit(Role::Password, Encoding::AsTyped)]);
        // Nor does anything that is not a plain token.
        let a = reduce_authorization(b"s3cr3t/token+value=", &[], None);
        assert_eq!(a.scheme, "{other}");
    }

    #[test]
    fn malformed_basic_has_no_markers_but_is_searched_as_sent() {
        let a = reduce_authorization(b"Basic !!!not-base64!!!", &[pw("Tr0ub4dor-9x")], None);
        assert_eq!(
            a,
            AuthShape {
                scheme: "basic".into(),
                markers: vec![]
            }
        );
        let a = reduce_authorization(b"Basic Tr0ub4dor-9x", &[pw("Tr0ub4dor-9x")], None);
        assert_eq!(a.markers, [hit(Role::Password, Encoding::AsTyped)]);
    }

    #[test]
    fn a_typed_value_holding_a_slash_is_not_kept_in_the_path() {
        let m = [pw("Tr0ub4/dor")];
        let s = strip_url("https://ex.test/a/Tr0ub4/dor", &m, None).unwrap();
        assert_eq!(s.value.path, "/a/{id}/{id}");
        assert_eq!(s.path_segments_replaced, 2);
        let s = strip_url("https://ex.test/a/Tr0ub4%2Fdor/z", &m, None).unwrap();
        assert_eq!(s.value.path, "/a/{id}/z");
        // The parser rewrites a backslash in the path to a slash.
        let m = [pw("Tr0ub4\\dor")];
        let s = strip_url("https://ex.test/a/Tr0ub4\\dor/z", &m, None).unwrap();
        assert_eq!(s.value.path, "/a/{id}/{id}/z");
    }

    #[test]
    fn a_site_cased_value_is_not_kept_in_the_path_or_query() {
        let m = [user("Bob.Smith@Ex.Test")];
        let s = strip_url(
            "https://ex.test/u/bob.smith@ex.test/x?BOB.SMITH%40EX.TEST=1&ok=2",
            &m,
            None,
        )
        .unwrap();
        assert_eq!(s.value.path, "/u/{id}/x");
        assert_eq!(s.value.query_keys, ["{typed}", "ok"]);
    }

    #[test]
    fn a_separator_inside_a_typed_value_does_not_leave_a_key() {
        let m = [pw("pa&ss")];
        let s = strip_url("https://ex.test/x?a=pa&ss=1&b=2", &m, None).unwrap();
        assert_eq!(s.value.query_keys, ["a", "{typed}", "b"]);
        let m = [pw("pa=ss")];
        let s = strip_url("https://ex.test/x?pa=ss&b=2", &m, None).unwrap();
        assert_eq!(s.value.query_keys, ["{typed}", "b"]);
        // A typed value sitting in a query VALUE does not cost its key.
        let m = [pw("Tr0ub4dor-9x")];
        let s = strip_url("https://ex.test/x?p=Tr0ub4dor-9x", &m, None).unwrap();
        assert_eq!(s.value.query_keys, ["p"]);
    }

    #[test]
    fn the_combined_credential_in_a_path_or_key_is_not_kept() {
        let b64 = Base64::encode_string(b"kh.throwaway7:Tr0ub4dor-9x");
        let (u, p) = (user("kh.throwaway7"), pw("Tr0ub4dor-9x"));
        let s = strip_url(&format!("https://ex.test/a/{b64}/z"), &[], Some((&u, &p))).unwrap();
        assert!(s.path_segments_replaced >= 1);
        assert_holds_no_typed_value(&s.value.path, &["kh.throwaway7:Tr0ub4dor-9x"]);
        let url = format!("https://ex.test/a?{}=1", b64.trim_end_matches('='));
        let s = strip_url(&url, &[], Some((&u, &p))).unwrap();
        assert_eq!(s.value.query_keys, ["{typed}"]);
    }

    #[test]
    fn a_url_that_cannot_be_a_base_keeps_only_its_scheme() {
        for (url, origin) in [
            ("data:text/plain,Tr0ub4dor-9x", "data:"),
            ("blob:https://ex.test/3f2b", "blob:"),
            ("about:blank", "about:"),
            ("mailto:a@b.test?subject=x", "{other}:"),
        ] {
            let s = strip_url(url, &[], None).unwrap();
            assert_eq!(
                s.value,
                StrippedUrl {
                    origin: origin.into(),
                    path: String::new(),
                    query_keys: vec![]
                }
            );
        }
    }

    #[test]
    fn an_unknown_url_scheme_is_other() {
        let s = strip_url("kh.throwaway7://ex.test/x", &[user("kh.throwaway7")], None).unwrap();
        assert_eq!(s.value.origin, "{other}://ex.test");
        let s = strip_url("chrome-extension://abc/x", &[], None).unwrap();
        assert_eq!(s.value.origin, "chrome-extension://abc");
    }

    #[test]
    fn only_a_known_authorization_scheme_is_kept() {
        for (header, want) in [
            (&b"Digest username=x"[..], "digest"),
            (b"AWS4-HMAC-SHA256 Credential=x", "aws4-hmac-sha256"),
            (b"Negotiate abc", "negotiate"),
            (b"s3cr3t-session-token-0123456789 x", "{other}"),
            (b"s3cr3t-session-token-0123456789", "{other}"),
            (b"Tr0ub4dor-9x", "{typed}"),
            (b"Tr0ub4dor-9x rest", "{typed}"),
        ] {
            let a = reduce_authorization(header, &[pw("Tr0ub4dor-9x")], None);
            assert_eq!(a.scheme, want);
        }
    }

    #[test]
    fn a_confident_duplicate_wins_over_a_low_confidence_one() {
        let h = |low| MarkerHit {
            role: Role::Password,
            encoding: Encoding::AsTyped,
            low_confidence: low,
        };
        assert_eq!(dedup_hits(vec![h(true), h(false)]), [h(false)]);
        assert_eq!(dedup_hits(vec![h(false), h(true)]), [h(false)]);
    }
}
