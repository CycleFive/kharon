//! Stripping: a URL or an `Authorization` header reduced to structure only.

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

/// Keeps the first hit for each (role, encoding).
pub(crate) fn dedup_hits(hits: Vec<MarkerHit>) -> Vec<MarkerHit> {
    let mut out: Vec<MarkerHit> = Vec::with_capacity(hits.len());
    for h in hits {
        if !out
            .iter()
            .any(|k| k.role == h.role && k.encoding == h.encoding)
        {
            out.push(h);
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

/// Origin, path and query keys of `url`. A path segment becomes "{id}" when it is all ASCII digits,
/// a UUID, 16 or more hex characters, or contains any marker (as typed or percent-encoded).
///
/// Userinfo and fragment are dropped. A query key or host label holding a typed value is written
/// as "{typed}". Known limit: an internationalised host is compared in its punycode form, so a
/// non-ASCII typed value inside such a label is not recognised.
pub fn strip_url(url: &str, markers: &[Marker]) -> Option<Stripped<StrippedUrl>> {
    let parsed = Url::parse(url).ok()?;
    let mut path_segments_replaced = 0u64;

    let origin = match parsed.host_str() {
        Some(host) => {
            let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!(
                "{}://{}{}",
                parsed.scheme(),
                strip_host(host, markers),
                port
            )
        }
        None => format!("{}:", parsed.scheme()),
    };

    let path = if parsed.cannot_be_a_base() {
        // Opaque path (`data:`, `mailto:` ...): it is a payload, not a route.
        path_segments_replaced += 1;
        ID.to_owned()
    } else {
        let mut owned: Vec<String> = Vec::new();
        for seg in parsed.path().split('/') {
            if segment_is_id(seg, markers) {
                path_segments_replaced += 1;
                owned.push(ID.to_owned());
            } else {
                owned.push(seg.to_owned());
            }
        }
        owned.join("/")
    };

    let mut query_keys = Vec::new();
    let mut query_values_removed = 0u64;
    for (key, _value) in parsed.query_pairs() {
        query_values_removed += 1;
        if any_hit(key.as_bytes(), markers, None) {
            query_keys.push(TYPED.to_owned());
        } else {
            query_keys.push(key.into_owned());
        }
    }

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
    let mut masked = vec![false; host.len()];
    for m in markers {
        let mut from = 0;
        while let Some(range) = host
            .get(from..)
            .and_then(|rest| m.find_ignore_ascii_case(rest))
        {
            let (start, end) = (from + range.start, from + range.end);
            masked[start..end].iter_mut().for_each(|b| *b = true);
            // Resume one character after the start so overlapping occurrences are found.
            from = start + host[start..].chars().next().map_or(1, char::len_utf8);
        }
    }
    let mut labels: Vec<&str> = Vec::new();
    let mut offset = 0;
    let mut previous_typed = false;
    for label in host.split('.') {
        let typed = masked[offset..offset + label.len()].iter().any(|b| *b);
        offset += label.len() + 1;
        if typed {
            if !previous_typed {
                labels.push(TYPED);
            }
        } else {
            labels.push(label);
        }
        previous_typed = typed;
    }
    labels.join(".")
}

fn segment_is_id(seg: &str, markers: &[Marker]) -> bool {
    if seg.is_empty() {
        return false;
    }
    let all_digits = seg.bytes().all(|b| b.is_ascii_digit());
    let long_hex = seg.len() >= 16 && seg.bytes().all(|b| b.is_ascii_hexdigit());
    if all_digits || long_hex || is_uuid(seg) {
        return true;
    }
    let decoded: Zeroizing<Vec<u8>> = Zeroizing::new(percent_decode(seg.as_bytes()).collect());
    any_hit(seg.as_bytes(), markers, None) || any_hit(&decoded, markers, None)
}

fn is_uuid(seg: &str) -> bool {
    let b = seg.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// scheme = first token, lowercased. For `basic`, the credentials are base64-decoded and the decoded bytes
/// are searched; a marker found there is reported with `Encoding::Base64`. Other schemes are searched as sent.
/// When `pair` is given the value is also searched with `search_pair`. No (role, encoding) is listed twice.
///
/// The value as sent is always searched too. The scheme is kept only when it is a plain token
/// (at most 32 ASCII letters, digits, `-` or `_`) holding no typed value; otherwise it is
/// `{typed}` or `{other}`, so a bare credential sent with no scheme is not copied into the file.
pub fn reduce_authorization(
    header_value: &[u8],
    markers: &[Marker],
    pair: Option<(&Marker, &Marker)>,
) -> AuthShape {
    let (scheme_bytes, credentials) = match header_value.iter().position(|b| *b == b' ') {
        Some(i) => (&header_value[..i], &header_value[i + 1..]),
        None => (header_value, &header_value[..0]),
    };
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

    let scheme = if any_hit(scheme_bytes, markers, pair) {
        TYPED.to_owned()
    } else if !scheme_lower.is_empty()
        && scheme_lower.len() <= 32
        && scheme_lower
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
    {
        String::from_utf8_lossy(&scheme_lower).into_owned()
    } else {
        "{other}".to_owned()
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
    use kharon_recording::Role;

    pub(crate) fn user(s: &str) -> Marker {
        Marker::new(Zeroizing::new(s.to_owned()), Role::Username)
    }
    pub(crate) fn pw(s: &str) -> Marker {
        Marker::new(Zeroizing::new(s.to_owned()), Role::Password)
    }
    fn hit(role: Role, encoding: Encoding) -> MarkerHit {
        MarkerHit {
            role,
            encoding,
            low_confidence: false,
        }
    }

    #[test]
    fn keeps_origin_path_and_query_keys() {
        let s = strip_url("https://ex.test/login/step?next=%2Fhome&lang=en#frag", &[]).unwrap();
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
        let s = strip_url("http://bob:s3cret@ex.test:8080/a?k=1&k=2", &[]).unwrap();
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
            let s = strip_url(&format!("https://ex.test{path}"), &[]).unwrap();
            assert_eq!(s.value.path, want);
            assert_eq!(s.path_segments_replaced, n);
        }
    }

    #[test]
    fn replaces_a_segment_that_contains_a_marker() {
        let m = [user("kh.throwaway7")];
        let s = strip_url("https://ex.test/u/kh.throwaway7/dash", &m).unwrap();
        assert_eq!(s.value.path, "/u/{id}/dash");
        let s = strip_url("https://ex.test/u/kh%2Ethrow%61way7/dash", &m).unwrap();
        assert_eq!(s.value.path, "/u/{id}/dash");
        assert_eq!(s.path_segments_replaced, 1);
    }

    #[test]
    fn unparseable_url_is_none() {
        assert!(strip_url("not a url", &[]).is_none());
    }

    #[test]
    fn a_query_key_that_holds_a_typed_value_is_not_kept() {
        let m = [user("kh.throwaway7")];
        let s = strip_url("https://ex.test/x?kh.throwaway7=1&ok=2", &m).unwrap();
        assert_eq!(s.value.query_keys, ["{typed}", "ok"]);
        let s = strip_url("https://ex.test/x?kh%2Ethrowaway7=1", &m).unwrap();
        assert_eq!(s.value.query_keys, ["{typed}"]);
    }

    #[test]
    fn a_host_label_that_holds_a_typed_value_is_replaced() {
        let m = [user("kh.throwaway7")];
        // The value spans two labels: the whole run of labels the match covers is one `{typed}`.
        let s = strip_url("https://kh.throwaway7.ex.test/login", &m).unwrap();
        assert_eq!(s.value.origin, "https://{typed}.ex.test");
        // Case-insensitive, and a partial label is replaced whole.
        let m = [user("Kh.Throwaway7")];
        let s = strip_url("https://x-kh.throwaway7-y.ex.test:81/", &m).unwrap();
        assert_eq!(s.value.origin, "https://{typed}.ex.test:81");
        // Every occurrence.
        let m = [user("bob12")];
        let s = strip_url("https://bob12.ex.bob12.test/", &m).unwrap();
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
                scheme: "negotiate".into(),
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
}
