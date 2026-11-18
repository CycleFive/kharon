//! Typed markers: a value the user typed, held only in memory, searched for in request bytes
//! under the encodings a site might apply. A `Marker` can never be printed.

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding as B64};
use kharon_recording::{Encoding, MarkerHit, Role};
use md5::Md5;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

/// Markers shorter than this many characters produce low-confidence hits.
pub const LOW_CONFIDENCE_BELOW: u32 = 6;

/// A typed value and its role. It implements none of `Debug`, `Display`, `Serialize` or `Clone`.
///
/// ```compile_fail
/// let m = kharon_teach::marker::Marker::new(zeroize::Zeroizing::new(String::from("x")), kharon_recording::Role::Password);
/// println!("{:?}", m);
/// ```
pub struct Marker {
    value: Zeroizing<String>,
    role: Role,
}

impl Marker {
    pub fn new(value: Zeroizing<String>, role: Role) -> Self {
        Self { value, role }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Length in characters.
    pub fn len(&self) -> u32 {
        u32::try_from(self.value.chars().count()).unwrap_or(u32::MAX)
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Whether both markers hold the same value (role is ignored). Not constant time.
    pub fn same_value(&self, other: &Marker) -> bool {
        self.value.as_str() == other.value.as_str()
    }

    pub fn with_role(self, role: Role) -> Self {
        Self { role, ..self }
    }

    /// Byte range of the first place this marker's value occurs in `haystack`, comparing ASCII letters
    /// without regard to case. `None` for an empty marker. Used for host names, which arrive lowercased.
    ///
    /// Compares byte windows in place, so no lowercase copy of the value is ever made. Non-ASCII
    /// bytes must match exactly. The range starts and ends on character boundaries: a match
    /// begins with an ASCII byte or a UTF-8 lead byte, and ends with a complete character.
    pub fn find_ignore_ascii_case(&self, haystack: &str) -> Option<std::ops::Range<usize>> {
        let needle = self.value.as_bytes();
        if needle.is_empty() {
            return None;
        }
        haystack
            .as_bytes()
            .windows(needle.len())
            .position(|w| w.eq_ignore_ascii_case(needle))
            .map(|start| start..start + needle.len())
    }
}

type Needle = Zeroizing<Vec<u8>>;

/// RFC 3986 unreserved characters stay as they are; every other byte is percent-encoded.
const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Every way `marker` occurs in `haystack`. Digests are searched only for Role::Password.
///
/// At most one hit per `Encoding`, in the order of the enum's variants. An encoded form that is
/// byte-identical to the as-typed form is not searched, so a plain value reports only `AsTyped`.
pub fn search(haystack: &[u8], marker: &Marker) -> Vec<MarkerHit> {
    if marker.is_empty() {
        return Vec::new();
    }
    let low_confidence = marker.len() < LOW_CONFIDENCE_BELOW;
    needles(marker)
        .into_iter()
        .filter(|(_, forms)| forms.iter().any(|n| contains(haystack, n)))
        .map(|(encoding, _)| MarkerHit {
            role: marker.role,
            encoding,
            low_confidence,
        })
        .collect()
}

/// The base64 and base64url (padded or not) of `username:password`. A match returns two hits,
/// one per role, both `Encoding::Base64` (or `Base64Url`).
///
/// Nothing is returned when either marker is empty. `low_confidence` is set when the combined
/// length of both values is under `LOW_CONFIDENCE_BELOW` characters.
pub fn search_pair(haystack: &[u8], username: &Marker, password: &Marker) -> Vec<MarkerHit> {
    if username.is_empty() || password.is_empty() {
        return Vec::new();
    }
    let mut joined = Zeroizing::new(String::with_capacity(
        username.value.len() + password.value.len() + 1,
    ));
    joined.push_str(&username.value);
    joined.push(':');
    joined.push_str(&password.value);
    let low_confidence = username.len().saturating_add(password.len()) < LOW_CONFIDENCE_BELOW;
    let (standard, url_safe) = base64_forms(joined.as_bytes());
    let url_safe = {
        let seen: Vec<&[u8]> = standard.iter().map(|n| n.as_slice()).collect();
        dedup(url_safe, &seen)
    };
    let mut hits = Vec::new();
    for (encoding, forms) in [
        (Encoding::Base64, standard),
        (Encoding::Base64Url, url_safe),
    ] {
        if forms.iter().any(|n| contains(haystack, n)) {
            for role in [username.role, password.role] {
                hits.push(MarkerHit {
                    role,
                    encoding,
                    low_confidence,
                });
            }
        }
    }
    hits
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// The search forms per encoding, in `Encoding` order.
fn needles(marker: &Marker) -> Vec<(Encoding, Vec<Needle>)> {
    let value = marker.value.as_bytes();
    let (standard, url_safe) = base64_forms(value);
    let standard = dedup(standard, &[value]);
    let url_safe = {
        let mut seen: Vec<&[u8]> = vec![value];
        seen.extend(standard.iter().map(|n| n.as_slice()));
        dedup(url_safe, &seen)
    };
    let mut out = vec![
        (Encoding::AsTyped, vec![Zeroizing::new(value.to_vec())]),
        (Encoding::Percent, dedup(percent_forms(value), &[value])),
        (
            Encoding::JsonEscaped,
            dedup(json_forms(&marker.value), &[value]),
        ),
        (Encoding::Base64, standard),
        (Encoding::Base64Url, url_safe),
        (Encoding::Hex, hex_forms(value)),
    ];
    if marker.role == Role::Password {
        let digests: [(Encoding, Encoding, Vec<u8>); 4] = [
            (
                Encoding::Md5Hex,
                Encoding::Md5Base64,
                Md5::digest(value).to_vec(),
            ),
            (
                Encoding::Sha1Hex,
                Encoding::Sha1Base64,
                Sha1::digest(value).to_vec(),
            ),
            (
                Encoding::Sha256Hex,
                Encoding::Sha256Base64,
                Sha256::digest(value).to_vec(),
            ),
            (
                Encoding::Sha512Hex,
                Encoding::Sha512Base64,
                Sha512::digest(value).to_vec(),
            ),
        ];
        for (hex_encoding, b64_encoding, digest) in digests {
            out.push((hex_encoding, hex_forms(&digest)));
            out.push((b64_encoding, base64_forms(&digest).0));
        }
    }
    out
}

/// Drops empty forms, forms equal to one in `seen`, and repeats.
fn dedup(forms: Vec<Needle>, seen: &[&[u8]]) -> Vec<Needle> {
    let mut kept: Vec<Needle> = Vec::new();
    for form in forms {
        let known = form.is_empty()
            || seen.iter().any(|s| *s == form.as_slice())
            || kept.iter().any(|k| k.as_slice() == form.as_slice());
        if !known {
            kept.push(form);
        }
    }
    kept
}

fn encode_b64<E: B64>(bytes: &[u8]) -> Needle {
    let mut buf = Zeroizing::new(vec![0u8; E::encoded_len(bytes)]);
    if E::encode(bytes, &mut buf).is_err() {
        // The buffer is sized by `encoded_len`, so this cannot happen; match nothing if it does.
        buf.clear();
    }
    buf
}

/// (standard, URL-safe), each padded then unpadded.
fn base64_forms(bytes: &[u8]) -> (Vec<Needle>, Vec<Needle>) {
    (
        vec![
            encode_b64::<Base64>(bytes),
            encode_b64::<Base64Unpadded>(bytes),
        ],
        vec![
            encode_b64::<Base64Url>(bytes),
            encode_b64::<Base64UrlUnpadded>(bytes),
        ],
    )
}

/// Lowercase then uppercase.
fn hex_forms(bytes: &[u8]) -> Vec<Needle> {
    let mut lower = Zeroizing::new(vec![0u8; bytes.len() * 2]);
    if hex::encode_to_slice(bytes, &mut lower).is_err() {
        lower.clear();
    }
    let mut upper = lower.clone();
    upper.make_ascii_uppercase();
    vec![lower, upper]
}

/// Uppercase and lowercase percent hex, each with space as `%20` and as `+`.
fn percent_forms(bytes: &[u8]) -> Vec<Needle> {
    let mut forms = Vec::new();
    for plus in [false, true] {
        for lower in [false, true] {
            let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() * 3));
            for chunk in percent_encode(bytes, UNRESERVED) {
                if plus && chunk == "%20" {
                    out.push(b'+');
                } else if lower && chunk.starts_with('%') {
                    out.extend(chunk.bytes().map(|b| b.to_ascii_lowercase()));
                } else {
                    out.extend_from_slice(chunk.as_bytes());
                }
            }
            forms.push(out);
        }
    }
    forms
}

#[derive(Clone, Copy)]
enum JsonMode {
    /// Non-ASCII characters stay as UTF-8.
    Raw,
    /// Non-ASCII characters become backslash-u escapes, with hex digits in the given case.
    Ascii { upper: bool },
}

/// The content between the quotes as `serde_json` writes it (raw non-ASCII), and the form with
/// every non-ASCII character as a backslash-u escape in each hex case.
fn json_forms(value: &str) -> Vec<Needle> {
    [
        JsonMode::Raw,
        JsonMode::Ascii { upper: false },
        JsonMode::Ascii { upper: true },
    ]
    .into_iter()
    .map(|mode| json_escape(value, mode))
    .collect()
}

fn push_u_escape(out: &mut Vec<u8>, unit: u16, upper: bool) {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    out.extend_from_slice(b"\\u");
    for shift in [12, 8, 4, 0] {
        out.push(digits[usize::from((unit >> shift) & 0xf)]);
    }
}

fn json_escape(value: &str, mode: JsonMode) -> Needle {
    let upper = matches!(mode, JsonMode::Ascii { upper: true });
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() * 6));
    for c in value.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if u32::from(c) < 0x20 => push_u_escape(&mut out, u16::from(c as u8), upper),
            c if c.is_ascii() => out.push(c as u8),
            c => match mode {
                JsonMode::Raw => {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                JsonMode::Ascii { .. } => {
                    let mut units = [0u16; 2];
                    for unit in c.encode_utf16(&mut units) {
                        push_u_escape(&mut out, *unit, upper);
                    }
                }
            },
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> Marker {
        Marker::new(Zeroizing::new(s.to_owned()), Role::Password)
    }
    fn user(s: &str) -> Marker {
        Marker::new(Zeroizing::new(s.to_owned()), Role::Username)
    }
    /// `@` stands for a backslash, so escape sequences stay literal in the source.
    fn bs(s: &str) -> String {
        s.replace('@', "\\")
    }
    fn encodings(h: &[u8], m: &Marker) -> Vec<Encoding> {
        search(h, m).into_iter().map(|x| x.encoding).collect()
    }

    #[test]
    fn as_typed() {
        assert_eq!(
            encodings(b"user=a&password=Tr0ub4dor-9x&x=1", &pw("Tr0ub4dor-9x")),
            [Encoding::AsTyped]
        );
    }

    #[test]
    fn percent_encoded() {
        assert_eq!(
            encodings(b"p=a%20b%26c%2Bd12", &pw("a b&c+d12")),
            [Encoding::Percent]
        );
    }

    #[test]
    fn percent_encoded_lowercase_hex() {
        assert_eq!(
            encodings(b"p=a%2fb%26c%2bd12", &pw("a/b&c+d12")),
            [Encoding::Percent]
        );
    }

    #[test]
    fn percent_encoded_plus_for_space() {
        assert_eq!(
            encodings(b"p=a+b%26c%2Bd12", &pw("a b&c+d12")),
            [Encoding::Percent]
        );
    }

    #[test]
    fn json_escaped() {
        assert_eq!(
            encodings(br#"{"p":"a\"b\\c12"}"#, &pw(r#"a"b\c12"#)),
            [Encoding::JsonEscaped]
        );
    }

    #[test]
    fn json_escaped_control_characters() {
        assert_eq!(
            encodings(br#"{"p":"a\nb\u0001c12"}"#, &pw("a\nb\u{1}c12")),
            [Encoding::JsonEscaped]
        );
    }

    #[test]
    fn base64_and_base64url() {
        assert_eq!(
            encodings(b"x=Pj4+Pz8/MTI=", &pw(">>>???12")),
            [Encoding::Base64]
        );
        // unpadded is found too
        assert_eq!(
            encodings(b"x=Pj4-Pz8_MTI", &pw(">>>???12")),
            [Encoding::Base64Url]
        );
    }

    #[test]
    fn hex_either_case() {
        let lower = hex::encode("Tr0ub4dor-9x");
        let upper = lower.to_uppercase();
        assert_eq!(
            encodings(lower.as_bytes(), &pw("Tr0ub4dor-9x")),
            [Encoding::Hex]
        );
        assert_eq!(
            encodings(upper.as_bytes(), &pw("Tr0ub4dor-9x")),
            [Encoding::Hex]
        );
    }

    #[test]
    fn sha256_hex_of_a_password() {
        let digest = hex::encode(Sha256::digest(b"Tr0ub4dor-9x"));
        let haystack = format!("h={digest}");
        assert_eq!(
            encodings(haystack.as_bytes(), &pw("Tr0ub4dor-9x")),
            [Encoding::Sha256Hex]
        );
    }

    #[test]
    fn digests_are_not_searched_for_a_username() {
        let digest = hex::encode(Sha256::digest(b"Tr0ub4dor-9x"));
        let haystack = format!("h={digest}");
        assert!(search(haystack.as_bytes(), &user("Tr0ub4dor-9x")).is_empty());
    }

    #[test]
    fn short_marker_is_low_confidence() {
        assert!(search(b"x=abc12", &pw("abc12"))[0].low_confidence);
        assert!(!search(b"x=abc123", &pw("abc123"))[0].low_confidence);
    }

    #[test]
    fn empty_marker_matches_nothing() {
        assert!(search(b"anything", &pw("")).is_empty());
    }

    #[test]
    fn hit_carries_the_marker_role() {
        let hits = search(b"u=kh.throwaway7", &user("kh.throwaway7"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].role, Role::Username);
    }

    #[test]
    fn non_ascii_percent_encoded() {
        assert_eq!(
            encodings(
                b"p=p%C3%A4ssw%C3%B6rd%E2%9C%9312",
                &pw("p\u{e4}ssw\u{f6}rd\u{2713}12")
            ),
            [Encoding::Percent]
        );
    }

    #[test]
    fn non_ascii_json_escaped_both_forms() {
        let m = pw("p\u{e4}ssw\u{f6}rd\u{2713}12");
        let raw = "{\"p\":\"p\u{e4}ssw\u{f6}rd\u{2713}12\"}";
        assert_eq!(encodings(raw.as_bytes(), &m), [Encoding::AsTyped]);
        assert_eq!(
            encodings(bs("{\"p\":\"p@u00e4ssw@u00f6rd@u271312\"}").as_bytes(), &m),
            [Encoding::JsonEscaped]
        );
        assert_eq!(
            encodings(bs("{\"p\":\"p@u00E4ssw@u00F6rd@u271312\"}").as_bytes(), &m),
            [Encoding::JsonEscaped]
        );
    }

    #[test]
    fn json_surrogate_pair() {
        assert_eq!(
            encodings(
                bs("{\"p\":\"pw@ud83d@ude00xyz\"}").as_bytes(),
                &pw("pw\u{1f600}xyz")
            ),
            [Encoding::JsonEscaped]
        );
    }

    #[test]
    fn two_hundred_characters() {
        let value = "Zq9".repeat(66) + "ab";
        assert_eq!(value.chars().count(), 200);
        let haystack = format!("a=1&p={value}&b=2");
        assert_eq!(
            encodings(haystack.as_bytes(), &pw(&value)),
            [Encoding::AsTyped]
        );
    }

    #[test]
    fn pair_is_found_where_neither_value_alone_is() {
        let b64 = Base64::encode_string(b"kh.throwaway7:Tr0ub4dor-9x");
        let haystack = format!(r#"{{"auth":"{b64}"}}"#);
        let u = user("kh.throwaway7");
        let p = pw("Tr0ub4dor-9x");
        assert!(search(haystack.as_bytes(), &u).is_empty());
        assert!(search(haystack.as_bytes(), &p).is_empty());
        let hits = search_pair(haystack.as_bytes(), &u, &p);
        assert_eq!(
            hits.iter()
                .map(|h| (h.role, h.encoding))
                .collect::<Vec<_>>(),
            [
                (Role::Username, Encoding::Base64),
                (Role::Password, Encoding::Base64)
            ]
        );
    }

    #[test]
    fn pair_absent_gives_nothing() {
        assert!(
            search_pair(b"nothing here", &user("kh.throwaway7"), &pw("Tr0ub4dor-9x")).is_empty()
        );
    }

    #[test]
    fn same_value_and_with_role() {
        let a = pw("abc");
        let b = user("abc");
        assert!(a.same_value(&b));
        assert_eq!(a.with_role(Role::None).role(), Role::None);
        assert_eq!(pw("h\u{e4}").len(), 2);
    }

    #[test]
    fn find_ignore_ascii_case_in_a_lowercased_host() {
        let m = user("Kh.Throwaway7");
        assert_eq!(
            m.find_ignore_ascii_case("a.kh.throwaway7.ex.test"),
            Some(2..15)
        );
    }

    #[test]
    fn find_ignore_ascii_case_no_match_and_empty() {
        assert_eq!(
            user("kh.throwaway7").find_ignore_ascii_case("ex.test"),
            None
        );
        assert_eq!(user("longer-than-host").find_ignore_ascii_case("a"), None);
        assert_eq!(user("").find_ignore_ascii_case("ex.test"), None);
    }

    #[test]
    fn find_ignore_ascii_case_non_ascii_is_byte_exact() {
        let m = user("M\u{fc}ller1");
        assert_eq!(m.find_ignore_ascii_case("x-m\u{fc}ller1"), Some(2..10));
        assert_eq!(
            user("\u{c9}t\u{e9}12").find_ignore_ascii_case("\u{e9}t\u{e9}12"),
            None
        );
    }
}
