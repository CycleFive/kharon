//! Support for this crate's tests. It takes only test constants, never a live typed value.
//!
//! It is public (and hidden from the docs) so unit tests and the integration tests under
//! `tests/` share one definition of "the encodings a site might apply to a value".

use base64ct::{Base64, Base64Unpadded, Base64Url, Base64UrlUnpadded, Encoding as B64};
use kharon_recording::Role;
use md5::Md5;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode, percent_encode};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::marker::Marker;

/// A username marker holding `value`.
pub fn user(value: &str) -> Marker {
    Marker::new(Zeroizing::new(value.to_owned()), Role::Username)
}

/// A password marker holding `value`.
pub fn pw(value: &str) -> Marker {
    Marker::new(Zeroizing::new(value.to_owned()), Role::Password)
}

const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Label and bytes of `value` as typed, ASCII-lowercased, ASCII-uppercased, percent-encoded
/// (RFC 3986 strict, upper and lower hex), form-encoded (space as `+`), JSON-escaped, base64 and
/// base64url (padded and not), hex (lower and upper), and the hex of MD5, SHA-1, SHA-256 and
/// SHA-512. A form identical to an earlier one is skipped.
pub fn needles_for(value: &str) -> Vec<(&'static str, Vec<u8>)> {
    let bytes = value.as_bytes();
    let strict: String = percent_encode(bytes, UNRESERVED).to_string();
    let lower_hex = {
        let mut out = String::new();
        for chunk in percent_encode(bytes, UNRESERVED) {
            if chunk.starts_with('%') {
                out.push_str(&chunk.to_ascii_lowercase());
            } else {
                out.push_str(chunk);
            }
        }
        out
    };
    let json = serde_json::to_string(value).unwrap_or_default();
    let json = json
        .strip_prefix('"')
        .and_then(|j| j.strip_suffix('"'))
        .unwrap_or_default()
        .to_owned();
    let hex_of = |b: &[u8]| hex::encode(b);
    let candidates: Vec<(&'static str, Vec<u8>)> = vec![
        ("as typed", bytes.to_vec()),
        ("lowercased", value.to_ascii_lowercase().into_bytes()),
        ("uppercased", value.to_ascii_uppercase().into_bytes()),
        ("percent upper", strict.clone().into_bytes()),
        ("percent lower", lower_hex.into_bytes()),
        ("form encoded", strict.replace("%20", "+").into_bytes()),
        ("json escaped", json.into_bytes()),
        ("base64", Base64::encode_string(bytes).into_bytes()),
        (
            "base64 unpadded",
            Base64Unpadded::encode_string(bytes).into_bytes(),
        ),
        ("base64url", Base64Url::encode_string(bytes).into_bytes()),
        (
            "base64url unpadded",
            Base64UrlUnpadded::encode_string(bytes).into_bytes(),
        ),
        ("hex lower", hex_of(bytes).into_bytes()),
        ("hex upper", hex_of(bytes).to_uppercase().into_bytes()),
        ("md5 hex", hex_of(&Md5::digest(bytes)).into_bytes()),
        ("sha1 hex", hex_of(&Sha1::digest(bytes)).into_bytes()),
        ("sha256 hex", hex_of(&Sha256::digest(bytes)).into_bytes()),
        ("sha512 hex", hex_of(&Sha512::digest(bytes)).into_bytes()),
    ];
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for (label, form) in candidates {
        if !form.is_empty() && !out.iter().any(|(_, f)| *f == form) {
            out.push((label, form));
        }
    }
    out
}

/// Panics when any needle of any of `values` occurs in `text` or in its percent-decoded form.
/// The message names the value's position and the encoding, never `text` or a value.
pub fn assert_holds_no_typed_value(text: &str, values: &[&str]) {
    let decoded: Vec<u8> = percent_decode(text.as_bytes()).collect();
    for (i, value) in values.iter().enumerate() {
        for (label, needle) in needles_for(value) {
            let found = |h: &[u8]| h.windows(needle.len()).any(|w| w == needle.as_slice());
            assert!(
                !found(text.as_bytes()) && !found(&decoded),
                "typed value #{i} found in the output, as: {label}"
            );
        }
    }
}
