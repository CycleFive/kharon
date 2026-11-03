//! TOTP generation and `fill_totp` (REQ-API-007; issue #19).
//!
//! - this module: the item's `login.totp` field parsed into a
//!   [`TotpKey`] (an `otpauth://totp/…` URI, a bare base32 secret, or a
//!   `steam://` secret, the three forms Bitwarden clients store) and
//!   RFC 6238 code generation (HMAC-SHA1/256/512, 6–10 digits, any
//!   period; Steam's 5-character alphabet).
//! - [`skew`]: the startup clock check against the Vaultwarden `Date`
//!   header (`clock_skew_warn` / `clock_skew_refuse`).
//! - [`fill`]: `fill_totp` over the existing fill engine
//!   ([`crate::cdp::FillEngine`] under the REQ-API-009 deadline).
//!
//! Secret handling (REQ-CRY-006, REQ-API-005, G1): the decrypted field
//! arrives as a [`Secret`]; the key bytes live in a [`Zeroizing`]
//! buffer that has no `Debug`/`Clone`; generated codes are returned as
//! `Zeroizing<String>` and only ever travel into a
//! [`crate::cdp::FieldFill`]. Nothing in this module formats, logs or
//! returns a key or code, and [`TotpError`] carries no value.
//! Parsing is done by hand rather than through [`url::Url`] so the
//! field is never copied into a non-zeroizing buffer.

pub mod fill;
pub mod skew;

mod base32;

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use kharon_bwcrypto::Secret;
use zeroize::{Zeroize, Zeroizing};

pub use fill::{TotpFill, TotpTarget, totp_code};
pub use skew::{ClockSample, ClockSkewGate, ClockSkewRefused, SkewPolicy, SkewVerdict};

/// RFC 6238 default period (seconds).
pub const DEFAULT_PERIOD: u64 = 30;
/// RFC 6238 default digits.
pub const DEFAULT_DIGITS: u32 = 6;
/// Fewest digits accepted (RFC 4226 §5.3: at least 6).
pub const MIN_DIGITS: u32 = 6;
/// Most digits accepted (a 31-bit truncation has 10 decimal digits;
/// Bitwarden clients cap at 10 too).
pub const MAX_DIGITS: u32 = 10;
/// Longest accepted period (one day). Longer periods are not TOTP in
/// any deployed sense and would mask a mangled parameter.
pub const MAX_PERIOD: u64 = 86_400;
/// Longest accepted `login.totp` field (bytes).
pub const MAX_FIELD_LEN: usize = 4096;

/// Steam Guard's code alphabet (26 symbols, 5 characters per code).
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const STEAM_CHARS: usize = 5;

/// HMAC hash for the TOTP (`algorithm=` in an `otpauth://` URI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// HMAC-SHA1 (default).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

/// How the truncated value becomes a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// RFC 4226 decimal, `digits` long, zero padded.
    Decimal {
        /// 6..=10.
        digits: u32,
    },
    /// Steam Guard: 5 characters from [`STEAM_ALPHABET`].
    Steam,
}

/// Why a `login.totp` field could not be used. Fixed variants only:
/// nothing here carries any part of the field (REQ-API-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    /// The field is empty or whitespace.
    #[error("TOTP field is empty")]
    Empty,
    /// The field exceeds [`MAX_FIELD_LEN`].
    #[error("TOTP field is too long")]
    TooLong,
    /// A URI scheme or `otpauth` type other than `otpauth://totp` or
    /// `steam://` (e.g. `otpauth://hotp`).
    #[error("unsupported TOTP URI type")]
    UnsupportedType,
    /// `otpauth://` without a `secret` parameter.
    #[error("TOTP URI has no secret")]
    MissingSecret,
    /// The secret is not valid base32 or decodes to nothing.
    #[error("TOTP secret is not valid base32")]
    InvalidSecret,
    /// `algorithm=` is not SHA1, SHA256 or SHA512.
    #[error("unsupported TOTP algorithm")]
    InvalidAlgorithm,
    /// `digits=` is not an integer in 6..=10.
    #[error("unsupported TOTP digits")]
    InvalidDigits,
    /// `period=` is not an integer in 1..=86400.
    #[error("unsupported TOTP period")]
    InvalidPeriod,
    /// A parameter appears twice, or a query is malformed.
    #[error("malformed TOTP URI")]
    Malformed,
    /// The system clock reads before 1970.
    #[error("system clock before the Unix epoch")]
    ClockBeforeEpoch,
}

/// A parsed TOTP key. The key bytes are zeroized on drop; there is
/// deliberately no `Clone`, and `Debug` prints parameters only.
pub struct TotpKey {
    key: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    encoding: Encoding,
    period: u64,
}

impl std::fmt::Debug for TotpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpKey")
            .field("key", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("encoding", &self.encoding)
            .field("period", &self.period)
            .finish()
    }
}

impl TotpKey {
    /// Parse a decrypted `login.totp` field: `otpauth://totp/…`
    /// (`secret`, `algorithm`, `digits`, `period`; other parameters
    /// such as `issuer` are ignored), `steam://<base32>`, or a bare
    /// base32 secret (SHA1, 6 digits, 30 s).
    pub fn parse(field: &Secret<String>) -> Result<Self, TotpError> {
        let s = field.expose_secret().trim();
        if s.is_empty() {
            return Err(TotpError::Empty);
        }
        if s.len() > MAX_FIELD_LEN {
            return Err(TotpError::TooLong);
        }
        if let Some(rest) = strip_prefix_ci(s, "steam://") {
            let key = base32::decode(rest.as_bytes())?;
            return Self::from_parts(key, Algorithm::Sha1, Encoding::Steam, DEFAULT_PERIOD);
        }
        if let Some(rest) = strip_prefix_ci(s, "otpauth://") {
            return parse_otpauth(rest);
        }
        if s.contains("://") {
            return Err(TotpError::UnsupportedType);
        }
        let key = base32::decode(s.as_bytes())?;
        Self::from_parts(
            key,
            Algorithm::Sha1,
            Encoding::Decimal {
                digits: DEFAULT_DIGITS,
            },
            DEFAULT_PERIOD,
        )
    }

    /// Build a key from raw bytes (tests and vectors).
    pub fn from_parts(
        key: Zeroizing<Vec<u8>>,
        algorithm: Algorithm,
        encoding: Encoding,
        period: u64,
    ) -> Result<Self, TotpError> {
        if key.is_empty() {
            return Err(TotpError::InvalidSecret);
        }
        if let Encoding::Decimal { digits } = encoding
            && !(MIN_DIGITS..=MAX_DIGITS).contains(&digits)
        {
            return Err(TotpError::InvalidDigits);
        }
        if !(1..=MAX_PERIOD).contains(&period) {
            return Err(TotpError::InvalidPeriod);
        }
        Ok(Self {
            key,
            algorithm,
            encoding,
            period,
        })
    }

    /// The HMAC algorithm.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The code encoding.
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// The period (seconds).
    pub fn period(&self) -> u64 {
        self.period
    }

    /// RFC 6238 time step for a Unix time (`T = floor(t / X)`, T0 = 0).
    pub fn counter_at(&self, unix_secs: u64) -> u64 {
        unix_secs / self.period
    }

    /// The code for the step containing `unix_secs`.
    pub fn code_at(&self, unix_secs: u64) -> Zeroizing<String> {
        self.code_for_counter(self.counter_at(unix_secs))
    }

    /// The code for the current step of `now` (the system clock; the
    /// site's verifier applies its own ±1 step tolerance).
    pub fn code_now(&self, now: SystemTime) -> Result<Zeroizing<String>, TotpError> {
        let secs = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TotpError::ClockBeforeEpoch)?
            .as_secs();
        Ok(self.code_at(secs))
    }

    /// RFC 4226 HOTP for `counter` with this key's algorithm and
    /// encoding.
    pub fn code_for_counter(&self, counter: u64) -> Zeroizing<String> {
        let msg = counter.to_be_bytes();
        let mut bin = match self.algorithm {
            Algorithm::Sha1 => truncate::<Hmac<sha1::Sha1>>(&self.key, &msg),
            Algorithm::Sha256 => truncate::<Hmac<sha2::Sha256>>(&self.key, &msg),
            Algorithm::Sha512 => truncate::<Hmac<sha2::Sha512>>(&self.key, &msg),
        };
        let mut out = Zeroizing::new(String::with_capacity(MAX_DIGITS as usize));
        match self.encoding {
            Encoding::Decimal { digits } => {
                let mut v = u64::from(bin) % 10u64.pow(digits);
                // Most significant digit first, zero padded.
                let mut div = 10u64.pow(digits - 1);
                while div > 0 {
                    out.push(char::from(b'0' + (v / div) as u8));
                    v %= div;
                    div /= 10;
                }
                v.zeroize();
            }
            Encoding::Steam => {
                for _ in 0..STEAM_CHARS {
                    out.push(char::from(
                        STEAM_ALPHABET[(bin as usize) % STEAM_ALPHABET.len()],
                    ));
                    bin /= STEAM_ALPHABET.len() as u32;
                }
            }
        }
        bin.zeroize();
        out
    }
}

/// HMAC over `msg`, then RFC 4226 §5.3 dynamic truncation to 31 bits.
/// The MAC output is wiped before returning.
fn truncate<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> u32 {
    let mut mac = <M as Mac>::new_from_slice(key).expect("invariant: HMAC accepts any key length");
    mac.update(msg);
    let mut out = mac.finalize().into_bytes();
    let bytes: &mut [u8] = out.as_mut_slice();
    let offset = usize::from(bytes[bytes.len() - 1] & 0x0f);
    let bin = u32::from_be_bytes([
        bytes[offset] & 0x7f,
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]);
    bytes.zeroize();
    bin
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// `otpauth://` after the scheme: `totp/<label>?<query>`.
fn parse_otpauth(rest: &str) -> Result<TotpKey, TotpError> {
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let kind = path.split('/').next().unwrap_or("");
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(TotpError::UnsupportedType);
    }
    let query = query.split('#').next().unwrap_or("");
    let mut secret: Option<Zeroizing<Vec<u8>>> = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = percent_decode(k.as_bytes())?;
        let slot_taken = match k.as_slice() {
            b"secret" => secret.replace(percent_decode(v.as_bytes())?).is_some(),
            b"algorithm" => algorithm
                .replace(parse_algorithm(&percent_decode(v.as_bytes())?)?)
                .is_some(),
            b"digits" => digits
                .replace(
                    parse_uint(&percent_decode(v.as_bytes())?).ok_or(TotpError::InvalidDigits)?,
                )
                .is_some(),
            b"period" => period
                .replace(
                    parse_uint(&percent_decode(v.as_bytes())?).ok_or(TotpError::InvalidPeriod)?,
                )
                .is_some(),
            _ => false,
        };
        if slot_taken {
            return Err(TotpError::Malformed);
        }
    }
    let secret = secret.ok_or(TotpError::MissingSecret)?;
    let key = base32::decode(&secret)?;
    let digits = match digits {
        None => DEFAULT_DIGITS,
        Some(d) => u32::try_from(d).map_err(|_| TotpError::InvalidDigits)?,
    };
    TotpKey::from_parts(
        key,
        algorithm.unwrap_or(Algorithm::Sha1),
        Encoding::Decimal { digits },
        period.unwrap_or(DEFAULT_PERIOD),
    )
}

fn parse_algorithm(v: &[u8]) -> Result<Algorithm, TotpError> {
    if v.eq_ignore_ascii_case(b"sha1") {
        Ok(Algorithm::Sha1)
    } else if v.eq_ignore_ascii_case(b"sha256") {
        Ok(Algorithm::Sha256)
    } else if v.eq_ignore_ascii_case(b"sha512") {
        Ok(Algorithm::Sha512)
    } else {
        Err(TotpError::InvalidAlgorithm)
    }
}

fn parse_uint(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 6 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(v.iter().fold(0u64, |acc, d| acc * 10 + u64::from(d - b'0')))
}

/// RFC 3986 percent-decoding into a zeroizing buffer (`+` is kept
/// literally: it is not in the base32 alphabet, so a `+` in a secret
/// is refused by the decoder either way).
fn percent_decode(v: &[u8]) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(v.len()));
    let mut i = 0;
    while i < v.len() {
        if v[i] == b'%' {
            let hex = v.get(i + 1..i + 3).ok_or(TotpError::Malformed)?;
            let hi = (hex[0] as char).to_digit(16).ok_or(TotpError::Malformed)?;
            let lo = (hex[1] as char).to_digit(16).ok_or(TotpError::Malformed)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(v[i]);
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
