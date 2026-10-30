//! Bitwarden `EncString` parsing and decryption (REQ-CRY-002, REQ-CRY-003).
//!
//! Wire format: `<type>.<base64 segments joined by '|'>`. Only the two
//! types kharon needs are supported; every other type fails closed with
//! [`EncError::UnsupportedEncType`]:
//!
//! - Type 2 (`AesCbc256_HmacSha256_B64`): `2.<iv>|<ct>|<mac>` under a
//!   64-byte symmetric key split as `enc_key = key[0..32]`,
//!   `mac_key = key[32..64]`. `mac = HMAC-SHA256(mac_key, iv || ct)`.
//! - Type 4 (`Rsa2048_OaepSha1_B64`): `4.<ct>`, RSA-OAEP with SHA-1
//!   (MGF1-SHA-1) under the account's RSA keypair.
//!
//! REQ-CRY-003 is enforced structurally: the CBC decryptor takes a
//! [`MacVerified`] token that only [`verify_mac`] can mint, after the
//! constant-time MAC check passes. There is no code path from a parsed
//! type-2 string to the decryptor that skips verification.

use base64ct::{Base64, Encoding};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rsa::RsaPrivateKey;
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const TYPE_AES_CBC256_HMAC_SHA256: u32 = 2;
const TYPE_RSA2048_OAEP_SHA1: u32 = 4;

/// Errors from EncString parsing and decryption. Deliberately coarse:
/// [`EncError::DecryptionFailed`] does not distinguish padding from RSA
/// errors, so error output can't serve as a decryption oracle.
#[derive(Debug, thiserror::Error)]
pub enum EncError {
    /// The EncString type is not one kharon implements (fail closed).
    #[error("unsupported EncString type: {0}")]
    UnsupportedEncType(u32),
    /// The string does not match the EncString wire format.
    #[error("malformed EncString")]
    Malformed,
    /// HMAC verification failed (REQ-CRY-003).
    #[error("MAC verification failed")]
    MacMismatch,
    /// Decryption failed after the MAC check (padding or RSA error).
    #[error("decryption failed")]
    DecryptionFailed,
    /// A symmetric key was not exactly 64 bytes.
    #[error("symmetric key must be 64 bytes")]
    InvalidKeyLength,
    /// A decrypt method was called on an EncString of the other kind.
    #[error("EncString type {found} does not use this key kind (expected type {expected})")]
    TypeMismatch { expected: u32, found: u32 },
    /// A type-4 unwrap was refused because an earlier type-4 unwrap in
    /// this unlock session already failed (RUSTSEC-2023-0071 mitigation
    /// invariant: no RSA decryption oracle across an unlock).
    #[error("type-4 unwrap refused: a previous unwrap failed this unlock")]
    Type4UnwrapRefused,
}

/// A 64-byte Bitwarden symmetric key: `enc_key || mac_key`, wiped on drop.
pub struct SymmetricKey(Zeroizing<[u8; 64]>);

impl SymmetricKey {
    /// Wrap exactly 64 bytes of key material.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EncError> {
        let arr: [u8; 64] = bytes.try_into().map_err(|_| EncError::InvalidKeyLength)?;
        Ok(Self(Zeroizing::new(arr)))
    }

    /// Test-only view of the raw key bytes, for byte-for-byte vector
    /// assertions. Not part of the non-test API: key material should
    /// only leave this type as a decryption result.
    #[cfg(test)]
    pub(crate) fn as_bytes_for_test(&self) -> &[u8] {
        &self.0[..]
    }

    fn enc_key(&self) -> &[u8] {
        &self.0[..32]
    }

    fn mac_key(&self) -> &[u8] {
        &self.0[32..]
    }
}

/// A parsed EncString. Segments are stored decoded; the plaintext is
/// never stored.
#[derive(Clone, PartialEq, Eq)]
pub enum EncString {
    /// Type 2: AES-256-CBC + HMAC-SHA256.
    AesCbc256WithMac {
        iv: Vec<u8>,
        ct: Vec<u8>,
        mac: Vec<u8>,
    },
    /// Type 4: RSA-2048-OAEP-SHA1.
    Rsa2048OaepSha1 { ct: Vec<u8> },
}

impl std::fmt::Debug for EncString {
    /// Prints only the type and segment lengths — never segment bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AesCbc256WithMac { iv, ct, mac } => f
                .debug_struct("EncString::AesCbc256WithMac")
                .field("iv_len", &iv.len())
                .field("ct_len", &ct.len())
                .field("mac_len", &mac.len())
                .finish(),
            Self::Rsa2048OaepSha1 { ct } => f
                .debug_struct("EncString::Rsa2048OaepSha1")
                .field("ct_len", &ct.len())
                .finish(),
        }
    }
}

fn b64(segment: &str) -> Result<Vec<u8>, EncError> {
    Base64::decode_vec(segment).map_err(|_| EncError::Malformed)
}

impl EncString {
    /// Parse an EncString. Unsupported types return
    /// [`EncError::UnsupportedEncType`] before the payload is examined;
    /// supported types with a bad payload return [`EncError::Malformed`].
    /// Never panics on arbitrary input.
    pub fn parse(input: &str) -> Result<Self, EncError> {
        let (type_str, data) = input.split_once('.').ok_or(EncError::Malformed)?;
        if type_str.is_empty() || !type_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(EncError::Malformed);
        }
        let enc_type: u32 = type_str.parse().map_err(|_| EncError::Malformed)?;
        match enc_type {
            TYPE_AES_CBC256_HMAC_SHA256 => {
                let segments: Vec<&str> = data.split('|').collect();
                if segments.len() != 3 {
                    return Err(EncError::Malformed);
                }
                let iv = b64(segments[0])?;
                let ct = b64(segments[1])?;
                let mac = b64(segments[2])?;
                if iv.len() != 16 || mac.len() != 32 || ct.is_empty() || ct.len() % 16 != 0 {
                    return Err(EncError::Malformed);
                }
                Ok(Self::AesCbc256WithMac { iv, ct, mac })
            }
            TYPE_RSA2048_OAEP_SHA1 => {
                if data.is_empty() || data.contains('|') {
                    return Err(EncError::Malformed);
                }
                let ct = b64(data)?;
                if ct.is_empty() {
                    return Err(EncError::Malformed);
                }
                Ok(Self::Rsa2048OaepSha1 { ct })
            }
            other => Err(EncError::UnsupportedEncType(other)),
        }
    }

    /// The EncString type number (2 or 4 for a successfully parsed value).
    pub fn enc_type(&self) -> u32 {
        match self {
            Self::AesCbc256WithMac { .. } => TYPE_AES_CBC256_HMAC_SHA256,
            Self::Rsa2048OaepSha1 { .. } => TYPE_RSA2048_OAEP_SHA1,
        }
    }

    /// Decrypt a type-2 EncString. The MAC is verified in constant time
    /// first; on mismatch this returns [`EncError::MacMismatch`] and the
    /// CBC decryptor is never invoked (REQ-CRY-003).
    pub fn decrypt_symmetric(&self, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>, EncError> {
        let Self::AesCbc256WithMac { iv, ct, mac } = self else {
            return Err(EncError::TypeMismatch {
                expected: TYPE_AES_CBC256_HMAC_SHA256,
                found: self.enc_type(),
            });
        };
        let verified = verify_mac(key.mac_key(), iv, ct, mac)?;
        aes_cbc_decrypt(key.enc_key(), verified)
    }

    /// Decrypt a type-4 EncString with the account's RSA private key.
    pub fn decrypt_rsa(&self, key: &RsaPrivateKey) -> Result<Zeroizing<Vec<u8>>, EncError> {
        let Self::Rsa2048OaepSha1 { ct } = self else {
            return Err(EncError::TypeMismatch {
                expected: TYPE_RSA2048_OAEP_SHA1,
                found: self.enc_type(),
            });
        };
        key.decrypt(rsa::Oaep::new::<sha1::Sha1>(), ct)
            .map(Zeroizing::new)
            .map_err(|_| EncError::DecryptionFailed)
    }
}

impl std::str::FromStr for EncString {
    type Err = EncError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Proof that an HMAC check passed for a specific `(iv, ct)` pair.
/// Only [`verify_mac`] constructs this; [`aes_cbc_decrypt`] requires it.
///
/// The guarantee is module-scoped: any code inside this module could
/// construct one, so do not add a second constructor — new code in this
/// module must go through [`verify_mac`] (noted on review of PR #33).
struct MacVerified<'a> {
    iv: &'a [u8],
    ct: &'a [u8],
}

/// Verify `mac == HMAC-SHA256(mac_key, iv || ct)` in constant time
/// (`verify_slice` compares without early exit).
fn verify_mac<'a>(
    mac_key: &[u8],
    iv: &'a [u8],
    ct: &'a [u8],
    mac: &[u8],
) -> Result<MacVerified<'a>, EncError> {
    // HMAC accepts a key of any length, so this cannot fail; `expect`
    // states the invariant honestly instead of mapping to an error
    // variant no caller can ever observe.
    let mut h = <HmacSha256 as Mac>::new_from_slice(mac_key)
        .expect("invariant: HMAC-SHA256 accepts keys of any length");
    h.update(iv);
    h.update(ct);
    h.verify_slice(mac).map_err(|_| EncError::MacMismatch)?;
    Ok(MacVerified { iv, ct })
}

/// AES-256-CBC decrypt with PKCS#7 unpadding. Reachable only with a
/// [`MacVerified`] token (REQ-CRY-003).
fn aes_cbc_decrypt(
    enc_key: &[u8],
    verified: MacVerified<'_>,
) -> Result<Zeroizing<Vec<u8>>, EncError> {
    #[cfg(test)]
    CBC_DECRYPT_CALLS.with(|c| c.set(c.get() + 1));
    // `enc_key` is 32 bytes by construction (`SymmetricKey` splits a
    // 64-byte key) and `verified.iv` was length-checked to 16 bytes at
    // parse time, so construction cannot fail; `expect` states that
    // invariant instead of mapping to an unreachable error variant.
    let pt = cbc::Decryptor::<aes::Aes256>::new_from_slices(enc_key, verified.iv)
        .expect("invariant: 32-byte enc_key and 16-byte iv, checked at parse/key construction")
        .decrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(verified.ct)
        .map_err(|_| EncError::DecryptionFailed)?;
    Ok(Zeroizing::new(pt))
}

// Test-only counter proving the CBC decryptor is not invoked when MAC
// verification fails (REQ-CRY-003 acceptance test). Thread-local so
// parallel tests don't interfere.
#[cfg(test)]
thread_local! {
    static CBC_DECRYPT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64ct::Encoding;
    use rsa::pkcs8::DecodePrivateKey;

    /// External vector, generated with `openssl enc -aes-256-cbc` and
    /// Python `hmac` — not with this crate — so the format is checked
    /// against an independent implementation.
    /// Key: bytes 0x00..0x40 (enc 0x00..0x20, mac 0x20..0x40).
    const TYPE2_VECTOR: &str = "2.oKGio6SlpqeoqaqrrK2urw==|3HUxX1WBbJOqEbVw85Oq4TqvrngqbgHwx/BiiBlGInc=|MhHrugkVdSorjlIHcZfinmqagailp2DbG/u49pIT2xQ=";
    const TYPE2_PLAINTEXT: &[u8] = b"kharon type-2 test vector";

    /// External vector: plaintext bytes 0x00..0x40 encrypted with
    /// `openssl pkeyutl`, RSA-OAEP-SHA1, under the throwaway fixture key
    /// in `tests/fixtures/type4-throwaway-key.pem` (generated for these
    /// tests only; never used for anything real).
    const TYPE4_CT_B64: &str = "MiHE+v1yx6Of009CSGoA4IpshdPxJl6cWObzi6HcvH6bauWyU2dK7GVi1uVn0mvTtpL05Gm/EctFiyY+JnD9rnuzg6CwxbQEkW4Bpj/jmKjB8PUZOsPNlDJbRRMJa//K9xMUXVGu5fwr93SsTpjmgd2b5j3NRyI3DgUA+eML/6d96hbu0O2lOXLwTNL1Q21w7pKW5a7fmZsWapURuoM0b7qJb6avUkmajFXGrpeRTBlq0Z6RlYrhFm5iOup2lMhZfmlqTMAZ+dItZzsdo3X9z6wgE4SA+uQQwx+uYf7gT3BATJ45WPPe8VJKViNaxbrlqkTa72qEyWJ1oEVKHiulQA==";
    const TYPE4_KEY_PEM: &str = include_str!("../tests/fixtures/type4-throwaway-key.pem");

    fn test_symmetric_key() -> SymmetricKey {
        let bytes: Vec<u8> = (0u8..64).collect();
        SymmetricKey::from_slice(&bytes).unwrap()
    }

    fn test_rsa_key() -> RsaPrivateKey {
        RsaPrivateKey::from_pkcs8_pem(TYPE4_KEY_PEM).unwrap()
    }

    /// Rebuild the type-2 vector string with one bit flipped in the
    /// chosen segment (0 = iv, 1 = ct, 2 = mac).
    fn type2_with_flipped_bit(segment: usize) -> String {
        let parsed = EncString::parse(TYPE2_VECTOR).unwrap();
        let EncString::AesCbc256WithMac {
            mut iv,
            mut ct,
            mut mac,
        } = parsed
        else {
            panic!("vector is type 2");
        };
        let target = match segment {
            0 => &mut iv,
            1 => &mut ct,
            _ => &mut mac,
        };
        target[0] ^= 0x01;
        format!(
            "2.{}|{}|{}",
            Base64::encode_string(&iv),
            Base64::encode_string(&ct),
            Base64::encode_string(&mac)
        )
    }

    #[test]
    fn req_cry_002_type2_valid_decrypts() {
        let parsed = EncString::parse(TYPE2_VECTOR).unwrap();
        assert_eq!(parsed.enc_type(), 2);
        let pt = parsed.decrypt_symmetric(&test_symmetric_key()).unwrap();
        assert_eq!(&pt[..], TYPE2_PLAINTEXT);
    }

    #[test]
    fn req_cry_002_type4_valid_decrypts() {
        let enc = format!("4.{TYPE4_CT_B64}");
        let parsed = EncString::parse(&enc).unwrap();
        assert_eq!(parsed.enc_type(), 4);
        let pt = parsed.decrypt_rsa(&test_rsa_key()).unwrap();
        let expected: Vec<u8> = (0u8..64).collect();
        assert_eq!(&pt[..], &expected[..]);
    }

    #[test]
    fn req_cry_002_unsupported_types_rejected() {
        for t in [0u32, 1, 3, 5, 6, 7] {
            let input = format!("{t}.AAAAAAAAAAAAAAAAAAAAAA==");
            assert!(
                matches!(
                    EncString::parse(&input),
                    Err(EncError::UnsupportedEncType(x)) if x == t
                ),
                "type {t} must be UnsupportedEncType"
            );
        }
    }

    #[test]
    fn req_cry_002_malformed_inputs_rejected() {
        let cases = [
            "",
            "2",
            "2.",
            ".AAAA",
            "x.AAAA",
            "2.|||",
            "2.AAAA",
            "2.AAAA|AAAA",
            "2.AAAA|AAAA|AAAA|AAAA",
            "2.!!!!|AAAA|AAAA",
            "4.",
            "4.AAAA|BBBB",
            "99999999999999999999999999.AAAA",
            " 2.AAAA|AAAA|AAAA",
        ];
        for input in cases {
            assert!(
                EncString::parse(input).is_err(),
                "input {input:?} must not parse"
            );
        }
        // Structurally valid base64 but wrong segment lengths.
        assert!(matches!(
            EncString::parse(
                "2.AAAA|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            ),
            Err(EncError::Malformed)
        ));
    }

    #[test]
    fn req_cry_003_flipped_bit_yields_mac_mismatch_and_no_decrypt() {
        let key = test_symmetric_key();
        for segment in 0..3 {
            CBC_DECRYPT_CALLS.with(|c| c.set(0));
            let tampered = EncString::parse(&type2_with_flipped_bit(segment)).unwrap();
            let err = tampered.decrypt_symmetric(&key).unwrap_err();
            assert!(
                matches!(err, EncError::MacMismatch),
                "segment {segment}: expected MacMismatch, got {err:?}"
            );
            assert_eq!(
                CBC_DECRYPT_CALLS.with(|c| c.get()),
                0,
                "segment {segment}: CBC decryptor must not run on MAC failure"
            );
        }
        // Sanity: the untampered vector does reach the decryptor, once.
        CBC_DECRYPT_CALLS.with(|c| c.set(0));
        let parsed = EncString::parse(TYPE2_VECTOR).unwrap();
        parsed.decrypt_symmetric(&key).unwrap();
        assert_eq!(CBC_DECRYPT_CALLS.with(|c| c.get()), 1);
    }

    #[test]
    fn req_cry_002_wrong_key_kind_is_type_mismatch() {
        let t2 = EncString::parse(TYPE2_VECTOR).unwrap();
        assert!(matches!(
            t2.decrypt_rsa(&test_rsa_key()),
            Err(EncError::TypeMismatch { .. })
        ));
        let t4 = EncString::parse(&format!("4.{TYPE4_CT_B64}")).unwrap();
        assert!(matches!(
            t4.decrypt_symmetric(&test_symmetric_key()),
            Err(EncError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn req_cry_002_type4_tampered_ct_fails_decryption() {
        let mut ct = Base64::decode_vec(TYPE4_CT_B64).unwrap();
        ct[10] ^= 0x01;
        let enc = format!("4.{}", Base64::encode_string(&ct));
        let parsed = EncString::parse(&enc).unwrap();
        assert!(matches!(
            parsed.decrypt_rsa(&test_rsa_key()),
            Err(EncError::DecryptionFailed)
        ));
    }

    #[test]
    fn symmetric_key_requires_64_bytes() {
        assert!(matches!(
            SymmetricKey::from_slice(&[0u8; 63]),
            Err(EncError::InvalidKeyLength)
        ));
        assert!(matches!(
            SymmetricKey::from_slice(&[0u8; 65]),
            Err(EncError::InvalidKeyLength)
        ));
        assert!(SymmetricKey::from_slice(&[0u8; 64]).is_ok());
    }

    /// Poor-man's fuzz: every truncation and single-character mutation
    /// of both vectors, plus deterministic pseudo-random inputs. The
    /// parser (and decrypt attempts on anything that parses) must never
    /// panic. The real fuzz target lives in `fuzz/`.
    #[test]
    fn req_cry_002_parse_never_panics() {
        let key = test_symmetric_key();
        let mut inputs: Vec<String> = Vec::new();
        for vector in [TYPE2_VECTOR, &format!("4.{TYPE4_CT_B64}")] {
            for i in 0..=vector.len() {
                inputs.push(vector[..i].to_string());
            }
            for i in 0..vector.len() {
                for replacement in ['A', 'z', '0', '.', '|', '=', '!', 'é'] {
                    let mut mutated = vector.to_string();
                    mutated.replace_range(i..i + 1, &replacement.to_string());
                    inputs.push(mutated);
                }
            }
        }
        // xorshift64 PRNG, fixed seed: deterministic across runs.
        let mut state: u64 = 0x853c_49e6_748f_ea9b;
        let mut rand = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        for _ in 0..2000 {
            let len = (rand() % 96) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (rand() % 128) as u8).collect();
            inputs.push(String::from_utf8_lossy(&bytes).into_owned());
        }
        for input in &inputs {
            if let Ok(parsed) = EncString::parse(input) {
                let _ = parsed.decrypt_symmetric(&key);
            }
        }
    }
}
