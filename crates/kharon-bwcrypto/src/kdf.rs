//! Master-key derivation and stretching (REQ-CRY-001), per SPEC §3.1.
//!
//! - PBKDF2-HMAC-SHA256: salt = lowercase(email), default 600 000
//!   iterations.
//! - Argon2id (version 0x13): salt = SHA-256(lowercase(email)),
//!   defaults m = 64 MiB, t = 3, p = 4. Prelogin `kdfMemory` is in MiB;
//!   the `argon2` crate takes KiB, so it is multiplied by 1024.
//! - Stretch: HKDF-Expand-SHA256 only (the master key is already a PRK —
//!   no extract step), `info = "enc"` and `info = "mac"`, 32 bytes each.
//! - Server auth hash: PBKDF2-HMAC-SHA256(master key, salt = password, 1).
//!
//! Passwords and derived keys live in [`Zeroizing`] buffers / [`MasterKey`]
//! and are wiped on drop. Callers pass the password as
//! `&Zeroizing<String>` (see [`derive_master_key`]) so the plaintext's
//! owner and wiping are unambiguous.
//!
//! The prelogin response is server-supplied and the server is untrusted,
//! so KDF parameters are range-checked against Bitwarden's own client
//! bounds before any derivation (see [`Kdf::validate`]): a hostile or
//! compromised server must not be able to talk kharon into deriving a
//! cheaply crackable master key (and then receiving the auth hash), nor
//! into an Argon2 allocation that OOMs the client.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encstring::SymmetricKey;

/// Prelogin KDF type numbers (`POST /identity/accounts/prelogin`).
const KDF_TYPE_PBKDF2: u32 = 0;
const KDF_TYPE_ARGON2ID: u32 = 1;

/// PBKDF2 iteration floor. The current server default is 600 000, but
/// Bitwarden's hard client minimum is 5 000 and pre-default accounts
/// legitimately sit between the two — so 5 000 is the floor, stated
/// explicitly: anything below it is refused, anything at or above it is
/// a (possibly legacy) account setting, not an attack signal by itself.
pub const PBKDF2_MIN_ITERATIONS: u32 = 5_000;
/// PBKDF2 iteration ceiling (Bitwarden's documented maximum): bounds
/// the CPU a hostile prelogin response can make the client burn.
pub const PBKDF2_MAX_ITERATIONS: u32 = 2_000_000;
/// Argon2id time-cost floor (Bitwarden minimum; the default is 3).
pub const ARGON2_MIN_ITERATIONS: u32 = 2;
/// Argon2id time-cost ceiling (Bitwarden maximum).
pub const ARGON2_MAX_ITERATIONS: u32 = 10;
/// Argon2id memory floor in MiB (Bitwarden minimum; the default is 64).
pub const ARGON2_MIN_MEMORY_MIB: u32 = 16;
/// Argon2id memory ceiling in MiB (Bitwarden maximum): a hostile
/// prelogin response must not be able to OOM the client.
pub const ARGON2_MAX_MEMORY_MIB: u32 = 1_024;
/// Argon2id parallelism floor (also the default is 4, but 1 is valid).
pub const ARGON2_MIN_PARALLELISM: u32 = 1;
/// Argon2id parallelism ceiling (Bitwarden maximum).
pub const ARGON2_MAX_PARALLELISM: u32 = 16;

/// KDF parameters from the prelogin response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kdf {
    /// PBKDF2-HMAC-SHA256 with the given iteration count.
    Pbkdf2 {
        /// Iteration count (Bitwarden default: 600 000).
        iterations: u32,
    },
    /// Argon2id with the given parameters.
    Argon2id {
        /// Time cost (passes).
        iterations: u32,
        /// Memory cost in MiB, as reported by prelogin.
        memory_mib: u32,
        /// Parallelism (lanes).
        parallelism: u32,
    },
}

/// Errors from KDF parameter parsing and derivation.
#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    /// The prelogin `kdf` type is not one kharon implements (fail closed).
    #[error("unsupported KDF type: {0}")]
    UnsupportedKdf(u32),
    /// A KDF parameter is zero or out of range.
    #[error("invalid KDF parameter: {0}")]
    InvalidParams(&'static str),
    /// The underlying KDF rejected the parameters or failed.
    #[error("key derivation failed")]
    DerivationFailed,
}

impl Kdf {
    /// Build from prelogin fields. `kdf_memory` / `kdf_parallelism` are
    /// only meaningful for Argon2id and may be `None` for PBKDF2.
    /// Parameters are range-checked by [`Kdf::validate`].
    pub fn from_prelogin(
        kdf_type: u32,
        iterations: u32,
        kdf_memory_mib: Option<u32>,
        kdf_parallelism: Option<u32>,
    ) -> Result<Self, KdfError> {
        let kdf = match kdf_type {
            KDF_TYPE_PBKDF2 => Self::Pbkdf2 { iterations },
            KDF_TYPE_ARGON2ID => Self::Argon2id {
                iterations,
                memory_mib: kdf_memory_mib
                    .ok_or(KdfError::InvalidParams("argon2id memory missing"))?,
                parallelism: kdf_parallelism
                    .ok_or(KdfError::InvalidParams("argon2id parallelism missing"))?,
            },
            other => return Err(KdfError::UnsupportedKdf(other)),
        };
        kdf.validate()?;
        Ok(kdf)
    }

    /// Range-check the parameters against Bitwarden's client bounds
    /// (see the `*_MIN_*` / `*_MAX_*` constants). The prelogin response
    /// is untrusted: below-floor parameters would make the derived
    /// master key — and the auth hash sent back to that server —
    /// crackable at negligible cost, and above-ceiling parameters are
    /// a CPU/memory denial of service against the client. Enforced in
    /// [`Kdf::from_prelogin`] and again in [`derive_master_key`], so
    /// direct construction cannot bypass it.
    pub fn validate(&self) -> Result<(), KdfError> {
        match *self {
            Self::Pbkdf2 { iterations } => {
                if !(PBKDF2_MIN_ITERATIONS..=PBKDF2_MAX_ITERATIONS).contains(&iterations) {
                    return Err(KdfError::InvalidParams(
                        "pbkdf2 iterations outside 5_000..=2_000_000",
                    ));
                }
            }
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                if !(ARGON2_MIN_ITERATIONS..=ARGON2_MAX_ITERATIONS).contains(&iterations) {
                    return Err(KdfError::InvalidParams(
                        "argon2id iterations outside 2..=10",
                    ));
                }
                if !(ARGON2_MIN_MEMORY_MIB..=ARGON2_MAX_MEMORY_MIB).contains(&memory_mib) {
                    return Err(KdfError::InvalidParams(
                        "argon2id memory outside 16..=1024 MiB",
                    ));
                }
                if !(ARGON2_MIN_PARALLELISM..=ARGON2_MAX_PARALLELISM).contains(&parallelism) {
                    return Err(KdfError::InvalidParams(
                        "argon2id parallelism outside 1..=16",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The 32-byte master key. Zeroized on drop; `Debug` prints no key bytes.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    /// The stretched master key (64 B: `enc_key || mac_key`) used to
    /// unwrap the user key.
    pub fn stretch(&self) -> SymmetricKey {
        let hk = Hkdf::<Sha256>::from_prk(&self.0[..])
            .expect("invariant: a 32-byte PRK is valid for HKDF-SHA256");
        let mut out = Zeroizing::new([0u8; 64]);
        hk.expand(b"enc", &mut out[..32])
            .expect("invariant: 32-byte HKDF output is within length limits");
        hk.expand(b"mac", &mut out[32..])
            .expect("invariant: 32-byte HKDF output is within length limits");
        SymmetricKey::from_slice(&out[..]).expect("invariant: stretched key is exactly 64 bytes")
    }

    /// Server auth hash: PBKDF2-HMAC-SHA256(master key, salt = password,
    /// 1 iteration). Not needed for API-key login, but needed for password
    /// login and `/accounts/verify-password` (SPEC §3.1).
    pub fn password_hash(&self, password: &Zeroizing<String>) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(self.0.as_ref(), password.as_bytes(), 1, &mut out[..]);
        out
    }
}

/// Bitwarden salts are the account email, trimmed and lowercased.
fn normalized_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Derive the 32-byte master key from the master password, the account
/// email, and the prelogin KDF parameters (REQ-CRY-001).
///
/// The password is taken as `&Zeroizing<String>`: the caller keeps the
/// plaintext in a buffer that wipes on drop, and this function never
/// copies it into an un-wiped buffer of its own (the KDF internals are
/// a documented exception — see `docs/crypto.md`, "Zeroization
/// limits"). The KDF parameters are re-validated here so a directly
/// constructed [`Kdf`] cannot bypass the prelogin bounds.
pub fn derive_master_key(
    password: &Zeroizing<String>,
    email: &str,
    kdf: &Kdf,
) -> Result<MasterKey, KdfError> {
    kdf.validate()?;
    let email = normalized_email(email);
    let mut out = Zeroizing::new([0u8; 32]);
    match *kdf {
        Kdf::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                email.as_bytes(),
                iterations,
                &mut out[..],
            );
        }
        Kdf::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            let memory_kib = memory_mib
                .checked_mul(1024)
                .ok_or(KdfError::InvalidParams("argon2id memory overflows KiB"))?;
            let params = Params::new(memory_kib, iterations, parallelism, Some(32))
                .map_err(|_| KdfError::InvalidParams("argon2id parameters out of range"))?;
            let salt = Sha256::digest(email.as_bytes());
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt, &mut out[..])
                .map_err(|_| KdfError::DerivationFailed)?;
        }
    }
    Ok(MasterKey(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    // All vectors in this module were generated with independent
    // implementations — Python `hashlib.pbkdf2_hmac`, `argon2-cffi`
    // (libargon2), and a hand-rolled RFC 5869 HKDF-Expand over Python
    // `hmac` — never with this crate. The generator is committed at
    // `tests/fixtures/gen/gen_kdf_vectors.py` (pinned versions in its
    // header) and reproduces every constant below. Fixture account:
    // email `Kharon-Fixture@Example.com` (mixed case on purpose: the
    // salt is the lowercased form), password below. KDF parameters are
    // deliberately non-default (PBKDF2 123 456 iterations vs the 600 000
    // default; Argon2id m = 32 MiB / t = 2 / p = 2 vs the 64/3/4
    // defaults), as REQ-CRY-001's acceptance criterion requires.
    const EMAIL: &str = "Kharon-Fixture@Example.com";
    const PASSWORD: &str = "kharon fixture password 7";

    fn password() -> Zeroizing<String> {
        Zeroizing::new(PASSWORD.to_string())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn req_cry_001_pbkdf2_nondefault_params_match_vector() {
        let kdf = Kdf::from_prelogin(0, 123_456, None, None).unwrap();
        let master = derive_master_key(&password(), EMAIL, &kdf).unwrap();
        assert_eq!(
            hex(&master.0[..]),
            "5ea111139336d17e265f1935527ead750c0f9007e7a054a050d1fca0730ec549"
        );
    }

    #[test]
    fn req_cry_001_argon2id_nondefault_params_match_vector() {
        let kdf = Kdf::from_prelogin(1, 2, Some(32), Some(2)).unwrap();
        let master = derive_master_key(&password(), EMAIL, &kdf).unwrap();
        assert_eq!(
            hex(&master.0[..]),
            "30773da8d8818c524e69c134da04b0ff9fd8af72c816c44b9211b21afa68a0ff"
        );
    }

    #[test]
    fn req_cry_001_email_is_lowercased_before_salting() {
        let kdf = Kdf::Pbkdf2 { iterations: 5_000 };
        let a = derive_master_key(&password(), "Kharon-Fixture@Example.com", &kdf).unwrap();
        let b = derive_master_key(&password(), "  kharon-fixture@example.com ", &kdf).unwrap();
        assert_eq!(&a.0[..], &b.0[..]);
    }

    #[test]
    fn req_cry_001_stretch_matches_hkdf_expand_vector() {
        let kdf = Kdf::from_prelogin(0, 123_456, None, None).unwrap();
        let master = derive_master_key(&password(), EMAIL, &kdf).unwrap();
        let stretched = master.stretch();
        // Compare through the public consumer: unwrapping is covered in
        // keys.rs; here the raw stretched bytes are checked via the
        // test-only accessor on SymmetricKey.
        assert_eq!(
            hex(stretched.as_bytes_for_test()),
            "0f113f396c5d8779a46cdff12bdd14c22a795094f860de7eb03abb6153947956\
             ea313c0287d85245fb601197f09d2d2203911a0f03d1206c8642378625ddd4c6"
        );
    }

    #[test]
    fn req_cry_001_password_hash_matches_vector() {
        let kdf = Kdf::from_prelogin(0, 123_456, None, None).unwrap();
        let master = derive_master_key(&password(), EMAIL, &kdf).unwrap();
        assert_eq!(
            hex(&master.password_hash(&password())[..]),
            "9ccb246223d23dcb09ba04d15859b49fd89acfee120874de8edbfe28ccf79f9b"
        );
    }

    #[test]
    fn req_cry_001_invalid_params_fail_closed() {
        assert!(matches!(
            Kdf::from_prelogin(2, 600_000, None, None),
            Err(KdfError::UnsupportedKdf(2))
        ));
        assert!(matches!(
            Kdf::from_prelogin(0, 0, None, None),
            Err(KdfError::InvalidParams(_))
        ));
        assert!(matches!(
            Kdf::from_prelogin(1, 3, None, Some(4)),
            Err(KdfError::InvalidParams(_))
        ));
        assert!(matches!(
            Kdf::from_prelogin(1, 3, Some(64), Some(0)),
            Err(KdfError::InvalidParams(_))
        ));
        // Memory that overflows the KiB conversion is rejected, not wrapped.
        let kdf = Kdf::Argon2id {
            iterations: 3,
            memory_mib: u32::MAX,
            parallelism: 4,
        };
        assert!(derive_master_key(&password(), EMAIL, &kdf).is_err());
    }

    #[test]
    fn req_cry_001_kdf_bounds_enforced() {
        // The prelogin response is untrusted (PR #34 review, Nyx):
        // every bound is refused below/above, accepted at the edge.
        // PBKDF2 iterations: floor is the explicit legacy minimum
        // 5_000 (server default is 600_000), ceiling 2_000_000.
        for (iters, ok) in [
            (0, false),
            (1, false),
            (4_999, false),
            (5_000, true),
            (600_000, true),
            (2_000_000, true),
            (2_000_001, false),
            (u32::MAX, false),
        ] {
            assert_eq!(
                Kdf::from_prelogin(0, iters, None, None).is_ok(),
                ok,
                "pbkdf2 iterations={iters}"
            );
        }
        // Argon2id time cost: 2..=10.
        for (t, ok) in [(1, false), (2, true), (10, true), (11, false)] {
            assert_eq!(
                Kdf::from_prelogin(1, t, Some(64), Some(4)).is_ok(),
                ok,
                "argon2id t={t}"
            );
        }
        // Argon2id memory: 16..=1024 MiB.
        for (m, ok) in [
            (1, false),
            (15, false),
            (16, true),
            (1_024, true),
            (1_025, false),
        ] {
            assert_eq!(
                Kdf::from_prelogin(1, 3, Some(m), Some(4)).is_ok(),
                ok,
                "argon2id m={m}"
            );
        }
        // Argon2id parallelism: 1..=16.
        for (p, ok) in [(0, false), (1, true), (16, true), (17, false)] {
            assert_eq!(
                Kdf::from_prelogin(1, 3, Some(64), Some(p)).is_ok(),
                ok,
                "argon2id p={p}"
            );
        }
        // Direct construction cannot bypass the bounds at derive time.
        let cheap = Kdf::Pbkdf2 { iterations: 1 };
        assert!(matches!(
            derive_master_key(&password(), EMAIL, &cheap),
            Err(KdfError::InvalidParams(_))
        ));
        let huge = Kdf::Argon2id {
            iterations: 3,
            memory_mib: 1_025,
            parallelism: 4,
        };
        assert!(matches!(
            derive_master_key(&password(), EMAIL, &huge),
            Err(KdfError::InvalidParams(_))
        ));
    }
}
