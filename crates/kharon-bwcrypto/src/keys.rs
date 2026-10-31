//! The key unwrap chain (REQ-CRY-004):
//! stretched master key → user key → RSA private key → org key →
//! optional per-cipher key → item fields.
//!
//! Type-4 (RSA-OAEP) unwraps enforce the RUSTSEC-2023-0071 mitigation
//! invariant recorded in `deny.toml` and SPEC §3.1 review history: the
//! org key is unwrapped **exactly once per unlock per org** and cached
//! (never per sync), and after any type-4 unwrap failure no further
//! type-4 unwraps are attempted until the next unlock (a fresh
//! [`OrgKeyUnwrapper`]). A hostile server can serve chosen type-4
//! ciphertexts, so two further bounds keep it from turning distinct
//! fake org IDs into an unbounded decryption oracle (PR #34 review):
//! an optional allow-list of the profile's organization IDs (orgs not
//! on it are refused *without* decrypting), and a hard cap of
//! [`MAX_ORG_UNWRAPS_PER_UNLOCK`] distinct-org decrypts per unlock,
//! exceeding which poisons the session like a failure does.

use std::collections::{HashMap, HashSet};

use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use zeroize::Zeroizing;

use crate::encstring::{EncError, EncString, SymmetricKey};

/// Unwrap the user key: a type-2 EncString under the stretched master
/// key whose plaintext is the 64-byte user key.
pub fn unwrap_user_key(
    protected_user_key: &EncString,
    stretched_master_key: &SymmetricKey,
) -> Result<SymmetricKey, EncError> {
    let pt = protected_user_key.decrypt_symmetric(stretched_master_key)?;
    SymmetricKey::from_slice(&pt)
}

/// Unwrap the account RSA private key: a type-2 EncString under the
/// user key whose plaintext is the PKCS#8 DER encoding of the key.
/// Parse errors map to [`EncError::DecryptionFailed`] so no detail
/// about the plaintext leaks through the error.
pub fn unwrap_private_key(
    protected_private_key: &EncString,
    user_key: &SymmetricKey,
) -> Result<RsaPrivateKey, EncError> {
    let der = protected_private_key.decrypt_symmetric(user_key)?;
    RsaPrivateKey::from_pkcs8_der(&der).map_err(|_| EncError::DecryptionFailed)
}

/// Unwrap a per-cipher key: a type-2 EncString under the org key whose
/// plaintext is the cipher's own 64-byte symmetric key.
pub fn unwrap_cipher_key(
    protected_cipher_key: &EncString,
    org_key: &SymmetricKey,
) -> Result<SymmetricKey, EncError> {
    let pt = protected_cipher_key.decrypt_symmetric(org_key)?;
    SymmetricKey::from_slice(&pt)
}

/// Decrypt an item field. Fields are under the cipher key when the
/// cipher has one (`cipher.key` present), otherwise directly under the
/// org key (REQ-CRY-004, both halves of the acceptance criterion).
pub fn decrypt_item_field(
    field: &EncString,
    org_key: &SymmetricKey,
    cipher_key: Option<&SymmetricKey>,
) -> Result<Zeroizing<Vec<u8>>, EncError> {
    field.decrypt_symmetric(cipher_key.unwrap_or(org_key))
}

/// Hard cap on distinct-org type-4 decrypts per unlock session.
/// Real accounts belong to a handful of organizations; a server
/// offering more distinct org keys than this in one unlock is
/// harvesting RSA timing samples, so exceeding the cap poisons the
/// session (same as a failed unwrap). The allow-list
/// ([`OrgKeyUnwrapper::with_allowed_orgs`]) normally binds tighter.
pub const MAX_ORG_UNWRAPS_PER_UNLOCK: usize = 16;

/// One cached org key plus the protected ciphertext it came from, so a
/// later call presenting a *different* ciphertext for the same org is
/// noticed instead of silently ignored.
struct CachedOrgKey {
    key: SymmetricKey,
    protected_ct: Vec<u8>,
}

/// Bitwarden organization IDs are GUIDs; case spellings of the same ID
/// must not become two cache entries (and two decrypts). Normalize by
/// trimming and lowercasing before any cache/allow-list use.
fn normalize_org_id(org_id: &str) -> String {
    org_id.trim().to_lowercase()
}

/// Stateful org-key unwrapper for one unlock session. See the module
/// docs for the once-per-unlock + fail-poisoned invariant.
pub struct OrgKeyUnwrapper {
    private_key: RsaPrivateKey,
    cache: HashMap<String, CachedOrgKey>,
    allowed_orgs: Option<HashSet<String>>,
    decrypt_count: usize,
    mismatched_orgs: HashSet<String>,
    poisoned: bool,
}

impl OrgKeyUnwrapper {
    /// Start a fresh unlock session with the unwrapped private key,
    /// without an organization allow-list (the per-unlock decrypt cap
    /// still applies). Prefer [`OrgKeyUnwrapper::with_allowed_orgs`]
    /// whenever the profile's organization list is known.
    pub fn new(private_key: RsaPrivateKey) -> Self {
        Self {
            private_key,
            cache: HashMap::new(),
            allowed_orgs: None,
            decrypt_count: 0,
            mismatched_orgs: HashSet::new(),
            poisoned: false,
        }
    }

    /// Start a fresh unlock session restricted to the given
    /// organization IDs (the profile's `organizations` list). Unwraps
    /// for any other org are refused *without* decrypting and without
    /// poisoning: the server gets no timing sample and the listed
    /// orgs are unaffected.
    pub fn with_allowed_orgs(
        private_key: RsaPrivateKey,
        allowed_orgs: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        Self {
            allowed_orgs: Some(
                allowed_orgs
                    .into_iter()
                    .map(|id| normalize_org_id(id.as_ref()))
                    .collect(),
            ),
            ..Self::new(private_key)
        }
    }

    /// Unwrap an organization's key (type 4). A second call for the
    /// same org returns the cached key **without** decrypting again —
    /// even if handed a different ciphertext; in that case the cached
    /// key is still returned (no decrypt happens, so the oracle bound
    /// holds) but the org is flagged in
    /// [`OrgKeyUnwrapper::ciphertext_mismatch`] so the caller can
    /// audit-log possible org-key rotation or server misbehaviour.
    /// On any decrypt failure — or once the per-unlock distinct-org
    /// cap is exceeded — the session is poisoned: every later call
    /// returns [`EncError::Type4UnwrapRefused`] until the next unlock.
    pub fn unwrap_org_key(
        &mut self,
        org_id: &str,
        protected_org_key: &EncString,
    ) -> Result<&SymmetricKey, EncError> {
        if self.poisoned {
            return Err(EncError::Type4UnwrapRefused);
        }
        let org_id = normalize_org_id(org_id);
        if let Some(cached) = self.cache.get(&org_id) {
            if cached.protected_ct != protected_org_key.ciphertext_bytes() {
                self.mismatched_orgs.insert(org_id.clone());
            }
            return Ok(&self
                .cache
                .get(&org_id)
                .expect("invariant: checked above")
                .key);
        }
        if let Some(allowed) = &self.allowed_orgs
            && !allowed.contains(&org_id)
        {
            return Err(EncError::Type4UnwrapRefused);
        }
        if self.decrypt_count >= MAX_ORG_UNWRAPS_PER_UNLOCK {
            self.poisoned = true;
            return Err(EncError::Type4UnwrapRefused);
        }
        self.decrypt_count += 1;
        let key = protected_org_key
            .decrypt_rsa(&self.private_key)
            .and_then(|pt| SymmetricKey::from_slice(&pt));
        match key {
            Ok(key) => {
                self.cache.insert(
                    org_id.clone(),
                    CachedOrgKey {
                        key,
                        protected_ct: protected_org_key.ciphertext_bytes().to_vec(),
                    },
                );
            }
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        }
        Ok(&self
            .cache
            .get(&org_id)
            .expect("invariant: just inserted")
            .key)
    }

    /// The cached org key, if this org was already unwrapped in this
    /// unlock session. Never triggers a decrypt.
    pub fn org_key(&self, org_id: &str) -> Option<&SymmetricKey> {
        self.cache
            .get(&normalize_org_id(org_id))
            .map(|cached| &cached.key)
    }

    /// Whether a later call presented a different protected ciphertext
    /// for this org than the one originally unwrapped (possible key
    /// rotation or server misbehaviour). The cached key was returned
    /// regardless and no extra decrypt happened; callers should
    /// audit-log this.
    pub fn ciphertext_mismatch(&self, org_id: &str) -> bool {
        self.mismatched_orgs.contains(&normalize_org_id(org_id))
    }

    /// How many type-4 decrypts this session has performed.
    pub fn decrypt_count(&self) -> usize {
        self.decrypt_count
    }

    /// Whether a type-4 failure (or the per-unlock cap) has poisoned
    /// this unlock session.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{Kdf, derive_master_key};

    // Chain vectors generated with independent implementations —
    // Python `hashlib`/`hmac` for the KDF and type-2 encryption,
    // `cryptography` (OpenSSL) for AES-CBC, the RSA key, and the
    // RSA-OAEP-SHA1 type-4 ciphertext — never with this crate. The
    // RSA key is the throwaway fixture in
    // `tests/fixtures/chain-throwaway-key.pem`, generated for these
    // tests only; the generator is committed at
    // `tests/fixtures/gen/gen_chain_vectors.py` (pinned versions in
    // its header). KDF side: PBKDF2, 123 456 iterations, email
    // `Kharon-Fixture@Example.com`, password below (same fixture as
    // kdf.rs). Plaintext keys are sequential byte ranges, so a wrong
    // unwrap cannot accidentally match.
    const EMAIL: &str = "Kharon-Fixture@Example.com";
    const PASSWORD: &str = "kharon fixture password 7";

    const PROTECTED_USER_KEY: &str = "2.EBESExQVFhcYGRobHB0eHw==|0Bz61C9h5CAqQGtK7J91Ns8aXVaBasnXoxlZl2wh31IVth3F3KoosmoxRjN5jtDsivF52WNyDyAT0yK+JsWQPrhOYG79h8CQyt2pXlPDM3k=|4YMXhkdVUZA1TpYFmNzQvU9xyiSlpDPeJOJFfPEp/Dg=";
    const PROTECTED_PRIVATE_KEY: &str = "2.ICEiIyQlJicoKSorLC0uLw==|iomroRk9ARSoH0tnE8oP4I00LTxsOo7AmTeHhc6GplX3yBnzx4eat8IklFFaALjDJ4Q+rGVpv++TXH08B4KJ0r+YS+nXlf5HE82T0ZxdDwR2BlFniNaHIZ6Rgx5ll9/JwhGfwag/bXWoM5PVyrsR/uxemsp+4k9DFKg9tnwdvTkERRgFXXD/Pw5jFaWGp5IcN8dZbFD9w+yD1LMJdgbVKtuSdBHS8k3+++TiVmLTu6S8z2jqUiTy9rUEUz+NO2Q6omVim4DqpIaCx8fKs0MhXwyvauwnmXfGgm7hoemGHKy7nKkXI3Yu7hfMVkdfiNhANsd1ifZBwLwczk74AsrW2EeWJt0mpgDFl4xlCtI4/6hgxmSaZZ+d0QK7uAo88a/Ksd22QJi1TCi4DwwXtkYTjN7gfpcU7piTBgGNGtGixarIQN08O2sgI0nQr9+wYYyrYZaRqja0sB/25Lebq/McGi25LcDB3h681jnTtJHIkyjSHcg9YfgmPKsRyc1K8bALrLydofFGFEyvBAR/tMquDgkOvSIWlXB7OTZTZj2rRlaP9+plbOfuwgxPqKV5vW3gYzcI/5y9gxVAw8aghpuvquQNckASqqbd2YkX9c8cnKQuOY+ki36A+Atcbe0usEeYmkih18KW4XVvNJLv71O6UgmqSOzRc/ocrCE1b2J6Bstsi64CDWF8fICloBmXa12Cp/WqMaX4iJmK97XV3X4IzM2LrotRWtbzvAlVib+OW3G31H/pK/3AFUfhiKiejbwdUbjmEA9XShuIED8BORH9/7ohp3kT3jFnO9glMNHTpMup4qCJ+Q1Qb94wG6b8QJUHWHGMYpiGB2MFO88j6xuyknq1XYIxLUbQe5N/JlFRIHSbKnNdHwko7XatA1K7X91MHSrAEK7YmGxWCVmRShZZ0IWUGjid9kir2+gG/At4acy6y22sL/NoXhxXyuVV6HlQT2dr0Fq9GNfTJTF4m0Ka+sCl8NB+aGnLK88YCAROuV8rL4Z5ymlbMPqsfn0ksady+gSNOs/o2Z68TabCEL6YWZYM2I6InuiJ2CVF2uSn1NmI2vs0iPKEU7QemwGl8DuFczSN5LZppXha4GHJ+uYqYi0u0cEKuTu/lWFfknqPe1/Bjb5f/YV49qTnmaUCRMaOuzDNsmgk0VI1kCgRKSeWNpVN7puVWEqBTEeIfcTLsA2KaS2P5gRhbgD6e20D2+uuxg9Q/sxFYeJQeXOD6Jw2RZIF4ZQwnUlkS4Lgc5kESdeJMCT85R04JyWpU1xKipjF4vh630rbuh+Y6kOS5CzcrqgF3txDPOcUL+NAuG579R+AZqdp19FLnc2jXtl0FpIgoiy58s8U+leJUJNawWFZAjrGCJ6HKJonAuKYoXKrOg5OdfqtMeNJH6TlA8hovdxspnhEfJMDPM9SgBHv3Hr7P6C5okEMGuO694SGHDHteRfZkX5U5eZKJb49XOFA1YbWeTbXBYF4I6XeP6YUyGrzx8xW9pmh3/uhcDqE2apjmq1BXausIFJbp/mzSNzHzE29VFnAlj9rReCsD4qVQ5NFfiaHlweiOfSoFOMcCmjNm9W+0bncKj16Zwnf9IB5fYLQzOoVNF9FO09Zqxn5Jngu6xnxSbVR62q+v0t6QzfMDc4=|m7U+Z6h5xoyVO2Pn6lgECGZkOdgDhid6gwQWkn4OSkk=";
    const PROTECTED_ORG_KEY: &str = "4.Q+AvDzsmD29WnO/jw8TywxTlO4HFezLIlwwQ4o9593eJDS7mSE0qld5J77DjxrQ+t0ZzrmAmS8EynsWevv88uU3tj4EJikhgu6b10WXXz6gNaZJ1sBYUrwzCfpC7FBEQ7DWBLZxh2cb+EhuqvHT5VQmB3BnW34wQkh/11hLMlJv0MvkG9rX+qnu0l9/G1ce73XyEstbWeC1xCb4oyGK58u4NmUhZpi53dYM0Jxx7eyh4atJ9OteGpWCLJxpd+6D/eN8dkTBLMsZeTNQbuwkMGS6J+d0z9gxrB4ywEGJK4T7hO9tdI1IvnK6fdAcl2KBVDx2A2x3jLJA/ii0aQLd4Wg==";
    const FIELD_NO_CIPHER_KEY: &str = "2.MDEyMzQ1Njc4OTo7PD0+Pw==|VXuldSSjyY2Glz5GPu1LKa5U35otBWOKaizxv6pNnCU=|oEL8noo8t+IzAMXTc8nQ7IU/mQlthVdhxzHWrVltxTs=";
    const PROTECTED_CIPHER_KEY: &str = "2.QEFCQ0RFRkdISUpLTE1OTw==|hYoBACrCGnHG3Rpw+iO+SMhuGNMCQOSn05DXfsJfb4P5PEsGImQDfaDU/vu4DdLgDcgYt+anZU21FRIlXYovGbcUbGm+8m7UzHipRlMRhhc=|qNdSQgppuMTJ1wqeKKzV9gXgow4lK7/iA4OlsBhTtPk=";
    const FIELD_WITH_CIPHER_KEY: &str = "2.UFFSU1RVVldYWVpbXF1eXw==|b8+ANDH66QxUhrxfWq7bd1Ulu4yjDXCDdwcgABnMSDo=|RGNanYJlb7YwH3RE5SwowwifxpZm8C4mU6n4iWPTdXY=";

    fn range(start: u32) -> Vec<u8> {
        (start..start + 64).map(|b| b as u8).collect()
    }

    /// Walk the whole chain from the password, asserting each
    /// unwrapped key byte-for-byte.
    fn full_chain() -> (SymmetricKey, OrgKeyUnwrapper) {
        let master = derive_master_key(
            &Zeroizing::new(PASSWORD.to_string()),
            EMAIL,
            &Kdf::Pbkdf2 {
                iterations: 123_456,
            },
        )
        .unwrap();
        let user_key = unwrap_user_key(
            &EncString::parse(PROTECTED_USER_KEY).unwrap(),
            &master.stretch(),
        )
        .unwrap();
        assert_eq!(user_key.as_bytes_for_test(), &range(0x40)[..]);
        let private_key =
            unwrap_private_key(&EncString::parse(PROTECTED_PRIVATE_KEY).unwrap(), &user_key)
                .unwrap();
        (user_key, OrgKeyUnwrapper::new(private_key))
    }

    #[test]
    fn req_cry_004_decrypts_item_without_cipher_key() {
        let (_user, mut unwrapper) = full_chain();
        let org_key = unwrapper
            .unwrap_org_key("org-fixture", &EncString::parse(PROTECTED_ORG_KEY).unwrap())
            .unwrap();
        assert_eq!(org_key.as_bytes_for_test(), &range(0x80)[..]);
        let field = EncString::parse(FIELD_NO_CIPHER_KEY).unwrap();
        let pt = decrypt_item_field(&field, org_key, None).unwrap();
        assert_eq!(&pt[..], b"fixture-item-password-123");
    }

    #[test]
    fn req_cry_004_decrypts_item_with_cipher_key() {
        let (_user, mut unwrapper) = full_chain();
        // Clone-out via a scoped unwrap: copy the org key bytes into an
        // owned key so the cipher unwrap doesn't fight the borrow.
        let org_key_bytes = {
            let org_key = unwrapper
                .unwrap_org_key("org-fixture", &EncString::parse(PROTECTED_ORG_KEY).unwrap())
                .unwrap();
            Zeroizing::new(org_key.as_bytes_for_test().to_vec())
        };
        let org_key = SymmetricKey::from_slice(&org_key_bytes).unwrap();
        let cipher_key =
            unwrap_cipher_key(&EncString::parse(PROTECTED_CIPHER_KEY).unwrap(), &org_key).unwrap();
        assert_eq!(cipher_key.as_bytes_for_test(), &range(0xC0)[..]);
        let field = EncString::parse(FIELD_WITH_CIPHER_KEY).unwrap();
        let pt = decrypt_item_field(&field, &org_key, Some(&cipher_key)).unwrap();
        assert_eq!(&pt[..], b"cipher-key-item-password-456");
    }

    #[test]
    fn req_cry_004_cache_hit_never_redecrypts_and_flags_new_ciphertext() {
        let (_user, mut unwrapper) = full_chain();
        let protected = EncString::parse(PROTECTED_ORG_KEY).unwrap();
        unwrapper.unwrap_org_key("org-fixture", &protected).unwrap();
        // Same ciphertext again: cache hit, no flag.
        unwrapper.unwrap_org_key("org-fixture", &protected).unwrap();
        assert!(!unwrapper.ciphertext_mismatch("org-fixture"));
        // A *different* ciphertext for the same org: the cached key is
        // still returned without decrypting (a re-decrypt of this
        // garbage would fail and poison), but the mismatch is flagged
        // for the caller's audit log — rotation or server misbehaviour
        // must not pass silently.
        let garbage = EncString::parse(&format!("4.{}==", "A".repeat(342))).unwrap();
        let again = unwrapper.unwrap_org_key("org-fixture", &garbage).unwrap();
        assert_eq!(again.as_bytes_for_test(), &range(0x80)[..]);
        assert!(!unwrapper.is_poisoned());
        assert_eq!(unwrapper.decrypt_count(), 1);
        assert!(unwrapper.ciphertext_mismatch("org-fixture"));
    }

    #[test]
    fn req_cry_004_org_id_case_is_normalized() {
        let (_user, mut unwrapper) = full_chain();
        let protected = EncString::parse(PROTECTED_ORG_KEY).unwrap();
        unwrapper.unwrap_org_key("Org-Fixture", &protected).unwrap();
        // The same GUID in another case spelling is the same cache
        // entry — not a second decrypt.
        assert!(unwrapper.org_key("ORG-FIXTURE").is_some());
        let garbage = EncString::parse(&format!("4.{}==", "A".repeat(342))).unwrap();
        let again = unwrapper.unwrap_org_key("org-fixture", &garbage).unwrap();
        assert_eq!(again.as_bytes_for_test(), &range(0x80)[..]);
        assert_eq!(unwrapper.decrypt_count(), 1);
    }

    /// The fixture account's RSA private key, unwrapped via the chain.
    fn fixture_private_key() -> RsaPrivateKey {
        let (user_key, _unwrapper) = full_chain();
        unwrap_private_key(&EncString::parse(PROTECTED_PRIVATE_KEY).unwrap(), &user_key).unwrap()
    }

    #[test]
    fn req_cry_004_allow_list_refuses_unlisted_without_decrypt_or_poison() {
        let mut listed = OrgKeyUnwrapper::with_allowed_orgs(fixture_private_key(), ["Org-Fixture"]);
        let protected = EncString::parse(PROTECTED_ORG_KEY).unwrap();
        // Unlisted org with a *valid* ciphertext: refused, no decrypt
        // performed, session not poisoned.
        assert!(matches!(
            listed.unwrap_org_key("org-other", &protected),
            Err(EncError::Type4UnwrapRefused)
        ));
        assert_eq!(listed.decrypt_count(), 0);
        assert!(!listed.is_poisoned());
        // The listed org (any case spelling) still unwraps afterwards.
        let key = listed.unwrap_org_key("org-fixture", &protected).unwrap();
        assert_eq!(key.as_bytes_for_test(), &range(0x80)[..]);
    }

    #[test]
    fn req_cry_004_distinct_org_decrypts_are_capped_per_unlock() {
        let (_user, mut unwrapper) = full_chain();
        let protected = EncString::parse(PROTECTED_ORG_KEY).unwrap();
        // The same valid ciphertext under MAX distinct org IDs: each
        // is a cache miss and a real decrypt.
        for i in 0..MAX_ORG_UNWRAPS_PER_UNLOCK {
            unwrapper
                .unwrap_org_key(&format!("org-{i}"), &protected)
                .unwrap();
        }
        assert_eq!(unwrapper.decrypt_count(), MAX_ORG_UNWRAPS_PER_UNLOCK);
        // One more distinct org exceeds the cap: refused, poisoned —
        // a server minting fake org IDs gets no further samples.
        assert!(matches!(
            unwrapper.unwrap_org_key("org-one-too-many", &protected),
            Err(EncError::Type4UnwrapRefused)
        ));
        assert!(unwrapper.is_poisoned());
    }

    #[test]
    fn req_cry_004_failed_type4_unwrap_poisons_session() {
        let (_user, mut unwrapper) = full_chain();
        let garbage = EncString::parse(&format!("4.{}==", "A".repeat(342))).unwrap();
        assert!(matches!(
            unwrapper.unwrap_org_key("org-fixture", &garbage),
            Err(EncError::DecryptionFailed)
        ));
        assert!(unwrapper.is_poisoned());
        // Even the *valid* org key is refused after a failure, until
        // the next unlock (a fresh OrgKeyUnwrapper).
        let valid = EncString::parse(PROTECTED_ORG_KEY).unwrap();
        assert!(matches!(
            unwrapper.unwrap_org_key("org-fixture", &valid),
            Err(EncError::Type4UnwrapRefused)
        ));
    }

    #[test]
    fn req_cry_004_wrong_password_fails_at_user_key_unwrap() {
        let master = derive_master_key(
            &Zeroizing::new("wrong password".to_string()),
            EMAIL,
            &Kdf::Pbkdf2 {
                iterations: 123_456,
            },
        )
        .unwrap();
        assert!(matches!(
            unwrap_user_key(
                &EncString::parse(PROTECTED_USER_KEY).unwrap(),
                &master.stretch()
            ),
            Err(EncError::MacMismatch)
        ));
    }
}
