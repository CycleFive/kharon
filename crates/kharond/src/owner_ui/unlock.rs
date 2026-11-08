//! Web unlock (#131 slice 5b; SPEC §8 "web UI after WebAuthn",
//! REQ-MEM-003).
//!
//! The master password never crosses HTTP in the clear. Behind a
//! live owner session, `POST /owner/unlock/begin` hands the page a
//! fresh ephemeral ECDH P-256 public key for one attempt. The page
//! (WebCrypto) generates its own ephemeral key, derives an AES-256-GCM
//! key with HKDF-SHA256 over the shared secret, and sends only the
//! ciphertext to `POST /owner/unlock`. hyper's read buffers, the
//! collected body and the JSON parse therefore only ever hold
//! ciphertext: the one plaintext copy is decrypted in place inside a
//! `Zeroizing` buffer and moved, without a copy, into the
//! `Zeroizing<String>` that [`OwnerUnlock::unlock`] consumes. That is
//! what lets the real-binary canary scan (REQ-MEM-003) hold for the
//! web channel as it does for the owner socket.
//!
//! Wire format (base64url, no padding):
//!
//! - key: HKDF-SHA256, empty salt, `info = INFO || server_pub ||
//!   client_pub` (uncompressed SEC1 points, 65 bytes each), 32 bytes;
//! - AES-256-GCM, 12-byte nonce, `aad = INFO`; the ciphertext carries
//!   the 16-byte tag at its end (WebCrypto's layout).
//!
//! An attempt is single use: it is removed before decryption, whatever
//! the outcome, and lives [`UNLOCK_TTL`]. It is bound to the session
//! that began it, so another session cannot spend it.

use std::time::{Duration, Instant};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::rand::SystemRandom;
use zeroize::{Zeroize, Zeroizing};

use crate::owner::OwnerFailure;

/// Domain separation for the HKDF info and the AEAD associated data.
/// The page uses the same bytes.
pub const INFO: &[u8] = b"kharon web unlock v1";

/// How long an unlock attempt may sit between `begin` and `unlock`.
pub const UNLOCK_TTL: Duration = Duration::from_secs(60);

/// Most attempts kept at once; the oldest is dropped first.
pub(super) const MAX_ATTEMPTS: usize = 4;

/// Uncompressed SEC1 P-256 point: `0x04 || X || Y`.
pub const P256_POINT_LEN: usize = 65;

/// AES-GCM tag length.
const TAG_LEN: usize = 16;

/// Longest password the web unlock accepts, in bytes. Generous for a
/// passphrase; it only caps the ciphertext the daemon will process.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// The daemon side of a web unlock: the same unlock the owner socket
/// runs ([`crate::owner::OwnerOps::unlock`]). Called on the UI's
/// blocking thread; implementations may block on the runtime.
pub trait OwnerUnlock: Send + Sync + 'static {
    /// Unlock with the owner's password. The password is consumed and
    /// zeroized on drop; implementations must not retain it.
    fn unlock(&self, password: Zeroizing<String>) -> Result<(), OwnerFailure>;
}

/// One pending attempt.
pub(super) struct Attempt {
    pub(super) id: String,
    pub(super) session: [u8; 32],
    pub(super) expires: Instant,
    key: EphemeralPrivateKey,
    server_pub: [u8; P256_POINT_LEN],
}

impl Attempt {
    /// A fresh attempt for `session`. Returns it with the public key
    /// the page encrypts to.
    pub(super) fn new(id: String, session: [u8; 32]) -> Option<Self> {
        let key = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new()).ok()?;
        let public = key.compute_public_key().ok()?;
        let server_pub: [u8; P256_POINT_LEN] = public.as_ref().try_into().ok()?;
        Some(Self {
            id,
            session,
            expires: Instant::now() + UNLOCK_TTL,
            key,
            server_pub,
        })
    }

    pub(super) fn server_pub(&self) -> &[u8; P256_POINT_LEN] {
        &self.server_pub
    }

    /// Decrypt the page's ciphertext into the password. Consumes the
    /// attempt (its private key is single use). Every failure is the
    /// same `Err(())`: a bad point, a bad nonce, a wrong tag, non-UTF-8
    /// or an oversized plaintext.
    pub(super) fn open(
        self,
        client_pub: &[u8],
        nonce: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<Zeroizing<String>, ()> {
        if client_pub.len() != P256_POINT_LEN
            || nonce.len() != NONCE_LEN
            || ciphertext.len() < TAG_LEN
            || ciphertext.len() > MAX_PASSWORD_LEN + TAG_LEN
        {
            return Err(());
        }
        let info = info(&self.server_pub, client_pub);
        let key = agree_ephemeral(
            self.key,
            UnparsedPublicKey::new(&ECDH_P256, client_pub),
            (),
            |shared| aead_key(shared, &info),
        )?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| ())?;
        // From here on the buffer may hold plaintext: it is zeroized
        // on every path, including a tag failure (which leaves the
        // buffer as it was, but costs nothing to wipe).
        let mut buf = Zeroizing::new(ciphertext);
        let len = key
            .open_in_place(nonce, Aad::from(INFO), buf.as_mut_slice())
            .map_err(|_| ())?
            .len();
        buf.truncate(len);
        // Move the allocation into the String: no copy is made.
        let bytes = std::mem::take(&mut *buf);
        match String::from_utf8(bytes) {
            Ok(s) => Ok(Zeroizing::new(s)),
            Err(e) => {
                e.into_bytes().zeroize();
                Err(())
            }
        }
    }
}

fn info(server_pub: &[u8], client_pub: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(INFO.len() + server_pub.len() + client_pub.len());
    info.extend_from_slice(INFO);
    info.extend_from_slice(server_pub);
    info.extend_from_slice(client_pub);
    info
}

fn aead_key(shared: &[u8], info: &[u8]) -> Result<LessSafeKey, ()> {
    let prk = Salt::new(HKDF_SHA256, &[]).extract(shared);
    let parts = [info];
    let okm = prk.expand(&parts, &AES_256_GCM).map_err(|_| ())?;
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

/// The page's half of the protocol, in Rust: encrypt `password` to
/// `server_pub`. Returns `(client_pub, nonce, ciphertext)`. The shell
/// does the same with WebCrypto; tests use this as the reference
/// client.
pub fn seal_password(
    server_pub: &[u8],
    password: &str,
) -> Option<([u8; P256_POINT_LEN], [u8; NONCE_LEN], Vec<u8>)> {
    let rng = SystemRandom::new();
    let mine = EphemeralPrivateKey::generate(&ECDH_P256, &rng).ok()?;
    let client_pub: [u8; P256_POINT_LEN] =
        mine.compute_public_key().ok()?.as_ref().try_into().ok()?;
    let info = info(server_pub, &client_pub);
    let key = agree_ephemeral(
        mine,
        UnparsedPublicKey::new(&ECDH_P256, server_pub),
        (),
        |shared| aead_key(shared, &info),
    )
    .ok()?;
    let mut nonce = [0u8; NONCE_LEN];
    aws_lc_rs::rand::fill(&mut nonce).ok()?;
    let mut buf = password.as_bytes().to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(INFO),
        &mut buf,
    )
    .ok()?;
    Some((client_pub, nonce, buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt() -> Attempt {
        Attempt::new("a".into(), [7; 32]).unwrap()
    }

    #[test]
    fn round_trip_recovers_the_password() {
        let a = attempt();
        let (client, nonce, ct) = seal_password(a.server_pub(), "correct horse \"9\" \\").unwrap();
        assert!(
            !ct.windows(7).any(|w| w == b"correct"),
            "ciphertext is plaintext"
        );
        let pw = a.open(&client, &nonce, ct).unwrap();
        assert_eq!(pw.as_str(), "correct horse \"9\" \\");
    }

    #[test]
    fn another_attempts_key_does_not_open() {
        let a = attempt();
        let b = attempt();
        let (client, nonce, ct) = seal_password(b.server_pub(), "pw").unwrap();
        assert!(a.open(&client, &nonce, ct).is_err());
    }

    #[test]
    fn tampering_is_refused() {
        for flip in 0..3 {
            let a = attempt();
            let (mut client, mut nonce, mut ct) = seal_password(a.server_pub(), "pw").unwrap();
            match flip {
                0 => ct[0] ^= 1,
                1 => nonce[0] ^= 1,
                _ => client[10] ^= 1,
            }
            assert!(a.open(&client, &nonce, ct).is_err(), "flip {flip}");
        }
    }

    #[test]
    fn malformed_inputs_are_refused() {
        let a = attempt();
        let (client, nonce, ct) = seal_password(a.server_pub(), "pw").unwrap();
        assert!(attempt().open(&client[..64], &nonce, ct.clone()).is_err());
        assert!(attempt().open(&client, &nonce[..11], ct.clone()).is_err());
        assert!(attempt().open(&client, &nonce, ct[..15].to_vec()).is_err());
        assert!(
            attempt()
                .open(&client, &nonce, vec![0; MAX_PASSWORD_LEN + TAG_LEN + 1])
                .is_err()
        );
        // The point at infinity / garbage point.
        assert!(attempt().open(&[4; 65], &nonce, ct).is_err());
    }

    #[test]
    fn non_utf8_plaintext_is_refused() {
        let a = attempt();
        let (client, nonce, _) = seal_password(a.server_pub(), "x").unwrap();
        // Re-seal raw bytes with the same agreement by hand.
        let b = attempt();
        let rng = SystemRandom::new();
        let mine = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
        let cp: [u8; 65] = mine
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let inf = info(b.server_pub(), &cp);
        let key = agree_ephemeral(
            mine,
            UnparsedPublicKey::new(&ECDH_P256, b.server_pub()),
            (),
            |s| aead_key(s, &inf),
        )
        .unwrap();
        let mut buf = vec![0xff, 0xfe];
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(INFO),
            &mut buf,
        )
        .unwrap();
        assert!(b.open(&cp, &nonce, buf).is_err());
        let _ = (a, client);
    }
}
