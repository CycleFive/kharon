//! Stateless, HMAC-sealed tokens for sign-in and enrollment
//! ceremonies (#208 D7, REQ-APR-009).
//!
//! A ceremony used to live in a server-side table of eight, so anyone
//! who could call `login/options` could evict the owner's challenge.
//! Now `options` stores nothing: it returns a token that carries the
//! purpose, the expiry and the claims (the challenge), sealed under a
//! random in-memory key. `finish` opens the token again. A *successful*
//! finish burns the token in [`UsedOnce`] (only successes, so a
//! stranger can't fill it).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::webauthn::{b64url_decode, b64url_encode};

/// Longest token [`Sealer::open`] looks at.
pub(crate) const MAX_TOKEN_LEN: usize = 4096;
/// Most live entries in [`UsedOnce`].
pub(crate) const MAX_USED: usize = 64;

type HmacSha256 = Hmac<Sha256>;

/// What the MAC covers, as it is written.
#[derive(Serialize)]
struct EnvelopeOut<'a, T> {
    p: &'a str,
    exp: u64,
    c: &'a T,
}

/// What [`Sealer::open`] reads back.
#[derive(Deserialize)]
struct EnvelopeIn<T> {
    p: String,
    exp: u64,
    c: T,
}

/// Seals and opens ceremony tokens under one in-memory key.
pub(crate) struct Sealer {
    /// Behind a lock so a panic can replace it through `&self`.
    key: RwLock<Zeroizing<[u8; 32]>>,
    /// Token expiry is milliseconds since this instant.
    epoch: Instant,
    /// Bumped by every [`Sealer::rotate`].
    generation: AtomicU64,
}

/// A token that opened: its claims, its single-use id, its expiry.
pub(crate) struct Opened<T> {
    pub claims: T,
    /// SHA-256 of the whole token.
    pub id: [u8; 32],
    pub expires: Instant,
    /// [`Sealer::generation`] when the token opened.
    pub generation: u64,
}

fn fresh_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());
    key
}

impl Sealer {
    pub fn new() -> Self {
        Self {
            key: RwLock::new(fresh_key()),
            epoch: Instant::now(),
            generation: AtomicU64::new(0),
        }
    }

    /// Replace the key: every token sealed before this stops opening.
    pub fn rotate(&self) {
        *self.key.write().unwrap_or_else(|p| p.into_inner()) = fresh_key();
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// How many times the key has been replaced.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    fn mac(&self, payload: &[u8]) -> HmacSha256 {
        let key = self.key.read().unwrap_or_else(|p| p.into_inner());
        let mut mac = HmacSha256::new_from_slice(key.as_ref()).expect("HMAC takes any key length");
        mac.update(payload);
        mac
    }

    fn millis(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.epoch).as_millis()).unwrap_or(u64::MAX)
    }

    /// `base64url(payload) "." base64url(HMAC-SHA256(key, payload))`.
    pub fn seal<T: Serialize>(
        &self,
        purpose: &str,
        claims: &T,
        ttl: Duration,
        now: Instant,
    ) -> String {
        let exp = self
            .millis(now)
            .saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX));
        let payload = serde_json::to_vec(&EnvelopeOut {
            p: purpose,
            exp,
            c: claims,
        })
        .expect("a derived Serialize of strings and integers cannot fail");
        let tag = self.mac(&payload).finalize().into_bytes();
        format!("{}.{}", b64url_encode(&payload), b64url_encode(&tag))
    }

    /// The claims, when `token` is ours, for `purpose`, and unexpired.
    /// The MAC is checked (constant time) before the payload is parsed.
    pub fn open<T: DeserializeOwned>(
        &self,
        purpose: &str,
        token: &str,
        now: Instant,
    ) -> Option<Opened<T>> {
        // Read before the MAC: a rotation after this read bumps the
        // generation, and one before it makes the MAC fail.
        let generation = self.generation();
        if token.len() > MAX_TOKEN_LEN {
            return None;
        }
        let mut parts = token.split('.');
        let (payload, tag) = (parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let payload = b64url_decode(payload).ok()?;
        let tag = b64url_decode(tag).ok()?;
        self.mac(&payload).verify_slice(&tag).ok()?;
        let envelope: EnvelopeIn<T> = serde_json::from_slice(&payload).ok()?;
        if envelope.p != purpose || envelope.exp <= self.millis(now) {
            return None;
        }
        Some(Opened {
            claims: envelope.c,
            id: Sha256::digest(token.as_bytes()).into(),
            expires: self.epoch + Duration::from_millis(envelope.exp),
            generation,
        })
    }
}

/// Ids of tokens that already finished a ceremony, until they expire.
pub(crate) struct UsedOnce {
    ids: Mutex<Vec<([u8; 32], Instant)>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Burn {
    /// First use: recorded.
    Fresh,
    /// Used before.
    Replayed,
    /// [`MAX_USED`] live entries: nothing recorded.
    Full,
}

impl UsedOnce {
    pub fn new() -> Self {
        Self {
            ids: Mutex::new(Vec::new()),
        }
    }

    /// Drop expired entries, then insert `id` if absent: one lock,
    /// one step, so two finishes of one token cannot both win.
    /// `still_current` runs while the lock is held; `false` (the key
    /// was rotated since the token opened) refuses like a replay.
    pub fn burn(
        &self,
        id: [u8; 32],
        expires: Instant,
        now: Instant,
        still_current: impl FnOnce() -> bool,
    ) -> Burn {
        let mut ids = self.ids.lock().unwrap_or_else(|p| p.into_inner());
        // Evaluated under the lock: see `OwnerUi::invalidate_sealed`.
        if !still_current() {
            return Burn::Replayed;
        }
        ids.retain(|(_, exp)| *exp > now);
        if ids.iter().any(|(seen, _)| *seen == id) {
            return Burn::Replayed;
        }
        if ids.len() >= MAX_USED {
            return Burn::Full;
        }
        ids.push((id, expires));
        Burn::Fresh
    }

    pub fn clear(&self) {
        self.ids.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Claims {
        challenge: String,
    }

    fn claims(s: &str) -> Claims {
        Claims {
            challenge: s.to_owned(),
        }
    }

    const TTL: Duration = Duration::from_secs(120);

    fn open_login(s: &Sealer, token: &str, now: Instant) -> Option<Opened<Claims>> {
        s.open::<Claims>("login", token, now)
    }

    #[test]
    fn sealed_round_trips_and_checks_purpose() {
        let s = Sealer::new();
        let now = Instant::now();
        let token = s.seal("login", &claims("abc"), TTL, now);
        let opened = open_login(&s, &token, now).expect("opens");
        assert_eq!(opened.claims, claims("abc"));
        assert!(opened.expires > now);
        assert!(s.open::<Claims>("register", &token, now).is_none());
    }

    #[test]
    fn sealed_expires() {
        let s = Sealer::new();
        let now = Instant::now();
        let token = s.seal("login", &claims("abc"), TTL, now);
        let ms = Duration::from_millis(1);
        assert!(open_login(&s, &token, now + TTL - ms).is_some());
        assert!(open_login(&s, &token, now + TTL).is_none());
        assert!(open_login(&s, &token, now + TTL + ms).is_none());
    }

    fn flip(token: &str, index: usize) -> String {
        let mut bytes = token.as_bytes().to_vec();
        bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn sealed_rejects_tampering() {
        let s = Sealer::new();
        let now = Instant::now();
        let token = s.seal("login", &claims("abc"), TTL, now);
        let dot = token.find('.').unwrap();
        assert!(open_login(&s, &token, now).is_some());

        // A changed character in each part.
        assert!(open_login(&s, &flip(&token, 3), now).is_none());
        assert!(open_login(&s, &flip(&token, dot + 5), now).is_none());
        // Every other spelling of the MAC's last character: base64 must
        // be canonical, or a replay could hide behind a new token id.
        let last = token.len() - 1;
        for c in b'A'..=b'Z' {
            let mut t = token.as_bytes().to_vec();
            t[last] = c;
            let t = String::from_utf8(t).unwrap();
            if t != token {
                assert!(open_login(&s, &t, now).is_none(), "{t}");
            }
        }
        // The payload of one token with the MAC of another.
        let other = s.seal("login", &claims("xyz"), TTL, now);
        let (p1, _) = token.split_at(dot);
        let (_, m2) = other.split_at(other.find('.').unwrap());
        assert!(open_login(&s, &format!("{p1}{m2}"), now).is_none());
        // Truncated, empty, a third part, too long, non-ASCII.
        assert!(open_login(&s, &token[..token.len() - 1], now).is_none());
        assert!(open_login(&s, &token[..dot], now).is_none());
        assert!(open_login(&s, "", now).is_none());
        assert!(open_login(&s, ".", now).is_none());
        assert!(open_login(&s, &format!("{token}.AAAA"), now).is_none());
        assert!(open_login(&s, &"a".repeat(MAX_TOKEN_LEN + 1), now).is_none());
        assert!(open_login(&s, "é.é", now).is_none());
        assert!(open_login(&s, &token.replacen('.', "é", 1), now).is_none());
    }

    #[test]
    fn sealed_tokens_from_another_key_do_not_open() {
        let (a, b) = (Sealer::new(), Sealer::new());
        let now = Instant::now();
        let token = a.seal("login", &claims("abc"), TTL, now);
        assert!(open_login(&b, &token, now).is_none());
        assert!(open_login(&a, &token, now).is_some());
    }

    #[test]
    fn rotate_kills_every_outstanding_token() {
        let s = Sealer::new();
        let now = Instant::now();
        let before = s.seal("login", &claims("old"), TTL, now);
        assert!(open_login(&s, &before, now).is_some());
        s.rotate();
        assert!(open_login(&s, &before, now).is_none());
        let after = s.seal("login", &claims("new"), TTL, now);
        assert_eq!(
            open_login(&s, &after, now).expect("opens").claims,
            claims("new")
        );
    }

    #[test]
    fn used_once_burns_once() {
        let u = UsedOnce::new();
        let now = Instant::now();
        let exp = now + TTL;
        assert_eq!(u.burn([1; 32], exp, now, || true), Burn::Fresh);
        assert_eq!(u.burn([1; 32], exp, now, || true), Burn::Replayed);
        assert_eq!(u.burn([2; 32], exp, now, || true), Burn::Fresh);
        u.clear();
        assert_eq!(u.burn([1; 32], exp, now, || true), Burn::Fresh);
    }

    #[test]
    fn used_once_forgets_expired_entries_and_reports_full() {
        let u = UsedOnce::new();
        let now = Instant::now();
        let exp = now + TTL;
        for i in 0..MAX_USED {
            assert_eq!(u.burn([i as u8; 32], exp, now, || true), Burn::Fresh);
        }
        assert_eq!(u.burn([200; 32], exp, now, || true), Burn::Full);
        assert_eq!(u.burn([0; 32], exp, now, || true), Burn::Replayed);
        assert_eq!(
            u.burn([200; 32], exp + TTL, now + TTL, || true),
            Burn::Fresh
        );
    }

    #[test]
    fn a_token_opened_before_rotate_cannot_burn_after_it() {
        let s = Sealer::new();
        let u = UsedOnce::new();
        let now = Instant::now();
        let token = s.seal("login", &claims("old"), TTL, now);
        let opened = open_login(&s, &token, now).unwrap();
        // A panic lands between the open and the burn.
        s.rotate();
        u.clear();
        assert_eq!(
            u.burn(opened.id, opened.expires, now, || s.generation()
                == opened.generation),
            Burn::Replayed
        );
        let token = s.seal("login", &claims("new"), TTL, now);
        let opened = open_login(&s, &token, now).unwrap();
        assert_eq!(
            u.burn(opened.id, opened.expires, now, || s.generation()
                == opened.generation),
            Burn::Fresh
        );
    }
}
