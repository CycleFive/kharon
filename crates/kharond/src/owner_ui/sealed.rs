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

use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::webauthn::b64url_encode;

/// The one size cap: the longest token [`Sealed::open`] looks at, and
/// what [`Sealed::seal`] must stay under (keep claims small).
pub(crate) const MAX_TOKEN_LEN: usize = 4096;
/// Most live entries in [`UsedOnce`].
pub(crate) const MAX_USED: usize = 64;
/// Exclusive bound of the per-sealer expiry offset, in ms.
const OFFSET_BOUND_MS: u64 = 1 << 40;

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

/// The key and how many times it has been replaced. They change
/// together, under one lock.
struct KeyState {
    key: Zeroizing<[u8; 32]>,
    generation: u64,
}

/// Seals and opens ceremony tokens under one in-memory key.
struct Sealer {
    /// Behind a lock so a panic can replace it through `&self`.
    state: RwLock<KeyState>,
    /// Token expiry is milliseconds since this instant, plus `offset_ms`.
    epoch: Instant,
    /// Random, so `exp` does not reveal when the daemon started.
    offset_ms: u64,
}

/// A token that opened: its claims, its single-use id, its expiry.
pub(crate) struct Opened<T> {
    pub claims: T,
    /// SHA-256 of the whole token.
    pub id: [u8; 32],
    pub expires: Instant,
    /// The key generation the token opened under.
    pub generation: u64,
}

fn fresh_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(key.as_mut());
    key
}

/// base64url, unpadded, canonical, alphabet-strict. No length cap of
/// its own: the caller has checked [`MAX_TOKEN_LEN`].
fn decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return None;
    }
    let mut buf = vec![0u8; s.len()];
    let n = Base64UrlUnpadded::decode(s, &mut buf).ok()?.len();
    buf.truncate(n);
    Some(buf)
}

impl Sealer {
    fn new() -> Self {
        let mut raw = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        Self {
            state: RwLock::new(KeyState {
                key: fresh_key(),
                generation: 0,
            }),
            epoch: Instant::now(),
            offset_ms: u64::from_le_bytes(raw) % OFFSET_BOUND_MS,
        }
    }

    /// Replace the key: every token sealed before this stops opening.
    fn rotate(&self) {
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        state.key = fresh_key();
        state.generation += 1;
    }

    /// How many times the key has been replaced.
    fn generation(&self) -> u64 {
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .generation
    }

    fn mac(key: &KeyState, payload: &[u8]) -> HmacSha256 {
        let mut mac =
            HmacSha256::new_from_slice(key.key.as_ref()).expect("HMAC takes any key length");
        mac.update(payload);
        mac
    }

    fn millis(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.epoch).as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(self.offset_ms)
    }

    /// `base64url(payload) "." base64url(HMAC-SHA256(key, payload))`.
    /// Callers keep `claims` small: a token over [`MAX_TOKEN_LEN`]
    /// would never open.
    fn seal<T: Serialize>(&self, purpose: &str, claims: &T, ttl: Duration, now: Instant) -> String {
        let exp = self
            .millis(now)
            .saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX));
        let payload = serde_json::to_vec(&EnvelopeOut {
            p: purpose,
            exp,
            c: claims,
        })
        .expect("a derived Serialize of strings and integers cannot fail");
        let tag = {
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());
            Self::mac(&state, &payload).finalize().into_bytes()
        };
        let token = format!("{}.{}", b64url_encode(&payload), b64url_encode(&tag));
        debug_assert!(token.len() <= MAX_TOKEN_LEN, "ceremony claims too large");
        token
    }

    /// The claims, when `token` is ours, for `purpose`, and unexpired.
    /// The MAC is checked (constant time) before the payload is parsed,
    /// and the generation is read under the same guard as the key.
    fn open<T: DeserializeOwned>(
        &self,
        purpose: &str,
        token: &str,
        now: Instant,
    ) -> Option<Opened<T>> {
        if token.len() > MAX_TOKEN_LEN {
            return None;
        }
        let mut parts = token.split('.');
        let (payload, tag) = (parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let payload = decode(payload)?;
        let tag = decode(tag)?;
        let generation = {
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());
            Self::mac(&state, &payload).verify_slice(&tag).ok()?;
            state.generation
        };
        let envelope: EnvelopeIn<T> = serde_json::from_slice(&payload).ok()?;
        if envelope.p != purpose || envelope.exp <= self.millis(now) {
            return None;
        }
        let since_epoch = envelope.exp.saturating_sub(self.offset_ms);
        Some(Opened {
            claims: envelope.c,
            id: Sha256::digest(token.as_bytes()).into(),
            expires: self.epoch.checked_add(Duration::from_millis(since_epoch))?,
            generation,
        })
    }
}

/// Ids of tokens that already finished a ceremony, until they expire.
struct UsedOnce {
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
    fn new() -> Self {
        Self {
            ids: Mutex::new(Vec::new()),
        }
    }

    /// Drop expired entries, then insert `id` if absent: one lock,
    /// one step, so two finishes of one token cannot both win.
    /// `still_current` runs while the lock is held; `false` (the key
    /// was rotated since the token opened) refuses like a replay.
    fn burn(
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

    /// Run `f` while holding the used-set's lock, then empty the set.
    /// No burn can interleave between `f` and the clear.
    fn clear_after(&self, f: impl FnOnce()) {
        let mut ids = self.ids.lock().unwrap_or_else(|p| p.into_inner());
        f();
        ids.clear();
    }
}

/// The sealing key, its generation and the used-set, owned together so
/// no caller can burn a token without the "still current" check.
pub(crate) struct Sealed {
    sealer: Sealer,
    used: UsedOnce,
}

impl Sealed {
    pub fn new() -> Self {
        Self {
            sealer: Sealer::new(),
            used: UsedOnce::new(),
        }
    }

    pub fn seal<T: Serialize>(
        &self,
        purpose: &str,
        claims: &T,
        ttl: Duration,
        now: Instant,
    ) -> String {
        self.sealer.seal(purpose, claims, ttl, now)
    }

    pub fn open<T: DeserializeOwned>(
        &self,
        purpose: &str,
        token: &str,
        now: Instant,
    ) -> Option<Opened<T>> {
        self.sealer.open(purpose, token, now)
    }

    /// Record an opened token as used. A token opened under an older
    /// key than the current one is refused as `Replayed`; the check
    /// runs under the used-set's own lock.
    pub fn burn<T>(&self, opened: &Opened<T>, now: Instant) -> Burn {
        self.used.burn(opened.id, opened.expires, now, || {
            self.sealer.generation() == opened.generation
        })
    }

    /// A panic: every outstanding token stops working at once.
    pub fn invalidate(&self) {
        // The rotation happens inside the used-set's lock, the lock
        // `burn` takes first (used-set, then key; no path takes them
        // the other way round). So no burn can fall between the
        // rotation and the clear: a token sealed under the new key
        // cannot burn and then be dropped by `clear`. A burn that
        // finished before this took the lock belongs to a finish that
        // began before the panic, and the clear empties it. Any token
        // opened earlier is refused by `burn` from the rotation on.
        self.used.clear_after(|| self.sealer.rotate());
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
        // The whole alphabet, so the non-canonical siblings (same top
        // four bits) are covered whatever the real last character is.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        assert_eq!(alphabet.len(), 64);
        for &c in alphabet {
            if c == token.as_bytes()[last] {
                continue;
            }
            let mut t = token.as_bytes().to_vec();
            t[last] = c;
            let t = String::from_utf8(t).unwrap();
            assert!(open_login(&s, &t, now).is_none(), "{t}");
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
        u.clear_after(|| {});
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
        u.clear_after(|| {});
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

    #[test]
    fn sealed_burn_refuses_a_token_opened_before_invalidate() {
        let s = Sealed::new();
        let now = Instant::now();
        let old = s.seal("login", &claims("old"), TTL, now);
        let opened = s.open::<Claims>("login", &old, now).unwrap();
        s.invalidate();
        assert_eq!(s.burn(&opened, now), Burn::Replayed);
        assert!(s.open::<Claims>("login", &old, now).is_none());
        let new = s.seal("login", &claims("new"), TTL, now);
        let opened = s.open::<Claims>("login", &new, now).unwrap();
        assert_eq!(s.burn(&opened, now), Burn::Fresh);
        assert_eq!(s.burn(&opened, now), Burn::Replayed);
        s.invalidate();
        let again = s.open::<Claims>("login", &new, now);
        assert!(again.is_none(), "a burned token must not reopen");
    }

    #[test]
    fn a_token_sealed_after_invalidate_burns_once() {
        let s = Sealed::new();
        let now = Instant::now();
        s.invalidate();
        let token = s.seal("login", &claims("new"), TTL, now);
        let opened = s.open::<Claims>("login", &token, now).unwrap();
        assert_eq!(s.burn(&opened, now), Burn::Fresh);
        assert_eq!(s.burn(&opened, now), Burn::Replayed);
    }

    #[test]
    fn a_large_token_seals_and_opens() {
        let s = Sealer::new();
        let now = Instant::now();
        let token = s.seal("login", &claims(&"x".repeat(2300)), TTL, now);
        assert!(token.len() > 3000 && token.len() <= MAX_TOKEN_LEN);
        assert!(open_login(&s, &token, now).is_some());
    }

    #[test]
    fn exp_does_not_reveal_the_start_time() {
        let now = Instant::now();
        let ttl_ms = u64::try_from(TTL.as_millis()).unwrap();
        for _ in 0..2 {
            let s = Sealer::new();
            let token = s.seal("login", &claims("a"), TTL, now);
            let payload = decode(token.split('.').next().unwrap()).unwrap();
            let env: EnvelopeIn<Claims> = serde_json::from_slice(&payload).unwrap();
            let plain =
                u64::try_from(now.saturating_duration_since(s.epoch).as_millis()).unwrap() + ttl_ms;
            assert_ne!(env.exp, plain, "exp is the bare uptime plus ttl");
            assert!(s.offset_ms < OFFSET_BOUND_MS);
        }
    }
}
