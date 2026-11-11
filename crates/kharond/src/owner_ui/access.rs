//! Optional Cloudflare Access JWT check for the owner UI (REQ-APR-009, #208 D9).
//!
//! With `[owner_ui.access]` set, every owner-UI request not on
//! [`super::EDGE_EXEMPT`] must carry a `Cf-Access-Jwt-Assertion`: an
//! RS256 token signed by one of the team's published keys, naming the
//! team as issuer and this application as audience, and not expired. It
//! is a second line in front of the passkey, never a session: a valid
//! token only lets a request reach the routes.
//!
//! Nothing here is ever logged or audited: not the token, not its
//! claims. A refusal is one of a few fixed classes, and the process names
//! each class once on stderr so a misconfiguration is visible.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use axum::http::HeaderMap;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;
use serde::de::IgnoredAny;

/// The header Cloudflare Access adds to every request it lets through.
pub const CF_ACCESS_JWT: &str = "cf-access-jwt-assertion";
/// At least this long between two key-set fetch attempts, whoever asks,
/// once a key set has been loaded.
pub(crate) const JWKS_REFETCH_SPACING: Duration = Duration::from_secs(60);
/// The spacing while no key set has been loaded yet: a first-deploy
/// hiccup should heal quickly.
pub(crate) const JWKS_EMPTY_RETRY: Duration = Duration::from_secs(5);
/// A cached key set older than this is fetched again.
pub(crate) const JWKS_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// The whole key-set request, connect to last byte.
pub(crate) const JWKS_TIMEOUT: Duration = Duration::from_secs(5);
/// A longer key-set body is refused.
pub(crate) const JWKS_MAX_BYTES: usize = 64 * 1024;
/// Clock skew tolerated on `exp` and `nbf`.
pub(crate) const CLOCK_LEEWAY: Duration = Duration::from_secs(60);
/// A longer header value is refused before it is split or decoded.
pub(crate) const MAX_TOKEN_BYTES: usize = 8192;

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    exp: u64,
    nbf: Option<u64>,
}

/// `aud` is a string or a list of strings (RFC 7519 4.1.3).
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, wanted: &str) -> bool {
        match self {
            Self::One(a) => a == wanted,
            Self::Many(list) => list.iter().any(|a| a == wanted),
        }
    }
}

/// A key set as published. One entry we cannot use (another key type, a
/// missing field, an odd value) must never reject the whole document, so
/// every field of every entry is optional and entries are skipped later.
#[derive(Deserialize)]
struct Jwks {
    keys: Vec<JwkEntry>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum JwkEntry {
    Key(Jwk),
    Other(IgnoredAny),
}

#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: Option<Text>,
    #[serde(default)]
    kty: Option<Text>,
    #[serde(default)]
    n: Option<Text>,
    #[serde(default)]
    e: Option<Text>,
}

/// A string field, or whatever else sits there.
#[derive(Deserialize)]
#[serde(untagged)]
enum Text {
    Str(String),
    Other(IgnoredAny),
}

impl Text {
    fn into_str(self) -> Option<String> {
        match self {
            Self::Str(s) => Some(s),
            Self::Other(_) => None,
        }
    }
}

type Key = RsaPublicKeyComponents<Vec<u8>>;

/// Why a request's token was refused. The response and the audit entry
/// carry fixed text, never this; it is for tests, branching and the
/// once-per-class stderr line.
#[derive(Debug, PartialEq, Eq)]
pub enum AccessRefusal {
    /// No `Cf-Access-Jwt-Assertion` header.
    Missing,
    /// More than one header, or not a three-part base64url RS256 JWT.
    Malformed,
    /// The `kid` is not in the team's key set.
    UnknownKey,
    /// The signature does not verify under that key.
    BadSignature,
    /// The claims do not parse.
    Claims,
    /// `iss` is not this team.
    Issuer,
    /// `aud` does not contain this application.
    Audience,
    /// `exp` has passed (or the clock is unusable).
    Expired,
    /// `nbf` is in the future.
    NotYetValid,
}

impl AccessRefusal {
    const ALL: usize = 9;

    fn index(&self) -> usize {
        match self {
            Self::Missing => 0,
            Self::Malformed => 1,
            Self::UnknownKey => 2,
            Self::BadSignature => 3,
            Self::Claims => 4,
            Self::Issuer => 5,
            Self::Audience => 6,
            Self::Expired => 7,
            Self::NotYetValid => 8,
        }
    }

    /// Fixed text for the log line: never any request data.
    fn class(&self) -> &'static str {
        match self {
            Self::Missing => "missing_token",
            Self::Malformed => "malformed_token",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::Claims => "claims",
            Self::Issuer => "issuer",
            Self::Audience => "audience",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
        }
    }
}

/// Why a key-set fetch produced no keys. Fixed classes for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchFault {
    /// Could not connect, timed out, or the connection broke.
    Connect,
    /// A status that is not 200.
    Status(&'static str),
    /// The body is over [`JWKS_MAX_BYTES`].
    TooLarge,
    /// The body is not a key-set document.
    Unparseable,
    /// A key set with no usable RSA key.
    NoUsableKeys,
}

impl FetchFault {
    fn class(self) -> &'static str {
        match self {
            Self::Connect => "connect_or_timeout",
            Self::Status(class) => class,
            Self::TooLarge => "too_large",
            Self::Unparseable => "unparseable",
            Self::NoUsableKeys => "no_usable_keys",
        }
    }
}

/// Where a fetch gets the key-set document from.
enum KeySource {
    /// A fixed document, parsed once; never fetched.
    Static,
    /// `https://<team_domain>/cdn-cgi/access/certs`.
    Remote {
        url: String,
        client: reqwest::Client,
    },
    /// Canned bodies, counting calls (tests only).
    #[cfg(test)]
    Fake(Arc<FakeFetch>),
}

/// Canned fetch results for the private seam (tests only).
#[cfg(test)]
pub(crate) struct FakeFetch {
    pub calls: Mutex<usize>,
    pub bodies: Mutex<std::collections::VecDeque<Option<String>>>,
    /// When set, a fetch waits for this before it answers.
    pub gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
}

impl KeySource {
    fn fetches(&self) -> bool {
        !matches!(self, Self::Static)
    }

    /// The document's bytes.
    async fn fetch(&self) -> Result<Vec<u8>, FetchFault> {
        match self {
            Self::Static => Err(FetchFault::Connect),
            Self::Remote { url, client } => {
                let mut resp = client
                    .get(url)
                    .send()
                    .await
                    .map_err(|_| FetchFault::Connect)?;
                let status = resp.status();
                if status != reqwest::StatusCode::OK {
                    return Err(FetchFault::Status(match status.as_u16() / 100 {
                        4 => "http_4xx",
                        5 => "http_5xx",
                        _ => "http_other",
                    }));
                }
                let mut body = Vec::new();
                while let Some(chunk) = resp.chunk().await.map_err(|_| FetchFault::Connect)? {
                    if body.len() + chunk.len() > JWKS_MAX_BYTES {
                        return Err(FetchFault::TooLarge);
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            }
            #[cfg(test)]
            Self::Fake(fake) => {
                *fake.calls.lock().unwrap() += 1;
                let gate = fake.gate.lock().unwrap().clone();
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                let next = fake.bodies.lock().unwrap().pop_front();
                next.flatten()
                    .map(String::into_bytes)
                    .ok_or(FetchFault::Connect)
            }
        }
    }
}

#[derive(Default)]
struct Cache {
    keys: HashMap<String, Key>,
    /// When `keys` was last replaced by a successful fetch.
    fetched_at: Option<Instant>,
    /// When a fetch was last started, successful or not.
    last_attempt: Option<Instant>,
}

/// Verifies `Cf-Access-Jwt-Assertion` tokens for one Access application.
pub struct AccessVerifier {
    issuer: String,
    audience: String,
    source: KeySource,
    cache: Mutex<Cache>,
    /// One flag per [`AccessRefusal`] class: has the process named it yet.
    refusal_noted: [AtomicBool; AccessRefusal::ALL],
}

/// The usable RSA keys of a JWKS document. Entries that are not RSA, or
/// lack a `kid`, `n` or `e`, or carry one that does not decode, are
/// skipped; a document with none left is a fault.
fn parse_keys(doc: &[u8]) -> Result<HashMap<String, Key>, FetchFault> {
    let jwks: Jwks = serde_json::from_slice(doc).map_err(|_| FetchFault::Unparseable)?;
    let strip = |mut v: Vec<u8>| {
        let zeros = v.iter().take_while(|b| **b == 0).count();
        v.drain(..zeros);
        v
    };
    let decode = |t: Option<Text>| {
        let text = t?.into_str()?;
        let bytes = strip(Base64UrlUnpadded::decode_vec(&text).ok()?);
        (!bytes.is_empty()).then_some(bytes)
    };
    let keys: HashMap<String, Key> = jwks
        .keys
        .into_iter()
        .filter_map(|entry| {
            let JwkEntry::Key(k) = entry else { return None };
            if k.kty?.into_str()? != "RSA" {
                return None;
            }
            let kid = k.kid?.into_str()?;
            Some((
                kid,
                RsaPublicKeyComponents {
                    n: decode(k.n)?,
                    e: decode(k.e)?,
                },
            ))
        })
        .collect();
    if keys.is_empty() {
        Err(FetchFault::NoUsableKeys)
    } else {
        Ok(keys)
    }
}

impl AccessVerifier {
    /// Build the verifier for `cfg`. Nothing is fetched here: kharond
    /// must start with Cloudflare unreachable ([`Self::warm`] tries in
    /// the background). A `TestStatic` document with no usable key is
    /// refused.
    pub fn new(cfg: &crate::config::AccessConfig) -> std::io::Result<Arc<Self>> {
        let mut cache = Cache::default();
        let source = match &cfg.jwks {
            crate::config::JwksSource::TestStatic(doc) => {
                cache.keys = parse_keys(doc.as_bytes()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "owner UI access: the static key set has no usable RSA key",
                    )
                })?;
                KeySource::Static
            }
            crate::config::JwksSource::TeamCerts => {
                let tls = crate::sync::tls_config(&crate::sync::TlsTrust::default())
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                let client = reqwest::Client::builder()
                    .use_preconfigured_tls(tls)
                    // A redirect could send the fetch to another host.
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(JWKS_TIMEOUT)
                    .build()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                KeySource::Remote {
                    url: format!("https://{}/cdn-cgi/access/certs", cfg.team_domain),
                    client,
                }
            }
        };
        Ok(Arc::new(Self::build(cfg, source, cache)))
    }

    fn build(cfg: &crate::config::AccessConfig, source: KeySource, cache: Cache) -> Self {
        Self {
            issuer: format!("https://{}", cfg.team_domain),
            audience: cfg.audience.clone(),
            source,
            cache: Mutex::new(cache),
            refusal_noted: std::array::from_fn(|_| AtomicBool::new(false)),
        }
    }

    /// A verifier whose fetch seam is `fake` (tests only).
    #[cfg(test)]
    fn with_fake(cfg: &crate::config::AccessConfig, fake: Arc<FakeFetch>) -> Arc<Self> {
        Arc::new(Self::build(cfg, KeySource::Fake(fake), Cache::default()))
    }

    /// Start the first key-set fetch in the background, so the cache is
    /// usually full before the first visitor. Must run inside the Tokio
    /// runtime. A static source has nothing to fetch.
    pub fn warm(self: &Arc<Self>) {
        let claimed = self.source.fetches() && {
            let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            Self::claim_attempt(&mut cache, Instant::now())
        };
        if claimed {
            let this = Arc::clone(self);
            let mono = Instant::now();
            tokio::spawn(async move { this.fetch_and_store(mono).await });
        }
    }

    /// Check the request's token. `Ok` means only that the request may
    /// reach the routes: it is not a session.
    pub async fn verify(
        self: &Arc<Self>,
        headers: &HeaderMap,
        now: SystemTime,
    ) -> Result<(), AccessRefusal> {
        self.verify_at(headers, now, Instant::now()).await
    }

    /// [`Self::verify`] with the monotonic clock the key cache's timing
    /// runs on passed in, so tests can move it.
    async fn verify_at(
        self: &Arc<Self>,
        headers: &HeaderMap,
        now: SystemTime,
        mono: Instant,
    ) -> Result<(), AccessRefusal> {
        let result = self.check(headers, now, mono).await;
        if let Err(refusal) = &result {
            self.note_refusal(refusal);
        }
        result
    }

    /// Name a refusal class on stderr the first time this process sees
    /// it. Fixed text only. Returns whether this call printed.
    fn note_refusal(&self, refusal: &AccessRefusal) -> bool {
        let first = !self.refusal_noted[refusal.index()].swap(true, Ordering::Relaxed);
        if first {
            eprintln!(
                "kharond: owner UI Access refused a request: {} (logged once)",
                refusal.class()
            );
        }
        first
    }

    async fn check(
        self: &Arc<Self>,
        headers: &HeaderMap,
        now: SystemTime,
        mono: Instant,
    ) -> Result<(), AccessRefusal> {
        let mut values = headers.get_all(CF_ACCESS_JWT).iter();
        let token = match (values.next(), values.next()) {
            (None, _) => return Err(AccessRefusal::Missing),
            (Some(v), None) => {
                if v.len() > MAX_TOKEN_BYTES {
                    return Err(AccessRefusal::Malformed);
                }
                v.to_str().map_err(|_| AccessRefusal::Malformed)?
            }
            (Some(_), Some(_)) => return Err(AccessRefusal::Malformed),
        };
        let parts: Vec<&str> = token.split('.').collect();
        let [header_b64, payload_b64, sig_b64] = parts[..] else {
            return Err(AccessRefusal::Malformed);
        };
        let decode = |s: &str| {
            if s.is_empty() {
                return Err(AccessRefusal::Malformed);
            }
            Base64UrlUnpadded::decode_vec(s).map_err(|_| AccessRefusal::Malformed)
        };
        let header_raw = decode(header_b64)?;
        let payload_raw = decode(payload_b64)?;
        let signature = decode(sig_b64)?;
        let header: JwtHeader =
            serde_json::from_slice(&header_raw).map_err(|_| AccessRefusal::Malformed)?;
        if header.alg != "RS256" {
            return Err(AccessRefusal::Malformed);
        }

        // An unknown key id ends here: no signature work for it.
        let key = self
            .key_for(&header.kid, mono)
            .await
            .ok_or(AccessRefusal::UnknownKey)?;
        let signing_input = &token[..header_b64.len() + 1 + payload_b64.len()];
        key.verify(
            &RSA_PKCS1_2048_8192_SHA256,
            signing_input.as_bytes(),
            &signature,
        )
        .map_err(|_| AccessRefusal::BadSignature)?;

        let claims: Claims =
            serde_json::from_slice(&payload_raw).map_err(|_| AccessRefusal::Claims)?;
        // A clock before 1970 is a broken clock: refuse, never read it as 0.
        let now_s = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AccessRefusal::Expired)?
            .as_secs();
        let leeway = CLOCK_LEEWAY.as_secs();
        if !claims.iss.eq_ignore_ascii_case(&self.issuer) {
            return Err(AccessRefusal::Issuer);
        }
        if !claims.aud.contains(&self.audience) {
            return Err(AccessRefusal::Audience);
        }
        if claims.exp.saturating_add(leeway) <= now_s {
            return Err(AccessRefusal::Expired);
        }
        if claims
            .nbf
            .is_some_and(|nbf| nbf > now_s.saturating_add(leeway))
        {
            return Err(AccessRefusal::NotYetValid);
        }
        Ok(())
    }

    /// Stamp a fetch attempt if the spacing allows one: 5 s while no key
    /// set has been loaded, else 60 s. Called under the cache lock, so
    /// the stamp precedes the fetch.
    fn claim_attempt(cache: &mut Cache, mono: Instant) -> bool {
        let spacing = if cache.keys.is_empty() {
            JWKS_EMPTY_RETRY
        } else {
            JWKS_REFETCH_SPACING
        };
        let allowed = cache
            .last_attempt
            .is_none_or(|t| mono.saturating_duration_since(t) >= spacing);
        if allowed {
            cache.last_attempt = Some(mono);
        }
        allowed
    }

    /// Fetch the key set and, if it holds usable keys, replace the cache.
    /// Runs outside the lock. A failure keeps the old keys and is named
    /// on stderr (a fixed class, nothing from the response).
    async fn fetch_and_store(&self, mono: Instant) {
        match self.source.fetch().await.and_then(|b| parse_keys(&b)) {
            Ok(keys) => {
                let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
                cache.keys = keys;
                cache.fetched_at = Some(mono);
            }
            Err(fault) => eprintln!(
                "kharond: owner UI Access keys fetch failed: {}",
                fault.class()
            ),
        }
    }

    /// The key for `kid`. A refetch is wanted when `kid` is not cached
    /// (waited for: nothing else can verify the request) or the cache is
    /// older than [`JWKS_MAX_AGE`] (done in the background: the cached key
    /// still verifies, so the request does not wait). Either only when
    /// the attempt spacing allows, so a stranger naming random key ids
    /// cannot make this a fetch amplifier. A failed fetch keeps the old
    /// keys.
    async fn key_for(self: &Arc<Self>, kid: &str, mono: Instant) -> Option<Key> {
        let (hit, fetch) = {
            let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            let hit = cache.keys.get(kid).cloned();
            let stale = cache
                .fetched_at
                .is_some_and(|t| mono.saturating_duration_since(t) >= JWKS_MAX_AGE);
            let fetch = (hit.is_none() || stale)
                && self.source.fetches()
                && Self::claim_attempt(&mut cache, mono);
            (hit, fetch)
        };
        if !fetch {
            return hit;
        }
        if hit.is_some() {
            let this = Arc::clone(self);
            tokio::spawn(async move { this.fetch_and_store(mono).await });
            return hit;
        }
        self.fetch_and_store(mono).await;
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.keys.get(kid).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{self, KeyPair, RsaKeyPair};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::Serialize;
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use std::time::UNIX_EPOCH;

    const NOW_S: u64 = 1_700_000_000;
    const TEAM: &str = "test.cloudflareaccess.com";
    const AUD: &str = "aud123";

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW_S)
    }

    #[derive(Serialize)]
    struct HeaderOut<'a> {
        alg: &'a str,
        kid: &'a str,
        typ: &'a str,
    }

    #[derive(Serialize)]
    #[serde(untagged)]
    enum AudOut<'a> {
        One(&'a str),
        Many(Vec<&'a str>),
    }

    #[derive(Serialize)]
    struct ClaimsOut<'a> {
        iss: &'a str,
        aud: AudOut<'a>,
        exp: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        nbf: Option<u64>,
    }

    #[derive(Serialize)]
    struct JwkOut {
        kid: String,
        kty: String,
        n: String,
        e: String,
    }

    #[derive(Serialize)]
    struct JwksOut {
        keys: Vec<JwkOut>,
    }

    fn b64(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    /// Two RSA-2048 keys, generated once for the whole test binary.
    fn keys() -> &'static (RsaKeyPair, RsaKeyPair) {
        static KEYS: OnceLock<(RsaKeyPair, RsaKeyPair)> = OnceLock::new();
        KEYS.get_or_init(|| {
            (
                RsaKeyPair::generate(KeySize::Rsa2048).unwrap(),
                RsaKeyPair::generate(KeySize::Rsa2048).unwrap(),
            )
        })
    }

    /// The modulus and exponent of a PKCS#1 `RSAPublicKey` DER, without
    /// leading zeros (the form a JWK carries).
    fn rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        fn len(d: &[u8], i: &mut usize) -> usize {
            let b = d[*i];
            *i += 1;
            if b < 0x80 {
                return b as usize;
            }
            let n = (b & 0x7f) as usize;
            let v = d[*i..*i + n]
                .iter()
                .fold(0usize, |a, x| (a << 8) | *x as usize);
            *i += n;
            v
        }
        fn int(d: &[u8], i: &mut usize) -> Vec<u8> {
            assert_eq!(d[*i], 0x02);
            *i += 1;
            let l = len(d, i);
            let v = d[*i..*i + l].to_vec();
            *i += l;
            let skip = v.iter().take_while(|b| **b == 0).count();
            v[skip..].to_vec()
        }
        let mut i = 0;
        assert_eq!(der[i], 0x30);
        i += 1;
        let _ = len(der, &mut i);
        let n = int(der, &mut i);
        let e = int(der, &mut i);
        (n, e)
    }

    fn jwk(kid: &str, key: &RsaKeyPair) -> JwkOut {
        let (n, e) = rsa_components(key.public_key().as_ref());
        JwkOut {
            kid: kid.to_owned(),
            kty: "RSA".to_owned(),
            n: b64(&n),
            e: b64(&e),
        }
    }

    fn jwks(entries: &[(&str, &RsaKeyPair)]) -> String {
        serde_json::to_string(&JwksOut {
            keys: entries.iter().map(|(k, p)| jwk(k, p)).collect(),
        })
        .unwrap()
    }

    fn good_claims() -> ClaimsOut<'static> {
        ClaimsOut {
            iss: "https://test.cloudflareaccess.com",
            aud: AudOut::One(AUD),
            exp: NOW_S + 3600,
            nbf: None,
        }
    }

    fn sign_with(key: &RsaKeyPair, alg: &str, kid: &str, claims: &ClaimsOut<'_>) -> String {
        let header = serde_json::to_vec(&HeaderOut {
            alg,
            kid,
            typ: "JWT",
        })
        .unwrap();
        let payload = serde_json::to_vec(claims).unwrap();
        let input = format!("{}.{}", b64(&header), b64(&payload));
        let mut sig = vec![0u8; key.public_modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{input}.{}", b64(&sig))
    }

    fn headers(tokens: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for t in tokens {
            h.append(CF_ACCESS_JWT, t.parse().unwrap());
        }
        h
    }

    fn cfg(source: crate::config::JwksSource) -> crate::config::AccessConfig {
        crate::config::AccessConfig {
            team_domain: TEAM.to_owned(),
            audience: AUD.to_owned(),
            jwks: source,
        }
    }

    /// A verifier over a fixed key set that never fetches.
    fn static_verifier(entries: &[(&str, &RsaKeyPair)]) -> Arc<AccessVerifier> {
        AccessVerifier::new(&cfg(crate::config::JwksSource::TestStatic(jwks(entries)))).unwrap()
    }

    /// A verifier whose fetch seam returns the canned bodies in order
    /// (`None` is a failed fetch; an empty queue also fails) and counts calls.
    fn fetching_verifier(bodies: Vec<Option<String>>) -> (Arc<AccessVerifier>, Arc<FakeFetch>) {
        let fake = Arc::new(FakeFetch {
            calls: Mutex::new(0),
            bodies: Mutex::new(bodies.into()),
            gate: Mutex::new(None),
        });
        (
            AccessVerifier::with_fake(
                &cfg(crate::config::JwksSource::TeamCerts),
                Arc::clone(&fake),
            ),
            fake,
        )
    }

    fn calls(fake: &FakeFetch) -> usize {
        *fake.calls.lock().unwrap()
    }

    #[tokio::test]
    async fn a_valid_token_passes() {
        let (a, _) = keys();
        let v = static_verifier(&[("k1", a)]);
        let t = sign_with(a, "RS256", "k1", &good_claims());
        assert_eq!(v.verify(&headers(&[&t]), now()).await, Ok(()));
    }

    #[tokio::test]
    async fn refusals() {
        let (a, b) = keys();
        let v = static_verifier(&[("k1", a)]);
        let good = sign_with(a, "RS256", "k1", &good_claims());
        let claims = |f: &dyn Fn(&mut ClaimsOut<'static>)| {
            let mut c = good_claims();
            f(&mut c);
            sign_with(a, "RS256", "k1", &c)
        };
        let two = headers(&[&good, &good]);
        let table: Vec<(&str, HeaderMap, AccessRefusal)> = vec![
            ("no header", HeaderMap::new(), AccessRefusal::Missing),
            ("two headers", two, AccessRefusal::Malformed),
            (
                "two parts",
                headers(&["aaaa.bbbb"]),
                AccessRefusal::Malformed,
            ),
            (
                "four parts",
                headers(&[&format!("{good}.x")]),
                AccessRefusal::Malformed,
            ),
            (
                "not base64",
                headers(&["a!a.b.c"]),
                AccessRefusal::Malformed,
            ),
            (
                "HS256",
                headers(&[&sign_with(a, "HS256", "k1", &good_claims())]),
                AccessRefusal::Malformed,
            ),
            (
                "none",
                headers(&[&sign_with(a, "none", "k1", &good_claims())]),
                AccessRefusal::Malformed,
            ),
            (
                "unknown kid",
                headers(&[&sign_with(a, "RS256", "other", &good_claims())]),
                AccessRefusal::UnknownKey,
            ),
            (
                "another key under a known kid",
                headers(&[&sign_with(b, "RS256", "k1", &good_claims())]),
                AccessRefusal::BadSignature,
            ),
            (
                "wrong iss",
                headers(&[&claims(&|c| c.iss = "https://evil.cloudflareaccess.com")]),
                AccessRefusal::Issuer,
            ),
            (
                "aud without ours",
                headers(&[&claims(&|c| c.aud = AudOut::Many(vec!["x", "y"]))]),
                AccessRefusal::Audience,
            ),
            (
                "exp 61 s past",
                headers(&[&claims(&|c| c.exp = NOW_S - 61)]),
                AccessRefusal::Expired,
            ),
            (
                "nbf 61 s ahead",
                headers(&[&claims(&|c| c.nbf = Some(NOW_S + 61))]),
                AccessRefusal::NotYetValid,
            ),
        ];
        for (name, h, want) in table {
            assert_eq!(v.verify(&h, now()).await, Err(want), "{name}");
        }
    }

    #[tokio::test]
    async fn leeway_is_sixty_seconds() {
        let (a, _) = keys();
        let v = static_verifier(&[("k1", a)]);
        let mut c = good_claims();
        c.exp = NOW_S - 59;
        assert_eq!(
            v.verify(&headers(&[&sign_with(a, "RS256", "k1", &c)]), now())
                .await,
            Ok(())
        );
        let mut c = good_claims();
        c.nbf = Some(NOW_S + 59);
        assert_eq!(
            v.verify(&headers(&[&sign_with(a, "RS256", "k1", &c)]), now())
                .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn aud_may_be_a_string_or_a_list() {
        let (a, _) = keys();
        let v = static_verifier(&[("k1", a)]);
        for aud in [AudOut::One(AUD), AudOut::Many(vec!["other", AUD])] {
            let mut c = good_claims();
            c.aud = aud;
            assert_eq!(
                v.verify(&headers(&[&sign_with(a, "RS256", "k1", &c)]), now())
                    .await,
                Ok(())
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_kid_refetches_at_most_once_a_minute() {
        let (a, b) = keys();
        let (v, fake) = fetching_verifier(vec![
            Some(jwks(&[("k1", a)])),
            Some(jwks(&[("k1", a), ("k2", b)])),
        ]);
        let token = headers(&[&sign_with(b, "RS256", "k2", &good_claims())]);
        let t0 = Instant::now();
        assert_eq!(
            v.verify_at(&token, now(), t0).await,
            Err(AccessRefusal::UnknownKey)
        );
        assert_eq!(calls(&fake), 1);
        assert_eq!(
            v.verify_at(&token, now(), t0 + Duration::from_secs(10))
                .await,
            Err(AccessRefusal::UnknownKey)
        );
        assert_eq!(calls(&fake), 1);
        assert_eq!(
            v.verify_at(&token, now(), t0 + Duration::from_secs(61))
                .await,
            Ok(())
        );
        assert_eq!(calls(&fake), 2);
    }

    #[tokio::test]
    async fn a_failed_refetch_keeps_the_old_keys() {
        let (a, b) = keys();
        let (v, fake) = fetching_verifier(vec![Some(jwks(&[("k1", a)])), None]);
        let known = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let unknown = headers(&[&sign_with(b, "RS256", "k2", &good_claims())]);
        let t0 = Instant::now();
        assert_eq!(v.verify_at(&known, now(), t0).await, Ok(()));
        assert_eq!(calls(&fake), 1);
        assert_eq!(
            v.verify_at(&unknown, now(), t0 + Duration::from_secs(61))
                .await,
            Err(AccessRefusal::UnknownKey)
        );
        assert_eq!(calls(&fake), 2);
        assert_eq!(
            v.verify_at(&known, now(), t0 + Duration::from_secs(62))
                .await,
            Ok(())
        );
        assert_eq!(calls(&fake), 2);
    }

    #[tokio::test]
    async fn a_cache_older_than_a_day_is_refreshed() {
        let (a, _) = keys();
        let (v, fake) = fetching_verifier(vec![Some(jwks(&[("k1", a)])), Some(jwks(&[("k1", a)]))]);
        let token = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let t0 = Instant::now();
        assert_eq!(v.verify_at(&token, now(), t0).await, Ok(()));
        assert_eq!(
            v.verify_at(&token, now(), t0 + Duration::from_secs(23 * 3600))
                .await,
            Ok(())
        );
        assert_eq!(calls(&fake), 1);
        assert_eq!(
            v.verify_at(&token, now(), t0 + Duration::from_secs(25 * 3600))
                .await,
            Ok(())
        );
        settle(&fake, 2).await;
    }

    /// Wait for the background refresh to reach the seam.
    async fn settle(fake: &FakeFetch, want: usize) {
        for _ in 0..200 {
            if calls(fake) >= want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(calls(fake), want);
    }

    #[tokio::test]
    async fn a_stale_refresh_for_a_known_kid_does_not_make_the_request_wait() {
        let (a, _) = keys();
        let (v, fake) = fetching_verifier(vec![Some(jwks(&[("k1", a)])), Some(jwks(&[("k1", a)]))]);
        let token = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let t0 = Instant::now();
        assert_eq!(v.verify_at(&token, now(), t0).await, Ok(()));
        // From here the seam's fetch blocks until released.
        let gate = Arc::new(tokio::sync::Notify::new());
        *fake.gate.lock().unwrap() = Some(Arc::clone(&gate));
        let late = t0 + Duration::from_secs(25 * 3600);
        let done = tokio::time::timeout(Duration::from_secs(5), v.verify_at(&token, now(), late))
            .await
            .expect("verify waited for the refresh");
        assert_eq!(done, Ok(()));
        settle(&fake, 2).await;
        gate.notify_one();
    }

    #[tokio::test]
    async fn an_empty_cache_retries_after_five_seconds_not_sixty() {
        let (a, _) = keys();
        let (v, fake) = fetching_verifier(vec![None, Some(jwks(&[("k1", a)]))]);
        let token = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let t0 = Instant::now();
        assert_eq!(
            v.verify_at(&token, now(), t0).await,
            Err(AccessRefusal::UnknownKey)
        );
        assert_eq!(calls(&fake), 1);
        assert_eq!(
            v.verify_at(&token, now(), t0 + Duration::from_secs(3))
                .await,
            Err(AccessRefusal::UnknownKey)
        );
        assert_eq!(calls(&fake), 1);
        assert_eq!(
            v.verify_at(&token, now(), t0 + Duration::from_secs(6))
                .await,
            Ok(())
        );
        assert_eq!(calls(&fake), 2);
    }

    #[tokio::test]
    async fn with_keys_loaded_the_spacing_is_sixty_seconds() {
        let (a, b) = keys();
        let (v, fake) = fetching_verifier(vec![
            Some(jwks(&[("k1", a)])),
            Some(jwks(&[("k1", a), ("k2", b)])),
        ]);
        let known = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let unknown = headers(&[&sign_with(b, "RS256", "k2", &good_claims())]);
        let t0 = Instant::now();
        assert_eq!(v.verify_at(&known, now(), t0).await, Ok(()));
        assert_eq!(
            v.verify_at(&unknown, now(), t0 + Duration::from_secs(6))
                .await,
            Err(AccessRefusal::UnknownKey)
        );
        assert_eq!(calls(&fake), 1);
    }

    #[tokio::test]
    async fn warm_up_fills_the_cache_before_the_first_request() {
        let (a, _) = keys();
        let (v, fake) = fetching_verifier(vec![Some(jwks(&[("k1", a)]))]);
        v.warm();
        settle(&fake, 1).await;
        let token = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        // Close behind the warm-up attempt: no second fetch, and it passes.
        assert_eq!(v.verify(&token, now()).await, Ok(()));
        assert_eq!(calls(&fake), 1);
    }

    #[derive(Serialize)]
    struct EcOut {
        kid: String,
        kty: String,
        crv: String,
        x: String,
        y: String,
    }

    #[derive(Serialize)]
    struct BareRsaOut {
        kty: String,
        n: String,
        e: String,
    }

    #[derive(Serialize)]
    #[serde(untagged)]
    enum AnyJwk {
        Rsa(JwkOut),
        Ec(EcOut),
        Bare(BareRsaOut),
    }

    #[derive(Serialize)]
    struct MixedOut {
        keys: Vec<AnyJwk>,
    }

    fn ec() -> AnyJwk {
        AnyJwk::Ec(EcOut {
            kid: "ec1".into(),
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "AAAA".into(),
            y: "AAAA".into(),
        })
    }

    fn mixed(first: Vec<AnyJwk>, rsa: &[(&str, &RsaKeyPair)]) -> String {
        let mut keys = first;
        keys.extend(rsa.iter().map(|(k, p)| AnyJwk::Rsa(jwk(k, p))));
        serde_json::to_string(&MixedOut { keys }).unwrap()
    }

    #[tokio::test]
    async fn entries_it_cannot_use_are_skipped_not_fatal() {
        let (a, _) = keys();
        let token = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let (n, e) = rsa_components(a.public_key().as_ref());
        let bare = || {
            AnyJwk::Bare(BareRsaOut {
                kty: "RSA".into(),
                n: b64(&n),
                e: b64(&e),
            })
        };
        for (name, first) in [
            ("an EC entry", vec![ec()]),
            ("a kid-less RSA entry", vec![bare()]),
        ] {
            let doc = mixed(first, &[("k1", a)]);
            let v = AccessVerifier::new(&cfg(crate::config::JwksSource::TestStatic(doc))).unwrap();
            assert_eq!(v.verify(&token, now()).await, Ok(()), "{name}");
        }
    }

    #[tokio::test]
    async fn a_document_with_no_usable_key_keeps_the_old_cache() {
        let (a, b) = keys();
        let only_ec = mixed(vec![ec()], &[]);
        let (v, fake) = fetching_verifier(vec![Some(jwks(&[("k1", a)])), Some(only_ec)]);
        let known = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let unknown = headers(&[&sign_with(b, "RS256", "k2", &good_claims())]);
        let t0 = Instant::now();
        assert_eq!(v.verify_at(&known, now(), t0).await, Ok(()));
        assert_eq!(
            v.verify_at(&unknown, now(), t0 + Duration::from_secs(61))
                .await,
            Err(AccessRefusal::UnknownKey)
        );
        assert_eq!(calls(&fake), 2);
        assert_eq!(
            v.verify_at(&known, now(), t0 + Duration::from_secs(62))
                .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn token_shape_limits() {
        let (a, _) = keys();
        let v = static_verifier(&[("k1", a)]);
        let good = sign_with(a, "RS256", "k1", &good_claims());
        let (head, rest) = good.split_once('.').unwrap();
        let (payload, _sig) = rest.split_once('.').unwrap();
        let long = format!("{}.{}.{}", head, payload, "A".repeat(8200));
        let table = [
            ("over 8192 bytes", long),
            ("empty signature", format!("{head}.{payload}.")),
            ("empty payload", format!("{head}..AAAA")),
            ("empty header", format!(".{payload}.AAAA")),
        ];
        for (name, token) in table {
            assert_eq!(
                v.verify(&headers(&[&token]), now()).await,
                Err(AccessRefusal::Malformed),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn a_clock_before_1970_refuses() {
        let (a, _) = keys();
        let v = static_verifier(&[("k1", a)]);
        let token = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let before = UNIX_EPOCH - Duration::from_secs(5);
        assert_eq!(v.verify(&token, before).await, Err(AccessRefusal::Expired));
    }

    #[tokio::test]
    async fn the_issuer_compares_without_case() {
        let (a, _) = keys();
        let v = static_verifier(&[("k1", a)]);
        let mut c = good_claims();
        c.iss = "https://TEST.CloudflareAccess.com";
        assert_eq!(
            v.verify(&headers(&[&sign_with(a, "RS256", "k1", &c)]), now())
                .await,
            Ok(())
        );
    }

    #[test]
    fn each_refusal_class_is_named_once() {
        let (a, _) = keys();
        let v = static_verifier(&[("k1", a)]);
        for r in [
            AccessRefusal::Missing,
            AccessRefusal::Malformed,
            AccessRefusal::UnknownKey,
            AccessRefusal::BadSignature,
            AccessRefusal::Claims,
            AccessRefusal::Issuer,
            AccessRefusal::Audience,
            AccessRefusal::Expired,
            AccessRefusal::NotYetValid,
        ] {
            let name = r.class();
            assert!(!name.contains(' '), "{name}");
            assert!(v.note_refusal(&r), "{name}: first sighting prints");
            assert!(!v.note_refusal(&r), "{name}: second does not");
        }
    }

    #[tokio::test]
    async fn an_unknown_kid_costs_no_signature_check() {
        let (a, _) = keys();
        let v = static_verifier(&[("k1", a)]);
        let header = serde_json::to_vec(&HeaderOut {
            alg: "RS256",
            kid: "nope",
            typ: "JWT",
        })
        .unwrap();
        let payload = serde_json::to_vec(&good_claims()).unwrap();
        let token = format!("{}.{}.AAAA", b64(&header), b64(&payload));
        assert_eq!(
            v.verify(&headers(&[&token]), now()).await,
            Err(AccessRefusal::UnknownKey)
        );
    }

    #[tokio::test]
    async fn a_static_source_never_fetches() {
        let (a, b) = keys();
        let v = static_verifier(&[("k1", a)]);
        let token = headers(&[&sign_with(b, "RS256", "k2", &good_claims())]);
        assert_eq!(
            v.verify(&token, now()).await,
            Err(AccessRefusal::UnknownKey)
        );
    }

    #[test]
    fn a_bad_static_document_is_refused_at_start() {
        let c = cfg(crate::config::JwksSource::TestStatic("not json".to_owned()));
        assert!(AccessVerifier::new(&c).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_unknown_kids_share_one_fetch() {
        let (a, _) = keys();
        let (v, fake) = fetching_verifier(vec![Some(jwks(&[("k1", a)]))]);
        let token = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let t0 = Instant::now();
        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let (v, token) = (Arc::clone(&v), token.clone());
                tokio::spawn(async move { v.verify_at(&token, now(), t0).await })
            })
            .collect();
        for t in tasks {
            // The one that fetched passes; the rest are refused or pass,
            // but none starts a second fetch.
            let _ = t.await.unwrap();
        }
        assert_eq!(calls(&fake), 1);
    }

    #[tokio::test]
    async fn a_stale_cache_is_refreshed_once_for_a_thousand_requests() {
        let (a, _) = keys();
        let (v, fake) = fetching_verifier(vec![Some(jwks(&[("k1", a)])), Some(jwks(&[("k1", a)]))]);
        let token = headers(&[&sign_with(a, "RS256", "k1", &good_claims())]);
        let t0 = Instant::now();
        assert_eq!(v.verify_at(&token, now(), t0).await, Ok(()));
        let late = t0 + Duration::from_secs(25 * 3600);
        for _ in 0..1000 {
            assert_eq!(v.verify_at(&token, now(), late).await, Ok(()));
        }
        settle(&fake, 2).await;
        assert_eq!(calls(&fake), 2, "the first load plus one refresh");
    }
}
