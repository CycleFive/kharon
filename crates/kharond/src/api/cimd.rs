//! OAuth client admission for N3 Connect (REQ-OAU-002; N3 design
//! #226, D2, I4 and I7).
//!
//! Before an authorize request can reach a consent screen, its
//! `client_id` — the HTTPS URL of a Client ID Metadata Document
//! (CIMD) — must be admitted:
//!
//! 1. **Allow-list.** Only a `client_id` listed in `[oauth] clients`
//!    is ever fetched. Any other is refused `not_allowlisted` and
//!    never touches the network: the allow-list is what closes SSRF,
//!    the address rules below are defence in depth (D2).
//! 2. **Fetch.** The document is fetched over the sync client's
//!    outbound HTTPS stack (reqwest on rustls, native roots): no
//!    redirects, a 5 s timeout, a 16 KiB body cap. The host is
//!    resolved once, every resolved address is checked against the
//!    refused classes (loopback, private, link-local, the deploy's
//!    own), and the connection is pinned to those addresses with SNI
//!    and `Host` from the URL, so DNS rebinding has no second answer
//!    to swap in.
//! 3. **Validation.** The document's `client_id` must equal the URL
//!    exactly; `client_name` must be present; `redirect_uris` must
//!    be non-empty, all `https`, with no localhost; and
//!    `token_endpoint_auth_method` must be absent or `none` (public
//!    clients only, PKCE binds the code — A4).
//! 4. **Cache.** A validated document is cached per process for its
//!    `Cache-Control` max-age clamped to 1 h–24 h, never persisted.
//!    There is no stale-on-error (A16): a failed fetch with no fresh
//!    cached copy fails closed as `cimd_unavailable`.
//!
//! Every refusal is audited as `oauth_client_refused` (SPEC §7)
//! through [`RefusalAudit`], best effort — a failed append never
//! turns a refusal into an admission (the `owner_ui::OwnerAudit`
//! precedent). The authorize endpoint itself is #230; this module
//! is the admission decision it renders, including the plain
//! failure text (I4).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use url::Url;

use crate::audit::{Entry, Event};

/// The whole CIMD fetch — resolve, connect, TLS, body — gets 5 s
/// (REQ-OAU-002).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// A CIMD is a small JSON document; 16 KiB is generous (REQ-OAU-002).
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
/// Cache lifetime floor and ceiling: the document's own max-age,
/// clamped into `[1 h, 24 h]` (REQ-OAU-002).
pub const MIN_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
/// See [`MIN_CACHE_TTL`].
pub const MAX_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// A validated CIMD: the only facts admission vouches for. The
/// consent screen (#230) shows `client_name`; the authorize checks
/// compare a requested `redirect_uri` against `redirect_uris`
/// through [`ClientAdmission::check_redirect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMetadata {
    /// The `client_id`: the URL the document was fetched from,
    /// byte-equal to the document's own `client_id` field.
    client_id: String,
    /// `client_name`, shown on the consent screen.
    client_name: String,
    /// The document's `redirect_uris`, each validated `https`.
    redirect_uris: Vec<String>,
}

impl ClientMetadata {
    /// The `client_id` (its CIMD URL).
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The name the consent screen shows.
    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    /// The redirect URIs an authorize request may name.
    pub fn redirect_uris(&self) -> &[String] {
        &self.redirect_uris
    }
}

/// Why a client was refused: the `detail_code` of the
/// `oauth_client_refused` audit entry (SPEC §7, #226 I7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// The `client_id` is not on `[oauth] clients`; never fetched.
    NotAllowlisted,
    /// The CIMD could not be fetched — transport failure, timeout,
    /// oversize body, non-200 status, or a refused address — and no
    /// fresh cached copy exists. Fails closed (A16).
    CimdUnavailable,
    /// The fetched document is not a valid CIMD for this URL.
    CimdInvalid,
    /// The authorize request's `redirect_uri` is not one of the
    /// document's `redirect_uris`.
    RedirectMismatch,
}

impl RefusalCode {
    /// The audit `detail_code` (SPEC §7).
    pub fn detail_code(&self) -> &'static str {
        match self {
            Self::NotAllowlisted => "not_allowlisted",
            Self::CimdUnavailable => "cimd_unavailable",
            Self::CimdInvalid => "cimd_invalid",
            Self::RedirectMismatch => "redirect_mismatch",
        }
    }
}

/// A refused admission. The authorize endpoint renders
/// [`Refusal::plain_message`] on a plain page and never redirects
/// (REQ-OAU-002/-003).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("client refused ({})", code.detail_code())]
pub struct Refusal {
    code: RefusalCode,
}

impl Refusal {
    /// Why the client was refused.
    pub fn code(&self) -> RefusalCode {
        self.code
    }

    /// The plain text the authorize page shows for this refusal.
    /// The `cimd_unavailable` text is I4's, verbatim.
    pub fn plain_message(&self) -> &'static str {
        match self.code {
            RefusalCode::NotAllowlisted => "This dashboard is not on this kharon's allow-list.",
            RefusalCode::CimdUnavailable => {
                "We couldn't check this dashboard. Try again in a minute."
            }
            RefusalCode::CimdInvalid => "This dashboard's client metadata is not valid.",
            RefusalCode::RedirectMismatch => {
                "The address this dashboard sent does not match its client metadata."
            }
        }
    }
}

/// Where `oauth_client_refused` entries go (cf.
/// `owner_ui::OwnerAudit`, whose daemon shim appends through the
/// broker). Best effort by contract: the caller has already decided
/// to refuse, and a failed append must not undo that.
pub trait RefusalAudit: Send + Sync {
    /// Append one `oauth_client_refused` entry.
    fn client_refused(&self, entry: Entry);
}

/// The audit entry for a refusal (SPEC §7, #226 I7): no `agent_id`,
/// `origin` is the client's CIMD hostname when the `client_id`
/// parses as a URL, `channel` is the authorize flow's `web_ui`.
pub fn refusal_entry(client_id: &str, code: RefusalCode) -> Entry {
    let mut entry = Entry::new(Event::OauthClientRefused)
        .channel("web_ui")
        .result("refused")
        .detail_code(code.detail_code());
    if let Some(host) = Url::parse(client_id)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
    {
        entry = entry.origin(host);
    }
    entry
}

/// Client admission: the allow-list, the fetch and the cache.
/// Built by the daemon when `[oauth]` is set and held by the owner
/// UI for the authorize endpoint (#230).
pub struct ClientAdmission {
    /// The `[oauth] clients` allow-list, exact strings.
    clients: HashSet<String>,
    /// Validated documents by `client_id`. An expired entry is
    /// never served (no stale-on-error, A16); it is only replaced
    /// by a fresh fetch. Bounded by the allow-list's size.
    cache: Mutex<HashMap<String, Cached>>,
    source: Source,
    audit: Arc<dyn RefusalAudit>,
}

struct Cached {
    metadata: ClientMetadata,
    expires: Instant,
}

impl ClientAdmission {
    /// Admission over the production fetch (resolve, pin, HTTPS).
    pub fn new(clients: &[String], audit: Arc<dyn RefusalAudit>) -> Self {
        Self::with_source(clients, audit, Source::Remote)
    }

    fn with_source(clients: &[String], audit: Arc<dyn RefusalAudit>, source: Source) -> Self {
        Self {
            clients: clients.iter().cloned().collect(),
            cache: Mutex::new(HashMap::new()),
            source,
            audit,
        }
    }

    /// Admit a `client_id` from an authorize request: allow-list,
    /// then a fresh cached document if one exists, else a fetch and
    /// validation. Every refusal is audited before it is returned.
    pub async fn admit(&self, client_id: &str) -> Result<ClientMetadata, Refusal> {
        if !self.clients.contains(client_id) {
            return Err(self.refuse(client_id, RefusalCode::NotAllowlisted));
        }
        if let Some(metadata) = self
            .cache
            .lock()
            .unwrap()
            .get(client_id)
            .filter(|c| c.expires > Instant::now())
            .map(|c| c.metadata.clone())
        {
            return Ok(metadata);
        }
        // Cache miss or expired: fetch. An expired entry is not
        // served while the fetch runs, nor if it fails (A16).
        let fetched = match self.source.fetch(client_id).await {
            Ok(doc) => doc,
            Err(_) => return Err(self.refuse(client_id, RefusalCode::CimdUnavailable)),
        };
        match validate_document(client_id, &fetched.body) {
            Ok(metadata) => {
                let ttl = cache_ttl(fetched.cache_control.as_deref());
                self.cache.lock().unwrap().insert(
                    client_id.to_owned(),
                    Cached {
                        metadata: metadata.clone(),
                        expires: Instant::now() + ttl,
                    },
                );
                Ok(metadata)
            }
            Err(code) => Err(self.refuse(client_id, code)),
        }
    }

    /// Check an authorize request's `redirect_uri` against the
    /// admitted document: an exact string match with one of its
    /// `redirect_uris` (D2). A mismatch is audited
    /// `redirect_mismatch`; the caller renders a plain page and
    /// never redirects.
    pub fn check_redirect(
        &self,
        client: &ClientMetadata,
        redirect_uri: &str,
    ) -> Result<(), Refusal> {
        if client.redirect_uris.iter().any(|u| u == redirect_uri) {
            Ok(())
        } else {
            Err(self.refuse(client.client_id(), RefusalCode::RedirectMismatch))
        }
    }

    /// Audit, then return, a refusal.
    fn refuse(&self, client_id: &str, code: RefusalCode) -> Refusal {
        self.audit.client_refused(refusal_entry(client_id, code));
        Refusal { code }
    }
}

/// A fetched document and the response's `Cache-Control`, if any.
#[derive(Debug)]
struct FetchedDocument {
    body: Vec<u8>,
    cache_control: Option<String>,
}

/// How a fetch failed. Every class maps to `cimd_unavailable` at
/// admission; the class name is kept for the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchFault {
    /// DNS, connect, TLS or client-setup failure.
    Connect,
    /// The 5 s budget elapsed.
    Timeout,
    /// A non-200 status — including a 3xx, which is never followed.
    Status(u16),
    /// The body exceeded [`MAX_DOCUMENT_BYTES`].
    TooLarge,
    /// A resolved address is loopback, private, link-local or the
    /// deploy's own.
    RefusedAddress,
}

impl FetchFault {
    #[cfg(test)]
    fn class(&self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Timeout => "timeout",
            Self::Status(_) => "status",
            Self::TooLarge => "too_large",
            Self::RefusedAddress => "refused_address",
        }
    }
}

/// Where documents come from: the network in production, canned
/// answers in tests (the `owner_ui::access` `KeySource` pattern).
enum Source {
    Remote,
    #[cfg(test)]
    Fake(Arc<FakeFetch>),
}

impl Source {
    async fn fetch(&self, url: &str) -> Result<FetchedDocument, FetchFault> {
        match self {
            Self::Remote => fetch_remote(url).await,
            #[cfg(test)]
            Self::Fake(fake) => fake.fetch(),
        }
    }
}

/// One canned fetch outcome: `Ok((body, cache_control))` or
/// `Err(())` for a fetch fault.
#[cfg(test)]
type FakeOutcome = Result<(String, Option<String>), ()>;

/// Canned fetch answers for tests: each call pops one outcome
/// and counts the call.
#[cfg(test)]
struct FakeFetch {
    calls: Mutex<usize>,
    outcomes: Mutex<std::collections::VecDeque<FakeOutcome>>,
}

#[cfg(test)]
impl FakeFetch {
    fn new(outcomes: Vec<FakeOutcome>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(0),
            outcomes: Mutex::new(outcomes.into()),
        })
    }

    fn fetch(&self) -> Result<FetchedDocument, FetchFault> {
        *self.calls.lock().unwrap() += 1;
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(()))
            .map(|(body, cache_control)| FetchedDocument {
                body: body.into_bytes(),
                cache_control,
            })
            .map_err(|()| FetchFault::Connect)
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

/// The production fetch (I4): resolve once, refuse bad addresses,
/// connect pinned to the answer, HTTPS with native roots.
async fn fetch_remote(url_str: &str) -> Result<FetchedDocument, FetchFault> {
    let url = Url::parse(url_str).map_err(|_| FetchFault::Connect)?;
    let host = url.host_str().ok_or(FetchFault::Connect)?;
    let port = url.port_or_known_default().ok_or(FetchFault::Connect)?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| FetchFault::Connect)?
        .collect();
    if addrs.is_empty() {
        return Err(FetchFault::Connect);
    }
    // All-or-nothing: any refused address in the answer refuses the
    // fetch, so a mixed answer can't steer the pinned connection.
    if addrs.iter().any(|a| address_refused(a.ip())) {
        return Err(FetchFault::RefusedAddress);
    }
    // The sync client's TLS stack (`sync/client.rs`), native roots
    // only: a CIMD is a public document on the public internet.
    let tls = crate::sync::tls_config(&crate::sync::TlsTrust { extra_ca_pem: None })
        .map_err(|_| FetchFault::Connect)?;
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        // Pin the checked answer: reqwest connects to these
        // addresses while SNI and `Host` come from the URL.
        .resolve_to_addrs(host, &addrs)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|_| FetchFault::Connect)?;
    get_document(&client, &url).await
}

/// One GET through an already-built client: 200 only, body streamed
/// under the cap, `Cache-Control` captured. Split from
/// [`fetch_remote`] so the redirect, cap and timeout behaviour is
/// testable against a local server with a test-built client.
async fn get_document(client: &reqwest::Client, url: &Url) -> Result<FetchedDocument, FetchFault> {
    let fault = |e: &reqwest::Error| {
        if e.is_timeout() {
            FetchFault::Timeout
        } else {
            FetchFault::Connect
        }
    };
    let mut resp = client
        .get(url.clone())
        .send()
        .await
        .map_err(|e| fault(&e))?;
    let status = resp.status();
    if status != reqwest::StatusCode::OK {
        return Err(FetchFault::Status(status.as_u16()));
    }
    let cache_control = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| fault(&e))? {
        if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Err(FetchFault::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(FetchedDocument {
        body,
        cache_control,
    })
}

/// Whether a resolved address may be connected to for a CIMD fetch:
/// not loopback, private, link-local or the deploy's own
/// (REQ-OAU-002).
fn address_refused(ip: IpAddr) -> bool {
    class_refused(ip) || is_own_address(ip)
}

/// The address classes D2 names, by range. An IPv4-mapped IPv6
/// address is judged as the IPv4 address it names, so a mapping
/// can't smuggle a refused class past the v6 checks.
fn class_refused(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => v4_class_refused(a),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => v4_class_refused(v4),
            None => v6_class_refused(a),
        },
    }
}

fn v4_class_refused(a: Ipv4Addr) -> bool {
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_broadcast()
        // 0.0.0.0/8, "this host on this network": never a host to
        // connect to (`is_unspecified` covers only 0.0.0.0 itself).
        || a.octets()[0] == 0
        // 100.64.0.0/10 (RFC 6598 shared address space): the
        // CGNAT / Tailscale range. `is_private` covers only
        // RFC 1918, so this passes it — but the tailnet carries
        // the owner UI, vault and raw CDP, so it is refused here.
        || (a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 0x40)
}

fn v6_class_refused(a: Ipv6Addr) -> bool {
    if a.is_loopback() || a.is_unspecified() {
        return true;
    }
    let s0 = a.segments()[0];
    // fe80::/10 link-local; fc00::/7 unique local (the v6 private).
    (s0 & 0xffc0) == 0xfe80 || (s0 & 0xfe00) == 0xfc00
}

/// Whether `ip` is one of this host's own addresses: an address
/// assigned to a local interface accepts a UDP bind, any other
/// fails with `EADDRNOTAVAIL`. Port 0 asks for an ephemeral port,
/// so the probe never collides with a listener. This judges "the
/// deploy's own" from kharond's seat without an
/// interface-enumeration dependency.
fn is_own_address(ip: IpAddr) -> bool {
    UdpSocket::bind((ip, 0)).is_ok()
}

/// The cache lifetime for a fetched document: its `Cache-Control`
/// max-age clamped to [`MIN_CACHE_TTL`]–[`MAX_CACHE_TTL`]. An
/// absent or unparseable max-age counts as 0 and so caches at the
/// floor.
fn cache_ttl(cache_control: Option<&str>) -> Duration {
    let secs = cache_control.and_then(parse_max_age).unwrap_or(0);
    let ttl = Duration::from_secs(secs);
    if ttl < MIN_CACHE_TTL {
        MIN_CACHE_TTL
    } else if ttl > MAX_CACHE_TTL {
        MAX_CACHE_TTL
    } else {
        ttl
    }
}

fn parse_max_age(cache_control: &str) -> Option<u64> {
    for directive in cache_control.split(',') {
        let Some((name, value)) = directive.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("max-age") {
            return value.trim().trim_matches('"').parse().ok();
        }
    }
    None
}

/// Validate a fetched document against D2's rules. The document is
/// judged for the exact URL it was fetched from.
fn validate_document(client_id: &str, body: &[u8]) -> Result<ClientMetadata, RefusalCode> {
    let invalid = RefusalCode::CimdInvalid;
    let doc: Value = serde_json::from_slice(body).map_err(|_| invalid)?;
    // `client_id` equals the URL exactly.
    if doc.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err(invalid);
    }
    // `client_name` is present (and non-empty: it names the client
    // on the consent screen, where a blank name is no name).
    let client_name = doc
        .get("client_name")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
        .ok_or(invalid)?;
    // `redirect_uris` is non-empty, every entry `https` and none of
    // them localhost.
    let uris = doc
        .get("redirect_uris")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(invalid)?;
    let mut redirect_uris = Vec::with_capacity(uris.len());
    for uri in uris {
        let uri = uri.as_str().ok_or(invalid)?;
        if !redirect_uri_ok(uri) {
            return Err(invalid);
        }
        redirect_uris.push(uri.to_owned());
    }
    // Public clients only: absent or `none` (A4).
    match doc.get("token_endpoint_auth_method") {
        None => {}
        Some(v) if v.as_str() == Some("none") => {}
        Some(_) => return Err(invalid),
    }
    Ok(ClientMetadata {
        client_id: client_id.to_owned(),
        client_name: client_name.to_owned(),
        redirect_uris,
    })
}

/// A `redirect_uris` entry: an `https` URL whose host is not
/// localhost — not the name, not a subdomain of it, and not a
/// loopback address (A3: dashboards are web services, loopback
/// redirects are refused).
fn redirect_uri_ok(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.to_ascii_lowercase();
            // The WHATWG parser keeps a trailing root dot, so
            // `localhost.` is not `localhost`: trim one trailing
            // `.` before comparing.
            let d = d.strip_suffix('.').unwrap_or(&d);
            d != "localhost" && !d.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(a)) => !a.is_loopback(),
        Some(url::Host::Ipv6(a)) => !a.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    const CLIENT: &str = "https://dashboard.example/.well-known/kharon-client.json";
    const REDIRECT: &str = "https://dashboard.example/oauth/callback";

    /// A valid CIMD for [`CLIENT`].
    fn valid_doc() -> String {
        format!(
            r#"{{"client_id": "{CLIENT}", "client_name": "Muse dashboard",
                 "redirect_uris": ["{REDIRECT}"],
                 "token_endpoint_auth_method": "none"}}"#
        )
    }

    /// An audit sink that keeps the entries it was handed.
    struct Recorded(Mutex<Vec<Entry>>);

    impl Recorded {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Vec::new())))
        }
        fn entries(&self) -> Vec<Entry> {
            self.0.lock().unwrap().clone()
        }
    }

    impl RefusalAudit for Recorded {
        fn client_refused(&self, entry: Entry) {
            self.0.lock().unwrap().push(entry);
        }
    }

    fn admission(
        clients: &[&str],
        fake: &Arc<FakeFetch>,
        audit: &Arc<Recorded>,
    ) -> ClientAdmission {
        ClientAdmission::with_source(
            &clients.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            audit.clone(),
            Source::Fake(fake.clone()),
        )
    }

    fn ok(body: String, cache_control: Option<&str>) -> Result<(String, Option<String>), ()> {
        Ok((body, cache_control.map(str::to_owned)))
    }

    #[tokio::test]
    async fn an_unlisted_client_is_refused_and_never_fetched() {
        let fake = FakeFetch::new(vec![]);
        let audit = Recorded::new();
        let admission = admission(&[CLIENT], &fake, &audit);
        let err = admission
            .admit("https://evil.example/cimd.json")
            .await
            .unwrap_err();
        assert_eq!(err.code(), RefusalCode::NotAllowlisted);
        assert_eq!(fake.calls(), 0, "the allow-list gate is before the fetch");
        let entries = audit.entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.event.as_str(), "oauth_client_refused");
        assert_eq!(e.detail_code.as_deref(), Some("not_allowlisted"));
        assert_eq!(e.origin.as_deref(), Some("evil.example"));
        assert_eq!(e.agent_id, None);
        assert_eq!(e.channel.as_deref(), Some("web_ui"));
    }

    #[tokio::test]
    async fn a_valid_document_admits_and_is_cached() {
        let fake = FakeFetch::new(vec![ok(valid_doc(), Some("max-age=7200"))]);
        let audit = Recorded::new();
        let admission = admission(&[CLIENT], &fake, &audit);
        let first = admission.admit(CLIENT).await.unwrap();
        assert_eq!(first.client_id(), CLIENT);
        assert_eq!(first.client_name(), "Muse dashboard");
        assert_eq!(first.redirect_uris(), [REDIRECT]);
        let second = admission.admit(CLIENT).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(fake.calls(), 1, "the second admit is a cache hit");
        assert!(audit.entries().is_empty());
    }

    #[tokio::test]
    async fn a_failed_fetch_is_unavailable_and_fails_closed() {
        let fake = FakeFetch::new(vec![Err(())]);
        let audit = Recorded::new();
        let admission = admission(&[CLIENT], &fake, &audit);
        let err = admission.admit(CLIENT).await.unwrap_err();
        assert_eq!(err.code(), RefusalCode::CimdUnavailable);
        // I4's plain page text, verbatim.
        assert_eq!(
            err.plain_message(),
            "We couldn't check this dashboard. Try again in a minute."
        );
        let entries = audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].detail_code.as_deref(), Some("cimd_unavailable"));
        assert_eq!(entries[0].origin.as_deref(), Some("dashboard.example"));
    }

    #[tokio::test]
    async fn invalid_documents_are_refused_cimd_invalid() {
        let cases: Vec<(&str, String)> = vec![
            ("body is not JSON", "not json".to_owned()),
            (
                "client_id differs from the URL",
                valid_doc().replace(CLIENT, "https://dashboard.example/other.json"),
            ),
            (
                "client_name missing",
                format!(r#"{{"client_id": "{CLIENT}", "redirect_uris": ["{REDIRECT}"]}}"#),
            ),
            (
                "client_name empty",
                valid_doc().replace("Muse dashboard", ""),
            ),
            (
                "redirect_uris missing",
                format!(r#"{{"client_id": "{CLIENT}", "client_name": "Dash"}}"#),
            ),
            (
                "redirect_uris empty",
                valid_doc().replace(&format!(r#"["{REDIRECT}"]"#), "[]"),
            ),
            (
                "redirect_uri not https",
                valid_doc().replace(
                    "https://dashboard.example/oauth",
                    "http://dashboard.example/oauth",
                ),
            ),
            (
                "redirect_uri is localhost",
                valid_doc().replace(REDIRECT, "https://localhost:8443/callback"),
            ),
            (
                "redirect_uri is a localhost subdomain",
                valid_doc().replace(REDIRECT, "https://app.localhost/callback"),
            ),
            (
                "redirect_uri is localhost with a trailing dot",
                valid_doc().replace(REDIRECT, "https://localhost./callback"),
            ),
            (
                "redirect_uri is a localhost subdomain with a trailing dot",
                valid_doc().replace(REDIRECT, "https://app.localhost./callback"),
            ),
            (
                "redirect_uri is a loopback address",
                valid_doc().replace(REDIRECT, "https://127.0.0.1/callback"),
            ),
            (
                "token_endpoint_auth_method is not none",
                valid_doc().replace("\"none\"", "\"private_key_jwt\""),
            ),
        ];
        for (name, body) in cases {
            let fake = FakeFetch::new(vec![ok(body, None)]);
            let audit = Recorded::new();
            let admission = admission(&[CLIENT], &fake, &audit);
            let err = admission.admit(CLIENT).await.unwrap_err();
            assert_eq!(err.code(), RefusalCode::CimdInvalid, "case: {name}");
            let entries = audit.entries();
            assert_eq!(entries.len(), 1, "case: {name}");
            assert_eq!(
                entries[0].detail_code.as_deref(),
                Some("cimd_invalid"),
                "case: {name}"
            );
        }
    }

    #[tokio::test]
    async fn an_expired_cache_entry_is_never_served_stale() {
        let fake = FakeFetch::new(vec![ok(valid_doc(), Some("max-age=3600")), Err(())]);
        let audit = Recorded::new();
        let admission = admission(&[CLIENT], &fake, &audit);
        admission.admit(CLIENT).await.unwrap();
        // Age the cached copy past its expiry, as 1 h later would.
        admission
            .cache
            .lock()
            .unwrap()
            .get_mut(CLIENT)
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        // The refetch fails: no stale use, the refusal is unavailable.
        let err = admission.admit(CLIENT).await.unwrap_err();
        assert_eq!(err.code(), RefusalCode::CimdUnavailable);
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn an_expired_entry_is_replaced_by_a_fresh_fetch() {
        let renamed = valid_doc().replace("Muse dashboard", "Renamed dashboard");
        let fake = FakeFetch::new(vec![
            ok(valid_doc(), Some("max-age=3600")),
            ok(renamed, Some("max-age=3600")),
        ]);
        let audit = Recorded::new();
        let admission = admission(&[CLIENT], &fake, &audit);
        admission.admit(CLIENT).await.unwrap();
        admission
            .cache
            .lock()
            .unwrap()
            .get_mut(CLIENT)
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        let fresh = admission.admit(CLIENT).await.unwrap();
        assert_eq!(fresh.client_name(), "Renamed dashboard");
        assert_eq!(fake.calls(), 2);
    }

    #[tokio::test]
    async fn the_redirect_check_is_an_exact_match_and_audits_a_mismatch() {
        let fake = FakeFetch::new(vec![ok(valid_doc(), None)]);
        let audit = Recorded::new();
        let admission = admission(&[CLIENT], &fake, &audit);
        let client = admission.admit(CLIENT).await.unwrap();
        admission.check_redirect(&client, REDIRECT).unwrap();
        assert!(audit.entries().is_empty());
        // A trailing slash is a different URI: string-equal or refuse.
        let err = admission
            .check_redirect(&client, &format!("{REDIRECT}/"))
            .unwrap_err();
        assert_eq!(err.code(), RefusalCode::RedirectMismatch);
        let entries = audit.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].detail_code.as_deref(), Some("redirect_mismatch"));
        assert_eq!(entries[0].origin.as_deref(), Some("dashboard.example"));
    }

    #[test]
    fn cache_ttl_is_the_max_age_clamped_to_an_hour_through_a_day() {
        let hour = Duration::from_secs(3600);
        let day = Duration::from_secs(24 * 3600);
        assert_eq!(cache_ttl(None), hour, "absent counts as 0, floored");
        assert_eq!(cache_ttl(Some("max-age=10")), hour);
        assert_eq!(cache_ttl(Some("max-age=3600")), hour);
        assert_eq!(cache_ttl(Some("max-age=7200")), Duration::from_secs(7200));
        assert_eq!(cache_ttl(Some("public, max-age=90000")), day);
        assert_eq!(cache_ttl(Some("max-age=86400")), day);
        assert_eq!(cache_ttl(Some("no-cache")), hour, "no max-age, floored");
        assert_eq!(cache_ttl(Some("max-age=abc")), hour, "unparseable, floored");
        assert_eq!(cache_ttl(Some("MAX-AGE=4000")), Duration::from_secs(4000));
    }

    #[test]
    fn refused_address_classes() {
        let refused = [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "0.1.2.3",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fe90::abcd",
            "fc00::1",
            "fd12:3456::1",
            // IPv4-mapped: judged as the IPv4 they name.
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ];
        for ip in refused {
            assert!(class_refused(ip.parse().unwrap()), "{ip} must be refused");
        }
        let allowed = [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ];
        for ip in allowed {
            assert!(
                !class_refused(ip.parse().unwrap()),
                "{ip} is a public address"
            );
        }
    }

    #[test]
    fn own_addresses_are_detected_by_the_bind_probe() {
        assert!(is_own_address("127.0.0.1".parse().unwrap()));
        // TEST-NET-1 (192.0.2.0/24, RFC 5737): never assigned.
        assert!(!is_own_address("192.0.2.1".parse().unwrap()));
        assert!(address_refused("127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_cimd_host_resolving_to_loopback_is_refused() {
        // The production fetch: localhost resolves to a refused
        // class, so admission fails closed before any connect.
        let audit = Recorded::new();
        let admission =
            ClientAdmission::new(&["https://localhost:9/cimd.json".to_owned()], audit.clone());
        let err = admission
            .admit("https://localhost:9/cimd.json")
            .await
            .unwrap_err();
        assert_eq!(err.code(), RefusalCode::CimdUnavailable);
        assert_eq!(
            audit.entries()[0].detail_code.as_deref(),
            Some("cimd_unavailable")
        );
    }

    // ---- get_document against a local HTTP server ----

    struct Route {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        delay: Duration,
    }

    impl Route {
        fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: body.into(),
                delay: Duration::ZERO,
            }
        }
    }

    /// A one-shot HTTP/1.1 server on loopback: each connection's
    /// path is recorded, then the scripted route answers.
    struct TestServer {
        port: u16,
        hits: Arc<Mutex<Vec<String>>>,
    }

    fn test_server(routes: Vec<(&str, Route)>) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let routes: HashMap<String, Route> =
            routes.into_iter().map(|(p, r)| (p.to_owned(), r)).collect();
        let thread_hits = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let hits = thread_hits.clone();
                let route = {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        continue;
                    }
                    let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    // Drain the remaining headers.
                    loop {
                        let mut h = String::new();
                        match reader.read_line(&mut h) {
                            Ok(0) => break,
                            Ok(_) if h == "\r\n" => break,
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                    hits.lock().unwrap().push(path.clone());
                    routes.get(&path)
                };
                let Some(route) = route else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                };
                if !route.delay.is_zero() {
                    std::thread::sleep(route.delay);
                }
                let mut head = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    route.status,
                    route.body.len()
                );
                for (k, v) in &route.headers {
                    head += &format!("{k}: {v}\r\n");
                }
                head += "\r\n";
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&route.body);
            }
        });
        TestServer { port, hits }
    }

    fn test_client(timeout: Duration) -> reqwest::Client {
        // The sync client's TLS stack, like production: a bare
        // builder has no rustls crypto provider in this workspace
        // and panics at build.
        let tls = crate::sync::tls_config(&crate::sync::TlsTrust { extra_ca_pem: None }).unwrap();
        reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .unwrap()
    }

    fn local_url(server: &TestServer, path: &str) -> Url {
        Url::parse(&format!("http://127.0.0.1:{}{path}", server.port)).unwrap()
    }

    #[tokio::test]
    async fn get_document_reads_a_200_and_its_cache_control() {
        let mut route = Route::new(200, "{\"ok\":true}");
        route
            .headers
            .push(("Cache-Control".to_owned(), "max-age=7200".to_owned()));
        let server = test_server(vec![("/doc", route)]);
        let doc = get_document(
            &test_client(Duration::from_secs(5)),
            &local_url(&server, "/doc"),
        )
        .await
        .unwrap();
        assert_eq!(doc.body, b"{\"ok\":true}");
        assert_eq!(doc.cache_control.as_deref(), Some("max-age=7200"));
    }

    #[tokio::test]
    async fn get_document_does_not_follow_a_redirect() {
        let mut redirect = Route::new(302, "");
        redirect
            .headers
            .push(("Location".to_owned(), "/real".to_owned()));
        let server = test_server(vec![
            ("/doc", redirect),
            ("/real", Route::new(200, valid_doc())),
        ]);
        let err = get_document(
            &test_client(Duration::from_secs(5)),
            &local_url(&server, "/doc"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, FetchFault::Status(302));
        assert_eq!(err.class(), "status");
        assert_eq!(
            server.hits.lock().unwrap().as_slice(),
            ["/doc"],
            "the redirect target was never requested"
        );
    }

    #[tokio::test]
    async fn get_document_refuses_an_oversize_body() {
        let server = test_server(vec![("/doc", Route::new(200, vec![b'a'; 20_000]))]);
        let err = get_document(
            &test_client(Duration::from_secs(5)),
            &local_url(&server, "/doc"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, FetchFault::TooLarge);
    }

    #[tokio::test]
    async fn get_document_times_out() {
        let mut slow = Route::new(200, "{}");
        slow.delay = Duration::from_secs(1);
        let server = test_server(vec![("/doc", slow)]);
        let err = get_document(
            &test_client(Duration::from_millis(150)),
            &local_url(&server, "/doc"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, FetchFault::Timeout);
    }
}
