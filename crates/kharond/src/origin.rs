//! Origin binding per SPEC §6 (REQ-ORG-001).
//!
//! Decides whether a decrypted `login.uris[]` entry may be filled into a
//! page, using the Bitwarden match-type table reduced through the Public
//! Suffix List. Fail closed everywhere: anything unparseable, unknown, or
//! non-HTTPS (absent the explicit localhost/IP exception) is a mismatch.
//!
//! The PSL snapshot is vendored at `crates/kharond/data/public_suffix_list.dat`
//! and pinned by git; per SPEC it is refreshed at release time.
//! Snapshot: VERSION 2026-10-28_13-15-55_UTC, COMMIT 9dfbe819.

use std::net::IpAddr;
use std::sync::OnceLock;

use publicsuffix::{List, Psl};
use url::Url;

/// Vendored Mozilla Public Suffix List snapshot (SPEC §6: "PSL snapshot
/// pinned and updated in release").
const PSL_SNAPSHOT: &[u8] = include_bytes!("../data/public_suffix_list.dat");

/// `List` is `Send + Sync` and read-only after construction, so one process-
/// global snapshot amortizes parsing without locks on the decision path.
fn psl() -> &'static List {
    static PSL: OnceLock<List> = OnceLock::new();
    PSL.get_or_init(|| List::from_bytes(PSL_SNAPSHOT).expect("vendored PSL snapshot must parse"))
}

/// Bitwarden `uri.match` values (SPEC §6 table). `None` in the vault JSON
/// means "account default", which is `Domain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    /// eTLD+1 equal (PSL, including private section: `github.io` registrable
    /// domain is the user's own subdomain).
    Domain,
    /// Host and port equal.
    Host,
    /// Origin must be host-equal; prefix check on the full URL.
    StartsWith,
    /// Full URL equal (origin + path).
    Exact,
    /// Refused, fail closed.
    Regex,
    /// Refused.
    Never,
}

impl MatchType {
    /// Map the vault's integer `uri.match` (or `None` for the account
    /// default). Unknown discriminants refuse by returning `None`.
    pub fn from_bw_repr(repr: Option<u8>) -> Option<Self> {
        match repr {
            None | Some(0) => Some(Self::Domain),
            Some(1) => Some(Self::Host),
            Some(2) => Some(Self::StartsWith),
            Some(3) => Some(Self::Exact),
            Some(4) => Some(Self::Regex),
            Some(5) => Some(Self::Never),
            Some(_) => None,
        }
    }
}

/// Why a comparison refused the fill. Surfaced for audit logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MismatchReason {
    /// `uri.match` held a discriminant outside 0..=5.
    UnknownMatchType,
    /// Match type 4 is refused (SPEC §6).
    RegexRefused,
    /// Match type 5.
    NeverRefused,
    /// Item URI did not parse as an absolute URL.
    ItemUriInvalid,
    /// Page scheme is not `https` and not the literal-http localhost/IP exception.
    SchemeNotHttps,
    /// Page scheme is `http` but `allow_http` is false.
    HttpNotAllowed,
    /// eTLD+1 of page host differs from item host.
    DomainMismatch,
    /// Host differs (or port differs, for `Host`/`StartsWith`/`Exact`).
    HostMismatch,
    /// Origin equal but `location.href` does not carry the item URL prefix.
    HrefPrefixMismatch,
    /// Origin equal but path differs.
    PathMismatch,
}

/// Outcome of an origin comparison. `reason` is `Some` exactly when the
/// fill was refused, and carries the audit/log code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub reason: Option<MismatchReason>,
}

impl Decision {
    fn allow() -> Decision {
        Decision {
            allowed: true,
            reason: None,
        }
    }

    fn refuse(reason: MismatchReason) -> Decision {
        Decision {
            allowed: false,
            reason: Some(reason),
        }
    }
}

/// Runtime knobs for origin binding. Cross-origin iframe allowlisting
/// (REQ-ORG-004) arrives with the CDP work (#17) and is intentionally absent.
#[derive(Debug, Clone, Default)]
pub struct OriginConfig {
    /// Permit `http://` pages for localhost and literal-IP hosts, but only
    /// when the item URI is itself literally `http`. Default false.
    pub allow_http: bool,
}

/// A parsed item URI plus its resolved match type.
#[derive(Debug, Clone)]
pub struct OriginMatcher {
    url: Url,
    match_type: MatchType,
}

impl OriginMatcher {
    /// Parse an item URI and resolve `uri.match`. `None` selects the account
    /// default (`Domain`). Unknown discriminants refuse at decision time.
    pub fn new(item_uri: &str, bw_match: Option<u8>) -> Result<Self, MismatchReason> {
        let match_type =
            MatchType::from_bw_repr(bw_match).ok_or(MismatchReason::UnknownMatchType)?;
        let url = Url::parse(item_uri).map_err(|_| MismatchReason::ItemUriInvalid)?;
        if url.host_str().is_none() {
            return Err(MismatchReason::ItemUriInvalid);
        }
        Ok(OriginMatcher { url, match_type })
    }

    /// Broker-side decision: may this item fill into `page_href`?
    ///
    /// `page_href` is the frame's `location.href` read live via CDP in
    /// production (REQ-ORG-002); tests may pass any absolute URL.
    pub fn decide(&self, page_href: &str, cfg: &OriginConfig) -> Decision {
        if matches!(self.match_type, MatchType::Regex) {
            return Decision::refuse(MismatchReason::RegexRefused);
        }
        if matches!(self.match_type, MatchType::Never) {
            return Decision::refuse(MismatchReason::NeverRefused);
        }
        let page = match Url::parse(page_href) {
            Ok(u) => u,
            Err(_) => return Decision::refuse(MismatchReason::SchemeNotHttps),
        };
        if let Some(r) = scheme_gate(&page, &self.url, cfg) {
            return Decision::refuse(r);
        }
        match self.match_type {
            MatchType::Domain => self.domain_match(&page),
            MatchType::Host => self.host_match(&page),
            MatchType::StartsWith => self.starts_with_match(&page),
            MatchType::Exact => self.exact_match(&page),
            MatchType::Regex | MatchType::Never => unreachable!("refused above"),
        }
    }

    /// The broker-PSL-reduced comparand injected into the page for the
    /// `Domain` in-page check (no PSL in-page, SPEC §6 step 2).
    pub fn reduced_domain(&self) -> Option<String> {
        registrable(self.url.host_str()?)
    }

    fn domain_match(&self, page: &Url) -> Decision {
        let item_host = self.url.host_str().expect("validated in new");
        let page_host = page.host_str().expect("absolute http(s) URL has a host");
        // IPs have no PSL entry; Bitwarden treats Domain on an IP as host
        // equality, so mirror that. (`url` serializes IPv6 hosts with
        // brackets, which `IpAddr::from_str` rejects.)
        let item_ip = parse_ip(item_host);
        let page_ip = parse_ip(page_host);
        match (item_ip, page_ip) {
            (Some(a), Some(b)) => {
                return if a == b {
                    Decision::allow()
                } else {
                    Decision::refuse(MismatchReason::DomainMismatch)
                };
            }
            (Some(_), None) | (None, Some(_)) => {
                return Decision::refuse(MismatchReason::DomainMismatch);
            }
            (None, None) => {}
        }
        // Single-label names (`localhost`, intranet hosts) have no PSL
        // registrable domain either; Bitwarden falls back to host equality.
        match (registrable(item_host), registrable(page_host)) {
            (Some(a), Some(b)) if a == b => Decision::allow(),
            (None, None) if item_host == page_host => Decision::allow(),
            _ => Decision::refuse(MismatchReason::DomainMismatch),
        }
    }

    fn host_match(&self, page: &Url) -> Decision {
        if hosts_equal(&self.url, page) && effective_port(&self.url) == effective_port(page) {
            Decision::allow()
        } else {
            Decision::refuse(MismatchReason::HostMismatch)
        }
    }

    fn starts_with_match(&self, page: &Url) -> Decision {
        if !(hosts_equal(&self.url, page) && effective_port(&self.url) == effective_port(page)) {
            return Decision::refuse(MismatchReason::HostMismatch);
        }
        if page.as_str().starts_with(self.url.as_str()) {
            Decision::allow()
        } else {
            Decision::refuse(MismatchReason::HrefPrefixMismatch)
        }
    }

    fn exact_match(&self, page: &Url) -> Decision {
        if !(hosts_equal(&self.url, page) && effective_port(&self.url) == effective_port(page)) {
            return Decision::refuse(MismatchReason::HostMismatch);
        }
        if self.url.path() == page.path() {
            Decision::allow()
        } else {
            Decision::refuse(MismatchReason::PathMismatch)
        }
    }
}

/// Scheme gate (SPEC §6): the page must be `https`, except
/// `http://localhost`/IP pages only when the item URI is literally `http`
/// and `allow_http` is set. This is also the secure-context rule: the
/// http exception is by construction localhost/IP only.
fn scheme_gate(page: &Url, item: &Url, cfg: &OriginConfig) -> Option<MismatchReason> {
    match page.scheme() {
        "https" => None,
        "http" => {
            if !cfg.allow_http {
                return Some(MismatchReason::HttpNotAllowed);
            }
            if item.scheme() != "http" {
                return Some(MismatchReason::SchemeNotHttps);
            }
            let host = page.host_str()?;
            let local = host == "localhost"
                || host.parse::<IpAddr>().is_ok()
                || host.ends_with(".localhost");
            if local {
                None
            } else {
                Some(MismatchReason::SchemeNotHttps)
            }
        }
        _ => Some(MismatchReason::SchemeNotHttps),
    }
}

fn parse_ip(host: &str) -> Option<IpAddr> {
    let bare = match host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Some(inner) => inner,
        None => host,
    };
    bare.parse().ok()
}

fn hosts_equal(a: &Url, b: &Url) -> bool {
    // `url` normalizes host case and IDN (unicode in, punycode out), so
    // string equality is the IDNA-normalized comparison SPEC §6 requires.
    a.host_str() == b.host_str()
}

fn effective_port(u: &Url) -> u16 {
    u.port_or_known_default().unwrap_or(0)
}

/// eTLD+1 (registrable domain) per the vendored PSL, including the private
/// section, so `github.io` yields `user.github.io`.
fn registrable(host: &str) -> Option<String> {
    psl()
        .domain(host.as_bytes())
        .map(|d| String::from_utf8_lossy(d.as_bytes()).into_owned())
}

/// Live-page location fields, read from the frame (never from agent input,
/// REQ-ORG-002). Mirrors the comparands of SPEC §6 step 2 so the decision
/// can be re-evaluated atomically inside the isolated world.
#[derive(Debug, Clone)]
pub struct PageLocation {
    pub protocol: String,
    pub hostname: String,
    pub origin: String,
    pub href: String,
}

/// In-page mirror of the match table (SPEC §6 step 2). `reduced_domain` is
/// the broker-computed eTLD+1 for `Domain` items; ignored otherwise.
pub fn in_page_match(
    matcher: &OriginMatcher,
    reduced_domain: &str,
    page: &PageLocation,
) -> Decision {
    match matcher.match_type {
        MatchType::Regex => Decision::refuse(MismatchReason::RegexRefused),
        MatchType::Never => Decision::refuse(MismatchReason::NeverRefused),
        MatchType::Domain => {
            let host_ok = page.hostname == reduced_domain
                || page
                    .hostname
                    .strip_suffix(reduced_domain)
                    .is_some_and(|rest| rest.ends_with('.'));
            let scheme_ok = page.protocol == format!("{}:", matcher.url.scheme());
            if scheme_ok && host_ok {
                Decision::allow()
            } else {
                Decision::refuse(MismatchReason::DomainMismatch)
            }
        }
        MatchType::Host => {
            if page.origin == origin_string(&matcher.url) {
                Decision::allow()
            } else {
                Decision::refuse(MismatchReason::HostMismatch)
            }
        }
        MatchType::Exact => {
            if page.href == matcher.url.as_str() {
                Decision::allow()
            } else {
                Decision::refuse(MismatchReason::HrefPrefixMismatch)
            }
        }
        MatchType::StartsWith => {
            if page.origin == origin_string(&matcher.url)
                && page.href.starts_with(matcher.url.as_str())
            {
                Decision::allow()
            } else {
                Decision::refuse(MismatchReason::HrefPrefixMismatch)
            }
        }
    }
}

fn origin_string(u: &Url) -> String {
    u.origin().ascii_serialization()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTPS_ON: OriginConfig = OriginConfig { allow_http: false };
    const HTTP_ON: OriginConfig = OriginConfig { allow_http: true };

    fn decide(item: &str, mt: Option<u8>, page: &str) -> Decision {
        OriginMatcher::new(item, mt)
            .expect("item parses")
            .decide(page, &HTTPS_ON)
    }

    fn allowed(item: &str, mt: Option<u8>, page: &str) -> bool {
        decide(item, mt, page).allowed
    }

    fn page_location(href: &str) -> PageLocation {
        let u = Url::parse(href).unwrap();
        PageLocation {
            protocol: u.scheme().to_string() + ":",
            hostname: u.host_str().unwrap().to_string(),
            origin: u.origin().ascii_serialization(),
            href: href.to_string(),
        }
    }

    fn in_page(item: &str, mt: Option<u8>, href: &str) -> Decision {
        let m = OriginMatcher::new(item, mt).expect("item parses");
        let d = m.reduced_domain().unwrap_or_default();
        in_page_match(&m, &d, &page_location(href))
    }

    // ---- MatchType::from_bw_repr -------------------------------------

    #[test]
    fn req_org_001_bw_repr_mapping() {
        assert_eq!(MatchType::from_bw_repr(None), Some(MatchType::Domain));
        assert_eq!(MatchType::from_bw_repr(Some(0)), Some(MatchType::Domain));
        assert_eq!(MatchType::from_bw_repr(Some(1)), Some(MatchType::Host));
        assert_eq!(
            MatchType::from_bw_repr(Some(2)),
            Some(MatchType::StartsWith)
        );
        assert_eq!(MatchType::from_bw_repr(Some(3)), Some(MatchType::Exact));
        assert_eq!(MatchType::from_bw_repr(Some(4)), Some(MatchType::Regex));
        assert_eq!(MatchType::from_bw_repr(Some(5)), Some(MatchType::Never));
        assert_eq!(MatchType::from_bw_repr(Some(6)), None);
        assert_eq!(MatchType::from_bw_repr(Some(255)), None);
    }

    // ---- Domain (0) ----------------------------------------------------

    #[test]
    fn req_org_001_domain_basic_subdomain() {
        assert!(allowed(
            "https://example.com",
            Some(0),
            "https://example.com/"
        ));
        assert!(allowed(
            "https://example.com",
            None,
            "https://login.example.com/"
        ));
        assert!(allowed(
            "https://example.com",
            Some(0),
            "https://deep.sub.example.com/x?y#z"
        ));
    }

    #[test]
    fn req_org_001_domain_co_uk() {
        assert!(allowed(
            "https://example.co.uk",
            Some(0),
            "https://example.co.uk/"
        ));
        assert!(allowed(
            "https://example.co.uk",
            Some(0),
            "https://www.example.co.uk/login"
        ));
        assert!(!allowed(
            "https://example.co.uk",
            Some(0),
            "https://otherexample.co.uk/"
        ));
        assert!(!allowed(
            "https://example.co.uk",
            Some(0),
            "https://example.co.uk.evil.test/"
        ));
        assert!(!allowed(
            "https://example.co.uk",
            Some(0),
            "https://gov.uk/"
        ));
        assert!(!allowed(
            "https://example.co.uk",
            Some(0),
            "https://parliament.uk/"
        ));
    }

    #[test]
    fn req_org_001_domain_private_suffix_github_io() {
        // Private-section entry: registrable domain IS the user's subdomain.
        assert!(allowed(
            "https://user.github.io",
            Some(0),
            "https://user.github.io/"
        ));
        assert!(allowed(
            "https://user.github.io/app",
            Some(0),
            "https://user.github.io/app/login"
        ));
        assert!(!allowed(
            "https://user.github.io",
            Some(0),
            "https://other.github.io/"
        ));
        assert!(!allowed(
            "https://user.github.io",
            Some(0),
            "https://github.io/"
        ));
    }

    #[test]
    fn req_org_001_domain_idn_normalized() {
        // Unicode and punycode forms normalize to the same registrable domain.
        assert!(allowed(
            "https://münchen.de",
            Some(0),
            "https://www.münchen.de/"
        ));
        assert!(allowed(
            "https://xn--mnchen-3ya.de",
            Some(0),
            "https://www.münchen.de/"
        ));
        assert!(allowed(
            "https://münchen.de",
            Some(0),
            "https://xn--mnchen-3ya.de/"
        ));
        assert!(!allowed(
            "https://münchen.de",
            Some(0),
            "https://berlin.de/"
        ));
        assert!(!allowed(
            "https://münchen.de",
            Some(0),
            "https://fake-münchen.de/"
        ));
    }

    #[test]
    fn req_org_001_domain_ip_host_equality() {
        assert!(allowed(
            "https://192.168.1.1",
            Some(0),
            "https://192.168.1.1/"
        ));
        assert!(!allowed(
            "https://192.168.1.1",
            Some(0),
            "https://192.168.1.2/"
        ));
        assert!(!allowed(
            "https://192.168.1.1",
            Some(0),
            "https://example.com/"
        ));
        assert!(!allowed(
            "https://example.com",
            Some(0),
            "https://192.168.1.1/"
        ));
        assert!(allowed("https://[::1]", Some(0), "https://[::1]/"));
        assert!(!allowed("https://[::1]", Some(0), "https://[::2]/"));
    }

    #[test]
    fn req_org_001_domain_port_agnostic() {
        assert!(allowed(
            "https://example.com",
            Some(0),
            "https://example.com:8443/"
        ));
        assert!(allowed(
            "https://example.com:8443",
            Some(0),
            "https://sub.example.com/"
        ));
    }

    // ---- Host (1) ------------------------------------------------------

    #[test]
    fn req_org_001_host_ports() {
        assert!(allowed(
            "https://example.com",
            Some(1),
            "https://example.com/"
        ));
        assert!(allowed(
            "https://example.com:8443",
            Some(1),
            "https://example.com:8443/"
        ));
        // Default and explicit default port are the same effective port.
        assert!(allowed(
            "https://example.com",
            Some(1),
            "https://example.com:443/"
        ));
        assert!(!allowed(
            "https://example.com",
            Some(1),
            "https://example.com:8443/"
        ));
        assert!(!allowed(
            "https://example.com:8443",
            Some(1),
            "https://example.com/"
        ));
        assert!(!allowed(
            "https://example.com",
            Some(1),
            "https://sub.example.com/"
        ));
    }

    // ---- StartsWith (2) -------------------------------------------------

    #[test]
    fn req_org_001_starts_with() {
        assert!(allowed(
            "https://example.com/app",
            Some(2),
            "https://example.com/app/login"
        ));
        assert!(allowed(
            "https://example.com/app",
            Some(2),
            "https://example.com/app"
        ));
        assert!(!allowed(
            "https://example.com/app",
            Some(2),
            "https://example.com/other"
        ));
        // Host-equal is required first.
        assert!(!allowed(
            "https://example.com/app",
            Some(2),
            "https://sub.example.com/app/x"
        ));
        assert!(!allowed(
            "https://example.com/app",
            Some(2),
            "https://example.com:8443/app/x"
        ));
        assert!(!allowed(
            "https://example.com/app",
            Some(2),
            "http://localhost/app/x"
        ));
    }

    // ---- Exact (3) ------------------------------------------------------

    #[test]
    fn req_org_001_exact_path_equality() {
        assert!(allowed(
            "https://example.com/login",
            Some(3),
            "https://example.com/login"
        ));
        assert!(allowed(
            "https://example.com/login",
            Some(3),
            "https://example.com/login?reset=1"
        ));
        assert!(!allowed(
            "https://example.com/login",
            Some(3),
            "https://example.com/login/"
        ));
        assert!(!allowed(
            "https://example.com/login",
            Some(3),
            "https://example.com/other"
        ));
        assert!(!allowed(
            "https://example.com/login",
            Some(3),
            "https://sub.example.com/login"
        ));
        assert!(!allowed(
            "https://example.com/login",
            Some(3),
            "https://example.com:8443/login"
        ));
    }

    // ---- Refused match types --------------------------------------------

    #[test]
    fn req_org_001_regex_refused() {
        let d = decide("https://example.com/.*", Some(4), "https://example.com/");
        assert!(!d.allowed);
        assert_eq!(d.reason, Some(MismatchReason::RegexRefused));
    }

    #[test]
    fn req_org_001_never_refused() {
        let d = decide("https://example.com", Some(5), "https://example.com/");
        assert!(!d.allowed);
        assert_eq!(d.reason, Some(MismatchReason::NeverRefused));
    }

    #[test]
    fn req_org_001_unknown_match_type_refused() {
        let m = OriginMatcher::new("https://example.com", Some(9));
        assert!(m.is_err());
        assert_eq!(m.unwrap_err(), MismatchReason::UnknownMatchType);
    }

    // ---- Scheme gate ------------------------------------------------------

    #[test]
    fn req_org_001_scheme_gate_http() {
        // allow_http off: every http page refuses.
        assert!(!allowed(
            "https://example.com",
            Some(0),
            "http://example.com/"
        ));
        assert!(!allowed("http://localhost", Some(0), "http://localhost/"));

        // allow_http on: localhost and IPs pass when the item is literally http.
        assert!(
            OriginMatcher::new("http://localhost", Some(0))
                .unwrap()
                .decide("http://localhost:3000/", &HTTP_ON)
                .allowed
        );
        assert!(
            OriginMatcher::new("http://192.168.1.10", Some(0))
                .unwrap()
                .decide("http://192.168.1.10/", &HTTP_ON)
                .allowed
        );
        assert!(
            OriginMatcher::new("http://app.localhost", Some(0))
                .unwrap()
                .decide("http://app.localhost/", &HTTP_ON)
                .allowed
        );

        // Item not literally http → still refused.
        assert!(
            !OriginMatcher::new("https://localhost", Some(0))
                .unwrap()
                .decide("http://localhost/", &HTTP_ON)
                .allowed
        );

        // http public host refuses even with allow_http.
        assert!(
            !OriginMatcher::new("http://example.com", Some(0))
                .unwrap()
                .decide("http://example.com/", &HTTP_ON)
                .allowed
        );

        // Non-http(s) schemes always refuse.
        assert!(
            !OriginMatcher::new("ftp://example.com", Some(0))
                .unwrap()
                .decide("ftp://example.com/", &HTTP_ON)
                .allowed
        );
    }

    #[test]
    fn req_org_001_item_uri_invalid() {
        let m = OriginMatcher::new("not a url", Some(0));
        assert!(m.is_err());
        assert_eq!(m.unwrap_err(), MismatchReason::ItemUriInvalid);
        let m = OriginMatcher::new("", Some(0));
        assert_eq!(m.unwrap_err(), MismatchReason::ItemUriInvalid);
    }

    // ---- In-page comparands (SPEC §6 step 2) -----------------------------

    #[test]
    fn req_org_001_in_page_domain_suffix() {
        // Broker reduces d; page checks protocol + hostname == or ends with .+d.
        // String-suffix semantics: "www.example.co.uk" ends with
        // ".example.co.uk" and therefore passes, matching both the spec text
        // and the broker-side eTLD+1 comparison.
        assert!(in_page("https://example.co.uk", Some(0), "https://example.co.uk/").allowed);
        assert!(
            in_page(
                "https://example.co.uk",
                Some(0),
                "https://sub.example.co.uk/"
            )
            .allowed
        );
        assert!(
            in_page(
                "https://user.github.io",
                Some(0),
                "https://user.github.io/x"
            )
            .allowed
        );
        assert!(
            in_page(
                "https://user.github.io",
                Some(0),
                "https://app.user.github.io/x"
            )
            .allowed
        );
        assert!(
            in_page(
                "https://example.co.uk",
                Some(0),
                "https://www.example.co.uk/"
            )
            .allowed
        );
        assert!(!in_page("https://example.co.uk", Some(0), "https://evil.co.uk/").allowed);
        assert!(
            !in_page(
                "https://example.co.uk",
                Some(0),
                "https://example.co.uk.evil.test/"
            )
            .allowed
        );
        assert!(!in_page("https://example.co.uk", Some(0), "http://example.co.uk/").allowed);
    }

    #[test]
    fn req_org_001_in_page_exact_origin_match_href_mismatch() {
        // AC: matching origin with a non-matching href → origin_mismatch.
        let d = in_page(
            "https://example.com/login",
            Some(3),
            "https://example.com/other",
        );
        assert!(!d.allowed);
        assert!(
            in_page(
                "https://example.com/login",
                Some(3),
                "https://example.com/login"
            )
            .allowed
        );
        // Exact compares the full href, so a query string mismatches.
        assert!(
            !in_page(
                "https://example.com/login",
                Some(3),
                "https://example.com/login?x=1"
            )
            .allowed
        );
    }

    #[test]
    fn req_org_001_in_page_starts_with_origin_match_href_mismatch() {
        // AC: matching origin with a non-matching href → origin_mismatch.
        let d = in_page(
            "https://example.com/app",
            Some(2),
            "https://example.com/other",
        );
        assert!(!d.allowed);
        assert!(
            in_page(
                "https://example.com/app",
                Some(2),
                "https://example.com/app/login"
            )
            .allowed
        );
        assert!(
            !in_page(
                "https://example.com/app",
                Some(2),
                "https://sub.example.com/app/x"
            )
            .allowed
        );
        assert!(
            !in_page(
                "https://example.com/app",
                Some(2),
                "http://example.com/app/x"
            )
            .allowed
        );
    }

    #[test]
    fn req_org_001_in_page_host_uses_origin() {
        assert!(
            in_page(
                "https://example.com:8443",
                Some(1),
                "https://example.com:8443/"
            )
            .allowed
        );
        assert!(!in_page("https://example.com:8443", Some(1), "https://example.com/").allowed);
    }

    // ---- Snapshot sanity ---------------------------------------------------

    #[test]
    fn req_org_001_psl_snapshot_covers_known_suffixes() {
        // Guards against a corrupt or swapped snapshot file. Inputs are
        // punycode because the crate matches bytes without IDNA; production
        // inputs come from `url::Url::host_str`, which is always punycode.
        assert_eq!(
            registrable("www.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable("user.github.io").as_deref(),
            Some("user.github.io")
        );
        assert_eq!(
            registrable("www.xn--mnchen-3ya.de").as_deref(),
            Some("xn--mnchen-3ya.de")
        );
    }
}
