//! Which site a host belongs to, by the Public Suffix List, and which hosts serve CAPTCHAs.

use std::net::IpAddr;
use std::sync::OnceLock;

use publicsuffix::{List, Psl};

/// The one vendored snapshot, shared with `kharond` as a data file (not as a crate).
const PSL_SNAPSHOT: &[u8] = include_bytes!("../../kharond/data/public_suffix_list.dat");

/// Hosts that serve a CAPTCHA. `google.com/recaptcha` is a path, so `capture` checks that case.
const CAPTCHA_HOSTS: [&str; 5] = [
    "recaptcha.net",
    "hcaptcha.com",
    "challenges.cloudflare.com",
    "arkoselabs.com",
    "funcaptcha.com",
];

fn psl() -> Option<&'static List> {
    static PSL: OnceLock<Option<List>> = OnceLock::new();
    PSL.get_or_init(|| List::from_bytes(PSL_SNAPSHOT).ok())
        .as_ref()
}

/// The registrable domain of `host` (its eTLD+1), lowercased. An IP address, a single-label host
/// such as `localhost`, or a host the list has no answer for is returned unchanged.
pub fn registrable_domain(host: &str) -> String {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if bare.parse::<IpAddr>().is_ok() {
        return host.to_owned();
    }
    psl()
        .and_then(|list| list.domain(host.as_bytes()))
        .map_or_else(
            || host.to_owned(),
            |d| String::from_utf8_lossy(d.as_bytes()).into_owned(),
        )
}

/// Whether `host`, or any parent domain of it, is a known CAPTCHA host.
pub fn is_captcha_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    CAPTCHA_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("login.ex.co.uk"), "ex.co.uk");
        assert_eq!(registrable_domain("login.ex.test"), "ex.test");
        assert_eq!(registrable_domain("ex.test"), "ex.test");
        assert_eq!(registrable_domain("127.0.0.1"), "127.0.0.1");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("[::1]"), "[::1]");
    }

    #[test]
    fn captcha_hosts_match_the_host_and_its_subdomains() {
        assert!(is_captcha_host("hcaptcha.com"));
        assert!(is_captcha_host("newassets.hcaptcha.com"));
        assert!(is_captcha_host("challenges.cloudflare.com"));
        assert!(is_captcha_host("www.recaptcha.net"));
        assert!(!is_captcha_host("cloudflare.com"));
        assert!(!is_captcha_host("nothcaptcha.com"));
        assert!(!is_captcha_host("www.google.com"));
    }
}
