//! Client admission for `GET /oauth/authorize` (REQ-OAU-002/-003).
//!
//! This is the seam #229 fills in. #230's authorize endpoint calls
//! [`ClientAdmission::admit`] for D6 steps 1–3 (allow-list, CIMD,
//! exact `redirect_uri`) and does the auditing and the page itself.
//! An implementation of this trait **does not audit** and **does not
//! render**: one `oauth_client_refused` entry is written by the
//! authorize endpoint, so a fetch that also appended the event would
//! record it twice.
//!
//! [`AllowlistAdmission`] is what the daemon wires until #229 lands.
//! It checks the allow-list and then fails closed (`cimd_unavailable`).
//! It never fetches. [`FixtureClients`] is the in-memory double tests
//! use in its place.

use url::Url;

/// Why steps 1–3 refused a client. `client_host` is set only when the
/// `client_id` was on the operator allow-list, so the hostname is one
/// we configured, not one a stranger typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRefusal {
    pub kind: RefusalKind,
    pub client_host: Option<String>,
}

/// The four `oauth_client_refused` detail codes (I7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalKind {
    NotAllowlisted,
    CimdUnavailable,
    CimdInvalid,
    RedirectMismatch,
}

impl RefusalKind {
    /// The audit `detail_code`.
    pub fn detail_code(self) -> &'static str {
        match self {
            Self::NotAllowlisted => "not_allowlisted",
            Self::CimdUnavailable => "cimd_unavailable",
            Self::CimdInvalid => "cimd_invalid",
            Self::RedirectMismatch => "redirect_mismatch",
        }
    }

    /// The plain sentence the authorize error page shows. No request
    /// data is interpolated (REQ-API-006).
    pub fn message(self) -> &'static str {
        match self {
            Self::NotAllowlisted => "This dashboard isn't one kharon connects to.",
            Self::CimdUnavailable => "We couldn't check this dashboard. Try again in a minute.",
            Self::CimdInvalid => {
                "This dashboard's registration isn't valid, so kharon won't connect to it."
            }
            Self::RedirectMismatch => {
                "This dashboard asked to send you somewhere it hasn't registered."
            }
        }
    }
}

impl ClientRefusal {
    pub fn not_allowlisted() -> Self {
        Self {
            kind: RefusalKind::NotAllowlisted,
            client_host: None,
        }
    }

    pub fn with_host(kind: RefusalKind, client_id: &str) -> Self {
        Self {
            kind,
            client_host: display_host(client_id),
        }
    }
}

/// A client that passed steps 1–3. Every string is safe to show: the
/// name came from a document we accepted, the host from its URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedClient {
    pub client_id: String,
    pub client_name: String,
    /// Hostname of the CIMD URL, with a non-default port if it has one.
    pub client_host: String,
}

/// Steps 1–3 of authorize. `redirect_uri` is `None` when the request
/// omitted it or sent it more than once: the implementation then
/// cannot match, and a listed client is `redirect_mismatch` rather
/// than an open redirect.
pub trait ClientAdmission: Send + Sync + 'static {
    fn admit(
        &self,
        client_id: Option<&str>,
        redirect_uri: Option<&str>,
    ) -> Result<AdmittedClient, ClientRefusal>;
}

/// Fail-closed stand-in for #229's CIMD fetch.
///
/// A `client_id` that is not an exact allow-list entry is
/// `not_allowlisted` and is never fetched. A listed id is
/// `cimd_unavailable`: this type has no document and does not make a
/// request. #229 replaces the value the daemon stores on the owner UI
/// with the real fetch; it should keep this trait's contract (no
/// audit, no page).
#[derive(Debug, Clone)]
pub struct AllowlistAdmission {
    allowlist: Vec<String>,
}

impl AllowlistAdmission {
    pub fn new(allowlist: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowlist: allowlist.into_iter().map(Into::into).collect(),
        }
    }
}

impl ClientAdmission for AllowlistAdmission {
    fn admit(
        &self,
        client_id: Option<&str>,
        _redirect_uri: Option<&str>,
    ) -> Result<AdmittedClient, ClientRefusal> {
        let Some(id) = client_id else {
            return Err(ClientRefusal::not_allowlisted());
        };
        if !self.allowlist.iter().any(|c| c == id) {
            return Err(ClientRefusal::not_allowlisted());
        }
        Err(ClientRefusal::with_host(RefusalKind::CimdUnavailable, id))
    }
}

/// One client a test (or a caller that already holds a document)
/// admits without a fetch. `fail` forces a refusal after the
/// allow-list check, which is how a test names `cimd_invalid` and
/// `cimd_unavailable` without standing up a server.
#[derive(Debug, Clone)]
pub struct FixtureClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub fail: Option<RefusalKind>,
}

/// In-memory [`ClientAdmission`]. Not what production runs: the
/// daemon uses [`AllowlistAdmission`] until #229's fetch is wired,
/// and tests pass one of these in its place.
#[derive(Debug, Clone)]
pub struct FixtureClients {
    clients: Vec<FixtureClient>,
}

impl FixtureClients {
    pub fn new(clients: Vec<FixtureClient>) -> Self {
        Self { clients }
    }

    /// One healthy client. `redirect_uris` are matched by exact string.
    pub fn one(
        client_id: impl Into<String>,
        client_name: impl Into<String>,
        redirect_uris: Vec<String>,
    ) -> Self {
        Self::new(vec![FixtureClient {
            client_id: client_id.into(),
            client_name: client_name.into(),
            redirect_uris,
            fail: None,
        }])
    }
}

impl ClientAdmission for FixtureClients {
    fn admit(
        &self,
        client_id: Option<&str>,
        redirect_uri: Option<&str>,
    ) -> Result<AdmittedClient, ClientRefusal> {
        let Some(id) = client_id else {
            return Err(ClientRefusal::not_allowlisted());
        };
        let Some(client) = self.clients.iter().find(|c| c.client_id == id) else {
            return Err(ClientRefusal::not_allowlisted());
        };
        if let Some(kind) = client.fail {
            return Err(ClientRefusal::with_host(kind, id));
        }
        if client.client_name.is_empty() {
            return Err(ClientRefusal::with_host(RefusalKind::CimdInvalid, id));
        }
        let Some(redirect) = redirect_uri else {
            return Err(ClientRefusal::with_host(RefusalKind::RedirectMismatch, id));
        };
        if !client.redirect_uris.iter().any(|u| u == redirect) {
            return Err(ClientRefusal::with_host(RefusalKind::RedirectMismatch, id));
        }
        let Some(client_host) = display_host(id) else {
            return Err(ClientRefusal::with_host(RefusalKind::CimdInvalid, id));
        };
        Ok(AdmittedClient {
            client_id: client.client_id.clone(),
            client_name: client.client_name.clone(),
            client_host,
        })
    }
}

/// Hostname to show and to audit. `None` when `url` is not an https
/// URL with a host: the caller then keeps the host out of the log.
pub fn display_host(url: &str) -> Option<String> {
    let url = Url::parse(url).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?;
    if host.is_empty() || host.len() > 253 || host.bytes().any(|b| b.is_ascii_control()) {
        return None;
    }
    match url.port() {
        Some(port) => Some(format!("{host}:{port}")),
        None => Some(host.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_never_admits_and_never_needs_a_redirect() {
        let a = AllowlistAdmission::new(["https://dashboard.example/client.json"]);
        assert_eq!(
            a.admit(None, Some("https://dashboard.example/cb"))
                .unwrap_err()
                .kind,
            RefusalKind::NotAllowlisted
        );
        let other = a
            .admit(
                Some("https://evil.example/client.json"),
                Some("https://evil.example/cb"),
            )
            .unwrap_err();
        assert_eq!(other.kind, RefusalKind::NotAllowlisted);
        assert!(other.client_host.is_none());
        // Listed, even with a perfect redirect: no document, no fetch.
        let listed = a
            .admit(
                Some("https://dashboard.example/client.json"),
                Some("https://dashboard.example/cb"),
            )
            .unwrap_err();
        assert_eq!(listed.kind, RefusalKind::CimdUnavailable);
        assert_eq!(listed.client_host.as_deref(), Some("dashboard.example"));
    }

    #[test]
    fn fixture_matches_the_redirect_exactly() {
        let f = FixtureClients::one(
            "https://dashboard.example/client.json",
            "Muse",
            vec!["https://dashboard.example/cb".into()],
        );
        let ok = f
            .admit(
                Some("https://dashboard.example/client.json"),
                Some("https://dashboard.example/cb"),
            )
            .unwrap();
        assert_eq!(ok.client_name, "Muse");
        assert_eq!(ok.client_host, "dashboard.example");
        assert_eq!(
            f.admit(
                Some("https://dashboard.example/client.json"),
                Some("https://dashboard.example/cb?extra=1"),
            )
            .unwrap_err()
            .kind,
            RefusalKind::RedirectMismatch
        );
        assert_eq!(
            f.admit(Some("https://dashboard.example/client.json"), None)
                .unwrap_err()
                .kind,
            RefusalKind::RedirectMismatch
        );
    }
}
