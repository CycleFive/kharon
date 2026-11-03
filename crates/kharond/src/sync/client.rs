//! HTTP side of the sync client (REQ-CRY-005): prelogin, personal
//! API-key login (`client_credentials`, `scope=api`), and `/api/sync`.
//!
//! Only the endpoints official clients use are called (SPEC §9
//! "Compatibility"). TLS uses the same aws_lc_rs rustls provider as
//! `cdp::tls`, trusting the OS roots plus an optional extra CA for a
//! self-hosted server with a private CA (and the loopback fixture).

use std::sync::Arc;
use std::time::{Duration, Instant};

use kharon_bwcrypto::{Kdf, Secret};
use reqwest::{Method, StatusCode, header};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use tokio::sync::watch;

use super::SyncError;
use super::push::{HubToken, NotificationsHub};
use super::wire::{PreloginResponse, SyncResponse, TokenResponse, normalize_keys};

/// `Device-Type` sent on every request: Bitwarden `DeviceType.LinuxCLI`.
pub const DEVICE_TYPE: &str = "25";
/// `Bitwarden-Client-Name`. kharon behaves as a CLI-style client.
pub const CLIENT_NAME: &str = "cli";
/// `Bitwarden-Client-Version`. Kept equal to the `bw` CLI the fixture
/// pins (`.github/workflows/fixture.yml`); cloud minimums are OQ-11.
pub const CLIENT_VERSION: &str = "2026.1.0";
/// `deviceName` in the token request.
pub const DEVICE_NAME: &str = "kharon";
/// Upper bound on any response body. A sync for a dedicated org is
/// small; this only stops a hostile server from exhausting memory.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// Refresh the access token this long before the server says it expires.
const TOKEN_SKEW: Duration = Duration::from_secs(60);

/// The account's personal API key. `client_secret` is a [`Secret`]:
/// no `Debug`, `Display` or `Serialize`.
pub struct ApiKey {
    client_id: String,
    client_secret: Secret<String>,
}

impl ApiKey {
    /// Build from parts. Only personal keys (`user.<uuid>`) are
    /// accepted: an organization key (`organization.<uuid>`) reaches
    /// the Public API only and yields no vault keys (SPEC §3.1).
    pub fn new(client_id: &str, client_secret: Zeroizing<String>) -> Result<Self, SyncError> {
        let client_id = client_id.trim();
        if client_id.starts_with("organization.") {
            return Err(SyncError::ApiKey(
                "organization API keys cannot sync a vault",
            ));
        }
        if !client_id.starts_with("user.") || client_id.len() <= "user.".len() {
            return Err(SyncError::ApiKey("client_id must be user.<uuid>"));
        }
        let secret = client_secret.trim();
        if secret.is_empty() {
            return Err(SyncError::ApiKey("client_secret is empty"));
        }
        Ok(Self {
            client_id: client_id.to_owned(),
            client_secret: Secret::new(secret.to_owned()),
        })
    }

    /// Parse the API-key file (`bitwarden.api_key_file`, a root-only
    /// file or Docker secret): a JSON object
    /// `{"client_id": "user.<uuid>", "client_secret": "…"}`.
    /// Parse errors never echo file content.
    pub fn from_json(text: &str) -> Result<Self, SyncError> {
        let bad = || SyncError::ApiKey("API key file must be {\"client_id\", \"client_secret\"}");
        let v: serde_json::Value = serde_json::from_str(text).map_err(|_| bad())?;
        let id = v
            .get("client_id")
            .and_then(|x| x.as_str())
            .ok_or_else(bad)?;
        let secret = v
            .get("client_secret")
            .and_then(|x| x.as_str())
            .ok_or_else(bad)?;
        Self::new(id, Zeroizing::new(secret.to_owned()))
    }

    /// Read and parse the API-key file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, SyncError> {
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|_| SyncError::ApiKey("API key file unreadable"))?,
        );
        Self::from_json(&text)
    }

    /// The public half (`user.<uuid>`).
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

/// Identity and API base URLs for a configured `bitwarden.server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub identity: Url,
    pub api: Url,
    /// Notifications service base (REQ-CRY-009 push); the hub is
    /// `<notifications>hub`.
    pub notifications: Url,
}

impl Endpoints {
    /// Self-hosted (Vaultwarden or Bitwarden) serves both under one
    /// origin at `/identity` and `/api`. Bitwarden cloud's web-vault
    /// hosts (`vault.bitwarden.com`, `vault.bitwarden.eu`) map to their
    /// dedicated `identity.` / `api.` hosts, as official clients do.
    pub fn for_server(server: &Url) -> Result<Self, SyncError> {
        if !matches!(server.scheme(), "http" | "https") || server.host_str().is_none() {
            return Err(SyncError::InvalidServerUrl);
        }
        let cloud = match server.host_str() {
            Some("vault.bitwarden.com") => Some("bitwarden.com"),
            Some("vault.bitwarden.eu") => Some("bitwarden.eu"),
            _ => None,
        };
        let parse = |s: String| Url::parse(&s).map_err(|_| SyncError::InvalidServerUrl);
        if let Some(domain) = cloud {
            return Ok(Self {
                identity: parse(format!("https://identity.{domain}/"))?,
                api: parse(format!("https://api.{domain}/"))?,
                notifications: parse(format!("https://notifications.{domain}/"))?,
            });
        }
        let base = server.as_str().trim_end_matches('/');
        Ok(Self {
            identity: parse(format!("{base}/identity/"))?,
            api: parse(format!("{base}/api/"))?,
            notifications: parse(format!("{base}/notifications/"))?,
        })
    }

    /// The notifications hub as a `ws(s)://` URL (REQ-CRY-009).
    pub fn hub(&self) -> Url {
        let http = self
            .notifications
            .join("hub")
            .expect("invariant: static relative path");
        super::push::ws_url(http).expect("invariant: endpoints are http(s)")
    }

    fn identity(&self, path: &str) -> Url {
        self.identity
            .join(path)
            .expect("invariant: static relative path")
    }

    fn api(&self, path: &str) -> Url {
        self.api
            .join(path)
            .expect("invariant: static relative path")
    }
}

/// A stable device identifier derived from the API key's client id.
/// Official clients persist a random UUID per install; kharon keeps no
/// state on disk for this, and a per-start random ID would look like a
/// new device on every restart (new-device mail / verification on
/// cloud, OQ-11). The client id is not secret, so hashing it leaks
/// nothing.
pub fn device_identifier(client_id: &str) -> String {
    let h = Sha256::digest(format!("kharon-device:{client_id}").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0f) | 0x50; // name-based (v5-style) version nibble
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let x = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &x[0..8],
        &x[8..12],
        &x[12..16],
        &x[16..20],
        &x[20..32]
    )
}

/// TLS trust for the Bitwarden server.
#[derive(Default)]
pub struct TlsTrust {
    /// Extra PEM CA certificates trusted in addition to the OS roots.
    pub extra_ca_pem: Option<Vec<u8>>,
}

fn tls_config(trust: &TlsTrust) -> Result<rustls::ClientConfig, SyncError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        // Individual unparsable OS certs are skipped, as browsers do.
        let _ = roots.add(cert);
    }
    if let Some(pem) = &trust.extra_ca_pem {
        let mut any = false;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|_| SyncError::Tls("extra CA is not valid PEM"))?;
            roots
                .add(cert)
                .map_err(|_| SyncError::Tls("extra CA certificate rejected"))?;
            any = true;
        }
        if !any {
            return Err(SyncError::Tls("extra CA file has no certificates"));
        }
    }
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| SyncError::Tls("TLS provider setup failed"))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

struct AccessToken {
    value: Arc<Zeroizing<String>>,
    refresh_after: Instant,
}

/// Talks to one Bitwarden/Vaultwarden server as one account.
pub struct SyncClient {
    http: reqwest::Client,
    endpoints: Endpoints,
    email: String,
    api_key: ApiKey,
    device_id: String,
    token: Option<AccessToken>,
    /// The rustls config `http` uses, kept for the hub's WebSocket.
    tls: Arc<rustls::ClientConfig>,
    /// Publishes the current access token to the notifications hub
    /// client. Dropped with the client, which ends the push task.
    token_tx: watch::Sender<Option<HubToken>>,
}

impl SyncClient {
    pub fn new(
        server: &Url,
        email: &str,
        api_key: ApiKey,
        trust: &TlsTrust,
    ) -> Result<Self, SyncError> {
        let endpoints = Endpoints::for_server(server)?;
        let mut headers = header::HeaderMap::new();
        headers.insert("Device-Type", header::HeaderValue::from_static(DEVICE_TYPE));
        headers.insert(
            "Bitwarden-Client-Name",
            header::HeaderValue::from_static(CLIENT_NAME),
        );
        headers.insert(
            "Bitwarden-Client-Version",
            header::HeaderValue::from_static(CLIENT_VERSION),
        );
        let tls = tls_config(trust)?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls.clone())
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            // A redirect could carry the bearer token to another host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| SyncError::Tls("HTTP client setup failed"))?;
        let device_id = device_identifier(api_key.client_id());
        Ok(Self {
            http,
            endpoints,
            email: email.trim().to_owned(),
            api_key,
            device_id,
            token: None,
            tls: Arc::new(tls),
            token_tx: watch::Sender::new(None),
        })
    }

    /// The REQ-CRY-009 push source for this account: the hub URL, the
    /// same TLS trust as the HTTP client, and a view of the access
    /// token this client keeps fresh. Run it with
    /// [`super::run_push`].
    pub fn notifications_hub(&self) -> NotificationsHub {
        let mut tls = (*self.tls).clone();
        // HTTP/1.1 only: the WebSocket upgrade does not run over h2.
        tls.alpn_protocols.clear();
        NotificationsHub::new(
            self.endpoints.hub(),
            Arc::new(tls),
            self.token_tx.subscribe(),
        )
    }

    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    /// `POST /identity/accounts/prelogin` → validated KDF parameters
    /// (range-checked by `Kdf::from_prelogin`; the server is untrusted).
    pub async fn prelogin(&self) -> Result<Kdf, SyncError> {
        const EP: &str = "prelogin";
        let body = serde_json::json!({ "email": self.email }).to_string();
        let req = self
            .http
            .request(Method::POST, self.endpoints.identity("accounts/prelogin"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body);
        let v = send(req, EP).await?;
        let p: PreloginResponse =
            serde_json::from_value(normalize_keys(v)).map_err(|_| SyncError::Malformed(EP))?;
        Ok(Kdf::from_prelogin(
            p.kdf,
            p.kdf_iterations,
            p.kdf_memory,
            p.kdf_parallelism,
        )?)
    }

    /// REQ-API-007 clock probe: `GET /api/alive` (unauthenticated, the
    /// liveness endpoint official clients use) and read the response's
    /// `Date` header. Any status is accepted — only the header matters,
    /// and the body is not read.
    pub async fn clock_sample(&self) -> Result<crate::totp::ClockSample, SyncError> {
        const EP: &str = "alive";
        let resp = self
            .http
            .request(Method::GET, self.endpoints.api("alive"))
            .send()
            .await
            .map_err(|_| SyncError::Transport(EP))?;
        let local = std::time::SystemTime::now();
        resp.headers()
            .get(header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| crate::totp::ClockSample::from_date_header(v, local))
            .ok_or(SyncError::Malformed(EP))
    }

    /// API-key login: `client_credentials` grant, `scope=api`.
    pub async fn login(&mut self) -> Result<(), SyncError> {
        const EP: &str = "token";
        let form = [
            ("grant_type", "client_credentials"),
            ("scope", "api"),
            ("client_id", self.api_key.client_id.as_str()),
            (
                "client_secret",
                self.api_key.client_secret.expose_secret().as_str(),
            ),
            ("deviceType", DEVICE_TYPE),
            ("deviceIdentifier", self.device_id.as_str()),
            ("deviceName", DEVICE_NAME),
        ];
        let req = self
            .http
            .request(Method::POST, self.endpoints.identity("connect/token"))
            .form(&form);
        let v = send(req, EP).await?;
        let t: TokenResponse = serde_json::from_value(v).map_err(|_| SyncError::Malformed(EP))?;
        if let Some(tt) = &t.token_type
            && !tt.eq_ignore_ascii_case("bearer")
        {
            return Err(SyncError::Malformed(EP));
        }
        if t.access_token.is_empty() {
            return Err(SyncError::Malformed(EP));
        }
        let lifetime = Duration::from_secs(t.expires_in.unwrap_or(3600));
        let token = AccessToken {
            value: Arc::new(Zeroizing::new(t.access_token)),
            refresh_after: Instant::now() + lifetime.saturating_sub(TOKEN_SKEW),
        };
        self.token_tx.send_replace(Some(HubToken::new(
            Arc::clone(&token.value),
            token.refresh_after,
        )));
        self.token = Some(token);
        Ok(())
    }

    /// `GET /api/sync`, logging in first if there is no live token. A
    /// 401 (token revoked or expired early) triggers exactly one
    /// re-login and retry.
    pub async fn sync(&mut self) -> Result<SyncResponse, SyncError> {
        const EP: &str = "sync";
        let fresh = self
            .token
            .as_ref()
            .is_some_and(|t| Instant::now() < t.refresh_after);
        if !fresh {
            self.login().await?;
        }
        let v = match self.get_sync().await {
            Err(SyncError::Status { status: 401, .. }) => {
                self.login().await?;
                self.get_sync().await?
            }
            r => r?,
        };
        serde_json::from_value(normalize_keys(v)).map_err(|_| SyncError::Malformed(EP))
    }

    async fn get_sync(&self) -> Result<serde_json::Value, SyncError> {
        let token = self.token.as_ref().ok_or(SyncError::Malformed("token"))?;
        let mut url = self.endpoints.api("sync");
        url.set_query(Some("excludeDomains=true"));
        let req = self
            .http
            .get(url)
            .bearer_auth(token.value.as_str())
            .header(header::ACCEPT, "application/json");
        send(req, "sync").await
    }

    /// Drop the access token (lock).
    pub fn forget_token(&mut self) {
        self.token = None;
        self.token_tx.send_replace(None);
    }
}

/// Send, check status, read a bounded body, parse JSON. Error values
/// carry the endpoint name and status only, never body text (the
/// token endpoint echoes request fields in some error bodies).
async fn send(
    req: reqwest::RequestBuilder,
    ep: &'static str,
) -> Result<serde_json::Value, SyncError> {
    let mut resp = req.send().await.map_err(|_| SyncError::Transport(ep))?;
    let status = resp.status();
    if status != StatusCode::OK {
        return Err(SyncError::Status {
            endpoint: ep,
            status: status.as_u16(),
        });
    }
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Err(SyncError::TooLarge(ep));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| SyncError::Transport(ep))? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(SyncError::TooLarge(ep));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| SyncError::Malformed(ep))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_cry_005_endpoints_self_hosted_and_cloud() {
        let e = Endpoints::for_server(&Url::parse("http://vaultwarden:80").unwrap()).unwrap();
        assert_eq!(e.identity.as_str(), "http://vaultwarden/identity/");
        assert_eq!(e.api("sync").as_str(), "http://vaultwarden/api/sync");
        assert_eq!(e.hub().as_str(), "ws://vaultwarden/notifications/hub");
        let e = Endpoints::for_server(&Url::parse("https://vw.example.net/sub/").unwrap()).unwrap();
        assert_eq!(
            e.identity("connect/token").as_str(),
            "https://vw.example.net/sub/identity/connect/token"
        );
        assert_eq!(
            e.hub().as_str(),
            "wss://vw.example.net/sub/notifications/hub"
        );
        let e = Endpoints::for_server(&Url::parse("https://vault.bitwarden.com").unwrap()).unwrap();
        assert_eq!(
            e.identity("accounts/prelogin").as_str(),
            "https://identity.bitwarden.com/accounts/prelogin"
        );
        assert_eq!(e.api("sync").as_str(), "https://api.bitwarden.com/sync");
        assert_eq!(e.hub().as_str(), "wss://notifications.bitwarden.com/hub");
        let e = Endpoints::for_server(&Url::parse("https://vault.bitwarden.eu").unwrap()).unwrap();
        assert_eq!(e.api.as_str(), "https://api.bitwarden.eu/");
        assert!(Endpoints::for_server(&Url::parse("ftp://x").unwrap()).is_err());
    }

    #[test]
    fn req_cry_005_api_key_shapes() {
        let z = |s: &str| Zeroizing::new(s.to_owned());
        assert!(ApiKey::new("user.0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6", z("s")).is_ok());
        assert!(matches!(
            ApiKey::new("organization.0f3c", z("s")),
            Err(SyncError::ApiKey(_))
        ));
        assert!(ApiKey::new("user.", z("s")).is_err());
        assert!(ApiKey::new("user.x", z("  ")).is_err());
        let k = ApiKey::from_json(r#"{"client_id":"user.x","client_secret":"y"}"#).unwrap();
        assert_eq!(k.client_id(), "user.x");
        // A malformed file must not echo its content in the error.
        let e = ApiKey::from_json(r#"{"client_id":"user.x","client_secret":7}"#)
            .err()
            .unwrap()
            .to_string();
        assert!(!e.contains("user.x"));
    }

    #[test]
    fn req_cry_005_device_identifier_is_stable_uuid() {
        let a = device_identifier("user.a");
        assert_eq!(a, device_identifier("user.a"));
        assert_ne!(a, device_identifier("user.b"));
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "5");
    }
}
