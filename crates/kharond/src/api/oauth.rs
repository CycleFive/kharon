//! OAuth discovery (REQ-OAU-001; N3 design #226, D1).
//!
//! With `[oauth]` configured, kharond is both the authorization
//! server and the resource server, on two hostnames:
//!
//! | Document | Served on | Route |
//! |---|---|---|
//! | RFC 9728 protected-resource metadata | `[public_ingress]` (the agent hostname) | `GET /.well-known/oauth-protected-resource/mcp` and `GET /.well-known/oauth-protected-resource` |
//! | RFC 9728 connector protected-resource metadata (#235 D1, REQ-OAU-009) | `[public_ingress]` (the agent hostname) | `GET /.well-known/oauth-protected-resource/connector`, only when a `[connector]` certificate is configured |
//! | RFC 8414 authorization-server metadata | the owner hostname (`[owner_ui]`) | `GET /.well-known/oauth-authorization-server` |
//!
//! The issuer is the `[owner_ui]` origin, no path. The protected
//! resource is the deploy's public `/mcp` URL, built from
//! `[public_ingress] public_host`; config validation (REQ-OAU-001)
//! refuses `[oauth]` without either, so a [`Discovery`] value is
//! only ever built whole. Both documents are pure functions of the
//! config: they are built once here and served verbatim.
//!
//! The `/mcp` 401 also changes shape with `[oauth]` set: its
//! `WWW-Authenticate` gains `resource_metadata` and `scope`
//! ([`Discovery::challenge`]). Without `[oauth]` the challenge is
//! the bare `Bearer realm="kharon"` it has always been. Scope
//! *enforcement* — the 403 `insufficient_scope` for a token missing
//! a scope — is #232: this module owns the bundle mapping
//! ([`scope_for_tool`]); the broker enforces it through the scope
//! set an OAuth token's [`super::AgentId`] carries.

use serde_json::{Value, json};

use crate::config::Config;

/// `GET /.well-known/oauth-protected-resource`: RFC 9728 metadata at
/// the root (clients try this and the path-inserted form).
pub const PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";
/// `GET /.well-known/oauth-protected-resource/mcp`: RFC 9728
/// metadata with the resource path inserted, the URL the `/mcp` 401
/// names as `resource_metadata`.
pub const PROTECTED_RESOURCE_MCP_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
/// `GET /.well-known/oauth-protected-resource/connector`: RFC 9728
/// metadata with the `/connector` resource path inserted (#235 D1,
/// Option B). This document — and only this document — carries the
/// `kharon_connector_pin` extension member. It is a publication for
/// comparison, never a root of trust: a dashboard runtime must
/// already hold the pin from operator provisioning (D1, Option C)
/// and must never adopt the value served here.
pub const PROTECTED_RESOURCE_CONNECTOR_PATH: &str =
    "/.well-known/oauth-protected-resource/connector";
/// The one scope the `/connector` resource supports (#235 D1).
pub const CONNECTOR_SCOPE: &str = "kharon:connector";
/// `GET /.well-known/oauth-authorization-server`: RFC 8414 metadata
/// on the owner hostname, the well-known URL the issuer derives.
pub const AUTHORIZATION_SERVER_PATH: &str = "/.well-known/oauth-authorization-server";

/// The scopes every deploy supports (REQ-OAU-006's bundles; the
/// bundle membership is #232, the names are discovery's from here).
pub const SCOPES_SUPPORTED: [&str; 3] = ["kharon:read", "kharon:fill", "kharon:request"];

/// The extension grant a dashboard runtime uses to spawn its
/// connector token family (#235 design D3, A1). RFC 6749 §4.5 wants
/// an extension grant type to be a URI. A client may spawn only if
/// its metadata document lists this in `grant_types`, recorded on the
/// Connect identity at consent (A11, [`super::cimd`]).
pub const CONNECTOR_GRANT_TYPE: &str = "urn:kharon:oauth:grant-type:connector";

/// `grant_types_supported` in the AS metadata: the two phase 1
/// grants and the connector extension grant (A1 keeps the first two).
pub const GRANT_TYPES_SUPPORTED: [&str; 3] =
    ["authorization_code", "refresh_token", CONNECTOR_GRANT_TYPE];

/// The scope bundles (REQ-OAU-006, design D5): each scope names a
/// fixed set of MCP tools. This table is the one place the mapping
/// lives — enforcement ([`scope_for_tool`]), `tools/list`
/// filtering and the tests all read it from here.
pub const SCOPE_TOOLS: [(&str, &[&str]); 3] = [
    (
        "kharon:read",
        &["kharon_status", "kharon_list", "kharon_search"],
    ),
    (
        "kharon:fill",
        &["kharon_context", "kharon_fill", "kharon_fill_totp"],
    ),
    ("kharon:request", &["kharon_request_grant"]),
];

/// The one scope whose bundle contains `tool`, if any. Every tool
/// is in exactly one bundle, so a call needs exactly one scope.
pub fn scope_for_tool(tool: &str) -> Option<&'static str> {
    SCOPE_TOOLS
        .iter()
        .find(|(_, tools)| tools.contains(&tool))
        .map(|(scope, _)| *scope)
}

/// Whether a granted scope set (as the token store carries it)
/// covers `tool`'s bundle.
pub fn scopes_allow(scopes: &[String], tool: &str) -> bool {
    scope_for_tool(tool).is_some_and(|needed| scopes.iter().any(|s| s == needed))
}

/// Whether `token` is an OAuth access or refresh token.
///
/// Owner surfaces refuse these (REQ-OAU-006): no scope approves
/// anything, and neither token is an enrollment code, a session,
/// or an ntfy approval link. The prefix is the whole check, so a
/// truncated token is refused too.
pub fn is_oauth_token(token: &str) -> bool {
    token.starts_with("kh_at_") || token.starts_with("kh_rt_")
}

/// Whether an `Authorization` header value is `Bearer` with an
/// OAuth token. The scheme is case-insensitive (RFC 9110); the
/// token prefix is not.
pub fn authorization_is_oauth_bearer(value: &str) -> bool {
    let Some((scheme, cred)) = value.split_once(' ') else {
        return false;
    };
    let cred = cred.trim_matches(' ');
    scheme.eq_ignore_ascii_case("bearer") && is_oauth_token(cred)
}

/// Everything discovery serves, derived once from the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The issuer: the `[owner_ui]` origin, no path.
    issuer: String,
    /// The protected resource: the deploy's public `/mcp` URL.
    resource: String,
    /// The RFC 9728 document URL the `/mcp` 401 challenge names.
    resource_metadata: String,
    /// The connector resource: the deploy's public `/connector` URL.
    connector_resource: String,
    /// SHA-256 of the `[connector]` certificate's DER, lowercase hex
    /// (#235 D1). `None` when no connector certificate is
    /// configured (or it cannot be read/parsed): the connector
    /// protected-resource document is then not served at all.
    connector_pin: Option<String>,
}

impl Discovery {
    /// Build from the validated config; `None` unless `[oauth]` is
    /// set. Validation has already established the two inputs (an
    /// https owner origin and a `public_host`), so this cannot fail:
    /// a missing input is the `None` case's twin, treated the same.
    pub fn from_config(cfg: &Config) -> Option<Self> {
        cfg.oauth.as_ref()?;
        let issuer = cfg.owner_ui.as_ref()?.origin.clone();
        let public_host = cfg.public_ingress.as_ref()?.public_host.as_ref()?;
        let mut discovery = Self::new(issuer, public_host);
        if let Some(pin) = connector_pin_from_config(cfg) {
            discovery = discovery.with_connector_pin(pin);
        }
        Some(discovery)
    }

    /// Build from an issuer and the public (agent) hostname.
    pub fn new(issuer: String, public_host: &str) -> Self {
        Self {
            resource: format!("https://{public_host}/mcp"),
            resource_metadata: format!("https://{public_host}{PROTECTED_RESOURCE_MCP_PATH}"),
            connector_resource: format!("https://{public_host}/connector"),
            connector_pin: None,
            issuer,
        }
    }

    /// Carry the connector certificate pin (#235 D1): the lowercase
    /// hex SHA-256 of the `[connector]` end-entity certificate DER,
    /// the same value a `connector.toml` holds as `broker_pin`.
    /// With a pin set, [`Self::connector_protected_resource_metadata`]
    /// serves the connector document; without one it serves nothing.
    pub fn with_connector_pin(mut self, pin_hex: String) -> Self {
        self.connector_pin = Some(pin_hex);
        self
    }

    /// The connector resource: this deploy's public `/connector` URL.
    pub fn connector_resource(&self) -> &str {
        &self.connector_resource
    }

    /// The published connector pin, when a connector certificate is
    /// configured.
    pub fn connector_pin(&self) -> Option<&str> {
        self.connector_pin.as_deref()
    }

    /// The issuer (the `[owner_ui]` origin).
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The protected resource: this deploy's public `/mcp` URL.
    /// Authorize (REQ-OAU-003) and the token endpoint
    /// (REQ-OAU-004) both require `resource` to equal it.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// RFC 9728 protected-resource metadata, served on
    /// `[public_ingress]` at both well-known paths. Known deviation:
    /// §3.3 wants the root document's `resource` to be the origin,
    /// but both paths serve the same document naming the `/mcp`
    /// resource — the one the 401 challenge points at (#228).
    pub fn protected_resource_metadata(&self) -> Value {
        json!({
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": SCOPES_SUPPORTED,
            "bearer_methods_supported": ["header"],
            "resource_name": "kharon",
        })
    }

    /// RFC 9728 protected-resource metadata for `/connector`,
    /// served on `[public_ingress]` at
    /// [`PROTECTED_RESOURCE_CONNECTOR_PATH`] (#235 D1, Option B;
    /// REQ-OAU-009). `None` when no connector certificate is
    /// configured — the caller answers 404, so a phase 1 deploy does
    /// not advertise a connector it has not configured.
    ///
    /// The document deliberately omits `bearer_methods_supported`:
    /// RFC 9728's methods are `header`, `body` and `query`, but this
    /// resource takes its credential in the wire-v1 hello after the
    /// inner TLS, and naming `header` would be a metadata lie.
    /// `kharon_connector_pin` is an extension member (clients that
    /// do not know it ignore it, as RFC 9728 requires). The `/mcp`
    /// and root documents never carry the pin or the connector
    /// scope. Publication is not trust: see the path constant.
    pub fn connector_protected_resource_metadata(&self) -> Option<Value> {
        let pin = self.connector_pin.as_ref()?;
        Some(json!({
            "resource": self.connector_resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": [CONNECTOR_SCOPE],
            "resource_name": "kharon",
            "kharon_connector_pin": pin,
        }))
    }

    /// RFC 8414 authorization-server metadata, served on the owner
    /// hostname. The endpoints are the issuer's `/oauth/*` paths
    /// (#230, #231); discovery names them first, as the spec's flow
    /// requires. There is deliberately no `registration_endpoint`:
    /// Dynamic Client Registration is off (REQ-OAU-002's allow-list
    /// is the registration).
    pub fn authorization_server_metadata(&self) -> Value {
        json!({
            "issuer": self.issuer,
            "authorization_endpoint": format!("{}/oauth/authorize", self.issuer),
            "token_endpoint": format!("{}/oauth/token", self.issuer),
            "revocation_endpoint": format!("{}/oauth/revoke", self.issuer),
            "response_types_supported": ["code"],
            "grant_types_supported": GRANT_TYPES_SUPPORTED,
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "client_id_metadata_document_supported": true,
            "authorization_response_iss_parameter_supported": true,
            "scopes_supported": SCOPES_SUPPORTED,
        })
    }

    /// The `WWW-Authenticate` value of a `/mcp` 401 with `[oauth]`
    /// set (D1): the bare realm gains the discovery pointer and the
    /// full scope set.
    pub fn challenge(&self) -> String {
        format!(
            "Bearer realm=\"kharon\", resource_metadata=\"{}\", scope=\"{}\"",
            self.resource_metadata,
            SCOPES_SUPPORTED.join(" ")
        )
    }

    /// The `WWW-Authenticate` value of a `/mcp` 403 refusing a call
    /// the token's scopes do not cover (REQ-OAU-001, D1): the RFC
    /// 6750 §3.1 step-up challenge — the 401 challenge's shape plus
    /// `error="insufficient_scope"` and a `scope` naming what the
    /// retry needs: the token's granted scopes plus the one the
    /// call needs, so re-authorizing does not drop a scope the
    /// token already holds. Only fixed scope names go in: nothing
    /// from the request is interpolated (REQ-API-006).
    pub fn step_up_challenge(&self, granted: &[String], needed: &str) -> String {
        let mut scopes: Vec<&str> = granted.iter().map(String::as_str).collect();
        if !scopes.contains(&needed) {
            scopes.push(needed);
        }
        format!(
            "Bearer realm=\"kharon\", error=\"insufficient_scope\", \
             scope=\"{}\", resource_metadata=\"{}\"",
            scopes.join(" "),
            self.resource_metadata
        )
    }
}

/// The pin of the configured `[connector]` certificate: SHA-256 of
/// the first (end-entity) certificate's DER in its PEM file,
/// lowercase hex — exactly `kharon_connector::pin_of_der`, the value
/// relay clients pin (#235 D1). `None` when there is no `[connector]`
/// section, the file cannot be read, or it holds no PEM certificate.
/// Startup validation (`Config::check_startup`) has already loaded
/// this material as TLS, so a `None` here from a configured section
/// fails closed: no connector document is published.
fn connector_pin_from_config(cfg: &Config) -> Option<String> {
    use rustls_pki_types::pem::PemObject;
    let connector = cfg.connector.as_ref()?;
    let pem = std::fs::read(&connector.tls.cert_file).ok()?;
    let first = rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
        .next()?
        .ok()?;
    Some(hex::encode(crate::connector::pin_of_der(first.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery() -> Discovery {
        Discovery::new("https://kharon-owner.twkr.io".to_owned(), "kharon.twkr.io")
    }

    #[test]
    fn protected_resource_metadata_is_the_golden_document() {
        assert_eq!(
            discovery().protected_resource_metadata(),
            json!({
                "resource": "https://kharon.twkr.io/mcp",
                "authorization_servers": ["https://kharon-owner.twkr.io"],
                "scopes_supported": ["kharon:read", "kharon:fill", "kharon:request"],
                "bearer_methods_supported": ["header"],
                "resource_name": "kharon",
            })
        );
    }

    #[test]
    fn req_oau_009_connector_metadata_is_the_golden_document_with_the_pin() {
        // #235 D1 Option B / spec test plan "Metadata": the exact
        // document, with the pin, and no bearer_methods_supported.
        let pin = "ab".repeat(32);
        let d = discovery().with_connector_pin(pin.clone());
        assert_eq!(
            d.connector_protected_resource_metadata(),
            Some(json!({
                "resource": "https://kharon.twkr.io/connector",
                "authorization_servers": ["https://kharon-owner.twkr.io"],
                "scopes_supported": ["kharon:connector"],
                "resource_name": "kharon",
                "kharon_connector_pin": pin,
            }))
        );
        let doc = d.connector_protected_resource_metadata().unwrap();
        assert!(doc.get("bearer_methods_supported").is_none());
        // The /mcp and root documents stay the phase 1 documents:
        // no pin, no connector scope (asserted byte-for-byte by
        // protected_resource_metadata_is_the_golden_document).
        let mcp = d.protected_resource_metadata().to_string();
        assert!(!mcp.contains("kharon_connector_pin"), "{mcp}");
        assert!(!mcp.contains("kharon:connector"), "{mcp}");
    }

    #[test]
    fn req_oau_009_from_config_publishes_the_configured_connector_certs_pin() {
        // The daemon path: Discovery::from_config reads the
        // [connector] certificate file and publishes pin_of_der of
        // its DER — the same pin a relay-test client pins
        // (req_arch_002_ws_relay). The pin may appear here: it is
        // public (spec test plan).
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("connector.crt");
        let key_path = dir.path().join("connector.key");
        std::fs::write(&cert_path, certified.cert.pem()).unwrap();
        std::fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();
        let text = format!(
            r#"mode = "export"
data_dir = "/data"
[export]
file = "/run/secrets/export.json"
[audit]
checkpoint_local_only = true
[agents.assistant]
token_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
connector_token_hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"
cdp = {{ endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }}
[public_ingress]
listen = "127.0.0.1:8790"
public_host = "kharon.example.com"
[owner_ui]
listen = "127.0.0.1:8788"
public_origin = "https://kharon-owner.example.com"
[oauth]
[connector]
websocket = true
tls_cert_file = "{}"
tls_key_file = "{}"
"#,
            cert_path.display(),
            key_path.display()
        );
        let cfg = Config::from_toml_str(&text).unwrap();
        let discovery = Discovery::from_config(&cfg).expect("oauth is set");
        let expected = hex::encode(crate::connector::pin_of_der(certified.cert.der()));
        assert_eq!(discovery.connector_pin(), Some(expected.as_str()));
        let doc = discovery.connector_protected_resource_metadata().unwrap();
        assert_eq!(doc["kharon_connector_pin"], expected);
        assert_eq!(doc["resource"], "https://kharon.example.com/connector");
    }

    #[test]
    fn req_oau_009_connector_metadata_is_absent_without_a_connector_certificate() {
        // No pin configured → no document (the handler 404s).
        assert_eq!(discovery().connector_protected_resource_metadata(), None);
        assert_eq!(discovery().connector_pin(), None);
    }

    #[test]
    fn authorization_server_metadata_is_the_golden_document() {
        let doc = discovery().authorization_server_metadata();
        assert_eq!(
            doc,
            json!({
                "issuer": "https://kharon-owner.twkr.io",
                "authorization_endpoint": "https://kharon-owner.twkr.io/oauth/authorize",
                "token_endpoint": "https://kharon-owner.twkr.io/oauth/token",
                "revocation_endpoint": "https://kharon-owner.twkr.io/oauth/revoke",
                "response_types_supported": ["code"],
                "grant_types_supported": [
                    "authorization_code",
                    "refresh_token",
                    "urn:kharon:oauth:grant-type:connector",
                ],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "client_id_metadata_document_supported": true,
                "authorization_response_iss_parameter_supported": true,
                "scopes_supported": ["kharon:read", "kharon:fill", "kharon:request"],
            })
        );
        // Dynamic Client Registration is off (REQ-OAU-001).
        assert!(doc.get("registration_endpoint").is_none());
        // The metadata issuer is the issuer the well-known URL is
        // derived from: it is the owner origin, with no path.
        assert_eq!(doc["issuer"], discovery().issuer());
    }

    #[test]
    fn scope_bundles_cover_every_tool_exactly_once() {
        // REQ-OAU-006: the bundles partition the tool registry — a
        // tool in no bundle could never be called by a Connect, and
        // a tool in two would make "the scope this call needs"
        // ambiguous.
        for tool in crate::api::mcp::TOOL_NAMES {
            let bundles = SCOPE_TOOLS
                .iter()
                .filter(|(_, tools)| tools.contains(&tool))
                .count();
            assert_eq!(bundles, 1, "{tool}");
            assert!(scope_for_tool(tool).is_some(), "{tool}");
        }
        assert_eq!(scope_for_tool("kharon_approve"), None);
        // The bundle names are exactly the supported scopes.
        for (scope, _) in SCOPE_TOOLS {
            assert!(SCOPES_SUPPORTED.contains(&scope), "{scope}");
        }
    }

    #[test]
    fn oauth_token_prefixes_are_recognized_and_bearer_is_case_insensitive() {
        assert!(is_oauth_token("kh_at_ab"));
        assert!(is_oauth_token("kh_rt_ab"));
        assert!(!is_oauth_token("kh_agent_ab"));
        assert!(!is_oauth_token("not-kh_at_ab"));
        assert!(authorization_is_oauth_bearer("Bearer kh_at_ab"));
        assert!(authorization_is_oauth_bearer("bearer  kh_rt_ab"));
        assert!(!authorization_is_oauth_bearer("Bearer enroll-code"));
        assert!(!authorization_is_oauth_bearer("Basic kh_at_ab"));
    }

    #[test]
    fn scopes_allow_checks_the_tools_bundle() {
        let read_only = vec!["kharon:read".to_owned()];
        assert!(scopes_allow(&read_only, "kharon_status"));
        assert!(scopes_allow(&read_only, "kharon_search"));
        assert!(!scopes_allow(&read_only, "kharon_fill"));
        assert!(!scopes_allow(&read_only, "kharon_request_grant"));
        assert!(!scopes_allow(&[], "kharon_status"));
    }

    #[test]
    fn challenge_names_the_metadata_url_and_every_scope() {
        assert_eq!(
            discovery().challenge(),
            "Bearer realm=\"kharon\", \
             resource_metadata=\"https://kharon.twkr.io/.well-known/oauth-protected-resource/mcp\", \
             scope=\"kharon:read kharon:fill kharon:request\""
        );
    }

    #[test]
    fn step_up_challenge_names_the_error_and_the_full_retry_scope_set() {
        // Granted scopes keep their order; the missing one is
        // appended, and an already-held scope is not repeated.
        let granted = vec!["kharon:read".to_owned()];
        assert_eq!(
            discovery().step_up_challenge(&granted, "kharon:fill"),
            "Bearer realm=\"kharon\", error=\"insufficient_scope\", \
             scope=\"kharon:read kharon:fill\", \
             resource_metadata=\"https://kharon.twkr.io/.well-known/oauth-protected-resource/mcp\""
        );
        assert_eq!(
            discovery().step_up_challenge(&granted, "kharon:read"),
            "Bearer realm=\"kharon\", error=\"insufficient_scope\", \
             scope=\"kharon:read\", \
             resource_metadata=\"https://kharon.twkr.io/.well-known/oauth-protected-resource/mcp\""
        );
        assert_eq!(
            discovery().step_up_challenge(&[], "kharon:request"),
            "Bearer realm=\"kharon\", error=\"insufficient_scope\", \
             scope=\"kharon:request\", \
             resource_metadata=\"https://kharon.twkr.io/.well-known/oauth-protected-resource/mcp\""
        );
    }
}
