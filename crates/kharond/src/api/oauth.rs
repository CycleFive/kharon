//! OAuth discovery (REQ-OAU-001; N3 design #226, D1).
//!
//! With `[oauth]` configured, kharond is both the authorization
//! server and the resource server, on two hostnames:
//!
//! | Document | Served on | Route |
//! |---|---|---|
//! | RFC 9728 protected-resource metadata | `[public_ingress]` (the agent hostname) | `GET /.well-known/oauth-protected-resource/mcp` and `GET /.well-known/oauth-protected-resource` |
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
/// `GET /.well-known/oauth-authorization-server`: RFC 8414 metadata
/// on the owner hostname, the well-known URL the issuer derives.
pub const AUTHORIZATION_SERVER_PATH: &str = "/.well-known/oauth-authorization-server";

/// The scopes every deploy supports (REQ-OAU-006's bundles; the
/// bundle membership is #232, the names are discovery's from here).
pub const SCOPES_SUPPORTED: [&str; 3] = ["kharon:read", "kharon:fill", "kharon:request"];

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

/// Everything discovery serves, derived once from the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The issuer: the `[owner_ui]` origin, no path.
    issuer: String,
    /// The protected resource: the deploy's public `/mcp` URL.
    resource: String,
    /// The RFC 9728 document URL the `/mcp` 401 challenge names.
    resource_metadata: String,
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
        Some(Self::new(issuer, public_host))
    }

    /// Build from an issuer and the public (agent) hostname.
    pub fn new(issuer: String, public_host: &str) -> Self {
        Self {
            resource: format!("https://{public_host}/mcp"),
            resource_metadata: format!("https://{public_host}{PROTECTED_RESOURCE_MCP_PATH}"),
            issuer,
        }
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
            "grant_types_supported": ["authorization_code", "refresh_token"],
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
                "grant_types_supported": ["authorization_code", "refresh_token"],
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
}
