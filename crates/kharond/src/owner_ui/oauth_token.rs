//! The OAuth token endpoints (REQ-OAU-004/-005/-008; N3 design
//! #226, D4/D6, I5): `POST /oauth/token` and `POST /oauth/revoke`
//! on the owner hostname.
//!
//! Both are on the named exemption list (#208): they take no
//! `Origin` and no Access token — a dashboard's backend is not a
//! browser and holds no Access login (D6) — and both are throttled
//! per source through the UI's failure throttle (REQ-OAU-008).
//! Answers are OAuth-shaped JSON (`{"error": …}` on failure), not
//! the owner UI's `{"ok": …}` shape: the clients are machines.
//! `Cache-Control: no-store` rides on every owner-UI response
//! already (see `build_response`), as RFC 6749 §5.1 requires.
//!
//! The token semantics — identities, rotation, reuse, persistence —
//! live in [`crate::api::oauth_store`]. This module is the HTTP
//! skin: form parsing, the `resource` pin, the single-use code take
//! (a pending redeemed-use marker recorded atomically with it), and
//! error mapping.
//!
//! Codes are the authorize side's (#230): redemption goes through
//! [`CodeRedeemer`], a seam over its in-memory code store.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::{Incoming, OwnerUi, Response, json_body, method_not_allowed, sha256};
use crate::api::oauth::CONNECTOR_GRANT_TYPE;
use crate::api::oauth_store::{
    CodeClaim, CodeGrant, DisconnectDetail, OauthStore, RefreshResource, SpawnRequest, TokenError,
};

/// A redeemed authorization code, carried from the authorize side
/// to the token store: #230's `CodeBody` across the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemedCode {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    /// The granted scopes, canonical order.
    pub scopes: Vec<String>,
    /// Unix seconds of the consent.
    pub consented_at: u64,
    /// The connector-grant declaration recorded at consent (#235 D3).
    pub connector_grant_declared: bool,
}

/// The authorize side's code store, as the token endpoint needs
/// it: take a code out, once. Codes live in memory only (D4), held
/// by the authorize endpoint (#230); production wiring adapts its
/// store to this trait.
pub trait CodeRedeemer: Send + Sync {
    /// Remove and return the code's body. `None` when the code is
    /// unknown, expired or already redeemed.
    fn redeem(&self, plaintext: &str) -> Option<RedeemedCode>;

    /// Called after this redemption has taken the code and recorded
    /// its pending use, and before the Connect is committed. The
    /// store lock is not held. The default does nothing; tests block
    /// here so a second presentation can land in that window.
    fn after_take(&self) {}
}

/// No authorize side wired: every code is unknown. On a tree
/// without #230's endpoint no code can have been issued, so failing
/// closed is the only correct answer.
pub struct UnwiredCodes;

impl CodeRedeemer for UnwiredCodes {
    fn redeem(&self, _plaintext: &str) -> Option<RedeemedCode> {
        None
    }
}

/// The production [`CodeRedeemer`]: #230's in-memory code store,
/// adapted across the seam. `CodeStore` is born with the
/// [`OwnerUi`] that serves the authorize routes, so the daemon
/// cannot hold it when it builds the [`TokenSide`];
/// [`OwnerUi::open_with`] binds this adapter over the UI's own
/// store when the side asks it to (see [`TokenSide::unwired`]).
pub struct CodeStoreRedeemer {
    codes: Arc<super::oauth::CodeStore>,
}

impl CodeStoreRedeemer {
    pub(super) fn new(codes: Arc<super::oauth::CodeStore>) -> Self {
        Self { codes }
    }
}

impl CodeRedeemer for CodeStoreRedeemer {
    fn redeem(&self, plaintext: &str) -> Option<RedeemedCode> {
        self.codes
            .redeem(plaintext, Instant::now())
            .map(|body| RedeemedCode {
                client_id: body.client_id,
                client_name: body.client_name,
                redirect_uri: body.redirect_uri,
                code_challenge: body.code_challenge,
                scopes: body.scopes.iter().map(|s| s.as_str().to_owned()).collect(),
                consented_at: body.consented_at,
                connector_grant_declared: body.connector_grant_declared,
            })
    }
}

/// What the token endpoints need: the shared OAuth token store and
/// the code redeemer. Built by the daemon when `[oauth]` is set.
#[derive(Clone)]
pub struct TokenSide {
    pub store: Arc<OauthStore>,
    pub codes: Arc<dyn CodeRedeemer>,
    /// True when `codes` is still the fail-closed placeholder and
    /// [`OwnerUi::open_with`] must bind the real redeemer over the
    /// authorize side's code store (the store does not exist until
    /// the UI is built). A side built with an explicit redeemer
    /// keeps it.
    pub bind_at_open: bool,
}

impl TokenSide {
    /// The token side with the code grant not yet wired (see
    /// [`UnwiredCodes`]): the placeholder redeemer fails closed
    /// until `open_with` binds the real one.
    pub fn unwired(store: Arc<OauthStore>) -> Self {
        Self {
            store,
            codes: Arc::new(UnwiredCodes),
            bind_at_open: true,
        }
    }

    /// The token side with an explicit code redeemer (tests fake
    /// the authorize side this way). `open_with` leaves it alone.
    pub fn with_codes(store: Arc<OauthStore>, codes: Arc<dyn CodeRedeemer>) -> Self {
        Self {
            store,
            codes,
            bind_at_open: false,
        }
    }
}

/// `POST /oauth/token` and `POST /oauth/revoke`.
pub const TOKEN_PATH: &str = "/oauth/token";
pub const REVOKE_PATH: &str = "/oauth/revoke";

impl OwnerUi {
    /// Dispatch one token-endpoint request. The caller has already
    /// established the path is one of the two; the response is
    /// OAuth-shaped.
    pub(super) fn oauth_token_dispatch(&self, req: &Incoming, side: &TokenSide) -> Response {
        if req.method != Method::POST {
            return method_not_allowed("POST");
        }
        // The throttle's refusal is checked in `dispatch` for every
        // THROTTLED_ROUTES path; failures are recorded here, where
        // the outcome is known.
        let response = if req.path == TOKEN_PATH {
            self.oauth_token(req, side)
        } else {
            self.oauth_revoke(req, side)
        };
        if response.status().is_client_error()
            && let Some(ip) = req.throttle_key
        {
            self.throttle.record(ip, Instant::now());
        }
        response
    }

    fn oauth_token(&self, req: &Incoming, side: &TokenSide) -> Response {
        let Some(form) = parse_form(req) else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let now = unix_now();
        match form.get("grant_type") {
            Some("authorization_code") => self.oauth_token_code(req, side, &form, now),
            Some("refresh_token") => {
                let Some(presented) = form.get("refresh_token") else {
                    return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
                };
                // `client_id` is required for a public client's
                // refresh (OAuth 2.1 §4.3); the store compares it
                // with the issuing client under its lock and a
                // mismatch answers `invalid_grant`.
                let Some(client_id) = form.get("client_id") else {
                    return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
                };
                let Some(oauth) = &self.oauth else {
                    return oauth_error(StatusCode::NOT_FOUND, "not_found");
                };
                // `resource` is optional. Omitted, an MCP-family
                // token still rotates (phase 1). A connector-family
                // token needs this deploy's `/connector` URL (D3).
                let connector = oauth.discovery.connector_resource();
                let resource = RefreshResource {
                    presented: form.get("resource"),
                    mcp: oauth.discovery.resource(),
                    connector: &connector,
                };
                map_token_result(
                    side.store
                        .refresh_for(presented, client_id, Some(resource), now),
                )
            }
            Some(CONNECTOR_GRANT_TYPE) => self.oauth_token_spawn(&form, side, now),
            Some(_) => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
            None => oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
        }
    }

    fn oauth_token_code(
        &self,
        _req: &Incoming,
        side: &TokenSide,
        form: &Form,
        now: u64,
    ) -> Response {
        let (Some(code), Some(client_id), Some(redirect_uri), Some(verifier), Some(resource)) = (
            form.get("code"),
            form.get("client_id"),
            form.get("redirect_uri"),
            form.get("code_verifier"),
            form.get("resource"),
        ) else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        // The audience pin (D4): exactly this deploy's `/mcp`
        // resource; `/connector` included in the refusal. Checked
        // before the code is touched, so a wrong-resource request
        // does not spend it.
        let Some(oauth) = &self.oauth else {
            return oauth_error(StatusCode::NOT_FOUND, "not_found");
        };
        if resource != oauth.discovery.resource() {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_target");
        }
        let code_hash = sha256(code.as_bytes());
        // Take the code and record the pending redeemed-use marker
        // under the store lock (D4, RFC 6749 §4.1.2). A second
        // presentation, at any point after this returns, sees the
        // marker: a committed Connect is revoked, and one that has
        // not committed yet is marked so `connect` refuses it.
        let codes = Arc::clone(&side.codes);
        let code_owned = code.to_owned();
        let claim = side.store.begin_redemption(code_hash, now, move || {
            codes.redeem(&code_owned).map(|body| {
                let consented_at = body.consented_at;
                (body, consented_at)
            })
        });
        let body = match claim {
            CodeClaim::Unknown => {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            CodeClaim::Reuse { identity_id } => {
                if let Some(identity_id) = identity_id {
                    let _ = side.store.disconnect(
                        &identity_id,
                        DisconnectDetail::CodeReuse,
                        "web_ui",
                        now,
                    );
                }
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            CodeClaim::Taken(body) => body,
        };
        // The marker is recorded and the lock is released. A second
        // redemption can land here; `connect` observes it under the
        // store lock and does not leave a live Connect.
        side.codes.after_take();
        // The redemption must name the client and redirect the code
        // was bound to (RFC 6749 §4.1.3). The code is spent either
        // way: the authorize side has already taken it out, and the
        // pending marker keeps a later presentation refused.
        if body.client_id != client_id || body.redirect_uri != redirect_uri {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }
        let grant = CodeGrant {
            client_id: body.client_id,
            client_name: body.client_name,
            code_challenge: body.code_challenge,
            scopes: body.scopes,
            consented_at: body.consented_at,
            connector_grant_declared: body.connector_grant_declared,
        };
        map_token_result(side.store.connect(&grant, verifier, code_hash, now))
    }

    /// The connector extension grant (D3). `resource` is required:
    /// omitting it is `invalid_request`, not a spawn at the `/mcp`
    /// URL. The store checks `client_id` before the resource.
    fn oauth_token_spawn(&self, form: &Form, side: &TokenSide, now: u64) -> Response {
        let (Some(presented), Some(client_id), Some(resource)) = (
            form.get("refresh_token"),
            form.get("client_id"),
            form.get("resource"),
        ) else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        let Some(oauth) = &self.oauth else {
            return oauth_error(StatusCode::NOT_FOUND, "not_found");
        };
        let connector = oauth.discovery.connector_resource();
        map_token_result(side.store.spawn(
            SpawnRequest {
                refresh_token: presented,
                client_id,
                resource,
                connector_resource: &connector,
                connector_configured: oauth.connector_configured,
            },
            now,
        ))
    }

    fn oauth_revoke(&self, req: &Incoming, side: &TokenSide) -> Response {
        let Some(form) = parse_form(req) else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        // `token_type_hint` is accepted and ignored beyond this: the
        // store dispatches on the presented value's own record, so
        // a wrong hint costs nothing (RFC 7009 §2.1).
        let Some(token) = form.get("token") else {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
        };
        match side.store.revoke(token, unix_now()) {
            Ok(()) => json_body(StatusCode::OK, String::new(), None),
            Err(_) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        }
    }
}

/// Map a store result onto the token-endpoint status. Every OAuth
/// error here is 400; a failed audit or persist is 500 and carries
/// no token.
fn map_token_result(result: Result<crate::api::oauth_store::IssuedPair, TokenError>) -> Response {
    match result {
        Ok(pair) => token_answer(pair),
        Err(TokenError::InvalidGrant) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
        Err(TokenError::InvalidTarget) => oauth_error(StatusCode::BAD_REQUEST, "invalid_target"),
        Err(TokenError::UnauthorizedClient) => {
            oauth_error(StatusCode::BAD_REQUEST, "unauthorized_client")
        }
        Err(TokenError::AuditFailed | TokenError::PersistFailed) => {
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// The token success answer (D6): the pair, its type and lifetime,
/// and the granted `scope`.
fn token_answer(pair: crate::api::oauth_store::IssuedPair) -> Response {
    json_body(
        StatusCode::OK,
        json!({
            "access_token": pair.access_token,
            "token_type": "Bearer",
            "expires_in": crate::api::oauth_store::ACCESS_TTL_SECS,
            "refresh_token": pair.refresh_token,
            "scope": pair.scope,
        })
        .to_string(),
        None,
    )
}

/// An OAuth error answer (RFC 6749 §5.2): `{"error": code}`.
fn oauth_error(status: StatusCode, error: &'static str) -> Response {
    json_body(status, json!({ "error": error }).to_string(), None)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A parsed `application/x-www-form-urlencoded` body. Repeated
/// keys keep the first value (OAuth parameters must not repeat;
/// first-wins keeps a smuggled second value inert).
pub struct Form {
    pairs: Vec<(String, String)>,
}

impl Form {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse the request body as form data. `None` when the content
/// type is not form encoding or a pair is malformed.
fn parse_form(req: &Incoming) -> Option<Form> {
    let content_type = req.content_type.as_deref()?;
    let media = content_type.split(';').next()?.trim();
    if !media.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return None;
    }
    let text = std::str::from_utf8(&req.body).ok()?;
    let mut pairs = Vec::new();
    for part in text.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        pairs.push((form_decode(key)?, form_decode(value)?));
    }
    Some(Form { pairs })
}

/// Percent-decode one form component (`+` is a space).
fn form_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = hex_val(*bytes.get(i + 1)?)?;
                let lo = hex_val(*bytes.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
