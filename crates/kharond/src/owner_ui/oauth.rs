//! Authorize, consent and the authorization code (REQ-OAU-003; N3 D6,
//! I1, D4's code).
//!
//! `GET /oauth/authorize` checks the request in D6's order. Failures
//! at steps 1–3 render a page and never redirect. Failures at steps
//! 4–7 redirect with `error`, `state` and `iss`. A valid request is
//! sealed into a pending authorization — #208's HMAC token, carried
//! in `/oauth/consent/<token>` — and nothing is stored, so strangers
//! cannot fill a table. The token lives 10 minutes. Approving or
//! denying records its hash as used.
//!
//! The issue text says "the bounded ceremony table". The design was
//! amended on 2026-11-11 (I1) and REQ-OAU-003 now requires the sealed
//! token: a bounded table cannot keep one source from evicting
//! another's pending Connect. The used-set that records the decision
//! is #208's, bounded and memory-only.
//!
//! Approving needs a live session and a fresh passkey assertion whose
//! challenge is `SHA-256(pending-id ‖ nonce ‖ 32 random bytes)`. The
//! code it issues is 32 random bytes, 60 seconds, single use, memory
//! only. The consent POST returns `{"redirect": ...}`; the code is
//! never placed in a `Location` header.
//!
//! Client admission (steps 1–3) is [`crate::api::cimd::ClientAdmission`].
//! A refusal is audited there, once, as `oauth_client_refused`. This
//! module renders the plain page or the redirect and does not append
//! that event.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::sealed::{Burn, Opened};
use super::webauthn::{b64url_decode, b64url_encode, ct_eq};
use super::{CEREMONY_TTL, CeremonyKind, Incoming, OwnerUi, credential_response};
use crate::api::cimd::{ClientAdmission, ClientMetadata, Refusal};
use crate::api::oauth::Discovery;
use crate::api::transport::ip_key;

/// How long a pending authorization can be approved or denied.
pub(super) const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
/// D4: an authorization code lives this long, in memory only.
pub(super) const CODE_TTL: Duration = Duration::from_secs(60);
/// Codes a process holds at once. Only a completed consent creates
/// one, so the cap is a backstop, not a stranger's target.
const MAX_CODES: usize = 64;
/// Unauthenticated `GET /oauth/authorize` budget per source (REQ-OAU-008).
/// Keyed by #200's address helper. There is no global bucket.
const AUTHORIZE_LIMIT: u32 = 30;
const AUTHORIZE_WINDOW: Duration = Duration::from_secs(60);
const MAX_AUTHORIZE_SOURCES: usize = 1024;

const MAX_QUERY: usize = 4096;
const MAX_PAIRS: usize = 32;
const MAX_STATE: usize = 512;
const MAX_REDIRECT: usize = 1024;
const MAX_CLIENT_ID: usize = 2048;
const MAX_NAME: usize = 128;

/// The authorization server on this owner UI. `None` on
/// [`super::OwnerUi`] means `[oauth]` is off and `/oauth/authorize`
/// 404s. Client admission is [`super::OwnerUi`]'s
/// [`super::OwnerUi::client_admission`], the CIMD fetch from #229.
pub struct OauthAs {
    pub discovery: Arc<Discovery>,
}

const PENDING_PURPOSE: &str = "pending";
const CONSENT_PURPOSE: &str = "consent";

/// The fixed line on the consent screen (D6, REQ-OAU-003).
pub(super) const CONNECT_NOTICE: &str = "Connecting does not let it sign in anywhere on its own. \
     Every sign-in still needs your approval in kharon.";

const UNUSABLE: &str = "This connection request isn't valid.";
const EXPIRED_PAGE: &str = "This connection request has expired or was already answered. \
     Go back to the dashboard and start again.";

const ERR_UNSUPPORTED_RESPONSE_TYPE: &str = "unsupported_response_type";
const ERR_INVALID_REQUEST: &str = "invalid_request";
const ERR_INVALID_TARGET: &str = "invalid_target";
const ERR_INVALID_SCOPE: &str = "invalid_scope";
const ERR_ACCESS_DENIED: &str = "access_denied";

/// A scope the consent screen can grant. Order is the wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Scope {
    #[serde(rename = "kharon:read")]
    Read,
    #[serde(rename = "kharon:fill")]
    Fill,
    #[serde(rename = "kharon:request")]
    Request,
}

impl Scope {
    const ALL: [Scope; 3] = [Scope::Read, Scope::Fill, Scope::Request];

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Read => "kharon:read",
            Self::Fill => "kharon:fill",
            Self::Request => "kharon:request",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == s)
    }

    /// Plain words from D5.
    fn words(self) -> &'static str {
        match self {
            Self::Read => {
                "See the names and websites of the logins you share with kharon. Never the passwords."
            }
            Self::Fill => {
                "Ask to sign in to a website for you. You approve every sign-in here first."
            }
            Self::Request => "Ask you ahead of time for permission to sign in to a site.",
        }
    }

    /// `kharon:read` is always granted and is not a checkbox.
    fn optional(self) -> bool {
        !matches!(self, Self::Read)
    }
}

/// What one code carries for the identity #231 creates at redemption.
/// No identity exists yet (D4, A17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CodeBody {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub resource: String,
    pub scopes: Vec<Scope>,
    /// Unix seconds of the consent, for the refresh token's absolute
    /// lifetime (D4: counted from consent).
    pub consented_at: u64,
    /// Whether the client's metadata document, as admitted for this
    /// consent, declares the connector extension grant (#235 D3).
    /// Fixed here: the identity redemption creates keeps this value.
    pub connector_grant_declared: bool,
}

impl CodeBody {
    /// Space-separated scope, canonical order. The token response
    /// (#231) returns this as `scope`.
    #[allow(dead_code)] // read by #231 and by the code tests
    pub(super) fn scope_param(&self) -> String {
        self.scopes
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

struct LiveCode {
    hash: [u8; 32],
    expires: Instant,
    body: CodeBody,
}

/// In-memory authorization codes. Plaintext exists only in the
/// consent response; the table keeps a SHA-256.
pub(super) struct CodeStore {
    codes: Mutex<Vec<LiveCode>>,
}

impl CodeStore {
    pub(super) fn new() -> Self {
        Self {
            codes: Mutex::new(Vec::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<LiveCode>> {
        self.codes.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Store `body` and return the plaintext code. `Err` when `MAX_CODES`
    /// live codes are already held.
    pub(super) fn issue(&self, body: CodeBody, now: Instant) -> Result<String, ()> {
        let mut codes = self.lock();
        codes.retain(|c| c.expires > now);
        if codes.len() >= MAX_CODES {
            return Err(());
        }
        let raw = super::random_bytes::<32>();
        let plaintext = b64url_encode(&raw);
        codes.push(LiveCode {
            hash: super::sha256(plaintext.as_bytes()),
            expires: now + CODE_TTL,
            body,
        });
        Ok(plaintext)
    }

    /// Drop a code that was issued and then not handed out.
    fn forget(&self, plaintext: &str) {
        let hash = super::sha256(plaintext.as_bytes());
        self.lock().retain(|c| !ct_eq(&c.hash, &hash));
    }

    /// Single use. `None` when the code is unknown, expired, or already
    /// redeemed. The lookup removes it either way once it matches.
    /// #231's token endpoint is the production caller, through the
    /// `CodeRedeemer` adapter in `oauth_token`.
    pub(super) fn redeem(&self, plaintext: &str, now: Instant) -> Option<CodeBody> {
        let hash = super::sha256(plaintext.as_bytes());
        let mut codes = self.lock();
        let pos = codes.iter().position(|c| ct_eq(&c.hash, &hash))?;
        let live = codes.remove(pos);
        (live.expires > now).then_some(live.body)
    }

    pub(super) fn clear(&self) {
        self.lock().clear();
    }
}

/// Per-source request counter for `GET /oauth/authorize`.
pub(super) struct AuthorizeBudget {
    sources: Mutex<Vec<(IpAddr, Instant, u32)>>,
}

impl AuthorizeBudget {
    pub(super) fn new() -> Self {
        Self {
            sources: Mutex::new(Vec::new()),
        }
    }

    /// Count one request. `Err` is how long this source must wait;
    /// the request was not given a slot.
    fn admit(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let key = ip_key(ip);
        let mut sources = self.sources.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(slot) = sources.iter_mut().find(|(ip, _, _)| *ip == key) {
            if now.saturating_duration_since(slot.1) >= AUTHORIZE_WINDOW {
                *slot = (key, now, 1);
                return Ok(());
            }
            if slot.2 >= AUTHORIZE_LIMIT {
                let left = AUTHORIZE_WINDOW.saturating_sub(now.saturating_duration_since(slot.1));
                return Err(left.max(Duration::from_secs(1)));
            }
            slot.2 += 1;
            return Ok(());
        }
        if sources.len() >= MAX_AUTHORIZE_SOURCES {
            sources
                .retain(|(_, start, _)| now.saturating_duration_since(*start) < AUTHORIZE_WINDOW);
            if sources.len() >= MAX_AUTHORIZE_SOURCES {
                let oldest = sources
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, start, _))| *start)
                    .map(|(i, _)| i);
                if let Some(i) = oldest {
                    sources.swap_remove(i);
                }
            }
        }
        sources.push((key, now, 1));
        Ok(())
    }
}

/// What a pending authorization seals. Every field was checked
/// before it was written.
#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    client_id: String,
    client_name: String,
    client_host: String,
    redirect_uri: String,
    redirect_host: String,
    code_challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    resource: String,
    scopes: Vec<Scope>,
    /// The admitted document's connector-grant declaration (#235 D3),
    /// sealed with the `client_name` the consent screen shows, so
    /// the identity records what the owner consented to.
    #[serde(default)]
    connector_grant_declared: bool,
}

#[derive(Serialize, Deserialize)]
struct ConsentCeremony {
    /// base64url of the WebAuthn challenge.
    challenge: String,
    /// base64url of the pending token's id.
    pending_id: String,
    /// base64url of the one-time nonce.
    nonce: String,
}

/// `SHA-256(pending-id ‖ nonce ‖ 32 random bytes)`.
fn consent_challenge(pending_id: &[u8; 32], nonce: &[u8], random: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pending_id);
    hasher.update(nonce);
    hasher.update(random);
    hasher.finalize().into()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

enum ConsentRoute {
    Page,
    View,
    Options,
    Approve,
    Deny,
}

fn consent_route(path: &str) -> Option<ConsentRoute> {
    match path {
        "/oauth/consent/view" => Some(ConsentRoute::View),
        "/oauth/consent/options" => Some(ConsentRoute::Options),
        "/oauth/consent/approve" => Some(ConsentRoute::Approve),
        "/oauth/consent/deny" => Some(ConsentRoute::Deny),
        _ => {
            let token = path.strip_prefix("/oauth/consent/")?;
            if token.is_empty() || token.contains('/') {
                None
            } else {
                Some(ConsentRoute::Page)
            }
        }
    }
}

impl OwnerUi {
    /// Consent routes. `/oauth/authorize` is [`Self::authorize_response`]:
    /// admission fetches, so it runs on the async runtime rather than
    /// this synchronous dispatch.
    pub(super) fn oauth_dispatch(&self, req: &Incoming) -> Response {
        let response = if let Some(route) = consent_route(&req.path) {
            self.consent(req, route)
        } else {
            super::respond(StatusCode::NOT_FOUND, "no_such_route", None)
        };
        frame_deny(response)
    }

    /// `GET /oauth/authorize`. Admission and its audit happen inside
    /// [`ClientAdmission`]; this only renders.
    pub(super) async fn authorize_response(&self, req: &Incoming) -> Response {
        frame_deny(self.authorize(req).await)
    }

    async fn authorize(&self, req: &Incoming) -> Response {
        if req.method != Method::GET {
            return super::method_not_allowed("GET");
        }
        let Some(oauth) = &self.oauth else {
            return super::respond(StatusCode::NOT_FOUND, "no_such_route", None);
        };
        let Some(clients) = self.client_admission() else {
            return error_page(crate::api::cimd::RefusalCode::NotAllowlisted.plain_message());
        };
        if let Some(ip) = req.throttle_key
            && let Err(left) = self.authorize_budget.admit(ip, Instant::now())
        {
            return super::rate_limited(left);
        }
        let decided = decide_authorize(
            req.query.as_deref().unwrap_or(""),
            oauth.discovery.resource(),
            clients.as_ref(),
        )
        .await;
        match decided {
            Authorize::Unusable => error_page(UNUSABLE),
            Authorize::Refused(refusal) => error_page(refusal.plain_message()),
            Authorize::Redirect {
                error,
                redirect_uri,
                state,
            } => match redirect_location(
                &redirect_uri,
                &redirect_params(error, state.as_deref(), oauth.discovery.issuer(), None),
            ) {
                Some(location) => redirect_response(location),
                None => error_page(UNUSABLE),
            },
            Authorize::Pending(pending) => {
                let token =
                    self.sealed
                        .seal(PENDING_PURPOSE, &pending, PENDING_TTL, Instant::now());
                if token.len() > super::sealed::MAX_TOKEN_LEN || !sealed_token_charset(&token) {
                    return error_page(UNUSABLE);
                }
                redirect_response(format!("/oauth/consent/{token}"))
            }
        }
    }

    fn consent(&self, req: &Incoming, route: ConsentRoute) -> Response {
        if self.oauth.is_none() {
            return super::respond(StatusCode::NOT_FOUND, "no_such_route", None);
        }
        match route {
            ConsentRoute::Page => self.consent_page(req),
            ConsentRoute::View => self.consent_view(req),
            ConsentRoute::Options => self.consent_options(req),
            ConsentRoute::Approve => self.consent_approve(req),
            ConsentRoute::Deny => self.consent_deny(req),
        }
    }

    fn consent_page(&self, req: &Incoming) -> Response {
        if req.method != Method::GET {
            return super::method_not_allowed("GET");
        }
        let Some(token) = req.path.strip_prefix("/oauth/consent/") else {
            return error_page(EXPIRED_PAGE);
        };
        if self.open_pending(token, Instant::now()).is_none() || !sealed_token_charset(token) {
            return error_page(EXPIRED_PAGE);
        }
        if !self.session_alive(req.cookie.as_deref()) {
            return super::html(&super::login_page(&format!("/oauth/consent/{token}")));
        }
        let view = self.shell.view();
        let state = if view.locked { "locked" } else { "unlocked" };
        super::html(&super::consent_shell(
            state,
            view.pending,
            &consent_script(token),
        ))
    }

    fn consent_view(&self, req: &Incoming) -> Response {
        if req.method != Method::POST {
            return super::method_not_allowed("POST");
        }
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Some(token) = pending_from_body(&req.body) else {
            return super::respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(opened) = self.open_pending(&token, Instant::now()) else {
            self.fail(req, "expired");
            return super::respond(StatusCode::BAD_REQUEST, "expired", None);
        };
        let pending = &opened.claims;
        let scopes: Vec<Value> = pending
            .scopes
            .iter()
            .map(|s| {
                json!({
                    "id": s.as_str(),
                    "words": s.words(),
                    "optional": s.optional(),
                })
            })
            .collect();
        super::json_body(
            StatusCode::OK,
            json!({
                "ok": true,
                "client_name": pending.client_name,
                "client_host": pending.client_host,
                "redirect_host": pending.redirect_host,
                "notice": CONNECT_NOTICE,
                "scopes": scopes,
            })
            .to_string(),
            None,
        )
    }

    fn consent_options(&self, req: &Incoming) -> Response {
        if req.method != Method::POST {
            return super::method_not_allowed("POST");
        }
        if let Some(err) = self.precheck_post(req) {
            return err;
        }
        if req.origin.as_deref() != Some(self.origin.as_str()) {
            self.fail(req, "origin");
            return super::respond(StatusCode::FORBIDDEN, "origin", None);
        }
        if !self.session_alive(req.cookie.as_deref()) {
            self.fail(req, "no_session");
            return super::respond(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        }
        let Some(token) = pending_from_body(&req.body) else {
            return super::respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(opened) = self.open_pending(&token, Instant::now()) else {
            self.fail(req, "expired");
            return super::respond(StatusCode::BAD_REQUEST, "expired", None);
        };
        let creds: Vec<Value> = {
            let store = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
            if store.is_empty() {
                return super::respond(StatusCode::CONFLICT, "no_credential", None);
            }
            store
                .credentials()
                .iter()
                .map(|c| json!({"type": "public-key", "id": b64url_encode(&c.id)}))
                .collect()
        };
        let nonce = super::random_bytes::<32>();
        let random = super::random_bytes::<32>();
        let challenge = consent_challenge(&opened.id, &nonce, &random);
        let claims = ConsentCeremony {
            challenge: b64url_encode(&challenge),
            pending_id: b64url_encode(&opened.id),
            nonce: b64url_encode(&nonce),
        };
        let ceremony_id = self
            .sealed
            .seal(CONSENT_PURPOSE, &claims, CEREMONY_TTL, Instant::now());
        super::json_body(
            StatusCode::OK,
            json!({
                "ceremony_id": ceremony_id,
                "nonce": claims.nonce,
                "publicKey": {
                    "challenge": claims.challenge,
                    "timeout": 60_000,
                    "rpId": self.rp_id,
                    "allowCredentials": creds,
                    "userVerification": "required",
                }
            })
            .to_string(),
            None,
        )
    }

    fn consent_approve(&self, req: &Incoming) -> Response {
        if req.method != Method::POST {
            return super::method_not_allowed("POST");
        }
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Ok(body) = serde_json::from_slice::<ApproveBody>(&req.body) else {
            return super::respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let wrapper = json!({ "credential": body.credential });
        let Some(cred) = credential_response(&wrapper, CeremonyKind::Login) else {
            self.fail(req, "no_assertion");
            return super::respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        };
        let now = Instant::now();
        let Some(ceremony) =
            self.sealed
                .open::<ConsentCeremony>(CONSENT_PURPOSE, &body.ceremony_id, now)
        else {
            self.fail(req, "bad_assertion");
            return super::respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
        };
        let Some((nonce_ok, pending_id, challenge)) = ceremony_binds(&ceremony, &body.nonce) else {
            self.fail(req, "bad_assertion");
            return super::respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
        };
        if !nonce_ok {
            self.fail(req, "bad_assertion");
            return super::respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
        }
        let Some(pending) = self.open_pending(&body.pending, now) else {
            self.fail(req, "expired");
            return super::respond(StatusCode::BAD_REQUEST, "expired", None);
        };
        if !ct_eq(&pending_id, &pending.id) {
            // The assertion was for a different pending authorization.
            self.fail(req, "bad_assertion");
            return super::respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
        }
        let verified = {
            let store = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
            let Some(known) = store.credentials().iter().find(|c| c.id == cred.id) else {
                drop(store);
                self.fail(req, "bad_assertion");
                return super::respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            };
            if let Some(handle) = &cred.user_handle
                && !ct_eq(handle, store.user_handle())
            {
                drop(store);
                self.fail(req, "bad_assertion");
                return super::respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            }
            super::webauthn::verify_assertion(super::webauthn::Assertion {
                client_data_json: &cred.client_data_json,
                authenticator_data: &cred.authenticator_data,
                signature: &cred.signature,
                challenge: &challenge,
                origin: &self.origin,
                rp_id: &self.rp_id,
                public_key: &known.public_key,
                stored_sign_count: known.sign_count,
            })
        };
        let new_count = match verified {
            Ok(n) => n,
            Err(_) => {
                self.fail(req, "bad_assertion");
                return super::respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            }
        };
        let Some(granted) = grant_scopes(&pending.claims.scopes, &body.scopes) else {
            return super::respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let code_body = CodeBody {
            client_id: pending.claims.client_id.clone(),
            client_name: pending.claims.client_name.clone(),
            redirect_uri: pending.claims.redirect_uri.clone(),
            code_challenge: pending.claims.code_challenge.clone(),
            resource: pending.claims.resource.clone(),
            scopes: granted,
            consented_at: unix_now(),
            connector_grant_declared: pending.claims.connector_grant_declared,
        };
        let state = pending.claims.state.clone();
        let redirect_uri = pending.claims.redirect_uri.clone();
        let Some(plaintext) = self.codes.issue(code_body, now).ok() else {
            return super::rate_limited(CODE_TTL);
        };
        if let Some(response) = self.burn_decision(&pending, req, now) {
            self.codes.forget(&plaintext);
            return response;
        }
        if !matches!(self.sealed.burn(&ceremony, now), Burn::Fresh) {
            self.codes.forget(&plaintext);
            self.fail(req, "already_used");
            return super::respond(StatusCode::CONFLICT, "already_used", None);
        }
        if self
            .passkeys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_sign_count(&cred.id, new_count)
            .is_err()
        {
            self.codes.forget(&plaintext);
            return super::respond(StatusCode::INTERNAL_SERVER_ERROR, "store_failed", None);
        }
        let Some(issuer) = self.oauth.as_ref().map(|o| o.discovery.issuer().to_owned()) else {
            self.codes.forget(&plaintext);
            return super::respond(StatusCode::NOT_FOUND, "no_such_route", None);
        };
        let Some(location) = success_location(&redirect_uri, &plaintext, state.as_deref(), &issuer)
        else {
            self.codes.forget(&plaintext);
            return error_page(UNUSABLE);
        };
        self.forgive(req);
        super::json_body(
            StatusCode::OK,
            json!({ "redirect": location }).to_string(),
            None,
        )
    }

    fn consent_deny(&self, req: &Incoming) -> Response {
        if req.method != Method::POST {
            return super::method_not_allowed("POST");
        }
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Some(token) = pending_from_body(&req.body) else {
            return super::respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let now = Instant::now();
        let Some(pending) = self.open_pending(&token, now) else {
            self.fail(req, "expired");
            return super::respond(StatusCode::BAD_REQUEST, "expired", None);
        };
        let state = pending.claims.state.clone();
        let redirect_uri = pending.claims.redirect_uri.clone();
        if let Some(response) = self.burn_decision(&pending, req, now) {
            return response;
        }
        let Some(issuer) = self.oauth.as_ref().map(|o| o.discovery.issuer().to_owned()) else {
            return super::respond(StatusCode::NOT_FOUND, "no_such_route", None);
        };
        let Some(location) = redirect_location(
            &redirect_uri,
            &redirect_params(ERR_ACCESS_DENIED, state.as_deref(), &issuer, None),
        ) else {
            return error_page(UNUSABLE);
        };
        super::json_body(
            StatusCode::OK,
            json!({ "redirect": location }).to_string(),
            None,
        )
    }

    fn open_pending(&self, token: &str, now: Instant) -> Option<Opened<Pending>> {
        self.sealed.open(PENDING_PURPOSE, token, now)
    }

    /// Record the pending authorization as used. `Some` is the refusal:
    /// a replay was already decided, and a full used-set leaves it
    /// unused so the owner can retry.
    fn burn_decision<T>(
        &self,
        opened: &Opened<T>,
        req: &Incoming,
        now: Instant,
    ) -> Option<Response> {
        match self.sealed.burn(opened, now) {
            Burn::Fresh => None,
            Burn::Replayed => {
                self.fail(req, "already_used");
                Some(super::respond(StatusCode::CONFLICT, "already_used", None))
            }
            Burn::Full => Some(super::rate_limited(PENDING_TTL)),
        }
    }
}

/// The ceremony's nonce check, the pending id it commits to, and the
/// WebAuthn challenge.
fn ceremony_binds(
    ceremony: &Opened<ConsentCeremony>,
    presented_nonce: &str,
) -> Option<(bool, [u8; 32], Vec<u8>)> {
    let nonce = b64url_decode(&ceremony.claims.nonce).ok()?;
    let presented = b64url_decode(presented_nonce).ok()?;
    let pending_id = b64url_decode(&ceremony.claims.pending_id).ok()?;
    if pending_id.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&pending_id);
    let challenge = b64url_decode(&ceremony.claims.challenge).ok()?;
    Some((ct_eq(&nonce, &presented), id, challenge))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    pending: String,
    ceremony_id: String,
    nonce: String,
    credential: Value,
    scopes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingBody {
    pending: String,
}

fn pending_from_body(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<PendingBody>(body)
        .ok()
        .map(|b| b.pending)
}

/// The scopes the owner granted: a subset of `effective`, always
/// including `kharon:read`, in canonical order. `None` when `chosen`
/// names a scope that was not requested or is not a scope at all.
fn grant_scopes(effective: &[Scope], chosen: &[String]) -> Option<Vec<Scope>> {
    let mut parsed = Vec::with_capacity(chosen.len());
    for name in chosen {
        let scope = Scope::parse(name)?;
        if !effective.contains(&scope) {
            return None;
        }
        parsed.push(scope);
    }
    let mut granted = Vec::new();
    for scope in Scope::ALL {
        if (scope == Scope::Read || parsed.contains(&scope)) && effective.contains(&scope) {
            granted.push(scope);
        }
    }
    if !granted.contains(&Scope::Read) {
        return None;
    }
    Some(granted)
}

enum Authorize {
    Unusable,
    Refused(Refusal),
    Redirect {
        error: &'static str,
        redirect_uri: String,
        state: Option<String>,
    },
    Pending(Pending),
}

struct Pairs {
    pairs: Vec<(String, String)>,
}

impl Pairs {
    /// The one value of `key`, or `Err` when it appears more than once.
    fn one<'a>(&'a self, key: &str) -> Result<Option<&'a str>, ()> {
        let mut found = None;
        for (k, v) in &self.pairs {
            if k == key {
                if found.is_some() {
                    return Err(());
                }
                found = Some(v.as_str());
            }
        }
        Ok(found)
    }
}

async fn decide_authorize(query: &str, resource: &str, clients: &ClientAdmission) -> Authorize {
    if query.len() > MAX_QUERY {
        return Authorize::Unusable;
    }
    let Some(pairs) = parse_query(query) else {
        return Authorize::Unusable;
    };
    // A missing, repeated, or over-long `client_id` is not a listed
    // URL. Admit `""` so the refusal is the one entry `admit` writes,
    // and so nothing is fetched.
    let client_id = match pairs.one("client_id") {
        Ok(Some(id)) if id.len() <= MAX_CLIENT_ID => id,
        Ok(Some(_)) | Err(()) | Ok(None) => return refusal_of(clients.admit("").await),
    };
    let redirect_raw = match pairs.one("redirect_uri") {
        Ok(v) => v,
        Err(()) => {
            // Two redirect URIs: still admit the client, and never
            // pick one to redirect to.
            return no_single_redirect(clients, client_id).await;
        }
    };
    let admitted = match clients.admit(client_id).await {
        Ok(metadata) => metadata,
        Err(refusal) => return Authorize::Refused(refusal),
    };
    let Some(redirect_uri) = redirect_raw else {
        return redirect_refused(clients, &admitted);
    };
    if let Err(refusal) = clients.check_redirect(&admitted, redirect_uri) {
        return Authorize::Refused(refusal);
    }
    // The document matched. These checks only keep a value we would
    // not put on the page or in a Location header from becoming a
    // pending authorization. They are not a second admission refusal:
    // `admit` already accepted the document, so nothing is audited here.
    if !safe_redirect(redirect_uri) || !plain_name(admitted.client_name()) {
        return Authorize::Unusable;
    }
    let Some(client_host) = display_host(admitted.client_id()) else {
        return Authorize::Unusable;
    };
    let Some(redirect_host) = display_host(redirect_uri) else {
        return Authorize::Unusable;
    };
    // Steps 4–7 may redirect. `redirect_to` echoes `state` only when
    // the request carried exactly one and it fits.
    let state = match pairs.one("state") {
        Ok(Some(s)) if s.len() <= MAX_STATE => Some(s.to_owned()),
        Ok(None) => None,
        Ok(Some(_)) | Err(()) => {
            return Authorize::Redirect {
                error: ERR_INVALID_REQUEST,
                redirect_uri: redirect_uri.to_owned(),
                state: None,
            };
        }
    };
    let redirect_to = |error| Authorize::Redirect {
        error,
        redirect_uri: redirect_uri.to_owned(),
        state: state.clone(),
    };
    match pairs.one("response_type") {
        Ok(Some("code")) => {}
        Ok(_) | Err(()) => return redirect_to(ERR_UNSUPPORTED_RESPONSE_TYPE),
    }
    match pairs.one("code_challenge_method") {
        Ok(Some("S256")) => {}
        Ok(_) | Err(()) => return redirect_to(ERR_INVALID_REQUEST),
    }
    let challenge = match pairs.one("code_challenge") {
        Ok(Some(c)) if valid_challenge(c) => c.to_owned(),
        Ok(_) | Err(()) => return redirect_to(ERR_INVALID_REQUEST),
    };
    match pairs.one("resource") {
        Ok(Some(got)) if got == resource => {}
        Ok(_) | Err(()) => return redirect_to(ERR_INVALID_TARGET),
    }
    let scopes = match pairs.one("scope") {
        Ok(raw) => match parse_scopes(raw) {
            Ok(scopes) => scopes,
            Err(()) => return redirect_to(ERR_INVALID_SCOPE),
        },
        Err(()) => return redirect_to(ERR_INVALID_SCOPE),
    };
    Authorize::Pending(Pending {
        client_id: admitted.client_id().to_owned(),
        client_name: admitted.client_name().to_owned(),
        client_host,
        redirect_uri: redirect_uri.to_owned(),
        redirect_host,
        code_challenge: challenge,
        state,
        resource: resource.to_owned(),
        scopes,
        connector_grant_declared: admitted.declares_connector_grant(),
    })
}

/// `admit` already audited. An `Ok` here would be an allow-list entry
/// of `""`, which config does not accept.
fn refusal_of(result: Result<ClientMetadata, Refusal>) -> Authorize {
    match result {
        Err(refusal) => Authorize::Refused(refusal),
        Ok(_) => Authorize::Unusable,
    }
}

/// No single `redirect_uri` to compare. Admit first, so a client that
/// is not listed is `not_allowlisted` and is not fetched; a listed
/// client is then one `redirect_mismatch`.
async fn no_single_redirect(clients: &ClientAdmission, client_id: &str) -> Authorize {
    let admitted = match clients.admit(client_id).await {
        Ok(metadata) => metadata,
        Err(refusal) => return Authorize::Refused(refusal),
    };
    redirect_refused(clients, &admitted)
}

/// An empty redirect matches no registered URI, so this is the one
/// `redirect_mismatch` entry.
fn redirect_refused(clients: &ClientAdmission, admitted: &ClientMetadata) -> Authorize {
    match clients.check_redirect(admitted, "") {
        Err(refusal) => Authorize::Refused(refusal),
        Ok(()) => Authorize::Unusable,
    }
}

/// Absent `scope` asks for all three. A present value is those tokens
/// plus `kharon:read`, which every Connect gets. An unknown token is
/// `invalid_scope`.
fn parse_scopes(raw: Option<&str>) -> Result<Vec<Scope>, ()> {
    let Some(raw) = raw else {
        return Ok(Scope::ALL.to_vec());
    };
    if raw.split_whitespace().next().is_none() {
        return Ok(vec![Scope::Read]);
    }
    let mut requested = Vec::new();
    for token in raw.split_whitespace() {
        let scope = Scope::parse(token).ok_or(())?;
        if !requested.contains(&scope) {
            requested.push(scope);
        }
    }
    let mut scopes = Vec::new();
    for scope in Scope::ALL {
        if scope == Scope::Read || requested.contains(&scope) {
            scopes.push(scope);
        }
    }
    Ok(scopes)
}

fn parse_query(query: &str) -> Option<Pairs> {
    if query.is_empty() {
        return Some(Pairs { pairs: Vec::new() });
    }
    let mut pairs = Vec::new();
    for part in query.split('&') {
        if pairs.len() >= MAX_PAIRS {
            return None;
        }
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let k = percent_decode(k)?;
        let v = percent_decode(v)?;
        if k.is_empty() {
            return None;
        }
        pairs.push((k, v));
    }
    Some(Pairs { pairs })
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = hex_val(bytes[i + 1])?;
                let lo = hex_val(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            c => {
                out.push(c);
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

fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn redirect_params<'a>(
    error: &'a str,
    state: Option<&'a str>,
    issuer: &'a str,
    code: Option<&'a str>,
) -> Vec<(&'a str, &'a str)> {
    let mut params = Vec::with_capacity(4);
    if let Some(code) = code {
        params.push(("code", code));
    } else {
        params.push(("error", error));
    }
    if let Some(state) = state {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    params
}

fn success_location(
    redirect_uri: &str,
    code: &str,
    state: Option<&str>,
    issuer: &str,
) -> Option<String> {
    let mut params = vec![("code", code)];
    if let Some(state) = state {
        params.push(("state", state));
    }
    params.push(("iss", issuer));
    redirect_location(redirect_uri, &params)
}

/// Append `params` to `redirect_uri`, preserving an existing query.
/// The base string is kept as the client registered it.
fn redirect_location(redirect_uri: &str, params: &[(&str, &str)]) -> Option<String> {
    if !safe_redirect(redirect_uri) {
        return None;
    }
    let (base, fragment) = match redirect_uri.split_once('#') {
        Some((base, fragment)) => (base, Some(fragment)),
        None => (redirect_uri, None),
    };
    let extra = params
        .iter()
        .map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let mut out = String::with_capacity(base.len() + extra.len() + 8);
    out.push_str(base);
    if base.contains('?') {
        if !base.ends_with('?') && !base.ends_with('&') {
            out.push('&');
        }
    } else {
        out.push('?');
    }
    out.push_str(&extra);
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    HeaderValue::from_str(&out).ok()?;
    Some(out)
}

fn safe_redirect(uri: &str) -> bool {
    if uri.is_empty() || uri.len() > MAX_REDIRECT || !uri.starts_with("https://") {
        return false;
    }
    if uri
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b == b'\\' || b == b'\r' || b == b'\n')
    {
        return false;
    }
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
}

fn plain_name(name: &str) -> bool {
    !name.is_empty() && name.chars().count() <= MAX_NAME && name.chars().all(|c| !c.is_control())
}

/// Hostname to show on the consent screen. `None` when `url` is not
/// an https URL with a host we are willing to render.
fn display_host(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
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

fn valid_challenge(s: &str) -> bool {
    b64url_decode(s).is_ok_and(|b| b.len() == 32)
}

fn sealed_token_charset(token: &str) -> bool {
    let Some((payload, mac)) = token.split_once('.') else {
        return false;
    };
    !payload.is_empty()
        && !mac.is_empty()
        && payload.bytes().all(is_token_char)
        && mac.bytes().all(is_token_char)
}

fn is_token_char(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn error_page(message: &'static str) -> Response {
    let body = format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>kharon</title>\
         \n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head>\n\
         <body>\n<h1>kharon</h1>\n<p>{message}</p>\n</body>\n</html>\n"
    );
    super::build_response(
        StatusCode::BAD_REQUEST,
        "text/html; charset=utf-8",
        body,
        None,
    )
}

fn redirect_response(location: String) -> Response {
    let mut response = super::build_response(
        StatusCode::FOUND,
        "text/html; charset=utf-8",
        String::new(),
        None,
    );
    match HeaderValue::from_str(&location) {
        Ok(value) => {
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        Err(_) => error_page(UNUSABLE),
    }
}

pub(super) fn frame_deny(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

fn consent_script(token: &str) -> String {
    let pending = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".to_owned());
    format!(
        r##"<script type="application/json" id="kharon-pending">{pending}</script>
<script>
(function () {{
  const pending = JSON.parse(document.getElementById("kharon-pending").textContent);
  const section = document.getElementById("connect");
  section.hidden = false;
  const err = document.getElementById("connect-err");
  function b64urlToBuf(s) {{
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }}
  function bufToB64url(buf) {{
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }}
  function prepGet(pk) {{
    pk.challenge = b64urlToBuf(pk.challenge);
    if (pk.allowCredentials) {{
      for (const c of pk.allowCredentials) c.id = b64urlToBuf(c.id);
    }}
    return pk;
  }}
  function credToJSON(cred) {{
    const r = cred.response;
    const response = {{ clientDataJSON: bufToB64url(r.clientDataJSON) }};
    if (r.authenticatorData) response.authenticatorData = bufToB64url(r.authenticatorData);
    if (r.signature) response.signature = bufToB64url(r.signature);
    if (r.userHandle) response.userHandle = bufToB64url(r.userHandle);
    return {{ id: cred.id, type: cred.type, response: response }};
  }}
  async function post(path, body) {{
    const r = await fetch(path, {{
      method: "POST",
      credentials: "same-origin",
      headers: {{ "content-type": "application/json" }},
      body: JSON.stringify(body)
    }});
    if (r.status === 401) {{ location.reload(); return null; }}
    return r;
  }}
  function go(redirect) {{
    if (typeof redirect === "string" && redirect.indexOf("https://") === 0) {{
      location.assign(redirect);
    }} else {{
      err.textContent = "kharon did not return a redirect.";
    }}
  }}
  post("/oauth/consent/view", {{ pending: pending }}).then(async (r) => {{
    if (!r || !r.ok) {{ err.textContent = "This connection request has expired."; return; }}
    const view = await r.json();
    document.getElementById("connect-who").textContent = view.client_name;
    document.getElementById("connect-hosts").textContent =
      "Dashboard host: " + view.client_host + ". It will return you to " + view.redirect_host + ".";
    document.getElementById("connect-notice").textContent = view.notice;
    const box = document.getElementById("connect-scopes");
    for (const s of view.scopes) {{
      const row = document.createElement("label");
      row.style.display = "block";
      if (s.optional) {{
        const input = document.createElement("input");
        input.type = "checkbox";
        input.checked = true;
        input.setAttribute("data-scope", s.id);
        row.appendChild(input);
      }}
      const span = document.createElement("span");
      span.textContent = s.words;
      row.appendChild(span);
      box.appendChild(row);
    }}
  }});
  document.getElementById("connect-approve").addEventListener("click", async () => {{
    err.textContent = "";
    const opt = await post("/oauth/consent/options", {{ pending: pending }});
    if (!opt || !opt.ok) {{ err.textContent = "Couldn't start the passkey check."; return; }}
    const data = await opt.json();
    let cred;
    try {{
      cred = await navigator.credentials.get({{ publicKey: prepGet(data.publicKey) }});
    }} catch (e) {{
      err.textContent = "Passkey was not asserted";
      return;
    }}
    const scopes = ["kharon:read"];
    for (const input of document.querySelectorAll("#connect-scopes input")) {{
      if (input.checked && input.getAttribute("data-scope")) {{
        scopes.push(input.getAttribute("data-scope"));
      }}
    }}
    const fin = await post("/oauth/consent/approve", {{
      pending: pending,
      ceremony_id: data.ceremony_id,
      nonce: data.nonce,
      credential: credToJSON(cred),
      scopes: scopes
    }});
    if (!fin || !fin.ok) {{ err.textContent = "Connect was refused."; return; }}
    go((await fin.json()).redirect);
  }});
  document.getElementById("connect-deny").addEventListener("click", async () => {{
    err.textContent = "";
    const r = await post("/oauth/consent/deny", {{ pending: pending }});
    if (!r || !r.ok) {{ err.textContent = "Couldn't decline."; return; }}
    go((await r.json()).redirect);
  }});
}})();
</script>"##
    )
}

#[cfg(test)]
#[path = "oauth_tests.rs"]
mod tests;
