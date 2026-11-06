//! Owner web UI (REQ-APR-005; SPEC §5, issue #17).
//!
//! A loopback HTTP server, separate from the agent API. Login is a
//! WebAuthn passkey assertion and nothing else: there is no password
//! field, no password route, and a JSON body that carries a
//! `password` key is refused before any session is issued. A session
//! lasts at most [`SESSION_TTL`] (15 minutes, SPEC §5) and is an
//! `HttpOnly; SameSite=Strict` cookie. Logout drops that session
//! on the server; clearing the cookie alone does not end it.
//!
//! Registering the first passkey is not a login. The owner socket
//! (same-uid) mints a single-use enrollment code via `passkey_enroll`;
//! `POST /owner/register/*` accepts that code, or an existing owner
//! session, and does not set a session cookie. Signing in still
//! requires an assertion.
//!
//! Fixed routes (no token in the path):
//!
//! | Method | Path | |
//! |---|---|---|
//! | GET | `/` | Login page, or the signed-in shell |
//! | GET | `/enroll` | Enrollment page (one-time code, not a password) |
//! | POST | `/owner/login/options` | Begin an assertion ceremony |
//! | POST | `/owner/login/finish` | Finish it; sets the session cookie |
//! | POST | `/owner/register/options` | Begin registration |
//! | POST | `/owner/register/finish` | Store the passkey; no session |
//! | POST | `/owner/logout` | Revoke the session and clear the cookie |
//! | GET | `/owner/session` | Shell JSON, or 401 |
//!
//! The same listener serves ntfy redeem (REQ-APR-004, REQ-DEP-006,
//! #136): `GET`/`POST` `/owner/approve/<token>` and
//! `/owner/deny/<token>`. GET confirms and POST decides. There is no
//! session cookie; the token is the credential. A used or expired
//! token is 410. Those paths are absent from the agent API.
//!
//! Responses use fixed error codes only (REQ-API-006). Failed login
//! and enrollment attempts are audited as `owner_auth_fail`.

mod store;
mod webauthn;

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use rand::RngCore;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use self::store::PasskeyStore;
use self::webauthn::{RegisteredCredential, b64url_decode, b64url_encode, ct_eq};
use crate::api::http::{
    ApprovalRedeemer, OWNER_APPROVE_PREFIX, OWNER_DENY_PREFIX, dispatch_owner_approval,
};

/// SPEC §5: an owner web session is at most 15 minutes.
pub const SESSION_TTL: Duration = Duration::from_secs(15 * 60);

/// A challenge or enrollment code lives this long, matching the
/// ntfy one-time token (SPEC §5).
pub const CEREMONY_TTL: Duration = Duration::from_secs(120);

/// Cookie that carries the session token. The token itself is not
/// stored; the server keeps its SHA-256.
const SESSION_COOKIE: &str = "kharon_owner";

/// Fixed routes this UI serves (no token in the path). Tests assert
/// none of them is a password login. ntfy redeem is the
/// `/owner/approve/<token>` and `/owner/deny/<token>` prefixes on
/// this same listener.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/"),
    ("GET", "/enroll"),
    ("POST", "/owner/login/options"),
    ("POST", "/owner/login/finish"),
    ("POST", "/owner/register/options"),
    ("POST", "/owner/register/finish"),
    ("POST", "/owner/logout"),
    ("GET", "/owner/session"),
];

const MAX_BODY: usize = 16 * 1024;
const MAX_CEREMONIES: usize = 8;
const MAX_ENROLL: usize = 4;
const MAX_SESSIONS: usize = 4;

/// What the signed-in shell shows. No item names, no secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellView {
    /// Whether the broker is locked.
    pub locked: bool,
    /// Pending grant requests.
    pub pending: usize,
}

/// Broker facts the shell renders. The daemon's implementation
/// takes the lock-controller mutex, so callers run it on a
/// blocking thread.
pub trait OwnerShell: Send + Sync + 'static {
    /// Current shell facts.
    fn view(&self) -> ShellView;
}

/// A fixed shell, for tests and for a UI with nothing to report.
pub struct StaticShell(pub ShellView);

impl OwnerShell for StaticShell {
    fn view(&self) -> ShellView {
        self.0
    }
}

/// Where `owner_auth_fail` entries go. Best effort: a failed append
/// does not turn a refusal into a success.
pub trait OwnerAudit: Send + Sync + 'static {
    /// Record a failed owner-UI authentication attempt. `detail` is
    /// a fixed code, never request data.
    fn auth_failed(&self, detail: &'static str);
}

/// Audit sink that discards. Tests that don't care use this.
pub struct NoAudit;

impl OwnerAudit for NoAudit {
    fn auth_failed(&self, _detail: &'static str) {}
}

/// The owner UI's state: passkeys, ceremonies, sessions, enrollment
/// codes. Cheap to clone via [`Arc`]; the server holds one.
pub struct OwnerUi {
    rp_id: String,
    origin: String,
    secure_cookie: bool,
    shell: Arc<dyn OwnerShell>,
    audit: Arc<dyn OwnerAudit>,
    passkeys: Mutex<PasskeyStore>,
    ceremonies: Mutex<Vec<Ceremony>>,
    sessions: Mutex<Vec<Session>>,
    enroll: Mutex<Vec<Enroll>>,
}

struct Ceremony {
    id: String,
    challenge: Vec<u8>,
    kind: CeremonyKind,
    expires: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CeremonyKind {
    Login,
    Register,
}

struct Session {
    hash: [u8; 32],
    expires: Instant,
}

struct Enroll {
    hash: [u8; 32],
    expires: Instant,
}

impl OwnerUi {
    /// Open the passkey store under `data_dir` and build the UI.
    /// `origin` is the browser origin exactly as `clientDataJSON`
    /// will report it (`http://localhost:8787`, no trailing slash).
    pub fn open(
        data_dir: &Path,
        rp_id: impl Into<String>,
        origin: impl Into<String>,
        shell: Arc<dyn OwnerShell>,
        audit: Arc<dyn OwnerAudit>,
    ) -> std::io::Result<Arc<Self>> {
        let origin = origin.into();
        let secure_cookie = origin.starts_with("https://");
        let passkeys = PasskeyStore::load(data_dir)?;
        Ok(Arc::new(Self {
            rp_id: rp_id.into(),
            origin,
            secure_cookie,
            shell,
            audit,
            passkeys: Mutex::new(passkeys),
            ceremonies: Mutex::new(Vec::new()),
            sessions: Mutex::new(Vec::new()),
            enroll: Mutex::new(Vec::new()),
        }))
    }

    /// The origin assertions are checked against.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Mint a single-use enrollment code (base64url, 256 bits).
    /// The returned buffer is the only copy the caller should print;
    /// the server stores SHA-256 of it. The owner socket is the
    /// intended caller: it is already authenticated by peer uid.
    pub fn mint_enroll_token(&self) -> Zeroizing<String> {
        let raw = random_bytes::<32>();
        let token = Zeroizing::new(b64url_encode(&raw));
        let hash = sha256(token.as_bytes());
        let mut guard = self.enroll.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        guard.retain(|e| e.expires > now);
        if guard.len() >= MAX_ENROLL {
            guard.remove(0);
        }
        guard.push(Enroll {
            hash,
            expires: now + CEREMONY_TTL,
        });
        token
    }

    /// Force every session to look expired. Session TTL is also
    /// [`SESSION_TTL`]; this is how the test observes the cap
    /// without waiting a quarter hour.
    #[cfg(test)]
    fn expire_sessions(&self) {
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        for s in guard.iter_mut() {
            s.expires = Instant::now();
        }
    }
}

/// Owner UI plus the ntfy redeem routes on one listener.
struct OwnerServer {
    ui: Arc<OwnerUi>,
    redeem: Arc<dyn ApprovalRedeemer>,
}

/// Serve until the future is dropped.
///
/// `redeem` handles `/owner/approve/<token>` and `/owner/deny/<token>`
/// on this listener (REQ-DEP-006, #136). Those requests skip the
/// WebAuthn origin check so an ntfy client can POST its action.
pub async fn serve(
    listener: TcpListener,
    ui: Arc<OwnerUi>,
    redeem: Arc<dyn ApprovalRedeemer>,
) -> std::io::Result<()> {
    axum::serve(listener, router(ui, redeem)).await
}

/// [`serve`], returning once `shutdown` resolves.
pub async fn serve_with_shutdown<F>(
    listener: TcpListener,
    ui: Arc<OwnerUi>,
    redeem: Arc<dyn ApprovalRedeemer>,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, router(ui, redeem))
        .with_graceful_shutdown(shutdown)
        .await
}

fn router(ui: Arc<OwnerUi>, redeem: Arc<dyn ApprovalRedeemer>) -> Router {
    let state = Arc::new(OwnerServer { ui, redeem });
    Router::new().fallback(handle).with_state(state)
}

async fn handle(State(state): State<Arc<OwnerServer>>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    if path.starts_with(OWNER_APPROVE_PREFIX) || path.starts_with(OWNER_DENY_PREFIX) {
        let redeem = Arc::clone(&state.redeem);
        return dispatch_owner_approval(redeem, method, path).await;
    }
    let ui = Arc::clone(&state.ui);
    let headers = req.headers().clone();
    let cookie = header_str(&headers, header::COOKIE);
    let origin = header_str(&headers, header::ORIGIN);
    let authorization = header_str(&headers, header::AUTHORIZATION);
    let content_type = header_str(&headers, header::CONTENT_TYPE);
    let (_parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b.to_vec(),
        Err(_) => return respond(StatusCode::PAYLOAD_TOO_LARGE, "bad_request", None),
    };
    let joined = tokio::task::spawn_blocking(move || {
        ui.dispatch(Incoming {
            method,
            path,
            cookie,
            origin,
            authorization,
            content_type,
            body: bytes,
        })
    })
    .await;
    match joined {
        Ok(response) => response,
        Err(_) => respond(StatusCode::INTERNAL_SERVER_ERROR, "error", None),
    }
}

struct Incoming {
    method: Method,
    path: String,
    cookie: Option<String>,
    origin: Option<String>,
    authorization: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl OwnerUi {
    fn dispatch(&self, req: Incoming) -> Response {
        if req.method == Method::POST && req.origin.as_deref().is_some_and(|o| o != self.origin) {
            self.audit.auth_failed("origin");
            return respond(StatusCode::FORBIDDEN, "origin", None);
        }
        let allowed = match req.path.as_str() {
            "/" | "/enroll" | "/owner/session" => Some(Method::GET),
            "/owner/login/options"
            | "/owner/login/finish"
            | "/owner/register/options"
            | "/owner/register/finish"
            | "/owner/logout" => Some(Method::POST),
            _ => None,
        };
        let Some(allowed) = allowed else {
            return respond(StatusCode::NOT_FOUND, "no_such_route", None);
        };
        if req.method != allowed {
            return method_not_allowed(if allowed == Method::GET {
                "GET"
            } else {
                "POST"
            });
        }
        match req.path.as_str() {
            "/" => self.page_home(&req),
            "/enroll" => html(ENROLL_PAGE),
            "/owner/session" => self.session_json(&req),
            "/owner/login/options" => self.login_options(&req),
            "/owner/login/finish" => self.login_finish(&req),
            "/owner/register/options" => self.register_options(&req),
            "/owner/register/finish" => self.register_finish(&req),
            "/owner/logout" => self.logout(&req),
            _ => unreachable!("path was matched above"),
        }
    }

    fn page_home(&self, req: &Incoming) -> Response {
        if self.session_alive(req.cookie.as_deref()) {
            let view = self.shell.view();
            let state = if view.locked { "locked" } else { "unlocked" };
            return html(&shell_page(state, view.pending));
        }
        html(LOGIN_PAGE)
    }

    fn session_json(&self, req: &Incoming) -> Response {
        if !self.session_alive(req.cookie.as_deref()) {
            return respond(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        }
        let view = self.shell.view();
        json_body(
            StatusCode::OK,
            json!({"ok": true, "locked": view.locked, "pending": view.pending}).to_string(),
            None,
        )
    }

    fn login_options(&self, req: &Incoming) -> Response {
        if let Some(err) = self.precheck_post(req) {
            return err;
        }
        let creds: Vec<(String, String)> = {
            let store = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
            if store.is_empty() {
                return respond(StatusCode::CONFLICT, "no_credential", None);
            }
            store
                .credentials()
                .iter()
                .map(|c| ("public-key".to_owned(), b64url_encode(&c.id)))
                .collect()
        };
        let ceremony = self.begin(CeremonyKind::Login);
        let allow: Vec<Value> = creds
            .into_iter()
            .map(|(ty, id)| json!({"type": ty, "id": id}))
            .collect();
        json_body(
            StatusCode::OK,
            json!({
                "ceremony_id": ceremony.id,
                "publicKey": {
                    "challenge": b64url_encode(&ceremony.challenge),
                    "timeout": 60_000,
                    "rpId": self.rp_id,
                    "allowCredentials": allow,
                    "userVerification": "required",
                }
            })
            .to_string(),
            None,
        )
    }

    fn register_options(&self, req: &Incoming) -> Response {
        if let Some(err) = self.precheck_post(req) {
            return err;
        }
        if !self.registration_authorized(req) {
            self.audit.auth_failed("bad_enroll_token");
            return respond(StatusCode::UNAUTHORIZED, "bad_enroll_token", None);
        }
        let user_handle = {
            let store = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
            b64url_encode(store.user_handle())
        };
        let ceremony = self.begin(CeremonyKind::Register);
        json_body(
            StatusCode::OK,
            json!({
                "ceremony_id": ceremony.id,
                "publicKey": {
                    "rp": {"id": self.rp_id, "name": "kharon"},
                    "user": {
                        "id": user_handle,
                        "name": "owner",
                        "displayName": "kharon owner",
                    },
                    "challenge": b64url_encode(&ceremony.challenge),
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                    "timeout": 60_000,
                    "attestation": "none",
                    "authenticatorSelection": {
                        "residentKey": "required",
                        "userVerification": "required",
                        "authenticatorAttachment": "platform",
                    },
                }
            })
            .to_string(),
            None,
        )
    }

    fn login_finish(&self, req: &Incoming) -> Response {
        if let Some(err) = self.precheck_post(req) {
            return err;
        }
        if req.body.is_empty() {
            self.audit.auth_failed("no_assertion");
            return respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        }
        let Some(value) = json_object(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(cred) = credential_response(&value, CeremonyKind::Login) else {
            self.audit.auth_failed("no_assertion");
            return respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        };
        let Some(ceremony_id) = value.get("ceremony_id").and_then(|v| v.as_str()) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(ceremony) = self.take_ceremony(ceremony_id, CeremonyKind::Login) else {
            self.audit.auth_failed("bad_assertion");
            return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
        };
        let verified = {
            let store = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
            let Some(known) = store.credentials().iter().find(|c| c.id == cred.id) else {
                drop(store);
                self.audit.auth_failed("bad_assertion");
                return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            };
            if let Some(handle) = &cred.user_handle
                && !ct_eq(handle, store.user_handle())
            {
                drop(store);
                self.audit.auth_failed("bad_assertion");
                return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            }
            webauthn::verify_assertion(webauthn::Assertion {
                client_data_json: &cred.client_data_json,
                authenticator_data: &cred.authenticator_data,
                signature: &cred.signature,
                challenge: &ceremony.challenge,
                origin: &self.origin,
                rp_id: &self.rp_id,
                public_key: &known.public_key,
                stored_sign_count: known.sign_count,
            })
        };
        let new_count = match verified {
            Ok(n) => n,
            Err(_) => {
                self.audit.auth_failed("bad_assertion");
                return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            }
        };
        if self
            .passkeys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .set_sign_count(&cred.id, new_count)
            .is_err()
        {
            self.audit.auth_failed("bad_assertion");
            return respond(StatusCode::INTERNAL_SERVER_ERROR, "store_failed", None);
        }
        let cookie = self.issue_session();
        json_body(
            StatusCode::OK,
            json!({"ok": true}).to_string(),
            Some(cookie),
        )
    }

    fn register_finish(&self, req: &Incoming) -> Response {
        if let Some(err) = self.precheck_post(req) {
            return err;
        }
        if req.body.is_empty() {
            self.audit.auth_failed("no_assertion");
            return respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        }
        let Some(value) = json_object(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(cred) = credential_response(&value, CeremonyKind::Register) else {
            self.audit.auth_failed("no_assertion");
            return respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        };
        let Some(ceremony_id) = value.get("ceremony_id").and_then(|v| v.as_str()) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(ceremony) = self.take_ceremony(ceremony_id, CeremonyKind::Register) else {
            self.audit.auth_failed("bad_assertion");
            return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
        };
        let registered = webauthn::verify_registration(
            &cred.client_data_json,
            &cred.attestation_object,
            &ceremony.challenge,
            &self.origin,
            &self.rp_id,
        );
        let registered = match registered {
            Ok(r) if r.credential_id == cred.id => r,
            _ => {
                self.audit.auth_failed("bad_assertion");
                return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            }
        };
        if self.store_credential(registered).is_err() {
            self.audit.auth_failed("bad_assertion");
            return respond(StatusCode::INTERNAL_SERVER_ERROR, "store_failed", None);
        }
        // Registration is not a login. No session cookie.
        json_body(
            StatusCode::OK,
            json!({"ok": true, "signed_in": false}).to_string(),
            None,
        )
    }

    /// End the session named by the request cookie, then clear it.
    /// A copied token must not keep working until [`SESSION_TTL`].
    /// Logout with no cookie still clears the cookie and succeeds.
    fn logout(&self, req: &Incoming) -> Response {
        self.revoke_session(req.cookie.as_deref());
        json_body(
            StatusCode::OK,
            json!({"ok": true}).to_string(),
            Some(clear_cookie(self.secure_cookie)),
        )
    }

    /// Password-shaped bodies are refused here, before a ceremony
    /// exists. Non-JSON bodies are `bad_request` (there is no form
    /// login). Empty bodies are fine: the options calls send one.
    fn precheck_post(&self, req: &Incoming) -> Option<Response> {
        if req.body.is_empty() {
            return None;
        }
        if !req.content_type.as_deref().is_some_and(|c| {
            c.split(';')
                .next()
                .is_some_and(|t| t.trim() == "application/json")
        }) {
            return Some(respond(StatusCode::BAD_REQUEST, "bad_request", None));
        }
        match serde_json::from_slice::<Value>(&req.body) {
            Ok(v) if json_has_password_key(&v) => {
                self.audit.auth_failed("password_rejected");
                Some(respond(StatusCode::BAD_REQUEST, "password_rejected", None))
            }
            Ok(_) => None,
            Err(_) => Some(respond(StatusCode::BAD_REQUEST, "bad_request", None)),
        }
    }

    fn registration_authorized(&self, req: &Incoming) -> bool {
        if self.session_alive(req.cookie.as_deref()) {
            return true;
        }
        let Some(header) = req.authorization.as_deref() else {
            return false;
        };
        let Some(token) = header.strip_prefix("Bearer ") else {
            return false;
        };
        if token.is_empty() || token.bytes().any(|b| b.is_ascii_whitespace()) {
            return false;
        }
        self.take_enroll(token)
    }

    fn begin(&self, kind: CeremonyKind) -> Ceremony {
        let mut id_raw = [0u8; 32];
        let mut challenge = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut id_raw);
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        let ceremony = Ceremony {
            id: b64url_encode(&id_raw),
            challenge,
            kind,
            expires: Instant::now() + CEREMONY_TTL,
        };
        let mut guard = self.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        guard.retain(|c| c.expires > now);
        if guard.len() >= MAX_CEREMONIES {
            guard.remove(0);
        }
        guard.push(Ceremony {
            id: ceremony.id.clone(),
            challenge: ceremony.challenge.clone(),
            kind: ceremony.kind,
            expires: ceremony.expires,
        });
        ceremony
    }

    fn take_ceremony(&self, id: &str, kind: CeremonyKind) -> Option<Ceremony> {
        let mut guard = self.ceremonies.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let idx = guard
            .iter()
            .position(|c| c.id == id && c.kind == kind && c.expires > now)?;
        Some(guard.remove(idx))
    }

    fn take_enroll(&self, token: &str) -> bool {
        let hash = sha256(token.as_bytes());
        let mut guard = self.enroll.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let mut found = None;
        for (i, e) in guard.iter().enumerate() {
            if e.expires > now && ct_eq(&e.hash, &hash) {
                found = Some(i);
            }
        }
        if let Some(i) = found {
            guard.remove(i);
            true
        } else {
            false
        }
    }

    fn issue_session(&self) -> String {
        let raw = random_bytes::<32>();
        let token = b64url_encode(&raw);
        let hash = sha256(token.as_bytes());
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        guard.retain(|s| s.expires > now);
        if guard.len() >= MAX_SESSIONS {
            guard.remove(0);
        }
        guard.push(Session {
            hash,
            expires: now + SESSION_TTL,
        });
        session_cookie(&token, self.secure_cookie)
    }

    fn session_alive(&self, cookie_header: Option<&str>) -> bool {
        let Some(hash) = session_hash(cookie_header) else {
            return false;
        };
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        guard.retain(|s| s.expires > now);
        guard.iter().any(|s| ct_eq(&s.hash, &hash))
    }

    /// Remove the session that matches this cookie, expired or not.
    /// Other sessions stay. A missing or unknown cookie is a no-op.
    fn revoke_session(&self, cookie_header: Option<&str>) {
        let Some(hash) = session_hash(cookie_header) else {
            return;
        };
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|s| !ct_eq(&s.hash, &hash));
    }

    fn store_credential(&self, cred: RegisteredCredential) -> std::io::Result<()> {
        self.passkeys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(store::Credential {
                id: cred.credential_id,
                public_key: cred.public_key,
                sign_count: cred.sign_count,
            })
    }
}

struct CredParts {
    id: Vec<u8>,
    client_data_json: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
    attestation_object: Vec<u8>,
    user_handle: Option<Vec<u8>>,
}

/// Pull the assertion (or attestation) out of a finish body.
/// `None` means the client did not present one — the "no assertion"
/// refusal, as opposed to a present assertion that fails to verify.
fn credential_response(value: &Value, kind: CeremonyKind) -> Option<CredParts> {
    let cred = value.get("credential")?;
    if cred.get("type").and_then(|v| v.as_str()) != Some("public-key") {
        return None;
    }
    let id = b64url_decode(cred.get("id").and_then(|v| v.as_str())?).ok()?;
    if let Some(raw) = cred.get("rawId").and_then(|v| v.as_str()) {
        let raw = b64url_decode(raw).ok()?;
        if raw != id {
            return None;
        }
    }
    let response = cred.get("response")?;
    let client_data_json =
        b64url_decode(response.get("clientDataJSON").and_then(|v| v.as_str())?).ok()?;
    let user_handle = match response.get("userHandle") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(b64url_decode(s).ok()?),
        Some(_) => return None,
    };
    let (authenticator_data, signature, attestation_object) = match kind {
        CeremonyKind::Login => {
            let auth = b64url_decode(
                response
                    .get("authenticatorData")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())?,
            )
            .ok()?;
            let sig = b64url_decode(
                response
                    .get("signature")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())?,
            )
            .ok()?;
            (auth, sig, Vec::new())
        }
        CeremonyKind::Register => {
            let att = b64url_decode(
                response
                    .get("attestationObject")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())?,
            )
            .ok()?;
            (Vec::new(), Vec::new(), att)
        }
    };
    Some(CredParts {
        id,
        client_data_json,
        authenticator_data,
        signature,
        attestation_object,
        user_handle,
    })
}

fn json_object(body: &[u8]) -> Option<Value> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => Some(Value::Object(map)),
        _ => None,
    }
}

fn json_has_password_key(v: &Value) -> bool {
    match v {
        Value::Object(map) => {
            map.keys().any(|k| k.eq_ignore_ascii_case("password"))
                || map.values().any(json_has_password_key)
        }
        Value::Array(items) => items.iter().any(json_has_password_key),
        _ => false,
    }
}

fn header_str(headers: &axum::http::HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn session_hash(cookie_header: Option<&str>) -> Option<[u8; 32]> {
    let token = cookie_value(cookie_header, SESSION_COOKIE)?;
    Some(sha256(token.as_bytes()))
}

fn cookie_value(header: Option<&str>, name: &str) -> Option<String> {
    let header = header?;
    for part in header.split(';') {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        if k.trim() == name {
            return Some(v.trim().to_owned());
        }
    }
    None
}

fn session_cookie(token: &str, secure: bool) -> String {
    let mut c = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn clear_cookie(secure: bool) -> String {
    let mut c = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn respond(status: StatusCode, code: &'static str, set_cookie: Option<String>) -> Response {
    json_body(
        status,
        json!({"ok": false, "error": code}).to_string(),
        set_cookie,
    )
}

fn json_body(status: StatusCode, body: String, set_cookie: Option<String>) -> Response {
    build_response(status, "application/json", body, set_cookie)
}

fn html(body: &str) -> Response {
    build_response(
        StatusCode::OK,
        "text/html; charset=utf-8",
        body.to_owned(),
        None,
    )
}

fn method_not_allowed(allow: &'static str) -> Response {
    let mut response = respond(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", None);
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    response
}

fn build_response(
    status: StatusCode,
    content_type: &'static str,
    body: String,
    set_cookie: Option<String>,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        );
    if let Some(cookie) = set_cookie {
        match HeaderValue::from_str(&cookie) {
            Ok(v) => {
                builder = builder.header(header::SET_COOKIE, v);
            }
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(r#"{"ok":false,"error":"error"}"#))
                    .expect("static response");
            }
        }
    }
    builder
        .body(Body::from(body))
        .expect("static response headers")
}

const LOGIN_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>kharon</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; margin: 2.5rem auto; max-width: 32rem; }
  button { font: inherit; padding: 0.55rem 1rem; }
  .err { min-height: 1.2em; }
</style>
</head>
<body>
<h1>kharon</h1>
<p>Sign in with your passkey.</p>
<button id="signin" type="button">Sign in with a passkey</button>
<p id="err" class="err" role="alert"></p>
<script>
function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function prepGet(pk) {
  pk.challenge = b64urlToBuf(pk.challenge);
  if (pk.allowCredentials) {
    for (const c of pk.allowCredentials) c.id = b64urlToBuf(c.id);
  }
  return pk;
}
function credToJSON(cred) {
  const r = cred.response;
  const response = { clientDataJSON: bufToB64url(r.clientDataJSON) };
  if (r.authenticatorData) response.authenticatorData = bufToB64url(r.authenticatorData);
  if (r.signature) response.signature = bufToB64url(r.signature);
  if (r.userHandle) response.userHandle = bufToB64url(r.userHandle);
  if (r.attestationObject) response.attestationObject = bufToB64url(r.attestationObject);
  return { id: cred.id, type: cred.type, response: response };
}
window.kharonSignIn = async function () {
  const err = document.getElementById("err");
  err.textContent = "";
  const opt = await fetch("/owner/login/options", { method: "POST", credentials: "same-origin" });
  if (!opt.ok) { err.textContent = "Sign-in is not available"; return false; }
  const data = await opt.json();
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey: prepGet(data.publicKey) });
  } catch (e) {
    err.textContent = "Passkey was not asserted";
    return false;
  }
  const fin = await fetch("/owner/login/finish", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ceremony_id: data.ceremony_id, credential: credToJSON(cred) })
  });
  if (!fin.ok) { err.textContent = "Sign-in refused"; return false; }
  return true;
};
document.getElementById("signin").addEventListener("click", async () => {
  if (await window.kharonSignIn()) location.assign("/");
});
</script>
</body>
</html>
"#;

const ENROLL_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>kharon enroll</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; margin: 2.5rem auto; max-width: 32rem; }
  input, button { font: inherit; }
  input { display: block; width: 100%; margin: 0.4rem 0 1rem; }
  button { padding: 0.55rem 1rem; }
</style>
</head>
<body>
<h1>Register a passkey</h1>
<p>Paste the one-time enrollment code from <code>kharon passkey-enroll</code>. Registering does not sign you in.</p>
<label for="code">Enrollment code</label>
<input id="code" type="text" name="enroll_code" autocomplete="one-time-code" spellcheck="false">
<button id="register" type="button">Register passkey</button>
<p id="err" role="alert"></p>
<p id="done" hidden>Passkey registered. <a href="/">Sign in</a></p>
<script>
function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function prepCreate(pk) {
  pk.challenge = b64urlToBuf(pk.challenge);
  pk.user.id = b64urlToBuf(pk.user.id);
  return pk;
}
function credToJSON(cred) {
  const r = cred.response;
  return {
    id: cred.id,
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      attestationObject: bufToB64url(r.attestationObject)
    }
  };
}
window.kharonRegister = async function (code) {
  const err = document.getElementById("err");
  err.textContent = "";
  const opt = await fetch("/owner/register/options", {
    method: "POST",
    credentials: "same-origin",
    headers: { "authorization": "Bearer " + code }
  });
  if (!opt.ok) { err.textContent = "Enrollment code refused"; return false; }
  const data = await opt.json();
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: prepCreate(data.publicKey) });
  } catch (e) {
    err.textContent = "Passkey was not created";
    return false;
  }
  const fin = await fetch("/owner/register/finish", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ceremony_id: data.ceremony_id, credential: credToJSON(cred) })
  });
  if (!fin.ok) { err.textContent = "Registration refused"; return false; }
  document.getElementById("done").hidden = false;
  return true;
};
document.getElementById("register").addEventListener("click", async () => {
  const input = document.getElementById("code");
  const code = input.value;
  input.value = "";
  await window.kharonRegister(code);
});
</script>
</body>
</html>
"#;

fn shell_page(locked: &str, pending: usize) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>kharon</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2.5rem auto; max-width: 32rem; }}
  button {{ font: inherit; padding: 0.55rem 1rem; }}
</style>
</head>
<body>
<h1>kharon</h1>
<p id="state">signed-in</p>
<p>Broker: <span id="locked">{locked}</span></p>
<p>Pending approvals: <span id="pending">{pending}</span></p>
<button id="signout" type="button">Sign out</button>
<script>
document.getElementById("signout").addEventListener("click", async () => {{
  await fetch("/owner/logout", {{ method: "POST", credentials: "same-origin" }});
  location.assign("/");
}});
</script>
</body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_apr_005_routes_have_no_password_login() {
        assert!(
            ROUTES.iter().all(|(method, path)| {
                let blob = format!("{method} {path}").to_ascii_lowercase();
                !blob.contains("password") && !blob.contains("unlock")
            }),
            "owner UI routes: {ROUTES:?}"
        );
        let login = LOGIN_PAGE.to_ascii_lowercase();
        assert!(
            !login.contains("password"),
            "login page mentions a password"
        );
        assert!(!login.contains("<input"), "login page has a text field");
        let enroll = ENROLL_PAGE.to_ascii_lowercase();
        assert!(!enroll.contains("password"));
        assert!(enroll.contains(r#"type="text""#));
        assert!(!enroll.contains(r#"type="password""#));
        assert_eq!(SESSION_TTL, Duration::from_secs(15 * 60));
    }

    #[test]
    fn req_apr_005_session_at_most_15_min() {
        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open(
            dir.path(),
            "localhost",
            "http://localhost:9",
            Arc::new(StaticShell(ShellView {
                locked: true,
                pending: 0,
            })),
            Arc::new(NoAudit),
        )
        .unwrap();
        let cookie = ui.issue_session();
        let header = cookie.split(';').next().unwrap();
        assert!(ui.session_alive(Some(header)));
        ui.expire_sessions();
        assert!(
            !ui.session_alive(Some(header)),
            "a session past its cap must not authenticate"
        );
        assert!(cookie.contains("Max-Age=900"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(!cookie.to_ascii_lowercase().contains("password"));
    }

    #[test]
    fn req_apr_005_password_key_is_rejected_before_a_session() {
        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open(
            dir.path(),
            "localhost",
            "http://localhost:9",
            Arc::new(StaticShell(ShellView {
                locked: true,
                pending: 0,
            })),
            Arc::new(NoAudit),
        )
        .unwrap();
        let response = ui.login_finish(&Incoming {
            method: Method::POST,
            path: "/owner/login/finish".into(),
            cookie: None,
            origin: Some("http://localhost:9".into()),
            authorization: None,
            content_type: Some("application/json".into()),
            body: br#"{"password":"hunter2","ceremony_id":"x"}"#.to_vec(),
        });
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert!(!ui.session_alive(None));
    }

    #[test]
    fn req_apr_005_logout_removes_only_the_presented_session() {
        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open(
            dir.path(),
            "localhost",
            "http://localhost:9",
            Arc::new(StaticShell(ShellView {
                locked: true,
                pending: 0,
            })),
            Arc::new(NoAudit),
        )
        .unwrap();
        let kept = ui.issue_session();
        let dropped = ui.issue_session();
        let kept_header = kept.split(';').next().unwrap().to_owned();
        let dropped_header = dropped.split(';').next().unwrap().to_owned();
        let response = ui.dispatch(Incoming {
            method: Method::POST,
            path: "/owner/logout".into(),
            cookie: Some(dropped_header.clone()),
            origin: Some("http://localhost:9".into()),
            authorization: None,
            content_type: None,
            body: Vec::new(),
        });
        assert_eq!(response.status(), StatusCode::OK);
        let cleared = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
        assert!(
            !ui.session_alive(Some(&dropped_header)),
            "logout left the session in place"
        );
        assert!(
            ui.session_alive(Some(&kept_header)),
            "logout revoked a different session"
        );
        let replay = ui.dispatch(Incoming {
            method: Method::GET,
            path: "/owner/session".into(),
            cookie: Some(dropped_header),
            origin: None,
            authorization: None,
            content_type: None,
            body: Vec::new(),
        });
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }
}
