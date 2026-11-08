//! Owner web UI (REQ-APR-005; SPEC §5, issue #17).
//!
//! A loopback HTTP server, separate from the agent API. Login is a
//! WebAuthn passkey assertion and nothing else: there is no password
//! login, and a JSON body that carries a `password` key is refused on
//! every route, before any session is issued. The master password
//! reaches the broker from this UI only through the web unlock
//! ([`unlock`], #131 slice 5b), behind a live session, and only
//! encrypted to a per-attempt daemon key. A session
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
//! | GET | `/owner/approvals` | Pending grant requests, or 401 |
//! | POST | `/owner/approvals/approve` | Approve one (`once` or `per-origin`) |
//! | POST | `/owner/approvals/deny` | Deny one |
//! | GET | `/owner/grants` | Live grants, or 401 |
//! | POST | `/owner/grants/revoke` | Revoke one |
//! | GET | `/owner/audit` | The audit tail, or 401 |
//! | POST | `/owner/panic` | Panic: revoke all grants, then lock |
//! | POST | `/owner/unlock/begin` | Begin a web unlock: a one-attempt key |
//! | POST | `/owner/unlock` | Unlock with the password encrypted to it |
//!
//! The approvals routes (#131 slice 1), the grants routes (slice 2),
//! the panic route (slice 3), the audit tail (slice 4) and the web
//! unlock (slice 5b) need a live session. The audit tail is read-only and unaudited, like the
//! grants list. Ids travel in a JSON body, never in the path. The
//! state-changing calls are POST-only and refused unless the request
//! carries an `Origin` header equal to the configured origin (a
//! missing header is refused too, not only a mismatched one) and a
//! JSON content type, so a cross-site form cannot reach them even
//! without `SameSite`. They call the broker's own approve, deny and
//! revoke on the `web_ui` channel ([`approvals`]), so the REQ-APR-003
//! expiry pass, the rollbacks and the audit entries are the CLI's.
//! Panic is the broker's `panic_lock` and carries no channel: its
//! entries are exactly a CLI panic's. Unlock is the owner socket's
//! own unlock; a failed attempt is `owner_auth_fail`
//! (`unlock_failed`) on the `web_ui` channel. Panic also needs `{"confirm": true}` in the body: the
//! shell's button arms on a first click and only the second sends
//! it, so neither a stray click nor a bare POST can fire it.
//!
//! The same listener serves ntfy redeem (REQ-APR-004, REQ-DEP-006,
//! #136): `GET`/`POST` `/owner/approve/<token>` and
//! `/owner/deny/<token>`. GET confirms and POST decides. There is no
//! session cookie; the token is the credential. A used or expired
//! token is 410. Those paths are absent from the agent API.
//!
//! Responses use fixed error codes only (REQ-API-006). Failed login
//! and enrollment attempts are audited as `owner_auth_fail`.

mod approvals;
mod store;
pub mod unlock;
mod webauthn;

pub use self::approvals::{
    AUDIT_TAIL_LEN, AuditRow, DecideError, NoApprovals, OwnerApprovals, PendingRow, WebGrantKind,
};
pub use self::unlock::OwnerUnlock;

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
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
    ("GET", "/owner/approvals"),
    ("POST", "/owner/approvals/approve"),
    ("POST", "/owner/approvals/deny"),
    ("GET", "/owner/grants"),
    ("POST", "/owner/grants/revoke"),
    ("GET", "/owner/audit"),
    ("POST", "/owner/panic"),
    ("POST", "/owner/unlock/begin"),
    ("POST", "/owner/unlock"),
];

/// Longest request or grant id the owner routes accept. Broker ids
/// are `gr_` or `g_` plus a short random suffix, well under this.
const MAX_ID_LEN: usize = 64;

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
    approvals: Arc<dyn OwnerApprovals>,
    passkeys: Mutex<PasskeyStore>,
    ceremonies: Mutex<Vec<Ceremony>>,
    sessions: Mutex<Vec<Session>>,
    enroll: Mutex<Vec<Enroll>>,
    /// The web unlock backend (slice 5b). Set once, after the daemon
    /// has built its owner ops; unset → the unlock routes answer
    /// `unknown_op`.
    unlocker: OnceLock<Arc<dyn OwnerUnlock>>,
    unlock_attempts: Mutex<Vec<unlock::Attempt>>,
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
    /// `approvals` decides grant requests for the approvals routes
    /// (the daemon passes its broker).
    pub fn open(
        data_dir: &Path,
        rp_id: impl Into<String>,
        origin: impl Into<String>,
        shell: Arc<dyn OwnerShell>,
        audit: Arc<dyn OwnerAudit>,
        approvals: Arc<dyn OwnerApprovals>,
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
            approvals,
            passkeys: Mutex::new(passkeys),
            ceremonies: Mutex::new(Vec::new()),
            sessions: Mutex::new(Vec::new()),
            enroll: Mutex::new(Vec::new()),
            unlocker: OnceLock::new(),
            unlock_attempts: Mutex::new(Vec::new()),
        }))
    }

    /// Attach the web unlock backend. The daemon calls this once,
    /// after its owner ops exist (they hold this UI for
    /// `passkey_enroll`, so the UI cannot take them at
    /// [`Self::open`]). Returns `false` if one was already set.
    pub fn set_unlocker(&self, unlocker: Arc<dyn OwnerUnlock>) -> bool {
        self.unlocker.set(unlocker).is_ok()
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
            "/" | "/enroll" | "/owner/session" | "/owner/approvals" | "/owner/grants"
            | "/owner/audit" => Some(Method::GET),
            "/owner/login/options"
            | "/owner/login/finish"
            | "/owner/register/options"
            | "/owner/register/finish"
            | "/owner/logout"
            | "/owner/approvals/approve"
            | "/owner/approvals/deny"
            | "/owner/grants/revoke"
            | "/owner/panic"
            | "/owner/unlock/begin"
            | "/owner/unlock" => Some(Method::POST),
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
            "/owner/approvals" => self.approvals_list(&req),
            "/owner/approvals/approve" => self.approvals_decide(&req, Decision::Approve),
            "/owner/approvals/deny" => self.approvals_decide(&req, Decision::Deny),
            "/owner/grants" => self.grants_list(&req),
            "/owner/grants/revoke" => self.grants_revoke(&req),
            "/owner/audit" => self.audit_tail(&req),
            "/owner/panic" => self.panic(&req),
            "/owner/unlock/begin" => self.unlock_begin(&req),
            "/owner/unlock" => self.unlock_finish(&req),
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

    fn approvals_list(&self, req: &Incoming) -> Response {
        if !self.session_alive(req.cookie.as_deref()) {
            return respond(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        }
        let rows: Vec<Value> = self
            .approvals
            .pending()
            .into_iter()
            .map(|r| {
                json!({
                    "request_id": r.request_id,
                    "agent_id": r.agent_id,
                    "item_id": r.item_id,
                    "action": r.action,
                    "origin": r.origin,
                    "age_s": r.age_s,
                })
            })
            .collect();
        json_body(
            StatusCode::OK,
            json!({"ok": true, "pending": rows}).to_string(),
            None,
        )
    }

    /// The gate in front of every state-changing owner call
    /// (approve, deny, revoke). The checks run in this order, and each
    /// refusal leaves broker state untouched: `Origin` present and
    /// equal to ours (CSRF), a live session, then a non-empty JSON
    /// body without a password key. The caller then parses its own
    /// body with unknown keys refused.
    fn gate_owner_post(&self, req: &Incoming) -> Option<Response> {
        if req.origin.as_deref() != Some(self.origin.as_str()) {
            self.audit.auth_failed("origin");
            return Some(respond(StatusCode::FORBIDDEN, "origin", None));
        }
        if !self.session_alive(req.cookie.as_deref()) {
            self.audit.auth_failed("no_session");
            return Some(respond(StatusCode::UNAUTHORIZED, "unauthenticated", None));
        }
        if req.body.is_empty() {
            return Some(respond(StatusCode::BAD_REQUEST, "bad_request", None));
        }
        self.precheck_post(req)
    }

    /// Approve or deny one request, behind [`Self::gate_owner_post`]
    /// and a well-formed request id and kind. Only then does the
    /// broker see the call.
    fn approvals_decide(&self, req: &Incoming, decision: Decision) -> Response {
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Ok(body) = serde_json::from_slice::<DecideBody>(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        if !valid_id(&body.request_id) {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        }
        let result = match decision {
            Decision::Approve => {
                let kind = match body.kind.as_deref() {
                    None => WebGrantKind::Once,
                    Some(k) => match WebGrantKind::parse(k) {
                        Some(k) => k,
                        None => return respond(StatusCode::BAD_REQUEST, "bad_kind", None),
                    },
                };
                self.approvals
                    .approve(&body.request_id, kind)
                    .map(|grant_id| json!({"ok": true, "grant_id": grant_id}))
            }
            Decision::Deny => {
                if body.kind.is_some() {
                    return respond(StatusCode::BAD_REQUEST, "bad_request", None);
                }
                self.approvals
                    .deny(&body.request_id)
                    .map(|()| json!({"ok": true}))
            }
        };
        match result {
            Ok(v) => json_body(StatusCode::OK, v.to_string(), None),
            Err(e) => decide_error(e),
        }
    }

    /// The live grants, across agents, in the status view's shape
    /// (SPEC §4 `Grant`). Metadata only; reading it is unaudited, like
    /// `kharon_status`.
    fn grants_list(&self, req: &Incoming) -> Response {
        if !self.session_alive(req.cookie.as_deref()) {
            return respond(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        }
        let grants = self.approvals.grants();
        json_body(
            StatusCode::OK,
            json!({"ok": true, "grants": grants}).to_string(),
            None,
        )
    }

    /// The last [`AUDIT_TAIL_LEN`] audit entries, newest first, as
    /// [`AuditRow`]s (#131 slice 4). Read-only; reading it is
    /// unaudited, like the grants list.
    fn audit_tail(&self, req: &Incoming) -> Response {
        if !self.session_alive(req.cookie.as_deref()) {
            return respond(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        }
        let entries = self.approvals.audit_tail();
        json_body(
            StatusCode::OK,
            json!({"ok": true, "entries": entries}).to_string(),
            None,
        )
    }

    /// Revoke one grant (REQ-REV-001), behind
    /// [`Self::gate_owner_post`] and a well-formed grant id.
    fn grants_revoke(&self, req: &Incoming) -> Response {
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Ok(body) = serde_json::from_slice::<RevokeBody>(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        if !valid_id(&body.grant_id) {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        }
        match self.approvals.revoke(&body.grant_id) {
            Ok(()) => json_body(StatusCode::OK, json!({"ok": true}).to_string(), None),
            Err(e) => decide_error(e),
        }
    }

    /// Panic (REQ-REV-002), behind [`Self::gate_owner_post`] and an
    /// explicit `{"confirm": true}` body. The broker's panic is
    /// revoke-first: every grant goes, then the lock (zeroize and
    /// CDP close ride the lock hook). The session is not revoked —
    /// the shell stays signed in and shows the locked broker, like
    /// after a CLI panic.
    fn panic(&self, req: &Incoming) -> Response {
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Ok(body) = serde_json::from_slice::<PanicBody>(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        if !body.confirm {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        }
        match self.approvals.panic() {
            Ok(()) => json_body(StatusCode::OK, json!({"ok": true}).to_string(), None),
            Err(e) => decide_error(e),
        }
    }

    /// Begin a web unlock (slice 5b): behind [`Self::gate_owner_post`]
    /// and an empty JSON object, mint a single-use attempt bound to
    /// this session and return its public key. No password is
    /// involved yet, so nothing is audited here.
    fn unlock_begin(&self, req: &Incoming) -> Response {
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        if serde_json::from_slice::<EmptyBody>(&req.body).is_err() {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        }
        if self.unlocker.get().is_none() {
            return respond(StatusCode::NOT_IMPLEMENTED, "unknown_op", None);
        }
        let Some(session) = session_hash(req.cookie.as_deref()) else {
            return respond(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        };
        let id = b64url_encode(&random_bytes::<16>());
        let Some(attempt) = unlock::Attempt::new(id.clone(), session) else {
            return respond(StatusCode::INTERNAL_SERVER_ERROR, "error", None);
        };
        let server_pub = b64url_encode(attempt.server_pub());
        let mut guard = self
            .unlock_attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        guard.retain(|a| a.expires > now);
        if guard.len() >= unlock::MAX_ATTEMPTS {
            guard.remove(0);
        }
        guard.push(attempt);
        drop(guard);
        json_body(
            StatusCode::OK,
            json!({"ok": true, "attempt_id": id, "server_pub": server_pub}).to_string(),
            None,
        )
    }

    /// Finish a web unlock: behind [`Self::gate_owner_post`], take
    /// the attempt (single use, this session's, unexpired), decrypt
    /// the password straight into a `Zeroizing` buffer and hand it to
    /// the owner socket's own unlock. Any failed attempt past the
    /// gate — an unknown, stale or foreign attempt, a ciphertext that
    /// does not open, or a wrong password — is `owner_auth_fail`
    /// (`unlock_failed`) and changes nothing. State refusals (already
    /// unlocked, mlock, audit) are not auth failures, as on the
    /// socket.
    fn unlock_finish(&self, req: &Incoming) -> Response {
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Ok(body) = serde_json::from_slice::<UnlockBody>(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(unlocker) = self.unlocker.get() else {
            return respond(StatusCode::NOT_IMPLEMENTED, "unknown_op", None);
        };
        let session = session_hash(req.cookie.as_deref());
        let attempt = {
            let mut guard = self
                .unlock_attempts
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            guard.retain(|a| a.expires > now);
            guard
                .iter()
                .position(|a| ct_eq(a.id.as_bytes(), body.attempt_id.as_bytes()))
                .map(|i| guard.remove(i))
        };
        let password = attempt
            .filter(|a| session.is_some_and(|s| ct_eq(&a.session, &s)))
            .and_then(|a| {
                let client_pub = b64url_decode(&body.client_pub).ok()?;
                let nonce = b64url_decode(&body.nonce).ok()?;
                let ciphertext = b64url_decode(&body.ciphertext).ok()?;
                a.open(&client_pub, &nonce, ciphertext).ok()
            });
        let Some(password) = password else {
            self.audit.auth_failed("unlock_failed");
            return respond(StatusCode::BAD_REQUEST, "unlock_failed", None);
        };
        match unlocker.unlock(password) {
            Ok(()) => json_body(
                StatusCode::OK,
                json!({"ok": true, "locked": false}).to_string(),
                None,
            ),
            Err(e) => {
                if e == crate::owner::OwnerFailure::UnlockFailed {
                    self.audit.auth_failed("unlock_failed");
                }
                respond(unlock_status(&e), e.code(), None)
            }
        }
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

#[derive(Clone, Copy)]
enum Decision {
    Approve,
    Deny,
}

/// Body of an approve or deny call. Unknown keys are refused.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideBody {
    request_id: String,
    #[serde(default)]
    kind: Option<String>,
}

/// Body of a revoke call. Unknown keys are refused.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    grant_id: String,
}

/// Body of `/owner/unlock/begin`: an empty JSON object.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}

/// Body of `/owner/unlock`. Only ciphertext and public values: the
/// password is never a field (base64url, see [`unlock`]).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UnlockBody {
    attempt_id: String,
    client_pub: String,
    nonce: String,
    ciphertext: String,
}

/// HTTP status for an owner unlock refusal.
fn unlock_status(e: &crate::owner::OwnerFailure) -> StatusCode {
    use crate::owner::OwnerFailure as F;
    match e {
        F::UnlockFailed => StatusCode::BAD_REQUEST,
        F::AlreadyUnlocked => StatusCode::CONFLICT,
        F::MlockUnavailable | F::ProcessDumpable | F::AuditFailed => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::NOT_IMPLEMENTED,
    }
}

/// Body of a panic call. Unknown keys are refused, and `confirm`
/// must be present and true: the confirm step is part of the wire
/// contract, not only of the shell page.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PanicBody {
    confirm: bool,
}

/// A request or grant id the owner routes pass to the broker:
/// non-empty, at most [`MAX_ID_LEN`] bytes, ASCII graphic.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_LEN && id.bytes().all(|b| b.is_ascii_graphic())
}

/// A broker refusal as its fixed code and status.
fn decide_error(e: DecideError) -> Response {
    let status = match e {
        DecideError::NotFound => StatusCode::NOT_FOUND,
        DecideError::NotPending => StatusCode::CONFLICT,
        DecideError::InvalidTerms => StatusCode::BAD_REQUEST,
        DecideError::AuditFailed => StatusCode::INTERNAL_SERVER_ERROR,
    };
    respond(status, e.code(), None)
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
    SHELL_PAGE
        .replace("{locked}", locked)
        .replace("{pending}", &pending.to_string())
}

/// The signed-in shell: broker state, the approvals queue (#131
/// slice 1), the live grants (slice 2), the panic button (slice 3,
/// two clicks: arm, then confirm) and the audit tail (slice 4).
/// Rows are built with `textContent` only: origins come from agents
/// (the page the tab was on, or the origin a grant was approved for),
/// so nothing from a row is ever parsed as markup.
const SHELL_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>kharon</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: system-ui, sans-serif; margin: 2.5rem auto; max-width: 48rem; padding: 0 1rem; }
  button { font: inherit; padding: 0.4rem 0.8rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #ccc; vertical-align: top; }
  td.origin { word-break: break-all; }
  .err { min-height: 1.2em; }
</style>
</head>
<body>
<h1>kharon</h1>
<p id="state">signed-in</p>
<p>Broker: <span id="locked">{locked}</span></p>
<form id="unlock" hidden>
<h2>Unlock</h2>
<p>The master password is encrypted in this page to a one-time broker key before it is sent.</p>
<input id="unlock-master" type="password" autocomplete="off" aria-label="Master password" required>
<button id="unlock-go" type="submit">Unlock</button>
</form>
<p>Pending approvals: <span id="pending">{pending}</span></p>
<h2>Approvals</h2>
<p id="empty">Nothing is waiting.</p>
<table id="queue" hidden>
<thead><tr><th>Agent</th><th>Action</th><th>Origin</th><th>Item</th><th>Age</th><th></th></tr></thead>
<tbody id="rows"></tbody>
</table>
<h2>Grants</h2>
<p id="grants-empty">No live grants.</p>
<table id="grants" hidden>
<thead><tr><th>Agent</th><th>Scope</th><th>Origin</th><th>Actions</th><th>Uses</th><th>Expires</th><th></th></tr></thead>
<tbody id="grant-rows"></tbody>
</table>
<h2>Audit</h2>
<p id="audit-empty">No audit entries yet.</p>
<table id="audit" hidden>
<thead><tr><th>Seq</th><th>Time</th><th>Event</th><th>Agent</th><th>Origin</th><th>Result</th><th>Channel</th></tr></thead>
<tbody id="audit-rows"></tbody>
</table>
<h2>Panic</h2>
<p>Lock the broker and revoke every grant. Fills stop until the next unlock.</p>
<button id="panic" type="button">Panic</button>
<p id="err" class="err" role="alert"></p>
<button id="signout" type="button">Sign out</button>
<script>
function cell(text, cls) {
  const td = document.createElement("td");
  td.textContent = text;
  if (cls) td.className = cls;
  return td;
}
async function decide(path, body) {
  const err = document.getElementById("err");
  err.textContent = "";
  const r = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (r.status === 401) { location.assign("/"); return false; }
  if (!r.ok) {
    let code = "error";
    try { code = (await r.json()).error || code; } catch (e) {}
    err.textContent = "Not done: " + code;
  }
  await window.kharonRefresh();
  return r.ok;
}
function button(label, onClick) {
  const b = document.createElement("button");
  b.type = "button";
  b.textContent = label;
  b.addEventListener("click", onClick);
  return b;
}
window.kharonDecide = decide;
async function refreshGrants() {
  const r = await fetch("/owner/grants", { credentials: "same-origin" });
  if (r.status === 401) { location.assign("/"); return; }
  if (!r.ok) return;
  const data = await r.json();
  const rows = document.getElementById("grant-rows");
  rows.replaceChildren();
  for (const g of data.grants) {
    const tr = document.createElement("tr");
    tr.dataset.grantId = g.id;
    const scope = g.item_id ? "item " + g.item_id : "collection " + g.collection_id;
    const uses = g.max_uses === undefined ? String(g.uses) : g.uses + " / " + g.max_uses;
    tr.append(cell(g.agent_id), cell(scope), cell(g.origin, "origin"), cell(g.actions.join(", ")), cell(uses), cell(g.expires_at));
    const actions = document.createElement("td");
    actions.append(button("Revoke", () => decide("/owner/grants/revoke", { grant_id: g.id })));
    tr.append(actions);
    rows.append(tr);
  }
  document.getElementById("grants").hidden = data.grants.length === 0;
  document.getElementById("grants-empty").hidden = data.grants.length !== 0;
}
async function refreshAudit() {
  const r = await fetch("/owner/audit", { credentials: "same-origin" });
  if (r.status === 401) { location.assign("/"); return; }
  if (!r.ok) return;
  const data = await r.json();
  const rows = document.getElementById("audit-rows");
  rows.replaceChildren();
  for (const e of data.entries) {
    const tr = document.createElement("tr");
    tr.dataset.seq = String(e.seq);
    const result = e.detail_code ? (e.result || "") + " (" + e.detail_code + ")" : (e.result || "");
    tr.append(cell(String(e.seq)), cell(e.ts), cell(e.event), cell(e.agent_id || ""),
      cell(e.live_origin || e.origin || "", "origin"), cell(result), cell(e.channel || ""));
    rows.append(tr);
  }
  document.getElementById("audit").hidden = data.entries.length === 0;
  document.getElementById("audit-empty").hidden = data.entries.length !== 0;
}
window.kharonRefresh = async function () {
  await refreshGrants();
  await refreshAudit();
  const r = await fetch("/owner/approvals", { credentials: "same-origin" });
  if (r.status === 401) { location.assign("/"); return; }
  if (!r.ok) return;
  const data = await r.json();
  const rows = document.getElementById("rows");
  rows.replaceChildren();
  for (const p of data.pending) {
    const tr = document.createElement("tr");
    tr.dataset.requestId = p.request_id;
    tr.append(cell(p.agent_id), cell(p.action), cell(p.origin, "origin"), cell(p.item_id), cell(p.age_s + " s"));
    const actions = document.createElement("td");
    actions.append(
      button("Approve once", () => decide("/owner/approvals/approve", { request_id: p.request_id, kind: "once" })),
      " ",
      button("Approve for 1 h", () => decide("/owner/approvals/approve", { request_id: p.request_id, kind: "per-origin" })),
      " ",
      button("Deny", () => decide("/owner/approvals/deny", { request_id: p.request_id })),
    );
    tr.append(actions);
    rows.append(tr);
  }
  document.getElementById("pending").textContent = String(data.pending.length);
  document.getElementById("queue").hidden = data.pending.length === 0;
  document.getElementById("empty").hidden = data.pending.length !== 0;
};
const panicButton = document.getElementById("panic");
let panicArmed = false;
let panicTimer = null;
function disarmPanic() {
  panicArmed = false;
  if (panicTimer !== null) { clearTimeout(panicTimer); panicTimer = null; }
  panicButton.textContent = "Panic";
}
panicButton.addEventListener("click", async () => {
  if (!panicArmed) {
    panicArmed = true;
    panicButton.textContent = "Confirm panic: lock and revoke all";
    panicTimer = setTimeout(disarmPanic, 10000);
    return;
  }
  disarmPanic();
  if (await decide("/owner/panic", { confirm: true })) {
    setLocked(true);
  }
});
function setLocked(locked) {
  document.getElementById("locked").textContent = locked ? "locked" : "unlocked";
  document.getElementById("unlock").hidden = !locked;
}
function b64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64u(s) {
  const t = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(t, (c) => c.charCodeAt(0));
}
function joinBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}
// The web unlock wire format (owner_ui::unlock): ECDH P-256 to the
// attempt's key, HKDF-SHA256 (empty salt, info = INFO || server_pub
// || client_pub), AES-256-GCM with aad = INFO. Only ciphertext and
// public values leave the page.
async function sealMaster(serverPubB64, secret) {
  const enc = new TextEncoder();
  const info = enc.encode("kharon web unlock v1");
  const serverPub = unb64u(serverPubB64);
  const theirs = await crypto.subtle.importKey("raw", serverPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const mine = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const clientPub = new Uint8Array(await crypto.subtle.exportKey("raw", mine.publicKey));
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, mine.privateKey, 256);
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: joinBytes(info, serverPub, clientPub) },
    ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(secret);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: info }, key, plain));
  plain.fill(0);
  return { client_pub: b64u(clientPub), nonce: b64u(nonce), ciphertext: b64u(sealed) };
}
document.getElementById("unlock").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const field = document.getElementById("unlock-master");
  const err = document.getElementById("err");
  err.textContent = "";
  const secret = field.value;
  field.value = "";
  const post = (path, body) => fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const begun = await post("/owner/unlock/begin", {});
  if (begun.status === 401) { location.assign("/"); return; }
  if (!begun.ok) { err.textContent = "Not done: " + ((await begun.json()).error || "error"); return; }
  const attempt = await begun.json();
  const sealed = await sealMaster(attempt.server_pub, secret);
  const r = await post("/owner/unlock", { attempt_id: attempt.attempt_id, ...sealed });
  if (r.status === 401) { location.assign("/"); return; }
  if (!r.ok) {
    let code = "error";
    try { code = (await r.json()).error || code; } catch (e) {}
    err.textContent = "Not done: " + code;
    return;
  }
  setLocked(false);
  await window.kharonRefresh();
});
setLocked(document.getElementById("locked").textContent === "locked");
document.getElementById("signout").addEventListener("click", async () => {
  await fetch("/owner/logout", { method: "POST", credentials: "same-origin" });
  location.assign("/");
});
window.kharonRefresh();
setInterval(window.kharonRefresh, 5000);
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_apr_005_routes_have_no_password_login() {
        // No route is a password route. The only unlock routes are
        // the slice 5b pair, which need a live passkey session and
        // carry ciphertext, never a `password` field (see
        // `unlock_*` below).
        assert!(
            ROUTES.iter().all(|(method, path)| {
                let blob = format!("{method} {path}").to_ascii_lowercase();
                !blob.contains("password")
                    && (!blob.contains("unlock")
                        || blob == "post /owner/unlock/begin"
                        || blob == "post /owner/unlock")
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
            Arc::new(NoApprovals),
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
            Arc::new(NoApprovals),
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
            Arc::new(NoApprovals),
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

    /// Records every decision it is asked for; `gr_gone` is not
    /// pending, anything else is.
    /// Fake web unlock backend: accepts one password.
    #[derive(Default)]
    struct FakeUnlock {
        seen: Mutex<Vec<String>>,
        already: std::sync::atomic::AtomicBool,
    }

    impl OwnerUnlock for FakeUnlock {
        fn unlock(&self, password: Zeroizing<String>) -> Result<(), crate::owner::OwnerFailure> {
            self.seen.lock().unwrap().push(password.to_string());
            if self.already.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(crate::owner::OwnerFailure::AlreadyUnlocked);
            }
            if password.as_str() == "right horse" {
                Ok(())
            } else {
                Err(crate::owner::OwnerFailure::UnlockFailed)
            }
        }
    }

    #[derive(Default)]
    struct FakeApprovals {
        calls: Mutex<Vec<String>>,
        panic_fails: std::sync::atomic::AtomicBool,
    }

    impl OwnerApprovals for FakeApprovals {
        fn pending(&self) -> Vec<PendingRow> {
            vec![PendingRow {
                request_id: "gr_1".into(),
                agent_id: "alpha".into(),
                item_id: "item-1".into(),
                action: "fill",
                origin: "https://login.example.com".into(),
                age_s: 7,
            }]
        }

        fn approve(&self, request_id: &str, kind: WebGrantKind) -> Result<String, DecideError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("approve {request_id} {kind:?}"));
            if request_id == "gr_gone" {
                return Err(DecideError::NotPending);
            }
            Ok("g_1".into())
        }

        fn deny(&self, request_id: &str) -> Result<(), DecideError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("deny {request_id}"));
            if request_id == "gr_gone" {
                return Err(DecideError::NotPending);
            }
            Ok(())
        }

        fn grants(&self) -> Vec<crate::api::grant::GrantView> {
            vec![crate::api::grant::GrantView {
                id: "g_1".into(),
                agent_id: "alpha".into(),
                item_id: Some("item-1".into()),
                collection_id: None,
                origin: "login.example.com".into(),
                actions: vec![crate::api::grant::GrantAction::Fill],
                expires_at: "2026-11-08T02:00:00Z".into(),
                max_uses: Some(1),
                uses: 0,
                created_by_channel: crate::api::grant::Channel::WebUi,
            }]
        }

        /// `g_gone` is not found and `g_audit` fails its audit append;
        /// anything else is revoked.
        fn revoke(&self, grant_id: &str) -> Result<(), DecideError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("revoke {grant_id}"));
            match grant_id {
                "g_gone" => Err(DecideError::NotFound),
                "g_audit" => Err(DecideError::AuditFailed),
                _ => Ok(()),
            }
        }

        /// One web revoke, newest first, built from a full [`Entry`]
        /// that also carries an item name in both forms, so the
        /// projection is what gets tested.
        fn audit_tail(&self) -> Vec<AuditRow> {
            use crate::audit::{Entry, Event};
            let mut e = Entry::new(Event::GrantRevoke)
                .agent_id("alpha")
                .item_id("item-1")
                .item_name("Bank of Example")
                .grant_id("g_1")
                .channel("web_ui")
                .result("revoked");
            e.seq = 7;
            e.ts = "2026-11-08T02:00:00Z".into();
            e.item_name_hash = Some("ab".repeat(32));
            e.log_id = "log-1".into();
            vec![AuditRow::from(&e)]
        }

        fn panic(&self) -> Result<(), DecideError> {
            self.calls.lock().unwrap().push("panic".to_owned());
            if self.panic_fails.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(DecideError::AuditFailed);
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FailCodes(Mutex<Vec<&'static str>>);

    impl OwnerAudit for FailCodes {
        fn auth_failed(&self, detail: &'static str) {
            self.0.lock().unwrap().push(detail);
        }
    }

    const ORIGIN: &str = "http://localhost:9";

    struct ApprovalsRig {
        ui: Arc<OwnerUi>,
        fake: Arc<FakeApprovals>,
        audit: Arc<FailCodes>,
        cookie: String,
        _dir: tempfile::TempDir,
    }

    impl ApprovalsRig {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(FakeApprovals::default());
            let audit = Arc::new(FailCodes::default());
            let ui = OwnerUi::open(
                dir.path(),
                "localhost",
                ORIGIN,
                Arc::new(StaticShell(ShellView {
                    locked: false,
                    pending: 1,
                })),
                audit.clone(),
                fake.clone(),
            )
            .unwrap();
            let cookie = ui.issue_session().split(';').next().unwrap().to_owned();
            Self {
                ui,
                fake,
                audit,
                cookie,
                _dir: dir,
            }
        }

        fn calls(&self) -> Vec<String> {
            self.fake.calls.lock().unwrap().clone()
        }

        fn send(
            &self,
            method: Method,
            path: &str,
            cookie: bool,
            origin: Option<&str>,
            content_type: Option<&str>,
            body: &str,
        ) -> (StatusCode, String) {
            let response = self.ui.dispatch(Incoming {
                method,
                path: path.into(),
                cookie: cookie.then(|| self.cookie.clone()),
                origin: origin.map(str::to_owned),
                authorization: None,
                content_type: content_type.map(str::to_owned),
                body: body.as_bytes().to_vec(),
            });
            let status = response.status();
            let bytes = futures_body(response);
            (status, bytes)
        }

        fn post(&self, path: &str, body: &str) -> (StatusCode, String) {
            self.send(
                Method::POST,
                path,
                true,
                Some(ORIGIN),
                Some("application/json"),
                body,
            )
        }
    }

    fn futures_body(response: Response) -> String {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let bytes = rt
            .block_on(axum::body::to_bytes(response.into_body(), MAX_BODY))
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn approvals_routes_are_listed_and_are_not_password_routes() {
        for route in [
            ("GET", "/owner/approvals"),
            ("POST", "/owner/approvals/approve"),
            ("POST", "/owner/approvals/deny"),
        ] {
            assert!(ROUTES.contains(&route), "{route:?} missing from ROUTES");
        }
        let shell = shell_page("unlocked", 0).to_ascii_lowercase();
        // The signed-in shell's one secret field is the slice 5b
        // unlock form; its value is only ever sealed, never a JSON
        // key of its own.
        assert_eq!(shell.matches(r#"type="password""#).count(), 1);
        assert!(shell.contains(r#"id="unlock-master" type="password""#));
        assert!(!shell.contains("password:") && !shell.contains(r#""password":"#));
        assert!(!shell.contains("innerhtml"), "rows must use textContent");
    }

    #[test]
    fn approvals_need_a_session() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(Method::GET, "/owner/approvals", false, None, None, "");
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        for path in ["/owner/approvals/approve", "/owner/approvals/deny"] {
            let (status, body) = rig.send(
                Method::POST,
                path,
                false,
                Some(ORIGIN),
                Some("application/json"),
                r#"{"request_id":"gr_1"}"#,
            );
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {body}");
            assert!(body.contains("unauthenticated"), "{body}");
        }
        rig.ui.expire_sessions();
        let (status, _) = rig.post("/owner/approvals/approve", r#"{"request_id":"gr_1"}"#);
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "an expired session decided"
        );
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
        assert_eq!(
            *rig.audit.0.lock().unwrap(),
            ["no_session", "no_session", "no_session"]
        );

        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(Method::GET, "/owner/approvals", true, None, None, "");
        assert_eq!(status, StatusCode::OK, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["pending"][0]["request_id"], "gr_1");
        assert_eq!(v["pending"][0]["origin"], "https://login.example.com");
        assert_eq!(v["pending"][0]["age_s"], 7);
    }

    #[test]
    fn approvals_decisions_are_post_only_and_the_list_is_get_only() {
        let rig = ApprovalsRig::new();
        for path in ["/owner/approvals/approve", "/owner/approvals/deny"] {
            for method in [Method::GET, Method::PUT, Method::DELETE] {
                let (status, body) = rig.send(
                    method.clone(),
                    path,
                    true,
                    Some(ORIGIN),
                    Some("application/json"),
                    r#"{"request_id":"gr_1"}"#,
                );
                assert_eq!(
                    status,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path}: {body}"
                );
            }
        }
        let (status, _) = rig.post("/owner/approvals", r#"{"request_id":"gr_1"}"#);
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }

    #[test]
    fn approvals_decisions_need_our_origin() {
        let rig = ApprovalsRig::new();
        for origin in [
            None,
            Some("https://evil.example"),
            Some("null"),
            Some("http://localhost:9/"),
        ] {
            for path in ["/owner/approvals/approve", "/owner/approvals/deny"] {
                let (status, body) = rig.send(
                    Method::POST,
                    path,
                    true,
                    origin,
                    Some("application/json"),
                    r#"{"request_id":"gr_1"}"#,
                );
                assert_eq!(status, StatusCode::FORBIDDEN, "{origin:?} {path}: {body}");
                assert!(body.contains("\"origin\""), "{body}");
            }
        }
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
        assert!(rig.audit.0.lock().unwrap().iter().all(|c| *c == "origin"));
    }

    #[test]
    fn approvals_decisions_refuse_form_posts_and_odd_bodies() {
        let rig = ApprovalsRig::new();
        // What a cross-site <form> can send: no JSON content type.
        for (ctype, body) in [
            (Some("application/x-www-form-urlencoded"), "request_id=gr_1"),
            (Some("text/plain"), r#"{"request_id":"gr_1"}"#),
            (Some("multipart/form-data; boundary=x"), "--x--"),
            (None, r#"{"request_id":"gr_1"}"#),
            (Some("application/json"), ""),
            (Some("application/json"), "[]"),
            (
                Some("application/json"),
                r#"{"request_id":"gr_1","extra":1}"#,
            ),
            (Some("application/json"), r#"{"request_id":""}"#),
            (Some("application/json"), r#"{"request_id":"gr 1"}"#),
        ] {
            for path in ["/owner/approvals/approve", "/owner/approvals/deny"] {
                let (status, out) = rig.send(Method::POST, path, true, Some(ORIGIN), ctype, body);
                assert_eq!(
                    status,
                    StatusCode::BAD_REQUEST,
                    "{ctype:?} {body:?} {path}: {out}"
                );
            }
        }
        let long = format!(r#"{{"request_id":"{}"}}"#, "a".repeat(MAX_ID_LEN + 1));
        let (status, _) = rig.post("/owner/approvals/approve", &long);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, out) = rig.post(
            "/owner/approvals/approve",
            r#"{"request_id":"gr_1","kind":"standing"}"#,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
        assert!(out.contains("bad_kind"), "{out}");
        let (status, out) = rig.post(
            "/owner/approvals/deny",
            r#"{"request_id":"gr_1","kind":"once"}"#,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
        let (status, out) = rig.post(
            "/owner/approvals/approve",
            r#"{"request_id":"gr_1","password":"hunter2"}"#,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            out.contains("password_rejected") && !out.contains("hunter2"),
            "{out}"
        );
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }

    #[test]
    fn approvals_decisions_reach_the_backend_and_map_its_refusals() {
        let rig = ApprovalsRig::new();
        let (status, out) = rig.post("/owner/approvals/approve", r#"{"request_id":"gr_1"}"#);
        assert_eq!(status, StatusCode::OK, "{out}");
        assert!(out.contains("\"grant_id\":\"g_1\""), "{out}");
        let (status, _) = rig.post(
            "/owner/approvals/approve",
            r#"{"request_id":"gr_2","kind":"per-origin"}"#,
        );
        assert_eq!(status, StatusCode::OK);
        let (status, _) = rig.post("/owner/approvals/deny", r#"{"request_id":"gr_3"}"#);
        assert_eq!(status, StatusCode::OK);
        let (status, out) = rig.post("/owner/approvals/approve", r#"{"request_id":"gr_gone"}"#);
        assert_eq!(status, StatusCode::CONFLICT, "{out}");
        assert!(out.contains("not_pending"), "{out}");
        let (status, _) = rig.post("/owner/approvals/deny", r#"{"request_id":"gr_gone"}"#);
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            rig.calls(),
            [
                "approve gr_1 Once",
                "approve gr_2 PerOrigin",
                "deny gr_3",
                "approve gr_gone Once",
                "deny gr_gone",
            ]
        );
    }

    // ---- #131 slice 2: grants ----

    #[test]
    fn grants_routes_are_listed() {
        for route in [("GET", "/owner/grants"), ("POST", "/owner/grants/revoke")] {
            assert!(ROUTES.contains(&route), "{route:?} missing from ROUTES");
        }
        let shell = shell_page("unlocked", 0);
        assert!(shell.contains("/owner/grants/revoke"), "no revoke button");
    }

    #[test]
    fn grants_need_a_session() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(Method::GET, "/owner/grants", false, None, None, "");
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        let (status, body) = rig.send(
            Method::POST,
            "/owner/grants/revoke",
            false,
            Some(ORIGIN),
            Some("application/json"),
            r#"{"grant_id":"g_1"}"#,
        );
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(*rig.audit.0.lock().unwrap(), ["no_session"]);
        rig.ui.expire_sessions();
        let (status, _) = rig.post("/owner/grants/revoke", r#"{"grant_id":"g_1"}"#);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = rig.send(Method::GET, "/owner/grants", true, None, None, "");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }

    #[test]
    fn grants_list_renders_the_status_view() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(Method::GET, "/owner/grants", true, None, None, "");
        assert_eq!(status, StatusCode::OK, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ok"], true);
        let g = &v["grants"][0];
        assert_eq!(g["id"], "g_1");
        assert_eq!(g["agent_id"], "alpha");
        assert_eq!(g["item_id"], "item-1");
        assert!(g.get("collection_id").is_none(), "{g}");
        assert_eq!(g["origin"], "login.example.com");
        assert_eq!(g["actions"], json!(["fill"]));
        assert_eq!(g["max_uses"], 1);
        assert_eq!(g["uses"], 0);
        assert_eq!(g["created_by_channel"], "web_ui");
    }

    #[test]
    fn grants_revoke_is_post_only_and_the_list_is_get_only() {
        let rig = ApprovalsRig::new();
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            let (status, _) = rig.send(
                method.clone(),
                "/owner/grants/revoke",
                true,
                Some(ORIGIN),
                Some("application/json"),
                r#"{"grant_id":"g_1"}"#,
            );
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        }
        let (status, _) = rig.post("/owner/grants", r#"{"grant_id":"g_1"}"#);
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }

    #[test]
    fn grants_revoke_needs_our_origin() {
        let rig = ApprovalsRig::new();
        for origin in [
            None,
            Some("https://evil.example"),
            Some("null"),
            Some("http://localhost:9/"),
        ] {
            let (status, body) = rig.send(
                Method::POST,
                "/owner/grants/revoke",
                true,
                origin,
                Some("application/json"),
                r#"{"grant_id":"g_1"}"#,
            );
            assert_eq!(status, StatusCode::FORBIDDEN, "{origin:?}: {body}");
        }
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
        assert!(rig.audit.0.lock().unwrap().iter().all(|c| *c == "origin"));
    }

    #[test]
    fn grants_revoke_refuses_form_posts_and_odd_bodies() {
        let rig = ApprovalsRig::new();
        let long = format!(r#"{{"grant_id":"{}"}}"#, "a".repeat(MAX_ID_LEN + 1));
        for (ctype, body) in [
            (Some("application/x-www-form-urlencoded"), "grant_id=g_1"),
            (Some("text/plain"), r#"{"grant_id":"g_1"}"#),
            (Some("multipart/form-data; boundary=x"), "--x--"),
            (None, r#"{"grant_id":"g_1"}"#),
            (Some("application/json"), ""),
            (Some("application/json"), "[]"),
            (Some("application/json"), r#"{"grant_id":"g_1","extra":1}"#),
            (Some("application/json"), r#"{"request_id":"g_1"}"#),
            (Some("application/json"), r#"{"grant_id":""}"#),
            (Some("application/json"), r#"{"grant_id":"g 1"}"#),
            (Some("application/json"), long.as_str()),
        ] {
            let (status, out) = rig.send(
                Method::POST,
                "/owner/grants/revoke",
                true,
                Some(ORIGIN),
                ctype,
                body,
            );
            assert_eq!(status, StatusCode::BAD_REQUEST, "{ctype:?} {body:?}: {out}");
        }
        let (status, out) = rig.post(
            "/owner/grants/revoke",
            r#"{"grant_id":"g_1","password":"hunter2"}"#,
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            out.contains("password_rejected") && !out.contains("hunter2"),
            "{out}"
        );
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }

    #[test]
    fn grants_revoke_reaches_the_backend_and_maps_its_refusals() {
        let rig = ApprovalsRig::new();
        let (status, out) = rig.post("/owner/grants/revoke", r#"{"grant_id":"g_1"}"#);
        assert_eq!(status, StatusCode::OK, "{out}");
        let (status, out) = rig.post("/owner/grants/revoke", r#"{"grant_id":"g_gone"}"#);
        assert_eq!(status, StatusCode::NOT_FOUND, "{out}");
        assert!(out.contains("not_found"), "{out}");
        let (status, out) = rig.post("/owner/grants/revoke", r#"{"grant_id":"g_audit"}"#);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{out}");
        assert!(out.contains("audit_failed"), "{out}");
        assert_eq!(
            rig.calls(),
            ["revoke g_1", "revoke g_gone", "revoke g_audit"]
        );
    }

    // ---- #131 slice 4: audit tail ----

    #[test]
    fn audit_route_is_listed_and_on_the_shell() {
        assert!(ROUTES.contains(&("GET", "/owner/audit")));
        let shell = shell_page("unlocked", 0);
        assert!(shell.contains("/owner/audit"), "no audit fetch");
        assert!(shell.contains("id=\"audit-rows\""), "no audit table");
    }

    #[test]
    fn audit_tail_needs_a_session() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(Method::GET, "/owner/audit", false, None, None, "");
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert!(!body.contains("g_1"), "{body}");
    }

    #[test]
    fn audit_tail_is_get_only() {
        let rig = ApprovalsRig::new();
        let (status, _) = rig.post("/owner/audit", "{}");
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        for method in [Method::PUT, Method::DELETE] {
            let (status, _) = rig.send(method.clone(), "/owner/audit", true, None, None, "");
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        }
    }

    #[test]
    fn audit_tail_renders_the_projection_without_item_names() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(Method::GET, "/owner/audit", true, None, None, "");
        assert_eq!(status, StatusCode::OK, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ok"], true);
        let e = &v["entries"][0];
        assert_eq!(e["seq"], 7);
        assert_eq!(e["ts"], "2026-11-08T02:00:00Z");
        assert_eq!(e["event"], "grant_revoke");
        assert_eq!(e["agent_id"], "alpha");
        assert_eq!(e["item_id"], "item-1");
        assert_eq!(e["grant_id"], "g_1");
        assert_eq!(e["channel"], "web_ui");
        assert_eq!(e["result"], "revoked");
        for absent in [
            "item_name",
            "item_name_hash",
            "prev_hash",
            "hash",
            "log_id",
            "origin",
            "detail_code",
        ] {
            assert!(e.get(absent).is_none(), "{absent} in {e}");
        }
        assert!(!body.contains("Bank of Example"), "{body}");
        assert!(!body.contains(&"ab".repeat(32)), "{body}");
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }
    // ---- #131 slice 3: panic ----

    #[test]
    fn panic_route_is_listed() {
        assert!(
            ROUTES.contains(&("POST", "/owner/panic")),
            "panic route missing from ROUTES"
        );
        let shell = shell_page("unlocked", 0);
        assert!(shell.contains("/owner/panic"), "no panic button");
        assert!(shell.contains("confirm: true"), "button sends no confirm");
    }

    #[test]
    fn panic_needs_a_session() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(
            Method::POST,
            "/owner/panic",
            false,
            Some(ORIGIN),
            Some("application/json"),
            r#"{"confirm":true}"#,
        );
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(*rig.audit.0.lock().unwrap(), ["no_session"]);
        rig.ui.expire_sessions();
        let (status, _) = rig.post("/owner/panic", r#"{"confirm":true}"#);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }

    #[test]
    fn panic_is_post_only() {
        let rig = ApprovalsRig::new();
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            let (status, _) = rig.send(
                method.clone(),
                "/owner/panic",
                true,
                Some(ORIGIN),
                Some("application/json"),
                r#"{"confirm":true}"#,
            );
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        }
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }

    #[test]
    fn panic_needs_our_origin() {
        let rig = ApprovalsRig::new();
        for origin in [
            None,
            Some("https://evil.example"),
            Some("null"),
            Some("http://localhost:9/"),
        ] {
            let (status, body) = rig.send(
                Method::POST,
                "/owner/panic",
                true,
                origin,
                Some("application/json"),
                r#"{"confirm":true}"#,
            );
            assert_eq!(status, StatusCode::FORBIDDEN, "{origin:?}: {body}");
        }
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
        assert!(rig.audit.0.lock().unwrap().iter().all(|c| *c == "origin"));
    }

    #[test]
    fn panic_refuses_form_posts_and_unconfirmed_bodies() {
        let rig = ApprovalsRig::new();
        for (ctype, body) in [
            (Some("application/x-www-form-urlencoded"), "confirm=true"),
            (Some("text/plain"), r#"{"confirm":true}"#),
            (Some("multipart/form-data; boundary=x"), "--x--"),
            (None, r#"{"confirm":true}"#),
            (Some("application/json"), ""),
            (Some("application/json"), "[]"),
            (Some("application/json"), "{}"),
            (Some("application/json"), r#"{"confirm":false}"#),
            (Some("application/json"), r#"{"confirm":"true"}"#),
            (Some("application/json"), r#"{"confirm":true,"extra":1}"#),
        ] {
            let (status, out) = rig.send(
                Method::POST,
                "/owner/panic",
                true,
                Some(ORIGIN),
                ctype,
                body,
            );
            assert_eq!(status, StatusCode::BAD_REQUEST, "{ctype:?} {body:?}: {out}");
        }
        let (status, out) = rig.post("/owner/panic", r#"{"confirm":true,"password":"hunter2"}"#);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            out.contains("password_rejected") && !out.contains("hunter2"),
            "{out}"
        );
        assert!(rig.calls().is_empty(), "{:?}", rig.calls());
    }

    #[test]
    fn panic_reaches_the_backend_and_maps_its_refusals() {
        let rig = ApprovalsRig::new();
        let (status, out) = rig.post("/owner/panic", r#"{"confirm":true}"#);
        assert_eq!(status, StatusCode::OK, "{out}");
        assert!(out.contains("\"ok\":true"), "{out}");
        rig.fake
            .panic_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (status, out) = rig.post("/owner/panic", r#"{"confirm":true}"#);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{out}");
        assert!(out.contains("audit_failed"), "{out}");
        assert_eq!(rig.calls(), ["panic", "panic"]);
    }

    // ---- #131 slice 5b: web unlock ----

    impl ApprovalsRig {
        fn with_unlock() -> (Self, Arc<FakeUnlock>) {
            let rig = Self::new();
            let unlock = Arc::new(FakeUnlock::default());
            assert!(rig.ui.set_unlocker(unlock.clone()));
            (rig, unlock)
        }

        fn begin(&self) -> (String, Vec<u8>) {
            let (status, out) = self.post("/owner/unlock/begin", "{}");
            assert_eq!(status, StatusCode::OK, "{out}");
            let v: Value = serde_json::from_str(&out).unwrap();
            let id = v["attempt_id"].as_str().unwrap().to_owned();
            let key = b64url_decode(v["server_pub"].as_str().unwrap()).unwrap();
            (id, key)
        }

        fn sealed(id: &str, server_pub: &[u8], password: &str) -> String {
            let (client, nonce, ct) = unlock::seal_password(server_pub, password).unwrap();
            json!({
                "attempt_id": id,
                "client_pub": b64url_encode(&client),
                "nonce": b64url_encode(&nonce),
                "ciphertext": b64url_encode(&ct),
            })
            .to_string()
        }
    }

    #[test]
    fn unlock_routes_are_listed_and_on_the_shell() {
        assert!(ROUTES.contains(&("POST", "/owner/unlock/begin")));
        assert!(ROUTES.contains(&("POST", "/owner/unlock")));
        let shell = shell_page("locked", 0);
        assert!(shell.contains("/owner/unlock/begin") && shell.contains("/owner/unlock\""));
        assert!(
            shell.contains("kharon web unlock v1"),
            "page and daemon must agree"
        );
        assert_eq!(unlock::INFO, b"kharon web unlock v1");
    }

    #[test]
    fn unlock_round_trip_reaches_the_backend_with_the_plaintext() {
        let (rig, unlock) = ApprovalsRig::with_unlock();
        let (id, key) = rig.begin();
        let body = ApprovalsRig::sealed(&id, &key, "right horse");
        assert!(
            !body.contains("right horse"),
            "the wire carries ciphertext only"
        );
        let (status, out) = rig.post("/owner/unlock", &body);
        assert_eq!(status, StatusCode::OK, "{out}");
        assert!(out.contains("\"locked\":false"), "{out}");
        assert_eq!(*unlock.seen.lock().unwrap(), ["right horse"]);
        assert!(rig.audit.0.lock().unwrap().is_empty());
    }

    #[test]
    fn unlock_wrong_password_is_audited_and_refused() {
        let (rig, unlock) = ApprovalsRig::with_unlock();
        let (id, key) = rig.begin();
        let (status, out) = rig.post("/owner/unlock", &ApprovalsRig::sealed(&id, &key, "wrong"));
        assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
        assert!(
            out.contains("unlock_failed") && !out.contains("wrong"),
            "{out}"
        );
        assert_eq!(*rig.audit.0.lock().unwrap(), ["unlock_failed"]);
        assert_eq!(unlock.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn unlock_state_refusals_are_not_auth_failures() {
        let (rig, unlock) = ApprovalsRig::with_unlock();
        unlock
            .already
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (id, key) = rig.begin();
        let (status, out) = rig.post(
            "/owner/unlock",
            &ApprovalsRig::sealed(&id, &key, "right horse"),
        );
        assert_eq!(status, StatusCode::CONFLICT, "{out}");
        assert!(out.contains("already_unlocked"), "{out}");
        assert!(rig.audit.0.lock().unwrap().is_empty());
    }

    #[test]
    fn unlock_attempt_is_single_use_and_session_bound() {
        let (rig, unlock) = ApprovalsRig::with_unlock();
        let (id, key) = rig.begin();
        let body = ApprovalsRig::sealed(&id, &key, "right horse");
        // Another live session cannot spend this session's attempt,
        // and trying burns it.
        let other = rig.ui.issue_session().split(';').next().unwrap().to_owned();
        let response = rig.ui.dispatch(Incoming {
            method: Method::POST,
            path: "/owner/unlock".into(),
            cookie: Some(other),
            origin: Some(ORIGIN.into()),
            authorization: None,
            content_type: Some("application/json".into()),
            body: body.as_bytes().to_vec(),
        });
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let (status, _) = rig.post("/owner/unlock", &body);
        assert_eq!(status, StatusCode::BAD_REQUEST, "attempt was not burned");
        // A fresh attempt works once, then is gone.
        let (id, key) = rig.begin();
        let body = ApprovalsRig::sealed(&id, &key, "right horse");
        assert_eq!(rig.post("/owner/unlock", &body).0, StatusCode::OK);
        assert_eq!(rig.post("/owner/unlock", &body).0, StatusCode::BAD_REQUEST);
        assert_eq!(*unlock.seen.lock().unwrap(), ["right horse"]);
        assert_eq!(
            *rig.audit.0.lock().unwrap(),
            ["unlock_failed", "unlock_failed", "unlock_failed"]
        );
    }

    #[test]
    fn unlock_attempt_expires() {
        let (rig, unlock) = ApprovalsRig::with_unlock();
        let (id, key) = rig.begin();
        for a in rig.ui.unlock_attempts.lock().unwrap().iter_mut() {
            a.expires = Instant::now();
        }
        let (status, _) = rig.post(
            "/owner/unlock",
            &ApprovalsRig::sealed(&id, &key, "right horse"),
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(unlock.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn unlock_keeps_at_most_a_few_attempts() {
        let (rig, unlock) = ApprovalsRig::with_unlock();
        let (first, key) = rig.begin();
        for _ in 0..unlock::MAX_ATTEMPTS {
            rig.begin();
        }
        assert_eq!(
            rig.ui.unlock_attempts.lock().unwrap().len(),
            unlock::MAX_ATTEMPTS
        );
        let (status, _) = rig.post(
            "/owner/unlock",
            &ApprovalsRig::sealed(&first, &key, "right horse"),
        );
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "oldest attempt was not dropped"
        );
        assert!(unlock.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn unlock_routes_need_a_session_and_our_origin() {
        let (rig, unlock) = ApprovalsRig::with_unlock();
        let (id, key) = rig.begin();
        let body = ApprovalsRig::sealed(&id, &key, "right horse");
        for path in ["/owner/unlock/begin", "/owner/unlock"] {
            let b = if path.ends_with("begin") {
                "{}"
            } else {
                body.as_str()
            };
            let (status, _) = rig.send(
                Method::POST,
                path,
                false,
                Some(ORIGIN),
                Some("application/json"),
                b,
            );
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
            for origin in [None, Some("https://evil.example"), Some("null")] {
                let (status, _) = rig.send(
                    Method::POST,
                    path,
                    true,
                    origin,
                    Some("application/json"),
                    b,
                );
                assert_eq!(status, StatusCode::FORBIDDEN, "{path} {origin:?}");
            }
            for method in [Method::GET, Method::PUT] {
                let (status, _) = rig.send(
                    method.clone(),
                    path,
                    true,
                    Some(ORIGIN),
                    Some("application/json"),
                    b,
                );
                assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{path} {method}");
            }
        }
        rig.ui.expire_sessions();
        assert_eq!(rig.post("/owner/unlock", &body).0, StatusCode::UNAUTHORIZED);
        assert!(unlock.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn unlock_refuses_a_plain_password_and_malformed_bodies() {
        let (rig, unlock) = ApprovalsRig::with_unlock();
        // The password-key refusal has no carve-out: a plaintext
        // password is refused before anything else, and not echoed.
        for path in ["/owner/unlock/begin", "/owner/unlock"] {
            let (status, out) = rig.post(path, r#"{"password":"hunter2"}"#);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
            assert!(
                out.contains("password_rejected") && !out.contains("hunter2"),
                "{out}"
            );
        }
        let (id, key) = rig.begin();
        let good: Value =
            serde_json::from_str(&ApprovalsRig::sealed(&id, &key, "right horse")).unwrap();
        let mut extra = good.clone();
        extra["kind"] = json!("x");
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("nonce");
        for (ctype, body) in [
            (
                Some("application/x-www-form-urlencoded"),
                "attempt_id=x".to_owned(),
            ),
            (Some("text/plain"), good.to_string()),
            (None, good.to_string()),
            (Some("application/json"), "[]".to_owned()),
            (Some("application/json"), extra.to_string()),
            (Some("application/json"), missing.to_string()),
        ] {
            let (status, out) = rig.send(
                Method::POST,
                "/owner/unlock",
                true,
                Some(ORIGIN),
                ctype,
                &body,
            );
            assert_eq!(status, StatusCode::BAD_REQUEST, "{ctype:?} {body}: {out}");
        }
        let (status, _) = rig.post("/owner/unlock/begin", r#"{"x":1}"#);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(unlock.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn unlock_without_a_backend_is_unknown_op() {
        let rig = ApprovalsRig::new();
        let (status, out) = rig.post("/owner/unlock/begin", "{}");
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{out}");
        assert!(out.contains("unknown_op"), "{out}");
        let (_, key) = {
            let (rig2, _) = ApprovalsRig::with_unlock();
            rig2.begin()
        };
        let (status, _) = rig.post(
            "/owner/unlock",
            &ApprovalsRig::sealed("x", &key, "right horse"),
        );
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }
}
