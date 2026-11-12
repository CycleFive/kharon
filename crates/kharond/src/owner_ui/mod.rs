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
//! on the server; clearing the cookie alone does not end it. In
//! public mode, [`SESSION_FAILURE_CAP`] auth failures attributed to
//! one session (any route, any detail except a refused `Origin`)
//! end it too: the next request with that cookie is 401, and one
//! `owner_auth_fail` (`session_ended`) records why (#254).
//!
//! Registering the first passkey is not a login. The owner socket
//! (same-uid) mints a single-use enrollment code via `passkey_enroll`;
//! `POST /owner/register/*` accepts that code, or an existing owner
//! session, and does not set a session cookie. Signing in still
//! requires an assertion. Minting a code and storing a passkey each
//! append an audit entry first; a failed append does neither (#249).
//! Listing passkeys and removing one do the same (#258). The signed-in
//! page lists them and can remove one, but not the last.
//!
//! Fixed routes (no token in the path):
//!
//! | Method | Path | |
//! |---|---|---|
//! | GET | `/` | Login page, or the signed-in shell |
//! | GET | `/enroll` | Enrollment page (one-time code, not a password) |
//! | GET | `/.well-known/oauth-authorization-server` | RFC 8414 metadata, only with `[oauth]` set (REQ-OAU-001); no session |
//! | GET | `/oauth/authorize` | Start a Connect (REQ-OAU-003); no session |
//! | GET | `/oauth/consent/<token>` | Consent page, or the passkey sign-in that returns to it |
//! | POST | `/oauth/consent/view` | Consent JSON for the signed-in shell |
//! | POST | `/oauth/consent/options` | Begin the fresh consent assertion |
//! | POST | `/oauth/consent/approve` | Approve; returns `{redirect}` |
//! | POST | `/oauth/consent/deny` | Deny; returns `{redirect}` with `access_denied` |
//! | POST | `/oauth/token` | OAuth token endpoint, only with `[oauth]` set (REQ-OAU-004); no session, no `Origin`, exempt |
//! | POST | `/oauth/revoke` | OAuth revocation endpoint, only with `[oauth]` set (REQ-OAU-005); no session, no `Origin`, exempt |
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

pub mod access;
mod approvals;
mod audit_budget;
mod oauth;
pub mod oauth_token;
mod sealed;
mod store;
mod throttle;
pub mod unlock;
mod webauthn;

pub use self::approvals::{
    AUDIT_TAIL_LEN, AuditRow, ConnectionRow, DecideError, GrantRow, NoApprovals, OwnerApprovals,
    PendingRow, WebGrantKind,
};
pub use self::oauth::OauthAs;
pub use self::unlock::OwnerUnlock;

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use hyper_util::rt::TokioIo;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tower_service::Service as TowerService;
use zeroize::Zeroizing;

use self::sealed::{Burn, Sealed};
use self::store::PasskeyStore;
use self::webauthn::{RegisteredCredential, b64url_decode, b64url_encode, ct_eq};
use crate::api::cimd::ClientAdmission;
use crate::api::http::{
    ApprovalRedeemer, OWNER_APPROVE_PREFIX, OWNER_DENY_PREFIX, dispatch_owner_approval,
};
use crate::api::oauth::AUTHORIZATION_SERVER_PATH;

/// SPEC §5: an owner web session is at most 15 minutes.
pub const SESSION_TTL: Duration = Duration::from_secs(15 * 60);

/// Auth failures behind one live session that end it, in public mode
/// (#254, REQ-APR-009). The same number as the per-source throttle:
/// a stolen cookie gets about as many guesses as one source, on any
/// route, and then the session is gone. A refused `Origin` does not
/// count. The count is the session's, so the source address does not
/// matter.
pub const SESSION_FAILURE_CAP: u32 = 10;

const _: () = assert!(SESSION_FAILURE_CAP == throttle::MAX_FAILURES);

/// A challenge or enrollment code lives this long, matching the
/// ntfy one-time token (SPEC §5).
pub const CEREMONY_TTL: Duration = Duration::from_secs(120);

/// Cookie that carries the session token. The token itself is not
/// stored; the server keeps its SHA-256.
const SESSION_COOKIE: &str = "kharon_owner";

/// The session cookie in public mode: the `__Host-` prefix makes a
/// browser refuse it unless it is `Secure`, has `Path=/` and no `Domain`,
/// so a sibling subdomain cannot set or shadow it (#208).
const HOST_SESSION_COOKIE: &str = "__Host-kharon_owner";

/// A route (or family of routes) that takes no `Origin` and no Access
/// login in public mode.
pub enum EdgeExempt {
    /// Every path starting with this.
    Prefix(&'static str),
    /// Exactly this path.
    Exact(&'static str),
}

/// The one list of routes that take no `Origin` and no Access login:
/// the ntfy redeem routes, whose clients are not browsers, and the
/// OAuth routes (the RFC 8414 metadata route and the token
/// endpoints), whose clients are not browsers behind Access either —
/// discovery is how an unauthenticated client finds the authorize
/// endpoint (REQ-OAU-001), and a token client holds no Access login
/// (REQ-OAU-008). The two kinds route differently: the redeem
/// prefixes are answered by the approval redeemer, the OAuth paths
/// by the UI's own dispatch.
pub const EDGE_EXEMPT: &[EdgeExempt] = &[
    EdgeExempt::Prefix(OWNER_APPROVE_PREFIX),
    EdgeExempt::Prefix(OWNER_DENY_PREFIX),
    EdgeExempt::Exact(AUTHORIZATION_SERVER_PATH),
    // The OAuth token endpoints (REQ-OAU-008): a dashboard's
    // backend is not a browser, so it can pass neither the `Origin`
    // rule nor an Access login. Like the metadata path, they are
    // the UI's own routes and fall through to `dispatch`.
    EdgeExempt::Exact(oauth_token::TOKEN_PATH),
    EdgeExempt::Exact(oauth_token::REVOKE_PATH),
];

/// True when `path` is on [`EDGE_EXEMPT`].
pub fn edge_exempt(path: &str) -> bool {
    EDGE_EXEMPT.iter().any(|e| match e {
        EdgeExempt::Prefix(p) => path.starts_with(p),
        EdgeExempt::Exact(x) => path == *x,
    })
}

/// True when `path` is an ntfy redeem route: the [`EDGE_EXEMPT`]
/// prefixes, which the approval redeemer answers rather than the
/// UI's own dispatch. The list's `Exact` entries (the RFC 8414
/// metadata path, the OAuth token endpoints) are the UI's own
/// routes and are not ones.
pub fn redeem_exempt(path: &str) -> bool {
    EDGE_EXEMPT.iter().any(|e| match e {
        EdgeExempt::Prefix(p) => path.starts_with(p),
        EdgeExempt::Exact(_) => false,
    })
}

/// Fixed routes this UI serves (no token in the path). Tests assert
/// none of them is a password login. ntfy redeem is the
/// `/owner/approve/<token>` and `/owner/deny/<token>` prefixes on
/// this same listener. The well-known route is served only when
/// `[oauth]` is configured (REQ-OAU-001); without it the path 404s
/// like any other unknown one.
pub const ROUTES: &[(&str, &str)] = &[
    ("GET", "/"),
    ("GET", "/enroll"),
    ("GET", AUTHORIZATION_SERVER_PATH),
    ("POST", oauth_token::TOKEN_PATH),
    ("POST", oauth_token::REVOKE_PATH),
    ("GET", "/oauth/authorize"),
    ("POST", "/oauth/consent/view"),
    ("POST", "/oauth/consent/options"),
    ("POST", "/oauth/consent/approve"),
    ("POST", "/oauth/consent/deny"),
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
    ("GET", "/owner/passkeys"),
    ("POST", "/owner/passkeys/remove"),
    ("GET", "/owner/connections"),
    ("POST", "/owner/connections/disconnect"),
    ("POST", "/owner/connections/unsuspend"),
    ("POST", "/owner/panic"),
    ("POST", "/owner/unlock/begin"),
    ("POST", "/owner/unlock"),
];

/// Longest request or grant id the owner routes accept. Broker ids
/// are `gr_` or `g_` plus a short random suffix, well under this.
const MAX_ID_LEN: usize = 64;

const MAX_BODY: usize = 16 * 1024;
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

/// Where owner-UI audit entries go.
///
/// `auth_failed` and `suppressed_only` are best effort: a failed
/// append does not turn a refusal into a success. Enrollment is
/// fail-closed (#249, the fill rule): `Err` means the entry was not
/// appended, and the caller must not mint a code or leave a
/// credential stored.
pub trait OwnerAudit: Send + Sync + 'static {
    /// Record a failed owner-UI authentication attempt.
    fn auth_failed(&self, failure: AuthFailure);
    /// Record the count of failures the audit ceiling (D6) did not
    /// itemize, as a `suppressed_only` entry.
    fn suppressed_only(&self, count: u64);
    /// `passkey_enroll_code` on channel `cli`, before a code is
    /// minted. `Err` mints nothing.
    fn passkey_enroll_code(&self) -> Result<(), OwnerAuditError>;
    /// `passkey_enrolled` on channel `web_ui`, before the passkey is
    /// stored. Called while the passkey store lock is held, so the
    /// sink must not call back into the UI. `Err` stores nothing.
    fn passkey_enrolled(&self, enrolled: PasskeyEnrolled) -> Result<(), OwnerAuditError>;
    /// `passkey_listed` before the list is returned (#258). Called
    /// while the passkey store lock is held, so the sink must not
    /// call back into the UI. `Err` returns no list.
    fn passkey_listed(&self, listed: PasskeyListed) -> Result<(), OwnerAuditError>;
    /// `passkey_removed` before the passkey is removed (#258). Called
    /// while the passkey store lock is held, so the sink must not
    /// call back into the UI. `Err` removes nothing.
    fn passkey_removed(&self, removed: PasskeyRemoved) -> Result<(), OwnerAuditError>;
}

/// A passkey that is about to be stored (#249). No credential id.
pub struct PasskeyEnrolled {
    /// Truncated SHA-256 of the raw credential id, 32 lowercase hex chars.
    pub credential_fingerprint: String,
    /// Enrolled passkeys once this one is stored.
    pub passkey_count: u64,
}

/// Which owner surface is listing or removing a passkey (#258).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyChannel {
    /// The owner socket (`kharon passkey …`). May remove the last passkey.
    Cli,
    /// The signed-in owner page. Refuses to remove the last passkey.
    WebUi,
}

impl PasskeyChannel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::WebUi => "web_ui",
        }
    }
}

/// A passkey list that is about to be returned (#258). No credential ids.
pub struct PasskeyListed {
    /// `cli` or `web_ui`.
    pub channel: &'static str,
    /// One 32-hex fingerprint per enrolled passkey, list order. Empty
    /// when the store is empty.
    pub credential_fingerprints: Vec<String>,
    /// Enrolled passkeys this list names.
    pub passkey_count: u64,
}

/// A passkey that is about to be removed (#258). No credential id.
pub struct PasskeyRemoved {
    /// `cli` or `web_ui`.
    pub channel: &'static str,
    /// Truncated SHA-256 of the raw credential id, 32 lowercase hex chars.
    pub credential_fingerprint: String,
    /// Enrolled passkeys once this one is gone.
    pub passkey_count: u64,
}

/// Why a passkey was not listed or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyOpError {
    /// The audit entry was not appended. Nothing was listed or removed.
    Audit,
    /// No passkey has that short id.
    NotFound,
    /// More than one passkey shares that short id. Nothing was removed.
    Ambiguous,
    /// The web UI will not remove the last passkey.
    LastPasskey,
    /// The id is not 8 lowercase hex characters.
    BadId,
    /// The passkey file could not be written. The passkey is still there.
    Store,
}

/// The enrollment entry was not appended.
#[derive(Debug, thiserror::Error)]
#[error("audit append failed")]
pub struct OwnerAuditError;

/// One failed owner-UI authentication attempt, as the audit sink sees it.
pub struct AuthFailure {
    /// A fixed code, never request data.
    pub detail: &'static str,
    /// The source address, in public mode only (`None` locally). It is
    /// audit data; it never decides anything (REQ-API-010).
    pub client_ip: Option<IpAddr>,
    /// Failures counted and not itemized since the last entry (D6).
    pub suppressed: Option<u64>,
}

/// Audit sink that discards. Tests that don't care use this.
pub struct NoAudit;

impl OwnerAudit for NoAudit {
    fn auth_failed(&self, _failure: AuthFailure) {}
    fn suppressed_only(&self, _count: u64) {}
    fn passkey_enroll_code(&self) -> Result<(), OwnerAuditError> {
        Ok(())
    }
    fn passkey_enrolled(&self, _enrolled: PasskeyEnrolled) -> Result<(), OwnerAuditError> {
        Ok(())
    }
    fn passkey_listed(&self, _listed: PasskeyListed) -> Result<(), OwnerAuditError> {
        Ok(())
    }
    fn passkey_removed(&self, _removed: PasskeyRemoved) -> Result<(), OwnerAuditError> {
        Ok(())
    }
}

/// The owner UI's state: passkeys, sealed ceremony tokens (nothing
/// stored per ceremony), sessions, enrollment codes. Cheap to clone via [`Arc`]; the server holds one.
pub struct OwnerUi {
    rp_id: String,
    origin: String,
    /// Behind the edge (`[owner_ui] public_origin`, #208).
    public: bool,
    /// Host and port of `origin`: the only `Host` public mode serves.
    host: String,
    port: u16,
    secure_cookie: bool,
    /// The optional Cloudflare Access check (public mode only, D9).
    access: Option<Arc<access::AccessVerifier>>,
    /// [`HOST_SESSION_COOKIE`] in public mode, else [`SESSION_COOKIE`].
    cookie_name: &'static str,
    shell: Arc<dyn OwnerShell>,
    audit: Arc<dyn OwnerAudit>,
    approvals: Arc<dyn OwnerApprovals>,
    passkeys: Mutex<PasskeyStore>,
    /// Seals and opens ceremony tokens (D7): nothing is stored at
    /// `options`.
    sealed: Sealed,
    sessions: Mutex<Vec<Session>>,
    /// Failed sign-in, enroll and unlock attempts per source (D5).
    throttle: throttle::FailureThrottle,
    /// Caps the `owner_auth_fail` entries a stranger can cause (D6).
    audit_budget: audit_budget::AuditBudget,
    /// Set once the missing-`CF-Connecting-IP` warning has been printed.
    peer_fallback_warned: std::sync::atomic::AtomicBool,
    /// Public-mode requests that fell back to the TCP peer.
    without_edge_address: std::sync::atomic::AtomicU64,
    enroll: Mutex<Vec<Enroll>>,
    /// The web unlock backend (slice 5b). Set once, after the daemon
    /// has built its owner ops; unset → the unlock routes answer
    /// `unknown_op`.
    unlocker: OnceLock<Arc<dyn OwnerUnlock>>,
    unlock_attempts: Mutex<Vec<unlock::Attempt>>,
    /// OAuth authorization server (REQ-OAU-001/-003). `None` → the
    /// well-known path and `/oauth/*` 404 like any other unknown route.
    oauth: Option<OauthAs>,
    /// Authorization codes (D4). Memory only; a panic clears them.
    /// Behind an `Arc` because the token side's code redeemer
    /// (#231) shares this one store.
    codes: Arc<oauth::CodeStore>,
    /// Per-source budget for `GET /oauth/authorize` (REQ-OAU-008).
    authorize_budget: oauth::AuthorizeBudget,
    /// OAuth client admission (REQ-OAU-002; #229): the allow-list,
    /// CIMD fetch and cache `/oauth/authorize` admits through.
    /// `None` → no `[oauth]`, so no client is admissible.
    admission: Option<Arc<ClientAdmission>>,
    /// The OAuth token side (REQ-OAU-004/-005; #231): the store
    /// and code redeemer behind `POST /oauth/token` and
    /// `POST /oauth/revoke`. `None` → the paths 404 like any other
    /// unknown route.
    oauth_tokens: Option<oauth_token::TokenSide>,
}

/// A ceremony as `options` hands it out: the sealed token (the
/// `ceremony_id` on the wire) and its challenge.
struct Ceremony {
    id: String,
    challenge: Vec<u8>,
}

/// What a ceremony token carries besides its purpose and expiry.
#[derive(Serialize, Deserialize)]
struct CeremonyClaims {
    /// base64url of 32 random bytes.
    challenge: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CeremonyKind {
    Login,
    Register,
}

impl CeremonyKind {
    /// The purpose sealed into the token: a `login` token never opens
    /// as `register`.
    fn purpose(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Register => "register",
        }
    }
}

struct Session {
    hash: [u8; 32],
    expires: Instant,
    /// Raw credential id that opened this session (#258). Empty for a
    /// session a test issued without a passkey. Removing the passkey
    /// ends every session that carries its id.
    credential_id: Vec<u8>,
    /// `owner_auth_fail` entries attributed to this session, other
    /// than a refused `Origin` (#254). Reaching
    /// [`SESSION_FAILURE_CAP`] drops the session.
    auth_failures: u32,
}

struct Enroll {
    hash: [u8; 32],
    expires: Instant,
}

/// What [`OwnerUi::open_with`] needs beyond the stores.
pub struct OwnerUiOptions {
    pub rp_id: String,
    pub origin: String,
    /// Public mode: behind the edge (#208).
    pub public: bool,
    /// The Access check, when `[owner_ui.access]` is set (public mode).
    pub access: Option<Arc<access::AccessVerifier>>,
    /// OAuth authorization server, when `[oauth]` is set: discovery
    /// plus the authorize and consent routes (REQ-OAU-001/-003).
    pub oauth: Option<OauthAs>,
    /// OAuth client admission, when `[oauth]` is set (REQ-OAU-002):
    /// the authorize endpoint admits clients through it.
    pub admission: Option<Arc<ClientAdmission>>,
    /// The OAuth token side, when `[oauth]` is set (REQ-OAU-004):
    /// the token store the daemon loaded at startup, plus the code
    /// redeemer over the authorize side's code store (#230).
    pub oauth_tokens: Option<oauth_token::TokenSide>,
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
        Self::open_with(
            data_dir,
            OwnerUiOptions {
                rp_id: rp_id.into(),
                origin: origin.into(),
                public: false,
                access: None,
                oauth: None,
                admission: None,
                oauth_tokens: None,
            },
            shell,
            audit,
            approvals,
        )
    }

    /// [`Self::open`] with the public-mode switch (#208).
    pub fn open_with(
        data_dir: &Path,
        opts: OwnerUiOptions,
        shell: Arc<dyn OwnerShell>,
        audit: Arc<dyn OwnerAudit>,
        approvals: Arc<dyn OwnerApprovals>,
    ) -> std::io::Result<Arc<Self>> {
        let OwnerUiOptions {
            rp_id,
            origin,
            public,
            access,
            oauth,
            admission,
            oauth_tokens,
        } = opts;
        // The Access gate exists only behind the edge. Config already
        // refuses `access` without `public_origin`; this is a second guard.
        let access = access.filter(|_| public);
        let secure_cookie = origin.starts_with("https://");
        let (host, port) = crate::config::origin_authority(&origin, &rp_id, public);
        let passkeys = PasskeyStore::load(data_dir)?;
        let codes = Arc::new(oauth::CodeStore::new());
        // REQ-OAU-004 (#231): a token side built `unwired` gets the
        // real code redeemer here, over the authorize side's own
        // store — the store is born with the UI, so this is the
        // first moment both halves exist. A side built with an
        // explicit redeemer (tests) keeps it.
        let oauth_tokens = oauth_tokens.map(|mut side| {
            if side.bind_at_open {
                side.codes = Arc::new(oauth_token::CodeStoreRedeemer::new(Arc::clone(&codes)));
            }
            side
        });
        Ok(Arc::new(Self {
            rp_id,
            origin,
            public,
            host,
            port,
            secure_cookie,
            access,
            cookie_name: if public {
                HOST_SESSION_COOKIE
            } else {
                SESSION_COOKIE
            },
            shell,
            audit,
            approvals,
            passkeys: Mutex::new(passkeys),
            sealed: Sealed::new(),
            sessions: Mutex::new(Vec::new()),
            throttle: throttle::FailureThrottle::new(),
            audit_budget: audit_budget::AuditBudget::new(),
            peer_fallback_warned: std::sync::atomic::AtomicBool::new(false),
            without_edge_address: std::sync::atomic::AtomicU64::new(0),
            enroll: Mutex::new(Vec::new()),
            unlocker: OnceLock::new(),
            unlock_attempts: Mutex::new(Vec::new()),
            oauth,
            codes,
            authorize_budget: oauth::AuthorizeBudget::new(),
            admission,
            oauth_tokens,
        }))
    }

    /// The OAuth client admission the authorize endpoint (#230)
    /// admits through, when `[oauth]` is set (REQ-OAU-002).
    pub fn client_admission(&self) -> Option<&Arc<ClientAdmission>> {
        self.admission.as_ref()
    }

    /// Attach the web unlock backend. The daemon calls this once,
    /// after its owner ops exist (they hold this UI for
    /// `passkey_enroll`, so the UI cannot take them at
    /// [`Self::open`]). Returns `false` if one was already set.
    pub fn set_unlocker(&self, unlocker: Arc<dyn OwnerUnlock>) -> bool {
        self.unlocker.set(unlocker).is_ok()
    }

    /// True when the UI is behind the edge (`public_origin`, #208).
    pub fn is_public(&self) -> bool {
        self.public
    }

    /// The origin assertions are checked against.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Mint a single-use enrollment code (base64url, 256 bits).
    /// The returned buffer is the only copy the caller should print;
    /// the server stores SHA-256 of it. The owner socket is the
    /// intended caller: it is already authenticated by peer uid.
    ///
    /// Appends `passkey_enroll_code` first (#249, the fill rule). A
    /// failed append returns [`OwnerAuditError`] and mints nothing.
    pub fn mint_enroll_token(&self) -> Result<Zeroizing<String>, OwnerAuditError> {
        self.audit.passkey_enroll_code()?;
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
        Ok(token)
    }

    /// Live enrollment codes. Unit tests use this to see that a
    /// failed append minted nothing.
    #[cfg(test)]
    pub(crate) fn outstanding_enroll_codes(&self) -> usize {
        let guard = self.enroll.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        guard.iter().filter(|e| e.expires > now).count()
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
    /// Handlers on the blocking pool. Shutdown waits for these after
    /// dropping sockets, so a failure already being recorded is in the
    /// budget before [`OwnerUi::drain_audit`] (#255).
    in_flight: Arc<InFlight>,
}

/// How many owner-UI handlers are on the blocking pool.
///
/// The count is taken before `spawn_blocking` and released when that
/// closure finishes, including when the connection task has already
/// been dropped. [`InFlight::drained`] waits until it is zero.
struct InFlight {
    n: AtomicUsize,
    idle: tokio::sync::Notify,
}

impl InFlight {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            n: AtomicUsize::new(0),
            idle: tokio::sync::Notify::new(),
        })
    }

    fn enter(self: &Arc<Self>) -> InFlightGuard {
        self.n.fetch_add(1, Ordering::AcqRel);
        InFlightGuard(Arc::clone(self))
    }

    /// Resolves once every [`Self::enter`] guard has dropped.
    async fn drained(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            // Subscribe before the load, or a drop that lands in
            // between stores a permit `enable` consumes.
            let ready = notified.as_mut().enable();
            if self.n.load(Ordering::Acquire) == 0 {
                return;
            }
            if ready {
                continue;
            }
            notified.await;
        }
    }
}

struct InFlightGuard(Arc<InFlight>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.0.n.fetch_sub(1, Ordering::Release) == 1 {
            self.0.idle.notify_one();
        }
    }
}

/// Run `work` on the blocking pool and keep it visible to
/// [`InFlight::drained`] until it returns. Dropping the returned
/// future does not cancel `work`.
async fn on_blocking_pool<T, F>(
    in_flight: &Arc<InFlight>,
    work: F,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let guard = in_flight.enter();
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        work()
    })
    .await
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
    let (app, _) = router(ui, redeem);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// [`serve`], but stop accepting when `shutdown` resolves, then wait at
/// most `drain_for` for connections already accepted.
///
/// Idle keep-alives close with hyper's graceful shutdown and do not
/// consume the bound. A connection still open when the bound elapses is
/// dropped: its task goes with this future's [`JoinSet`], so it cannot
/// be dispatched afterwards. A handler already on the blocking pool is
/// allowed to finish first, which is what puts its failure in the audit
/// budget before the daemon's `drain_audit` (#255).
pub async fn serve_with_shutdown<F>(
    listener: TcpListener,
    ui: Arc<OwnerUi>,
    redeem: Arc<dyn ApprovalRedeemer>,
    shutdown: F,
    drain_for: Duration,
) -> std::io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let (app, in_flight) = router(ui, redeem);
    let mut shutdown = std::pin::pin!(shutdown);
    let mut tasks = JoinSet::new();
    // `true` tells each connection to finish the request it is serving
    // and close. An idle keep-alive is not serving one, so hyper closes
    // it on the next poll.
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((tcp, peer)) => {
                        tasks.spawn(serve_owner_conn(
                            tcp,
                            peer,
                            app.clone(),
                            shutdown_tx.subscribe(),
                        ));
                    }
                    Err(_) => {
                        tokio::select! {
                            biased;
                            _ = &mut shutdown => break,
                            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                        }
                    }
                }
            }
        }
    }
    drop(listener);
    let _ = shutdown_tx.send(true);

    let deadline = tokio::time::sleep(drain_for);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            joined = tasks.join_next() => {
                if joined.is_none() {
                    in_flight.drained().await;
                    return Ok(());
                }
            }
            _ = &mut deadline => break,
        }
    }
    // Still open at the bound. Abort drops each connection future, and
    // with it the socket, before this function returns.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    in_flight.drained().await;
    Ok(())
}

fn router(ui: Arc<OwnerUi>, redeem: Arc<dyn ApprovalRedeemer>) -> (Router, Arc<InFlight>) {
    let in_flight = InFlight::new();
    let state = Arc::new(OwnerServer {
        ui,
        redeem,
        in_flight: Arc::clone(&in_flight),
    });
    (Router::new().fallback(handle).with_state(state), in_flight)
}

/// One accepted owner-UI connection. `shutdown` becoming `true` is
/// hyper's graceful shutdown: finish the current request, close an
/// idle keep-alive immediately.
async fn serve_owner_conn(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    app: Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let io = TokioIo::new(tcp);
    let service = HyperOwner { app, peer };
    let mut conn =
        std::pin::pin!(hyper::server::conn::http1::Builder::new().serve_connection(io, service));
    let mut closing = *shutdown.borrow();
    if closing {
        conn.as_mut().graceful_shutdown();
    }
    loop {
        tokio::select! {
            result = conn.as_mut() => {
                // A client that went away, or a socket dropped at the
                // shutdown bound. Not a daemon failure.
                let _ = result;
                break;
            }
            changed = shutdown.changed(), if !closing => {
                if changed.is_err() || *shutdown.borrow() {
                    closing = true;
                    conn.as_mut().graceful_shutdown();
                }
            }
        }
    }
}

/// Axum router as a hyper service, with the TCP peer in extensions so
/// [`ConnectInfo`] still resolves. The ordinary [`serve`] path gets the
/// peer from axum; this shutdown path owns the connection itself.
struct HyperOwner {
    app: Router,
    peer: SocketAddr,
}

impl hyper::service::Service<axum::http::Request<hyper::body::Incoming>> for HyperOwner {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn call(&self, req: axum::http::Request<hyper::body::Incoming>) -> Self::Future {
        let mut app = self.app.clone();
        let peer = self.peer;
        Box::pin(async move {
            let mut req: axum::http::Request<Body> = req.map(Body::new);
            req.extensions_mut().insert(ConnectInfo(peer));
            let Ok(()) = std::future::poll_fn(|cx| {
                TowerService::<axum::http::Request<Body>>::poll_ready(&mut app, cx)
            })
            .await;
            TowerService::call(&mut app, req).await
        })
    }
}

async fn handle(
    State(state): State<Arc<OwnerServer>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    // Public mode: a request not addressed to the published name is
    // refused before routing, the ntfy redeem branch and the body.
    // Never audited: a stranger must not be able to grow the log.
    if state.ui.public
        && !crate::api::public::host_matches(req.headers(), &state.ui.host, state.ui.port)
    {
        return respond(StatusCode::MISDIRECTED_REQUEST, "misdirected", None);
    }
    // REQ-OAU-006: an OAuth access or refresh token is not a
    // credential on this listener. Refuse before redeem, Access,
    // the body and every route, and do not audit — a stranger
    // spraying tokens must not grow the log. A session cookie
    // does not override the refusal, and the approval link is
    // not consulted, so it is not consumed.
    if req
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .any(|value| {
            value
                .to_str()
                .is_ok_and(crate::api::oauth::authorization_is_oauth_bearer)
        })
    {
        return respond(StatusCode::FORBIDDEN, "forbidden", None);
    }
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    let exempt = edge_exempt(&path);
    // The ntfy redeem routes: on `EDGE_EXEMPT`, so they take no `Origin`
    // and no Access token, and the approval redeemer answers them.
    // The RFC 8414 metadata path is on the same list but is the UI's
    // own route: it falls through to `dispatch` below, skipping only
    // the Access gate.
    if redeem_exempt(&path) {
        let redeem = Arc::clone(&state.redeem);
        return dispatch_owner_approval(redeem, method, path).await;
    }
    let ui = Arc::clone(&state.ui);
    let headers = req.headers().clone();
    let cookie = header_str(&headers, header::COOKIE);
    let origin = header_str(&headers, header::ORIGIN);
    let authorization = header_str(&headers, header::AUTHORIZATION);
    // Public mode only. The shared helper honours CF-Connecting-IP
    // only from a loopback peer or a trusted_proxies entry
    // (REQ-API-010). This listener binds loopback and has no proxy
    // list of its own: every peer it can accept is loopback, so the
    // header still names the client. A non-loopback peer — which the
    // bind rules refuse — would be audited as itself and not throttled.
    let edge_ip = ui
        .public
        .then(|| crate::api::public::client_ip(&headers, true, peer.ip(), &[]))
        .flatten();
    let client_ip = ui.public.then(|| {
        edge_ip.unwrap_or_else(|| {
            ui.note_peer_fallback();
            peer.ip()
        })
    });
    // Access (D9): after the Host check, before the body is read or
    // anything routes. Exempt routes skip it: the redeem routes
    // returned above, and the metadata path, which `dispatch` serves
    // (with `[oauth]`) or 404s (without) — a discovering client holds
    // no Access token.
    if !exempt
        && let Some(verifier) = ui.access.as_ref()
        && verifier
            .verify(&headers, std::time::SystemTime::now())
            .await
            .is_err()
    {
        let audit_ui = Arc::clone(&ui);
        // Never counted by the throttle: not a sign-in attempt. Audited
        // within the ceiling, on the blocking pool like every append.
        // The guard outlives this task so shutdown can wait for the
        // append before `drain_audit` (#255).
        let _ = on_blocking_pool(&state.in_flight, move || {
            audit_ui.record_failure(
                Instant::now(),
                FailureCtx {
                    client_ip,
                    throttle_key: None,
                    throttled_route: false,
                    session: None,
                },
                ACCESS_REFUSED,
            );
        })
        .await;
        return respond(StatusCode::FORBIDDEN, "access_denied", None);
    }
    let content_type = header_str(&headers, header::CONTENT_TYPE);
    let (_parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b.to_vec(),
        Err(_) => return respond(StatusCode::PAYLOAD_TOO_LARGE, "bad_request", None),
    };
    let incoming = Incoming {
        method,
        path: path.clone(),
        cookie,
        origin,
        authorization,
        content_type,
        body: bytes,
        client_ip,
        throttle_key: edge_ip,
        query,
    };
    // CIMD admission fetches. That stays on this runtime. The rest of
    // the UI runs on the blocking pool, with the passkey store and the
    // vault lock.
    if path == "/oauth/authorize" {
        return ui.authorize_response(&incoming).await;
    }
    // Same guard as the Access refusal above: a dispatch already on
    // the pool finishes, and is counted, before shutdown drains.
    let joined = on_blocking_pool(&state.in_flight, move || ui.dispatch(incoming)).await;
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
    /// Public mode only: `CF-Connecting-IP` under REQ-API-010's rule,
    /// else the TCP peer. Audit data.
    client_ip: Option<IpAddr>,
    /// Public mode only: the address, when it came from a usable
    /// `CF-Connecting-IP`. It keys the throttle. `None` means exempt:
    /// behind the tunnel the peer is cloudflared, so if the edge stripped
    /// the header every visitor would share one bucket (#253).
    throttle_key: Option<IpAddr>,
    /// The request URI's query, without the leading `?`. Authorize
    /// reads it; other routes ignore it.
    query: Option<String>,
}

/// The detail code of a refused `Origin`: always capped by the audit
/// ceiling (D6), never counted by the throttle (D5), and never counted
/// toward the per-session cap (#254). A same-site sibling page can
/// send the cookie; counting it would let that page sign the owner out.
const ORIGIN_REFUSED: &str = "origin";

/// The one `owner_auth_fail` detail that records a session ended
/// because it reached [`SESSION_FAILURE_CAP`] (#254).
const SESSION_ENDED: &str = "session_ended";

/// How an `owner_auth_fail` entry meets the public audit ceiling (D6).
#[derive(Clone, Copy)]
enum Admit {
    /// Always itemized, outside the ceiling.
    Exempt,
    /// Counts against the 20 a window.
    Budget,
    /// A `throttled` trip: its own allowance of 5 a window.
    Trip,
}

/// The detail code of a refused Access token (D9): audited within the
/// ceiling, never counted by the throttle.
const ACCESS_REFUSED: &str = "access";

/// What a recorded failure knows about its request.
struct FailureCtx {
    /// The address for audit.
    client_ip: Option<IpAddr>,
    /// The address for the throttle; see [`Incoming::throttle_key`].
    throttle_key: Option<IpAddr>,
    /// The request was on one of [`throttle::THROTTLED_ROUTES`].
    throttled_route: bool,
    /// The live session this failure is attributed to, when the
    /// cookie names one (#254).
    session: Option<[u8; 32]>,
}

impl OwnerUi {
    /// The only place an owner-UI auth failure is recorded.
    fn fail(&self, req: &Incoming, detail: &'static str) {
        self.record_failure(
            Instant::now(),
            FailureCtx {
                client_ip: req.client_ip,
                throttle_key: req.throttle_key,
                throttled_route: throttle::THROTTLED_ROUTES.contains(&req.path.as_str()),
                session: self.live_session(req.cookie.as_deref()),
            },
            detail,
        );
    }

    /// [`Self::fail`] for failures raised before an [`Incoming`] exists.
    fn record_failure(&self, now: Instant, ctx: FailureCtx, detail: &'static str) {
        // A failure that passed the `Origin` check behind a live session
        // is always itemized: a stranger cannot make one (D6). A wrong
        // `Origin` is capped either way: a same-site sibling page can
        // send one with the owner's cookie.
        let session_bearing = ctx.session.is_some() && detail != ORIGIN_REFUSED;
        self.write_failure(
            now,
            detail,
            ctx.client_ip,
            if session_bearing {
                Admit::Exempt
            } else {
                Admit::Budget
            },
        );
        // A wrong `Origin` is never counted: a page the owner visits
        // sends those from the owner's own address (D5). Counting does
        // not depend on whether the entry was itemized.
        if let Some(ip) = ctx.throttle_key
            && self.public
            && ctx.throttled_route
            && detail != ORIGIN_REFUSED
            && self.throttle.record(ip, now) == throttle::Counted::Tripped
        {
            // Session-less in the budget's eyes, like any other entry.
            self.write_failure(now, "throttled", ctx.client_ip, Admit::Trip);
        }
        // Per-session cap (#254). Public mode only, like the throttle.
        // The count is the session's, so rotating source addresses
        // adds up, and a refused `Origin` never counts. Reaching the
        // cap drops the session; one entry records that, and it is
        // not itself counted.
        if self.public
            && session_bearing
            && let Some(hash) = ctx.session
            && self.note_session_failure(hash)
        {
            self.write_failure(now, SESSION_ENDED, ctx.client_ip, Admit::Exempt);
        }
    }

    /// Append one `owner_auth_fail` entry, or count it when the public
    /// ceiling is spent. Local mode and `exempt` entries always write.
    fn write_failure(
        &self,
        now: Instant,
        detail: &'static str,
        client_ip: Option<IpAddr>,
        admit: Admit,
    ) {
        let verdict = match admit {
            _ if !self.public => None,
            Admit::Exempt => None,
            Admit::Budget => Some(self.audit_budget.admit(now)),
            Admit::Trip => Some(self.audit_budget.admit_trip(now)),
        };
        let suppressed = match verdict {
            Some(audit_budget::Verdict::Write { suppressed }) => suppressed,
            Some(audit_budget::Verdict::Suppress) => return,
            None => None,
        };
        self.audit.auth_failed(AuthFailure {
            detail,
            client_ip,
            suppressed,
        });
    }

    /// How many public-mode requests had no usable `CF-Connecting-IP`.
    /// Such requests are audited with the peer address and are not
    /// throttled; a count that grows means the edge is not sending it.
    pub fn requests_without_edge_address(&self) -> u64 {
        self.without_edge_address
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// A public-mode request had no usable `CF-Connecting-IP`: count it,
    /// and say so once per process. It is audited with the TCP peer and
    /// exempt from the throttle (if the edge strips the header, every
    /// visitor would share the tunnel's key). Returns whether this call
    /// printed.
    fn note_peer_fallback(&self) -> bool {
        self.without_edge_address
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let first = !self
            .peer_fallback_warned
            .swap(true, std::sync::atomic::Ordering::Relaxed);
        if first {
            eprintln!(
                "kharond: owner UI request without a usable CF-Connecting-IP; such requests are not throttled until the edge sends it"
            );
        }
        first
    }

    /// Write the count of a closed audit window, if any (D6). The
    /// daemon's housekeeping tick calls this.
    pub fn flush_audit(&self, now: Instant) {
        if let Some(count) = self.audit_budget.flush(now) {
            self.audit.suppressed_only(count);
        }
    }

    /// Write whatever count is pending, window closed or not. Shutdown.
    pub fn drain_audit(&self) {
        if let Some(count) = self.audit_budget.drain() {
            self.audit.suppressed_only(count);
        }
    }

    /// A completed sign-in or unlock clears the source's failure count
    /// and this session's (#254). An owner who mistypes and then gets
    /// in starts fresh; the typos before the success do not end the
    /// session.
    fn forgive(&self, req: &Incoming) {
        if let Some(ip) = req.throttle_key {
            self.throttle.clear(ip);
        }
        let Some(hash) = session_hash(self.cookie_name, req.cookie.as_deref()) else {
            return;
        };
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(session) = guard.iter_mut().find(|s| ct_eq(&s.hash, &hash)) {
            session.auth_failures = 0;
        }
    }

    fn dispatch(&self, req: Incoming) -> Response {
        let origin_refused = if self.public {
            // Public mode: a POST names the public origin, or it is on
            // the exemption list (#208).
            req.method == Method::POST
                && !edge_exempt(&req.path)
                && req.origin.as_deref() != Some(self.origin.as_str())
        } else {
            req.method == Method::POST && req.origin.as_deref().is_some_and(|o| o != self.origin)
        };
        if origin_refused {
            self.fail(&req, "origin");
            let response = respond(StatusCode::FORBIDDEN, "origin", None);
            return if req.path.starts_with("/oauth/") {
                oauth::frame_deny(response)
            } else {
                response
            };
        }
        if let Some(ip) = req.throttle_key
            && self.public
            && throttle::THROTTLED_ROUTES.contains(&req.path.as_str())
            && let Some(left) = self.throttle.blocked(ip, Instant::now())
        {
            let response = rate_limited(left);
            return if req.path.starts_with("/oauth/") {
                oauth::frame_deny(response)
            } else {
                response
            };
        }
        // RFC 8414 discovery (REQ-OAU-001): public metadata, no
        // session — it is how an unauthenticated client finds the
        // authorize endpoint. Only with `[oauth]` set; without it
        // the path falls through to the unknown-route 404 below.
        if req.path == AUTHORIZATION_SERVER_PATH
            && let Some(oauth) = &self.oauth
        {
            if req.method != Method::GET {
                return method_not_allowed("GET");
            }
            return json_body(
                StatusCode::OK,
                oauth.discovery.authorization_server_metadata().to_string(),
                None,
            );
        }
        // The OAuth token endpoints (REQ-OAU-004/-005): on the
        // exemption list, so no `Origin` and no Access stood in the
        // way; the per-source throttle above has already refused a
        // throttled source. Only with the token side configured;
        // without it the paths fall through to the unknown-route
        // 404 below.
        if (req.path == oauth_token::TOKEN_PATH || req.path == oauth_token::REVOKE_PATH)
            && let Some(side) = &self.oauth_tokens
        {
            return self.oauth_token_dispatch(&req, side);
        }
        if self.oauth.is_some() && req.path.starts_with("/oauth/consent") {
            return self.oauth_dispatch(&req);
        }
        let allowed = match req.path.as_str() {
            "/" | "/enroll" | "/owner/session" | "/owner/approvals" | "/owner/grants"
            | "/owner/audit" | "/owner/passkeys" | "/owner/connections" => Some(Method::GET),
            "/owner/login/options"
            | "/owner/login/finish"
            | "/owner/register/options"
            | "/owner/register/finish"
            | "/owner/logout"
            | "/owner/approvals/approve"
            | "/owner/approvals/deny"
            | "/owner/grants/revoke"
            | "/owner/passkeys/remove"
            | "/owner/connections/disconnect"
            | "/owner/connections/unsuspend"
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
            "/owner/passkeys" => self.passkeys_list(&req),
            "/owner/passkeys/remove" => self.passkeys_remove(&req),
            "/owner/connections" => self.connections_list(&req),
            "/owner/connections/disconnect" => {
                self.connections_act(&req, ConnectAction::Disconnect)
            }
            "/owner/connections/unsuspend" => self.connections_act(&req, ConnectAction::Unsuspend),
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
        html(&login_page("/"))
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
                    "agent_name": r.agent_name,
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
            self.fail(req, "origin");
            return Some(respond(StatusCode::FORBIDDEN, "origin", None));
        }
        if !self.session_alive(req.cookie.as_deref()) {
            self.fail(req, "no_session");
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

    /// The live Connect identities for the Connections page (#233,
    /// D3). Read-only and unaudited, like the grants list: the page
    /// refreshes it on the shell's timer.
    fn connections_list(&self, req: &Incoming) -> Response {
        if !self.session_alive(req.cookie.as_deref()) {
            return respond(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        }
        let connections = self.approvals.connections();
        json_body(
            StatusCode::OK,
            json!({"ok": true, "connections": connections}).to_string(),
            None,
        )
    }

    /// Disconnect or Unsuspend a Connect identity (#233), behind
    /// [`Self::gate_owner_post`] and a well-formed agent id. Neither
    /// route is on the sign-in throttle list: Disconnect is a
    /// revoke-class action and Unsuspend its reset (REQ-APR-009).
    fn connections_act(&self, req: &Incoming, action: ConnectAction) -> Response {
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Ok(body) = serde_json::from_slice::<AgentBody>(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        if !valid_id(&body.agent_id) {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        }
        let result = match action {
            ConnectAction::Disconnect => self.approvals.disconnect(&body.agent_id),
            ConnectAction::Unsuspend => self.approvals.unsuspend(&body.agent_id),
        };
        match result {
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
        // No sealed-token invalidation here (#252): the broker's
        // panic hook does it, on every panic path and whatever the
        // outcome (the panic keeps grants revoked even when its own
        // audit append fails, so its hooks run either way). The
        // daemon registers the hook when it builds this UI.
        let outcome = self.approvals.panic();
        match outcome {
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
        let Some(session) = session_hash(self.cookie_name, req.cookie.as_deref()) else {
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
        let session = session_hash(self.cookie_name, req.cookie.as_deref());
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
            self.fail(req, "unlock_failed");
            return respond(StatusCode::BAD_REQUEST, "unlock_failed", None);
        };
        match unlocker.unlock(password) {
            Ok(()) => {
                self.forgive(req);
                json_body(
                    StatusCode::OK,
                    json!({"ok": true, "locked": false}).to_string(),
                    None,
                )
            }
            Err(e) => {
                // A scope refusal is audited exactly like a wrong
                // password; only the owner-facing code differs (#243).
                if e.is_auth_failure() {
                    self.fail(req, "unlock_failed");
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
            self.fail(req, "bad_enroll_token");
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
            self.fail(req, "no_assertion");
            return respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        }
        let Some(value) = json_object(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(cred) = credential_response(&value, CeremonyKind::Login) else {
            self.fail(req, "no_assertion");
            return respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        };
        let Some(ceremony_id) = value.get("ceremony_id").and_then(|v| v.as_str()) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some((challenge, opened)) = self.open_ceremony(ceremony_id, CeremonyKind::Login) else {
            self.fail(req, "bad_assertion");
            return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
        };
        let verified = {
            let store = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
            let Some(known) = store.credentials().iter().find(|c| c.id == cred.id) else {
                drop(store);
                self.fail(req, "bad_assertion");
                return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            };
            if let Some(handle) = &cred.user_handle
                && !ct_eq(handle, store.user_handle())
            {
                drop(store);
                self.fail(req, "bad_assertion");
                return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            }
            webauthn::verify_assertion(webauthn::Assertion {
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
                return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            }
        };
        if let Some(refused) = self.burn_ceremony(req, &opened) {
            return refused;
        }
        // Hold the passkey lock across the session issue so a remove
        // cannot land between the assertion and the session that
        // records it (#258).
        let cookie = {
            let mut store = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
            if store.set_sign_count(&cred.id, new_count).is_err() {
                drop(store);
                self.fail(req, "bad_assertion");
                return respond(StatusCode::INTERNAL_SERVER_ERROR, "store_failed", None);
            }
            self.issue_session(&cred.id)
        };
        self.forgive(req);
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
            self.fail(req, "no_assertion");
            return respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        }
        let Some(value) = json_object(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some(cred) = credential_response(&value, CeremonyKind::Register) else {
            self.fail(req, "no_assertion");
            return respond(StatusCode::UNAUTHORIZED, "no_assertion", None);
        };
        let Some(ceremony_id) = value.get("ceremony_id").and_then(|v| v.as_str()) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        let Some((challenge, opened)) = self.open_ceremony(ceremony_id, CeremonyKind::Register)
        else {
            self.fail(req, "bad_assertion");
            return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
        };
        let registered = webauthn::verify_registration(
            &cred.client_data_json,
            &cred.attestation_object,
            &challenge,
            &self.origin,
            &self.rp_id,
        );
        let registered = match registered {
            Ok(r) if r.credential_id == cred.id => r,
            _ => {
                self.fail(req, "bad_assertion");
                return respond(StatusCode::UNAUTHORIZED, "bad_assertion", None);
            }
        };
        if let Some(refused) = self.burn_ceremony(req, &opened) {
            return refused;
        }
        match self.store_enrolled(registered) {
            Ok(()) => {}
            Err(EnrollStore::Audit) => {
                return respond(StatusCode::INTERNAL_SERVER_ERROR, "audit_failed", None);
            }
            Err(EnrollStore::Store) => {
                self.fail(req, "bad_assertion");
                return respond(StatusCode::INTERNAL_SERVER_ERROR, "store_failed", None);
            }
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
            Some(clear_cookie(self.cookie_name, self.secure_cookie)),
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
                self.fail(req, "password_rejected");
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

    /// A panic happened: every outstanding ceremony token and every
    /// pending authorization stop opening, because both are sealed
    /// under this key, and every unredeemed authorization code is
    /// dropped (REQ-OAU-005, REQ-REV-002). An ordinary lock does not
    /// call this. Called only from the broker's panic hook (#252 —
    /// the daemon registers it in `bind_owner_ui`); no panic caller
    /// calls it directly.
    pub fn invalidate_sealed(&self) {
        self.sealed.invalidate();
        self.codes.clear();
    }

    fn begin(&self, kind: CeremonyKind) -> Ceremony {
        let challenge = random_bytes::<32>().to_vec();
        let claims = CeremonyClaims {
            challenge: b64url_encode(&challenge),
        };
        Ceremony {
            id: self
                .sealed
                .seal(kind.purpose(), &claims, CEREMONY_TTL, Instant::now()),
            challenge,
        }
    }

    /// Open a ceremony token: its challenge and its single-use handle.
    fn open_ceremony(
        &self,
        token: &str,
        kind: CeremonyKind,
    ) -> Option<(Vec<u8>, sealed::Opened<CeremonyClaims>)> {
        let opened = self
            .sealed
            .open::<CeremonyClaims>(kind.purpose(), token, Instant::now())?;
        let challenge = b64url_decode(&opened.claims.challenge).ok()?;
        Some((challenge, opened))
    }

    /// Record a verified ceremony as used. `Some` is the refusal.
    fn burn_ceremony(
        &self,
        req: &Incoming,
        opened: &sealed::Opened<CeremonyClaims>,
    ) -> Option<Response> {
        match self.sealed.burn(opened, Instant::now()) {
            Burn::Fresh => None,
            Burn::Replayed => {
                self.fail(req, "bad_assertion");
                Some(respond(StatusCode::UNAUTHORIZED, "bad_assertion", None))
            }
            Burn::Full => Some(respond(StatusCode::TOO_MANY_REQUESTS, "rate_limited", None)),
        }
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

    fn issue_session(&self, credential_id: &[u8]) -> String {
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
            credential_id: credential_id.to_vec(),
            auth_failures: 0,
        });
        session_cookie(self.cookie_name, &token, self.secure_cookie)
    }

    /// End every live session opened with this credential (#258).
    fn end_sessions_for(&self, credential_id: &[u8]) {
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|s| !ct_eq(&s.credential_id, credential_id));
    }

    fn session_alive(&self, cookie_header: Option<&str>) -> bool {
        self.live_session(cookie_header).is_some()
    }

    /// The hash of the live session `cookie_header` names, if it
    /// still has time left. Expired sessions are dropped.
    fn live_session(&self, cookie_header: Option<&str>) -> Option<[u8; 32]> {
        let hash = session_hash(self.cookie_name, cookie_header)?;
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        guard.retain(|s| s.expires > now);
        guard.iter().any(|s| ct_eq(&s.hash, &hash)).then_some(hash)
    }

    /// Count one non-origin failure against this session.
    ///
    /// `true` when the count reaches [`SESSION_FAILURE_CAP`] and the
    /// session was removed. A session that is already gone (logged
    /// out, expired, or ended by an earlier failure) counts nothing
    /// and writes no second ending entry.
    fn note_session_failure(&self, hash: [u8; 32]) -> bool {
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let Some(pos) = guard.iter().position(|s| ct_eq(&s.hash, &hash)) else {
            return false;
        };
        guard[pos].auth_failures = guard[pos].auth_failures.saturating_add(1);
        if guard[pos].auth_failures < SESSION_FAILURE_CAP {
            return false;
        }
        guard.remove(pos);
        true
    }

    /// Remove the session that matches this cookie, expired or not.
    /// Other sessions stay. A missing or unknown cookie is a no-op.
    fn revoke_session(&self, cookie_header: Option<&str>) {
        let Some(hash) = session_hash(self.cookie_name, cookie_header) else {
            return;
        };
        let mut guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|s| !ct_eq(&s.hash, &hash));
    }

    /// Store `cred` only after `passkey_enrolled` is durable (#249).
    /// The count on the entry is the number of passkeys this store
    /// will hold. The passkey lock is held across the append so that
    /// count cannot race another enrollment.
    fn store_enrolled(&self, cred: RegisteredCredential) -> Result<(), EnrollStore> {
        let mut guard = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
        if guard
            .credentials()
            .iter()
            .any(|c| c.id == cred.credential_id)
        {
            return Err(EnrollStore::Store);
        }
        let passkey_count = guard.credentials().len() as u64 + 1;
        let credential_fingerprint =
            crate::api::revocation::truncated_sha256_hex(&cred.credential_id);
        self.audit
            .passkey_enrolled(PasskeyEnrolled {
                credential_fingerprint,
                passkey_count,
            })
            .map_err(|_| EnrollStore::Audit)?;
        guard
            .insert(store::Credential {
                id: cred.credential_id,
                public_key: cred.public_key,
                sign_count: cred.sign_count,
                enrolled_at: Some(unix_now()),
                last_used_at: None,
            })
            .map_err(|_| EnrollStore::Store)
    }

    /// List enrolled passkeys after `passkey_listed` is durable (#258).
    /// The passkey lock is held across the append. The rows carry the
    /// short id and the two timestamps, never a credential id, a
    /// fingerprint, or a public key.
    pub(crate) fn list_passkeys(
        &self,
        channel: PasskeyChannel,
    ) -> Result<Vec<crate::owner::PasskeyRow>, PasskeyOpError> {
        let guard = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
        let fingerprints: Vec<String> = guard
            .credentials()
            .iter()
            .map(|c| store::fingerprint(&c.id))
            .collect();
        self.audit
            .passkey_listed(PasskeyListed {
                channel: channel.as_str(),
                credential_fingerprints: fingerprints,
                passkey_count: guard.credentials().len() as u64,
            })
            .map_err(|_| PasskeyOpError::Audit)?;
        Ok(guard
            .credentials()
            .iter()
            .map(|c| crate::owner::PasskeyRow {
                id: store::short_id(&c.id),
                enrolled_at: rfc3339(c.enrolled_at),
                last_used_at: rfc3339(c.last_used_at),
            })
            .collect())
    }

    /// Remove one passkey after `passkey_removed` is durable, then end
    /// every session opened with it (#258). The web UI refuses when it
    /// is the last passkey and writes no entry. A failed append or a
    /// failed write leaves the passkey and its sessions in place.
    pub(crate) fn remove_passkey(
        &self,
        channel: PasskeyChannel,
        id: &str,
    ) -> Result<(), PasskeyOpError> {
        if !store::valid_short_id(id) {
            return Err(PasskeyOpError::BadId);
        }
        let mut guard = self.passkeys.lock().unwrap_or_else(|p| p.into_inner());
        let matches: Vec<usize> = guard
            .credentials()
            .iter()
            .enumerate()
            .filter(|(_, c)| store::short_id(&c.id) == id)
            .map(|(i, _)| i)
            .collect();
        let index = match matches.as_slice() {
            [] => return Err(PasskeyOpError::NotFound),
            [index] => *index,
            _ => return Err(PasskeyOpError::Ambiguous),
        };
        if channel == PasskeyChannel::WebUi && guard.credentials().len() == 1 {
            return Err(PasskeyOpError::LastPasskey);
        }
        let credential_id = guard.credentials()[index].id.clone();
        let passkey_count = guard.credentials().len() as u64 - 1;
        self.audit
            .passkey_removed(PasskeyRemoved {
                channel: channel.as_str(),
                credential_fingerprint: store::fingerprint(&credential_id),
                passkey_count,
            })
            .map_err(|_| PasskeyOpError::Audit)?;
        guard
            .remove(&credential_id)
            .map_err(|_| PasskeyOpError::Store)?;
        drop(guard);
        self.end_sessions_for(&credential_id);
        Ok(())
    }

    /// The signed-in passkey list (#258). A missing session is the
    /// same 401 as the grants list, and is not an auth failure.
    /// Listing writes `passkey_listed` on `web_ui` before the rows
    /// are returned.
    fn passkeys_list(&self, req: &Incoming) -> Response {
        if !self.session_alive(req.cookie.as_deref()) {
            return respond(StatusCode::UNAUTHORIZED, "unauthenticated", None);
        }
        match self.list_passkeys(PasskeyChannel::WebUi) {
            Ok(rows) => json_body(
                StatusCode::OK,
                json!({"ok": true, "passkeys": rows}).to_string(),
                None,
            ),
            Err(PasskeyOpError::Audit) => {
                respond(StatusCode::INTERNAL_SERVER_ERROR, "audit_failed", None)
            }
            Err(_) => respond(StatusCode::INTERNAL_SERVER_ERROR, "store_failed", None),
        }
    }

    /// Remove one passkey from the signed-in page (#258). The last
    /// passkey is refused, so the page cannot end the session it is
    /// using by removing every way back in.
    fn passkeys_remove(&self, req: &Incoming) -> Response {
        if let Some(err) = self.gate_owner_post(req) {
            return err;
        }
        let Ok(body) = serde_json::from_slice::<PasskeyRemoveBody>(&req.body) else {
            return respond(StatusCode::BAD_REQUEST, "bad_request", None);
        };
        match self.remove_passkey(PasskeyChannel::WebUi, &body.id) {
            Ok(()) => json_body(StatusCode::OK, json!({"ok": true}).to_string(), None),
            Err(e) => passkey_error(e),
        }
    }
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// RFC3339 UTC, or `None` when the store has no timestamp.
fn rfc3339(secs: Option<i64>) -> Option<String> {
    let secs = secs?;
    let dt = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    dt.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// Why a verified registration was not stored.
#[derive(Debug)]
enum EnrollStore {
    /// The `passkey_enrolled` entry was not appended. Nothing was stored.
    Audit,
    /// The passkey file could not be written, or the id was already stored.
    Store,
}

#[derive(Clone, Copy)]
enum Decision {
    Approve,
    Deny,
}

/// Which Connections-page action a POST route runs (#233).
#[derive(Clone, Copy)]
enum ConnectAction {
    Disconnect,
    Unsuspend,
}

/// Body of a Connections-page action. Unknown keys are refused.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentBody {
    agent_id: String,
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

/// Body of `/owner/passkeys/remove`. The id is the short id from the list.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyRemoveBody {
    id: String,
}

/// A passkey-op refusal as its fixed code and status.
fn passkey_error(e: PasskeyOpError) -> Response {
    let (status, code) = match e {
        PasskeyOpError::BadId => (StatusCode::BAD_REQUEST, "bad_request"),
        PasskeyOpError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
        PasskeyOpError::Ambiguous | PasskeyOpError::LastPasskey => (StatusCode::CONFLICT, e.code()),
        PasskeyOpError::Audit => (StatusCode::INTERNAL_SERVER_ERROR, "audit_failed"),
        PasskeyOpError::Store => (StatusCode::INTERNAL_SERVER_ERROR, "store_failed"),
    };
    respond(status, code, None)
}

impl PasskeyOpError {
    fn code(self) -> &'static str {
        match self {
            Self::Audit => "audit_failed",
            Self::NotFound => "not_found",
            Self::Ambiguous => "ambiguous",
            Self::LastPasskey => "last_passkey",
            Self::BadId => "bad_request",
            Self::Store => "store_failed",
        }
    }
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
        F::UnlockFailed | F::ScopeTooBroad => StatusCode::BAD_REQUEST,
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

fn session_hash(name: &str, cookie_header: Option<&str>) -> Option<[u8; 32]> {
    let token = cookie_value(cookie_header, name)?;
    Some(sha256(token.as_bytes()))
}

fn cookie_value(header: Option<&str>, name: &str) -> Option<String> {
    let header = header?;
    for part in header.split(';') {
        let part = part.trim();
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        if k.trim() == name {
            return Some(v.trim().to_owned());
        }
    }
    None
}

fn session_cookie(name: &str, token: &str, secure: bool) -> String {
    let mut c = format!(
        "{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn clear_cookie(name: &str, secure: bool) -> String {
    let mut c = format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
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

/// `429` for a source over the failure limit; `Retry-After` counts to
/// the end of its window, rounded up, at least one second.
fn rate_limited(left: Duration) -> Response {
    let seconds = left.as_secs() + u64::from(left.subsec_nanos() > 0);
    let mut response = respond(StatusCode::TOO_MANY_REQUESTS, "rate_limited", None);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(seconds.max(1)));
    response
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
function tooMany(resp) {
  const secs = Number(resp.headers.get("retry-after"));
  const mins = Math.ceil((secs > 0 ? secs : 600) / 60);
  return "Too many failed attempts from this network. Try again in " + mins + " min.";
}
window.kharonSignIn = async function () {
  const err = document.getElementById("err");
  err.textContent = "";
  const opt = await fetch("/owner/login/options", { method: "POST", credentials: "same-origin" });
  if (opt.status === 429) { err.textContent = tooMany(opt); return false; }
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
  if (fin.status === 429) { err.textContent = tooMany(fin); return false; }
  if (!fin.ok) { err.textContent = "Sign-in refused"; return false; }
  return true;
};
document.getElementById("signin").addEventListener("click", async () => {
  if (await window.kharonSignIn()) location.assign({next});
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
function tooMany(resp) {
  const secs = Number(resp.headers.get("retry-after"));
  const mins = Math.ceil((secs > 0 ? secs : 600) / 60);
  return "Too many failed attempts from this network. Try again in " + mins + " min.";
}
window.kharonRegister = async function (code) {
  const err = document.getElementById("err");
  err.textContent = "";
  const opt = await fetch("/owner/register/options", {
    method: "POST",
    credentials: "same-origin",
    headers: { "authorization": "Bearer " + code }
  });
  if (opt.status === 429) { err.textContent = tooMany(opt); return false; }
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
  if (fin.status === 429) { err.textContent = tooMany(fin); return false; }
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

fn login_page(next_path: &str) -> String {
    let next = serde_json::to_string(next_path).expect("a path serializes");
    LOGIN_PAGE.replace("{next}", &next)
}

fn shell_page(locked: &str, pending: usize) -> String {
    render_shell(locked, pending, "")
}

/// The signed-in shell with the consent script filled in. `{connect}`
/// is substituted last so the script is not scanned for `{locked}`
/// or `{pending}`.
fn consent_shell(locked: &str, pending: usize, connect: &str) -> String {
    render_shell(locked, pending, connect)
}

fn render_shell(locked: &str, pending: usize, connect: &str) -> String {
    SHELL_PAGE
        .replace("{locked}", locked)
        .replace("{pending}", &pending.to_string())
        .replace("{connect}", connect)
}

/// The signed-in shell: broker state, the approvals queue (#131
/// slice 1), the live grants (slice 2), the panic button (slice 3,
/// two clicks: arm, then confirm), the audit tail (slice 4), the
/// passkey list (#258) and the Connections page (#233). The passkey
/// list is fetched once, not on the 5 s refresh: each fetch writes
/// an audit entry.
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
<section id="connect" hidden>
<h2>Connect a dashboard</h2>
<p id="connect-who"></p>
<p id="connect-hosts"></p>
<div id="connect-scopes"></div>
<p id="connect-notice">Connecting does not let it sign in anywhere on its own. Every sign-in still needs your approval in kharon.</p>
<p><button id="connect-approve" type="button">Connect</button>
<button id="connect-deny" type="button">Don't connect</button></p>
<p id="connect-err" class="err" role="alert"></p>
</section>
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
<h2>Connections</h2>
<p id="connections-empty">No dashboards connected.</p>
<table id="connections" hidden>
<thead><tr><th>Identity</th><th>Client</th><th>Host</th><th>Scopes</th><th>Connected</th><th>Channel</th><th></th></tr></thead>
<tbody id="connection-rows"></tbody>
</table>
<h2>Audit</h2>
<p id="audit-empty">No audit entries yet.</p>
<table id="audit" hidden>
<thead><tr><th>Seq</th><th>Time</th><th>Event</th><th>Agent</th><th>Origin</th><th>Result</th><th>Channel</th></tr></thead>
<tbody id="audit-rows"></tbody>
</table>
<h2>Passkeys</h2>
<p id="passkeys-empty">No passkeys.</p>
<table id="passkeys" hidden>
<thead><tr><th>Id</th><th>Enrolled</th><th>Last used</th><th></th></tr></thead>
<tbody id="passkey-rows"></tbody>
</table>
<p>Removing the last passkey is refused here. Use <code>kharon passkey remove</code> on the box for that.</p>
<h2>Panic</h2>
<p>Lock the broker and revoke every grant. Fills stop until the next unlock. A panic also ends every dashboard connection, so each dashboard has to click Connect again.</p>
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
    tr.append(cell(g.agent_name ? g.agent_name + " (" + g.agent_id + ")" : g.agent_id), cell(scope), cell(g.origin, "origin"), cell(g.actions.join(", ")), cell(uses), cell(g.expires_at));
    const actions = document.createElement("td");
    actions.append(button("Revoke", () => decide("/owner/grants/revoke", { grant_id: g.id })));
    tr.append(actions);
    rows.append(tr);
  }
  document.getElementById("grants").hidden = data.grants.length === 0;
  document.getElementById("grants-empty").hidden = data.grants.length !== 0;
}
async function refreshConnections() {
  const r = await fetch("/owner/connections", { credentials: "same-origin" });
  if (r.status === 401) { location.assign("/"); return; }
  if (!r.ok) return;
  const data = await r.json();
  const rows = document.getElementById("connection-rows");
  rows.replaceChildren();
  for (const c of data.connections) {
    const tr = document.createElement("tr");
    tr.dataset.agentId = c.agent_id;
    tr.append(cell(c.agent_id), cell(c.client_name), cell(c.host || "", "origin"),
      cell(c.scopes.join(", ")), cell(c.connected_at), cell(c.channel));
    const actions = document.createElement("td");
    if (c.suspended) {
      actions.append(button("Unsuspend", () => decide("/owner/connections/unsuspend", { agent_id: c.agent_id })), " ");
    }
    actions.append(button("Disconnect", () => decide("/owner/connections/disconnect", { agent_id: c.agent_id })));
    tr.append(actions);
    rows.append(tr);
  }
  document.getElementById("connections").hidden = data.connections.length === 0;
  document.getElementById("connections-empty").hidden = data.connections.length !== 0;
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
    tr.append(cell(String(e.seq)), cell(e.ts), cell(e.event), cell(e.agent_name ? e.agent_name + " (" + (e.agent_id || "") + ")" : (e.agent_id || "")),
      cell(e.live_origin || e.origin || "", "origin"), cell(result), cell(e.channel || ""));
    rows.append(tr);
  }
  document.getElementById("audit").hidden = data.entries.length === 0;
  document.getElementById("audit-empty").hidden = data.entries.length !== 0;
}
function dash(v) { return v || "\u2014"; }
async function refreshPasskeys() {
  const r = await fetch("/owner/passkeys", { credentials: "same-origin" });
  if (r.status === 401) { location.assign("/"); return; }
  if (!r.ok) {
    let code = "error";
    try { code = (await r.json()).error || code; } catch (e) {}
    document.getElementById("err").textContent = "Passkeys: " + code;
    return;
  }
  const data = await r.json();
  const rows = document.getElementById("passkey-rows");
  rows.replaceChildren();
  for (const p of data.passkeys) {
    const tr = document.createElement("tr");
    tr.dataset.passkeyId = p.id;
    tr.append(cell(p.id), cell(dash(p.enrolled_at)), cell(dash(p.last_used_at)));
    const actions = document.createElement("td");
    actions.append(button("Remove", async () => {
      const err = document.getElementById("err");
      err.textContent = "";
      const resp = await fetch("/owner/passkeys/remove", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: p.id }),
      });
      if (resp.status === 401) { location.assign("/"); return; }
      if (!resp.ok) {
        let code = "error";
        try { code = (await resp.json()).error || code; } catch (e) {}
        err.textContent = code === "last_passkey"
          ? "Not done: last_passkey: use kharon passkey remove on the box to remove the last passkey"
          : "Not done: " + code;
        return;
      }
      await refreshPasskeys();
    }));
    tr.append(actions);
    rows.append(tr);
  }
  document.getElementById("passkeys").hidden = data.passkeys.length === 0;
  document.getElementById("passkeys-empty").hidden = data.passkeys.length !== 0;
}
window.kharonRefresh = async function () {
  await refreshGrants();
  await refreshConnections();
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
    tr.append(cell(p.agent_name ? p.agent_name + " (" + p.agent_id + ")" : p.agent_id), cell(p.action), cell(p.origin, "origin"), cell(p.item_id), cell(p.age_s + " s"));
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
    panicButton.textContent = "Confirm panic: lock, revoke all, disconnect every dashboard";
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
    // #243: the one refusal the owner can fix gets its hint (the
    // same text as owner::SCOPE_TOO_BROAD_HINT, pinned by a test).
    err.textContent = code === "scope_too_broad"
      ? "Not done: scope_too_broad: the kharon account can see items or organizations outside its kharon organization (personal-vault items count). Move or delete them in Bitwarden, then unlock again."
      : "Not done: " + code;
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
refreshPasskeys();
window.kharonRefresh();
setInterval(window.kharonRefresh, 5000);
</script>
{connect}
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::oauth::Discovery;

    /// Discovery only. These tests serve the metadata document and
    /// do not admit a client.
    fn metadata_oauth(discovery: Discovery) -> OauthAs {
        OauthAs {
            discovery: Arc::new(discovery),
        }
    }

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
    fn a_nameless_cookie_part_does_not_hide_the_rest() {
        assert_eq!(
            cookie_value(Some("x; name=v"), "name").as_deref(),
            Some("v")
        );
        assert_eq!(
            cookie_value(Some("name=v; x"), "name").as_deref(),
            Some("v")
        );
        assert_eq!(cookie_value(Some("x; y"), "name"), None);
    }

    #[test]
    fn edge_exempt_lists_the_redeem_routes_and_the_oauth_paths() {
        for path in ["/owner/approve/abc", "/owner/deny/abc"] {
            assert!(edge_exempt(path), "{path}");
            assert!(redeem_exempt(path), "{path}");
        }
        // The RFC 8414 metadata path is exempt from Access and
        // `Origin`, but it is the UI's own route, not a redeem route:
        // the routing has to tell the two apart.
        assert!(edge_exempt(AUTHORIZATION_SERVER_PATH));
        assert!(!redeem_exempt(AUTHORIZATION_SERVER_PATH));
        // The OAuth token endpoints are on the same list for the
        // same reason (REQ-OAU-008), and route the same way.
        for path in [oauth_token::TOKEN_PATH, oauth_token::REVOKE_PATH] {
            assert!(edge_exempt(path), "{path}");
            assert!(!redeem_exempt(path), "{path}");
        }
        for path in [
            "/owner/approvals/approve",
            "/owner/login/finish",
            "/",
            "/oauth/authorize",
            "/oauth/token/",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server/",
        ] {
            assert!(!edge_exempt(path), "{path}");
        }
    }

    #[test]
    fn oauth_metadata_route_serves_the_golden_document() {
        // REQ-OAU-001: the owner hostname is the authorization
        // server. Its RFC 8414 metadata is public (no session) and
        // exists only with `[oauth]` set.
        let dir = tempfile::tempdir().unwrap();
        let shell = Arc::new(StaticShell(ShellView {
            locked: true,
            pending: 0,
        }));
        let mk = |oauth: Option<OauthAs>| {
            OwnerUi::open_with(
                dir.path(),
                OwnerUiOptions {
                    rp_id: "kharon-owner.example.com".into(),
                    origin: "https://kharon-owner.example.com".into(),
                    public: true,
                    access: None,
                    oauth,
                    admission: None,
                    oauth_tokens: None,
                },
                shell.clone(),
                Arc::new(NoAudit),
                Arc::new(NoApprovals),
            )
            .unwrap()
        };
        let call = |ui: &OwnerUi, method: Method, origin: Option<&str>| {
            ui.dispatch(Incoming {
                method,
                path: AUTHORIZATION_SERVER_PATH.into(),
                cookie: None,
                origin: origin.map(str::to_owned),
                authorization: None,
                content_type: None,
                body: Vec::new(),
                client_ip: None,
                throttle_key: None,
                query: None,
            })
        };
        // Without `[oauth]`: an unknown route, like any other.
        let ui = mk(None);
        assert_eq!(call(&ui, Method::GET, None).status(), StatusCode::NOT_FOUND);
        // With it: the golden document, and GET only.
        let discovery = Discovery::new(
            "https://kharon-owner.example.com".to_owned(),
            "kharon.example.com",
        );
        let ui = mk(Some(metadata_oauth(discovery.clone())));
        let response = call(&ui, Method::GET, None);
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&futures_body(response)).unwrap();
        assert_eq!(body, discovery.authorization_server_metadata());
        assert_eq!(
            call(&ui, Method::POST, Some("https://kharon-owner.example.com")).status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }

    // ---- OAuth token endpoints (#231; REQ-OAU-004/-005/-008) ----

    use crate::api::oauth_store::{ConnectLifecycle, OauthStore};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// The store's lifecycle seam, recorded.
    #[derive(Default)]
    struct RecLifecycle {
        entries: StdMutex<Vec<crate::audit::Entry>>,
        ended: StdMutex<Vec<String>>,
        fail_append: StdMutex<bool>,
    }

    impl ConnectLifecycle for RecLifecycle {
        fn append(&self, entry: crate::audit::Entry) -> bool {
            if *self.fail_append.lock().unwrap() {
                return false;
            }
            self.entries.lock().unwrap().push(entry);
            true
        }
        fn connect_ended(&self, agent_id: &str) {
            self.ended.lock().unwrap().push(agent_id.to_owned());
        }
    }

    impl RecLifecycle {
        fn events(&self) -> Vec<(String, Option<String>)> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .map(|e| (e.event.as_str().to_owned(), e.detail_code.clone()))
                .collect()
        }
    }

    /// The authorize side's code store (#230), faked at the seam.
    #[derive(Default)]
    struct FakeCodes(StdMutex<HashMap<String, oauth_token::RedeemedCode>>);

    impl oauth_token::CodeRedeemer for FakeCodes {
        fn redeem(&self, plaintext: &str) -> Option<oauth_token::RedeemedCode> {
            self.0.lock().unwrap().remove(plaintext)
        }
    }

    struct TokenFixture {
        ui: Arc<OwnerUi>,
        store: Arc<OauthStore>,
        codes: Arc<FakeCodes>,
        lifecycle: Arc<RecLifecycle>,
    }

    fn open_token_ui(
        dir: &Path,
        store: Arc<OauthStore>,
        codes: Option<Arc<dyn oauth_token::CodeRedeemer>>,
    ) -> Arc<OwnerUi> {
        let oauth_tokens = codes.map(|codes| oauth_token::TokenSide::with_codes(store, codes));
        let discovery = Discovery::new(
            "https://kharon-owner.example.com".to_owned(),
            "kharon.example.com",
        );
        OwnerUi::open_with(
            dir,
            OwnerUiOptions {
                rp_id: "kharon-owner.example.com".into(),
                origin: "https://kharon-owner.example.com".into(),
                public: true,
                access: None,
                oauth: Some(metadata_oauth(discovery)),
                admission: None,
                oauth_tokens,
            },
            Arc::new(StaticShell(ShellView {
                locked: false,
                pending: 0,
            })),
            Arc::new(NoAudit),
            Arc::new(NoApprovals),
        )
        .unwrap()
    }

    fn token_fixture(dir: &Path, with_side: bool) -> TokenFixture {
        let store = Arc::new(OauthStore::load(dir).unwrap());
        let lifecycle = Arc::new(RecLifecycle::default());
        store.set_lifecycle(lifecycle.clone());
        let codes = Arc::new(FakeCodes::default());
        let ui = open_token_ui(
            dir,
            store.clone(),
            with_side.then(|| codes.clone() as Arc<dyn oauth_token::CodeRedeemer>),
        );
        TokenFixture {
            ui,
            store,
            codes,
            lifecycle,
        }
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A code bound to `verifier`'s PKCE challenge, the dashboard
    /// client and redirect the token tests present.
    fn redeemed_code(verifier: &str) -> oauth_token::RedeemedCode {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let challenge = Base64UrlUnpadded::encode_string(&sha256(verifier.as_bytes()));
        oauth_token::RedeemedCode {
            client_id: "https://dashboard.example/.well-known/kharon-client.json".to_owned(),
            client_name: "Dashboard".to_owned(),
            redirect_uri: "https://dashboard.example/cb".to_owned(),
            code_challenge: challenge,
            scopes: vec!["kharon:read".to_owned()],
            consented_at: unix_now(),
        }
    }

    /// Insert a code on the fake authorize side, bound to
    /// `verifier`'s PKCE challenge.
    fn plant_code(fx: &TokenFixture, code: &str, verifier: &str) {
        fx.codes
            .0
            .lock()
            .unwrap()
            .insert(code.to_owned(), redeemed_code(verifier));
    }

    fn assert_no_live_connect(dir: &Path) {
        let path = dir.join("oauth").join("state.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        let state: Value = serde_json::from_str(&text).unwrap();
        let live = state["identities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["revoked"].as_bool() == Some(false));
        assert!(!live, "{text}");
    }

    fn oauth_err(response: Response) -> String {
        let status = response.status();
        let body = futures_body(response);
        serde_json::from_str::<Value>(&body).unwrap_or_else(|_| {
            panic!("status {status}, body {body}");
        })["error"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
        fn enc(s: &str) -> String {
            s.bytes()
                .map(|b| match b {
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect()
        }
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes()
    }

    fn post_token(
        ui: &OwnerUi,
        path: &str,
        body: Vec<u8>,
        origin: Option<&str>,
        throttle_key: Option<std::net::IpAddr>,
    ) -> Response {
        ui.dispatch(Incoming {
            method: Method::POST,
            path: path.into(),
            cookie: None,
            origin: origin.map(str::to_owned),
            authorization: None,
            content_type: Some("application/x-www-form-urlencoded".into()),
            body,
            client_ip: None,
            throttle_key,
            query: None,
        })
    }

    fn code_form(code: &str, verifier: &str, resource: &str) -> Vec<u8> {
        form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            (
                "client_id",
                "https://dashboard.example/.well-known/kharon-client.json",
            ),
            ("redirect_uri", "https://dashboard.example/cb"),
            ("code_verifier", verifier),
            ("resource", resource),
        ])
    }

    #[test]
    fn oauth_token_endpoints_404_without_the_token_side() {
        let dir = tempfile::tempdir().unwrap();
        let fx = token_fixture(dir.path(), false);
        for path in [oauth_token::TOKEN_PATH, oauth_token::REVOKE_PATH] {
            let r = post_token(&fx.ui, path, form(&[("token", "x")]), None, None);
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[test]
    fn oauth_token_redeems_rotates_and_revokes() {
        let dir = tempfile::tempdir().unwrap();
        let fx = token_fixture(dir.path(), true);
        plant_code(&fx, "code-1", "verifier-1");
        // The audience pin (D4): the `/connector` resource is
        // refused, and the refusal does not spend the code.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            code_form(
                "code-1",
                "verifier-1",
                "https://kharon.example.com/connector",
            ),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<Value>(&futures_body(r)).unwrap()["error"],
            "invalid_target"
        );
        // Redemption issues the pair (D6 shape), `no-store` on it.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            code_form("code-1", "verifier-1", "https://kharon.example.com/mcp"),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers().get("cache-control").unwrap(), "no-store");
        let body: Value = serde_json::from_str(&futures_body(r)).unwrap();
        let access = body["access_token"].as_str().unwrap().to_owned();
        let refresh = body["refresh_token"].as_str().unwrap().to_owned();
        assert!(access.starts_with("kh_at_"), "{access}");
        assert!(refresh.starts_with("kh_rt_"), "{refresh}");
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 3600);
        assert_eq!(body["scope"], "kharon:read");
        let auth = fx.store.authenticate_access(&access, unix_now()).unwrap();
        assert!(auth.agent_id.starts_with("c-"), "{}", auth.agent_id);
        // Refresh rotates.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                (
                    "client_id",
                    "https://dashboard.example/.well-known/kharon-client.json",
                ),
            ]),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&futures_body(r)).unwrap();
        let access2 = body["access_token"].as_str().unwrap().to_owned();
        let refresh2 = body["refresh_token"].as_str().unwrap().to_owned();
        assert_ne!(access2, access);
        assert_ne!(refresh2, refresh);
        // Revoking the access token ends only itself.
        let r = post_token(
            &fx.ui,
            oauth_token::REVOKE_PATH,
            form(&[("token", &access2)]),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(futures_body(r), "");
        assert!(fx.store.authenticate_access(&access2, unix_now()).is_none());
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh2),
                (
                    "client_id",
                    "https://dashboard.example/.well-known/kharon-client.json",
                ),
            ]),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&futures_body(r)).unwrap();
        let refresh3 = body["refresh_token"].as_str().unwrap().to_owned();
        // Revoking the refresh token ends the whole Connect.
        let r = post_token(
            &fx.ui,
            oauth_token::REVOKE_PATH,
            form(&[("token", &refresh3)]),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh3),
                (
                    "client_id",
                    "https://dashboard.example/.well-known/kharon-client.json",
                ),
            ]),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            fx.lifecycle.ended.lock().unwrap().as_slice(),
            [auth.agent_id]
        );
    }

    #[test]
    fn oauth_token_refresh_requires_the_issuing_client() {
        let dir = tempfile::tempdir().unwrap();
        let fx = token_fixture(dir.path(), true);
        plant_code(&fx, "code-7", "verifier-7");
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            code_form("code-7", "verifier-7", "https://kharon.example.com/mcp"),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&futures_body(r)).unwrap();
        let refresh = body["refresh_token"].as_str().unwrap().to_owned();
        // No client_id at all: `invalid_request`.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)]),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<Value>(&futures_body(r)).unwrap()["error"],
            "invalid_request"
        );
        // The wrong client: `invalid_grant`, and nothing is spent —
        // the issuing client still rotates with the same token.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                (
                    "client_id",
                    "https://other.example/.well-known/kharon-client.json",
                ),
            ]),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<Value>(&futures_body(r)).unwrap()["error"],
            "invalid_grant"
        );
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                (
                    "client_id",
                    "https://dashboard.example/.well-known/kharon-client.json",
                ),
            ]),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn oauth_token_refusals_are_oauth_shaped() {
        let dir = tempfile::tempdir().unwrap();
        let fx = token_fixture(dir.path(), true);
        plant_code(&fx, "code-9", "right-verifier");
        let err = |r: Response| {
            serde_json::from_str::<Value>(&futures_body(r)).unwrap()["error"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        // Wrong PKCE verifier.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            code_form("code-9", "wrong-verifier", "https://kharon.example.com/mcp"),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(err(r), "invalid_grant");
        // Unknown code.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            code_form("nope", "v", "https://kharon.example.com/mcp"),
            None,
            None,
        );
        assert_eq!(err(r), "invalid_grant");
        // Unknown grant type, and a missing parameter.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[("grant_type", "password")]),
            None,
            None,
        );
        assert_eq!(err(r), "unsupported_grant_type");
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[("grant_type", "refresh_token")]),
            None,
            None,
        );
        assert_eq!(err(r), "invalid_request");
        // Wrong method on a wired endpoint.
        let r = fx.ui.dispatch(Incoming {
            method: Method::GET,
            path: oauth_token::TOKEN_PATH.into(),
            cookie: None,
            origin: None,
            authorization: None,
            content_type: None,
            body: Vec::new(),
            client_ip: None,
            throttle_key: None,
            query: None,
        });
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// The production composition (#268 + #231): a token side
    /// built `unwired` is bound at open to the UI's own code
    /// store, so a code the authorize side issued redeems at the
    /// token endpoint for real. A panic drops unredeemed codes
    /// (REQ-OAU-005): the broker's panic hook calls
    /// `OwnerUi::invalidate_sealed`, which clears the store.
    #[test]
    fn oauth_token_redeems_through_the_real_code_store() {
        use base64ct::{Base64UrlUnpadded, Encoding};

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(OauthStore::load(dir.path()).unwrap());
        store.set_lifecycle(Arc::new(RecLifecycle::default()));
        let discovery = Discovery::new(
            "https://kharon-owner.example.com".to_owned(),
            "kharon.example.com",
        );
        let ui = OwnerUi::open_with(
            dir.path(),
            OwnerUiOptions {
                rp_id: "kharon-owner.example.com".into(),
                origin: "https://kharon-owner.example.com".into(),
                public: true,
                access: None,
                oauth: Some(metadata_oauth(discovery)),
                admission: None,
                oauth_tokens: Some(oauth_token::TokenSide::unwired(Arc::clone(&store))),
            },
            Arc::new(StaticShell(ShellView {
                locked: false,
                pending: 0,
            })),
            Arc::new(NoAudit),
            Arc::new(NoApprovals),
        )
        .unwrap();
        // Issue from the UI's own code store, the way consent
        // approval does: bound to the verifier's PKCE challenge,
        // the dashboard's client and redirect, this deploy's
        // resource.
        let issue = |verifier: &str| {
            let challenge = Base64UrlUnpadded::encode_string(&sha256(verifier.as_bytes()));
            ui.codes
                .issue(
                    oauth::CodeBody {
                        client_id: "https://dashboard.example/.well-known/kharon-client.json"
                            .to_owned(),
                        client_name: "Dashboard".to_owned(),
                        redirect_uri: "https://dashboard.example/cb".to_owned(),
                        code_challenge: challenge,
                        resource: "https://kharon.example.com/mcp".to_owned(),
                        scopes: vec![oauth::Scope::Read],
                        consented_at: unix_now(),
                    },
                    Instant::now(),
                )
                .unwrap()
        };
        let code = issue("verifier-real");
        let r = post_token(
            &ui,
            oauth_token::TOKEN_PATH,
            code_form(&code, "verifier-real", "https://kharon.example.com/mcp"),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&futures_body(r)).unwrap();
        let access = body["access_token"].as_str().unwrap();
        assert!(store.authenticate_access(access, unix_now()).is_some());
        // A second code, unredeemed when the panic lands, is
        // gone: the redemption fails closed with `invalid_grant`.
        let code = issue("verifier-lost");
        ui.invalidate_sealed();
        let r = post_token(
            &ui,
            oauth_token::TOKEN_PATH,
            code_form(&code, "verifier-lost", "https://kharon.example.com/mcp"),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_str::<Value>(&futures_body(r)).unwrap()["error"],
            "invalid_grant"
        );
    }

    #[test]
    fn oauth_token_second_redemption_revokes_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let fx = token_fixture(dir.path(), true);
        plant_code(&fx, "code-2", "verifier-2");
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            code_form("code-2", "verifier-2", "https://kharon.example.com/mcp"),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&futures_body(r)).unwrap();
        let access = body["access_token"].as_str().unwrap().to_owned();
        let auth = fx.store.authenticate_access(&access, unix_now()).unwrap();
        // The same code presented again (D4): refused, and
        // everything it issued is revoked.
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            code_form("code-2", "verifier-2", "https://kharon.example.com/mcp"),
            None,
            None,
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert!(fx.store.authenticate_access(&access, unix_now()).is_none());
        assert_eq!(
            fx.lifecycle.ended.lock().unwrap().as_slice(),
            [auth.agent_id]
        );
        let events: Vec<(String, Option<String>)> = fx
            .lifecycle
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| (e.event.as_str().to_owned(), e.detail_code.clone()))
            .collect();
        assert_eq!(
            events,
            [
                ("oauth_connect".to_owned(), None),
                ("oauth_disconnect".to_owned(), Some("code_reuse".to_owned())),
            ]
        );
    }

    /// Parks the first redemption after the code is taken and the
    /// pending marker is recorded, and before the Connect commits.
    struct ParkingCodes {
        codes: StdMutex<HashMap<String, oauth_token::RedeemedCode>>,
        parked: StdMutex<Option<std::sync::mpsc::Sender<()>>>,
        release: StdMutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl oauth_token::CodeRedeemer for ParkingCodes {
        fn redeem(&self, plaintext: &str) -> Option<oauth_token::RedeemedCode> {
            self.codes.lock().unwrap().remove(plaintext)
        }

        fn after_take(&self) {
            let tx = self.parked.lock().unwrap().take();
            let Some(tx) = tx else {
                return;
            };
            let _ = tx.send(());
            let rx = self.release.lock().unwrap().take();
            let Some(rx) = rx else {
                return;
            };
            rx.recv_timeout(Duration::from_secs(5))
                .expect("the racing redemption did not release the first");
        }
    }

    #[test]
    fn oauth_token_racing_second_redemption_leaves_no_connect() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(OauthStore::load(dir.path()).unwrap());
        let lifecycle = Arc::new(RecLifecycle::default());
        store.set_lifecycle(lifecycle.clone());
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let codes = Arc::new(ParkingCodes {
            codes: StdMutex::new(HashMap::new()),
            parked: StdMutex::new(Some(parked_tx)),
            release: StdMutex::new(Some(release_rx)),
        });
        codes
            .codes
            .lock()
            .unwrap()
            .insert("code-race".to_owned(), redeemed_code("verifier-race"));
        let ui = open_token_ui(
            dir.path(),
            store.clone(),
            Some(codes as Arc<dyn oauth_token::CodeRedeemer>),
        );
        let ui_first = Arc::clone(&ui);
        let first = std::thread::spawn(move || {
            post_token(
                &ui_first,
                oauth_token::TOKEN_PATH,
                code_form(
                    "code-race",
                    "verifier-race",
                    "https://kharon.example.com/mcp",
                ),
                None,
                None,
            )
        });
        parked_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first redemption did not park between take and commit");
        // The second presentation runs while the first is past the
        // take and not yet committed.
        let second = post_token(
            &ui,
            oauth_token::TOKEN_PATH,
            code_form(
                "code-race",
                "verifier-race",
                "https://kharon.example.com/mcp",
            ),
            None,
            None,
        );
        assert_eq!(second.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_err(second), "invalid_grant");
        release_tx.send(()).unwrap();
        let first = first.join().unwrap();
        assert_eq!(first.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_err(first), "invalid_grant");
        // The first had already been audited (I5) by the time it
        // observed the marker, so it compensates with `code_reuse`
        // and persists nothing.
        assert_eq!(
            lifecycle.events(),
            [
                ("oauth_connect".to_owned(), None),
                ("oauth_disconnect".to_owned(), Some("code_reuse".to_owned())),
            ]
        );
        assert!(lifecycle.ended.lock().unwrap().is_empty());
        assert_no_live_connect(dir.path());
        // The code stays spent.
        let third = post_token(
            &ui,
            oauth_token::TOKEN_PATH,
            code_form(
                "code-race",
                "verifier-race",
                "https://kharon.example.com/mcp",
            ),
            None,
            None,
        );
        assert_eq!(third.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_err(third), "invalid_grant");
        assert_eq!(lifecycle.events().len(), 2);
    }

    #[test]
    fn oauth_token_failed_redemption_stays_spent() {
        let resource = "https://kharon.example.com/mcp";
        let present =
            |ui: &OwnerUi, body: Vec<u8>| post_token(ui, oauth_token::TOKEN_PATH, body, None, None);
        let again = |ui: &OwnerUi, code: &str, verifier: &str| {
            let response = present(ui, code_form(code, verifier, resource));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(oauth_err(response), "invalid_grant");
        };

        // Bad PKCE. The code is spent; nothing is created.
        {
            let dir = tempfile::tempdir().unwrap();
            let fx = token_fixture(dir.path(), true);
            plant_code(&fx, "code-pkce", "right-verifier");
            let response = present(&fx.ui, code_form("code-pkce", "wrong-verifier", resource));
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(oauth_err(response), "invalid_grant");
            again(&fx.ui, "code-pkce", "right-verifier");
            assert!(fx.lifecycle.events().is_empty());
            assert!(fx.lifecycle.ended.lock().unwrap().is_empty());
            assert_no_live_connect(dir.path());
        }

        // Client mismatch.
        {
            let dir = tempfile::tempdir().unwrap();
            let fx = token_fixture(dir.path(), true);
            plant_code(&fx, "code-client", "verifier-client");
            let response = present(
                &fx.ui,
                form(&[
                    ("grant_type", "authorization_code"),
                    ("code", "code-client"),
                    (
                        "client_id",
                        "https://other.example/.well-known/kharon-client.json",
                    ),
                    ("redirect_uri", "https://dashboard.example/cb"),
                    ("code_verifier", "verifier-client"),
                    ("resource", resource),
                ]),
            );
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(oauth_err(response), "invalid_grant");
            again(&fx.ui, "code-client", "verifier-client");
            assert!(fx.lifecycle.events().is_empty());
            assert_no_live_connect(dir.path());
        }

        // Redirect mismatch.
        {
            let dir = tempfile::tempdir().unwrap();
            let fx = token_fixture(dir.path(), true);
            plant_code(&fx, "code-redir", "verifier-redir");
            let response = present(
                &fx.ui,
                form(&[
                    ("grant_type", "authorization_code"),
                    ("code", "code-redir"),
                    (
                        "client_id",
                        "https://dashboard.example/.well-known/kharon-client.json",
                    ),
                    ("redirect_uri", "https://dashboard.example/other"),
                    ("code_verifier", "verifier-redir"),
                    ("resource", resource),
                ]),
            );
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(oauth_err(response), "invalid_grant");
            again(&fx.ui, "code-redir", "verifier-redir");
            assert!(fx.lifecycle.events().is_empty());
            assert_no_live_connect(dir.path());
        }

        // Audit failure: nothing is created, and the code stays spent.
        {
            let dir = tempfile::tempdir().unwrap();
            let fx = token_fixture(dir.path(), true);
            plant_code(&fx, "code-audit", "verifier-audit");
            *fx.lifecycle.fail_append.lock().unwrap() = true;
            let response = present(&fx.ui, code_form("code-audit", "verifier-audit", resource));
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(oauth_err(response), "server_error");
            *fx.lifecycle.fail_append.lock().unwrap() = false;
            again(&fx.ui, "code-audit", "verifier-audit");
            assert!(fx.lifecycle.events().is_empty());
            assert_no_live_connect(dir.path());
        }

        // Persist failure: compensating disconnect, no live Connect,
        // and a later presentation is still refused.
        {
            let dir = tempfile::tempdir().unwrap();
            let fx = token_fixture(dir.path(), true);
            plant_code(&fx, "code-disk", "verifier-disk");
            std::fs::write(dir.path().join("oauth"), b"not a directory").unwrap();
            let response = present(&fx.ui, code_form("code-disk", "verifier-disk", resource));
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(oauth_err(response), "server_error");
            assert_eq!(
                fx.lifecycle.events(),
                [
                    ("oauth_connect".to_owned(), None),
                    (
                        "oauth_disconnect".to_owned(),
                        Some("persist_failed".to_owned())
                    ),
                ]
            );
            again(&fx.ui, "code-disk", "verifier-disk");
            assert_eq!(fx.lifecycle.events().len(), 2);
            assert!(fx.lifecycle.ended.lock().unwrap().is_empty());
            assert_no_live_connect(dir.path());
        }
    }

    #[test]
    fn oauth_token_paths_are_origin_exempt_and_throttled_per_source() {
        let dir = tempfile::tempdir().unwrap();
        let fx = token_fixture(dir.path(), true);
        // Exempt (#208): a foreign `Origin` does not refuse the
        // request — it is answered (here, an unknown code).
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            code_form("nope", "v", "https://kharon.example.com/mcp"),
            Some("https://unrelated.example"),
            None,
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        // Throttled per source (REQ-OAU-008): ten failures from one
        // source close it; the eleventh request is refused before
        // it is answered.
        let ip: std::net::IpAddr = "10.0.0.9".parse().unwrap();
        for _ in 0..10 {
            let r = post_token(
                &fx.ui,
                oauth_token::TOKEN_PATH,
                form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", "kh_rt_unknown"),
                    (
                        "client_id",
                        "https://dashboard.example/.well-known/kharon-client.json",
                    ),
                ]),
                None,
                Some(ip),
            );
            assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        }
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", "kh_rt_unknown"),
                (
                    "client_id",
                    "https://dashboard.example/.well-known/kharon-client.json",
                ),
            ]),
            None,
            Some(ip),
        );
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(r.headers().contains_key("retry-after"));
        // A different source is its own bucket.
        let other: std::net::IpAddr = "10.0.0.10".parse().unwrap();
        let r = post_token(
            &fx.ui,
            oauth_token::TOKEN_PATH,
            form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", "kh_rt_unknown"),
                (
                    "client_id",
                    "https://dashboard.example/.well-known/kharon-client.json",
                ),
            ]),
            None,
            Some(other),
        );
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
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
        let cookie = ui.issue_session(&[]);
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
            client_ip: None,
            throttle_key: None,
            query: None,
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
        let kept = ui.issue_session(&[]);
        let dropped = ui.issue_session(&[]);
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
            client_ip: None,
            throttle_key: None,
            query: None,
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
            client_ip: None,
            throttle_key: None,
            query: None,
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
            // #243: the account's scope is too broad (REQ-CRY-008).
            if password.as_str() == "scope" {
                return Err(crate::owner::OwnerFailure::ScopeTooBroad);
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
                agent_name: None,
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

        fn grants(&self) -> Vec<GrantRow> {
            vec![GrantRow {
                view: crate::api::grant::GrantView {
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
                },
                agent_name: None,
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

        /// One suspended Connect (#233).
        fn connections(&self) -> Vec<ConnectionRow> {
            vec![ConnectionRow {
                agent_id: "c-abcdefghij".into(),
                client_name: "Example Dashboard".into(),
                host: Some("dashboard.example".into()),
                scopes: vec!["kharon:read".into(), "kharon:fill".into()],
                connected_at: "2026-11-12T00:00:00Z".into(),
                channel: "oauth".into(),
                suspended: true,
            }]
        }

        /// `c-gone` is not found; anything else disconnects.
        fn disconnect(&self, agent_id: &str) -> Result<(), DecideError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("disconnect {agent_id}"));
            if agent_id == "c-gone" {
                return Err(DecideError::NotFound);
            }
            Ok(())
        }

        fn unsuspend(&self, agent_id: &str) -> Result<(), DecideError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("unsuspend {agent_id}"));
            Ok(())
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
        fn auth_failed(&self, failure: AuthFailure) {
            self.0.lock().unwrap().push(failure.detail);
        }

        fn suppressed_only(&self, _count: u64) {}

        fn passkey_enroll_code(&self) -> Result<(), OwnerAuditError> {
            Ok(())
        }

        fn passkey_enrolled(&self, _enrolled: PasskeyEnrolled) -> Result<(), OwnerAuditError> {
            Ok(())
        }

        fn passkey_listed(&self, _listed: PasskeyListed) -> Result<(), OwnerAuditError> {
            Ok(())
        }

        fn passkey_removed(&self, _removed: PasskeyRemoved) -> Result<(), OwnerAuditError> {
            Ok(())
        }
    }

    const ORIGIN: &str = "http://localhost:9";

    struct ApprovalsRig {
        /// The `Origin` the rig's posts carry.
        origin: &'static str,
        /// The source address of its requests (public mode only).
        client_ip: Option<IpAddr>,
        ui: Arc<OwnerUi>,
        fake: Arc<FakeApprovals>,
        audit: Arc<FailCodes>,
        cookie: String,
        _dir: tempfile::TempDir,
    }

    impl ApprovalsRig {
        fn new() -> Self {
            Self::build(false)
        }

        /// A public-mode UI whose requests come from `198.51.100.9`.
        fn public() -> Self {
            Self::build(true)
        }

        fn build(public: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let fake = Arc::new(FakeApprovals::default());
            let audit = Arc::new(FailCodes::default());
            let (rp_id, origin) = if public {
                ("owner.example.com", PUBLIC)
            } else {
                ("localhost", ORIGIN)
            };
            let ui = OwnerUi::open_with(
                dir.path(),
                OwnerUiOptions {
                    rp_id: rp_id.into(),
                    origin: origin.into(),
                    public,
                    access: None,
                    oauth: None,
                    admission: None,
                    oauth_tokens: None,
                },
                Arc::new(StaticShell(ShellView {
                    locked: false,
                    pending: 1,
                })),
                audit.clone(),
                fake.clone(),
            )
            .unwrap();
            let cookie = ui.issue_session(&[]).split(';').next().unwrap().to_owned();
            Self {
                origin,
                client_ip: public.then(|| "198.51.100.9".parse().unwrap()),
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
                client_ip: self.client_ip,
                throttle_key: self.client_ip,
                query: None,
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
                Some(self.origin),
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
    // ---- #233: Connections page ----

    #[test]
    fn connections_routes_are_listed() {
        for route in [
            ("GET", "/owner/connections"),
            ("POST", "/owner/connections/disconnect"),
            ("POST", "/owner/connections/unsuspend"),
        ] {
            assert!(ROUTES.contains(&route), "{route:?} missing from ROUTES");
        }
        let shell = shell_page("unlocked", 0);
        assert!(shell.contains("/owner/connections"), "no connections fetch");
        assert!(
            shell.contains("click Connect again"),
            "the panic text must say a panic means re-clicking Connect"
        );
        // Disconnect is a revoke-class action and Unsuspend its
        // reset: neither is on the sign-in throttle list
        // (REQ-APR-009).
        for path in [
            "/owner/connections/disconnect",
            "/owner/connections/unsuspend",
        ] {
            assert!(
                !throttle::THROTTLED_ROUTES.contains(&path),
                "{path} must not be throttled"
            );
        }
    }

    #[test]
    fn connections_list_renders_the_rows() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(Method::GET, "/owner/connections", true, None, None, "");
        assert_eq!(status, StatusCode::OK, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ok"], true);
        let c = &v["connections"][0];
        assert_eq!(c["agent_id"], "c-abcdefghij");
        assert_eq!(c["client_name"], "Example Dashboard");
        assert_eq!(c["host"], "dashboard.example");
        assert_eq!(c["scopes"], json!(["kharon:read", "kharon:fill"]));
        assert_eq!(c["connected_at"], "2026-11-12T00:00:00Z");
        assert_eq!(c["channel"], "oauth");
        assert_eq!(c["suspended"], true);
        assert!(rig.calls().is_empty(), "listing is read-only");
    }

    #[test]
    fn connections_list_needs_a_session() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(Method::GET, "/owner/connections", false, None, None, "");
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    #[test]
    fn connections_actions_reach_the_backend() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.post(
            "/owner/connections/disconnect",
            r#"{"agent_id":"c-abcdefghij"}"#,
        );
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = rig.post(
            "/owner/connections/unsuspend",
            r#"{"agent_id":"c-abcdefghij"}"#,
        );
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            rig.calls(),
            ["disconnect c-abcdefghij", "unsuspend c-abcdefghij"]
        );
        // An unknown Connect is the backend's not_found.
        let (status, body) = rig.post("/owner/connections/disconnect", r#"{"agent_id":"c-gone"}"#);
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(body.contains("not_found"), "{body}");
    }

    #[test]
    fn connections_posts_need_our_origin() {
        let rig = ApprovalsRig::new();
        let (status, body) = rig.send(
            Method::POST,
            "/owner/connections/disconnect",
            true,
            Some("https://evil.example"),
            Some("application/json"),
            r#"{"agent_id":"c-abcdefghij"}"#,
        );
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(rig.calls().is_empty(), "the gate runs first");
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

    /// #243: a scope refusal reaches the owner as its own code (and
    /// the page carries the hint for it), while the audit still
    /// records `unlock_failed`, as for a wrong password.
    #[test]
    fn unlock_scope_refusal_is_named_for_the_owner_and_audited_as_before() {
        let (rig, _unlock) = ApprovalsRig::with_unlock();
        let (id, key) = rig.begin();
        let (status, out) = rig.post("/owner/unlock", &ApprovalsRig::sealed(&id, &key, "scope"));
        assert_eq!(status, StatusCode::BAD_REQUEST, "{out}");
        assert!(out.contains("\"error\":\"scope_too_broad\""), "{out}");
        assert_eq!(*rig.audit.0.lock().unwrap(), ["unlock_failed"]);
        assert!(
            SHELL_PAGE.contains(crate::owner::SCOPE_TOO_BROAD_HINT),
            "the unlock page shows the hint for scope_too_broad"
        );
    }

    /// D5: a throttled source is told to wait, not that sign-in is broken
    /// or that its enrollment code was refused.
    #[test]
    fn the_sign_in_and_enroll_pages_explain_a_429() {
        for (name, page) in [("login", LOGIN_PAGE), ("enroll", ENROLL_PAGE)] {
            assert!(
                page.contains("Too many failed attempts from this network. Try again in "),
                "{name} page"
            );
            assert!(page.contains(".status === 429"), "{name} page");
            assert!(page.contains("retry-after"), "{name} page");
        }
    }

    /// D5: a completed unlock clears the source's count, so nine typos
    /// before it and nine after never add up to a 429.
    #[test]
    fn a_successful_unlock_clears_the_throttle_count() {
        let (rig, _unlock) = {
            let rig = ApprovalsRig::public();
            let unlock = Arc::new(FakeUnlock::default());
            assert!(rig.ui.set_unlocker(unlock.clone()));
            (rig, unlock)
        };
        let attempt = |password: &str| {
            let (id, key) = rig.begin();
            rig.post("/owner/unlock", &ApprovalsRig::sealed(&id, &key, password))
        };
        for i in 0..9 {
            let (status, out) = attempt("wrong");
            assert_eq!(status, StatusCode::BAD_REQUEST, "{i}: {out}");
        }
        let (status, out) = attempt("right horse");
        assert_eq!(status, StatusCode::OK, "{out}");
        for i in 0..9 {
            let (status, out) = attempt("wrong");
            assert_eq!(status, StatusCode::BAD_REQUEST, "after: {i}: {out}");
        }
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
        let other = rig
            .ui
            .issue_session(&[])
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let response = rig.ui.dispatch(Incoming {
            method: Method::POST,
            path: "/owner/unlock".into(),
            cookie: Some(other),
            origin: Some(ORIGIN.into()),
            authorization: None,
            content_type: Some("application/json".into()),
            body: body.as_bytes().to_vec(),
            client_ip: None,
            throttle_key: None,
            query: None,
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
    #[derive(serde::Deserialize)]
    struct OptionsReply {
        ceremony_id: String,
        #[serde(rename = "publicKey")]
        public_key: OptionsKey,
    }

    #[derive(serde::Deserialize)]
    struct OptionsKey {
        challenge: String,
    }

    #[derive(serde::Serialize)]
    struct FinishBody<'a> {
        ceremony_id: &'a str,
        credential: FinishCred,
    }

    #[derive(serde::Serialize)]
    struct FinishCred {
        id: String,
        #[serde(rename = "type")]
        kind: &'static str,
        response: FinishResponse,
    }

    #[derive(serde::Serialize)]
    struct FinishResponse {
        #[serde(rename = "clientDataJSON")]
        client_data_json: String,
        #[serde(rename = "authenticatorData")]
        authenticator_data: String,
        signature: String,
    }

    fn post_ui(ui: &OwnerUi, path: &str, body: &[u8]) -> (StatusCode, String) {
        let response = ui.dispatch(Incoming {
            method: Method::POST,
            path: path.into(),
            cookie: None,
            origin: Some(ORIGIN.into()),
            authorization: None,
            content_type: (!body.is_empty()).then(|| "application/json".to_owned()),
            body: body.to_vec(),
            client_ip: None,
            throttle_key: None,
            query: None,
        });
        let status = response.status();
        (status, futures_body(response))
    }

    #[test]
    fn req_apr_009_ceremony_creation_stores_nothing() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open(
            dir.path(),
            "localhost",
            ORIGIN,
            Arc::new(StaticShell(ShellView {
                locked: true,
                pending: 0,
            })),
            Arc::new(NoAudit),
            Arc::new(NoApprovals),
        )
        .unwrap();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let cred_id = vec![9u8; 16];
        ui.store_enrolled(RegisteredCredential {
            credential_id: cred_id.clone(),
            public_key: key.public_key().as_ref().try_into().unwrap(),
            sign_count: 0,
        })
        .unwrap();

        let (status, body) = post_ui(&ui, "/owner/login/options", b"");
        assert_eq!(status, StatusCode::OK, "{body}");
        let first: OptionsReply = serde_json::from_str(&body).unwrap();

        for i in 0..100_000 {
            let (status, _) = post_ui(&ui, "/owner/login/options", b"");
            assert_eq!(status, StatusCode::OK, "options #{i}");
        }

        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
            first.public_key.challenge
        );
        let mut auth = sha256(b"localhost").to_vec();
        auth.push(0x01 | 0x04);
        auth.extend_from_slice(&0u32.to_be_bytes());
        let mut message = auth.clone();
        message.extend_from_slice(&sha256(client.as_bytes()));
        let signature = key.sign(&SystemRandom::new(), &message).unwrap();
        let body = serde_json::to_vec(&FinishBody {
            ceremony_id: &first.ceremony_id,
            credential: FinishCred {
                id: b64url_encode(&cred_id),
                kind: "public-key",
                response: FinishResponse {
                    client_data_json: b64url_encode(client.as_bytes()),
                    authenticator_data: b64url_encode(&auth),
                    signature: b64url_encode(signature.as_ref()),
                },
            },
        })
        .unwrap();
        let (status, reply) = post_ui(&ui, "/owner/login/finish", &body);
        assert_eq!(status, StatusCode::OK, "{reply}");
    }

    #[test]
    fn a_ceremony_opened_before_a_panic_cannot_burn_after_it() {
        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open(
            dir.path(),
            "localhost",
            ORIGIN,
            Arc::new(StaticShell(ShellView {
                locked: true,
                pending: 0,
            })),
            Arc::new(NoAudit),
            Arc::new(NoApprovals),
        )
        .unwrap();
        let ceremony = ui.begin(CeremonyKind::Login);
        let (_, opened) = ui
            .open_ceremony(&ceremony.id, CeremonyKind::Login)
            .expect("opens");
        ui.invalidate_sealed();
        let req = Incoming {
            method: Method::POST,
            path: "/owner/login/finish".into(),
            cookie: None,
            origin: Some(ORIGIN.into()),
            authorization: None,
            content_type: None,
            body: Vec::new(),
            client_ip: None,
            throttle_key: None,
            query: None,
        };
        let refused = ui.burn_ceremony(&req, &opened).expect("refused");
        assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        assert!(
            ui.open_ceremony(&ceremony.id, CeremonyKind::Login)
                .is_none()
        );
    }

    /// #252: the sealed invalidation is a hook on the broker's
    /// panic, not a step in any caller. A panic invoked directly on
    /// the broker — no web route, no owner socket — kills an
    /// outstanding ceremony token, and every panic runs the hook.
    #[test]
    fn a_direct_broker_panic_kills_an_outstanding_ceremony() {
        use crate::api::token::TokenStore;
        use crate::api::{AuditSink, Broker};
        use crate::export::ExportSession;
        use crate::lock::{AuditError, LockController, LockPolicy, StaticHardening, SystemClock};
        use crate::origin::OriginConfig;

        struct NullSink;
        impl AuditSink for NullSink {
            fn append(&mut self, _entry: crate::audit::Entry) -> Result<(), AuditError> {
                Ok(())
            }
        }

        let (_token, hash) = crate::api::token::generate("alpha");
        let tokens = TokenStore::new([("alpha", hash.as_str())]).unwrap();
        let lock = LockController::<ExportSession, SystemClock>::new(
            LockPolicy {
                require_mlock: false,
                ..LockPolicy::default()
            },
            SystemClock,
            Box::new(StaticHardening::all_ok()),
        );
        let broker = Arc::new(Broker::new(
            tokens,
            lock,
            Box::new(NullSink),
            OriginConfig { allow_http: false },
        ));
        broker.wire_lock_audit();

        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open(
            dir.path(),
            "localhost",
            ORIGIN,
            Arc::new(StaticShell(ShellView {
                locked: true,
                pending: 0,
            })),
            Arc::new(NoAudit),
            broker.clone() as Arc<dyn OwnerApprovals>,
        )
        .unwrap();
        // The daemon's registration (`bind_owner_ui`), in miniature.
        let weak = Arc::downgrade(&ui);
        broker.add_panic_hook(Arc::new(move || {
            if let Some(ui) = weak.upgrade() {
                ui.invalidate_sealed();
            }
        }));

        let ceremony = ui.begin(CeremonyKind::Login);
        assert!(
            ui.open_ceremony(&ceremony.id, CeremonyKind::Login)
                .is_some(),
            "the token opens before the panic"
        );
        broker.panic_lock().unwrap();
        assert!(
            ui.open_ceremony(&ceremony.id, CeremonyKind::Login)
                .is_none(),
            "a direct broker panic killed the outstanding token"
        );
        // A token sealed after the panic works, and a second panic
        // (already locked) kills that one too: the hook runs on
        // every panic, not just the one that transitions.
        let ceremony = ui.begin(CeremonyKind::Login);
        assert!(
            ui.open_ceremony(&ceremony.id, CeremonyKind::Login)
                .is_some()
        );
        broker.panic_lock().unwrap();
        assert!(
            ui.open_ceremony(&ceremony.id, CeremonyKind::Login)
                .is_none()
        );
    }

    // ---- The audit ceiling (D6) ----

    /// Records every entry the UI asks the sink for.
    #[derive(Default)]
    struct Recorder {
        itemized: Mutex<Vec<(&'static str, Option<u64>)>>,
        summaries: Mutex<Vec<u64>>,
    }

    impl OwnerAudit for Recorder {
        fn auth_failed(&self, failure: AuthFailure) {
            self.itemized
                .lock()
                .unwrap()
                .push((failure.detail, failure.suppressed));
        }

        fn suppressed_only(&self, count: u64) {
            self.summaries.lock().unwrap().push(count);
        }

        fn passkey_enroll_code(&self) -> Result<(), OwnerAuditError> {
            Ok(())
        }

        fn passkey_enrolled(&self, _enrolled: PasskeyEnrolled) -> Result<(), OwnerAuditError> {
            Ok(())
        }

        fn passkey_listed(&self, _listed: PasskeyListed) -> Result<(), OwnerAuditError> {
            Ok(())
        }

        fn passkey_removed(&self, _removed: PasskeyRemoved) -> Result<(), OwnerAuditError> {
            Ok(())
        }
    }

    const PUBLIC: &str = "https://owner.example.com";

    fn public_ui(audit: Arc<Recorder>) -> (Arc<OwnerUi>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open_with(
            dir.path(),
            OwnerUiOptions {
                rp_id: "owner.example.com".into(),
                origin: PUBLIC.into(),
                public: true,
                access: None,
                oauth: None,
                admission: None,
                oauth_tokens: None,
            },
            Arc::new(StaticShell(ShellView {
                locked: false,
                pending: 0,
            })),
            audit,
            Arc::new(NoApprovals),
        )
        .unwrap();
        (ui, dir)
    }

    fn post(path: &str, cookie: Option<&str>, origin: &str, body: &str) -> Incoming {
        Incoming {
            method: Method::POST,
            path: path.into(),
            cookie: cookie.map(str::to_owned),
            origin: Some(origin.into()),
            authorization: None,
            content_type: Some("application/json".into()),
            body: body.as_bytes().to_vec(),
            client_ip: None,
            throttle_key: None,
            query: None,
        }
    }

    #[test]
    fn req_apr_009_session_failures_are_always_itemized() {
        let rec = Arc::new(Recorder::default());
        let (ui, _dir) = public_ui(rec.clone());
        for _ in 0..40 {
            let r = ui.dispatch(post("/owner/login/finish", None, PUBLIC, "{}"));
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        }
        let cookie = ui.issue_session(&[]).split(';').next().unwrap().to_owned();
        let r = ui.dispatch(post(
            "/owner/approvals/approve",
            Some(&cookie),
            PUBLIC,
            r#"{"password":"x"}"#,
        ));
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let got = rec.itemized.lock().unwrap().clone();
        assert_eq!(got.len(), 21, "{got:?}");
        assert_eq!(got[20], ("password_rejected", None));
    }

    #[test]
    fn req_apr_009_wrong_origin_with_a_session_is_still_capped() {
        let rec = Arc::new(Recorder::default());
        let (ui, _dir) = public_ui(rec.clone());
        let cookie = ui.issue_session(&[]).split(';').next().unwrap().to_owned();
        for _ in 0..40 {
            let r = ui.dispatch(post(
                "/owner/approvals/approve",
                Some(&cookie),
                "https://sibling.example.com",
                "{}",
            ));
            assert_eq!(r.status(), StatusCode::FORBIDDEN);
        }
        let got = rec.itemized.lock().unwrap().clone();
        assert_eq!(got.len(), 20, "{got:?}");
        assert!(got.iter().all(|(d, _)| *d == "origin"));
    }

    #[test]
    fn a_suppressed_failure_still_counts_toward_the_throttle() {
        let rec = Arc::new(Recorder::default());
        let (ui, _dir) = public_ui(rec.clone());
        for _ in 0..20 {
            ui.dispatch(post("/owner/login/finish", None, PUBLIC, "{}"));
        }
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..10 {
            let mut req = post("/owner/login/finish", None, PUBLIC, "{}");
            req.client_ip = Some(ip);
            req.throttle_key = Some(ip);
            assert_eq!(ui.dispatch(req).status(), StatusCode::UNAUTHORIZED);
        }
        // The budget is spent, yet the tenth failure tripped the throttle.
        let mut req = post("/owner/login/finish", None, PUBLIC, "{}");
        req.client_ip = Some(ip);
        req.throttle_key = Some(ip);
        assert_eq!(ui.dispatch(req).status(), StatusCode::TOO_MANY_REQUESTS);
        // The ten failures were counted, not itemized; the trip has its own
        // allowance and is the 21st entry.
        let got = rec.itemized.lock().unwrap().clone();
        assert_eq!(got.len(), 21, "{got:?}");
        assert_eq!(got[20].0, "throttled");
        assert_eq!(ui.audit_budget.drain(), Some(10));
    }

    #[test]
    fn flush_and_drain_write_the_count_once() {
        let rec = Arc::new(Recorder::default());
        let (ui, _dir) = public_ui(rec.clone());
        for _ in 0..25 {
            ui.dispatch(post("/owner/login/finish", None, PUBLIC, "{}"));
        }
        let t0 = Instant::now();
        ui.flush_audit(t0);
        assert!(rec.summaries.lock().unwrap().is_empty());
        ui.flush_audit(t0 + audit_budget::AUDIT_WINDOW);
        ui.flush_audit(t0 + audit_budget::AUDIT_WINDOW);
        ui.drain_audit();
        assert_eq!(*rec.summaries.lock().unwrap(), vec![5]);
    }

    #[test]
    fn the_carried_count_reaches_the_next_windows_first_entry() {
        let rec = Arc::new(Recorder::default());
        let (ui, _dir) = public_ui(rec.clone());
        let ctx = || FailureCtx {
            client_ip: None,
            throttle_key: None,
            throttled_route: false,
            session: None,
        };
        let t = Instant::now();
        for _ in 0..25 {
            ui.record_failure(t, ctx(), "no_assertion");
        }
        let later = t + audit_budget::AUDIT_WINDOW;
        ui.record_failure(later, ctx(), "no_assertion");
        ui.record_failure(later, ctx(), "no_assertion");
        let got = rec.itemized.lock().unwrap().clone();
        assert_eq!(got.len(), 22, "{got:?}");
        assert_eq!(got[20].1, Some(5));
        assert_eq!(got[21].1, None);
        assert!(got[..20].iter().all(|(_, n)| n.is_none()));
    }

    #[test]
    fn the_missing_header_warning_is_printed_once() {
        let (ui, _dir) = public_ui(Arc::new(Recorder::default()));
        assert!(ui.note_peer_fallback());
        assert!(!ui.note_peer_fallback());
        assert!(!ui.note_peer_fallback());
    }

    /// Reviewer's probe: wrong-`Origin` noise spends the budget, and a
    /// throttle trip must still be itemized (D6, Nyx's ruling).
    #[test]
    fn a_throttle_trip_is_itemized_when_wrong_origin_noise_spent_the_budget() {
        let rec = Arc::new(Recorder::default());
        let (ui, _dir) = public_ui(rec.clone());
        for _ in 0..20 {
            let r = ui.dispatch(post(
                "/owner/login/finish",
                None,
                "https://sibling.example.com",
                "{}",
            ));
            assert_eq!(r.status(), StatusCode::FORBIDDEN);
        }
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..10 {
            let mut req = post("/owner/login/finish", None, PUBLIC, "{}");
            req.client_ip = Some(ip);
            req.throttle_key = Some(ip);
            ui.dispatch(req);
        }
        let got = rec.itemized.lock().unwrap().clone();
        assert!(got.iter().any(|(d, _)| *d == "throttled"), "{got:?}");
    }

    /// Never reached by the Access tests: the redeem routes are not used.
    struct NoRedeem;

    impl ApprovalRedeemer for NoRedeem {
        fn prompt(
            &self,
            _token: &str,
        ) -> Result<
            (
                crate::api::grant::ApprovalPrompt,
                crate::api::approval::ApprovalAction,
            ),
            crate::api::approval::TokenGone,
        > {
            Err(crate::api::approval::TokenGone::Unknown)
        }

        fn redeem(
            &self,
            _token: &str,
        ) -> Result<crate::api::approval::ApprovalAction, crate::api::approval::TokenGone> {
            Err(crate::api::approval::TokenGone::Unknown)
        }
    }

    #[tokio::test]
    async fn the_access_gate_is_off_outside_public_mode() {
        // One RSA entry; the verifier only decodes it, no token is checked.
        let doc = r#"{"keys":[{"kid":"k1","kty":"RSA","n":"AQAB","e":"AQAB"}]}"#;
        let verifier = access::AccessVerifier::new(&crate::config::AccessConfig {
            team_domain: "test.cloudflareaccess.com".into(),
            audience: "aud123".into(),
            jwks: crate::config::JwksSource::TestStatic(doc.into()),
        })
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open_with(
            dir.path(),
            OwnerUiOptions {
                rp_id: "localhost".into(),
                origin: ORIGIN.into(),
                public: false,
                access: Some(verifier),
                oauth: None,
                admission: None,
                oauth_tokens: None,
            },
            Arc::new(StaticShell(ShellView {
                locked: false,
                pending: 0,
            })),
            Arc::new(NoAudit),
            Arc::new(NoApprovals),
        )
        .unwrap();
        let state = Arc::new(OwnerServer {
            ui,
            redeem: Arc::new(NoRedeem),
            in_flight: InFlight::new(),
        });
        let req = Request::builder()
            .uri("/owner/session")
            .body(Body::empty())
            .unwrap();
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let resp = handle(State(state), ConnectInfo(peer), req).await;
        // Local mode's own answer (no session), not the gate's 403.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_metadata_path_answers_behind_the_access_gate() {
        // REQ-OAU-001 + #208 D9: with `[owner_ui.access]` set, the
        // RFC 8414 document still answers with no Access token — a
        // discovering client is not a browser behind Access — while
        // the rest of the UI stays gated. Without `[oauth]` the path
        // keeps the uniform 404, gate or no gate.
        let doc = r#"{"keys":[{"kid":"k1","kty":"RSA","n":"AQAB","e":"AQAB"}]}"#;
        let mk = |oauth: Option<OauthAs>| {
            let verifier = access::AccessVerifier::new(&crate::config::AccessConfig {
                team_domain: "test.cloudflareaccess.com".into(),
                audience: "aud123".into(),
                jwks: crate::config::JwksSource::TestStatic(doc.into()),
            })
            .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let ui = OwnerUi::open_with(
                dir.path(),
                OwnerUiOptions {
                    rp_id: "owner.example.com".into(),
                    origin: PUBLIC.into(),
                    public: true,
                    access: Some(verifier),
                    oauth,
                    admission: None,
                    oauth_tokens: None,
                },
                Arc::new(StaticShell(ShellView {
                    locked: true,
                    pending: 0,
                })),
                Arc::new(NoAudit),
                Arc::new(NoApprovals),
            )
            .unwrap();
            (
                Arc::new(OwnerServer {
                    ui,
                    redeem: Arc::new(NoRedeem),
                    in_flight: InFlight::new(),
                }),
                dir,
            )
        };
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let get = |path: &str| {
            Request::builder()
                .uri(path)
                .header(header::HOST, "owner.example.com")
                .body(Body::empty())
                .unwrap()
        };
        let discovery = Discovery::new(PUBLIC.to_owned(), "kharon.example.com");
        let (state, _dir) = mk(Some(metadata_oauth(discovery.clone())));
        // No Access token: the metadata answers anyway...
        let resp = handle(
            State(Arc::clone(&state)),
            ConnectInfo(peer),
            get(AUTHORIZATION_SERVER_PATH),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), MAX_BODY)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body, discovery.authorization_server_metadata());
        // ...while the UI itself stays behind the gate.
        let resp = handle(State(Arc::clone(&state)), ConnectInfo(peer), get("/")).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Without `[oauth]`: the uniform 404, not the gate's 403.
        let (state, _dir) = mk(None);
        let resp = handle(
            State(state),
            ConnectInfo(peer),
            get(AUTHORIZATION_SERVER_PATH),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    fn point() -> [u8; webauthn::P256_POINT_LEN] {
        let mut pk = [0u8; webauthn::P256_POINT_LEN];
        pk[0] = 0x04;
        pk
    }

    fn enroll(ui: &OwnerUi, id: &[u8]) {
        ui.store_enrolled(webauthn::RegisteredCredential {
            credential_id: id.to_vec(),
            public_key: point(),
            sign_count: 0,
        })
        .unwrap();
    }

    fn cookie_header(set_cookie: &str) -> String {
        set_cookie.split(';').next().unwrap().to_owned()
    }

    /// #258: removing a passkey ends only the sessions it opened.
    /// The web UI refuses the last one; the CLI does not. A failed
    /// append removes nothing and leaves the session.
    #[test]
    fn passkey_remove_ends_its_sessions_and_the_web_ui_keeps_the_last() {
        let dir = tempfile::tempdir().unwrap();
        let ui = OwnerUi::open(
            dir.path(),
            "localhost",
            ORIGIN,
            Arc::new(StaticShell(ShellView {
                locked: true,
                pending: 0,
            })),
            Arc::new(NoAudit),
            Arc::new(NoApprovals),
        )
        .unwrap();
        let id_a = vec![0x11u8; 16];
        let id_b = vec![0x22u8; 16];
        enroll(&ui, &id_a);
        enroll(&ui, &id_b);
        let cookie_a = cookie_header(&ui.issue_session(&id_a));
        let cookie_b = cookie_header(&ui.issue_session(&id_b));
        let rows = ui.list_passkeys(PasskeyChannel::Cli).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.enrolled_at.is_some()));
        assert!(rows.iter().all(|r| r.last_used_at.is_none()));
        let short_a = store::short_id(&id_a);
        let short_b = store::short_id(&id_b);
        assert_ne!(short_a, short_b);
        assert!(rows.iter().any(|r| r.id == short_a));
        assert!(rows.iter().any(|r| r.id == short_b));
        for row in &rows {
            assert_eq!(row.id.len(), store::PASSKEY_SHORT_ID_LEN);
        }

        ui.remove_passkey(PasskeyChannel::WebUi, &short_b).unwrap();
        assert!(!ui.session_alive(Some(&cookie_b)));
        assert!(ui.session_alive(Some(&cookie_a)));
        assert_eq!(
            ui.remove_passkey(PasskeyChannel::WebUi, &short_a),
            Err(PasskeyOpError::LastPasskey)
        );
        assert!(ui.session_alive(Some(&cookie_a)));
        assert_eq!(ui.list_passkeys(PasskeyChannel::Cli).unwrap().len(), 1);

        ui.remove_passkey(PasskeyChannel::Cli, &short_a).unwrap();
        assert!(!ui.session_alive(Some(&cookie_a)));
        assert!(ui.list_passkeys(PasskeyChannel::Cli).unwrap().is_empty());
        assert_eq!(
            ui.remove_passkey(PasskeyChannel::Cli, &short_a),
            Err(PasskeyOpError::NotFound)
        );
        assert_eq!(
            ui.remove_passkey(PasskeyChannel::Cli, "ZZZZZZZZ"),
            Err(PasskeyOpError::BadId)
        );
    }

    /// #258: a failed list or remove append does not disclose the list
    /// and does not remove the passkey or its session.
    #[test]
    fn passkey_list_and_remove_fail_closed_when_the_append_fails() {
        let dir = tempfile::tempdir().unwrap();
        let gate = Arc::new(ListGate::default());
        let ui = OwnerUi::open(
            dir.path(),
            "localhost",
            ORIGIN,
            Arc::new(StaticShell(ShellView {
                locked: true,
                pending: 0,
            })),
            gate.clone(),
            Arc::new(NoApprovals),
        )
        .unwrap();
        let id = vec![0x33u8; 16];
        enroll(&ui, &id);
        let cookie = cookie_header(&ui.issue_session(&id));
        gate.fail_list
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            ui.list_passkeys(PasskeyChannel::WebUi).unwrap_err(),
            PasskeyOpError::Audit
        );
        gate.fail_list
            .store(false, std::sync::atomic::Ordering::SeqCst);
        gate.fail_remove
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let short = store::short_id(&id);
        assert_eq!(
            ui.remove_passkey(PasskeyChannel::Cli, &short).unwrap_err(),
            PasskeyOpError::Audit
        );
        assert!(ui.session_alive(Some(&cookie)));
        gate.fail_remove
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let rows = ui.list_passkeys(PasskeyChannel::Cli).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, short);
    }

    #[derive(Default)]
    struct ListGate {
        fail_list: std::sync::atomic::AtomicBool,
        fail_remove: std::sync::atomic::AtomicBool,
    }

    impl OwnerAudit for ListGate {
        fn auth_failed(&self, _failure: AuthFailure) {}
        fn suppressed_only(&self, _count: u64) {}
        fn passkey_enroll_code(&self) -> Result<(), OwnerAuditError> {
            Ok(())
        }
        fn passkey_enrolled(&self, _enrolled: PasskeyEnrolled) -> Result<(), OwnerAuditError> {
            Ok(())
        }
        fn passkey_listed(&self, _listed: PasskeyListed) -> Result<(), OwnerAuditError> {
            if self.fail_list.load(std::sync::atomic::Ordering::SeqCst) {
                Err(OwnerAuditError)
            } else {
                Ok(())
            }
        }
        fn passkey_removed(&self, _removed: PasskeyRemoved) -> Result<(), OwnerAuditError> {
            if self.fail_remove.load(std::sync::atomic::Ordering::SeqCst) {
                Err(OwnerAuditError)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn signed_in_page_lists_passkeys_with_a_remove_button() {
        let shell = shell_page("unlocked", 0);
        assert!(shell.contains("<h2>Passkeys</h2>"));
        assert!(shell.contains("/owner/passkeys/remove"));
        assert!(shell.contains("\"Remove\""));
        assert!(shell.contains("kharon passkey remove"));
        assert!(!LOGIN_PAGE.contains("/owner/passkeys"));
        assert!(ROUTES.contains(&("GET", "/owner/passkeys")));
        assert!(ROUTES.contains(&("POST", "/owner/passkeys/remove")));
    }
}
