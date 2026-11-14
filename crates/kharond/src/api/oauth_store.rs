//! The OAuth token store (REQ-OAU-004/-005; N3 design #226, D3/D4,
//! I5): Connect identities and their tokens, persisted in
//! `data_dir/oauth/state.json`.
//!
//! A Connect identity (`c-<10 lowercase base32>`) is created when an
//! authorization code is redeemed at `POST /oauth/token` — never at
//! consent, so an unredeemed consent leaves nothing behind (A17).
//! Tokens are opaque (`kh_at_<64 hex>`, `kh_rt_<64 hex>`); the file
//! holds only their SHA-256 hashes, with the identities (D3). Each
//! record stores an audience (`mcp` or `connector`) in its own
//! field, not in scope or resource (D4, #304). A phase-1 file omits
//! the field and loads as `mcp`. Code redemption and refresh issue
//! `mcp`. Codes are never written here: they live in the authorize
//! side's memory (#230). The redeemed-code set that makes a second
//! redemption revoke is memory-only too, expiring with the code. A pending
//! marker is recorded in that set atomically with the code take
//! ([`OauthStore::begin_redemption`]); [`OauthStore::connect`]
//! resolves it under the store lock, so a second presentation that
//! arrives after the take and before the commit is not missed.
//!
//! Ordering follows I5 / REQ-AUD-003, and the two directions fail
//! closed opposite ways, on purpose:
//! - **Issuance** (connect, refresh): audit first where an entry is
//!   owed (`oauth_connect`), then persist, then answer. Re-check,
//!   mutation, persist and commit all happen under the one store
//!   lock, so concurrent writers cannot overwrite each other (or
//!   resurrect a Connect an ending path just revoked); a failed
//!   write rolls the in-memory state back from a snapshot taken
//!   under the same lock, answers 500 with no tokens, and leaves
//!   the previous state — in memory and on disk — untouched.
//! - **Ending a Connect** (revoke, reuse, panic): revoke first, in
//!   memory and in the state file, then audit (the #135 precedent).
//!   A failed write is reported but cannot un-revoke what memory
//!   already ended.
//!
//! The store is transport-free. Audit appends and grant cleanup go
//! through [`ConnectLifecycle`], which the daemon implements over
//! the broker (cf. [`super::cimd::RefusalAudit`]); the token and
//! revoke endpoints live in `owner_ui::oauth_token`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit::{Entry, Event};

/// Access tokens live one hour (D4).
pub const ACCESS_TTL_SECS: u64 = 3_600;
/// A refresh token idles out 30 days after its last rotation (D4).
pub const REFRESH_IDLE_SECS: u64 = 30 * 86_400;
/// …and dies absolutely 90 days after consent (D4, A6).
pub const REFRESH_ABSOLUTE_SECS: u64 = 90 * 86_400;
/// The refresh-retry grace after a rotation (I5, A13).
pub const GRACE_SECS: u64 = 30;
/// Authorization codes live 60 s (D4); the redeemed set is kept
/// exactly that long past consent.
pub const CODE_TTL_SECS: u64 = 60;

/// On-disk schema. Stays at 1 when the audience field arrives: a
/// phase-1 file has no `audience` key and deserializes as `mcp`
/// (A6). Bumping this refuses those files at startup.
const STATE_VERSION: u32 = 1;

/// Where a Connect's audit entries go, and who drops its live
/// grants when it ends. Implemented by the daemon over the broker.
pub trait ConnectLifecycle: Send + Sync {
    /// Append one audit entry; `false` when the log refused it.
    /// Only `oauth_connect` treats a refusal as fatal (I5: the
    /// append precedes the persist, and a failed append creates
    /// nothing); the ending entries are appended after the
    /// revocation they describe and are best effort.
    fn append(&self, entry: Entry) -> bool;
    /// A Connect ended: drop the identity's live grants and pending
    /// requests (REQ-REV-001). Best effort, like the audit append
    /// that follows it.
    fn connect_ended(&self, agent_id: &str);
}

/// Why a token operation failed. `InvalidGrant` is the OAuth
/// `invalid_grant` error; `PersistFailed` and `AuditFailed` are
/// server faults the endpoint answers 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// The presented code or token is unknown, expired, spent or
    /// otherwise not usable.
    InvalidGrant,
    /// The `oauth_connect` append failed: nothing was created.
    AuditFailed,
    /// The state write failed: no tokens are answered.
    PersistFailed,
}

/// A freshly issued token pair, plaintext, for the one response
/// that carries it. Never stored, never logged.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedPair {
    pub access_token: String,
    pub refresh_token: String,
    /// The granted scopes, space-separated, as the token response's
    /// `scope` (the granted set can differ from the requested one,
    /// REQ-OAU-003).
    pub scope: String,
}

impl std::fmt::Debug for IssuedPair {
    /// The plaintext tokens never print, even in a test failure.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedPair")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("scope", &self.scope)
            .finish()
    }
}

/// What a live access token resolves to. The audience is the
/// record's own field. `/mcp` accepts only [`TokenAudience::Mcp`],
/// and that refusal happens in the broker before the scope gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated {
    pub agent_id: String,
    /// The Connect's granted scopes (the store carries them from
    /// here; the broker enforces them via `AgentId`, #232).
    pub scopes: Vec<String>,
    /// The audience stored on this access token.
    pub audience: TokenAudience,
}

/// Which surface a token record is for (D4, #304).
///
/// Its own field on the access token and on the refresh token:
/// not a scope, and not the `resource` parameter. A phase-1
/// `oauth/state.json` has no audience key; that record loads as
/// [`Self::Mcp`], an `/mcp` token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenAudience {
    /// `/mcp`. Code redemption and refresh issue this audience.
    #[default]
    Mcp,
    /// The connector tunnel. Refused on `/mcp`.
    Connector,
}

/// The checked contents of a redeemed authorization code (#230's
/// `CodeBody`, carried across the seam): everything the identity
/// will need (D4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeGrant {
    pub client_id: String,
    pub client_name: String,
    /// The S256 `code_challenge` the code was bound to.
    pub code_challenge: String,
    /// The granted scopes, canonical order.
    pub scopes: Vec<String>,
    /// Unix seconds of the consent; the refresh token's 90-day
    /// absolute lifetime counts from here (D4).
    pub consented_at: u64,
    /// Whether the client's metadata document declared the connector
    /// extension grant when the owner consented (#235 D3).
    pub connector_grant_declared: bool,
}

/// How a Connect ended, for the `oauth_disconnect` `detail_code`
/// (SPEC §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectDetail {
    /// Disconnect in the owner UI or `revoke agent` on the socket.
    Owner,
    /// The client's `POST /oauth/revoke` with its refresh token.
    Client,
    /// Panic (REQ-REV-002).
    Panic,
    /// The code was redeemed a second time.
    CodeReuse,
}

impl DisconnectDetail {
    pub fn detail_code(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Client => "client",
            Self::Panic => "panic",
            Self::CodeReuse => "code_reuse",
        }
    }
}

/// One Connect identity (D3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// `c-<10 lowercase base32>`.
    pub id: String,
    pub client_id: String,
    /// The `client_name` as shown at consent.
    pub client_name: String,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// Unix seconds the identity was created (code redemption).
    pub created_at: u64,
    /// Unix seconds of the consent; the refresh absolute lifetime
    /// counts from here.
    pub consented_at: u64,
    /// Always `"oauth"` in this design (D3); kept in the record so
    /// the Connections page can say how a Connect arrived.
    pub connected_via: String,
    pub revoked: bool,
    /// Whether the client declared the connector extension grant
    /// (`grant_types` lists `urn:kharon:oauth:grant-type:connector`)
    /// at consent (#235 D3, A11). Fixed at consent: nothing after
    /// redemption writes it, so a client that adds the grant to its
    /// document later is still not declared on this Connect. A
    /// phase 1 record has no field and loads as not declared.
    #[serde(default)]
    pub connector_grant_declared: bool,
}

impl Identity {
    /// The CIMD hostname an audit entry names as `origin` (I7),
    /// when the `client_id` parses as a URL with a host.
    pub fn audit_origin(&self) -> Option<String> {
        cimd_host(&self.client_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TokenKind {
    Access,
    Refresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TokenStatus {
    Live,
    Retired,
    Revoked,
}

/// One token, by hash only (D3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TokenRecord {
    /// Lowercase hex SHA-256 of the plaintext token.
    hash: String,
    kind: TokenKind,
    identity_id: String,
    /// The refresh family: one per Connect, named by the identity.
    /// Not the audience — a Connect has one family today, and the
    /// audience says which surface the token is for.
    family: String,
    /// `mcp` or `connector`. Absent on a phase-1 record, which
    /// deserializes as [`TokenAudience::Mcp`].
    #[serde(default)]
    audience: TokenAudience,
    /// The hash of the token this one descends from: a refresh
    /// token's parent is the refresh token it rotated from; an
    /// access token's parent is the refresh token issued in its
    /// pair. `None` for a Connect's first pair.
    parent: Option<String>,
    issued_at: u64,
    /// Access: issue + 1 h. Refresh: the earlier of the 30-day idle
    /// limit and the 90-day absolute limit.
    expires_at: u64,
    status: TokenStatus,
    /// Refresh only: when a rotation retired this token.
    retired_at: Option<u64>,
    /// Refresh only: the hash of the refresh token that replaced
    /// this one.
    successor: Option<String>,
    /// Refresh only: the 30 s grace retry has been spent (I5).
    grace_used: bool,
}

/// The persisted form. Codes are never in it (D3); the redeemed
/// set below is runtime-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileState {
    version: u32,
    identities: Vec<Identity>,
    tokens: Vec<TokenRecord>,
}

impl FileState {
    fn new() -> Self {
        Self {
            version: STATE_VERSION,
            identities: Vec::new(),
            tokens: Vec::new(),
        }
    }

    fn identity(&self, id: &str) -> Option<&Identity> {
        self.identities.iter().find(|i| i.id == id)
    }
}

/// A code taken for redemption, remembered until the code would have
/// expired. A second presentation in that window revokes what the
/// first one issued (D4, RFC 6749 §4.1.2). Memory only, like the
/// codes themselves.
///
/// The marker is recorded when the code is taken, before the Connect
/// commits. `identity_id` stays `None` until that commit, and `reused`
/// is set by a second presentation whenever it arrives — including
/// while the first is still between the take and the commit.
struct RedeemedUse {
    code_hash: [u8; 32],
    /// `None` until [`OauthStore::connect`] commits the identity.
    identity_id: Option<String>,
    /// A second presentation has been seen. Monotonic.
    reused: bool,
    expires_at: u64,
}

/// What [`OauthStore::begin_redemption`] decided about a presented code.
#[derive(Debug)]
pub enum CodeClaim<T> {
    /// This caller took the code. A pending marker is recorded;
    /// [`OauthStore::connect`] resolves it.
    Taken(T),
    /// The code was already taken. `identity_id` is `Some` once that
    /// redemption has committed a Connect, and `None` while it is
    /// still in flight or it failed without committing.
    Reuse { identity_id: Option<String> },
    /// Unknown or expired, and no redemption is on record.
    Unknown,
}

struct Inner {
    file: FileState,
    redeemed: Vec<RedeemedUse>,
}

/// The store. One per daemon, shared by the token endpoints (via
/// the owner UI), the broker's `/mcp` auth dispatch and the daemon.
pub struct OauthStore {
    path: PathBuf,
    inner: Mutex<Inner>,
    lifecycle: OnceLock<Arc<dyn ConnectLifecycle>>,
}

impl OauthStore {
    /// Load `data_dir/oauth/state.json`. A missing file is an empty
    /// store; an unparseable one is an error, and with `[oauth]`
    /// set the daemon refuses to start on it (I2: fail closed).
    /// Called before any listener opens.
    pub fn load(data_dir: &Path) -> io::Result<Self> {
        let path = data_dir.join("oauth").join("state.json");
        let file = match std::fs::read(&path) {
            Ok(bytes) => {
                let parsed: FileState = serde_json::from_slice(&bytes).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("oauth state {}: {e}", path.display()),
                    )
                })?;
                if parsed.version != STATE_VERSION {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "oauth state {}: unsupported version {}",
                            path.display(),
                            parsed.version
                        ),
                    ));
                }
                parsed
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => FileState::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            path,
            inner: Mutex::new(Inner {
                file,
                redeemed: Vec::new(),
            }),
            lifecycle: OnceLock::new(),
        })
    }

    /// Wire the audit/grant lifecycle (the daemon, once the broker
    /// exists). Until set, audit appends fail — so `connect` fails
    /// closed — and grant cleanup is skipped.
    pub fn set_lifecycle(&self, lifecycle: Arc<dyn ConnectLifecycle>) {
        let _ = self.lifecycle.set(lifecycle);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn append(&self, entry: Entry) -> bool {
        match self.lifecycle.get() {
            Some(lifecycle) => lifecycle.append(entry),
            None => false,
        }
    }

    fn connect_ended(&self, agent_id: &str) {
        if let Some(lifecycle) = self.lifecycle.get() {
            lifecycle.connect_ended(agent_id);
        }
    }

    /// Serialize and atomically replace the state file (0600,
    /// write-then-rename, like `owner/passkeys.json`).
    fn persist(&self, file: &FileState) -> io::Result<()> {
        let text = serde_json::to_string(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        write_private(&self.path, text.as_bytes())
    }

    /// The identity a code's first redemption committed, while the
    /// code would still be live. Pending markers (taken, not yet
    /// committed) are not visible here. The token endpoint does not
    /// use this to detect a second redemption: that goes through
    /// [`Self::begin_redemption`], which also sees an in-flight take.
    pub fn redeemed_identity(&self, code_hash: &[u8; 32], now: u64) -> Option<String> {
        let mut inner = self.lock();
        inner.redeemed.retain(|r| r.expires_at > now);
        inner
            .redeemed
            .iter()
            .find(|r| ct_eq(&r.code_hash, code_hash))
            .and_then(|r| r.identity_id.clone())
    }

    /// Take `code_hash` for redemption, atomically with the pending
    /// marker that makes a second presentation detectable.
    ///
    /// `redeem` runs while the store lock is held, so it must not
    /// call back into the store (this mutex is not re-entrant). The
    /// lock order is store, then whatever `redeem` locks (the
    /// authorize side's code store). It returns the taken value and
    /// the consent time the code's TTL is counted from, or `None`
    /// when the code is unknown or expired.
    ///
    /// A second call for the same hash, at any point after the first
    /// returned [`CodeClaim::Taken`], returns [`CodeClaim::Reuse`]
    /// and sets the marker's `reused` flag. It does not call `redeem`.
    /// The in-flight [`Self::connect`] observes that flag under the
    /// store lock and does not leave a live Connect.
    pub fn begin_redemption<T>(
        &self,
        code_hash: [u8; 32],
        now: u64,
        redeem: impl FnOnce() -> Option<(T, u64)>,
    ) -> CodeClaim<T> {
        let mut inner = self.lock();
        inner.redeemed.retain(|r| r.expires_at > now);
        if let Some(existing) = inner
            .redeemed
            .iter_mut()
            .find(|r| ct_eq(&r.code_hash, &code_hash))
        {
            existing.reused = true;
            return CodeClaim::Reuse {
                identity_id: existing.identity_id.clone(),
            };
        }
        let Some((body, consented_at)) = redeem() else {
            return CodeClaim::Unknown;
        };
        inner.redeemed.push(RedeemedUse {
            code_hash,
            identity_id: None,
            reused: false,
            expires_at: consented_at.saturating_add(CODE_TTL_SECS),
        });
        CodeClaim::Taken(body)
    }

    /// Create a Connect identity from a redeemed code and issue its
    /// first token pair (I5 ordering: append `oauth_connect`, then
    /// persist, then answer; a failed persist writes a compensating
    /// `oauth_disconnect`/`persist_failed` and creates nothing).
    ///
    /// The caller has already taken the code. When it did so through
    /// [`Self::begin_redemption`], a pending marker is already
    /// recorded; this resolves it. A direct caller (no marker yet)
    /// gets one recorded on a successful commit. Either way the code
    /// is spent: a failure here leaves no live Connect, and a marker
    /// from `begin_redemption` stays so a later presentation is still
    /// refused.
    ///
    /// A marker already flagged `reused` — a second presentation
    /// arrived after the take and before this commit — is refused
    /// under the store lock. The `oauth_connect` append has already
    /// happened (I5), so the refusal writes the compensating
    /// `oauth_disconnect` with `code_reuse` and persists nothing.
    pub fn connect(
        &self,
        grant: &CodeGrant,
        code_verifier: &str,
        code_hash: [u8; 32],
        now: u64,
    ) -> Result<IssuedPair, TokenError> {
        // PKCE S256: SHA-256(verifier), base64url without padding,
        // must equal the challenge the code was bound to.
        let digest = sha256(code_verifier.as_bytes());
        if !ct_eq(
            b64url_encode(&digest).as_bytes(),
            grant.code_challenge.as_bytes(),
        ) {
            return Err(TokenError::InvalidGrant);
        }
        let id = new_identity_id();
        let origin = cimd_host(&grant.client_id);
        // 1. Audit. A failed append fails the request closed: no
        // identity, no tokens (I5).
        let entry = Entry::new(Event::OauthConnect)
            .agent_id(id.clone())
            .channel("web_ui")
            .result("connected");
        let entry = match &origin {
            Some(host) => entry.origin(host.clone()),
            None => entry,
        };
        if !self.append(entry) {
            return Err(TokenError::AuditFailed);
        }
        // 2. Persist. Mutate and write under the one lock, so a
        // concurrent writer (another connect, a refresh, an ending
        // path) cannot be overwritten by a stale swap; on failure
        // roll back what was pushed, so the running state is
        // untouched. The reuse check is in that same critical
        // section: a second presentation that set the flag after the
        // take cannot be committed over.
        let identity = Identity {
            id: id.clone(),
            client_id: grant.client_id.clone(),
            client_name: grant.client_name.clone(),
            scopes: grant.scopes.clone(),
            created_at: now,
            consented_at: grant.consented_at,
            connected_via: "oauth".to_owned(),
            revoked: false,
            connector_grant_declared: grant.connector_grant_declared,
        };
        let (pair, access_rec, refresh_rec) = issue_pair(&identity, None, now, TokenAudience::Mcp);
        enum Commit {
            Issued(IssuedPair),
            /// A second presentation landed before this commit.
            Reused,
            PersistFailed,
        }
        let outcome = {
            let mut inner = self.lock();
            // Keep this code's own marker even if its TTL elapsed
            // while the redemption was in flight: its `reused` flag
            // is the signal a second presentation already landed.
            inner
                .redeemed
                .retain(|r| r.expires_at > now || ct_eq(&r.code_hash, &code_hash));
            let reused = inner
                .redeemed
                .iter()
                .find(|r| ct_eq(&r.code_hash, &code_hash))
                .is_some_and(|r| r.reused);
            if reused {
                Commit::Reused
            } else {
                let identities_len = inner.file.identities.len();
                let tokens_len = inner.file.tokens.len();
                let had_marker = inner
                    .redeemed
                    .iter()
                    .any(|r| ct_eq(&r.code_hash, &code_hash));
                inner.file.identities.push(identity);
                inner.file.tokens.push(access_rec);
                inner.file.tokens.push(refresh_rec);
                if let Some(marker) = inner
                    .redeemed
                    .iter_mut()
                    .find(|r| ct_eq(&r.code_hash, &code_hash))
                {
                    marker.identity_id = Some(id.clone());
                } else {
                    inner.redeemed.push(RedeemedUse {
                        code_hash,
                        identity_id: Some(id.clone()),
                        reused: false,
                        expires_at: grant.consented_at.saturating_add(CODE_TTL_SECS),
                    });
                }
                match self.persist(&inner.file) {
                    Ok(()) => Commit::Issued(pair),
                    Err(_) => {
                        inner.file.identities.truncate(identities_len);
                        inner.file.tokens.truncate(tokens_len);
                        if had_marker {
                            // The take already spent the code. Drop
                            // the identity binding and keep the marker,
                            // so a later presentation is still refused
                            // and there is no live Connect to end.
                            if let Some(marker) = inner
                                .redeemed
                                .iter_mut()
                                .find(|r| ct_eq(&r.code_hash, &code_hash))
                            {
                                marker.identity_id = None;
                            }
                        } else {
                            inner.redeemed.retain(|r| !ct_eq(&r.code_hash, &code_hash));
                        }
                        Commit::PersistFailed
                    }
                }
            }
        };
        match outcome {
            Commit::Issued(pair) => Ok(pair),
            Commit::PersistFailed => {
                // Best-effort compensation (I5): the chain reads connect,
                // then disconnect, for an identity that never served.
                self.append(disconnect_entry(&id, &origin, "persist_failed"));
                Err(TokenError::PersistFailed)
            }
            Commit::Reused => {
                // Same shape as a failed persist (I5: the append
                // already happened), with the reuse detail. Nothing
                // was persisted, so there is no Connect to revoke
                // first; the refusal is the ending.
                self.append(disconnect_entry(
                    &id,
                    &origin,
                    DisconnectDetail::CodeReuse.detail_code(),
                ));
                Err(TokenError::InvalidGrant)
            }
        }
    }

    /// `grant_type=refresh_token`: rotate, applying the idle and
    /// absolute limits, the 30 s grace and reuse detection (D4, I5).
    /// `client_id` must name the client the token was issued to
    /// (OAuth 2.1 §4.3); it is compared under the store lock.
    pub fn refresh(
        &self,
        presented: &str,
        client_id: &str,
        now: u64,
    ) -> Result<IssuedPair, TokenError> {
        let hash = hex(&sha256(presented.as_bytes()));
        enum Outcome {
            Reuse(String),
            Pair(IssuedPair),
            PersistFailed,
        }
        // Re-check, mutate, persist and commit under the one lock:
        // concurrent refreshes serialize into exactly the
        // sequential outcomes (rotate, then grace, then reuse), and
        // a concurrent ending path (panic, disconnect, reuse) can
        // neither be overwritten nor resurrected by a stale swap.
        // The one exception is the reuse outcome itself, handled
        // after the lock drops because `end_connect` takes it.
        let outcome = {
            let mut inner = self.lock();
            let Some(pos) = inner.file.tokens.iter().position(|t| t.hash == hash) else {
                return Err(TokenError::InvalidGrant);
            };
            let rec = inner.file.tokens[pos].clone();
            if rec.kind != TokenKind::Refresh {
                return Err(TokenError::InvalidGrant);
            }
            let Some(identity) = inner.file.identity(&rec.identity_id).cloned() else {
                return Err(TokenError::InvalidGrant);
            };
            // The token must have been issued to this client. A
            // mismatch is a plain `invalid_grant`, checked before
            // any status handling, so a wrong-client replay of a
            // retired token cannot trigger the reuse kill either.
            if identity.client_id != client_id {
                return Err(TokenError::InvalidGrant);
            }
            if identity.revoked || rec.status == TokenStatus::Revoked {
                return Err(TokenError::InvalidGrant);
            }
            let grace = rec.status == TokenStatus::Retired
                && !rec.grace_used
                && rec
                    .retired_at
                    .is_some_and(|t| now.saturating_sub(t) <= GRACE_SECS)
                && rec.successor.as_ref().is_some_and(|succ| {
                    inner.file.tokens.iter().any(|t| {
                        t.hash == *succ
                            && t.status == TokenStatus::Live
                            && t.identity_id == rec.identity_id
                    })
                });
            if rec.status == TokenStatus::Retired && !grace {
                Outcome::Reuse(rec.identity_id.clone())
            } else {
                if rec.status == TokenStatus::Live
                    && (now >= rec.expires_at || refresh_deadline(&identity, now) <= now)
                {
                    return Err(TokenError::InvalidGrant);
                }
                // Snapshot for rollback only: mutation and persist
                // happen on the live state, under the lock; a
                // failed write restores the snapshot, so the
                // presented token stays as it was for a retry.
                let backup = inner.file.clone();
                // Refresh issues audience `mcp`, as code redemption
                // does. A connector family's rotation is a later slice.
                let (pair, access_rec, refresh_rec) =
                    issue_pair(&identity, Some(hash.clone()), now, TokenAudience::Mcp);
                if grace {
                    inner.file.tokens[pos].grace_used = true;
                    // The pair issued moments before is superseded,
                    // both tokens (I5). Its refresh token is
                    // *retired* — reuse-detectable, with the grace
                    // already spent — not silently revoked, so a
                    // later presentation still ends the Connect as
                    // reuse (detection delayed, never lost). Its
                    // access token is revoked outright.
                    if let Some(succ) = rec.successor.clone() {
                        for t in inner.file.tokens.iter_mut() {
                            if (t.hash == succ || t.parent.as_deref() == Some(succ.as_str()))
                                && t.status == TokenStatus::Live
                            {
                                if t.kind == TokenKind::Refresh {
                                    t.status = TokenStatus::Retired;
                                    t.retired_at = Some(now);
                                    t.grace_used = true;
                                    t.successor = Some(refresh_rec.hash.clone());
                                } else {
                                    t.status = TokenStatus::Revoked;
                                }
                            }
                        }
                    }
                } else {
                    let old = &mut inner.file.tokens[pos];
                    old.status = TokenStatus::Retired;
                    old.retired_at = Some(now);
                    old.successor = Some(refresh_rec.hash.clone());
                    old.grace_used = false;
                }
                inner.file.tokens.push(access_rec);
                inner.file.tokens.push(refresh_rec);
                // The store is written before the response (I5).
                match self.persist(&inner.file) {
                    Ok(()) => Outcome::Pair(pair),
                    Err(_) => {
                        inner.file = backup;
                        Outcome::PersistFailed
                    }
                }
            }
        };
        match outcome {
            Outcome::Pair(pair) => Ok(pair),
            Outcome::PersistFailed => Err(TokenError::PersistFailed),
            Outcome::Reuse(identity_id) => {
                // Reuse (I5): revoke first — memory and the state
                // file — then audit `oauth_refresh_reuse`. The
                // answer is `invalid_grant` whatever the write did.
                let ended = self.end_connect(&identity_id);
                if let Some(identity) = ended {
                    let entry = Entry::new(Event::OauthRefreshReuse)
                        .agent_id(identity.id.clone())
                        .channel("web_ui")
                        .result("revoked");
                    let entry = match cimd_host(&identity.client_id) {
                        Some(host) => entry.origin(host),
                        None => entry,
                    };
                    self.append(entry);
                }
                Err(TokenError::InvalidGrant)
            }
        }
    }

    /// `POST /oauth/revoke` (RFC 7009): an access token ends only
    /// itself; a refresh token ends the whole Connect (detail
    /// `client`). An unknown or already-dead token is a success:
    /// RFC 7009 answers 200 either way. A failed state write fails
    /// the request — the revocation still stands in memory.
    pub fn revoke(&self, presented: &str, now: u64) -> Result<(), TokenError> {
        let hash = hex(&sha256(presented.as_bytes()));
        let (kind, identity_id) = {
            let inner = self.lock();
            let Some(rec) = inner.file.tokens.iter().find(|t| t.hash == hash) else {
                return Ok(());
            };
            if rec.status == TokenStatus::Revoked {
                return Ok(());
            }
            (rec.kind, rec.identity_id.clone())
        };
        match kind {
            TokenKind::Refresh => {
                self.disconnect(&identity_id, DisconnectDetail::Client, "web_ui", now)?;
                Ok(())
            }
            TokenKind::Access => {
                let mut inner = self.lock();
                if let Some(rec) = inner.file.tokens.iter_mut().find(|t| t.hash == hash) {
                    rec.status = TokenStatus::Revoked;
                }
                let persisted = self.persist(&inner.file);
                drop(inner);
                persisted.map_err(|_| TokenError::PersistFailed)?;
                Ok(())
            }
        }
    }

    /// End a whole Connect: the identity and all its tokens, at
    /// once (REQ-OAU-005). Revoke first — in memory and in the
    /// state file — then the grants hook, then audit
    /// `oauth_disconnect` (best effort). Returns whether a live
    /// Connect ended; a failed write is `Err` after the revocation
    /// has already taken effect in memory.
    pub fn disconnect(
        &self,
        identity_id: &str,
        detail: DisconnectDetail,
        channel: &str,
        _now: u64,
    ) -> Result<bool, TokenError> {
        let Some(identity) = self.end_connect(identity_id) else {
            return Ok(false);
        };
        let entry = Entry::new(Event::OauthDisconnect)
            .agent_id(identity.id.clone())
            .channel(channel)
            .result("revoked")
            .detail_code(detail.detail_code());
        let entry = match cimd_host(&identity.client_id) {
            Some(host) => entry.origin(host),
            None => entry,
        };
        self.append(entry);
        Ok(true)
    }

    /// End every live Connect (panic, REQ-REV-002). One write for
    /// the batch; a failed write is only logged, never allowed to
    /// fail a panic. Returns the identities that ended, with their
    /// audit origins, for the caller's `oauth_disconnect` entries.
    pub fn revoke_all(&self) -> Vec<Identity> {
        let ended = {
            let mut inner = self.lock();
            let ids: Vec<String> = inner
                .file
                .identities
                .iter()
                .filter(|i| !i.revoked)
                .map(|i| i.id.clone())
                .collect();
            let mut ended = Vec::new();
            for id in ids {
                if let Some(identity) = end_in(&mut inner.file, &id) {
                    ended.push(identity);
                }
            }
            if !ended.is_empty() && self.persist(&inner.file).is_err() {
                eprintln!("kharond: oauth state write failed during panic revoke-all");
            }
            ended
        };
        for identity in &ended {
            self.connect_ended(&identity.id);
        }
        ended
    }

    /// A live access token, of whichever audience it stores: a hash
    /// lookup, never an Argon2id permit (REQ-OAU-008). `None` for
    /// unknown, expired, revoked or wrong-kind tokens, and for
    /// tokens whose Connect has ended. A connector audience is
    /// still `Some` here; `/mcp` refuses it before the scope gate.
    pub fn authenticate_access(&self, presented: &str, now: u64) -> Option<Authenticated> {
        let hash = hex(&sha256(presented.as_bytes()));
        let inner = self.lock();
        let rec = inner.file.tokens.iter().find(|t| t.hash == hash)?;
        if rec.kind != TokenKind::Access || rec.status != TokenStatus::Live || now >= rec.expires_at
        {
            return None;
        }
        let identity = inner.file.identity(&rec.identity_id)?;
        if identity.revoked {
            return None;
        }
        Some(Authenticated {
            agent_id: identity.id.clone(),
            scopes: identity.scopes.clone(),
            audience: rec.audience,
        })
    }

    /// The audience stored for `presented`, access or refresh,
    /// whatever its status. `None` when the hash is not in the
    /// store. Does not check expiry or revocation: a round-trip
    /// reads what was written.
    pub fn token_audience(&self, presented: &str) -> Option<TokenAudience> {
        let hash = hex(&sha256(presented.as_bytes()));
        let inner = self.lock();
        inner
            .file
            .tokens
            .iter()
            .find(|t| t.hash == hash)
            .map(|t| t.audience)
    }

    /// Plant a connector-audience access token and its refresh
    /// sibling on a live Connect, and persist them.
    ///
    /// Tests use this constructor to hold a connector record and
    /// round-trip it. Not an issuance path: code redemption and
    /// refresh pass [`TokenAudience::Mcp`] and do not call this.
    /// An unknown or revoked identity is [`TokenError::InvalidGrant`].
    /// A failed write leaves the store unchanged and returns
    /// [`TokenError::PersistFailed`]. The plaintext pair is returned
    /// once and is not stored.
    pub fn insert_connector_audience(
        &self,
        identity_id: &str,
        now: u64,
    ) -> Result<IssuedPair, TokenError> {
        let mut inner = self.lock();
        let Some(identity) = inner
            .file
            .identity(identity_id)
            .filter(|identity| !identity.revoked)
            .cloned()
        else {
            return Err(TokenError::InvalidGrant);
        };
        let backup = inner.file.clone();
        let (pair, access_rec, refresh_rec) =
            issue_pair(&identity, None, now, TokenAudience::Connector);
        inner.file.tokens.push(access_rec);
        inner.file.tokens.push(refresh_rec);
        if self.persist(&inner.file).is_err() {
            inner.file = backup;
            return Err(TokenError::PersistFailed);
        }
        Ok(pair)
    }

    /// Whether the id is one of this store's Connect identities
    /// (live or ended). The broker's grant cleanup for a `c-…` id
    /// goes through [`Self::disconnect`]; this only names the set.
    pub fn is_connect(&self, agent_id: &str) -> bool {
        self.lock().file.identity(agent_id).is_some()
    }

    /// Every identity, live and ended, in creation order (D3). The
    /// Connections page lists the live ones; the display-name lookup
    /// below also resolves ended ones, because an audit entry can
    /// name a Connect that has since been disconnected.
    pub fn identities(&self) -> Vec<Identity> {
        self.lock().file.identities.clone()
    }

    /// Whether a Connect's client declared the connector extension
    /// grant at consent (#235 D3), for the spawn grant to check
    /// (slice 4). `None` for an id this store never issued. An ended
    /// Connect still answers; spawn checks liveness itself.
    pub fn connector_grant_declared(&self, identity_id: &str) -> Option<bool> {
        self.lock()
            .file
            .identity(identity_id)
            .map(|i| i.connector_grant_declared)
    }

    /// The `client_name` an identity was shown under at consent,
    /// for owner-facing display (D9, #233): approvals, grants and
    /// the audit view name a Connect by it. `None` for an id this
    /// store never issued (a config agent, or nothing at all).
    pub fn client_name(&self, agent_id: &str) -> Option<String> {
        self.lock()
            .file
            .identity(agent_id)
            .map(|i| i.client_name.clone())
    }

    /// The shared tail of every Connect-ending path: mutate memory
    /// first (fail closed in-process), then persist, then the
    /// grants hook. Returns the identity as it stood, when a live
    /// one ended. Audit is the caller's entry, after this returns.
    fn end_connect(&self, identity_id: &str) -> Option<Identity> {
        let identity = {
            let mut inner = self.lock();
            let identity = end_in(&mut inner.file, identity_id)?;
            if self.persist(&inner.file).is_err() {
                eprintln!(
                    "kharond: oauth state write failed ending Connect {identity_id}; \
                     the revocation stands in memory"
                );
            }
            identity
        };
        self.connect_ended(identity_id);
        Some(identity)
    }
}

/// An `oauth_disconnect` for a Connect that was audited and then not
/// left live (persist failure, or a reuse caught before commit).
fn disconnect_entry(agent_id: &str, origin: &Option<String>, detail: &str) -> Entry {
    let entry = Entry::new(Event::OauthDisconnect)
        .agent_id(agent_id)
        .channel("web_ui")
        .result("revoked")
        .detail_code(detail);
    match origin {
        Some(host) => entry.origin(host.clone()),
        None => entry,
    }
}

/// End one Connect inside `file`: the identity and every token it
/// owns. Returns the identity as it stood before the revocation,
/// when a live one ended.
fn end_in(file: &mut FileState, identity_id: &str) -> Option<Identity> {
    let identity = file.identity(identity_id)?.clone();
    if identity.revoked {
        return None;
    }
    for i in file.identities.iter_mut() {
        if i.id == identity_id {
            i.revoked = true;
        }
    }
    for t in file.tokens.iter_mut() {
        if t.identity_id == identity_id && t.status != TokenStatus::Revoked {
            t.status = TokenStatus::Revoked;
        }
    }
    Some(identity)
}

/// A refresh token's expiry from `issued_at`: the earlier of the
/// 30-day idle limit and 90 days after consent (D4).
fn refresh_deadline(identity: &Identity, issued_at: u64) -> u64 {
    issued_at
        .saturating_add(REFRESH_IDLE_SECS)
        .min(identity.consented_at.saturating_add(REFRESH_ABSOLUTE_SECS))
}

/// Mint a token pair for `identity`. `parent` is the hash of the
/// refresh token being rotated from (`None` for a Connect's first
/// pair). `audience` is stored on both records. Code redemption
/// and refresh pass [`TokenAudience::Mcp`]; they do not issue a
/// connector audience.
fn issue_pair(
    identity: &Identity,
    parent: Option<String>,
    now: u64,
    audience: TokenAudience,
) -> (IssuedPair, TokenRecord, TokenRecord) {
    let access_token = format!("kh_at_{}", hex(&random_bytes::<32>()));
    let refresh_token = format!("kh_rt_{}", hex(&random_bytes::<32>()));
    let refresh_hash = hex(&sha256(refresh_token.as_bytes()));
    let access_rec = TokenRecord {
        hash: hex(&sha256(access_token.as_bytes())),
        kind: TokenKind::Access,
        identity_id: identity.id.clone(),
        family: identity.id.clone(),
        audience,
        parent: Some(refresh_hash.clone()),
        issued_at: now,
        expires_at: now.saturating_add(ACCESS_TTL_SECS),
        status: TokenStatus::Live,
        retired_at: None,
        successor: None,
        grace_used: false,
    };
    let refresh_rec = TokenRecord {
        hash: refresh_hash,
        kind: TokenKind::Refresh,
        identity_id: identity.id.clone(),
        family: identity.id.clone(),
        audience,
        parent,
        issued_at: now,
        expires_at: refresh_deadline(identity, now),
        status: TokenStatus::Live,
        retired_at: None,
        successor: None,
        grace_used: false,
    };
    let pair = IssuedPair {
        access_token,
        refresh_token,
        scope: identity.scopes.join(" "),
    };
    (pair, access_rec, refresh_rec)
}

/// `c-<10 lowercase base32>` (D3): 50 bits of randomness, RFC 4648
/// lowercase alphabet.
fn new_identity_id() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let raw = random_bytes::<8>();
    let mut bits = u64::from_be_bytes(raw);
    let mut id = String::with_capacity(12);
    id.push_str("c-");
    for _ in 0..10 {
        id.push(ALPHABET[(bits >> 59) as usize] as char);
        bits <<= 5;
    }
    id
}

/// The CIMD hostname an audit entry names as `origin` (I7), when
/// the `client_id` parses as a URL with a host.
fn cimd_host(client_id: &str) -> Option<String> {
    url::Url::parse(client_id)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Base64url without padding (RFC 4648 §5): the S256 challenge form.
fn b64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// Constant-time equality for equal-length inputs (token hashes,
/// code hashes, PKCE digests); differing lengths are just unequal.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Write `bytes` to `path` as mode 0600, replacing any previous
/// file (the `owner/passkeys.json` pattern): tmp file, sync,
/// rename.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    const NOW: u64 = 1_700_000_000;
    const CLIENT: &str = "https://dashboard.example/.well-known/kharon-client.json";

    #[derive(Default)]
    struct Recording {
        entries: StdMutex<Vec<Entry>>,
        ended: StdMutex<Vec<String>>,
        fail_append: StdMutex<bool>,
    }

    impl ConnectLifecycle for Recording {
        fn append(&self, entry: Entry) -> bool {
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

    impl Recording {
        fn events(&self) -> Vec<(String, Option<String>)> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .map(|e| (e.event.as_str().to_owned(), e.detail_code.clone()))
                .collect()
        }
    }

    fn store(dir: &Path) -> (Arc<OauthStore>, Arc<Recording>) {
        let store = OauthStore::load(dir).unwrap();
        let recording = Arc::new(Recording::default());
        store.set_lifecycle(recording.clone() as Arc<dyn ConnectLifecycle>);
        (Arc::new(store), recording)
    }

    fn grant(verifier: &str) -> (CodeGrant, String) {
        let challenge = b64url_encode(&sha256(verifier.as_bytes()));
        (
            CodeGrant {
                client_id: CLIENT.to_owned(),
                client_name: "Dashboard".to_owned(),
                code_challenge: challenge,
                scopes: vec!["kharon:read".to_owned(), "kharon:fill".to_owned()],
                consented_at: NOW,
                connector_grant_declared: false,
            },
            verifier.to_owned(),
        )
    }

    fn connect_one(store: &OauthStore) -> (IssuedPair, String) {
        let (g, verifier) = grant("correct-verifier");
        let pair = store
            .connect(&g, &verifier, sha256(b"the-code"), NOW)
            .unwrap();
        let id = store
            .authenticate_access(&pair.access_token, NOW)
            .unwrap()
            .agent_id;
        (pair, id)
    }

    #[test]
    fn connect_creates_identity_and_pair() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        let (pair, id) = connect_one(&store);
        assert!(id.starts_with("c-"), "{id}");
        assert_eq!(id.len(), 12, "{id}");
        assert!(pair.access_token.starts_with("kh_at_"));
        assert!(pair.refresh_token.starts_with("kh_rt_"));
        assert_eq!(pair.scope, "kharon:read kharon:fill");
        let auth = store.authenticate_access(&pair.access_token, NOW).unwrap();
        assert_eq!(auth.scopes, ["kharon:read", "kharon:fill"]);
        assert_eq!(recording.events(), [("oauth_connect".to_owned(), None)],);
        // The state file names no plaintext token (D3).
        let text = std::fs::read_to_string(dir.path().join("oauth/state.json")).unwrap();
        assert!(!text.contains(&pair.access_token));
        assert!(!text.contains(&pair.refresh_token));
        // Mode 0600.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("oauth/state.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn connect_rejects_a_wrong_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (g, _v) = grant("right");
        let err = store.connect(&g, "wrong", sha256(b"c"), NOW).err().unwrap();
        assert_eq!(err, TokenError::InvalidGrant);
        assert!(!std::fs::exists(dir.path().join("oauth/state.json")).unwrap());
    }

    #[test]
    fn connect_audit_failure_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        *recording.fail_append.lock().unwrap() = true;
        let (g, v) = grant("v");
        let err = store.connect(&g, &v, sha256(b"c"), NOW).err().unwrap();
        assert_eq!(err, TokenError::AuditFailed);
        assert!(!std::fs::exists(dir.path().join("oauth/state.json")).unwrap());
    }

    #[test]
    fn second_redemption_revokes_the_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        let (pair, id) = connect_one(&store);
        let code_hash = sha256(b"the-code");
        // The endpoint's redeemed-set check sees the first redemption.
        assert_eq!(store.redeemed_identity(&code_hash, NOW), Some(id.clone()));
        // …and ends the Connect for the second (detail `code_reuse`).
        let ended = store
            .disconnect(&id, DisconnectDetail::CodeReuse, "web_ui", NOW)
            .unwrap();
        assert!(ended);
        assert!(store.authenticate_access(&pair.access_token, NOW).is_none());
        assert_eq!(
            store.refresh(&pair.refresh_token, CLIENT, NOW),
            Err(TokenError::InvalidGrant)
        );
        assert_eq!(recording.ended.lock().unwrap().as_slice(), [id.as_str()]);
        assert_eq!(
            recording.events(),
            [
                ("oauth_connect".to_owned(), None),
                ("oauth_disconnect".to_owned(), Some("code_reuse".to_owned())),
            ]
        );
        // The redeemed set is gone once the code would have expired.
        assert_eq!(
            store.redeemed_identity(&code_hash, NOW + CODE_TTL_SECS + 1),
            None
        );
    }

    #[test]
    fn refresh_rotates_and_the_old_token_dies_after_grace() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (pair, _id) = connect_one(&store);
        let pair2 = store
            .refresh(&pair.refresh_token, CLIENT, NOW + 60)
            .unwrap();
        assert_ne!(pair2.refresh_token, pair.refresh_token);
        assert_ne!(pair2.access_token, pair.access_token);
        // Rotation retires the old refresh; its access token lives
        // out its own hour (only the grace path retires a pair).
        assert!(
            store
                .authenticate_access(&pair.access_token, NOW + 60)
                .is_some()
        );
        // After the grace, the retired token is reuse.
        assert_eq!(
            store.refresh(&pair.refresh_token, CLIENT, NOW + 60 + GRACE_SECS + 1),
            Err(TokenError::InvalidGrant)
        );
    }

    #[test]
    fn grace_retry_rotates_again_and_retires_the_superseded_pair() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        let (pair, _id) = connect_one(&store);
        let pair2 = store
            .refresh(&pair.refresh_token, CLIENT, NOW + 100)
            .unwrap();
        // The client lost pair2's response and retries with the
        // just-retired token inside 30 s (I5).
        let pair3 = store
            .refresh(&pair.refresh_token, CLIENT, NOW + 100 + GRACE_SECS)
            .unwrap();
        // The superseded pair is retired, both tokens.
        assert!(
            store
                .authenticate_access(&pair2.access_token, NOW + 100)
                .is_none()
        );
        // pair3 works.
        assert!(
            store
                .authenticate_access(&pair3.access_token, NOW + 100)
                .is_some()
        );
        // Presenting the superseded refresh token is reuse, not a
        // silent invalid_grant: its record was retired (grace
        // spent), so the presentation ends the Connect and writes
        // `oauth_refresh_reuse`.
        assert_eq!(
            store.refresh(&pair2.refresh_token, CLIENT, NOW + 100),
            Err(TokenError::InvalidGrant)
        );
        assert!(
            store
                .authenticate_access(&pair3.access_token, NOW + 100)
                .is_none()
        );
        assert_eq!(
            recording.events(),
            [
                ("oauth_connect".to_owned(), None),
                ("oauth_refresh_reuse".to_owned(), None),
            ]
        );
        // pair3 worked until that reuse presentation ended it.
        // A second presentation of the original token is likewise
        // refused (the Connect is already ended).
        assert_eq!(
            store.refresh(&pair.refresh_token, CLIENT, NOW + 100 + GRACE_SECS),
            Err(TokenError::InvalidGrant)
        );
        assert!(
            store
                .authenticate_access(&pair3.access_token, NOW + 100)
                .is_none()
        );
    }

    #[test]
    fn reuse_writes_oauth_refresh_reuse_and_ends_the_connect() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        let (pair, id) = connect_one(&store);
        let _pair2 = store.refresh(&pair.refresh_token, CLIENT, NOW).unwrap();
        let err = store
            .refresh(&pair.refresh_token, CLIENT, NOW + GRACE_SECS + 1)
            .err()
            .unwrap();
        assert_eq!(err, TokenError::InvalidGrant);
        assert_eq!(
            recording.events(),
            [
                ("oauth_connect".to_owned(), None),
                ("oauth_refresh_reuse".to_owned(), None),
            ]
        );
        let entries = recording.entries.lock().unwrap();
        assert_eq!(entries[1].agent_id.as_deref(), Some(id.as_str()));
        assert_eq!(entries[1].origin.as_deref(), Some("dashboard.example"));
    }

    #[test]
    fn refresh_requires_the_issuing_client() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (pair, _id) = connect_one(&store);
        // A token presented by a different client is refused, and
        // the refusal spends nothing: the issuing client can still
        // rotate with it.
        assert_eq!(
            store.refresh(
                &pair.refresh_token,
                "https://other.example/.well-known/kharon-client.json",
                NOW + 1,
            ),
            Err(TokenError::InvalidGrant)
        );
        assert!(store.refresh(&pair.refresh_token, CLIENT, NOW + 1).is_ok());
    }

    #[test]
    fn concurrent_refreshers_and_revoke_all_end_everything() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (pair, _id) = connect_one(&store);
        let presented = pair.refresh_token.clone();
        // N refreshers of one token race a panic-style revoke_all.
        // Serialized writers may only produce the sequential
        // outcomes — at most a rotate and a grace retry succeed —
        // and whatever happens, the Connect ends revoked: no
        // racing swap resurrects it, in memory or on disk.
        let results: Vec<Result<IssuedPair, TokenError>> = std::thread::scope(|scope| {
            let refreshers: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| store.refresh(&presented, CLIENT, NOW + 10)))
                .collect();
            let revoker = scope.spawn(|| store.revoke_all());
            let mut results = Vec::new();
            for h in refreshers {
                results.push(h.join().unwrap());
            }
            let _ = revoker.join().unwrap();
            results
        });
        let issued: Vec<&IssuedPair> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert!(issued.len() <= 2, "{}", issued.len());
        for pair in &issued {
            assert!(
                store
                    .authenticate_access(&pair.access_token, NOW + 10)
                    .is_none()
            );
        }
        assert!(
            store
                .authenticate_access(&pair.access_token, NOW + 10)
                .is_none()
        );
        assert!(store.revoke_all().is_empty());
        // The end state is the persisted one.
        let reloaded = OauthStore::load(dir.path()).unwrap();
        assert!(
            reloaded
                .authenticate_access(&pair.access_token, NOW + 10)
                .is_none()
        );
        assert!(reloaded.revoke_all().is_empty());
    }

    #[test]
    fn refresh_idle_and_absolute_limits() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (pair, _id) = connect_one(&store);
        // Idle: 30 days after the last rotation the token is dead.
        assert_eq!(
            store.refresh(&pair.refresh_token, CLIENT, NOW + REFRESH_IDLE_SECS),
            Err(TokenError::InvalidGrant)
        );
        // Just inside the idle limit it rotates…
        let mut current = store
            .refresh(&pair.refresh_token, CLIENT, NOW + REFRESH_IDLE_SECS - 1)
            .unwrap();
        // …but nothing outlives 90 days from consent.
        let mut t = NOW + REFRESH_IDLE_SECS - 1;
        while t + REFRESH_IDLE_SECS - 1 < NOW + REFRESH_ABSOLUTE_SECS {
            t += REFRESH_IDLE_SECS - 1;
            current = store.refresh(&current.refresh_token, CLIENT, t).unwrap();
        }
        assert_eq!(
            store.refresh(&current.refresh_token, CLIENT, NOW + REFRESH_ABSOLUTE_SECS),
            Err(TokenError::InvalidGrant)
        );
    }

    #[test]
    fn revoke_access_ends_only_itself_revoke_refresh_ends_the_connect() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        let (pair, _id) = connect_one(&store);
        store.revoke(&pair.access_token, NOW).unwrap();
        assert!(store.authenticate_access(&pair.access_token, NOW).is_none());
        // The refresh token still works.
        let pair2 = store.refresh(&pair.refresh_token, CLIENT, NOW + 1).unwrap();
        // Revoking by the refresh token ends the whole Connect.
        store.revoke(&pair2.refresh_token, NOW + 2).unwrap();
        assert!(
            store
                .authenticate_access(&pair2.access_token, NOW + 2)
                .is_none()
        );
        assert_eq!(
            store.refresh(&pair2.refresh_token, CLIENT, NOW + 3),
            Err(TokenError::InvalidGrant)
        );
        // Unknown tokens are a quiet success (RFC 7009).
        store.revoke("kh_rt_unknown", NOW).unwrap();
        assert_eq!(
            recording.events().last().unwrap(),
            &("oauth_disconnect".to_owned(), Some("client".to_owned()))
        );
    }

    #[test]
    fn a_phase_1_identity_without_the_declaration_loads_as_not_declared() {
        // A state file written before #235: the identity has no
        // `connector_grant_declared` field.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("oauth")).unwrap();
        let phase1 = serde_json::json!({
            "version": STATE_VERSION,
            "identities": [{
                "id": "c-abcdefghij",
                "client_id": CLIENT,
                "client_name": "Dashboard",
                "scopes": ["kharon:read", "kharon:fill"],
                "created_at": NOW,
                "consented_at": NOW,
                "connected_via": "oauth",
                "revoked": false,
            }],
            "tokens": [],
        });
        std::fs::write(dir.path().join("oauth/state.json"), phase1.to_string()).unwrap();
        let store = OauthStore::load(dir.path()).unwrap();
        assert_eq!(store.connector_grant_declared("c-abcdefghij"), Some(false));
        assert_eq!(store.connector_grant_declared("c-zzzzzzzzzz"), None);
    }

    #[test]
    fn the_connector_grant_declaration_is_fixed_at_consent() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        // Connect A: its document did not declare the grant at consent.
        let (pair, undeclared) = connect_one(&store);
        // The client's document adds the grant; only a new Connect
        // (B, a fresh consent) records it.
        let (mut g, verifier) = grant("second-verifier");
        g.connector_grant_declared = true;
        let pair_b = store
            .connect(&g, &verifier, sha256(b"second-code"), NOW)
            .unwrap();
        let declared = store
            .authenticate_access(&pair_b.access_token, NOW)
            .unwrap()
            .agent_id;
        assert_ne!(undeclared, declared);
        assert_eq!(store.connector_grant_declared(&undeclared), Some(false));
        assert_eq!(store.connector_grant_declared(&declared), Some(true));
        // A's refresh rotates without touching the flag, and both
        // survive a reload as consented.
        store
            .refresh(&pair.refresh_token, CLIENT, NOW + 60)
            .unwrap();
        assert_eq!(store.connector_grant_declared(&undeclared), Some(false));
        drop(store);
        let reloaded = OauthStore::load(dir.path()).unwrap();
        assert_eq!(reloaded.connector_grant_declared(&undeclared), Some(false));
        assert_eq!(reloaded.connector_grant_declared(&declared), Some(true));
    }

    #[test]
    fn state_survives_a_reload_and_corruption_is_a_load_error() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (pair, id) = connect_one(&store);
        drop(store);
        let reloaded = OauthStore::load(dir.path()).unwrap();
        let auth = reloaded
            .authenticate_access(&pair.access_token, NOW)
            .unwrap();
        assert_eq!(auth.agent_id, id);
        // Disconnect persists too.
        reloaded
            .disconnect(&id, DisconnectDetail::Owner, "cli", NOW)
            .unwrap();
        let again = OauthStore::load(dir.path()).unwrap();
        assert!(again.authenticate_access(&pair.access_token, NOW).is_none());
        // Corrupt the file: load refuses (the daemon then refuses
        // to start, with `[oauth]` set).
        std::fs::write(dir.path().join("oauth/state.json"), b"{not json").unwrap();
        assert!(OauthStore::load(dir.path()).is_err());
    }

    #[test]
    fn access_tokens_expire_and_wrong_kinds_do_not_authenticate() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (pair, _id) = connect_one(&store);
        assert!(
            store
                .authenticate_access(&pair.access_token, NOW + ACCESS_TTL_SECS)
                .is_none()
        );
        // A refresh token is not an access token.
        assert!(
            store
                .authenticate_access(&pair.refresh_token, NOW)
                .is_none()
        );
        // An access token is not a refresh token.
        assert_eq!(
            store.refresh(&pair.access_token, CLIENT, NOW),
            Err(TokenError::InvalidGrant)
        );
    }

    #[test]
    fn failed_write_fails_the_request_with_no_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        // Sabotage persistence after the (empty) load: `oauth`
        // exists as a regular file, so the state write can never
        // land.
        std::fs::write(dir.path().join("oauth"), b"not a directory").unwrap();
        let (g, v) = grant("v");
        let err = store.connect(&g, &v, sha256(b"c"), NOW).err().unwrap();
        assert_eq!(err, TokenError::PersistFailed);
        // The compensating disconnect follows the connect (I5).
        assert_eq!(
            recording.events(),
            [
                ("oauth_connect".to_owned(), None),
                (
                    "oauth_disconnect".to_owned(),
                    Some("persist_failed".to_owned())
                ),
            ]
        );
    }

    #[test]
    fn revoke_all_ends_every_connect() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (pair, id) = connect_one(&store);
        let (pair2, id2) = connect_one(&store);
        let ended = store.revoke_all();
        assert_eq!(ended.len(), 2);
        assert!(store.authenticate_access(&pair.access_token, NOW).is_none());
        assert!(
            store
                .authenticate_access(&pair2.access_token, NOW)
                .is_none()
        );
        assert_ne!(id, id2);
    }

    #[test]
    fn unknown_code_records_no_marker() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let claim = store.begin_redemption(sha256(b"missing"), NOW, || None::<((), u64)>);
        assert!(matches!(claim, CodeClaim::Unknown));
        // A code that does exist afterwards is a first redemption.
        let claim = store.begin_redemption(sha256(b"real"), NOW, || Some(((), NOW)));
        assert!(matches!(claim, CodeClaim::Taken(())));
    }

    #[test]
    fn second_claim_before_commit_leaves_no_connect() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        let (g, verifier) = grant("correct-verifier");
        let code_hash = sha256(b"the-code");
        let taken = store.begin_redemption(code_hash, NOW, || Some(((), g.consented_at)));
        assert!(matches!(taken, CodeClaim::Taken(())));
        // The racer, after the take and before the commit. The code
        // store must not be consulted: the marker is the record.
        let second = store.begin_redemption(code_hash, NOW, || -> Option<((), u64)> {
            unreachable!("a pending marker must not consult the code store");
        });
        assert!(matches!(second, CodeClaim::Reuse { identity_id: None }));
        let err = store.connect(&g, &verifier, code_hash, NOW).err().unwrap();
        assert_eq!(err, TokenError::InvalidGrant);
        assert!(!std::fs::exists(dir.path().join("oauth/state.json")).unwrap());
        assert_eq!(
            recording.events(),
            [
                ("oauth_connect".to_owned(), None),
                ("oauth_disconnect".to_owned(), Some("code_reuse".to_owned())),
            ]
        );
        // The code stays spent: a later presentation is still refused,
        // and there is still no Connect to end.
        let third = store.begin_redemption(code_hash, NOW, || -> Option<((), u64)> {
            unreachable!("the marker outlives the failed commit");
        });
        assert!(matches!(third, CodeClaim::Reuse { identity_id: None }));
        assert!(recording.ended.lock().unwrap().is_empty());
    }

    #[test]
    fn claim_then_commit_names_the_identity_for_a_later_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _rec) = store(dir.path());
        let (g, verifier) = grant("correct-verifier");
        let code_hash = sha256(b"the-code");
        assert!(matches!(
            store.begin_redemption(code_hash, NOW, || Some(((), g.consented_at))),
            CodeClaim::Taken(())
        ));
        let pair = store.connect(&g, &verifier, code_hash, NOW).unwrap();
        let id = store
            .authenticate_access(&pair.access_token, NOW)
            .unwrap()
            .agent_id;
        assert_eq!(store.redeemed_identity(&code_hash, NOW), Some(id.clone()));
        let second = store.begin_redemption(code_hash, NOW, || -> Option<((), u64)> {
            unreachable!("a committed marker must not consult the code store");
        });
        match second {
            CodeClaim::Reuse {
                identity_id: Some(got),
            } => assert_eq!(got, id),
            other => panic!("expected the committed identity, got {other:?}"),
        }
    }

    #[test]
    fn failed_claim_redemption_leaves_no_connect_and_stays_spent() {
        let dir = tempfile::tempdir().unwrap();
        let (store, recording) = store(dir.path());
        let (g, verifier) = grant("correct-verifier");
        let code_hash = sha256(b"the-code");
        assert!(matches!(
            store.begin_redemption(code_hash, NOW, || Some(((), g.consented_at))),
            CodeClaim::Taken(())
        ));
        // Bad PKCE: nothing is audited, nothing is persisted.
        assert_eq!(
            store.connect(&g, "wrong", code_hash, NOW),
            Err(TokenError::InvalidGrant)
        );
        assert!(recording.events().is_empty());
        assert!(!std::fs::exists(dir.path().join("oauth/state.json")).unwrap());
        let again = store.begin_redemption(code_hash, NOW, || -> Option<((), u64)> {
            unreachable!("a failed redemption stays spent");
        });
        assert!(matches!(again, CodeClaim::Reuse { identity_id: None }));

        // Audit failure, same shape.
        let code_hash = sha256(b"other");
        assert!(matches!(
            store.begin_redemption(code_hash, NOW, || Some(((), g.consented_at))),
            CodeClaim::Taken(())
        ));
        *recording.fail_append.lock().unwrap() = true;
        assert_eq!(
            store.connect(&g, &verifier, code_hash, NOW),
            Err(TokenError::AuditFailed)
        );
        *recording.fail_append.lock().unwrap() = false;
        assert!(recording.events().is_empty());
        let again = store.begin_redemption(code_hash, NOW, || -> Option<((), u64)> {
            unreachable!("an audit failure stays spent");
        });
        assert!(matches!(again, CodeClaim::Reuse { identity_id: None }));

        // Persist failure: the chain reads connect then disconnect,
        // and the marker stays with no identity.
        let code_hash = sha256(b"third");
        assert!(matches!(
            store.begin_redemption(code_hash, NOW, || Some(((), g.consented_at))),
            CodeClaim::Taken(())
        ));
        std::fs::write(dir.path().join("oauth"), b"not a directory").unwrap();
        assert_eq!(
            store.connect(&g, &verifier, code_hash, NOW),
            Err(TokenError::PersistFailed)
        );
        assert_eq!(
            recording.events(),
            [
                ("oauth_connect".to_owned(), None),
                (
                    "oauth_disconnect".to_owned(),
                    Some("persist_failed".to_owned())
                ),
            ]
        );
        let again = store.begin_redemption(code_hash, NOW, || -> Option<((), u64)> {
            unreachable!("a persist failure stays spent");
        });
        assert!(matches!(again, CodeClaim::Reuse { identity_id: None }));
        assert!(recording.ended.lock().unwrap().is_empty());
    }
}
