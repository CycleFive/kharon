//! Broker accept loop for the agent connector (path B, REQ-ARCH-002).
//!
//! Agents dial `[connector].listen` over TLS, present a tunnel credential
//! (`kh_tunnel_...`, not an agent API token), and then the broker opens
//! CDP streams on that session. A failed credential never reaches the
//! mux. A new session for the same agent replaces the previous one.
//!
//! A Connect (#235) presents its connector access token (`kh_at_`)
//! instead, under its `c-…` id. The hello is dispatched on the token's
//! prefix before any Argon2id permit: `kh_at_` is a hash lookup through
//! [`ConnectTokens`], `kh_rt_` is refused outright. Such a session ends
//! when its token expires.
//!
//! At most [`ARGON2_CONCURRENCY`] Argon2id evaluations run at once, counted
//! across both transports, and each socket has one absolute pre-auth
//! deadline (#219): [`WS_PREAUTH_DEADLINE`] from its slot on the WebSocket
//! path, [`RAW_PREAUTH_DEADLINE`] from accept on the raw one.
//!
//! Framing, the pin, and reconnect live in `kharon-connector` so a review
//! of OQ-14 can change them in one place.
//!
//! Each accepted session is logged on attach (after `AUTH_OK`) and on
//! detach, with the agent id and peer address and never the credential
//! (#150). These are log lines, not audit entries: the audit chain records
//! requests, grants, fills and owner actions (SPEC §7, REQ-AUD-003), and a
//! transport attach changes none of them. Two connector events are audit
//! entries (#199), best effort and rate-limited per agent: a refused
//! credential for a configured agent (`connector_auth_fail`) and a session
//! that evicts a live one (`connector_replaced`).

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use kharon_connector::{
    AUTH_OK, AUTH_PROTOCOL, AUTH_UNAUTHORIZED, BrokerSession, MuxIo, WS_PREAUTH_SLOTS,
    read_client_hello, spawn_broker, write_server_hello,
};
pub use kharon_connector::{
    AgentParams, ClientError, connect_pinned, pin_of_der, run_agent_once, server_config_from_pem,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsAcceptor;

use crate::api::token::TokenStore;
use crate::audit::{Entry, Event};

mod ws;
pub use crate::audit::SessionTransport;
pub use ws::WsEntry;

/// A connector session event, reported once per occurrence (#150).
///
/// None of the variants carries credential material. `Display` renders the
/// log line without the `kharond: ` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorEvent {
    /// The tunnel credential was accepted and `AUTH_OK` was sent. `peer` is
    /// the TCP peer, which is the proxy when the agent dials through one.
    Attached {
        agent_id: String,
        transport: SessionTransport,
        peer: SocketAddr,
    },
    /// An attached session ended. `replaced` is true when a newer session
    /// for the same agent superseded it.
    Detached {
        agent_id: String,
        transport: SessionTransport,
        peer: SocketAddr,
        secs: u64,
        replaced: bool,
    },
    /// The tunnel credential was refused. The claimed agent id is not
    /// reported: it is unauthenticated input.
    Refused { peer: SocketAddr },
    /// The Argon2id check did not start before the pre-auth deadline. No
    /// credential was refused.
    Busy { peer: SocketAddr },
}

impl fmt::Display for ConnectorEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attached {
                agent_id,
                transport,
                peer,
            } => {
                write!(
                    f,
                    "agent connector attached: agent={agent_id} transport={transport} peer={peer}"
                )
            }
            Self::Detached {
                agent_id,
                transport,
                peer,
                secs,
                replaced,
            } => {
                write!(
                    f,
                    "agent connector detached: agent={agent_id} transport={transport} peer={peer} after={secs}s"
                )?;
                if *replaced {
                    f.write_str(" (replaced by a new session)")?;
                }
                Ok(())
            }
            Self::Refused { .. } => f.write_str("agent connector refused a credential"),
            Self::Busy { .. } => {
                f.write_str("agent connector busy: credential check did not start in time")
            }
        }
    }
}

/// Where connector events go. The default prints them to stderr.
pub type EventSink = Arc<dyn Fn(&ConnectorEvent) + Send + Sync>;

fn stderr_sink() -> EventSink {
    Arc::new(|event| eprintln!("kharond: {event}"))
}

/// Where the connector's audit entries go (#199): the broker's audit
/// append. Best effort: an `Err` is logged and changes nothing else.
pub type ConnectorAudit = Arc<dyn Fn(Entry) -> Result<(), ()> + Send + Sync>;

/// The hello prefix of a Connect access token (#235 D2).
pub const ACCESS_PREFIX: &str = "kh_at_";
/// The hello prefix of a Connect refresh token, refused with no lookup.
pub const REFRESH_PREFIX: &str = "kh_rt_";

/// What the OAuth store says about a `kh_at_` value presented in a hello
/// (#235 D4). Facts only; the hub applies D4's check order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectAccess {
    /// No live access token for the value: unknown, not an access token,
    /// expired, revoked, or its Connect has ended.
    Unknown,
    /// A live access token.
    Live {
        /// The Connect identity (`c-…`) the token belongs to.
        identity: String,
        /// The token's audience is `connector` (not `/mcp`).
        connector_audience: bool,
        /// The token carries `kharon:connector`.
        connector_scope: bool,
        /// The record's expiry, Unix seconds. The session ends then.
        expires_at: u64,
    },
}

/// The Connect side of the hello (#235 slice 5): looks up `kh_at_`
/// values by hash. Never an Argon2id permit. The OAuth store implements
/// it; tests can inject their own.
pub trait ConnectTokens: Send + Sync {
    /// Check `presented` at `now` (Unix seconds).
    fn access(&self, presented: &str, now: u64) -> ConnectAccess;
    /// Whether `agent_id` is a Connect identity the store knows, ended
    /// ones included (the audit's "auditable id" rule).
    fn is_connect(&self, agent_id: &str) -> bool;
}

/// Why a hello was refused: the `detail_code` of its
/// `connector_auth_fail` entry, in D4's check order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailDetail {
    /// No live credential for the presented value. Every tunnel refusal.
    Unauthorized,
    /// A live access token whose audience is not `connector`.
    Audience,
    /// A connector token presented under another agent id.
    Identity,
    /// A connector token without `kharon:connector`.
    Scope,
}

impl AuthFailDetail {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Audience => "audience",
            Self::Identity => "identity",
            Self::Scope => "scope",
        }
    }
}

/// Unix seconds now.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Argon2id evaluations allowed at once, across both transports (#219).
pub const ARGON2_CONCURRENCY: usize = 2;
/// Pre-auth time of a WebSocket socket, from its slot to the start of the
/// Argon2id check. A hash already running is bounded by its parameters.
pub const WS_PREAUTH_DEADLINE: Duration = Duration::from_secs(10);
/// Pre-auth time of a raw socket, from accept to the start of the Argon2id
/// check: the old 10 s TLS plus 5 s hello maximum.
pub const RAW_PREAUTH_DEADLINE: Duration = Duration::from_secs(15);

/// The bound on a server-hello write that only tells a refused or
/// malformed peer why it is being closed. A refusal's closing answer gets
/// at most this long after the slot is freed. The `AUTH_PROTOCOL` write
/// happens while the pre-auth slot is still held, so it also stops at the
/// socket's deadline (whichever is earlier); the `AUTH_UNAUTHORIZED` write
/// comes after the slot is released and has this bound alone (#220).
const TRAILING_HELLO_WRITE: Duration = Duration::from_secs(1);

/// Accepted connector sessions, keyed by agent id.
pub struct Hub {
    tokens: TokenStore,
    sessions: std::sync::Mutex<HashMap<String, Live>>,
    changed: Notify,
    auth: Arc<Semaphore>,
    /// Pre-auth budget of the WebSocket path, separate from `auth` (#199).
    ws_auth: Arc<Semaphore>,
    /// Argon2id evaluations at once, shared by both transports (#219). A
    /// permit moves into the blocking task, so it is held for as long as
    /// the hash runs, whatever happens to the connection.
    argon: Arc<Semaphore>,
    /// WebSocket connections refused after the ClientHello gate, since the
    /// last per-minute line: the inner TLS handshake failed or timed out
    /// (`tls`), and the hello was malformed, timed out, carried a refused
    /// credential, or waited out the deadline for an Argon2id permit
    /// (`auth`). Counted, never reported per event (#199).
    ws_refused_tls: AtomicU64,
    ws_refused_auth: AtomicU64,
    next: AtomicU64,
    events: EventSink,
    /// Audit sink; unset means the connector writes no audit entries.
    audit: OnceLock<ConnectorAudit>,
    /// The Connect token lookup (`[oauth]`); unset means every `kh_at_`
    /// hello is refused, still without an Argon2id permit.
    connect: OnceLock<Arc<dyn ConnectTokens>>,
    /// Per-agent rate-limit windows for the two audit events.
    limits: std::sync::Mutex<Limits>,
}

/// Length of one audit rate-limit window.
const AUDIT_WINDOW: Duration = Duration::from_secs(60);

/// One (event kind, agent) window: when it opened and how many events it
/// has swallowed since its entry was written.
struct Window {
    start: Instant,
    pending: u64,
}

/// Rate-limit state of the two connector audit events. Keyed by configured
/// agent id only, so a peer cannot grow it.
#[derive(Default)]
struct Limits {
    auth_fail: HashMap<String, Window>,
    replaced: HashMap<String, Window>,
}

/// `Some(suppressed)` when an entry is due for `agent` at `now`: the
/// first event ever, or the first after the window expired. Otherwise the
/// event is only counted.
fn admit(windows: &mut HashMap<String, Window>, agent: &str, now: Instant) -> Option<u64> {
    match windows.get_mut(agent) {
        None => {
            windows.insert(
                agent.to_owned(),
                Window {
                    start: now,
                    pending: 0,
                },
            );
            Some(0)
        }
        Some(w) if now.duration_since(w.start) >= AUDIT_WINDOW => {
            let suppressed = std::mem::take(&mut w.pending);
            w.start = now;
            Some(suppressed)
        }
        Some(w) => {
            w.pending = w.pending.saturating_add(1);
            None
        }
    }
}

/// Remove every window `expired` selects from `windows`, pushing a summary
/// entry onto `out` for each one that has a pending count.
fn drain_windows(
    windows: &mut HashMap<String, Window>,
    event: Event,
    out: &mut Vec<Entry>,
    expired: impl Fn(&Window) -> bool,
) {
    windows.retain(|agent, w| {
        if !expired(w) {
            return true;
        }
        if w.pending > 0 {
            out.push(
                Entry::new(event.clone())
                    .agent_id(agent.as_str())
                    .suppressed(w.pending)
                    .result("suppressed_only"),
            );
        }
        false
    });
}

struct Live {
    id: u64,
    session: BrokerSession,
    /// Set when a newer session for the same agent evicts this one.
    replaced: Arc<AtomicBool>,
    /// When this session was registered.
    since: Instant,
    /// Unix seconds the authenticating token expires (#235 D5); `None`
    /// for a tunnel credential, which does not expire.
    expires_at: Option<u64>,
}

impl Live {
    /// Live at `now` (Unix seconds): a session past its token's expiry is
    /// absent even before its timer runs. No grace.
    fn current(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|exp| now < exp)
    }
}

impl Hub {
    /// `tokens` holds only connector hashes (`kh_tunnel_` prefix). Session
    /// events are logged to stderr.
    pub fn new(tokens: TokenStore) -> Self {
        Self::with_events(tokens, stderr_sink())
    }

    /// Like [`Hub::new`], with session events sent to `events`.
    pub fn with_events(tokens: TokenStore, events: EventSink) -> Self {
        Self {
            tokens,
            sessions: std::sync::Mutex::new(HashMap::new()),
            changed: Notify::new(),
            auth: Arc::new(Semaphore::new(4)),
            ws_auth: Arc::new(Semaphore::new(WS_PREAUTH_SLOTS)),
            argon: Arc::new(Semaphore::new(ARGON2_CONCURRENCY)),
            ws_refused_tls: AtomicU64::new(0),
            ws_refused_auth: AtomicU64::new(0),
            next: AtomicU64::new(1),
            events,
            audit: OnceLock::new(),
            connect: OnceLock::new(),
            limits: std::sync::Mutex::new(Limits::default()),
        }
    }

    /// Accept Connect access tokens in the hello, checked by `tokens`
    /// (#235 slice 5). Set once; a later call is ignored.
    pub fn set_connect_tokens(&self, tokens: Arc<dyn ConnectTokens>) {
        let _ = self.connect.set(tokens);
    }

    /// Whether `agent_id` may hold a session: a configured agent, or a
    /// Connect identity the store knows.
    fn is_known_agent(&self, agent_id: &str) -> bool {
        self.tokens.agents().any(|id| id == agent_id)
            || self.connect.get().is_some_and(|c| c.is_connect(agent_id))
    }

    /// Send the connector's audit entries to `sink` (the broker's audit
    /// append). Set once; a later call is ignored.
    pub fn set_audit(&self, sink: ConnectorAudit) {
        let _ = self.audit.set(sink);
    }

    /// Append `entry` through the sink, if one is set. The sink runs
    /// synchronously on the calling connection task; the per-agent
    /// per-minute limiter bounds how often. Best effort: a
    /// failure prints a fixed line (no detail) and changes nothing. Never
    /// call this with a `Hub` lock held.
    fn emit(&self, entry: Entry) {
        if let Some(sink) = self.audit.get()
            && sink(entry).is_err()
        {
            eprintln!("kharond: connector audit append failed");
        }
    }

    /// Audit a refused hello that claimed `claimed` (#199), with detail
    /// `unauthorized`. See [`Hub::audit_auth_fail_with`].
    pub fn audit_auth_fail(&self, claimed: &str, transport: SessionTransport) {
        self.audit_auth_fail_with(claimed, transport, AuthFailDetail::Unauthorized);
    }

    /// Audit a refused hello that claimed `claimed` (#199, #235). Written
    /// only when `claimed` is a configured agent or a Connect identity in
    /// the store (ended ones included), at most one entry per id per 60 s
    /// whatever the detail; unknown ids and junk are not audited. A
    /// malformed hello carries no attributable agent id and never gets
    /// here. The token is never part of the entry.
    pub fn audit_auth_fail_with(
        &self,
        claimed: &str,
        transport: SessionTransport,
        detail: AuthFailDetail,
    ) {
        if !self.is_known_agent(claimed) {
            return;
        }
        let due = {
            let mut limits = self.limits.lock().unwrap_or_else(|p| p.into_inner());
            admit(&mut limits.auth_fail, claimed, Instant::now())
        };
        if let Some(suppressed) = due {
            self.emit(
                Entry::new(Event::ConnectorAuthFail)
                    .agent_id(claimed)
                    .transport(transport)
                    .detail_code(detail.as_str())
                    .suppressed(suppressed),
            );
        }
    }

    /// Write the counts the rate limiter swallowed (#219). For every window
    /// older than [`AUDIT_WINDOW`] at `now`, a summary entry when anything
    /// is pending; the window is then dropped, so the agent's next event
    /// writes at once. Without this a burst followed by silence would never
    /// reach the log. The sink runs after the `limits` lock is released.
    pub fn flush_audit(&self, now: Instant) {
        self.flush_where(|w| now.saturating_duration_since(w.start) >= AUDIT_WINDOW);
    }

    /// Shutdown: a summary entry for every window with a pending count,
    /// open or not, then forget all windows (#219).
    pub fn flush_audit_all(&self) {
        self.flush_where(|_| true);
    }

    /// Drain the windows `expired` selects under the lock, then write the
    /// summaries with it released.
    fn flush_where(&self, expired: impl Fn(&Window) -> bool) {
        let mut out = Vec::new();
        {
            let mut limits = self.limits.lock().unwrap_or_else(|p| p.into_inner());
            let Limits {
                auth_fail,
                replaced,
            } = &mut *limits;
            drain_windows(auth_fail, Event::ConnectorAuthFail, &mut out, &expired);
            drain_windows(replaced, Event::ConnectorReplaced, &mut out, &expired);
        }
        for entry in out {
            self.emit(entry);
        }
    }

    /// WebSocket sockets that are past the upgrade but have not finished
    /// the Argon2id check. At most [`WS_PREAUTH_SLOTS`].
    pub fn ws_preauth_in_flight(&self) -> usize {
        WS_PREAUTH_SLOTS.saturating_sub(self.ws_auth.available_permits())
    }

    /// Argon2id evaluations running now, across both transports. At most
    /// [`ARGON2_CONCURRENCY`].
    pub fn argon_in_flight(&self) -> usize {
        ARGON2_CONCURRENCY.saturating_sub(self.argon.available_permits())
    }

    fn report(&self, event: ConnectorEvent) {
        (self.events)(&event);
    }

    /// Whether `agent_id` has a live authenticated session. A session past
    /// its token's expiry is not one, even before its timer runs.
    pub fn is_connected(&self, agent_id: &str) -> bool {
        let now = unix_now();
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(agent_id)
            .is_some_and(|live| live.current(now))
    }

    /// Drop `agent_id`'s session, if any. The agent is expected to redial.
    pub fn disconnect(&self, agent_id: &str) {
        if let Some(live) = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(agent_id)
        {
            live.session.shutdown();
            self.changed.notify_waiters();
        }
    }

    /// Open one CDP stream for `agent_id`, waiting until a session exists.
    /// Dial failures are returned; a missing session waits (the caller's
    /// connect budget is the timeout).
    pub async fn open_stream(&self, agent_id: &str) -> Result<MuxIo, kharon_connector::OpenError> {
        if !self.is_known_agent(agent_id) {
            return Err(kharon_connector::OpenError::Closed);
        }
        loop {
            let notified = self.changed.notified();
            if let Some(session) = self.session(agent_id) {
                match session.open_stream().await {
                    Ok(io) => return Ok(io),
                    Err(e @ kharon_connector::OpenError::DialFailed)
                    | Err(e @ kharon_connector::OpenError::TooManyStreams) => return Err(e),
                    Err(kharon_connector::OpenError::Closed) => {}
                }
            }
            notified.await;
        }
    }

    fn session(&self, agent_id: &str) -> Option<BrokerSession> {
        let now = unix_now();
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(agent_id)
            .filter(|live| live.current(now))
            .map(|live| live.session.clone())
    }

    /// Register `session` for `agent`, evicting (and flagging as replaced)
    /// any older session. Returns the new session's id and its flag.
    /// `transport` is the new session's; an eviction is audited with it
    /// (`connector_replaced`, #199) after the sessions lock is released.
    fn insert(
        &self,
        agent: String,
        session: BrokerSession,
        transport: SessionTransport,
        expires_at: Option<u64>,
    ) -> (u64, Arc<AtomicBool>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let replaced = Arc::new(AtomicBool::new(false));
        let now = Instant::now();
        let live = Live {
            id,
            session,
            replaced: Arc::clone(&replaced),
            since: now,
            expires_at,
        };
        let mut map = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        let old_age = map.insert(agent.clone(), live).map(|old| {
            old.replaced.store(true, Ordering::SeqCst);
            old.session.shutdown();
            now.duration_since(old.since).as_secs()
        });
        drop(map);
        self.changed.notify_waiters();
        if let Some(old_secs) = old_age {
            let due = {
                let mut limits = self.limits.lock().unwrap_or_else(|p| p.into_inner());
                admit(&mut limits.replaced, &agent, now)
            };
            if let Some(suppressed) = due {
                self.emit(
                    Entry::new(Event::ConnectorReplaced)
                        .agent_id(agent)
                        .transport(transport)
                        .old_session_secs(old_secs)
                        .suppressed(suppressed),
                );
            }
        }
        (id, replaced)
    }

    /// The Connect half of the hello's prefix dispatch (#235 D2, D4).
    /// `None`: not a Connect token, so the tunnel path (Argon2id) decides.
    /// Otherwise the token's expiry on success, or why it was refused, in
    /// D4's order. Never touches the sessions map, so a refusal evicts
    /// nobody.
    pub(crate) fn check_connect(
        &self,
        claimed: &str,
        token: &str,
        now: u64,
    ) -> Option<Result<u64, AuthFailDetail>> {
        if token.starts_with(REFRESH_PREFIX) {
            return Some(Err(AuthFailDetail::Unauthorized));
        }
        if !token.starts_with(ACCESS_PREFIX) {
            return None;
        }
        let Some(connect) = self.connect.get() else {
            return Some(Err(AuthFailDetail::Unauthorized));
        };
        Some(match connect.access(token, now) {
            ConnectAccess::Unknown => Err(AuthFailDetail::Unauthorized),
            ConnectAccess::Live {
                connector_audience: false,
                ..
            } => Err(AuthFailDetail::Audience),
            ConnectAccess::Live { identity, .. } if identity != claimed => {
                Err(AuthFailDetail::Identity)
            }
            ConnectAccess::Live {
                connector_scope: false,
                ..
            } => Err(AuthFailDetail::Scope),
            ConnectAccess::Live { expires_at, .. } => Ok(expires_at),
        })
    }

    fn remove_if(&self, agent: &str, id: u64) {
        let mut map = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if map.get(agent).is_some_and(|live| live.id == id) {
            map.remove(agent);
            drop(map);
            self.changed.notify_waiters();
        }
    }
}

/// Accept connector dials until `listener` fails.
pub async fn accept(listener: TcpListener, tls: Arc<rustls::ServerConfig>, hub: Arc<Hub>) {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let hub = Arc::clone(&hub);
        tokio::spawn(async move {
            let Ok(permit) = hub.auth.clone().try_acquire_owned() else {
                return;
            };
            let deadline = Instant::now() + RAW_PREAUTH_DEADLINE;
            authenticate_and_serve(
                tcp,
                peer,
                SessionTransport::Tls,
                acceptor,
                hub,
                deadline,
                permit,
                None,
            )
            .await;
        });
    }
}

/// Resolves when `stop` flips to true. Never resolves without a `stop`
/// (or once its sender is gone).
async fn stopped(stop: &mut Option<watch::Receiver<bool>>) {
    if let Some(rx) = stop
        && rx.wait_for(|v| *v).await.is_ok()
    {
        return;
    }
    std::future::pending::<()>().await;
}

/// The pre-auth half: inner TLS, hello, Argon2id. All of it, up to the
/// start of the hash, must finish by `deadline`. `permit` (the pre-auth
/// slot) is dropped as soon as the Argon2id result is known.
async fn authenticate<S>(
    stream: S,
    peer: SocketAddr,
    transport: SessionTransport,
    acceptor: TlsAcceptor,
    hub: &Arc<Hub>,
    deadline: Instant,
    permit: OwnedSemaphorePermit,
) -> Option<(tokio_rustls::server::TlsStream<S>, String, Option<u64>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(Ok(mut tls)) = timeout_at(deadline, acceptor.accept(stream)).await else {
        if transport == SessionTransport::Ws {
            hub.ws_refused_tls.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    };
    let hello = match timeout_at(deadline, read_client_hello(&mut tls)).await {
        Ok(Ok(hello)) => hello,
        _ => {
            if transport == SessionTransport::Ws {
                hub.ws_refused_auth.fetch_add(1, Ordering::Relaxed);
            }
            // The slot is still held here, so this write may not outlive
            // the socket's deadline either. Best effort: a write that is
            // ready at once still goes out, and it adds no hold time.
            let _ = timeout_at(
                deadline.min(Instant::now() + TRAILING_HELLO_WRITE),
                write_server_hello(&mut tls, AUTH_PROTOCOL),
            )
            .await;
            return None;
        }
    };
    // #235 D2: dispatch on the token's prefix after the hello parses and
    // before any Argon2id permit. A Connect access token is a hash lookup;
    // a refresh token is refused outright. Neither may spend a permit.
    if let Some(verdict) = hub.check_connect(&hello.agent_id, hello.token.as_str(), unix_now()) {
        drop(permit);
        return match verdict {
            Ok(expires_at) => {
                if write_server_hello(&mut tls, AUTH_OK).await.is_err() {
                    return None;
                }
                Some((tls, hello.agent_id, Some(expires_at)))
            }
            Err(detail) => {
                refuse(&mut tls, peer, transport, hub, &hello.agent_id, detail).await;
                None
            }
        };
    }
    // At most `ARGON2_CONCURRENCY` evaluations run at once, across both
    // transports. The wait is bounded by the socket's deadline; running out
    // of time here writes no server hello, so a legitimate client sees a
    // disconnect and retries with jitter instead of the 60 s refusal wait.
    let Ok(Ok(argon)) = timeout_at(deadline, hub.argon.clone().acquire_owned()).await else {
        if transport == SessionTransport::Ws {
            hub.ws_refused_auth.fetch_add(1, Ordering::Relaxed);
        } else {
            hub.report(ConnectorEvent::Busy { peer });
        }
        return None;
    };
    let agent_id = hello.agent_id.clone();
    let token = hello.token.clone();
    let tokens_hub = Arc::clone(hub);
    // The Argon2id permit moves into the blocking task: it is released when
    // the hash returns, even if this future was dropped meanwhile. A hash
    // that has started is not bounded by the deadline; the Argon2 params are.
    let authed = tokio::task::spawn_blocking(move || {
        let _argon = argon;
        tokens_hub
            .tokens
            .authenticate_for(&agent_id, token.as_str())
    })
    .await;
    drop(permit);
    if matches!(authed, Ok(Ok(()))) {
        if write_server_hello(&mut tls, AUTH_OK).await.is_err() {
            return None;
        }
        Some((tls, hello.agent_id, None))
    } else {
        refuse(
            &mut tls,
            peer,
            transport,
            hub,
            &hello.agent_id,
            AuthFailDetail::Unauthorized,
        )
        .await;
        None
    }
}

/// The refusal tail shared by both credential paths: count or log it,
/// audit it for an auditable id, and answer `AUTH_UNAUTHORIZED` within
/// [`TRAILING_HELLO_WRITE`]. The pre-auth slot is already released.
async fn refuse<S>(
    tls: &mut tokio_rustls::server::TlsStream<S>,
    peer: SocketAddr,
    transport: SessionTransport,
    hub: &Hub,
    claimed: &str,
    detail: AuthFailDetail,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The raw listener logs each refusal (#150). On the public path any
    // stranger can reach this, so a refusal is only counted.
    if transport == SessionTransport::Ws {
        hub.ws_refused_auth.fetch_add(1, Ordering::Relaxed);
    } else {
        hub.report(ConnectorEvent::Refused { peer });
    }
    hub.audit_auth_fail_with(claimed, transport, detail);
    let _ = timeout(
        TRAILING_HELLO_WRITE,
        write_server_hello(tls, AUTH_UNAUTHORIZED),
    )
    .await;
}

/// Run one connector socket from inner TLS to detach. `stop` ends the
/// session early (the WebSocket path's shutdown); the raw path passes
/// `None`.
#[allow(clippy::too_many_arguments)]
async fn authenticate_and_serve<S>(
    stream: S,
    peer: SocketAddr,
    transport: SessionTransport,
    acceptor: TlsAcceptor,
    hub: Arc<Hub>,
    deadline: Instant,
    permit: OwnedSemaphorePermit,
    mut stop: Option<watch::Receiver<bool>>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let authed = tokio::select! {
        a = authenticate(stream, peer, transport, acceptor, &hub, deadline, permit) => a,
        () = stopped(&mut stop) => return,
    };
    let Some((tls, agent_id, expires_at)) = authed else {
        return;
    };
    let session = spawn_broker(tls);
    let since = Instant::now();
    // Report before the session is visible, so anyone who sees
    // `is_connected` also sees the attach.
    hub.report(ConnectorEvent::Attached {
        agent_id: agent_id.clone(),
        transport,
        peer,
    });
    let (id, replaced) = hub.insert(agent_id.clone(), session.clone(), transport, expires_at);
    // #235 D5: a Connect session ends when its access token expires, with
    // no grace. The drop is the ordinary detach line, not an audit entry.
    let expiry = async {
        match expires_at {
            Some(exp) => {
                let left = exp.saturating_sub(unix_now());
                tokio::time::sleep(Duration::from_secs(left)).await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        () = session.closed() => {}
        () = stopped(&mut stop) => session.shutdown(),
        () = expiry => session.shutdown(),
    }
    hub.remove_if(&agent_id, id);
    hub.report(ConnectorEvent::Detached {
        agent_id,
        transport,
        peer,
        secs: since.elapsed().as_secs(),
        replaced: replaced.load(Ordering::SeqCst),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::token::{ParamFloor, TUNNEL_PREFIX, TokenStore, generate_tunnel_with};
    use std::sync::Mutex;

    fn hub() -> (Hub, Arc<Mutex<Vec<Entry>>>) {
        let floor = ParamFloor {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let argon = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(8, 1, 1, None).unwrap(),
        );
        let (_, a) = generate_tunnel_with(&argon, "assistant");
        let (_, b) = generate_tunnel_with(&argon, "other");
        let store = TokenStore::with_floor_and_prefix(
            [("assistant", a.as_str()), ("other", b.as_str())],
            &floor,
            TUNNEL_PREFIX,
        )
        .unwrap();
        let hub = Hub::with_events(store, Arc::new(|_| {}));
        let entries = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&entries);
        hub.set_audit(Arc::new(move |e| {
            sink.lock().unwrap().push(e);
            Ok(())
        }));
        (hub, entries)
    }

    const CID: &str = "c-abcdefghij";

    /// A Connect token lookup with fixed answers per token.
    struct FakeConnect(HashMap<&'static str, ConnectAccess>);

    impl ConnectTokens for FakeConnect {
        fn access(&self, presented: &str, _now: u64) -> ConnectAccess {
            self.0
                .get(presented)
                .cloned()
                .unwrap_or(ConnectAccess::Unknown)
        }
        fn is_connect(&self, agent_id: &str) -> bool {
            agent_id == CID
        }
    }

    fn live(identity: &str, audience: bool, scope: bool) -> ConnectAccess {
        ConnectAccess::Live {
            identity: identity.into(),
            connector_audience: audience,
            connector_scope: scope,
            expires_at: 4_000_000_000,
        }
    }

    fn connect_hub() -> (Hub, Arc<Mutex<Vec<Entry>>>) {
        let (hub, entries) = hub();
        hub.set_connect_tokens(Arc::new(FakeConnect(HashMap::from([
            ("kh_at_good", live(CID, true, true)),
            ("kh_at_mcp", live(CID, false, true)),
            ("kh_at_other", live("c-otherother", true, true)),
            ("kh_at_noscope", live(CID, true, false)),
        ]))));
        (hub, entries)
    }

    /// D2/D4: prefix dispatch and the check order. A tunnel token is not a
    /// Connect token; a refresh token never reaches the lookup.
    #[test]
    fn connect_checks_run_in_d4_order() {
        let (hub, _) = connect_hub();
        let check = |claimed: &str, token: &str| hub.check_connect(claimed, token, 0);
        assert_eq!(check(CID, "kh_at_good"), Some(Ok(4_000_000_000)));
        assert_eq!(check(CID, "kh_at_mcp"), Some(Err(AuthFailDetail::Audience)));
        // Audience is checked before identity.
        assert_eq!(
            check("c-otherother", "kh_at_mcp"),
            Some(Err(AuthFailDetail::Audience))
        );
        assert_eq!(
            check(CID, "kh_at_other"),
            Some(Err(AuthFailDetail::Identity))
        );
        assert_eq!(
            check(CID, "kh_at_noscope"),
            Some(Err(AuthFailDetail::Scope))
        );
        assert_eq!(
            check(CID, "kh_at_unknown"),
            Some(Err(AuthFailDetail::Unauthorized))
        );
        assert_eq!(
            check(CID, "kh_rt_good"),
            Some(Err(AuthFailDetail::Unauthorized))
        );
        assert_eq!(check("assistant", "kh_tunnel_assistant_00"), None);
        assert_eq!(check("assistant", "junk"), None);
        // Without `[oauth]` a Connect token is refused, still with no permit.
        let (bare, _) = super::tests::hub();
        assert_eq!(
            bare.check_connect(CID, "kh_at_good", 0),
            Some(Err(AuthFailDetail::Unauthorized))
        );
    }

    /// The `connector_auth_fail` detail codes share one window per id; a
    /// known Connect id is auditable, an unknown `c-…` id writes nothing.
    #[tokio::test(start_paused = true)]
    async fn connect_auth_fail_details_share_one_window() {
        let (hub, entries) = connect_hub();
        hub.audit_auth_fail_with(CID, SessionTransport::Ws, AuthFailDetail::Audience);
        hub.audit_auth_fail_with(CID, SessionTransport::Ws, AuthFailDetail::Identity);
        hub.audit_auth_fail_with(CID, SessionTransport::Tls, AuthFailDetail::Unauthorized);
        hub.audit_auth_fail_with(
            "c-zzzzzzzzzz",
            SessionTransport::Ws,
            AuthFailDetail::Audience,
        );
        {
            let all = entries.lock().unwrap();
            assert_eq!(all.len(), 1, "one entry per id per minute: {all:?}");
            assert_eq!(all[0].event, Event::ConnectorAuthFail);
            assert_eq!(all[0].agent_id.as_deref(), Some(CID));
            assert_eq!(all[0].detail_code.as_deref(), Some("audience"));
            assert_eq!(all[0].suppressed, Some(0));
        }
        tokio::time::advance(AUDIT_WINDOW).await;
        hub.audit_auth_fail_with(CID, SessionTransport::Ws, AuthFailDetail::Identity);
        let all = entries.lock().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].detail_code.as_deref(), Some("identity"));
        assert_eq!(all[1].suppressed, Some(2));
    }

    /// A4: a session past its token's `expires_at` is absent before any
    /// timer runs: not connected, and no stream lookup finds it.
    #[tokio::test]
    async fn expired_session_is_absent_before_its_timer() {
        let (hub, _) = connect_hub();
        let (a, _b) = tokio::io::duplex(1024);
        let session = spawn_broker(a);
        let now = unix_now();
        hub.insert(
            CID.into(),
            session.clone(),
            SessionTransport::Ws,
            Some(now + 3600),
        );
        assert!(hub.is_connected(CID));
        assert!(hub.session(CID).is_some());
        // Same session, expiry already passed: still in the map, not live.
        hub.insert(
            CID.into(),
            session,
            SessionTransport::Ws,
            Some(now.saturating_sub(1)),
        );
        assert!(hub.sessions.lock().unwrap().contains_key(CID));
        assert!(!hub.is_connected(CID));
        assert!(hub.session(CID).is_none());
    }

    /// Count one `replaced` event for `agent` the way `insert` does.
    fn replaced_event(hub: &Hub, agent: &str, now: Instant) {
        let due = {
            let mut limits = hub.limits.lock().unwrap();
            admit(&mut limits.replaced, agent, now)
        };
        if let Some(suppressed) = due {
            hub.emit(
                Entry::new(Event::ConnectorReplaced)
                    .agent_id(agent)
                    .suppressed(suppressed),
            );
        }
    }

    fn summaries(entries: &Mutex<Vec<Entry>>, event: Event, agent: &str) -> Vec<Entry> {
        entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| {
                e.event == event
                    && e.agent_id.as_deref() == Some(agent)
                    && e.result.as_deref() == Some("suppressed_only")
            })
            .cloned()
            .collect()
    }

    /// Both windows of one agent and one window of another flush on their
    /// own: one summary each where something is pending, none elsewhere.
    #[tokio::test(start_paused = true)]
    async fn flush_is_per_agent_and_event() {
        let (hub, entries) = hub();
        let t0 = Instant::now();
        // assistant: auth_fail pending 2, replaced pending 1.
        for _ in 0..3 {
            hub.audit_auth_fail("assistant", SessionTransport::Tls);
        }
        replaced_event(&hub, "assistant", t0);
        replaced_event(&hub, "assistant", t0);
        // other: auth_fail pending 0, replaced pending 4.
        hub.audit_auth_fail("other", SessionTransport::Tls);
        for _ in 0..5 {
            replaced_event(&hub, "other", t0);
        }
        hub.flush_audit(t0 + AUDIT_WINDOW);
        let a = summaries(&entries, Event::ConnectorAuthFail, "assistant");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].suppressed, Some(2));
        let r = summaries(&entries, Event::ConnectorReplaced, "assistant");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].suppressed, Some(1));
        assert!(summaries(&entries, Event::ConnectorAuthFail, "other").is_empty());
        let r = summaries(&entries, Event::ConnectorReplaced, "other");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].suppressed, Some(4));
        assert!(r[0].transport.is_none() && r[0].old_session_secs.is_none());
    }

    /// A window that expires with nothing pending writes nothing and is
    /// dropped, so the next event is a fresh first event.
    #[tokio::test(start_paused = true)]
    async fn expired_empty_window_writes_nothing() {
        let (hub, entries) = hub();
        let t0 = Instant::now();
        replaced_event(&hub, "assistant", t0);
        assert_eq!(entries.lock().unwrap().len(), 1);
        hub.flush_audit(t0 + AUDIT_WINDOW);
        assert_eq!(entries.lock().unwrap().len(), 1, "nothing was pending");
        assert!(
            hub.limits.lock().unwrap().replaced.is_empty(),
            "the expired window was dropped"
        );
        replaced_event(
            &hub,
            "assistant",
            t0 + AUDIT_WINDOW + Duration::from_secs(1),
        );
        let all = entries.lock().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].suppressed, Some(0));
    }

    /// Open windows with pending counts are written by `flush_audit_all`
    /// and both maps are cleared.
    #[tokio::test(start_paused = true)]
    async fn flush_all_covers_replaced_and_clears() {
        let (hub, entries) = hub();
        let t0 = Instant::now();
        replaced_event(&hub, "assistant", t0);
        replaced_event(&hub, "assistant", t0);
        replaced_event(&hub, "assistant", t0);
        hub.flush_audit_all();
        let r = summaries(&entries, Event::ConnectorReplaced, "assistant");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].suppressed, Some(2));
        let limits = hub.limits.lock().unwrap();
        assert!(limits.auth_fail.is_empty() && limits.replaced.is_empty());
    }

    /// A server-side stream that passes everything through until armed, then
    /// never completes a write or flush: a peer that has stopped reading.
    struct Stall<S> {
        inner: S,
        armed: Arc<AtomicBool>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Stall<S> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Stall<S> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.armed.load(Ordering::SeqCst) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.armed.load(Ordering::SeqCst) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Drive `authenticate` over an in-memory stream whose server side stops
    /// accepting writes right after the TLS handshake, send `hello_record`
    /// (a whole length-prefixed record) and never read. Returns how long
    /// `authenticate` took after the hello was sent; asserts it returned
    /// `None`, released the slot, and never took the TLS-failure branch.
    /// `hello_record` of `None` sends nothing at all. The socket's deadline
    /// is `deadline_in` after the call.
    async fn stalled_refusal(hello_record: Option<Vec<u8>>, deadline_in: Duration) -> Run {
        use kharon_connector::{TlsVersions, connect_pinned_stream, server_config_from_pem_with};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pin = kharon_connector::pin_of_der(certified.cert.der());
        let server_cfg = server_config_from_pem_with(
            certified.cert.pem().as_bytes(),
            certified.key_pair.serialize_pem().as_bytes(),
            TlsVersions::Tls13Only,
        )
        .unwrap();
        let (hub, entries) = hub();
        let hub = Arc::new(hub);
        let permit = hub.ws_auth.clone().try_acquire_owned().unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = Stall {
            inner: server_io,
            armed: Arc::clone(&armed),
        };
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let deadline_std = std::time::Instant::now() + deadline_in;
        let deadline = Instant::now() + deadline_in;
        let task = tokio::spawn({
            let hub = Arc::clone(&hub);
            async move {
                authenticate(
                    server,
                    peer,
                    SessionTransport::Ws,
                    TlsAcceptor::from(server_cfg),
                    &hub,
                    deadline,
                    permit,
                )
                .await
                .is_none()
            }
        });
        let mut client = connect_pinned_stream("localhost", pin, client_io, TlsVersions::Tls13Only)
            .await
            .unwrap();
        // A TLS 1.3 server sends session tickets after the client's
        // Finished, possibly after `connect` returned. rustls consumes
        // ticket records inside `read` without returning data for them, so
        // this loop is a fixed 300 ms wait. What makes arming afterwards
        // safe is the current_thread test runtime: the server task, woken
        // by the client's Finished, runs `accept` to completion (tickets
        // flushed) before the timer driver can fire this timeout. Do not
        // switch these tests to a multi_thread runtime: that turns the
        // guarantee into a timing assumption.
        let mut sink = [0u8; 1024];
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), client.read(&mut sink)).await
        {
            assert!(n > 0, "server closed during the handshake");
        }
        armed.store(true, Ordering::SeqCst);
        let sent = std::time::Instant::now();
        if let Some(record) = &hello_record {
            client.write_all(record).await.unwrap();
            client.flush().await.unwrap();
        }
        let none = tokio::time::timeout(Duration::from_secs(5) + deadline_in, task)
            .await
            .expect(
                "authenticate did not return: the trailing write is unbounded \
                 (or the stall landed in the TLS accept)",
            )
            .unwrap();
        let done = std::time::Instant::now();
        let took = done - sent;
        assert!(none, "authenticate refused the peer");
        assert_eq!(
            hub.ws_auth.available_permits(),
            WS_PREAUTH_SLOTS,
            "the pre-auth slot was released"
        );
        assert_eq!(
            hub.ws_refused_tls.load(Ordering::Relaxed),
            0,
            "the stall landed in the TLS handshake, not the trailing write"
        );
        let auth_fail = entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.event == Event::ConnectorAuthFail)
            .count();
        drop(client);
        Run {
            took,
            past_deadline: done.checked_duration_since(deadline_std),
            auth_fail,
        }
    }

    struct Run {
        /// From the hello being sent (or the stall being armed) to the return.
        took: Duration,
        /// How long after the socket's deadline it returned; `None` if before.
        past_deadline: Option<Duration>,
        /// `connector_auth_fail` audit entries: 1 only on the refusal branch.
        auth_fail: usize,
    }

    fn assert_bounded(took: Duration) {
        assert!(
            took >= Duration::from_millis(900),
            "returned in {took:?}: the write was never stalled"
        );
        assert!(took < Duration::from_secs(3), "took {took:?}");
    }

    /// A malformed hello is answered with `AUTH_PROTOCOL`; a peer that never
    /// reads cannot hold the slot past the 1 s write bound.
    #[tokio::test]
    async fn trailing_protocol_hello_write_is_bounded() {
        // Length 0 is a protocol error.
        let run = stalled_refusal(Some(vec![0, 0, 0, 0]), Duration::from_secs(30)).await;
        assert_bounded(run.took);
        assert_eq!(run.auth_fail, 0, "a protocol error is not a refusal");
    }

    /// A well-formed hello with a wrong token is answered with
    /// `AUTH_UNAUTHORIZED`; the same bound applies.
    #[tokio::test]
    async fn trailing_unauthorized_hello_write_is_bounded() {
        let token = "kh_tunnel_assistant_00";
        let mut body = Vec::new();
        body.extend_from_slice(kharon_connector::MAGIC);
        body.push(kharon_connector::WIRE_VERSION);
        body.extend_from_slice(&(9u16).to_be_bytes());
        body.extend_from_slice(b"assistant");
        body.extend_from_slice(&(token.len() as u16).to_be_bytes());
        body.extend_from_slice(token.as_bytes());
        let mut record = (body.len() as u32).to_be_bytes().to_vec();
        record.extend_from_slice(&body);
        let run = stalled_refusal(Some(record), Duration::from_secs(30)).await;
        assert_bounded(run.took);
        assert_eq!(run.auth_fail, 1, "the refusal branch ran");
    }

    /// A peer that never sends a hello and never reads: the `AUTH_PROTOCOL`
    /// write starts at the deadline with the slot still held, so it must
    /// stop at the deadline, not 1 s after it (REQ-DEP-006: frees its slot
    /// by its deadline).
    #[tokio::test]
    async fn protocol_hello_write_stops_at_the_deadline() {
        let run = stalled_refusal(None, Duration::from_secs(2)).await;
        let past = run.past_deadline.expect("returned before the deadline");
        assert!(
            past < Duration::from_millis(500),
            "returned {past:?} after the deadline"
        );
        assert_eq!(run.auth_fail, 0);
    }
}
