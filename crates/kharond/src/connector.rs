//! Broker accept loop for the agent connector (path B, REQ-ARCH-002).
//!
//! Agents dial `[connector].listen` over TLS, present a tunnel credential
//! (`kh_tunnel_...`, not an agent API token), and then the broker opens
//! CDP streams on that session. A failed credential never reaches the
//! mux. A new session for the same agent replaces the previous one.
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
use tokio::time::{Instant, timeout_at};
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

/// Argon2id evaluations allowed at once, across both transports (#219).
pub const ARGON2_CONCURRENCY: usize = 2;
/// Pre-auth time of a WebSocket socket, from its slot to the start of the
/// Argon2id check. A hash already running is bounded by its parameters.
pub const WS_PREAUTH_DEADLINE: Duration = Duration::from_secs(10);
/// Pre-auth time of a raw socket, from accept to the start of the Argon2id
/// check: the old 10 s TLS plus 5 s hello maximum.
pub const RAW_PREAUTH_DEADLINE: Duration = Duration::from_secs(15);

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
            limits: std::sync::Mutex::new(Limits::default()),
        }
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

    /// Audit a refused hello that claimed `claimed` (#199). Written only
    /// when `claimed` is a configured agent, at most one entry per agent
    /// per 60 s; unknown ids and junk are not audited. `detail_code` is
    /// always `unauthorized`: a malformed hello carries no attributable
    /// agent id.
    pub fn audit_auth_fail(&self, claimed: &str, transport: SessionTransport) {
        if !self.tokens.agents().any(|id| id == claimed) {
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
                    .detail_code("unauthorized")
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

    /// Whether `agent_id` has a live authenticated session.
    pub fn is_connected(&self, agent_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(agent_id)
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
        if !self.tokens.agents().any(|id| id == agent_id) {
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
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(agent_id)
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
    ) -> (u64, Arc<AtomicBool>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let replaced = Arc::new(AtomicBool::new(false));
        let now = Instant::now();
        let live = Live {
            id,
            session,
            replaced: Arc::clone(&replaced),
            since: now,
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
) -> Option<(tokio_rustls::server::TlsStream<S>, String)>
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
            let _ = write_server_hello(&mut tls, AUTH_PROTOCOL).await;
            return None;
        }
    };
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
        Some((tls, hello.agent_id))
    } else {
        // The raw listener logs each refusal (#150). On the public path any
        // stranger can reach this, so a refusal is only counted.
        if transport == SessionTransport::Ws {
            hub.ws_refused_auth.fetch_add(1, Ordering::Relaxed);
        } else {
            hub.report(ConnectorEvent::Refused { peer });
        }
        hub.audit_auth_fail(&hello.agent_id, transport);
        let _ = write_server_hello(&mut tls, AUTH_UNAUTHORIZED).await;
        None
    }
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
    let Some((tls, agent_id)) = authed else {
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
    let (id, replaced) = hub.insert(agent_id.clone(), session.clone(), transport);
    tokio::select! {
        () = session.closed() => {}
        () = stopped(&mut stop) => session.shutdown(),
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
}
