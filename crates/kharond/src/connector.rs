//! Broker accept loop for the agent connector (path B, REQ-ARCH-002).
//!
//! Agents dial `[connector].listen` over TLS, present a tunnel credential
//! (`kh_tunnel_...`, not an agent API token), and then the broker opens
//! CDP streams on that session. A failed credential never reaches the
//! mux. A new session for the same agent replaces the previous one.
//!
//! Framing, the pin, and reconnect live in `kharon-connector` so a review
//! of OQ-14 can change them in one place.
//!
//! Each accepted session is logged on attach (after `AUTH_OK`) and on
//! detach, with the agent id and peer address and never the credential
//! (#150). These are log lines, not audit entries: the audit chain records
//! requests, grants, fills and owner actions (SPEC §7, REQ-AUD-003), and a
//! transport attach changes none of them.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use kharon_connector::{
    AUTH_OK, AUTH_PROTOCOL, AUTH_UNAUTHORIZED, BrokerSession, MuxIo, read_client_hello,
    spawn_broker, write_server_hello,
};
pub use kharon_connector::{
    AgentParams, ClientError, connect_pinned, pin_of_der, run_agent_once, server_config_from_pem,
};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio_rustls::TlsAcceptor;

use crate::api::token::TokenStore;

/// A connector session event, reported once per occurrence (#150).
///
/// None of the variants carries credential material. `Display` renders the
/// log line without the `kharond: ` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorEvent {
    /// The tunnel credential was accepted and `AUTH_OK` was sent. `peer` is
    /// the TCP peer, which is the proxy when the agent dials through one.
    Attached { agent_id: String, peer: SocketAddr },
    /// An attached session ended. `replaced` is true when a newer session
    /// for the same agent superseded it.
    Detached {
        agent_id: String,
        peer: SocketAddr,
        secs: u64,
        replaced: bool,
    },
    /// The tunnel credential was refused. The claimed agent id is not
    /// reported: it is unauthenticated input.
    Refused { peer: SocketAddr },
}

impl fmt::Display for ConnectorEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attached { agent_id, peer } => {
                write!(f, "agent connector attached: agent={agent_id} peer={peer}")
            }
            Self::Detached {
                agent_id,
                peer,
                secs,
                replaced,
            } => {
                write!(
                    f,
                    "agent connector detached: agent={agent_id} peer={peer} after={secs}s"
                )?;
                if *replaced {
                    f.write_str(" (replaced by a new session)")?;
                }
                Ok(())
            }
            Self::Refused { .. } => f.write_str("agent connector refused a credential"),
        }
    }
}

/// Where connector events go. The default prints them to stderr.
pub type EventSink = Arc<dyn Fn(&ConnectorEvent) + Send + Sync>;

fn stderr_sink() -> EventSink {
    Arc::new(|event| eprintln!("kharond: {event}"))
}

/// Accepted connector sessions, keyed by agent id.
pub struct Hub {
    tokens: TokenStore,
    sessions: std::sync::Mutex<HashMap<String, Live>>,
    changed: Notify,
    auth: Arc<Semaphore>,
    next: AtomicU64,
    events: EventSink,
}

struct Live {
    id: u64,
    session: BrokerSession,
    /// Set when a newer session for the same agent evicts this one.
    replaced: Arc<AtomicBool>,
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
            next: AtomicU64::new(1),
            events,
        }
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
    fn insert(&self, agent: String, session: BrokerSession) -> (u64, Arc<AtomicBool>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let replaced = Arc::new(AtomicBool::new(false));
        let live = Live {
            id,
            session,
            replaced: Arc::clone(&replaced),
        };
        let mut map = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(old) = map.insert(agent, live) {
            old.replaced.store(true, Ordering::SeqCst);
            old.session.shutdown();
        }
        drop(map);
        self.changed.notify_waiters();
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
        tokio::spawn(async move { handle_one(tcp, peer, acceptor, hub).await });
    }
}

async fn handle_one(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    hub: Arc<Hub>,
) {
    let Ok(permit) = hub.auth.clone().try_acquire_owned() else {
        return;
    };
    let Ok(Ok(mut tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await
    else {
        return;
    };
    let hello =
        match tokio::time::timeout(Duration::from_secs(5), read_client_hello(&mut tls)).await {
            Ok(Ok(hello)) => hello,
            _ => {
                let _ = write_server_hello(&mut tls, AUTH_PROTOCOL).await;
                return;
            }
        };
    let agent_id = hello.agent_id.clone();
    let token = hello.token.clone();
    let tokens_hub = Arc::clone(&hub);
    let authed = tokio::task::spawn_blocking(move || {
        tokens_hub
            .tokens
            .authenticate_for(&agent_id, token.as_str())
    })
    .await;
    drop(permit);
    match authed {
        Ok(Ok(())) => {
            if write_server_hello(&mut tls, AUTH_OK).await.is_err() {
                return;
            }
            let session = spawn_broker(tls);
            let since = Instant::now();
            // Report before the session is visible, so anyone who sees
            // `is_connected` also sees the attach.
            hub.report(ConnectorEvent::Attached {
                agent_id: hello.agent_id.clone(),
                peer,
            });
            let (id, replaced) = hub.insert(hello.agent_id.clone(), session.clone());
            session.closed().await;
            hub.remove_if(&hello.agent_id, id);
            hub.report(ConnectorEvent::Detached {
                agent_id: hello.agent_id.clone(),
                peer,
                secs: since.elapsed().as_secs(),
                replaced: replaced.load(Ordering::SeqCst),
            });
        }
        _ => {
            hub.report(ConnectorEvent::Refused { peer });
            let _ = write_server_hello(&mut tls, AUTH_UNAUTHORIZED).await;
        }
    }
}
