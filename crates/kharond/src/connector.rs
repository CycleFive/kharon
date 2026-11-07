//! Broker accept loop for the agent connector (path B, REQ-ARCH-002).
//!
//! Agents dial `[connector].listen` over TLS, present a tunnel credential
//! (`kh_tunnel_...`, not an agent API token), and then the broker opens
//! CDP streams on that session. A failed credential never reaches the
//! mux. A new session for the same agent replaces the previous one.
//!
//! Framing, the pin, and reconnect live in `kharon-connector` so a review
//! of OQ-14 can change them in one place.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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

/// Accepted connector sessions, keyed by agent id.
pub struct Hub {
    tokens: TokenStore,
    sessions: std::sync::Mutex<HashMap<String, Live>>,
    changed: Notify,
    auth: Arc<Semaphore>,
    next: AtomicU64,
}

struct Live {
    id: u64,
    session: BrokerSession,
}

impl Hub {
    /// `tokens` holds only connector hashes (`kh_tunnel_` prefix).
    pub fn new(tokens: TokenStore) -> Self {
        Self {
            tokens,
            sessions: std::sync::Mutex::new(HashMap::new()),
            changed: Notify::new(),
            auth: Arc::new(Semaphore::new(4)),
            next: AtomicU64::new(1),
        }
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

    fn insert(&self, agent: String, session: BrokerSession) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut map = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(old) = map.insert(agent, Live { id, session }) {
            old.session.shutdown();
        }
        drop(map);
        self.changed.notify_waiters();
        id
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
        let (tcp, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let _ = tcp.set_nodelay(true);
        let acceptor = acceptor.clone();
        let hub = Arc::clone(&hub);
        tokio::spawn(async move { handle_one(tcp, acceptor, hub).await });
    }
}

async fn handle_one(tcp: tokio::net::TcpStream, acceptor: TlsAcceptor, hub: Arc<Hub>) {
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
            let id = hub.insert(hello.agent_id.clone(), session.clone());
            session.closed().await;
            hub.remove_if(&hello.agent_id, id);
        }
        _ => {
            eprintln!("kharond: agent connector refused a credential");
            let _ = write_server_hello(&mut tls, AUTH_UNAUTHORIZED).await;
        }
    }
}
