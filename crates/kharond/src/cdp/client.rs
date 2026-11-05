//! A minimal Chrome DevTools Protocol client (JSON-RPC over WebSocket).
//!
//! Hand-rolled following the project's own-implementation pattern: CDP
//! is a small protocol (numbered requests, `result`/`error` replies,
//! fire-and-forget events) and pulling in a browser-automation crate
//! would drag orders of magnitude more dependency surface than the
//! broker needs.
//!
//! Session hygiene (REQ-ARCH-003): the broker's connection never enables
//! `Runtime`, `Log`, `Network`, or `Page` events. Incoming events are
//! therefore not expected and are dropped; every request is one
//! request → one reply, correlated by `id`.
//!
//! Flattened sessions: `Target.attachToTarget` returns a `sessionId`
//! carried as a top-level field on subsequent messages, which is how
//! page-level commands (`Page.*`, `Runtime.*`) reach a specific tab.
//!
//! Cancellation (issue #76): a request future may be dropped at any
//! await (the fill deadline, REQ-API-009, drops the whole fill). Two
//! rules keep that safe:
//!
//! - A request dropped while its frame is being written (`send` holds
//!   the sink and may have buffered part or all of the frame without
//!   flushing it) **poisons** the connection: the sink is dropped
//!   unflushed, the read task is stopped, and every later request fails
//!   fast with [`CdpError::Poisoned`]. The buffered bytes are never
//!   written by anyone, so a frame is either on the wire when its
//!   `send` returns or never goes out — no later write (another
//!   request's, or [`CdpClient::close`]'s close frame) can flush it
//!   after the deadline or after a lock. [`CdpClient::is_closed`] turns
//!   true, so callers that keep a client (the daemon's fill backend)
//!   reconnect on next use.
//! - A request dropped at any point removes its `pending` entry (a
//!   drop guard), so cancelled or timed-out requests do not accumulate
//!   until the connection ends.
//!
//! A request dropped *before* it takes the sink, or *after* its frame
//! was written (waiting for the reply, including the per-request
//! timeout), leaves the connection usable: nothing of it is buffered.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, oneshot, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use zeroize::Zeroizing;

type WsSplitSink = SplitSink<WebSocketStream<MaybeTls>, Message>;

use super::endpoint::CdpEndpoint;

/// Per-request default ceiling. The fill deadline (REQ-API-009, issue
/// #18) will wrap fills with its own shorter budget; this is only a
/// hang-guard for individual protocol calls.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum CdpError {
    /// TCP / WebSocket / TLS transport failure.
    #[error("transport: {0}")]
    Transport(String),
    /// The endpoint URL's host/port was unusable.
    #[error("connect: {0}")]
    Connect(String),
    /// Reply carried an `error` object (code, message).
    #[error("cdp error {code}: {message}")]
    Protocol { code: i64, message: String },
    /// No reply within the request timeout.
    #[error("request timed out")]
    Timeout,
    /// The connection closed with the request still in flight.
    #[error("connection closed")]
    ConnectionClosed,
    /// An earlier request on this connection was cancelled mid-send, so
    /// the connection was dropped (issue #76). Reconnect.
    #[error("connection poisoned by a request cancelled mid-send")]
    Poisoned,
}

impl From<WsError> for CdpError {
    fn from(e: WsError) -> Self {
        Self::Transport(e.to_string())
    }
}

/// One in-flight request.
type Reply = oneshot::Sender<Result<Value, CdpError>>;

/// In-flight requests by id. A std mutex: it is never held across an
/// await, and the cancellation guards below must lock it from `Drop`.
type Pending = std::sync::Mutex<HashMap<u64, Reply>>;

fn lock_pending(pending: &Pending) -> std::sync::MutexGuard<'_, HashMap<u64, Reply>> {
    pending.lock().unwrap_or_else(|p| p.into_inner())
}

/// Fail every in-flight request with `error()`: [`CdpError::Poisoned`]
/// when the connection was poisoned, so a waiter already awaiting its
/// reply and the next request fail with the same error, otherwise
/// [`CdpError::ConnectionClosed`].
fn fail_pending(pending: &Pending, error: impl Fn() -> CdpError) {
    let drained: Vec<Reply> = lock_pending(pending).drain().map(|(_, r)| r).collect();
    for reply in drained {
        let _ = reply.send(Err(error()));
    }
}

/// A plain or TLS TCP stream under a WebSocket. Shared with the
/// notifications hub client (`sync::push`).
pub(crate) enum MaybeTls {
    Plain(TcpStream),
    // Boxed: the TLS variant is ~1.1 KB and this enum crosses every
    // websocket poll.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl tokio::io::AsyncRead for MaybeTls {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeTls {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => std::pin::Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Tls(s) => std::pin::Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
        }
    }
}

/// A connection to the browser-level CDP endpoint.
#[derive(Clone)]
pub struct CdpClient {
    /// The write half. `None` once the connection was poisoned or
    /// closed: dropping the sink discards anything it buffered without
    /// flushing it (issue #76).
    write: Arc<Mutex<Option<WsSplitSink>>>,
    pending: Arc<Pending>,
    next_id: Arc<AtomicU64>,
    /// Set by the read task when the WebSocket ends (stream end or
    /// protocol error), by [`Self::close`], and when a request is
    /// cancelled mid-send. A closed client never recovers; callers that
    /// keep one (the daemon's fill backend) reconnect.
    closed: Arc<AtomicBool>,
    /// Set (with `closed`) when a request was cancelled mid-send.
    poisoned: Arc<AtomicBool>,
    /// Flipped to `true` by [`Self::close`]: a request blocked in
    /// `send` gives up (and poisons) instead of finishing its write
    /// after the close.
    shutdown: Arc<watch::Sender<bool>>,
    /// The read task. It owns the read half, so the socket stays open
    /// for as long as it runs — dropping every clone of the client does
    /// not end the connection; [`Self::close`] does.
    reader: Arc<tokio::task::AbortHandle>,
    /// Test hook: bumped each time a frame write returns `Pending`,
    /// i.e. a send is armed (a drop or `close` now poisons) and parked
    /// mid-send. Lets tests synchronize on "blocked mid-send" instead
    /// of sleeping; subscribe before starting the request so an
    /// earlier request's park cannot satisfy the wait.
    #[cfg(test)]
    send_blocked: Arc<watch::Sender<u64>>,
}

/// How long [`CdpClient::close`] waits to hand the browser a WebSocket
/// close frame before dropping the socket anyway.
const CLOSE_GRACE: Duration = Duration::from_millis(500);

impl CdpClient {
    /// Whether the connection has ended. Every request on a closed
    /// client fails; a fresh [`Self::connect`] is needed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Whether a request was cancelled mid-send on this connection
    /// (issue #76). Implies [`Self::is_closed`].
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// The error for a request on a closed client.
    fn closed_error(&self) -> CdpError {
        if self.is_poisoned() {
            CdpError::Poisoned
        } else {
            CdpError::ConnectionClosed
        }
    }

    /// Poison the connection (a send was cancelled mid-write): mark it
    /// closed, drop the sink unflushed, stop the read task (which would
    /// otherwise flush the sink's buffer when it answers a ping), and
    /// fail everything in flight. Synchronous so it can run from a drop
    /// guard; `sink` is the caller's held write lock.
    fn poison(&self, sink: &mut Option<WsSplitSink>) {
        self.poisoned.store(true, Ordering::Release);
        self.closed.store(true, Ordering::Release);
        self.reader.abort();
        drop(sink.take());
        fail_pending(&self.pending, || CdpError::Poisoned);
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        lock_pending(&self.pending).len()
    }

    /// Connect per a validated endpoint. `ws://` connects plainly;
    /// `wss://` runs the pinned-TLS handshake first (REQ-ARCH-002).
    pub async fn connect(endpoint: &CdpEndpoint) -> Result<Self, CdpError> {
        let host = endpoint
            .url
            .host_str()
            .ok_or_else(|| CdpError::Connect("endpoint has no host".into()))?
            .to_string();
        let port = endpoint.url.port_or_known_default().unwrap_or(80);
        let stream = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| CdpError::Connect(e.to_string()))?;

        let stream = if endpoint.url.scheme() == "wss" {
            let pin = endpoint
                .peer_pin
                .ok_or_else(|| CdpError::Connect("wss endpoint missing peer pin".into()))?;
            MaybeTls::Tls(Box::new(
                super::tls::connect_tls_pinned(&host, pin, stream)
                    .await
                    .map_err(|e| CdpError::Transport(e.to_string()))?,
            ))
        } else {
            MaybeTls::Plain(stream)
        };

        let request = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri(endpoint.url.as_str())
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .map_err(|e| CdpError::Connect(format!("bad websocket request: {e}")))?;
        let (ws, _response) = tokio_tungstenite::client_async(request, stream)
            .await
            .map_err(CdpError::from)?;

        Ok(Self::spawn(ws))
    }

    fn spawn(ws: WebSocketStream<MaybeTls>) -> Self {
        let (write, mut read) = ws.split();
        let pending: Arc<Pending> = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let pending_read = Arc::clone(&pending);
        let closed = Arc::new(AtomicBool::new(false));
        let closed_read = Arc::clone(&closed);
        let reader = tokio::spawn(async move {
            loop {
                let frame = match read.next().await {
                    Some(Ok(frame)) => frame,
                    // Protocol error or stream end: fail everything
                    // in flight below.
                    Some(Err(_)) | None => break,
                };
                let Message::Text(text) = frame else {
                    // Pings/pongs are answered by tungstenite in the
                    // same poll; other frames are unexpected.
                    continue;
                };
                let Ok(value) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                // Events have no `id`. The broker session enables no
                // domains (REQ-ARCH-003), so events are unexpected and
                // dropped rather than surfaced.
                let Some(id) = value.get("id").and_then(Value::as_u64) else {
                    continue;
                };
                let reply = lock_pending(&pending_read).remove(&id);
                if let Some(reply) = reply {
                    let result = if let Some(err) = value.get("error") {
                        Err(CdpError::Protocol {
                            code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                            message: err
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown")
                                .to_string(),
                        })
                    } else {
                        Ok(value.get("result").cloned().unwrap_or(Value::Null))
                    };
                    let _ = reply.send(result);
                }
            }
            // Connection ended: fail every in-flight request.
            closed_read.store(true, Ordering::Release);
            fail_pending(&pending_read, || CdpError::ConnectionClosed);
        });

        Self {
            write: Arc::new(Mutex::new(Some(write))),
            pending,
            next_id: Arc::new(AtomicU64::new(1)),
            closed,
            poisoned: Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(watch::channel(false).0),
            reader: Arc::new(reader.abort_handle()),
            #[cfg(test)]
            send_blocked: Arc::new(watch::channel(0).0),
        }
    }

    /// End the connection: best-effort WebSocket close frame (bounded by
    /// [`CLOSE_GRACE`]), then stop the read task and drop the sink so the
    /// socket is released, and fail anything in flight.
    ///
    /// A request blocked mid-send when this is called is cancelled and
    /// poisons the connection (issue #76): its frame is discarded, not
    /// finished after the close, and no close frame is sent (that would
    /// flush the half-written frame first). Requests started after this
    /// call fail fast.
    ///
    /// This sends no CDP command. The browser disposes every browser
    /// context this connection created when it sees the connection end,
    /// which is how a context whose `createBrowserContext` reply never
    /// arrived is cleaned up (issue #68).
    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.shutdown.send_replace(true);
        let _ = tokio::time::timeout(CLOSE_GRACE, async {
            let mut write = self.write.lock().await;
            if let Some(sink) = write.as_mut() {
                let _ = sink.close().await;
            }
        })
        .await;
        self.reader.abort();
        // Senders give up on `shutdown`, so the lock is free promptly.
        drop(self.write.lock().await.take());
        // A send cancelled by this close poisoned the connection first;
        // keep its error for anything still in flight.
        fail_pending(&self.pending, || self.closed_error());
    }

    /// Send a browser-level request and await its reply.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value, CdpError> {
        self.request_inner(None, method, params, DEFAULT_REQUEST_TIMEOUT)
            .await
    }

    /// Send a session-scoped request (page-level commands after
    /// `Target.attachToTarget`).
    pub async fn request_in_session(
        &self,
        session_id: &str,
        method: &str,
        params: Value,
    ) -> Result<Value, CdpError> {
        self.request_inner(Some(session_id), method, params, DEFAULT_REQUEST_TIMEOUT)
            .await
    }

    /// Like [`Self::request`] with an explicit timeout budget. REQ-API-009
    /// (fill deadline) uses this; it is also the seam for the loaderId
    /// re-check which must not hang.
    pub async fn request_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, CdpError> {
        self.request_inner(None, method, params, timeout).await
    }

    async fn request_inner(
        &self,
        session_id: Option<&str>,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, CdpError> {
        if self.is_closed() {
            return Err(self.closed_error());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        // Removes the entry however this future ends: reply, timeout,
        // send error, or drop (issue #76).
        let _entry = PendingEntry::insert(&self.pending, id, tx);

        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session_id) = session_id {
            message["sessionId"] = Value::String(session_id.to_string());
        }
        let text = Zeroizing::new(serde_json::to_string(&message).expect("Value serializes"));
        {
            let mut shutdown = self.shutdown.subscribe();
            let write = self.write.lock().await;
            // Re-checked under the lock: a request that poisoned or
            // closed the connection while we waited took the sink.
            if write.is_none() || *shutdown.borrow_and_update() {
                return Err(self.closed_error());
            }
            // From here until `send` returns, part of the frame may sit
            // unflushed in the sink: dropping this future (or a send
            // error) poisons the connection via the guard.
            let mut guard = SendGuard {
                client: self,
                write,
                armed: true,
            };
            let sink = guard.write.as_mut().expect("checked above");
            // REQ-CRY-006: our serialized copy is zeroized on drop.
            // tungstenite's internal send buffer is the one remaining
            // plaintext copy — a documented limitation (it is freed by
            // the library, not zeroized).
            let mut send = std::pin::pin!(sink.send(Message::Text((*text).clone())));
            let send = std::future::poll_fn(|cx| {
                let poll = send.as_mut().poll(cx);
                #[cfg(test)]
                if poll.is_pending() {
                    self.send_blocked.send_modify(|parks| *parks += 1);
                }
                poll
            });
            let sent = tokio::select! {
                sent = send => sent,
                // `close` was called while we were blocked mid-send:
                // abandon the frame rather than finish it after the
                // close (the guard poisons).
                _ = shutdown.wait_for(|closing| *closing) => {
                    return Err(CdpError::ConnectionClosed);
                }
            };
            sent.map_err(CdpError::from)?;
            guard.armed = false;
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                // Sender dropped without a value: only happens if the
                // map was drained (connection ended) — race-safe anyway.
                Err(self.closed_error())
            }
            Err(_) => Err(CdpError::Timeout),
        }
    }

    /// Attach to a target and get a session handle for its page-level
    /// commands.
    pub async fn attach(&self, target_id: &str) -> Result<CdpSession, CdpError> {
        let result = self
            .request(
                "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": true }),
            )
            .await?;
        let session_id = result
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| CdpError::Protocol {
                code: -1,
                message: "attachToTarget reply lacked sessionId".into(),
            })?
            .to_string();
        Ok(CdpSession {
            client: self.clone(),
            session_id,
        })
    }
}

/// A request's `pending` entry, removed when the request future ends
/// for any reason (issue #76). A no-op if the read task already took
/// it to deliver the reply.
struct PendingEntry<'a> {
    pending: &'a Pending,
    id: u64,
}

impl<'a> PendingEntry<'a> {
    fn insert(pending: &'a Pending, id: u64, reply: Reply) -> Self {
        lock_pending(pending).insert(id, reply);
        Self { pending, id }
    }
}

impl Drop for PendingEntry<'_> {
    fn drop(&mut self) {
        lock_pending(self.pending).remove(&self.id);
    }
}

/// Held (with the write lock) while a frame is being written. Dropped
/// armed — the request future was cancelled mid-send, or the send
/// failed — it poisons the connection (issue #76).
struct SendGuard<'a> {
    client: &'a CdpClient,
    write: tokio::sync::MutexGuard<'a, Option<WsSplitSink>>,
    armed: bool,
}

impl Drop for SendGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.client.poison(&mut self.write);
        }
    }
}

/// A flattened CDP session bound to one target (tab or iframe).
#[derive(Clone)]
pub struct CdpSession {
    client: CdpClient,
    session_id: String,
}

impl CdpSession {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub async fn request(&self, method: &str, params: Value) -> Result<Value, CdpError> {
        self.client
            .request_in_session(&self.session_id, method, params)
            .await
    }

    pub async fn request_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, CdpError> {
        self.client
            .request_inner(Some(&self.session_id), method, params, timeout)
            .await
    }

    /// Detach best-effort: CDP destroys the session with the connection
    /// anyway; this just lets the browser reclaim the session eagerly.
    pub async fn detach(self) {
        let _ = self
            .client
            .request(
                "Target.detachFromTarget",
                json!({ "sessionId": self.session_id }),
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::collections::HashMap as StdMap;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    /// A scripted CDP peer: answers each request by looking up `method`
    /// in `script` (or a default ack), recording every received message.
    struct MockPeer {
        addr: std::net::SocketAddr,
        received: Arc<std::sync::Mutex<Vec<Value>>>,
        _task: tokio::task::JoinHandle<()>,
    }

    impl MockPeer {
        async fn start(script: StdMap<String, Value>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let received = Arc::new(std::sync::Mutex::new(Vec::new()));
            let received_task = Arc::clone(&received);
            let _task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ws = accept_async(stream).await.unwrap();
                while let Some(Ok(Message::Text(text))) = ws.next().await {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    received_task.lock().unwrap().push(msg.clone());
                    let method = msg["method"].as_str().unwrap();
                    let result = script
                        .get(method)
                        .cloned()
                        .unwrap_or_else(|| json!({ "ok": true }));
                    // Echo the request's own id: a correlation bug
                    // must fail this test, not a counter (review
                    // finding 8 — the old counter would pass under
                    // reordering).
                    let mut reply = json!({ "id": msg["id"], "result": result });
                    if let Some(session_id) = msg.get("sessionId") {
                        reply["sessionId"] = session_id.clone();
                    }
                    ws.send(Message::Text(reply.to_string())).await.unwrap();
                }
            });
            Self {
                addr,
                received,
                _task,
            }
        }
    }

    #[tokio::test]
    async fn request_roundtrip_and_session_passthrough() {
        let mut script = HashMap::new();
        script.insert(
            "Target.attachToTarget".to_string(),
            json!({ "sessionId": "sess-1" }),
        );
        script.insert(
            "Browser.getVersion".to_string(),
            json!({ "product": "HeadlessChrome/1" }),
        );
        let peer = MockPeer::start(script).await;

        let endpoint = super::super::endpoint::CdpEndpoint::validate(
            &format!("ws://{}/devtools/browser", peer.addr),
            super::super::endpoint::Tunnel::Direct,
            None,
        )
        .unwrap();
        let client = CdpClient::connect(&endpoint).await.unwrap();

        let version = client
            .request("Browser.getVersion", json!({}))
            .await
            .unwrap();
        assert_eq!(version["product"], "HeadlessChrome/1");

        let session = client.attach("target-1").await.unwrap();
        assert_eq!(session.session_id(), "sess-1");
        let ack = session
            .request("Page.getFrameTree", json!({}))
            .await
            .unwrap();
        assert_eq!(ack["ok"], true);

        // The sessionId must ride on the wire for session-scoped calls.
        let seen = peer.received.lock().unwrap();
        let session_msg = seen
            .iter()
            .find(|m| m["method"] == "Page.getFrameTree")
            .expect("session call recorded");
        assert_eq!(session_msg["sessionId"], "sess-1");
    }

    #[tokio::test]
    async fn protocol_error_is_typed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let msg: Value = serde_json::from_str(&text).unwrap();
                ws.send(Message::Text(
                    json!({
                        "id": msg["id"],
                        "error": { "code": -32000, "message": "No such target" }
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            }
        });
        let endpoint = super::super::endpoint::CdpEndpoint::validate(
            &format!("ws://{addr}/devtools/browser"),
            super::super::endpoint::Tunnel::Direct,
            None,
        )
        .unwrap();
        let client = CdpClient::connect(&endpoint).await.unwrap();
        let err = client
            .request("Target.attachToTarget", json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, CdpError::Protocol { code: -32000, .. }));
    }

    fn endpoint(addr: std::net::SocketAddr) -> super::super::endpoint::CdpEndpoint {
        super::super::endpoint::CdpEndpoint::validate(
            &format!("ws://{addr}/devtools/browser"),
            super::super::endpoint::Tunnel::Direct,
            None,
        )
        .unwrap()
    }

    /// Larger than loopback socket buffers on both ends, so `send` of a
    /// frame this size blocks mid-write while the peer is not reading.
    const STALL_BYTES: usize = 32 * 1024 * 1024;

    /// A peer that completes the handshake, answers nothing, and reads
    /// nothing until `go` fires; then it drains the socket to EOF and
    /// reports every *complete* text frame it received (by method). No
    /// size limits, so a fully delivered stall frame would be counted.
    async fn stalled_reader_peer() -> (
        std::net::SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<Vec<String>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (go_tx, go_rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
                max_message_size: None,
                max_frame_size: None,
                ..Default::default()
            };
            let mut ws = tokio_tungstenite::accept_async_with_config(stream, Some(config))
                .await
                .unwrap();
            let _ = go_rx.await;
            let mut seen = Vec::new();
            while let Some(Ok(frame)) = ws.next().await {
                if let Message::Text(text) = frame {
                    let msg: Value = serde_json::from_str(&text).unwrap();
                    seen.push(msg["method"].as_str().unwrap_or("").to_owned());
                }
            }
            seen
        });
        (addr, go_tx, task)
    }

    fn huge_params() -> Value {
        json!({ "blob": "x".repeat(STALL_BYTES) })
    }

    /// Run a stall-sized request until its frame write is armed and
    /// parked mid-send (the `send_blocked` hook), then drop it there — the fill deadline firing mid-send. No timing: building
    /// and serializing 32 MiB can take arbitrarily long on a loaded box.
    async fn drop_request_blocked_mid_send(client: &CdpClient) {
        let mut blocked = client.send_blocked.subscribe();
        tokio::select! {
            res = client.request("Runtime.callFunctionOn", huge_params()) => {
                panic!("stall send must block mid-write, got {res:?}");
            }
            changed = blocked.changed() => changed.unwrap(),
        }
    }

    /// Issue #76: a request dropped mid-send (the fill deadline firing
    /// while the frame is being written) poisons the connection. Later
    /// requests fail fast, `close` sends nothing, and the buffered frame
    /// never reaches the peer — not with a later write, not with the
    /// close frame.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_send_poisons_and_nothing_is_written_after() {
        let (addr, go, peer) = stalled_reader_peer().await;
        let client = CdpClient::connect(&endpoint(addr)).await.unwrap();

        drop_request_blocked_mid_send(&client).await;

        assert!(client.is_poisoned());
        assert!(client.is_closed());
        assert_eq!(client.pending_len(), 0);

        // The peer starts reading only now: under the old client the
        // next write would flush the buffered frame here.
        go.send(()).unwrap();
        let err = client
            .request("Browser.getVersion", json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, CdpError::Poisoned), "{err:?}");
        let Err(err) = client.attach("t1").await else {
            panic!("attach must fail fast too");
        };
        assert!(matches!(err, CdpError::Poisoned), "{err:?}");
        client.close().await;
        drop(client);

        let seen = tokio::time::timeout(Duration::from_secs(10), peer)
            .await
            .expect("socket released after poison")
            .unwrap();
        assert!(seen.is_empty(), "frames reached the peer: {seen:?}");
    }

    /// Issue #76 / #71: `close` (the lock's teardown) while a request is
    /// blocked mid-send cancels that send rather than letting it finish
    /// after the close.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn close_cancels_a_blocked_send() {
        let (addr, go, peer) = stalled_reader_peer().await;
        let client = CdpClient::connect(&endpoint(addr)).await.unwrap();

        let mut blocked = client.send_blocked.subscribe();
        let sender = client.clone();
        let in_flight = tokio::spawn(async move {
            sender
                .request("Runtime.callFunctionOn", huge_params())
                .await
        });
        // Wait until the send is armed and parked mid-send. A
        // fixed sleep here was racy: under load, building and
        // serializing 32 MiB outlasted it, `close` landed before the
        // request took the write lock, and the request failed fast
        // without ever arming the send — closed, never poisoned.
        blocked.changed().await.unwrap();
        assert!(!in_flight.is_finished());

        tokio::time::timeout(Duration::from_secs(5), client.close())
            .await
            .expect("close is bounded");
        let err = tokio::time::timeout(Duration::from_secs(5), in_flight)
            .await
            .expect("blocked send gives up on close")
            .unwrap()
            .unwrap_err();
        assert!(matches!(err, CdpError::ConnectionClosed), "{err:?}");
        assert!(client.is_closed());
        assert!(client.is_poisoned());
        assert_eq!(client.pending_len(), 0);

        go.send(()).unwrap();
        drop(client);
        let seen = tokio::time::timeout(Duration::from_secs(10), peer)
            .await
            .expect("socket released after close")
            .unwrap();
        assert!(seen.is_empty(), "frames reached the peer: {seen:?}");
    }

    /// A request already awaiting its reply when the connection is
    /// poisoned fails with `Poisoned`, the same error as the requests
    /// after it — not `ConnectionClosed` (#83 review nit).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poison_fails_reply_phase_waiters_with_poisoned() {
        let (addr, _go, _peer) = stalled_reader_peer().await;
        let client = CdpClient::connect(&endpoint(addr)).await.unwrap();

        // A small frame fits the socket buffer, so the send completes
        // and the request then awaits its (never sent) reply. Drive it
        // until it has released the write lock: its send may park a
        // few polls on the sink/stream split lock the read task shares.
        let mut waiter = std::pin::pin!(client.request("Browser.getVersion", json!({})));
        loop {
            tokio::select! {
                biased;
                res = &mut waiter => panic!("no reply is ever sent, got {res:?}"),
                () = tokio::task::yield_now() => {}
            }
            // Polled at least once, so it holds the write lock until
            // its send has returned.
            if client.write.try_lock().is_ok() {
                break;
            }
        }
        assert!(!client.is_closed(), "waiter's send succeeded");
        assert_eq!(client.pending_len(), 1);

        drop_request_blocked_mid_send(&client).await;
        assert!(client.is_poisoned());

        let err = waiter.await.unwrap_err();
        assert!(matches!(err, CdpError::Poisoned), "{err:?}");
        let err = client
            .request("Browser.getVersion", json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, CdpError::Poisoned), "{err:?}");
        assert_eq!(client.pending_len(), 0);
    }

    /// Issue #76: requests that time out or are dropped while awaiting
    /// their reply leave no `pending` entry, and — their frame being
    /// fully written — do not poison the connection.
    #[tokio::test]
    async fn cancelled_requests_leave_no_pending_entry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            // Answer only `Browser.getVersion`; stall everything else.
            while let Some(Ok(Message::Text(text))) = ws.next().await {
                let msg: Value = serde_json::from_str(&text).unwrap();
                if msg["method"] == "Browser.getVersion" {
                    ws.send(Message::Text(
                        json!({ "id": msg["id"], "result": { "product": "P" } }).to_string(),
                    ))
                    .await
                    .unwrap();
                }
            }
        });
        let client = CdpClient::connect(&endpoint(addr)).await.unwrap();

        // Per-request timeout.
        let err = client
            .request_with_timeout("Page.stall", json!({}), Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(err, CdpError::Timeout));
        assert_eq!(client.pending_len(), 0);

        // Outer cancellation while awaiting the reply (the fill
        // deadline dropping the future).
        for _ in 0..5 {
            let dropped = tokio::time::timeout(
                Duration::from_millis(50),
                client.request("Page.stall", json!({})),
            )
            .await;
            assert!(dropped.is_err());
        }
        assert_eq!(client.pending_len(), 0);

        // A future dropped before its first poll never registers.
        drop(client.request("Page.stall", json!({})));
        assert_eq!(client.pending_len(), 0);

        // Reply-phase cancellation does not poison: the connection
        // still works.
        assert!(!client.is_closed());
        let version = client
            .request("Browser.getVersion", json!({}))
            .await
            .unwrap();
        assert_eq!(version["product"], "P");
        assert_eq!(client.pending_len(), 0);
    }
}
