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

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, oneshot};
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
}

impl From<WsError> for CdpError {
    fn from(e: WsError) -> Self {
        Self::Transport(e.to_string())
    }
}

/// One in-flight request.
type Reply = oneshot::Sender<Result<Value, CdpError>>;

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
    write: Arc<Mutex<WsSplitSink>>,
    pending: Arc<Mutex<HashMap<u64, Reply>>>,
    next_id: Arc<AtomicU64>,
    /// Set by the read task when the WebSocket ends (stream end or
    /// protocol error). A closed client never recovers; callers that
    /// keep one (the daemon's fill backend) reconnect.
    closed: Arc<AtomicBool>,
}

impl CdpClient {
    /// Whether the connection has ended. Every request on a closed
    /// client fails; a fresh [`Self::connect`] is needed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
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
        let pending: Arc<Mutex<HashMap<u64, Reply>>> = Arc::new(Mutex::new(HashMap::new()));
        let pending_read = Arc::clone(&pending);
        let closed = Arc::new(AtomicBool::new(false));
        let closed_read = Arc::clone(&closed);
        tokio::spawn(async move {
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
                let reply = pending_read.lock().await.remove(&id);
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
            let mut pending = pending_read.lock().await;
            for (_, reply) in pending.drain() {
                let _ = reply.send(Err(CdpError::ConnectionClosed));
            }
        });

        Self {
            write: Arc::new(Mutex::new(write)),
            pending,
            next_id: Arc::new(AtomicU64::new(1)),
            closed,
        }
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
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session_id) = session_id {
            message["sessionId"] = Value::String(session_id.to_string());
        }
        let text = Zeroizing::new(serde_json::to_string(&message).expect("Value serializes"));
        {
            let mut write = self.write.lock().await;
            // REQ-CRY-006: our serialized copy is zeroized on drop.
            // tungstenite's internal send buffer is the one remaining
            // plaintext copy — a documented limitation (it is freed by
            // the library, not zeroized).
            if let Err(e) = write.send(Message::Text((*text).clone())).await {
                self.pending.lock().await.remove(&id);
                return Err(CdpError::from(e));
            }
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                // Sender dropped without a value: only happens if the
                // read loop exited, and it drains the map on exit — but
                // race-safe anyway.
                Err(CdpError::ConnectionClosed)
            }
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(CdpError::Timeout)
            }
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
}
