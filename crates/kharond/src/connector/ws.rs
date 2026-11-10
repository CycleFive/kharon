//! The WebSocket entry of the agent connector (#199): the `GET /connector`
//! upgrade on `[public_ingress]`, its pre-auth budget, the ClientHello
//! gate, and the tracking that ends every session at shutdown.
//!
//! The WebSocket carries the same inner stack as the raw listener (pinned
//! TLS, then the hello record, then the mux, wire v1) in binary messages.
//! Nothing in the outer WebSocket is trusted: the edge may terminate TLS,
//! and every check that matters happens on the inner stream.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use base64ct::{Base64, Encoding};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use kharon_connector::{WS_SUBPROTOCOL, WsByteStream, ws_config};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, OwnedSemaphorePermit, watch};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;

use super::{Hub, SessionTransport, authenticate_and_serve, stopped};

/// The inner TLS handshake and the hello each get this long on the
/// WebSocket path (the raw listener allows 10 s for the handshake).
const WS_DEADLINE: Duration = Duration::from_secs(5);

/// Refusals since the last [`WsEntry::take_refusal_line`].
#[derive(Default)]
struct Refusals {
    budget: AtomicU64,
    protocol: AtomicU64,
    hello: AtomicU64,
}

/// Everything `GET /connector` needs on `[public_ingress]`.
pub struct WsEntry {
    acceptor: TlsAcceptor,
    hub: Arc<Hub>,
    refusals: Refusals,
    stop: watch::Sender<bool>,
    live: AtomicUsize,
    idle: Notify,
}

/// A registered session: counted by [`WsEntry::wait_idle`] until dropped.
struct SessionGuard(Arc<WsEntry>);

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.0.live.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

impl WsEntry {
    /// `tls` is the inner server config, TLS 1.3 only. The pre-auth
    /// budget is the hub's.
    pub fn new(hub: Arc<Hub>, tls: Arc<rustls::ServerConfig>) -> Arc<Self> {
        Arc::new(Self {
            acceptor: TlsAcceptor::from(tls),
            hub,
            refusals: Refusals::default(),
            stop: watch::channel(false).0,
            live: AtomicUsize::new(0),
            idle: Notify::new(),
        })
    }

    /// End every WebSocket session, and refuse new ones.
    pub fn begin_shutdown(&self) {
        self.stop.send_replace(true);
    }

    /// Resolves once no WebSocket session is left.
    pub async fn wait_idle(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.live.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// The per-minute summary, if anything was refused since the last
    /// call. Resets the counts.
    pub fn take_refusal_line(&self) -> Option<String> {
        let budget = self.refusals.budget.swap(0, Ordering::Relaxed);
        let protocol = self.refusals.protocol.swap(0, Ordering::Relaxed);
        let hello = self.refusals.hello.swap(0, Ordering::Relaxed);
        let total = budget + protocol + hello;
        (total > 0).then(|| {
            format!(
                "connector: refused {total} websocket upgrades in the last 60s \
                 (budget {budget}, protocol {protocol}, hello {hello})"
            )
        })
    }

    /// Answer a `GET /connector`: 101 and a session task, or a refusal.
    pub(crate) fn upgrade(self: &Arc<Self>, mut req: Request, peer: SocketAddr) -> Response {
        let key = match check_upgrade(req.headers()) {
            Ok(key) => key,
            Err(status) => {
                self.refusals.protocol.fetch_add(1, Ordering::Relaxed);
                return refusal(status);
            }
        };
        // The slot is taken before the 101: a full budget answers 503
        // instead of upgrading a socket that would then be closed.
        let Ok(permit) = self.hub.ws_auth.clone().try_acquire_owned() else {
            self.refusals.budget.fetch_add(1, Ordering::Relaxed);
            return refusal(StatusCode::SERVICE_UNAVAILABLE);
        };
        self.live.fetch_add(1, Ordering::SeqCst);
        let guard = SessionGuard(Arc::clone(self));
        if *self.stop.borrow() {
            return refusal(StatusCode::SERVICE_UNAVAILABLE);
        }
        let on_upgrade = hyper::upgrade::on(&mut req);
        let entry = Arc::clone(self);
        tokio::spawn(async move { entry.session(on_upgrade, peer, permit, guard).await });
        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::UPGRADE, "websocket")
            .header(header::CONNECTION, "Upgrade")
            .header(
                header::SEC_WEBSOCKET_ACCEPT,
                derive_accept_key(key.as_bytes()),
            )
            .header(header::SEC_WEBSOCKET_PROTOCOL, WS_SUBPROTOCOL)
            .body(Body::empty())
            .unwrap_or_else(|_| refusal(StatusCode::INTERNAL_SERVER_ERROR))
    }

    async fn session(
        self: Arc<Self>,
        on_upgrade: OnUpgrade,
        peer: SocketAddr,
        permit: OwnedSemaphorePermit,
        _guard: SessionGuard,
    ) {
        let Ok(upgraded) = on_upgrade.await else {
            return;
        };
        let ws = WebSocketStream::from_raw_socket(
            TokioIo::new(upgraded),
            Role::Server,
            Some(ws_config()),
        )
        .await;
        let mut stop = Some(self.stop.subscribe());
        let gated = tokio::select! {
            g = tokio::time::timeout(WS_DEADLINE, ClientHelloGate::check(WsByteStream::new(ws))) => g,
            () = stopped(&mut stop) => return,
        };
        let stream = match gated {
            Ok(Ok(stream)) => stream,
            Ok(Err(GateError::NotClientHello)) | Err(_) => {
                self.refusals.hello.fetch_add(1, Ordering::Relaxed);
                return;
            }
            Ok(Err(GateError::Io)) => return,
        };
        authenticate_and_serve(
            stream,
            peer,
            SessionTransport::Ws,
            self.acceptor.clone(),
            Arc::clone(&self.hub),
            WS_DEADLINE,
            permit,
            stop,
        )
        .await;
    }
}

fn refusal(status: StatusCode) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = status;
    resp
}

/// Whether any value of `name` lists `token` (comma separated; ASCII
/// case-insensitive unless `exact`).
fn lists(headers: &HeaderMap, name: header::HeaderName, token: &str, exact: bool) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|t| {
            if exact {
                t == token
            } else {
                t.eq_ignore_ascii_case(token)
            }
        })
}

/// The upgrade checks. `Ok` holds the `Sec-WebSocket-Key`. A browser
/// context (`Origin`) is 403, anything else missing or wrong is 400.
/// `Sec-WebSocket-Extensions` is never read: no compression is negotiated.
fn check_upgrade(headers: &HeaderMap) -> Result<String, StatusCode> {
    if headers.contains_key(header::ORIGIN) {
        return Err(StatusCode::FORBIDDEN);
    }
    let version_ok = headers
        .get(header::SEC_WEBSOCKET_VERSION)
        .is_some_and(|v| v.as_bytes() == b"13");
    let key = headers
        .get(header::SEC_WEBSOCKET_KEY)
        .and_then(|v| v.to_str().ok())
        .filter(|k| Base64::decode_vec(k).is_ok_and(|raw| raw.len() == 16));
    match key {
        Some(key)
            if lists(headers, header::UPGRADE, "websocket", false)
                && lists(headers, header::CONNECTION, "upgrade", false)
                && version_ok
                && lists(
                    headers,
                    header::SEC_WEBSOCKET_PROTOCOL,
                    WS_SUBPROTOCOL,
                    true,
                ) =>
        {
            Ok(key.to_owned())
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

/// Why the gate refused.
enum GateError {
    /// The first record is not a TLS ClientHello.
    NotClientHello,
    /// The stream ended or failed before six bytes arrived.
    Io,
}

/// Reads the first six bytes of the inner stream and checks they open a
/// TLS ClientHello (record type 0x16, version 0x0301..=0x0304, handshake
/// type 0x01) before rustls sees any of them, then replays them. A peer
/// that is not a connector never reaches the TLS stack, so it gets no TLS
/// alert and costs no handshake.
struct ClientHelloGate<S> {
    inner: S,
    head: [u8; 6],
    pos: usize,
}

impl<S: AsyncRead + Unpin> ClientHelloGate<S> {
    async fn check(mut inner: S) -> Result<Self, GateError> {
        let mut head = [0u8; 6];
        inner
            .read_exact(&mut head)
            .await
            .map_err(|_| GateError::Io)?;
        let hello =
            head[0] == 0x16 && head[1] == 0x03 && (1..=4).contains(&head[2]) && head[5] == 1;
        if hello {
            Ok(Self {
                inner,
                head,
                pos: 0,
            })
        } else {
            Err(GateError::NotClientHello)
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ClientHelloGate<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pos < this.head.len() {
            let n = buf.remaining().min(this.head.len() - this.pos);
            buf.put_slice(&this.head[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ClientHelloGate<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
