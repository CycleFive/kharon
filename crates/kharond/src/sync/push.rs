//! Notifications hub push client (issue #9; REQ-CRY-009 push half).
//!
//! When the server runs the notifications hub (`/notifications/hub`,
//! ASP.NET SignalR on Bitwarden, a SignalR-compatible WebSocket on
//! Vaultwarden), [`run_push`] keeps one WebSocket open and turns every
//! vault-relevant update into a nudge on the channel that
//! [`super::run`] already listens on, so web-vault changes land within
//! seconds instead of at the next 5-minute poll. The push client never
//! touches the vault itself: it only nudges, and the full `/api/sync`
//! plus the REQ-CRY-008 scope check run in the sync loop as before.
//! Polling never stops, so a missing or broken hub degrades to the
//! poll floor and nothing else.
//!
//! Protocol, as the official clients speak it with `skipNegotiation`:
//!
//! 1. WebSocket `GET <hub>` with `Authorization: Bearer <access
//!    token>`. The token goes in a header, never the URL (URLs end up
//!    in proxy and server logs). Vaultwarden and ASP.NET's JWT handler
//!    both accept the header.
//! 2. Handshake: text `{"protocol":"messagepack","version":1}` + RS
//!    (0x1e); the server answers `{}` + RS (Vaultwarden sends it as a
//!    binary frame). MessagePack is the only protocol Vaultwarden
//!    answers, and Bitwarden supports it too, so JSON is not offered.
//! 3. Messages: each binary frame holds one or more
//!    `VarInt(len) ‖ msgpack` records. Updates are invocations
//!    `[1, headers, invocationId, "ReceiveMessage", [{ContextId, Type,
//!    Payload}]]`; `[6]` is a ping and `[7, error, allowReconnect]` a
//!    close.
//!
//! Keepalive: the client sends a SignalR ping every 15 s (ASP.NET
//! drops clients silent for 30 s; Vaultwarden echoes it) and treats 30
//! s without any frame as a dead connection (Vaultwarden pings every
//! 15 s at the WebSocket layer). Every (re)connect nudges one catch-up
//! sync, because changes made while disconnected were not pushed.
//! Failures reconnect with jittered exponential backoff; a server
//! without the hub (404 and friends) is retried only every
//! [`HubTiming::unsupported_retry`].
//!
//! The push task ends when the session locks (the [`SyncClient`]'s
//! token channel closes, i.e. the `LiveSync` was dropped) or when the
//! sync loop stops listening (the nudge receiver is dropped).
//!
//! [`SyncClient`]: super::SyncClient

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderValue, header};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::cdp::MaybeTls;

/// SignalR record separator, terminating handshake messages.
const RECORD_SEPARATOR: u8 = 0x1e;
/// The handshake request: MessagePack, protocol version 1.
pub const HANDSHAKE_REQUEST: &str = "{\"protocol\":\"messagepack\",\"version\":1}\u{1e}";
/// A framed SignalR ping, `VarInt(1) ‖ msgpack [6]`.
pub const PING_FRAME: [u8; 3] = [0x02, 0x91, 0x06];
/// Upper bound on one WebSocket message or frame. Hub updates are a
/// few hundred bytes; this only stops a hostile server from making the
/// client buffer without limit.
pub const MAX_HUB_MESSAGE: usize = 64 * 1024;
/// Nesting depth past which a msgpack value is rejected.
const MAX_DEPTH: usize = 16;

/// The bearer token the hub authenticates with, shared from the
/// [`super::SyncClient`] that logged in. No `Debug`, `Display` or
/// `Serialize` of the value: the manual `Debug` prints a placeholder.
#[derive(Clone)]
pub struct HubToken {
    value: Arc<Zeroizing<String>>,
    refresh_after: std::time::Instant,
}

impl HubToken {
    pub(crate) fn new(value: Arc<Zeroizing<String>>, refresh_after: std::time::Instant) -> Self {
        Self {
            value,
            refresh_after,
        }
    }

    /// Whether the token is still inside its validity window (same
    /// rule the sync client uses before reusing a token).
    pub fn is_fresh(&self) -> bool {
        std::time::Instant::now() < self.refresh_after
    }
}

impl std::fmt::Debug for HubToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HubToken(<redacted>)")
    }
}

/// Timeouts, keepalive and backoff for the hub client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubTiming {
    /// TCP connect plus TLS plus WebSocket upgrade.
    pub connect_timeout: Duration,
    /// From sending the handshake to the server's `{}`.
    pub handshake_timeout: Duration,
    /// How often the client sends a SignalR ping.
    pub ping_interval: Duration,
    /// No frame for this long means the connection is dead.
    pub server_timeout: Duration,
    /// First reconnect delay; doubles per failure.
    pub backoff_base: Duration,
    /// Reconnect delay cap.
    pub backoff_max: Duration,
    /// Retry delay when the server has no hub (404, 405, 501).
    pub unsupported_retry: Duration,
    /// A connection that stayed up this long resets the backoff.
    pub stable_after: Duration,
}

impl Default for HubTiming {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            ping_interval: Duration::from_secs(15),
            server_timeout: Duration::from_secs(30),
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            unsupported_retry: super::MAX_SYNC_INTERVAL,
            stable_after: Duration::from_secs(30),
        }
    }
}

/// Exponential backoff with jitter: the n-th delay is uniform in
/// `[c/2, c]` with `c = min(base * 2^n, max)`.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max: max.max(base),
            attempt: 0,
        }
    }

    /// The ceiling of the next delay (no jitter).
    pub fn ceiling(&self) -> Duration {
        let factor = 1u32 << self.attempt.min(20);
        self.base.saturating_mul(factor).min(self.max)
    }

    /// The next delay, and advance.
    pub fn next_delay(&mut self) -> Duration {
        let c = self.ceiling();
        self.attempt = self.attempt.saturating_add(1);
        let half = c / 2;
        let span = (c - half).as_micros() as u64;
        let jitter = if span == 0 {
            0
        } else {
            rand::Rng::gen_range(&mut rand::thread_rng(), 0..=span)
        };
        half + Duration::from_micros(jitter)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// A Bitwarden push update type (`PushType` / Vaultwarden
/// `UpdateType`), as carried in the `Type` field of a `ReceiveMessage`
/// invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpdateType(pub i64);

impl UpdateType {
    pub const SYNC_CIPHER_UPDATE: Self = Self(0);
    pub const SYNC_CIPHER_CREATE: Self = Self(1);
    pub const SYNC_LOGIN_DELETE: Self = Self(2);
    pub const SYNC_FOLDER_DELETE: Self = Self(3);
    pub const SYNC_CIPHERS: Self = Self(4);
    pub const SYNC_VAULT: Self = Self(5);
    pub const SYNC_ORG_KEYS: Self = Self(6);
    pub const SYNC_FOLDER_CREATE: Self = Self(7);
    pub const SYNC_FOLDER_UPDATE: Self = Self(8);
    pub const SYNC_CIPHER_DELETE: Self = Self(9);
    pub const SYNC_SETTINGS: Self = Self(10);
    pub const LOG_OUT: Self = Self(11);
    pub const SYNC_SEND_CREATE: Self = Self(12);
    pub const SYNC_SEND_UPDATE: Self = Self(13);
    pub const SYNC_SEND_DELETE: Self = Self(14);
    pub const AUTH_REQUEST: Self = Self(15);
    pub const AUTH_REQUEST_RESPONSE: Self = Self(16);
    /// Bitwarden server only (not sent by Vaultwarden 1.33).
    pub const SYNC_ORGANIZATIONS: Self = Self(17);
    pub const SYNC_ORGANIZATION_STATUS_CHANGED: Self = Self(18);
    pub const SYNC_ORGANIZATION_COLLECTION_SETTING_CHANGED: Self = Self(19);

    /// Whether this update can change what `/api/sync` returns for the
    /// kharon account: items, folders, collections, org membership or
    /// keys, or the whole vault. `LogOut` (security stamp change) also
    /// syncs: the sync re-logs in with the API key, and fails loudly
    /// if the key was revoked. Sends, auth requests, settings and
    /// unknown types do not.
    pub fn triggers_sync(self) -> bool {
        matches!(self.0, 0..=9 | 11 | 17..=19)
    }
}

/// What a single SignalR MessagePack record said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubMessage {
    /// An invocation. `update` is the `Type` of a `ReceiveMessage`
    /// argument, if the target is `ReceiveMessage` and it had one.
    Invocation {
        target: String,
        update: Option<UpdateType>,
    },
    Ping,
    /// The server is closing the connection.
    Close {
        allow_reconnect: Option<bool>,
    },
    /// Any other message type (completions, stream items, …).
    Other(i64),
}

/// Hub failures. Fixed text, status codes and counts only: never
/// tokens, URLs with credentials, or server-provided text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HubError {
    #[error("hub URL: {0}")]
    Url(&'static str),
    #[error("hub connect: {0}")]
    Connect(&'static str),
    #[error("hub TLS handshake failed")]
    Tls,
    #[error("hub upgrade returned HTTP {0}")]
    Status(u16),
    #[error("hub handshake: {0}")]
    Handshake(&'static str),
    #[error("hub protocol: {0}")]
    Protocol(&'static str),
    #[error("hub transport error")]
    Transport,
    #[error("hub connection timed out")]
    Timeout,
    #[error("hub connection closed")]
    Closed,
    #[error("hub server sent close")]
    ServerClose,
    #[error("access token gone")]
    TokenGone,
}

impl HubError {
    /// The server has no notifications hub (or it is disabled).
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::Status(400 | 404 | 405 | 501))
    }

    fn is_auth(&self) -> bool {
        matches!(self, Self::Status(401 | 403))
    }
}

/// Status reports from [`run_push`], for logging and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubStatus {
    /// Handshake done; a catch-up sync was nudged.
    Connected,
    /// A sync-relevant update arrived and a sync was nudged.
    Push(UpdateType),
    /// The connection failed or dropped.
    Disconnected(HubError),
    /// The server has no hub; polling only until the next retry.
    Unsupported { status: u16 },
    /// No fresh access token yet; a sync was nudged to log in.
    WaitingForToken,
    /// Waiting this long before reconnecting.
    Retrying(Duration),
    /// The session locked or the sync loop stopped; the task ends.
    Stopped,
}

/// A configured push source. Built by
/// [`super::SyncClient::notifications_hub`] (or
/// [`super::LiveSync::notifications_hub`]), consumed by [`run_push`].
pub struct NotificationsHub {
    url: Url,
    tls: Arc<rustls::ClientConfig>,
    tokens: watch::Receiver<Option<HubToken>>,
    timing: HubTiming,
}

impl std::fmt::Debug for NotificationsHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationsHub")
            .field("url", &self.url.as_str())
            .field("timing", &self.timing)
            .finish_non_exhaustive()
    }
}

impl NotificationsHub {
    pub(crate) fn new(
        url: Url,
        tls: Arc<rustls::ClientConfig>,
        tokens: watch::Receiver<Option<HubToken>>,
    ) -> Self {
        Self {
            url,
            tls,
            tokens,
            timing: HubTiming::default(),
        }
    }

    pub fn with_timing(mut self, timing: HubTiming) -> Self {
        self.timing = timing;
        self
    }

    /// The `ws(s)://…/hub` URL (no credentials in it).
    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn timing(&self) -> HubTiming {
        self.timing
    }

    fn fresh_token(&self) -> Option<HubToken> {
        self.tokens
            .borrow()
            .as_ref()
            .filter(|t| t.is_fresh())
            .cloned()
    }
}

/// `http(s)://…` hub endpoint → `ws(s)://…`.
pub(crate) fn ws_url(http: Url) -> Result<Url, HubError> {
    let mut u = http;
    let scheme = match u.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return Err(HubError::Url("scheme must be http(s)")),
    };
    u.set_scheme(scheme)
        .map_err(|_| HubError::Url("cannot set ws scheme"))?;
    Ok(u)
}

enum SessionEnd {
    /// Lock or sync loop gone: stop for good.
    Stop,
    /// The connection ended; `up_for` is how long it was established.
    Failed {
        error: HubError,
        up_for: Option<Duration>,
    },
}

/// Push loop (REQ-CRY-009): hold the hub connection and nudge `nudge`
/// on every sync-relevant update, reconnecting with backoff. Returns
/// when the session locks or the nudge receiver is dropped. Polling in
/// [`super::run`] is unaffected by anything that happens here.
pub async fn run_push(
    mut hub: NotificationsHub,
    nudge: mpsc::Sender<()>,
    mut on_status: impl FnMut(&HubStatus),
) {
    let timing = hub.timing;
    let mut backoff = Backoff::new(timing.backoff_base, timing.backoff_max);
    loop {
        if nudge.is_closed() || !token_source_open(&hub.tokens) {
            break;
        }
        let Some(token) = hub.fresh_token() else {
            on_status(&HubStatus::WaitingForToken);
            // The sync loop logs in on its next sync; ask for it now.
            let _ = nudge.try_send(());
            let wait = backoff.next_delay();
            if !wait_or_stop(&mut hub.tokens, &nudge, wait, true).await {
                break;
            }
            continue;
        };
        let end = tokio::select! {
            end = session(&hub.url, &hub.tls, &mut hub.tokens, token, &nudge, &timing, &mut on_status) => end,
            _ = nudge.closed() => SessionEnd::Stop,
        };
        let (error, up_for) = match end {
            SessionEnd::Stop => break,
            SessionEnd::Failed { error, up_for } => (error, up_for),
        };
        on_status(&HubStatus::Disconnected(error.clone()));
        if up_for.is_some_and(|d| d >= timing.stable_after) {
            backoff.reset();
        }
        let (wait, token_change_ends_wait) = if let HubError::Status(status) = error
            && error.is_unsupported()
        {
            on_status(&HubStatus::Unsupported { status });
            (timing.unsupported_retry, false)
        } else if error.is_auth() {
            // Token rejected (revoked, security stamp changed): a sync
            // re-logs in, and the new token ends the wait early.
            let _ = nudge.try_send(());
            (backoff.next_delay(), true)
        } else {
            (backoff.next_delay(), false)
        };
        on_status(&HubStatus::Retrying(wait));
        if !wait_or_stop(&mut hub.tokens, &nudge, wait, token_change_ends_wait).await {
            break;
        }
    }
    on_status(&HubStatus::Stopped);
}

fn token_source_open(tokens: &watch::Receiver<Option<HubToken>>) -> bool {
    tokens.has_changed().is_ok()
}

/// Sleep `wait`; `false` if the session locked or the sync loop went
/// away meanwhile. With `token_change_ends_wait`, a new token ends the
/// wait early.
async fn wait_or_stop(
    tokens: &mut watch::Receiver<Option<HubToken>>,
    nudge: &mpsc::Sender<()>,
    wait: Duration,
    token_change_ends_wait: bool,
) -> bool {
    let deadline = tokio::time::sleep(wait);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return true,
            _ = nudge.closed() => return false,
            r = tokens.changed() => {
                if r.is_err() {
                    return false;
                }
                if token_change_ends_wait && tokens.borrow().is_some() {
                    return true;
                }
            }
        }
    }
}

type Ws = WebSocketStream<MaybeTls>;

async fn session(
    url: &Url,
    tls: &Arc<rustls::ClientConfig>,
    tokens: &mut watch::Receiver<Option<HubToken>>,
    token: HubToken,
    nudge: &mpsc::Sender<()>,
    timing: &HubTiming,
    on_status: &mut impl FnMut(&HubStatus),
) -> SessionEnd {
    let fail = |error| SessionEnd::Failed {
        error,
        up_for: None,
    };
    let mut ws = match tokio::time::timeout(timing.connect_timeout, connect(url, tls, &token)).await
    {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => return fail(e),
        Err(_) => return fail(HubError::Timeout),
    };
    drop(token);
    let leftover = match tokio::time::timeout(timing.handshake_timeout, handshake(&mut ws)).await {
        Ok(Ok(rest)) => rest,
        Ok(Err(e)) => return fail(e),
        Err(_) => return fail(HubError::Timeout),
    };
    let up = Instant::now();
    let failed = |error| SessionEnd::Failed {
        error,
        up_for: Some(up.elapsed()),
    };
    on_status(&HubStatus::Connected);
    // Catch up on anything that changed while not subscribed.
    let _ = nudge.try_send(());
    if !leftover.is_empty()
        && let Err(e) = dispatch(&leftover, nudge, on_status)
    {
        return failed(e);
    }

    let mut ping = tokio::time::interval_at(up + timing.ping_interval, timing.ping_interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_rx = Instant::now();
    loop {
        let idle = tokio::time::sleep_until(last_rx + timing.server_timeout);
        tokio::select! {
            msg = ws.next() => {
                last_rx = Instant::now();
                match msg {
                    None => return failed(HubError::Closed),
                    Some(Err(_)) => return failed(HubError::Transport),
                    Some(Ok(Message::Binary(b))) => {
                        if let Err(e) = dispatch(&b, nudge, on_status) {
                            let _ = ws.close(None).await;
                            return failed(e);
                        }
                    }
                    Some(Ok(Message::Close(_))) => return failed(HubError::Closed),
                    // Ping frames are answered by tungstenite; text is
                    // the JSON protocol, which was not negotiated.
                    Some(Ok(_)) => {}
                }
            }
            _ = ping.tick() => {
                if ws.send(Message::Binary(PING_FRAME.to_vec())).await.is_err() {
                    return failed(HubError::Transport);
                }
            }
            _ = idle => {
                let _ = ws.close(None).await;
                return failed(HubError::Timeout);
            }
            r = tokens.changed() => {
                if r.is_err() {
                    let _ = ws.close(None).await;
                    return SessionEnd::Stop;
                }
                if tokens.borrow().is_none() {
                    let _ = ws.close(None).await;
                    return failed(HubError::TokenGone);
                }
                // A refreshed token: the open connection stays valid.
            }
        }
    }
}

/// Parse one binary frame and nudge on relevant updates.
fn dispatch(
    frame: &[u8],
    nudge: &mpsc::Sender<()>,
    on_status: &mut impl FnMut(&HubStatus),
) -> Result<(), HubError> {
    for msg in parse_frame(frame)? {
        match msg {
            HubMessage::Invocation {
                update: Some(u), ..
            } if u.triggers_sync() => {
                on_status(&HubStatus::Push(u));
                // Capacity-1 channel: a pending nudge already covers
                // this update, so Full is fine.
                let _ = nudge.try_send(());
            }
            HubMessage::Close { .. } => return Err(HubError::ServerClose),
            _ => {}
        }
    }
    Ok(())
}

async fn connect(
    url: &Url,
    tls: &Arc<rustls::ClientConfig>,
    token: &HubToken,
) -> Result<Ws, HubError> {
    let host = match url.host() {
        Some(Host::Domain(d)) => d.to_owned(),
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => ip.to_string(),
        None => return Err(HubError::Url("no host")),
    };
    let port = url
        .port_or_known_default()
        .ok_or(HubError::Url("no port"))?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|_| HubError::Connect("TCP connect failed"))?;
    let _ = tcp.set_nodelay(true);
    let stream = if url.scheme() == "wss" {
        let name = rustls::pki_types::ServerName::try_from(host)
            .map_err(|_| HubError::Url("invalid TLS server name"))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(tls));
        MaybeTls::Tls(Box::new(
            connector
                .connect(name, tcp)
                .await
                .map_err(|_| HubError::Tls)?,
        ))
    } else {
        MaybeTls::Plain(tcp)
    };
    let mut req = url
        .as_str()
        .into_client_request()
        .map_err(|_| HubError::Url("not a valid WebSocket URL"))?;
    let mut auth = HeaderValue::from_str(&format!("Bearer {}", token.value.as_str()))
        .map_err(|_| HubError::Protocol("access token is not a valid header value"))?;
    auth.set_sensitive(true);
    req.headers_mut().insert(header::AUTHORIZATION, auth);
    let config = WebSocketConfig {
        max_message_size: Some(MAX_HUB_MESSAGE),
        max_frame_size: Some(MAX_HUB_MESSAGE),
        ..Default::default()
    };
    match tokio_tungstenite::client_async_with_config(req, stream, Some(config)).await {
        Ok((ws, _)) => Ok(ws),
        Err(WsError::Http(resp)) => Err(HubError::Status(resp.status().as_u16())),
        Err(_) => Err(HubError::Connect("WebSocket upgrade failed")),
    }
}

/// Send the handshake and wait for `{}` + RS. Returns any bytes the
/// server sent after the separator in the same frame.
async fn handshake(ws: &mut Ws) -> Result<Vec<u8>, HubError> {
    ws.send(Message::Text(HANDSHAKE_REQUEST.to_owned()))
        .await
        .map_err(|_| HubError::Transport)?;
    loop {
        let bytes = match ws.next().await {
            None => return Err(HubError::Closed),
            Some(Err(_)) => return Err(HubError::Transport),
            Some(Ok(Message::Text(t))) => t.into_bytes(),
            Some(Ok(Message::Binary(b))) => b,
            Some(Ok(Message::Close(_))) => return Err(HubError::Closed),
            Some(Ok(_)) => continue,
        };
        return parse_handshake_response(&bytes).map(<[u8]>::to_vec);
    }
}

/// `{}` + RS (+ trailing records) → the trailing bytes. A response
/// with an `error` member is a refusal.
pub fn parse_handshake_response(bytes: &[u8]) -> Result<&[u8], HubError> {
    let end = bytes
        .iter()
        .position(|b| *b == RECORD_SEPARATOR)
        .ok_or(HubError::Handshake("response has no record separator"))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes[..end])
        .map_err(|_| HubError::Handshake("response is not JSON"))?;
    let obj = v
        .as_object()
        .ok_or(HubError::Handshake("response is not an object"))?;
    if obj.contains_key("error") {
        return Err(HubError::Handshake("server refused the protocol"));
    }
    Ok(&bytes[end + 1..])
}

/// Split a binary frame into `VarInt(len) ‖ msgpack` records and parse
/// each.
pub fn parse_frame(mut frame: &[u8]) -> Result<Vec<HubMessage>, HubError> {
    let mut out = Vec::new();
    while !frame.is_empty() {
        let (len, used) = read_varint(frame)?;
        let rest = &frame[used..];
        if len > rest.len() {
            return Err(HubError::Protocol("record length past end of frame"));
        }
        out.push(parse_message(&rest[..len])?);
        frame = &rest[len..];
    }
    Ok(out)
}

/// SignalR binary length prefix: 7 bits per byte, little-endian, at
/// most 5 bytes.
fn read_varint(b: &[u8]) -> Result<(usize, usize), HubError> {
    let mut len: usize = 0;
    for (i, byte) in b.iter().take(5).enumerate() {
        len |= ((byte & 0x7f) as usize) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((len, i + 1));
        }
    }
    Err(HubError::Protocol("bad length prefix"))
}

/// Parse one msgpack SignalR message.
pub fn parse_message(b: &[u8]) -> Result<HubMessage, HubError> {
    let mut r = Reader { b, pos: 0 };
    let n = r.array_len()?;
    if n == 0 {
        return Err(HubError::Protocol("empty message"));
    }
    let kind = r.int()?;
    let msg = match kind {
        1 if n >= 5 => {
            r.skip(0)?; // headers
            r.skip(0)?; // invocation id
            let target = r.str()?.to_owned();
            let update = if target == "ReceiveMessage" {
                r.receive_message_type()?
            } else {
                r.skip(0)?;
                None
            };
            for _ in 5..n {
                r.skip(0)?; // stream ids
            }
            HubMessage::Invocation { target, update }
        }
        1 => return Err(HubError::Protocol("short invocation")),
        6 => {
            for _ in 1..n {
                r.skip(0)?;
            }
            HubMessage::Ping
        }
        7 => {
            let mut allow_reconnect = None;
            if n >= 2 {
                r.skip(0)?; // error text: server-provided, not kept
            }
            if n >= 3 {
                allow_reconnect = r.bool_opt()?;
            }
            for _ in 3..n {
                r.skip(0)?;
            }
            HubMessage::Close { allow_reconnect }
        }
        other => {
            for _ in 1..n {
                r.skip(0)?;
            }
            HubMessage::Other(other)
        }
    };
    if r.pos != b.len() {
        return Err(HubError::Protocol("trailing bytes in record"));
    }
    Ok(msg)
}

/// A minimal, bounds-checked MessagePack reader: just enough to read
/// SignalR envelopes and skip everything else. Never allocates from a
/// length field.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

const BAD: HubError = HubError::Protocol("malformed msgpack");

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], HubError> {
        let end = self.pos.checked_add(n).ok_or(BAD)?;
        let s = self.b.get(self.pos..end).ok_or(BAD)?;
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, HubError> {
        Ok(self.take(1)?[0])
    }

    fn be(&mut self, n: usize) -> Result<u64, HubError> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    fn peek(&self) -> Result<u8, HubError> {
        self.b.get(self.pos).copied().ok_or(BAD)
    }

    fn array_len(&mut self) -> Result<usize, HubError> {
        match self.u8()? {
            t @ 0x90..=0x9f => Ok((t & 0x0f) as usize),
            0xdc => Ok(self.be(2)? as usize),
            0xdd => Ok(self.be(4)? as usize),
            _ => Err(HubError::Protocol("expected array")),
        }
    }

    fn map_len(&mut self) -> Result<usize, HubError> {
        match self.u8()? {
            t @ 0x80..=0x8f => Ok((t & 0x0f) as usize),
            0xde => Ok(self.be(2)? as usize),
            0xdf => Ok(self.be(4)? as usize),
            _ => Err(HubError::Protocol("expected map")),
        }
    }

    fn int(&mut self) -> Result<i64, HubError> {
        let t = self.u8()?;
        Ok(match t {
            0x00..=0x7f => i64::from(t),
            0xe0..=0xff => i64::from(t as i8),
            0xcc => self.be(1)? as i64,
            0xcd => self.be(2)? as i64,
            0xce => self.be(4)? as i64,
            0xcf => i64::try_from(self.be(8)?).map_err(|_| BAD)?,
            0xd0 => i64::from(self.be(1)? as u8 as i8),
            0xd1 => i64::from(self.be(2)? as u16 as i16),
            0xd2 => i64::from(self.be(4)? as u32 as i32),
            0xd3 => self.be(8)? as i64,
            _ => return Err(HubError::Protocol("expected integer")),
        })
    }

    fn str(&mut self) -> Result<&'a str, HubError> {
        let len = match self.u8()? {
            t @ 0xa0..=0xbf => (t & 0x1f) as usize,
            0xd9 => self.be(1)? as usize,
            0xda => self.be(2)? as usize,
            0xdb => self.be(4)? as usize,
            _ => return Err(HubError::Protocol("expected string")),
        };
        std::str::from_utf8(self.take(len)?).map_err(|_| BAD)
    }

    fn bool_opt(&mut self) -> Result<Option<bool>, HubError> {
        match self.peek()? {
            0xc2 | 0xc3 => Ok(Some(self.u8()? == 0xc3)),
            _ => {
                self.skip(0)?;
                Ok(None)
            }
        }
    }

    /// `[{ContextId, Type, Payload}, …]` → the first argument's `Type`
    /// (key matched case-insensitively; other keys skipped).
    fn receive_message_type(&mut self) -> Result<Option<UpdateType>, HubError> {
        let args = self.array_len()?;
        let mut found = None;
        for i in 0..args {
            let is_map = matches!(self.peek()?, 0x80..=0x8f | 0xde | 0xdf);
            if i > 0 || !is_map {
                self.skip(0)?;
                continue;
            }
            let pairs = self.map_len()?;
            for _ in 0..pairs {
                let key_is_type = match self.peek()? {
                    0xa0..=0xbf | 0xd9..=0xdb => self.str()?.eq_ignore_ascii_case("type"),
                    _ => {
                        self.skip(2)?;
                        false
                    }
                };
                let value_is_int = matches!(self.peek()?, 0x00..=0x7f | 0xe0..=0xff | 0xcc..=0xd3);
                if key_is_type && value_is_int {
                    found = Some(UpdateType(self.int()?));
                } else {
                    self.skip(2)?;
                }
            }
        }
        Ok(found)
    }

    /// Skip one value of any type.
    fn skip(&mut self, depth: usize) -> Result<(), HubError> {
        if depth > MAX_DEPTH {
            return Err(HubError::Protocol("msgpack nested too deep"));
        }
        let t = self.u8()?;
        let (fixed, items): (usize, usize) = match t {
            0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => (0, 0),
            0x80..=0x8f => (0, 2 * (t & 0x0f) as usize),
            0x90..=0x9f => (0, (t & 0x0f) as usize),
            0xa0..=0xbf => ((t & 0x1f) as usize, 0),
            0xc4 | 0xd9 => (self.be(1)? as usize, 0),
            0xc5 | 0xda => (self.be(2)? as usize, 0),
            0xc6 | 0xdb => (self.be(4)? as usize, 0),
            0xc7 => (1 + self.be(1)? as usize, 0),
            0xc8 => (1 + self.be(2)? as usize, 0),
            0xc9 => (1 + self.be(4)? as usize, 0),
            0xca => (4, 0),
            0xcb => (8, 0),
            0xcc | 0xd0 => (1, 0),
            0xcd | 0xd1 => (2, 0),
            0xce | 0xd2 => (4, 0),
            0xcf | 0xd3 => (8, 0),
            0xd4 => (2, 0),
            0xd5 => (3, 0),
            0xd6 => (5, 0),
            0xd7 => (9, 0),
            0xd8 => (17, 0),
            0xdc => (0, self.be(2)? as usize),
            0xdd => (0, self.be(4)? as usize),
            0xde => (0, 2 * self.be(2)? as usize),
            0xdf => (0, 2usize.saturating_mul(self.be(4)? as usize)),
            0xc1 => return Err(BAD),
        };
        self.take(fixed)?;
        // Each item needs at least one byte: reject impossible counts
        // before looping.
        if items > self.b.len() - self.pos {
            return Err(BAD);
        }
        for _ in 0..items {
            self.skip(depth + 1)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny msgpack encoder for test vectors, matching rmpv's choice of
    /// the shortest encoding (what Vaultwarden emits).
    enum V {
        Nil,
        Bool(bool),
        Int(i64),
        Str(&'static str),
        Arr(Vec<V>),
        Map(Vec<(V, V)>),
        /// msgpack timestamp (ext -1, 8 bytes), as Vaultwarden's
        /// `serialize_date`.
        Ts,
    }

    fn enc(v: &V, out: &mut Vec<u8>) {
        match v {
            V::Nil => out.push(0xc0),
            V::Bool(b) => out.push(if *b { 0xc3 } else { 0xc2 }),
            V::Int(i) if (0..=0x7f).contains(i) => out.push(*i as u8),
            V::Int(i) if (-32..0).contains(i) => out.push(*i as i8 as u8),
            V::Int(i) if (0..=0xff).contains(i) => out.extend([0xcc, *i as u8]),
            V::Int(i) => {
                out.push(0xd3);
                out.extend(i.to_be_bytes());
            }
            V::Str(s) if s.len() < 32 => {
                out.push(0xa0 | s.len() as u8);
                out.extend(s.as_bytes());
            }
            V::Str(s) => {
                out.extend([0xd9, s.len() as u8]);
                out.extend(s.as_bytes());
            }
            V::Arr(a) => {
                assert!(a.len() < 16);
                out.push(0x90 | a.len() as u8);
                a.iter().for_each(|x| enc(x, out));
            }
            V::Map(m) => {
                assert!(m.len() < 16);
                out.push(0x80 | m.len() as u8);
                for (k, v) in m {
                    enc(k, out);
                    enc(v, out);
                }
            }
            V::Ts => {
                out.extend([0xd7, 0xff]);
                out.extend(0x0000_0001_6543_2100u64.to_be_bytes());
            }
        }
    }

    fn frame(msgs: &[V]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in msgs {
            let mut body = Vec::new();
            enc(m, &mut body);
            let mut n = body.len();
            loop {
                let mut b = (n & 0x7f) as u8;
                n >>= 7;
                if n > 0 {
                    b |= 0x80;
                }
                out.push(b);
                if n == 0 {
                    break;
                }
            }
            out.extend(body);
        }
        out
    }

    /// Vaultwarden 1.33 `send_cipher_update` (`create_update`) shape.
    fn vw_cipher_update(ut: i64) -> V {
        V::Arr(vec![
            V::Int(1),
            V::Map(vec![]),
            V::Nil,
            V::Str("ReceiveMessage"),
            V::Arr(vec![V::Map(vec![
                (
                    V::Str("ContextId"),
                    V::Str("0b9e1b6e-6f86-4c3e-9a0f-4f0b8e0d9c11"),
                ),
                (V::Str("Type"), V::Int(ut)),
                (
                    V::Str("Payload"),
                    V::Map(vec![
                        (V::Str("Id"), V::Str("a7c4d1d0-41a8-4d0b-9b8b-27d1c8f1e0aa")),
                        (V::Str("UserId"), V::Nil),
                        (
                            V::Str("OrganizationId"),
                            V::Str("0d9f4c1e-0000-4000-8000-0000000000aa"),
                        ),
                        (V::Str("CollectionIds"), V::Arr(vec![V::Str("c1")])),
                        (V::Str("RevisionDate"), V::Ts),
                    ]),
                ),
            ])]),
        ])
    }

    #[test]
    fn req_cry_009_parses_vaultwarden_update_ping_and_close() {
        let f = frame(&[vw_cipher_update(1)]);
        assert_eq!(
            parse_frame(&f).unwrap(),
            vec![HubMessage::Invocation {
                target: "ReceiveMessage".into(),
                update: Some(UpdateType::SYNC_CIPHER_CREATE),
            }]
        );
        // Vaultwarden's create_ping(): serialize([6]).
        assert_eq!(parse_frame(&PING_FRAME).unwrap(), vec![HubMessage::Ping]);
        let close = frame(&[V::Arr(vec![V::Int(7), V::Str("bye"), V::Bool(true)])]);
        assert_eq!(
            parse_frame(&close).unwrap(),
            vec![HubMessage::Close {
                allow_reconnect: Some(true)
            }]
        );
        // Several records in one frame, lowercase key (JSON-ish servers).
        let lower = V::Arr(vec![
            V::Int(1),
            V::Map(vec![]),
            V::Nil,
            V::Str("ReceiveMessage"),
            V::Arr(vec![V::Map(vec![(V::Str("type"), V::Int(5))])]),
        ]);
        let f = frame(&[V::Arr(vec![V::Int(6)]), lower, vw_cipher_update(9)]);
        let got = parse_frame(&f).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(
            got[1],
            HubMessage::Invocation {
                target: "ReceiveMessage".into(),
                update: Some(UpdateType::SYNC_VAULT)
            }
        );
        // Other targets and message types parse without an update.
        let other = frame(&[
            V::Arr(vec![
                V::Int(1),
                V::Map(vec![]),
                V::Nil,
                V::Str("AuthRequestResponseRecieved"),
                V::Arr(vec![V::Map(vec![(V::Str("Type"), V::Int(16))])]),
            ]),
            V::Arr(vec![V::Int(3), V::Map(vec![]), V::Str("id"), V::Int(1)]),
        ]);
        assert_eq!(
            parse_frame(&other).unwrap(),
            vec![
                HubMessage::Invocation {
                    target: "AuthRequestResponseRecieved".into(),
                    update: None
                },
                HubMessage::Other(3)
            ]
        );
    }

    #[test]
    fn req_cry_009_handshake_response() {
        // Vaultwarden's INITIAL_RESPONSE.
        assert_eq!(
            parse_handshake_response(&[0x7b, 0x7d, 0x1e]).unwrap(),
            &[] as &[u8]
        );
        let mut with_rest = b"{}\x1e".to_vec();
        with_rest.extend(PING_FRAME);
        assert_eq!(parse_handshake_response(&with_rest).unwrap(), PING_FRAME);
        assert!(matches!(
            parse_handshake_response(b"{\"error\":\"nope\"}\x1e"),
            Err(HubError::Handshake(_))
        ));
        assert!(parse_handshake_response(b"{}").is_err());
        assert!(parse_handshake_response(b"[]\x1e").is_err());
        assert_eq!(
            HANDSHAKE_REQUEST.as_bytes(),
            b"{\"protocol\":\"messagepack\",\"version\":1}\x1e"
        );
    }

    #[test]
    fn req_cry_009_event_filter() {
        for t in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 17, 18, 19] {
            assert!(UpdateType(t).triggers_sync(), "{t}");
        }
        // Settings, sends, auth requests, Vaultwarden's None (100),
        // unknown and negative types never sync.
        for t in [10, 12, 13, 14, 15, 16, 20, 21, 100, -1, i64::MAX] {
            assert!(!UpdateType(t).triggers_sync(), "{t}");
        }
    }

    #[test]
    fn req_cry_009_dispatch_nudges_only_on_relevant_updates() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut seen = Vec::new();
        let mut on = |s: &HubStatus| seen.push(s.clone());
        dispatch(&frame(&[vw_cipher_update(12)]), &tx, &mut on).unwrap();
        dispatch(&PING_FRAME, &tx, &mut on).unwrap();
        assert!(rx.try_recv().is_err());
        // Two relevant updates coalesce into one pending nudge.
        dispatch(
            &frame(&[vw_cipher_update(0), vw_cipher_update(2)]),
            &tx,
            &mut on,
        )
        .unwrap();
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
        assert_eq!(
            seen,
            vec![
                HubStatus::Push(UpdateType::SYNC_CIPHER_UPDATE),
                HubStatus::Push(UpdateType::SYNC_LOGIN_DELETE)
            ]
        );
        let close = frame(&[V::Arr(vec![V::Int(7), V::Nil])]);
        assert_eq!(
            dispatch(&close, &tx, &mut |_| {}),
            Err(HubError::ServerClose)
        );
    }

    #[test]
    fn req_cry_009_malformed_frames_are_errors_not_panics() {
        let good = frame(&[vw_cipher_update(1)]);
        // Every truncation of a valid frame is rejected.
        for n in 1..good.len() {
            assert!(parse_frame(&good[..n]).is_err(), "{n}");
        }
        for bad in [
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01][..], // 6-byte varint
            &[0x05, 0x91][..],                         // length past end
            &[0x01, 0xc1][..],                         // reserved byte
            &[0x01, 0x90][..],                         // empty array
            &[0x02, 0x91, 0xa0][..],                   // non-int type
            &[0x06, 0xdd, 0xff, 0xff, 0xff, 0xff, 0x01][..], // huge count
            &[0x03, 0x92, 0x06, 0x06, 0x00][..],       // trailing bytes
        ] {
            assert!(parse_frame(bad).is_err(), "{bad:x?}");
        }
        // Deep nesting is cut off, not recursed into.
        let mut deep = vec![0x92, 0x06];
        deep.extend(std::iter::repeat_n(0x91, 64));
        deep.push(0xc0);
        let mut f = vec![deep.len() as u8];
        f.extend(&deep);
        assert!(parse_frame(&f).is_err());
        // Random input never panics.
        let mut rng = rand::thread_rng();
        for _ in 0..20_000 {
            let len = rand::Rng::gen_range(&mut rng, 0..48);
            let b: Vec<u8> = (0..len).map(|_| rand::Rng::r#gen(&mut rng)).collect();
            let _ = parse_frame(&b);
        }
    }

    #[test]
    fn req_cry_009_backoff_doubles_with_jitter_caps_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        let mut ceilings = Vec::new();
        for _ in 0..10 {
            let c = b.ceiling();
            let d = b.next_delay();
            assert!(d >= c / 2 && d <= c, "{d:?} vs {c:?}");
            ceilings.push(c.as_secs());
        }
        assert_eq!(ceilings, [1, 2, 4, 8, 16, 32, 60, 60, 60, 60]);
        for _ in 0..100 {
            b.next_delay();
        }
        assert_eq!(b.ceiling(), Duration::from_secs(60));
        b.reset();
        assert_eq!(b.ceiling(), Duration::from_secs(1));
        assert_eq!(HubTiming::default().backoff_max, Duration::from_secs(60));
        assert_eq!(
            HubTiming::default().unsupported_retry,
            super::super::MAX_SYNC_INTERVAL
        );
    }

    #[test]
    fn req_cry_009_unsupported_and_auth_statuses() {
        for s in [400, 404, 405, 501] {
            assert!(HubError::Status(s).is_unsupported());
        }
        for s in [401, 403] {
            assert!(HubError::Status(s).is_auth());
            assert!(!HubError::Status(s).is_unsupported());
        }
        assert!(!HubError::Status(502).is_unsupported());
        assert!(!HubError::Timeout.is_unsupported());
    }

    #[test]
    fn req_cry_009_token_never_debug_printed() {
        let t = HubToken::new(
            Arc::new(Zeroizing::new("eyJ.secret-token".to_owned())),
            std::time::Instant::now() + Duration::from_secs(60),
        );
        assert!(t.is_fresh());
        let s = format!("{t:?} {:?}", Some(t.clone()));
        assert!(!s.contains("secret"), "{s}");
        let stale = HubToken::new(
            Arc::new(Zeroizing::new("x".to_owned())),
            std::time::Instant::now(),
        );
        assert!(!stale.is_fresh());
    }

    #[test]
    fn req_cry_009_hub_url_scheme() {
        assert_eq!(
            ws_url(Url::parse("https://vw.example/notifications/hub").unwrap())
                .unwrap()
                .as_str(),
            "wss://vw.example/notifications/hub"
        );
        assert_eq!(
            ws_url(Url::parse("http://127.0.0.1:8080/notifications/hub").unwrap())
                .unwrap()
                .as_str(),
            "ws://127.0.0.1:8080/notifications/hub"
        );
        assert!(ws_url(Url::parse("ftp://x/").unwrap()).is_err());
    }
}
