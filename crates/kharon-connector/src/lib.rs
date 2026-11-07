//! Agent-initiated connector wire (SPEC OQ-14, path B).
//!
//! v1 is a raw TLS reverse tunnel. The agent dials the broker, pins the
//! broker certificate, presents a tunnel credential, and then relays the
//! broker's CDP bytes to a loopback address on the agent host. The broker
//! stays the CDP client. This crate is the framing both sides share; the
//! Argon2id check and the CDP WebSocket stay in `kharond`.
//!
//! # Wire version 1
//!
//! Everything after the TLS handshake is versioned by [`WIRE_VERSION`].
//! Bump it rather than overloading a field: the peer closes on a mismatch.
//!
//! 1. **Auth record**, each direction, `u32be` length then body (max
//!    [`AUTH_MAX`] bytes).
//!    - Client body: magic `KHCN`, version, `u16be` agent id, `u16be` token.
//!    - Server body: magic `KHCN`, version, status ([`AUTH_OK`],
//!      [`AUTH_UNAUTHORIZED`], [`AUTH_PROTOCOL`]).
//!    - Any status other than [`AUTH_OK`] ends the connection. No CDP
//!      dial happens before [`AUTH_OK`].
//! 2. **Frames**, both directions: `u8` type, `u32be` stream id, `u32be`
//!    length, payload (max [`MAX_PAYLOAD`]).
//!    - [`FRAME_OPEN`] broker → agent, **empty payload**. The agent dials
//!      only the loopback address in its own config. A non-empty payload
//!      is a protocol error (the broker cannot aim the dial).
//!    - The agent replies [`FRAME_OPEN`] with an empty payload once the
//!      TCP connect succeeded, or [`FRAME_CLOSE`] with
//!      [`CLOSE_DIAL_FAILED`].
//!    - [`FRAME_DATA`] is bytes. [`FRAME_CLOSE`] ends one stream.
//!      [`FRAME_PING`] / [`FRAME_PONG`] are empty keepalives.
//!
//! Stream ids are allocated by the broker, starting at 1. The agent opens
//! none. v1 backpressure is head-of-line: a stream that does not read
//! stalls the connection's reader (the per-stream queue is
//! [`STREAM_QUEUE`] frames). CDP does not need a credit window; one can
//! be added under a new version without changing the CDP client.
//!
//! Reconnect is not a frame. The agent drops the TLS session and dials
//! again. A new authenticated session for the same agent replaces the
//! previous one; streams on the old session fail.
//!
//! # Adjusting this
//!
//! The constants and the codecs in [`frame`] and [`auth`] are the whole
//! v1 contract. `kharond` and `kharon-agent-connector` should not grow a
//! second copy.

#![forbid(unsafe_code)]

mod auth;
mod client;
mod frame;
mod mux;
mod proxy;
mod tls;

pub use auth::{read_client_hello, read_server_hello, write_client_hello, write_server_hello};
pub use client::{AgentParams, run_agent_once};
pub use frame::{Frame, encode_frame};
pub use mux::{BrokerSession, MuxIo, OpenError, serve_agent, spawn_broker};
pub use proxy::connect_http_proxy;
pub use tls::{CertSha256, TlsMaterialError, connect_pinned, pin_of_der, server_config_from_pem};

/// Why [`run_agent_once`] stopped. Display text is fixed: it never includes
/// the tunnel token, the certificate, or a peer's response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The broker certificate was not the pinned one (REQ-ARCH-002).
    #[error("broker TLS certificate did not match the pin")]
    BadCert,
    /// The broker refused the tunnel credential (REQ-ARCH-002).
    #[error("tunnel credentials were refused")]
    Unauthorized,
    /// The HTTP CONNECT proxy returned 407 (REQ-DEP-005 path B).
    /// Display text never includes the credential or the response body.
    #[error("proxy authentication was refused")]
    ProxyAuth,
    /// The peer did not speak version 1.
    #[error("connector protocol error")]
    Protocol,
    /// The TLS session ended after a successful auth.
    #[error("connector connection ended")]
    Disconnected,
    /// `cdp` is not a loopback socket. The connector will not dial it.
    #[error("cdp address is not a loopback socket")]
    CdpNotLoopback,
    /// TCP, proxy, or handshake failure that is not a pin mismatch.
    #[error("connector transport error ({context})")]
    Transport {
        /// `tcp`, `tls`, or `proxy`.
        context: &'static str,
    },
}

/// ASCII magic at the start of both auth bodies.
pub const MAGIC: &[u8; 4] = b"KHCN";
/// Bump when an auth body or frame stops being readable as v1.
pub const WIRE_VERSION: u8 = 1;

/// Largest auth body (length prefix not included).
pub const AUTH_MAX: usize = 1024;
/// Largest frame payload. Larger lengths are a protocol error.
pub const MAX_PAYLOAD: usize = 16 * 1024;
/// Broker-side cap on streams open at once (discovery + WebSocket, with room).
pub const MAX_STREAMS: usize = 32;
/// Inbound frames buffered per stream before the connection reader waits.
pub const STREAM_QUEUE: usize = 8;
/// Outbound frames buffered per connection before a writer waits.
pub const OUTBOX_QUEUE: usize = 32;

/// How often each side sends [`FRAME_PING`] when the connection is idle.
pub const PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(20);
/// Drop the connection if no frame arrives for this long.
pub const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
/// How long the agent waits for its loopback CDP dial.
pub const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub const AUTH_OK: u8 = 0;
pub const AUTH_UNAUTHORIZED: u8 = 1;
pub const AUTH_PROTOCOL: u8 = 2;

pub const FRAME_OPEN: u8 = 1;
pub const FRAME_DATA: u8 = 2;
pub const FRAME_CLOSE: u8 = 3;
pub const FRAME_PING: u8 = 4;
pub const FRAME_PONG: u8 = 5;

pub const CLOSE_NORMAL: u8 = 0;
pub const CLOSE_DIAL_FAILED: u8 = 1;
pub const CLOSE_RESET: u8 = 2;

/// Duplex buffer between a CDP byte stream and the frame pump.
///
/// One in-page fill carries the isolated-world script (tens of KiB) plus
/// the WebSocket framing, so the buffer is well above [`MAX_PAYLOAD`].
pub const DUPLEX_BYTES: usize = 256 * 1024;
