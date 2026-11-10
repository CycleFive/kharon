//! WebSocket as a byte stream, for the connector's inner TLS.
//!
//! The edge (Cloudflare) terminates the outer TLS and forwards WebSocket
//! messages. [`WsByteStream`] carries the inner TLS records in binary
//! messages and nothing else.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use crate::{MAX_WS_WRITE, WS_MAX_MESSAGE};

/// Message and frame limits for both ends. Unmasked client frames stay
/// refused (the tungstenite default).
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(WS_MAX_MESSAGE),
        max_frame_size: Some(WS_MAX_MESSAGE),
        ..WebSocketConfig::default()
    }
}

/// `AsyncRead + AsyncWrite` over a [`WebSocketStream`].
pub struct WsByteStream<S> {
    ws: WebSocketStream<S>,
    pending: Vec<u8>,
    pos: usize,
}

impl<S> WsByteStream<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            ws,
            pending: Vec::new(),
            pos: 0,
        }
    }
}

fn io_err(e: WsError) -> io::Error {
    match e {
        WsError::Io(e) => e,
        e @ (WsError::Capacity(_) | WsError::Protocol(_)) => {
            io::Error::new(io::ErrorKind::InvalidData, e)
        }
        other => io::Error::other(other),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsByteStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.pos < this.pending.len() {
                let n = buf.remaining().min(this.pending.len() - this.pos);
                buf.put_slice(&this.pending[this.pos..this.pos + n]);
                this.pos += n;
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.ws).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed))) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io_err(e))),
                Poll::Ready(Some(Ok(Message::Binary(b)))) => {
                    this.pending = b;
                    this.pos = 0;
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)))) => {}
                Poll::Ready(Some(Ok(Message::Text(_)))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "websocket text message on a binary stream",
                    )));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsByteStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let ws = &mut self.ws;
        match Pin::new(&mut *ws).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io_err(e))),
            Poll::Ready(Ok(())) => {}
        }
        let n = buf.len().min(MAX_WS_WRITE);
        match Pin::new(ws).start_send(Message::Binary(buf[..n].to_vec())) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(io_err(e))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws).poll_flush(cx).map_err(io_err)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.ws).poll_close(cx) {
            Poll::Ready(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => {
                Poll::Ready(Ok(()))
            }
            other => other.map_err(io_err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_WS_WRITE, WS_MAX_MESSAGE};
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::protocol::Role;

    type Duplex = tokio::io::DuplexStream;

    /// (adapter under test on the server role, raw peer on the client role)
    async fn pair() -> (WsByteStream<Duplex>, WebSocketStream<Duplex>) {
        let (a, b) = tokio::io::duplex(256 * 1024);
        let server = WebSocketStream::from_raw_socket(a, Role::Server, Some(ws_config())).await;
        // The peer is permissive so tests can send oversize messages.
        let client = WebSocketStream::from_raw_socket(b, Role::Client, None).await;
        (WsByteStream::new(server), client)
    }

    #[tokio::test]
    async fn reads_span_messages() {
        let (mut s, mut peer) = pair().await;
        peer.send(Message::Binary(b"hello ".to_vec()))
            .await
            .unwrap();
        peer.send(Message::Ping(vec![1])).await.unwrap();
        peer.send(Message::Binary(b"wor".to_vec())).await.unwrap();
        peer.send(Message::Pong(vec![])).await.unwrap();
        peer.send(Message::Binary(b"ld".to_vec())).await.unwrap();
        let mut got = [0u8; 11];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello world");
    }

    #[tokio::test]
    async fn write_splits_at_max_ws_write() {
        let (mut s, mut peer) = pair().await;
        let data = vec![7u8; 40 * 1024];
        let want = data.clone();
        let writer = tokio::spawn(async move {
            s.write_all(&data).await.unwrap();
            s.flush().await.unwrap();
            s
        });
        let mut total = 0;
        let mut messages = 0;
        while total < want.len() {
            match peer.next().await.unwrap().unwrap() {
                Message::Binary(b) => {
                    assert!(b.len() <= MAX_WS_WRITE);
                    total += b.len();
                    messages += 1;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(total, want.len());
        assert!(messages >= 3, "{messages}");
        let _ = writer.await.unwrap();
    }

    #[tokio::test]
    async fn text_message_is_invalid_data() {
        let (mut s, mut peer) = pair().await;
        peer.send(Message::Text("nope".into())).await.unwrap();
        let mut buf = [0u8; 8];
        let err = s.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn oversize_message_errors() {
        let (mut s, mut peer) = pair().await;
        peer.send(Message::Binary(vec![0u8; WS_MAX_MESSAGE + 1]))
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let err = s.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn close_gives_eof() {
        let (mut s, mut peer) = pair().await;
        peer.send(Message::Binary(b"x".to_vec())).await.unwrap();
        peer.close(None).await.unwrap();
        let mut all = Vec::new();
        s.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"x");
        let mut buf = [0u8; 1];
        assert_eq!(s.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn shutdown_sends_close() {
        let (mut s, mut peer) = pair().await;
        s.shutdown().await.unwrap();
        assert!(matches!(peer.next().await, Some(Ok(Message::Close(_)))));
    }

    #[tokio::test]
    async fn pinned_tls_over_ws_round_trips() {
        use crate::{TlsVersions, connect_pinned_stream, pin_of_der, server_config_from_pem_with};
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pin = pin_of_der(cert.der());
        let acceptor = tokio_rustls::TlsAcceptor::from(
            server_config_from_pem_with(
                cert.pem().as_bytes(),
                key_pair.serialize_pem().as_bytes(),
                TlsVersions::Tls13Only,
            )
            .unwrap(),
        );
        let (a, b) = tokio::io::duplex(256 * 1024);
        let server_ws = WebSocketStream::from_raw_socket(a, Role::Server, Some(ws_config())).await;
        let client_ws = WebSocketStream::from_raw_socket(b, Role::Client, Some(ws_config())).await;
        let server = tokio::spawn(async move {
            let mut t = acceptor.accept(WsByteStream::new(server_ws)).await.unwrap();
            let mut buf = vec![0u8; 50_000];
            t.read_exact(&mut buf).await.unwrap();
            t.write_all(&buf).await.unwrap();
            t.flush().await.unwrap();
        });
        let mut c = connect_pinned_stream(
            "localhost",
            pin,
            WsByteStream::new(client_ws),
            TlsVersions::Tls13Only,
        )
        .await
        .unwrap();
        let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        c.write_all(&data).await.unwrap();
        c.flush().await.unwrap();
        let mut back = vec![0u8; data.len()];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(back, data);
        server.await.unwrap();
    }
}
