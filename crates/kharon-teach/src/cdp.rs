//! A small Chrome DevTools Protocol client over a loopback WebSocket that makes
//! calls and receives events.
//!
//! Everything arriving on this socket may contain what a person typed into a
//! login page. Nothing from a frame reaches an error message, a log line or a
//! `Debug` output: errors are built from fixed words and numbers only.

use crate::browser::DevTools;
use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};

const MAX_REMOTE_MESSAGE_CHARS: usize = 200;
/// CDP frames that carry request bodies can be large.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CdpError {
    #[error("cdp connection closed")]
    Closed,
    #[error("cdp error {code}: {message}")]
    Remote { code: i64, message: String },
    #[error("cdp transport: {0}")]
    Transport(String),
    #[error("cdp reply did not parse ({category} at line {line} column {column})")]
    Parse {
        category: &'static str,
        line: usize,
        column: usize,
    },
}

impl From<serde_json::Error> for CdpError {
    /// Keeps the error's category and position only: its message can quote
    /// the offending value.
    fn from(e: serde_json::Error) -> Self {
        use serde_json::error::Category;
        let category = match e.classify() {
            Category::Io => "io",
            Category::Syntax => "syntax",
            Category::Data => "data",
            Category::Eof => "eof",
        };
        CdpError::Parse {
            category,
            line: e.line(),
            column: e.column(),
        }
    }
}

/// Parse browser-derived JSON without ever letting the serde error text (which
/// can quote the offending value) out.
pub fn parse_quiet<T: DeserializeOwned>(raw: &str) -> Result<T, CdpError> {
    serde_json::from_str(raw).map_err(CdpError::from)
}

/// An event pushed by the browser. No `Debug`: `params` can hold page data.
pub struct Event {
    pub method: String,
    pub session_id: Option<String>,
    pub params: Box<RawValue>,
}

/// What we send. Typed, never `json!`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Outgoing<'a, P: Serialize> {
    id: u64,
    method: &'a str,
    params: &'a P,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
}

/// Anything the browser sends: a reply (`id`) or an event (`method`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Incoming {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    params: Option<Box<RawValue>>,
    #[serde(default)]
    result: Option<Box<RawValue>>,
    #[serde(default)]
    error: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
struct WireError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

type Reply = Result<Box<RawValue>, CdpError>;

#[derive(Default)]
struct State {
    pending: HashMap<u64, oneshot::Sender<Reply>>,
    closed: bool,
}

struct Shared {
    state: Mutex<State>,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Mark closed and drop every waiter: their receivers see `Closed`.
    fn close(&self) {
        let mut st = self.lock();
        st.closed = true;
        st.pending.clear();
    }
}

struct Inner {
    shared: Arc<Shared>,
    next_id: AtomicU64,
    /// When the last clone drops, this closes, the task ends and the socket closes.
    out: UnboundedSender<String>,
}

#[derive(Clone)]
pub struct Cdp {
    inner: Arc<Inner>,
}

fn transport(e: &tungstenite::Error) -> CdpError {
    use tungstenite::Error as E;
    let words = match e {
        E::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => "connection refused",
        E::Io(_) => "io error",
        E::Url(_) => "bad url",
        E::Http(_) | E::HttpFormat(_) => "handshake failed",
        E::ConnectionClosed | E::AlreadyClosed => "connection closed",
        _ => "protocol error",
    };
    CdpError::Transport(words.to_owned())
}

impl Cdp {
    /// Dials ws://127.0.0.1:<port><ws_path>. The host is a constant.
    pub async fn connect(dev: &DevTools) -> Result<(Cdp, UnboundedReceiver<Event>), CdpError> {
        if !dev.ws_path.starts_with("/devtools/")
            || dev.ws_path.chars().any(|c| c.is_control() || c == ' ')
        {
            return Err(CdpError::Transport("bad websocket path".to_owned()));
        }
        let url = format!("ws://127.0.0.1:{}{}", dev.port, dev.ws_path);
        let config = WebSocketConfig {
            max_message_size: Some(MAX_FRAME_BYTES),
            max_frame_size: Some(MAX_FRAME_BYTES),
            ..WebSocketConfig::default()
        };
        let (ws, _resp) = connect_async_with_config(url, Some(config), false)
            .await
            .map_err(|e| transport(&e))?;

        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
        });
        let (out, out_rx) = unbounded_channel();
        let (ev_tx, ev_rx) = unbounded_channel();
        tokio::spawn(run(ws, out_rx, Arc::clone(&shared), ev_tx));
        let cdp = Cdp {
            inner: Arc::new(Inner {
                shared,
                next_id: AtomicU64::new(1),
                out,
            }),
        };
        Ok((cdp, ev_rx))
    }

    pub async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
        session_id: Option<&str>,
    ) -> Result<R, CdpError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = serde_json::to_string(&Outgoing {
            id,
            method,
            params,
            session_id,
        })
        // The serde message could quote a value; say only that it failed.
        .map_err(|_| CdpError::Transport("could not encode call".to_owned()))?;

        let (tx, rx) = oneshot::channel();
        {
            let mut st = self.inner.shared.lock();
            if st.closed {
                return Err(CdpError::Closed);
            }
            st.pending.insert(id, tx);
        }
        if self.inner.out.send(frame).is_err() {
            self.inner.shared.lock().pending.remove(&id);
            return Err(CdpError::Closed);
        }
        let raw = rx.await.map_err(|_| CdpError::Closed)??;
        parse_quiet(raw.get())
    }
}

/// The one task: reads frames, routes them, and writes queued calls.
async fn run(
    mut ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    mut out: UnboundedReceiver<String>,
    shared: Arc<Shared>,
    events: UnboundedSender<Event>,
) {
    loop {
        tokio::select! {
            msg = ws.next() => match msg {
                Some(Ok(Message::Text(t))) => route(&t, &shared, &events),
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                // Binary, ping, pong: dropped.
                Some(Ok(_)) => {}
            },
            queued = out.recv() => match queued {
                Some(text) => {
                    if ws.send(Message::Text(text)).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    shared.close();
    let _ = tokio::time::timeout(Duration::from_millis(500), ws.close(None)).await;
}

/// A frame that does not parse is dropped silently (never logged).
fn route(text: &str, shared: &Shared, events: &UnboundedSender<Event>) {
    let Ok(m) = serde_json::from_str::<Incoming>(text) else {
        return;
    };
    if let Some(id) = m.id {
        let Some(waiter) = shared.lock().pending.remove(&id) else {
            return; // matches no pending call
        };
        let reply = match (m.error, m.result) {
            (Some(raw), _) => {
                let w = parse_quiet::<WireError>(raw.get()).unwrap_or(WireError {
                    code: 0,
                    message: String::new(),
                });
                Err(CdpError::Remote {
                    code: w.code,
                    message: w.message.chars().take(MAX_REMOTE_MESSAGE_CHARS).collect(),
                })
            }
            (None, Some(result)) => Ok(result),
            (None, None) => RawValue::from_string("{}".to_owned())
                .map_err(|_| CdpError::Transport("protocol error".to_owned())),
        };
        let _ = waiter.send(reply);
    } else if let Some(method) = m.method {
        let params = match m.params {
            Some(p) => p,
            None => match RawValue::from_string("{}".to_owned()) {
                Ok(p) => p,
                Err(_) => return,
            },
        };
        let _ = events.send(Event {
            method,
            session_id: m.session_id,
            params,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Empty, FrameNavigated};
    use futures_util::{SinkExt, StreamExt};
    use serde::Deserialize;
    use std::future::Future;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};

    type Ws = WebSocketStream<TcpStream>;
    const T: Duration = Duration::from_secs(5);

    /// Serve one connection with `f`; returns the DevTools to dial and the
    /// server task's handle.
    async fn serve<F, Fut, O>(f: F) -> (DevTools, JoinHandle<O>)
    where
        F: FnOnce(Ws) -> Fut + Send + 'static,
        Fut: Future<Output = O> + Send + 'static,
        O: Send + 'static,
    {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            f(accept_async(s).await.unwrap()).await
        });
        (
            DevTools {
                port,
                ws_path: "/devtools/browser/test".to_owned(),
            },
            h,
        )
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Sent {
        id: u64,
        method: String,
        #[serde(default)]
        session_id: Option<String>,
    }

    async fn next_text(ws: &mut Ws) -> String {
        loop {
            match timeout(T, ws.next()).await.unwrap() {
                Some(Ok(Message::Text(t))) => return t,
                Some(Ok(_)) => continue,
                other => panic!("server expected a text frame, got end: {}", other.is_none()),
            }
        }
    }

    #[derive(Deserialize)]
    struct Reply {
        v: String,
    }

    #[tokio::test]
    async fn a_call_gets_its_own_reply() {
        let (dev, srv) = serve(|mut ws| async move {
            let a: Sent = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            let b: Sent = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            for s in [b, a] {
                let reply = format!(r#"{{"id":{},"result":{{"v":"{}"}}}}"#, s.id, s.method);
                ws.send(Message::Text(reply)).await.unwrap();
            }
            ws
        })
        .await;
        let (cdp, _rx) = Cdp::connect(&dev).await.unwrap();
        let (ra, rb) = timeout(T, async {
            tokio::join!(
                cdp.call::<_, Reply>("A.first", &Empty {}, None),
                cdp.call::<_, Reply>("B.second", &Empty {}, None)
            )
        })
        .await
        .unwrap();
        assert_eq!(ra.unwrap().v, "A.first");
        assert_eq!(rb.unwrap().v, "B.second");
        drop(srv);
    }

    #[tokio::test]
    async fn a_remote_error_is_returned() {
        let (dev, _srv) = serve(|mut ws| async move {
            let s: Sent = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            let long = "n".repeat(500);
            let r = format!(
                r#"{{"id":{},"error":{{"code":-32000,"message":"{long}"}}}}"#,
                s.id
            );
            ws.send(Message::Text(r)).await.unwrap();
            ws
        })
        .await;
        let (cdp, _rx) = Cdp::connect(&dev).await.unwrap();
        let r = timeout(T, cdp.call::<_, Empty2>("X.y", &Empty {}, None))
            .await
            .unwrap();
        match r {
            Err(CdpError::Remote { code, message }) => {
                assert_eq!(code, -32000);
                assert_eq!(message.chars().count(), 200);
            }
            _ => panic!("expected Remote"),
        }
    }

    #[derive(Deserialize)]
    struct Empty2 {}

    #[tokio::test]
    async fn a_short_remote_message_is_kept_whole() {
        let (dev, _srv) = serve(|mut ws| async move {
            let s: Sent = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            let r = format!(
                r#"{{"id":{},"error":{{"code":-32601,"message":"nope"}}}}"#,
                s.id
            );
            ws.send(Message::Text(r)).await.unwrap();
            ws
        })
        .await;
        let (cdp, _rx) = Cdp::connect(&dev).await.unwrap();
        let r = timeout(T, cdp.call::<_, Empty2>("X.y", &Empty {}, None))
            .await
            .unwrap();
        assert!(
            matches!(r, Err(CdpError::Remote { code: -32601, ref message }) if message == "nope")
        );
    }

    #[tokio::test]
    async fn events_are_delivered_with_their_session() {
        let (dev, _srv) = serve(|mut ws| async move {
            let ev = r#"{"method":"Page.frameNavigated","sessionId":"S1","params":{"frame":{"id":"F","url":"https://a.test/","extra":1}}}"#;
            ws.send(Message::Text(ev.to_owned())).await.unwrap();
            let ev2 = r#"{"method":"Target.targetDestroyed","params":{"targetId":"T"}}"#;
            ws.send(Message::Text(ev2.to_owned())).await.unwrap();
            ws
        })
        .await;
        let (_cdp, mut rx) = Cdp::connect(&dev).await.unwrap();
        let e = timeout(T, rx.recv()).await.unwrap().unwrap();
        assert_eq!(e.method, "Page.frameNavigated");
        assert_eq!(e.session_id.as_deref(), Some("S1"));
        let f: FrameNavigated = parse_quiet(e.params.get()).unwrap();
        assert_eq!(
            (f.frame.id.as_str(), f.frame.url.as_str()),
            ("F", "https://a.test/")
        );
        assert!(f.frame.parent_id.is_none());
        let e = timeout(T, rx.recv()).await.unwrap().unwrap();
        assert_eq!(e.method, "Target.targetDestroyed");
        assert!(e.session_id.is_none());
    }

    #[tokio::test]
    async fn session_id_is_sent_at_top_level() {
        let (dev, srv) = serve(|mut ws| async move {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let t = next_text(&mut ws).await;
                let s: Sent = serde_json::from_str(&t).unwrap();
                ws.send(Message::Text(format!(r#"{{"id":{},"result":{{}}}}"#, s.id)))
                    .await
                    .unwrap();
                seen.push(t);
            }
            (seen, ws)
        })
        .await;
        let (cdp, _rx) = Cdp::connect(&dev).await.unwrap();
        timeout(
            T,
            cdp.call::<_, Empty2>("Runtime.enable", &Empty {}, Some("S1")),
        )
        .await
        .unwrap()
        .unwrap();
        timeout(
            T,
            cdp.call::<_, Empty2>("Browser.getVersion", &Empty {}, None),
        )
        .await
        .unwrap()
        .unwrap();
        let (seen, _ws) = timeout(T, srv).await.unwrap().unwrap();
        let first: Sent = serde_json::from_str(&seen[0]).unwrap();
        assert_eq!(first.id, 1);
        assert_eq!(first.session_id.as_deref(), Some("S1"));
        assert!(seen[0].contains(r#""params":{}"#));
        let second: Sent = serde_json::from_str(&seen[1]).unwrap();
        assert_eq!(second.id, 2);
        assert!(second.session_id.is_none());
        assert!(!seen[1].contains("sessionId"));
    }

    #[tokio::test]
    async fn calls_fail_after_the_socket_closes() {
        let (dev, _srv) = serve(|mut ws| async move {
            // Read the first call, then close without answering.
            let _ = next_text(&mut ws).await;
            let _ = ws.close(None).await;
        })
        .await;
        let (cdp, mut rx) = Cdp::connect(&dev).await.unwrap();
        // The pending call fails.
        let r = timeout(T, cdp.call::<_, Empty2>("A.a", &Empty {}, None))
            .await
            .unwrap();
        assert!(matches!(r, Err(CdpError::Closed)));
        // A later call fails too, without hanging.
        let r = timeout(T, cdp.call::<_, Empty2>("A.b", &Empty {}, None))
            .await
            .unwrap();
        assert!(matches!(r, Err(CdpError::Closed)));
        // The event channel ends.
        assert!(timeout(T, rx.recv()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn stray_replies_and_junk_frames_are_dropped_silently() {
        let (dev, _srv) = serve(|mut ws| async move {
            let s: Sent = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            ws.send(Message::Text(
                r#"{"id":999,"result":{"v":"stray"}}"#.to_owned(),
            ))
            .await
            .unwrap();
            ws.send(Message::Text("not json at all {{".to_owned()))
                .await
                .unwrap();
            ws.send(Message::Binary(vec![1, 2, 3])).await.unwrap();
            ws.send(Message::Text(format!(
                r#"{{"id":{},"result":{{"v":"ok"}}}}"#,
                s.id
            )))
            .await
            .unwrap();
            ws
        })
        .await;
        let (cdp, mut rx) = Cdp::connect(&dev).await.unwrap();
        let r = timeout(T, cdp.call::<_, Reply>("A.a", &Empty {}, None))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r.v, "ok");
        assert!(rx.try_recv().is_err(), "junk must not surface as an event");
    }

    #[tokio::test]
    async fn dropping_the_last_clone_closes_the_socket() {
        let (dev, srv) = serve(|mut ws| async move {
            loop {
                match ws.next().await {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await;
        let (cdp, rx) = Cdp::connect(&dev).await.unwrap();
        let other = cdp.clone();
        drop(cdp);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!srv.is_finished(), "one clone is still alive");
        drop(other);
        drop(rx);
        timeout(T, srv).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_bad_ws_path_is_refused() {
        for bad in [
            "",
            "/json/version",
            "devtools/x",
            "/devtools/\r\nHost: evil",
            "//evil/devtools/x",
        ] {
            let dev = DevTools {
                port: 1,
                ws_path: bad.to_owned(),
            };
            match Cdp::connect(&dev).await {
                Err(CdpError::Transport(_)) => {}
                _ => panic!("expected Transport for {bad:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_refused_connection_is_a_transport_error_in_fixed_words() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let dev = DevTools {
            port,
            ws_path: "/devtools/browser/x".to_owned(),
        };
        match Cdp::connect(&dev).await {
            Err(CdpError::Transport(w)) => assert_eq!(w, "connection refused"),
            _ => panic!("expected Transport"),
        }
    }

    #[test]
    fn a_parse_error_never_carries_the_value() {
        #[derive(Debug, Deserialize)]
        struct Wants {
            #[allow(dead_code)]
            value: u32,
        }
        let e = parse_quiet::<Wants>(r#"{"value": "Tr0ub4dor-9x"}"#)
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(
            e,
            CdpError::Parse {
                category: "data",
                ..
            }
        ));
        assert!(!e.to_string().contains("Tr0ub4dor-9x"));
        assert!(!format!("{e:?}").contains("Tr0ub4dor-9x"));
        let e = parse_quiet::<Wants>(r#"{"value": 1"#)
            .map(|_| ())
            .unwrap_err();
        assert!(matches!(
            e,
            CdpError::Parse {
                category: "eof",
                ..
            }
        ));
    }
}
