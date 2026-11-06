//! Multiplex loopback TCP streams over one authenticated connection.
//!
//! v1 backpressure is head-of-line on purpose: the reader does not pull
//! the next frame until the current [`FRAME_DATA`] has been queued for
//! its stream, and a full per-stream queue waits. A credit window would
//! be a new [`crate::WIRE_VERSION`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::frame::{Frame, FrameError, read_frame, write_frame};
use crate::{
    CLOSE_DIAL_FAILED, CLOSE_NORMAL, CLOSE_RESET, DIAL_TIMEOUT, DUPLEX_BYTES, MAX_STREAMS,
    OUTBOX_QUEUE, PING_INTERVAL, STREAM_QUEUE,
};

/// The byte stream the broker's CDP client reads and writes.
///
/// Dropping it closes the stream (the peer sees [`FRAME_CLOSE`]).
pub struct MuxIo {
    io: tokio::io::DuplexStream,
}

impl AsyncRead for MuxIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// The connection is gone.
    #[error("connector connection closed")]
    Closed,
    /// The agent could not dial its loopback CDP address.
    #[error("connector dial failed")]
    DialFailed,
    /// [`MAX_STREAMS`] is already in use.
    #[error("too many connector streams")]
    TooManyStreams,
}

/// Broker half of one authenticated connection.
#[derive(Clone)]
pub struct BrokerSession {
    inner: Arc<Inner>,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl BrokerSession {
    pub fn id(&self) -> u64 {
        self.inner.id
    }

    /// Open one stream. Resolves when the agent has dialed loopback CDP,
    /// or when the dial fails.
    pub async fn open_stream(&self) -> Result<MuxIo, OpenError> {
        if *self.inner.dead.borrow() {
            return Err(OpenError::Closed);
        }
        let id = self.inner.alloc_id()?;
        let (local, remote) = tokio::io::duplex(DUPLEX_BYTES);
        let (inbound_tx, inbound_rx) = mpsc::channel(STREAM_QUEUE);
        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let mut streams = self.inner.streams.lock().unwrap_or_else(|p| p.into_inner());
            streams.insert(
                id,
                Slot {
                    inbound: inbound_tx,
                    ack: Some(ack_tx),
                },
            );
        }
        let out = self.inner.out.clone();
        let pump = tokio::spawn(pump(remote, id, out.clone(), inbound_rx));
        self.inner.track_task(pump);
        if out.send(Frame::Open { id }).await.is_err() {
            self.inner.remove_stream(id);
            return Err(OpenError::Closed);
        }
        match tokio::time::timeout(DIAL_TIMEOUT, ack_rx).await {
            Ok(Ok(Ok(()))) => Ok(MuxIo { io: local }),
            Ok(Ok(Err(_))) => {
                self.inner.remove_stream(id);
                Err(OpenError::DialFailed)
            }
            _ => {
                let _ = out.try_send(Frame::Close {
                    id,
                    reason: CLOSE_RESET,
                });
                self.inner.remove_stream(id);
                Err(OpenError::DialFailed)
            }
        }
    }

    /// End the connection. In-flight streams fail.
    pub fn shutdown(&self) {
        self.inner.fail_all();
        if let Some(task) = self.task.lock().unwrap_or_else(|p| p.into_inner()).take() {
            task.abort();
        }
    }

    /// Resolves when the connection ends.
    pub async fn closed(&self) {
        let mut rx = self.inner.dead.clone();
        if *rx.borrow() {
            return;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }
}

/// Run the agent half until the connection ends. `cdp` must be loopback;
/// every [`FRAME_OPEN`] dials that address and no other.
pub async fn serve_agent<S>(stream: S, cdp: std::net::SocketAddr) -> Result<(), crate::ClientError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if !cdp.ip().is_loopback() || cdp.port() == 0 {
        return Err(crate::ClientError::CdpNotLoopback);
    }
    let (inner, task) = start(stream, Role::Agent { cdp });
    let _ = task.await;
    inner.fail_all();
    Ok(())
}

/// Broker half. The returned session can [`BrokerSession::open_stream`]
/// until the peer leaves or [`BrokerSession::shutdown`] is called.
pub fn spawn_broker<S>(stream: S) -> BrokerSession
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (inner, drive) = start(stream, Role::Broker);
    BrokerSession {
        inner,
        task: Arc::new(Mutex::new(Some(drive))),
    }
}

enum Role {
    Broker,
    Agent { cdp: std::net::SocketAddr },
}

struct Slot {
    inbound: mpsc::Sender<Vec<u8>>,
    /// Broker only: waiting for the agent's OPEN ack or CLOSE.
    ack: Option<oneshot::Sender<Result<(), u8>>>,
}

struct Inner {
    id: u64,
    out: mpsc::Sender<Frame>,
    streams: Mutex<HashMap<u32, Slot>>,
    next_stream: AtomicU32,
    dead_flag: AtomicBool,
    dead: watch::Receiver<bool>,
    dead_tx: watch::Sender<bool>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    role_cdp: Option<std::net::SocketAddr>,
}

impl Inner {
    fn alloc_id(&self) -> Result<u32, OpenError> {
        let streams = self.streams.lock().unwrap_or_else(|p| p.into_inner());
        if streams.len() >= MAX_STREAMS {
            return Err(OpenError::TooManyStreams);
        }
        let id = self.next_stream.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id == u32::MAX {
            return Err(OpenError::TooManyStreams);
        }
        Ok(id)
    }

    fn remove_stream(&self, id: u32) {
        self.streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
    }

    fn track_task(&self, task: JoinHandle<()>) {
        self.tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(task);
    }

    fn fail_all(&self) {
        if self
            .dead_flag
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let _ = self.dead_tx.send(true);
        let mut streams = self.streams.lock().unwrap_or_else(|p| p.into_inner());
        for (_, slot) in streams.drain() {
            if let Some(ack) = slot.ack {
                let _ = ack.send(Err(CLOSE_RESET));
            }
        }
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain(..)
        {
            task.abort();
        }
    }
}

fn start<S>(stream: S, role: Role) -> (Arc<Inner>, JoinHandle<()>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let (dead_tx, dead) = watch::channel(false);
    let (out_tx, out_rx) = mpsc::channel(OUTBOX_QUEUE);
    let cdp = match role {
        Role::Agent { cdp } => Some(cdp),
        Role::Broker => None,
    };
    let inner = Arc::new(Inner {
        id: NEXT.fetch_add(1, Ordering::Relaxed),
        out: out_tx,
        streams: Mutex::new(HashMap::new()),
        next_stream: AtomicU32::new(1),
        dead_flag: AtomicBool::new(false),
        dead,
        dead_tx,
        tasks: Mutex::new(Vec::new()),
        role_cdp: cdp,
    });
    let ping_tx = inner.out.clone();
    let ping = tokio::spawn(async move {
        let mut tick = tokio::time::interval(PING_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            if ping_tx.send(Frame::Ping).await.is_err() {
                break;
            }
        }
    });
    inner.track_task(ping);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let reader_inner = Arc::clone(&inner);
    let writer_inner = Arc::clone(&inner);
    let task = tokio::spawn(async move {
        let write = write_loop(writer_inner, &mut writer, out_rx);
        let read = read_loop(reader_inner, &mut reader);
        tokio::pin!(write);
        tokio::pin!(read);
        tokio::select! {
            _ = &mut write => {}
            _ = &mut read => {}
        }
    });
    (inner, task)
}

async fn write_loop<W>(inner: Arc<Inner>, writer: &mut W, mut rx: mpsc::Receiver<Frame>)
where
    W: AsyncWrite + Unpin,
{
    // One frame at a time, never `select`ed with another write: `write_all`
    // is not cancellation-safe. Pings arrive on `rx` from a side task.
    while let Some(frame) = rx.recv().await {
        if write_frame(writer, &frame).await.is_err() {
            break;
        }
    }
    inner.fail_all();
}

async fn read_loop<R>(inner: Arc<Inner>, reader: &mut R)
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = match read_frame(reader).await {
            Ok(frame) => frame,
            Err(_) => break,
        };
        if handle_frame(&inner, frame).await.is_err() {
            break;
        }
    }
    inner.fail_all();
}

async fn handle_frame(inner: &Arc<Inner>, frame: Frame) -> Result<(), FrameError> {
    match frame {
        Frame::Ping => {
            let _ = inner.out.try_send(Frame::Pong);
            Ok(())
        }
        Frame::Pong => Ok(()),
        Frame::Open { id } => on_open(inner, id).await,
        Frame::Data { id, payload } => {
            let tx = {
                let streams = inner.streams.lock().unwrap_or_else(|p| p.into_inner());
                streams.get(&id).map(|s| s.inbound.clone())
            };
            match tx {
                Some(tx) => {
                    // Head-of-line: wait until this stream accepts the bytes.
                    tx.send(payload).await.map_err(|_| FrameError::Eof)?;
                    Ok(())
                }
                None => {
                    let _ = inner.out.try_send(Frame::Close {
                        id,
                        reason: CLOSE_RESET,
                    });
                    Ok(())
                }
            }
        }
        Frame::Close { id, reason } => {
            if let Some(slot) = inner
                .streams
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id)
                && let Some(ack) = slot.ack
            {
                let _ = ack.send(Err(reason));
            }
            Ok(())
        }
    }
}

async fn on_open(inner: &Arc<Inner>, id: u32) -> Result<(), FrameError> {
    if let Some(cdp) = inner.role_cdp {
        // Agent: an OPEN is a dial request. A second OPEN for a live id is a bug.
        let exists = inner
            .streams
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(&id);
        if exists {
            return Err(FrameError::Protocol);
        }
        let dial_inner = Arc::clone(inner);
        let task = tokio::spawn(async move {
            dial(&dial_inner, id, cdp).await;
        });
        inner.track_task(task);
        return Ok(());
    }
    // Broker: an OPEN is the agent's ack.
    let ack = {
        let mut streams = inner.streams.lock().unwrap_or_else(|p| p.into_inner());
        streams.get_mut(&id).and_then(|s| s.ack.take())
    };
    match ack {
        Some(ack) => {
            let _ = ack.send(Ok(()));
            Ok(())
        }
        None => Err(FrameError::Protocol),
    }
}

async fn dial(inner: &Arc<Inner>, id: u32, cdp: std::net::SocketAddr) {
    let stream = match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(cdp)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            let _ = inner
                .out
                .send(Frame::Close {
                    id,
                    reason: CLOSE_DIAL_FAILED,
                })
                .await;
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    let (local, remote) = tokio::io::duplex(DUPLEX_BYTES);
    let (inbound_tx, inbound_rx) = mpsc::channel(STREAM_QUEUE);
    {
        let mut streams = inner.streams.lock().unwrap_or_else(|p| p.into_inner());
        streams.insert(
            id,
            Slot {
                inbound: inbound_tx,
                ack: None,
            },
        );
    }
    let pump = tokio::spawn(pump(remote, id, inner.out.clone(), inbound_rx));
    if inner.out.send(Frame::Open { id }).await.is_err() {
        pump.abort();
        inner.remove_stream(id);
        return;
    }
    let mut tcp = stream;
    let mut local = local;
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut local).await;
    pump.abort();
    inner.remove_stream(id);
    let _ = inner
        .out
        .send(Frame::Close {
            id,
            reason: CLOSE_NORMAL,
        })
        .await;
}

/// Move bytes between one duplex half and the frame connection.
///
/// `read` (not `read_exact`) is cancellation-safe, so `select!` does not
/// drop a partial frame. Frames themselves are read only on the connection
/// reader task.
async fn pump(
    mut io: tokio::io::DuplexStream,
    id: u32,
    out: mpsc::Sender<Frame>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
) {
    let mut buf = vec![0u8; crate::MAX_PAYLOAD];
    loop {
        tokio::select! {
            read = io.read(&mut buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.send(Frame::Data { id, payload: buf[..n].to_vec() }).await.is_err() {
                            break;
                        }
                    }
                }
            }
            msg = inbound.recv() => {
                match msg {
                    Some(bytes) => {
                        if io.write_all(&bytes).await.is_err() || io.flush().await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    let _ = out
        .send(Frame::Close {
            id,
            reason: CLOSE_NORMAL,
        })
        .await;
}
