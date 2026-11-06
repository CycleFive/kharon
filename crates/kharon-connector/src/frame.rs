//! v1 frames. See the crate docs for the layout.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    CLOSE_DIAL_FAILED, CLOSE_NORMAL, CLOSE_RESET, FRAME_CLOSE, FRAME_DATA, FRAME_OPEN, FRAME_PING,
    FRAME_PONG, IDLE_TIMEOUT, MAX_PAYLOAD,
};

/// One decoded frame. Payloads are owned so the read buffer can be reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Broker → agent: dial the configured loopback CDP. Payload empty.
    /// Agent → broker: dial succeeded. Payload empty.
    Open {
        id: u32,
    },
    Data {
        id: u32,
        payload: Vec<u8>,
    },
    Close {
        id: u32,
        reason: u8,
    },
    Ping,
    Pong,
}

impl Frame {
    pub fn id(&self) -> u32 {
        match self {
            Self::Open { id } | Self::Data { id, .. } | Self::Close { id, .. } => *id,
            Self::Ping | Self::Pong => 0,
        }
    }
}

/// Encode one frame. Returns [`None`] when the payload exceeds [`MAX_PAYLOAD`].
pub fn encode_frame(frame: &Frame) -> Option<Vec<u8>> {
    let (typ, id, payload): (u8, u32, &[u8]) = match frame {
        Frame::Open { id } => (FRAME_OPEN, *id, &[]),
        Frame::Data { id, payload } => (FRAME_DATA, *id, payload),
        Frame::Close { id, reason } => (FRAME_CLOSE, *id, std::slice::from_ref(reason)),
        Frame::Ping => (FRAME_PING, 0, &[]),
        Frame::Pong => (FRAME_PONG, 0, &[]),
    };
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(typ);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

pub(crate) fn parse_frame(typ: u8, id: u32, payload: Vec<u8>) -> Result<Frame, FrameError> {
    match typ {
        FRAME_OPEN => {
            if payload.is_empty() && id != 0 {
                Ok(Frame::Open { id })
            } else {
                // Non-empty OPEN is the pivot refusal: the dial target is
                // not on the wire in v1. Id 0 is reserved.
                Err(FrameError::Protocol)
            }
        }
        FRAME_DATA if id != 0 && payload.len() <= MAX_PAYLOAD => Ok(Frame::Data { id, payload }),
        FRAME_CLOSE if id != 0 && payload.len() == 1 && is_reason(payload[0]) => Ok(Frame::Close {
            id,
            reason: payload[0],
        }),
        FRAME_PING if id == 0 && payload.is_empty() => Ok(Frame::Ping),
        FRAME_PONG if id == 0 && payload.is_empty() => Ok(Frame::Pong),
        _ => Err(FrameError::Protocol),
    }
}

fn is_reason(r: u8) -> bool {
    matches!(r, CLOSE_NORMAL | CLOSE_DIAL_FAILED | CLOSE_RESET)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FrameError {
    #[error("connector protocol error")]
    Protocol,
    #[error("connector connection ended")]
    Eof,
    #[error("connector idle timeout")]
    Idle,
}

pub(crate) async fn read_frame<R>(reader: &mut R) -> Result<Frame, FrameError>
where
    R: AsyncRead + Unpin,
{
    let mut hdr = [0u8; 9];
    read_exact_idle(reader, &mut hdr).await?;
    let typ = hdr[0];
    let id = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(FrameError::Protocol);
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        read_exact_idle(reader, &mut payload).await?;
    }
    parse_frame(typ, id, payload)
}

async fn read_exact_idle<R>(reader: &mut R, buf: &mut [u8]) -> Result<(), FrameError>
where
    R: AsyncRead + Unpin,
{
    match tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(FrameError::Eof),
        Ok(Err(_)) => Err(FrameError::Eof),
        Err(_) => Err(FrameError::Idle),
    }
}

pub(crate) async fn write_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = encode_frame(frame).ok_or(FrameError::Protocol)?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| FrameError::Eof)?;
    writer.flush().await.map_err(|_| FrameError::Eof)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_arch_002_frame_round_trip_and_limits() {
        let samples = [
            Frame::Open { id: 1 },
            Frame::Data {
                id: 7,
                payload: b"cdp".to_vec(),
            },
            Frame::Close {
                id: 7,
                reason: CLOSE_DIAL_FAILED,
            },
            Frame::Ping,
            Frame::Pong,
        ];
        for frame in samples {
            let bytes = encode_frame(&frame).unwrap();
            let typ = bytes[0];
            let id = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
            let len = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
            let payload = bytes[9..].to_vec();
            assert_eq!(payload.len(), len);
            assert_eq!(parse_frame(typ, id, payload).unwrap(), frame);
        }
        assert!(
            encode_frame(&Frame::Data {
                id: 1,
                payload: vec![0; MAX_PAYLOAD + 1],
            })
            .is_none()
        );
        // A non-empty OPEN is refused: v1 has no broker-supplied dial target.
        assert_eq!(
            parse_frame(FRAME_OPEN, 1, b"127.0.0.1:9222".to_vec()),
            Err(FrameError::Protocol)
        );
        assert_eq!(
            parse_frame(FRAME_OPEN, 0, Vec::new()),
            Err(FrameError::Protocol)
        );
    }
}
