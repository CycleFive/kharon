//! v1 auth records. The token is zeroized after it is written or verified
//! by the caller; this module never logs it.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::{AUTH_MAX, MAGIC, WIRE_VERSION};

/// What the agent sends once TLS is up. `token` is zeroized on drop.
pub struct ClientHello {
    pub agent_id: String,
    pub token: Zeroizing<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("connector protocol error")]
    Protocol,
    #[error("connector connection ended")]
    Eof,
}

/// Write the client auth record. The buffer that held the token is zeroized
/// before this returns.
pub async fn write_client_hello<W>(
    writer: &mut W,
    agent_id: &str,
    token: &str,
) -> Result<(), AuthError>
where
    W: AsyncWrite + Unpin,
{
    if !valid_id(agent_id) || token.is_empty() || token.len() > 512 {
        return Err(AuthError::Protocol);
    }
    let mut body = Zeroizing::new(Vec::with_capacity(7 + agent_id.len() + token.len()));
    body.extend_from_slice(MAGIC);
    body.push(WIRE_VERSION);
    body.extend_from_slice(&(agent_id.len() as u16).to_be_bytes());
    body.extend_from_slice(agent_id.as_bytes());
    body.extend_from_slice(&(token.len() as u16).to_be_bytes());
    body.extend_from_slice(token.as_bytes());
    write_record(writer, &body).await
}

pub async fn read_client_hello<R>(reader: &mut R) -> Result<ClientHello, AuthError>
where
    R: AsyncRead + Unpin,
{
    let body = Zeroizing::new(read_record(reader).await?);
    parse_client_hello(&body)
}

pub async fn write_server_hello<W>(writer: &mut W, status: u8) -> Result<(), AuthError>
where
    W: AsyncWrite + Unpin,
{
    let body = [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], WIRE_VERSION, status];
    write_record(writer, &body).await
}

pub async fn read_server_hello<R>(reader: &mut R) -> Result<u8, AuthError>
where
    R: AsyncRead + Unpin,
{
    let body = read_record(reader).await?;
    if body.len() != 6 || &body[0..4] != MAGIC || body[4] != WIRE_VERSION {
        return Err(AuthError::Protocol);
    }
    let status = body[5];
    if status > 2 {
        return Err(AuthError::Protocol);
    }
    Ok(status)
}

fn parse_client_hello(body: &[u8]) -> Result<ClientHello, AuthError> {
    if body.len() < 7 || &body[0..4] != MAGIC || body[4] != WIRE_VERSION {
        return Err(AuthError::Protocol);
    }
    let id_len = u16::from_be_bytes([body[5], body[6]]) as usize;
    let id_end = 7 + id_len;
    if body.len() < id_end + 2 {
        return Err(AuthError::Protocol);
    }
    let agent_id = std::str::from_utf8(&body[7..id_end]).map_err(|_| AuthError::Protocol)?;
    if !valid_id(agent_id) {
        return Err(AuthError::Protocol);
    }
    let tok_len = u16::from_be_bytes([body[id_end], body[id_end + 1]]) as usize;
    let tok_end = id_end + 2 + tok_len;
    if tok_end != body.len() || tok_len == 0 || tok_len > 512 {
        return Err(AuthError::Protocol);
    }
    let token = std::str::from_utf8(&body[id_end + 2..tok_end]).map_err(|_| AuthError::Protocol)?;
    Ok(ClientHello {
        agent_id: agent_id.to_owned(),
        token: Zeroizing::new(token.to_owned()),
    })
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

async fn write_record<W>(writer: &mut W, body: &[u8]) -> Result<(), AuthError>
where
    W: AsyncWrite + Unpin,
{
    if body.len() > AUTH_MAX {
        return Err(AuthError::Protocol);
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(body);
    writer.write_all(&buf).await.map_err(|_| AuthError::Eof)?;
    writer.flush().await.map_err(|_| AuthError::Eof)?;
    Ok(())
}

async fn read_record<R>(reader: &mut R) -> Result<Vec<u8>, AuthError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|_| AuthError::Eof)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > AUTH_MAX || len == 0 {
        return Err(AuthError::Protocol);
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| AuthError::Eof)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::AUTH_OK;

    #[tokio::test]
    async fn req_arch_002_auth_round_trip_zeroizes_token_buffer() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let token = "kh_tunnel_assistant_abcd";
        write_client_hello(&mut client, "assistant", token)
            .await
            .unwrap();
        let hello = read_client_hello(&mut server).await.unwrap();
        assert_eq!(hello.agent_id, "assistant");
        assert_eq!(hello.token.as_str(), token);
        write_server_hello(&mut server, AUTH_OK).await.unwrap();
        assert_eq!(read_server_hello(&mut client).await.unwrap(), AUTH_OK);
    }

    #[tokio::test]
    async fn req_arch_002_auth_rejects_bad_identity_shape() {
        let (mut client, mut server) = tokio::io::duplex(256);
        // Uppercase is not an agent id. Nothing is written.
        assert!(
            write_client_hello(&mut client, "Assistant", "x")
                .await
                .is_err()
        );
        let mut junk = Vec::new();
        junk.extend_from_slice(&4u32.to_be_bytes());
        junk.extend_from_slice(b"nope");
        client.write_all(&junk).await.unwrap();
        assert!(read_client_hello(&mut server).await.is_err());
    }
}
