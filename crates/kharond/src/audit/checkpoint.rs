//! Signed checkpoints and the sink through which they leave the host
//! (REQ-AUD-002).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;

use super::keys::AuditKeys;

/// `{seq, hash, log_id}` of the log head, signed with the audit Ed25519 key
/// over the JCS canonicalization of that triple. `log_id` binds the
/// checkpoint to one deployment: a checkpoint from another log sharing the
/// same key can never satisfy truncation detection here.
///
/// The checkpoint stream lives off-host; truncation of the local log is
/// detected by comparing the local head against the highest signed
/// checkpoint (REQ-AUD-002).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub seq: u64,
    pub hash: String,
    /// Instance id of the log this checkpoint attests (entry `log_id`).
    pub log_id: String,
    /// Hex-encoded Ed25519 signature over `JCS({seq, hash, log_id})`.
    pub sig: String,
}

impl Checkpoint {
    pub fn new(seq: u64, hash: String, keys: &AuditKeys) -> Self {
        let sig = keys.sign(&payload_jcs(seq, &hash, keys.log_id()));
        Self {
            seq,
            hash,
            log_id: keys.log_id().to_string(),
            sig: hex::encode(sig.to_bytes()),
        }
    }

    pub fn verify_signature(&self, vk: &VerifyingKey) -> bool {
        let Ok(bytes) = hex::decode(&self.sig) else {
            return false;
        };
        let Ok(sig) = Signature::try_from(bytes.as_slice()) else {
            return false;
        };
        vk.verify(&payload_jcs(self.seq, &self.hash, &self.log_id), &sig)
            .is_ok()
    }
}

fn payload_jcs(seq: u64, hash: &str, log_id: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct Payload<'a> {
        seq: u64,
        hash: &'a str,
        log_id: &'a str,
    }
    serde_jcs::to_vec(&Payload { seq, hash, log_id })
        .expect("JCS of a u64 and two strings cannot fail")
}

#[cfg(test)]
impl Checkpoint {
    /// Sign a checkpoint for an explicit (possibly foreign) `log_id`, to test
    /// cross-deployment replay rejection.
    pub(crate) fn new_with_log_id(seq: u64, hash: String, log_id: &str, keys: &AuditKeys) -> Self {
        let sig = keys.sign(&payload_jcs(seq, &hash, log_id));
        Self {
            seq,
            hash,
            log_id: log_id.to_string(),
            sig: hex::encode(sig.to_bytes()),
        }
    }
}

/// Where checkpoints go. Production pushes off-host with
/// [`NtfyCheckpointSink`] (REQ-AUD-002); explicit local-only runs use
/// [`FileCheckpointSink`]. `Send` so the daemon can share the log
/// between tasks behind a mutex (the agent API, #14).
pub trait CheckpointSink: Send {
    fn push(&mut self, cp: &Checkpoint) -> io::Result<()>;
}

/// Discards checkpoints. Only for tests that do not exercise truncation
/// detection, and for deployments that explicitly accept the risk.
pub struct NullCheckpointSink;

impl CheckpointSink for NullCheckpointSink {
    fn push(&mut self, _cp: &Checkpoint) -> io::Result<()> {
        Ok(())
    }
}

/// Appends checkpoints as JSONL to a file — the stand-in for "off-host" in
/// tests and single-host deployments.
pub struct FileCheckpointSink {
    file: File,
}

impl FileCheckpointSink {
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file })
    }
}

impl CheckpointSink for FileCheckpointSink {
    fn push(&mut self, cp: &Checkpoint) -> io::Result<()> {
        let line = serde_json::to_string(cp)?;
        writeln!(self.file, "{line}")?;
        self.file.sync_all()
    }
}

/// The synchronous ntfy publish transport shared by the checkpoint
/// sink (REQ-AUD-002, #127) and the approval-prompt publisher
/// (REQ-APR-004, #128): a minimal synchronous HTTP/1.1 POST — plain
/// TCP for `http`, rustls (OS roots, no client auth, mirroring the
/// sync client's trust setup) for `https` — because its callers run
/// from both blocking and async contexts, where an async client
/// runtime cannot be assumed. Redirects are never followed: a
/// redirect could carry the ntfy token to another host.
///
/// Fail-closed setup: construction reads the token file eagerly, so a
/// deployment that configured a token it cannot read refuses to start
/// instead of silently publishing unauthenticated (or not at all).
pub(crate) struct NtfyTransport {
    /// `http` or `https`.
    scheme: String,
    host: String,
    port: u16,
    /// The base URL's path prefix (`""` or `"/…"`), no trailing slash.
    prefix: String,
    token: Option<zeroize::Zeroizing<String>>,
}

/// How long a single ntfy publish may take before it is a failure
/// (the checkpoint cadence retries; see `AuditLog::emit_checkpoint`).
const NTFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// ntfy's topic charset, shared by every publisher on the channel.
pub(crate) fn validate_ntfy_topic(topic: &str) -> io::Result<()> {
    if topic.is_empty()
        || !topic
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ntfy topic is empty or has characters outside [A-Za-z0-9._-]",
        ));
    }
    Ok(())
}

impl NtfyTransport {
    /// Build a transport for the ntfy server at `base`, reading the
    /// bearer token from `token_file` when one is configured.
    pub(crate) fn new(base: &url::Url, token_file: Option<&Path>) -> io::Result<Self> {
        let scheme = base.scheme();
        if !matches!(scheme, "http" | "https") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ntfy transport needs an http(s) base URL",
            ));
        }
        let host = base
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ntfy URL has no host"))?
            .to_string();
        let port = base
            .port_or_known_default()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ntfy URL has no port"))?;
        let token = match token_file {
            Some(p) => {
                let raw = std::fs::read_to_string(p)?;
                let trimmed = raw.trim().to_string();
                if trimmed.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ntfy token file is empty",
                    ));
                }
                Some(zeroize::Zeroizing::new(trimmed))
            }
            None => None,
        };
        Ok(Self {
            scheme: scheme.to_string(),
            host,
            port,
            prefix: base.path().trim_end_matches('/').to_string(),
            token,
        })
    }

    /// The base URL's path prefix (`""` or `"/…"`).
    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }

    /// POST `body` (JSON) to `path` on the ntfy server. `title`, when
    /// given, goes out as the `X-Title` header (the plain-publish
    /// shape; JSON-publish callers carry the title in the body and
    /// pass `None`).
    pub(crate) fn post(&self, path: &str, title: Option<&str>, body: &str) -> io::Result<()> {
        let mut request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: kharond\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            path,
            self.host,
            body.len()
        );
        if let Some(title) = title {
            request.push_str(&format!("X-Title: {title}\r\n"));
        }
        if let Some(token) = &self.token {
            request.push_str(&format!("Authorization: Bearer {}\r\n", token.as_str()));
        }
        request.push_str("\r\n");
        request.push_str(body);

        let addr = (self.host.as_str(), self.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ntfy host did not resolve"))?;
        let stream = TcpStream::connect_timeout(&addr, NTFY_TIMEOUT)?;
        stream.set_read_timeout(Some(NTFY_TIMEOUT))?;
        stream.set_write_timeout(Some(NTFY_TIMEOUT))?;

        let status = if self.scheme == "https" {
            let config = ntfy_tls_config()?;
            let server_name = rustls_pki_types::ServerName::try_from(self.host.clone())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad ntfy host name"))?;
            let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let mut tls = rustls::StreamOwned::new(conn, stream);
            tls.write_all(request.as_bytes())?;
            read_status_line(&mut tls)?
        } else {
            let mut plain = stream;
            plain.write_all(request.as_bytes())?;
            read_status_line(&mut plain)?
        };
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "ntfy publish refused: HTTP {status}"
            )))
        }
    }
}

/// Production off-host sink (REQ-AUD-002, #127): every checkpoint is
/// published as one ntfy message whose body is the checkpoint JSON, so
/// the ntfy topic *is* the off-host checkpoint stream the verifier
/// consumes. A failed `push` returns `Err`; [`super::AuditLog`] does
/// not count the checkpoint as delivered and retries it on the next
/// append or timer tick.
pub struct NtfyCheckpointSink {
    transport: NtfyTransport,
    /// Request path: the base URL's path prefix plus the topic.
    path: String,
}

impl NtfyCheckpointSink {
    /// Build a sink publishing to `base/topic`, reading the bearer
    /// token from `token_file` when one is configured.
    pub fn new(base: &url::Url, topic: &str, token_file: Option<&Path>) -> io::Result<Self> {
        validate_ntfy_topic(topic)?;
        let transport = NtfyTransport::new(base, token_file)?;
        let path = format!("{}/{topic}", transport.prefix());
        Ok(Self { transport, path })
    }
}

impl CheckpointSink for NtfyCheckpointSink {
    fn push(&mut self, cp: &Checkpoint) -> io::Result<()> {
        let body = serde_json::to_string(cp)?;
        self.transport
            .post(&self.path, Some("kharon audit checkpoint"), &body)
    }
}

/// rustls client config with OS roots — the same trust shape as the
/// sync client's (native certs, aws_lc_rs provider, no client auth).
fn ntfy_tls_config() -> io::Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        // Individual unparsable OS certs are skipped, as browsers do.
        let _ = roots.add(cert);
    }
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| io::Error::other("TLS provider setup failed"))
        .map(|b| b.with_root_certificates(roots).with_no_client_auth())
}

/// Read one HTTP response status line (`HTTP/1.1 200 OK`) byte by byte
/// — the reply body is irrelevant and the connection is closing.
fn read_status_line(r: &mut impl io::Read) -> io::Result<u16> {
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\r\n") && line.len() < 1024 {
        if r.read(&mut byte)? == 0 {
            break;
        }
        line.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&line);
    let mut parts = text.split_whitespace();
    let _version = parts.next();
    parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ntfy reply had no status"))
}

#[cfg(test)]
mod ntfy_tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// A one-shot stub ntfy server: records the request line, headers
    /// and body, then replies with the given status.
    fn stub_ntfy(status: u16) -> (u16, Arc<Mutex<Option<String>>>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(None));
        let seen2 = Arc::clone(&seen);
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request = String::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.to_ascii_lowercase().starts_with("content-length:") {
                    content_length = line.split(':').nth(1).unwrap().trim().parse().unwrap();
                }
                let done = line == "\r\n";
                request.push_str(&line);
                if done {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            std::io::Read::read_exact(&mut reader, &mut body).unwrap();
            request.push_str(&String::from_utf8(body).unwrap());
            *seen2.lock().unwrap() = Some(request);
            let reason = if status == 200 { "OK" } else { "Nope" };
            let mut stream = reader.into_inner();
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n"
            )
            .unwrap();
        });
        (port, seen, handle)
    }

    fn test_keys(dir: &Path) -> AuditKeys {
        AuditKeys::load_or_generate(&dir.join("keys")).unwrap()
    }

    #[test]
    fn ntfy_sink_publishes_checkpoint_json_with_token() {
        let (port, seen, handle) = stub_ntfy(200);
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("ntfy-token");
        std::fs::write(&token_path, "tk_test_token\n").unwrap();
        let base = url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let mut sink = NtfyCheckpointSink::new(&base, "kharon-audit", Some(&token_path)).unwrap();
        let cp = Checkpoint::new(7, "ab".repeat(32), &test_keys(dir.path()));
        sink.push(&cp).unwrap();
        handle.join().unwrap();
        let request = seen.lock().unwrap().clone().unwrap();
        assert!(
            request.starts_with("POST /kharon-audit HTTP/1.1"),
            "{request}"
        );
        assert!(
            request.contains("Authorization: Bearer tk_test_token"),
            "{request}"
        );
        assert!(
            request.contains("X-Title: kharon audit checkpoint"),
            "{request}"
        );
        let body = request.split("\r\n\r\n").nth(1).unwrap();
        let parsed: Checkpoint = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.seq, 7);
        assert!(parsed.verify_signature(&test_keys(dir.path()).verifying_key()));
    }

    #[test]
    fn ntfy_sink_http_error_is_an_error() {
        let (port, _seen, handle) = stub_ntfy(500);
        let base = url::Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let mut sink = NtfyCheckpointSink::new(&base, "kharon-audit", None).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cp = Checkpoint::new(1, "cd".repeat(32), &test_keys(dir.path()));
        let err = sink.push(&cp).expect_err("500 must fail the push");
        assert!(err.to_string().contains("HTTP 500"), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn ntfy_sink_missing_token_file_fails_construction() {
        let base = url::Url::parse("https://ntfy.example.net").unwrap();
        let missing = Path::new("/nonexistent/kharon-ntfy-token");
        let err = NtfyCheckpointSink::new(&base, "kharon-audit", Some(missing))
            .err()
            .expect("unreadable token file must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }
}
