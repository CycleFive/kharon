//! Pinned-certificate TLS for the connector (REQ-ARCH-002).
//!
//! Same rule as `kharond`'s CDP `wss` pin: the peer is trusted exactly
//! when the SHA-256 of its end-entity DER matches the configured pin.
//! No WebPKI, no SAN check, no expiry check — rotation is "change the
//! pin". A wrong broker key fails the handshake before any auth byte.

use std::sync::Arc;

use base64ct::Encoding;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

/// SHA-256 of the broker's DER certificate.
pub type CertSha256 = [u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum TlsMaterialError {
    #[error("tls material is unreadable")]
    Unreadable,
    #[error("tls material is not a PEM certificate and private key")]
    BadPem,
}

/// SHA-256 of a DER certificate.
pub fn pin_of_der(der: &[u8]) -> CertSha256 {
    let digest = sha2::Sha256::digest(der);
    let mut pin = [0u8; 32];
    pin.copy_from_slice(&digest);
    pin
}

static TLS13_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS13];

/// Which TLS protocol versions a config offers.
///
/// The raw `:8789` path keeps [`Default`](TlsVersions::Default). The
/// WebSocket path's inner TLS is [`Tls13Only`](TlsVersions::Tls13Only) on
/// both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersions {
    /// `rustls::DEFAULT_VERSIONS` (TLS 1.2 and 1.3).
    Default,
    /// TLS 1.3 only.
    Tls13Only,
}

impl TlsVersions {
    pub fn as_slice(self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match self {
            Self::Default => rustls::DEFAULT_VERSIONS,
            Self::Tls13Only => &TLS13_ONLY,
        }
    }
}

/// Broker (or agent-API) `ServerConfig` from PEM files' bytes.
/// The certificate file may hold a chain; the first certificate is the
/// one the agent pins. The key file is PKCS#8 or SEC1.
pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>, TlsMaterialError> {
    server_config_from_pem_with(cert_pem, key_pem, TlsVersions::Default)
}

/// [`server_config_from_pem`] with a chosen version set. Early data is
/// never accepted.
pub fn server_config_from_pem_with(
    cert_pem: &[u8],
    key_pem: &[u8],
    versions: TlsVersions,
) -> Result<Arc<rustls::ServerConfig>, TlsMaterialError> {
    let certs = pem_certs(cert_pem)?;
    if certs.is_empty() {
        return Err(TlsMaterialError::BadPem);
    }
    let key = pem_key(key_pem)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions.as_slice())
        .expect("aws-lc-rs supports the versions it advertises")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsMaterialError::BadPem)?;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// Handshake `stream` and require the end-entity certificate to match `pin`.
pub async fn connect_pinned(
    server_name: &str,
    pin: CertSha256,
    stream: TcpStream,
) -> Result<TlsStream<TcpStream>, std::io::Error> {
    connect_pinned_stream(server_name, pin, stream, TlsVersions::Default).await
}

/// [`connect_pinned`] over any byte stream, with a chosen version set.
pub async fn connect_pinned_stream<S: AsyncRead + AsyncWrite + Unpin>(
    server_name: &str,
    pin: CertSha256,
    stream: S,
    versions: TlsVersions,
) -> std::io::Result<TlsStream<S>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinVerifier {
        pin,
        provider: Arc::clone(&provider),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions.as_slice())
        .expect("aws-lc-rs supports the versions it advertises")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let name = server_name_from(server_name).map_err(std::io::Error::other)?;
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
}

fn pem_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsMaterialError> {
    Ok(pem_blocks(pem, "CERTIFICATE")?
        .into_iter()
        .map(CertificateDer::from)
        .collect())
}

fn pem_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsMaterialError> {
    if let Ok(der) = pem_blocks(pem, "PRIVATE KEY")
        && let Some(der) = der.into_iter().next()
    {
        return Ok(PrivateKeyDer::Pkcs8(der.into()));
    }
    if let Ok(der) = pem_blocks(pem, "RSA PRIVATE KEY")
        && let Some(der) = der.into_iter().next()
    {
        return Ok(PrivateKeyDer::Pkcs1(der.into()));
    }
    if let Ok(der) = pem_blocks(pem, "EC PRIVATE KEY")
        && let Some(der) = der.into_iter().next()
    {
        return Ok(PrivateKeyDer::Sec1(der.into()));
    }
    Err(TlsMaterialError::BadPem)
}

/// Decode every PEM block with `label`. Empty is an error so a missing
/// banner is not confused with a file that holds a different label.
fn pem_blocks(pem: &[u8], label: &str) -> Result<Vec<Vec<u8>>, TlsMaterialError> {
    let text = std::str::from_utf8(pem).map_err(|_| TlsMaterialError::BadPem)?;
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        rest = &rest[start + begin.len()..];
        let Some(stop) = rest.find(&end) else {
            return Err(TlsMaterialError::BadPem);
        };
        let b64: String = rest[..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = base64ct::Base64::decode_vec(&b64).map_err(|_| TlsMaterialError::BadPem)?;
        if der.is_empty() {
            return Err(TlsMaterialError::BadPem);
        }
        out.push(der);
        rest = &rest[stop + end.len()..];
    }
    if out.is_empty() {
        return Err(TlsMaterialError::BadPem);
    }
    Ok(out)
}

fn server_name_from(domain: &str) -> Result<ServerName<'static>, RustlsError> {
    if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(domain.to_owned())
        .map_err(|_| RustlsError::General("invalid TLS server name".into()))
}

#[derive(Debug)]
struct PinVerifier {
    pin: CertSha256,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if sha2::Sha256::digest(end_entity.as_ref()).as_slice() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        false
    }
}

/// Whether `err` is the pin verifier refusing the peer certificate.
pub fn is_pin_mismatch(err: &std::io::Error) -> bool {
    // tokio-rustls wraps the rustls error in `io::Error`. Walk the source
    // chain, and also the Display text: some wrappers only keep the message
    // ("invalid peer certificate").
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if matches!(
            e.downcast_ref::<RustlsError>(),
            Some(RustlsError::InvalidCertificate(_))
        ) {
            return true;
        }
        let text = e.to_string().to_ascii_lowercase();
        if text.contains("certificate") {
            return true;
        }
        cur = e.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static TLS12_ONLY: [&rustls::SupportedProtocolVersion; 1] = [&rustls::version::TLS12];

    struct Material {
        pin: CertSha256,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    }

    fn material() -> Material {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        Material {
            pin: pin_of_der(cert.der()),
            cert_pem: cert.pem().into_bytes(),
            key_pem: key_pair.serialize_pem().into_bytes(),
        }
    }

    /// A pinned client restricted to `versions`, for probing servers.
    fn client_with(
        pin: CertSha256,
        versions: &'static [&'static rustls::SupportedProtocolVersion],
    ) -> tokio_rustls::TlsConnector {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = Arc::new(PinVerifier {
            pin,
            provider: Arc::clone(&provider),
        });
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    fn server_with_versions(
        m: &Material,
        versions: &'static [&'static rustls::SupportedProtocolVersion],
    ) -> tokio_rustls::TlsAcceptor {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                pem_certs(&m.cert_pem).unwrap(),
                pem_key(&m.key_pem).unwrap(),
            )
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    fn name() -> ServerName<'static> {
        server_name_from("localhost").unwrap()
    }

    #[tokio::test]
    async fn tls13_only_server_refuses_a_tls12_client() {
        let m = material();
        let acceptor = tokio_rustls::TlsAcceptor::from(
            server_config_from_pem_with(&m.cert_pem, &m.key_pem, TlsVersions::Tls13Only).unwrap(),
        );
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move { acceptor.accept(b).await.is_err() });
        let client = client_with(m.pin, &TLS12_ONLY).connect(name(), a).await;
        assert!(client.is_err());
        assert!(server.await.unwrap());
    }

    #[tokio::test]
    async fn default_server_still_accepts_tls12() {
        let m = material();
        let acceptor = tokio_rustls::TlsAcceptor::from(
            server_config_from_pem(&m.cert_pem, &m.key_pem).unwrap(),
        );
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move { acceptor.accept(b).await.is_ok() });
        let client = client_with(m.pin, &TLS12_ONLY).connect(name(), a).await;
        assert!(client.is_ok());
        assert!(server.await.unwrap());
    }

    #[tokio::test]
    async fn tls13_only_client_refuses_a_tls12_only_server() {
        let m = material();
        let acceptor = server_with_versions(&m, &TLS12_ONLY);
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let _ = acceptor.accept(b).await;
        });
        let client = connect_pinned_stream("localhost", m.pin, a, TlsVersions::Tls13Only).await;
        assert!(client.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pinned_stream_works_over_a_duplex() {
        let m = material();
        let acceptor = tokio_rustls::TlsAcceptor::from(
            server_config_from_pem_with(&m.cert_pem, &m.key_pem, TlsVersions::Tls13Only).unwrap(),
        );
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut s = acceptor.accept(b).await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.flush().await.unwrap();
        });
        let mut c = connect_pinned_stream("localhost", m.pin, a, TlsVersions::Tls13Only)
            .await
            .unwrap();
        c.write_all(b"ping").await.unwrap();
        c.flush().await.unwrap();
        let mut back = [0u8; 4];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pinned_stream_wrong_pin_is_a_mismatch() {
        let m = material();
        let acceptor = tokio_rustls::TlsAcceptor::from(
            server_config_from_pem_with(&m.cert_pem, &m.key_pem, TlsVersions::Tls13Only).unwrap(),
        );
        let (a, b) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = acceptor.accept(b).await;
        });
        let err = connect_pinned_stream("localhost", [0u8; 32], a, TlsVersions::Tls13Only)
            .await
            .unwrap_err();
        assert!(is_pin_mismatch(&err));
    }

    #[test]
    fn ws_server_config_has_no_early_data() {
        let m = material();
        let cfg =
            server_config_from_pem_with(&m.cert_pem, &m.key_pem, TlsVersions::Tls13Only).unwrap();
        assert_eq!(cfg.max_early_data_size, 0);
    }
}
