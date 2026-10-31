//! Pinned-certificate TLS for the broker's CDP tunnel (REQ-ARCH-002).
//!
//! kharon terminates `wss://` itself with no implicit root store: the
//! peer is authenticated by an exact SHA-256 pin of its certificate,
//! configured out of band. Everything else about the handshake is
//! stock TLS 1.2/1.3 via rustls (aws-lc-rs provider). A peer presenting
//! any other key fails the handshake — that is the REQ-ARCH-002 tunnel
//! acceptance test (`req_arch_002_wrong_peer_key_fails_to_connect`).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::Digest;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::endpoint::CertSha256;

/// Build a `ClientConfig` that trusts exactly one certificate: the one
/// whose SHA-256 over DER equals `peer_pin`.
fn pinned_client_config(peer_pin: CertSha256) -> (Arc<rustls::ClientConfig>, Arc<CryptoProvider>) {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinVerifier {
        pin: peer_pin,
        provider: Arc::clone(&provider),
    });
    // The provider's DEFAULT_VERSIONS carry TLS 1.2 + 1.3 (with the
    // tls12 feature enabled, as configured).
    let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .expect("provider supports its own protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    (Arc::new(config), provider)
}

/// Connect `stream` to `domain`, authenticating the peer against
/// `peer_pin`. The handshake is the authentication: any other peer key
/// is refused before a single application byte flows.
pub async fn connect_tls_pinned(
    domain: &str,
    peer_pin: CertSha256,
    stream: TcpStream,
) -> Result<TlsStream<TcpStream>, std::io::Error> {
    let (config, _provider) = pinned_client_config(peer_pin);
    let server_name = server_name(domain).map_err(std::io::Error::other)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    connector.connect(server_name, stream).await
}

fn server_name(domain: &str) -> Result<ServerName<'static>, RustlsError> {
    if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(domain.to_string())
        .map_err(|_| RustlsError::General(format!("invalid TLS server name: {domain}")))
}

/// A `ServerCertVerifier` that accepts exactly the pinned certificate
/// and nothing else — no CAs, no WebPKI, no SAN checks beyond the pin.
#[derive(Debug)]
struct PinVerifier {
    pin: CertSha256,
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    fn pinned(&self, end_entity: &CertificateDer<'_>) -> Result<ServerCertVerified, RustlsError> {
        let digest = sha2::Sha256::digest(end_entity.as_ref());
        if digest.as_slice() == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ))
        }
    }
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
        self.pinned(end_entity)
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

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_echo_server(cert_key: CertifiedKey) -> (std::net::SocketAddr, Arc<tokio::task::JoinHandle<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_key.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert_key.key_pair.serialize_der().into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
        });
        (addr, Arc::new(handle))
    }

    fn pin_of(cert: &CertificateDer<'_>) -> CertSha256 {
        let digest = sha2::Sha256::digest(cert.as_ref());
        let mut pin = [0u8; 32];
        pin.copy_from_slice(digest.as_slice());
        pin
    }

    #[tokio::test]
    async fn req_arch_002_right_peer_key_connects() {
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(
            vec!["localhost".to_string(), "127.0.0.1".to_string()],
        )
        .unwrap();
        let cert_der = cert.der().clone();
        let server_key = CertifiedKey {
            cert,
            key_pair,
        };
        let (addr, _server) = spawn_echo_server(server_key).await;

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut tls = connect_tls_pinned("localhost", pin_of(&cert_der), stream)
            .await
            .expect("pinned handshake must succeed");
        tls.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[tokio::test]
    async fn req_arch_002_wrong_peer_key_fails_to_connect() {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let server_key = CertifiedKey { cert, key_pair };
        let (addr, _server) = spawn_echo_server(server_key).await;

        // A pin that is not the server's: the handshake itself must fail,
        // before any application data flows.
        let wrong_pin = [0x5au8; 32];
        let stream = TcpStream::connect(addr).await.unwrap();
        let result = connect_tls_pinned("localhost", wrong_pin, stream).await;
        assert!(
            result.is_err(),
            "handshake with a wrong peer key must not complete"
        );
    }
}
