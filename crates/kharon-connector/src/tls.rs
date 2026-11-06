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

/// Broker (or agent-API) `ServerConfig` from PEM files' bytes.
/// The certificate file may hold a chain; the first certificate is the
/// one the agent pins. The key file is PKCS#8 or SEC1.
pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>, TlsMaterialError> {
    let certs = pem_certs(cert_pem)?;
    if certs.is_empty() {
        return Err(TlsMaterialError::BadPem);
    }
    let key = pem_key(key_pem)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .expect("aws-lc-rs supports the versions it advertises")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| TlsMaterialError::BadPem)?;
    Ok(Arc::new(config))
}

/// Handshake `stream` and require the end-entity certificate to match `pin`.
pub async fn connect_pinned(
    server_name: &str,
    pin: CertSha256,
    stream: TcpStream,
) -> Result<TlsStream<TcpStream>, std::io::Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(PinVerifier {
        pin,
        provider: Arc::clone(&provider),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
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
