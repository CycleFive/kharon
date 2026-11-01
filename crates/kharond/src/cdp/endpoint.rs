//! CDP endpoint validation (REQ-ARCH-002, config-load half).
//!
//! The broker talks to Chromium's CDP socket over one of four transports
//! (SPEC §3.3):
//!
//! | `via`        | who encrypts                          | kharon's role |
//! |--------------|---------------------------------------|---------------|
//! | `direct`     | nobody — loopback only                | plain ws      |
//! | `wireguard`  | the WireGuard interface               | validate only |
//! | `ssh`        | the ssh `-R` tunnel                   | validate only |
//! | `mtls`       | kharon itself (TLS, pinned peer cert) | TLS client    |
//!
//! Fail closed at config load: plain `ws://` to a non-loopback address
//! with `via = direct` is refused before any connection exists. `wss://`
//! always requires an explicit peer certificate pin — no implicit
//! WebPKI roots are pulled in (SPEC §3.3 leaves root stores open; a pin
//! is the stricter, dependency-free choice). `via = mtls` is terminated
//! in-crate: the TLS handshake authenticates the peer against the pinned
//! certificate, so a wrong peer key fails to connect (REQ-ARCH-002 AC).

use std::net::IpAddr;

use url::Url;

/// How the broker reaches the CDP endpoint (`via` in SPEC §9 config).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tunnel {
    /// No tunnel: plain WebSocket. Loopback addresses only.
    Direct,
    /// WireGuard carries the traffic; kharon validates and speaks plain
    /// ws over the interface (terminated externally per SPEC §3.3).
    WireGuard,
    /// `ssh -R` relay; validated, not terminated, in-crate.
    Ssh,
    /// kharon terminates TLS itself with a pinned peer certificate.
    Mtls,
}

impl Tunnel {
    /// Config-string form (`via = "wireguard"` in SPEC §9).
    pub fn from_config(s: &str) -> Option<Self> {
        match s {
            "direct" => Some(Self::Direct),
            "wireguard" => Some(Self::WireGuard),
            "ssh" => Some(Self::Ssh),
            "mtls" => Some(Self::Mtls),
            _ => None,
        }
    }
}

/// Why an endpoint configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// Not an absolute `ws://`/`wss://` URL.
    #[error("CDP endpoint must be an absolute ws:// or wss:// URL")]
    NotWebSocketUrl,
    /// `via = direct` with a non-loopback host: plaintext CDP on the
    /// network, refused at config load (REQ-ARCH-002).
    #[error(
        "plain ws:// to a non-loopback address refused (via = direct); use wireguard, ssh, or mtls"
    )]
    PlainWsNonLoopback,
    /// `via = mtls` speaks TLS in-crate, so the endpoint must be `wss://`.
    #[error("via = mtls requires a wss:// endpoint")]
    MtlsRequiresWss,
    /// `wss://` without a pinned peer certificate. Fail closed: no
    /// implicit root store.
    #[error("wss:// requires peer_cert (pinned self-signed DER is fine)")]
    WssRequiresPeerPin,
    /// Unknown `via` value.
    #[error("unknown via value: {0}")]
    UnknownTunnel(String),
    /// Host present but unresolvable as an IP / hostname shape we accept
    /// (empty host, bad port, …).
    #[error("CDP endpoint host is missing or invalid")]
    BadHost,
}

/// SHA-256 of the peer's DER certificate, configured out of band.
pub type CertSha256 = [u8; 32];

/// A validated CDP endpoint, ready to connect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpEndpoint {
    /// Normalized endpoint URL (`ws`/`wss`).
    pub url: Url,
    /// Transport mode.
    pub tunnel: Tunnel,
    /// For `wss`: the pinned peer certificate (SHA-256 of DER). `None`
    /// only for `ws` transports.
    pub peer_pin: Option<CertSha256>,
}

impl CdpEndpoint {
    /// Validate a configured endpoint. `peer_cert_sha256` is the raw
    /// (non-base64) hex-decoded pin when `wss://` is used.
    pub fn validate(
        endpoint: &str,
        via: Tunnel,
        peer_cert_sha256: Option<CertSha256>,
    ) -> Result<Self, EndpointError> {
        let url = Url::parse(endpoint).map_err(|_| EndpointError::NotWebSocketUrl)?;
        match url.scheme() {
            "ws" | "wss" => {}
            _ => return Err(EndpointError::NotWebSocketUrl),
        }
        let host = url.host_str().ok_or(EndpointError::BadHost)?;

        match via {
            Tunnel::Direct => {
                if url.scheme() == "ws" && !is_loopback(host) {
                    return Err(EndpointError::PlainWsNonLoopback);
                }
                if url.scheme() == "wss" && peer_cert_sha256.is_none() {
                    return Err(EndpointError::WssRequiresPeerPin);
                }
            }
            Tunnel::WireGuard | Tunnel::Ssh => {
                // External tunnel: plain ws is fine over it, wss still
                // pins (defense in depth, same rule as direct).
                if url.scheme() == "wss" && peer_cert_sha256.is_none() {
                    return Err(EndpointError::WssRequiresPeerPin);
                }
            }
            Tunnel::Mtls => {
                if url.scheme() != "wss" {
                    return Err(EndpointError::MtlsRequiresWss);
                }
                // pin is mandatory for mtls (same fail-closed rule).
                if peer_cert_sha256.is_none() {
                    return Err(EndpointError::WssRequiresPeerPin);
                }
            }
        }

        Ok(Self {
            url,
            tunnel: via,
            peer_pin: peer_cert_sha256,
        })
    }

    /// Whether kharon terminates TLS for this endpoint itself.
    pub fn terminates_tls(&self) -> bool {
        self.url.scheme() == "wss"
    }
}

fn is_loopback(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    let bare = match host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Some(inner) => inner,
        None => host,
    };
    match bare.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_arch_002_plain_ws_loopback_allowed() {
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let ep = CdpEndpoint::validate(
                &format!("ws://{host}:9222/devtools/browser"),
                Tunnel::Direct,
                None,
            )
            .unwrap_or_else(|e| panic!("{host}: {e}"));
            assert_eq!(ep.tunnel, Tunnel::Direct);
            assert!(ep.peer_pin.is_none());
        }
    }

    #[test]
    fn req_arch_002_plain_ws_non_loopback_refused() {
        for host in ["10.66.0.2", "192.168.1.5", "example.com", "[2001:db8::1]"] {
            let err = CdpEndpoint::validate(
                &format!("ws://{host}:9222/devtools/browser"),
                Tunnel::Direct,
                None,
            )
            .unwrap_err();
            assert_eq!(
                err,
                EndpointError::PlainWsNonLoopback,
                "{host}: got {err:?}"
            );
        }
    }

    #[test]
    fn req_arch_002_plain_ws_non_loopback_allowed_over_tunnel() {
        for via in [Tunnel::WireGuard, Tunnel::Ssh] {
            let ep = CdpEndpoint::validate("ws://10.66.0.2:9222/", via, None).unwrap();
            assert_eq!(ep.tunnel, via);
        }
    }

    #[test]
    fn req_arch_002_wss_requires_peer_pin() {
        // direct + wss + no pin → refused
        assert_eq!(
            CdpEndpoint::validate("wss://127.0.0.1:9222/", Tunnel::Direct, None).unwrap_err(),
            EndpointError::WssRequiresPeerPin
        );
        // wireguard + wss + no pin → refused (same rule over tunnels)
        assert_eq!(
            CdpEndpoint::validate("wss://10.66.0.2:9222/", Tunnel::WireGuard, None).unwrap_err(),
            EndpointError::WssRequiresPeerPin
        );
        // with a pin → accepted
        let pin = [0x42u8; 32];
        let ep =
            CdpEndpoint::validate("wss://10.66.0.2:9222/", Tunnel::WireGuard, Some(pin)).unwrap();
        assert_eq!(ep.peer_pin, Some(pin));
    }

    #[test]
    fn req_arch_002_mtls_requires_wss_and_pin() {
        assert_eq!(
            CdpEndpoint::validate("ws://10.66.0.2:9222/", Tunnel::Mtls, Some([0u8; 32]))
                .unwrap_err(),
            EndpointError::MtlsRequiresWss
        );
        assert_eq!(
            CdpEndpoint::validate("wss://10.66.0.2:9222/", Tunnel::Mtls, None).unwrap_err(),
            EndpointError::WssRequiresPeerPin
        );
        let ep =
            CdpEndpoint::validate("wss://10.66.0.2:9222/", Tunnel::Mtls, Some([1u8; 32])).unwrap();
        assert!(ep.terminates_tls());
    }

    #[test]
    fn req_arch_002_non_ws_url_refused() {
        for bad in ["http://localhost:9222", "tcp://localhost:9222", "not a url"] {
            assert_eq!(
                CdpEndpoint::validate(bad, Tunnel::Direct, None).unwrap_err(),
                EndpointError::NotWebSocketUrl,
                "{bad}"
            );
        }
    }
}
