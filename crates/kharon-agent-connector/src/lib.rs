//! The connector's config loader (`connector.toml`), as a library so
//! that `kharon setup` (#405) can check the `connector.toml` it puts in
//! the agent-host bundle with the same code the binary runs. The binary
//! (`src/main.rs`) is the only other user.
//!
//! Field and key meanings are in the binary's module docs.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kharon_connector::{DiscoverSource, default_hermes_home, proxy_creds_line};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
enum TransportKind {
    #[default]
    Tls,
    Ws,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    transport: TransportKind,
    /// `host:port` of the raw listener. `transport = "tls"` only.
    #[serde(default)]
    broker: Option<String>,
    /// `wss://host[:port][/path]`. `transport = "ws"` only.
    #[serde(default)]
    broker_url: Option<String>,
    /// Inner TLS name. Defaults to the broker host.
    #[serde(default)]
    server_name: Option<String>,
    broker_pin: String,
    /// For tests and private edges only: a PEM CA that is the *only* root
    /// for the outer TLS of a `ws` transport (the system roots are not
    /// used then). Refused with `transport = "tls"`. Outer verification
    /// is never switched off.
    #[serde(default)]
    outer_ca_file: Option<PathBuf>,
    agent_id: String,
    token_file: PathBuf,
    /// Explicit loopback `host:port`. Wins over discovery.
    #[serde(default)]
    cdp: Option<String>,
    /// Explicit loopback URL (`http://` or `ws://`). Wins over discovery.
    /// Not combined with `cdp`.
    #[serde(default)]
    cdp_url: Option<String>,
    /// Path of one Chromium `DevToolsActivePort` file.
    #[serde(default)]
    devtools_active_port: Option<PathBuf>,
    /// One Chromium `--user-data-dir`. The file is `<dir>/DevToolsActivePort`.
    #[serde(default)]
    user_data_dir: Option<PathBuf>,
    /// Hermes home for the stock preset (`<home>/cache/browser/chromium`).
    /// Default is `$HERMES_HOME` or `~/.hermes`.
    #[serde(default)]
    hermes_home: Option<PathBuf>,
    /// `http://host:port` with no userinfo. A password does not belong here.
    #[serde(default)]
    proxy: Option<String>,
    /// One `user:password` line. Same mode rule as `token_file`.
    #[serde(default)]
    proxy_creds_file: Option<PathBuf>,
}

pub enum Dest {
    Tls {
        host: String,
        port: u16,
    },
    Ws {
        host: String,
        port: u16,
        path: String,
    },
}

pub struct Config {
    pub dest: Dest,
    pub server_name: String,
    pub outer_roots: Option<Arc<rustls::RootCertStore>>,
    pub pin: kharon_connector::CertSha256,
    pub agent_id: String,
    pub token: Zeroizing<String>,
    /// Dialed only when `devtools` is `None`.
    pub cdp: SocketAddr,
    /// Re-read on every CDP dial. Set when no explicit endpoint was configured.
    pub devtools: Option<DiscoverSource>,
    pub proxy: Option<(String, u16)>,
    pub proxy_creds: Option<Zeroizing<Vec<u8>>>,
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|_| "cannot read config".to_owned())?;
    let raw: RawConfig = toml::from_str(&text).map_err(|_| "config parse error".to_owned())?;
    let (dest, default_name) = match raw.transport {
        TransportKind::Tls => {
            if raw.broker_url.is_some() {
                return Err("broker_url requires transport = \"ws\"".to_owned());
            }
            if raw.outer_ca_file.is_some() {
                return Err("outer_ca_file requires transport = \"ws\"".to_owned());
            }
            let broker = raw
                .broker
                .as_deref()
                .ok_or_else(|| "broker must be host:port".to_owned())?;
            let (host, port) =
                split_host_port(broker).ok_or_else(|| "broker must be host:port".to_owned())?;
            (
                Dest::Tls {
                    host: host.to_owned(),
                    port,
                },
                host.to_owned(),
            )
        }
        TransportKind::Ws => {
            if raw.broker.is_some() {
                return Err("broker requires transport = \"tls\"; use broker_url".to_owned());
            }
            let url = raw.broker_url.as_deref().ok_or_else(|| {
                "broker_url must be wss://host[:port][/path] with transport = \"ws\"".to_owned()
            })?;
            let (host, port, path) = parse_wss_url(url)?;
            (
                Dest::Ws {
                    host: host.clone(),
                    port,
                    path,
                },
                host,
            )
        }
    };
    let server_name = match &raw.server_name {
        Some(n) if n.trim().is_empty() => return Err("server_name must not be empty".to_owned()),
        Some(n) => n.clone(),
        None => default_name,
    };
    let outer_roots = match &raw.outer_ca_file {
        None => None,
        Some(p) => Some(read_outer_ca(p)?),
    };
    if !valid_agent_id(&raw.agent_id) {
        return Err("agent_id must match [a-z0-9-]{1,64}".to_owned());
    }
    let pin = parse_pin(&raw.broker_pin)?;
    let (cdp, devtools) = cdp_target(&raw)?;
    let proxy = match raw.proxy {
        None => None,
        Some(p) => Some(parse_proxy(&p)?),
    };
    let proxy_creds = match raw.proxy_creds_file {
        None => None,
        Some(path) => {
            if proxy.is_none() {
                return Err("proxy_creds_file requires proxy".to_owned());
            }
            Some(read_proxy_creds(&path)?)
        }
    };
    let token = read_token(&raw.token_file)?;
    Ok(Config {
        dest,
        server_name,
        outer_roots,
        pin,
        agent_id: raw.agent_id,
        token,
        cdp,
        devtools,
        proxy,
        proxy_creds,
    })
}

/// `wss://host[:port][/path]` -> (host, port, path). Only `wss`; no
/// userinfo, query or fragment. Port defaults to 443, path to `/connector`.
pub fn parse_wss_url(raw: &str) -> Result<(String, u16, String), String> {
    const BAD: &str = "broker_url must be wss://host[:port][/path]";
    let rest = raw.strip_prefix("wss://").ok_or_else(|| BAD.to_owned())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/connector"),
    };
    if authority.is_empty()
        || authority.contains('@')
        || path.contains(['?', '#'])
        || path
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(BAD.to_owned());
    }
    let (host, port) = if authority.starts_with('[') {
        match authority.rsplit_once("]:") {
            Some(_) => split_host_port(authority).ok_or_else(|| BAD.to_owned())?,
            None => {
                let h = authority
                    .strip_prefix('[')
                    .and_then(|a| a.strip_suffix(']'))
                    .filter(|h| !h.is_empty())
                    .ok_or_else(|| BAD.to_owned())?;
                (h, 443)
            }
        }
    } else if authority.contains(':') {
        split_host_port(authority).ok_or_else(|| BAD.to_owned())?
    } else {
        (authority, 443)
    };
    if port == 0 {
        return Err(BAD.to_owned());
    }
    Ok((host.to_owned(), port, path.to_owned()))
}

fn read_outer_ca(path: &Path) -> Result<Arc<rustls::RootCertStore>, String> {
    use rustls_pki_types::{CertificateDer, pem::PemObject};
    let pem = std::fs::read(path).map_err(|_| "cannot read outer_ca_file".to_owned())?;
    let mut store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(|_| "outer_ca_file is not valid PEM".to_owned())?;
        store
            .add(cert)
            .map_err(|_| "outer_ca_file holds an unusable certificate".to_owned())?;
    }
    if store.is_empty() {
        return Err("outer_ca_file holds no certificate".to_owned());
    }
    Ok(Arc::new(store))
}

fn read_proxy_creds(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let meta =
        std::fs::metadata(path).map_err(|_| "cannot read proxy credential file".to_owned())?;
    if !meta.is_file() {
        return Err("proxy credential file is not a regular file".to_owned());
    }
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    };
    if mode & 0o077 != 0 {
        return Err("proxy credential file must be mode 0400 or 0600".to_owned());
    }
    let raw = Zeroizing::new(
        std::fs::read(path).map_err(|_| "cannot read proxy credential file".to_owned())?,
    );
    proxy_creds_line(&raw).map_err(str::to_owned)
}

pub fn read_token(path: &Path) -> Result<Zeroizing<String>, String> {
    let meta = std::fs::metadata(path).map_err(|_| "cannot read token file".to_owned())?;
    if !meta.is_file() {
        return Err("token file is not a regular file".to_owned());
    }
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    };
    if mode & 0o077 != 0 {
        return Err("token file must be mode 0400 or 0600".to_owned());
    }
    let text = std::fs::read_to_string(path).map_err(|_| "cannot read token file".to_owned())?;
    let token = text.trim().to_owned();
    if token.is_empty() || token.chars().any(char::is_whitespace) {
        return Err("token file must hold one connector credential".to_owned());
    }
    // The credential is a tunnel credential (`kh_tunnel_`) or a
    // broker-issued connector access token (`kh_at_`, REQ-ARCH-002);
    // anything else in the file is refused before any dial. The token's
    // audience is the broker's check at authenticate time: an
    // MCP-audience `kh_at_` is refused there, before any CDP traffic.
    if !token.starts_with("kh_tunnel_") && !token.starts_with("kh_at_") {
        return Err(
            "token file must hold a tunnel credential (kh_tunnel_...) or a connector access token (kh_at_...)"
                .to_owned(),
        );
    }
    Ok(Zeroizing::new(token))
}

/// Explicit `cdp` / `cdp_url`, or DevToolsActivePort discovery.
///
/// An explicit endpoint wins and the discovery keys are not read. With
/// none set, the stock Hermes preset is `<hermes_home>/cache/browser/chromium`.
fn cdp_target(raw: &RawConfig) -> Result<(SocketAddr, Option<DiscoverSource>), String> {
    let explicit = match (&raw.cdp, &raw.cdp_url) {
        (Some(_), Some(_)) => return Err("set cdp or cdp_url, not both".to_owned()),
        (Some(cdp), None) => Some(parse_cdp_socket(cdp)?),
        (None, Some(url)) => Some(parse_cdp_url(url)?),
        (None, None) => None,
    };
    if let Some(addr) = explicit {
        return Ok((addr, None));
    }
    if raw.devtools_active_port.is_some() && raw.user_data_dir.is_some() {
        return Err("set devtools_active_port or user_data_dir, not both".to_owned());
    }
    if raw.hermes_home.is_some()
        && (raw.devtools_active_port.is_some() || raw.user_data_dir.is_some())
    {
        return Err(
            "hermes_home is the preset root; do not combine it with devtools_active_port or user_data_dir"
                .to_owned(),
        );
    }
    let source = if let Some(path) = &raw.devtools_active_port {
        non_empty_path(path, "devtools_active_port")?;
        DiscoverSource::File(path.clone())
    } else if let Some(dir) = &raw.user_data_dir {
        non_empty_path(dir, "user_data_dir")?;
        DiscoverSource::UserDataDir(dir.clone())
    } else {
        let home = match &raw.hermes_home {
            Some(path) => {
                non_empty_path(path, "hermes_home")?;
                path.clone()
            }
            None => default_hermes_home(),
        };
        DiscoverSource::HermesEphemeral { home }
    };
    // Not dialed. Discovery replaces it on every CDP open, and only with
    // 127.0.0.1.
    Ok((
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 9)),
        Some(source),
    ))
}

/// One line for stderr at startup. Discovery names the source the next
/// dial will read; an explicit endpoint names the socket.
pub fn cdp_startup_line(cdp: SocketAddr, devtools: Option<&DiscoverSource>) -> String {
    match devtools {
        Some(DiscoverSource::HermesEphemeral { home }) => {
            format!("cdp: discover hermes_home={}", home.display())
        }
        Some(DiscoverSource::UserDataDir(dir)) => {
            format!("cdp: discover user_data_dir={}", dir.display())
        }
        Some(DiscoverSource::File(path)) => {
            format!("cdp: discover devtools_active_port={}", path.display())
        }
        None => format!("cdp: {cdp}"),
    }
}

fn non_empty_path(path: &Path, key: &str) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    Ok(())
}

fn parse_cdp_socket(raw: &str) -> Result<SocketAddr, String> {
    let cdp: SocketAddr = raw
        .parse()
        .map_err(|_| "cdp must be a loopback socket, e.g. 127.0.0.1:9222".to_owned())?;
    if !cdp.ip().is_loopback() || cdp.port() == 0 {
        return Err("cdp must be a loopback socket, e.g. 127.0.0.1:9222".to_owned());
    }
    Ok(cdp)
}

/// `http://` or `ws://` loopback URL, or a bare `host:port`. The path is
/// ignored: the connector dials the port, and the broker names the
/// WebSocket path. Anything that is not a loopback IP is refused.
fn parse_cdp_url(raw: &str) -> Result<SocketAddr, String> {
    const BAD: &str = "cdp_url must be a loopback socket, e.g. http://127.0.0.1:9222";
    let raw = raw.trim();
    let rest = if let Some(rest) = raw.strip_prefix("http://") {
        rest
    } else if let Some(rest) = raw.strip_prefix("ws://") {
        rest
    } else if raw.contains("://") {
        return Err(BAD.to_owned());
    } else {
        raw
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() || authority.contains('@') {
        return Err(BAD.to_owned());
    }
    let (host, port) = split_host_port(authority).ok_or_else(|| BAD.to_owned())?;
    let ip: std::net::IpAddr = host.parse().map_err(|_| BAD.to_owned())?;
    if !ip.is_loopback() || port == 0 {
        return Err(BAD.to_owned());
    }
    Ok(SocketAddr::new(ip, port))
}

fn parse_pin(hex_pin: &str) -> Result<kharon_connector::CertSha256, String> {
    let hex_pin = hex_pin.trim();
    if hex_pin.len() != 64 || !hex_pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(
            "broker_pin must be 64 hex characters (SHA-256 of the broker certificate DER)"
                .to_owned(),
        );
    }
    let mut pin = [0u8; 32];
    for i in 0..32 {
        pin[i] = u8::from_str_radix(&hex_pin[i * 2..i * 2 + 2], 16).map_err(|_| {
            "broker_pin must be 64 hex characters (SHA-256 of the broker certificate DER)"
                .to_owned()
        })?;
    }
    Ok(pin)
}

pub fn parse_proxy(raw: &str) -> Result<(String, u16), String> {
    let rest = raw
        .strip_prefix("http://")
        .ok_or_else(|| "proxy must be http://host:port with no userinfo".to_owned())?;
    if rest.contains('@') || rest.contains("://") {
        return Err("proxy must be http://host:port with no userinfo".to_owned());
    }
    let (host, port) =
        split_host_port(rest).ok_or_else(|| "proxy must be http://host:port".to_owned())?;
    Ok((host.to_owned(), port))
}

fn split_host_port(s: &str) -> Option<(&str, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        if host.is_empty() {
            return None;
        }
        return Some((host, port.parse().ok()?));
    }
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') {
        return None;
    }
    Some((host, port.parse().ok()?))
}

pub fn valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
