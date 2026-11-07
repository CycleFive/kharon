//! Agent-host connector (path B, REQ-ARCH-001 / REQ-ARCH-002).
//!
//! Dials kharond's connector listener over outbound TLS, proves the tunnel
//! credential, and relays the broker's CDP traffic to loopback Chromium.
//! It holds that tunnel credential and, when configured, the egress
//! proxy's password. It does not hold an agent API token, a vault key,
//! or the account password. A token that does not start
//! with `kh_tunnel_` is refused before any dial, so an agent API token
//! left in the file by mistake is not sent to the broker.
//!
//! Reconnects with backoff until SIGINT or SIGTERM. v1 wire constants
//! live in `kharon-connector` (SPEC OQ-14).
//!
//! An optional HTTP CONNECT proxy is `http://host:port` with no
//! userinfo. When that proxy requires authentication,
//! `proxy_creds_file` is a mode `0400` or `0600` file of one
//! `user:password` line (a trailing newline is ignored). The connector
//! sends it only as `Proxy-Authorization` on the CONNECT. It is not
//! taken from the proxy URL or argv, and it is never logged.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use kharon_connector::{AgentParams, ClientError, proxy_creds_line, run_agent_once};
use serde::Deserialize;
use zeroize::Zeroizing;

/// `sysexits.h` `EX_CONFIG`.
const EX_CONFIG: u8 = 78;
/// `sysexits.h` `EX_UNAVAILABLE` — could not resolve the broker or proxy.
const EX_UNAVAILABLE: u8 = 69;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    broker: String,
    broker_pin: String,
    agent_id: String,
    token_file: PathBuf,
    cdp: String,
    /// `http://host:port` with no userinfo. A password does not belong here.
    #[serde(default)]
    proxy: Option<String>,
    /// One `user:password` line. Same mode rule as `token_file`.
    #[serde(default)]
    proxy_creds_file: Option<PathBuf>,
}

struct Config {
    broker_host: String,
    broker_port: u16,
    pin: kharon_connector::CertSha256,
    agent_id: String,
    token: Zeroizing<String>,
    cdp: SocketAddr,
    proxy: Option<(String, u16)>,
    proxy_creds: Option<Zeroizing<Vec<u8>>>,
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut path = PathBuf::from("/etc/kharon-connector/connector.toml");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => match args.next() {
                Some(p) => path = PathBuf::from(p),
                None => {
                    eprintln!("kharon-agent-connector: --config needs a path");
                    return ExitCode::from(EX_CONFIG);
                }
            },
            "--help" | "-h" => {
                eprintln!("kharon-agent-connector --config /etc/kharon-connector/connector.toml");
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("kharon-agent-connector: unknown argument");
                return ExitCode::from(EX_CONFIG);
            }
        }
    }
    let cfg = match load(&path) {
        Ok(cfg) => cfg,
        Err(msg) => {
            eprintln!("kharon-agent-connector: {msg}");
            return ExitCode::from(EX_CONFIG);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            eprintln!("kharon-agent-connector: cannot start runtime");
            return ExitCode::from(EX_UNAVAILABLE);
        }
    };
    rt.block_on(async move {
        let params = match resolve(&cfg).await {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("kharon-agent-connector: {msg}");
                return ExitCode::from(EX_UNAVAILABLE);
            }
        };
        run_until_signal(params).await;
        ExitCode::SUCCESS
    })
}

fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|_| "cannot read config".to_owned())?;
    let raw: RawConfig = toml::from_str(&text).map_err(|_| "config parse error".to_owned())?;
    let (broker_host, broker_port) =
        split_host_port(&raw.broker).ok_or_else(|| "broker must be host:port".to_owned())?;
    if !valid_agent_id(&raw.agent_id) {
        return Err("agent_id must match [a-z0-9-]{1,64}".to_owned());
    }
    let pin = parse_pin(&raw.broker_pin)?;
    let cdp: SocketAddr = raw
        .cdp
        .parse()
        .map_err(|_| "cdp must be a loopback socket, e.g. 127.0.0.1:9222".to_owned())?;
    if !cdp.ip().is_loopback() || cdp.port() == 0 {
        return Err("cdp must be a loopback socket, e.g. 127.0.0.1:9222".to_owned());
    }
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
        broker_host: broker_host.to_owned(),
        broker_port,
        pin,
        agent_id: raw.agent_id,
        token,
        cdp,
        proxy,
        proxy_creds,
    })
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

fn read_token(path: &Path) -> Result<Zeroizing<String>, String> {
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
        return Err("token file must hold one tunnel credential".to_owned());
    }
    // An agent API token must never be sent on this socket (REQ-ARCH-001).
    if !token.starts_with("kh_tunnel_") {
        return Err(
            "token file must hold a tunnel credential (kh_tunnel_...), not an agent API token"
                .to_owned(),
        );
    }
    Ok(Zeroizing::new(token))
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

fn parse_proxy(raw: &str) -> Result<(String, u16), String> {
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

fn valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

async fn resolve(cfg: &Config) -> Result<AgentParams, String> {
    let broker = lookup(&cfg.broker_host, cfg.broker_port).await?;
    let proxy = match &cfg.proxy {
        None => None,
        Some((host, port)) => Some(lookup(host, *port).await?),
    };
    Ok(AgentParams {
        broker,
        server_name: cfg.broker_host.clone(),
        pin: cfg.pin,
        agent_id: cfg.agent_id.clone(),
        token: cfg.token.clone(),
        cdp: cfg.cdp,
        proxy,
        proxy_creds: cfg.proxy_creds.clone(),
    })
}

async fn lookup(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut it = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "cannot resolve host".to_owned())?;
    it.next().ok_or_else(|| "cannot resolve host".to_owned())
}

async fn run_until_signal(params: AgentParams) {
    let mut delay = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        tokio::select! {
            _ = shutdown() => {
                eprintln!("kharon-agent-connector: shutting down");
                return;
            }
            result = run_agent_once(&params) => {
                let lived = started.elapsed() >= Duration::from_secs(10);
                match result {
                    Err(ClientError::Unauthorized) => {
                        eprintln!(
                            "kharon-agent-connector: tunnel credentials refused; retrying in 60s"
                        );
                        if sleep_or_shutdown(Duration::from_secs(60)).await {
                            return;
                        }
                    }
                    Err(ClientError::ProxyAuth) => {
                        eprintln!(
                            "kharon-agent-connector: proxy authentication was refused; retrying in 60s"
                        );
                        if sleep_or_shutdown(Duration::from_secs(60)).await {
                            return;
                        }
                    }
                    Err(ClientError::BadCert) => {
                        eprintln!(
                            "kharon-agent-connector: broker certificate did not match broker_pin"
                        );
                        if sleep_or_shutdown(delay).await {
                            return;
                        }
                        delay = (delay * 2).min(Duration::from_secs(30));
                    }
                    Err(ClientError::CdpNotLoopback) => {
                        eprintln!("kharon-agent-connector: cdp is not a loopback socket");
                        return;
                    }
                    Ok(()) => {
                        eprintln!("kharon-agent-connector: connection ended; reconnecting");
                        delay = Duration::from_secs(1);
                        if sleep_or_shutdown(delay).await {
                            return;
                        }
                    }
                    Err(_) if lived => {
                        eprintln!("kharon-agent-connector: connection ended; reconnecting");
                        delay = Duration::from_secs(1);
                        if sleep_or_shutdown(delay).await {
                            return;
                        }
                    }
                    Err(_) => {
                        eprintln!("kharon-agent-connector: connection failed; reconnecting");
                        if sleep_or_shutdown(delay).await {
                            return;
                        }
                        delay = (delay * 2).min(Duration::from_secs(30));
                    }
                }
            }
        }
    }
}

async fn shutdown() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut int = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

async fn sleep_or_shutdown(delay: Duration) -> bool {
    tokio::select! {
        _ = shutdown() => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{load, parse_proxy};

    const SECRET: &str = "leaked-user:leaked-pass";

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "kharon-proxy-creds-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }

        fn config(&self, extra: &str) -> PathBuf {
            let token = self.file("token", b"kh_tunnel_assistant_testtoken\n", 0o600);
            let path = self.0.join("connector.toml");
            let text = format!(
                "broker = \"127.0.0.1:8788\"\n\
                 broker_pin = \"{pin}\"\n\
                 agent_id = \"assistant\"\n\
                 token_file = \"{token}\"\n\
                 cdp = \"127.0.0.1:9222\"\n\
                 {extra}\n",
                pin = "00".repeat(32),
                token = token.display(),
            );
            std::fs::write(&path, text).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn assert_secret_absent(err: &str) {
        assert!(!err.contains("leaked-pass"), "{err}");
        assert!(!err.contains("leaked-user"), "{err}");
    }

    /// `Config` is not `Debug`: it holds the tunnel token and the proxy
    /// credential, and a failed assertion must not print them.
    fn expect_err(result: Result<super::Config, String>) -> String {
        match result {
            Ok(_) => panic!("expected config error"),
            Err(err) => err,
        }
    }

    #[test]
    fn proxy_url_still_refuses_userinfo_without_echoing_it() {
        let err = parse_proxy("http://leaked-user:leaked-pass@127.0.0.1:3128").unwrap_err();
        assert!(err.contains("userinfo"));
        assert_secret_absent(&err);
        let err = parse_proxy("http://leaked-user@127.0.0.1:3128").unwrap_err();
        assert!(err.contains("userinfo"));
        assert_secret_absent(&err);
        assert_eq!(
            parse_proxy("http://127.0.0.1:3128").unwrap(),
            ("127.0.0.1".to_owned(), 3128)
        );
    }

    #[test]
    fn proxy_without_a_credential_file_stays_unauthenticated() {
        let scratch = Scratch::new();
        let cfg = load(&scratch.config("proxy = \"http://127.0.0.1:3128\"")).unwrap();
        assert_eq!(
            cfg.proxy.as_ref().map(|(h, p)| (h.as_str(), *p)),
            Some(("127.0.0.1", 3128))
        );
        assert!(cfg.proxy_creds.is_none());
    }

    #[test]
    fn proxy_credential_file_loads_one_line_at_0400_and_0600() {
        for mode in [0o400, 0o600] {
            let scratch = Scratch::new();
            let creds = scratch.file("creds", format!("{SECRET}\n").as_bytes(), mode);
            let cfg = load(&scratch.config(&format!(
                "proxy = \"http://127.0.0.1:3128\"\nproxy_creds_file = \"{}\"",
                creds.display()
            )))
            .unwrap();
            assert_eq!(
                cfg.proxy_creds.as_ref().map(|z| z.as_slice()),
                Some(SECRET.as_bytes())
            );
        }
    }

    #[test]
    fn proxy_credential_file_rejects_a_loose_mode_without_echoing_it() {
        let scratch = Scratch::new();
        let creds = scratch.file("creds", SECRET.as_bytes(), 0o644);
        let err = expect_err(load(&scratch.config(&format!(
            "proxy = \"http://127.0.0.1:3128\"\nproxy_creds_file = \"{}\"",
            creds.display()
        ))));
        assert!(err.contains("0400"));
        assert_secret_absent(&err);
    }

    #[test]
    fn proxy_credential_file_requires_proxy_and_one_line() {
        let scratch = Scratch::new();
        let creds = scratch.file("creds", SECRET.as_bytes(), 0o600);
        let err = expect_err(load(
            &scratch.config(&format!("proxy_creds_file = \"{}\"", creds.display())),
        ));
        assert!(err.contains("requires proxy"));
        assert_secret_absent(&err);

        let bad = scratch.file("bad", b"leaked-pass-without-colon\n", 0o600);
        let err = expect_err(load(&scratch.config(&format!(
            "proxy = \"http://127.0.0.1:3128\"\nproxy_creds_file = \"{}\"",
            bad.display()
        ))));
        assert!(err.contains("user:password"));
        assert!(!err.contains("leaked-pass-without-colon"), "{err}");
    }
}
