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
//! Two transports: `transport = "tls"` (default) dials `broker` over raw
//! pinned TLS; `transport = "ws"` dials `broker_url` (`wss://host[:port]/path`)
//! and runs the same pinned TLS inside a WebSocket, so it can pass an
//! HTTPS-only edge. `--check` walks the legs once and exits.
//!
//! Reconnects with jittered backoff until SIGINT or SIGTERM. v1 wire constants
//! live in `kharon-connector` (SPEC OQ-14).
//!
//! An optional HTTP CONNECT proxy is `http://host:port` with no
//! userinfo. When that proxy requires authentication,
//! `proxy_creds_file` is a mode `0400` or `0600` file of one
//! `user:password` line (a trailing newline is ignored). The connector
//! sends it only as `Proxy-Authorization` on the CONNECT. It is not
//! taken from the proxy URL or argv, and it is never logged.

#![forbid(unsafe_code)]

mod backoff;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use backoff::{At, Backoff, Outage, err_text, fmt_dur, is_fixed_wait, leg_line_at};
use kharon_connector::{
    AgentParams, ClientError, Leg, Transport, check_once, connect_and_auth, proxy_creds_line,
};
use serde::Deserialize;
use zeroize::Zeroizing;

/// `sysexits.h` `EX_CONFIG`.
const EX_CONFIG: u8 = 78;
/// `sysexits.h` `EX_UNAVAILABLE` — could not resolve the broker or proxy.
const EX_UNAVAILABLE: u8 = 69;
/// How long a name lookup may take before it counts as a failed `dns` leg.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

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
    cdp: String,
    /// `http://host:port` with no userinfo. A password does not belong here.
    #[serde(default)]
    proxy: Option<String>,
    /// One `user:password` line. Same mode rule as `token_file`.
    #[serde(default)]
    proxy_creds_file: Option<PathBuf>,
}

enum Dest {
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

struct Config {
    dest: Dest,
    server_name: String,
    outer_roots: Option<Arc<rustls::RootCertStore>>,
    pin: kharon_connector::CertSha256,
    agent_id: String,
    token: Zeroizing<String>,
    cdp: SocketAddr,
    proxy: Option<(String, u16)>,
    proxy_creds: Option<Zeroizing<Vec<u8>>>,
}

impl Config {
    fn at(&self) -> At {
        let (host, port) = match &self.dest {
            Dest::Tls { host, port } | Dest::Ws { host, port, .. } => (host, *port),
        };
        let join = |h: &str, p: u16| {
            if h.contains(':') {
                format!("[{h}]:{p}")
            } else {
                format!("{h}:{p}")
            }
        };
        At {
            host: host.clone(),
            broker: join(host, port),
            proxy: self.proxy.as_ref().map(|(h, p)| join(h, *p)),
        }
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut path = PathBuf::from("/etc/kharon-connector/connector.toml");
    let mut check = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => match args.next() {
                Some(p) => path = PathBuf::from(p),
                None => {
                    eprintln!("kharon-agent-connector: --config needs a path");
                    return ExitCode::from(EX_CONFIG);
                }
            },
            "--check" => check = true,
            "--help" | "-h" => {
                eprintln!(
                    "kharon-agent-connector [--check] --config /etc/kharon-connector/connector.toml"
                );
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
            Err(msg) if check => {
                println!("fail dns: {msg}");
                println!("check: failed");
                return ExitCode::from(EX_UNAVAILABLE);
            }
            Err(msg) => {
                eprintln!("kharon-agent-connector: {msg}");
                return ExitCode::from(EX_UNAVAILABLE);
            }
        };
        let at = cfg.at();
        if check {
            return run_check(&params, &at).await;
        }
        run_until_signal(params, at).await;
        ExitCode::SUCCESS
    })
}

fn load(path: &Path) -> Result<Config, String> {
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
    let server_name = match raw.server_name {
        Some(n) if n.trim().is_empty() => return Err("server_name must not be empty".to_owned()),
        Some(n) => n,
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
        dest,
        server_name,
        outer_roots,
        pin,
        agent_id: raw.agent_id,
        token,
        cdp,
        proxy,
        proxy_creds,
    })
}

/// `wss://host[:port][/path]` -> (host, port, path). Only `wss`; no
/// userinfo, query or fragment. Port defaults to 443, path to `/connector`.
fn parse_wss_url(raw: &str) -> Result<(String, u16, String), String> {
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
    let proxy = match &cfg.proxy {
        None => None,
        Some((host, port)) => Some(lookup(host, *port, "proxy").await?),
    };
    // Through a proxy the proxy resolves the broker host; with `ws` the
    // dial resolves it, so there is nothing to look up here.
    let transport = match &cfg.dest {
        Dest::Tls { host, port } => Transport::Tls {
            broker: lookup(host, *port, "broker").await?,
            host: Some(host.clone()),
        },
        Dest::Ws { host, port, path } => Transport::Ws {
            host: host.clone(),
            port: *port,
            path: path.clone(),
            outer_tls: true,
        },
    };
    Ok(AgentParams {
        transport,
        server_name: cfg.server_name.clone(),
        pin: cfg.pin,
        agent_id: cfg.agent_id.clone(),
        token: cfg.token.clone(),
        cdp: cfg.cdp,
        proxy,
        proxy_creds: cfg.proxy_creds.clone(),
        outer_roots: cfg.outer_roots.clone(),
    })
}

/// Resolve `host`, which is the `what` host ("broker" or "proxy") in the
/// failure text. A lookup that hangs fails after [`LOOKUP_TIMEOUT`].
async fn lookup(host: &str, port: u16, what: &str) -> Result<SocketAddr, String> {
    let fail = || format!("cannot resolve the {what} host ({host})");
    let mut it = tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| fail())?
        .map_err(|_| fail())?;
    it.next().ok_or_else(fail)
}

/// `--check`: one pass over the legs. Exit 0 only when auth succeeded.
async fn run_check(params: &AgentParams, at: &At) -> ExitCode {
    let legs = check_once(params).await;
    let mut authed = false;
    for (leg, result) in &legs {
        match result {
            Ok(()) => {
                println!("ok {}", leg_label(*leg));
                if *leg == Leg::Auth {
                    authed = true;
                    // Wire v1 has no probe that leaves a live session alone.
                    println!("note: a successful check replaces this agent's live broker session");
                }
            }
            Err(e) => println!("fail {}: {}", leg_label(*leg), err_text(e, at)),
        }
    }
    if authed {
        println!("check: ok");
        ExitCode::SUCCESS
    } else {
        println!("check: failed");
        ExitCode::from(EX_UNAVAILABLE)
    }
}

fn leg_label(leg: Leg) -> &'static str {
    match leg {
        Leg::Dns => "dns",
        Leg::Tcp => "tcp",
        Leg::Proxy => "proxy",
        Leg::OuterTls => "outer-tls",
        Leg::Upgrade => "upgrade",
        Leg::InnerTls => "inner-tls",
        Leg::Auth => "auth",
    }
}

/// One connection: dial, auth, then serve. `authed_at` is set once
/// `AUTH_OK` arrived.
async fn session(
    params: &AgentParams,
    outage: &mut Outage,
    authed_at: &mut Option<Instant>,
) -> Result<(), ClientError> {
    let sess = connect_and_auth(params).await?;
    outage.on_auth();
    *authed_at = Some(Instant::now());
    eprintln!("kharon-agent-connector: authenticated");
    sess.serve().await
}

async fn run_until_signal(params: AgentParams, at: At) {
    let mut backoff = Backoff::default();
    let mut outage = Outage::default();
    let mut rng = rand::thread_rng();
    loop {
        let mut authed_at = None;
        let result = tokio::select! {
            _ = shutdown() => {
                eprintln!("kharon-agent-connector: shutting down");
                return;
            }
            r = session(&params, &mut outage, &mut authed_at) => r,
        };
        let lived = authed_at.is_some_and(|t| t.elapsed() >= Duration::from_secs(10));
        // Anything that ends without an authenticated session counts toward
        // the outage summary, whatever the variant.
        if authed_at.is_none()
            && !matches!(result, Err(ClientError::CdpNotLoopback))
            && let Some(line) = outage.on_failure(
                Instant::now(),
                result.as_ref().err().unwrap_or(&ClientError::Disconnected),
                &at,
            )
        {
            eprintln!("{line}");
        }
        let wait = match result {
            Err(ClientError::CdpNotLoopback) => {
                eprintln!("kharon-agent-connector: cdp is not a loopback socket");
                return;
            }
            Ok(()) | Err(ClientError::Disconnected) => {
                match authed_at {
                    Some(t) => eprintln!(
                        "kharon-agent-connector: session ended after {}; reconnecting",
                        fmt_dur(t.elapsed())
                    ),
                    None => eprintln!("kharon-agent-connector: connection ended; reconnecting"),
                }
                if lived {
                    backoff.reset();
                }
                backoff.next(&mut rng)
            }
            Err(e) => {
                eprintln!("kharon-agent-connector: {}", leg_line_at(&e, &at));
                if authed_at.is_some() {
                    // Authenticated, then failed mid-session: the outage
                    // clock was just reset by `on_auth`.
                    if lived {
                        backoff.reset();
                    }
                }
                if is_fixed_wait(&e) {
                    eprintln!("kharon-agent-connector: retrying in 60s");
                    Duration::from_secs(60)
                } else {
                    backoff.next(&mut rng)
                }
            }
        };
        if sleep_or_shutdown(wait).await {
            return;
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

    use super::{load, parse_proxy, parse_wss_url};

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

        /// A config body with no `broker` line: the test supplies the transport keys.
        fn config_raw(&self, keys: &str) -> PathBuf {
            let token = self.file("token", b"kh_tunnel_assistant_testtoken\n", 0o600);
            let path = self.0.join("connector.toml");
            let text = format!(
                "broker_pin = \"{pin}\"\n\
                 agent_id = \"assistant\"\n\
                 token_file = \"{token}\"\n\
                 cdp = \"127.0.0.1:9222\"\n\
                 {keys}\n",
                pin = "00".repeat(32),
                token = token.display(),
            );
            std::fs::write(&path, text).unwrap();
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

    #[test]
    fn config_ws_requires_wss_url() {
        let scratch = Scratch::new();
        for keys in [
            "transport = \"ws\"",
            "transport = \"ws\"\nbroker_url = \"https://h.example/connector\"",
            "transport = \"ws\"\nbroker_url = \"ws://h.example/connector\"",
            "transport = \"ws\"\nbroker_url = \"wss://u:p@h.example/connector\"",
        ] {
            let err = expect_err(load(&scratch.config_raw(keys)));
            assert!(err.contains("broker_url"), "{err}");
            assert_secret_absent(&err);
        }
        let cfg = load(&scratch.config_raw(
            "transport = \"ws\"\nbroker_url = \"wss://h.example:8443/x/y\"\nserver_name = \"n.example\"",
        ))
        .unwrap();
        assert_eq!(cfg.server_name, "n.example");
        match cfg.dest {
            super::Dest::Ws { host, port, path } => {
                assert_eq!(
                    (host.as_str(), port, path.as_str()),
                    ("h.example", 8443, "/x/y")
                );
            }
            super::Dest::Tls { .. } => panic!("expected ws"),
        }
        assert_eq!(
            parse_wss_url("wss://h.example").unwrap(),
            ("h.example".to_owned(), 443, "/connector".to_owned())
        );
        assert_eq!(
            parse_wss_url("wss://[::1]:9/c").unwrap(),
            ("::1".to_owned(), 9, "/c".to_owned())
        );
        assert!(parse_wss_url("wss://h.example/p?q=1").is_err());
    }

    #[test]
    fn config_ws_refuses_broker_key() {
        let scratch = Scratch::new();
        let err = expect_err(load(&scratch.config_raw(
            "transport = \"ws\"\nbroker = \"127.0.0.1:8789\"\nbroker_url = \"wss://h.example/connector\"",
        )));
        assert!(err.contains("broker"), "{err}");
    }

    #[test]
    fn config_tls_refuses_broker_url() {
        let scratch = Scratch::new();
        let err = expect_err(load(&scratch.config_raw(
            "broker = \"127.0.0.1:8789\"\nbroker_url = \"wss://h.example/connector\"",
        )));
        assert!(err.contains("broker_url"), "{err}");
        let err = expect_err(load(&scratch.config_raw(
            "transport = \"tls\"\nbroker = \"127.0.0.1:8789\"\nouter_ca_file = \"/nonexistent\"",
        )));
        assert!(err.contains("outer_ca_file"), "{err}");
    }
}
