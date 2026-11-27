//! Agent-host connector (path B, REQ-ARCH-001 / REQ-ARCH-002).
//!
//! Dials kharond's connector listener over outbound TLS, proves its
//! connector credential, and relays the broker's CDP traffic to loopback
//! Chromium. It holds that credential — a tunnel credential
//! (`kh_tunnel_`) or a broker-issued connector access token (`kh_at_`,
//! REQ-ARCH-002) — and, when configured, the egress proxy's password.
//! It does not hold a vault key or the account password. Token material
//! with any other prefix is refused before any dial; the broker enforces
//! the token's audience at authenticate time, so an MCP-audience token
//! is refused there before any CDP traffic.
//!
//! Two transports: `transport = "tls"` (default) dials `broker` over raw
//! pinned TLS; `transport = "ws"` dials `broker_url` (`wss://host[:port]/path`)
//! and runs the same pinned TLS inside a WebSocket, so it can pass an
//! HTTPS-only edge. `--check` walks the legs once and exits.
//!
//! Reconnects with jittered backoff until SIGINT or SIGTERM. v1 wire constants
//! live in `kharon-connector` (SPEC OQ-14).
//!
//! With no `cdp` or `cdp_url`, each CDP dial re-reads Chromium's
//! `DevToolsActivePort` (the stock Hermes preset, or a path the operator
//! set). An explicit endpoint wins. A missing or stale file fails that
//! dial with `no_browser` and does not stop the process.
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
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use backoff::{At, Backoff, Outage, err_text, fmt_dur, is_fixed_wait, leg_line_at};
use kharon_agent_connector::{Config, Dest, cdp_startup_line, load};
use kharon_connector::{AgentParams, ClientError, Leg, Transport, check_once, connect_and_auth};

/// `sysexits.h` `EX_CONFIG`.
const EX_CONFIG: u8 = 78;
/// `sysexits.h` `EX_UNAVAILABLE` — could not resolve the broker or proxy.
const EX_UNAVAILABLE: u8 = 69;
/// How long a name lookup may take before it counts as a failed `dns` leg.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Where `cfg` dials, for log lines.
fn config_at(cfg: &Config) -> At {
    let (host, port) = match &cfg.dest {
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
        proxy: cfg.proxy.as_ref().map(|(h, p)| join(h, *p)),
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
    // Once, before any dial. The Hermes preset is this process's own
    // home, so a unit that runs as `connector` must show that path here
    // or a wrong home is invisible (`--check` never opens the file).
    eprintln!(
        "kharon-agent-connector: {}",
        cdp_startup_line(cfg.cdp, cfg.devtools.as_ref())
    );
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
        let at = config_at(&cfg);
        if check {
            return run_check(&params, &at).await;
        }
        run_until_signal(params, at).await;
        ExitCode::SUCCESS
    })
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
        devtools: cfg.devtools.clone(),
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

    use kharon_agent_connector::{load, parse_proxy, parse_wss_url, read_token};

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

        /// Like [`Self::config_raw`] but the caller supplies the CDP keys.
        fn config_lines(&self, lines: &str) -> PathBuf {
            let token = self.file("token", b"kh_tunnel_assistant_testtoken\n", 0o600);
            let path = self.0.join("connector.toml");
            let text = format!(
                "broker = \"127.0.0.1:8788\"\n\
                 broker_pin = \"{pin}\"\n\
                 agent_id = \"assistant\"\n\
                 token_file = \"{token}\"\n\
                 {lines}\n",
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
    fn token_file_accepts_tunnel_and_connector_access_tokens() {
        // REQ-ARCH-002: a Connect access token (kh_at_) of connector
        // audience is a tunnel credential on wire v1, so the spawn flow's
        // token file must load exactly like a kh_tunnel_ file.
        let scratch = Scratch::new();
        for body in [b"kh_tunnel_x\n".as_slice(), b"kh_at_x\n".as_slice()] {
            let path = scratch.file("token", body, 0o600);
            assert!(read_token(&path).is_ok());
        }
    }

    #[test]
    fn token_file_refuses_other_material() {
        // REQ-ARCH-001's guarantee, with the real prefixes: an agent API
        // token (kh_agent_) or a refresh token (kh_rt_) left in the file
        // by mistake is refused before any dial, like anything else that
        // is not a connector credential.
        let scratch = Scratch::new();
        for body in [
            b"kh_agent_x\n".as_slice(),
            b"kh_rt_x\n".as_slice(),
            b"hunter2\n".as_slice(),
            b"\n".as_slice(),
        ] {
            let path = scratch.file("token", body, 0o600);
            assert!(read_token(&path).is_err());
        }
    }

    #[test]
    fn token_file_mode_check_applies_to_access_tokens() {
        let scratch = Scratch::new();
        let path = scratch.file("token", b"kh_at_x\n", 0o644);
        assert!(read_token(&path).is_err());
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

    #[test]
    fn startup_line_names_the_discovery_source() {
        let fixed: std::net::SocketAddr = "127.0.0.1:9222".parse().unwrap();
        assert_eq!(super::cdp_startup_line(fixed, None), "cdp: 127.0.0.1:9222");
        assert_eq!(
            super::cdp_startup_line(
                fixed,
                Some(&kharon_connector::DiscoverSource::HermesEphemeral {
                    home: PathBuf::from("/var/lib/kharon-connector/.hermes"),
                }),
            ),
            "cdp: discover hermes_home=/var/lib/kharon-connector/.hermes"
        );
        assert_eq!(
            super::cdp_startup_line(
                fixed,
                Some(&kharon_connector::DiscoverSource::UserDataDir(
                    PathBuf::from("/var/profile")
                )),
            ),
            "cdp: discover user_data_dir=/var/profile"
        );
        assert_eq!(
            super::cdp_startup_line(
                fixed,
                Some(&kharon_connector::DiscoverSource::File(PathBuf::from(
                    "/var/profile/DevToolsActivePort"
                ))),
            ),
            "cdp: discover devtools_active_port=/var/profile/DevToolsActivePort"
        );
    }

    #[test]
    fn explicit_cdp_wins_over_discovery() {
        let scratch = Scratch::new();
        let cfg = load(&scratch.config_lines(
            "cdp = \"127.0.0.1:9333\"\ndevtools_active_port = \"/no/such/DevToolsActivePort\"",
        ))
        .unwrap();
        assert_eq!(cfg.cdp, "127.0.0.1:9333".parse().unwrap());
        assert!(cfg.devtools.is_none());

        let cfg = load(&scratch.config_lines(
            "cdp_url = \"http://127.0.0.1:9444/devtools/browser/ignored\"\nuser_data_dir = \"/no/such\"",
        ))
        .unwrap();
        assert_eq!(cfg.cdp, "127.0.0.1:9444".parse().unwrap());
        assert!(cfg.devtools.is_none());

        let cfg = load(&scratch.config_lines("cdp_url = \"ws://[::1]:9222\"")).unwrap();
        assert_eq!(cfg.cdp, "[::1]:9222".parse().unwrap());
        assert!(cfg.devtools.is_none());
    }

    #[test]
    fn cdp_url_rejects_non_loopback_and_both_explicit_keys() {
        let scratch = Scratch::new();
        for line in [
            "cdp_url = \"http://10.1.2.3:9222\"",
            "cdp_url = \"http://localhost:9222\"",
            "cdp_url = \"https://127.0.0.1:9222\"",
            "cdp_url = \"wss://127.0.0.1:9222\"",
            "cdp = \"10.1.2.3:9222\"",
            "cdp = \"127.0.0.1:0\"",
        ] {
            let err = expect_err(load(&scratch.config_lines(line)));
            assert!(err.contains("loopback"), "{line}: {err}");
        }
        let err = expect_err(load(&scratch.config_lines(
            "cdp = \"127.0.0.1:9222\"\ncdp_url = \"http://127.0.0.1:9222\"",
        )));
        assert!(err.contains("not both"), "{err}");
    }

    #[test]
    fn omitted_endpoint_uses_the_hermes_preset_and_overrides() {
        let scratch = Scratch::new();
        let cfg = load(&scratch.config_lines("")).unwrap();
        match cfg.devtools {
            Some(kharon_connector::DiscoverSource::HermesEphemeral { home }) => {
                assert_eq!(home, kharon_connector::default_hermes_home());
            }
            other => panic!("expected the Hermes preset, got {other:?}"),
        }
        // The placeholder is loopback and is not the discovered port.
        assert!(cfg.cdp.ip().is_loopback());

        let cfg = load(&scratch.config_lines("hermes_home = \"/var/hermes\"")).unwrap();
        match cfg.devtools {
            Some(kharon_connector::DiscoverSource::HermesEphemeral { home }) => {
                assert_eq!(home, PathBuf::from("/var/hermes"));
            }
            other => panic!("expected hermes_home, got {other:?}"),
        }

        let cfg = load(&scratch.config_lines("user_data_dir = \"/var/profile\"")).unwrap();
        match cfg.devtools {
            Some(kharon_connector::DiscoverSource::UserDataDir(dir)) => {
                assert_eq!(dir, PathBuf::from("/var/profile"));
            }
            other => panic!("expected user_data_dir, got {other:?}"),
        }

        let cfg = load(
            &scratch.config_lines("devtools_active_port = \"/var/profile/DevToolsActivePort\""),
        )
        .unwrap();
        match cfg.devtools {
            Some(kharon_connector::DiscoverSource::File(path)) => {
                assert_eq!(path, PathBuf::from("/var/profile/DevToolsActivePort"));
            }
            other => panic!("expected a file, got {other:?}"),
        }
    }

    #[test]
    fn discovery_keys_are_unambiguous_and_pin_and_agent_id_still_apply() {
        let scratch = Scratch::new();
        let err = expect_err(load(
            &scratch.config_lines("devtools_active_port = \"/a\"\nuser_data_dir = \"/b\""),
        ));
        assert!(err.contains("not both"), "{err}");
        let err = expect_err(load(
            &scratch.config_lines("hermes_home = \"/h\"\ndevtools_active_port = \"/a\""),
        ));
        assert!(err.contains("hermes_home"), "{err}");

        let path = scratch.0.join("bad-id.toml");
        let token = scratch.file("token2", b"kh_tunnel_assistant_testtoken\n", 0o600);
        std::fs::write(
            &path,
            format!(
                "broker = \"127.0.0.1:8788\"\n\
                 broker_pin = \"{pin}\"\n\
                 agent_id = \"Not-Valid\"\n\
                 token_file = \"{token}\"\n",
                pin = "00".repeat(32),
                token = token.display(),
            ),
        )
        .unwrap();
        let err = expect_err(load(&path));
        assert!(err.contains("agent_id"), "{err}");

        let path = scratch.0.join("bad-pin.toml");
        std::fs::write(
            &path,
            format!(
                "broker = \"127.0.0.1:8788\"\n\
                 broker_pin = \"abcd\"\n\
                 agent_id = \"assistant\"\n\
                 token_file = \"{token}\"\n\
                 user_data_dir = \"/var/profile\"\n",
                token = token.display(),
            ),
        )
        .unwrap();
        let err = expect_err(load(&path));
        assert!(err.contains("broker_pin"), "{err}");
    }
}
