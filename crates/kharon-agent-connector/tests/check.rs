//! #199 Task 3: `--check` exit codes against an in-test WebSocket broker.
//!
//! The outer TLS cert comes from a throwaway CA that the binary trusts
//! through the test-only `outer_ca_file` key; outer verification stays on.

#![allow(clippy::result_large_err)] // tungstenite's callback signature

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use kharon_connector::{
    AUTH_OK, TlsVersions, WS_SUBPROTOCOL, WsByteStream, pin_of_der, read_client_hello,
    server_config_from_pem, server_config_from_pem_with, write_server_hello, ws_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey, IsCa, KeyPair, generate_simple_self_signed,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const TOKEN: &str = "kh_tunnel_assistant_checktoken";

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Start the broker, write a config, run `--check`, return the outcome.
async fn run_check(upgrade_status: Option<u16>) -> Out {
    run_check_to(upgrade_status, None).await
}

/// `url_override` replaces the `broker_url` (the server still starts).
async fn run_check_to(upgrade_status: Option<u16>, url_override: Option<&str>) -> Out {
    run_check_with(upgrade_status, url_override, false, false).await
}

/// `other_ca` makes the binary trust a CA that did not sign the broker's
/// outer certificate. `follow` runs the real reconnect loop (no `--check`)
/// until it logs that its first session ended, then kills it.
async fn run_check_with(
    upgrade_status: Option<u16>,
    url_override: Option<&str>,
    other_ca: bool,
    follow: bool,
) -> Out {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    let outer_cfg =
        server_config_from_pem(leaf.pem().as_bytes(), leaf_key.serialize_pem().as_bytes()).unwrap();
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let inner_cfg = server_config_from_pem_with(
        cert.pem().as_bytes(),
        key_pair.serialize_pem().as_bytes(),
        TlsVersions::Tls13Only,
    )
    .unwrap();
    let pin = pin_of_der(cert.der());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let outer = tokio_rustls::TlsAcceptor::from(outer_cfg);
    let inner = tokio_rustls::TlsAcceptor::from(inner_cfg);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let (outer, inner) = (outer.clone(), inner.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = outer.accept(tcp).await else {
                    return;
                };
                if let Some(code) = upgrade_status {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        if tls.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        buf.push(b[0]);
                    }
                    let resp = format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n");
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                    return;
                }
                let cb = |_: &Request, mut resp: Response| {
                    resp.headers_mut()
                        .insert("sec-websocket-protocol", WS_SUBPROTOCOL.parse().unwrap());
                    Ok(resp)
                };
                let Ok(ws) =
                    tokio_tungstenite::accept_hdr_async_with_config(tls, cb, Some(ws_config()))
                        .await
                else {
                    return;
                };
                let Ok(mut s) = inner.accept(WsByteStream::new(ws)).await else {
                    return;
                };
                let Ok(hello) = read_client_hello(&mut s).await else {
                    return;
                };
                if hello.token.as_str() == TOKEN {
                    let _ = write_server_hello(&mut s, AUTH_OK).await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });

    let dir: PathBuf = std::env::temp_dir().join(format!(
        "kharon-check-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let token = dir.join("token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ca_file = dir.join("ca.pem");
    if other_ca {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        // A different subject, so the chain has no issuer match at all.
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "some other ca");
        std::fs::write(&ca_file, params.self_signed(&key).unwrap().pem()).unwrap();
    } else {
        std::fs::write(&ca_file, ca.pem()).unwrap();
    }
    let hex: String = pin.iter().map(|b| format!("{b:02x}")).collect();
    let cfg = dir.join("connector.toml");
    std::fs::write(
        &cfg,
        format!(
            "transport = \"ws\"\n\
             broker_url = \"{url}\"\n\
             broker_pin = \"{hex}\"\n\
             outer_ca_file = \"{ca}\"\n\
             agent_id = \"assistant\"\n\
             token_file = \"{token}\"\n\
             cdp = \"127.0.0.1:9\"\n",
            url = url_override
                .map(str::to_owned)
                .unwrap_or_else(|| format!("wss://127.0.0.1:{port}/connector")),
            ca = ca_file.display(),
            token = token.display(),
        ),
    )
    .unwrap();

    let cfg2 = cfg.clone();
    if follow {
        let stderr = tokio::task::spawn_blocking(move || follow_until_session_ends(&cfg2))
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        return Out {
            code: None,
            stdout: String::new(),
            stderr,
        };
    }
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_kharon-agent-connector"))
            .arg("--check")
            .arg("--config")
            .arg(&cfg2)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Run the connector's own loop and return its stderr up to and including
/// the first "session ended" line (or whatever it printed in 20 s).
fn follow_until_session_ends(cfg: &std::path::Path) -> String {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let mut child = Command::new(env!("CARGO_BIN_EXE_kharon-agent-connector"))
        .arg("--config")
        .arg(cfg)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let pid = child.id();
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(20));
        let _ = Command::new("kill").arg(pid.to_string()).status();
    });
    let mut seen = String::new();
    for line in BufReader::new(stderr).lines() {
        let Ok(line) = line else { break };
        seen.push_str(&line);
        seen.push('\n');
        if line.contains("session ended") {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    drop(watchdog);
    seen
}

#[tokio::test(flavor = "multi_thread")]
async fn check_exits_0_on_auth() {
    let out = run_check(None).await;
    assert_eq!(out.code, Some(0), "{} / {}", out.stdout, out.stderr);
    for leg in ["tcp", "outer-tls", "upgrade", "inner-tls", "auth"] {
        assert!(
            out.stdout.contains(&format!("ok {leg}\n")),
            "{}",
            out.stdout
        );
    }
    assert!(
        out.stdout.ends_with(
            "ok auth\n\
             note: a successful check replaces this agent's live broker session\n\
             check: ok\n"
        ),
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains(TOKEN) && !out.stderr.contains(TOKEN));
}

#[tokio::test(flavor = "multi_thread")]
async fn check_exits_69_and_names_upgrade_on_502() {
    let out = run_check(Some(502)).await;
    assert_eq!(out.code, Some(69), "{} / {}", out.stdout, out.stderr);
    assert!(
        out.stdout
            .contains("fail upgrade: websocket upgrade answered 502\n"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.ends_with("check: failed\n"), "{}", out.stdout);
    assert!(!out.stdout.contains(TOKEN) && !out.stderr.contains(TOKEN));
}

/// ws without a proxy resolves inside `check_once`, so this exercises the
/// client's own Dns leg.
#[tokio::test(flavor = "multi_thread")]
async fn check_exits_69_and_names_dns_on_unresolvable_host() {
    let out = run_check_to(None, Some("wss://kharon.invalid/connector")).await;
    assert_eq!(out.code, Some(69), "{} / {}", out.stdout, out.stderr);
    assert!(
        out.stdout
            .contains("fail dns: cannot resolve the broker host (kharon.invalid)\n"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.ends_with("check: failed\n"), "{}", out.stdout);
    assert!(!out.stdout.contains(TOKEN) && !out.stderr.contains(TOKEN));
}

/// The outer certificate is signed by a CA the binary does not trust: the
/// line names the WebPKI class as fixed text.
#[tokio::test(flavor = "multi_thread")]
async fn check_names_the_outer_tls_class() {
    let out = run_check_with(None, None, true, false).await;
    assert_eq!(out.code, Some(69), "{} / {}", out.stdout, out.stderr);
    assert!(
        out.stdout
            .contains("fail outer-tls: outer TLS to the broker host failed: untrusted issuer\n"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.ends_with("check: failed\n"), "{}", out.stdout);
}

/// The tcp leg names the address it dialed.
#[tokio::test(flavor = "multi_thread")]
async fn check_names_the_tcp_address() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let out = run_check_to(None, Some(&format!("wss://127.0.0.1:{port}/connector"))).await;
    assert_eq!(out.code, Some(69), "{} / {}", out.stdout, out.stderr);
    assert!(
        out.stdout.contains(&format!(
            "fail tcp: tcp connect failed (connection refused) to 127.0.0.1:{port}\n"
        )),
        "{}",
        out.stdout
    );
}

/// `transport = "tls"` resolves the broker in the binary before any dial:
/// an unresolvable host prints the dns failure naming it, then fails.
#[tokio::test(flavor = "multi_thread")]
async fn tls_check_names_an_unresolvable_broker_host() {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "kharon-check-tls-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let token = dir.join("token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let cfg = dir.join("connector.toml");
    std::fs::write(
        &cfg,
        format!(
            "transport = \"tls\"\n\
             broker = \"broker.invalid:8789\"\n\
             broker_pin = \"{pin}\"\n\
             agent_id = \"assistant\"\n\
             token_file = \"{token}\"\n\
             cdp = \"127.0.0.1:9\"\n",
            pin = "00".repeat(32),
            token = token.display(),
        ),
    )
    .unwrap();
    let cfg2 = cfg.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_kharon-agent-connector"))
            .arg("--check")
            .arg("--config")
            .arg(&cfg2)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(69), "{stdout}");
    assert_eq!(
        stdout,
        "fail dns: cannot resolve the broker host (broker.invalid)\ncheck: failed\n"
    );
    assert!(!stdout.contains(TOKEN));
}

/// The reconnect loop says how long the session lasted.
#[tokio::test(flavor = "multi_thread")]
async fn session_end_line_carries_the_duration() {
    let out = run_check_with(None, None, false, true).await;
    assert!(
        out.stderr
            .contains("kharon-agent-connector: session ended after 0s; reconnecting\n"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("connection ended"), "{}", out.stderr);
}
