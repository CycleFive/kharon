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

const TOKEN: &str = "kh_tunnel_assistant_checktoken";

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Start the broker, write a config, run `--check`, return the outcome.
async fn run_check(upgrade_status: Option<u16>) -> Out {
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
        upgrade_status.unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let token = dir.join("token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, ca.pem()).unwrap();
    let hex: String = pin.iter().map(|b| format!("{b:02x}")).collect();
    let cfg = dir.join("connector.toml");
    std::fs::write(
        &cfg,
        format!(
            "transport = \"ws\"\n\
             broker_url = \"wss://127.0.0.1:{port}/connector\"\n\
             broker_pin = \"{hex}\"\n\
             outer_ca_file = \"{ca}\"\n\
             agent_id = \"assistant\"\n\
             token_file = \"{token}\"\n\
             cdp = \"127.0.0.1:9\"\n",
            ca = ca_file.display(),
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
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
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
    assert!(out.stdout.ends_with("check: ok\n"), "{}", out.stdout);
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
}
