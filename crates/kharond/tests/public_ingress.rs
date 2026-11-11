//! #198 public ingress (decision record on #197): the listener a public
//! edge (cloudflared for `kharon.twkr.io`) forwards to serves
//! `POST /mcp` and nothing else, independent of the edge's own rules.
//! The tailnet `/v1/*` API, the OpenAPI document, the owner UI and
//! redeem routes, health probes and other methods all answer the fixed
//! 404, and the config refuses the shapes that would put it on the
//! wrong address or in the clear.
//! The example cloudflared config in `deploy/cloudflared` is checked
//! too: it routes `^/mcp$` and `^/connector$` and 404s the rest.

mod api_support;

use std::path::Path;
use std::sync::Arc;

use api_support::{Harness, TestBroker, get, mcp_call, mcp_request, raw_request};
use kharond::api::token::generate;
use kharond::config::{Config, StaticMlockProbe};
use kharond::connector::connect_pinned;
use kharond::daemon;
use kharond::lock::StaticHardening;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TOKEN_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo";

/// Every request the edge must not pass and the daemon refuses anyway:
/// `(method, target)`. Bodies, when any, are empty JSON objects.
const REFUSED: &[(&str, &str)] = &[
    ("GET", "/"),
    ("GET", "/ui"),
    ("GET", "/healthz"),
    ("GET", "/v1/status"),
    ("GET", "/v1/items"),
    ("GET", "/v1/items?q=canary"),
    ("GET", "/v1/openapi.json"),
    ("POST", "/v1/fill"),
    ("POST", "/v1/fill_totp"),
    ("POST", "/v1/context"),
    ("POST", "/v1/grants"),
    ("GET", "/owner/session"),
    ("POST", "/owner/unlock"),
    ("GET", "/owner/approve/abc"),
    ("GET", "/mcp"),
    ("DELETE", "/mcp"),
    ("POST", "/mcp/"),
    ("GET", "/connector"),
    ("POST", "/connector"),
];

async fn serve_public(broker: Arc<TestBroker>) -> std::net::SocketAddr {
    serve_public_for(broker, None).await
}

async fn serve_public_for(
    broker: Arc<TestBroker>,
    public_host: Option<&str>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::public::serve_with_shutdown(
        listener,
        broker,
        None,
        public_host.map(Arc::from),
        std::future::pending(),
    ));
    addr
}

fn request(method: &str, target: &str, token: Option<&str>) -> String {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let body = if method == "POST" { "{}" } else { "" };
    format!(
        "{method} {target} HTTP/1.1\r\nHost: kharon.twkr.io\r\n{auth}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn assert_not_found(status: u16, body: &str, what: &str) {
    assert_eq!(status, 404, "{what}: {body}");
    let v: Value = serde_json::from_str(body).unwrap_or_else(|e| panic!("{what}: {e}: {body}"));
    assert_eq!(
        v,
        json!({"error": "not_found", "detail": "no such route"}),
        "{what}"
    );
}

#[tokio::test]
async fn public_ingress_serves_mcp_like_the_api_listener() {
    let h = Harness::new(false);
    let addr = serve_public(h.broker.clone()).await;

    let r = mcp_request(addr, Some(&h.alpha), "tools/list", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["result"]["tools"].as_array().unwrap().len(), 7);

    let r = mcp_call(addr, Some(&h.alpha), "kharon_status", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let text = r.json()["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .to_owned();
    let status: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(status["agent_id"], "alpha");
    assert_eq!(status["locked"], false);

    // Same gate as on [api]: no token, no dispatch.
    let r = mcp_request(addr, None, "tools/list", "{}").await;
    assert_eq!(r.status, 401, "{}", r.body);
    let r = mcp_request(addr, Some("kh_agent_alpha_nope"), "tools/list", "{}").await;
    assert_eq!(r.status, 401, "{}", r.body);
}

#[tokio::test]
async fn public_ingress_refuses_everything_else_even_with_a_valid_token() {
    let h = Harness::new(false);
    let addr = serve_public(h.broker.clone()).await;
    for (method, target) in REFUSED {
        for token in [None, Some(h.alpha.as_str())] {
            let r = raw_request(addr, request(method, target, token).as_bytes()).await;
            assert_not_found(
                r.status,
                &r.body,
                &format!("{method} {target} (token: {})", token.is_some()),
            );
        }
    }
    // The tailnet listener still serves the same token on /v1/status:
    // the 404s above are the listener's allow-list, not a dead broker.
    let api = api_support::serve_http(h.broker.clone()).await;
    assert_eq!(get(api, "/v1/status", Some(&h.alpha)).await.status, 200);
}

#[tokio::test]
async fn public_host_refuses_a_foreign_host_with_the_uniform_404() {
    let h = Harness::new(false);
    let with_host = |host: &str, method: &str, target: &str| {
        let body = if method == "POST" { "{}" } else { "" };
        format!(
            "{method} {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };

    let addr = serve_public_for(h.broker.clone(), Some("kharon.example.com")).await;
    let unknown = raw_request(
        addr,
        with_host("kharon.example.com", "GET", "/nope").as_bytes(),
    )
    .await;
    assert_not_found(unknown.status, &unknown.body, "GET /nope");
    let foreign = raw_request(
        addr,
        with_host("evil.example.com", "POST", "/mcp").as_bytes(),
    )
    .await;
    assert_not_found(foreign.status, &foreign.body, "foreign Host");
    assert_eq!(foreign.body, unknown.body, "the same 404 body");
    for host in ["kharon.example.com", "KHARON.example.com:443"] {
        let r = raw_request(addr, with_host(host, "POST", "/mcp").as_bytes()).await;
        assert_eq!(r.status, 401, "{host}: {}", r.body);
    }

    // No public_host: any Host reaches auth.
    let addr = serve_public_for(h.broker.clone(), None).await;
    let r = raw_request(
        addr,
        with_host("evil.example.com", "POST", "/mcp").as_bytes(),
    )
    .await;
    assert_eq!(r.status, 401, "{}", r.body);
}

/// An export-mode config with `[api]` on loopback and `public` appended.
fn config(hash: &str, data_dir: &Path, public: &str) -> String {
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.assistant]
token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9222" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"

{public}"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        )
    )
}

fn public(listen: &str, tls: Option<(&Path, &Path)>) -> String {
    let keys = tls
        .map(|(c, k)| {
            format!(
                "tls_cert_file = \"{}\"\ntls_key_file = \"{}\"\n",
                c.display(),
                k.display()
            )
        })
        .unwrap_or_default();
    format!("[public_ingress]\nlisten = \"{listen}\"\n{keys}")
}

fn write_cert(dir: &Path) -> ([u8; 32], std::path::PathBuf, std::path::PathBuf) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let pin = kharond::connector::pin_of_der(cert.der());
    let cert_path = dir.join("tls.crt");
    let key_path = dir.join("tls.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (pin, cert_path, key_path)
}

#[test]
fn public_ingress_config_refuses_wildcards_cleartext_and_shared_sockets() {
    let data = Path::new("/data");
    let tls = Some((Path::new("/tmp/c.pem"), Path::new("/tmp/k.pem")));
    let code = |text: String| Config::from_toml_str(&text).unwrap_err().code();

    for addr in ["0.0.0.0:8790", "[::]:8790", "[::ffff:0.0.0.0]:8790"] {
        assert_eq!(
            code(config(TOKEN_HASH, data, &public(addr, tls))),
            "public_ingress_wildcard_bind",
            "{addr}"
        );
    }
    assert_eq!(
        code(config(TOKEN_HASH, data, &public("224.0.0.1:8790", tls))),
        "public_ingress_listen_not_unicast"
    );
    assert_eq!(
        code(config(TOKEN_HASH, data, &public("kharon.twkr.io:443", tls))),
        "public_ingress_listen_invalid"
    );
    // Off loopback the hop from the edge must be TLS.
    assert_eq!(
        code(config(TOKEN_HASH, data, &public("100.64.0.1:8790", None))),
        "public_ingress_plain_http_non_loopback"
    );
    let half = public("100.64.0.1:8790", None) + "tls_cert_file = \"/tmp/c.pem\"\n";
    assert_eq!(
        code(config(TOKEN_HASH, data, &half)),
        "tls_material_incomplete"
    );
    // One socket per listener.
    let api_fixed = config(TOKEN_HASH, data, &public("127.0.0.1:8787", None))
        .replace("listen = \"127.0.0.1:0\"", "listen = \"127.0.0.1:8787\"");
    assert_eq!(code(api_fixed), "public_ingress_listen_conflict");
    let ui = public("127.0.0.1:8788", None)
        + "\n[owner_ui]\nlisten = \"127.0.0.1:8788\"\norigin = \"http://localhost:8788\"\n";
    assert_eq!(
        code(config(TOKEN_HASH, data, &ui)),
        "public_ingress_listen_conflict"
    );
    let unknown = public("127.0.0.1:8790", None) + "serve_v1 = true\n";
    assert_eq!(code(config(TOKEN_HASH, data, &unknown)), "parse");

    // Accepted shapes: TLS on a tailnet address, plain HTTP on loopback.
    let cfg =
        Config::from_toml_str(&config(TOKEN_HASH, data, &public("100.64.0.1:8790", tls))).unwrap();
    let p = cfg.public_ingress.unwrap();
    assert_eq!(p.listen, "100.64.0.1:8790".parse().unwrap());
    assert!(p.tls.is_some());
    let cfg =
        Config::from_toml_str(&config(TOKEN_HASH, data, &public("127.0.0.1:8790", None))).unwrap();
    assert!(cfg.public_ingress.unwrap().tls.is_none());
    let cfg = Config::from_toml_str(&config(TOKEN_HASH, data, "")).unwrap();
    assert!(cfg.public_ingress.is_none());
}

#[test]
fn public_ingress_tls_material_checked_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let (_pin, cert, key) = write_cert(dir.path());
    let data = dir.path().join("data");
    let text = config(
        TOKEN_HASH,
        &data,
        &public("100.64.0.1:8790", Some((&cert, &key))),
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    cfg.check_startup(&StaticMlockProbe(Ok(()))).unwrap();
    let broken = text.replace(&key.display().to_string(), "/tmp/does-not-exist.pem");
    let cfg = Config::from_toml_str(&broken).unwrap();
    assert_eq!(
        cfg.check_startup(&StaticMlockProbe(Ok(())))
            .unwrap_err()
            .code(),
        "tls_material"
    );
}

async fn tls_roundtrip(addr: std::net::SocketAddr, pin: [u8; 32], req: &str) -> String {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = connect_pinned("127.0.0.1", pin, tcp).await.unwrap();
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn public_ingress_daemon_serves_mcp_over_pinned_tls_and_nothing_else() {
    let (token, hash) = generate("assistant");
    let token = token.expose_secret().clone();
    let dir = tempfile::tempdir().unwrap();
    let (pin, cert, key) = write_cert(dir.path());
    let data = dir.path().join("data");
    let text = config(&hash, &data, &public("127.0.0.3:0", Some((&cert, &key))));
    let cfg = Config::from_toml_str(&text).unwrap();
    let daemon = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let api = daemon.local_addr().unwrap();
    let public_addr = daemon.public_ingress_addr().expect("public ingress bound");
    assert_eq!(public_addr.ip().to_string(), "127.0.0.3");
    assert_ne!(public_addr, api);
    assert!(daemon.public_ingress_tls());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(daemon.run(async {
        let _ = stopped.await;
    }));

    // `kharon_status` over MCP on the public listener: booted locked.
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"kharon_status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: kharon.twkr.io\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: kharon_status\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let out = tls_roundtrip(public_addr, pin, &req).await;
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains(r#"\"locked\":true"#), "{out}");

    // The token that works on /mcp gets 404 on the tailnet routes.
    for (method, target) in REFUSED {
        let out = tls_roundtrip(public_addr, pin, &request(method, target, Some(&token))).await;
        assert!(out.starts_with("HTTP/1.1 404"), "{method} {target}: {out}");
        assert!(out.contains(r#""detail":"no such route""#), "{out}");
    }

    // Plain HTTP on the TLS listener fails the handshake.
    let mut plain = tokio::net::TcpStream::connect(public_addr).await.unwrap();
    plain
        .write_all(request("POST", "/mcp", Some(&token)).as_bytes())
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = plain.read(&mut buf).await.unwrap_or(0);
    assert!(!String::from_utf8_lossy(&buf[..n]).contains("HTTP/1.1"));

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

/// A public client that never finishes its request (and, after #199, a
/// WebSocket that never closes) cannot hold daemon shutdown open: the
/// public listener gets [`daemon::PUBLIC_INGRESS_DRAIN`] to drain, then
/// it is aborted.
#[tokio::test(flavor = "multi_thread")]
async fn public_ingress_open_connection_cannot_stall_shutdown() {
    let (_token, hash) = generate("assistant");
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let text = config(&hash, &data, &public("127.0.0.3:0", None));
    let cfg = Config::from_toml_str(&text).unwrap();
    let daemon = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let public_addr = daemon.public_ingress_addr().expect("public ingress bound");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(daemon.run(async {
        let _ = stopped.await;
    }));

    // Headers that never end: hyper keeps waiting for the rest.
    let mut held = tokio::net::TcpStream::connect(public_addr).await.unwrap();
    held.write_all(b"POST /mcp HTTP/1.1\r\nHost: kharon.twkr.io\r\n")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let started = std::time::Instant::now();
    stop.send(()).unwrap();
    let budget = daemon::PUBLIC_INGRESS_DRAIN + std::time::Duration::from_secs(5);
    tokio::time::timeout(budget, server)
        .await
        .expect("daemon shutdown waited on an open public connection")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= daemon::PUBLIC_INGRESS_DRAIN / 2);
    drop(held);
}

/// What is wrong with a cloudflared config's ingress, if anything: a
/// line-based read of the shape `deploy/cloudflared/config.yml` uses
/// (each rule starts with `- `; keys `hostname`, `path`, `service`).
fn cloudflared_problems(yml: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut rules: Vec<Vec<(String, String)>> = Vec::new();
    let mut in_ingress = false;
    for line in yml.lines() {
        let code = line.split(" #").next().unwrap_or("").trim_end();
        let trimmed = code.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed
            .replace(' ', "")
            .eq_ignore_ascii_case("noTLSVerify:true")
        {
            problems.push("noTLSVerify: true".to_owned());
        }
        if !code.starts_with(' ') {
            in_ingress = code == "ingress:";
            continue;
        }
        if !in_ingress {
            continue;
        }
        let (starts_rule, kv) = match trimmed.strip_prefix("- ") {
            Some(rest) => (true, rest),
            None => (false, trimmed),
        };
        if starts_rule {
            rules.push(Vec::new());
        }
        if let (Some(rule), Some((k, v))) = (rules.last_mut(), kv.split_once(':')) {
            rule.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let get = |rule: &[(String, String)], key: &str| {
        rule.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };
    let Some((last, routed)) = rules.split_last() else {
        problems.push("no ingress rules".to_owned());
        return problems;
    };
    if last.len() != 1 || get(last, "service").as_deref() != Some("http_status:404") {
        problems.push("last rule is not a bare http_status:404".to_owned());
    }
    let mut paths = Vec::new();
    for rule in routed {
        if get(rule, "hostname").as_deref() != Some("kharon.twkr.io") {
            problems.push(format!("rule without the public hostname: {rule:?}"));
        }
        match get(rule, "path") {
            Some(p) => paths.push(p),
            None => problems.push(format!("rule without a path: {rule:?}")),
        }
    }
    paths.sort();
    if paths != ["^/connector$", "^/mcp$"] {
        problems.push(format!("routed paths are {paths:?}"));
    }
    problems
}

#[test]
fn cloudflared_example_routes_only_mcp_and_connector() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/cloudflared/config.yml");
    let yml = std::fs::read_to_string(&path).unwrap();
    assert_eq!(cloudflared_problems(&yml), Vec::<String>::new());

    // The checker refuses the shapes it is there to catch.
    for (bad, why) in [
        (yml.replace("^/mcp$", "/mcp"), "unanchored path"),
        (yml.replace("    path: ^/connector$\n", ""), "rule with no path"),
        (yml.replace("  - service: http_status:404\n", ""), "no final 404"),
        (yml.replace("noTLSVerify: false", "noTLSVerify: true"), "TLS check off"),
        (
            format!("{yml}  - hostname: kharon.twkr.io\n    path: ^/ui$\n    service: http://127.0.0.1:8788\n"),
            "route after the 404",
        ),
        (
            yml.replace("  - service: http_status:404\n", "  - hostname: kharon.twkr.io\n    service: https://<BROKER-TAILNET-IP>:8787\n  - service: http_status:404\n"),
            "whole-host route",
        ),
    ] {
        assert!(!cloudflared_problems(&bad).is_empty(), "{why}");
    }
}
