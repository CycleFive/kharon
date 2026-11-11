//! REQ-APR-009 (#208): the owner web UI behind a public edge.
//!
//! `[owner_ui] public_origin` switches the UI to public mode. These
//! cases drive the real daemon with the raw HTTP client the other
//! owner-UI tests use.

mod api_support;
mod owner_ui_support;

use std::path::PathBuf;

use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;
use owner_ui_support::{Http, http};

const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";
const PUBLIC_ORIGIN: &str = "https://kharon-owner.example.com";
const PUBLIC_HOST: &str = "kharon-owner.example.com";

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/export/password_protected.json")
}

struct Running {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
    ui: std::net::SocketAddr,
    origin: String,
    data: tempfile::TempDir,
}

/// A daemon whose owner UI is behind the edge (`public_origin`).
async fn start_public() -> Running {
    start_with(&format!(
        "[owner_ui]\nlisten = \"127.0.0.1:0\"\nrp_id = \"{PUBLIC_HOST}\"\npublic_origin = \"{PUBLIC_ORIGIN}\"\n"
    ))
    .await
}

/// A daemon with today's local owner UI.
async fn start_local() -> Running {
    start_with(
        "[owner_ui]\nlisten = \"127.0.0.1:0\"\nrp_id = \"localhost\"\norigin = \"http://localhost:1\"\n",
    )
    .await
}

async fn start_with(owner_ui: &str) -> Running {
    let data = tempfile::tempdir().unwrap();
    let text = format!(
        r#"mode = "export"
data_dir = "{data}"
[export]
file = "{export}"
[agents.alpha]
token_hash = "{TOKEN_HASH}"
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}
[audit]
checkpoint_local_only = true
[memory]
require_mlock = false
[api]
listen = "127.0.0.1:0"
{owner_ui}"#,
        data = data.path().display(),
        export = fixture().display(),
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let ui = d.owner_ui_addr().expect("owner UI bound");
    let origin = d.owner_ui_origin().expect("owner UI origin").to_owned();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));
    Running {
        stop: Some(stop),
        server,
        ui,
        origin,
        data,
    }
}

impl Running {
    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.server.await.unwrap().unwrap();
    }

    /// The raw audit log (empty when nothing was written yet).
    fn audit(&self) -> String {
        std::fs::read_to_string(self.data.path().join("audit/audit.jsonl")).unwrap_or_default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_foreign_host_is_misdirected() {
    let run = start_public().await;
    assert_eq!(run.origin, PUBLIC_ORIGIN);
    let port_host = format!("{PUBLIC_HOST}:{}", run.ui.port());
    let upper = PUBLIC_HOST.to_ascii_uppercase();
    let with_443 = format!("{PUBLIC_HOST}:443");

    for host in [PUBLIC_HOST, with_443.as_str(), upper.as_str()] {
        let r = http(run.ui, &run.origin, Http::get("/").host(host)).await;
        assert_eq!(r.status, 200, "{host}: {}", r.body);
    }
    for (host, path) in [
        ("evil.example.com", "/"),
        (port_host.as_str(), "/"),
        ("evil.example.com", "/owner/approve/x"),
        ("evil.example.com", "/owner/deny/x"),
    ] {
        let r = http(run.ui, &run.origin, Http::get(path).host(host)).await;
        assert_eq!(r.status, 421, "{host} {path}: {}", r.body);
        assert!(r.body.contains(r#""error":"misdirected""#), "{}", r.body);
    }
    let audit = run.audit();
    assert!(!audit.contains("owner_auth_fail"), "{audit}");
    run.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_apr_009_local_mode_has_no_host_check() {
    let run = start_local().await;
    let r = http(run.ui, &run.origin, Http::get("/").host("anything.example")).await;
    assert_eq!(r.status, 200, "{}", r.body);
    run.shutdown().await;
}
