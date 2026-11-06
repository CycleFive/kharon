//! Issue #113 against a real Chromium: a base-address CDP endpoint
//! (`ws://127.0.0.1:<port>`, no path) keeps working across a browser
//! restart.
//!
//! Chromium serves its browser-level socket at `/devtools/browser/<id>`
//! and picks a new `<id>` at every start. The test starts Chromium on a
//! fixed port, connects kharond's CDP client through the base address
//! (which resolves the path from `/json/version`), restarts Chromium on
//! the same port, and checks that:
//!
//! - the first connection ends with the old browser;
//! - the new browser has a different `<id>`, and a fresh connect through
//!   the same base address resolves and reaches it;
//! - the old full URL (the pre-#113 config form) no longer connects.
//!
//! The daemon-level version of this, with fills, runs against a stub in
//! `req_api_008_daemon_cdp.rs`; this one checks that real Chromium's
//! `/json/version` (its `Host` check and keep-alive included) works
//! with kharond's lookup.
//!
//! Ignored by default: it needs a Chromium binary. `fixture.yml` runs it
//! with `KHARON_FIXTURE_CHROMIUM` (the pinned `chrome-headless-shell`).

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kharond::cdp::discover::browser_url;
use kharond::cdp::{CdpClient, CdpEndpoint, Tunnel};
use serde_json::json;

/// A headless Chromium child, killed on drop.
struct Chromium {
    child: Child,
    /// `/devtools/browser/<id>` from `DevToolsActivePort`.
    path: String,
    _profile: tempfile::TempDir,
}

impl Drop for Chromium {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn launch(bin: &str, port: u16) -> Chromium {
    let profile = tempfile::tempdir().unwrap();
    let child = Command::new(bin)
        .args([
            "--headless",
            // As in req_dep_002_chromium_e2e: CI runners restrict the
            // user namespaces the sandbox needs; this browser loads
            // nothing but about:blank.
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--no-proxy-server",
            "--remote-debugging-address=127.0.0.1",
        ])
        .arg(format!("--remote-debugging-port={port}"))
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot launch Chromium at {bin}: {e}"));
    let port_file = profile.path().join("DevToolsActivePort");
    let deadline = Instant::now() + Duration::from_secs(30);
    let path = loop {
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(p), Some(path)) = (lines.next(), lines.next()) {
                assert_eq!(p, port.to_string(), "Chromium took another port");
                break path.to_owned();
            }
        }
        assert!(Instant::now() < deadline, "Chromium never opened DevTools");
        std::thread::sleep(Duration::from_millis(100));
    };
    Chromium {
        child,
        path,
        _profile: profile,
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn eventually(what: &str, cond: impl Fn() -> bool) {
    let started = Instant::now();
    while !cond() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore = "needs a Chromium binary (fixture.yml)"]
async fn req_arch_002_base_address_follows_chromium_across_a_restart() {
    let bin = std::env::var("KHARON_FIXTURE_CHROMIUM").expect("KHARON_FIXTURE_CHROMIUM");
    let port = free_port();
    let base =
        CdpEndpoint::validate(&format!("ws://127.0.0.1:{port}"), Tunnel::Direct, None).unwrap();
    assert!(base.discovers());

    let first = launch(&bin, port);
    assert_eq!(browser_url(&base).await.unwrap().path(), first.path);
    let client = CdpClient::connect(&base).await.expect("connect via base");
    let v = client
        .request("Browser.getVersion", json!({}))
        .await
        .unwrap();
    assert!(v["product"].is_string(), "{v}");

    // Restart Chromium on the same port.
    let old_path = first.path.clone();
    drop(first);
    eventually("old connection to end", || client.is_closed()).await;
    let second = launch(&bin, port);
    assert_ne!(second.path, old_path, "Chromium reused the browser id");

    // The same base address reaches the new browser...
    assert_eq!(browser_url(&base).await.unwrap().path(), second.path);
    let client = CdpClient::connect(&base).await.expect("reconnect via base");
    let v = client
        .request("Browser.getVersion", json!({}))
        .await
        .unwrap();
    assert!(v["product"].is_string(), "{v}");
    client.close().await;

    // ...and the old full URL does not.
    let stale = CdpEndpoint::validate(
        &format!("ws://127.0.0.1:{port}{old_path}"),
        Tunnel::Direct,
        None,
    )
    .unwrap();
    assert!(!stale.discovers());
    assert!(
        CdpClient::connect(&stale).await.is_err(),
        "stale browser id still connected"
    );
}
