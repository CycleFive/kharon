//! REQ-ARCH-005 (#342): on real Chromium a tab in the default context
//! carries a `browserContextId`. `allow_default_context` still admits
//! it, and a tab in some other created context stays `target_not_owned`.
//!
//! Skips when no Chromium binary is found (as `req_arch_003_org_chromium`
//! and `req_apr_005` do). `KHARON_CHROMIUM` names one, and
//! `KHARON_REQUIRE_CHROMIUM=1` turns the skip into a failure. The
//! Chromium flags are for this throwaway test browser only.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kharond::cdp::{Browser, CdpClient, CdpEndpoint, OwnershipError, Tunnel};
use serde_json::{Value, json};

fn chromium_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KHARON_CHROMIUM") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/local/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// The Chromium binary, or `None` to skip (unless a run requires it).
fn chromium_or_skip(test: &str) -> Option<PathBuf> {
    let bin = chromium_bin();
    if bin.is_none() {
        if std::env::var_os("KHARON_REQUIRE_CHROMIUM").is_some() {
            panic!("KHARON_REQUIRE_CHROMIUM is set but no Chromium binary was found");
        }
        eprintln!("SKIP {test}: no Chromium binary");
    }
    bin
}

/// A headless Chromium child, killed on drop.
struct Chromium {
    child: Child,
    /// Browser-level DevTools websocket URL.
    ws: String,
    _profile: tempfile::TempDir,
}

impl Drop for Chromium {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn launch_chromium(bin: &Path) -> Chromium {
    let profile = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(bin);
    cmd.args([
        "--headless=new",
        // CI runners restrict the user namespaces the sandbox needs;
        // this browser only ever loads about:blank.
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--password-store=basic",
        "--no-proxy-server",
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=0",
    ])
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
    .stderr(Stdio::null());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("cannot launch Chromium at {}: {e}", bin.display()));
    let port_file = profile.path().join("DevToolsActivePort");
    let deadline = Instant::now() + Duration::from_secs(30);
    let ws = loop {
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                break format!("ws://127.0.0.1:{port}{path}");
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("Chromium exited {status} before DevTools opened");
        }
        assert!(Instant::now() < deadline, "Chromium never opened DevTools");
        std::thread::sleep(Duration::from_millis(50));
    };
    Chromium {
        child,
        ws,
        _profile: profile,
    }
}

async fn browser(ws: &str) -> Browser {
    let endpoint = CdpEndpoint::validate(ws, Tunnel::Direct, None).unwrap();
    Browser::new(CdpClient::connect(&endpoint).await.unwrap())
}

async fn call(browser: &Browser, method: &str, params: Value) -> Value {
    browser
        .client()
        .request(method, params)
        .await
        .unwrap_or_else(|e| panic!("{method}: {e}"))
}

/// Open `about:blank`. `context` set puts the tab there; `None` leaves
/// it in the browser's default context.
async fn open_tab(browser: &Browser, context: Option<&str>) -> String {
    let mut params = json!({"url": "about:blank"});
    if let Some(context) = context {
        params["browserContextId"] = json!(context);
    }
    let created = call(browser, "Target.createTarget", params).await;
    created["targetId"]
        .as_str()
        .unwrap_or_else(|| panic!("createTarget lacked a targetId: {created}"))
        .to_string()
}

#[tokio::test]
async fn req_arch_005_default_context_tab_on_real_chromium() {
    let Some(bin) = chromium_or_skip("req_arch_005_default_context_tab_on_real_chromium") else {
        return;
    };
    let chromium = launch_chromium(&bin);
    let browser = browser(&chromium.ws).await;
    let agent = browser.create_agent_context("agent-A").await.unwrap();
    // A context the browser created that is not the agent's and not
    // the default (OpenClaw's isolated dashboard is this shape).
    let other = call(&browser, "Target.createBrowserContext", json!({})).await;
    let other_id = other["browserContextId"]
        .as_str()
        .unwrap_or_else(|| panic!("createBrowserContext lacked an id: {other}"))
        .to_string();

    let default_tab = open_tab(&browser, None).await;
    let other_tab = open_tab(&browser, Some(&other_id)).await;
    let agent_tab = open_tab(&browser, Some(agent.browser_context_id())).await;

    let owned = browser
        .check_ownership(&agent_tab, &agent, false)
        .await
        .unwrap();
    assert_eq!(
        owned.browser_context_id.as_deref(),
        Some(agent.browser_context_id())
    );

    let err = browser
        .check_ownership(&default_tab, &agent, false)
        .await
        .unwrap_err();
    assert_eq!(err, OwnershipError::DefaultContextRefused);
    let info = browser
        .check_ownership(&default_tab, &agent, true)
        .await
        .unwrap();
    let default_id = info
        .browser_context_id
        .as_deref()
        .expect("Chromium sets browserContextId on a default-context tab");
    assert_ne!(default_id, agent.browser_context_id());
    assert_ne!(default_id, other_id);

    let err = browser
        .check_ownership(&other_tab, &agent, true)
        .await
        .unwrap_err();
    assert_eq!(err, OwnershipError::TargetNotOwned);
}
