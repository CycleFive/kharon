//! Issue #349 against a real Chromium: `--remote-debugging-port=0`,
//! discover the endpoint from `DevToolsActivePort`, attach, then do it
//! again after the browser restarts on a new port.
//!
//! Skips when no Chromium binary is found (as `req_arch_005` does).
//! `KHARON_CHROMIUM` names one, and `KHARON_REQUIRE_CHROMIUM=1` turns
//! the skip into a failure. The flags are for this throwaway browser.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use kharon_connector::{DiscoverSource, read_devtools_active_port, resolve_devtools};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::{Request, generate_key};

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

struct Chromium {
    child: Child,
}

impl Drop for Chromium {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn launch(bin: &Path, profile: &Path) -> Chromium {
    let child = Command::new(bin)
        .args([
            "--headless=new",
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
        .arg(format!("--user-data-dir={}", profile.display()))
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
        .unwrap_or_else(|e| panic!("cannot launch Chromium at {}: {e}", bin.display()));
    Chromium { child }
}

fn scratch() -> PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "kharon-devtools-chromium-{}-{}",
        std::process::id(),
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}

/// The handshake kharond's CDP client sends: no `Origin` header.
async fn browser_version(url: &str) -> Result<String, String> {
    let hostport = url
        .strip_prefix("ws://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(host, _)| host)
        .ok_or_else(|| format!("bad url {url}"))?;
    let addr: SocketAddr = hostport
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    let request = Request::builder()
        .uri(url)
        .header("Host", "127.0.0.1")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())
        .map_err(|e| e.to_string())?;
    let (mut ws, _) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::client_async(request, stream),
    )
    .await
    .map_err(|_| "websocket handshake timed out".to_owned())?
    .map_err(|e| e.to_string())?;
    ws.send(Message::Text(
        r#"{"id":1,"method":"Browser.getVersion","params":{}}"#.to_owned(),
    ))
    .await
    .map_err(|e| e.to_string())?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err("no Browser.getVersion reply".into());
        }
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .map_err(|_| "reply timed out".to_owned())?
            .ok_or_else(|| "websocket closed".to_owned())?
            .map_err(|e| e.to_string())?;
        if let Message::Text(text) = msg
            && text.contains("\"id\":1")
        {
            return Ok(text.to_string());
        }
    }
}

#[tokio::test]
async fn devtools_active_port_discovers_chromium_and_follows_a_restart() {
    let Some(bin) =
        chromium_or_skip("devtools_active_port_discovers_chromium_and_follows_a_restart")
    else {
        return;
    };
    let profile = scratch();
    let source = DiscoverSource::UserDataDir(profile.clone());

    let mut first = launch(&bin, &profile);
    let deadline = Instant::now() + Duration::from_secs(30);
    let found = loop {
        if let Ok(ep) = resolve_devtools(&source).await {
            break ep;
        }
        if let Ok(Some(status)) = first.child.try_wait() {
            panic!("Chromium exited {status} before DevTools opened");
        }
        assert!(
            Instant::now() < deadline,
            "Chromium never published a live DevToolsActivePort"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let on_disk = read_devtools_active_port(&profile.join("DevToolsActivePort")).unwrap();
    assert_eq!(found.port, on_disk.port);
    assert_eq!(found.path, on_disk.path);
    assert_eq!(found.addr().ip().to_string(), "127.0.0.1");
    assert_eq!(
        found.ws_url(),
        format!("ws://127.0.0.1:{}{}", found.port, found.path)
    );
    let version = browser_version(&found.ws_url()).await.expect("attach");
    assert!(
        version.contains("\"result\""),
        "Browser.getVersion did not answer: {version}"
    );

    let old_url = found.ws_url();
    let old_port = found.port;
    drop(first);
    // The file outlives the process. Until the new browser rewrites it,
    // discovery must not treat the stale port as a browser.
    let stale_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if resolve_devtools(&source).await.is_err() {
            break;
        }
        assert!(
            Instant::now() < stale_deadline,
            "stale DevToolsActivePort still looked live"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut second = launch(&bin, &profile);
    let deadline = Instant::now() + Duration::from_secs(30);
    let again = loop {
        if let Ok(ep) = resolve_devtools(&source).await
            && ep.port != old_port
        {
            break ep;
        }
        if let Ok(Some(status)) = second.child.try_wait() {
            panic!("Chromium exited {status} on restart");
        }
        assert!(
            Instant::now() < deadline,
            "restart did not publish a new DevTools port"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let version = browser_version(&again.ws_url()).await.expect("reattach");
    assert!(version.contains("\"result\""), "{version}");
    assert!(
        browser_version(&old_url).await.is_err(),
        "stale browser url still attached: {old_url}"
    );

    drop(second);
    let _ = std::fs::remove_dir_all(&profile);
}
