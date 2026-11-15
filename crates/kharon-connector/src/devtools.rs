//! Chromium `DevToolsActivePort` discovery (issue #349).
//!
//! Stock Hermes launches Chromium with `--remote-debugging-port=0`.
//! Chromium writes two lines into `<user-data-dir>/DevToolsActivePort`:
//! the port, then the browser WebSocket path. The connector dials
//! `127.0.0.1:<port>` and checks that `/json/version` still names that
//! path. The host is never taken from the file.
//!
//! Hermes's own default (verified in `NousResearch/hermes-agent` at
//! `f578714`, the #337 source pin, in `hermes_constants.py`
//! `_platform_default_hermes_home` and `tools/browser_launcher.py`
//! `_ephemeral_root` / `_default_user_data_dir`): the home is
//! `$HERMES_HOME` or `~/.hermes`, and each stock launch gets its own
//! directory under `<home>/cache/browser/chromium/`. There is no single
//! stable profile path, so the preset scans that directory.
//!
//! A missing, unreadable, truncated, or stale file is [`DiscoverError::NoBrowser`].
//! Callers dial nothing and do not panic. The file is read again on
//! every dial: the port changes each time the browser starts.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long a liveness probe may take. A dead port fails faster than this.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// `DevToolsActivePort` is two short lines. Anything larger is not one.
const MAX_FILE_BYTES: u64 = 4096;

/// Bound on the `/json/version` probe, head and body.
const MAX_PROBE_BYTES: usize = 64 * 1024;

/// Newest profiles considered under the Hermes ephemeral root. The live
/// one is almost always the newest; the cap keeps a cluttered cache from
/// holding a dial open.
const MAX_CANDIDATES: usize = 32;

/// Why discovery produced no endpoint. Display text is the fixed word
/// `no_browser`: a missing, stale, or unreadable file, never a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiscoverError {
    /// The file is missing, unreadable, not a browser endpoint, or names
    /// a port whose `/json/version` browser id does not match line 2.
    #[error("no_browser")]
    NoBrowser,
}

/// Where to read `DevToolsActivePort` on each dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverSource {
    /// The file itself.
    File(PathBuf),
    /// `<dir>/DevToolsActivePort`, one Chromium `--user-data-dir`.
    UserDataDir(PathBuf),
    /// Scan `<home>/cache/browser/chromium/*/DevToolsActivePort` and use
    /// the newest file whose browser is still live. `home` is Hermes's
    /// home (`$HERMES_HOME` or `~/.hermes` when the operator does not
    /// set one).
    HermesEphemeral { home: PathBuf },
}

/// What one dial uses. `Discover` is resolved again on every open.
#[derive(Clone)]
pub(crate) enum CdpTarget {
    Fixed(SocketAddr),
    Discover(DiscoverSource),
}

/// A loopback CDP endpoint taken from a `DevToolsActivePort` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevToolsEndpoint {
    /// Line 1. Never zero.
    pub port: u16,
    /// Line 2, always `/devtools/browser/<id>`.
    pub path: String,
}

impl DevToolsEndpoint {
    /// `127.0.0.1:<port>`. The file does not choose the address.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)
    }

    /// `ws://127.0.0.1:<port><path>`.
    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}{}", self.port, self.path)
    }
}

/// Hermes home when the operator sets neither `hermes_home` nor an
/// explicit endpoint: `$HERMES_HOME` if that variable is non-empty,
/// otherwise `~/.hermes`.
///
/// This matches `get_process_hermes_home` in upstream
/// `hermes_constants.py`: the environment variable, else the platform
/// default `~/.hermes`. A profile home other than that default is not
/// inferred; set `hermes_home` or `HERMES_HOME`.
pub fn default_hermes_home() -> PathBuf {
    if let Some(raw) = std::env::var_os("HERMES_HOME") {
        let text = raw.to_string_lossy();
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home).join(".hermes"),
        _ => PathBuf::from("/nonexistent").join(".hermes"),
    }
}

/// `<home>/cache/browser/chromium`, Hermes's `_ephemeral_root`.
pub fn hermes_ephemeral_root(home: &Path) -> PathBuf {
    home.join("cache").join("browser").join("chromium")
}

/// Parse the two-line file body. No I/O and no liveness check.
pub fn parse_devtools_active_port(text: &str) -> Result<DevToolsEndpoint, DiscoverError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.lines();
    let port_line = lines.next().ok_or(DiscoverError::NoBrowser)?.trim();
    let path = lines.next().ok_or(DiscoverError::NoBrowser)?.trim();
    if port_line.is_empty() || port_line.len() > 5 || !port_line.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(DiscoverError::NoBrowser);
    }
    let port: u16 = port_line.parse().map_err(|_| DiscoverError::NoBrowser)?;
    if port == 0 {
        return Err(DiscoverError::NoBrowser);
    }
    let id = path
        .strip_prefix("/devtools/browser/")
        .ok_or(DiscoverError::NoBrowser)?;
    if id.is_empty()
        || id.len() > 128
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(DiscoverError::NoBrowser);
    }
    Ok(DevToolsEndpoint {
        port,
        path: path.to_owned(),
    })
}

/// Read one `DevToolsActivePort` file. Missing, unreadable, or not a
/// regular file is [`DiscoverError::NoBrowser`]. Does not check that the
/// port is live; [`resolve_devtools`] does.
pub fn read_devtools_active_port(path: &Path) -> Result<DevToolsEndpoint, DiscoverError> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| DiscoverError::NoBrowser)?;
    if !meta.file_type().is_file() || meta.len() > MAX_FILE_BYTES {
        return Err(DiscoverError::NoBrowser);
    }
    let text = std::fs::read_to_string(path).map_err(|_| DiscoverError::NoBrowser)?;
    parse_devtools_active_port(&text)
}

/// The endpoint to dial for `source`, re-reading the file.
///
/// [`DiscoverError::NoBrowser`] covers a missing or unreadable file, a
/// file that does not parse, and a file whose port is dead or whose
/// `/json/version` browser id is not line 2 (the file outlives a crashed
/// Chromium, and the port can be reused).
pub async fn resolve_devtools(source: &DiscoverSource) -> Result<DevToolsEndpoint, DiscoverError> {
    match source {
        DiscoverSource::File(path) => confirm(read_devtools_active_port(path)?).await,
        DiscoverSource::UserDataDir(dir) => {
            confirm(read_devtools_active_port(&dir.join("DevToolsActivePort"))?).await
        }
        DiscoverSource::HermesEphemeral { home } => {
            for path in hermes_candidates(home) {
                if let Ok(ep) = read_devtools_active_port(&path)
                    && confirm_live(&ep).await
                {
                    return Ok(ep);
                }
            }
            Err(DiscoverError::NoBrowser)
        }
    }
}

async fn confirm(ep: DevToolsEndpoint) -> Result<DevToolsEndpoint, DiscoverError> {
    if confirm_live(&ep).await {
        Ok(ep)
    } else {
        Err(DiscoverError::NoBrowser)
    }
}

/// `GET /json/version` on loopback and require the browser WebSocket URL
/// to end with `ep.path`. Hermes's `_devtools_endpoint_live` does the
/// same check: the file is stale when the id does not match.
async fn confirm_live(ep: &DevToolsEndpoint) -> bool {
    let probe = async {
        let mut stream = TcpStream::connect(ep.addr()).await.ok()?;
        let req = format!(
            "GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            port = ep.port
        );
        stream.write_all(req.as_bytes()).await.ok()?;
        stream.flush().await.ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            if version_matches(&buf, &ep.path) {
                return Some(());
            }
            if buf.len() > MAX_PROBE_BYTES {
                return None;
            }
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        version_matches(&buf, &ep.path).then_some(())
    };
    tokio::time::timeout(PROBE_TIMEOUT, probe)
        .await
        .ok()
        .flatten()
        .is_some()
}

fn version_matches(buf: &[u8], path: &str) -> bool {
    let Ok(text) = std::str::from_utf8(buf) else {
        return false;
    };
    let Some(status) = text.lines().next() else {
        return false;
    };
    if status.split(' ').nth(1) != Some("200") {
        return false;
    }
    let Some(idx) = text.find("\"webSocketDebuggerUrl\"") else {
        return false;
    };
    let rest = &text[idx..];
    let Some(colon) = rest.find(':') else {
        return false;
    };
    let after = rest[colon + 1..].trim_start();
    let Some(after) = after.strip_prefix('"') else {
        return false;
    };
    let Some(end) = after.find('"') else {
        return false;
    };
    after[..end].ends_with(path)
}

/// Immediate child directories of the ephemeral root, newest
/// `DevToolsActivePort` first. Symlinks are skipped.
fn hermes_candidates(home: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(hermes_ephemeral_root(home)) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let Ok(ty) = entry.file_type() else {
            continue;
        };
        if !ty.is_dir() {
            continue;
        }
        let file = entry.path().join("DevToolsActivePort");
        let Ok(meta) = std::fs::symlink_metadata(&file) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        found.push((mtime, file));
    }
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    found.truncate(MAX_CANDIDATES);
    found.into_iter().map(|(_, path)| path).collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const PATH: &str = "/devtools/browser/4f0b2c1e-9a7d-4e43-b1a2-6f9c0d8e7a65";

    fn good_text(port: u16) -> String {
        format!("{port}\n{PATH}\n")
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "kharon-devtools-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.0.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, text).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parse_good_file_is_loopback_with_the_browser_path() {
        let ep = parse_devtools_active_port(&format!("\u{feff}9222\r\n{PATH}\r\nextra\n")).unwrap();
        assert_eq!(ep.port, 9222);
        assert_eq!(ep.path, PATH);
        assert_eq!(ep.addr(), "127.0.0.1:9222".parse().unwrap());
        assert_eq!(ep.ws_url(), format!("ws://127.0.0.1:9222{PATH}"));
        assert_eq!(
            parse_devtools_active_port("0080\n/devtools/browser/abc\n")
                .unwrap()
                .port,
            80
        );
    }

    #[test]
    fn missing_file_is_no_browser() {
        let err = read_devtools_active_port(Path::new("/no/such/DevToolsActivePort")).unwrap_err();
        assert_eq!(err, DiscoverError::NoBrowser);
        assert_eq!(err.to_string(), "no_browser");
        let scratch = Scratch::new();
        let dir = scratch.write("not-a-file/placeholder", "");
        let err = read_devtools_active_port(dir.parent().unwrap()).unwrap_err();
        assert_eq!(err, DiscoverError::NoBrowser);
    }

    #[test]
    fn truncated_or_garbage_file_is_no_browser() {
        for text in [
            "",
            "9222\n",
            "\n",
            "9222",
            "hello\nworld\n",
            "\n/devtools/browser/abc\n",
        ] {
            assert_eq!(
                parse_devtools_active_port(text),
                Err(DiscoverError::NoBrowser),
                "{text:?}"
            );
        }
        let scratch = Scratch::new();
        let path = scratch.write("DevToolsActivePort", "not a port\n/devtools/browser/abc\n");
        assert_eq!(
            read_devtools_active_port(&path),
            Err(DiscoverError::NoBrowser)
        );
    }

    #[test]
    fn non_numeric_port_is_no_browser() {
        for text in [
            "abc\n/devtools/browser/abc\n",
            "12a\n/devtools/browser/abc\n",
            "65536\n/devtools/browser/abc\n",
            "0\n/devtools/browser/abc\n",
            "-1\n/devtools/browser/abc\n",
            "9222\n/devtools/page/abc\n",
            "9222\n/devtools/browser/\n",
            "9222\n/devtools/browser/a/b\n",
            "9222\n/devtools/browser/..\n",
            "9222\n/devtools/browser/a%2Fb\n",
        ] {
            assert_eq!(
                parse_devtools_active_port(text),
                Err(DiscoverError::NoBrowser),
                "{text:?}"
            );
        }
    }

    /// Answers `/json/version` with `path`, and counts every accept.
    async fn fake_browser(path: &str) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits2 = Arc::clone(&hits);
        let body = format!(
            r#"{{"webSocketDebuggerUrl":"ws://127.0.0.1:{port}{path}"}}"#,
            port = addr.port()
        );
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                hits2.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0u8; 2048];
                let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await
                else {
                    continue;
                };
                if buf[..n].windows(3).any(|w| w == b"GET") {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                }
                let _ = sock.read(&mut buf).await;
            }
        });
        (addr, hits)
    }

    #[tokio::test]
    async fn stale_or_unmatched_file_is_no_browser() {
        let scratch = Scratch::new();
        let closed = scratch.write("closed", &good_text(1));
        let err = resolve_devtools(&DiscoverSource::File(closed))
            .await
            .unwrap_err();
        assert_eq!(err, DiscoverError::NoBrowser);

        let (addr, _) = fake_browser("/devtools/browser/other-id").await;
        let wrong = scratch.write("wrong", &format!("{}\n{PATH}\n", addr.port()));
        let err = resolve_devtools(&DiscoverSource::File(wrong))
            .await
            .unwrap_err();
        assert_eq!(err, DiscoverError::NoBrowser);
    }

    #[tokio::test]
    async fn live_file_and_user_data_dir_resolve_to_loopback() {
        let (addr, _) = fake_browser(PATH).await;
        let scratch = Scratch::new();
        let file = scratch.write("DevToolsActivePort", &good_text(addr.port()));
        let ep = resolve_devtools(&DiscoverSource::File(file)).await.unwrap();
        assert_eq!(ep.addr(), addr);
        assert_eq!(
            ep.ws_url(),
            format!("ws://127.0.0.1:{port}{PATH}", port = addr.port())
        );

        let profile = scratch.0.join("profile");
        std::fs::create_dir(&profile).unwrap();
        scratch.write("profile/DevToolsActivePort", &good_text(addr.port()));
        let ep = resolve_devtools(&DiscoverSource::UserDataDir(profile))
            .await
            .unwrap();
        assert_eq!(ep.port, addr.port());
        assert!(ep.addr().ip().is_loopback());
    }

    #[tokio::test]
    async fn hermes_preset_uses_the_newest_live_profile() {
        let (old_addr, _) = fake_browser("/devtools/browser/old-browser").await;
        let (new_addr, _) = fake_browser("/devtools/browser/new-browser").await;
        let scratch = Scratch::new();
        let root = hermes_ephemeral_root(&scratch.0);
        let old = root.join("aaa-old");
        let new = root.join("bbb-new");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::create_dir_all(&new).unwrap();
        let old_file = old.join("DevToolsActivePort");
        let new_file = new.join("DevToolsActivePort");
        std::fs::write(
            &old_file,
            format!("{}\n/devtools/browser/old-browser\n", old_addr.port()),
        )
        .unwrap();
        std::fs::write(
            &new_file,
            format!("{}\n/devtools/browser/new-browser\n", new_addr.port()),
        )
        .unwrap();
        // Newest mtime wins. Bump the new file after the old one.
        let later = SystemTime::now() + Duration::from_secs(2);
        let file_time = std::fs::FileTimes::new().set_modified(later);
        std::fs::File::options()
            .write(true)
            .open(&new_file)
            .unwrap()
            .set_times(file_time)
            .unwrap();

        let ep = resolve_devtools(&DiscoverSource::HermesEphemeral {
            home: scratch.0.clone(),
        })
        .await
        .unwrap();
        assert_eq!(ep.port, new_addr.port());
        assert_eq!(ep.path, "/devtools/browser/new-browser");

        // A home with no cache is a missing file, not a panic.
        let err = resolve_devtools(&DiscoverSource::HermesEphemeral {
            home: scratch.0.join("absent"),
        })
        .await
        .unwrap_err();
        assert_eq!(err, DiscoverError::NoBrowser);
    }

    #[tokio::test]
    async fn each_open_rereads_the_file_and_a_missing_file_does_not_panic() {
        use crate::mux::{serve_agent_discovering, spawn_broker};

        let scratch = Scratch::new();
        let file = scratch.0.join("DevToolsActivePort");
        let (first, first_hits) = fake_browser(PATH).await;
        std::fs::write(&file, good_text(first.port())).unwrap();

        let (agent, broker) = tokio::io::duplex(64 * 1024);
        let serve = tokio::spawn(serve_agent_discovering(
            agent,
            DiscoverSource::File(file.clone()),
        ));
        let session = spawn_broker(broker);
        let mut io = session.open_stream().await.expect("first dial");
        io.write_all(b"one").await.unwrap();
        assert!(first_hits.load(Ordering::SeqCst) >= 1);

        let (second, second_hits) = fake_browser(PATH).await;
        std::fs::write(&file, good_text(second.port())).unwrap();
        let before = first_hits.load(Ordering::SeqCst);
        let mut io = session.open_stream().await.expect("redial");
        io.write_all(b"two").await.unwrap();
        assert!(
            second_hits.load(Ordering::SeqCst) >= 1,
            "second open did not dial the new port"
        );
        assert_eq!(
            first_hits.load(Ordering::SeqCst),
            before,
            "second open reused the old port"
        );

        std::fs::remove_file(&file).unwrap();
        match session.open_stream().await {
            Err(crate::OpenError::DialFailed) => {}
            Err(err) => panic!("missing file: {err:?}"),
            Ok(_) => panic!("missing file still dialed"),
        }
        assert!(!serve.is_finished(), "missing file ended the session");
    }
}
