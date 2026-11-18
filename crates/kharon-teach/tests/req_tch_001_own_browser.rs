//! SPEC req_tch_001: the recorder launches its own browser on its own
//! throwaway profile and the DevTools port is loopback only.

mod support;

use kharon_teach::browser::{Browser, Launch, Profile};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Local addresses (hex ip) of every listening row for `port` in a
/// `/proc/net/tcp*` file.
fn listeners(file: &str, port: u16) -> Vec<String> {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    let want = format!(":{port:04X}");
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            let local = *cols.get(1)?;
            let state = *cols.get(3)?;
            (state == "0A" && local.ends_with(&want))
                .then(|| local[..local.len() - want.len()].to_owned())
        })
        .collect()
}

#[tokio::test]
async fn launches_on_its_own_profile_and_binds_loopback_only() {
    let Some(bin) = support::chromium_or_skip("launches_on_its_own_profile") else {
        return;
    };
    let profile = Profile::create().unwrap();
    let profile_path = profile.path().to_owned();
    let (browser, dt) = Browser::launch(Launch {
        browser: &bin,
        profile: &profile,
        first_url: "about:blank",
        headless: true,
    })
    .await
    .unwrap();

    let cmdline = std::fs::read(format!("/proc/{}/cmdline", browser.pid())).unwrap();
    let cmdline = String::from_utf8_lossy(&cmdline).replace('\0', " ");
    assert!(
        cmdline.contains(&format!("--user-data-dir={}", profile_path.display())),
        "{cmdline}"
    );

    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", dt.port))
        .await
        .unwrap();
    s.write_all(b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    // Chromium keeps the connection open, so read until the document is complete.
    let mut body = String::new();
    let mut buf = [0u8; 4096];
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !body.trim_end().ends_with('}') {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n > 0, "closed early: {body}");
            body.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    })
    .await
    .expect("no /json/version answer");
    assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    assert!(body.contains("webSocketDebuggerUrl"), "{body}");

    let v4 = listeners("/proc/net/tcp", dt.port);
    let v6 = listeners("/proc/net/tcp6", dt.port);
    assert!(!v4.is_empty() || !v6.is_empty(), "no listener found");
    assert!(v4.iter().all(|a| a == "0100007F"), "{v4:?}");
    assert!(
        v6.iter()
            .all(|a| a == "00000000000000000000000001000000"
                || a == "0000000000000000FFFF00000100007F"),
        "{v6:?}"
    );

    browser.close().await.unwrap();
    profile.remove().unwrap();
    assert!(!Path::new(&profile_path).exists());
}

#[test]
fn the_library_has_no_way_to_attach_elsewhere() {
    let mut launch_src = None;
    for (f, shipped) in support::shipped_sources() {
        let shipped = shipped.as_str();
        for line in shipped.lines() {
            for lit in ["ws://", "http://"] {
                assert!(
                    !line.contains(lit) || line.contains("127.0.0.1"),
                    "{}: a {lit} literal that is not the loopback CDP URL: {line}",
                    f.display()
                );
            }
        }
        if let Some(at) = shipped.find("pub struct Launch<") {
            let rest = &shipped[at..];
            let open = rest.find('{').unwrap();
            let close = rest.find('}').unwrap();
            launch_src = Some(rest[open + 1..close].to_owned());
        }
    }
    let body = launch_src.expect("Launch struct not found");
    let mut names: Vec<String> = body
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(|f| {
            let f = f.strip_prefix("pub ").unwrap_or(f);
            f.split(':').next().unwrap().trim().to_owned()
        })
        .collect();
    names.sort();
    assert_eq!(names, ["browser", "first_url", "headless", "profile"]);
}
