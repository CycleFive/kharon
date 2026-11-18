//! SPEC req_tch_004: the recorder opens no socket but loopback CDP, and links no TLS or HTTP client.

use std::path::{Path, PathBuf};

/// Shipped code only: the text before the first `#[cfg(test)]` of each file under `src/`.
fn shipped_sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(!files.is_empty());
    files
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap();
            let shipped = text.split("#[cfg(test)]").next().unwrap().to_owned();
            (p, shipped)
        })
        .collect()
}

#[test]
fn the_crate_listens_on_nothing_and_has_no_tls() {
    for (path, text) in shipped_sources() {
        for banned in ["TcpListener", "UdpSocket", "bind(", "accept("] {
            assert!(!text.contains(banned), "{} holds {banned}", path.display());
        }
    }
    let out = std::process::Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "kharon-teach",
            "-e",
            "normal",
            "--prefix",
            "none",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = String::from_utf8_lossy(&out.stdout);
    assert!(tree.lines().any(|l| l.starts_with("kharon-teach ")));
    for banned in [
        "rustls",
        "native-tls",
        "openssl",
        "openssl-sys",
        "reqwest",
        "hyper",
        "kharon-connector",
        "kharond",
    ] {
        let hit = tree
            .lines()
            .any(|l| l.split_whitespace().next() == Some(banned));
        assert!(!hit, "the dependency tree holds {banned}");
    }
}

#[test]
fn the_only_dial_is_loopback() {
    let sources = shipped_sources();
    let cdp = sources
        .iter()
        .find(|(p, _)| p.ends_with("cdp.rs"))
        .expect("cdp.rs exists");
    assert!(
        cdp.1.contains("ws://127.0.0.1:"),
        "cdp.rs does not build its URL from the loopback literal"
    );
    let dials: Vec<_> = sources
        .iter()
        .flat_map(|(p, t)| {
            ["connect_async", "TcpStream::connect", "UnixStream::connect"]
                .into_iter()
                .filter(|d| t.contains(d))
                .map(move |d| format!("{}: {d}", p.display()))
        })
        .collect();
    assert!(
        !dials.is_empty(),
        "cdp.rs no longer dials with connect_async"
    );
    assert!(
        dials.iter().all(|d| d.contains("cdp.rs")),
        "a dial outside cdp.rs: {dials:?}"
    );
}
