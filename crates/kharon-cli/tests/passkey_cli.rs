//! `kharon passkey list` and `kharon passkey remove` over a live
//! daemon's owner socket (#258). The socket is peer-uid checked
//! before the request is written, the same as every other owner
//! command. Removing a real passkey, and the assertion that follows,
//! is covered in `req_apr_258_passkey_list_remove` against this
//! command's request.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;

fn run_cli(socket: &PathBuf, args: &[&str]) -> (bool, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kharon"));
    cmd.args(args).arg("--socket").arg(socket);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let out = cmd.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn kharon_passkey_list_and_remove_talk_to_the_owner_socket() {
    let data = tempfile::tempdir().unwrap();
    let export = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kharond/tests/fixtures/export/password_protected.json"
    ));
    let (token, hash) = kharond::api::token::generate("alpha");
    drop(token);
    let cfg = Config::from_toml_str(&format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.alpha]
token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false

[api]
listen = "127.0.0.1:0"

[owner_ui]
listen = "127.0.0.1:0"
rp_id = "localhost"
origin = "http://localhost:1"
"#,
        data.path().display(),
        export.display()
    ))
    .unwrap();
    let d = daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
        .await
        .unwrap();
    let socket = d.owner_socket().to_path_buf();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(d.run(async {
        let _ = stopped.await;
    }));

    let (ok, out, err) = run_cli(&socket, &["passkey", "list"]);
    assert!(ok, "{err}");
    assert_eq!(out, "no passkeys");
    assert!(err.is_empty(), "{err}");

    let (ok, out, err) = run_cli(&socket, &["passkey", "remove", "abcd1234"]);
    assert!(!ok, "{out}");
    assert!(err.contains("not_found"), "{err}");
    assert!(
        !err.contains("abcd1234"),
        "the refusal does not echo the id: {err}"
    );

    let (ok, _, err) = run_cli(&socket, &["passkey", "remove", "NOPE"]);
    assert!(!ok);
    assert!(err.contains("bad_request"), "{err}");

    // A different uid is refused by the CLI before it writes, the
    // same check as unlock. We cannot change uid here; the request
    // path is `owner_request`, and a same-uid reply above is the
    // evidence the check let us through.
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();

    let audit = std::fs::read_to_string(data.path().join("audit/audit.jsonl")).unwrap();
    let entries: Vec<serde_json::Value> = audit
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let listed: Vec<_> = entries
        .iter()
        .filter(|e| e["event"] == "passkey_listed")
        .collect();
    assert_eq!(listed.len(), 1, "{audit}");
    assert_eq!(listed[0]["channel"], "cli");
    assert_eq!(listed[0]["result"], "listed");
    assert_eq!(listed[0]["passkey_count"], 0);
    assert!(listed[0].get("credential_fingerprint").is_none());
    assert!(listed[0].get("credential_fingerprints").is_none());
    assert!(
        entries.iter().all(|e| e["event"] != "passkey_removed"),
        "a refused remove writes no passkey_removed: {audit}"
    );
}
