//! REQ-API-003 (issue #129): `kharon token mint` mints an agent token
//! and prints the Argon2id PHC `token_hash` for config.
//!
//! The binary runs under `script(1)`, which gives it a pseudo
//! terminal as its controlling tty, with stdout and stderr redirected
//! to files. The token must show on the terminal exactly once and in
//! neither file. Stdout is the hash, one line, and it must verify the
//! token at [`ParamFloor::PRODUCTION`]. Without a controlling terminal
//! (`setsid`) the command must refuse and print no token and no hash.

use std::process::{Command, Stdio};

use kharond::api::token::{ParamFloor, TokenStore, check_token_hash, claimed_agent_id};

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Run `kharon token mint <agent_id>` on a fresh pty; return (exit ok,
/// tty text, stdout file, stderr file).
fn mint_on_a_tty(agent_id: &str) -> (bool, String, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("stdout");
    let err = dir.path().join("stderr");
    let inner = format!(
        "{} token mint {} >{} 2>{}",
        sh_quote(env!("CARGO_BIN_EXE_kharon")),
        sh_quote(agent_id),
        sh_quote(&out.display().to_string()),
        sh_quote(&err.display().to_string())
    );
    let run = Command::new("script")
        .args(["--quiet", "--return", "--command", &inner, "/dev/null"])
        .stdin(Stdio::null())
        .output()
        .expect("script(1) from util-linux is needed for this test");
    (
        run.status.success(),
        String::from_utf8_lossy(&run.stdout).into_owned(),
        std::fs::read_to_string(&out).unwrap(),
        std::fs::read_to_string(&err).unwrap(),
    )
}

/// Every `kh_agent_<id>_<64 lowercase hex>` word in `text`.
fn tokens_in(text: &str, agent_id: &str) -> Vec<String> {
    let prefix = format!("kh_agent_{agent_id}_");
    text.split_whitespace()
        .filter(|w| {
            let Some(rand) = w.strip_prefix(&prefix) else {
                return false;
            };
            rand.len() == 64
                && rand
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn req_api_003_token_mint_prints_token_once_and_hash_for_config() {
    let (ok, tty, stdout, stderr) = mint_on_a_tty("assistant");
    assert!(ok, "kharon token mint failed; tty: {tty}\nstderr: {stderr}");
    let shown = tokens_in(&tty, "assistant");
    assert_eq!(shown.len(), 1, "expected one token on the tty: {tty}");
    assert!(
        tokens_in(&stdout, "assistant").is_empty(),
        "token leaked to stdout: {stdout}"
    );
    assert!(
        tokens_in(&stderr, "assistant").is_empty() && !stderr.contains("kh_agent_"),
        "token leaked to stderr: {stderr}"
    );
    assert!(stderr.is_empty(), "stderr must stay empty: {stderr}");
    assert!(tty.contains("token_hash"), "{tty}");
    assert!(tty.contains("[agents.assistant]"), "{tty}");
    assert!(!tty.contains("$argon2id$"), "hash belongs on stdout: {tty}");

    let hash = stdout.trim_end_matches('\n');
    assert_eq!(stdout, format!("{hash}\n"), "stdout is one hash line");
    assert!(hash.starts_with("$argon2id$"), "{hash}");
    assert!(
        hash.contains("m=19456,t=2,p=1"),
        "production Argon2id floor: {hash}"
    );
    check_token_hash(hash, &ParamFloor::PRODUCTION).unwrap_or_else(|e| panic!("{e:?}: {hash}"));
    assert_eq!(claimed_agent_id(&shown[0]), Some("assistant"));
    let store = TokenStore::new([("assistant", hash)]).unwrap_or_else(|e| panic!("{e}: {hash}"));
    assert_eq!(store.authenticate(&shown[0]).unwrap(), "assistant");
}

#[test]
fn req_api_003_token_mint_mints_a_new_token_each_run() {
    let (_, a, stdout_a, _) = mint_on_a_tty("assistant");
    let (_, b, stdout_b, _) = mint_on_a_tty("assistant");
    assert_ne!(tokens_in(&a, "assistant"), tokens_in(&b, "assistant"));
    assert_ne!(stdout_a, stdout_b);
}

#[test]
fn req_api_003_token_mint_refuses_without_a_tty() {
    let run = Command::new("setsid")
        .arg(env!("CARGO_BIN_EXE_kharon"))
        .args(["token", "mint", "assistant"])
        .stdin(Stdio::null())
        .output()
        .expect("setsid(1) from util-linux is needed for this test");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        !run.status.success(),
        "token mint must refuse without a tty"
    );
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stdout.contains("kh_agent_") && !stdout.contains("$argon2id$"));
    assert!(
        !stderr.contains("kh_agent_") && !stderr.contains("$argon2id$"),
        "{stderr}"
    );
    assert!(stderr.contains("terminal"), "{stderr}");
}

#[test]
fn req_api_003_token_mint_refuses_a_bad_agent_id() {
    for bad in [
        "",
        "Assistant",
        "agent_b",
        "has space",
        &"a".repeat(65),
        "a/b",
    ] {
        let run = Command::new(env!("CARGO_BIN_EXE_kharon"))
            .args(["token", "mint", bad])
            .stdin(Stdio::null())
            .output()
            .expect("kharon binary");
        let stdout = String::from_utf8_lossy(&run.stdout);
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "accepted {bad:?}: {stderr}");
        assert!(stdout.is_empty(), "{bad:?} stdout: {stdout}");
        assert!(
            !stdout.contains("$argon2id$") && !stderr.contains("$argon2id$"),
            "{bad:?} minted a hash"
        );
        assert!(
            !stdout.contains("kh_agent_") && !stderr.contains("kh_agent_"),
            "{bad:?} printed a token: {stderr}"
        );
        assert!(stderr.contains("agent id"), "{bad:?}: {stderr}");
    }
}

#[test]
fn req_api_003_token_mint_hyphenated_id_round_trips() {
    let (ok, tty, stdout, stderr) = mint_on_a_tty("agent-2");
    assert!(ok, "tty: {tty}\nstderr: {stderr}");
    let shown = tokens_in(&tty, "agent-2");
    assert_eq!(shown.len(), 1, "{tty}");
    assert!(shown[0].starts_with("kh_agent_agent-2_"));
    assert_eq!(claimed_agent_id(&shown[0]), Some("agent-2"));
    let hash = stdout.trim_end();
    check_token_hash(hash, &ParamFloor::PRODUCTION).unwrap_or_else(|e| panic!("{e:?}: {hash}"));
    let store = TokenStore::new([("agent-2", hash)]).unwrap_or_else(|e| panic!("{e}: {hash}"));
    assert_eq!(store.authenticate(&shown[0]).unwrap(), "agent-2");
}
