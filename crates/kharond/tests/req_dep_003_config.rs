//! REQ-DEP-003: table of bad configs → each refused with a specific error,
//! both through the library and through the `kharond` binary (non-zero
//! exit, error code on stderr).

use std::process::Command;

use kharond::config::{
    Config, ConfigError, MlockProbe, ProcfsMlockProbe, StaticMlockProbe, load_for_startup,
};

const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g";
const ORG: &str = "0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const COLL: &str = "11111111-2222-3333-4444-555555555555";

/// A known-good config, split into sections so each table row can break
/// exactly one thing. Every row is otherwise valid.
#[derive(Clone)]
struct Parts {
    top: String,
    bitwarden: String,
    export: String,
    agents: String,
    policy: String,
    approval: String,
    audit: String,
    memory: String,
}

impl Parts {
    fn good() -> Self {
        Self {
            top: String::new(),
            bitwarden: format!(
                "[bitwarden]\nserver = \"https://vault.example.net\"\nemail = \"kharon@example.net\"\n\
                 api_key_file = \"{}\"\norganization_id = \"{ORG}\"\n\
                 collection_ids = [\"{COLL}\"]\n",
                api_key_path().display()
            ),
            export: String::new(),
            agents: agent("assistant", "ws://10.66.0.2:9222", "wireguard"),
            policy: "[policy]\n".to_owned(),
            approval:
                "[approval]\nntfy = { url = \"https://ntfy.example.net\", topic = \"kharon\" }\n"
                    .to_owned(),
            audit: String::new(),
            memory: "[memory]\nrequire_mlock = false\n".to_owned(),
        }
    }

    fn render(&self) -> String {
        [
            &self.top,
            &self.bitwarden,
            &self.export,
            &self.agents,
            &self.policy,
            &self.approval,
            &self.audit,
            &self.memory,
        ]
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("\n")
    }
}

/// Per-binary scratch dir for fixture files referenced from configs.
fn fixture_dir() -> &'static std::path::Path {
    static D: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    D.get_or_init(|| tempfile::tempdir().unwrap().keep())
}

fn fixture_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
    let p = fixture_dir().join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

const CLIENT_ID: &str = "user.6b1e0c52-0a3e-4a8e-9a4f-1f0e2d3c4b5a";

/// A valid personal API-key file (canary secret `xyz...`).
fn api_key_path() -> &'static std::path::Path {
    static P: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    P.get_or_init(|| {
        fixture_file(
            "bw_api_key.json",
            format!(r#"{{"client_id":"{CLIENT_ID}","client_secret":"xyzCANARYsecret"}}"#)
                .as_bytes(),
        )
    })
}

fn set_bw(p: &mut Parts, extra: &str, key: &std::path::Path) {
    p.bitwarden = format!(
        "[bitwarden]\nserver = \"https://vault.example.net\"\nemail = \"kharon@example.net\"\n\
         api_key_file = \"{}\"\norganization_id = \"{ORG}\"\ncollection_ids = [\"{COLL}\"]\n{extra}",
        key.display()
    );
}

fn agent(id: &str, endpoint: &str, via: &str) -> String {
    format!(
        "[agents.{id}]\ntoken_hash = \"{TOKEN_HASH}\"\ncdp = {{ endpoint = \"{endpoint}\", via = \"{via}\" }}\n"
    )
}

struct Row {
    name: &'static str,
    code: &'static str,
    toml: String,
    /// Mlock answer for the library run.
    mlock: Result<(), String>,
}

fn row(name: &'static str, code: &'static str, f: impl FnOnce(&mut Parts)) -> Row {
    let mut p = Parts::good();
    f(&mut p);
    Row {
        name,
        code,
        toml: p.render(),
        mlock: Ok(()),
    }
}

fn bad_configs() -> Vec<Row> {
    let mut rows = vec![
        // The three unsafe combos named by REQ-DEP-003.
        row("non-loopback plain CDP", "cdp_plain_ws_non_loopback", |p| {
            p.agents = agent("assistant", "ws://10.66.0.2:9222", "direct")
        }),
        row(
            "standing grants without flag",
            "standing_grants_disabled",
            |p| p.policy = "[policy]\ndefault_grant = \"standing\"\n".into(),
        ),
        // ("missing mlock" is appended below with an injected probe.)
        // Other CDP transport refusals (REQ-ARCH-002).
        row("wss without pin", "cdp_wss_requires_peer_pin", |p| {
            p.agents = agent("assistant", "wss://10.66.0.2:9222", "wireguard")
        }),
        row("mtls over ws", "cdp_mtls_requires_wss", |p| {
            p.agents = format!(
                "[agents.assistant]\ntoken_hash = \"{TOKEN_HASH}\"\n\
                 cdp = {{ endpoint = \"ws://10.66.0.2:9222\", via = \"mtls\", peer_cert_sha256 = \"{}\" }}\n",
                "ab".repeat(32)
            )
        }),
        row("cdp not websocket", "cdp_not_websocket_url", |p| {
            p.agents = agent("assistant", "http://127.0.0.1:9222", "direct")
        }),
        row("unknown via", "unknown_tunnel", |p| {
            p.agents = agent("assistant", "ws://127.0.0.1:9222", "carrier-pigeon")
        }),
        row("bad peer pin", "invalid_peer_pin", |p| {
            p.agents = format!(
                "[agents.assistant]\ntoken_hash = \"{TOKEN_HASH}\"\n\
                 cdp = {{ endpoint = \"wss://10.66.0.2:9222\", via = \"mtls\", peer_cert_sha256 = \"abcd\" }}\n"
            )
        }),
        // Secrets never live in config (SPEC §8, REQ-EXP-003).
        row("master password in config", "secret_in_config", |p| {
            p.bitwarden.push_str("master_password = \"hunter2\"\n")
        }),
        row("inline agent token", "secret_in_config", |p| {
            p.agents.push_str("token = \"kh_agent_assistant_xyz\"\n")
        }),
        // Structural / value errors.
        row("toml syntax", "parse", |p| {
            p.policy = "[policy]\nidle_lock = \"30m\"; max_unlocked = \"12h\"\n".into()
        }),
        row("unknown key", "parse", |p| {
            p.policy = "[policy]\nallow_standnig = true\n".into()
        }),
        row("secret-looking value in a typed key", "parse", |p| {
            p.policy = "[policy]\nallow_standing = \"hunter2\"\n".into()
        }),
        row("unknown grant type", "parse", |p| {
            p.policy = "[policy]\ndefault_grant = \"forever\"\n".into()
        }),
        row("missing bitwarden", "missing_section", |p| {
            p.bitwarden.clear()
        }),
        row(
            "export section in sync mode",
            "section_not_allowed_in_mode",
            |p| p.export = "[export]\nfile = \"/data/export.json\"\n".into(),
        ),
        row("bad server url", "invalid_url", |p| {
            p.bitwarden = p
                .bitwarden
                .replace("https://vault.example.net", "ftp://vault.example.net")
        }),
        row("bad org id", "invalid_uuid", |p| {
            p.bitwarden = p.bitwarden.replace(ORG, "uuid")
        }),
        row("bad email", "invalid_email", |p| {
            p.bitwarden = p.bitwarden.replace("kharon@example.net", "kharon")
        }),
        row("no collections", "no_collections", |p| {
            p.bitwarden = p.bitwarden.replace(&format!("[\"{COLL}\"]"), "[]")
        }),
        row("no agents", "no_agents", |p| p.agents.clear()),
        row("bad agent id", "invalid_agent_id", |p| {
            p.agents = agent("Bad_Agent", "ws://10.66.0.2:9222", "wireguard")
        }),
        row("plaintext token hash", "token_hash_not_argon2id", |p| {
            p.agents = p.agents.replace(TOKEN_HASH, "$2b$12$bcryptbcryptbcrypt")
        }),
        row("bad duration", "invalid_duration", |p| {
            p.policy = "[policy]\nfill_deadline = \"10 seconds\"\n".into()
        }),
        row("zero duration", "zero_duration", |p| {
            p.policy = "[policy]\nidle_lock = \"0s\"\n".into()
        }),
        row(
            "skew thresholds inverted",
            "clock_skew_thresholds_inverted",
            |p| {
                p.policy = "[policy]\nclock_skew_warn = \"2m\"\nclock_skew_refuse = \"1m\"\n".into()
            },
        ),
        row(
            "default context with two agents",
            "default_context_multi_agent",
            |p| {
                p.agents
                    .push_str(&agent("second", "ws://10.66.0.3:9222", "wireguard"));
                p.policy = "[policy]\nallow_default_context = true\n".into()
            },
        ),
        row("no off-host audit sink", "audit_no_off_host_sink", |p| {
            p.approval.clear()
        }),
    ];
    // Sync-client wiring (#8): the files behind the config must be usable.
    rows.push(row("api key file missing", "api_key_file", |p| {
        set_bw(p, "", &fixture_dir().join("does-not-exist.json"))
    }));
    rows.push(row("api key file not a key", "api_key_file", |p| {
        let k = fixture_file(
            "bad_key.json",
            br#"{"client_id":"user.x","password":"hunter2"}"#,
        );
        set_bw(p, "", &k)
    }));
    rows.push(row("api key is an org key", "api_key_file", |p| {
        let k = fixture_file(
            "org_key.json",
            br#"{"client_id":"organization.6b1e0c52-0a3e-4a8e-9a4f-1f0e2d3c4b5a","client_secret":"xyz"}"#,
        );
        set_bw(p, "", &k)
    }));
    rows.push(row("ca file missing", "ca_file", |p| {
        let ca = fixture_dir().join("no-ca.pem");
        set_bw(
            p,
            &format!("ca_file = \"{}\"\n", ca.display()),
            api_key_path(),
        )
    }));
    rows.push(row("ca file not PEM", "ca_file", |p| {
        let ca = fixture_file("junk-ca.pem", b"hunter2 is not a certificate\n");
        set_bw(
            p,
            &format!("ca_file = \"{}\"\n", ca.display()),
            api_key_path(),
        )
    }));
    let mut mlock = row("missing mlock", "mlock_unavailable", |p| {
        p.memory = "[memory]\nrequire_mlock = true\n".into()
    });
    mlock.mlock = Err("no CAP_IPC_LOCK and RLIMIT_MEMLOCK soft limit is 65536 bytes".into());
    rows.push(mlock);
    rows
}

fn check(text: &str, probe: &dyn MlockProbe) -> Result<Config, ConfigError> {
    let cfg = Config::from_toml_str(text)?;
    cfg.check_startup(probe)?;
    Ok(cfg)
}

#[test]
fn req_dep_003_good_config_accepted() {
    let text = Parts::good().render();
    check(&text, &StaticMlockProbe(Ok(()))).unwrap();
}

#[test]
fn req_dep_003_bad_config_table_specific_errors() {
    let rows = bad_configs();
    for r in &rows {
        let err = check(&r.toml, &StaticMlockProbe(r.mlock.clone()))
            .expect_err(&format!("{}: accepted", r.name));
        assert_eq!(err.code(), r.code, "{}: got {err:?}", r.name);
        // Refusals never echo the canary password or token values.
        let msg = err.to_string();
        assert!(
            !msg.contains("hunter2") && !msg.contains("xyz"),
            "{}: {msg}",
            r.name
        );
    }
    // The three unsafe combos named by REQ-DEP-003 each get their own code.
    let named = [
        "non-loopback plain CDP",
        "standing grants without flag",
        "missing mlock",
    ];
    let codes: std::collections::BTreeSet<&str> = rows
        .iter()
        .filter(|r| named.contains(&r.name))
        .map(|r| r.code)
        .collect();
    assert_eq!(codes.len(), 3, "{codes:?}");
}

fn run_daemon(text: &str) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kharon.toml");
    std::fs::write(&path, text).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_kharond"))
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn req_dep_003_daemon_exits_nonzero_with_specific_error() {
    let (code, stderr) = run_daemon(&Parts::good().render());
    assert_eq!(code, Some(0), "good config: {stderr}");
    assert!(stderr.contains("config ok"), "{stderr}");

    for r in bad_configs() {
        if r.code == "mlock_unavailable" {
            continue; // host-dependent; see the dedicated test below
        }
        let (code, stderr) = run_daemon(&r.toml);
        assert_eq!(code, Some(78), "{}: {stderr}", r.name);
        assert!(
            stderr.contains(&format!("config error [{}]", r.code)),
            "{}: {stderr}",
            r.name
        );
        assert!(!stderr.contains("hunter2"), "{}: {stderr}", r.name);
    }
}

/// The daemon's real probe decides the mlock row. CI runners usually lack
/// `CAP_IPC_LOCK` and an unlimited memlock limit, so this normally proves
/// the refusal; on a privileged host it proves the same config boots. The
/// child inherits this process's capabilities and limits, so the
/// in-process probe predicts the child's answer.
#[test]
fn req_dep_003_daemon_refuses_missing_mlock() {
    let mut p = Parts::good();
    p.memory = "[memory]\nrequire_mlock = true\n".into();
    let (code, stderr) = run_daemon(&p.render());
    match ProcfsMlockProbe.mlock_available() {
        Err(_) => {
            assert_eq!(code, Some(78), "{stderr}");
            assert!(
                stderr.contains("config error [mlock_unavailable]"),
                "{stderr}"
            );
        }
        Ok(()) => assert_eq!(code, Some(0), "{stderr}"),
    }
}

#[test]
fn req_dep_003_daemon_missing_file_and_usage() {
    let (code, stderr) = run_daemon_args(&["--config", "/nonexistent/kharon.toml"]);
    assert_eq!(code, Some(78), "{stderr}");
    assert!(stderr.contains("config error [read]"), "{stderr}");
    let (code, _) = run_daemon_args(&["--bogus"]);
    assert_eq!(code, Some(64));
}

fn run_daemon_args(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_kharond"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn req_dep_003_load_for_startup_reads_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kharon.toml");
    std::fs::write(&path, Parts::good().render()).unwrap();
    load_for_startup(&path, &StaticMlockProbe(Ok(()))).unwrap();
}

fn ca_pem() -> String {
    rcgen::generate_simple_self_signed(vec!["vault.example.net".into()])
        .unwrap()
        .cert
        .pem()
}

#[test]
fn req_dep_003_sync_client_built_from_config() {
    let mut p = Parts::good();
    let ca = fixture_file("ca.pem", ca_pem().as_bytes());
    set_bw(
        &mut p,
        &format!("ca_file = \"{}\"\n", ca.display()),
        api_key_path(),
    );
    let cfg = check(&p.render(), &StaticMlockProbe(Ok(()))).unwrap();
    let kharond::config::Source::Sync(bw) = &cfg.source else {
        panic!("sync mode");
    };
    assert_eq!(bw.ca_file.as_deref(), Some(ca.as_path()));
    assert!(bw.tls_trust().unwrap().extra_ca_pem.is_some());
    assert_eq!(bw.api_key().unwrap().client_id(), CLIENT_ID);
    let scope = bw.scope();
    assert!(
        format!("{scope:?}").contains(&ORG.to_ascii_lowercase()),
        "{scope:?}"
    );
    bw.sync_client().unwrap();

    // The daemon accepts the same config.
    let (code, stderr) = run_daemon(&p.render());
    assert_eq!(code, Some(0), "{stderr}");
}

#[test]
fn req_dep_003_ca_file_is_not_a_secret_key() {
    // `ca_file` passes the secret-shaped-key refusal; without it the
    // trust is OS roots only.
    let cfg = check(&Parts::good().render(), &StaticMlockProbe(Ok(()))).unwrap();
    let kharond::config::Source::Sync(bw) = &cfg.source else {
        panic!("sync mode");
    };
    assert!(bw.ca_file.is_none());
    assert!(bw.tls_trust().unwrap().extra_ca_pem.is_none());
}
