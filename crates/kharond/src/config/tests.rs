use super::*;

const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";

/// SPEC §9 example, with the `[policy]` line split (the spec's
/// `a = 1; b = 2` form is not valid TOML).
fn spec_example() -> String {
    format!(
        r#"
[bitwarden]
server = "http://vaultwarden:80"
email = "kharon@example.net"
api_key_file = "/run/secrets/kharon_bw_api_key"
organization_id = "0F3C2A6E-1B2C-4D5E-8F90-A1B2C3D4E5F6"
collection_ids = ["11111111-2222-3333-4444-555555555555"]
[agents.assistant]
token_hash = "{TOKEN_HASH}"
cdp = {{ endpoint = "ws://10.66.0.2:9222", via = "wireguard" }}
[policy]
idle_lock = "30m"
max_unlocked = "12h"
default_grant = "once"
allow_standing = false
[approval]
ntfy = {{ url = "https://ntfy.example.net", topic = "kharon", token_file = "/run/secrets/ntfy" }}
"#
    )
}

/// The spec example with `api_key_file` pointing at a real key file, for
/// tests that run [`Config::check_startup`].
fn spec_example_with_key() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.json");
    std::fs::write(
        &key,
        r#"{"client_id":"user.6b1e0c52-0a3e-4a8e-9a4f-1f0e2d3c4b5a","client_secret":"s"}"#,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let text = spec_example().replace("/run/secrets/kharon_bw_api_key", key.to_str().unwrap());
    (dir, text)
}

#[test]
fn req_dep_003_spec_example_loads_with_defaults() {
    let cfg = Config::from_toml_str(&spec_example()).unwrap();
    let Source::Sync(bw) = &cfg.source else {
        panic!("expected sync mode")
    };
    assert_eq!(bw.server.as_str(), "http://vaultwarden/");
    assert_eq!(bw.organization_id, "0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6");
    assert!(!bw.allow_extra_orgs);
    let agent = &cfg.agents["assistant"];
    assert_eq!(agent.cdp.tunnel, Tunnel::WireGuard);
    assert_eq!(cfg.policy, PolicyConfig::default());
    assert_eq!(cfg.audit, AuditConfig::default());
    assert!(cfg.memory.require_mlock);
    assert!(cfg.owner_ui.is_none());
    assert!(cfg.warnings().is_empty());
}

#[test]
fn req_dep_003_spec_defaults() {
    let p = PolicyConfig::default();
    assert_eq!(p.idle_lock, Duration::from_secs(30 * 60));
    assert_eq!(p.max_unlocked, Duration::from_secs(12 * 3600));
    assert_eq!(p.fill_deadline, Duration::from_secs(10));
    assert_eq!(p.clock_skew_warn, Duration::from_secs(30));
    assert_eq!(p.clock_skew_refuse, Duration::from_secs(90));
    assert_eq!(p.default_grant, GrantKind::Once);
    assert!(!p.allow_standing && !p.allow_http && !p.allow_default_context);
    assert!(p.allow_cross_origin_iframe_hosts.is_empty());
    assert!(MemoryConfig::default().require_mlock);
    let a = AuditConfig::default();
    assert!(!a.checkpoint_local_only && !a.item_names);
}

#[test]
fn req_dep_003_overrides_apply() {
    let text = spec_example().replace(
        "allow_standing = false",
        "allow_standing = true\nfill_deadline = \"2s\"\nallow_http = true",
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    assert_eq!(cfg.policy.fill_deadline, Duration::from_secs(2));
    assert!(cfg.policy.origin_config().allow_http);
    assert_eq!(
        cfg.warnings(),
        vec![
            ConfigWarning::StandingGrantsAllowed,
            ConfigWarning::HttpAllowed
        ]
    );
}

#[test]
fn req_dep_003_debug_never_shows_token_hash() {
    let cfg = Config::from_toml_str(&spec_example()).unwrap();
    let dbg = format!("{cfg:?} {:#?}", cfg.agents["assistant"]);
    assert!(!dbg.contains("CANARY"), "{dbg}");
    assert!(!dbg.contains("argon2id"), "{dbg}");
    assert!(dbg.contains("<redacted>"));
    assert_eq!(cfg.agents["assistant"].token_hash.expose(), TOKEN_HASH);
}

#[test]
fn req_dep_003_mlock_check_is_injected() {
    let (_dir, text) = spec_example_with_key();
    let cfg = Config::from_toml_str(&text).unwrap();
    cfg.check_startup(&StaticMlockProbe(Ok(()))).unwrap();
    let err = cfg
        .check_startup(&StaticMlockProbe(Err("no CAP_IPC_LOCK".into())))
        .unwrap_err();
    assert_eq!(err.code(), "mlock_unavailable");

    // require_mlock = false skips the probe, with a startup warning.
    let off = format!("{text}\n[memory]\nrequire_mlock = false\n");
    let cfg = Config::from_toml_str(&off).unwrap();
    cfg.check_startup(&StaticMlockProbe(Err("no".into())))
        .unwrap();
    assert_eq!(cfg.warnings(), vec![ConfigWarning::MlockNotRequired]);
}

#[test]
fn req_dep_003_export_mode() {
    let text = format!(
        r#"
mode = "export"
[export]
file = "/data/export.json"
[agents.solo]
token_hash = "{TOKEN_HASH}"
cdp = {{ endpoint = "ws://127.0.0.1:9222" }}
[policy]
allow_default_context = true
[audit]
checkpoint_local_only = true
"#
    );
    let cfg = Config::from_toml_str(&text).unwrap();
    assert_eq!(
        cfg.source,
        Source::Export(ExportConfig {
            file: "/data/export.json".into()
        })
    );
    assert_eq!(cfg.agents["solo"].cdp.tunnel, Tunnel::Direct);
    assert_eq!(
        cfg.warnings(),
        vec![ConfigWarning::AuditCheckpointLocalOnly]
    );
}

#[test]
fn req_apr_005_owner_ui_is_loopback_and_origin_matches_rp_id() {
    let ok = format!(
        "{}\n[api]\nlisten = \"127.0.0.1:8787\"\n[owner_ui]\nlisten = \"127.0.0.1:8788\"\norigin = \"http://localhost:8788/\"\n",
        spec_example()
    );
    let cfg = Config::from_toml_str(&ok).unwrap();
    let ui = cfg.owner_ui.expect("owner ui");
    assert_eq!(ui.rp_id, "localhost");
    assert_eq!(ui.origin, "http://localhost:8788");
    assert_eq!(ui.origin_for_bound_port(8788), "http://localhost:8788");

    let wildcard = spec_example()
        + "\n[owner_ui]\nlisten = \"0.0.0.0:8788\"\norigin = \"http://localhost:8788\"\n";
    assert_eq!(
        Config::from_toml_str(&wildcard).unwrap_err().code(),
        "owner_ui_not_loopback"
    );
    let remote = spec_example()
        + "\n[owner_ui]\nlisten = \"10.66.0.1:8788\"\norigin = \"http://localhost:8788\"\n";
    assert_eq!(
        Config::from_toml_str(&remote).unwrap_err().code(),
        "owner_ui_not_loopback"
    );
    let mismatch = spec_example()
        + "\n[owner_ui]\nlisten = \"127.0.0.1:8788\"\norigin = \"http://localhost:9\"\n";
    assert_eq!(
        Config::from_toml_str(&mismatch).unwrap_err().code(),
        "owner_ui_origin_port"
    );
    let ip_origin = spec_example()
        + "\n[owner_ui]\nlisten = \"127.0.0.1:8788\"\nrp_id = \"127.0.0.1\"\norigin = \"http://127.0.0.1:8788\"\n";
    assert_eq!(
        Config::from_toml_str(&ip_origin).unwrap_err().code(),
        "owner_ui_rp_id"
    );
}

/// #149: an API key file kharond's uid may not open, which is the
/// plain-Compose bind mount of an operator-owned 0400 file, fails the
/// startup check (and so `--check`) with the uid, owner and mode, not
/// the sync client's bare "API key file unreadable". Root opens
/// anything, so this needs an unprivileged test run.
#[test]
fn req_dep_008_check_startup_names_unopenable_key_file() {
    let euid = rustix::process::geteuid().as_raw();
    if euid == 0 {
        eprintln!("req_dep_008: running as root, which can open any file; skipped");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let (dir, text) = spec_example_with_key();
    let key = dir.path().join("key.json");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
    let cfg = Config::from_toml_str(&text).unwrap();
    let err = cfg.check_startup(&StaticMlockProbe(Ok(()))).unwrap_err();
    assert_eq!(
        err,
        ConfigError::ApiKeyFileNotReadable {
            euid,
            owner: euid,
            mode: 0
        }
    );
    assert_eq!(err.code(), "api_key_file");
}

/// #149: a TLS certificate or private key kharond's uid may not open
/// says so; a missing one keeps the plain "unreadable" reason.
#[test]
fn req_dep_008_tls_material_not_openable_is_named() {
    if rustix::process::geteuid().is_root() {
        eprintln!("req_dep_008: running as root, which can open any file; skipped");
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("tls.crt");
    let key = dir.path().join("tls.key");
    // Never parsed: every case below fails on a read first.
    std::fs::write(&cert, b"cert").unwrap();
    std::fs::write(&key, b"key").unwrap();
    let material = TlsMaterial {
        cert_file: cert.clone(),
        key_file: key.clone(),
    };
    let reason = |m: &TlsMaterial| match load_tls(m) {
        Err(ConfigError::TlsMaterial { reason }) => reason,
        other => panic!("expected a tls_material refusal, got {other:?}"),
    };

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        reason(&material),
        "private key not readable by kharond's uid (make it owned by that uid, mode 0400)"
    );

    std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        reason(&material),
        "certificate not readable by kharond's uid (check owner and mode)"
    );

    std::fs::remove_file(&cert).unwrap();
    std::fs::remove_file(&key).unwrap();
    assert_eq!(reason(&material), "unreadable certificate");
    std::fs::write(&cert, b"cert").unwrap();
    assert_eq!(reason(&material), "unreadable private key");
}
