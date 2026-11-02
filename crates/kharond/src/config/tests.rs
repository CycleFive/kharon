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
    let cfg = Config::from_toml_str(&spec_example()).unwrap();
    cfg.check_startup(&StaticMlockProbe(Ok(()))).unwrap();
    let err = cfg
        .check_startup(&StaticMlockProbe(Err("no CAP_IPC_LOCK".into())))
        .unwrap_err();
    assert_eq!(err.code(), "mlock_unavailable");

    // require_mlock = false skips the probe, with a startup warning.
    let off = format!("{}\n[memory]\nrequire_mlock = false\n", spec_example());
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
