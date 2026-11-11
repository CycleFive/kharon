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

/// Path B export-mode config with the given `[connector]` body and an
/// optional `[public_ingress]`.
fn connector_config(connector: &str, public_ingress: bool) -> String {
    let public = if public_ingress {
        "[public_ingress]\nlisten = \"127.0.0.1:8790\"\n"
    } else {
        ""
    };
    format!(
        r#"mode = "export"
data_dir = "/data"
[export]
file = "/run/secrets/export.json"
[audit]
checkpoint_local_only = true
[agents.assistant]
token_hash = "{TOKEN_HASH}"
connector_token_hash = "{TOKEN_HASH}"
cdp = {{ endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }}
{public}
[connector]
{connector}
tls_cert_file = "/run/secrets/tls.crt"
tls_key_file = "/run/secrets/tls.key"
"#
    )
}

/// #199: `listen` may be left out when the WebSocket carries the agents.
#[test]
fn connector_listen_is_optional_with_websocket() {
    let cfg = Config::from_toml_str(&connector_config("websocket = true", true)).unwrap();
    let connector = cfg.connector.unwrap();
    assert_eq!(connector.listen, None);
    assert!(connector.websocket);

    let both = connector_config("listen = \"127.0.0.1:8789\"\nwebsocket = true", true);
    let connector = Config::from_toml_str(&both).unwrap().connector.unwrap();
    assert_eq!(connector.listen, Some("127.0.0.1:8789".parse().unwrap()));
    assert!(connector.websocket);
}

#[test]
fn connector_no_transport_refused() {
    for body in ["", "websocket = false"] {
        let err = Config::from_toml_str(&connector_config(body, true)).unwrap_err();
        assert_eq!(err, ConfigError::ConnectorNoTransport, "{body}");
        assert_eq!(err.code(), "connector_no_transport");
    }
}

#[test]
fn connector_websocket_needs_public_ingress() {
    let err = Config::from_toml_str(&connector_config("websocket = true", false)).unwrap_err();
    assert_eq!(err, ConfigError::ConnectorWebsocketNeedsPublicIngress);
    assert_eq!(err.code(), "connector_websocket_needs_public_ingress");
    // `listen` alone never needs a public ingress.
    let ok = connector_config("listen = \"127.0.0.1:8789\"", false);
    assert!(Config::from_toml_str(&ok).is_ok());
}

/// An existing config with only `listen` parses as it always did: the
/// raw listener, no WebSocket.
#[test]
fn connector_listen_only_unchanged() {
    let cfg =
        Config::from_toml_str(&connector_config("listen = \"127.0.0.1:8789\"", false)).unwrap();
    let connector = cfg.connector.unwrap();
    assert_eq!(connector.listen, Some("127.0.0.1:8789".parse().unwrap()));
    assert!(!connector.websocket);
}

/// Config with an `[owner_ui]` body (and optional extra tables) on the
/// spec example.
fn owner_ui_config(body: &str) -> String {
    format!("{}\n[owner_ui]\n{body}\n", spec_example())
}

fn owner_ui_err(body: &str) -> ConfigError {
    Config::from_toml_str(&owner_ui_config(body)).unwrap_err()
}

#[test]
fn owner_ui_public_origin_enables_public_mode() {
    let cfg = Config::from_toml_str(&owner_ui_config(
        "listen = \"127.0.0.1:8788\"\npublic_origin = \"https://kharon-owner.example.com\"",
    ))
    .unwrap();
    let ui = cfg.owner_ui.unwrap();
    assert!(ui.public);
    assert_eq!(ui.origin, "https://kharon-owner.example.com");
    assert_eq!(ui.rp_id, "kharon-owner.example.com");
    assert_eq!(ui.authority(), ("kharon-owner.example.com".to_owned(), 443));
    assert_eq!(ui.access, None);
}

#[test]
fn owner_ui_local_mode_is_not_public() {
    let cfg = Config::from_toml_str(&owner_ui_config(
        "listen = \"127.0.0.1:8788\"\norigin = \"http://localhost:8788\"",
    ))
    .unwrap();
    let ui = cfg.owner_ui.unwrap();
    assert!(!ui.public);
    assert_eq!(ui.access, None);
    assert_eq!(ui.authority(), ("localhost".to_owned(), 8788));
}

#[test]
fn owner_ui_public_origin_normalizes_ports() {
    let load = |origin: &str| {
        Config::from_toml_str(&owner_ui_config(&format!(
            "listen = \"127.0.0.1:8788\"\npublic_origin = \"{origin}\""
        )))
        .unwrap()
        .owner_ui
        .unwrap()
    };
    let ui = load("https://o.example.com:443");
    assert_eq!(ui.origin, "https://o.example.com");
    assert_eq!(ui.authority().1, 443);
    let ui = load("https://o.example.com:8443");
    assert_eq!(ui.origin, "https://o.example.com:8443");
    assert_eq!(ui.authority().1, 8443);
}

#[test]
fn owner_ui_public_mode_ignores_the_listen_port() {
    for listen in ["127.0.0.1:0", "127.0.0.1:8788"] {
        let cfg = Config::from_toml_str(&owner_ui_config(&format!(
            "listen = \"{listen}\"\npublic_origin = \"https://o.example.com\""
        )))
        .unwrap();
        let ui = cfg.owner_ui.unwrap();
        assert_eq!(ui.origin_for_bound_port(54321), "https://o.example.com");
    }
}

#[test]
fn owner_ui_needs_exactly_one_origin() {
    let both = owner_ui_err(
        "listen = \"127.0.0.1:8788\"\norigin = \"http://localhost:8788\"\npublic_origin = \"https://o.example.com\"",
    );
    assert_eq!(both, ConfigError::OwnerUiOriginChoice);
    assert_eq!(both.code(), "owner_ui_origin_choice");
    let neither = owner_ui_err("listen = \"127.0.0.1:8788\"");
    assert_eq!(neither, ConfigError::OwnerUiOriginChoice);
}

#[test]
fn owner_ui_public_origin_must_be_https_and_bare() {
    for origin in [
        "http://o.example.com",
        "https://203.0.113.7",
        "https://o.example.com/x",
        "https://u@o.example.com",
        "https://o.example.com?x=1",
    ] {
        let err = owner_ui_err(&format!(
            "listen = \"127.0.0.1:8788\"\npublic_origin = \"{origin}\""
        ));
        assert_eq!(err, ConfigError::OwnerUiPublicOrigin, "{origin}");
        assert_eq!(err.code(), "owner_ui_public_origin");
    }
    let err = owner_ui_err(
        "listen = \"127.0.0.1:8788\"\nrp_id = \"example.com\"\npublic_origin = \"https://o.example.com\"",
    );
    assert_eq!(err, ConfigError::OwnerUiPublicOrigin);
}

#[test]
fn owner_ui_access_needs_public_mode() {
    let err = owner_ui_err(
        "listen = \"127.0.0.1:8788\"\norigin = \"http://localhost:8788\"\n[owner_ui.access]\nteam_domain = \"t.cloudflareaccess.com\"\naudience = \"abc123\"",
    );
    assert_eq!(err, ConfigError::OwnerUiAccessNeedsPublicOrigin);
    assert_eq!(err.code(), "owner_ui_access_needs_public_origin");
}

fn public_access(access: &str) -> String {
    format!(
        "listen = \"127.0.0.1:8788\"\npublic_origin = \"https://o.example.com\"\n[owner_ui.access]\n{access}"
    )
}

#[test]
fn owner_ui_access_is_validated() {
    for access in [
        "team_domain = \"evil.example.com\"\naudience = \"abc123\"",
        "team_domain = \"t.cloudflareaccess.com\"\naudience = \"\"",
        "team_domain = \"t.cloudflareaccess.com\"\naudience = \"a b\"",
    ] {
        let err = owner_ui_err(&public_access(access));
        assert_eq!(err, ConfigError::OwnerUiAccess, "{access}");
        assert_eq!(err.code(), "owner_ui_access");
    }
    let cfg = Config::from_toml_str(&owner_ui_config(&public_access(
        "team_domain = \"t.cloudflareaccess.com\"\naudience = \"abc123\"",
    )))
    .unwrap();
    assert_eq!(
        cfg.owner_ui.unwrap().access,
        Some(AccessConfig {
            team_domain: "t.cloudflareaccess.com".to_owned(),
            audience: "abc123".to_owned(),
            jwks: JwksSource::TeamCerts,
        })
    );
}

#[test]
fn owner_ui_access_has_no_jwks_key() {
    for extra in ["jwks = \"{}\"", "jwks_url = \"https://x\""] {
        let body = public_access(&format!(
            "team_domain = \"t.cloudflareaccess.com\"\naudience = \"abc123\"\n{extra}"
        ));
        assert!(
            Config::from_toml_str(&owner_ui_config(&body)).is_err(),
            "{extra}"
        );
    }
}

#[test]
fn public_ingress_public_host_is_optional_and_validated() {
    let load = |extra: &str| {
        Config::from_toml_str(&format!(
            "{}\n[public_ingress]\nlisten = \"127.0.0.1:8790\"\n{extra}\n",
            spec_example()
        ))
    };
    assert_eq!(load("").unwrap().public_ingress.unwrap().public_host, None);
    assert_eq!(
        load("public_host = \"Kharon.Example.com\"")
            .unwrap()
            .public_ingress
            .unwrap()
            .public_host,
        Some("kharon.example.com".to_owned())
    );
    for bad in ["https://x", "203.0.113.7", "a b"] {
        let err = load(&format!("public_host = \"{bad}\"")).unwrap_err();
        assert_eq!(err, ConfigError::PublicIngressPublicHost, "{bad}");
        assert_eq!(err.code(), "public_ingress_public_host");
    }
}
