//! Issue #207 (N1 of the portable gateway), REQ-DEP-002 and
//! REQ-DEP-006: the compose package. kharond and cloudflared share a
//! do-nothing holder container's network namespace, nothing is
//! published, the tunnel token is a secret file, and the WireGuard
//! network is an overlay (`compose.vpn.yml`).
//!
//! The docker-gated tests (`#[ignore]`) run from `image.yml`; they
//! only render `docker compose config`, so they need the CLI but no
//! daemon, image or secret files.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use kharond::config::{Config, Source};
use serde::Deserialize;

const HOLDER_IMAGE: &str = "registry.k8s.io/pause:3.10@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a";
const CLOUDFLARED_IMAGE: &str = "cloudflare/cloudflared:2026.10.4@sha256:c6c7ae1d5dfdcb094ad344ed68ccffc26635c9c6be80965664c33baf064b0515";
const CLOUDFLARED_COMMAND: &[&str] = &[
    "tunnel",
    "--metrics",
    "127.0.0.1:20241",
    "run",
    "--token-file",
    "/run/secrets/cloudflared_tunnel_token",
];

#[derive(Deserialize)]
struct Compose {
    services: BTreeMap<String, Service>,
    #[serde(default)]
    secrets: BTreeMap<String, TopSecret>,
}

#[derive(Deserialize)]
struct Service {
    image: Option<String>,
    network_mode: Option<String>,
    #[serde(default)]
    ports: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    networks: BTreeMap<String, Option<ServiceNetwork>>,
    /// `null` when the service keeps the image's command.
    command: Option<Vec<String>>,
    #[serde(default)]
    environment: BTreeMap<String, Option<String>>,
    #[serde(default)]
    secrets: Vec<ServiceSecret>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    cap_drop: Vec<String>,
}

#[derive(Deserialize)]
struct ServiceNetwork {
    ipv4_address: Option<String>,
}

#[derive(Deserialize)]
struct ServiceSecret {
    source: String,
}

#[derive(Deserialize)]
struct TopSecret {
    file: Option<String>,
}

fn compose_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/compose"))
}

/// Render the compose model with the given overlays layered on the
/// base file, both profiles on.
fn config(overlays: &[&str]) -> Compose {
    let dir = compose_dir();
    let mut cmd = Command::new("docker");
    cmd.arg("compose")
        .arg("-f")
        .arg(dir.join("docker-compose.yml"));
    for overlay in overlays {
        cmd.arg("-f").arg(dir.join(overlay));
    }
    let out = cmd
        .args([
            "--profile",
            "edge",
            "--profile",
            "vaultwarden",
            "config",
            "--format",
            "json",
        ])
        .output()
        .expect("run docker compose");
    assert!(
        out.status.success(),
        "docker compose config failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse compose config")
}

#[test]
fn n1_example_config_is_loopback_only() {
    let raw = std::fs::read_to_string(compose_dir().join("kharon.toml.example"))
        .expect("read kharon.toml.example");
    let hash = format!("{:?}", kharond::api::token::generate("assistant").1);
    let text = raw.replace("\"$argon2id$...\"", &hash);
    let cfg = Config::from_toml_str(&text).expect("example config parses");

    assert_eq!(cfg.api.expect("api").listen.to_string(), "127.0.0.1:8787");
    let ingress = cfg.public_ingress.expect("public_ingress");
    assert_eq!(ingress.listen.to_string(), "127.0.0.1:8790");
    assert!(ingress.tls.is_none());
    assert!(cfg.connector.is_none());
    assert!(cfg.owner_ui.is_none());
    let Source::Sync(bw) = &cfg.source else {
        panic!("example config is not a Bitwarden sync source");
    };
    assert_eq!(bw.server.as_str(), "https://vault.bitwarden.com/");
}

#[test]
#[ignore = "needs docker (image.yml)"]
fn n1_base_compose_publishes_nothing_and_shares_the_holder_netns() {
    let c = config(&[]);
    let names: Vec<&str> = c.services.keys().map(String::as_str).collect();
    assert_eq!(names, ["cloudflared", "holder", "kharon", "vaultwarden"]);
    for (name, svc) in &c.services {
        assert!(svc.ports.is_empty(), "{name} publishes a port");
    }
    let (holder, kharon, cf) = (
        &c.services["holder"],
        &c.services["kharon"],
        &c.services["cloudflared"],
    );
    assert_eq!(kharon.network_mode.as_deref(), Some("service:holder"));
    assert_eq!(cf.network_mode.as_deref(), Some("service:holder"));
    assert!(kharon.networks.is_empty());
    assert_eq!(holder.network_mode, None);
    let nets: Vec<&str> = holder.networks.keys().map(String::as_str).collect();
    assert_eq!(nets, ["default"]);
}

#[test]
#[ignore = "needs docker (image.yml)"]
fn n1_holder_and_cloudflared_are_pinned() {
    let c = config(&[]);
    let holder = &c.services["holder"];
    let cf = &c.services["cloudflared"];
    assert_eq!(holder.image.as_deref(), Some(HOLDER_IMAGE));
    assert_eq!(cf.image.as_deref(), Some(CLOUDFLARED_IMAGE));
    for (name, svc) in [("holder", holder), ("cloudflared", cf)] {
        assert!(svc.read_only, "{name} is not read_only");
        assert!(
            svc.cap_drop.iter().any(|c| c == "ALL"),
            "{name} does not drop ALL caps"
        );
    }
}

#[test]
#[ignore = "needs docker (image.yml)"]
fn n1_cloudflared_reads_its_token_from_a_secret_file() {
    let c = config(&[]);
    let cf = &c.services["cloudflared"];
    let command = cf.command.as_deref().expect("cloudflared sets a command");
    assert_eq!(command, CLOUDFLARED_COMMAND);
    assert!(!command.iter().any(|a| a == "--token"));
    assert!(!cf.environment.contains_key("TUNNEL_TOKEN"));
    assert!(
        cf.secrets
            .iter()
            .any(|s| s.source == "cloudflared_tunnel_token"),
        "cloudflared does not mount the tunnel token secret"
    );
    let file = c.secrets["cloudflared_tunnel_token"]
        .file
        .as_deref()
        .expect("secret has a file");
    assert!(
        file.ends_with("/secrets/cloudflared_tunnel_token"),
        "unexpected secret file {file}"
    );
    assert_eq!(cf.profiles, ["edge"]);
    assert_eq!(c.services["vaultwarden"].profiles, ["vaultwarden"]);
}

#[test]
#[ignore = "needs docker (image.yml)"]
fn n1_vpn_overlay_puts_the_holder_on_wg() {
    let c = config(&["compose.vpn.yml"]);
    let holder = &c.services["holder"];
    let nets: Vec<&str> = holder.networks.keys().map(String::as_str).collect();
    assert_eq!(nets, ["default", "wg"]);
    let wg = holder.networks["wg"].as_ref().expect("wg network settings");
    assert_eq!(wg.ipv4_address.as_deref(), Some("10.66.0.1"));
    assert_eq!(
        c.services["kharon"].network_mode.as_deref(),
        Some("service:holder")
    );
}

#[test]
fn n1_tunnel_routes_in_docs_use_127_0_0_1() {
    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let read =
        |p: &str| std::fs::read_to_string(root.join(p)).unwrap_or_else(|e| panic!("read {p}: {e}"));
    let files = [
        "docs/deployment.md",
        "deploy/compose/README.md",
        "deploy/cloudflared/config.yml",
        "deploy/compose/docker-compose.yml",
        "deploy/compose/kharon.toml.example",
    ];
    for f in files {
        for line in read(f).lines() {
            assert!(
                !(line.contains("localhost") && line.contains("8790")),
                "{f}: tunnel origin uses localhost: {line}"
            );
            assert!(
                !((line.contains("service:") || line.contains('→') || line.contains("route"))
                    && line.contains("localhost")),
                "{f}: route or service line uses localhost: {line}"
            );
        }
    }
    let readme = read("deploy/compose/README.md");
    for needle in ["COMPOSE_PROFILES=edge", "65532:65532", "compose.vpn.yml"] {
        assert!(readme.contains(needle), "compose README lacks {needle}");
    }
    let guide = read("docs/deployment.md");
    for needle in ["http://127.0.0.1:8790", "--token-file"] {
        assert!(guide.contains(needle), "deployment guide lacks {needle}");
    }
}
