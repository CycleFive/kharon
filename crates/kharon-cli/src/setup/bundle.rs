//! The agent-host bundle (#405, #401 assumption 2).
//!
//! With `--cdp-via agent-connector` (path B), setup makes everything the
//! agent host needs and puts it in one directory for out-of-band
//! transfer, so that side is copy-and-run instead of assembled from the
//! docs:
//!
//! | File | Secret | What it is |
//! |---|---|---|
//! | `connector.toml` | no | The connector's config, ready for `/etc/kharon-connector/connector.toml` |
//! | `connector-tunnel-token` | **yes** | The tunnel credential (`kh_tunnel_…`), for the connector only |
//! | `agent-api-token` | **yes** | The agent API token (`kh_agent_…`), for the agent's MCP client only |
//! | `broker-pin` | no, but must arrive unaltered | SHA-256 of the `[connector]` certificate (also in `connector.toml`) |
//! | `agent-id` | no | The `[agents.<id>]` name (also in `connector.toml`) |
//! | `apply.sh` | no | Installs the connector side on the agent host |
//! | `README.txt` | no | The same table, and the steps |
//!
//! The two tokens are not interchangeable (REQ-ARCH-001): the connector
//! refuses anything but `kh_tunnel_`/`kh_at_`, the broker refuses a
//! `kh_tunnel_` on `/mcp`, and `apply.sh` installs only the tunnel
//! credential. Each sits alone in a file named for its role, because the
//! connector's `token_file` must hold the bare credential and nothing
//! else.
//!
//! Everything here is pure text. Writing it (create-new, modes,
//! rollback) is [`super::run`]'s job, with the same `create_file` as the
//! other setup files.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::toml_str;

/// Where the connector reads its config and credential on the agent
/// host. Same paths as `deploy/agent-host/provision-connector.sh` and
/// `docs/agent-runtime-setup.md`.
pub const AGENT_CONFIG: &str = "/etc/kharon-connector/connector.toml";
pub const AGENT_TOKEN_FILE: &str = "/etc/kharon-connector/token";

/// File names inside the bundle directory.
pub const CONNECTOR_TOML: &str = "connector.toml";
pub const TUNNEL_TOKEN: &str = "connector-tunnel-token";
pub const AGENT_TOKEN: &str = "agent-api-token";
pub const BROKER_PIN: &str = "broker-pin";
pub const AGENT_ID: &str = "agent-id";
pub const APPLY: &str = "apply.sh";
pub const README: &str = "README.txt";

/// Path B as setup decided it, before anything is written.
#[derive(Clone, Debug)]
pub struct ConnectorPlan {
    /// The `[connector]` certificate and key on this host.
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// The same two files as kharond sees them (`tls_cert_file`,
    /// `tls_key_file`). Equal to the host paths in the host layout.
    pub cert_in_config: PathBuf,
    pub key_in_config: PathBuf,
    /// Compose layout: the `docker-compose.override.yml` that mounts
    /// the pair where the config points. `None` in the host layout.
    pub compose_override: Option<PathBuf>,
    /// The bundle directory (created, mode 0700).
    pub bundle_dir: PathBuf,
    /// The public host: the connector dials `wss://<host>/connector`,
    /// and the certificate is issued for it (the inner TLS name).
    pub public_host: String,
    /// The agent host's loopback CDP socket for `connector.toml`'s
    /// `cdp`, from the endpoint in `[agents.<id>].cdp`.
    pub cdp: String,
}

impl ConnectorPlan {
    pub fn broker_url(&self) -> String {
        format!("wss://{}/connector", self.public_host)
    }
}

/// A fresh self-signed `[connector]` certificate and key.
pub struct TlsPair {
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
    /// `broker_pin`: lowercase hex SHA-256 of the certificate DER.
    pub pin_hex: String,
}

/// Generate the `[connector]` TLS pair for `host`. The connector pins
/// the certificate's SHA-256 and does not use WebPKI or the expiry
/// (`docs/deployment.md`, path B), so self-signed is the documented
/// choice. The key never leaves the broker host.
pub fn generate_tls(host: &str) -> Result<TlsPair, String> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![host.to_owned()])
            .map_err(|e| format!("cannot generate the connector certificate: {e}"))?;
    let pin = kharon_connector::pin_of_der(cert.der());
    Ok(TlsPair {
        cert_pem: cert.pem(),
        key_pem: Zeroizing::new(key_pair.serialize_pem()),
        pin_hex: hex(&pin),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `cdp` socket for `connector.toml` from a `ws://` loopback
/// endpoint (kharond requires exactly that for `via = agent_connector`;
/// the connector requires a loopback socket).
pub fn cdp_socket(endpoint: &str) -> Result<String, String> {
    let bad = || {
        format!(
            "with --cdp-via agent-connector the CDP endpoint is Chromium on the agent host's \
             loopback, e.g. ws://127.0.0.1:9222, not {endpoint:?}"
        )
    };
    let url = url::Url::parse(endpoint).map_err(|_| bad())?;
    if url.scheme() != "ws" {
        return Err(bad());
    }
    let port = url.port_or_known_default().ok_or_else(bad)?;
    let ip: std::net::IpAddr = match url.host() {
        Some(url::Host::Domain("localhost")) => std::net::Ipv4Addr::LOCALHOST.into(),
        Some(url::Host::Ipv4(a)) => a.into(),
        Some(url::Host::Ipv6(a)) => a.into(),
        _ => return Err(bad()),
    };
    if !ip.is_loopback() || port == 0 {
        return Err(bad());
    }
    Ok(std::net::SocketAddr::new(ip, port).to_string())
}

/// `connector.toml` for the agent host. No secret: the credential is in
/// `token_file`, which `apply.sh` installs from the bundle.
pub fn connector_toml(c: &ConnectorPlan, agent_id: &str, pin_hex: &str) -> String {
    format!(
        "# Written by `kharon setup` (#405) for agent `{agent_id}`. No secret here:\n\
         # the tunnel credential is token_file, installed by apply.sh. Check with\n\
         # kharon-agent-connector --config {AGENT_CONFIG} --check\n\
         transport = \"ws\"\n\
         broker_url = {url}\n\
         broker_pin = {pin}\n\
         agent_id = {id}\n\
         token_file = {tok}\n\
         cdp = {cdp}\n",
        url = toml_str(&c.broker_url()),
        pin = toml_str(pin_hex),
        id = toml_str(agent_id),
        tok = toml_str(AGENT_TOKEN_FILE),
        cdp = toml_str(&c.cdp),
    )
}

/// The connector's systemd unit, the same text as
/// `deploy/agent-host/provision-connector.sh` writes (a test keeps the
/// two in step).
pub const CONNECTOR_UNIT: &str = "[Unit]
Description=Outbound TLS connector to loopback CDP
After=network-online.target browser.service
Wants=network-online.target

[Service]
User=connector
Group=connector
ExecStart=/usr/local/bin/kharon-agent-connector --config /etc/kharon-connector/connector.toml
Restart=always
RestartSec=1
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/kharon-connector

[Install]
WantedBy=multi-user.target
";

/// `apply.sh`: install the connector side from the files beside it. It
/// reads no secret into a variable, an argument or the environment:
/// `install` copies the credential file as is.
pub fn apply_sh(agent_id: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "#!/bin/sh\n\
         # Written by `kharon setup` (#405) for agent `{agent_id}`.\n\
         # Run as root on the agent host, from anywhere:\n\
         #   sudo ./apply.sh [path/to/kharon-agent-connector]\n\
         #\n\
         # Installs the connector side only: the `connector` user, the tunnel\n\
         # credential ({AGENT_TOKEN_FILE}, mode 0400), connector.toml\n\
         # ({AGENT_CONFIG}), the binary if you name it, then checks the\n\
         # connection and starts the connector (systemd), or prints the command\n\
         # for your supervisor. It never installs {AGENT_TOKEN}: that goes in\n\
         # the agent's MCP client. Chromium with CDP on loopback is the agent\n\
         # host's own (provision-connector.sh, or your runtime's).\n\
         # Re-running is safe: the files are replaced.\n"
    ));
    s.push_str(
        r#"set -eu
cd "$(dirname "$0")"
say() { printf 'apply.sh: %s\n' "$*"; }
die() { printf 'apply.sh: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./apply.sh)"
for f in connector.toml connector-tunnel-token; do
    [ -f "$f" ] || die "$f is missing: run the apply.sh inside the bundle directory"
done

if ! id -u connector >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/kharon-connector \
        --shell /usr/sbin/nologin connector
fi
install -d -m 0700 -o connector -g connector /var/lib/kharon-connector
install -d -m 0755 -o root -g root /etc/kharon-connector
install -m 0400 -o connector -g connector connector-tunnel-token /etc/kharon-connector/token
install -m 0644 -o root -g root connector.toml /etc/kharon-connector/connector.toml

BIN=/usr/local/bin/kharon-agent-connector
if [ $# -ge 1 ]; then
    [ -f "$1" ] || die "$1 is not a file"
    install -m 0755 -o root -g root "$1" "$BIN"
fi
[ -x "$BIN" ] || die "no $BIN: run again as sudo ./apply.sh path/to/kharon-agent-connector (cargo build --release -p kharon-agent-connector)"

if [ -d /run/systemd/system ]; then
    systemctl stop kharon-agent-connector.service 2>/dev/null || true
fi
say "checking the connection to the broker as the connector user"
if command -v runuser >/dev/null 2>&1; then
    runuser -u connector -- "$BIN" --config /etc/kharon-connector/connector.toml --check \
        || die "the check failed (each leg is listed above); nothing was started"
else
    say "no runuser here: skipping the check"
fi

if [ -d /run/systemd/system ]; then
    install -m 0644 -o root -g root /dev/stdin /etc/systemd/system/kharon-agent-connector.service <<'UNIT'
"#,
    );
    s.push_str(CONNECTOR_UNIT);
    s.push_str(
        r#"UNIT
    systemctl daemon-reload
    systemctl enable -q kharon-agent-connector.service
    systemctl restart kharon-agent-connector.service
    say "connector started (systemctl status kharon-agent-connector)"
else
    say "no systemd: run, as the connector user, under your supervisor:"
    say "  $BIN --config /etc/kharon-connector/connector.toml"
fi
say "the broker logs 'agent connector attached' when it is up"
say "agent-api-token was NOT installed: put it in the agent's MCP client as its bearer token"
say "then delete this bundle directory: it holds both secrets"
"#,
    );
    s
}

/// `README.txt`: what each file is, labelled by role, and the steps.
pub fn readme(c: &ConnectorPlan, agent_id: &str, pin_hex: &str) -> String {
    format!(
        "kharon agent-host bundle for agent `{agent_id}` (written by `kharon setup`, #405)\n\
         \n\
         THIS DIRECTORY HOLDS TWO SECRETS. Move it to the agent host out of band\n\
         (scp, a USB stick), not through chat, email, a ticket or a prompt, and\n\
         delete every copy once it is applied.\n\
         \n\
         File                    Secret  Role\n\
         {TUNNEL_TOKEN:<23} YES     Tunnel credential (kh_tunnel_...). For the CONNECTOR only.\n\
         {:<23}         apply.sh installs it at {AGENT_TOKEN_FILE}, mode 0400.\n\
         {AGENT_TOKEN:<23} YES     Agent API token (kh_agent_...). For the agent's MCP CLIENT only:\n\
         {:<23}         the bearer for POST https://{host}/mcp. Store it in the client's\n\
         {:<23}         secret setting, never in a prompt or a file the model reads.\n\
         {CONNECTOR_TOML:<23} no      The connector's config for {AGENT_CONFIG}.\n\
         {BROKER_PIN:<23} no      broker_pin: SHA-256 of the broker's [connector] certificate.\n\
         {:<23}         Not secret, but it must arrive unaltered. Compare it with\n\
         {:<23}         the value setup printed on the broker host.\n\
         {AGENT_ID:<23} no      The agent id ([agents.{agent_id}] on the broker).\n\
         {APPLY:<23} no      Installs the connector side (below).\n\
         \n\
         The two tokens are not interchangeable: the connector refuses the agent\n\
         token, and the broker refuses the tunnel credential on /mcp.\n\
         \n\
         broker_pin = {pin_hex}\n\
         broker_url = {url}\n\
         \n\
         On the agent host\n\
         \n\
         1. Chromium with CDP on {cdp} (deploy/agent-host/provision-connector.sh\n\
            sets it up on Debian; a hosted runtime has its own).\n\
         2. sudo ./apply.sh path/to/kharon-agent-connector\n\
            It installs the connector user, the credential and connector.toml,\n\
            runs `kharon-agent-connector --check`, and starts the connector\n\
            under systemd if there is one (or prints the command to run).\n\
            Without root, do the same by hand: {TUNNEL_TOKEN} to\n\
            {AGENT_TOKEN_FILE} (mode 0400, the connector's uid) and\n\
            {CONNECTOR_TOML} to {AGENT_CONFIG}.\n\
         3. Put {AGENT_TOKEN} in the agent's MCP client (see above).\n\
         4. Delete this directory, here and on the broker host.\n",
        "",
        "",
        "",
        "",
        "",
        host = c.public_host,
        url = c.broker_url(),
        cdp = c.cdp,
    )
}

/// `docker-compose.override.yml` for the Compose layout: mount the
/// `[connector]` pair read-only where the config points. Compose merges
/// this file with `docker-compose.yml` on its own.
pub fn compose_override(c: &ConnectorPlan) -> String {
    let src = |p: &Path| {
        let s = p.to_string_lossy().into_owned();
        if p.is_absolute() || s.starts_with("./") || s.starts_with("../") {
            s
        } else {
            format!("./{s}")
        }
    };
    format!(
        "# Written by `kharon setup` (#405): the [connector] TLS pair for path B,\n\
         # mounted read-only where kharon.toml points. The key stays uid 10001,\n\
         # mode 0400 (Compose keeps the host file's owner and mode).\n\
         services:\n  kharon:\n    volumes:\n\
         \x20     - {cert}\n\
         \x20     - {key}\n",
        cert = yaml_str(&format!(
            "{}:{}:ro",
            src(&c.cert_path),
            c.cert_in_config.display()
        )),
        key = yaml_str(&format!(
            "{}:{}:ro",
            src(&c.key_path),
            c.key_in_config.display()
        )),
    )
}

/// A YAML double-quoted scalar (JSON string syntax is valid YAML).
fn yaml_str(s: &str) -> String {
    serde_json::to_string(s).expect("invariant: a string serializes")
}
