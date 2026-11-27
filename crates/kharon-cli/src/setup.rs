//! `kharon setup`: the guided first-run flow on the broker host (#404,
//! #401 assumption 1, scope (a) of the M3 Groom on #398).
//!
//! The operator has created the dedicated kharon account themselves, on
//! Bitwarden cloud or their own Vaultwarden. Setup replaces the
//! hand-copied steps that come after that:
//!
//! 1. Offer `kharon init` (the account's master password) if the account
//!    does not exist yet. The password has to exist before the account
//!    does, so this is the first step, not the last.
//! 2. Ask for the server URL, the account email and the personal API key,
//!    and check the key type on entry with [`check_client_id`] (#403), so
//!    an `organization.` key is refused before anything else happens.
//! 3. Log in with the key, sync once, and list the organizations and
//!    collections the account can see ([`kharond::sync::discover`]), so
//!    the operator picks them instead of pasting UUIDs. The REQ-CRY-008
//!    scope check runs on the same sync, so an account kharond would
//!    refuse is refused here, with the fix.
//! 4. Mint the first agent token, render `kharon.toml` with its hash in
//!    it, including the mandatory `[approval]` ntfy topic (which is also
//!    the off-host audit checkpoint sink), and validate it with the
//!    daemon's own loader and `kharond --check` rules before anything is
//!    written.
//! 5. Write the API key file (`0400`, owned by kharond's uid) and the
//!    config. Any failure after the first write removes what was written.
//! 6. Show the agent token once: on the terminal, or into a new `0600`
//!    file named by `--agent-token-file`.
//!
//! Every prompt has a flag and an answers-file key of the same name, so
//! a provisioner can run the whole flow with `--non-interactive` (#404
//! assumption 1). A prompt with a default uses it; a prompt without one
//! is a required flag in that mode.
//!
//! What setup does not do: weaken a refusal. It writes nothing kharond
//! would refuse (the rendered file goes through `Config::from_toml_str`
//! and `daemon::check`), it never sets `allow_extra_orgs`,
//! `checkpoint_local_only` or `allow_standing`, and it never asks for the
//! master password: that stays on the unlock channel (SPEC §8).
//!
//! Secrets: the client secret is read with echo off or from the JSON file
//! Bitwarden shows, never from argv or env, and goes only into the key
//! file. The agent token goes only to the terminal or the token file.
//! Neither is ever in an error message.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use kharond::sync::{
    ApiKey, Discovery, SyncError, TlsTrust, check_client_id, discover, scope_violation,
    wire::SyncResponse,
};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

/// Where the files go: the Compose example or a host install
/// (`docs/broker-lifecycle.md`). Both run kharond as uid 10001.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layout {
    /// `./kharon.toml` and `./secrets/kharon_bw_api_key.json` (run in
    /// `deploy/compose`); the daemon reads `/run/secrets/kharon_bw_api_key`.
    Compose,
    /// `/etc/kharon.toml` and `/etc/kharon/kharon_bw_api_key.json`.
    Host,
}

/// How kharond reaches the agent's Chromium. The path-B agent connector
/// needs a TLS pin and a tunnel credential; it arrives with the
/// agent-host bundle (#405).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CdpVia {
    /// Over the WireGuard link (`compose.vpn.yml`).
    Wireguard,
    /// Chromium on this host's loopback.
    Direct,
}

impl CdpVia {
    fn name(self) -> &'static str {
        match self {
            Self::Wireguard => "wireguard",
            Self::Direct => "direct",
        }
    }
    fn default_endpoint(self) -> &'static str {
        match self {
            Self::Wireguard => "ws://10.66.0.2:9222",
            Self::Direct => "ws://127.0.0.1:9222",
        }
    }
}

/// Every answer setup can take. Each field is a flag (`--server`) and a
/// key in the `--answers` TOML file (`server = "…"`); a flag wins over
/// the file. No field holds a secret: the API key comes from the JSON
/// file named by `api-key-json`, or from a no-echo prompt.
#[derive(Args, Deserialize, Default, Debug, Clone)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Answers {
    /// TOML file of answers, same keys as these flags (kebab-case).
    #[arg(long, value_name = "FILE")]
    #[serde(skip)]
    pub answers: Option<PathBuf>,
    /// Never prompt: take every answer from flags or the answers file,
    /// and fail naming the flag that is missing.
    #[arg(long)]
    #[serde(skip)]
    pub non_interactive: bool,
    /// The account already exists, so skip the `kharon init` offer.
    #[arg(long)]
    pub account_exists: bool,
    /// File layout [default: compose].
    #[arg(long, value_enum)]
    pub layout: Option<Layout>,
    /// Where to write kharon.toml (default by layout).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Where to write the API key file on this host (default by layout).
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,
    /// The key file's path as kharond sees it, for `api_key_file`
    /// (Compose: /run/secrets/kharon_bw_api_key).
    #[arg(long, value_name = "PATH")]
    pub key_file_in_config: Option<PathBuf>,
    /// Owner of the key file, `uid[:gid]` [default: 10001:10001].
    #[arg(long, value_name = "UID[:GID]")]
    pub key_owner: Option<String>,
    /// Bitwarden or Vaultwarden server [default: https://vault.bitwarden.com].
    #[arg(long, value_name = "URL")]
    pub server: Option<String>,
    /// The dedicated kharon account's email.
    #[arg(long)]
    pub email: Option<String>,
    /// JSON file with the personal API key, `{"client_id", "client_secret"}`.
    #[arg(long, value_name = "FILE")]
    pub api_key_json: Option<PathBuf>,
    /// Extra CA certificate (PEM) for a self-hosted server with a private CA.
    #[arg(long, value_name = "FILE")]
    pub ca_file: Option<PathBuf>,
    /// Organization id, if not picked from the list.
    #[arg(long)]
    pub organization_id: Option<String>,
    /// Collection id (repeatable), if not picked from the list.
    #[arg(long = "collection-id", value_name = "ID")]
    pub collection_ids: Vec<String>,
    /// Skip the login and discovery (needs --organization-id and
    /// --collection-id). For a server this host cannot reach, such as
    /// the Compose-internal `http://vaultwarden:80`.
    #[arg(long)]
    pub no_discover: bool,
    /// The first agent's id [default: assistant].
    #[arg(long)]
    pub agent_id: Option<String>,
    /// How kharond reaches the agent's Chromium [default: wireguard].
    #[arg(long, value_enum)]
    pub cdp_via: Option<CdpVia>,
    /// The agent's CDP endpoint (default by --cdp-via).
    #[arg(long, value_name = "URL")]
    pub cdp_endpoint: Option<String>,
    /// Public hostname agents reach through the tunnel (`[public_ingress]`).
    #[arg(long, value_name = "HOST")]
    pub public_host: Option<String>,
    /// Agent API address on a VPN (`[api] listen`), instead of --public-host.
    #[arg(long, value_name = "IP:PORT")]
    pub api_listen: Option<String>,
    /// Owner UI public origin, e.g. https://kharon-owner.example.com (optional).
    #[arg(long, value_name = "URL")]
    pub owner_origin: Option<String>,
    /// ntfy server for approvals and audit checkpoints [default: https://ntfy.sh].
    #[arg(long, value_name = "URL")]
    pub ntfy_url: Option<String>,
    /// ntfy topic [default: a fresh random `kharon-…` name].
    #[arg(long)]
    pub ntfy_topic: Option<String>,
    /// ntfy write-token file, as kharond sees it (optional).
    #[arg(long, value_name = "PATH")]
    pub ntfy_token_file: Option<PathBuf>,
    /// Write the agent token to this new 0600 file instead of the terminal.
    #[arg(long, value_name = "PATH")]
    pub agent_token_file: Option<PathBuf>,
}

impl Answers {
    /// `self` (the flags) over `file`.
    pub fn over(self, file: Answers) -> Answers {
        Answers {
            answers: self.answers,
            non_interactive: self.non_interactive,
            account_exists: self.account_exists || file.account_exists,
            layout: self.layout.or(file.layout),
            config: self.config.or(file.config),
            key_file: self.key_file.or(file.key_file),
            key_file_in_config: self.key_file_in_config.or(file.key_file_in_config),
            key_owner: self.key_owner.or(file.key_owner),
            server: self.server.or(file.server),
            email: self.email.or(file.email),
            api_key_json: self.api_key_json.or(file.api_key_json),
            ca_file: self.ca_file.or(file.ca_file),
            organization_id: self.organization_id.or(file.organization_id),
            collection_ids: if self.collection_ids.is_empty() {
                file.collection_ids
            } else {
                self.collection_ids
            },
            no_discover: self.no_discover || file.no_discover,
            agent_id: self.agent_id.or(file.agent_id),
            cdp_via: self.cdp_via.or(file.cdp_via),
            cdp_endpoint: self.cdp_endpoint.or(file.cdp_endpoint),
            public_host: self.public_host.or(file.public_host),
            api_listen: self.api_listen.or(file.api_listen),
            owner_origin: self.owner_origin.or(file.owner_origin),
            ntfy_url: self.ntfy_url.or(file.ntfy_url),
            ntfy_topic: self.ntfy_topic.or(file.ntfy_topic),
            ntfy_token_file: self.ntfy_token_file.or(file.ntfy_token_file),
            agent_token_file: self.agent_token_file.or(file.agent_token_file),
        }
    }

    /// Parse an answers file. Unknown keys are refused, so a typo is
    /// not silently a default.
    pub fn from_toml(text: &str) -> Result<Answers, String> {
        toml::from_str(text).map_err(|e| format!("answers file: {}", e.message()))
    }
}

/// The operator's side of the conversation. [`TtyPrompter`] in the
/// binary; [`NonInteractive`] for `--non-interactive`; a script in tests.
pub trait Prompter {
    /// Tell the operator something (not secret).
    fn say(&mut self, text: &str) -> Result<(), String>;
    /// Ask a question. Empty input takes `default`, or is `""` without one.
    /// `flag` names the flag that answers it, for the non-interactive error.
    fn ask(&mut self, question: &str, default: Option<&str>, flag: &str) -> Result<String, String>;
    /// Ask for a secret, with echo off.
    fn ask_secret(&mut self, question: &str, flag: &str) -> Result<Zeroizing<String>, String>;
    /// Show a secret once, on the terminal only.
    fn show_secret(&mut self, text: &str) -> Result<(), String>;
    /// Whether a person is answering.
    fn interactive(&self) -> bool;
    /// Whether [`Prompter::show_secret`] can work right now.
    fn can_show_secret(&self) -> bool;
}

/// `--non-interactive`: defaults are taken silently, a question with no
/// default is an error naming its flag, and secrets can be shown only if
/// there is a controlling terminal.
pub struct NonInteractive;

impl Prompter for NonInteractive {
    fn say(&mut self, text: &str) -> Result<(), String> {
        eprintln!("{text}");
        Ok(())
    }
    fn ask(&mut self, question: &str, default: Option<&str>, flag: &str) -> Result<String, String> {
        match default {
            Some(d) => Ok(d.to_owned()),
            None => Err(format!(
                "{question}: pass {flag} (running with --non-interactive)"
            )),
        }
    }
    fn ask_secret(&mut self, question: &str, flag: &str) -> Result<Zeroizing<String>, String> {
        Err(format!(
            "{question}: pass {flag} (running with --non-interactive)"
        ))
    }
    fn show_secret(&mut self, text: &str) -> Result<(), String> {
        let mut tty = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .map_err(|e| format!("cannot open /dev/tty: {e}"))?;
        tty.write_all(text.as_bytes())
            .and_then(|()| tty.flush())
            .map_err(|e| format!("cannot write to the terminal: {e}"))
    }
    fn interactive(&self) -> bool {
        false
    }
    fn can_show_secret(&self) -> bool {
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .is_ok()
    }
}

/// Prompts on `/dev/tty`, so stdout and stderr can be redirected without
/// a question or a secret ending up in them. Lines are read with one
/// `read` each (canonical mode returns at most one line), into zeroizing
/// buffers.
pub struct TtyPrompter {
    tty: std::fs::File,
}

impl TtyPrompter {
    pub fn open() -> Result<Self, String> {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|e| {
                format!(
                    "setup asks its questions on a terminal, and /dev/tty is unavailable ({e}); \
                     run it in an interactive shell, or pass --non-interactive with the answers"
                )
            })?;
        Ok(Self { tty })
    }

    fn write(&mut self, text: &str) -> Result<(), String> {
        self.tty
            .write_all(text.as_bytes())
            .and_then(|()| self.tty.flush())
            .map_err(|e| format!("cannot write to the terminal: {e}"))
    }

    fn line(&mut self) -> Result<Zeroizing<String>, String> {
        use std::os::fd::AsFd;
        super::read_password_line(&mut super::FdReader(self.tty.as_fd()), "the terminal")
    }
}

impl Prompter for TtyPrompter {
    fn say(&mut self, text: &str) -> Result<(), String> {
        self.write(text)?;
        self.write("\n")
    }
    fn ask(
        &mut self,
        question: &str,
        default: Option<&str>,
        _flag: &str,
    ) -> Result<String, String> {
        match default {
            Some(d) if !d.is_empty() => self.write(&format!("{question} [{d}]: "))?,
            _ => self.write(&format!("{question}: "))?,
        }
        let answer = self.line()?;
        let answer = answer.trim();
        Ok(if answer.is_empty() {
            default.unwrap_or("").to_owned()
        } else {
            answer.to_owned()
        })
    }
    fn ask_secret(&mut self, question: &str, _flag: &str) -> Result<Zeroizing<String>, String> {
        use std::os::fd::AsFd;
        let original = rustix::termios::tcgetattr(self.tty.as_fd())
            .map_err(|e| format!("cannot read terminal settings: {e}"))?;
        // SIGINT watcher first, echo off second (#92).
        super::watch_for_sigint(original.clone());
        let secret = {
            let _guard = super::EchoOff::new(self.tty.as_fd(), original)?;
            self.write(&format!("{question} (not shown): "))?;
            self.line()
        };
        self.write("\n")?;
        secret
    }
    fn show_secret(&mut self, text: &str) -> Result<(), String> {
        self.write(text)
    }
    fn interactive(&self) -> bool {
        true
    }
    fn can_show_secret(&self) -> bool {
        true
    }
}

/// The server side: one login and one sync with the personal API key.
/// The binary uses [`LiveVault`]; tests use a canned response.
pub trait VaultProbe {
    fn sync(
        &mut self,
        server: &Url,
        email: &str,
        key: ApiKey,
        trust: &TlsTrust,
    ) -> Result<SyncResponse, SyncError>;
}

/// [`kharond::sync::SyncClient`] on a current-thread runtime.
pub struct LiveVault;

impl VaultProbe for LiveVault {
    fn sync(
        &mut self,
        server: &Url,
        email: &str,
        key: ApiKey,
        trust: &TlsTrust,
    ) -> Result<SyncResponse, SyncError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| SyncError::Transport("runtime"))?;
        rt.block_on(async {
            let mut client = kharond::sync::SyncClient::new(server, email, key, trust)?;
            client.sync().await
        })
    }
}

/// `uid:gid` for a file setup writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

/// kharond's uid and gid in the image and in the host unit.
pub const KHAROND_OWNER: Owner = Owner {
    uid: 10001,
    gid: 10001,
};

fn parse_owner(text: &str) -> Result<Owner, String> {
    let bad = || format!("--key-owner must be uid or uid:gid (numbers), not {text:?}");
    let (u, g) = match text.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (text, None),
    };
    let uid: u32 = u.trim().parse().map_err(|_| bad())?;
    let gid: u32 = match g {
        Some(g) => g.trim().parse().map_err(|_| bad())?,
        None => uid,
    };
    Ok(Owner { uid, gid })
}

/// How agents reach kharond.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Listener {
    /// `[public_ingress]` on loopback, behind the tunnel, for `public_host`.
    Public { host: String },
    /// `[api] listen` on a VPN address.
    Api { listen: String },
}

/// Everything setup decided, before anything is written. The agent-host
/// bundle (#405) is built from this plus the minted token.
#[derive(Clone, Debug)]
pub struct Plan {
    pub config_path: PathBuf,
    pub key_path: PathBuf,
    pub key_in_config: PathBuf,
    pub key_owner: Owner,
    pub server: Url,
    pub email: String,
    pub ca_file: Option<PathBuf>,
    pub organization_id: String,
    pub collection_ids: Vec<String>,
    pub agent_id: String,
    pub cdp_via: CdpVia,
    pub cdp_endpoint: String,
    pub listener: Listener,
    pub owner_origin: Option<String>,
    pub ntfy_url: String,
    pub ntfy_topic: String,
    pub ntfy_token_file: Option<PathBuf>,
    pub agent_token_file: Option<PathBuf>,
}

/// The loopback port `[public_ingress]` listens on in the Compose
/// example; the tunnel route points here.
const PUBLIC_INGRESS_LISTEN: &str = "127.0.0.1:8790";
/// The owner UI's loopback listener in the Compose example.
const OWNER_UI_LISTEN: &str = "127.0.0.1:8788";
const DEFAULT_SERVER: &str = "https://vault.bitwarden.com";
const DEFAULT_NTFY: &str = "https://ntfy.sh";
const DEFAULT_AGENT: &str = "assistant";

/// A TOML basic string.
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn path_str(p: &Path) -> String {
    toml_str(&p.to_string_lossy())
}

/// Render `kharon.toml` for `plan`, with `token_hash` for the first agent.
pub fn render(plan: &Plan, token_hash: &str) -> String {
    let mut t = String::new();
    t.push_str(
        "# Written by `kharon setup` (#404). kharond refuses unknown keys and\n\
         # unsafe combinations; check this file with `kharond --check --config <path>`.\n\n",
    );
    t.push_str("[bitwarden]\n");
    t.push_str(&format!("server = {}\n", toml_str(plan.server.as_str())));
    t.push_str(&format!("email = {}\n", toml_str(&plan.email)));
    t.push_str(&format!(
        "api_key_file = {}\n",
        path_str(&plan.key_in_config)
    ));
    t.push_str(&format!(
        "organization_id = {}\n",
        toml_str(&plan.organization_id)
    ));
    let colls: Vec<String> = plan.collection_ids.iter().map(|c| toml_str(c)).collect();
    t.push_str(&format!("collection_ids = [{}]\n", colls.join(", ")));
    if let Some(ca) = &plan.ca_file {
        t.push_str(&format!("ca_file = {}\n", path_str(ca)));
    }
    t.push_str(&format!(
        "\n# The first agent. Its token was shown once by setup; only the hash is here.\n\
         [agents.{}]\ntoken_hash = {}\ncdp = {{ endpoint = {}, via = {} }}\n",
        plan.agent_id,
        toml_str(token_hash),
        toml_str(&plan.cdp_endpoint),
        toml_str(plan.cdp_via.name())
    ));
    t.push_str(
        "\n# Approval prompts (REQ-APR-004) and the off-host audit checkpoints\n\
         # (REQ-AUD-002) both go to this topic.\n[approval]\n",
    );
    let mut ntfy = format!(
        "ntfy = {{ url = {}, topic = {}",
        toml_str(&plan.ntfy_url),
        toml_str(&plan.ntfy_topic)
    );
    if let Some(f) = &plan.ntfy_token_file {
        ntfy.push_str(&format!(", token_file = {}", path_str(f)));
    }
    ntfy.push_str(" }\n");
    t.push_str(&ntfy);
    match &plan.listener {
        Listener::Public { host } => t.push_str(&format!(
            "\n# Agents reach POST /mcp here, through the tunnel.\n\
             [public_ingress]\nlisten = {}\npublic_host = {}\n",
            toml_str(PUBLIC_INGRESS_LISTEN),
            toml_str(host)
        )),
        Listener::Api { listen } => t.push_str(&format!(
            "\n# The agent API, on the VPN address.\n[api]\nlisten = {}\n",
            toml_str(listen)
        )),
    }
    if let Some(origin) = &plan.owner_origin {
        t.push_str(&format!(
            "\n# The owner web UI, published at its own hostname.\n\
             [owner_ui]\nlisten = {}\npublic_origin = {}\n",
            toml_str(OWNER_UI_LISTEN),
            toml_str(origin)
        ));
    }
    t
}

/// Check rendered text with the daemon's own loader and `--check` rules,
/// so setup never writes a file kharond would refuse. Host checks that
/// need the files (key-file mode, mlock) come after the write.
pub fn validate(text: &str) -> Result<kharond::config::Config, String> {
    let cfg = kharond::config::Config::from_toml_str(text).map_err(|e| {
        format!(
            "the answers make a config kharond would refuse [{}]: {e}",
            e.code()
        )
    })?;
    kharond::daemon::check(&cfg)
        .map_err(|e| format!("the answers make a config kharond would refuse: {e}"))?;
    Ok(cfg)
}

/// Strip control characters from server-provided text before it reaches
/// the terminal.
fn printable(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// A fresh, unguessable ntfy topic: anyone who knows a public topic's
/// name can read it, so the default name is the secret-free capability.
fn random_topic() -> Result<String, String> {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let mut bytes = [0u8; 20];
    let mut filled = 0;
    while filled < bytes.len() {
        match rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(format!("OS RNG: {e}")),
        }
    }
    let mut out = String::from("kharon-");
    for b in bytes {
        out.push(char::from(ALPHABET[usize::from(b & 31)]));
    }
    Ok(out)
}

/// The text shown with a fresh master password (as `kharon init`).
fn init_text(password: &str) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(1024));
    text.push_str("\nMaster password for the kharon Bitwarden account (160 bits):\n\n    ");
    text.push_str(password);
    text.push_str(
        "\n\nUse it when you create the kharon account, then store it in your own\n\
         vault, outside the kharon organization. kharon does not keep it and\n\
         this is the only time it is shown (SPEC REQ-DEP-007).\n\n",
    );
    text
}

const ACCOUNT_STEPS: &str = "Now, in the web vault:\n\
  1. Create the dedicated kharon account with that password.\n\
  2. As yourself, create the kharon organization and its collection, invite the\n\
     account with Can view on that collection, then confirm it once it accepts.\n\
  3. Signed in as the kharon account: Settings > Security > Keys > View API key.\n\
     Keep that dialog open; setup asks for its client_id and client_secret next.";

/// Ask for the personal API key. The type is checked on entry (#403):
/// the `client_id` is checked before the secret is even asked for, and a
/// key file is checked before its secret is used.
fn ask_api_key(
    answers: &Answers,
    p: &mut dyn Prompter,
) -> Result<(String, Zeroizing<String>), String> {
    if let Some(path) = &answers.api_key_json {
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read --api-key-json {}: {e}", path.display()))?,
        );
        let bad =
            || "--api-key-json must be a JSON object {\"client_id\", \"client_secret\"}".to_owned();
        // Deserialize the secret into Zeroizing so it is wiped, matching
        // key_file_bytes. A serde_json::Value would leave a copy on the heap.
        #[derive(Deserialize)]
        struct ApiKeyJson {
            client_id: String,
            client_secret: Zeroizing<String>,
        }
        let parsed: ApiKeyJson = serde_json::from_str(&text).map_err(|_| bad())?;
        check_client_id(&parsed.client_id).map_err(|e| e.message().to_owned())?;
        let secret = Zeroizing::new(parsed.client_secret.trim().to_owned());
        if secret.is_empty() {
            return Err("--api-key-json: client_secret is empty".to_owned());
        }
        return Ok((parsed.client_id.trim().to_owned(), secret));
    }
    let mut tries = 0;
    let id = loop {
        let id = p.ask("API key client_id (user.<uuid>)", None, "--api-key-json")?;
        match check_client_id(&id) {
            Ok(()) => break id.trim().to_owned(),
            Err(e) if p.interactive() && tries < 2 => {
                tries += 1;
                p.say(e.message())?;
            }
            Err(e) => return Err(e.message().to_owned()),
        }
    };
    let secret = p.ask_secret("API key client_secret", "--api-key-json")?;
    let secret = Zeroizing::new(secret.trim().to_owned());
    if secret.is_empty() {
        return Err("client_secret is empty".to_owned());
    }
    Ok((id, secret))
}

/// The key file's bytes, `{"client_id": …, "client_secret": …}`, in a
/// buffer sized so it never reallocates (no unwiped copies).
fn key_file_bytes(client_id: &str, secret: &str) -> Zeroizing<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct KeyFile<'a> {
        client_id: &'a str,
        client_secret: &'a str,
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(
        (client_id.len() + secret.len()) * 6 + 64,
    ));
    serde_json::to_writer(
        &mut *buf,
        &KeyFile {
            client_id,
            client_secret: secret,
        },
    )
    .expect("invariant: serializing two strings into a Vec cannot fail");
    buf.push(b'\n');
    buf
}

fn server_url(text: &str, discovering: bool) -> Result<Url, String> {
    let url = Url::parse(text.trim())
        .map_err(|_| format!("server must be an http(s) URL, not {:?}", printable(text)))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("server must be an http(s) URL with a host".to_owned());
    }
    if discovering && url.scheme() == "http" {
        let loopback = match url.host() {
            Some(url::Host::Ipv4(a)) => a.is_loopback(),
            Some(url::Host::Ipv6(a)) => a.is_loopback(),
            Some(url::Host::Domain(d)) => d == "localhost",
            None => false,
        };
        if !loopback {
            return Err(
                "setup sends the API key to the server, so it needs https (or http on \
                 loopback). For the Compose-internal http://vaultwarden:80, pass --no-discover \
                 with --organization-id and --collection-id"
                    .to_owned(),
            );
        }
    }
    Ok(url)
}

fn explain_sync_error(e: &SyncError, server: &Url) -> String {
    match e {
        SyncError::Status {
            endpoint: "token",
            status: 400 | 401,
        } => "the server refused the API key: check the client_id and client_secret (rotating \
              the key replaces the secret) and that the key belongs to the dedicated account"
            .to_owned(),
        SyncError::Transport(_) => format!(
            "could not reach {} ({e}); check the URL, or pass --ca-file for a private CA",
            server.as_str()
        ),
        _ => format!("login and sync failed: {e}"),
    }
}

fn org_label(o: &kharond::sync::DiscoveredOrg) -> String {
    match &o.name {
        Some(n) => format!("{} ({}, {} items)", printable(n), o.id, o.items),
        None => format!("{} ({} items)", o.id, o.items),
    }
}

/// Pick the organization: the given one if the account can see it, the
/// only one, or from a numbered list.
fn pick_org(answers: &Answers, d: &Discovery, p: &mut dyn Prompter) -> Result<String, String> {
    if let Some(want) = &answers.organization_id {
        let want = want.trim().to_ascii_lowercase();
        return d
            .orgs
            .iter()
            .find(|o| o.id == want)
            .map(|o| o.id.clone())
            .ok_or_else(|| {
                "the account cannot see that organization: invite the account to it, accept \
                 the invite as the account, and confirm it"
                    .to_owned()
            });
    }
    match d.orgs.len() {
        0 => Err(
            "the account is not a confirmed member of any organization. As yourself: invite \
             the account to the kharon organization, accept the invite as the account, then \
             confirm it (Admin Console > Members)"
                .to_owned(),
        ),
        1 => {
            p.say(&format!("Organization: {}", org_label(&d.orgs[0])))?;
            Ok(d.orgs[0].id.clone())
        }
        _ => {
            let mut list = String::from("The account can see these organizations:");
            for (i, o) in d.orgs.iter().enumerate() {
                list.push_str(&format!("\n  {}. {}", i + 1, org_label(o)));
            }
            p.say(&list)?;
            let n = p.ask("Organization number", None, "--organization-id")?;
            let i: usize = n
                .trim()
                .parse()
                .ok()
                .filter(|i| (1..=d.orgs.len()).contains(i))
                .ok_or_else(|| format!("pick a number from 1 to {}", d.orgs.len()))?;
            Ok(d.orgs[i - 1].id.clone())
        }
    }
}

/// Pick collections in `org`: the given ones, the only one, or from a
/// numbered list (`1,3` or `all`).
fn pick_collections(
    answers: &Answers,
    d: &Discovery,
    org: &str,
    p: &mut dyn Prompter,
) -> Result<Vec<String>, String> {
    let o = d
        .orgs
        .iter()
        .find(|o| o.id == org)
        .expect("invariant: org was picked from the discovery");
    if o.collections.is_empty() {
        return Err(
            "no collection in that organization is assigned to the account: give the account \
             Can view on the kharon collection (Admin Console > Collections > Access)"
                .to_owned(),
        );
    }
    if !answers.collection_ids.is_empty() {
        let mut out = Vec::new();
        for want in &answers.collection_ids {
            let want = want.trim().to_ascii_lowercase();
            if !o.collections.iter().any(|c| c.id == want) {
                return Err(
                    "the account cannot see one of the given collections: assign it to the \
                     account with Can view"
                        .to_owned(),
                );
            }
            if !out.contains(&want) {
                out.push(want);
            }
        }
        return Ok(out);
    }
    if o.collections.len() == 1 {
        let c = &o.collections[0];
        p.say(&format!("Collection: {} ({} items)", c.id, c.items))?;
        return Ok(vec![c.id.clone()]);
    }
    let mut list = String::from(
        "Collections assigned to the account (names are encrypted, so ids and item counts):",
    );
    for (i, c) in o.collections.iter().enumerate() {
        list.push_str(&format!("\n  {}. {} ({} items)", i + 1, c.id, c.items));
    }
    p.say(&list)?;
    let pick = p.ask(
        "Collections to use (numbers like 1,3, or all)",
        Some("all"),
        "--collection-id",
    )?;
    if pick.trim().eq_ignore_ascii_case("all") {
        return Ok(o.collections.iter().map(|c| c.id.clone()).collect());
    }
    let mut out = Vec::new();
    for part in pick.split(',') {
        let i: usize = part
            .trim()
            .parse()
            .ok()
            .filter(|i| (1..=o.collections.len()).contains(i))
            .ok_or_else(|| format!("pick numbers from 1 to {}, or all", o.collections.len()))?;
        let id = o.collections[i - 1].id.clone();
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Whether this process may create a file owned by `owner`.
fn can_own(owner: Owner) -> bool {
    let euid = rustix::process::geteuid().as_raw();
    let egid = rustix::process::getegid().as_raw();
    euid == 0 || (owner.uid == euid && owner.gid == egid)
}

/// Everything that can make a write fail, checked before the first one.
fn preflight_paths(plan: &Plan, p: &dyn Prompter) -> Result<(), String> {
    let mut targets = vec![("config", &plan.config_path), ("key file", &plan.key_path)];
    if let Some(t) = &plan.agent_token_file {
        targets.push(("agent token file", t));
    }
    for (what, path) in targets {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(format!(
                "the {what} {} already exists; setup does not overwrite files. Move it \
                 away or choose another path",
                path.display()
            ));
        }
        let parent = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        if !parent.is_dir() {
            return Err(format!(
                "the {what}'s directory {} does not exist; create it first",
                parent.display()
            ));
        }
    }
    if plan.config_path == plan.key_path {
        return Err("the config and the key file must be different paths".to_owned());
    }
    if !can_own(plan.key_owner) {
        return Err(format!(
            "the key file must belong to uid {} gid {} (kharond's), which needs root: run \
             setup with sudo, or pass --key-owner with your own uid:gid if kharond runs as you",
            plan.key_owner.uid, plan.key_owner.gid
        ));
    }
    if plan.agent_token_file.is_none() && !p.can_show_secret() {
        return Err(
            "there is no terminal to show the agent token on; pass --agent-token-file".to_owned(),
        );
    }
    Ok(())
}

/// Create `path` (it must not exist) with `mode`, write `bytes`, set the
/// owner, and sync. If anything after a successful `create_new` fails,
/// the path is removed here so a partial file (and any secret already
/// written to it) does not stay on disk. The caller only records the
/// path in [`Written`] after this returns `Ok`, so there is no
/// double-remove, and a failed open cannot delete a pre-existing file.
fn create_file(path: &Path, bytes: &[u8], mode: u32, owner: Option<Owner>) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    let result = write_created_file(&mut f, path, bytes, mode, owner);
    if result.is_err() {
        drop(f);
        let _ = std::fs::remove_file(path);
    }
    result
}

fn write_created_file(
    f: &mut std::fs::File,
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<Owner>,
) -> Result<(), String> {
    // The umask may have narrowed the mode; set it exactly.
    f.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot set the mode of {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    // Tests inject a failure here, after the bytes are on disk and
    // before fchown/sync, the window where a leftover file would hold
    // the secret.
    #[cfg(test)]
    after_write_hook(path)?;
    if let Some(o) = owner {
        rustix::fs::fchown(
            &f,
            Some(rustix::fs::Uid::from_raw(o.uid)),
            Some(rustix::fs::Gid::from_raw(o.gid)),
        )
        .map_err(|e| format!("cannot set the owner of {}: {e}", path.display()))?;
    }
    f.sync_all()
        .map_err(|e| format!("cannot sync {}: {e}", path.display()))
}

// When set, create_file runs this after write_all and before fchown,
// so a test can force a post-open failure once the secret is already
// on disk.
#[cfg(test)]
type AfterWrite = fn(&Path) -> Result<(), String>;

#[cfg(test)]
thread_local! {
    static AFTER_WRITE: std::cell::Cell<Option<AfterWrite>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn after_write_hook(path: &Path) -> Result<(), String> {
    AFTER_WRITE.with(|h| h.get().map_or(Ok(()), |f| f(path)))
}

/// Files written so far; removed on drop unless [`Written::keep`]ed.
struct Written(Vec<PathBuf>);

impl Written {
    fn keep(mut self) {
        self.0.clear();
    }
}

impl Drop for Written {
    fn drop(&mut self) {
        for p in self.0.drain(..) {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// What a finished setup leaves for the next step. #405's agent-host
/// bundle hooks in here: it is built from the plan and the token before
/// the token is dropped.
pub struct Outcome {
    /// Read by the bundle step (#405) and the tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub plan: Plan,
}

/// Decide everything: ask, check the key type, discover, pick. Nothing
/// is written.
pub fn plan(
    answers: &Answers,
    p: &mut dyn Prompter,
    vault: &mut dyn VaultProbe,
) -> Result<(Plan, String, Zeroizing<String>), String> {
    // 1. `kharon init`, if the account does not exist yet.
    if p.interactive() && !answers.account_exists {
        let have = p.ask(
            "Have you already created the dedicated kharon account and its personal API key? (y/n)",
            Some("y"),
            "--account-exists",
        )?;
        if have.trim().to_ascii_lowercase().starts_with('n') {
            let password = super::generate_master_password()?;
            p.show_secret(&init_text(&password))?;
            drop(password);
            p.say(ACCOUNT_STEPS)?;
            p.ask(
                "Press Enter when the API key dialog is open",
                Some(""),
                "--account-exists",
            )?;
        }
    }

    // 2. Server, email, key (type checked on entry, #403).
    let layout = answers.layout.unwrap_or(Layout::Compose);
    let discovering = !answers.no_discover;
    let server_text = match &answers.server {
        Some(s) => s.clone(),
        None => p.ask(
            "Bitwarden or Vaultwarden server URL",
            Some(DEFAULT_SERVER),
            "--server",
        )?,
    };
    let server = server_url(&server_text, discovering)?;
    let email = match &answers.email {
        Some(e) => e.trim().to_owned(),
        None => p.ask("The kharon account's email", None, "--email")?,
    };
    if email.is_empty() {
        return Err("the account email is empty".to_owned());
    }
    let (client_id, secret) = ask_api_key(answers, p)?;
    let ca_file = answers.ca_file.clone();

    // 3. Discovery and the scope check, from one sync.
    let (organization_id, collection_ids) = if discovering {
        let trust = match &ca_file {
            Some(path) => TlsTrust {
                extra_ca_pem: Some(
                    std::fs::read(path)
                        .map_err(|e| format!("cannot read --ca-file {}: {e}", path.display()))?,
                ),
            },
            None => TlsTrust::default(),
        };
        let key = ApiKey::new(&client_id, Zeroizing::new(secret.to_string()))
            .map_err(|e| e.to_string())?;
        p.say(&format!(
            "Logging in to {} and syncing once…",
            server.as_str()
        ))?;
        let sync = vault
            .sync(&server, &email, key, &trust)
            .map_err(|e| explain_sync_error(&e, &server))?;
        let d = discover(&sync);
        if !d.email.trim().eq_ignore_ascii_case(&email) {
            return Err(
                "the API key belongs to a different account than that email; use the \
                 dedicated account's email and its own personal API key"
                    .to_owned(),
            );
        }
        let org = pick_org(answers, &d, p)?;
        let v = scope_violation(&sync, &org);
        if !v.is_empty() {
            return Err(format!(
                "the kharon account can see {} other organization(s) and {} item(s) outside \
                 the kharon organization (personal-vault items count), so kharond would refuse \
                 it [scope_too_broad]. Move or delete those items in Bitwarden, or remove the \
                 account from the other organizations, then run setup again",
                v.other_orgs.len(),
                v.outside_items.len()
            ));
        }
        let colls = pick_collections(answers, &d, &org, p)?;
        (org, colls)
    } else {
        let org = answers
            .organization_id
            .clone()
            .ok_or("--no-discover needs --organization-id")?;
        if answers.collection_ids.is_empty() {
            return Err("--no-discover needs at least one --collection-id".to_owned());
        }
        (
            org.trim().to_ascii_lowercase(),
            answers
                .collection_ids
                .iter()
                .map(|c| c.trim().to_ascii_lowercase())
                .collect(),
        )
    };

    // 4. The agent, how agents reach kharond, approvals.
    let agent_id = match &answers.agent_id {
        Some(a) => a.clone(),
        None => p.ask("First agent's id", Some(DEFAULT_AGENT), "--agent-id")?,
    };
    if !kharond::api::token::valid_agent_id(&agent_id) {
        return Err("the agent id must match [a-z0-9-]{1,64}".to_owned());
    }
    let cdp_via = match answers.cdp_via {
        Some(v) => v,
        None => {
            let v = p.ask(
                "How does kharond reach the agent's browser? wireguard or direct (same host)",
                Some("wireguard"),
                "--cdp-via",
            )?;
            match v.trim() {
                "wireguard" => CdpVia::Wireguard,
                "direct" => CdpVia::Direct,
                _ => return Err("--cdp-via is wireguard or direct".to_owned()),
            }
        }
    };
    let cdp_endpoint = match &answers.cdp_endpoint {
        Some(e) => e.clone(),
        None => p.ask(
            "The agent's Chromium CDP endpoint",
            Some(cdp_via.default_endpoint()),
            "--cdp-endpoint",
        )?,
    };
    let listener = match (&answers.public_host, &answers.api_listen) {
        (Some(_), Some(_)) => {
            return Err("pass --public-host or --api-listen, not both".to_owned());
        }
        (Some(h), None) => Listener::Public {
            host: h.trim().to_owned(),
        },
        (None, Some(l)) => Listener::Api {
            listen: l.trim().to_owned(),
        },
        (None, None) => {
            let h = p.ask(
                "Public hostname agents reach through the tunnel (empty: an [api] address on a VPN)",
                if p.interactive() { Some("") } else { None },
                "--public-host or --api-listen",
            )?;
            if h.trim().is_empty() {
                let l = p.ask(
                    "Agent API listen address on the VPN",
                    Some("10.66.0.1:8787"),
                    "--api-listen",
                )?;
                Listener::Api { listen: l }
            } else {
                Listener::Public {
                    host: h.trim().to_owned(),
                }
            }
        }
    };
    let owner_origin = match &answers.owner_origin {
        Some(o) => Some(o.trim().to_owned()),
        None if p.interactive() => {
            let o = p.ask(
                "Owner UI public origin, e.g. https://kharon-owner.example.com (empty: none)",
                Some(""),
                "--owner-origin",
            )?;
            (!o.trim().is_empty()).then(|| o.trim().to_owned())
        }
        None => None,
    };
    let ntfy_url = match &answers.ntfy_url {
        Some(u) => u.clone(),
        None => p.ask(
            "ntfy server for approval prompts and audit checkpoints",
            Some(DEFAULT_NTFY),
            "--ntfy-url",
        )?,
    };
    let ntfy_topic = match &answers.ntfy_topic {
        Some(t) => t.clone(),
        None => {
            let fresh = random_topic()?;
            p.ask("ntfy topic", Some(&fresh), "--ntfy-topic")?
        }
    };
    let ntfy_token_file = match &answers.ntfy_token_file {
        Some(f) => Some(f.clone()),
        None if p.interactive() => {
            let f = p.ask(
                "ntfy write-token file as kharond sees it (empty: none)",
                Some(""),
                "--ntfy-token-file",
            )?;
            (!f.trim().is_empty()).then(|| PathBuf::from(f.trim()))
        }
        None => None,
    };
    if owner_origin.is_some() && ntfy_token_file.is_none() {
        p.say(
            "Note: with a published owner UI the ntfy topic must be private: its messages \
             carry Approve/Deny links. Reserve the topic and set a write token \
             (docs/deployment.md, \"Setting up the ntfy topic\").",
        )?;
    }

    // 5. Paths and owner.
    let (config_default, key_default, in_config_default) = match layout {
        Layout::Compose => (
            "kharon.toml",
            "secrets/kharon_bw_api_key.json",
            "/run/secrets/kharon_bw_api_key",
        ),
        Layout::Host => (
            "/etc/kharon.toml",
            "/etc/kharon/kharon_bw_api_key.json",
            "/etc/kharon/kharon_bw_api_key.json",
        ),
    };
    let key_path = answers
        .key_file
        .clone()
        .unwrap_or_else(|| PathBuf::from(key_default));
    let key_in_config = answers.key_file_in_config.clone().unwrap_or_else(|| {
        if layout == Layout::Host {
            key_path.clone()
        } else {
            PathBuf::from(in_config_default)
        }
    });
    let key_owner = match &answers.key_owner {
        Some(o) => parse_owner(o)?,
        None => KHAROND_OWNER,
    };
    let plan = Plan {
        config_path: answers
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from(config_default)),
        key_path,
        key_in_config,
        key_owner,
        server,
        email,
        ca_file,
        organization_id,
        collection_ids,
        agent_id,
        cdp_via,
        cdp_endpoint,
        listener,
        owner_origin,
        ntfy_url,
        ntfy_topic,
        ntfy_token_file,
        agent_token_file: answers.agent_token_file.clone(),
    };
    Ok((plan, client_id, secret))
}

/// The whole flow: [`plan`], mint, render, validate, write, show.
pub fn run(
    answers: &Answers,
    p: &mut dyn Prompter,
    vault: &mut dyn VaultProbe,
) -> Result<Outcome, String> {
    let (plan, client_id, secret) = plan(answers, p, vault)?;
    preflight_paths(&plan, p)?;

    // Mint first (in memory only) so the config is validated with the
    // real hash, then write, then show the token.
    let (token, hash) = kharond::api::token::generate(&plan.agent_id);
    let text = render(&plan, &hash);
    validate(&text)?;

    let mut written = Written(Vec::new());
    create_file(
        &plan.key_path,
        &key_file_bytes(&client_id, &secret),
        0o400,
        Some(plan.key_owner),
    )?;
    written.0.push(plan.key_path.clone());
    drop(secret);
    // The config holds no secret (kharond refuses secret-shaped keys);
    // 0640 with kharond's group, as docs/broker-lifecycle.md recommends.
    let config_owner = Owner {
        uid: rustix::process::geteuid().as_raw(),
        gid: plan.key_owner.gid,
    };
    create_file(
        &plan.config_path,
        text.as_bytes(),
        0o640,
        Some(config_owner).filter(|o| can_own(*o)),
    )?;
    written.0.push(plan.config_path.clone());

    // Host layout: the daemon reads these same paths, so run its
    // startup file checks (key-file mode and type, CA file) now.
    if plan.key_in_config == plan.key_path {
        let cfg = validate(&text)?;
        cfg.check_startup(&kharond::config::StaticMlockProbe(Ok(())))
            .map_err(|e| format!("kharond would refuse the written files [{}]: {e}", e.code()))?;
    }

    // #405 hook: the agent-host bundle is built here, from `plan` and
    // `token`, before the token is dropped.
    let secret_text = token.expose_secret();
    match &plan.agent_token_file {
        Some(path) => {
            let mut line = Zeroizing::new(String::with_capacity(secret_text.len() + 1));
            line.push_str(secret_text);
            line.push('\n');
            create_file(path, line.as_bytes(), 0o600, None)?;
            written.0.push(path.clone());
        }
        None => {
            let mut shown = Zeroizing::new(String::with_capacity(secret_text.len() + 400));
            shown.push_str("\nAgent token for `");
            shown.push_str(&plan.agent_id);
            shown.push_str("` (shown once; store it in the agent's own secret store):\n\n    ");
            shown.push_str(secret_text);
            shown.push_str(
                "\n\nIts hash is already in the config. kharon does not keep the token, and\n\
                 this mint is not an audit event (SPEC §7).\n\n",
            );
            p.show_secret(&shown)?;
        }
    }
    drop(token);
    written.keep();

    let mut done = format!(
        "Wrote {} and {} (uid {}, gid {}, mode 0400).",
        plan.config_path.display(),
        plan.key_path.display(),
        plan.key_owner.uid,
        plan.key_owner.gid
    );
    if let Some(t) = &plan.agent_token_file {
        done.push_str(&format!(
            "\nThe agent token for `{}` is in {} (root-owned 0600 when setup ran as root). \
             Copy or chown it for the agent host.",
            plan.agent_id,
            t.display()
        ));
    }
    done.push_str(
        "\nNext: start kharond (it checks the file again at startup), unlock with \
         `kharon unlock`, and enroll a passkey with `kharon passkey-enroll`.",
    );
    p.say(&done)?;
    Ok(Outcome { plan })
}

/// `kharon setup` from the binary.
pub fn command(flags: Answers) -> std::process::ExitCode {
    let answers = match &flags.answers {
        Some(path) => {
            let file = match std::fs::read_to_string(path) {
                Ok(t) => match Answers::from_toml(&t) {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("kharon setup: {e}");
                        return std::process::ExitCode::from(2);
                    }
                },
                Err(e) => {
                    eprintln!("kharon setup: cannot read {}: {e}", path.display());
                    return std::process::ExitCode::from(2);
                }
            };
            flags.over(file)
        }
        None => flags,
    };
    let result = if answers.non_interactive {
        run(&answers, &mut NonInteractive, &mut LiveVault)
    } else {
        match TtyPrompter::open() {
            Ok(mut p) => run(&answers, &mut p, &mut LiveVault),
            Err(e) => Err(e),
        }
    };
    match result {
        Ok(_) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kharon setup: {e}");
            std::process::ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    // Placeholder ids and a canary secret; nothing here is a real key.
    const USER: &str = "user.00000000-0000-4000-8000-000000000001";
    const ORG_KEY: &str = "organization.00000000-0000-4000-8000-000000000002";
    const SECRET: &str = "CANARYclientSECRET";
    const EMAIL: &str = "kharon@example.net";
    const ORG: &str = "0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
    const COLL1: &str = "11111111-2222-3333-4444-555555555555";
    const COLL2: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";

    /// Answers queued in order; records everything said and shown.
    struct Script {
        answers: VecDeque<String>,
        asked: Vec<String>,
        said: Vec<String>,
        shown: Vec<String>,
        tty: bool,
        /// Answer "" (take the default) once the queue is empty.
        lenient: bool,
    }

    impl Script {
        fn new(answers: &[&str]) -> Self {
            Self {
                answers: answers.iter().map(|a| (*a).to_owned()).collect(),
                asked: Vec::new(),
                said: Vec::new(),
                shown: Vec::new(),
                tty: true,
                lenient: false,
            }
        }
        fn next(&mut self, q: &str) -> String {
            self.asked.push(q.to_owned());
            match self.answers.pop_front() {
                Some(a) => a,
                None if self.lenient => String::new(),
                None => panic!("script ran out at {q:?}"),
            }
        }
        fn all_said(&self) -> String {
            self.said.join("\n")
        }
    }

    impl Prompter for Script {
        fn say(&mut self, text: &str) -> Result<(), String> {
            self.said.push(text.to_owned());
            Ok(())
        }
        fn ask(&mut self, q: &str, default: Option<&str>, _flag: &str) -> Result<String, String> {
            let a = self.next(q);
            Ok(if a.is_empty() {
                default.unwrap_or("").to_owned()
            } else {
                a
            })
        }
        fn ask_secret(&mut self, q: &str, _flag: &str) -> Result<Zeroizing<String>, String> {
            Ok(Zeroizing::new(self.next(q)))
        }
        fn show_secret(&mut self, text: &str) -> Result<(), String> {
            self.shown.push(text.to_owned());
            Ok(())
        }
        fn interactive(&self) -> bool {
            true
        }
        fn can_show_secret(&self) -> bool {
            self.tty
        }
    }

    /// `--non-interactive` without a terminal, recording what it says.
    struct Headless(Vec<String>);

    impl Prompter for Headless {
        fn say(&mut self, text: &str) -> Result<(), String> {
            self.0.push(text.to_owned());
            Ok(())
        }
        fn ask(&mut self, q: &str, d: Option<&str>, f: &str) -> Result<String, String> {
            NonInteractive.ask(q, d, f)
        }
        fn ask_secret(&mut self, q: &str, f: &str) -> Result<Zeroizing<String>, String> {
            NonInteractive.ask_secret(q, f)
        }
        fn show_secret(&mut self, _: &str) -> Result<(), String> {
            Err("no terminal".into())
        }
        fn interactive(&self) -> bool {
            false
        }
        fn can_show_secret(&self) -> bool {
            false
        }
    }

    /// A canned `/api/sync`, recording what it was asked with.
    struct Fake {
        sync: serde_json::Value,
        fail: Option<SyncError>,
        calls: Vec<(String, String, String)>,
    }

    impl Fake {
        fn new(sync: serde_json::Value) -> Self {
            Self {
                sync,
                fail: None,
                calls: Vec::new(),
            }
        }
    }

    impl VaultProbe for Fake {
        fn sync(
            &mut self,
            server: &Url,
            email: &str,
            key: ApiKey,
            _trust: &TlsTrust,
        ) -> Result<SyncResponse, SyncError> {
            self.calls.push((
                server.as_str().to_owned(),
                email.to_owned(),
                key.client_id().to_owned(),
            ));
            if let Some(e) = self.fail.take() {
                return Err(e);
            }
            Ok(serde_json::from_value(self.sync.clone()).unwrap())
        }
    }

    fn sync_with(colls: &[&str], extra: impl FnOnce(&mut serde_json::Value)) -> serde_json::Value {
        let mut v = serde_json::json!({
            "profile": {"id": "u1", "email": "Kharon@Example.net",
                        "organizations": [{"id": ORG.to_uppercase(), "name": "kharon\u{1b}[31m"}]},
            "collections": colls.iter().map(|c| serde_json::json!({"id": c, "organizationId": ORG})).collect::<Vec<_>>(),
            "ciphers": [{"id": "i1", "type": 1, "organizationId": ORG, "collectionIds": [COLL1]}]
        });
        extra(&mut v);
        v
    }

    fn me() -> String {
        format!(
            "{}:{}",
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw()
        )
    }

    /// Host layout in a temp dir, owned by the test's own uid.
    fn base(dir: &Path) -> Answers {
        Answers {
            layout: Some(Layout::Host),
            config: Some(dir.join("kharon.toml")),
            key_file: Some(dir.join("bw_api_key.json")),
            key_owner: Some(me()),
            ..Answers::default()
        }
    }

    fn key_json(dir: &Path, client_id: &str) -> PathBuf {
        let p = dir.join("in-key.json");
        std::fs::write(
            &p,
            format!(r#"{{"client_id":"{client_id}","client_secret":"{SECRET}","scope":"api"}}"#),
        )
        .unwrap();
        p
    }

    /// Non-interactive answers that need no prompt at all.
    fn headless(dir: &Path) -> Answers {
        Answers {
            non_interactive: true,
            email: Some(EMAIL.into()),
            api_key_json: Some(key_json(dir, USER)),
            public_host: Some("kharon.example.com".into()),
            agent_token_file: Some(dir.join("agent-token")),
            ..base(dir)
        }
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn assert_hash_matches(config: &str, agent: &str, token: &str) {
        let cfg = kharond::config::Config::from_toml_str(config).unwrap();
        let hash = cfg.agents[agent].token_hash.expose().clone();
        let store = kharond::api::token::TokenStore::new([(agent, hash.as_str())]).unwrap();
        assert_eq!(store.authenticate(token).unwrap(), agent);
    }

    #[test]
    fn req_404_prompt_path_writes_a_config_kharond_starts_on() {
        let dir = tempfile::tempdir().unwrap();
        let answers = base(dir.path());
        let mut p = Script::new(&[
            "",                                 // account exists [y]
            "",                                 // server [default]
            EMAIL,                              // email
            USER,                               // client_id
            SECRET,                             // client_secret
            "",                                 // agent id [assistant]
            "",                                 // cdp via [wireguard]
            "",                                 // endpoint [default]
            "kharon.example.com",               // public host
            "https://kharon-owner.example.com", // owner origin
            "",                                 // ntfy url [default]
            "",                                 // topic [random]
            "",                                 // token file [none]
        ]);
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        let out = run(&answers, &mut p, &mut vault).unwrap();
        assert!(p.answers.is_empty(), "unused answers: {:?}", p.answers);

        // Logged in at the default server, as the account, with the key.
        assert_eq!(
            vault.calls,
            vec![(
                "https://vault.bitwarden.com/".to_owned(),
                EMAIL.to_owned(),
                USER.to_owned()
            )]
        );
        // The only org and collection were picked without a question;
        // the server's control characters never reach the terminal.
        assert!(p.all_said().contains("Organization: kharon[31m (0f3c2a6e"));
        assert!(!p.all_said().contains('\u{1b}'));
        assert_eq!(out.plan.organization_id, ORG);
        assert_eq!(out.plan.collection_ids, vec![COLL1.to_owned()]);

        // The config is what kharond loads, with host checks, as written.
        let cfg_path = dir.path().join("kharon.toml");
        let text = std::fs::read_to_string(&cfg_path).unwrap();
        let (cfg, _warnings) = kharond::config::load_for_startup(
            &cfg_path,
            &kharond::config::StaticMlockProbe(Ok(())),
        )
        .unwrap();
        kharond::daemon::check(&cfg).unwrap();
        assert!(text.contains("[public_ingress]\nlisten = \"127.0.0.1:8790\""));
        assert!(text.contains("public_origin = \"https://kharon-owner.example.com\""));
        assert!(text.contains("topic = \"kharon-"));
        assert!(!text.contains("checkpoint_local_only"));
        assert!(!text.contains("allow_extra_orgs"));

        // The key file: 0400, the personal key, readable by the daemon.
        let key = dir.path().join("bw_api_key.json");
        assert_eq!(mode(&key), 0o400);
        assert_eq!(mode(&cfg_path), 0o640);
        let k = kharond::sync::ApiKey::from_file(&key).unwrap();
        assert_eq!(k.client_id(), USER);

        // The token was shown once, on the terminal, and matches the hash.
        assert_eq!(p.shown.len(), 1);
        let token = p.shown[0]
            .split_whitespace()
            .find(|w| w.starts_with("kh_agent_assistant_"))
            .unwrap()
            .to_owned();
        assert_hash_matches(&text, "assistant", &token);
        // Neither secret is in the config, or in anything said.
        for s in [SECRET, token.as_str()] {
            assert!(!text.contains(s));
            assert!(!p.all_said().contains(s));
        }
        // The ntfy note fired: published owner UI, no token file.
        assert!(p.all_said().contains("must be private"));
    }

    #[test]
    fn req_404_init_is_offered_first_when_the_account_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = Script::new(&["n", "", ""]);
        // Stop right after the key prompt: the script runs out of
        // answers there is no client_id. Run `plan` under catch_unwind.
        let answers = base(dir.path());
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = plan(&answers, &mut p, &mut vault);
        }));
        assert!(r.is_err());
        // The password was shown before the server was even asked for.
        assert_eq!(p.shown.len(), 1);
        assert!(p.shown[0].contains("Master password for the kharon Bitwarden account"));
        assert!(
            p.all_said()
                .contains("Settings > Security > Keys > View API key")
        );
        assert!(p.asked[1].starts_with("Press Enter"));
        assert!(p.asked[2].starts_with("Bitwarden or Vaultwarden server URL"));
    }

    #[test]
    fn req_404_org_key_refused_on_entry_with_403_message() {
        let dir = tempfile::tempdir().unwrap();
        // Interactive: the message is shown and the client_id asked again,
        // before any secret is asked for.
        let mut p = Script::new(&["y", "", EMAIL, ORG_KEY, ORG_KEY, ORG_KEY]);
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        let e = plan(&base(dir.path()), &mut p, &mut vault).unwrap_err();
        let msg = kharond::sync::KeyTypeError::Organization.message();
        assert_eq!(e, msg);
        assert_eq!(p.said.iter().filter(|s| *s == msg).count(), 2);
        assert!(p.asked.iter().all(|q| !q.contains("client_secret")));
        assert!(vault.calls.is_empty(), "no login with an org key");

        // Non-interactive: an org key in the JSON file, same message,
        // nothing written.
        let mut a = headless(dir.path());
        a.api_key_json = Some(key_json(dir.path(), ORG_KEY));
        let e = run(&a, &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert_eq!(e, msg);
        assert!(!e.contains(SECRET));
        assert!(!dir.path().join("kharon.toml").exists());
        assert!(!dir.path().join("bw_api_key.json").exists());
        assert!(vault.calls.is_empty());
    }

    #[test]
    fn req_404_non_interactive_path_from_flags_and_answers_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = Answers::from_toml(&format!(
            "email = \"{EMAIL}\"\napi-key-json = \"{}\"\nntfy-topic = \"kharon-approvals\"\n\
             cdp-via = \"direct\"\napi-listen = \"10.66.0.1:8787\"\n",
            key_json(dir.path(), USER).display()
        ))
        .unwrap();
        let flags = Answers {
            non_interactive: true,
            agent_id: Some("hermes".into()),
            agent_token_file: Some(dir.path().join("agent-token")),
            ..base(dir.path())
        };
        let answers = flags.over(file);
        let mut p = Headless(Vec::new());
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        run(&answers, &mut p, &mut vault).unwrap();
        let text = std::fs::read_to_string(dir.path().join("kharon.toml")).unwrap();
        assert!(text.contains("[agents.hermes]"));
        assert!(text.contains("cdp = { endpoint = \"ws://127.0.0.1:9222\", via = \"direct\" }"));
        assert!(text.contains("[api]\nlisten = \"10.66.0.1:8787\""));
        assert!(text.contains("topic = \"kharon-approvals\""));
        assert!(!text.contains("[owner_ui]"));
        let tf = dir.path().join("agent-token");
        assert_eq!(mode(&tf), 0o600);
        let token = std::fs::read_to_string(&tf).unwrap();
        assert_hash_matches(&text, "hermes", token.trim());
        let said = p.0.join("\n");
        assert!(!said.contains(token.trim()) && !said.contains(SECRET));
    }

    #[test]
    fn req_404_non_interactive_names_the_missing_flag() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        for (strip, flag) in [
            (0, "--email"),
            (1, "--api-key-json"),
            (2, "--public-host or --api-listen"),
            (3, "--agent-token-file"),
        ] {
            let mut a = headless(dir.path());
            match strip {
                0 => a.email = None,
                1 => a.api_key_json = None,
                2 => a.public_host = None,
                _ => a.agent_token_file = None,
            }
            let e = run(&a, &mut Headless(Vec::new()), &mut vault)
                .err()
                .unwrap();
            assert!(e.contains(flag), "{flag}: {e}");
            assert!(!dir.path().join("kharon.toml").exists());
        }
    }

    #[test]
    fn req_404_picker_for_several_collections() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Fake::new(sync_with(&[COLL1, COLL2], |_| {}));
        let mut a = headless(dir.path());
        a.non_interactive = false;
        a.account_exists = true;
        a.server = Some(DEFAULT_SERVER.into());
        let lenient = |answers: &[&str]| {
            let mut s = Script::new(answers);
            s.lenient = true;
            s
        };
        let mut p = lenient(&["2,1,2"]);
        let (plan, _, _) = plan(&a, &mut p, &mut vault).unwrap();
        assert_eq!(
            plan.collection_ids,
            vec![COLL2.to_owned(), COLL1.to_owned()]
        );
        assert!(
            p.all_said()
                .contains("1. 11111111-2222-3333-4444-555555555555 (1 items)")
        );

        let mut p = lenient(&[]);
        let (plan, _, _) = super::plan(&a, &mut p, &mut vault).unwrap();
        assert_eq!(plan.collection_ids.len(), 2, "default is all");

        let mut p = Script::new(&["7"]);
        assert!(super::plan(&a, &mut p, &mut vault).is_err());

        // Non-interactive with two collections and none named: "all".
        let (plan, _, _) =
            super::plan(&headless(dir.path()), &mut Headless(Vec::new()), &mut vault).unwrap();
        assert_eq!(plan.collection_ids.len(), 2);

        // A named collection the account cannot see is refused.
        let mut a = headless(dir.path());
        a.collection_ids = vec!["99999999-0000-4000-8000-000000000000".into()];
        assert!(
            super::plan(&a, &mut Headless(Vec::new()), &mut vault)
                .err()
                .unwrap()
                .contains("cannot see one of the given collections")
        );
    }

    #[test]
    fn req_404_refuses_what_kharond_would_refuse_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let cases: Vec<(serde_json::Value, &str)> = vec![
            // A personal item: REQ-CRY-008 scope_too_broad.
            (
                sync_with(&[COLL1], |v| {
                    v["ciphers"]
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::json!({"id": "p1", "type": 1, "organizationId": null}))
                }),
                "scope_too_broad",
            ),
            // A second org, also too broad.
            (
                sync_with(&[COLL1], |v| {
                    v["profile"]["organizations"]
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::json!({"id": "eeeeeeee-0000-4000-8000-000000000000"}))
                }),
                "pass --organization-id",
            ),
            (sync_with(&[], |_| {}), "Can view on the kharon collection"),
            (
                sync_with(&[COLL1], |v| {
                    v["profile"]["organizations"] = serde_json::json!([])
                }),
                "not a confirmed member",
            ),
            (
                sync_with(&[COLL1], |v| {
                    v["profile"]["email"] = "someone@example.net".into()
                }),
                "different account",
            ),
        ];
        for (sync, want) in cases {
            let mut vault = Fake::new(sync);
            let e = run(&headless(dir.path()), &mut Headless(Vec::new()), &mut vault)
                .err()
                .unwrap();
            assert!(e.contains(want), "{want}: {e}");
            assert!(!e.contains(SECRET));
            assert!(
                std::fs::read_dir(dir.path()).unwrap().count() == 1,
                "only in-key.json"
            );
        }
        // A rejected key and an unreachable server get their own fixes.
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        vault.fail = Some(SyncError::Status {
            endpoint: "token",
            status: 400,
        });
        let e = run(&headless(dir.path()), &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("refused the API key"), "{e}");
        vault.fail = Some(SyncError::Transport("token"));
        let e = run(&headless(dir.path()), &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("could not reach"), "{e}");
    }

    #[test]
    fn req_404_existing_refusals_stay() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        // The API key never goes to a plain-http server that is not loopback.
        let mut a = headless(dir.path());
        a.server = Some("http://vault.example.net".into());
        let e = run(&a, &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("needs https"), "{e}");
        assert!(vault.calls.is_empty());
        // Answers kharond refuses are refused by kharond's own checks:
        // a wildcard listen, a plain-ws CDP endpoint off loopback.
        let mut a = headless(dir.path());
        a.public_host = None;
        a.api_listen = Some("0.0.0.0:8787".into());
        let e = run(&a, &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("[api_wildcard_bind]"), "{e}");
        let mut a = headless(dir.path());
        a.cdp_via = Some(CdpVia::Direct);
        a.cdp_endpoint = Some("ws://192.0.2.7:9222".into());
        let e = run(&a, &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("[cdp_plain_ws_non_loopback]"), "{e}");
        let mut a = headless(dir.path());
        a.owner_origin = Some("http://kharon-owner.example.com".into());
        assert!(run(&a, &mut Headless(Vec::new()), &mut vault).is_err());
        assert!(!dir.path().join("kharon.toml").exists());
    }

    #[test]
    fn req_404_never_overwrites_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        std::fs::write(dir.path().join("kharon.toml"), "keep me").unwrap();
        let e = run(&headless(dir.path()), &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("already exists"), "{e}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("kharon.toml")).unwrap(),
            "keep me"
        );
        assert!(!dir.path().join("bw_api_key.json").exists());

        // A failure after the files are written removes them: here the
        // terminal goes away when the token is to be shown.
        struct BrokenTty(Headless);
        impl Prompter for BrokenTty {
            fn say(&mut self, t: &str) -> Result<(), String> {
                self.0.say(t)
            }
            fn ask(&mut self, q: &str, d: Option<&str>, f: &str) -> Result<String, String> {
                self.0.ask(q, d, f)
            }
            fn ask_secret(&mut self, q: &str, f: &str) -> Result<Zeroizing<String>, String> {
                self.0.ask_secret(q, f)
            }
            fn show_secret(&mut self, _: &str) -> Result<(), String> {
                Err("cannot write to the terminal: EIO".into())
            }
            fn interactive(&self) -> bool {
                false
            }
            fn can_show_secret(&self) -> bool {
                true
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut a = headless(dir.path());
        a.agent_token_file = None;
        let e = run(&a, &mut BrokenTty(Headless(Vec::new())), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("EIO"), "{e}");
        assert!(!dir.path().join("kharon.toml").exists());
        assert!(!dir.path().join("bw_api_key.json").exists());
    }

    #[test]
    fn req_404_create_file_removes_the_key_after_a_post_open_failure() {
        let dir = tempfile::tempdir().unwrap();
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                super::AFTER_WRITE.with(|h| h.set(None));
            }
        }
        let _reset = Reset;
        fn fail_after_secret_is_on_disk(path: &Path) -> Result<(), String> {
            let bytes = std::fs::read(path).unwrap();
            assert!(
                bytes.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()),
                "the secret must already be on disk when this fails"
            );
            Err(format!(
                "cannot set the owner of {}: injected",
                path.display()
            ))
        }
        super::AFTER_WRITE.with(|h| h.set(Some(fail_after_secret_is_on_disk)));

        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        let e = run(&headless(dir.path()), &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("injected"), "{e}");
        assert!(!e.contains(SECRET), "{e}");
        assert!(!dir.path().join("bw_api_key.json").exists());
        assert!(!dir.path().join("kharon.toml").exists());
        assert!(!dir.path().join("agent-token").exists());
    }

    #[test]
    fn req_404_key_owner_needs_root_unless_it_is_us() {
        if rustix::process::geteuid().is_root() {
            return; // root may chown to anyone
        }
        let dir = tempfile::tempdir().unwrap();
        let mut a = headless(dir.path());
        a.key_owner = None; // 10001:10001
        let mut vault = Fake::new(sync_with(&[COLL1], |_| {}));
        let e = run(&a, &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(
            e.contains("uid 10001 gid 10001") && e.contains("sudo"),
            "{e}"
        );
        assert!(!dir.path().join("bw_api_key.json").exists());
    }

    #[test]
    fn req_404_no_discover_for_an_unreachable_internal_server() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = headless(dir.path());
        a.server = Some("http://vaultwarden:80".into());
        a.no_discover = true;
        a.layout = Some(Layout::Compose);
        a.key_file_in_config = None;
        let mut vault = Fake::new(serde_json::json!({}));
        let e = run(&a, &mut Headless(Vec::new()), &mut vault)
            .err()
            .unwrap();
        assert!(e.contains("--organization-id"), "{e}");
        a.organization_id = Some(ORG.to_uppercase());
        a.collection_ids = vec![COLL1.into()];
        run(&a, &mut Headless(Vec::new()), &mut vault).unwrap();
        assert!(vault.calls.is_empty());
        let text = std::fs::read_to_string(dir.path().join("kharon.toml")).unwrap();
        assert!(text.contains("server = \"http://vaultwarden/\""));
        assert!(text.contains("api_key_file = \"/run/secrets/kharon_bw_api_key\""));
        assert!(text.contains(&format!("organization_id = \"{ORG}\"")));
    }

    #[test]
    fn req_404_answers_file_refuses_unknown_keys_and_secrets() {
        assert!(Answers::from_toml("emial = \"x\"").is_err());
        // There is no key for a secret: the client secret can't be put in it.
        assert!(Answers::from_toml("client-secret = \"x\"").is_err());
        let a = Answers::from_toml("collection-ids = [\"a\", \"b\"]\nlayout = \"host\"").unwrap();
        assert_eq!(a.collection_ids, vec!["a", "b"]);
        assert_eq!(a.layout, Some(Layout::Host));
        let flags = Answers {
            email: Some("flag@example.net".into()),
            ..Answers::default()
        };
        let file = Answers::from_toml("email = \"file@example.net\"\nagent-id = \"x\"").unwrap();
        let m = flags.over(file);
        assert_eq!(m.email.as_deref(), Some("flag@example.net"));
        assert_eq!(m.agent_id.as_deref(), Some("x"));
    }

    #[test]
    fn req_404_render_escapes_and_parses_back() {
        assert_eq!(toml_str("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
        assert_eq!(parse_owner("10001").unwrap(), KHAROND_OWNER);
        assert_eq!(parse_owner("1:2").unwrap(), Owner { uid: 1, gid: 2 });
        assert!(parse_owner("kharon").is_err());
        let t = random_topic().unwrap();
        assert!(t.starts_with("kharon-") && t.len() == 27, "{t}");
        assert_ne!(t, random_topic().unwrap());
    }
}
