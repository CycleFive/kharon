//! `kharon doctor`: the verification pass for a first-run
//! installation (#406, child 4 of #401). Where `kharon setup` (#404)
//! writes the installation, doctor reads it back and reports six
//! checks, one line each — `PASS`, `FAIL`, or `SKIP` — every failure
//! naming the fix. The exit status is non-zero when any check fails;
//! a skip never fails the run. Doctor holds no secrets: it never
//! prints the client secret, a token, or the ntfy topic (a capability
//! on the public server), and the key file's secret is never even
//! deserialized.
//!
//! The checks, and where each fact comes from:
//!
//! 1. **Config and key files** — metadata of the config and the API
//!    key file, under the daemon's own REQ-DEP-008 rules: a missing,
//!    non-regular, or group/world-writable file fails (kharond would
//!    refuse to start); the rules kharond only warns about (a
//!    group/other-readable key file, an owner other than doctor's
//!    euid) are notes on a pass. A config that does not load fails
//!    this check with the loader's message, and the checks that need
//!    the config skip gracefully.
//! 2. **API key type** — the key file's `client_id` against #403's
//!    check (`kharond::sync::check_client_id`), the refusal `kharon
//!    setup` and kharond share.
//! 3. **Sync visibility** — one sync with the broker account, then
//!    `kharond::sync::discover` (the same discovery setup uses): the
//!    configured organization and every configured collection must
//!    be visible from the account's own view, and REQ-CRY-008's
//!    scope rule must come back clean, as kharond will demand at
//!    unlock.
//! 4. **Audit sink** — an off-host checkpoint sink is configured, or
//!    `audit.checkpoint_local_only` is set (a pass with a note:
//!    kharond warns about it at startup, SPEC §7).
//! 5. **Passkey enrolled** — the owner socket's `passkey_list` op
//!    (#258) names at least one passkey. Skipped when the config has
//!    no `[owner_ui]`; passkeys belong to the owner UI.
//! 6. **Agent attached** — the owner socket's `status` reply lists
//!    every configured agent and its connector attachment (#406).
//!    Only agents on `via = "agent_connector"` hold a session, so
//!    the check skips when no agent uses that transport. A daemon
//!    whose reply has no `agents` field predates the report and
//!    fails with the upgrade as the fix.
//!
//! Checks 5–6 talk to the live daemon and are not unlock-gated, so
//! they work while the broker is locked. A daemon that does not
//! answer fails both with "start kharond" as the fix; doctor never
//! crashes on a down daemon.
//!
//! The checks are testable units over three injected seams, mirroring
//! setup.rs: [`FileProbe`] for filesystem facts and reads,
//! [`setup::VaultProbe`] for the sync, and [`OwnerChannel`] for the
//! owner socket. The live wiring is in [`command`].

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Args;
use kharond::config::{BitwardenConfig, Config, Source};
use kharond::sync::{
    ApiKey, Discovery, ScopeViolation, check_client_id, discover, scope_violation,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::setup::{self, VaultProbe};

/// `kharon doctor`'s arguments (#406).
#[derive(Args, Debug, Clone)]
pub struct DoctorArgs {
    /// The config kharond runs with.
    /// [default: /etc/kharon.toml]
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// The daemon's owner socket. Default: `<data_dir>/owner.sock`
    /// from the config, or `/data/owner.sock` when the config does
    /// not load.
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// The API key file on this host, when the path in the config is
    /// the daemon's own (in the Compose deployment the config names
    /// the in-container path `/run/secrets/kharon_bw_api_key`).
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Skip,
}

impl Check {
    fn pass(name: &'static str, detail: String) -> Self {
        Check {
            name,
            verdict: Verdict::Pass,
            detail,
        }
    }

    fn fail(name: &'static str, detail: String) -> Self {
        Check {
            name,
            verdict: Verdict::Fail,
            detail,
        }
    }

    fn skip(name: &'static str, detail: String) -> Self {
        Check {
            name,
            verdict: Verdict::Skip,
            detail,
        }
    }

    fn line(&self) -> String {
        let word = match self.verdict {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Skip => "SKIP",
        };
        format!("{word} {}: {}", self.name, self.detail)
    }
}

/// The filesystem facts doctor needs about one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    /// A regular file (not a directory, device, …).
    pub regular: bool,
    /// Unix mode, file-type bits included; mask before use.
    pub mode: u32,
    pub uid: u32,
}

/// Seam: filesystem facts and reads (setup.rs's `VaultProbe` shape,
/// for the filesystem). The error a read returns is a fixed reason,
/// never file content.
pub trait FileProbe {
    fn facts(&self, path: &Path) -> Option<FileFacts>;
    fn read(&self, path: &Path) -> Result<Vec<u8>, String>;
}

/// The live filesystem.
pub struct LiveFiles;

impl FileProbe for LiveFiles {
    fn facts(&self, path: &Path) -> Option<FileFacts> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).ok()?;
        Some(FileFacts {
            regular: meta.file_type().is_file(),
            mode: meta.mode(),
            uid: meta.uid(),
        })
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e.kind()))
    }
}

/// Seam: one request/response over the daemon's owner socket. The
/// error is the CLI's fixed connection-refusal text; a reply is the
/// daemon's parsed JSON.
pub trait OwnerChannel {
    fn call(&mut self, request: &str) -> Result<serde_json::Value, String>;
}

/// The live owner socket, through main.rs's `owner_request_text`
/// (which refuses a socket owned by another uid, REQ-DEP-008).
pub struct LiveOwner {
    socket: PathBuf,
}

impl LiveOwner {
    pub fn new(socket: PathBuf) -> Self {
        LiveOwner { socket }
    }
}

impl OwnerChannel for LiveOwner {
    fn call(&mut self, request: &str) -> Result<serde_json::Value, String> {
        let text = super::owner_request_text(&self.socket, request)?;
        serde_json::from_str(&text).map_err(|_| "malformed reply from daemon".to_owned())
    }
}

/// Group/other write bits: REQ-DEP-008's refusal line for both files.
const GROUP_OTHER_WRITE: u32 = 0o022;
/// Group/other read bits: kharond warns about these on the key file.
const GROUP_OTHER_READ: u32 = 0o044;

/// Check 1: config and key-file ownership and permissions, under
/// REQ-DEP-008's rules — the daemon's fatal rules fail, its warning
/// rules become notes. `load_error` is the config loader's refusal,
/// when the config did not load.
fn check_files(
    files: &dyn FileProbe,
    config_path: &Path,
    key_path: Option<&Path>,
    load_error: Option<&str>,
    euid: u32,
) -> Check {
    let name = "config and key files";
    let mut problems: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    match files.facts(config_path) {
        None => problems.push(format!(
            "the config file {} cannot be read. Fix: pass --config for the file kharond runs \
             with, or create it with `kharon setup`",
            config_path.display()
        )),
        Some(f) if !f.regular => problems.push(format!(
            "the config file {} is not a regular file. Fix: point --config at the kharon.toml \
             kharond runs with",
            config_path.display()
        )),
        Some(f) if f.mode & GROUP_OTHER_WRITE != 0 => problems.push(format!(
            "the config file {} is group- or world-writable (mode {:04o}); anyone who can write \
             it can replace the agents' token hashes. Fix: chmod 0640 {}",
            config_path.display(),
            f.mode & 0o7777,
            config_path.display()
        )),
        Some(_) => {}
    }
    if let Some(e) = load_error {
        problems.push(format!(
            "the config does not load: {e}. Fix: correct it — `kharond --check` prints the same \
             refusal"
        ));
    }
    if let Some(key_path) = key_path {
        match files.facts(key_path) {
            None => problems.push(format!(
                "the API key file {} cannot be read. Fix: check the secret mount, or pass \
                 --key-file for the file's path on this host",
                key_path.display()
            )),
            Some(f) if !f.regular => problems.push(format!(
                "the API key file {} is not a regular file. Fix: replace it with the JSON file \
                 the personal API key dialog shows",
                key_path.display()
            )),
            Some(f) => {
                if f.mode & GROUP_OTHER_WRITE != 0 {
                    problems.push(format!(
                        "the API key file {} is group- or world-writable (mode {:04o}); anyone \
                         who can write it can point kharond at their own account (SPEC §8). \
                         Fix: chmod 0400 {}",
                        key_path.display(),
                        f.mode & 0o7777,
                        key_path.display()
                    ));
                } else {
                    if f.mode & GROUP_OTHER_READ != 0 {
                        notes.push(format!(
                            "the key file is group/other-readable (mode {:04o}); kharond warns \
                             but starts — chmod 0400 {} to silence it",
                            f.mode & 0o7777,
                            key_path.display()
                        ));
                    }
                    if f.uid != euid {
                        notes.push(format!(
                            "the key file is owned by uid {}, doctor is running as uid {euid}; \
                             kharond compares the owner with its own euid",
                            f.uid
                        ));
                    }
                }
            }
        }
    }
    if problems.is_empty() {
        let mut detail = if key_path.is_some() {
            "the config and key files are regular files, not group- or world-writable".to_owned()
        } else {
            "the config file is a regular file, not group- or world-writable (no key file)"
                .to_owned()
        };
        for note in notes {
            detail.push_str("; note: ");
            detail.push_str(&note);
        }
        Check::pass(name, detail)
    } else {
        Check::fail(name, problems.join("; "))
    }
}

/// Check 2: the API key type, by #403's shared check. Only the
/// `client_id` is deserialized — the secret never lands in a field
/// doctor keeps — and the file bytes zeroize on drop.
fn check_key_type(files: &dyn FileProbe, key_path: &Path) -> Check {
    let name = "api key type";
    let bytes = match files.read(key_path) {
        Ok(b) => Zeroizing::new(b),
        Err(e) => {
            return Check::fail(
                name,
                format!(
                    "{e}. Fix: check the secret mount, or pass --key-file for the file's path \
                     on this host"
                ),
            );
        }
    };
    #[derive(Deserialize)]
    struct KeyFileHead {
        client_id: String,
    }
    let head: KeyFileHead = match serde_json::from_slice(&bytes) {
        Ok(h) => h,
        Err(_) => {
            return Check::fail(
                name,
                "the key file is not the JSON object {\"client_id\", \"client_secret\"} the \
                 personal API key dialog shows. Fix: save that dialog's JSON as the key file"
                    .to_owned(),
            );
        }
    };
    match check_client_id(&head.client_id) {
        Ok(()) => Check::pass(
            name,
            "the API key is a personal key (client_id user.<uuid>)".to_owned(),
        ),
        Err(e) => Check::fail(name, e.message().to_owned()),
    }
}

/// Check 3's judgement over a finished discovery: pure, so both the
/// pass and every failure are unit tests.
fn assess_visibility(bw: &BitwardenConfig, d: &Discovery, scope: &ScopeViolation) -> Check {
    let name = "sync visibility";
    if !d.email.trim().eq_ignore_ascii_case(bw.email.trim()) {
        return Check::fail(
            name,
            "the API key belongs to a different account than the configured email. Fix: put \
             the dedicated account's email in [bitwarden] and use its own personal API key"
                .to_owned(),
        );
    }
    let Some(org) = d.orgs.iter().find(|o| o.id == bw.organization_id) else {
        return Check::fail(
            name,
            format!(
                "the account cannot see organization {}. Fix: invite the dedicated account to \
                 the organization in Bitwarden, or correct organization_id in the config",
                bw.organization_id
            ),
        );
    };
    let missing: Vec<&String> = bw
        .collection_ids
        .iter()
        .filter(|c| !org.collections.iter().any(|x| &x.id == *c))
        .collect();
    if let Some(first) = missing.first() {
        return Check::fail(
            name,
            format!(
                "collection {first} is not visible to the account in organization {} ({} of {} \
                 configured collections visible). Fix: assign the collection to the dedicated \
                 account in Bitwarden, or correct collection_ids in the config",
                bw.organization_id,
                bw.collection_ids.len() - missing.len(),
                bw.collection_ids.len()
            ),
        );
    }
    if !scope.is_empty() {
        return Check::fail(
            name,
            format!(
                "the account can see {} other organization(s) and {} item(s) outside the kharon \
                 organization, so kharond would refuse it at unlock [scope_too_broad]. Fix: \
                 move or delete those items in Bitwarden, or remove the account from the other \
                 organizations",
                scope.other_orgs.len(),
                scope.outside_items.len()
            ),
        );
    }
    let label = match &org.name {
        Some(n) => format!("{} ({})", super::plain(n), org.id),
        None => org.id.clone(),
    };
    Check::pass(
        name,
        format!(
            "organization {label} visible with all {} configured collection(s) ({} items in \
             the organization's view)",
            bw.collection_ids.len(),
            org.items
        ),
    )
}

/// Check 3: one sync with the broker account, judged by
/// [`assess_visibility`]. `key_override` is `--key-file`: when the
/// config's key path is the daemon's own, the key is read from the
/// override instead.
fn check_sync(
    vault: &mut dyn VaultProbe,
    files: &dyn FileProbe,
    bw: &BitwardenConfig,
    key_override: Option<&Path>,
) -> Check {
    let name = "sync visibility";
    let key: ApiKey = match key_override {
        Some(path) => {
            let bytes = match files.read(path) {
                Ok(b) => Zeroizing::new(b),
                Err(e) => {
                    return Check::fail(
                        name,
                        format!("{e}. Fix: pass --key-file for the file's path on this host"),
                    );
                }
            };
            let text = match String::from_utf8(bytes.to_vec()) {
                Ok(t) => Zeroizing::new(t),
                Err(_) => {
                    return Check::fail(
                        name,
                        "the key file is not UTF-8 JSON. Fix: save the personal API key \
                         dialog's JSON as the key file"
                            .to_owned(),
                    );
                }
            };
            match ApiKey::from_json(&text) {
                Ok(k) => k,
                Err(e) => return Check::fail(name, e.to_string()),
            }
        }
        None => match bw.api_key() {
            Ok(k) => k,
            Err(e) => {
                return Check::fail(name, format!("the API key file cannot be used: {e}"));
            }
        },
    };
    let trust = match bw.tls_trust() {
        Ok(t) => t,
        Err(e) => return Check::fail(name, format!("the TLS trust cannot be built: {e}")),
    };
    match vault.sync(&bw.server, &bw.email, key, &trust) {
        Ok(sync) => {
            let found = discover(&sync);
            let scope = scope_violation(&sync, &bw.organization_id);
            assess_visibility(bw, &found, &scope)
        }
        Err(e) => Check::fail(name, setup::explain_sync_error(&e, &bw.server)),
    }
}

/// Check 4's judgement: an off-host sink configured, or checkpoints
/// deliberately kept on-host. Pure; the inputs come from the loaded
/// config.
fn assess_audit_sink(checkpoint_configured: bool, local_only: bool) -> Check {
    let name = "audit sink";
    if checkpoint_configured {
        Check::pass(
            name,
            "audit checkpoints go off-host to the configured ntfy sink".to_owned(),
        )
    } else if local_only {
        Check::pass(
            name,
            "audit checkpoints stay on this host (audit.checkpoint_local_only = true); kharond \
             warns about this at startup (SPEC §7)"
                .to_owned(),
        )
    } else {
        Check::fail(
            name,
            "no off-host audit checkpoint sink is configured, and kharond refuses to start \
             without one. Fix: set [approval].ntfy or [audit].checkpoint_ntfy, or set \
             audit.checkpoint_local_only = true to keep checkpoints on this host"
                .to_owned(),
        )
    }
}

/// Check 5: a passkey is enrolled, via the owner socket's
/// `passkey_list` op (#258). `ui_configured` is the config's word on
/// `[owner_ui]` — `None` when the config did not load, so an
/// `unknown_op` reply can still be read as "no owner UI".
fn check_passkey(owner: &mut dyn OwnerChannel, ui_configured: Option<bool>) -> Check {
    let name = "passkey enrolled";
    if ui_configured == Some(false) {
        return Check::skip(
            name,
            "no [owner_ui] is configured; passkeys belong to the owner UI".to_owned(),
        );
    }
    let reply = match owner.call("{\"op\":\"passkey_list\"}") {
        Ok(r) => r,
        Err(e) => {
            return Check::fail(
                name,
                format!(
                    "the daemon did not answer on the owner socket ({e}). Fix: start kharond, \
                     or pass --socket for its owner socket"
                ),
            );
        }
    };
    if reply.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let code = reply
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if code == "unknown_op" {
            return match ui_configured {
                Some(true) => Check::fail(
                    name,
                    "the config has [owner_ui] but the running daemon reports no owner UI. Fix: \
                     restart kharond with this config"
                        .to_owned(),
                ),
                _ => Check::skip(
                    name,
                    "the daemon has no owner UI; passkeys belong to the owner UI".to_owned(),
                ),
            };
        }
        return Check::fail(
            name,
            format!(
                "the daemon refused passkey_list [{code}]. Fix: check the daemon log — a failed \
                 audit append (audit_failed) leaves the list unread"
            ),
        );
    }
    let Some(rows) = reply.get("passkeys").and_then(|v| v.as_array()) else {
        return Check::fail(
            name,
            "the daemon's passkey_list reply has no passkey list. Fix: restart kharond; if it \
             persists, the daemon and this CLI are from different builds"
                .to_owned(),
        );
    };
    if rows.is_empty() {
        Check::fail(
            name,
            "no passkey is enrolled, so nobody can sign in to the owner UI to approve grants. \
             Fix: run `kharon passkey-enroll` and register a passkey in the owner UI"
                .to_owned(),
        )
    } else {
        Check::pass(name, format!("{} passkey(s) enrolled", rows.len()))
    }
}

/// Check 6: an agent is attached, via the owner socket's `status`
/// reply (#406). `connector_agents` is the config's agents on
/// `via = "agent_connector"` — `None` when the config did not load.
fn check_agents(owner: &mut dyn OwnerChannel, connector_agents: Option<&[String]>) -> Check {
    let name = "agent attached";
    let Some(agents) = connector_agents else {
        return Check::skip(
            name,
            "the config did not load, so the configured agents are unknown".to_owned(),
        );
    };
    if agents.is_empty() {
        return Check::skip(
            name,
            "no agent uses via = \"agent_connector\"; the other transports are dialed per fill, \
             so there is no attachment to check"
                .to_owned(),
        );
    }
    let reply = match owner.call("{\"op\":\"status\"}") {
        Ok(r) => r,
        Err(e) => {
            return Check::fail(
                name,
                format!(
                    "the daemon did not answer on the owner socket ({e}). Fix: start kharond, \
                     or pass --socket for its owner socket"
                ),
            );
        }
    };
    if reply.get("ok") != Some(&serde_json::Value::Bool(true)) {
        let code = reply
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        return Check::fail(name, format!("the daemon refused status [{code}]"));
    }
    let Some(rows) = reply.get("agents").and_then(|v| v.as_array()) else {
        return Check::fail(
            name,
            "the running daemon does not report agent attachment (its status reply has no \
             agents field). Fix: update and restart kharond from a build with #406"
                .to_owned(),
        );
    };
    let mut states: Vec<String> = Vec::new();
    let mut any_attached = false;
    for id in agents {
        let attached = rows.iter().any(|r| {
            r.get("id").and_then(|v| v.as_str()) == Some(id.as_str())
                && r.get("attached") == Some(&serde_json::Value::Bool(true))
        });
        any_attached |= attached;
        states.push(format!(
            "{id}: {}",
            if attached { "attached" } else { "not attached" }
        ));
    }
    if any_attached {
        Check::pass(name, states.join("; "))
    } else {
        Check::fail(
            name,
            format!(
                "no agent is attached ({}). Fix: start kharon-agent-connector on the agent \
                 host, and check its broker pin, tunnel credential and the [connector] listener",
                states.join("; ")
            ),
        )
    }
}

/// Run the six checks. `owner` builds the owner channel for the
/// resolved socket, so tests inject a fake while production dials the
/// socket [`command`] resolved. Returns the checks and whether any
/// failed.
pub fn run(
    args: &DoctorArgs,
    files: &dyn FileProbe,
    vault: &mut dyn VaultProbe,
    owner: &mut dyn FnMut(&Path) -> Box<dyn OwnerChannel>,
) -> (Vec<Check>, bool) {
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(kharond::config::DEFAULT_CONFIG_PATH));
    let loaded = Config::load(&config_path);
    let cfg: Option<&Config> = loaded.as_ref().ok();
    let load_error: Option<String> = loaded.as_ref().err().map(ToString::to_string);
    let key_path: Option<PathBuf> = args.key_file.clone().or_else(|| match cfg {
        Some(c) => match &c.source {
            Source::Sync(bw) => Some(bw.api_key_file.clone()),
            Source::Export(_) => None,
        },
        None => None,
    });
    let socket = args
        .socket
        .clone()
        .or_else(|| cfg.map(|c| kharond::owner::socket_path(&c.data_dir)))
        .unwrap_or_else(|| PathBuf::from(super::DEFAULT_OWNER_SOCKET));
    let mut channel = owner(&socket);
    let euid = rustix::process::geteuid().as_raw();

    let mut checks = Vec::with_capacity(6);
    checks.push(check_files(
        files,
        &config_path,
        key_path.as_deref(),
        load_error.as_deref(),
        euid,
    ));
    checks.push(match &key_path {
        Some(p) => check_key_type(files, p),
        None => Check::skip(
            "api key type",
            match cfg {
                Some(_) => "export mode: there is no API key".to_owned(),
                None => "no key file is known (the config did not load, and --key-file was not \
                         passed)"
                    .to_owned(),
            },
        ),
    });
    checks.push(match cfg {
        Some(c) => match &c.source {
            Source::Sync(bw) => check_sync(vault, files, bw, args.key_file.as_deref()),
            Source::Export(_) => Check::skip(
                "sync visibility",
                "export mode: items come from the encrypted export, there is no sync".to_owned(),
            ),
        },
        None => Check::skip("sync visibility", "the config did not load".to_owned()),
    });
    checks.push(match cfg {
        Some(c) => assess_audit_sink(c.checkpoint_ntfy().is_some(), c.audit.checkpoint_local_only),
        None => Check::skip("audit sink", "the config did not load".to_owned()),
    });
    checks.push(check_passkey(
        &mut *channel,
        cfg.map(|c| c.owner_ui.is_some()),
    ));
    let connector_agents: Option<Vec<String>> = cfg.map(|c| {
        c.agents
            .iter()
            .filter(|(_, a)| a.cdp.tunnel == kharond::cdp::Tunnel::AgentConnector)
            .map(|(id, _)| id.clone())
            .collect()
    });
    checks.push(check_agents(&mut *channel, connector_agents.as_deref()));
    let failed = checks.iter().any(|c| c.verdict == Verdict::Fail);
    (checks, failed)
}

/// `kharon doctor`: print one line per check and a summary; the exit
/// status is non-zero when any check fails.
pub fn command(args: &DoctorArgs) -> ExitCode {
    let files = LiveFiles;
    let mut vault = setup::LiveVault;
    let (checks, failed) = run(args, &files, &mut vault, &mut |socket| {
        Box::new(LiveOwner::new(socket.to_path_buf()))
    });
    let (mut passed, mut failed_n, mut skipped) = (0, 0, 0);
    for c in &checks {
        match c.verdict {
            Verdict::Pass => passed += 1,
            Verdict::Fail => failed_n += 1,
            Verdict::Skip => skipped += 1,
        }
        println!("{}", c.line());
    }
    println!("doctor: {passed} passed, {failed_n} failed, {skipped} skipped");
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use kharond::sync::{DiscoveredCollection, DiscoveredOrg, SyncError, TlsTrust};
    use url::Url;

    const ORG: &str = "0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
    const COLL: &str = "11111111-2222-3333-4444-555555555555";
    const USER_KEY: &[u8] =
        br#"{"client_id":"user.6b1e0c52-0a3e-4a8e-9a4f-1f0e2d3c4b5a","client_secret":"DOCTOR-SECRET-CANARY"}"#;
    const ORG_KEY: &[u8] =
        br#"{"client_id":"organization.6b1e0c52-0a3e-4a8e-9a4f-1f0e2d3c4b5a","client_secret":"DOCTOR-SECRET-CANARY"}"#;

    #[derive(Default)]
    struct FakeFiles {
        facts: HashMap<PathBuf, FileFacts>,
        reads: HashMap<PathBuf, Vec<u8>>,
    }

    impl FakeFiles {
        fn with_file(mut self, path: &str, mode: u32, uid: u32, bytes: &[u8]) -> Self {
            self.facts.insert(
                PathBuf::from(path),
                FileFacts {
                    regular: true,
                    mode: 0o100_000 | mode,
                    uid,
                },
            );
            self.reads.insert(PathBuf::from(path), bytes.to_vec());
            self
        }
    }

    impl FileProbe for FakeFiles {
        fn facts(&self, path: &Path) -> Option<FileFacts> {
            self.facts.get(path).copied()
        }

        fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
            self.reads
                .get(path)
                .cloned()
                .ok_or_else(|| format!("cannot read {}: NotFound", path.display()))
        }
    }

    /// A stateless owner channel: canned replies per op.
    #[derive(Default)]
    struct FakeOwner {
        down: bool,
        /// `passkey_list` outcome: `None` → the daemon answers
        /// `unknown_op`; `Some(n)` → n passkeys enrolled.
        passkeys: Option<usize>,
        /// `status` outcome: `None` → a pre-#406 reply (no `agents`
        /// field); `Some(rows)` → (agent id, session start).
        agents: Option<Vec<(String, Option<u64>)>>,
    }

    impl OwnerChannel for FakeOwner {
        fn call(&mut self, request: &str) -> Result<serde_json::Value, String> {
            if self.down {
                return Err("cannot connect to owner socket: NotFound".to_owned());
            }
            if request.contains("passkey_list") {
                return Ok(match self.passkeys {
                    None => serde_json::json!({"ok": false, "error": "unknown_op"}),
                    Some(n) => serde_json::json!({
                        "ok": true,
                        "passkeys": (0..n)
                            .map(|i| serde_json::json!({
                                "id": format!("{i:08x}"),
                                "enrolled_at": null,
                                "last_used_at": null,
                            }))
                            .collect::<Vec<_>>(),
                    }),
                });
            }
            if request.contains("\"status\"") {
                return Ok(match &self.agents {
                    None => serde_json::json!({"ok": true, "locked": false}),
                    Some(rows) => serde_json::json!({
                        "ok": true,
                        "locked": false,
                        "agents": rows
                            .iter()
                            .map(|(id, since)| serde_json::json!({
                                "id": id,
                                "attached": since.is_some(),
                                "since": since,
                            }))
                            .collect::<Vec<_>>(),
                    }),
                });
            }
            Err("unexpected request".to_owned())
        }
    }

    /// A vault whose sync always fails the same way.
    struct RefusingVault;

    impl VaultProbe for RefusingVault {
        fn sync(
            &mut self,
            _server: &Url,
            _email: &str,
            _key: ApiKey,
            _trust: &TlsTrust,
        ) -> Result<kharond::sync::wire::SyncResponse, SyncError> {
            Err(SyncError::Transport("connection refused"))
        }
    }

    // ---- check 1: files ----

    #[test]
    fn req_406_files_pass() {
        let files = FakeFiles::default()
            .with_file("/cfg/kharon.toml", 0o640, 0, b"")
            .with_file("/run/secrets/key", 0o400, 0, USER_KEY);
        let c = check_files(
            &files,
            Path::new("/cfg/kharon.toml"),
            Some(Path::new("/run/secrets/key")),
            None,
            0,
        );
        assert_eq!(c.verdict, Verdict::Pass, "{}", c.detail);
    }

    #[test]
    fn req_406_files_fail_writable_key_and_missing_config() {
        let files = FakeFiles::default().with_file("/run/secrets/key", 0o666, 0, USER_KEY);
        let c = check_files(
            &files,
            Path::new("/cfg/kharon.toml"),
            Some(Path::new("/run/secrets/key")),
            None,
            0,
        );
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("cannot be read"), "{}", c.detail);
        assert!(c.detail.contains("chmod 0400"), "{}", c.detail);
    }

    #[test]
    fn req_406_files_fail_load_error_and_pass_with_readable_note() {
        // The loader's refusal fails the check even when the
        // metadata is fine.
        let files = FakeFiles::default()
            .with_file("/cfg/kharon.toml", 0o640, 0, b"")
            .with_file("/run/secrets/key", 0o400, 0, USER_KEY);
        let c = check_files(
            &files,
            Path::new("/cfg/kharon.toml"),
            Some(Path::new("/run/secrets/key")),
            Some("bitwarden.organization_id: not a UUID"),
            0,
        );
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("does not load"), "{}", c.detail);

        // A group-readable key file is kharond's warning, not a
        // refusal: a pass with the note attached.
        let files = FakeFiles::default()
            .with_file("/cfg/kharon.toml", 0o640, 0, b"")
            .with_file("/run/secrets/key", 0o440, 0, USER_KEY);
        let c = check_files(
            &files,
            Path::new("/cfg/kharon.toml"),
            Some(Path::new("/run/secrets/key")),
            None,
            0,
        );
        assert_eq!(c.verdict, Verdict::Pass, "{}", c.detail);
        assert!(c.detail.contains("note:"), "{}", c.detail);
    }

    // ---- check 2: key type ----

    #[test]
    fn req_406_key_type_pass_and_fail() {
        let files = FakeFiles::default().with_file("/key", 0o400, 0, USER_KEY);
        let c = check_key_type(&files, Path::new("/key"));
        assert_eq!(c.verdict, Verdict::Pass, "{}", c.detail);
        assert!(!c.detail.contains("DOCTOR-SECRET-CANARY"));

        let files = FakeFiles::default().with_file("/key", 0o400, 0, ORG_KEY);
        let c = check_key_type(&files, Path::new("/key"));
        assert_eq!(c.verdict, Verdict::Fail);
        // #403's refusal text, verbatim shape: it names the fix and
        // never echoes the id or the secret.
        assert!(c.detail.contains("organization API key"), "{}", c.detail);
        assert!(c.detail.contains("Fix:"), "{}", c.detail);
        assert!(!c.detail.contains("6b1e0c52"), "{}", c.detail);
        assert!(!c.detail.contains("DOCTOR-SECRET-CANARY"), "{}", c.detail);

        let files = FakeFiles::default().with_file("/key", 0o400, 0, b"not json");
        let c = check_key_type(&files, Path::new("/key"));
        assert_eq!(c.verdict, Verdict::Fail);
    }

    // ---- check 3: sync visibility (the pure judgement) ----

    fn bw() -> BitwardenConfig {
        BitwardenConfig {
            server: Url::parse("https://vault.example.net").unwrap(),
            email: "kharon@example.net".to_owned(),
            api_key_file: PathBuf::from("/key"),
            organization_id: ORG.to_owned(),
            collection_ids: vec![COLL.to_owned()],
            allow_extra_orgs: false,
            ca_file: None,
        }
    }

    fn discovery() -> Discovery {
        Discovery {
            email: "kharon@example.net".to_owned(),
            orgs: vec![DiscoveredOrg {
                id: ORG.to_owned(),
                name: Some("Agents".to_owned()),
                collections: vec![DiscoveredCollection {
                    id: COLL.to_owned(),
                    items: 3,
                }],
                items: 3,
            }],
            personal_items: 0,
        }
    }

    fn clean_scope() -> ScopeViolation {
        ScopeViolation {
            other_orgs: Vec::new(),
            outside_items: Vec::new(),
        }
    }

    #[test]
    fn req_406_visibility_pass() {
        let c = assess_visibility(&bw(), &discovery(), &clean_scope());
        assert_eq!(c.verdict, Verdict::Pass, "{}", c.detail);
        assert!(c.detail.contains("Agents"), "{}", c.detail);
    }

    #[test]
    fn req_406_visibility_failures() {
        // Wrong account entirely.
        let mut d = discovery();
        d.email = "someone-else@example.net".to_owned();
        let c = assess_visibility(&bw(), &d, &clean_scope());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("different account"), "{}", c.detail);

        // Organization not visible.
        let mut d = discovery();
        d.orgs.clear();
        let c = assess_visibility(&bw(), &d, &clean_scope());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("cannot see organization"), "{}", c.detail);

        // Collection not assigned.
        let mut d = discovery();
        d.orgs[0].collections.clear();
        let c = assess_visibility(&bw(), &d, &clean_scope());
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains(COLL), "{}", c.detail);

        // REQ-CRY-008: the account sees more than the kharon org.
        let scope = ScopeViolation {
            other_orgs: vec!["other-org".to_owned()],
            outside_items: vec!["item".to_owned()],
        };
        let c = assess_visibility(&bw(), &discovery(), &scope);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("scope_too_broad"), "{}", c.detail);
    }

    // ---- check 4: audit sink ----

    #[test]
    fn req_406_audit_sink_pass_and_fail() {
        assert_eq!(assess_audit_sink(true, false).verdict, Verdict::Pass);
        let local = assess_audit_sink(false, true);
        assert_eq!(local.verdict, Verdict::Pass);
        assert!(
            local.detail.contains("checkpoint_local_only"),
            "{}",
            local.detail
        );
        let none = assess_audit_sink(false, false);
        assert_eq!(none.verdict, Verdict::Fail);
        assert!(none.detail.contains("Fix:"), "{}", none.detail);
    }

    // ---- check 5: passkey ----

    #[test]
    fn req_406_passkey_pass_and_fail() {
        let mut owner = FakeOwner {
            passkeys: Some(2),
            ..Default::default()
        };
        let c = check_passkey(&mut owner, Some(true));
        assert_eq!(c.verdict, Verdict::Pass, "{}", c.detail);
        assert!(c.detail.contains('2'), "{}", c.detail);

        let mut owner = FakeOwner {
            passkeys: Some(0),
            ..Default::default()
        };
        let c = check_passkey(&mut owner, Some(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("passkey-enroll"), "{}", c.detail);

        // Daemon down: a failure naming the fix, not a crash.
        let mut owner = FakeOwner {
            down: true,
            ..Default::default()
        };
        let c = check_passkey(&mut owner, Some(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("start kharond"), "{}", c.detail);
    }

    #[test]
    fn req_406_passkey_skips_without_owner_ui() {
        // Config says no [owner_ui]: skipped without asking.
        let mut owner = FakeOwner {
            down: true,
            ..Default::default()
        };
        let c = check_passkey(&mut owner, Some(false));
        assert_eq!(c.verdict, Verdict::Skip);

        // Config unknown and the daemon has no owner UI: skip.
        let mut owner = FakeOwner {
            passkeys: None,
            ..Default::default()
        };
        let c = check_passkey(&mut owner, None);
        assert_eq!(c.verdict, Verdict::Skip);

        // Config says [owner_ui] but the daemon disagrees: fail.
        let mut owner = FakeOwner {
            passkeys: None,
            ..Default::default()
        };
        let c = check_passkey(&mut owner, Some(true));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("restart kharond"), "{}", c.detail);
    }

    // ---- check 6: agent attached ----

    #[test]
    fn req_406_agents_pass_and_fail() {
        let agents = vec!["assistant".to_owned()];
        let mut owner = FakeOwner {
            agents: Some(vec![("assistant".to_owned(), Some(1_700_000_000))]),
            ..Default::default()
        };
        let c = check_agents(&mut owner, Some(&agents));
        assert_eq!(c.verdict, Verdict::Pass, "{}", c.detail);
        assert!(c.detail.contains("assistant: attached"), "{}", c.detail);

        let mut owner = FakeOwner {
            agents: Some(vec![("assistant".to_owned(), None)]),
            ..Default::default()
        };
        let c = check_agents(&mut owner, Some(&agents));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("kharon-agent-connector"), "{}", c.detail);

        // A pre-#406 daemon: no agents field at all.
        let mut owner = FakeOwner {
            agents: None,
            ..Default::default()
        };
        let c = check_agents(&mut owner, Some(&agents));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("does not report"), "{}", c.detail);

        // Daemon down.
        let mut owner = FakeOwner {
            down: true,
            ..Default::default()
        };
        let c = check_agents(&mut owner, Some(&agents));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("start kharond"), "{}", c.detail);
    }

    #[test]
    fn req_406_agents_skips() {
        let mut owner = FakeOwner {
            down: true,
            ..Default::default()
        };
        // Config unknown.
        assert_eq!(check_agents(&mut owner, None).verdict, Verdict::Skip);
        // No connector-transport agents.
        assert_eq!(check_agents(&mut owner, Some(&[])).verdict, Verdict::Skip);
    }

    // ---- the whole pass ----

    const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";

    fn args(config: &Path) -> DoctorArgs {
        DoctorArgs {
            config: Some(config.to_path_buf()),
            socket: None,
            key_file: None,
        }
    }

    #[test]
    fn req_406_run_reports_each_check_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.json");
        std::fs::write(&key, USER_KEY).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
        let config = dir.path().join("kharon.toml");
        std::fs::write(
            &config,
            format!(
                "data_dir = {:?}\n\
                 [bitwarden]\n\
                 server = \"https://vault.example.net\"\n\
                 email = \"kharon@example.net\"\n\
                 api_key_file = {:?}\n\
                 organization_id = \"{ORG}\"\n\
                 collection_ids = [\"{COLL}\"]\n\
                 [agents.assistant]\n\
                 token_hash = \"{TOKEN_HASH}\"\n\
                 cdp = {{ endpoint = \"ws://10.66.0.2:9222\", via = \"wireguard\" }}\n\
                 [approval]\n\
                 ntfy = {{ url = \"https://ntfy.example.net\", topic = \"kharon-doctor-test\" }}\n",
                dir.path(),
                key,
            ),
        )
        .unwrap();
        // Not group-writable, whatever the process umask is.
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640)).unwrap();
        let files = LiveFiles;
        let mut vault = RefusingVault;
        let (checks, failed) = run(&args(&config), &files, &mut vault, &mut |_| {
            Box::new(FakeOwner {
                down: true,
                ..Default::default()
            }) as Box<dyn OwnerChannel>
        });
        assert_eq!(checks.len(), 6);
        let verdicts: Vec<Verdict> = checks.iter().map(|c| c.verdict).collect();
        // Files pass (real temp files, key 0400), key type passes,
        // sync fails (refusing vault), audit passes (ntfy sink),
        // passkey skips (no [owner_ui]), agents skip (wireguard).
        assert_eq!(
            verdicts,
            [
                Verdict::Pass,
                Verdict::Pass,
                Verdict::Fail,
                Verdict::Pass,
                Verdict::Skip,
                Verdict::Skip
            ]
        );
        assert!(failed);
        for c in &checks {
            assert!(!c.detail.contains("DOCTOR-SECRET-CANARY"), "{}", c.detail);
        }
    }

    #[test]
    fn req_406_run_with_a_missing_config_fails_check_one_and_skips() {
        let files = LiveFiles;
        let mut vault = RefusingVault;
        let (checks, failed) = run(
            &args(Path::new("/nonexistent/kharon.toml")),
            &files,
            &mut vault,
            &mut |_| {
                Box::new(FakeOwner {
                    down: true,
                    ..Default::default()
                }) as Box<dyn OwnerChannel>
            },
        );
        assert_eq!(checks.len(), 6);
        assert_eq!(checks[0].verdict, Verdict::Fail);
        assert_eq!(checks[1].verdict, Verdict::Skip);
        assert_eq!(checks[2].verdict, Verdict::Skip);
        assert_eq!(checks[3].verdict, Verdict::Skip);
        // The daemon is down, so the passkey check fails on its own
        // feet even with the config unknown.
        assert_eq!(checks[4].verdict, Verdict::Fail);
        assert_eq!(checks[5].verdict, Verdict::Skip);
        assert!(failed);
    }
}
