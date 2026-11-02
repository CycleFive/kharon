//! Serde-facing raw config and its conversion to the validated [`Config`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use url::Url;

use super::{
    AgentConfig, ApprovalConfig, AuditConfig, BitwardenConfig, Config, ConfigError, ExportConfig,
    FORBIDDEN_SECRET_KEYS, GrantKind, MemoryConfig, NtfyConfig, PolicyConfig, Redacted, Source,
    parse_duration, tunnel_from_config,
};
use crate::cdp::{CdpEndpoint, CertSha256};

#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Mode {
    #[default]
    Sync,
    Export,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Export => "export",
        }
    }
}

// No `Debug` on raw structs: they hold unvalidated input, including
// `token_hash`. Only the validated, redacting types are `Debug`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    mode: Mode,
    bitwarden: Option<RawBitwarden>,
    export: Option<RawExport>,
    #[serde(default)]
    agents: BTreeMap<String, RawAgent>,
    #[serde(default)]
    policy: RawPolicy,
    #[serde(default)]
    approval: RawApproval,
    #[serde(default)]
    audit: RawAudit,
    #[serde(default)]
    memory: RawMemory,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBitwarden {
    server: String,
    email: String,
    api_key_file: PathBuf,
    organization_id: String,
    collection_ids: Vec<String>,
    #[serde(default)]
    allow_extra_orgs: bool,
    #[serde(default)]
    ca_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExport {
    file: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAgent {
    token_hash: String,
    cdp: RawCdp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCdp {
    endpoint: String,
    #[serde(default = "default_via")]
    via: String,
    peer_cert_sha256: Option<String>,
}

fn default_via() -> String {
    // Fail-closed default: `direct` allows plain ws only on loopback.
    "direct".to_owned()
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    idle_lock: Option<String>,
    max_unlocked: Option<String>,
    default_grant: Option<GrantKind>,
    #[serde(default)]
    allow_standing: bool,
    fill_deadline: Option<String>,
    #[serde(default)]
    allow_http: bool,
    #[serde(default)]
    allow_cross_origin_iframe_hosts: Vec<String>,
    #[serde(default)]
    allow_default_context: bool,
    clock_skew_warn: Option<String>,
    clock_skew_refuse: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawApproval {
    ntfy: Option<RawNtfy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNtfy {
    url: String,
    topic: String,
    token_file: Option<PathBuf>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawAudit {
    #[serde(default)]
    checkpoint_local_only: bool,
    #[serde(default)]
    item_names: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMemory {
    #[serde(default = "default_true")]
    require_mlock: bool,
}

impl Default for RawMemory {
    fn default() -> Self {
        Self {
            require_mlock: true,
        }
    }
}

fn default_true() -> bool {
    true
}

pub(super) fn parse(text: &str) -> Result<Config, ConfigError> {
    // Untyped pass first so secret-shaped keys are refused by name
    // before serde can echo their values in a type error.
    let table: toml::Table = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
    scan_secret_keys(&table, "")?;
    let raw: RawConfig = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
    validate(raw)
}

fn parse_error(text: &str, e: &toml::de::Error) -> ConfigError {
    let (line, column) = match e.span() {
        Some(span) => {
            let before = &text[..span.start.min(text.len())];
            let line = before.matches('\n').count() + 1;
            let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
            (line, column)
        }
        None => (0, 0),
    };
    ConfigError::Parse {
        line,
        column,
        message: redact_quoted(e.message()),
    }
}

/// Replace the contents of every `"…"` literal in a parser message.
/// serde renders offending string values that way ("invalid type:
/// string \"…\""); field names use backticks and survive.
fn redact_quoted(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut in_quote = false;
    for c in msg.chars() {
        if c == '"' {
            if in_quote {
                out.push_str("<redacted>\"");
            } else {
                out.push('"');
            }
            in_quote = !in_quote;
        } else if !in_quote {
            out.push(c);
        }
    }
    out
}

fn scan_secret_keys(table: &toml::Table, prefix: &str) -> Result<(), ConfigError> {
    for (k, v) in table {
        let path = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        let lower = k.to_ascii_lowercase();
        if FORBIDDEN_SECRET_KEYS.contains(&lower.as_str()) {
            return Err(ConfigError::SecretInConfig { key: path });
        }
        scan_value(v, &path)?;
    }
    Ok(())
}

fn scan_value(v: &toml::Value, path: &str) -> Result<(), ConfigError> {
    match v {
        toml::Value::Table(t) => scan_secret_keys(t, path),
        toml::Value::Array(items) => items.iter().try_for_each(|i| scan_value(i, path)),
        _ => Ok(()),
    }
}

fn validate(raw: RawConfig) -> Result<Config, ConfigError> {
    let source = match raw.mode {
        Mode::Sync => {
            if raw.export.is_some() {
                return Err(ConfigError::SectionNotAllowedInMode {
                    section: "export",
                    mode: raw.mode.name(),
                });
            }
            let bw = raw.bitwarden.ok_or(ConfigError::MissingSection {
                section: "bitwarden",
            })?;
            Source::Sync(validate_bitwarden(bw)?)
        }
        Mode::Export => {
            if raw.bitwarden.is_some() {
                return Err(ConfigError::SectionNotAllowedInMode {
                    section: "bitwarden",
                    mode: raw.mode.name(),
                });
            }
            let ex = raw
                .export
                .ok_or(ConfigError::MissingSection { section: "export" })?;
            Source::Export(ExportConfig { file: ex.file })
        }
    };

    if raw.agents.is_empty() {
        return Err(ConfigError::NoAgents);
    }
    let mut agents = BTreeMap::new();
    for (id, a) in raw.agents {
        let agent = validate_agent(&id, a)?;
        agents.insert(id, agent);
    }

    let policy = validate_policy(raw.policy)?;
    if policy.allow_default_context && agents.len() > 1 {
        return Err(ConfigError::DefaultContextMultiAgent);
    }

    let approval = ApprovalConfig {
        ntfy: raw.approval.ntfy.map(validate_ntfy).transpose()?,
    };
    let audit = AuditConfig {
        checkpoint_local_only: raw.audit.checkpoint_local_only,
        item_names: raw.audit.item_names,
    };
    if !audit.checkpoint_local_only && approval.ntfy.is_none() {
        return Err(ConfigError::AuditNoOffHostSink);
    }

    Ok(Config {
        source,
        agents,
        policy,
        approval,
        audit,
        memory: MemoryConfig {
            require_mlock: raw.memory.require_mlock,
        },
    })
}

fn http_url(key: &str, s: &str) -> Result<Url, ConfigError> {
    let invalid = || ConfigError::InvalidUrl {
        key: key.to_owned(),
    };
    let url = Url::parse(s).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(invalid());
    }
    Ok(url)
}

/// 8-4-4-4-12 hex, any case (Bitwarden IDs are lowercase UUIDs).
fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn validate_bitwarden(bw: RawBitwarden) -> Result<BitwardenConfig, ConfigError> {
    let server = http_url("bitwarden.server", &bw.server)?;
    let email_ok = bw
        .email
        .split_once('@')
        .is_some_and(|(l, d)| !l.is_empty() && !d.is_empty() && !d.contains('@'));
    if !email_ok {
        return Err(ConfigError::InvalidEmail);
    }
    if !is_uuid(&bw.organization_id) {
        return Err(ConfigError::InvalidUuid {
            key: "bitwarden.organization_id".to_owned(),
        });
    }
    if bw.collection_ids.is_empty() {
        return Err(ConfigError::NoCollections);
    }
    for (i, c) in bw.collection_ids.iter().enumerate() {
        if !is_uuid(c) {
            return Err(ConfigError::InvalidUuid {
                key: format!("bitwarden.collection_ids[{i}]"),
            });
        }
    }
    Ok(BitwardenConfig {
        server,
        email: bw.email,
        api_key_file: bw.api_key_file,
        organization_id: bw.organization_id.to_ascii_lowercase(),
        collection_ids: bw
            .collection_ids
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect(),
        allow_extra_orgs: bw.allow_extra_orgs,
        ca_file: bw.ca_file,
    })
}

fn validate_agent(id: &str, a: RawAgent) -> Result<AgentConfig, ConfigError> {
    let id_ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !id_ok {
        return Err(ConfigError::InvalidAgentId { id: id.to_owned() });
    }
    if !a.token_hash.starts_with("$argon2id$") {
        return Err(ConfigError::TokenHashNotArgon2id {
            agent: id.to_owned(),
        });
    }
    let via = tunnel_from_config(id, &a.cdp.via)?;
    let pin = a
        .cdp
        .peer_cert_sha256
        .as_deref()
        .map(|h| parse_pin(id, h))
        .transpose()?;
    let cdp =
        CdpEndpoint::validate(&a.cdp.endpoint, via, pin).map_err(|source| ConfigError::Cdp {
            agent: id.to_owned(),
            source,
        })?;
    Ok(AgentConfig {
        token_hash: Redacted::new(a.token_hash),
        cdp,
    })
}

fn parse_pin(agent: &str, h: &str) -> Result<CertSha256, ConfigError> {
    let bad = || ConfigError::InvalidPeerPin {
        agent: agent.to_owned(),
    };
    let bytes = hex::decode(h.trim()).map_err(|_| bad())?;
    bytes.try_into().map_err(|_| bad())
}

fn duration(key: &str, v: Option<String>, default: Duration) -> Result<Duration, ConfigError> {
    let d = match v {
        None => default,
        Some(s) => parse_duration(&s).ok_or_else(|| ConfigError::InvalidDuration {
            key: key.to_owned(),
        })?,
    };
    if d.is_zero() {
        return Err(ConfigError::ZeroDuration {
            key: key.to_owned(),
        });
    }
    Ok(d)
}

fn validate_policy(p: RawPolicy) -> Result<PolicyConfig, ConfigError> {
    let d = PolicyConfig::default();
    let policy = PolicyConfig {
        idle_lock: duration("policy.idle_lock", p.idle_lock, d.idle_lock)?,
        max_unlocked: duration("policy.max_unlocked", p.max_unlocked, d.max_unlocked)?,
        default_grant: p.default_grant.unwrap_or(d.default_grant),
        allow_standing: p.allow_standing,
        fill_deadline: duration("policy.fill_deadline", p.fill_deadline, d.fill_deadline)?,
        allow_http: p.allow_http,
        allow_cross_origin_iframe_hosts: p.allow_cross_origin_iframe_hosts,
        allow_default_context: p.allow_default_context,
        clock_skew_warn: duration(
            "policy.clock_skew_warn",
            p.clock_skew_warn,
            d.clock_skew_warn,
        )?,
        clock_skew_refuse: duration(
            "policy.clock_skew_refuse",
            p.clock_skew_refuse,
            d.clock_skew_refuse,
        )?,
    };
    if policy.default_grant == GrantKind::Standing && !policy.allow_standing {
        return Err(ConfigError::StandingGrantsDisabled);
    }
    if policy.clock_skew_warn > policy.clock_skew_refuse {
        return Err(ConfigError::ClockSkewThresholdsInverted);
    }
    Ok(policy)
}

fn validate_ntfy(n: RawNtfy) -> Result<NtfyConfig, ConfigError> {
    Ok(NtfyConfig {
        url: http_url("approval.ntfy.url", &n.url)?,
        topic: n.topic,
        token_file: n.token_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_dep_003_parse_messages_redact_string_values() {
        assert_eq!(
            redact_quoted("invalid type: string \"hunter2\", expected a boolean"),
            "invalid type: string \"<redacted>\", expected a boolean"
        );
        assert_eq!(redact_quoted("unknown field `x`"), "unknown field `x`");
    }

    #[test]
    fn req_dep_003_uuid_shape() {
        assert!(is_uuid("0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6"));
        assert!(!is_uuid("0f3c2a6e1b2c4d5e8f90a1b2c3d4e5f6"));
        assert!(!is_uuid("0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5fg"));
        assert!(!is_uuid("uuid"));
    }
}
