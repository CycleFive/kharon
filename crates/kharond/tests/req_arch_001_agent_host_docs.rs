//! REQ-ARCH-001 (issue #24): no kharon binary or secret-bearing config
//! on the agent host. AC: "The deployment guide's agent-host steps
//! install only Chromium flags and tunnel config. CI checks the docs."
//!
//! The agent-host steps are `deploy/agent-host/provision.sh`, which
//! the guide (`docs/deployment.md`, "Agent host") tells the owner to
//! run. This checks that the script:
//!
//! - installs only Chromium, its fonts, WireGuard and the relay;
//! - writes files (all through its `put_file`) only as Chromium
//!   policy, WireGuard config, a sysctl or a systemd unit, and has no
//!   other way to write, copy or fetch a file;
//! - starts only Chromium and the relay;
//! - names nothing of kharon's or the vault's outside comments;
//!
//! and that the guide's agent-host section points at the script,
//! lists every file it writes, and has no command that installs or
//! configures kharon. The script itself runs in a VM in
//! `agent-host.yml` (REQ-DEP-005).
//!
//! Each check is also run against a bad input, so a checker that
//! accepts everything fails here too.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Packages the agent host may install.
const ALLOWED_PACKAGES: &[&str] = &["chromium", "fonts-liberation", "wireguard-tools", "socat"];
/// Where the script may write files: Chromium flags (policy and its
/// unit), tunnel config (WireGuard and the relay unit), and the
/// ptrace sysctl.
const ALLOWED_FILE_PREFIXES: &[&str] = &[
    "/etc/chromium/policies/managed/",
    "/etc/wireguard/",
    "/etc/sysctl.d/",
    "/etc/systemd/system/",
];
/// Programs a unit may start.
const ALLOWED_EXEC: &[&str] = &["/usr/bin/chromium", "/usr/bin/socat"];
/// Words that must not appear in the script's code or the guide's
/// agent-host commands: kharon's binaries and config, the vault, and
/// ways to ship either.
const FORBIDDEN: &[&str] = &[
    "kharon",
    "bitwarden",
    "vaultwarden",
    "api_key",
    "/run/secrets",
    "docker",
    "cargo",
];
/// Commands that would write, copy or fetch a file around `put_file`.
const FORBIDDEN_COMMANDS: &[&str] = &[
    "tee", "cp", "mv", "ln", "dd", "curl", "wget", "rsync", "scp", "git",
];

fn repo_file(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The script's lines that are not comments, with `\` continuations
/// joined.
fn code_lines(script: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in script.lines() {
        let t = line.trim();
        if cur.is_empty() && t.starts_with('#') {
            continue;
        }
        if let Some(head) = t.strip_suffix('\\') {
            cur.push_str(head);
            cur.push(' ');
        } else {
            cur.push_str(t);
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Every problem with the script, empty when it passes.
fn script_problems(script: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let lines = code_lines(script);
    let mut packages = BTreeSet::new();
    let mut in_put_file_def = false;

    for line in &lines {
        let lower = line.to_lowercase();
        for word in FORBIDDEN {
            if lower.contains(word) {
                problems.push(format!("names {word:?}: {line}"));
            }
        }
        if line.starts_with("put_file()") {
            in_put_file_def = true;
            continue;
        }
        if in_put_file_def {
            if line == "}" {
                in_put_file_def = false;
            }
            continue;
        }
        let words: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || "|;&()".contains(c))
            .filter(|w| !w.is_empty())
            .collect();
        for cmd in FORBIDDEN_COMMANDS {
            if words.first() == Some(cmd) || line.contains(&format!("| {cmd} ")) {
                problems.push(format!("runs {cmd}: {line}"));
            }
        }
        if let Some(pos) = words.iter().position(|w| *w == "put_file") {
            match words.get(pos + 1) {
                Some(path)
                    if ALLOWED_FILE_PREFIXES
                        .iter()
                        .any(|p| path.starts_with(p) && !path.contains("..")) => {}
                other => problems.push(format!("writes {other:?}: {line}")),
            }
        }
        if words.first() == Some(&"install")
            && !(words.contains(&"-d") && words.last() == Some(&"/var/lib/browser"))
        {
            problems.push(format!("install outside put_file: {line}"));
        }
        // Redirections to a file other than /dev/null.
        for (i, _) in line.match_indices('>') {
            let rest = line[i + 1..].trim_start_matches('>').trim_start();
            if rest.starts_with('&') {
                continue;
            }
            if rest.starts_with('/') && !rest.starts_with("/dev/null") {
                problems.push(format!("redirects to a file: {line}"));
            }
        }
        if let Some(pos) = words.iter().position(|w| *w == "apt-get")
            && words.get(pos + 1) == Some(&"install")
        {
            packages.extend(
                words[pos + 2..]
                    .iter()
                    .filter(|w| !w.starts_with('-'))
                    .map(|w| (*w).to_owned()),
            );
        }
        if let Some(exec) = line.strip_prefix("ExecStart=") {
            let prog = exec.split_whitespace().next().unwrap_or("");
            if !ALLOWED_EXEC.contains(&prog) {
                problems.push(format!("unit starts {prog:?}"));
            }
        }
    }
    for pkg in &packages {
        if !ALLOWED_PACKAGES.contains(&pkg.as_str()) {
            problems.push(format!("installs package {pkg:?}"));
        }
    }
    if packages.is_empty() {
        problems.push("installs no packages: the parser missed apt-get".to_owned());
    }
    problems
}

/// The paths the script writes with `put_file`.
fn put_file_paths(script: &str) -> Vec<String> {
    code_lines(script)
        .iter()
        .filter_map(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            let pos = words.iter().position(|w| *w == "put_file")?;
            words.get(pos + 1).map(|p| (*p).to_owned())
        })
        .filter(|p| p.starts_with('/'))
        .collect()
}

/// The guide's "## Agent host" section, up to the next `## ` heading.
fn agent_host_section(guide: &str) -> Option<&str> {
    let start = guide.find("\n## Agent host")? + 1;
    let rest = &guide[start + 3..];
    let end = rest.find("\n## ").map_or(guide.len(), |e| start + 3 + e);
    Some(&guide[start..end])
}

/// The fenced code blocks in `text`.
fn code_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            match cur.take() {
                Some(b) => blocks.push(b),
                None => cur = Some(String::new()),
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(line);
            b.push('\n');
        }
    }
    blocks
}

/// Names the path (B) guide and script may use for the connector binary
/// and its config directory. Stripped before the "no kharon" scan so the
/// connector is allowed and a vault binary still is not (REQ-ARCH-001).
fn scrub_connector_names(text: &str) -> String {
    text.replace("kharon-agent-connector", "")
        .replace("provision-connector.sh", "")
        .replace("/etc/kharon-connector", "")
        .replace("/var/lib/kharon-connector", "")
        .replace("kharon-connector", "")
}

fn guide_problems(guide: &str, script: &str) -> Vec<String> {
    let Some(section) = agent_host_section(guide) else {
        return vec!["the guide has no \"## Agent host\" section".to_owned()];
    };
    let mut problems = Vec::new();
    if !section.contains("deploy/agent-host/provision.sh") {
        problems.push("the agent-host section does not link provision.sh".to_owned());
    }
    for path in put_file_paths(script) {
        let name = path.rsplit('/').next().unwrap_or(&path);
        if !section.contains(name) {
            problems.push(format!("the agent-host section does not list {path}"));
        }
    }
    for block in code_blocks(section) {
        let lower = scrub_connector_names(&block).to_lowercase();
        for word in FORBIDDEN {
            if lower.contains(word) {
                problems.push(format!("an agent-host command names {word:?}: {block}"));
            }
        }
    }
    problems
}

const CONNECTOR_PACKAGES: &[&str] = &["chromium", "fonts-liberation"];
const CONNECTOR_FILE_PREFIXES: &[&str] = &[
    "/etc/chromium/policies/managed/",
    "/etc/sysctl.d/",
    "/etc/systemd/system/",
    "/etc/kharon-connector/",
];
const CONNECTOR_EXEC: &[&str] = &["/usr/bin/chromium", "/usr/local/bin/kharon-agent-connector"];
const CONNECTOR_INSTALL: &[&str] = &[
    "/var/lib/browser",
    "/var/lib/kharon-connector",
    "/etc/kharon-connector",
    "/usr/local/bin/kharon-agent-connector",
    "/etc/kharon-connector/token",
];
/// After connector names are stripped, path (B) code must not name these.
const CONNECTOR_FORBIDDEN: &[&str] = &[
    "kharon",
    "kharond",
    "bitwarden",
    "vaultwarden",
    "api_key",
    "kh_agent_",
    "token_hash",
    "wireguard",
    "wg0",
    "socat",
    "cargo",
    "docker",
    "curl",
    "wget",
    "51820",
];

fn connector_script_problems(script: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let lines = code_lines(script);
    let mut packages = BTreeSet::new();
    let mut in_put_file_def = false;
    for line in &lines {
        let scrubbed = scrub_connector_names(line).to_lowercase();
        for word in CONNECTOR_FORBIDDEN {
            if scrubbed.contains(word) {
                problems.push(format!("names {word:?}: {line}"));
            }
        }
        if line.starts_with("put_file()") {
            in_put_file_def = true;
            continue;
        }
        if in_put_file_def {
            if line == "}" {
                in_put_file_def = false;
            }
            continue;
        }
        let words: Vec<&str> = line
            .split(|c: char| c.is_whitespace() || "|;&()".contains(c))
            .filter(|w| !w.is_empty())
            .collect();
        for cmd in FORBIDDEN_COMMANDS {
            if words.first() == Some(cmd) || line.contains(&format!("| {cmd} ")) {
                problems.push(format!("runs {cmd}: {line}"));
            }
        }
        if let Some(pos) = words.iter().position(|w| *w == "put_file") {
            match words.get(pos + 1) {
                Some(path)
                    if CONNECTOR_FILE_PREFIXES
                        .iter()
                        .any(|p| path.starts_with(p) && !path.contains("..")) => {}
                other => problems.push(format!("writes {other:?}: {line}")),
            }
        }
        if words.first() == Some(&"install") {
            let dest = words.iter().rev().find(|w| w.starts_with('/'));
            match dest {
                Some(path) if CONNECTOR_INSTALL.contains(path) => {}
                other => problems.push(format!("installs {other:?}: {line}")),
            }
        }
        if let Some(pos) = words.iter().position(|w| *w == "apt-get")
            && words.get(pos + 1) == Some(&"install")
        {
            packages.extend(
                words[pos + 2..]
                    .iter()
                    .filter(|w| !w.starts_with('-'))
                    .map(|w| (*w).to_owned()),
            );
        }
        if let Some(exec) = line.strip_prefix("ExecStart=") {
            let prog = exec.split_whitespace().next().unwrap_or("");
            if !CONNECTOR_EXEC.contains(&prog) {
                problems.push(format!("unit starts {prog:?}"));
            }
        }
    }
    for pkg in &packages {
        if !CONNECTOR_PACKAGES.contains(&pkg.as_str()) {
            problems.push(format!("installs package {pkg:?}"));
        }
    }
    if packages.is_empty() {
        problems.push("installs no packages".to_owned());
    }
    if !script.contains("127.0.0.1") {
        problems.push("does not bind CDP to loopback".to_owned());
    }
    problems
}

fn connector_guide_problems(guide: &str, script: &str) -> Vec<String> {
    let Some(section) = agent_host_section(guide) else {
        return vec!["the guide has no \"## Agent host\" section".to_owned()];
    };
    let mut problems = Vec::new();
    if !section.contains("deploy/agent-host/provision-connector.sh") {
        problems.push("the agent-host section does not link provision-connector.sh".to_owned());
    }
    if !section.contains("No `wg0`") && !section.contains("No WireGuard") {
        problems.push("path B does not say there is no WireGuard".to_owned());
    }
    for path in put_file_paths(script) {
        let name = path.rsplit('/').next().unwrap_or(&path);
        if !section.contains(name) {
            problems.push(format!("the agent-host section does not list {path}"));
        }
    }
    problems
}

#[test]
fn req_arch_001_provision_script_installs_only_chromium_and_tunnel_config() {
    let script = repo_file("deploy/agent-host/provision.sh");
    let problems = script_problems(&script);
    assert!(problems.is_empty(), "{problems:#?}");
    let written = put_file_paths(&script);
    assert!(written.len() >= 5, "put_file targets: {written:?}");
}

#[test]
fn req_arch_001_guide_agent_host_steps_match_the_script() {
    let guide = repo_file("docs/deployment.md");
    let script = repo_file("deploy/agent-host/provision.sh");
    let problems = guide_problems(&guide, &script);
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn req_arch_001_connector_script_installs_only_chromium_and_tunnel_config() {
    let script = repo_file("deploy/agent-host/provision-connector.sh");
    let problems = connector_script_problems(&script);
    assert!(problems.is_empty(), "{problems:#?}");
    let guide = repo_file("docs/deployment.md");
    let guide_problems = connector_guide_problems(&guide, &script);
    assert!(guide_problems.is_empty(), "{guide_problems:#?}");
}

#[test]
fn req_arch_001_connector_checker_rejects_vault_material_and_wireguard() {
    let good = repo_file("deploy/agent-host/provision-connector.sh");
    let bad_scripts = [
        good.replace(
            "chromium fonts-liberation",
            "chromium fonts-liberation wireguard-tools",
        ),
        good.replace(
            "/usr/local/bin/kharon-agent-connector",
            "/usr/local/bin/kharond",
        ),
        format!("{good}\ncurl -o /tmp/x https://example.net/x\n"),
        good.replace(
            "ExecStart=/usr/local/bin/kharon-agent-connector",
            "ExecStart=/usr/bin/wg-quick",
        ),
        format!("{good}\nprintf 'token_hash = \"x\"\\n'\n"),
    ];
    for (i, bad) in bad_scripts.iter().enumerate() {
        assert_ne!(bad, &good, "bad script {i} did not change the script");
        assert!(
            !connector_script_problems(bad).is_empty(),
            "bad script {i} passed the checker"
        );
    }
}

#[test]
fn req_arch_001_compose_example_links_the_guide() {
    let readme = repo_file("deploy/compose/README.md");
    assert!(readme.contains("docs/deployment.md"), "{readme}");
}

#[test]
fn req_arch_001_checker_rejects_kharon_on_the_agent_host() {
    let good = repo_file("deploy/agent-host/provision.sh");
    let bad_scripts = [
        // A kharon binary.
        good.replace(
            "chromium fonts-liberation",
            "chromium kharond fonts-liberation",
        ),
        // Some other package.
        good.replace("wireguard-tools socat", "wireguard-tools socat nodejs"),
        // kharon config through put_file.
        good.replace(
            "put_file /etc/sysctl.d/60-ptrace-scope.conf",
            "put_file /etc/agent/broker.toml",
        ),
        // A file written around put_file.
        format!("{good}\necho secret > /etc/agent.conf\n"),
        format!("{good}\nprintf x | tee /etc/agent.conf\n"),
        format!("{good}\ncurl -o /usr/local/bin/x https://example.net/x\n"),
        // A unit starting something else.
        good.replace("ExecStart=/usr/bin/socat", "ExecStart=/usr/local/bin/relay"),
    ];
    for (i, bad) in bad_scripts.iter().enumerate() {
        assert_ne!(bad, &good, "bad script {i} did not change the script");
        assert!(
            !script_problems(bad).is_empty(),
            "bad script {i} passed the checker"
        );
    }

    let guide = repo_file("docs/deployment.md");
    let section = agent_host_section(&guide).unwrap();
    let bad_guide = guide.replace(
        section,
        &format!("{section}\n```sh\ndocker run kharon\n```\n"),
    );
    assert!(!guide_problems(&bad_guide, &good).is_empty());
    let unlisted = guide.replace("no-password-manager.json", "the policy file");
    assert!(!guide_problems(&unlisted, &good).is_empty());
}
