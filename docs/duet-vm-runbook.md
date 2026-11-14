# Duet kharon VM: setup runbook

> Point-in-time research record from Claude Duet, Nov 14, 2026. Check claims against current code and the linked sources before relying on them.

Nov 14, 2026.

Ten steps take a new Proxmox VM to a box where Duet fills logins through kharon. It runs as a static agent (duet below), with Claude Code under Remote Control as Duet's hands on the box. Steps 1 and 2 happen on the broker and a build machine; the rest happen on the VM. Nothing here is posted anywhere, and no secret goes in chat, Discord, argv or this doc.

Tags: **\[repo\]** = from CycleFive/kharon at v0.3.0 (30ecd56). **\[docs\]** = from Claude Code's docs, read today. **\[inferred\]** = my judgment, untested.

## 0. The VM

| Setting | Value |
| --- | --- |
| Guest | Debian 13 netinst, a full VM, not an LXC (ptrace\_scope and Chromium's sandbox need it) \[repo\] |
| Size | 2 vCPU, 8 GB RAM, 32 GB disk. Claude Code wants 4 GB or more on its own \[docs\], and Chromium takes the rest \[inferred\] |
| Extras | qemu-guest-agent, systemd-timesyncd on, unattended-upgrades \[inferred\] |
| Network | Outbound only. HTTPS to kharon.twkr.io, api.anthropic.com, claude.ai, platform.claude.com, downloads.claude.ai, the Debian mirrors, and the sites being signed in to. No inbound ports, no tailnet needed \[repo\] \[docs\] |

## 1. Broker side (you, on the broker host)

Mint both credentials in an interactive terminal; each prints the secret once to the terminal and the hash to stdout. \[repo\]

```sh
kharon token mint duet  > duet.token_hash      # agent token kh_agent_duet_… stays on screen
kharon tunnel mint duet > duet.tunnel_hash     # tunnel credential kh_tunnel_… stays on screen
openssl x509 -in /etc/kharon/tls.crt -outform DER | sha256sum   # broker_pin, from the [connector] cert
```

Add the agent to kharon.toml and restart kharond. \[repo\]

```toml
[agents.duet]
token_hash = "<contents of duet.token_hash>"
connector_token_hash = "<contents of duet.tunnel_hash>"
cdp = { endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }
```

A restart probably means unlocking the broker again in the owner UI. \[inferred\]

## 2. Build the connector (any machine with the repo)

```sh
git checkout v0.3.0        # or master at 30ecd56 or later, which has #321
cargo build --release -p kharon-agent-connector
```

The binary is target/release/kharon-agent-connector. It holds no secret, so scp is fine. \[repo\]

## 3. Provision Chromium and the connector (VM, as root)

Put the tunnel credential in a file at a hidden prompt, so it never touches argv, history or an editor. \[repo\] agent-runtime-setup.md

```sh
( umask 077; IFS= read -rs T; printf '%s' "$T" > /root/tunnel.token; unset T )
sudo CONNECTOR_BIN=./kharon-agent-connector \
  BROKER_URL=wss://kharon.twkr.io/connector \
  BROKER_PIN=<64 hex from step 1> \
  AGENT_ID=duet \
  TUNNEL_TOKEN_FILE=/root/tunnel.token \
  ./provision-connector.sh
shred -u /root/tunnel.token
```

The script installs chromium and fonts-liberation, creates the browser and connector users, sets ptrace\_scope = 1, writes the no-password-manager policy, installs the token at /etc/kharon-connector/token (0400, connector), and starts browser.service and kharon-agent-connector.service. \[repo\] Confirm broker\_pin's first and last 8 hex digits against the owner UI or a second channel. \[repo\]

## 4. Check the connector

```sh
sudo systemctl stop kharon-agent-connector
sudo -u connector kharon-agent-connector --config /etc/kharon-connector/connector.toml --check   # expect: check: ok
sudo systemctl start kharon-agent-connector
journalctl -u kharon-agent-connector -f     # expect: authenticated
```

On the broker, kharond logs `agent connector attached: agent=duet transport=ws`. Never run --check while the service is up: it takes over the live session. \[repo\]

## 5. The agent user

```sh
sudo useradd -m -s /bin/bash duet     # not in browser or connector, no sudo
sudo loginctl enable-linger duet
```

The agent must not be root, browser or connector, or the isolation is gone. \[repo\] Claude Code with a shell can still run JS in pages and read filled values over CDP, so the harness policy is not enforced on this path. That is acceptable for the soak with throwaway accounts. \[inferred\]

## 6. Claude Code (as duet)

```sh
curl -fsSL https://claude.ai/install.sh | bash     # native installer, auto-updates [docs]
claude                                            # press c to copy the login URL, sign in on another device, paste the code [docs]
```

Remote Control needs a claude.ai login on Pro, Max, Team or Enterprise. A long-lived setup-token cannot start Remote Control. \[docs\] Renew with /login when the expiry warning shows, or the session stops working. \[docs\]

## 7. kharon's MCP tools for Claude Code (as duet)

Put the agent token in an env file at a hidden prompt, and reference it from the project's .mcp.json so the token is never in a config Claude reads. \[docs\] \[repo\]

```sh
mkdir -p ~/kharon-work && cd ~/kharon-work
( umask 077; IFS= read -rs T; printf 'KHARON_AGENT_TOKEN=%s\n' "$T" > ~/.kharon.env; unset T )
```

```json
{
  "mcpServers": {
    "kharon": {
      "type": "http",
      "url": "https://kharon.twkr.io/mcp",
      "headers": { "Authorization": "Bearer ${KHARON_AGENT_TOKEN}" }
    }
  }
}
```

That goes in \~/kharon-work/.mcp.json. Use a variable name of your own: ANTHROPIC\_-style names read as empty in MCP headers. \[docs\]

## 8. Driving the browser

Chromium's CDP is on 127.0.0.1:9222, which the duet user can reach. The agent calls kharon\_context for its browser\_context\_id, opens tabs in that context with Target.createTarget, and passes the tab's target id to kharon\_fill. \[repo\] Playwright's connectOverCDP may not open pages in a context kharond created, so a small CDP helper script that does Target.createTarget with browserContextId is the safer route. \[inferred, test first\]

## 9. Remote Control (as duet, in \~/kharon-work)

```sh
set -a; . ~/.kharon.env; set +a
tmux new -s duet
claude remote-control --name kharon-duet --permission-mode default
```

Answer y to Enable Remote Control and to trusting the directory on the first run; it fails without a terminal otherwise. \[docs\] Server mode takes several sessions at once and exits after about 10 minutes without network, so it needs a restart wrapper. \[docs\] The docs give no systemd unit; a user unit that starts it in tmux is my suggestion, untested. \[inferred\]

## 10. Smoke test

1. In the Claude app, open the kharon-duet Remote Control session.
2. kharon\_status shows agent duet and whether the broker is unlocked.
3. kharon\_context returns a browser\_context\_id.
4. Open the login.page canary tab in that context, then kharon\_fill against the canary item. Approve the grant in the owner UI.
5. The page's length report matches the canary values (8 and 29 in #322).
6. Stop kharon-agent-connector: kharon\_fill now refuses with no browser attached. Start it again.

## Open items

- [ ] Agent id: duet, unless you want another name.
- [ ] Whether Claude Duet can hand kharon work straight to this Remote Control session, or you open it from the app each time. \[inferred: the project can list Remote Control sessions, but I haven't tested starting one\]
- [ ] Whether Claude Code's requests to /mcp pass the twkr.io bot rule that blocked a default Python client in #322.
- [ ] The CDP helper in step 8: confirm it can open tabs in kharond's context before the soak.

## Sources

kharon at v0.3.0: docs/deployment.md, docs/agent-runtime-setup.md, docs/api/mcp-tools.json, deploy/agent-host/provision-connector.sh, issue #322. Claude Code docs: setup, authentication, remote-control, mcp, network-config and permission-modes pages, read today.
