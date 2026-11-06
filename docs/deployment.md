# Deploying kharon

kharon runs on two machines (SPEC §3.3, option (a)):

- **Broker host.** Your hardware. It runs kharond and, if you
  self-host, Vaultwarden. It holds the vault credentials and the
  decrypted items while unlocked.
- **Agent host.** Where the agent and its Chromium run. It is
  partially trusted (SPEC §2): the agent may be curious or
  compromised, but root on this host is not. It holds no kharon
  binary, no kharon config and no vault credential (REQ-ARCH-001).

kharond reaches the agent host's Chromium over CDP through a
WireGuard tunnel and fills forms there. The agent keeps its own CDP
session to the same browser; kharond never hands it the filled
values (see the harness policy below for what the agent should not
read back from the page).

```
 broker host (10.66.0.1)                      agent host (10.66.0.2)
 ┌──────────────────────┐   WireGuard   ┌──────────────────────────────┐
 │ kharond ─────────────┼───────────────┼─▶ cdp-relay ─▶ 127.0.0.1:9222│
 │ Vaultwarden          │               │                Chromium      │
 │ owner CLI            │               │ agent ──────▶ (user browser) │
 └──────────────────────┘               └──────────────────────────────┘
```

## Broker host

Start from the Compose example in
[`deploy/compose`](../deploy/compose/README.md). It runs kharond
from this repository's image next to Vaultwarden, with the agent API
bound to the WireGuard address only (REQ-DEP-006).

### The kharon account and its master password (REQ-DEP-007)

kharond logs in to a dedicated Bitwarden account with an API key and
reads one organization (SPEC OQ-5). The API-key file sits on the
broker host. Anyone who gets that file and a copy of the server's
data (a backup, a compromised Vaultwarden) can fetch the account's
encrypted keys and is then left with an offline attack on its
master password. So the master password must be long and random,
not something a person chose:

1. Generate it with `kharon init`, in an interactive terminal on
   any machine that has the CLI, for example from the Compose
   example's image:

   ```sh
   docker compose build kharon
   docker run --rm -it --entrypoint kharon kharon:local init
   ```

   It prints a 160-bit password (32 base32 characters in groups of
   four) to the terminal once. It never writes it to stdout, a file
   or a log, and it refuses to run without a terminal.
2. Create the kharon account with that password.
3. Store the password in your own vault, outside the kharon
   organization. kharon does not keep it, and the API key cannot
   recover it.
4. Create the kharon organization and collection, then create the
   account's API key and save it as
   `deploy/compose/secrets/kharon_bw_api_key.json`.

### The broker's WireGuard peer

Give the broker host a WireGuard interface at `10.66.0.1` with the
agent host as its only peer:

```ini
[Interface]
Address = 10.66.0.1/32
PrivateKey = <broker private key>

[Peer]
PublicKey = <printed by provision.sh on the agent host>
AllowedIPs = 10.66.0.2/32
Endpoint = <agent host>:51820
PersistentKeepalive = 25
```

The agent host listens on UDP 51820, so the broker dials it and the
agent host needs no address for the broker. If the broker should be
the one listening, set `BROKER_ENDPOINT` when you run
`provision.sh` and drop `Endpoint` here.

### Pointing kharond at the browser

kharond uses the configured CDP endpoint as written, so it must be
the browser's full WebSocket URL. Read it through the tunnel:

```sh
curl -s http://10.66.0.2:9222/json/version | jq -r .webSocketDebuggerUrl
# ws://10.66.0.2:9222/devtools/browser/<id>
```

and put it in `kharon.toml`:

```toml
[agents.assistant]
cdp = { endpoint = "ws://10.66.0.2:9222/devtools/browser/<id>", via = "wireguard" }
```

The `<id>` changes each time Chromium starts, so update it after a
restart of the agent host's `browser.service`.

## Agent host (REQ-DEP-005)

The agent host needs four things, and nothing else from kharon
(REQ-ARCH-001):

| What | Why |
|---|---|
| Chromium runs as its own OS user, `browser`, with its profile in `/var/lib/browser` (mode 0700) | The agent runs as a different user, so it cannot read the profile directory. |
| `kernel.yama.ptrace_scope = 1` | The agent's user cannot attach to Chromium or read `/proc/<pid>/mem`, where filled values live briefly. |
| Password manager, leak check, autofill and sync off by managed policy | Chromium never stores a filled password (REQ-ARCH-004). |
| CDP on `127.0.0.1:9222`, exposed to the broker only through WireGuard | The agent uses CDP on loopback as before. The broker reaches it at `10.66.0.2:9222`, and nothing else can. |

[`deploy/agent-host/provision.sh`](../deploy/agent-host/provision.sh)
does all of it on Debian 12 or 13. Copy it to the agent host and run
it as root with the broker's WireGuard public key:

```sh
sudo BROKER_WG_PUBKEY='<broker public key>' ./provision.sh
```

It:

- installs `chromium`, `fonts-liberation`, `wireguard-tools` and
  `socat`;
- creates the `browser` system user and `/var/lib/browser` (0700);
- writes `/etc/sysctl.d/60-ptrace-scope.conf`;
- writes the managed policy
  `/etc/chromium/policies/managed/no-password-manager.json`;
- writes `browser.service`, which runs headless Chromium as
  `browser` with CDP on `127.0.0.1:9222`;
- generates the host's WireGuard key in `/etc/wireguard/wg0.key`
  (0600) and writes `/etc/wireguard/wg0.conf` with the broker as the
  only peer;
- writes `cdp-relay.service`, a `socat` relay from `10.66.0.2:9222`
  to `127.0.0.1:9222` that accepts only the broker's tunnel address
  and runs as a throwaway uid;
- prints the host's WireGuard public key for the broker's peer
  entry.

`AGENT_WG_ADDR`, `BROKER_WG_ADDR`, `WG_LISTEN_PORT`, `CDP_PORT` and
`BROKER_ENDPOINT` override the defaults. Re-running it is safe: it
keeps the WireGuard key and rewrites everything else.

The WireGuard private key is the only secret on the agent host, and
only root can read it. Someone holding it could pose as the agent
host to the broker and receive fills meant for its Chromium, so
treat it like an SSH host key: never copy it off the host, and
replace it (re-run with the old key file removed, then update the
broker's peer entry) if the host is rebuilt or root is compromised.

CI runs the script in a fresh Debian VM and checks the result
(`.github/workflows/agent-host.yml`), and checks that it installs
only Chromium flags and tunnel config
(`crates/kharond/tests/req_arch_001_agent_host_docs.rs`).

### Running the agent

Run the agent as its own user, not `browser` and not in the
`browser` group, and have it connect to CDP on loopback, for example
with Playwright's `chromium.connectOverCDP("http://127.0.0.1:9222")`.

For a visible browser instead of a headless one, change
`browser.service`'s `ExecStart`: drop `--headless=new` and give it a
display. Without `--headless`, Chromium binds CDP to loopback
whatever `--remote-debugging-address` says.

### Agent harness policy (SPEC OQ-3)

kharond fills inside an isolated world and hands the agent only a
result, but a page's DOM is shared. An agent that reads input values
after a fill can read what kharond typed. kharon cannot stop a
compromised agent from doing that; the harness can stop a curious
one. We recommend that the agent's tool harness:

- does not expose `Runtime.evaluate`, `Runtime.callFunctionOn` or
  any other way to run JavaScript in pages;
- does not return input values, `value` attributes or form data to
  the model, only the page's text and structure;
- masks password fields in screenshots, or takes none while a
  login form is on screen.
