# First run: from nothing to a checked first fill

This page takes a new install from nothing to an agent filling a real
login form. kharon has three parts, and you set up each one once:

- **The vault.** A Bitwarden account that belongs to kharon alone,
  in an organization you own, which sees one collection of logins.
- **The broker host.** It runs kharond, which holds that account's
  keys in memory while it is unlocked.
- **The agent host.** It runs the agent, its Chromium, and a small
  connector that dials the broker. It never holds a vault secret
  (REQ-ARCH-001).

You do seven things, in this order:

1. [Create the broker account, an organization and a collection](#1-create-the-broker-account-an-organization-and-a-collection)
2. [Get the account's personal API key](#2-get-the-accounts-personal-api-key)
3. [Run `kharon setup`](#3-run-kharon-setup)
4. [Start kharond and enroll your passkey](#4-start-kharond-and-enroll-your-passkey)
5. [Apply the agent-host bundle](#5-apply-the-agent-host-bundle)
6. [Unlock](#6-unlock)
7. [Check it with `kharon doctor`, then do a first fill](#7-check-it-with-kharon-doctor-then-do-a-first-fill)

Steps 1, 2, 4 and 6 are yours to do by hand, because they involve
the master password or your passkey. `kharon setup` and the bundle
it writes do the rest. Every refusal kharond has still applies:
setup never writes a file kharond would refuse, and it never weakens
a check.

This page uses the Compose package in
[`deploy/compose`](../deploy/compose/README.md), with the agent
connecting through the tunnel (path B, no VPN). The examples use
`kharon.example.com` for the agent gateway and
`kharon-owner.example.com` for the owner UI; use your own names.
On a managed deploy, where an operator runs the broker for a
customer, follow the [managed deploy runbook](managed-deploy-runbook.md),
which wraps these same steps with who does what.

## Before you start

- **A broker host** with Docker Engine and the Compose plugin, and a
  checkout of a kharon release that has `kharon setup` (any release
  after v0.5.0). OS and sizing notes are in
  [Host install](broker-lifecycle.md#host-install).
- **The kharon image, built on the broker** before step 1, so that
  `kharon init` and `kharon setup` are at hand:
  `cd deploy/compose && docker compose build kharon`. It builds from
  source; on 2 vCPU with about 1 GB of free memory it took about
  4.5 minutes.
- **A Cloudflare tunnel with two hostnames**, the gateway and the
  owner UI, both pointing at the broker. Agents and the connector
  reach kharond only through it. Creating it is in
  [Creating the tunnel](deployment.md#creating-the-tunnel-owner) and
  [Publishing the owner UI](deployment.md#publishing-the-owner-ui),
  steps 3–4. You need the tunnel token for step 4 below. To create
  the tunnel and its DNS records with the Cloudflare API rather than
  the dashboard, the API token needs **Account → Cloudflare Tunnel →
  Edit** and **Zone → DNS → Edit** on the zone.
- **An agent host** with Chromium serving CDP on its loopback
  (`127.0.0.1:9222`), or a Debian 12 or 13 machine where the
  provisioning script can install it (step 5).

## 1. Create the broker account, an organization and a collection

kharond logs in as its own Bitwarden account, never yours. That
account sees one organization, and inside it, only the collection of
logins you want kharon to fill. Collection membership is how you
grant kharon access: there is nothing else to grant.

**First, the account's master password.** Anyone with the account's
API key file and a copy of the server's data is left with an offline
attack on that password, so it must be long and random (REQ-DEP-007).
Let kharon generate it, in a terminal, from the image you built:

```sh
docker run --rm -it --entrypoint kharon kharon:local init
```

It prints a 160-bit password once, to the terminal only. Store it in
your own vault, outside the kharon organization. kharon never keeps
it. (`kharon setup` offers the same thing if you answer `n` to its
first question, and then walks you through the rest of this step.)
If you pick the password some other way, take it from a password
generator at 128 bits or more, for example 22 or more random letters
and digits. Never reuse one.

**Then, in the web vault. The two server types are set up
differently, on purpose.**

| | **Vaultwarden** (self-hosted, or run for a tenant) | **Bitwarden cloud** (`vault.bitwarden.com`, `.eu`) |
|---|---|---|
| Who creates the organization | **The dedicated account**, signed in as itself | **You**, signed in as yourself |
| The account's role | **Owner** of that organization, with manage on its collection | **User**, with **View items** on one collection |
| Invite, accept, confirm | **None.** There is no second person to invite it | Invite as User, accept as the account, then confirm as yourself, checking the fingerprint phrase |
| Plans | None to pick: any organization works | A Free organization is enough |

**This is how we want Vaultwarden set up.** On a Vaultwarden that
exists for kharon, whether you self-host it or we run it for a
tenant, the dedicated account creating and owning its organization
is the supported path. It needs no invite, no confirm and no second
account, so there is less to get wrong. The tradeoff is that the
account's API key can administer that organization, not only read one
collection. That is acceptable here because the Vaultwarden instance
and the account exist only for kharon, and nothing else lives in the
organization. kharond's scope check still applies: it refuses an
account that can see a second organization, or any item outside its
organization (`scope_too_broad`). On Bitwarden cloud the organization
is the customer's, and may hold other people and other collections,
so the account stays a **User**: there, never make it Owner, Admin or
Manage. Today, neither `kharon setup` nor kharond checks the role: that is
on you. (`kharon doctor` is planned to warn about an Owner on
Bitwarden cloud and only note it on Vaultwarden.)

**Vaultwarden path:**

1. Create the dedicated account with the password you set up above
   (a Vaultwarden may have signups disabled: then have the server's
   admin allow them, or invite the account from the admin page).
   Leave its personal vault empty: an item there is outside the
   organization and kharond refuses it (`scope_too_broad`).
2. Signed in as that account, create an organization (Vaultwarden has
   no plans to pick) and one collection for kharon, for example
   `kharon`. SMTP is not needed for any of this, and the account's
   email does not have to be verified.
3. Create or move the logins kharon may fill into that collection.

**Bitwarden cloud path:**

1. Create the dedicated account with the password you set up above,
   on `https://vault.bitwarden.com` or `https://vault.bitwarden.eu`.
   Leave its personal vault empty (`scope_too_broad`, as above).
2. As yourself, create an organization (a Free organization is
   enough) and one collection for kharon, for example `kharon`.
3. Invite the dedicated account with the **User** role and **View
   items** on that one collection. Accept the invite as the account,
   then confirm it as yourself, checking the fingerprint phrase.
4. Move or copy the logins kharon may fill into the collection.

**On both:** check each login's URI. It has to be `https://`, and its
match detection decides which pages it fills (see
[URI match](vault-onboarding.md#uri-match)). Default match detection
means the base domain, so it fills on every host of that domain;
**Host** narrows it to one. kharond refuses a fill when the tab does
not match (`origin_mismatch`).

The plans, the exact menus and the permission details are in
[Customer vault onboarding](vault-onboarding.md).

## 2. Get the account's personal API key

Signed in as the **dedicated account** (not as yourself), open
**Settings → Security → Keys → View API key**. kharond needs this
account's *personal* key: its `client_id` starts with `user.`. The
organization's API key, in the Admin Console, starts with
`organization.` and is refused, by setup and by kharond alike.

Keep the dialog open for the next step, or save the two values as a
JSON file that only you can read:

```json
{
  "client_id": "user.00000000-0000-0000-0000-000000000000",
  "client_secret": "…"
}
```

If the broker is a different machine from the one with the web vault,
create that file on the broker itself under `umask 077`, or copy it
there out of band (`scp`, never chat or email). Keep it `0600` and
pass it to setup as `--api-key-json <file>`. Delete it once setup has
finished, because setup writes its own copy for kharond.

## 3. Run `kharon setup`

`kharon setup` does what used to be a page of hand edits: it checks
the key type, logs in once, lists the organizations and collections
the account can see so you pick them instead of pasting IDs, mints
the agent's two credentials, writes `kharon.toml` and the key file
with the right owner and mode, and packs everything the agent host
needs into one directory.

Copy the CLI out of the image (it is a static binary and runs on the
host), then run setup as root from `deploy/compose`, so it can give
the key file to kharond's uid (10001):

```sh
cd deploy/compose
cid=$(docker create kharon:local)
docker cp "$cid":/usr/local/bin/kharon /tmp/kharon
docker rm "$cid"
sudo install -o root -g root -m 0755 /tmp/kharon /usr/local/bin/kharon
rm -f /tmp/kharon

sudo kharon setup --cdp-via agent-connector \
  --public-host kharon.example.com \
  --owner-origin https://kharon-owner.example.com
```

`/usr/local/bin/kharon` is only a suggestion: the CLI runs from any
path. If that path is already taken by an earlier host install, don't
overwrite it. Install the new binary somewhere else, such as
`~/bin/kharon`, and run `sudo ~/bin/kharon setup …`. Setup asks
its questions on a terminal, so over ssh use `ssh -t`, or pass
`--non-interactive` with every answer given as a flag.

Setup asks, on the terminal:

| Question | What to answer |
|---|---|
| Have you already created the dedicated kharon account…? | `y` after steps 1–2 (`n` generates the password and shows step 1's list) |
| Bitwarden or Vaultwarden server URL | Enter for Bitwarden US cloud, or your server's `https://` URL |
| The kharon account's email | The dedicated account's email |
| API key client_id, then client_secret | From step 2. The secret is read with echo off. Or pass `--api-key-json <file>` instead |
| Organization number, collections | Pick from the list. Collections show as IDs with item counts: their names are encrypted. With one organization and one collection, setup asks nothing and prints its pick |
| First agent's id | Enter for `assistant` |
| The agent's Chromium CDP endpoint | Enter for `ws://127.0.0.1:9222`, on the agent host's loopback |
| ntfy server, topic, write-token file | Approval prompts and the off-host audit checkpoints go here. The defaults are `https://ntfy.sh` and a fresh random topic |

A `client_id` that starts with `organization.` is refused on the spot,
before the secret is asked for. An account that can see a second
organization or a personal item is refused with the fix, before
anything is written.

When it finishes, `deploy/compose` holds:

| File | What it is |
|---|---|
| `kharon.toml` | The config, mode `0640`, group 10001. It holds token hashes, never tokens |
| `secrets/kharon_bw_api_key.json` | The API key, uid 10001, mode `0400` |
| `secrets/kharon_connector_tls.crt`, `.key` | The certificate the connector pins, and its key (uid 10001, `0400`) |
| `docker-compose.override.yml` | Mounts that certificate and key into the container |
| `secrets/agent-bundle-assistant/` | The agent-host bundle, mode `0700`. **It holds two secrets** |

Setup also prints `broker_pin = <64 hex>`. Keep that line on screen
for step 5: it is how the agent host knows the bundle arrived
unaltered.

If you passed `--api-key-json`, delete that file now
(`rm <file>`). Setup has written kharond's own copy.

Setup's closing "Next:" line, and `kharon doctor`'s fix lines, give
bare `kharon unlock` and `kharon passkey-enroll`. In the Compose
layout, run every `kharon` command against the running container:
`docker compose exec kharon kharon …`.

Every question has a flag of the same name, and `--answers <file>`
takes them as TOML, so `--non-interactive` runs the whole thing from
a provisioning script. `kharon setup --help` lists them all.

**About the ntfy topic.** With a published owner UI, the ntfy
messages carry Approve and Deny links, so anyone who can read the
topic can approve a fill. A random topic name on `ntfy.sh` is hard to
guess but not private. For anything beyond a first test, reserve the
topic and give kharond a write token, as in
[Setting up the ntfy topic](deployment.md#setting-up-the-ntfy-topic),
and pass `--ntfy-topic` and `--ntfy-token-file /run/secrets/ntfy_token`
(the path inside the container). Setup does not mount that file: add
`- ./secrets/ntfy_token:/run/secrets/ntfy_token:ro` under
`services.kharon.volumes` in the `docker-compose.override.yml` it
wrote.

## 4. Start kharond and enroll your passkey

Put the tunnel token in place without echoing it, turn the tunnel on,
and start the stack:

```sh
cd deploy/compose
read -rs T; ( umask 077; printf '%s' "$T" > secrets/cloudflared_tunnel_token ); unset T
sudo chown 65532:65532 secrets/cloudflared_tunnel_token
sudo chmod 0400 secrets/cloudflared_tunnel_token
printf 'COMPOSE_PROFILES=edge\n' > .env
docker compose up -d
```

Leave `COMPOSE_FILE` out of `.env`: Compose reads
`docker-compose.override.yml` (the certificate mounts from step 3)
only when `COMPOSE_FILE` is unset.

Your passkey is how you sign in to the owner UI to unlock and to
approve fills. Open `https://kharon-owner.example.com/enroll` in your
browser first, then on the broker host:

```sh
docker compose exec kharon kharon passkey-enroll
```

It prints a 43-character code that works once, for 120 seconds. Paste
it into the page and follow your browser's passkey prompt. If it
expires, run the command again. Registering does not sign you in: go
to `https://kharon-owner.example.com/` and sign in with the passkey.
Bookmark that address; always open it from the bookmark.

## 5. Apply the agent-host bundle

`secrets/agent-bundle-assistant/` is everything the agent host needs,
and nothing else:

| File | Secret? | For |
|---|---|---|
| `connector-tunnel-token` | yes | The connector only. `apply.sh` installs it |
| `agent-api-token` | yes | The agent's MCP client only, as its bearer token |
| `connector.toml` | no | The connector's config |
| `broker-pin` | no | The certificate pin, which must match what setup printed |
| `agent-id` | no | The agent's name on the broker |
| `apply.sh` | no | Installs the connector side |
| `README.txt` | no | What each file is |

The two tokens are not interchangeable: the connector refuses the
agent token, and kharond refuses the tunnel credential on `/mcp`.

**Move the directory to the agent host out of band**: `scp`, or a USB
stick. Never chat, email, a ticket or an agent's prompt. It is
root-owned when setup ran as root, so for example:

```sh
sudo tar -C secrets -cf - agent-bundle-assistant | ssh agent-host 'umask 077; tar -xf -'
```

If the broker host can't reach the agent host, relay the bundle
through a machine that can reach both. Pack it into a tar on the
broker (`umask 077`, mode `0600`), copy the tar on with `scp`, keep it
`0600` in a `0700` directory at each hop, and shred each copy once it
has moved on. Never unpack the tar along the way. Compare the tar's
`sha256sum` at both ends. The hash reveals nothing about the secrets
inside, so it is safe to compare in chat.

**On the agent host**, check that `broker-pin` matches the
`broker_pin` setup printed, then install the connector. Build the
binary from the same checkout with
`cargo build --release -p kharon-agent-connector`, and copy it over
the same way.

- **If Chromium is already running with CDP on `127.0.0.1:9222`**
  (Hermes, OpenClaw, or your own runtime):

  ```sh
  cd agent-bundle-assistant
  sudo ./apply.sh ./kharon-agent-connector
  ```

  It creates the `connector` user, installs the credential (`0400`)
  and `connector.toml`, runs `kharon-agent-connector --check`, and
  starts the connector under systemd. Without systemd, it prints
  the command instead: run that as the `connector` user under your
  own supervisor (for example
  `sudo runuser -u connector -- /usr/local/bin/kharon-agent-connector --config /etc/kharon-connector/connector.toml`).
  The connector logs `authenticated` once the broker accepts it. For a runtime where you are not root, or have no shell,
  see [Agent side: hosted and root runtimes](agent-runtime-setup.md).

- **On a bare Debian 12 or 13 machine**, let
  [`provision-connector.sh`](../deploy/agent-host/provision-connector.sh)
  install Chromium as its own user (CDP on loopback, password manager
  off, `ptrace_scope = 1`) together with the connector, fed from the
  bundle:

  ```sh
  cd agent-bundle-assistant
  sudo CONNECTOR_BIN=./kharon-agent-connector \
    BROKER_URL=wss://kharon.example.com/connector \
    BROKER_PIN="$(cat broker-pin)" \
    AGENT_ID="$(cat agent-id)" \
    TUNNEL_TOKEN_FILE=./connector-tunnel-token \
    /path/to/kharon/deploy/agent-host/provision-connector.sh
  ```

Either way, kharond logs `agent connector attached: … transport=ws`
(`docker compose logs kharon` on the broker host) once the connector
is up.

Now put `agent-api-token` in the agent's MCP client as the bearer for
`POST https://kharon.example.com/mcp`: in the client's secret
setting, never in a prompt or a file the model reads. A worked client
config is in [MCP client](deployment.md#mcp-client), and the
[agent harness policy](deployment.md#agent-harness-policy-spec-oq-3)
says what the agent should not read back from a page.

Then **delete the bundle**, on the agent host and on the broker host
(`sudo rm -r deploy/compose/secrets/agent-bundle-assistant`). Its two
secrets now live where they are used.

## 6. Unlock

kharond starts locked, and locks again after a restart or an idle
timeout. That is its resting state, not a fault. Open the owner UI
from your bookmark, sign in with the passkey, and enter the dedicated
account's master password. The page encrypts it before it is sent;
see [Unlocking from the browser](deployment.md#unlocking-from-the-browser)
for what that does and does not protect against.

Or unlock on the broker host's terminal, which avoids the edge:

```sh
docker compose exec kharon kharon unlock
```

## 7. Check it with `kharon doctor`, then do a first fill

`kharon doctor` reads the installation back and checks each piece:

```sh
docker compose exec kharon kharon doctor
```

It prints one line per check and a summary. On a finished install
all six pass:

| Check | What it proves |
|---|---|
| `config and key files` | The config loads, and the key file is a regular file kharond can read and nobody else can write |
| `api key type` | The key file holds a personal (`user.`) key |
| `sync visibility` | The account can see the configured organization and every configured collection, and nothing kharond would refuse |
| `audit sink` | Audit checkpoints leave the host (the ntfy topic) |
| `passkey enrolled` | At least one passkey is enrolled for the owner UI |
| `agent attached` | The agent's connector holds a live session |

Every failure names its fix, and the exit status is non-zero when any
check fails, so you can rerun it after any later step: before step 5
it tells you that no connector is attached. Doctor never prints a secret, and it works while the broker
is locked.

Doctor checks the parts, not a fill. The last step is one real fill,
on a login page made for testing: the
[login-fixtures](https://login.page.twkr.io/) pages behave like real
sites toward the browser, and report only the lengths of what was
typed, never the values.

1. In the kharon collection, add a login with URI
   `https://login.page.twkr.io/login.html` and match detection
   **Host** (the default, base domain, would also match every other
   `twkr.io` host), username `testuser` and password
   `correct-horse-battery-staple`. That is the page's public test
   pair, so it is safe to write down; never use a real credential for
   this. It reaches kharond at the next sync: within 10 seconds when
   the server pushes changes, within 5 minutes otherwise (REQ-CRY-009).
2. Ask the agent to log in at `https://login.page.twkr.io/login.html`
   with that item. It opens the page (`kharon_open`), asks for a grant
   (`kharon_request_grant`), and waits.
3. Approve the request: in the owner UI, or from the ntfy
   notification.
4. The agent calls `kharon_fill` with `submit: true`. Expect
   `status: filled`, with both fields named.
5. The tab lands on `/login/welcome.html?from=strict`, which says it
   is logged in: `#login-status` has `data-state="success"`. The page
   only counts characters, so `#submit-report` has
   `data-recorded="true"`, `data-username-length="8"` and
   `data-password-length="28"`: the lengths of the test pair.

That is a working install. To take it further: more agents
(`kharon token mint`), more logins (add them to the collection; they
appear at the next sync), the
[acceptance checks](acceptance-checks.md) before anyone but you relies
on it, and [backup and upgrades](broker-lifecycle.md#data-backup-restore-and-upgrade).

## When something is refused

| You see | It means | Fix |
|---|---|---|
| `this is an organization API key (client_id organization.<id>); it reaches the Public API only and cannot sync a vault` | An organization key | Step 2, signed in as the dedicated account |
| `client_id is not a personal API key (expected user.<uuid>)` | Any other prefix, or a pasted id that is not the `client_id` | Step 2, signed in as the dedicated account |
| `the server refused the API key` | Wrong secret, or a rotated key | Copy the key again; rotating replaces the secret |
| `the account cannot see that organization` | The invite is not accepted or not confirmed | Step 1.3, both halves |
| `… would refuse it [scope_too_broad]` | The account sees a personal item or a second organization | Empty its personal vault; remove it from other organizations |
| `the key file must belong to uid 10001 …, which needs root` | Setup ran without `sudo` | Run it with `sudo` |
| `the config … already exists; setup does not overwrite files` | A second run | Move the old files away first; setup never overwrites |
| `not readable by kharond (euid 10001; …)` at startup | The key file was copied by hand with your own uid | `sudo chown 10001:10001`, mode `0400`, or let setup write it |
| `origin_mismatch` on the fill | The item's URI does not match the tab | Fix the URI (`https://`, and its match detection). Five in a row suspend the agent until `kharon unsuspend` |

## Manual and advanced setups

Setup covers the path above. These still need the
[deployment guide](deployment.md):

- **A connector over a VPN or a raw TLS listener** instead of the
  tunnel: setup refuses `--cdp-via agent-connector` without
  `--public-host`. See [Path (B) broker](deployment.md#path-b-broker-agent-connector).
- **WireGuard (path A)**: setup writes the config with
  `--cdp-via wireguard` and shows the agent token once (or writes it
  to `--agent-token-file`), but there is no bundle; the agent host is
  [Path (A)](deployment.md#agent-host-req-dep-005).
- **The bundled Vaultwarden** (`COMPOSE_PROFILES=edge,vaultwarden`):
  setup cannot reach `http://vaultwarden:80` from the host, so pass
  `--no-discover` with `--organization-id` and `--collection-id`.
- **A private ntfy topic, or a separate checkpoint topic**:
  [Setting up the ntfy topic](deployment.md#setting-up-the-ntfy-topic)
  and [A separate checkpoint topic](deployment.md#a-separate-checkpoint-topic-302).
- **Cloudflare Access, the WAF and rate-limit rules, dashboard
  Connect (`[oauth]`)**: the [managed deploy runbook](managed-deploy-runbook.md)
  lists them in order.
- **More agents, and rotating a token**: `kharon token mint <id>` and
  `kharon tunnel mint <id>`, as in [Agent tokens](deployment.md#agent-tokens-req-api-003).
- **A host install without Docker**: `kharon setup --layout host`
  writes `/etc/kharon.toml` and `/etc/kharon/kharon_bw_api_key.json`;
  the rest of the host shape is in [Host install](broker-lifecycle.md#host-install).
