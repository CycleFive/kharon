# Broker lifecycle

This page is the broker host after the
[deployment guide](deployment.md): how kharond is installed on the
host-networked shape the pilot runs, what `/data` holds, how to back
it up, restore it and upgrade, where every secret lives and how it is
rotated, and the alerts the guide mentions in separate sections.

The other shape is the Compose package in
[`deploy/compose`](../deploy/compose/README.md). The runbook's later
steps use that package. Both shapes run the same binary and the same
config. Paths below are the host's unless a command says it runs
inside the container.

## Host install

The pilot broker is kharond and cloudflared on the host network, with
`[public_ingress]` on `127.0.0.1:8790`
([Where cloudflared runs](deployment.md#where-cloudflared-runs)).
cloudflared's unit is already in the guide. This is kharond's.

### Operating system

kharond's process hardening is Linux only. On any other OS it fails
closed (`process hardening is not supported on this platform`).

The unit below is systemd, the same supervisor as
`cloudflared-kharon.service` and `kharon-guard.service`.

Debian 12 or 13 is the recommendation. The agent-host scripts and
their CI job are Debian 12 or 13, and the image base is distroless
static Debian 12. Nothing in this repo installs or boots a broker-host
image, so that recommendation is not a tested broker appliance.

The host is single-purpose (REQ-DEP-006). kharond and cloudflared
share the host's network namespace, so every local process can reach
the loopback listeners. A local process can also spoof
`CF-Connecting-IP`; that header only moves a request between throttle
buckets and changes an audit field, never an authentication decision.
Don't run anything else on the box.

SPEC §8 says no swap, or encrypted swap. The process does not check.
Turn swap off. Leave `[memory] require_mlock` at its default, `true`.
Setting it `false` starts with the warning
`memory.require_mlock = false: key material may be swapped to disk`.

### VM size

A vCPU count and a RAM size are not determined by this repository.
Nothing in the code, the compose file or the guide records one, and
the pilot's size is not written down.

What the process does use, so a size has a floor to clear:

- A connector credential check is Argon2id at the production floor,
  m = 19456 KiB, t = 2, p = 1, and at most two of those run at once,
  across both connector transports. An agent-token check is the same
  Argon2id floor, with its own limit, separate from the connector's.
- With `require_mlock` (the default), `mlockall(MCL_CURRENT|MCL_FUTURE)`
  locks the whole process. A finite memlock limit without
  `CAP_IPC_LOCK` is treated as unavailable and startup refuses.
- While the vault is unlocked, its keys and items stay in that locked
  memory. This repository does not measure that set.

### Docker, for the Compose shape

The rest of the [runbook](managed-deploy-runbook.md) uses Compose.
The command in the repo is `docker compose` (the v2 plugin), not
`docker-compose`. This repository does not pin a Docker Engine version
and does not ship an install script. Install Docker Engine and the
Compose plugin for the OS from Docker's own instructions, then build
with `docker compose build kharon` in `deploy/compose`, from a tagged
release.

### User and uid

The image and the compose file run as uid `10001`, gid `10001`
(`USER 10001:10001` in the Dockerfile, `user: "10001:10001"` in
`docker-compose.yml`). The binary does not hardcode that number. It
checks files against its own effective uid.

On the host:

```sh
sudo groupadd --system --gid 10001 kharon
sudo useradd --system --uid 10001 --gid 10001 \
  --no-create-home --shell /usr/sbin/nologin kharon
```

If uid 10001 is already allocated, pick a free one and use it in the
unit and in every `chown 10001` the guide shows. The checks compare
the file's owner with the process's euid, not with the number 10001.

The owner socket accepts a connection only when the peer's uid is the
daemon's euid. Root is refused (`peer_uid`). On this unit the CLI is:

```sh
sudo -u kharon kharon status
```

The default socket is `/data/owner.sock`, which matches the default
`data_dir`. `docker compose exec kharon kharon status` works for the
same reason: the exec runs as uid 10001, which is the daemon's uid
inside the container.

### `data_dir`

The default is `/data` (`data_dir` at the top of the config, not under
a table). It has to be absolute. A relative path is refused
(`data_dir_not_absolute`, exit 78).

```sh
sudo install -d -o kharon -g kharon -m 0700 /data
```

kharond creates `<data_dir>/audit` at mode `0700` and writes only
under `data_dir`. The image's root filesystem is read-only; `/data` is
the only volume. If the directory cannot be created, startup fails
with `data_dir` and exit 73.

The unit below allows writes only on `/data`. If you set `data_dir` to
another absolute path, change `ReadWritePaths` to match.

### `memlock`

`require_mlock` defaults to `true`. Startup asks whether the process
can lock its memory: `CAP_IPC_LOCK` in the effective capability set,
or a soft `RLIMIT_MEMLOCK` of unlimited. Anything else is a config
error, exit 78:

```text
require_mlock = true but mlock is unavailable: no CAP_IPC_LOCK and RLIMIT_MEMLOCK soft limit is N bytes (needs unlimited)
```

The compose file sets `ulimits: { memlock: -1, core: 0 }`. Its
`cap_add: [IPC_LOCK]` does not take effect for this non-root uid; the
ulimit is what makes the probe succeed. The unit does the same thing
with `LimitMEMLOCK=infinity` and `LimitCORE=0`, and with an empty
capability set. The process also sets its own core limit to 0 and
makes itself non-dumpable at start (REQ-MEM-001).

`mlockall` runs at startup when `require_mlock` is set, and again at
every unlock. A failure at startup is `mlock_failed`, exit 71.

### Install the binary

The image carries both binaries at `/usr/local/bin/kharond` and
`/usr/local/bin/kharon`. They are static (musl), which is why the
Dockerfile builds them that way: distroless static has no libc, and
the same files run on the host. Copy them out rather than building a
toolchain on the broker:

```sh
docker build -t kharon:local .
cid=$(docker create kharon:local)
docker cp "$cid":/usr/local/bin/kharond /tmp/kharond
docker cp "$cid":/usr/local/bin/kharon /tmp/kharon
docker rm "$cid"
sudo install -o root -g root -m 0755 /tmp/kharond /usr/local/bin/kharond
sudo install -o root -g root -m 0755 /tmp/kharon /usr/local/bin/kharon
rm -f /tmp/kharond /tmp/kharon
```

A native `cargo build --release --locked -p kharond -p kharon-cli`
also produces the two binaries. A dynamic build has to match the
host's libc. Build it somewhere other than the broker when you can:
the broker holds the vault credentials.

The image's entrypoint is `kharond` and its default arguments are
`--config /etc/kharon.toml`. The unit passes that path explicitly.
Start from
[`deploy/compose/kharon.toml.example`](../deploy/compose/kharon.toml.example).
The code does not check the config file's mode. The file holds token
hashes, not the tokens. `root:kharon` mode `0640` is the
recommendation.

### The image, on the host network

The same shape as a container, without the compose holder. The holder
is a different namespace; don't run both.

```sh
docker run -d --name kharond --restart unless-stopped \
  --network host --read-only \
  --user 10001:10001 \
  --ulimit memlock=-1 --ulimit core=0 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=deploy/compose/kharon-seccomp.json \
  -v kharon-data:/data \
  -v /etc/kharon.toml:/etc/kharon.toml:ro \
  -v /etc/kharon/tls.crt:/etc/kharon/tls.crt:ro \
  -v /etc/kharon/tls.key:/etc/kharon/tls.key:ro \
  -v /etc/kharon/kharon_bw_api_key.json:/run/secrets/kharon_bw_api_key:ro \
  -v /etc/kharon/ntfy_token:/run/secrets/ntfy_token:ro \
  kharon:local
```

Run that from the repository root, so the seccomp path is the profile
the compose file uses (`seccomp=./kharon-seccomp.json` there). Those
two `security_opt` lines are the same SPEC §9 hardening as the compose
service. Mount only the files this deploy uses. The API key, the TLS key and
the ntfy token are mode `0400`, uid `10001`, as in the
[secrets inventory](#secrets-inventory). `--restart unless-stopped`
is the compose file's restart policy. A config the daemon refuses
(exit 78) restarts until you stop the container and fix it.

### systemd unit

```ini
# /etc/systemd/system/kharond.service
[Unit]
Description=kharon broker (kharond)
After=network-online.target
Wants=network-online.target

[Service]
User=kharon
Group=kharon
ExecStart=/usr/local/bin/kharond --config /etc/kharon.toml
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
UMask=0077
LimitMEMLOCK=infinity
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/data
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

`LimitMEMLOCK` and `LimitCORE` are the compose ulimits. The empty
capability set is deliberate: `CAP_IPC_LOCK` is not how this non-root
uid locks memory.

`UMask=0077` covers files the process creates without its own mode.
`checkpoints.jsonl` is one (only when
`[audit] checkpoint_local_only = true`), and so is `audit/keys/`.
The key files request mode `0600`, which this umask leaves alone.
`audit_sign.pub` requests `0644` and this umask leaves it `0600`.
`kharon audit verify` run as the `kharon` user can still read it.

`ReadWritePaths=/data` matches the only tree the process writes.
`ProtectSystem=strict` leaves `/etc` readable, which is where the
config, the TLS key and the ntfy token are.

`Restart=on-failure` restarts a non-zero exit and leaves a clean stop
down. SIGTERM and SIGINT are a clean shutdown: the public listener and
the owner UI each get at most 5 seconds to drain, an exit checkpoint
is published, and the process prints `kharond: shut down` and exits 0.
`TimeoutStopSec=30s` covers that drain. There is no reload. A config
change, a new binary, a new API key, a new TLS key and a new ntfy
token are all picked up at the next start.

A config refusal is exit 78 and a startup error that is not a clean
shutdown is non-zero, so the unit restarts every 5 seconds until you
stop it. Compose's `restart: unless-stopped` does the same.

`After=network-online.target` is so the startup scope check and the
clock probe have a route. An unreachable Bitwarden server does not
refuse startup. The log line is
`kharond: warning: REQ-CRY-008 startup scope check skipped (…). Starting anyway; …`.
The check runs again before the first unlock. A scope that is actually
too broad refuses startup (`scope_too_broad`, exit 78).

Check, then start. `--check` does not create `data_dir`, bind a
listener, or use the network. It does open the API key file and the
TLS files, and it runs the memlock probe (`load_for_startup` with
`ProcfsMlockProbe`).

Run the check under the unit's memlock limit. A plain
`sudo -u kharon kharond --check` does not get `LimitMEMLOCK=infinity`.
On a stock Debian host the soft limit is 8 MiB, so with the default
`require_mlock = true` that command exits 78:
`RLIMIT_MEMLOCK soft limit is 8388608 bytes (needs unlimited)`. The
unit is never started, and the check has not said the config is wrong.

```sh
sudo systemd-run --uid=kharon --gid=kharon \
  -p LimitMEMLOCK=infinity --wait --pty \
  /usr/local/bin/kharond --check --config /etc/kharon.toml
sudo systemctl daemon-reload && sudo systemctl enable --now kharond.service
```

Logs are stderr, so `journalctl -u kharond`. In Compose,
`docker compose logs kharon`.

The pilot's `[public_ingress]` is `127.0.0.1:8790`, which needs no
input filter. A listen address that is not loopback still needs the
filter in
[Tunnel-only listeners](deployment.md#tunnel-only-listeners-req-dep-006).

## Data backup, restore and upgrade

On the host unit, `data_dir` is the host's `/data`. In Compose it is
the named volume `kharon-data`, mounted at `/data` inside the
container. Back up the one this deploy uses. The host's `/data` is
empty when the broker is the compose volume.

### What is in `/data`

| Path | Mode the code asks for | What it is |
|---|---|---|
| `/data` | you create it `0700`, owner the kharond uid | `data_dir`. The image ships this directory owned by `10001`. |
| `/data/audit` | `0700` | created at start. Holds the log and `keys/`. |
| `/data/audit/audit.jsonl` | `0600` | the hash-chained audit log. |
| `/data/audit/keys/` | the process umask (`0700` with the unit's `UMask=0077`) | `create_dir_all` sets no mode of its own. |
| `/data/audit/keys/audit_sign_key` | `0600` | 32-byte Ed25519 seed. Signs checkpoints. |
| `/data/audit/keys/audit_sign.pub` | `0644`, then the umask | the verifying key. `kharon audit verify` reads this file. |
| `/data/audit/keys/audit_name_key` | `0600` | 32-byte HMAC key for item names (REQ-AUD-004). |
| `/data/audit/keys/audit_log_id` | `0600` | 32 hex characters, generated once. Stamped on every entry. |
| `/data/audit/checkpoints.jsonl` | no mode of its own; the umask | only when `[audit] checkpoint_local_only = true`. |
| `/data/owner/` | `0700` | created when a passkey is stored. |
| `/data/owner/passkeys.json` | `0600` | credential id, public key, signature counter, user handle, and the enrolled-at and last-used times when they exist. No private key, no session cookie, no enrollment code. A group- or world-writable file is refused. |
| `/data/oauth/` | `0700` | created when a Connect is persisted. Absent until `[oauth]` writes one. |
| `/data/oauth/state.json` | `0600` | Connect identities and the SHA-256 of their access and refresh tokens. Not the tokens. Authorization codes are not in this file. A missing file is an empty store. The mode is not checked on load. |
| `/data/owner.sock` | `0600` | the CLI socket. Recreated on start. Not part of a backup. |

SPEC §8 names the name key's directory as `/data/keys/`. The code, and
the deployment guide's `kharon audit verify --data <data_dir>/audit`,
use `<data_dir>/audit/keys/`. Use the code's path.

A second kharond pointed at the same `data_dir` fails at the audit
lock (`cannot open audit log: audit log is locked by another process`,
exit 73) before it can unlink the live socket.

These are not in `/data`. A backup of `/data` does not have them. They
are in the [secrets inventory](#secrets-inventory): the master
password (nowhere on the broker), the Bitwarden API key, the TLS key,
the ntfy token, the tunnel token, and the config file that holds the
agent and tunnel hashes.

### What a restart locks or ends

A restart is a new process. It always comes up locked (REQ-MEM-005).
SIGTERM is how `systemctl restart`, `docker stop` and
`docker compose restart kharon` ask it to exit.

| Comes back from disk | Ends with the process |
|---|---|
| The audit log and its keys. Revocations and suspensions are rebuilt from the log. A restart clears neither. | The vault unlock. Keys were only in memory. The customer unlocks again. |
| Passkeys (`owner/passkeys.json`). | Owner web sessions. They are memory, 15 minutes at most. |
| Connect identities and token hashes (`oauth/state.json`), when `[oauth]` is set. An ordinary lock does not end a Connect. A panic does, by rewriting this file. A restart is not a panic. | Live grants. They are memory only. Pending grant requests are dropped, and the next start appends one `abandoned` entry for each, with `detail_code` `restart`. |
| | The CDP session and its browser context. After the next unlock the agent calls `kharon_context`. A fill aimed at the old context is `target_not_owned`. |
| | The connector's session. The connector reconnects on its own. A fill in flight fails. |
| | Throttle counts, both the owner UI's and `/mcp`'s. |
| | Unredeemed OAuth codes, and the in-memory set of codes already redeemed. |
| | The Cloudflare Access key cache. Until one fetch succeeds, routes behind Access answer 403. |
| | An enrollment code. It lived 120 seconds in memory. |

There is no un-revoke. Replacing a revoked agent's `token_hash` and
restarting is how that agent comes back, and the old token stays
refused. That is the agent-token row in the inventory, not a side
effect of every restart.

### Backup

Stop kharond first. The shutdown publishes a checkpoint of the tail
when the ntfy publish succeeds, and the copy is not taken mid-append.
A copy of a running log can end on a partial line. The next open
truncates that line and appends `log_truncated`.

Host unit:

```sh
sudo systemctl stop kharond
sudo sh -c 'umask 077; tar -C / --exclude data/owner.sock -cf /root/kharon-data.tar data'
sudo systemctl start kharond
```

Compose. This archives the volume, not the host's `/data`. Stop
`kharon` only; leave the holder and cloudflared up. The helper image
only has to provide `tar`. `alpine:3.22` is an example; this
repository does not pin that tag.

```sh
docker compose stop kharon
docker run --rm -v kharon-data:/data:ro -v /root:/backup alpine:3.22 \
  tar -C / --exclude data/owner.sock -cf /backup/kharon-data.tar data
sudo chmod 0600 /root/kharon-data.tar
docker compose start kharon
```

`tar` skips `owner.sock`. The archive holds the audit signing key and
the name key, so it stays mode `0600` in a directory only root can
read, and off the broker when you can move it. It is not a substitute
for the off-host checkpoint stream: that stream is what makes a
truncated log detectable, and it lives on the subscriber from
[Setting up the ntfy topic](deployment.md#setting-up-the-ntfy-topic).

Copy `/etc/kharon.toml` and the secret files in the inventory in the
same pass, separately, with their modes. They are not in the tar of
`/data`.

### Restore

Stop kharond. Keep the tree you are replacing until
`kharon audit verify` has been run against the restored one, and do
that verify while kharond is still stopped. Restore the whole tree
from one moment. A log from one backup and keys from another, or a
newer `state.json` on an older log, is not a state the daemon repairs.

Starting first appends entries past the restored head and publishes
checkpoints for those sequence numbers. If the off-host stream already
has a checkpoint there, `truncated after local seq L` becomes
`checkpoint at seq N does not match the log`. Start only when verify
prints `audit log OK, head seq N`.

Host unit:

```sh
sudo systemctl stop kharond
sudo mv /data /data.pre-restore
sudo tar -C / -xpf /root/kharon-data.tar
sudo chown -R kharon:kharon /data
sudo find /data -printf '%m %u:%g %p\n'
sudo -u kharon kharon audit verify --data /data/audit --checkpoints /path/to/checkpoints.jsonl
```

Compose, again without recreating the holder. The restore helper needs
`tar`, `find` and `chown`; `alpine:3.22` is an example, as in Backup.
Verify with a one-off container on the volume, read-only, so nothing
appends. The holder can stay up or not. This does not start kharond.

```sh
docker compose stop kharon
docker run --rm -v kharon-data:/data:ro -v /root:/backup alpine:3.22 \
  tar -C / --exclude data/owner.sock -cf /backup/kharon-data-pre-restore.tar data
sudo chmod 0600 /root/kharon-data-pre-restore.tar
docker run --rm -v kharon-data:/data -v /root:/backup:ro alpine:3.22 \
  sh -c 'find /data -mindepth 1 -exec rm -rf {} + ; tar -C / -xpf /backup/kharon-data.tar && chown -R 10001:10001 /data'
docker run --rm -v kharon-data:/data alpine:3.22 ls -lR /data
docker run --rm --user 10001:10001 --entrypoint /usr/local/bin/kharon \
  -v kharon-data:/data:ro \
  -v /path/to/checkpoints.jsonl:/checkpoints.jsonl:ro \
  kharon:local \
  audit verify --data /data/audit --checkpoints /checkpoints.jsonl
```

When that prints `audit log OK, head seq N`, start. Host:
`sudo systemctl start kharond`. Compose: `docker compose start kharon`.

From `deploy/compose`, with the holder still running, the same verify
is:

```sh
docker compose run --rm --no-deps --entrypoint /usr/local/bin/kharon \
  -v /path/to/checkpoints.jsonl:/checkpoints.jsonl:ro \
  kharon audit verify --data /data/audit --checkpoints /checkpoints.jsonl
```

`--no-deps` does not start the holder, and this service joins the
holder's network namespace, so that form needs the holder up. The
`docker run` above does not.

Check the modes against the table. A group- or world-writable
`passkeys.json` refuses startup (`owner_ui_store`, exit 73,
`permission denied`). An unparseable `oauth/state.json`, or one whose
`version` is not 1, refuses startup when `[oauth]` is set
(`oauth_state`, exit 78). The log line carries the error kind, not the
parser's text.

**The audit chain.** `audit.jsonl` and `audit/keys/` come from the
same backup. New entries are stamped with `audit_log_id`. If that id
is not the id on entry 1, the start after those entries refuses the
log as corrupt (exit 73). The public key is rewritten whenever it
doesn't match the seed, so an old `audit_sign.pub` next to a new seed
does not survive a start.

`kharon audit verify` against the saved checkpoint stream prints one
of:

| Printed line | What it means here |
|---|---|
| `audit log OK, head seq N` | The chain and the checkpoints agree. |
| `truncated after local seq L: signed checkpoint exists for seq C` | The restored log is shorter than a checkpoint that already left the host. A restore does not rewind the off-host stream. Nothing in the code discards those checkpoints. |
| `checkpoint at seq N does not match the log` | The local entry at that sequence is not the one that was signed. |
| `checkpoint at seq N has an invalid signature` | The signing key is not the key that signed the stream. |
| `checkpoint at seq N belongs to a different log` | The checkpoint's log id is another deployment's. |

Anything other than `audit log OK, head seq N` means leave kharond
stopped. Starting would append past the restored head, and the new
entries are a different chain from the one the old checkpoints signed.
Keep `/data.pre-restore` (or `/root/kharon-data-pre-restore.tar`) until
you accept that.

**Passkeys.** The file is the set that can sign in. A credential
enrolled after the backup is gone. A credential removed after the
backup is back. The browser presents the user handle from enrollment;
if it doesn't match the file's `user_handle`, sign-in fails with
`bad_assertion`, the same answer as a bad signature. The signature
counter has to be strictly greater than the stored count, or both
zero. An older file has a lower count, so the next real assertion
still succeeds and the stored count catches up. A file whose count is
already ahead of the authenticator fails with `bad_assertion` until
the authenticator's counter passes it. A passkey is also bound to the
RP ID, the hostname in `public_origin`. A file from another hostname
does not sign in here; enroll again, as in
[If the RP ID changes](deployment.md#if-the-rp-id-changes).

**Connects.** `oauth/state.json` is the list of Connects. Startup does
not rebuild it from the audit log. A missing file means every Connect
is gone, and each dashboard Connects again. An older file brings back
the identities and the token hashes from that moment. Tokens issued
after the backup are unknown. A Connect that was disconnected, or
ended by panic, after the backup is back, and its refresh token works
again while the deadlines stored in that file still say it is live
(access tokens 1 hour, refresh tokens 30 days idle and 90 days
absolute from consent). If the audit log you restored is newer than
the file, it still records the ending, and the broker does not
re-apply it. Open the Connections page and Disconnect anything that
should stay ended.

**Revocations and suspensions.** Rebuilt from the restored log only.
A revocation that happened after the backup is gone, and that agent
token works again until you revoke it. The same for a suspension.

**Grants, sessions, the unlock.** Gone, as on any start. The broker is
locked. The customer signs in and unlocks again.

Don't restore one customer's `/data` onto another broker. The log id
and the keys are that deployment's.

### Upgrade

Work from a tagged release, as the runbook says.

The compose file builds `kharon:local`. The image workflow builds and
scans that image. It does not push one. SPEC §9 sketches
`ghcr.io/cyclefive/kharon:0.1`; whether that tag is published is not
determined by the files in this repository. There is no pull step to
run here. If a deploy is actually running a pulled image, change the
tag and run `docker compose up -d`.

Compose, from `deploy/compose`:

```sh
docker compose build kharon
docker compose up -d
```

`up -d` recreates `kharon` when the image changed, and leaves the
holder and cloudflared when they did not. `docker compose restart
kharon` restarts the container that is already running and does not
pick up a newly built image. Use `restart` for a config change. Use
`build` and then `up -d` for an upgrade. Don't recreate the holder
alone; that strands kharond and cloudflared in a dead namespace.

Host unit. Copy the new binaries over as in
[Install the binary](#install-the-binary), then:

```sh
sudo systemctl restart kharond
```

Overwriting the binary does not affect the running process. The
restart does. cloudflared is its own unit. Replacing kharond does not
replace it; cloudflared's own update is the `--no-autoupdate` note in
the guide.

Either way the restart does what the table above says. The customer
unlocks again. Connects stay. Grants don't. The connector reconnects
by itself.

## Secrets inventory

One row per secret. The mode is what to set. Where startup or the
connector checks something weaker, or something else, the row says so.
Rotation never prints a secret into a shell history or a chat. The
mint commands need a terminal; they refuse without `/dev/tty`.

| Secret | Location | Owner and mode | Who knows it | Rotation |
|---|---|---|---|---|
| Bitwarden API key | `bitwarden.api_key_file`. Compose: `deploy/compose/secrets/kharon_bw_api_key.json`, mounted at `/run/secrets/kharon_bw_api_key`. Host: `/etc/kharon/kharon_bw_api_key.json` (the path is whatever the config says). | uid `10001` (or the host user's uid), mode `0400`. Not a regular file, or group- or world-writable: exit 78, `api_key_file`. Group- or world-readable, or a foreign owner: a warning, and startup continues if the uid can open the file. Unreadable by the euid: exit 78, and the message names the euid, the owner and the mode. | The customer creates it. The operator installs the file. kharond reads it. It syncs ciphertext and does not decrypt. The agent never has it. | The customer creates a new key in Bitwarden and revokes the old one there. This repo has no rotate command. Remove the `0400` file and recreate it (an unprivileged operator cannot overwrite it), `chown` and `chmod` as before, and restart kharond. The file is read at startup. |
| Master password | Nowhere on the broker. A `password` key in the config is refused. It is not in the environment and not in `/data`. `kharon init` prints it once, on a terminal: 32 base32 characters, 160 bits. | None. | The customer, in their own vault, outside the kharon organization. The operator does not know it unless the customer chooses a CLI unlock. | No kharon command. The customer changes it in Bitwarden. If that change rotates the organization key, the next sync locks and audits `key_rotated` (REQ-MEM-006). The next unlock uses the new password. |
| Agent token | Plaintext only on the minting terminal (`kharon token mint <id>`, `kh_agent_<id>_…`), then in the agent's own secret store. The broker has the Argon2id hash in `[agents.<id>] token_hash`, in `/etc/kharon.toml`. | The hash is in the config. The code does not check that file's mode. Recommend `root:kharon` `0640`. | The operator, at mint time, and whoever holds the agent's secret. kharond can verify the token and cannot reprint it. | While kharond is running, `kharon revoke agent <id>`. That is durable and revokes the agent's grants. Mint a new token, replace `token_hash`, restart. The old token stays refused: the revoke is bound to that hash's fingerprint. Putting the old hash back does not un-revoke it. See [Agent tokens](deployment.md#agent-tokens-req-api-003). |
| Tunnel credential | Plaintext on the minting terminal (`kharon tunnel mint <id>`, `kh_tunnel_<id>_…`), then the connector's `token_file`. The provision script uses `/etc/kharon-connector/token`. The hash is `[agents.<id>] connector_token_hash` in the broker config. | The connector refuses a file with any group or other permission bit, so `0400` or `0600`. It does not check the owner uid. The script owns the file as the `connector` user. It also refuses a value that does not start with `kh_tunnel_`. | The operator, at mint time, and the connector's uid. Not the agent's MCP client. | Mint a new one, replace `connector_token_hash`, restart kharond. The old credential stops matching because the hash changed. There is no durable revoke: restoring the old hash and restarting accepts the old credential again. Write the new file at `0400` and restart the connector. See [Rotating after a leak](agent-runtime-setup.md#rotating-after-a-leak). |
| Tunnel token | cloudflared's `--token-file`. Compose: `secrets/cloudflared_tunnel_token`, uid `65532`, mode `0400`, mounted at `/run/secrets/cloudflared_tunnel_token`. Host: `/etc/cloudflared/kharon.token`, owner the `cloudflared` user, mode `0400`. That user's numeric uid is whichever `useradd --system` assigned; the unit does not pin one. Compose pins `65532` because that is the image's uid. | As in the location column. | The zone admin creates it. The operator installs the file. cloudflared reads it. kharond does not. | A new token from the dashboard, written with `umask 077` and never in argv, then restart cloudflared only (`docker compose restart cloudflared`, or `systemctl restart cloudflared-kharon`). Revoke the old token in the dashboard. This repo has no command for that. |
| TLS key, and the pin | `tls_cert_file` and `tls_key_file`. The guide uses `/etc/kharon/tls.crt` and `/etc/kharon/tls.key`, bind-mounted read-only. The pin is the SHA-256 of the certificate's DER (`openssl x509 -in /etc/kharon/tls.crt -outform DER \| sha256sum`). It is `broker_pin` on every connector. The pin is not a secret. It has to arrive unchanged. | The key: uid `10001`, mode `0400`. The code requires the uid to be able to read the cert and the key. A key it cannot read fails with `make it owned by that uid, mode 0400`. A looser mode that is still readable is not refused. A cert and key that are not a matching PEM pair fail with `tls_material` / `not a PEM certificate and private key`, exit 78. | The operator generates the key. kharond reads it. Every connector has the pin. The agent host does not have the key. | A new key and a new certificate together. Install them, restart kharond, recompute the pin, and set `broker_pin` on every connector, then restart each connector. The old pin fails before a credential is sent. The raw listener and the WebSocket path share this certificate, so rotating it re-pins every connector. |
| ntfy write token | `token_file` inside the `[approval].ntfy` table. A `token_file` key beside `ntfy` is an unknown field and the config is refused. Compose: `secrets/ntfy_token`, uid `10001`, mode `0400`, mounted at `/run/secrets/ntfy_token`. Host: `/etc/kharon/ntfy_token`, same owner and mode. | The code reads the file once at startup, trims it, and refuses if it is missing, unreadable or empty. It does not check the mode. It is sent as `Authorization: Bearer`. | The operator, from `ntfy token add kharond` on the write-only user. kharond's uid can read the file. That token cannot read the topic. Subscribers do not use it. | [Setting up the ntfy topic](deployment.md#setting-up-the-ntfy-topic): `ntfy token add kharond`, remove the `0400` file, recreate it, `chown`, `chmod`, restart kharond, then `ntfy token remove`. The section restarts the whole stack, which also restarts cloudflared. cloudflared does not read this token. kharond comes back locked. |
| ntfy checkpoint token | On the keeper's machine, not the broker: `/etc/kharon-checkpoints/auth`, mode `0400`, one line `Authorization: Bearer tk_…`. The `checkpoints` user's token. The phone uses a username and password, not this token. | Mode `0400`, as that section writes it. kharond never reads this file. | Whoever keeps the checkpoint stream. The customer's phone password is the customer's; the operator does not need to know it. | `ntfy token add checkpoints`, replace the file, restart the subscriber. `ntfy user remove <user>` cuts a subscriber off. |
| Audit signing key | `/data/audit/keys/audit_sign_key`, mode `0600`, owner the kharond uid. Generated on first start if the file is absent. `audit_sign.pub` beside it is the verifying key. | `0600` on the seed. The pub key requests `0644`, masked by the umask. | The file. Whoever can read `/data` can read the seed. `kharon audit verify` needs the pub key, not the seed. | Don't. There is no command. A new seed makes the next start rewrite the pub key to match, and checkpoints signed by the old key fail with `checkpoint at seq N has an invalid signature`. Restore the file from backup. |
| Audit name key | `/data/audit/keys/audit_name_key`, mode `0600`, owner the kharond uid. HMAC-SHA256 of item names. | `0600`. | The file. Someone who has it can test guesses of item names (REQ-AUD-004). | Don't. SPEC says it is not rotated: a new key breaks correlation of names across the log. The chain still verifies, because the hash is stored on the entry and not recomputed. Restore the file from backup. |

`audit_log_id` sits in the same directory, mode `0600`. It is not a
password. It is generated once, and every new entry is stamped with
it. Replacing it makes the next entries disagree with entry 1, and the
start after that refuses the log as corrupt. Back it up with the two
keys. Don't regenerate it.

## Alerts

The guide tells you to act on four signals, in four different
sections. This is the list. The first two are the ones the runbook
requires before handover; the other two are the ones the guide states
alongside them.

| Signal | Where the guide says it | What it means |
|---|---|---|
| On the agent host: `kharon-agent-connector: no broker session for …`. The first line is after 2 minutes without an authenticated session, then one every 10 minutes while that lasts. The duration and the attempt count in the guide's example vary. | [Connector config over WebSocket](deployment.md#connector-config-over-websocket) | The connector is not attached. The `last failure` clause names the leg (`upgrade: websocket upgrade answered 502` is the origin being down). The per-attempt lines are not the alert. |
| `kharon status` prints `owner UI: N requests without a usable CF-Connecting-IP (not throttled)` and N rises. The first such request also logs `kharond: owner UI request without a usable CF-Connecting-IP; such requests are not throttled until the edge sends it`. | [Watching it](deployment.md#watching-it) | The edge is not sending the header. Sign-in and unlock have lost their per-address throttle. The passkey still decides who gets in. |
| The checkpoint subscriber has stopped, for longer than the ntfy server's `cache-duration`. | [Setting up the ntfy topic](deployment.md#setting-up-the-ntfy-topic), step 4 | Checkpoints from the gap were not saved. A later `kharon audit verify` cannot see a tail the subscriber never wrote down. |
| An audit entry `connector_replaced` when nobody restarted that connector and nobody ran `kharon-agent-connector --check`. | [Over WebSocket](deployment.md#over-websocket-through-the-public-gateway-199) | Someone else may hold the tunnel credential. Mint a new one. A successful `--check` writes this entry too, and it replaces the live session, so it is not itself the alert. |

These are startup warnings, printed once as `kharond: warning:`. They
are the misconfiguration lines for the install and the secrets above,
not a fifth page to add:

- `audit.checkpoint_local_only = true: checkpoints are not pushed off-host`. The guide's temporary pilot posture.
- `public_ingress.listen is not loopback and trusted_proxies is empty: CF-Connecting-IP is ignored, so every client shares the peer's throttle key and audit client_ip`. Loopback, which the pilot and the compose holder use, does not print this.
- `memory.require_mlock = false: key material may be swapped to disk`.
- `bitwarden.api_key_file is group- or world-readable; use mode 0400 or 0600 unless it is a container-private secret`, and `bitwarden.api_key_file is not owned by kharond's effective uid`.
- `REQ-CRY-008 startup scope check skipped (…). Starting anyway; …`. The Bitwarden server was unreachable, or the check did not finish. A scope that is too broad is a refusal, not this warning.

A failed checkpoint publish is not its own log line. The entry is
already on disk, and the next checkpoint that does get published
covers the current head. The way to see a gap is
`kharon audit verify` against the saved stream.
