# Acceptance checks for a live deploy

These are the checks a new managed deploy has to pass before it carries
anyone but a pilot. They're written from the #201 acceptance run
(2026-11-12) and the #223 edge-rule verification. They cover the edge,
one real fill, and the canary checks for REQ-GOAL-002 (SPEC §1).

**No secret value goes in this repository, an issue, a chat, a command
line or an agent's context.** Evidence posts carry counts, paths,
statuses and lengths only.

## 1. Edge

Run [`deploy/checks/edge-checks.sh`](../deploy/checks/edge-checks.sh)
from an internet host. Not from the tailnet, and not from an agent host.

```sh
GATEWAY=kharon.example.com OWNER=kharon-owner.example.com OAUTH=1 ./deploy/checks/edge-checks.sh
```

Every scored line must be `ok`; `info` lines are reported, and fail
only on a 5xx or no answer. Read the script's header for what each switch
does and which checks write an audit entry. The checks are the ones in
the deployment guide's
[Verifying](deployment.md#verifying) and
[Checks on the first live deploy](deployment.md#checks-on-the-first-live-deploy)
sections, plus the `/connector` upgrade answers from
[Over WebSocket](deployment.md#over-websocket-through-the-public-gateway-199).
Two checks can't run from outside, so they stay manual:
- the owner UI's `421` for a wrong `Host`, from inside the holder's
  namespace, as in the guide;
- the `/connector` burst check in the
  [rate-limit checklist](deployment.md#per-customer-deploy-checklist-the-connector-rate-limit-required-223),
  which gets the source address blocked.

## 2. One real fill

1. **The canary item.** The customer adds a vault item to the kharon
   collection with a random password (for example 29 bytes) and a
   username, and its URI set to the test login page's **exact origin,
   scheme included**. In #201, an item stored as `http://…` for an
   `https://…` page was refused as `origin_mismatch` four times, and the
   agent side can't see why, because the metadata shows only the host.
   Five consecutive `origin_mismatch` fills suspend the agent (REQ-RL-002) until the owner runs `kharon unsuspend`.
2. **The test page.** An `https` login page you control, with a
   username and a password field. It should report field lengths only,
   never the values.
3. **The fill.** The agent:
   - opens the page in the agent host's Chromium;
   - calls `kharon_request_grant` for the item with the page's origin;
   - after the customer approves on the owner UI, calls `kharon_fill`
     with `submit: false`.

   Expect `status: filled` with the fields named, and lengths that
   match the item. The agent reports the grant id and the
   `created_by_channel`; the broker operator reports the audit `seq`s.

## 3. Canary filesystem check (agent host)

Run this on the host whose Chromium took the fill, after the fill.

The **customer** types the canary at a hidden prompt. It must never be
pasted to the agent or to the person running the commands:

```sh
PAT=$(mktemp)                   # a fresh 0600 file, not a fixed name in /tmp
( IFS= read -rs C; printf '%s' "$C" > "$PAT"; unset C )
wc -c < "$PAT"                  # must equal the canary's known length
sudo grep -rlF -f "$PAT" / \
  --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev --exclude-dir=run \
  2>/dev/null | grep -vxF "$PAT" | wc -l      # must be 0
```

While the pattern file exists, anything running as the same user can
read it, the agent included. Stop the agent runtime for this check, or
run it as a different user.

- **The length check** catches a stray newline or a mistyped value; a
  wrong pattern makes a `0` meaningless.
- **`--exclude-dir`** matches a directory name at any depth, not only
  `/proc` and the others at the root.
- **Saved passwords in the fill profile.** Find `Login Data` under the
  fill browser's profile directory, copy it, and count rows with
  `sqlite3 <copy> 'select count(*) from logins'`. Expect 0, or no file.
  Don't open other browsers' `Login Data`; they aren't the fill profile.
- **Clean up:** `shred -u "$PAT"` when done.

Pass: 0 files, and the fill profile has no saved logins.

The `grep` only sees the canary's plaintext bytes. A `0` says nothing
about compressed or encoded stores, which is why the `Login Data` row
count is a separate check.

After acceptance, delete or rotate the canary item in the vault: its
value has been typed on two hosts.

## 4. Canary sweep (broker and edge)

With a pattern file made the same way on the broker host (`mktemp`,
kept in `$PAT`), count
matches with `grep -cF -f` or `grep -rlF -f` only. Never print matching
lines.

| Surface | Command shape | Expect |
|---|---|---|
| kharond log | `docker compose logs kharon 2>&1 \| grep -cF -f "$PAT"` | 0 |
| cloudflared log | `docker compose logs cloudflared 2>&1 \| grep -cF -f "$PAT"` | 0 |
| journal since the fill | `sudo journalctl --since '<fill time>' \| grep -cF -f "$PAT"` | 0 |
| `/var/log` | `sudo grep -rlF -f "$PAT" /var/log \| wc -l` | 0 |
| kharond's data volume, audit log and keys included | `sudo grep -rlF -f "$PAT" <volume path> \| wc -l` | 0 |
| agent connector log (agent host) | `journalctl -u kharon-agent-connector \| grep -cF -f "$PAT"` | 0 |

Two legs are covered by construction rather than by grep:
- **`/mcp`:** its requests and responses have no credential field
  (REQ-GOAL-001, `docs/api/mcp-tools.json`).
- **The edge on `/connector`:** it sees only the inner TLS
  (REQ-ARCH-002). A `101` on `wss://<gateway>/connector`, followed by an
  inner ServerHello, shows this.

Shred the pattern files afterwards.

**Agent-runtime state is a different surface.** That means the
agent's own databases, chat history and notes. In #201 the only hits
were in the agent runtime's own SQLite and WAL files, after the canary
value had been seen and repeated in a chat, not through a fill. If the
canary ever reached a chat, rotate it to a new value and redo sections
2–4. Don't open those files to investigate.

## 5. Stop rule

Any hit in a kharon-controlled surface stops the run: the broker's
logs or data volume, cloudflared, the connector, or the fill browser
profile. Post only the surface and the count, then file a bug. Tick
an acceptance row only with its evidence linked.
