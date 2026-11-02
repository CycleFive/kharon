# Vaultwarden fixture harness (issue #10)

Throwaway Vaultwarden + seeded data for kharon's live tests. The
seed's *cipher-key shape* is deterministic (exactly one item with a
per-cipher key, one without); the bytes are not — every run uses
fresh randomness and UUIDs. Covers REQ-DEP-002 **(part)** per SPEC
§11 issue 6, and exists primarily to unblock the live half of
**REQ-CRY-004** (issue #7): decrypt a known item **with** and
**without** `cipher.key`, matching `bw get item`.

## Contents

| File | What |
|---|---|
| `docker-compose.yml` | Pinned Vaultwarden (`vaultwarden/server:1.33.0`), loopback-only port 8222 serving HTTPS with a per-run self-signed cert from `./tls/` (the `bw` CLI refuses plain-HTTP servers), signups on for the fixture account, admin panel disabled, throwaway named volume. |
| `fixture.json` | The manifest: fixture account (email / password / KDF params), org + collection names, and the two seeded items with their expected plaintexts. Fixture-only values — never reuse them. |
| `seed.py` | Builds all account/org/cipher crypto client-side (independent `cryptography`/OpenSSL implementation). `--offline` writes a `/api/sync`-shaped payload; `--live` registers + seeds a running server via the official API endpoints and captures its real `/api/sync`. |
| `mutate.py` | Live only: logs in as the fixture account like a web-vault device and adds / edits / deletes an item, or adds a second org, through the official API, so Vaultwarden emits real notifications-hub pushes. Drives the `req_cry_009_live_*` push E2E and `req_cry_008_live_second_org_while_unlocked_locks` (which widens the fixture, so the workflow runs it last). |
| `sync_fixture.json` | Checked-in output of `seed.py --offline`; decrypted end-to-end by the Rust fixture tests on every `cargo test` run. Regenerate with the pinned env below. |
| `../../req_dep_002_fixture.rs` | The Rust tests: harness-contract checks (`req_dep_002_*`), the offline chain decrypt (`req_cry_004_fixture_*`), and the ignored live decrypt (`req_cry_004_live_*`). |

## Pinned versions

Both external components are pinned, and the pins move together:

| Component | Pin | Where |
|---|---|---|
| Vaultwarden server | `vaultwarden/server:1.33.0` | `docker-compose.yml` |
| `bw` CLI (oracle) | `@bitwarden/cli@2026.1.0` | `.github/workflows/fixture.yml` |

The CLI pin is load-bearing, not cosmetic: 2026.2+ moved password
login into the Rust SDK, whose prelogin call (`POST
/identity/accounts/prelogin/password`) Vaultwarden 1.33.0 does not
route — `bw login` dies with a 404 before it starts. 2026.1.0 is the
last release whose prelogin is `POST /api/accounts/prelogin`, which
1.33.0 serves. Unpin the CLI only together with the server pin.

## Why the seed constructs ciphers itself

The REQ-CRY-004 contract is *exactly one* cipher with a per-cipher
key and *exactly one* without. Current Bitwarden clients generate
per-cipher keys opportunistically, so creating both items with `bw`
cannot guarantee the "without" half. `seed.py` therefore performs the
client-side crypto directly (the same operations official clients
perform) and sends `key: null` explicitly for the without item. The
official `bw` CLI remains the independent oracle: the fixture CI job
runs `bw get item` for both items and diffs against `fixture.json`.

## Run it

Offline (no Docker needed — this is what normal CI exercises):

```sh
python3 -m venv /tmp/kharon-fixture-venv
/tmp/kharon-fixture-venv/bin/pip install "cryptography==43.0.3"
/tmp/kharon-fixture-venv/bin/python seed.py --offline   # rewrites sync_fixture.json
cargo test -p kharon-bwcrypto --test req_dep_002_fixture
```

Live (Docker required; this is what `.github/workflows/fixture.yml` does):

```sh
# Throwaway CA + 127.0.0.1 cert (bw requires HTTPS; rustls rejects a
# self-signed CA cert as the server cert, hence the tiny CA).
sh gen-tls.sh
docker compose -f docker-compose.yml up -d
/tmp/kharon-fixture-venv/bin/python seed.py --live \
  --base-url https://127.0.0.1:8222 --ca-cert "$PWD/tls/ca.pem" \
  --out /tmp/sync.live.json --api-key-out /tmp/api-key.json
KHARON_FIXTURE_SYNC_JSON=/tmp/sync.live.json \
  cargo test -p kharon-bwcrypto --test req_dep_002_fixture \
    req_cry_004_live -- --ignored
KHARON_FIXTURE_BASE_URL=https://127.0.0.1:8222 \
KHARON_FIXTURE_CA_CERT="$PWD/tls/ca.pem" \
KHARON_FIXTURE_API_KEY_JSON=/tmp/api-key.json \
  cargo test -p kharond --test req_cry_005_sync req_cry_005_live -- --ignored
docker compose -f docker-compose.yml down -v
```

## Scope / honest limits

- The full REQ-DEP-002 acceptance criterion — *a seeded fixture fills
  a test page through headless Chromium* — needs the sync client
  (issue #8, this harness's stated dependency) and the fill path; its
  full AC is owned by issue #24. This harness delivers the compose
  stack, the seeded org/collection/items, and the live decrypt check.
- The live seed path is exercised by the fixture workflow
  (`workflow_dispatch` + changes under this directory); the offline
  path is exercised by every normal `cargo test` run.
