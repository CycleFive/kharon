# Official Bitwarden compatibility

REQ-DEP-004: a manual or nightly job against a cloud test account
passes REQ-CRY-005 (personal API-key login → `GET /api/sync` 200 →
scoped collection items decrypt). Results are recorded here.

## How it runs

Workflow: [`.github/workflows/compat.yml`](.github/workflows/compat.yml)
(`workflow_dispatch` + nightly cron `41 4 * * *` UTC).

1. `mint_api_key.py` derives the master-password hash from prelogin
   KDF params, password-grants as the official CLI client, and POSTs
   `/api/accounts/api-key` (same shape as the Vaultwarden seed).
2. `req_dep_004_live_bitwarden_cloud_api_key_sync_decrypts` builds a
   `SyncClient` against `https://vault.bitwarden.com`, syncs with the
   minted personal API key, unlocks with the master password, and
   decrypts at least one login password in the scoped org collection.

Repo secrets (set 2026-11-05):

| Secret | Role |
|---|---|
| `BW_COMPAT_EMAIL` | Cloud test account email |
| `BW_COMPAT_PASSWORD` | Master password |

Optional (workflow comments show the wiring): `BW_COMPAT_ORG_ID`,
`BW_COMPAT_COLLECTION_ID` to pin scope instead of “first org + first
collection of that org”.

The cloud account must have **one dedicated organization** with at
least one **collection** containing a **login** item (REQ-CRY-007
scope). Personal-vault-only accounts will fail the test on purpose.

Known uncertainty (SPEC OQ-11): official cloud may enforce new-device
verification or captcha on the password grant used only to mint the
API key. If the job fails there, rotate/confirm the account’s API
access from a trusted client and re-run.

## Results

| Date (UTC) | Server | Job | REQ-CRY-005 | Notes |
|---|---|---|---|---|
| _pending first green `compat.yml` run_ | `vault.bitwarden.com` | — | — | PR for #25 lands the harness; update this row after the first successful `workflow_dispatch`. |

Vaultwarden 1.3x half of REQ-CRY-005 is covered by
`fixture.yml` → `req_cry_005_live_vaultwarden_api_key_sync` (issue #8 / #10).
