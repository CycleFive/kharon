#!/usr/bin/env python3
"""Rotate the live kharon Vaultwarden fixture account to Argon2id
(issue #84, REQ-EXP-001).

Why this exists: #84 needs a password-protected export produced by
the real `bw` CLI whose envelope covers the Argon2id export path.
Password-protected exports derive with the *account's* configured
KDF settings (Bitwarden help centre, "Encrypted Exports"), and the
fixture account is seeded with PBKDF2 (`fixture.json`: `kdf: 0`,
600 000 iterations) because the sync/decrypt live tests are written
against those parameters. A straight `bw export` of the seeded
vault would therefore land as PBKDF2 — the same KDF family the
Python generator fixtures already cover.

This script performs the same KDF change the web vault performs
(Settings → Security → Keys): log in with the seeded PBKDF2
parameters, recover the user key client-side, re-wrap it under the
Argon2id-derived stretched key, and POST `/api/accounts/kdf` with
the old/new master-password hashes. Afterwards `bw login` derives
with Argon2id (Bitwarden defaults: t = 3, m = 64 MiB, p = 4 — the
bounds/defaults recorded in kharon-bwcrypto `src/kdf.rs`) and
`bw export --format encrypted_json` produces an Argon2id envelope.

IRREVERSIBLE for the fixture: every helper that derives with the
seeded PBKDF2 parameters (seed.py, mutate.py, the kharond live
tests) stops working against this account afterwards. The fixture
workflow must run this LAST, after all other live steps, just
before teardown.

Crypto is independent of kharon-bwcrypto: PBKDF2/HKDF via
hashlib/hmac, Argon2id via argon2-cffi (libargon2), AES-256-CBC +
HMAC-SHA256 (EncString type 2) via `cryptography` (OpenSSL) —
reusing seed.py's helpers, mirroring gen_export_fixture.py.

Pinned environment (Python 3.12):
    pip install "cryptography==43.0.3" "argon2-cffi==23.1.0"

Fixture-only credentials; nothing secret is printed.
"""
import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import uuid

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from seed import (  # noqa: E402
    MANIFEST_PATH,
    derive_master,
    enc_type2,
    http_json,
    password_hash,
    stretch,
    tls_context,
)

# Bitwarden's Argon2id defaults (kdf.rs: m = 64 MiB, t = 3, p = 4).
ARGON2_ITERATIONS = 3
ARGON2_MEMORY_MIB = 64
ARGON2_PARALLELISM = 4


def dec_type2(key64: bytes, enc: str) -> bytes:
    """Decrypt an EncString type 2 (AES-256-CBC + HMAC-SHA256)."""
    kind, rest = enc.split(".", 1)
    if kind != "2":
        raise SystemExit(f"expected a type-2 EncString, got type {kind}")
    iv, ct, mac = (base64.b64decode(p) for p in rest.split("|"))
    want = hmac_mod.new(key64[32:], iv + ct, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(want, mac):
        raise SystemExit("EncString MAC mismatch")
    d = Cipher(algorithms.AES(key64[:32]), modes.CBC(iv)).decryptor()
    padded = d.update(ct) + d.finalize()
    u = padding.PKCS7(128).unpadder()
    return u.update(padded) + u.finalize()


def pick(d: dict, key: str):
    """Vaultwarden 1.33 answers camelCase; tolerate PascalCase too."""
    return d.get(key, d.get(key[0].upper() + key[1:]))


def derive_argon2id(password: str, email: str) -> bytes:
    """Bitwarden account Argon2id: salt = SHA-256(lowercase(email))."""
    return hash_secret_raw(
        password.encode(),
        hashlib.sha256(email.strip().lower().encode()).digest(),
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_MIB * 1024,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
        version=0x13,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default="https://127.0.0.1:8222")
    ap.add_argument(
        "--ca-cert",
        default=os.environ.get("KHARON_FIXTURE_CA_CERT"),
        help="CA cert to trust for the live server; default: $KHARON_FIXTURE_CA_CERT",
    )
    args = ap.parse_args()
    ctx = tls_context(args.ca_cert)

    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)
    acct = manifest["account"]
    email, password = acct["email"], acct["password"]

    prelogin = http_json(
        "POST", args.base_url + "/identity/accounts/prelogin", {"email": email}, context=ctx
    )
    if pick(prelogin, "kdf") == 1:
        print("fixture account is already on Argon2id; nothing to do")
        return 0

    # Log in with the seeded (PBKDF2) parameters and recover the
    # user key, exactly as an official client would before offering
    # the KDF change.
    master_old = derive_master(password, email, acct["kdf_iterations"])
    stretched_old = stretch(master_old)
    tok = http_json(
        "POST",
        args.base_url + "/identity/connect/token",
        {
            "grant_type": "password",
            "username": email,
            "password": password_hash(master_old, password),
            "scope": "api offline_access",
            "client_id": "cli",
            "deviceType": "9",
            "deviceName": "kharon-fixture-rotate-kdf",
            "deviceIdentifier": str(uuid.uuid4()),
        },
        form=True,
        context=ctx,
    )
    token = tok["access_token"]
    sync = http_json("GET", args.base_url + "/api/sync", token=token, context=ctx)
    profile = pick(sync, "profile")
    user_key = dec_type2(stretched_old, pick(profile, "key"))

    master_new = derive_argon2id(password, email)
    http_json(
        "POST",
        args.base_url + "/api/accounts/kdf",
        {
            "kdf": 1,
            "kdfIterations": ARGON2_ITERATIONS,
            "kdfMemory": ARGON2_MEMORY_MIB,
            "kdfParallelism": ARGON2_PARALLELISM,
            "masterPasswordHash": password_hash(master_old, password),
            "newMasterPasswordHash": password_hash(master_new, password),
            "key": enc_type2(stretch(master_new), user_key),
        },
        token=token,
        context=ctx,
    )

    prelogin = http_json(
        "POST", args.base_url + "/identity/accounts/prelogin", {"email": email}, context=ctx
    )
    got = (
        pick(prelogin, "kdf"),
        pick(prelogin, "kdfIterations"),
        pick(prelogin, "kdfMemory"),
        pick(prelogin, "kdfParallelism"),
    )
    want = (1, ARGON2_ITERATIONS, ARGON2_MEMORY_MIB, ARGON2_PARALLELISM)
    if got != want:
        raise SystemExit(f"prelogin after rotation is {got}, expected {want}")
    print(f"fixture account KDF rotated to Argon2id (t={ARGON2_ITERATIONS}, "
          f"m={ARGON2_MEMORY_MIB} MiB, p={ARGON2_PARALLELISM})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
