#!/usr/bin/env python3
"""Mint a Bitwarden personal API key from email + master password (issue #25).

Official-client flow against cloud or self-hosted:

  1. POST /identity/accounts/prelogin  → KDF params
  2. Derive master key + masterPasswordHash (PBKDF2 or Argon2id)
  3. POST /identity/connect/token      → password grant (client_id=cli)
  4. POST /api/accounts/api-key        → client_secret
  5. Write {\"client_id\": \"user.<id>\", \"client_secret\": ...} mode 0600

Used by `.github/workflows/compat.yml` so the REQ-CRY-005 live cloud
test can log in with the same personal API key path as production
kharond (REQ-DEP-004). Credentials come from env; nothing secret is
printed.

Pinned environment (Python 3.12):
    pip install \"argon2-cffi==23.1.0\"

Cloud host mapping matches `Endpoints::for_server` in kharond:
  vault.bitwarden.com → identity./api.bitwarden.com
  vault.bitwarden.eu  → identity./api.bitwarden.eu
  anything else       → <base>/identity and <base>/api
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

from argon2.low_level import Type, hash_secret_raw

DEVICE_TYPE = "9"  # CLI
DEVICE_NAME = "kharon-compat-mint"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def pick(d: dict, key: str):
    return d.get(key, d.get(key[0].upper() + key[1:]))


def endpoints(server: str) -> tuple[str, str]:
    base = server.rstrip("/")
    host = urllib.parse.urlparse(base).hostname or ""
    if host == "vault.bitwarden.com":
        return "https://identity.bitwarden.com", "https://api.bitwarden.com"
    if host == "vault.bitwarden.eu":
        return "https://identity.bitwarden.eu", "https://api.bitwarden.eu"
    return f"{base}/identity", f"{base}/api"


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def derive_master_pbkdf2(password: str, email: str, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), email.strip().lower().encode(), iterations, 32
    )


def derive_master_argon2id(
    password: str, email: str, iterations: int, memory_mib: int, parallelism: int
) -> bytes:
    return hash_secret_raw(
        password.encode(),
        hashlib.sha256(email.strip().lower().encode()).digest(),
        time_cost=iterations,
        memory_cost=memory_mib * 1024,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
        version=0x13,
    )


def password_hash(master: bytes, password: str) -> str:
    return b64(hashlib.pbkdf2_hmac("sha256", master, password.encode(), 1, 32))


def http_json(
    method: str,
    url: str,
    body=None,
    token: str | None = None,
    form: bool = False,
    email_header: str | None = None,
):
    if form:
        data = urllib.parse.urlencode(body).encode()
        ctype = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        ctype = "application/json"
    else:
        data, ctype = None, None
    req = urllib.request.Request(url, data=data, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if email_header:
        # Official clients send Auth-Email (base64) on identity calls.
        req.add_header("Auth-Email", b64(email_header.strip().lower().encode()))
    req.add_header("Device-Type", DEVICE_TYPE)
    req.add_header("Bitwarden-Client-Name", "cli")
    req.add_header("Bitwarden-Client-Version", "2026.1.0")
    try:
        with urllib.request.urlopen(req, timeout=60, context=ssl.create_default_context()) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise SystemExit(f"HTTP {e.code} {method} {url}: {detail}") from e


def mint(server: str, email: str, password: str, out_path: str) -> None:
    identity, api = endpoints(server)
    prelogin = http_json(
        "POST",
        f"{identity}/accounts/prelogin",
        {"email": email},
        email_header=email,
    )
    kdf = pick(prelogin, "kdf")
    iterations = pick(prelogin, "kdfIterations")
    if kdf is None or iterations is None:
        raise SystemExit(f"prelogin missing kdf fields: {sorted(prelogin)}")
    if kdf == 0:
        master = derive_master_pbkdf2(password, email, int(iterations))
    elif kdf == 1:
        memory = pick(prelogin, "kdfMemory")
        parallelism = pick(prelogin, "kdfParallelism")
        if memory is None or parallelism is None:
            raise SystemExit(f"argon2 prelogin missing memory/parallelism: {sorted(prelogin)}")
        master = derive_master_argon2id(
            password, email, int(iterations), int(memory), int(parallelism)
        )
    else:
        raise SystemExit(f"unsupported prelogin kdf type {kdf} (OQ-8)")

    auth = password_hash(master, password)
    tok = http_json(
        "POST",
        f"{identity}/connect/token",
        {
            "grant_type": "password",
            "username": email,
            "password": auth,
            "scope": "api offline_access",
            "client_id": "cli",
            "deviceType": DEVICE_TYPE,
            "deviceName": DEVICE_NAME,
            "deviceIdentifier": str(uuid.uuid4()),
        },
        form=True,
        email_header=email,
    )
    token = tok.get("access_token")
    if not token:
        raise SystemExit(
            "password grant returned no access_token "
            "(OQ-11: captcha / new-device verification may block CI)"
        )

    sync = http_json("GET", f"{api}/sync?excludeDomains=true", token=token)
    profile = pick(sync, "profile") or {}
    user_id = pick(profile, "id")
    if not user_id:
        raise SystemExit("sync profile missing id")

    resp = http_json(
        "POST",
        f"{api}/accounts/api-key",
        {"masterPasswordHash": auth},
        token=token,
    )
    secret = pick(resp, "apiKey")
    if not secret:
        raise SystemExit(f"api-key response missing apiKey: {sorted(resp)}")

    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"client_id": f"user.{user_id}", "client_secret": secret}, f)
    orgs = pick(profile, "organizations") or []
    colls = pick(sync, "collections") or []
    print(
        f"personal API key written to {out_path} (0600); "
        f"orgs={len(orgs)} collections={len(colls)}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--server",
        default=os.environ.get("KHARON_COMPAT_BASE_URL", "https://vault.bitwarden.com"),
    )
    ap.add_argument("--email", default=os.environ.get("BW_COMPAT_EMAIL") or os.environ.get("KHARON_COMPAT_EMAIL"))
    ap.add_argument(
        "--password-env",
        default="BW_COMPAT_PASSWORD",
        help="env var holding the master password (default BW_COMPAT_PASSWORD)",
    )
    ap.add_argument("--out", required=True, help="path for {client_id, client_secret} JSON (0600)")
    args = ap.parse_args()
    if not args.email:
        raise SystemExit("email required (--email or BW_COMPAT_EMAIL)")
    password = os.environ.get(args.password_env) or os.environ.get("KHARON_COMPAT_PASSWORD")
    if not password:
        raise SystemExit(f"password required (${args.password_env} or KHARON_COMPAT_PASSWORD)")
    mint(args.server, args.email, password, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
