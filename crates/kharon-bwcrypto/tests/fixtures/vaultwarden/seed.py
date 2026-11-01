#!/usr/bin/env python3
"""Seed the kharon Vaultwarden fixture (issue #10).

Two modes, one crypto construction — the whole point is that both
modes build *identical shapes*, so the offline payload is a faithful
stand-in for the live server payload:

  --offline   Build the account / org / cipher EncStrings locally and
              write a `/api/sync`-shaped JSON file (sync_fixture.json).
              No server needed. The Rust fixture tests decrypt this
              payload through the full kharon-bwcrypto chain
              (REQ-CRY-004) and compare against fixture.json.

  --live      Register the fixture account on a running Vaultwarden
              (see docker-compose.yml), create the org + collection +
              ciphers through the official API endpoints, then capture
              GET /api/sync to the --out path. The ignored Rust live
              test then decrypts that capture the same way, and the
              fixture CI job cross-checks with `bw get item`
              (the official CLI as an arms-length program, per OQ-2).
              The live server speaks HTTPS with a throwaway
              self-signed cert (see docker-compose.yml): pass
              --ca-cert <cert.pem> (or set KHARON_FIXTURE_CA_CERT)
              so the seed trusts it.

Why ciphers are constructed here instead of via `bw create item`:
the fixture's contract is *exactly one* cipher with a per-cipher key
(`cipher.key` present) and *exactly one* without. Current clients
generate per-cipher keys opportunistically, so `bw` alone cannot
guarantee the without half. Constructing both ciphers client-side
(the same crypto official clients perform) makes the distinction
deterministic; `bw` is still the independent oracle in CI.

Crypto is independent of kharon-bwcrypto: AES-256-CBC + HMAC-SHA256
(type 2) and RSA-OAEP-SHA1 (type 4) via `cryptography` (OpenSSL),
PBKDF2/HKDF via hashlib/hmac — mirroring gen_chain_vectors.py.

Pinned environment (Python 3.12):
    pip install "cryptography==43.0.3"

Fixture-only secrets: every password/key in fixture.json exists
solely for this throwaway harness. Never reuse them elsewhere.
"""
import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.path.join(HERE, "fixture.json")


# ---------------------------------------------------------------- crypto

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def derive_master(password: str, email: str, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), email.strip().lower().encode(), iterations, 32
    )


def stretch(master: bytes) -> bytes:
    return hkdf_expand(master, b"enc") + hkdf_expand(master, b"mac")


def password_hash(master: bytes, password: str) -> str:
    return b64(hashlib.pbkdf2_hmac("sha256", master, password.encode(), 1, 32))


def enc_type2(key64: bytes, plaintext: bytes) -> str:
    """Bitwarden EncString type 2: AES-256-CBC + HMAC-SHA256."""
    enc_key, mac_key = key64[:32], key64[32:]
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    mac = hmac_mod.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def enc_type4(public_key, plaintext: bytes) -> str:
    """Bitwarden EncString type 4: RSA-OAEP-SHA1."""
    ct = public_key.encrypt(
        plaintext, apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    )
    return f"4.{b64(ct)}"


# ---------------------------------------------------------------- fixture

class Fixture:
    """All key material + EncStrings for the manifest, built once."""

    def __init__(self, manifest: dict):
        acct = manifest["account"]
        self.manifest = manifest
        self.email = acct["email"]
        self.password = acct["password"]
        self.iterations = acct["kdf_iterations"]
        master = derive_master(self.password, self.email, self.iterations)
        self.stretched = stretch(master)
        self.auth_hash = password_hash(master, self.password)

        self.user_key = os.urandom(64)
        self.protected_user_key = enc_type2(self.stretched, self.user_key)

        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        pkcs8 = self.private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        self.protected_private_key = enc_type2(self.user_key, pkcs8)
        self.public_key_b64 = b64(
            self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )

        self.org_key = os.urandom(64)
        # Profile / org-creation form: org key under the owner's RSA key.
        self.protected_org_key = enc_type4(self.public_key, self.org_key)

        org = manifest["organization"]
        self.org_id = str(uuid.uuid4())
        self.collection_id = str(uuid.uuid4())
        self.protected_collection_name = enc_type2(self.org_key, org["collection_name"].encode())

    def cipher_payload(self, item: dict) -> dict:
        """One cipher in /api/sync (and POST /api/ciphers) shape."""
        if item["cipher_key"]:
            cipher_key = os.urandom(64)
            field_key = cipher_key
            protected_cipher_key = enc_type2(self.org_key, cipher_key)
        else:
            field_key = self.org_key
            protected_cipher_key = None
        return {
            "id": str(uuid.uuid4()),
            "type": 1,
            "organizationId": self.org_id,
            "collectionIds": [self.collection_id],
            "name": enc_type2(field_key, item["name"].encode()),
            "key": protected_cipher_key,
            "login": {
                "username": enc_type2(field_key, item["username"].encode()),
                "password": enc_type2(field_key, item["password"].encode()),
                "uris": [{"uri": enc_type2(field_key, item["uri"].encode()), "match": None}],
            },
        }

    def sync_payload(self) -> dict:
        """A GET /api/sync-shaped document for the offline tests."""
        org = self.manifest["organization"]
        return {
            "profile": {
                "id": str(uuid.uuid4()),
                "name": self.manifest["account"]["name"],
                "email": self.email,
                "key": self.protected_user_key,
                "privateKey": self.protected_private_key,
                "organizations": [
                    {"id": self.org_id, "name": org["name"], "key": self.protected_org_key}
                ],
            },
            "collections": [
                {
                    "id": self.collection_id,
                    "organizationId": self.org_id,
                    "name": self.protected_collection_name,
                }
            ],
            "ciphers": [self.cipher_payload(item) for item in self.manifest["items"]],
        }


# ---------------------------------------------------------------- live API

def tls_context(ca_cert: str = None):
    """SSL context trusting the fixture's throwaway self-signed cert.

    None when no CA is given (plain system trust — e.g. a future
    real-cert deployment); the fixture always passes its cert.
    """
    if not ca_cert:
        return None
    return ssl.create_default_context(cafile=ca_cert)


def http_json(method: str, url: str, body=None, token: str = None, form: bool = False,
              context=None):
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
    req.add_header("Device-Type", "9")  # 9 = CLI, as official clients send
    req.add_header("Bitwarden-Client-Name", "kharon-fixture-seed")
    with urllib.request.urlopen(req, timeout=30, context=context) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def wait_ready(base: str, timeout_s: int = 60, context=None) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/alive", timeout=5, context=context) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(1)
    raise SystemExit(f"Vaultwarden at {base} did not become ready in {timeout_s}s")


def seed_live(base: str, out_path: str, ca_cert: str = None) -> None:
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)
    fx = Fixture(manifest)
    ctx = tls_context(ca_cert)
    wait_ready(base, context=ctx)

    # 1. Register the fixture account.
    http_json(
        "POST",
        base + "/identity/accounts/register",
        {
            "email": fx.email,
            "name": manifest["account"]["name"],
            "masterPasswordHash": fx.auth_hash,
            "masterPasswordHint": None,
            "key": fx.protected_user_key,
            "keys": {
                "publicKey": fx.public_key_b64,
                "encryptedPrivateKey": fx.protected_private_key,
            },
            "kdf": manifest["account"]["kdf"],
            "kdfIterations": fx.iterations,
        },
        context=ctx,
    )

    # 2. Password-grant token (official-client flow).
    tok = http_json(
        "POST",
        base + "/identity/connect/token",
        {
            "grant_type": "password",
            "username": fx.email,
            "password": fx.auth_hash,
            "scope": "api offline_access",
            "client_id": "cli",
            "deviceType": "9",
            "deviceName": "kharon-fixture-seed",
            "deviceIdentifier": str(uuid.uuid4()),
        },
        form=True,
        context=ctx,
    )
    token = tok["access_token"]

    # 3. Create the organization (default collection comes with it).
    org = manifest["organization"]
    created = http_json(
        "POST",
        base + "/api/organizations",
        {
            "name": org["name"],
            "billingEmail": fx.email,
            "planType": 0,
            # Official clients send collectionName as an EncString
            # under the new org key (OrganizationCreateRequest); the
            # server stores it verbatim and sync hands it back, so a
            # plaintext name would be undecryptable downstream.
            "collectionName": fx.protected_collection_name,
            "key": fx.protected_org_key,
        },
        token=token,
        context=ctx,
    )
    org_id = created.get("id") or created.get("Id")
    if not org_id:
        raise SystemExit(f"organization creation returned no id: {created}")

    # Resolve the real org / collection IDs from a sync.
    sync = http_json("GET", base + "/api/sync", token=token, context=ctx)
    collections = [c for c in sync.get("collections", []) if c.get("organizationId") == org_id]
    if not collections:
        raise SystemExit("sync after org creation shows no collection for the fixture org")
    collection_id = collections[0]["id"]

    # 4. Create both ciphers through POST /api/ciphers/create — the
    # endpoint official clients use for org ciphers, which takes
    # {cipher, collectionIds}; plain POST /api/ciphers does not apply
    # collection membership (review on PR #44). The Rust decrypt test
    # asserts every captured cipher carries the fixture collection.
    for item in manifest["items"]:
        payload = fx.cipher_payload(item)
        payload.pop("id", None)
        payload.pop("collectionIds", None)
        payload["organizationId"] = org_id
        http_json(
            "POST",
            base + "/api/ciphers/create",
            {"cipher": payload, "collectionIds": [collection_id]},
            token=token,
            context=ctx,
        )

    # 5. Capture the sync payload the live Rust test will decrypt.
    sync = http_json("GET", base + "/api/sync", token=token, context=ctx)
    with open(out_path, "w") as f:
        json.dump(sync, f, indent=2)
    print(f"seeded {base}; sync captured to {out_path}")


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", action="store_true", help="write a sync-shaped fixture payload")
    mode.add_argument("--live", action="store_true", help="seed a running Vaultwarden, capture sync")
    ap.add_argument("--base-url", default="https://127.0.0.1:8222")
    ap.add_argument(
        "--ca-cert",
        default=os.environ.get("KHARON_FIXTURE_CA_CERT"),
        help="CA cert to trust for the live server (the fixture's "
        "throwaway self-signed cert); default: $KHARON_FIXTURE_CA_CERT",
    )
    ap.add_argument("--out", default=os.path.join(HERE, "sync_fixture.json"))
    args = ap.parse_args()

    if args.offline:
        with open(MANIFEST_PATH) as f:
            manifest = json.load(f)
        payload = Fixture(manifest).sync_payload()
        with open(args.out, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"offline sync fixture written to {args.out}")
        return 0
    seed_live(args.base_url, args.out, ca_cert=args.ca_cert)
    return 0


if __name__ == "__main__":
    sys.exit(main())
