#!/usr/bin/env python3
"""Mutate the live kharon Vaultwarden fixture as the web vault would
(issue #9, REQ-CRY-009 / REQ-CRY-008 live tests).

Logs in as the fixture account with the password grant (like a web
vault or CLI device), recovers the org key client-side, and performs
one change through the official API endpoints, so Vaultwarden emits
the same notifications-hub pushes it would for a human editing in
the web vault:

  add --name N            new login in the fixture collection
                          (pushes SyncCipherCreate); prints {"id": ...}
      [--username U --uri URI --password-env VAR]
                          ... with these login fields instead of the
                          push-test defaults; the password is read from
                          the environment variable VAR, never argv (the
                          compose E2E's canary item, issue #24)
  edit --id ID --name N   rename it (pushes SyncCipherUpdate)
  delete --id ID          hard delete (pushes SyncCipherDelete)
  add-org                 create a SECOND org owned by the account,
                          widening its scope (REQ-CRY-008). This is
                          irreversible for the fixture: run it last.

Reuses seed.py's crypto and HTTP helpers. Fixture-only credentials;
nothing secret is printed.
"""
import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import sys
import uuid

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_private_key

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from seed import (  # noqa: E402
    MANIFEST_PATH,
    b64,
    derive_master,
    enc_type2,
    enc_type4,
    http_json,
    password_hash,
    stretch,
    tls_context,
)


def dec_type2(key64: bytes, enc: str) -> bytes:
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


def dec_type4(private_key, enc: str) -> bytes:
    kind, rest = enc.split(".", 1)
    if kind != "4":
        raise SystemExit(f"expected a type-4 EncString, got type {kind}")
    return private_key.decrypt(
        base64.b64decode(rest),
        apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    )


def pick(d: dict, key: str):
    """Vaultwarden 1.33 answers camelCase; tolerate PascalCase too."""
    return d.get(key, d.get(key[0].upper() + key[1:]))


class Session:
    def __init__(self, base: str, ca_cert: str):
        with open(MANIFEST_PATH) as f:
            self.manifest = json.load(f)
        acct = self.manifest["account"]
        self.base = base
        self.ctx = tls_context(ca_cert)
        master = derive_master(acct["password"], acct["email"], acct["kdf_iterations"])
        stretched = stretch(master)
        tok = http_json(
            "POST",
            base + "/identity/connect/token",
            {
                "grant_type": "password",
                "username": acct["email"],
                "password": password_hash(master, acct["password"]),
                "scope": "api offline_access",
                "client_id": "cli",
                "deviceType": "9",
                "deviceName": "kharon-fixture-mutate",
                "deviceIdentifier": str(uuid.uuid4()),
            },
            form=True,
            context=self.ctx,
        )
        self.token = tok["access_token"]
        sync = self.get("/api/sync")
        profile = pick(sync, "profile")
        user_key = dec_type2(stretched, pick(profile, "key"))
        self.private_key = load_der_private_key(
            dec_type2(user_key, pick(profile, "privateKey")), password=None
        )
        self.public_key = self.private_key.public_key()
        org = pick(profile, "organizations")[0]
        self.org_id = pick(org, "id")
        self.org_key = dec_type4(self.private_key, pick(org, "key"))
        colls = [c for c in pick(sync, "collections") if pick(c, "organizationId") == self.org_id]
        self.collection_id = pick(colls[0], "id")

    def get(self, path):
        return http_json("GET", self.base + path, token=self.token, context=self.ctx)

    def call(self, method, path, body=None):
        return http_json(method, self.base + path, body, token=self.token, context=self.ctx)

    def cipher(self, name: str, username: bytes = b"push-user",
               password: bytes = b"push-password",
               uri: str = "https://push.example.test/login") -> dict:
        k = self.org_key
        return {
            "type": 1,
            "organizationId": self.org_id,
            "name": enc_type2(k, name.encode()),
            "key": None,
            "login": {
                "username": enc_type2(k, username),
                "password": enc_type2(k, password),
                "uris": [{
                    "uri": enc_type2(k, uri.encode()),
                    "uriChecksum": enc_type2(
                        k, b64(hashlib.sha256(uri.encode()).digest()).encode()),
                    "match": None,
                }],
            },
        }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=os.environ.get(
        "KHARON_FIXTURE_BASE_URL", "https://127.0.0.1:8222"))
    ap.add_argument("--ca-cert", default=os.environ.get("KHARON_FIXTURE_CA_CERT"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("--name", required=True)
    a.add_argument("--username")
    a.add_argument("--uri")
    a.add_argument("--password-env", metavar="VAR")
    e = sub.add_parser("edit")
    e.add_argument("--id", required=True)
    e.add_argument("--name", required=True)
    d = sub.add_parser("delete")
    d.add_argument("--id", required=True)
    sub.add_parser("add-org")
    args = ap.parse_args()

    s = Session(args.base_url.rstrip("/"), args.ca_cert)
    if args.cmd == "add":
        login = {}
        if args.username is not None:
            login["username"] = args.username.encode()
        if args.uri is not None:
            login["uri"] = args.uri
        if args.password_env is not None:
            password = os.environ.get(args.password_env)
            if not password:
                raise SystemExit(f"{args.password_env} is not set")
            login["password"] = password.encode()
        created = s.call("POST", "/api/ciphers/create",
                         {"cipher": s.cipher(args.name, **login),
                          "collectionIds": [s.collection_id]})
        print(json.dumps({"id": pick(created, "id")}))
    elif args.cmd == "edit":
        s.call("PUT", f"/api/ciphers/{args.id}", s.cipher(args.name))
        print(json.dumps({"id": args.id}))
    elif args.cmd == "delete":
        s.call("DELETE", f"/api/ciphers/{args.id}")
        print(json.dumps({"id": args.id}))
    elif args.cmd == "add-org":
        org_key = os.urandom(64)
        created = s.call("POST", "/api/organizations", {
            "name": "kharon second org",
            "billingEmail": s.manifest["account"]["email"],
            "planType": 0,
            "collectionName": enc_type2(org_key, b"second"),
            "key": enc_type4(s.public_key, org_key),
        })
        print(json.dumps({"id": pick(created, "id")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
