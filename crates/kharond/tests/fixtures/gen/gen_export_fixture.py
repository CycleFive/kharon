#!/usr/bin/env python3
"""Regenerate the REQ-EXP-* fixtures and the bwcrypto export vectors.

Independent implementations only — nothing here uses the kharon crates:
PBKDF2 via `hashlib`, Argon2id via `argon2-cffi` (libargon2), a
hand-rolled RFC 5869 HKDF-Expand over `hmac` for the stretch, and
AES-256-CBC + HMAC-SHA256 (EncString type 2) via `cryptography`
(OpenSSL).

The export envelope mirrors the official clients' password-protected
export (Bitwarden help centre, "Encrypted Exports": the password is
salted, derived with the file's KDF settings, then stretched with HKDF
into the encryption + MAC keys):

    {
      "encrypted": true, "passwordProtected": true,
      "salt": <base64 string, used verbatim as the KDF salt string>,
      "kdfType": 0, "kdfIterations": 123456,
      "kdfMemory": null, "kdfParallelism": null,
      "encKeyValidation_DO_NOT_EDIT": "2.<iv>|<ct>|<mac>",
      "data": "2.<iv>|<ct>|<mac>"
    }

`encKeyValidation_DO_NOT_EDIT` encrypts a GUID string; `data` encrypts
the plaintext export JSON (folders/items with cleartext fields).

Pinned environment (Python 3.12):
    pip install "cryptography==43.0.3" "argon2-cffi==23.1.0"

Run:  python3 gen_export_fixture.py [--write]
Prints the bwcrypto vectors (for `src/kdf.rs` / `src/encstring.rs`
tests); with --write also (re)writes the two fixture files next to
this script in ../export/.
"""
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PASSWORD = "kharon export fixture password 9"
SALT = base64.b64encode(b"kharon-export-16").decode()  # a2hhcm9uLWV4cG9ydC0xNg==
KDF_ITERATIONS = 123_456  # non-default on purpose, like the REQ-CRY-001 vectors
VALIDATION_GUID = "01234567-89ab-cdef-0123-456789abcdef"

IV_VALIDATION = bytes(range(0x10, 0x20))
IV_DATA_A = bytes(range(0x20, 0x30))
IV_DATA_B = bytes(range(0x30, 0x40))
IV_DATA_C = bytes(range(0x40, 0x50))

# A password containing the two characters that force JSON string
# escapes on the owner socket (`"` and `\`): the fixture for the
# REQ-MEM-003 escaped-password canary case (PR #81 review, item 7 —
# a serde escape-decoding scratch copy of this password must never
# survive in daemon memory).
ESCAPED_PASSWORD = "kharon \"escape\" \\ fixture 9"


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, c = b"", b"", 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        out += t
        c += 1
    return out[:length]


def stretch(key32: bytes) -> bytes:
    return hkdf_expand(key32, b"enc", 32) + hkdf_expand(key32, b"mac", 32)


def derive_pbkdf2(password: str, salt: str, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), iterations, 32
    )


def derive_argon2id(password: str, salt: str, t: int, m_mib: int, p: int) -> bytes:
    argon_salt = hashlib.sha256(salt.encode()).digest()
    return hash_secret_raw(
        password.encode(),
        argon_salt,
        time_cost=t,
        memory_cost=m_mib * 1024,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
        version=0x13,
    )


def enc_string(plaintext: bytes, key64: bytes, iv: bytes) -> str:
    enc_key, mac_key = key64[:32], key64[32:]
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = hmac_mod.new(mac_key, iv + ct, hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def export_file(data_obj: dict, iv_data: bytes, password: str = PASSWORD) -> dict:
    key = stretch(derive_pbkdf2(password, SALT, KDF_ITERATIONS))
    return {
        "encrypted": True,
        "passwordProtected": True,
        "salt": SALT,
        "kdfType": 0,
        "kdfIterations": KDF_ITERATIONS,
        "kdfMemory": None,
        "kdfParallelism": None,
        "encKeyValidation_DO_NOT_EDIT": enc_string(
            VALIDATION_GUID.encode(), key, IV_VALIDATION
        ),
        "data": enc_string(
            json.dumps(data_obj, separators=(",", ":")).encode(), key, iv_data
        ),
    }


ITEM_LOGIN_1 = {
    "id": "aaaaaaaa-1111-4000-8000-000000000001",
    "organizationId": None,
    "folderId": "ffffffff-1111-4000-8000-000000000001",
    "type": 1,
    "reprompt": 0,
    "name": "Example Login",
    "notes": "fixture note (not carried into the vault)",
    "favorite": False,
    "login": {
        "uris": [
            {"match": None, "uri": "https://example.com/login"},
            {"match": 1, "uri": "https://example.com/"},
        ],
        "username": "fixture@example.net",
        "password": "CANARY-EXPORT-PASSWORD-7f3a",
        "totp": "JBSWY3DPEHPK3PXP",
    },
    "collectionIds": None,
    "revisionDate": "2026-01-02T03:04:05.000Z",
    "creationDate": "2026-01-01T00:00:00.000Z",
    "deletedDate": None,
    "fields": [
        {"name": "hidden-fixture", "value": "CANARY-HIDDEN-FIELD-9c1d",
         "type": 1, "linkedId": None}
    ],
}

ITEM_LOGIN_2 = {
    "id": "aaaaaaaa-2222-4000-8000-000000000002",
    "organizationId": None,
    "folderId": None,
    "type": 1,
    "reprompt": 0,
    "name": "Second Login",
    "notes": None,
    "favorite": False,
    "login": {
        "uris": [],
        "username": None,
        "password": "second-password-123",
        "totp": None,
    },
    "collectionIds": None,
    "revisionDate": None,
    "creationDate": "2026-01-01T00:00:00.000Z",
    "deletedDate": None,
}

ITEM_NOTE = {
    "id": "aaaaaaaa-3333-4000-8000-000000000003",
    "organizationId": None,
    "folderId": None,
    "type": 2,
    "reprompt": 0,
    "name": "Fixture Note",
    "notes": "a secure note (not a login; the loader skips it)",
    "favorite": False,
    "secureNote": {"type": 0},
    "collectionIds": None,
    "revisionDate": None,
    "creationDate": "2026-01-01T00:00:00.000Z",
    "deletedDate": None,
}

DATA_A = {
    "folders": [{"id": "ffffffff-1111-4000-8000-000000000001",
                 "name": "Fixture Folder"}],
    "items": [ITEM_LOGIN_1, ITEM_LOGIN_2, ITEM_NOTE],
}

DATA_B = {
    "folders": [],
    "items": [
        {
            "id": "aaaaaaaa-1010-4000-8000-000000000010",
            "organizationId": None,
            "folderId": None,
            "type": 1,
            "reprompt": 0,
            "name": "Replaced Login",
            "notes": None,
            "favorite": False,
            "login": {
                "uris": [{"match": None, "uri": "https://replaced.example/"}],
                "username": "replaced@example.net",
                "password": "replaced-password-456",
                "totp": None,
            },
            "collectionIds": None,
            "revisionDate": "2026-02-03T04:05:06.000Z",
            "creationDate": "2026-02-01T00:00:00.000Z",
            "deletedDate": None,
        }
    ],
}


def main() -> None:
    key_pbkdf2 = stretch(derive_pbkdf2(PASSWORD, SALT, KDF_ITERATIONS))
    print("export PBKDF2 stretched key:", key_pbkdf2.hex())
    key_argon = stretch(derive_argon2id(PASSWORD, SALT, t=2, m_mib=32, p=2))
    print("export Argon2id (m=32,t=2,p=2) stretched key:", key_argon.hex())

    vec_key = bytes(range(64))
    vec_iv = bytes(range(0xA0, 0xB0))
    vec = enc_string(b"kharon type-2 encrypt vector", vec_key, vec_iv)
    print("type-2 encrypt vector:", vec)

    if "--write" in sys.argv:
        out_dir = os.path.join(os.path.dirname(__file__), "..", "export")
        for name, obj, iv, pw in [
            ("password_protected.json", DATA_A, IV_DATA_A, PASSWORD),
            ("password_protected_replaced.json", DATA_B, IV_DATA_B, PASSWORD),
            ("password_protected_escaped.json", DATA_A, IV_DATA_C, ESCAPED_PASSWORD),
        ]:
            path = os.path.join(out_dir, name)
            with open(path, "w") as f:
                json.dump(export_file(obj, iv, pw), f, indent=2)
                f.write("\n")
            print("wrote", path)


if __name__ == "__main__":
    main()
