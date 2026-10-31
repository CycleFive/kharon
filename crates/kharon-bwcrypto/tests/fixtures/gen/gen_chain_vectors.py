#!/usr/bin/env python3
"""Regenerate / verify the REQ-CRY-004 chain vectors in `src/keys.rs`.

Independent implementations only — nothing here uses this crate:
AES-256-CBC + HMAC-SHA256 (type 2) and RSA-OAEP-SHA1 (type 4) via
`cryptography` (OpenSSL). The RSA key is the throwaway fixture
`../chain-throwaway-key.pem`, generated for these tests only.

Pinned environment (Python 3.12):
    pip install "cryptography==43.0.3"

Run:  python3 gen_chain_vectors.py
The type-2 constants are deterministic (fixed IVs) and are reproduced
byte-for-byte. Type 4 OAEP encryption is randomized, so the committed
org-key ciphertext is verified by decryption and a fresh equivalent
ciphertext is printed.
"""
import base64
import hashlib
import hmac as hmac_mod
import os
import re

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_PEM = os.path.join(HERE, "..", "chain-throwaway-key.pem")
KEYS_RS = os.path.join(HERE, "..", "..", "..", "src", "keys.rs")

# The stretched master key from gen_kdf_vectors.py (PBKDF2 fixture).
STRETCHED = bytes.fromhex(
    "0f113f396c5d8779a46cdff12bdd14c22a795094f860de7eb03abb6153947956"
    "ea313c0287d85245fb601197f09d2d2203911a0f03d1206c8642378625ddd4c6"
)


def byte_range(start: int) -> bytes:
    """Plaintext keys are sequential byte ranges, as in the tests."""
    return bytes((start + i) % 256 for i in range(64))


def enc_type2(key64: bytes, iv: bytes, plaintext: bytes) -> str:
    enc_key, mac_key = key64[:32], key64[32:]
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    mac = hmac_mod.new(mac_key, iv + ct, hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def committed_constant(name: str) -> str:
    src = open(KEYS_RS).read()
    return re.search(rf'const {name}: &str = "([^"]+)"', src).group(1)


def iv_of(encstring: str) -> bytes:
    return base64.b64decode(encstring.split("|")[0].split(".")[1])


def check(name: str, reproduced: str) -> None:
    committed = committed_constant(name)
    assert reproduced == committed, f"{name} MISMATCH"
    print(f"{name}: reproduces byte-for-byte")


def main() -> None:
    private_key = load_pem_private_key(open(KEY_PEM, "rb").read(), None)
    der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

    user_key, org_key, cipher_key = byte_range(0x40), byte_range(0x80), byte_range(0xC0)

    check(
        "PROTECTED_USER_KEY",
        enc_type2(STRETCHED, iv_of(committed_constant("PROTECTED_USER_KEY")), user_key),
    )
    check(
        "PROTECTED_PRIVATE_KEY",
        enc_type2(user_key, iv_of(committed_constant("PROTECTED_PRIVATE_KEY")), der),
    )
    check(
        "FIELD_NO_CIPHER_KEY",
        enc_type2(
            org_key,
            iv_of(committed_constant("FIELD_NO_CIPHER_KEY")),
            b"fixture-item-password-123",
        ),
    )
    check(
        "PROTECTED_CIPHER_KEY",
        enc_type2(org_key, iv_of(committed_constant("PROTECTED_CIPHER_KEY")), cipher_key),
    )
    check(
        "FIELD_WITH_CIPHER_KEY",
        enc_type2(
            cipher_key,
            iv_of(committed_constant("FIELD_WITH_CIPHER_KEY")),
            b"cipher-key-item-password-456",
        ),
    )

    # Type 4: OAEP is randomized — verify the committed ciphertext
    # decrypts to the org key, and print a fresh equivalent.
    committed_org = committed_constant("PROTECTED_ORG_KEY")
    oaep = apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
    pt = private_key.decrypt(base64.b64decode(committed_org.split(".")[1]), oaep)
    assert pt == org_key, "PROTECTED_ORG_KEY decrypts to unexpected bytes"
    print("PROTECTED_ORG_KEY: committed ciphertext decrypts to the org key")
    fresh = private_key.public_key().encrypt(org_key, oaep)
    print("fresh equivalent: 4." + base64.b64encode(fresh).decode())

    print("all REQ-CRY-004 vectors verified against src/keys.rs")


if __name__ == "__main__":
    main()
