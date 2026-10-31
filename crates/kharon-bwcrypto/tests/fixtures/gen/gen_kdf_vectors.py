#!/usr/bin/env python3
"""Regenerate the REQ-CRY-001 test vectors in `src/kdf.rs`.

Independent implementations only — nothing here uses this crate:
PBKDF2 via `hashlib`, Argon2id via `argon2-cffi` (libargon2), and a
hand-rolled RFC 5869 HKDF-Expand over `hmac` for the stretch and
auth-hash vectors.

Pinned environment (Python 3.12):
    pip install "argon2-cffi==23.1.0"

Run:  python3 gen_kdf_vectors.py
Prints each vector and asserts it equals the constant in `src/kdf.rs`.
"""
import hashlib
import hmac as hmac_mod

from argon2 import low_level

EMAIL = b"kharon-fixture@example.com"  # salt form: trimmed + lowercased
PASSWORD = b"kharon fixture password 7"

EXPECTED_PBKDF2 = "5ea111139336d17e265f1935527ead750c0f9007e7a054a050d1fca0730ec549"
EXPECTED_ARGON2ID = "30773da8d8818c524e69c134da04b0ff9fd8af72c816c44b9211b21afa68a0ff"
EXPECTED_STRETCH = (
    "0f113f396c5d8779a46cdff12bdd14c22a795094f860de7eb03abb6153947956"
    "ea313c0287d85245fb601197f09d2d2203911a0f03d1206c8642378625ddd4c6"
)
EXPECTED_PWHASH = "9ccb246223d23dcb09ba04d15859b49fd89acfee120874de8edbfe28ccf79f9b"


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def main() -> None:
    # PBKDF2-HMAC-SHA256, 123 456 iterations (non-default on purpose).
    master_pbkdf2 = hashlib.pbkdf2_hmac("sha256", PASSWORD, EMAIL, 123_456, 32)
    print("pbkdf2 master key:  ", master_pbkdf2.hex())
    assert master_pbkdf2.hex() == EXPECTED_PBKDF2

    # Argon2id v0x13, salt = SHA-256(email), m = 32 MiB, t = 2, p = 2
    # (all non-default on purpose).
    salt = hashlib.sha256(EMAIL).digest()
    master_argon2 = low_level.hash_secret_raw(
        PASSWORD,
        salt,
        time_cost=2,
        memory_cost=32 * 1024,  # KiB
        parallelism=2,
        hash_len=32,
        type=low_level.Type.ID,
        version=19,  # 0x13
    )
    print("argon2id master key:", master_argon2.hex())
    assert master_argon2.hex() == EXPECTED_ARGON2ID

    # Stretch of the PBKDF2 master key: HKDF-Expand only, enc || mac.
    stretched = hkdf_expand(master_pbkdf2, b"enc") + hkdf_expand(master_pbkdf2, b"mac")
    print("stretched key:      ", stretched.hex())
    assert stretched.hex() == EXPECTED_STRETCH

    # Server auth hash: PBKDF2(master key, salt = password, 1).
    pw_hash = hashlib.pbkdf2_hmac("sha256", master_pbkdf2, PASSWORD, 1, 32)
    print("password hash:      ", pw_hash.hex())
    assert pw_hash.hex() == EXPECTED_PWHASH

    print("all REQ-CRY-001 vectors reproduce the constants in src/kdf.rs")


if __name__ == "__main__":
    main()
