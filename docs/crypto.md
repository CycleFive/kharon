# kharon-bwcrypto: the Bitwarden key chain, step by step

REQ-CRY-010: every crypto step kharon implements, with the source it was
written from. The normative in-repo summary is [SPEC §3.1](../SPEC.md);
the external sources are the Bitwarden Security Whitepaper, the
Bitwarden help/KDF documentation, the `bitwarden-crypto` SDK API docs,
and the RFC for each primitive. Code: `crates/kharon-bwcrypto`
(`kdf.rs`, `encstring.rs`, `keys.rs`).

| Step | Construction | Source |
|---|---|---|
| KDF params | `POST /identity/accounts/prelogin` → `{kdf, kdfIterations, kdfMemory, kdfParallelism}`; `kdf` 0 = PBKDF2, 1 = Argon2id; unknown types fail closed. The response is untrusted, so parameters are range-checked against Bitwarden's client bounds before derivation (`Kdf::validate`, re-checked in `derive_master_key`): PBKDF2 iterations 5 000–2 000 000 (5 000 is the hard client minimum, kept explicitly so legacy accounts below the current 600 000 default still work; below it the auth hash would be crackable at negligible cost), Argon2id t 2–10, m 16–1 024 MiB, p 1–16 (ceilings bound the CPU/memory a hostile prelogin can make the client burn) | [SPEC §3.1](../SPEC.md); [`bitwarden_crypto::Kdf`](https://sdk-api-docs.bitwarden.com/bitwarden_crypto/enum.Kdf.html); [KDF algorithms](https://bitwarden.com/help/kdf-algorithms/) |
| Master key, PBKDF2 (32 B) | PBKDF2-HMAC-SHA256(password, salt = lowercase(email), iterations; default 600 000) | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); [KDF algorithms](https://bitwarden.com/help/kdf-algorithms/); RFC 8018 (PBKDF2) |
| Master key, Argon2id (32 B) | Argon2id v0x13(password, salt = SHA-256(lowercase(email)), m, t, p; defaults m = 64 MiB, t = 3, p = 4). Prelogin `kdfMemory` is in MiB; converted to KiB for the primitive | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); [KDF algorithms](https://bitwarden.com/help/kdf-algorithms/); RFC 9106 (Argon2) |
| Stretched master key (64 B) | HKDF-Expand-SHA256(master key as PRK, info = `"enc"`, 32) ‖ HKDF-Expand-SHA256(master key, info = `"mac"`, 32). Expand only — the master key is already pseudorandom, so there is no extract step | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); RFC 5869 (HKDF) |
| Server auth hash | PBKDF2-HMAC-SHA256(master key, salt = password, 1 iteration). Not needed for API-key login; needed for password login and `/accounts/verify-password` | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); RFC 8018 |
| EncString type 2 | `2.<iv>\|<ct>\|<mac>`: AES-256-CBC with PKCS#7 padding; `mac = HMAC-SHA256(mac_key, iv ‖ ct)` (encrypt-then-MAC), verified in constant time **before** any decryption (REQ-CRY-003) | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); [SPEC §3.1](../SPEC.md) |
| EncString type 4 | `4.<ct>`: RSA-2048-OAEP with SHA-1 / MGF1-SHA-1 | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); RFC 8017 (RSA-OAEP) |
| User key (64 B: enc ‖ mac) | Sync/token response `Key`: type 2 under the stretched master key | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); [SPEC §3.1](../SPEC.md) |
| RSA private key | `PrivateKey`: PKCS#8 RSA-2048, type 2 under the user key | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); RFC 5208 (PKCS#8) |
| Org key (64 B) | `profile.organizations[].key`: type 4 under the account public key. Unwrapped **exactly once per unlock per org** and cached; after any type-4 failure, further type-4 unwraps are refused until the next unlock (RUSTSEC-2023-0071 mitigation, see `deny.toml`). Two further oracle bounds (PR #34 review): when the profile's organization list is known, unwraps are restricted to those IDs — unlisted orgs are refused *without* decrypting — and at most 16 distinct-org decrypts happen per unlock, exceeding which poisons the session. Org IDs are case-normalized (GUIDs) before cache/allow-list use. A cache hit presenting a *different* ciphertext returns the cached key without decrypting but flags the org (`ciphertext_mismatch`) for audit — rotation or server misbehaviour is never silent | [SPEC §3.1](../SPEC.md); kharon PR #33 review (Nyx); kharon PR #34 review (Nyx) |
| Cipher key (optional, per item) | `cipher.key`: type 2 under the org key. When present, the cipher's fields are under the cipher key instead of the org key | [SPEC §3.1](../SPEC.md) |
| Item fields | `name`, `login.username`, `login.password`, `login.totp`, `login.uris[].uri`, `notes`, `fields[]`: type 2 under the effective item key (cipher key if present, else org key) | [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/); [SPEC §3.1](../SPEC.md) |
| Unknown crypto | EncString types other than 2 and 4 (including type 7, account-cryptography v2) are rejected with a typed error — fail closed (OQ-8) | [SPEC §3.1](../SPEC.md) |

## Zeroization limits

What kharon wipes, and what it cannot (accepted limits, PR #34 review):

- The master password is passed as `&Zeroizing<String>`; the master
  key, stretched key, symmetric keys, and plaintext buffers are
  `Zeroizing` and wipe on drop. Argon2's working memory (the m-KiB
  block array derived from the password) is wiped because the
  `argon2` crate is built with its `zeroize` feature.
- Inside the RustCrypto KDF/HMAC constructions (PBKDF2, HKDF-Expand),
  internal states hold copies of the password / PRK that those crates
  do not expose zeroization hooks for. Those copies live for the
  duration of one derivation call and are freed un-wiped. This is the
  same posture as the reference clients; eliminating it would mean
  vendoring the primitives, which the own-crypto review (OQ-2) does
  not currently justify.

## Test vectors

Vectors are generated with independent implementations, never with this
crate (same rule as issue #6's OpenSSL/Python vectors). The generator
scripts are committed at `crates/kharon-bwcrypto/tests/fixtures/gen/`
(`gen_kdf_vectors.py`, `gen_chain_vectors.py`, pinned dependency
versions in their headers) and reproduce the committed constants —
"independent" is checkable, not just asserted:

- REQ-CRY-001: Python `hashlib.pbkdf2_hmac` (PBKDF2, 123 456 iterations —
  non-default), `argon2-cffi`/libargon2 (Argon2id, m = 32 MiB, t = 2,
  p = 2 — non-default), and a hand-rolled RFC 5869 HKDF-Expand over
  Python `hmac` for the stretch and auth-hash vectors.
- REQ-CRY-004: Python `cryptography` (OpenSSL) for AES-CBC type-2
  segments, the throwaway RSA fixture key
  (`crates/kharon-bwcrypto/tests/fixtures/chain-throwaway-key.pem`,
  test-only), and the RSA-OAEP-SHA1 type-4 org-key ciphertext. The
  chain test walks password → master key → user key → private key →
  org key → item field, with and without `cipher.key`.

Open item, stated plainly: the REQ-CRY-004 acceptance text also asks
for a live Vaultwarden fixture comparison against `bw get item`. That
needs a fixture server, which does not exist in this repo yet; the
independent-vector chain above is the offline half, and the live half
belongs with the sync-client work (REQ-CRY-005, issue #8) where a
fixture account first becomes reachable.
