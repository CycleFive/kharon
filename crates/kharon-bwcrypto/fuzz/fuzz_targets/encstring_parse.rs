#![no_main]

//! REQ-CRY-002 acceptance: the EncString parser must never panic on
//! arbitrary input, and neither may a decrypt attempt on anything that
//! parses. Run with:
//! `cargo fuzz run encstring_parse -- -max_total_time=600`

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(parsed) = kharon_bwcrypto::EncString::parse(s) {
            // Fixed, non-secret fuzz key (bytes 0x00..0x40), matching the
            // unit tests: exercise the MAC-verify + CBC path, not just
            // the parser (extended per Nyx's review on PR #33).
            let key_bytes: Vec<u8> = (0u8..64).collect();
            if let Ok(key) = kharon_bwcrypto::SymmetricKey::from_slice(&key_bytes) {
                let _ = parsed.decrypt_symmetric(&key);
            }
        }
    }
});
