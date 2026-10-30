#![no_main]

//! REQ-CRY-002 acceptance: the EncString parser must never panic on
//! arbitrary input. Run with:
//! `cargo fuzz run encstring_parse -- -max_total_time=600`

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = kharon_bwcrypto::EncString::parse(s);
    }
});
