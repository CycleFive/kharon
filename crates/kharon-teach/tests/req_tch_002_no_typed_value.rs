//! SPEC req_tch_002: nothing a person typed reaches the recording.

mod support;

use kharon_teach::testing::assert_holds_no_typed_value;
use support::{Login, PASS, USER, record_login};

#[tokio::test]
async fn no_typed_value_in_the_recording_for_any_fixture() {
    for (name, which) in [
        ("form", Login::Form),
        ("script", Login::Script),
        ("two_step", Login::TwoStep),
        ("hashed", Login::Hashed),
    ] {
        let Some(r) = record_login(&format!("no_typed_value_{name}"), which).await else {
            return;
        };
        let json = r.to_json();
        // The file is a real one: the typed fields are in it as lengths, not as text.
        assert!(json.contains("\"value_len\""), "{name}: no input steps");
        assert_holds_no_typed_value(&json, &[USER, PASS]);
    }
}
