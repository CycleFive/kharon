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

#[tokio::test]
async fn nothing_typed_reaches_the_file_or_the_output() {
    let Some(p) = support::run_program("whole_program_no_typed_value", "/form").await else {
        return;
    };
    assert_eq!(p.exit, kharon_teach::Exit::Done, "{}", p.stderr);
    assert_eq!(p.file_mode, 0o600);
    assert!(p.file_text.contains("\"value_len\""), "the file is empty");
    assert!(p.stdout.contains(&p.path.display().to_string()));
    for text in [&p.file_text, &p.stdout, &p.stderr] {
        assert_holds_no_typed_value(text, &[USER, PASS]);
    }
}
