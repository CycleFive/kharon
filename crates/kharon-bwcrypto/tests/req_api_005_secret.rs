//! REQ-API-005: `Secret` does not implement `Serialize`/`Debug`/`Display`.

#[test]
fn req_api_005_secret_is_not_serialize_debug_or_display() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/req_api_005_*.rs");
}
