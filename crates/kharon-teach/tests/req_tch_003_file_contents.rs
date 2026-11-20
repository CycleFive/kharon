//! SPEC req_tch_003: the file holds only what the spec keeps.

mod support;

use kharon_recording::Recording;
use support::{COOKIE_VALUE, run_program};

const NEXT_VALUE: &str = "secret-next-value";

#[tokio::test]
async fn the_file_is_0600_and_holds_only_what_the_spec_keeps() {
    let Some(p) = run_program("file_contents", &format!("/form?next=/{NEXT_VALUE}")).await else {
        return;
    };
    assert_eq!(p.exit, kharon_teach::Exit::Done, "{}", p.stderr);
    assert_eq!(p.file_mode, 0o600);
    let text = &p.file_text;
    let rec = Recording::from_json(text).expect("the file reads back");
    // Query keys are kept, their values are not.
    let keys_kept = std::iter::once(&rec.start_url)
        .chain(rec.requests.iter().map(|r| &r.url))
        .any(|u| u.query_keys.iter().any(|k| k == "next"));
    assert!(keys_kept, "the query key `next` was not kept");
    assert!(!text.contains(NEXT_VALUE), "a query value is in the file");
    // No cookie, no response body, no page title.
    assert!(
        !text.contains(COOKIE_VALUE),
        "a cookie value is in the file"
    );
    assert!(!text.contains("sid="), "a cookie is in the file");
    assert!(!text.contains("signed in"), "response text is in the file");
    for title in ["<title>", ">form<", "\"home\"", "step one"] {
        assert!(
            !text.contains(title),
            "a page title is in the file: {title}"
        );
    }
    // Headers are reduced to the content type: no other header the fixture and the browser
    // exchanged is in the file, by name or by value.
    let lower = text.to_ascii_lowercase();
    for header in [
        "set-cookie",
        "user-agent",
        "referer",
        "accept-language",
        "accept-encoding",
        "content-length",
        "location",
        "\"cookie\"",
    ] {
        assert!(!lower.contains(header), "header {header} is in the file");
    }
    // The cookie was set by the response, and the file says only that it was.
    let login = rec
        .requests
        .iter()
        .find(|r| r.url.path == "/form-login")
        .expect("the sign-in request was stored");
    assert!(
        login.response.as_ref().is_some_and(|r| r.set_cookie),
        "the response's Set-Cookie was not noted as a flag"
    );
}
