//! SPEC req_tch_002: nothing a person typed reaches the recording.

mod support;

use kharon_teach::session::{End, Outcome};
use kharon_teach::testing::assert_holds_no_typed_value;
use support::{Login, PASS, Run, USER, record_login};

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

/// The typed values are in text the recording KEEPS: the next page's path and query key, and the
/// key of the JSON body. They must be stripped there, not merely absent from the values. This
/// fails if `strip_url` or the name check returned its input unchanged.
#[tokio::test]
async fn typed_values_in_a_url_and_a_json_key_are_stripped_from_kept_text() {
    use kharon_recording::{BodyShape, JsonShape, Role, Step};
    let Some(run) = Run::start("typed_in_text", "/typed").await else {
        return;
    };
    run.begin("/typed").await;
    run.person.type_into("input[name=user]", USER).await;
    run.person.type_into("input[name=pass]", PASS).await;
    run.person.click("#go").await;
    run.person.wait_for_path(&format!("/u/{USER}")).await;
    let Outcome::Recorded(r) = run.finish(End::Confirmed).await else {
        panic!("expected a recording");
    };
    assert_holds_no_typed_value(&r.to_json(), &[USER, PASS]);

    // The navigation to /u/<user>?<user>=1 is in the file, with both typed places replaced.
    let moved = |url: &kharon_recording::StrippedUrl| {
        url.path == "/u/{id}" && url.query_keys == ["{typed}"]
    };
    assert!(
        r.steps
            .iter()
            .any(|s| matches!(s, Step::Navigation { url, .. } if moved(url))),
        "no navigation step with the typed path replaced"
    );
    assert!(r.requests.iter().any(|q| moved(&q.url)));
    assert!(r.final_url.as_ref().is_some_and(moved));

    // The login posts JSON keyed by the user name: the key is {typed} and its hit is not lost.
    let login = r
        .requests
        .iter()
        .find(|q| q.url.path == "/api/typed")
        .expect("the login request is stored");
    let BodyShape::Json {
        root: JsonShape::Object { fields },
    } = &login.body
    else {
        panic!("the body is not a JSON object");
    };
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].key, "{typed}");
    let hits = login.hits();
    assert!(hits.iter().any(|h| h.role == Role::Password));
    assert!(hits.iter().any(|h| h.role == Role::Username));
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

/// A page that copies what is typed into a field into the field's own `id` must not get it into
/// the recording through the descriptor or the selectors, not even on the Enter-key report and
/// not for a value of two characters (which no search for typed values can safely look for).
#[tokio::test]
async fn a_page_that_mirrors_the_value_into_an_attribute_leaks_nothing() {
    use kharon_recording::Step;
    let Some(run) = Run::start("mirror", "/mirror").await else {
        return;
    };
    run.begin("/mirror").await;
    run.person.type_into("input[name=user]", "q7").await;
    run.person.type_into("input[name=pass]", PASS).await;
    run.person.press_enter().await;
    run.person.wait_for_path("/home").await;
    let Outcome::Recorded(r) = run.finish(End::Confirmed).await else {
        panic!("expected a recording");
    };
    assert_holds_no_typed_value(&r.to_json(), &[PASS]);
    let mut seen = 0;
    for step in &r.steps {
        let element = match step {
            Step::Input { element, .. } | Step::EnterKey { element, .. } => element,
            _ => continue,
        };
        seen += 1;
        let texts = element
            .selectors
            .iter()
            .chain(element.id.iter())
            .chain(element.name.iter())
            .chain(element.autocomplete.iter());
        for t in texts {
            assert!(!t.contains("q7"), "a selector or attribute holds the value");
        }
        assert!(!element.selectors.is_empty(), "the field keeps a selector");
    }
    assert!(seen >= 3, "two inputs and the Enter key were recorded");
}

/// The listener itself, run in the page's main world with a stand-in binding, so the raw reports
/// can be read. Whatever the recorder later strips, the script must not send the typed text in
/// a descriptor or a selector.
#[tokio::test]
async fn the_listener_never_describes_an_element_by_what_was_typed_into_it() {
    use kharon_teach::events::ListenerReport;
    let Some(run) = Run::start("listener_raw", "/mirror").await else {
        return;
    };
    run.begin("/mirror").await;
    let source = kharon_teach::session::LISTENER_JS.replace("__NONCE__", "raw-test");
    let install = format!(
        "window.__reports=[];window.__kharonTeach=(p)=>{{window.__reports.push(p)}};\
         document.addEventListener('submit',(e)=>e.preventDefault(),true);{source}\n;'ok'"
    );
    assert_eq!(run.person.eval(&install).await.as_deref(), Some("ok"));
    run.person.type_into("input[name=user]", "q7").await;
    run.person.press_enter().await;
    let raw = run
        .person
        .eval("JSON.stringify(window.__reports)")
        .await
        .expect("the reports");
    let reports: Vec<String> = serde_json::from_str(&raw).unwrap();
    let mut seen = (0, 0);
    for r in &reports {
        let Ok(rep) = serde_json::from_str::<ListenerReport>(r) else {
            continue; // the hello
        };
        match rep.kind {
            kharon_teach::events::ReportKind::Input => seen.0 += 1,
            kharon_teach::events::ReportKind::EnterKey => seen.1 += 1,
            _ => {}
        }
        let e = &rep.element;
        let texts = e
            .selectors
            .iter()
            .chain(e.id.iter())
            .chain(e.name.iter())
            .chain(e.autocomplete.iter())
            .chain(e.placeholder.iter())
            .chain(e.aria_label.iter());
        for t in texts {
            assert!(
                !t.contains("q7"),
                "a descriptor or selector holds typed text"
            );
        }
        assert!(
            !e.selectors.is_empty(),
            "the field keeps a selector that does not hold it"
        );
    }
    assert!(
        seen.0 >= 1 && seen.1 >= 1,
        "an input and an Enter key were reported"
    );
    let _ = run.finish(End::Discard).await;
}
