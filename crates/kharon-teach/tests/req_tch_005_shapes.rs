//! SPEC req_tch_005: the recorder tells the shapes of login apart in a real browser.

mod support;

use kharon_recording::{
    EndedBy, ListenerWorld, PasswordLeg, Recording, ResourceKind, RungCeiling, Shape,
};
use kharon_teach::session::POST_DATA_FETCHES;
use kharon_teach::session::{End, Outcome};
use kharon_teach::testing::assert_holds_no_typed_value;
use support::{COOKIE_VALUE, Login, PASS, Run, USER, record_login};

#[tokio::test]
async fn form_page_classifies_as_form_post() {
    let Some(r) = record_login("form_page", Login::Form).await else {
        return;
    };
    let c = &r.classification;
    assert_eq!(c.shape, Shape::FormPost, "{:?}", c.notes);
    assert_eq!(c.rung_ceiling, RungCeiling::Milliseconds);
    assert!(c.network_swap_candidate);
    assert_eq!(r.ended_by, EndedBy::Confirmed);
    assert!(r.success_confirmed);
    assert_eq!(r.listener_world, ListenerWorld::Isolated);
    assert!(!r.browser.product.is_empty());
    assert!(r.browser.viewport.width > 0 && r.browser.viewport.height > 0);

    // The 302 that sets a cookie is stored with its response, and the cookie's value is not.
    let post = r
        .requests
        .iter()
        .find(|q| q.method == "POST" && q.url.path == "/form-login")
        .expect("the login POST is stored");
    assert_eq!(post.resource, ResourceKind::Document);
    let resp = post.response.as_ref().expect("the 302 is stored with it");
    assert_eq!(resp.status, 302);
    assert!(resp.set_cookie);
    assert!(!r.to_json().contains(COOKIE_VALUE));
}

#[tokio::test]
async fn script_page_classifies_as_script_post() {
    let Some(r) = record_login("script_page", Login::Script).await else {
        return;
    };
    assert_eq!(
        r.classification.shape,
        Shape::ScriptPost,
        "{:?}",
        r.classification.notes
    );
    assert_eq!(
        r.classification.rung_ceiling,
        RungCeiling::Milliseconds,
        "{:?}",
        r.classification.notes
    );
}

#[tokio::test]
async fn two_step_page_classifies_as_two_step() {
    let Some(r) = record_login("two_step_page", Login::TwoStep).await else {
        return;
    };
    let c = &r.classification;
    assert_eq!(
        c.shape,
        Shape::TwoStep {
            password_leg: PasswordLeg::FormPost
        },
        "{:?}",
        c.notes
    );
    assert_eq!(c.rung_ceiling, RungCeiling::AgentContinues);
}

#[tokio::test]
async fn hashed_page_classifies_as_transformed() {
    let Some(r) = record_login("hashed_page", Login::Hashed).await else {
        return;
    };
    let c = &r.classification;
    assert_eq!(
        c.shape,
        Shape::Transformed {
            digest: Some("sha256".to_owned())
        },
        "{:?}",
        c.notes
    );
    assert_eq!(c.rung_ceiling, RungCeiling::Milliseconds, "{:?}", c.notes);
    assert!(!c.network_swap_candidate);
}

/// The first selector of an element is one a later visit can use to find the same field.
#[tokio::test]
async fn the_first_selector_of_each_typed_element_matches() {
    let Some(r) = record_login("first_selector", Login::Form).await else {
        return;
    };
    let typed = typed_elements(&r);
    assert_eq!(typed.len(), 2, "two typed fields");
    for sel in &typed {
        assert!(!sel.is_empty());
    }
    // Re-open the fixture and check each selector finds exactly the field it describes.
    let Some(run) = Run::start("first_selector_reopen", "/form").await else {
        return;
    };
    run.begin("/form").await;
    for (sel, want_name) in typed.iter().zip(["user", "pass"]) {
        let found = run.person.attr_of(sel, "name").await;
        assert_eq!(found.as_deref(), Some(want_name), "selector {sel}");
    }
    assert!(matches!(run.finish(End::Discard).await, Outcome::Discarded));
}

fn typed_elements(r: &Recording) -> Vec<String> {
    use kharon_recording::Step;
    r.steps
        .iter()
        .filter_map(|s| match s {
            Step::Input { element, .. } => element.selectors.first().cloned(),
            _ => None,
        })
        .collect()
}

fn request_to<'a>(r: &'a Recording, path: &str) -> &'a kharon_recording::StoredRequest {
    r.requests
        .iter()
        .find(|q| q.method == "POST" && q.url.path == path)
        .unwrap_or_else(|| panic!("no stored POST to {path}"))
}

fn has_password_hit(parts: &[kharon_recording::FieldShape], key: &str) -> bool {
    parts.iter().any(|p| {
        p.key == key
            && p.value
                .markers
                .iter()
                .any(|m| m.role == kharon_recording::Role::Password)
    })
}

#[tokio::test]
async fn a_form_data_post_is_stored_as_multipart_with_the_password_found() {
    let Some(r) = record_login("script_formdata", Login::ScriptFormData).await else {
        return;
    };
    assert_eq!(
        r.classification.shape,
        Shape::ScriptPost,
        "{:?}",
        r.classification.notes
    );
    match &request_to(&r, "/api/login-form").body {
        kharon_recording::BodyShape::Multipart { parts } => {
            assert!(
                has_password_hit(parts, "pass"),
                "no password hit on the pass part"
            )
        }
        _ => panic!("the body is not multipart"),
    }
    assert!(!r.flags.body_unavailable);
    assert_holds_no_typed_value(&r.to_json(), &[USER, PASS]);
}

#[tokio::test]
async fn a_blob_body_is_fetched_with_get_request_post_data() {
    use std::sync::atomic::Ordering;
    let before = POST_DATA_FETCHES.load(Ordering::Relaxed);
    let Some(r) = record_login("script_blob", Login::ScriptBlob).await else {
        return;
    };
    // Whether Chromium sends a Blob body inline or not, the stored shape must carry the password.
    assert_eq!(
        r.classification.shape,
        Shape::ScriptPost,
        "{:?}",
        r.classification.notes
    );
    match &request_to(&r, "/api/login-blob").body {
        kharon_recording::BodyShape::Json { .. } | kharon_recording::BodyShape::Opaque { .. } => {}
        other => panic!("unexpected body shape kind {}", shape_name(other)),
    }
    assert!(!r.flags.body_unavailable);
    assert!(
        POST_DATA_FETCHES.load(Ordering::Relaxed) > before,
        "the body was inline: getRequestPostData never ran"
    );
    assert_holds_no_typed_value(&r.to_json(), &[USER, PASS]);
}

fn shape_name(b: &kharon_recording::BodyShape) -> &'static str {
    use kharon_recording::BodyShape::*;
    match b {
        None => "none",
        Unavailable => "unavailable",
        Urlencoded { .. } => "urlencoded",
        Json { .. } => "json",
        Multipart { .. } => "multipart",
        Opaque { .. } => "opaque",
    }
}

#[tokio::test]
async fn the_main_world_fallback_still_records_a_login() {
    use kharon_teach::session::WorldProbe;
    let Some(run) = Run::start_with("main_world", "/form", WorldProbe::SkipIsolated).await else {
        return;
    };
    run.begin("/form").await;
    run.person.type_into("input[name=user]", USER).await;
    run.person.type_into("input[name=pass]", PASS).await;
    run.person.click("#go").await;
    run.person.wait_for_path("/home").await;
    let Outcome::Recorded(r) = run.finish(End::Confirmed).await else {
        panic!("expected a recording");
    };
    assert_eq!(r.listener_world, ListenerWorld::Main);
    assert_eq!(
        r.classification.shape,
        Shape::FormPost,
        "{:?}",
        r.classification.notes
    );
    assert_holds_no_typed_value(&r.to_json(), &[USER, PASS]);
}

#[tokio::test]
async fn children_named_like_form_properties_do_not_hide_the_form() {
    let Some(r) = record_login("clobber", Login::Clobber).await else {
        return;
    };
    assert_eq!(
        r.classification.shape,
        Shape::FormPost,
        "{:?}",
        r.classification.notes
    );
    let form = r
        .steps
        .iter()
        .find_map(|s| match s {
            kharon_recording::Step::Submit { form, .. } => Some(form.clone()),
            _ => None,
        })
        .expect("a submit step");
    assert_eq!(form.method, "post");
    assert_eq!(form.action.map(|a| a.path).as_deref(), Some("/form-login"));
    assert_holds_no_typed_value(&r.to_json(), &[USER, PASS]);
}

#[tokio::test]
async fn a_popup_sets_the_flag_and_is_not_a_login() {
    let Some(run) = Run::start("popup", "/popup").await else {
        return;
    };
    run.begin("/popup").await;
    run.person.click("#go").await;
    run.person.wait_for_pages(2).await;
    let Outcome::Recorded(r) = run.finish(End::Confirmed).await else {
        panic!("expected a recording");
    };
    assert!(r.flags.popup);
    assert_eq!(
        r.classification.shape,
        Shape::Unrecognized,
        "{:?}",
        r.classification.notes
    );
}

#[tokio::test]
async fn a_login_in_a_cross_origin_frame_sets_framed_login() {
    let Some(run) = Run::start("framed", "/frame-outer").await else {
        return;
    };
    run.begin("/frame-outer").await;
    let frame = run.person.attach_frame("localhost").await;
    run.person
        .type_into_frame(&frame, "input[name=user]", USER)
        .await;
    run.person
        .type_into_frame(&frame, "input[name=pass]", PASS)
        .await;
    run.person.press_enter().await;
    run.person.wait_for_frame_path(&frame, "/home").await;
    let Outcome::Recorded(r) = run.finish(End::Confirmed).await else {
        panic!("expected a recording");
    };
    assert!(r.flags.framed_login, "{:?}", r.classification.notes);
    assert_holds_no_typed_value(&r.to_json(), &[USER, PASS]);
}

#[tokio::test]
async fn a_checkbox_is_not_a_typed_value() {
    let Some(run) = Run::start("checkbox", "/form").await else {
        return;
    };
    run.begin("/form").await;
    run.person.click("#rem").await;
    run.person.type_into("input[name=user]", USER).await;
    run.person.type_into("input[name=pass]", PASS).await;
    run.person.click("#go").await;
    run.person.wait_for_path("/home").await;
    let Outcome::Recorded(r) = run.finish(End::Confirmed).await else {
        panic!("expected a recording");
    };
    assert_eq!(r.stripped.typed_values_removed, 2);
    assert_eq!(
        r.classification.shape,
        Shape::FormPost,
        "{:?}",
        r.classification.notes
    );
    assert!(r.requests.iter().any(|q| q.url.path == "/form-login"));
    assert_holds_no_typed_value(&r.to_json(), &[USER, PASS]);
}
