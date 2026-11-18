//! SPEC req_tch_005: the recorder tells the shapes of login apart in a real browser.

mod support;

use kharon_recording::{
    EndedBy, ListenerWorld, PasswordLeg, Recording, ResourceKind, RungCeiling, Shape,
};
use kharon_teach::session::{End, Outcome};
use support::{COOKIE_VALUE, Login, Run, record_login};

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
