//! Classification of a recorded login: its shape and the strongest rung it can take.

use serde::{Deserialize, Serialize};

use crate::format::{ElementDescriptor, Step};
use crate::request::{Deciding, ResourceKind, Role, StoredRequest};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Flags {
    pub captcha: bool,
    pub otp_step: bool,
    pub cross_site: bool,
    pub popup: bool,
    pub framed_login: bool,
    pub shadow_dom: bool,
    pub multiple_passwords: bool,
    pub body_unavailable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordLeg {
    FormPost,
    ScriptPost,
    Transformed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Shape {
    FormPost,
    ScriptPost,
    TwoStep { password_leg: PasswordLeg },
    Transformed { digest: Option<String> },
    Unrecognized,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RungCeiling {
    Milliseconds,
    AgentContinues,
    NeedsPerson,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classification {
    pub shape: Shape,
    pub rung_ceiling: RungCeiling,
    pub network_swap_candidate: bool,
    pub notes: Vec<String>,
}

/// A plain (not digest) password hit that decides anything: a weak one counts only when no
/// confident password hit exists anywhere (see `Deciding`).
fn plain_hit(r: &StoredRequest, d: &Deciding) -> bool {
    r.hits()
        .iter()
        .any(|h| h.role == Role::Password && !h.encoding.is_digest() && d.counts(h))
}

fn has_hit(r: &StoredRequest, role: Role, d: &Deciding) -> bool {
    r.hits().iter().any(|h| h.role == role && d.counts(h))
}

/// Restates the three TOTP tests in `resolveField` in
/// `crates/kharond/src/cdp/page_js.rs`; keep the two in step.
pub fn is_otp_descriptor(e: &ElementDescriptor) -> bool {
    e.autocomplete
        .as_deref()
        .is_some_and(|a| a.contains("one-time"))
        || e.name
            .as_deref()
            .is_some_and(|n| n.to_lowercase().contains("otp"))
        || e.input_type.as_deref() == Some("tel")
}

fn t_ms(step: &Step) -> u64 {
    match step {
        Step::Navigation { t_ms, .. }
        | Step::Input { t_ms, .. }
        | Step::Click { t_ms, .. }
        | Step::Submit { t_ms, .. }
        | Step::EnterKey { t_ms, .. } => *t_ms,
    }
}

fn unrecognized(note: &str) -> Classification {
    Classification {
        shape: Shape::Unrecognized,
        rung_ceiling: RungCeiling::NeedsPerson,
        network_swap_candidate: false,
        notes: vec![note.to_string()],
    }
}

/// Names the shape of a recorded login and the strongest rung it can take.
pub fn classify(steps: &[Step], requests: &[StoredRequest], flags: &Flags) -> Classification {
    let deciding = Deciding::from_hits(requests.iter().flat_map(|r| r.hits()));
    let swap_candidate = requests.iter().filter(|r| plain_hit(r, &deciding)).count() == 1;

    // Rule 1.
    let blocking = [
        (
            flags.cross_site,
            "The login goes to another site partway through, so a person has to look at it.",
        ),
        (
            flags.popup,
            "The login opens a pop-up window, so a person has to look at it.",
        ),
        (
            flags.framed_login,
            "The login form sits inside a frame, so a person has to look at it.",
        ),
        (
            flags.multiple_passwords,
            "The page has more than one password field, so a person has to look at it.",
        ),
    ];
    let notes: Vec<String> = blocking
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, n)| n.to_string())
        .collect();
    if !notes.is_empty() {
        return Classification {
            shape: Shape::Unrecognized,
            rung_ceiling: RungCeiling::NeedsPerson,
            network_swap_candidate: false,
            notes,
        };
    }

    // Rule 2.
    let first_password = steps.iter().find_map(|s| match s {
        Step::Input {
            t_ms,
            role: Role::Password,
            element,
            ..
        } => Some((*t_ms, element)),
        _ => None,
    });
    let Some((p, password_element)) = first_password else {
        return unrecognized("no password field was used");
    };

    // Rule 3.
    let username_t = steps.iter().find_map(|s| match s {
        Step::Input {
            t_ms,
            role: Role::Username,
            ..
        } => Some(*t_ms),
        _ => None,
    });
    let navigated = username_t.is_some_and(|u| {
        steps.iter().any(|s| {
            matches!(s, Step::Navigation { frame, .. } if frame.main) && t_ms(s) > u && t_ms(s) < p
        })
    });
    let username_only_request = requests.iter().any(|r| {
        r.t_ms < p
            && has_hit(r, Role::Username, &deciding)
            && !has_hit(r, Role::Password, &deciding)
    });
    let two_step = navigated || username_only_request;

    // Rule 4.
    let mut notes = Vec::new();
    let earliest_plain = requests
        .iter()
        .filter(|r| plain_hit(r, &deciding))
        .min_by_key(|r| r.t_ms);
    let leg = match earliest_plain {
        Some(r) => match r.resource {
            ResourceKind::Document if r.main_frame_navigation => PasswordLeg::FormPost,
            ResourceKind::Xhr | ResourceKind::Fetch => PasswordLeg::ScriptPost,
            _ => {
                notes.push(
                    "The password was sent in a way this tool does not know, so a person has to look at it."
                        .to_string(),
                );
                return finish_unrecognized(notes);
            }
        },
        None => {
            if flags.body_unavailable {
                notes.push(
                    "The browser would not give up the request bodies, so the password could not be found in them."
                        .to_string(),
                );
                return finish_unrecognized(notes);
            }
            PasswordLeg::Transformed
        }
    };
    let digest = requests
        .iter()
        .flat_map(|r| r.hits())
        .find(|h| h.role == Role::Password && h.encoding.is_digest() && deciding.counts(h))
        .and_then(|h| h.encoding.digest_name())
        .map(str::to_string);

    // Rule 5.
    let shape = if two_step {
        Shape::TwoStep { password_leg: leg }
    } else {
        match leg {
            PasswordLeg::FormPost => Shape::FormPost,
            PasswordLeg::ScriptPost => Shape::ScriptPost,
            PasswordLeg::Transformed => Shape::Transformed {
                digest: digest.clone(),
            },
        }
    };

    // Rule 6.
    let mut ceiling = RungCeiling::Milliseconds;
    let mut lower = |to: RungCeiling, note: &str| {
        if to == RungCeiling::NeedsPerson || ceiling == RungCeiling::Milliseconds {
            ceiling = to;
        }
        notes.push(note.to_string());
    };
    if matches!(shape, Shape::TwoStep { .. }) {
        lower(
            RungCeiling::AgentContinues,
            "The username and password are entered on separate steps, so the agent has to carry on after the first.",
        );
    }
    if matches!(
        shape,
        Shape::TwoStep {
            password_leg: PasswordLeg::Transformed
        }
    ) {
        // The leg is the same uncertainty as a one-page transformed login: the password was
        // found nowhere in plain form. Only a named digest lets the agent carry on.
        match &digest {
            Some(name) => lower(
                RungCeiling::AgentContinues,
                &format!(
                    "The password is sent as a {name} digest, so the agent has to hash it the same way."
                ),
            ),
            None => lower(
                RungCeiling::NeedsPerson,
                "The password is changed before it is sent in a way this tool cannot name, so a person has to look at it.",
            ),
        }
    }
    if flags.captcha {
        lower(
            RungCeiling::AgentContinues,
            "The login shows a CAPTCHA, so the agent has to carry on from there.",
        );
    }
    if flags.otp_step {
        lower(
            RungCeiling::AgentContinues,
            "The login asks for a one-time code, so the agent has to carry on from there.",
        );
    }
    let one_page = !matches!(shape, Shape::TwoStep { .. });
    if one_page && password_element.form.is_none() {
        let can_submit = steps.iter().any(|s| {
            t_ms(s) >= p
                && match s {
                    Step::EnterKey { .. } => true,
                    Step::Click { element, .. } => {
                        element.tag.eq_ignore_ascii_case("button")
                            || element.input_type.as_deref() == Some("submit")
                    }
                    _ => false,
                }
        });
        if !can_submit {
            lower(
                RungCeiling::AgentContinues,
                "The password field is not in a form and nothing was pressed to send it, so the agent has to find a way to submit.",
            );
        }
    }
    if matches!(shape, Shape::Transformed { digest: None }) {
        lower(
            RungCeiling::NeedsPerson,
            "The password is changed before it is sent in a way this tool cannot name, so a person has to look at it.",
        );
    }

    Classification {
        shape,
        rung_ceiling: ceiling,
        network_swap_candidate: swap_candidate,
        notes,
    }
}

fn finish_unrecognized(notes: Vec<String>) -> Classification {
    Classification {
        shape: Shape::Unrecognized,
        rung_ceiling: RungCeiling::NeedsPerson,
        network_swap_candidate: false,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{FormRef, FrameRef, StrippedUrl};
    use crate::request::{BodyShape, Encoding, FieldShape, MarkerHit, ValueKind, ValueShape};

    fn frame() -> FrameRef {
        FrameRef {
            main: true,
            origin: "https://example.test".into(),
            cross_origin: false,
        }
    }

    fn url() -> StrippedUrl {
        StrippedUrl {
            origin: "https://example.test".into(),
            path: "/login".into(),
            query_keys: vec![],
        }
    }

    fn element(id: u32, input_type: &str, in_form: bool) -> ElementDescriptor {
        ElementDescriptor {
            element_id: id,
            tag: "input".into(),
            input_type: Some(input_type.into()),
            id: None,
            name: None,
            autocomplete: None,
            placeholder: None,
            aria_label: None,
            was_password: input_type == "password",
            form: in_form.then(|| FormRef {
                index: 0,
                action: None,
                method: "post".into(),
            }),
            selectors: vec![],
            in_shadow_root: false,
        }
    }

    fn input(t: u64, role: Role, in_form: bool) -> Step {
        let ty = if role == Role::Password {
            "password"
        } else {
            "text"
        };
        Step::Input {
            t_ms: t,
            frame: frame(),
            element: element(t as u32, ty, in_form),
            value_len: 6,
            role,
        }
    }

    fn nav(t: u64) -> Step {
        Step::Navigation {
            t_ms: t,
            frame: frame(),
            url: url(),
        }
    }

    fn hit(role: Role, encoding: Encoding) -> MarkerHit {
        MarkerHit {
            role,
            encoding,
            low_confidence: false,
        }
    }

    fn req(t: u64, resource: ResourceKind, hits: Vec<MarkerHit>) -> StoredRequest {
        StoredRequest {
            t_ms: t,
            method: "POST".into(),
            url: url(),
            resource,
            main_frame_navigation: resource == ResourceKind::Document,
            content_type: None,
            authorization: None,
            url_markers: vec![],
            body: BodyShape::Urlencoded {
                fields: vec![FieldShape {
                    key: "k".into(),
                    value: ValueShape {
                        kind: ValueKind::String,
                        len: 6,
                        markers: hits,
                    },
                }],
            },
            response: None,
        }
    }

    fn plain_pw() -> MarkerHit {
        hit(Role::Password, Encoding::AsTyped)
    }

    fn one_page_steps() -> Vec<Step> {
        vec![
            nav(0),
            input(10, Role::Username, true),
            input(20, Role::Password, true),
        ]
    }

    fn clean_form_post() -> Classification {
        classify(
            &one_page_steps(),
            &[req(100, ResourceKind::Document, vec![plain_pw()])],
            &Flags::default(),
        )
    }

    #[test]
    fn form_post() {
        let c = clean_form_post();
        assert_eq!(c.shape, Shape::FormPost);
        assert_eq!(c.rung_ceiling, RungCeiling::Milliseconds);
        assert!(c.network_swap_candidate);
    }

    #[test]
    fn script_post() {
        let c = classify(
            &one_page_steps(),
            &[req(
                100,
                ResourceKind::Fetch,
                vec![hit(Role::Password, Encoding::JsonEscaped)],
            )],
            &Flags::default(),
        );
        assert_eq!(c.shape, Shape::ScriptPost);
        assert_eq!(c.rung_ceiling, RungCeiling::Milliseconds);
        assert!(c.network_swap_candidate);
    }

    #[test]
    fn two_step_by_navigation() {
        let steps = vec![
            nav(0),
            input(10, Role::Username, true),
            nav(50),
            input(60, Role::Password, true),
        ];
        let c = classify(
            &steps,
            &[req(100, ResourceKind::Document, vec![plain_pw()])],
            &Flags::default(),
        );
        assert_eq!(
            c.shape,
            Shape::TwoStep {
                password_leg: PasswordLeg::FormPost
            }
        );
        assert_eq!(c.rung_ceiling, RungCeiling::AgentContinues);
        assert!(!c.notes.is_empty());
    }

    #[test]
    fn two_step_by_request() {
        let steps = vec![
            nav(0),
            input(10, Role::Username, true),
            input(60, Role::Password, true),
        ];
        let reqs = [
            req(
                30,
                ResourceKind::Xhr,
                vec![hit(Role::Username, Encoding::AsTyped)],
            ),
            req(100, ResourceKind::Fetch, vec![plain_pw()]),
        ];
        let c = classify(&steps, &reqs, &Flags::default());
        assert_eq!(
            c.shape,
            Shape::TwoStep {
                password_leg: PasswordLeg::ScriptPost
            }
        );
        assert_eq!(c.rung_ceiling, RungCeiling::AgentContinues);
    }

    #[test]
    fn two_step_with_a_transformed_leg_is_agent_continues() {
        let steps = vec![
            nav(0),
            input(10, Role::Username, true),
            nav(50),
            input(60, Role::Password, true),
        ];
        let c = classify(
            &steps,
            &[req(
                100,
                ResourceKind::Fetch,
                vec![hit(Role::Password, Encoding::Sha256Hex)],
            )],
            &Flags::default(),
        );
        assert_eq!(
            c.shape,
            Shape::TwoStep {
                password_leg: PasswordLeg::Transformed
            }
        );
        assert_eq!(c.rung_ceiling, RungCeiling::AgentContinues);
        assert!(
            c.notes.iter().any(|n| n.contains("sha256 digest")),
            "{:?}",
            c.notes
        );
    }

    #[test]
    fn two_step_with_a_transformed_leg_and_no_named_digest_needs_a_person() {
        let steps = vec![
            nav(0),
            input(10, Role::Username, true),
            nav(50),
            input(60, Role::Password, true),
        ];
        let c = classify(
            &steps,
            &[req(100, ResourceKind::Fetch, vec![])],
            &Flags::default(),
        );
        assert_eq!(
            c.shape,
            Shape::TwoStep {
                password_leg: PasswordLeg::Transformed
            }
        );
        assert_eq!(c.rung_ceiling, RungCeiling::NeedsPerson);
        assert!(
            c.notes.iter().any(|n| n.contains("cannot name")),
            "{:?}",
            c.notes
        );
    }

    fn weak(role: Role, encoding: Encoding) -> MarkerHit {
        MarkerHit {
            role,
            encoding,
            low_confidence: true,
        }
    }

    #[test]
    fn a_weak_password_hit_does_not_pick_the_leg_when_a_confident_one_exists() {
        // A short password matched by chance in an earlier request of a kind no leg is made
        // from; the request that really carried it is a form post.
        let reqs = [
            req(
                30,
                ResourceKind::Other,
                vec![weak(Role::Password, Encoding::AsTyped)],
            ),
            req(100, ResourceKind::Document, vec![plain_pw()]),
        ];
        let c = classify(&one_page_steps(), &reqs, &Flags::default());
        assert_eq!(c.shape, Shape::FormPost);
        assert!(
            c.network_swap_candidate,
            "only the confident request counts"
        );
        // With no confident hit anywhere, the weak ones decide, as before.
        let only_weak = [req(
            100,
            ResourceKind::Document,
            vec![weak(Role::Password, Encoding::AsTyped)],
        )];
        let c = classify(&one_page_steps(), &only_weak, &Flags::default());
        assert_eq!(c.shape, Shape::FormPost);
        assert!(c.network_swap_candidate);
    }

    #[test]
    fn a_weak_username_hit_does_not_make_a_two_step_when_a_confident_one_exists() {
        let reqs = [
            req(
                15,
                ResourceKind::Xhr,
                vec![weak(Role::Username, Encoding::AsTyped)],
            ),
            req(
                100,
                ResourceKind::Document,
                vec![hit(Role::Username, Encoding::AsTyped), plain_pw()],
            ),
        ];
        let c = classify(&one_page_steps(), &reqs, &Flags::default());
        assert_eq!(c.shape, Shape::FormPost);
        // Alone, a weak username-only request still reads as a first step.
        let alone = [
            req(
                15,
                ResourceKind::Xhr,
                vec![weak(Role::Username, Encoding::AsTyped)],
            ),
            req(100, ResourceKind::Document, vec![plain_pw()]),
        ];
        let c = classify(&one_page_steps(), &alone, &Flags::default());
        assert!(matches!(c.shape, Shape::TwoStep { .. }));
    }

    #[test]
    fn transformed_with_digest() {
        let c = classify(
            &one_page_steps(),
            &[req(
                100,
                ResourceKind::Fetch,
                vec![hit(Role::Password, Encoding::Sha256Hex)],
            )],
            &Flags::default(),
        );
        assert_eq!(
            c.shape,
            Shape::Transformed {
                digest: Some("sha256".into())
            }
        );
        assert_eq!(c.rung_ceiling, RungCeiling::Milliseconds);
        assert!(!c.network_swap_candidate);
    }

    #[test]
    fn transformed_unknown() {
        let c = classify(
            &one_page_steps(),
            &[req(100, ResourceKind::Fetch, vec![])],
            &Flags::default(),
        );
        assert_eq!(c.shape, Shape::Transformed { digest: None });
        assert_eq!(c.rung_ceiling, RungCeiling::NeedsPerson);
        assert!(!c.notes.is_empty());
    }

    #[test]
    fn password_nowhere_and_body_unavailable_is_unrecognized() {
        let flags = Flags {
            body_unavailable: true,
            ..Flags::default()
        };
        let c = classify(
            &one_page_steps(),
            &[req(100, ResourceKind::Fetch, vec![])],
            &flags,
        );
        assert_eq!(c.shape, Shape::Unrecognized);
        assert_eq!(c.rung_ceiling, RungCeiling::NeedsPerson);
        assert!(!c.notes.is_empty());
    }

    #[test]
    fn each_blocking_flag_wins() {
        let setters: [fn(&mut Flags); 4] = [
            |f| f.cross_site = true,
            |f| f.popup = true,
            |f| f.framed_login = true,
            |f| f.multiple_passwords = true,
        ];
        for set in setters {
            let mut flags = Flags::default();
            set(&mut flags);
            let c = classify(
                &one_page_steps(),
                &[req(100, ResourceKind::Document, vec![plain_pw()])],
                &flags,
            );
            assert_eq!(c.shape, Shape::Unrecognized);
            assert_eq!(c.rung_ceiling, RungCeiling::NeedsPerson);
            assert!(!c.network_swap_candidate);
            assert!(!c.notes.is_empty());
        }
    }

    #[test]
    fn captcha_caps_a_form_post_at_agent_continues() {
        let flags = Flags {
            captcha: true,
            ..Flags::default()
        };
        let c = classify(
            &one_page_steps(),
            &[req(100, ResourceKind::Document, vec![plain_pw()])],
            &flags,
        );
        assert_eq!(c.shape, Shape::FormPost);
        assert_eq!(c.rung_ceiling, RungCeiling::AgentContinues);
        assert!(!c.notes.is_empty());
    }

    #[test]
    fn otp_step_caps_at_agent_continues() {
        let flags = Flags {
            otp_step: true,
            ..Flags::default()
        };
        let c = classify(
            &one_page_steps(),
            &[req(100, ResourceKind::Document, vec![plain_pw()])],
            &flags,
        );
        assert_eq!(c.rung_ceiling, RungCeiling::AgentContinues);
        assert!(!c.notes.is_empty());
    }

    fn formless_steps() -> Vec<Step> {
        vec![
            nav(0),
            input(10, Role::Username, false),
            input(20, Role::Password, false),
        ]
    }

    #[test]
    fn no_way_to_submit_caps_at_agent_continues() {
        let c = classify(
            &formless_steps(),
            &[req(100, ResourceKind::Fetch, vec![plain_pw()])],
            &Flags::default(),
        );
        assert_eq!(c.shape, Shape::ScriptPost);
        assert_eq!(c.rung_ceiling, RungCeiling::AgentContinues);
        assert!(!c.notes.is_empty());
    }

    #[test]
    fn enter_key_keeps_milliseconds_without_a_form() {
        let mut steps = formless_steps();
        steps.push(Step::EnterKey {
            t_ms: 30,
            frame: frame(),
            element: element(2, "password", false),
        });
        let c = classify(
            &steps,
            &[req(100, ResourceKind::Fetch, vec![plain_pw()])],
            &Flags::default(),
        );
        assert_eq!(c.rung_ceiling, RungCeiling::Milliseconds);
        assert!(c.notes.is_empty());
    }

    #[test]
    fn two_plain_hits_is_not_a_swap_candidate() {
        let c = classify(
            &one_page_steps(),
            &[
                req(100, ResourceKind::Document, vec![plain_pw()]),
                req(110, ResourceKind::Fetch, vec![plain_pw()]),
            ],
            &Flags::default(),
        );
        assert!(!c.network_swap_candidate);
    }

    #[test]
    fn no_password_step_is_unrecognized() {
        let steps = vec![nav(0), input(10, Role::Username, true)];
        let c = classify(
            &steps,
            &[req(100, ResourceKind::Document, vec![plain_pw()])],
            &Flags::default(),
        );
        assert_eq!(c.shape, Shape::Unrecognized);
        assert_eq!(c.rung_ceiling, RungCeiling::NeedsPerson);
        assert!(c.notes.iter().any(|n| n == "no password field was used"));
    }

    #[test]
    fn otp_descriptor_matches_the_three_tests_and_nothing_else() {
        let base = element(1, "text", true);
        assert!(!is_otp_descriptor(&base));
        let mut a = base.clone();
        a.autocomplete = Some("one-time-code".into());
        assert!(is_otp_descriptor(&a));
        let mut n = base.clone();
        n.name = Some("User_OTP".into());
        assert!(is_otp_descriptor(&n));
        let t = element(1, "tel", true);
        assert!(is_otp_descriptor(&t));
        let mut other = base;
        other.autocomplete = Some("username".into());
        other.name = Some("email".into());
        assert!(!is_otp_descriptor(&other));
    }
}
