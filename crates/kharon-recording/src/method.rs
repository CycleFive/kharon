//! The login method: a typed, value-free description of a site's login that
//! the broker can replay (#382).

use serde::{Deserialize, Serialize};

use crate::classify::{RungCeiling, Shape};
use crate::format::ListenerWorld;

pub const METHOD_FORMAT_VERSION: u32 = 1;
pub const METHOD_FILE_SUFFIX: &str = ".kharon-method.json";

const MAX_SELECTOR_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginMethod {
    /// `to_json` always writes `METHOD_FORMAT_VERSION`, whatever this field holds.
    pub format_version: u32,
    pub site: Site,
    pub shape: Shape,
    pub rung: Rung,
    pub legs: Vec<Leg>,
    pub success: SuccessCheck,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub domain: String,
    /// scheme://host[:port]
    pub origin: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rung {
    Milliseconds,
    AgentContinues,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Leg {
    pub steps: Vec<MethodStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MethodStep {
    Navigate {
        path: String,
    },
    Fill {
        role: FillRole,
        selectors: Vec<String>,
        expect: Expected,
    },
    Submit {
        via: SubmitVia,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FillRole {
    Username,
    Password,
}

/// What the element must look like before the broker acts on it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub tag: String,
    pub input_type: Option<String>,
    pub id: Option<String>,
    pub name: Option<String>,
    pub autocomplete: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SubmitVia {
    Form,
    Enter,
    Click {
        selectors: Vec<String>,
        expect: Expected,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SuccessCheck {
    PathChangedTo { path: String },
    PasswordFieldGone,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum Provenance {
    Recording {
        sha256: String,
        tool_version: String,
        browser_product: String,
        listener_world: ListenerWorld,
        rung_ceiling: RungCeiling,
    },
    HandWritten {
        author: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum MethodError {
    #[error("unsupported method format_version {0}")]
    UnsupportedVersion(u32),
    #[error("not a kharon login method: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("not a usable login method: {0}")]
    Invalid(&'static str),
}

#[derive(Deserialize)]
struct VersionProbe {
    format_version: u32,
}

fn bad_path(path: &str) -> bool {
    !path.starts_with('/')
        || path.starts_with("//")
        || path.chars().any(|c| c == '?' || c == '#' || c.is_control())
}

fn bad_selectors(selectors: &[String]) -> bool {
    selectors.is_empty()
        || selectors
            .iter()
            .any(|s| s.is_empty() || s.len() > MAX_SELECTOR_BYTES)
}

fn bad_origin(origin: &str) -> bool {
    let Some(host) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return true;
    };
    host.is_empty() || host.contains(['/', '?', '#', '@'])
}

impl LoginMethod {
    /// Pretty JSON with a trailing newline.
    pub fn to_json(&self) -> String {
        let mut copy = self.clone();
        copy.format_version = METHOD_FORMAT_VERSION;
        let mut text = serde_json::to_string_pretty(&copy)
            .expect("a LoginMethod is plain data and always serializes");
        text.push('\n');
        text
    }

    /// The version is checked before the full parse; the result is validated.
    pub fn from_json(text: &str) -> Result<Self, MethodError> {
        let probe: VersionProbe = serde_json::from_str(text)?;
        if probe.format_version != METHOD_FORMAT_VERSION {
            return Err(MethodError::UnsupportedVersion(probe.format_version));
        }
        let method: Self = serde_json::from_str(text)?;
        method.validate()?;
        Ok(method)
    }

    pub fn validate(&self) -> Result<(), MethodError> {
        use MethodError::Invalid;

        let want_legs = match self.shape {
            Shape::Unrecognized => return Err(Invalid("shape")),
            Shape::TwoStep { .. } => 2,
            _ => 1,
        };
        if self.legs.len() != want_legs {
            return Err(Invalid("legs"));
        }
        for leg in &self.legs {
            let submits = leg
                .steps
                .iter()
                .filter(|s| matches!(s, MethodStep::Submit { .. }))
                .count();
            let ok = matches!(leg.steps.first(), Some(MethodStep::Navigate { .. }))
                && leg
                    .steps
                    .iter()
                    .any(|s| matches!(s, MethodStep::Fill { .. }))
                && submits == 1
                && matches!(leg.steps.last(), Some(MethodStep::Submit { .. }));
            if !ok {
                return Err(Invalid("leg_steps"));
            }
        }
        let last_has_password = self.legs.last().is_some_and(|leg| {
            leg.steps.iter().any(|s| {
                matches!(
                    s,
                    MethodStep::Fill {
                        role: FillRole::Password,
                        ..
                    }
                )
            })
        });
        if !last_has_password {
            return Err(Invalid("no_password"));
        }
        for (_, _, step) in self.steps() {
            match step {
                MethodStep::Fill {
                    selectors,
                    role,
                    expect,
                } => {
                    if bad_selectors(selectors) {
                        return Err(Invalid("selector"));
                    }
                    if *role == FillRole::Password
                        && expect.input_type.as_deref() != Some("password")
                    {
                        return Err(Invalid("password_type"));
                    }
                }
                MethodStep::Submit {
                    via: SubmitVia::Click { selectors, .. },
                } if bad_selectors(selectors) => return Err(Invalid("selector")),
                _ => {}
            }
        }
        let success_path = match &self.success {
            SuccessCheck::PathChangedTo { path } => Some(path.as_str()),
            _ => None,
        };
        let navigates = self.steps().filter_map(|(_, _, s)| match s {
            MethodStep::Navigate { path } => Some(path.as_str()),
            _ => None,
        });
        if std::iter::once(self.site.path.as_str())
            .chain(navigates)
            .chain(success_path)
            .any(bad_path)
        {
            return Err(Invalid("path"));
        }
        if bad_origin(&self.site.origin) {
            return Err(Invalid("origin"));
        }
        if self.site.domain.is_empty() {
            return Err(Invalid("domain"));
        }
        match self.legs[0].steps.first() {
            Some(MethodStep::Navigate { path }) if *path == self.site.path => {}
            _ => return Err(Invalid("site_path")),
        }
        Ok(())
    }

    /// Every step as (index across all legs from 0, leg index, step).
    pub fn steps(&self) -> impl Iterator<Item = (u32, usize, &MethodStep)> {
        self.legs
            .iter()
            .enumerate()
            .flat_map(|(leg, l)| l.steps.iter().map(move |s| (leg, s)))
            .zip(0u32..)
            .map(|((leg, step), index)| (index, leg, step))
    }

    /// The recording's sha256; `None` for a hand-written method.
    pub fn digest(&self) -> Option<&str> {
        match &self.provenance {
            Provenance::Recording { sha256, .. } => Some(sha256),
            Provenance::HandWritten { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(input_type: &str) -> Expected {
        Expected {
            tag: "input".into(),
            input_type: Some(input_type.into()),
            id: None,
            name: None,
            autocomplete: None,
        }
    }

    fn fill(role: FillRole, selector: &str, input_type: &str) -> MethodStep {
        MethodStep::Fill {
            role,
            selectors: vec![selector.into()],
            expect: expected(input_type),
        }
    }

    fn nav(path: &str) -> MethodStep {
        MethodStep::Navigate { path: path.into() }
    }

    fn submit() -> MethodStep {
        MethodStep::Submit {
            via: SubmitVia::Form,
        }
    }

    fn recording() -> Provenance {
        Provenance::Recording {
            sha256: "ab12".into(),
            tool_version: "0.0.0".into(),
            browser_product: "Chrome/1".into(),
            listener_world: ListenerWorld::Isolated,
            rung_ceiling: RungCeiling::Milliseconds,
        }
    }

    fn sample() -> LoginMethod {
        LoginMethod {
            format_version: METHOD_FORMAT_VERSION,
            site: Site {
                domain: "example.test".into(),
                origin: "https://example.test".into(),
                path: "/login".into(),
            },
            shape: Shape::FormPost,
            rung: Rung::Milliseconds,
            legs: vec![Leg {
                steps: vec![
                    nav("/login"),
                    fill(FillRole::Username, "#user", "text"),
                    fill(FillRole::Password, "#pw", "password"),
                    submit(),
                ],
            }],
            success: SuccessCheck::PathChangedTo {
                path: "/home".into(),
            },
            provenance: recording(),
        }
    }

    fn two_leg() -> LoginMethod {
        let mut m = sample();
        m.shape = Shape::TwoStep {
            password_leg: crate::classify::PasswordLeg::FormPost,
        };
        m.legs = vec![
            Leg {
                steps: vec![
                    nav("/login"),
                    fill(FillRole::Username, "#user", "text"),
                    submit(),
                ],
            },
            Leg {
                steps: vec![
                    nav("/password"),
                    fill(FillRole::Password, "#pw", "password"),
                    submit(),
                ],
            },
        ];
        m
    }

    fn round_trip(m: &LoginMethod) {
        assert_eq!(&LoginMethod::from_json(&m.to_json()).unwrap(), m);
    }

    #[test]
    fn req_tch_007_round_trips_every_variant() {
        round_trip(&sample());
        round_trip(&two_leg());
        let click = SubmitVia::Click {
            selectors: vec!["button.go".into()],
            expect: expected("submit"),
        };
        for via in [SubmitVia::Form, SubmitVia::Enter, click] {
            let mut m = sample();
            *m.legs[0].steps.last_mut().unwrap() = MethodStep::Submit { via };
            round_trip(&m);
        }
        for success in [
            SuccessCheck::PathChangedTo { path: "/x".into() },
            SuccessCheck::PasswordFieldGone,
            SuccessCheck::None,
        ] {
            let mut m = sample();
            m.success = success;
            round_trip(&m);
        }
        for rung in [Rung::Milliseconds, Rung::AgentContinues] {
            let mut m = sample();
            m.rung = rung;
            round_trip(&m);
        }
        let mut m = sample();
        m.provenance = Provenance::HandWritten {
            author: "lothrop".into(),
        };
        round_trip(&m);
    }

    #[test]
    fn req_tch_007_refuses_an_unknown_version() {
        let text = sample()
            .to_json()
            .replace("\"format_version\": 1", "\"format_version\": 2");
        assert!(matches!(
            LoginMethod::from_json(&text),
            Err(MethodError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            LoginMethod::from_json("{}"),
            Err(MethodError::Parse(_))
        ));
    }

    #[test]
    fn to_json_always_writes_the_current_version() {
        let mut m = sample();
        m.format_version = 99;
        let text = m.to_json();
        assert!(text.ends_with("}\n"));
        assert_eq!(
            LoginMethod::from_json(&text).unwrap().format_version,
            METHOD_FORMAT_VERSION
        );
    }

    #[test]
    fn req_tch_007_refuses_unknown_fields() {
        let json = sample().to_json();
        let in_fill = json.replacen(
            "\"role\": \"username\",",
            "\"role\": \"username\",\n\"value_len\": 8,",
            1,
        );
        assert_ne!(in_fill, json);
        assert!(matches!(
            LoginMethod::from_json(&in_fill),
            Err(MethodError::Parse(_))
        ));
        let in_expect = json.replacen(
            "\"tag\": \"input\",",
            "\"tag\": \"input\",\n\"placeholder\": \"x\",",
            1,
        );
        assert_ne!(in_expect, json);
        assert!(matches!(
            LoginMethod::from_json(&in_expect),
            Err(MethodError::Parse(_))
        ));
    }

    fn reason(m: &LoginMethod) -> &'static str {
        match m.validate() {
            Err(MethodError::Invalid(r)) => r,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_the_samples() {
        sample().validate().unwrap();
        two_leg().validate().unwrap();
    }

    #[test]
    fn validate_names_each_fault() {
        let mutate = |f: &dyn Fn(&mut LoginMethod)| {
            let mut m = sample();
            f(&mut m);
            reason(&m)
        };
        assert_eq!(mutate(&|m| m.shape = Shape::Unrecognized), "shape");
        assert_eq!(mutate(&|m| m.legs.clear()), "legs");
        assert_eq!(
            mutate(&|m| m.shape = Shape::TwoStep {
                password_leg: crate::classify::PasswordLeg::FormPost
            }),
            "legs"
        );
        assert_eq!(
            mutate(&|m| m.legs.push(m.legs[0].clone())),
            "legs",
            "a single-leg shape with two legs"
        );
        assert_eq!(mutate(&|m| m.legs[0].steps[0] = submit()), "leg_steps");
        assert_eq!(
            mutate(&|m| m.legs[0]
                .steps
                .retain(|s| !matches!(s, MethodStep::Fill { .. }))),
            "leg_steps"
        );
        assert_eq!(
            mutate(&|m| m.legs[0].steps.insert(1, submit())),
            "leg_steps",
            "two submits"
        );
        assert_eq!(
            mutate(&|m| m.legs[0].steps.pop().map(drop).unwrap()),
            "leg_steps",
            "no submit"
        );
        assert_eq!(
            mutate(&|m| m.legs[0].steps.push(nav("/login"))),
            "leg_steps",
            "submit not last"
        );
        assert_eq!(
            mutate(&|m| m.legs[0].steps[2] = fill(FillRole::Username, "#pw", "text")),
            "no_password"
        );
        assert_eq!(
            mutate(&|m| m.legs[0].steps[1] = MethodStep::Fill {
                role: FillRole::Username,
                selectors: vec![],
                expect: expected("text"),
            }),
            "selector"
        );
        assert_eq!(
            mutate(&|m| m.legs[0].steps[1] = fill(FillRole::Username, "", "text")),
            "selector"
        );
        assert_eq!(
            mutate(&|m| m.legs[0].steps[1] = fill(FillRole::Username, &"a".repeat(1025), "text")),
            "selector"
        );
        assert_eq!(
            mutate(
                &|m| *m.legs[0].steps.last_mut().unwrap() = MethodStep::Submit {
                    via: SubmitVia::Click {
                        selectors: vec![],
                        expect: expected("submit")
                    }
                }
            ),
            "selector"
        );
        assert_eq!(
            mutate(&|m| m.legs[0].steps[2] = fill(FillRole::Password, "#pw", "text")),
            "password_type"
        );
        for bad in ["login", "//evil.test/x", "/a?b=1", "/a#f", "/a\nb"] {
            assert_eq!(
                mutate(&|m| m.success = SuccessCheck::PathChangedTo { path: bad.into() }),
                "path",
                "{bad:?}"
            );
        }
        assert_eq!(
            mutate(&|m| {
                m.site.path = "/login?x=1".into();
                m.legs[0].steps[0] = nav("/login?x=1");
            }),
            "path"
        );
        for bad in [
            "example.test",
            "ftp://example.test",
            "https://",
            "https://example.test/",
            "https://u@example.test",
            "https://example.test?x",
            "https://example.test#x",
        ] {
            assert_eq!(mutate(&|m| m.site.origin = bad.into()), "origin", "{bad}");
        }
        assert_eq!(mutate(&|m| m.site.domain.clear()), "domain");
        assert_eq!(mutate(&|m| m.site.path = "/other".into()), "site_path");
    }

    #[test]
    fn from_json_validates() {
        let mut m = sample();
        m.legs.clear();
        assert!(matches!(
            LoginMethod::from_json(&m.to_json()),
            Err(MethodError::Invalid("legs"))
        ));
    }

    #[test]
    fn wire_names() {
        let j = sample().to_json();
        for needle in [
            "\"kind\": \"fill\"",
            "\"role\": \"password\"",
            "\"rung\": \"milliseconds\"",
            "\"source\": \"recording\"",
            "\"kind\": \"path_changed_to\"",
        ] {
            assert!(j.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn steps_are_numbered_across_legs() {
        let mut m = two_leg();
        m.legs[0].steps = vec![nav("/login"), submit()];
        let got: Vec<(u32, usize)> = m.steps().map(|(i, l, _)| (i, l)).collect();
        assert_eq!(got, vec![(0, 0), (1, 0), (2, 1), (3, 1), (4, 1)]);
    }

    #[test]
    fn digest_is_the_recording_sha() {
        let mut m = sample();
        assert_eq!(m.digest(), Some("ab12"));
        m.provenance = Provenance::HandWritten { author: "a".into() };
        assert_eq!(m.digest(), None);
    }
}
