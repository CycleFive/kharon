//! The login method: a typed, value-free description of a site's login that
//! the broker can replay (#382).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::classify::{RungCeiling, Shape};
use crate::format::{ElementDescriptor, ListenerWorld, Recording, Step};
use crate::request::Role;

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
    // Empty struct variants, not unit variants: serde only enforces
    // `deny_unknown_fields` on the former. The wire form is still {"kind":"form"}.
    Form {},
    Enter {},
    Click {
        selectors: Vec<String>,
        expect: Expected,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SuccessCheck {
    PathChangedTo { path: String },
    PasswordFieldGone {},
    None {},
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

/// A path as `location.pathname` reports it: ASCII, `%`-escapes, and the
/// unreserved and sub-delimiter characters. No space, control character,
/// non-ASCII character or other character the URL parser escapes.
fn bad_path(path: &str) -> bool {
    !path.starts_with('/')
        || path.starts_with("//")
        || !path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._~!$&'()*+,;=:@/%".contains(c))
}

/// The in-page compare is against `tagName.toLowerCase()`.
fn bad_tag(tag: &str) -> bool {
    tag.is_empty()
        || !tag
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
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
    host.contains(['/', '?', '#', '@']) || host.split(':').next().is_none_or(str::is_empty)
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
        // One value per role goes to the page, and one element takes it. A second fill
        // step of the same role would resolve to the same element and drift, or write
        // the value into a second element.
        for leg in &self.legs {
            for role in [FillRole::Username, FillRole::Password] {
                let fills = leg
                    .steps
                    .iter()
                    .filter(|s| matches!(s, MethodStep::Fill { role: r, .. } if *r == role))
                    .count();
                if fills > 1 {
                    return Err(Invalid("duplicate_role"));
                }
            }
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
                    if bad_tag(&expect.tag) {
                        return Err(Invalid("tag"));
                    }
                    if *role == FillRole::Password
                        && expect.input_type.as_deref() != Some("password")
                    {
                        return Err(Invalid("password_type"));
                    }
                }
                MethodStep::Submit {
                    via: SubmitVia::Click { selectors, expect },
                } => {
                    if bad_selectors(selectors) {
                        return Err(Invalid("selector"));
                    }
                    if bad_tag(&expect.tag) {
                        return Err(Invalid("tag"));
                    }
                }
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
        // The player picks a leg by the page's path; two legs on one path
        // could never be told apart.
        let leg_paths: Vec<&str> = self
            .legs
            .iter()
            .filter_map(|l| match l.steps.first() {
                Some(MethodStep::Navigate { path }) => Some(path.as_str()),
                _ => None,
            })
            .collect();
        if leg_paths.len() == 2 && leg_paths[0] == leg_paths[1] {
            return Err(Invalid("legs"));
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

#[derive(Debug, Clone, Copy, Default)]
pub struct ConvertOptions {
    pub allow_unconfirmed: bool,
    pub success: Option<SuccessOverride>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SuccessOverride {
    PathChanged,
    PasswordFieldGone,
    None,
}

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum NotConvertible {
    #[error("kharon cannot tell how this login works; a person has to write the method by hand")]
    NeedsPerson,
    #[error(
        "a credential field sits in a shadow root, which a fill cannot reach; kharon cannot use a login method on this page"
    )]
    InShadowRoot,
    #[error("no submit was recorded after the last field of a step")]
    NoSubmit,
    #[error("nobody confirmed that this login worked; pass --unconfirmed to convert it anyway")]
    Unconfirmed,
    #[error("the recording does not match its own classification")]
    ShapeMismatch,
}

fn expected_of(el: &ElementDescriptor) -> Expected {
    Expected {
        tag: el.tag.to_ascii_lowercase(),
        input_type: el.input_type.clone(),
        id: el.id.clone(),
        name: el.name.clone(),
        autocomplete: el.autocomplete.clone(),
    }
}

fn is_submit_button(el: &ElementDescriptor) -> bool {
    el.tag == "button"
        || matches!(
            el.input_type.as_deref(),
            Some("submit" | "button" | "image")
        )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The element a method step acts on, refused when it cannot be reached.
fn reachable(el: &ElementDescriptor) -> Result<(Vec<String>, Expected), NotConvertible> {
    if el.in_shadow_root {
        return Err(NotConvertible::InShadowRoot);
    }
    if el.selectors.is_empty() {
        return Err(NotConvertible::ShapeMismatch);
    }
    Ok((el.selectors.clone(), expected_of(el)))
}

impl LoginMethod {
    /// `domain` is the registrable domain of the login origin; the caller computes it (this
    /// crate has no PSL).
    pub fn from_recording(
        rec: &Recording,
        recording_bytes: &[u8],
        domain: &str,
        opts: ConvertOptions,
    ) -> Result<LoginMethod, NotConvertible> {
        use NotConvertible::*;

        if !rec.success_confirmed && !opts.allow_unconfirmed {
            return Err(Unconfirmed);
        }
        let class = &rec.classification;
        if matches!(
            class.shape,
            Shape::Unrecognized | Shape::Transformed { digest: None }
        ) {
            return Err(NeedsPerson);
        }
        let rung = match class.rung_ceiling {
            RungCeiling::Milliseconds => Rung::Milliseconds,
            RungCeiling::AgentContinues => Rung::AgentContinues,
            RungCeiling::NeedsPerson => return Err(NeedsPerson),
        };

        let steps: Vec<&Step> = rec
            .steps
            .iter()
            .filter(|s| match s {
                Step::Navigation { frame, .. }
                | Step::Input { frame, .. }
                | Step::Click { frame, .. }
                | Step::Submit { frame, .. }
                | Step::EnterKey { frame, .. } => frame.main,
            })
            .collect();

        let credentials: Vec<usize> = steps
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                matches!(
                    s,
                    Step::Input {
                        role: Role::Username | Role::Password,
                        ..
                    }
                )
            })
            .map(|(i, _)| i)
            .collect();
        for &i in &credentials {
            if let Step::Input { element, .. } = steps[i]
                && element.in_shadow_root
            {
                return Err(InShadowRoot);
            }
        }

        // The (origin, path) of the last main-frame navigation before `idx`, else the start URL.
        let nav_before = |idx: usize| -> (&str, &str) {
            steps[..idx]
                .iter()
                .rev()
                .find_map(|s| match s {
                    Step::Navigation { url, .. } => Some((url.origin.as_str(), url.path.as_str())),
                    _ => None,
                })
                .unwrap_or((rec.start_url.origin.as_str(), rec.start_url.path.as_str()))
        };

        // Group credential steps into legs.
        let mut groups: Vec<Vec<usize>> = Vec::new();
        for &c in &credentials {
            let split = match groups.last() {
                None => true,
                Some(prev) => {
                    let first = prev[0];
                    let leg_at = nav_before(first);
                    let last = *prev.last().expect("a group is never empty");
                    steps[last..c]
                        .iter()
                        .any(|s| matches!(s, Step::Navigation { url, .. } if (url.origin.as_str(), url.path.as_str()) != leg_at))
                }
            };
            if split {
                groups.push(vec![c]);
            } else {
                groups.last_mut().expect("just checked").push(c);
            }
        }
        let want = if matches!(class.shape, Shape::TwoStep { .. }) {
            2
        } else {
            1
        };
        if groups.len() != want {
            return Err(ShapeMismatch);
        }
        let has_password = |g: &[usize]| {
            g.iter().any(|&i| {
                matches!(
                    steps[i],
                    Step::Input {
                        role: Role::Password,
                        ..
                    }
                )
            })
        };
        if !has_password(groups.last().expect("want is at least 1")) {
            return Err(ShapeMismatch);
        }

        let mut legs = Vec::new();
        for g in &groups {
            let (origin, path) = nav_before(g[0]);
            if origin != rec.start_url.origin {
                return Err(ShapeMismatch);
            }
            let mut method_steps = vec![MethodStep::Navigate { path: path.into() }];
            let role_at = |i: usize| match steps[i] {
                Step::Input {
                    role: Role::Username,
                    ..
                } => FillRole::Username,
                _ => FillRole::Password,
            };
            for (n, &i) in g.iter().enumerate() {
                let Step::Input { element, .. } = steps[i] else {
                    unreachable!("credential indexes point at inputs");
                };
                let role = role_at(i);
                // A person who typed a field again (a mistyped password, a form the page
                // drew again on the same path) left one input step per element. Only the
                // last of a role is the attempt that the successful submit followed.
                if g[n + 1..].iter().any(|&later| role_at(later) == role) {
                    continue;
                }
                let (selectors, expect) = reachable(element)?;
                method_steps.push(MethodStep::Fill {
                    role,
                    selectors,
                    expect,
                });
            }

            let after = *g.last().expect("a group is never empty") + 1;
            let region: Vec<&Step> = steps[after..]
                .iter()
                .take_while(|s| {
                    !matches!(s, Step::Navigation { url, .. }
                        if (url.origin.as_str(), url.path.as_str()) != (origin, path))
                })
                .copied()
                .collect();
            // A foreign-origin navigation that cuts the region short, before any submit.
            let foreign_cut = matches!(
                steps.get(after + region.len()),
                Some(Step::Navigation { url, .. }) if url.origin != rec.start_url.origin
            );
            let via = if region.iter().any(|s| matches!(s, Step::Submit { .. })) {
                SubmitVia::Form {}
            } else if region.iter().any(|s| matches!(s, Step::EnterKey { .. })) {
                SubmitVia::Enter {}
            } else {
                let clicks: Vec<&ElementDescriptor> = region
                    .iter()
                    .filter_map(|s| match s {
                        Step::Click { element, .. } => Some(element),
                        _ => None,
                    })
                    .collect();
                let pick = clicks
                    .iter()
                    .find(|e| is_submit_button(e))
                    .or(clicks.first())
                    .ok_or(if foreign_cut { ShapeMismatch } else { NoSubmit })?;
                let (selectors, expect) = reachable(pick)?;
                SubmitVia::Click { selectors, expect }
            };
            method_steps.push(MethodStep::Submit { via });
            legs.push(Leg {
                steps: method_steps,
            });
        }

        let last_path = match legs.last().and_then(|l| l.steps.first()) {
            Some(MethodStep::Navigate { path }) => path.as_str(),
            _ => return Err(ShapeMismatch),
        };
        let final_path = rec.final_url.as_ref().map(|u| u.path.clone());
        let success = match opts.success {
            Some(SuccessOverride::PathChanged) => SuccessCheck::PathChangedTo {
                path: final_path.ok_or(ShapeMismatch)?,
            },
            Some(SuccessOverride::PasswordFieldGone) => SuccessCheck::PasswordFieldGone {},
            Some(SuccessOverride::None) => SuccessCheck::None {},
            None => match final_path {
                Some(path) if path != last_path => SuccessCheck::PathChangedTo { path },
                _ => SuccessCheck::None {},
            },
        };

        let site_path = match legs[0].steps.first() {
            Some(MethodStep::Navigate { path }) => path.clone(),
            _ => return Err(ShapeMismatch),
        };
        let method = LoginMethod {
            format_version: METHOD_FORMAT_VERSION,
            site: Site {
                domain: domain.into(),
                origin: rec.start_url.origin.clone(),
                path: site_path,
            },
            shape: class.shape.clone(),
            rung,
            legs,
            success,
            provenance: Provenance::Recording {
                sha256: hex(&Sha256::digest(recording_bytes)),
                tool_version: rec.tool_version.clone(),
                browser_product: rec.browser.product.clone(),
                listener_world: rec.listener_world,
                rung_ceiling: class.rung_ceiling.clone(),
            },
        };
        method.validate().map_err(|_| ShapeMismatch)?;
        Ok(method)
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
            via: SubmitVia::Form {},
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
        for via in [SubmitVia::Form {}, SubmitVia::Enter {}, click] {
            let mut m = sample();
            *m.legs[0].steps.last_mut().unwrap() = MethodStep::Submit { via };
            round_trip(&m);
        }
        for success in [
            SuccessCheck::PathChangedTo { path: "/x".into() },
            SuccessCheck::PasswordFieldGone {},
            SuccessCheck::None {},
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
    fn req_tch_007_refuses_unknown_fields_on_unit_like_variants() {
        for (via, kind) in [(SubmitVia::Form {}, "form"), (SubmitVia::Enter {}, "enter")] {
            let mut m = sample();
            *m.legs[0].steps.last_mut().unwrap() = MethodStep::Submit { via };
            let json = m.to_json();
            let needle = format!("\"kind\": \"{kind}\"");
            assert!(json.contains(&needle), "{json}");
            let bad = json.replacen(&needle, &format!("{needle},\n\"value_len\": 8"), 1);
            assert!(matches!(
                LoginMethod::from_json(&bad),
                Err(MethodError::Parse(_))
            ));
        }
        for (success, kind) in [
            (SuccessCheck::None {}, "none"),
            (SuccessCheck::PasswordFieldGone {}, "password_field_gone"),
        ] {
            let mut m = sample();
            m.success = success;
            let json = m.to_json();
            let needle = format!("\"kind\": \"{kind}\"");
            assert!(json.contains(&needle), "{json}");
            let bad = json.replacen(&needle, &format!("{needle},\n\"placeholder\": \"x\""), 1);
            assert!(matches!(
                LoginMethod::from_json(&bad),
                Err(MethodError::Parse(_))
            ));
        }
        let hand = sample().to_json().replacen(
            "\"source\": \"recording\"",
            "\"source\": \"recording\",\n\"value_len\": 8",
            1,
        );
        assert!(matches!(
            LoginMethod::from_json(&hand),
            Err(MethodError::Parse(_))
        ));
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
            mutate(&|m| m.legs[0]
                .steps
                .insert(3, fill(FillRole::Password, "#pw", "password"))),
            "duplicate_role",
            "two password fills in one leg"
        );
        assert_eq!(
            mutate(&|m| m.legs[0]
                .steps
                .insert(1, fill(FillRole::Username, "#login", "text"))),
            "duplicate_role",
            "two user name fills in one leg, on different elements"
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
            "https://:80",
        ] {
            assert_eq!(mutate(&|m| m.site.origin = bad.into()), "origin", "{bad}");
        }
        let mut two = two_leg();
        two.legs[1].steps[0] = nav("password");
        assert_eq!(reason(&two), "path");
        assert_eq!(mutate(&|m| m.site.domain.clear()), "domain");
        assert_eq!(mutate(&|m| m.site.path = "/other".into()), "site_path");
    }

    #[test]
    fn req_tch_007_refuses_a_bad_tag_a_bad_path_and_equal_leg_paths() {
        for bad in ["", "INPUT", "in put", "input!", "inp\u{fc}t"] {
            let mut m = sample();
            m.legs[0].steps[1] = MethodStep::Fill {
                role: FillRole::Username,
                selectors: vec!["#user".into()],
                expect: Expected {
                    tag: bad.into(),
                    ..expected("text")
                },
            };
            assert_eq!(reason(&m), "tag", "fill {bad:?}");
            let mut m = sample();
            *m.legs[0].steps.last_mut().unwrap() = MethodStep::Submit {
                via: SubmitVia::Click {
                    selectors: vec!["button".into()],
                    expect: Expected {
                        tag: bad.into(),
                        ..expected("submit")
                    },
                },
            };
            assert_eq!(reason(&m), "tag", "click {bad:?}");
        }
        for ok in ["input", "button", "my-element", "h1"] {
            let mut m = sample();
            m.legs[0].steps[1] = MethodStep::Fill {
                role: FillRole::Username,
                selectors: vec!["#user".into()],
                expect: Expected {
                    tag: ok.into(),
                    ..expected("text")
                },
            };
            assert!(m.validate().is_ok(), "{ok}");
        }
        for bad in ["/log in", "/l\u{f6}gin", "/a\\b", "/a\"b", "/a<b", "/a{b}"] {
            let mut m = sample();
            m.site.path = bad.into();
            m.legs[0].steps[0] = nav(bad);
            assert_eq!(reason(&m), "path", "{bad:?}");
        }
        for ok in ["/log%20in", "/a-b_c.d~e/f", "/u/(x);y=1,2:3@4+5*6!7$8&9'"] {
            let mut m = sample();
            m.site.path = ok.into();
            m.legs[0].steps[0] = nav(ok);
            assert!(m.validate().is_ok(), "{ok}");
        }
        let mut two = two_leg();
        two.legs[1].steps[0] = nav("/login");
        assert_eq!(reason(&two), "legs");
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

    mod convert {
        use super::super::*;
        use crate::classify::{Classification, Flags, PasswordLeg};
        use crate::format::{
            BrowserInfo, EndedBy, FORMAT_VERSION, FormRef, FrameRef, StrippedCounts, StrippedUrl,
            Viewport,
        };
        use crate::request::{
            BodyShape, Encoding, FieldShape, MarkerHit, ResourceKind, StoredRequest, ValueKind,
            ValueShape,
        };

        const ORIGIN: &str = "https://example.test";

        fn url(path: &str) -> StrippedUrl {
            StrippedUrl {
                origin: ORIGIN.into(),
                path: path.into(),
                query_keys: vec!["receipt".into()],
            }
        }

        fn frame(main: bool) -> FrameRef {
            FrameRef {
                main,
                origin: ORIGIN.into(),
                cross_origin: !main,
            }
        }

        fn el(id: &str, tag: &str, input_type: &str, ac: Option<&str>) -> ElementDescriptor {
            ElementDescriptor {
                element_id: 1,
                tag: tag.into(),
                input_type: Some(input_type.into()),
                id: Some(id.into()),
                name: Some(id.into()),
                autocomplete: ac.map(Into::into),
                placeholder: Some("zz-ph".into()),
                aria_label: Some("zz-aria".into()),
                was_password: input_type == "password",
                form: Some(FormRef {
                    index: 0,
                    action: Some(url("/zz-api/submit")),
                    method: "post".into(),
                }),
                selectors: vec![format!("#{id}")],
                in_shadow_root: false,
            }
        }

        fn nav(path: &str) -> Step {
            Step::Navigation {
                t_ms: 1,
                frame: frame(true),
                url: url(path),
            }
        }

        fn input(role: Role, e: ElementDescriptor) -> Step {
            Step::Input {
                t_ms: 2,
                frame: frame(true),
                element: e,
                value_len: 9,
                role,
            }
        }

        fn click(e: ElementDescriptor) -> Step {
            Step::Click {
                t_ms: 3,
                frame: frame(true),
                element: e,
            }
        }

        fn form_submit() -> Step {
            Step::Submit {
                t_ms: 4,
                frame: frame(true),
                form: FormRef {
                    index: 0,
                    action: None,
                    method: "post".into(),
                },
            }
        }

        fn enter() -> Step {
            Step::EnterKey {
                t_ms: 4,
                frame: frame(true),
                element: el("pw", "input", "password", None),
            }
        }

        fn user() -> Step {
            input(
                Role::Username,
                el("user", "input", "text", Some("username")),
            )
        }

        fn pass() -> Step {
            input(Role::Password, el("pw", "input", "password", None))
        }

        fn rec(shape: Shape, ceiling: RungCeiling, steps: Vec<Step>) -> Recording {
            let value = ValueShape {
                kind: ValueKind::String,
                len: 9,
                markers: vec![MarkerHit {
                    role: Role::Password,
                    encoding: Encoding::AsTyped,
                    low_confidence: false,
                }],
            };
            Recording {
                format_version: FORMAT_VERSION,
                tool_version: "9.9.9".into(),
                browser: BrowserInfo {
                    product: "Chrome/1".into(),
                    user_agent: "zz-agent".into(),
                    viewport: Viewport {
                        width: 1,
                        height: 1,
                    },
                },
                listener_world: ListenerWorld::Isolated,
                started_at: "2026-11-24T00:00:00Z".into(),
                ended_at: "2026-11-24T00:01:00Z".into(),
                ended_by: EndedBy::Confirmed,
                success_confirmed: true,
                start_url: url("/login"),
                final_url: Some(url("/home")),
                steps,
                requests: vec![StoredRequest {
                    t_ms: 5,
                    method: "POST".into(),
                    url: url("/zz-api/submit"),
                    resource: ResourceKind::Document,
                    main_frame_navigation: true,
                    content_type: None,
                    authorization: None,
                    url_markers: vec![],
                    body: BodyShape::Urlencoded {
                        fields: vec![FieldShape {
                            key: "zz_field_key".into(),
                            value,
                        }],
                    },
                    response: None,
                }],
                flags: Flags::default(),
                classification: Classification {
                    shape,
                    rung_ceiling: ceiling,
                    network_swap_candidate: false,
                    notes: vec![],
                },
                stripped: StrippedCounts {
                    requests_seen: 1,
                    requests_stored: 1,
                    request_bodies_reduced: 1,
                    query_values_removed: 1,
                    path_segments_replaced: 0,
                    typed_values_removed: 2,
                    steps_dropped: 0,
                },
            }
        }

        fn form_post() -> Recording {
            rec(
                Shape::FormPost,
                RungCeiling::Milliseconds,
                vec![nav("/login"), user(), pass(), form_submit(), nav("/home")],
            )
        }

        fn script_post() -> Recording {
            let mut go = el("go", "button", "submit", None);
            go.selectors = vec!["#go".into(), "button.go".into()];
            rec(
                Shape::ScriptPost,
                RungCeiling::Milliseconds,
                vec![nav("/login"), user(), pass(), click(go), nav("/home")],
            )
        }

        fn two_step() -> Recording {
            rec(
                Shape::TwoStep {
                    password_leg: PasswordLeg::FormPost,
                },
                RungCeiling::AgentContinues,
                vec![
                    nav("/login"),
                    user(),
                    form_submit(),
                    nav("/password"),
                    pass(),
                    form_submit(),
                    nav("/home"),
                ],
            )
        }

        fn transformed() -> Recording {
            let mut r = form_post();
            r.classification.shape = Shape::Transformed {
                digest: Some("sha256".into()),
            };
            r
        }

        fn convert(r: &Recording) -> Result<LoginMethod, NotConvertible> {
            LoginMethod::from_recording(r, b"bytes", "example.test", ConvertOptions::default())
        }

        fn exp(id: &str, tag: &str, input_type: &str, ac: Option<&str>) -> Expected {
            Expected {
                tag: tag.into(),
                input_type: Some(input_type.into()),
                id: Some(id.into()),
                name: Some(id.into()),
                autocomplete: ac.map(Into::into),
            }
        }

        fn user_fill() -> MethodStep {
            MethodStep::Fill {
                role: FillRole::Username,
                selectors: vec!["#user".into()],
                expect: exp("user", "input", "text", Some("username")),
            }
        }

        fn pass_fill() -> MethodStep {
            MethodStep::Fill {
                role: FillRole::Password,
                selectors: vec!["#pw".into()],
                expect: exp("pw", "input", "password", None),
            }
        }

        fn form_step() -> MethodStep {
            MethodStep::Submit {
                via: SubmitVia::Form {},
            }
        }

        fn want(shape: Shape, rung: Rung, ceiling: RungCeiling, legs: Vec<Leg>) -> LoginMethod {
            LoginMethod {
                format_version: METHOD_FORMAT_VERSION,
                site: Site {
                    domain: "example.test".into(),
                    origin: ORIGIN.into(),
                    path: "/login".into(),
                },
                shape,
                rung,
                legs,
                success: SuccessCheck::PathChangedTo {
                    path: "/home".into(),
                },
                provenance: Provenance::Recording {
                    sha256: hex(&Sha256::digest(b"bytes")),
                    tool_version: "9.9.9".into(),
                    browser_product: "Chrome/1".into(),
                    listener_world: ListenerWorld::Isolated,
                    rung_ceiling: ceiling,
                },
            }
        }

        fn one_leg(submit: MethodStep) -> Vec<Leg> {
            vec![Leg {
                steps: vec![
                    MethodStep::Navigate {
                        path: "/login".into(),
                    },
                    user_fill(),
                    pass_fill(),
                    submit,
                ],
            }]
        }

        #[test]
        fn converts_form_post() {
            assert_eq!(
                convert(&form_post()).unwrap(),
                want(
                    Shape::FormPost,
                    Rung::Milliseconds,
                    RungCeiling::Milliseconds,
                    one_leg(form_step())
                )
            );
        }

        #[test]
        fn converts_script_post() {
            let click = MethodStep::Submit {
                via: SubmitVia::Click {
                    selectors: vec!["#go".into(), "button.go".into()],
                    expect: exp("go", "button", "submit", None),
                },
            };
            assert_eq!(
                convert(&script_post()).unwrap(),
                want(
                    Shape::ScriptPost,
                    Rung::Milliseconds,
                    RungCeiling::Milliseconds,
                    one_leg(click)
                )
            );
        }

        #[test]
        fn converts_two_step() {
            let legs = vec![
                Leg {
                    steps: vec![
                        MethodStep::Navigate {
                            path: "/login".into(),
                        },
                        user_fill(),
                        form_step(),
                    ],
                },
                Leg {
                    steps: vec![
                        MethodStep::Navigate {
                            path: "/password".into(),
                        },
                        pass_fill(),
                        form_step(),
                    ],
                },
            ];
            assert_eq!(
                convert(&two_step()).unwrap(),
                want(
                    Shape::TwoStep {
                        password_leg: PasswordLeg::FormPost
                    },
                    Rung::AgentContinues,
                    RungCeiling::AgentContinues,
                    legs
                )
            );
        }

        #[test]
        fn converts_transformed_with_named_digest() {
            assert_eq!(
                convert(&transformed()).unwrap(),
                want(
                    Shape::Transformed {
                        digest: Some("sha256".into())
                    },
                    Rung::Milliseconds,
                    RungCeiling::Milliseconds,
                    one_leg(form_step())
                )
            );
        }

        #[test]
        fn a_retyped_field_keeps_only_its_last_input() {
            // A wrong password, the form drawn again on the same path with a new
            // password element, then the attempt that worked.
            let retry = || input(Role::Password, el("pw2", "input", "password", None));
            let pass2_fill = || MethodStep::Fill {
                role: FillRole::Password,
                selectors: vec!["#pw2".into()],
                expect: exp("pw2", "input", "password", None),
            };
            let r = rec(
                Shape::FormPost,
                RungCeiling::Milliseconds,
                vec![
                    nav("/login"),
                    user(),
                    pass(),
                    form_submit(),
                    nav("/login"),
                    retry(),
                    form_submit(),
                    nav("/home"),
                ],
            );
            let got = convert(&r).unwrap();
            let leg = vec![Leg {
                steps: vec![
                    MethodStep::Navigate {
                        path: "/login".into(),
                    },
                    user_fill(),
                    pass2_fill(),
                    form_step(),
                ],
            }];
            assert_eq!(
                got,
                want(
                    Shape::FormPost,
                    Rung::Milliseconds,
                    RungCeiling::Milliseconds,
                    leg
                )
            );
            got.validate().unwrap();

            // Both fields typed again: the last of each role, in the order typed.
            let user2 = input(Role::Username, el("user2", "input", "text", None));
            let r = rec(
                Shape::FormPost,
                RungCeiling::Milliseconds,
                vec![
                    nav("/login"),
                    user(),
                    pass(),
                    form_submit(),
                    nav("/login"),
                    user2,
                    retry(),
                    form_submit(),
                    nav("/home"),
                ],
            );
            let got = convert(&r).unwrap();
            assert_eq!(
                got.legs[0].steps[1..3],
                [
                    MethodStep::Fill {
                        role: FillRole::Username,
                        selectors: vec!["#user2".into()],
                        expect: exp("user2", "input", "text", None),
                    },
                    pass2_fill(),
                ]
            );
            got.validate().unwrap();

            // The password leg of a two-step login.
            let mut r = two_step();
            r.steps.insert(5, retry());
            let got = convert(&r).unwrap();
            assert_eq!(
                got.legs[1].steps,
                vec![
                    MethodStep::Navigate {
                        path: "/password".into(),
                    },
                    pass2_fill(),
                    form_step(),
                ]
            );
            got.validate().unwrap();
        }

        #[test]
        fn refuses_unrecognized() {
            let mut r = form_post();
            r.classification.shape = Shape::Unrecognized;
            assert_eq!(convert(&r), Err(NotConvertible::NeedsPerson));
            let mut r = form_post();
            r.classification.rung_ceiling = RungCeiling::NeedsPerson;
            assert_eq!(convert(&r), Err(NotConvertible::NeedsPerson));
        }

        #[test]
        fn refuses_transformed_without_digest() {
            let mut r = form_post();
            r.classification.shape = Shape::Transformed { digest: None };
            assert_eq!(convert(&r), Err(NotConvertible::NeedsPerson));
        }

        #[test]
        fn refuses_shadow_root_step() {
            let mut e = el("pw", "input", "password", None);
            e.in_shadow_root = true;
            let mut r = form_post();
            r.steps[2] = input(Role::Password, e);
            assert_eq!(convert(&r), Err(NotConvertible::InShadowRoot));
            let mut go = el("go", "button", "submit", None);
            go.in_shadow_root = true;
            let mut r = script_post();
            r.steps[3] = click(go);
            assert_eq!(convert(&r), Err(NotConvertible::InShadowRoot));
        }

        #[test]
        fn refuses_a_leg_without_submit() {
            let mut r = form_post();
            r.steps.remove(3);
            assert_eq!(convert(&r), Err(NotConvertible::NoSubmit));
            let mut r = two_step();
            r.steps.remove(2);
            assert_eq!(convert(&r), Err(NotConvertible::NoSubmit));
        }

        #[test]
        fn refuses_unconfirmed_without_the_flag() {
            let mut r = form_post();
            r.success_confirmed = false;
            assert_eq!(convert(&r), Err(NotConvertible::Unconfirmed));
            let opts = ConvertOptions {
                allow_unconfirmed: true,
                ..Default::default()
            };
            assert!(LoginMethod::from_recording(&r, b"bytes", "example.test", opts).is_ok());
        }

        #[test]
        fn refuses_a_recording_that_disagrees_with_its_shape() {
            let mut r = form_post();
            r.classification.shape = Shape::TwoStep {
                password_leg: PasswordLeg::FormPost,
            };
            assert_eq!(convert(&r), Err(NotConvertible::ShapeMismatch));
            let mut r = form_post();
            r.steps.remove(2);
            assert_eq!(convert(&r), Err(NotConvertible::ShapeMismatch));
            let mut r = form_post();
            r.steps.retain(|s| !matches!(s, Step::Input { .. }));
            assert_eq!(convert(&r), Err(NotConvertible::ShapeMismatch));
            let mut e = el("pw", "input", "password", None);
            e.selectors.clear();
            let mut r = form_post();
            r.steps[2] = input(Role::Password, e);
            assert_eq!(convert(&r), Err(NotConvertible::ShapeMismatch));
        }

        #[test]
        fn a_cross_origin_leg_is_a_mismatch() {
            let mut r = two_step();
            r.steps[3] = Step::Navigation {
                t_ms: 1,
                frame: frame(true),
                url: StrippedUrl {
                    origin: "https://other.test".into(),
                    path: "/password".into(),
                    query_keys: vec![],
                },
            };
            assert_eq!(convert(&r), Err(NotConvertible::ShapeMismatch));
        }

        fn nav_to(origin: &str, path: &str) -> Step {
            Step::Navigation {
                t_ms: 1,
                frame: frame(true),
                url: StrippedUrl {
                    origin: origin.into(),
                    path: path.into(),
                    query_keys: vec![],
                },
            }
        }

        #[test]
        fn a_same_path_on_another_origin_is_a_mismatch() {
            // The password would be typed on a different origin.
            let r = rec(
                Shape::FormPost,
                RungCeiling::Milliseconds,
                vec![
                    nav("/login"),
                    user(),
                    nav_to("https://other.test", "/login"),
                    pass(),
                    form_submit(),
                ],
            );
            assert_eq!(convert(&r), Err(NotConvertible::ShapeMismatch));
            // Cut off before any submit by a foreign navigation.
            let r = rec(
                Shape::FormPost,
                RungCeiling::Milliseconds,
                vec![
                    nav("/login"),
                    user(),
                    pass(),
                    nav_to("https://other.test", "/login"),
                    form_submit(),
                ],
            );
            assert_eq!(convert(&r), Err(NotConvertible::ShapeMismatch));
        }

        #[test]
        fn submit_selection_stops_at_the_leg_boundary() {
            let mut r = two_step();
            r.steps[2] = enter();
            let m = convert(&r).unwrap();
            assert_eq!(
                m.legs[0].steps.last(),
                Some(&MethodStep::Submit {
                    via: SubmitVia::Enter {}
                })
            );
            assert_eq!(m.legs[1].steps.last(), Some(&form_step()));
        }

        #[test]
        fn other_frames_are_ignored() {
            let mut r = form_post();
            let mut stray = click(el("ad", "button", "submit", None));
            if let Step::Click { frame, .. } = &mut stray {
                frame.main = false;
            }
            r.steps.insert(3, stray);
            r.steps.remove(4);
            assert_eq!(convert(&r), Err(NotConvertible::NoSubmit));
        }

        #[test]
        fn req_tch_007_method_holds_none_of_the_dropped_fields() {
            for r in [form_post(), script_post(), two_step(), transformed()] {
                let text = convert(&r).unwrap().to_json();
                for gone in [
                    "receipt",
                    "query_keys",
                    "value_len",
                    "placeholder",
                    "aria_label",
                    "requests",
                    "t_ms",
                    "user_agent",
                    "viewport",
                    "flags",
                    "stripped",
                    "zz-",
                    "zz_",
                ] {
                    assert!(!text.contains(gone), "{gone} leaked into {text}");
                }
            }
        }

        #[test]
        fn picks_the_button_not_the_checkbox() {
            let mut r = script_post();
            r.steps[3] = click(el("remember", "input", "checkbox", None));
            let mut go = el("go", "button", "submit", None);
            go.selectors = vec!["#go".into()];
            r.steps.insert(4, click(go));
            let m = convert(&r).unwrap();
            match m.legs[0].steps.last() {
                Some(MethodStep::Submit {
                    via: SubmitVia::Click { selectors, .. },
                }) => assert_eq!(selectors, &vec!["#go".to_string()]),
                other => panic!("{other:?}"),
            }
        }

        #[test]
        fn enter_in_a_form_is_a_form_submit() {
            let mut r = form_post();
            r.steps.insert(3, enter());
            let m = convert(&r).unwrap();
            assert_eq!(m.legs[0].steps.last(), Some(&form_step()));
            let mut r = form_post();
            r.steps[3] = enter();
            let m = convert(&r).unwrap();
            assert_eq!(
                m.legs[0].steps.last(),
                Some(&MethodStep::Submit {
                    via: SubmitVia::Enter {}
                })
            );
        }

        #[test]
        fn success_override_is_used() {
            let with = |success, r: &Recording| {
                let opts = ConvertOptions {
                    success: Some(success),
                    ..Default::default()
                };
                LoginMethod::from_recording(r, b"bytes", "example.test", opts)
            };
            let r = form_post();
            assert_eq!(
                with(SuccessOverride::None, &r).unwrap().success,
                SuccessCheck::None {}
            );
            assert_eq!(
                with(SuccessOverride::PasswordFieldGone, &r)
                    .unwrap()
                    .success,
                SuccessCheck::PasswordFieldGone {}
            );
            assert_eq!(
                with(SuccessOverride::PathChanged, &r).unwrap().success,
                SuccessCheck::PathChangedTo {
                    path: "/home".into()
                }
            );
            let mut r = form_post();
            r.final_url = None;
            assert_eq!(
                with(SuccessOverride::PathChanged, &r),
                Err(NotConvertible::ShapeMismatch)
            );
            assert_eq!(convert(&r).unwrap().success, SuccessCheck::None {});
        }

        #[test]
        fn an_unchanged_final_path_is_no_success_check() {
            let mut r = form_post();
            r.final_url = Some(url("/login"));
            assert_eq!(convert(&r).unwrap().success, SuccessCheck::None {});
        }

        #[test]
        fn provenance_digest_is_the_sha256_of_the_bytes() {
            let m = LoginMethod::from_recording(
                &form_post(),
                b"abc",
                "example.test",
                ConvertOptions::default(),
            )
            .unwrap();
            assert_eq!(
                m.digest(),
                Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            );
        }
    }
}
