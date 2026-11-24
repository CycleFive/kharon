//! Shared types between the method registry (`crate::teach`) and the fill
//! engine: what a lookup returns, and the record of how a fill used it.
//! Plain data only. Nothing here holds a value or page text.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use kharon_recording::{
    Expected, FillRole, LoginMethod, MethodStep, Rung, Shape, SubmitVia, SuccessCheck,
};
use serde::Serialize;

use super::fill::FieldKind;

/// Where the fill engine finds a site's taught method.
pub trait MethodSource: Send + Sync + std::fmt::Debug {
    /// The site's method for the page at `live_url` (the URL the browser reported), if the registry holds one.
    fn lookup(&self, live_url: &str) -> Option<MethodLookup>;
}

#[derive(Debug, Clone)]
pub struct MethodLookup {
    pub domain: String,
    pub method: Arc<LoginMethod>,
    /// Step number (flat index) to owner-supplied selectors, tried first.
    pub overrides: BTreeMap<u32, Vec<String>>,
    pub stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodResult {
    Succeeded,
    Unconfirmed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodEnd {
    Stale,
    WrongPage,
    FieldNotRequested,
    Drift { step: u32 },
    NotReady { step: u32 },
    Filled(MethodResult),
    Other,
}

/// How one fill used a method; handed to `TeachRegistry::record_fill`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodUse {
    pub domain: String,
    pub rung: Rung,
    pub end: MethodEnd,
    pub selectors_ignored: bool,
    pub browser_product: Option<String>,
}

/// A write-once slot a fill path shares with its caller to report a [`MethodUse`].
#[derive(Debug, Clone, Default)]
pub struct MethodNote(Arc<OnceLock<MethodUse>>);

impl MethodNote {
    pub fn new() -> Self {
        Self::default()
    }

    /// First write wins; returns whether this call was the first.
    pub fn record(&self, used: MethodUse) -> bool {
        self.0.set(used).is_ok()
    }

    pub fn get(&self) -> Option<&MethodUse> {
        self.0.get()
    }
}

/// The in-page leg argument (7th argument of `fillInPage`). It holds
/// selectors and shape checks, never a value: `fields[i]` of the call
/// carries the value for `fills[i]`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct InPageLeg {
    pub path: String,
    pub fills: Vec<InPageFill>,
    pub submit: Option<InPageSubmit>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InPageFill {
    pub index: u32,
    pub selectors: Vec<String>,
    pub password: bool,
    pub expect: Expected,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct InPageSubmit {
    pub index: u32,
    pub via: InPageVia,
    pub selectors: Vec<String>,
    pub expect: Option<Expected>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InPageVia {
    Form,
    Enter,
    Click,
}

/// What `prepare` decided for one method fill.
#[derive(Debug, Clone)]
pub(crate) struct Prepared {
    pub leg: InPageLeg,
    /// The leg's fill roles in write order; the only kinds sent to the page.
    pub order: Vec<FieldKind>,
    pub submit: bool,
    pub scrub: bool,
    /// The live path the leg matched (same as `leg.path`); kept for the broker's audit.
    #[allow(dead_code)]
    pub leg_path: String,
    pub has_password: bool,
    pub success: SuccessCheck,
    pub rung: Rung,
}

fn kind_of(role: FillRole) -> FieldKind {
    match role {
        FillRole::Username => FieldKind::Username,
        FillRole::Password => FieldKind::Password,
    }
}

/// Pick the leg for the live page and build the in-page argument.
/// Nothing here talks to the browser. Errors are the ends that send
/// nothing: `Stale`, `WrongPage`, `FieldNotRequested`.
pub(crate) fn prepare(
    lookup: &MethodLookup,
    live_url: &str,
    requested: &[FieldKind],
    plan_submit: bool,
    plan_scrub: bool,
) -> Result<Prepared, MethodEnd> {
    if lookup.stale {
        return Err(MethodEnd::Stale);
    }
    let method = &*lookup.method;
    let live = url::Url::parse(live_url).map_err(|_| MethodEnd::WrongPage)?;
    // The same registrable domain is not enough: a sibling origin is another site.
    if live.origin().ascii_serialization() != method.site.origin {
        return Err(MethodEnd::WrongPage);
    }
    let path = live.path();

    // The first leg at this path whose fill roles were all requested; failing
    // that, the first leg at this path (which then refuses the fill).
    let mut chosen = None;
    let mut first_at_path = None;
    for (li, leg) in method.legs.iter().enumerate() {
        if !matches!(leg.steps.first(), Some(MethodStep::Navigate { path: p }) if p == path) {
            continue;
        }
        let covered = leg.steps.iter().all(|s| match s {
            MethodStep::Fill { role, .. } => requested.contains(&kind_of(*role)),
            _ => true,
        });
        if covered {
            chosen = Some(li);
            break;
        }
        first_at_path.get_or_insert(li);
    }
    let Some(leg_index) = chosen else {
        return Err(if first_at_path.is_some() {
            MethodEnd::FieldNotRequested
        } else {
            MethodEnd::WrongPage
        });
    };

    let with_overrides = |index: u32, own: &[String]| -> Vec<String> {
        lookup
            .overrides
            .get(&index)
            .into_iter()
            .flatten()
            .chain(own)
            .cloned()
            .collect()
    };
    let mut fills = Vec::new();
    let mut order = Vec::new();
    let mut submit_step = None;
    for (index, li, step) in method.steps() {
        if li != leg_index {
            continue;
        }
        match step {
            MethodStep::Navigate { .. } => {}
            MethodStep::Fill {
                role,
                selectors,
                expect,
            } => {
                fills.push(InPageFill {
                    index,
                    selectors: with_overrides(index, selectors),
                    password: *role == FillRole::Password,
                    expect: expect.clone(),
                });
                order.push(kind_of(*role));
            }
            MethodStep::Submit { via } => {
                submit_step = Some(match via {
                    SubmitVia::Form {} => InPageSubmit {
                        index,
                        via: InPageVia::Form,
                        selectors: Vec::new(),
                        expect: None,
                    },
                    SubmitVia::Enter {} => InPageSubmit {
                        index,
                        via: InPageVia::Enter,
                        selectors: Vec::new(),
                        expect: None,
                    },
                    SubmitVia::Click { selectors, expect } => InPageSubmit {
                        index,
                        via: InPageVia::Click,
                        selectors: with_overrides(index, selectors),
                        expect: Some(expect.clone()),
                    },
                });
            }
        }
    }

    let has_password = fills.iter().any(|f| f.password);
    let force = method.rung == Rung::Milliseconds || matches!(method.shape, Shape::TwoStep { .. });
    // A leg without a submit step has nothing to submit with.
    let submit = (force || plan_submit) && submit_step.is_some();
    let scrub = submit && (plan_scrub || (force && has_password));
    Ok(Prepared {
        leg: InPageLeg {
            path: path.to_owned(),
            fills,
            submit: submit_step,
        },
        order,
        submit,
        scrub,
        leg_path: path.to_owned(),
        has_password,
        success: method.success.clone(),
        rung: method.rung,
    })
}

/// Read the method's success check from what the one re-read saw.
pub(crate) fn judge(
    check: &SuccessCheck,
    has_password: bool,
    loader_changed: bool,
    path_now: Option<&str>,
    password_connected: Option<bool>,
) -> MethodResult {
    if !has_password {
        return MethodResult::Unconfirmed;
    }
    match check {
        SuccessCheck::None {} => MethodResult::Unconfirmed,
        SuccessCheck::PathChangedTo { path } => match path_now {
            Some(now) if now == path => MethodResult::Succeeded,
            Some(_) if loader_changed => MethodResult::Failed,
            _ => MethodResult::Unconfirmed,
        },
        SuccessCheck::PasswordFieldGone {} => {
            if loader_changed {
                MethodResult::Succeeded
            } else {
                match password_connected {
                    Some(false) => MethodResult::Succeeded,
                    Some(true) => MethodResult::Failed,
                    None => MethodResult::Unconfirmed,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judge_table() {
        use MethodResult::*;
        let path = SuccessCheck::PathChangedTo {
            path: "/home".into(),
        };
        let gone = SuccessCheck::PasswordFieldGone {};
        let none = SuccessCheck::None {};
        // (check, has_password, loader_changed, path_now, connected, want)
        type Row<'a> = (
            &'a SuccessCheck,
            bool,
            bool,
            Option<&'a str>,
            Option<bool>,
            MethodResult,
        );
        let rows: Vec<Row> = vec![
            (&path, false, true, Some("/home"), None, Unconfirmed),
            (&gone, false, true, None, Some(false), Unconfirmed),
            (&none, true, true, Some("/home"), Some(false), Unconfirmed),
            (&path, true, true, Some("/home"), None, Succeeded),
            (&path, true, false, Some("/home"), None, Succeeded),
            (&path, true, true, Some("/login"), None, Failed),
            (&path, true, false, Some("/login"), None, Unconfirmed),
            (&path, true, true, None, None, Unconfirmed),
            (&path, true, false, None, None, Unconfirmed),
            (&gone, true, true, None, None, Succeeded),
            (&gone, true, true, None, Some(true), Succeeded),
            (&gone, true, false, None, Some(false), Succeeded),
            (&gone, true, false, None, Some(true), Failed),
            (&gone, true, false, None, None, Unconfirmed),
        ];
        for (check, pw, changed, now, connected, want) in rows {
            assert_eq!(
                judge(check, pw, changed, now, connected),
                want,
                "{check:?} pw={pw} changed={changed} now={now:?} connected={connected:?}"
            );
        }
    }
}
