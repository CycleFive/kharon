//! Classification types. Task 2 adds the classifier functions.

use serde::{Deserialize, Serialize};

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
#[serde(tag = "shape", rename_all = "snake_case")]
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
