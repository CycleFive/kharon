//! The agent API's response surface (REQ-GOAL-001; #18).
//!
//! Every MCP tool and its HTTP route, with the JSON Schema of the body
//! it answers with, generated from the Rust type that is serialized
//! ([`schemars`], the same generator as the tool input schemas). The
//! REQ-GOAL-001 schema test (`tests/req_goal_001_surface.rs`) walks
//! these schemas and the OpenAPI document; this module is the one place
//! a new response type has to be listed.
//!
//! Two properties keep secret types off it:
//!
//! - [`schema_of`] requires `Serialize`, and `Secret<…>` does not
//!   implement it (REQ-API-005, a `trybuild` compile-fail test), so a
//!   response type that held one, directly or nested, could not be
//!   listed here (or serialized by a transport at all).
//! - The matches below are exhaustive over [`Tool`], so a new tool does
//!   not build until its response type is listed.

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, Schema};
use serde::Serialize;

use super::core::{ContextResult, StatusBody};
use super::error::ErrorBody;
use super::fill::FillResult;
use super::mcp::Tool;
use super::meta::ItemMeta;

/// The HTTP route serving the same operation as `tool`: `(method, path)`.
pub const fn http_route(tool: Tool) -> (&'static str, &'static str) {
    match tool {
        Tool::Status => ("GET", "/v1/status"),
        Tool::List | Tool::Search => ("GET", "/v1/items"),
        Tool::Fill => ("POST", super::http::FILL_PATH),
        Tool::FillTotp => ("POST", super::http::FILL_TOTP_PATH),
        Tool::Context => ("POST", super::http::CONTEXT_PATH),
    }
}

/// The schema of `tool`'s success body (the HTTP 200 body, and the MCP
/// tool result text).
pub fn response_schema(tool: Tool) -> Schema {
    match tool {
        Tool::Status => schema_of::<StatusBody>(),
        Tool::List | Tool::Search => schema_of::<Vec<ItemMeta>>(),
        Tool::Fill | Tool::FillTotp => schema_of::<FillResult>(),
        Tool::Context => schema_of::<ContextResult>(),
    }
}

/// The schema of the error body every route and tool can answer with.
pub fn error_schema() -> Schema {
    schema_of::<ErrorBody>()
}

/// A response type's schema. `Serialize` is the REQ-API-005 gate: no
/// type containing a `Secret` satisfies it.
pub fn schema_of<T: Serialize + JsonSchema>() -> Schema {
    SchemaSettings::draft2020_12()
        .with(|s| s.meta_schema = None)
        .into_generator()
        .into_root_schema_for::<T>()
}
