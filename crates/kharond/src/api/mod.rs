//! Agent-facing API (SPEC §4; issue #14).
//!
//! - [`token`]: agent tokens, Argon2id hashes, verification (REQ-API-003).
//! - [`meta`]: `ItemMeta` and the origin/search filters (REQ-API-004).
//! - [`error`]: fixed-text errors (REQ-API-006).
//! - [`core`]: transport-independent dispatch (REQ-API-002).
//! - [`fill`]: `fill` / `fill_totp` requests, results and the browser
//!   backend (REQ-API-008, REQ-API-009; #18, #19).
//! - [`http`]: the `/v1/*` HTTP transport and its OpenAPI document.
//! - [`mcp`]: the MCP transport (`POST /mcp`, REQ-API-001), a second
//!   adapter over [`core`] on the same listener.
//! - [`surface`]: every tool/route and its response schema
//!   (REQ-GOAL-001).
//!
//! Grants (`kharon_request_grant`, `POST /v1/grants`) arrive with #20.

pub mod core;
pub mod error;
pub mod fill;
pub mod http;
pub mod mcp;
pub mod meta;
pub mod surface;
pub mod token;

pub use self::core::{
    AgentId, AuditSink, Broker, ContextResult, FillSync, Outcome, Request, StatusBody, SyncFetch,
    VaultView,
};
pub use error::{ApiError, Detail, ErrorBody, ErrorCode};
pub use fill::{
    CdpFillBackend, ConnectingCdpBackend, FillBackend, FillOperation, FillPolicy, FillRequest,
    FillResult, FillStatus, parse_fill,
};
pub use meta::ItemMeta;
pub use token::{ParamFloor, TokenStore};
