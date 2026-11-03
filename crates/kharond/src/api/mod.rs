//! Agent-facing API (SPEC §4; issue #14).
//!
//! - [`token`]: agent tokens, Argon2id hashes, verification (REQ-API-003).
//! - [`meta`]: `ItemMeta` and the origin/search filters (REQ-API-004).
//! - [`error`]: fixed-text errors (REQ-API-006).
//! - [`core`]: transport-independent dispatch (REQ-API-002).
//! - [`http`]: the `/v1/*` HTTP transport and its OpenAPI document.
//!
//! The MCP transport (REQ-API-001, issue #15) is a second adapter over
//! [`core`]. Fill endpoints arrive with #18.

pub mod core;
pub mod error;
pub mod http;
pub mod meta;
pub mod token;

pub use self::core::{AgentId, AuditSink, Broker, Outcome, Request, StatusBody, VaultView};
pub use error::{ApiError, Detail, ErrorCode};
pub use meta::ItemMeta;
pub use token::{ParamFloor, TokenStore};
