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
//! - [`grant`]: the grant model and request lifecycle (SPEC §5,
//!   REQ-APR-001/002/003/007; #20), behind `kharon_request_grant`,
//!   `POST /v1/grants`, the fill grant gate and status's grants.
//! - [`approval`]: one-time ntfy approval tokens (REQ-APR-004; #21),
//!   redeemed on the owner listener (`/owner/approve|deny/<token>`
//!   in [`http`], mounted by the owner UI).
//! - [`notify`]: publishing approval prompts to the owner's ntfy
//!   topic (REQ-APR-004 send half; #128).

pub mod approval;
pub mod core;
pub mod error;
pub mod fill;
pub mod grant;
pub mod http;
pub mod mcp;
pub mod meta;
pub mod notify;
pub mod rate;
pub mod rollback;
pub mod surface;
pub mod token;

pub use self::core::{
    AgentId, AuditSink, Broker, ContextResult, FillSync, Outcome, Request, StatusBody, SyncFetch,
    VaultView,
};
pub use approval::{
    ApprovalAction, ApprovalTokenStore, TOKEN_TTL as APPROVAL_TOKEN_TTL, TokenGone,
};
pub use error::{ApiError, Detail, ErrorBody, ErrorCode};
pub use fill::{
    CdpFillBackend, ConnectingCdpBackend, FillBackend, FillOperation, FillPolicy, FillRequest,
    FillResult, FillStatus, parse_fill,
};
pub use grant::{
    ApprovalPrompt, Channel, Grant, GrantAction, GrantError, GrantPolicy, GrantRequest,
    GrantRequestArgs, GrantRequestBody, GrantScope, GrantStore, GrantTerms, GrantView,
    RequestState, parse_grant,
};
pub use meta::ItemMeta;
pub use notify::{ApprovalNotifier, NtfyApprovalNotifier};
pub use rate::{RateDenied, RateLimiter, RatePolicy};
pub use rollback::{RollbackGuard, RollbackReason};
pub use token::{ParamFloor, TokenStore};
