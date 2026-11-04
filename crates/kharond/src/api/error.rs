//! API errors (REQ-API-006).
//!
//! Every error a transport can return is an [`ApiError`]: an
//! [`ErrorCode`] and a [`Detail`], both closed enums whose wire
//! strings are `&'static str` literals. Nothing here takes a value at
//! construction time — no field, no request data, no `Secret` can
//! reach an error body, because there is no constructor that accepts
//! one. The REQ-API-006 source lint (`tests/req_api_006_errors.rs`)
//! keeps it that way: this file may not contain `format!`, `Secret`,
//! or a `String`-carrying variant.

use serde_json::{Value, json};

/// Machine-readable error class (`error` in the body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Missing or invalid agent token (HTTP 401).
    Unauthorized,
    /// The request came from a browser context (an `Origin` header on
    /// the MCP endpoint; HTTP 403).
    Forbidden,
    /// The broker is locked (HTTP 423). The `locked` of SPEC §4.
    Locked,
    /// The request is malformed (HTTP 400).
    BadRequest,
    /// No such route (HTTP 404).
    NotFound,
    /// Route exists, method does not (HTTP 405).
    MethodNotAllowed,
    /// The audit write failed; the request was refused (REQ-AUD-003,
    /// HTTP 500).
    AuditFailed,
}

impl ErrorCode {
    /// Wire string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::Locked => "locked",
            Self::BadRequest => "bad_request",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::AuditFailed => "audit_failed",
        }
    }

    /// HTTP status (the HTTP transport's mapping).
    pub const fn http_status(self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::Locked => 423,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::AuditFailed => 500,
        }
    }

    /// Every code (for the REQ-API-006 tests and the OpenAPI enum).
    pub const ALL: [Self; 7] = [
        Self::Unauthorized,
        Self::Forbidden,
        Self::Locked,
        Self::BadRequest,
        Self::NotFound,
        Self::MethodNotAllowed,
        Self::AuditFailed,
    ];
}

/// Human-readable detail (`detail` in the body). Fixed text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    /// No `Authorization: Bearer` header.
    MissingToken,
    /// The token did not verify (wrong, unknown agent, malformed — not
    /// distinguished).
    InvalidToken,
    /// Locked; the owner must unlock.
    Locked,
    /// A query parameter the route does not take.
    UnknownParameter,
    /// A query parameter given twice.
    DuplicateParameter,
    /// `origin` is not an absolute `http(s)` URL.
    InvalidOrigin,
    /// `origin` or `q` exceeds its length cap.
    ParameterTooLong,
    /// The query string is not valid UTF-8 form encoding.
    InvalidQueryEncoding,
    /// `q` is empty (use list).
    EmptyQuery,
    /// No such route.
    NoSuchRoute,
    /// Method not allowed on this route.
    MethodNotAllowed,
    /// The audit entry could not be written.
    AuditWriteFailed,
    /// A required parameter is absent (`q` on `kharon_search`).
    MissingParameter,
    /// A tool argument is neither a string nor `null` (MCP).
    InvalidParameterType,
    /// Tool `arguments` is not a JSON object (MCP).
    InvalidArguments,
    /// The MCP endpoint refuses requests carrying `Origin`.
    BrowserOriginRefused,
    /// The request body (MCP, `fill`) is not `application/json`.
    UnsupportedContentType,
    /// The request body (MCP, `fill`) exceeds its cap.
    BodyTooLarge,
    /// The request body is not valid JSON (`fill`, `fill_totp`).
    InvalidJsonBody,
    /// The fill request does not match `FillRequest` / `FillTotpRequest`
    /// (unknown, missing, duplicate or mistyped field).
    InvalidFillRequest,
    /// `item_id` is not a UUID.
    InvalidItemId,
    /// A fill request string exceeds its length cap.
    FieldTooLong,
    /// `fields` is empty.
    NoFillFields,
    /// `fields` names the same kind twice.
    DuplicateFillField,
    /// `target.frame_id` is set; address a frame by its own CDP target id.
    FrameIdUnsupported,
}

impl Detail {
    /// Wire string. Literals only (REQ-API-006).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingToken => "missing bearer token",
            Self::InvalidToken => "invalid agent token",
            Self::Locked => "broker is locked; owner unlock required",
            Self::UnknownParameter => "unknown query parameter",
            Self::DuplicateParameter => "duplicate query parameter",
            Self::InvalidOrigin => "origin must be an absolute http or https URL",
            Self::ParameterTooLong => "query parameter too long",
            Self::InvalidQueryEncoding => "query string is not valid form encoding",
            Self::EmptyQuery => "search query is empty",
            Self::NoSuchRoute => "no such route",
            Self::MethodNotAllowed => "method not allowed",
            Self::AuditWriteFailed => "audit write failed; request refused",
            Self::MissingParameter => "required parameter missing",
            Self::InvalidParameterType => "parameter value must be a string",
            Self::InvalidArguments => "tool arguments must be a JSON object",
            Self::BrowserOriginRefused => "browser origins are not accepted",
            Self::UnsupportedContentType => "content type must be application/json",
            Self::BodyTooLarge => "request body too large",
            Self::InvalidJsonBody => "request body is not valid JSON",
            Self::InvalidFillRequest => "fill request does not match the schema",
            Self::InvalidItemId => "item_id must be a UUID",
            Self::FieldTooLong => "request field too long",
            Self::NoFillFields => "fields must name at least one field",
            Self::DuplicateFillField => "fields names a kind twice",
            Self::FrameIdUnsupported => "frame_id is not supported; use the frame's cdp_target_id",
        }
    }

    /// Every detail (for the REQ-API-006 tests).
    pub const ALL: [Self; 25] = [
        Self::MissingToken,
        Self::InvalidToken,
        Self::Locked,
        Self::UnknownParameter,
        Self::DuplicateParameter,
        Self::InvalidOrigin,
        Self::ParameterTooLong,
        Self::InvalidQueryEncoding,
        Self::EmptyQuery,
        Self::NoSuchRoute,
        Self::MethodNotAllowed,
        Self::AuditWriteFailed,
        Self::MissingParameter,
        Self::InvalidParameterType,
        Self::InvalidArguments,
        Self::BrowserOriginRefused,
        Self::UnsupportedContentType,
        Self::BodyTooLarge,
        Self::InvalidJsonBody,
        Self::InvalidFillRequest,
        Self::InvalidItemId,
        Self::FieldTooLong,
        Self::NoFillFields,
        Self::DuplicateFillField,
        Self::FrameIdUnsupported,
    ];
}

/// An API error: code plus fixed detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}: {}", self.code.as_str(), self.detail.as_str())]
pub struct ApiError {
    /// Error class.
    pub code: ErrorCode,
    /// Fixed detail text.
    pub detail: Detail,
}

impl ApiError {
    /// Pair a code with a detail.
    pub const fn new(code: ErrorCode, detail: Detail) -> Self {
        Self { code, detail }
    }

    /// 401, no/garbled `Authorization` header.
    pub const MISSING_TOKEN: Self = Self::new(ErrorCode::Unauthorized, Detail::MissingToken);
    /// 401, token did not verify.
    pub const INVALID_TOKEN: Self = Self::new(ErrorCode::Unauthorized, Detail::InvalidToken);
    /// 423.
    pub const LOCKED: Self = Self::new(ErrorCode::Locked, Detail::Locked);
    /// 500, REQ-AUD-003 fail-closed.
    pub const AUDIT_FAILED: Self = Self::new(ErrorCode::AuditFailed, Detail::AuditWriteFailed);

    /// 400 with `detail`.
    pub const fn bad_request(detail: Detail) -> Self {
        Self::new(ErrorCode::BadRequest, detail)
    }

    /// The JSON body: `{"error": code, "detail": detail}`.
    pub fn body(&self) -> Value {
        json!({ "error": self.code.as_str(), "detail": self.detail.as_str() })
    }
}

/// REQ-AUD-003†: an engine-level outcome append failure
/// ([`crate::cdp::fill::DeadlineFiller`]'s `fill_timeout`) is the API's
/// `audit_failed`, the same reply `Broker::fill` gives (#46).
impl From<crate::cdp::AuditFailed> for ApiError {
    fn from(_: crate::cdp::AuditFailed) -> Self {
        Self::AUDIT_FAILED
    }
}
