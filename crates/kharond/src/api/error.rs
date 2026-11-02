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
            Self::Locked => 423,
            Self::BadRequest => 400,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::AuditFailed => 500,
        }
    }

    /// Every code (for the REQ-API-006 tests and the OpenAPI enum).
    pub const ALL: [Self; 6] = [
        Self::Unauthorized,
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
        }
    }

    /// Every detail (for the REQ-API-006 tests).
    pub const ALL: [Self; 12] = [
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
