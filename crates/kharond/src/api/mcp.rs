//! MCP transport: `POST /mcp` (REQ-API-001, REQ-API-002; SPEC §4).
//!
//! A stateless MCP server over the Streamable HTTP transport, served
//! on the agent API listener next to `/v1/*`. Like [`super::http`] it
//! is a thin adapter over [`super::core`]: a tool call is turned into
//! `(name, value)` pairs and handed to [`parse_request`] and
//! [`Broker::dispatch`](super::core::Broker::dispatch), so a request
//! means the same thing on both transports, and the tool result
//! carries exactly the body `/v1/*` would return (the contract test,
//! `tests/req_api_002_contract.rs`, checks this case by case).
//!
//! Tools (SPEC §4):
//!
//! | Tool | HTTP equivalent |
//! |---|---|
//! | `kharon_status` | `GET /v1/status` |
//! | `kharon_list` | `GET /v1/items[?origin=]` |
//! | `kharon_search` | `GET /v1/items?q=[&origin=]` |
//! | `kharon_fill` | `POST /v1/fill` |
//! | `kharon_fill_totp` | `POST /v1/fill_totp` |
//! | `kharon_context` | `POST /v1/context` (#65) |
//! | `kharon_request_grant` | `POST /v1/grants` (#20) |
//!
//! The read tools' arguments become `(name, value)` pairs for
//! [`parse_request`]; the fill tools' arguments object is exactly the
//! HTTP JSON body, handed to [`parse_fill`] and
//! [`Broker::fill`](super::core::Broker::fill); `kharon_context`'s
//! (none) go to [`parse_context_body`] and
//! [`Broker::context`](super::core::Broker::context). A fill that ran but did
//! not fill (`origin_mismatch`, `timeout`, …) is a `FillResult`, as on
//! HTTP, so `isError` is `false`; `isError: true` is reserved for the
//! `ApiError` bodies (bad arguments, locked, audit failure).
//!
//! Input schemas are generated from the Rust argument types below with
//! `schemars` (JSON Schema 2020-12); `docs/api/mcp-tools.json` is the
//! snapshot the REQ-API-001 test compares against.
//!
//! Protocol versions: `2026-07-28` (stateless: `server/discover`, the
//! `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` headers checked
//! against the body) and, for clients that predate it, `2025-11-25` and
//! `2025-06-18` (`initialize` handshake; no session id is issued, so
//! every request stands alone either way).
//!
//! Order per request: method (405, `Allow: POST`), `Origin` (403 — a
//! browser page must not drive the broker, MCP's DNS-rebinding rule
//! taken to its strict form), the per-IP transport window (429, #200:
//! charged before auth so bad tokens cost no Argon2id), bearer token
//! (401, the same Argon2id path and semaphore as `/v1/*`), the
//! per-agent transport window (429, #200), content type and size
//! (400; 413 past the caps), then JSON-RPC. Everything before JSON-RPC answers with the `/v1/*` error
//! body. JSON-RPC protocol errors use fixed messages ([`RpcError`]);
//! tool errors are results with `isError: true` whose text is the
//! [`ApiError`] body. No response here interpolates request data,
//! except the requested protocol version in an unsupported-version
//! error, which is echoed only when it has the `YYYY-MM-DD` shape
//! (REQ-API-006).

use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use base64ct::{Base64, Encoding};
use schemars::JsonSchema;
use schemars::generate::SchemaSettings;
use serde::Deserialize;
use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Map, Value, json};

use super::core::{
    AgentId, Broker, MAX_ORIGIN_LEN, MAX_QUERY_LEN, Operation, VaultView, parse_context_body,
    parse_request,
};
use super::error::{ApiError, Detail, ErrorCode};
use super::fill::{FillArgs, FillOperation, FillTotpArgs, parse_fill};
use super::grant::{GrantArgs, parse_grant};
use super::http::{AppState, authenticate_mcp, bearer_token, error, json_response};
use super::transport::ClientIp;
use crate::lock::Clock;
use tokio::time::Instant;

/// The MCP endpoint path.
pub const MCP_PATH: &str = "/mcp";
/// The newest protocol version, and the one `server/discover` leads with.
pub const LATEST_PROTOCOL_VERSION: &str = "2026-07-28";
/// Older versions served through the `initialize` handshake.
pub const LEGACY_PROTOCOL_VERSIONS: [&str; 2] = ["2025-11-25", "2025-06-18"];
/// Every supported version, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = [
    LATEST_PROTOCOL_VERSION,
    LEGACY_PROTOCOL_VERSIONS[0],
    LEGACY_PROTOCOL_VERSIONS[1],
];
/// Largest accepted request body (bytes).
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Deepest accepted JSON nesting in a request body (#200). An
/// explicit cap, well under `serde_json`'s implicit recursion limit,
/// so a hostile body cannot spend the parser's stack; excess is 413.
/// Counted by [`json_depth`], which scans the raw bytes *before* any
/// JSON parser runs.
pub const MAX_JSON_DEPTH: usize = 32;

/// The nesting depth of a JSON text: the maximum number of
/// simultaneously open `[` / `{`, ignoring brackets inside strings
/// (and their escapes). Malformed input simply yields the depth seen
/// so far; validity is the parser's call, not this scan's.
pub fn json_depth(body: &[u8]) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}
/// Server name in `serverInfo`.
pub const SERVER_NAME: &str = "kharond";

const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
/// How long a client may cache discovery and the tool list (ms). The
/// tool set changes only with the daemon binary.
const CACHE_TTL_MS: u64 = 3_600_000;
const INSTRUCTIONS: &str = "kharon credentials broker. No tool ever returns a secret: \
kharon_list and kharon_search return item metadata, and kharon_fill / kharon_fill_totp type the \
item's username, password or current TOTP code into a tab in your own browser context and \
report only which fields were filled. kharon_context returns your own browserContextId: open the \
tabs you want filled in it. The live page origin decides, never your claim. Every call is \
audited.";

// ---------------------------------------------------------------- tools

/// `kharon_status` arguments: none.
#[derive(Debug, Clone, Default, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct StatusArgs {}

/// `kharon_context` arguments: none (#65).
#[derive(Debug, Clone, Default, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ContextArgs {}

/// `kharon_list` arguments.
#[derive(Debug, Clone, Default, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ListArgs {
    /// Only items whose URIs match this origin under the item's match
    /// rule (absolute http or https URL). Omitted or null: every item.
    #[schemars(length(max = MAX_ORIGIN_LEN), extend("format" = "uri"))]
    pub origin: Option<String>,
}

/// `kharon_search` arguments.
#[derive(Debug, Clone, Default, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct SearchArgs {
    /// Case-insensitive substring of the item name or a URI host. Must
    /// not be blank.
    #[schemars(length(min = 1, max = MAX_QUERY_LEN))]
    pub q: String,
    /// Only items whose URIs match this origin under the item's match
    /// rule (absolute http or https URL). Omitted or null: no filter.
    #[schemars(length(max = MAX_ORIGIN_LEN), extend("format" = "uri"))]
    pub origin: Option<String>,
}

/// The tools this server exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `kharon_status`.
    Status,
    /// `kharon_list`.
    List,
    /// `kharon_search`.
    Search,
    /// `kharon_fill` (#18).
    Fill,
    /// `kharon_fill_totp` (#19).
    FillTotp,
    /// `kharon_context` (#65).
    Context,
    /// `kharon_request_grant` (#20).
    RequestGrant,
}

impl Tool {
    /// Every tool, in `tools/list` order.
    pub const ALL: [Self; 7] = [
        Self::Status,
        Self::List,
        Self::Search,
        Self::Fill,
        Self::FillTotp,
        Self::Context,
        Self::RequestGrant,
    ];

    /// Tool name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Status => "kharon_status",
            Self::List => "kharon_list",
            Self::Search => "kharon_search",
            Self::Fill => "kharon_fill",
            Self::FillTotp => "kharon_fill_totp",
            Self::Context => "kharon_context",
            Self::RequestGrant => "kharon_request_grant",
        }
    }

    /// The tool called `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }

    /// The read operation the tool runs ([`parse_request`]); `None`
    /// for the fill tools, `kharon_context` and
    /// `kharon_request_grant`.
    pub const fn operation(self) -> Option<Operation> {
        match self {
            Self::Status => Some(Operation::Status),
            Self::List => Some(Operation::List),
            Self::Search => Some(Operation::Search),
            Self::Fill | Self::FillTotp | Self::Context | Self::RequestGrant => None,
        }
    }

    /// The fill operation the tool runs ([`parse_fill`]); `None` for
    /// the read tools, `kharon_context` and `kharon_request_grant`.
    pub const fn fill_operation(self) -> Option<FillOperation> {
        match self {
            Self::Fill => Some(FillOperation::Fill),
            Self::FillTotp => Some(FillOperation::FillTotp),
            Self::Status | Self::List | Self::Search | Self::Context | Self::RequestGrant => None,
        }
    }

    /// Argument names the tool takes (its schema's `properties`).
    pub const fn parameters(self) -> &'static [&'static str] {
        match self {
            Self::Status | Self::Context => &[],
            Self::List => &["origin"],
            Self::Search => &["q", "origin"],
            Self::Fill | Self::FillTotp => &["item_id", "target", "fields", "submit", "grant_id"],
            Self::RequestGrant => &["item_id", "target", "action"],
        }
    }

    const fn title(self) -> &'static str {
        match self {
            Self::Status => "Broker status",
            Self::List => "List items",
            Self::Search => "Search items",
            Self::Fill => "Fill a login form",
            Self::FillTotp => "Fill a TOTP code",
            Self::Context => "Your browser context",
            Self::RequestGrant => "Request a grant",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Status => {
                "Whether the broker is locked, the calling agent's id, its active grants, and \
                 its cached browser_context_id (null until kharon_context or a fill opened one, \
                 and after a lock or browser restart; reading status never connects). \
                 Same body as GET /v1/status."
            }
            Self::List => {
                "Item metadata (never secrets), optionally filtered by origin. Audited. \
                 Same body as GET /v1/items."
            }
            Self::Search => {
                "Item metadata (never secrets) whose name or URI host contains q, optionally \
                 filtered by origin. Audited. Same body as GET /v1/items?q=."
            }
            Self::Fill => {
                "Type the item's username and/or password into the tab cdp_target_id in your \
                 own browser context; with submit: true, submit the form once every field \
                 filled. The secret never leaves the broker: the result is a status and the \
                 kinds filled. The live origin must match the item and expected_origin. \
                 Bounded by the fill deadline (10 s). Audited. Same body as POST /v1/fill."
            }
            Self::FillTotp => {
                "Type the item's current TOTP code into the tab cdp_target_id in your own \
                 browser context; the code is never returned. Refused while the broker clock \
                 is skewed. Audited. Same body as POST /v1/fill_totp."
            }
            Self::Context => {
                "Your own browser context id (browser_context_id, the CDP browserContextId): \
                 connects to your configured browser if needed and creates your context, or \
                 returns the one already open. Open the tabs you want filled in it \
                 (Target.createTarget with this browserContextId); tabs elsewhere are \
                 target_not_owned. The same id until the connection ends: after a browser \
                 restart or a broker lock you get a new one. Requires unlock. Bounded by the \
                 fill deadline (10 s). Audited. Same body as POST /v1/context."
            }
            Self::RequestGrant => {
                "Ask the owner for a grant to fill one item (action fill, or totp) in the \
                 tab cdp_target_id in your own browser context. The broker reads the tab's \
                 live origin itself: if it differs from expected_origin the request is \
                 origin_mismatch and no prompt is shown. Otherwise the request is pending \
                 until the owner approves or it times out after 120 s (denied). Calling \
                 again while one is pending returns the same request. A fill without a \
                 matching grant creates the same request implicitly. Requires unlock. \
                 Audited. Same body as POST /v1/grants."
            }
        }
    }

    /// The JSON Schema of the tool's arguments, generated from its Rust
    /// type (REQ-API-001).
    pub fn input_schema(self) -> Value {
        let generator = SchemaSettings::draft2020_12()
            .with(|s| s.meta_schema = None)
            .into_generator();
        let schema = match self {
            Self::Status => generator.into_root_schema_for::<StatusArgs>(),
            Self::List => generator.into_root_schema_for::<ListArgs>(),
            Self::Search => generator.into_root_schema_for::<SearchArgs>(),
            Self::Fill => generator.into_root_schema_for::<FillArgs>(),
            Self::FillTotp => generator.into_root_schema_for::<FillTotpArgs>(),
            Self::Context => generator.into_root_schema_for::<ContextArgs>(),
            Self::RequestGrant => generator.into_root_schema_for::<GrantArgs>(),
        };
        let mut v = schema.to_value();
        if let Some(o) = v.as_object_mut() {
            // MCP requires `type: object` at the root and wants the
            // properties spelled out even when there are none.
            o.entry("properties").or_insert_with(|| json!({}));
        }
        v
    }

    /// The tool's `tools/list` entry.
    pub fn definition(self) -> Value {
        json!({
            "name": self.name(),
            "title": self.title(),
            "description": self.description(),
            "inputSchema": self.input_schema(),
            "annotations": self.annotations(),
        })
    }

    /// MCP tool annotations. The fill tools write into a page outside
    /// the broker (open world, not idempotent: a submit is an action)
    /// but destroy nothing. `kharon_context` may create a browser
    /// context (open world, not read-only) but repeating it returns the
    /// same one (idempotent).
    fn annotations(self) -> Value {
        let reads = self.operation().is_some();
        json!({
            "readOnlyHint": reads,
            "destructiveHint": false,
            // `kharon_request_grant` is idempotent too: the broker
            // dedupes a pending request per (agent, item, action).
            "idempotentHint": reads || matches!(self, Self::Context | Self::RequestGrant),
            "openWorldHint": !reads,
        })
    }
}

/// The `tools` array of `tools/list` (snapshot: `docs/api/mcp-tools.json`).
pub fn tool_definitions() -> Value {
    Value::Array(Tool::ALL.into_iter().map(Tool::definition).collect())
}

/// Every tool name, in [`Tool::ALL`] order — the registry the other
/// layers validate against (per-agent allow-lists, #200).
pub const TOOL_NAMES: [&str; 7] = {
    let mut names = [""; 7];
    let mut i = 0;
    while i < Tool::ALL.len() {
        names[i] = Tool::ALL[i].name();
        i += 1;
    }
    names
};

// ------------------------------------------------------------- JSON-RPC

/// JSON-RPC errors this server sends. Messages are literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcError {
    /// Body is not JSON.
    Parse,
    /// Not a single JSON-RPC 2.0 request or notification.
    InvalidRequest,
    /// No such method.
    MethodNotFound,
    /// Malformed method parameters.
    InvalidParams,
    /// `tools/call` named a tool that does not exist.
    UnknownTool,
    /// A required MCP header is missing or disagrees with the body.
    HeaderMismatch,
    /// The requested protocol version is not supported.
    UnsupportedProtocolVersion,
}

impl RpcError {
    /// JSON-RPC error code.
    pub const fn code(self) -> i64 {
        match self {
            Self::Parse => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams | Self::UnknownTool => -32602,
            Self::HeaderMismatch => -32020,
            Self::UnsupportedProtocolVersion => -32022,
        }
    }

    /// Fixed message.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Parse => "Parse error",
            Self::InvalidRequest => "Invalid request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::UnknownTool => "Unknown tool",
            Self::HeaderMismatch => "Header mismatch",
            Self::UnsupportedProtocolVersion => "Unsupported protocol version",
        }
    }

    /// Every error (for the REQ-API-006 tests).
    pub const ALL: [Self; 7] = [
        Self::Parse,
        Self::InvalidRequest,
        Self::MethodNotFound,
        Self::InvalidParams,
        Self::UnknownTool,
        Self::HeaderMismatch,
        Self::UnsupportedProtocolVersion,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Era {
    /// 2026-07-28: stateless, headers mirror the body.
    Modern,
    /// 2025-11-25 / 2025-06-18: `initialize` handshake.
    Legacy,
}

enum Reply {
    /// Notification or client response: 202, no body.
    Accepted,
    Json(StatusCode, Value),
}

fn rpc_error(id: Option<&Value>, e: RpcError, status: StatusCode) -> Reply {
    rpc_error_data(id, e, status, None)
}

fn rpc_error_data(
    id: Option<&Value>,
    e: RpcError,
    status: StatusCode,
    data: Option<Value>,
) -> Reply {
    let mut err = json!({ "code": e.code(), "message": e.message() });
    if let Some(d) = data {
        err["data"] = d;
    }
    Reply::Json(
        status,
        json!({ "jsonrpc": "2.0", "id": id.cloned().unwrap_or(Value::Null), "error": err }),
    )
}

fn rpc_result(id: &Value, era: Era, mut result: Map<String, Value>) -> Reply {
    if era == Era::Modern {
        result.insert("resultType".into(), json!("complete"));
    }
    Reply::Json(
        StatusCode::OK,
        json!({ "jsonrpc": "2.0", "id": id, "result": result }),
    )
}

fn object(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => unreachable!("invariant: built with json!({{..}})"),
    }
}

/// `YYYY-MM-DD`, the only shape a protocol version can take; anything
/// else is not echoed back.
fn is_version_shaped(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

fn header_str<'h>(headers: &'h HeaderMap, name: &str) -> Result<Option<&'h str>, ()> {
    let mut all = headers.get_all(name).iter();
    match (all.next(), all.next()) {
        (None, _) => Ok(None),
        (Some(v), None) => v.to_str().map(Some).map_err(|_| ()),
        _ => Err(()),
    }
}

/// Decode `Mcp-Name`: plain, or `=?base64?<b64>?=` for names that are
/// not header-safe.
fn decode_name(raw: &str) -> Option<String> {
    let inner = raw
        .get(..9)
        .filter(|p| p.eq_ignore_ascii_case("=?base64?"))
        .and_then(|_| raw[9..].strip_suffix("?="));
    match inner {
        None => Some(raw.to_owned()),
        Some(b64) => String::from_utf8(Base64::decode_vec(b64).ok()?).ok(),
    }
}

/// Tool arguments as `(name, value)` pairs in document order, keeping
/// duplicates so they can be refused like a repeated query parameter.
struct ArgPairs(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for ArgPairs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ArgPairs;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<ArgPairs, A::Error> {
                let mut pairs = Vec::new();
                while let Some(kv) = m.next_entry::<String, Value>()? {
                    pairs.push(kv);
                }
                Ok(ArgPairs(pairs))
            }
        }
        d.deserialize_map(V)
    }
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(borrow, default)]
    params: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct CallParams<'a> {
    name: String,
    #[serde(borrow, default)]
    arguments: Option<&'a RawValue>,
}

/// Turn tool arguments into the pairs [`parse_request`] takes. `null`
/// on a known parameter means absent; a non-string value on a known
/// parameter is [`Detail::InvalidParameterType`]; an unknown parameter
/// is passed through (as `""`) so the core refuses it exactly as it
/// refuses an unknown query parameter.
fn argument_pairs(tool: Tool, raw: Option<&RawValue>) -> Result<Vec<(String, String)>, ApiError> {
    let Some(raw) = raw.filter(|r| r.get() != "null") else {
        return Ok(Vec::new());
    };
    if !raw.get().starts_with('{') {
        return Err(ApiError::bad_request(Detail::InvalidArguments));
    }
    let ArgPairs(args) = serde_json::from_str(raw.get())
        .map_err(|_| ApiError::bad_request(Detail::InvalidArguments))?;
    let mut pairs = Vec::with_capacity(args.len());
    for (k, v) in args {
        let known = tool.parameters().contains(&k.as_str());
        match v {
            Value::String(s) => pairs.push((k, s)),
            Value::Null if known => {}
            _ if known => return Err(ApiError::bad_request(Detail::InvalidParameterType)),
            _ => pairs.push((k, String::new())),
        }
    }
    Ok(pairs)
}

/// The fill tools' arguments as the JSON body [`parse_fill`] takes
/// (the HTTP body). Absent or `null` is `{}` (then refused as missing
/// fields); a non-object is [`Detail::InvalidArguments`], as for the
/// read tools.
fn fill_arguments(raw: Option<&RawValue>) -> Result<&[u8], ApiError> {
    match raw.map(RawValue::get) {
        None | Some("null") => Ok(b"{}"),
        Some(r) if r.starts_with('{') => Ok(r.as_bytes()),
        Some(_) => Err(ApiError::bad_request(Detail::InvalidArguments)),
    }
}

fn tool_result(id: &Value, era: Era, body: Value, is_error: bool) -> Reply {
    rpc_result(
        id,
        era,
        object(json!({
            "content": [{ "type": "text", "text": body.to_string() }],
            "isError": is_error,
        })),
    )
}

/// Handle one JSON-RPC message from an authenticated agent.
/// `received` starts a fill's REQ-API-009 deadline.
async fn rpc<S, C>(
    broker: &Broker<S, C>,
    agent: &AgentId,
    headers: &HeaderMap,
    body: &[u8],
    received: Instant,
    client_ip: Option<std::net::IpAddr>,
) -> Reply
where
    S: VaultView,
    C: Clock,
{
    const BAD: StatusCode = StatusCode::BAD_REQUEST;
    let Ok(msg) = serde_json::from_slice::<Value>(body) else {
        return rpc_error(None, RpcError::Parse, BAD);
    };
    let Some(obj) = msg.as_object() else {
        return rpc_error(None, RpcError::InvalidRequest, BAD);
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return rpc_error(None, RpcError::InvalidRequest, BAD);
    }
    let id = match obj.get("id") {
        None => None,
        Some(i @ (Value::String(_) | Value::Number(_))) => Some(i),
        Some(_) => return rpc_error(None, RpcError::InvalidRequest, BAD),
    };
    let method = match obj.get("method") {
        Some(Value::String(m)) => m.as_str(),
        // A response to a server request (this server sends none).
        None if obj.contains_key("result") || obj.contains_key("error") => {
            return Reply::Accepted;
        }
        _ => return rpc_error(id, RpcError::InvalidRequest, BAD),
    };

    let Ok(header_version) = header_str(headers, "mcp-protocol-version") else {
        return rpc_error(id, RpcError::HeaderMismatch, BAD);
    };
    let era = match header_version {
        Some(LATEST_PROTOCOL_VERSION) => Era::Modern,
        Some(v) if LEGACY_PROTOCOL_VERSIONS.contains(&v) => Era::Legacy,
        Some(v) if is_version_shaped(v) => {
            let data = json!({ "supported": SUPPORTED_PROTOCOL_VERSIONS, "requested": v });
            return rpc_error_data(id, RpcError::UnsupportedProtocolVersion, BAD, Some(data));
        }
        Some(_) => return rpc_error(id, RpcError::HeaderMismatch, BAD),
        // Pre-2026 clients send `initialize` before they know a version.
        None if method == "initialize" => Era::Legacy,
        None => return rpc_error(id, RpcError::HeaderMismatch, BAD),
    };

    let Ok(Envelope { params }) = serde_json::from_slice::<Envelope>(body) else {
        return rpc_error(id, RpcError::InvalidRequest, BAD);
    };
    let params_value = match obj.get("params") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(p @ Value::Object(_)) => p.clone(),
        Some(_) => return rpc_error(id, RpcError::InvalidParams, StatusCode::OK),
    };

    if era == Era::Modern {
        let Ok(Some(h_method)) = header_str(headers, "mcp-method") else {
            return rpc_error(id, RpcError::HeaderMismatch, BAD);
        };
        let meta_version = params_value
            .get("_meta")
            .and_then(|m| m.get(META_PROTOCOL_VERSION))
            .and_then(Value::as_str);
        if h_method != method || meta_version != Some(LATEST_PROTOCOL_VERSION) {
            return rpc_error(id, RpcError::HeaderMismatch, BAD);
        }
        if method == "tools/call" {
            let h_name = match header_str(headers, "mcp-name") {
                Ok(Some(n)) => decode_name(n),
                _ => None,
            };
            let b_name = params_value.get("name").and_then(Value::as_str);
            if h_name.is_none() || h_name.as_deref() != b_name {
                return rpc_error(id, RpcError::HeaderMismatch, BAD);
            }
        }
    }

    // Notifications (`notifications/initialized`, cancellations, …)
    // need nothing from a stateless server.
    let Some(id) = id else {
        return Reply::Accepted;
    };

    let not_found = match era {
        Era::Modern => StatusCode::NOT_FOUND,
        // Pre-2026 clients read HTTP 404 as "session expired".
        Era::Legacy => StatusCode::OK,
    };
    let server_info = json!({ "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") });
    match method {
        "initialize" if era == Era::Legacy => {
            let Some(requested) = params_value.get("protocolVersion").and_then(Value::as_str)
            else {
                return rpc_error(Some(id), RpcError::InvalidParams, StatusCode::OK);
            };
            let version = LEGACY_PROTOCOL_VERSIONS
                .into_iter()
                .find(|v| *v == requested)
                .unwrap_or(LEGACY_PROTOCOL_VERSIONS[0]);
            rpc_result(
                id,
                era,
                object(json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": server_info,
                    "instructions": INSTRUCTIONS,
                })),
            )
        }
        "server/discover" => rpc_result(
            id,
            era,
            object(json!({
                "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "capabilities": { "tools": {} },
                "instructions": INSTRUCTIONS,
                "ttlMs": CACHE_TTL_MS,
                "cacheScope": "public",
                "_meta": { META_SERVER_INFO: server_info },
            })),
        ),
        "ping" => rpc_result(id, era, Map::new()),
        "tools/list" => rpc_result(
            id,
            era,
            object(json!({
                // Scope-filtered (#200): an agent with an allow-list
                // sees only its tools. Unrestricted agents get the
                // full registry (the mcp-tools.json snapshot).
                "tools": Tool::ALL.into_iter()
                    .filter(|t| broker.tool_allowed(agent, t.name()))
                    .map(Tool::definition)
                    .collect::<Vec<_>>(),
                "ttlMs": CACHE_TTL_MS,
                "cacheScope": "public",
            })),
        ),
        "tools/call" => {
            let Some(Ok(call)) = params.map(|p| serde_json::from_str::<CallParams>(p.get())) else {
                return rpc_error(Some(id), RpcError::InvalidParams, StatusCode::OK);
            };
            let Some(tool) = Tool::from_name(&call.name) else {
                return rpc_error(Some(id), RpcError::UnknownTool, StatusCode::OK);
            };
            let outcome = match (tool.operation(), tool.fill_operation()) {
                (Some(op), _) => argument_pairs(tool, call.arguments)
                    .and_then(|pairs| {
                        parse_request(op, pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                    })
                    .and_then(|r| broker.dispatch_from(agent, r, client_ip)),
                (None, Some(op)) => {
                    match fill_arguments(call.arguments).and_then(|raw| parse_fill(op, raw)) {
                        Ok(r) => broker.fill_from(agent, r, received, client_ip).await,
                        Err(e) => Err(e),
                    }
                }
                (None, None) => match tool {
                    Tool::Context => {
                        match fill_arguments(call.arguments).and_then(parse_context_body) {
                            Ok(()) => broker.context_from(agent, received, client_ip).await,
                            Err(e) => Err(e),
                        }
                    }
                    Tool::RequestGrant => {
                        match fill_arguments(call.arguments).and_then(parse_grant) {
                            Ok(r) => {
                                broker
                                    .request_grant_from(agent, r, received, client_ip)
                                    .await
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => unreachable!("only context and request_grant have no operation"),
                },
            };
            match outcome {
                Ok(o) => tool_result(id, era, o.body(), false),
                Err(e) => tool_result(id, era, e.body(), true),
            }
        }
        _ => rpc_error(Some(id), RpcError::MethodNotFound, not_found),
    }
}

pub(super) fn is_json(headers: &HeaderMap) -> bool {
    match header_str(headers, header::CONTENT_TYPE.as_str()) {
        Ok(Some(v)) => v
            .split(';')
            .next()
            .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json")),
        _ => false,
    }
}

/// The `/mcp` handler (routed from [`super::http`]).
pub(super) async fn handle<S, C>(state: Arc<AppState<S, C>>, req: Request) -> Response
where
    S: VaultView + 'static,
    C: Clock + Send + 'static,
{
    let received = Instant::now();
    if req.method() != Method::POST {
        // Stateless server: no GET stream, no DELETE session.
        let mut resp = error(ApiError::new(
            ErrorCode::MethodNotAllowed,
            Detail::MethodNotAllowed,
        ));
        resp.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("POST"));
        return resp;
    }
    if req.headers().contains_key(header::ORIGIN) {
        return error(ApiError::new(
            ErrorCode::Forbidden,
            Detail::BrowserOriginRefused,
        ));
    }
    // Transport budgets (#200): the per-IP window is charged before
    // auth, so a bad-token flood is refused before it costs an
    // Argon2id evaluation; the per-agent window after. The client IP
    // is the admitting listener's call (see api::transport's
    // contract); a handler invoked without one skips the IP window.
    let client_ip = req.extensions().get::<ClientIp>().map(|c| c.0);
    if let Some(ip) = client_ip
        && !state.broker.transport_ip_admit(ip, received)
    {
        return error(ApiError::RATE_LIMITED);
    }
    let token = bearer_token(&req);
    let (parts, body) = req.into_parts();
    let agent = match authenticate_mcp(&state, token).await {
        Ok(a) => a,
        Err(e) => {
            let mut resp = error(e);
            // REQ-OAU-001: with `[oauth]` set, the 401 challenge
            // names the discovery document and the scope set. Only
            // `/mcp` changes; `/v1/*` keeps the bare challenge, and
            // without `[oauth]` nothing here changes either.
            if e.code == super::error::ErrorCode::Unauthorized
                && let Some(discovery) = state.broker.oauth_discovery()
                && let Ok(challenge) = HeaderValue::from_str(&discovery.challenge())
            {
                resp.headers_mut()
                    .insert(header::WWW_AUTHENTICATE, challenge);
            }
            return resp;
        }
    };
    if !state.broker.transport_agent_admit(&agent, received) {
        return error(ApiError::RATE_LIMITED);
    }
    if !is_json(&parts.headers) {
        return error(ApiError::bad_request(Detail::UnsupportedContentType));
    }
    let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return error(ApiError::BODY_TOO_LARGE);
    };
    if json_depth(&bytes) > MAX_JSON_DEPTH {
        return error(ApiError::JSON_TOO_DEEP);
    }
    match rpc(
        &state.broker,
        &agent,
        &parts.headers,
        &bytes,
        received,
        client_ip,
    )
    .await
    {
        Reply::Accepted => Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(axum::body::Body::empty())
            .expect("invariant: static response is valid"),
        Reply::Json(status, v) => json_response(status, v.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_shape() {
        assert!(is_version_shaped("2026-07-28"));
        assert!(!is_version_shaped("2026-07-2x"));
        assert!(!is_version_shaped("2026-07-288"));
        assert!(!is_version_shaped("hunter2hun"));
    }

    #[test]
    fn json_depth_counts_nesting_not_string_brackets() {
        assert_eq!(json_depth(b"{}"), 1);
        assert_eq!(json_depth(b"42"), 0);
        assert_eq!(json_depth(b"[[[{}]]]"), 4);
        assert_eq!(json_depth(br#"{"a":"[[[{"}"#), 1);
        assert_eq!(json_depth(br#"{"a":"\"[[["}"#), 1);
        assert_eq!(json_depth(b"[[[]"), 3, "malformed input still scans");
        let deep = "[".repeat(MAX_JSON_DEPTH + 1);
        assert_eq!(json_depth(deep.as_bytes()), MAX_JSON_DEPTH + 1);
    }

    #[test]
    fn mcp_name_decoding() {
        assert_eq!(decode_name("kharon_list").as_deref(), Some("kharon_list"));
        let b64 = Base64::encode_string(b"kharon_list");
        let wrapped = ["=?base64?", &b64, "?="].concat();
        assert_eq!(decode_name(&wrapped).as_deref(), Some("kharon_list"));
        assert_eq!(decode_name("=?base64?!!!?="), None);
    }

    #[test]
    fn every_schema_is_an_object_with_the_declared_parameters() {
        for t in Tool::ALL {
            let s = t.input_schema();
            assert_eq!(s["type"], "object", "{}", t.name());
            assert_eq!(s["additionalProperties"], false, "{}", t.name());
            let mut props: Vec<&str> = s["properties"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            props.sort_unstable();
            let mut declared = t.parameters().to_vec();
            declared.sort_unstable();
            assert_eq!(props, declared, "{}", t.name());
        }
    }
}
