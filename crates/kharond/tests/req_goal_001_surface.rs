//! REQ-GOAL-001 (#18), schema leg: "A schema test enumerates every MCP
//! tool and HTTP route response type. None contains a type marked
//! `Secret<…>`."
//!
//! The enumeration is `kharond::api::surface`: an exhaustive match over
//! [`Tool`] giving each tool's HTTP route and the schema generated from
//! the Rust type its success body serializes, plus the shared error
//! body. Its `Serialize` bound is the compile-time half (no `Secret` is
//! `Serialize`, REQ-API-005); this file is the run-time half:
//!
//! - the enumeration covers every served tool and every OpenAPI route,
//!   and nothing else;
//! - no schema node is named or titled like a secret type, and no
//!   property is named like a secret field;
//! - every free-form string a response can carry is on a reviewed
//!   allowlist, so a new string field fails here until someone has
//!   looked at what it can contain;
//! - the OpenAPI document's response components have exactly the
//!   generated types' property sets, so the published contract cannot
//!   drift from the types this test checked.
//!
//! The fuzzed canary leg is `tests/req_goal_001_canary_fuzz.rs`.

use std::collections::{BTreeMap, BTreeSet};

use kharond::api::http::OPENAPI_JSON;
use kharond::api::mcp::Tool;
use kharond::api::surface::{error_schema, http_route, response_schema};
use serde_json::Value;

const MCP_TOOLS_JSON: &str = include_str!("../../../docs/api/mcp-tools.json");

/// Property names that would mean a secret (or something derived from
/// one) is on the wire. Compared case-insensitively against every
/// property of every response schema, nested types included.
const SECRET_NAMES: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "totp",
    "totp_code",
    "code",
    "otp",
    "seed",
    "key",
    "token",
    "value",
    "username",
    "cipher",
    "plaintext",
    "master_password",
    "private_key",
    "session_key",
    "auth",
    "authorization",
    "cookie",
];

/// Every free-form string (or string-array item) a response can carry,
/// as `<schema title or $defs name>.<property>`, with what it holds.
/// Reviewed: none of these can hold vault plaintext or page data.
const REVIEWED_STRINGS: &[(&str, &str)] = &[
    ("StatusBody.agent_id", "the config's agent id"),
    (
        "StatusBody.browser_context_id",
        "a CDP id the broker created",
    ),
    ("ItemMeta.id", "item UUID"),
    ("ItemMeta.name", "item name (metadata, REQ-API-004)"),
    ("ItemMeta.username_hint", "masked username (OQ-4)"),
    ("ItemMeta.revision", "server revision date"),
    ("UriMeta.host", "URI host only (REQ-API-004)"),
    ("FillResult.status", "fixed FillStatus literal"),
    ("FillResult.fields_filled[]", "fixed field-kind literal"),
    ("FillResult.detail", "fixed detail-code literal"),
    (
        "FillResult.grant_request_id",
        "broker-assigned grant request id (#20)",
    ),
    ("GrantView.id", "broker-assigned grant id (#20)"),
    ("GrantView.agent_id", "the config's agent id"),
    ("GrantView.item_id", "item UUID"),
    ("GrantView.collection_id", "collection UUID"),
    (
        "GrantView.origin",
        "granted origin: a host or registrable domain, from item metadata",
    ),
    (
        "GrantView.expires_at",
        "RFC 3339 rendering of the grant's remaining TTL",
    ),
    (
        "GrantRequestBody.grant_request_id",
        "broker-assigned grant request id (#20)",
    ),
    ("GrantRequestBody.state", "fixed request-state literal"),
    ("ContextResult.status", "fixed literal"),
    (
        "ContextResult.browser_context_id",
        "a CDP id the broker created",
    ),
    ("ContextResult.detail", "fixed detail-code literal"),
    ("ErrorBody.error", "fixed ErrorCode literal"),
    ("ErrorBody.detail", "fixed Detail literal"),
];

fn openapi() -> Value {
    serde_json::from_str(OPENAPI_JSON).unwrap()
}

/// Every response schema the API can send: each tool's success body,
/// then the error body.
fn surface() -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = Tool::ALL
        .iter()
        .map(|t| {
            (
                t.name().to_owned(),
                serde_json::to_value(response_schema(*t)).unwrap(),
            )
        })
        .collect();
    out.push((
        "error".to_owned(),
        serde_json::to_value(error_schema()).unwrap(),
    ));
    out
}

#[test]
fn req_goal_001_surface_enumerates_every_tool_and_route() {
    // Every served tool (the published tools/list snapshot, which
    // req_api_001 pins to what `/mcp` serves) is in the enumeration.
    let served: BTreeSet<String> = serde_json::from_str::<Value>(MCP_TOOLS_JSON)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    let listed: BTreeSet<String> = Tool::ALL.iter().map(|t| t.name().to_owned()).collect();
    assert_eq!(served, listed, "tools/list vs api::surface");

    // Every OpenAPI operation that answers JSON (all but the document
    // itself) is some tool's route, with the same method.
    let doc = openapi();
    let mut documented = BTreeSet::new();
    for (path, ops) in doc["paths"].as_object().unwrap() {
        if path == "/v1/openapi.json" {
            continue;
        }
        for method in ops.as_object().unwrap().keys() {
            documented.insert((method.to_uppercase(), path.clone()));
        }
    }
    let routed: BTreeSet<(String, String)> = Tool::ALL
        .iter()
        .map(|t| {
            let (m, p) = http_route(*t);
            (m.to_owned(), p.to_owned())
        })
        .collect();
    assert_eq!(documented, routed, "OpenAPI operations vs api::surface");
}

/// Visit every schema node in `root` (its `$defs` included), with the
/// name of the nearest enclosing type.
fn walk<'a>(root: &'a Value, mut visit: impl FnMut(&str, &'a Value)) {
    fn go<'a>(owner: &str, v: &'a Value, visit: &mut dyn FnMut(&str, &'a Value)) {
        match v {
            Value::Object(m) => {
                visit(owner, v);
                for (k, child) in m {
                    if k == "$defs" {
                        for (name, def) in child.as_object().unwrap() {
                            go(name, def, visit);
                        }
                    } else {
                        go(owner, child, visit);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|c| go(owner, c, visit)),
            _ => {}
        }
    }
    let title = root["title"].as_str().unwrap_or("root").to_owned();
    go(&title, root, &mut visit);
}

fn is_string(schema: &Value) -> bool {
    match &schema["type"] {
        Value::String(t) => t == "string",
        Value::Array(ts) => ts.iter().any(|t| t == "string"),
        _ => false,
    }
}

#[test]
fn req_goal_001_no_response_schema_contains_a_secret_type_or_field() {
    let reviewed: BTreeMap<&str, &str> = REVIEWED_STRINGS.iter().copied().collect();
    let mut strings_seen = BTreeSet::new();
    let mut properties = 0;
    for (tool, schema) in surface() {
        let text = schema.to_string();
        assert!(!text.contains("Secret"), "{tool}: schema names Secret");
        if let Some(defs) = schema["$defs"].as_object() {
            for name in defs.keys() {
                assert!(
                    !name.to_lowercase().contains("secret"),
                    "{tool}: $defs {name}"
                );
            }
        }
        walk(&schema, |owner, node| {
            assert_ne!(node["writeOnly"], Value::Bool(true), "{tool}: writeOnly");
            assert_ne!(node["format"], "password", "{tool}: format password");
            if let Some(title) = node["title"].as_str() {
                assert!(!title.to_lowercase().contains("secret"), "{tool}: {title}");
            }
            let Some(props) = node["properties"].as_object() else {
                return;
            };
            for (name, prop) in props {
                properties += 1;
                let lower = name.to_lowercase();
                assert!(
                    !SECRET_NAMES.contains(&lower.as_str()),
                    "{tool}: {owner}.{name} is named like a secret"
                );
                let key = if is_string(prop) {
                    Some(format!("{owner}.{name}"))
                } else if prop["type"] == "array" && is_string(&prop["items"]) {
                    Some(format!("{owner}.{name}[]"))
                } else {
                    None
                };
                if let Some(key) = key {
                    assert!(
                        reviewed.contains_key(key.as_str()),
                        "{tool}: new response string {key}: review what it can carry \
                         and add it to REVIEWED_STRINGS"
                    );
                    strings_seen.insert(key);
                }
            }
        });
    }
    // The walk saw the whole surface (not a vacuous pass), and the
    // allowlist has no stale entries.
    assert!(properties >= 20, "walked only {properties} properties");
    let reviewed_keys: BTreeSet<String> = reviewed.keys().map(|k| (*k).to_owned()).collect();
    assert_eq!(strings_seen, reviewed_keys, "REVIEWED_STRINGS is stale");
}

/// Property names of the object schema `s`, following one `$ref` (into
/// `defs`, keyed by the ref's last segment) and one array level.
fn object_properties(s: &Value, defs: &Value) -> BTreeSet<String> {
    let s = match s["$ref"].as_str() {
        Some(r) => &defs[r.rsplit('/').next().unwrap()],
        None => s,
    };
    if s["type"] == "array" {
        return object_properties(&s["items"], defs);
    }
    s["properties"]
        .as_object()
        .unwrap_or_else(|| panic!("not an object schema: {s}"))
        .keys()
        .cloned()
        .collect()
}

#[test]
fn req_goal_001_openapi_responses_are_the_enumerated_types() {
    let doc = openapi();
    let components = &doc["components"]["schemas"];
    for tool in Tool::ALL {
        let (method, path) = http_route(tool);
        let op = &doc["paths"][path][method.to_lowercase()];
        let documented = object_properties(
            &op["responses"]["200"]["content"]["application/json"]["schema"],
            components,
        );
        let generated = serde_json::to_value(response_schema(tool)).unwrap();
        let types = object_properties(&generated, &generated["$defs"]);
        assert_eq!(documented, types, "{} 200 body vs {}", path, tool.name());

        // Every non-200 response is the shared error body.
        for (status, resp) in op["responses"].as_object().unwrap() {
            if status == "200" {
                continue;
            }
            let name = resp["$ref"].as_str().unwrap().rsplit('/').next().unwrap();
            let schema =
                &doc["components"]["responses"][name]["content"]["application/json"]["schema"];
            assert_eq!(
                schema["$ref"], "#/components/schemas/Error",
                "{path} {status}"
            );
        }
    }
    // Nested component types match too.
    let items = serde_json::to_value(response_schema(Tool::List)).unwrap();
    assert_eq!(
        object_properties(&components["UriMeta"], components),
        object_properties(&items["$defs"]["UriMeta"], &items["$defs"]),
        "UriMeta"
    );
    let error = serde_json::to_value(error_schema()).unwrap();
    assert_eq!(
        object_properties(&components["Error"], components),
        object_properties(&error, &Value::Null),
        "Error"
    );
}

#[test]
fn req_goal_001_error_body_is_the_enumerated_error_type() {
    // `ApiError::body()` is built from `ErrorBody`, so the schema above
    // is the error body on every transport.
    use kharond::api::{ApiError, Detail};
    let body = ApiError::bad_request(Detail::InvalidJsonBody).body();
    let keys: BTreeSet<String> = body.as_object().unwrap().keys().cloned().collect();
    let error = serde_json::to_value(error_schema()).unwrap();
    assert_eq!(keys, object_properties(&error, &Value::Null));
}
