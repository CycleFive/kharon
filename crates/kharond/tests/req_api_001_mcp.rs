//! REQ-API-001: MCP server (streamable HTTP) exposing the SPEC §4
//! tools with JSON Schemas generated from Rust types (`schemars`).
//! AC: `mcp-inspector` lists the tools; schemas match the snapshot
//! test. (Semantics are REQ-API-002's contract test, which runs every
//! case over MCP too.)
//!
//! Today six of the seven tools exist: `kharon_request_grant` arrives
//! with #20 and extends [`Tool::ALL`] and the snapshot.

mod api_support;

use api_support::*;
use base64ct::{Base64, Encoding};
use kharond::api::mcp::{
    LATEST_PROTOCOL_VERSION, MAX_BODY_BYTES, SUPPORTED_PROTOCOL_VERSIONS, Tool, tool_definitions,
};
use kharond::api::{ApiError, Detail, ErrorCode};
use serde_json::{Value, json};

const SNAPSHOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api/mcp-tools.json");

fn rpc_error_code(r: &RawResponse) -> i64 {
    r.json()["error"]["code"].as_i64().unwrap()
}

/// The tool result's text as JSON, and `isError`.
fn tool_body(r: &RawResponse) -> (Value, bool) {
    let v = r.json();
    let res = &v["result"];
    let text = res["content"][0]["text"].as_str().unwrap();
    (
        serde_json::from_str(text).unwrap(),
        res["isError"] == json!(true),
    )
}

#[test]
fn req_api_001_schemas_match_the_snapshot() {
    let generated = tool_definitions();
    if std::env::var_os("KHARON_UPDATE_SNAPSHOTS").is_some() {
        let text = serde_json::to_string_pretty(&generated).unwrap() + "\n";
        std::fs::write(SNAPSHOT, text).unwrap();
    }
    let snapshot: Value = serde_json::from_str(&std::fs::read_to_string(SNAPSHOT).unwrap())
        .expect("docs/api/mcp-tools.json (KHARON_UPDATE_SNAPSHOTS=1 regenerates it)");
    assert_eq!(
        generated, snapshot,
        "tool schemas changed; review and rerun with KHARON_UPDATE_SNAPSHOTS=1"
    );
}

#[test]
fn req_api_001_schema_properties_are_exactly_what_the_core_accepts() {
    // The schema (from the Rust type) and the validator (core) must not
    // drift: every declared property is accepted, anything else is an
    // unknown parameter, and the required set is what the core needs.
    use kharond::api::core::parse_request;
    for t in Tool::ALL {
        let Some(op) = t.operation() else {
            continue; // fill tools and kharon_context: next tests
        };
        let s = t.input_schema();
        assert_eq!(s["type"], "object");
        assert_eq!(s["additionalProperties"], json!(false));
        for p in t.parameters() {
            let v = if *p == "origin" {
                "https://login.example.com"
            } else {
                "x"
            };
            let mut pairs = vec![(*p, v)];
            if t == Tool::Search && *p != "q" {
                pairs.push(("q", "x"));
            }
            assert!(parse_request(op, pairs).is_ok(), "{} {p}", t.name());
        }
        let mut pairs = vec![("include_secret", "1")];
        if t == Tool::Search {
            pairs.push(("q", "x"));
        }
        assert_eq!(
            parse_request(op, pairs),
            Err(ApiError::bad_request(Detail::UnknownParameter)),
            "{}",
            t.name()
        );
        let required: Vec<&str> = s["required"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap()).collect())
            .unwrap_or_default();
        let expect: &[&str] = if t == Tool::Search { &["q"] } else { &[] };
        assert_eq!(required, expect, "{}", t.name());
    }
}

#[test]
fn req_api_001_context_schema_is_what_parse_context_body_accepts() {
    // `kharon_context` takes no arguments: the schema is an empty
    // closed object and the core accepts exactly an empty body or `{}`.
    use kharond::api::core::parse_context_body;
    let t = Tool::Context;
    assert_eq!(t.name(), "kharon_context");
    assert!(t.operation().is_none() && t.fill_operation().is_none());
    let s = t.input_schema();
    assert_eq!(s["type"], "object");
    assert_eq!(s["additionalProperties"], json!(false));
    assert_eq!(s["properties"], json!({}));
    assert!(s.get("required").is_none());
    let d = &t.definition()["annotations"];
    assert_eq!(d["readOnlyHint"], json!(false));
    assert_eq!(d["idempotentHint"], json!(true));
    assert_eq!(d["destructiveHint"], json!(false));
    assert_eq!(d["openWorldHint"], json!(true));
    for ok in [&b""[..], b"{}", b" { } "] {
        assert_eq!(parse_context_body(ok), Ok(()), "{ok:?}");
    }
    for (bad, detail) in [
        (&br#"{"agent_id":"beta"}"#[..], Detail::UnknownParameter),
        (b"[]", Detail::InvalidArguments),
        (b"null", Detail::InvalidArguments),
        (b"{", Detail::InvalidJsonBody),
    ] {
        assert_eq!(
            parse_context_body(bad),
            Err(ApiError::bad_request(detail)),
            "{bad:?}"
        );
    }
}

#[test]
fn req_api_001_fill_schemas_are_what_parse_fill_accepts() {
    // The fill tools' arguments are the HTTP JSON body: the schema's
    // properties are exactly the body's fields, a minimal body per the
    // schema's `required` parses, and an extra property is refused.
    use kharond::api::fill::parse_fill;
    for (t, required) in [
        (Tool::Fill, &["item_id", "target", "fields"][..]),
        (Tool::FillTotp, &["item_id", "target"][..]),
    ] {
        let op = t.fill_operation().unwrap();
        assert!(t.operation().is_none());
        let s = t.input_schema();
        assert_eq!(s["type"], "object");
        assert_eq!(s["additionalProperties"], json!(false));
        let got: Vec<&str> = s["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(got, required, "{}", t.name());
        let mut body = json!({
            "item_id": "5d38619a-0591-4d2d-ab79-3d34e7a88f66",
            "target": {"cdp_target_id": "T1", "expected_origin": "https://login.example.com"},
        });
        if t == Tool::Fill {
            body["fields"] = json!([{"kind": "password"}]);
        }
        assert!(
            parse_fill(op, body.to_string().as_bytes()).is_ok(),
            "{}",
            t.name()
        );
        body["submit"] = json!(true);
        body["grant_id"] = json!("g1");
        assert!(
            parse_fill(op, body.to_string().as_bytes()).is_ok(),
            "{}",
            t.name()
        );
        body["include_secret"] = json!(true);
        assert_eq!(
            parse_fill(op, body.to_string().as_bytes()).unwrap_err(),
            ApiError::bad_request(Detail::InvalidFillRequest),
            "{}",
            t.name()
        );
    }
}

#[tokio::test]
async fn req_api_001_tools_list_serves_the_generated_tools() {
    let h = Harness::new(true); // listing tools needs no unlock
    let addr = serve_http(h.broker.clone()).await;
    let r = mcp_request(addr, Some(&h.alpha), "tools/list", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let v = r.json();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 1);
    let res = &v["result"];
    assert_eq!(res["resultType"], "complete");
    assert_eq!(res["tools"], tool_definitions());
    let names: Vec<&str> = res["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "kharon_status",
            "kharon_list",
            "kharon_search",
            "kharon_fill",
            "kharon_fill_totp",
            "kharon_context"
        ]
    );
    assert!(res["ttlMs"].is_u64());
    assert_eq!(res["cacheScope"], "public");
}

#[tokio::test]
async fn req_api_001_server_discover() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let r = mcp_request(addr, Some(&h.alpha), "server/discover", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let res = &r.json()["result"];
    assert_eq!(res["resultType"], "complete");
    assert_eq!(res["supportedVersions"], json!(SUPPORTED_PROTOCOL_VERSIONS));
    assert_eq!(res["capabilities"], json!({ "tools": {} }));
    assert_eq!(
        res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "kharond"
    );
    assert!(res["instructions"].is_string());
    let r = mcp_request(addr, Some(&h.alpha), "ping", "{}").await;
    assert_eq!(r.json()["result"], json!({ "resultType": "complete" }));
}

#[tokio::test]
async fn req_api_001_legacy_initialize_handshake() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let json_ct = ("Content-Type", "application/json");
    // initialize carries no version header.
    let init = r#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;
    let r = post_mcp_raw(addr, Some(&h.alpha), &[json_ct], init).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!(v["id"], "a");
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(v["result"]["serverInfo"]["name"], "kharond");
    assert_eq!(v["result"]["capabilities"]["tools"]["listChanged"], false);
    assert!(v["result"].get("resultType").is_none());
    assert!(
        r.header("mcp-session-id").is_none(),
        "stateless: no session"
    );
    // An unknown requested version gets the newest legacy one.
    let init_new = init.replace("2025-06-18", "2024-11-05");
    let r = post_mcp_raw(addr, Some(&h.alpha), &[json_ct], &init_new).await;
    assert_eq!(r.json()["result"]["protocolVersion"], "2025-11-25");

    let legacy = [json_ct, ("MCP-Protocol-Version", "2025-11-25")];
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &legacy,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;
    assert_eq!(r.status, 202);
    assert!(r.body.is_empty());
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &legacy,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kharon_status"}}"#,
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let (body, is_error) = tool_body(&r);
    assert!(!is_error);
    assert_eq!(
        body,
        json!({"locked": false, "agent_id": "alpha", "grants": [], "browser_context_id": null})
    );
    // Legacy unknown method: JSON-RPC error on HTTP 200 (a pre-2026
    // client reads 404 as an expired session).
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &legacy,
        r#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#,
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(rpc_error_code(&r), -32601);
    // Without a version header only initialize is accepted.
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &[json_ct],
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#,
    )
    .await;
    assert_eq!(r.status, 400);
    assert_eq!(rpc_error_code(&r), -32020);
}

#[tokio::test]
async fn req_api_001_modern_headers_must_match_the_body() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let body = |method: &str, meta: &str, name: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"{method}","params":{{"name":"{name}","_meta":{{"io.modelcontextprotocol/protocolVersion":"{meta}"}}}}}}"#
        )
    };
    let v = LATEST_PROTOCOL_VERSION;
    let base = |m: &'static str| {
        vec![
            ("Content-Type", "application/json"),
            ("MCP-Protocol-Version", v),
            ("Mcp-Method", m),
        ]
    };
    // Missing Mcp-Method.
    let hs = vec![
        ("Content-Type", "application/json"),
        ("MCP-Protocol-Version", v),
    ];
    let r = post_mcp_raw(addr, Some(&h.alpha), &hs, &body("tools/list", v, "")).await;
    assert_eq!((r.status, rpc_error_code(&r)), (400, -32020));
    assert_eq!(r.json()["id"], 7);
    // Mcp-Method disagrees with the body.
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &base("ping"),
        &body("tools/list", v, ""),
    )
    .await;
    assert_eq!((r.status, rpc_error_code(&r)), (400, -32020));
    // _meta version disagrees with the header, or is missing.
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &base("tools/list"),
        &body("tools/list", "2025-11-25", ""),
    )
    .await;
    assert_eq!((r.status, rpc_error_code(&r)), (400, -32020));
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &base("tools/list"),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    )
    .await;
    assert_eq!((r.status, rpc_error_code(&r)), (400, -32020));
    // tools/call: Mcp-Name missing, wrong, plain and base64-encoded.
    let call = body("tools/call", v, "kharon_status");
    let r = post_mcp_raw(addr, Some(&h.alpha), &base("tools/call"), &call).await;
    assert_eq!((r.status, rpc_error_code(&r)), (400, -32020));
    let mut hs = base("tools/call");
    hs.push(("Mcp-Name", "kharon_list"));
    let r = post_mcp_raw(addr, Some(&h.alpha), &hs, &call).await;
    assert_eq!((r.status, rpc_error_code(&r)), (400, -32020));
    let mut hs = base("tools/call");
    hs.push(("Mcp-Name", "kharon_status"));
    let r = post_mcp_raw(addr, Some(&h.alpha), &hs, &call).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let encoded = ["=?base64?", &Base64::encode_string(b"kharon_status"), "?="].concat();
    let mut hs = base("tools/call");
    hs.push(("Mcp-Name", &encoded));
    let r = post_mcp_raw(addr, Some(&h.alpha), &hs, &call).await;
    assert_eq!(r.status, 200, "{}", r.body);
    // Unsupported, version-shaped: -32022 with the supported list.
    let hs = vec![
        ("Content-Type", "application/json"),
        ("MCP-Protocol-Version", "2024-11-05"),
        ("Mcp-Method", "tools/list"),
    ];
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &hs,
        &body("tools/list", "2024-11-05", ""),
    )
    .await;
    assert_eq!((r.status, rpc_error_code(&r)), (400, -32022));
    assert_eq!(
        r.json()["error"]["data"],
        json!({ "supported": SUPPORTED_PROTOCOL_VERSIONS, "requested": "2024-11-05" })
    );
    // Not version-shaped: not echoed (REQ-API-006), header mismatch.
    let hs = vec![
        ("Content-Type", "application/json"),
        ("MCP-Protocol-Version", "not-a-version"),
        ("Mcp-Method", "tools/list"),
    ];
    let r = post_mcp_raw(addr, Some(&h.alpha), &hs, &body("tools/list", v, "")).await;
    assert_eq!((r.status, rpc_error_code(&r)), (400, -32020));
    assert!(!r.body.contains("not-a-version"));
}

#[tokio::test]
async fn req_api_001_json_rpc_errors() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let ct = [
        ("Content-Type", "application/json"),
        ("MCP-Protocol-Version", LATEST_PROTOCOL_VERSION),
    ];
    for (body, code) in [
        ("{", -32700),
        ("[]", -32600),
        (r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#, -32600),
        (r#"{"id":1,"method":"ping"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#, -32600),
        (r#"{"jsonrpc":"2.0","id":1,"method":5}"#, -32600),
    ] {
        let r = post_mcp_raw(addr, Some(&h.alpha), &ct, body).await;
        assert_eq!((r.status, rpc_error_code(&r)), (400, code), "{body}");
    }
    // Unknown method: 404 on 2026-07-28.
    let r = mcp_request(addr, Some(&h.alpha), "resources/list", "{}").await;
    assert_eq!((r.status, rpc_error_code(&r)), (404, -32601));
    // initialize does not exist in 2026-07-28.
    let r = mcp_request(
        addr,
        Some(&h.alpha),
        "initialize",
        r#"{"protocolVersion":"2026-07-28"}"#,
    )
    .await;
    assert_eq!((r.status, rpc_error_code(&r)), (404, -32601));
    // Unknown tool: protocol error, not a tool result.
    let r = mcp_call(addr, Some(&h.alpha), "kharon_export", "{}").await;
    assert_eq!((r.status, rpc_error_code(&r)), (200, -32602));
    let r = mcp_call(addr, Some(&h.alpha), "kharon_request_grant", "{}").await;
    assert_eq!(rpc_error_code(&r), -32602, "request_grant is #20");
    // Notifications are accepted with no body.
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &[
            ("Content-Type", "application/json"),
            ("MCP-Protocol-Version", LATEST_PROTOCOL_VERSION),
            ("Mcp-Method", "notifications/cancelled"),
        ],
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
    )
    .await;
    assert_eq!(r.status, 202);
}

#[tokio::test]
async fn req_api_001_tool_argument_errors_are_tool_results() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let bad = |d| ApiError::bad_request(d).body();
    for (tool, args, expect) in [
        ("kharon_list", r#"{"q":"x"}"#, bad(Detail::UnknownParameter)),
        (
            "kharon_list",
            r#"{"q":"   "}"#,
            bad(Detail::UnknownParameter),
        ),
        ("kharon_search", "{}", bad(Detail::MissingParameter)),
        (
            "kharon_search",
            r#"{"q":null}"#,
            bad(Detail::MissingParameter),
        ),
        (
            "kharon_search",
            r#"{"q":5}"#,
            bad(Detail::InvalidParameterType),
        ),
        (
            "kharon_search",
            r#"{"q":"x","q":"y"}"#,
            bad(Detail::DuplicateParameter),
        ),
        (
            "kharon_list",
            r#"{"origin":["https://a.test"]}"#,
            bad(Detail::InvalidParameterType),
        ),
        (
            "kharon_list",
            r#"{"include_secret":true}"#,
            bad(Detail::UnknownParameter),
        ),
        (
            "kharon_list",
            r#"{"include_secret":null}"#,
            bad(Detail::UnknownParameter),
        ),
        (
            "kharon_list",
            r#"["https://a.test"]"#,
            bad(Detail::InvalidArguments),
        ),
        (
            "kharon_list",
            r#""https://a.test""#,
            bad(Detail::InvalidArguments),
        ),
        ("kharon_status", r#"{"x":1}"#, bad(Detail::UnknownParameter)),
    ] {
        let r = mcp_call(addr, Some(&h.alpha), tool, args).await;
        assert_eq!(r.status, 200, "{tool} {args}: {}", r.body);
        let (body, is_error) = tool_body(&r);
        assert!(is_error, "{tool} {args}");
        assert_eq!(body, expect, "{tool} {args}");
    }
    // null origin and absent/null arguments mean "no filter".
    for (tool, args) in [
        ("kharon_list", r#"{"origin":null}"#),
        ("kharon_list", "null"),
        ("kharon_list", "{}"),
    ] {
        let (body, is_error) = tool_body(&mcp_call(addr, Some(&h.alpha), tool, args).await);
        assert!(!is_error, "{args}");
        assert_eq!(body.as_array().unwrap().len(), 6, "{args}");
    }
    assert!(h.audit.summary().len() >= 3);
}

#[tokio::test]
async fn req_api_001_transport_gate() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    // Stateless: no GET stream, no DELETE.
    for m in ["GET", "DELETE", "PUT"] {
        let head = format!(
            "{m} /mcp HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            h.alpha
        );
        let r = raw_request(addr, head.as_bytes()).await;
        assert_eq!(r.status, 405, "{m}");
        assert_eq!(r.header("allow"), Some("POST"), "{m}");
        assert_eq!(
            r.json(),
            ApiError::new(ErrorCode::MethodNotAllowed, Detail::MethodNotAllowed).body()
        );
    }
    // Any Origin is refused, before authentication.
    for origin in ["https://evil.test", "null", "http://127.0.0.1"] {
        let r = post_mcp_raw(
            addr,
            None,
            &[("Origin", origin), ("Content-Type", "application/json")],
            "{}",
        )
        .await;
        assert_eq!(r.status, 403, "{origin}");
        assert_eq!(
            r.json(),
            ApiError::new(ErrorCode::Forbidden, Detail::BrowserOriginRefused).body()
        );
    }
    // REQ-API-003: same 401s as /v1, before anything is parsed.
    let r = mcp_request(addr, None, "tools/list", "{}").await;
    assert_eq!(r.status, 401);
    assert!(r.header("www-authenticate").unwrap().starts_with("Bearer"));
    assert_eq!(r.json(), ApiError::MISSING_TOKEN.body());
    let r = post_mcp_raw(addr, Some("kh_agent_alpha_nope"), &[], "not json").await;
    assert_eq!(r.status, 401);
    assert_eq!(r.json(), ApiError::INVALID_TOKEN.body());
    // Content type and size.
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &[("Content-Type", "text/plain")],
        "{}",
    )
    .await;
    assert_eq!(
        r.json(),
        ApiError::bad_request(Detail::UnsupportedContentType).body()
    );
    let r = post_mcp_raw(addr, Some(&h.alpha), &[], "{}").await;
    assert_eq!(r.status, 400);
    assert_eq!(
        r.json(),
        ApiError::bad_request(Detail::UnsupportedContentType).body()
    );
    let big = " ".repeat(MAX_BODY_BYTES + 1);
    let r = post_mcp_raw(
        addr,
        Some(&h.alpha),
        &[("Content-Type", "application/json; charset=utf-8")],
        &big,
    )
    .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.json(), ApiError::bad_request(Detail::BodyTooLarge).body());
}
