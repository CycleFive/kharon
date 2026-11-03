//! REQ-API-006: error `detail` strings are built from an enum, never
//! interpolated with field values. AC: a lint/test asserts no
//! `format!` in `detail` constructors takes `Secret`; fuzz finds no
//! canary in details.

mod api_support;

use std::collections::BTreeSet;

use api_support::*;
use kharond::api::core::parse_items_query;
use kharond::api::mcp::RpcError;
use kharond::api::{ApiError, Detail, ErrorCode};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use serde_json::Value;

const API_SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/api");

/// Source with `//` comments removed (doc comments may mention the
/// forbidden words to explain why they are forbidden).
fn code_of(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn req_api_006_lint_error_details_are_not_interpolated() {
    // The detail/error constructors live in error.rs: no formatting
    // machinery, no secret types, and no owned strings at all, so no
    // variant can carry a value.
    let src = code_of(&format!("{API_SRC}/error.rs"));
    for forbidden in [
        "format!",
        "format_args!",
        "write!",
        "concat!",
        "Secret",
        "expose",
        "String",
        "to_string",
        "to_owned",
        "&'a str",
        "impl Into",
    ] {
        assert!(!src.contains(forbidden), "error.rs contains `{forbidden}`");
    }
    // Everywhere else in the API, an error is one of the enum's
    // constants or `ApiError::new/bad_request(Detail::…)`: never built
    // next to a `format!`, and no `format!` touches a `Secret`.
    for entry in std::fs::read_dir(API_SRC).unwrap() {
        let path = entry.unwrap().path();
        let src = code_of(path.to_str().unwrap());
        for (n, line) in src.lines().enumerate() {
            if line.contains("format!") {
                assert!(
                    !line.contains("ApiError") && !line.contains("Detail"),
                    "{}:{}: format! near an error constructor",
                    path.display(),
                    n + 1
                );
                assert!(
                    !line.contains("Secret") && !line.contains("expose"),
                    "{}:{}: format! takes a Secret",
                    path.display(),
                    n + 1
                );
            }
        }
    }
}

#[test]
fn req_api_006_lint_mcp_builds_no_strings_from_input() {
    // The MCP adapter renders JSON-RPC errors from `RpcError` literals
    // and tool errors from `ApiError`; it has no formatting at all.
    let src = code_of(&format!("{API_SRC}/mcp.rs"));
    for forbidden in ["format!", "format_args!", "write!", "Secret", "expose"] {
        assert!(!src.contains(forbidden), "mcp.rs contains `{forbidden}`");
    }
    for e in RpcError::ALL {
        assert!(e.message().is_ascii() && e.message().len() < 40);
    }
}

#[test]
fn req_api_006_details_are_fixed_literals() {
    let details: BTreeSet<&str> = Detail::ALL.iter().map(|d| d.as_str()).collect();
    assert_eq!(details.len(), Detail::ALL.len(), "details are distinct");
    for d in &details {
        assert!(d.is_ascii() && !d.is_empty() && d.len() < 80, "{d}");
        assert_no_canary(d);
    }
    let codes: BTreeSet<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(codes.len(), ErrorCode::ALL.len());
}

/// Every body an error can have.
fn all_error_bodies() -> Vec<Value> {
    let mut v = Vec::new();
    for c in ErrorCode::ALL {
        for d in Detail::ALL {
            v.push(ApiError::new(c, d).body());
        }
    }
    v
}

fn fuzz_value(rng: &mut StdRng, canaries: &[String]) -> String {
    let pool = [
        "",
        " ",
        "https://login.example.com",
        "https://app.example.com/login",
        "http://login.example.com",
        "javascript:alert(1)",
        "fixture",
        "login.example",
        "%ZZ",
        "\u{fffd}",
        "ü",
        "a&b=c",
        "https://user:pass@login.example.com",
    ];
    match rng.gen_range(0..4) {
        0 => canaries.choose(rng).unwrap().clone(),
        1 => pool.choose(rng).unwrap().to_string(),
        2 => {
            // Canary embedded in a URL or a long value.
            let c = canaries.choose(rng).unwrap();
            if rng.gen_bool(0.5) {
                format!("https://{c}.example.com/{c}")
            } else {
                c.repeat(rng.gen_range(1..300))
            }
        }
        _ => (0..rng.gen_range(0..40))
            .map(|_| rng.gen_range(0x20u8..0x7f) as char)
            .collect(),
    }
}

#[test]
fn req_api_006_fuzz_core_details_never_echo_input() {
    let canaries = canaries();
    let mut rng = StdRng::seed_from_u64(0x6b68_6172_6f6e);
    let bodies = all_error_bodies();
    let keys = ["q", "origin", "include_secret", "password", "Q", ""];
    for _ in 0..5000 {
        let n = rng.gen_range(0..4);
        let pairs: Vec<(String, String)> = (0..n)
            .map(|_| {
                let k = if rng.gen_bool(0.2) {
                    fuzz_value(&mut rng, &canaries)
                } else {
                    keys.choose(&mut rng).unwrap().to_string()
                };
                (k, fuzz_value(&mut rng, &canaries))
            })
            .collect();
        if let Err(e) = parse_items_query(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))) {
            // Membership in the fixed set is the strong form of "never
            // echoes input": every possible error body is enumerable.
            let body = e.body();
            assert!(bodies.contains(&body), "body not from the enum: {body}");
            assert_no_canary(&body.to_string());
        }
    }
}

#[tokio::test]
async fn req_api_006_fuzz_http_no_canary_in_any_response() {
    let canaries = canaries();
    let mut rng = StdRng::seed_from_u64(0x0006_0006);
    let bodies = all_error_bodies();
    for locked in [false, true] {
        let h = Harness::new(locked);
        let addr = serve_http(h.broker.clone()).await;
        for _ in 0..300 {
            let path = [
                "/v1/items",
                "/v1/status",
                "/v1/fill",
                "/v1/items/",
                "/v1/openapi.json",
            ]
            .choose(&mut rng)
            .unwrap();
            let method = ["GET", "GET", "GET", "POST", "DELETE"]
                .choose(&mut rng)
                .unwrap();
            let mut q = url::form_urlencoded::Serializer::new(String::new());
            for _ in 0..rng.gen_range(0..3) {
                let k = ["q", "origin", "x"].choose(&mut rng).unwrap();
                q.append_pair(k, &fuzz_value(&mut rng, &canaries));
            }
            let q = q.finish();
            let auth = match rng.gen_range(0..4) {
                0 => String::new(),
                1 => format!("Authorization: Bearer {}\r\n", h.alpha),
                2 => format!(
                    "Authorization: Bearer {}\r\n",
                    canaries.choose(&mut rng).unwrap()
                ),
                _ => format!(
                    "Authorization: Bearer kh_agent_alpha_{}\r\n",
                    fuzz_value(&mut rng, &canaries).replace(['\r', '\n'], "")
                ),
            };
            let head = format!(
                "{method} {path}?{q} HTTP/1.1\r\nHost: x\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let r = raw_request(addr, head.as_bytes()).await;
            assert_no_canary(&r.body);
            if r.status != 200 {
                assert!(
                    bodies.contains(&r.json()),
                    "{}: body not from the enum: {}",
                    r.status,
                    r.body
                );
            }
        }
    }
}

#[tokio::test]
async fn req_api_006_fuzz_mcp_no_canary_in_any_response() {
    let canaries = canaries();
    let mut rng = StdRng::seed_from_u64(0x006d_6370);
    let bodies = all_error_bodies();
    let messages: Vec<&str> = RpcError::ALL.iter().map(|e| e.message()).collect();
    let header_safe =
        |s: String| -> String { s.chars().filter(|c| (' '..='~').contains(c)).collect() };
    for locked in [false, true] {
        let h = Harness::new(locked);
        let addr = serve_http(h.broker.clone()).await;
        for _ in 0..300 {
            let tool = [
                "kharon_status",
                "kharon_list",
                "kharon_search",
                "kharon_fill",
            ]
            .choose(&mut rng)
            .unwrap()
            .to_string();
            let tool = if rng.gen_bool(0.1) {
                header_safe(fuzz_value(&mut rng, &canaries)).replace(['"', '\\'], "")
            } else {
                tool
            };
            let mut args = Vec::new();
            for _ in 0..rng.gen_range(0..3) {
                let k = if rng.gen_bool(0.2) {
                    fuzz_value(&mut rng, &canaries)
                } else {
                    ["q", "origin", "x"].choose(&mut rng).unwrap().to_string()
                };
                let v = match rng.gen_range(0..5) {
                    0 => serde_json::json!(null),
                    1 => serde_json::json!([fuzz_value(&mut rng, &canaries)]),
                    2 => serde_json::json!({ "v": fuzz_value(&mut rng, &canaries) }),
                    _ => serde_json::json!(fuzz_value(&mut rng, &canaries)),
                };
                args.push(format!("{}:{v}", serde_json::json!(k)));
            }
            let args = format!("{{{}}}", args.join(","));
            let r = if rng.gen_bool(0.8) {
                mcp_call(addr, Some(&h.alpha), &tool, &args).await
            } else {
                // Mangled headers: wrong name, canary version.
                let version = header_safe(fuzz_value(&mut rng, &canaries));
                let name = header_safe(fuzz_value(&mut rng, &canaries));
                let body = format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":{},"arguments":{args}}}}}"#,
                    serde_json::json!(tool)
                );
                post_mcp_raw(
                    addr,
                    Some(&h.alpha),
                    &[
                        ("Content-Type", "application/json"),
                        ("MCP-Protocol-Version", version.trim()),
                        ("Mcp-Method", "tools/call"),
                        ("Mcp-Name", name.trim()),
                    ],
                    &body,
                )
                .await
            };
            assert_no_canary(&r.body);
            let v = r.json();
            if let Some(err) = v.get("error").filter(|e| e.is_object()) {
                assert!(messages.contains(&err["message"].as_str().unwrap()), "{v}");
            } else if let Some(res) = v.get("result") {
                if res["isError"] == serde_json::json!(true) {
                    let inner: Value =
                        serde_json::from_str(res["content"][0]["text"].as_str().unwrap()).unwrap();
                    assert!(
                        bodies.contains(&inner),
                        "tool error not from the enum: {inner}"
                    );
                }
            } else {
                assert!(
                    bodies.contains(&v),
                    "{}: body not from the enum: {}",
                    r.status,
                    r.body
                );
            }
        }
    }
}
