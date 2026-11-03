//! REQ-API-002: the HTTP API has the same semantics as every other
//! transport, and has an OpenAPI document.
//!
//! The contract harness runs every case against each transport and
//! requires identical results (outcome, body, and audit trail). The
//! transports are the transport-independent core (`kharond::api::core`,
//! which every adapter must be a thin shim over), HTTP (`/v1/*`) and
//! MCP (`POST /mcp`, REQ-API-001). On MCP a case maps to
//! `kharon_status`, or `kharon_search` when it has a `q`, else
//! `kharon_list`; its parameters become the tool arguments (duplicates
//! kept), and the tool result's text must equal the HTTP body.

mod api_support;

use std::collections::BTreeSet;

use api_support::*;
use kharond::api::core::{Operation, parse_request};
use kharond::api::http::OPENAPI_JSON;
use kharond::api::{ApiError, Detail, ErrorCode};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug)]
enum Tool {
    Status,
    Items,
}

#[derive(Clone, Copy, Debug)]
enum Transport {
    Core,
    Http,
    Mcp,
}

const TRANSPORTS: [Transport; 3] = [Transport::Core, Transport::Http, Transport::Mcp];

#[derive(Clone, Copy, Debug)]
enum Who {
    Alpha,
    Beta,
    NoToken,
    Garbage,
    /// Alpha's random part under beta's id.
    Swapped,
}

struct Case {
    name: &'static str,
    locked: bool,
    idle_out: bool,
    who: Who,
    tool: Tool,
    params: &'static [(&'static str, &'static str)],
}

/// `("ok" | error code, body)`.
type Outcome = (String, Value);

fn token(h: &Harness, who: Who) -> Option<String> {
    match who {
        Who::Alpha => Some(h.alpha.clone()),
        Who::Beta => Some(h.beta.clone()),
        Who::NoToken => None,
        Who::Garbage => Some("kh_agent_alpha_not-a-token".into()),
        Who::Swapped => Some(format!(
            "kh_agent_beta_{}",
            h.alpha.rsplit_once('_').unwrap().1
        )),
    }
}

fn err(e: ApiError) -> Outcome {
    (e.code.as_str().to_owned(), e.body())
}

async fn call(t: Transport, h: &Harness, case: &Case) -> Outcome {
    let tok = token(h, case.who);
    match t {
        Transport::Core => {
            let Some(tok) = tok else {
                return err(ApiError::MISSING_TOKEN);
            };
            let agent = match h.broker.authenticate(&tok) {
                Ok(a) => a,
                Err(e) => return err(e),
            };
            // The same validation entry point the HTTP adapter uses.
            let op = match case.tool {
                Tool::Status => Operation::Status,
                Tool::Items => Operation::Items,
            };
            let req = parse_request(op, case.params.iter().copied());
            match req.and_then(|r| h.broker.dispatch(&agent, r)) {
                Ok(o) => ("ok".into(), o.body()),
                Err(e) => err(e),
            }
        }
        Transport::Http => {
            let addr = serve_http(h.broker.clone()).await;
            let path = match case.tool {
                Tool::Status => "/v1/status",
                Tool::Items => "/v1/items",
            };
            let mut target = path.to_owned();
            if !case.params.is_empty() {
                let q = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(case.params.iter())
                    .finish();
                target = format!("{path}?{q}");
            }
            let r = get(addr, &target, tok.as_deref()).await;
            let body = r.json();
            if r.status == 200 {
                ("ok".into(), body)
            } else {
                let code = body["error"].as_str().unwrap().to_owned();
                let ec = ErrorCode::ALL
                    .into_iter()
                    .find(|c| c.as_str() == code)
                    .unwrap();
                assert_eq!(r.status, ec.http_status(), "{}", case.name);
                (code, body)
            }
        }
        Transport::Mcp => {
            let addr = serve_http(h.broker.clone()).await;
            let tool = match case.tool {
                Tool::Status => "kharon_status",
                Tool::Items if case.params.iter().any(|(k, _)| *k == "q") => "kharon_search",
                Tool::Items => "kharon_list",
            };
            let r = mcp_call(addr, tok.as_deref(), tool, &json_object(case.params)).await;
            let body = r.json();
            if r.status == 401 {
                // Authentication is the transport's, before JSON-RPC:
                // same status and body as HTTP.
                return (body["error"].as_str().unwrap().to_owned(), body);
            }
            assert_eq!(r.status, 200, "{}: {body}", case.name);
            let result = &body["result"];
            assert_eq!(result["resultType"], "complete", "{}", case.name);
            let content = result["content"].as_array().unwrap();
            assert_eq!(content.len(), 1, "{}", case.name);
            assert_eq!(content[0]["type"], "text", "{}", case.name);
            let inner: Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
            if result["isError"] == json!(true) {
                (inner["error"].as_str().unwrap().to_owned(), inner)
            } else {
                assert_eq!(result["isError"], json!(false), "{}", case.name);
                ("ok".into(), inner)
            }
        }
    }
}

const CASES: &[Case] = &[
    Case {
        name: "status unlocked",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Status,
        params: &[],
    },
    Case {
        name: "status locked",
        locked: true,
        idle_out: false,
        who: Who::Beta,
        tool: Tool::Status,
        params: &[],
    },
    Case {
        name: "status after idle timeout",
        locked: false,
        idle_out: true,
        who: Who::Alpha,
        tool: Tool::Status,
        params: &[],
    },
    Case {
        name: "status with params",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Status,
        params: &[("x", "1")],
    },
    Case {
        name: "status no token",
        locked: false,
        idle_out: false,
        who: Who::NoToken,
        tool: Tool::Status,
        params: &[],
    },
    Case {
        name: "list no token",
        locked: false,
        idle_out: false,
        who: Who::NoToken,
        tool: Tool::Items,
        params: &[],
    },
    Case {
        name: "list garbage token",
        locked: false,
        idle_out: false,
        who: Who::Garbage,
        tool: Tool::Items,
        params: &[],
    },
    Case {
        name: "list swapped token",
        locked: false,
        idle_out: false,
        who: Who::Swapped,
        tool: Tool::Items,
        params: &[],
    },
    Case {
        name: "list all",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[],
    },
    Case {
        name: "list locked",
        locked: true,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[],
    },
    Case {
        name: "list after idle timeout",
        locked: false,
        idle_out: true,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[],
    },
    Case {
        name: "list origin login",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("origin", "https://login.example.com")],
    },
    Case {
        name: "list origin app page",
        locked: false,
        idle_out: false,
        who: Who::Beta,
        tool: Tool::Items,
        params: &[("origin", "https://app.example.com/login")],
    },
    Case {
        name: "list origin other site",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("origin", "https://example.org")],
    },
    Case {
        name: "list origin http",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("origin", "http://login.example.com")],
    },
    Case {
        name: "list origin lookalike",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("origin", "https://login.example.com.evil.test")],
    },
    Case {
        name: "list origin invalid",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("origin", "login.example.com")],
    },
    Case {
        name: "list origin javascript",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("origin", "javascript:alert(1)")],
    },
    Case {
        name: "list unknown param",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("include_secret", "true")],
    },
    Case {
        name: "list duplicate origin",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("origin", "https://a.test"), ("origin", "https://b.test")],
    },
    Case {
        name: "search name",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("q", "With-Cipher")],
    },
    Case {
        name: "search host",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("q", "login.example")],
    },
    Case {
        name: "search host + origin",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[
            ("q", "login.example"),
            ("origin", "https://login.example.com"),
        ],
    },
    Case {
        name: "search username not searched",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("q", "fixture-user")],
    },
    Case {
        name: "search password not searched",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("q", "fixture-password")],
    },
    Case {
        name: "search blank",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[("q", "  ")],
    },
    Case {
        name: "search locked",
        locked: true,
        idle_out: false,
        who: Who::Beta,
        tool: Tool::Items,
        params: &[("q", "fixture")],
    },
];

fn ids(body: &Value) -> BTreeSet<String> {
    body.as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_owned())
        .collect()
}

/// Spot checks of the semantics themselves (the harness proves the
/// transports agree; this proves what they agree on is right).
fn check_expected(case: &Case, (code, body): &Outcome) {
    let n = |k: usize| {
        assert_eq!(code, "ok", "{}: {body}", case.name);
        assert_eq!(body.as_array().unwrap().len(), k, "{}: {body}", case.name);
    };
    match case.name {
        "status unlocked" => assert_eq!(
            body,
            &json!({"locked": false, "agent_id": "alpha", "grants": []})
        ),
        "status locked" => assert_eq!(
            body,
            &json!({"locked": true, "agent_id": "beta", "grants": []})
        ),
        "status after idle timeout" => assert_eq!(body["locked"], json!(true)),
        "status with params" | "list unknown param" => {
            assert_eq!(
                body,
                &ApiError::bad_request(Detail::UnknownParameter).body()
            )
        }
        "status no token" | "list no token" => assert_eq!(body, &ApiError::MISSING_TOKEN.body()),
        "list garbage token" | "list swapped token" => {
            assert_eq!(body, &ApiError::INVALID_TOKEN.body())
        }
        "list locked" | "list after idle timeout" | "search locked" => {
            assert_eq!(body, &ApiError::LOCKED.body())
        }
        "list all" => n(6),
        "list origin login" => {
            // Two domain-match items (example.com) and the host clone;
            // not the exact clone (other URL), regex, or never.
            n(3);
            assert!(ids(body).contains(HOST_CLONE));
            assert!(!ids(body).contains(EXACT_CLONE));
        }
        "list origin app page" => {
            n(3);
            assert!(ids(body).contains(EXACT_CLONE));
            assert!(!ids(body).contains(HOST_CLONE));
        }
        "list origin other site" | "list origin http" | "list origin lookalike" => n(0),
        "list origin invalid" | "list origin javascript" => {
            assert_eq!(body, &ApiError::bad_request(Detail::InvalidOrigin).body())
        }
        "list duplicate origin" => {
            assert_eq!(
                body,
                &ApiError::bad_request(Detail::DuplicateParameter).body()
            )
        }
        "search name" => n(3), // item B and its exact and never clones
        "search host" => n(3),
        "search host + origin" => {
            n(2);
            assert!(!ids(body).contains(REGEX_CLONE));
        }
        "search username not searched" | "search password not searched" => n(0),
        "search blank" => assert_eq!(body, &ApiError::bad_request(Detail::EmptyQuery).body()),
        other => panic!("no expectation for case {other}"),
    }
}

#[tokio::test]
async fn req_api_002_contract_every_case_identical_on_every_transport() {
    for case in CASES {
        let mut results = Vec::new();
        for t in TRANSPORTS {
            let h = Harness::new(case.locked);
            if case.idle_out {
                h.idle_out();
            }
            let out = call(t, &h, case).await;
            assert_no_canary(&out.1.to_string());
            results.push((t, out, h.audit.summary()));
        }
        let (_, first, first_audit) = &results[0];
        check_expected(case, first);
        for (t, out, audit) in &results[1..] {
            assert_eq!(
                out, first,
                "{}: {t:?} disagrees with {:?}",
                case.name, results[0].0
            );
            assert_eq!(
                audit, first_audit,
                "{}: {t:?} audit trail differs",
                case.name
            );
        }
    }
}

#[tokio::test]
async fn req_api_002_list_and_search_are_audited_before_the_reply() {
    for t in TRANSPORTS {
        let h = Harness::new(false);
        let list = Case {
            name: "list",
            locked: false,
            idle_out: false,
            who: Who::Alpha,
            tool: Tool::Items,
            params: &[("origin", "https://login.example.com")],
        };
        let search = Case {
            name: "search",
            locked: false,
            idle_out: false,
            who: Who::Beta,
            tool: Tool::Items,
            params: &[("q", "fixture")],
        };
        let status = Case {
            name: "status",
            locked: false,
            idle_out: false,
            who: Who::Alpha,
            tool: Tool::Status,
            params: &[],
        };
        let bad = Case {
            name: "bad",
            locked: false,
            idle_out: false,
            who: Who::Garbage,
            tool: Tool::Items,
            params: &[],
        };
        for c in [&list, &search, &status, &bad] {
            call(t, &h, c).await;
        }
        assert_eq!(
            h.audit.summary(),
            vec![
                json!(["list", "alpha", "https://login.example.com", "ok"]),
                json!(["search", "beta", null, "ok"]),
            ],
            "{t:?}"
        );
        // REQ-AUD-003: audit write fails → request fails closed, no items.
        *h.audit.fail.lock().unwrap() = true;
        let (code, body) = call(t, &h, &list).await;
        assert_eq!(code, "audit_failed", "{t:?}");
        assert_eq!(body, ApiError::AUDIT_FAILED.body());
        // Status is not a §7 event and needs no audit write.
        assert_eq!(call(t, &h, &status).await.0, "ok");
    }
}

#[tokio::test]
async fn req_api_002_list_does_not_extend_the_idle_timer() {
    // Listing is not fill activity: polling list/status must not keep
    // the vault unlocked past the idle timeout (REQ-MEM-004).
    let h = Harness::new(false);
    let list = Case {
        name: "list",
        locked: false,
        idle_out: false,
        who: Who::Alpha,
        tool: Tool::Items,
        params: &[],
    };
    for _ in 0..4 {
        h.clock.advance(std::time::Duration::from_secs(10 * 60));
        let _ = call(Transport::Core, &h, &list).await;
    }
    assert_eq!(call(Transport::Core, &h, &list).await.0, "locked");
}

#[tokio::test]
async fn req_api_002_openapi_document_matches_the_routes() {
    let doc: Value = serde_json::from_str(OPENAPI_JSON).unwrap();
    assert_eq!(doc["openapi"], json!("3.1.0"));
    let paths: BTreeSet<&str> = doc["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        paths,
        BTreeSet::from(["/v1/status", "/v1/items", "/v1/openapi.json"])
    );
    // Error codes in the doc are exactly the enum.
    let codes: BTreeSet<&str> =
        doc["components"]["schemas"]["Error"]["properties"]["error"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
    assert_eq!(codes, ErrorCode::ALL.iter().map(|c| c.as_str()).collect());
    // Every documented route answers; undocumented ones are 404, and
    // the served document is this one.
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let r = get(addr, "/v1/openapi.json", None).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), doc);
    for p in ["/v1/status", "/v1/items"] {
        assert_eq!(get(addr, p, Some(&h.alpha)).await.status, 200, "{p}");
        let r = get(addr, p, None).await;
        assert_eq!(r.status, 401, "{p}");
        assert!(r.header("www-authenticate").unwrap().starts_with("Bearer"));
    }
    for p in [
        "/",
        "/v1",
        "/v1/items/x",
        "/v1/fill",
        "/v1/secret",
        "/v1/export",
    ] {
        let r = get(addr, p, Some(&h.alpha)).await;
        assert_eq!(r.status, 404, "{p}");
        assert_eq!(
            r.json(),
            ApiError::new(ErrorCode::NotFound, Detail::NoSuchRoute).body()
        );
    }
    let r = raw_request(
        addr,
        format!(
            "POST /v1/items HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            h.alpha
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("GET"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
}
