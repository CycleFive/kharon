//! REQ-ARCH-005 (#65): the broker hands the agent its `browserContextId`
//! over `POST /v1/context` and the MCP tool `kharon_context`, with the
//! same request hygiene as the fill routes (POST only, no browser
//! `Origin`, agent token, no parameters), the same result on both
//! transports, a lock gate, the fill deadline, and the REQ-AUD-003†
//! `context_open` / `context` pair. Against a [`FakeFill`] backend; the
//! daemon path over a CDP stub (lazy connect, idempotency, reconnect,
//! lock invalidation, CDP ordering) is in `req_api_008_daemon_cdp.rs`.

mod api_support;

use std::time::Duration;

use api_support::*;
use kharond::api::fill::FillPolicy;
use kharond::api::{ApiError, Detail, ErrorCode, Outcome};
use serde_json::{Value, json};
use tokio::time::Instant;

fn with_fake(locked: bool, answer: FakeAnswer, deadline: Option<Duration>) -> (Harness, FakeFill) {
    let fake = FakeFill::new(answer);
    let f = fake.clone();
    let h = Harness::with(locked, move |b| {
        let mut policy = FillPolicy::default();
        if let Some(d) = deadline {
            policy.deadline = d;
        }
        b.with_fill_backend(Box::new(f)).with_fill_policy(policy)
    });
    (h, fake)
}

/// `POST /v1/context` with optional extra headers and body.
async fn post_context(
    addr: std::net::SocketAddr,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: &str,
) -> RawResponse {
    let mut head = String::from("POST /v1/context HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(t) = token {
        head.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    raw_request(addr, head.as_bytes()).await
}

/// `(isError, body)` of a `kharon_context` call.
async fn mcp_context(addr: std::net::SocketAddr, token: &str, args: &str) -> (bool, Value) {
    let r = mcp_call(addr, Some(token), "kharon_context", args).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    let res = &v["result"];
    let body = serde_json::from_str(res["content"][0]["text"].as_str().unwrap()).unwrap();
    (res["isError"].as_bool().unwrap(), body)
}

fn entries(h: &Harness) -> Vec<Value> {
    h.audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .map(|e| serde_json::to_value(e).unwrap())
        .collect()
}

fn ok_alpha() -> Value {
    json!({"status": "ok", "browser_context_id": "ctx-alpha"})
}

#[tokio::test]
async fn req_arch_005_context_route_has_the_fill_routes_hygiene() {
    let (h, fake) = with_fake(false, FakeAnswer::Filled, None);
    let addr = serve_http(h.broker.clone()).await;
    let t = Some(h.alpha.as_str());
    let json_ct = [("Content-Type", "application/json")];

    let r = get(addr, "/v1/context", t).await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("POST"));
    let r = post_context(addr, t, &[("Origin", "https://evil.example")], "").await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(
        r.json(),
        ApiError::new(ErrorCode::Forbidden, Detail::BrowserOriginRefused).body()
    );
    let r = post_context(addr, None, &[], "").await;
    assert_eq!(r.status, 401);
    assert!(r.header("www-authenticate").unwrap().starts_with("Bearer"));
    let r = post_context(addr, Some("kh_agent_alpha_nope"), &[], "").await;
    assert_eq!(r.status, 401);
    let r = post_context(addr, t, &[("Content-Type", "text/plain")], "{}").await;
    assert_eq!(r.status, 400);
    assert_eq!(
        r.json(),
        ApiError::bad_request(Detail::UnsupportedContentType).body()
    );
    for (body, detail) in [
        (r#"{"agent_id":"beta"}"#, Detail::UnknownParameter),
        ("[]", Detail::InvalidArguments),
        ("{", Detail::InvalidJsonBody),
    ] {
        let r = post_context(addr, t, &json_ct, body).await;
        assert_eq!(r.status, 400, "{body}");
        assert_eq!(r.json(), ApiError::bad_request(detail).body(), "{body}");
    }
    // Nothing above reached the backend or the audit log.
    assert!(fake.context_calls.lock().unwrap().is_empty());
    assert!(h.audit.summary().is_empty());

    for (headers, body) in [(&[][..], ""), (&json_ct[..], "{}")] {
        let r = post_context(addr, t, headers, body).await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert_eq!(r.json(), ok_alpha());
    }
}

/// REQ-API-002: the same result over HTTP and MCP, per agent; MCP
/// refuses arguments like HTTP refuses a body. Status carries the cached
/// id, `null` before the first call.
#[tokio::test]
async fn req_arch_005_context_is_the_same_over_http_and_mcp() {
    let (h, fake) = with_fake(false, FakeAnswer::Filled, None);
    let addr = serve_http(h.broker.clone()).await;
    let status = |tok: String| async move {
        get(addr, "/v1/status", Some(&tok)).await.json()["browser_context_id"].clone()
    };
    assert_eq!(status(h.alpha.clone()).await, Value::Null);

    let http = post_context(addr, Some(&h.alpha), &[], "").await.json();
    assert_eq!(http, ok_alpha());
    for args in ["{}", "null"] {
        assert_eq!(mcp_context(addr, &h.alpha, args).await, (false, ok_alpha()));
    }
    let (is_error, body) = mcp_context(addr, &h.alpha, r#"{"x":"1"}"#).await;
    assert!(is_error);
    assert_eq!(body, ApiError::bad_request(Detail::UnknownParameter).body());
    let (is_error, body) = mcp_context(addr, &h.alpha, "[]").await;
    assert!(is_error);
    assert_eq!(body, ApiError::bad_request(Detail::InvalidArguments).body());

    assert_eq!(status(h.alpha.clone()).await, json!("ctx-alpha"));
    assert_eq!(status(h.beta.clone()).await, Value::Null, "per agent");
    assert_eq!(
        mcp_context(addr, &h.beta, "{}").await,
        (
            false,
            json!({"status": "ok", "browser_context_id": "ctx-beta"})
        )
    );
    assert_eq!(
        *fake.context_calls.lock().unwrap(),
        ["alpha", "alpha", "alpha", "beta"]
    );
    // context_open + one context outcome per admitted call, paired.
    let e = entries(&h);
    assert_eq!(e.len(), 8, "{e:?}");
    for pair in e.chunks(2) {
        assert_eq!(pair[0]["event"], "context_open");
        assert_eq!(pair[0]["result"], "dispatched");
        assert_eq!(pair[1]["event"], "context");
        assert_eq!(pair[1]["result"], "ok");
        assert_eq!(pair[0]["request_id"], pair[1]["request_id"]);
    }
    assert_ne!(e[0]["request_id"], e[2]["request_id"]);
}

#[tokio::test]
async fn req_arch_005_context_is_423_while_locked() {
    let (h, fake) = with_fake(true, FakeAnswer::Filled, None);
    let addr = serve_http(h.broker.clone()).await;
    let r = post_context(addr, Some(&h.alpha), &[], "").await;
    assert_eq!(r.status, 423, "{}", r.body);
    assert_eq!(r.json(), ApiError::LOCKED.body());
    let (is_error, body) = mcp_context(addr, &h.alpha, "{}").await;
    assert!(is_error);
    assert_eq!(body, ApiError::LOCKED.body());
    assert!(fake.context_calls.lock().unwrap().is_empty());
    assert_eq!(
        h.audit.summary(),
        vec![json!(["context", "alpha", null, "locked"]); 2]
    );
}

/// An agent without a configured browser: `error`/`fill_unavailable`,
/// audited once (no `context_open`: nothing was dispatched).
#[tokio::test]
async fn req_arch_005_context_without_a_browser_is_fill_unavailable() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let r = post_context(addr, Some(&h.alpha), &[], "").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(
        r.json(),
        json!({"status": "error", "detail": "fill_unavailable"})
    );
    let e = entries(&h);
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0]["event"], "context");
    assert_eq!(e[0]["result"], "error");
    assert_eq!(e[0]["detail_code"], "fill_unavailable");
}

async fn context(h: &Harness, received: Instant) -> Value {
    let agent = h.broker.authenticate(&h.alpha).unwrap();
    match h.broker.context(&agent, received).await.unwrap() {
        Outcome::Context(c) => serde_json::to_value(c).unwrap(),
        other => panic!("not a context result: {:?}", other.body()),
    }
}

/// REQ-API-009: the call runs under `fill_deadline` from receipt (paused
/// clock: exact). A stall is cut off at the deadline with
/// `context_open` + one `context`/`timeout`; a request already past
/// its deadline never reaches the backend (outcome entry only).
#[tokio::test(start_paused = true)]
async fn req_api_009_context_deadline_is_the_fill_deadline() {
    fixture_vault();
    let (h, fake) = with_fake(false, FakeAnswer::Stall, Some(Duration::from_secs(2)));
    let received = Instant::now();
    assert_eq!(context(&h, received).await, json!({"status": "timeout"}));
    assert_eq!(received.elapsed(), Duration::from_secs(2));
    let e = entries(&h);
    assert_eq!(e.len(), 2, "{e:?}");
    assert_eq!(e[0]["event"], "context_open");
    assert_eq!(e[1]["event"], "context");
    assert_eq!(e[1]["result"], "timeout");
    assert_eq!(e[1]["detail_code"], "deadline_expired");
    assert_eq!(e[0]["request_id"], e[1]["request_id"]);
    assert_eq!(fake.context_calls.lock().unwrap().len(), 1);

    let stale = Instant::now();
    tokio::time::advance(Duration::from_secs(3)).await;
    assert_eq!(context(&h, stale).await, json!({"status": "timeout"}));
    let e = entries(&h);
    assert_eq!(e.len(), 3, "{e:?}");
    assert_eq!(e[2]["event"], "context");
    assert_eq!(e[2]["result"], "timeout");
    assert_eq!(
        fake.context_calls.lock().unwrap().len(),
        1,
        "not dispatched"
    );
}

/// The handler dropped mid-call (client gone): `context_open`, then one
/// `context`/`aborted` entry.
#[tokio::test(start_paused = true)]
async fn req_aud_003_dropped_context_call_is_audited_aborted() {
    fixture_vault();
    let (h, _fake) = with_fake(false, FakeAnswer::Stall, None);
    let agent = h.broker.authenticate(&h.alpha).unwrap();
    let call = h.broker.context(&agent, Instant::now());
    assert!(
        tokio::time::timeout(Duration::from_secs(1), call)
            .await
            .is_err()
    );
    let e = entries(&h);
    assert_eq!(e.len(), 2, "{e:?}");
    assert_eq!(e[0]["event"], "context_open");
    assert_eq!(e[1]["event"], "context");
    assert_eq!(e[1]["result"], "aborted");
    assert_eq!(e[1]["detail_code"], "handler_dropped");
    assert_eq!(e[0]["request_id"], e[1]["request_id"]);
}
