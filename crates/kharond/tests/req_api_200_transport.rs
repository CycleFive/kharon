//! #200 transport hardening: trusted-proxy client identity and the
//! transport rate windows on `/mcp`.
//!
//! The two-sided spoof property, end to end: on `[public_ingress]`
//! the `CF-Connecting-IP` header keys the pre-auth per-IP window —
//! exhaust one claimed address and the next request is 429 while a
//! different claimed address (and a headerless request, keyed by the
//! edge peer) still reaches auth. On the tailnet `[api]` listener
//! the same header is ignored: varying it changes nothing, and the
//! window is exhausted by the real peer alone — a client cannot name
//! its own throttle key there.

mod api_support;

use std::sync::Arc;

use api_support::{Harness, TestBroker, mcp_call, raw_request};
use kharond::api::transport::{PER_AGENT_PER_MINUTE, PER_IP_PER_MINUTE};

async fn serve_public(broker: Arc<TestBroker>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::public::serve_with_shutdown(
        listener,
        broker,
        None,
        std::future::pending(),
    ));
    addr
}

/// One `POST /mcp` with a bad token (so auth is the next step after
/// the transport windows) and an optional `CF-Connecting-IP`.
fn bad_token_post(cf_ip: Option<&str>) -> Vec<u8> {
    let cf = cf_ip
        .map(|ip| format!("CF-Connecting-IP: {ip}\r\n"))
        .unwrap_or_default();
    let body = "{}";
    format!(
        "POST /mcp HTTP/1.1\r\nHost: kharon.test\r\nAuthorization: Bearer bogus\r\n{cf}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[tokio::test]
async fn public_ingress_keys_the_ip_window_by_the_honoured_header() {
    let h = Harness::new(false);
    let addr = serve_public(h.broker.clone()).await;
    let claimed = Some("198.51.100.23");
    for i in 0..PER_IP_PER_MINUTE {
        let r = raw_request(addr, &bad_token_post(claimed)).await;
        assert_eq!(r.status, 401, "request {i} must reach auth: {}", r.body);
    }
    let r = raw_request(addr, &bad_token_post(claimed)).await;
    assert_eq!(r.status, 429, "the claimed address is out of budget");
    let r = raw_request(addr, &bad_token_post(Some("198.51.100.24"))).await;
    assert_eq!(
        r.status, 401,
        "a different claimed address has its own budget"
    );
    let r = raw_request(addr, &bad_token_post(None)).await;
    assert_eq!(
        r.status, 401,
        "no header: the edge peer's budget, untouched"
    );
}

/// One authenticated `POST /mcp` (`tools/list`) from claimed
/// address `cf_ip` with `token`.
fn agent_post(cf_ip: &str, token: &str) -> Vec<u8> {
    let payload = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}";
    format!(
        "POST /mcp HTTP/1.1\r\nHost: kharon.test\r\nAuthorization: Bearer {token}\r\nCF-Connecting-IP: {cf_ip}\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/list\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    )
    .into_bytes()
}

/// Duet's R2 on PR #238: the per-agent window's *wiring* — only the
/// `TransportLimits` unit test covered 240/min, so removing
/// `transport_agent_admit` from the `/mcp` handler failed no test.
/// End to end on public ingress (REQ-RL-005's AC): one token spread
/// across five claimed addresses (48 each, under the per-IP 60/min)
/// answers 240 authenticated requests, and the 241st — from a sixth
/// address whose per-IP budget is fresh — is 429 `rate_limited`.
/// Another agent from that same sixth address is still admitted:
/// the budget that ran out is the agent's, not the address's.
#[tokio::test]
async fn public_ingress_agent_window_refuses_the_241st_request() {
    let h = Harness::new(false);
    let addr = serve_public(h.broker.clone()).await;
    let ips = [
        "198.51.100.11",
        "198.51.100.12",
        "198.51.100.13",
        "198.51.100.14",
        "198.51.100.15",
    ];
    for i in 0..PER_AGENT_PER_MINUTE {
        let r = raw_request(addr, &agent_post(ips[(i as usize) % ips.len()], &h.alpha)).await;
        assert_eq!(r.status, 200, "request {i} must be admitted: {}", r.body);
    }
    let r = raw_request(addr, &agent_post("198.51.100.16", &h.alpha)).await;
    assert_eq!(r.status, 429, "the 241st request is out of budget");
    assert_eq!(r.json()["error"], "rate_limited", "{}", r.body);
    let r = raw_request(addr, &agent_post("198.51.100.16", &h.beta)).await;
    assert_eq!(
        r.status, 200,
        "beta's agent budget is untouched: {}",
        r.body
    );
}

#[tokio::test]
async fn api_listener_ignores_a_spoofed_header() {
    let h = Harness::new(false);
    let addr = api_support::serve_http(h.broker.clone()).await;
    // Vary the claimed address on every request: if the header keyed
    // the window, no bucket would ever fill.
    for i in 0..PER_IP_PER_MINUTE {
        let claimed = format!("198.51.100.{}", i % 7);
        let r = raw_request(addr, &bad_token_post(Some(&claimed))).await;
        assert_eq!(r.status, 401, "request {i} must reach auth: {}", r.body);
    }
    let r = raw_request(addr, &bad_token_post(Some("203.0.113.99"))).await;
    assert_eq!(
        r.status, 429,
        "the real peer exhausted the window; the spoofed header moved nothing"
    );
}

/// The audit half of the contract: entries a call produces carry
/// the effective client address — the honoured header value on
/// public ingress, the connection peer on `[api]`.
#[tokio::test]
async fn audit_entries_carry_the_effective_client_ip() {
    // Public ingress, header honoured.
    let h = Harness::new(false);
    let addr = serve_public(h.broker.clone()).await;
    let payload = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"kharon_list\",\"arguments\":{},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}";
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: kharon.test\r\nAuthorization: Bearer {}\r\nCF-Connecting-IP: 198.51.100.23\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: kharon_list\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        h.alpha,
        payload.len(),
        payload
    );
    let r = raw_request(addr, req.as_bytes()).await;
    assert_eq!(r.status, 200, "{}", r.body);
    {
        let entries = h.audit.entries.lock().unwrap();
        let list = entries
            .iter()
            .find(|e| e.event == kharond::audit::Event::List)
            .expect("a list entry");
        assert_eq!(list.client_ip.as_deref(), Some("198.51.100.23"));
    }

    // The tailnet listener: the peer, header or no header.
    let h = Harness::new(false);
    let addr = api_support::serve_http(h.broker.clone()).await;
    let r = mcp_call(addr, Some(&h.alpha), "kharon_list", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let entries = h.audit.entries.lock().unwrap();
    let list = entries
        .iter()
        .find(|e| e.event == kharond::audit::Event::List)
        .expect("a list entry");
    assert_eq!(list.client_ip.as_deref(), Some("127.0.0.1"));
}

/// The redaction probe (#200): canary-shaped secrets — the fixture
/// vault's passwords and full usernames, the agent's own bearer
/// token, and a canary used as a search query — must appear in no
/// response body and no audit entry the public surface produces,
/// across success and error paths alike.
#[tokio::test]
async fn public_surface_never_echoes_secrets() {
    use api_support::{assert_no_canary, canaries, mcp_request};
    let h = Harness::new(false);
    let addr = serve_public(h.broker.clone()).await;
    let token = h.alpha.clone();

    let mut bodies: Vec<String> = Vec::new();
    // Discovery + reads.
    for (method, params) in [
        ("tools/list", "{}"),
        ("tools/call", r#"{"name":"kharon_list","arguments":{}}"#),
        ("tools/call", r#"{"name":"kharon_status","arguments":{}}"#),
    ] {
        let r = mcp_request(addr, Some(&token), method, params).await;
        bodies.push(r.body);
    }
    // The canary as a search query: queries are not logged, and the
    // query itself is a vault password — it must come back nowhere.
    let q = canaries()[0].clone();
    let params = format!(r#"{{"name":"kharon_search","arguments":{{"q":"{q}"}}}}"#);
    let r = mcp_request(addr, Some(&token), "tools/call", &params).await;
    bodies.push(r.body);
    // A near-miss token (the real one, corrupted) is refused; the
    // refusal must not echo what was presented.
    let bad = format!("{token}x");
    let r = mcp_request(addr, Some(&bad), "tools/list", "{}").await;
    assert_eq!(r.status, 401, "{}", r.body);
    assert!(!r.body.contains(&bad), "401 echoed the presented token");
    bodies.push(r.body);
    // An oversized body: the 413 shape is fixed text too.
    let big = " ".repeat(70 * 1024);
    let r = api_support::post_mcp_raw(
        addr,
        Some(&token),
        &[("Content-Type", "application/json")],
        &big,
    )
    .await;
    assert_eq!(r.status, 413, "{}", r.body);
    bodies.push(r.body);

    for body in &bodies {
        assert_no_canary(body);
        assert!(!body.contains(&token), "response echoed the bearer token");
    }
    let audit = serde_json::to_string(&*h.audit.entries.lock().unwrap()).unwrap();
    assert_no_canary(&audit);
    assert!(
        !audit.contains(&token),
        "audit entry holds the bearer token"
    );
}
