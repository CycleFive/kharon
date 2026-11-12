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

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use api_support::{Harness, TestBroker, mcp_call, raw_request};
use kharond::api::transport::{PER_AGENT_PER_MINUTE, PER_IP_PER_MINUTE};

async fn serve_public(broker: Arc<TestBroker>) -> std::net::SocketAddr {
    serve_public_proxies(broker, Arc::from([])).await
}

async fn serve_public_proxies(
    broker: Arc<TestBroker>,
    trusted: Arc<[std::net::IpAddr]>,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::public::serve_with_shutdown(
        listener,
        broker,
        None,
        None,
        trusted,
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

/// Records every tracing event and span field emitted on this thread.
struct TracingCapture(Arc<Mutex<String>>);

struct TracingRecorder<'a>(&'a mut String);

impl tracing::field::Visit for TracingRecorder<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

impl<S> tracing_subscriber::Layer<S> for TracingCapture
where
    S: tracing::Subscriber,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut line = format!("span {}", attrs.metadata().name());
        attrs.record(&mut TracingRecorder(&mut line));
        self.push(line);
    }

    fn on_record(
        &self,
        _id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut line = String::from("record");
        values.record(&mut TracingRecorder(&mut line));
        self.push(line);
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut line = format!(
            "event {} {}",
            event.metadata().target(),
            event.metadata().name()
        );
        event.record(&mut TracingRecorder(&mut line));
        self.push(line);
    }
}

impl TracingCapture {
    fn push(&self, line: String) {
        let mut buf = self.0.lock().unwrap();
        buf.push_str(&line);
        buf.push('\n');
    }
}

/// The redaction probe (#200, #239): canary-shaped secrets — the fixture
/// vault's passwords and full usernames, the agent's own bearer
/// token, and a canary used as a search query — must appear in no
/// response body, no audit entry, and no tracing output the public
/// surface produces, across success and error paths alike. One
/// `kharon_fill` runs through it, and that fill really decrypts a
/// vault password, so the scan is not of a path that never held one.
///
/// `current_thread` keeps the server task on this thread, where the
/// capture subscriber is installed. kharond's own lines are
/// `eprintln!`, not tracing events; the subscriber is what a later
/// `tracing` event is checked against, and the sentinel proves it
/// was recording.
#[tokio::test(flavor = "current_thread")]
async fn public_surface_never_echoes_secrets() {
    use api_support::{FakeAnswer, FakeFill, ITEM_A, assert_no_canary, canaries, mcp_request};
    use tracing_subscriber::prelude::*;

    let captured = Arc::new(Mutex::new(String::new()));
    let subscriber = tracing_subscriber::registry().with(TracingCapture(Arc::clone(&captured)));
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::info!(target: "kharon_redaction_probe", "subscriber armed");

    let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/");
    let recorded = fake.clone();
    let h = Harness::with(false, move |b| b.with_fill_backend(Box::new(fake)));
    h.grant_fixture_items();
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
    // One fill. The password is decrypted into the plan the backend
    // sees; the reply is status only.
    let fill = format!(
        r#"{{"item_id":"{ITEM_A}","target":{{"cdp_target_id":"tab-1","expected_origin":"https://login.example.com"}},"fields":[{{"kind":"username"}},{{"kind":"password"}}]}}"#
    );
    let r = mcp_call(addr, Some(&token), "kharon_fill", &fill).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let reply = r.json();
    assert_eq!(reply["result"]["isError"], false, "{}", r.body);
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    let filled: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(filled["status"], "filled", "{filled}");
    assert!(
        recorded.seen().iter().any(|plan| {
            plan.fields.iter().any(|(kind, _, value)| {
                *kind == "password" && canaries().iter().any(|c| c == value)
            })
        }),
        "kharon_fill did not decrypt a vault password, so the scan would be vacuous"
    );
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
        assert!(!body.contains(&q), "response echoed the search query");
    }
    let audit = serde_json::to_string(&*h.audit.entries.lock().unwrap()).unwrap();
    assert_no_canary(&audit);
    assert!(
        !audit.contains(&token),
        "audit entry holds the bearer token"
    );
    assert!(!audit.contains(&q), "audit entry holds the search query");
    let logs = captured.lock().unwrap().clone();
    assert!(
        logs.contains("subscriber armed"),
        "the tracing subscriber recorded nothing, so the scan would be vacuous"
    );
    assert_no_canary(&logs);
    assert!(
        !logs.contains(&token),
        "tracing output holds the bearer token"
    );
    assert!(!logs.contains(&q), "tracing output holds the search query");
}

/// `POST /mcp` as if the TCP peer were `peer`, through the real router.
/// A missing [`ConnectInfo`] is a 500, so a 401 or 429 means the peer
/// was the one the handler read.
async fn post_as(
    app: &axum::Router,
    peer: SocketAddr,
    headers: &[(&str, &str)],
    body: &'static str,
) -> u16 {
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::Request;
    use kharond::api::public::Peer;
    use tower::ServiceExt;

    let mut builder = Request::builder().method("POST").uri("/mcp");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let req = builder
        .extension(ConnectInfo(Peer(peer)))
        .body(Body::from(body))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status().as_u16()
}

fn bad_headers(cf: &str) -> Vec<(&str, String)> {
    vec![
        ("host", "kharon.test".to_owned()),
        ("content-type", "application/json".to_owned()),
        ("authorization", "Bearer bogus".to_owned()),
        ("cf-connecting-ip", cf.to_owned()),
    ]
}

/// A non-loopback peer that is not in `trusted_proxies` cannot pick its
/// throttle key. Rotating `CF-Connecting-IP` still fills one window,
/// the peer's, and a second peer is unaffected.
#[tokio::test]
async fn untrusted_peer_cannot_choose_its_throttle_key() {
    let h = Harness::new(false);
    let app = kharond::api::public::router(h.broker.clone(), None, None, Arc::from([]));
    let peer: SocketAddr = "203.0.113.9:40000".parse().unwrap();
    for i in 0..PER_IP_PER_MINUTE {
        let cf = format!("198.51.100.{}", i + 1);
        let headers = bad_headers(&cf);
        let pairs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let status = post_as(&app, peer, &pairs, "{}").await;
        assert_eq!(status, 401, "request {i} must reach auth");
    }
    let headers = bad_headers("198.51.100.200");
    let pairs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
    assert_eq!(
        post_as(&app, peer, &pairs, "{}").await,
        429,
        "the peer's own window is exhausted; the rotating header did not mint keys"
    );
    let other: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    assert_eq!(
        post_as(&app, other, &pairs, "{}").await,
        401,
        "a different peer has its own budget"
    );
}

/// Audit `client_ip` is the same address the throttle uses. A listed
/// proxy's header is recorded; an unlisted peer is recorded as itself.
/// Loopback stays trusted even when the list names someone else.
#[tokio::test]
async fn audit_client_ip_follows_the_proxy_list() {
    let h = Harness::new(false);
    let listed: IpAddr = "203.0.113.9".parse().unwrap();
    let proxies: Arc<[IpAddr]> = Arc::from([listed]);
    let app = kharond::api::public::router(h.broker.clone(), None, None, Arc::clone(&proxies));
    let payload = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"kharon_list\",\"arguments\":{},\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}";
    let list_from = async |peer: SocketAddr| {
        let headers = [
            ("host", "kharon.test".to_owned()),
            ("content-type", "application/json".to_owned()),
            ("authorization", format!("Bearer {}", h.alpha)),
            ("cf-connecting-ip", "198.51.100.23".to_owned()),
            ("mcp-protocol-version", "2026-07-28".to_owned()),
            ("mcp-method", "tools/call".to_owned()),
            ("mcp-name", "kharon_list".to_owned()),
        ];
        let pairs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        post_as(&app, peer, &pairs, payload).await
    };
    let trusted: SocketAddr = "203.0.113.9:40000".parse().unwrap();
    assert_eq!(list_from(trusted).await, 200);
    let stranger: SocketAddr = "203.0.113.8:40000".parse().unwrap();
    assert_eq!(list_from(stranger).await, 200);
    let ips: Vec<_> = {
        let entries = h.audit.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| e.event == kharond::audit::Event::List)
            .filter_map(|e| e.client_ip.clone())
            .collect()
    };
    assert_eq!(
        ips,
        vec!["198.51.100.23".to_owned(), "203.0.113.8".to_owned()],
        "listed proxy records the header; an unlisted peer records itself"
    );

    // A real loopback accept, with a list that does not name 127.0.0.1.
    let h = Harness::new(false);
    let addr = serve_public_proxies(h.broker.clone(), proxies).await;
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: kharon.test\r\nAuthorization: Bearer {}\r\nCF-Connecting-IP: 198.51.100.23\r\nMCP-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/call\r\nMcp-Name: kharon_list\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        h.alpha,
        payload.len()
    );
    let r = raw_request(addr, req.as_bytes()).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let entries = h.audit.entries.lock().unwrap();
    let list = entries
        .iter()
        .find(|e| e.event == kharond::audit::Event::List)
        .expect("a list entry");
    assert_eq!(
        list.client_ip.as_deref(),
        Some("198.51.100.23"),
        "loopback stays trusted when the list names another proxy"
    );
}
