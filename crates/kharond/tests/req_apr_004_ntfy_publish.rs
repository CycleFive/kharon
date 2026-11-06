//! REQ-APR-004 send half (SPEC §5; issue #128): when a grant request
//! is created, the broker publishes it to the configured ntfy topic
//! with single-use approve/deny `http` actions on the owner
//! listener's address — and the published action actually redeems.
//!
//! - A pending fill publishes exactly one message: JSON publish to
//!   the ntfy server root, the configured topic, agent / item /
//!   observed origin in the text, the bearer token from the token
//!   file, and Approve/Deny POST actions whose URLs are the live
//!   token paths joined onto the redeem base.
//! - POSTing the published approve URL's path to the owner listener
//!   issues the `once` grant (publish + redeem, end to end).
//! - A deduped retry (no new request) publishes nothing new; an
//!   origin-mismatch request is refused before prompting and
//!   publishes nothing.
//! - `kharon panic` notifies (REQ-REV-002), and the ntfy panic
//!   message carries no actions.

mod api_support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::{
    CHEAP_FLOOR, FakeAnswer, FakeFill, ITEM_A, RawResponse, RecordingAudit, TestBroker,
    TestSession, cheap_argon, raw_request, serve_owner,
};
use kharond::api::grant::{ApprovalPrompt, RequestState};
use kharond::api::notify::ApprovalNotifier;
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{Broker, NtfyApprovalNotifier, Outcome, parse_fill};
use kharond::lock::{Clock, LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use serde_json::{Value, json};
use tokio::time::Instant;

/// A stub ntfy server: records every raw request and answers 200.
struct StubNtfy {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

fn stub_ntfy() -> StubNtfy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&requests);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let mut reader = BufReader::new(stream);
            let mut raw = String::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.is_empty() {
                    break;
                }
                if line.to_ascii_lowercase().starts_with("content-length:") {
                    content_length = line.split(':').nth(1).unwrap().trim().parse().unwrap();
                }
                let done = line == "\r\n";
                raw.push_str(&line);
                if done {
                    break;
                }
            }
            let mut body = vec![0u8; content_length];
            if reader.read_exact(&mut body).is_ok() {
                raw.push_str(&String::from_utf8_lossy(&body));
            }
            sink.lock().unwrap().push(raw);
            let mut stream = reader.into_inner();
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            );
        }
    });
    StubNtfy { port, requests }
}

impl StubNtfy {
    /// Wait for the detached publisher to deliver `n` requests.
    fn wait_for(&self, n: usize) -> Vec<String> {
        for _ in 0..100 {
            let got = self.requests.lock().unwrap().clone();
            if got.len() >= n {
                return got;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "stub ntfy saw {} requests, wanted {n}",
            self.requests.lock().unwrap().len()
        );
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

/// Split a recorded raw request into (request line, headers, JSON body).
fn parse_request(raw: &str) -> (String, String, Value) {
    let mut parts = raw.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap();
    let body = parts.next().unwrap_or("");
    let line = head.lines().next().unwrap().to_owned();
    (line, head.to_owned(), serde_json::from_str(body).unwrap())
}

#[derive(Default)]
struct RecordingNotifier {
    calls: Mutex<Vec<(ApprovalPrompt, String, String)>>,
    panics: Mutex<u32>,
}

impl ApprovalNotifier for RecordingNotifier {
    fn notify_grant_request(&self, prompt: &ApprovalPrompt, approve_path: &str, deny_path: &str) {
        self.calls.lock().unwrap().push((
            prompt.clone(),
            approve_path.to_owned(),
            deny_path.to_owned(),
        ));
    }

    fn notify_panic(&self) {
        *self.panics.lock().unwrap() += 1;
    }
}

struct Rig {
    broker: Arc<TestBroker>,
    alpha: String,
}

impl Rig {
    fn build(notifier: Option<Arc<dyn ApprovalNotifier>>) -> Self {
        let (alpha, ha) = generate_with(&cheap_argon(), "alpha");
        let tokens = TokenStore::with_floor([("alpha", ha.as_str())], &CHEAP_FLOOR).unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut lock = LockController::new(
            LockPolicy::default(),
            clock.clone(),
            Box::new(StaticHardening::all_ok()),
        );
        lock.unlock(|| Ok::<_, ()>(TestSession::fixture())).unwrap();
        let audit = RecordingAudit::default();
        let fake = FakeFill::new(FakeAnswer::Filled).with_live_url("https://login.example.com/");
        let grant_clock: Arc<dyn Clock> = clock.clone();
        let mut broker = Broker::new(tokens, lock, Box::new(audit), OriginConfig::default())
            .with_grant_clock(grant_clock)
            .with_fill_backend(Box::new(fake));
        if let Some(notifier) = notifier {
            broker = broker.with_approval_notifier(notifier);
        }
        Self {
            broker: Arc::new(broker),
            alpha: alpha.expose_secret().clone(),
        }
    }

    async fn fill(&self, expected_origin: &str) -> Value {
        let req = parse_fill(
            kharond::api::FillOperation::Fill,
            json!({
                "item_id": ITEM_A,
                "target": {"cdp_target_id": "tab-1", "expected_origin": expected_origin},
                "fields": [{"kind": "password"}],
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let agent = self.broker.authenticate(&self.alpha).unwrap();
        match self.broker.fill(&agent, req, Instant::now()).await {
            Ok(Outcome::Fill(r)) => serde_json::to_value(r).unwrap(),
            other => panic!("expected a fill outcome, got {other:?}"),
        }
    }

    async fn fill_password(&self) -> Value {
        self.fill("https://login.example.com").await
    }
}

async fn http(addr: std::net::SocketAddr, method: &str, path: &str) -> RawResponse {
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    raw_request(addr, head.as_bytes()).await
}

#[tokio::test]
async fn req_apr_004_publish_posts_prompt_with_single_use_actions() {
    let stub = stub_ntfy();
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("ntfy-token");
    std::fs::write(&token_path, "tk_canary_token\n").unwrap();
    let base = url::Url::parse(&format!("http://127.0.0.1:{}", stub.port)).unwrap();
    let notifier = NtfyApprovalNotifier::new(
        &base,
        "kharon-alerts",
        Some(&token_path),
        "http://127.0.0.1:8788".to_owned(),
    )
    .unwrap();
    let rig = Rig::build(Some(Arc::new(notifier)));

    let r = rig.fill_password().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    let id = r["grant_request_id"].as_str().unwrap().to_owned();

    let requests = stub.wait_for(1);
    assert_eq!(requests.len(), 1, "exactly one publish per request");
    let (line, head, body) = parse_request(&requests[0]);
    assert!(line.starts_with("POST / HTTP/1.1"), "{line}");
    assert!(head.contains("Authorization: Bearer tk_"), "{head}");
    assert_eq!(body["topic"], "kharon-alerts");
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("alpha"), "{message}");
    assert!(message.contains(ITEM_A), "{message}");
    assert!(
        message.contains("https://login.example.com"),
        "the prompt shows the observed origin: {message}"
    );
    // The actions are the live token pair, joined onto the redeem base.
    let (approve_path, deny_path) = rig.broker.approval_token_paths(&id).unwrap();
    let actions = body["actions"].as_array().unwrap();
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0]["label"], "Approve");
    assert_eq!(actions[0]["method"], "POST");
    assert_eq!(
        actions[0]["url"],
        format!("http://127.0.0.1:8788{approve_path}")
    );
    assert_eq!(actions[1]["label"], "Deny");
    assert_eq!(actions[1]["method"], "POST");
    assert_eq!(
        actions[1]["url"],
        format!("http://127.0.0.1:8788{deny_path}")
    );
}

#[tokio::test]
async fn req_apr_004_published_action_redeems_end_to_end() {
    let stub = stub_ntfy();
    let base = url::Url::parse(&format!("http://127.0.0.1:{}", stub.port)).unwrap();
    let notifier = NtfyApprovalNotifier::new(
        &base,
        "kharon-alerts",
        None,
        "http://127.0.0.1:8788".to_owned(),
    )
    .unwrap();
    let rig = Rig::build(Some(Arc::new(notifier)));

    let r = rig.fill_password().await;
    let id = r["grant_request_id"].as_str().unwrap().to_owned();

    // Take the approve URL out of the published message and POST its
    // path to the owner listener, exactly what the ntfy client's
    // http action does on the device that can reach the listener.
    let requests = stub.wait_for(1);
    let (_, _, body) = parse_request(&requests[0]);
    let approve_url = body["actions"][0]["url"].as_str().unwrap();
    let approve_path = approve_url
        .strip_prefix("http://127.0.0.1:8788")
        .unwrap()
        .to_owned();

    let addr = serve_owner(rig.broker.clone()).await;
    let post = http(addr, "POST", &approve_path).await;
    assert_eq!(post.status, 200, "{}", post.body);
    assert_eq!(
        rig.broker.grant_request(&id).unwrap().state,
        RequestState::Approved
    );
    // And the fill the owner just approved now runs.
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "filled", "{r}");
}

#[tokio::test]
async fn req_apr_004_no_publish_for_deduped_or_origin_mismatch_requests() {
    let recorder = Arc::new(RecordingNotifier::default());
    let rig = Rig::build(Some(recorder.clone() as Arc<dyn ApprovalNotifier>));

    let r = rig.fill_password().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    {
        let calls = recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (prompt, approve, deny) = &calls[0];
        assert_eq!(prompt.agent_id, "alpha");
        assert_eq!(prompt.item_id, ITEM_A);
        assert_eq!(prompt.origin, "https://login.example.com");
        let (want_approve, want_deny) =
            rig.broker.approval_token_paths(&prompt.request_id).unwrap();
        assert_eq!(approve, &want_approve);
        assert_eq!(deny, &want_deny);
    }

    // A deduped retry creates no request and publishes nothing.
    let r = rig.fill_password().await;
    assert_eq!(r["status"], "pending_approval", "{r}");
    assert_eq!(recorder.calls.lock().unwrap().len(), 1);

    // An origin-mismatch request is refused before prompting
    // (REQ-APR-007): no notification.
    let r = rig.fill("https://phish.example.com").await;
    assert_eq!(r["status"], "origin_mismatch", "{r}");
    assert_eq!(recorder.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn req_apr_004_panic_notifies_without_actions() {
    let recorder = Arc::new(RecordingNotifier::default());
    let rig = Rig::build(Some(recorder.clone() as Arc<dyn ApprovalNotifier>));
    rig.broker.panic_lock().unwrap();
    assert_eq!(*recorder.panics.lock().unwrap(), 1);

    // The ntfy panic message itself: topic + text, no actions.
    let stub = stub_ntfy();
    let base = url::Url::parse(&format!("http://127.0.0.1:{}", stub.port)).unwrap();
    let notifier = NtfyApprovalNotifier::new(
        &base,
        "kharon-alerts",
        None,
        "http://127.0.0.1:8788".to_owned(),
    )
    .unwrap();
    notifier.publish_panic().unwrap();
    let requests = stub.wait_for(1);
    let (_, _, body) = parse_request(&requests[0]);
    assert_eq!(body["topic"], "kharon-alerts");
    assert!(body["message"].as_str().unwrap().contains("panic"));
    assert!(body.get("actions").is_none(), "{body}");
    assert_eq!(stub.count(), 1);
}
