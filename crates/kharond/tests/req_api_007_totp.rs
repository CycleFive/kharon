//! REQ-API-007 end to end over a CDP stub: `fill_totp` fills the current
//! code through the fill engine and never returns it; clock skew above
//! `clock_skew_refuse` refuses `fill_totp` while password fills are
//! unaffected; 45 s is warn-only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use kharon_bwcrypto::Secret;
use kharond::audit::{AuditConfig, AuditLog, NullCheckpointSink};
use kharond::cdp::fill::DeadlineFiller;
use kharond::cdp::{
    AgentContext, Browser, CdpClient, CdpEndpoint, FieldFill, FieldKind, FillEngine, FillOutcome,
    FillPlan, Tunnel,
};
use kharond::origin::{OriginConfig, OriginMatcher};
use kharond::totp::{ClockSample, ClockSkewGate, SkewVerdict, TotpFill, TotpTarget};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use zeroize::Zeroizing;

const URL: &str = "https://accounts.example.com/login";
/// base32("12345678901234567890"), the RFC 6238 SHA1 seed.
const SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

type Received = Arc<Mutex<Vec<Value>>>;

/// A CDP peer: answers session setup and acks every in-page fill with
/// the kinds it was asked to fill. Records every frame.
async fn cdp_stub() -> (String, Received) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received: Received = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&received);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let mut script: HashMap<&str, Value> = HashMap::new();
        script.insert(
            "Target.createBrowserContext",
            json!({ "browserContextId": "ctx-A" }),
        );
        script.insert(
            "Target.getTargetInfo",
            json!({ "targetInfo": {
                "targetId": "t1", "browserContextId": "ctx-A",
                "url": URL, "title": "", "type": "page",
            } }),
        );
        script.insert("Target.attachToTarget", json!({ "sessionId": "sess-1" }));
        script.insert(
            "Page.getFrameTree",
            json!({ "frameTree": { "frame": {
                "id": "f1", "loaderId": "l1", "url": URL,
            }, "childFrames": [] } }),
        );
        script.insert(
            "Page.createIsolatedWorld",
            json!({ "executionContextId": 7 }),
        );
        while let Some(Ok(Message::Text(text))) = ws.next().await {
            let msg: Value = serde_json::from_str(&text).unwrap();
            rec.lock().unwrap().push(msg.clone());
            let method = msg["method"].as_str().unwrap_or_default();
            let result = if method == "Runtime.callFunctionOn" {
                let kinds: Vec<Value> = msg["params"]["arguments"][1]["value"]
                    .as_array()
                    .map(|fields| {
                        fields
                            .iter()
                            .map(|f| json!({ "kind": f["kind"] }))
                            .collect()
                    })
                    .unwrap_or_default();
                json!({ "result": { "type": "object", "value": { "results": kinds } } })
            } else {
                script.get(method).cloned().unwrap_or_else(|| json!({}))
            };
            let mut reply = json!({ "id": msg["id"], "result": result });
            if let Some(s) = msg.get("sessionId") {
                reply["sessionId"] = s.clone();
            }
            ws.send(Message::Text(reply.to_string())).await.unwrap();
        }
    });
    (format!("ws://{addr}/devtools/browser"), received)
}

struct Harness {
    engine: FillEngine,
    ctx: AgentContext,
    audit: AuditLog,
    dir: tempfile::TempDir,
    received: Received,
}

async fn harness() -> Harness {
    let (url, received) = cdp_stub().await;
    let endpoint = CdpEndpoint::validate(&url, Tunnel::Direct, None).unwrap();
    let client = CdpClient::connect(&endpoint).await.unwrap();
    let browser = Browser::new(client);
    let ctx = browser.create_agent_context("agent-A").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(
        dir.path(),
        AuditConfig::default(),
        Box::new(NullCheckpointSink),
    )
    .unwrap();
    Harness {
        engine: FillEngine::new(browser),
        ctx,
        audit,
        dir,
        received,
    }
}

fn target() -> TotpTarget {
    TotpTarget {
        target_id: "t1".to_string(),
        selector: None,
        item_matchers: vec![OriginMatcher::new(URL, None).unwrap()],
        origin_cfg: OriginConfig::default(),
        cross_origin_iframe_hosts: Vec::new(),
        submit: false,
    }
}

fn seed() -> Secret<String> {
    Secret::new(format!(
        "otpauth://totp/Example:alice?secret={SEED_B32}&issuer=Example"
    ))
}

fn sample(skew: u64) -> ClockSample {
    let server = SystemTime::now();
    ClockSample {
        server,
        local: server + Duration::from_secs(skew),
    }
}

/// Values the stub saw in in-page fill calls.
fn filled_values(received: &Received) -> Vec<(String, String)> {
    received
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m["method"] == "Runtime.callFunctionOn")
        .filter_map(|m| m["params"]["arguments"][1]["value"].as_array().cloned())
        .flatten()
        .map(|f| {
            (
                f["kind"].as_str().unwrap_or_default().to_string(),
                f["value"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn audit_events(dir: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// The SPEC §4 `FillResult` body carries only these keys; none can
/// hold a code.
fn assert_no_code(body: &Value, code: &str) {
    let obj = body.as_object().unwrap();
    for k in obj.keys() {
        assert!(
            [
                "status",
                "fields_filled",
                "detail",
                "grant_request_id",
                "audit_seq"
            ]
            .contains(&k.as_str()),
            "unexpected key {k} in {body}"
        );
    }
    assert!(!body.to_string().contains(code), "{body}");
}

#[tokio::test]
async fn req_api_007_fill_totp_fills_code_never_returns_it() {
    let mut h = harness().await;
    let gate = ClockSkewGate::default();
    // t = 59: step 1, RFC 4226 counter-1 code.
    let now = UNIX_EPOCH + Duration::from_secs(59);
    let outcome = TotpFill::new(&h.engine, &mut h.audit, &gate)
        .at(now)
        .run(target(), seed(), &h.ctx, false)
        .await
        .expect("audit append");
    assert_eq!(
        outcome,
        FillOutcome::Filled {
            kinds: vec![FieldKind::Totp]
        }
    );
    assert_eq!(
        filled_values(&h.received),
        vec![("totp".to_string(), "287082".to_string())]
    );
    let body = outcome.result_body();
    assert_eq!(body["status"], "filled");
    assert_eq!(body["fields_filled"], json!(["totp"]));
    assert_no_code(&body, "287082");
    assert!(!format!("{outcome:?}").contains("287082"));

    // Steam: 5-char code through the same path.
    let steam = Secret::new("steam://2NGTJU2NGTJU2NGTJU2NGTJU2NGTJU2N".to_string());
    let outcome = TotpFill::new(&h.engine, &mut h.audit, &gate)
        .at(UNIX_EPOCH + Duration::from_secs(1_634_603_498))
        .run(target(), steam, &h.ctx, false)
        .await
        .expect("audit append");
    assert_eq!(outcome.status(), "filled");
    assert_eq!(filled_values(&h.received)[1].1, "2C5H2");
    assert_no_code(&outcome.result_body(), "2C5H2");
}

#[tokio::test]
async fn req_api_007_unsupported_field_refused_without_cdp() {
    let mut h = harness().await;
    let gate = ClockSkewGate::default();
    let outcome = TotpFill::new(&h.engine, &mut h.audit, &gate)
        .run(
            target(),
            Secret::new("otpauth://hotp/x?secret=GEZDGNBV".to_string()),
            &h.ctx,
            false,
        )
        .await
        .expect("audit append");
    assert_eq!(outcome, FillOutcome::TotpUnsupported);
    assert_eq!(outcome.result_body()["detail"], "totp_unsupported");
    assert!(filled_values(&h.received).is_empty());
    let events = audit_events(h.dir.path());
    let last = events.last().unwrap();
    assert_eq!(last["event"], "fill_totp");
    assert_eq!(last["result"], "error");
    assert_eq!(last["detail_code"], "totp_unsupported");
}

#[tokio::test]
async fn req_api_007_skew_45s_warning_only() {
    let mut h = harness().await;
    let gate = ClockSkewGate::default();
    let obs = gate.observe(sample(45));
    assert_eq!(obs.verdict, SkewVerdict::Warn);
    assert!(obs.warning.as_deref().unwrap().contains("+45 s"));
    h.audit.append(obs.audit.unwrap()).unwrap();

    let outcome = TotpFill::new(&h.engine, &mut h.audit, &gate)
        .run(target(), seed(), &h.ctx, false)
        .await
        .expect("audit append");
    assert_eq!(outcome.status(), "filled");
    let events = audit_events(h.dir.path());
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "clock_skew" && e["result"] == "warn")
    );
}

#[tokio::test]
async fn req_api_007_skew_120s_refuses_totp_not_passwords() {
    let mut h = harness().await;
    let gate = ClockSkewGate::default();
    let obs = gate.observe(sample(120));
    assert_eq!(obs.verdict, SkewVerdict::Refuse);
    h.audit.append(obs.audit.unwrap()).unwrap();

    let outcome = TotpFill::new(&h.engine, &mut h.audit, &gate)
        .run(target(), seed(), &h.ctx, false)
        .await
        .expect("audit append");
    assert_eq!(outcome, FillOutcome::ClockSkew);
    let body = outcome.result_body();
    assert_eq!(body["status"], "error");
    assert_eq!(body["detail"], "clock_skew");
    // Refused before any CDP work for the fill.
    assert!(filled_values(&h.received).is_empty());

    // Password fills are unaffected by the gate.
    let plan = FillPlan {
        target_id: "t1".to_string(),
        fields: vec![FieldFill {
            kind: FieldKind::Password,
            selector: None,
            value: Zeroizing::new("CANARY-pw-7c1e".to_string()),
        }],
        item_matchers: vec![OriginMatcher::new(URL, None).unwrap()],
        origin_cfg: OriginConfig::default(),
        cross_origin_iframe_hosts: Vec::new(),
        submit: false,
        expected_origin: None,
        live_origin: kharond::cdp::LiveOrigin::new(),
    };
    let (_plan, outcome) = DeadlineFiller::new(&h.engine, &mut h.audit)
        .run(plan, &h.ctx, false)
        .await;
    assert_eq!(
        outcome,
        Ok(FillOutcome::Filled {
            kinds: vec![FieldKind::Password]
        })
    );

    let events = audit_events(h.dir.path());
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "clock_skew" && e["result"] == "refuse")
    );
    assert!(events.iter().any(|e| e["event"] == "fill_totp"
        && e["result"] == "error"
        && e["detail_code"] == "clock_skew"
        && e["agent_id"] == "agent-A"));

    // Resolved: a later in-threshold sample reopens fill_totp.
    let obs = gate.observe(sample(1));
    assert_eq!(obs.verdict, SkewVerdict::Ok);
    h.audit.append(obs.audit.unwrap()).unwrap();
    let outcome = TotpFill::new(&h.engine, &mut h.audit, &gate)
        .run(target(), seed(), &h.ctx, false)
        .await
        .expect("audit append");
    assert_eq!(outcome.status(), "filled");
}

/// Startup probe: the sync client reads the server's `Date` header
/// (`GET /api/alive`) and the skew is measured against the local clock.
#[tokio::test]
async fn req_api_007_clock_probe_reads_server_date() {
    use kharond::sync::{ApiKey, SyncClient, TlsTrust};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let paths_task = Arc::clone(&paths);
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf[..n]).to_string();
        paths_task
            .lock()
            .unwrap()
            .push(head.lines().next().unwrap_or_default().to_string());
        // Server clock 120 s behind ours: local skew +120 s.
        let date = httpdate::fmt_http_date(SystemTime::now() - Duration::from_secs(120));
        let resp = format!(
            "HTTP/1.1 200 OK\r\nDate: {date}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        sock.write_all(resp.as_bytes()).await.unwrap();
    });

    let server = url::Url::parse(&format!("http://{addr}")).unwrap();
    let key = ApiKey::new(
        "user.11111111-2222-4333-8444-555555555555",
        Zeroizing::new("s".to_string()),
    )
    .unwrap();
    let client = SyncClient::new(&server, "a@example.com", key, &TlsTrust::default()).unwrap();
    let s = client.clock_sample().await.unwrap();
    assert!((119..=122).contains(&s.skew_secs()), "{}", s.skew_secs());
    assert_eq!(paths.lock().unwrap()[0], "GET /api/alive HTTP/1.1");

    let gate = ClockSkewGate::default();
    assert_eq!(gate.observe(s).verdict, SkewVerdict::Refuse);
    assert!(gate.check_totp().is_err());
}
