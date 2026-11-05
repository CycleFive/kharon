//! REQ-API-007 end to end through [`Broker::fill`], the one `fill_totp`
//! path (HTTP and MCP both call it), over a CDP stub: `fill_totp`
//! fills the current code through the fill engine and never returns
//! it; clock skew above `clock_skew_refuse` refuses `fill_totp` (before
//! the seed is decrypted) while password fills are unaffected; 45 s is
//! warn-only.
//!
//! Every fill that reaches the browser is the REQ-AUD-003† pair: a
//! `fill_dispatch` entry, then exactly one `fill_totp` outcome entry
//! with the same `request_id`. A refusal before the browser (clock
//! skew, unsupported field) writes the outcome entry only, and a failed
//! append of any outcome entry is `audit_failed` (#46, #77).
//!
//! The vault is the encrypted export fixture; its login's TOTP field is
//! swapped per test ([`SeedSession`]) so one item can carry an RFC 6238
//! URI, a Steam secret or an unsupported HOTP URI.

mod api_support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use api_support::{CHEAP_FLOOR, FakeAnswer, FakeFill, RecordingAudit, cheap_argon};
use futures_util::{SinkExt, StreamExt};
use kharon_bwcrypto::Secret;
use kharond::api::fill::{FillOperation, FillPolicy, parse_fill};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{AgentId, ApiError, Broker, CdpFillBackend, FillBackend, Outcome, VaultView};
use kharond::cdp::{Browser, CdpClient, CdpEndpoint, FillEngine, Tunnel};
use kharond::export::{ExportFile, ExportSession};
use kharond::lock::{LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::sync::{SecretField, SyncError, Vault};
use kharond::totp::{ClockSample, ClockSkewGate, SkewVerdict, totp_code};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use zeroize::{ZeroizeOnDrop, Zeroizing};

const EXPORT: &[u8] = include_bytes!("fixtures/export/password_protected.json");
const EXPORT_PASSWORD: &str = "kharon export fixture password 9";
const CANARY_PASSWORD: &str = "CANARY-EXPORT-PASSWORD-7f3a";
const URL: &str = "https://example.com/login";
const ORIGIN: &str = "https://example.com";
/// base32("12345678901234567890"), the RFC 6238 SHA1 seed.
const SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
/// [`SEED_B32`] as the `otpauth://` URI Bitwarden clients store.
const RFC_URI: &str =
    "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example";
const STEAM: &str = "steam://2NGTJU2NGTJU2NGTJU2NGTJU2NGTJU2N";
const HOTP: &str = "otpauth://hotp/x?secret=GEZDGNBV";

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

/// The export session, with the login's `login.totp` replaced by
/// `seed` and every TOTP decrypt counted (a refused call must decrypt
/// nothing).
struct SeedSession {
    inner: ExportSession,
    seed: &'static str,
    totp_decrypts: Arc<AtomicUsize>,
}

impl ZeroizeOnDrop for SeedSession {}

impl VaultView for SeedSession {
    fn vault(&self) -> &Vault {
        self.inner.vault()
    }

    fn decrypt_secret(
        &self,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        match field {
            SecretField::Totp => {
                // The real ciphertext must still decrypt: same item,
                // same error cases, only the plaintext is swapped.
                self.inner.decrypt_secret(item_id, field)?;
                self.totp_decrypts.fetch_add(1, Ordering::SeqCst);
                Ok(Zeroizing::new(self.seed.as_bytes().to_vec()))
            }
            _ => self.inner.decrypt_secret(item_id, field),
        }
    }
}

struct Harness {
    broker: Broker<SeedSession, Arc<ManualClock>>,
    agent: AgentId,
    item_id: String,
    audit: RecordingAudit,
    totp_decrypts: Arc<AtomicUsize>,
    /// Every field value of every plan, as seen after the broker wiped it.
    wiped: Arc<Mutex<Vec<String>>>,
}

fn broker_with(seed: &'static str, backend: Box<dyn FillBackend>, policy: FillPolicy) -> Harness {
    let inner: ExportSession = ExportFile::from_bytes(EXPORT)
        .unwrap()
        .unlock(&Zeroizing::new(EXPORT_PASSWORD.to_owned()))
        .unwrap();
    let item_id = inner
        .vault()
        .items()
        .find(|i| i.name() == "Example Login")
        .unwrap()
        .id()
        .to_owned();
    let totp_decrypts = Arc::new(AtomicUsize::new(0));
    let session = SeedSession {
        inner,
        seed,
        totp_decrypts: Arc::clone(&totp_decrypts),
    };
    let mut lock = LockController::new(
        LockPolicy::default(),
        Arc::new(ManualClock::new()),
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| Ok::<_, ()>(session)).unwrap();
    let (token, hash) = generate_with(&cheap_argon(), "alpha");
    let tokens = TokenStore::with_floor([("alpha", hash.as_str())], &CHEAP_FLOOR).unwrap();
    let audit = RecordingAudit::default();
    let wiped: Arc<Mutex<Vec<String>>> = Arc::default();
    let w = Arc::clone(&wiped);
    let broker = Broker::new(
        tokens,
        lock,
        Box::new(audit.clone()),
        OriginConfig::default(),
    )
    .with_fill_backend(backend)
    .with_fill_policy(policy)
    .with_plan_wiped_hook(Arc::new(move |plan| {
        w.lock()
            .unwrap()
            .extend(plan.fields.iter().map(|f| (*f.value).clone()));
    }));
    // #20: fills need a grant. The export item has no collections, so
    // seed item-scope grants for both actions (long TTL: this broker's
    // grant clock is the wall clock).
    {
        let now = kharond::lock::Clock::now(&kharond::lock::SystemClock);
        let terms = kharond::api::GrantTerms {
            scope: kharond::api::GrantScope::Item(item_id.clone()),
            kind: kharond::config::GrantKind::PerOrigin,
            ttl: Some(std::time::Duration::from_secs(24 * 3600)),
            max_uses: None,
        };
        let mut store = broker.grant_store().lock().unwrap();
        for action in [
            kharond::api::GrantAction::Fill,
            kharond::api::GrantAction::Totp,
        ] {
            store
                .issue(
                    "alpha",
                    &item_id,
                    action,
                    "https://example.com",
                    &terms,
                    kharond::api::Channel::Cli,
                    None,
                    now,
                )
                .unwrap();
        }
    }
    let agent = broker.authenticate(token.expose_secret()).unwrap();
    Harness {
        broker,
        agent,
        item_id,
        audit,
        totp_decrypts,
        wiped,
    }
}

/// A broker filling through the real engine into [`cdp_stub`].
async fn harness(seed: &'static str) -> (Harness, Received) {
    let (url, received) = cdp_stub().await;
    let endpoint = CdpEndpoint::validate(&url, Tunnel::Direct, None).unwrap();
    let browser = Browser::new(CdpClient::connect(&endpoint).await.unwrap());
    let ctx = browser.create_agent_context("alpha").await.unwrap();
    let mut backend = CdpFillBackend::new();
    backend.register("alpha", FillEngine::new(browser), ctx);
    let h = broker_with(seed, Box::new(backend), FillPolicy::default());
    (h, received)
}

impl Harness {
    async fn call(&self, op: FillOperation, fields: Value) -> Result<Value, ApiError> {
        let body = json!({
            "item_id": self.item_id,
            "target": {"cdp_target_id": "t1", "expected_origin": ORIGIN},
            "fields": fields,
        });
        let req = parse_fill(op, body.to_string().as_bytes()).unwrap();
        self.broker
            .fill(&self.agent, req, Instant::now())
            .await
            .map(|o| match o {
                Outcome::Fill(f) => serde_json::to_value(f).unwrap(),
                other => panic!("not a fill result: {:?}", other.body()),
            })
    }

    /// `fill_totp` with the default `[{"kind": "totp"}]` fields.
    async fn fill_totp(&self) -> Result<Value, ApiError> {
        self.call(FillOperation::FillTotp, json!([{"kind": "totp"}]))
            .await
    }

    fn entries(&self) -> Vec<Value> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| serde_json::to_value(e).unwrap())
            .collect()
    }

    fn observe(&self, skew: u64) -> kharond::totp::skew::Observation {
        let server = SystemTime::now();
        let (obs, appended) = self.broker.observe_clock(ClockSample {
            server,
            local: server + Duration::from_secs(skew),
        });
        appended.expect("clock_skew append");
        obs
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

/// `entries` is exactly the REQ-AUD-003† pair for one
/// fill that reached the browser: `fill_dispatch` then one `event`
/// outcome with `result` and the same `request_id`.
fn assert_dispatch_pair(entries: &[Value], item_id: &str, event: &str, result: &str) {
    assert_eq!(entries.len(), 2, "{entries:?}");
    let (d, o) = (&entries[0], &entries[1]);
    assert_eq!(d["event"], "fill_dispatch");
    assert_eq!(d["agent_id"], "alpha");
    assert_eq!(d["item_id"], item_id);
    assert_eq!(d["origin"], ORIGIN);
    assert_eq!(d["field_count"], 1);
    assert_eq!(d["result"], "dispatched");
    assert_eq!(o["event"], event);
    assert_eq!(o["agent_id"], "alpha");
    assert_eq!(o["result"], result);
    assert_eq!(o["request_id"], d["request_id"]);
    assert_eq!(o["live_origin"], ORIGIN);
}

/// `fill_totp` through the broker types the code `totp_code` gives for
/// the time of the call (one of the steps around it) and nothing else.
async fn assert_fills_current_code(seed: &'static str, len: usize) {
    let (h, received) = harness(seed).await;
    let gate = ClockSkewGate::default();
    let code = |t| (*totp_code(&gate, Secret::new(seed.to_owned()), t).unwrap()).clone();
    let before = code(SystemTime::now());
    let out = h.fill_totp().await.expect("audit append");
    let after = code(SystemTime::now());

    assert_eq!(out, json!({"status": "filled", "fields_filled": ["totp"]}));
    let typed = filled_values(&received);
    assert_eq!(typed.len(), 1, "{typed:?}");
    let (kind, typed) = &typed[0];
    assert_eq!(kind, "totp");
    assert_eq!(typed.len(), len);
    assert!(*typed == before || *typed == after, "not the current code");
    assert_no_code(&out, typed);

    let e = h.entries();
    assert_dispatch_pair(&e, &h.item_id, "fill_totp", "filled");
    let text = serde_json::to_string(&e).unwrap();
    assert!(!text.contains(typed.as_str()), "code in the audit log");
    assert!(!text.contains(SEED_B32) && !text.contains("steam://"));
    assert_eq!(h.totp_decrypts.load(Ordering::SeqCst), 1);
    let wiped = h.wiped.lock().unwrap().clone();
    assert!(wiped.len() == 1 && wiped[0].is_empty(), "plan zeroized");
}

#[tokio::test]
async fn req_api_007_fill_totp_fills_code_never_returns_it() {
    // The generator the broker calls, at fixed times: RFC 6238's SHA1
    // vector (t = 59: step 1, RFC 4226 counter-1 code) and Steam's.
    let gate = ClockSkewGate::default();
    let at = |seed: &str, t: u64| {
        (*totp_code(
            &gate,
            Secret::new(seed.to_owned()),
            UNIX_EPOCH + Duration::from_secs(t),
        )
        .unwrap())
        .clone()
    };
    assert_eq!(at(RFC_URI, 59), "287082");
    assert_eq!(at(STEAM, 1_634_603_498), "2C5H2");

    // And through the broker, now.
    assert_fills_current_code(RFC_URI, 6).await;
    // Steam: 5-char code through the same path.
    assert_fills_current_code(STEAM, 5).await;
}

#[tokio::test]
async fn req_api_007_unsupported_field_refused_without_cdp() {
    let (h, received) = harness(HOTP).await;
    let out = h.fill_totp().await.expect("audit append");
    assert_eq!(
        out,
        json!({"status": "error", "fields_filled": [], "detail": "totp_unsupported"})
    );
    assert!(filled_values(&received).is_empty());
    // A refusal before the browser: the outcome entry only.
    let e = h.entries();
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0]["event"], "fill_totp");
    assert_eq!(e[0]["agent_id"], "alpha");
    assert_eq!(e[0]["result"], "error");
    assert_eq!(e[0]["detail_code"], "totp_unsupported");
    assert!(
        e[0].get("live_origin").is_none(),
        "never reached the browser"
    );
}

#[tokio::test]
async fn req_api_007_skew_45s_warning_only() {
    let (h, received) = harness(STEAM).await;
    let obs = h.observe(45);
    assert_eq!(obs.verdict, SkewVerdict::Warn);
    assert!(obs.warning.as_deref().unwrap().contains("+45 s"));

    let out = h.fill_totp().await.expect("audit append");
    assert_eq!(out["status"], "filled");
    assert_eq!(filled_values(&received).len(), 1);
    let e = h.entries();
    assert_eq!(e[0]["event"], "clock_skew");
    assert_eq!(e[0]["result"], "warn");
    assert_dispatch_pair(&e[1..], &h.item_id, "fill_totp", "filled");
}

#[tokio::test]
async fn req_api_007_skew_120s_refuses_totp_not_passwords() {
    let (h, received) = harness(STEAM).await;
    let obs = h.observe(120);
    assert_eq!(obs.verdict, SkewVerdict::Refuse);

    let out = h.fill_totp().await.expect("audit append");
    assert_eq!(
        out,
        json!({"status": "error", "fields_filled": [], "detail": "clock_skew"})
    );
    // Refused before any CDP work for the fill, and before the seed
    // was decrypted.
    assert!(filled_values(&received).is_empty());
    assert_eq!(h.totp_decrypts.load(Ordering::SeqCst), 0);
    let e = h.entries();
    assert_eq!(e.len(), 2, "{e:?}");
    assert_eq!(e[0]["event"], "clock_skew");
    assert_eq!(e[0]["result"], "refuse");
    assert_eq!(e[1]["event"], "fill_totp");
    assert_eq!(e[1]["result"], "error");
    assert_eq!(e[1]["detail_code"], "clock_skew");
    assert_eq!(e[1]["agent_id"], "alpha");

    // Password fills are unaffected by the gate.
    let out = h
        .call(FillOperation::Fill, json!([{"kind": "password"}]))
        .await
        .expect("audit append");
    assert_eq!(
        out,
        json!({"status": "filled", "fields_filled": ["password"]})
    );
    assert_eq!(
        filled_values(&received),
        [("password".to_string(), CANARY_PASSWORD.to_string())]
    );
    assert_dispatch_pair(&h.entries()[2..], &h.item_id, "fill", "filled");

    // Resolved: a later in-threshold sample reopens fill_totp.
    let obs = h.observe(1);
    assert_eq!(obs.verdict, SkewVerdict::Ok);
    let out = h.fill_totp().await.expect("audit append");
    assert_eq!(out["status"], "filled");
    let e = h.entries();
    assert_eq!(e[4]["event"], "clock_skew");
    assert_dispatch_pair(&e[5..], &h.item_id, "fill_totp", "filled");
}

/// REQ-AUD-003†: a refusal made before any CDP call (here an
/// unsupported TOTP field, REQ-API-007) is still an outcome; when its
/// `fill_totp` entry cannot be appended the call is `audit_failed`, not
/// the refusal (#46), and the backend is never called.
#[tokio::test]
async fn req_aud_003_totp_refusal_append_failure_is_audit_failed() {
    let fake = FakeFill::new(FakeAnswer::Filled);
    let h = broker_with(HOTP, Box::new(fake.clone()), FillPolicy::default());
    *h.audit.fail_event.lock().unwrap() = Some("fill_totp");
    assert_eq!(h.fill_totp().await, Err(ApiError::AUDIT_FAILED));
    assert!(fake.seen().is_empty(), "no fill call on a refusal");
    assert!(h.entries().is_empty(), "{:?}", h.entries());
}

/// REQ-API-009 + REQ-AUD-003†: `fill_totp` through the deadline with a
/// failing `fill_timeout` append is `audit_failed` at the deadline, not
/// `timeout`; the plan (the code's only buffer) is still wiped.
#[tokio::test(start_paused = true)]
async fn req_api_009_totp_timeout_append_failure_is_audit_failed() {
    let fake = FakeFill::new(FakeAnswer::Stall);
    let policy = FillPolicy {
        deadline: Duration::from_millis(500),
        ..FillPolicy::default()
    };
    let h = broker_with(STEAM, Box::new(fake.clone()), policy);
    *h.audit.fail_event.lock().unwrap() = Some("fill_timeout");
    let start = Instant::now();
    assert_eq!(h.fill_totp().await, Err(ApiError::AUDIT_FAILED));
    assert_eq!(start.elapsed(), Duration::from_millis(500));
    assert_eq!(fake.seen().len(), 1, "dispatched");
    let e = h.entries();
    assert_eq!(e.len(), 1, "only the dispatch reached the log: {e:?}");
    assert_eq!(e[0]["event"], "fill_dispatch");
    let wiped = h.wiped.lock().unwrap().clone();
    assert!(wiped.len() == 1 && wiped[0].is_empty(), "plan zeroized");
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
