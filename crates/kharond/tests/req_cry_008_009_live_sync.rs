//! Dedicated-org scope check and live sync (issue #9; REQ-CRY-008,
//! REQ-CRY-009, REQ-MEM-006) against an in-process mock Bitwarden
//! server serving the recorded Vaultwarden fixture
//! (`crates/kharon-bwcrypto/tests/fixtures/vaultwarden/`). The served
//! `/api/sync` payload is mutable so tests can widen the scope, rotate
//! the org key, or add/edit/delete items while unlocked.

mod api_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::{CHEAP_FLOOR, FakeAnswer, FakeFill, RecordingAudit, cheap_argon};
use kharond::api::fill::{FillOperation, parse_fill};
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{ApiError, Broker, FillSync, Outcome, SyncFetch};
use kharond::audit::Event;
use kharond::lock::{LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::sync::{
    ApiKey, LiveSync, LockReason, MAX_SYNC_INTERVAL, Scope, SyncClient, SyncError, SyncOutcome,
    SyncPolicy, TlsTrust, check_dedicated_scope, preflight, run, scope_violation,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use url::Url;
use zeroize::Zeroizing;

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);
const CLIENT_ID: &str = "user.11111111-2222-4333-8444-555555555555";
const CLIENT_SECRET: &str = "mock-client-secret";
const OTHER_ORG: &str = "0d9f4c1e-0000-4000-8000-00000000beef";
const NEW_ITEM: &str = "bbbbbbbb-0000-4000-8000-000000000001";

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}")).unwrap())
        .unwrap()
}

struct Req {
    method: String,
    path: String,
    #[allow(dead_code)] // parsed by the shared reader; unused here
    headers: Vec<(String, String)>,
    body: String,
}

/// Mock server state: the payload `/api/sync` serves now, plus knobs.
struct Mock {
    sync: Value,
    syncs: usize,
    /// Answer the next N `/api/sync` calls with 503.
    fail_next: usize,
    /// Swap in this payload once `syncs` reaches the given count.
    after: Option<(usize, Value)>,
}

type Shared = Arc<Mutex<Mock>>;

fn fixture() -> (Value, String, String) {
    let s = load("sync_fixture.json");
    let org = s["profile"]["organizations"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let coll = s["collections"][0]["id"].as_str().unwrap().to_owned();
    (s, org, coll)
}

/// The account added to a second org (the REQ-CRY-008 AC fixture).
fn with_second_org(mut s: Value) -> Value {
    let key = s["profile"]["organizations"][0]["key"].clone();
    s["profile"]["organizations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": OTHER_ORG, "name": "other", "key": key}));
    s
}

/// A personal item (no org) visible to the account.
fn with_personal_item(mut s: Value) -> Value {
    let mut c = s["ciphers"][0].clone();
    c["id"] = json!("cccccccc-0000-4000-8000-000000000001");
    c["organizationId"] = Value::Null;
    c["collectionIds"] = json!([]);
    s["ciphers"].as_array_mut().unwrap().push(c);
    s
}

async fn serve(state: Shared) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let manifest = load("fixture.json");
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let state = state.clone();
            let manifest = manifest.clone();
            tokio::spawn(async move {
                while let Some(req) = read_req(&mut sock).await {
                    let (status, body) = respond(&req, &manifest, &state);
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Url::parse(&format!("http://{addr}")).unwrap()
}

fn respond(req: &Req, manifest: &Value, state: &Mutex<Mock>) -> (u16, String) {
    let acct = &manifest["account"];
    match (req.method.as_str(), req.path.as_str()) {
        ("POST", "/identity/accounts/prelogin") => (
            200,
            json!({"kdf": acct["kdf"], "kdfIterations": acct["kdf_iterations"],
                   "kdfMemory": null, "kdfParallelism": null})
            .to_string(),
        ),
        ("POST", "/identity/connect/token") => {
            if !req.body.contains(CLIENT_SECRET) {
                return (400, json!({"error": "invalid_client"}).to_string());
            }
            (
                200,
                json!({"access_token": "tok", "expires_in": 7200,
                       "token_type": "Bearer", "scope": "api"})
                .to_string(),
            )
        }
        ("GET", p) if p.starts_with("/api/sync") => {
            let mut st = state.lock().unwrap();
            if st.fail_next > 0 {
                st.fail_next -= 1;
                return (503, "{}".into());
            }
            st.syncs += 1;
            if st.after.as_ref().is_some_and(|(n, _)| st.syncs > *n) {
                st.sync = st.after.take().unwrap().1;
            }
            (200, st.sync.to_string())
        }
        _ => (404, "{}".into()),
    }
}

async fn read_req(sock: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.parse().unwrap())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string();
    Some(Req {
        method,
        path,
        headers,
        body,
    })
}

async fn mock(sync: Value) -> (Shared, SyncClient) {
    let (state, client, _) = mock_at(sync).await;
    (state, client)
}

/// As [`mock`], also returning the server URL (for a second client).
async fn mock_at(sync: Value) -> (Shared, SyncClient, Url) {
    let state = Arc::new(Mutex::new(Mock {
        sync,
        syncs: 0,
        fail_next: 0,
        after: None,
    }));
    let server = serve(state.clone()).await;
    (state, client_for(&server), server)
}

fn client_for(server: &Url) -> SyncClient {
    let email = load("fixture.json")["account"]["email"]
        .as_str()
        .unwrap()
        .to_owned();
    let key = ApiKey::new(CLIENT_ID, Zeroizing::new(CLIENT_SECRET.to_owned())).unwrap();
    SyncClient::new(server, &email, key, &TlsTrust::default()).unwrap()
}

fn password() -> Zeroizing<String> {
    Zeroizing::new(
        load("fixture.json")["account"]["password"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

fn set(state: &Shared, sync: Value) {
    state.lock().unwrap().sync = sync;
}

async fn unlocked(sync: Value, policy: SyncPolicy) -> (Shared, LiveSync, String) {
    let (_, org, coll) = fixture();
    let (state, client) = mock(sync).await;
    let live = LiveSync::unlock(
        client,
        &password(),
        Scope::new(&org, [&coll]).unwrap(),
        policy,
    )
    .await
    .unwrap();
    (state, live, org)
}

// ---- REQ-CRY-008 ----

#[tokio::test]
async fn req_cry_008_startup_refuses_second_org_scope_too_broad() {
    let (s, org, _) = fixture();
    let (_, mut client) = mock(with_second_org(s.clone())).await;
    let err = preflight(&mut client, &org, false).await.unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::ScopeTooBroad {
                other_orgs: 1,
                outside_items: 0
            }
        ),
        "{err:?}"
    );
    assert!(err.to_string().starts_with("ScopeTooBroad"), "{err}");
    // The error names counts, never ids or names.
    assert!(!err.to_string().contains(OTHER_ORG));

    // The dedicated fixture account passes.
    let (_, mut client) = mock(s).await;
    preflight(&mut client, &org, false).await.unwrap();
}

#[tokio::test]
async fn req_cry_008_personal_item_is_outside_scope() {
    let (s, org, _) = fixture();
    let s = with_personal_item(s);
    let v = scope_violation(&serde_json::from_value(s.clone()).unwrap(), &org);
    assert_eq!(v.other_orgs, Vec::<String>::new());
    assert_eq!(
        v.outside_items,
        vec!["cccccccc-0000-4000-8000-000000000001"]
    );
    let (_, mut client) = mock(s).await;
    let err = preflight(&mut client, &org, false).await.unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::ScopeTooBroad {
                other_orgs: 0,
                outside_items: 1
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn req_cry_008_unlock_checks_scope_before_deriving_keys() {
    // A wrong password would fail at key unwrap; ScopeTooBroad first
    // shows the check runs on ciphertext before any key derivation.
    let (s, org, coll) = fixture();
    let (_, client) = mock(with_second_org(s)).await;
    let err = LiveSync::unlock(
        client,
        &Zeroizing::new("not the password".to_owned()),
        Scope::new(&org, [&coll]).unwrap(),
        SyncPolicy::default(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(err, SyncError::ScopeTooBroad { .. }), "{err:?}");
}

#[tokio::test]
async fn req_cry_008_allow_extra_orgs_waives_the_check() {
    let (s, org, _) = fixture();
    let wide = with_personal_item(with_second_org(s));
    check_dedicated_scope(&serde_json::from_value(wide.clone()).unwrap(), &org, true).unwrap();
    let (state, mut live, _) = unlocked(wide, SyncPolicy::new(true, MAX_SYNC_INTERVAL)).await;
    assert_eq!(live.vault().len(), 2);
    // Still scoped by REQ-CRY-007: the personal item is not in the vault.
    assert_eq!(live.vault().report().out_of_scope, 1);
    set(&state, with_second_org(fixture().0));
    assert!(matches!(
        live.sync_now().await.unwrap(),
        SyncOutcome::Synced
    ));
}

#[tokio::test]
async fn req_cry_008_widening_mid_run_locks_with_scope_widened_audit() {
    let (s, _, _) = fixture();
    let (state, mut live, _) = unlocked(s.clone(), SyncPolicy::default()).await;
    let before = live.vault().len();
    set(&state, with_second_org(s));
    let SyncOutcome::Lock(reason) = live.sync_now().await.unwrap() else {
        panic!("widened scope must lock");
    };
    let LockReason::ScopeWidened(v) = &reason else {
        panic!("{reason:?}");
    };
    assert_eq!(v.other_orgs, vec![OTHER_ORG]);
    let entry = reason.audit_entry();
    assert_eq!(entry.event, Event::ScopeWidened);
    assert_eq!(entry.detail_code.as_deref(), Some("other_org_visible"));
    // Nothing from the widened payload was applied.
    assert_eq!(live.vault().len(), before);
}

// ---- REQ-CRY-009 ----

#[tokio::test]
async fn req_cry_009_resync_reflects_add_edit_delete() {
    let (s, _, _) = fixture();
    let (state, mut live, _) = unlocked(s.clone(), SyncPolicy::default()).await;
    assert_eq!(live.vault().len(), 2);
    let first = s["ciphers"][0]["id"].as_str().unwrap().to_owned();
    let second = s["ciphers"][1]["id"].as_str().unwrap().to_owned();

    // Add: a new in-scope item.
    let mut added = s.clone();
    let mut c = s["ciphers"][0].clone();
    c["id"] = json!(NEW_ITEM);
    added["ciphers"].as_array_mut().unwrap().push(c);
    set(&state, added.clone());
    assert!(matches!(
        live.sync_now().await.unwrap(),
        SyncOutcome::Synced
    ));
    assert_eq!(live.vault().len(), 3);
    assert!(live.vault().get(NEW_ITEM).is_ok());

    // Edit: the revision moves.
    let mut edited = added.clone();
    edited["ciphers"][0]["revisionDate"] = json!("2026-11-01T22:00:00Z");
    set(&state, edited.clone());
    live.sync_now().await.unwrap();
    assert_eq!(
        live.vault().get(&first).unwrap().revision(),
        Some("2026-11-01T22:00:00Z")
    );

    // Delete: gone from the vault, so fills fail closed.
    let mut deleted = edited;
    deleted["ciphers"]
        .as_array_mut()
        .unwrap()
        .retain(|c| c["id"] != json!(second));
    set(&state, deleted);
    live.sync_now().await.unwrap();
    assert_eq!(live.vault().len(), 2);
    assert!(matches!(
        live.vault().get(&second),
        Err(SyncError::ItemNotFound)
    ));
}

#[tokio::test]
async fn req_cry_009_poll_loop_syncs_on_interval_until_lock() {
    let (s, _, _) = fixture();
    let interval = Duration::from_millis(40);
    let (state, mut live, _) = unlocked(s.clone(), SyncPolicy::new(false, interval)).await;
    // After three polls (plus the unlock sync) the scope widens.
    state.lock().unwrap().after = Some((4, with_second_org(s)));
    let (_tx, rx) = mpsc::channel(1);
    let t0 = tokio::time::Instant::now();
    let reason = tokio::time::timeout(Duration::from_secs(10), run(&mut live, rx, |_| {}))
        .await
        .expect("poll loop must lock");
    assert!(matches!(reason, LockReason::ScopeWidened(_)));
    assert_eq!(state.lock().unwrap().syncs, 5);
    assert!(t0.elapsed() >= interval * 4, "{:?}", t0.elapsed());
}

#[tokio::test]
async fn req_cry_009_push_nudge_syncs_without_waiting_for_poll() {
    let (s, _, _) = fixture();
    let (state, mut live, _) = unlocked(s.clone(), SyncPolicy::default()).await;
    set(&state, with_second_org(s));
    let (tx, rx) = mpsc::channel(1);
    tx.send(()).await.unwrap();
    let reason = tokio::time::timeout(Duration::from_secs(10), run(&mut live, rx, |_| {}))
        .await
        .expect("nudge must sync immediately, not after 5 min");
    assert_eq!(reason.audit_event(), Event::ScopeWidened);
}

#[tokio::test]
async fn req_cry_009_transient_errors_keep_vault_and_retry() {
    let (s, _, _) = fixture();
    let interval = Duration::from_millis(20);
    let (state, mut live, _) = unlocked(s.clone(), SyncPolicy::new(false, interval)).await;
    {
        let mut st = state.lock().unwrap();
        st.fail_next = 2;
        st.after = Some((1, with_second_org(s)));
    }
    let mut errors = 0;
    let (_tx, rx) = mpsc::channel(1);
    let reason = tokio::time::timeout(
        Duration::from_secs(10),
        run(&mut live, rx, |e| {
            assert!(matches!(e, SyncError::Status { status: 503, .. }), "{e:?}");
            errors += 1;
        }),
    )
    .await
    .unwrap();
    assert_eq!(errors, 2);
    assert!(matches!(reason, LockReason::ScopeWidened(_)));
}

#[tokio::test]
async fn req_cry_009_interval_capped_and_fill_staleness_rule() {
    assert_eq!(
        SyncPolicy::new(false, Duration::from_secs(3600)).interval,
        MAX_SYNC_INTERVAL
    );
    assert_eq!(MAX_SYNC_INTERVAL, Duration::from_secs(300));
    let (s, _, _) = fixture();
    let (_, mut live, _) = unlocked(s, SyncPolicy::default()).await;
    let t = live.last_sync();
    assert!(!live.is_stale(t + Duration::from_secs(299)));
    assert!(live.is_stale(t + Duration::from_secs(301)));
    // Fresh vault: the /v1/fill hook does not hit the server.
    assert!(matches!(
        live.sync_if_stale().await.unwrap(),
        SyncOutcome::Synced
    ));
}

// ---- REQ-CRY-009, SPEC §8 fill-time re-sync (issue #100) ----

/// The fill path's `/api/sync` source: a second client on the mock
/// (the daemon builds a fresh one per fetch from its config).
struct MockFillSync(tokio::sync::Mutex<SyncClient>);

impl FillSync for MockFillSync {
    fn fetch(&self) -> SyncFetch<'_> {
        Box::pin(async move { self.0.lock().await.sync().await })
    }
}

struct FillRig {
    state: Shared,
    broker: Broker<LiveSync, Arc<ManualClock>>,
    audit: RecordingAudit,
    fake: FakeFill,
    alpha: String,
}

/// A broker holding an unlocked [`LiveSync`] of the mock, with the
/// fill-time re-sync wired to the same server and a fake browser.
async fn fill_rig(sync: Value) -> FillRig {
    let (_, org, coll) = fixture();
    let (state, client, server) = mock_at(sync).await;
    let live = LiveSync::unlock(
        client,
        &password(),
        Scope::new(&org, [&coll]).unwrap(),
        SyncPolicy::default(),
    )
    .await
    .unwrap();
    let (alpha, hash) = generate_with(&cheap_argon(), "alpha");
    let tokens = TokenStore::with_floor([("alpha", hash.as_str())], &CHEAP_FLOOR).unwrap();
    let mut lock = LockController::new(
        LockPolicy::default(),
        Arc::new(ManualClock::new()),
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| Ok::<_, ()>(live)).unwrap();
    let audit = RecordingAudit::default();
    let fake = FakeFill::new(FakeAnswer::Filled);
    let broker = Broker::new(
        tokens,
        lock,
        Box::new(audit.clone()),
        OriginConfig::default(),
    )
    .with_fill_backend(Box::new(fake.clone()))
    .with_fill_sync(Arc::new(MockFillSync(tokio::sync::Mutex::new(client_for(
        &server,
    )))));
    broker.wire_lock_audit();
    FillRig {
        state,
        broker,
        audit,
        fake,
        alpha: alpha.expose_secret().clone(),
    }
}

impl FillRig {
    async fn fill(&self, item_id: &str) -> Result<Value, ApiError> {
        let agent = self.broker.authenticate(&self.alpha).unwrap();
        let body = json!({
            "item_id": item_id,
            "target": {"cdp_target_id": "T-1", "expected_origin": "https://login.example.com"},
            "fields": [{"kind": "password"}],
        });
        let req = parse_fill(FillOperation::Fill, body.to_string().as_bytes()).unwrap();
        self.broker
            .fill(&agent, req, tokio::time::Instant::now())
            .await
            .map(|o| match o {
                Outcome::Fill(f) => serde_json::to_value(f).unwrap(),
                other => panic!("not a fill result: {:?}", other.body()),
            })
    }

    fn syncs(&self) -> usize {
        self.state.lock().unwrap().syncs
    }

    fn events(&self) -> Vec<Value> {
        self.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| {
                let v = serde_json::to_value(e).unwrap();
                json!([v["event"], v["result"], v["detail_code"]])
            })
            .collect()
    }
}

/// Age the vault past the 5-minute bound on tokio's clock (the
/// `LiveSync` last-sync instant), leaving real time running for I/O.
async fn age_past_max_interval() {
    tokio::time::pause();
    tokio::time::advance(MAX_SYNC_INTERVAL + Duration::from_secs(1)).await;
    tokio::time::resume();
}

fn with_new_item(mut s: Value) -> Value {
    let mut c = s["ciphers"][0].clone();
    c["id"] = json!(NEW_ITEM);
    s["ciphers"].as_array_mut().unwrap().push(c);
    s
}

#[tokio::test]
async fn req_cry_009_fill_resyncs_stale_vault_before_resolving() {
    let (s, _, _) = fixture();
    let r = fill_rig(s.clone()).await;
    let base = r.syncs();
    set(&r.state, with_new_item(s));

    // Fresh vault: no server hit, so the item added server-side is
    // not visible yet.
    let out = r.fill(NEW_ITEM).await.unwrap();
    assert_eq!(out["status"], "not_found", "{out}");
    assert_eq!(r.syncs(), base);

    // Stale vault: the fill re-syncs first and finds the new item.
    age_past_max_interval().await;
    let out = r.fill(NEW_ITEM).await.unwrap();
    assert_eq!(out["status"], "filled", "{out}");
    assert_eq!(r.syncs(), base + 1);
    assert_eq!(r.fake.seen().len(), 1);

    // The re-sync reset the staleness clock: the next fill does not.
    r.fill(NEW_ITEM).await.unwrap();
    assert_eq!(r.syncs(), base + 1);
}

#[tokio::test]
async fn req_cry_009_fill_refuses_stale_vault_when_resync_fails() {
    let (s, _, _) = fixture();
    let r = fill_rig(s.clone()).await;
    let item = s["ciphers"][0]["id"].as_str().unwrap().to_owned();
    r.state.lock().unwrap().fail_next = 1;
    age_past_max_interval().await;

    // Fails closed: the stale vault is not filled from.
    let out = r.fill(&item).await.unwrap();
    assert_eq!(
        out,
        json!({"status": "error", "fields_filled": [], "detail": "sync_failed"})
    );
    assert!(r.fake.seen().is_empty(), "no plan may reach the browser");
    assert_eq!(r.events(), vec![json!(["fill", "error", "sync_failed"])]);
    assert!(!r.broker.lock_controller().lock().unwrap().is_locked());

    // The server recovers: the next fill re-syncs and proceeds.
    let out = r.fill(&item).await.unwrap();
    assert_eq!(out["status"], "filled", "{out}");
}

#[tokio::test]
async fn req_cry_009_fill_resync_widening_scope_locks() {
    let (s, _, _) = fixture();
    let r = fill_rig(s.clone()).await;
    let item = s["ciphers"][0]["id"].as_str().unwrap().to_owned();
    set(&r.state, with_second_org(s));
    age_past_max_interval().await;

    assert!(matches!(r.fill(&item).await, Err(ApiError::LOCKED)));
    assert!(r.fake.seen().is_empty());
    assert!(r.broker.lock_controller().lock().unwrap().is_locked());
    let events = r.events();
    assert_eq!(events.last().unwrap(), &json!(["fill", "locked", null]));
    assert!(events.iter().any(|e| e[0] == "scope_widened"), "{events:?}");
}

#[tokio::test]
async fn req_mem_006_org_key_change_on_resync_locks_key_rotated() {
    let (s, _, _) = fixture();
    let (state, mut live, _) = unlocked(s.clone(), SyncPolicy::default()).await;
    // The server now presents a different protected key for the same
    // org. The cached key is kept (no second type-4 decrypt), and the
    // differing ciphertext forces a lock.
    let mut rotated = s;
    let k = rotated["profile"]["organizations"][0]["key"]
        .as_str()
        .unwrap()
        .to_owned();
    rotated["profile"]["organizations"][0]["key"] = json!(rotated_key(&k));
    set(&state, rotated);
    match live.sync_now().await {
        Ok(SyncOutcome::Lock(r)) => {
            assert_eq!(r, LockReason::KeyRotated);
            assert_eq!(r.audit_entry().event, Event::KeyRotated);
        }
        other => panic!("{other:?}"),
    }
}

/// Same length and alphabet, different ciphertext: swap two distinct
/// leading base64 characters of a `4.<b64>` EncString.
fn rotated_key(k: &str) -> String {
    let (head, body) = k.split_at(2);
    let mut b: Vec<char> = body.chars().collect();
    let j = (1..b.len()).find(|&j| b[j] != b[0]).unwrap();
    b.swap(0, j);
    format!("{head}{}", b.into_iter().collect::<String>())
}

/// Live: real Vaultwarden over HTTPS (`fixture.yml`). The seeded
/// account is dedicated (one org, no personal items), so the startup
/// check passes, and an unlocked re-sync keeps the same vault.
#[tokio::test]
#[ignore = "needs the live Vaultwarden fixture (fixture.yml)"]
async fn req_cry_008_009_live_vaultwarden_preflight_and_resync() {
    let base = Url::parse(&std::env::var("KHARON_FIXTURE_BASE_URL").unwrap()).unwrap();
    let trust = TlsTrust {
        extra_ca_pem: Some(
            std::fs::read(std::env::var("KHARON_FIXTURE_CA_CERT").unwrap()).unwrap(),
        ),
    };
    let key = ApiKey::from_file(
        std::env::var("KHARON_FIXTURE_API_KEY_JSON")
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    let manifest = load("fixture.json");
    let email = manifest["account"]["email"].as_str().unwrap();
    let mut c = SyncClient::new(&base, email, key, &trust).unwrap();
    let raw = c.sync().await.unwrap();
    let org = raw.profile.organizations.as_ref().unwrap()[0].id.clone();
    let coll = raw.collections.as_ref().unwrap()[0].id.clone();
    preflight(&mut c, &org, false).await.unwrap();
    let mut live = LiveSync::unlock(
        c,
        &password(),
        Scope::new(&org, [&coll]).unwrap(),
        SyncPolicy::default(),
    )
    .await
    .unwrap();
    let n = live.vault().len();
    assert_eq!(n, manifest["items"].as_array().unwrap().len());
    assert!(matches!(
        live.sync_now().await.unwrap(),
        SyncOutcome::Synced
    ));
    assert_eq!(live.vault().len(), n);
}
