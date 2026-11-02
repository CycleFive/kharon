//! Notifications hub push sync (issue #9; REQ-CRY-009 push half,
//! REQ-CRY-008 lock-on-widening via push) against an in-process mock
//! that speaks Vaultwarden 1.33's `/notifications/hub` wire format
//! (WebSocket, MessagePack SignalR, `{}`+RS handshake reply as a
//! binary frame, varint-framed `ReceiveMessage` invocations) next to
//! the mock Bitwarden HTTP API serving the recorded fixture.
//!
//! The live tests at the bottom run against the real Vaultwarden
//! fixture in `fixture.yml`, mutating it through `mutate.py`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use kharond::audit::Event;
use kharond::sync::{
    ApiKey, HubError, HubStatus, HubTiming, LiveSync, LockReason, MAX_SYNC_INTERVAL,
    NotificationsHub, Scope, SyncClient, SyncOutcome, SyncPolicy, TlsTrust, UpdateType, run,
    run_push,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use url::Url;
use zeroize::Zeroizing;

const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);
const CLIENT_ID: &str = "user.11111111-2222-4333-8444-555555555555";
const CLIENT_SECRET: &str = "mock-client-secret";
const ACCESS_TOKEN: &str = "mock-access-token-7f3a";
const OTHER_ORG: &str = "0d9f4c1e-0000-4000-8000-00000000beef";
const NEW_ITEM: &str = "bbbbbbbb-0000-4000-8000-000000000001";
/// "Changes land within ~10 s" (REQ-CRY-009 AC).
const PUSH_DEADLINE: Duration = Duration::from_secs(10);

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}")).unwrap())
        .unwrap()
}

fn fixture() -> (Value, String, String) {
    let s = load("sync_fixture.json");
    let org = s["profile"]["organizations"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let coll = s["collections"][0]["id"].as_str().unwrap().to_owned();
    (s, org, coll)
}

fn with_second_org(mut s: Value) -> Value {
    let key = s["profile"]["organizations"][0]["key"].clone();
    s["profile"]["organizations"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": OTHER_ORG, "name": "other", "key": key}));
    s
}

// ---- mock hub ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HubMode {
    /// Vaultwarden 1.33 behaviour.
    Normal,
    /// Websockets disabled: the route does not exist.
    NotFound,
    /// Token rejected.
    Unauthorized,
    /// Handshake, then drop the TCP connection.
    DropAfterHandshake,
    /// Handshake, then a SignalR close message `[7, nil, true]`.
    CloseMessage,
    /// Handshake, then never send anything (a dead middlebox).
    Silent,
}

struct Mock {
    sync: Value,
    syncs: usize,
    hub_mode: HubMode,
    /// After this many hub connections, switch to `Normal`.
    hub_mode_for: usize,
    hub_requests: usize,
    hub_uris: Vec<String>,
    hub_auth: Vec<Option<String>>,
    /// The client's first message on each connection.
    handshakes: Vec<String>,
}

#[derive(Clone)]
struct Server {
    state: Arc<Mutex<Mock>>,
    pushes: broadcast::Sender<Vec<u8>>,
    pings: Arc<AtomicUsize>,
    url: Url,
}

impl Server {
    fn set(&self, sync: Value) {
        self.state.lock().unwrap().sync = sync;
    }

    fn hub_mode(&self, mode: HubMode, for_connections: usize) {
        let mut st = self.state.lock().unwrap();
        st.hub_mode = mode;
        st.hub_mode_for = st.hub_requests + for_connections;
    }

    fn syncs(&self) -> usize {
        self.state.lock().unwrap().syncs
    }

    fn hub_requests(&self) -> usize {
        self.state.lock().unwrap().hub_requests
    }

    /// Push a `ReceiveMessage` of the given type to every connection.
    fn push(&self, update: i64) {
        self.pushes.send(update_frame(update)).unwrap();
    }
}

async fn serve(sync: Value) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let server = Server {
        state: Arc::new(Mutex::new(Mock {
            sync,
            syncs: 0,
            hub_mode: HubMode::Normal,
            hub_mode_for: 0,
            hub_requests: 0,
            hub_uris: vec![],
            hub_auth: vec![],
            handshakes: vec![],
        })),
        pushes: broadcast::channel(16).0,
        pings: Arc::new(AtomicUsize::new(0)),
        url,
    };
    let manifest = load("fixture.json");
    let srv = server.clone();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let srv = srv.clone();
            let manifest = manifest.clone();
            tokio::spawn(async move {
                if is_hub_request(&sock).await {
                    hub_session(sock, srv).await;
                } else {
                    http_session(sock, &manifest, &srv.state).await;
                }
            });
        }
    });
    server
}

async fn is_hub_request(sock: &TcpStream) -> bool {
    let want = b"GET /notifications/hub";
    let mut buf = [0u8; 32];
    for _ in 0..200 {
        match sock.peek(&mut buf).await {
            Ok(n) if n >= want.len() => return buf.starts_with(want),
            Ok(0) | Err(_) => return false,
            Ok(_) => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    }
    false
}

// The callback type is fixed by tungstenite's `Callback` trait.
#[allow(clippy::result_large_err)]
async fn hub_session(sock: TcpStream, srv: Server) {
    let mode = {
        let mut st = srv.state.lock().unwrap();
        st.hub_requests += 1;
        if st.hub_requests > st.hub_mode_for {
            st.hub_mode = HubMode::Normal;
        }
        st.hub_mode
    };
    let state = srv.state.clone();
    let callback = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let mut st = state.lock().unwrap();
        st.hub_uris.push(req.uri().to_string());
        let auth = req
            .headers()
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_owned());
        st.hub_auth.push(auth.clone());
        let status = match mode {
            HubMode::NotFound => 404,
            HubMode::Unauthorized => 401,
            // Vaultwarden: 401 unless the bearer token decodes.
            _ if auth.as_deref() != Some(&format!("Bearer {ACCESS_TOKEN}")) => 401,
            _ => return Ok(resp),
        };
        let mut e = ErrorResponse::new(None);
        *e.status_mut() =
            tokio_tungstenite::tungstenite::http::StatusCode::from_u16(status).unwrap();
        Err(e)
    };
    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(sock, callback).await else {
        return;
    };
    // Subscribe before answering, so a push sent after the client
    // reports Connected is never missed.
    let mut pushes = srv.pushes.subscribe();
    let Some(Ok(Message::Text(hello))) = ws.next().await else {
        return;
    };
    srv.state.lock().unwrap().handshakes.push(hello.clone());
    if !hello.starts_with("{\"protocol\":\"messagepack\",\"version\":1}") {
        return;
    }
    // Vaultwarden's INITIAL_RESPONSE, sent as a binary frame.
    if ws
        .send(Message::Binary(vec![0x7b, 0x7d, 0x1e]))
        .await
        .is_err()
    {
        return;
    }
    match mode {
        HubMode::DropAfterHandshake => return,
        HubMode::CloseMessage => {
            // VarInt(4) ‖ [7, nil, true]
            let _ = ws.send(Message::Binary(vec![4, 0x93, 7, 0xc0, 0xc3])).await;
            let _ = timeout(Duration::from_secs(5), ws.next()).await;
            return;
        }
        _ => {}
    }
    let silent = mode == HubMode::Silent;
    loop {
        tokio::select! {
            m = ws.next() => match m {
                Some(Ok(Message::Binary(b))) => {
                    if b == [0x02, 0x91, 0x06] {
                        srv.pings.fetch_add(1, Ordering::SeqCst);
                    }
                    // Vaultwarden echoes binary frames back.
                    if !silent && ws.send(Message::Binary(b)).await.is_err() {
                        return;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            },
            p = pushes.recv() => {
                let Ok(frame) = p else { return };
                if !silent && ws.send(Message::Binary(frame)).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Vaultwarden 1.33 `create_update` frame: `VarInt(len) ‖ [1, {}, nil,
/// "ReceiveMessage", [{ContextId, Type, Payload}]]`, with a msgpack
/// timestamp extension in the payload as Vaultwarden sends.
fn update_frame(update: i64) -> Vec<u8> {
    let mut m = vec![0x95, 0x01, 0x80, 0xc0];
    str_into(&mut m, "ReceiveMessage");
    m.extend([0x91, 0x83]);
    str_into(&mut m, "ContextId");
    m.push(0xc0);
    str_into(&mut m, "Type");
    m.push(update as u8);
    str_into(&mut m, "Payload");
    m.push(0x82);
    str_into(&mut m, "Id");
    str_into(&mut m, NEW_ITEM);
    str_into(&mut m, "RevisionDate");
    m.extend([0xd7, 0xff]);
    m.extend(0x0000_0001_6543_2100u64.to_be_bytes());
    assert!(m.len() < 128);
    let mut f = vec![m.len() as u8];
    f.extend(m);
    f
}

fn str_into(out: &mut Vec<u8>, s: &str) {
    assert!(s.len() < 256);
    if s.len() < 32 {
        out.push(0xa0 | s.len() as u8);
    } else {
        out.extend([0xd9, s.len() as u8]);
    }
    out.extend(s.as_bytes());
}

// ---- mock HTTP API ----

async fn http_session(mut sock: TcpStream, manifest: &Value, state: &Mutex<Mock>) {
    while let Some((method, path, body)) = read_req(&mut sock).await {
        let (status, body) = respond(&method, &path, &body, manifest, state);
        let resp = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        if sock.write_all(resp.as_bytes()).await.is_err() {
            return;
        }
    }
}

fn respond(
    method: &str,
    path: &str,
    body: &str,
    manifest: &Value,
    state: &Mutex<Mock>,
) -> (u16, String) {
    let acct = &manifest["account"];
    match (method, path) {
        ("POST", "/identity/accounts/prelogin") => (
            200,
            json!({"kdf": acct["kdf"], "kdfIterations": acct["kdf_iterations"],
                   "kdfMemory": null, "kdfParallelism": null})
            .to_string(),
        ),
        ("POST", "/identity/connect/token") if body.contains(CLIENT_SECRET) => (
            200,
            json!({"access_token": ACCESS_TOKEN, "expires_in": 7200,
                   "token_type": "Bearer", "scope": "api"})
            .to_string(),
        ),
        ("GET", p) if p.starts_with("/api/sync") => {
            let mut st = state.lock().unwrap();
            st.syncs += 1;
            (200, st.sync.to_string())
        }
        _ => (404, "{}".into()),
    }
}

async fn read_req(sock: &mut TcpStream) -> Option<(String, String, String)> {
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
    let len: usize = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.trim().parse().unwrap())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string();
    Some((method, path, body))
}

// ---- helpers ----

fn client(server: &Server) -> SyncClient {
    let email = load("fixture.json")["account"]["email"]
        .as_str()
        .unwrap()
        .to_owned();
    let key = ApiKey::new(CLIENT_ID, Zeroizing::new(CLIENT_SECRET.to_owned())).unwrap();
    SyncClient::new(&server.url, &email, key, &TlsTrust::default()).unwrap()
}

fn password() -> Zeroizing<String> {
    Zeroizing::new(
        load("fixture.json")["account"]["password"]
            .as_str()
            .unwrap()
            .to_owned(),
    )
}

/// Polling slow enough (the 5-minute default) that only push can
/// explain a change landing within the test deadline.
async fn unlocked(sync: Value) -> (Server, LiveSync) {
    unlocked_with(sync, SyncPolicy::default()).await
}

async fn unlocked_with(sync: Value, policy: SyncPolicy) -> (Server, LiveSync) {
    let (_, org, coll) = fixture();
    let server = serve(sync).await;
    let live = LiveSync::unlock(
        client(&server),
        &password(),
        Scope::new(&org, [&coll]).unwrap(),
        policy,
    )
    .await
    .unwrap();
    (server, live)
}

fn fast() -> HubTiming {
    HubTiming {
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(5),
        ping_interval: Duration::from_secs(5),
        server_timeout: Duration::from_secs(20),
        backoff_base: Duration::from_millis(20),
        backoff_max: Duration::from_millis(200),
        unsupported_retry: Duration::from_millis(300),
        stable_after: Duration::from_secs(30),
    }
}

type Statuses = mpsc::UnboundedReceiver<HubStatus>;

/// Spawn the push task; statuses go to the returned receiver.
fn spawn_push(
    hub: NotificationsHub,
    nudge: mpsc::Sender<()>,
) -> (tokio::task::JoinHandle<()>, Statuses) {
    let (st_tx, st_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run_push(hub, nudge, move |s| {
        let _ = st_tx.send(s.clone());
    }));
    (task, st_rx)
}

/// Wait for a status matching `want`, returning everything seen.
async fn wait_status(rx: &mut Statuses, want: impl Fn(&HubStatus) -> bool) -> Vec<HubStatus> {
    let mut seen = Vec::new();
    let r = timeout(PUSH_DEADLINE, async {
        while let Some(s) = rx.recv().await {
            let hit = want(&s);
            seen.push(s);
            if hit {
                return;
            }
        }
    })
    .await;
    assert!(r.is_ok(), "status not reached; saw {seen:?}");
    seen
}

async fn nudged(rx: &mut mpsc::Receiver<()>) {
    timeout(PUSH_DEADLINE, rx.recv())
        .await
        .expect("no nudge within 10 s")
        .expect("push task gone");
}

fn drain(rx: &mut mpsc::Receiver<()>) {
    while rx.try_recv().is_ok() {}
}

// ---- tests ----

#[tokio::test]
async fn req_cry_009_push_reflects_add_edit_delete_within_seconds() {
    let (s, _, _) = fixture();
    let (server, mut live) = unlocked(s.clone()).await;
    let first = s["ciphers"][0]["id"].as_str().unwrap().to_owned();
    let second = s["ciphers"][1]["id"].as_str().unwrap().to_owned();
    let (tx, mut rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(live.notifications_hub().with_timing(fast()), tx);
    wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    // The connect-time catch-up nudge.
    nudged(&mut rx).await;
    live.sync_now().await.unwrap();

    // Add.
    let mut added = s.clone();
    let mut c = s["ciphers"][0].clone();
    c["id"] = json!(NEW_ITEM);
    added["ciphers"].as_array_mut().unwrap().push(c);
    server.set(added.clone());
    server.push(1); // SyncCipherCreate
    let t0 = tokio::time::Instant::now();
    nudged(&mut rx).await;
    assert!(matches!(
        live.sync_now().await.unwrap(),
        SyncOutcome::Synced
    ));
    assert!(live.vault().get(NEW_ITEM).is_ok());

    // Edit.
    let mut edited = added.clone();
    edited["ciphers"][0]["revisionDate"] = json!("2026-11-02T12:00:00Z");
    server.set(edited.clone());
    server.push(0); // SyncCipherUpdate
    nudged(&mut rx).await;
    live.sync_now().await.unwrap();
    assert_eq!(
        live.vault().get(&first).unwrap().revision(),
        Some("2026-11-02T12:00:00Z")
    );

    // Delete (Vaultwarden sends SyncLoginDelete for a hard delete).
    let mut deleted = edited;
    deleted["ciphers"]
        .as_array_mut()
        .unwrap()
        .retain(|c| c["id"] != json!(second));
    server.set(deleted);
    server.push(2);
    nudged(&mut rx).await;
    live.sync_now().await.unwrap();
    assert!(live.vault().get(&second).is_err());
    assert!(t0.elapsed() < PUSH_DEADLINE, "{:?}", t0.elapsed());

    // Irrelevant updates (settings, sends, auth requests) do not nudge.
    for t in [10, 12, 15, 16] {
        server.push(t);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err());
    let mut pushed = Vec::new();
    while let Ok(s) = st.try_recv() {
        if let HubStatus::Push(t) = s {
            pushed.push(t.0);
        }
    }
    assert_eq!(pushed, vec![1, 0, 2]);
}

#[tokio::test]
async fn req_cry_009_push_with_run_loop_second_org_locks_scope_widened() {
    // REQ-CRY-008 via push: the account is added to a second org while
    // unlocked; Vaultwarden pushes SyncOrgKeys; the sync loop syncs at
    // once (not at the 5-minute poll) and locks.
    let (s, _, _) = fixture();
    let (server, mut live) = unlocked(s.clone()).await;
    let (tx, rx) = mpsc::channel(1);
    let (task, mut st) = spawn_push(live.notifications_hub().with_timing(fast()), tx);
    wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    let srv = server.clone();
    let widen = tokio::spawn(async move {
        // Let the catch-up sync (unlock + 1) finish on the old payload.
        while srv.syncs() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        srv.set(with_second_org(s));
        srv.push(6); // SyncOrgKeys
    });
    let t0 = tokio::time::Instant::now();
    let reason = timeout(PUSH_DEADLINE, run(&mut live, rx, |_| {}))
        .await
        .expect("push must trigger the sync, not the 5-minute poll");
    widen.await.unwrap();
    assert!(t0.elapsed() < PUSH_DEADLINE);
    let LockReason::ScopeWidened(v) = &reason else {
        panic!("{reason:?}");
    };
    assert_eq!(v.other_orgs, vec![OTHER_ORG]);
    assert_eq!(reason.audit_event(), Event::ScopeWidened);
    // Lock = drop the session; the push task follows it down.
    drop(live);
    wait_status(&mut st, |s| *s == HubStatus::Stopped).await;
    timeout(PUSH_DEADLINE, task).await.unwrap().unwrap();
}

#[tokio::test]
async fn req_cry_009_token_sent_as_bearer_header_never_in_url() {
    let (s, _, _) = fixture();
    let (server, live) = unlocked(s).await;
    let hub = live.notifications_hub().with_timing(fast());
    assert_eq!(hub.url().path(), "/notifications/hub");
    assert_eq!(hub.url().scheme(), "ws");
    assert!(!format!("{hub:?}").contains(ACCESS_TOKEN));
    let (tx, _rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(hub, tx);
    let seen = wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    assert!(!format!("{seen:?}").contains(ACCESS_TOKEN));
    let state = server.state.lock().unwrap();
    assert_eq!(state.hub_uris, vec!["/notifications/hub".to_owned()]);
    assert_eq!(state.hub_auth, vec![Some(format!("Bearer {ACCESS_TOKEN}"))]);
    assert_eq!(
        state.handshakes,
        vec!["{\"protocol\":\"messagepack\",\"version\":1}\u{1e}".to_owned()]
    );
}

#[tokio::test]
async fn req_cry_009_hub_unsupported_falls_back_to_polling() {
    let (s, _, _) = fixture();
    // Fast polling stands in for the 5-minute floor.
    let (server, mut live) =
        unlocked_with(s.clone(), SyncPolicy::new(false, Duration::from_millis(50))).await;
    server.hub_mode(HubMode::NotFound, usize::MAX);
    let (tx, rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(live.notifications_hub().with_timing(fast()), tx);
    let srv = server.clone();
    let widen = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        srv.set(with_second_org(s));
    });
    let reason = timeout(PUSH_DEADLINE, run(&mut live, rx, |_| {}))
        .await
        .expect("polling must still run without the hub");
    widen.await.unwrap();
    assert!(matches!(reason, LockReason::ScopeWidened(_)));
    let seen = wait_status(&mut st, |s| matches!(s, HubStatus::Retrying(_))).await;
    assert!(
        seen.contains(&HubStatus::Unsupported { status: 404 }),
        "{seen:?}"
    );
    assert!(
        seen.contains(&HubStatus::Retrying(fast().unsupported_retry)),
        "{seen:?}"
    );
    // ~400 ms at one attempt per 300 ms: no hammering.
    assert!(server.hub_requests() <= 4, "{}", server.hub_requests());
    assert!(!seen.contains(&HubStatus::Connected));
}

#[tokio::test]
async fn req_cry_009_hub_coming_back_reconnects() {
    let (s, _, _) = fixture();
    let (server, live) = unlocked(s).await;
    server.hub_mode(HubMode::NotFound, 2);
    let (tx, _rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(live.notifications_hub().with_timing(fast()), tx);
    let seen = wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    let unsupported = seen
        .iter()
        .filter(|s| matches!(s, HubStatus::Unsupported { status: 404 }))
        .count();
    assert_eq!(unsupported, 2, "{seen:?}");
    assert_eq!(server.hub_requests(), 3);
}

#[tokio::test]
async fn req_cry_009_reconnects_with_backoff_and_catch_up_sync() {
    let (s, _, _) = fixture();
    let (server, live) = unlocked(s).await;
    server.hub_mode(HubMode::DropAfterHandshake, 3);
    let (tx, mut rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(live.notifications_hub().with_timing(fast()), tx);
    let mut connects = 0;
    let mut delays = Vec::new();
    while connects < 4 {
        for s in wait_status(&mut st, |s| *s == HubStatus::Connected).await {
            match s {
                HubStatus::Connected => connects += 1,
                HubStatus::Retrying(d) => delays.push(d),
                _ => {}
            }
        }
        // Every (re)connect asks for a catch-up sync.
        nudged(&mut rx).await;
    }
    assert_eq!(delays.len(), 3, "{delays:?}");
    // Jittered exponential: within [c/2, c] for c = 20, 40, 80 ms.
    for (d, c) in delays.iter().zip([20u64, 40, 80]) {
        let c = Duration::from_millis(c);
        assert!(*d >= c / 2 && *d <= c, "{d:?} vs {c:?}");
    }
    // Healthy now: a push still gets through.
    drain(&mut rx);
    server.push(5); // SyncVault
    nudged(&mut rx).await;
}

#[tokio::test]
async fn req_cry_009_signalr_close_message_reconnects() {
    let (s, _, _) = fixture();
    let (server, live) = unlocked(s).await;
    server.hub_mode(HubMode::CloseMessage, 1);
    let (tx, _rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(live.notifications_hub().with_timing(fast()), tx);
    wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    let seen = wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    assert!(
        seen.contains(&HubStatus::Disconnected(HubError::ServerClose)),
        "{seen:?}"
    );
}

#[tokio::test]
async fn req_cry_009_keepalive_pings_and_dead_connection_timeout() {
    let (s, _, _) = fixture();
    let (server, live) = unlocked(s).await;
    server.hub_mode(HubMode::Silent, 1);
    let timing = HubTiming {
        ping_interval: Duration::from_millis(50),
        server_timeout: Duration::from_millis(400),
        ..fast()
    };
    let (tx, _rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(live.notifications_hub().with_timing(timing), tx);
    wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    let seen = wait_status(&mut st, |s| matches!(s, HubStatus::Disconnected(_))).await;
    assert_eq!(
        seen.last(),
        Some(&HubStatus::Disconnected(HubError::Timeout))
    );
    assert!(server.pings.load(Ordering::SeqCst) >= 3);
    // And it comes back on a healthy server.
    wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    // Echoed pings count as traffic: no timeout while healthy.
    tokio::time::sleep(Duration::from_millis(800)).await;
    while let Ok(s) = st.try_recv() {
        assert!(!matches!(s, HubStatus::Disconnected(_)), "{s:?}");
    }
}

#[tokio::test]
async fn req_cry_009_rejected_token_nudges_a_relogin_sync() {
    let (s, _, _) = fixture();
    let (server, live) = unlocked(s).await;
    server.hub_mode(HubMode::Unauthorized, 1);
    let (tx, mut rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(live.notifications_hub().with_timing(fast()), tx);
    let seen = wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    assert_eq!(
        seen.first(),
        Some(&HubStatus::Disconnected(HubError::Status(401)))
    );
    nudged(&mut rx).await;
}

#[tokio::test]
async fn req_cry_009_waits_for_login_before_connecting() {
    let (s, _, _) = fixture();
    let server = serve(s).await;
    let mut c = client(&server);
    let (tx, mut rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(c.notifications_hub().with_timing(fast()), tx);
    wait_status(&mut st, |s| *s == HubStatus::WaitingForToken).await;
    // It asked the sync loop to log in, and has not tried the hub.
    nudged(&mut rx).await;
    assert_eq!(server.hub_requests(), 0);
    c.sync().await.unwrap();
    wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    // forget_token (re-login path) ends the session; dropping the
    // client (the lock) stops the task.
    c.forget_token();
    wait_status(&mut st, |s| {
        *s == HubStatus::Disconnected(HubError::TokenGone)
    })
    .await;
    drop(c);
    wait_status(&mut st, |s| *s == HubStatus::Stopped).await;
}

#[tokio::test]
async fn req_cry_009_stops_when_sync_loop_stops_listening() {
    let (s, _, _) = fixture();
    let (_server, live) = unlocked(s).await;
    let (tx, rx) = mpsc::channel(1);
    let (task, mut st) = spawn_push(live.notifications_hub().with_timing(fast()), tx);
    wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    drop(rx);
    wait_status(&mut st, |s| *s == HubStatus::Stopped).await;
    timeout(PUSH_DEADLINE, task).await.unwrap().unwrap();
}

#[test]
fn req_cry_009_poll_floor_unchanged() {
    // Push is an accelerator; the poll floor stays the spec's 5 min.
    assert_eq!(MAX_SYNC_INTERVAL, Duration::from_secs(300));
    assert_eq!(HubTiming::default().unsupported_retry, MAX_SYNC_INTERVAL);
}

// ---- live: real Vaultwarden 1.33 (fixture.yml) ----

struct Live {
    live: LiveSync,
}

async fn live_session() -> Live {
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
    let email = load("fixture.json")["account"]["email"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut c = SyncClient::new(&base, &email, key, &trust).unwrap();
    let raw = c.sync().await.unwrap();
    let org = raw.profile.organizations.as_ref().unwrap()[0].id.clone();
    let coll = raw.collections.as_ref().unwrap()[0].id.clone();
    // Default policy: the 5-minute poll never fires during the test,
    // so every change below can only arrive by push.
    let live = LiveSync::unlock(
        c,
        &password(),
        Scope::new(&org, [&coll]).unwrap(),
        SyncPolicy::default(),
    )
    .await
    .unwrap();
    Live { live }
}

/// Run `mutate.py <args>` against the live fixture (as a web-vault
/// user would edit), returning the cipher id it reports.
async fn mutate(args: &[&str]) -> String {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("python3")
            .arg(format!("{FIXTURE_DIR}/mutate.py"))
            .args(&args)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "mutate.py failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    v["id"].as_str().unwrap().to_owned()
}

/// Push E2E (REQ-CRY-009 AC): add, edit, delete in the "web vault"
/// are reflected in the unlocked broker within 10 s, via the hub.
#[tokio::test]
#[ignore = "needs the live Vaultwarden fixture (fixture.yml)"]
async fn req_cry_009_live_push_reflects_add_edit_delete_within_10s() {
    let Live { mut live } = live_session().await;
    let (tx, mut rx) = mpsc::channel(1);
    let (_task, mut st) = spawn_push(live.notifications_hub(), tx);
    let seen = wait_status(&mut st, |s| *s == HubStatus::Connected).await;
    assert!(
        !seen
            .iter()
            .any(|s| matches!(s, HubStatus::Unsupported { .. })),
        "{seen:?}"
    );
    nudged(&mut rx).await; // catch-up
    live.sync_now().await.unwrap();
    let before = live.vault().len();

    let t0 = tokio::time::Instant::now();
    let id = mutate(&["add", "--name", "kharon push added"]).await;
    nudged(&mut rx).await;
    live.sync_now().await.unwrap();
    assert_eq!(live.vault().get(&id).unwrap().name(), "kharon push added");
    assert_eq!(live.vault().len(), before + 1);
    assert!(t0.elapsed() < PUSH_DEADLINE, "add: {:?}", t0.elapsed());

    drain(&mut rx);
    let t0 = tokio::time::Instant::now();
    mutate(&["edit", "--id", &id, "--name", "kharon push edited"]).await;
    nudged(&mut rx).await;
    live.sync_now().await.unwrap();
    assert_eq!(live.vault().get(&id).unwrap().name(), "kharon push edited");
    assert!(t0.elapsed() < PUSH_DEADLINE, "edit: {:?}", t0.elapsed());

    drain(&mut rx);
    let t0 = tokio::time::Instant::now();
    mutate(&["delete", "--id", &id]).await;
    nudged(&mut rx).await;
    live.sync_now().await.unwrap();
    assert!(live.vault().get(&id).is_err());
    assert_eq!(live.vault().len(), before);
    assert!(t0.elapsed() < PUSH_DEADLINE, "delete: {:?}", t0.elapsed());

    let pushes: Vec<_> = std::iter::from_fn(|| st.try_recv().ok())
        .filter_map(|s| match s {
            HubStatus::Push(t) => Some(t),
            _ => None,
        })
        .collect();
    for t in [
        UpdateType::SYNC_CIPHER_CREATE,
        UpdateType::SYNC_CIPHER_UPDATE,
        UpdateType::SYNC_CIPHER_DELETE,
    ] {
        assert!(pushes.contains(&t), "{t:?} not pushed: {pushes:?}");
    }
}

/// REQ-CRY-008 live: the account gains a second org while unlocked;
/// the next sync locks with ScopeWidened. Irreversible for the shared
/// fixture, so `fixture.yml` runs it last, alone (`--exact`).
#[tokio::test]
#[ignore = "needs the live Vaultwarden fixture (fixture.yml); widens the fixture, run last"]
async fn req_cry_008_live_second_org_while_unlocked_locks() {
    let Live { mut live } = live_session().await;
    let before = live.vault().len();
    mutate(&["add-org"]).await;
    let SyncOutcome::Lock(reason) = live.sync_now().await.unwrap() else {
        panic!("a second org must lock");
    };
    let LockReason::ScopeWidened(v) = &reason else {
        panic!("{reason:?}");
    };
    assert_eq!(v.other_orgs.len(), 1);
    assert_eq!(reason.audit_event(), Event::ScopeWidened);
    assert_eq!(live.vault().len(), before);
}
