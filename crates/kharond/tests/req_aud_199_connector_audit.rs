//! #199: `connector_auth_fail` and `connector_replaced` audit entries,
//! rate-limited to one per agent per 60 s per kind. Both are best effort:
//! a failed append never changes the auth result or the eviction.

mod api_support;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use api_support::Harness;
use argon2::Argon2;
use kharon_connector::Transport as Dial;
use kharond::api::token::{ParamFloor, TUNNEL_PREFIX, TokenStore, generate_tunnel_with};
use kharond::audit::{
    AuditConfig, AuditKeys, AuditLog, Entry, Event, NullCheckpointSink, VerifyOutcome, verify,
};
use kharond::connector::{
    AgentParams, ConnectorAudit, Hub, SessionTransport, WsEntry, accept, pin_of_der,
    run_agent_once, server_config_from_pem,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const FLOOR: ParamFloor = ParamFloor {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

fn argon() -> Argon2<'static> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(8, 1, 1, None).unwrap(),
    )
}

fn store() -> (TokenStore, String) {
    let (secret, hash) = generate_tunnel_with(&argon(), "assistant");
    let store =
        TokenStore::with_floor_and_prefix([("assistant", hash.as_str())], &FLOOR, TUNNEL_PREFIX)
            .unwrap();
    (store, secret.expose_secret().clone())
}

/// A well-formed tunnel credential that is not `assistant`'s.
fn wrong_token() -> String {
    generate_tunnel_with(&argon(), "assistant")
        .0
        .expose_secret()
        .clone()
}

/// Collects every entry the hub sends. `fail` makes each append fail.
#[derive(Clone, Default)]
struct Sink {
    entries: Arc<Mutex<Vec<Entry>>>,
    fail: bool,
}

impl Sink {
    fn audit(&self) -> ConnectorAudit {
        let entries = Arc::clone(&self.entries);
        let fail = self.fail;
        Arc::new(move |e| {
            if fail {
                return Err(());
            }
            entries.lock().unwrap().push(e);
            Ok(())
        })
    }

    fn all(&self) -> Vec<Entry> {
        self.entries.lock().unwrap().clone()
    }

    fn of(&self, event: Event) -> Vec<Entry> {
        self.all()
            .into_iter()
            .filter(|e| e.event == event)
            .collect()
    }
}

struct Rig {
    hub: Arc<Hub>,
    token: String,
    pin: [u8; 32],
    raw: SocketAddr,
    public: SocketAddr,
    _harness: Harness,
}

async fn rig_with(sink: &ConnectorAudit) -> Rig {
    let (store, token) = store();
    let hub = Arc::new(Hub::with_events(store, Arc::new(|_| {})));
    hub.set_audit(Arc::clone(sink));
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let (pem_cert, pem_key) = (cert.pem(), key_pair.serialize_pem());

    let raw_tls = server_config_from_pem(pem_cert.as_bytes(), pem_key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw = listener.local_addr().unwrap();
    let raw_hub = Arc::clone(&hub);
    tokio::spawn(async move { accept(listener, raw_tls, raw_hub).await });

    let ws_tls = kharon_connector::server_config_from_pem_with(
        pem_cert.as_bytes(),
        pem_key.as_bytes(),
        kharon_connector::TlsVersions::Tls13Only,
    )
    .unwrap();
    let ws = WsEntry::new(Arc::clone(&hub), ws_tls);
    let harness = Harness::new(false);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::public::serve_with_shutdown(
        listener,
        harness.broker.clone(),
        Some(ws),
        None,
        Arc::<[std::net::IpAddr]>::from([]),
        std::future::pending(),
    ));
    Rig {
        hub,
        token,
        pin: pin_of_der(cert.der()),
        raw,
        public,
        _harness: harness,
    }
}

fn dial(rig: &Rig, transport: SessionTransport, agent: &str, token: &str) -> AgentParams {
    let transport = match transport {
        SessionTransport::Tls => Dial::Tls {
            broker: rig.raw,
            host: None,
        },
        SessionTransport::Ws => Dial::Ws {
            host: "127.0.0.1".into(),
            port: rig.public.port(),
            path: "/connector".into(),
            outer_tls: false,
        },
    };
    AgentParams {
        transport,
        server_name: "127.0.0.1".into(),
        pin: rig.pin,
        agent_id: agent.into(),
        token: Zeroizing::new(token.to_owned()),
        cdp: "127.0.0.1:9".parse().unwrap(),
        proxy: None,
        proxy_creds: None,
        outer_roots: None,
    }
}

/// One dial that is expected to be refused; returns when the agent is told.
async fn refused(rig: &Rig, transport: SessionTransport, agent: &str, token: &str) {
    let params = dial(rig, transport, agent, token);
    let r = tokio::time::timeout(Duration::from_secs(10), run_agent_once(&params))
        .await
        .expect("refusal timed out");
    assert!(r.is_err(), "the dial must be refused");
}

async fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !ok() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Attach `assistant` over `transport`; returns the agent task.
async fn attach(rig: &Rig, transport: SessionTransport) -> tokio::task::JoinHandle<()> {
    let params = dial(rig, transport, "assistant", &rig.token);
    let task = tokio::spawn(async move {
        let _ = run_agent_once(&params).await;
    });
    eventually("attach", || rig.hub.is_connected("assistant")).await;
    task
}

/// The window rule, on the paused tokio clock: the first event writes with
/// `suppressed = 0`, later ones inside 60 s only count, and the first one
/// after the window writes the count and starts a new window.
#[tokio::test(start_paused = true)]
async fn refused_configured_agent_writes_one_entry_per_minute() {
    let sink = Sink::default();
    let (store, _) = store();
    let hub = Hub::with_events(store, Arc::new(|_| {}));
    hub.set_audit(sink.audit());
    let fail = |hub: &Hub| hub.audit_auth_fail("assistant", SessionTransport::Tls);

    fail(&hub);
    fail(&hub);
    fail(&hub);
    let first = sink.of(Event::ConnectorAuthFail);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].agent_id.as_deref(), Some("assistant"));
    assert_eq!(first[0].transport, Some(SessionTransport::Tls));
    assert_eq!(first[0].detail_code.as_deref(), Some("unauthorized"));
    assert_eq!(first[0].suppressed, Some(0));

    tokio::time::advance(Duration::from_secs(59)).await;
    fail(&hub);
    assert_eq!(
        sink.of(Event::ConnectorAuthFail).len(),
        1,
        "still inside the window"
    );

    tokio::time::advance(Duration::from_secs(2)).await;
    hub.audit_auth_fail("assistant", SessionTransport::Ws);
    let all = sink.of(Event::ConnectorAuthFail);
    assert_eq!(all.len(), 2);
    assert_eq!(
        all[1].suppressed,
        Some(3),
        "two + one dropped, then this one writes"
    );
    assert_eq!(all[1].transport, Some(SessionTransport::Ws));
    assert_eq!(all[1].detail_code.as_deref(), Some("unauthorized"));

    // A new window: the counter restarted.
    tokio::time::advance(Duration::from_secs(61)).await;
    fail(&hub);
    assert_eq!(sink.of(Event::ConnectorAuthFail)[2].suppressed, Some(0));

    // Exactly 60 s after the window start: one tick short is inside,
    // the boundary itself opens a new window.
    tokio::time::advance(Duration::from_millis(59_999)).await;
    fail(&hub);
    assert_eq!(sink.of(Event::ConnectorAuthFail).len(), 3);
    tokio::time::advance(Duration::from_millis(1)).await;
    fail(&hub);
    let all = sink.of(Event::ConnectorAuthFail);
    assert_eq!(all.len(), 4);
    assert_eq!(all[3].suppressed, Some(1));
}

/// Each transport gets a fresh hub, so a refusal over it is the only
/// thing that can have written the entry.
#[tokio::test(flavor = "multi_thread")]
async fn refused_over_raw_and_ws_is_audited_with_transport() {
    for (transport, name) in [(SessionTransport::Tls, "tls"), (SessionTransport::Ws, "ws")] {
        let sink = Sink::default();
        let rig = rig_with(&sink.audit()).await;
        refused(&rig, transport, "assistant", &wrong_token()).await;
        let got = sink.of(Event::ConnectorAuthFail);
        assert_eq!(got.len(), 1, "{name}: written before the agent is told");
        assert_eq!(
            got[0].transport.map(|t| t.to_string()).as_deref(),
            Some(name)
        );
        assert_eq!(got[0].detail_code.as_deref(), Some("unauthorized"));
        assert_eq!(got[0].agent_id.as_deref(), Some("assistant"));
        assert_eq!(got[0].suppressed, Some(0));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_unknown_agent_writes_none() {
    let sink = Sink::default();
    let rig = rig_with(&sink.audit()).await;
    // A valid credential for `assistant`, claimed as someone else.
    refused(&rig, SessionTransport::Tls, "ghost", &rig.token).await;
    refused(&rig, SessionTransport::Ws, "ghost", &wrong_token()).await;
    rig.hub.audit_auth_fail("ghost", SessionTransport::Tls);
    assert!(sink.all().is_empty(), "{:?}", sink.all());
}

#[tokio::test(flavor = "multi_thread")]
async fn replace_writes_connector_replaced_with_age_and_transport() {
    let sink = Sink::default();
    let rig = rig_with(&sink.audit()).await;
    let started = tokio::time::Instant::now();
    let raw = attach(&rig, SessionTransport::Tls).await;
    assert!(
        sink.of(Event::ConnectorReplaced).is_empty(),
        "no eviction yet"
    );
    eventually("old session is a second old", || {
        started.elapsed() >= Duration::from_millis(1100)
    })
    .await;

    let ws = attach(&rig, SessionTransport::Ws).await;
    eventually("replaced entry", || {
        !sink.of(Event::ConnectorReplaced).is_empty()
    })
    .await;
    let got = sink.of(Event::ConnectorReplaced);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].agent_id.as_deref(), Some("assistant"));
    assert_eq!(
        got[0].transport,
        Some(SessionTransport::Ws),
        "the new session's"
    );
    assert_eq!(got[0].suppressed, Some(0));
    let age = got[0].old_session_secs.expect("old_session_secs");
    assert!((1..=3).contains(&age), "age {age}");

    // Back to raw inside the window: the eviction happens, no new entry.
    let raw2 = attach(&rig, SessionTransport::Tls).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), ws).await;
    assert_eq!(sink.of(Event::ConnectorReplaced).len(), 1);
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(5), raw).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), raw2).await;
}

/// Real log on disk: the tunnel credential (the accepted one and a refused
/// one) is in none of its bytes, and the chain verifies with the new events.
#[tokio::test(flavor = "multi_thread")]
async fn audit_entries_never_hold_the_credential() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Mutex::new(
        AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap(),
    ));
    let writer = Arc::clone(&log);
    let audit: ConnectorAudit = Arc::new(move |e| writer.lock().unwrap().append(e).map_err(|_| ()));
    let rig = rig_with(&audit).await;
    let bad = wrong_token();

    refused(&rig, SessionTransport::Tls, "assistant", &bad).await;
    let a = attach(&rig, SessionTransport::Tls).await;
    let b = attach(&rig, SessionTransport::Ws).await;
    eventually("two entries", || log.lock().unwrap().head_seq() >= 2).await;
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(5), a).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), b).await;

    let path = dir.path().join("audit.jsonl");
    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("connector_auth_fail") && text.contains("connector_replaced"));
    for secret in [
        &rig.token,
        &bad,
        &rig.token[TUNNEL_PREFIX.len()..].to_owned(),
    ] {
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "the credential is in the audit log"
        );
    }
    let keys = AuditKeys::load_or_generate(&dir.path().join("keys")).unwrap();
    assert!(matches!(
        verify(&path, &[], &keys.verifying_key()).unwrap(),
        VerifyOutcome::Ok { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_append_failure_does_not_block_auth() {
    let sink = Sink {
        fail: true,
        ..Sink::default()
    };
    let rig = rig_with(&sink.audit()).await;

    // Still refused, still told so.
    refused(&rig, SessionTransport::Tls, "assistant", &wrong_token()).await;
    // Still accepted, and a second session still evicts the first.
    let first = attach(&rig, SessionTransport::Tls).await;
    let second = attach(&rig, SessionTransport::Ws).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .expect("the evicted session kept its socket");
    assert!(rig.hub.is_connected("assistant"));
    assert!(sink.all().is_empty());
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(5), second).await;
}

// ---- #219: suppressed counts are flushed, not left in memory ----------

/// A closed window with swallowed events writes one summary entry on the
/// flush, and the next event opens a fresh window with `suppressed = 0`.
#[tokio::test(start_paused = true)]
async fn flush_writes_a_summary_for_a_closed_window() {
    let sink = Sink::default();
    let (store, _) = store();
    let hub = Hub::with_events(store, Arc::new(|_| {}));
    hub.set_audit(sink.audit());
    let fail = |hub: &Hub| hub.audit_auth_fail("assistant", SessionTransport::Tls);
    let t0 = tokio::time::Instant::now();

    fail(&hub);
    tokio::time::advance(Duration::from_secs(10)).await;
    for _ in 0..3 {
        fail(&hub);
    }
    assert_eq!(sink.of(Event::ConnectorAuthFail).len(), 1);

    hub.flush_audit(t0 + Duration::from_secs(59));
    assert_eq!(sink.of(Event::ConnectorAuthFail).len(), 1, "window is open");

    hub.flush_audit(t0 + Duration::from_secs(60));
    let all = sink.of(Event::ConnectorAuthFail);
    assert_eq!(all.len(), 2);
    let summary = &all[1];
    assert_eq!(summary.suppressed, Some(3));
    assert_eq!(summary.result.as_deref(), Some("suppressed_only"));
    assert_eq!(summary.agent_id.as_deref(), Some("assistant"));
    assert_eq!(summary.transport, None);
    assert_eq!(summary.detail_code, None);

    tokio::time::advance(Duration::from_secs(61)).await;
    fail(&hub);
    let all = sink.of(Event::ConnectorAuthFail);
    assert_eq!(all.len(), 3, "the next event writes at once");
    assert_eq!(all[2].suppressed, Some(0));
    assert_eq!(all[2].result, None);
}

/// Shutdown flushes an open window's pending count.
#[tokio::test(start_paused = true)]
async fn flush_all_writes_pending_of_open_windows() {
    let sink = Sink::default();
    let (store, _) = store();
    let hub = Hub::with_events(store, Arc::new(|_| {}));
    hub.set_audit(sink.audit());
    hub.audit_auth_fail("assistant", SessionTransport::Tls);
    tokio::time::advance(Duration::from_secs(5)).await;
    hub.audit_auth_fail("assistant", SessionTransport::Tls);
    hub.audit_auth_fail("assistant", SessionTransport::Tls);

    hub.flush_audit_all();
    let all = sink.of(Event::ConnectorAuthFail);
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].suppressed, Some(2));
    assert_eq!(all[1].result.as_deref(), Some("suppressed_only"));

    hub.flush_audit_all();
    assert_eq!(
        sink.of(Event::ConnectorAuthFail).len(),
        2,
        "maps were cleared"
    );
}

/// Review Focus 5: a failing sink must not make the flush panic, and
/// leaves the maps cleared.
#[tokio::test(start_paused = true)]
async fn flush_with_failing_sink_returns() {
    let sink = Sink {
        fail: true,
        ..Sink::default()
    };
    let (store, _) = store();
    let hub = Hub::with_events(store, Arc::new(|_| {}));
    hub.set_audit(sink.audit());
    for _ in 0..3 {
        hub.audit_auth_fail("assistant", SessionTransport::Tls);
    }
    hub.flush_audit(tokio::time::Instant::now() + Duration::from_secs(60));
    hub.flush_audit_all();
    assert!(sink.all().is_empty());
}

/// The sink runs after the `limits` lock is released: a sink that calls
/// back into the hub would deadlock otherwise. Run on a thread so a hang
/// fails the test instead of stalling it.
#[test]
fn flush_does_not_hold_the_lock_across_the_sink() {
    let (store, _) = store();
    let hub = Arc::new(Hub::with_events(store, Arc::new(|_| {})));
    let inner = Arc::clone(&hub);
    let calls = Arc::new(Mutex::new(0usize));
    let seen = Arc::clone(&calls);
    hub.set_audit(Arc::new(move |_| {
        *seen.lock().unwrap() += 1;
        // Re-entrant: touches the same limiter the flush just drained.
        inner.audit_auth_fail("assistant", SessionTransport::Tls);
        Ok(())
    }));
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let runner = Arc::clone(&hub);
    std::thread::spawn(move || {
        runner.audit_auth_fail("assistant", SessionTransport::Tls);
        runner.audit_auth_fail("assistant", SessionTransport::Tls);
        runner.flush_audit(tokio::time::Instant::now() + Duration::from_secs(61));
        runner.audit_auth_fail("assistant", SessionTransport::Tls);
        runner.flush_audit_all();
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("flush deadlocked: the sink ran under the limits lock");
    assert!(*calls.lock().unwrap() >= 2);
}

/// I1 (#219 AC3): a burst, then silence, while the daemon keeps running.
/// The periodic task alone writes the summary.
#[tokio::test(start_paused = true)]
async fn housekeeping_flushes_a_burst_followed_by_silence() {
    let sink = Sink::default();
    let (store, _) = store();
    let hub = Arc::new(Hub::with_events(store, Arc::new(|_| {})));
    hub.set_audit(sink.audit());
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(kharond::daemon::connector_housekeeping(
        Arc::clone(&hub),
        None,
        stop_rx,
    ));
    for _ in 0..3 {
        hub.audit_auth_fail("assistant", SessionTransport::Tls);
    }
    assert_eq!(sink.of(Event::ConnectorAuthFail).len(), 1);

    tokio::time::sleep(Duration::from_secs(75)).await;
    // The flush runs on the blocking pool.
    for _ in 0..200 {
        if sink.of(Event::ConnectorAuthFail).len() > 1 {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(5));
    }
    let all = sink.of(Event::ConnectorAuthFail);
    assert_eq!(all.len(), 2, "exactly one summary: {all:?}");
    assert_eq!(all[1].suppressed, Some(2));
    assert_eq!(all[1].result.as_deref(), Some("suppressed_only"));
    let _ = stop.send(true);
    let _ = task.await;
}

/// Shutdown stops the housekeeping task with a signal rather than an
/// abort, so a flush already on the blocking pool finishes before the task
/// returns, and the daemon's final flush and exit checkpoint come after it.
#[tokio::test]
async fn housekeeping_returns_when_stopped() {
    let (store, _) = store();
    let hub = Arc::new(Hub::with_events(store, Arc::new(|_| {})));
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(kharond::daemon::connector_housekeeping(hub, None, stop_rx));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("housekeeping returns once stopped")
        .expect("housekeeping task did not panic");
}
