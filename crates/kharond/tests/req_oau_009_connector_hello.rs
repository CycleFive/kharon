//! REQ-OAU-009 / REQ-ARCH-002 (#235 slice 5, #308): the connector hello
//! accepts a Connect access token (`kh_at_`) of audience `connector` on
//! wire v1, over the WebSocket and raw TLS. The prefix dispatch runs
//! before any Argon2id permit; the session carries the token's expiry and
//! drops at it; refusals carry D4's audit detail codes.
//!
//! The Connect lookup is injected here: #304 adds the audience field to
//! the OAuth store, and the store side of the lookup has its own unit test
//! (`connector_access_sees_an_mcp_token_as_the_wrong_audience`).

mod api_support;
mod connector_support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use connector_support::*;
use kharon_connector::{ClientError, connect_and_auth, run_agent_once};
use kharond::audit::{Entry, Event};
use kharond::connector::{
    AgentParams, ConnectAccess, ConnectTokens, ConnectorEvent, connect_pinned,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use zeroize::Zeroizing;

const CID: &str = "c-abcdefghij";
const OTHER: &str = "c-otherother";
const GOOD: &str = "kh_at_0000000000000000000000000000000000000000000000000000000000good";
const MCP: &str = "kh_at_00000000000000000000000000000000000000000000000000000000000mcp";
const OTHERS: &str = "kh_at_000000000000000000000000000000000000000000000000000000000other";
const SHORT: &str = "kh_at_000000000000000000000000000000000000000000000000000000000short";
const REFRESH: &str = "kh_rt_0000000000000000000000000000000000000000000000000000000000good";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A Connect lookup with fixed answers, counting its calls.
struct FakeConnect {
    answers: HashMap<&'static str, ConnectAccess>,
    calls: AtomicUsize,
}

impl ConnectTokens for FakeConnect {
    fn access(&self, presented: &str, _now: u64) -> ConnectAccess {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answers
            .get(presented)
            .cloned()
            .unwrap_or(ConnectAccess::Unknown)
    }
    fn is_connect(&self, agent_id: &str) -> bool {
        agent_id == CID || agent_id == OTHER
    }
}

fn live(identity: &str, audience: bool, expires_at: u64) -> ConnectAccess {
    ConnectAccess::Live {
        identity: identity.into(),
        connector_audience: audience,
        connector_scope: true,
        expires_at,
    }
}

/// Wire `rig`'s hub with the fake lookup and an audit sink.
fn connect_rig(rig: &Rig) -> (Arc<FakeConnect>, Arc<Mutex<Vec<Entry>>>) {
    let hour = now() + 3600;
    let fake = Arc::new(FakeConnect {
        answers: HashMap::from([
            (GOOD, live(CID, true, hour)),
            (MCP, live(CID, false, hour)),
            (OTHERS, live(OTHER, true, hour)),
            (SHORT, live(CID, true, now() + 2)),
        ]),
        calls: AtomicUsize::new(0),
    });
    rig.hub
        .set_connect_tokens(Arc::clone(&fake) as Arc<dyn ConnectTokens>);
    let entries = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&entries);
    rig.hub.set_audit(Arc::new(move |e| {
        sink.lock().unwrap().push(e);
        Ok(())
    }));
    (fake, entries)
}

fn ws_as(rig: &Rig, agent: &str, token: &str) -> AgentParams {
    AgentParams {
        agent_id: agent.into(),
        token: Zeroizing::new(token.to_owned()),
        ..ws_dial(rig, token)
    }
}

fn raw_as(rig: &Rig, agent: &str, token: &str) -> AgentParams {
    AgentParams {
        agent_id: agent.into(),
        token: Zeroizing::new(token.to_owned()),
        ..raw_dial(rig)
    }
}

fn auth_fails(entries: &Mutex<Vec<Entry>>) -> Vec<Entry> {
    entries
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.event == Event::ConnectorAuthFail)
        .cloned()
        .collect()
}

/// A connector access token with its own `c-…` id reaches `AUTH_OK` on
/// both transports, and a fill over that session reaches the CDP stub.
#[tokio::test(flavor = "multi_thread")]
async fn connect_token_attaches_and_fills_over_ws_and_raw_tls() {
    let rig = rig().await;
    let (_fake, entries) = connect_rig(&rig);
    for params in [ws_as(&rig, CID, GOOD), raw_as(&rig, CID, GOOD)] {
        let agent = tokio::spawn(async move { run_agent_once(&params).await });
        eventually("Connect session attached", || rig.hub.is_connected(CID)).await;
        assert_eq!(rig.hub.argon_in_flight(), 0);
        let outcome = fill_once_as(&rig.hub, CID).await;
        assert_eq!(outcome.status(), "filled", "{outcome:?}");
        // A Connect session is not a config agent's.
        assert!(!rig.hub.is_connected("assistant"));
        rig.hub.disconnect(CID);
        let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
    }
    assert!(
        rig.received
            .lock()
            .unwrap()
            .iter()
            .any(|m| m.to_string().contains(CANARY)),
        "the fill never reached the CDP stub"
    );
    assert!(auth_fails(&entries).is_empty());
    // The tunnel credential still attaches next to it.
    let params = ws_dial(&rig, &rig.token);
    let agent = tokio::spawn(async move { run_agent_once(&params).await });
    eventually("tunnel session attached", || {
        rig.hub.is_connected("assistant")
    })
    .await;
    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
}

/// A raw hello whose answer the caller waits for.
async fn raw_hello(rig: &Rig, agent: &str, token: String) -> u8 {
    let tcp = TcpStream::connect(rig.raw).await.unwrap();
    let mut tls = connect_pinned("127.0.0.1", rig.pin, tcp).await.unwrap();
    kharon_connector::write_client_hello(&mut tls, agent, &token)
        .await
        .unwrap();
    tls.flush().await.unwrap();
    kharon_connector::read_server_hello(&mut tls).await.unwrap()
}

/// D2: with both Argon2id permits held by slow tunnel hellos, Connect
/// hellos are still answered at once: `kh_at_` and `kh_rt_` never wait
/// for a permit or reach the tunnel verifier. An `/mcp` token is
/// `audience`, a refresh token `unauthorized` with no lookup, and the
/// entries carry no token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_hellos_never_take_an_argon2_permit() {
    let rig = Arc::new(rig_with(argon(65536, 200)).await);
    let (fake, entries) = connect_rig(&rig);
    let holders: Vec<_> = (0..2)
        .map(|_| {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { raw_hello(&rig, "assistant", rig.token.clone()).await })
        })
        .collect();
    eventually("both permits held", || rig.hub.argon_in_flight() == 2).await;

    let quick = Duration::from_secs(2);
    let mcp = tokio::time::timeout(quick, connect_and_auth(&ws_as(&rig, CID, MCP)))
        .await
        .expect("an /mcp token waited for a permit");
    assert_eq!(mcp.err(), Some(ClientError::Unauthorized));
    let refresh = tokio::time::timeout(quick, connect_and_auth(&raw_as(&rig, CID, REFRESH)))
        .await
        .expect("a refresh token waited for a permit");
    assert_eq!(refresh.err(), Some(ClientError::Unauthorized));
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        1,
        "kh_rt_ is not looked up"
    );
    let good = tokio::time::timeout(quick, connect_and_auth(&ws_as(&rig, CID, GOOD)))
        .await
        .expect("a connector token waited for a permit");
    assert!(good.is_ok(), "AUTH_OK");
    assert_eq!(rig.hub.argon_in_flight(), 2, "the holders still hash");

    let fails = auth_fails(&entries);
    assert_eq!(fails.len(), 1, "one entry per id per minute: {fails:?}");
    assert_eq!(fails[0].agent_id.as_deref(), Some(CID));
    assert_eq!(fails[0].detail_code.as_deref(), Some("audience"));
    assert_eq!(
        fails[0].transport.map(|t| t.to_string()).as_deref(),
        Some("ws")
    );
    let all = format!("{:?}", entries.lock().unwrap());
    for token in [MCP, REFRESH, GOOD] {
        assert!(!all.contains(token), "a token reached an audit entry");
    }
    assert!(!all.contains("kh_at_") && !all.contains("kh_rt_"));
    for h in holders {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(60), h)
                .await
                .unwrap()
                .unwrap(),
            0,
            "the tunnel holders still reach AUTH_OK"
        );
    }
}

/// D4 step 3: the right token under another id is `identity` and evicts
/// nobody; an unknown token is `unauthorized`; an unknown `c-…` id
/// writes no entry.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_identity_refused_without_eviction() {
    let rig = rig().await;
    let (_fake, entries) = connect_rig(&rig);
    let params = ws_as(&rig, CID, GOOD);
    let agent = tokio::spawn(async move { run_agent_once(&params).await });
    eventually("Connect session attached", || rig.hub.is_connected(CID)).await;

    // OTHER's live connector token presented as CID.
    let r = connect_and_auth(&raw_as(&rig, CID, OTHERS)).await;
    assert_eq!(r.err(), Some(ClientError::Unauthorized));
    // CID's token presented as OTHER: OTHER's (absent) session untouched.
    let r = connect_and_auth(&ws_as(&rig, OTHER, GOOD)).await;
    assert_eq!(r.err(), Some(ClientError::Unauthorized));
    assert!(rig.hub.is_connected(CID), "the real session was evicted");
    assert!(!rig.hub.is_connected(OTHER));

    // An unknown token, and a stranger's id.
    let unknown = "kh_at_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let r = connect_and_auth(&ws_as(&rig, "c-zzzzzzzzzz", unknown)).await;
    assert_eq!(r.err(), Some(ClientError::Unauthorized));

    let fails = auth_fails(&entries);
    let detail = |id: &str| {
        fails
            .iter()
            .find(|e| e.agent_id.as_deref() == Some(id))
            .and_then(|e| e.detail_code.clone())
    };
    assert_eq!(fails.len(), 2, "{fails:?}");
    assert_eq!(detail(CID).as_deref(), Some("identity"));
    assert_eq!(detail(OTHER).as_deref(), Some("identity"));
    assert!(
        !entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.event == Event::ConnectorReplaced),
        "a refusal replaced a session"
    );
    rig.hub.disconnect(CID);
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
}

/// D5: the session carries the token's `expires_at` and is dropped when
/// it passes, with no grace; the drop is the ordinary detach line.
#[tokio::test(flavor = "multi_thread")]
async fn session_drops_at_token_expiry() {
    let rig = rig().await;
    let (_fake, _entries) = connect_rig(&rig);
    let params = ws_as(&rig, CID, SHORT);
    let agent = tokio::spawn(async move { run_agent_once(&params).await });
    eventually("Connect session attached", || rig.hub.is_connected(CID)).await;
    eventually("session dropped at expiry", || !rig.hub.is_connected(CID)).await;
    eventually("detach reported", || {
        rig.events.lock().unwrap().iter().any(|e| {
            matches!(e, ConnectorEvent::Detached { agent_id, replaced: false, .. } if agent_id == CID)
        })
    })
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), agent).await;
}

/// D2: a hello carrying a Connect access token is still wire v1. It
/// round-trips through the codec with `WIRE_VERSION == 1`, and the
/// server's answers are the three v1 status bytes.
#[tokio::test]
async fn connect_hello_is_wire_v1() {
    assert_eq!(kharon_connector::WIRE_VERSION, 1);
    let token = format!("kh_at_{}", "ab".repeat(32));
    assert_eq!(token.len(), 70);
    let (mut a, mut b) = tokio::io::duplex(4096);
    kharon_connector::write_client_hello(&mut a, CID, &token)
        .await
        .unwrap();
    let hello = kharon_connector::read_client_hello(&mut b).await.unwrap();
    assert_eq!(hello.agent_id, CID);
    assert_eq!(hello.token.as_str(), token);
    assert_eq!(
        [
            kharon_connector::AUTH_OK,
            kharon_connector::AUTH_UNAUTHORIZED,
            kharon_connector::AUTH_PROTOCOL
        ],
        [0, 1, 2]
    );
}
