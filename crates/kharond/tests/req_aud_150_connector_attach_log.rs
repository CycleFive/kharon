//! #150: the broker logs agent-connector attach and detach.
//!
//! An accepted tunnel credential reports exactly one attach and, when the
//! session ends, exactly one detach, each with the agent id and peer and
//! never the credential. A refused credential reports only the existing
//! refusal line. No CDP stream is opened, so the agent's CDP address is
//! never dialed.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use argon2::Argon2;
use kharond::api::token::{ParamFloor, TUNNEL_PREFIX, TokenStore, generate_tunnel_with};
use kharond::connector::{
    AgentParams, ClientError, ConnectorEvent, Hub, accept, pin_of_der, run_agent_once,
    server_config_from_pem,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

const FLOOR: ParamFloor = ParamFloor {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

struct Rig {
    hub: Arc<Hub>,
    token: String,
    pin: [u8; 32],
    broker: SocketAddr,
    events: Arc<Mutex<Vec<ConnectorEvent>>>,
}

async fn rig(token_ok: bool) -> Rig {
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(8, 1, 1, None).unwrap(),
    );
    let (secret, hash) = generate_tunnel_with(&argon, "assistant");
    let token = secret.expose_secret().clone();
    let store =
        TokenStore::with_floor_and_prefix([("assistant", hash.as_str())], &FLOOR, TUNNEL_PREFIX)
            .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let hub = Arc::new(Hub::with_events(
        store,
        Arc::new(move |e: &ConnectorEvent| sink.lock().unwrap().push(e.clone())),
    ));
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let tls =
        server_config_from_pem(cert.pem().as_bytes(), key_pair.serialize_pem().as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker = listener.local_addr().unwrap();
    let accept_hub = Arc::clone(&hub);
    tokio::spawn(async move { accept(listener, tls, accept_hub).await });
    Rig {
        hub,
        token: if token_ok {
            token
        } else {
            format!("{token}nope")
        },
        pin: pin_of_der(cert.der()),
        broker,
        events,
    }
}

fn params(rig: &Rig) -> AgentParams {
    AgentParams {
        broker: rig.broker,
        server_name: "127.0.0.1".into(),
        pin: rig.pin,
        agent_id: "assistant".into(),
        token: Zeroizing::new(rig.token.clone()),
        // Never dialed: these tests open no CDP stream.
        cdp: "127.0.0.1:9".parse().unwrap(),
        proxy: None,
        proxy_creds: None,
    }
}

fn events(rig: &Rig) -> Vec<ConnectorEvent> {
    rig.events.lock().unwrap().clone()
}

async fn wait_events(rig: &Rig, n: usize) -> Vec<ConnectorEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let seen = events(rig);
        if seen.len() >= n {
            return seen;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("expected {n} connector events, got {seen:?}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_connected(hub: &Hub) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !hub.is_connected("assistant") {
        if tokio::time::Instant::now() > deadline {
            panic!("connector did not authenticate");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One attach on `AUTH_OK`, one detach when the session ends, and neither
/// line carries the tunnel credential.
#[tokio::test(flavor = "multi_thread")]
async fn req_aud_150_attach_and_detach_logged_once() {
    let rig = rig(true).await;
    let p = params(&rig);
    let agent = tokio::spawn(async move { run_agent_once(&p).await });
    wait_connected(&rig.hub).await;

    let seen = events(&rig);
    assert_eq!(seen.len(), 1, "{seen:?}");
    let ConnectorEvent::Attached { agent_id, peer } = &seen[0] else {
        panic!("expected an attach, got {seen:?}");
    };
    assert_eq!(agent_id, "assistant");
    assert!(peer.ip().is_loopback(), "{peer}");
    let line = seen[0].to_string();
    assert_eq!(
        line,
        format!("agent connector attached: agent=assistant peer={peer}")
    );
    assert!(!line.contains(&rig.token));
    assert!(!line.contains(TUNNEL_PREFIX));

    rig.hub.disconnect("assistant");
    let seen = wait_events(&rig, 2).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), agent).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(seen, events(&rig), "no further events after the detach");
    match &seen[1] {
        ConnectorEvent::Detached {
            agent_id,
            peer: p,
            replaced,
            ..
        } => {
            assert_eq!(agent_id, "assistant");
            assert_eq!(p, peer);
            assert!(!replaced, "a disconnect is not a replacement");
        }
        other => panic!("expected a detach, got {other:?}"),
    }
    let line = seen[1].to_string();
    assert!(
        line.starts_with(&format!(
            "agent connector detached: agent=assistant peer={peer} after="
        )),
        "{line}"
    );
    assert!(!line.contains(&rig.token));
}

/// A refused credential still logs only the existing refusal line.
#[tokio::test(flavor = "multi_thread")]
async fn req_aud_150_refused_credential_logs_only_refusal() {
    let rig = rig(false).await;
    let err = run_agent_once(&params(&rig)).await.unwrap_err();
    assert_eq!(err, ClientError::Unauthorized);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let seen = events(&rig);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(matches!(seen[0], ConnectorEvent::Refused { .. }));
    assert_eq!(seen[0].to_string(), "agent connector refused a credential");
    assert!(!rig.hub.is_connected("assistant"));
}

/// A second session for the same agent detaches the first as replaced,
/// and each session attaches once.
#[tokio::test(flavor = "multi_thread")]
async fn req_aud_150_replaced_session_logged_as_replaced() {
    let rig = rig(true).await;
    let first = params(&rig);
    let a = tokio::spawn(async move { run_agent_once(&first).await });
    wait_connected(&rig.hub).await;
    let second = params(&rig);
    let b = tokio::spawn(async move { run_agent_once(&second).await });
    let seen = wait_events(&rig, 3).await;

    let attached = seen
        .iter()
        .filter(|e| matches!(e, ConnectorEvent::Attached { .. }))
        .count();
    assert_eq!(attached, 2, "{seen:?}");
    let detached: Vec<_> = seen
        .iter()
        .filter_map(|e| match e {
            ConnectorEvent::Detached { replaced, .. } => Some(*replaced),
            _ => None,
        })
        .collect();
    assert_eq!(detached, vec![true], "{seen:?}");
    assert!(
        seen[2]
            .to_string()
            .ends_with(" (replaced by a new session)")
    );

    rig.hub.disconnect("assistant");
    let _ = tokio::time::timeout(Duration::from_secs(2), a).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), b).await;
}
