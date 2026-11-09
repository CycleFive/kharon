//! REQ-ARCH-002 path B wire: the connector relays bytes only after the
//! broker certificate matches the pin and the tunnel credential is
//! accepted. A wrong pin, a refused credential, and a broker-supplied
//! dial target never reach the loopback listener.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kharon_connector::{
    AUTH_OK, AUTH_UNAUTHORIZED, AgentParams, BrokerSession, ClientError, FRAME_OPEN, Frame,
    Transport, encode_frame, pin_of_der, read_client_hello, run_agent_once, serve_agent,
    server_config_from_pem, spawn_broker, write_server_hello,
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

struct Cert {
    pem_cert: String,
    pem_key: String,
    pin: [u8; 32],
}

fn cert() -> Cert {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let pin = pin_of_der(cert.der());
    Cert {
        pem_cert: cert.pem(),
        pem_key: key_pair.serialize_pem(),
        pin,
    }
}

async fn counting_listener() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            hits2.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = sock.read(&mut buf).await {
                    if n > 0 {
                        let _ = sock.write_all(&buf[..n]).await;
                    }
                    let _ = sock.read(&mut buf).await;
                }
            });
        }
    });
    (addr, hits)
}

fn params(broker: SocketAddr, pin: [u8; 32], token: &str, cdp: SocketAddr) -> AgentParams {
    AgentParams {
        transport: Transport::Tls { broker },
        server_name: "127.0.0.1".into(),
        pin,
        agent_id: "assistant".into(),
        token: Zeroizing::new(token.into()),
        cdp,
        proxy: None,
        proxy_creds: None,
        outer_roots: None,
    }
}

/// Broker that checks the token as a raw string (Argon2id is kharond's
/// job) and exposes the live [`BrokerSession`].
async fn token_broker(
    expected: &'static str,
) -> (SocketAddr, [u8; 32], Arc<Mutex<Vec<BrokerSession>>>) {
    let cert = cert();
    let config = server_config_from_pem(cert.pem_cert.as_bytes(), cert.pem_key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let slot = Arc::clone(&sessions);
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let slot = Arc::clone(&slot);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(hello) = read_client_hello(&mut tls).await else {
                    return;
                };
                if hello.token.as_str() != expected || hello.agent_id != "assistant" {
                    let _ = write_server_hello(&mut tls, AUTH_UNAUTHORIZED).await;
                    return;
                }
                if write_server_hello(&mut tls, AUTH_OK).await.is_err() {
                    return;
                }
                let session = spawn_broker(tls);
                slot.lock().unwrap().push(session.clone());
                session.closed().await;
            });
        }
    });
    (addr, cert.pin, sessions)
}

async fn wait_sessions(slot: &Mutex<Vec<BrokerSession>>, n: usize) -> BrokerSession {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(session) = slot.lock().unwrap().get(n - 1).cloned() {
            return session;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for connector session {n}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn req_arch_002_connector_relays_bytes_and_reconnects() {
    let (cdp, hits) = counting_listener().await;
    let (broker, pin, sessions) = token_broker("kh_tunnel_assistant_ok").await;
    let params = params(broker, pin, "kh_tunnel_assistant_ok", cdp);
    let stop = Arc::new(AtomicUsize::new(0));
    let stop2 = Arc::clone(&stop);
    let agent = tokio::spawn(async move {
        while stop2.load(Ordering::SeqCst) == 0 {
            let _ = run_agent_once(&params).await;
        }
    });

    let session = wait_sessions(&sessions, 1).await;
    let mut io = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .unwrap()
        .unwrap();
    io.write_all(b"ping").await.unwrap();
    io.flush().await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"ping");
    assert!(hits.load(Ordering::SeqCst) >= 1);

    session.shutdown();
    let session = wait_sessions(&sessions, 2).await;
    let mut io = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .unwrap()
        .unwrap();
    io.write_all(b"pong").await.unwrap();
    io.flush().await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"pong");

    stop.store(1, Ordering::SeqCst);
    session.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), agent).await;
}

#[tokio::test]
async fn req_arch_002_bad_creds_do_not_dial_cdp() {
    let (cdp, hits) = counting_listener().await;
    let (broker, pin, _) = token_broker("kh_tunnel_assistant_ok").await;
    let err = run_agent_once(&params(broker, pin, "kh_tunnel_assistant_nope", cdp))
        .await
        .unwrap_err();
    assert_eq!(err, ClientError::Unauthorized);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn req_arch_002_wrong_broker_cert_does_not_dial_cdp() {
    let (cdp, hits) = counting_listener().await;
    let (broker, _pin, _) = token_broker("kh_tunnel_assistant_ok").await;
    let other = cert();
    let err = run_agent_once(&params(broker, other.pin, "kh_tunnel_assistant_ok", cdp))
        .await
        .unwrap_err();
    assert_eq!(err, ClientError::BadCert);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn req_arch_002_open_payload_is_not_a_dial_target() {
    let (cdp, hits) = counting_listener().await;
    let (agent, mut broker) = tokio::io::duplex(4096);
    let serve = tokio::spawn(async move {
        let _ = serve_agent(agent, cdp).await;
    });
    // A v1 OPEN with a payload is a protocol error, not a dial request.
    let mut frame = Vec::new();
    frame.push(FRAME_OPEN);
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&4u32.to_be_bytes());
    frame.extend_from_slice(b"evil");
    broker.write_all(&frame).await.unwrap();
    let mut buf = [0u8; 8];
    let _ = tokio::time::timeout(Duration::from_secs(2), broker.read(&mut buf)).await;
    serve.await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    // The honest frame still encodes with an empty payload.
    let honest = encode_frame(&Frame::Open { id: 1 }).unwrap();
    assert_eq!(honest[0], FRAME_OPEN);
    assert_eq!(&honest[5..9], &0u32.to_be_bytes());
}

#[tokio::test]
async fn req_arch_002_http_connect_proxy_reaches_the_broker() {
    let (cdp, _) = counting_listener().await;
    let (broker, pin, sessions) = token_broker("kh_tunnel_assistant_ok").await;
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            inbound.read_exact(&mut byte).await.unwrap();
            buf.push(byte[0]);
        }
        let head = String::from_utf8(buf).unwrap();
        let _ = tx.send(head.clone());
        let target = head
            .split("\r\n")
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse::<SocketAddr>()
            .unwrap();
        let mut outbound = tokio::net::TcpStream::connect(target).await.unwrap();
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    });
    let mut p = params(broker, pin, "kh_tunnel_assistant_ok", cdp);
    p.proxy = Some(proxy_addr);
    let agent = tokio::spawn(async move {
        let _ = run_agent_once(&p).await;
    });
    let head = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap();
    let port = broker.port();
    let expected = format!(
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    assert_eq!(head, expected);
    let session = wait_sessions(&sessions, 1).await;
    let mut io = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .unwrap()
        .unwrap();
    io.write_all(b"via-proxy").await.unwrap();
    let mut buf = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"via-proxy");
    session.shutdown();
    let _ = agent.await;
}

/// RFC 7617 §2 vector. The proxy accepts only this header.
const PROXY_BASIC: &str = "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==";

#[tokio::test]
async fn req_arch_002_http_connect_proxy_basic_auth_reaches_the_broker() {
    let (cdp, _) = counting_listener().await;
    let (broker, pin, sessions) = token_broker("kh_tunnel_assistant_ok").await;
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            inbound.read_exact(&mut byte).await.unwrap();
            buf.push(byte[0]);
        }
        let head = String::from_utf8(buf).unwrap();
        let ok = head.contains(PROXY_BASIC) && !head.contains("open sesame");
        let _ = tx.send(head.clone());
        if !ok {
            let _ = inbound
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await;
            return;
        }
        let target = head
            .split("\r\n")
            .next()
            .unwrap()
            .split(' ')
            .nth(1)
            .unwrap()
            .parse::<SocketAddr>()
            .unwrap();
        let mut outbound = tokio::net::TcpStream::connect(target).await.unwrap();
        inbound
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
    });
    let mut p = params(broker, pin, "kh_tunnel_assistant_ok", cdp);
    p.proxy = Some(proxy_addr);
    p.proxy_creds = Some(Zeroizing::new(b"Aladdin:open sesame".to_vec()));
    let agent = tokio::spawn(async move {
        let _ = run_agent_once(&p).await;
    });
    let head = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap();
    assert!(head.contains(PROXY_BASIC), "{head}");
    assert!(!head.contains("open sesame"));
    assert!(!head.contains("Aladdin"));
    let session = wait_sessions(&sessions, 1).await;
    let mut io = tokio::time::timeout(Duration::from_secs(5), session.open_stream())
        .await
        .unwrap()
        .unwrap();
    io.write_all(b"authed").await.unwrap();
    let mut buf = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"authed");
    session.shutdown();
    let _ = agent.await;
}

#[tokio::test]
async fn req_arch_002_proxy_407_does_not_dial_cdp() {
    let (cdp, hits) = counting_listener().await;
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if inbound.read(&mut byte).await.unwrap() == 0 {
                return;
            }
            buf.push(byte[0]);
        }
        let _ = inbound
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"Aladdin\"\r\n\
\r\n\
open sesame",
            )
            .await;
    });
    let mut p = params(
        "127.0.0.1:9".parse().unwrap(),
        [7u8; 32],
        "kh_tunnel_assistant_ok",
        cdp,
    );
    p.proxy = Some(proxy_addr);
    p.proxy_creds = Some(Zeroizing::new(b"Aladdin:open sesame".to_vec()));
    let err = run_agent_once(&p).await.unwrap_err();
    assert_eq!(err, ClientError::ProxyAuth);
    assert_eq!(err.to_string(), "proxy authentication was refused");
    let shown = format!("{err:?} {err}");
    assert!(!shown.contains("open sesame"));
    assert!(!shown.contains("Aladdin"));
    assert!(!shown.contains("QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
