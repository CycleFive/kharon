//! The compose E2E for the OAuth Connect flow (issue #234). Task 1: the
//! shared transport helpers and their tests; the scenario follows.

mod api_support;
mod compose_support;
mod docker_support;
mod owner_ui_support;

use std::sync::Arc;

use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn https_raw_round_trips_through_a_tls_listener() {
    let (ca_pem, leaf_pem, leaf_key_pem) = compose_support::edge_pki(&["edge.test"]);
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(leaf_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(leaf_key_pem.as_bytes()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(
                        b"HTTP/1.1 418 I'm a teapot\r\nX-Probe: yes\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });

    let r = compose_support::https_raw(
        addr,
        "edge.test",
        &ca_pem,
        b"GET /x HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    assert_eq!(r.status, 418);
    assert_eq!(r.header("x-probe"), Some("yes"));
    assert_eq!(r.body, "ok");
    // A CA that did not sign the leaf is refused.
    let (other_ca, _, _) = compose_support::edge_pki(&["edge.test"]);
    assert!(
        compose_support::https_raw(
            addr,
            "edge.test",
            &other_ca,
            b"GET / HTTP/1.1\r\nHost: edge.test\r\n\r\n"
        )
        .await
        .is_err()
    );
}

#[test]
fn request_bytes_matches_what_http_sends() {
    let req = owner_ui_support::Http::post("/owner/logout", Some("application/json"), "{}")
        .host("kharon-owner.e2e.test")
        .cookie("__Host-kharon_owner=abc")
        .header("CF-Connecting-IP", "198.51.100.10");
    let text = String::from_utf8(owner_ui_support::request_bytes(
        "https://kharon-owner.e2e.test",
        &req,
    ))
    .unwrap();
    assert!(text.starts_with("POST /owner/logout HTTP/1.1\r\n"));
    for line in [
        "Host: kharon-owner.e2e.test\r\n",
        "Origin: https://kharon-owner.e2e.test\r\n",
        "Cookie: __Host-kharon_owner=abc\r\n",
        "CF-Connecting-IP: 198.51.100.10\r\n",
        "Content-Length: 2\r\n",
    ] {
        assert!(
            text.to_ascii_lowercase()
                .contains(&line.to_ascii_lowercase()),
            "missing {line:?}"
        );
    }
    assert!(text.ends_with("\r\n\r\n{}"));
}
