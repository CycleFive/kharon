//! Owner web UI test support shared by `req_apr_005` and the
//! REQ-MEM-003 canary scan of a web unlock: a raw HTTP client for the
//! owner listener, and a software ES256 passkey.

#![allow(dead_code)]

use std::time::{Duration, Instant};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;

use crate::api_support::{RawResponse, raw_request};

pub struct Http<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub cookie: Option<&'a str>,
    pub bearer: Option<&'a str>,
    pub content_type: Option<&'a str>,
    pub body: &'a str,
}

impl<'a> Http<'a> {
    pub fn get(path: &'a str) -> Self {
        Self {
            method: "GET",
            path,
            cookie: None,
            bearer: None,
            content_type: None,
            body: "",
        }
    }

    pub fn post(path: &'a str, content_type: Option<&'a str>, body: &'a str) -> Self {
        Self {
            method: "POST",
            path,
            cookie: None,
            bearer: None,
            content_type,
            body,
        }
    }

    pub fn cookie(mut self, cookie: &'a str) -> Self {
        self.cookie = Some(cookie);
        self
    }

    pub fn bearer(mut self, bearer: &'a str) -> Self {
        self.bearer = Some(bearer);
        self
    }
}

pub async fn http(addr: std::net::SocketAddr, origin: &str, req: Http<'_>) -> RawResponse {
    let method = req.method;
    let path = req.path;
    let body = req.body;
    let cookie = req
        .cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    let bearer = req
        .bearer
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let ctype = req
        .content_type
        .map(|t| format!("Content-Type: {t}\r\nContent-Length: {}\r\n", body.len()))
        .unwrap_or_default();
    let origin = if method == "POST" {
        format!("Origin: {origin}\r\n")
    } else {
        String::new()
    };
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n{origin}{cookie}{bearer}{ctype}Connection: close\r\n\r\n{body}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => break,
            Err(e) => {
                assert!(Instant::now() < deadline, "owner UI never came up: {e}");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    raw_request(addr, head.as_bytes()).await
}

pub fn session_cookie(resp: &RawResponse) -> Option<String> {
    resp.headers.iter().find_map(|(k, v)| {
        (k.eq_ignore_ascii_case("set-cookie") && v.starts_with("kharon_owner="))
            .then(|| v.split(';').next().unwrap().to_owned())
    })
}

pub fn b64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub fn b64url_dec(s: &str) -> Vec<u8> {
    let mut buf = vec![0u8; s.len()];
    let n = Base64UrlUnpadded::decode(s, &mut buf).unwrap().len();
    buf.truncate(n);
    buf
}

/// A software passkey: ES256, `none` attestation, UV+UP. The same
/// shape Chrome's WebAuthn virtual authenticator produces.
pub struct VirtAuth {
    pub key: EcdsaKeyPair,
    /// PKCS#8 of the private key, kept only to prove it never hits disk.
    pub pkcs8: Vec<u8>,
    pub cred_id: Vec<u8>,
    pub sign_count: u32,
    pub user_handle: Vec<u8>,
}

impl VirtAuth {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pkcs8 = doc.as_ref().to_vec();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).unwrap();
        Self {
            key,
            pkcs8,
            cred_id: vec![0x11; 16],
            sign_count: 0,
            user_handle: Vec::new(),
        }
    }

    pub fn public_point(&self) -> [u8; 65] {
        let raw = self.key.public_key().as_ref();
        assert_eq!(
            raw.len(),
            65,
            "uncompressed P-256 point, got {} bytes",
            raw.len()
        );
        raw.try_into().unwrap()
    }

    pub fn cose(&self) -> Vec<u8> {
        let point = self.public_point();
        let map = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (
                Value::Integer((-2i64).into()),
                Value::Bytes(point[1..33].to_vec()),
            ),
            (
                Value::Integer((-3i64).into()),
                Value::Bytes(point[33..65].to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        out
    }

    pub fn auth_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(if attested {
            0x01 | 0x04 | 0x40
        } else {
            0x01 | 0x04
        });
        data.extend_from_slice(&self.sign_count.to_be_bytes());
        if attested {
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.cred_id);
            data.extend_from_slice(&self.cose());
        }
        data
    }

    pub fn client_data(&self, kind: &str, challenge_b64: &str, origin: &str) -> String {
        format!(
            r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
        )
    }

    pub fn registration(&self, challenge_b64: &str, origin: &str, rp_id: &str) -> Json {
        let client = self.client_data("webauthn.create", challenge_b64, origin);
        let auth = self.auth_data(rp_id, true);
        let map = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth)),
        ]);
        let mut attestation = Vec::new();
        ciborium::into_writer(&map, &mut attestation).unwrap();
        json!({
            "id": b64url(&self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client.as_bytes()),
                "attestationObject": b64url(&attestation),
            }
        })
    }

    pub fn assertion(&mut self, challenge_b64: &str, origin: &str, rp_id: &str) -> Json {
        self.sign_count += 1;
        let client = self.client_data("webauthn.get", challenge_b64, origin);
        let auth = self.auth_data(rp_id, false);
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let sig = self
            .key
            .sign(&SystemRandom::new(), &message)
            .unwrap()
            .as_ref()
            .to_vec();
        let mut response = json!({
            "clientDataJSON": b64url(client.as_bytes()),
            "authenticatorData": b64url(&auth),
            "signature": b64url(&sig),
        });
        if !self.user_handle.is_empty() {
            response["userHandle"] = json!(b64url(&self.user_handle));
        }
        json!({
            "id": b64url(&self.cred_id),
            "type": "public-key",
            "response": response,
        })
    }
}

/// Register a software passkey with the enrollment code `token`, then
/// sign in with an assertion. Returns the `Cookie` value.
pub async fn register_and_sign_in(ui: std::net::SocketAddr, origin: &str, token: &str) -> String {
    let mut auth = VirtAuth::new();
    let opts = http(
        ui,
        origin,
        Http::post("/owner/register/options", None, "").bearer(token),
    )
    .await;
    assert_eq!(opts.status, 200, "{}", opts.body);
    let opts: Json = serde_json::from_str(&opts.body).unwrap();
    auth.user_handle = b64url_dec(opts["publicKey"]["user"]["id"].as_str().unwrap());
    let ceremony = opts["ceremony_id"].as_str().unwrap();
    let challenge = opts["publicKey"]["challenge"].as_str().unwrap();
    let reg = auth.registration(challenge, origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": reg}).to_string();
    let registered = http(
        ui,
        origin,
        Http::post("/owner/register/finish", Some("application/json"), &body),
    )
    .await;
    assert_eq!(registered.status, 200, "{}", registered.body);
    assert!(session_cookie(&registered).is_none());

    let login_opts = http(ui, origin, Http::post("/owner/login/options", None, "")).await;
    assert_eq!(login_opts.status, 200, "{}", login_opts.body);
    let login_opts: Json = serde_json::from_str(&login_opts.body).unwrap();
    let ceremony = login_opts["ceremony_id"].as_str().unwrap();
    let challenge = login_opts["publicKey"]["challenge"].as_str().unwrap();
    let assertion = auth.assertion(challenge, origin, "localhost");
    let body = json!({"ceremony_id": ceremony, "credential": assertion}).to_string();
    let ok = http(
        ui,
        origin,
        Http::post("/owner/login/finish", Some("application/json"), &body),
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    session_cookie(&ok).expect("session cookie")
}
