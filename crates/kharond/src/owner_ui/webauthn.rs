//! WebAuthn relying party for the owner UI (REQ-APR-005).
//!
//! A narrow verifier, not a general WebAuthn stack: ES256 (COSE
//! alg -7, P-256) only, attestation format `none` only, user
//! presence and user verification both required, credential
//! extensions refused. That is the ceremony a passkey and a
//! virtual authenticator actually perform for this UI. Anything
//! else fails closed. No attestation statement is trusted; the
//! enrollment token (or an existing owner session) is what
//! authorizes a new credential, and this check only binds the
//! credential to the challenge, the origin, and the rpId.
//!
//! Assertion signatures are ECDSA P-256 over
//! `authenticatorData ‖ SHA-256(clientDataJSON)`, DER-encoded, the
//! encoding the WebAuthn spec requires for ES256.

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use base64ct::{Base64UrlUnpadded, Encoding};
use ciborium::Value;
use sha2::{Digest, Sha256};

/// `authenticatorData` flag: user present.
const FLAG_UP: u8 = 0x01;
/// `authenticatorData` flag: user verified.
const FLAG_UV: u8 = 0x04;
/// `authenticatorData` flag: attested credential data follows.
const FLAG_AT: u8 = 0x40;
/// `authenticatorData` flag: extensions follow. Refused.
const FLAG_ED: u8 = 0x80;

/// Uncompressed P-256 point: `0x04 ‖ x ‖ y`.
pub(crate) const P256_POINT_LEN: usize = 65;

/// Why a ceremony did not verify. Callers collapse this to a fixed
/// client-facing code; the variant stays inside the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyError {
    /// `clientDataJSON` is not the JSON object the ceremony requires.
    ClientData,
    /// `authenticatorData` / attestation object is not the shape we accept.
    AuthenticatorData,
    /// The ES256 signature does not verify.
    Signature,
    /// The signature counter went backwards (a cloned authenticator).
    SignCount,
}

/// A credential just registered. The public key is an uncompressed
/// P-256 point; the private key never lands here.
pub(crate) struct RegisteredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: [u8; P256_POINT_LEN],
    pub sign_count: u32,
}

/// Check a `webauthn.create` ceremony and return the credential to store.
pub(crate) fn verify_registration(
    client_data_json: &[u8],
    attestation_object: &[u8],
    challenge: &[u8],
    origin: &str,
    rp_id: &str,
) -> Result<RegisteredCredential, VerifyError> {
    check_client_data(client_data_json, "webauthn.create", challenge, origin)?;
    let auth_data = attestation_auth_data(attestation_object)?;
    let parsed = parse_auth_data(&auth_data, true)?;
    check_rp_id_hash(&parsed.rp_id_hash, rp_id)?;
    let credential_id = parsed.credential_id.ok_or(VerifyError::AuthenticatorData)?;
    let public_key = parsed.public_key.ok_or(VerifyError::AuthenticatorData)?;
    Ok(RegisteredCredential {
        credential_id,
        public_key,
        sign_count: parsed.sign_count,
    })
}

/// Inputs to one assertion check. Grouped so the verifier stays a
/// single-argument function.
pub(crate) struct Assertion<'a> {
    /// Raw `clientDataJSON`.
    pub client_data_json: &'a [u8],
    /// Raw `authenticatorData`.
    pub authenticator_data: &'a [u8],
    /// DER ECDSA signature.
    pub signature: &'a [u8],
    /// The ceremony's challenge bytes.
    pub challenge: &'a [u8],
    /// Expected browser origin.
    pub origin: &'a str,
    /// Expected relying party id.
    pub rp_id: &'a str,
    /// Stored uncompressed P-256 point.
    pub public_key: &'a [u8; P256_POINT_LEN],
    /// Counter stored for this credential.
    pub stored_sign_count: u32,
}

/// Check a `webauthn.get` ceremony. Returns the counter to store.
pub(crate) fn verify_assertion(input: Assertion<'_>) -> Result<u32, VerifyError> {
    check_client_data(
        input.client_data_json,
        "webauthn.get",
        input.challenge,
        input.origin,
    )?;
    let parsed = parse_auth_data(input.authenticator_data, false)?;
    check_rp_id_hash(&parsed.rp_id_hash, input.rp_id)?;
    if !accept_sign_count(input.stored_sign_count, parsed.sign_count) {
        return Err(VerifyError::SignCount);
    }
    let mut message = Vec::with_capacity(input.authenticator_data.len() + 32);
    message.extend_from_slice(input.authenticator_data);
    message.extend_from_slice(&Sha256::digest(input.client_data_json));
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &input.public_key[..]);
    if key.verify(&message, input.signature).is_err() {
        return Err(VerifyError::Signature);
    }
    Ok(parsed.sign_count)
}

/// `stored == 0 && new == 0` is an authenticator with no counter.
/// Otherwise the counter must strictly increase.
fn accept_sign_count(stored: u32, new: u32) -> bool {
    stored == 0 && new == 0 || new > stored
}

fn check_client_data(
    json: &[u8],
    expected_type: &str,
    challenge: &[u8],
    origin: &str,
) -> Result<(), VerifyError> {
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|_| VerifyError::ClientData)?;
    let obj = value.as_object().ok_or(VerifyError::ClientData)?;
    if obj.get("type").and_then(|v| v.as_str()) != Some(expected_type) {
        return Err(VerifyError::ClientData);
    }
    let presented = obj
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or(VerifyError::ClientData)?;
    let presented = b64url_decode(presented).map_err(|_| VerifyError::ClientData)?;
    if !ct_eq(&presented, challenge) {
        return Err(VerifyError::ClientData);
    }
    if obj.get("origin").and_then(|v| v.as_str()) != Some(origin) {
        return Err(VerifyError::ClientData);
    }
    if let Some(cross) = obj.get("crossOrigin")
        && cross.as_bool() != Some(false)
    {
        return Err(VerifyError::ClientData);
    }
    Ok(())
}

fn check_rp_id_hash(got: &[u8], rp_id: &str) -> Result<(), VerifyError> {
    let expect = Sha256::digest(rp_id.as_bytes());
    if !ct_eq(got, &expect) {
        return Err(VerifyError::AuthenticatorData);
    }
    Ok(())
}

struct ParsedAuth {
    rp_id_hash: Vec<u8>,
    sign_count: u32,
    credential_id: Option<Vec<u8>>,
    public_key: Option<[u8; P256_POINT_LEN]>,
}

fn parse_auth_data(data: &[u8], expect_at: bool) -> Result<ParsedAuth, VerifyError> {
    if data.len() < 37 {
        return Err(VerifyError::AuthenticatorData);
    }
    let flags = data[32];
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 || flags & FLAG_ED != 0 {
        return Err(VerifyError::AuthenticatorData);
    }
    let at = flags & FLAG_AT != 0;
    if at != expect_at {
        return Err(VerifyError::AuthenticatorData);
    }
    let sign_count = u32::from_be_bytes(data[33..37].try_into().expect("4 bytes"));
    if !at {
        if data.len() != 37 {
            return Err(VerifyError::AuthenticatorData);
        }
        return Ok(ParsedAuth {
            rp_id_hash: data[0..32].to_vec(),
            sign_count,
            credential_id: None,
            public_key: None,
        });
    }
    // rpIdHash ‖ flags ‖ signCount ‖ aaguid(16) ‖ credIdLen ‖ credId ‖ COSE key
    if data.len() < 37 + 16 + 2 {
        return Err(VerifyError::AuthenticatorData);
    }
    let mut i = 37 + 16;
    let cred_len = u16::from_be_bytes(data[i..i + 2].try_into().expect("2 bytes")) as usize;
    i += 2;
    if cred_len == 0 || cred_len > 1023 || data.len() < i + cred_len {
        return Err(VerifyError::AuthenticatorData);
    }
    let credential_id = data[i..i + cred_len].to_vec();
    i += cred_len;
    let public_key = parse_cose_p256(&data[i..])?;
    Ok(ParsedAuth {
        rp_id_hash: data[0..32].to_vec(),
        sign_count,
        credential_id: Some(credential_id),
        public_key: Some(public_key),
    })
}

/// `fmt: none` attestation object. The authData is returned; the
/// (empty) attStmt is not a signature and is not trusted.
fn attestation_auth_data(object: &[u8]) -> Result<Vec<u8>, VerifyError> {
    let mut cur = std::io::Cursor::new(object);
    let value: Value =
        ciborium::from_reader(&mut cur).map_err(|_| VerifyError::AuthenticatorData)?;
    if cur.position() as usize != object.len() {
        return Err(VerifyError::AuthenticatorData);
    }
    let pairs = match value {
        Value::Map(pairs) => pairs,
        _ => return Err(VerifyError::AuthenticatorData),
    };
    let mut fmt = None;
    let mut auth_data = None;
    let mut att_stmt_empty = false;
    for (k, v) in pairs {
        let Value::Text(key) = k else {
            return Err(VerifyError::AuthenticatorData);
        };
        match key.as_str() {
            "fmt" => {
                let Value::Text(s) = v else {
                    return Err(VerifyError::AuthenticatorData);
                };
                fmt = Some(s);
            }
            "authData" => {
                let Value::Bytes(b) = v else {
                    return Err(VerifyError::AuthenticatorData);
                };
                auth_data = Some(b);
            }
            "attStmt" => {
                att_stmt_empty = matches!(v, Value::Map(ref m) if m.is_empty());
            }
            _ => return Err(VerifyError::AuthenticatorData),
        }
    }
    if fmt.as_deref() != Some("none") || !att_stmt_empty {
        return Err(VerifyError::AuthenticatorData);
    }
    auth_data.ok_or(VerifyError::AuthenticatorData)
}

fn parse_cose_p256(bytes: &[u8]) -> Result<[u8; P256_POINT_LEN], VerifyError> {
    let mut cur = std::io::Cursor::new(bytes);
    let value: Value =
        ciborium::from_reader(&mut cur).map_err(|_| VerifyError::AuthenticatorData)?;
    if cur.position() as usize != bytes.len() {
        return Err(VerifyError::AuthenticatorData);
    }
    let pairs = match value {
        Value::Map(pairs) => pairs,
        _ => return Err(VerifyError::AuthenticatorData),
    };
    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;
    for (k, v) in pairs {
        let key = cbor_i64(&k).ok_or(VerifyError::AuthenticatorData)?;
        match key {
            1 => kty = Some(cbor_i64(&v).ok_or(VerifyError::AuthenticatorData)?),
            3 => alg = Some(cbor_i64(&v).ok_or(VerifyError::AuthenticatorData)?),
            -1 => crv = Some(cbor_i64(&v).ok_or(VerifyError::AuthenticatorData)?),
            -2 => x = Some(cbor_bytes(&v).ok_or(VerifyError::AuthenticatorData)?),
            -3 => y = Some(cbor_bytes(&v).ok_or(VerifyError::AuthenticatorData)?),
            // A private component, or anything else, is refused.
            _ => return Err(VerifyError::AuthenticatorData),
        }
    }
    // kty EC2 = 2, alg ES256 = -7, crv P-256 = 1.
    if kty != Some(2) || alg != Some(-7) || crv != Some(1) {
        return Err(VerifyError::AuthenticatorData);
    }
    let x = x.ok_or(VerifyError::AuthenticatorData)?;
    let y = y.ok_or(VerifyError::AuthenticatorData)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(VerifyError::AuthenticatorData);
    }
    let mut point = [0u8; P256_POINT_LEN];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&x);
    point[33..65].copy_from_slice(&y);
    // Shape only. The point is not checked to lie on P-256, so an
    // off-curve point can be stored. Assertion verification then
    // fails closed: aws-lc rejects a point that is not on the curve.
    // Registration still requires an enrollment code or a session.
    Ok(point)
}

fn cbor_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => i64::try_from(*i).ok(),
        _ => None,
    }
}

fn cbor_bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

/// Constant-time equality for equal-length slices. Different lengths
/// are not equal; those lengths are not secret (hashes, points).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.is_empty() || s.len() > 2048 || !s.bytes().all(is_b64url) {
        return Err(());
    }
    let mut buf = vec![0u8; s.len()];
    let decoded = Base64UrlUnpadded::decode(s, &mut buf).map_err(|_| ())?;
    let n = decoded.len();
    buf.truncate(n);
    Ok(buf)
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    fn point_of(key: &EcdsaKeyPair) -> [u8; P256_POINT_LEN] {
        let raw = key.public_key().as_ref();
        assert_eq!(
            raw.len(),
            P256_POINT_LEN,
            "public key is an uncompressed point"
        );
        raw.try_into().unwrap()
    }

    struct Auth {
        key: EcdsaKeyPair,
        cred_id: Vec<u8>,
        sign_count: u32,
    }

    impl Auth {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
            Self {
                key,
                cred_id: vec![7u8; 16],
                sign_count: 0,
            }
        }

        fn cose(&self) -> Vec<u8> {
            let point = point_of(&self.key);
            let x = point[1..33].to_vec();
            let y = point[33..65].to_vec();
            let map = Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(3.into()), Value::Integer((-7i64).into())),
                (Value::Integer((-1i64).into()), Value::Integer(1.into())),
                (Value::Integer((-2i64).into()), Value::Bytes(x)),
                (Value::Integer((-3i64).into()), Value::Bytes(y)),
            ]);
            let mut out = Vec::new();
            ciborium::into_writer(&map, &mut out).unwrap();
            out
        }

        fn auth_data(&self, rp_id: &str, at: bool) -> Vec<u8> {
            let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
            let flags = if at {
                FLAG_UP | FLAG_UV | FLAG_AT
            } else {
                FLAG_UP | FLAG_UV
            };
            data.push(flags);
            data.extend_from_slice(&self.sign_count.to_be_bytes());
            if at {
                data.extend_from_slice(&[0u8; 16]);
                data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.cred_id);
                data.extend_from_slice(&self.cose());
            }
            data
        }

        fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            format!(
                r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
                b64url_encode(challenge)
            )
            .into_bytes()
        }

        fn attestation(&self, rp_id: &str) -> Vec<u8> {
            let map = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(vec![])),
                (
                    Value::Text("authData".into()),
                    Value::Bytes(self.auth_data(rp_id, true)),
                ),
            ]);
            let mut out = Vec::new();
            ciborium::into_writer(&map, &mut out).unwrap();
            out
        }

        fn sign(&self, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
            let mut message = auth_data.to_vec();
            message.extend_from_slice(&Sha256::digest(client_data));
            let rng = SystemRandom::new();
            self.key.sign(&rng, &message).unwrap().as_ref().to_vec()
        }
    }

    #[test]
    fn req_apr_005_registration_and_assertion_roundtrip() {
        let auth = Auth::new();
        let challenge = [9u8; 32];
        let origin = "http://localhost:8787";
        let rp = "localhost";
        let client = Auth::client_data("webauthn.create", &challenge, origin);
        let reg = verify_registration(&client, &auth.attestation(rp), &challenge, origin, rp)
            .expect("registration verifies");
        assert_eq!(reg.credential_id, auth.cred_id);
        assert_eq!(reg.sign_count, 0);
        assert_eq!(reg.public_key, point_of(&auth.key));

        let mut auth = auth;
        auth.sign_count = 1;
        let challenge2 = [3u8; 32];
        let client = Auth::client_data("webauthn.get", &challenge2, origin);
        let auth_data = auth.auth_data(rp, false);
        let sig = auth.sign(&auth_data, &client);
        let next = verify_assertion(Assertion {
            client_data_json: &client,
            authenticator_data: &auth_data,
            signature: &sig,
            challenge: &challenge2,
            origin,
            rp_id: rp,
            public_key: &reg.public_key,
            stored_sign_count: 0,
        })
        .expect("assertion verifies");
        assert_eq!(next, 1);
        // A cloned authenticator that replays counter 1 is refused.
        let err = verify_assertion(Assertion {
            client_data_json: &client,
            authenticator_data: &auth_data,
            signature: &sig,
            challenge: &challenge2,
            origin,
            rp_id: rp,
            public_key: &reg.public_key,
            stored_sign_count: 1,
        });
        assert_eq!(err, Err(VerifyError::SignCount));
    }

    #[test]
    fn req_apr_005_verifier_refuses_wrong_origin_and_packed_attestation() {
        let auth = Auth::new();
        let challenge = [1u8; 32];
        let client = Auth::client_data("webauthn.create", &challenge, "http://localhost:8787");
        let err = verify_registration(
            &client,
            &auth.attestation("localhost"),
            &challenge,
            "http://evil.test",
            "localhost",
        );
        assert!(matches!(err, Err(VerifyError::ClientData)));

        let packed = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("packed".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (
                Value::Text("authData".into()),
                Value::Bytes(auth.auth_data("localhost", true)),
            ),
        ]);
        let mut object = Vec::new();
        ciborium::into_writer(&packed, &mut object).unwrap();
        let err = verify_registration(
            &client,
            &object,
            &challenge,
            "http://localhost:8787",
            "localhost",
        );
        assert!(matches!(err, Err(VerifyError::AuthenticatorData)));
    }
}
