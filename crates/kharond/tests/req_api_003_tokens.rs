//! REQ-API-003: agent token auth. Argon2id hash stored, constant-time
//! compare (the `password-hash` digest comparison). AC: bad token →
//! 401; the token store (the config file's `[agents.*].token_hash`)
//! holds no plaintext token (grep).

mod api_support;

use api_support::*;
use kharond::api::token::{TOKEN_PREFIX, generate, generate_with};
use kharond::api::{ApiError, TokenStore};
use kharond::config::Config;

#[tokio::test]
async fn req_api_003_bad_token_is_401_with_fixed_body() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let alpha_rand = h.alpha.rsplit_once('_').unwrap().1.to_owned();
    let mut flipped = h.alpha.clone().into_bytes();
    let last = flipped.last_mut().unwrap();
    *last = if *last == b'0' { b'1' } else { b'0' };
    let flipped = String::from_utf8(flipped).unwrap();
    let invalid: Vec<String> = vec![
        flipped,
        format!("kh_agent_beta_{alpha_rand}"),
        format!("kh_agent_nobody_{alpha_rand}"),
        h.alpha.to_uppercase(),
        h.alpha[..h.alpha.len() - 1].to_owned(),
        format!("{}0", h.alpha),
        alpha_rand.clone(),
        "kh_agent_alpha_".to_owned(),
        "x".repeat(4096),
    ];
    for t in &invalid {
        for target in ["/v1/status", "/v1/items", "/v1/items?q=fixture"] {
            let r = get(addr, target, Some(t)).await;
            assert_eq!(r.status, 401, "{target} {t:.40}");
            assert_eq!(r.json(), ApiError::INVALID_TOKEN.body());
            assert_eq!(
                r.header("www-authenticate"),
                Some("Bearer realm=\"kharon\"")
            );
        }
    }
    // Missing, wrong scheme, empty, or ambiguous header: 401 too.
    let heads = [
        "GET /v1/items HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_owned(),
        format!(
            "GET /v1/items HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
            h.alpha
        ),
        format!(
            "GET /v1/items HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nConnection: close\r\n\r\n",
            h.alpha
        ),
        "GET /v1/items HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer \r\nConnection: close\r\n\r\n"
            .to_owned(),
        format!(
            "GET /v1/items HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            h.alpha, h.alpha
        ),
    ];
    for head in &heads {
        let r = raw_request(addr, head.as_bytes()).await;
        assert_eq!(r.status, 401, "{head:.60}");
        assert_eq!(r.json(), ApiError::MISSING_TOKEN.body());
    }
    // The scheme is case-insensitive (RFC 9110 §11.1).
    let ok = format!(
        "GET /v1/status HTTP/1.1\r\nHost: x\r\nAuthorization: bEaReR {}\r\nConnection: close\r\n\r\n",
        h.alpha
    );
    assert_eq!(raw_request(addr, ok.as_bytes()).await.status, 200);
    // Failed authentications never reach the audit trail as list/search.
    assert!(h.audit.summary().is_empty());
}

#[test]
fn req_api_003_token_store_has_no_plaintext_token() {
    // The token store is the config file. Write a real one with a
    // freshly minted token's hash (production Argon2id parameters:
    // the loader refuses anything below the floor), then grep it.
    let (token, hash) = generate("assistant");
    let token = token.expose_secret().clone();
    let random = token.rsplit_once('_').unwrap().1.to_owned();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("bw_api_key.json");
    std::fs::write(
        &key,
        r#"{"client_id":"user.6b1e0c52-0a3e-4a8e-9a4f-1f0e2d3c4b5a","client_secret":"s"}"#,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let toml = format!(
        "[bitwarden]\nserver = \"https://vault.example.net\"\nemail = \"kharon@example.net\"\n\
         api_key_file = \"{}\"\norganization_id = \"0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6\"\n\
         collection_ids = [\"11111111-2222-3333-4444-555555555555\"]\n\n\
         [agents.assistant]\ntoken_hash = \"{hash}\"\n\
         cdp = {{ endpoint = \"ws://10.66.0.2:9222\", via = \"wireguard\" }}\n\n\
         [policy]\n\n[approval]\nntfy = {{ url = \"https://ntfy.example.net\", topic = \"kharon\" }}\n\n\
         [memory]\nrequire_mlock = false\n",
        key.display()
    );
    let path = dir.path().join("kharon.toml");
    std::fs::write(&path, &toml).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains(&token), "plaintext token in the store");
    assert!(!text.contains(&random), "token random part in the store");
    assert!(!text.contains(TOKEN_PREFIX), "token prefix in the store");
    assert!(!text.contains(&random.to_uppercase()));
    assert!(
        text.contains("token_hash = \"$argon2id$"),
        "stored as Argon2id PHC"
    );

    // And the stored hash is what authenticates the token.
    let config = Config::load(&path).unwrap();
    let store = TokenStore::from_agents(&config.agents).unwrap();
    assert_eq!(store.authenticate(&token).unwrap(), "assistant");
    assert!(
        store
            .authenticate(&format!("kh_agent_assistant_{}", "0".repeat(64)))
            .is_err()
    );
}

/// REQ-API-003 floor at config load: a hash minted with weak Argon2id
/// parameters is a startup refusal, not a working token.
#[test]
fn req_api_003_config_refuses_weak_token_hash() {
    let (_token, weak) = generate_with(&cheap_argon(), "assistant");
    let toml = |hash: &str| {
        format!(
            "mode = \"export\"\n[export]\nfile = \"/data/export.json\"\n\
             [agents.assistant]\ntoken_hash = \"{hash}\"\n\
             cdp = {{ endpoint = \"ws://127.0.0.1:9222\" }}\n\
             [audit]\ncheckpoint_local_only = true\n"
        )
    };
    let err = Config::from_toml_str(&toml(&weak)).unwrap_err();
    assert_eq!(err.code(), "token_hash_weak_params", "{err:?}");
    assert!(!err.to_string().contains(&weak));
    // The floor itself (m=19456, t=2, p=1) is accepted.
    Config::from_toml_str(&toml(
        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo",
    ))
    .unwrap();
}
