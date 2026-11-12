//! REQ-OAU-003 acceptance tests. Run inside `oauth` so they can open
//! sealed tokens and the in-memory code table.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use axum::http::{Method, StatusCode, header};
use axum::response::Response;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::super::store::Credential;
use super::super::webauthn::{P256_POINT_LEN, b64url_encode};
use super::super::{
    Incoming, NoApprovals, NoAudit, OwnerAudit, OwnerUi, OwnerUiOptions, ShellView, StaticShell,
};
use super::{
    AuthorizeBudget, CODE_TTL, CONNECT_NOTICE, CodeStore, OauthAs, PENDING_PURPOSE, PENDING_TTL,
    Scope, consent_challenge, parse_query,
};
use crate::api::cimd::{ClientAdmission, RefusalAudit};
use crate::api::oauth::Discovery;
use crate::audit::{Entry, Event};

const ORIGIN: &str = "https://owner.example";
const RP_ID: &str = "owner.example";
const CLIENT_ID: &str = "https://dashboard.example/client.json";
const REDIRECT: &str = "https://dashboard.example/cb";
const RESOURCE: &str = "https://kharon.example/mcp";

fn discovery() -> Discovery {
    Discovery::new(ORIGIN.to_owned(), "kharon.example")
}

/// One valid CIMD for [`CLIENT_ID`] whose only redirect is [`REDIRECT`].
fn cimd_document(name: &str, redirects: &[&str]) -> String {
    let uris = redirects
        .iter()
        .map(|uri| format!("\"{uri}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"client_id":"{CLIENT_ID}","client_name":"{name}","redirect_uris":[{uris}],"token_endpoint_auth_method":"none"}}"#
    )
}

fn listed_document() -> Result<(String, Option<String>), ()> {
    Ok((
        cimd_document("Muse", &[REDIRECT]),
        Some("max-age=86400".into()),
    ))
}

struct SilentAudit;

impl RefusalAudit for SilentAudit {
    fn client_refused(&self, _: Entry) {}
}

struct Recorded(Mutex<Vec<Entry>>);

impl Recorded {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Vec::new())))
    }

    fn entries(&self) -> Vec<Entry> {
        self.0.lock().unwrap().clone()
    }
}

impl RefusalAudit for Recorded {
    fn client_refused(&self, entry: Entry) {
        self.0.lock().unwrap().push(entry);
    }
}

fn admission(
    outcomes: Vec<Result<(String, Option<String>), ()>>,
    audit: Arc<dyn RefusalAudit>,
) -> Arc<ClientAdmission> {
    Arc::new(ClientAdmission::from_canned(
        &[CLIENT_ID.to_owned()],
        outcomes,
        audit,
    ))
}

fn fixture() -> Arc<ClientAdmission> {
    admission(vec![listed_document()], Arc::new(SilentAudit))
}

fn open_ui(
    clients: Arc<ClientAdmission>,
    audit: Arc<dyn OwnerAudit>,
    public: bool,
) -> (Arc<OwnerUi>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let ui = OwnerUi::open_with(
        dir.path(),
        OwnerUiOptions {
            rp_id: RP_ID.into(),
            origin: ORIGIN.into(),
            public,
            access: None,
            oauth: Some(OauthAs {
                discovery: Arc::new(discovery()),
            }),
            admission: Some(clients),
            oauth_tokens: None,
        },
        Arc::new(StaticShell(ShellView {
            locked: false,
            pending: 0,
        })),
        audit,
        Arc::new(NoApprovals),
    )
    .unwrap();
    (ui, dir)
}

fn ui() -> (Arc<OwnerUi>, tempfile::TempDir) {
    open_ui(fixture(), Arc::new(NoAudit), false)
}

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    thread_local! {
        static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
    }
    RT.with(|rt| rt.block_on(fut))
}

fn body_of(response: Response) -> (StatusCode, String, Option<String>) {
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    assert_oauth_frame(&response);
    let bytes = block_on(axum::body::to_bytes(response.into_body(), 64 * 1024)).unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap(), location)
}

fn incoming(
    method: Method,
    path: &str,
    query: Option<&str>,
    cookie: Option<&str>,
    body: &str,
) -> Incoming {
    Incoming {
        method,
        path: path.into(),
        cookie: cookie.map(str::to_owned),
        origin: Some(ORIGIN.into()),
        authorization: None,
        content_type: Some("application/json".into()),
        body: body.as_bytes().to_vec(),
        client_ip: None,
        throttle_key: None,
        query: query.map(str::to_owned),
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn challenge() -> String {
    b64url_encode(&[7u8; 32])
}

fn valid_query(scope: &str, state: &str) -> String {
    form(&[
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT),
        ("code_challenge", &challenge()),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("resource", RESOURCE),
        ("scope", scope),
    ])
}

fn assert_oauth_frame(response: &Response) {
    let framed = response
        .headers()
        .get(header::X_FRAME_OPTIONS)
        .and_then(|v| v.to_str().ok())
        == Some("DENY");
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(framed, "X-Frame-Options");
    assert!(csp.contains("frame-ancestors 'none'"), "csp: {csp}");
}

fn plain_body(response: Response) -> (StatusCode, String, Option<String>) {
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = block_on(axum::body::to_bytes(response.into_body(), 64 * 1024)).unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap(), location)
}

fn authorize(ui: &OwnerUi, query: &str) -> (StatusCode, String, Option<String>) {
    authorize_req(
        ui,
        incoming(Method::GET, "/oauth/authorize", Some(query), None, ""),
    )
}

fn authorize_req(ui: &OwnerUi, req: Incoming) -> (StatusCode, String, Option<String>) {
    body_of(block_on(ui.authorize_response(&req)))
}

fn param(url: &str, key: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    let query = query.split('#').next().unwrap_or(query);
    parse_query(query)?
        .one(key)
        .ok()
        .flatten()
        .map(str::to_owned)
}

fn consent_token(location: &str) -> &str {
    location
        .strip_prefix("/oauth/consent/")
        .expect("consent location")
}

#[test]
fn steps_1_to_3_never_redirect_and_each_refusal_is_one_audit_entry() {
    let not_listed = "This dashboard is not on this kharon's allow-list.";
    let unavailable = "We couldn't check this dashboard. Try again in a minute.";
    let mismatch = "The address this dashboard sent does not match its client metadata.";
    let invalid = "This dashboard's client metadata is not valid.";

    // A bad client wins over a bad response_type: no redirect, the
    // attacker-supplied id is not echoed, and admit writes one entry.
    let audit = Recorded::new();
    let (ui, _dir) = open_ui(
        admission(vec![listed_document()], audit.clone()),
        Arc::new(NoAudit),
        false,
    );
    let evil = form(&[
        ("client_id", "https://evil.example/<script>"),
        ("response_type", "token"),
        ("redirect_uri", "https://evil.example/phish"),
    ]);
    let (status, page, location) = authorize(&ui, &evil);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(location.is_none(), "{location:?}");
    assert!(page.contains(not_listed));
    assert!(!page.contains("evil.example"));
    assert!(!page.contains("<script>"));
    assert_one_refusal(&audit.entries(), "not_allowlisted", Some("evil.example"));
    // The same refusal again is one more entry, not a second write of the first.
    let (_status, _page, location) = authorize(&ui, &evil);
    assert!(location.is_none());
    assert_eq!(audit.entries().len(), 2);

    // Listed, but the fetch fails closed: unavailable, still no redirect,
    // and the wrong redirect is not consulted first.
    let unavailable_audit = Recorded::new();
    let (ui, _dir) = open_ui(
        admission(vec![Err(())], unavailable_audit.clone()),
        Arc::new(NoAudit),
        false,
    );
    let (status, page, location) = authorize(
        &ui,
        &form(&[
            ("client_id", CLIENT_ID),
            ("redirect_uri", "https://evil.example/phish"),
            ("response_type", "token"),
        ]),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(location.is_none(), "{location:?}");
    assert!(page.contains(unavailable));
    assert!(!page.contains("evil.example"));
    assert_one_refusal(
        &unavailable_audit.entries(),
        "cimd_unavailable",
        Some("dashboard.example"),
    );

    // The document does not validate: one cimd_invalid, no redirect.
    let invalid_audit = Recorded::new();
    let (ui, _dir) = open_ui(
        admission(vec![Ok(("not json".into(), None))], invalid_audit.clone()),
        Arc::new(NoAudit),
        false,
    );
    let (status, page, location) = authorize(
        &ui,
        &form(&[
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT),
            ("response_type", "code"),
        ]),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(location.is_none(), "{location:?}");
    assert!(page.contains(invalid));
    assert_one_refusal(
        &invalid_audit.entries(),
        "cimd_invalid",
        Some("dashboard.example"),
    );

    // Exact redirect mismatch, after a document we do have. A repeat
    // is a cache hit and still exactly one new entry.
    let mismatch_audit = Recorded::new();
    let (listed, _listed_dir) = open_ui(
        admission(vec![listed_document()], mismatch_audit.clone()),
        Arc::new(NoAudit),
        false,
    );
    let mismatch_query = form(&[
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", "https://dashboard.example/other"),
        ("code_challenge", &challenge()),
        ("code_challenge_method", "S256"),
        ("state", "xyz"),
        ("resource", RESOURCE),
    ]);
    let (status, page, location) = authorize(&listed, &mismatch_query);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(location.is_none(), "{location:?}");
    assert!(page.contains(mismatch));
    assert!(!page.contains("other"));
    assert_one_refusal(
        &mismatch_audit.entries(),
        "redirect_mismatch",
        Some("dashboard.example"),
    );
    let (_status, _page, location) = authorize(&listed, &mismatch_query);
    assert!(location.is_none());
    assert_eq!(mismatch_audit.entries().len(), 2);
    assert_eq!(
        mismatch_audit.entries()[1].detail_code.as_deref(),
        Some("redirect_mismatch")
    );

    // A request that reaches consent writes no refusal.
    let quiet = Recorded::new();
    let (ui, _dir) = open_ui(
        admission(vec![listed_document()], quiet.clone()),
        Arc::new(NoAudit),
        false,
    );
    let (status, _page, location) = authorize(&ui, &valid_query("kharon:fill", "xyz"));
    assert_eq!(status, StatusCode::FOUND);
    assert!(location.unwrap().starts_with("/oauth/consent/"));
    assert!(quiet.entries().is_empty());
}

/// One `oauth_client_refused` entry, the shape admission writes.
fn assert_one_refusal(entries: &[Entry], detail: &str, origin: Option<&str>) {
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0];
    assert_eq!(entry.event, Event::OauthClientRefused);
    assert_eq!(entry.detail_code.as_deref(), Some(detail));
    assert_eq!(entry.result.as_deref(), Some("refused"));
    assert_eq!(entry.channel.as_deref(), Some("web_ui"));
    assert_eq!(entry.origin.as_deref(), origin);
    assert!(entry.agent_id.is_none());
    let value = serde_json::to_value(entry).unwrap();
    assert_eq!(value["event"], "oauth_client_refused");
    assert_eq!(value["detail_code"], detail);
    let event: Event = serde_json::from_value(value["event"].clone()).unwrap();
    assert_eq!(event, Event::OauthClientRefused);
}

/// The production handler, not the sync dispatch: one refusal, one entry.
#[tokio::test]
async fn the_http_handler_audits_one_refusal() {
    let audit = Recorded::new();
    let (ui, _dir) = open_ui(
        admission(vec![listed_document()], audit.clone()),
        Arc::new(NoAudit),
        false,
    );
    let state = Arc::new(super::super::OwnerServer {
        ui,
        redeem: Arc::new(NoRedeem),
    });
    let req = axum::http::Request::builder()
        .uri("/oauth/authorize?client_id=https%3A%2F%2Fevil.example%2Fcimd.json")
        .body(axum::body::Body::empty())
        .unwrap();
    let peer: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let response = super::super::handle(
        axum::extract::State(state),
        axum::extract::ConnectInfo(peer),
        req,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::LOCATION).is_none());
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let page = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(page.contains("not on this kharon's allow-list"));
    assert!(!page.contains("evil.example"));
    assert_one_refusal(&audit.entries(), "not_allowlisted", Some("evil.example"));
}

struct NoRedeem;

impl crate::api::http::ApprovalRedeemer for NoRedeem {
    fn prompt(
        &self,
        _token: &str,
    ) -> Result<
        (
            crate::api::grant::ApprovalPrompt,
            crate::api::approval::ApprovalAction,
        ),
        crate::api::approval::TokenGone,
    > {
        Err(crate::api::approval::TokenGone::Unknown)
    }

    fn redeem(
        &self,
        _token: &str,
    ) -> Result<crate::api::approval::ApprovalAction, crate::api::approval::TokenGone> {
        Err(crate::api::approval::TokenGone::Unknown)
    }
}

#[test]
fn steps_4_to_7_redirect_with_error_state_and_iss() {
    let (ui, _dir) = ui();
    let challenge = challenge();
    let base = |response_type, method, resource, scope| {
        form(&[
            ("response_type", response_type),
            ("client_id", CLIENT_ID),
            ("redirect_uri", REDIRECT),
            ("code_challenge", &challenge),
            ("code_challenge_method", method),
            ("state", "s t"),
            ("resource", resource),
            ("scope", scope),
        ])
    };
    let cases = [
        (
            base("token", "S256", RESOURCE, "kharon:fill"),
            "unsupported_response_type",
        ),
        (
            base("code", "plain", RESOURCE, "kharon:fill"),
            "invalid_request",
        ),
        (
            base(
                "code",
                "S256",
                "https://kharon.example/connector",
                "kharon:fill",
            ),
            "invalid_target",
        ),
        (
            base("code", "S256", RESOURCE, "kharon:fill kharon:nope"),
            "invalid_scope",
        ),
    ];
    for (query, error) in cases {
        let (status, _page, location) = authorize(&ui, &query);
        assert_eq!(status, StatusCode::FOUND, "{error}");
        let location = location.expect(error);
        assert_eq!(
            param(&location, "error").as_deref(),
            Some(error),
            "{location}"
        );
        assert_eq!(
            param(&location, "state").as_deref(),
            Some("s t"),
            "{location}"
        );
        assert_eq!(
            param(&location, "iss").as_deref(),
            Some(ORIGIN),
            "{location}"
        );
        assert!(param(&location, "code").is_none(), "{location}");
        assert!(location.starts_with(REDIRECT), "{location}");
    }
}

#[test]
fn a_valid_request_seals_a_pending_authorization_and_stores_nothing() {
    let (ui, dir) = ui();
    let (status, _page, location) = authorize(&ui, &valid_query("kharon:fill", "xyz"));
    assert_eq!(status, StatusCode::FOUND);
    let location = location.unwrap();
    assert!(location.starts_with("/oauth/consent/"), "{location}");
    assert!(!location.contains("code="));
    let token = consent_token(&location).to_owned();
    let opened = ui.open_pending(&token, std::time::Instant::now()).unwrap();
    assert_eq!(opened.claims.client_name, "Muse");
    assert_eq!(opened.claims.client_host, "dashboard.example");
    assert_eq!(opened.claims.redirect_host, "dashboard.example");
    assert_eq!(opened.claims.scopes, vec![Scope::Read, Scope::Fill]);
    assert!(ui.codes.redeem("nope", std::time::Instant::now()).is_none());
    // A thousand more do not evict it: nothing was stored at authorize.
    for _ in 0..1000 {
        let (_s, _b, loc) = authorize(&ui, &valid_query("kharon:read", "xyz"));
        assert!(loc.unwrap().starts_with("/oauth/consent/"));
    }
    assert!(ui.open_pending(&token, std::time::Instant::now()).is_some());
    let now = std::time::Instant::now();
    let early = ui
        .sealed
        .seal(PENDING_PURPOSE, &opened.claims, PENDING_TTL, now);
    assert!(
        ui.open_pending(
            &early,
            now + PENDING_TTL - std::time::Duration::from_millis(1)
        )
        .is_some()
    );
    assert!(ui.open_pending(&early, now + PENDING_TTL).is_none());
    // A new process has a new key: the token does not survive a restart.
    let (other, _dir2) = open_ui(fixture(), Arc::new(NoAudit), false);
    assert!(
        other
            .open_pending(&token, std::time::Instant::now())
            .is_none()
    );
    // And nothing under data_dir holds the token.
    let token_hit = walk_contains(dir.path(), &token);
    assert!(!token_hit, "pending token was written to disk");
    let _ = dir;
}

#[test]
fn consent_page_signs_in_first_then_shows_plain_words() {
    let (ui, _dir) = ui();
    let (_s, _b, location) = authorize(&ui, &valid_query("kharon:fill kharon:request", "xyz"));
    let token = consent_token(&location.unwrap()).to_owned();
    let path = format!("/oauth/consent/{token}");
    let (status, page, location) =
        body_of(ui.dispatch(incoming(Method::GET, &path, None, None, "")));
    assert_eq!(status, StatusCode::OK);
    assert!(location.is_none());
    assert!(page.contains("Sign in with a passkey"));
    assert!(page.contains(&path));
    assert!(
        !page.contains("Muse"),
        "client name is not shown before sign-in"
    );

    let cookie = cookie_of(&ui.issue_session(&[0x11; 16]));
    let (status, page, _) =
        body_of(ui.dispatch(incoming(Method::GET, &path, None, Some(&cookie), "")));
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(CONNECT_NOTICE));
    assert!(page.contains("Connect a dashboard"));
    assert!(page.contains("/oauth/consent/view"));
    assert!(page.contains("/oauth/consent/approve"));
    assert!(page.contains("/oauth/consent/deny"));
    assert!(!page.to_ascii_lowercase().contains("innerhtml"));

    let view_body = json!({"pending": token}).to_string();
    let (status, view, location) = body_of(ui.dispatch(incoming(
        Method::POST,
        "/oauth/consent/view",
        None,
        Some(&cookie),
        &view_body,
    )));
    assert_eq!(status, StatusCode::OK, "{view}");
    assert!(location.is_none());
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!(view["client_name"], "Muse");
    assert_eq!(view["client_host"], "dashboard.example");
    assert_eq!(view["redirect_host"], "dashboard.example");
    assert_eq!(view["notice"], CONNECT_NOTICE);
    let ids: Vec<&str> = view["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["kharon:read", "kharon:fill", "kharon:request"]);
    assert_eq!(view["scopes"][0]["optional"], false);
    assert_eq!(view["scopes"][1]["optional"], true);
    assert!(
        view["scopes"][1]["words"]
            .as_str()
            .unwrap()
            .contains("You approve every sign-in here first.")
    );
}

#[test]
fn approve_needs_a_fresh_assertion_and_issues_one_code() {
    let (ui, dir) = ui();
    let mut auth = enroll(&ui);
    let cookie = sign_in(&ui, &mut auth);
    let token = start(&ui, "kharon:fill");
    // No assertion: refused, and the pending authorization is still open.
    let (status, body, location) = post(
        &ui,
        "/oauth/consent/approve",
        &cookie,
        &json!({
            "pending": token,
            "ceremony_id": "nope",
            "nonce": "aa",
            "credential": {"type": "public-key"},
            "scopes": ["kharon:read"]
        })
        .to_string(),
    );
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(location.is_none());
    assert!(ui.open_pending(&token, std::time::Instant::now()).is_some());

    // An assertion for a different pending authorization is refused.
    // A different `state` keeps the sealed tokens from colliding when
    // two requests land in the same millisecond.
    let other = start_state(&ui, "kharon:fill", "other");
    let (ceremony, nonce, challenge) = options(&ui, &cookie, &token);
    let cred = auth.assertion(&challenge, ORIGIN, RP_ID);
    let (status, body, _) = post(
        &ui,
        "/oauth/consent/approve",
        &cookie,
        &json!({
            "pending": other,
            "ceremony_id": ceremony,
            "nonce": nonce,
            "credential": cred,
            "scopes": ["kharon:read", "kharon:fill"]
        })
        .to_string(),
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(ui.open_pending(&token, std::time::Instant::now()).is_some());
    assert!(ui.open_pending(&other, std::time::Instant::now()).is_some());

    // Adding a scope that was not requested is refused and does not burn.
    let (ceremony, nonce, challenge) = options(&ui, &cookie, &token);
    let cred = auth.assertion(&challenge, ORIGIN, RP_ID);
    let (status, body, _) = post(
        &ui,
        "/oauth/consent/approve",
        &cookie,
        &json!({
            "pending": token,
            "ceremony_id": ceremony,
            "nonce": nonce,
            "credential": cred,
            "scopes": ["kharon:read", "kharon:fill", "kharon:request"]
        })
        .to_string(),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(ui.open_pending(&token, std::time::Instant::now()).is_some());

    // Unticking fill grants read only. The code is the whole identity.
    let (ceremony, nonce, challenge) = options(&ui, &cookie, &token);
    let cred = auth.assertion(&challenge, ORIGIN, RP_ID);
    let (status, body, location) = post(
        &ui,
        "/oauth/consent/approve",
        &cookie,
        &json!({
            "pending": token,
            "ceremony_id": ceremony,
            "nonce": nonce,
            "credential": cred,
            "scopes": ["kharon:read"]
        })
        .to_string(),
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(location.is_none(), "the code is not in a Location header");
    let redirect = serde_json::from_str::<Value>(&body).unwrap()["redirect"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(redirect.starts_with(REDIRECT), "{redirect}");
    let code = param(&redirect, "code").unwrap();
    assert_eq!(param(&redirect, "state").as_deref(), Some("xyz"));
    assert_eq!(param(&redirect, "iss").as_deref(), Some(ORIGIN));
    assert!(param(&redirect, "error").is_none());
    let raw = b64_decode(&code);
    assert_eq!(raw.len(), 32, "32 random bytes");
    let record = ui
        .codes
        .redeem(&code, std::time::Instant::now())
        .expect("code");
    assert_eq!(record.client_id, CLIENT_ID);
    assert_eq!(record.client_name, "Muse");
    assert_eq!(record.redirect_uri, REDIRECT);
    assert_eq!(record.code_challenge, challenge_b64());
    assert_eq!(record.resource, RESOURCE);
    assert_eq!(record.scope_param(), "kharon:read");
    assert!(ui.codes.redeem(&code, std::time::Instant::now()).is_none());
    let later = std::time::Instant::now() + CODE_TTL + std::time::Duration::from_secs(1);
    // A second copy was not kept; expiry is covered on a fresh code below.
    let _ = later;
    assert!(
        !walk_contains(dir.path(), &code),
        "code was written to disk"
    );
    let mode = std::fs::metadata(dir.path().join("owner/passkeys.json"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "passkey store mode follows the file, not the umask"
    );

    // The pending authorization is single use.
    let (ceremony, nonce, challenge) = options(&ui, &cookie, &token);
    let cred = auth.assertion(&challenge, ORIGIN, RP_ID);
    let (status, body, _) = post(
        &ui,
        "/oauth/consent/approve",
        &cookie,
        &json!({
            "pending": token,
            "ceremony_id": ceremony,
            "nonce": nonce,
            "credential": cred,
            "scopes": ["kharon:read", "kharon:fill"]
        })
        .to_string(),
    );
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("already_used"));
}

fn challenge_b64() -> String {
    challenge()
}

#[test]
fn deny_burns_the_pending_authorization_and_creates_nothing() {
    let (ui, _dir) = ui();
    let mut auth = enroll(&ui);
    let cookie = sign_in(&ui, &mut auth);
    let token = start(&ui, "kharon:fill");
    let (status, body, location) = post(
        &ui,
        "/oauth/consent/deny",
        &cookie,
        &json!({"pending": token}).to_string(),
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(location.is_none());
    let redirect = serde_json::from_str::<Value>(&body).unwrap()["redirect"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(param(&redirect, "error").as_deref(), Some("access_denied"));
    assert_eq!(param(&redirect, "state").as_deref(), Some("xyz"));
    assert_eq!(param(&redirect, "iss").as_deref(), Some(ORIGIN));
    assert!(param(&redirect, "code").is_none());
    let (ceremony, nonce, challenge) = options(&ui, &cookie, &token);
    let cred = auth.assertion(&challenge, ORIGIN, RP_ID);
    let (status, body, location) = post(
        &ui,
        "/oauth/consent/approve",
        &cookie,
        &json!({
            "pending": token,
            "ceremony_id": ceremony,
            "nonce": nonce,
            "credential": cred,
            "scopes": ["kharon:read", "kharon:fill"]
        })
        .to_string(),
    );
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(location.is_none());
    assert!(
        ui.codes
            .redeem("anything", std::time::Instant::now())
            .is_none()
    );
}

#[test]
fn panic_clears_pending_authorizations_and_codes() {
    let (ui, _dir) = ui();
    let mut auth = enroll(&ui);
    let cookie = sign_in(&ui, &mut auth);
    let token = start(&ui, "kharon:fill");
    let code = approve_all(
        &ui,
        &mut auth,
        &cookie,
        &token,
        &["kharon:read", "kharon:fill"],
    );
    assert_eq!(
        ui.codes
            .redeem(&code, std::time::Instant::now())
            .unwrap()
            .scope_param(),
        "kharon:read kharon:fill"
    );
    // Re-issue so panic has something to drop. redeem consumed the first.
    let token = start(&ui, "kharon:request");
    let code = approve_all(&ui, &mut auth, &cookie, &token, &["kharon:read"]);
    let pending = start(&ui, "kharon:fill");
    ui.invalidate_sealed();
    assert!(
        ui.open_pending(&pending, std::time::Instant::now())
            .is_none()
    );
    assert!(ui.codes.redeem(&code, std::time::Instant::now()).is_none());
    // A code issued after the panic works: only the pre-panic ones died.
    let token = start(&ui, "kharon:fill");
    assert!(ui.open_pending(&token, std::time::Instant::now()).is_some());
}

#[test]
fn authorize_is_throttled_per_source_and_not_globally() {
    let (ui, _dir) = open_ui(fixture(), Arc::new(NoAudit), true);
    let query = valid_query("kharon:fill", "xyz");
    let one: std::net::IpAddr = "203.0.113.7".parse().unwrap();
    let other: std::net::IpAddr = "203.0.113.8".parse().unwrap();
    for _ in 0..30 {
        let mut req = incoming(Method::GET, "/oauth/authorize", Some(&query), None, "");
        req.throttle_key = Some(one);
        req.client_ip = Some(one);
        let (status, _, location) = authorize_req(&ui, req);
        assert_eq!(status, StatusCode::FOUND, "{location:?}");
    }
    let mut blocked = incoming(Method::GET, "/oauth/authorize", Some(&query), None, "");
    blocked.throttle_key = Some(one);
    let (status, body, location) = authorize_req(&ui, blocked);
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(location.is_none());
    let mut ok = incoming(Method::GET, "/oauth/authorize", Some(&query), None, "");
    ok.throttle_key = Some(other);
    let (status, _, location) = authorize_req(&ui, ok);
    assert_eq!(status, StatusCode::FOUND, "{location:?}");
    // No edge address: not throttled, and it does not share a bucket.
    for _ in 0..40 {
        let (status, _, _) = authorize(&ui, &query);
        assert_eq!(status, StatusCode::FOUND);
    }
}

#[test]
fn code_store_is_single_use_and_expires() {
    let store = CodeStore::new();
    let now = std::time::Instant::now();
    let body = super::CodeBody {
        client_id: CLIENT_ID.into(),
        client_name: "Muse".into(),
        redirect_uri: REDIRECT.into(),
        code_challenge: challenge(),
        resource: RESOURCE.into(),
        scopes: vec![Scope::Read, Scope::Fill],
        consented_at: 1,
    };
    let code = store.issue(body.clone(), now).unwrap();
    assert_eq!(b64_decode(&code).len(), 32);
    assert!(store.redeem(&code, now + CODE_TTL).is_none(), "expired");
    let code = store.issue(body, now).unwrap();
    assert!(store.redeem(&code, now).is_some());
    assert!(store.redeem(&code, now).is_none());
    store.clear();
    assert!(store.redeem(&code, now).is_none());
}

#[test]
fn consent_challenge_is_the_named_hash() {
    let pending_id = [1u8; 32];
    let nonce = [2u8; 32];
    let random = [3u8; 32];
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&pending_id);
    preimage.extend_from_slice(&nonce);
    preimage.extend_from_slice(&random);
    assert_eq!(
        consent_challenge(&pending_id, &nonce, &random)[..],
        Sha256::digest(&preimage)[..]
    );
    assert_ne!(
        consent_challenge(&pending_id, &nonce, &random),
        consent_challenge(&pending_id, &nonce, &[4u8; 32])
    );
}

#[test]
fn granted_scopes_stay_inside_the_request_and_keep_read() {
    let effective = [Scope::Read, Scope::Fill];
    assert_eq!(
        super::grant_scopes(&effective, &["kharon:read".into(), "kharon:fill".into()]).unwrap(),
        vec![Scope::Read, Scope::Fill]
    );
    assert_eq!(
        super::grant_scopes(&effective, &["kharon:read".into()]).unwrap(),
        vec![Scope::Read]
    );
    assert!(
        super::grant_scopes(&effective, &["kharon:read".into(), "kharon:request".into()]).is_none()
    );
    assert!(super::grant_scopes(&effective, &["not-a-scope".into()]).is_none());
    // Absent scope asks for all three. An empty present scope is read only.
    assert_eq!(super::parse_scopes(None).unwrap(), Scope::ALL.to_vec());
    assert_eq!(super::parse_scopes(Some("")).unwrap(), vec![Scope::Read]);
    assert!(super::parse_scopes(Some("kharon:fill kharon:nope")).is_err());
}

#[test]
fn without_oauth_the_routes_are_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let ui = OwnerUi::open(
        dir.path(),
        RP_ID,
        ORIGIN,
        Arc::new(StaticShell(ShellView {
            locked: false,
            pending: 0,
        })),
        Arc::new(NoAudit),
        Arc::new(NoApprovals),
    )
    .unwrap();
    let (status, _, location) = plain_body(ui.dispatch(incoming(
        Method::GET,
        "/oauth/authorize",
        Some(&valid_query("kharon:fill", "xyz")),
        None,
        "",
    )));
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(location.is_none());
}

#[test]
fn a_wrong_origin_does_not_approve() {
    let (ui, _dir) = ui();
    let mut auth = enroll(&ui);
    let cookie = sign_in(&ui, &mut auth);
    let token = start(&ui, "kharon:fill");
    let mut req = incoming(
        Method::POST,
        "/oauth/consent/deny",
        None,
        Some(&cookie),
        &json!({"pending": token}).to_string(),
    );
    req.origin = Some("https://evil.example".into());
    let (status, _, _) = body_of(ui.dispatch(req));
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(ui.open_pending(&token, std::time::Instant::now()).is_some());
}

fn start(ui: &OwnerUi, scope: &str) -> String {
    start_state(ui, scope, "xyz")
}

fn start_state(ui: &OwnerUi, scope: &str, state: &str) -> String {
    let (_s, _b, location) = authorize(ui, &valid_query(scope, state));
    consent_token(&location.unwrap()).to_owned()
}

fn post(
    ui: &OwnerUi,
    path: &str,
    cookie: &str,
    body: &str,
) -> (StatusCode, String, Option<String>) {
    body_of(ui.dispatch(incoming(Method::POST, path, None, Some(cookie), body)))
}

fn options(ui: &OwnerUi, cookie: &str, token: &str) -> (String, String, String) {
    let (status, body, _) = post(
        ui,
        "/oauth/consent/options",
        cookie,
        &json!({"pending": token}).to_string(),
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    (
        v["ceremony_id"].as_str().unwrap().to_owned(),
        v["nonce"].as_str().unwrap().to_owned(),
        v["publicKey"]["challenge"].as_str().unwrap().to_owned(),
    )
}

fn approve_all(
    ui: &OwnerUi,
    auth: &mut SoftKey,
    cookie: &str,
    token: &str,
    scopes: &[&str],
) -> String {
    let (ceremony, nonce, challenge) = options(ui, cookie, token);
    let cred = auth.assertion(&challenge, ORIGIN, RP_ID);
    let (status, body, location) = post(
        ui,
        "/oauth/consent/approve",
        cookie,
        &json!({
            "pending": token,
            "ceremony_id": ceremony,
            "nonce": nonce,
            "credential": cred,
            "scopes": scopes,
        })
        .to_string(),
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(location.is_none());
    let redirect = serde_json::from_str::<Value>(&body).unwrap()["redirect"]
        .as_str()
        .unwrap()
        .to_owned();
    param(&redirect, "code").unwrap()
}

fn cookie_of(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}

fn sign_in(ui: &OwnerUi, auth: &mut SoftKey) -> String {
    let (status, body, _) = plain_body(ui.dispatch(incoming(
        Method::POST,
        "/owner/login/options",
        None,
        None,
        "",
    )));
    assert_eq!(status, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    let ceremony = v["ceremony_id"].as_str().unwrap().to_owned();
    let challenge = v["publicKey"]["challenge"].as_str().unwrap().to_owned();
    let cred = auth.assertion(&challenge, ORIGIN, RP_ID);
    let response = ui.dispatch(incoming(
        Method::POST,
        "/owner/login/finish",
        None,
        None,
        &json!({"ceremony_id": ceremony, "credential": cred}).to_string(),
    ));
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let (status, body, _) = plain_body(response);
    assert_eq!(status, StatusCode::OK, "{body}");
    cookie_of(&set_cookie)
}

fn enroll(ui: &OwnerUi) -> SoftKey {
    let key = SoftKey::new();
    ui.passkeys
        .lock()
        .unwrap()
        .insert(Credential {
            id: key.cred_id.clone(),
            public_key: key.public_point(),
            sign_count: 0,
            enrolled_at: Some(1),
            last_used_at: None,
        })
        .unwrap();
    key
}

struct SoftKey {
    key: EcdsaKeyPair,
    cred_id: Vec<u8>,
    sign_count: u32,
}

impl SoftKey {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref()).unwrap();
        Self {
            key,
            cred_id: vec![0x11; 16],
            sign_count: 0,
        }
    }

    fn public_point(&self) -> [u8; P256_POINT_LEN] {
        let raw = self.key.public_key().as_ref();
        raw.try_into().expect("uncompressed P-256 point")
    }

    fn assertion(&mut self, challenge_b64: &str, origin: &str, rp_id: &str) -> Value {
        self.sign_count += 1;
        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
        );
        let mut auth = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth.push(0x01 | 0x04);
        auth.extend_from_slice(&self.sign_count.to_be_bytes());
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let sig = self
            .key
            .sign(&SystemRandom::new(), &message)
            .unwrap()
            .as_ref()
            .to_vec();
        json!({
            "id": b64url_encode(&self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(client.as_bytes()),
                "authenticatorData": b64url_encode(&auth),
                "signature": b64url_encode(&sig),
            }
        })
    }
}

fn b64_decode(s: &str) -> Vec<u8> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let mut buf = vec![0u8; s.len()];
    let n = Base64UrlUnpadded::decode(s, &mut buf).unwrap().len();
    buf.truncate(n);
    buf
}

fn walk_contains(dir: &std::path::Path, needle: &str) -> bool {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&path) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&p)
                && text.contains(needle)
            {
                return true;
            }
        }
    }
    false
}

// Keep the budget type referenced so a rename of the cap stays local.
#[test]
fn authorize_budget_forgets_the_oldest_source() {
    let budget = AuthorizeBudget::new();
    let now = std::time::Instant::now();
    let ip = |i: u16| std::net::IpAddr::from([203, 0, (i >> 8) as u8, i as u8]);
    for i in 0..1024u16 {
        assert!(budget.admit(ip(i), now).is_ok());
    }
    assert!(budget.admit(ip(1024), now).is_ok());
}
