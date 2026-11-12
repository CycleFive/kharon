//! REQ-OAU-006 / REQ-OAU-007 (#232): scope enforcement and the
//! phase-1 `no_browser` refusal for Connect identities.
//!
//! An OAuth access token's `AgentId` carries its granted scope
//! set; the broker checks every call against the bundles
//! (REQ-OAU-006) on top of #200's allow-list, `tools/list` shows
//! only what the scopes allow, and a Connect — which has no CDP
//! endpoint in phase 1 — gets `forbidden` / `no_browser` for
//! context and fills, before any fill backend is consulted
//! (REQ-OAU-007). The `[policy]` limits are keyed by agent id, so
//! they bind a `c-…` id exactly like a config agent's.

mod api_support;

use std::sync::Arc;

use api_support::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use kharond::api::grant::{GrantAction, GrantRequestArgs};
use kharond::api::oauth::Discovery;
use kharond::api::oauth_store::{CodeGrant, ConnectLifecycle, OauthStore};
use kharond::api::rate::RatePolicy;
use kharond::api::revocation::DurableState;
use kharond::api::token::{TokenStore, generate_with};
use kharond::api::{ApiError, Broker, Detail, ErrorCode, FillOperation, FillRequest, Request};
use kharond::audit::{AuditConfig, AuditLog, Entry, Event, NullCheckpointSink};
use kharond::cdp::fill::FieldKind;
use kharond::lock::{LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The lifecycle seam, permissive: these tests exercise
/// enforcement, not the audit contents (covered in
/// `api::oauth_store`'s tests).
struct AllowAll;

impl ConnectLifecycle for AllowAll {
    fn append(&self, _entry: Entry) -> bool {
        true
    }
    fn connect_ended(&self, _agent_id: &str) {}
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An OAuth store with no Connects yet. The backing tempdir is
/// leaked: the store keeps an in-memory image for the test's life
/// (test processes are short-lived).
fn empty_store() -> Arc<OauthStore> {
    let dir = tempfile::tempdir().unwrap();
    let store = OauthStore::load(dir.path()).unwrap();
    std::mem::forget(dir);
    store.set_lifecycle(Arc::new(AllowAll));
    Arc::new(store)
}

/// Redeem a code on `store`, creating a Connect with `scopes`;
/// returns its access token and `c-…` identity. `tag` keeps each
/// Connect's code and verifier distinct on a shared store.
fn add_connect(store: &OauthStore, tag: &str, scopes: &[&str]) -> (String, String) {
    let verifier = format!("verifier-{tag}");
    let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(verifier.as_bytes()));
    let grant = CodeGrant {
        client_id: "https://dashboard.example/.well-known/kharon-client.json".to_owned(),
        client_name: "Dashboard".to_owned(),
        code_challenge: challenge,
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        consented_at: unix_now(),
    };
    let code_hash: [u8; 32] = Sha256::digest(format!("code-{tag}").as_bytes()).into();
    let pair = store
        .connect(&grant, &verifier, code_hash, unix_now())
        .unwrap();
    let auth = store
        .authenticate_access(&pair.access_token, unix_now())
        .unwrap();
    (pair.access_token, auth.agent_id)
}

/// A store holding a single Connect with `scopes`.
fn live_connect(scopes: &[&str]) -> (Arc<OauthStore>, String, String) {
    let store = empty_store();
    let (access, agent_id) = add_connect(&store, "solo", scopes);
    (store, access, agent_id)
}

fn tool_names(list_reply: &Value) -> Vec<&str> {
    list_reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect()
}

/// The `{"error", "detail"}` body of a failed `tools/call`.
fn tool_error(call_reply: &Value) -> Value {
    assert_eq!(call_reply["result"]["isError"], true, "{call_reply}");
    let text = call_reply["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

fn fill_req(operation: FillOperation) -> FillRequest {
    let kind = match operation {
        FillOperation::Fill => FieldKind::Username,
        FillOperation::FillTotp => FieldKind::Totp,
    };
    FillRequest {
        operation,
        item_id: ITEM_A.to_owned(),
        target_id: "target-1".to_owned(),
        expected_origin: "https://example.com".to_owned(),
        fields: vec![(kind, None)],
        submit: false,
        grant_id: None,
    }
}

fn grant_args() -> GrantRequestArgs {
    GrantRequestArgs {
        item_id: ITEM_A.to_owned(),
        target_id: "target-1".to_owned(),
        expected_origin: "https://example.com".to_owned(),
        action: GrantAction::Fill,
    }
}

const ALL_SCOPES: [&str; 3] = ["kharon:read", "kharon:fill", "kharon:request"];

#[test]
fn agent_id_carries_the_connects_scope_set() {
    let (store, access, agent_id) = live_connect(&["kharon:read"]);
    let h = Harness::with(false, |b| b.with_oauth_store(store));

    // The OAuth token's identity carries its scopes (I3).
    let agent = h.broker.authenticate_on_mcp(&access).unwrap();
    assert_eq!(agent.as_str(), agent_id);
    assert!(agent_id.starts_with("c-"), "{agent_id}");
    assert_eq!(
        agent.scopes().map(|s| s.join(" ")),
        Some("kharon:read".to_owned())
    );
    assert!(agent.is_connect());

    // A config agent carries none: #200's allow-list alone
    // decides for it.
    let alpha = h.broker.authenticate(&h.alpha).unwrap();
    assert_eq!(alpha.scopes(), None);
    assert!(!alpha.is_connect());

    // The combined gate: the Connect passes its bundle's tools
    // and nothing else; the config agent passes on its (here
    // unrestricted) allow-list.
    assert!(h.broker.tool_allowed(&agent, "kharon_status"));
    assert!(h.broker.tool_allowed(&agent, "kharon_search"));
    assert!(!h.broker.tool_allowed(&agent, "kharon_fill"));
    assert!(!h.broker.tool_allowed(&agent, "kharon_request_grant"));
    assert!(h.broker.tool_allowed(&alpha, "kharon_fill"));
}

#[tokio::test]
async fn tools_list_returns_only_the_tokens_scope_tools() {
    let store = empty_store();
    let (read_only, _) = add_connect(&store, "ro", &["kharon:read"]);
    let (read_request, _) = add_connect(&store, "rr", &["kharon:read", "kharon:request"]);
    let (full, _) = add_connect(&store, "full", &ALL_SCOPES);
    let h = Harness::with(false, |b| b.with_oauth_store(store));
    let addr = serve_http(h.broker.clone()).await;

    // REQ-OAU-006's acceptance shape: a read-only token lists
    // exactly the read bundle's three tools.
    let r = mcp_request(addr, Some(&read_only), "tools/list", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    let mut names = tool_names(&v);
    names.sort_unstable();
    assert_eq!(names, ["kharon_list", "kharon_search", "kharon_status"]);

    // Bundles compose: read + request adds kharon_request_grant
    // and still hides the fill bundle.
    let r = mcp_request(addr, Some(&read_request), "tools/list", "{}").await;
    let v = r.json();
    let mut names = tool_names(&v);
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "kharon_list",
            "kharon_request_grant",
            "kharon_search",
            "kharon_status"
        ]
    );

    // All three scopes (and an unrestricted config agent) see
    // the full registry.
    for token in [&full, &h.alpha] {
        let r = mcp_request(addr, Some(token), "tools/list", "{}").await;
        assert_eq!(tool_names(&r.json()).len(), 7, "{}", r.body);
    }
}

#[tokio::test]
async fn tools_list_for_an_empty_scope_set_is_empty() {
    // Fail closed: a Connect whose token carries no scopes at all
    // lists nothing (and could call nothing).
    let (store, access, _) = live_connect(&[]);
    let h = Harness::with(false, |b| b.with_oauth_store(store));
    let addr = serve_http(h.broker.clone()).await;
    let r = mcp_request(addr, Some(&access), "tools/list", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(tool_names(&r.json()).is_empty(), "{}", r.body);
}

#[tokio::test]
async fn out_of_scope_calls_get_insufficient_scope() {
    let (store, access, _) = live_connect(&["kharon:read"]);
    let discovery = Discovery::new("https://kharon-owner.example".to_owned(), "kharon.example");
    let h = Harness::with(false, |b| {
        b.with_oauth_store(store).with_oauth(discovery.clone())
    });
    let addr = serve_http(h.broker.clone()).await;

    // On the wire (REQ-OAU-001's acceptance): a read-only token
    // calling a fill-bundle tool gets the RFC 6750 step-up — HTTP
    // 403 and the challenge naming the error and every scope the
    // retry needs (the granted `kharon:read` plus the missing
    // `kharon:fill`), so the client can re-authorize and call
    // again. The refusal is the scope one, not `no_browser`: the
    // scope gate is checked first. The body stays the tool-error
    // result.
    let r = mcp_call(addr, Some(&access), "kharon_context", "{}").await;
    assert_eq!(r.status, 403, "{}", r.body);
    let challenge = r.header("www-authenticate").expect("step-up challenge");
    assert_eq!(
        challenge,
        discovery.step_up_challenge(&["kharon:read".to_owned()], "kharon:fill")
    );
    assert!(
        challenge.contains("error=\"insufficient_scope\""),
        "{challenge}"
    );
    assert!(
        challenge.contains("scope=\"kharon:read kharon:fill\""),
        "{challenge}"
    );
    assert!(
        challenge.contains(
            "resource_metadata=\"https://kharon.example/.well-known/oauth-protected-resource/mcp\""
        ),
        "{challenge}"
    );
    let err = tool_error(&r.json());
    assert_eq!(err["error"], "insufficient_scope", "{err}");
    assert_eq!(
        err["detail"],
        "token does not have the scope this tool needs"
    );

    // Its own bundle still works, in the plain 200 shape.
    let r = mcp_call(addr, Some(&access), "kharon_status", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["result"]["isError"], false, "{}", r.body);

    // At the broker, the same refusal for the other bundles, as
    // the typed error.
    let agent = h.broker.authenticate_on_mcp(&access).unwrap();
    assert_eq!(
        h.broker
            .fill_from(
                &agent,
                fill_req(FillOperation::Fill),
                tokio::time::Instant::now(),
                None
            )
            .await,
        Err(ApiError::INSUFFICIENT_SCOPE)
    );
    assert_eq!(
        h.broker
            .request_grant_from(&agent, grant_args(), tokio::time::Instant::now(), None)
            .await,
        Err(ApiError::INSUFFICIENT_SCOPE)
    );
    // And an in-scope dispatch is untouched by the scope gate.
    assert!(
        h.broker
            .dispatch(
                &agent,
                Request::Search {
                    q: "example".to_owned(),
                    origin: None,
                },
            )
            .is_ok()
    );
}

#[tokio::test]
async fn connect_context_and_fills_answer_no_browser_without_a_backend() {
    let (store, access, _) = live_connect(&ALL_SCOPES);
    let fake = FakeFill::new(FakeAnswer::Filled);
    let probe = fake.clone();
    let h = Harness::with(false, |b| {
        b.with_oauth_store(store)
            .with_fill_backend(Box::new(fake))
            .with_oauth(Discovery::new(
                "https://kharon-owner.example".to_owned(),
                "kharon.example",
            ))
    });
    let agent = h.broker.authenticate_on_mcp(&access).unwrap();

    // REQ-OAU-007: forbidden / no_browser, as the typed error,
    // for all three browser tools — even with the fill scope
    // granted.
    assert_eq!(ApiError::NO_BROWSER.code, ErrorCode::Forbidden);
    assert_eq!(ApiError::NO_BROWSER.detail, Detail::NoBrowser);
    assert_eq!(
        h.broker
            .context_from(&agent, tokio::time::Instant::now(), None)
            .await,
        Err(ApiError::NO_BROWSER)
    );
    for op in [FillOperation::Fill, FillOperation::FillTotp] {
        assert_eq!(
            h.broker
                .fill_from(&agent, fill_req(op), tokio::time::Instant::now(), None)
                .await,
            Err(ApiError::NO_BROWSER)
        );
    }

    // Never falls back: the fill backend saw nothing at all.
    assert!(probe.seen().is_empty());
    assert!(probe.context_calls.lock().unwrap().is_empty());

    // On the wire the refusal keeps the plain tool-result shape —
    // HTTP 200, `forbidden` / `no_browser`, no step-up challenge:
    // the step-up answers scope refusals only, and this token
    // holds every scope.
    let addr = serve_http(h.broker.clone()).await;
    let r = mcp_call(addr, Some(&access), "kharon_context", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.header("www-authenticate"), None);
    let err = tool_error(&r.json());
    assert_eq!(err["error"], "forbidden", "{err}");
    assert_eq!(err["detail"], "this connection has no browser attached yet");
    assert!(probe.context_calls.lock().unwrap().is_empty());

    // A config agent is unaffected: its context call reaches the
    // backend as before.
    let alpha = h.broker.authenticate(&h.alpha).unwrap();
    assert!(
        h.broker
            .context_from(&alpha, tokio::time::Instant::now(), None)
            .await
            .is_ok()
    );
    assert_eq!(
        probe.context_calls.lock().unwrap().as_slice(),
        ["alpha".to_owned()]
    );
}

#[test]
fn connect_list_calls_draw_on_the_list_budget() {
    let (store, access, _) = live_connect(&ALL_SCOPES);
    let policy = RatePolicy {
        list_per_minute: 2,
        ..RatePolicy::default()
    };
    let h = Harness::with(false, |b| {
        b.with_oauth_store(store).with_rate_policy(policy)
    });
    let agent = h.broker.authenticate_on_mcp(&access).unwrap();

    // REQ-OAU-007: the [policy] list budget binds the c-… id
    // like a config agent's.
    let list = Request::List { origin: None };
    assert!(h.broker.dispatch(&agent, list.clone()).is_ok());
    assert!(h.broker.dispatch(&agent, list.clone()).is_ok());
    assert_eq!(h.broker.dispatch(&agent, list), Err(ApiError::RATE_LIMITED));
}

#[test]
fn a_suspended_connect_is_refused_until_the_owner_resets_it() {
    let (store, access, agent_id) = live_connect(&ALL_SCOPES);

    // A previous run's log ends with this Connect suspended
    // (the REQ-RL-002 streak entry, as #132 rebuilds it).
    let dir = tempfile::tempdir().unwrap();
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir_all(&audit_dir).unwrap();
    let log_path = audit_dir.join("audit.jsonl");
    {
        let mut log = AuditLog::open(
            &audit_dir,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        log.append(
            Entry::new(Event::RateLimit)
                .agent_id(agent_id.clone())
                .result("suspended")
                .detail_code("origin_mismatch_streak"),
        )
        .unwrap();
    }

    // A fresh broker over that log, seeded from it exactly as
    // the daemon seeds its own, with the OAuth store attached.
    let (alpha, alpha_hash) = generate_with(&cheap_argon(), "alpha");
    let _ = alpha;
    let tokens = TokenStore::with_floor([("alpha", alpha_hash.as_str())], &CHEAP_FLOOR).unwrap();
    let clock = Arc::new(ManualClock::new());
    let mut lock = LockController::new(
        LockPolicy::default(),
        clock,
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| Ok::<_, ()>(TestSession::fixture())).unwrap();
    let audit = AuditLog::open(
        &audit_dir,
        AuditConfig::default(),
        Box::new(NullCheckpointSink),
    )
    .unwrap();
    let broker = Broker::new(tokens, lock, Box::new(audit), OriginConfig::default())
        .with_oauth_store(store)
        .with_durable_state(DurableState::from_log(&log_path).unwrap());

    // The suspension binds the c-… id…
    let agent = broker.authenticate_on_mcp(&access).unwrap();
    assert_eq!(
        broker.dispatch(&agent, Request::List { origin: None }),
        Err(ApiError::RATE_LIMITED)
    );
    // …and the owner's reset clears it, by id, as for a config
    // agent.
    broker.unsuspend_agent(&agent_id).unwrap();
    assert!(
        broker
            .dispatch(&agent, Request::List { origin: None })
            .is_ok()
    );
}
