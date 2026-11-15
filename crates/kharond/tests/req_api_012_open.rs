//! REQ-API-012: `kharon_open` returns only `target_id` and the live
//! origin. A canary in the saved URI's path, query and fragment is
//! absent from the tool result and from the audit log. `kharon_search`
//! stays metadata (REQ-API-004).

mod api_support;

use std::collections::BTreeSet;
use std::sync::Arc;

use api_support::*;
use kharond::api::fill::FillPolicy;
use kharond::api::http::OPENAPI_JSON;
use kharond::api::{Broker, OpenResult};
use kharond::lock::{LockController, LockPolicy, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::sync::{ItemUri, SyncReport, Vault};
use serde_json::Value;

const PATH_CANARY: &str = "KHARON_OPEN_PATH_CANARY";
const QUERY_CANARY: &str = "KHARON_OPEN_QUERY_CANARY";
const FRAG_CANARY: &str = "KHARON_OPEN_FRAG_CANARY";

fn schema(name: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let doc: Value = serde_json::from_str(OPENAPI_JSON).unwrap();
    let s = &doc["components"]["schemas"][name];
    assert_eq!(
        s["additionalProperties"],
        Value::Bool(false),
        "{name} is closed"
    );
    let props = s["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let required = s["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    (props, required)
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().unwrap().keys().cloned().collect()
}

fn assert_no_url_canary(text: &str) {
    assert!(!text.contains(PATH_CANARY), "path canary leaked: {text}");
    assert!(!text.contains(QUERY_CANARY), "query canary leaked: {text}");
    assert!(
        !text.contains(FRAG_CANARY),
        "fragment canary leaked: {text}"
    );
    assert!(!text.contains("user:secret"), "userinfo leaked: {text}");
}

struct Rig {
    broker: Arc<TestBroker>,
    alpha: String,
    audit: RecordingAudit,
    fake: FakeFill,
}

impl Rig {
    fn new() -> Self {
        let (session, vault) = fixture();
        let uri = format!(
            "https://user:secret@app.example.com/{PATH_CANARY}?q={QUERY_CANARY}#{FRAG_CANARY}"
        );
        let item = vault.get(ITEM_B).unwrap().with_uris(vec![ItemUri {
            uri,
            match_type: None,
        }]);
        let vault = Vault::with_report(vec![item], SyncReport::default());
        let (alpha, hash) = kharond::api::token::generate_with(&cheap_argon(), "alpha");
        let tokens =
            kharond::api::token::TokenStore::with_floor([("alpha", hash.as_str())], &CHEAP_FLOOR)
                .unwrap();
        let clock = Arc::new(kharond::lock::ManualClock::new());
        let mut lock = LockController::new(
            LockPolicy::default(),
            clock,
            Box::new(StaticHardening::all_ok()),
        );
        lock.unlock(|| Ok::<_, ()>(TestSession(Arc::new(vault), session.clone())))
            .unwrap();
        let audit = RecordingAudit::default();
        let fake = FakeFill::new(FakeAnswer::Filled);
        let broker = Broker::new(
            tokens,
            lock,
            Box::new(audit.clone()),
            OriginConfig::default(),
        )
        .with_fill_policy(FillPolicy::default())
        .with_fill_backend(Box::new(fake.clone()));
        Self {
            broker: Arc::new(broker),
            alpha: alpha.expose_secret().clone(),
            audit,
            fake,
        }
    }
}

#[test]
fn req_api_012_open_result_type_is_the_schema() {
    let full = OpenResult {
        target_id: "t".into(),
        origin: "https://app.example.com".into(),
    };
    let v = serde_json::to_value(&full).unwrap();
    assert_eq!(keys(&v), schema("OpenResult").0);
    assert_eq!(v["origin"], "https://app.example.com");
}

#[tokio::test]
async fn req_api_012_golden_response_is_target_and_origin_and_canary_is_absent() {
    let (props, required) = schema("OpenResult");
    assert_eq!(
        props,
        BTreeSet::from(["target_id".to_owned(), "origin".to_owned()])
    );
    let rig = Rig::new();
    let addr = serve_http(rig.broker.clone()).await;
    let body = format!(r#"{{"item_id":"{ITEM_B}"}}"#);

    let http = post_json(addr, "/v1/open", Some(&rig.alpha), &body).await;
    assert_eq!(http.status, 200, "{}", http.body);
    assert_no_url_canary(&http.body);
    assert_no_canary(&http.body);
    let http_json = http.json();
    let k = keys(&http_json);
    assert_eq!(k, props, "extra or missing keys {k:?}");
    assert!(required.is_subset(&k));
    assert_eq!(http_json["target_id"], "tab-open");
    assert_eq!(http_json["origin"], "https://app.example.com");

    let mcp = mcp_call(addr, Some(&rig.alpha), "kharon_open", &body).await;
    assert_eq!(mcp.status, 200, "{}", mcp.body);
    let v = mcp.json();
    assert_eq!(v["result"]["isError"], false, "{v}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, http.body.trim());
    assert_no_url_canary(text);
    assert_no_url_canary(&mcp.body);

    // The broker did navigate to the saved URL. Only the result hides it.
    let opened = rig.fake.opened.lock().unwrap().clone();
    assert_eq!(opened.len(), 2, "http and mcp each open a tab");
    for url in &opened {
        assert!(url.contains(PATH_CANARY), "{url}");
        assert!(url.contains(QUERY_CANARY), "{url}");
        assert!(url.contains(FRAG_CANARY), "{url}");
        assert!(!url.contains("secret"), "{url}");
    }

    let audit = serde_json::to_string(&*rig.audit.entries.lock().unwrap()).unwrap();
    assert_no_url_canary(&audit);
    assert!(audit.contains("\"event\":\"open\"") || audit.contains("open"));

    // REQ-API-004 is unchanged: search still returns the host only.
    let listed = get(addr, "/v1/items?q=fixture", Some(&rig.alpha)).await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    assert_no_url_canary(&listed.body);
    let item = &listed.json()[0];
    assert_eq!(item["uris"][0]["host"], "app.example.com");
    assert!(item["uris"][0].get("path").is_none());
}

#[tokio::test]
async fn req_api_012_no_login_url_does_not_open() {
    let (session, vault) = fixture();
    let item = vault.get(ITEM_A).unwrap().with_uris(vec![
        ItemUri {
            uri: format!("login.example.com/{PATH_CANARY}?q={QUERY_CANARY}"),
            match_type: None,
        },
        ItemUri {
            uri: format!("https://login.example.com/{PATH_CANARY}?q={QUERY_CANARY}"),
            match_type: Some(4),
        },
        ItemUri {
            uri: format!("http://login.example.com/{PATH_CANARY}"),
            match_type: None,
        },
    ]);
    let vault = Vault::with_report(vec![item], SyncReport::default());
    let (alpha, hash) = kharond::api::token::generate_with(&cheap_argon(), "alpha");
    let tokens =
        kharond::api::token::TokenStore::with_floor([("alpha", hash.as_str())], &CHEAP_FLOOR)
            .unwrap();
    let clock = Arc::new(kharond::lock::ManualClock::new());
    let mut lock = LockController::new(
        LockPolicy::default(),
        clock,
        Box::new(StaticHardening::all_ok()),
    );
    lock.unlock(|| Ok::<_, ()>(TestSession(Arc::new(vault), session.clone())))
        .unwrap();
    let audit = RecordingAudit::default();
    let fake = FakeFill::new(FakeAnswer::Filled);
    let broker = Arc::new(
        Broker::new(
            tokens,
            lock,
            Box::new(audit.clone()),
            OriginConfig::default(),
        )
        .with_fill_backend(Box::new(fake.clone())),
    );
    let alpha = alpha.expose_secret().clone();
    let addr = serve_http(broker).await;
    let body = format!(r#"{{"item_id":"{ITEM_A}"}}"#);
    let http = post_json(addr, "/v1/open", Some(&alpha), &body).await;
    assert_eq!(http.status, 403, "{}", http.body);
    assert_eq!(http.json()["error"], "no_login_url");
    assert_no_url_canary(&http.body);
    let mcp = mcp_call(addr, Some(&alpha), "kharon_open", &body).await;
    let v = mcp.json();
    assert_eq!(v["result"]["isError"], true, "{v}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"error\":\"no_login_url\""), "{text}");
    assert_no_url_canary(text);
    assert!(
        fake.opened.lock().unwrap().is_empty(),
        "refused open navigated"
    );
    let audit = serde_json::to_string(&*audit.entries.lock().unwrap()).unwrap();
    assert_no_url_canary(&audit);
}
