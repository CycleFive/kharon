//! REQ-API-004: list/search return `ItemMeta` only, filtered by
//! `origin` if given. AC: golden test — response keys ⊆ the ItemMeta
//! schema (the OpenAPI document's, which REQ-API-002 pins to the
//! routes); canary absent.

mod api_support;

use std::collections::BTreeSet;

use api_support::*;
use kharond::api::ItemMeta;
use kharond::api::http::OPENAPI_JSON;
use kharond::api::meta::{MatchKind, UriMeta};
use serde_json::Value;

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

#[test]
fn req_api_004_item_meta_type_is_the_schema() {
    // A fully-populated ItemMeta serializes to exactly the schema's
    // properties; the golden test below then holds for any instance.
    let full = ItemMeta {
        id: "x".into(),
        name: "n".into(),
        username_hint: Some("u***".into()),
        uris: vec![UriMeta {
            host: "h".into(),
            match_kind: MatchKind::StartsWith,
        }],
        has_password: true,
        has_totp: true,
        revision: Some("2026-11-02T00:00:00Z".into()),
    };
    let v = serde_json::to_value(&full).unwrap();
    assert_eq!(keys(&v), schema("ItemMeta").0);
    assert_eq!(keys(&v["uris"][0]), schema("UriMeta").0);
    assert_eq!(v["uris"][0]["match"], "starts_with");
}

#[tokio::test]
async fn req_api_004_golden_response_keys_within_item_meta_and_no_canary() {
    let (item_props, item_req) = schema("ItemMeta");
    let (uri_props, uri_req) = schema("UriMeta");
    let doc: Value = serde_json::from_str(OPENAPI_JSON).unwrap();
    let match_enum: BTreeSet<String> =
        doc["components"]["schemas"]["UriMeta"]["properties"]["match"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();

    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;
    let mut seen = 0;
    for target in [
        "/v1/items",
        "/v1/items?origin=https%3A%2F%2Flogin.example.com",
        "/v1/items?origin=https%3A%2F%2Fapp.example.com%2Flogin",
        "/v1/items?q=fixture",
        "/v1/items?q=example&origin=https%3A%2F%2Fapp.example.com",
    ] {
        let r = get(addr, target, Some(&h.alpha)).await;
        assert_eq!(r.status, 200, "{target}");
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_no_canary(&r.body);
        // No ciphertext either: nothing EncString-shaped.
        assert!(!r.body.contains("2."), "{target}: {}", r.body);
        for item in r.json().as_array().unwrap() {
            seen += 1;
            let k = keys(item);
            assert!(k.is_subset(&item_props), "{target}: extra keys {k:?}");
            assert!(item_req.is_subset(&k), "{target}: missing required keys");
            for u in item["uris"].as_array().unwrap() {
                let k = keys(u);
                assert!(k.is_subset(&uri_props) && uri_req.is_subset(&k));
                assert!(match_enum.contains(u["match"].as_str().unwrap()));
                let host = u["host"].as_str().unwrap();
                assert!(!host.contains('/') && !host.contains(':') && !host.contains('@'));
            }
            let hint = item["username_hint"].as_str().unwrap();
            assert!(hint.contains("***"), "{hint}");
        }
    }
    assert!(seen > 6, "the golden test saw items");
}

#[test]
fn req_api_004_item_meta_from_fixture() {
    let v = fixture_vault();
    let metas: Vec<ItemMeta> = v.items().map(ItemMeta::from_item).collect();
    let by_id = |id: &str| metas.iter().find(|m| m.id == id).unwrap();
    for m in &metas {
        assert!(m.has_password && !m.has_totp);
        assert_eq!(m.username_hint.as_deref(), Some("f***@example.com"));
    }
    // Regex and never URIs can never fill: omitted, not mislabelled.
    assert!(by_id(REGEX_CLONE).uris.is_empty());
    assert!(by_id(NEVER_CLONE).uris.is_empty());
    assert_eq!(
        by_id(HOST_CLONE).uris,
        vec![UriMeta {
            host: "login.example.com".into(),
            match_kind: MatchKind::Host
        }]
    );
    assert_eq!(
        by_id(EXACT_CLONE).uris,
        vec![UriMeta {
            host: "app.example.com".into(),
            match_kind: MatchKind::Exact
        }]
    );
    let names: BTreeSet<&str> = metas.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(
        names,
        BTreeSet::from(["fixture-no-cipher-key", "fixture-with-cipher-key"])
    );
    // Debug of ItemMeta has no canary either (it is logged in places).
    assert_no_canary(&format!("{metas:?}"));
}
