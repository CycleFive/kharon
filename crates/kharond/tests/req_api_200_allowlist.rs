//! #200 per-agent tool allow-list and revocation immediacy.
//!
//! A token is bound to one agent identity (the id is in the token
//! and selects the hash — it cannot be presented as another agent),
//! and an agent's allow-list binds that identity to a tool set:
//! `tools/list` is filtered, calls outside the list are refused 403
//! `tool_not_allowed` on both transports, and the owner's revoke
//! refuses the very next request on `/v1` and `/mcp` — no cache
//! window anywhere (auth and the allow-list are read fresh per
//! request).

mod api_support;

use api_support::{Harness, ITEM_A, get, mcp_call, mcp_request, post_json, serve_http};
use serde_json::Value;

fn tool_names(list_reply: &Value) -> Vec<&str> {
    list_reply["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn allow_list_filters_tools_list_and_refuses_calls() {
    let h = Harness::with_alpha_tools(false, Some(vec!["kharon_status".to_owned()]));
    let addr = serve_http(h.broker.clone()).await;

    // Alpha sees only its tool.
    let r = mcp_request(addr, Some(&h.alpha), "tools/list", "{}").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(tool_names(&r.json()), ["kharon_status"]);

    // Beta (unrestricted) sees the full registry.
    let r = mcp_request(addr, Some(&h.beta), "tools/list", "{}").await;
    assert_eq!(tool_names(&r.json()).len(), 7);

    // Alpha calling outside its list: a tool error, 403 shape.
    let r = mcp_call(addr, Some(&h.alpha), "kharon_list", "{}").await;
    let v = r.json();
    assert_eq!(v["result"]["isError"], true, "{v}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    let err: Value = serde_json::from_str(text).unwrap();
    assert_eq!(err["error"], "forbidden");
    assert_eq!(err["detail"], "tool not in the agent's allow-list");

    // Alpha's own tool still works, and beta's list call works.
    let r = mcp_call(addr, Some(&h.alpha), "kharon_status", "{}").await;
    assert_eq!(r.json()["result"]["isError"], false, "{}", r.body);
    let r = mcp_call(addr, Some(&h.beta), "kharon_list", "{}").await;
    assert_eq!(r.json()["result"]["isError"], false, "{}", r.body);

    // The same list binds the /v1 transport: status yes, items no.
    let r = get(addr, "/v1/status", Some(&h.alpha)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = get(addr, "/v1/items", Some(&h.alpha)).await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(r.json()["detail"], "tool not in the agent's allow-list");
}

/// Parse an MCP tool call's error body and assert it is the
/// allow-list refusal (403 shape carried in-band).
fn assert_mcp_forbidden(r: &api_support::RawResponse) {
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!(v["result"]["isError"], true, "{v}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    let err: Value = serde_json::from_str(text).unwrap();
    assert_eq!(err["error"], "forbidden", "{err}");
    assert_eq!(err["detail"], "tool not in the agent's allow-list", "{err}");
}

/// Duet's R1 on PR #238: the refusal must hold for *every* tool
/// outside the list, not just `kharon_list` — a client can call a
/// tool it was never shown, so `tools/list` filtering is not the
/// enforcement. Each refusal happens in the broker before any state
/// is read, so it leaves no audit entry behind: deleting any one
/// `require_tool` line (above all `kharon_fill`'s) fails this test.
#[tokio::test]
async fn allow_list_refuses_every_other_tool_on_both_transports() {
    let h = Harness::with_alpha_tools(false, Some(vec!["kharon_status".to_owned()]));
    let addr = serve_http(h.broker.clone()).await;
    let audited = || h.audit.entries.lock().unwrap().len();
    let before = audited();

    let fill = format!(
        r#"{{"item_id":"{ITEM_A}","target":{{"cdp_target_id":"tab-1","expected_origin":"https://login.example.com"}},"fields":[{{"kind":"password"}}]}}"#
    );
    let grant = format!(
        r#"{{"item_id":"{ITEM_A}","target":{{"cdp_target_id":"tab-1","expected_origin":"https://login.example.com"}}}}"#
    );
    // `fill_totp` takes no `fields` (it defaults to the one totp field).
    let totp = format!(
        r#"{{"item_id":"{ITEM_A}","target":{{"cdp_target_id":"tab-1","expected_origin":"https://login.example.com"}}}}"#
    );

    // /mcp: each of the five remaining tools, with valid arguments
    // (argument parsing precedes the broker, so only a valid call
    // reaches the allow-list check).
    for (tool, args) in [
        ("kharon_search", r#"{"q":"example"}"#),
        ("kharon_fill", &fill),
        ("kharon_fill_totp", &totp),
        ("kharon_context", "{}"),
        ("kharon_request_grant", &grant),
    ] {
        let r = mcp_call(addr, Some(&h.alpha), tool, args).await;
        assert_mcp_forbidden(&r);
        assert_eq!(audited(), before, "{tool} refusal wrote an audit entry");
    }

    // /v1 alike (REQ-API-011's AC): the same restricted token is
    // refused 403 with the allow-list detail on every other route.
    for (path, body) in [
        ("/v1/fill", fill.as_str()),
        ("/v1/fill_totp", totp.as_str()),
        ("/v1/context", "{}"),
        ("/v1/grants", grant.as_str()),
    ] {
        let r = post_json(addr, path, Some(&h.alpha), body).await;
        assert_eq!(r.status, 403, "{path}: {}", r.body);
        assert_eq!(
            r.json()["detail"],
            "tool not in the agent's allow-list",
            "{path}"
        );
        assert_eq!(audited(), before, "{path} refusal wrote an audit entry");
    }
    // Search rides the items route with a query.
    let r = get(addr, "/v1/items?q=example", Some(&h.alpha)).await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(r.json()["detail"], "tool not in the agent's allow-list");
    assert_eq!(audited(), before, "search refusal wrote an audit entry");
}

#[tokio::test]
async fn revoke_refuses_the_next_request_immediately() {
    let h = Harness::new(false);
    let addr = serve_http(h.broker.clone()).await;

    let agent = h.broker.authenticate(&h.alpha).unwrap();
    assert!(h.broker.tool_allowed(&agent, "kharon_fill"));

    h.broker.revoke_agent("alpha").unwrap();

    assert!(
        h.broker.authenticate(&h.alpha).is_err(),
        "the same token, one call later, no longer authenticates"
    );
    let r = get(addr, "/v1/status", Some(&h.alpha)).await;
    assert_eq!(r.status, 401, "{}", r.body);
    // REQ-API-011: revocation is read fresh per request in the
    // broker, so both transports are bound. One `/mcp` call with
    // the same token is 401 as well (#239 N6).
    let r = mcp_call(addr, Some(&h.alpha), "kharon_status", "{}").await;
    assert_eq!(r.status, 401, "{}", r.body);
    // Beta is untouched by alpha's revocation.
    let r = get(addr, "/v1/status", Some(&h.beta)).await;
    assert_eq!(r.status, 200, "{}", r.body);
}
