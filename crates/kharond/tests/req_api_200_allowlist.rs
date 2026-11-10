//! #200 per-agent tool allow-list and revocation immediacy.
//!
//! A token is bound to one agent identity (the id is in the token
//! and selects the hash — it cannot be presented as another agent),
//! and an agent's allow-list binds that identity to a tool set:
//! `tools/list` is filtered, calls outside the list are refused 403
//! `tool_not_allowed` on both transports, and the owner's revoke
//! refuses the very next request — no cache window anywhere (auth
//! and the allow-list are read fresh per request).

mod api_support;

use api_support::{Harness, get, mcp_call, mcp_request, serve_http};
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
    // Beta is untouched by alpha's revocation.
    let r = get(addr, "/v1/status", Some(&h.beta)).await;
    assert_eq!(r.status, 200, "{}", r.body);
}
