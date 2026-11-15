//! `kharon_open` / `POST /v1/open` (REQ-API-012, #351).
//!
//! The agent names an item. The broker opens that item's saved login
//! URL in a new tab in the agent's own browser context and returns
//! only the tab's target id and live origin. The path, query and
//! fragment stay in the broker: they are not in the result, and they
//! are not written to a log line.
//!
//! A saved URI counts only when it is a full `https` URL the SPEC §6
//! matcher would allow as a page at that same URL. A bare host, a
//! non-https URI, and the `regex` and `never` match types do not.
//! With none, the call is `no_login_url` and nothing is navigated.
//! kharon does not guess a login page.
//!
//! Opening a tab does not approve a fill. The fill that follows still
//! needs its grant, and the grant-time live-origin check still runs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::error::{ApiError, Detail};
use super::fill::canonical_uuid;
use crate::origin::OriginMatcher;
use crate::sync::Item;

/// `kharon_open` arguments.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct OpenArgs {
    /// The item whose saved login URL to open.
    pub item_id: String,
}

/// `kharon_open` success body. Exactly these two fields: the new tab
/// and its live origin (scheme, host, port).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct OpenResult {
    /// CDP target id of the new tab. It belongs to the calling agent.
    pub target_id: String,
    /// The tab's live origin, `https://host[:port]`.
    pub origin: String,
}

/// The first saved URI that is a full https URL the origin matcher
/// would allow at that URL, with userinfo removed. `None` when nothing
/// qualifies. The returned string still has the path, query and
/// fragment: it is the navigation target, not a tool result, and must
/// not be logged.
pub fn verifiable_login_url(item: &Item) -> Option<String> {
    item.uris().iter().find_map(|u| {
        let matcher = OriginMatcher::new(&u.uri, u.match_type).ok()?;
        if !matcher.verifiable_https_login() {
            return None;
        }
        Some(matcher.navigation_url())
    })
}

/// Validate `kharon_open` arguments. The body is the HTTP body and the
/// MCP arguments object.
pub fn parse_open(json: &[u8]) -> Result<String, ApiError> {
    if json.iter().all(u8::is_ascii_whitespace) {
        return Err(ApiError::bad_request(Detail::InvalidOpenRequest));
    }
    let args: OpenArgs = serde_json::from_slice(json).map_err(|e| match e.classify() {
        serde_json::error::Category::Data => ApiError::bad_request(Detail::InvalidOpenRequest),
        _ => ApiError::bad_request(Detail::InvalidJsonBody),
    })?;
    canonical_uuid(&args.item_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::ItemUri;

    fn item(uris: Vec<(&str, Option<u8>)>) -> Item {
        Item::from_parts(
            "aaaaaaaa-0000-4000-8000-0000000000b1".into(),
            "n".into(),
            None,
            uris.into_iter()
                .map(|(uri, match_type)| ItemUri {
                    uri: uri.to_owned(),
                    match_type,
                })
                .collect(),
            None,
            None,
            None,
        )
    }

    #[test]
    fn https_url_is_the_navigation_target_and_userinfo_is_stripped() {
        let url = verifiable_login_url(&item(vec![(
            "https://user:secret@login.example.com/KHARON_OPEN_PATH_CANARY?q=KHARON_OPEN_QUERY_CANARY#KHARON_OPEN_FRAG_CANARY",
            None,
        )]))
        .unwrap();
        assert!(url.starts_with("https://login.example.com/KHARON_OPEN_PATH_CANARY?"));
        assert!(url.contains("KHARON_OPEN_QUERY_CANARY"));
        assert!(url.contains("KHARON_OPEN_FRAG_CANARY"));
        assert!(!url.contains("secret"));
        assert!(!url.contains("user"));
    }

    #[test]
    fn bare_host_regex_http_and_never_do_not_qualify() {
        assert!(verifiable_login_url(&item(vec![("login.example.com", None)])).is_none());
        assert!(
            verifiable_login_url(&item(vec![(
                "https://login.example.com/KHARON_OPEN_PATH_CANARY?q=KHARON_OPEN_QUERY_CANARY",
                Some(4),
            )]))
            .is_none()
        );
        assert!(
            verifiable_login_url(&item(vec![(
                "http://login.example.com/KHARON_OPEN_PATH_CANARY",
                None,
            )]))
            .is_none()
        );
        assert!(
            verifiable_login_url(&item(vec![("https://login.example.com/login", Some(5),)]))
                .is_none()
        );
    }

    #[test]
    fn the_first_verifiable_uri_wins() {
        let url = verifiable_login_url(&item(vec![
            ("login.example.com", None),
            (
                "https://login.example.com/first?q=KHARON_OPEN_QUERY_CANARY",
                Some(3),
            ),
            ("https://other.example.com/second", None),
        ]))
        .unwrap();
        assert!(url.contains("/first"));
        assert!(!url.contains("/second"));
    }
}
