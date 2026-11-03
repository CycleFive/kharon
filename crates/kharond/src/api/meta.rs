//! `ItemMeta` and the list/search filters (REQ-API-004; SPEC §4).
//!
//! [`ItemMeta`] is the only item shape the agent API returns. It is
//! built from a synced [`Item`]'s metadata class (REQ-CRY-006: name,
//! URIs, username) and never touches the item's protected fields: the
//! constructor has no access to a key, so it cannot decrypt one.
//! The username leaves the broker only as a masked hint (OQ-4).
//!
//! The `origin` filter runs the SPEC §6 matcher
//! ([`crate::origin::OriginMatcher`], #16) against each item URI with
//! the given origin as the page URL: an item is listed if at least one
//! of its URIs would be allowed to fill there. `origin` may be a bare
//! origin (`https://accounts.example.com`) or a full page URL, which
//! `exact` and `starts_with` items need to match. Fill re-checks the
//! live frame origin regardless (REQ-ORG-002); the filter is a
//! convenience, not a grant.

use serde::Serialize;
use url::Url;

use crate::origin::{MatchType, OriginConfig, OriginMatcher};
use crate::sync::Item;

/// SPEC §4 `ItemMeta`. Field set is pinned by the OpenAPI document
/// (`docs/api/openapi.json`) and the REQ-API-004 golden test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemMeta {
    /// Item id (lowercase UUID).
    pub id: String,
    /// Item name.
    pub name: String,
    /// Masked username, e.g. `j***@example.com` (OQ-4). Absent when
    /// the item has no username.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username_hint: Option<String>,
    /// URI hosts and their match types. URIs that can never fill
    /// (regex, never, unparseable) are omitted.
    pub uris: Vec<UriMeta>,
    /// The item has a password.
    pub has_password: bool,
    /// The item has a TOTP seed.
    pub has_totp: bool,
    /// Server revision date (RFC 3339). Absent if the server sent none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// One `ItemMeta.uris[]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UriMeta {
    /// Host (no scheme, path, or credentials).
    pub host: String,
    /// Effective match type.
    #[serde(rename = "match")]
    pub match_kind: MatchKind,
}

/// `ItemMeta.uris[].match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// eTLD+1 (Bitwarden `Domain`, also the default).
    Domain,
    /// Host and port.
    Host,
    /// Full URL.
    Exact,
    /// Host-equal plus URL prefix.
    StartsWith,
}

impl MatchKind {
    fn from_bw(repr: Option<u8>) -> Option<Self> {
        match MatchType::from_bw_repr(repr)? {
            MatchType::Domain => Some(Self::Domain),
            MatchType::Host => Some(Self::Host),
            MatchType::Exact => Some(Self::Exact),
            MatchType::StartsWith => Some(Self::StartsWith),
            MatchType::Regex | MatchType::Never => None,
        }
    }
}

/// OQ-4 default masking: first character, `***`, then the `@domain`
/// part if the username is an email address. Empty → `***`. A
/// one-character local part is not revealed at all (`***@domain`):
/// its first character would be the whole of it.
pub fn mask_username(username: &str) -> String {
    let (local, domain) = match username.rsplit_once('@') {
        Some((l, d)) => (l, (!d.is_empty()).then_some(d)),
        None => (username, None),
    };
    let mut chars = local.chars();
    let mut out = String::new();
    if let (Some(first), Some(_)) = (chars.next(), chars.next()) {
        out.push(first);
    }
    out.push_str("***");
    if let Some(d) = domain {
        out.push('@');
        out.push_str(d);
    }
    out
}

impl ItemMeta {
    /// Metadata view of a synced item.
    pub fn from_item(item: &Item) -> Self {
        let uris = item
            .uris()
            .iter()
            .filter_map(|u| {
                let match_kind = MatchKind::from_bw(u.match_type)?;
                let host = Url::parse(&u.uri).ok()?.host_str()?.to_owned();
                Some(UriMeta { host, match_kind })
            })
            .collect();
        Self {
            id: item.id().to_owned(),
            name: item.name().to_owned(),
            username_hint: item.username().filter(|u| !u.is_empty()).map(mask_username),
            uris,
            has_password: item.has_password(),
            has_totp: item.has_totp(),
            revision: item.revision().map(str::to_owned),
        }
    }
}

/// REQ-API-004 origin filter: some URI of `item` may fill at `origin`.
pub fn matches_origin(item: &Item, origin: &str, cfg: &OriginConfig) -> bool {
    item.uris().iter().any(|u| {
        OriginMatcher::new(&u.uri, u.match_type).is_ok_and(|m| m.decide(origin, cfg).allowed)
    })
}

/// Search predicate: case-insensitive substring of the item name or
/// of a URI host. The username is deliberately not searched: a
/// substring oracle over it would undo the OQ-4 mask one character at
/// a time.
pub fn matches_query(item: &Item, q: &str) -> bool {
    let q = q.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    item.name().to_lowercase().contains(&q)
        || item.uris().iter().any(|u| {
            Url::parse(&u.uri)
                .ok()
                .and_then(|url| url.host_str().map(|h| h.to_lowercase().contains(&q)))
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::mask_username;

    #[test]
    fn req_api_004_username_hint_is_masked() {
        assert_eq!(mask_username("jane@example.com"), "j***@example.com");
        assert_eq!(mask_username("jane"), "j***");
        assert_eq!(mask_username("@example.com"), "***@example.com");
        assert_eq!(mask_username("a@b@example.com"), "a***@example.com");
        assert_eq!(mask_username("jane@"), "j***");
        assert_eq!(mask_username("ünï@x.y"), "ü***@x.y");
        assert_eq!(mask_username(""), "***");
    }

    #[test]
    fn req_api_004_single_char_local_part_not_revealed() {
        assert_eq!(mask_username("j@example.com"), "***@example.com");
        assert_eq!(mask_username("j"), "***");
        assert_eq!(mask_username("j@"), "***");
        assert_eq!(mask_username("ü@x.y"), "***@x.y");
        assert_eq!(mask_username("jo@example.com"), "j***@example.com");
    }
}
