//! What the kharon account can see, for `kharon setup` (#404) and
//! `kharon doctor` (#406).
//!
//! Built from one `/api/sync` response, from ids and plaintext metadata
//! only: organization ids and names, collection ids, and which items sit
//! where. Nothing is decrypted, so no master password is needed.
//! Collection *names* are encrypted under the org key and are therefore
//! not available here; a collection is shown by its id and item count.

use super::norm_id;
use super::wire::SyncResponse;

/// The account's view, ordered as the server listed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The account email the server reports, as sent; compare it
    /// case-insensitively.
    pub email: String,
    /// Organizations the account is a member of.
    pub orgs: Vec<DiscoveredOrg>,
    /// Items with no organization (personal vault items). A dedicated
    /// kharon account must have none (REQ-CRY-008).
    pub personal_items: usize,
}

/// One organization the account can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredOrg {
    /// Normalized (lowercase) id, as the config takes it.
    pub id: String,
    /// The plaintext display name, if the server sent one. Untrusted:
    /// strip control characters before printing.
    pub name: Option<String>,
    /// Collections in this org assigned to the account.
    pub collections: Vec<DiscoveredCollection>,
    /// Items in this org the account can see (not in the trash).
    pub items: usize,
}

/// One collection the account can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredCollection {
    /// Normalized (lowercase) id.
    pub id: String,
    /// Items in this collection (not in the trash).
    pub items: usize,
}

/// Summarize `sync` for a picker. Collections whose org is not in the
/// profile are dropped (the account could not use them anyway).
pub fn discover(sync: &SyncResponse) -> Discovery {
    let live = || {
        sync.ciphers
            .iter()
            .flatten()
            .filter(|c| c.deleted_date.is_none())
    };
    let orgs = sync
        .profile
        .organizations
        .iter()
        .flatten()
        .map(|o| {
            let id = norm_id(&o.id);
            let collections = sync
                .collections
                .iter()
                .flatten()
                .filter(|c| c.organization_id.as_deref().map(norm_id).as_deref() == Some(&id))
                .map(|c| {
                    let cid = norm_id(&c.id);
                    let items = live()
                        .filter(|x| x.collection_ids.iter().flatten().any(|k| norm_id(k) == cid))
                        .count();
                    DiscoveredCollection { id: cid, items }
                })
                .collect();
            let items = live()
                .filter(|x| x.organization_id.as_deref().map(norm_id).as_deref() == Some(&id))
                .count();
            DiscoveredOrg {
                id,
                name: o.name.clone(),
                collections,
                items,
            }
        })
        .collect();
    let personal_items = live().filter(|c| c.organization_id.is_none()).count();
    Discovery {
        email: sync.profile.email.clone(),
        orgs,
        personal_items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::wire::normalize_keys;

    fn sync(v: serde_json::Value) -> SyncResponse {
        serde_json::from_value(normalize_keys(v)).unwrap()
    }

    #[test]
    fn req_cry_008_discovery_lists_orgs_collections_and_counts() {
        // PascalCase, as Bitwarden cloud sends; ids in mixed case.
        let s = sync(serde_json::json!({
            "Profile": {
                "Id": "u1", "Email": "Kharon@Example.net",
                "Organizations": [
                    {"Id": "AAAA0000-0000-4000-8000-000000000001", "Name": "kharon", "Key": null},
                    {"Id": "bbbb0000-0000-4000-8000-000000000002"}
                ]
            },
            "Collections": [
                {"Id": "CCCC0000-0000-4000-8000-000000000001", "OrganizationId": "aaaa0000-0000-4000-8000-000000000001"},
                {"Id": "cccc0000-0000-4000-8000-000000000002", "OrganizationId": "aaaa0000-0000-4000-8000-000000000001"},
                {"Id": "cccc0000-0000-4000-8000-000000000009", "OrganizationId": "ffff0000-0000-4000-8000-000000000009"}
            ],
            "Ciphers": [
                {"Id": "i1", "Type": 1, "OrganizationId": "aaaa0000-0000-4000-8000-000000000001",
                 "CollectionIds": ["cccc0000-0000-4000-8000-000000000001"]},
                {"Id": "i2", "Type": 1, "OrganizationId": "aaaa0000-0000-4000-8000-000000000001",
                 "CollectionIds": ["cccc0000-0000-4000-8000-000000000001"], "DeletedDate": "2026-10-01T00:00:00Z"},
                {"Id": "i3", "Type": 1, "OrganizationId": null, "CollectionIds": []}
            ]
        }));
        let d = discover(&s);
        assert_eq!(d.email, "Kharon@Example.net");
        assert_eq!(d.personal_items, 1);
        assert_eq!(d.orgs.len(), 2);
        let k = &d.orgs[0];
        assert_eq!(k.id, "aaaa0000-0000-4000-8000-000000000001");
        assert_eq!(k.name.as_deref(), Some("kharon"));
        assert_eq!(k.items, 1, "the trashed item is not counted");
        assert_eq!(
            k.collections,
            vec![
                DiscoveredCollection {
                    id: "cccc0000-0000-4000-8000-000000000001".into(),
                    items: 1
                },
                DiscoveredCollection {
                    id: "cccc0000-0000-4000-8000-000000000002".into(),
                    items: 0
                },
            ]
        );
        assert_eq!(d.orgs[1].name, None);
        assert!(d.orgs[1].collections.is_empty());
    }

    #[test]
    fn req_cry_008_discovery_of_an_empty_account() {
        let d = discover(&sync(serde_json::json!({
            "profile": {"id": "u1", "email": "k@example.net"}
        })));
        assert!(d.orgs.is_empty());
        assert_eq!(d.personal_items, 0);
    }
}
