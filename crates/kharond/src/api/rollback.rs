//! Sync rollback detection (REQ-REV-004).
//!
//! While unlocked the broker keeps a per-item high-water
//! `revisionDate` and every item-set fingerprint observed since
//! unlock. A sync that regresses a per-item revision, or that
//! revisits an earlier item-set fingerprint after a different one,
//! is a rollback: the broker locks and audits `rollback_detected`.
//!
//! A fingerprint revisit locks only when items come back (the new
//! id set is not a subset of the previous sync). Pure add-then-remove
//! that recreates an earlier fingerprint does not lock — REQ-REV-003
//! treats that deletion as grant invalidation. Re-adding those items
//! so the earlier fingerprint returns inside the same unlock does
//! lock; that churn is fail-closed.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::sync::Vault;

/// In-memory high-water marks for one unlock session.
#[derive(Debug, Default, Clone)]
pub struct RollbackGuard {
    /// Max `revisionDate` observed per item id (RFC 3339 strings
    /// compare lexicographically when they share a format).
    high_water: BTreeMap<String, String>,
    /// Every item-set fingerprint seen this unlock.
    seen_sets: BTreeSet<[u8; 32]>,
    /// Fingerprint of the most recent accepted sync.
    last_set: Option<[u8; 32]>,
    /// Item ids of the most recent accepted sync. Used so a pure
    /// deletion (new ids ⊆ last ids) that happens to recreate an
    /// earlier fingerprint is not a false rollback; items *coming
    /// back* after deletion against a previously seen fingerprint is.
    last_ids: BTreeSet<String>,
}

/// Why a sync was refused as a rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackReason {
    /// An item's `revisionDate` moved backwards vs the high-water.
    RevisionRegressed {
        /// Item id.
        item_id: String,
    },
    /// The item-set fingerprint was seen earlier, then left, then
    /// returned (a restored backup / replayed sync).
    SetRegressed,
}

impl RollbackGuard {
    /// Empty guard (fresh unlock).
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear marks (called on lock so the next unlock starts clean).
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Observe a vault after a successful sync. `Ok(())` updates the
    /// marks; `Err` leaves them unchanged so a locked broker can
    /// still inspect the previous high-water in tests.
    pub fn observe(&mut self, vault: &Vault) -> Result<(), RollbackReason> {
        let mut proposed_hw = self.high_water.clone();
        for item in vault.items() {
            let Some(rev) = item.revision() else {
                // Items without a revisionDate cannot regress one;
                // they still participate in the set fingerprint.
                continue;
            };
            match proposed_hw.get(item.id()) {
                Some(hw) if rev < hw.as_str() => {
                    return Err(RollbackReason::RevisionRegressed {
                        item_id: item.id().to_owned(),
                    });
                }
                Some(hw) if rev == hw.as_str() => {}
                _ => {
                    proposed_hw.insert(item.id().to_owned(), rev.to_owned());
                }
            }
        }
        let set = set_fingerprint(vault);
        let new_ids: BTreeSet<String> = vault.items().map(|i| i.id().to_owned()).collect();
        // A fingerprint revisit is a rollback only when items reappear
        // (new ids not ⊆ last ids). Pure deletions that recreate an
        // earlier fingerprint (add → delete) must not lock the broker.
        if self.seen_sets.contains(&set)
            && self.last_set.is_some_and(|last| last != set)
            && !new_ids.is_subset(&self.last_ids)
        {
            return Err(RollbackReason::SetRegressed);
        }
        self.high_water = proposed_hw;
        self.seen_sets.insert(set);
        self.last_set = Some(set);
        self.last_ids = new_ids;
        Ok(())
    }

    /// High-water revision for `item_id`, if any.
    pub fn high_water(&self, item_id: &str) -> Option<&str> {
        self.high_water.get(item_id).map(String::as_str)
    }
}

/// SHA-256 of sorted `id\0revision\n` lines (empty revision is `""`).
fn set_fingerprint(vault: &Vault) -> [u8; 32] {
    let mut lines: Vec<String> = vault
        .items()
        .map(|i| format!("{}\0{}\n", i.id(), i.revision().unwrap_or("")))
        .collect();
    lines.sort();
    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{Item, ItemUri, SyncReport, Vault};

    fn item(id: &str, rev: Option<&str>) -> Item {
        Item::from_parts(
            id.to_owned(),
            "n".into(),
            None,
            vec![ItemUri {
                uri: "https://example.com".into(),
                match_type: Some(0),
            }],
            rev.map(str::to_owned),
            None,
            None,
        )
    }

    fn vault(items: Vec<Item>) -> Vault {
        Vault::with_report(items, SyncReport::default())
    }

    #[test]
    fn req_rev_004_older_cipher_revision_is_rollback() {
        let mut g = RollbackGuard::new();
        let v1 = vault(vec![item("a", Some("2026-11-05T12:00:00Z"))]);
        assert!(g.observe(&v1).is_ok());
        let v2 = vault(vec![item("a", Some("2026-11-05T11:00:00Z"))]);
        assert!(matches!(
            g.observe(&v2),
            Err(RollbackReason::RevisionRegressed { .. })
        ));
        // Marks unchanged on refusal.
        assert_eq!(g.high_water("a"), Some("2026-11-05T12:00:00Z"));
    }

    #[test]
    fn req_rev_004_revisiting_an_earlier_set_is_rollback() {
        let mut g = RollbackGuard::new();
        let a = vault(vec![item("a", Some("2026-11-05T10:00:00Z"))]);
        // A disjoint set (item a replaced by item b) — not a pure deletion.
        let b = vault(vec![item("b", Some("2026-11-05T10:00:00Z"))]);
        assert!(g.observe(&a).is_ok());
        assert!(g.observe(&b).is_ok());
        // Restoring the earlier snapshot brings `a` back (not ⊆ {b}).
        assert_eq!(g.observe(&a), Err(RollbackReason::SetRegressed));
    }

    #[test]
    fn req_rev_004_pure_deletion_that_recreates_an_earlier_fingerprint_is_ok() {
        let mut g = RollbackGuard::new();
        let a = vault(vec![item("a", Some("2026-11-05T10:00:00Z"))]);
        let ab = vault(vec![
            item("a", Some("2026-11-05T10:00:00Z")),
            item("b", Some("2026-11-05T10:00:00Z")),
        ]);
        assert!(g.observe(&a).is_ok());
        assert!(g.observe(&ab).is_ok());
        // Delete b → fingerprint equals the first sync, but ids ⊆ last.
        assert!(g.observe(&a).is_ok());
    }
}
