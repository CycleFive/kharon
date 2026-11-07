//! Grant requests left pending by a restart (SPEC §8, #130).
//!
//! Pending grant requests live only in memory, so a restart, crash or
//! OOM drops them. SPEC §8 asks that they be "audited on next start as
//! `abandoned`". The audit log already records every request's
//! creation (`grant_request`, result `pending`) and its resolution
//! (`grant_issue` for an approval, `grant_request` with result `denied`
//! for an owner denial or a timeout), each carrying the request's
//! `request_id`. So on start the daemon reads the log it has just
//! verified, finds the creations with no later resolution, and appends
//! one `abandoned` entry for each. No separate store is needed, and a
//! crash is covered as well as a clean shutdown.

use std::collections::HashMap;
use std::io;
use std::path::Path;

use super::entry::{Entry, Event};

/// A grant request whose creation has no later resolution in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedRequest {
    /// The request's `gr_…` id.
    pub request_id: String,
    /// The requesting agent.
    pub agent_id: Option<String>,
    /// The requested item.
    pub item_id: Option<String>,
}

impl UnresolvedRequest {
    /// The `abandoned` entry that records this request's end.
    pub fn abandoned_entry(&self) -> Entry {
        let mut entry = Entry::new(Event::Abandoned)
            .request_id(self.request_id.clone())
            .result("abandoned")
            .detail_code("restart");
        if let Some(agent) = &self.agent_id {
            entry = entry.agent_id(agent.clone());
        }
        if let Some(item) = &self.item_id {
            entry = entry.item_id(item.clone());
        }
        entry
    }
}

/// The grant requests the log at `path` shows as created `pending` and
/// never resolved, in creation order. A missing log has none.
pub fn unresolved_grant_requests(path: &Path) -> io::Result<Vec<UnresolvedRequest>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    // request_id → (creation order, request).
    let mut open: HashMap<String, (usize, UnresolvedRequest)> = HashMap::new();
    for (order, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: Entry = serde_json::from_str(line).map_err(io::Error::other)?;
        let Some(request_id) = entry.request_id else {
            continue;
        };
        match (entry.event, entry.result.as_deref()) {
            (Event::GrantRequest, Some("pending")) => {
                open.entry(request_id.clone()).or_insert((
                    order,
                    UnresolvedRequest {
                        request_id,
                        agent_id: entry.agent_id,
                        item_id: entry.item_id,
                    },
                ));
            }
            // Any other outcome for the request resolves it: an owner
            // or timeout denial, an approval, or an earlier abandon.
            (Event::GrantRequest | Event::GrantIssue | Event::Abandoned, _) => {
                open.remove(&request_id);
            }
            _ => {}
        }
    }
    let mut left: Vec<(usize, UnresolvedRequest)> = open.into_values().collect();
    left.sort_by_key(|(order, _)| *order);
    Ok(left.into_iter().map(|(_, r)| r).collect())
}

#[cfg(test)]
mod tests {
    use super::super::log::AuditConfig;
    use super::super::{AuditLog, NullCheckpointSink};
    use super::*;

    fn pending(id: &str) -> Entry {
        Entry::new(Event::GrantRequest)
            .agent_id("alpha")
            .item_id(format!("item-{id}"))
            .request_id(id)
            .result("pending")
    }

    #[test]
    fn req_aud_130_only_unresolved_pending_requests_are_abandoned() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = AuditLog::open(
            dir.path(),
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        // A: pending, never resolved.
        log.append(pending("gr_a")).unwrap();
        // B: approved.
        log.append(pending("gr_b")).unwrap();
        log.append(
            Entry::new(Event::GrantIssue)
                .agent_id("alpha")
                .grant_id("g_b")
                .request_id("gr_b")
                .result("issued"),
        )
        .unwrap();
        // C: denied (owner or timeout).
        log.append(pending("gr_c")).unwrap();
        log.append(
            Entry::new(Event::GrantRequest)
                .request_id("gr_c")
                .result("denied")
                .detail_code("request_timeout"),
        )
        .unwrap();
        // D: born refused (origin_mismatch), never pending.
        log.append(
            Entry::new(Event::GrantRequest)
                .request_id("gr_d")
                .result("origin_mismatch"),
        )
        .unwrap();
        // E: abandoned by an earlier restart.
        log.append(pending("gr_e")).unwrap();
        log.append(
            UnresolvedRequest {
                request_id: "gr_e".into(),
                agent_id: None,
                item_id: None,
            }
            .abandoned_entry(),
        )
        .unwrap();
        // F: pending, never resolved, after A.
        log.append(pending("gr_f")).unwrap();
        // Unrelated entries with request ids are ignored.
        log.append(Entry::new(Event::Fill).request_id("req_1").result("filled"))
            .unwrap();
        drop(log);

        let left = unresolved_grant_requests(&dir.path().join("audit.jsonl")).unwrap();
        let ids: Vec<&str> = left.iter().map(|r| r.request_id.as_str()).collect();
        assert_eq!(ids, ["gr_a", "gr_f"], "creation order, unresolved only");
        assert_eq!(left[0].agent_id.as_deref(), Some("alpha"));
        assert_eq!(left[0].item_id.as_deref(), Some("item-gr_a"));

        let e = left[0].abandoned_entry();
        assert!(matches!(e.event, Event::Abandoned));
        assert_eq!(e.request_id.as_deref(), Some("gr_a"));
        assert_eq!(e.result.as_deref(), Some("abandoned"));
        assert_eq!(e.detail_code.as_deref(), Some("restart"));
    }

    #[test]
    fn req_aud_130_missing_log_has_nothing_to_abandon() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            unresolved_grant_requests(&dir.path().join("audit.jsonl")).unwrap(),
            Vec::new()
        );
    }
}
