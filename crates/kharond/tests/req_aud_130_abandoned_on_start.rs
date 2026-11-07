//! SPEC §8 (#130): "Pending requests are dropped and audited on next
//! start as `abandoned`." Grant requests live only in memory, so a run
//! that dies with one pending leaves just its creation in the audit
//! log. The next `daemon::start` appends one `abandoned` entry for it,
//! before serving; a further start appends none, and the chain still
//! verifies.
//!
//! Its own test binary on purpose: it drops a daemon and starts another
//! on the same audit log, and a concurrent fork elsewhere in the binary
//! could hold the log's `flock` across that gap (#162).

use std::path::Path;

use kharond::api::token::generate;
use kharond::audit::{
    AuditConfig, AuditKeys, AuditLog, Entry, Event, NullCheckpointSink, VerifyOutcome, verify,
};
use kharond::config::Config;
use kharond::daemon;
use kharond::lock::StaticHardening;

fn config(hash: &str, data_dir: &Path) -> String {
    format!(
        r#"mode = "export"
data_dir = "{}"

[export]
file = "{}"

[agents.assistant]
token_hash = "{hash}"
cdp = {{ endpoint = "ws://127.0.0.1:9222" }}

[api]
listen = "127.0.0.1:0"

[audit]
checkpoint_local_only = true

[memory]
require_mlock = false
"#,
        data_dir.display(),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/export/password_protected.json"
        )
    )
}

fn entries(audit_dir: &Path) -> Vec<Entry> {
    std::fs::read_to_string(audit_dir.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Entry>(l).unwrap())
        .collect()
}

fn abandoned(audit_dir: &Path, request_id: &str) -> Vec<Entry> {
    entries(audit_dir)
        .into_iter()
        .filter(|e| {
            matches!(e.event, Event::Abandoned) && e.request_id.as_deref() == Some(request_id)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn req_aud_130_start_audits_the_last_runs_pending_requests_as_abandoned() {
    let (_token, hash) = generate("assistant");
    let data = tempfile::tempdir().unwrap();
    let audit_dir = data.path().join("audit");
    let cfg = Config::from_toml_str(&config(&hash, data.path())).unwrap();

    // A first run creates the log and its keys.
    drop(
        daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
            .await
            .unwrap(),
    );

    // As if that run had died with two requests pending and one
    // resolved: only their audit entries survive it.
    {
        let mut log = AuditLog::open(
            &audit_dir,
            AuditConfig::default(),
            Box::new(NullCheckpointSink),
        )
        .unwrap();
        for id in ["gr_dead_1", "gr_dead_2", "gr_resolved"] {
            log.append(
                Entry::new(Event::GrantRequest)
                    .agent_id("assistant")
                    .item_id("item-1")
                    .request_id(id)
                    .result("pending"),
            )
            .unwrap();
        }
        log.append(
            Entry::new(Event::GrantRequest)
                .agent_id("assistant")
                .request_id("gr_resolved")
                .result("denied")
                .detail_code("owner_denied"),
        )
        .unwrap();
    }

    // The next start records each unresolved request as abandoned.
    drop(
        daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
            .await
            .unwrap(),
    );
    for id in ["gr_dead_1", "gr_dead_2"] {
        let found = abandoned(&audit_dir, id);
        assert_eq!(found.len(), 1, "{id}: {found:?}");
        assert_eq!(found[0].agent_id.as_deref(), Some("assistant"));
        assert_eq!(found[0].item_id.as_deref(), Some("item-1"));
        assert_eq!(found[0].result.as_deref(), Some("abandoned"));
        assert_eq!(found[0].detail_code.as_deref(), Some("restart"));
    }
    assert!(abandoned(&audit_dir, "gr_resolved").is_empty());

    // Once recorded, a further start adds nothing.
    let before = entries(&audit_dir).len();
    drop(
        daemon::start(&cfg, Box::new(StaticHardening::all_ok()))
            .await
            .unwrap(),
    );
    let after = entries(&audit_dir);
    assert_eq!(
        after
            .iter()
            .filter(|e| matches!(e.event, Event::Abandoned))
            .count(),
        2
    );
    assert_eq!(after.len(), before, "no new entries on a clean restart");

    // And the chain is intact.
    let keys = AuditKeys::load_or_generate(&audit_dir.join("keys")).unwrap();
    assert!(matches!(
        verify(&audit_dir.join("audit.jsonl"), &[], &keys.verifying_key()).unwrap(),
        VerifyOutcome::Ok { .. }
    ));
}
