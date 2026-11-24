//! REQ-TCH-010 (#382): only the broker's owner may add, change or remove a
//! login method. The ops ride the owner's Unix socket (`owner::serve`),
//! delegate to the audited operations on `Broker`, and work while the broker
//! is locked. Requests are typed `Serialize` structs and replies typed
//! `Deserialize` structs; nothing here builds JSON by hand except the two
//! malformed lines that must fail to parse.

mod api_support;

use std::collections::BTreeMap;
use std::sync::Arc;

use api_support::{Harness, TestBroker};
use kharon_recording::{
    Expected, FillRole, Leg, ListenerWorld, LoginMethod, METHOD_FORMAT_VERSION, MethodStep,
    Provenance, Rung, RungCeiling, Shape, Site, SubmitVia, SuccessCheck,
};
use kharond::api::TeachOpError;
use kharond::cdp::{MethodEnd, MethodUse};
use kharond::owner::{OwnerFailure, OwnerOps, TeachRow, bind, peer_uid_accepted, serve};
use kharond::teach::{Entry, ImportFlags, TeachRegistry};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const SELECTOR: &str = "#override-selector-c4n4ry";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// ---------------------------------------------------------------- the ops

struct Ops {
    broker: Arc<TestBroker>,
}

impl OwnerOps for Ops {
    async fn unlock(&self, _password: Zeroizing<String>) -> Result<(), OwnerFailure> {
        Err(OwnerFailure::Unsupported)
    }

    async fn lock(&self) -> bool {
        true
    }

    async fn is_locked(&self) -> bool {
        let lock = self
            .broker
            .lock_controller()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        lock.is_locked()
    }

    async fn teach_import(
        &self,
        method: LoginMethod,
        flags: ImportFlags,
    ) -> Result<Entry, OwnerFailure> {
        Ok(self.broker.teach_import(method, flags)?)
    }

    async fn teach_list(&self) -> Result<Vec<Entry>, OwnerFailure> {
        Ok(self.broker.teach_list()?)
    }

    async fn teach_show(&self, domain: String) -> Result<Entry, OwnerFailure> {
        Ok(self.broker.teach_show(&domain)?)
    }

    async fn teach_override(
        &self,
        domain: String,
        step: u32,
        selector: String,
    ) -> Result<Entry, OwnerFailure> {
        Ok(self.broker.teach_override(&domain, step, &selector)?)
    }

    async fn teach_clear_stale(&self, domain: String) -> Result<Entry, OwnerFailure> {
        Ok(self.broker.teach_clear_stale(&domain)?)
    }

    async fn teach_remove(&self, domain: String) -> Result<Entry, OwnerFailure> {
        Ok(self.broker.teach_remove(&domain)?)
    }
}

/// Typed so the compiler, not a string, says what a request line is made of.
const _: fn(TeachOpError) -> OwnerFailure = OwnerFailure::from;

// ------------------------------------------------------- requests, replies

#[derive(Serialize, Default)]
struct Req<'a> {
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a LoginMethod>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    replace: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    accept_main_world: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<&'a str>,
}

#[derive(Deserialize)]
struct Reply {
    ok: bool,
    error: Option<String>,
    entry: Option<TeachRow>,
    entries: Option<Vec<TeachRow>>,
    method: Option<LoginMethod>,
    locked: Option<bool>,
}

/// What a test reads of an audit entry.
#[derive(Deserialize)]
struct Audited {
    event: String,
    origin: Option<String>,
    channel: Option<String>,
    result: Option<String>,
    file_sha256: Option<String>,
    detail_code: Option<String>,
    step_index: Option<u64>,
}

fn audited(h: &Harness) -> Vec<Audited> {
    let entries = h.audit.entries.lock().unwrap();
    entries
        .iter()
        .map(|e| serde_json::from_str(&serde_json::to_string(e).unwrap()).unwrap())
        .collect()
}

fn audit_text(h: &Harness) -> String {
    serde_json::to_string(&*h.audit.entries.lock().unwrap()).unwrap()
}

// ------------------------------------------------------------- the methods

fn expect(input_type: &str) -> Expected {
    Expected {
        tag: "input".into(),
        input_type: Some(input_type.into()),
        id: None,
        name: None,
        autocomplete: None,
    }
}

fn base(provenance: Provenance, rung: Rung) -> LoginMethod {
    LoginMethod {
        format_version: METHOD_FORMAT_VERSION,
        site: Site {
            domain: "example.com".into(),
            origin: "https://example.com".into(),
            path: "/login".into(),
        },
        shape: Shape::FormPost,
        rung,
        legs: vec![Leg {
            steps: vec![
                MethodStep::Navigate {
                    path: "/login".into(),
                },
                MethodStep::Fill {
                    role: FillRole::Username,
                    selectors: vec!["#u".into()],
                    expect: expect("text"),
                },
                MethodStep::Fill {
                    role: FillRole::Password,
                    selectors: vec!["#pw".into()],
                    expect: expect("password"),
                },
                MethodStep::Submit {
                    via: SubmitVia::Form {},
                },
            ],
        }],
        success: SuccessCheck::None {},
        provenance,
    }
}

fn hand_written() -> LoginMethod {
    base(
        Provenance::HandWritten {
            author: "test".into(),
        },
        Rung::Milliseconds,
    )
}

fn recorded(world: ListenerWorld, ceiling: RungCeiling, rung: Rung) -> LoginMethod {
    base(
        Provenance::Recording {
            sha256: DIGEST.into(),
            tool_version: "0.0.0".into(),
            browser_product: "Chrome/1".into(),
            listener_world: world,
            rung_ceiling: ceiling,
        },
        rung,
    )
}

// -------------------------------------------------------------- the rig

struct Rig {
    h: Harness,
    registry: Arc<TeachRegistry>,
    socket: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn rig(locked: bool) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(TeachRegistry::load(dir.path()).unwrap());
    let reg = Arc::clone(&registry);
    let h = Harness::with(locked, move |b: TestBroker| b.with_teach_registry(reg));
    let socket = dir.path().join("owner.sock");
    let listener = bind(&socket).unwrap();
    tokio::spawn(serve(
        listener,
        Arc::new(Ops {
            broker: Arc::clone(&h.broker),
        }),
    ));
    Rig {
        h,
        registry,
        socket,
        _dir: dir,
    }
}

async fn send_line(socket: &std::path::Path, line: &str) -> Reply {
    let mut stream = UnixStream::connect(socket).await.unwrap();
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).await.unwrap();
    serde_json::from_str(text.trim()).unwrap_or_else(|_| panic!("bad owner reply: {text}"))
}

async fn send(socket: &std::path::Path, req: &Req<'_>) -> Reply {
    send_line(socket, &serde_json::to_string(req).unwrap()).await
}

fn import<'a>(method: &'a LoginMethod) -> Req<'a> {
    Req {
        op: "teach_import",
        method: Some(method),
        ..Req::default()
    }
}

fn on<'a>(op: &'a str, domain: &'a str) -> Req<'a> {
    Req {
        op,
        domain: Some(domain),
        ..Req::default()
    }
}

fn refused(r: &Reply) -> &str {
    assert!(!r.ok, "expected a refusal");
    r.error.as_deref().unwrap()
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn req_tch_010_import_then_list_show_override_clear_remove() {
    let rig = rig(false).await;
    let method = recorded(
        ListenerWorld::Isolated,
        RungCeiling::Milliseconds,
        Rung::Milliseconds,
    );

    // import
    let r = send(&rig.socket, &import(&method)).await;
    assert!(r.ok, "{:?}", r.error);
    let row = r.entry.unwrap();
    assert_eq!(row.domain, "example.com");
    assert_eq!(row.rung, Rung::Milliseconds);
    assert!(!row.hand_written);
    assert_eq!(row.digest.as_deref(), Some(DIGEST));
    assert!(row.overrides.is_empty() && row.stale.is_none());

    // list, show (not audited)
    let r = send(
        &rig.socket,
        &Req {
            op: "teach_list",
            ..Req::default()
        },
    )
    .await;
    assert!(r.ok);
    assert_eq!(r.entries.unwrap().len(), 1);
    let r = send(&rig.socket, &on("teach_show", "example.com")).await;
    assert!(r.ok);
    assert_eq!(r.method.unwrap(), method);
    assert_eq!(r.entry.unwrap().domain, "example.com");
    // a host name is normalized to its site key
    let r = send(&rig.socket, &on("teach_show", "Login.Example.com")).await;
    assert!(r.ok, "{:?}", r.error);

    // override
    let r = send(
        &rig.socket,
        &Req {
            op: "teach_override",
            domain: Some("example.com"),
            step: Some(2),
            selector: Some(SELECTOR),
            ..Req::default()
        },
    )
    .await;
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(
        r.entry.unwrap().overrides,
        BTreeMap::from([(2, vec![SELECTOR.to_owned()])])
    );

    // clear-stale: mark the entry stale the way a drifted fill does
    let used = MethodUse {
        domain: "example.com".into(),
        rung: Rung::Milliseconds,
        end: MethodEnd::Drift { step: 2 },
        selectors_ignored: false,
        browser_product: None,
    };
    assert!(
        rig.registry
            .record_fill(&used, "2026-11-24T10:00:00Z")
            .newly_stale
    );
    let r = send(&rig.socket, &on("teach_show", "example.com")).await;
    assert_eq!(r.entry.unwrap().stale.unwrap().step, 2);
    let r = send(&rig.socket, &on("teach_clear_stale", "example.com")).await;
    assert!(r.ok, "{:?}", r.error);
    assert!(r.entry.unwrap().stale.is_none());

    // remove
    let r = send(&rig.socket, &on("teach_remove", "example.com")).await;
    assert!(r.ok, "{:?}", r.error);
    assert!(rig.registry.list().is_empty());
    let r = send(&rig.socket, &on("teach_remove", "example.com")).await;
    assert_eq!(refused(&r), "not_found");

    // exactly one audit entry per mutating op, none for the reads or the
    // refusal, and the override's selector is in none of them
    let log = audited(&rig.h);
    let events: Vec<&str> = log.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(
        events,
        [
            "teach_import",
            "teach_override",
            "teach_clear_stale",
            "teach_remove"
        ]
    );
    for e in &log {
        assert_eq!(e.origin.as_deref(), Some("example.com"));
        assert_eq!(e.channel.as_deref(), Some("cli"));
        assert_eq!(e.result.as_deref(), Some("ok"));
        assert_eq!(e.file_sha256.as_deref(), Some(DIGEST));
        assert_eq!(e.detail_code, None);
    }
    assert_eq!(log[1].step_index, Some(2));
    assert_eq!(log[0].step_index, None);
    assert!(!audit_text(&rig.h).contains(SELECTOR));
}

#[tokio::test]
async fn req_tch_010_a_hand_written_method_audits_as_hand_written() {
    let rig = rig(false).await;
    let r = send(&rig.socket, &import(&hand_written())).await;
    assert!(r.ok, "{:?}", r.error);
    let row = r.entry.unwrap();
    assert!(row.hand_written);
    assert_eq!(row.digest, None);
    let log = audited(&rig.h);
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].file_sha256, None);
    assert_eq!(log[0].detail_code.as_deref(), Some("hand_written"));
}

#[tokio::test]
async fn req_tch_010_each_import_refusal_over_the_socket() {
    let rig = rig(false).await;

    // off_domain: the origin is not on the entry's domain
    let mut off = hand_written();
    off.site.origin = "https://other.org".into();
    assert_eq!(
        refused(&send(&rig.socket, &import(&off)).await),
        "off_domain"
    );

    // main_world: refused, then accepted with the flag
    let main = recorded(
        ListenerWorld::Main,
        RungCeiling::Milliseconds,
        Rung::Milliseconds,
    );
    assert_eq!(
        refused(&send(&rig.socket, &import(&main)).await),
        "main_world"
    );
    assert!(rig.registry.list().is_empty());
    let accepted = Req {
        accept_main_world: true,
        ..import(&main)
    };
    assert!(send(&rig.socket, &accepted).await.ok);
    assert_eq!(audited(&rig.h).len(), 1, "only the accepted import");

    // method_exists: refused, then accepted with replace
    assert_eq!(
        refused(&send(&rig.socket, &import(&main)).await),
        "main_world"
    );
    let again = hand_written();
    assert_eq!(
        refused(&send(&rig.socket, &import(&again)).await),
        "method_exists"
    );
    let replace = Req {
        replace: true,
        ..import(&again)
    };
    assert!(send(&rig.socket, &replace).await.ok);
    assert_eq!(audited(&rig.h).len(), 2);

    // rung_above_ceiling: a recording that only reached agent_continues
    let above = recorded(
        ListenerWorld::Isolated,
        RungCeiling::AgentContinues,
        Rung::Milliseconds,
    );
    let mut other = above.clone();
    other.site.domain = "example.org".into();
    other.site.origin = "https://example.org".into();
    assert_eq!(
        refused(&send(&rig.socket, &import(&other)).await),
        "rung_above_ceiling"
    );

    // invalid_method: the line parses, the method does not validate
    let mut invalid = hand_written();
    invalid.shape = Shape::Unrecognized;
    assert_eq!(
        refused(&send(&rig.socket, &import(&invalid)).await),
        "invalid_method"
    );

    // bad_request: the line itself fails to parse (an unknown field) or
    // carries another format version
    let compact = serde_json::to_string(&hand_written()).unwrap();
    let version = format!("\"format_version\":{METHOD_FORMAT_VERSION}");
    let unknown = compact.replace(&version, &format!("{version},\"bogus\":true"));
    assert_ne!(unknown, compact);
    let r = send_line(
        &rig.socket,
        &format!("{{\"op\":\"teach_import\",\"method\":{unknown}}}"),
    )
    .await;
    assert_eq!(refused(&r), "bad_request");
    let next = compact.replace(&version, "\"format_version\":2");
    let r = send_line(
        &rig.socket,
        &format!("{{\"op\":\"teach_import\",\"method\":{next}}}"),
    )
    .await;
    assert_eq!(refused(&r), "bad_request");
    let r = send(
        &rig.socket,
        &Req {
            op: "teach_import",
            ..Req::default()
        },
    )
    .await;
    assert_eq!(refused(&r), "bad_request", "no method");

    // no audit entry for any refusal
    assert_eq!(audited(&rig.h).len(), 2);
}

#[tokio::test]
async fn req_tch_010_edit_refusals_over_the_socket() {
    let rig = rig(false).await;
    assert!(send(&rig.socket, &import(&hand_written())).await.ok);
    let edit = |domain, step, selector| Req {
        op: "teach_override",
        domain,
        step,
        selector,
        ..Req::default()
    };

    let r = send(&rig.socket, &edit(Some("nowhere.org"), Some(2), Some("#x"))).await;
    assert_eq!(refused(&r), "not_found");
    // step 0 is a navigate; step 9 does not exist
    for step in [0, 9] {
        let r = send(
            &rig.socket,
            &edit(Some("example.com"), Some(step), Some("#x")),
        )
        .await;
        assert_eq!(refused(&r), "bad_step");
    }
    let r = send(&rig.socket, &edit(Some("example.com"), Some(2), Some("  "))).await;
    assert_eq!(refused(&r), "bad_selector");
    // missing or empty arguments
    for r in [
        edit(None, Some(2), Some("#x")),
        edit(Some(""), Some(2), Some("#x")),
        edit(Some("example.com"), None, Some("#x")),
        edit(Some("example.com"), Some(2), None),
    ] {
        assert_eq!(refused(&send(&rig.socket, &r).await), "bad_request");
    }
    let r = send(&rig.socket, &on("teach_show", "")).await;
    assert_eq!(refused(&r), "bad_request");
    let r = send(
        &rig.socket,
        &Req {
            op: "teach_show",
            ..Req::default()
        },
    )
    .await;
    assert_eq!(refused(&r), "bad_request");

    assert_eq!(audited(&rig.h).len(), 1, "only the import");
}

#[test]
fn req_tch_010_a_peer_with_another_uid_is_refused() {
    // The teach ops have no transport of their own: they are reachable
    // only through `owner::serve`, whose `handle` applies this gate to
    // every connection before it reads a request line.
    let own = rustix::process::geteuid().as_raw();
    assert!(peer_uid_accepted(Some(own), own));
    assert!(!peer_uid_accepted(Some(own + 1), own));
    assert!(!peer_uid_accepted(None, own));
}

#[tokio::test]
async fn teach_ops_work_while_locked() {
    let rig = rig(true).await;
    let status = send(
        &rig.socket,
        &Req {
            op: "status",
            ..Req::default()
        },
    )
    .await;
    assert_eq!(status.locked, Some(true));
    assert!(send(&rig.socket, &import(&hand_written())).await.ok);
    let r = send(
        &rig.socket,
        &Req {
            op: "teach_override",
            domain: Some("example.com"),
            step: Some(1),
            selector: Some("#user"),
            ..Req::default()
        },
    )
    .await;
    assert!(r.ok, "{:?}", r.error);
    assert!(send(&rig.socket, &on("teach_show", "example.com")).await.ok);
    assert!(
        send(&rig.socket, &on("teach_remove", "example.com"))
            .await
            .ok
    );
    assert_eq!(audited(&rig.h).len(), 3);
}

#[tokio::test]
async fn audit_failure_changes_nothing() {
    let rig = rig(false).await;
    let kept = hand_written();
    assert!(send(&rig.socket, &import(&kept)).await.ok);
    let used = MethodUse {
        domain: "example.com".into(),
        rung: Rung::Milliseconds,
        end: MethodEnd::Drift { step: 1 },
        selectors_ignored: false,
        browser_product: None,
    };
    rig.registry.record_fill(&used, "2026-11-24T10:00:00Z");
    let before = rig.registry.list();
    assert!(before[0].1.stale.is_some());
    let teach_dir = rig._dir.path().join("teach");
    let listing = || {
        let mut names: Vec<String> = std::fs::read_dir(&teach_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let bytes = std::fs::read(teach_dir.join("registry.json")).unwrap();
    let files_unchanged = || {
        assert_eq!(
            std::fs::read(teach_dir.join("registry.json")).unwrap(),
            bytes,
            "registry file bytes"
        );
        assert_eq!(listing(), ["registry.json"], "no temp file left");
    };

    *rig.h.audit.fail.lock().unwrap() = true;

    let replacement = recorded(
        ListenerWorld::Isolated,
        RungCeiling::Milliseconds,
        Rung::Milliseconds,
    );
    let replace = Req {
        replace: true,
        ..import(&replacement)
    };
    assert_eq!(refused(&send(&rig.socket, &replace).await), "audit_failed");
    assert_eq!(rig.registry.list(), before, "entry intact");
    files_unchanged();

    let r = send(
        &rig.socket,
        &Req {
            op: "teach_override",
            domain: Some("example.com"),
            step: Some(2),
            selector: Some("#x"),
            ..Req::default()
        },
    )
    .await;
    assert_eq!(refused(&r), "audit_failed");
    assert_eq!(rig.registry.list(), before);
    files_unchanged();

    let r = send(&rig.socket, &on("teach_clear_stale", "example.com")).await;
    assert_eq!(refused(&r), "audit_failed");
    assert_eq!(rig.registry.list(), before);
    files_unchanged();

    let r = send(&rig.socket, &on("teach_remove", "example.com")).await;
    assert_eq!(refused(&r), "audit_failed");
    assert_eq!(rig.registry.list(), before);
    files_unchanged();

    // a first import that cannot be audited leaves the registry empty
    let fresh = rig_empty_after_failed_import().await;
    assert!(fresh, "a failed first import leaves nothing behind");

    // reads need no audit
    assert!(send(&rig.socket, &on("teach_show", "example.com")).await.ok);
}

async fn rig_empty_after_failed_import() -> bool {
    let rig = rig(false).await;
    *rig.h.audit.fail.lock().unwrap() = true;
    let r = send(&rig.socket, &import(&hand_written())).await;
    assert_eq!(refused(&r), "audit_failed");
    rig.registry.list().is_empty() && rig.registry.get("example.com").is_none()
}

#[tokio::test]
async fn req_tch_010_without_a_registry_the_ops_are_teach_unavailable() {
    let h = Harness::new(false);
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("owner.sock");
    let listener = bind(&socket).unwrap();
    tokio::spawn(serve(
        listener,
        Arc::new(Ops {
            broker: Arc::clone(&h.broker),
        }),
    ));
    let r = send(
        &socket,
        &Req {
            op: "teach_list",
            ..Req::default()
        },
    )
    .await;
    assert_eq!(refused(&r), "teach_unavailable");
    let r = send(&socket, &import(&hand_written())).await;
    assert_eq!(refused(&r), "teach_unavailable");
    assert!(audited(&h).is_empty());
}

const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";

fn startup_config(data: &std::path::Path) -> String {
    let export = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/export/password_protected.json");
    format!(
        r#"mode = "export"
data_dir = "{data}"
[export]
file = "{export}"
[agents.alpha]
token_hash = "{TOKEN_HASH}"
cdp = {{ endpoint = "ws://127.0.0.1:9/devtools/browser" }}
[audit]
checkpoint_local_only = true
[memory]
require_mlock = false
[api]
listen = "127.0.0.1:0"
"#,
        data = data.display(),
        export = export.display(),
    )
}

#[tokio::test]
async fn daemon_refuses_to_start_on_a_bad_registry_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let teach = dir.path().join("teach");
    std::fs::create_dir(&teach).unwrap();
    let file = teach.join("registry.json");
    std::fs::write(&file, "{\"format_version\":1,\"entries\":{}}").unwrap();
    // group-readable: the registry steers where passwords go
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();

    let cfg = kharond::config::Config::from_toml_str(&startup_config(dir.path())).unwrap();
    let started =
        kharond::daemon::start(&cfg, Box::new(kharond::lock::StaticHardening::all_ok())).await;
    match started {
        Ok(_) => panic!("the daemon started on a group-readable registry"),
        Err(e) => assert_eq!(e.code(), "teach_registry"),
    }

    // the same file at 0600 starts, and the broker serves the teach ops
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let started =
        kharond::daemon::start(&cfg, Box::new(kharond::lock::StaticHardening::all_ok())).await;
    assert!(started.is_ok(), "a sound registry file starts the daemon");
}

#[tokio::test]
async fn req_tch_010_a_password_field_beside_a_teach_op_is_never_echoed() {
    let rig = rig(false).await;
    let secret = "CANARY-PASSWORD-9e1f";
    let mut stream = UnixStream::connect(&rig.socket).await.unwrap();
    let line = format!("{{\"op\":\"teach_list\",\"password\":\"{secret}\"}}\n");
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).await.unwrap();
    assert!(text.contains("\"ok\":true"), "the teach op ran: {text}");
    assert!(!text.contains(secret));
    assert!(!audit_text(&rig.h).contains(secret));
}

#[tokio::test]
async fn req_tch_010_the_request_cap_is_32_kib() {
    let rig = rig(false).await;
    // A hand-written method whose author name pads the line to a target size.
    let line_for = |pad: usize| {
        let mut m = hand_written();
        m.provenance = Provenance::HandWritten {
            author: "a".repeat(pad),
        };
        format!(
            "{{\"op\":\"teach_import\",\"method\":{}}}",
            serde_json::to_string(&m).unwrap()
        )
    };
    let base = line_for(0).len();
    let cap = kharond::owner::MAX_REQUEST_BYTES;
    assert_eq!(cap, 32 * 1024);

    // just under the cap (the line plus its newline stays within it)
    let under = line_for(cap - base - 16);
    assert!(under.len() < cap);
    let r = send_line(&rig.socket, &under).await;
    assert!(r.ok, "{:?}", r.error);

    // over the cap
    let over = line_for(cap - base + 16);
    assert!(over.len() > cap);
    let r = send_line(&rig.socket, &over).await;
    assert_eq!(refused(&r), "bad_request");
}
