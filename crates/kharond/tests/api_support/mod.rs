//! Shared fixtures for the `req_api_*` integration tests (issue #14).
//!
//! The vault is the recorded Vaultwarden fixture
//! (`crates/kharon-bwcrypto/tests/fixtures/vaultwarden/`) unlocked
//! once per test binary — no network — plus clones of its two ciphers
//! with other URI match types, so the origin filter and the ItemMeta
//! URI mapping see every case. The fixture's plaintext passwords are
//! the canaries: no API response may contain them.

#![allow(dead_code)]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use argon2::Argon2;
use kharon_bwcrypto::Kdf;
use kharond::api::token::{ParamFloor, TokenStore, generate_with};
use kharond::api::{AuditSink, Broker, VaultView};
use kharond::audit::Entry;
use kharond::lock::{AuditError, LockController, LockPolicy, ManualClock, StaticHardening};
use kharond::origin::OriginConfig;
use kharond::sync::wire::SyncResponse;
use kharond::sync::{Scope, Session, Vault};
use serde_json::{Value, json};
use zeroize::{ZeroizeOnDrop, Zeroizing};

pub const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../kharon-bwcrypto/tests/fixtures/vaultwarden"
);

/// Ids of the match-type clones added to the fixture sync.
pub const REGEX_CLONE: &str = "aaaaaaaa-0000-4000-8000-0000000000a4";
pub const HOST_CLONE: &str = "aaaaaaaa-0000-4000-8000-0000000000a1";
pub const EXACT_CLONE: &str = "aaaaaaaa-0000-4000-8000-0000000000a3";
pub const NEVER_CLONE: &str = "aaaaaaaa-0000-4000-8000-0000000000a5";

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{FIXTURE_DIR}/{name}")).unwrap())
        .unwrap()
}

/// Fixture manifest (`fixture.json`).
pub fn manifest() -> &'static Value {
    static M: OnceLock<Value> = OnceLock::new();
    M.get_or_init(|| load("fixture.json"))
}

/// Every plaintext secret in the fixture: item passwords and the
/// account master password. Must never appear in any API output.
pub fn canaries() -> Vec<String> {
    let m = manifest();
    let mut c: Vec<String> = m["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["password"].as_str().unwrap().to_owned())
        .collect();
    c.push(m["account"]["password"].as_str().unwrap().to_owned());
    // Full usernames are masked, so they must not appear either.
    c.extend(
        m["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["username"].as_str().unwrap().to_owned()),
    );
    c
}

/// Assert no canary occurs in `text`.
pub fn assert_no_canary(text: &str) {
    for c in canaries() {
        assert!(!text.contains(&c), "canary leaked into API output: {text}");
    }
}

/// The fixture vault, unlocked once (PBKDF2 600k) per test binary.
pub fn fixture_vault() -> Arc<Vault> {
    static V: OnceLock<Arc<Vault>> = OnceLock::new();
    V.get_or_init(|| {
        let mut s = load("sync_fixture.json");
        let base = s["ciphers"].as_array().unwrap().clone();
        let mut clone = |from: usize, id: &str, m: u8| {
            let mut c = base[from].clone();
            c["id"] = json!(id);
            c["login"]["uris"][0]["match"] = json!(m);
            s["ciphers"].as_array_mut().unwrap().push(c);
        };
        clone(0, HOST_CLONE, 1);
        clone(1, EXACT_CLONE, 3);
        clone(0, REGEX_CLONE, 4);
        clone(1, NEVER_CLONE, 5);
        let sync: SyncResponse = serde_json::from_value(s).unwrap();
        let org = sync.profile.organizations.as_ref().unwrap()[0].id.clone();
        let coll = sync.collections.as_ref().unwrap()[0].id.clone();
        let m = manifest();
        let email = m["account"]["email"].as_str().unwrap();
        let password = Zeroizing::new(m["account"]["password"].as_str().unwrap().to_owned());
        let kdf = Kdf::from_prelogin(0, 600_000, None, None).unwrap();
        let mut session = Session::unlock(
            &password,
            email,
            &kdf,
            &sync,
            Scope::new(&org, [&coll]).unwrap(),
        )
        .unwrap();
        let vault = session.apply_sync(&sync).unwrap();
        assert_eq!(vault.len(), 6, "fixture items + clones in scope");
        Arc::new(vault)
    })
    .clone()
}

/// The lock controller's session in tests: the shared fixture vault.
/// (The real one is `LiveSync`.) No key material: the `Session` that
/// decrypted the fixture is dropped inside `fixture_vault`.
pub struct TestSession(pub Arc<Vault>);

impl ZeroizeOnDrop for TestSession {}

impl VaultView for TestSession {
    fn vault(&self) -> &Vault {
        &self.0
    }
}

/// Records API audit entries; can be told to fail.
#[derive(Clone, Default)]
pub struct RecordingAudit {
    pub entries: Arc<Mutex<Vec<Entry>>>,
    pub fail: Arc<Mutex<bool>>,
}

impl AuditSink for RecordingAudit {
    fn append(&mut self, entry: Entry) -> Result<(), AuditError> {
        if *self.fail.lock().unwrap() {
            return Err(AuditError);
        }
        self.entries.lock().unwrap().push(entry);
        Ok(())
    }
}

impl RecordingAudit {
    /// `(event, agent_id, origin, result)` of every entry, as JSON
    /// (stable across transports; `seq`/`ts` are the log's job).
    pub fn summary(&self) -> Vec<Value> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|e| {
                let v = serde_json::to_value(e).unwrap();
                json!([v["event"], v["agent_id"], v["origin"], v["result"]])
            })
            .collect()
    }
}

/// The floor [`cheap_argon`] hashes clear. Production stores use
/// `ParamFloor::PRODUCTION`, which refuses these hashes.
pub const CHEAP_FLOOR: ParamFloor = ParamFloor {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

/// Cheap Argon2id for test tokens (production: `Argon2::default()`).
pub fn cheap_argon() -> Argon2<'static> {
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(8, 1, 1, None).unwrap(),
    )
}

pub type TestBroker = Broker<TestSession, Arc<ManualClock>>;

/// A broker with agents `alpha` and `beta`, unlocked unless `locked`.
pub struct Harness {
    pub broker: Arc<TestBroker>,
    pub clock: Arc<ManualClock>,
    pub audit: RecordingAudit,
    pub alpha: String,
    pub beta: String,
}

impl Harness {
    pub fn new(locked: bool) -> Self {
        let (alpha, ha) = generate_with(&cheap_argon(), "alpha");
        let (beta, hb) = generate_with(&cheap_argon(), "beta");
        let tokens = TokenStore::with_floor(
            [("alpha", ha.as_str()), ("beta", hb.as_str())],
            &CHEAP_FLOOR,
        )
        .unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut lock = LockController::new(
            LockPolicy::default(),
            clock.clone(),
            Box::new(StaticHardening::all_ok()),
        );
        if !locked {
            let vault = fixture_vault();
            lock.unlock(|| Ok::<_, ()>(TestSession(vault))).unwrap();
        }
        let audit = RecordingAudit::default();
        let broker = Broker::new(
            tokens,
            lock,
            Box::new(audit.clone()),
            OriginConfig::default(),
        );
        Self {
            broker: Arc::new(broker),
            clock,
            audit,
            alpha: alpha.expose_secret().clone(),
            beta: beta.expose_secret().clone(),
        }
    }

    /// Advance past the idle timer (30 min default).
    pub fn idle_out(&self) {
        self.clock.advance(Duration::from_secs(31 * 60));
    }
}

/// A served HTTP transport for `broker` on an ephemeral loopback port.
pub async fn serve_http(broker: Arc<TestBroker>) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(kharond::api::http::serve(listener, broker));
    addr
}

/// A parsed HTTP/1.1 response.
#[derive(Debug)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl RawResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }
}

/// Send raw request bytes (head through `\r\n\r\n`) and read the whole
/// response (`Connection: close`). Raw so tests can send anything.
pub async fn raw_request(addr: std::net::SocketAddr, head: &[u8]) -> RawResponse {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(head).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8(buf).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    RawResponse {
        status,
        headers,
        body: body.to_owned(),
    }
}

/// `GET <target>` with an optional bearer token.
pub async fn get(addr: std::net::SocketAddr, target: &str, token: Option<&str>) -> RawResponse {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let head =
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n");
    raw_request(addr, head.as_bytes()).await
}

/// MCP protocol version the helpers speak.
pub const MCP_VERSION: &str = "2026-07-28";

/// `POST /mcp` with `body`, an optional bearer token and extra headers
/// (no defaults beyond Host, Content-Length and Connection).
pub async fn post_mcp_raw(
    addr: std::net::SocketAddr,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: &str,
) -> RawResponse {
    let mut head = String::from("POST /mcp HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(t) = token {
        head.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    raw_request(addr, head.as_bytes()).await
}

/// A 2026-07-28 MCP request: JSON-RPC envelope, `_meta` protocol
/// version, and the `MCP-Protocol-Version` / `Mcp-Method` (/ `Mcp-Name`)
/// headers. `params` is raw JSON text for an object without `_meta`
/// (raw so tests can send duplicate keys).
pub async fn mcp_request(
    addr: std::net::SocketAddr,
    token: Option<&str>,
    method: &str,
    params: &str,
) -> RawResponse {
    let meta = format!(r#""_meta":{{"io.modelcontextprotocol/protocolVersion":"{MCP_VERSION}"}}"#);
    let inner = params
        .trim()
        .strip_prefix('{')
        .and_then(|p| p.strip_suffix('}'))
        .expect("params is a JSON object")
        .trim();
    let params = if inner.is_empty() {
        format!("{{{meta}}}")
    } else {
        format!("{{{inner},{meta}}}")
    };
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let name = (method == "tools/call").then(|| {
        serde_json::from_str::<Value>(&params).unwrap()["name"]
            .as_str()
            .unwrap()
            .to_owned()
    });
    let mut headers = vec![
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("MCP-Protocol-Version", MCP_VERSION),
        ("Mcp-Method", method),
    ];
    if let Some(n) = name.as_deref() {
        headers.push(("Mcp-Name", n));
    }
    post_mcp_raw(addr, token, &headers, &body).await
}

/// `tools/call` of `tool` with raw JSON `arguments`.
pub async fn mcp_call(
    addr: std::net::SocketAddr,
    token: Option<&str>,
    tool: &str,
    arguments: &str,
) -> RawResponse {
    let params = format!(r#"{{"name":"{tool}","arguments":{arguments}}}"#);
    mcp_request(addr, token, "tools/call", &params).await
}

/// Raw JSON object text with `pairs` in order (duplicates kept).
pub fn json_object(pairs: &[(&str, &str)]) -> String {
    let fields: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}:{}", json!(k), json!(v)))
        .collect();
    format!("{{{}}}", fields.join(","))
}
