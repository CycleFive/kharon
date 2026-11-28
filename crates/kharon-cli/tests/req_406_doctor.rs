//! REQ-406 (#406): `kharon doctor` against a fixture deployment — a
//! real config and key file on disk, a mock Bitwarden, and a fake
//! owner socket speaking the daemon's line protocol. Asserts the six
//! check lines, the exit status, and that the client secret never
//! reaches stdout.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_kharon");
const ORG: &str = "0f3c2a6e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const COLL: &str = "11111111-2222-3333-4444-555555555555";
const ACCOUNT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const SECRET: &str = "DOCTOR-E2E-SECRET-CANARY";
const TOKEN_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$CANARYhashCANARYhash";

fn user_key() -> String {
    format!(
        r#"{{"client_id":"user.6b1e0c52-0a3e-4a8e-9a4f-1f0e2d3c4b5a","client_secret":"{SECRET}"}}"#
    )
}

fn org_key() -> String {
    format!(
        r#"{{"client_id":"organization.6b1e0c52-0a3e-4a8e-9a4f-1f0e2d3c4b5a","client_secret":"{SECRET}"}}"#
    )
}

// ---------------------------------------------------------------------------
// Mock Bitwarden (the req_404_setup.rs shape): identity token, then
// one sync — a profile in one organization, one collection, one
// cipher in it.
// ---------------------------------------------------------------------------

struct MockBw {
    state: tokio::sync::Mutex<u8>,
}

fn profile_json() -> String {
    format!(
        r#"{{"id":"{ACCOUNT}","name":"Kharon","email":"kharon@example.net","emailVerified":true,"premium":true,"culture":"en-US","twoFactorEnabled":false,"organizations":[{{"id":"{ORG}","name":"Agents","status":2,"type":0,"enabled":true,"usePolicies":false,"useGroups":false,"useDirectory":false,"useEvents":false,"useTotp":false,"use2fa":false,"useApi":false,"useResetPassword":false,"selfHost":false,"usersGetPremium":true,"useSso":false,"useKeyConnector":false,"useSecretsManager":false,"usePasswordManager":true,"useActivateAutofillPolicy":false,"useAutomaticUserConfirmation":false,"limitCollectionCreation":false,"limitCollectionDeletion":false,"limitItemCreation":false,"limitItemDeletion":false,"allowAdminAccessToAllCollectionItems":false,"useRiskInsights":false,"useOrganizationDomains":false,"useAdminSponsoredFamilies":false,"isProvider":false,"key":"2.x","permissions":{{"accessEventLogs":false,"accessImportExport":false,"accessReports":false,"createNewCollections":false,"editAnyCollection":false,"deleteAnyCollection":false,"accessNotifications":false,"manageGroups":false,"managePolicies":false,"manageSso":false,"manageUsers":false,"manageResetPassword":false,"manageScim":false}}}}],"providers":[],"providerOrganizations":[],"forcePasswordReset":false,"avatarColor":null,"creationDate":"2024-01-01T00:00:00Z"}}"#
    )
}

fn sync_json() -> String {
    format!(
        r#"{{"profile":{},"collections":[{{"id":"{COLL}","organizationId":"{ORG}","name":"2.LoginsKey","externalId":null,"hidePasswords":false,"readOnly":false,"manage":false}}],"ciphers":[{{"id":"c1111111-2222-3333-4444-555555555555","organizationId":"{ORG}","collectionIds":["{COLL}"],"folderId":null,"type":1,"name":"2.SiteKey","notes":null,"favorite":false,"reprompt":0,"login":{{"username":"2.u","password":"2.p","uris":[{{"uri":"2.https://example.com","match":null}}],"totp":null,"passwordRevisionDate":null,"autofillOnPageLoad":null,"fido2Credentials":[]}},"creationDate":"2024-01-01T00:00:00Z","revisionDate":"2024-01-01T00:00:00Z","deletedDate":null,"attachments":[],"fields":[],"passwordHistory":[],"key":"2.k"}}],"policies":[],"folders":[],"domains":null,"sends":[],"settings":{{"equivalentDomains":null}}}}"#,
        profile_json()
    )
}

async fn mock_bw(bw: &MockBw, path: &str) -> String {
    let mut state = bw.state.lock().await;
    match (*state, path) {
        (0, "/identity/connect/token") => {
            *state = 1;
            r#"{"access_token":"tok","token_type":"Bearer","expires_in":3600,"refresh_token":"ref","Key":"account-key","PrivateKey":"enc-priv","Kdf":0,"KdfIterations":600000,"ResetMasterPassword":false,"scope":"api offline_access"}"#.to_owned()
        }
        (1, "/api/sync") => sync_json(),
        _ => format!("mock bw: unexpected state {state} path {path}"),
    }
}

async fn start_mock_bw() -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let bw = std::sync::Arc::new(MockBw {
        state: tokio::sync::Mutex::new(0),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                continue;
            };
            let bw = std::sync::Arc::clone(&bw);
            tokio::spawn(async move {
                // Read the request head, then the body per Content-Length.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end = loop {
                    match sock.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p + 4;
                            }
                        }
                        Err(_) => return,
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .split('?')
                    .next()
                    .unwrap_or("")
                    .to_owned();
                let content_length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut have = buf.len() - head_end;
                while have < content_length {
                    match sock.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => have += n,
                        Err(_) => break,
                    }
                }
                let body = mock_bw(&bw, &path).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    url
}

// ---------------------------------------------------------------------------
// Fake owner socket: the daemon's line protocol, canned replies.
// ---------------------------------------------------------------------------

fn start_fake_owner(socket: &Path, passkeys: usize, agent_attached: bool) {
    let listener = UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut line = String::new();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let reply = if line.contains("passkey_list") {
                let rows = (0..passkeys)
                    .map(|i| {
                        format!(r#"{{"id":"{i:08x}","enrolled_at":null,"last_used_at":null}}"#)
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!(r#"{{"ok":true,"passkeys":[{rows}]}}"#)
            } else if line.contains("\"status\"") {
                let since = if agent_attached {
                    r#","since":1700000000"#
                } else {
                    ""
                };
                format!(
                    r#"{{"ok":true,"locked":false,"agents":[{{"id":"assistant","attached":{agent_attached}{since}}}]}}"#
                )
            } else {
                r#"{"ok":false,"error":"unknown_op"}"#.to_owned()
            };
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.write_all(b"\n");
        }
    });
}

// ---------------------------------------------------------------------------
// The fixture deployment and the doctor runs.
// ---------------------------------------------------------------------------

struct Deployment {
    _dir: tempfile::TempDir,
    config: PathBuf,
    socket: PathBuf,
}

fn deployment(server: &str, key_bytes: &str, key_mode: u32) -> Deployment {
    deployment_variant(server, key_bytes, key_mode, false)
}

/// A deployment whose checks 5–6 skip: no `[owner_ui]`, and the
/// agent is on the wireguard transport instead of the connector.
fn deployment_with_skips(server: &str, key_bytes: &str, key_mode: u32) -> Deployment {
    deployment_variant(server, key_bytes, key_mode, true)
}

fn deployment_variant(server: &str, key_bytes: &str, key_mode: u32, skips: bool) -> Deployment {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    std::fs::create_dir(&data_dir).unwrap();
    let key = dir.path().join("key.json");
    std::fs::write(&key, key_bytes).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(key_mode)).unwrap();
    let config = dir.path().join("kharon.toml");
    let crt = dir.path().join("tls.crt");
    let key_pem = dir.path().join("tls.key");
    std::fs::write(&crt, "doctor fixture cert\n").unwrap();
    std::fs::write(&key_pem, "doctor fixture key\n").unwrap();
    let (via, connector_token_hash, owner_ui, connector) = if skips {
        ("wireguard", String::new(), String::new(), String::new())
    } else {
        (
            "agent_connector",
            format!("connector_token_hash = \"{TOKEN_HASH}\"\n"),
            "[owner_ui]\n\
             listen = \"127.0.0.1:8788\"\n\
             origin = \"http://localhost:8788\"\n"
                .to_owned(),
            format!(
                "[connector]\n\
                 listen = \"127.0.0.1:8789\"\n\
                 tls_cert_file = {crt:?}\n\
                 tls_key_file = {key_pem:?}\n"
            ),
        )
    };
    std::fs::write(
        &config,
        format!(
            "data_dir = {data_dir:?}\n\
             [bitwarden]\n\
             server = \"{server}\"\n\
             email = \"kharon@example.net\"\n\
             api_key_file = {key:?}\n\
             organization_id = \"{ORG}\"\n\
             collection_ids = [\"{COLL}\"]\n\
             [agents.assistant]\n\
             token_hash = \"{TOKEN_HASH}\"\n\
             {connector_token_hash}\
             cdp = {{ endpoint = \"ws://127.0.0.1:9222\", via = \"{via}\" }}\n\
             {owner_ui}\
             [approval]\n\
             ntfy = {{ url = \"https://ntfy.example.net\", topic = \"kharon-doctor-e2e\" }}\n\
             {connector}",
        ),
    )
    .unwrap();
    // Not group-writable, whatever the process umask is.
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640)).unwrap();
    let socket = data_dir.join("owner.sock");
    Deployment {
        _dir: dir,
        config,
        socket,
    }
}

fn doctor(config: &Path) -> Output {
    Command::new(BIN)
        .args(["doctor", "--config"])
        .arg(config)
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn req_406_doctor_all_six_checks_pass() {
    let server = start_mock_bw().await;
    let dep = deployment(&server, &user_key(), 0o400);
    start_fake_owner(&dep.socket, 1, true);
    let out = doctor(&dep.config);
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "doctor failed:\n{text}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for line in [
        "PASS config and key files",
        "PASS api key type",
        "PASS sync visibility",
        "PASS audit sink",
        "PASS passkey enrolled",
        "PASS agent attached",
        "doctor: 6 passed, 0 failed, 0 skipped",
    ] {
        assert!(text.contains(line), "missing `{line}` in:\n{text}");
    }
    assert!(!text.contains(SECRET), "secret leaked:\n{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn req_406_doctor_org_key_and_writable_key_file_fail() {
    let server = start_mock_bw().await;
    let dep = deployment(&server, &org_key(), 0o666);
    start_fake_owner(&dep.socket, 1, true);
    let out = doctor(&dep.config);
    let text = stdout(&out);
    assert!(!out.status.success(), "doctor passed:\n{text}");
    assert!(text.contains("FAIL config and key files"), "{text}");
    assert!(text.contains("chmod 0400"), "{text}");
    assert!(text.contains("FAIL api key type"), "{text}");
    assert!(text.contains("organization API key"), "{text}");
    assert!(!text.contains(SECRET), "secret leaked:\n{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn req_406_doctor_skips_without_failures_exit_zero() {
    // Assumption 5: skips never fail the run. No [owner_ui] and a
    // wireguard agent, so checks 5–6 skip; everything else passes.
    let server = start_mock_bw().await;
    let dep = deployment_with_skips(&server, &user_key(), 0o400);
    let out = doctor(&dep.config);
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "doctor failed:\n{text}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("SKIP passkey enrolled"), "{text}");
    assert!(text.contains("SKIP agent attached"), "{text}");
    assert!(
        text.contains("doctor: 4 passed, 0 failed, 2 skipped"),
        "{text}"
    );
    assert!(!text.contains(SECRET), "secret leaked:\n{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn req_406_doctor_without_a_daemon_fails_the_live_checks() {
    let server = start_mock_bw().await;
    let dep = deployment(&server, &user_key(), 0o400);
    // No fake owner: the socket path does not exist.
    let out = doctor(&dep.config);
    let text = stdout(&out);
    assert!(!out.status.success(), "doctor passed:\n{text}");
    assert!(text.contains("PASS sync visibility"), "{text}");
    assert!(text.contains("FAIL passkey enrolled"), "{text}");
    assert!(text.contains("FAIL agent attached"), "{text}");
    assert!(text.contains("start kharond"), "{text}");
    assert!(!text.contains(SECRET), "secret leaked:\n{text}");
}
