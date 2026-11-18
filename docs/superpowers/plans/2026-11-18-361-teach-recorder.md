# Teach Recorder (kharon-teach) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone `kharon-teach <login-url>` program that opens a visible Chromium on a fresh profile, records a login a person performs with throwaway credentials, and writes one recording file that says how the login works and holds nothing that was typed.

**Architecture:** Two new workspace crates. `kharon-recording` is a pure library: the typed recording format and the classifier. `kharon-teach` is a library plus a thin `main`: browser launch, its own event-subscribing CDP client, an in-page listener script, a pure capture state machine that turns events into a `Recording`, and the command line. Nothing here touches `kharond` or `kharon-connector`.

**Tech Stack:** Rust 2024, `tokio`, `tokio-tungstenite` 0.24 (no TLS), `serde`/`serde_json`, `clap` 4, `zeroize`, `sha1`/`sha2`/`md-5`, `publicsuffix` 2.3, `url` 2. Real-browser tests use the Chromium that CI already installs.

**Spec:** `docs/superpowers/specs/2026-11-18-teach-recorder-design.md`. Read it first. Where this plan and the spec disagree, stop and report; do not pick one.

## Global Constraints

- Work in the worktree `~/projects/kharon-361-teach`, on branch `duet/361-teach-recorder`, cut from `master` at `947a457` (the merge of #362, which holds the spec and this plan). No rebase, no force-push. Set `CARGO_TARGET_DIR=$PWD/target` in every cargo command; the machine's default target dir is shared between checkouts.
- Every commit message ends with these two lines and no other `Co-Authored-By` line:
  ```
  Claude-Session: https://claude.ai/code/session_017zqkEAhTEMgVMZCGQw2mT8
  Co-Authored-By: Claude & Lothrop (cycle.five@proton.me)
  ```
- CI runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and `cargo deny check`. Each task ends with the first three passing for the two new crates.
- Data this project owns is typed `serde` structs and enums. Never `serde_json::json!` or `serde_json::Value` for it. `Value` is allowed in exactly two places: CDP event parameters the recorder does not inspect, and a site's JSON request body while its shape is extracted.
- Prefer `&str` over `String` in types that are built and immediately serialized.
- `kharon-teach` depends on nothing in `crates/kharond` and not on `kharon-connector`. `tokio-tungstenite` is declared `default-features = false, features = ["connect", "handshake"]` (no TLS).
- A typed value exists only inside a `Marker` (Task 3). No `Debug`, `Display` or `Serialize` on it, and no log line, error message or panic message may contain one.
- The shipped binary always launches a visible browser. No flag and no environment variable changes that. Tests reach headless through the library's `Launch { headless: true }`.
- The binary listens on no socket and opens no connection except loopback CDP to the browser it launched.
- Real-browser tests follow the existing convention: find the binary with the same path list as `chromium_bin` in `crates/kharond/tests/req_arch_003_org_chromium.rs`, honor `KHARON_CHROMIUM`, skip when none is found unless `KHARON_REQUIRE_CHROMIUM` is set, in which case panic.
- Test files that prove a SPEC row are named for it: `req_tch_00N_<what>.rs`.
- A source scan in a test covers shipped code only: for each file under `crates/kharon-teach/src`, the text before its first `#[cfg(test)]`. Unit-test modules sit at the bottom of their file, so a test server or a test URL there does not trip a scan.
- `cargo-deny` is not installed on the dev machine. Where a task says to run `cargo deny check`, CI runs it on the PR.
- Linux only is built and tested. Platform-specific code sits behind `cfg`.

## Review Focus

Conditions the spec implies but does not spell out, most likely first. Each has a test in the task named.

1. **The person closes the window, or presses Ctrl-C, mid-login.** Expected: no hang; on window close a file is saved with `success_confirmed: false`; on Ctrl-C nothing is saved; in both the profile directory is gone. (Task 8, Task 9)
2. **No Chromium-family browser is installed, or `--browser` names a missing file.** Expected: one clear line on stderr and exit code 2, before the notice, with no directory created. (Task 6, Task 9)
3. **The `--out` file already exists, or its directory is not writable.** Expected: refused with exit code 2 before the browser opens, so a demonstration is never lost at the last step and no file is overwritten. (Task 9)
4. **A typed value that is not plain ASCII, or is very long.** `pässwörd✓12` and a 200-character password must still be found percent-encoded (UTF-8 bytes) and JSON-escaped (both raw UTF-8 and `\uXXXX` forms). (Task 3)
5. **A request body too large to analyze** (a file upload on the login site). Expected: bodies over 1 MiB are recorded as `unavailable` and set `body_unavailable`; memory stays bounded. (Task 5)

---

## File Structure

```
crates/kharon-recording/
  Cargo.toml
  src/lib.rs        re-exports
  src/format.rs     Recording and its parts; FORMAT_VERSION; to_json / from_json
  src/request.rs    StoredRequest, BodyShape, MarkerHit, Encoding, Role
  src/classify.rs   Flags, Classification, Shape, RungCeiling, classify(), is_otp_descriptor()
crates/kharon-teach/
  Cargo.toml        [lib] + [[bin]] kharon-teach
  src/main.rs       parse args, call kharon_teach::run, map to exit code
  src/lib.rs        module list, run()
  src/cli.rs        clap types, validate_login_url, output path rules
  src/notice.rs     NOTICE text, notice_page_url(), terminal consent and end prompt
  src/marker.rs     Marker, search()
  src/strip.rs      strip_url, reduce_authorization
  src/body.rs       shape_of_body
  src/site.rs       registrable_domain, CAPTCHA_HOSTS
  src/capture.rs    Capture: CaptureEvent in, Recording out (pure)
  src/browser.rs    find_browser, Profile, launch, parse_devtools_active_port
  src/cdp.rs        event-subscribing CDP client
  src/events.rs     typed CDP event params and the listener's report
  src/listener.js   the in-page script (include_str!)
  src/session.rs    record(): wires browser, cdp, listener and Capture
  tests/support/mod.rs            chromium_or_skip, fixture server, Person driver
  tests/req_tch_001_own_browser.rs
  tests/req_tch_002_no_typed_value.rs
  tests/req_tch_003_file_contents.rs
  tests/req_tch_004_no_network.rs
  tests/req_tch_005_shapes.rs
  tests/req_tch_006_profile_and_visible.rs
docs/teach-mode.md
SPEC.md             REQ-TCH-001..006 rows (Task 10)
Cargo.toml          two new workspace members
```

---

### Task 1: `kharon-recording`: the recording format

**Files:**
- Create: `crates/kharon-recording/Cargo.toml`, `src/lib.rs`, `src/format.rs`, `src/request.rs`
- Modify: `Cargo.toml` (workspace `members`)
- Test: unit tests in `src/format.rs`

**Interfaces:**
- Consumes: nothing.
- Produces (all `pub`, all derive `Debug, Clone, PartialEq, Serialize, Deserialize`; enums use `#[serde(rename_all = "snake_case")]`; tagged enums as noted):

```rust
// request.rs
pub enum Role { None, Username, Password }
pub enum Encoding { AsTyped, Percent, JsonEscaped, Base64, Base64Url, Hex,
    Md5Hex, Md5Base64, Sha1Hex, Sha1Base64, Sha256Hex, Sha256Base64, Sha512Hex, Sha512Base64 }
impl Encoding {
    pub fn is_digest(self) -> bool;                    // the eight Md5*/Sha* variants
    pub fn digest_name(self) -> Option<&'static str>;  // "md5" | "sha1" | "sha256" | "sha512"
}
pub struct MarkerHit { pub role: Role, pub encoding: Encoding, pub low_confidence: bool }
pub enum ValueKind { String, Number, Bool, Null, File }
pub struct ValueShape { pub kind: ValueKind, pub len: u32, pub markers: Vec<MarkerHit> }
pub struct FieldShape { pub key: String, pub value: ValueShape }
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JsonShape { Object { fields: Vec<JsonField> }, Array { items: Vec<JsonShape> }, Value { value: ValueShape } }
pub struct JsonField { pub key: String, pub value: JsonShape }
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BodyShape { None, Unavailable, Urlencoded { fields: Vec<FieldShape> }, Json { root: JsonShape },
    Multipart { parts: Vec<FieldShape> }, Opaque { len: u64, markers: Vec<MarkerHit> } }
pub struct AuthShape { pub scheme: String, pub markers: Vec<MarkerHit> }
pub enum ResourceKind { Document, Xhr, Fetch, Other }
pub struct ResponseShape { pub status: u16, pub content_type: Option<String>, pub set_cookie: bool }
pub struct StoredRequest { pub t_ms: u64, pub method: String, pub url: StrippedUrl, pub resource: ResourceKind,
    pub main_frame_navigation: bool, pub content_type: Option<String>, pub authorization: Option<AuthShape>,
    pub url_markers: Vec<MarkerHit>, pub body: BodyShape, pub response: Option<ResponseShape> }
impl StoredRequest { pub fn hits(&self) -> Vec<&MarkerHit>; } // url, authorization and every level of the body

// format.rs
pub const FORMAT_VERSION: u32 = 1;
pub struct StrippedUrl { pub origin: String, pub path: String, pub query_keys: Vec<String> }
pub struct FrameRef { pub main: bool, pub origin: String, pub cross_origin: bool }
pub struct FormRef { pub index: u32, pub action: Option<StrippedUrl>, pub method: String }
pub struct ElementDescriptor { pub element_id: u32, pub tag: String, pub input_type: Option<String>,
    pub id: Option<String>, pub name: Option<String>, pub autocomplete: Option<String>,
    pub placeholder: Option<String>, pub aria_label: Option<String>, pub was_password: bool,
    pub form: Option<FormRef>, pub selectors: Vec<String>, pub in_shadow_root: bool }
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Step {
    Navigation { t_ms: u64, frame: FrameRef, url: StrippedUrl },
    Input { t_ms: u64, frame: FrameRef, element: ElementDescriptor, value_len: u32, role: Role },
    Click { t_ms: u64, frame: FrameRef, element: ElementDescriptor },
    Submit { t_ms: u64, frame: FrameRef, form: FormRef },
    EnterKey { t_ms: u64, frame: FrameRef, element: ElementDescriptor },
}
pub enum EndedBy { Confirmed, WindowClosed }
pub enum ListenerWorld { Isolated, Main }
pub struct Viewport { pub width: u32, pub height: u32 }
pub struct BrowserInfo { pub product: String, pub user_agent: String, pub viewport: Viewport }
pub struct StrippedCounts { pub requests_seen: u64, pub requests_stored: u64, pub request_bodies_reduced: u64,
    pub query_values_removed: u64, pub path_segments_replaced: u64, pub typed_values_removed: u64 }
pub struct Recording { pub format_version: u32, pub tool_version: String, pub browser: BrowserInfo,
    pub listener_world: ListenerWorld,
    pub started_at: String, pub ended_at: String, pub ended_by: EndedBy, pub success_confirmed: bool,
    pub start_url: StrippedUrl, pub final_url: Option<StrippedUrl>, pub steps: Vec<Step>,
    pub requests: Vec<StoredRequest>, pub flags: Flags, pub classification: Classification,
    pub stripped: StrippedCounts }
#[derive(Debug, thiserror::Error)]
pub enum FormatError { #[error("unsupported recording format_version {0}")] UnsupportedVersion(u32),
    #[error("not a kharon recording: {0}")] Parse(#[from] serde_json::Error) }
impl Recording {
    pub fn to_json(&self) -> String;                          // serde_json::to_string_pretty + trailing newline
    pub fn from_json(text: &str) -> Result<Self, FormatError>; // version checked before the full parse
}
```

`Flags` and `Classification` are defined in Task 2. For this task, create `classify.rs` with just those two types and `Shape`, `PasswordLeg`, `RungCeiling` exactly as Task 2's Produces block gives them, so the crate compiles; Task 2 adds the functions.

An `Input` step is recorded once per element, at its first input event, and its `value_len` is updated in place as the value changes. `change` events add no step.

- [ ] **Step 1: Write the failing tests** in `src/format.rs`

```rust
#[test]
fn round_trips() {
    let r = sample(); // a small Recording built by hand: one Navigation, one Input (role Password), one StoredRequest with a Urlencoded body
    assert_eq!(Recording::from_json(&r.to_json()).unwrap(), r);
}

#[test]
fn refuses_an_unknown_version() {
    let text = sample().to_json().replace("\"format_version\": 1", "\"format_version\": 2");
    assert!(matches!(Recording::from_json(&text), Err(FormatError::UnsupportedVersion(2))));
}

#[test]
fn refuses_a_file_with_no_version() {
    assert!(matches!(Recording::from_json("{}"), Err(FormatError::Parse(_))));
}

#[test]
fn wire_names_are_snake_case_and_tagged() {
    let j = sample().to_json();
    for needle in ["\"type\": \"navigation\"", "\"role\": \"password\"", "\"kind\": \"urlencoded\"",
                   "\"encoding\": \"as_typed\"", "\"ended_by\": \"confirmed\""] {
        assert!(j.contains(needle), "missing {needle}");
    }
}

#[test]
fn hits_walks_url_authorization_and_nested_json() {
    // a StoredRequest with one hit in url_markers, one in authorization, one two levels deep in a Json body
    assert_eq!(request_with_three_hits().hits().len(), 3);
}
```

- [ ] **Step 2: Run** `cargo test -p kharon-recording`. Expected: does not compile (types missing).
- [ ] **Step 3: Implement** the crate. `Cargo.toml` copies the `[package]` block style of `crates/kharon-connector/Cargo.toml`; dependencies `serde` (derive), `serde_json`, `thiserror = "2"`. `from_json` first deserializes a private `struct VersionProbe { format_version: u32 }`, checks it, then parses the whole file.
- [ ] **Step 4: Run** `cargo test -p kharon-recording`, `cargo clippy -p kharon-recording --all-targets -- -D warnings`, `cargo fmt --all --check`. Expected: all pass.
- [ ] **Step 5: Commit** `feat(recording): typed recording format for teach mode (#361)`

---

### Task 2: `kharon-recording`: the classifier

**Files:**
- Modify: `crates/kharon-recording/src/classify.rs`, `src/lib.rs`
- Test: unit tests in `src/classify.rs`

**Interfaces:**
- Consumes: Task 1's `Step`, `StoredRequest`, `ElementDescriptor`, `Role`, `Encoding`, `ResourceKind`.
- Produces:

```rust
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Flags { pub captcha: bool, pub otp_step: bool, pub cross_site: bool, pub popup: bool,
    pub framed_login: bool, pub shadow_dom: bool, pub multiple_passwords: bool, pub body_unavailable: bool }
#[serde(rename_all = "snake_case")] pub enum PasswordLeg { FormPost, ScriptPost, Transformed }
#[serde(tag = "kind", rename_all = "snake_case")] // on the wire: "shape": {"kind": "two_step", "password_leg": "form_post"}
pub enum Shape { FormPost, ScriptPost, TwoStep { password_leg: PasswordLeg },
    Transformed { digest: Option<String> }, Unrecognized }
#[serde(rename_all = "snake_case")] pub enum RungCeiling { Milliseconds, AgentContinues, NeedsPerson }
pub struct Classification { pub shape: Shape, pub rung_ceiling: RungCeiling,
    pub network_swap_candidate: bool, pub notes: Vec<String> }
pub fn classify(steps: &[Step], requests: &[StoredRequest], flags: &Flags) -> Classification;
pub fn is_otp_descriptor(e: &ElementDescriptor) -> bool;
```

The rules, in the order they are applied. "Plain hit" means a `MarkerHit` with `role == Password` and `!encoding.is_digest()`. "Digest hit" is the same with `is_digest()`.

1. If any of `cross_site`, `popup`, `framed_login`, `multiple_passwords` is set: `Unrecognized`.
2. If no `Input` step has `role == Password`: `Unrecognized`, note `"no password field was used"`.
3. Let `p` be the `t_ms` of the first password `Input` step. The login is two-step when a main-frame `Navigation` step lies between the username `Input` step and `p`, or a stored request with `t_ms < p` has a `Username` hit and no `Password` hit.
4. The password leg: take the earliest request with a plain hit. `resource == Document && main_frame_navigation` gives `FormPost`; `Xhr` or `Fetch` gives `ScriptPost`; anything else gives `Unrecognized`. With no plain hit: `Unrecognized` if `body_unavailable`, else `Transformed`, whose digest is the `digest_name()` of the first digest hit, if any.
5. Shape: two-step wraps the leg as `TwoStep { password_leg }` (a leg of `Unrecognized` makes the whole shape `Unrecognized`); otherwise the leg is the shape.
6. Ceiling starts at `Milliseconds`. Lower to `AgentContinues` when the shape is `TwoStep`, when `captcha` or `otp_step` is set, or when the password element has `form == None` and no `EnterKey` step and no `Click` step on a `button` or an `input_type == "submit"` element follows `p`. Lower to `NeedsPerson` for `Unrecognized` and for `Transformed { digest: None }`.
7. `network_swap_candidate`: exactly one stored request has a plain hit.

`is_otp_descriptor` restates the three TOTP tests in `resolveField` in `crates/kharond/src/cdp/page_js.rs`: `autocomplete` contains `one-time`, `name` contains `otp` ignoring case, or `input_type == "tel"`. Put a comment at both sites naming the other.

- [ ] **Step 1: Write the failing tests.** One helper builds steps and requests tersely (`login(username_then, password_in_form, request(...))`). Tests, each asserting the full `Classification` fields named:

```rust
#[test] fn form_post()            // Document main-frame POST, plain hit -> FormPost, Milliseconds, swap true
#[test] fn script_post()          // Fetch, JsonEscaped hit -> ScriptPost, Milliseconds, swap true
#[test] fn two_step_by_navigation()   // Navigation between username and password input -> TwoStep{FormPost}, AgentContinues
#[test] fn two_step_by_request()      // earlier request with Username hit only -> TwoStep{ScriptPost}, AgentContinues
#[test] fn transformed_with_digest()  // only a Sha256Hex hit -> Transformed{digest: Some("sha256")}, Milliseconds, swap false
#[test] fn transformed_unknown()      // no hit at all -> Transformed{digest: None}, NeedsPerson
#[test] fn password_nowhere_and_body_unavailable_is_unrecognized()
#[test] fn each_blocking_flag_wins()  // loop over cross_site, popup, framed_login, multiple_passwords on a clean form_post -> Unrecognized, NeedsPerson
#[test] fn captcha_caps_a_form_post_at_agent_continues()
#[test] fn otp_step_caps_at_agent_continues()
#[test] fn no_way_to_submit_caps_at_agent_continues() // password element with form None, no EnterKey, no submitting Click
#[test] fn enter_key_keeps_milliseconds_without_a_form()
#[test] fn two_plain_hits_is_not_a_swap_candidate()
#[test] fn no_password_step_is_unrecognized()
#[test] fn otp_descriptor_matches_the_three_tests_and_nothing_else()
```

- [ ] **Step 2: Run** `cargo test -p kharon-recording classify`. Expected: FAIL (functions missing).
- [ ] **Step 3: Implement** `classify` and `is_otp_descriptor`. Each lowering of the ceiling and each `Unrecognized` adds one plain-English note saying why.
- [ ] **Step 4: Run** tests, clippy, fmt. Expected: pass.
- [ ] **Step 5: Commit** `feat(recording): classify a recorded login by shape and rung ceiling (#361)`

---

### Task 3: `kharon-teach`: crate scaffold and markers

**Files:**
- Create: `crates/kharon-teach/Cargo.toml`, `src/lib.rs`, `src/main.rs` (prints "not implemented" and exits 1 for now), `src/marker.rs`
- Modify: `Cargo.toml` (workspace member)
- Test: unit tests in `src/marker.rs`

**Interfaces:**
- Consumes: `kharon_recording::{Role, Encoding, MarkerHit}`.
- Produces:

```rust
pub struct Marker { /* private: Zeroizing<String>, Role */ }
impl Marker {
    pub fn new(value: zeroize::Zeroizing<String>, role: Role) -> Self;
    pub fn role(&self) -> Role;
    pub fn len(&self) -> u32;            // length in chars
    pub fn is_empty(&self) -> bool;
    pub fn same_value(&self, other: &Marker) -> bool; // constant-time is not required
    pub fn with_role(self, role: Role) -> Self;
}
/// Every way `marker` occurs in `haystack`. Digests are searched only for Role::Password.
pub fn search(haystack: &[u8], marker: &Marker) -> Vec<MarkerHit>;
/// The base64 and base64url (padded or not) of `username:password`. A match returns two hits,
/// one per role, both `Encoding::Base64` (or `Base64Url`).
pub fn search_pair(haystack: &[u8], username: &Marker, password: &Marker) -> Vec<MarkerHit>;
pub const LOW_CONFIDENCE_BELOW: u32 = 6;
```

`Marker` implements none of `Debug`, `Display`, `Serialize`, `Clone`. `search` returns at most one hit per `Encoding`, sets `low_confidence` when `marker.len() < LOW_CONFIDENCE_BELOW`, and returns nothing for an empty marker. Encodings: as typed (UTF-8 bytes); percent-encoded both with space as `%20` and as `+`; JSON-escaped both keeping non-ASCII raw and as `\uXXXX`; standard and URL-safe base64, each with and without padding; lowercase and uppercase hex; and for passwords the hex and standard base64 of MD5, SHA-1, SHA-256 and SHA-512 of the UTF-8 bytes. When the as-typed form equals an encoded form (a plain alphanumeric value), report only `AsTyped`. When the standard and URL-safe base64 forms are identical, report only `Base64`.

- [ ] **Step 1: Write the failing tests**

```rust
fn pw(s: &str) -> Marker { Marker::new(Zeroizing::new(s.to_owned()), Role::Password) }
fn encodings(h: &[u8], m: &Marker) -> Vec<Encoding> { search(h, m).into_iter().map(|x| x.encoding).collect() }

#[test] fn as_typed() { assert_eq!(encodings(b"user=a&password=Tr0ub4dor-9x&x=1", &pw("Tr0ub4dor-9x")), [Encoding::AsTyped]); }
#[test] fn percent_encoded() { assert_eq!(encodings(b"p=a%20b%26c%2Bd12", &pw("a b&c+d12")), [Encoding::Percent]); }
#[test] fn percent_encoded_plus_for_space() { assert_eq!(encodings(b"p=a+b%26c%2Bd12", &pw("a b&c+d12")), [Encoding::Percent]); }
#[test] fn json_escaped() { assert_eq!(encodings(br#"{"p":"a\"b\\c12"}"#, &pw(r#"a"b\c12"#)), [Encoding::JsonEscaped]); }
#[test] fn base64_and_base64url() {
    assert_eq!(encodings(b"x=Pj4+Pz8/MTI=", &pw(">>>???12")), [Encoding::Base64]);
    assert_eq!(encodings(b"x=Pj4-Pz8_MTI", &pw(">>>???12")), [Encoding::Base64Url]); // unpadded is found too
}
#[test] fn hex_either_case() { /* lowercase and uppercase hex of "Tr0ub4dor-9x" both give [Encoding::Hex] */ }
#[test] fn sha256_hex_of_a_password() { /* haystack holds hex(sha256("Tr0ub4dor-9x")) -> [Sha256Hex] */ }
#[test] fn digests_are_not_searched_for_a_username() { /* same haystack, Role::Username -> [] */ }
#[test] fn short_marker_is_low_confidence() { assert!(search(b"x=abc12", &pw("abc12"))[0].low_confidence); }
#[test] fn empty_marker_matches_nothing() { assert!(search(b"anything", &pw("")).is_empty()); }
#[test] fn non_ascii_percent_encoded() { /* "pässwörd✓12" as UTF-8 percent-encoded -> [Percent] */ }
#[test] fn non_ascii_json_escaped_both_forms() { /* raw UTF-8 inside quotes -> [AsTyped]; ä-style escapes -> [JsonEscaped] */ }
#[test] fn two_hundred_characters() { /* a 200-char value is found as typed */ }
#[test] fn pair_is_found_where_neither_value_alone_is() {
    // haystack: {"auth":"<base64("kh.throwaway7:Tr0ub4dor-9x")>"}; search() finds nothing for either marker;
    // search_pair() returns [Username Base64, Password Base64]
}
```

Also add this doc test on `Marker`, which is the compile-time guard:

```rust
/// ```compile_fail
/// let m = kharon_teach::marker::Marker::new(zeroize::Zeroizing::new(String::from("x")), kharon_recording::Role::Password);
/// println!("{:?}", m);
/// ```
```

- [ ] **Step 2: Run** `cargo test -p kharon-teach marker`. Expected: does not compile.
- [ ] **Step 3: Implement.** `Cargo.toml`: `[lib]` plus `[[bin]] name = "kharon-teach"`; dependencies for this task `kharon-recording` (path), `zeroize`, `sha1 = "0.10"`, `sha2 = "0.10"`, `md-5 = "0.10"`, `base64ct` (features `alloc`), `hex = "0.4"`, `percent-encoding = "2"`. Encoded needles are built in `Zeroizing<Vec<u8>>`.
- [ ] **Step 4: Run** tests (including `cargo test -p kharon-teach --doc`), clippy, fmt, and `cargo deny check` (a new crate, `md-5`, enters the tree). Expected: pass.
- [ ] **Step 5: Commit** `feat(teach): markers and their search over request bytes (#361)`

---

### Task 4: stripping and body shapes

**Files:**
- Create: `crates/kharon-teach/src/strip.rs`, `src/body.rs`
- Test: unit tests in both

**Interfaces:**
- Consumes: `Marker`, `search` (Task 3); `StrippedUrl`, `BodyShape`, `AuthShape`, `FieldShape`, `JsonShape`, `ValueShape`, `ValueKind`, `MarkerHit` (Task 1).
- Produces:

```rust
// strip.rs
pub struct Stripped<T> { pub value: T, pub query_values_removed: u64, pub path_segments_replaced: u64 }
/// Origin, path and query keys of `url`. A path segment becomes "{id}" when it is all ASCII digits,
/// a UUID, 16 or more hex characters, or contains any marker (as typed or percent-encoded).
pub fn strip_url(url: &str, markers: &[Marker]) -> Option<Stripped<StrippedUrl>>; // None when `url` does not parse
/// scheme = first token, lowercased. For `basic`, the credentials are base64-decoded and the decoded bytes
/// are searched; a marker found there is reported with `Encoding::Base64`. Other schemes are searched as sent.
/// When `pair` is given the value is also searched with `search_pair`. No (role, encoding) is listed twice.
pub fn reduce_authorization(header_value: &[u8], markers: &[Marker], pair: Option<(&Marker, &Marker)>) -> AuthShape;
// body.rs
pub const MAX_BODY_BYTES: usize = 1 << 20;
/// `content_type` picks the reader: application/x-www-form-urlencoded, application/json (and any +json),
/// multipart/form-data; anything else, or a body that fails to parse as its declared type, is Opaque.
/// `pair` is (username, password) once both are known; see below.
pub fn shape_of_body(content_type: Option<&str>, body: &[u8], markers: &[Marker], pair: Option<(&Marker, &Marker)>) -> BodyShape;
```

A multipart part with a `filename` is `ValueKind::File` with its length and no marker search. Every other value is searched with every marker and, when `pair` is given, with `search_pair`, so a combined credential is recorded on the value that holds it (an `Opaque` body holds it at whole-body level). A place never lists the same role and encoding twice. `shape_of_body` never returns `None` or `Unavailable`; the caller (Task 5) chooses those.

- [ ] **Step 1: Write the failing tests**

```rust
// strip.rs
#[test] fn keeps_origin_path_and_query_keys() {
    let s = strip_url("https://ex.test/login/step?next=%2Fhome&lang=en#frag", &[]).unwrap();
    assert_eq!(s.value, StrippedUrl { origin: "https://ex.test".into(), path: "/login/step".into(), query_keys: vec!["next".into(), "lang".into()] });
    assert_eq!(s.query_values_removed, 2);
}
#[test] fn replaces_id_like_segments() {
    for (path, want) in [("/users/12345/home", "/users/{id}/home"),
                         ("/s/3f2b8c1e-9a4d-4c1b-8e2f-0a1b2c3d4e5f", "/s/{id}"),
                         ("/t/0123456789abcdef0123", "/t/{id}"),
                         ("/v2/login", "/v2/login")] { /* assert path */ }
}
#[test] fn replaces_a_segment_that_contains_a_marker() { /* username marker "kh.throwaway7" in /u/kh.throwaway7/dash -> /u/{id}/dash */ }
#[test] fn unparseable_url_is_none() { assert!(strip_url("not a url", &[]).is_none()); }
#[test] fn basic_auth_is_reduced_to_scheme_and_hits() { /* "Basic " + base64("kh.throwaway7:Tr0ub4dor-9x") -> scheme "basic"; markers == [Username Base64, Password Base64] */ }
#[test] fn bearer_keeps_no_token() { /* AuthShape { scheme: "bearer", markers: [] } and its JSON has no token bytes */ }

// body.rs
#[test] fn urlencoded_fields_with_roles() { /* "user=kh.throwaway7&password=Tr0ub4dor-9x&remember=1" -> three fields; password field has one AsTyped Password hit; remember has len 1 and no hit */ }
#[test] fn json_nested() { /* {"auth":{"id":"kh.throwaway7","secret":"Tr0ub4dor-9x"},"n":3,"ok":true,"z":null} -> Object with kinds String/Number/Bool/Null and hits on the two strings */ }
#[test] fn graphql_is_json() { /* {"query":"mutation…","variables":{"password":"Tr0ub4dor-9x"}} -> hit under variables.password */ }
#[test] fn multipart_text_and_file() { /* a text part "password" with a hit, a file part kind File with no hits */ }
#[test] fn unknown_type_is_opaque_with_whole_body_hit() { /* content type application/octet-stream holding the password bytes -> Opaque { len, markers: [AsTyped] } */ }
#[test] fn bad_json_falls_back_to_opaque() {}
#[test] fn a_combined_credential_lands_on_the_value_that_holds_it() { /* {"auth":"<base64("kh.throwaway7:Tr0ub4dor-9x")>","n":1} with pair -> the auth value has [Username Base64, Password Base64]; without pair -> no hits */ }
#[test] fn basic_auth_with_the_pair_lists_each_hit_once() { /* reduce_authorization on a Basic header with pair given -> still exactly [Username Base64, Password Base64] */ }
#[test] fn serialized_shapes_never_contain_a_marker() { /* for each case above: serde_json::to_string(&shape) contains neither "Tr0ub4dor-9x" nor "kh.throwaway7" */ }
```

- [ ] **Step 2: Run** `cargo test -p kharon-teach -- strip body` (cargo takes one filter before `--`; several go after it). Expected: FAIL.
- [ ] **Step 3: Implement.** Add `url = "2"`, `serde_json`. The JSON body is the one place a site payload is read as `serde_json::Value`; say so in a comment. Urlencoded keys and JSON keys are kept as they are; values never are.
- [ ] **Step 4: Run** tests, clippy, fmt. Expected: pass.
- [ ] **Step 5: Commit** `feat(teach): strip URLs and reduce request bodies to shapes (#361)`

---

### Task 5: the capture state machine

**Files:**
- Create: `crates/kharon-teach/src/capture.rs`, `src/site.rs`
- Test: unit tests in `src/capture.rs`, `src/site.rs`

**Interfaces:**
- Consumes: Tasks 1 to 4.
- Produces:

```rust
// site.rs
pub fn registrable_domain(host: &str) -> String;   // PSL-reduced; an IP or "localhost" is returned unchanged
pub fn is_captcha_host(host: &str) -> bool;        // CAPTCHA_HOSTS, matched on the host or any parent domain

// capture.rs
pub struct RawElement { pub element_id: u32, pub document_id: String, pub tag: String, pub input_type: Option<String>,
    pub id: Option<String>, pub name: Option<String>, pub autocomplete: Option<String>, pub placeholder: Option<String>,
    pub aria_label: Option<String>, pub is_password_now: bool, pub form: Option<RawForm>,
    pub selectors: Vec<String>, pub in_shadow_root: bool }
pub struct RawForm { pub index: u32, pub action: Option<String>, pub method: String }
pub struct RawFrame { pub main: bool, pub url: String }
pub enum PageEventKind { Input, Change, Click, Submit, EnterKey }
pub enum RawBody { None, Unavailable, Bytes(zeroize::Zeroizing<Vec<u8>>) }
pub enum CaptureEvent {
    Started { browser: BrowserInfo, listener_world: ListenerWorld }, // the main frame left the notice page
    Navigation { t_ms: u64, frame: RawFrame },              // main and child frames alike
    Page { t_ms: u64, kind: PageEventKind, frame: RawFrame, element: RawElement,
           value: Option<zeroize::Zeroizing<String>> },      // value only for Input and Change
    Request { request_id: String, t_ms: u64, method: String, url: String, resource: ResourceKind,
              main_frame_navigation: bool, content_type: Option<String>,
              authorization: Option<zeroize::Zeroizing<Vec<u8>>>, body: RawBody, frame_url: String },
    Response { request_id: String, status: u16, content_type: Option<String>, set_cookie: bool },
    Popup,
}
pub struct EndInfo { pub ended_by: EndedBy, pub success_confirmed: bool, pub started_at: String, pub ended_at: String }
pub struct Capture { /* private */ }
impl Capture {
    pub fn new(start_url: &str, tool_version: &str) -> Self;
    pub fn push(&mut self, ev: CaptureEvent);
    pub fn started(&self) -> bool;
    /// Resolves markers, searches the buffered requests, strips, sets flags, classifies.
    pub fn finish(self, end: EndInfo) -> Recording;
}
```

Decisions `finish` implements, beyond the spec's text:

- Username candidates are tried against the raw buffered bytes first. Once the username is resolved, every buffered request is reduced with the pair: `search_pair` over the URL bytes goes into `url_markers`, and `reduce_authorization` and `shape_of_body` are called with `pair = Some((username, password))`, so a combined credential is recorded where it sits.
- Elements are keyed by `(document_id, element_id)`. One `Marker` per element holds its latest value. An element is a password element if any of its reports had `is_password_now`.
- Password markers: the latest values of password elements, with equal values merged. More than one distinct value sets `multiple_passwords`.
- Username: among non-password elements with a non-empty value, prefer one in the same form as a password element; else one whose value is found in a request that also carries the password; else one whose value is found in any request; else the last one typed in before the first password input. Other typed values are dropped.
- The login site is `registrable_domain` of the start URL's host. `cross_site`: a main-frame navigation to a different registrable domain after `Started`. `framed_login`: a password element whose frame is not main and whose origin differs from the main frame's. `shadow_dom`: a password or username element with `in_shadow_root`. `captcha`: a `Navigation` of any frame, or a `Request`, whose host `is_captcha_host`. `otp_step`: an `Input` step later than the first password input whose element `is_otp_descriptor`. `popup`: any `Popup`.
- A body over `MAX_BODY_BYTES` is treated as `Unavailable`. `body_unavailable` is set when a non-GET request to the login site has an `Unavailable` body.
- Stored requests: main-frame navigations since `Started`; requests with any hit; non-GET requests to the login site after the first `Input`. All requests count in `requests_seen`.
- `final_url` is the last main-frame navigation.

`CAPTCHA_HOSTS`: `google.com/recaptcha` is a path, so match hosts only: `recaptcha.net`, `www.google.com` when the path starts with `/recaptcha/`, `hcaptcha.com`, `challenges.cloudflare.com`, `arkoselabs.com`, `funcaptcha.com`. `is_captcha_host` takes the host; the `/recaptcha/` path case is checked in `capture.rs` where the URL is in hand.

- [ ] **Step 1: Write the failing tests.** A small builder feeds events (`Session::new("https://ex.test/login").type_into(el, "…").click(el).request(...)`). Markers in tests: username `kh.throwaway7`, password `Tr0ub4dor-9x`.

```rust
#[test] fn form_post_end_to_end()        // classification.shape == FormPost; steps hold one Input per element with roles Username and Password
#[test] fn keystrokes_collapse_to_one_input_step() // ten Input events on one element -> one Step::Input, value_len == 12
#[test] fn show_password_toggle_keeps_the_password() // is_password_now true then false on the same element -> still the password marker
#[test] fn confirm_field_with_the_same_value_is_one_password() // flags.multiple_passwords == false
#[test] fn two_different_passwords_set_the_flag_and_block() // multiple_passwords, shape Unrecognized
#[test] fn two_step_by_navigation()
#[test] fn username_falls_back_to_the_value_sent_with_the_password() // no form on either element
#[test] fn cross_site_navigation_sets_the_flag() // ex.test -> idp.other.test
#[test] fn same_site_subdomain_is_not_cross_site() // ex.test -> login.ex.test
#[test] fn captcha_frame_sets_the_flag()
#[test] fn otp_input_after_the_password_sets_the_flag()
#[test] fn oversized_body_is_unavailable_and_flagged() // a MAX_BODY_BYTES + 1 body on a POST to the login site
#[test] fn a_combined_base64_credential_in_a_json_body_is_a_plain_hit() // classifies as ScriptPost, not Transformed
#[test] fn only_the_three_kinds_of_request_are_stored() // a GET image and a third-party POST are counted, not stored
#[test] fn events_before_started_are_ignored_for_steps()
#[test] fn the_serialized_recording_holds_no_typed_value() {
    // for every scenario above: recording.to_json() contains neither marker in any encoding
    // (as typed, percent, base64, hex, sha256 hex). Share the needle list with Task 8's test via a pub(crate) helper.
}
// site.rs
#[test] fn registrable_domains() { /* login.ex.co.uk -> ex.co.uk; 127.0.0.1 and localhost unchanged */ }
```

- [ ] **Step 2: Run** `cargo test -p kharon-teach -- capture site`. Expected: FAIL.
- [ ] **Step 3: Implement.** Load the public suffix list the way `crates/kharond/src/origin.rs` does: `include_bytes!` of the same vendored snapshot, `crates/kharond/data/public_suffix_list.dat`, by relative path. That is one data file shared, not a crate dependency; do not copy it. Requests are buffered with their bodies in `Zeroizing` buffers and analyzed in `finish`, after the markers are known.
- [ ] **Step 4: Run** tests, clippy, fmt. Expected: pass.
- [ ] **Step 5: Commit** `feat(teach): capture state machine from events to a stripped recording (#361)`

---

### Task 6: browser launch and the profile's life

**Files:**
- Create: `crates/kharon-teach/src/browser.rs`
- Test: unit tests in `src/browser.rs`; `tests/support/mod.rs` (only `chromium_or_skip` for now); `tests/req_tch_001_own_browser.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:

```rust
#[derive(Debug, thiserror::Error)]
pub enum BrowserError { #[error("no Chromium-family browser found; pass --browser <path>")] NotFound,
    #[error("browser not found at {0}")] BadPath(std::path::PathBuf),
    #[error("the browser did not start: {0}")] Launch(String) }
pub fn find_browser(explicit: Option<&std::path::Path>) -> Result<std::path::PathBuf, BrowserError>; // uses $PATH
pub fn find_browser_in(explicit: Option<&std::path::Path>, path_var: &std::ffi::OsStr) -> Result<std::path::PathBuf, BrowserError>;
pub const PROFILE_PREFIX: &str = "kharon-teach-";
pub struct Profile { /* private */ }
impl Profile {
    pub fn create() -> std::io::Result<Self>;          // <temp>/kharon-teach-<random>, mode 0700
    pub fn path(&self) -> &std::path::Path;
    pub fn remove(self) -> std::io::Result<()>;        // also runs on Drop, ignoring errors
    /// Removes leftover PROFILE_PREFIX directories in the temp location owned by this user. Returns how many.
    pub fn sweep_stale() -> std::io::Result<usize>;
}
pub struct Launch<'a> { pub browser: &'a std::path::Path, pub profile: &'a Profile,
    pub first_url: &'a str, pub headless: bool }
pub struct Browser { /* private: tokio::process::Child */ }
pub struct DevTools { pub port: u16, pub ws_path: String }
impl Browser {
    pub async fn launch(l: Launch<'_>) -> Result<(Browser, DevTools), BrowserError>; // waits up to 20 s for DevToolsActivePort
    pub fn pid(&self) -> u32;
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus>;
    pub async fn close(self) -> std::io::Result<()>;   // kill and reap
}
pub fn parse_devtools_active_port(text: &str) -> Option<DevTools>;
```

Launch arguments: `--user-data-dir=<profile>`, `--remote-debugging-port=0`, `--no-first-run`, `--no-default-browser-check`, `--disk-cache-size=1`, `--disable-sync`, `--password-store=basic`, `--disable-features=AutofillServerCommunication,PasswordManagerOnboarding`, plus `--headless=new` when `headless`, then `first_url`. Before launch, write `<profile>/Default/Preferences` with `credentials_enable_service: false`, `profile.password_manager_enabled: false`, `autofill.profile_enabled: false` and `autofill.credit_card_enabled: false` (a typed struct, serialized). If the browser CI uses rejects a flag, drop that flag and say so in the commit; the test in Task 8 is what must hold. `find_browser` search order with no explicit path: `chromium`, `chromium-browser`, `google-chrome`, `google-chrome-stable`, `microsoft-edge`, `brave-browser` on `PATH`. `parse_devtools_active_port` is a copy of the rules in `crates/kharon-connector/src/devtools.rs`; the loopback host is never taken from the file.

- [ ] **Step 1: Write the failing tests**

```rust
// unit
#[test] fn profile_is_private_and_removed() { /* mode & 0o777 == 0o700; after remove() the path is gone */ }
#[test] fn profile_is_removed_on_drop() {}
#[test] fn sweep_removes_a_leftover_and_counts_it() { /* make <temp>/kharon-teach-stale by hand; sweep_stale() >= 1; it is gone */ }
#[test] fn sweep_leaves_other_directories() {}
#[test] fn no_browser_on_an_empty_path_is_not_found() { assert!(matches!(find_browser_in(None, OsStr::new("")), Err(BrowserError::NotFound))); }
#[test] fn finds_the_first_name_in_search_order() { /* a temp dir on path_var holding executable stubs "google-chrome" and "chromium" -> the chromium one */ }
#[test] fn explicit_missing_browser_is_bad_path() { assert!(matches!(find_browser(Some(Path::new("/nonexistent/chrome"))), Err(BrowserError::BadPath(_)))); }
#[test] fn parses_the_two_line_file() { /* "45123\n/devtools/browser/abc-123\n" -> port 45123 */ }
#[test] fn rejects_port_zero_garbage_and_a_foreign_path() {}

// tests/req_tch_001_own_browser.rs (real browser, headless)
#[tokio::test] async fn launches_on_its_own_profile_and_binds_loopback_only() {
    // launch headless on about:blank; the process command line holds --user-data-dir=<profile.path()>;
    // 127.0.0.1:<port>/json/version answers; nothing listens on that port on a non-loopback address
    // (read /proc/net/tcp for the port and assert every listener is 0100007F); close(); profile removed.
}
#[test] fn the_library_has_no_way_to_attach_elsewhere() {
    // source scan of crates/kharon-teach/src: no "ws://" or "http://" literal other than the 127.0.0.1 CDP URL
    // builder in cdp.rs/browser.rs, and Launch has no endpoint or profile-path-from-user field.
}
```

- [ ] **Step 2: Run** `cargo test -p kharon-teach browser` and `--test req_tch_001_own_browser`. Expected: FAIL.
- [ ] **Step 3: Implement.** Add `tokio` (features `fs`, `macros`, `net`, `process`, `rt-multi-thread`, `signal`, `sync`, `time`, `io-std`, `io-util`), `thiserror`, `serde`, `rand = "0.8"`.
- [ ] **Step 4: Run** tests with `KHARON_REQUIRE_CHROMIUM=1`, clippy, fmt. Expected: pass.
- [ ] **Step 5: Commit** `feat(teach): launch a browser on a private throwaway profile (#361)`

---

### Task 7: the event-subscribing CDP client

**Files:**
- Create: `crates/kharon-teach/src/cdp.rs`, `src/events.rs`
- Test: unit tests in `src/cdp.rs` against an in-test WebSocket server

**Interfaces:**
- Consumes: `DevTools` (Task 6).
- Produces:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CdpError { #[error("cdp connection closed")] Closed, #[error("cdp error {code}: {message}")] Remote { code: i64, message: String },
    #[error("cdp transport: {0}")] Transport(String), #[error("cdp reply did not parse: {0}")] Parse(#[from] serde_json::Error) }
pub struct Event { pub method: String, pub session_id: Option<String>, pub params: Box<serde_json::value::RawValue> }
pub struct Cdp { /* private */ }
impl Cdp {
    /// Dials ws://127.0.0.1:<port><ws_path>. The host is a constant.
    pub async fn connect(dev: &DevTools) -> Result<(Cdp, tokio::sync::mpsc::UnboundedReceiver<Event>), CdpError>;
    pub async fn call<P: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self, method: &str, params: &P, session_id: Option<&str>) -> Result<R, CdpError>;
}
```

`events.rs` holds typed `Deserialize` structs for the parameters the recorder reads, each with only the fields it uses: `AttachedToTarget`, `TargetInfo`, `FrameNavigated`, `BindingCalled`, `RequestWillBeSent`, `ResponseReceived`, `TargetDestroyed`, `VersionInfo`; typed `Serialize` structs for every params object it sends; and `ListenerReport`, the JSON the page script passes through the binding, whose `value` field is `Option<Zeroizing<String>>` (enable `zeroize`'s `serde` feature). Request and response headers arrive as an object of arbitrary keys: deserialize them into a `HashMap<String, Zeroizing<String>>` and read only `content-type`, `authorization` and the presence of `set-cookie`, case-insensitively.

- [ ] **Step 1: Write the failing tests** with a local `tokio_tungstenite::accept_async` server on `127.0.0.1:0`:

```rust
#[tokio::test] async fn a_call_gets_its_own_reply()          // two concurrent calls, replies sent in reverse order
#[tokio::test] async fn a_remote_error_is_returned()         // {"id":1,"error":{"code":-32000,"message":"nope"}} -> CdpError::Remote
#[tokio::test] async fn events_are_delivered_with_their_session() // {"method":"Page.frameNavigated","sessionId":"S1","params":{…}}
#[tokio::test] async fn session_id_is_sent_at_top_level()    // the server asserts the frame it received
#[tokio::test] async fn calls_fail_after_the_socket_closes() // CdpError::Closed, no hang
#[test] fn listener_report_parses_and_value_is_zeroizing()   // a sample report JSON -> ListenerReport
#[test] fn headers_are_read_case_insensitively()
```

- [ ] **Step 2: Run** `cargo test -p kharon-teach -- cdp events`. Expected: FAIL.
- [ ] **Step 3: Implement.** Add `tokio-tungstenite = { version = "0.24", default-features = false, features = ["connect", "handshake"] }`, `futures-util`. One reader task routes replies by `id` to `oneshot` senders and everything else to the event channel. Outgoing frames are typed structs, never `json!`.
- [ ] **Step 4: Run** tests, clippy, fmt. Expected: pass.
- [ ] **Step 5: Commit** `feat(teach): a CDP client that subscribes to events (#361)`

---

### Task 8: the listener script, the session, and the real-browser tests

**Files:**
- Create: `crates/kharon-teach/src/listener.js`, `src/session.rs`, `src/notice.rs` (only `notice_page_url` and `NOTICE` here)
- Create: `tests/support/mod.rs` (fixture server and `Person`), `tests/req_tch_002_no_typed_value.rs`, `tests/req_tch_005_shapes.rs`, `tests/req_tch_006_profile_and_visible.rs`

**Interfaces:**
- Consumes: Tasks 5, 6, 7.
- Produces:

```rust
// notice.rs
pub const NOTICE: &str = "kharon-teach records how a login works so kharon can learn it.\n\
Use a THROWAWAY account. Everything you type in the window that\n\
opens is read by this program. Nothing you type is saved, and\n\
nothing is sent anywhere. The result is one file on this computer.\n";
/// A data: URL page that shows NOTICE and one link, "Start recording and open <host>", to `login_url`.
pub fn notice_page_url(login_url: &url::Url) -> String;

// session.rs
pub enum End { Confirmed, Discard }
pub struct RecordOptions<'a> { pub login_url: &'a url::Url, pub browser: &'a std::path::Path,
    pub headless: bool, pub tool_version: &'a str }
pub struct Ready { pub devtools_port: u16, pub profile_dir: std::path::PathBuf, pub stale_profiles_removed: usize }
#[derive(Debug, thiserror::Error)]
pub enum SessionError { #[error(transparent)] Browser(#[from] BrowserError), #[error(transparent)] Cdp(#[from] CdpError),
    #[error(transparent)] Io(#[from] std::io::Error) }
pub enum Outcome { Recorded(Box<Recording>), Discarded, NeverStarted }
/// RFC 3339 UTC, with the `time` crate as `crates/kharond/src/audit/log.rs` does. Fills `EndInfo`; Task 9 reuses it.
pub fn utc_rfc3339(t: std::time::SystemTime) -> String;
/// Sweeps stale profiles, launches, records until `end` fires or the window closes, cleans up.
/// `ready` fires once the browser is up. Dropping the future (Ctrl-C) still removes the profile.
pub async fn record(opts: RecordOptions<'_>, ready: tokio::sync::oneshot::Sender<Ready>,
    end: tokio::sync::oneshot::Receiver<End>) -> Result<Outcome, SessionError>;
```

Wiring, in order: `Profile::sweep_stale`; `Profile::create`; `Browser::launch` with `first_url = notice_page_url(..)`; `Cdp::connect`; `Target.setAutoAttach { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }` on the browser session and again on each attached page session; for each attached target of type `page` or `iframe`: `Page.enable`, `Network.enable`, `Runtime.addBinding { name: "__kharonTeach", executionContextName: "kharon-teach" }`, `Page.addScriptToEvaluateOnNewDocument { source: LISTENER_JS, worldName: "kharon-teach" }`, then `Runtime.runIfWaitingForDebugger`. If the binding is not visible in the isolated world, install script and binding in the main world instead. Which world was used goes into `CaptureEvent::Started` as `listener_world`, and so into the file; say in the commit message which one the CI browser needed. Other target types are released without attaching streams. A second `page` target after the first sends `CaptureEvent::Popup`. `CaptureEvent::Started` is sent when the main frame first navigates to a URL that is not the notice page; its `BrowserInfo` comes from `Browser.getVersion` (product, user agent) and `Page.getLayoutMetrics` (the CSS viewport). A request with `hasPostData` and no inline body is completed with `Network.getRequestPostData`; an error there is `RawBody::Unavailable`. The window counts as closed when the last `page` target is destroyed or the browser process exits; that ends as `EndedBy::WindowClosed` with `success_confirmed: false`, or `Outcome::NeverStarted` if `Started` never fired.

`listener.js` reports, in the capture phase on `document`: `input` and `change` on `input`, `textarea`, `select`; `click` on `button`, `a`, `input[type=submit]`, `input[type=button]`, `[role=button]`; `submit` on forms; `keydown` with `key === "Enter"` on an `input`. It numbers elements with a `WeakMap` counter, gives each document a random `document_id`, uses `event.composedPath()[0]` to see into open shadow roots, and builds `selectors` (how is the builder's call; the first entry must match the element with `document.querySelector` at the time of the event when the element is not in a shadow root). It sends `value` only for `input` and `change`. It keeps no state other than the counter.

- [ ] **Step 1: Write the fixture server and the `Person`** in `tests/support/mod.rs`. The server binds `127.0.0.1:0` and serves:
  - `/form`: a `<form method=post action=/form-login>` with `name=user`, `name=pass type=password`, a submit button. `POST /form-login` answers 302 to `/home`.
  - `/script`: the same two inputs with no form; a button whose handler does `fetch("/api/login", {method:"POST", headers:{"content-type":"application/json"}, body: JSON.stringify({user, pass})})` then `location = "/home"`.
  - `/two-step`: a username form posting to `/two-step/password`, which serves a password form posting to `/form-login`.
  - `/hashed`: like `/script`, but sends `{user, digest}` where `digest` is the hex SHA-256 of the password (`crypto.subtle`; loopback `http` is a secure context).
  - `/home`: "signed in".

  `Person::connect(port)` opens a second CDP connection with `kharon_teach::cdp::Cdp` and offers `goto(url)`, `type_into(css, text)` (focus by `Runtime.evaluate` of `document.querySelector(css).focus()`, then `Input.insertText`), `press_enter()`, `click(css)` (element centre via `Runtime.evaluate`, then `Input.dispatchMouseEvent` pressed and released), `wait_for_path(path)`, `close_all_pages()`.

- [ ] **Step 2: Write the failing tests**

```rust
// req_tch_005_shapes.rs — one test per fixture; each runs record() headless, drives the Person, sends End::Confirmed
#[tokio::test] async fn form_page_classifies_as_form_post()        // Shape::FormPost, RungCeiling::Milliseconds, swap candidate true
#[tokio::test] async fn script_page_classifies_as_script_post()    // Shape::ScriptPost
#[tokio::test] async fn two_step_page_classifies_as_two_step()     // Shape::TwoStep { password_leg: PasswordLeg::FormPost }, AgentContinues
#[tokio::test] async fn hashed_page_classifies_as_transformed()    // Shape::Transformed { digest: Some("sha256") }, swap candidate false
#[tokio::test] async fn the_first_selector_of_each_typed_element_matches() // re-open the fixture, querySelector(selectors[0]) is the same field

// req_tch_002_no_typed_value.rs
#[tokio::test] async fn no_typed_value_in_the_recording_for_any_fixture() {
    // username "kh.throwaway7", password "Tr0ub4dor-9x": recording.to_json() contains neither, in none of the
    // encodings marker::search knows (reuse the needle helper from Task 5).
}

// req_tch_006_profile_and_visible.rs
#[tokio::test] async fn nothing_is_saved_in_the_profile_during_a_login() {
    // before End: copy <profile>/Default/"Login Data" and "Web Data"; logins and autofill tables have 0 rows
    // (skip a file that does not exist; assert at least the profile dir exists).
}
#[tokio::test] async fn profile_is_gone_after_confirm()     {}
#[tokio::test] async fn profile_is_gone_after_discard()     {}   // End::Discard -> Outcome::Discarded
#[tokio::test] async fn closing_the_window_ends_unconfirmed() {  // Person::close_all_pages() mid-login
    // Outcome::Recorded with ended_by == WindowClosed and success_confirmed == false; profile gone; returns within 10 s
}
#[tokio::test] async fn closing_before_start_is_never_started() {}
#[tokio::test] async fn dropping_the_future_removes_the_profile() { // the Ctrl-C path: abort the task after Ready
}
#[tokio::test] async fn a_stale_profile_is_swept_at_the_next_start() {}
```

For the two SQLite reads use the `rusqlite` crate as a dev-dependency only if it is already in the workspace's lock file; otherwise shell out to `python3 -c` as the canary runbook does, and skip with a printed reason when `python3` is absent.

- [ ] **Step 3: Run** `KHARON_REQUIRE_CHROMIUM=1 cargo test -p kharon-teach --test req_tch_005_shapes --test req_tch_002_no_typed_value --test req_tch_006_profile_and_visible`. Expected: FAIL.
- [ ] **Step 4: Implement** `listener.js`, `notice.rs` (the page part) and `session.rs`.
- [ ] **Step 5: Run** the same command, then the whole crate's tests, clippy, fmt. Expected: pass, three times in a row for the real-browser tests (they must not be flaky).
- [ ] **Step 6: Commit** `feat(teach): record a login from a live browser session (#361)`

---

### Task 9: the command line

**Files:**
- Create: `crates/kharon-teach/src/cli.rs`
- Modify: `src/main.rs`, `src/lib.rs`, `src/notice.rs` (terminal prompts)
- Create: `tests/req_tch_003_file_contents.rs`, `tests/req_tch_004_no_network.rs`; add to `tests/req_tch_006_profile_and_visible.rs`

**Interfaces:**
- Consumes: `record`, `RecordOptions`, `Outcome`, `End` (Task 8); `find_browser` (Task 6); `Recording` (Task 1).
- Produces:

```rust
// cli.rs
#[derive(clap::Parser)] #[command(name = "kharon-teach", version)]
pub struct Cli { #[command(subcommand)] pub command: Option<Command>, pub login_url: Option<String>,
    #[arg(long)] pub out: Option<std::path::PathBuf>, #[arg(long)] pub browser: Option<std::path::PathBuf>,
    #[arg(long)] pub yes: bool }
#[derive(clap::Subcommand)] pub enum Command { Show { file: std::path::PathBuf } }
#[derive(Debug, thiserror::Error)] pub enum Refusal { /* one variant per refusal below, each with a one-line message */ }
pub fn validate_login_url(s: &str) -> Result<url::Url, Refusal>;
pub fn default_file_name(host: &str, utc: std::time::SystemTime) -> String; // "<host>-<YYYYMMDDTHHMMSSZ>.kharon-recording.json"
pub fn check_out_path(p: &std::path::Path) -> Result<(), Refusal>;          // must not exist; parent must be a writable directory
pub fn summary(r: &Recording) -> String;
// lib.rs
pub async fn run(cli: Cli, stdin: impl tokio::io::AsyncBufRead + Unpin, stdout: impl std::io::Write) -> std::process::ExitCode;
```

Exit codes: `0` a file was written, or the recording was discarded; `2` a refusal; `1` anything else. Refusals, all before the notice and before any directory is created: the URL is not `https` (plain `http` is accepted only when the host is `localhost` or a loopback address); the URL has userinfo; no browser is found or `--browser` is missing; the `--out` file exists; its directory is missing or not writable. When `Ready.stale_profiles_removed` is not zero, print "Removed N leftover browser profile(s) from an earlier run." Order of `run`: validate, find the browser, check the output path, print `NOTICE`, wait for a line that is exactly `yes` unless `--yes` (any other line: print "Nothing was recorded." and exit 0), make the process non-dumpable on Linux the way `kharon` does in `crates/kharon-cli/src/main.rs`, `record(.. headless: false ..)`, print "Press Enter once you are logged in. Type q to discard.", map the next stdin line (`q` to `End::Discard`, anything else to `End::Confirmed`), and on SIGINT or SIGTERM drop the recording future and exit 1 without writing. The file is created with `create_new` and mode `0600`, written, then the summary and the path are printed. `summary` gives, in plain words: the site, how it ended, the shape, the rung ceiling, whether it is a network-swap candidate, each set flag, each note, and the `stripped` counts. `show` prints `summary` for a file and exits 2 on a `FormatError`.

- [ ] **Step 1: Write the failing tests**

```rust
// cli.rs unit
#[test] fn accepts_https_and_loopback_http() { /* https://ex.test/login, http://localhost:8080/, http://127.0.0.1:1/ ok */ }
#[test] fn refuses_plain_http_userinfo_and_other_schemes() { /* http://ex.test, https://u:p@ex.test, file:///x, "ex.test" */ }
#[test] fn file_name_shape() { assert_eq!(default_file_name("ex.test", UNIX_EPOCH + Duration::from_secs(1_794_974_640)), "ex.test-20261118T040400Z.kharon-recording.json"); }
#[test] fn refuses_an_existing_out_file() {}
#[test] fn refuses_a_missing_or_read_only_directory() {}
#[test] fn summary_names_shape_ceiling_flags_and_counts() {}
#[test] fn cli_has_no_headless_or_attach_option() {
    use clap::CommandFactory;
    let names: Vec<_> = Cli::command().get_arguments().map(|a| a.get_id().to_string()).collect();
    for banned in ["headless", "attach", "port", "profile", "user-data-dir", "endpoint"] { assert!(!names.iter().any(|n| n.contains(banned))); }
}

// run(), driven with in-memory stdin/stdout and no browser needed
#[tokio::test] async fn refusals_exit_2_before_the_notice() { /* bad URL, missing --browser path, existing --out: stdout holds no NOTICE text; no kharon-teach-* dir was created */ }
#[tokio::test] async fn anything_but_yes_records_nothing() { /* stdin "no\n" -> exit 0, "Nothing was recorded." */ }
#[tokio::test] async fn show_prints_the_summary_and_refuses_a_bad_file() {}

// tests/req_tch_003_file_contents.rs (real browser; calls record() headless then the same writer run() uses)
#[tokio::test] async fn the_file_is_0600_and_holds_only_what_the_spec_keeps() {
    // mode 0o600; parse it back; every StoredRequest has query keys but the JSON text holds none of the fixture's
    // query values; no "cookie" value, no response body text ("signed in"), no page title; headers reduced to content type.
    // The fixture for this test adds ?next=/secret-next-value to the login URL and a Set-Cookie: sid=COOKIEVALUE123 on /form-login.
}

// tests/req_tch_004_no_network.rs
#[test] fn the_crate_listens_on_nothing_and_has_no_tls() {
    // source scan of crates/kharon-teach/src (not tests): no "TcpListener", "UdpSocket", "bind(" or "accept(";
    // `cargo metadata` for kharon-teach's normal dependencies holds none of: rustls, native-tls, openssl, reqwest, hyper, kharon-connector, kharond.
}
#[test] fn the_only_dial_is_loopback() { /* the one connect call in cdp.rs builds its URL from the literal "ws://127.0.0.1:" */ }

// add to req_tch_006_profile_and_visible.rs
#[test] fn the_shipped_main_never_asks_for_headless() {
    // source scan: "headless: true" appears nowhere under crates/kharon-teach/src, and src reads no environment variable
    // (no "env::var" / "env::var_os") outside browser discovery of PATH.
}
```

- [ ] **Step 2: Run** `cargo test -p kharon-teach`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement.** Add `clap` (derive) and, Linux only, `rustix` with the `process` feature. For the file name's UTC timestamp use the `time` crate, already a dependency since Task 8's `utc_rfc3339`; do not add a second date crate.
- [ ] **Step 4: Run** `KHARON_REQUIRE_CHROMIUM=1 cargo test -p kharon-teach`, clippy, fmt, `cargo deny check`. The manual run (`cargo run -p kharon-teach -- https://login.page.twkr.io/login.html`, log in with made-up values, press Enter, read the file) needs a person at a display. The implementer does not do it; the controller arranges it with Lothrop after this task and puts the printed summary in the PR body.
- [ ] **Step 5: Commit** `feat(teach): kharon-teach command line, consent and the recording file (#361)`

---

### Task 10: SPEC rows and the user page

**Files:**
- Modify: `SPEC.md` (requirements table: a new `REQ-TCH-*` group), the docs index that links `docs/agent-runtime-setup.md` (find it with `git grep -l "agent-runtime-setup.md" -- '*.md'`)
- Create: `docs/teach-mode.md`

**Interfaces:**
- Consumes: the finished program and its tests.
- Produces: six SPEC rows whose acceptance column names the test file that proves each, as the existing rows do.

- [ ] **Step 1: Add the rows.** Requirement text from the spec's "Proposed SPEC rows" table, REQ-TCH-001 to REQ-TCH-006. Acceptance column, one per row: `req_tch_001_own_browser`, `req_tch_002_no_typed_value`, `req_tch_003_file_contents`, `req_tch_004_no_network`, `req_tch_005_shapes`, `req_tch_006_profile_and_visible`, each with one sentence on what it checks. Follow the wording and column style of the neighbouring `REQ-ARCH-*` rows.
- [ ] **Step 2: Write `docs/teach-mode.md`** for the person who will run it: what it is for, the throwaway-account rule, the command and its options, what the window and the terminal will show, what the file holds and does not hold (the spec's stripping table), what each shape and rung ceiling means in one line, how to send a file to someone, and the known limits from the spec. State that it is Linux only for now and that turning a recording into a login method is not built yet.
- [ ] **Step 3: Check** that every test file named in SPEC exists and that `cargo test --workspace` passes with `KHARON_REQUIRE_CHROMIUM=1`.
- [ ] **Step 4: Commit** `docs(spec): REQ-TCH rows and the teach-mode user page (#361)`

The SPEC rows need Nyx's and Muse's review. Say so in the PR body and add both review labels.
