# Teach mode, piece 2: login methods, a player, and a per-site registry

Status: design, 2026-11-24, for #381 (piece 2 of #361, milestone M2). Built in #382.
Author: Duet (kharon session). Reviewers: Muse and Nyx. Every decision
here is Duet's call unless it is marked otherwise. The outline was
posted on #381 before this note was written; where the code showed a
point of that outline to be wrong or incomplete, the note says so
under [Changes from the #381 outline](#changes-from-the-381-outline).
No code and no SPEC change land with this note. New REQ-TCH rows ship
with the implementation (#382).

## Why

Piece 1 (the recorder, [design](2026-11-18-teach-recorder-design.md),
#364) writes a file that says how a site's login works: its shape, the
strongest rung it could take, and the elements a person used. Nothing
reads that file yet. A fill is still one page and one call, the agent
supplies any selector, and `submit` is whatever the agent asked for.
So the canaries' exposure (the password sits in the page until the
agent moves on, [post-fill exposure](../../post-fill-exposure.md) rows
D1 and D2) is unchanged for every site, including the ones kharon has
been shown.

This piece turns a recording into something a fill can use:

1. a **login method**: the value-free steps of one site's login, in a
   typed format a person can read and check
2. a **player**: the broker running a fill by the method instead of by
   the agent's selectors, at the rung the method allows
3. a **registry**: the broker's per-site record of which method it
   holds, which rung it uses, and when it last worked

## Goals

- A recording the classifier recognizes becomes a login method with
  one command, and the method holds no value and nothing the steps do
  not need.
- A fill on a site with a method runs the method's steps at the
  method's rung. At `milliseconds` that is atomic fill and submit plus
  the post-submit scrub, whatever the agent asked for.
- When the site has changed since the recording, the player stops
  before it writes anything, says which step no longer matches, and
  does not guess.
- Only the owner adds, changes or removes a method.
- Every flow shape is testable without a real account on a real site.

## Non-goals

- Rung 1, the never-in-the-page rung. Piece 3 (#384).
- A shared or shipped list of methods. Methods stay on the broker that
  imported them. Sending one to another broker is the owner copying a
  file.
- Logins that the classifier calls `unrecognized`, or `transformed`
  with no named digest, turned into methods by a program. A person
  writes those by hand in the same format (see
  [Hand-written methods](#hand-written-methods)).
- MFA. A method ends at the password leg. A TOTP step stays a separate
  `kharon_fill_totp` call by the agent, as today.
- An owner UI for the registry. The owner CLI is the only way in for
  this piece.
- macOS and Windows builds, as in piece 1.

## Anti-goals

These would make the piece a failure even if it works.

- **An event-listening CDP client in the broker.** The player must run
  inside the existing fill path: one in-page call in the isolated
  world, and the loader reads the engine already makes. No `Runtime`,
  `Log`, `Network` or `Page` subscription (REQ-ARCH-003).
- **A value in a method or the registry.** Not a password, not a user
  name, not the length of either.
- **An agent changing what a fill does on a site with a method.** An
  agent cannot add, change, override or skip a method, and its
  `selector` arguments are not used on such a site.
- **The player guessing.** A step that does not match exactly is a
  stop, not a fallback to the broker's heuristics or the agent's
  selector.
- **A method widening origin binding.** The item's URIs still decide
  which origins a fill may touch (REQ-ORG-001/002). A method can only
  narrow what a fill does there.

## Constraints

- The fill engine (`crates/kharond/src/cdp/fill.rs`) does one
  synchronous `Runtime.callFunctionOn` of `FILL_IN_PAGE`
  (`crates/kharond/src/cdp/page_js.rs`) in an isolated world. That
  call is where the check-and-set is atomic (REQ-ORG-003). Fields are
  resolved there with `document.querySelector`, which takes the first
  match, checks neither visibility nor uniqueness, and cannot reach
  into a shadow root.
- Submit today is `form.requestSubmit()` on the last filled field's
  form, or synthesized Enter key events when there is no form
  (REQ-API-008). There is no click submit.
- The post-submit scrub (#355, REQ-API-013, shipped in v0.4.0) is
  **opt-in and off by default**. A fill turns it on with
  `post_submit_scrub: true`. It waits `post_submit_scrub_delay`
  (500 ms), re-reads the loader once, and clears only what the fill
  wrote. One check, not a watch.
- `kharon-recording` is a library with no browser I/O (its only
  dependencies are `serde`, `serde_json` and `thiserror`). The broker
  can depend on it without gaining a CDP client. `kharon-teach`
  depends on nothing in `kharond`.
- The broker already reduces an origin to its registrable domain with
  a vendored Public Suffix List (`crates/kharond/src/origin.rs`), and
  keeps owner state as `0600` JSON files under `data_dir` (for example
  `owner/passkeys.json`, `crates/kharond/src/owner_ui/store.rs`).
- Owner-only operations go through the owner socket, which checks the
  peer uid (`crates/kharond/src/owner.rs`), and are driven by the
  `kharon` CLI. Agents never reach that socket.
- Fill replies carry a fixed status and a fixed `&'static str` detail
  code, never a value (REQ-GOAL-001, REQ-API-006). New outcomes reuse
  the existing statuses with new detail codes, as #118 did.
- Data kharon owns is typed `serde` structs and enums, never
  `serde_json::Value`.

## Approaches

**1. The player runs inside the fill path in kharond. Picked.** A fill
on a site with a method is still a `kharon_fill` call. After the
engine reads the live origin, the broker looks up the registry, and
when it holds a usable method the in-page call is given the method's
steps instead of the agent's selectors. No new CDP client, no new
process, no new tool for the agent to learn. The cost is that the
in-page fill function grows a pre-check and a click submit.

**2. The player runs in the connector.** The connector sits next to
the browser, so it could replay a method without the broker's CDP
round trips. Rejected: the connector is a relay with no page logic,
and the security docs rely on that (as in piece 1, approach 3).

**3. A separate player program, like the recorder.** Rejected: it
would need the secret, so it would be a second program holding broker
credentials, which is the thing piece 1 was built to avoid.

**4. The registry as a shared list in the repository.** Rejected for
this piece (out of scope in the #381 outline): who may publish a
method for everyone is a trust question of its own. A per-broker
registry has one owner who imports what they have looked at.

## The design

### 1. The login method

A typed `LoginMethod` in a new module of `kharon-recording`
(`method.rs`), with its own `format_version: 1`, written as
pretty-printed JSON named `<registrable domain>.kharon-method.json`,
mode `0600`. Unknown versions are refused, not guessed at, as for
recordings.

It holds:

| Field | What it is |
|---|---|
| `format_version` | `1` |
| `site` | The registrable domain (the registry key), and the login page's origin and path. No query, no fragment |
| `shape` | The recording's `Shape`: `form_post`, `script_post`, `two_step { password_leg }`, or `transformed { digest }` with a named digest |
| `rung` | `milliseconds` or `agent_continues`. Never stronger than the recording's `rung_ceiling` |
| `legs` | One leg for a one-page login, two for `two_step`. Each leg is an ordered list of steps |
| `success` | How the player tells, once, that the login went through (below) |
| `provenance` | Where the method came from (below) |

**Steps.** A leg is a list of these, in order:

- `navigate`: the path the leg starts on, on the site's origin. The
  player does not navigate; the agent does, as today. The step is
  what the pre-check compares the live page's path against.
- `fill`: a role (`username` or `password`), an ordered list of
  candidate selectors (most stable first, from the recording's
  `ElementDescriptor.selectors`), and the expected element: tag,
  `type`, and whichever of `id`, `name` and `autocomplete` the
  recording saw.
- `submit`: one of `form` (`requestSubmit()` on the form of the last
  filled element), `click` (a click on one element, given as a
  selector list and an expected element like a fill step's), or
  `enter` (Enter on the last filled element). Taken from the
  recording's `Submit`, `Click` or `EnterKey` step that came after the
  last fill of the leg. A leg with no submit is not convertible.

**Success check.** The broker cannot watch the network
(REQ-ARCH-003), so success is read from the page, once, at the point
where the post-submit scrub already re-reads the loader. One of:

- `path_changed_to`: the main frame's path is this path (from the
  recording's `final_url`, query dropped)
- `password_field_gone`: the password step's element is no longer
  connected (script logins that remove the form, such as
  `/login/spa.html` on the test pages)
- `none`: the page gives no sign a page-side check can read (a script
  login that keeps the form)

The result goes to the registry entry only. The fill reply stays
`filled`, as the scrub's does.

**Provenance.** One of two kinds, tagged `source`:
- `recording`: the SHA-256 of the recording file's bytes, the recording's `tool_version`, its browser product string, its `listener_world` (`isolated` or `main`), and its `rung_ceiling`. The last two are copied because import gets only the method file, and section 5's main-world and ceiling checks read them there.
- `hand_written`: an author string. No digest, no world, no ceiling (section 6).

The user agent and viewport are not copied. The digest covers them, so a reader who holds the recording can check them. `listener_world` and `rung_ceiling` can't be left to the digest, because import has no recording to check a digest against.

**Roles, never values.** The method holds no value, no value length,
and no page text.

### 2. From recording to method

A pure function in `kharon-recording`,
`LoginMethod::from_recording(&Recording, recording_bytes) ->
Result<LoginMethod, NotConvertible>`, and a subcommand that calls it:

```text
kharon-teach method <recording> [--out <file>]
```

`kharon-teach show <method>` prints a method the same way it prints a
recording, so the owner can read it before importing it.

**Convertible** recordings are those whose classification is
`form_post`, `script_post`, `two_step`, or `transformed` with a named
digest, and that pass every refusal below. For `transformed` the
player fills the password as typed and the page computes its digest
itself, exactly as when a person logs in; the digest name is kept for
piece 3.

**Refused**, with the reason printed:

- `unrecognized`, or `transformed` with no digest (`needs_person`).
  These stay recordings, and a person writes the method by hand.
- A credential step in a shadow root (`in_shadow_root`). The
  classifier does not block `shadow_dom`, but the fill function's
  `querySelector` cannot reach inside one. Hand-written for now.
- A leg with no submit step after its last fill.
- A recording with `success_confirmed: false`, unless the person
  passes `--unconfirmed`. A login nobody saw work is a poor template.

**Dropped** on the way, beyond what the recorder already strips
(REQ-TCH-002/003):

| In the recording | In the method |
|---|---|
| `value_len` on every input step (the length of each typed value, so the password's length) | Dropped |
| `placeholder`, `aria-label` | Dropped. Page text, often translated, and not needed to find the element |
| Query keys on every URL, including `start_url`, `final_url` and form actions | Dropped. A query can carry state the steps do not use (the test pages' `?expect=` digest is one) |
| Paths other than the login path, each leg's start path and the success path | Dropped |
| `requests` (every stored request shape) | Dropped. The player sends nothing itself, and piece 3 reads the recording, not the method |
| `steps` timings, the person's other clicks and inputs, `stripped` counts, `flags` | Dropped |
| User agent and viewport | Not copied; covered by the provenance digest |
| `listener_world`, `rung_ceiling` | Copied into the provenance, not dropped. Import checks both (section 5) and has only the method file |

### 3. The player

The player is the fill path with a method in hand. The order inside
`Broker::fill` and the engine stays as it is, with two additions.

**Lookup.** After the engine reads the target's live origin from the
browser (step 1 of the engine, REQ-ORG-002) and before any value is
sent, the broker reduces that origin to its registrable domain and
looks up the registry. The agent's `expected_origin` plays no part in
the lookup. No entry: the fill runs exactly as today. An entry: the
fill becomes a method fill.

**What a method fill changes:**

- The fields come from the method's current leg, not from the agent.
  An agent `selector` is ignored on a site with a method (the reply's
  detail says so on the first such fill: `method_selectors`). The
  agent still names the item and the field kinds it wants.
- At `milliseconds` the fill always submits, with the method's submit,
  and always runs the post-submit scrub (`post_submit_scrub: true` for
  this fill, whatever the deploy and the agent said). An agent's
  `submit: false` does not hold the password in the page on a site the
  owner has taught. This is the point of the piece, and it is the
  first open question below.
- A `two_step` method runs leg by leg, at `agent_continues`. Each leg
  is one `kharon_fill` call by the agent. The broker picks the leg
  whose `navigate` path matches the live path. No leg matching is the
  wrong page, not drift. A leg whose path matches but whose fields fail
  rule 2 is drift on that leg. Leg 1 fills the user name and submits.
  Leg 2 fills the password and submits atomically, with the scrub,
  like a one-page method. The rung stays `agent_continues`, because the
  agent drives the page between the legs (the classifier's rule).

**The pre-check.** Inside the same in-page call, before the first
value is written, the fill function checks every step of the leg:

1. The live path matches the leg's `navigate` path.
2. For each fill step, and for a `click` submit: the candidate
   selectors are tried in order, and the first that resolves to
   exactly one element is used. That element must be connected,
   visible (it has client rects and is not `visibility: hidden`), of
   the expected tag and `type`, and must match every one of `id`,
   `name` and `autocomplete` that the method records. A password step
   must be `type="password"` now.
3. The element must be enabled, alone and through its `fieldset`.

Because the check and the writes are one JavaScript task, the page
cannot change between them (the same argument as REQ-ORG-003).

**On a miss**, the fill function throws before it writes anything:

- Rule 1 fails (the live path matches no leg: the home page, a consent
  page, a fill before the login redirect finishes): `field_not_found`,
  detail `method_wrong_page`. No stale mark, no owner notice and no
  registry write; only the fill's audit entry. The agent may navigate
  and retry. A wrong page says nothing about whether the site changed,
  and any agent can cause one, so it must not lock the site.
- Rule 1 passes and rule 2 fails (element gone, two matches, a changed
  type or name): `field_not_found`, detail `method_drift`. The broker
  marks the entry stale with the step's index and the time, writes the
  step index into the fill's audit entry, and sends the owner one
  notice through the existing notify channel. It does not retry with
  other selectors, the broker's heuristics or the agent's selector.
- Only rule 3 fails (the field is there but disabled): `field_not_found`,
  detail `method_not_ready`. Not drift, nothing marked. The agent may
  try again. The test pages hit this case: their fields sit in a
  disabled `fieldset` until the page's service worker is ready.

**A stale entry** refuses method fills on its site (`field_not_found`,
detail `method_stale`) until the owner re-imports a method or runs
`kharon teach clear-stale`. Setting an override does not clear it by
itself. It does not quietly fall back to today's fill. This is the
second open question below.

**After the submit**, at the scrub's single re-read, the broker
evaluates the success check and records the result, the time and the
browser's product string (`Browser.getVersion`, which the CDP client
already calls) on the entry. If the main frame is still navigating at
the re-read, the result is `unconfirmed`, not `failed`.

**Changes to the in-page fill function**, all inside `FILL_IN_PAGE`
and its tests:

- a `steps` form of its field list: selector lists plus expected
  attributes, checked as above before any write
- the `click` submit
- `method_wrong_page`, `method_drift` and `method_not_ready` failures,
  thrown before the first write so that the existing clear-on-failure
  has nothing to do

The `requestSubmit` and Enter paths are unchanged. REQ-API-008's
wording gains the click submit in #382.

### 4. The registry

**Where.** One per broker, `<data_dir>/teach/registry.json`, mode
`0600`, in a directory created `0700`, written by write-to-temp and
rename, following `owner/passkeys.json`. It is read at start and kept
in memory; it holds no secret, so it is not sealed.

**Keyed by registrable domain**, as the broker's PSL computes it. One
entry per domain. A site with two different logins on one registrable
domain is out of scope for this piece and is refused at import if the
domain already has an entry, unless the owner replaces it.

**An entry holds:**

| Field | |
|---|---|
| `method` | The imported `LoginMethod`, as imported |
| `rung` | The rung the player uses: the method's `rung` |
| `shape` | Copied from the method, for listing |
| `overrides` | Owner-set selectors per step index, tried before the method's own list. An override changes only where the element is looked for; the element it finds still has to pass rule 2 |
| `imported_at` | Time |
| `last_checked` | Time and browser product string of the last method fill that reached the browser |
| `last_result` | `succeeded`, `unconfirmed` (success check `none`, or the main frame still navigating at the re-read), `failed` (success check not met), `drift` (with the step index), `not_ready` |
| `stale` | Set by drift, cleared by re-import or `clear-stale` |

**Who writes.** Only the owner, through the owner socket and the
`kharon` CLI:

```text
kharon teach import <method-file> [--replace] [--accept-main-world]
kharon teach list
kharon teach show <domain>
kharon teach override <domain> <step> <selector>
kharon teach clear-stale <domain>
kharon teach remove <domain>
```

`kharon teach import` prints the domain, the rung and whether the
method is `hand_written` before it commits.

Each is one owner-socket op and one audit entry (`teach_import`,
`teach_override`, `teach_clear_stale`, `teach_remove`, carrying the
domain and the method's provenance digest, never a selector the agent
could have chosen). The broker itself writes only `last_checked`,
`last_result` and `stale`, and only from a method fill. A
`method_wrong_page` fill writes none of them.

**What agents see.** The rung, read-only. A method fill's reply and
its audit entries name the rung used, and the approval prompt for a
grant on that item says it, as #361 asked. Agents have no tool that
lists, reads or writes entries. The exact surface (a `rung` field on
the reply, on item metadata, or both) is the builder's, with its SPEC
rows.

### 5. Trust and stripping

The recorder already keeps no typed value, cookie, header value,
response body, query value or request-body value (REQ-TCH-002,
REQ-TCH-003). The conversion in section 2 drops the rest of what a
method does not need. On top of that, **import refuses**:

- a method whose `site` is not the registrable domain of its login
  origin, or any of whose leg paths or success path sits on another
  origin. The cross-site flag already makes a recording
  `unrecognized`; this check is for hand-written and edited files
- a method converted from a recording with `listener_world: main`,
  unless the owner passes `--accept-main-world`. In the main world a
  page's own scripts can see and fake the listener's reports. The
  method carries the recording's world in its provenance so that
  import can check it
- a `rung` stronger than the provenance's recorded ceiling, for a
  converted method
- a second method for a domain that already has one, unless
  `--replace`

The shadow-root refusal is at conversion only (section 2). Import
cannot tell a shadow-root selector from any other. A hand-written
shadow-root selector never resolves, so its first fill ends in
`method_drift`.

**Who is trusted to add a method:** the broker's owner, and nobody
else. A method decides where kharon types a password on that site, so
adding one is the same class of act as approving a grant. Import is
therefore owner-socket only, and nothing an agent sends can reach it.

### 6. Hand-written methods

A person writing a method for a login the classifier would not
convert writes the same JSON. They supply:

- `site`: the registrable domain, and the login origin and path
- `shape`: one of the convertible shapes, or `transformed` with
  `digest: null` when the page encrypts with a key the site supplies
  (the common bank case piece 1 expected)
- `rung`: `agent_continues` unless they have checked the site submits
  in one step from the fields they list
- `legs`: per step, the role, at least one selector, and the expected
  tag and `type`; `id`, `name` and `autocomplete` where they want the
  pre-check to hold them
- the submit kind and, for `click`, its element
- `success`
- `provenance` with `source: "hand_written"`, an author string, and no
  recording digest

Import treats it as any other method, with every refusal in section 5 except the two that read a recording's provenance. The ceiling check has no ceiling to compare with. The main-world check has no listener world, because no listener ran. A hand-written method's rung is the author's claim, which is why it defaults to `agent_continues`. `kharon
teach list` marks it hand-written.

### Tests

**Without a browser:**

- Conversion: one hand-built recording per convertible shape becomes
  the expected method; every refusal in section 2 has a case; the
  method file holds none of the dropped fields (a test serializes the
  method and searches it for `value_len`, `placeholder`, query keys
  and request shapes).
- Import: every refusal in section 5 has a case, on the owner socket,
  with no agent route reaching it.
- The in-page function, through the existing node harness in
  `page_js.rs`: the pre-check passes on a matching page; each drift
  case (element gone, two matches, a renamed field, a changed type)
  throws `method_drift` before any write; a wrong path throws
  `method_wrong_page` before any write, with no stale mark and no
  notice; a disabled field throws `method_not_ready`; the click submit
  fires once, and only after every field filled.

**With a real Chromium in CI** (`KHARON_REQUIRE_CHROMIUM`): the
kharon-teach fixture server's four logins, plus a drift variant of the
form page, served on loopback. For each: record, convert, import into
a test broker, fill by the method, and read the registry entry. The
drift variant must end `field_not_found` / `method_drift` with the
entry stale and nothing typed into the page. A fill on `/` must end
`field_not_found` / `method_wrong_page` with the entry not stale. A
two-step method whose leg 2 password field is renamed must end
`method_drift` on leg 2.

**The live test (#383)** runs on the public_oauth_test pages
(`cycle-five/public_oauth_test`, served at `login.page.twkr.io`),
which answer a real form POST from a service worker, so nothing typed
reaches the network. The table is #383's pre-check: before any
recording, each page must exist, record to the shape named, and
replay to the result named.

| Page | Exists today | Recorded shape | Rung | Player result | Success check |
|---|---|---|---|---|---|
| `/login/any.html` | Yes | `form_post` (form POST to `/login/session/any`, answered by the service worker) | `milliseconds` | `filled`, then the page navigates | `path_changed_to /login/welcome.html` |
| `/login/spa.html` | Yes | `script_post` (`fetch()` of a JSON body to `/login/api/session`) | `milliseconds` | `filled`; the form is removed | `password_field_gone` |
| `/login/spa-keep.html` | Yes | `script_post` | `milliseconds` | `filled`; the form stays, so the scrub's clear runs | `none` |
| A two-step page (user name, then a password page) | **No, to add** | `two_step` with `password_leg: form_post` | `agent_continues` | leg 1 `filled` and submitted, leg 2 `filled` and submitted | `path_changed_to` the landing page |
| A page that sends the SHA-256 of the password in place of the password | **No, to add** | `transformed { digest: "sha256" }` | `milliseconds` | `filled`, then the page navigates | `path_changed_to` the landing page |
| A drift variant of `/login/any.html` (the password field renamed) | **No, to add** | replayed with `/login/any.html`'s method | — | `field_not_found` / `method_drift` on the password step, nothing typed, entry stale | — |

Notes for the pre-check:

- `?expect=<digest>` on the existing pages is a receipt the page checks
  after the submit. The POST still carries the password as typed, so
  it does not make a `transformed` login, and the conversion drops the
  query key.
- The fields are disabled until the service worker controls the page
  (`#login-form[data-ready="true"]`). A fill before that is
  `method_not_ready`, not drift.
- That the recorder sees the service-worker-answered POST, body
  included, is the first thing to check on `/login/any.html`, since
  the `form_post` classification depends on it.
- `/login.html` (strict, only the public pair works) is not in the run.

The three missing pages are changes to `cycle-five/public_oauth_test`,
filed against #383. The kharon-teach fixture server already has a
two-step and a SHA-256 login, so the CI test above does not wait on
them.

### Proposed SPEC rows

For the implementation PR (#382), wording to be reviewed there:

| ID | Requirement |
|---|---|
| REQ-TCH-007 | A login method holds no typed value, no value length, no query key, no request shape and no page text, and a method whose `format_version` the library does not know is refused |
| REQ-TCH-008 | A fill on a site with a method checks every step of the leg before writing, in the same in-page call. When no leg's path matches the live page it writes nothing, replies `field_not_found` with `method_wrong_page`, and marks nothing. When a leg's path matches and a step does not, it writes nothing, replies `field_not_found` with `method_drift`, and marks the entry stale. It never uses the agent's selector or the broker's heuristics on that site |
| REQ-TCH-009 | A method fill at `milliseconds` submits with the method's submit and runs the post-submit scrub, whatever the request's `submit` and `post_submit_scrub` say |
| REQ-TCH-010 | Only the owner socket adds, changes or removes a registry entry. Import refuses an off-domain method, a main-world recording without the owner's flag, and a rung above the recording's ceiling. Conversion refuses a shadow-root step |
| REQ-TCH-011 | The registry records per site the rung, the shape, overrides, and the time, browser version and result of the last method fill |

REQ-API-008 gains the click submit.

## Open questions for review

1. **`submit: false` on a taught site.** This note has a method fill
   at `milliseconds` submit regardless of the agent. The alternative
   keeps the agent's `submit` and only uses the method's selectors,
   which leaves the canaries' exposure in place whenever an agent asks
   for `submit: false`. Duet's view: the owner taught the site so that
   the password does not sit in the page; the agent should not be able
   to undo that.
2. **A stale entry refuses fills on its site.** The alternative falls
   back to today's fill until the owner looks. Refusing is safer and
   louder; falling back keeps agents working. Duet's view: refuse,
   with the owner notice, because drift is exactly when the player's
   selectors would type into the wrong place. Only real drift gets
   there: a wrong page is `method_wrong_page` and marks nothing.
3. **Whether a `two_step` password leg should earn `milliseconds`.**
   Its password is filled and submitted atomically, so in the page it
   sits for milliseconds too. The ceiling stays `agent_continues` here
   because the classifier set it, and because the agent controls the
   page between the legs. Piece 3 or a later change can revisit it.

## Changes from the #381 outline

Reading the code changed these points of the plan posted on #381:

- **Click submit is new code.** The outline listed form, click or
  Enter as if all three existed. The fill path has `requestSubmit()`
  and Enter only (REQ-API-008); `click` is added to the in-page
  function and to REQ-API-008 in #382.
- **The scrub is opt-in and off by default.** The outline said the
  player runs the scrub; it now says the method fill turns it on for
  itself, because the deploy default is off.
- **The pre-check also requires the element to be enabled**, and a
  disabled field is `method_not_ready`, not drift. The test pages
  start with their fields disabled.
- **Success is read once, at the scrub's re-read.** The broker cannot
  watch the network, so the success check is a page-side read with
  three kinds, and `none` where the page gives no sign.
- **More is stripped.** Beyond query keys, unused paths, the user
  agent and the viewport, the method drops `value_len` (which gives
  away the password's length), `placeholder`, `aria-label`, every
  request shape, timings and flags.
- **More is refused.** Shadow-root steps at conversion (the fill
  resolver cannot reach them), and at import a rung above the
  recording's ceiling; unconfirmed recordings need the person's flag.
- **The test pages.** Only `form_post` and `script_post` pages exist on
  public_oauth_test today. The two-step page, the SHA-256 page and the
  drift variant have to be added before #383 runs. The `?expect=`
  digest on the existing pages is not a `transformed` login.

## Left to the builder

- The module layout in `kharon-recording` and `kharond`, and the
  owner-socket op names.
- How candidate selectors are re-ordered by overrides.
- The `rung` field's exact place on the agent-facing surface, with its
  SPEC rows.
- The wording of `kharon-teach show` for a method, of `kharon teach
  list`, and of the owner notice on drift.

## Known limits

- The pre-check compares structure, not meaning. A site that keeps
  every name and type but changes what a field is for will pass it.
- A recording made in a visible desktop browser may not match the
  agent's headless layout. Visibility in the pre-check is checked in
  the agent's browser, so a field hidden there is drift, not a guess.
- One method per registrable domain. Sites with separate logins on
  subdomains of one registrable domain need a later change.
- A method made from a throwaway account may differ from the real
  account's login (an extra prompt on the real one). That shows up as
  drift on the first real fill, which is the intended outcome.
- Provenance is what the method file says. Import can't check a converted method's `listener_world` or `rung_ceiling` against the recording, because it doesn't have the recording. The owner reading `kharon-teach show` before import is that check. A `--recording <file>` flag on import that verifies the digest is left to the builder.
