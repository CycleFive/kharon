# Teach mode, piece 1: a recorder for a demonstrated login

Status: design, 2026-11-18, for #361. Author: Duet (kharon session).
Decisions marked **Lothrop** were made by him on 2026-11-18. The rest
are Duet's calls and are marked so. No code and no SPEC change land
with this note.

## Why

The OpenClaw and Hermes canaries (#336, #339) filled with
`submit: false`. The password then sits in the page for as long as the
agent likes, and both stock harnesses can read the page
([post-fill exposure](../../post-fill-exposure.md), rows D1 and D2).
kharon cannot block those reads, because the agent's harness has its
own CDP connection to the same browser. What kharon can control is
whether the secret is in the page at all, and for how long:

1. **Never in the page.** A placeholder is filled and the real secret
   is put into the login request as it leaves the browser.
2. **In the page for milliseconds.** Atomic fill-and-submit, which
   exists (`submit: true`), plus the post-submit scrub (#355).
3. **In the page until the agent moves on.** Today's `submit: false`.

Which rung a site can take depends on how its login works: one page or
two, a form post or a script request, the password sent as typed or
transformed in the page. kharon knows none of that today. A fill is
one page and one call, and the agent supplies any selector.

Teach mode is how kharon learns it. A person who knows the site says
"I'm going to show you how to log in", logs in with **throwaway
credentials**, and kharon keeps a recording of what the login did
(**Lothrop**). Where the structure is one kharon recognizes, it says
so. Otherwise the recording is kept for an engineer or a model to
work through later (**Lothrop**).

## What this piece is

The work is three pieces, in this order (Duet's call, accepted):

1. **This note:** the recorder, the recording file, and the classifier
   that names the login's shape.
2. The login-method format, a player that replays a method with a
   real secret at rung 2, importing a recording into a broker, and the
   per-site registry.
3. The never-in-the-page rung.

The recorder goes first because pieces 2 and 3 need real recordings to
design against. Pieces 2 and 3 get their own notes.

## Goals

- One command a non-engineer can run on their own computer that
  records a login they perform by hand.
- A recording file that says how the login works and holds nothing
  secret, so it can be kept, read, and sent to someone else.
- A classifier that names the shape of the login and the strongest
  rung it could take, or says a person has to look.

## Non-goals

- Turning a recording into a login method, or replaying one. Piece 2.
- Importing a recording into a broker. Piece 2. Until then the file
  stays where the recorder wrote it.
- The site registry and the words on the approval prompt. Piece 2.
- Rung 1. Piece 3.
- Recording a failed login, an MFA enrolment, or a sign-up.
- macOS and Windows builds. The code is written to be portable; only
  Linux is built and tested in this piece.

## Anti-goals

These would make the piece a failure even if it works.

- **The recorder touching a real secret path.** It must share nothing
  with a fill: no broker credential, no connection to a broker, no
  vault access, no way to attach to a browser it did not launch.
- **The recorder writing a typed value to disk.** Not the password,
  not the username, not in the recording, a temp file of its own, or
  a log line. The browser's own profile is a separate matter: while
  the window is open, Chromium keeps the throwaway session there as
  any browser would. That directory is private to the user and is
  deleted on every way out (see The browser's profile).
- **Sending anything anywhere.** The recorder makes no network
  connection of its own except loopback CDP to its own browser.
  Export is the person copying a file (**Lothrop**: recordings stay
  with the owner, and sending one is their explicit choice).
- **Recording without the person knowing.** The notice comes before
  the browser opens, and the recorded window says what it is.

## Constraints

- The broker's CDP client never subscribes to `Runtime`, `Log`,
  `Network` or `Page` events (REQ-ARCH-003,
  `crates/kharond/src/cdp/client.rs`). The recorder needs those
  streams. It therefore gets its own client and does not touch the
  broker's.
- The connector is a relay with no page logic
  (`crates/kharon-agent-connector/src/main.rs`). It stays that way.
- Project pattern: a hand-rolled minimal CDP client over
  `tokio-tungstenite`, not a browser-automation crate.
- Data kharon owns is typed `serde` structs and enums, never
  `serde_json::json!` or `serde_json::Value`. Two things here are
  third-party payloads and may be read as `Value`: CDP event
  parameters the recorder does not inspect, and a site's request
  body while its shape is being extracted.
- CI has a real Chromium for tests (`KHARON_REQUIRE_CHROMIUM`, the
  `chromium_bin` discovery in the `req_arch_003` tests).
- A SPEC change needs Nyx's and Muse's review and ships with its code.

## Approaches

**1. A standalone recorder. Picked (Lothrop).** A new program that
launches its own visible Chromium, records, strips, classifies and
writes a file. No broker is involved. It works for anyone in one
step, including us when we build the shipped list, and it cannot be
pointed at an agent's browser or see a real secret because it has no
broker access at all. The cost is a second program that speaks CDP.

**2. The broker records through a teach connector.** The connector
gains a mode that launches a visible browser, and the broker gains a
recording mode. Recordings land on the broker directly. Rejected: it
puts an event-listening mode inside the one client that promises
never to listen, and a person needs a minted credential, a config
file and a route to the broker before a first recording.

**3. Recorder logic inside the connector binary.** Same experience as
1. Rejected: the connector stops being a relay with no page logic,
which the security docs rely on.

Where the demonstration happens was decided first (**Lothrop**): on
the person's own computer, in a visible Chromium. The agent's browser
is usually headless on a server, and a browser extension would be a
new artifact living in a real profile.

## The design

Everything in this section is Duet's call unless marked.

### Two crates

- `crates/kharon-recording`, a library. The typed recording format,
  the stripping rules as types, and the classifier. It does no I/O
  with a browser, so the broker can depend on it in piece 2 without
  gaining an event-listening CDP client.
- `crates/kharon-teach`, the `kharon-teach` binary. The command line,
  the browser launch, the event-subscribing CDP client, capture, and
  writing the file.

`kharon-teach` has a library target and a thin `main`, so tests can
call the launch and capture code directly. It depends on nothing in
`kharond` and not on `kharon-connector`, which would bring a TLS
stack into a program that dials nothing but loopback. It reads the
`DevToolsActivePort` file of the browser it launched with its own
copy of that small parser. New dependencies are limited to what this
note needs: `md-5` for one of the digests, and `tokio-tungstenite`
without TLS features.

### The command

```text
kharon-teach <login-url> [--out <file>] [--browser <path>] [--yes]
kharon-teach show <file>
```

1. Refuse a URL that is not `https://`. `http://` is allowed only for
   `localhost` and loopback addresses, which the tests use.
2. Print the notice and wait for the person to type `yes`
   (`--yes` skips the wait, not the notice):

   ```text
   kharon-teach records how a login works so kharon can learn it.
   Use a THROWAWAY account. Everything you type in the window that
   opens is read by this program. Nothing you type is saved, and
   nothing is sent anywhere. The result is one file on this computer.
   ```

3. Launch a Chromium-family browser: `--browser`, else the first of
   Chromium, Google Chrome, Microsoft Edge and Brave found on the
   machine. Visible, not headless. A new empty profile in a temporary
   directory created mode `0700`. `--remote-debugging-port=0`, which
   binds loopback only. There is no option to attach to a running
   browser or to name a profile.
4. The first tab shows a notice page, a `data:` URL the recorder
   builds, that repeats the notice and has one link, "Start recording
   and open `<host>`". The link is an ordinary link to the login URL.
   Recording starts when the main frame leaves the notice page. The
   recorder runs no HTTP listener of its own.
5. The terminal says "Press Enter once you are logged in. Type q to
   discard." Enter ends the recording as a confirmed success. `q`
   discards it. Closing the window ends it and saves it marked
   `success_confirmed: false`.
6. Strip, classify, write the file, print a summary and the path,
   close the browser and delete the profile directory.

`show` prints the same summary from a file.

### The browser's profile

The profile directory is the one place outside the recorder's control
where the throwaway login leaves traces: session cookies, history,
cache. The recorder keeps that small and short-lived:

- The browser is launched with the password manager, autofill and
  sync turned off and the disk cache disabled, by whatever flags or
  profile preferences do that on the browser CI uses. The builder
  picks them and a test checks that `Login Data` and the autofill
  table are empty after a login.
- The directory is deleted on every exit the program can see: a
  normal end, `q`, the window closing, SIGINT and SIGTERM.
- An exit it cannot see (a kill, a crash, power loss) leaves the
  directory behind. Every start therefore first deletes any leftover
  `kharon-teach-*` profile directory owned by the user in the temp
  location, and says that it did.

### What is captured

The recorder attaches to its browser and follows new tabs, popups and
out-of-process frames (`Target.setAutoAttach`, flattened sessions).
New targets are held at start (`waitForDebuggerOnStart`) until the
recorder has enabled its streams and installed its script, then
released, so nothing early is missed. Workers and service workers are
not followed. For each page or frame session it takes three streams.

**Navigation.** Main-frame and child-frame navigations
(`Page.frameNavigated`): origin and path.

**What the person did.** A listener script installed in every new
document (`Page.addScriptToEvaluateOnNewDocument`, in its own isolated
world) reports through a binding (`Runtime.addBinding` scoped to that
world; the builder checks this against the browser CI uses and falls
back to the main world if needed). It listens in the capture phase
for `input` and `change` on form controls, `click` on buttons, links
and submit controls, `submit` on forms, and Enter in an input. Each
report carries the time since the start, the kind of event, the frame,
and an element descriptor:

- a number the script gives each element, stable for the life of its
  document
- tag, `type`, `id`, `name`, `autocomplete`, `placeholder`,
  `aria-label`, and whether it has been `type="password"` at any
  point while it was being typed in
- the form it belongs to: its index, `action` (origin and path) and
  `method`
- an ordered list of candidate selectors, most stable first
- whether it is in a cross-origin frame, and whether it is inside a
  shadow root

For `input` and `change` the report also carries the value. That is
the only place a typed value enters the recorder.

**What the browser sent.** `Network.requestWillBeSent` and
`Network.responseReceived`, buffered in memory from the moment
recording starts, so that flags which depend on page-load requests
can be set. For a request: method, origin and path, query keys,
resource type, content type, and the body
(`Network.getRequestPostData` when needed). For a response: status,
content type, and whether it set a cookie. Which of these are stored
is under What is stripped.

A body is read as one of four kinds: urlencoded, JSON (GraphQL
included), multipart (part names, and text parts), or opaque
(anything else: its length only). The marker search below runs over
the raw bytes of every kind, so a marker in an opaque body is still
found and is recorded at whole-body level. When the browser cannot
return a body, the request is recorded as `body: unavailable`.

### Markers: how typed values are used and never kept

A typed value is held in memory as a `Marker`: zeroized on drop, with
no `Serialize`, `Debug` or `Display` implementation, so the compiler
refuses any path that would write one out.

One marker is kept per element: its latest value. Keystrokes on the
way there are overwritten, not kept. An element that was
`type="password"` at any point while being typed in is a password
element, so a show-password toggle does not lose it. Its latest value
is the password marker. Two password elements with the same value (a
confirm field) count as one. Two with different values set the
`multiple_passwords` flag, which is a change-password or sign-up form
and out of scope. Every other element's latest value is a candidate
username marker; the one that shares a form or a step with the
password, or that the site sends alongside it, is the username.

Each captured request is searched for each marker in its URL, its
`Authorization` header and its body, in these encodings: as typed,
percent-encoded, JSON-escaped, base64 and base64url, and hex. For the
password it is also searched for the hex and base64 of its MD5, SHA-1,
SHA-256 and SHA-512. A marker shorter than six characters is searched
but its matches are marked low-confidence.

What is recorded is the **role** and the place: "the `password` key of
this urlencoded body is the password, as typed". The value is not.

### What is stripped

The file holds structure. Before anything is written:

| Captured | Kept in the file |
|---|---|
| Typed values | Role and length only |
| Request body | Its shape: keys, and per value a kind, a length and a role |
| Query string | Keys only |
| URL path | Kept, with a segment replaced by `{id}` when it is all digits, a UUID, 16 or more hex characters, or contains a marker |
| Request and response headers | Content type only. `Authorization` is reduced to its scheme and whether a marker was in it |
| Cookies, `Set-Cookie` | Whether one was set, nothing else |
| Response bodies | Never read |
| Page text, titles, HTML | Never read, apart from the element attributes listed above |

Only three kinds of request are stored: main-frame navigations from
the start of recording, requests in which a marker was found, and
non-GET requests to the login site after the first input event. The
rest are used for the flags and then counted.

The file carries a `stripped` block with those counts, so someone
reading an exported file can see what was removed.

### The recording file

One pretty-printed JSON document, `format_version: 1`, written mode
`0600`, named `<host>-<UTC time>.kharon-recording.json` in the current
directory unless `--out` says otherwise. It holds:

- the tool version, the browser's product string and user agent, the
  viewport size, start and end times, how it ended, and
  `success_confirmed`
- the start URL and the last main-frame URL, stripped as above
- the ordered steps: navigations and the person's events
- the stored requests, as shapes with roles
- the flags and the classification below
- the `stripped` block

The format is fully typed in `kharon-recording`. A file with a
`format_version` the library does not know is refused, not guessed at.

### The classifier

A pure function from a recording to a classification: a shape, a rung
ceiling, a `network_swap_candidate` yes or no, flags, and notes in
plain words. It can be run again on an old file when the classifier
improves. It cannot find a new encoding in an old file, because the
values are gone; that is accepted.

**Flags**, each set from the capture:

- `captcha`: a frame or request to a known CAPTCHA host
- `otp_step`: an input used after the password step that passes the
  same three tests the fill script uses for a TOTP field
  (`resolveField` in `crates/kharond/src/cdp/page_js.rs`):
  `autocomplete` contains `one-time`, `name` contains `otp` in any
  case, or `type` is `tel`. They are restated in Rust over the
  element descriptor, with a comment at each site naming the other
- `cross_site`: the main frame went to a different registrable domain
  during the login (single sign-on)
- `popup`: the login opened another window
- `framed_login`: a credential field in a cross-origin frame
- `shadow_dom`: a credential field inside a shadow root
- `multiple_passwords`: two password elements with different values
- `body_unavailable`: a non-GET request to the login site whose body
  the browser could not return

**Shapes:**

| Shape | Recognized when |
|---|---|
| `form_post` | One page. The password field is in a form, and a main-frame document request carries the password as typed or encoded |
| `script_post` | One page. A script request (XHR or fetch) carries the password as typed or encoded |
| `two_step` | The username was submitted, by a navigation or a request that carries it and not the password, before the password field was used. It carries a `password_leg`, which is `form_post`, `script_post` or `transformed` |
| `transformed` | No request carries the password as typed or encoded, and `body_unavailable` is not set. If a digest matched, the shape carries its name |
| `unrecognized` | None of the above, or any of `cross_site`, `popup`, `framed_login`, `multiple_passwords` is set, or the password was found nowhere and `body_unavailable` is set |

The shape is decided first. The blocking flags in the last row win
over every other row.

**Rung ceiling.** One of three values. Each rule below can only lower
it, and they are applied in this order:

1. Start at `milliseconds` for `form_post` and `script_post`, and for
   `transformed` with a named digest.
2. Lower to `agent_continues` when the shape is `two_step`, when
   `captcha` or `otp_step` is set, or when a one-page login gave no
   way to submit it: the password field is in no form and no Enter
   key or submitting click was seen.
3. Lower to `needs_person` for `unrecognized`, and for `transformed`
   with no named digest.

**`network_swap_candidate`** is separate from the ceiling, because
rung 1 is not designed yet. It is yes when the password appears as
typed or encoded in exactly one stored request, in the shape itself
or in a `two_step`'s password leg. Piece 3 decides what that is
worth.

### Hardening

The recorder holds only throwaway values, and it is still written as
if they were secrets, because people will sometimes ignore the notice:
markers are zeroized, nothing typed is logged at any log level, and on
Linux the process makes itself non-dumpable at start as `kharon` does.
Platform-specific code sits behind `cfg`; the rest uses `std` and
`tokio` only.

### Tests

- **Classifier:** unit tests over hand-built recordings, one or more
  per shape, flag and ceiling. No browser.
- **Nothing typed reaches the file:** drive a full capture with known
  markers, then byte-search the written file, and the recorder's
  whole stderr and stdout, for each marker in every encoding the
  search knows. Zero matches.
- **End to end with a real Chromium:** a loopback test server serves
  four login pages (form post, script post, two-step, SHA-256 in the
  page). The test plays the person through a second CDP connection
  with `Input` events. Each page must classify as its shape, and each
  file must pass the byte search. These follow the existing
  `KHARON_REQUIRE_CHROMIUM` convention. The tests call the library's
  launch function with headless on. The shipped `main` always passes
  headless off, and there is no flag or environment variable that
  changes it. The loopback server belongs to the tests, not to the
  binary.
- **The profile:** after a recorded login, `Login Data` and the
  autofill table are empty; after each visible exit the profile
  directory is gone; a leftover directory is removed at the next
  start.
- **Refusals:** a non-HTTPS URL, an unknown `format_version`.

### Proposed SPEC rows

For the implementation PR, wording to be reviewed there:

| ID | Requirement |
|---|---|
| REQ-TCH-001 | The recorder attaches only to a browser it launched, on a profile it created. It has no option to do otherwise |
| REQ-TCH-002 | The recorder writes no typed value to the recording file, to any file of its own, or to its output |
| REQ-TCH-003 | The file holds no cookie, no header value beyond content type and auth scheme, no response body, no query value and no request-body value |
| REQ-TCH-004 | The recorder holds no broker credential, listens on no socket, and opens no network connection except loopback CDP to its own browser |
| REQ-TCH-005 | The four fixture logins classify as `form_post`, `script_post`, `two_step` and `transformed` |
| REQ-TCH-006 | The browser profile is deleted on every exit the recorder can see, a leftover one is deleted at the next start, and the browser is always visible |

## Left to the builder

- How candidate selectors are generated and ordered.
- The exact Chromium flag set, and how the browser is found on each
  platform.
- Module layout inside the two crates, and the CDP client's shape.
- The fixture pages and the test driver.
- The wording of the summary and of `show`.
- The list of CAPTCHA hosts.

## Known limits

- The recording is made in a visible desktop browser. The agent's
  browser is usually headless, and a site may lay itself out
  differently there. The file records the viewport and user agent so
  a mismatch can be seen later.
- A site with bot detection may treat a fresh profile with a
  debugging port differently from a person's everyday browser.
- A person can type a real password in spite of the notice. The
  recorder still writes it nowhere, but the program read it and the
  browser held it until the profile was deleted.
- Passkey logins are not detected in this piece.
