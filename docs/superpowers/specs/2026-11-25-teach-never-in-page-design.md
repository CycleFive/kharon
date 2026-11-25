# Teach mode, piece 3: the never-in-the-page rung is not a rung

Status: design, 2026-11-25, for #384 (piece 3 of #361, milestone M2).
The note is Muse's, posted on #384 as comment 7169424066 and copied
here unchanged. The owner's framing it works from is Lothrop's,
2026-11-25, posted on #384 as comment 7158633746. Duet (kharon session)
added the last section, marked as Duet's, to answer what M2 exit
criterion 4 asks and the note left open. Reviewers: Muse and Nyx. No
code and no SPEC change land with this note.

Earlier pieces: [piece 1, the recorder](2026-11-18-teach-recorder-design.md)
and [piece 2, login methods](2026-11-24-teach-method-design.md).

## Design note — "never in the page" is not a rung

This is the piece-3 design document for #384. The owner's framing is on this issue (comment 7158633746); this note turns it into the design record, with the #383 live-test evidence folded in.

### Question

Teach mode's ladder, as designed (2026-11-18 recorder design, strongest first): rung 1 = never in the page — a placeholder is filled and the real secret is put into the login request as it leaves the browser; rung 2 = in the page for milliseconds — atomic fill-and-submit plus the opt-in post-submit scrub; rung 3 = in the page until the agent moves on (today's `submit: false`). Piece 3 asked whether rung 1 exists: substitute the credential into the outgoing request at the network layer (CDP Fetch interception / request rewrite), so the secret never enters the page at all. (The code's rung ceilings are only `milliseconds` and `agent_continues` — "never" is not a ceiling value anywhere in SPEC or code.)

### Short answer

No — not as a general rung. Where request rewrite is sound, it is replay of a recorded request template, and there rung 2 already bounds exposure to milliseconds, so rewrite buys almost nothing. Where rewrite would buy something — logins whose payload the page's own code constructs, signs, or transforms — the rewrite layer would have to reimplement that site's login logic from observation, which is guessing, not replay. **The ladder tops out at rung 2 for agent replays.**

### Case analysis, by the four teach shapes (#383 live test, 2026-11-25)

The #383 run replayed all four recorded shapes end-to-end in fresh profiles, plus the drift case. The shapes are the right partition for this question:

1. **form_post** — the browser serializes named fields into the POST body. A recording hands you the exact request shape, so substitution is templating, not guessing. Feasible — and redundant: this is precisely the shape where rung 2's scrub is cheapest and the secret's in-page lifetime is already ~500 ms (the #369 rig observed fields empty ~510 ms after they were seen filled, `fill_scrub: cleared`).
2. **script_post** — page JS reads the fields and constructs the request itself (fetch/XHR). Skip the fields and the JS builds the request from empty or wrong values; rewriting the serialized body afterwards means knowing the site's serialization (field names, encoding, extra tokens), which a recording shows for *one* instance, not as a rule. Fragile templating at best; any page-side change silently breaks it.
3. **two_step** — the second request depends on state created by the first (in the fixture, step 2 is gated on step 1; real sites add cookies, CSRF tokens, and per-session nonces). A rewrite layer must track that multi-request state machine — state the page currently maintains for free. Each additional dependency is another guessed invariant.
4. **transformed** — the page transforms the credential before submit (the fixture SHA-256-hashes the password and its worker *refuses any non-digest POST*). This is the empirical kill case: in the #383 run the replay provably went through the page's own hashing handler, because no other submit is accepted. A network-layer substitution of the raw secret would be refused; substituting the digest means reimplementing the transform — the exact guessing the rung was supposed to avoid.

### The drift argument

Rung 2/3 replay has a cheap, designed failure mode: the method checks the page structure it was taught against, and drift refuses cleanly — #383's drift beat produced `field_not_found` / `method_drift`, nothing typed, entry marked stale. A request-template method has no equivalent signal: the outgoing request looks well-formed whether or not the site still expects that shape, so drift failure presents as a rejected login (or worse, a lockout counter increment) instead of a pre-flight refusal. Any rung-1 design would have to invent a drift check at least as good; none is obvious, and #393 (stale methods still prompting for grants they will refuse) shows the team is already tightening pre-refusal on the existing rungs rather than adding weaker-checked ones.

### What would change this conclusion

A named class of real logins where rewrite is (a) not guessing — the request shape is fully determined by the recording, with no page-side construction, signing, transformation, or cross-step state — and (b) not redundant — rung 2's bounded in-page exposure is demonstrably insufficient for that class. If Duet or Nyx can name such a class, this note should be amended to carve it out; absent one, "not a rung" stands.

### Disposition

- #384 closes with this note as the design record; no implementation issue is filed.
- Consequence for M2 close-out (#380, Nyx): record the teach ladder as topping out at rung 2 (`milliseconds`) for agent replay, with rung 1 considered and rejected on the transformed-shape evidence, not merely unbuilt.
- SPEC check, re-run against current master (`1094972`, post-#388/#392): no REQ row promises the never-in-the-page rung; REQ-TCH-005 names only the `milliseconds` and `agent_continues` ceilings. The rung-1 promise lives only in the design docs' piece lists, so this note, as the piece-3 design doc, is itself the amendment — no SPEC change is needed.

— cycle-five-muse[bot]

## Added by Duet: the parts of #384 and M2 criterion 4 the note leaves open

Everything in this section is Duet's (kharon session), written on
2026-11-25 against master `90a899c`. It does not change the note's
conclusion. It adds the three things M2 exit criterion 4 and #384's
"What the design must settle" ask for and the note does not answer:
the second-CDP-client question, where the rewrite would live under
REQ-ARCH-003, and an explicit go/no-go. It also settles the recorder's
`network_swap_candidate`, which the piece-1 design left to this piece.

Sources for the CDP claims are the protocol definitions in
[ChromeDevTools/devtools-protocol](https://github.com/ChromeDevTools/devtools-protocol)
(`pdl/domains/Fetch.pdl` and `pdl/domains/Network.pdl`), read on
2026-11-25. Each claim says how sure it is. None was checked against a
running Chromium for this note.

### Can a second CDP client observe the rewritten request?

**Yes, on at least one path, and the protocol gives kharon no way to
stop it.** Rung 1 would take the secret out of the page. It would not
take it out of reach of the agent's harness, which is the client the
ladder exists to defend against: the harness has its own CDP
connection to the same browser ([post-fill exposure](../../post-fill-exposure.md),
rows D1 and D2, and #361).

A rewrite would work like this: the broker enables `Fetch` with a
request-stage pattern for the login origin, the page submits a
placeholder, the broker gets `Fetch.requestPaused`, and it answers with
`Fetch.continueRequest` carrying the real secret in `postData` (or in
`headers`). What another client can see of that:

| Path | What the second client sees | How sure |
|---|---|---|
| Its own `Fetch` interception | A second client that enables `Fetch` on the same target gets its own `Fetch.requestPaused`, whose `request` carries the body. Chromium lets more than one client intercept (DevTools and an automation client can both hold `Fetch`). If its interception runs after the broker's, it sees the real secret. The protocol says nothing about the order of two clients' interceptions, so kharon cannot arrange to be last. | Medium. That several clients can intercept is well established; the order, and whether a later interceptor sees an earlier one's rewritten body, is not specified and was not tested. |
| Redirecting the rewritten request | `Fetch.continueRequest` takes a `url`, documented as modifying the request URL "in a way that's not observable by page". A client whose interception runs after the broker's can send the request, secret included, to another host. kharon's origin binding checks the page, not where the request finally goes. | High that the parameter exists and does this; medium on the ordering, as above. |
| Credential in a header | `Network.requestWillBeSentExtraInfo` carries "raw request headers as they will be sent over the wire" to any client with `Network` enabled. A site that sends the credential in a header (HTTP Basic, a bearer field the page builds) would leak it to a plain `Network` subscriber, the kind REQ-ARCH-003's acceptance test already uses. | High from the protocol text; not tested with a `Fetch` header override. |
| Credential in the body, `Network` only | `Network.requestWillBeSent` describes the request as the page made it, so it shows the placeholder. `Network.getRequestPostData` is defined as "post data sent with the request"; whether that is the page's body or the rewritten one is not specified. | Low. Unknown without a test. |

Two consequences:

1. REQ-ARCH-003's acceptance test subscribes the second client to
   `Runtime`, `Log`, `Network` and `Page`, not `Fetch`. A rung-1 build
   could pass that test and still be observable, so the test would not
   show the rung is safe.
2. The test that would settle the open rows is small: a real Chromium,
   the broker's client rewriting a placeholder login, and a second
   client with `Fetch` and `Network` enabled byte-searching its
   transcript for the canary, in both attach orders. kharon-teach's
   test support already drives a second CDP connection
   (`Person::connect`), so it would fit there. Under the no-go below it
   is not needed, and it is not filed.

### Where the rewrite would live (REQ-ARCH-003)

The rewrite needs the secret, and only the broker holds it, so it would
have to run on the broker's own CDP client. The recorder's way out
(a separate program with its own client) does not apply: that program
would need the secret too.

So the broker's client would enable `Fetch`. `Fetch` is not one of the
domains REQ-ARCH-003 names, and its events go to the enabling session,
so the letter of the requirement could be read to allow it. Its intent,
that the broker never puts the secret where another session can see it,
fails on the paths in the table. Rung 1 would need an explicit
exception to REQ-ARCH-003 and a stronger acceptance test (a second
client with `Fetch` enabled). With the no-go, neither is proposed.

### Prototype: no-go

**No prototype is filed.** Three reasons, any one of which is enough:

1. The note's case analysis: where a rewrite is sound it is redundant
   with rung 2, and where it would help it is guessing.
2. The table above: the secret leaves the page but not the harness's
   reach, and a later interceptor can redirect it.
3. It needs an exception to REQ-ARCH-003 that the team has not made
   for anything else.

The note's "What would change this conclusion" stands, with one more
condition added: a class of logins that meets (a) and (b) there must
also be one where the second-client paths above are closed, which
needs the test sketched above first.

### What happens to `network_swap_candidate`

The recorder sets `classification.network_swap_candidate` when the
password appears as typed or encoded in exactly one stored request, and
the piece-1 design ([2026-11-18](2026-11-18-teach-recorder-design.md),
"`network_swap_candidate`") left "what that is worth" to this piece.
`kharon-teach`'s summary currently prints, for a candidate, "Network
swap: this login looks like one where the password can be put in at the
network level", which reads as a promise of a rung kharon will not
build.

Decision (Duet's call, for the reviewers): keep the field. It is a
true fact about the recording, it is in the recording format, and
removing it would break files already written. Change the printed line
so it states the fact without the promise, for example "The password
was sent as typed in one request." That is a code change, so it goes in
a follow-up issue filed in `next`, not in this note. The same issue
changes `docs/teach-mode.md`, whose "What is not built yet" list still
says rung 1 is "tracked in #384", to say it was considered and is not
planned, linking here.

### Index

`README.md`'s documentation index lists this note under Design specs.
The same change adds two files the index was missing:
`docs/milestone-chores.md` and the piece-2 implementation plan.
