# Exploration: a page-side fill deadline (#75)

Status: exploration, not an implementation. Follow-up to the
REQ-API-009 clarification (#74, from #46/#73). Recommendation in
§4; the decision is Nyx's.

## 1. The window, precisely

REQ-API-009's deadline is enforced broker-side: on expiry the
broker replies `timeout`, zeroizes its plaintext buffer, writes
`fill_timeout`, and sends nothing more for that fill (#76 also
drops a connection caught mid-send so an unflushed frame can never
flush late).

What the broker cannot recall is a fill call **already delivered**:
`FILL_IN_PAGE` (`crates/kharond/src/cdp/page_js.rs`) is a single
synchronous `Runtime.callFunctionOn` in an isolated world. Once it
starts, it runs to completion in one renderer task — remaining
fields are written, and if `submit: true`, the submit is
dispatched — whether or not the broker has stopped waiting. The
post-timeout window is therefore *the remaining execution time of
that one task after the broker's deadline fires*.

That remainder is usually small (a few DOM writes), but it is not
bounded by the fill itself: `setNativeValue` dispatches `input` and
`change` events, and `dispatchEvent` is synchronous — a slow (or
hostile) page event handler runs *inside* the fill task and can
stretch it arbitrarily. `form.requestSubmit()` has the same
property for the submit step. So the honest worst case today is:
an already-delivered fill completes, including submit, an
unbounded time after the `timeout` reply.

## 2. Why "a page clock" is the wrong frame — and the right one

The issue's objection is to a page-side **wall-clock** deadline
(e.g. "stop after 21:04:31.200"): the broker would have to trust
the page's `Date.now()` — clock skew between hosts, and a clock
the checked code reports about itself. That objection stands for
absolute timestamps.

A **relative budget** is a different mechanism:

- The broker passes a duration in milliseconds (computed at
  dispatch: `fill_deadline` minus time already spent on the
  request, minus a safety margin for the return trip), as one more
  argument to `fillInPage`.
- The function samples `performance.now()` at entry and again
  before each step. Both samples are taken *inside the same
  synchronous task*, in the *isolated world* — the page's own
  scripts run in a different world and cannot patch the isolated
  world's `performance.now`, and no wall clock is involved at all.
  The only thing measured is elapsed time within the task, which
  is exactly the quantity the window is made of.
- Checks go where they bound damage: before writing each field,
  and — the important one — **immediately before dispatching the
  submit**. On expiry the function runs the existing
  clear-on-failure path (`clearWritten`, #101) and throws a new
  code, `kharon:deadline`.

Nothing here asks the broker to trust a page-reported value: the
reply is still governed by the broker's own deadline. The page
check is a *cooperative early abort* for the realistic case — an
honest but slow page (heavy handlers, large DOM) — and it converts
the common case from "completes late, possibly with submit" to
"stops at the next step boundary, fields cleared, no submit".

## 3. Alternatives considered

- **Absolute wall-clock deadline in the page.** Rejected, per §2:
  host clock skew plus a self-reported clock.
- **Split fill and submit into two CDP calls** (fill returns, the
  broker re-checks the deadline, then a second call submits). This
  gives the strongest guarantee for the submit specifically, but
  it gives up the property REQ-ORG-003 relies on: checks and
  writes in one run-to-completion task, with no navigation able to
  commit in between. A second call can re-verify origin/top-frame
  (the machinery exists), yet credentials then sit filled and
  unsubmitted for a full extra round trip on *every* fill, and a
  timeout between the calls needs a third, best-effort clear call
  — which, like the existing `CLEAR_IN_PAGE` scrub, the broker
  cannot confirm after the fact.
  Rejected as the primary mechanism; the §2 check before submit
  captures most of the benefit inside the existing atomic call.
- **`setTimeout` watchdog in the page** that clears fields at the
  deadline. Timers cannot preempt a running synchronous task — the
  watchdog fires only after the fill task has already run to
  completion. Useless for this window.
- **Broker-side `Runtime.terminateExecution` on timeout**, via a
  second attached session. The only mechanism that could stop a
  *never-returning* handler, but it terminates all script in the
  target, needs a parallel CDP attachment racing the first, and is
  a DevTools debugging affordance, not a page contract. Worth a
  spike only if the residual in §5 is ever judged unacceptable;
  not proposed here.

## 4. Recommendation

Implement the §2 relative budget:

1. `fillInPage` gains a fifth argument, `budgetMs` (`0`/absent =
   no page-side check, preserving current behaviour for any other
   caller). Sample `performance.now()` at entry; check before
   each field write and before the submit dispatch; on expiry,
   `clearWritten(written)` and `fail("deadline")`.
2. Broker side (REQ-API-009 path): compute the budget at dispatch
   from the request's existing deadline — remaining time minus a
   fixed return margin (suggest 250 ms; make it a named constant,
   not config). If the remaining time is already exhausted, the
   fill is refused before dispatch, as today.
3. If the broker *does* receive the `kharon:deadline` exception
   reply before its own deadline fires, map it to the existing
   `timeout` status and the `fill_timeout` audit outcome — the
   semantics already documented in the REQ-API-009 †note ("could
   not confirm the fill in time") cover it; no new status value,
   no SPEC change beyond noting the narrowed window in that note.

Expected effect: for an honest-but-slow page, post-timeout
completion shrinks from "the rest of the task" to **at most one
step's overshoot** (one field write + its synchronous handlers,
past the last check). A submit is never *dispatched* after the
budget expires; a submit dispatched in time whose own handlers
stall is in the same class as a fill dispatched in time today.

## 5. Residual window (what this does not fix)

- A single step that never returns (a page handler in an infinite
  loop) blocks the task before any later check runs. Nothing
  page-side can preempt synchronous JS; see `terminateExecution`
  in §3 for the only, heavyweight, broker-side candidate.
- A hostile page gains nothing from the budget either way: it
  cannot patch the isolated world's clock or the fill function,
  and its only lever — stalling inside its own handlers — is the
  residual above, unchanged from today.
- The margin means the page may abort slightly *before* the
  broker's deadline on fills that would have just made it. That
  is the intended trade: `timeout` already means "not confirmed",
  never "nothing happened".

## 6. Test plan (for the implementation issue)

- Node-stub unit test in the `page_js.rs` style of
  `req_org_003_top_frame_check_pins`: a field whose `input`
  handler advances a fake `performance.now()` past the budget →
  later fields are never written, written fields are cleared, the
  submit is never dispatched, and the thrown code is
  `kharon:deadline`. Same harness with the clock held under budget
  → fill + submit complete.
- CDP-stub test alongside `req_api_009_*`: a `callFunctionOn` that
  returns the `deadline` exception → reply is `timeout`, exactly
  one `fill_timeout` audit entry, buffer zeroized (the existing
  AC's assertions, new trigger).
- The existing REQ-API-009 AC is unchanged broker-side: no later
  write reaches the stub after expiry.

## 7. Provenance

- REQ-API-009 and its †clarification, SPEC.md §4 (the note that
  tracks this issue by number).
- `crates/kharond/src/cdp/page_js.rs` — the single-task fill and
  the #101 clear-on-failure path this design reuses.
- #73 review Q2 (origin of the question), #46 (landed as the
  documentation clarified in #74), #76 (mid-send drop), #101 /
  PR #105 (clear written fields when a fill fails).
