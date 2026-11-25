# Milestone chores

Lead duties (writing issues, grooming the backlog, checking scope creep) are tasks inside each milestone, not a standing role. Every milestone carries three chore issues, and each one is routed with an `assigned:<agent>` label. The chores rotate across Nyx, Muse, and Claude Duet.

## Milestones and release trains

These are two separate things, and they run independently.

- **A milestone is a unit of scope.** It has a goal, exit criteria in its description, and a due date (for example `M6 — teach mode`). The prior milestone's Close-out creates it with a title only, its Groom chore fills in the goal, exit criteria, and due date, and it closes when its own Close-out chore closes. The due date gives the Scope check a real midpoint, and the milestone's progress bar counts the chores along with the work.
- **The release train is the shipping schedule.** A version (`v0.7.0`, `v0.8.0`, …) is cut whenever master is green and something user-visible has landed. That can happen zero, one, or several times during a milestone. Each version is recorded as a tag and a GitHub release whose notes list the issues it shipped. Versions no longer get their own milestones, because GitHub puts an issue in only one milestone and that slot now belongs to scope. The closed milestones `v0.2.0` through `v0.6.0` stay as history.
- **[`next`](https://github.com/CycleFive/kharon/milestone/12) is the unscheduled backlog.** Work that isn't in the current milestone waits there. Groom pulls issues from `next` into the new milestone, and Close-out sends unfinished work back to `next` or forward into the next milestone on purpose. `next` itself has no chores and never closes, and the Groom sweeps it at the start of every milestone (see below).

Any agent may file an issue into `next`. Filing doesn't set priority or put the issue in a milestone; the Groom decides both. Parked issues (label `parked`) carry no milestone, so `next` holds only work that can be picked up.

Platform goals are still tracked with `platform:` labels and tracking issues.

## The three chores

1. **Groom** (start). Set the milestone's goal, exit criteria, and due date (the prior Close-out created it with a title only). Sweep `next` (below). Then write, size, label, and order its issues, pulling them from `next`. For each gate in the exit criteria, list its consequences: the state changes elsewhere that finishing the gate triggers (for example, flipping a platform to supported once its canary passes).
2. **Scope check** (around the midpoint, using the due date). Compare the open work to the exit criteria, and cut or defer anything that has drifted. Ping Lothrop in #needs-lothrop only when a decision is needed.
3. **Close-out** (end). Verify the exit criteria or record a waiver, confirm that every consequence from the Groom is done or handed to a named owner, and list the versions the train shipped during the milestone. Create the next milestone (title only) and open its three chores in it, move unfinished issues on purpose (into that milestone or back to `next`), write a short retro, and then close this issue and the milestone. Close-out doesn't cut a release; the train does that whenever its gate passes.

### Sweeping `next`

Before pulling anything into the new milestone, the Groom reads every open issue in `next`, every open issue with no milestone, and every `parked` issue, including bodies and recent comments, not just titles. It sorts each one:

- **Done or stale:** the work landed, or the reason for the issue is gone. Close it with a comment that links the proof (the merged PR, the closing change, or the decision that ended it).
- **Duplicate:** close it into the issue that survives, and say why that one survives. Carry over anything the closed issue adds.
- **A nit or a small follow-up with its own issue:** fold it into the open rolling list for its area (for example #286 for OAuth, deploy, and CI, or #387 for teach mode) and close the issue.
- **Still valid:** check its labels, and that it is in `next` or in the right milestone.

A `parked` issue is never started, unparked, or re-milestoned in a sweep; it waits for Lothrop's ✅. The sweep only confirms that the label still matches his last word on the issue, and reports any that don't.

Post the sorted list on the Groom issue as one action list, each line with the issue number, the action, and a one-line reason. Closes that are a judgment call (not planned, a duplicate, a parked issue) wait for Lothrop's ✅ on that list; plainly done items can close straight away with their proof.

Use the issue forms in `.github/ISSUE_TEMPLATE/`. Open all three chores into the milestone they belong to, then apply exactly one of `assigned:nyx`, `assigned:muse`, or `assigned:duet`.

**Rotation.** The ring order is `nyx` → `muse` → `duet` → `nyx`. Each of a milestone's three chores goes to a different agent. Each chore type moves one step around the ring from the prior milestone, so no agent does the same chore twice in a row. Record the agent on the issue (in the dropdown and the label) so the next Close-out can pick the successor.

**Bootstrapping.** The first milestone has no prior Close-out. Lothrop, or the agent he names, creates it with a title, opens its three chores in it, and assigns them as he directs. The rotation runs from there.

**Trust.** Assignment labels count only when a collaborator with triage, write, maintain, or admin access on the repo applied them. Anyone can open an issue on a public repo, but they can't add labels. Nothing in this repo reads the labels. Routing happens in the agents' mailroom, which lives outside kharon and checks who applied a label before acting on it.
