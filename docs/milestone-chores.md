# Milestone chores

Lead duties (create issues, groom the backlog, check scope creep) are per-cycle tasks, not a standing role. Every chore cycle opens three chore issues and routes each with an `assigned:<agent>` label. The chores rotate across Nyx, Muse, and Claude Duet.

## Release trains and chore cycles

kharon ships on a rolling release train. Work is collected in the one open milestone, [`next`](https://github.com/CycleFive/kharon/milestone/12), which never closes. A version (`v0.7.0`, `v0.8.0`, …) is cut from `next` when its gate passes: master is green and something user-visible landed. Platform goals are tracked with `platform:` labels and tracking issues, not milestones.

A **chore cycle** is one train: the span from one version cut to the next. The chore issues name the version the cycle is expected to cut. At close-out, the shipped issues move from `next` into a closed milestone named for that version, the same as `v0.2.0`–`v0.6.0`.

## The three chores

1. **Groom** (start) — write, size, label, and order issues in `next`; record the cycle's scope and exit criteria.
2. **Scope check** (midpoint) — compare open work in `next` to the exit criteria; cut or defer drift. Ping Lothrop in #needs-lothrop only when a decision is needed.
3. **Close-out** (end) — verify the gate and exit criteria; cut the version from `next` as `cycle-five`; move the shipped issues into the version milestone and close it (`next` stays open); short retro; open the next cycle's three chores.

Use the issue forms in `.github/ISSUE_TEMPLATE/`. After opening, apply exactly one of `assigned:nyx`, `assigned:muse`, or `assigned:duet`.

**Rotation.** Ring order: `nyx` → `muse` → `duet` → `nyx`. Assign one distinct agent to each of the three chores in a cycle, and advance each chore type one step in the ring from the prior cycle so no agent does the same chore twice in a row. Record the agent on the issue (dropdown + label) so the next close-out can pick the successor.

**Trust.** Assignment labels are honored only when applied by a collaborator with triage, write, maintain, or admin on that repo. Anyone can open an issue on a public repo, but they cannot add labels. Nothing in this repo reads the labels; routing happens in the agents' mailroom, which lives outside kharon and checks who applied the label before acting on it.
