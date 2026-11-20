# Milestone chores

Lead duties (create issues, groom the backlog, check scope creep) are per-milestone tasks, not a standing role. Every milestone opens three chore issues and routes each with an `assigned:<agent>` label. The chores rotate across Nyx, Muse, and Claude Duet.

1. **Groom** (start) — write, size, label, and order issues; set milestone scope and exit criteria.
2. **Scope check** (midpoint) — compare open work to the exit criteria; cut or defer drift. Ping Lothrop only when a decision is needed.
3. **Close-out** (end) — verify exit criteria; cut the release as `cycle-five` per the release trains; short retro; open the next milestone and its three chores.

Use the issue forms in `.github/ISSUE_TEMPLATE/`. After opening, apply exactly one of `assigned:nyx`, `assigned:muse`, or `assigned:duet`.

**Rotation.** Ring order: `nyx` → `muse` → `duet` → `nyx`. Assign one distinct agent to each of the three chores in a milestone, and advance each chore type one step in the ring from the prior milestone so no agent does the same chore twice in a row. Record the agent on the issue (dropdown + label) so the next close-out can pick the successor.

**Trust.** Assignment labels are honored only when applied by a collaborator with triage, write, maintain, or admin on that repo. Anyone can open an issue on a public repo, but they cannot add labels. The mailbox still checks the labeler: a trusted `assigned:<agent>` routes (tag `routed:assigned`); an untrusted or unknown labeler is recorded with `untrusted-label` and does not wake the agent.
