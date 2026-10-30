# Contributing to kharon

kharon is built by three agents plus the owner. The spec ([`SPEC.md`](SPEC.md)) is the source of truth; requirement IDs (`REQ-<AREA>-NNN`) tie issues, tests and PRs together. Work is tracked on the org Project **kharon**.

| Agent | GitHub login | Branch prefix |
|---|---|---|
| Nyx (lead) | `cycle-five-nyx[bot]` | `nyx/` |
| Muse | `cycle-five-muse[bot]` | `muse/` |
| Nix | `cycle-five-nix[bot]` | `kimi/` |
| Owner | `cycle-five` (Lothrop) | — |

## Claim protocol

1. Pick an issue whose Project status is **Ready** (all `Depends on #n` issues closed).
2. Claim it before starting: self-assign, or comment `/claim` if you can't assign. First claim wins; a claim with no push or comment for 24 h may be released by the lead.
3. Move it to **In progress**. **One In-progress issue per agent at a time.**
4. Branch name: `<agent>/<issue#>-<slug>`, e.g. `muse/6-encstring`.
5. Blocked? Add `status:blocked`, comment the reason, and you may claim something else.

## Pull requests

- Title is a [Conventional Commit](https://www.conventionalcommits.org/): `feat(bwcrypto): …`, `fix(api): …`, `test: …`, `docs: …`, `build: …`, `chore: …`.
- Body cites the REQ IDs covered and `Closes #<issue>`.
- Tests are named after the REQ ID they prove: `req_cry_002_rejects_bad_mac`.
- CI (fmt, clippy `-D warnings`, test) must be green.
- **One approving review from another agent** is required. Don't approve your own PR. Squash-merge.
- Move the issue to **In review** when the PR opens.

## Spec changes and disputes

- Spec changes go by PR to `SPEC.md` only, titled `docs(spec): …`, and must keep REQ IDs stable (add new IDs; never renumber).
- Disputes about the spec or design are resolved by the lead (Nyx). The owner can override.
- If implementation shows an AC is wrong, open a spec PR rather than silently diverging.

## Secrets

Never commit real credentials. Fixtures use generated canaries only.

## License

Contributions are dual licensed `MIT OR Apache-2.0` (see README).
