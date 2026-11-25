# kharon

Vaultwarden fill broker: lets AI agents fill credentials without ever seeing them.

## Documentation

### Start here

- [`SPEC.md`](SPEC.md): the spec and source of truth. Every requirement has a `REQ-<AREA>-NNN` ID and one acceptance criterion.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): who builds kharon, the claim protocol, PR and review rules, and secrets policy.
- [`COMPAT.md`](COMPAT.md): official Bitwarden cloud compatibility (REQ-DEP-004), how the nightly job runs, and recorded results.
- [`docs/milestone-chores.md`](docs/milestone-chores.md): milestones, release trains and the `next` backlog, and the three chore issues (Groom, Scope check, Close-out) that rotate across the agents.
- [`docs/roadmap.md`](docs/roadmap.md): the agent platform roadmap. Releases are rolling trains; the platform order is OpenClaw, then Hermes, then other CDP hosts.

### Design and security

- [`docs/crypto.md`](docs/crypto.md): the Bitwarden key chain step by step (REQ-CRY-010), with the source for each construction.
- [`docs/post-fill-exposure.md`](docs/post-fill-exposure.md): the threat model for what happens to a secret after kharon fills it — page leftovers, browser-retained state, and what an agent sharing the CDP session can read (#354).
- [`docs/1password-agent-model.md`](docs/1password-agent-model.md): how 1Password serves agents, the research behind kharon's agent-initiated transport (#121).
- [`docs/fill-deadline-exploration.md`](docs/fill-deadline-exploration.md): exploration of a page-side fill deadline (#75), beyond the broker-side REQ-API-009 timeout.

### Deploying and operating

- [`docs/managed-deploy-runbook.md`](docs/managed-deploy-runbook.md): the ordered steps for one managed customer deploy, end to end.
- [`docs/deployment.md`](docs/deployment.md): the deployment guide, the reference each runbook step points into.
- [`docs/broker-lifecycle.md`](docs/broker-lifecycle.md): host install of kharond, backup and restore of `/data`, upgrades, and the secrets inventory.
- [`docs/vault-onboarding.md`](docs/vault-onboarding.md): the customer's Bitwarden organization, collection, dedicated account, and API key.
- [`docs/agent-runtime-setup.md`](docs/agent-runtime-setup.md): the agent side on a hosted or root runtime, and handing over credentials.
- [`docs/teach-mode.md`](docs/teach-mode.md): `kharon-teach`, a program that records how a login works while a person logs in by hand with a throwaway account, and writes a file with no typed value in it (#361).
- [`docs/hermes-end-to-end.md`](docs/hermes-end-to-end.md): Hermes after the connector is installed: the MCP client, what the agent and the owner do in a fill, and what each failure looks like. A record of one live run.
- [`docs/acceptance-checks.md`](docs/acceptance-checks.md): checks a new managed deploy must pass before it carries anyone but a pilot (edge, one real fill, REQ-GOAL-002 canaries).
- [`deploy/compose/README.md`](deploy/compose/README.md): running kharond with Docker Compose.

Scripts referenced by those guides:

- [`deploy/agent-host/provision.sh`](deploy/agent-host/provision.sh) and [`deploy/agent-host/provision-connector.sh`](deploy/agent-host/provision-connector.sh): agent host provisioning, without and with the WebSocket connector.
- [`deploy/checks/edge-checks.sh`](deploy/checks/edge-checks.sh): edge checks, run from an internet host.
- [`deploy/cloudflared/config.yml`](deploy/cloudflared/config.yml): the Cloudflare Tunnel config.

### API reference

- [`docs/api/openapi.json`](docs/api/openapi.json): the HTTP API (OpenAPI).
- [`docs/api/mcp-tools.json`](docs/api/mcp-tools.json): the MCP tool definitions agents call at `/mcp`.

### Claude Duet integration

Research and setup notes for running Claude Duet as a kharon agent. These are point-in-time records from Nov 14, 2026; each says what it verified and what it inferred. Superseded in part: #327 (a standing Duet host) is parked and 1Password is out; kharon stays on CDP hosts, per the [roadmap](docs/roadmap.md).

- [`docs/duet-1password-comparison.md`](docs/duet-1password-comparison.md): 1Password's fill inside Claude Duet compared with kharon, plus a live fill test. Verdict: a custom connector can't reach Duet's browser.
- [`docs/claude-browser-credential-access.md`](docs/claude-browser-credential-access.md): what access 1Password got from Anthropic, whether any third party can fill Claude's browser, Bitwarden's Agent Access SDK, and the routes open to kharon.
- [`docs/duet-connector-host-requirements.md`](docs/duet-connector-host-requirements.md): requirements for a host running the connector and Chromium for Duet, Duet's side of the gap, and browser pool options.
- [`docs/duet-vm-runbook.md`](docs/duet-vm-runbook.md): ten steps from a new Proxmox VM to a box where Duet fills through kharon (#327, parked). Untested; kept as a record.
- [`docs/agent-adoption-survey.md`](docs/agent-adoption-survey.md): the agent platforms kharon can plug into, ranked by fit and reach, with the Bitwarden Agent Access SDK and 1Password compared (1Password is out; see the roadmap for order).

### Design specs

Approved designs, newest last. Each names its issue, builder and reviewers.

- [`2026-11-09-connector-websocket-design.md`](docs/superpowers/specs/2026-11-09-connector-websocket-design.md): the agent connector over WebSocket at `/connector` (#199).
- [`2026-11-09-portable-gateway-design.md`](docs/superpowers/specs/2026-11-09-portable-gateway-design.md): one kharon package, reachable only through Cloudflare (#197, #206).
- [`2026-11-10-n3-mcp-oauth-connect-design.md`](docs/superpowers/specs/2026-11-10-n3-mcp-oauth-connect-design.md): N3, connecting kharon from a dashboard over MCP OAuth (#213).
- [`2026-11-11-n2-owner-ui-behind-edge-design.md`](docs/superpowers/specs/2026-11-11-n2-owner-ui-behind-edge-design.md): N2, the owner UI behind the edge (#208).
- [`2026-11-12-n3-phase2-connector-auth-design.md`](docs/superpowers/specs/2026-11-12-n3-phase2-connector-auth-design.md): N3 phase 2, a dashboard runtime's connector authenticating with a Connect token (#235).
- [`2026-11-18-teach-recorder-design.md`](docs/superpowers/specs/2026-11-18-teach-recorder-design.md): teach mode piece 1, `kharon-teach`, a recorder for a demonstrated login (#361).
- [`2026-11-24-teach-method-design.md`](docs/superpowers/specs/2026-11-24-teach-method-design.md): teach mode piece 2, login methods, the player and the per-site registry (#381).
- [`2026-11-25-teach-never-in-page-design.md`](docs/superpowers/specs/2026-11-25-teach-never-in-page-design.md): teach mode piece 3, why the never-in-the-page rung is not a rung, whether a second CDP client can see a rewritten request, and the no-go for a prototype (#384).

### Implementation plans

Task-by-task plans that implemented the specs above.

- [`2026-11-09-199-connector-ws.md`](docs/superpowers/plans/2026-11-09-199-connector-ws.md): the WebSocket connector (#199).
- [`2026-11-09-210-api-optional.md`](docs/superpowers/plans/2026-11-09-210-api-optional.md): kharond running with no `[api]` listener (#210).
- [`2026-11-09-n1-portable-compose.md`](docs/superpowers/plans/2026-11-09-n1-portable-compose.md): N1, the portable compose package.
- [`2026-11-10-219-connector-preauth-hardening.md`](docs/superpowers/plans/2026-11-10-219-connector-preauth-hardening.md): connector pre-auth hardening (#219).
- [`2026-11-10-220-compose-ws-e2e.md`](docs/superpowers/plans/2026-11-10-220-compose-ws-e2e.md): compose E2E for path B over WebSocket with no VPN (#220).
- [`2026-11-11-n2-owner-ui-behind-edge.md`](docs/superpowers/plans/2026-11-11-n2-owner-ui-behind-edge.md): N2, the owner UI behind the edge.
- [`2026-11-12-234-n3-compose-connect-e2e.md`](docs/superpowers/plans/2026-11-12-234-n3-compose-connect-e2e.md): N3 compose E2E with a fake dashboard running Connect, refresh, reuse-kill and Disconnect (#234).
- [`2026-11-18-361-teach-recorder.md`](docs/superpowers/plans/2026-11-18-361-teach-recorder.md): the teach recorder, `kharon-recording` and `kharon-teach` (#361).
- [`2026-11-24-382-teach-method.md`](docs/superpowers/plans/2026-11-24-382-teach-method.md): teach mode piece 2, login methods, the player and the per-site registry (#382).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
