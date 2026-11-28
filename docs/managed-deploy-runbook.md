# Managed deploy runbook: one customer, end to end

This is the order for standing up one managed, single-tenant kharon
deploy: one broker, one customer vault, one gateway hostname and one
owner hostname, with the agent connecting over WebSocket through the
tunnel (path B, no VPN). The broker and agent-host setup itself is the
[first-run guide](first-run.md): `kharon setup`, the agent-host
bundle and `kharon doctor`. This page wraps it with who does what on
a managed deploy, and adds the steps a deploy for someone else needs:
a private ntfy topic, the Cloudflare rules, the edge checks,
acceptance and handover. Each step points at the section of the
first-run guide, the [deployment guide](deployment.md) or the
[compose README](../deploy/compose/README.md) that holds the detail.
This page doesn't repeat that detail. Where the guide doesn't cover a
step yet, the step says so and names the issue tracking it.

Work from a tagged release that has `kharon setup` (any release
after v0.5.0), not a branch.

**Who does what**

- **Operator.** Runs the broker box and has its shell. Never learns the
  master password, unless the customer chooses a CLI unlock.
- **Customer.** Owns the Bitwarden vault and the passkey. The guide
  calls this person "the owner".
- **Zone admin.** Holds the Cloudflare account for the zone (for
  example `twkr.io`), and applies every Cloudflare-side change: the
  tunnel, its routes, DNS, WAF, rate-limit and Access rules. The guide
  says "the owner" for these too.
- **Agent host.** Whoever runs the agent's runtime and its connector.
  That may be the customer's own machine, or a third party's hosted
  runtime that neither the operator nor the customer has a shell on.
  The operator hands it the agent-host bundle `kharon setup` writes
  (the agent token, the tunnel credential and the pin) out of band.

**Required** steps must be done before the deploy carries anyone but a
short pilot. **Optional** steps depend on the deploy's shape.

The examples use `kharon.example.com` (gateway) and
`kharon-owner.example.com` (owner UI). Use the customer's own names:
two hostnames, the owner UI on its own hostname, not a path under
the gateway's.

## 1. Plan

1. **Required. Pick the names and the shape** (operator). Pick the gateway
   hostname and the owner hostname, and the agent id, for example
   `assistant`. Pick an ntfy server and a private topic, which carry
   approvals and the off-host audit checkpoints. Decide whether the
   deploy uses dashboard Connect (`[oauth]`) and Cloudflare Access.
   Background:
   - [Two modes](deployment.md#two-modes) (always public mode on a managed deploy);
   - [Where cloudflared runs](deployment.md#where-cloudflared-runs) (option 1, the compose `edge` profile, is the default);
   - [Over WebSocket, through the public gateway](deployment.md#over-websocket-through-the-public-gateway-199).

## 2. Broker host

2. **Required. Provision the box** (operator). The rest of this runbook
   uses the Compose package: a Linux VM with Docker Engine and the
   Compose plugin (`docker compose`), and a checkout of the release.
   OS notes, what this repo does and doesn't say about VM size and the
   Docker install, and the host-networked unit the pilot runs (the
   user, `memlock`, `data_dir`) are in
   [Host install](broker-lifecycle.md#host-install).
3. **Required. Build the image and install the CLI** (operator):
   `docker compose build kharon` in `deploy/compose`, then copy the
   static `kharon` binary out of the image to `/usr/local/bin`. See
   [first run, step 3](first-run.md#3-run-kharon-setup).

## 3. The customer's vault

4. **Required. Create the account, organization, collection and
   personal API key** (customer, on their own machine). This is
   [first run, steps 1–2](first-run.md#1-create-the-broker-account-an-organization-and-a-collection):
   `kharon init` for the master password (whoever runs it sees the
   password, so the customer does), the dedicated account, the
   organization and collection, inviting and confirming the account,
   moving the logins kharon may fill into the collection, and the
   account's personal API key as a JSON file. The Bitwarden web-app
   detail is in [Customer vault onboarding](vault-onboarding.md).
5. **Required. Hand over the API key file and the account email**
   (customer to operator), out of band: never in a shared channel.
   The organization and collection IDs are not needed: setup lists
   what the account can see. The master password is never handed
   over.

## 4. ntfy

6. **Required. Set up the ntfy topic before the first start** (operator,
   with the customer). The topic carries approval prompts and the
   off-host audit checkpoints, and kharond starts pushing checkpoints
   the moment it starts. If the checkpoint keeper is not someone who
   may approve, use two topics: an approval topic and a checkpoint
   topic (`[audit] checkpoint_ntfy`, step 7), so the keeper never
   reads a prompt:
   - Create the private topic's users on the ntfy server: a
     write-only user whose token goes in kharond's `token_file`
     (setup's `--ntfy-token-file`, step 7), and a read-only user for
     each subscriber. The checkpoint keeper uses its user's token; the
     phone signs in with its user. Never reuse kharond's write token
     for a subscriber. With two topics, each topic gets its own
     write-only user and token file, the keeper's user reads only the
     checkpoint topic, and the phone's user reads only the approval
     topic.
   - Name who keeps the checkpoint stream. On a managed deploy that is
     the operator, unless the customer chooses to keep it. Start saving
     it off the broker host (a subscriber on another machine, or the ntfy
     server's own retention) before step 13, so the stream step 22
     verifies is complete from the first checkpoint. On one topic the
     keeper can approve, since every reader of the approval topic can;
     on a managed deploy the operator can approve from the CLI anyway.
     With two topics the keeper reads checkpoints only and cannot.
   - If approvals go through ntfy, the customer subscribes to the topic
     in the ntfy app on their phone and signs in as their read-only
     user (username and password).

   See [Setting up the ntfy topic](deployment.md#setting-up-the-ntfy-topic)
   for the tokens, the subscriber and the phone, and
   [A separate checkpoint topic](deployment.md#a-separate-checkpoint-topic-302)
   for the two-topic setup. Background:
   [Audit checkpoints off-host](deployment.md#audit-checkpoints-off-host-req-aud-002)
   and [ntfy approve and deny](deployment.md#ntfy-approve-and-deny-req-apr-004-req-dep-006).

## 5. `kharon setup`

7. **Required. Run setup** (operator, in `deploy/compose`, as root so
   the key file goes to uid 10001):

   ```sh
   sudo kharon setup --account-exists --api-key-json /path/to/handed-over-key.json \
     --cdp-via agent-connector \
     --public-host kharon.example.com \
     --owner-origin https://kharon-owner.example.com \
     --ntfy-url https://ntfy.example.com --ntfy-topic <approval topic> \
     --ntfy-token-file /run/secrets/ntfy_token
   ```

   It asks for the account email and the organization and collection,
   refuses an organization key or an account that sees too much, and
   writes `kharon.toml`, the key file (`0400`, uid 10001), the
   `[connector]` certificate and key with their Compose override, and
   the agent-host bundle. It prints `broker_pin`. See
   [first run, step 3](first-run.md#3-run-kharon-setup) for the
   questions and the files. Then delete the handed-over key file.

   `--ntfy-token-file` is the path inside the container. Setup does
   not mount it, and it refuses to overwrite an existing
   `docker-compose.override.yml`, so add the token's line to the
   override setup wrote (`- ./secrets/ntfy_token:/run/secrets/ntfy_token:ro`
   under `services.kharon.volumes`), with the file in place, as in
   [Setting up the ntfy topic](deployment.md#setting-up-the-ntfy-topic).
   Setup writes no Access, OAuth or second topic, so add these to
   `kharon.toml` by hand when the deploy uses them:
   - **Optional, `[audit] checkpoint_ntfy`:** the checkpoint topic and
     its own `token_file`, with two topics (step 6). See
     [A separate checkpoint topic](deployment.md#a-separate-checkpoint-topic-302).
   - **Optional, `[oauth] clients`:** for dashboard Connect. See
     [OAuth discovery and Connect endpoints](deployment.md#oauth-discovery-and-connect-endpoints-n3).
   - **Optional, `[owner_ui.access]`:** only after the Access application
     exists (step 12).
8. **Required. Check it** (operator):
   `docker compose run --rm kharon --check --config /etc/kharon.toml`.
   kharond refuses unsafe combinations by name. Setup already ran the
   same checks on what it wrote; this catches the hand edits of step 7.

## 6. Cloudflare (zone admin)

9. **Required. Create the tunnel and the gateway routes**: `^/mcp$` and
   `^/connector$` to `http://127.0.0.1:8790`, and a 404 catch-all. With
   `[oauth]`, also the two `.well-known/oauth-protected-resource` routes.
   The dashboard creates the proxied DNS record. See
   [Creating the tunnel (owner)](deployment.md#creating-the-tunnel-owner).
10. **Required. Put the tunnel token in place** (zone admin to operator,
    never echoed or in argv): `secrets/cloudflared_tunnel_token`, owned
    by `65532:65532`, mode `0400`. See
    [first run, step 4](first-run.md#4-start-kharond-and-enroll-your-passkey)
    and the [compose README](../deploy/compose/README.md#run-it).
11. **Required. Add the owner hostname route** to `http://127.0.0.1:8788`,
    with an empty path, no HTTP Host Header and no HTTP/2 to origin. Then
    apply the Cloudflare settings that keep the throttle working. See
    [Publishing the owner UI](deployment.md#publishing-the-owner-ui),
    steps 3–4.
12. **Required. Add the `/connector` rate-limit rule**, Free or Pro form.
    See
    [Per-customer deploy checklist](deployment.md#per-customer-deploy-checklist-the-connector-rate-limit-required-223).
    It's verified in step 16.

    **Optional.**
    - The WAF rules and the `/mcp` rate limit: see
      [Optional: WAF and the `/mcp` rate limit](deployment.md#optional-waf-and-the-mcp-rate-limit).
    - Cloudflare Access in front of the owner hostname, including the
      ntfy bypass application (step 5 there) and, with `[oauth]`, the
      OAuth bypass (step 6 there): see
      [Optional: Cloudflare Access in front](deployment.md#optional-cloudflare-access-in-front).
      Then add `[owner_ui.access]` to the config.

## 7. Start, enrol, unlock

13. **Required. Start the stack** (operator): `COMPOSE_PROFILES=edge` in
    `.env`, then `docker compose up -d`. See
    [first run, step 4](first-run.md#4-start-kharond-and-enroll-your-passkey)
    and [What the example sets](../deploy/compose/README.md#what-the-example-sets).
    The startup lines should say public mode for the owner UI and
    `POST /mcp and GET /connector` for public ingress. Restart the whole
    stack, never the `holder` alone.
14. **Required. Enrol the customer's passkey** (customer and operator
    together). The customer opens `/enroll` first. The operator runs
    `docker compose exec kharon kharon passkey-enroll` and sends the
    43-character code as a message the customer can paste from. It
    works once, for 120 seconds. Then check the owner UI answers `200`.
    See [first run, step 4](first-run.md#4-start-kharond-and-enroll-your-passkey)
    and [Publishing the owner UI](deployment.md#publishing-the-owner-ui),
    steps 5–6.
15. **Required. Unlock** (customer, from a bookmark of the owner
    hostname). See [first run, step 6](first-run.md#6-unlock) and
    [Unlocking from the browser](deployment.md#unlocking-from-the-browser).
    After every restart and idle lock the broker is `locked`. That is
    its normal resting state, not a fault.

## 8. Verify the edge

16. **Required. Run the checks** (operator, from outside the broker
    host; the zone admin fixes anything Cloudflare-side that fails):
    - [`deploy/checks/edge-checks.sh`](../deploy/checks/edge-checks.sh),
      as in [Acceptance checks, Edge](acceptance-checks.md#1-edge):
      every other path is `404` at the edge, and `POST /mcp` without a
      token is `401`.
    - [Checks on the first live deploy](deployment.md#checks-on-the-first-live-deploy):
      the owner UI's Host check and Access.
    - The `/connector` burst check in the
      [rate-limit checklist](deployment.md#per-customer-deploy-checklist-the-connector-rate-limit-required-223).
    - `kharon status` shows no growing
      `requests without a usable CF-Connecting-IP` counter. See
      [Watching it](deployment.md#watching-it).

## 9. Agent host

17. **Required. Apply the agent-host bundle** (operator hands it over;
    agent host applies it). The bundle setup wrote in step 7 holds the
    tunnel credential, the agent token, `connector.toml`, the pin and
    `apply.sh`. Move it to the agent host out of band, compare
    `broker-pin` with the `broker_pin` setup printed, and run
    `sudo ./apply.sh path/to/kharon-agent-connector` there (or
    `provision-connector.sh` fed from the bundle on a bare Debian
    host). Expect `agent connector attached: … transport=ws` in
    kharond's log. Delete every copy of the bundle afterwards. See
    [first run, step 5](first-run.md#5-apply-the-agent-host-bundle).
    For hosted or root agent runtimes that can't run `apply.sh`, and
    for handing secrets to a runtime you have no shell on, see
    [Agent side: hosted and root runtimes](agent-runtime-setup.md).
18. **Required. Point the agent's MCP client at the gateway** (agent
    host): `POST https://kharon.example.com/mcp`, with the bundle's
    `agent-api-token` as a bearer token. Apply the
    [agent harness policy](deployment.md#agent-harness-policy-spec-oq-3),
    and see [Running the agent](deployment.md#running-the-agent) for
    the idle lock and `kharon_context` after an unlock. A worked client
    config is in [MCP client](deployment.md#mcp-client). The tool
    schemas are [`docs/api/mcp-tools.json`](api/mcp-tools.json).

## 10. Dashboard Connect (optional, with `[oauth]`)

19. **Optional.**
    - The dashboard's operator publishes its client metadata document,
      and its URL is listed in `[oauth] clients` (step 7).
    - The customer clicks Connect in the dashboard and approves on the
      owner hostname with the passkey.
    - The Connect then appears on the Connections page.

    See [OAuth discovery and Connect endpoints](deployment.md#oauth-discovery-and-connect-endpoints-n3)
    and [Connections, Disconnect and panic](deployment.md#connections-disconnect-and-panic-n3-233).
    A Connect authorizes `/mcp` only. A hosted dashboard runtime that
    fills still uses a connector from the setup bundle (steps 7 and
    17) until #235.

## 11. Acceptance

20. **Required. Run `kharon doctor`** (operator):
    `docker compose exec kharon kharon doctor`. All six checks pass:
    files, key type, sync visibility, audit sink, passkey, agent
    attached. See
    [first run, step 7](first-run.md#7-check-it-with-kharon-doctor-then-do-a-first-fill).
21. **Required. Do one real fill end to end** (agent host and customer):
    the agent asks for a grant, the customer approves on the owner UI
    (or through ntfy, step 6), and the fill lands in the agent host's
    browser through the connector. Then run the canary sweep and the
    filesystem check against REQ-GOAL-002 (SPEC §1) (agent host, with
    the operator). The procedure is
    [Acceptance checks](acceptance-checks.md), sections 2–4. *Never
    paste a canary value into chat, a command line or an agent's
    context.*
22. **Required. Verify the audit chain** against the saved ntfy
    checkpoint stream (whoever keeps it, step 6, hands the saved file
    to the operator, who runs this on the broker):
    `kharon audit verify --data /data/audit --checkpoints <file>`.
    See [Audit checkpoints off-host](deployment.md#audit-checkpoints-off-host-req-aud-002)
    and the [compose README](../deploy/compose/README.md#owner-web-ui).

## 12. Hand over

23. **Required. Walk the customer through it** (operator, with the customer):
    - Bookmark the owner hostname, and save a Bitwarden login item for it
      with URI match **Host**. See
      [Unlocking from the browser](deployment.md#unlocking-from-the-browser).
    - Open the Passkeys page together and confirm it lists only the
      customer's own passkey. On a managed deploy the operator can
      enrol a passkey too, and the audit log records it on `web_ui`
      just like the customer's own (#249), so this page is the
      customer's real check.
    - What panic does, including that it ends every Connect. See
      [Connections, Disconnect and panic](deployment.md#connections-disconnect-and-panic-n3-233).
    - What to do with a lost passkey or after being throttled. See
      [A lost passkey](deployment.md#a-lost-passkey) and
      [The throttle, and getting back in](deployment.md#the-throttle-and-getting-back-in).
24. **Required. Set up alerts, backup and rotation** (operator). The
    alerts are the connector outage line, the `CF-Connecting-IP`
    counter and the checkpoint subscriber; the list is
    [Alerts](broker-lifecycle.md#alerts). Backup and restore of `/data`,
    upgrades, and the secrets inventory are in
    [Data backup, restore and upgrade](broker-lifecycle.md#data-backup-restore-and-upgrade)
    and [Secrets inventory](broker-lifecycle.md#secrets-inventory).

To take the deploy off the internet again, see
[Rollback](deployment.md#rollback).
