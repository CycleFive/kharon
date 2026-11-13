# Managed deploy runbook: one customer, end to end

This is the order for standing up one managed, single-tenant kharon
deploy: one broker, one customer vault, one gateway hostname and one
owner hostname, with the agent connecting over WebSocket through the
tunnel (path B, no VPN). Each step points at the section of the
[deployment guide](deployment.md) or the
[compose README](../deploy/compose/README.md) that holds the detail.
This page doesn't repeat that detail. Where the guide doesn't cover a
step yet, the step says so and names the issue tracking it.

Work from a tagged release, not a branch.

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
  The operator hands it the agent token, the tunnel credential and the
  pin out of band.

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
3. **Required. Build the image** (operator): `docker compose build kharon`
   in `deploy/compose`. See the
   [compose README, Run it](../deploy/compose/README.md#run-it).

## 3. The customer's vault

4. **Required. Generate the kharon account's master password** (customer,
   on their own machine, with `kharon init`). Whoever runs `init` sees
   the password. See
   [The kharon account and its master password](deployment.md#the-kharon-account-and-its-master-password-req-dep-007),
   step 1.
5. **Required. Create the account, organization, collection and API key**
   (customer). See steps 2–4 of the same section. The customer then
   moves the logins kharon may fill into that collection. *Detail on the
   Bitwarden side (org setup, moving items, where the IDs and the API
   key are) is tracked in #293.*
6. **Required. Hand over the API key file, the account email, and the
   organization and collection IDs** (customer to operator), out of band:
   never in a shared channel. The master password is never handed over.
7. **Required. Install the API key file** as
   `deploy/compose/secrets/kharon_bw_api_key.json`, owned by uid 10001,
   mode `0400` (operator). See step 4 of
   [the kharon account](deployment.md#the-kharon-account-and-its-master-password-req-dep-007)
   and the [compose README](../deploy/compose/README.md#run-it).

## 4. Agent identity and connector key

8. **Required. Mint the agent token** (operator, in an interactive
   terminal): `kharon token mint <id>`. The hash goes in the config. The
   token goes only to the agent's own secret store. See
   [Agent tokens](deployment.md#agent-tokens-req-api-003).
9. **Required. Mint the tunnel credential** (operator):
   `kharon tunnel mint <id>`. Its hash goes in the config as
   `connector_token_hash`, and the credential goes only to the agent
   host's connector. See
   [Path (B) broker](deployment.md#path-b-broker-agent-connector).
10. **Required. Make the `[connector]` certificate and key, mount them,
    and compute `BROKER_PIN`** (operator). Mount read-only, with the key
    owned by uid 10001 at mode `0400`, through `docker-compose.override.yml`.
    `BROKER_PIN` is the SHA-256 of the certificate's DER. See
    [Path (B) broker](deployment.md#path-b-broker-agent-connector) and
    [Over WebSocket](deployment.md#over-websocket-through-the-public-gateway-199).

## 5. ntfy and kharond config

11. **Required. Set up the ntfy topic before the first start** (operator,
    with the customer). The topic carries approval prompts and the
    off-host audit checkpoints, and kharond starts pushing checkpoints
    the moment it starts:
    - Create the private topic's users on the ntfy server: a
      write-only user whose token goes in kharond's `token_file`
      (step 12), and a read-only user for each subscriber. The
      checkpoint keeper uses its user's token; the phone signs in with
      its user. Never reuse kharond's write token for a subscriber.
    - Name who keeps the checkpoint stream. On a managed deploy that is
      the operator, unless the customer chooses to keep it. Start saving
      it off the broker host (a subscriber on another machine, or the ntfy
      server's own retention) before step 19, so the stream step 27
      verifies is complete from the first checkpoint.
    - If approvals go through ntfy, the customer subscribes to the topic
      in the ntfy app on their phone and signs in as their read-only
      user (username and password).

    See [Setting up the ntfy topic](deployment.md#setting-up-the-ntfy-topic)
    for the tokens, the subscriber and the phone. Background:
    [Audit checkpoints off-host](deployment.md#audit-checkpoints-off-host-req-aud-002)
    and [ntfy approve and deny](deployment.md#ntfy-approve-and-deny-req-apr-004-req-dep-006).
12. **Required. Write `kharon.toml`** from
    [`kharon.toml.example`](../deploy/compose/kharon.toml.example)
    (operator). It needs:
    - **`[bitwarden]`:** server, email, API key file, org and collection IDs.
    - **`[agents.<id>]`:** `token_hash`, `connector_token_hash`, and
      `cdp = { endpoint = "ws://127.0.0.1:9222", via = "agent_connector" }`.
    - **`[connector]`:** `websocket = true` and the TLS files, with no `listen`.
    - **`[public_ingress]`:** `listen = "127.0.0.1:8790"` and **`public_host`** (required when published). See
      [the `[public_ingress]` listener](deployment.md#kharond-the-public_ingress-listener).
    - **`[approval].ntfy`:** with `token_file` holding the write token from step 11. See
      [Audit checkpoints off-host](deployment.md#audit-checkpoints-off-host-req-aud-002)
      and [ntfy approve and deny](deployment.md#ntfy-approve-and-deny-req-apr-004-req-dep-006).
    - **`[owner_ui]`:** `listen = "127.0.0.1:8788"` and
      `public_origin = "https://kharon-owner.example.com"`. See
      [Publishing the owner UI](deployment.md#publishing-the-owner-ui), steps 1–2.
    - **Optional, `[oauth] clients`:** for dashboard Connect. See
      [OAuth discovery and Connect endpoints](deployment.md#oauth-discovery-and-connect-endpoints-n3).
    - **Optional, `[owner_ui.access]`:** only after the Access application
      exists (step 18).
13. **Required. Check it** (operator):
    `docker compose run --rm kharon --check --config /etc/kharon.toml`
    (the example's header). kharond refuses unsafe combinations by name.

## 6. Cloudflare (zone admin)

14. **Required. Create the tunnel and the gateway routes**: `^/mcp$` and
    `^/connector$` to `http://127.0.0.1:8790`, and a 404 catch-all. With
    `[oauth]`, also the two `.well-known/oauth-protected-resource` routes.
    The dashboard creates the proxied DNS record. See
    [Creating the tunnel (owner)](deployment.md#creating-the-tunnel-owner).
15. **Required. Put the tunnel token in place** (zone admin to operator,
    never echoed or in argv): `secrets/cloudflared_tunnel_token`, owned
    by `65532:65532`, mode `0400`. See
    [Creating the tunnel](deployment.md#creating-the-tunnel-owner) and
    the [compose README](../deploy/compose/README.md#run-it).
16. **Required. Add the owner hostname route** to `http://127.0.0.1:8788`,
    with an empty path, no HTTP Host Header and no HTTP/2 to origin. Then
    apply the Cloudflare settings that keep the throttle working. See
    [Publishing the owner UI](deployment.md#publishing-the-owner-ui),
    steps 3–4.
17. **Required. Add the `/connector` rate-limit rule**, Free or Pro form.
    See
    [Per-customer deploy checklist](deployment.md#per-customer-deploy-checklist-the-connector-rate-limit-required-223).
    It's verified in step 22.
18. **Optional.**
    - The WAF rules and the `/mcp` rate limit: see
      [Optional: WAF and the `/mcp` rate limit](deployment.md#optional-waf-and-the-mcp-rate-limit).
    - Cloudflare Access in front of the owner hostname, including the
      ntfy bypass application (step 5 there) and, with `[oauth]`, the
      OAuth bypass (step 6 there): see
      [Optional: Cloudflare Access in front](deployment.md#optional-cloudflare-access-in-front).
      Then add `[owner_ui.access]` to the config.

## 7. Start, enrol, unlock

19. **Required. Start the stack** (operator): `COMPOSE_PROFILES=edge` in
    `.env`, then `docker compose up -d`. See
    [Running it](deployment.md#running-it) and
    [What the example sets](../deploy/compose/README.md#what-the-example-sets).
    The startup lines should say public mode for the owner UI and
    `POST /mcp and GET /connector` for public ingress. Restart the whole
    stack, never the `holder` alone.
20. **Required. Enrol the customer's passkey** (customer and operator
    together). The customer opens `/enroll` first. The operator runs
    `kharon passkey-enroll` and sends the 43-character code as a
    message the customer can paste from. It works once, for 120 seconds.
    Then check the owner UI answers `200`. See
    [Publishing the owner UI](deployment.md#publishing-the-owner-ui),
    steps 5–6.
21. **Required. Unlock** (customer, from a bookmark of the owner
    hostname). See
    [Unlocking from the browser](deployment.md#unlocking-from-the-browser).
    After every restart and idle lock the broker is `locked`. That is
    its normal resting state, not a fault.

## 8. Verify the edge

22. **Required. Run the checks** (operator, from outside the broker
    host; the zone admin fixes anything Cloudflare-side that fails):
    - [Verifying](deployment.md#verifying): every other path is `404`
      at the edge, and `POST /mcp` without a token is `401`.
    - [Checks on the first live deploy](deployment.md#checks-on-the-first-live-deploy):
      the owner UI's Host check and Access.
    - The `/connector` burst check in the
      [rate-limit checklist](deployment.md#per-customer-deploy-checklist-the-connector-rate-limit-required-223).
    - `kharon status` shows no growing
      `requests without a usable CF-Connecting-IP` counter. See
      [Watching it](deployment.md#watching-it).

    *A checked-in script for these is tracked in #290.*

## 9. Agent host

23. **Required. Install the connector** (agent host, with what the
    operator hands over): path B with
    `BROKER_URL=wss://kharon.example.com/connector`, the `BROKER_PIN`
    from step 10, the agent id, and the tunnel credential file from
    step 9, delivered out of band at mode `0400`. Run `--check` once with
    the service stopped, then expect `agent connector attached:
    … transport=ws` in kharond's log. See
    [Agent host](deployment.md#agent-host-req-dep-005),
    [Path (B) — agent-connector](deployment.md#path-b--agent-connector)
    and [Connector config over WebSocket](deployment.md#connector-config-over-websocket).
    For hosted or root agent runtimes that can't run
    `provision-connector.sh`, and for handing secrets to a runtime you
    have no shell on, see
    [Agent side: hosted and root runtimes](agent-runtime-setup.md).
24. **Required. Point the agent's MCP client at the gateway** (agent
    host): `POST https://kharon.example.com/mcp`, with the agent token
    from step 8 as a bearer token. Apply the
    [agent harness policy](deployment.md#agent-harness-policy-spec-oq-3),
    and see [Running the agent](deployment.md#running-the-agent) for
    the idle lock and `kharon_context` after an unlock. *A worked client
    config example is tracked in #293.*

## 10. Dashboard Connect (optional, with `[oauth]`)

25. **Optional.**
    - The dashboard's operator publishes its client metadata document,
      and its URL is listed in `[oauth] clients` (step 12).
    - The customer clicks Connect in the dashboard and approves on the
      owner hostname with the passkey.
    - The Connect then appears on the Connections page.

    See [OAuth discovery and Connect endpoints](deployment.md#oauth-discovery-and-connect-endpoints-n3)
    and [Connections, Disconnect and panic](deployment.md#connections-disconnect-and-panic-n3-233).
    A Connect authorizes `/mcp` only. A hosted dashboard runtime that
    fills still uses a hand-provisioned connector (steps 8–10 and 23)
    until #235.

## 11. Acceptance

26. **Required. Do one real fill end to end** (agent host and customer):
    the agent asks for a grant, the customer approves on the owner UI
    (or through ntfy, step 11), and the fill lands in the agent host's
    browser through the connector. Then run the canary sweep and the
    filesystem check against REQ-GOAL-002 (SPEC §1) (agent host, with
    the operator). *The live procedure, as #201 ran it, isn't in the repo
    yet; it's tracked in #290. Never paste a canary value into chat, a
    command line or an agent's context.*
27. **Required. Verify the audit chain** against the saved ntfy
    checkpoint stream (whoever keeps it, step 11, hands the saved file
    to the operator, who runs this on the broker):
    `kharon audit verify --data /data/audit --checkpoints <file>`.
    See [Audit checkpoints off-host](deployment.md#audit-checkpoints-off-host-req-aud-002)
    and the [compose README](../deploy/compose/README.md#owner-web-ui).

## 12. Hand over

28. **Required. Walk the customer through it** (operator, with the customer):
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
29. **Required. Set up alerts, backup and rotation** (operator). The
    alerts are the connector outage line, the `CF-Connecting-IP`
    counter and the checkpoint subscriber; the list is
    [Alerts](broker-lifecycle.md#alerts). Backup and restore of `/data`,
    upgrades, and the secrets inventory are in
    [Data backup, restore and upgrade](broker-lifecycle.md#data-backup-restore-and-upgrade)
    and [Secrets inventory](broker-lifecycle.md#secrets-inventory).

To take the deploy off the internet again, see
[Rollback](deployment.md#rollback).
