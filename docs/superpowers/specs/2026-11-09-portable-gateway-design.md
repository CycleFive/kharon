# Portable gateway: one kharon package, reachable only through Cloudflare

Status: design, 2026-11-09. Owner decisions from a conversation with Lothrop
the same day. Amends the decision record on #197. Builder: Duet.

## Why

#197 put kharon on the internet for hosted MCP clients that cannot join a
tailnet: a Cloudflare Tunnel publishes `POST /mcp` (and, with #199,
`/connector`) at `kharon.twkr.io`. The first deployment of that idea leaned on
Tailscale everywhere. cloudflared was to run in its own guest *on the tailnet*,
reaching kharond's tailnet address, and the owner UI, vault and raw CDP "stay
on the tailnet". Tailscale was meant as a quick shim to get one test running.
It turned into tags, ACL rules and per-port firewall pins, and it ties the
broker to one network.

The owner wants kharon packaged so it can be **dropped on any machine with
outbound internet**: his Proxmox, a cloud VM, a VPS. It must be reachable from
the internet **only through Cloudflare**, and must need **no VPN** in the
base case.

The same package must serve two deployments:

| | Hosted service (in theory, later) | Self-hosted (the owner's case today) |
|---|---|---|
| Who runs the box | us, for a customer | the owner, on his own hardware |
| Vault | the customer's **Bitwarden cloud** account | a **self-hosted Vaultwarden**: bundled in the package, or reached over HTTPS |
| Who approves grants | the customer, from wherever they are | the owner, from wherever he is |

Both already differ only in config for the vault (`[bitwarden] server`).
Bitwarden-cloud compatibility is tested nightly (REQ-DEP-004, `COMPAT.md`).
What does *not* work for either today is owner access without a VPN or SSH.
That is the gap this design closes.

## Goals

1. **One package.** kharond and its Cloudflare connection start together, and
   optionally a bundled Vaultwarden too. They run anywhere with outbound
   internet: no inbound ports, no VPN, no static IP.
2. **Only Cloudflare reaches it.** Every kharond listener binds loopback (or a
   unix socket). cloudflared is the only thing that can reach them, and it
   only dials out.
3. **The owner UI works from anywhere.** Unlock, approvals, grants, audit tail
   and panic (all built under #131) are reachable on their own public
   hostname, behind the owner's **passkey**.
4. **VPNs are optional add-ons.** WireGuard (path A) and Tailscale stay
   supported for people who want them (a private vault, a private agent host),
   but nothing requires them.

## Non-goals

- A multi-customer broker. **One broker per owner**: the hosted service would
  run one package per customer (*Duet's call*).
- Automating per-customer provisioning (tunnels, hostnames, Access apps).
- First-class Tailscale packaging. Wanted eventually; not in this work.
- Changes to vault sync, crypto or the fill path.
- Cloudflare-side WAF and rate-limit rules. They stay optional suggestions,
  as in `docs/deployment.md` today.

## Anti-goals (failure even if it "works")

- Anything in the base case that needs a VPN, an inbound port, or a
  non-loopback kharond listener.
- An owner UI reachable without the passkey, or a password-only route
  (REQ-APR-005 stands).
- Any secret on the `/mcp` path (#197's threat model stands).
- **Cloudflare Access being required.** It is a recommended extra, not a
  dependency.
- A tunnel token in the repo, an image, a log or argv.

## Decisions

**Owner (Lothrop), 2026-11-09:**

1. kharond and cloudflared run **together, wherever the broker runs**, not in
   a separate guest on the owner's Proxmox (amends #197).
2. The base case needs **no Tailscale/WireGuard**. Supporting Tailscale as an
   option is welcome and expected later.
3. The broker's one real outside dependency is the vault: Bitwarden cloud, or
   self-hosted Vaultwarden.
4. The **owner UI is published** on its own hostname through the same tunnel
   (reverses #197's "owner UI never published; stays on the tailnet").
5. **Passkey required; Cloudflare Access optional**, recommended for
   self-hosters.
6. The package and docs live in this repo; our own infra specifics may appear
   here (as `kharon.twkr.io` already does). Duet builds it through the normal
   issue/claim/review process.
7. **The owner UI is published *or* local, one at a time, chosen in config.**
   A passkey is bound to one RP ID, so the web UI works either at the public
   hostname or at `localhost` (over an SSH forward), not both. There's no
   dual-RP-ID support.
   - **The CLI is the fallback** (`kharon` over the owner socket, via SSH or
     `docker compose exec`). It already covers unlock, grants, approve, deny
     and panic.
   - Switching modes means re-enrolling the passkey once (`kharon
     passkey-enroll`).
   - A self-hoster without a domain stays in local mode, as today.
   - Credentials enrolled under the old RP ID simply stop verifying. Whether
     the CLI also offers a purge is the builder's call.

**Duet's calls (check these):**

- **cloudflared shares kharond's network namespace** in compose
  (`network_mode: "service:kharon"`). kharond's listeners stay on `127.0.0.1`,
  so REQ-DEP-006's "owner API binds to loopback" stays literally true. Only
  kharond and cloudflared can reach those listeners: the bundled Vaultwarden
  cannot, being in its own namespace. That placement is also #200's trust root
  for `CF-Connecting-IP`.
  On a host-networked deployment (VM 125 today) every process on the host
  shares that loopback. Acceptable on a single-purpose host, and the docs say
  so.
- **The tunnel is set up from a token** (dashboard-managed, `--token-file`),
  which is the easiest thing for anyone to do and how the live `kharon` tunnel
  already works. Consequence: the edge allow-list lives in the Cloudflare
  dashboard, and kharond's own allow-list is the line that holds. The
  locally-managed `deploy/cloudflared/config.yml` stays as a documented
  alternative.
- **The owner UI gets its own hostname**, not a path on `kharon.twkr.io`, so
  Access can guard it without ever touching `/mcp` clients. It is one label
  deep, because Cloudflare Universal SSL covers only `*.twkr.io`: ours is
  **`kharon-owner.twkr.io`**.
- **The bundled Vaultwarden becomes a compose profile.** The Bitwarden-cloud
  case doesn't need it.
- **cloudflared is a compose profile too (`edge`)**, and the README's default
  run command turns it on (`COMPOSE_PROFILES=edge`). With the profile on and
  no token file, `docker compose up` fails loudly; that's intended. Without
  the profile the stack runs as it does today, which covers VPN-only users
  and CI. The example `kharon.toml` ships `[public_ingress]` on
  `127.0.0.1:8790`, which is safe because only the edge shares that loopback.
  It ships `[owner_ui]` in **local mode** (`rp_id = "localhost"`), so
  publishing the owner UI is a deliberate step.
- **Proof without a real tunnel:** the CI E2E overlay adds a **fake-edge**
  container in kharond's network namespace. It sends `Host`,
  `CF-Connecting-IP` and (for the optional check) a test-signed
  `Cf-Access-Jwt-Assertion` to the loopback listeners. That proves the origin,
  source-address, cookie and Access-check work in CI. The live proof is our
  instance and #201.
- **A configured public origin is the owner UI's "behind the edge" switch.**
  Only then is `CF-Connecting-IP` honoured on owner-UI requests. In local mode
  it is ignored, because an SSH forward or local process is the peer.
  Residual risk: on a host-networked box, another local process could spoof
  the header. That only touches audit source and throttle keys, never auth,
  and is accepted for single-purpose hosts (documented).
- **Throttling counts failed sign-in, enroll and unlock attempts only.**
  - Behind the edge: keyed per trusted source address.
  - In local mode: no throttle, because only loopback reaches it.
  - **Never a global bucket**, so a stranger can't lock the owner out.
  - Signed-in actions (approve, deny, panic) are never throttled.
  - The CLI over the owner socket (unlock, grants, approve, deny, panic) is
    always the recovery path.
- **N2 starts after #200 merges** and reuses its trusted-proxy helper rather
  than building a second one, so nothing conflicts with Muse's branch.
- **Who does what.** Duet does all of it:
  - the kharon-repo work, through the normal process;
  - the issue amendments: a comment on #197 carrying the owner's amendment,
    edits to #201's ACs with a comment saying why, and a comment to Muse on
    #200;
  - the homelab-side work, from the homelab repo, where each live step
    (VM 125, Cloudflare, rbw) is confirmed with the owner as it happens.

## The shape

```
            internet
               │  HTTPS (Cloudflare edge; Access optional on the owner host)
        ┌──────┴───────────────────────────────┐
 kharon.twkr.io                     kharon-owner.twkr.io
 ^/mcp$, ^/connector$ only          everything
        │                                       │
        └──────────── Cloudflare Tunnel ────────┘
                         │ outbound only
  ┌──────────────────────┼──────────── one host, any host ───────────┐
  │  cloudflared ── shares kharond's netns ──┐                       │
  │                                          ▼                       │
  │  kharond   127.0.0.1:8790 [public_ingress]  ← /mcp, /connector   │
  │            127.0.0.1:8788 [owner_ui]        ← owner hostname     │
  │            unix socket    owner CLI (docker compose exec)        │
  │            optional: [api] / [connector] on a VPN address        │
  │  vaultwarden (profile, optional) ── or ── vault.bitwarden.com    │
  └──────────────────────────────────────────────────────────────────┘
```

| Listener | Base case | Reached by |
|---|---|---|
| `[public_ingress]` | `127.0.0.1:8790`, plain HTTP (allowed on loopback since #198) | cloudflared, for `kharon.twkr.io` `^/mcp$` / `^/connector$` |
| `[owner_ui]` | `127.0.0.1:8788` | cloudflared, for the owner hostname |
| owner socket | unix socket in `/data` | `docker compose exec kharon kharon …` |
| `[api]`, `[connector]` | **off**, or on a VPN address when one is used | agents on a tailnet/WireGuard (optional) |

Fills need the broker to reach the agent's browser. With no VPN that is
**#199** (`/connector` over WebSocket). Until #199 lands, the base case
supports MCP calls, grants and approvals, but fills still ride a VPN path.

## What has to change

### Works as-is

- `[public_ingress]` (#198, merged): loopback without TLS is already allowed.
- #195, #196: unrelated audit fixes. #196 matters more now that panic is one
  tap on a phone.
- #132 (durable revoke): unchanged scope, but `/mcp` tokens become
  internet-reachable, so it should move up. Suggest to Nyx.

### Critical path

- **#199**: unchanged; it is what makes "no VPN" true for fills.

### Changes to existing issues and docs (wording and ACs)

- **#197**: append an amendment to the decision record carrying the owner
  decisions above. Add a threat-model note:
  - Cloudflare now sees owner-UI traffic (approvals, grants list, audit tail).
  - The master password still never crosses in the clear: web unlock seals
    it in the page (#194).
  - An active intermediary serving a tampered page is a risk the owner has
    accepted, the same trust already placed in Cloudflare's TLS.

  Add the new issues to the checklist.
- **#200** (Muse, in progress): name the trust root as *placement* (only
  cloudflared shares the listener's loopback), not only "the public listener".
  Owner-UI exposure is **not** folded in; it gets its own issue (below).
  Coordinate on a comment, not by editing Muse's branch.
- **#201**: replace "approved in the owner UI (tailnet only)" with *approved
  through the owner hostname*. Replace "Owner UI … unreachable from the public
  hostname" with *owner UI reachable only on its own hostname and only after
  the passkey; vault and raw CDP unreachable*. Add: *the run uses a host with
  no VPN*.
- **`docs/deployment.md` › Public gateway**: the default becomes "cloudflared
  beside kharond, from a tunnel token". The tailnet/separate-guest setup and
  the locally-managed config become alternatives. Owner-UI publishing and the
  optional Access setup are documented here.
- **SPEC.md** (needs both non-author agents):
  - B4 (owner ↔ broker) and the threat model: the owner UI may be published
    behind the edge.
  - REQ-DEP-006: public listeners are reachable only by the edge, by
    placement.
  - REQ-APR-005: ACs for public exposure (below).

  Requirement numbering is the builder's call.

### New work

**N1: the portable compose package.**
- `deploy/compose` gains cloudflared (netns sidecar, profile `edge`) and puts
  Vaultwarden under a profile. The README's default run turns `edge` on.
- WireGuard (the `wg` network) and a VPN-shaped `[api]`/`[connector]` move to
  an optional overlay.
- The tunnel token is a compose secret file under `secrets/` (git-ignored).
- The CI compose E2E (REQ-DEP-002) keeps passing. Its overlay keeps the agent
  host and fixture vault as today, and adds the fake-edge container.

**N2: the owner UI behind the edge.**
1. **Public origin.** `canonical_origin` (`config/raw.rs`) requires the origin
   port to equal the listen port, which assumes the browser talks to the
   listener directly. Behind the edge the origin is
   `https://kharon-owner.twkr.io` (443) while the listener is `:8788`. Add a
   way to declare the public origin; the config shape is the builder's call.
   Origin and Host checks (`gate_owner_post`) use it.
2. **Source address.** Honour `CF-Connecting-IP` for owner-UI requests only
   when a public origin is configured, reusing #200's trusted-proxy helper.
   Owner auth failures are audited with it.
3. **Throttling.** Failed sign-in, enroll, unlock-begin and unlock attempts
   only, per trusted source address. There is no global bucket, signed-in
   actions are exempt, and local mode has no throttle (see Duet's calls).
4. **Cookies.** `Secure`, and the `__Host-` prefix, when the public origin is
   https.
5. **Optional Access check.** When configured (team domain + audience),
   kharond verifies the `Cf-Access-Jwt-Assertion` header as a second line.
   Off by default.
6. **ntfy approve/deny** (REQ-APR-004, #128). The action URL must use the
   public origin. With Access on, Access blocks ntfy's background POSTs. The
   docs give an Access **bypass** for `/owner/approve/*` and `/owner/deny/*`,
   which their single-use, 120-second tokens already protect. That's Duet's
   call; the alternative is notifications that open the page instead.

## Our instance (homelab side: Duet, from the homelab repo, each live step confirmed with the owner)

The specifics, so nobody has to rediscover them:

- **Tunnel** `kharon`, `12be3d56-e163-4d8e-8172-d67ac2b1ca59`, dashboard-managed,
  made by Nyx 2026-11-09. Routes become:
  - `kharon.twkr.io` `^/mcp$` and `^/connector$` → `http://localhost:8790`
  - `kharon-owner.twkr.io` → `http://localhost:8788`
  - everything else → 404

  The current routes point at `https://100.120.48.90:8790` with a pinned CA;
  drop that.
- **The token** comes from `cloudflared tunnel token kharon` on the
  workstation (`~/.cloudflared/cert.pem` is for this account). It goes into a
  new rbw item and onto VM 125 as a 0400 file, never printed.
- **VM 125**:
  - rebuild `kharon:local` from a master that includes #203/#204 (the running
    build, `7d12a77`, refuses `[public_ingress]` because unknown keys are
    rejected);
  - add the cloudflared sidecar (host network there);
  - set `[public_ingress] listen = "127.0.0.1:8790"`;
  - after N2: `[owner_ui]` with the public origin, then **re-enroll the
    passkey**, because the RP ID changes from `localhost`.
- **DNS**: `kharon.twkr.io` exists (Nyx, proxied CNAME) but is not in
  `dns/records.json`, so add it there. Add `kharon-owner.twkr.io` the same way.
  `./homelab.sh dns` can write `twkr.io`.
- **Access**: an app on `kharon-owner.twkr.io`, one-time PIN to the owner's
  email (as on the bots' `-admin` hosts), plus the approve/deny bypass if ntfy
  is turned on (the pilot runs without ntfy).
- **Monitoring**: add `kharon` to the tunnel collector's `EXPECTED` (1
  connector). Its `CloudflareTunnelUnlisted` warning has been firing since
  2026-11-09 12:20Z.
- **Tailnet**: keep `tag:kharon-agent → tag:kharon-broker:8787,8789` until
  #199 is live for Muse's runtime, then retire it. **Nyx's plan for a separate
  guest on the tailnet, a new tag and a `:8790` firewall pin is dropped.**

## Order of work

1. **First task of this work, no new kharon code:** do the VM 125 steps up to
   `[public_ingress]` and reroute the tunnel. Nyx's checks (`POST /mcp` with no token → 401;
   `GET /mcp`, `/`, `/ui`, `/v1/*` → 404) then pass, and Muse can run the grant
   and fill test. MCP goes through `kharon.twkr.io`. The connector stays on the
   tailnet, and approval stays on the owner UI over SSH, as today.
2. **N1 + the doc/#197/#201 amendments.**
3. **N2**, then publish `kharon-owner.twkr.io` (+ Access) for our instance.
4. **#199 lands**: our instance drops the tailnet. #201 runs on a host with no
   VPN, which proves the package is portable.

## Left to the builder

The config key names for the public origin and Access check, the compose
profile and overlay names, and the SPEC requirement numbers. Also the exact
rate-limit values, the cloudflared version pin (the estate runs `2026.10.4`),
and whether `[api]` stays loopback-only or is simply omitted in the base case
(it is optional in config today).
