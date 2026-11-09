# Portable gateway: one kharon package, reachable only through Cloudflare

Status: design, 2026-11-09. Owner decisions from a conversation with Lothrop
the same day. Amends the decision record on #197. Builder: Duet. Reviewed by
Nyx and Muse on #206; their points are folded in and credited where they
land.

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
outbound internet**: their Proxmox, a cloud VM, a VPS. It must be reachable from
the internet **only through Cloudflare**, and must need **no VPN** in the
base case.

The same package must serve two deployments:

| | Hosted service (in theory, later) | Self-hosted (the owner's case today) |
|---|---|---|
| Who runs the box | us, for a customer | the owner, on their own hardware |
| Vault | the customer's **Bitwarden cloud** account | a **self-hosted Vaultwarden**: bundled in the package, or reached over HTTPS |
| Who approves grants | the customer, from wherever they are | the owner, from wherever they are |

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
   - **Switch only with the CLI in hand** (SSH, or a console on the host;
     Muse's review). The old passkey stops verifying at once, with no grace
     period, and re-enrolling needs the owner socket. An owner who switches
     while away has no web UI until they can reach the host.
   - A self-hoster without a domain stays in local mode, as today.
   - Credentials enrolled under the old RP ID simply stop verifying. Whether
     the CLI also offers a purge is the builder's call.

**Duet's calls (check these):**

- **kharond and cloudflared share one network namespace** in compose. A tiny
  holder container that does nothing (a pinned pause-style image) owns it, and
  both join it with `network_mode: "service:<holder>"`. kharond's listeners
  stay on `127.0.0.1`, so REQ-DEP-006's "owner API binds to loopback" stays
  literally true. Only what runs in that namespace can reach those listeners:
  the bundled Vaultwarden cannot, being in its own. That placement is also
  #200's trust root for `CF-Connecting-IP`.
  - **Why a holder, not `network_mode: "service:kharon"`** (Nyx's review,
    measured 2026-11-09 with two alpine containers). A container that joins
    another's namespace keeps the *old* namespace when the other one restarts.
    One plain `docker restart` of the parent left the joiner with nothing but
    a dead `lo`, and it stayed cut off until it was restarted too. So a
    kharond crash, recovered by its restart policy, would have taken the
    tunnel down silently. With both joined to a holder, the listener stayed
    reachable across a kharond restart *and* a recreate.
  - On a host-networked deployment (VM 125 today) there is no holder: both
    use the host's namespace, which never goes away. Every process on the
    host shares that loopback. Acceptable on a single-purpose host, and the
    docs say so.
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
  container in the shared network namespace. It sends `Host`,
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
  - **The trusted-proxy helper's contract** (Muse's review), for #200 and N2
    alike: an address taken from `CF-Connecting-IP` may key throttling and
    appear in audit. It must **never** gate auth or any decision next to it:
    no allow-list, no exemption from the passkey or a token, no choice of
    mode. That contract is what makes the residual risk above acceptable, so
    the helper's doc comment and the SPEC say it in so many words.
- **Throttling counts failed sign-in, enroll and unlock attempts only.**
  - Behind the edge: keyed per trusted source address. That means per
    address for IPv4 and per **/64** for IPv6 (Nyx's review), so hopping
    addresses inside one allocation doesn't reset it.
  - The throttle table is bounded. When it's full it forgets the oldest
    stranger's count, which can't lock anyone out.
  - In local mode: no throttle, because only loopback reaches it.
  - **Never a global bucket**, so a stranger can't lock the owner out.
  - Signed-in actions (approve, deny, panic) are never throttled.
  - The CLI over the owner socket (unlock, grants, approve, deny, panic) is
    always the recovery path.
  - A failed-attempt throttle can't cover ceremony *creation*, which never
    fails. That lockout is closed separately (N2 item 5).
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
  │  holder (owns the shared netns) ◄── cloudflared, kharond join it │
  │  cloudflared ── 127.0.0.1 ───────────────┐                       │
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
  internet-reachable, so it moves up. Nyx and Muse agreed in review: it goes
  next after #200, ahead of the rest of the #30 queue.

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
  - That risk has two halves (Muse's review). Sealed unlock protects the
    password and WebAuthn's origin binding protects the passkey. But a
    tampered page *at the real origin* can still mislead the owner into
    approving or denying a real request: deceptive grant text, a fake panic
    state. Name both halves, so REQ-APR-005's ACs inherit the right threat.

  Add the new issues to the checklist.
- **#200** (Muse, in progress): name the trust root as *placement* (only
  cloudflared shares the listener's loopback), not only "the public listener".
  Owner-UI exposure is **not** folded in; it gets its own issue (below).
  Coordinate on a comment, not by editing Muse's branch. Muse agreed in
  review: #200's rule will read "`CF-Connecting-IP` is honoured only on the
  `[public_ingress]` listener, whose loopback cloudflared shares by
  placement", and #200's text states the host-networked residual.
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
- `deploy/compose` gains the netns holder and cloudflared (profile `edge`),
  with kharond joining the holder, and puts Vaultwarden under a profile. The
  README's default run turns `edge` on.
- WireGuard (the `wg` network) and a VPN-shaped `[api]`/`[connector]` move to
  an optional overlay.
- The tunnel token is a compose secret file under `secrets/` (git-ignored).
- The CI compose E2E (REQ-DEP-002) keeps passing. Its overlay keeps the agent
  host and fixture vault as today, and adds the fake-edge container (joined
  to the holder).
- **The edge survives kharond restarting** (Nyx's review). The E2E restarts
  kharond (`docker compose restart kharon`), then recreates it (`up -d
  --force-recreate kharon`), and after each the fake-edge still reaches both
  loopback listeners with nothing else touched. Then it restarts the whole
  stack and checks again.

**N2: the owner UI behind the edge.**
1. **Public origin.** `canonical_origin` (`config/raw.rs`) requires the origin
   port to equal the listen port, which assumes the browser talks to the
   listener directly. Behind the edge the origin is
   `https://kharon-owner.twkr.io` (443) while the listener is `:8788`. Add a
   way to declare the public origin; the config shape is the builder's call.
2. **Host and Origin checks, in public mode** (Nyx's review).
   - **`Host`.** Nothing checks it today (`Incoming` has no `host` field).
     Every owner-UI route, GETs included, refuses a `Host` other than the
     public host (421 or 404, the builder's call). Then a dashboard edit that
     points some other hostname at `:8788` gets a refusal, not a login page.
     With a token-managed tunnel the dashboard is the only edge allow-list,
     so this is kharond's own copy of it. The edge passes the client's `Host`
     through unless a route sets `httpHostHeader`, so `deployment.md` says
     never to set one.
   - **`[public_ingress]` gets the same `Host` check** against its own
     public host (`kharon.twkr.io` for us). It lands here, after #200, so it
     doesn't collide with Muse's branch, unless she'd rather fold it into
     #200.
   - **`Origin` on every POST.** Every POST must carry an `Origin` equal to
     the public origin. Today login, register and logout pass with *no*
     `Origin`; only the signed-in routes (`gate_owner_post`) require one.
     **Except the ntfy redeem routes** (`/owner/approve/<token>`,
     `/owner/deny/<token>`). ntfy's action POSTs carry no `Origin`, which is
     why they skip the check today (`owner_ui/mod.rs`, `serve`). Their
     single-use, 120-second tokens are what protects them.
3. **Source address.** Honour `CF-Connecting-IP` for owner-UI requests only
   when a public origin is configured, reusing #200's trusted-proxy helper
   under its contract (see Duet's calls). Owner auth failures are audited
   with it.
4. **Throttling.** Failed sign-in, enroll, unlock-begin and unlock attempts
   only, per trusted source address (per /64 for IPv6), in a bounded table.
   There is no global bucket, signed-in actions are exempt, and local mode
   has no throttle (see Duet's calls).
5. **No unauthenticated request can lock the owner out of signing in**
   (Nyx's review; must-have).
   - Today `MAX_CEREMONIES = 8` is one global table, and a new ceremony
     evicts the oldest (`owner_ui/mod.rs`). Anyone who can reach `POST
     /owner/login/options` can keep evicting the owner's challenge, so
     `login/finish` never finds it. Harmless on loopback; once published,
     it's a one-line griefing loop. The failed-attempt throttle doesn't
     cover it, because `login/options` never fails. (`register/options`
     needs an enroll token first, so a stranger's attempt there is a failed
     enroll, which the throttle does count.)
   - **The AC is the property:** no unauthenticated request, from any
     number of sources, can evict or block another client's in-flight
     ceremony. Optional Access in front would hide this, but Access isn't
     required, so kharond holds the line itself.
   - Per-source slots that refuse when *that source* is full stop one
     source. But a table with a global bound still gives way to many
     sources, and IPv6 /64s are cheap.
   - A **stateless challenge** has no table to fill. The server signs
     (challenge, kind, expiry) with a key it holds, and the client hands it
     back on finish. Only *successful* finishes are recorded, for single
     use, and a stranger can't produce one.
   - Duet leans stateless; the builder decides.
   - **Test:** the owner signs in while another source (and, for the
     stateless form, many sources) floods `login/options`.
   - Sessions and unlock attempts are fine as they are. Evicting a session
     needs a successful passkey login, and unlock sits behind a live
     session.
6. **Cookies.** `Secure`, and the `__Host-` prefix, when the public origin is
   https.
7. **Optional Access check.** When configured (team domain + audience),
   kharond verifies the `Cf-Access-Jwt-Assertion` header as a second line.
   Off by default.
   - Verify the signature against the team's JWKS, plus `aud`, `iss` (the
     team domain) and `exp` (Nyx's review). An unknown `kid` triggers one
     rate-limited JWKS refetch, so key rotation doesn't lock the owner out.
   - The CI fake-edge signs with a test key, so the JWKS source must be
     overridable. Make that impossible to set by accident in a production
     `kharon.toml`: a clearly test-named key, or a test-only build. A stray
     config line must never make the "second line" accept any signer.
   - cloudflared can check the same JWT itself (`originRequest.access`), but
     that lives in the dashboard, which is the thing this check backs up.
8. **ntfy approve/deny** (REQ-APR-004, #128). The action URL must use the
   public origin. With Access on, Access blocks ntfy's background POSTs. The
   docs give an Access **bypass** for `/owner/approve/*` and `/owner/deny/*`,
   which their single-use, 120-second tokens already protect. That's Duet's
   call; the alternative is notifications that open the page instead.

## Our instance (homelab side: Duet, from the homelab repo, each live step confirmed with the owner)

The specifics, so nobody has to rediscover them:

- **Tunnel** `kharon`, `12be3d56-e163-4d8e-8172-d67ac2b1ca59`, dashboard-managed,
  made by Nyx 2026-11-09. Routes become:
  - `kharon.twkr.io` `^/mcp$` and `^/connector$` → `http://127.0.0.1:8790`
  - `kharon-owner.twkr.io` → `http://127.0.0.1:8788`
  - everything else → 404

  `127.0.0.1`, not `localhost` (Nyx's and Muse's reviews): `localhost` can
  resolve to `::1` first, kharond binds IPv4 loopback only, and the result is
  a confusing 502 on some images. The current routes point at
  `https://100.120.48.90:8790` with a pinned CA; drop that.
- **The token.** Nyx made it with the tunnel and holds a copy out of band.
  `cloudflared tunnel token kharon` on the workstation
  (`~/.cloudflared/cert.pem` is for this account) returns the same token, so
  there is nothing to rotate, and nobody mints a second tunnel. It goes into
  a new rbw item and onto VM 125 as a 0400 file, never printed.
- **VM 125**:
  - rebuild `kharon:local` from a master that includes #203/#204 (the running
    build, `7d12a77`, refuses `[public_ingress]` because unknown keys are
    rejected);
  - add cloudflared on the host network, like kharond there, so no holder is
    needed;
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

   **This exposes `/mcp` before #200's hardening: an interim that ends when
   #200 merges** (Muse's review; Nyx, as lead, wants step 1 first; the owner
   confirms on this PR).
   - What already holds on master:
     - `POST` only, and any `Origin` is refused.
     - The bearer token is checked **before the body is read**, so a stranger
       gets a 401 without kharond reading a byte of it.
     - The body is capped at 64 KiB.
     - Per-agent rate limits apply after auth.
     - No secret rides `/mcp`.
   - What's missing until #200:
     - per-IP limits on unauthenticated attempts;
     - the JSON depth limit;
     - per-token tool allow-lists;
     - the tested redaction pass.

     Those bear on noise and on what a token holder can do, not on a
     stranger getting in.
   - If #200 slips, the owner can delete the `kharon.twkr.io` routes in the
     dashboard, which takes effect at once.
2. **N1 + the doc/#197/#201 amendments.**
3. **N2**, then publish `kharon-owner.twkr.io` (+ Access) for our instance.
4. **#199 lands**: our instance drops the tailnet. #201 runs on a host with no
   VPN, which proves the package is portable.

## Left to the builder

The config key names for the public origin, the public hosts and the Access
check, the compose profile and overlay names, and the SPEC requirement
numbers. Also:
- the exact rate-limit values and table bounds;
- the holder image (pinned);
- the cloudflared version pin (the estate runs `2026.10.4`);
- the `Host` refusal status;
- stateless or per-source ceremonies (N2 item 5), as long as the property
  holds;
- whether `[api]` stays loopback-only or is simply omitted in the base case
  (it is optional in config today).
