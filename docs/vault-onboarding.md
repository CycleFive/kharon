# Customer vault onboarding

A managed deploy is one broker and one customer. The vault is the
customer's own Bitwarden Password Manager on Bitwarden cloud.
kharond does not own it. The customer unlocks it, and the keys stay
in memory. This page is that vault: the organization, the collection,
the dedicated account, the logins, and the API key file.

It is the Bitwarden side of steps 2–4 in
[The kharon account and its master password](deployment.md#the-kharon-account-and-its-master-password-req-dep-007).
That section still generates the master password (`kharon init`) and
installs the file on the broker. The runbook's order is
[The customer's vault](managed-deploy-runbook.md#3-the-customers-vault).

`[bitwarden]` is sync mode, which is the default (`mode = "sync"`).
`mode = "export"` refuses a `[bitwarden]` table
(`section_not_allowed_in_mode`).

kharond syncs Password Manager login items. It has no Secrets
Manager client.

## The organization

Bitwarden's [Organizations overview](https://bitwarden.com/help/about-organizations/)
is the source for which plan holds a collection. It lists four
organization types:

| Type | What that page states |
|---|---|
| Free organizations | Two users, sharing in up to two collections. |
| Families organizations | Six users, unlimited collections. |
| Teams organizations | Unlimited users, billed per user per month, unlimited collections, plus operational tools such as event logs. |
| Enterprise organizations | Unlimited users, billed per user per month, unlimited collections, plus enterprise-only features such as login with SSO and policies. |

Feature detail is on
[Password Manager plans](https://bitwarden.com/help/password-manager-plans/).
Organizations are created in the web app: **New organization**, a
name, a billing email, and a plan
([Create an organization](https://bitwarden.com/help/about-organizations/#create-an-organization)).

A Free organization covers this deploy: the customer's existing
account as owner, and the dedicated kharon account as the second
user, with one collection. Families, Teams and Enterprise cover it
too. Pick the plan the customer already pays for when they have one.

The web vault the account lives on is `bitwarden.server`:

- `https://vault.bitwarden.com` for the US cloud. kharond talks to
  `identity.bitwarden.com`, `api.bitwarden.com` and
  `notifications.bitwarden.com`.
- `https://vault.bitwarden.eu` for the EU cloud, mapped the same way
  onto `bitwarden.eu`.

Any other host is treated as a single origin (Vaultwarden or a
self-hosted Bitwarden server), with `/identity`, `/api` and
`/notifications` under it. A managed cloud deploy uses one of the
two vault hosts. `` `bitwarden.server` must be an absolute http:// or https:// URL ``
(`invalid_url`) otherwise.

## The collection

Bitwarden describes a collection as a way to associate and share
items, similar to a shared folder. An item may belong to one or more
collections
([Organizations overview](https://bitwarden.com/help/about-organizations/#collections-and-groups)).
Create one collection for the logins kharon may fill, for example
`kharon`. Leave the customer's other collections, if any, off the
dedicated account.

## The dedicated account

The dedicated account is a Bitwarden account created with the
password from `kharon init`, on the same cloud region as the
organization. Its email is `bitwarden.email`. kharond refuses a
value that is not an address:
`` `bitwarden.email` must be an email address `` (`invalid_email`).

Store that password in the customer's own vault, on the customer's
own account, as
[the kharon account](deployment.md#the-kharon-account-and-its-master-password-req-dep-007)
says. The dedicated account's personal vault stays empty. A personal
item there is an item outside `organization_id`, and startup refuses
it (below).

The customer owns the organization. The dedicated account is invited
into it. It is not the owner.

### Invite and confirm

Bitwarden adds a member in three steps, invite, accept, confirm
([User management](https://bitwarden.com/help/managing-users/)).

1. In the Admin Console, **Members**, **Invite member**, **By
   email**. Enter the dedicated account's email. Set the member role
   to **User**. On the **Collections** tab, select the kharon
   collection and **View items** (the permission
   [below](#collection-permission)).
2. The dedicated account accepts in the web app, fully logged in.
   Bitwarden says an administrator then has to confirm access.
3. The customer confirms. In **Members**, select the **Accepted**
   user, **Confirm selected**, and check that the fingerprint phrase
   on that screen matches the one the dedicated account shows at
   **Settings → My account**
   ([Account fingerprint phrase](https://bitwarden.com/help/fingerprint-phrase/)).
   They match before **Submit**.

[Member roles](https://bitwarden.com/help/user-types-access-control/)
describe **User** as the role that can access shared items in its
assigned collections and manage personal vault items, and that does
not manage organization settings, members or policies. The same page
says that when an organization is first set up, collection settings
are off and an invited user receives the **View items** permission.
Owners and admins can access every collection when **Allow owners
and admins to manage all collections and items from the Admin
Console** is on. A User is outside that row. Leave the dedicated
account a User.

### Collection permission

[Collection permissions](https://bitwarden.com/help/collection-permissions/)
are per collection. The default for a user or group is **View
items**. That permission can view the collection's items and their
hidden fields, and it cannot add, edit or delete them. kharond never
writes a vault item, so **View items** is the permission it needs.

**View items, hidden passwords** is not a way to keep a password from
kharond. Bitwarden's page says hidden-password permissions still
allow autofill of hidden fields, and that hiding a password does not
prevent access. Assign **View items** on the one collection, and no
other collection.

To change it later: open the collection, the arrow next to its name,
**Access**, the **Permission** dropdown, **Save**.

### What the account may see

`bitwarden.allow_extra_orgs` defaults to false. With that default,
the dedicated account may see the configured organization and nothing
else: no second organization, and no item whose organization is not
`organization_id`. Personal-vault items count. kharond checks this
on the raw `/api/sync` payload before it decrypts anything
(REQ-CRY-008).

A hit at startup exits 78:

```text
kharond: startup error [scope_too_broad]: ScopeTooBroad: account sees 0 other organization(s) and 1 item(s) outside organization_id
```

The two counts are how many other organizations and how many outside
items the account can see. Unlock names the same refusal
`scope_too_broad`. The CLI prints:

```text
kharon: daemon refused [scope_too_broad]: the kharon account can see items or organizations outside its kharon organization (personal-vault items count). Move or delete them in Bitwarden, then unlock again.
```

The owner UI shows that same hint. The audit entry stays
`owner_auth_fail` / `unlock_failed`.

`allow_extra_orgs = true` skips this check and logs
`bitwarden.allow_extra_orgs = true: dedicated-org scope check disabled`.
It does not widen the collection filter below. Leave it false.

An `organization_id` the account cannot see is a different failure.
Startup continues with:

```text
kharond: warning: REQ-CRY-008 startup scope check skipped (the scope check did not complete (configured organization is not visible to the account)). Starting anyway; the check runs before the first unlock or sync succeeds. A too-broad scope still refuses unlock, and a widening locks with scope_widened.
```

Unlock then fails as `unlock_failed`. An unreachable Bitwarden server
is the same warning, with `the Bitwarden server is unreachable` in
place of the parenthetical reason. `--check` does not contact
Bitwarden.

## organization_id and collection_ids

Both keys are UUIDs. kharond lowercases them. Any case is accepted.
A bad value is `invalid_uuid`:

```text
kharond: config error [invalid_uuid]: `bitwarden.organization_id` must be a UUID
kharond: config error [invalid_uuid]: `bitwarden.collection_ids[0]` must be a UUID
```

`collection_ids` lists at least one id. Empty is `no_collections`:

```text
kharond: config error [no_collections]: `bitwarden.collection_ids` must list at least one collection
```

Bitwarden's CLI documents where the ids are
([Organization IDs](https://bitwarden.com/help/cli/#organization-ids)).
Logged in as the customer (the owner) or, after confirm, as the
dedicated account:

```sh
bw list organizations
bw list org-collections --organizationid <organization id>
```

`bw list collections` lists the collections the logged-in account can
see, across organizations. After confirm, the dedicated account's
list should be the one collection it was assigned. The `id` on the
organization object is `organization_id`. The `id` on each collection
object is an entry of `collection_ids`.

On Teams and Enterprise, the organization API key's `client_id` is
`organization.<guid>`, and Bitwarden's
[migration script](https://bitwarden.com/help/migration-script/) says
the organization's GUID is that value with the `organization.` prefix
removed. That key is not the file kharond reads. The next section is
the personal key.

```toml
[bitwarden]
server = "https://vault.bitwarden.com"
email = "kharon@example.net"
api_key_file = "/run/secrets/kharon_bw_api_key"
organization_id = "00000000-0000-0000-0000-000000000001"
collection_ids = ["00000000-0000-0000-0000-000000000002"]
```

Those UUIDs are the placeholders in
[`deploy/compose/kharon.toml.example`](../deploy/compose/kharon.toml.example).
Replace them. `ca_file` is optional and unused for Bitwarden cloud.

## Logins kharon may fill

Share the logins into the collection. Bitwarden's
[Share items](https://bitwarden.com/help/sharing/) page says sharing
does two things: the item's ownership moves to the organization, and
the item is added to one or more collections. The collection's
access settings decide who can read it.

From the web app, for items the customer already has:

1. In the vault, select the logins.
2. **Assign to collections**.
3. **Move to organization**: this organization.
4. **Select collections to assign**: the kharon collection.
5. **Assign**.

A new login uses the **Owner** dropdown for the organization and the
**Collections** dropdown for the collection, then **Save**.

The same page documents the CLI form, `bw move`. It takes the item
id, the organization id, and an encoded JSON array of collection ids:

```sh
echo '["00000000-0000-0000-0000-000000000002"]' | bw encode | bw move <item id> <organization id>
```

kharond keeps login items only (cipher type 1). Notes, cards and
identities are skipped, and so is anything in the trash. Whether a
login matches a page is decided by the URI and the match setting in
[URI match](#uri-match).

## URI match

On each login, the **Website (URI)** field holds one or more URIs.
Bitwarden's [Form URIs for autofill](https://bitwarden.com/help/uri-match-detection/)
page says the default match method for a new login is **Base
domain**, and that a login can override it: the settings icon on the
URI field, then a **Match detection** method. kharond uses the value
stored on that URI. It does not read the account's **Default URI
match detection** setting. A URI left at Default is stored with no
match value, and kharond treats that as Base domain, which is also
Bitwarden's default for new items. Set **Host**, **Starts with** or
**Exact** on the URI itself when that is what the fill should use.

kharond asks `/api/sync` with `excludeDomains=true`, so Bitwarden's
equivalent-domain list (Account settings → Domain rules) is not
applied. Only the URIs saved on the item count.

A login matches a page when one of its URIs matches. The vault
integer and what kharond does with it (`MatchType::from_bw_repr`):

| Bitwarden setting | Stored value | kharond |
|---|---|---|
| Default, or Base domain | absent, or 0 | Base domain: the registrable domain (eTLD+1) from kharond's vendored Public Suffix List, private section included, so `user.github.io` does not match `other.github.io`. An IP, `localhost` or a single-label host compares as that exact host. |
| Host | 1 | Hostname and port equal. The path may differ. |
| Starts with | 2 | Hostname and port equal, and the page's full URL starts with the saved URI. |
| Exact | 3 | The full URL is equal, query and fragment included (`location.href`). |
| Regular expression | 4 | Refused. The fill is `origin_mismatch`. |
| Never | 5 | Refused. The fill is `origin_mismatch`. |
| anything else | | Refused. The fill is `origin_mismatch`. |

The page has to be `https`. `policy.allow_http` defaults to false.
Setting it true logs
`policy.allow_http = true: http:// localhost/IP fills permitted`
and permits an `http://` page only for `localhost`, a name ending in
`.localhost`, or a literal IP, and only when the saved URI is itself
`http`. Bitwarden's base-domain examples include `http://` pages on
public hosts. kharond refuses those.

An `androidapp://` URI is not an `http` or `https` URL, so it does
not match.

The owner-UI bookmark in
[Unlocking from the browser](deployment.md#unlocking-from-the-browser)
is a separate login, in the customer's own vault, with match
detection **Host**. It is not one of the logins in this collection.

## The API key

The file is the dedicated account's personal API key, created while
logged in as that account. Bitwarden's
[CLI authentication via API key](https://bitwarden.com/help/personal-api-key/)
page says where it is: web app, **Settings → Security → Keys**,
**View API key**, then the master password. The dialog shows:

- `client_id`, format `"user.clientId"`. Unique to the account, and
  it does not change.
- `client_secret`. Unique, and **Rotate API key** changes only this.
  Rotating invalidates the previous secret.
- `scope`, always `"api"`.
- `grant_type`, always `"client_credentials"`.

That page also says a personal key is not the organization API key.
The organization key lives in the Admin Console at **Settings →
Organization info** and its `client_id` is `organization.<id>`
([Public API](https://bitwarden.com/help/public-api/)). kharond
refuses one.

Write a JSON object. kharond reads two string fields and ignores any
other key (`ApiKey::from_json`):

```json
{
  "client_id": "user.00000000-0000-0000-0000-000000000000",
  "client_secret": "clientSecret"
}
```

Both values are placeholders. `client_id` must start with `user.`
and continue past that prefix. `client_secret` must be non-empty.
The refusals, all `api_key_file`, exit 78:

```text
kharond: config error [api_key_file]: bitwarden.api_key_file: API key file must be {"client_id", "client_secret"}
kharond: config error [api_key_file]: bitwarden.api_key_file: client_id must be user.<uuid>
kharond: config error [api_key_file]: bitwarden.api_key_file: organization API keys cannot sync a vault
kharond: config error [api_key_file]: bitwarden.api_key_file: client_secret is empty
kharond: config error [api_key_file]: bitwarden.api_key_file: unreadable
kharond: config error [api_key_file]: bitwarden.api_key_file: not a regular file
kharond: config error [api_key_file]: bitwarden.api_key_file: group- or world-writable (use mode 0400 or 0600)
```

A file the uid cannot open names the euid, the owner and the mode:

```text
kharond: config error [api_key_file]: bitwarden.api_key_file: not readable by kharond (euid 10001; file owner uid 1000, mode 0400); make it owned by uid 10001 with mode 0400
```

Group- or world-readable, and a foreign owner, warn and startup
continues when the uid can open the file:

```text
bitwarden.api_key_file is group- or world-readable; use mode 0400 or 0600 unless it is a container-private secret
bitwarden.api_key_file is not owned by kharond's effective uid
```

kharond logs in with `grant_type=client_credentials` and `scope=api`,
as device name `kharon`. The device id is derived from `client_id`
and stays the same across restarts. The API key syncs ciphertext. It
does not decrypt, and it does not recover the master password.

On the compose broker the path is
`deploy/compose/secrets/kharon_bw_api_key.json`, mounted at
`/run/secrets/kharon_bw_api_key`, which is what `api_key_file` says.
Install it as step 4 of
[the kharon account](deployment.md#the-kharon-account-and-its-master-password-req-dep-007):
uid 10001, mode `0400`. The customer hands the file, the email and
the two ids to the operator out of band. The master password stays
with the customer. Rotation is in the
[secrets inventory](broker-lifecycle.md#secrets-inventory): a new
personal key in Bitwarden, then replace the `0400` file and restart.

## kharond reads only the configured collections

`collection_ids` is the allow-list. Sync is `GET /api/sync` as the
dedicated account; the request does not take a collection id. Before
any field is decrypted, an item is kept only when its `organizationId`
equals `organization_id` and at least one of its `collectionIds` is
in `collection_ids` (`Scope::contains`). Both ids are compared
lowercase, after trimming. An item outside that set is dropped
before decrypt. It is absent from `kharon_list` and `kharon_search`.
A fill that names it is `not_found` with detail `unknown_item`. A
grant request that names it is `not_found`.

So the account's Bitwarden permissions decide what the sync payload
can contain, and `collection_ids` decides what kharond decrypts. An
item in a second collection of the same organization does not trip
`scope_too_broad` (it is still inside `organization_id`). It is
still dropped before decrypt when that collection is not listed.
Assign the dedicated account only the collections named in the
config, and list only those ids.
