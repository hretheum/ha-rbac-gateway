# Policy files

One YAML file per restricted user. All files in `POLICY_DIR` (default
`/config/policies`) are loaded at startup. **Editing a file by hand requires a
gateway restart to apply**; changes made through the admin panel (or admin API)
are validated and hot-reloaded live.

A malformed policy **fails loudly at startup** with a file- and field-specific
error and aborts — a typo can't silently widen or narrow access.

Example files in this directory: `example-guest.yaml` (individual entities),
`example-area.yaml` (whole areas), `example-domain-and-mixed.yaml` (domains +
entities together).

## Matching a user

Set exactly one of:

- `user.id` — the Home Assistant user id (**preferred**: stable and unambiguous).
- `user.name` — the HA display name (convenient, but names can collide or change).

Don't know the id yet? Start the gateway, have the user log in once through it,
and read the gateway log — the first connection from an unmatched user logs their
id and name.

## Granting access

Under `allow`, three list types, each an item with `id` and optional
`access` (`read` — the default — or `control`; `control` implies `read`):

- `entities` — individual entity ids (`light.kitchen`).
- `domains` — a whole domain (`light`, `sensor`). Expanded live from HA.
- `areas` — an HA area id. Expanded via the registry; if the registry is stale
  (HA unreachable for a while) area rules **fail closed** (deny) until it refreshes.

Everything not granted is denied. There is no `deny` list — the model is
allowlist-only.

## Own access tokens (`allow.token_creation`)

`allow: { token_creation: true }` (a boolean, default `false`) lets this user
create and list **their own** Home Assistant long-lived access tokens through
the gateway — the two WebSocket commands `auth/long_lived_access_token` and
`auth/refresh_tokens`, which are otherwise denied like everything outside the
allowlist. Without it, the only way to issue a token is to make the person a
full HA administrator, which defeats the point of this project.

It is **not** an entity grant. Home Assistant scopes both commands to the
calling user's own account, and a token minted this way is still subject to
this same policy on **every request that goes through the gateway** — verified
against a live instance: the minted token, replayed through the gateway, saw
the same two entities the policy allows and nothing else.

What it changes is lifetime, and that deserves care. The same token sent
*directly* to Home Assistant is an ordinary HA token and sees everything that
user's HA account can see — as their normal login token already does. The
gateway's model has always assumed restricted users cannot reach `:8123`
themselves (bind HA to loopback and expose only the gateway); this grant makes
that assumption load-bearing for longer, because a long-lived token is durable
and copyable where a browser session is not. Grant it only where HA is
genuinely unreachable except through the gateway, and treat the result as a
credential the user is now responsible for.

Revoking a token is deliberately **not** included — that stays in Home
Assistant's own profile page. Only real YAML booleans are accepted; a quoted
`"true"` is rejected at startup rather than read as a grant.

## Dashboards

`dashboards.default` and `dashboards.allowed` are Lovelace `url_path`s the user
may load through the gateway. Requests for any other dashboard config are denied.
