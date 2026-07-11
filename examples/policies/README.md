# Policy files

One YAML file per restricted user. All files in `POLICY_DIR` (default
`/config/policies`) are loaded at startup; **restart the gateway to apply
changes** (policies are deliberately not hot-reloaded — a change to who can see
what should be an explicit action).

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

## Dashboards

`dashboards.default` and `dashboards.allowed` are Lovelace `url_path`s the user
may load through the gateway. Requests for any other dashboard config are denied.
