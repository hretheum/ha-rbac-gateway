# Admin UI design (v1)

A Home Assistant sidebar panel ("RBAC") for admins to manage which non-admin
users can access which dashboards, areas, domains and entities — instead of
editing policy YAML by hand.

## Delivery (option C — native HA panel)

- The panel is a **custom web component** (`<rbac-panel>`, vanilla JS, no build
  step, themed with HA CSS variables) served from HA's own `www/` folder
  (`/local/rbac-panel.js`) and registered with `panel_custom` in
  `configuration.yaml` (`require_admin: true`). The admin keeps using HA on its
  normal origin.
- The component talks to the gateway's **admin API** (`/rbac-admin/api/*` on the
  gateway's port). This is cross-origin (HA origin → gateway origin), so the API
  sends CORS headers and the component passes the admin's HA token. The gateway
  base URL is provided explicitly via the panel's `config.gateway_base`.
- Assumes LAN access over http (no mixed-content). Not intended to be reached
  through an https reverse proxy that only fronts HA.

## Admin API (gateway)

All routes under `/rbac-admin/api/` require a Bearer token that resolves (via
HA) to an **admin/owner**; anything else is 403. CORS: reflect the request
Origin, allow `Authorization`/`Content-Type`, handle `OPTIONS` preflight.

- `GET /context` — everything the UI needs to render: non-admin users,
  dashboards, areas, domains and entities (id, name, area). Gathered with the
  backend token + the registry cache.
- `GET /policies` — summary of every user's current policy.
- `GET /policies/{key}` — one user's policy as an editable structure.
- `PUT /policies/{key}` — validate (via `parse_policy`), back up the old file,
  write atomically, then hot-reload.
- `DELETE /policies/{key}` — remove a user's policy (revoke) + reload.

## Hot-reload

Policies load into a fresh `PolicyStore`; the store is swapped on the gateway
only if the new set parses. A bad write can't take the gateway down, and changes
apply without a restart. The policy directory is mounted read-write for this.

## Security

The UI grants access, so the API is the boundary: admin-token-gated, strict
policy validation before any write, backups before overwrite, and a reload that
fails safe. Non-admin users can never reach the API (their token resolves to
non-admin → 403), and the panel itself is `require_admin`.
