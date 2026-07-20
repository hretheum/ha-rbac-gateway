# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-20

### Fixed
- Restricted users now LAND on their own default dashboard instead of an
  access-denied page when the instance has a custom global default panel.
  frontend/subscribe_system_data (key core) is intercepted and its
  default_panel rewritten to the user policy dashboards.default (else the
  built-in lovelace, which get_panels aliases). Admins/owners pass through
  unchanged (keep the instance-wide default).

## [0.2.0] - 2026-07-20

### Fixed
- Frontend compatibility with newer HA (2026.7.x): the WS allowlist now handles
  lovelace/dashboards/list (result filtered to the user allowed dashboards,
  fail-closed) so a restricted user default dashboard resolves instead of an
  access-denied landing. Added frontend/get_icons, lovelace/info,
  unsubscribe_events to plain-forward and persistent_notification/subscribe,
  labs/subscribe to a new silent-ack set (subscription resolves, payload never
  relayed). No entity/dashboard content leaks; filtered like get_panels.

## [0.1.0] - 2026-07-12

First public release.

### Added
- Fail-closed RBAC reverse proxy for Home Assistant: per-user policies limit a
  non-admin HA user to specific entities, areas and domains (read or control)
  over both REST and WebSocket, using a positive allowlist (default-deny), a
  canary self-test, and a trip switch that fails closed.
- Serves the **filtered Home Assistant web UI** (states, entity/device/area
  registries, panels, dashboards) so a restricted user gets a working, scoped
  frontend — not just a filtered API.
- **Admin panel**: a Home Assistant sidebar web component (`panel_custom`) plus
  an admin API (`/rbac-admin/api/*`) to manage per-user policies, with live
  hot-reload of the running policy set.
- Deployment as a container via rootless Podman/Quadlet or docker-compose.

### Security
- Filtered responses fail **closed** if Home Assistant returns an unexpected
  shape (never forwarding an unfiltered payload).
- Editing or revoking a policy force-closes the affected user's live WebSocket
  sessions, so changes take effect immediately.

[Unreleased]: https://github.com/hretheum/ha-rbac-gateway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hretheum/ha-rbac-gateway/releases/tag/v0.1.0
