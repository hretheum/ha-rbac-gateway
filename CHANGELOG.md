# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
