# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Policies may grant `allow.token_creation` (boolean, default `false`), which
  lets that user create and list **their own** Home Assistant long-lived access
  tokens through the gateway (`auth/long_lived_access_token`,
  `auth/refresh_tokens`). Both are `ws_require_user`, not `require_admin`, in HA
  core, so previously the only way to issue a restricted user a token was to
  make them an HA administrator. The grant carries no entity access: HA scopes
  both commands to the caller's own account, and a token minted this way is
  re-evaluated against the same policy on every later request. Opt-in — a policy
  file written before this field parses to `false` and behaves exactly as it did
  before. Revocation (`auth/delete_refresh_token`) is deliberately still denied.
- Admin panel: a **Domains** filter box (case-insensitive substring). Filtering
  only hides rows, so a checked domain scrolled out of view is still saved.
- Admin panel: an **Own access tokens** checkbox for the grant above, so the
  setting round-trips instead of being silently dropped when the panel — which
  rebuilds its payload from the DOM — saves an unrelated change.

### Added
- Local devices that cannot carry the gateway's auth (ESPHome Voice Satellite
  and the HA frontend's `<img>`/`<audio>` fetches) can now reach the three HA
  views that HA core itself marks `requires_auth = False`
  (`REST_PUBLIC_UNAUTH_PREFIXES`: assist_satellite connection test, tts_proxy,
  esphome ffmpeg_proxy). GET only, and still audited. Verified against HA
  source: `assist_satellite/connection_test.py`, `tts/__init__.py`,
  `esphome/ffmpeg_proxy.py`. Without this, local TTS playback and the voice
  satellite setup wizard time out behind the gateway.
- `_bearer()` also accepts the access token as a `?token=`/`?access_token=`
  query parameter, the transport HA's own clients use for media URLs where an
  `Authorization` header is impossible. The token is validated against HA
  identically either way. Because that puts credentials in the URL, the access
  log is redacted at the same time (see below) — otherwise every such request
  would leave a usable token in the container log.

### Fixed
- The HTTP access log no longer records query strings. aiohttp's default format
  logs the request line (`%r`, i.e. the path *with* its query), which since the
  `?token=` transport above means live user tokens in `podman logs`/journald in
  clear text. `web.run_app` now installs `PathOnlyAccessLogger`, which formats
  from `request.path`; changing `access_log_format` alone cannot fix this, as
  `%r` is defined as the full request line. The `audit.py` decision log was
  already token-free and is unchanged.
- The Docker image no longer ships three copies of the package. The
  single-stage build left raw sources in `/app/src` and setuptools' `/app/build`
  alongside the real installed package in `site-packages`, so anyone patching a
  running container could easily edit a dead copy and see no effect. The build
  is now multi-stage: a `builder` stage produces wheels, and the runtime stage
  installs from a bind-mounted wheel dir, leaving `ha_rbac_gateway` at exactly
  one path and no wheel layer in the final image.

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
