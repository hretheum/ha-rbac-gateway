# ha-rbac-gateway

[![CI](https://github.com/hretheum/ha-rbac-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/hretheum/ha-rbac-gateway/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)

A fail-closed **authorization gateway** for [Home Assistant](https://www.home-assistant.io/).
It lets you give a non-admin HA user access to **only** the entities, areas or domains you choose —
read or control — without making them an administrator and without touching HA's internal group
mechanism.

> **Independent community project** — not affiliated with, sponsored by, or endorsed by Home
> Assistant or the Open Home Foundation. "Home Assistant" is a trademark of the Open Home Foundation;
> it is used here only to describe what this tool works with.

Home Assistant has no public API for creating custom per-user entity permissions, so a normal
non-admin user can see every entity. `ha-rbac-gateway` sits in front of HA as a reverse proxy:
users still log in with their own HA account (**authentication stays in HA**), but every REST and
WebSocket call is checked against a per-user policy **before** it reaches HA (**authorization lives
in the gateway**).

> **Status:** v0.1 / beta. It is a security component; read [SECURITY.md](SECURITY.md) and the
> [limitations](#limitations) before relying on it. No third-party security audit has been done yet —
> be especially careful granting `control` over life-safety entities (locks, alarms, garage doors).

## Why "fail closed"

The gateway uses a **positive allowlist**: it forwards only the requests and WebSocket commands it
recognizes and knows how to filter. Anything else — an unknown endpoint, a new HA command, a
template-rendering call that could read any entity — is denied, not forwarded. A Home Assistant
upgrade that changes the API can, at worst, lock a restricted user out; it can never silently start
leaking. See [docs/architecture.md](docs/architecture.md) for the full model.

## How it works

```
   browser ──►  ha-rbac-gateway  ──(user's token)──►  Home Assistant :8123
   (:8124)        filters REST + WS
                  per-user policy
```

- The user logs in through the gateway using the normal HA login page.
- The gateway asks HA who the token belongs to (`auth/current_user`) — HA remains the only
  authority on authentication.
- Each request is evaluated against the user's policy. Reads are filtered; writes
  (`call_service`) are allowed only when every target entity is in the user's `control` set.
- A **backend token** (configured once) is used only for read-only registry lookups
  (entity → area mapping). User traffic is always forwarded with the user's own token.

> **Where does this run?** The gateway is a container that sits *in front of* HA, so it needs
> somewhere to run a container plus a reachable `HA_URL`. Home Assistant **Container** and **Core**
> installs work directly. On **HA OS / Supervised** there is no general-purpose container host, so
> run the gateway on a **separate machine** (any Docker/Podman host) pointed at your HA. It is not
> an HA add-on — see [why](docs/architecture.md#why-not-a-home-assistant-add-on).

## Quick start (docker-compose)

```bash
git clone https://github.com/hretheum/ha-rbac-gateway
cd ha-rbac-gateway

# No image is published yet — build it locally:
docker build -t ghcr.io/hretheum/ha-rbac-gateway:latest .

cd deploy/compose
cp ../../.env.example .env
# edit .env: set HA_URL and HA_TOKEN (a long-lived token from HA:
#   Profile -> Security -> Long-lived access tokens)

mkdir -p policies data
cp ../../examples/policies/example-guest.yaml policies/guest.yaml
# edit policies/guest.yaml: set the user and the entities they may access

docker compose up -d
```

Point the user at `http://<host>:8124/`. They log in with their HA account and see only what their
policy allows. Bind to loopback and put TLS in front for anything beyond a trusted LAN
(see [SECURITY.md](SECURITY.md)).

## Quick start (Podman / Quadlet, rootless)

```bash
# No image is published yet — build it locally under the tag the unit expects:
podman build -t ghcr.io/hretheum/ha-rbac-gateway:latest .

mkdir -p ~/ha-rbac-gateway/{policies,data}
cp .env.example ~/ha-rbac-gateway/.env         # edit HA_URL, HA_TOKEN
cp examples/policies/example-guest.yaml ~/ha-rbac-gateway/policies/guest.yaml
cp deploy/quadlet/ha-rbac-gateway.container ~/.config/containers/systemd/

systemctl --user daemon-reload
systemctl --user start ha-rbac-gateway
loginctl enable-linger "$USER"                 # keep it running without an active login
```

## Configuration

All configuration is environment variables ([.env.example](.env.example)). The essentials:

| Variable | Meaning |
|----------|---------|
| `HA_URL` | Base URL of your HA instance, e.g. `http://127.0.0.1:8123` |
| `HA_TOKEN` | Long-lived token, used **only** for read-only registry/identity lookups |
| `LISTEN_PORT` | Port the gateway listens on (default `8124`) |
| `POLICY_DIR` | Directory of per-user policy files (default `/config/policies`) |
| `CANARY_TOKEN` | Optional: a restricted test user's token for the self-test (see below) |

## Policy format

One YAML file per user in `POLICY_DIR`. Restart the gateway to apply changes.

```yaml
user:
  id: 0a1b2c3d...          # HA user id (preferred). Or use `name:` to match display name.

allow:
  entities:
    - { id: light.living_room_lamp, access: control }   # control implies read
    - { id: sensor.outdoor_temperature }                # access defaults to read
  domains:
    - { id: light, access: read }                       # every light, read-only
  areas:
    - { id: living_room, access: control }              # everything in an area
  token_creation: true                                  # optional, default false —
                                                        # may manage their OWN HA tokens

dashboards:
  default: guest-home
  allowed: [guest-home]
```

Everything not granted is denied — there is no deny list. Full reference:
[examples/policies/README.md](examples/policies/README.md).

**Finding a user id:** start the gateway, have the user log in once; the first connection from an
unmatched user logs their id and name.

## The canary self-test

Set `CANARY_TOKEN` to a long-lived token belonging to a **restricted test user** and the gateway
periodically drives its own port to confirm filtering still works: the test user can read what they
should, and is denied a known-forbidden entity, the template endpoint, `render_template`, and unknown
commands. If any check fails — for example after an HA upgrade changed behaviour — the canary
**trips** the gateway (a file at `DATA_DIR/tripped`), which then denies all restricted traffic until
you review the change and remove the file.

Run it as a one-shot too (CI / cron):

```bash
GATEWAY_BASE=http://127.0.0.1:8124 CANARY_TOKEN=... \
CANARY_ALLOWED_READ_ENTITY=sensor.something CANARY_FORBIDDEN_ENTITY=sun.sun \
python -m ha_rbac_gateway.canary
```

## Adding a restricted user

1. Create the user in HA as a normal **non-admin** user.
2. Add `policies/<name>.yaml` describing what they may access.
3. Restart the gateway.
4. Point the user at the gateway's URL instead of HA's.

## Admin panel (optional)

Instead of editing policy YAML by hand, you can manage users from a **"RBAC"
item in Home Assistant's sidebar** (admins only). It's a small web component that
talks to the gateway's admin API and applies changes live (no restart).

1. Copy the component into HA's `www/` folder:
   ```bash
   cp web/rbac-panel.js /path/to/homeassistant/config/www/rbac-panel.js
   ```
2. Register it in HA `configuration.yaml` and restart HA once:
   ```yaml
   panel_custom:
     - name: rbac-panel
       sidebar_title: RBAC
       sidebar_icon: mdi:shield-account
       url_path: rbac
       module_url: /local/rbac-panel.js
       require_admin: true
       embed_iframe: false
       config:
         gateway_base: http://<gateway-host>:8124   # reachable from your browser
   ```
3. Make sure the gateway's `policies` directory is mounted **read-write** (the
   admin API writes policy files) — see the deploy files. The API is gated on an
   HA admin token, and `ADMIN_API_ENABLED` (default on) can turn it off.

The admin's browser must be able to reach `gateway_base` directly. Two common gotchas: if HA is
served over **https** and the gateway over http, the browser blocks the cross-origin call as mixed
content (keep both plain http on the LAN, or put TLS in front of both); and the host **firewall**
must allow the gateway port for devices other than `localhost`. See
[docs/troubleshooting.md](docs/troubleshooting.md). Every write is validated, backs up the previous
file, and hot-reloads the running policy set — a revoke also drops that user's live sessions.

## Disabling / rollback (important)

Disabling the gateway is **lockout, not passthrough**:

- Stop the gateway (`systemctl --user stop ha-rbac-gateway` or `docker compose down`). Restricted
  users lose access entirely — they are **never** silently forwarded to plain HA (where a non-admin
  would see everything).
- Admins/owners are unaffected: they keep using Home Assistant directly on `:8123` as always. The
  gateway is an *additional*, narrower door, never a replacement for HA's own.
- To force fail-closed without stopping the service, create the trip file (`touch DATA_DIR/tripped`);
  remove it to resume.

## Prior art & alternatives

Home Assistant has no public API for per-user entity permissions — a non-admin user's group has the
same full entity access as admin. A substantial core RBAC proposal was declined by HA maintainers as
needing Foundation oversight/audit resources they can't currently commit
([architecture discussion #1374](https://github.com/home-assistant/architecture/discussions/1374)),
which is why an external gateway is a reasonable path. If you're comparing options:

- **[user-rbac](https://github.com/SamAthanas/user-rbac)** — a HA custom component that patches HA's
  service-call handling in-process, with a GUI and template rules. Different architecture from this
  project (in-process vs an external fail-closed proxy that also serves the filtered frontend); it is
  early-stage but real. If you want something that lives inside HA, look there.
- **[kiosk-mode](https://github.com/maykar/kiosk-mode) / Restriction Card** — hide the sidebar or
  cards per user. Frontend-only: they do **not** restrict backend/API access, so a user can still
  read or control hidden entities directly. Use them for UX, not access control.
- **Reverse-proxy SSO** (Authelia/Authentik, `hass-auth-header`) solves *authentication* (who you
  are), not *authorization* (what you may see). This project does the opposite: HA stays the auth
  authority; the gateway adds per-user scoping on top.

Where this project differs: an external, fail-closed reverse proxy enforcing a positive allowlist
server-side, that also serves the filtered HA web UI and ships a sidebar admin panel.

## Limitations

v1 deliberately excludes surfaces that cannot yet be filtered safely:

- WebSocket `subscribe_events` is limited to `state_changed` (filtered) plus a few stateless UI events.
- Services using `return_response` are denied.
- Template rendering (`render_template`, `/api/template`), script execution, and
  history/logbook/camera access are denied to restricted users.

These are enforced denials, not gaps — see [docs/architecture.md](docs/architecture.md).

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
```

Tests run the real gateway in front of a fake HA that filters nothing, so any scoping the tests
observe was done by the gateway. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE).
