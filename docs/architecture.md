# Architecture

## The problem

Home Assistant has an internal permission model (users, groups, entity
policies), but **no public, supported API to create custom groups with per-entity
policies**. A non-admin user therefore sees every entity. The only supported way
to give someone scoped access is to put an enforcement layer in front of HA.

## Shape

`ha-rbac-gateway` is a reverse proxy for HA's HTTP + WebSocket API. It is a
single process (not split into microservices): the policy/authorization logic
and the proxy are separate *modules* but share one event loop, because they share
the same per-request state (identity, policy, registry) and splitting them would
add an internal network hop and two failure domains for no operational gain at
this scale. The module boundaries (`policy`, `registry`, `identity`, `filters`
vs `rest_proxy`, `ws_proxy`) keep the security logic independently testable.

```
             user's HA token                      backend token (registry only)
                  │                                          │
   browser ──►  gateway  ──── user's token ────►  Home Assistant :8123
   (:8124)      │  filters REST + WS                         ▲
               policy                                        │
               registry ◄───────── read-only registry/identity plumbing
```

## Authentication vs authorization

- **Authentication stays in HA.** The gateway never issues or verifies tokens
  itself. A user logs in through the normal HA login flow (proxied) and receives
  a normal HA token. To learn who a token belongs to, the gateway opens a short
  WebSocket to HA, authenticates *with that same token*, and calls
  `auth/current_user`. HA is the sole authority on token validity.
- **Authorization is the gateway's job.** Every proxied request is evaluated
  against the user's policy before it reaches HA (writes) or before the response
  reaches the user (reads).

## Two tokens, two jobs

- **The user's own token** is what the gateway forwards upstream for user
  traffic. HA sees the real user, so HA's own base checks still apply
  (defence in depth). The gateway never elevates a user by swapping in a
  privileged token.
- **The backend token** (a long-lived token) is used *only* by the registry
  module, read-only, to list the entity/device/area registries. That mapping is
  needed to expand `area`/`domain` rules and to enumerate entities for
  subscription rewriting. User traffic is never sent with this token.

## Enforcement model: positive allowlist

The gateway forwards only what it explicitly recognizes and can filter:

- **REST**: `/auth/*` and the static frontend shell pass through (no entity
  state). Under `/api/`, only `/api/`, `/api/services` (catalogue),
  `GET /api/config` (with home GPS redacted), `GET /api/states[/id]` (filtered),
  and `POST /api/services/<d>/<s>` (target-checked, `return_response` denied) are
  allowed. Everything else — `/api/template`, `/api/history`, `/api/logbook`,
  `/api/camera_proxy`, `/api/error_log`, unknown paths — is denied.
- **WebSocket**: a curated command set (`get_states`, `get_config` (GPS
  redacted), `subscribe_entities`, `subscribe_events` limited to `state_changed`,
  `call_service`, `get_panels`, `lovelace/config`, plus stateless frontend
  plumbing). `subscribe_entities` is
  rewritten so HA only streams the user's allowed entities, and the incoming
  stream is filtered again as defence in depth. Commands that read or act on
  arbitrary entities — `render_template`, `execute_script`, `subscribe_trigger`,
  `config/*` — are denied. Any unrecognized command is denied.

Why allowlist and not blocklist: a blocklist fails **open** on every future HA
change (a new command or endpoint leaks until someone notices). An allowlist
fails **closed** — a new command is simply denied until we add support for it.

### Per-policy commands: own-token management

Two WebSocket commands sit outside the shared allowlist and are enabled per
user by `allow.token_creation` in their policy (default `false`, so every
policy written before the field existed keeps its current denial):

- `auth/long_lived_access_token` — mint a token, result is the token string;
- `auth/refresh_tokens` — list the caller's own token *metadata* (no values).

Both are `@websocket_api.ws_require_user()` in HA core, not `require_admin`
(`homeassistant/components/auth/__init__.py`), so HA itself permits them for
any signed-in user; today it is this gateway that blocks them. Without the
opt-in, the only way to give a restricted user a token is to promote them to
HA administrator — which is exactly what this project exists to avoid.

The gating is a policy field rather than an extension of the
`is_admin or is_owner` passthrough on purpose: passthrough means "stop
filtering this session entirely", and the goal here is the opposite — a user
who stays fully restricted and merely gains one narrow capability. The two
mechanisms never interact; admins bypass the router before it is consulted.

This does **not** widen entity access. HA scopes both commands to the
connection's own user, and the gateway forwards the user's own token upstream
(never the backend token), so the caller can only act on themselves. A token
minted this way is re-evaluated against the same policy on every request it is
later used for; what changes is its lifetime, not its reach. The request is
relayed unmodified, the token-list result is type-guarded to `[]` on an
unexpected shape like every other filtered result, and only the command name is
audited — never the minted credential. Revocation
(`auth/delete_refresh_token`) is deliberately excluded and remains in HA's own
profile UI.

Filtering an allowed response is not always about entities: `get_config` /
`GET /api/config` are allowed (the frontend needs them) but their home GPS
coordinates (`latitude`/`longitude`/`elevation`) are zeroed for restricted
users, since a scoped user has no reason to learn the household's location.

## Serving the Home Assistant frontend

Making the actual HA web UI usable by a restricted user (not just the API)
requires a few more allowed-but-filtered commands, because the frontend can't
finish loading without them:

- **Registries** (`config/entity_registry/list[_for_display]`,
  `config/device_registry/list`, `config/area_registry/list`) are forwarded but
  their results are **filtered to the user's entities** (and the areas/devices
  those entities belong to). Without this the UI hangs on "Loading data"; naively
  allowing them would leak the entire inventory of entity names. Floor and label
  registries return empty.
- **Registry-change subscriptions** (`*_registry_updated`, `component_loaded`,
  service events) are accepted so the frontend's subscription promises resolve,
  but no events are relayed (they can carry ids the user may not see).
- **`get_panels` is filtered** to the user's dashboards plus the built-in panels
  the router needs (`profile`, `notfound`, the `my` redirect). Other dashboards
  and feature panels (history, energy, media, …) are removed, so the sidebar
  shows only what the user can open. HA's router falls back to a panel named
  `lovelace` as its default; if the user doesn't have it, a hidden alias of their
  default dashboard is injected under that key (and `lovelace/config` for it is
  rewritten to their dashboard). Navigating by URL to a removed dashboard yields
  HA's own "no access" page — no content.
- **`system_log.write`** (the frontend's own error logging) is acknowledged
  without forwarding, so a denial can't start an unhandled-rejection storm.
- WebSocket frames may be **coalesced** by HA into a JSON array of several
  messages; the proxy unpacks arrays and filters each message individually.

## Failing closed

- **Unknown traffic** (unrecognized REST path or WS command) → deny.
- **Stale registry** (HA unreachable past `REGISTRY_STALE_MAX`) → area/domain
  rules stop expanding and evaluate to deny; only static entity rules remain.
- **Identity resolution error** → deny (no cached guesses on infrastructure
  errors).
- **The trip switch** — a file at `DATA_DIR/tripped`. While it exists, all
  restricted traffic is denied. The canary creates it automatically when it
  detects filtering has broken; an operator removes it after reviewing what
  changed. Clearing it is deliberately manual.
- **Disabling the gateway** locks restricted users out — it never routes them to
  plain HA. Admin/owner access to HA on `:8123` is independent and unaffected in
  every failure mode.

## The canary

A scheduled self-test (`canary.py`) drives the gateway's own port with a
restricted test-user token and asserts: an allowed entity stays readable; a
forbidden entity stays denied over REST and WS; `render_template`, the template
endpoint, and an unknown command stay denied. Any failure trips the gateway. It
runs both as a background task in the process and as a standalone one-shot for
CI/cron (`python -m ha_rbac_gateway.canary`).

## Known v1 limitations

- WebSocket `subscribe_events` is limited to `state_changed` (filtered) plus a
  few stateless UI-refresh events; broader event subscriptions are denied.
- Services that use `return_response` are denied (their response payload is not
  generically filterable yet).
- Template rendering, script execution and history/logbook/camera access are not
  available to restricted users. These are deliberate exclusions, not oversights.
- Floor and label registries return empty, so a restricted user's UI shows no
  floor grouping or labels.

## Why not a Home Assistant add-on?

Add-ons appear in HA's sidebar through **Ingress**, which routes traffic *from*
an already-authenticated HA session *to* the add-on — it assumes HA is the first
thing the browser reaches and has already decided who you are. This gateway needs
the opposite: the browser must reach the **gateway first**, before HA
authenticates anyone, so the gateway can scope the session. That's incompatible
with the Ingress model.

Add-ons also only run on HA OS / Supervised installs, which would exclude the
Container/Core and rootless-Podman audience this project targets. Every
comparable "reverse proxy in front of HA" tool (Authelia, Authentik, nginx,
Traefik) ships as a standalone container for the same reasons — so does this one.

The frontend **admin panel** is a separate matter: it is a plain custom panel
(`panel_custom`) and could plausibly be distributed on its own via HACS in the
future; the gateway service itself stays a standalone container.
