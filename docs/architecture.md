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
  state). Under `/api/`, only `/api/`, `/api/config`, `/api/services`
  (catalogue), `GET /api/states[/id]` (filtered), and
  `POST /api/services/<d>/<s>` (target-checked) are allowed. Everything else —
  `/api/template`, `/api/history`, `/api/logbook`, `/api/camera_proxy`,
  `/api/error_log`, unknown paths — is denied.
- **WebSocket**: a curated command set (`get_states`, `subscribe_entities`,
  `subscribe_events` limited to `state_changed`, `call_service`, `get_panels`,
  `lovelace/config`, plus stateless frontend plumbing). `subscribe_entities` is
  rewritten so HA only streams the user's allowed entities, and the incoming
  stream is filtered again as defence in depth. Commands that read or act on
  arbitrary entities — `render_template`, `execute_script`, `subscribe_trigger`,
  `config/*` — are denied. Any unrecognized command is denied.

Why allowlist and not blocklist: a blocklist fails **open** on every future HA
change (a new command or endpoint leaks until someone notices). An allowlist
fails **closed** — a new command is simply denied until we add support for it.

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
