# Validation report

This records how v0.1 was validated empirically against a real Home Assistant
instance. Deployment-specific values (host, tokens, real entity ids, user ids)
are intentionally omitted; entities below are referred to generically.

## Reference deployment

- Home Assistant **2026.7.1**, rootless Podman/Quadlet, gateway on its own port
  beside HA, `Network=host`.
- Registry snapshot on start: **~349 entities** (~140 with an area).
- A dedicated **non-admin** test user with a two-entity policy:
  - `ENTITY_READ` — a binary sensor, `access: read`.
  - `ENTITY_CONTROL` — a sensor, `access: control`.
- A known-forbidden entity `sun.sun` (not in the policy).

## Method

All requests were made as the restricted test user (its own token), against the
gateway's port. A second, identical request was made straight to HA to show what
plain HA would expose to the same non-admin token.

## Results — scoping (14/14 passed)

The decisive comparison:

| Path | Result |
|------|--------|
| `GET /api/states` **through the gateway** | **2 entities** (exactly the policy) |
| `GET /api/states` **straight to HA**, same token | **349 entities** (HA does not scope a non-admin) |

REST, as the test user:

| Check | Expected | Got |
|-------|----------|-----|
| `GET /api/states` | only policy entities | PASS (2) |
| `GET /api/states/<ENTITY_READ>` | 200 | PASS |
| `GET /api/states/sun.sun` | 403 | PASS |
| `POST /api/template` (`{{ states('sun.sun') }}`) | 403 | PASS |
| `GET /api/error_log` | 403 | PASS |
| `POST /api/services/homeassistant/update_entity` on `ENTITY_CONTROL` | 200 | PASS |
| `POST /api/services/homeassistant/update_entity` on `sun.sun` | 403 | PASS |
| `GET /api/config` | home GPS zeroed, other fields intact | PASS |
| `POST /api/services/.../update_entity?return_response` | 403 (unfilterable) | PASS |

WebSocket, as the test user:

| Check | Expected | Got |
|-------|----------|-----|
| `auth` handshake | auth_ok | PASS |
| `get_states` | only policy entities | PASS (2) |
| `render_template` | denied | PASS (`unauthorized`) |
| `config/entity_registry/list` | denied | PASS (`unauthorized`) |
| `subscribe_entities` (no filter) | rewritten to policy | PASS (2) |
| `call_service` on `sun.sun` | denied | PASS (`unauthorized`) |
| `get_config` | home GPS zeroed | PASS |

## Independent API review

A separate source-level review of the Home Assistant auth/REST/WS API (read
against HA core on GitHub, not just the docs) independently **confirmed the
founding assumption**: there is no public API to create custom groups or
per-entity ACLs — `USER_POLICY == ADMIN_POLICY`, so a stock non-admin user has
full entity access and the gateway is the entire enforcement layer. That review
also surfaced two hardening items, both now fixed and covered above:

- `GET /api/config` / WS `get_config` leak the home's GPS coordinates → now
  redacted for restricted users.
- `POST /api/services/...?return_response` returns an unfilterable payload shape
  → now denied for restricted users (matching the WebSocket rule).

Everything else the review flagged (`call_service` `area_id`/`device_id`
targets, `subscribe_events` firehose, `get_states` having no server-side filter,
`auth/sign_path`, per-connection WS id isolation) was already handled by the
allowlist design and is covered by the checks above and by unit tests.

## Results — fail-closed behaviour

- **Canary self-test** (one-shot): 6/6 checks pass (allowed entity readable;
  forbidden entity, template endpoint, `render_template`, and unknown WS command
  all denied).
- **Trip switch**: with `DATA_DIR/tripped` present, a previously-200 allowed read
  returned **503** and `/healthz` reported `"status": "tripped"`; removing the
  file restored 200. This is the state the canary drives to automatically on a
  detected filtering failure.

## Results — real browser, end to end

A dedicated storage-mode dashboard was created for the test user and the full HA
web UI was driven in a real browser through the gateway (over an SSH tunnel to
the gateway's port):

- The restricted user logged in through the gateway using the normal HA login
  page and reached their dashboard.
- The dashboard rendered exactly the two policy entities with live state (a
  "read" binary sensor and a "control" sensor), plus an explanatory note — and
  nothing else from the ~349-entity instance.
- The **sidebar showed only the user's own dashboard** (plus their profile) — no
  other dashboards and no feature panels (history, energy, media, …).
- Registry filtering was required to get there: the entity/device/area registries
  are forwarded but filtered to the user's scope, so the UI finishes loading
  without leaking the inventory.
- Navigating by URL to a dashboard the user has no policy for (the owner's
  `dashboard-sdres`) showed HA's own **"no access"** page — its content never
  loaded.

Getting the frontend to work surfaced (and fixed) several proxy-correctness
issues that pure-API tests didn't: brotli passthrough, WS message coalescing
(arrays of messages in one frame), and a handful of init-time commands the
frontend can't proceed without.

## Results — durability & non-interference

- **Service restart**: `systemctl --user restart` → `active`, `/healthz` ok.
  User-linger is enabled, so the Quadlet starts on boot (`WantedBy=default.target`).
- **Owner/admin untouched**: HA continued serving directly on `:8123` (HTTP 200)
  throughout. All pre-existing containers kept running; the gateway was added
  alongside them and changed none of their configuration.

## Uncertainties / notes for an operator

- A full **host reboot** was not performed (the reference host runs a live
  household HA). Persistence rests on user-linger + `WantedBy=default.target`,
  verified by service restart but not by a cold boot.
- **Not load-tested.** Behaviour under many concurrent WebSocket clients or large
  `subscribe_entities` sets is unmeasured.
- The v1 scope deliberately denies template rendering, script execution,
  history/logbook/camera, `return_response` services, and non-`state_changed`
  event subscriptions. A restricted user's dashboard that relies on those will
  show gaps by design (see [architecture.md](architecture.md) → Limitations).
