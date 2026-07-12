# PROMPT: HA RBAC Gateway — open-source authorization middleware for Home Assistant

> Language note: this prompt and every artifact it produces are written in English so the
> resulting project is publishable as open source. The maintainer's own instance (`hass`) is
> used only as the reference deployment for empirical validation, never as the design center.

## 1. OUTCOME (named artifact)

A **standalone, open-source, configuration-driven authorization gateway (RBAC gateway)** that sits
in front of Home Assistant and lets an operator grant selected HA users access limited to specific
entities / areas / domains (read or control), without giving them the Administrator role and without
touching HA's internal, non-public group mechanism.

The gateway is generic from the first line. It targets *any* Home Assistant instance: the connection
(base URL, backend token) and the per-user policies come from configuration, not from hardcoded values.
No IP address, hostname, username, or token belonging to any single deployment appears in the source.

Model of responsibility:
- **Authentication stays in HA.** A restricted user logs in with their existing (non-admin) HA account.
- **Authorization moves to the gateway.** The gateway holds its own long-lived access token with full
  access, intercepts REST and WebSocket traffic bound for HA, evaluates the policy assigned to the
  logged-in user, and either forwards the call to HA or rejects it before HA ever sees it.

This split is deliberate. HA exposes no public API for creating custom groups with policies (verify this
live, see Source Package), so enforcement has to live in a separate layer rather than inside HA.

**Safety invariants (non-negotiable — this is the point of the whole service):**
- **Default-deny (positive allowlist), never blocklist.** The gateway forwards only the REST paths and
  WS message types it explicitly recognizes and knows how to filter. Anything it does not recognize (a new
  endpoint, a new WS command, a shape it cannot parse) is denied for restricted users, not forwarded. A
  blocklist ("forward everything except known-bad") is forbidden: it fails open on every future HA change,
  whereas an allowlist fails closed (at worst a lockout, never a leak).
- **Entity-list filtering alone is insufficient.** Several HA commands read the state of ANY entity
  regardless of an entity allowlist and must be denied to restricted users by default: WS `render_template`
  and REST `/api/template` (`{{ states('sensor.anything') }}`), `execute_script`, `subscribe_trigger`,
  `get_states` (returns everything, so it needs post-filtering), and the `config/*` and `search/*` command
  families. Treat generic/powerful commands as deny-by-default; add any to the allowlist only with a
  filtering strategy you have proven safe.
- **Fail closed on version skew.** Depend only on the documented public HA API. When the gateway meets an
  HA version, message type, or schema it was not built against, it degrades to denial for restricted users
  and raises an alert. It never guesses and forwards.
- **Fallback is lockout, not passthrough.** The only safe degraded mode for a restricted user is losing
  access, never being routed to plain HA (where a non-admin sees every entity). The owner's direct `:8123`
  access is unaffected in every failure mode.

Deliverable = a **new public git repository** at `~/dev/ha-rbac-gateway/` (its own repo; `git init` is
expected), laid out as a proper open-source project:

```
ha-rbac-gateway/
├─ src/                      # the service; keep the authorization/policy layer
│                           #   cleanly separated from the REST/WS proxy layer
├─ deploy/
│  ├─ quadlet/              # generic rootless Podman/Quadlet .container (placeholders only)
│  └─ compose/              # docker-compose.yml alternative for non-Podman/non-systemd users
├─ examples/policies/        # sample per-user policy files
├─ docs/                     # validation report (§8), threat model notes
├─ Dockerfile
├─ .github/
│  ├─ workflows/ci.yml       # lint + test + image build (see §3 on publishing)
│  └─ ISSUE_TEMPLATE/ , PULL_REQUEST_TEMPLATE.md
├─ .env.example              # HA_URL=..., HA_TOKEN=..., GATEWAY_PORT=..., etc.
├─ .gitignore                # must ignore .env and any real secrets
├─ README.md                 # quickstart, configuration, policy format, add-a-user, rollback
├─ CONTRIBUTING.md
├─ SECURITY.md               # this is a security gateway — document the threat model & reporting
├─ CODE_OF_CONDUCT.md
├─ LICENSE
└─ PROMPT.md                 # optional: a copy of this prompt, as build provenance
```

Concrete pieces:
1. **Service source** split into modules: policy/authorization layer separated from the REST/WS proxy
   layer. Whether these become one modular process or separate containers (e.g. `policy-api` + `proxy`)
   is a Work Plan decision — justify it; split only if it genuinely helps independent testing / restart /
   scaling, not for its own sake.
2. **Policy format** — YAML or JSON, one policy per user (or reusable policy sets referenced by users;
   a reusable policy set *is* a role, which is what makes this RBAC). Fields: allowed
   `entity_ids` / `area_ids` / `domains`, access level (`read` / `control`), default dashboard.
3. **Two deployment targets** kept in sync: a rootless Quadlet `.container` and a `docker-compose.yml`,
   both parameterized (no real host values baked in).
4. **Container image + CI** — a `Dockerfile` plus a CI workflow that lints, tests, and builds the image.
5. **README** — how to add a restricted user, how to deploy (Quadlet and compose), and how to disable the
   gateway safely: doing so restores the owner's/admins' direct `:8123` access and **locks restricted
   users out** — it never routes them to plain HA (that would be a fail-open leak).
6. **Test report** (see §8).

## 2. SOURCE PACKAGE (read and verify against reality, do not assume from training data)

**Authoritative HA documentation (verify live — it may have changed since the date below):**
- https://developers.home-assistant.io/docs/auth_permissions/ — internal permission model
  (`entities`, `read` / `control` / `edit`, group merge). Confirmed 2026-07-11: the auth store can
  technically hold custom groups with policies, but there is **no public API to create them** — the
  reason we build an external gateway instead of trying to expose a custom HA group.
- https://developers.home-assistant.io/docs/api/rest/ — REST API (`/api/states`,
  `/api/services/<domain>/<service>`, `Authorization: Bearer <token>`).
- https://developers.home-assistant.io/docs/api/websocket/ — WebSocket API (`auth`, `subscribe_events`,
  `call_service`, `get_states`, `get_config`). This is the hard part: the HA frontend talks mostly over
  WS, not REST.
- https://www.home-assistant.io/docs/authentication/ — long-lived access tokens (the gateway's backend
  token).

**Reference-deployment context (the maintainer's host; adapt or ignore for other deployments):**
- The reference host is a low-power machine running **rootless Podman with Quadlet**, reachable via
  `ssh hass`, already running HA plus a few sibling containers. Study its Quadlet convention as the model
  for the *generic* `deploy/quadlet/` example: rootless, `%h/...` volumes, `PublishPort=127.0.0.1:<port>`
  (loopback only), `Restart=always`/`on-failure`, `[Install] WantedBy=default.target`, optional
  `PodmanArgs=--memory=... --cpus=...` to protect a weak host. Follow this shape, but the committed
  example must use placeholders, not the host's real values.
- The maintainer's host is currently LAN-only by design. External exposure (TLS, reverse proxy) is out
  of scope for the reference deployment, but the README may describe it as an option for other operators.

## 3. TOOL ACCESS

- **Full write:** the new repository directory `~/dev/ha-rbac-gateway/` — create and edit freely.
  `git init` and local commits are expected (this is a fresh project, unlike a note in an existing tree).
- **SSH:** allowed ONLY to `ssh hass` (the maintainer's reference host; a user with sudo nopasswd) — for
  the reference deployment and empirical validation of your service. SSH to any other host is forbidden
  (out of scope).
- **On the reference host you may:** create new files/dirs for this service, generate a new long-lived
  access token in HA (for the gateway backend's own use), install and run a new rootless Quadlet
  container, and create a dedicated test HA user to verify policy. Do not use a real person's account for
  testing.
- **On the reference host you must not:** modify the HA config (read it only to understand current
  entities/areas — prefer reading via the API over touching files), or modify any existing
  container/Quadlet. Your service stands beside them, never in place of them, and never changes their
  config.
- **Internet:** fetching/verifying the docs above and pulling standard dependencies (pip/npm/etc., per
  your chosen stack) is allowed, as is building the container image locally. Any action on external cloud
  services, DNS, or a public registry is out of scope here (see Human Gate on publishing).
- **Publishing is NOT autonomous.** Configure the CI workflow and image tags so that publishing the repo
  and pushing the image to a registry is a single, ready-to-run step — but do not run it. Making the repo
  public or pushing an image under the owner's account is an outward-facing action gated on the owner
  (see §9 and Failure/Escalation).

## 4. BOUNDARIES

- **No real deployment values in the repo.** The public repository must contain zero real IP addresses,
  hostnames, usernames, personal names, or tokens. Connection details come from `.env` (git-ignored);
  `.env.example` carries placeholders only. Before declaring done, run a leak audit (§8) and prove it.
- **Backend token handling.** The gateway's long-lived HA token never lands in the repo or the image in
  plaintext. Load it from an environment file / secret mechanism, keep `.env` git-ignored, and reference
  a secret file from the Quadlet (`EnvironmentFile=`) and from compose (`env_file:`), the way the
  reference host loads other container secrets.
- **State-backup rule (from the reference host's operating rules).** Before touching anything that is the
  running state of an application (not your own new code) — copy it first
  (`cp file file.bak-$(date +%F%H%M)`). In practice: if you read HA data at all, go through the API, not
  by editing `.storage` files.
- **No changes to HA's internal permission mechanism.** No editing `.storage/auth`, no attempts to call a
  non-public group-creation API. All authorization logic lives in your service.
- **Owner access stays intact.** The owner's direct admin access on `:8123` must keep working, unchanged,
  throughout. The gateway is an additional path for restricted users, not a replacement for existing
  access. Regression here = zero.
- **Disabling the gateway means lockout, not passthrough.** The kill switch / rollback must remove
  restricted users' access, never send them to plain HA. "Rollback to `:8123`" applies to the owner and
  admins only; for a restricted user the safe degraded state is no access (see the Safety invariants in
  §1).
- **No external exposure on the reference host.** Keep the reference deployment LAN-only; run the gateway
  on its own port, never `:8123`. (Documenting TLS/reverse-proxy as an option for other operators in the
  README is fine.)
- **WS honesty.** If full, safe per-message WebSocket filtering (real-time `subscribe_events`, where HA
  can push the state of out-of-policy entities in a live stream) turns out disproportionately risky or
  complex for the first iteration — see Failure/Escalation and document the trade-off, rather than
  shipping something that looks implemented but leaks data to unauthorized users.
- Create no HA accounts or tokens other than the one dedicated test user and the one backend token.

## 5. WORK PLAN

1. Verify the Source Package docs live (REST/WS API; the absence of a public custom-group API). Confirm
   assumptions; do not rely on training-data memory.
2. Study the reference Quadlet convention and host layout (§2) so the generic `deploy/quadlet/` example
   matches real, working conventions (networking, volumes, restart, loopback ports).
3. Design the architecture: AuthN layer (delegate to HA — the user logs in with their HA account) vs
   AuthZ layer (yours, per-user policy). Connection to HA is fully config-driven. Adopt the **positive
   allowlist / default-deny** model from §1 as the backbone: enumerate the REST paths and WS commands the
   gateway understands and can filter; everything else is denied. Include HA-version/message-type detection
   so unknown traffic degrades to denial. Decide and justify: one internally-modular process or split
   containers (e.g. `policy-api` + `proxy`). Split only if it genuinely eases independent testing / restart
   / scaling.
4. Design the policy schema (YAML/JSON): user, `entity_ids`/`area_ids`/`domains`, `read`/`control`,
   `default_dashboard`, and reusable policy sets ("roles"). Justify the format choice.
5. Implement the REST proxy: intercept `/api/states`, `/api/services/*`, filter by the logged-in user's
   policy before forwarding to HA (with the backend token). Deny by default any endpoint that returns full
   state or evaluates templates (`/api/template`, unfiltered `/api/states`, `/api/config`, `/api/error_log`)
   unless you have a proven per-request filter for it.
6. Implement the WebSocket proxy: handle `auth` (delegate to HA), filter
   `get_states` / `subscribe_events` / `call_service` by policy. Deny by default the commands that bypass
   entity-level filtering (`render_template`, `execute_script`, `subscribe_trigger`, `config/*`, `search/*`)
   for restricted users. Any WS message type you do not recognize is denied, not forwarded. If full WS
   coverage is not safely achievable in reasonable time — see Failure/Escalation and document a deliberately
   narrowed v1 scope.
7. Write both deployment targets: a rootless Quadlet `.container` (following §2 conventions) and a
   `docker-compose.yml`, plus the `Dockerfile`. Parameterize everything; no host-specific values.
8. Write the CI workflow (lint, test, image build) and the OSS hygiene files (README, CONTRIBUTING,
   SECURITY.md, CODE_OF_CONDUCT, LICENSE, issue/PR templates). Delegate the boilerplate (see §6).
9. Deploy to the reference host over SSH (§3), running beside the existing services on its own port.
10. Create a dedicated test HA user + a policy restricting it to 1–2 entities/an area, and verify
    empirically (see Review Standard and Evidence Path). Include fail-closed checks: as the test user, an
    out-of-policy entity, a `render_template`/`/api/template` call, and an unknown/unrecognized WS command
    must each be denied — not forwarded, not 500. Build a **canary self-test** that reruns these and can be
    scheduled, so a future HA update that breaks filtering is caught (and trips the gateway to fail-closed)
    instead of leaking silently.
11. Run the leak audit and write the README, including the kill-switch runbook (adding users, deploy via
    Quadlet and compose, and how to disable the gateway so restricted users are locked out — never routed
    to plain HA).

## 6. COST ROUTE

The mechanical work — fetching/reading the HA REST/WS docs, scaffolding OSS boilerplate (README skeleton,
CONTRIBUTING, CODE_OF_CONDUCT, issue/PR templates, Dockerfile and CI templates) — should be delegated to
a subagent / cheaper model as parallel research and scaffolding. The architecture decisions (split or not,
v1 WS scope, policy format) and the security-critical implementation (the authorization and proxy code)
stay with you. That is where the value is.

## 7. REVIEW STANDARD (definition of done)

1. A logged-in test user, through the gateway, sees and controls ONLY the entities assigned in their
   policy — confirmed empirically (not by assertion), with request/response records in the report.
2. An attempt (REST and WS) to reach an entity outside the test user's policy ends in an explicit denial
   (not a 500) — show the actual log.
3. **Fail-closed proven.** As the test user, a `render_template`/`/api/template` call, a full-state
   endpoint, and an unknown/unrecognized WS command each return an explicit denial — not forwarded, not a
   500. Show the actual logs.
4. **Canary self-test** exists, is runnable and schedulable, and passes; the report explains how it trips
   the gateway to fail-closed if a future HA change breaks filtering.
5. **Disabling the gateway locks restricted users out**, and never routes them to plain HA, while the
   owner and admins keep direct `:8123`. Demonstrate this.
6. The owner's direct `:8123` access works unchanged throughout the build (regression = 0).
7. The backend token appears in no file outside the secret mechanism (env, git-ignored, absent from the
   image).
8. **Both** deployment targets start cleanly: the Quadlet survives a host restart
   (`systemctl --user status` *after* a reboot, not only first start), and `docker compose up` starts the
   same image from the same config.
9. CI is green and the image builds.
10. **Leak audit passes:** grepping the repo for real IPs / tokens / hostnames / personal names returns
    nothing (show the audit).
11. README lets a stranger deploy the gateway without reading the service source, and lets the owner add a
    restricted user the same way. LICENSE is present.
12. If WS filtering was deliberately narrowed (§4 WS honesty / §5 step 6): clearly document what works, what
    does not, and why the shipped scope is safe (not "looks like it works").

## 8. EVIDENCE PATH (report inside the repo, e.g. `docs/validation-report.md`)

- Log of sources actually read (URL/file, date, what you took from it), including confirmation of HA's
  API state on the verification day.
- List of design decisions with rationale: allowlist vs blocklist (must be allowlist), the deny-by-default
  command set, split or single service, policy format, v1 WS filtering scope.
- Actual test logs from step 10 (allowed and denied requests, with responses) — not just a "works"
  summary.
- Fail-closed evidence: the denial logs for `render_template`/`/api/template`, a full-state endpoint, and
  an unknown WS command by the test user; plus the canary self-test output and how it is scheduled.
- `systemctl --user status` after a host restart (or a simulated service restart) as proof of durability,
  and the `docker compose up` output for the compose path.
- Leak-audit output (the grep and its result).
- CI run result (or the local equivalent if CI has not been pushed yet).
- List of uncertainties / trade-offs for the owner to review before production use (e.g. "not tested under
  load", "WS filtering covers X, not Y").

## 9. HUMAN GATE

- **Restricted users:** no real person is put behind the gateway as their only access path automatically.
  Before handing a real login to a real person (not the test user): manual review of that person's policy,
  a manual test on a test account reproducing their intended permissions, and explicit consent to any
  narrowed WS scope (§4/§7).
- **Publishing:** making the repository public and pushing the container image to a registry are
  outward-facing actions that need the owner's credentials and consent. Prepare everything so publishing is
  one command; do not run it. The LICENSE choice (default Apache-2.0 for the patent grant; MIT as the
  simpler alternative) is confirmed here, at publish time.
- The gateway never replaces the owner's direct `:8123` access.

---

## FAILURE / ESCALATION

If full, safe per-message WebSocket filtering (especially `subscribe_events`, where HA may push the state
of out-of-policy entities in a real-time stream) proves disproportionately complex or risky to close in
this iteration — STOP at that point, document why (the specific HA mechanism, not a hand-wave), and ship a
v1 with an explicitly narrowed scope instead of something that looks like full isolation but leaks. A
reasonable v1 narrowing: REST fully enforced + WS limited to `get_states`/`call_service`
(request/response, easy to filter), without full `subscribe_events` (real-time push). Document it as a
deliberate trade-off, not a hidden gap.

If, during the work, HA (a newer version than what you verified in the Source Package) turns out to expose
a public API for custom groups — stop, report it as a change to the task's founding assumption, and do not
quietly continue with two parallel mechanisms.

When a breaking HA change makes safe filtering impossible (a new message type you cannot parse, an auth
flow you no longer understand, a schema mismatch), the built-in behavior must be to **fail closed**: deny
restricted users and raise an alert. Never respond to a breaking change by forwarding unfiltered traffic or
by routing restricted users to plain HA. Re-widening the allowlist after such an event is a human decision,
made against the updated HA, not an automatic recovery.

If any step requires the owner's credentials or an outward-facing action (making the repo public, pushing
to a registry, DNS, external services) — stop and hand control back. Configure it, do not execute it.

**Be terse in progress updates.** Do not narrate your reasoning at length. Stop only when you genuinely
need a human decision (see Boundaries and Human Gate); otherwise carry the work end to end.
