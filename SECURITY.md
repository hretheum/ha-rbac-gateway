# Security Policy

## Supported Versions

This project is pre-1.0. Only the latest `0.x` release receives security fixes.
There is no backporting to older `0.x` releases — please stay on the latest
release if you want fixes.

| Version      | Supported          |
| ------------ | ------------------- |
| Latest `0.x` | :white_check_mark:  |
| Older `0.x`  | :x:                  |

## Reporting a Vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately using [GitHub Security Advisories](../../security/advisories/new)
for this repository. This lets us discuss and fix the issue before it's public
knowledge.

Please include:

- the endpoint, WebSocket command, or code path involved
- the minimal steps or request needed to reproduce it
- what a restricted user could see or do as a result

We'll acknowledge reports and follow up as we investigate. There's no bug
bounty program — this is a volunteer-maintained project — but genuine reports
are taken seriously and credited in the advisory unless you ask otherwise.

## Threat Model

`ha-rbac-gateway` is a reverse proxy that sits in front of Home Assistant and
narrows what a *restricted* (non-admin) HA user can see and do, based on an
operator-defined policy of entities, areas, and domains. Authentication itself
is delegated to HA — the gateway trusts HA's session/token validation and adds
an authorization layer on top.

### What the gateway protects against

- A restricted user reading the state of entities outside their granted scope
  (via REST or WebSocket).
- A restricted user calling services on, or otherwise controlling, entities
  outside their granted scope.
- A restricted user using indirect paths to reach data or control outside
  their scope, including:
  - `render_template` / `/api/template` (template rendering can read
    arbitrary state)
  - `execute_script` (scripts can act on arbitrary entities)
  - `subscribe_trigger` and other event/trigger subscriptions that could leak
    state changes for out-of-policy entities
  - `config/*` and other config/registry endpoints that expose or modify
    system-wide configuration
- Unknown or unrecognized REST endpoints and WebSocket commands being
  forwarded to HA on behalf of a restricted user. These are denied by default,
  not guessed at (see "Fail-closed philosophy" below).

### What the gateway does NOT protect against

- **A compromised HA admin token or admin account.** The gateway constrains
  restricted users; it does nothing to contain an admin credential in the
  wrong hands, and it does not sit between the admin and HA.
- **Network-level attackers, if deployed without TLS.** The gateway does not
  provide transport security on its own. On any network you don't fully
  trust, put TLS in front of it (reverse proxy, tunnel, or the gateway's own
  TLS support if configured) rather than relying on plaintext HTTP/WS.
- **Vulnerabilities in Home Assistant itself.** The gateway is a policy layer
  in front of HA, not a replacement for keeping HA patched. A flaw in HA
  core is out of scope here.
- **Malicious or compromised HA add-ons/integrations.** Anything running
  inside HA with its own access to the HA core API is outside the gateway's
  reach — the gateway only mediates traffic that flows through it from
  restricted clients.

### Fail-closed philosophy

The gateway is built on a positive allowlist: every REST endpoint and
WebSocket command a restricted user may reach must be explicitly listed,
along with how it gets filtered down to that user's granted scope. Anything
not on the allowlist is denied, never forwarded — there is no default-allow
fallback and no attempt to "guess" whether an unrecognized request is safe.

This extends to version skew: if the gateway encounters HA traffic it
doesn't recognize (for example, after an HA upgrade introduces new API
shapes), it denies rather than assumes compatibility. A canary self-test
runs to confirm the gateway is correctly intercepting and filtering traffic;
if the canary fails, the gateway trips into a denying state for restricted
users rather than silently passing traffic through unfiltered.

Disabling or misconfiguring the gateway is designed to fail toward "restricted
users see nothing," never toward "restricted users get plain, unfiltered HA
access." The admin's own direct access to HA is unaffected either way — the
gateway only ever adds restriction, never adds a path around HA's own auth
for the admin.

Policy changes apply live: editing or revoking a user's policy (via the admin
API/panel) reloads the policy set **and force-closes that user's open
WebSocket sessions**, so a revoke takes effect immediately rather than waiting
for the client to reconnect. REST requests are re-evaluated per request.

### Deployment cautions

- Bind the gateway to the interface appropriate for its trust boundary —
  loopback if everything reaching it is local, your LAN interface if it's
  serving LAN clients. Don't bind to a public interface without TLS and a
  network boundary (firewall, VPN) in front of it.
- Put TLS in front of the gateway for any network you don't fully trust —
  it does not encrypt traffic for you by default.
- The backend token the gateway uses to talk to HA is as sensitive as an HA
  admin token, because it is one. Keep it in an env file with restrictive
  permissions (e.g. `chmod 600`), not in a world-readable config file, and
  never commit it.
- Restricted users' policy (which entities/areas/domains they can reach) is
  only as good as its filtering strategy — review new allowlist entries and
  policy grants with the same scrutiny you'd give firewall rules.
- A `control` grant means the **full Home Assistant service capability** for
  that entity's domain, with caller-chosen `service_data`, not just "toggle
  this entity." The gateway validates the *target* entity, but HA services can
  accept free-form parameters (filenames, payloads, etc.). Grant `control` only
  where you'd trust the user with everything that entity's services can do.
