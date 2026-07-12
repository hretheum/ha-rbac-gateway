# Working on ha-rbac-gateway (notes for Claude Code / contributors)

A fail-closed RBAC reverse proxy for Home Assistant (Python 3.12 / aiohttp). It
filters REST + WebSocket so a non-admin HA user only sees/controls the
entities/areas/domains in a per-user policy, serves the filtered HA web UI, and
ships a sidebar admin panel (`web/rbac-panel.js`) + admin API to manage policies.

## Dev workflow

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check .   # both are enforced in CI
pytest -q                                # tests run the gateway in front of a fake HA
```

`main` is protected: changes land via a **pull request**, merged with **Squash
and merge** (GitHub signs the squash commit). No direct pushes. A version tag
`vX.Y.Z` triggers the multi-arch image publish to ghcr.

## Non-negotiable invariants (this is a security tool)

- **Fail closed.** Never forward an HA response of an unexpected shape, or an
  unknown REST path / WS command — return empty / deny. Positive allowlist only.
- **Every allowlist addition needs a filtering strategy + a deny-path test.**
  See `CONTRIBUTING.md` and the `test_reject_*` / fail-closed tests.
- HA can **coalesce** several WS messages into one JSON-array frame — message
  handling must accept both a single object and an array.
- Secrets never in the repo; no real deployment values (IPs/hostnames/tokens).

## Layout

`src/ha_rbac_gateway/` — policy, registry, identity, filters, rest_proxy,
ws_proxy, admin_api, canary, trip, server. `web/` — the admin panel. `deploy/` —
Quadlet + compose. `docs/` — architecture, admin-ui-design, troubleshooting,
validation-report.

## What's next

The full, tiered list is in **[docs/oss-release-readiness.md](docs/oss-release-readiness.md)**.
Currently open:

- **Screenshots / GIF** of the restricted dashboard and admin panel — needs a
  **sanitized demo instance** (real captures would leak a maintainer's entity
  names into a public repo).
- **Wire up `REST_FRONTEND_PREFIXES`** so non-`/api/` GETs aren't passed through
  by a broad default (a strict static allowlist; do it carefully so the frontend
  doesn't break).
- **Supply chain:** cosign/sigstore image signing, a Trivy/Grype scan on the
  built image, a generated `THIRD_PARTY_LICENSES.md`; digest-pin the Docker base
  image (or let Dependabot track it).
- **Distribution:** evaluate a dedicated HACS "Plugin (Dashboard)" repo for the
  admin panel so admins get update-tracking instead of copying the JS by hand.
- **Community:** confirm current Open Home Foundation trademark/brand guidance;
  post to community.home-assistant.io ("Share your Projects").
- Triage the Dependabot PRs (the pinned action SHAs are current; major bumps are
  optional).
