# Public OSS release readiness

Checklist from a four-dimension review (security, release engineering,
docs/adoption, HA-ecosystem fit). `[x]` done in the release-prep pass, `[ ]`
remaining. Effort tags: `[S]`/`[M]`/`[L]`.

**Status:** **published** at https://github.com/hretheum/ha-rbac-gateway (v0.1.0,
CI green, public multi-arch image on ghcr, GitHub Release). Remaining items are
optional — an external trademark check and sanitized screenshots.

## MUST — before publishing

### Security
- [x] Fail closed on an unexpected upstream result type (every filter branch
      returns empty on a type mismatch; regression tests for malformed WS + REST).
- [x] Policy revoke/edit force-closes the affected user's live WebSocket
      sessions (regression test; SECURITY.md documents it).

### Release engineering
- [x] Repo owner set to `hretheum` (URLs, compose/quadlet images).
- [x] Packaging: MANIFEST.in ships `web/`, `examples/`, `deploy/`, `docs/` in the
      sdist; the pip wheel is server-only and the README says to build-first /
      take the panel from the repo. `python -m build` + `twine check` pass.
- [x] `CHANGELOG.md` (Keep a Changelog) + `v0.1.0` tag pushed; CI built and
      published the multi-arch image to ghcr.
- [x] ghcr package is public — anonymous `docker pull` works.

### Positioning / legal
- [x] Non-affiliation disclaimer in the README.
- [x] Prior-art / alternatives section (user-rbac, kiosk-mode, SSO proxies,
      HA's declined core RBAC).
- [ ] Confirm current OHF trademark/brand guidance directly (no canonical policy
      page was locatable; the name reads as low-risk). `[S, external]`

### Docs / adoption
- [x] Quickstarts fixed (build-first; no image published yet).
- [x] `docs/troubleshooting.md` (firewall, mixed content, image build,
      unavailable cards, double-compression, WS coalescing).
- [x] HAOS/Supervised note (separate container host required).
- [x] Admin-panel mixed-content/firewall caveat promoted into the README.

## SHOULD

- [x] `ADMIN_ALLOWED_ORIGINS` to lock CORS to named origins (default reflects).
- [x] Cap the pre-auth WebSocket frame size (16 MiB).
- [x] aiohttp floored at a CVE-patched baseline + `pip-audit` in CI + Dependabot.
- [x] SECURITY.md: `control` grants full service capability with attacker-chosen
      `service_data`.
- [x] Single-source the version; multi-arch (amd64+arm64) publish job with
      provenance/SBOM; `build`/`twine check` in CI.
- [x] Badges; more example policies (area, domain+mixed); `--version` flag;
      "where does this run?" note.
- [x] "Why not an add-on?" note in the architecture doc.
- [x] Pin GitHub Actions to commit SHAs (Dependabot tracks the `github-actions`
      ecosystem to keep the pins fresh).
- [ ] Digest-pin the Docker base image — deferred to Dependabot (`docker`
      ecosystem). `[S]`
- [ ] Wire up the unused `REST_FRONTEND_PREFIXES` — deferred (a strict static
      allowlist risks breaking the frontend; low practical risk today, wants a
      careful pass). `[M]`
- [ ] GitHub topics + a community.home-assistant.io post — at publish time. `[S]`

## NICE

- [x] `/healthz` no longer exposes the HA version.
- [x] README life-safety caution / no-audit note.
- [x] Git author identity kept as-is (decided).
- [ ] Screenshots/GIF of the restricted dashboard + admin panel — deferred: real
      captures show the maintainer's actual entity names, so they need a
      **sanitized demo instance** before going in a public repo. `[M]`
- [ ] cosign signing, Trivy scan, `THIRD_PARTY_LICENSES.md`. `[S/M]`
- [ ] A dedicated HACS "Plugin" repo for the admin panel. `[M]`

## Confirmed sound (do not re-litigate)

Secrets/leak sweep (tree + full git history) clean; admin-API path traversal not
possible; admin-API auth gating complete; `call_service` target resolution fails
closed; XSS-escaped panel; permissive-only dependency licenses; non-root
Dockerfile; CI least-privilege.

## Distribution decision

Standalone container (compose + Podman Quadlet). Not an HA add-on (Ingress model
is incompatible), not HACS for the gateway itself.
