# Public OSS release readiness

A checklist produced from a four-dimension review (security, release engineering,
docs/adoption, HA-ecosystem fit) before making this repository public. Tiers:
**MUST** (block release), **SHOULD** (do soon), **NICE** (later). Effort tags:
`[S]` small, `[M]` medium, `[L]` large.

Overall: architecturally solid and well-documented for a v0.1, but not yet
public-ready. The blockers are two real code-level security gaps that contradict
the project's own "fail-closed"/"instant revoke" wording, plus release mechanics
and positioning. Rough core effort: ~2–3 focused days.

## MUST — before publishing

### Security (highest priority — these contradict documented guarantees)
- [x] **Fail-open on unexpected upstream result type.** ~~`_transform_result`
      (ws_proxy) and `rest_proxy._states_list/_config_redacted/_call_service`
      gate filtering on `isinstance(result, list|dict)` with no `else`.~~
      **Fixed:** every filter branch now returns an empty result on a type
      mismatch (fail closed), incl. `filter_entity_registry_display`; regression
      tests cover malformed WS + REST shapes.
- [x] **Revoke doesn't cut live WebSocket sessions.** ~~Evaluator bound at
      connect time; `reload_policies()` only affected new connections.~~
      **Fixed:** the gateway tracks open WS sessions; a policy PUT/DELETE
      force-closes the affected user's live sessions so revoke is immediate
      (they reconnect under the new policy or are denied). SECURITY.md updated;
      regression test asserts the live socket closes on revoke.

### Release engineering
- [ ] Replace the literal `OWNER` placeholder (README, compose, quadlet,
      `pyproject.toml` Homepage) with the real GitHub org/user — every install
      command currently points at a non-resolving URL. `[S]`
- [ ] Decide packaging of non-`src/` assets: `web/rbac-panel.js` and
      `examples/` are excluded from the wheel today, but the README tells users
      to `cp` them. Ship them as package data or document "pip = server-only,
      panel/examples from a clone/tarball". `[S]`
- [ ] Cut a real `v0.1.0` tag (CI already triggers on `v*`) and add a
      `CHANGELOG.md` (seed it from the commit messages). `[S/M]`

### Positioning / legal
- [ ] Add a non-affiliation disclaimer near the top of the README (independent
      project, not affiliated with/endorsed by Home Assistant / Open Home
      Foundation). `[S]`
- [ ] Verify current OHF trademark/brand guidance directly (no canonical policy
      page was locatable). Name `ha-rbac-gateway` reads as low risk. `[S]`
- [ ] Add an honest "Prior art / alternatives" section: `SamAthanas/user-rbac`
      (closest, in-process vs external proxy), kiosk-mode/Restriction Card
      (UI-only). Frame as filling a gap HA maintainers have said they can't
      resource in core (architecture discussion #1374). `[S/M]`

### Docs / adoption
- [ ] Fix the quickstart so it runs (build-first, or actually publish an image).
      `[S]`
- [ ] Add a troubleshooting section: host firewall/port reachability,
      admin-panel mixed-content (http gateway vs https HA), double-compression
      behind an extra proxy, WS message coalescing (for contributors). `[S]`
- [ ] Add a HAOS/Supervised note: a separate container host is required (add-on
      packaging is not a fit — see below). `[S]`
- [ ] Promote the admin panel's http/mixed-content caveat from
      `docs/admin-ui-design.md` into the README. `[S]`

## SHOULD

- [ ] Restrict admin-API CORS to an explicit allowed-origin list (it reflects
      any Origin today). `[S]`
- [ ] Wire up the unused `REST_FRONTEND_PREFIXES` so non-`/api/` GETs aren't
      passed through by a broad default. `[S]`
- [ ] Cap `max_msg_size` on the pre-auth client WebSocket. `[S]`
- [ ] Raise the `aiohttp` floor to a patched baseline and add `pip-audit` /
      Dependabot (this project parses untrusted HTTP/WS framing). `[S]`
- [ ] Note in SECURITY.md that `control` grants full HA service capability with
      attacker-chosen `service_data`, not just entity toggles. `[S]`
- [ ] Single-source the version; finish the container publish job with
      multi-arch (arm64) + provenance/SBOM; pin GitHub Actions to SHAs; add
      `python -m build` + `twine check` to CI; digest-pin the base image. `[S/M]`
- [ ] Screenshots/GIF of the restricted dashboard and the admin panel (highest
      adoption leverage); README badges; more example policies (domain/area/
      mixed); fix the `--version` reference in the bug-report template. `[S/M]`
- [ ] Ecosystem: an "why not an add-on" note (Ingress assumes HA authenticates
      first; this must be reached first); GitHub topics; a
      community.home-assistant.io "Share your Projects" post linking demand
      discussions. `[S]`

## NICE

- [ ] Gate the HA version detail in `/healthz` behind auth. `[S]`
- [ ] README caution: no third-party security audit yet; be careful granting
      `control` over locks/alarms/garage doors. `[S]`
- [ ] Decide git-author identity (real name/email vs noreply) before the first
      push — trivial now, painful after forks. `[S]`
- [ ] cosign signing, Trivy scan, `THIRD_PARTY_LICENSES.md`, `ruff format
      --check`, coverage. `[S/M]`
- [ ] Evaluate a dedicated HACS "Plugin" repo for the admin panel (verify HACS
      subdirectory support). `[M]`

## Confirmed sound (do not re-litigate)

Secrets/leak sweep (tree + full git history) clean; admin-API path traversal not
possible (`_safe_filename`); admin-API auth gating complete; `call_service`
target resolution fails closed; XSS-escaped panel; permissive-only dependency
licenses; non-root Dockerfile; CI least-privilege with a human-gated publish job.

## Distribution decision

Standalone container (compose + Podman Quadlet) is the correct form — same as
every "reverse proxy in front of HA" tool. Not an HA add-on (Ingress model is
incompatible), not HACS for the gateway itself.
