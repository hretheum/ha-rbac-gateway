# Contributing to ha-rbac-gateway

Thanks for looking into contributing. This project is a fail-closed authorization
gateway sitting in front of Home Assistant — correctness and conservative defaults
matter more than velocity. Please read the security section below before opening a PR.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the checks locally before pushing:

```bash
ruff check .
pytest
```

Both must pass cleanly. CI runs the same commands and will reject anything that doesn't.

## Making a change

1. Open an issue first for anything non-trivial (new features, allowlist changes,
   behavioral changes) so the approach can be discussed before you invest time in it.
2. Keep PRs focused — one logical change per PR. Unrelated cleanups belong in a
   separate PR.
3. Add or update tests for any behavior change. A change with no test coverage is
   a change nobody can verify stays correct after the next refactor.
4. Update relevant docs (`README.md`, `SECURITY.md`, docstrings) in the same PR as
   the code change, not as a follow-up.
5. Write commit messages and PR descriptions that explain *why*, not just *what*.

## Security-relevant changes

This is the part that gets extra scrutiny. A change is security-relevant if it
touches:

- the allowlist (which REST endpoints or WebSocket commands are permitted)
- policy evaluation (how a request is matched against a user's grants)
- authentication or session handling
- entity/area/domain filtering logic
- anything in the fail-closed / default-deny path

For these changes:

- **Tests proving deny behavior are required, not optional.** It's not enough to
  test that an allowed request succeeds — you must also test that a request just
  outside the granted scope is denied. If you added a new allowed pattern, add a
  test for the closest-but-not-quite-matching request that should still be
  rejected.
- **New allowlist entries must come with a documented filtering strategy.**
  Explain, in the PR description and in code comments where the entry lives, how
  the entry is filtered down to a restricted user's granted entities/areas/domains
  — not just that it's now reachable. "It's in the allowlist" is not a filtering
  strategy.
- If a change makes an ambiguous case resolve to "allow" instead of "deny", the
  PR description must justify why that ambiguity is safe to resolve that way.
  When in doubt, the reviewer will ask you to make it deny instead.
- Reviewers will push back harder on these PRs than on ordinary bug fixes. That's
  by design, not a reflection on the contribution.

## Code style

`ruff` is the source of truth for style and lint — if `ruff check .` is clean,
you're done. Don't fight the formatter; if a rule seems wrong, raise it as its
own issue rather than working around it silently.

## Reporting bugs vs. vulnerabilities

Regular bugs go through GitHub Issues using the bug report template.
Anything that looks like a way to bypass the allowlist or reach an endpoint a
restricted user shouldn't reach — see `SECURITY.md` and use GitHub Security
Advisories instead of a public issue.
