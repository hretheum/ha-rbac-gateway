## Summary

<!-- What does this PR do, and why? -->

## Security-relevant?

<!--
Mark yes if this touches the allowlist, policy evaluation, auth handling, or
entity/area/domain filtering. See CONTRIBUTING.md for what that means in
practice.
-->

- [ ] This PR touches the allowlist, policy evaluation, auth handling, or
      filtering logic.

If checked: describe the filtering strategy for any new allowlist entries,
and confirm the deny-path tests below cover the closest-but-not-matching
case, not just the happy path.

## Checklist

- [ ] Tests added/updated for the behavior change (for security-relevant
      changes: includes tests proving the deny path, not just the allow path)
- [ ] `ruff check .` is clean
- [ ] Docs updated (`README.md`, `SECURITY.md`, docstrings) if behavior or
      configuration changed
- [ ] No real deployment values (IPs, hostnames, tokens, credentials) appear
      anywhere in the diff
