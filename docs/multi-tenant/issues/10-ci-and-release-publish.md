# 10: CI and crates.io publishing

**Status:** todo · **Blocked by:** 09

**What to build:**

- `.github/workflows/ci.yml`: fmt, clippy, tests on push and pull request.
- `release.yml`: after the tag exists, publish `erbridge-core`, wait until the
  index has it, then publish `erbridge`. Uses the `CARGO_REGISTRY_TOKEN` secret.
  A failed publish does not undo the GitHub release but is reported.

## Acceptance

- CI passes on a clean checkout.
- Release workflow is syntax-checked (`actionlint` if available) and a dry run
  mode (`publish: false` input) exercises everything except the upload.
- The secret name and setup steps are documented in `RELEASING` notes in the
  README.
