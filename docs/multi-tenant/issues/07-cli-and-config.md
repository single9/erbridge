# 07: CLI, config and docs

**Status:** todo · **Crate:** erbridge · **Blocked by:** 06

**What to build:**

- `erbridge serve --tenants FILE --sni-listen ADDR` (and config keys).
- `erbridge serve-admin issue --tenants FILE --sni HOST [--max-conns N]
  [--expires-in SECS]` prints a code; `revoke NAME`; `list`.
- `erbridge enroll --server ADDR --code CODE [--out FILE]` writes credentials.
- `config.example.toml` and the README document the new mode.

## Acceptance

- Each command has a parsing test; `serve-admin` works on a file `serve` is
  running against.
- Errors for conflicting options are clear.
