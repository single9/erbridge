# 09: crates.io publish preparation

**Status:** todo · **Blocked by:** 07

**What to build:** metadata and layout so both crates pass `cargo publish
--dry-run`.

- `[workspace.dependencies] erbridge-core = { path, version }`, version bumped
  together with the workspace version.
- `repository`, `readme`, `keywords`, `categories`, `rust-version`, per-crate
  README, `exclude` for non-source files.
- Release workflow keeps the dependency version in sync.

## Acceptance

- `cargo publish --dry-run -p erbridge-core` passes.
- `cargo package -p erbridge --list` shows only intended files; `erbridge`
  verifies against a local registry or `--no-verify` documented until core exists
  upstream.
