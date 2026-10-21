# 04: Tenant store and hot reload

**Status:** done · **Crate:** erbridge-core · **Blocked by:** 03

**What to build:** `TenantStore` trait (`snapshot`, `redeem`, `issue`,
`revoke`), `MemoryStore`, `FileStore` (TOML, exclusive lock, atomic rename).
`serve` polls the file's mtime every second and applies changes.

## Acceptance

- Adding a tenant while serving makes it connectable without a restart.
- Disabling or removing tenant A ends A's session; B's session is untouched.
- Concurrent writers (two threads issuing codes) lose no entries.
- A corrupt file on reload keeps the previous snapshot and logs an error.
- Same behaviour suite runs against both store implementations.
