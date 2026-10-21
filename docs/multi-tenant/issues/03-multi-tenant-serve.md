# 03: Multi-tenant serve with SNI routing

**Status:** done · **Crate:** erbridge-core · **Blocked by:** 01, 02

**What to build:** `ServeConfig` gains `tenants_file` and `sni_listen`;
`run_serve_with_shutdown` runs the multi-tenant mode when `tenants_file` is set
(in-memory store from the file at start, hot reload comes in 04). Per-tenant
session slots; new session replaces the old; header sent to `connect` is the
tenant name.

## Acceptance

- Two tenants connected at once; traffic never crosses.
- Tenant A's `connect` claims B's tunnel name; it still reaches only A.
- Wrong token is indistinguishable from an unknown tenant (both just close).
- Unknown / missing SNI and offline tenant close without a reply.
- Setting both `token`/`tunnel` and `tenants_file` is a config error.
- Legacy mode tests still pass unchanged.
- Shutdown stops everything and frees ports.
