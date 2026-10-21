# 05: Per-tenant connection limit

**Status:** done · **Crate:** erbridge-core · **Blocked by:** 03

**What to build:** `max_conns` enforced per tenant with a semaphore; excess
connections are closed immediately.

## Acceptance

- With `max_conns = 2`, a third simultaneous connection is closed while the
  first two keep working; after one closes a new one is accepted.
- One tenant at its limit does not affect another tenant.
- Changing `max_conns` in the file applies to new connections after reload.
