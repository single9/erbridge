# Multi-tenant `serve`: scope (not yet implemented)

Status: scoped only. Nothing here is built. Domain names, TLS certificates and
payment are out of scope; erbridge treats a tenant's `sni` as an opaque string.

## Goals

1. **Tenant table.** Each tenant has its own token, a server-assigned name, an
   `sni` routing key and a `max_conns` limit. The legacy single `[serve] token`
   plus `[[serve.tunnel]]` form keeps working.
2. **Handshake tries each PSK.** `Noise_NNpsk0` mixes the PSK in before the
   first message, so the responder reads message 1 once and tries each tenant's
   PSK on a fresh responder. The first AEAD success identifies the tenant. Wire
   format is unchanged; old `connect` binaries still work. A wrong token and an
   unknown tenant are indistinguishable (connection just closes).
3. **Tenant is bound to its tunnel.** The tunnel name a `connect` sends is
   ignored; `serve` decides it from the matched tenant.
4. **SNI routing.** One public listener reads the TLS ClientHello SNI (no
   decryption) and hands the connection to the matching tenant's session.
5. **Per-tenant connection cap** (`max_conns`).
6. **Single-use enrollment codes.** An operator issues a code. `connect
   --enroll CODE` handshakes with PSK = code (tried like any tenant PSK); inside
   the encrypted channel `serve` generates a random tenant name and a long-term
   token, persists them, returns them, and burns the code. Later connections use
   the token. Codes may carry an expiry.
7. **Persistent tenant file, watched for changes.** Replaces SIGHUP and an admin
   API: edits (add, revoke) apply without a restart and never disturb other
   tenants' sessions. `erbridge serve-admin issue|revoke` edits the same file.

## Non-goals (deferred)

- Admin HTTP API, bandwidth limits, idle timeouts.
- TLS termination, HTTP Host routing, ACME, domain and certificate handling.
- Open self-registration without a code (abuse and name squatting).

## Acceptance tests (write first)

1. Two tenants connected at once; traffic never crosses.
2. Tenant A claims B's tunnel name; it still reaches only A.
3. Wrong token is indistinguishable from an unknown tenant.
4. Revoking A leaves B's session up.
5. An enrollment code works once; a second use fails; an expired code fails.

## Library readiness (prerequisites for embedding)

The project is a workspace: `erbridge-core` (the library) and `erbridge` (the
CLI and TUI binary). Done: the split, `run_serve_with_shutdown` /
`run_connect_with_shutdown`, and `Registry::subscribe`. Still to do:

- Tenant logic goes in a socket-free core module behind a `TenantStore` trait
  (in-memory and file-backed impls) so a host can plug in its own storage and
  the logic is unit-testable without sockets.

## Estimate

About 3 days for items 1-7, including the `TenantStore` module.
