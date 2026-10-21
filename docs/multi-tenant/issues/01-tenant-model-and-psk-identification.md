# 01: Tenant model and PSK identification

**Status:** todo · **Crate:** erbridge-core · **Blocked by:** none

**What to build:** socket-free tenant types and the handshake that picks a
tenant by trying each PSK.

- `tenant` module: `Tenant`, `EnrollCode`, `TenantSet` (immutable snapshot with
  lookup by name and by sni).
- `noise::accept_any(io, candidates)`: reads handshake message 1 once, tries each
  candidate PSK on a fresh responder, finishes the handshake with the one that
  verifies, returns the stream and the matched index.

## Acceptance

- With three candidates, each matching PSK identifies the right one.
- No match returns an error and writes nothing to the socket.
- Handshake interoperates with the existing `noise::connect`.
- Unit tests, no sockets beyond an in-memory duplex.
