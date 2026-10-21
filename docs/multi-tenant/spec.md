# Multi-tenant `serve`

Status: in progress. Tickets are in `issues/`, built in numeric order.

Domain names, TLS certificates and payment are out of scope. erbridge treats a
tenant's `sni` as an opaque host string and never terminates TLS: it reads the
ClientHello's SNI and relays the bytes untouched.

## Problem

Today `serve` has one shared token and a fixed `[[serve.tunnel]]` list, and
accepts one `connect` at a time. A host that wants to serve many independent
users from one `serve` process (each behind their own hostname, each with their
own secret) cannot.

## Model

- **Tenant:** `name` (server-assigned, `t-` + 8 hex), `psk` (hex of
  `derive_psk(token)`; the token itself is never stored), `sni`, `max_conns`
  (default 64), `disabled`.
- **Enrollment code:** a single-use PSK, optionally expiring, bound to an `sni`
  and `max_conns`, redeemed into a tenant.
- **Tenant file:** TOML, the source of truth. `serve` watches it; `serve-admin`
  and enrollment edit it.
- **Modes:** legacy (`[serve] token` + `[[serve.tunnel]]`, unchanged) or
  multi-tenant (`[serve] tenants_file` + `sni_listen`). Setting both is an error.

## Behaviour

1. **Identification.** `Noise_NNpsk0` mixes the PSK in before message 1, so the
   responder reads message 1 once and tries each candidate PSK on a fresh
   responder; the first AEAD success identifies the tenant (or an enrollment
   code). Wire format is unchanged, so existing `connect` binaries work. A wrong
   token and an unknown tenant are indistinguishable: the connection closes.
2. **Isolation.** A tenant owns one session slot and one routing key. The tunnel
   header `serve` sends to `connect` is the tenant's `name`, decided by `serve`;
   nothing the client says picks a tunnel.
3. **Routing.** `sni_listen` accepts TCP, reads the first TLS record (at most
   16 KiB, 5 s), parses the ClientHello SNI (case-insensitive exact match),
   opens a stream on the matching tenant's session, replays the buffered bytes,
   then pumps. No SNI, unknown SNI, disabled tenant or offline tenant: close
   without replying. Limitation: the ClientHello must fit in one TLS record.
4. **Sessions.** A new authenticated session for a tenant replaces the old one
   (a reconnecting client must not wait for a dead TCP connection to time out).
   Disabling or removing a tenant ends its session and leaves others untouched.
5. **Limits.** `max_conns` caps concurrent relayed connections per tenant;
   excess connections are closed.
6. **Enrollment.** `connect`-side `enroll(server, code)` handshakes with PSK =
   code. Inside the encrypted channel `serve` burns the code, creates the tenant
   (random name, random 32-byte hex token), persists it, and sends
   `{name, token, sni}`. Later connections use the token. Redemption is atomic
   under a file lock; a code works once and not after expiry.
7. **Store.** `TenantStore` trait with in-memory and file-backed
   implementations. The file is written by atomic rename under an exclusive
   lock; `serve` polls its mtime once a second and applies changes without
   restarting.

## Non-goals

Admin HTTP API, bandwidth limits, idle timeouts, TLS termination, Host
routing, ACME, open self-registration without a code.

## Library readiness

Done: the `erbridge-core` / `erbridge` workspace split,
`run_serve_with_shutdown` / `run_connect_with_shutdown`, `Registry::subscribe`.
Remaining: the socket-free tenant module behind `TenantStore` (ticket 01, 04).

## Release

`erbridge-core` and `erbridge` are published to crates.io by the release
workflow, core first (tickets 09, 10).
