# erbridge-core

The library behind [`erbridge`](https://github.com/single9/erbridge): TCP/UDP
forwarding and reverse (NAT-traversal) tunnels secured with the Noise protocol,
plus a multi-tenant server that routes TLS connections to tenants by SNI without
decrypting them.

- `reverse::serve` / `reverse::connect`: the two roles of a reverse tunnel, each
  with a `*_with_shutdown` variant that stops cleanly on a `CancellationToken`.
- `reverse::tenant_serve`: many tenants on one `serve`, each with its own token
  and host, identified by which PSK completes the Noise handshake.
- `reverse::enroll`: trade a single-use code for a new tenant's credentials.
- `tenant`, `tenant_store`: tenants, enrollment codes and the `TenantStore` trait
  (in-memory and file-backed implementations).
- `stats::Registry`: live connections and a structured event stream
  (`Registry::subscribe`).

The command-line tool and terminal UI are in the separate
[`erbridge`](https://crates.io/crates/erbridge) crate, so depending on this one
pulls in neither.

See the [project README](https://github.com/single9/erbridge#readme) for usage
and an embedding example, and `docs/multi-tenant/spec.md` for the multi-tenant
design.

MIT licensed.
