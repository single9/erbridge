# erbridge

A low-latency TCP/UDP port forwarder and reverse (NAT-traversal) tunnel with a
terminal UI. It can also run as a multi-tenant server: many users, each with
their own token and hostname, routed by TLS SNI without decrypting the traffic.

```sh
cargo install erbridge
erbridge --help
```

See the [project README](https://github.com/single9/erbridge#readme) for the
four modes (`forward`, `client`, `serve`, `connect`), multi-tenant `serve`,
`serve-admin` and `enroll`, security notes, and prebuilt binaries.

The reusable library is [`erbridge-core`](https://crates.io/crates/erbridge-core).

MIT licensed.
