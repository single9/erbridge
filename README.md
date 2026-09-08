# erbridge

Low-latency TCP/UDP port forwarder with a built-in reverse-connection (NAT traversal) mode and a live traffic-monitoring TUI.

## Four modes

- **forward**: Direct forwarding, `external port -> internal target host:port`, supports TCP/UDP simultaneously, multiple mappings can be configured at once. A per-mapping `secure`/`/tls` option can wrap the external (listen-side) TCP leg in TLS, optionally with a `token` (same scheme as `serve`/`connect`) so only an authenticated peer can connect.
- **client**: Companion to a `secure` forward mapping. Listens locally in plaintext and, for every connection, dials that mapping over TLS (presenting its `token` if one is set), so a plain local client doesn't need its own TLS support to reach it.
- **serve** (reverse mode, role A): Listens and waits for `connect` (B) to connect in; traffic received on the externally exposed port is then multiplexed and forwarded to B over that A↔B connection.
- **connect** (reverse mode, role B): Actively connects to `serve` (A); every time A receives a new external connection, it opens a new multiplexed stream over the same connection, and B decides which local (or B-reachable internal) target to forward to based on the tunnel name carried by the stream.

Suitable scenario: A sits in front of the public network/firewall while B (the internal host where the actual service runs) cannot be reached directly by A and can only dial out; in that case use `serve`/`connect` to establish a reverse tunnel. When A and B can reach each other directly, just run `forward` on each side — no need for reverse mode.

### forward connection diagram

```
 external client                   erbridge forward                  internal target
 +------------+              +-------------------------+              +------------+
 |            | -----------> | listen 0.0.0.0:8080     | -----------> |            |
 |   client   | <----------- |   -> 10.0.0.5:80        | <----------- |   target   |
 |            |              | (--map / [[forward]])   |              |            |
 +------------+              +-------------------------+              +------------+
```

With `secure`/`/tls` set on a mapping, the listen-side leg is TLS-wrapped (self-signed
cert, generated at startup); the erbridge-to-target leg is unchanged and stays plaintext:

```
 external client                   erbridge forward                  internal target
 +------------+              +-------------------------+              +------------+
 |            | ===TLS=====> | listen 0.0.0.0:8443     | -----------> |            |
 |   client   | <===TLS===== |   -> 10.0.0.5:80        | <----------- |   target   |
 |            |              | (secure = true)         |              |            |
 +------------+              +-------------------------+              +------------+
```

If the mapping also sets a `token`, a plain TLS client (`curl -k`, ...) can no longer
connect on its own — it also has to speak the token handshake right after the TLS
handshake. Use `client` mode as that connecting peer instead, so your own app keeps
talking plaintext to a local port:

```
 your app        erbridge client                erbridge forward (on A)             internal target
 +--------+   +------------------------+   +---------------------------+            +------------+
 |        |-->| listen 127.0.0.1:1080  |==>| listen 0.0.0.0:8443       |----------->|            |
 | client |<--|   -> A_IP:8443         |<==|   -> 10.0.0.5:80          |<-----------|   target   |
 |        |   | (--token change-me)    |   | (secure=true, token=...) |            |            |
 +--------+   +------------------------+   +---------------------------+            +------------+
                          TLS + token handshake
```

### serve / connect connection diagram

Stage 1: B actively connects to A, establishing an encrypted, token-authenticated control channel.

```
 A (serve)                                     B (connect)
 +--------------------------+                  +--------------------------+
 | listen 0.0.0.0:9000      |                  | dial A:9000              |
 | (control channel)        |<================ | authenticate with token  |
 | waits for B to dial in   |                  | retry w/ backoff on drop |
 +--------------------------+                  +--------------------------+
                              TLS + token handshake
```

Stage 2: Once the control channel is established, every external connection received on A's
externally exposed port opens a new yamux stream multiplexed over the same A<->B connection,
tagged with the tunnel name and handed to B; B decides which local target to forward to based
on the name. Multiple external clients share the same A<->B connection, each corresponding to
its own independent stream.

```
 external client                A (serve)                         B (connect)               internal target
 +------------+      +---------------------------+      +---------------------------+      +------------+
 |            | ---> | external 0.0.0.0:8081     | ===> |                           | ---> |            |
 |   client   | <--- | open yamux stream,        | <=== | accept stream, read       | <--- |   target   |
 |            |      | tag it "web"              |      | "web", dial local target  |      |            |
 +------------+      +---------------------------+      +---------------------------+      +------------+
```

## Build

```sh
cargo build --release
```

Cross-compilation (mirrors the other Rust sub-projects in this repo):

```sh
make windows   # -> target/x86_64-pc-windows-gnu/release/erbridge.exe (on macOS, first: brew install mingw-w64)
make linux     # -> target/x86_64-unknown-linux-musl/release/erbridge
make osx       # -> universal (Apple Silicon + Intel) build, one binary per arch under target/<target>/release/erbridge
make osx-x86   # -> target/x86_64-apple-darwin/release/erbridge (Intel only, no lipo)
make dist      # package the Windows executable + config.example.toml into dist/windows/
make dist-osx      # lipo the two osx builds into a universal binary + config.example.toml under dist/osx/
make dist-osx-x86  # package the Intel-only osx-x86 build + config.example.toml under dist/osx/
```

## Releases

Prebuilt binaries for Windows, Linux, and macOS (universal) are published from the
[Release workflow](.github/workflows/release.yml). Trigger it manually from the Actions tab
("Run workflow") and pick a version bump (`patch`/`minor`/`major`); it advances the version
tag, regenerates [`CHANGELOG.md`](CHANGELOG.md) from [Conventional Commits](https://www.conventionalcommits.org/)
with [git-cliff](https://github.com/orhun/git-cliff) (config: [`cliff.toml`](cliff.toml)),
builds every platform, and publishes a GitHub release with the archives, that release's
changelog section as the release notes, plus a signed `SHA256SUMS` manifest.

Verify a downloaded archive against the release:

```sh
# 1. Check the manifest itself hasn't been tampered with (keyless Sigstore signature)
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/.+/\.github/workflows/release\.yml@.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

# 2. Check the archive you downloaded matches the manifest
sha256sum -c SHA256SUMS --ignore-missing
```

## Quick start

### forward: direct forwarding

```sh
# No config file needed, single mapping at a time
erbridge forward --map "8080->10.0.0.5:80"          # forwards TCP+UDP by default
erbridge forward --map "5353->10.0.0.5:53/udp"      # UDP only
erbridge forward --map "8080->10.0.0.5:80" --map "5353->10.0.0.5:53/udp"

# Secure forward: wraps the listen-side TCP connection in TLS, so
# external client -> erbridge is encrypted; erbridge -> target stays plaintext.
# `/tls` is shorthand for `/tcp+tls` (secure only supports tcp, not udp/both).
erbridge forward --map "8443->10.0.0.5:80/tls"
```

The cert is a fresh self-signed one generated on every start (same trust model as
`serve`/`connect` — see Security notes below), so a client connecting to it must
skip certificate verification:

```sh
curl -k https://<erbridge_host>:8443/...
openssl s_client -connect <erbridge_host>:8443
```

```sh
# Or use a config file (can describe multiple mappings at once, see config.example.toml)
erbridge --config config.toml forward
```

### client: reach a secure forward mapping without your own TLS support

Add `--token` on the secure mapping to also require authentication (same length-prefixed,
constant-time-compared token as `serve`/`connect`) — after that, only `client` mode (or
something implementing the same handshake) can connect, not a bare TLS client:

```sh
# on A (the secure forward mapping, now token-gated):
erbridge forward --map "8443->10.0.0.5:80/tls" --token change-me
```

```sh
# on your computer: local plaintext port -> TLS + token -> A's mapping
erbridge client --map "1080->A_IP:8443" --token change-me
```

Your app then just talks plaintext to `127.0.0.1:1080`; `client` handles the TLS
handshake and token exchange to A on its behalf. Repeat `--map` for multiple mappings;
see the `[[client]]` section in `config.example.toml` for the config-file form.

### serve / connect: reverse connection

A (listens and waits for B, and exposes a port externally):

```sh
erbridge serve --listen 0.0.0.0:9000 --token change-me --tunnel "web=0.0.0.0:8081"
```

B (connects to A, forwards received traffic to a local service):

```sh
erbridge connect --server A_IP:9000 --token change-me --tunnel "web=127.0.0.1:80"
```

Both sides use the same `NAME` in `--tunnel NAME=...` to correspond to the same tunnel; repeat the flag to define multiple tunnels. For the config-file syntax, see the `[serve]` / `[connect]` sections in `config.example.toml`.

After B disconnects, A's external listening port does not close; new connections wait for B to reconnect. B automatically retries connecting back to A with exponential backoff (`reconnect_min_secs` ~ `reconnect_max_secs`).

## Observing traffic

By default an interactive TUI (ratatui) opens, showing aggregate traffic, a per-connection list (source/destination/protocol/bytes/lifetime), and an event log; it is read-only and cannot control connections. Press `q` / `Esc` / `Ctrl+C` to exit.

For background/service mode use `--headless`, which writes structured JSON lines to a log file (default `erbridge.log`, path can be set with `--log-file`) instead of starting the TUI:

```sh
erbridge --headless --log-file /var/log/erbridge.log serve --config config.toml
```

## Security notes

The A↔B connection in reverse mode is encrypted with an auto-generated self-signed TLS certificate; authentication relies on a shared token compared after the connection is established, not on a certificate chain — this design avoids requiring users to manage certificates. This means TLS here only provides confidentiality/integrity and does **not** verify peer identity; if the network between A and B is itself untrusted (no VPN or other trusted underlying channel), a man-in-the-middle that can intercept traffic can also obtain the token. This is fine to use over an internal network or an existing VPN; if you need to cross an untrusted network, it is recommended to add an additional trusted channel on top.

`forward`'s optional `secure`/`/tls` mode uses the same self-signed, unauthenticated-identity TLS: it stops passive eavesdropping on the external-client-to-erbridge leg but does not prove erbridge's identity to the client, so a client connecting to it should expect (and typically must configure itself to accept) a certificate it cannot otherwise verify. It only covers that one leg — TCP only, since TLS has no UDP equivalent here — the erbridge-to-target leg remains plaintext.

Adding a `token` to a secure mapping layers on the same post-handshake, constant-time-compared token check `serve`/`connect` uses — it restricts *who* can connect (only a peer that knows the token and speaks the same length-prefixed frame, i.e. `client` mode), but doesn't change what the TLS layer itself does or doesn't prove; the same caveats above still apply.

## Config file

See [`config.example.toml`](config.example.toml) for a complete example. The sections are independent of each other; the same config file can fill in just one section or all of them. CLI arguments (`--listen`/`--token`/`--server`/`--map`/`--tunnel`) can override or supplement the config file's contents.

## Tests

```sh
make test    # equivalent to cargo test: covers forward's TCP/UDP forwarding, UDP idle timeout,
             # secure/token-gated forward mappings, client mode against them, and serve/connect's
             # multiplexed forwarding and token authentication
```

## Latency benchmark

```sh
make bench   # equivalent to: cargo bench --bench latency
```

`benches/latency.rs` measures steady-state TCP round-trip latency (a 64-byte
ping over an already-open connection, not connection setup) across the three
data paths, all on loopback:

- `baseline_direct_tcp_roundtrip` — client <-> echo server, no erbridge
- `forward_tcp_roundtrip` — client <-> `forward` <-> echo server
- `reverse_tunnel_tcp_roundtrip` — client <-> `serve` (A) <=yamux/TLS=> `connect` (B) <-> echo server

Criterion prints p-value-style `[low mid high]` estimates per run and writes
an HTML report with full distributions to `target/criterion/report/index.html`.
Compare `forward`/`reverse` against `baseline` to get erbridge's added
latency; loopback numbers isolate erbridge's own per-message overhead but
don't include real network RTT — for that, run the same three modes over an
actual link and drive them with `wrk`/`hey` (HTTP) or `iperf3 -u` (UDP
throughput/jitter) instead.

### Comparing against frp / rathole / bore

```sh
make compare-tunnels   # equivalent to: cargo run --release --example compare_tunnels
```

`examples/compare_tunnels.rs` runs the same persistent-connection ping-pong
against erbridge's `serve`/`connect` reverse tunnel and three other NAT-traversal
tools — [frp](https://github.com/fatedier/frp), [rathole](https://github.com/rathole-org/rathole),
and [bore](https://github.com/ekzhang/bore) — all on the same machine, same
payload, same warmup/iteration count, so the numbers are comparable to each
other (unlike published benchmarks elsewhere, which use different payloads,
units, and hardware — see the caveats in the latency report). It compares
against erbridge's *reverse* mode specifically, not `forward`, since frp/rathole/bore
only implement the dial-out/reverse case.

Needs `frpc`, `frps`, `rathole`, and `bore` on `PATH` (`brew install frpc frps
rathole bore-cli`, or point `FRPC_BIN`/`FRPS_BIN`/`RATHOLE_BIN`/`BORE_BIN` at
prebuilt binaries). A missing tool is skipped with a note, not fatal — the
rest of the comparison still runs. Per-process logs land in a temp dir printed
at the top of the output.

## License

[MIT](LICENSE)
