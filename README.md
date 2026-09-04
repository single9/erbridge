# erbridge

Low-latency TCP/UDP port forwarder with a built-in reverse-connection (NAT traversal) mode and a live traffic-monitoring TUI.

## Three modes

- **forward**: Direct forwarding, `external port -> internal target host:port`, supports TCP/UDP simultaneously, multiple mappings can be configured at once.
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
make dist      # package the Windows executable + config.example.toml into dist/windows/
```

## Quick start

### forward: direct forwarding

```sh
# No config file needed, single mapping at a time
erbridge forward --map "8080->10.0.0.5:80"          # forwards TCP+UDP by default
erbridge forward --map "5353->10.0.0.5:53/udp"      # UDP only
erbridge forward --map "8080->10.0.0.5:80" --map "5353->10.0.0.5:53/udp"

# Or use a config file (can describe multiple mappings at once, see config.example.toml)
erbridge --config config.toml forward
```

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

## Config file

See [`config.example.toml`](config.example.toml) for a complete example. The three sections are independent of each other; the same config file can fill in just one section or all of them. CLI arguments (`--listen`/`--token`/`--server`/`--map`/`--tunnel`) can override or supplement the config file's contents.

## Tests

```sh
make test    # equivalent to cargo test: covers forward's TCP/UDP forwarding, UDP idle timeout,
             # and serve/connect's multiplexed forwarding and token authentication
```
