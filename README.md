# erbridge

Low-latency TCP/UDP port forwarder with a built-in reverse-connection (NAT traversal) mode and a live traffic-monitoring TUI.

## Four modes

- **forward**: Direct forwarding, `external port -> internal target host:port`, supports TCP/UDP simultaneously, multiple mappings can be configured at once. A per-mapping `transport` option can wrap the external (listen-side) TCP leg in TLS or Noise, optionally with a `token` so only an authenticated peer can connect.
- **client**: Companion to a `transport`-secured forward mapping. Listens locally in plaintext and, for every connection, dials that mapping using the same transport (presenting its `token` if one is set), so a plain local client doesn't need its own TLS/Noise support to reach it.
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

With `transport = "tls"` set on a mapping, the listen-side leg is TLS-wrapped (self-signed
cert, generated at startup); the erbridge-to-target leg is unchanged and stays plaintext:

```
 external client                   erbridge forward                  internal target
 +------------+              +-------------------------+              +------------+
 |            | ===TLS=====> | listen 0.0.0.0:8443     | -----------> |            |
 |   client   | <===TLS===== |   -> 10.0.0.5:80        | <----------- |   target   |
 |            |              | (transport = "tls")     |              |            |
 +------------+              +-------------------------+              +------------+
```

If the mapping also sets a `token`, a plain TLS client (`curl -k`, ...) can no longer
connect on its own — it also has to speak the token handshake right after the TLS
handshake. Use `client` mode as that connecting peer instead, so your own app keeps
talking plaintext to a local port:

```
 your app        erbridge client                erbridge forward (on A)                internal target
 +--------+   +------------------------+   +------------------------------+            +------------+
 |        |-->| listen 127.0.0.1:1080  |==>| listen 0.0.0.0:8443          |----------->|            |
 | client |<--|   -> A_IP:8443         |<==|   -> 10.0.0.5:80             |<-----------|   target   |
 |        |   | (--token change-me)    |   | (transport=tls, token=...)   |            |            |
 +--------+   +------------------------+   +------------------------------+            +------------+
                          TLS + token handshake
```

`transport = "noise"` is the same shape, but there's no generic client for it the way
`curl -k` speaks TLS — it only ever interoperates with erbridge's own `client` mode, and
`token` is mandatory (it's hashed into the Noise handshake's pre-shared key, not checked
as a separate step afterward). Use it when both ends are always erbridge, for a faster
handshake and authentication that's cryptographically bound to the session rather than
exchanged in a plaintext frame after the fact.

### serve / connect connection diagram

Stage 1: B actively connects to A, establishing a Noise-encrypted control channel whose
handshake is itself authenticated by the shared token (see Security notes below).

```
 A (serve)                                     B (connect)
 +--------------------------+                  +--------------------------+
 | listen 0.0.0.0:9000      |                  | dial A:9000              |
 | (control channel)        |<================ | token is the handshake's |
 | waits for B to dial in   |                  | PSK; retry w/ backoff    |
 +--------------------------+                  +--------------------------+
                              Noise_NNpsk0 handshake
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

The repository is a Cargo workspace with two crates: `erbridge-core` (the library) and
`erbridge` (the command-line binary, with the terminal UI).

```sh
cargo build --release    # -> target/release/erbridge
```

Cross-compilation (mirrors the other Rust sub-projects in this repo):

```sh
make windows   # -> target/x86_64-pc-windows-gnu/release/erbridge.exe (on macOS, first: brew install mingw-w64)
make linux     # -> target/x86_64-unknown-linux-musl/release/erbridge
make linux-arm # -> target/aarch64-unknown-linux-musl/release/erbridge (needs `cross`: cargo install cross --git https://github.com/cross-rs/cross; builds via Docker)
make osx       # -> universal (Apple Silicon + Intel) build, one binary per arch under target/<target>/release/erbridge
make osx-arm   # -> target/aarch64-apple-darwin/release/erbridge (Apple Silicon only, no lipo)
make osx-x86   # -> target/x86_64-apple-darwin/release/erbridge (Intel only, no lipo)
make dist          # package the Windows executable + config.example.toml into dist/windows/
make dist-linux-arm # package the aarch64 Linux build + config.example.toml into dist/linux-arm64/
make dist-osx      # lipo the two osx builds into a universal binary + config.example.toml under dist/osx/
make dist-osx-arm  # package the Apple-Silicon-only osx-arm build + config.example.toml under dist/osx/
make dist-osx-x86  # package the Intel-only osx-x86 build + config.example.toml under dist/osx/
```

## Install

### Download a prebuilt binary

Grab an archive for your platform from the
[Releases page](https://github.com/single9/erbridge/releases/latest) (`erbridge-<version>-linux.tar.gz`,
`-linux-arm64`, `-osx` (universal), `-osx-arm64`, `-osx-x86_64`, or `-windows.zip`), then:

```sh
tar -xzf erbridge-*-linux.tar.gz         # extracts erbridge + config.example.toml
sudo install -m 755 erbridge /usr/local/bin/erbridge
```

Each release also publishes a signed `SHA256SUMS` manifest; verify the archive against it
before extracting if you want to confirm integrity:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

### Build and install with cargo

Install the `erbridge` binary onto your system's `PATH` via `cargo install`:

```sh
cargo install --path crates/erbridge
```

This builds a release binary and copies it to `~/.cargo/bin/erbridge` (make sure that
directory is on your `PATH`; `cargo install` prints a warning if it isn't). Run
`cargo install --path crates/erbridge --force` to reinstall after pulling new changes.

### Run as a systemd service (Linux)

A template unit is provided at
[`packaging/systemd/erbridge.service`](packaging/systemd/erbridge.service). It runs
erbridge `--headless` (JSON logs instead of the TUI) against `/etc/erbridge/config.toml`;
edit its `ExecStart` line to pick the subcommand (`forward`/`client`/`serve`/`connect`) and
adjust paths, then install the binary to `/usr/local/bin` (the service runs as a dedicated
`erbridge` system user with no home directory, so it can't resolve `~/.cargo/bin` --
use a downloaded release archive, or `cargo build --release` and install the resulting
`target/release/erbridge`):

```sh
sudo install -m 755 erbridge /usr/local/bin/erbridge
sudo useradd --system --no-create-home erbridge   # skip if the user already exists
sudo mkdir -p /etc/erbridge
sudo cp config.example.toml /etc/erbridge/config.toml   # then edit it
sudo cp packaging/systemd/erbridge.service /etc/systemd/system/erbridge.service
sudo systemctl daemon-reload
sudo systemctl enable --now erbridge
```

## Releases

Prebuilt binaries for Windows (x86_64), Linux (x86_64 and arm64), and macOS (universal, plus
separate arm64/x86_64-only archives) are published from the
[Release workflow](.github/workflows/release.yml). Trigger it manually from the Actions tab
("Run workflow") and pick a version bump (`auto` by default, or `patch`/`minor`/`major`); it
advances the version tag, regenerates [`CHANGELOG.md`](CHANGELOG.md) from [Conventional Commits](https://www.conventionalcommits.org/)
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

### Choosing the version

`auto` reads the [Conventional Commits](https://www.conventionalcommits.org/) since the last
release tag (rules in [`.github/scripts/next-version.sh`](.github/scripts/next-version.sh)):

| Commits since the last release | Next version |
| --- | --- |
| a breaking change (`type!:` or a `BREAKING CHANGE:` footer) | major, or **minor while the version is 0.x** |
| a `feat:` | minor |
| anything else (`fix:`, `docs:`, `build:`, ...) | patch |
| none | the release stops with an error |

Mark breaking changes, including API changes to `erbridge-core`, with `!`: once the project is
at 1.0 an unmarked one would be released as a minor version. Choose `patch`/`minor`/`major`
explicitly to override `auto`. The rules are tested in CI
(`.github/scripts/test-next-version.sh`).

### Publishing to crates.io

`erbridge-core` and `erbridge` are published by the Release workflow, core first. The last job
(`publish-crates`) runs only after every binary built and the GitHub release exists.

One-time setup:

1. On crates.io, create an API token with the `publish-new` and `publish-update` scopes
   (restrict it to the `erbridge` and `erbridge-core` crates once they exist).
2. In the GitHub repo, add it as the secret `CARGO_REGISTRY_TOKEN` (repository secret, or a
   secret of the `crates-io` environment, which the job uses; add required reviewers to that
   environment if you want a manual approval before anything is published).

The first release has to create both crate names, so the token needs `publish-new` at that point.

Run the workflow with **publish** unticked for a dry run: it builds and packages everything and
skips only the upload. The CI workflow does the same check on every push
(`cargo publish --workspace --dry-run`). Publishing is permanent, so a bad release is fixed by
yanking the version and releasing the next patch.

If only `publish-crates` failed (for example an expired token), fix the secret and publish the
tag by hand:

```sh
git checkout vX.Y.Z && cargo publish --workspace
```

## Upgrading

### From 0.2 to 0.3

**Using the `erbridge` command: nothing to change.** The commands, flags and config files are
the same, and the wire protocol is unchanged, so old and new builds interoperate: a 0.2
`connect` works against a 0.3 `serve` (including its multi-tenant mode) and the other way
round, and `forward`/`client` with `noise` also mix. You can upgrade one side at a time.

One thing differs if you build from source: the binary crate moved, so install with

```sh
cargo install --path crates/erbridge     # was: cargo install --path .
```

(`cargo build --release` at the repository root still produces `target/release/erbridge`.)

**Using erbridge as a library: three changes.** Nothing was ever published to crates.io, so this
only affects programs that depend on it by `path` or `git`.

- The library is now the `erbridge-core` crate, imported as `erbridge_core` (it was `erbridge`).
  The `cli` and `tui` modules are no longer part of it.
- `config::ServeConfig` gained two fields, `tenants_file` and `sni_listen`, and implements
  `Default`. A struct literal needs `..Default::default()` added.
- New and optional: `run_serve_with_shutdown`, `run_connect_with_shutdown`,
  `Registry::subscribe`, and the multi-tenant API (`tenant`, `tenant_store`,
  `reverse::tenant_serve`, `reverse::enroll`). The existing `run_serve` and `run_connect` are
  unchanged.

## Quick start

### forward: direct forwarding

```sh
# No config file needed, single mapping at a time
erbridge forward --map "8080->10.0.0.5:80"          # forwards TCP+UDP by default
erbridge forward --map "5353->10.0.0.5:53/udp"      # UDP only
erbridge forward --map "8080->10.0.0.5:80" --map "5353->10.0.0.5:53/udp"

# Secure forward: wraps the listen-side TCP connection in TLS, so
# external client -> erbridge is encrypted; erbridge -> target stays plaintext.
# `/tls` is shorthand for `/tcp+tls` (a transport only supports tcp, not udp/both).
erbridge forward --map "8443->10.0.0.5:80/tls"
```

The cert is a fresh self-signed one generated on every start (see Security notes below),
so a client connecting to it must skip certificate verification:

```sh
curl -k https://<erbridge_host>:8443/...
openssl s_client -connect <erbridge_host>:8443
```

```sh
# Or use a config file (can describe multiple mappings at once, see config.example.toml)
erbridge --config config.toml forward
```

If both ends are always erbridge (no generic TLS client needs to reach this mapping
directly), `/noise` wraps it in the Noise protocol instead — faster handshake, and a
mandatory token that's cryptographically bound into it rather than checked afterward:

```sh
erbridge forward --map "8444->10.0.0.5:80/noise" --token change-me
```

### client: reach a secured forward mapping without your own TLS/Noise support

Add `--token` on the secure mapping to also require authentication (mandatory under
`/noise`; under `/tls`, optional and checked in a length-prefixed frame right after the
handshake) — after that, only `client` mode (or something implementing the same
handshake) can connect, not a bare TLS client:

```sh
# on A (the secure forward mapping, now token-gated):
erbridge forward --map "8443->10.0.0.5:80/tls" --token change-me
```

```sh
# on your computer: local plaintext port -> TLS + token -> A's mapping
erbridge client --map "1080->A_IP:8443" --token change-me
```

`client`'s `--map` also takes a `/tls`/`/noise` modifier naming the far side's transport,
defaulting to `/tls`:

```sh
erbridge client --map "1081->A_IP:8444/noise" --token change-me
```

Your app then just talks plaintext to the local port; `client` handles the transport's
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

### Multi-tenant serve: many clients, one server

A single `serve` can host many independent users, each with their own secret and their own
hostname. Clients are told apart by which token they hold, and TLS visitors are routed by the
SNI in their ClientHello. `serve` never decrypts the TLS traffic; it relays the bytes.

```sh
# On the server. The tenant file starts empty (or missing).
erbridge serve --listen 0.0.0.0:9000 --tenants tenants.toml --sni-listen 0.0.0.0:443

# Hand a user a single-use code for a hostname (works while serve is running):
erbridge serve-admin --tenants tenants.toml issue --sni abc123.example.com --expires-in 86400

# On the user's machine: trade the code for credentials, then connect.
erbridge enroll --server A_IP:9000 --code <CODE> --out credentials.toml
erbridge connect --server A_IP:9000 --credentials credentials.toml --target 127.0.0.1:8080
```

`serve-admin` also has `list`, `disable NAME`, `enable NAME` and `revoke NAME`. Revoking or
disabling a tenant ends its session and leaves everyone else's untouched.

- A code works once and may expire. It is stored only as a hash, and a newly issued code is
  usable within a second (the file is re-read every second).
- Enrolling creates the tenant with a server-chosen name and a random token. The token is shown
  once, in `credentials.toml` (mode 0600, never overwritten).
- A tenant's tunnel name is decided by `serve`, so a client cannot steer traffic at someone
  else's target. A wrong token and an unknown tenant look identical: the connection closes.
- `max_conns` (default 64) caps a tenant's concurrent connections; extra ones are closed.
- Unknown hosts, missing SNI, non-TLS bytes and tenants that are offline get a closed
  connection and no reply. The ClientHello must fit in one TLS record, which every mainstream
  client satisfies.
- `serve --tenants` cannot be combined with `--token` or `--tunnel`.

Embedders use `run_tenant_serve_with_store` with their own `TenantStore` to keep tenants
somewhere other than a file.

## Observing traffic

By default an interactive TUI (ratatui) opens, showing aggregate traffic, a per-connection list (source/destination/protocol/bytes/lifetime), and an event log; it is read-only and cannot control connections. Press `q` / `Esc` / `Ctrl+C` to exit.

For background/service mode use `--headless`, which writes structured JSON lines to a log file (default `erbridge.log`, path can be set with `--log-file`) instead of starting the TUI:

```sh
erbridge --headless --log-file /var/log/erbridge.log serve --config config.toml
```

## Security notes

The A↔B connection in reverse mode is encrypted and authenticated with the Noise protocol
(`Noise_NNpsk0`): the shared `token` is hashed into a 32-byte pre-shared key mixed into the
handshake itself, rather than checked afterward. A mismatched token fails the handshake's
AEAD tag verification (typically on B's very first message), so the connection just closes
the same as it would on any other handshake or network failure — there's no dedicated
"token rejected" reply frame for a remote peer to use as an oracle. This only ever
interoperates with another erbridge instance; if you need this control channel to cross a
network you don't otherwise trust, it is still recommended to add an additional trusted
channel (VPN, etc.) on top, the same as for any point-to-point secret.

`forward`'s `transport = "noise"` mappings use the same Noise handshake and PSK derivation,
and likewise require a `token` — there's no anonymous form, since nothing but erbridge's own
`client` mode can speak the protocol anyway.

`forward`'s `transport = "tls"` mode instead uses a fresh self-signed, unauthenticated-identity
TLS certificate generated at startup: it stops passive eavesdropping on the
external-client-to-erbridge leg but does not prove erbridge's identity to the client, so a
client connecting to it should expect (and typically must configure itself to accept) a
certificate it cannot otherwise verify. This tradeoff exists specifically so a generic TLS
client (`curl -k`, `openssl s_client`) can connect directly, which Noise has no equivalent
for. It only covers that one leg — TCP only, neither transport has a UDP equivalent here —
the erbridge-to-target leg remains plaintext either way. Adding a `token` to a `tls` mapping
layers on a post-handshake, constant-time-compared token check exchanged in a plaintext
frame: it restricts *who* can connect (only a peer that knows the token and speaks that
frame, i.e. `client` mode), but doesn't change what the TLS layer itself does or doesn't
prove — the identity caveat above still applies.

Noise depends on the `snow` crate built with its `ring-accelerated` feature (see
`Cargo.toml`), which runs the ChaCha20-Poly1305 and X25519 operations through `ring` instead
of `snow`'s pure-Rust default resolver (BLAKE2s, which `ring` doesn't implement, still falls
back to the default resolver). This isn't just a speed preference: without it, the Noise
transport measured ~14% slower steady-state latency than the TLS transport it replaces;
with it, the two are indistinguishable. See
[`docs/benchmarks/tls-vs-noise-reverse-tunnel-latency.md`](docs/benchmarks/tls-vs-noise-reverse-tunnel-latency.md)
before changing that feature or the `snow` dependency.

## Config file

See [`config.example.toml`](config.example.toml) for a complete example. The sections are independent of each other; the same config file can fill in just one section or all of them. CLI arguments (`--listen`/`--token`/`--server`/`--map`/`--tunnel`) can override or supplement the config file's contents.

## Use as a library

`erbridge-core` has no command-line or terminal-UI dependencies, so another program can
embed a tunnel directly. This runs the `connect` role, reports its events, and stops it on
demand:

```rust
use erbridge_core::config::{ConnectConfig, ConnectTunnel};
use erbridge_core::reverse::connect::run_connect_with_shutdown;
use erbridge_core::stats::{Event, Registry};
use tokio_util::sync::CancellationToken;

let cfg = ConnectConfig {
    server: "relay.example.com:9000".into(),
    token: "secret".into(),
    tunnel: vec![ConnectTunnel { name: "web".into(), target: "127.0.0.1:8080".into() }],
    reconnect_min_secs: 1,
    reconnect_max_secs: 30,
};

let registry = Registry::new();
let mut events = registry.subscribe();          // structured `Event`s, not log lines
let shutdown = CancellationToken::new();
let task = tokio::spawn(run_connect_with_shutdown(cfg, registry, shutdown.clone()));

// ... later: stops the session, in-flight connections and reconnect loop
shutdown.cancel();
task.await??;
```

`run_serve_with_shutdown` works the same way for the `serve` role, and returns once every
listener and tunnelled connection is closed and its port released. `run_serve` and
`run_connect` are the same without a shutdown handle. The crate is not published to
crates.io yet; depend on it with a `git` or `path` dependency.

## Tests

```sh
make test    # equivalent to cargo test: covers forward's TCP/UDP forwarding, UDP idle timeout,
             # TLS- and Noise-secured forward mappings, client mode against both, the Noise
             # transport itself, serve/connect's multiplexed forwarding and PSK authentication, and
             # shutdown of both roles
```

## Latency benchmark

```sh
make bench   # equivalent to: cargo bench -p erbridge-core --bench latency
```

`crates/erbridge-core/benches/latency.rs` measures steady-state TCP round-trip latency (a 64-byte
ping over an already-open connection, not connection setup) across the three
data paths, all on loopback:

- `baseline_direct_tcp_roundtrip` — client <-> echo server, no erbridge
- `forward_tcp_roundtrip` — client <-> `forward` <-> echo server
- `reverse_tunnel_tcp_roundtrip` — client <-> `serve` (A) <=yamux/Noise=> `connect` (B) <-> echo server

Criterion prints p-value-style `[low mid high]` estimates per run and writes
an HTML report with full distributions to `target/criterion/report/index.html`.
Compare `forward`/`reverse` against `baseline` to get erbridge's added
latency; loopback numbers isolate erbridge's own per-message overhead but
don't include real network RTT — for that, run the same three modes over an
actual link and drive them with `wrk`/`hey` (HTTP) or `iperf3 -u` (UDP
throughput/jitter) instead.

### Comparing against frp / rathole / bore

```sh
make compare-tunnels   # equivalent to: cargo run --release -p erbridge-core --example compare_tunnels
```

`crates/erbridge-core/examples/compare_tunnels.rs` runs the same persistent-connection ping-pong
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

## Related tools

- [MoonProxy](https://github.com/MoonProxyHQ/moonproxy-desktop) — Cross-platform
  desktop GUI client for frp (Tauri v2 + Rust) for non-technical users,
  featuring visual proxy rules, traffic monitoring and system tray

## License

[MIT](LICENSE)
