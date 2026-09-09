# TLS vs Noise reverse-tunnel latency

Measured while migrating the `serve`/`connect` control channel (and `forward`/`client`'s `transport = "noise"` mappings) from TLS to the Noise protocol, to check whether the switch cost any steady-state latency (see README's Security notes for why that migration happened). Recorded here so a future change to `src/noise.rs`, the `snow` dependency, or its Cargo features can be checked against a known-good number instead of re-deriving one from scratch.

Absolute numbers below are specific to the machine they were measured on and are only meaningful relative to each other, not as a portable latency figure.

## Machine

- CPU: Intel Core i7-13700KF (16 cores / 24 threads), governor pinned to `performance` for every run (see "Environment note" below)
- RAM: 125 GiB
- OS: Ubuntu 24.04.4 LTS, kernel 6.8.0-139-generic
- Toolchain: rustc/cargo 1.98.1, release profile (`lto = "thin"`, `codegen-units = 1`, per `Cargo.toml`)
- Not a VM (`systemd-detect-virt` reports `none`)

## Result

No measurable difference, after two prerequisites were met:

1. `snow` built with the `ring-accelerated` feature (`Cargo.toml`), so ChaCha20-Poly1305 and X25519 run through `ring` instead of the pure-Rust default resolver. BLAKE2s has no `ring` implementation and keeps using the default resolver as a fallback.
2. The measuring machine's CPU governor set to `performance`, not `powersave` (see "Environment note" below) — required for either version to produce a stable number at all, not specific to Noise.

With both in place, `reverse_tunnel_tcp_roundtrip` (a 64-byte ping over an already-open connection, `benches/latency.rs`) lands at essentially the same latency for TLS and Noise:

| Transport | Run 1 [low mid high] | Run 2 [low mid high] |
|---|---|---|
| TLS (pre-migration) | 39.29 / 39.45 / 39.64 µs | 39.43 / 39.65 / 39.91 µs |
| Noise, default resolver | 45.22 / 45.51 / 45.85 µs | 44.89 / 45.08 / 45.30 µs |
| Noise, `ring-accelerated` | 39.14 / 39.40 / 39.83 µs | 38.89 / 39.04 / 39.22 µs |

The default-resolver row is included because it's the regression a future contributor might reintroduce by removing the `ring-accelerated` feature (e.g. while trying to drop the `ring` dependency): roughly **+5.7 µs (+14%)** over TLS, reproduced across two independent runs.

Cross-checked against `examples/compare_tunnels.rs`, which drives the same tunnel end-to-end alongside frp/rathole/bore rather than through Criterion:

| Tool | TLS p50 | Noise (`ring-accelerated`) p50 |
|---|---|---|
| baseline (direct, no tunnel) | 11.8 µs | 11.7 µs |
| **erbridge (serve/connect)** | **40.8 µs** | **39.4 µs** |
| frp | 56.9 µs | 54.5 µs |
| rathole (unencrypted) | 36.1 µs | 39.7 µs |
| rathole + noise | 45.2 µs | 42.2 µs |
| bore (unencrypted) | 37.4 µs | 37.4 µs |

Same conclusion: erbridge's number doesn't move in a consistent direction between the two transports, and sits in the same band as rathole/bore's own numbers rather than trailing them.

## Environment note: CPU governor dominates this measurement

Before fixing the governor, single runs of `reverse_tunnel_tcp_roundtrip` swung between 64 µs and 90 µs depending on when they were taken, and Criterion's own regression detector reported contradictory results from run to run: +19.9% "regressed", then -35% "improved", on unchanged code. The tell was that `compare_tunnels`' frp/rathole/bore numbers -- untouched by this migration -- swung by 55-142% between consecutive runs too. `cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor` showed `powersave` on every core; frequency transitions mid-measurement are large enough to dominate a 64-byte round trip.

Fix (needs root, not persistent across reboot):

```sh
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# afterward, to go back to the power-saving default:
echo powersave | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

**Any future benchmark comparison on this machine needs this set first**, and needs at least two runs compared against each other before trusting a single number -- Criterion's own baseline diffing is not sufficient on its own, since it happily reports a confident-looking regression or improvement that's actually just governor noise.

## How to reproduce

```sh
# Criterion (steady-state, in-process, no external tools)
cargo bench --bench latency

# End-to-end against frp/rathole/bore (needs those on PATH; see README)
cargo run --release --example compare_tunnels
```

To get a TLS-side number for comparison, `git stash` the Noise migration changes, rerun, then `git stash pop` (both scripts spin up their own listeners on random ports, so nothing needs to be torn down manually between runs).
