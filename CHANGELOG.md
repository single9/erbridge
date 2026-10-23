# Changelog

All notable changes to this project are documented in this file.

## [0.3.0] - 2026-10-23

### Bug Fixes

- Bound the control handshake, redact secrets in Debug, harden the tenant file write
- Survive a poisoned lock and rate-limit the refused-connection log
- Per-address handshake cap, withdraw orphaned tenants, close the disable race, pin actions

### Build

- Prepare both crates for crates.io

### CI

- Add CI workflow and publish both crates to crates.io from the release workflow
- Pick the release version from Conventional Commits
- Record the scripts as executable and run them through bash
- Keep file names from being read as options in the checksum step
- Make the release dry run touch nothing in the repository

### Documentation

- Add MoonProxy to related tools
- Scope multi-tenant serve and library readiness
- Describe the workspace and library usage in the README
- Add multi-tenant spec and tickets
- Add upgrade notes for 0.3 to the README

### Features

- Gate cli/tui behind a feature, add shutdown handle for serve/connect
- Add Registry::subscribe and crate-level embedding docs
- Add tenant model and Noise handshake that identifies the PSK used
- Add a ClientHello SNI parser that returns the bytes it consumed
- Multi-tenant serve with per-tenant tokens and SNI routing
- Tenant stores and live reload of tenant changes
- Cap concurrent connections per tenant
- Single-use enrollment codes that create tenants
- Serve --tenants, serve-admin, enroll and connect --credentials

### Refactor

- Split into an erbridge-core library and an erbridge binary crate
- Wrap PSKs in a Psk type that redacts itself and compares in constant time

### Testing

- End-to-end multi-tenant tests with real TLS and the real binary

## [0.2.0] - 2026-09-09

### Documentation

- Add install instructions and a systemd unit template

### Features

- Replace TLS with Noise for erbridge-internal connections

## [0.1.4] - 2026-09-08

### Build

- Cross-compile Linux aarch64 via cross-rs, publish it in releases

## [0.1.3] - 2026-09-08

### Build

- Add single-arch macOS dist targets, publish them alongside universal

## [0.1.2] - 2026-09-08

### Bug Fixes

- Pass --repo to gh release create

## [0.1.1] - 2026-09-08

### Benchmarks

- Settle the machine between compare-tunnels rounds
- Add an encrypted rathole scenario to isolate crypto cost
- Rotate scenario order to cancel position bias
- Add layer decomposition and connection-setup benchmarks
- Keep the setup benchmark from exhausting the port range
- Derive the layer marginals from min, not p50
- Pool several passes per layer before taking the min

### Bug Fixes

- Acknowledge tunnel streams instead of waiting for the target
- Raise the yamux stream ceiling from 512 to 4096

### Build

- Enable thin LTO in the release profile
- Add osx and osx-x86 make targets

### CI

- Add manual release workflow with cross-platform builds and signing

### Features

- Initial erbridge implementation
- Add latency benchmarks, tunnel comparison, and MIT license
- Add TLS/token-secured forward mappings and a client mode

### Performance

- Forward the request without waiting for B's reply
- Coalesce yamux's frame writes into one syscall

### Styling

- Sort imports in the udp forward test
- Format the connection-setup benchmark


