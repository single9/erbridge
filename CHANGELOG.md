# Changelog

All notable changes to this project are documented in this file.

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


