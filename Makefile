WIN_TARGET   := x86_64-pc-windows-gnu
LINUX_TARGET := x86_64-unknown-linux-musl
BIN_NAME     := erbridge
DIST_DIR     := dist
WIN_DIST     := $(DIST_DIR)/windows
LINUX_DIST   := $(DIST_DIR)/linux

## compare-tunnels: rounds to run, and seconds to let the machine settle before each
COMPARE_ROUNDS  ?= 1
COMPARE_SETTLE  ?= 2

.PHONY: all build release windows linux check-mingw check-linux dist dist-windows dist-linux clean run test bench compare-tunnels

all: build

## native-platform debug build
build:
	cargo build

## native-platform release build
release:
	cargo build --release

## Check whether the mingw-w64 cross-compilation linker is installed (needed to build the Windows target on macOS)
check-mingw:
	@command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { \
		echo "x86_64-w64-mingw32-gcc not found, please install it first: brew install mingw-w64"; \
		exit 1; \
	}
	@rustup target list --installed | grep -q '^$(WIN_TARGET)$$' || { \
		echo "rustup target $(WIN_TARGET) not found, please install it first: rustup target add $(WIN_TARGET)"; \
		exit 1; \
	}

## Check whether the Linux cross-compilation target is installed
check-linux:
	@rustup target list --installed | grep -q '^$(LINUX_TARGET)$$' || { \
		echo "rustup target $(LINUX_TARGET) not found, please install it first: rustup target add $(LINUX_TARGET)"; \
		exit 1; \
	}

## Cross-compile the Windows .exe (release)
windows: check-mingw
	cargo build --release --target $(WIN_TARGET)
	@echo "Built: target/$(WIN_TARGET)/release/$(BIN_NAME).exe"

## Cross-compile the Linux executable (release)
linux: check-linux
	RUSTFLAGS="-C linker=rust-lld" cargo build --release --target $(LINUX_TARGET)
	@echo "Built: target/$(LINUX_TARGET)/release/$(BIN_NAME)"

## Package the Windows executable together with the example config into dist/windows/ for deployment
dist-windows: windows
	mkdir -p $(WIN_DIST)
	cp target/$(WIN_TARGET)/release/$(BIN_NAME).exe $(WIN_DIST)/
	cp config.example.toml $(WIN_DIST)/
	@echo "Packaged to $(WIN_DIST)/"

## Package the Linux executable together with the example config into dist/linux/ for deployment
dist-linux: linux
	mkdir -p $(LINUX_DIST)
	cp target/$(LINUX_TARGET)/release/$(BIN_NAME) $(LINUX_DIST)/
	cp config.example.toml $(LINUX_DIST)/
	@echo "Packaged to $(LINUX_DIST)/"

dist: dist-windows

test:
	cargo test

## Latency benchmark: baseline vs forward vs serve/connect roundtrip, HTML report in target/criterion/
bench:
	cargo bench --bench latency

## Same ping-pong methodology, but against external tunnels (frp/rathole/bore) for comparison.
## Needs frpc/frps/rathole/bore-cli on PATH (brew install frpc frps rathole bore-cli), or point
## FRPC_BIN/FRPS_BIN/RATHOLE_BIN/BORE_BIN at their binaries. Missing tools are skipped, not fatal.
##
## The build is kept out of the measurement and the machine is given COMPARE_SETTLE seconds to
## quiesce before each round. Measuring straight after a 24-core build, or running rounds
## back-to-back, inflates every path by roughly 2x on a frequency-scaling (powersave) CPU --
## unevenly enough to reorder the results, so the settle is load-bearing, not cosmetic.
##   make compare-tunnels                     # one round
##   make compare-tunnels COMPARE_ROUNDS=10   # ten rounds, settling between each
compare-tunnels:
	cargo build --release --example compare_tunnels
	@echo "settling $(COMPARE_SETTLE)s before measuring..."
	@sleep $(COMPARE_SETTLE)
	@for i in $$(seq 1 $(COMPARE_ROUNDS)); do \
		if [ $(COMPARE_ROUNDS) -gt 1 ]; then echo "=== round $$i/$(COMPARE_ROUNDS) ==="; fi; \
		./target/release/examples/compare_tunnels || exit 1; \
		if [ $$i -lt $(COMPARE_ROUNDS) ]; then sleep $(COMPARE_SETTLE); fi; \
	done

clean:
	cargo clean
	rm -rf $(DIST_DIR)
