WIN_TARGET   := x86_64-pc-windows-gnu
LINUX_TARGET := x86_64-unknown-linux-musl
LINUX_ARM_TARGET := aarch64-unknown-linux-musl
OSX_ARM_TARGET := aarch64-apple-darwin
OSX_X86_TARGET := x86_64-apple-darwin
OSX_TARGETS  := $(OSX_ARM_TARGET) $(OSX_X86_TARGET)
BIN_NAME     := erbridge
DIST_DIR     := dist
WIN_DIST     := $(DIST_DIR)/windows
LINUX_DIST   := $(DIST_DIR)/linux
LINUX_ARM_DIST := $(DIST_DIR)/linux-arm64
OSX_DIST     := $(DIST_DIR)/osx

## compare-tunnels: rounds to run, and seconds to let the machine settle before each
COMPARE_ROUNDS  ?= 1
COMPARE_SETTLE  ?= 2

.PHONY: all build release windows linux linux-arm osx osx-arm osx-x86 check-mingw check-linux check-cross check-osx check-osx-arm check-osx-x86 dist dist-windows dist-linux dist-linux-arm dist-osx dist-osx-arm dist-osx-x86 clean run test bench compare-tunnels

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

## Check whether `cross` is installed (needed for the aarch64 Linux cross-compile; it builds
## inside a Docker container with its own musl toolchain, so no local aarch64 linker is needed)
check-cross:
	@command -v cross >/dev/null 2>&1 || { \
		echo "cross not found, please install it first: cargo install cross --git https://github.com/cross-rs/cross"; \
		exit 1; \
	}

## Cross-compile the Linux aarch64 executable (release), via cross-rs/Docker
linux-arm: check-cross
	cross build --release --target $(LINUX_ARM_TARGET)
	@echo "Built: target/$(LINUX_ARM_TARGET)/release/$(BIN_NAME)"

## Check whether both macOS cross-compilation targets (Apple Silicon + Intel) are installed
check-osx:
	@for t in $(OSX_TARGETS); do \
		rustup target list --installed | grep -q "^$$t$$" || { \
			echo "rustup target $$t not found, please install it first: rustup target add $$t"; \
			exit 1; \
		}; \
	done

## Build both macOS architectures (release); dist-osx lipo's them into a universal binary
osx: check-osx
	@for t in $(OSX_TARGETS); do \
		cargo build --release --target $$t; \
	done
	@echo "Built: $(foreach t,$(OSX_TARGETS),target/$(t)/release/$(BIN_NAME))"

## Check whether the Apple Silicon macOS cross-compilation target is installed
check-osx-arm:
	@rustup target list --installed | grep -q '^$(OSX_ARM_TARGET)$$' || { \
		echo "rustup target $(OSX_ARM_TARGET) not found, please install it first: rustup target add $(OSX_ARM_TARGET)"; \
		exit 1; \
	}

## Cross-compile the Apple Silicon macOS executable only (release)
osx-arm: check-osx-arm
	cargo build --release --target $(OSX_ARM_TARGET)
	@echo "Built: target/$(OSX_ARM_TARGET)/release/$(BIN_NAME)"

## Check whether the Intel macOS cross-compilation target is installed
check-osx-x86:
	@rustup target list --installed | grep -q '^$(OSX_X86_TARGET)$$' || { \
		echo "rustup target $(OSX_X86_TARGET) not found, please install it first: rustup target add $(OSX_X86_TARGET)"; \
		exit 1; \
	}

## Cross-compile the Intel macOS executable only (release)
osx-x86: check-osx-x86
	cargo build --release --target $(OSX_X86_TARGET)
	@echo "Built: target/$(OSX_X86_TARGET)/release/$(BIN_NAME)"

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

## Package the Linux aarch64 executable together with the example config into dist/linux-arm64/ for deployment
dist-linux-arm: linux-arm
	mkdir -p $(LINUX_ARM_DIST)
	cp target/$(LINUX_ARM_TARGET)/release/$(BIN_NAME) $(LINUX_ARM_DIST)/
	cp config.example.toml $(LINUX_ARM_DIST)/
	@echo "Packaged to $(LINUX_ARM_DIST)/"

## Combine the Apple Silicon and Intel builds into a universal binary, packaged with the example
## config into dist/osx/ for deployment
dist-osx: osx
	mkdir -p $(OSX_DIST)
	lipo -create -output $(OSX_DIST)/$(BIN_NAME) $(foreach t,$(OSX_TARGETS),target/$(t)/release/$(BIN_NAME))
	cp config.example.toml $(OSX_DIST)/
	@echo "Packaged universal binary to $(OSX_DIST)/"

## Package the Apple Silicon macOS executable together with the example config into dist/osx/ for deployment
dist-osx-arm: osx-arm
	mkdir -p $(OSX_DIST)
	cp target/$(OSX_ARM_TARGET)/release/$(BIN_NAME) $(OSX_DIST)/
	cp config.example.toml $(OSX_DIST)/
	@echo "Packaged to $(OSX_DIST)/"

## Package the Intel macOS executable together with the example config into dist/osx/ for deployment
dist-osx-x86: osx-x86
	mkdir -p $(OSX_DIST)
	cp target/$(OSX_X86_TARGET)/release/$(BIN_NAME) $(OSX_DIST)/
	cp config.example.toml $(OSX_DIST)/
	@echo "Packaged to $(OSX_DIST)/"

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
