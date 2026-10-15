# Makefile for the Pico (Brevis) zkVM guest build of zesu.
#
# Prerequisites:
#   - Zig (see minimum_zig_version in build.zig.zon)
#   - Rust nightly-2025-08-04 (pinned in runner/rust-toolchain; rustup installs it
#     on first use). On macOS 27 that toolchain's linker cannot read the newest SDK's
#     .tbd stubs: build with SDKROOT pointing at an older SDK, e.g.
#       SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk make runner
#   - Network access to fetch the zesu commit pinned in build.zig.zon, or a local zesu
#     checkout passed as ZESU_SOURCE=<dir>. zesu is built inside this build, for Pico's own ISA
#     target (see build.zig).
#
# Usage:
#   make runner               — build the Rust host runner
#   make                      — build the Zig guest ELF
#   make run INPUT=<file>     — build and execute end-to-end
#   make prove INPUT=<file>   — also generate + verify a RISCV-phase proof (slow)
#   make test                 — execute all test vectors
#   make bless                — regenerate expected.hex files
#   make clean                — remove build artifacts
#   make clean-runner         — also remove the compiled runner
#
#   ZESU_SOURCE=../../zesu make ...   use a local zesu checkout instead of the pinned commit

CARGO     ?= cargo
ZIG       ?= zig
RUNNER    = runner/target/release/zesu-pico-runner
ELF       = zig-out/bin/zesu-pico
# ZESU_SOURCE=../../zesu builds against a local zesu checkout instead of the pinned commit.
ZIG_FLAGS = $(if $(ZESU_SOURCE),--fork=$(ZESU_SOURCE),)

# Bytes of SszStatelessValidationResult to compare: the zkevm@v0.8.0 flat layout
# is root(32) + valid(1) + chain_id(8) + schema_id(2). Must agree with the guest's
# output length (the runner writes exactly the bytes the guest put on fd 3).
SSZ_OUTPUT_LEN ?= 43

.PHONY: all runner run prove test bless clean clean-runner

all:
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)

runner: $(RUNNER)

$(RUNNER):
	@command -v $(CARGO) >/dev/null 2>&1 || \
	    { echo "ERROR: cargo not found. Install Rust: https://rustup.rs"; exit 1; }
	cd runner && $(CARGO) build --release

run: all runner
	@test -n "$(INPUT)" || { echo "ERROR: INPUT is required: make run INPUT=path/to/block.bin" >&2; exit 1; }
	$(RUNNER) -e $(ELF) -i $(INPUT)

prove: all runner
	@test -n "$(INPUT)" || { echo "ERROR: INPUT is required: make prove INPUT=path/to/block.bin" >&2; exit 1; }
	$(RUNNER) -p -e $(ELF) -i $(INPUT)

test: all runner
	@fail=0; \
	for bin in ../vectors/*.bin; do \
	    name=$$(basename $$bin .bin); \
	    expected=../vectors/$$name.expected.hex; \
	    out=$$(mktemp); \
	    echo "==> $$name"; \
	    if ! $(RUNNER) -e $(ELF) -i $$bin -o $$out; then \
	        echo "  FAIL: runner non-zero exit"; \
	        fail=1; \
	    elif [ -f $$expected ]; then \
	        got=$$(xxd -p -l $(SSZ_OUTPUT_LEN) $$out | tr -d '\n'); \
	        want=$$(tr -d '[:space:]' < $$expected | sed 's/^0x//' | tr 'A-F' 'a-f'); \
	        if [ "$$got" = "$$want" ]; then \
	            echo "  OK"; \
	        else \
	            echo "  FAIL"; \
	            echo "    expected: $$want"; \
	            echo "    got:      $$got"; \
	            fail=1; \
	        fi; \
	    else \
	        echo "  (no expected.hex — informational)"; \
	    fi; \
	    rm -f $$out; \
	done; \
	exit $$fail

bless: all runner
	@for bin in ../vectors/*.bin; do \
	    name=$$(basename $$bin .bin); \
	    expected=../vectors/$$name.expected.hex; \
	    out=$$(mktemp); \
	    $(RUNNER) -e $(ELF) -i $$bin -o $$out; \
	    xxd -p -l $(SSZ_OUTPUT_LEN) $$out | tr -d '\n' > $$expected; \
	    echo "wrote $$expected"; \
	    rm -f $$out; \
	done

clean:
	rm -rf zig-out .zig-cache

clean-runner: clean
	cd runner && $(CARGO) clean
