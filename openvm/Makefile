# Makefile for the OpenVM zkVM guest build of zesu.
#
# Prerequisites:
#   - Zig (see minimum_zig_version in build.zig.zon)
#   - Rust 1.91.1 stable (for the runner)
#   - Stock Rust nightly with rust-src and llvm-tools (for the pairing library):
#       rustup toolchain install nightly-2026-01-18 --component rust-src,llvm-tools --profile minimal
#   - OpenVM is fetched by cargo, pinned to the revision eth-act/ere executes with
#
# Usage:
#   make runner               — build the Rust host runner
#   make pairing-lib          — build OpenVM's pairing library for the guest
#   make                      — build runner then the Zig guest ELF
#   make run INPUT=<file>     — build and run end-to-end
#   make test                 — run all test vectors
#   make bless                — regenerate expected.hex files
#   make clean                — remove build artifacts
#   make clean-runner         — also remove the compiled runner

CARGO     ?= cargo
ZIG       ?= zig
RUNNER    = runner/target/release/zesu-openvm-runner
ELF       = zig-out/bin/zesu-openvm

# Prebuilt zesu.rv64im.o (zig build rv64im-object in zesu); omit to build from ../../zesu.
ZESU_OBJ  ?=
ZIG_FLAGS  = $(if $(ZESU_OBJ),-Dzesu_obj=$(ZESU_OBJ))

# OpenVM's pairing library (openvm/pairing), linked into the ELF by build.zig.
# Built for the stock tier-3 riscv64imac-unknown-none-elf target (std from rust-src
# via -Z build-std), the path OpenVM v2.1.0-preview supports with
# OPENVM_RUSTC_TARGET, so no custom OpenVM toolchain is needed.
OPENVM_TOOLCHAIN ?= nightly-2026-01-18
PAIRING_TARGET    = riscv64imac-unknown-none-elf
PAIRING_LIB       = lib/libzesu_openvm_pairing.a
PAIRING_BUILT     = pairing/target/$(PAIRING_TARGET)/release/libzesu_openvm_pairing.a
# The llvm-tools component ships llvm-objcopy under its host rustlib directory.
OPENVM_OBJCOPY    = $(shell rustc +$(OPENVM_TOOLCHAIN) --print sysroot)/lib/rustlib/$(shell rustc +$(OPENVM_TOOLCHAIN) -vV | sed -n 's/^host: //p')/bin/llvm-objcopy

# Bytes of SszStatelessValidationResult to compare: the zkevm@v0.8.0 flat layout
# is root(32) + valid(1) + chain_id(8) + schema_id(2). Must agree with
# SSZ_OUTPUT_LEN in openvm/runner/src/main.rs.
SSZ_OUTPUT_LEN ?= 43

.PHONY: all runner pairing-lib run test bless clean clean-runner

all: runner pairing-lib
	$(ZIG) build $(ZIG_FLAGS)

pairing-lib:
	cd pairing && $(CARGO) +$(OPENVM_TOOLCHAIN) build --release --target $(PAIRING_TARGET) \
	    -Z build-std=core,alloc,panic_abort -Z build-std-features=compiler-builtins-mem
	@mkdir -p lib
	@# The Zig guest keeps its own entry point and mem* routines: hide the
	@# openvm crate's _start/__start and compiler_builtins' mem* from the link,
	@# and move its .text._start out of the linker script's KEEP so it is dropped.
	$(OPENVM_OBJCOPY) \
	    --localize-symbol=_start --localize-symbol=__start \
	    --rename-section=.text._start=.text.openvm_rust_start \
	    --localize-symbol=memcpy --localize-symbol=memmove --localize-symbol=memset \
	    --localize-symbol=memcmp --localize-symbol=bcmp \
	    $(PAIRING_BUILT) $(PAIRING_LIB)

runner: $(RUNNER)

$(RUNNER):
	@command -v $(CARGO) >/dev/null 2>&1 || \
	    { echo "ERROR: cargo not found. Install Rust: https://rustup.rs"; exit 1; }
	cd runner && $(CARGO) build --release

run: all
	@test -n "$(INPUT)" || { echo "ERROR: INPUT is required: make run INPUT=path/to/block.bin" >&2; exit 1; }
	$(RUNNER) -e $(ELF) -i $(INPUT)

test: runner
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)
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

bless: runner
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)
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
