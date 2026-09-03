# Makefile for the OpenVM zkVM guest build of zesu.
#
# Prerequisites:
#   - Zig (see minimum_zig_version in build.zig.zon)
#   - Rust 1.91.1 stable (for the runner)
#   - openvm checkout at ../../../../openvm relative to this directory
#
# Usage:
#   make runner               — build the Rust host runner
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

# Bytes of SszStatelessValidationResult to compare: the zkevm@v0.8.0 flat layout
# is root(32) + valid(1) + chain_id(8) + schema_id(2). Must agree with
# SSZ_OUTPUT_LEN in openvm/runner/src/main.rs.
SSZ_OUTPUT_LEN ?= 43

.PHONY: all runner run test bless clean clean-runner

all: runner
	$(ZIG) build

runner: $(RUNNER)

$(RUNNER):
	@command -v $(CARGO) >/dev/null 2>&1 || \
	    { echo "ERROR: cargo not found. Install Rust: https://rustup.rs"; exit 1; }
	cd runner && $(CARGO) build --release

run: all
	@test -n "$(INPUT)" || { echo "ERROR: INPUT is required: make run INPUT=path/to/block.bin" >&2; exit 1; }
	$(RUNNER) -e $(ELF) -i $(INPUT)

test: runner
	$(ZIG) build -Doptimize=ReleaseFast
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
	$(ZIG) build -Doptimize=ReleaseFast
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
