# Makefile for the SP1 zkVM guest build of zesu.
#
# Prerequisites:
#   - Zig (see minimum_zig_version in build.zig.zon)
#   - Rust stable (for the runner; sp1-sdk needs 1.88+)
#   - curl and shasum (to fetch the SP1 zkvm-standards SDK)
#   - Network access to fetch the zesu commit pinned in build.zig.zon, or a local zesu
#     checkout passed as ZESU_SOURCE=<dir>.
#
# Usage:
#   make sdk                  — fetch libzkevm.a + zkvm.ld (SP1's zkvm-standards SDK) into lib/
#   make runner               — build the Rust host runner
#   make                      — build the Zig guest ELF
#   make run INPUT=<file>     — build and execute end-to-end
#   make test                 — execute all test vectors (VECTORS=<files> for a subset)
#   make bless                — regenerate expected.hex files
#   make clean                — remove build artifacts
#   make clean-runner         — also remove the compiled runner
#
#   ZESU_SOURCE=../../zesu make ...   use a local zesu checkout instead of the pinned commit

CARGO     ?= cargo
ZIG       ?= zig
RUNNER    = runner/target/release/zesu-sp1-runner
ELF       = zig-out/bin/zesu-sp1
# ZESU_SOURCE=../../zesu builds against a local zesu checkout instead of the pinned commit.
ZIG_FLAGS = $(if $(ZESU_SOURCE),--fork=$(ZESU_SOURCE),)

# SP1's published zkvm-standards SDK (libzkevm.a, zkvm.ld). Pinned by version and checksum.
SP1_VERSION ?= 6.9.0
SP1_SDK_SHA256 ?= a3cf67df80e59491a8816c005c85296df3532587a1ce39e8b2a60af2b7f2ceef
SP1_SDK_URL = https://github.com/succinctlabs/sp1/releases/download/v$(SP1_VERSION)/zkevm-sdk-v$(SP1_VERSION).tar.gz

# Vectors that `make test` and `make bless` run. Override to run a subset, e.g.
#   make test VECTORS=../vectors/sepolia_amsterdam_11856500.bin
VECTORS ?= ../vectors/*.bin

# Bytes of SszStatelessValidationResult to compare: the zkevm@v0.8.0 flat layout
# is root(32) + valid(1) + chain_id(8) + schema_id(2). The runner writes exactly the bytes
# the guest put in its public output.
SSZ_OUTPUT_LEN ?= 43

.PHONY: all sdk runner run test bless clean clean-runner

all: sdk
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)

sdk: lib/libzkevm.a lib/zkvm.ld

lib/libzkevm.a lib/zkvm.ld:
	@command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found"; exit 1; }
	@mkdir -p lib
	@tmp=$$(mktemp -d); \
	curl -fsSL "$(SP1_SDK_URL)" -o "$$tmp/sdk.tar.gz" || { echo "ERROR: download failed: $(SP1_SDK_URL)"; rm -rf "$$tmp"; exit 1; }; \
	got=$$(shasum -a 256 "$$tmp/sdk.tar.gz" | cut -d' ' -f1); \
	if [ "$$got" != "$(SP1_SDK_SHA256)" ]; then \
	    echo "ERROR: SP1 SDK checksum mismatch: expected $(SP1_SDK_SHA256), got $$got"; rm -rf "$$tmp"; exit 1; \
	fi; \
	tar -xzf "$$tmp/sdk.tar.gz" -C "$$tmp" && \
	cp "$$tmp/zkevm-sdk-v$(SP1_VERSION)/libzkevm.a" "$$tmp/zkevm-sdk-v$(SP1_VERSION)/zkvm.ld" lib/; \
	rm -rf "$$tmp"

# Always invoke cargo: it is incremental, and a "binary exists" check would miss source edits.
runner:
	@command -v $(CARGO) >/dev/null 2>&1 || \
	    { echo "ERROR: cargo not found. Install Rust: https://rustup.rs"; exit 1; }
	cd runner && $(CARGO) build --release

run: all runner
	@test -n "$(INPUT)" || { echo "ERROR: INPUT is required: make run INPUT=path/to/block.bin" >&2; exit 1; }
	$(RUNNER) -e $(ELF) -i $(INPUT)

test: all runner
	@fail=0; \
	for bin in $(VECTORS); do \
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
	@for bin in $(VECTORS); do \
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
