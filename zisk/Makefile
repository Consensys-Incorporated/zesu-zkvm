# Makefile for the Zisk zkVM guest build of zesu.
#
# Prerequisites:
#   - Rust stable toolchain (rustup default stable)
#   - Zisk source checkout (default: ../../zisk, override via ZISK_DIR)
#   - Zig (see minimum_zig_version in build.zig.zon)
#
# Usage:
#   make lib/libziskos_staticlib.a — build the Zisk OS static library (ZisK 1.0.0-alpha)
#   make                           — build lib/libziskos_staticlib.a then the Zig guest ELF
#   make run INPUT=<file>          — build and run under ziskemu
#   make clean                     — remove build artifacts (preserves lib/libziskos_staticlib.a)
#   make clean-lib                 — also remove lib/libziskos_staticlib.a (forces a rebuild)

ZISK_DIR  ?= ../../zisk
ZISK_PKG   = ziskos-staticlib
ZISK_LIB   = ziskos_staticlib
ZISK_TARGET = riscv64ima-zisk-zkvm-elf
CARGO     ?= cargo

LIB_OUT   = lib/libziskos_staticlib.a
CARGO_OUT = $(ZISK_DIR)/target/$(ZISK_TARGET)/release/lib$(ZISK_LIB).a

ZIG       ?= zig
# ziskup installs ziskemu into ~/.zisk/bin, which is not on PATH by default —
# prefer it when present so `make test` works out of the box.
ZISKEMU   ?= $(if $(wildcard $(HOME)/.zisk/bin/ziskemu),$(HOME)/.zisk/bin/ziskemu,ziskemu)
ZESU_OBJ  ?=

ZIG_FLAGS  = $(if $(ZESU_OBJ),-Dzesu_obj=$(ZESU_OBJ))

.PHONY: all run test bless clean clean-lib check-ziskemu

all: $(LIB_OUT)
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)

$(LIB_OUT):
	@command -v $(CARGO) >/dev/null 2>&1 || \
	    { echo "ERROR: cargo not found. Install Rust: https://rustup.rs"; exit 1; }
	@test -d $(ZISK_DIR) || \
	    { echo "ERROR: ZISK_DIR=$(ZISK_DIR) not found."; \
	      echo "       Clone zisk: git clone --branch v1.0.0-alpha https://github.com/0xPolygonHermez/zisk $(ZISK_DIR)"; \
	      echo "       Or set ZISK_DIR=/path/to/zisk"; exit 1; }
	@$(CARGO) +zisk --version >/dev/null 2>&1 || \
	    { echo "ERROR: Zisk Rust toolchain 'zisk' not installed."; \
	      echo "       Install via ziskup / cargo-zisk toolchain install"; exit 1; }
	@echo "==> Building libziskos_staticlib.a from $(ZISK_DIR) ..."
	cd $(ZISK_DIR) && $(CARGO) +zisk build -p $(ZISK_PKG) \
	    --target $(ZISK_TARGET) --release \
	    --config 'profile.release.lto="fat"'
	@mkdir -p lib
	cp $(CARGO_OUT) $(LIB_OUT)
	@echo "==> Copied $(LIB_OUT)  ($$(wc -c < $(LIB_OUT)) bytes)"

run: all
ifndef INPUT
	$(error INPUT is required: make run INPUT=path/to/block.bin)
endif
	$(ZISKEMU) -e zig-out/bin/zesu-zisk -i $(INPUT)

# Fail with a usable message instead of one opaque "non-zero exit" per vector.
check-ziskemu:
	@command -v $(ZISKEMU) >/dev/null 2>&1 || test -x $(ZISKEMU) || \
	    { echo "ERROR: ziskemu not found at '$(ZISKEMU)'."; \
	      echo "       Install it with ziskup, then either add ~/.zisk/bin to PATH"; \
	      echo "       or pass ZISKEMU=/path/to/ziskemu to make"; exit 1; }

test: $(LIB_OUT) check-ziskemu
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)
	@fail=0; total_steps=0; total_cost=0; total_base=0; total_main=0; total_ops=0; total_precomp=0; total_mem=0; \
	for bin in ../vectors/*.bin; do \
	    name=$$(basename $$bin .bin); \
	    expected=../vectors/$$name.expected.hex; \
	    out=$$(mktemp); \
	    metrics=$$(mktemp); \
	    rc_file=$$(mktemp); \
	    echo "==> $$name"; \
	    { $(ZISKEMU) -e zig-out/bin/zesu-zisk -i $$bin -o $$out -m -X -x; echo $$? >$$rc_file; } >$$metrics 2>&1; \
	    if [ "$$(cat $$rc_file)" != "0" ]; then \
	        echo "  FAIL: ziskemu exited $$(cat $$rc_file)"; \
	        sed 's/^/    /' $$metrics | tail -20; \
	        fail=1; \
	    else \
	        steps=$$(grep -o 'steps=[0-9]*' $$metrics | head -1 | cut -d= -f2); \
	        dur=$$(grep -o 'duration=[0-9.]*' $$metrics | head -1 | cut -d= -f2); \
	        tp=$$(grep -o 'tp=[0-9.]*' $$metrics | head -1 | cut -d= -f2); \
	        cost=$$(grep 'TOTAL COST:' $$metrics | grep -oE '[0-9]+'); \
	        base=$$(grep 'BASE COST:' $$metrics | grep -oE '[0-9]+'); \
	        main=$$(grep 'MAIN COST:' $$metrics | grep -oE '[0-9]+'); \
	        ops=$$(grep 'OPCODES COST:' $$metrics | grep -oE '[0-9]+'); \
	        precomp=$$(grep 'PRECOMPILED COST:' $$metrics | grep -oE '[0-9]+'); \
	        mem=$$(grep 'MEMORY COST:' $$metrics | grep -oE '[0-9]+'); \
	        total_steps=$$((total_steps + $${steps:-0})); \
        total_cost=$$((total_cost + $${cost:-0})); \
        total_base=$$((total_base + $${base:-0})); \
        total_main=$$((total_main + $${main:-0})); \
        total_ops=$$((total_ops + $${ops:-0})); \
        total_precomp=$$((total_precomp + $${precomp:-0})); \
        total_mem=$$((total_mem + $${mem:-0})); \
	        echo "  steps=$${steps:-?} dur=$${dur:-?}s tp=$${tp:-?}Mst/s  base=$${base:-?} main=$${main:-?} ops=$${ops:-?} precomp=$${precomp:-?} mem=$${mem:-?} total=$${cost:-?}"; \
	        if [ -f $$expected ]; then \
	            got=$$(xxd -p -l 43 $$out | tr -d '\n'); \
	            want=$$(tr -d '[:space:]' < $$expected | sed 's/^0x//' | tr 'A-F' 'a-f'); \
	            success_byte=$$(xxd -p -s 32 -l 1 $$out | tr -d '\n'); \
	            echo "  success_byte=0x$$success_byte"; \
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
	    fi; \
	    rm -f $$out $$metrics $$rc_file; \
	done; \
	echo "==> total steps=$$total_steps  base=$$total_base main=$$total_main ops=$$total_ops precomp=$$total_precomp mem=$$total_mem total=$$total_cost"; \
	exit $$fail

bless: $(LIB_OUT) check-ziskemu
	$(ZIG) build -Doptimize=ReleaseFast $(ZIG_FLAGS)
	@for bin in ../vectors/*.bin; do \
	    name=$$(basename $$bin .bin); \
	    expected=../vectors/$$name.expected.hex; \
	    out=$$(mktemp); \
	    $(ZISKEMU) -e zig-out/bin/zesu-zisk -i $$bin -o $$out; \
	    xxd -p -l 43 $$out | tr -d '\n' > $$expected; \
	    echo "wrote $$expected"; \
	    rm -f $$out; \
	done

clean:
	rm -rf zig-out .zig-cache

clean-lib: clean
	rm -f $(LIB_OUT)
