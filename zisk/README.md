# zesu-zkvm / zisk

Zisk zkVM guest for zesu — compiles the Ethereum stateless block executor to a
`riscv64-freestanding-none` ELF that runs inside the
[Zisk zkVM](https://github.com/0xPolygonHermez/zisk) (v1.1.0-alpha).

## Architecture

The guest ELF is assembled from two relocatable objects:

```
zesu.o          — EVM + stateless execution logic (from zesu/src/zkvm)
                  Compiled for rv64im freestanding; leaves all platform
                  symbols (IO, crypto, heap, runtime) as extern refs.

zisk-wrapped.o  — All platform symbols, merged in a partial-link step:
                    zisk-host.o          (Zig)   zkvm_log
                  + libziskos_staticlib.a (Rust)  everything else — all zkvm_*
                                                   accelerators, read_input/
                                                   write_output, entry-point
                                                   chain, heap init, exit
```

The partial link step (`zig ld.lld -r --whole-archive zisk-host.o
libziskos_staticlib.a --no-whole-archive`) merges `zisk-host.o` and
`libziskos_staticlib.a` into `zisk-wrapped.o`. Since ZisK 1.1.0-alpha,
**all** `zkvm_*` accelerators (keccak256, sha256, secp256k1, secp256r1,
BN254, BLS12-381, RIPEMD-160, BLAKE2f, modexp, KZG point eval, …) are
circuit-backed implementations provided directly by ZisK's own
`libziskos_staticlib.a`. `zisk-host.o` no longer contains any bespoke Zig
CSR implementations — the earlier generation of hand-written accelerators in
`src/runtime/` was dropped in favor of linking straight to ZisK's Rust
implementations. `zisk-host.o` now only exports `zkvm_log`, the one runtime
symbol ZisK doesn't provide itself. `zesu.o`'s `main()` returns its status
(0/1) in `a0` per the RISC-V C ABI rather than calling an explicit halt
function; `libziskos_staticlib.a`'s own `_start` performs the `exit(93)`
ecall automatically once `main()` returns, with `a0` passed through
untouched — so no exit routine, and no inline assembly, lives in this repo's
ZisK target at all. The final link is a clean `zesu.o + zisk-wrapped.o` with
each symbol defined exactly once.

### Symbol ownership

| Symbol(s) | Source | Implementation |
|---|---|---|
| `zkvm_log` | `zisk_host.zig` | UART (0xa0000200) |
| `read_input`, `write_output` | `libziskos_staticlib.a` | memory-mapped IO (0x40000000 / 0xa0010000) |
| all `zkvm_*` accelerators (keccak256, sha256, secp256k1, secp256r1, bn254, bls12-381, ripemd160, blake2f, modexp, kzg_point_eval) | `libziskos_staticlib.a` | ZisK 1.1.0-alpha circuit-backed implementations (Rust) |
| `_start`, `_zisk_main`, `init_sys_alloc` | `libziskos_staticlib.a` | Rust entry-point chain |
| `ZISK_BUMP_HEAP_POS`, `ZISK_BUMP_HEAP_TOP` | `libziskos_staticlib.a` | shared bump heap vars |

## Directory layout

```
zisk/
  src/
    zisk_host.zig        — host object: zkvm_log (no other symbols, no asm)
  lib/
    libziskos_staticlib.a — NOT committed; build with `make lib/libziskos_staticlib.a`
  build.zig              — Zig build script
  build.zig.zon          — package manifest (no dependencies; zesu.o is either
                           passed in via -Dzesu_obj or built from a sibling
                           ../../zesu checkout)
  zisk.ld                — linker script (Zisk memory map)
  Makefile               — builds libziskos_staticlib.a then the Zig guest ELF
```

## Dependencies

| Dependency | Version | Notes |
|---|---|---|
| Zig | 0.16.0 | see `minimum_zig_version` in `build.zig.zon`; CI pins exactly 0.16.0 |
| Rust + cargo-zisk | 1.1.0-alpha | ZisK custom Rust toolchain |
| Zisk source | v1.1.0-alpha | for building `libziskos_staticlib.a` |
| zesu.rv64im.o | — | pre-built object passed via `-Dzesu_obj`, or built from a sibling `../../zesu` checkout if omitted |

## Building `lib/libziskos_staticlib.a`

`libziskos_staticlib.a` is the Zisk OS runtime (ZisK's `ziskos-staticlib`
crate). After the partial link step it contributes every `zkvm_*`
accelerator, `read_input`/`write_output`, and the Rust entry-point/heap-init
chain.

It is **not committed** because it is a cross-compiled RISC-V binary that must be
reproducibly built from a known Zisk commit.

### One-time toolchain setup

```sh
# 1. Install cargo-zisk
curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash

# 2. Install the Zisk Rust toolchain (downloads ~1.5 GB)
cargo-zisk toolchain install

# 3. Clone Zisk v1.1.0-alpha alongside this repo (or set ZISK_DIR)
git clone --branch v1.1.0-alpha https://github.com/0xPolygonHermez/zisk ../../zisk
```

### Build the library

```sh
# From this directory (zesu-zkvm/zisk/)
make lib/libziskos_staticlib.a

# With a custom Zisk checkout location
make lib/libziskos_staticlib.a ZISK_DIR=/path/to/zisk
```

This runs:

```sh
cd $ZISK_DIR && cargo +zisk build -p ziskos-staticlib \
    --target riscv64ima-zisk-zkvm-elf --release \
    --config 'profile.release.lto="fat"'
cp $ZISK_DIR/target/riscv64ima-zisk-zkvm-elf/release/libziskos_staticlib.a lib/
```

## Building the guest ELF

```sh
make                              # builds lib/libziskos_staticlib.a then the debug ELF
zig build -Doptimize=ReleaseFast  # release build only (lib/ must already exist)

# Against a pre-built zesu.rv64im.o (CI / release default) instead of a
# sibling ../../zesu checkout:
zig build -Doptimize=ReleaseFast -Dzesu_obj=/path/to/zesu.rv64im.o
```

Output: `zig-out/bin/zesu-zisk`

The build executes three steps:

1. **Compile `zesu.o`** — either supplied directly via `-Dzesu_obj`, or built
   from source by invoking `zig build rv64im-object` against a sibling
   `../../zesu` checkout. All `zkvm_*`, IO, and heap symbols are unresolved
   extern refs.
2. **Partial link** — `zig ld.lld -r --whole-archive zisk-host.o
   libziskos_staticlib.a --no-whole-archive` produces `zisk-wrapped.o`: the
   three host runtime symbols plus every accelerator/IO/entrypoint symbol
   from `libziskos_staticlib.a`.
3. **Final link** — `zesu.o + zisk-wrapped.o` under `zisk.ld`.

## Running under ziskemu

```sh
make run INPUT=../vectors/mainnet_24758573.bin

# or directly
ziskemu -e zig-out/bin/zesu-zisk -i /path/to/block.bin
```

## Conformance vectors

```sh
make test           # build ReleaseFast + run every ../vectors/*.bin through
                     # ziskemu, diffing output against *.expected.hex
make bless          # regenerate the *.expected.hex files from current output
```

Pass a pre-built zesu object with `ZESU_OBJ=/path/to/zesu.rv64im.o` (used by CI).

## Entry-point chain

```
_start           (libziskos_staticlib.a, Rust)
  sets gp from _global_pointer linker symbol
  sets sp from _init_stack_top linker symbol
  calls _zisk_main
  reads exit code from a0 (left by main(), untouched by _zisk_main)
  ecall a7=93 (exit) — the same halt every ZisK guest uses, ours included

_zisk_main       (libziskos_staticlib.a, Rust)
  calls init_sys_alloc()   — sets ZISK_BUMP_HEAP_POS / ZISK_BUMP_HEAP_TOP
  calls main()

main()           (zesu.o / zesu/src/zkvm/root.zig, Zig, export fn)
  calls runner.runStateless(bump_allocator)
  writes SSZ output via zkvm_io.write_output
  returns 0 (success) or 1 (guestMain() error) — no explicit halt call
```

## Memory map (Zisk 1.1.0-alpha)

| Region | Address | Size |
|---|---|---|
| ROM (code + rodata) | `0x80000000` | 128 MB |
| SYS / UART | `0xa0000000` | 64 KB |
| OUTPUT | `0xa0010000` | 64 KB |
| gap | `0xa0020000` | 64 KB |
| RAM (heap + stack) | `0xa0030000` | ~512 MB |
| INPUT | `0x40000000` | 1 GB |
