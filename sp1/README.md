# zesu-zkvm / sp1

SP1 (Succinct) zkVM guest for zesu — compiles the Ethereum stateless block executor to a
`riscv64-freestanding-none` ELF that runs inside [SP1](https://github.com/succinctlabs/sp1)
(tested against v6.9.0).

SP1 executes **rv64im** (ELF64, `EM_RISCV`); it has no Zbb/Zbs and no compressed instructions.

## Status

| | |
|---|---|
| RISC-V execution of zesu on SP1's executor | yes — both vectors run to completion and match in full |
| Accelerators (keccak, sha256, secp256k1/r1, bn254, bls12-381, KZG, modexp, ripemd160, blake2f) | all provided by SP1's SDK (`libzkevm.a`) on SP1's precompiles; nothing to implement here |
| Proving | not attempted; this target is for execution |

`make test` executes each vector on SP1's executor and compares the guest's output with the
expected output: the SSZ root of the block's new-payload request, plus `valid`, chain id and
schema id.

| Vector | Instructions | Syscalls | Time / peak memory (Apple M2 Max) |
|---|---|---|---|
| `sepolia_amsterdam_11856500` | 680M | 147k | 9 s / 5.4 GB |
| `mainnet_fusaka_24758573` | 333M | 707k | 7.5 s / 2.8 GB |

## Architecture

The guest ELF, `zig-out/bin/zesu-sp1`, is linked from three parts, laid out by SP1's own linker
script:

```
zesu-sp1  (ELF)
├── zesu          — EVM + stateless execution, built by this project's build.zig from the
│                   zesu source for SP1's own target (rv64im, strict alignment)
├── sp1-host.o    — sp1_host.zig  zesu's heap region, the log and abort hooks
└── libzkevm.a    — SP1's zkvm-standards SDK (fetched by `make sdk`, pinned by checksum):
                    _start, read_input / write_output, zkvm_halt, every zkvm_* accelerator
                    and SP1's allocator
```

Because SP1 ships the whole zkvm-standards C ABI, this target is much smaller than the others:
the host object is about 30 lines. `main()` in zesu returns 0 or 1, and SP1's `_start` turns that
into the exit code.

## Memory layout

SP1 gives the guest a 128 GiB address space. Addresses for the current build (they shift slightly
with each build; sizes are approximate):

```
 address          what is there                                   who puts it there
 ──────────────────────────────────────────────────────────────────────────────────────
 0x00000000       stack, growing downward from 0x78000000         SP1 (sp is set by _start)
 0x78000000       .text         guest code              ~1.4 MB   ┐
 0x7816xxxx       .rodata, .data                        ~65 KB    │ the guest program:
                  .bss                                  ~1.1 MB   │ defined by the ELF
 0x7827bac0     ← _end                                            ┘
 0x7827bac0       SP1's heap (TLSF allocator, used by libzkevm's Rust code: modexp, KZG,
                  pairing libraries), growing upward from _end
 0x10_0000_0000   zesu's heap, 512 MiB (ZKVM_HEAP_POS / ZKVM_HEAP_TOP in sp1_host.zig)
 0x1C_0000_0000 ← end of SP1's heap (112 GiB)
 0x1C_0000_0000   reserved input region: SP1 places the input here   SP1
 0x20_0000_0000 ← end of memory (128 GiB)
```

- **The input** is put in the reserved region by SP1's `read_input`, not in the heap. There is no
  fixed size cap beyond the region's 16 GiB, and none of Pico's constraints about where input may
  be read apply.
- **Two allocators share the address space.** SP1's own heap serves libzkevm's Rust code; zesu has
  its own bump/free-list heap. They must never overlap, so zesu's heap is placed at 64 GiB,
  far above where SP1's allocator (which hands out low addresses first) will ever reach: it would
  take over 64 GiB of allocation inside SP1's heap. A `.bss`-reserved heap would be disjoint by
  construction, but SP1's ELF loader walks every `.bss` word, so a 512 MiB `.bss` is impractical.

## SP1 specifics that shaped this target

- **Input format.** The test vectors use ZisK's format: an 8-byte little-endian payload length,
  the SSZ payload, then padding. The zkvm-standards interface hands the guest only the payload,
  and SP1's `read_input` returns the whole stdin entry as is, so the runner strips the header and
  padding and pushes the payload as **one** `write_slice` call (`read_input` exposes only the first
  entry).
- **No misaligned access.** SP1's executor stops with an error on misaligned loads and stores
  (`LH must be aligned to 2 bytes`). zesu's published `rv64im` object is built to allow them, and
  running it on SP1 fails, so this target builds zesu for strict alignment. SP1's SDK README
  describes the target as equivalent to the zkvm-standards `riscv64im_zicclsm`, which does not
  hold at run time.
- **Output** goes to SP1's public-values stream (fd 13) through `write_output`; the runner returns
  the raw bytes.

## How zesu is built

zesu is not linked from a published object. `build.zig.zon` pins a zesu commit as a Zig package
dependency (`git+https://github.com/Consensys-Incorporated/zesu#<commit>`), and `build.zig` calls
zesu's `addGuestObject(builder, target, optimize, has_dma)` with SP1's own `target`. The ISA
extensions a zkVM supports are therefore decided here, in one place.

- Local zesu checkout: `ZESU_SOURCE=../../zesu make` (or `zig build --fork=../../zesu`) overrides
  the pin without editing any file.
- Bump the pin: `zig fetch --save=zesu "git+https://github.com/Consensys-Incorporated/zesu#<commit>"`.

## Build and run

```sh
make sdk                          # fetch libzkevm.a + zkvm.ld (checksum-verified) into lib/
make runner                       # Rust runner (stable Rust; sp1-sdk executor only)
make                              # guest ELF -> zig-out/bin/zesu-sp1
make test                         # execute all vectors
make run INPUT=../vectors/sepolia_amsterdam_11856500.bin
```

Set `RUST_LOG=info` to see the guest's `zkvm_log` output.

The SDK version and its SHA-256 are pinned in the Makefile (`SP1_VERSION`, `SP1_SDK_SHA256`); to
move to a newer SP1, update both after checking the release's `zkevm-sdk-v<version>.tar.gz`.
