# zesu-zkvm / openvm

OpenVM zkVM guest for zesu — compiles the Ethereum stateless block executor to a
`riscv64-freestanding-none` ELF that runs inside
[OpenVM](https://github.com/openvm-org/openvm).

## Architecture

The guest ELF is assembled from two relocatable objects:

```
zesu.o          — EVM + stateless execution logic (from zesu/core)
                  Compiled for rv64im freestanding; leaves all platform
                  symbols (IO, crypto, heap, runtime) as extern refs.

openvm-host.o   — All platform symbols:
                    openvm_host.zig  pure-Zig / std.crypto accelerators,
                                     hint-stream IO, bump heap vars + init
                    startup.S        _start, TERMINATE exit (see below)
```

Unlike the ZisK build, no partial link step is needed: OpenVM has no external
archive with duplicate symbol definitions. The final link is a clean
`zesu.o + openvm-host.o` with each symbol defined exactly once.

### Entry-point chain

```
_start           (startup.S)
  li sp, 0x00200400
  call openvm_init_heap   — sets ZKVM_BUMP_HEAP_POS / ZKVM_BUMP_HEAP_TOP
  call main
  branch on a0 (main's return value) to the matching TERMINATE immediate

main()           (zesu.o / zesu/src/zkvm/root.zig, Zig, export fn)
  calls runner.runStateless(bump_allocator)
  writes SSZ output via write_output (REVEAL instructions)
  returns 0 (success) or 1 (guestMain() error) — no explicit halt call
```

`main()` has no way to pass a runtime value as TERMINATE's immediate (it's
encoded directly into the instruction, not a register operand), so the
branch-and-halt lives entirely in `startup.S` — the one file that already
has to speak OpenVM's non-standard opcode regardless of guest language.

### Symbol ownership

| Symbol(s)                                                  | Source | Implementation |
|------------------------------------------------------------|---|---|
| `zkvm_keccak256`, `zkvm_sha256`                            | `openvm_host.zig` | `std.crypto` |
| `zkvm_secp256k1_ecrecover`, `zkvm_secp256k1_verify`        | `openvm_host.zig` | `std.crypto.ecc.Secp256k1` |
| `zkvm_ripemd160`                                           | `openvm_host.zig` | stub (returns zero) |
| `zkvm_modexp`                                              | `openvm_host.zig` | stub (zeros output) |
| `zkvm_bn254_g1_add`, `zkvm_bn254_g1_mul`                   | `openvm_host.zig` | stub (returns false) |
| `zkvm_bn254_pairing`                                       | `openvm_host.zig` | stub (returns false) |
| `zkvm_blake2f`                                             | `openvm_host.zig` | stub (returns false) |
| `zkvm_kzg_point_eval`                                      | `openvm_host.zig` | pairing check via OpenVM's pairing library (`pairing/`) |
| `zkvm_bls12_g1_*`, `zkvm_bls12_g2_*`                       | `openvm_host.zig` | OpenVM Fp/Fp2/ECC accelerators |
| `zkvm_bls12_pairing`                                       | `openvm_host.zig` | OpenVM's pairing library (`pairing/`) |
| `zkvm_bls12_map_fp*`, `zkvm_secp256r1_verify`              | `openvm_host.zig` | stubs (return false) |
| `read_input`                                               | `openvm_host.zig` | hint-stream (hintInput + hintBufferChunked) |
| `write_output`                                             | `openvm_host.zig` | REVEAL instructions (funct3=2, opcode 0x0b) |
| `zkvm_log`                                                 | `openvm_host.zig` | print_str phantom (funct3=3, imm=1) |
| exit (TERMINATE, funct3=0, opcode 0x0b)                    | `startup.S` | branch on `main()`'s a0 return value |
| `ZKVM_BUMP_HEAP_POS`, `ZKVM_BUMP_HEAP_TOP`                 | `openvm_host.zig` | BSS vars; initialized by `openvm_init_heap` from `_end` |
| `openvm_init_heap`                                         | `openvm_host.zig` | called by `_start` before `main` |

## Status

**Early / experimental.** Known limitations:

- **No ZK proof generation.** The runner calls `sdk.execute()` (emulation
  only). Proof generation would require wiring in STARK aggregation params and
  a real trusted setup.
- **The BN254 pairing and BLS12-381 map-to-curve are stubs.** Blocks that
  call them will produce wrong state.
- **ecrecover, SHA-256, keccak256, secp256k1 verify** use `std.crypto` —
  functional and tested against mainnet blocks.

## Directory layout

```
openvm/
  src/
    openvm_host.zig    — host object root: IO, runtime, heap init, 19 export fn zkvm_*
    zkvm_io.zig        — hint-stream I/O (read_input, write_output, printStr)
    startup.S          — _start: sets sp, calls openvm_init_heap, calls main
    runtime/
      stdlibs_accel.zig — accel_impl: keccak256/sha256/ecrecover via std.crypto;
                          kzg_point_eval returns success; everything else stubbed
      allocator.zig     — OpenVmAllocator (unused after refactor; retained for reference)
      main.zig          — re-export of OpenVmAllocator (unused after refactor)
      zesu_allocator.zig — zesu_allocator shim (unused after refactor)
    main.zig            — previous entry point (unused after refactor)
  runner/
    src/main.rs        — Rust host: executes the ELF the way eth-act/ere does
  openvm.ld            — linker script (TEXT_START=0x00200800, 512 MB heap)
  openvm.toml          — VM config: a copy of openvm's `openvm_standard.toml` (`SdkVmConfig::standard()`)
  build.zig            — Zig build script
  Makefile             — build / run / test / bless
```

## Dependencies

| Dependency | Version | Notes |
|---|---|---|
| Zig | ≥ 0.16.0 | see `minimum_zig_version` in `build.zig.zon` |
| Rust stable | ≥ 1.91 | `rustup update stable` |
| OpenVM | [`v2.1.0-preview`](https://github.com/openvm-org/openvm/releases/tag/v2.1.0-preview) | git dep, pinned to the revision [eth-act/ere](https://github.com/eth-act/ere) v0.17.0 uses |
| OpenVM Rust toolchain | `openvm-1.94.1` | builds `pairing/` for `riscv64im-unknown-openvm-elf`; install with OpenVM's `ci/install-openvm-toolchain.sh` (see the Makefile) |
| zesu/core | path dep | sibling at `../../zesu/core` |

## Building the guest ELF

```sh
# Build the Rust host runner (one-time or after openvm changes)
make runner

# Build OpenVM's pairing library into lib/ (one-time or after pairing/ changes)
make pairing-lib

# Build the Zig guest ELF
make

# Or both in one step
make all
```

The build executes two steps:

1. **Compile `zesu.o`** — zesu/core's `zkvm_root` module for rv64im freestanding.
   All `zkvm_*`, IO, and heap symbols are unresolved extern refs.
2. **Final link** — `zesu.o + openvm-host.o + lib/libzesu_openvm_pairing.a + startup.S`
   under `openvm.ld`.

### Pairing library (`pairing/`)

The BLS12-381 pairing check (EIP-2537 `PAIRING_CHECK`, EIP-4844 KZG) comes from
OpenVM's own guest library, `openvm-pairing`, built as a static library with
OpenVM's toolchain and the rustc
flags `cargo openvm build` uses (`pairing/.cargo/config.toml`). It shares the
Zig guest's heap through a patched copy of `openvm-platform`
(`pairing/vendor/`), and `make pairing-lib` localizes its `_start` and `mem*`
symbols so the Zig entry point and routines stay in charge.

Output: `zig-out/bin/zesu-openvm`

## Running

```sh
make run INPUT=../vectors/mainnet_24758573.bin

# Run all vectors and check against .expected.hex files
make test

# Regenerate expected outputs after intentional changes
make bless
```

## ere compatibility

The guest targets the ABI eth-act/ere's OpenVM host executes with, so the same ELF
runs under the runner here and under `zkevm-benchmark-workload`:

- **VM config:** `SdkVmConfig::standard()` with 256 public-value bytes. The
  accelerators in `src/zkvm_accel/` encode modulus, curve, Fp2 and pairing indices
  in that config's order (BN254 first, then secp256k1, P-256, BLS12-381).
- **Input:** the raw SSZ payload as one hint-stream entry — ere's
  `StdIn::write_bytes(statelessInputBytes)`, read like `openvm::io::read_vec`.

## Input format

Input files (`vectors/*.bin`) share the ZisK target's format:

```
[0..8]   payload_len  — u64 LE, byte count of the SSZ body
[8..]    SSZ body     — padded to 8-byte boundary
```

The host runner strips the header and passes only the SSZ body to the guest.

## Output format

41 bytes written to `public_values[0..41]` via REVEAL instructions:

```
[0..32]  new_payload_request_root  — SSZ hash_tree_root of the execution payload
[32]     success                   — 1 = block executed correctly, 0 = failed
[33..41] chain_id                  — u64 LE
```

## Memory map (OpenVM)

| Region | Address | Size |
|---|---|---|
| Stack top | `0x00200400` | grows down |
| ROM (code + rodata) | `0x00200800` | TEXT_START |
| Heap | `_end` (after BSS) | up to `0x20000000` (512 MB) |
