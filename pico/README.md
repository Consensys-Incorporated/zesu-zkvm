# zesu-zkvm / pico

Pico (Brevis) zkVM guest for zesu — compiles the Ethereum stateless block executor to a
`riscv64-freestanding-none` ELF that runs inside
[Pico](https://github.com/brevis-network/pico) (tested against v2.1.2, `bfa8f12`).

Pico's VM executes **rv64im** (ELF64, `EM_RISCV`); it has no Zbb/Zbs and no
compressed instructions.

## Status

| | |
|---|---|
| RISC-V execution of zesu on Pico's VM | yes — both vectors run to completion and match in full |
| keccak256, sha256 | Pico precompiles |
| ripemd160, modexp, blake2f | pure Zig, shared with `openvm/` |
| ecrecover, secp256k1/secp256r1 verify | Pico curve precompiles (`SECP256K1_*`, `SECP256R1_*`) plus `UINT256_MUL` for scalar arithmetic |
| bn254 G1 add/mul | Pico `BN254_ADD`/`BN254_DOUBLE` |
| bn254 pairing | Zig optimal-ate pairing on the `BN254_FP*` / `FP2*` precompiles (~20M cycles per pair) |
| bls12-381 G1 add/MSM | Pico `BLS12381_ADD`/`BLS12381_DOUBLE` |
| bls12-381 G2, pairing, map-to-curve | Zig on the `BLS12381_FP*` / `FP2*` precompiles |
| KZG point evaluation (EIP-4844) | a real pairing check, not a trusted result (~100M cycles per call) |

`make test` executes each vector on Pico's VM and compares the guest's output with the expected
output: the SSZ root of the block's new-payload request, plus `valid`, chain id and schema id.
Both vectors match in full (`sepolia_amsterdam_11856500`: 695M cycles; `mainnet_fusaka_24758573`:
417M cycles, which includes one KZG point evaluation). So RISC-V execution of zesu on Pico's VM
reaches the correct result for full blocks. This target is for execution; it is not used to
generate proofs.

### Testing the crypto

The curve code (`src/zkvm_accel/secp.zig`, `bn254.zig`, `bls12_381.zig`) is generic over a field
backend: the guest uses Pico's precompiles (`pico_fp.zig`), and tests use a software backend
(`soft.zig`), so the same algorithms are checked in two places.

- `make unit` — native unit tests (about a minute): the official EIP-196/197/2537 vectors, c-kzg
  KZG vectors, ECDSA differential tests against `std.crypto`, and property tests (bilinearity,
  subgroup orders, Frobenius).
- `make selftest` — runs the same modules on Pico's VM and compares the precompile-backed path
  against software and known answers (about two minutes; `-Dselftest=secp|bn254|bls` runs one).

## Architecture

The guest ELF, `zig-out/bin/zesu-pico`, is linked from two parts:

```
zesu-pico  (ELF)
├── zesu         — EVM + stateless execution, built by this project's build.zig from the
│                  zesu source for Pico's own target (rv64im, strict alignment)
└── pico-host.o  — pico_host.zig  accelerators, heap vars, read_input/write_output, log, exit
                   startup.S      _start, calls pico_init_heap → main → pico_exit
```

```
_start (startup.S)
  gp, sp = 0x78000000
  call pico_init_heap    — ZKVM_HEAP_POS = _end, ZKVM_HEAP_TOP = 512 MB
  call main              — zesu; returns 0/1 in a0
  call pico_exit(a0)     — sha256(public values) → 8×COMMIT, 8×COMMIT_DEFERRED_PROOFS, HALT
```

## Memory layout

Pico gives the guest one flat address space, 0 to `0x78000000` (about 1.9 GB), shared by the
program, its input, and everything it allocates. Addresses are for the current build (they
shift slightly with each build; sizes are approximate):

```
 address       what is there                                  who puts it there
 ─────────────────────────────────────────────────────────────────────────────────────────
 0x00000000    register file (32 × 8 bytes)                   Pico
 0x00000100    lowest address the guest may use               Pico
 0x00010000    lowest address a program segment may use       Pico
 0x00200000    ELF headers                                    ┐
 0x00200800    .text         guest code            ~1.0 MB    │
 0x002f2fa0    .rodata       constants             ~31 KB     │  the guest program:
 0x002fab00    .bss          zero-filled statics   ~1.1 MB    │  defined by the ELF
 0x003fefd0  ← _end (the end of everything the ELF defines)   ┘
 0x003fefd0    heap, in order of use:                         the guest, at run time
               1. the input        (size = the input file, rounded up to 8 bytes)
               2. zesu's allocations while it processes the input
 0x20000000  ← heap limit (512 MB, GUEST_MAX_MEM in pico_host.zig)
               unused
 0x78000000  ← end of memory; the stack starts here and grows downward
```

Reading it top to bottom:

- **The guest program** is everything the ELF defines: code, constants, and the zero-filled
  static data (`.bss`). Pico treats this memory as fixed by the program, with exactly these
  starting values.
- **The input** (the block and its witness, one `.bin` file) is *not* part of the program. The
  host supplies it at run time, and Pico loads it into memory the guest chooses.
- **The heap** holds the input first and then everything zesu allocates. The input has no fixed
  size cap of its own; it only has to fit in the heap, together with whatever zesu allocates
  while processing it (decoded data takes more room than the raw input). To allow larger inputs,
  raise `GUEST_MAX_MEM`; the hard ceiling is the 0x78000000 end of memory.

### Why the input cannot go in a static buffer

The input and the guest program must never share memory. If the guest loads its input into an
address the ELF already defines — for example a static buffer in `.bss` — that address ends up
with two conflicting starting values: the zero from the program and the input byte from the
host. Execution can still appear to run correctly, but Pico's proof system rejects the program
("global lookup cumulative sum is not zero"), so the rule keeps the target valid for anyone who
does prove it.

(Pico's loader treats every `.bss` word as part of the program, which is why `.bss` counts.)
So `read_input` takes its buffer from the heap, which starts after the ELF's memory ends. The
buffer must also be:

- 8-byte aligned, with its size rounded up to a multiple of 8;
- untouched before the read, and read into only once;
- exactly the length of the input (Pico checks this).

Pico's own name for this operation is a "hint": the ecalls are `HINT_LEN` and `HINT_READ`, and
the OpenVM and SP1 targets use the same word.

## Other Pico specifics

- **Output** goes to file descriptor 3 (the `WRITE` ecall). At halt the guest commits a SHA-256
  digest of everything it wrote there, as Pico's SDK does; verifiers see that digest, and the
  runner returns the raw bytes.
- **No misaligned access.** Pico stops with an error on misaligned loads and stores
  (`lh`/`lw`/`ld`/`sh`/`sw`/`sd`). zesu's published `rv64im` object is built to allow them, so
  this target builds zesu for strict alignment (see "How zesu is built").
- **Precompile data layout:** pointers must be 8-byte aligned, and data is arrays of `u64` (a
  SHA-256 word occupies the low half of each `u64`).
- **Optimization workaround: `src/memops.S`.** Hand-written word-wise `memcpy`/`memset` that
  override Zig's `compiler_rt` versions, which copy to an unaligned destination with eight byte
  stores per 8 bytes (about 2.8 cycles/byte). Profiling the mainnet vector showed `memcpy` at 62%
  of all cycles, mostly the BLS12-381 tower code copying field elements for the KZG check; this
  file roughly halved the total (899M to 450M cycles), and `tower.zig` passing operands by
  pointer took it to 417M. It exists only because of how Zig's generic `memcpy` and Pico's
  alignment rules interact, so when moving to a newer Pico (or Zig) it is a candidate for
  removal: delete it, drop the two `addAssemblyFile("src/memops.S")` lines in `build.zig`, and
  compare cycle counts to see whether it still pays for itself.
- **Execute-only runs use the untraced emulator.** The runner calls `RiscvEmulator::run_fast`
  (Pico's "simple" mode) directly. Going through `RiscvProver::emulate` records every event for
  proving and was 2-3x slower (mainnet vector 37s vs 16s, sepolia 44s vs 13s). `-p` still takes
  the full proving path.
- **Program limits:** at most 2²² instructions (zesu is about 250k), and segments must start at
  `0x10000` or above.

## Provenance of the pure-Zig crypto

Where an operation is not (fully) done by a Pico precompile, the Zig implementation is below. None
of it is a port of another project's source; each follows a public specification or textbook
algorithm, listed here so the lineage is clear. Only sources the code or its tests already cite are
named. If a piece was in fact adapted from somewhere else, add it here.

| Code | Not accelerated | Follows / checked against |
|---|---|---|
| `ripemd160.zig`, `blake2f.zig`, `modexp.zig` (shared with `openvm/`) | whole primitive (no Pico precompile) | RIPEMD-160: Dobbertin, Bosselaers, Preneel's reference description (<https://homes.esat.kuleuven.be/~bosselae/ripemd160.html>). BLAKE2f: RFC 7693 §3.2 and EIP-152. modexp: EIP-198. |
| `secp.zig` | scalar-field arithmetic and ECDSA/recovery logic (Pico supplies affine point add/double and `UINT256_MUL`) | ECDSA verify and public-key recovery as in SEC 1 / FIPS 186; two-scalar multiplication by Shamir's trick. Differentially tested against `std.crypto` (`ecdsa_soft.zig`). |
| `bn254.zig` | G2 arithmetic, optimal-ate pairing, final exponentiation | EIP-196 / EIP-197; optimal ate pairing (Vercauteren, "Optimal pairings", 2008) with a plain exponentiation for the hard part of the final exponentiation. Tested against the EIP-196/197 vectors. |
| `bls12_381.zig` | G2 arithmetic, optimal-ate pairing, final exponentiation, KZG check | EIP-2537 and EIP-4844; same pairing structure as BN254, on the M-type twist. Tested against the Besu EIP-2537 CSVs (from the pinned zesu) and the c-kzg-4844 `verify_kzg_proof` vectors. |
| `bls12_381.zig` map-to-curve | MAP_FP_TO_G1 / MAP_FP2_TO_G2 | RFC 9380 simplified SWU plus the isogeny. The isogeny constants (`bls12_381_map_constants.zig`) are generated from `py_ecc`, the library EELS uses for EIP-2537. |
| `tower.zig` | Fp2/Fp6/Fp12 extension tower (Fp2 ops use `FP2_*` syscalls) | Standard tower construction; Frobenius coefficients ξ^((p^k-1)/6) derived at runtime. |
| `memops.S` | (not crypto) | Original word-wise `memcpy`/`memset`; see "Other Pico specifics". |

The KZG check is a real pairing equation. OpenVM's `kzgVerify`, by contrast, emits a pairing hint
and returns true.

## How zesu is built

zesu is not linked from a published object. `build.zig.zon` pins a zesu commit as a Zig package
dependency (`git+https://github.com/Consensys-Incorporated/zesu#<commit>`), and `build.zig` calls
zesu's `addGuestObject(builder, target, optimize, has_dma)` with the same `target` it uses for the
Pico host object. The ISA extensions a zkVM supports are therefore decided here, in one place, and
zesu needs no Pico-specific release artifact. (zesu's published `rv64im` object targets
I+M+Zicclsm+unaligned access and cannot be used: Pico traps on the misaligned loads/stores it
contains.)

- Local zesu checkout: `ZESU_SOURCE=../../zesu make` (or `zig build --fork=../../zesu`) overrides the
  pin without editing any file.
- Bump the pin: `zig fetch --save=zesu "git+https://github.com/Consensys-Incorporated/zesu#<commit>"`.
- The pinned commit must export `addGuestObject` (zesu `build.zig`, "build: export
  addGuestObject for zkVM projects").

## Build and run

```sh
make runner                       # Rust runner (pinned nightly via rust-toolchain)
make                              # guest ELF -> zig-out/bin/zesu-pico
make test                         # execute all vectors and compare with expected output
make run INPUT=../vectors/sepolia_amsterdam_11856500.bin     # execute, print execution stats
make trace INPUT=../vectors/sepolia_amsterdam_11856500.bin   # execute, print stats + trace report
make prove INPUT=../vectors/sepolia_amsterdam_11856500.bin   # also prove and verify (slow)
```

`run`, `trace` and `prove` require `INPUT`. All of them build the guest and runner first. Set
`RUST_LOG=info` to see the guest's `zkvm_log` output.

- **`make run`** executes without recording a trace (the fast path) and prints the `-X` report:
  cycles, throughput and per-syscall counts, like `ziskemu -X` but counts only, since Pico has no
  per-category cost model.
- **`make trace`** runs the emulator in trace mode and prints the `-X` report followed by a
  trace report built from the prover events Pico records: chunk count, events per chip, the
  instruction mix, and the top functions by cycles (each cpu event's PC attributed to the ELF's
  symbols). It is 3-4x slower than `make run` (sepolia vector: ~60s vs 13s); records are
  aggregated per chunk as they arrive.
- **`make prove`** generates and verifies a RISCV-phase proof; no stats are printed.

The same modes are available from the build system and the runner directly:

```sh
zig build run -Doptimize=ReleaseFast -Dinput=../vectors/mainnet_fusaka_24758573.bin             # execute
zig build run -Doptimize=ReleaseFast -Dinput=../vectors/mainnet_fusaka_24758573.bin -- -X       # + stats
zig build run -Doptimize=ReleaseFast -Dinput=../vectors/mainnet_fusaka_24758573.bin -- -T       # + trace
zig build run -Doptimize=ReleaseFast -Dinput=../vectors/mainnet_fusaka_24758573.bin -Dprove     # prove
runner/target/release/zesu-pico-runner -e zig-out/bin/zesu-pico -i <block.bin> [-X] [-T] [-p] [-o out]
```

Runner flags: `-X` execution stats, `-T` trace report (implies `-X`), `-p` prove, `-o` write the
guest's public values to a file. Flags go after `--` for `zig build run`; `make` takes no runner
flags, which is why `run`/`trace`/`prove` are separate targets. `zig build run` without
`-Dinput` fails with a message saying so.

## Next steps

1. Cut cycle cost where it is high: the pairings use affine Miller steps and a plain
   final-exponentiation hard part (KZG ≈ 100M cycles, bn254 ≈ 20M per pair). Projective steps and
   cyclotomic squaring would reduce both substantially.
2. Use Pico's `BLS12381_DECOMPRESS` for G1 decompression (currently a software square root).
3. Proving has not been attempted for a full block (this target is for execution).
