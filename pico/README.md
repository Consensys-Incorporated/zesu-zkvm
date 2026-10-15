# zesu-zkvm / pico

Pico (Brevis) zkVM guest for zesu — compiles the Ethereum stateless block executor to a
`riscv64-freestanding-none` ELF that runs inside
[Pico](https://github.com/brevis-network/pico) (tested against v2.1.2, `bfa8f12`).

Pico's VM executes **rv64im** (ELF64, `EM_RISCV`); it has no Zbb/Zbs and no
compressed instructions.

## Status

| | |
|---|---|
| RISC-V execution of zesu on Pico's VM | yes — both vectors run to completion, 34M–1.3B cycles |
| keccak256, sha256 | Pico precompiles |
| ripemd160, modexp, blake2f | pure Zig, shared with `openvm/` |
| ecrecover, secp256k1/secp256r1 verify | **software** (`std.crypto`) — correct but ~3M cycles per signature |
| bn254, bls12-381, kzg | **not implemented** (return failure) |

`make test` executes each vector on Pico's VM and compares the guest's output with the expected
output: the SSZ root of the block's new-payload request, plus `valid`, chain id and schema id.
So the vectors show that RISC-V execution of zesu on Pico's VM reaches the correct result for
full blocks. 

`sepolia_amsterdam_11856500` matches in full. `mainnet_fusaka_24758573` matches except the
`valid` byte, which is 0 only because that block calls the KZG point-evaluation precompile
(verified by temporarily forcing it to succeed: the output then matches in full).

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
- **Program limits:** at most 2²² instructions (zesu is about 250k), and segments must start at
  `0x10000` or above.

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
make test                         # execute all vectors
make run INPUT=../vectors/sepolia_amsterdam_11856500.bin
```

Set `RUST_LOG=info` to see the guest's `zkvm_log` output.

On macOS 27 the pinned nightly cannot link against the newest SDK; build the runner with
`SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk`.

## Next steps

1. Wire the Pico curve precompiles (`SECP256K1_*`, `SECP256R1_*`, `UINT256_MUL`) under
   ecrecover/verify to replace the software path.
2. bn254 g1 add/mul on `BN254_ADD/DOUBLE`; bn254 pairing and bls12-381 (incl. KZG, which the
   mainnet vector needs) in Zig on the Fp/Fp2 precompiles.
3. CI (`.github/workflows/ci.yml`, job `pico`) builds the guest and smoke-tests the Sepolia vector;
   add the mainnet vector once KZG works.
