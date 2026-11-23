# Testing

Every zkVM guest is tested the same way. A shared set of stateless-validation inputs in
[`vectors/`](vectors/) runs through each target's emulator, and the guest's output is compared
byte-for-byte with the expected result.

## Running the tests

From a target directory (`zisk/`, `sp1/`, `openvm/` or `pico/`):

```sh
make test                                              # every vector in ../vectors
make test VECTORS=../vectors/zkevm.p256verify*.bin     # a subset
make test ZESU_SOURCE=../../zesu                       # against a local zesu checkout (zisk/sp1/pico)
```

`make test` builds the guest (ReleaseFast) and the target's runner, then runs every vector.
Each vector prints a one-line result, followed by a summary:

```
OK    mainnet_fusaka_24758573
FAIL  zkevm.ecrecover.precompiles__state-...
      expected: 5e1f...0101000000000000000100
      got:      5e1f...0001000000000000000100
---- 25 passed, 1 failed
failed:
  zkevm.ecrecover.precompiles__state-...
```

The exit status is non-zero if any vector fails, or if `VECTORS` is empty. The runner's own
output is shown only for failures.

Pico has two more test targets:

```sh
make unit       # native unit tests of the shared curve code (no VM)
make selftest   # crypto modules on the Pico VM: syscall path vs software path + known answers
```

Linea has no runner, so CI only builds it.

## Vectors

Each vector is a pair of files:

| File | Contents |
|---|---|
| `<name>.bin` | u64 LE payload length, then the SSZ `StatelessInput`, zero-padded to a multiple of 8 bytes |
| `<name>.expected.hex` | the expected 43-byte `SszStatelessValidationResult` as hex: `root(32) ‖ valid(1) ‖ chain_id(8) ‖ schema_id(2)` |

The vectors fall into two groups:

- **Real blocks**:
  - `mainnet_fusaka_24758573`
  - `sepolia_amsterdam_11856500`
- **`zkevm.*`**: blocks taken from the
  [execution-specs](https://github.com/ethereum/execution-specs) `tests-zkevm` fixtures (the
  release is recorded in [`vectors/zkevm/RELEASE`](vectors/zkevm/RELEASE)). They cover what the
  real blocks don't:
  - every precompile a zkVM accelerates (ecrecover, sha256, ripemd, modexp, blake2, BN254
    add/mul/pairing, BLS12-381, KZG point evaluation, P-256)
  - storage and trie shapes, including all three blocks of a trie deletion that collapses a
    branch into a leaf
  - invalid blocks, which the guest must report as `valid = false` instead of trapping

The vectors are checked in, so CI never downloads fixtures.

### How the input reaches the guest

The `.bin` header is a file-format convention. It doesn't describe what the guest reads.
Each runner delivers the input the way [ere](https://github.com/eth-act/ere) does in
production, so a guest that passes here also works under ere:

| Target | Runner behavior | ere equivalent |
|---|---|---|
| ZisK | `ziskemu` reads the `.bin` file as-is | `framed_stdin`: the same length + payload + padding |
| SP1 | strips the header, `SP1Stdin::write_slice(payload)` | `write_slice(input.stdin())` |
| OpenVM | strips the header, `StdIn::write_bytes(payload)` | `write_bytes(input.stdin())` |
| Pico | strips the header, `Stdin::write_bytes(payload)` | `write_bytes(input.stdin())` |

Don't feed a guest the raw `.bin` (header included) unless ere does the same for that zkVM.
Pico once parsed the header itself, so it passed locally and failed under ere (#71).

## The runner harness: `vectors/run.sh`

All four Makefiles call the same compare loop:

```sh
vectors/run.sh "<runner> -e <elf>" vector.bin...
```

- The script calls `<runner> -e <elf> -i <vector.bin> -o <out>` for each vector. It compares the
  first `SSZ_OUTPUT_LEN` bytes of `<out>` (default 43) with `<vector>.expected.hex`.
- A vector without an `.expected.hex` is run and reported as `INFO`; it doesn't count as a failure.
- With `RUNNER_BATCH=1`, the script runs every vector in a single runner call
  (`-i a.bin -o a.out -i b.bin -o b.out ...`). OpenVM uses this because compiling the guest costs
  about 10 s per process, far more than executing a small block. The runner must keep going past
  a failing input and exit non-zero at the end; a vector that produced no output counts as failed.
  If the runner exits 0 but some outputs are missing, it probably predates batching and only ran
  the last input.
- Each target's `make runner` always calls `cargo build`, and cargo's incremental build decides
  whether the runner is stale. Don't make the runner a file target: an old binary, for example
  one restored from a CI cache, would then survive changes to its source.

A new target only needs a runner that accepts `-e`, `-i` and `-o` and writes the guest's public
output. Its `make test` can then call `run.sh`.

## Refreshing the `zkevm.*` vectors

Refresh them when the pinned zesu moves to a new `tests-zkevm` release (zesu's `build.zig`
declares it as `zkevm_version`). [`vectors/zkevm/fetch.py`](vectors/zkevm/fetch.py) is a
maintainer tool and never runs in CI:

```sh
curl -fLO https://github.com/ethereum/execution-specs/releases/download/tests-zkevm%40v21.0.7/fixtures_zkevm.tar.gz
python3 vectors/zkevm/fetch.py --tarball fixtures_zkevm.tar.gz --release tests-zkevm@v21.0.7
```

The script streams the archive (about 600 MB), so nothing needs to be unpacked first. It then:

1. Writes the blocks that [`vectors/zkevm/subset.txt`](vectors/zkevm/subset.txt) selects into
   a scratch directory.
2. Checks that every subset line matched at least one block and that no two lines produce the
   same vector.
3. Only then replaces every existing `vectors/zkevm.*` file and updates `RELEASE`.

If a check fails, for example because a fixture was renamed upstream or the tarball is
corrupt, `vectors/` and `RELEASE` are left unchanged.

Each `.expected.hex` comes from the fixture's `statelessOutputBytes`, never from a guest. This
makes the vectors an independent oracle.

### `subset.txt` format

```
<glob>  [count]  [valid|invalid]  [pick=S]
```

| Field | Meaning |
|---|---|
| `glob` | fnmatch pattern for fixture JSON paths, relative to `blockchain_tests/for_amsterdam/` |
| `count` | blocks to take from each matching file, spread evenly over its sorted test cases (default 1; `all` takes every block) |
| `valid` / `invalid` | only blocks whose expected output has that validity |
| `pick=S` | only test cases whose id contains `S`. Use it to choose an input that does real work, since the first case is often an empty or trivial one |

Keep the subset small. Every vector runs on every target in CI, and the whole suite should
finish in about a minute per zkVM.

## Blessing expected output

`make bless` rewrites the `.expected.hex` files of `$(VECTORS)` (every vector by default) from
the current guest's output. Use it only for vectors with no independent source of truth, i.e.
the real blocks:

```sh
make bless VECTORS="../vectors/mainnet_*.bin ../vectors/sepolia_*.bin"
```

 Check the diff carefully: blessing a broken guest makes its bug the expected output. Never bless the `zkevm.*`
vectors; regenerate them with `fetch.py` instead.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `make test` against every vector for
ZisK (the "Vectors" job), OpenVM, SP1 and Pico. Pico also runs `make unit` and `make selftest`.
