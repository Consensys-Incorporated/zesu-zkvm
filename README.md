# zesu-zkvm

zkVM guest builds for [zesu](https://github.com/Consensys/zesu) — the Ethereum
stateless block executor. Each subdirectory is a self-contained build for one
zkVM target.

## Targets

| Directory | zkVM | Status |
|---|---|---|
| [`zisk/`](zisk/) | [Zisk 0.17.0](https://github.com/0xPolygonHermez/zisk) | Working |
| [`openvm/`](openvm/) | [openvm](https://github.com/openvm-org/openvm) | Working (emulation only, no proofs) |
| [`linea/`](linea/) | [Linea zkVM](https://github.com/Consensys/linea-zkvm) | Working |

## Building

There are two ways to supply the zesu core object, depending on whether you want
to build against a published release or a local development checkout.

### Against a published zesu release (recommended)

Download `zesu.rv64im.o` from the [zesu releases page](https://github.com/Consensys/zesu/releases)
and pass it via `-Dzesu_obj`. This avoids cloning the zesu repository entirely.

```sh
# Download the latest release
curl -fsSL https://github.com/Consensys/zesu/releases/latest/download/zesu.rv64im.o \
  -o /tmp/zesu.rv64im.o

# Or pin a specific tag
curl -fsSL https://github.com/Consensys/zesu/releases/download/bal-devnet-3/zesu.rv64im.o \
  -o /tmp/zesu.rv64im.o

# Build any target
zig build -Doptimize=ReleaseFast -Dzesu_obj=/tmp/zesu.rv64im.o   # from zisk/, openvm/, or linea/
```

For the zisk target, `libziskos.a` must also be present. See [`zisk/README.md`](zisk/README.md)
for the full build procedure, or use the Makefile which handles this automatically:

```sh
cd zisk
make ZESU_OBJ=/tmp/zesu.rv64im.o
```

### Against a local zesu checkout (development)

When working on zesu and zesu-zkvm together, omit `-Dzesu_obj` and the build
will automatically invoke `zig build rv64im-object` in the sibling zesu checkout
and link against the resulting `zig-out/lib/zesu.o`. This requires zesu to be
checked out as a sibling:

```
<parent>/
  zesu-zkvm/    <- this repo
  zesu/         <- EVM + stateless executor (built in-place as rv64im object)
  zisk/         <- Zisk source checkout (needed to build libziskos.a for zisk target)
```

```sh
# From zisk/, openvm/, or linea/ — no -Dzesu_obj needed
zig build -Doptimize=ReleaseFast
```

Zig's build caching means subsequent builds only recompile zesu when its sources change.

## Repository layout

```
zesu-zkvm/
  zisk/     — Zisk zkVM guest (Zig + libziskos.a)
  openvm/   — OpenVM guest (Zig ELF)
  linea/    — Linea zkVM guest (Zig ELF, stripped)
```

Each target directory contains its own `build.zig`, linker script, and `README.md`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
