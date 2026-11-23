#!/usr/bin/env python3
"""Regenerate the tests-zkevm vectors checked into vectors/ (maintainer tool; not run in CI).

Reads the blocks subset.txt selects from an execution-specs fixtures_zkevm.tar.gz and writes each
as vectors/zkevm.<name>.bin (u64 LE payload length + SSZ input, zero-padded to 8 bytes, the format
every runner takes) and vectors/zkevm.<name>.expected.hex (its statelessOutputBytes). Existing
zkevm.* vectors are replaced only once every subset line has matched. The release used is recorded in vectors/zkevm/RELEASE.

Use the release the guests' pinned zesu declares (`zkevm_version` in zesu's build.zig):

    curl -fLO https://github.com/ethereum/execution-specs/releases/download/tests-zkevm%40v21.0.7/fixtures_zkevm.tar.gz
    python3 vectors/zkevm/fetch.py --tarball fixtures_zkevm.tar.gz --release tests-zkevm@v21.0.7
"""
import argparse
import fnmatch
import glob
import hashlib
import json
import os
import re
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_ROOT = "blockchain_tests/for_amsterdam/"


def parse_subset(path):
    entries = []
    for n, line in enumerate(open(path), 1):
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        count, want, pick = 1, None, None
        for f in fields[1:]:
            if f.startswith("pick="):
                pick = f[len("pick="):]
            elif f in ("valid", "invalid"):
                want = f == "valid"
            elif f == "all":
                count = None
            elif f.isdigit():
                count = int(f)
            else:
                sys.exit(f"error: {path}:{n}: unknown field {f!r}")
        entries.append({"glob": fields[0], "count": count, "want": want, "pick": pick, "line": n, "hits": 0, "taken": 0})
    return entries


def spread(items, count):
    """`count` items spread evenly across `items` (deterministic)."""
    if count is None or count >= len(items):
        return items
    if count == 1:
        return [items[0]]
    step = (len(items) - 1) / (count - 1)
    return [items[round(i * step)] for i in range(count)]


def safe(s, limit=60):
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("_")
    if len(s) > limit:
        s = s[:limit] + "_" + hashlib.sha256(s.encode()).hexdigest()[:8]
    return s


def vector_name(rel, test_id, block_idx, nblocks):
    # zkevm.<parent dir>.<file stem>__<test parameters>[-b<i>]: file stems repeat across directories.
    parent, stem = os.path.split(rel[: -len(".json")])
    params = test_id[test_id.find("[") + 1 : test_id.rfind("]")] if "[" in test_id else test_id
    params = params.replace("fork_Amsterdam-", "").replace("blockchain_test_from_state_test", "state")
    params = params.replace("blockchain_test", "bt")
    name = f"zkevm.{os.path.basename(parent)}.{stem}__{safe(params)}"
    return name + (f"-b{block_idx}" if nblocks > 1 else "")


def convert(rel, data, entries, out_dir):
    written = []
    for e in entries:
        if not fnmatch.fnmatchcase(rel, e["glob"]):
            continue
        e["hits"] += 1
        blocks = []
        for test_id in sorted(data):
            if e["pick"] and e["pick"] not in test_id:
                continue
            bs = [b for b in data[test_id].get("blocks", []) if b.get("statelessInputBytes") and b.get("statelessOutputBytes")]
            for i, b in enumerate(bs):
                out = bytes.fromhex(b["statelessOutputBytes"][2:])
                if e["want"] is not None and (out[32] != 0) != e["want"]:
                    continue
                blocks.append((test_id, i, len(bs), b))
        for test_id, i, nb, b in spread(blocks, e["count"]):
            payload = bytes.fromhex(b["statelessInputBytes"][2:])
            name = vector_name(rel, test_id, i, nb)
            with open(os.path.join(out_dir, name + ".bin"), "wb") as f:
                f.write(len(payload).to_bytes(8, "little") + payload + b"\0" * (-len(payload) % 8))
            with open(os.path.join(out_dir, name + ".expected.hex"), "w") as f:
                f.write(b["statelessOutputBytes"][2:] + "\n")
            written.append(name)
            e["taken"] += 1
    return written


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tarball", required=True, help="a downloaded fixtures_zkevm.tar.gz")
    ap.add_argument("--release", required=True, help="its release tag, e.g. tests-zkevm@v21.0.7")
    ap.add_argument("--subset", default=os.path.join(HERE, "subset.txt"))
    ap.add_argument("--out", default=os.path.dirname(HERE))
    args = ap.parse_args()

    entries = parse_subset(args.subset)

    # Build the new set in a scratch directory next to the output, and only replace the checked-in
    # vectors once every subset line has matched: a bad tarball or a fixture renamed upstream must
    # leave vectors/ and RELEASE untouched.
    os.makedirs(args.out, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.out, prefix=".zkevm-fetch-") as tmp:
        written = []
        with tarfile.open(args.tarball, mode="r|gz") as tar:
            for m in tar:
                if not m.isfile() or not m.name.endswith(".json"):
                    continue
                idx = m.name.find(FIXTURE_ROOT)
                if idx < 0:
                    continue
                rel = m.name[idx + len(FIXTURE_ROOT) :]
                if any(fnmatch.fnmatchcase(rel, e["glob"]) for e in entries):
                    written += convert(rel, json.load(tar.extractfile(m)), entries, tmp)

        missing = [e for e in entries if e["hits"] == 0 or e["taken"] == 0]
        for e in missing:
            print(f"error: {args.subset}:{e['line']}: {e['glob']} matched no fixture block", file=sys.stderr)
        if missing:
            sys.exit("error: vectors left unchanged")
        dupes = sorted({n for n in written if written.count(n) > 1})
        if dupes:
            sys.exit(f"error: several subset lines produce the same vector: {', '.join(dupes)}; vectors left unchanged")

        for old in glob.glob(os.path.join(args.out, "zkevm.*.bin")) + glob.glob(os.path.join(args.out, "zkevm.*.expected.hex")):
            os.remove(old)
        for f in os.listdir(tmp):
            os.replace(os.path.join(tmp, f), os.path.join(args.out, f))

    with open(os.path.join(HERE, "RELEASE"), "w") as f:
        f.write(args.release + "\n")
    print(f"{len(written)} vectors from {args.release} written to {args.out}")

if __name__ == "__main__":
    main()
