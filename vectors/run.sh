#!/bin/sh
# Run each vector through a zkVM runner and compare the guest's output with <vector>.expected.hex.
#
#   run.sh "<runner> -e <elf>" vector.bin...
#
# The runner is invoked as `<runner> -e <elf> -i <vector.bin> -o <out>` (every target's runner and
# ziskemu take these flags). Its output is shown only when a vector fails. Vectors without an
# .expected.hex are run but only reported. SSZ_OUTPUT_LEN (default 43, the
# SszStatelessValidationResult size) bounds how many output bytes are compared.
#
# RUNNER_BATCH=1 runs every vector in one runner call (`-i a.bin -o a.out -i b.bin -o b.out ...`)
# for runners whose per-process setup dwarfs a small block (OpenVM compiles the guest first). The
# runner must keep going past a failing input; a vector with no output then counts as failed and
# the runner's log is shown.
set -u
cmd=$1
shift
len=${SSZ_OUTPUT_LEN:-43}
batch=${RUNNER_BATCH:-0}
log=$(mktemp)
outs=$(mktemp -d)
trap 'rm -rf "$log" "$outs"' EXIT

if [ "$batch" = 1 ]; then
    args="" n=0
    for bin in "$@"; do
        n=$((n + 1))
        args="$args -i $bin -o $outs/$n"
    done
    # shellcheck disable=SC2086 # word splitting of the runner command and vector paths is intended
    $cmd $args > "$log" 2>&1 || {
        echo "runner reported failures:"
        sed 's/^/      /' "$log" | tail -40
    }
fi

pass=0 fail=0 info=0 failed="" n=0
for bin in "$@"; do
    n=$((n + 1))
    name=$(basename "$bin" .bin)
    expected=${bin%.bin}.expected.hex
    out=$outs/$n
    if [ "$batch" = 1 ]; then
        if [ ! -s "$out" ]; then
            echo "FAIL  $name: no output (see runner log above)"
            fail=$((fail + 1)) failed="$failed $name"
            continue
        fi
    elif ! $cmd -i "$bin" -o "$out" > "$log" 2>&1; then
        echo "FAIL  $name: runner exited non-zero"
        sed 's/^/      /' "$log" | tail -20
        fail=$((fail + 1)) failed="$failed $name"
        continue
    fi
    if [ ! -f "$expected" ]; then
        echo "INFO  $name (no expected.hex)"
        info=$((info + 1))
        continue
    fi
    got=$(xxd -p -l "$len" "$out" | tr -d '\n')
    want=$(tr -d '[:space:]' < "$expected" | sed 's/^0x//' | tr 'A-F' 'a-f')
    if [ "$got" = "$want" ]; then
        echo "OK    $name"
        pass=$((pass + 1))
    else
        echo "FAIL  $name"
        echo "      expected: $want"
        echo "      got:      $got"
        fail=$((fail + 1)) failed="$failed $name"
    fi
done

summary="---- $pass passed, $fail failed"
[ "$info" -eq 0 ] || summary="$summary, $info without expected output"
echo "$summary"
[ "$fail" -eq 0 ] || { echo "failed:$failed" | tr ' ' '\n' | sed '2,$s/^/  /'; exit 1; }
