/// Guest self-test: runs each curve module's `selfTest()` on Pico's VM.
///
/// Each selfTest() computes results through the Pico-syscall backend and compares them with the
/// software backend (and fixed known-answer vectors), so it checks the syscall ABI (limb order,
/// layouts, edge cases) as well as the algorithm. The guest writes one byte to the public values:
/// 1 = every module passed. Per-module results go to the host's stdout (RUST_LOG=info).
///
/// Build and run:  make selftest
const io = @import("zkvm_io");
const accel = @import("accel_impl");

const opts = @import("selftest_opts");

const Test = struct { name: []const u8, enabled: bool, run: *const fn () bool };

// `zig build selftest -Dselftest=bn254` runs one module (comma-separated list); default is all.
const tests = [_]Test{
    .{ .name = "secp256k1/secp256r1", .enabled = opts.secp, .run = accel.secp.selfTest },
    .{ .name = "bn254", .enabled = opts.bn254, .run = accel.bn254.selfTest },
    .{ .name = "bls12-381", .enabled = opts.bls, .run = accel.bls12_381.selfTest },
};

export fn main() c_int {
    var all_ok = true;
    for (tests) |t| {
        if (!t.enabled) continue;
        const ok = t.run();
        io.printStr(t.name);
        io.printStr(if (ok) ": PASS\n" else ": FAIL\n");
        if (!ok) all_ok = false;
    }
    io.write_output(&[_]u8{@intFromBool(all_ok)});
    return if (all_ok) 0 else 1;
}
