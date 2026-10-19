const std = @import("std");

/// Native unit tests for the zkVM-independent crypto in src/. The zkVM targets do not build this
/// package; they import src/zkvm_crypto.zig as a module from their own build.zig.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Besu's EIP-2537 CSV suites, from the pinned zesu dependency (embedded by the BLS tests).
    const zesu_dep = b.dependency("zesu", .{ .@"crypto-backend" = .@"extern" });

    const test_roots = [_][]const u8{
        "src/ripemd160.zig",
        "src/modexp.zig",
        "src/blake2f.zig",
        "src/tower.zig",
        "src/secp.zig",
        "src/bn254.zig",
        "src/bls12_381.zig",
    };

    const test_step = b.step("test", "Run native unit tests (curve code on the software field backend)");
    for (test_roots) |root| {
        const tmod = b.createModule(.{
            .root_source_file = b.path(root),
            .target = target,
            .optimize = optimize,
        });
        if (std.mem.eql(u8, root, "src/bls12_381.zig")) {
            for ([_][]const u8{ "g1_add", "g2_add", "g1_msm", "g2_msm", "pairing", "pairing_invalid_subgroup", "fp_to_g1", "fp2_to_g2" }) |name| {
                tmod.addAnonymousImport(b.fmt("eip2537_{s}.csv", .{name}), .{
                    .root_source_file = zesu_dep.path(b.fmt("src/evm/precompile/testdata/eip2537_{s}.csv", .{name})),
                });
            }
        }
        const t = b.addTest(.{ .root_module = tmod });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
