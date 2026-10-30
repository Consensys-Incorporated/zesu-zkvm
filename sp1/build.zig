const std = @import("std");
const zesu_build = @import("zesu");

pub fn build(b: *std.Build) void {
    // ── SP1 target: RISC-V 64-bit freestanding (rv64im) ──────────────────────
    // SP1's decoder accepts only the I and M extensions and its executor stops with an error
    // on misaligned loads/stores, so unaligned scalar access must stay off.
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{.m}),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .zca, .zcb, .d, .f, .zicsr, .zaamo, .zalrsc }),
        .os_tag = .freestanding,
        .abi = .none,
    });
    const optimize = b.standardOptimizeOption(.{});

    // ── zesu object ───────────────────────────────────────────────────────────
    // Built here for SP1's own target (see build.zig.zon); zesu only exports addGuestObject.
    const zesu_dep = b.dependency("zesu", .{ .@"crypto-backend" = .@"extern" });
    const zesu_obj = zesu_build.addGuestObject(zesu_dep.builder, target, optimize, .{});

    // ── SP1 host object ───────────────────────────────────────────────────────
    const host_obj = b.addObject(.{
        .name = "sp1-host",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sp1_host.zig"),
            .target = target,
            .optimize = optimize,
            .code_model = .medium,
        }),
    });

    // ── Guest executable ──────────────────────────────────────────────────────
    // zesu + sp1-host.o + libzkevm.a (SP1's zkvm-standards SDK: _start, IO, accelerators,
    // allocator), laid out by the SDK's linker script. Fetch the SDK with `make sdk`.
    const exe = b.addExecutable(.{
        .name = "zesu-sp1",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.entry = .{ .symbol_name = "_start" };
    exe.root_module.code_model = .medium;
    exe.root_module.addObject(zesu_obj);
    exe.root_module.addObject(host_obj);
    exe.root_module.addObjectFile(b.path("lib/libzkevm.a"));
    exe.setLinkerScript(b.path("lib/zkvm.ld"));
    b.installArtifact(exe);
}
