const std = @import("std");
const zesu_build = @import("zesu");

const Isa = enum { zisk, rv64im };

pub fn build(b: *std.Build) void {
    // ── Zisk zkVM target: RISC-V 64-bit freestanding ──────────────────────────
    // zisk   (default) rv64im + Zbb + Zbs: ZisK proves Zbb/Zbs natively, and zesu's
    //        fixed-size copies use ZisK's DMA chip.
    // rv64im the zkvm-standards baseline (zesu's rv64im-object): no Zbb/Zbs, no DMA.
    // Both accept misaligned scalar access. No atomics, no compressed, no float.
    const isa = b.option(Isa, "isa", "ISA the guest (zesu and host) is built for: zisk (default) or rv64im") orelse .zisk;
    const base_features = [_]std.Target.riscv.Feature{ .m, .zicclsm, .unaligned_scalar_mem };
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(switch (isa) {
            .zisk => &(base_features ++ [_]std.Target.riscv.Feature{ .zbb, .zbs }),
            .rv64im => &base_features,
        }),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .zca, .zcb, .d, .f, .zicsr, .zaamo, .zalrsc }),
        .os_tag = .freestanding,
        .abi = .none,
    });
    const optimize = b.standardOptimizeOption(.{});

    // ── zesu object ───────────────────────────────────────────────────────────
    // Built here, for the target above, from the zesu pinned in build.zig.zon.
    // -Dzesu_obj links a pre-built object instead.
    const zesu_obj_path = b.option([]const u8, "zesu_obj", "Path to a pre-built zesu object (omit to build zesu for this target from the build.zig.zon pin)");

    // ── zisk-host object ─────────────────────────────────────────────────────
    // Compiled separately so it can be partially linked with libziskos_staticlib.a before
    // the final link.  Exports: runtime and profiling symbols (zkvm_log, zkvm_exit, sys_read,
    // zkvm_profiling_*).  read_input/write_output and all zkvm_* accelerators come from
    // libziskos_staticlib.a (ZisK 1.2.0-alpha circuit-backed).
    const host_mod = b.createModule(.{
        .root_source_file = b.path("src/zisk_host.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .medium,
    });
    const host_obj = b.addObject(.{
        .name = "zisk-host",
        .root_module = host_mod,
    });

    // ── Partial link: zisk-host.o + libziskos_staticlib.a → zisk-wrapped.o ───
    //
    // Merges host (IO, runtime, profiling) with libziskos_staticlib.a (all zkvm_*
    // accelerators + _start/init_sys_alloc) into a single relocatable object.
    // All accelerators come from libziskos_staticlib.a with no duplicates.
    const wrap_cmd = b.addSystemCommand(&.{
        "zig", "ld.lld",
        "-r",  "--whole-archive",
    });
    wrap_cmd.addFileArg(host_obj.getEmittedBin());
    wrap_cmd.addFileArg(b.path("lib/libziskos_staticlib.a"));
    wrap_cmd.addArg("--no-whole-archive");
    wrap_cmd.addArg("-o");
    const zisk_wrapped = wrap_cmd.addOutputFileArg("zisk-wrapped.o");

    // ── Final guest executable ────────────────────────────────────────────────
    // zesu.o (main + EVM logic) + zisk-wrapped.o (host + libziskos_staticlib merged).
    // The linker script handles memory layout; no Zig root source needed here.
    const exe = b.addExecutable(.{
        .name = "zesu-zisk",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.code_model = .medium;
    if (zesu_obj_path) |path| {
        exe.root_module.addObjectFile(.{ .cwd_relative = path });
    } else {
        const zesu_dep = b.dependency("zesu", .{ .@"crypto-backend" = .@"extern" });
        exe.root_module.addObject(zesu_build.addGuestObject(zesu_dep.builder, target, optimize, isa == .zisk));
    }
    exe.root_module.addObjectFile(zisk_wrapped);
    exe.setLinkerScript(b.path("zisk.ld"));

    b.installArtifact(exe);

    // Run via ziskemu emulator
    const run_step = b.step("run", "Run via Zisk emulator (ziskemu must be in PATH)");
    const run_cmd = b.addSystemCommand(&.{ "ziskemu", "-e" });
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // Placeholder test step
    _ = b.step("test", "Run unit tests");
}
