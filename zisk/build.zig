const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── Zisk zkVM target: RISC-V 64-bit freestanding (rv64im + zicclsm) ──────
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{ .m, .zicclsm }),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .d, .f, .zicsr, .zaamo, .zalrsc }),
        .os_tag = .freestanding,
        .abi = .none,
    });
    const optimize = b.standardOptimizeOption(.{});

    // ── zesu object ───────────────────────────────────────────────────────────
    // -Dzesu_obj=/path/to/zesu.rv64im.o  use a pre-built object (CI default)
    // (omit)                             build from source via zesu_core path dep
    const zesu_obj_path = b.option([]const u8, "zesu_obj", "Path to pre-built zesu.rv64im.o (omit to build from source via zesu_core dep)");

    // ── zesu rv64im object ────────────────────────────────────────────────────

    // ── zisk-host object ─────────────────────────────────────────────────────
    // Compiled separately so it can be partially linked with libziskos_staticlib.a before
    // the final link.  Exports: runtime and profiling symbols (zkvm_log, zkvm_exit, sys_read,
    // zkvm_profiling_*).  read_input/write_output and all zkvm_* accelerators come from
    // libziskos_staticlib.a (ZisK 1.1.0-alpha circuit-backed).
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
        const build_zesu = b.addSystemCommand(&.{
            "zig",                                          "build", "rv64im-object",
            b.fmt("-Doptimize={s}", .{@tagName(optimize)}),
        });
        build_zesu.setCwd(b.path("../../zesu"));
        exe.root_module.addObjectFile(b.path("../../zesu/zig-out/lib/zesu.o"));
        exe.step.dependOn(&build_zesu.step);
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
