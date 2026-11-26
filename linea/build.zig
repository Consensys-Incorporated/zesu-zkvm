const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── Linea zkVM target: RISC-V 64-bit freestanding (rv64im + zicclsm) ─────
    // Matches riscv64im_zicclsm-unknown-none-elf per the Linea zkVM Makefile.
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv64,
        .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 },
        .cpu_features_add = std.Target.riscv.featureSet(&.{ .m, .zicclsm }),
        .cpu_features_sub = std.Target.riscv.featureSet(&.{ .a, .c, .zca, .zcb, .d, .f, .zicsr, .zaamo, .zalrsc }),
        .os_tag = .freestanding,
        .abi = .none,
    });
    const optimize = b.standardOptimizeOption(.{});

    // ── zesu object ───────────────────────────────────────────────────────────
    // -Dzesu_obj=/path/to/zesu.rv64im.o  use a pre-built object (CI default)
    // (omit)                             build from source via zesu_core path dep
    const zesu_obj_path = b.option([]const u8, "zesu_obj", "Path to pre-built zesu.rv64im.o (omit to build from source via zesu_core dep)");

    // ── Linea zkvm_io: memory-mapped input + write-ecall output ──────────────
    const linea_io_mod = b.createModule(.{
        .root_source_file = b.path("src/zkvm_io.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── accel_impl: pure-Zig implementations (std.crypto + stubs) ────────────
    const accel_impl_mod = b.createModule(.{
        .root_source_file = b.path("src/zkvm_accel/linea_accel.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── zesu rv64im object ────────────────────────────────────────────────────

    // ── Linea host object ─────────────────────────────────────────────────────
    // Satisfies all extern refs from zesu.o:
    //   - 19 zkvm_* accelerators (pure-Zig / std.crypto stubs)
    //   - read_input (memory-mapped from _input_start)
    //   - write_output / zkvm_log (Linux write ecall a7=64)
    //   - zkvm_exit (Linux exit ecall a7=93)
    //   - ZKVM_BUMP_HEAP_POS / ZKVM_BUMP_HEAP_TOP + linea_init_heap
    const host_mod = b.createModule(.{
        .root_source_file = b.path("src/linea_host.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .medium,
    });
    host_mod.addImport("accel_impl", accel_impl_mod);
    host_mod.addImport("zkvm_io", linea_io_mod);
    const host_obj = b.addObject(.{
        .name = "linea-host",
        .root_module = host_mod,
    });

    // ── Guest executable ──────────────────────────────────────────────────────
    // zesu.o (main + EVM logic) + linea-host.o (host + accelerators).
    // startup.S provides _start → linea_init_heap → main.
    // Stripped to minimize binary size per Linea zkVM requirements.
    const exe = b.addExecutable(.{
        .name = "zesu-linea",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.entry = .{ .symbol_name = "_start" };
    exe.root_module.strip = true;
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
    exe.root_module.addObject(host_obj);
    exe.root_module.addAssemblyFile(b.path("src/startup.S"));
    exe.setLinkerScript(b.path("linea.ld"));

    b.installArtifact(exe);

    // Run step: invoke zkc emulator with the built ELF and an input file.
    const run_step = b.step("run", "Run via Linea zkc emulator (zkc must be in PATH)");
    const run_cmd = b.addSystemCommand(&.{ "zkc", "run" });
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    // Zig 0.17 replaced `b.args` with `addPassthruArgs`.
    if (comptime @hasDecl(std.Build.Step.Run, "addPassthruArgs")) run_cmd.addPassthruArgs() else if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    _ = b.step("test", "Run unit tests");
}
