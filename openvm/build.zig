const std = @import("std");

pub fn build(b: *std.Build) void {
    // ── OpenVM target: RISC-V 64-bit freestanding (rv64im) ───────────────────
    // Matches riscv64im-openvm-none-elf: no atomics, no compressed, no float.
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
    // -Dzesu_obj=/path/to/zesu.rv64im.o  use a pre-built object (CI default)
    // (omit)                             build from source via zesu_core path dep
    const zesu_obj_path = b.option([]const u8, "zesu_obj", "Path to pre-built zesu.rv64im.o (omit to build from source via zesu_core dep)");

    // ── OpenVM zkvm_io: hint-stream I/O ───────────────────────────────────────
    const openvm_io_mod = b.createModule(.{
        .root_source_file = b.path("src/zkvm_io.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── accel_impl: OpenVM native accelerator implementations ─────────────────
    // keccak256/sha256: native XORIN+KECCAKF / SHA256 compress opcodes
    // ecrecover/secp256k1_verify: native modular arithmetic + ECC opcodes
    // ripemd160/modexp/bn254/bls12/blake2f: pure-Zig implementations
    const accel_impl_mod = b.createModule(.{
        .root_source_file = b.path("src/zkvm_accel/openvm_accel.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ── OpenVM host object ────────────────────────────────────────────────────
    // Satisfies all extern refs from zesu.o:
    //   - 19 zkvm_* accelerators (OpenVM native + pure-Zig implementations)
    //   - read_input / write_output (hint-stream IO)
    //   - zkvm_log / zkvm_exit (print_str phantom / TERMINATE)
    //   - ZKVM_HEAP_POS / ZKVM_HEAP_TOP (bump heap vars + init fn)
    const host_mod = b.createModule(.{
        .root_source_file = b.path("src/openvm_host.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .medium,
    });
    host_mod.addImport("accel_impl", accel_impl_mod);
    host_mod.addImport("zkvm_io", openvm_io_mod);
    const host_obj = b.addObject(.{
        .name = "openvm-host",
        .root_module = host_mod,
    });

    // ── Guest executable ──────────────────────────────────────────────────────
    // zesu.o (main + EVM logic) + openvm-host.o (host + accelerators)
    // + lib/libzesu_openvm_pairing.a (OpenVM's pairing library; `make pairing-lib`).
    // startup.S provides _start → openvm_init_heap → main; the library's own
    // _start and mem* routines are localized when it is built.
    const exe = b.addExecutable(.{
        .name = "zesu-openvm",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.entry = .{ .symbol_name = "_start" };
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
    exe.root_module.addObjectFile(b.path("lib/libzesu_openvm_pairing.a"));
    exe.root_module.addAssemblyFile(b.path("src/startup.S"));
    exe.setLinkerScript(b.path("openvm.ld"));

    b.installArtifact(exe);

    // Run step: build runner, then execute via the Rust runner binary.
    const run_step = b.step("run", "Run via OpenVM runner (cargo build runner first)");
    const run_cmd = b.addSystemCommand(&.{"runner/target/release/zesu-openvm-runner"});
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    _ = b.step("test", "Run unit tests");
}
