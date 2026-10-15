const std = @import("std");
const zesu_build = @import("zesu");

pub fn build(b: *std.Build) void {
    // ── Pico target: RISC-V 64-bit freestanding (rv64im) ─────────────────────
    // Pico's decoder accepts only the I and M extensions: no atomics, no
    // compressed, no float. It traps on misaligned loads/stores, so unaligned
    // scalar access (zicclsm) must stay off.
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
    // zesu is built here, for Pico's own target, rather than linked from a published
    // object: the ISA extensions a zkVM supports are this project's concern, and zesu
    // only exports `addGuestObject(builder, target, optimize, has_dma)`.
    const zesu_dep = b.dependency("zesu", .{ .@"crypto-backend" = .@"extern" });
    const zesu_obj = zesu_build.addGuestObject(zesu_dep.builder, target, optimize, false);

    const mod = struct {
        fn make(bb: *std.Build, path: []const u8, t: std.Build.ResolvedTarget, o: std.builtin.OptimizeMode) *std.Build.Module {
            return bb.createModule(.{ .root_source_file = bb.path(path), .target = t, .optimize = o });
        }
    };

    // ── Pico ecall ABI ────────────────────────────────────────────────────────
    const sys_mod = mod.make(b, "src/pico_sys.zig", target, optimize);

    // ── zkvm_io: hint input, fd-3 public values, commit + halt ───────────────
    const io_mod = mod.make(b, "src/zkvm_io.zig", target, optimize);
    io_mod.addImport("pico_sys", sys_mod);

    // ── accel_impl: Pico precompiles + shared pure-Zig implementations ───────
    // keccak256/sha256: KECCAK_PERMUTE / SHA_EXTEND+SHA_COMPRESS precompiles.
    // ripemd160/modexp/blake2f: the pure-Zig files shared with the openvm target.
    const accel_impl_mod = mod.make(b, "src/zkvm_accel/pico_accel.zig", target, optimize);
    accel_impl_mod.addImport("pico_sys", sys_mod);
    accel_impl_mod.addImport("ripemd160", mod.make(b, "../openvm/src/zkvm_accel/ripemd160.zig", target, optimize));
    accel_impl_mod.addImport("modexp", mod.make(b, "../openvm/src/zkvm_accel/modexp.zig", target, optimize));
    accel_impl_mod.addImport("blake2f", mod.make(b, "../openvm/src/zkvm_accel/blake2f.zig", target, optimize));

    // ── Pico host object ──────────────────────────────────────────────────────
    const host_mod = b.createModule(.{
        .root_source_file = b.path("src/pico_host.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .medium,
    });
    host_mod.addImport("accel_impl", accel_impl_mod);
    host_mod.addImport("zkvm_io", io_mod);
    const host_obj = b.addObject(.{
        .name = "pico-host",
        .root_module = host_mod,
    });

    // ── Guest executable ──────────────────────────────────────────────────────
    // zesu-pico = zesu (main + EVM logic, built above for the Pico target) + pico-host.o (host + accelerators).
    // startup.S provides _start → pico_init_heap → main → pico_exit.
    const exe = b.addExecutable(.{
        .name = "zesu-pico",
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
    exe.root_module.addAssemblyFile(b.path("src/startup.S"));
    exe.setLinkerScript(b.path("pico.ld"));

    b.installArtifact(exe);

    // Run step: execute via the Rust runner binary (build it with `make runner`).
    const run_step = b.step("run", "Run via Pico runner (cargo build runner first)");
    const run_cmd = b.addSystemCommand(&.{"runner/target/release/zesu-pico-runner"});
    run_cmd.addArtifactArg(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    _ = b.step("test", "Run unit tests");
}
