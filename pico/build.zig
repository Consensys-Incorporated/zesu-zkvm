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
    const zesu_obj = zesu_build.addGuestObject(zesu_dep.builder, target, optimize, .{});

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

    // ── zkvm_crypto: the zkVM-independent crypto shared with the other targets (../shared) ───
    const crypto_mod = mod.make(b, "../shared/src/zkvm_crypto.zig", target, optimize);

    // ── accel_impl: Pico precompiles + shared pure-Zig implementations ───────
    // keccak256/sha256: KECCAK_PERMUTE / SHA_EXTEND+SHA_COMPRESS precompiles.
    // ripemd160/modexp/blake2f: pure Zig from zkvm_crypto. The curve code is zkvm_crypto's
    // generic implementation instantiated with Pico's field/point syscalls (src/zkvm_accel).
    const accel_impl_mod = mod.make(b, "src/zkvm_accel/pico_accel.zig", target, optimize);
    accel_impl_mod.addImport("pico_sys", sys_mod);
    accel_impl_mod.addImport("zkvm_crypto", crypto_mod);

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
    exe.root_module.addAssemblyFile(b.path("src/memops.S"));
    exe.setLinkerScript(b.path("pico.ld"));

    b.installArtifact(exe);

    // ── Guest self-test (crypto modules, run on the VM): `zig build selftest`, `make selftest`
    const selftest_mod = b.createModule(.{
        .root_source_file = b.path("src/selftest.zig"),
        .target = target,
        .optimize = optimize,
        .code_model = .medium,
    });
    const selftest_list = b.option([]const u8, "selftest", "comma-separated self-test modules: secp,bn254,bls (default: all)") orelse "secp,bn254,bls";
    const selftest_opts = b.addOptions();
    selftest_opts.addOption(bool, "secp", std.mem.indexOf(u8, selftest_list, "secp") != null);
    selftest_opts.addOption(bool, "bn254", std.mem.indexOf(u8, selftest_list, "bn254") != null);
    selftest_opts.addOption(bool, "bls", std.mem.indexOf(u8, selftest_list, "bls") != null);
    selftest_mod.addOptions("selftest_opts", selftest_opts);
    selftest_mod.addImport("accel_impl", accel_impl_mod);
    selftest_mod.addImport("zkvm_io", io_mod);
    const selftest_obj = b.addObject(.{ .name = "pico-selftest", .root_module = selftest_mod });
    const selftest_exe = b.addExecutable(.{
        .name = "zesu-pico-selftest",
        .root_module = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        }),
    });
    selftest_exe.entry = .{ .symbol_name = "_start" };
    selftest_exe.root_module.code_model = .medium;
    selftest_exe.root_module.addObject(selftest_obj);
    selftest_exe.root_module.addObject(host_obj);
    selftest_exe.root_module.addAssemblyFile(b.path("src/startup.S"));
    selftest_exe.root_module.addAssemblyFile(b.path("src/memops.S"));
    selftest_exe.setLinkerScript(b.path("pico.ld"));
    const selftest_step = b.step("selftest", "Build the crypto self-test guest (zesu-pico-selftest)");
    selftest_step.dependOn(&b.addInstallArtifact(selftest_exe, .{}).step);

    // Run step: execute via the Rust runner binary (build it with `make runner`).
    // `zig build run -Dinput=../vectors/<block>.bin [-Dprove]`; extra args after `--` go to the runner.
    const run_step = b.step("run", "Run via Pico runner (cargo build runner first); needs -Dinput=<block.bin>");
    const input_path = b.option([]const u8, "input", "block input file for `zig build run`");
    const prove = b.option(bool, "prove", "generate + verify a RISCV-phase proof in `zig build run` (slow)") orelse false;
    const run_cmd = b.addSystemCommand(&.{"runner/target/release/zesu-pico-runner"});
    if (prove) run_cmd.addArg("-p");
    run_cmd.addArg("-e");
    run_cmd.addArtifactArg(exe);
    if (input_path) |input| {
        run_cmd.addArgs(&.{ "-i", input });
    } else {
        run_step.dependOn(&b.addFail("`zig build run` needs a block: zig build run -Dinput=../vectors/mainnet_fusaka_24758573.bin").step);
    }
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    run_step.dependOn(&run_cmd.step);

    // The native unit tests of the curve code live with the code, in ../shared (`make -C ../shared test`).
}
