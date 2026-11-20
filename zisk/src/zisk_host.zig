/// ZisK host object: satisfies all extern symbol references in zesu.rv64im.o
///
/// Exports:
///   zkvm_log                         — runtime (UART)
///   zkvm_* accelerators in `zkvmcalls` — thunks into ZisK's hand-written routines
///
/// zesu.o's main() returns its status code (0/1) in a0 per the RISC-V C ABI
/// instead of calling an explicit halt function. libziskos_staticlib.a's own
/// _start (vendor Rust code) performs the actual exit(93) ecall automatically
/// once _zisk_main/main() returns, with a0 passed through untouched — so no
/// halt/exit routine, and no inline assembly, is needed in this file at all.
///
/// Symbols provided by libziskos_staticlib.a at link time (NOT exported here):
///   read_input / write_output        — zkvm-standards io-interface
///   zkvm_ripemd160, zkvm_secp256k1_verify, zkvm_secp256r1_verify — Rust implementations
///   zkvm_init / zkvm_deinit / _start — entrypoint and lifecycle
const std = @import("std");

/// Zisk zkVM UART — SYS_ADDR + 0x200 = 0xa0400000 + 0x200 (v1.1.0-alpha layout)
const ZISK_UART: *volatile u8 = @ptrFromInt(0xa0400200);

// ── Runtime ───────────────────────────────────────────────────────────────────

/// Logging sink used by zesu.o's std_options.logFn (src/zkvm/root.zig).
export fn zkvm_log(level: u8, msg_ptr: [*]const u8, msg_len: usize) void {
    _ = level;
    for (msg_ptr[0..msg_len]) |byte| {
        ZISK_UART.* = byte;
    }
    ZISK_UART.* = '\n';
}

/// Abort hook called by zesu.o's panic handler. Uses the same exit(93) ecall
/// that libziskos's _start fires on normal return — the ZisK circuit handles it.
export fn zkvm_abort() noreturn {
    asm volatile (
        \\li a7, 93
        \\li a0, 1
        \\ecall
        ::: .{ .a7 = true, .a0 = true, .memory = true });
    unreachable;
}

// ── Accelerators ──────────────────────────────────────────────────────────────

/// Accelerators served by ZisK's hand-written routines (ziskasm, ZisK >= 1.4): name and
/// zkvmcall id. The transpiler replaces `csrs <id>, x0` with a jump to the routine, which
/// takes the C-ABI arguments and returns to the caller. zisk/Makefile's ZKVMCALLS makes
/// libziskos's own copies of these local.
const zkvmcalls = [_]struct { []const u8, u16 }{
    .{ "zkvm_keccak256", 0x850 },
    .{ "zkvm_sha256", 0x851 },
    .{ "zkvm_secp256k1_ecrecover", 0x854 },
    .{ "zkvm_modexp", 0x856 },
    .{ "zkvm_bn254_g1_add", 0x857 },
    .{ "zkvm_bn254_g1_mul", 0x858 },
    .{ "zkvm_bn254_pairing", 0x859 },
    .{ "zkvm_blake2f", 0x85A },
    .{ "zkvm_kzg_point_eval", 0x85B },
    .{ "zkvm_bls12_g1_add", 0x85C },
    .{ "zkvm_bls12_g1_msm", 0x85D },
    .{ "zkvm_bls12_g2_add", 0x85E },
    .{ "zkvm_bls12_g2_msm", 0x85F },
    .{ "zkvm_bls12_pairing", 0x860 },
    .{ "zkvm_bls12_map_fp_to_g1", 0x861 },
    .{ "zkvm_bls12_map_fp2_to_g2", 0x862 },
};

comptime {
    for (zkvmcalls) |c| asm (std.fmt.comptimePrint(
            \\.section .text.{0s},"ax",@progbits
            \\.globl {0s}
            \\.type {0s}, @function
            \\.p2align 2
            \\{0s}:
            \\    csrs {1d}, x0
            \\    ret
        , .{ c[0], c[1] }));
}
