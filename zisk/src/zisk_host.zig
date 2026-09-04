/// ZisK host object: satisfies all extern symbol references in zesu.rv64im.o
///
/// Exports:
///   zkvm_log                         — runtime (UART)
///
/// zesu.o's main() returns its status code (0/1) in a0 per the RISC-V C ABI
/// instead of calling an explicit halt function. libziskos_staticlib.a's own
/// _start (vendor Rust code) performs the actual exit(93) ecall automatically
/// once _zisk_main/main() returns, with a0 passed through untouched — so no
/// halt/exit routine, and no inline assembly, is needed in this file at all.
///
/// Symbols provided by libziskos_staticlib.a at link time (NOT exported here):
///   read_input / write_output        — zkvm-standards io-interface
///   zkvm_* accelerators              — all circuit-backed implementations (ZisK 1.1.0-alpha)
///   zkvm_init / zkvm_deinit / _start — entrypoint and lifecycle
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
