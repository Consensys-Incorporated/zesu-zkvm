/// SP1 host object: the few symbols zesu.o needs that libzkevm.a does not provide.
///
/// libzkevm.a (SP1's zkvm-standards SDK) supplies `_start`, `read_input`, `write_output`, every
/// `zkvm_*` accelerator and `zkvm_halt`. This file adds:
///   ZKVM_HEAP_POS / ZKVM_HEAP_TOP   zesu's heap region (see below)
///   zkvm_log / zkvm_abort           logging sink and abort hook zesu's panic handler calls
///
/// Heap placement. libzkevm's own Rust code (modexp, KZG, the pairing libraries) allocates from
/// SP1's TLSF heap, which spans [_end, input region) and hands out low addresses first. zesu's
/// heap therefore lives in a separate region far above anything that heap will reach, so the two
/// allocators can never overlap. SP1's address space is 128 GiB with the input region in the top
/// 16 GiB (zkvm.ld: __sp1_max_memory, __sp1_input_region).
extern fn sys_write(fd: u32, buf: [*]const u8, len: usize) void;
extern fn zkvm_halt(exit_code: u8) noreturn;

/// 64 GiB: well above SP1's heap in practice, and below the input region (at 112 GiB).
const ZESU_HEAP_BASE: usize = 0x10_0000_0000;
/// zesu's heap cap, as on the other targets.
const ZESU_HEAP_SIZE: usize = 0x2000_0000;

export var ZKVM_HEAP_POS: usize = ZESU_HEAP_BASE;
export var ZKVM_HEAP_TOP: usize = ZESU_HEAP_BASE + ZESU_HEAP_SIZE;

export fn zkvm_log(level: u8, msg_ptr: [*]const u8, msg_len: usize) void {
    _ = level;
    sys_write(1, msg_ptr, msg_len);
    sys_write(1, "\n", 1);
}

/// Abort hook called by zesu.o's panic handler: halt with a failing exit code.
export fn zkvm_abort() noreturn {
    zkvm_halt(1);
}
