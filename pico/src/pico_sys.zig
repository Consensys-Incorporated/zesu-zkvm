/// Pico ecall ABI: syscall number in t0, arguments in a0..a2, result (if any) in t0.
/// Numbers mirror pico-sdk's `riscv_ecalls` (vm/src/emulator/riscv/syscalls/code.rs).
pub const HALT = 0x00;
pub const WRITE = 0x02;
pub const SHA_EXTEND = 0x00300105;
pub const SHA_COMPRESS = 0x00010106;
pub const KECCAK_PERMUTE = 0x00010109;
pub const COMMIT = 0x10;
pub const COMMIT_DEFERRED_PROOFS = 0x1A;
pub const UINT256_MUL = 0x0001011D;
pub const HINT_LEN = 0xF0;
pub const HINT_READ = 0xF1;

pub inline fn ecall(code: usize, a0: usize, a1: usize, a2: usize) usize {
    var t0 = code;
    asm volatile ("ecall"
        : [t0] "+{t0}" (t0),
        : [a0] "{a0}" (a0),
          [a1] "{a1}" (a1),
          [a2] "{a2}" (a2),
        : .{ .memory = true });
    return t0;
}
