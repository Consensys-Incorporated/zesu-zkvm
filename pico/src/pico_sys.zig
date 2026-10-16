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

// Weierstrass curve precompiles. Points are affine, x‖y, each coordinate a little-endian
// field element packed in u64 limbs: [8]u64 for secp256k1/secp256r1/bn254, [12]u64 for
// bls12-381. Pointers must be 8-byte aligned.
pub const SECP256K1_ADD = 0x0001010A;
pub const SECP256K1_DOUBLE = 0x0000010B;
pub const SECP256K1_DECOMPRESS = 0x0000010C;
pub const SECP256R1_ADD = 0x00010130;
pub const SECP256R1_DOUBLE = 0x00000131;
pub const SECP256R1_DECOMPRESS = 0x00000132;
pub const BN254_ADD = 0x0001010E;
pub const BN254_DOUBLE = 0x0000010F;
pub const BLS12381_ADD = 0x0001011E;
pub const BLS12381_DOUBLE = 0x0000011F;
pub const BLS12381_DECOMPRESS = 0x0000011C;

// Field precompiles: x = x op y (mod p), in place, canonical inputs. Fp elements are [4]u64
// (secp256k1, bn254) or [6]u64 (bls12-381); Fp2 elements are c0‖c1, i.e. [8]u64 / [12]u64.
pub const BLS12381_FP_ADD = 0x00010120;
pub const BLS12381_FP_SUB = 0x00010121;
pub const BLS12381_FP_MUL = 0x00010122;
pub const BLS12381_FP2_ADD = 0x00010123;
pub const BLS12381_FP2_SUB = 0x00010124;
pub const BLS12381_FP2_MUL = 0x00010125;
pub const BN254_FP_ADD = 0x00010126;
pub const BN254_FP_SUB = 0x00010127;
pub const BN254_FP_MUL = 0x00010128;
pub const BN254_FP2_ADD = 0x00010129;
pub const BN254_FP2_SUB = 0x0001012A;
pub const BN254_FP2_MUL = 0x0001012B;
pub const SECP256K1_FP_ADD = 0x0001012C;
pub const SECP256K1_FP_SUB = 0x0001012D;
pub const SECP256K1_FP_MUL = 0x0001012E;
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

/// Field op: x = x op y.
pub inline fn fpOp(code: usize, x: [*]u64, y: [*]const u64) void {
    _ = ecall(code, @intFromPtr(x), @intFromPtr(y), 0);
}

/// p = p + q (affine). Pico panics the VM if p == q and returns garbage if p == -q or either
/// is the identity: callers must handle those cases.
pub inline fn ecAdd(code: usize, p: [*]u64, q: [*]const u64) void {
    _ = ecall(code, @intFromPtr(p), @intFromPtr(q), 0);
}

/// p = 2p (affine).
pub inline fn ecDouble(code: usize, p: [*]u64) void {
    _ = ecall(code, @intFromPtr(p), 0, 0);
}

/// Decompress: `buf` is [y ‖ x] (each one field element, little-endian limbs); x is read and
/// y is written, choosing the root whose parity matches `is_odd`.
pub inline fn ecDecompress(code: usize, buf: [*]u64, is_odd: bool) void {
    _ = ecall(code, @intFromPtr(buf), @intFromBool(is_odd), 0);
}

/// x = x * y mod m for 256-bit values. `ym` is y followed by the modulus (8 limbs total).
pub inline fn uint256Mul(x: *[4]u64, ym: *const [8]u64) void {
    _ = ecall(UINT256_MUL, @intFromPtr(x), @intFromPtr(ym), 0);
}
