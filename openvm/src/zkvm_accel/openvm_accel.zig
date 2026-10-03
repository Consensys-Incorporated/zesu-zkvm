/// OpenVM accel_impl: native accelerator instructions for keccak256, sha256, and secp256k1;
/// pure-Zig software implementation for ripemd160.
/// keccak256: OpenVM XORIN + KECCAKF custom opcodes (opcode=0x0b, funct3=4, funct7=0/1).
/// sha256:    OpenVM SHA256 compression (opcode=0x0b, funct3=4, funct7=2).
/// ecrecover, secp256k1_verify: OpenVM modular arithmetic + ECC opcodes (opcode=0x2b).
/// ripemd160, modexp: pure-Zig (no native OpenVM extension exists).
/// Everything else: stub (returns false/zero) — sufficient for blocks that
/// don't exercise BN254 or BLS12 precompiles.
const std = @import("std");
const secp256k1 = @import("secp256k1.zig");
const secp256r1 = @import("secp256r1.zig");
const ripemd160_impl = @import("ripemd160.zig");
const modexp_impl = @import("modexp.zig");
const bn254_impl = @import("bn254.zig");
const bls12_impl = @import("bls12_381.zig");
const blake2f_impl = @import("blake2f.zig");

// ── Hashes ────────────────────────────────────────────────────────────────────

// Keccak-256 sponge constants (rate = 136 bytes, state = 200 bytes, output = 32 bytes).
const KECCAK_RATE: usize = 136;
const KECCAK_WIDTH: usize = 200;

/// XOR exactly KECCAK_RATE bytes from `inp` into `state[0..KECCAK_RATE]` using
/// OpenVM's native XORIN instruction (opcode=0x0b, funct3=4, funct7=1).
/// Both pointers must be 8-byte aligned; KECCAK_RATE=136 is a multiple of 8.
inline fn nativeXorin(state: *[KECCAK_WIDTH]u8, inp: *const [KECCAK_RATE]u8) void {
    var buf: usize = @intFromPtr(state);
    const src: usize = @intFromPtr(inp);
    const len: usize = KECCAK_RATE;
    asm volatile (".insn r 0x0b, 4, 1, %[buf], %[src], %[len]"
        : [buf] "+r" (buf),
        : [src] "r" (src),
          [len] "r" (len),
        : .{ .memory = true });
}

/// Apply Keccak-f[1600] to the 200-byte `state` buffer using OpenVM's native
/// KECCAKF instruction (opcode=0x0b, funct3=4, funct7=0).
/// `state` must be 8-byte aligned.
inline fn nativeKeccakf(state: *[KECCAK_WIDTH]u8) void {
    var buf: usize = @intFromPtr(state);
    asm volatile (".insn r 0x0b, 4, 0, %[buf], x0, x0"
        : [buf] "+r" (buf),
        :
        : .{ .memory = true });
}

pub fn keccak256(data: []const u8, output: *[32]u8) void {
    var state: [KECCAK_WIDTH]u8 align(8) = .{0} ** KECCAK_WIDTH;
    // Aligned staging buffer for full-rate absorb blocks; handles unaligned input.
    var temp: [KECCAK_RATE]u8 align(8) = undefined;

    var remaining = data;

    // Absorb full KECCAK_RATE-byte blocks via native XORIN + KECCAKF.
    while (remaining.len >= KECCAK_RATE) {
        @memcpy(&temp, remaining[0..KECCAK_RATE]);
        nativeXorin(&state, &temp);
        nativeKeccakf(&state);
        remaining = remaining[KECCAK_RATE..];
    }

    // Final partial block: XOR remaining bytes manually, then apply Keccak pad10*1.
    for (remaining, 0..) |byte, i| state[i] ^= byte;
    state[remaining.len] ^= 0x01;
    state[KECCAK_RATE - 1] ^= 0x80;

    // Final permutation and squeeze.
    nativeKeccakf(&state);
    @memcpy(output, state[0..32]);
}

// SHA-256 IV: 8 u32 words stored as little-endian bytes (native RISC-V order).
const SHA256_IV: [32]u8 align(8) = .{
    0x67, 0xe6, 0x09, 0x6a, // H0 = 0x6a09e667
    0x85, 0xae, 0x67, 0xbb, // H1 = 0xbb67ae85
    0x72, 0xf3, 0x6e, 0x3c, // H2 = 0x3c6ef372
    0x3a, 0xf5, 0x4f, 0xa5, // H3 = 0xa54ff53a
    0x7f, 0x52, 0x0e, 0x51, // H4 = 0x510e527f
    0x8c, 0x68, 0x05, 0x9b, // H5 = 0x9b05688c
    0xab, 0xd9, 0x83, 0x1f, // H6 = 0x1f83d9ab
    0x19, 0xcd, 0xe0, 0x5b, // H7 = 0x5be0cd19
};

/// One SHA-256 block compression via OpenVM native instruction (opcode=0x0b, funct3=4, funct7=2).
/// state: 8 u32 words in little-endian; block: 64 raw bytes; out: same format as state.
inline fn nativeSha256Compress(out: *[32]u8, state: *const [32]u8, block: *const [64]u8) void {
    asm volatile (".insn r 0x0b, 4, 2, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(state)),
          [rs2] "r" (@intFromPtr(block)),
        : .{ .memory = true });
}

pub fn sha256(data: []const u8, output: *[32]u8) void {
    var state: [32]u8 align(8) = SHA256_IV;
    var new_state: [32]u8 align(8) = undefined;
    var block: [64]u8 align(8) = undefined;

    var remaining = data;

    // Absorb full 64-byte blocks.
    while (remaining.len >= 64) {
        @memcpy(&block, remaining[0..64]);
        nativeSha256Compress(&new_state, &state, &block);
        state = new_state;
        remaining = remaining[64..];
    }

    // Final padded block(s): append 0x80, zeros, 8-byte big-endian bit count.
    const bit_len: u64 = @as(u64, data.len) * 8;
    @memset(&block, 0);
    @memcpy(block[0..remaining.len], remaining);
    block[remaining.len] = 0x80;

    if (remaining.len < 56) {
        block[56] = @truncate(bit_len >> 56);
        block[57] = @truncate(bit_len >> 48);
        block[58] = @truncate(bit_len >> 40);
        block[59] = @truncate(bit_len >> 32);
        block[60] = @truncate(bit_len >> 24);
        block[61] = @truncate(bit_len >> 16);
        block[62] = @truncate(bit_len >> 8);
        block[63] = @truncate(bit_len);
        nativeSha256Compress(&new_state, &state, &block);
        state = new_state;
    } else {
        // Padding spills into a second block.
        nativeSha256Compress(&new_state, &state, &block);
        state = new_state;
        @memset(&block, 0);
        block[56] = @truncate(bit_len >> 56);
        block[57] = @truncate(bit_len >> 48);
        block[58] = @truncate(bit_len >> 40);
        block[59] = @truncate(bit_len >> 32);
        block[60] = @truncate(bit_len >> 24);
        block[61] = @truncate(bit_len >> 16);
        block[62] = @truncate(bit_len >> 8);
        block[63] = @truncate(bit_len);
        nativeSha256Compress(&new_state, &state, &block);
        state = new_state;
    }

    // State is 8 LE u32 words; convert to standard big-endian hash output.
    for (0..8) |i| {
        output[i * 4 + 0] = state[i * 4 + 3];
        output[i * 4 + 1] = state[i * 4 + 2];
        output[i * 4 + 2] = state[i * 4 + 1];
        output[i * 4 + 3] = state[i * 4 + 0];
    }
}

// ── secp256k1 ─────────────────────────────────────────────────────────────────

/// Recover the 64-byte uncompressed public key (x‖y, no 0x04 prefix) from a
/// recoverable ECDSA signature over secp256k1 using OpenVM native accelerators.
///
/// msg:   32-byte message hash (big-endian)
/// sig:   64-byte compact signature r‖s (each 32 bytes, big-endian)
/// recid: recovery id (0 or 1; 2 and 3 for x >= n, extremely rare)
pub fn ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    return secp256k1.recoverPubkey(msg, sig, recid, output);
}

/// Verify a compact secp256k1 ECDSA signature (r‖s, big-endian) against a
/// pre-hashed message and an uncompressed public key (x‖y, no 0x04 prefix).
pub fn secp256k1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    verified.* = secp256k1.verifySignature(msg, sig, pubkey);
}

// ── Stubs ─────────────────────────────────────────────────────────────────────

pub fn ripemd160(data: []const u8, output: *[32]u8) void {
    ripemd160_impl.ripemd160(data, output);
}

pub fn modexp(base: []const u8, exp: []const u8, modulus: []const u8, output: []u8) bool {
    return modexp_impl.modexp(base, exp, modulus, output);
}

pub fn bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) bool {
    return bn254_impl.g1Add(p1, p2, result);
}

pub fn bn254_g1_mul(point: *const [64]u8, scalar_: *const [32]u8, result: *[64]u8) bool {
    return bn254_impl.g1Mul(point, scalar_, result);
}

pub fn bn254_pairing(pairs: anytype, verified: *bool) bool {
    _ = pairs;
    verified.* = false;
    return false;
}

pub fn blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) bool {
    return blake2f_impl.blake2f(rounds, h, m, t, f);
}

pub fn kzg_point_eval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) bool {
    if (!bls12_impl.kzgVerify(commitment, z, y, proof)) return false;
    verified.* = true;
    return true;
}

pub fn bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) bool {
    return bls12_impl.g1Add(p1, p2, result);
}

pub fn bls12_g1_msm(pairs: anytype, result: *[96]u8) bool {
    return bls12_impl.g1Msm(pairs, result);
}

pub fn bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) bool {
    return bls12_impl.g2Add(p1, p2, result);
}

pub fn bls12_g2_msm(pairs: anytype, result: *[192]u8) bool {
    return bls12_impl.g2Msm(pairs, result);
}

pub fn bls12_pairing(pairs: anytype, verified: *bool) bool {
    _ = pairs;
    verified.* = false;
    return false;
}

pub fn bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) bool {
    return bls12_impl.mapFpToG1(field_element, result);
}

pub fn bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) bool {
    return bls12_impl.mapFp2ToG2(field_element, result);
}

pub fn secp256r1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    verified.* = secp256r1.verifySignature(msg, sig, pubkey);
}
