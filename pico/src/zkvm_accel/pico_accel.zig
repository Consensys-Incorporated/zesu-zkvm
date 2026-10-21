/// Pico accel_impl: Pico precompiles for keccak256 and sha256; shared pure-Zig
/// implementations for ripemd160, modexp and blake2f.
///
/// Curve code: secp.zig, bn254.zig and bls12_381.zig instantiate shared/src's implementations,
/// which are generic over a field backend and unit-tested natively there, with Pico's backends
/// (pico_fp.zig field ops, plus the curve-point syscalls).
const std = @import("std");
const sys = @import("pico_sys");
const crypto = @import("zkvm_crypto");
const ripemd160_impl = crypto.ripemd160;
const modexp_impl = crypto.modexp;
const blake2f_impl = crypto.blake2f;
pub const secp = @import("secp.zig");
pub const bn254 = @import("bn254.zig");
pub const bls12_381 = @import("bls12_381.zig");

// ── Hashes ────────────────────────────────────────────────────────────────────

// Keccak-256 sponge constants (rate = 136 bytes, state = 200 bytes, output = 32 bytes).
const KECCAK_RATE: usize = 136;
const KECCAK_WIDTH: usize = 200;

/// Keccak-f[1600] via the KECCAK_PERMUTE precompile. `state` is 25 little-endian
/// u64 lanes and must be 8-byte aligned.
inline fn keccakf(state: *align(8) [KECCAK_WIDTH]u8) void {
    _ = sys.ecall(sys.KECCAK_PERMUTE, @intFromPtr(state), 0, 0);
}

pub fn keccak256(data: []const u8, output: *[32]u8) void {
    var state: [KECCAK_WIDTH]u8 align(8) = .{0} ** KECCAK_WIDTH;

    var remaining = data;
    while (remaining.len >= KECCAK_RATE) {
        for (remaining[0..KECCAK_RATE], 0..) |b, i| state[i] ^= b;
        keccakf(&state);
        remaining = remaining[KECCAK_RATE..];
    }

    // Final partial block with Keccak pad10*1 (domain byte 0x01).
    for (remaining, 0..) |b, i| state[i] ^= b;
    state[remaining.len] ^= 0x01;
    state[KECCAK_RATE - 1] ^= 0x80;
    keccakf(&state);

    @memcpy(output, state[0..32]);
}

const SHA256_IV: [8]u64 = .{
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

/// One SHA-256 block via SHA_EXTEND + SHA_COMPRESS. Pico keeps each 32-bit word
/// in the low half of a u64 slot; both buffers must be 8-byte aligned.
fn sha256Block(h: *align(8) [8]u64, block: *const [64]u8) void {
    var w: [64]u64 align(8) = undefined;
    for (0..16) |i| w[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .big);
    @memset(w[16..], 0);
    _ = sys.ecall(sys.SHA_EXTEND, @intFromPtr(&w), 0, 0);
    _ = sys.ecall(sys.SHA_COMPRESS, @intFromPtr(&w), @intFromPtr(h), 0);
}

pub fn sha256(data: []const u8, output: *[32]u8) void {
    var h: [8]u64 align(8) = SHA256_IV;
    var block: [64]u8 = undefined;

    var remaining = data;
    while (remaining.len >= 64) {
        sha256Block(&h, remaining[0..64]);
        remaining = remaining[64..];
    }

    // Final padded block(s): 0x80, zeros, 8-byte big-endian bit count.
    const bit_len: u64 = @as(u64, data.len) * 8;
    @memset(&block, 0);
    @memcpy(block[0..remaining.len], remaining);
    block[remaining.len] = 0x80;
    if (remaining.len >= 56) {
        sha256Block(&h, &block);
        @memset(&block, 0);
    }
    std.mem.writeInt(u64, block[56..64], bit_len, .big);
    sha256Block(&h, &block);

    for (h, 0..) |hv, i| std.mem.writeInt(u32, output[i * 4 ..][0..4], @truncate(hv), .big);
}

// ── ECDSA ─────────────────────────────────────────────────────────────────────

pub fn ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    return secp.ecrecover(msg, sig, recid, output);
}

pub fn secp256k1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    verified.* = secp.verifyK1(msg, sig, pubkey);
}

pub fn secp256r1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) void {
    verified.* = secp.verifyR1(msg, sig, pubkey);
}

// ── Pure-Zig implementations ──────────────────────────────────────────────────

pub fn ripemd160(data: []const u8, output: *[32]u8) void {
    ripemd160_impl.ripemd160(data, output);
}

pub fn modexp(base: []const u8, exp: []const u8, modulus: []const u8, output: []u8) bool {
    return modexp_impl.modexp(base, exp, modulus, output);
}

pub fn blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) bool {
    return blake2f_impl.blake2f(rounds, h, m, t, f);
}

// ── BN254 ─────────────────────────────────────────────────────────────────────

pub fn bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) bool {
    return bn254.g1Add(p1, p2, result);
}

pub fn bn254_g1_mul(point: *const [64]u8, scalar_: *const [32]u8, result: *[64]u8) bool {
    return bn254.g1Mul(point, scalar_, result);
}

pub fn bn254_pairing(pairs: anytype, verified: *bool) bool {
    return bn254.pairing(pairs, verified);
}

// ── BLS12-381 ─────────────────────────────────────────────────────────────────

pub fn kzg_point_eval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) bool {
    return bls12_381.kzgPointEval(commitment, z, y, proof, verified);
}

pub fn bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) bool {
    return bls12_381.g1Add(p1, p2, result);
}

pub fn bls12_g1_msm(pairs: anytype, result: *[96]u8) bool {
    return bls12_381.g1Msm(pairs, result);
}

pub fn bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) bool {
    return bls12_381.g2Add(p1, p2, result);
}

pub fn bls12_g2_msm(pairs: anytype, result: *[192]u8) bool {
    return bls12_381.g2Msm(pairs, result);
}

pub fn bls12_pairing(pairs: anytype, verified: *bool) bool {
    return bls12_381.pairing(pairs, verified);
}

pub fn bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) bool {
    return bls12_381.mapFpToG1(field_element, result);
}

pub fn bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) bool {
    return bls12_381.mapFp2ToG2(field_element, result);
}
