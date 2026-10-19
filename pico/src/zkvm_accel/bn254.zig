/// BN254 (alt_bn128) G1 add / scalar mul and pairing check on Pico's precompiles.
///
/// Public API (called from pico_accel.zig), all byte layouts as in the EIPs (big-endian):
///   g1Add(p1, p2, result) bool           G1 point = x‖y (64 bytes); (0,0) is the identity
///   g1Mul(point, scalar, result) bool    scalar = 32 bytes, any 256-bit value (not reduced)
///   pairing(pairs, verified) bool        pairs: slice of {g1: [64]u8, g2: [128]u8};
///                                        G2 = x_im‖x_re‖y_im‖y_re (EIP-197 order)
///   selfTest() bool                      guest-only differential test (see selftest.zig)
///
/// The algorithms and their native tests live in shared/src/bn254.zig; this file instantiates
/// them with Pico's backend: FP_* / FP2_* syscalls (pico_fp.zig) plus the BN254 curve
/// precompiles for G1.
const std = @import("std");
const crypto = @import("zkvm_crypto");
const pico_fp = @import("pico_fp.zig");

const bn254 = crypto.bn254;
const Impl = bn254.Impl;
const checkAdd = bn254.checkAdd;
const checkMul = bn254.checkMul;
const checkPairing = bn254.checkPairing;
const vec_add = bn254.vectors.vec_add;
const vec_mul = bn254.vectors.vec_mul;
const vec_pairing = bn254.vectors.vec_pairing;

// ── guest instantiation (Pico precompiles) ────────────────────────────────────

const Guest = Impl(GuestBackend);

/// Pico backend: FP_*/FP2_* syscalls (pico_fp.zig) plus the BN254 curve precompiles for G1.
const GuestBackend = struct {
    const F = pico_fp.Bn254Fq;
    const sys = @import("pico_sys");
    pub const limbs = F.limbs;
    pub const modulus = F.modulus;
    pub const add = F.add;
    pub const sub = F.sub;
    pub const mul = F.mul;
    pub const fp2_add = F.fp2_add;
    pub const fp2_sub = F.fp2_sub;
    pub const fp2_mul = F.fp2_mul;
    pub fn g1_add(p: *[8]u64, q: *const [8]u64) void {
        sys.ecAdd(sys.BN254_ADD, p, q);
    }
    pub fn g1_double(p: *[8]u64) void {
        sys.ecDouble(sys.BN254_DOUBLE, p);
    }
};

/// Same field syscalls but G1 add/double done by the affine formulas instead of the curve
/// precompiles — an independent in-guest reference for BN254_ADD / BN254_DOUBLE.
const GuestFpOnly = struct {
    const G = GuestBackend;
    pub const limbs = G.limbs;
    pub const modulus = G.modulus;
    pub const add = G.add;
    pub const sub = G.sub;
    pub const mul = G.mul;
    pub const fp2_add = G.fp2_add;
    pub const fp2_sub = G.fp2_sub;
    pub const fp2_mul = G.fp2_mul;
};

pub fn g1Add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) bool {
    return Guest.g1AddBytes(p1, p2, result);
}

pub fn g1Mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) bool {
    return Guest.g1MulBytes(point, scalar, result);
}

pub fn pairing(pairs: anytype, verified: *bool) bool {
    return Guest.pairingBytes(pairs, verified);
}

// ── guest self-test ──────────────────────────────────────────────────────────

/// Guest-only: run the EIP vectors through the Pico-precompile path, and cross-check G1 against
/// the software backend. Never referenced by native tests.
fn dbg(msg: []const u8) void {
    const sys = @import("pico_sys");
    _ = sys.ecall(sys.WRITE, 1, @intFromPtr(msg.ptr), msg.len);
}

pub fn selfTest() bool {
    dbg("bn254: add\n");
    for (vec_add[0..6]) |v| if (!checkAdd(Guest, v)) return false;
    dbg("bn254: mul\n");
    for (vec_mul[0..6]) |v| if (!checkMul(Guest, v)) return false;
    dbg("bn254: G1 precompiles vs formulas\n");
    // BN254_ADD / BN254_DOUBLE vs the affine formulas, on a non-trivial multiple of the generator
    const Soft = Impl(GuestFpOnly);
    var gen: [64]u8 = .{0} ** 64;
    gen[31] = 1;
    gen[63] = 2;
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    var rg: [64]u8 = undefined;
    var rs: [64]u8 = undefined;
    if (!Guest.g1MulBytes(&gen, &k, &rg)) return false;
    if (!Soft.g1MulBytes(&gen, &k, &rs)) return false;
    if (!std.mem.eql(u8, &rg, &rs)) return false;
    dbg("bn254: pairing\n");
    for ([_]usize{ 0, 5, 6, 7, 14 }) |i| if (!checkPairing(Guest, vec_pairing[i])) return false;
    return true;
}
