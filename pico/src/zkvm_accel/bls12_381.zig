/// BLS12-381 G1/G2 add + MSM, pairing check, map-to-curve (EIP-2537) and KZG point
/// evaluation (EIP-4844) on Pico.
///
/// Public API (called from pico_accel.zig), all byte layouts big-endian per EIP-2537:
///   g1Add(p1, p2, result) bool              96-byte x‖y; all zeros = identity
///   g1Msm(pairs, result) bool               pairs: slice of {point: [96]u8, scalar: [32]u8}
///   g2Add(p1, p2, result) bool              192 bytes: x_c0‖x_c1‖y_c0‖y_c1 (48 bytes each)
///   g2Msm(pairs, result) bool               pairs: slice of {point: [192]u8, scalar: [32]u8}
///   pairing(pairs, verified) bool           pairs: slice of {g1: [96]u8, g2: [192]u8}
///   mapFpToG1(fe, result) bool              fe: 48 bytes
///   mapFp2ToG2(fe, result) bool             fe: 96 bytes (c0‖c1)
///   kzgPointEval(commitment, z, y, proof, verified) bool
///   selfTest() bool                         guest-only (see selftest.zig)
///
/// The algorithms and their native tests live in shared/src/bls12_381.zig; this file instantiates
/// them with Pico's backend: FP_* / FP2_* syscalls (pico_fp.zig), plus BLS12381_ADD /
/// BLS12381_DOUBLE for G1 (affine, one syscall per group operation). G2 and everything else is
/// built from Fp / Fp2 operations.
const std = @import("std");
const crypto = @import("zkvm_crypto");
const sys = @import("pico_sys");
const pico_fp = @import("pico_fp.zig");

const g = crypto.bls12_381;
const Impl = g.Impl;
const Kind = g.Kind;
const vectors = g.vectors;
const runVector = g.runVector;
const runAllVectors = g.runAllVectors;
const logf = g.logf;
const G1_GEN_BE = g.G1_GEN_BE;

// ── Guest instance: Pico syscalls ───────────────────────────────────────────

/// pico_fp.Bls12381Fq plus the G1 curve precompiles.
const GuestB = struct {
    pub const limbs = 6;
    pub const modulus = pico_fp.Bls12381Fq.modulus;
    pub const add = pico_fp.Bls12381Fq.add;
    pub const sub = pico_fp.Bls12381Fq.sub;
    pub const mul = pico_fp.Bls12381Fq.mul;
    pub const fp2_add = pico_fp.Bls12381Fq.fp2_add;
    pub const fp2_sub = pico_fp.Bls12381Fq.fp2_sub;
    pub const fp2_mul = pico_fp.Bls12381Fq.fp2_mul;
    pub fn ec_add(p: *[12]u64, q: *const [12]u64) void {
        sys.ecAdd(sys.BLS12381_ADD, p, q);
    }
    pub fn ec_double(p: *[12]u64) void {
        sys.ecDouble(sys.BLS12381_DOUBLE, p);
    }
};

/// Same syscalls, without the curve precompiles (selfTest cross-checks them against the
/// Fp-syscall formulas).
const GuestNoEc = struct {
    pub const limbs = 6;
    pub const modulus = pico_fp.Bls12381Fq.modulus;
    pub const add = pico_fp.Bls12381Fq.add;
    pub const sub = pico_fp.Bls12381Fq.sub;
    pub const mul = pico_fp.Bls12381Fq.mul;
    pub const fp2_add = pico_fp.Bls12381Fq.fp2_add;
    pub const fp2_sub = pico_fp.Bls12381Fq.fp2_sub;
    pub const fp2_mul = pico_fp.Bls12381Fq.fp2_mul;
};

const Guest = Impl(GuestB);

pub fn g1Add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) bool {
    return Guest.g1Add(p1, p2, result);
}
pub fn g1Msm(pairs: anytype, result: *[96]u8) bool {
    return Guest.g1Msm(pairs, result);
}
pub fn g2Add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) bool {
    return Guest.g2Add(p1, p2, result);
}
pub fn g2Msm(pairs: anytype, result: *[192]u8) bool {
    return Guest.g2Msm(pairs, result);
}
pub fn pairing(pairs: anytype, verified: *bool) bool {
    return Guest.pairing(pairs, verified);
}
pub fn mapFpToG1(field_element: *const [48]u8, result: *[96]u8) bool {
    return Guest.mapFpToG1(field_element, result);
}
pub fn mapFp2ToG2(field_element: *const [96]u8, result: *[192]u8) bool {
    return Guest.mapFp2ToG2(field_element, result);
}
pub fn kzgPointEval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) bool {
    return Guest.kzgPointEval(commitment, z, y, proof, verified);
}

fn writeStdout(msg: []const u8) void {
    _ = sys.ecall(sys.WRITE, 1, @intFromPtr(msg.ptr), msg.len);
}

// ── Guest self-test ──────────────────────────────────────────────────────────

/// Runs on the VM: the Pico-syscall implementation (with and without the G1 curve precompiles)
/// against EIP-2537 / c-kzg known answers, plus a direct precompile-vs-formula cross-check.
pub fn selfTest() bool {
    g.write_hook = &writeStdout;
    var good = true;
    if (!runAllVectors(Guest, "bls12-381", false)) good = false;
    // Same vectors without the G1 curve precompiles: isolates BLS12381_ADD/DOUBLE from the
    // Fp/Fp2 syscalls the rest of the code relies on.
    const NoEc = Impl(GuestNoEc);
    inline for (.{
        .{ Kind.g1_add, vectors.g1_add },
        .{ Kind.g1_msm, vectors.g1_msm },
    }) |group| {
        for (group[1]) |v| {
            if (!runVector(NoEc, group[0], v.input, v.expected)) {
                logf("bls12-381 (no ec precompiles): vector FAILED: {s}\n", .{@tagName(group[0])});
                good = false;
            }
        }
    }
    // Precompile add/double of generator multiples agree with the Fp formulas.
    const G = Guest.G1;
    const N = NoEc.G1;
    const gen = Guest.g1FromBE(&G1_GEN_BE).?;
    const gen_n = NoEc.g1FromBE(&G1_GEN_BE).?;
    var k: u8 = 2;
    var acc = gen;
    var acc_n = gen_n;
    while (k < 12) : (k += 1) {
        acc = G.add(acc, gen);
        acc_n = N.add(acc_n, gen_n);
        const d = G.double(acc);
        const d_n = N.double(acc_n);
        if (!std.mem.eql(u64, &acc.x, &acc_n.x) or !std.mem.eql(u64, &acc.y, &acc_n.y) or
            !std.mem.eql(u64, &d.x, &d_n.x) or !std.mem.eql(u64, &d.y, &d_n.y))
        {
            logf("bls12-381: BLS12381_ADD/DOUBLE disagree with the Fp formulas at k={d}\n", .{k});
            good = false;
            break;
        }
    }
    return good;
}
