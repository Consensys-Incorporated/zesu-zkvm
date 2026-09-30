/// BN254 G1 add and scalar mul using OpenVM native accelerator instructions.
/// mod_idx=0 → BN254 base field prime p  (opcode=0x2b, funct3=0, funct7=mod_idx*8+op)
/// mod_idx=1 → BN254 scalar field order r
/// curve_idx=0 → BN254 G1               (opcode=0x2b, funct3=1, funct7=curve_idx*8+op)
///
/// Indices follow openvm's SdkVmConfig::standard(), the config eth-act/ere executes with:
///   supported_moduli = [bn254.p, bn254.r, secp256k1.p, secp256k1.n, ...]  (indices 0,1,2,3)
///   supported_curves = [bn254_g1, secp256k1, ...]                          (indices 0,1)
const std = @import("std");

// ── Types & constants ─────────────────────────────────────────────────────────

const Fe = [32]u8; // 256-bit field element, little-endian

// BN254 base field prime p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
const P_LE: Fe align(8) = .{
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c,
    0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a, 0x81, 0x97,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
};

// BN254 scalar field order r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
const R_LE: Fe align(8) = .{
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43,
    0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
};

const ZERO: Fe align(8) = .{0} ** 32;
const ONE: Fe align(8) = .{1} ++ .{0} ** 31;

// EC setup payload: [field_prime_le || curve_a_le]  (a=0 for BN254 G1: y²=x³+3)
const EC_SETUP_P1: [64]u8 align(8) = P_LE ++ ZERO;
const EC_SETUP_P2: [64]u8 align(8) = ONE ++ ONE; // dummy second point

var setup_done: bool = false;

// ── Setup ─────────────────────────────────────────────────────────────────────

fn setupOnce() void {
    if (setup_done) return;
    setup_done = true;
    var uninit: [32]u8 align(8) = undefined;
    var ec_uninit: [128]u8 align(8) = undefined;
    const p_ptr: usize = @intFromPtr(&P_LE);
    const r_ptr: usize = @intFromPtr(&R_LE);
    const p1_ptr: usize = @intFromPtr(&EC_SETUP_P1);
    const p2_ptr: usize = @intFromPtr(&EC_SETUP_P2);

    // SETUP_ADDSUB for mod_idx=0 (BN254 p): funct7 = 0*8+5 = 5
    asm volatile (".insn r 0x2b, 0, 5, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (p_ptr),
        : .{ .memory = true });
    // SETUP_MULDIV for mod_idx=0 (BN254 p)
    asm volatile (".insn r 0x2b, 0, 5, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (p_ptr),
        : .{ .memory = true });
    // SETUP_ADDSUB for mod_idx=1 (BN254 r): funct7 = 1*8+5 = 13
    asm volatile (".insn r 0x2b, 0, 13, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (r_ptr),
        : .{ .memory = true });
    // SETUP_MULDIV for mod_idx=1 (BN254 r)
    asm volatile (".insn r 0x2b, 0, 13, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (r_ptr),
        : .{ .memory = true });
    // SETUP_EC_ADD_NE for curve_idx=0: funct7 = 0*8+2 = 2, rs2 ≠ x0
    asm volatile (".insn r 0x2b, 1, 2, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(&ec_uninit)),
          [rs1] "r" (p1_ptr),
          [rs2] "r" (p2_ptr),
        : .{ .memory = true });
    // SETUP_EC_DOUBLE for curve_idx=0: rs2 = x0
    asm volatile (".insn r 0x2b, 1, 2, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&ec_uninit)),
          [rs1] "r" (p1_ptr),
        : .{ .memory = true });
}

// ── Byte-order helpers ─────────────────────────────────────────────────────────

inline fn beToLe(be: *const [32]u8) Fe {
    var le: Fe = undefined;
    for (0..32) |i| le[i] = be[31 - i];
    return le;
}

inline fn leToBe(le: *const [32]u8) [32]u8 {
    var be: [32]u8 = undefined;
    for (0..32) |i| be[i] = le[31 - i];
    return be;
}

// ── Modular arithmetic — BN254 p (mod_idx=0) ──────────────────────────────────

inline fn addModP(out: *Fe, a: *const Fe, b: *const Fe) void {
    asm volatile (".insn r 0x2b, 0, 0, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn subModP(out: *Fe, a: *const Fe, b: *const Fe) void {
    asm volatile (".insn r 0x2b, 0, 1, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn mulModP(out: *Fe, a: *const Fe, b: *const Fe) void {
    asm volatile (".insn r 0x2b, 0, 2, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

// ── Point helpers ──────────────────────────────────────────────────────────────

fn isCanonical(v: *const Fe, mod: *const Fe) bool {
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (v[i] < mod[i]) return true;
        if (v[i] > mod[i]) return false;
    }
    return false;
}

fn isInfinity(p: *const [64]u8) bool {
    const words: *const [8]u64 = @ptrCast(@alignCast(p));
    for (words) |w| if (w != 0) return false;
    return true;
}

/// In-place point addition using BN254 G1 instructions (curve_idx=0).
/// Handles identity, doubling, and negation.
fn pointAddInPlace(a: *[64]u8, b: *const [64]u8) void {
    if (isInfinity(a)) {
        @memcpy(a, b);
        return;
    }
    if (isInfinity(b)) return;

    if (std.mem.eql(u8, a[0..32], b[0..32])) {
        if (std.mem.eql(u8, a[32..64], b[32..64])) {
            // P == Q: EC_DOUBLE in-place; funct7 = 0*8+1 = 1
            asm volatile (".insn r 0x2b, 1, 1, %[rd], %[rs1], x0"
                :
                : [rd] "r" (@intFromPtr(a)),
                  [rs1] "r" (@intFromPtr(a)),
                : .{ .memory = true });
        } else {
            @memset(a, 0); // P + (−P) = identity
        }
        return;
    }
    // EC_ADD_NE; funct7 = 0*8+0 = 0
    asm volatile (".insn r 0x2b, 1, 0, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(a)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

/// Scalar multiplication: result = k * p, LSB-first double-and-add.
fn scalarMul(result: *[64]u8, k: *const Fe, p: *const [64]u8) void {
    @memset(result, 0);
    if (std.mem.allEqual(u8, k, 0)) return;
    var cur: [64]u8 align(8) = p.*;
    for (0..256) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((k[byte_idx] >> bit_idx) & 1 == 1) {
            pointAddInPlace(result, &cur);
        }
        if (!isInfinity(&cur)) {
            // EC_DOUBLE cur; funct7=1
            asm volatile (".insn r 0x2b, 1, 1, %[rd], %[rs1], x0"
                :
                : [rd] "r" (@intFromPtr(&cur)),
                  [rs1] "r" (@intFromPtr(&cur)),
                : .{ .memory = true });
        }
    }
}

// ── On-curve check ─────────────────────────────────────────────────────────────

/// Verify that (x_le, y_le) satisfies y² = x³ + 3 mod p.
/// Returns true for the identity point (0, 0) as well.
fn isOnCurveOrIdentity(x_le: *const Fe, y_le: *const Fe) bool {
    if (std.mem.allEqual(u8, x_le, 0) and std.mem.allEqual(u8, y_le, 0)) return true;
    var x2: Fe align(8) = undefined;
    var x3: Fe align(8) = undefined;
    var y2: Fe align(8) = undefined;
    var rhs: Fe align(8) = undefined;
    const THREE_LE: Fe align(8) = .{3} ++ .{0} ** 31;
    mulModP(&y2, y_le, y_le);
    mulModP(&x2, x_le, x_le);
    mulModP(&x3, &x2, x_le);
    addModP(&rhs, &x3, &THREE_LE);
    return std.mem.eql(u8, &y2, &rhs);
}

// ── Public interface ───────────────────────────────────────────────────────────

/// EIP-196 G1 point addition: inputs are 64-byte big-endian (x||y); identity = (0,0).
pub fn g1Add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) bool {
    setupOnce();

    var x1 = beToLe(p1[0..32]);
    var y1 = beToLe(p1[32..64]);
    var x2 = beToLe(p2[0..32]);
    var y2 = beToLe(p2[32..64]);

    if (!isCanonical(&x1, &P_LE) or !isCanonical(&y1, &P_LE) or
        !isCanonical(&x2, &P_LE) or !isCanonical(&y2, &P_LE)) return false;
    if (!isOnCurveOrIdentity(&x1, &y1) or !isOnCurveOrIdentity(&x2, &y2)) return false;

    var a: [64]u8 align(8) = undefined;
    var b: [64]u8 align(8) = undefined;
    @memcpy(a[0..32], &x1);
    @memcpy(a[32..64], &y1);
    @memcpy(b[0..32], &x2);
    @memcpy(b[32..64], &y2);

    pointAddInPlace(&a, &b);

    const rx = leToBe(a[0..32]);
    const ry = leToBe(a[32..64]);
    @memcpy(result[0..32], &rx);
    @memcpy(result[32..64], &ry);
    return true;
}

/// EIP-196 G1 scalar multiplication: point is 64-byte big-endian (x||y), scalar is 32-byte big-endian.
pub fn g1Mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) bool {
    setupOnce();

    var px = beToLe(point[0..32]);
    var py = beToLe(point[32..64]);

    if (!isCanonical(&px, &P_LE) or !isCanonical(&py, &P_LE)) return false;
    if (!isOnCurveOrIdentity(&px, &py)) return false;

    var p_buf: [64]u8 align(8) = undefined;
    @memcpy(p_buf[0..32], &px);
    @memcpy(p_buf[32..64], &py);

    const k_le = beToLe(scalar);
    if (!isCanonical(&k_le, &R_LE)) return false;
    var res: [64]u8 align(8) = undefined;
    scalarMul(&res, &k_le, &p_buf);

    const rx = leToBe(res[0..32]);
    const ry = leToBe(res[32..64]);
    @memcpy(result[0..32], &rx);
    @memcpy(result[32..64], &ry);
    return true;
}
