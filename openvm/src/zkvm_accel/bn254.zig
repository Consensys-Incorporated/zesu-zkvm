/// BN254 G1 add and scalar mul using OpenVM native accelerator instructions.
/// mod_idx=0 → BN254 base field prime p  (opcode=0x2b, funct3=0, funct7=mod_idx*8+op)
/// mod_idx=1 → BN254 scalar field order r
/// curve_idx=0 → BN254 G1               (opcode=0x2b, funct3=1, funct7=curve_idx*8+op)
/// fp2_idx=0   → BN254 Fp2              (opcode=0x2b, funct3=2, funct7=fp2_idx*8+op)
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
    // Fp2 SETUP_ADDSUB for fp2_idx=0: funct3=2, funct7 = 0*8+4 = 4, rs2=x0
    var uninit_fp2: [64]u8 align(8) = undefined;
    asm volatile (".insn r 0x2b, 2, 4, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit_fp2)),
          [rs1] "r" (p_ptr),
        : .{ .memory = true });
    // Fp2 SETUP_MULDIV for fp2_idx=0: funct7=4, rs2=x1
    asm volatile (".insn r 0x2b, 2, 4, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit_fp2)),
          [rs1] "r" (p_ptr),
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

// ── G2 on the sextic twist (software Weierstrass over Fp2) ────────────────────
//
// Fp2 = c0 + c1·u (u² = −1); internal G2 format:
// [x_c0_LE(32) || x_c1_LE(32) || y_c0_LE(32) || y_c1_LE(32)], all-zero = identity.

const Fp2 = [64]u8;

// Twist coefficient b' = 3 / (9 + u) (py_ecc optimized_bn128.b2), c0 || c1.
const B2_LE: Fp2 align(8) = .{
    0xe5, 0x38, 0xa1, 0x24, 0xdc, 0xe6, 0x67, 0x32,
    0xa3, 0xef, 0xdb, 0x59, 0xe5, 0xc5, 0xb4, 0xb5,
    0xc3, 0x6a, 0xe0, 0x1b, 0x99, 0x18, 0xbe, 0x81,
    0xae, 0xaa, 0xb8, 0xce, 0x40, 0x9d, 0x14, 0x2b,
    0xd2, 0x15, 0xc3, 0x85, 0x06, 0xbd, 0xa2, 0xe4,
    0x52, 0x18, 0x2d, 0xe5, 0x84, 0xa0, 0x4f, 0xa7,
    0xf4, 0xfd, 0xd8, 0xee, 0xad, 0xaf, 0x2c, 0xcd,
    0xd4, 0xfe, 0xf0, 0x3a, 0xb0, 0x13, 0x97, 0x00,
};

inline fn addFp2(out: *Fp2, a: *const Fp2, b: *const Fp2) void {
    asm volatile (".insn r 0x2b, 2, 0, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn subFp2(out: *Fp2, a: *const Fp2, b: *const Fp2) void {
    asm volatile (".insn r 0x2b, 2, 1, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn mulFp2(out: *Fp2, a: *const Fp2, b: *const Fp2) void {
    asm volatile (".insn r 0x2b, 2, 2, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn divFp2(out: *Fp2, a: *const Fp2, b: *const Fp2) void {
    asm volatile (".insn r 0x2b, 2, 3, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

fn g2IsInfinity(p: *const [128]u8) bool {
    const words: *const [16]u64 = @ptrCast(@alignCast(p));
    for (words) |w| if (w != 0) return false;
    return true;
}

/// y² = x³ + b' over Fp2, or the identity.
fn g2IsOnCurveOrIdentity(p: *const [128]u8) bool {
    if (g2IsInfinity(p)) return true;
    const x: *const Fp2 = p[0..64];
    const y: *const Fp2 = p[64..128];
    var x2: Fp2 align(8) = undefined;
    var x3: Fp2 align(8) = undefined;
    var y2: Fp2 align(8) = undefined;
    var rhs: Fp2 align(8) = undefined;
    mulFp2(&y2, y, y);
    mulFp2(&x2, x, x);
    mulFp2(&x3, &x2, x);
    addFp2(&rhs, &x3, &B2_LE);
    return std.mem.eql(u8, &y2, &rhs);
}

/// p ← 2p, for p not the identity. #E'(Fp2) = r·(2p − r) is odd, so no
/// point has order 2 and y ≠ 0.
fn g2Double(p: *[128]u8) void {
    const x: *const Fp2 = p[0..64];
    const y: *const Fp2 = p[64..128];
    // lambda = 3x² / 2y  (a = 0)
    var x2: Fp2 align(8) = undefined;
    var num: Fp2 align(8) = undefined;
    var den: Fp2 align(8) = undefined;
    var lambda: Fp2 align(8) = undefined;
    mulFp2(&x2, x, x);
    addFp2(&num, &x2, &x2);
    addFp2(&num, &num, &x2);
    addFp2(&den, y, y);
    divFp2(&lambda, &num, &den);
    // x3 = lambda² − 2x;  y3 = lambda·(x − x3) − y
    var x3: Fp2 align(8) = undefined;
    var y3: Fp2 align(8) = undefined;
    var t: Fp2 align(8) = undefined;
    mulFp2(&x3, &lambda, &lambda);
    subFp2(&x3, &x3, x);
    subFp2(&x3, &x3, x);
    subFp2(&t, x, &x3);
    mulFp2(&y3, &lambda, &t);
    subFp2(&y3, &y3, y);
    @memcpy(p[0..64], &x3);
    @memcpy(p[64..128], &y3);
}

/// a ← a + b.
fn g2PointAddInPlace(a: *[128]u8, b: *const [128]u8) void {
    if (g2IsInfinity(a)) {
        @memcpy(a, b);
        return;
    }
    if (g2IsInfinity(b)) return;
    if (std.mem.eql(u8, a[0..64], b[0..64])) {
        if (std.mem.eql(u8, a[64..128], b[64..128])) {
            g2Double(a);
        } else {
            @memset(a, 0); // P + (−P) = identity
        }
        return;
    }
    const ax: *const Fp2 = a[0..64];
    const ay: *const Fp2 = a[64..128];
    const bx: *const Fp2 = b[0..64];
    const by: *const Fp2 = b[64..128];
    // lambda = (by − ay) / (bx − ax)
    var dy: Fp2 align(8) = undefined;
    var dx: Fp2 align(8) = undefined;
    var lambda: Fp2 align(8) = undefined;
    subFp2(&dy, by, ay);
    subFp2(&dx, bx, ax);
    divFp2(&lambda, &dy, &dx);
    // x3 = lambda² − ax − bx;  y3 = lambda·(ax − x3) − ay
    var x3: Fp2 align(8) = undefined;
    var y3: Fp2 align(8) = undefined;
    var t: Fp2 align(8) = undefined;
    mulFp2(&x3, &lambda, &lambda);
    subFp2(&x3, &x3, ax);
    subFp2(&x3, &x3, bx);
    subFp2(&t, ax, &x3);
    mulFp2(&y3, &lambda, &t);
    subFp2(&y3, &y3, ay);
    @memcpy(a[0..64], &x3);
    @memcpy(a[64..128], &y3);
}

/// EIP-197 requires G2 points in the r-order subgroup: [r]Q = O.
fn g2InSubgroup(q: *const [128]u8) bool {
    var result: [128]u8 align(8) = .{0} ** 128;
    var cur: [128]u8 align(8) = q.*;
    for (0..256) |i| {
        if ((R_LE[i / 8] >> @intCast(i % 8)) & 1 == 1) g2PointAddInPlace(&result, &cur);
        if (!g2IsInfinity(&cur)) g2Double(&cur);
    }
    return g2IsInfinity(&result);
}

// ── Pairing check (OpenVM's pairing library, linked from openvm/pairing) ────

const heap = @import("heap.zig");

extern fn zesu_openvm_bn254_pairing_check(g1: [*]const u8, g2: [*]const u8, n: usize) u8;

/// EIP-197 pairing check. pairs is a slice of (g1:[64]u8, g2:[128]u8) as the
/// precompile encodes them: G1 x||y, G2 x_im||x_re||y_im||y_re, each 32-byte
/// big-endian, all-zero for the identity. Returns false if any point is
/// non-canonical, off its curve, or (G2) outside the r-order subgroup;
/// otherwise sets `verified` to whether the pairing product is 1.
pub fn pairingCheck(pairs: anytype, verified: *bool) bool {
    setupOnce();
    const g1_buf = heap.alloc(pairs.len * 64) orelse return false;
    const g2_buf = heap.alloc(pairs.len * 128) orelse return false;
    var n: usize = 0;
    for (pairs) |*pair| {
        var p: [64]u8 align(8) = undefined;
        p[0..32].* = beToLe(pair.g1[0..32]);
        p[32..64].* = beToLe(pair.g1[32..64]);
        if (!isCanonical(p[0..32], &P_LE) or !isCanonical(p[32..64], &P_LE)) return false;
        if (!isOnCurveOrIdentity(p[0..32], p[32..64])) return false;

        // x_im, x_re, y_im, y_re → internal c0 (re) || c1 (im).
        var q: [128]u8 align(8) = undefined;
        q[0..32].* = beToLe(pair.g2[32..64]);
        q[32..64].* = beToLe(pair.g2[0..32]);
        q[64..96].* = beToLe(pair.g2[96..128]);
        q[96..128].* = beToLe(pair.g2[64..96]);
        inline for (0..4) |c| {
            if (!isCanonical(q[c * 32 ..][0..32], &P_LE)) return false;
        }
        if (!g2IsOnCurveOrIdentity(&q)) return false;
        if (!g2InSubgroup(&q)) return false;

        // Pairs with an identity point contribute 1 to the product.
        if (isInfinity(&p) or g2IsInfinity(&q)) continue;
        @memcpy(g1_buf[n * 64 ..][0..64], &p);
        @memcpy(g2_buf[n * 128 ..][0..128], &q);
        n += 1;
    }
    verified.* = zesu_openvm_bn254_pairing_check(g1_buf, g2_buf, n) == 1;
    return true;
}
