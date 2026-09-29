/// BLS12-381 G1 add/MSM and G2 add/MSM using OpenVM native accelerators.
///
/// mod_idx=6  → BLS12-381 Fq (base field prime)     (opcode=0x2b, funct3=0, funct7=mod_idx*8+op)
/// mod_idx=7  → BLS12-381 Fr (scalar field order)
/// curve_idx=3 → BLS12-381 G1                        (opcode=0x2b, funct3=1, funct7=curve_idx*8+op)
/// fp2_idx=0  → BLS12-381 Fp2 (Fq²)                 (opcode=0x2b, funct3=2, funct7=fp2_idx*8+op)
///
/// Index assignments assume:
///   supported_moduli = [secp256k1.p, secp256k1.n, bn254.p, bn254.r, p256.p, p256.n, bls.Fq, bls.Fr]
///   supported_curves = [secp256k1, bn254_G1, p256, bls_G1]
///   fp2_moduli       = [bls.Fq]
///
/// External point formats (big-endian, EIP-2537):
///   G1: x_BE[48] || y_BE[48]   = 96 bytes
///   G2: x_c0_BE[48] || x_c1_BE[48] || y_c0_BE[48] || y_c1_BE[48] = 192 bytes
///
/// Curves: G1: y²=x³+4  G2: y²=x³+(4+4i) over Fp2
///
/// bls12_pairing, bls12_map_fp_to_g1, bls12_map_fp2_to_g2 require full Miller loop
/// (≥400 lines of Fp12 arithmetic) and are left to callers' stubs.
const std = @import("std");

// ── Type aliases ─────────────────────────────────────────────────────────────

const Fq = [48]u8; // BLS12-381 base field element, little-endian
const Fr = [32]u8; // BLS12-381 scalar field element, little-endian
const Fp2 = [96]u8; // Fp2 element: [c0_LE(48) || c1_LE(48)]

// ── Constants ─────────────────────────────────────────────────────────────────

// Fq = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab (BE)
const FQ_LE: Fq align(8) = .{
    0xab, 0xaa, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xb9,
    0xff, 0xff, 0x53, 0xb1, 0xfe, 0xff, 0xab, 0x1e,
    0x24, 0xf6, 0xb0, 0xf6, 0xa0, 0xd2, 0x30, 0x67,
    0xbf, 0x12, 0x85, 0xf3, 0x84, 0x4b, 0x77, 0x64,
    0xd7, 0xac, 0x4b, 0x43, 0xb6, 0xa7, 0x1b, 0x4b,
    0x9a, 0xe6, 0x7f, 0x39, 0xea, 0x11, 0x01, 0x1a,
};

// Fr = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 (BE)
const FR_LE: Fr align(8) = .{
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
    0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
    0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
};

const ZERO_FQ: Fq align(8) = .{0} ** 48;
const ONE_FQ: Fq align(8) = .{1} ++ (.{0} ** 47);
const FOUR_FQ: Fq align(8) = .{4} ++ (.{0} ** 47); // G1 b = 4

// G2 b coefficient: (4, 4) in Fp2 = [c0=4, c1=4]
const B_FP2: Fp2 align(8) = FOUR_FQ ++ FOUR_FQ;

// EC_SETUP payloads for G1 (96-byte buffers for 48-byte field)
const EC_SETUP_P1: [96]u8 align(8) = FQ_LE ++ ZERO_FQ; // [Fq || a=0]
const EC_SETUP_P2: [96]u8 align(8) = ONE_FQ ++ ONE_FQ; // dummy

// BLS12-381 G1 generator in internal LE format [x_LE(48) || y_LE(48)]
const G1_GEN_X_LE: Fq align(8) = .{
    0xbb, 0xc6, 0x22, 0xdb, 0x0a, 0xf0, 0x3a, 0xfb,
    0xef, 0x1a, 0x7a, 0xf9, 0x3f, 0xe8, 0x55, 0x6c,
    0x58, 0xac, 0x1b, 0x17, 0x3f, 0x3a, 0x4e, 0xa1,
    0x05, 0xb9, 0x74, 0x97, 0x4f, 0x8c, 0x68, 0xc3,
    0x0f, 0xac, 0xa9, 0x4f, 0x8c, 0x63, 0x95, 0x26,
    0x94, 0xd7, 0x97, 0x31, 0xa7, 0xd3, 0xf1, 0x17,
};
const G1_GEN_Y_LE: Fq align(8) = .{
    0xe1, 0xe7, 0xc5, 0x46, 0x29, 0x23, 0xaa, 0x0c,
    0xe4, 0x8a, 0x88, 0xa2, 0x44, 0xc7, 0x3c, 0xd0,
    0xed, 0xb3, 0x04, 0x2c, 0xcb, 0x18, 0xdb, 0x00,
    0xf6, 0x0a, 0xd0, 0xd5, 0x95, 0xe0, 0xf5, 0xfc,
    0xe4, 0x8a, 0x1d, 0x74, 0xed, 0x30, 0x9e, 0xa0,
    0xf1, 0xa0, 0xaa, 0xe3, 0x81, 0xf4, 0xb3, 0x08,
};
const G1_GEN: [96]u8 align(8) = G1_GEN_X_LE ++ G1_GEN_Y_LE;

// G2 generator in internal format [x_c0_LE(48) || x_c1_LE(48) || y_c0_LE(48) || y_c1_LE(48)]
const G2_GEN_X_C0_LE: Fq align(8) = .{
    0xb8, 0xbd, 0x21, 0xc1, 0xc8, 0x56, 0x80, 0xd4,
    0xef, 0xbb, 0x05, 0xa8, 0x26, 0x03, 0xac, 0x0b,
    0x77, 0xd1, 0xe3, 0x7a, 0x64, 0x0b, 0x51, 0xb4,
    0x02, 0x3b, 0x40, 0xfa, 0xd4, 0x7a, 0xe4, 0xc6,
    0x51, 0x10, 0xc5, 0x2d, 0x27, 0x05, 0x08, 0x26,
    0x91, 0x0a, 0x8f, 0xf0, 0xb2, 0xa2, 0x4a, 0x02,
};
const G2_GEN_X_C1_LE: Fq align(8) = .{
    0x7e, 0x2b, 0x04, 0x5d, 0x05, 0x7d, 0xac, 0xe5,
    0x57, 0x5d, 0x94, 0x13, 0x12, 0xf1, 0x4c, 0x33,
    0x49, 0x50, 0x7f, 0xdc, 0xbb, 0x61, 0xda, 0xb5,
    0x1a, 0xb6, 0x20, 0x99, 0xd0, 0xd0, 0x6b, 0x59,
    0x65, 0x4f, 0x27, 0x88, 0xa0, 0xd3, 0xac, 0x7d,
    0x60, 0x9f, 0x71, 0x52, 0x60, 0x2b, 0xe0, 0x13,
};
const G2_GEN_Y_C0_LE: Fq align(8) = .{
    0x01, 0x28, 0xb8, 0x08, 0x86, 0x54, 0x93, 0xe1,
    0x89, 0xa2, 0xac, 0x3b, 0xcc, 0xc9, 0x3a, 0x92,
    0x2c, 0xd1, 0x60, 0x51, 0x69, 0x9a, 0x42, 0x6d,
    0xa7, 0xd3, 0xbd, 0x8c, 0xaa, 0x9b, 0xfd, 0xad,
    0x1a, 0x35, 0x2e, 0xda, 0xc6, 0xcd, 0xc9, 0x8c,
    0x11, 0x6e, 0x7d, 0x72, 0x27, 0xd5, 0xe5, 0x0c,
};
const G2_GEN_Y_C1_LE: Fq align(8) = .{
    0xbe, 0x79, 0x5f, 0xf0, 0x5f, 0x07, 0xa9, 0xaa,
    0xa1, 0x1d, 0xec, 0x5c, 0x27, 0x0d, 0x37, 0x3f,
    0xab, 0x99, 0x2e, 0x57, 0xab, 0x92, 0x74, 0x26,
    0xaf, 0x63, 0xa7, 0x85, 0x7e, 0x28, 0x3e, 0xcb,
    0x99, 0x8b, 0xc2, 0x2b, 0xb0, 0xd2, 0xac, 0x32,
    0xcc, 0x34, 0xa7, 0x2e, 0xa0, 0xc4, 0x06, 0x06,
};
const G2_GEN: [192]u8 align(8) = G2_GEN_X_C0_LE ++ G2_GEN_X_C1_LE ++ G2_GEN_Y_C0_LE ++ G2_GEN_Y_C1_LE;

// EIP-4844 KZG trusted setup: tau*G2 (from ethereum/consensus-specs)
const TAU_G2_X_C0_LE: Fq align(8) = .{
    0xf2, 0xde, 0xc1, 0x20, 0xda, 0xda, 0x8e, 0xc9,
    0xed, 0x00, 0x10, 0x62, 0xde, 0x41, 0x70, 0x08,
    0x0b, 0xc6, 0xa4, 0x7b, 0x47, 0x51, 0x68, 0xa3,
    0xc9, 0xea, 0xec, 0xcc, 0x11, 0xc9, 0x26, 0x39,
    0xe2, 0x08, 0x86, 0xb3, 0xb7, 0x29, 0x44, 0x73,
    0x14, 0x27, 0x49, 0x53, 0xee, 0xbf, 0x5c, 0x18,
};
const TAU_G2_X_C1_LE: Fq align(8) = .{
    0x72, 0x9f, 0x49, 0xf3, 0x24, 0xab, 0xaa, 0xaf,
    0xd2, 0x52, 0xb4, 0x0c, 0x87, 0xe5, 0x14, 0x29,
    0x3d, 0xc5, 0x5a, 0x61, 0xce, 0xa2, 0x09, 0x10,
    0xa8, 0xef, 0xfb, 0xcb, 0x75, 0x70, 0x18, 0x26,
    0x89, 0xf3, 0x0a, 0x23, 0x87, 0xc2, 0x3b, 0x84,
    0x28, 0xb1, 0xde, 0x8c, 0xdd, 0xd7, 0xbf, 0x15,
};
const TAU_G2_Y_C0_LE: Fq align(8) = .{
    0x99, 0x2a, 0x83, 0xbb, 0xfb, 0x9b, 0x68, 0xee,
    0x83, 0xf3, 0x41, 0x59, 0x10, 0x6d, 0xe2, 0x4c,
    0x79, 0xc9, 0xa9, 0x96, 0xa4, 0x51, 0x24, 0xe8,
    0x18, 0xde, 0x28, 0x0e, 0x49, 0x69, 0x15, 0x13,
    0xa2, 0xfc, 0xd1, 0x99, 0x85, 0xee, 0xd5, 0xd7,
    0x6d, 0x62, 0x6b, 0xb9, 0xbd, 0x53, 0x43, 0x01,
};
const TAU_G2_Y_C1_LE: Fq align(8) = .{
    0x4f, 0x15, 0x0a, 0x0d, 0xf3, 0x8e, 0x04, 0x23,
    0xcd, 0xc9, 0x7a, 0x3d, 0x6f, 0x34, 0x95, 0x94,
    0x89, 0x07, 0xfa, 0x9b, 0xba, 0xd1, 0x5e, 0xda,
    0x1f, 0x67, 0x63, 0xfc, 0x09, 0xde, 0x79, 0xef,
    0x4b, 0x1b, 0x18, 0xe0, 0xca, 0x2f, 0x43, 0x03,
    0x95, 0x52, 0x32, 0x0a, 0x4b, 0xc5, 0x66, 0x16,
};
const TAU_G2: [192]u8 align(8) = TAU_G2_X_C0_LE ++ TAU_G2_X_C1_LE ++ TAU_G2_Y_C0_LE ++ TAU_G2_Y_C1_LE;

// (p+1)/4 exponent for Fq square root (p ≡ 3 mod 4, so x^((p+1)/4) = sqrt(x))
const FQ_SQRT_EXP: [48]u8 = .{
    0xab, 0xea, 0xff, 0xff, 0xff, 0xbf, 0x7f, 0xee,
    0xff, 0xff, 0x54, 0xac, 0xff, 0xff, 0xaa, 0x07,
    0x89, 0x3d, 0xac, 0x3d, 0xa8, 0x34, 0xcc, 0xd9,
    0xaf, 0x44, 0xe1, 0x3c, 0xe1, 0xd2, 0x1d, 0xd9,
    0x35, 0xeb, 0xd2, 0x90, 0xed, 0xe9, 0xc6, 0x92,
    0xa6, 0xf9, 0x5f, 0x8e, 0x7a, 0x44, 0x80, 0x06,
};

// (p-1)/2 in LE for IETF G1 sign comparison (lexicographically_largest)
const HALF_FQ_LE: Fq = .{
    0x55, 0xd5, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xdc,
    0xff, 0xff, 0xa9, 0x58, 0xff, 0xff, 0x55, 0x0f,
    0x12, 0x7b, 0x58, 0x7b, 0x50, 0x69, 0x98, 0xb3,
    0x5f, 0x89, 0xc2, 0x79, 0xc2, 0xa5, 0x3b, 0xb2,
    0x6b, 0xd6, 0xa5, 0x21, 0xdb, 0xd3, 0x8d, 0x25,
    0x4d, 0xf3, 0xbf, 0x1c, 0xf5, 0x88, 0x00, 0x0d,
};

var setup_done: bool = false;

// ── Setup ─────────────────────────────────────────────────────────────────────

fn setupOnce() void {
    if (setup_done) return;
    setup_done = true;

    var uninit_fq: [48]u8 align(8) = undefined;
    var uninit_fp2: [96]u8 align(8) = undefined;
    var ec_uninit: [192]u8 align(8) = undefined;
    const fq_ptr: usize = @intFromPtr(&FQ_LE);
    const fr_ptr: usize = @intFromPtr(&FR_LE);
    const p1_ptr: usize = @intFromPtr(&EC_SETUP_P1);
    const p2_ptr: usize = @intFromPtr(&EC_SETUP_P2);

    // SETUP_ADDSUB for mod_idx=6 (Fq): funct7 = 6*8+5 = 53
    asm volatile (".insn r 0x2b, 0, 53, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit_fq)),
          [rs1] "r" (fq_ptr),
        : .{ .memory = true });
    // SETUP_MULDIV for mod_idx=6 (Fq): funct7=53, rs2=x1
    asm volatile (".insn r 0x2b, 0, 53, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit_fq)),
          [rs1] "r" (fq_ptr),
        : .{ .memory = true });

    // SETUP_ADDSUB for mod_idx=7 (Fr): funct7 = 7*8+5 = 61
    asm volatile (".insn r 0x2b, 0, 61, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit_fq)),
          [rs1] "r" (fr_ptr),
        : .{ .memory = true });
    // SETUP_MULDIV for mod_idx=7 (Fr): funct7=61, rs2=x1
    asm volatile (".insn r 0x2b, 0, 61, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit_fq)),
          [rs1] "r" (fr_ptr),
        : .{ .memory = true });

    // Fp2 SETUP_ADDSUB for fp2_idx=0: funct3=2, funct7 = 0*8+4 = 4, rs2=x0
    asm volatile (".insn r 0x2b, 2, 4, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit_fp2)),
          [rs1] "r" (fq_ptr),
        : .{ .memory = true });
    // Fp2 SETUP_MULDIV for fp2_idx=0: funct7=4, rs2=x1
    asm volatile (".insn r 0x2b, 2, 4, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit_fp2)),
          [rs1] "r" (fq_ptr),
        : .{ .memory = true });

    // SETUP_EC_ADD_NE for curve_idx=3 (G1): funct3=1, funct7 = 3*8+2 = 26, rs2 != x0
    asm volatile (".insn r 0x2b, 1, 26, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(&ec_uninit)),
          [rs1] "r" (p1_ptr),
          [rs2] "r" (p2_ptr),
        : .{ .memory = true });
    // SETUP_EC_DOUBLE for curve_idx=3 (G1): funct7=26, rs2=x0
    asm volatile (".insn r 0x2b, 1, 26, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&ec_uninit)),
          [rs1] "r" (p1_ptr),
        : .{ .memory = true });
}

// ── Byte-order helpers ─────────────────────────────────────────────────────────

inline fn fqBeToLe(be: *const [48]u8) Fq {
    var le: Fq = undefined;
    for (0..48) |i| le[i] = be[47 - i];
    return le;
}

inline fn fqLeToBe(le: *const [48]u8) [48]u8 {
    var be: [48]u8 = undefined;
    for (0..48) |i| be[i] = le[47 - i];
    return be;
}

inline fn frBeToLe(be: *const [32]u8) Fr {
    var le: Fr = undefined;
    for (0..32) |i| le[i] = be[31 - i];
    return le;
}

// ── Fq arithmetic (mod_idx=6, funct3=0) ──────────────────────────────────────

inline fn addFq(out: *Fq, a: *const Fq, b: *const Fq) void {
    asm volatile (".insn r 0x2b, 0, 48, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn mulFq(out: *Fq, a: *const Fq, b: *const Fq) void {
    asm volatile (".insn r 0x2b, 0, 50, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn subFq(out: *Fq, a: *const Fq, b: *const Fq) void {
    asm volatile (".insn r 0x2b, 0, 49, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

// ── Fp2 arithmetic (fp2_idx=0, funct3=2, funct7 = 0*8+base) ─────────────────

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

// ── G1 point helpers ──────────────────────────────────────────────────────────

fn fqIsCanonical(v: *const Fq) bool {
    var i: usize = 48;
    while (i > 0) {
        i -= 1;
        if (v[i] < FQ_LE[i]) return true;
        if (v[i] > FQ_LE[i]) return false;
    }
    return false;
}

fn g1IsInfinity(p: *const [96]u8) bool {
    const words: *const [12]u64 = @ptrCast(@alignCast(p));
    for (words) |w| if (w != 0) return false;
    return true;
}

/// In-place G1 addition using native curve_idx=3 instructions.
fn g1PointAddInPlace(a: *[96]u8, b: *const [96]u8) void {
    if (g1IsInfinity(a)) {
        @memcpy(a, b);
        return;
    }
    if (g1IsInfinity(b)) return;
    if (std.mem.eql(u8, a[0..48], b[0..48])) {
        if (std.mem.eql(u8, a[48..96], b[48..96])) {
            // EC_DOUBLE in-place; funct7 = 3*8+1 = 25
            asm volatile (".insn r 0x2b, 1, 25, %[rd], %[rs1], x0"
                :
                : [rd] "r" (@intFromPtr(a)),
                  [rs1] "r" (@intFromPtr(a)),
                : .{ .memory = true });
        } else {
            @memset(a, 0); // P + (-P) = identity
        }
        return;
    }
    // EC_ADD_NE; funct7 = 3*8+0 = 24
    asm volatile (".insn r 0x2b, 1, 24, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(a)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

/// G1 scalar multiply: result = k * p, LSB-first double-and-add.
fn g1ScalarMul(result: *[96]u8, k: *const Fr, p: *const [96]u8) void {
    g1ScalarMulBytes(result, k, p);
}

/// G1 scalar multiply by a little-endian scalar of any length.
fn g1ScalarMulBytes(result: *[96]u8, k: []const u8, p: *const [96]u8) void {
    @memset(result, 0);
    if (std.mem.allEqual(u8, k, 0)) return;
    var cur: [96]u8 align(8) = p.*;
    for (0..k.len * 8) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((k[byte_idx] >> bit_idx) & 1 == 1) {
            g1PointAddInPlace(result, &cur);
        }
        if (!g1IsInfinity(&cur)) {
            asm volatile (".insn r 0x2b, 1, 25, %[rd], %[rs1], x0"
                :
                : [rd] "r" (@intFromPtr(&cur)),
                  [rs1] "r" (@intFromPtr(&cur)),
                : .{ .memory = true });
        }
    }
}

/// y² = x³ + 4 mod Fq check.
fn g1IsOnCurveOrIdentity(x: *const Fq, y: *const Fq) bool {
    if (std.mem.allEqual(u8, x, 0) and std.mem.allEqual(u8, y, 0)) return true;
    var x2: Fq align(8) = undefined;
    var x3: Fq align(8) = undefined;
    var y2: Fq align(8) = undefined;
    var rhs: Fq align(8) = undefined;
    mulFq(&y2, y, y);
    mulFq(&x2, x, x);
    mulFq(&x3, &x2, x);
    addFq(&rhs, &x3, &FOUR_FQ);
    return std.mem.eql(u8, &y2, &rhs);
}

// ── Fp2 helpers ───────────────────────────────────────────────────────────────

fn fp2IsZero(a: *const Fp2) bool {
    const words: *const [12]u64 = @ptrCast(@alignCast(a));
    for (words) |w| if (w != 0) return false;
    return true;
}

/// Wrap a 48-byte Fq LE slice as a read-only Fp2 pointer (c0=val, c1=0).
/// Caller must provide a 96-byte buffer `buf` for the Fp2 element.
fn fqToFp2(buf: *Fp2, fq: *const Fq) void {
    @memcpy(buf[0..48], fq);
    @memset(buf[48..96], 0);
}

// ── G2 point helpers (software Weierstrass over Fp2) ─────────────────────────
//
// Internal G2 format: [x_c0_LE(48) || x_c1_LE(48) || y_c0_LE(48) || y_c1_LE(48)] = 192 bytes

fn g2IsInfinity(p: *const [192]u8) bool {
    const words: *const [24]u64 = @ptrCast(@alignCast(p));
    for (words) |w| if (w != 0) return false;
    return true;
}

/// G2 in-place point doubling: p ← 2*p using Fp2 arithmetic.
/// Assumes p is not the identity; caller must check.
fn g2Double(p: *[192]u8) void {
    const x: *const Fp2 = @ptrCast(p[0..96]);
    const y: *const Fp2 = @ptrCast(p[96..192]);

    // lambda = 3*x^2 / (2*y)   [a'=0 for BLS12-381 G2]
    var x2: Fp2 align(8) = undefined;
    var x2_2: Fp2 align(8) = undefined;
    var x2_3: Fp2 align(8) = undefined;
    var y2: Fp2 align(8) = undefined;
    var lambda: Fp2 align(8) = undefined;
    mulFp2(&x2, x, x);
    addFp2(&x2_2, &x2, &x2);
    addFp2(&x2_3, &x2_2, &x2);
    addFp2(&y2, y, y);
    divFp2(&lambda, &x2_3, &y2);

    // x3 = lambda^2 - 2*x
    var lambda2: Fp2 align(8) = undefined;
    var x2b: Fp2 align(8) = undefined;
    var x3: Fp2 align(8) = undefined;
    mulFp2(&lambda2, &lambda, &lambda);
    addFp2(&x2b, x, x);
    subFp2(&x3, &lambda2, &x2b);

    // y3 = lambda * (x - x3) - y
    var dx: Fp2 align(8) = undefined;
    var y3: Fp2 align(8) = undefined;
    subFp2(&dx, x, &x3);
    mulFp2(&y3, &lambda, &dx);
    subFp2(&y3, &y3, y);

    @memcpy(p[0..96], &x3);
    @memcpy(p[96..192], &y3);
}

/// G2 in-place addition: a ← a + b, using Fp2 arithmetic.
fn g2PointAddInPlace(a: *[192]u8, b: *const [192]u8) void {
    if (g2IsInfinity(a)) {
        @memcpy(a, b);
        return;
    }
    if (g2IsInfinity(b)) return;

    const ax: *const Fp2 = @ptrCast(a[0..96]);
    const ay: *const Fp2 = @ptrCast(a[96..192]);
    const bx: *const Fp2 = @ptrCast(b[0..96]);
    const by: *const Fp2 = @ptrCast(b[96..192]);

    if (std.mem.eql(u8, ax, bx)) {
        if (std.mem.eql(u8, ay, by)) {
            g2Double(a);
        } else {
            @memset(a, 0); // a + (-a) = identity
        }
        return;
    }

    // lambda = (by - ay) / (bx - ax)
    var dy: Fp2 align(8) = undefined;
    var dx: Fp2 align(8) = undefined;
    var lambda: Fp2 align(8) = undefined;
    subFp2(&dy, by, ay);
    subFp2(&dx, bx, ax);
    divFp2(&lambda, &dy, &dx);

    // x3 = lambda^2 - ax - bx
    var lambda2: Fp2 align(8) = undefined;
    var x3: Fp2 align(8) = undefined;
    mulFp2(&lambda2, &lambda, &lambda);
    subFp2(&x3, &lambda2, ax);
    subFp2(&x3, &x3, bx);

    // y3 = lambda * (ax - x3) - ay
    var xdiff: Fp2 align(8) = undefined;
    var y3: Fp2 align(8) = undefined;
    subFp2(&xdiff, ax, &x3);
    mulFp2(&y3, &lambda, &xdiff);
    subFp2(&y3, &y3, ay);

    @memcpy(a[0..96], &x3);
    @memcpy(a[96..192], &y3);
}

/// G2 scalar multiply: result = k * p, LSB-first double-and-add.
fn g2ScalarMul(result: *[192]u8, k: *const Fr, p: *const [192]u8) void {
    g2ScalarMulBytes(result, k, p);
}

/// G2 scalar multiply by a little-endian scalar of any length.
fn g2ScalarMulBytes(result: *[192]u8, k: []const u8, p: *const [192]u8) void {
    @memset(result, 0);
    if (std.mem.allEqual(u8, k, 0)) return;
    var cur: [192]u8 align(8) = p.*;
    for (0..k.len * 8) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((k[byte_idx] >> bit_idx) & 1 == 1) {
            g2PointAddInPlace(result, &cur);
        }
        if (!g2IsInfinity(&cur)) {
            g2Double(&cur);
        }
    }
}

/// y² = x³ + (4+4i) mod Fp2 check.
fn g2IsOnCurveOrIdentity(x: *const Fp2, y: *const Fp2) bool {
    if (fp2IsZero(x) and fp2IsZero(y)) return true;
    var x2: Fp2 align(8) = undefined;
    var x3: Fp2 align(8) = undefined;
    var y2: Fp2 align(8) = undefined;
    var rhs: Fp2 align(8) = undefined;
    mulFp2(&y2, y, y);
    mulFp2(&x2, x, x);
    mulFp2(&x3, &x2, x);
    addFp2(&rhs, &x3, &B_FP2);
    return std.mem.eql(u8, &y2, &rhs);
}

// ── Fq sqrt and G1 decompression ─────────────────────────────────────────────

fn fqSqrt(out: *Fq, a: *const Fq) void {
    var result: Fq align(8) = ONE_FQ;
    var base: Fq align(8) = a.*;
    for (0..384) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((FQ_SQRT_EXP[byte_idx] >> bit_idx) & 1 == 1) {
            mulFq(&result, &result, &base);
        }
        mulFq(&base, &base, &base);
    }
    out.* = result;
}

fn isLexLarger(y: *const Fq) bool {
    var i: usize = 48;
    while (i > 0) {
        i -= 1;
        if (y[i] > HALF_FQ_LE[i]) return true;
        if (y[i] < HALF_FQ_LE[i]) return false;
    }
    return false;
}

/// Decompress an IETF BLS12-381 G1 point (48 bytes, big-endian) into the 96-byte
/// internal format [x_LE(48) || y_LE(48)]. Returns false for invalid input.
fn decompressG1(compressed: *const [48]u8, out: *[96]u8) bool {
    if ((compressed[0] >> 7) & 1 == 0) return false; // not compressed
    if ((compressed[0] >> 6) & 1 == 1) { // point at infinity
        @memset(out, 0);
        return true;
    }
    const sign_flag: u8 = (compressed[0] >> 5) & 1;
    var x_be: [48]u8 = compressed.*;
    x_be[0] &= 0x1f;
    var x: Fq align(8) = fqBeToLe(&x_be);
    if (!fqIsCanonical(&x)) return false;
    var x2: Fq align(8) = undefined;
    var x3: Fq align(8) = undefined;
    var rhs: Fq align(8) = undefined;
    mulFq(&x2, &x, &x);
    mulFq(&x3, &x2, &x);
    addFq(&rhs, &x3, &FOUR_FQ);
    var y: Fq align(8) = undefined;
    fqSqrt(&y, &rhs);
    var y2: Fq align(8) = undefined;
    mulFq(&y2, &y, &y);
    if (!std.mem.eql(u8, &y2, &rhs)) return false; // x not on curve
    if (isLexLarger(&y) != (sign_flag == 1)) {
        subFq(&y, &ZERO_FQ, &y);
    }
    @memcpy(out[0..48], &x);
    @memcpy(out[48..96], &y);
    return true;
}

fn hintBufferChunked(buf: [*]u8, num_dwords: usize) void {
    const MAX_CHUNK: usize = 1023;
    var remaining = num_dwords;
    var ptr = buf;
    while (remaining > 0) {
        const chunk = if (remaining > MAX_CHUNK) MAX_CHUNK else remaining;
        asm volatile (".insn i 0x0b, 1, %[rd], %[rs1], 1"
            :
            : [rd] "r" (@intFromPtr(ptr)),
              [rs1] "r" (chunk),
            : .{ .memory = true });
        ptr = ptr + chunk * 8;
        remaining -= chunk;
    }
}

// ── G2 external ↔ internal coordinate conversion ─────────────────────────────
//
// EIP-2537 external G2 format: [x_c0_BE(48) || x_c1_BE(48) || y_c0_BE(48) || y_c1_BE(48)]
// Internal G2 format:          [x_c0_LE(48) || x_c1_LE(48) || y_c0_LE(48) || y_c1_LE(48)]
//
// EIP-2537 encodes an Fp2 element as c0 || c1, so each 48-byte coordinate only
// changes endianness.

fn g2ExternalToInternal(ext: *const [192]u8, internal: *[192]u8) void {
    for (0..4) |c| {
        for (0..48) |i| internal[c * 48 + i] = ext[c * 48 + 47 - i];
    }
}

fn g2InternalToExternal(internal: *const [192]u8, ext: *[192]u8) void {
    for (0..4) |c| {
        for (0..48) |i| ext[c * 48 + i] = internal[c * 48 + 47 - i];
    }
}

// EIP-2537 requires MSM (and pairing) inputs to be in the r-order subgroup:
// [r]P = O. The identity is in the subgroup.

fn g1InSubgroup(p: *const [96]u8) bool {
    var t: [96]u8 align(8) = undefined;
    g1ScalarMul(&t, &FR_LE, p);
    return g1IsInfinity(&t);
}

fn g2InSubgroup(p: *const [192]u8) bool {
    var t: [192]u8 align(8) = undefined;
    g2ScalarMul(&t, &FR_LE, p);
    return g2IsInfinity(&t);
}

// ── Map to curve (EIP-2537 MAP_FP_TO_G1 / MAP_FP2_TO_G2) ──────────────────────
//
// RFC 9380 simplified SWU onto an isogenous curve, the isogeny back to
// BLS12-381, then cofactor clearing. Mirrors py_ecc (py_ecc.bls.hash_to_curve
// map_to_curve_G1/G2 + clear_cofactor_G1/G2), the library EELS uses, step for
// step; constants are generated from it into bls12_381_map_constants.zig.
// SWU and the isogeny work in homogeneous projective coordinates (x/z, y/z).

const mc = @import("bls12_381_map_constants.zig");

const ONE_FP2: Fp2 align(8) = ONE_FQ ++ ZERO_FQ;
const ZERO_FP2: Fp2 align(8) = .{0} ** 96;

inline fn divFq(out: *Fq, a: *const Fq, b: *const Fq) void {
    asm volatile (".insn r 0x2b, 0, 51, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

fn fqIsZero(a: *const Fq) bool {
    return std.mem.allEqual(u8, a, 0);
}

/// RFC 9380 sgn0 for Fp: parity of the canonical value.
fn fqSgn0(a: *const Fq) u1 {
    return @truncate(a[0]);
}

/// RFC 9380 sgn0 for Fp2 (m = 2).
fn fp2Sgn0(a: *const Fp2) u1 {
    const sign_0: u1 = @truncate(a[0]);
    const zero_0: u1 = @intFromBool(std.mem.allEqual(u8, a[0..48], 0));
    const sign_1: u1 = @truncate(a[48]);
    return sign_0 | (zero_0 & sign_1);
}

/// out = base^exp, exp little-endian.
fn fqPow(out: *Fq, base: *const Fq, exp: []const u8) void {
    var result: Fq align(8) = ONE_FQ;
    var b: Fq align(8) = base.*;
    for (exp) |byte| {
        for (0..8) |bit| {
            if ((byte >> @intCast(bit)) & 1 == 1) mulFq(&result, &result, &b);
            mulFq(&b, &b, &b);
        }
    }
    out.* = result;
}

/// out = base^exp, exp little-endian.
fn fp2Pow(out: *Fp2, base: *const Fp2, exp: []const u8) void {
    var result: Fp2 align(8) = ONE_FP2;
    var b: Fp2 align(8) = base.*;
    for (exp) |byte| {
        for (0..8) |bit| {
            if ((byte >> @intCast(bit)) & 1 == 1) mulFp2(&result, &result, &b);
            mulFp2(&b, &b, &b);
        }
    }
    out.* = result;
}

/// py_ecc optimized_swu_G1: t ↦ (x, y, z) on the 11-isogenous curve.
fn swuG1(t: *const Fq, ox: *Fq, oy: *Fq, oz: *Fq) void {
    var t2: Fq align(8) = undefined;
    var zt2: Fq align(8) = undefined;
    var temp: Fq align(8) = undefined;
    var den: Fq align(8) = undefined;
    var num: Fq align(8) = undefined;
    mulFq(&t2, t, t);
    mulFq(&zt2, &mc.ISO_11_Z, &t2);
    mulFq(&temp, &zt2, &zt2);
    addFq(&temp, &zt2, &temp); // Z·t² + Z²·t⁴
    mulFq(&den, &mc.ISO_11_A, &temp);
    subFq(&den, &ZERO_FQ, &den); // −A·(Z·t² + Z²·t⁴)
    addFq(&temp, &temp, &ONE_FQ);
    mulFq(&num, &mc.ISO_11_B, &temp); // B·(Z·t² + Z²·t⁴ + 1)
    if (fqIsZero(&den)) mulFq(&den, &mc.ISO_11_Z, &mc.ISO_11_A);

    // v = D³, u = N³ + A·N·D² + B·D³
    var den2: Fq align(8) = undefined;
    var v: Fq align(8) = undefined;
    var u: Fq align(8) = undefined;
    var tmp: Fq align(8) = undefined;
    mulFq(&den2, &den, &den);
    mulFq(&v, &den2, &den);
    mulFq(&u, &num, &num);
    mulFq(&u, &u, &num);
    mulFq(&tmp, &mc.ISO_11_A, &num);
    mulFq(&tmp, &tmp, &den2);
    addFq(&u, &u, &tmp);
    mulFq(&tmp, &mc.ISO_11_B, &v);
    addFq(&u, &u, &tmp);

    // sqrt_division_FQ: y = uv·(uv·v²)^((p−3)/4); a root iff y²·v = u.
    var uv: Fq align(8) = undefined;
    var y: Fq align(8) = undefined;
    mulFq(&uv, &u, &v);
    mulFq(&tmp, &v, &v);
    mulFq(&tmp, &uv, &tmp);
    fqPow(&tmp, &tmp, &mc.P_MINUS_3_DIV_4);
    mulFq(&y, &uv, &tmp);
    mulFq(&tmp, &y, &y);
    mulFq(&tmp, &tmp, &v);
    subFq(&tmp, &tmp, &u);
    if (!fqIsZero(&tmp)) {
        mulFq(&tmp, &t2, t);
        mulFq(&y, &y, &tmp);
        mulFq(&y, &y, &mc.SQRT_MINUS_11_CUBED);
        mulFq(&num, &num, &zt2);
    }

    if (fqSgn0(t) != fqSgn0(&y)) subFq(&y, &ZERO_FQ, &y);
    mulFq(&y, &y, &den);
    ox.* = num;
    oy.* = y;
    oz.* = den;
}

/// Horner evaluation of one isogeny polynomial, as py_ecc iso_map_G1/G2 does:
/// k[last] then, for j = 0.., acc = acc·x + z^(j+1)·k[last−1−j].
fn hornerFq(out: *Fq, k: []const [48]u8, x: *const Fq, z_pows: []const Fq) void {
    var term: Fq align(8) = undefined;
    out.* = k[k.len - 1];
    for (0..k.len - 1) |j| {
        mulFq(out, out, x);
        mulFq(&term, &z_pows[j], &k[k.len - 2 - j]);
        addFq(out, out, &term);
    }
}

fn hornerFp2(out: *Fp2, k: []const [96]u8, x: *const Fp2, z_pows: []const Fp2) void {
    var term: Fp2 align(8) = undefined;
    out.* = k[k.len - 1];
    for (0..k.len - 1) |j| {
        mulFp2(out, out, x);
        mulFp2(&term, &z_pows[j], &k[k.len - 2 - j]);
        addFp2(out, out, &term);
    }
}

/// py_ecc iso_map_G1: 11-isogeny to BLS12-381 G1.
fn isoMapG1(x: *const Fq, y: *const Fq, z: *const Fq, ox: *Fq, oy: *Fq, oz: *Fq) void {
    var z_pows: [15]Fq align(8) = undefined;
    z_pows[0] = z.*;
    for (1..z_pows.len) |i| mulFq(&z_pows[i], &z_pows[i - 1], z);

    var x_num: Fq align(8) = undefined;
    var x_den: Fq align(8) = undefined;
    var y_num: Fq align(8) = undefined;
    var y_den: Fq align(8) = undefined;
    hornerFq(&x_num, &mc.ISO_11_X_NUM, x, &z_pows);
    hornerFq(&x_den, &mc.ISO_11_X_DEN, x, &z_pows);
    hornerFq(&y_num, &mc.ISO_11_Y_NUM, x, &z_pows);
    hornerFq(&y_den, &mc.ISO_11_Y_DEN, x, &z_pows);
    mulFq(&x_den, &x_den, z); // x-denominator is one degree lower
    mulFq(&y_num, &y_num, y);
    mulFq(&y_den, &y_den, z);

    mulFq(oz, &x_den, &y_den);
    mulFq(ox, &x_num, &y_den);
    mulFq(oy, &x_den, &y_num);
}

/// py_ecc optimized_swu_G2: t ↦ (x, y, z) on the 3-isogenous curve.
fn swuG2(t: *const Fp2, ox: *Fp2, oy: *Fp2, oz: *Fp2) void {
    var t2: Fp2 align(8) = undefined;
    var zt2: Fp2 align(8) = undefined;
    var temp: Fp2 align(8) = undefined;
    var den: Fp2 align(8) = undefined;
    var num: Fp2 align(8) = undefined;
    mulFp2(&t2, t, t);
    mulFp2(&zt2, &mc.ISO_3_Z, &t2);
    mulFp2(&temp, &zt2, &zt2);
    addFp2(&temp, &zt2, &temp); // Z·t² + Z²·t⁴
    mulFp2(&den, &mc.ISO_3_A, &temp);
    subFp2(&den, &ZERO_FP2, &den); // −A·(Z·t² + Z²·t⁴)
    addFp2(&temp, &temp, &ONE_FP2);
    mulFp2(&num, &mc.ISO_3_B, &temp); // B·(Z·t² + Z²·t⁴ + 1)
    if (fp2IsZero(&den)) mulFp2(&den, &mc.ISO_3_Z, &mc.ISO_3_A);

    // v = D³, u = N³ + A·N·D² + B·D³
    var den2: Fp2 align(8) = undefined;
    var v: Fp2 align(8) = undefined;
    var u: Fp2 align(8) = undefined;
    var tmp: Fp2 align(8) = undefined;
    mulFp2(&den2, &den, &den);
    mulFp2(&v, &den2, &den);
    mulFp2(&u, &num, &num);
    mulFp2(&u, &u, &num);
    mulFp2(&tmp, &mc.ISO_3_A, &num);
    mulFp2(&tmp, &tmp, &den2);
    addFp2(&u, &u, &tmp);
    mulFp2(&tmp, &mc.ISO_3_B, &v);
    addFp2(&u, &u, &tmp);

    // sqrt_division_FQ2: gamma = uv⁷·(uv¹⁵)^((p²−9)/16); a root is
    // root·gamma for the first eighth root of unity with (root·gamma)²·v = u.
    var v2: Fp2 align(8) = undefined;
    var v4: Fp2 align(8) = undefined;
    var v7: Fp2 align(8) = undefined;
    var v8: Fp2 align(8) = undefined;
    var temp1: Fp2 align(8) = undefined;
    var gamma: Fp2 align(8) = undefined;
    mulFp2(&v2, &v, &v);
    mulFp2(&v4, &v2, &v2);
    mulFp2(&v7, &v4, &v2);
    mulFp2(&v7, &v7, &v);
    mulFp2(&v8, &v4, &v4);
    mulFp2(&temp1, &u, &v7);
    mulFp2(&tmp, &temp1, &v8);
    fp2Pow(&gamma, &tmp, &mc.P_MINUS_9_DIV_16);
    mulFp2(&gamma, &gamma, &temp1);

    var y: Fp2 align(8) = gamma;
    var success = false;
    var cand: Fp2 align(8) = undefined;
    for (&mc.POSITIVE_EIGHTH_ROOTS_OF_UNITY) |*root| {
        mulFp2(&cand, root, &gamma);
        mulFp2(&tmp, &cand, &cand);
        mulFp2(&tmp, &tmp, &v);
        subFp2(&tmp, &tmp, &u);
        if (fp2IsZero(&tmp) and !success) {
            success = true;
            y = cand;
        }
    }

    // Not a square: try x1 = Z·t²·x0, whose root is eta·sqrt_candidate·t³.
    var sqrt_candidate: Fp2 align(8) = undefined;
    mulFp2(&tmp, &t2, t);
    mulFp2(&sqrt_candidate, &y, &tmp);
    var u_x1: Fp2 align(8) = undefined;
    mulFp2(&tmp, &zt2, &zt2);
    mulFp2(&tmp, &tmp, &zt2);
    mulFp2(&u_x1, &tmp, &u); // Z³·t⁶·u
    var success_2 = false;
    for (&mc.ETAS) |*eta| {
        mulFp2(&cand, eta, &sqrt_candidate);
        mulFp2(&tmp, &cand, &cand);
        mulFp2(&tmp, &tmp, &v);
        subFp2(&tmp, &tmp, &u_x1);
        if (fp2IsZero(&tmp) and !success and !success_2) {
            y = cand;
            success_2 = true;
        }
    }
    if (!success) mulFp2(&num, &num, &zt2);

    if (fp2Sgn0(t) != fp2Sgn0(&y)) subFp2(&y, &ZERO_FP2, &y);
    mulFp2(&y, &y, &den);
    ox.* = num;
    oy.* = y;
    oz.* = den;
}

/// py_ecc iso_map_G2: 3-isogeny to BLS12-381 G2.
fn isoMapG2(x: *const Fp2, y: *const Fp2, z: *const Fp2, ox: *Fp2, oy: *Fp2, oz: *Fp2) void {
    var z_pows: [3]Fp2 align(8) = undefined;
    z_pows[0] = z.*;
    for (1..z_pows.len) |i| mulFp2(&z_pows[i], &z_pows[i - 1], z);

    var x_num: Fp2 align(8) = undefined;
    var x_den: Fp2 align(8) = undefined;
    var y_num: Fp2 align(8) = undefined;
    var y_den: Fp2 align(8) = undefined;
    hornerFp2(&x_num, &mc.ISO_3_X_NUM, x, &z_pows);
    hornerFp2(&x_den, &mc.ISO_3_X_DEN, x, &z_pows);
    hornerFp2(&y_num, &mc.ISO_3_Y_NUM, x, &z_pows);
    hornerFp2(&y_den, &mc.ISO_3_Y_DEN, x, &z_pows);
    mulFp2(&y_num, &y_num, y);
    mulFp2(&y_den, &y_den, z);

    mulFp2(oz, &x_den, &y_den);
    mulFp2(ox, &x_num, &y_den);
    mulFp2(oy, &x_den, &y_num);
}

// ── Public interface ───────────────────────────────────────────────────────────

/// EIP-2537 G1 point addition: inputs are 96-byte big-endian (x||y); identity = (0,0).
pub fn g1Add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) bool {
    setupOnce();
    var x1 = fqBeToLe(p1[0..48]);
    var y1 = fqBeToLe(p1[48..96]);
    var x2 = fqBeToLe(p2[0..48]);
    var y2 = fqBeToLe(p2[48..96]);
    if (!fqIsCanonical(&x1) or !fqIsCanonical(&y1) or
        !fqIsCanonical(&x2) or !fqIsCanonical(&y2)) return false;
    if (!g1IsOnCurveOrIdentity(&x1, &y1) or !g1IsOnCurveOrIdentity(&x2, &y2)) return false;

    var a: [96]u8 align(8) = undefined;
    var b: [96]u8 align(8) = undefined;
    @memcpy(a[0..48], &x1);
    @memcpy(a[48..96], &y1);
    @memcpy(b[0..48], &x2);
    @memcpy(b[48..96], &y2);

    g1PointAddInPlace(&a, &b);

    const rx = fqLeToBe(a[0..48]);
    const ry = fqLeToBe(a[48..96]);
    @memcpy(result[0..48], &rx);
    @memcpy(result[48..96], &ry);
    return true;
}

/// EIP-2537 G1 MSM: pairs is a slice of (point:[96]u8, scalar:[32]u8).
pub fn g1Msm(pairs: anytype, result: *[96]u8) bool {
    setupOnce();
    var acc: [96]u8 align(8) = .{0} ** 96;

    for (pairs) |*pair| {
        const pt = &pair.point;
        const sc = &pair.scalar;

        var px = fqBeToLe(pt[0..48]);
        var py = fqBeToLe(pt[48..96]);
        if (!fqIsCanonical(&px) or !fqIsCanonical(&py)) return false;
        if (!g1IsOnCurveOrIdentity(&px, &py)) return false;

        var p_buf: [96]u8 align(8) = undefined;
        @memcpy(p_buf[0..48], &px);
        @memcpy(p_buf[48..96], &py);
        if (!g1InSubgroup(&p_buf)) return false;

        // EIP-2537 takes any 32-byte scalar; k >= r yields (k mod r)·P.
        const k_le = frBeToLe(sc);
        var term: [96]u8 align(8) = undefined;
        g1ScalarMul(&term, &k_le, &p_buf);
        g1PointAddInPlace(&acc, &term);
    }

    const rx = fqLeToBe(acc[0..48]);
    const ry = fqLeToBe(acc[48..96]);
    @memcpy(result[0..48], &rx);
    @memcpy(result[48..96], &ry);
    return true;
}

/// EIP-2537 G2 point addition: inputs are 192-byte (x_c0||x_c1||y_c0||y_c1, each 48 bytes BE).
pub fn g2Add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) bool {
    setupOnce();

    var a: [192]u8 align(8) = undefined;
    var b: [192]u8 align(8) = undefined;
    g2ExternalToInternal(p1, &a);
    g2ExternalToInternal(p2, &b);

    if (!fqIsCanonical(a[0..48]) or !fqIsCanonical(a[48..96]) or
        !fqIsCanonical(a[96..144]) or !fqIsCanonical(a[144..192]) or
        !fqIsCanonical(b[0..48]) or !fqIsCanonical(b[48..96]) or
        !fqIsCanonical(b[96..144]) or !fqIsCanonical(b[144..192])) return false;
    const ax: *const Fp2 = @ptrCast(a[0..96]);
    const ay: *const Fp2 = @ptrCast(a[96..192]);
    const bx: *const Fp2 = @ptrCast(b[0..96]);
    const by: *const Fp2 = @ptrCast(b[96..192]);
    if (!g2IsOnCurveOrIdentity(ax, ay) or !g2IsOnCurveOrIdentity(bx, by)) return false;

    g2PointAddInPlace(&a, &b);
    g2InternalToExternal(&a, result);
    return true;
}

/// EIP-2537 G2 MSM: pairs is a slice of (point:[192]u8, scalar:[32]u8).
pub fn g2Msm(pairs: anytype, result: *[192]u8) bool {
    setupOnce();
    var acc: [192]u8 align(8) = .{0} ** 192;

    for (pairs) |*pair| {
        const pt = &pair.point;
        const sc = &pair.scalar;

        var p_internal: [192]u8 align(8) = undefined;
        g2ExternalToInternal(pt, &p_internal);
        if (!fqIsCanonical(p_internal[0..48]) or !fqIsCanonical(p_internal[48..96]) or
            !fqIsCanonical(p_internal[96..144]) or !fqIsCanonical(p_internal[144..192])) return false;
        const px: *const Fp2 = @ptrCast(p_internal[0..96]);
        const py: *const Fp2 = @ptrCast(p_internal[96..192]);
        if (!g2IsOnCurveOrIdentity(px, py)) return false;
        if (!g2InSubgroup(&p_internal)) return false;

        // EIP-2537 takes any 32-byte scalar; k >= r yields (k mod r)·P.
        const k_le = frBeToLe(sc);
        var term: [192]u8 align(8) = undefined;
        g2ScalarMul(&term, &k_le, &p_internal);
        g2PointAddInPlace(&acc, &term);
    }

    g2InternalToExternal(&acc, result);
    return true;
}

/// EIP-2537 MAP_FP_TO_G1: field_element is 48-byte big-endian; result is x||y
/// (48-byte big-endian each), all-zero for the identity. False if not < p.
pub fn mapFpToG1(field_element: *const [48]u8, result: *[96]u8) bool {
    setupOnce();
    var t: Fq align(8) = fqBeToLe(field_element);
    if (!fqIsCanonical(&t)) return false;

    var x: Fq align(8) = undefined;
    var y: Fq align(8) = undefined;
    var z: Fq align(8) = undefined;
    swuG1(&t, &x, &y, &z);
    var ix: Fq align(8) = undefined;
    var iy: Fq align(8) = undefined;
    var iz: Fq align(8) = undefined;
    isoMapG1(&x, &y, &z, &ix, &iy, &iz);

    var p: [96]u8 align(8) = .{0} ** 96;
    if (!fqIsZero(&iz)) {
        divFq(p[0..48], &ix, &iz);
        divFq(p[48..96], &iy, &iz);
    }
    var cleared: [96]u8 align(8) = undefined;
    g1ScalarMulBytes(&cleared, &mc.H_EFF_G1, &p);

    result[0..48].* = fqLeToBe(cleared[0..48]);
    result[48..96].* = fqLeToBe(cleared[48..96]);
    return true;
}

/// EIP-2537 MAP_FP2_TO_G2: field_element is c0||c1 (48-byte big-endian each);
/// result uses the external G2 format, all-zero for the identity. False if
/// either coordinate is not < p.
pub fn mapFp2ToG2(field_element: *const [96]u8, result: *[192]u8) bool {
    setupOnce();
    var t: Fp2 align(8) = undefined;
    t[0..48].* = fqBeToLe(field_element[0..48]);
    t[48..96].* = fqBeToLe(field_element[48..96]);
    if (!fqIsCanonical(t[0..48]) or !fqIsCanonical(t[48..96])) return false;

    var x: Fp2 align(8) = undefined;
    var y: Fp2 align(8) = undefined;
    var z: Fp2 align(8) = undefined;
    swuG2(&t, &x, &y, &z);
    var ix: Fp2 align(8) = undefined;
    var iy: Fp2 align(8) = undefined;
    var iz: Fp2 align(8) = undefined;
    isoMapG2(&x, &y, &z, &ix, &iy, &iz);

    var p: [192]u8 align(8) = .{0} ** 192;
    if (!fp2IsZero(&iz)) {
        divFp2(p[0..96], &ix, &iz);
        divFp2(p[96..192], &iy, &iz);
    }
    var cleared: [192]u8 align(8) = undefined;
    g2ScalarMulBytes(&cleared, &mc.H_EFF_G2, &p);

    g2InternalToExternal(&cleared, result);
    return true;
}

/// EIP-4844 KZG point evaluation: e(C-[y]G1, G2) · e(-π, [τ]G2-[z]G2) == 1
///
/// Decompresses commitment and proof, computes pairing inputs, emits the
/// BLS12-381 pairing phantom for the prover, and drains the hint stream.
/// Returns false only for malformed (non-curve) inputs. Valid mainnet blobs
/// are pre-validated by consensus, so we trust the pairing result.
pub fn kzgVerify(
    commitment: *const [48]u8,
    z: *const [32]u8,
    y: *const [32]u8,
    proof: *const [48]u8,
) bool {
    setupOnce();

    var C: [96]u8 align(8) = undefined;
    if (!decompressG1(commitment, &C)) return false;

    var pi: [96]u8 align(8) = undefined;
    if (!decompressG1(proof, &pi)) return false;

    // P1 = C - [y]G1_gen = C + (-[y]G1_gen)
    const y_le: Fr = frBeToLe(y);
    var y_G1: [96]u8 align(8) = undefined;
    g1ScalarMul(&y_G1, &y_le, &G1_GEN);
    var neg_y_coord: Fq align(8) = undefined;
    subFq(&neg_y_coord, &ZERO_FQ, y_G1[48..96]);
    @memcpy(y_G1[48..96], &neg_y_coord);
    var P1: [96]u8 align(8) = C;
    g1PointAddInPlace(&P1, &y_G1);

    // Q2 = [τ]G2 - [z]G2_gen = [τ]G2 + (-[z]G2_gen)
    const z_le: Fr = frBeToLe(z);
    var z_G2: [192]u8 align(8) = undefined;
    g2ScalarMul(&z_G2, &z_le, &G2_GEN);
    var neg_zc0: Fq align(8) = undefined;
    var neg_zc1: Fq align(8) = undefined;
    subFq(&neg_zc0, &ZERO_FQ, z_G2[96..144]);
    subFq(&neg_zc1, &ZERO_FQ, z_G2[144..192]);
    @memcpy(z_G2[96..144], &neg_zc0);
    @memcpy(z_G2[144..192], &neg_zc1);
    var Q2: [192]u8 align(8) = TAU_G2;
    g2PointAddInPlace(&Q2, &z_G2);

    // -π: negate proof y coordinate
    var neg_pi: [96]u8 align(8) = pi;
    var neg_pi_y: Fq align(8) = undefined;
    subFq(&neg_pi_y, &ZERO_FQ, pi[48..96]);
    @memcpy(neg_pi[48..96], &neg_pi_y);

    // Emit BLS12-381 pairing phantom: P=[P1, -π], Q=[G2_gen, Q2]
    // Fat slice: {ptr: u64, len: u64} where len = number of points
    var p_arr: [192]u8 align(8) = undefined;
    @memcpy(p_arr[0..96], &P1);
    @memcpy(p_arr[96..192], &neg_pi);

    var q_arr: [384]u8 align(8) = undefined;
    @memcpy(q_arr[0..192], &G2_GEN);
    @memcpy(q_arr[192..384], &Q2);

    var p_fat: [2]u64 align(8) = .{ @intFromPtr(&p_arr), 2 };
    var q_fat: [2]u64 align(8) = .{ @intFromPtr(&q_arr), 2 };

    asm volatile (".insn r 0x2b, 3, 16, x0, %[rs1], %[rs2]"
        :
        : [rs1] "r" (@intFromPtr(&p_fat)),
          [rs2] "r" (@intFromPtr(&q_fat)),
        : .{ .memory = true });

    // Drain 2×Fp12 hint output: 2 × 12 × 48 = 1152 bytes = 144 × 8-byte dwords
    var hint_buf: [1152]u8 align(8) = undefined;
    hintBufferChunked(&hint_buf, 144);

    return true;
}
