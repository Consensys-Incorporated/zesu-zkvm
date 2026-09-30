/// secp256r1 (P-256) ECDSA signature verification for the OpenVM zkVM target.
///
/// Uses OpenVM custom-1 (opcode=0x2b) hardware accelerators:
///   - Modular arithmetic: AddMod, SubMod, MulMod, DivMod (funct3=0)
///   - ECC short Weierstrass: EC_ADD_NE, EC_DOUBLE (funct3=1)
///
/// Instruction encoding (R-type, opcode=0x2b):
///   funct3=0, funct7 = mod_idx*8 + base_op
///     AddMod=0, SubMod=1, MulMod=2, DivMod=3, Setup=5
///   funct3=1, funct7 = curve_idx*8 + base_op
///     EC_ADD_NE=0, EC_DOUBLE=1, EC_SETUP=2
///
/// Indices follow openvm's SdkVmConfig::standard(), the config eth-act/ere executes with:
///   mod_idx=0: BN254 p
///   mod_idx=1: BN254 r
///   mod_idx=2: secp256k1 p
///   mod_idx=3: secp256k1 n
///   mod_idx=4: P-256 p   ← this module
///   mod_idx=5: P-256 n   ← this module
///   curve_idx=0: BN254 G1
///   curve_idx=1: secp256k1
///   curve_idx=2: P-256   ← this module
///
/// Point format: 64 bytes = x(32 LE bytes) || y(32 LE bytes), align(8).
/// All-zero = point at infinity.
const std = @import("std");

// ── Type alias ────────────────────────────────────────────────────────────────

const Fe = [32]u8;

// ── P-256 constants (little-endian 256-bit) ───────────────────────────────────

// p = ffffffff00000001000000000000000000000000ffffffffffffffffffffffff (BE)
const P_LE: Fe align(8) = .{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

// n = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 (BE)
const N_LE: Fe align(8) = .{
    0x51, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3,
    0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

// a = p - 3 = fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc (LE)
const A_LE: Fe align(8) = .{
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

// b = 5ac635d8aa3a93e7b3ebbd5576988bc65 1d06b0cc53b0f63bce3c3e27d2604b (BE)
// stored LE: 4b60d2273e3cce3bf6b053ccb0061d65bc86987655bdebb3e7933aaad835c65a
const B_LE: Fe align(8) = .{
    0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b,
    0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d, 0x65,
    0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3,
    0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35, 0xc6, 0x5a,
};

// Generator x (LE): 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296 reversed
const GX_LE: Fe align(8) = .{
    0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4,
    0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
    0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8,
    0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b,
};

// Generator y (LE): 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 reversed
const GY_LE: Fe align(8) = .{
    0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb,
    0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b,
    0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e,
    0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f,
};

const ZERO: Fe align(8) = .{0} ** 32;
const ONE: Fe align(8) = .{1} ++ (.{0} ** 31);

const G_BUF: [64]u8 align(8) = GX_LE ++ GY_LE;

// EC_SETUP payload: [P_LE || A_LE]  (a = -3 for P-256, not zero)
const EC_SETUP_P1: [64]u8 align(8) = P_LE ++ A_LE;
const EC_SETUP_P2: [64]u8 align(8) = ONE ++ ONE;

// ── Byte-order conversion ──────────────────────────────────────────────────────

fn beToLe(be: *const [32]u8) Fe {
    var le: Fe align(8) = undefined;
    for (0..32) |i| le[i] = be[31 - i];
    return le;
}

// ── Field helpers ─────────────────────────────────────────────────────────────

fn feIsZero(a: *const Fe) bool {
    return std.mem.allEqual(u8, a, 0);
}

fn feNumericLessThan(a: *const Fe, b: *const Fe) bool {
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false;
}

// ── Setup ─────────────────────────────────────────────────────────────────────

var setup_done: bool = false;

fn setupOnce() void {
    if (setup_done) return;
    setup_done = true;

    var uninit: [32]u8 align(8) = undefined;
    var ec_uninit: [128]u8 align(8) = undefined;

    const p_ptr: usize = @intFromPtr(&P_LE);
    const n_ptr: usize = @intFromPtr(&N_LE);
    const p1_ptr: usize = @intFromPtr(&EC_SETUP_P1);
    const p2_ptr: usize = @intFromPtr(&EC_SETUP_P2);

    // SETUP_ADDSUB for mod_idx=4 (P-256 p): funct7 = 4*8+5 = 37, rs2=x0
    asm volatile (".insn r 0x2b, 0, 37, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (p_ptr),
        : .{ .memory = true });
    // SETUP_MULDIV for mod_idx=4 (P-256 p): funct7=37, rs2=x1
    asm volatile (".insn r 0x2b, 0, 37, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (p_ptr),
        : .{ .memory = true });

    // SETUP_ADDSUB for mod_idx=5 (P-256 n): funct7 = 5*8+5 = 45, rs2=x0
    asm volatile (".insn r 0x2b, 0, 45, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (n_ptr),
        : .{ .memory = true });
    // SETUP_MULDIV for mod_idx=5 (P-256 n): funct7=45, rs2=x1
    asm volatile (".insn r 0x2b, 0, 45, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (n_ptr),
        : .{ .memory = true });

    // SETUP_EC_ADD_NE for curve_idx=2 (P-256): funct7 = 2*8+2 = 18, rs2 != x0
    asm volatile (".insn r 0x2b, 1, 18, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(&ec_uninit)),
          [rs1] "r" (p1_ptr),
          [rs2] "r" (p2_ptr),
        : .{ .memory = true });
    // SETUP_EC_DOUBLE for curve_idx=2 (P-256): funct7=18, rs2=x0
    asm volatile (".insn r 0x2b, 1, 18, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&ec_uninit)),
          [rs1] "r" (p1_ptr),
        : .{ .memory = true });
}

// ── Modular arithmetic (mod_idx=4, P-256 p) ───────────────────────────────────

inline fn addModP(out: *Fe, a: *const Fe, b: *const Fe) void {
    // funct7 = 4*8+0 = 32
    asm volatile (".insn r 0x2b, 0, 32, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn mulModP(out: *Fe, a: *const Fe, b: *const Fe) void {
    // funct7 = 4*8+2 = 34
    asm volatile (".insn r 0x2b, 0, 34, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

// ── Modular arithmetic (mod_idx=5, P-256 n) ───────────────────────────────────

inline fn subModN(out: *Fe, a: *const Fe, b: *const Fe) void {
    // funct7 = 5*8+1 = 41
    asm volatile (".insn r 0x2b, 0, 41, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn divModN(out: *Fe, a: *const Fe, b: *const Fe) void {
    // funct7 = 5*8+3 = 43
    asm volatile (".insn r 0x2b, 0, 43, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

// ── Point operations (curve_idx=2) ────────────────────────────────────────────

fn isInfinity(p: *const [64]u8) bool {
    const words: *const [8]u64 = @ptrCast(@alignCast(p));
    for (words) |w| if (w != 0) return false;
    return true;
}

fn pointAddInPlace(a: *[64]u8, b: *const [64]u8) void {
    if (isInfinity(a)) {
        @memcpy(a, b);
        return;
    }
    if (isInfinity(b)) return;

    if (std.mem.eql(u8, a[0..32], b[0..32])) {
        if (std.mem.eql(u8, a[32..64], b[32..64])) {
            // EC_DOUBLE in-place; funct7 = 2*8+1 = 17
            asm volatile (".insn r 0x2b, 1, 17, %[rd], %[rs1], x0"
                :
                : [rd] "r" (@intFromPtr(a)),
                  [rs1] "r" (@intFromPtr(a)),
                : .{ .memory = true });
        } else {
            @memset(a, 0); // P + (-P) = infinity
        }
        return;
    }
    // EC_ADD_NE; funct7 = 2*8+0 = 16
    asm volatile (".insn r 0x2b, 1, 16, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(a)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

fn scalarMul(result: *[64]u8, k: *const Fe, p: *const [64]u8) void {
    @memset(result, 0);
    if (feIsZero(k)) return;
    var cur: [64]u8 align(8) = p.*;
    for (0..256) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((k[byte_idx] >> bit_idx) & 1 == 1) {
            pointAddInPlace(result, &cur);
        }
        if (!isInfinity(&cur)) {
            // EC_DOUBLE; funct7=17
            asm volatile (".insn r 0x2b, 1, 17, %[rd], %[rs1], x0"
                :
                : [rd] "r" (@intFromPtr(&cur)),
                  [rs1] "r" (@intFromPtr(&cur)),
                : .{ .memory = true });
        }
    }
}

// ── ECDSA verify ──────────────────────────────────────────────────────────────

fn doVerify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    var r_le: Fe align(8) = beToLe(sig[0..32]);
    var s_le: Fe align(8) = beToLe(sig[32..64]);
    if (feIsZero(&r_le) or feIsZero(&s_le)) return false;
    if (!feNumericLessThan(&r_le, &N_LE)) return false;
    if (!feNumericLessThan(&s_le, &N_LE)) return false;

    var pk_x: Fe align(8) = beToLe(pubkey[0..32]);
    var pk_y: Fe align(8) = beToLe(pubkey[32..64]);
    var PK_buf: [64]u8 align(8) = undefined;
    @memcpy(PK_buf[0..32], &pk_x);
    @memcpy(PK_buf[32..64], &pk_y);
    if (isInfinity(&PK_buf)) return false;

    // On-curve check: y² = x³ + ax + b mod p  (a = -3 for P-256)
    var y2: Fe align(8) = undefined;
    var x2: Fe align(8) = undefined;
    var x3: Fe align(8) = undefined;
    var ax: Fe align(8) = undefined;
    var rhs: Fe align(8) = undefined;
    mulModP(&y2, &pk_y, &pk_y);
    mulModP(&x2, &pk_x, &pk_x);
    mulModP(&x3, &x2, &pk_x);
    mulModP(&ax, &A_LE, &pk_x);
    addModP(&rhs, &x3, &ax);
    addModP(&rhs, &rhs, &B_LE);
    if (!std.mem.eql(u8, &y2, &rhs)) return false;

    // z = hash mod n (P-256: n < p so the hash may exceed n).
    var z_le: Fe align(8) = beToLe(msg);
    if (!feNumericLessThan(&z_le, &N_LE)) {
        subModN(&z_le, &z_le, &N_LE);
    }

    // sv1 = z / s mod n,  sv2 = r / s mod n.
    var sv1: Fe align(8) = undefined;
    var sv2: Fe align(8) = undefined;
    divModN(&sv1, &z_le, &s_le);
    divModN(&sv2, &r_le, &s_le);

    // Q = sv1*G + sv2*PK.
    var Q: [64]u8 align(8) = undefined;
    var Q2: [64]u8 align(8) = undefined;
    scalarMul(&Q, &sv1, &G_BUF);
    scalarMul(&Q2, &sv2, &PK_buf);
    pointAddInPlace(&Q, &Q2);
    if (isInfinity(&Q)) return false;

    // Valid iff Q.x mod n == r.
    var rx_le: Fe align(8) = Q[0..32].*;
    if (!feNumericLessThan(&rx_le, &N_LE)) {
        subModN(&rx_le, &rx_le, &N_LE);
    }
    return std.mem.eql(u8, &rx_le, &r_le);
}

// ── Public interface ───────────────────────────────────────────────────────────

/// Verify a compact secp256r1 (P-256) ECDSA signature.
/// msg: 32-byte message hash (big-endian); sig: 64-byte r‖s (big-endian);
/// pubkey: 64-byte uncompressed x‖y (big-endian, no 0x04 prefix).
pub fn verifySignature(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    setupOnce();
    return doVerify(msg, sig, pubkey);
}
