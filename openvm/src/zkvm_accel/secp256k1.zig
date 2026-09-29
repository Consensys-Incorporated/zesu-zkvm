/// secp256k1 ecrecover for the OpenVM zkVM target.
///
/// Uses OpenVM custom-1 (opcode=0x2b) hardware accelerators:
///   - Modular arithmetic: AddMod, SubMod, MulMod, DivMod (funct3=0)
///   - ECC short Weierstrass: EC_ADD_NE, EC_DOUBLE (funct3=1)
///   - HintSqrt phantom: efficient field sqrt via hint stream
///
/// Instruction encoding (R-type, opcode=0x2b):
///   funct3=0, funct7 = mod_idx*8 + base_op
///     AddMod=0, SubMod=1, MulMod=2, DivMod=3, SetupMod=5, HintSqrt=7
///   funct3=1, funct7 = curve_idx*8 + base_op
///     EC_ADD_NE=0, EC_DOUBLE=1, EC_SETUP=2
///
/// Indices follow openvm's SdkVmConfig::standard(), the config eth-act/ere executes with:
///   mod_idx=2: secp256k1 field prime p
///   mod_idx=3: secp256k1 scalar order n
///   curve_idx=1: secp256k1
///
/// Point format: 64 bytes = x(32 LE bytes) || y(32 LE bytes), align(8).
/// All-zero = point at infinity.
const std = @import("std");

// ── secp256k1 constants (little-endian 256-bit) ───────────────────────────────

/// Field prime p = 2²⁵⁶ − 2³² − 977
const P_LE: Fe align(8) = .{
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// Curve order n
const N_LE: Fe align(8) = .{
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
    0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/// Generator x-coordinate (LE)
const GX_LE: Fe align(8) = .{
    0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59,
    0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
    0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55,
    0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79,
};

/// Generator y-coordinate (LE)
const GY_LE: Fe align(8) = .{
    0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c,
    0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd,
    0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d,
    0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48,
};

const ZERO: Fe align(8) = .{0} ** 32;
const ONE: Fe align(8) = .{1} ++ (.{0} ** 31);
const SEVEN: Fe align(8) = .{7} ++ (.{0} ** 31);

const G_BUF: [64]u8 align(8) = GX_LE ++ GY_LE;

// EC_SETUP p1 = [P_LE || curve_a] where a=0 for secp256k1
const EC_SETUP_P1: [64]u8 align(8) = P_LE ++ ZERO;
// EC_SETUP p2 = [1 || 1]: dummy points with x1-x2 != 0 for ADD_NE setup
const EC_SETUP_P2: [64]u8 align(8) = ONE ++ ONE;

// ── Type alias ────────────────────────────────────────────────────────────────

const Fe = [32]u8;

// ── Byte-order conversion ──────────────────────────────────────────────────────

fn beToLe(be: *const [32]u8) Fe {
    var le: Fe align(8) = undefined;
    for (0..32) |i| le[i] = be[31 - i];
    return le;
}

fn leToBe(le: *const [32]u8) [32]u8 {
    var be: [32]u8 = undefined;
    for (0..32) |i| be[i] = le[31 - i];
    return be;
}

// ── Field helpers ─────────────────────────────────────────────────────────────

fn feIsZero(a: *const Fe) bool {
    return std.mem.eql(u8, a, &ZERO);
}

/// LE 256-bit numeric less-than (compare from MSB = index 31).
fn feNumericLessThan(a: *const Fe, b: *const Fe) bool {
    var i: usize = 32;
    while (i > 0) {
        i -= 1;
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return false;
}

// ── Hint stream helpers (duplicated from zkvm_io to avoid cross-module deps) ──

inline fn hintStoreU64(ptr: *u64) void {
    asm volatile (".insn i 0x0b, 1, %[rd], x0, 0"
        :
        : [rd] "r" (@intFromPtr(ptr)),
        : .{ .memory = true });
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

// ── Setup ──────────────────────────────────────────────────────────────────────

var setup_done: bool = false;

fn setupOnce() void {
    if (setup_done) return;
    setup_done = true;

    // Uninit buffers for setup outputs (not used, just required by instruction)
    var uninit: [32]u8 align(8) = undefined;
    var ec_uninit: [128]u8 align(8) = undefined;

    const p_ptr: usize = @intFromPtr(&P_LE);
    const n_ptr: usize = @intFromPtr(&N_LE);
    const p1_ptr: usize = @intFromPtr(&EC_SETUP_P1);
    const p2_ptr: usize = @intFromPtr(&EC_SETUP_P2);

    // SETUP_ADDSUB for mod_idx=2 (p): funct7=21 (5+16), rs2=x0
    asm volatile (".insn r 0x2b, 0, 21, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (p_ptr),
        : .{ .memory = true });
    // SETUP_MULDIV for mod_idx=2 (p): funct7=21 (5+16), rs2=x1
    asm volatile (".insn r 0x2b, 0, 21, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (p_ptr),
        : .{ .memory = true });

    // SETUP_ADDSUB for mod_idx=3 (n): funct7=29 (5+24), rs2=x0
    asm volatile (".insn r 0x2b, 0, 29, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (n_ptr),
        : .{ .memory = true });
    // SETUP_MULDIV for mod_idx=3 (n): funct7=29 (5+24), rs2=x1
    asm volatile (".insn r 0x2b, 0, 29, %[rd], %[rs1], x1"
        :
        : [rd] "r" (@intFromPtr(&uninit)),
          [rs1] "r" (n_ptr),
        : .{ .memory = true });

    // SETUP_EC_ADD_NE for curve_idx=1 (secp256k1): funct7=10 (2+8), rs2=p2_ptr (!=0)
    asm volatile (".insn r 0x2b, 1, 10, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(&ec_uninit)),
          [rs1] "r" (p1_ptr),
          [rs2] "r" (p2_ptr),
        : .{ .memory = true });
    // SETUP_EC_DOUBLE for curve_idx=1 (secp256k1): funct7=10 (2+8), rs2=x0
    asm volatile (".insn r 0x2b, 1, 10, %[rd], %[rs1], x0"
        :
        : [rd] "r" (@intFromPtr(&ec_uninit)),
          [rs1] "r" (p1_ptr),
        : .{ .memory = true });
}

// ── Modular arithmetic (mod_idx=2, p) ─────────────────────────────────────────

inline fn addModP(out: *Fe, a: *const Fe, b: *const Fe) void {
    asm volatile (".insn r 0x2b, 0, 16, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn subModP(out: *Fe, a: *const Fe, b: *const Fe) void {
    asm volatile (".insn r 0x2b, 0, 17, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn mulModP(out: *Fe, a: *const Fe, b: *const Fe) void {
    asm volatile (".insn r 0x2b, 0, 18, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

// ── Modular arithmetic (mod_idx=3, n) ─────────────────────────────────────────

inline fn subModN(out: *Fe, a: *const Fe, b: *const Fe) void {
    // funct7 = 1 + 3*8 = 25
    asm volatile (".insn r 0x2b, 0, 25, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

inline fn divModN(out: *Fe, a: *const Fe, b: *const Fe) void {
    // funct7 = 3 + 3*8 = 27
    asm volatile (".insn r 0x2b, 0, 27, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(out)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

// ── HintSqrt ──────────────────────────────────────────────────────────────────

/// Compute sqrt(x) mod p using OpenVM's HintSqrt phantom (mod_idx=2).
/// Returns true if x is a quadratic residue; on success, out = sqrt(x) mod p.
/// Always reads 40 bytes from the hint stream (flag + sqrt) to keep it in sync.
fn fieldSqrtP(out: *Fe, x: *const Fe) bool {
    // HintSqrt phantom: funct7 = 7 + 2*8 = 23, rd=x0, rs2=x0
    asm volatile (".insn r 0x2b, 0, 23, x0, %[rs1], x0"
        :
        : [rs1] "r" (@intFromPtr(x)),
        : .{ .memory = true });

    // Read 8-byte success flag (first element = 1 if QR, 0 otherwise)
    var flag: u64 align(8) = 0;
    hintStoreU64(&flag);

    // Read 32-byte sqrt value — always consume to keep hint stream consistent
    hintBufferChunked(@ptrCast(out), 4);

    if (flag == 0) return false;

    // Verify out^2 == x mod p (guards against a dishonest prover in pure-exec mode)
    var sq: Fe align(8) = undefined;
    mulModP(&sq, out, out);
    return std.mem.eql(u8, &sq, x);
}

// ── Point operations ───────────────────────────────────────────────────────────

fn isInfinity(p: *const [64]u8) bool {
    const words: *const [8]u64 = @ptrCast(@alignCast(p));
    for (words) |w| if (w != 0) return false;
    return true;
}

/// In-place addition: a += b.  Handles identity, doubling, and negation cases.
fn pointAddInPlace(a: *[64]u8, b: *const [64]u8) void {
    if (isInfinity(a)) {
        @memcpy(a, b);
        return;
    }
    if (isInfinity(b)) return;

    if (std.mem.eql(u8, a[0..32], b[0..32])) {
        if (std.mem.eql(u8, a[32..64], b[32..64])) {
            // P == Q: double in-place (rd = rs1 = a)
            asm volatile (".insn r 0x2b, 1, 9, %[rd], %[rs1], x0"
                :
                : [rd] "r" (@intFromPtr(a)),
                  [rs1] "r" (@intFromPtr(a)),
                : .{ .memory = true });
        } else {
            @memset(a, 0); // P + (-P) = infinity
        }
        return;
    }
    // x-coordinates differ: add ne (rd = rs1 = a for in-place)
    asm volatile (".insn r 0x2b, 1, 8, %[rd], %[rs1], %[rs2]"
        :
        : [rd] "r" (@intFromPtr(a)),
          [rs1] "r" (@intFromPtr(a)),
          [rs2] "r" (@intFromPtr(b)),
        : .{ .memory = true });
}

/// Scalar multiply: result = k * p, LSB-first double-and-add.
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
            asm volatile (".insn r 0x2b, 1, 9, %[rd], %[rs1], x0"
                :
                : [rd] "r" (@intFromPtr(&cur)),
                  [rs1] "r" (@intFromPtr(&cur)),
                : .{ .memory = true });
        }
    }
}

// ── ecrecover ──────────────────────────────────────────────────────────────────

fn doRecover(msg_hash: [32]u8, sig: [64]u8, recid: u8) ?[64]u8 {
    if (recid > 3) return null;

    var r_le: Fe align(8) = beToLe(sig[0..32]);
    var s_le: Fe align(8) = beToLe(sig[32..64]);
    if (feIsZero(&r_le) or feIsZero(&s_le)) return null;
    if (!feNumericLessThan(&r_le, &N_LE) or !feNumericLessThan(&s_le, &N_LE)) return null;

    // z = hash mod n.  Hash is 256-bit; n > 2^255 so at most one subtraction needed.
    var z_le: Fe align(8) = beToLe(&msg_hash);
    if (!feNumericLessThan(&z_le, &N_LE)) {
        subModN(&z_le, &z_le, &N_LE);
    }

    // rx = r (recid bit 0) or r + n (recid bit 1, x overflow — extremely rare)
    var rx: Fe align(8) = r_le;
    if (recid & 2 != 0) {
        addModP(&rx, &r_le, &N_LE);
        if (feNumericLessThan(&rx, &r_le)) return null; // overflowed p
    }

    // y² = rx³ + 7 mod p
    var x2: Fe align(8) = undefined;
    var x3: Fe align(8) = undefined;
    var y2: Fe align(8) = undefined;
    mulModP(&x2, &rx, &rx);
    mulModP(&x3, &x2, &rx);
    addModP(&y2, &x3, &SEVEN);

    // y = sqrt(y²) mod p via HintSqrt
    var y: Fe align(8) = undefined;
    if (!fieldSqrtP(&y, &y2)) return null;

    // Select y parity to match recid bit 0
    if ((y[0] & 1) != (recid & 1)) subModP(&y, &P_LE, &y);

    // Build R point
    var R_buf: [64]u8 align(8) = undefined;
    @memcpy(R_buf[0..32], &rx);
    @memcpy(R_buf[32..64], &y);

    // k2 = s / r mod n,  k1 = -(z / r) mod n
    var k2: Fe align(8) = undefined;
    divModN(&k2, &s_le, &r_le);

    var k1: Fe align(8) = undefined;
    divModN(&k1, &z_le, &r_le);
    subModN(&k1, &ZERO, &k1); // negate: -z/r mod n

    // Q = k1*G + k2*R
    var Q: [64]u8 align(8) = undefined;
    var Q2: [64]u8 align(8) = undefined;
    scalarMul(&Q, &k1, &G_BUF);
    scalarMul(&Q2, &k2, &R_buf);
    pointAddInPlace(&Q, &Q2);

    if (isInfinity(&Q)) return null;

    // Convert Q to big-endian uncompressed x||y (no 0x04 prefix)
    var pubkey: [64]u8 = undefined;
    const qx = leToBe(Q[0..32]);
    const qy = leToBe(Q[32..64]);
    @memcpy(pubkey[0..32], &qx);
    @memcpy(pubkey[32..64], &qy);
    return pubkey;
}

// ── ECDSA verify ──────────────────────────────────────────────────────────────

fn doVerify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    // Parse and validate r, s in [1, n-1].
    var r_le: Fe align(8) = beToLe(sig[0..32]);
    var s_le: Fe align(8) = beToLe(sig[32..64]);
    if (feIsZero(&r_le) or feIsZero(&s_le)) return false;
    if (!feNumericLessThan(&r_le, &N_LE)) return false;
    if (!feNumericLessThan(&s_le, &N_LE)) return false;

    // Parse public key (big-endian x||y → little-endian).
    var pk_x: Fe align(8) = beToLe(pubkey[0..32]);
    var pk_y: Fe align(8) = beToLe(pubkey[32..64]);
    var PK_buf: [64]u8 align(8) = undefined;
    @memcpy(PK_buf[0..32], &pk_x);
    @memcpy(PK_buf[32..64], &pk_y);
    if (isInfinity(&PK_buf)) return false;

    // Validate pubkey on secp256k1: y² = x³ + 7 mod p.
    var y2: Fe align(8) = undefined;
    var x2: Fe align(8) = undefined;
    var x3: Fe align(8) = undefined;
    var rhs: Fe align(8) = undefined;
    mulModP(&y2, &pk_y, &pk_y);
    mulModP(&x2, &pk_x, &pk_x);
    mulModP(&x3, &x2, &pk_x);
    addModP(&rhs, &x3, &SEVEN);
    if (!std.mem.eql(u8, &y2, &rhs)) return false;

    // z = hash mod n (hash is 256-bit; n > 2^255 so one subtraction suffices).
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

    // r_check = Q.x mod n; valid iff r_check == r.
    var rx_le: Fe align(8) = Q[0..32].*;
    if (!feNumericLessThan(&rx_le, &N_LE)) {
        subModN(&rx_le, &rx_le, &N_LE);
    }
    return std.mem.eql(u8, &rx_le, &r_le);
}

// ── Public interface ───────────────────────────────────────────────────────────

/// Recover the 64-byte uncompressed secp256k1 public key from a recoverable
/// signature.  Returns true and writes x||y (big-endian, no 0x04) to `output`.
pub fn recoverPubkey(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    setupOnce();
    const pubkey = doRecover(msg.*, sig.*, recid) orelse return false;
    output.* = pubkey;
    return true;
}

/// Verify a compact secp256k1 ECDSA signature.
/// msg: 32-byte message hash (big-endian); sig: 64-byte r‖s (big-endian);
/// pubkey: 64-byte uncompressed x‖y (big-endian, no 0x04 prefix).
pub fn verifySignature(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    setupOnce();
    return doVerify(msg, sig, pubkey);
}
