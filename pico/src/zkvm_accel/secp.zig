/// secp256k1 ecrecover / verify and secp256r1 verify on Pico's curve precompiles.
///
/// Public API (called from pico_accel.zig):
///   ecrecover(msg, sig, recid, output) bool      secp256k1; false = invalid input / no key
///   verifyK1(msg, sig, pubkey) bool              secp256k1 ECDSA verify
///   verifyR1(msg, sig, pubkey) bool              secp256r1 ECDSA verify
///   selfTest() bool                              guest-only differential test (see selftest.zig)
///
/// The ECDSA logic itself (and its native tests) lives in shared/src/secp.zig; this file
/// instantiates it with Pico's backends: pico_fp.zig field ops (FP_* / UINT256_MUL) and the
/// SECP256K1_* / SECP256R1_* affine point syscalls.
const std = @import("std");
const crypto = @import("zkvm_crypto");
const sys = @import("pico_sys");
const pico_fp = @import("pico_fp.zig");

const g = crypto.secp;
const field = crypto.field;
const ecdsa_soft = g.ecdsa_soft;
const Params = g.Params;
const Ecdsa = g.Ecdsa;
const k1_n = g.k1_n;
const r1_p = g.r1_p;
const r1_n = g.r1_n;
const k1_params = g.k1_params;
const r1_params = g.r1_params;
const Case = g.Case;
const Secp256k1 = g.Secp256k1;
const P256 = g.P256;
const fillRandom = g.fillRandom;
const signStd = g.signStd;
const randomCase = g.randomCase;
const scalarBE = g.scalarBE;

// ── affine point ops: Pico syscalls ──────────────────────────────────────────

const Codes = struct { add: usize, double: usize, decompress: usize };

fn HwPts(comptime FpB: type, comptime P: Params, comptime c: Codes) type {
    const Fp = field.Field(FpB);
    return struct {
        pub fn add(p: *[8]u64, q: *const [8]u64) void {
            sys.ecAdd(c.add, p, q);
        }

        pub fn double(p: *[8]u64) void {
            sys.ecDouble(c.double, p);
        }

        /// The decompress syscall aborts the VM when x is not on the curve, so check first
        /// (Euler's criterion on x³ + ax + b) and only then call it.
        pub fn decompress(x: [4]u64, odd: bool) ?[4]u64 {
            if (!Fp.isCanonical(x)) return null;
            const rhs = Fp.add(Fp.add(Fp.mul(Fp.sq(x), x), Fp.mul(P.a, x)), P.b);
            if (!Fp.eql(Fp.pow(rhs, &Fp.exp_p_minus_1_div_2), Fp.one)) return null;
            var buf: [8]u64 align(8) = undefined;
            buf[0..4].* = .{ 0, 0, 0, 0 }; // y (output)
            buf[4..8].* = x;
            sys.ecDecompress(c.decompress, &buf, odd);
            return buf[0..4].*;
        }
    };
}

const k1_codes = Codes{ .add = sys.SECP256K1_ADD, .double = sys.SECP256K1_DOUBLE, .decompress = sys.SECP256K1_DECOMPRESS };
const r1_codes = Codes{ .add = sys.SECP256R1_ADD, .double = sys.SECP256R1_DOUBLE, .decompress = sys.SECP256R1_DECOMPRESS };
const K1Hw = Ecdsa(pico_fp.Secp256k1Fq, pico_fp.UintMod(k1_n), HwPts(pico_fp.Secp256k1Fq, k1_params, k1_codes), k1_params);
const R1Hw = Ecdsa(pico_fp.UintMod(r1_p), pico_fp.UintMod(r1_n), HwPts(pico_fp.UintMod(r1_p), r1_params, r1_codes), r1_params);

// ── public API (guest) ───────────────────────────────────────────────────────

pub fn ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    return K1Hw.recover(msg, sig, recid, output);
}
pub fn verifyK1(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    return K1Hw.verify(msg, sig, pubkey);
}
pub fn verifyR1(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    return R1Hw.verify(msg, sig, pubkey);
}

// ── guest self-test ──────────────────────────────────────────────────────────

/// Guest-only: runs the Pico-syscall implementation on pseudo-random signatures (made with
/// std.crypto) and compares it with the std.crypto reference (ecdsa_soft.zig) and with fixed
/// known-answer vectors. Positive, mutated and edge cases; verify on both curves, recover on k1.
pub fn selfTest() bool {
    var ok = true;
    var st: u64 = 0xC0FFEE;

    // known answers
    {
        var msg: [32]u8 = undefined;
        var sig: [64]u8 = undefined;
        _ = std.fmt.hexToBytes(&msg, "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3") catch return false;
        _ = std.fmt.hexToBytes(sig[0..32], "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608") catch return false;
        _ = std.fmt.hexToBytes(sig[32..64], "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada") catch return false;
        var out: [64]u8 = undefined;
        var h: [32]u8 = undefined;
        var want: [20]u8 = undefined;
        _ = std.fmt.hexToBytes(&want, "7156526fbd7a3c72969b54f64e42c10fbb768c8a") catch return false;
        if (!ecrecover(&msg, &sig, 1, &out)) ok = false else {
            std.crypto.hash.sha3.Keccak256.hash(&out, &h, .{});
            if (!std.mem.eql(u8, &want, h[12..32])) ok = false;
            if (!verifyK1(&msg, &sig, &out)) ok = false;
        }
    }
    {
        var msg: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash("sample", &msg, .{});
        var sig: [64]u8 = undefined;
        var pk: [64]u8 = undefined;
        _ = std.fmt.hexToBytes(sig[0..32], "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716") catch return false;
        _ = std.fmt.hexToBytes(sig[32..64], "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8") catch return false;
        _ = std.fmt.hexToBytes(pk[0..32], "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6") catch return false;
        _ = std.fmt.hexToBytes(pk[32..64], "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299") catch return false;
        if (!verifyR1(&msg, &sig, &pk)) ok = false;
        sig[63] ^= 1;
        if (verifyR1(&msg, &sig, &pk)) ok = false;
    }

    // differential: syscall implementation vs std.crypto reference
    for (0..3) |round| {
        const ck = randomCase(Secp256k1, &st);
        var cases = [_]Case{ ck, ck, ck, ck, ck, ck };
        cases[1].msg[0] ^= 1; //                wrong message
        cases[2].sig[5] ^= 0x40; //             corrupted r
        cases[3].sig[40] ^= 0x08; //            corrupted s
        cases[4].recid ^= 1; //                 other parity
        cases[5].pubkey[63] ^= 1; //            off-curve key
        for (cases) |c| {
            if (ecdsa_soft.verifySecp256k1(&c.msg, &c.sig, &c.pubkey) != verifyK1(&c.msg, &c.sig, &c.pubkey)) ok = false;
            var o1: [64]u8 = undefined;
            var o2: [64]u8 = undefined;
            const a = ecdsa_soft.recoverSecp256k1(&c.msg, &c.sig, c.recid, &o1);
            const b = ecrecover(&c.msg, &c.sig, c.recid, &o2);
            if (a != b) ok = false else if (a and !std.mem.eql(u8, &o1, &o2)) ok = false;
        }
        // an x that is not on the curve must be rejected, not abort the VM
        var nc = ck;
        var xv: u64 = 5 + round;
        while (true) : (xv += 1) {
            nc.sig[0..32].* = scalarBE(xv);
            var o: [64]u8 = undefined;
            if (!ecdsa_soft.recoverSecp256k1(&nc.msg, &nc.sig, 0, &o)) break;
        }
        var o: [64]u8 = undefined;
        if (ecrecover(&nc.msg, &nc.sig, 0, &o)) ok = false;

        const cr = randomCase(P256, &st);
        var rc = [_]Case{ cr, cr, cr, cr };
        rc[1].msg[31] ^= 0x80;
        rc[2].sig[10] ^= 0x01;
        rc[3].pubkey[1] ^= 0x01;
        for (rc) |c| {
            if (ecdsa_soft.verifySecp256r1(&c.msg, &c.sig, &c.pubkey) != verifyR1(&c.msg, &c.sig, &c.pubkey)) ok = false;
        }
    }

    // degenerate keys: Q = G (d = 1) and Q = -G (d = n - 1), hash >= n
    {
        var n_minus_1: [32]u8 = undefined;
        for (0..4) |i| std.mem.writeInt(u64, n_minus_1[24 - 8 * i ..][0..8], k1_n[i], .big);
        n_minus_1[31] -= 1;
        var k: [32]u8 = undefined;
        fillRandom(&st, &k);
        k[0] &= 0x7f;
        for ([_][32]u8{ scalarBE(1), n_minus_1 }) |d| {
            for ([_][32]u8{ .{0xff} ** 32, .{0x11} ** 32 }) |m| {
                if (signStd(Secp256k1, d, k, m)) |c| {
                    if (!verifyK1(&c.msg, &c.sig, &c.pubkey)) ok = false;
                    var o: [64]u8 = undefined;
                    if (!ecrecover(&c.msg, &c.sig, c.recid, &o) or !std.mem.eql(u8, &o, &c.pubkey)) ok = false;
                }
            }
        }
    }
    return ok;
}
