/// secp256k1 / secp256r1 ECDSA verify and secp256k1 public-key recovery, generic over the field
/// and point backends, plus the native tests and the std.crypto-based test-vector generator.
///
/// Semantics (identical to ecdsa_soft.zig, the std.crypto reference):
///   - r and s must be canonical scalars in [1, n-1]; high-s is accepted; verify is plain ECDSA.
///   - the public key is 64-byte big-endian x‖y, coordinates < p, and must be on the curve.
///   - msg is reduced mod n (it is a full 32-byte hash, not truncated).
///   - recid 0/1 select the parity of R.y; recid 2/3 (x >= n) are rejected.
///
/// `Ecdsa(FpB, FnB, Pts, Params)` is generic over three backends:
///   FpB   base field backend       FnB   scalar field backend       Pts   affine point ops
/// Natively (`zig test`) they are soft.zig field arithmetic and the software point ops below. A
/// zkVM target instantiates it with its own accelerated backends (Pico: pico_fp.zig field ops and
/// the SECP256K1_* / SECP256R1_* point syscalls, see pico/src/zkvm_accel/secp.zig).
/// Pico's point syscalls do plain affine P+Q: they abort the VM for P == Q and return garbage
/// for P == -Q or the identity, so this file does all of that case analysis itself.
const std = @import("std");
pub const field = @import("field.zig");
pub const soft = @import("soft.zig");
pub const ecdsa_soft = @import("ecdsa_soft.zig");

// ── curve parameters ─────────────────────────────────────────────────────────

fn hex4(comptime s: *const [64]u8) [4]u64 {
    @setEvalBranchQuota(100_000);
    var r: [4]u64 = undefined;
    for (0..4) |i| {
        const chunk = s[(3 - i) * 16 ..][0..16];
        r[i] = std.fmt.parseInt(u64, chunk, 16) catch unreachable;
    }
    return r;
}

pub const Params = struct { a: [4]u64, b: [4]u64, gx: [4]u64, gy: [4]u64 };

pub const k1_p = hex4("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
pub const k1_n = hex4("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
pub const k1_params = Params{
    .a = .{ 0, 0, 0, 0 },
    .b = .{ 7, 0, 0, 0 },
    .gx = hex4("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    .gy = hex4("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
};

pub const r1_p = hex4("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
pub const r1_n = hex4("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
pub const r1_params = Params{
    .a = hex4("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"), // p - 3
    .b = hex4("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    .gx = hex4("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
    .gy = hex4("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
};

// ── affine point ops: software (native tests) ────────────────────────────────

/// Software affine add/double/decompress with the same contract as the zkVM point syscalls, on
/// std.crypto's fast field type (native tests only; the guest never instantiates this).
fn SoftPts(comptime Curve: type, comptime P: Params) type {
    const StdFe = Curve.Fe;
    const conv = struct {
        fn to(l: [4]u64) StdFe {
            var b: [32]u8 = undefined;
            for (0..4) |i| std.mem.writeInt(u64, b[8 * i ..][0..8], l[i], .little);
            return StdFe.fromBytes(b, .little) catch unreachable; // callers pass canonical values
        }
        fn from(f: StdFe) [4]u64 {
            const b = f.toBytes(.little);
            var l: [4]u64 = undefined;
            for (0..4) |i| l[i] = std.mem.readInt(u64, b[8 * i ..][0..8], .little);
            return l;
        }
    };
    return struct {
        pub fn add(p: *[8]u64, q: *const [8]u64) void {
            const px = conv.to(p[0..4].*);
            const py = conv.to(p[4..8].*);
            const qx = conv.to(q[0..4].*);
            const qy = conv.to(q[4..8].*);
            std.debug.assert(!px.equivalent(qx)); // the caller handles equal / opposite points
            const lambda = qy.sub(py).mul(qx.sub(px).invert());
            const x3 = lambda.sq().sub(px).sub(qx);
            const y3 = lambda.mul(px.sub(x3)).sub(py);
            p[0..4].* = conv.from(x3);
            p[4..8].* = conv.from(y3);
        }

        pub fn double(p: *[8]u64) void {
            const x = conv.to(p[0..4].*);
            const y = conv.to(p[4..8].*);
            const x2 = x.sq();
            const num = x2.dbl().add(x2).add(conv.to(P.a)); // 3x² + a
            const lambda = num.mul(y.dbl().invert());
            const x3 = lambda.sq().sub(x.dbl());
            const y3 = lambda.mul(x.sub(x3)).sub(y);
            p[0..4].* = conv.from(x3);
            p[4..8].* = conv.from(y3);
        }

        /// y with the requested parity such that (x, y) is on the curve; null if x is not.
        pub fn decompress(xl: [4]u64, odd: bool) ?[4]u64 {
            var b: [32]u8 = undefined;
            for (0..4) |i| std.mem.writeInt(u64, b[8 * i ..][0..8], xl[i], .little);
            const x = StdFe.fromBytes(b, .little) catch return null; // x >= p
            const rhs = x.sq().mul(x).add(conv.to(P.a).mul(x)).add(conv.to(P.b));
            const y = rhs.sqrt() catch return null;
            return conv.from(if (y.isOdd() == odd) y else y.neg());
        }
    };
}

// ── generic ECDSA ────────────────────────────────────────────────────────────

pub fn Ecdsa(comptime FpB: type, comptime FnB: type, comptime Pts: type, comptime P: Params) type {
    return struct {
        const Fp = field.Field(FpB);
        const Fn = field.Field(FnB);
        const Fe = [4]u64;

        const Pt = struct {
            xy: [8]u64 align(8),
            inf: bool,

            fn x(self: *const Pt) Fe {
                return self.xy[0..4].*;
            }
            fn y(self: *const Pt) Fe {
                return self.xy[4..8].*;
            }
            fn make(px: Fe, py: Fe) Pt {
                var r: Pt = .{ .xy = undefined, .inf = false };
                r.xy[0..4].* = px;
                r.xy[4..8].* = py;
                return r;
            }
        };
        const identity = Pt{ .xy = .{0} ** 8, .inf = true };

        fn dbl(a: Pt) Pt {
            if (a.inf or Fp.isZero(a.y())) return identity;
            var r = a;
            Pts.double(&r.xy);
            return r;
        }

        fn addPts(a: Pt, b: Pt) Pt {
            if (a.inf) return b;
            if (b.inf) return a;
            if (Fp.eql(a.x(), b.x())) {
                if (Fp.eql(a.y(), b.y())) return dbl(a);
                return identity; // a == -b
            }
            var r = a;
            Pts.add(&r.xy, &b.xy);
            return r;
        }

        fn bit(k: Fe, i: usize) bool {
            return (k[i / 64] >> @intCast(i % 64)) & 1 == 1;
        }

        /// k1*p1 + k2*p2 (Shamir's trick). All point-at-infinity / equal-point cases go through
        /// addPts, so p1 == ±p2 and partial sums hitting ±p are handled.
        fn mulDouble(k1: Fe, p1: Pt, k2: Fe, p2: Pt) Pt {
            const both = addPts(p1, p2);
            var acc = identity;
            var i: usize = 256;
            while (i > 0) {
                i -= 1;
                acc = dbl(acc);
                const b1 = bit(k1, i);
                const b2 = bit(k2, i);
                if (b1 and b2) {
                    acc = addPts(acc, both);
                } else if (b1) {
                    acc = addPts(acc, p1);
                } else if (b2) {
                    acc = addPts(acc, p2);
                }
            }
            return acc;
        }

        fn onCurve(x: Fe, y: Fe) bool {
            if (!Fp.isCanonical(x) or !Fp.isCanonical(y)) return false;
            const rhs = Fp.add(Fp.add(Fp.mul(Fp.sq(x), x), Fp.mul(P.a, x)), P.b);
            return Fp.eql(Fp.sq(y), rhs);
        }

        /// x mod n for x < 2n (true for any 256-bit hash and for any x < p).
        fn reduceOnce(x: Fe) Fe {
            if (Fn.cmp(x, Fn.modulus) == .lt) return x;
            var r: Fe = undefined;
            var borrow: u1 = 0;
            for (0..4) |i| {
                const d1 = @subWithOverflow(x[i], Fn.modulus[i]);
                const d2 = @subWithOverflow(d1[0], @as(u64, borrow));
                r[i] = d2[0];
                borrow = d1[1] | d2[1];
            }
            return r;
        }

        /// A canonical scalar in [1, n-1].
        fn scalarFromBytes(b: *const [32]u8) ?Fe {
            const s = Fn.fromBytesBE(b);
            if (!Fn.isCanonical(s) or Fn.isZero(s)) return null;
            return s;
        }

        const generator = Pt.make(P.gx, P.gy);

        pub fn verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
            const r = scalarFromBytes(sig[0..32]) orelse return false;
            const s = scalarFromBytes(sig[32..64]) orelse return false;
            const qx = Fp.fromBytesBE(pubkey[0..32]);
            const qy = Fp.fromBytesBE(pubkey[32..64]);
            if (!onCurve(qx, qy)) return false;

            const z = reduceOnce(Fn.fromBytesBE(msg));
            const w = Fn.inv(s);
            const k1 = Fn.mul(z, w);
            const k2 = Fn.mul(r, w);
            const pt = mulDouble(k1, generator, k2, Pt.make(qx, qy));
            if (pt.inf) return false;
            return Fn.eql(reduceOnce(pt.x()), r);
        }

        pub fn recover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
            if (recid > 1) return false;
            const r = scalarFromBytes(sig[0..32]) orelse return false;
            const s = scalarFromBytes(sig[32..64]) orelse return false;
            // x = r (r < n < p); R is the point with that x and the parity selected by recid.
            const ry = Pts.decompress(r, recid == 1) orelse return false;

            const z = reduceOnce(Fn.fromBytesBE(msg));
            const rinv = Fn.inv(r);
            const k1 = Fn.mul(Fn.neg(z), rinv);
            const k2 = Fn.mul(s, rinv);
            const pt = mulDouble(k1, generator, k2, Pt.make(r, ry));
            if (pt.inf) return false;
            output[0..32].* = Fp.toBytesBE(pt.x());
            output[32..64].* = Fp.toBytesBE(pt.y());
            return true;
        }
    };
}

const K1Soft = Ecdsa(soft.Soft(4, k1_p), soft.Soft(4, k1_n), SoftPts(std.crypto.ecc.Secp256k1, k1_params), k1_params);
const R1Soft = Ecdsa(soft.Soft(4, r1_p), soft.Soft(4, r1_n), SoftPts(std.crypto.ecc.P256, r1_params), r1_params);

// ── test-vector generation (std.crypto, independent of the code above) ────────

pub const Case = struct {
    msg: [32]u8,
    sig: [64]u8,
    recid: u8,
    pubkey: [64]u8,
};

fn splitmix(state: *u64) u64 {
    state.* +%= 0x9E3779B97F4A7C15;
    var z = state.*;
    z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
    return z ^ (z >> 31);
}

pub fn fillRandom(state: *u64, buf: []u8) void {
    var i: usize = 0;
    while (i < buf.len) : (i += 8) {
        var w = splitmix(state);
        for (0..@min(8, buf.len - i)) |j| {
            buf[i + j] = @truncate(w);
            w >>= 8;
        }
    }
}

/// Sign `msg` with private key `d` and nonce `k` using std's curve and scalar arithmetic.
pub fn signStd(comptime Curve: type, d_be: [32]u8, k_be: [32]u8, msg: [32]u8) ?Case {
    const Scalar = Curve.scalar.Scalar;
    const d = Scalar.fromBytes(d_be, .big) catch return null;
    const k = Scalar.fromBytes(k_be, .big) catch return null;
    if (d.isZero() or k.isZero()) return null;
    const rp = Curve.basePoint.mul(k_be, .big) catch return null;
    const ra = rp.affineCoordinates();
    var wide: [64]u8 = .{0} ** 64;
    wide[32..].* = ra.x.toBytes(.big);
    const r = Scalar.fromBytes64(wide, .big);
    if (r.isZero()) return null;
    wide = .{0} ** 64;
    wide[32..].* = msg;
    const z = Scalar.fromBytes64(wide, .big);
    const s = k.invert().mul(z.add(r.mul(d)));
    if (s.isZero()) return null;
    const qp = Curve.basePoint.mul(d_be, .big) catch return null;
    const qa = qp.affineCoordinates();
    var c: Case = undefined;
    c.msg = msg;
    c.sig[0..32].* = r.toBytes(.big);
    c.sig[32..64].* = s.toBytes(.big);
    c.recid = @intFromBool(ra.y.isOdd());
    c.pubkey[0..32].* = qa.x.toBytes(.big);
    c.pubkey[32..64].* = qa.y.toBytes(.big);
    return c;
}

/// Pseudo-random valid case for `Curve` (retries on the rare degenerate draw).
pub fn randomCase(comptime Curve: type, state: *u64) Case {
    while (true) {
        var d: [32]u8 = undefined;
        var k: [32]u8 = undefined;
        var m: [32]u8 = undefined;
        fillRandom(state, &d);
        fillRandom(state, &k);
        fillRandom(state, &m);
        if (signStd(Curve, d, k, m)) |c| return c;
    }
}

// ── native tests ─────────────────────────────────────────────────────────────

pub const Secp256k1 = std.crypto.ecc.Secp256k1;
pub const P256 = std.crypto.ecc.P256;

pub fn scalarBE(v: u64) [32]u8 {
    var b: [32]u8 = .{0} ** 32;
    std.mem.writeInt(u64, b[24..32], v, .big);
    return b;
}

/// Check one case against the std-based reference, for verify (both curves) and recover (k1).
fn expectSameK1(c: Case) !void {
    const want_v = ecdsa_soft.verifySecp256k1(&c.msg, &c.sig, &c.pubkey);
    try std.testing.expectEqual(want_v, K1Soft.verify(&c.msg, &c.sig, &c.pubkey));
    var o1: [64]u8 = undefined;
    var o2: [64]u8 = undefined;
    const want_r = ecdsa_soft.recoverSecp256k1(&c.msg, &c.sig, c.recid, &o1);
    const got_r = K1Soft.recover(&c.msg, &c.sig, c.recid, &o2);
    try std.testing.expectEqual(want_r, got_r);
    if (want_r) try std.testing.expectEqualSlices(u8, &o1, &o2);
}

fn expectSameR1(c: Case) !void {
    try std.testing.expectEqual(
        ecdsa_soft.verifySecp256r1(&c.msg, &c.sig, &c.pubkey),
        R1Soft.verify(&c.msg, &c.sig, &c.pubkey),
    );
}

test "secp256k1: valid signatures verify and recover to the signer" {
    var st: u64 = 1;
    for (0..2) |_| {
        const c = randomCase(Secp256k1, &st);
        try std.testing.expect(K1Soft.verify(&c.msg, &c.sig, &c.pubkey));
        var out: [64]u8 = undefined;
        try std.testing.expect(K1Soft.recover(&c.msg, &c.sig, c.recid, &out));
        try std.testing.expectEqualSlices(u8, &c.pubkey, &out);
    }
}

test "secp256r1: valid signatures verify" {
    var st: u64 = 2;
    for (0..2) |_| {
        const c = randomCase(P256, &st);
        try std.testing.expect(R1Soft.verify(&c.msg, &c.sig, &c.pubkey));
    }
}

test "secp256k1: negative cases agree with the reference" {
    var st: u64 = 3;
    const c = randomCase(Secp256k1, &st);
    // wrong message
    var bad = c;
    bad.msg[0] ^= 1;
    try expectSameK1(bad);
    try std.testing.expect(!K1Soft.verify(&bad.msg, &bad.sig, &bad.pubkey));
    // flipped recid recovers a different key (still a valid point) and does not verify as signer
    var flip = c;
    flip.recid ^= 1;
    try expectSameK1(flip);
    var out: [64]u8 = undefined;
    try std.testing.expect(K1Soft.recover(&flip.msg, &flip.sig, flip.recid, &out));
    try std.testing.expect(!std.mem.eql(u8, &out, &c.pubkey));
    // recid 2 / 3 rejected
    try std.testing.expect(!K1Soft.recover(&c.msg, &c.sig, 2, &out));
    try std.testing.expect(!K1Soft.recover(&c.msg, &c.sig, 3, &out));
    // r = 0, s = 0, r >= n, s >= n
    var z = c;
    z.sig[0..32].* = .{0} ** 32;
    try expectSameK1(z);
    try std.testing.expect(!K1Soft.verify(&z.msg, &z.sig, &z.pubkey));
    try std.testing.expect(!K1Soft.recover(&z.msg, &z.sig, z.recid, &out));
    z = c;
    z.sig[32..64].* = .{0} ** 32;
    try expectSameK1(z);
    try std.testing.expect(!K1Soft.verify(&z.msg, &z.sig, &z.pubkey));
    var n_be: [32]u8 = undefined;
    for (0..4) |i| std.mem.writeInt(u64, n_be[24 - 8 * i ..][0..8], k1_n[i], .big);
    z = c;
    z.sig[0..32].* = n_be; // r == n
    try expectSameK1(z);
    try std.testing.expect(!K1Soft.verify(&z.msg, &z.sig, &z.pubkey));
    try std.testing.expect(!K1Soft.recover(&z.msg, &z.sig, z.recid, &out));
    z = c;
    z.sig[32..64].* = .{0xff} ** 32; // s > n
    try expectSameK1(z);
    try std.testing.expect(!K1Soft.verify(&z.msg, &z.sig, &z.pubkey));
    // off-curve and non-canonical public keys
    var oc = c;
    oc.pubkey[63] ^= 1;
    try expectSameK1(oc);
    try std.testing.expect(!K1Soft.verify(&oc.msg, &oc.sig, &oc.pubkey));
    oc = c;
    oc.pubkey = .{0} ** 64; // identity encoding
    try std.testing.expect(!K1Soft.verify(&oc.msg, &oc.sig, &oc.pubkey));
    oc = c;
    oc.pubkey[0..32].* = .{0xff} ** 32; // x >= p
    try std.testing.expect(!K1Soft.verify(&oc.msg, &oc.sig, &oc.pubkey));
    // r with no curve point (x not on the curve): scan until the reference rejects it
    var found = false;
    var rv: u64 = 5;
    while (rv < 200 and !found) : (rv += 1) {
        var t = c;
        t.sig[0..32].* = scalarBE(rv);
        const ref_ok = ecdsa_soft.recoverSecp256k1(&t.msg, &t.sig, 0, &out);
        try expectSameK1(t);
        if (!ref_ok) found = true;
    }
    try std.testing.expect(found);
}

test "secp256r1: negative cases agree with the reference" {
    var st: u64 = 4;
    const c = randomCase(P256, &st);
    var bad = c;
    bad.msg[31] ^= 0x80;
    try expectSameR1(bad);
    try std.testing.expect(!R1Soft.verify(&bad.msg, &bad.sig, &bad.pubkey));
    var z = c;
    z.sig[0..32].* = .{0} ** 32;
    try expectSameR1(z);
    try std.testing.expect(!R1Soft.verify(&z.msg, &z.sig, &z.pubkey));
    z = c;
    z.sig[32..64].* = .{0xff} ** 32;
    try std.testing.expect(!R1Soft.verify(&z.msg, &z.sig, &z.pubkey));
    var oc = c;
    oc.pubkey[63] ^= 1;
    try expectSameR1(oc);
    try std.testing.expect(!R1Soft.verify(&oc.msg, &oc.sig, &oc.pubkey));
    oc = c;
    oc.pubkey = .{0} ** 64;
    try std.testing.expect(!R1Soft.verify(&oc.msg, &oc.sig, &oc.pubkey));
}

fn msgBE(m: [32]u8) [32]u8 {
    return m;
}

test "edge cases: hash >= n, hash = 0, and keys that make the double-mul degenerate" {
    var st: u64 = 5;
    // msg = 0xff..ff (>= n) and msg = 0
    inline for (.{ Secp256k1, P256 }) |Curve| {
        for ([_][32]u8{ .{0xff} ** 32, .{0} ** 32 }) |m| {
            var d: [32]u8 = undefined;
            var k: [32]u8 = undefined;
            fillRandom(&st, &d);
            fillRandom(&st, &k);
            d[0] &= 0x7f;
            k[0] &= 0x7f;
            if (signStd(Curve, d, k, m)) |c| {
                if (Curve == Secp256k1) {
                    try std.testing.expect(K1Soft.verify(&c.msg, &c.sig, &c.pubkey));
                    try expectSameK1(c);
                } else {
                    try std.testing.expect(R1Soft.verify(&c.msg, &c.sig, &c.pubkey));
                }
            }
        }
    }
    // d = 1 (Q == G: the Shamir table entry G+Q is a doubling) and d = n-1 (Q == -G: G+Q is the
    // identity, and partial sums hit the identity).
    var n_minus_1: [32]u8 = undefined;
    for (0..4) |i| std.mem.writeInt(u64, n_minus_1[24 - 8 * i ..][0..8], k1_n[i], .big);
    n_minus_1[31] -= 1;
    var m: [32]u8 = undefined;
    var k: [32]u8 = undefined;
    for (0..3) |_| {
        fillRandom(&st, &m);
        fillRandom(&st, &k);
        k[0] &= 0x7f;
        for ([_][32]u8{ scalarBE(1), n_minus_1, scalarBE(2) }) |d| {
            if (signStd(Secp256k1, d, k, m)) |c| {
                try std.testing.expect(K1Soft.verify(&c.msg, &c.sig, &c.pubkey));
                try expectSameK1(c);
            }
        }
    }
    // same for P-256 (n-1 for its own order)
    var r1_n_minus_1: [32]u8 = undefined;
    for (0..4) |i| std.mem.writeInt(u64, r1_n_minus_1[24 - 8 * i ..][0..8], r1_n[i], .big);
    r1_n_minus_1[31] -= 1;
    fillRandom(&st, &m);
    fillRandom(&st, &k);
    k[0] &= 0x7f;
    for ([_][32]u8{ scalarBE(1), r1_n_minus_1 }) |d| {
        if (signStd(P256, d, k, m)) |c| {
            try std.testing.expect(R1Soft.verify(&c.msg, &c.sig, &c.pubkey));
        }
    }
}

test "mulDouble handles identity partial sums: k1*G + k2*(-G) with k1 == k2" {
    const G = K1Soft.generator;
    var negG = G;
    negG.xy[4..8].* = K1Soft.Fp.neg(G.y());
    const k = [4]u64{ 12345, 6789, 0, 1 };
    const r = K1Soft.mulDouble(k, G, k, negG);
    try std.testing.expect(r.inf);
    // k1*G + k2*G == (k1+k2)*G
    const a = [4]u64{ 3, 0, 0, 0 };
    const b = [4]u64{ 5, 0, 0, 0 };
    const s = K1Soft.mulDouble(a, G, b, G);
    const eight = K1Soft.mulDouble(.{ 8, 0, 0, 0 }, G, .{ 0, 0, 0, 0 }, G);
    try std.testing.expect(!s.inf);
    try std.testing.expectEqual(eight.xy, s.xy);
}

test "known answer: the classic Ethereum ecrecover vector" {
    // hash / v=28 / r / s from the widely used web3 ecrecover example; the recovered address is
    // 0x7156526fbd7a3c72969b54f64e42c10fbb768c8a.
    var msg: [32]u8 = undefined;
    var sig: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&msg, "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3");
    _ = try std.fmt.hexToBytes(sig[0..32], "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608");
    _ = try std.fmt.hexToBytes(sig[32..64], "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada");
    var out: [64]u8 = undefined;
    try std.testing.expect(K1Soft.recover(&msg, &sig, 1, &out));
    var h: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&out, &h, .{});
    var want: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "7156526fbd7a3c72969b54f64e42c10fbb768c8a");
    try std.testing.expectEqualSlices(u8, &want, h[12..32]);
    try std.testing.expect(K1Soft.verify(&msg, &sig, &out));
}

test "known answer: RFC 6979 P-256 / SHA-256 / \"sample\"" {
    var msg: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("sample", &msg, .{});
    var sig: [64]u8 = undefined;
    var pk: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(sig[0..32], "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    _ = try std.fmt.hexToBytes(sig[32..64], "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
    _ = try std.fmt.hexToBytes(pk[0..32], "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6");
    _ = try std.fmt.hexToBytes(pk[32..64], "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299");
    try std.testing.expect(R1Soft.verify(&msg, &sig, &pk));
    sig[63] ^= 1;
    try std.testing.expect(!R1Soft.verify(&msg, &sig, &pk));
}

test "many random signatures: software ECDSA agrees with std.crypto reference" {
    var st: u64 = 99;
    for (0..3) |i| {
        const ck = randomCase(Secp256k1, &st);
        try expectSameK1(ck);
        var m = ck;
        m.sig[(i * 7) % 64] ^= 0x10; // corrupt r or s
        try expectSameK1(m);
        const cr = randomCase(P256, &st);
        try expectSameR1(cr);
        m = cr;
        m.pubkey[(i * 5) % 64] ^= 0x01;
        try expectSameR1(m);
    }
}
