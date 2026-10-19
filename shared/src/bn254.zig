/// BN254 (alt_bn128) G1 add / scalar mul and pairing check, EIP-196 / EIP-197, generic over a
/// field backend, plus the native tests.
///
/// `Impl(B)` exposes, for a backend `B` (soft.zig contract), all byte layouts as in the EIPs
/// (big-endian):
///   g1AddBytes(p1, p2, result) bool      G1 point = x‖y (64 bytes); (0,0) is the identity
///   g1MulBytes(point, scalar, result)    scalar = 32 bytes, any 256-bit value (not reduced)
///   pairingBytes(pairs, verified) bool   pairs: slice of {g1: [64]u8, g2: [128]u8};
///                                        G2 = x_im‖x_re‖y_im‖y_re (EIP-197 order)
///
/// Return convention (what zesu's precompile wrapper expects): `false` means the input is
/// invalid (coordinate >= p, point not on the curve, G2 point outside the r-order subgroup) and
/// the precompile must fail; `true` means success, and for pairing the check result is in
/// `verified` (an empty pair list verifies true; pairs with an identity point contribute 1).
///
/// Natively (`zig test`) the backend is soft.zig. A zkVM target instantiates `Impl` with a backend
/// built on its own accelerators: field ops, optionally Fp2 ops (`fp2_*`), and optionally G1
/// point ops (`g1_add` / `g1_double`). Pico is the worked example: FP_* / FP2_* syscalls plus
/// BN254_ADD / BN254_DOUBLE (see pico/src/zkvm_accel/bn254.zig).
///   * G1 add / double use the backend's `g1_add` / `g1_double` when it provides them, else
///     affine formulas on the field ops. Point accelerators are typically plain affine P+Q
///     (Pico's abort the VM when the two points are equal and return garbage for P = -Q or the
///     identity), so the callers here always special-case those before reaching them.
///   * G2 and the optimal-ate pairing: affine Fp2 arithmetic in Zig, line functions on the
///     D-type sextic twist, final exponentiation with a plain exponentiation for the hard part
///     (cycle cost is irrelevant next to correctness).
const std = @import("std");
pub const field = @import("field.zig");
pub const tower = @import("tower.zig");
pub const soft = @import("soft.zig");

pub const bn_p: [4]u64 = .{ 0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029 };
const p_int: comptime_int = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
const r_int: comptime_int = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
/// Optimal-ate loop count 6x+2, x = 4965661367192848881 (bit 64 is the implicit top bit).
const ate_loop: u128 = 29793968203157093288;

fn limbsOf(comptime n: usize, comptime v: comptime_int) [n]u64 {
    var r: [n]u64 = undefined;
    var t = v;
    for (0..n) |i| {
        r[i] = @intCast(t & 0xFFFFFFFFFFFFFFFF);
        t >>= 64;
    }
    return r;
}

fn bitLen(comptime v: comptime_int) usize {
    var n: usize = 0;
    var t = v;
    while (t > 0) : (t >>= 1) n += 1;
    return n;
}

const r_limbs = limbsOf(4, r_int);
const hard_int: comptime_int = blk: {
    const num = p_int * p_int * p_int * p_int - p_int * p_int + 1;
    if (num % r_int != 0) @compileError("(p^4 - p^2 + 1) must be divisible by r");
    break :blk num / r_int;
};
const hard_exp = limbsOf((bitLen(hard_int) + 63) / 64, hard_int);

pub fn Impl(comptime B: type) type {
    const T = tower.Tower(B, 9, 1);
    const Fp = T.Fp;
    const Fp2 = T.Fp2;
    const Fp6 = T.Fp6;
    const Fp12 = T.Fp12;
    const Fe = Fp.Fe;
    const N = Fp.N;
    comptime std.debug.assert(N == 4);

    return struct {
        pub const G1 = struct { x: Fe, y: Fe, inf: bool };
        pub const G2 = struct { x: Fp2, y: Fp2, inf: bool };
        const g1_inf = G1{ .x = Fp.zero, .y = Fp.zero, .inf = true };
        const g2_inf = G2{ .x = Fp2.zero, .y = Fp2.zero, .inf = true };

        // ── G1 ────────────────────────────────────────────────────────────────

        /// 32-byte big-endian field element, rejected unless < p.
        fn readFe(b: *const [32]u8) ?Fe {
            const v = Fp.fromBytesBE(b);
            return if (Fp.isCanonical(v)) v else null;
        }

        /// Decode and validate a G1 point: coordinates < p, on y² = x³ + 3; (0,0) = identity.
        pub fn decodeG1(b: *const [64]u8) ?G1 {
            const x = readFe(b[0..32]) orelse return null;
            const y = readFe(b[32..64]) orelse return null;
            if (Fp.isZero(x) and Fp.isZero(y)) return g1_inf;
            const lhs = Fp.sq(y);
            const rhs = Fp.add(Fp.mul(Fp.sq(x), x), Fp.fromU64(3));
            if (!Fp.eql(lhs, rhs)) return null;
            return .{ .x = x, .y = y, .inf = false };
        }

        pub fn encodeG1(p: G1) [64]u8 {
            var out: [64]u8 = .{0} ** 64;
            if (p.inf) return out;
            out[0..32].* = Fp.toBytesBE(p.x);
            out[32..64].* = Fp.toBytesBE(p.y);
            return out;
        }

        fn g1Dbl(p: G1) G1 {
            if (p.inf or Fp.isZero(p.y)) return g1_inf;
            if (@hasDecl(B, "g1_double")) {
                var buf: [2 * N]u64 align(8) = undefined;
                buf[0..N].* = p.x;
                buf[N .. 2 * N].* = p.y;
                B.g1_double(&buf);
                return .{ .x = buf[0..N].*, .y = buf[N .. 2 * N].*, .inf = false };
            }
            const xx = Fp.sq(p.x);
            const num = Fp.add(Fp.dbl(xx), xx);
            const s = Fp.mul(num, Fp.inv(Fp.dbl(p.y)));
            const x3 = Fp.sub(Fp.sq(s), Fp.dbl(p.x));
            const y3 = Fp.sub(Fp.mul(s, Fp.sub(p.x, x3)), p.y);
            return .{ .x = x3, .y = y3, .inf = false };
        }

        fn g1Add_(p: G1, q: G1) G1 {
            if (p.inf) return q;
            if (q.inf) return p;
            if (Fp.eql(p.x, q.x)) {
                if (Fp.eql(p.y, q.y)) return g1Dbl(p);
                return g1_inf; // p = -q
            }
            if (@hasDecl(B, "g1_add")) {
                var a: [2 * N]u64 align(8) = undefined;
                var c: [2 * N]u64 align(8) = undefined;
                a[0..N].* = p.x;
                a[N .. 2 * N].* = p.y;
                c[0..N].* = q.x;
                c[N .. 2 * N].* = q.y;
                B.g1_add(&a, &c);
                return .{ .x = a[0..N].*, .y = a[N .. 2 * N].*, .inf = false };
            }
            const s = Fp.mul(Fp.sub(q.y, p.y), Fp.inv(Fp.sub(q.x, p.x)));
            const x3 = Fp.sub(Fp.sub(Fp.sq(s), p.x), q.x);
            const y3 = Fp.sub(Fp.mul(s, Fp.sub(p.x, x3)), p.y);
            return .{ .x = x3, .y = y3, .inf = false };
        }

        /// k * p, k big-endian bytes of any length (MSB-first double-and-add).
        fn g1MulBE(p: G1, k: []const u8) G1 {
            var acc = g1_inf;
            for (k) |byte| {
                var bit: u4 = 8;
                while (bit > 0) {
                    bit -= 1;
                    acc = g1Dbl(acc);
                    if ((byte >> @as(u3, @intCast(bit))) & 1 == 1) acc = g1Add_(acc, p);
                }
            }
            return acc;
        }

        pub fn g1AddBytes(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) bool {
            const a = decodeG1(p1) orelse return false;
            const b = decodeG1(p2) orelse return false;
            result.* = encodeG1(g1Add_(a, b));
            return true;
        }

        pub fn g1MulBytes(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) bool {
            const a = decodeG1(point) orelse return false;
            result.* = encodeG1(g1MulBE(a, scalar));
            return true;
        }

        // ── G2 (on the twist y² = x³ + 3/ξ over Fp2) ──────────────────────────

        var twist_b_cache: ?Fp2 = null;
        fn twistB() Fp2 {
            if (twist_b_cache) |b| return b;
            const b = Fp2.mul(.{ .c0 = Fp.fromU64(3), .c1 = Fp.zero }, Fp2.inv(Fp2.xi));
            twist_b_cache = b;
            return b;
        }

        var gamma1_cache: ?Fp2 = null;
        /// ξ^((p-1)/6)
        fn gamma1() Fp2 {
            if (gamma1_cache) |g| return g;
            const e = field.divSmall(N, field.limbsSubSmall(N, Fp.modulus, 1), 6);
            const g = Fp2.pow(Fp2.xi, &e);
            gamma1_cache = g;
            return g;
        }

        fn g2OnCurve(x: Fp2, y: Fp2) bool {
            const rhs = Fp2.add(Fp2.mul(Fp2.sq(x), x), twistB());
            return Fp2.eql(Fp2.sq(y), rhs);
        }

        fn g2Neg(p: G2) G2 {
            return .{ .x = p.x, .y = Fp2.neg(p.y), .inf = p.inf };
        }

        fn g2Dbl(p: G2) G2 {
            if (p.inf or Fp2.isZero(p.y)) return g2_inf;
            const xx = Fp2.sq(p.x);
            const num = Fp2.add(Fp2.dbl(xx), xx);
            const lam = Fp2.mul(num, Fp2.inv(Fp2.dbl(p.y)));
            const x3 = Fp2.sub(Fp2.sq(lam), Fp2.dbl(p.x));
            const y3 = Fp2.sub(Fp2.mul(lam, Fp2.sub(p.x, x3)), p.y);
            return .{ .x = x3, .y = y3, .inf = false };
        }

        fn g2Add_(p: G2, q: G2) G2 {
            if (p.inf) return q;
            if (q.inf) return p;
            if (Fp2.eql(p.x, q.x)) {
                if (Fp2.eql(p.y, q.y)) return g2Dbl(p);
                return g2_inf;
            }
            const lam = Fp2.mul(Fp2.sub(q.y, p.y), Fp2.inv(Fp2.sub(q.x, p.x)));
            const x3 = Fp2.sub(Fp2.sub(Fp2.sq(lam), p.x), q.x);
            const y3 = Fp2.sub(Fp2.mul(lam, Fp2.sub(p.x, x3)), p.y);
            return .{ .x = x3, .y = y3, .inf = false };
        }

        /// k * p, k little-endian limbs.
        fn g2MulLimbs(p: G2, k: []const u64) G2 {
            var acc = g2_inf;
            var i: usize = k.len * 64;
            while (i > 0) {
                i -= 1;
                acc = g2Dbl(acc);
                if ((k[i / 64] >> @intCast(i % 64)) & 1 == 1) acc = g2Add_(acc, p);
            }
            return acc;
        }

        /// Decode and validate a G2 point (EIP-197 layout x_im‖x_re‖y_im‖y_re): coordinates < p,
        /// on the twist, in the r-order subgroup; all-zero = identity.
        pub fn decodeG2(b: *const [128]u8) ?G2 {
            const x1 = readFe(b[0..32]) orelse return null;
            const x0 = readFe(b[32..64]) orelse return null;
            const y1 = readFe(b[64..96]) orelse return null;
            const y0 = readFe(b[96..128]) orelse return null;
            const x = Fp2{ .c0 = x0, .c1 = x1 };
            const y = Fp2{ .c0 = y0, .c1 = y1 };
            if (Fp2.isZero(x) and Fp2.isZero(y)) return g2_inf;
            if (!g2OnCurve(x, y)) return null;
            const q = G2{ .x = x, .y = y, .inf = false };
            if (!g2MulLimbs(q, &r_limbs).inf) return null; // not in the r-order subgroup
            return q;
        }

        // ── pairing ───────────────────────────────────────────────────────────

        /// Frobenius endomorphism on the twist: (x, y) -> (conj(x) γ², conj(y) γ³).
        fn frobTwist(q: G2) G2 {
            const g = gamma1();
            const g2 = Fp2.sq(g);
            const g3 = Fp2.mul(g2, g);
            return .{ .x = Fp2.mul(Fp2.conj(q.x), g2), .y = Fp2.mul(Fp2.conj(q.y), g3), .inf = q.inf };
        }

        /// Line through T with slope λ (on the twist) evaluated at P ∈ G1, as an Fp12 element:
        ///   y_P + (-λ x_P) w + (λ x_T - y_T) w³      (w² = v, ψ(x,y) = (x w², y w³))
        fn mkLine(lam: Fp2, t: G2, p: G1) Fp12 {
            const a = Fp2{ .c0 = p.y, .c1 = Fp.zero };
            const b = Fp2.mulByFp(Fp2.neg(lam), p.x);
            const c = Fp2.sub(Fp2.mul(lam, t.x), t.y);
            return .{
                .c0 = .{ .c0 = a, .c1 = Fp2.zero, .c2 = Fp2.zero },
                .c1 = .{ .c0 = b, .c1 = c, .c2 = Fp2.zero },
            };
        }

        fn dblStep(t: *G2, p: G1) Fp12 {
            const xx = Fp2.sq(t.x);
            const num = Fp2.add(Fp2.dbl(xx), xx);
            const lam = Fp2.mul(num, Fp2.inv(Fp2.dbl(t.y)));
            const line = mkLine(lam, t.*, p);
            const x3 = Fp2.sub(Fp2.sq(lam), Fp2.dbl(t.x));
            const y3 = Fp2.sub(Fp2.mul(lam, Fp2.sub(t.x, x3)), t.y);
            t.* = .{ .x = x3, .y = y3, .inf = false };
            return line;
        }

        fn addStep(t: *G2, q: G2, p: G1) Fp12 {
            const lam = Fp2.mul(Fp2.sub(q.y, t.y), Fp2.inv(Fp2.sub(q.x, t.x)));
            const line = mkLine(lam, t.*, p);
            const x3 = Fp2.sub(Fp2.sub(Fp2.sq(lam), t.x), q.x);
            const y3 = Fp2.sub(Fp2.mul(lam, Fp2.sub(t.x, x3)), t.y);
            t.* = .{ .x = x3, .y = y3, .inf = false };
            return line;
        }

        /// Optimal-ate Miller loop for non-identity P, Q (Q in the r-subgroup).
        pub fn millerLoop(p: G1, q: G2) Fp12 {
            var f = Fp12.one;
            var t = q;
            var i: i32 = 63;
            while (i >= 0) : (i -= 1) {
                f = Fp12.sq(f);
                f = Fp12.mul(f, dblStep(&t, p));
                if ((ate_loop >> @as(u7, @intCast(i))) & 1 == 1) f = Fp12.mul(f, addStep(&t, q, p));
            }
            const q1 = frobTwist(q);
            const q2 = g2Neg(frobTwist(q1));
            f = Fp12.mul(f, addStep(&t, q1, p));
            f = Fp12.mul(f, addStep(&t, q2, p));
            return f;
        }

        /// f^((p^12 - 1) / r)
        pub fn finalExp(f: Fp12) Fp12 {
            const f1 = Fp12.mul(Fp12.conj(f), Fp12.inv(f)); // f^(p^6 - 1)
            const f2 = Fp12.mul(Fp12.frobenius(f1, 2), f1); // ^(p^2 + 1)
            return Fp12.pow(f2, &hard_exp); // ^((p^4 - p^2 + 1) / r)
        }

        pub fn pairing(p: G1, q: G2) Fp12 {
            if (p.inf or q.inf) return Fp12.one;
            return finalExp(millerLoop(p, q));
        }

        /// EIP-197 check over a slice of {g1: [64]u8, g2: [128]u8}. null = invalid input.
        pub fn pairingCheck(pairs: anytype) ?bool {
            // validate everything first: any invalid pair fails the whole call
            for (pairs) |pr| {
                _ = decodeG1(&pr.g1) orelse return null;
                _ = decodeG2(&pr.g2) orelse return null;
            }
            var acc = Fp12.one;
            for (pairs) |pr| {
                const a = decodeG1(&pr.g1).?;
                const b = decodeG2(&pr.g2).?;
                if (a.inf or b.inf) continue;
                acc = Fp12.mul(acc, millerLoop(a, b));
            }
            return Fp12.isOne(finalExp(acc));
        }

        pub fn pairingBytes(pairs: anytype, verified: *bool) bool {
            verified.* = false;
            const ok = pairingCheck(pairs) orelse return false;
            verified.* = ok;
            return true;
        }

        // exposed for tests
        pub const Types = struct {
            pub const Fp12_ = Fp12;
            pub const Fp6_ = Fp6;
            pub const Fp2_ = Fp2;
            pub const Fp_ = Fp;
        };
        pub const g2MulLimbs_ = g2MulLimbs;
        pub const g2OnCurve_ = g2OnCurve;
        pub const frobTwist_ = frobTwist;
        pub const g1MulBE_ = g1MulBE;
        pub const g1Add2 = g1Add_;
        pub const g2Add2 = g2Add_;
        pub const g2Neg_ = g2Neg;
        pub const twistB_ = twistB;
    };
}

// ── vector plumbing shared by native tests and the guest self-test ───────────

pub const vectors = @import("bn254_vectors.zig");
pub const Vec = vectors.Vec;
const vec_add = vectors.vec_add;
const vec_mul = vectors.vec_mul;
const vec_pairing = vectors.vec_pairing;

fn hex(comptime n: usize, s: []const u8) ?[n]u8 {
    var b: [n]u8 = undefined;
    const r = std.fmt.hexToBytes(&b, s) catch return null;
    if (r.len != n) return null;
    return b;
}

pub fn checkAdd(comptime G: type, v: Vec) bool {
    const in = hex(128, v.in) orelse return false;
    var res: [64]u8 = undefined;
    const ok = G.g1AddBytes(in[0..64], in[64..128], &res);
    if (ok != v.ok) return false;
    if (!ok) return true;
    const want = hex(64, v.out) orelse return false;
    return std.mem.eql(u8, &res, &want);
}

pub fn checkMul(comptime G: type, v: Vec) bool {
    const in = hex(96, v.in) orelse return false;
    var res: [64]u8 = undefined;
    const ok = G.g1MulBytes(in[0..64], in[64..96], &res);
    if (ok != v.ok) return false;
    if (!ok) return true;
    const want = hex(64, v.out) orelse return false;
    return std.mem.eql(u8, &res, &want);
}

pub const PairBytes = extern struct { g1: [64]u8, g2: [128]u8 };

/// Pairing vectors have 192*k input bytes; `buf` holds up to 10 pairs.
pub fn checkPairing(comptime G: type, v: Vec) bool {
    var buf: [10]PairBytes = undefined;
    const n = v.in.len / 2 / 192;
    if (n > buf.len) return true; // larger vectors are covered natively only
    const raw = std.mem.sliceAsBytes(buf[0..n]);
    _ = std.fmt.hexToBytes(raw, v.in) catch return false;
    var verified = false;
    const ok = G.pairingBytes(buf[0..n], &verified);
    if (ok != v.ok) return false;
    if (!ok) return true;
    const want_true = std.mem.endsWith(u8, v.out, "1");
    return verified == want_true;
}

// ── native tests (software backend) ──────────────────────────────────────────

const S = Impl(soft.Soft(4, bn_p));
const SFe = S.Types.Fp_.Fe;
const SFp12 = S.Types.Fp12_;
const SFp2 = S.Types.Fp2_;

fn fe(comptime v: comptime_int) SFe {
    return limbsOf(4, v);
}

const g1_gen = S.G1{ .x = fe(1), .y = fe(2), .inf = false };
const g2_gen = S.G2{
    .x = .{
        .c0 = fe(10857046999023057135944570762232829481370756359578518086990519993285655852781),
        .c1 = fe(11559732032986387107991004021392285783925812861821192530917403151452391805634),
    },
    .y = .{
        .c0 = fe(8495653923123431417604973247489272438418190587263600148770280649306958101930),
        .c1 = fe(4082367875863433681332203403145435568316851327593401208105741076214120093531),
    },
    .inf = false,
};

fn encG2(q: S.G2) [128]u8 {
    var out: [128]u8 = .{0} ** 128;
    if (q.inf) return out;
    out[0..32].* = S.Types.Fp_.toBytesBE(q.x.c1);
    out[32..64].* = S.Types.Fp_.toBytesBE(q.x.c0);
    out[64..96].* = S.Types.Fp_.toBytesBE(q.y.c1);
    out[96..128].* = S.Types.Fp_.toBytesBE(q.y.c0);
    return out;
}

fn pair1(p: S.G1, q: S.G2) PairBytes {
    return .{ .g1 = S.encodeG1(p), .g2 = encG2(q) };
}

fn scalarLimbs(k: u64) [1]u64 {
    return .{k};
}

fn g1Mul64(p: S.G1, k: u64) S.G1 {
    var be: [8]u8 = undefined;
    std.mem.writeInt(u64, &be, k, .big);
    return S.g1MulBE_(p, &be);
}

test "bn254 EIP-196 G1 add vectors" {
    for (vec_add, 0..) |v, i| {
        try std.testing.expect(checkAdd(S, v) or blk: {
            std.debug.print("add vector {d} failed\n", .{i});
            break :blk false;
        });
    }
}

test "bn254 EIP-196 G1 mul vectors" {
    for (vec_mul, 0..) |v, i| {
        try std.testing.expect(checkMul(S, v) or blk: {
            std.debug.print("mul vector {d} failed\n", .{i});
            break :blk false;
        });
    }
}

test "bn254 EIP-197 pairing vectors" {
    for (vec_pairing, 0..) |v, i| {
        // the native table keeps every vector, including the 10-pair ones
        const n = v.in.len / 2 / 192;
        var buf: [10]PairBytes = undefined;
        try std.testing.expect(n <= buf.len);
        _ = try std.fmt.hexToBytes(std.mem.sliceAsBytes(buf[0..n]), v.in);
        var verified = false;
        const ok = S.pairingBytes(buf[0..n], &verified);
        try std.testing.expectEqual(v.ok, ok);
        if (ok) try std.testing.expectEqual(std.mem.endsWith(u8, v.out, "1"), verified);
        if (ok != v.ok) std.debug.print("pairing vector {d} failed\n", .{i});
    }
}

test "bn254 generators: on curve, order r" {
    try std.testing.expect(S.g2OnCurve_(g2_gen.x, g2_gen.y));
    try std.testing.expect(S.g2MulLimbs_(g2_gen, &r_limbs).inf);
    // (r-1)G = -G
    var rm1 = r_limbs;
    rm1[0] -= 1;
    const neg = S.g2MulLimbs_(g2_gen, &rm1);
    try std.testing.expect(SFp2.eql(neg.x, g2_gen.x) and SFp2.eql(neg.y, SFp2.neg(g2_gen.y)));
    // G1: 2G + 3G = 5G, r*G = O
    const g5 = g1Mul64(g1_gen, 5);
    const sum = S.g1Add2(g1Mul64(g1_gen, 2), g1Mul64(g1_gen, 3));
    try std.testing.expect(S.Types.Fp_.eql(g5.x, sum.x) and S.Types.Fp_.eql(g5.y, sum.y));
    var r_be: [32]u8 = undefined;
    for (0..4) |i| std.mem.writeInt(u64, r_be[24 - 8 * i ..][0..8], r_limbs[i], .big);
    try std.testing.expect(S.g1MulBE_(g1_gen, &r_be).inf);
}

test "bn254 Frobenius on the twist is multiplication by p" {
    const f = S.frobTwist_(g2_gen);
    try std.testing.expect(S.g2OnCurve_(f.x, f.y));
    const pm = S.g2MulLimbs_(g2_gen, &bn_p);
    try std.testing.expect(SFp2.eql(f.x, pm.x) and SFp2.eql(f.y, pm.y));
}

test "bn254 pairing: non-degenerate, order r, bilinear" {
    const e = S.pairing(g1_gen, g2_gen);
    try std.testing.expect(!SFp12.isOne(e));
    try std.testing.expect(SFp12.isOne(SFp12.pow(e, &r_limbs)));
    // e(2P, Q) = e(P, 2Q) = e(P, Q)^2
    const e2 = SFp12.sq(e);
    const g2x2 = S.g2Add2(g2_gen, g2_gen);
    try std.testing.expect(SFp12.eql(S.pairing(g1Mul64(g1_gen, 2), g2_gen), e2));
    try std.testing.expect(SFp12.eql(S.pairing(g1_gen, g2x2), e2));
    // e(3P, 5Q) = e(P, Q)^15
    const g2x5 = S.g2MulLimbs_(g2_gen, &scalarLimbs(5));
    try std.testing.expect(SFp12.eql(S.pairing(g1Mul64(g1_gen, 3), g2x5), SFp12.pow(e, &scalarLimbs(15))));
}

test "bn254 pairing check: e(P,Q)·e(-P,Q) = 1 and a failing product" {
    const neg_p = S.G1{ .x = g1_gen.x, .y = S.Types.Fp_.neg(g1_gen.y), .inf = false };
    var verified = false;
    const good = [_]PairBytes{ pair1(g1_gen, g2_gen), pair1(neg_p, g2_gen) };
    try std.testing.expect(S.pairingBytes(&good, &verified));
    try std.testing.expect(verified);
    const bad = [_]PairBytes{ pair1(g1_gen, g2_gen), pair1(g1_gen, g2_gen) };
    try std.testing.expect(S.pairingBytes(&bad, &verified));
    try std.testing.expect(!verified);
    // e(aP, Q)·e(-P, aQ) = 1 for a = 7
    const aq = S.g2MulLimbs_(g2_gen, &scalarLimbs(7));
    const mixed = [_]PairBytes{ pair1(g1Mul64(g1_gen, 7), g2_gen), pair1(neg_p, aq) };
    try std.testing.expect(S.pairingBytes(&mixed, &verified));
    try std.testing.expect(verified);
    // empty input and identity pairs verify true
    try std.testing.expect(S.pairingBytes(&[_]PairBytes{}, &verified));
    try std.testing.expect(verified);
    const ident = [_]PairBytes{ pair1(S.G1{ .x = S.Types.Fp_.zero, .y = S.Types.Fp_.zero, .inf = true }, g2_gen), pair1(g1_gen, S.G2{ .x = SFp2.zero, .y = SFp2.zero, .inf = true }) };
    try std.testing.expect(S.pairingBytes(&ident, &verified));
    try std.testing.expect(verified);
}

/// Square root in Fp2 (p = 3 mod 4), or null.
fn fp2Sqrt(a: SFp2) ?SFp2 {
    if (SFp2.isZero(a)) return a;
    const p3_4 = field.divSmall(4, field.limbsSubSmall(4, bn_p, 3), 4);
    const p1_2 = field.divSmall(4, field.limbsSubSmall(4, bn_p, 1), 2);
    const a1 = SFp2.pow(a, &p3_4);
    const alpha = SFp2.mul(SFp2.sq(a1), a);
    const a0 = SFp2.mul(SFp2.pow(alpha, &bn_p), alpha);
    const minus_one = SFp2.neg(SFp2.one);
    if (SFp2.eql(a0, minus_one)) return null;
    const x0 = SFp2.mul(a1, a);
    const root = if (SFp2.eql(alpha, minus_one))
        SFp2.mul(SFp2{ .c0 = SFp.zero_, .c1 = SFp.one_ }, x0)
    else
        SFp2.mul(SFp2.pow(SFp2.add(SFp2.one, alpha), &p1_2), x0);
    return if (SFp2.eql(SFp2.sq(root), a)) root else null;
}

const SFp = struct {
    const zero_ = S.Types.Fp_.zero;
    const one_ = S.Types.Fp_.one;
};

test "bn254 invalid inputs are rejected" {
    // G1: not on the curve, coordinate >= p
    var bad_g1: [64]u8 = .{0} ** 64;
    bad_g1[31] = 1;
    bad_g1[63] = 3; // (1, 3) is not on y² = x³ + 3
    try std.testing.expect(S.decodeG1(&bad_g1) == null);
    var big: [64]u8 = .{0xff} ** 64;
    try std.testing.expect(S.decodeG1(&big) == null);
    var res: [64]u8 = undefined;
    try std.testing.expect(!S.g1AddBytes(&bad_g1, &bad_g1, &res));

    // G2: off the twist
    var g2b = encG2(g2_gen);
    g2b[127] ^= 1;
    try std.testing.expect(S.decodeG2(&g2b) == null);
    // G2: on the twist but outside the r-order subgroup
    var x = SFp2{ .c0 = SFe{ 2, 0, 0, 0 }, .c1 = SFe{ 0, 0, 0, 0 } };
    var found: ?S.G2 = null;
    var tries: usize = 0;
    while (tries < 40) : (tries += 1) {
        const rhs = SFp2.add(SFp2.mul(SFp2.sq(x), x), S.twistB_());
        if (fp2Sqrt(rhs)) |y| {
            found = .{ .x = x, .y = y, .inf = false };
            break;
        }
        x.c0 = S.Types.Fp_.add(x.c0, S.Types.Fp_.one);
    }
    const q = found.?;
    try std.testing.expect(S.g2OnCurve_(q.x, q.y));
    try std.testing.expect(S.decodeG2(&encG2(q)) == null);
    // a pairing call containing it fails as invalid input
    var verified = true;
    const pr = [_]PairBytes{pair1(g1_gen, q)};
    try std.testing.expect(!S.pairingBytes(&pr, &verified));
    try std.testing.expect(!verified);
}
