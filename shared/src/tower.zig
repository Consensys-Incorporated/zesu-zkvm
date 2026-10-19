/// Extension tower Fp2 = Fp[u]/(u²+1), Fp6 = Fp2[v]/(v³-ξ), Fp12 = Fp6[w]/(w²-v),
/// shared by BN254 (ξ = 9+u) and BLS12-381 (ξ = 1+u).
///
/// Generic over the base-field backend (soft.zig contract). If the backend also declares
/// `fp2_add / fp2_sub / fp2_mul` (in place on [2*limbs]u64 = c0‖c1) those are used for Fp2,
/// which maps straight onto Pico's FP2_* syscalls; otherwise Fp2 is built from Fp ops.
const std = @import("std");
const field = @import("field.zig");
const soft = @import("soft.zig");

pub fn Tower(comptime B: type, comptime xi_c0: u64, comptime xi_c1: u64) type {
    return struct {
        pub const Fp = field.Field(B);
        pub const Fe = Fp.Fe;

        // ── Fp2 ───────────────────────────────────────────────────────────────
        pub const Fp2 = extern struct {
            c0: Fe,
            c1: Fe,

            pub const zero = Fp2{ .c0 = Fp.zero, .c1 = Fp.zero };
            pub const one = Fp2{ .c0 = Fp.one, .c1 = Fp.zero };
            pub const xi = Fp2{ .c0 = Fp.fromU64(xi_c0), .c1 = Fp.fromU64(xi_c1) };

            const has_native = @hasDecl(B, "fp2_mul");

            /// Copy of `a` as straight-line word moves. A by-value copy of this 8-byte-aligned
            /// struct otherwise becomes a `memcpy` call, which dominated the pairing's cost.
            inline fn dup(a: *const Fp2) Fp2 {
                var r: Fp2 = undefined;
                const src: *const [2 * Fp.N]u64 = @ptrCast(a);
                const dst: *[2 * Fp.N]u64 = @ptrCast(&r);
                inline for (0..2 * Fp.N) |i| dst[i] = src[i];
                return r;
            }

            // The `*P` forms take operands by pointer: a by-value Fp2 argument is copied to a
            // temporary (a `memcpy` call), and the tower code below calls these in bulk.
            pub fn addP(a: *const Fp2, b: *const Fp2) Fp2 {
                if (has_native) {
                    var r = dup(a);
                    B.fp2_add(@ptrCast(&r), @ptrCast(b));
                    return r;
                }
                return .{ .c0 = Fp.add(a.c0, b.c0), .c1 = Fp.add(a.c1, b.c1) };
            }
            pub fn subP(a: *const Fp2, b: *const Fp2) Fp2 {
                if (has_native) {
                    var r = dup(a);
                    B.fp2_sub(@ptrCast(&r), @ptrCast(b));
                    return r;
                }
                return .{ .c0 = Fp.sub(a.c0, b.c0), .c1 = Fp.sub(a.c1, b.c1) };
            }
            pub fn mulP(a: *const Fp2, b: *const Fp2) Fp2 {
                if (has_native) {
                    var r = dup(a);
                    B.fp2_mul(@ptrCast(&r), @ptrCast(b));
                    return r;
                }
                // (a0 + a1 u)(b0 + b1 u) = (a0b0 - a1b1) + (a0b1 + a1b0) u
                const t0 = Fp.mul(a.c0, b.c0);
                const t1 = Fp.mul(a.c1, b.c1);
                const t2 = Fp.mul(a.c0, b.c1);
                const t3 = Fp.mul(a.c1, b.c0);
                return .{ .c0 = Fp.sub(t0, t1), .c1 = Fp.add(t2, t3) };
            }
            pub fn add(a: Fp2, b: Fp2) Fp2 {
                return addP(&a, &b);
            }
            pub fn sub(a: Fp2, b: Fp2) Fp2 {
                return subP(&a, &b);
            }
            pub fn neg(a: Fp2) Fp2 {
                return sub(zero, a);
            }
            pub fn dbl(a: Fp2) Fp2 {
                return add(a, a);
            }
            pub fn mul(a: Fp2, b: Fp2) Fp2 {
                return mulP(&a, &b);
            }
            pub fn sq(a: Fp2) Fp2 {
                return mul(a, a);
            }
            pub fn mulByFp(a: Fp2, k: Fe) Fp2 {
                return .{ .c0 = Fp.mul(a.c0, k), .c1 = Fp.mul(a.c1, k) };
            }
            pub fn mulByXi(a: Fp2) Fp2 {
                return mulP(&a, &xi);
            }
            pub fn conj(a: Fp2) Fp2 {
                return .{ .c0 = a.c0, .c1 = Fp.neg(a.c1) };
            }
            pub fn isZero(a: Fp2) bool {
                return Fp.isZero(a.c0) and Fp.isZero(a.c1);
            }
            pub fn eql(a: Fp2, b: Fp2) bool {
                return Fp.eql(a.c0, b.c0) and Fp.eql(a.c1, b.c1);
            }
            /// 1/(a0 + a1 u) = (a0 - a1 u) / (a0² + a1²); inv(0) = 0.
            pub fn inv(a: Fp2) Fp2 {
                const n = Fp.add(Fp.sq(a.c0), Fp.sq(a.c1));
                const ni = Fp.inv(n);
                return .{ .c0 = Fp.mul(a.c0, ni), .c1 = Fp.neg(Fp.mul(a.c1, ni)) };
            }
            pub fn pow(base: Fp2, exp: []const u64) Fp2 {
                var r = one;
                var i: usize = exp.len * 64;
                while (i > 0) {
                    i -= 1;
                    r = sq(r);
                    if ((exp[i / 64] >> @intCast(i % 64)) & 1 == 1) r = mul(r, base);
                }
                return r;
            }
        };

        // ── Frobenius constants ───────────────────────────────────────────────
        // γ_k = ξ^((p^k-1)/6) for k = 1..3. γ_1 is one exponentiation; the others follow
        // from γ_k = Π_{j<k} frob^j(γ_1) with frob on Fp2 = conjugation.
        const Gammas = struct { g1: Fp2, g2: Fp2, g3: Fp2 };
        var gammas_cache: ?Gammas = null;
        fn gammas() Gammas {
            if (gammas_cache) |g| return g;
            const e = field.divSmall(Fp.N, field.limbsSubSmall(Fp.N, Fp.modulus, 1), 6);
            const g1 = Fp2.pow(Fp2.xi, &e);
            const g2 = Fp2.mul(g1, Fp2.conj(g1));
            const g3 = Fp2.mul(g2, g1);
            gammas_cache = .{ .g1 = g1, .g2 = g2, .g3 = g3 };
            return gammas_cache.?;
        }

        // ── Fp6 ───────────────────────────────────────────────────────────────
        pub const Fp6 = extern struct {
            c0: Fp2,
            c1: Fp2,
            c2: Fp2,

            pub const zero = Fp6{ .c0 = Fp2.zero, .c1 = Fp2.zero, .c2 = Fp2.zero };
            pub const one = Fp6{ .c0 = Fp2.one, .c1 = Fp2.zero, .c2 = Fp2.zero };

            pub fn add(a: Fp6, b: Fp6) Fp6 {
                return addP(&a, &b);
            }
            pub fn sub(a: Fp6, b: Fp6) Fp6 {
                return subP(&a, &b);
            }
            pub fn addP(a: *const Fp6, b: *const Fp6) Fp6 {
                return .{ .c0 = Fp2.addP(&a.c0, &b.c0), .c1 = Fp2.addP(&a.c1, &b.c1), .c2 = Fp2.addP(&a.c2, &b.c2) };
            }
            pub fn subP(a: *const Fp6, b: *const Fp6) Fp6 {
                return .{ .c0 = Fp2.subP(&a.c0, &b.c0), .c1 = Fp2.subP(&a.c1, &b.c1), .c2 = Fp2.subP(&a.c2, &b.c2) };
            }
            pub fn neg(a: Fp6) Fp6 {
                return sub(zero, a);
            }
            pub fn mul(a: Fp6, b: Fp6) Fp6 {
                return mulP(&a, &b);
            }
            pub fn mulP(a: *const Fp6, b: *const Fp6) Fp6 {
                // v³ = ξ
                const a0b0 = Fp2.mulP(&a.c0, &b.c0);
                const a1b1 = Fp2.mulP(&a.c1, &b.c1);
                const a2b2 = Fp2.mulP(&a.c2, &b.c2);
                const m12 = Fp2.mulP(&a.c1, &b.c2);
                const m21 = Fp2.mulP(&a.c2, &b.c1);
                const m01 = Fp2.mulP(&a.c0, &b.c1);
                const m10 = Fp2.mulP(&a.c1, &b.c0);
                const m02 = Fp2.mulP(&a.c0, &b.c2);
                const m20 = Fp2.mulP(&a.c2, &b.c0);
                const t0 = Fp2.addP(&m12, &m21);
                const t1 = Fp2.addP(&m01, &m10);
                const t2 = Fp2.addP(&m02, &m20);
                const x0 = Fp2.mulP(&t0, &Fp2.xi);
                const x2 = Fp2.mulP(&a2b2, &Fp2.xi);
                return .{
                    .c0 = Fp2.addP(&a0b0, &x0),
                    .c1 = Fp2.addP(&t1, &x2),
                    .c2 = Fp2.addP(&t2, &a1b1),
                };
            }
            pub fn sq(a: Fp6) Fp6 {
                return mul(a, a);
            }
            /// multiply by v: (a0, a1, a2) -> (ξ a2, a0, a1)
            pub fn mulByV(a: Fp6) Fp6 {
                return .{ .c0 = Fp2.mulByXi(a.c2), .c1 = a.c0, .c2 = a.c1 };
            }
            pub fn isZero(a: Fp6) bool {
                return Fp2.isZero(a.c0) and Fp2.isZero(a.c1) and Fp2.isZero(a.c2);
            }
            pub fn eql(a: Fp6, b: Fp6) bool {
                return Fp2.eql(a.c0, b.c0) and Fp2.eql(a.c1, b.c1) and Fp2.eql(a.c2, b.c2);
            }
            pub fn inv(a: Fp6) Fp6 {
                const t0 = Fp2.sub(Fp2.sq(a.c0), Fp2.mulByXi(Fp2.mul(a.c1, a.c2)));
                const t1 = Fp2.sub(Fp2.mulByXi(Fp2.sq(a.c2)), Fp2.mul(a.c0, a.c1));
                const t2 = Fp2.sub(Fp2.sq(a.c1), Fp2.mul(a.c0, a.c2));
                const den = Fp2.add(
                    Fp2.mul(a.c0, t0),
                    Fp2.mulByXi(Fp2.add(Fp2.mul(a.c2, t1), Fp2.mul(a.c1, t2))),
                );
                const di = Fp2.inv(den);
                return .{ .c0 = Fp2.mul(t0, di), .c1 = Fp2.mul(t1, di), .c2 = Fp2.mul(t2, di) };
            }
        };

        // ── Fp12 ──────────────────────────────────────────────────────────────
        pub const Fp12 = extern struct {
            c0: Fp6,
            c1: Fp6,

            pub const zero = Fp12{ .c0 = Fp6.zero, .c1 = Fp6.zero };
            pub const one = Fp12{ .c0 = Fp6.one, .c1 = Fp6.zero };

            pub fn add(a: Fp12, b: Fp12) Fp12 {
                return .{ .c0 = Fp6.add(a.c0, b.c0), .c1 = Fp6.add(a.c1, b.c1) };
            }
            pub fn sub(a: Fp12, b: Fp12) Fp12 {
                return .{ .c0 = Fp6.sub(a.c0, b.c0), .c1 = Fp6.sub(a.c1, b.c1) };
            }
            pub fn mul(a: Fp12, b: Fp12) Fp12 {
                return mulP(&a, &b);
            }
            pub fn mulP(a: *const Fp12, b: *const Fp12) Fp12 {
                // w² = v
                const a0b0 = Fp6.mulP(&a.c0, &b.c0);
                const a1b1 = Fp6.mulP(&a.c1, &b.c1);
                const m01 = Fp6.mulP(&a.c0, &b.c1);
                const m10 = Fp6.mulP(&a.c1, &b.c0);
                const v = Fp6.mulByV(a1b1);
                return .{ .c0 = Fp6.addP(&a0b0, &v), .c1 = Fp6.addP(&m01, &m10) };
            }
            pub fn sq(a: Fp12) Fp12 {
                return mul(a, a);
            }
            /// conjugation = Frobenius^6: (a0, a1) -> (a0, -a1)
            pub fn conj(a: Fp12) Fp12 {
                return .{ .c0 = a.c0, .c1 = Fp6.neg(a.c1) };
            }
            pub fn isOne(a: Fp12) bool {
                return eql(a, one);
            }
            pub fn eql(a: Fp12, b: Fp12) bool {
                return Fp6.eql(a.c0, b.c0) and Fp6.eql(a.c1, b.c1);
            }
            pub fn inv(a: Fp12) Fp12 {
                const den = Fp6.sub(Fp6.sq(a.c0), Fp6.mulByV(Fp6.sq(a.c1)));
                const di = Fp6.inv(den);
                return .{ .c0 = Fp6.mul(a.c0, di), .c1 = Fp6.neg(Fp6.mul(a.c1, di)) };
            }
            pub fn pow(base: Fp12, exp: []const u64) Fp12 {
                var r = one;
                var i: usize = exp.len * 64;
                while (i > 0) {
                    i -= 1;
                    r = sq(r);
                    if ((exp[i / 64] >> @intCast(i % 64)) & 1 == 1) r = mul(r, base);
                }
                return r;
            }

            /// x -> x^(p^k) for k = 1, 2, 3.
            pub fn frobenius(a: Fp12, comptime k: u2) Fp12 {
                const g = gammas();
                const gk = switch (k) {
                    1 => g.g1,
                    2 => g.g2,
                    3 => g.g3,
                    else => @compileError("frobenius: k must be 1, 2 or 3"),
                };
                const gk2 = Fp2.sq(gk);
                const gk3 = Fp2.mul(gk2, gk);
                const gk4 = Fp2.sq(gk2);
                const gk5 = Fp2.mul(gk4, gk);
                // coefficient of v^i w^j is scaled by γ_k^(2i+j) after Fp2-frobenius^k
                const f = struct {
                    fn c(x: Fp2) Fp2 {
                        return if (k % 2 == 1) Fp2.conj(x) else x;
                    }
                };
                return .{
                    .c0 = .{
                        .c0 = f.c(a.c0.c0),
                        .c1 = Fp2.mul(f.c(a.c0.c1), gk2),
                        .c2 = Fp2.mul(f.c(a.c0.c2), gk4),
                    },
                    .c1 = .{
                        .c0 = Fp2.mul(f.c(a.c1.c0), gk),
                        .c1 = Fp2.mul(f.c(a.c1.c1), gk3),
                        .c2 = Fp2.mul(f.c(a.c1.c2), gk5),
                    },
                };
            }
        };
    };
}

// ── tests ────────────────────────────────────────────────────────────────────
const BN_P: [4]u64 = .{ 0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029 };
const BLS_P: [6]u64 = .{
    0xb9feffffffffaaab, 0x1eabfffeb153ffff, 0x6730d2a0f6b0f624,
    0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a,
};

fn sample(comptime T: type, seed: u64) T.Fp.Fe {
    // deterministic pseudo-random canonical-ish element (top limb masked below the modulus)
    var s = seed;
    var r: T.Fp.Fe = undefined;
    for (&r) |*l| {
        s = s *% 6364136223846793005 +% 1442695040888963407;
        l.* = s;
    }
    r[T.Fp.N - 1] &= 0x0fffffffffffffff;
    return r;
}

fn sampleFp2(comptime T: type, seed: u64) T.Fp2 {
    return .{ .c0 = sample(T, seed), .c1 = sample(T, seed +% 1) };
}
fn sampleFp6(comptime T: type, seed: u64) T.Fp6 {
    return .{ .c0 = sampleFp2(T, seed), .c1 = sampleFp2(T, seed +% 10), .c2 = sampleFp2(T, seed +% 20) };
}
fn sampleFp12(comptime T: type, seed: u64) T.Fp12 {
    return .{ .c0 = sampleFp6(T, seed), .c1 = sampleFp6(T, seed +% 100) };
}

fn towerTests(comptime T: type) !void {
    const a = sampleFp12(T, 1);
    const b = sampleFp12(T, 2);
    const c = sampleFp12(T, 3);
    // field axioms
    try std.testing.expect(T.Fp12.eql(T.Fp12.mul(a, T.Fp12.inv(a)), T.Fp12.one));
    try std.testing.expect(T.Fp12.eql(T.Fp12.mul(T.Fp12.mul(a, b), c), T.Fp12.mul(a, T.Fp12.mul(b, c))));
    try std.testing.expect(T.Fp12.eql(T.Fp12.mul(a, T.Fp12.add(b, c)), T.Fp12.add(T.Fp12.mul(a, b), T.Fp12.mul(a, c))));
    try std.testing.expect(T.Fp6.eql(T.Fp6.mul(sampleFp6(T, 5), T.Fp6.inv(sampleFp6(T, 5))), T.Fp6.one));
    try std.testing.expect(T.Fp2.eql(T.Fp2.mul(sampleFp2(T, 7), T.Fp2.inv(sampleFp2(T, 7))), T.Fp2.one));
    // Frobenius is x -> x^p (this also validates that ξ and the tower are right)
    const p = T.Fp.modulus;
    try std.testing.expect(T.Fp12.eql(T.Fp12.frobenius(a, 1), T.Fp12.pow(a, &p)));
    // frob² = frob∘frob, frob³ = frob∘frob∘frob, frob⁶ = conjugation
    const f1 = T.Fp12.frobenius(a, 1);
    try std.testing.expect(T.Fp12.eql(T.Fp12.frobenius(a, 2), T.Fp12.frobenius(f1, 1)));
    try std.testing.expect(T.Fp12.eql(T.Fp12.frobenius(a, 3), T.Fp12.frobenius(T.Fp12.frobenius(f1, 1), 1)));
    try std.testing.expect(T.Fp12.eql(T.Fp12.frobenius(T.Fp12.frobenius(a, 3), 3), T.Fp12.conj(a)));
}

test "tower over BN254 (ξ = 9+u)" {
    const T = Tower(soft.Soft(4, BN_P), 9, 1);
    try towerTests(T);
}

test "tower over BLS12-381 (ξ = 1+u)" {
    const T = Tower(soft.Soft(6, BLS_P), 1, 1);
    try towerTests(T);
}

/// Soft backend that also declares native Fp2 ops, to exercise the `has_native` path
/// (the same layout contract as Pico's FP2_* syscalls) natively.
fn SoftWithFp2(comptime n: usize, comptime mod: [n]u64) type {
    const S = soft.Soft(n, mod);
    return struct {
        pub const limbs = n;
        pub const modulus = mod;
        pub const add = S.add;
        pub const sub = S.sub;
        pub const mul = S.mul;
        pub fn fp2_add(x: *[2 * n]u64, y: *const [2 * n]u64) void {
            S.add(x[0..n], y[0..n]);
            S.add(x[n .. 2 * n], y[n .. 2 * n]);
        }
        pub fn fp2_sub(x: *[2 * n]u64, y: *const [2 * n]u64) void {
            S.sub(x[0..n], y[0..n]);
            S.sub(x[n .. 2 * n], y[n .. 2 * n]);
        }
        pub fn fp2_mul(x: *[2 * n]u64, y: *const [2 * n]u64) void {
            var a0: [n]u64 = x[0..n].*;
            var a1: [n]u64 = x[n .. 2 * n].*;
            const b0: [n]u64 = y[0..n].*;
            const b1: [n]u64 = y[n .. 2 * n].*;
            var t0 = a0;
            S.mul(&t0, &b0);
            var t1 = a1;
            S.mul(&t1, &b1);
            S.mul(&a0, &b1);
            S.mul(&a1, &b0);
            S.sub(&t0, &t1);
            S.add(&a0, &a1);
            x[0..n].* = t0;
            x[n .. 2 * n].* = a0;
        }
    };
}

test "tower with native Fp2 ops agrees with the Fp-built Fp2" {
    const A = Tower(soft.Soft(4, BN_P), 9, 1);
    const N = Tower(SoftWithFp2(4, BN_P), 9, 1);
    const a = sampleFp12(A, 11);
    const b = sampleFp12(A, 12);
    const an: N.Fp12 = @bitCast(a);
    const bn: N.Fp12 = @bitCast(b);
    const ra = A.Fp12.mul(a, b);
    const rn = N.Fp12.mul(an, bn);
    try std.testing.expectEqual(ra, @as(A.Fp12, @bitCast(rn)));
    try towerTests(N);
}
