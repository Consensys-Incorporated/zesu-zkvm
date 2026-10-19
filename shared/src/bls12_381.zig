/// BLS12-381 G1/G2 add + MSM, pairing check, map-to-curve (EIP-2537) and KZG point evaluation
/// (EIP-4844), generic over a base-field backend, plus the native tests and the vector runner.
///
/// `Impl(B)` exposes, for a backend `B` (soft.zig contract), all byte layouts big-endian per
/// EIP-2537:
///   g1Add(p1, p2, result) bool              96-byte x‖y; all zeros = identity
///   g1Msm(pairs, result) bool               pairs: slice of {point: [96]u8, scalar: [32]u8}
///   g2Add(p1, p2, result) bool              192 bytes: x_c0‖x_c1‖y_c0‖y_c1 (48 bytes each)
///   g2Msm(pairs, result) bool               pairs: slice of {point: [192]u8, scalar: [32]u8}
///   pairing(pairs, verified) bool           pairs: slice of {g1: [96]u8, g2: [192]u8}
///   mapFpToG1(fe, result) bool              fe: 48 bytes
///   mapFp2ToG2(fe, result) bool             fe: 96 bytes (c0‖c1)
///   kzgPointEval(commitment, z, y, proof, verified) bool
/// A `false` return means malformed input (coordinate >= p, not on the curve, or, for MSM,
/// pairing and KZG, not in the r-order subgroup). `verified` is only meaningful when true is
/// returned. add does NOT subgroup-check (EIP-2537); empty pairing / MSM inputs are accepted.
///
/// Design. Everything is generic over a base-field backend, so the same code runs natively under
/// `zig test` on a software backend and in a guest on the zkVM's accelerators: field ops,
/// optionally Fp2 ops (`fp2_*`), and optionally G1 point ops (`ec_add` / `ec_double`). Pico is the
/// worked example (FP_* / FP2_* syscalls plus BLS12381_ADD / BLS12381_DOUBLE; see
/// pico/src/zkvm_accel/bls12_381.zig). Without a pairing precompile the pairing
/// is a plain optimal-ate Miller loop on the M-twist plus a final exponentiation whose hard part
/// is a straight exponentiation by (p^4 - p^2 + 1)/r. Unlike OpenVM's kzgVerify, which emits a
/// pairing hint and returns true, kzgPointEval really checks the pairing equation.
const std = @import("std");
const builtin = @import("builtin");
pub const field = @import("field.zig");
pub const tower = @import("tower.zig");
pub const soft = @import("soft.zig");
const mc = @import("bls12_381_map_constants.zig");

comptime {
    if (builtin.cpu.arch.endian() != .little)
        @compileError("bls12_381.zig reinterprets little-endian constant byte arrays as u64 limbs");
}

// ── Constants ────────────────────────────────────────────────────────────────

/// The base field modulus p, little-endian limbs.
pub const P_LIMBS: [6]u64 = .{
    0xb9feffffffffaaab, 0x1eabfffeb153ffff, 0x6730d2a0f6b0f624,
    0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a,
};
/// Subgroup order r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
const R_LIMBS: [4]u64 = .{ 0xffffffff00000001, 0x53bda402fffe5bfe, 0x3339d80809a1d805, 0x73eda753299d7d48 };
const R_BE: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    for (0..4) |i| std.mem.writeInt(u64, out[32 - 8 * (i + 1) ..][0..8], R_LIMBS[i], .big);
    break :blk out;
};
/// |x| for the BLS12-381 parameter x = -0xd201000000010000
const BLS_X_ABS: u64 = 0xd201000000010000;

/// (p^4 - p^2 + 1) / r, the hard part of the final exponentiation (1270 bits -> 20 limbs).
const HARD_EXP: [20]u64 = blk: {
    @setEvalBranchQuota(1_000_000);
    const W = std.meta.Int(.unsigned, 1600);
    var p: W = 0;
    var i: usize = 6;
    while (i > 0) {
        i -= 1;
        p = (p << 64) | P_LIMBS[i];
    }
    var r: W = 0;
    i = 4;
    while (i > 0) {
        i -= 1;
        r = (r << 64) | R_LIMBS[i];
    }
    const p2 = p * p;
    const num = p2 * p2 - p2 + 1;
    const e = num / r;
    if (e * r != num) @compileError("r does not divide p^4 - p^2 + 1");
    var out: [20]u64 = undefined;
    var t = e;
    for (0..20) |k| {
        out[k] = @truncate(t);
        t >>= 64;
    }
    break :blk out;
};

// Generators and the KZG trusted-setup point tau*G2, big-endian (EIP-2537 layout).
pub const G1_GEN_BE = hex(96, "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" ++
    "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1");
const G2_GEN_BE = hex(192, "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8" ++
    "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e" ++
    "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801" ++
    "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be");
const TAU_G2_BE = hex(192, "185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2" ++
    "15bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72" ++
    "014353bdb96b626dd7d5ee8599d1fca2131569490e28de18e82451a496a9c9794ce26d105941f383ee689bfbbb832a99" ++
    "1666c54b0a32529503432fcae0181b4bef79de09fc63671fda5ed1ba9bfa07899495346f3d7ac9cd23048ef30d0a154f");

fn hex(comptime n: usize, comptime s: *const [2 * n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch @compileError("bad hex");
    return out;
}

// ── Generic short-Weierstrass curve (a = 0) over F with y² = x³ + b ─────────
//
// F is a field type exposing add/sub/mul/sq/dbl/neg/inv/isZero/eql/zero/one on values of
// type E. `Hw` is `void`, or a type with add/double on [2]E affine points (a zkVM's G1 point
// accelerators, e.g. Pico's BLS12381_ADD / BLS12381_DOUBLE): then scalar multiplication runs in affine coordinates with one precompile call
// per group operation, otherwise in Jacobian coordinates with a single inversion at the end.

fn Curve(comptime F: type, comptime E: type, comptime b_coeff: E, comptime Hw: type) type {
    return struct {
        pub const Pt = struct { x: E, y: E, inf: bool };
        pub const infinity: Pt = .{ .x = F.zero, .y = F.zero, .inf = true };
        const Jac = struct { x: E, y: E, z: E }; // z == 0: point at infinity
        const jinf: Jac = .{ .x = F.one, .y = F.one, .z = F.zero };

        pub fn neg(p: Pt) Pt {
            if (p.inf) return p;
            return .{ .x = p.x, .y = F.neg(p.y), .inf = false };
        }

        pub fn isOnCurve(p: Pt) bool {
            if (p.inf) return true;
            return F.eql(F.sq(p.y), F.add(F.mul(F.sq(p.x), p.x), b_coeff));
        }

        pub fn double(p: Pt) Pt {
            if (p.inf or F.isZero(p.y)) return infinity;
            if (Hw != void) {
                const r = Hw.double(.{ p.x, p.y });
                return .{ .x = r[0], .y = r[1], .inf = false };
            }
            const x2 = F.sq(p.x);
            const lam = F.mul(F.add(F.dbl(x2), x2), F.inv(F.dbl(p.y)));
            const x3 = F.sub(F.sq(lam), F.dbl(p.x));
            const y3 = F.sub(F.mul(lam, F.sub(p.x, x3)), p.y);
            return .{ .x = x3, .y = y3, .inf = false };
        }

        pub fn add(a: Pt, b: Pt) Pt {
            if (a.inf) return b;
            if (b.inf) return a;
            if (F.eql(a.x, b.x)) {
                if (F.eql(a.y, b.y)) return double(a);
                return infinity; // a == -b
            }
            if (Hw != void) {
                const r = Hw.add(.{ a.x, a.y }, .{ b.x, b.y });
                return .{ .x = r[0], .y = r[1], .inf = false };
            }
            const lam = F.mul(F.sub(b.y, a.y), F.inv(F.sub(b.x, a.x)));
            const x3 = F.sub(F.sub(F.sq(lam), a.x), b.x);
            const y3 = F.sub(F.mul(lam, F.sub(a.x, x3)), a.y);
            return .{ .x = x3, .y = y3, .inf = false };
        }

        fn jdbl(p: Jac) Jac {
            if (F.isZero(p.z)) return p;
            const a = F.sq(p.x);
            const b = F.sq(p.y);
            const c = F.sq(b);
            const d = F.dbl(F.sub(F.sub(F.sq(F.add(p.x, b)), a), c));
            const e = F.add(F.dbl(a), a);
            const x3 = F.sub(F.sq(e), F.dbl(d));
            const y3 = F.sub(F.mul(e, F.sub(d, x3)), F.dbl(F.dbl(F.dbl(c))));
            const z3 = F.dbl(F.mul(p.y, p.z));
            return .{ .x = x3, .y = y3, .z = z3 };
        }

        /// Jacobian + affine (q must not be the identity).
        fn jmadd(p: Jac, q: Pt) Jac {
            if (F.isZero(p.z)) return .{ .x = q.x, .y = q.y, .z = F.one };
            const z1z1 = F.sq(p.z);
            const uu2 = F.mul(q.x, z1z1);
            const s2 = F.mul(F.mul(q.y, p.z), z1z1);
            const h = F.sub(uu2, p.x);
            if (F.isZero(h)) {
                if (F.eql(s2, p.y)) return jdbl(p);
                return jinf;
            }
            const hh = F.sq(h);
            const i = F.dbl(F.dbl(hh));
            const j = F.mul(h, i);
            const r = F.dbl(F.sub(s2, p.y));
            const v = F.mul(p.x, i);
            const x3 = F.sub(F.sub(F.sq(r), j), F.dbl(v));
            const y3 = F.sub(F.mul(r, F.sub(v, x3)), F.dbl(F.mul(p.y, j)));
            const z3 = F.sub(F.sub(F.sq(F.add(p.z, h)), z1z1), hh);
            return .{ .x = x3, .y = y3, .z = z3 };
        }

        fn toAffine(p: Jac) Pt {
            if (F.isZero(p.z)) return infinity;
            const zi = F.inv(p.z);
            const zi2 = F.sq(zi);
            return .{ .x = F.mul(p.x, zi2), .y = F.mul(F.mul(p.y, zi2), zi), .inf = false };
        }

        /// k * p for a big-endian scalar of any length (not reduced).
        pub fn mulBE(p: Pt, scalar: []const u8) Pt {
            if (p.inf) return infinity;
            if (Hw != void) {
                var acc = infinity;
                for (scalar) |byte| {
                    for (0..8) |k| {
                        acc = double(acc);
                        if ((byte >> @intCast(7 - k)) & 1 == 1) acc = add(acc, p);
                    }
                }
                return acc;
            }
            var acc = jinf;
            for (scalar) |byte| {
                for (0..8) |k| {
                    acc = jdbl(acc);
                    if ((byte >> @intCast(7 - k)) & 1 == 1) acc = jmadd(acc, p);
                }
            }
            return toAffine(acc);
        }

        /// k * p for a little-endian scalar of up to 96 bytes.
        pub fn mulLE(p: Pt, scalar: []const u8) Pt {
            var be: [96]u8 = undefined;
            std.debug.assert(scalar.len <= be.len);
            for (scalar, 0..) |b, i| be[scalar.len - 1 - i] = b;
            return mulBE(p, be[0..scalar.len]);
        }
    };
}

/// G1 point ops on a backend's `ec_add` / `ec_double` accelerators (e.g. Pico's BLS12381_ADD /
/// BLS12381_DOUBLE): affine, x‖y little-endian limbs.
fn G1Hw(comptime B: type, comptime Fe: type) type {
    return struct {
        pub fn add(p: [2]Fe, q: [2]Fe) [2]Fe {
            var a: [12]u64 align(8) = undefined;
            var b: [12]u64 align(8) = undefined;
            a[0..6].* = p[0];
            a[6..12].* = p[1];
            b[0..6].* = q[0];
            b[6..12].* = q[1];
            B.ec_add(&a, &b);
            return .{ a[0..6].*, a[6..12].* };
        }
        pub fn double(p: [2]Fe) [2]Fe {
            var a: [12]u64 align(8) = undefined;
            a[0..6].* = p[0];
            a[6..12].* = p[1];
            B.ec_double(&a);
            return .{ a[0..6].*, a[6..12].* };
        }
    };
}

// ── Pair types (the layout of the zkVM host ABI's pair structs, e.g. pico_host.zig) ──

pub const G1MsmPair = extern struct { point: [96]u8, scalar: [32]u8 };
pub const G2MsmPair = extern struct { point: [192]u8, scalar: [32]u8 };
pub const PairingPair = extern struct { g1: [96]u8, g2: [192]u8 };

// ── The implementation, generic over the base-field backend ──────────────────

pub fn Impl(comptime B: type) type {
    return struct {
        const T = tower.Tower(B, 1, 1);
        pub const Fp = T.Fp;
        pub const Fp2 = T.Fp2;
        pub const Fp12 = T.Fp12;
        const Fe = Fp.Fe;

        const b1: Fe = Fp.fromU64(4);
        const b2: Fp2 = .{ .c0 = Fp.fromU64(4), .c1 = Fp.fromU64(4) };
        const Hw = if (@hasDecl(B, "ec_add")) G1Hw(B, Fe) else void;
        pub const G1 = Curve(Fp, Fe, b1, Hw);
        pub const G2 = Curve(Fp2, Fp2, b2, void);

        // ── encodings ─────────────────────────────────────────────────────────

        fn fpFromBE(b: *const [48]u8) ?Fe {
            const e = Fp.fromBytesBE(b);
            return if (Fp.isCanonical(e)) e else null;
        }

        /// 96 big-endian bytes; null if a coordinate is >= p or the point is not on the curve.
        pub fn g1FromBE(b: *const [96]u8) ?G1.Pt {
            const x = fpFromBE(b[0..48]) orelse return null;
            const y = fpFromBE(b[48..96]) orelse return null;
            if (Fp.isZero(x) and Fp.isZero(y)) return G1.infinity;
            const p = G1.Pt{ .x = x, .y = y, .inf = false };
            return if (G1.isOnCurve(p)) p else null;
        }

        pub fn g1ToBE(p: G1.Pt, out: *[96]u8) void {
            if (p.inf) {
                @memset(out, 0);
                return;
            }
            out[0..48].* = Fp.toBytesBE(p.x);
            out[48..96].* = Fp.toBytesBE(p.y);
        }

        pub fn g2FromBE(b: *const [192]u8) ?G2.Pt {
            const x0 = fpFromBE(b[0..48]) orelse return null;
            const x1 = fpFromBE(b[48..96]) orelse return null;
            const y0 = fpFromBE(b[96..144]) orelse return null;
            const y1 = fpFromBE(b[144..192]) orelse return null;
            const x = Fp2{ .c0 = x0, .c1 = x1 };
            const y = Fp2{ .c0 = y0, .c1 = y1 };
            if (Fp2.isZero(x) and Fp2.isZero(y)) return G2.infinity;
            const p = G2.Pt{ .x = x, .y = y, .inf = false };
            return if (G2.isOnCurve(p)) p else null;
        }

        pub fn g2ToBE(p: G2.Pt, out: *[192]u8) void {
            if (p.inf) {
                @memset(out, 0);
                return;
            }
            out[0..48].* = Fp.toBytesBE(p.x.c0);
            out[48..96].* = Fp.toBytesBE(p.x.c1);
            out[96..144].* = Fp.toBytesBE(p.y.c0);
            out[144..192].* = Fp.toBytesBE(p.y.c1);
        }

        pub fn g1InSubgroup(p: G1.Pt) bool {
            return G1.mulBE(p, &R_BE).inf;
        }
        pub fn g2InSubgroup(p: G2.Pt) bool {
            return G2.mulBE(p, &R_BE).inf;
        }

        // ── EIP-2537 add / MSM ────────────────────────────────────────────────

        pub fn g1Add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) bool {
            const a = g1FromBE(p1) orelse return false;
            const b = g1FromBE(p2) orelse return false;
            g1ToBE(G1.add(a, b), result);
            return true;
        }

        pub fn g1Msm(pairs: anytype, result: *[96]u8) bool {
            var acc = G1.infinity;
            for (pairs) |*pr| {
                const p = g1FromBE(&pr.point) orelse return false;
                if (!g1InSubgroup(p)) return false;
                acc = G1.add(acc, G1.mulBE(p, &pr.scalar));
            }
            g1ToBE(acc, result);
            return true;
        }

        pub fn g2Add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) bool {
            const a = g2FromBE(p1) orelse return false;
            const b = g2FromBE(p2) orelse return false;
            g2ToBE(G2.add(a, b), result);
            return true;
        }

        pub fn g2Msm(pairs: anytype, result: *[192]u8) bool {
            var acc = G2.infinity;
            for (pairs) |*pr| {
                const p = g2FromBE(&pr.point) orelse return false;
                if (!g2InSubgroup(p)) return false;
                acc = G2.add(acc, G2.mulBE(p, &pr.scalar));
            }
            g2ToBE(acc, result);
            return true;
        }

        // ── Pairing ───────────────────────────────────────────────────────────
        //
        // Optimal ate pairing, M-type sextic twist E': y² = x³ + 4ξ (ξ = 1+u), untwist
        // ψ(x', y') = (x'/w², y'/w³) with w⁶ = ξ. The line through T with slope λ' (computed on
        // the twist) evaluated at P = (xP, yP) and scaled by ξ (a factor in Fp2 ⊂ Fp6, removed by
        // the final exponentiation) is the sparse Fp12 element
        //     ξ·yP  +  (λ'·xT − yT)·w³  −  λ'·xP·w⁵.

        fn line(lam: Fp2, t: G2.Pt, p: G1.Pt) Fp12 {
            var l = Fp12.zero;
            l.c0.c0 = Fp2.mulByFp(Fp2.xi, p.y);
            l.c1.c1 = Fp2.sub(Fp2.mul(lam, t.x), t.y);
            l.c1.c2 = Fp2.neg(Fp2.mulByFp(lam, p.x));
            return l;
        }

        fn lineDouble(t: *G2.Pt, p: G1.Pt) Fp12 {
            const x2 = Fp2.sq(t.x);
            const lam = Fp2.mul(Fp2.add(Fp2.dbl(x2), x2), Fp2.inv(Fp2.dbl(t.y)));
            const l = line(lam, t.*, p);
            const x3 = Fp2.sub(Fp2.sq(lam), Fp2.dbl(t.x));
            const y3 = Fp2.sub(Fp2.mul(lam, Fp2.sub(t.x, x3)), t.y);
            t.* = .{ .x = x3, .y = y3, .inf = false };
            return l;
        }

        fn lineAdd(t: *G2.Pt, q: G2.Pt, p: G1.Pt) Fp12 {
            const lam = Fp2.mul(Fp2.sub(q.y, t.y), Fp2.inv(Fp2.sub(q.x, t.x)));
            const l = line(lam, t.*, p);
            const x3 = Fp2.sub(Fp2.sub(Fp2.sq(lam), t.x), q.x);
            const y3 = Fp2.sub(Fp2.mul(lam, Fp2.sub(t.x, x3)), t.y);
            t.* = .{ .x = x3, .y = y3, .inf = false };
            return l;
        }

        /// Miller loop for non-identity P in G1, Q in G2 (both in their prime-order subgroups).
        pub fn millerLoop(p: G1.Pt, q: G2.Pt) Fp12 {
            var f = Fp12.one;
            var t = q;
            var i: usize = 63;
            while (i > 0) {
                i -= 1;
                f = Fp12.mul(Fp12.sq(f), lineDouble(&t, p));
                if ((BLS_X_ABS >> @intCast(i)) & 1 == 1) f = Fp12.mul(f, lineAdd(&t, q, p));
            }
            return Fp12.conj(f); // x is negative
        }

        /// f^((p^12 - 1)/r)
        pub fn finalExp(f: Fp12) Fp12 {
            const f1 = Fp12.mul(Fp12.conj(f), Fp12.inv(f)); // f^(p^6 - 1)
            const f2 = Fp12.mul(Fp12.frobenius(f1, 2), f1); // ^(p^2 + 1)
            return Fp12.pow(f2, &HARD_EXP);
        }

        /// Reduced pairing e(P, Q); identity if either input is the identity.
        pub fn pair(p: G1.Pt, q: G2.Pt) Fp12 {
            if (p.inf or q.inf) return Fp12.one;
            return finalExp(millerLoop(p, q));
        }

        pub fn pairing(pairs: anytype, verified: *bool) bool {
            verified.* = false;
            var f = Fp12.one;
            for (pairs) |*pr| {
                const p = g1FromBE(&pr.g1) orelse return false;
                const q = g2FromBE(&pr.g2) orelse return false;
                if (!g1InSubgroup(p) or !g2InSubgroup(q)) return false;
                if (p.inf or q.inf) continue;
                f = Fp12.mul(f, millerLoop(p, q));
            }
            verified.* = Fp12.isOne(finalExp(f));
            return true;
        }

        // ── KZG point evaluation (EIP-4844) ───────────────────────────────────

        /// ZCash/IETF compressed G1: bit 7 compressed, bit 6 infinity, bit 5 "y is the larger
        /// root". Null if malformed. Does not check the subgroup.
        fn decompressG1(c: *const [48]u8) ?G1.Pt {
            if (c[0] & 0x80 == 0) return null;
            const inf = c[0] & 0x40 != 0;
            const sign = c[0] & 0x20 != 0;
            var xb = c.*;
            xb[0] &= 0x1f;
            if (inf) {
                if (sign) return null;
                for (xb) |b| if (b != 0) return null;
                return G1.infinity;
            }
            const x = fpFromBE(&xb) orelse return null;
            var y = Fp.sqrt(Fp.add(Fp.mul(Fp.sq(x), x), b1)) orelse return null;
            const larger = Fp.cmp(y, Fp.exp_p_minus_1_div_2) == .gt;
            if (larger != sign) y = Fp.neg(y);
            return .{ .x = x, .y = y, .inf = false };
        }

        fn scalarCanonical(s: *const [32]u8) bool {
            return std.mem.order(u8, s, &R_BE) == .lt;
        }

        /// e(C - [y]G1, G2) * e(-proof, [tau]G2 - [z]G2) == 1. Returns false only for malformed
        /// input; a well-formed but wrong proof returns true with verified = false.
        pub fn kzgPointEval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) bool {
            verified.* = false;
            if (!scalarCanonical(z) or !scalarCanonical(y)) return false;
            const c = decompressG1(commitment) orelse return false;
            const pi = decompressG1(proof) orelse return false;
            if (!g1InSubgroup(c) or !g1InSubgroup(pi)) return false;

            const gen1 = g1FromBE(&G1_GEN_BE).?;
            const gen2 = g2FromBE(&G2_GEN_BE).?;
            const tau = g2FromBE(&TAU_G2_BE).?;

            const p1 = G1.add(c, G1.neg(G1.mulBE(gen1, y)));
            const q2 = G2.add(tau, G2.neg(G2.mulBE(gen2, z)));

            var f = Fp12.one;
            if (!p1.inf) f = Fp12.mul(f, millerLoop(p1, gen2));
            if (!pi.inf and !q2.inf) f = Fp12.mul(f, millerLoop(G1.neg(pi), q2));
            verified.* = Fp12.isOne(finalExp(f));
            return true;
        }

        // ── Map to curve (EIP-2537 MAP_FP_TO_G1 / MAP_FP2_TO_G2) ──────────────
        //
        // RFC 9380 simplified SWU onto an isogenous curve, the isogeny back to BLS12-381, then
        // cofactor clearing. Mirrors py_ecc step for step (as OpenVM's port does); constants
        // come from bls12_381_map_constants.zig (little-endian bytes = little-endian u64 limbs).

        fn feLe(comptime bytes: *const [48]u8) Fe {
            return @bitCast(bytes.*);
        }
        fn fe2Le(comptime bytes: *const [96]u8) Fp2 {
            return @bitCast(bytes.*);
        }
        fn limbsLe(comptime n: usize, comptime bytes: *const [8 * n]u8) [n]u64 {
            return @bitCast(bytes.*);
        }

        fn sgn0Fp(a: Fe) u1 {
            return @truncate(a[0]);
        }
        fn sgn0Fp2(a: Fp2) u1 {
            const sign_0: u1 = @truncate(a.c0[0]);
            const zero_0: u1 = @intFromBool(Fp.isZero(a.c0));
            const sign_1: u1 = @truncate(a.c1[0]);
            return sign_0 | (zero_0 & sign_1);
        }

        const Proj1 = struct { x: Fe, y: Fe, z: Fe };
        const Proj2 = struct { x: Fp2, y: Fp2, z: Fp2 };

        fn swuG1(t: Fe) Proj1 {
            const A = comptime feLe(&mc.ISO_11_A);
            const Bc = comptime feLe(&mc.ISO_11_B);
            const Z = comptime feLe(&mc.ISO_11_Z);
            const t2 = Fp.sq(t);
            const zt2 = Fp.mul(Z, t2);
            var temp = Fp.add(zt2, Fp.sq(zt2)); // Z·t² + Z²·t⁴
            var den = Fp.neg(Fp.mul(A, temp));
            temp = Fp.add(temp, Fp.one);
            var num = Fp.mul(Bc, temp);
            if (Fp.isZero(den)) den = Fp.mul(Z, A);

            // v = D³, u = N³ + A·N·D² + B·D³
            const den2 = Fp.sq(den);
            const v = Fp.mul(den2, den);
            const u = Fp.add(Fp.add(Fp.mul(Fp.sq(num), num), Fp.mul(Fp.mul(A, num), den2)), Fp.mul(Bc, v));

            // sqrt_division_FQ: y = uv·(uv·v²)^((p−3)/4); a root iff y²·v = u.
            const uv = Fp.mul(u, v);
            var y = Fp.mul(uv, Fp.pow(Fp.mul(uv, Fp.sq(v)), &comptime limbsLe(6, &mc.P_MINUS_3_DIV_4)));
            if (!Fp.isZero(Fp.sub(Fp.mul(Fp.sq(y), v), u))) {
                y = Fp.mul(Fp.mul(y, Fp.mul(t2, t)), comptime feLe(&mc.SQRT_MINUS_11_CUBED));
                num = Fp.mul(num, zt2);
            }
            if (sgn0Fp(t) != sgn0Fp(y)) y = Fp.neg(y);
            return .{ .x = num, .y = Fp.mul(y, den), .z = den };
        }

        /// Horner evaluation as py_ecc: k[last], then acc = acc·x + z^(j+1)·k[last−1−j].
        fn hornerFp(comptime k: anytype, x: Fe, z_pows: []const Fe) Fe {
            var out = feLe(&k[k.len - 1]);
            inline for (0..k.len - 1) |j| {
                out = Fp.add(Fp.mul(out, x), Fp.mul(z_pows[j], feLe(&k[k.len - 2 - j])));
            }
            return out;
        }

        fn hornerFp2(comptime k: anytype, x: Fp2, z_pows: []const Fp2) Fp2 {
            var out = fe2Le(&k[k.len - 1]);
            inline for (0..k.len - 1) |j| {
                out = Fp2.add(Fp2.mul(out, x), Fp2.mul(z_pows[j], fe2Le(&k[k.len - 2 - j])));
            }
            return out;
        }

        fn isoMapG1(p: Proj1) Proj1 {
            var z_pows: [15]Fe = undefined;
            z_pows[0] = p.z;
            for (1..z_pows.len) |i| z_pows[i] = Fp.mul(z_pows[i - 1], p.z);
            const x_num = hornerFp(mc.ISO_11_X_NUM, p.x, &z_pows);
            var x_den = hornerFp(mc.ISO_11_X_DEN, p.x, &z_pows);
            var y_num = hornerFp(mc.ISO_11_Y_NUM, p.x, &z_pows);
            var y_den = hornerFp(mc.ISO_11_Y_DEN, p.x, &z_pows);
            x_den = Fp.mul(x_den, p.z); // x-denominator is one degree lower
            y_num = Fp.mul(y_num, p.y);
            y_den = Fp.mul(y_den, p.z);
            return .{ .x = Fp.mul(x_num, y_den), .y = Fp.mul(x_den, y_num), .z = Fp.mul(x_den, y_den) };
        }

        fn swuG2(t: Fp2) Proj2 {
            const A = comptime fe2Le(&mc.ISO_3_A);
            const Bc = comptime fe2Le(&mc.ISO_3_B);
            const Z = comptime fe2Le(&mc.ISO_3_Z);
            const t2 = Fp2.sq(t);
            const zt2 = Fp2.mul(Z, t2);
            var temp = Fp2.add(zt2, Fp2.sq(zt2)); // Z·t² + Z²·t⁴
            var den = Fp2.neg(Fp2.mul(A, temp));
            temp = Fp2.add(temp, Fp2.one);
            var num = Fp2.mul(Bc, temp);
            if (Fp2.isZero(den)) den = Fp2.mul(Z, A);

            const den2 = Fp2.sq(den);
            const v = Fp2.mul(den2, den);
            const u = Fp2.add(Fp2.add(Fp2.mul(Fp2.sq(num), num), Fp2.mul(Fp2.mul(A, num), den2)), Fp2.mul(Bc, v));

            // sqrt_division_FQ2: gamma = uv⁷·(uv¹⁵)^((p²−9)/16); a root is root·gamma for the
            // first eighth root of unity with (root·gamma)²·v = u.
            const v2 = Fp2.sq(v);
            const v4 = Fp2.sq(v2);
            const v7 = Fp2.mul(Fp2.mul(v4, v2), v);
            const v8 = Fp2.sq(v4);
            const temp1 = Fp2.mul(u, v7);
            var gamma = Fp2.pow(Fp2.mul(temp1, v8), &comptime limbsLe(12, &mc.P_MINUS_9_DIV_16));
            gamma = Fp2.mul(gamma, temp1);

            var y = gamma;
            var success = false;
            inline for (mc.POSITIVE_EIGHTH_ROOTS_OF_UNITY) |root| {
                const cand = Fp2.mul(fe2Le(&root), gamma);
                if (Fp2.isZero(Fp2.sub(Fp2.mul(Fp2.sq(cand), v), u)) and !success) {
                    success = true;
                    y = cand;
                }
            }

            // Not a square: try x1 = Z·t²·x0, whose root is eta·sqrt_candidate·t³.
            const sqrt_candidate = Fp2.mul(y, Fp2.mul(t2, t));
            const u_x1 = Fp2.mul(Fp2.mul(Fp2.sq(zt2), zt2), u); // Z³·t⁶·u
            var success_2 = false;
            inline for (mc.ETAS) |eta| {
                const cand = Fp2.mul(fe2Le(&eta), sqrt_candidate);
                if (Fp2.isZero(Fp2.sub(Fp2.mul(Fp2.sq(cand), v), u_x1)) and !success and !success_2) {
                    y = cand;
                    success_2 = true;
                }
            }
            if (!success) num = Fp2.mul(num, zt2);

            if (sgn0Fp2(t) != sgn0Fp2(y)) y = Fp2.neg(y);
            return .{ .x = num, .y = Fp2.mul(y, den), .z = den };
        }

        fn isoMapG2(p: Proj2) Proj2 {
            var z_pows: [3]Fp2 = undefined;
            z_pows[0] = p.z;
            for (1..z_pows.len) |i| z_pows[i] = Fp2.mul(z_pows[i - 1], p.z);
            const x_num = hornerFp2(mc.ISO_3_X_NUM, p.x, &z_pows);
            const x_den = hornerFp2(mc.ISO_3_X_DEN, p.x, &z_pows);
            var y_num = hornerFp2(mc.ISO_3_Y_NUM, p.x, &z_pows);
            var y_den = hornerFp2(mc.ISO_3_Y_DEN, p.x, &z_pows);
            y_num = Fp2.mul(y_num, p.y);
            y_den = Fp2.mul(y_den, p.z);
            return .{ .x = Fp2.mul(x_num, y_den), .y = Fp2.mul(x_den, y_num), .z = Fp2.mul(x_den, y_den) };
        }

        pub fn mapFpToG1(field_element: *const [48]u8, result: *[96]u8) bool {
            const t = fpFromBE(field_element) orelse return false;
            const iso = isoMapG1(swuG1(t));
            var p = G1.infinity;
            if (!Fp.isZero(iso.z)) {
                const zi = Fp.inv(iso.z);
                p = .{ .x = Fp.mul(iso.x, zi), .y = Fp.mul(iso.y, zi), .inf = false };
            }
            g1ToBE(G1.mulLE(p, &mc.H_EFF_G1), result);
            return true;
        }

        pub fn mapFp2ToG2(field_element: *const [96]u8, result: *[192]u8) bool {
            const c0 = fpFromBE(field_element[0..48]) orelse return false;
            const c1 = fpFromBE(field_element[48..96]) orelse return false;
            const iso = isoMapG2(swuG2(.{ .c0 = c0, .c1 = c1 }));
            var p = G2.infinity;
            if (!Fp2.isZero(iso.z)) {
                const zi = Fp2.inv(iso.z);
                p = .{ .x = Fp2.mul(iso.x, zi), .y = Fp2.mul(iso.y, zi), .inf = false };
            }
            g2ToBE(G2.mulLE(p, &mc.H_EFF_G2), result);
            return true;
        }
    };
}

// ── Vector runner (shared by the native tests and the guest self-tests) ──────

pub const vectors = @import("bls12_381_vectors.zig");
const kzg_vectors = @import("bls12_381_kzg_vectors.zig");

pub const Kind = enum { g1_add, g2_add, g1_msm, g2_msm, pairing, fp_to_g1, fp2_to_g2 };

/// A padded EIP-2537 Fp is 16 zero bytes + 48 big-endian bytes; null if the padding is not zero.
fn unpadFp(b: []const u8, out: *[48]u8) bool {
    for (b[0..16]) |x| if (x != 0) return false;
    out.* = b[16..64].*;
    return true;
}

fn padFp(fe: []const u8, out: []u8) void {
    @memset(out[0..16], 0);
    @memcpy(out[16..64], fe[0..48]);
}

fn unpadG1(b: []const u8, out: *[96]u8) bool {
    return unpadFp(b[0..64], out[0..48]) and unpadFp(b[64..128], out[48..96]);
}
fn unpadG2(b: []const u8, out: *[192]u8) bool {
    inline for (0..4) |i| {
        if (!unpadFp(b[64 * i ..][0..64], out[48 * i ..][0..48])) return false;
    }
    return true;
}
fn padG1(p: *const [96]u8, out: *[128]u8) void {
    padFp(p[0..48], out[0..64]);
    padFp(p[48..96], out[64..128]);
}
fn padG2(p: *const [192]u8, out: *[256]u8) void {
    inline for (0..4) |i| padFp(p[48 * i ..][0..48], out[64 * i ..][0..64]);
}

const max_msm_pairs = 130; // the largest Besu MSM vector has 129 G1 pairs
const max_pairing_pairs = 16;

fn stripHexPrefix(h: []const u8) []const u8 {
    return if (h.len >= 2 and h[0] == '0' and (h[1] == 'x' or h[1] == 'X')) h[2..] else h;
}

/// Run one EIP-2537 vector through `I` (an Impl type). `expected` empty means the input must
/// be rejected. Returns true if the behaviour matches.
pub fn runVector(comptime I: type, comptime kind: Kind, input_hex_raw: []const u8, expected_hex_raw: []const u8) bool {
    const input_hex = stripHexPrefix(input_hex_raw);
    const expected_hex = stripHexPrefix(expected_hex_raw);
    var in_buf: [24576]u8 = undefined;
    var exp_buf: [512]u8 = undefined;
    if (input_hex.len % 2 != 0 or input_hex.len / 2 > in_buf.len) return false;
    const input = in_buf[0 .. input_hex.len / 2];
    _ = std.fmt.hexToBytes(input, input_hex) catch return false;
    if (expected_hex.len / 2 > exp_buf.len) return false;
    const expected = exp_buf[0 .. expected_hex.len / 2];
    _ = std.fmt.hexToBytes(expected, expected_hex) catch return false;
    const want_ok = expected.len != 0;

    var out128: [128]u8 = undefined;
    var out256: [256]u8 = undefined;
    var ok = false; // did the implementation accept the input
    var produced: []const u8 = &.{};

    switch (kind) {
        .g1_add => {
            if (input.len != 256) return !want_ok;
            var a: [96]u8 = undefined;
            var b: [96]u8 = undefined;
            if (!unpadG1(input[0..128], &a) or !unpadG1(input[128..256], &b)) return !want_ok;
            var r: [96]u8 = undefined;
            ok = I.g1Add(&a, &b, &r);
            if (ok) {
                padG1(&r, &out128);
                produced = &out128;
            }
        },
        .g2_add => {
            if (input.len != 512) return !want_ok;
            var a: [192]u8 = undefined;
            var b: [192]u8 = undefined;
            if (!unpadG2(input[0..256], &a) or !unpadG2(input[256..512], &b)) return !want_ok;
            var r: [192]u8 = undefined;
            ok = I.g2Add(&a, &b, &r);
            if (ok) {
                padG2(&r, &out256);
                produced = &out256;
            }
        },
        .g1_msm => {
            if (input.len == 0 or input.len % 160 != 0 or input.len / 160 > max_msm_pairs) return !want_ok;
            var pairs: [max_msm_pairs]G1MsmPair = undefined;
            const n = input.len / 160;
            for (0..n) |i| {
                if (!unpadG1(input[160 * i ..][0..128], &pairs[i].point)) return !want_ok;
                pairs[i].scalar = input[160 * i + 128 ..][0..32].*;
            }
            var r: [96]u8 = undefined;
            ok = I.g1Msm(pairs[0..n], &r);
            if (ok) {
                padG1(&r, &out128);
                produced = &out128;
            }
        },
        .g2_msm => {
            if (input.len == 0 or input.len % 288 != 0 or input.len / 288 > max_msm_pairs) return !want_ok;
            var pairs: [max_msm_pairs]G2MsmPair = undefined;
            const n = input.len / 288;
            for (0..n) |i| {
                if (!unpadG2(input[288 * i ..][0..256], &pairs[i].point)) return !want_ok;
                pairs[i].scalar = input[288 * i + 256 ..][0..32].*;
            }
            var r: [192]u8 = undefined;
            ok = I.g2Msm(pairs[0..n], &r);
            if (ok) {
                padG2(&r, &out256);
                produced = &out256;
            }
        },
        .pairing => {
            if (input.len == 0 or input.len % 384 != 0 or input.len / 384 > max_pairing_pairs) return !want_ok;
            var pairs: [max_pairing_pairs]PairingPair = undefined;
            const n = input.len / 384;
            for (0..n) |i| {
                if (!unpadG1(input[384 * i ..][0..128], &pairs[i].g1)) return !want_ok;
                if (!unpadG2(input[384 * i + 128 ..][0..256], &pairs[i].g2)) return !want_ok;
            }
            var verified = false;
            ok = I.pairing(pairs[0..n], &verified);
            if (ok) {
                out128[0..31].* = .{0} ** 31;
                out128[31] = @intFromBool(verified);
                produced = out128[0..32];
            }
        },
        .fp_to_g1 => {
            if (input.len != 64) return !want_ok;
            var fe: [48]u8 = undefined;
            if (!unpadFp(input, &fe)) return !want_ok;
            var r: [96]u8 = undefined;
            ok = I.mapFpToG1(&fe, &r);
            if (ok) {
                padG1(&r, &out128);
                produced = &out128;
            }
        },
        .fp2_to_g2 => {
            if (input.len != 128) return !want_ok;
            var fe: [96]u8 = undefined;
            if (!unpadFp(input[0..64], fe[0..48]) or !unpadFp(input[64..128], fe[48..96])) return !want_ok;
            var r: [192]u8 = undefined;
            ok = I.mapFp2ToG2(&fe, &r);
            if (ok) {
                padG2(&r, &out256);
                produced = &out256;
            }
        },
    }
    if (!want_ok) return !ok;
    return ok and std.mem.eql(u8, produced, expected);
}

/// One c-kzg vector: expect true / false (valid / wrong proof) or null (input must be rejected).
fn runKzg(comptime I: type, c: kzg_vectors.Case) bool {
    var commitment: [48]u8 = undefined;
    var proof: [48]u8 = undefined;
    var z: [32]u8 = undefined;
    var y: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&commitment, c.commitment) catch return false;
    _ = std.fmt.hexToBytes(&proof, c.proof) catch return false;
    _ = std.fmt.hexToBytes(&z, c.z) catch return false;
    _ = std.fmt.hexToBytes(&y, c.y) catch return false;
    var verified = true;
    const ok = I.kzgPointEval(&commitment, &z, &y, &proof, &verified);
    if (c.expect) |want| return ok and verified == want;
    return !ok;
}

/// `full` = every KZG case; otherwise (the guest, where each pairing costs ~100M cycles) only a
/// representative few of the valid / wrong-proof cases plus all the cheap malformed-input rejections.
pub fn runAllVectors(comptime I: type, comptime name: []const u8, comptime full: bool) bool {
    var good = true;
    inline for (.{
        .{ Kind.g1_add, vectors.g1_add },
        .{ Kind.g2_add, vectors.g2_add },
        .{ Kind.g1_msm, vectors.g1_msm },
        .{ Kind.g2_msm, vectors.g2_msm },
        .{ Kind.pairing, vectors.pairing },
        .{ Kind.fp_to_g1, vectors.fp_to_g1 },
        .{ Kind.fp2_to_g2, vectors.fp2_to_g2 },
        .{ Kind.g1_add, vectors.g1_add_invalid },
        .{ Kind.pairing, vectors.pairing_invalid_subgroup },
    }) |group| {
        for (group[1]) |v| {
            if (!runVector(I, group[0], v.input, v.expected)) {
                logf(name ++ ": EIP-2537 vector FAILED: {s}\n", .{@tagName(group[0])});
                good = false;
            }
        }
    }
    for (kzg_vectors.cases) |c| {
        if (!full and c.expect != null and !guestKzgSubset(c.name)) continue;
        if (!runKzg(I, c)) {
            logf(name ++ ": KZG vector FAILED: {s}\n", .{c.name});
            good = false;
        }
    }
    return good;
}

fn guestKzgSubset(name: []const u8) bool {
    const keep = [_][]const u8{ "correct_proof_1_0", "correct_proof_point_at_infinity_for_zero_poly_0", "incorrect_proof_1_0" };
    for (keep) |k| if (std.mem.eql(u8, name, k)) return true;
    return false;
}

/// Where `logf` output goes outside `zig test` (which uses std.debug.print). A zkVM target sets
/// this to its stdout/stderr write before running a self-test; unset, messages are dropped.
pub var write_hook: ?*const fn (msg: []const u8) void = null;

pub fn logf(comptime fmt: []const u8, args: anytype) void {
    if (builtin.is_test) {
        std.debug.print(fmt, args);
    } else if (write_hook) |hook| {
        var buf: [160]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
        hook(msg);
    }
}

// ── Native tests ─────────────────────────────────────────────────────────────

/// Native test backend: Montgomery (CIOS) arithmetic on u64 limbs with canonical in/out
/// (mul = montmul(montmul(x, y), R²)). ~50x faster than soft.zig's u768 `%`, which matters
/// because the pairing needs hundreds of thousands of multiplications per evaluation.
fn FastSoft(comptime n: usize, comptime mod: [n]u64) type {
    const n0inv: u64 = blk: {
        // -mod^-1 mod 2^64 by Newton iteration
        var inv: u64 = 1;
        for (0..6) |_| inv *%= 2 -% mod[0] *% inv;
        break :blk 0 -% inv;
    };
    const r2: [n]u64 = blk: {
        // 2^(2*64*n) mod p by repeated doubling of 1
        const W = std.meta.Int(.unsigned, n * 64 + 1);
        var pm: W = 0;
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            pm = (pm << 64) | mod[i];
        }
        var x: W = 1;
        @setEvalBranchQuota(100_000);
        for (0..2 * 64 * n) |_| {
            x <<= 1;
            if (x >= pm) x -= pm;
        }
        var out: [n]u64 = undefined;
        for (0..n) |k| {
            out[k] = @truncate(x);
            x >>= 64;
        }
        break :blk out;
    };
    return struct {
        pub const limbs = n;
        pub const modulus = mod;

        fn geq(a: [n]u64, b: [n]u64) bool {
            var i: usize = n;
            while (i > 0) {
                i -= 1;
                if (a[i] != b[i]) return a[i] > b[i];
            }
            return true;
        }

        fn subMod(a: *[n]u64) void {
            var borrow: u64 = 0;
            for (0..n) |i| {
                const d1 = @subWithOverflow(a[i], mod[i]);
                const d2 = @subWithOverflow(d1[0], borrow);
                a[i] = d2[0];
                borrow = @as(u64, d1[1]) | d2[1];
            }
        }

        fn montmul(a: [n]u64, b: [n]u64) [n]u64 {
            var t: [n + 2]u64 = .{0} ** (n + 2);
            for (0..n) |i| {
                var carry: u64 = 0;
                for (0..n) |j| {
                    const v: u128 = @as(u128, a[j]) * b[i] + t[j] + carry;
                    t[j] = @truncate(v);
                    carry = @intCast(v >> 64);
                }
                const s1: u128 = @as(u128, t[n]) + carry;
                t[n] = @truncate(s1);
                t[n + 1] = @intCast(s1 >> 64);

                const m = t[0] *% n0inv;
                const v0: u128 = @as(u128, m) * mod[0] + t[0];
                carry = @intCast(v0 >> 64);
                for (1..n) |j| {
                    const v: u128 = @as(u128, m) * mod[j] + t[j] + carry;
                    t[j - 1] = @truncate(v);
                    carry = @intCast(v >> 64);
                }
                const s2: u128 = @as(u128, t[n]) + carry;
                t[n - 1] = @truncate(s2);
                t[n] = t[n + 1] + @as(u64, @intCast(s2 >> 64));
            }
            var out: [n]u64 = t[0..n].*;
            if (t[n] != 0 or geq(out, mod)) subMod(&out);
            return out;
        }

        pub fn mul(x: *[n]u64, y: *const [n]u64) void {
            x.* = montmul(montmul(x.*, y.*), r2);
        }

        pub fn add(x: *[n]u64, y: *const [n]u64) void {
            var carry: u64 = 0;
            for (0..n) |i| {
                const s1 = @addWithOverflow(x[i], y[i]);
                const s2 = @addWithOverflow(s1[0], carry);
                x[i] = s2[0];
                carry = @as(u64, s1[1]) | s2[1];
            }
            if (carry != 0 or geq(x.*, mod)) subMod(x);
        }

        pub fn sub(x: *[n]u64, y: *const [n]u64) void {
            var borrow: u64 = 0;
            for (0..n) |i| {
                const d1 = @subWithOverflow(x[i], y[i]);
                const d2 = @subWithOverflow(d1[0], borrow);
                x[i] = d2[0];
                borrow = @as(u64, d1[1]) | d2[1];
            }
            if (borrow != 0) {
                var carry: u64 = 0;
                for (0..n) |i| {
                    const s1 = @addWithOverflow(x[i], mod[i]);
                    const s2 = @addWithOverflow(s1[0], carry);
                    x[i] = s2[0];
                    carry = @as(u64, s1[1]) | s2[1];
                }
            }
        }
    };
}

const SoftFq = soft.Soft(6, P_LIMBS);
const FastFq = FastSoft(6, P_LIMBS);
const Sw = Impl(FastFq);
const SwSlow = Impl(SoftFq);

test "FastSoft agrees with the u768 soft backend" {
    var s: u64 = 0x9e3779b97f4a7c15;
    for (0..2000) |_| {
        var a: [6]u64 = undefined;
        var b: [6]u64 = undefined;
        for (&a) |*l| {
            s = s *% 6364136223846793005 +% 1442695040888963407;
            l.* = s;
        }
        for (&b) |*l| {
            s = s *% 6364136223846793005 +% 1442695040888963407;
            l.* = s;
        }
        a[5] &= 0x0fffffffffffffff; // < p
        b[5] &= 0x0fffffffffffffff;
        var m1 = a;
        var m2 = a;
        FastFq.mul(&m1, &b);
        SoftFq.mul(&m2, &b);
        try std.testing.expectEqual(m2, m1);
        var a1 = a;
        var a2 = a;
        FastFq.add(&a1, &b);
        SoftFq.add(&a2, &b);
        try std.testing.expectEqual(a2, a1);
        var s1 = a;
        var s2 = a;
        FastFq.sub(&s1, &b);
        SoftFq.sub(&s2, &b);
        try std.testing.expectEqual(s2, s1);
        var t1 = b;
        var t2 = b;
        FastFq.sub(&t1, &a);
        SoftFq.sub(&t2, &a);
        try std.testing.expectEqual(t2, t1);
    }
    // extremes
    var x: [6]u64 = .{ P_LIMBS[0] - 1, P_LIMBS[1], P_LIMBS[2], P_LIMBS[3], P_LIMBS[4], P_LIMBS[5] };
    var y = x;
    var z = x;
    FastFq.mul(&y, &x);
    SoftFq.mul(&z, &x);
    try std.testing.expectEqual(z, y);
    x = .{ 0, 0, 0, 0, 0, 0 };
    y = .{ 1, 0, 0, 0, 0, 0 };
    FastFq.mul(&y, &x);
    try std.testing.expectEqual([6]u64{ 0, 0, 0, 0, 0, 0 }, y);
}

test "FastSoft pairing equals the slow backend's" {
    const g1 = SwSlow.g1FromBE(&G1_GEN_BE).?;
    const g2 = SwSlow.g2FromBE(&G2_GEN_BE).?;
    const slow = SwSlow.pair(g1, g2);
    const fast = Sw.pair(Sw.g1FromBE(&G1_GEN_BE).?, Sw.g2FromBE(&G2_GEN_BE).?);
    try std.testing.expectEqual(slow, @as(SwSlow.Fp12, @bitCast(fast)));
}

fn expectFp12Eq(a: Sw.Fp12, b: Sw.Fp12) !void {
    try std.testing.expect(Sw.Fp12.eql(a, b));
}

test "constants: generators and tau*G2 are valid subgroup points; R, hard exponent" {
    const g1 = Sw.g1FromBE(&G1_GEN_BE).?;
    const g2 = Sw.g2FromBE(&G2_GEN_BE).?;
    const tau = Sw.g2FromBE(&TAU_G2_BE).?;
    try std.testing.expect(!g1.inf and !g2.inf and !tau.inf);
    try std.testing.expect(Sw.g1InSubgroup(g1));
    try std.testing.expect(Sw.g2InSubgroup(g2));
    try std.testing.expect(Sw.g2InSubgroup(tau));
    // [r-1]G + G == O
    var rm1 = R_BE;
    rm1[31] -= 1;
    try std.testing.expect(Sw.G1.add(Sw.G1.mulBE(g1, &rm1), g1).inf);
}

test "G1/G2 group law: associativity, scalar mul vs repeated add" {
    const g1 = Sw.g1FromBE(&G1_GEN_BE).?;
    const two = Sw.G1.double(g1);
    const three = Sw.G1.add(two, g1);
    const five = Sw.G1.add(three, two);
    try std.testing.expect(Sw.G1.mulBE(g1, &[_]u8{5}).x[0] == five.x[0]);
    try std.testing.expectEqual(five.y, Sw.G1.mulBE(g1, &[_]u8{5}).y);
    try std.testing.expect(Sw.G1.isOnCurve(five));
    const g2 = Sw.g2FromBE(&G2_GEN_BE).?;
    const t2 = Sw.G2.double(g2);
    const t3 = Sw.G2.add(t2, g2);
    const t5 = Sw.G2.add(t3, t2);
    const m5 = Sw.G2.mulBE(g2, &[_]u8{5});
    try std.testing.expect(Sw.Fp2.eql(t5.x, m5.x) and Sw.Fp2.eql(t5.y, m5.y));
    try std.testing.expect(Sw.G2.isOnCurve(t5));
}

test "pairing is bilinear and non-degenerate" {
    const g1 = Sw.g1FromBE(&G1_GEN_BE).?;
    const g2 = Sw.g2FromBE(&G2_GEN_BE).?;
    const e = Sw.pair(g1, g2);
    try std.testing.expect(!Sw.Fp12.isOne(e));
    // e^r == 1 (result lies in the order-r subgroup of Fp12*)
    try std.testing.expect(Sw.Fp12.isOne(Sw.Fp12.pow(e, &R_LIMBS)));
    // e(aP, bQ) == e(P, Q)^(ab)
    const a = Sw.G1.mulBE(g1, &[_]u8{3});
    const b = Sw.G2.mulBE(g2, &[_]u8{5});
    try expectFp12Eq(Sw.pair(a, b), Sw.Fp12.pow(e, &[_]u64{15}));
    try expectFp12Eq(Sw.pair(a, g2), Sw.Fp12.pow(e, &[_]u64{3}));
    try expectFp12Eq(Sw.pair(g1, b), Sw.Fp12.pow(e, &[_]u64{5}));
    // e(P,Q) * e(-P,Q) == 1
    try std.testing.expect(Sw.Fp12.isOne(Sw.Fp12.mul(e, Sw.pair(Sw.G1.neg(g1), g2))));
}

test "pairing check API: product of pairings" {
    const g1 = Sw.g1FromBE(&G1_GEN_BE).?;
    const g2 = Sw.g2FromBE(&G2_GEN_BE).?;
    var pairs: [2]PairingPair = undefined;
    // e(2P, Q) * e(-P, 2Q) == 1
    Sw.g1ToBE(Sw.G1.double(g1), &pairs[0].g1);
    pairs[0].g2 = G2_GEN_BE;
    Sw.g1ToBE(Sw.G1.neg(g1), &pairs[1].g1);
    Sw.g2ToBE(Sw.G2.double(g2), &pairs[1].g2);
    var verified = false;
    try std.testing.expect(Sw.pairing(pairs[0..2], &verified));
    try std.testing.expect(verified);
    // break it
    Sw.g1ToBE(Sw.G1.neg(Sw.G1.double(g1)), &pairs[1].g1);
    try std.testing.expect(Sw.pairing(pairs[0..2], &verified));
    try std.testing.expect(!verified);
    // empty input is trivially true
    try std.testing.expect(Sw.pairing(pairs[0..0], &verified));
    try std.testing.expect(verified);
    // wrong-subgroup / off-curve inputs are rejected
    pairs[1].g2[191] ^= 1;
    try std.testing.expect(!Sw.pairing(pairs[0..2], &verified));
}

test "EIP-4844 KZG vectors (c-kzg-4844)" {
    for (kzg_vectors.cases) |c| {
        if (!runKzg(Sw, c)) {
            std.debug.print("KZG vector failed: {s}\n", .{c.name});
            return error.KzgVectorFailed;
        }
    }
}

test "embedded self-test vectors pass on the software backend" {
    try std.testing.expect(runAllVectors(Sw, "soft", true));
}

// ── Besu EIP-2537 suites (CSV files come from the pinned zesu dependency via build.zig) ──

fn csvSuite(comptime kind: Kind, comptime csv: []const u8, comptime stride_in_debug: usize) !void {
    var it = std.mem.splitScalar(u8, csv, '\n');
    var row: usize = 0;
    var ran: usize = 0;
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        row += 1;
        if (row == 1 or line.len == 0) continue;
        if (builtin.mode == .Debug and row % stride_in_debug != 0) continue;
        // input,result,gas,notes
        var f: [4][]const u8 = .{ "", "", "", "" };
        var idx: usize = 0;
        var start: usize = 0;
        for (line, 0..) |ch, i| {
            if (ch == ',' and idx < 3) {
                f[idx] = line[start..i];
                idx += 1;
                start = i + 1;
            }
        }
        f[idx] = line[start..];
        const expected: []const u8 = if (f[3].len > 0) "" else f[1];
        if (!runVector(Sw, kind, f[0], expected)) {
            std.debug.print("{s} row {d} failed (notes: '{s}')\n", .{ @tagName(kind), row, f[3] });
            return error.CsvVectorFailed;
        }
        ran += 1;
    }
    try std.testing.expect(ran > 0);
}

test "Besu EIP-2537 G1 add" {
    try csvSuite(.g1_add, @embedFile("eip2537_g1_add.csv"), 4);
}
test "Besu EIP-2537 G2 add" {
    try csvSuite(.g2_add, @embedFile("eip2537_g2_add.csv"), 4);
}
test "Besu EIP-2537 G1 MSM" {
    try csvSuite(.g1_msm, @embedFile("eip2537_g1_msm.csv"), 8);
}
test "Besu EIP-2537 G2 MSM" {
    try csvSuite(.g2_msm, @embedFile("eip2537_g2_msm.csv"), 8);
}
test "Besu EIP-2537 map Fp to G1" {
    try csvSuite(.fp_to_g1, @embedFile("eip2537_fp_to_g1.csv"), 4);
}
test "Besu EIP-2537 map Fp2 to G2" {
    try csvSuite(.fp2_to_g2, @embedFile("eip2537_fp2_to_g2.csv"), 4);
}
test "Besu EIP-2537 pairing" {
    try csvSuite(.pairing, @embedFile("eip2537_pairing.csv"), 8);
}
test "Besu EIP-2537 pairing, invalid subgroup (all rejected)" {
    try csvSuite(.pairing, @embedFile("eip2537_pairing_invalid_subgroup.csv"), 8);
}
