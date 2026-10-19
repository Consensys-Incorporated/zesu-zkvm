/// Prime-field arithmetic over a backend (see soft.zig for the backend contract).
///
/// Elements are `[limbs]u64`, little-endian limbs, always canonical (< modulus).
/// Both zkVM-friendly primes used here (BN254 Fq and BLS12-381 Fq) are 3 mod 4, so
/// square roots are a single exponentiation.
const std = @import("std");

pub fn Field(comptime B: type) type {
    return struct {
        pub const N = B.limbs;
        pub const BYTES = N * 8;
        pub const Fe = [N]u64;
        pub const zero: Fe = .{0} ** N;
        pub const one: Fe = blk: {
            var o: Fe = zero;
            o[0] = 1;
            break :blk o;
        };
        pub const modulus: Fe = B.modulus;

        pub fn add(a: Fe, b: Fe) Fe {
            var r = a;
            B.add(&r, &b);
            return r;
        }
        pub fn sub(a: Fe, b: Fe) Fe {
            var r = a;
            B.sub(&r, &b);
            return r;
        }
        pub fn mul(a: Fe, b: Fe) Fe {
            var r = a;
            B.mul(&r, &b);
            return r;
        }
        pub fn sq(a: Fe) Fe {
            return mul(a, a);
        }
        pub fn dbl(a: Fe) Fe {
            return add(a, a);
        }
        pub fn neg(a: Fe) Fe {
            return sub(zero, a);
        }
        pub fn isZero(a: Fe) bool {
            var acc: u64 = 0;
            for (a) |l| acc |= l;
            return acc == 0;
        }
        pub fn eql(a: Fe, b: Fe) bool {
            return std.mem.eql(u64, &a, &b);
        }
        /// a < modulus
        pub fn isCanonical(a: Fe) bool {
            return cmp(a, modulus) == .lt;
        }
        pub fn cmp(a: Fe, b: Fe) std.math.Order {
            var i: usize = N;
            while (i > 0) {
                i -= 1;
                if (a[i] < b[i]) return .lt;
                if (a[i] > b[i]) return .gt;
            }
            return .eq;
        }
        pub fn isOdd(a: Fe) bool {
            return a[0] & 1 == 1;
        }
        pub fn fromU64(v: u64) Fe {
            var r = zero;
            r[0] = v;
            return r;
        }

        /// base^exp, exp little-endian limbs.
        pub fn pow(base: Fe, exp: []const u64) Fe {
            var r = one;
            var i: usize = exp.len * 64;
            while (i > 0) {
                i -= 1;
                r = sq(r);
                if ((exp[i / 64] >> @intCast(i % 64)) & 1 == 1) r = mul(r, base);
            }
            return r;
        }

        /// a^-1 (Fermat); inv(0) = 0.
        pub fn inv(a: Fe) Fe {
            return pow(a, &exp_p_minus_2);
        }

        /// A square root of `a` if it is a square, else null.
        pub fn sqrt(a: Fe) ?Fe {
            const r = pow(a, &exp_p_plus_1_div_4);
            return if (eql(sq(r), a)) r else null;
        }

        pub const exp_p_minus_2: Fe = limbsSubSmall(N, modulus, 2);
        pub const exp_p_plus_1_div_4: Fe = divSmall(N, limbsAddSmall(N, modulus, 1), 4);
        pub const exp_p_minus_1_div_2: Fe = divSmall(N, limbsSubSmall(N, modulus, 1), 2);

        /// Big-endian bytes <-> element. fromBytesBE does not reduce: check isCanonical.
        pub fn fromBytesBE(b: *const [BYTES]u8) Fe {
            var r: Fe = undefined;
            for (0..N) |i| r[i] = std.mem.readInt(u64, b[BYTES - 8 * (i + 1) ..][0..8], .big);
            return r;
        }
        pub fn toBytesBE(a: Fe) [BYTES]u8 {
            var b: [BYTES]u8 = undefined;
            for (0..N) |i| std.mem.writeInt(u64, b[BYTES - 8 * (i + 1) ..][0..8], a[i], .big);
            return b;
        }
    };
}

pub fn limbsSubSmall(comptime n: usize, a: [n]u64, s: u64) [n]u64 {
    var r = a;
    var borrow = s;
    for (0..n) |i| {
        const old = r[i];
        r[i] = old -% borrow;
        borrow = if (old < borrow) 1 else 0;
        if (borrow == 0) break;
    }
    return r;
}

pub fn limbsAddSmall(comptime n: usize, a: [n]u64, s: u64) [n]u64 {
    var r = a;
    var carry = s;
    for (0..n) |i| {
        const sum = @addWithOverflow(r[i], carry);
        r[i] = sum[0];
        carry = sum[1];
        if (carry == 0) break;
    }
    return r;
}

pub fn divSmall(comptime n: usize, a: [n]u64, d: u64) [n]u64 {
    var r: [n]u64 = undefined;
    var rem: u128 = 0;
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        const cur = (rem << 64) | a[i];
        r[i] = @intCast(cur / d);
        rem = cur % d;
    }
    return r;
}

const soft = @import("soft.zig");

test "field: inverse, sqrt, bytes" {
    const P: [4]u64 = .{ 0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029 };
    const F = Field(soft.Soft(4, P));
    const a = F.fromU64(123456789);
    try std.testing.expect(F.eql(F.mul(a, F.inv(a)), F.one));
    const r = F.sqrt(F.sq(a)).?;
    try std.testing.expect(F.eql(r, a) or F.eql(r, F.neg(a)));
    const b = F.toBytesBE(a);
    try std.testing.expect(F.eql(F.fromBytesBE(&b), a));
    try std.testing.expect(F.isCanonical(a));
    try std.testing.expect(!F.isCanonical(F.modulus));
}
