/// Software field backend, for native `zig test` of the curve code.
///
/// A backend is a type with
///   limbs   : usize          number of u64 limbs of a field element
///   modulus : [limbs]u64     the prime, little-endian limbs
///   add/sub/mul(x: *[limbs]u64, y: *const [limbs]u64) void
///             in-place:  x = x op y  (mod modulus), canonical in and out
/// which is exactly the shape of Pico's FP_ADD / FP_SUB / FP_MUL syscalls, so the same
/// curve code runs on the syscalls in the guest and on this backend under `zig test`.
const std = @import("std");

pub fn Soft(comptime n: usize, comptime mod: [n]u64) type {
    const Int = std.meta.Int(.unsigned, n * 64);
    const Wide = std.meta.Int(.unsigned, n * 128);
    const p: Int = toInt(n, Int, mod);
    return struct {
        pub const limbs = n;
        pub const modulus = mod;

        pub fn add(x: *[n]u64, y: *const [n]u64) void {
            const a: Wide = toInt(n, Int, x.*);
            const b: Wide = toInt(n, Int, y.*);
            x.* = fromInt(n, Int, @intCast((a + b) % p));
        }
        pub fn sub(x: *[n]u64, y: *const [n]u64) void {
            const a: Wide = toInt(n, Int, x.*);
            const b: Wide = toInt(n, Int, y.*);
            x.* = fromInt(n, Int, @intCast((a + p - b) % p));
        }
        pub fn mul(x: *[n]u64, y: *const [n]u64) void {
            const a: Wide = toInt(n, Int, x.*);
            const b: Wide = toInt(n, Int, y.*);
            x.* = fromInt(n, Int, @intCast((a * b) % p));
        }
    };
}

fn toInt(comptime n: usize, comptime Int: type, l: [n]u64) Int {
    var r: Int = 0;
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        r = (r << 64) | l[i];
    }
    return r;
}

fn fromInt(comptime n: usize, comptime Int: type, v: Int) [n]u64 {
    var r: [n]u64 = undefined;
    var t = v;
    for (0..n) |i| {
        r[i] = @truncate(t);
        t >>= 64;
    }
    return r;
}

test "soft backend arithmetic" {
    // BN254 base field prime
    const P: [4]u64 = .{ 0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029 };
    const F = Soft(4, P);
    var a: [4]u64 = .{ P[0] - 5, P[1], P[2], P[3] }; // p - 5
    const b: [4]u64 = .{ P[0] - 7, P[1], P[2], P[3] }; // p - 7
    F.mul(&a, &b);
    try std.testing.expectEqual([4]u64{ 35, 0, 0, 0 }, a);
    var c: [4]u64 = .{ 3, 0, 0, 0 };
    const d: [4]u64 = .{ 5, 0, 0, 0 };
    F.sub(&c, &d);
    try std.testing.expectEqual([4]u64{ P[0] - 2, P[1], P[2], P[3] }, c);
}
