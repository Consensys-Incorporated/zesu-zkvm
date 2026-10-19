/// Pure-Zig RIPEMD-160 implementation.
/// Reference: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
const std = @import("std");

// ── Round constants ───────────────────────────────────────────────────────────

const KL = [5]u32{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
const KR = [5]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

// ── Message word selection ────────────────────────────────────────────────────

const RL = [80]u32{
    0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
    4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13,
};

const RR = [80]u32{
    5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
    12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11,
};

// ── Rotation amounts ──────────────────────────────────────────────────────────

const SL = [80]u5{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
    9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6,
};

const SR = [80]u5{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
    8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11,
};

// ── Round functions ───────────────────────────────────────────────────────────

inline fn f0(x: u32, y: u32, z: u32) u32 {
    return x ^ y ^ z;
}
inline fn f1(x: u32, y: u32, z: u32) u32 {
    return (x & y) | (~x & z);
}
inline fn f2(x: u32, y: u32, z: u32) u32 {
    return (x | ~y) ^ z;
}
inline fn f3(x: u32, y: u32, z: u32) u32 {
    return (x & z) | (y & ~z);
}
inline fn f4(x: u32, y: u32, z: u32) u32 {
    return x ^ (y | ~z);
}

inline fn rol(x: u32, n: u5) u32 {
    return std.math.rotl(u32, x, n);
}

// ── Compress one 64-byte block ────────────────────────────────────────────────

fn compressBlock(h: *[5]u32, block: *const [64]u8) void {
    var x: [16]u32 = undefined;
    for (0..16) |i| {
        x[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
    }

    var al = h[0];
    var bl = h[1];
    var cl = h[2];
    var dl = h[3];
    var el = h[4];
    var ar = h[0];
    var br = h[1];
    var cr = h[2];
    var dr = h[3];
    var er = h[4];

    comptime var j: usize = 0;
    inline while (j < 80) : (j += 1) {
        const round = j / 16;

        const fl: u32 = switch (round) {
            0 => f0(bl, cl, dl),
            1 => f1(bl, cl, dl),
            2 => f2(bl, cl, dl),
            3 => f3(bl, cl, dl),
            4 => f4(bl, cl, dl),
            else => unreachable,
        };
        const fr: u32 = switch (round) {
            0 => f4(br, cr, dr),
            1 => f3(br, cr, dr),
            2 => f2(br, cr, dr),
            3 => f1(br, cr, dr),
            4 => f0(br, cr, dr),
            else => unreachable,
        };

        const tl = rol(al +% fl +% x[RL[j]] +% KL[round], SL[j]) +% el;
        al = el;
        el = dl;
        dl = rol(cl, 10);
        cl = bl;
        bl = tl;

        const tr = rol(ar +% fr +% x[RR[j]] +% KR[round], SR[j]) +% er;
        ar = er;
        er = dr;
        dr = rol(cr, 10);
        cr = br;
        br = tr;
    }

    const t = h[1] +% cl +% dr;
    h[1] = h[2] +% dl +% er;
    h[2] = h[3] +% el +% ar;
    h[3] = h[4] +% al +% br;
    h[4] = h[0] +% bl +% cr;
    h[0] = t;
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Compute RIPEMD-160 and write the 20-byte digest into output[12..32]; output[0..12] = 0.
pub fn ripemd160(data: []const u8, output: *[32]u8) void {
    var h: [5]u32 = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

    var offset: usize = 0;
    while (offset + 64 <= data.len) : (offset += 64) {
        compressBlock(&h, data[offset..][0..64]);
    }

    const msg_bit_len: u64 = @as(u64, data.len) * 8;
    const remaining = data.len - offset;
    var pad: [128]u8 = .{0} ** 128;
    @memcpy(pad[0..remaining], data[offset..]);
    pad[remaining] = 0x80;

    if (remaining < 56) {
        std.mem.writeInt(u64, pad[56..64], msg_bit_len, .little);
        compressBlock(&h, pad[0..64]);
    } else {
        std.mem.writeInt(u64, pad[120..128], msg_bit_len, .little);
        compressBlock(&h, pad[0..64]);
        compressBlock(&h, pad[64..128]);
    }

    // The zkvm_ripemd160 contract is the EVM precompile's output: the 20-byte
    // digest right-aligned in a 32-byte word.
    @memset(output[0..12], 0);
    for (h, 0..) |word, i| {
        std.mem.writeInt(u32, output[12 + i * 4 ..][0..4], word, .little);
    }
}

test "ripemd160 writes the digest right-aligned" {
    const vectors = [_]struct { in: []const u8, digest: []const u8 }{
        .{ .in = "", .digest = "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
        .{ .in = "abc", .digest = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
        .{ .in = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", .digest = "12a053384a9c0c88e405a06c27dcf49ada62eb2b" },
    };
    for (vectors) |v| {
        var expected: [32]u8 = .{0} ** 32;
        _ = try std.fmt.hexToBytes(expected[12..], v.digest);
        var got: [32]u8 = .{0xaa} ** 32;
        ripemd160(v.in, &got);
        try std.testing.expectEqualSlices(u8, &expected, &got);
    }
}
