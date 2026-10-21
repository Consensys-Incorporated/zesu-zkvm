/// BLAKE2b F compression function (EIP-152, RFC 7693 §3.2).
/// Pure-Zig — no OpenVM native accelerator exists for BLAKE2f.
const std = @import("std");

const SIGMA: [10][16]usize = .{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

const IV: [8]u64 = .{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

inline fn g(v: *[16]u64, a: usize, b: usize, c_: usize, d: usize, x: u64, y: u64) void {
    var va = v[a];
    var vb = v[b];
    var vc = v[c_];
    var vd = v[d];
    va = va +% vb +% x;
    vd = std.math.rotr(u64, vd ^ va, 32);
    vc = vc +% vd;
    vb = std.math.rotr(u64, vb ^ vc, 24);
    va = va +% vb +% y;
    vd = std.math.rotr(u64, vd ^ va, 16);
    vc = vc +% vd;
    vb = std.math.rotr(u64, vb ^ vc, 63);
    v[a] = va;
    v[b] = vb;
    v[c_] = vc;
    v[d] = vd;
}

inline fn mixRound(v: *[16]u64, m: *const [16]u64, r: usize) void {
    const s = &SIGMA[r % 10];
    g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
}

pub fn blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) bool {
    if (f > 1) return false;

    var state: [8]u64 = undefined;
    for (&state, 0..) |*w, i| w.* = std.mem.readInt(u64, h[i * 8 ..][0..8], .little);

    var msg: [16]u64 = undefined;
    for (&msg, 0..) |*w, i| w.* = std.mem.readInt(u64, m[i * 8 ..][0..8], .little);

    const t0 = std.mem.readInt(u64, t[0..8], .little);
    const t1 = std.mem.readInt(u64, t[8..16], .little);

    var v: [16]u64 = undefined;
    @memcpy(v[0..8], &state);
    @memcpy(v[8..16], &IV);
    v[12] ^= t0;
    v[13] ^= t1;
    if (f == 1) v[14] = ~v[14];

    for (0..rounds) |i| mixRound(&v, &msg, i);

    for (&state, 0..) |*w, i| w.* ^= v[i] ^ v[i + 8];

    for (state, 0..) |w, i| std.mem.writeInt(u64, h[i * 8 ..][0..8], w, .little);

    return true;
}
