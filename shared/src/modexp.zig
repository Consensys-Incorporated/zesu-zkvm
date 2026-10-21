/// Pure-Zig big-integer modular exponentiation (EIP-198 / precompile 0x05).
/// All inputs are big-endian byte slices of arbitrary length.
/// Allocation-free: uses stack buffers bounded by MAX_BYTES.
const std = @import("std");

/// Maximum byte length accepted for base, exponent, or modulus.
/// Inputs exceeding this produce a zero result (conservative; these are never
/// seen on Ethereum mainnet where gas pricing makes them prohibitively expensive).
const MAX_BYTES: usize = 1024;

// ── Big-endian variable-width integer helpers ─────────────────────────────────

fn bigCmp(a: []const u8, b: []const u8) std.math.Order {
    var ai: usize = 0;
    var bi: usize = 0;
    while (ai < a.len and a[ai] == 0) ai += 1;
    while (bi < b.len and b[bi] == 0) bi += 1;
    const alen = a.len - ai;
    const blen = b.len - bi;
    if (alen != blen) return if (alen < blen) .lt else .gt;
    return std.mem.order(u8, a[ai..], b[bi..]);
}

fn bigSubInPlace(a: []u8, b: []const u8) void {
    var borrow: u8 = 0;
    var i: usize = a.len;
    while (i > 0) {
        i -= 1;
        const lsb_pos = a.len - 1 - i;
        const bval: u8 = if (lsb_pos < b.len) b[b.len - 1 - lsb_pos] else 0;
        const sub: i16 = @as(i16, a[i]) - @as(i16, bval) - @as(i16, borrow);
        if (sub < 0) {
            a[i] = @intCast(sub + 256);
            borrow = 1;
        } else {
            a[i] = @intCast(sub);
            borrow = 0;
        }
    }
}

fn bigBitLen(a: []const u8) usize {
    for (a, 0..) |byte, i| {
        if (byte != 0) return (a.len - i) * 8 - @as(usize, @clz(byte));
    }
    return 0;
}

fn bigShiftInto(dst: []u8, m: []const u8, shift: usize) void {
    @memset(dst, 0);
    const byte_shift = shift / 8;
    const bit_off: u3 = @intCast(shift % 8);
    var i: usize = dst.len;
    while (i > 0) {
        i -= 1;
        const lsb_pos = dst.len - 1 - i;
        if (lsb_pos < byte_shift) continue;
        const src_lsb = lsb_pos - byte_shift;
        if (src_lsb >= m.len) continue;
        const mb = m[m.len - 1 - src_lsb];
        dst[i] |= mb << bit_off;
        if (bit_off != 0 and i > 0) dst[i - 1] |= mb >> @as(u3, @intCast(8 - @as(u4, bit_off)));
    }
}

/// Reduce a in-place modulo m. scratch must be at least a.len bytes.
fn bigReduce(a: []u8, m: []const u8, scratch: []u8) void {
    if (bigCmp(a, m) == .lt) return;
    const shifted_m = scratch[0..a.len];
    while (bigCmp(a, m) != .lt) {
        const a_bl = bigBitLen(a);
        const m_bl = bigBitLen(m);
        var shift = a_bl - m_bl;
        bigShiftInto(shifted_m, m, shift);
        if (bigCmp(shifted_m, a) == .gt) {
            shift -= 1;
            bigShiftInto(shifted_m, m, shift);
        }
        bigSubInPlace(a, shifted_m);
    }
}

/// Compute a*b mod m, storing the result in out.
/// product must be >= 2*m.len bytes; reduce_scratch must be >= 2*m.len bytes.
fn bigModMulInto(
    a: []const u8,
    b: []const u8,
    m: []const u8,
    out: []u8,
    product: []u8,
    reduce_scratch: []u8,
) void {
    const n = m.len;
    const prod = product[0 .. n * 2];
    @memset(prod, 0);

    var ai: usize = 0;
    while (ai < a.len) : (ai += 1) {
        const a_byte = a[a.len - 1 - ai];
        if (a_byte == 0) continue;
        var carry: u32 = 0;
        var bi: usize = 0;
        while (bi < b.len) : (bi += 1) {
            const pidx = prod.len - 1 - ai - bi;
            const cur = @as(u32, prod[pidx]) +
                @as(u32, a_byte) * @as(u32, b[b.len - 1 - bi]) + carry;
            prod[pidx] = @truncate(cur);
            carry = cur >> 8;
        }
        var ci: usize = prod.len - 1 - ai - b.len;
        while (carry > 0) {
            const cur = @as(u32, prod[ci]) + carry;
            prod[ci] = @truncate(cur);
            carry = cur >> 8;
            if (ci == 0) break;
            ci -= 1;
        }
    }

    bigReduce(prod, m, reduce_scratch);

    @memset(out, 0);
    const src_start = prod.len - @min(prod.len, out.len);
    const dst_start = out.len - (prod.len - src_start);
    @memcpy(out[dst_start..], prod[src_start..]);
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn modexp(base: []const u8, exp: []const u8, modulus: []const u8, output: []u8) bool {
    if (modulus.len == 0 or std.mem.allEqual(u8, modulus, 0)) {
        @memset(output, 0);
        return true;
    }
    const mod_is_one = blk: {
        for (modulus[0 .. modulus.len - 1]) |byte| if (byte != 0) break :blk false;
        break :blk modulus[modulus.len - 1] == 1;
    };
    if (mod_is_one) {
        @memset(output, 0);
        return true;
    }
    if (exp.len == 0 or std.mem.allEqual(u8, exp, 0)) {
        @memset(output, 0);
        if (output.len > 0) output[output.len - 1] = 1;
        return true;
    }
    if (base.len == 0 or std.mem.allEqual(u8, base, 0)) {
        @memset(output, 0);
        return true;
    }

    // Inputs beyond MAX_BYTES are never seen on mainnet; return 0 conservatively.
    if (modulus.len > MAX_BYTES or base.len > MAX_BYTES * 2 or exp.len > MAX_BYTES * 2) {
        @memset(output, 0);
        return true;
    }

    const n = modulus.len;

    // Stack buffers — total ~7 * MAX_BYTES = 7 KB for n = MAX_BYTES.
    var result_buf = std.mem.zeroes([MAX_BYTES]u8);
    var a_buf: [MAX_BYTES]u8 = undefined;
    var tmp_buf: [MAX_BYTES]u8 = undefined;
    // product: 2n bytes for the multiplication result.
    // reduce_scratch: 2n bytes for bigReduce's shifted_m (always called on a 2n-byte product).
    var product_buf: [MAX_BYTES * 2]u8 = undefined;
    var reduce_scratch_buf: [MAX_BYTES * 2]u8 = undefined;

    const result = result_buf[0..n];
    if (n > 0) result[n - 1] = 1; // initialise to 1

    const a = a_buf[0..n];
    if (base.len <= n) {
        @memset(a, 0);
        @memcpy(a[n - base.len ..], base);
        bigReduce(a, modulus, &reduce_scratch_buf);
    } else {
        // base.len > n: reduce a larger buffer mod modulus first.
        // Borrow product_buf as temporary (base.len <= MAX_BYTES * 2).
        const a_big = product_buf[0..base.len];
        @memcpy(a_big, base);
        bigReduce(a_big, modulus, &reduce_scratch_buf);
        @memset(a, 0);
        const tail = @min(n, a_big.len);
        @memcpy(a[n - tail ..], a_big[a_big.len - tail ..]);
    }

    const tmp = tmp_buf[0..n];

    var highest_bit: usize = 0;
    for (0..exp.len * 8) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((exp[exp.len - 1 - byte_idx] >> bit_idx) & 1 != 0) highest_bit = i;
    }

    for (0..highest_bit + 1) |i| {
        const byte_idx = i / 8;
        const bit_idx: u3 = @intCast(i % 8);
        if ((exp[exp.len - 1 - byte_idx] >> bit_idx) & 1 != 0) {
            bigModMulInto(result, a, modulus, tmp, &product_buf, &reduce_scratch_buf);
            @memcpy(result, tmp);
        }
        if (i < highest_bit) {
            bigModMulInto(a, a, modulus, tmp, &product_buf, &reduce_scratch_buf);
            @memcpy(a, tmp);
        }
    }

    @memset(output, 0);
    const copy_len = @min(result.len, output.len);
    @memcpy(output[output.len - copy_len ..], result[result.len - copy_len ..]);
    return true;
}
