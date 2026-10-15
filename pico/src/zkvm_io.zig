/// zkVM I/O interface for Pico.
///
/// Input arrives as one stdin entry (the whole .bin test-vector file) read with
/// HINT_LEN + HINT_READ. Output is written to fd 3 (the public-values stream);
/// at halt the guest commits the SHA-256 digest of everything written there.
const std = @import("std");
const sys = @import("pico_sys");

/// Public-values staging buffer (the SSZ result is 43 bytes).
var pv_buf: [1024]u8 align(8) = .{0} ** 1024;
var pv_len: usize = 0;

/// Print a UTF-8 string to the host stdout (fd 1).
pub fn printStr(s: []const u8) void {
    if (s.len == 0) return;
    _ = sys.ecall(sys.WRITE, 1, @intFromPtr(s.ptr), s.len);
}

/// Read the private input data.
///
/// Input file format (.bin test vectors):
///   [0..8]   payload_len (u64 LE) — byte count of the SSZ payload
///   [8..]    SSZ payload (padded to 8-byte boundary in the file)
///
/// HINT_READ requires memory that is neither in the ELF image nor previously
/// touched. Pico registers every .bss word in the program image, so a static
/// buffer would double-initialise it and the proof would fail to verify;
/// instead the buffer is carved from the bump heap (`heap_pos`), which lies
/// past _end and is fresh.
///
/// There is no fixed input-size cap: the input only has to fit in the heap
/// (below `heap_top`), alongside everything zesu allocates while processing it.
pub fn read_input(heap_pos: *usize, heap_top: usize, buf_ptr: *[*]const u8, buf_size: *usize) void {
    const total_len = sys.ecall(sys.HINT_LEN, 0, 0, 0);
    if (total_len < 8) {
        @panic("input shorter than the 8-byte header");
    }

    // 8-byte aligned destination; capacity rounded up to a whole dword.
    const base = std.mem.alignForward(usize, heap_pos.*, 8);
    const capacity = std.mem.alignForward(usize, total_len, 8);
    if (capacity > heap_top -| base) {
        @panic("input does not fit in the guest heap");
    }
    heap_pos.* = base + capacity;
    _ = sys.ecall(sys.HINT_READ, base, total_len, 0);

    const payload_len = std.mem.littleToNative(u64, @as(*const u64, @ptrFromInt(base)).*);
    if (payload_len > total_len - 8) {
        @panic("file header payload_len exceeds total_len");
    }

    buf_ptr.* = @ptrFromInt(base + 8);
    buf_size.* = @intCast(payload_len);
}

/// Append the SSZ output bytes to the public-values stream (fd 3).
pub fn write_output(output: []const u8) void {
    if (pv_len + output.len > pv_buf.len) {
        @panic("public values exceed staging buffer");
    }
    @memcpy(pv_buf[pv_len..][0..output.len], output);
    pv_len += output.len;
    _ = sys.ecall(sys.WRITE, 3, @intFromPtr(output.ptr), output.len);
}

/// Everything written to fd 3 so far.
pub fn publicValues() []const u8 {
    return pv_buf[0..pv_len];
}

/// Commit the public-values digest, then halt. Pico's convention (pico-sdk
/// `syscall_halt`): 8 COMMIT ecalls carrying the digest as little-endian u32
/// words, 8 COMMIT_DEFERRED_PROOFS ecalls (zeros: no deferred proofs), HALT.
pub fn commitAndHalt(digest: *const [32]u8, exit_code: u32) noreturn {
    for (0..8) |i| {
        const word = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
        _ = sys.ecall(sys.COMMIT, i, word, 0);
    }
    for (0..8) |i| {
        _ = sys.ecall(sys.COMMIT_DEFERRED_PROOFS, i, 0, 0);
    }
    _ = sys.ecall(sys.HALT, exit_code, 0, 0);
    unreachable;
}
