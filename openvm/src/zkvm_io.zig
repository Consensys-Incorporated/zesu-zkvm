/// zkVM I/O Interface for OpenVM
///
/// Implements I/O via OpenVM's hint-stream custom RISC-V instructions.
/// All instructions use opcode 0x0b (RISC-V custom-0).
///
/// Instruction encoding (I-type):
///   funct3=0 TERMINATE: terminate with exit code in imm
///   funct3=1 HINT:      hint_stored (imm=0) or hint_buffer (imm=1)
///   funct3=2 REVEAL:    write rs1 (value) to public_values[rd] (byte offset)
///   funct3=3 PHANTOM:   hint_input (imm=0), print_str (imm=1)
const std = @import("std");

/// Maximum input size: up to 64 MB SSZ payload. A multiple of 8, so reading
/// the payload rounded up to whole dwords never overruns the buffer.
const MAX_INPUT_SIZE: usize = 64 * 1024 * 1024;

/// Static input buffer; populated once per execution via the hint stream.
var input_buf: [MAX_INPUT_SIZE]u8 align(8) = undefined;

/// Temporary 8-byte buffer for reading the hint-stream length word.
var len_buf: u64 align(8) = 0;

// ── Hint-stream primitives ────────────────────────────────────────────────────

/// Advance the hint stream to the next input vector (phantom instruction).
inline fn hintInput() void {
    asm volatile (".insn i 0x0b, 3, x0, x0, 0" ::: .{ .memory = true });
}

/// Read 8 bytes from the hint stream into *ptr.
inline fn hintStoreU64(ptr: *u64) void {
    asm volatile (".insn i 0x0b, 1, %[rd], x0, 0"
        :
        : [rd] "r" (@intFromPtr(ptr)),
        : .{ .memory = true });
}

/// Read num_dwords * 8 bytes from the hint stream into buf.
/// Splits automatically into chunks ≤ 1023 dwords (MAX_HINT_BUFFER_DWORDS limit).
fn hintBufferChunked(buf: [*]u8, num_dwords: usize) void {
    const MAX_CHUNK: usize = 1023;
    var remaining = num_dwords;
    var ptr = buf;
    while (remaining > 0) {
        const chunk = if (remaining > MAX_CHUNK) MAX_CHUNK else remaining;
        asm volatile (".insn i 0x0b, 1, %[rd], %[rs1], 1"
            :
            : [rd] "r" (@intFromPtr(ptr)),
              [rs1] "r" (chunk),
            : .{ .memory = true });
        ptr = ptr + chunk * 8;
        remaining -= chunk;
    }
}

// ── Public interface ──────────────────────────────────────────────────────────

/// Print a UTF-8 string to the host stdout (phantom debug instruction).
pub fn printStr(s: []const u8) void {
    if (s.len == 0) return;
    asm volatile (".insn i 0x0b, 3, %[rd], %[rs1], 1"
        :
        : [rd] "r" (@intFromPtr(s.ptr)),
          [rs1] "r" (s.len),
        : .{ .memory = true });
}

/// Read the private input data.
///
/// The input is the raw SSZ payload as a single hint-stream entry — what
/// eth-act/ere's OpenVM host writes (`StdIn::write_bytes(statelessInputBytes)`)
/// and what `openvm::io::read_vec` reads: the executor prefixes the entry with
/// an 8-byte LE length word and zero-pads the bytes to a dword boundary.
///
/// On return, buf_ptr points to the SSZ payload and buf_size is its length.
pub fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void {
    // Advance hint stream to the first (and only) input vector.
    hintInput();

    // Read the executor's 8-byte length prefix (= payload length).
    hintStoreU64(&len_buf);
    const len = len_buf;

    // Validate before reading: a malformed or oversized hint stream must not
    // write past input_buf.
    if (len > MAX_INPUT_SIZE) {
        @panic("hint-stream length exceeds MAX_INPUT_SIZE");
    }

    const num_dwords = (len + 7) / 8;
    hintBufferChunked(&input_buf, @intCast(num_dwords));

    buf_ptr.* = @ptrCast(&input_buf[0]);
    buf_size.* = @intCast(len);
}

/// Write the SSZ output bytes to the OpenVM public values via reveal instructions.
///
/// Each reveal packs up to 8 bytes as a u64 (LE) and writes them to
/// public_values[byte_offset .. byte_offset+8].  Configure the runner with
/// num_public_values ≥ ceil(output.len / 8) * 8.
pub fn write_output(output: []const u8) void {
    var i: usize = 0;
    while (i < output.len) {
        // Pack up to 8 bytes little-endian.
        var chunk: u64 = 0;
        const n = if (output.len - i < 8) output.len - i else 8;
        for (0..n) |j| {
            chunk |= @as(u64, output[i + j]) << @intCast(j * 8);
        }
        const byte_offset: u64 = @intCast(i);
        // REVEAL: writes chunk to PUBLIC_VALUES[byte_offset .. byte_offset+8]
        asm volatile (".insn i 0x0b, 2, %[rd], %[rs1], 0"
            :
            : [rd] "r" (byte_offset),
              [rs1] "r" (chunk),
            : .{ .memory = true });
        i += 8;
    }
}
