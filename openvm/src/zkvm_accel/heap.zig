/// Scratch allocations for the accelerators, from the guest's shared bump heap
/// (ZKVM_HEAP_POS / ZKVM_HEAP_TOP, openvm_host.zig). zesu's allocator and the
/// linked pairing library take fresh memory the same way, so bumping here never
/// overlaps them. Nothing is freed.
const std = @import("std");

extern var ZKVM_HEAP_POS: usize;
extern var ZKVM_HEAP_TOP: usize;

pub fn alloc(bytes: usize) ?[*]u8 {
    const start = std.mem.alignForward(usize, ZKVM_HEAP_POS, 8);
    if (start + bytes > ZKVM_HEAP_TOP) return null;
    ZKVM_HEAP_POS = start + bytes;
    return @ptrFromInt(start);
}
