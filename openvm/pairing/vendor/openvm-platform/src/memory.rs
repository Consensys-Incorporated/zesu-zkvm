pub const MEM_BITS: usize = 29;
pub const MEM_SIZE: usize = 1 << MEM_BITS;
pub const GUEST_MIN_MEM: usize = 0x0000_0400;
pub const GUEST_MAX_MEM: usize = MEM_SIZE;

/// Top of stack; stack grows down from this location.
pub const STACK_TOP: u64 = 0x0020_0400;
/// Program (text followed by data and then bss) gets loaded in
/// starting at this location.  HEAP begins right afterwards.
pub const TEXT_START: u64 = 0x0020_0800;

/// Returns whether `addr` is within guest memory bounds.
pub fn is_guest_memory(addr: u64) -> bool {
    GUEST_MIN_MEM <= (addr as usize) && (addr as usize) < GUEST_MAX_MEM
}

/// # Safety
///
/// This function should be safe to call, but clippy complains if it is not marked as `unsafe`.
#[cfg(feature = "rust-runtime")]
#[no_mangle]
pub unsafe extern "C" fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8 {
    use crate::print::println;

    // ZESU PATCH: share the Zig guest's bump heap (openvm_host.zig) instead of
    // keeping a private HEAP_POS that also starts at `_end` and would hand out
    // the same memory. zesu's allocator takes fresh memory the same way, so
    // bumping ZKVM_HEAP_POS here never overlaps it.
    extern "C" {
        static mut ZKVM_HEAP_POS: usize;
        static ZKVM_HEAP_TOP: usize;
    }
    #[allow(non_snake_case)]
    let HEAP_TOP = unsafe { ZKVM_HEAP_TOP };

    // SAFETY: Single threaded, so nothing else can touch this while we're working.
    let mut heap_pos = unsafe { ZKVM_HEAP_POS };

    // Honor requested alignment if larger than word size.
    // Note: align is typically a power of two.
    let align = usize::max(align, super::WORD_SIZE);

    let offset = heap_pos & (align - 1);
    if offset != 0 {
        heap_pos += align - offset;
    }

    match heap_pos.checked_add(bytes) {
        Some(new_heap_pos) if new_heap_pos <= HEAP_TOP => {
            // SAFETY: Single threaded, and non-preemptive so modification is safe.
            unsafe { ZKVM_HEAP_POS = new_heap_pos };
        }
        _ => {
            println("ERROR: Maximum memory exceeded, program terminating.");
            super::rust_rt::terminate::<1>();
        }
    }
    heap_pos as *mut u8
}
