/* Linker script for Zisk zkVM (v1.1.0-alpha memory map)
 * ROM: 0x80000000 - 0x87F00000 (127MB) - code and read-only data
 *      Ends BEFORE FLOAT_LIB_ROM_ADDR (0x87F00000, the last 1MB of the 128MB
 *      ROM window), which ziskemu reserves for the float library's code.
 *
 * ZisK system regions (NOT mapped here — managed by ziskemu). Mirrors upstream
 * ziskbuild/zisk_linker_script.ld; constants in zisk/core/src/mem.rs:
 *   0xa0000000 - 0xa0400000  STACK   (4MB  STACK_SIZE, grew in v1.1.0-alpha)
 *   0xa0400000 - 0xa0408000  SYS     (32KB general registers; UART at 0xa0400200)
 *   0xa0408000 - 0xa0410000  SYS     (32KB float registers)
 *   0xa0410000 - 0xa0430000  OUTPUT  (128KB OUTPUT_MAX_SIZE, reserved)
 *
 * RAM: 0xa0430000 - 0xbfff0000 (~507MB) - writable data
 *      Starts at the first general-purpose RAM address, i.e. after the whole
 *      128KB OUTPUT region. Note OUTPUT_MAX_SIZE is 0x20000, not 0x10000: only
 *      the first 256 bytes (ZISK_PUBLICS * 4) are read back by the emulator, so
 *      a lower origin appears to work, but it puts .bss inside a region upstream
 *      reserves for output data.
 *      Ends BEFORE FLOAT_LIB_RAM_ADDR (0xbfff0000, the last 64KB of RAM), which
 *      ziskemu reserves for the float library's scratch space and stack.
 *
 * ziskemu maps the whole 0xa0000000..0xc0000000 range as one zero-initialized
 * writable section, so .bss needs no explicit clearing and every address past
 * the program image is valid heap.
 */

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    /* Both regions stop short of the float library's reserved windows:
     * ROM ends at FLOAT_LIB_ROM_ADDR (0x87f00000), RAM at FLOAT_LIB_RAM_ADDR
     * (0xbfff0000). Excluding them here means an overrun fails the link rather
     * than silently colliding with the float library at runtime. */
    ROM (rx)  : ORIGIN = 0x80000000, LENGTH = 0x07F00000
    RAM (rw)  : ORIGIN = 0xa0430000, LENGTH = 0x1FBC0000
}

PHDRS
{
    text     PT_LOAD FLAGS(1);   /* X only — execute-only for max ZisK performance (v1.1.0-alpha) */
    rodata   PT_LOAD FLAGS(4);   /* R only — read-only data, init/fini arrays */
    data     PT_LOAD FLAGS(6);   /* R|W */
    bss      PT_LOAD FLAGS(6);   /* R|W */
    heapvars PT_LOAD FLAGS(6);   /* R|W — heap bounds, placed after .bss */
}

SECTIONS
{
    /* Code in ROM — execute-only */
    .text : {
        *(.text._start)
        *(.text .text.*)
        . = ALIGN(4);
    } >ROM :text

    /* Read-only data in ROM */
    .rodata : {
        *(.rodata .rodata.*)
        . = ALIGN(8);
    } >ROM :rodata

    /* C++ static constructors / destructors — placed in ROM so they are within
     * PC-relative (±512 KiB) reach of _zisk_main (also in ROM).  Required by
     * libziskos_staticlib.a since ZisK 1.1.0-alpha, which added C++ ctor/dtor
     * support.  Empty when the program has no static initializers (start == end)
     * so it costs nothing otherwise. */
    . = ALIGN(8);
    .init_array : {
        PROVIDE(__init_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE(__init_array_end = .);
    } >ROM :rodata

    .fini_array : {
        PROVIDE(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
        KEEP(*(.fini_array))
        PROVIDE(__fini_array_end = .);
    } >ROM :rodata

    /* Writable data in RAM */
    . = ALIGN(8);
    .data : {
        __data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(8);
        __data_end = .;
    } >RAM AT>RAM :data

    /* Set global pointer after data */
    . = ALIGN(8);
    PROVIDE(__global_pointer$ = .);
    PROVIDE(_global_pointer = .);  /* alias used by libziskos.a _start */

    . = ALIGN(8);
    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    } >RAM AT>RAM :bss

    /* Initial stack pointer, loaded by libziskos_staticlib.a's _start
     * ("la sp, _init_stack_top"). The guest stack lives in ziskemu's own
     * 0xa0000000..0xa0400000 region and grows down from the top of it, so no
     * stack is carved out of RAM here — matching upstream's
     * ziskbuild/zisk_linker_script.ld, which also puts _init_stack_top at
     * 0xa0400000. The previous "somewhere after .bss" placement left sp
     * pointing into the middle of the heap. */
    PROVIDE(_init_stack_top = 0xa0400000);

    /* Agnostic heap bounds used by zesu.o's allocator (src/zkvm/alt_fl_alloc.zig).
     *
     * These must NOT be aliased onto ZISK_BUMP_HEAP_POS/TOP. Since 1.1.0-alpha,
     * libziskos_staticlib.a carves its heap out of an isolated 8 MiB static
     * buffer in its own .bss — deliberately, so that ziskos's allocations stay
     * independent of the host application that owns the linker script. Sharing
     * that 8 MiB with zesu silently exhausts it on any real block (a mainnet
     * block's working set is hundreds of MiB, and the SSZ input alone is ~6 MiB).
     *
     * Exhaustion does NOT surface as a clean OOM, which is what makes this so
     * expensive to debug. sysAllocAligned returns null, and zesu then fails two
     * ways: parts of the MPT layer swallow the error (src/stateless/mpt/main.zig
     * "decodeNode(...) catch null") and skip trie canonicalization, yielding a
     * silently WRONG state root; elsewhere the failure reaches an unchecked
     * pointer and ziskemu panics reading "addr = 0 + struct_offset", so the crash
     * site moves with the workload and looks like memory corruption. Confirmed by
     * A/B test: restoring the alias while keeping a correct stack reproduces the
     * addr=0 panic; a correct heap with a deliberately bad stack does not.
     *
     * Emitted as initialized data rather than .bss so zesu's allocator sees a
     * live heap on its very first call, with no startup hook to sequence
     * against ziskos's own init_sys_alloc(). Both operands are already defined
     * at this point, so there are no forward references to resolve. */
    . = ALIGN(8);
    __zesu_heap_bottom = . + 16;                    /* heap starts after the two words below */
    __zesu_heap_top    = ORIGIN(RAM) + LENGTH(RAM); /* 0xbfff0000, below FLOAT_LIB_RAM_ADDR */
    .zesu_heap_vars : {
        ZKVM_HEAP_POS = .;
        QUAD(__zesu_heap_bottom);
        ZKVM_HEAP_TOP = .;
        QUAD(__zesu_heap_top);
    } >RAM AT>RAM :heapvars

    . = ALIGN(8);
    _end = .;

    /* Machine-check the heap invariants. Every one of these was violated at some
     * point during the 1.1.0-alpha bring-up, and each failure mode was silent at
     * build time and surfaced only as a null deref or wrong output deep inside a
     * block. Prefer failing the link.
     *
     * 1. The "+ 16" above must match the real size of .zesu_heap_vars, or the
     *    heap would start on top of its own bounds words (or waste space). */
    ASSERT(__zesu_heap_bottom == ADDR(.zesu_heap_vars) + SIZEOF(.zesu_heap_vars),
           "zesu heap must begin immediately after .zesu_heap_vars — update the '+ 16'")
    /* 2. RAM must start at the first general-purpose address, i.e. after the full
     *    128KB OUTPUT region (OUTPUT_ADDR 0xa0410000 + OUTPUT_MAX_SIZE 0x20000).
     *    Only the first 256 bytes are read back by the emulator, so a lower
     *    origin silently "works" while .bss squats on reserved output space. */
    ASSERT(ORIGIN(RAM) >= 0xa0430000,
           "RAM must start at or after 0xa0430000 (end of the 128KB OUTPUT region)")
    /* 3. The heap must stay below FLOAT_LIB_RAM_ADDR (0xbfff0000), which ziskemu
     *    uses for the float library's scratch space and stack. */
    ASSERT(__zesu_heap_top <= 0xbfff0000,
           "zesu heap must end at or below FLOAT_LIB_RAM_ADDR (0xbfff0000)")
    /* 4. Catch a heap that has collapsed to nothing (or inverted) — e.g. if .bss
     *    ever grows past the end of RAM. */
    ASSERT(__zesu_heap_bottom < __zesu_heap_top,
           "zesu heap is empty or inverted — .bss may have overrun the RAM region")
    /* 5. The heap must be plausibly large. This is the guard that would have
     *    caught the original bug directly: aliasing onto ZISK_BUMP_HEAP_* gave
     *    zesu ziskos's private 8MB buffer, which is ~2 orders of magnitude too
     *    small for a block and failed only at runtime, as null derefs. 256MB is
     *    well under the ~507MB actually available but far above any accidental
     *    small-buffer aliasing. */
    ASSERT(__zesu_heap_top - __zesu_heap_bottom >= 0x10000000,
           "zesu heap is under 256MB — check RAM bounds and that ZKVM_HEAP_* is not aliased onto ziskos's private 8MB heap")

    /* Discard unnecessary sections.
     * Debug sections must be dropped: R_RISCV_SET32 is a signed 32-bit
     * relocation but our ROM base (0x80000000) exceeds the signed max,
     * so LLD cannot resolve these relocations in release builds. */
    /DISCARD/ : {
        *(.comment)
        *(.note.GNU-stack)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.debug_frame)
        *(.debug_info)
        *(.debug_abbrev)
        *(.debug_aranges)
        *(.debug_ranges)
        *(.debug_str)
        *(.debug_line)
        *(.debug_loc)
        *(.debug_pubnames)
        *(.debug_pubtypes)
    }
}
