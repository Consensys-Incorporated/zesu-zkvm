/* Linker script for Zisk zkVM (v1.1.0-alpha memory map)
 * ROM: 0x80000000 - 0x87FFFFFF (128MB) - code and read-only data
 *      Note: 0x87F00000-0x87FFFFFF (last 1MB) reserved for float library
 *
 * ZisK system regions (NOT mapped here — managed by ziskemu):
 *   0xa0000000 - 0xa0400000  STACK   (4MB — STACK_SIZE increased in v1.1.0-alpha)
 *   0xa0400000 - 0xa0410000  SYS     (64KB — UART at 0xa0400200)
 *   0xa0410000 - 0xa0410100  OUTPUT  (256B — pubout slots, set_output writes here)
 *
 * RAM: 0xa0420000 - 0xbfff0000 (~510MB) - writable data
 *      Starts AFTER the OUTPUT region to prevent heap from overlapping with
 *      pubout-intercepted addresses (0xa0410000..0xa041ffff).
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
    ROM (rx)  : ORIGIN = 0x80000000, LENGTH = 0x08000000
    RAM (rw)  : ORIGIN = 0xa0420000, LENGTH = 0x1FBD0000
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
     * block's working set is hundreds of MiB); sysAllocAligned then returns
     * null and ReleaseFast turns the unchecked failures into null derefs.
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
