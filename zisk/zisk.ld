/* Linker script for Zisk zkVM
 * ROM: 0x80000000 - 0x87FFFFFF (128MB) - code and read-only data
 *      Note: 0x87F00000-0x87FFFFFF (last 1MB) reserved for float library
 * RAM: 0xa0030000 - 0xc0000000 (~512MB) - writable data
 *      Note: 0xa0000000-0xa0010000 is SYS_ADDR (registers, UART, CSRs)
 *      Note: 0xa0010000-0xa0020000 is OUTPUT_ADDR region
 *      Note: 0xa0020000-0xa0030000 is reserved gap
 *      Note: 0xa0030000 is AVAILABLE_MEM_ADDR (general purpose RAM)
 */

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
    ROM (rx)  : ORIGIN = 0x80000000, LENGTH = 0x08000000
    RAM (rw)  : ORIGIN = 0xa0030000, LENGTH = 0x1FFD0000
}

PHDRS
{
    text PT_LOAD FLAGS(7);
    data PT_LOAD FLAGS(6);
    bss PT_LOAD FLAGS(6);
}

SECTIONS
{
    /* Code in ROM */
    .text : {
        *(.text._start)
        *(.text .text.*)
        . = ALIGN(4);
    } >ROM :text

    /* Read-only data in ROM */
    .rodata : {
        *(.rodata .rodata.*)
        . = ALIGN(8);
    } >ROM :text

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
    } >ROM :text

    .fini_array : {
        PROVIDE(__fini_array_start = .);
        KEEP(*(SORT_BY_INIT_PRIORITY(.fini_array.*)))
        KEEP(*(.fini_array))
        PROVIDE(__fini_array_end = .);
    } >ROM :text

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

    /* Stack (grows down from here) */
    . = ALIGN(16);
    PROVIDE(_init_stack_top = . + 0x100000);  /* 1MB stack */

    /* Heap (after stack) */
    PROVIDE(_kernel_heap_bottom = _init_stack_top);
    PROVIDE(_kernel_heap_top = ORIGIN(RAM) + LENGTH(RAM));
    PROVIDE(_kernel_heap_size = _kernel_heap_top - _kernel_heap_bottom);

    /* Agnostic heap symbols used by zesu.o bump_alloc.zig; aliased onto
     * libziskos.a's own heap vars so both names reference the same memory. */
    ZKVM_HEAP_POS = ZISK_BUMP_HEAP_POS;
    ZKVM_HEAP_TOP = ZISK_BUMP_HEAP_TOP;

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
