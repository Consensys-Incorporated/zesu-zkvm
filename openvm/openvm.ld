/* OpenVM zkVM linker script.
 *
 * Memory layout (from openvm-platform/src/memory.rs):
 *   STACK_TOP  = 0x00200400  (stack grows down from here)
 *   TEXT_START = 0x00200800  (ELF loaded here)
 *   MEM_SIZE   = 0x100000000 (4 GB, as of v2.x.0-preview.2 — upper bound openvm-platform allows)
 *
 * zesu's own heap cap (GUEST_MAX_MEM in openvm_host.zig) stays at 512 MB
 * regardless, well within this ceiling.
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
    . = 0x00200800;

    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    .data : ALIGN(8) {
        *(.data .data.*)
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.sdata .sdata.*)
    }

    .bss : ALIGN(8) {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    }

    /* Heap starts immediately after BSS. */
    _end = ALIGN(8);

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.debug*)
    }
}
