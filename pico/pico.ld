/* Pico zkVM linker script.
 *
 * Memory layout (from pico-cli's guest build flags and pico-sdk):
 *   TEXT_START = 0x00200800  (pico-cli: -Ttext=0x00200800)
 *   STACK_TOP  = 0x78000000  (pico-sdk STACK_TOP; stack grows down)
 *   MEM_SIZE   = 0x78000000  (emulator memory; addresses must stay below the
 *                             BabyBear prime, see sys_alloc_aligned MAX_MEMORY)
 *
 * zesu's own heap cap (GUEST_MAX_MEM in pico_host.zig) stays at 512 MB,
 * well within this ceiling.
 *
 * Pico's ELF loader registers every word of a segment's memsz (including
 * .bss) in the program's initial memory image, so HINT_READ must never target
 * .bss: read_input reads into the heap that starts at _end instead.
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
