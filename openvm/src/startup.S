/* OpenVM guest entry point.
 * Placed in .text._start so the linker script's KEEP(*(.text._start))
 * forces it to the very first instruction at TEXT_START (0x00200800).
 *
 * main() (zesu.o, Zig, no asm) returns its status (0 success / 1 failure) in
 * a0 per the RISC-V C ABI. TERMINATE's exit code is an immediate baked into
 * the instruction encoding, not a register operand, so we branch on a0 here
 * to pick the matching TERMINATE variant instead of main() calling a halt
 * function itself — this is OpenVM's one required non-standard opcode, kept
 * entirely in this entry-point file rather than spread into guest logic.
 */
	.section .text._start,"ax",@progbits
	.global _start
	.type   _start, @function
_start:
	li   sp, 0x00200400
	call openvm_init_heap
	call main
	beqz a0, 1f
	.insn i 0x0b, 0, x0, x0, 1   /* TERMINATE(1) — guestMain() returned an error */
	unimp
1:
	.insn i 0x0b, 0, x0, x0, 0   /* TERMINATE(0) — success */
	unimp
	.size _start, . - _start
