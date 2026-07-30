/* Linea zkVM guest entry point.
 * Placed in .text._start so the linker script's KEEP(*(.text._start))
 * forces it to the very first instruction at PROGRAM origin (0x00000000).
 *
 * main() (zesu.o, Zig, no asm) returns its status (0 success / 1 failure) in
 * a0 per the RISC-V C ABI, and nothing between `call main` and the ecall
 * below touches a0 — so it already holds the exit code the Linux exit(93)
 * syscall expects, with no extra move needed.
 */
	.section .text._start,"ax",@progbits
	.global _start
	.type   _start, @function
_start:
	la   sp, _stack_start
	call linea_init_heap
	call main
	li   a7, 93
	ecall
1:	wfi
	j    1b
	.size _start, . - _start
