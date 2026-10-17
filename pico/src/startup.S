/* Pico guest entry point.
 * Placed in .text._start so the linker script's KEEP(*(.text._start))
 * forces it to the very first instruction at TEXT_START (0x00200800).
 *
 * main() (zesu.o) returns its status (0 success / 1 failure) in a0 per the
 * RISC-V C ABI. pico_exit() (pico_host.zig) takes it as the exit code: it
 * commits the SHA-256 digest of the public values the guest wrote to fd 3
 * (Pico's public-values convention) and then issues HALT.
 */
	.section .text._start,"ax",@progbits
	.global _start
	.type   _start, @function
_start:
	.option push
	.option norelax
	la   gp, __global_pointer$
	.option pop
	li   sp, 0x78000000
	call pico_init_heap
	call main
	call pico_exit
	unimp
	.size _start, . - _start
