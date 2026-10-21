/* Word-wise memcpy/memset for the Pico guest.
 *
 * Zig's compiler_rt memcpy copies to an unaligned destination with one load and eight byte
 * stores per 8 bytes (~2.8 cycles/byte), and the BLS12-381 tower code copies small field
 * elements by value constantly. These strong definitions override compiler_rt's weak ones.
 * Pico traps on misaligned loads/stores, so the wide paths are taken only when both pointers
 * are suitably aligned, and everything else falls back to bytes.
 *
 * Written in assembly so the compiler cannot turn the loops back into a call to memcpy.
 * Only caller-saved temporaries (t0-t5) are used; no stack.
 */
	.text

	.global memcpy
	.type   memcpy, @function
memcpy:
	mv    t0, a0
	li    t1, 16
	bltu  a2, t1, .Lcpy_bytes
	or    t1, a0, a1
	andi  t1, t1, 7
	beqz  t1, .Lcpy_aligned
	xor   t1, a0, a1
	andi  t1, t1, 7
	bnez  t1, .Lcpy_try4
	/* same misalignment: byte-copy up to the next 8-byte boundary (n >= 16, so n stays >= 9) */
.Lcpy_align:
	lbu   t2, 0(a1)
	sb    t2, 0(t0)
	addi  a1, a1, 1
	addi  t0, t0, 1
	addi  a2, a2, -1
	andi  t1, t0, 7
	bnez  t1, .Lcpy_align
.Lcpy_aligned:
	li    t1, 32
	bltu  a2, t1, .Lcpy_dwords
.Lcpy_32:
	ld    t2, 0(a1)
	ld    t3, 8(a1)
	ld    t4, 16(a1)
	ld    t5, 24(a1)
	sd    t2, 0(t0)
	sd    t3, 8(t0)
	sd    t4, 16(t0)
	sd    t5, 24(t0)
	addi  a1, a1, 32
	addi  t0, t0, 32
	addi  a2, a2, -32
	bgeu  a2, t1, .Lcpy_32
.Lcpy_dwords:
	li    t1, 8
	bltu  a2, t1, .Lcpy_bytes
.Lcpy_8:
	ld    t2, 0(a1)
	sd    t2, 0(t0)
	addi  a1, a1, 8
	addi  t0, t0, 8
	addi  a2, a2, -8
	bgeu  a2, t1, .Lcpy_8
.Lcpy_bytes:
	beqz  a2, .Lcpy_done
.Lcpy_b:
	lbu   t2, 0(a1)
	sb    t2, 0(t0)
	addi  a1, a1, 1
	addi  t0, t0, 1
	addi  a2, a2, -1
	bnez  a2, .Lcpy_b
.Lcpy_done:
	ret
.Lcpy_try4:
	/* differing 8-byte phase: still use words if both pointers are 4-aligned */
	or    t1, a0, a1
	andi  t1, t1, 3
	bnez  t1, .Lcpy_bytes
	li    t1, 4
.Lcpy_4:
	lw    t2, 0(a1)
	sw    t2, 0(t0)
	addi  a1, a1, 4
	addi  t0, t0, 4
	addi  a2, a2, -4
	bgeu  a2, t1, .Lcpy_4
	j     .Lcpy_bytes
	.size memcpy, . - memcpy

	.global memset
	.type   memset, @function
memset:
	mv    t0, a0
	li    t1, 16
	bltu  a2, t1, .Lset_bytes
	andi  a1, a1, 0xff
	li    t2, 0x0101010101010101
	mul   a1, a1, t2
.Lset_align:
	andi  t1, t0, 7
	beqz  t1, .Lset_aligned
	sb    a1, 0(t0)
	addi  t0, t0, 1
	addi  a2, a2, -1
	j     .Lset_align
.Lset_aligned:
	li    t1, 32
	bltu  a2, t1, .Lset_dwords
.Lset_32:
	sd    a1, 0(t0)
	sd    a1, 8(t0)
	sd    a1, 16(t0)
	sd    a1, 24(t0)
	addi  t0, t0, 32
	addi  a2, a2, -32
	bgeu  a2, t1, .Lset_32
.Lset_dwords:
	li    t1, 8
	bltu  a2, t1, .Lset_bytes
.Lset_8:
	sd    a1, 0(t0)
	addi  t0, t0, 8
	addi  a2, a2, -8
	bgeu  a2, t1, .Lset_8
.Lset_bytes:
	beqz  a2, .Lset_done
.Lset_b:
	sb    a1, 0(t0)
	addi  t0, t0, 1
	addi  a2, a2, -1
	bnez  a2, .Lset_b
.Lset_done:
	ret
	.size memset, . - memset
