/*
 *  linux/arch/arm/lib/copypage.S
 *
 *  Copyright (C) 1995-1999 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  ASM optimised string functions
 */
#include <linux/linkage.h>
#include <linux/const.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/cache.h>

#define COPY_COUNT (PAGE_SZ / (2 * L1_CACHE_BYTES) PLD( -1 ))

		.text
		.align	5
/*
 * StrongARM optimised copy_page routine
 * now 1.78bytes/cycle, was 1.60 bytes/cycle (50MHz bus -> 89MB/s)
 * Note that we probably achieve closer to the 100MB/s target with
 * the core clock switching.
 */
ENTRY(copy_page)
		stmfd	sp!, {r4, lr}			@	2
	PLD(	pld	[r1, #0]		)
	PLD(	pld	[r1, #L1_CACHE_BYTES]		)
#ifdef CONFIG_MV_LARGE_PAGE_SUPPORT
		ldr	r2, =COPY_COUNT
#else
		mov	r2, #COPY_COUNT			@	1
#endif
		ldmia	r1!, {r3, r4, ip, lr}		@	4+1
1:	PLD(	pld	[r1, #2 * L1_CACHE_BYTES])
	PLD(	pld	[r1, #3 * L1_CACHE_BYTES])
2:
	.rept	(2 * L1_CACHE_BYTES / 16 - 1)
		stmia	r0!, {r3, r4, ip, lr}		@	4
		ldmia	r1!, {r3, r4, ip, lr}		@	4
	.endr
		subs	r2, r2, #1			@	1
		stmia	r0!, {r3, r4, ip, lr}		@	4
		ldmgtia	r1!, {r3, r4, ip, lr}		@	4
		bgt	1b				@	1
	PLD(	ldmeqia r1!, {r3, r4, ip, lr}	)
	PLD(	beq	2b			)
		ldmfd	sp!, {r4, pc}			@	3
ENDPROC(copy_page)
