/*
 * Based on arch/arm/mm/proc.S
 *
 * Copyright (C) 2001 Deep Blue Solutions Ltd.
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/hwcap.h>
#include <asm/pgtable-hwdef.h>
#include <asm/pgtable.h>
#include <asm/cpufeature.h>
#include <asm/alternative.h>

#include "proc-macros.S"

#ifndef CONFIG_SMP
/* PTWs cacheable, inner/outer WBWA not shareable */
#define TCR_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
#else
/* PTWs cacheable, inner/outer WBWA shareable */
#define TCR_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA | TCR_SHARED
#endif

#define MAIR(attr, mt)	((attr) << ((mt) * 8))

/*
 *	cpu_cache_off()
 *
 *	Turn the CPU D-cache off.
 */
ENTRY(cpu_cache_off)
	mrs	x0, sctlr_el1
	bic	x0, x0, #1 << 2			// clear SCTLR.C
	msr	sctlr_el1, x0
	isb
	ret
ENDPROC(cpu_cache_off)

/*
 *	cpu_reset(loc)
 *
 *	Perform a soft reset of the system.  Put the CPU into the same state
 *	as it would be if it had been reset, and branch to what would be the
 *	reset vector. It must be executed with the flat identity mapping.
 *
 *	- loc   - location to jump to for soft reset
 */
	.align	5
ENTRY(cpu_reset)
	mrs	x1, sctlr_el1
	bic	x1, x1, #1
	msr	sctlr_el1, x1			// disable the MMU
	isb
	ret	x0
ENDPROC(cpu_reset)

/*
 *	cpu_do_idle()
 *
 *	Idle the processor (wait for interrupt).
 */
ENTRY(cpu_do_idle)
	dsb	sy				// WFI may enter a low-power mode
	wfi
	ret
ENDPROC(cpu_do_idle)

/*
 *	cpu_switch_mm(pgd_phys, tsk)
 *
 *	Set the translation table base pointer to be pgd_phys.
 *
 *	- pgd_phys - physical address of new TTB
 */
ENTRY(cpu_do_switch_mm)
	mmid	w1, x1				// get mm->context.id
	bfi	x0, x1, #48, #16		// set the ASID
	msr	ttbr0_el1, x0			// set TTBR0
	isb
alternative_if_not ARM64_WORKAROUND_CAVIUM_27456
	ret
	nop
	nop
	nop
alternative_else
	ic	iallu
	dsb	nsh
	isb
	ret
alternative_endif
ENDPROC(cpu_do_switch_mm)

	.section ".text.init", #alloc, #execinstr

/*
 *	__cpu_setup
 *
 *	Initialise the processor for turning the MMU on.  Return in x0 the
 *	value of the SCTLR_EL1 register.
 */
ENTRY(__cpu_setup)
	/*
	 * Preserve the link register across the function call.
	 */
	mov	x28, lr
	bl	__flush_dcache_all
	mov	lr, x28
	ic	iallu				// I+BTB cache invalidate
	tlbi	vmalle1is			// invalidate I + D TLBs
	dsb	ish

	mov	x0, #3 << 20
	msr	cpacr_el1, x0			// Enable FP/ASIMD
	msr	mdscr_el1, xzr			// Reset mdscr_el1
	/*
	 * Memory region attributes for LPAE:
	 *
	 *   n = AttrIndx[2:0]
	 *			n	MAIR
	 *   DEVICE_nGnRnE	000	00000000
	 *   DEVICE_nGnRE	001	00000100
	 *   DEVICE_GRE		010	00001100
	 *   NORMAL_NC		011	01000100
	 *   NORMAL		100	11111111
	 */
	ldr	x5, =MAIR(0x00, MT_DEVICE_nGnRnE) | \
		     MAIR(0x04, MT_DEVICE_nGnRE) | \
		     MAIR(0x0c, MT_DEVICE_GRE) | \
		     MAIR(0x44, MT_NORMAL_NC) | \
		     MAIR(0xff, MT_NORMAL)
	msr	mair_el1, x5
	/*
	 * Prepare SCTLR
	 */
	adr	x5, crval
	ldp	w5, w6, [x5]
	mrs	x0, sctlr_el1
	bic	x0, x0, x5			// clear bits
	orr	x0, x0, x6			// set bits
#ifdef CONFIG_CPU_BIG_ENDIAN
        orr	x0, x0, #(3<<24)		// set EE and EOE bits
#endif
	/*
	 * Set/prepare TCR and TTBR. We use 512GB (39-bit) address range for
	 * both user and kernel.
	 */
	ldr	x10, =TCR_TxSZ(VA_BITS) | TCR_FLAGS | TCR_IPS_BITS | \
		      TCR_ASID16 | (1 << 31)
#ifdef CONFIG_ARM64_64K_PAGES
	orr	x10, x10, TCR_TG0_64K
	orr	x10, x10, TCR_TG1_64K
#endif

#ifdef CONFIG_ARCH_XGENE
#ifdef CONFIG_ARM64_64K_PAGES
	// This is PSCR optimization specific only to Storm
	// Do not change this unless you know for sure.
	ldr	x5, =0x121			// 512M & 64K User Space
	msr	S3_0_c15_c1_0, x5		// potenza only TB0PSCR_EL1
	ldr	x5, =0x142			// 512M & 64K Kernel Space
	msr	S3_0_c15_c1_1, x5		// potenza only TB1PSCR_EL1

#else
	// This is PSCR optimization specific only to Storm
	// Do not change this unless you know for sure.
	ldr	x5, =0x4521			// 2M and 4K and 1G User Space
	msr	S3_0_c15_c1_0, x5		// potenza only TB0PSCR_EL1
	ldr	x5, =0x142			// 2M and 4K Kernel Space
	msr	S3_0_c15_c1_1, x5		// potenza only TB1PSCR_EL1
#endif
#endif
	msr	tcr_el1, x10
	ret					// return to head.S
ENDPROC(__cpu_setup)

	/*
	 *                 n n            T
	 *       U E      WT T UD     US IHBS
	 *       CE0      XWHW CZ     ME TEEA S
	 * .... .IEE .... NEAI TE.I ..AD DEN0 ACAM
	 * 0011 0... 1101 ..0. ..0. 10.. .... .... < hardware reserved
	 * .... .1.. .... 01.1 11.1 ..01 0001 1101 < software settings
	 */
	.type	crval, #object
crval:
	.word	0x000802e2			// clear
	.word	0x0405d11d			// set
