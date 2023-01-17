/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1999 Ralf Baechle
 * Copyright (C) 1999 Silicon Graphics, Inc.
 */
#include <asm/mipsregs.h>
#include <asm/regdef.h>
#include <asm/stackframe.h>

	.macro tlb_do_page_fault, write
	NESTED(tlb_do_page_fault_\write, PT_SIZE, sp)
	CFI_SIGNAL_FRAME
	SAVE_ALL docfi=1
#ifdef CONFIG_MICROSTATE_ACCT
	/*
	 * Save the IE bit so we can enable interrupts if they were
	 * enabled before.
	 */
	MFC0	k0, CP0_STATUS
	and	k0, ST0_IE
	CLI
	jal	msa_kernel
	MFC0	a2, CP0_BADVADDR
	beqz	k0, 1f
	STI
1:
#else
	MFC0	a2, CP0_BADVADDR
	KMODE
#endif
	move	a0, sp
	REG_S	a2, PT_BVADDR(sp)
	li	a1, \write
	jal	do_page_fault
	j	ret_from_exception
	END(tlb_do_page_fault_\write)
	.endm

	tlb_do_page_fault 0
	tlb_do_page_fault 1
