/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1996, 1997, 1998, 2001 by Ralf Baechle
 */
#ifndef _ASM_BRANCH_H
#define _ASM_BRANCH_H

#include <asm/ptrace.h>
#include <asm/inst.h>

extern int __isa_exception_epc(struct pt_regs *regs);
extern int __compute_return_epc(struct pt_regs *regs);
extern int __compute_return_epc_for_insn(struct pt_regs *regs,
					 union mips_instruction insn);
extern int __microMIPS_compute_return_epc(struct pt_regs *regs);
extern int __MIPS16e_compute_return_epc(struct pt_regs *regs);


static inline int delay_slot(struct pt_regs *regs)
{
	return regs->cp0_cause & CAUSEF_BD;
}

static inline unsigned long exception_epc(struct pt_regs *regs)
{
	if (likely(!delay_slot(regs)))
		return regs->cp0_epc;

	if (get_isa16_mode(regs->cp0_epc))
		return __isa_exception_epc(regs);

	return regs->cp0_epc + 4;
}

#define BRANCH_LIKELY_TAKEN 0x0001

extern int __compute_return_epc(struct pt_regs *regs);
extern int __compute_return_epc_for_insn(struct pt_regs *regs,
					 union mips_instruction insn);
extern int __compute_return_epc_for_insn0(struct pt_regs *regs,
					  union mips_instruction insn,
					  unsigned int (*get_fcr31)(void));

static inline int compute_return_epc(struct pt_regs *regs)
{
	if (get_isa16_mode(regs->cp0_epc)) {
		if (cpu_has_mmips)
			return __microMIPS_compute_return_epc(regs);
		if (cpu_has_mips16)
			return __MIPS16e_compute_return_epc(regs);
	} else if (!delay_slot(regs)) {
		regs->cp0_epc += 4;
		return 0;
	}

	return __compute_return_epc(regs);
}

static inline int MIPS16e_compute_return_epc(struct pt_regs *regs,
					     union mips16e_instruction *inst)
{
	if (likely(!delay_slot(regs))) {
		if (inst->ri.opcode == MIPS16e_extend_op) {
			regs->cp0_epc += 4;
			return 0;
		}
		regs->cp0_epc += 2;
		return 0;
	}

	return __MIPS16e_compute_return_epc(regs);
}

#endif /* _ASM_BRANCH_H */
