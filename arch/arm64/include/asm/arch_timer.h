/*
 * arch/arm64/include/asm/arch_timer.h
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software: you can redistribute it and/or modify
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
#ifndef __ASM_ARCH_TIMER_H
#define __ASM_ARCH_TIMER_H

#include <asm/barrier.h>

#include <linux/init.h>
#include <linux/types.h>

#include <clocksource/arm_arch_timer.h>

/*
 * These register accessors are marked inline so the compiler can
 * nicely work out which register we want, and chuck away the rest of
 * the code.
 */
static __always_inline
void arch_timer_reg_write_cp15(int access, enum arch_timer_reg reg, u32 val)
{
#ifdef CONFIG_LS2085A_ERRATA_TKT269926
	u32 val_read;
#endif
	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("msr cntp_ctl_el0,  %0" : : "r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("msr cntp_tval_el0, %0" : : "r" (val));
#ifdef CONFIG_LS2085A_ERRATA_TKT269926
			asm volatile("mrs %0, cntp_tval_el0" : "=r" (val_read));
			if ((val & 0xffffff00) != (val_read & 0xffffff00)) {
				asm volatile("msr cntp_tval_el0, xzr");
				asm volatile("msr cntp_tval_el0, %0" : : "r" (val));
			}
#endif
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("msr cntv_ctl_el0,  %0" : : "r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("msr cntv_tval_el0, %0" : : "r" (val));
			break;
		}
	}

	isb();
}

static __always_inline
u32 arch_timer_reg_read_cp15(int access, enum arch_timer_reg reg)
{
	u32 val;

#ifdef CONFIG_LS2085A_ERRATA_ERR008585
	u32 val_new, timeout = 200;
#endif

	if (access == ARCH_TIMER_PHYS_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mrs %0,  cntp_ctl_el0" : "=r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("mrs %0, cntp_tval_el0" : "=r" (val));
#ifdef CONFIG_LS2085A_ERRATA_ERR008585
			asm volatile("mrs %0, cntp_tval_el0" : "=r" (val_new));
			while (val != val_new && timeout) {
				asm volatile("mrs %0, cntp_tval_el0" : "=r" (val));
				asm volatile("mrs %0, cntp_tval_el0" : "=r" (val_new));
				timeout--;

			}
			BUG_ON((timeout <= 0) && (val != val_new));
#endif
			break;
		}
	} else if (access == ARCH_TIMER_VIRT_ACCESS) {
		switch (reg) {
		case ARCH_TIMER_REG_CTRL:
			asm volatile("mrs %0,  cntv_ctl_el0" : "=r" (val));
			break;
		case ARCH_TIMER_REG_TVAL:
			asm volatile("mrs %0, cntv_tval_el0" : "=r" (val));
#ifdef CONFIG_LS2085A_ERRATA_ERR008585
			asm volatile("mrs %0, cntv_tval_el0" : "=r" (val_new));
			while (val != val_new && timeout) {
				asm volatile("mrs %0, cntp_tval_el0" : "=r" (val));
				asm volatile("mrs %0, cntp_tval_el0" : "=r" (val_new));
				timeout--;
			}
			BUG_ON((timeout <= 0) && (val != val_new));
#endif
			break;
		}
	}

	return val;
}

static inline u32 arch_timer_get_cntfrq(void)
{
	u32 val;
	asm volatile("mrs %0,   cntfrq_el0" : "=r" (val));
	return val;
}

static inline void arch_counter_set_user_access(void)
{
	u32 cntkctl;

	/* Disable user access to the timers and the physical counter. */
	asm volatile("mrs	%0, cntkctl_el1" : "=r" (cntkctl));
	cntkctl &= ~((3 << 8) | (1 << 0));

	/* Enable user access to the virtual counter and frequency. */
	cntkctl |= (1 << 1);
	asm volatile("msr	cntkctl_el1, %0" : : "r" (cntkctl));
}

static inline u64 arch_counter_get_cntvct(void)
{
	u64 cval;

#ifdef CONFIG_LS2085A_ERRATA_ERR008585
	u64 tmp, timeout = 200;
#endif

	isb();
	asm volatile("mrs %0, cntvct_el0" : "=r" (cval));

#ifdef CONFIG_LS2085A_ERRATA_ERR008585
	asm volatile("mrs %0, cntvct_el0" : "=r" (tmp));
	while (cval != tmp && timeout) {
		asm volatile("mrs %0, cntvct_el0" : "=r" (cval));
		asm volatile("mrs %0, cntvct_el0" : "=r" (tmp));
		timeout--;
	}
	BUG_ON((timeout <= 0) && (cval != tmp));
#endif

	return cval;
}

static inline int arch_timer_arch_init(void)
{
	return 0;
}

#endif
