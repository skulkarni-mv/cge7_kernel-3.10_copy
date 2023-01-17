/*
 *  arch/arm64/kernel/v7_obsolete.c
 *
 *  Copied from arch/arm/kernel/swp_emulate.c and modified for ARMv8
 *
 *  Copyright (C) 2009,2012,2014 ARM Limited
 *  __user_* functions adapted from include/asm/uaccess.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/perf_event.h>

#include <asm/opcodes.h>
#include <asm/system_misc.h>
#include <asm/traps.h>
#include <asm/uaccess.h>

#define RN_OFFSET	16
#define RT_OFFSET	12
#define RT2_OFFSET	 0

/*
 * Macros/defines for extracting register numbers from instruction.
 */
static u32 aarch32_insn_extract_reg_num(u32 insn, int offset)
{
	return (insn & (0xf << offset)) >> offset;
}

#define OPC2_MASK	0x7
#define OPC2_OFFSET	5
u32 aarch32_insn_mcr_extract_opc2(u32 insn)
{
	return (insn & (OPC2_MASK << OPC2_OFFSET)) >> OPC2_OFFSET;
}

#define CRM_MASK	0xf
u32 aarch32_insn_mcr_extract_crm(u32 insn)
{
	return insn & CRM_MASK;
}

#define dmb(opt)	asm volatile("dmb " #opt : : : "memory")

/*
 *  Implements emulation of the SWP/SWPB instructions using load-exclusive and
 *  store-exclusive.
 *
 *  Syntax of SWP{B} instruction: SWP{B}<c> <Rt>, <Rt2>, [<Rn>]
 *  Where: Rt  = destination
 *	   Rt2 = source
 *	   Rn  = address
 */


/*
 * Error-checking SWP macros implemented using ldxr{b}/stxr{b}
 */
#define __user_swpX_asm(data, addr, res, temp, B)		\
	__asm__ __volatile__(					\
	"	mov		%w2, %w1\n"			\
	"0:	ldxr"B"		%w1, [%3]\n"			\
	"1:	stxr"B"		%w0, %w2, [%3]\n"		\
	"	cbz		%w0, 2f\n"			\
	"	mov		%w0, %w4\n"			\
	"2:\n"							\
	"	.pushsection	 .fixup,\"ax\"\n"		\
	"	.align		2\n"				\
	"3:	mov		%w0, %w5\n"			\
	"	b		2b\n"				\
	"	.popsection"					\
	"	.pushsection	 __ex_table,\"a\"\n"		\
	"	.align		3\n"				\
	"	.quad		0b, 3b\n"			\
	"	.quad		1b, 3b\n"			\
	"	.popsection"					\
	: "=&r" (res), "+r" (data), "=&r" (temp)		\
	: "r" (addr), "i" (-EAGAIN), "i" (-EFAULT)		\
	: "memory")

#define __user_swp_asm(data, addr, res, temp) \
	__user_swpX_asm(data, addr, res, temp, "")
#define __user_swpb_asm(data, addr, res, temp) \
	__user_swpX_asm(data, addr, res, temp, "b")

/*
 * Bit 22 of the instruction encoding distinguishes between
 * the SWP and SWPB variants (bit set means SWPB).
 */
#define TYPE_SWPB (1 << 22)

static atomic_t swp_counter;
static atomic_t swpb_counter;
static u32 swp_enabled = 1;

/*
 * Set up process info to signal segmentation fault - called on access error.
 */
static void set_segfault(struct pt_regs *regs, unsigned long addr)
{
	siginfo_t info;

	down_read(&current->mm->mmap_sem);
	if (find_vma(current->mm, addr) == NULL)
		info.si_code = SEGV_MAPERR;
	else
		info.si_code = SEGV_ACCERR;
	up_read(&current->mm->mmap_sem);

	info.si_signo = SIGSEGV;
	info.si_errno = 0;
	info.si_addr  = (void *) instruction_pointer(regs);

	pr_debug("SWP{B} emulation: access caused memory abort!\n");
	arm64_notify_die("Illegal memory access", regs, &info, 0);
}

static int emulate_swpX(unsigned int address, unsigned int *data,
			unsigned int type)
{
	unsigned int res = 0;

	if ((type != TYPE_SWPB) && (address & 0x3)) {
		/* SWP to unaligned address not permitted */
		pr_debug("SWP instruction on unaligned pointer!\n");
		return -EFAULT;
	}

	while (1) {
		unsigned long temp;

		if (type == TYPE_SWPB)
			__user_swpb_asm(*data, address, res, temp);
		else
			__user_swp_asm(*data, address, res, temp);

		if (likely(res != -EAGAIN) || signal_pending(current))
			break;

		cond_resched();
	}

	return res;
}

/*
 * swp_handler logs the id of calling process, dissects the instruction, sanity
 * checks the memory location, calls emulate_swpX for the actual operation and
 * deals with fixup/error handling before returning
 */
static int swp_handler(struct pt_regs *regs, u32 instr)
{
	u32 address, destreg, data, type;
	int rn, rt2, res = 0;

	if (!swp_enabled)
		return -EFAULT;

	perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS, 1, regs, regs->pc);

	type = instr & TYPE_SWPB;

	switch (arm_check_condition(instr, regs->pstate)) {
	case ARM_OPCODE_CONDTEST_PASS:
		break;
	case ARM_OPCODE_CONDTEST_FAIL:
		/* Condition failed - return to next instruction */
		goto ret;
	case ARM_OPCODE_CONDTEST_UNCOND:
		/* If unconditional encoding - not a SWP, undef */
		return -EFAULT;
	default:
		return -EINVAL;
	}

	rn = aarch32_insn_extract_reg_num(instr, RN_OFFSET);
	rt2 = aarch32_insn_extract_reg_num(instr, RT2_OFFSET);

	address = (u32)regs->user_regs.regs[rn];
	data	= (u32)regs->user_regs.regs[rt2];
	destreg = aarch32_insn_extract_reg_num(instr, RT_OFFSET);

	pr_debug("addr in r%d->0x%08x, dest is r%d, source in r%d->0x%08x)\n",
		rn, address, destreg,
		aarch32_insn_extract_reg_num(instr, RT2_OFFSET), data);

	/* Check access in reasonable access range for both SWP and SWPB */
	if (!access_ok(VERIFY_WRITE, (address & ~3), 4)) {
		pr_debug("SWP{B} emulation: access to 0x%08x not allowed!\n",
			address);
		goto fault;
	}

	res = emulate_swpX(address, &data, type);
	if (res == -EFAULT)
		goto fault;
	else if (res == 0)
		regs->user_regs.regs[destreg] = data;

ret:
	if (type == TYPE_SWPB)
		atomic_inc(&swpb_counter);
	else
		atomic_inc(&swp_counter);

	pr_warn_ratelimited("\"%s\" (%ld) uses obsolete SWP{B} instruction at 0x%llx\n",
			current->comm, (unsigned long)current->pid, regs->pc);

	regs->pc += 4;
	return 0;

fault:
	set_segfault(regs, address);

	return 0;
}

/*
 * Only emulate SWP/SWPB executed in ARM state/User mode.
 * The kernel must be SWP free and SWP{B} does not exist in Thumb.
 */
static struct undef_hook swp_hook = {
	.instr_mask	= 0x0fb00ff0,
	.instr_val	= 0x01000090,
	.pstate_mask	= COMPAT_PSR_MODE_MASK,
	.pstate_val	= COMPAT_PSR_MODE_USR,
	.fn		= swp_handler
};

static int debugfs_atomic_t_set(void *data, u64 val)
{
	atomic_set((atomic_t *)data, val);
	return 0;
}

static int debugfs_atomic_t_get(void *data, u64 *val)
{
	*val = atomic_read((atomic_t *)data);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(fops_atomic_t, debugfs_atomic_t_get,
			debugfs_atomic_t_set, "%lld\n");

static struct dentry *debugfs_create_atomic_t(const char *name, umode_t mode,
				struct dentry *parent, atomic_t *value)
{
	return debugfs_create_file(name, mode, parent, value, &fops_atomic_t);
}

static void __init swp_emulation_init(void)
{
	struct dentry *swp_d;

	atomic_set(&swp_counter, 0);
	atomic_set(&swpb_counter, 0);

	swp_d = debugfs_create_dir("swp_emulation", arch_debugfs_dir);
	if (!IS_ERR_OR_NULL(swp_d)) {
		debugfs_create_atomic_t("swp_count", S_IRUGO, swp_d, &swp_counter);
		debugfs_create_atomic_t("swpb_count", S_IRUGO, swp_d, &swpb_counter);
		debugfs_create_bool("enabled", S_IRUGO | S_IWUSR, swp_d,
				&swp_enabled);
	}

	if (register_undef_hook(&swp_hook) == 0)
		pr_notice("Registered SWP/SWPB emulation handler\n");
}

static atomic_t cp15_barrier_count;
static u32 cp15_barrier_enabled = 1;

static int cp15barrier_handler(struct pt_regs *regs, u32 instr)
{
	if (!cp15_barrier_enabled)
		return -EFAULT;

	perf_sw_event(PERF_COUNT_SW_EMULATION_FAULTS, 1, regs, regs->pc);

	switch (arm_check_condition(instr, regs->pstate)) {
	case ARM_OPCODE_CONDTEST_PASS:
		break;
	case ARM_OPCODE_CONDTEST_FAIL:
		/* Condition failed - return to next instruction */
		goto ret;
	case ARM_OPCODE_CONDTEST_UNCOND:
		/* If unconditional encoding - not a barrier instruction */
		return -EFAULT;
	default:
		return -EINVAL;
	}

	switch(aarch32_insn_mcr_extract_crm(instr)) {
	case 10:
		/*
		 * dmb - mcr p15, 0, Rt, c7, c10, 5
		 * dsb - mcr p15, 0, Rt, c7, c10, 4
		 */
		if (aarch32_insn_mcr_extract_opc2(instr) == 5)
			dmb(sy);
		else
			dsb();
		break;
	case 5:
		/*
		 * isb - mcr p15, 0, Rt, c7, c5, 4
		 */
		isb();
		break;
	}

ret:
	atomic_inc(&cp15_barrier_count);
	pr_warn_ratelimited("\"%s\" (%ld) uses deprecated CP15 Barrier instruction at 0x%llx\n",
			current->comm, (unsigned long)current->pid, regs->pc);

	regs->pc += 4;
	return 0;
}

/* data barrier */
static struct undef_hook cp15db_hook = {
	.instr_mask	= 0x0fff0fdf,
	.instr_val	= 0x0e070f9a,
	.pstate_mask	= COMPAT_PSR_MODE_MASK,
	.pstate_val	= COMPAT_PSR_MODE_USR,
	.fn		= cp15barrier_handler,
};

/* instruction barrier */
static struct undef_hook cp15isb_hook = {
	.instr_mask	= 0x0fff0fff,
	.instr_val	= 0x0e070f95,
	.pstate_mask	= COMPAT_PSR_MODE_MASK,
	.pstate_val	= COMPAT_PSR_MODE_USR,
	.fn		= cp15barrier_handler,
};

static void __init cp15_barrier_emulation_init(void)
{
	struct dentry *cp15_d;

	atomic_set(&cp15_barrier_count, 0);

	cp15_d = debugfs_create_dir("cp15_barrier_emulation", arch_debugfs_dir);
	if (!IS_ERR_OR_NULL(cp15_d)) {
		debugfs_create_atomic_t("cp15_barrier_count", S_IRUGO, cp15_d,
				&cp15_barrier_count);
		debugfs_create_bool("enabled", S_IRUGO | S_IWUSR, cp15_d,
				&cp15_barrier_enabled);
	}

	if (register_undef_hook(&cp15db_hook) == 0 &&
		register_undef_hook(&cp15isb_hook) == 0)
		pr_notice("Registered CP15 Barrier emulation handler\n");
}

/*
 * Invoked as late_initcall, since not needed before init spawned.
 */
static int __init v7_obsolete_init(void)
{
	if (IS_ENABLED(CONFIG_SWP_EMULATION))
		swp_emulation_init();

	/* Enable this only after we hit something */
	if (IS_ENABLED(CONFIG_CP15_BARRIER_EMULATION))
		cp15_barrier_emulation_init();

	return 0;
}

late_initcall(v7_obsolete_init);
