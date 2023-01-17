/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1997, 99, 2001 - 2004 Ralf Baechle <ralf@linux-mips.org>
 */
#include <linux/module.h>
#include <linux/spinlock.h>
#include <asm/branch.h>
#include <asm/uaccess.h>
#include <asm/sections.h>

#define LOAD_OFFSET ((unsigned long long)_text - (unsigned long long)VMLINUX_LOAD_ADDRESS)
int fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *fixup;

	fixup = search_exception_tables(exception_epc(regs) - LOAD_OFFSET);
	if (fixup) {
		regs->cp0_epc = fixup->nextinsn + LOAD_OFFSET;

		return 1;
	}

	return 0;
}
