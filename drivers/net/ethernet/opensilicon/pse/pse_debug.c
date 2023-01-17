/*
 * Author: Open Silicon, Inc.
 * Contact: platform@open-silicon.com
 * This file is part of the Voledia SDK
 *
 * Copyright (c) 2012 Open-Silicon Inc.
 *
 * This file is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License, Version 2, as published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but AS-IS and WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE, TITLE, or NONINFRINGEMENT. See the GNU
 * General Public License for more details.
 *
 * This file may also be available under a different license from Open-Silicon.
 * Contact Open-Silicon for more information
 */

#include "pse.h"

#if defined(PSE_DEBUG)
#include <linux/kdebug.h>

#define PDUMP pr_emerg

static int debug_level = DEBUG_LEVEL_INFO;

void pse_debug_level_cfg(int level)
{
	if ((level < DEBUG_LEVEL_TRACE) || (level > DEBUG_LEVEL_ERROR))
		return;
	debug_level = level;
}

int pse_debug_level(void)
{
	return debug_level;
}

static void dump_pse(void)
{
	int i, start, end;

	PDUMP("================================================\n");
	PDUMP("PSE REG\n");

	start = 0x0; end = 0x00FC;
	for (i = start; i <= end; i += 4)
		PDUMP("offset 0x%.4x:   0x%.8x\n", i, rd32(i));

	start = 0x100; end = 0x01FC;
	for (i = start; i <= end; i += 4)
		PDUMP("offset 0x%.4x:   0x%.8x\n", i, rd32(i));
}

static void dump_cfp(void)
{
	int i, start, end;

	PDUMP("================================================\n");
	PDUMP("CFP REG\n");

	start = 0x000; end = 0x09C;
	for (i = start; i <= end; i += 4)
		PDUMP("offset 0x%.4x:   0x%.8x\n", i, frd32(i));

	start = 0x400; end = 0x4BC;
	for (i = start; i <= end; i += 4)
		PDUMP("offset 0x%.4x:   0x%.8x\n", i, frd32(i));

}

static int die_notifier(struct notifier_block *self, unsigned long cmd, void *ptr)
{
	switch (cmd) {
	case DIE_OOPS:
		dump_pse();
		dump_cfp();
		break;
	default:
		break;
	}

	return 0;
}

struct notifier_block pse_die_notifier = {
	.notifier_call  = die_notifier,
	.priority       = -INT_MAX,
};
#endif

void pse_debug_init(void)
{
#if defined(PSE_DEBUG)
	register_die_notifier(&pse_die_notifier);
#endif
};

void pse_debug_fini(void)
{
#if defined(PSE_DEBUG)
	unregister_die_notifier(&pse_die_notifier);
#endif
};
