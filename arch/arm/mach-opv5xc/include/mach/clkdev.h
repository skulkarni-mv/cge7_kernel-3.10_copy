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

#ifndef __ASM_MACH_CLKDEV_H
#define __ASM_MACH_CLKDEV_H

struct clk {
	struct device		*dev;
	const char		*name;
	struct clk		*parent;
	char			**parent_names;
	struct clk		**parents;
	u8			num_parents;
	unsigned long		rate;
	unsigned long		new_rate;
	unsigned long		flags;
	unsigned int		enable_count;
	unsigned int		prepare_count;
	unsigned int		notifier_count;
	spinlock_t		lock;
	void			(*init) (struct clk *);
	int			(*set_rate) (struct clk *, unsigned long);
	unsigned long		(*get_rate) (struct clk *);
	void			(*recalc) (struct clk *);
	unsigned long		(*round_rate) (struct clk *, unsigned long);
	void			(*enable) (struct clk *);
	void			(*disable) (struct clk *);
};

#define __clk_get(clk) ({ 1; })
#define __clk_put(clk) do { } while (0)

extern int opv5xc_clock_init(void);

#endif
