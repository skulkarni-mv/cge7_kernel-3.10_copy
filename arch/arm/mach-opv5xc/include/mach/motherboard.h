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

#ifndef __MACH_MOTHERBOARD_H
#define __MACH_MOTHERBOARD_H

/*
 * Core tile IDs
 */
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
#define OPV5XC_CT_ID_CA9		0x413fc090
#else
#define OPV5XC_CT_ID_CA9		0x0c000191
#endif
#define OPV5XC_CT_ID_UNSUPPORTED	0xff000191
#define OPV5XC_CT_ID_MASK		0xff000fff

struct ct_desc {
	u32		id;
	const char	*name;
	void		(*map_io)(void);
	void		(*init_early)(void);
	void		(*init_irq)(void);
	void		(*init_tile)(void);
#ifdef CONFIG_SMP
	void		(*init_cpu_map)(void);
	void		(*smp_enable)(unsigned int);
#endif
};

extern struct ct_desc *ct_desc;

#endif
