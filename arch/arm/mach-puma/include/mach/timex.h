/*
 * Copyright (C) 2010 Wind River Systems, Inc.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef __ASM_ARCH_TIMEX_H
#define __ASM_ARCH_TIMEX_H

#define PUMA_CLK_LOW    75000000
#define PUMA_CLK_HIGH   100000000

#ifndef CLOCK_TICK_RATE

#ifdef CONFIG_PUMA_CLOCK_LOW
#define CLOCK_TICK_RATE PUMA_CLK_LOW
#endif

/* default: high speed clock */
#define CLOCK_TICK_RATE PUMA_CLK_HIGH

#endif

#endif /* __ASM_ARCH_TIMEX_H */
