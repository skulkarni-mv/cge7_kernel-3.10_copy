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

#ifndef __ASM_ARCH_I2C_H
#define __ASM_ARCH_I2C_H

#include "io.h"
#include "irqs.h"

/* All frequencies are expressed in kHz */
struct PUMA_i2c_platform_data {
	unsigned int	bus_freq;	/* standard bus frequency */
	unsigned int	bus_delay;	/* transaction delay */
};

#endif /* __ASM_ARCH_I2C_H */
