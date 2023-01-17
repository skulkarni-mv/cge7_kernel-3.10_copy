/*
 * Copyright (C) 2015 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __BROADCOM_CMIC_MDIO
#define __BROADCOM_CMIC_MDIO

#include <linux/types.h>

enum {
	INTERNAL,
	EXTERNAL
};

enum {
	CLAUS22,
	CLAUS45
};

u16
cmic_mdio_read(u32 ext, u32 claus, u32 busid, u32 phyaddr, u32 reg, u16 *val);

int
cmic_mdio_write(u32 ext, u32 claus, u32 busid, u32 phyaddr, u32 reg, u16 val);

#endif /* __BROADCOM_CMIC_MDIO */
