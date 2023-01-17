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

#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/io.h>
#include "pse.h"

#define OPV5XC_PHY_ADDR_MAP	(0xffffffff)
#define OPV5XC_PHY_MASK		(~(OPV5XC_PHY_ADDR_MAP))

#define PSE_MII_RW_DELAY() udelay(10);

/* PHY_CTRL */
#define RW_DATA_OFFSET	(16)
#define RW_OK_OFFSET	(15)
#define RD_CMD_OFFSET	(14)
#define WT_CMD_OFFSET	(13)
#define PHY_REG_OFFSET	(8)
#define MI_DIS_OFFSET	(7)
#define PHY_ADDR_OFFSET	(0)

static void pse_mdio_enable(bool enable)
{
	int reg;

	reg = rd32(PHY_CTRL);

	if (enable) {
		/* clear MI_DIS bit */
		reg &= ~(0x1 << MI_DIS_OFFSET);
	} else {
		reg |= (0x1 << MI_DIS_OFFSET);
	}

	wr32(reg, PHY_CTRL);
}

/* pse_mii_read - read PHY's register
 * @bus:
 * @addr: PHY address
 * @reg: PHY register
 */
static int pse_mii_read(struct mii_bus *bus, int addr, int reg)
{
	int val;

	wr32((0x1 << RW_OK_OFFSET), PHY_CTRL);

	PSE_MII_RW_DELAY(); /* XXX this delay is necessary */

	val = ((addr & 0x1F) << PHY_ADDR_OFFSET)
		| ((reg & 0x1F) << PHY_REG_OFFSET)
		| (0x1 << RD_CMD_OFFSET);

	/* issue command */
	wr32(val, PHY_CTRL);

	/* wait for command complete */
	while (!(val & (0x1 << RW_OK_OFFSET)))
		val = rd32(PHY_CTRL);

	/* store data */
	val = (val >> RW_DATA_OFFSET) & 0xFFFF;

	/*clear complete bit */
	wr32((0x1 << RW_OK_OFFSET), PHY_CTRL);

	return val;
}

/* pse_mii_write - write PHY's register
 * @bus:
 * @addr: PHY address
 * @reg: PHY register
 * @data: register data
 */
static int pse_mii_write(struct mii_bus *bus, int addr, int reg, u16 data)
{
	int val;

	val = ((addr & 0x1F) << PHY_ADDR_OFFSET)
		| ((reg & 0x1F) << PHY_REG_OFFSET)
		| ((data & 0xFFFF) << RW_DATA_OFFSET)
		| (0x1 << WT_CMD_OFFSET);

	/* issue command */
	wr32(val, PHY_CTRL);

	/* wait for command complete */
	while (!(val & (0x1 << RW_OK_OFFSET)))
		val = rd32(PHY_CTRL);

	/*clear complete bit */
	wr32((0x1 << RW_OK_OFFSET), PHY_CTRL);
	PSE_MII_RW_DELAY(); /* XXX this delay is necessary */

	return 0;
}

int pse_mii_init(struct pse_resource *res)
{
	struct mii_bus *mii_bus;

	mii_bus = mdiobus_alloc();

	if (!mii_bus) {
		P_ERR("Fail to alloc mii_bus\n");
		return -ENOMEM;
	}

	pse_mdio_enable(true);

	mii_bus->priv = res;
	mii_bus->parent = &(res->pdev->dev);
	mii_bus->read = pse_mii_read;
	mii_bus->write = pse_mii_write;
	mii_bus->name = "pse_mii_bus";
	mii_bus->phy_mask = OPV5XC_PHY_MASK;
	snprintf(mii_bus->id, MII_BUS_ID_SIZE, "%x", res->pdev->id);

	if (mdiobus_register(mii_bus))
		goto error_register;

	res->mii_bus = mii_bus;

	return 0;

error_register:
	P_ERR("<%s>: Fail to register mii_bus\n", __func__);
	mdiobus_free(mii_bus);
	return -1;
}

void pse_mii_fini(struct pse_resource *res)
{
	pse_mdio_enable(false);
	mdiobus_unregister(res->mii_bus);
	mdiobus_free(res->mii_bus);
}
