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

#define PSE_PHY_DEBUG
#undef PSE_PHY_DEBUG

static int pse_update_mac_link(struct pse_priv *priv)
{
	struct phy_device *phydev = priv->phy_dev;
	u32 val, offset;

	switch (priv->sp) {
	case OPV5XC_PSE_PORT_MAC0:
		offset = MAC0_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		offset = MAC1_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		offset = MAC2_CFG;
		break;
	default:
		return PSE_FAIL;
	}

	val = rd32(offset);

	if (phydev->link && !(val & (0x1 << 7))) {
		/* update speed */
		val &= ~(0x3 << 8);
		if (phydev->speed == SPEED_10)
			val |= (0x0 << 8);
		else if (phydev->speed == SPEED_100)
			val |= (0x1 << 8);
		else if (phydev->speed == SPEED_1000)
			val |= (0x2 << 8);

		/* update duplex */
		val &= ~(0x1 << 10);
		val |= (phydev->duplex << 10);
		wr32(val, offset);
	}

	return PSE_OK;
}

static void pse_adjust_link(struct net_device *ndev)
{
	struct pse_priv *priv = netdev_priv(ndev);
	struct phy_device *phydev = priv->phy_dev;
	int link_changed = 0;

	if (!(PSE_FLAG_PHY_CONNECTED & priv->pse_flags))
		return;

	/* phydev->link: current state
	 * priv->link: previous state
	 */
	if (phydev->link) { /* is not PHY_DOWN */
		if (!priv->link) {
			/* down => up */
			link_changed = 1;
		}
	} else {
		if (priv->link) {
			/* up => down */
			link_changed = -1;
		}
	}
#ifdef PSE_PHY_DEBUG
	P_TRACE("priv->link %d, phydev->link %d\n", priv->link, phydev->link);
#endif

	priv->link = phydev->link;
	priv->link_speed = phydev->speed;
	priv->link_duplex = phydev->duplex;

	/* need update to MAC as link up and AN_EN=0 */
	pse_update_mac_link(priv);

#ifdef PSE_PHY_DEBUG
	P_TRACE("link %d, link_speed %d, link_duplex %d\n",
		priv->link, priv->link_speed, priv->link_duplex);
#endif

	if (link_changed) {
		if (0 < link_changed)
			netif_carrier_on(ndev);
		else
			netif_carrier_off(ndev);
#ifdef PSE_PHY_STATUS_DISPLAY
		phy_print_status(phydev);
#endif
	}
}

void pse_phy_start(struct net_device *dev)
{
	struct pse_priv *priv = netdev_priv(dev);
	struct phy_device *phydev;

	P_TRACE("<%s>\n", __func__);

	phydev = priv->phy_dev;

#if 0
	if (!(priv->pse_flags & PSE_FLAG_PHY_CONNECTED)) {
		/* FIXME we have to do something if connect to switch */
		P_TRACE("pse_flags 0x%.8x\n", priv->pse_flags);
		return;
	}
#endif

	if (priv->phy_dev) {
		P_TRACE("<%s> has phy_dev\n", __func__);
		phy_start(phydev);
		phy_start_aneg(phydev);
#ifdef PSE_PHY_DEBUG
	P_TRACE("phy_id 0x%.8x interface %d state %d dev_flags %d\n",
		phydev->phy_id, phydev->interface,
		phydev->state, phydev->dev_flags);
	P_TRACE("addr %d speed %d\n",
		phydev->addr, phydev->speed);
#endif
#ifdef PSE_PHY_DEBUG
	} else {
		P_TRACE("<%s> has no phy_dev\n", __func__);
#endif
	}
};

void pse_phy_stop(struct net_device *dev)
{
	struct pse_priv *priv = netdev_priv(dev);
	struct phy_device *phydev;

	if (priv->phy_dev) {
		phydev = priv->phy_dev;
		phy_stop(phydev);

		/* release phy */
		phy_disconnect(phydev);
		priv->phy_dev = NULL;
	}

	/* TODO: if connect to switch  */
};

int pse_phy_init(struct pse_priv *priv)
{
	char phy_id[MII_BUS_ID_SIZE + 3];
	struct phy_device *phydev = NULL;

	snprintf(phy_id, sizeof(phy_id), "%s:%02x", priv->res->mii_bus->id, priv->phy_addr);

	phydev = phy_connect(priv->netdev, phy_id,
			&pse_adjust_link, PHY_INTERFACE_MODE_RGMII);

	if (IS_ERR(phydev)) {
		dev_err(&priv->netdev->dev, "phy_connect failed\n");
		return PTR_ERR(phydev);
	}

	if (PSE_FLAG_PHY_CONNECTED & priv->pse_flags) {
		phydev->supported = (PHY_GBIT_FEATURES | SUPPORTED_Pause);
		phydev->advertising = phydev->supported;
	}

#if defined(CONFIG_ARCH_OPV5XC_CX4)
	/* FPGA platform */
	phydev->advertising &= ~(ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full);
#endif

	dev_info(&priv->netdev->dev, "attached phy %i to driver %s\n",
		phydev->addr, phydev->drv->name);

#ifdef PSE_PHY_DEBUG
	P_TRACE("phy_id 0x%.8x interface %d state %d dev_flags %d\n",
		phydev->phy_id, phydev->interface,
		phydev->state, phydev->dev_flags);
	P_TRACE("addr %d speed %d\n",
		phydev->addr, phydev->speed);
#endif

	priv->phy_dev = phydev;
#if 0
	priv->open = pse_phy_start;
	priv->close = pse_phy_stop;
#endif
	priv->link = 0;
	priv->link_speed = 0;
	priv->link_duplex = 0;

	return 0;
}
