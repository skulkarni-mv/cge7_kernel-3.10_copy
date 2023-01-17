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

#include <linux/ethtool.h>

#include "pse.h"

static void pse_get_drvinfo(struct net_device *netdev,
				struct ethtool_drvinfo *drvinfo)
{
	strncpy(drvinfo->driver, DRV_NAME, 32);
	strncpy(drvinfo->version, DRV_VERSION, 32);
	strncpy(drvinfo->fw_version, "N/A", 32);
	strncpy(drvinfo->bus_info, "N/A", 32);
}

static int pse_get_settings(struct net_device *dev,
				struct ethtool_cmd *cmd)
{
	struct pse_priv *priv = netdev_priv(dev);
	u32 val, addr, speed_st[3] = {SPEED_10, SPEED_100, SPEED_1000};

	if (priv->pse_flags == PSE_FLAG_PHY_CONNECTED) {
		if (!priv->phy_dev)
			return -ENODEV;
		return phy_ethtool_gset(priv->phy_dev, cmd);
	} else {
		/* connected to switch chip */
		if (priv->phy_dev)
			return phy_ethtool_gset(priv->phy_dev, cmd);


		switch (priv->sp) {
		case OPV5XC_PSE_PORT_MAC0:
			addr = MAC0_CFG;
			break;
		case OPV5XC_PSE_PORT_MAC1:
			addr = MAC1_CFG;
			break;
		case OPV5XC_PSE_PORT_MAC2:
			addr = MAC2_CFG;
			break;
		default:
			return -EINVAL;
		}

		val = rd32(addr);

		ethtool_cmd_speed_set(cmd, speed_st[((val >> 2) & 0x3)]);
		cmd->autoneg = ((val >> 7) & 1) ? AUTONEG_ENABLE : AUTONEG_DISABLE;
		cmd->duplex = ((val >> 4) & 0x1) ? DUPLEX_FULL : DUPLEX_HALF;

		cmd->supported = SUPPORTED_10baseT_Half |
						 SUPPORTED_10baseT_Full |
						 SUPPORTED_100baseT_Half |
						 SUPPORTED_100baseT_Full |
						 SUPPORTED_1000baseT_Half |
						 SUPPORTED_1000baseT_Full |
						 SUPPORTED_TP |
						 SUPPORTED_MII |
						 SUPPORTED_Pause;

		cmd->phy_address = priv->phy_addr;
	}
	return 0;
}

static int pse_set_settings(struct net_device *dev,
				struct ethtool_cmd *cmd)
{
	struct pse_priv *priv = netdev_priv(dev);
	u32 val, addr;
	int ret;

	if (priv->pse_flags == PSE_FLAG_PHY_CONNECTED) {
		if (!priv->phy_dev)
			return -ENODEV;
#if defined(CONFIG_ARCH_OPV5XC_CX4)
		/* FPGA platform */
		cmd->advertising &=  ~(ADVERTISED_1000baseT_Half | ADVERTISED_1000baseT_Full);
#endif
		ret = phy_ethtool_sset(priv->phy_dev, cmd);
		if (ret)
			return ret;
	} else {
		/* connected to switch chip */
		if (priv->phy_dev) {
			if (cmd->autoneg == AUTONEG_ENABLE) {
				cmd->advertising |= ((priv->phy_dev->supported & ADVERTISED_Pause) |
									(priv->phy_dev->supported & ADVERTISED_Asym_Pause));
			}
			return phy_ethtool_sset(priv->phy_dev, cmd);
		}

		if (cmd->autoneg == AUTONEG_ENABLE)
			return -EINVAL;
	}

	/* update to MAC */

	switch (priv->sp) {
	case OPV5XC_PSE_PORT_MAC0:
		addr = MAC0_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		addr = MAC1_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		addr = MAC2_CFG;
		break;
	default:
		return -EINVAL;
	}

	val = rd32(addr);

	if (cmd->autoneg != AUTONEG_ENABLE) {
		val &= ~(0x1 << 7);

		/* force speed */
		val &= ~(0x3 << 8);
		if (cmd->speed == SPEED_10)
			val |= (0x0 << 8);
		else if (cmd->speed == SPEED_100)
			val |= (0x1 << 8);
		else if (cmd->speed == SPEED_1000)
			val |= (0x2 << 8);
		else
			return -EINVAL;

		/* force duplex */
		val &= ~(0x1 << 10);
		val |= (cmd->duplex << 10);
	} else {
		val |= (0x1 << 7);
	}
	wr32(val, addr);
	return 0;
}

static void pse_get_pauseparam(struct net_device *dev,
				struct ethtool_pauseparam *cmd)
{
	struct pse_priv *priv = netdev_priv(dev);
	u32 val, addr;

	switch (priv->sp) {
	case OPV5XC_PSE_PORT_MAC0:
		addr = MAC0_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		addr = MAC1_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		addr = MAC2_CFG;
		break;
	default:
		return;
	}
	val = rd32(addr);

	if (priv->phy_dev)
		cmd->autoneg = priv->phy_dev->autoneg;
	else
		cmd->autoneg = (val >> 7) & 0x1;

	cmd->rx_pause = (val >> 5) & 0x1;
	cmd->tx_pause = (val >> 6) & 0x1;
}

static int pse_set_pauseparam(struct net_device *dev,
				struct ethtool_pauseparam *cmd)
{
	struct pse_priv *priv = netdev_priv(dev);
	struct ethtool_cmd setcmd;
	int	ret;
	u32 val, addr;

	if (priv->pse_flags == PSE_FLAG_PHY_CONNECTED) {
		if (!priv->phy_dev)
			return -ENODEV;

		phy_ethtool_gset(priv->phy_dev, &setcmd);
		setcmd.autoneg = cmd->autoneg;
		if (cmd->rx_pause && cmd->tx_pause)
			setcmd.advertising |= ADVERTISED_Pause;
		else
			setcmd.advertising &= ~(ADVERTISED_Pause);

		ret = phy_ethtool_sset(priv->phy_dev, &setcmd);
		if (ret)
			return ret;
	} else {
		/* connected to switch chip */
		if (priv->phy_dev && (priv->phy_dev->supported & SUPPORTED_Autoneg)) {
			phy_ethtool_gset(priv->phy_dev, &setcmd);
			setcmd.autoneg = cmd->autoneg;
			if (cmd->rx_pause && cmd->tx_pause)
				setcmd.advertising |= ADVERTISED_Pause;
			else
				setcmd.advertising &= ~(ADVERTISED_Pause);

			return phy_ethtool_sset(priv->phy_dev, &setcmd);
		}
	}

	/* update to MAC */
	switch (priv->sp) {
	case OPV5XC_PSE_PORT_MAC0:
		addr = MAC0_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		addr = MAC1_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		addr = MAC2_CFG;
		break;
	default:
		return -EINVAL;
	}
	val = rd32(addr);

	if (cmd->autoneg == AUTONEG_ENABLE)
		val |= (0x1 << 7);
	else
		val &= ~(0x1 << 7);

	val &= ~(0x1 << 11);
	val |= (cmd->rx_pause << 11);
	val |= (cmd->tx_pause << 12);
	wr32(val, addr);
	return 0;
}

static struct ethtool_ops pse_ethtool_ops = {
	.get_settings		= pse_get_settings,
	.set_settings		= pse_set_settings,
	.get_drvinfo		= pse_get_drvinfo,
	.get_pauseparam		= pse_get_pauseparam,
	.set_pauseparam		= pse_set_pauseparam,
	.get_link           = ethtool_op_get_link,
};

void pse_set_ethtool_ops(struct net_device *netdev)
{
	SET_ETHTOOL_OPS(netdev, &pse_ethtool_ops);
}
