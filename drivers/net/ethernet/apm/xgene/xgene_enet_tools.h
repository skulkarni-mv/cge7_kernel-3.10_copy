/* Applied Micro X-Gene SoC Ethernet Driver
 *
 * Copyright (c) 2014 Applied Micro Circuits Corporation.
 * Authors: Hrishikesh Karanjikar <hkaranjikar@apm.com>
 *	    Keyur Chudgar <kchudgar@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __XGENE_ENET_TOOLS_H__
#define __XGENE_ENET_TOOLS_H__

#include <linux/netdevice.h>
#include <linux/ethtool.h>

/* MII definitions */

#define MII_CTRL_REG		0x0	/* Control Register */

/* MII control register bit  */

#define MII_CR_1000		0x0040		/* 1 = 1000mb when
						   MII_CR_100 is also 1 */
#define MII_CR_FDX		0x0100		/* FDX =1, half duplex =0 */
#define MII_CR_RESTART		0x0200		/* restart auto negotiation */
#define MII_CR_POWER_DOWN	0x0800		/* power down */
#define MII_CR_AUTO_EN		0x1000		/* auto-negotiation enable */
#define MII_CR_100		0x2000		/* 0 = 10mb, 1 = 100mb */
#define MII_CR_RESET		0x8000		/* 0 = normal, 1 = PHY reset */

#define FLAG_RX_CSUM_ENABLED 	(1 << 0)

int xgene_ethtool_get_settings(struct net_device *ndev, 
			    struct ethtool_cmd *cmd);

int xgene_ethtool_set_settings(struct net_device *ndev, 
			    struct ethtool_cmd *cmd);

int xgene_ethtool_set_pauseparam(struct net_device *ndev,
			      struct ethtool_pauseparam *pp);

void xgene_ethtool_get_pauseparam(struct net_device *ndev,
			       struct ethtool_pauseparam *pp);

int xgene_ethtool_set_tx_csum(struct net_device *ndev, u32 set);

u32 xgene_ethtool_get_tx_csum(struct net_device *ndev);

u32 xgene_ethtool_get_sg(struct net_device *ndev);

int xgene_ethtool_set_sg(struct net_device *ndev, u32 set);

int xgene_ethtool_nway_reset(struct net_device *ndev);

void xgene_ethtool_get_ethtool_stats(struct net_device *ndev,
				  struct ethtool_stats *estats,
				  u64 *tmp_stats);

void xgene_ethtool_get_drvinfo(struct net_device *ndev,
			    struct ethtool_drvinfo *info);

u32 xgene_ethtool_op_get_link(struct net_device *ndev);

u32 xgene_ethtool_get_tso(struct net_device *ndev);

int xgene_ethtool_set_tso(struct net_device *dev, u32 set);

int xgene_get_sset_count(struct net_device *ndev, int sset);

void xgene_get_strings(struct net_device *netdev, u32 stringset, u8 *data);

extern const struct ethtool_ops xgene_ethtool_ops;

#endif
