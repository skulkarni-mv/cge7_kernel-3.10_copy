/* AppliedMicro X-Gene SoC Ethernet Driver
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

#include <linux/mii.h>
#include <linux/phy.h>
#include "xgene_enet_main.h"
#include "xgene_enet_gmac.h"
#include "xgene_enet_xgmac.h"
#include "xgene_enet_tools.h"

#define XGENE_GLOBAL_STATS_LEN ARRAY_SIZE(xgene_gstrings_stats)

#define XGENE_XGMAC_ADVERTISED_MASK	(ADVERTISED_10000baseT_Full)

#define XGENE_STAT_OFFSET(m) offsetof(struct xgene_enet_pdata, m)
		      
const struct ethtool_ops xgene_ethtool_ops = {
	.get_settings = xgene_ethtool_get_settings,
	.set_settings = xgene_ethtool_set_settings,
	.get_drvinfo = xgene_ethtool_get_drvinfo,
	.nway_reset = xgene_ethtool_nway_reset,
	.get_pauseparam = xgene_ethtool_get_pauseparam,
	.set_pauseparam = xgene_ethtool_set_pauseparam,
	.get_tx_csum = xgene_ethtool_get_tx_csum,
	.set_tx_csum = xgene_ethtool_set_tx_csum,
	.get_sg = xgene_ethtool_get_sg,
	.set_sg = xgene_ethtool_set_sg,
	.get_tso = xgene_ethtool_get_tso,
	.set_tso = xgene_ethtool_set_tso,
	.get_ethtool_stats = xgene_ethtool_get_ethtool_stats,
	.get_sset_count = xgene_get_sset_count,
	.get_strings = xgene_get_strings,
	.get_link = ethtool_op_get_link,
};

struct xgene_stats {
	char stat_string[ETH_GSTRING_LEN];
	int stat_offset;
};

static const struct xgene_stats xgene_gstrings_stats[] = {
	{ "c_64B", XGENE_STAT_OFFSET(stats.eth_combined_stats.c_64B_frames) },
	{ "c_65_127B",
		XGENE_STAT_OFFSET(stats.eth_combined_stats.c_65_127B_frames) },
	{ "c_128_255B",
		XGENE_STAT_OFFSET(stats.eth_combined_stats.c_128_255B_frames) },
	{ "c_256_511B",
		XGENE_STAT_OFFSET(stats.eth_combined_stats.c_256_511B_frames) },
	{ "c_512_1023B",
		XGENE_STAT_OFFSET(stats.eth_combined_stats.c_512_1023B_frames) },
	{ "c_1024_1518B",
		XGENE_STAT_OFFSET(stats.eth_combined_stats.c_1024_1518B_frames) },
	{ "c_1519_1522B",
		XGENE_STAT_OFFSET(stats.eth_combined_stats.c_1519_1522B_frames) },
	{ "rx_packets", XGENE_STAT_OFFSET(stats.rx_stats.rx_packet_count) },
	{ "rx_bytes", XGENE_STAT_OFFSET(stats.rx_stats.rx_byte_count) },
	{ "rx_drop", XGENE_STAT_OFFSET(stats.rx_stats.rx_drop_pkt_count) },
	{ "rx_multicast", XGENE_STAT_OFFSET(stats.rx_stats.rx_multicast_pkt_count) },
	{ "rx_broadcast", XGENE_STAT_OFFSET(stats.rx_stats.rx_broadcast_pkt_count) },
	{ "rx_cntrl", XGENE_STAT_OFFSET(stats.rx_stats.rx_cntrl_frame_pkt_count) },
	{ "rx_pause", XGENE_STAT_OFFSET(stats.rx_stats.rx_pause_frame_pkt_count) },
	{ "rx_unknown_op",
		XGENE_STAT_OFFSET(stats.rx_stats.rx_unknown_op_pkt_count)},
	{ "rx_fcs_err", XGENE_STAT_OFFSET(stats.rx_stats.rx_fcs_err_count) },
	{ "rx_alignment_err",
		XGENE_STAT_OFFSET(stats.rx_stats.rx_alignment_err_pkt_count) },
	{ "rx_frm_len_err",
		XGENE_STAT_OFFSET(stats.rx_stats.rx_frm_len_err_pkt_count) },
	{ "rx_code_err", XGENE_STAT_OFFSET(stats.rx_stats.rx_code_err_pkt_count) }, 
	{ "rx_false_carrier_err",
		XGENE_STAT_OFFSET(stats.rx_stats.rx_false_carrier_count) },
	{ "rx_undersize", XGENE_STAT_OFFSET(stats.rx_stats.rx_undersize_pkt_count) },
	{ "rx_oversize", XGENE_STAT_OFFSET(stats.rx_stats.rx_oversize_pkt_count) },
	{ "rx_fragment", XGENE_STAT_OFFSET(stats.rx_stats.rx_fragment_count) },
	{ "rx_jabber", XGENE_STAT_OFFSET(stats.rx_stats.rx_jabber_count) },
	{ "rx_overrun", XGENE_STAT_OFFSET(stats.rx_stats.rx_icm_drop_count) },
	{ "rx_total_err", XGENE_STAT_OFFSET(stats.rx_stats.rx_total_err_count) },
	{ "tx_packets", XGENE_STAT_OFFSET(stats.tx_stats.tx_packet_count) },
	{ "tx_bytes", XGENE_STAT_OFFSET(stats.tx_stats.tx_byte_count) },
	{ "tx_drop", XGENE_STAT_OFFSET(stats.tx_stats.tx_drop_frm_count) },
	{ "tx_multicast", XGENE_STAT_OFFSET(stats.tx_stats.tx_multicast_pkt_count) },
	{ "tx_broadcast", XGENE_STAT_OFFSET(stats.tx_stats.tx_broadcast_pkt_count) },
	{ "tx_cntrl", XGENE_STAT_OFFSET(stats.tx_stats.tx_cntrl_frame_pkt_count) },
	{ "tx_pause", XGENE_STAT_OFFSET(stats.tx_stats.tx_pause_frame_count) },
	{ "tx_deferra", XGENE_STAT_OFFSET(stats.tx_stats.tx_deferral_pkt_count) },
	{ "tx_exesiv_def",
		XGENE_STAT_OFFSET(stats.tx_stats.tx_exesiv_def_pkt_count) },
	{ "tx_single_coll",
		XGENE_STAT_OFFSET(stats.tx_stats.tx_single_coll_pkt_count) },
	{ "tx_multi_coll",
		XGENE_STAT_OFFSET(stats.tx_stats.tx_multi_coll_pkt_count) },
	{ "tx_late_coll", XGENE_STAT_OFFSET(stats.tx_stats.tx_late_coll_pkt_count) }, 
	{ "tx_exesiv_coll",
		XGENE_STAT_OFFSET(stats.tx_stats.tx_exesiv_coll_pkt_count) },
	{ "tx_toll_coll", XGENE_STAT_OFFSET(stats.tx_stats.tx_toll_coll_pkt_count) },
	{ "tx_pause_hon", XGENE_STAT_OFFSET(stats.tx_stats.tx_pause_frm_hon_count) },
	{ "tx_jabber", XGENE_STAT_OFFSET(stats.tx_stats.tx_jabber_frm_count) },
	{ "tx_fcs_err", XGENE_STAT_OFFSET(stats.tx_stats.tx_fcs_err_frm_count) },
	{ "tx_control", XGENE_STAT_OFFSET(stats.tx_stats.tx_control_frm_count) },
	{ "tx_oversize", XGENE_STAT_OFFSET(stats.tx_stats.tx_oversize_frm_count) },
	{ "tx_undersize", XGENE_STAT_OFFSET(stats.tx_stats.tx_undersize_frm_count) },
	{ "tx_fragments", XGENE_STAT_OFFSET(stats.tx_stats.tx_fragments_frm_count) },
	{ "tx_underrun", XGENE_STAT_OFFSET(stats.tx_stats.tx_ecm_drop_count) },
};

/* Ethtool APIs */

int xgene_ethtool_get_settings(struct net_device *ndev,
		struct ethtool_cmd *cmd)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct phy_device *phydev = pdata->phy_dev;

	if (pdata->mac_ops.type != XGENE_XGMAC) {
		if (!phydev)
			return -ENODEV;
		return phy_ethtool_gset(phydev, cmd);
	} else {
		cmd->port = PORT_FIBRE;
		cmd->phy_address = pdata->phy_addr;
		cmd->transceiver = XCVR_EXTERNAL;

		cmd->supported = cmd->advertising = XGENE_XGMAC_ADVERTISED_MASK;

		cmd->supported |= SUPPORTED_FIBRE;
		cmd->advertising |= SUPPORTED_FIBRE;

		cmd->autoneg = AUTONEG_DISABLE;

		if (netif_running(ndev)) {
			if (ethtool_op_get_link(ndev)) {
				cmd->duplex = DUPLEX_FULL;
				cmd->speed = SPEED_10000;
			} else {
				cmd->duplex = -1;
				cmd->speed = -1;
			}
		} else {
			cmd->duplex = -1;
			cmd->speed = -1;
		}
	}
	return 0;
}

int xgene_ethtool_set_settings(struct net_device *ndev,
		struct ethtool_cmd *cmd)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct phy_device *phydev = pdata->phy_dev;

	if (pdata->mac_ops.type != XGENE_XGMAC) {
		if (!phydev)
			return -ENODEV;
		return phy_ethtool_sset(phydev, cmd);
	} else {
		if ((cmd->autoneg == AUTONEG_ENABLE) || 
				(cmd->speed != SPEED_10000) ||
				(cmd->duplex != DUPLEX_FULL)) {
			return -EINVAL;
		}
	}
	return 0;
}

int xgene_ethtool_set_pauseparam(struct net_device *ndev,
		struct ethtool_pauseparam *pp)
{
	u32 data;
	u32 addr;
	u32 rx_flow_en_bit;
	u32 tx_flow_en_bit;
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);

	if (pdata->mac_ops.type == XGENE_GMAC) {
		addr = MAC_CONFIG_1_ADDR;
		rx_flow_en_bit = RX_FLOW_EN;
		tx_flow_en_bit = TX_FLOW_EN;
	} else {
		addr = AXGMAC_CONFIG_1;
		rx_flow_en_bit = HSTRCTLEN;
		tx_flow_en_bit = HSTTCTLEN;
	}

	pdata->enet_rd_wr_ops.rd_mac(pdata, addr, &data);

	/* Modify value to set or reset rx flow control */
	if (pp->rx_pause)
		data |= rx_flow_en_bit;
	else
		data &= ~(rx_flow_en_bit);

	/* Modify value to set or reset tx flow control */
	if (pp->tx_pause)
		data |= tx_flow_en_bit;
	else
		data &= ~(tx_flow_en_bit);

	pdata->enet_rd_wr_ops.wr_mac(pdata, addr, data);

	return 0;
}

void xgene_ethtool_get_pauseparam(struct net_device *ndev,
		struct ethtool_pauseparam *pp)
{
	u32 data;
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);

	if (pdata->mac_ops.type == XGENE_GMAC) {
		pdata->enet_rd_wr_ops.rd_mac(pdata, MAC_CONFIG_1_ADDR, &data);
		pp->rx_pause = MCX_RD_RX_FLOW_EN(data);
		pp->tx_pause = MCX_RD_TX_FLOW_EN(data);
	} else {
		pdata->enet_rd_wr_ops.rd_mac(pdata, AXGMAC_CONFIG_1, &data);
		pp->rx_pause = AXG_RD_RX_FLOW_EN(data);
		pp->tx_pause = AXG_RD_TX_FLOW_EN(data);
	}
}

inline int xgene_ethtool_set_tx_csum(struct net_device *ndev, u32 set)
{
	if (set)
		ndev->features |= NETIF_F_IP_CSUM;
	else
		ndev->features &= ~NETIF_F_IP_CSUM;

	return 0;
}

inline u32 xgene_ethtool_get_tx_csum(struct net_device * ndev)
{
	return (ndev->features & NETIF_F_IP_CSUM);
}

inline u32 xgene_ethtool_get_sg(struct net_device * ndev)
{
	return (ndev->features & NETIF_F_SG);
}

int xgene_ethtool_set_sg(struct net_device *ndev, u32 set)
{
	if (set)
		ndev->features |= NETIF_F_SG;
	else
		ndev->features &= ~NETIF_F_SG;
	return 0;
}

int xgene_ethtool_nway_reset(struct net_device *ndev)
{
	u32 data = 0, retry = 0;
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);

	if (pdata->mac_ops.type == XGENE_XGMAC)
		return 0;

	mutex_lock(&pdata->mdio_bus->mdio_lock);

	/* Power-down PHY */
	data = MII_CR_POWER_DOWN;
	pdata->enet_rd_wr_ops.mii_phy_write(pdata, pdata->phy_addr, 
			MII_CTRL_REG, data);

	/* Power-up PHY */
	data = 0x0;
	pdata->enet_rd_wr_ops.mii_phy_write(pdata, pdata->phy_addr, 
			MII_CTRL_REG, data);

	/* Reset PHY */
	data = MII_CR_RESET;
	pdata->enet_rd_wr_ops.mii_phy_write(pdata, pdata->phy_addr, 
			MII_CTRL_REG, data);

	/* Wait till PHY reset completes */
	retry = 1000;
	while ((data & MII_CR_RESET) && (retry > 0)) {
		pdata->enet_rd_wr_ops.mii_phy_read(pdata, pdata->phy_addr, 
				MII_CTRL_REG, &data);
		retry--;
		msleep(1);
	}

	pdata->enet_rd_wr_ops.mii_phy_write(pdata, pdata->phy_addr, 
			MII_CTRL_REG, MII_CR_AUTO_EN|MII_CR_RESTART|MII_CR_FDX);

	pdata->phy_speed = SPEED_1000;
	pdata->mac_ops.init(pdata);

	mutex_unlock(&pdata->mdio_bus->mdio_lock);

	return 0;
}

void xgene_get_strings(struct net_device *ndev, u32 stringset,
		    u8 *data)
{
	u8 *p = data;
	int i;
	
	switch (stringset) {
	case ETH_SS_TEST:
	case ETH_SS_STATS:
		for (i = 0; i < XGENE_GLOBAL_STATS_LEN; i++) {
			memcpy(p, xgene_gstrings_stats[i].stat_string,
					ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
		}
		break;

	default:
		break;
	}
}

int xgene_get_sset_count(struct net_device *ndev, int sset)
{
	switch (sset) {
	case ETH_SS_TEST:
	case ETH_SS_STATS:
		return XGENE_GLOBAL_STATS_LEN; 

	default:
		return -EOPNOTSUPP;
	}
	
}

void xgene_ethtool_get_ethtool_stats(struct net_device *ndev,
		struct ethtool_stats *ethtool_stats,
		u64 *data)
{

	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	int i;

	pdata->mac_ops.get_stats(pdata);
	for (i = 0; i < XGENE_GLOBAL_STATS_LEN; i++) {
		char *p = (char *)pdata + xgene_gstrings_stats[i].stat_offset;
		data[i] = *(u32 *)p;
	}
}

void xgene_ethtool_get_drvinfo(struct net_device *ndev,
		struct ethtool_drvinfo *info)
{
	strcpy(info->driver, ndev->name);
	strcpy(info->version, DRV_VERSION);
	strcpy(info->fw_version, "N/A");
}

u32 xgene_ethtool_get_tso(struct net_device *ndev)
{
	return (ndev->features & NETIF_F_TSO);
}

int xgene_ethtool_set_tso(struct net_device *dev, u32 set)
{
	if (set)
		dev->features |= NETIF_F_TSO;
	else
		dev->features &= ~NETIF_F_TSO;

	return 0;
}
