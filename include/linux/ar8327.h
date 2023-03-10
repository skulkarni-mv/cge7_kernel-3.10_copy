/*
 * ar8216.h: AR8216 switch driver
 *
 * Copyright (C) 2009 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __AR8216_H
#define __AR8216_H

#define BITS(_s, _n)	(((1UL << (_n)) - 1) << _s)

#define AR8216_PORT_CPU	0
#define AR8216_NUM_PORTS	6
#define AR8216_NUM_VLANS	16
#define AR8316_NUM_VLANS	4096

/* Atheros specific MII registers */
#define MII_ATH_DBG_ADDR		0x1d
#define MII_ATH_DBG_DATA		0x1e

#define MII_8337_DBG_ADDR		0x0d
#define MII_8337_DBG_DATA		0x0e


#define AR8216_REG_CTRL			0x0000
#define   AR8216_CTRL_REVISION		BITS(0, 8)
#define   AR8216_CTRL_REVISION_S	0
#define   AR8216_CTRL_VERSION		BITS(8, 8)
#define   AR8216_CTRL_VERSION_S		8
#define   AR8216_CTRL_RESET		BIT(31)

#define AR8216_REG_FLOOD_MASK		0x002C
#define   AR8216_FM_UNI_DEST_PORTS	BITS(0, 6)
#define   AR8216_FM_MULTI_DEST_PORTS	BITS(16, 6)

#define AR8216_REG_GLOBAL_CTRL		0x0030
#define   AR8216_GCTRL_MTU		BITS(0, 11)
#define   AR8236_GCTRL_MTU		BITS(0, 14)
#define   AR8316_GCTRL_MTU		BITS(0, 14)

#define AR8216_REG_VTU			0x0040
#define   AR8216_VTU_OP			BITS(0, 3)
#define   AR8216_VTU_OP_NOOP		0x0
#define   AR8216_VTU_OP_FLUSH		0x1
#define   AR8216_VTU_OP_LOAD		0x2
#define   AR8216_VTU_OP_PURGE		0x3
#define   AR8216_VTU_OP_REMOVE_PORT	0x4
#define   AR8216_VTU_ACTIVE		BIT(3)
#define   AR8216_VTU_FULL		BIT(4)
#define   AR8216_VTU_PORT		BITS(8, 4)
#define   AR8216_VTU_PORT_S		8
#define   AR8216_VTU_VID		BITS(16, 12)
#define   AR8216_VTU_VID_S		16
#define   AR8216_VTU_PRIO		BITS(28, 3)
#define   AR8216_VTU_PRIO_S		28
#define   AR8216_VTU_PRIO_EN		BIT(31)

#define AR8216_REG_VTU_DATA		0x0044
#define   AR8216_VTUDATA_MEMBER		BITS(0, 10)
#define   AR8236_VTUDATA_MEMBER		BITS(0, 7)
#define   AR8216_VTUDATA_VALID		BIT(11)

#define AR8216_REG_ATU			0x0050
#define   AR8216_ATU_OP			BITS(0, 3)
#define   AR8216_ATU_OP_NOOP		0x0
#define   AR8216_ATU_OP_FLUSH		0x1
#define   AR8216_ATU_OP_LOAD		0x2
#define   AR8216_ATU_OP_PURGE		0x3
#define   AR8216_ATU_OP_FLUSH_LOCKED	0x4
#define   AR8216_ATU_OP_FLUSH_UNICAST	0x5
#define   AR8216_ATU_OP_GET_NEXT	0x6
#define   AR8216_ATU_ACTIVE		BIT(3)
#define   AR8216_ATU_PORT_NUM		BITS(8, 4)
#define   AR8216_ATU_FULL_VIO		BIT(12)
#define   AR8216_ATU_ADDR4		BITS(16, 8)
#define   AR8216_ATU_ADDR5		BITS(24, 8)

#define AR8216_REG_ATU_DATA		0x0054
#define   AR8216_ATU_ADDR3		BITS(0, 8)
#define   AR8216_ATU_ADDR2		BITS(8, 8)
#define   AR8216_ATU_ADDR1		BITS(16, 8)
#define   AR8216_ATU_ADDR0		BITS(24, 8)

#define AR8216_REG_ATU_CTRL		0x005C
#define   AR8216_ATU_CTRL_AGE_EN	BIT(17)
#define   AR8216_ATU_CTRL_AGE_TIME	BITS(0, 16)
#define   AR8216_ATU_CTRL_AGE_TIME_S	0

#define AR8216_PORT_OFFSET(_i)		(0x0100 * (_i + 1))
#define AR8216_REG_PORT_STATUS(_i)	(AR8216_PORT_OFFSET(_i) + 0x0000)
#define   AR8216_PORT_STATUS_SPEED	BITS(0, 2)
#define   AR8216_PORT_STATUS_SPEED_S	0
#define   AR8216_PORT_STATUS_TXMAC	BIT(2)
#define   AR8216_PORT_STATUS_RXMAC	BIT(3)
#define   AR8216_PORT_STATUS_TXFLOW	BIT(4)
#define   AR8216_PORT_STATUS_RXFLOW	BIT(5)
#define   AR8216_PORT_STATUS_DUPLEX	BIT(6)
#define   AR8216_PORT_STATUS_LINK_UP	BIT(8)
#define   AR8216_PORT_STATUS_LINK_AUTO	BIT(9)
#define   AR8216_PORT_STATUS_FLOW_LINK	BIT(12)

#define AR8216_REG_PORT_CTRL(_i)	(AR8216_PORT_OFFSET(_i) + 0x0004)

/* port forwarding state */
#define   AR8216_PORT_CTRL_STATE	BITS(0, 3)
#define   AR8216_PORT_CTRL_STATE_S	0

#define   AR8216_PORT_CTRL_LEARN_LOCK	BIT(7)

/* egress 802.1q mode */
#define   AR8216_PORT_CTRL_VLAN_MODE	BITS(8, 2)
#define   AR8216_PORT_CTRL_VLAN_MODE_S	8

#define   AR8216_PORT_CTRL_IGMP_SNOOP	BIT(10)
#define   AR8216_PORT_CTRL_HEADER	BIT(11)
#define   AR8216_PORT_CTRL_MAC_LOOP	BIT(12)
#define   AR8216_PORT_CTRL_SINGLE_VLAN	BIT(13)
#define   AR8216_PORT_CTRL_LEARN	BIT(14)
#define   AR8216_PORT_CTRL_MIRROR_TX	BIT(16)
#define   AR8216_PORT_CTRL_MIRROR_RX	BIT(17)

#define AR8216_REG_PORT_VLAN(_i)	(AR8216_PORT_OFFSET(_i) + 0x0008)

#define   AR8216_PORT_VLAN_DEFAULT_ID	BITS(0, 12)
#define   AR8216_PORT_VLAN_DEFAULT_ID_S	0

#define   AR8216_PORT_VLAN_DEST_PORTS	BITS(16, 9)
#define   AR8216_PORT_VLAN_DEST_PORTS_S	16

/* bit0 added to the priority field of egress frames */
#define   AR8216_PORT_VLAN_TX_PRIO	BIT(27)

/* port default priority */
#define   AR8216_PORT_VLAN_PRIORITY	BITS(28, 2)
#define   AR8216_PORT_VLAN_PRIORITY_S	28

/* ingress 802.1q mode */
#define   AR8216_PORT_VLAN_MODE		BITS(30, 2)
#define   AR8216_PORT_VLAN_MODE_S	30

#define AR8216_REG_PORT_RATE(_i)	(AR8216_PORT_OFFSET(_i) + 0x000c)
#define AR8216_REG_PORT_PRIO(_i)	(AR8216_PORT_OFFSET(_i) + 0x0010)


#define AR8236_REG_PORT_VLAN(_i)	(AR8216_PORT_OFFSET((_i)) + 0x0008)
#define   AR8236_PORT_VLAN_DEFAULT_ID	BITS(16, 12)
#define   AR8236_PORT_VLAN_DEFAULT_ID_S	16
#define   AR8236_PORT_VLAN_PRIORITY	BITS(29, 3)
#define   AR8236_PORT_VLAN_PRIORITY_S	28

#define AR8236_REG_PORT_VLAN2(_i)	(AR8216_PORT_OFFSET((_i)) + 0x000c)
#define   AR8236_PORT_VLAN2_MEMBER	BITS(16, 7)
#define   AR8236_PORT_VLAN2_MEMBER_S	16
#define   AR8236_PORT_VLAN2_TX_PRIO	BIT(23)
#define   AR8236_PORT_VLAN2_VLAN_MODE	BITS(30, 2)
#define   AR8236_PORT_VLAN2_VLAN_MODE_S	30

#define AR8327_NUM_PORTS	7
#define AR8327_NUM_PHYS		5
#define AR8327_PORTS_ALL	0x7f

#define AR8327_REG_MASK				0x000

#define AR8327_REG_PAD0_MODE			0x004
#define AR8327_REG_PAD5_MODE			0x008
#define AR8327_REG_PAD6_MODE			0x00c
#define   AR8327_PAD_MAC_MII_RXCLK_SEL		BIT(0)
#define   AR8327_PAD_MAC_MII_TXCLK_SEL		BIT(1)
#define   AR8327_PAD_MAC_MII_EN			BIT(2)
#define   AR8327_PAD_MAC_GMII_RXCLK_SEL		BIT(4)
#define   AR8327_PAD_MAC_GMII_TXCLK_SEL		BIT(5)
#define   AR8327_PAD_MAC_GMII_EN		BIT(6)
#define   AR8327_PAD_SGMII_EN			BIT(7)
#define   AR8327_PAD_PHY_MII_RXCLK_SEL		BIT(8)
#define   AR8327_PAD_PHY_MII_TXCLK_SEL		BIT(9)
#define   AR8327_PAD_PHY_MII_EN			BIT(10)
#define   AR8327_PAD_PHY_GMII_PIPE_RXCLK_SEL	BIT(11)
#define   AR8327_PAD_PHY_GMII_RXCLK_SEL		BIT(12)
#define   AR8327_PAD_PHY_GMII_TXCLK_SEL		BIT(13)
#define   AR8327_PAD_PHY_GMII_EN		BIT(14)
#define   AR8327_PAD_PHYX_GMII_EN		BIT(16)
#define   AR8327_PAD_PHYX_RGMII_EN		BIT(17)
#define   AR8327_PAD_PHYX_MII_EN		BIT(18)
#define   AR8327_PAD_RGMII_RXCLK_DELAY_SEL	BITS(20, 2)
#define   AR8327_PAD_RGMII_RXCLK_DELAY_SEL_S	20
#define   AR8327_PAD_RGMII_TXCLK_DELAY_SEL	BITS(22, 2)
#define   AR8327_PAD_RGMII_TXCLK_DELAY_SEL_S	22
#define   AR8327_PAD_RGMII_RXCLK_DELAY_EN	BIT(24)
#define   AR8327_PAD_RGMII_TXCLK_DELAY_EN	BIT(25)
#define   AR8327_PAD_RGMII_EN			BIT(26)

#define AR8327_REG_POWER_ON_STRIP		0x010

#define AR8327_REG_INT_STATUS0			0x020
#define   AR8327_INT0_VT_DONE			BIT(20)

#define AR8327_REG_INT_STATUS1			0x024
#define AR8327_REG_INT_MASK0			0x028
#define AR8327_REG_INT_MASK1			0x02c
#define AR8327_REG_SERVICE_TAG			0x048
#define AR8327_REG_LED_CTRL0			0x050
#define AR8327_REG_LED_CTRL1			0x054
#define AR8327_REG_LED_CTRL2			0x058
#define AR8327_REG_LED_CTRL3			0x05c
#define AR8327_REG_MAC_ADDR0			0x060
#define AR8327_REG_MAC_ADDR1			0x064

#define AR8327_REG_MAX_FRAME_SIZE		0x078
#define   AR8327_MAX_FRAME_SIZE_MTU		BITS(0, 14)

#define AR8327_REG_PORT_STATUS(_i)		(0x07c + (_i) * 4)

#define AR8327_REG_HEADER_CTRL			0x098
#define AR8327_REG_PORT_HEADER(_i)		(0x09c + (_i) * 4)

#define AR8327_EEE_CTRL				0x100
#define  AR8327_LPI_EN_1			4
#define  AR8327_LPI_EN_2			6
#define  AR8327_LPI_EN_3			8
#define  AR8327_LPI_EN_4			10
#define  AR8327_LPI_EN_5			12

#define AR8327_REG_PORT_VLAN0(_i)		(0x420 + (_i) * 0x8)
#define   AR8327_PORT_VLAN0_DEF_SVID		BITS(0, 12)
#define   AR8327_PORT_VLAN0_DEF_SVID_S		0
#define   AR8327_PORT_VLAN0_DEF_CVID		BITS(16, 12)
#define   AR8327_PORT_VLAN0_DEF_CVID_S		16

#define AR8327_REG_PORT_VLAN1(_i)		(0x424 + (_i) * 0x8)
#define   AR8327_PORT_VLAN1_PORT_CORE_PORT     BIT(9)
#define   AR8327_PORT_VLAN1_PORT_TLS_MODE      BIT(7)
#define   AR8327_PORT_VLAN1_PORT_VLAN_PROP	BIT(6)
#define   AR8327_PORT_VLAN1_OUT_MODE		BITS(12, 2)
#define   AR8327_PORT_VLAN1_OUT_MODE_S		12
#define   AR8327_PORT_VLAN1_OUT_MODE_UNMOD	0
#define   AR8327_PORT_VLAN1_OUT_MODE_UNTAG	1
#define   AR8327_PORT_VLAN1_OUT_MODE_TAG	2
#define   AR8327_PORT_VLAN1_OUT_MODE_UNTOUCH	3

#define AR8327_REG_ATU_DATA0			0x600
#define AR8327_REG_ATU_DATA1			0x604
#define AR8327_REG_ATU_DATA2			0x608

#define AR8327_REG_ATU_FUNC			0x60c
#define   AR8327_ATU_FUNC_OP			BITS(0, 4)
#define   AR8327_ATU_FUNC_OP_NOOP		0x0
#define   AR8327_ATU_FUNC_OP_FLUSH		0x1
#define   AR8327_ATU_FUNC_OP_LOAD		0x2
#define   AR8327_ATU_FUNC_OP_PURGE		0x3
#define   AR8327_ATU_FUNC_OP_FLUSH_LOCKED	0x4
#define   AR8327_ATU_FUNC_OP_FLUSH_UNICAST	0x5
#define   AR8327_ATU_FUNC_OP_GET_NEXT		0x6
#define   AR8327_ATU_FUNC_OP_SEARCH_MAC		0x7
#define   AR8327_ATU_FUNC_OP_CHANGE_TRUNK	0x8
#define   AR8327_ATU_FUNC_BUSY			BIT(31)

#define AR8327_REG_VTU_FUNC0			0x0610
#define   AR8327_VTU_FUNC0_EG_MODE		BITS(4, 14)
#define   AR8327_VTU_FUNC0_EG_MODE_S(_i)	(4 + (_i) * 2)
#define   AR8327_VTU_FUNC0_EG_MODE_KEEP		0
#define   AR8327_VTU_FUNC0_EG_MODE_UNTAG	1
#define   AR8327_VTU_FUNC0_EG_MODE_TAG		2
#define   AR8327_VTU_FUNC0_EG_MODE_NOT		3
#define   AR8327_VTU_FUNC0_IVL			BIT(19)
#define   AR8327_VTU_FUNC0_VALID		BIT(20)

#define AR8327_REG_VTU_FUNC1			0x0614
#define   AR8327_VTU_FUNC1_OP			BITS(0, 3)
#define   AR8327_VTU_FUNC1_OP_NOOP		0
#define   AR8327_VTU_FUNC1_OP_FLUSH		1
#define   AR8327_VTU_FUNC1_OP_LOAD		2
#define   AR8327_VTU_FUNC1_OP_PURGE		3
#define   AR8327_VTU_FUNC1_OP_REMOVE_PORT	4
#define   AR8327_VTU_FUNC1_OP_GET_NEXT		5
#define   AR8327_VTU_FUNC1_OP_GET_ONE		6
#define   AR8327_VTU_FUNC1_FULL			BIT(4)
#define   AR8327_VTU_FUNC1_PORT			BIT(8, 4)
#define   AR8327_VTU_FUNC1_PORT_S		8
#define   AR8327_VTU_FUNC1_VID			BIT(16, 12)
#define   AR8327_VTU_FUNC1_VID_S		16
#define   AR8327_VTU_FUNC1_BUSY			BIT(31)

#define AR8327_REG_FWD_CTRL0			0x620
#define   AR8327_FWD_CTRL0_CPU_PORT_EN		BIT(10)
#define   AR8327_FWD_CTRL0_MIRROR_PORT		BITS(4, 4)
#define   AR8327_FWD_CTRL0_MIRROR_PORT_S	4

#define AR8327_REG_FWD_CTRL1			0x624
#define   AR8327_FWD_CTRL1_UC_FLOOD		BITS(0, 7)
#define   AR8327_FWD_CTRL1_UC_FLOOD_S		0
#define   AR8327_FWD_CTRL1_MC_FLOOD		BITS(8, 7)
#define   AR8327_FWD_CTRL1_MC_FLOOD_S		8
#define   AR8327_FWD_CTRL1_BC_FLOOD		BITS(16, 7)
#define   AR8327_FWD_CTRL1_BC_FLOOD_S		16
#define   AR8327_FWD_CTRL1_IGMP			BITS(24, 7)
#define   AR8327_FWD_CTRL1_IGMP_S		24

#define AR8327_REG_PORT_LOOKUP(_i)		(0x660 + (_i) * 0xc)
#define   AR8327_PORT_LOOKUP_MEMBER		BITS(0, 7)
#define   AR8327_PORT_LOOKUP_IN_MODE		BITS(8, 2)
#define   AR8327_PORT_LOOKUP_IN_MODE_S		8
#define   AR8327_PORT_LOOKUP_STATE		BITS(16, 3)
#define   AR8327_PORT_LOOKUP_STATE_S		16
#define   AR8327_PORT_LOOKUP_LEARN		BIT(20)

#define AR8327_REG_PORT_PRIO(_i)		(0x664 + (_i) * 0xc)


#define AR8327_REG_PORT_HOL_CTRL0(_i)          (0x970 + (_i) * 0x08)
#define AR8327_REG_PORT_HOL_CTRL1(_i)          (0x974 + (_i) * 0x08)

/* port speed */
enum {
	AR8216_PORT_SPEED_10M = 0,
	AR8216_PORT_SPEED_100M = 1,
	AR8216_PORT_SPEED_1000M = 2,
	AR8216_PORT_SPEED_ERR = 3,
};

/* ingress 802.1q mode */
enum {
	AR8216_IN_PORT_ONLY = 0,
	AR8216_IN_PORT_FALLBACK = 1,
	AR8216_IN_VLAN_ONLY = 2,
	AR8216_IN_SECURE = 3
};

/* egress 802.1q mode */
enum {
	AR8216_OUT_KEEP = 0,
	AR8216_OUT_STRIP_VLAN = 1,
	AR8216_OUT_ADD_VLAN = 2
};

/* port forwarding state */
enum {
	AR8216_PORT_STATE_DISABLED = 0,
	AR8216_PORT_STATE_BLOCK = 1,
	AR8216_PORT_STATE_LISTEN = 2,
	AR8216_PORT_STATE_LEARN = 3,
	AR8216_PORT_STATE_FORWARD = 4
};

/* device */
enum {
	UNKNOWN = 0,
	AR8216 = 8216,
	AR8236 = 8236,
	AR8316 = 8316,
	AR8327 = 8327,
};

enum ar8327_pad_mode {
	AR8327_PAD_NC = 0,
	AR8327_PAD_MAC2MAC_MII,
	AR8327_PAD_MAC2MAC_GMII,
	AR8327_PAD_MAC_SGMII,
	AR8327_PAD_MAC2PHY_MII,
	AR8327_PAD_MAC2PHY_GMII,
	AR8327_PAD_MAC_RGMII,
	AR8327_PAD_PHY_GMII,
	AR8327_PAD_PHY_RGMII,
	AR8327_PAD_PHY_MII,
};

enum ar8327_clk_delay_sel {
	AR8327_CLK_DELAY_SEL0 = 0,
	AR8327_CLK_DELAY_SEL1,
	AR8327_CLK_DELAY_SEL2,
	AR8327_CLK_DELAY_SEL3,
};

struct ar8327_pad_cfg {
	enum ar8327_pad_mode mode;
	bool rxclk_sel;
	bool txclk_sel;
	bool pipe_rxclk_sel;
	bool txclk_delay_en;
	bool rxclk_delay_en;
	enum ar8327_clk_delay_sel txclk_delay_sel;
	enum ar8327_clk_delay_sel rxclk_delay_sel;
};

enum ar8327_port_speed {
	AR8327_PORT_SPEED_10 = 0,
	AR8327_PORT_SPEED_100,
	AR8327_PORT_SPEED_1000,
};

struct ar8327_port_cfg {
	int force_link:1;
	enum ar8327_port_speed speed;
	int txpause:1;
	int rxpause:1;
	int duplex:1;
};

struct ar8327_platform_data {
	bool global_reset_done;
	bool giga;
	bool EEE_enable;
	struct ar8327_pad_cfg *pad0_cfg;
	struct ar8327_pad_cfg *pad5_cfg;
	struct ar8327_pad_cfg *pad6_cfg;
	struct ar8327_port_cfg port0_cfg;
	struct ar8327_port_cfg port6_cfg;
	int ref;
};

#define S17_CHIPID_VERSION             0x12
#define S17C_CHIPID_VERSION            0x13

#define S17_CHIPID_V1_0                 0x1201
#define S17_CHIPID_V1_1                 0x1202
#define S17C_CHIPID_V1_0                0x1301
#define S17C_CHIPID_V1_1                0x1302

#endif
