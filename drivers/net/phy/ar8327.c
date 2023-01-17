/*
 * ar8216.c: AR8216 switch driver
 *
 * Copyright (C) 2009 Felix Fietkau <nbd@openwrt.org>
 * Copyright (C) 2011-2012 Gabor Juhos <juhosg@openwrt.org>
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

#include <linux/if.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/bitops.h>
#include <net/genetlink.h>
#include <linux/delay.h>
#include <linux/phy.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/lockdep.h>
#include <linux/ar8327.h>
#include <linux/gpio.h>



#define ENABLE_PROC_MIB
#define ENABLE_JUMBO_FRAME
#define ENABLE_PVID
#ifdef ENABLE_PVID
#define STAG_HEADER 0x8100
#define AR8327_MAX_VLANS        128
#endif

#define MAX_AR8327_PORTS	7	/* CPU port + 5 ports + MAC port 6 */
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
#define MAX_LAN_PORTS		5	/* CPU(P0) + (P1, P2, P3, P4) */
#else
#define MAX_LAN_PORTS		6	/* CPU(P0) + (P1, P2, P3, P4, P5) */
#endif


int ar8327_gpio_check = -1;

struct ar8327_priv {
	struct phy_device *phy;
	u32 (*read)(struct ar8327_priv *priv, int reg);
	void (*write)(struct ar8327_priv *priv, int reg, u32 val);
	u32 (*rmw)(struct ar8327_priv *priv, int reg, u32 mask, u32 val);
#ifdef ENABLE_PVID
	u8 vlan_tagged;
	bool pvid_enable;
	u16 pvid[MAX_AR8327_PORTS];
	u8 vlan_table[AR8327_MAX_VLANS];
#endif
};

static struct ar8327_pad_cfg ar8327_pad0_cfg = {
	.mode = AR8327_PAD_MAC_RGMII,
	.txclk_delay_en = false,
	.rxclk_delay_en = false,
	.txclk_delay_sel = AR8327_CLK_DELAY_SEL2,
	.rxclk_delay_sel = AR8327_CLK_DELAY_SEL2
};

static struct ar8327_pad_cfg ar8327_pad6_cfg = {
	.mode = AR8327_PAD_MAC_RGMII,
	.txclk_delay_en = false,
	.rxclk_delay_en = false,
	.txclk_delay_sel = AR8327_CLK_DELAY_SEL0,
	.rxclk_delay_sel = AR8327_CLK_DELAY_SEL1
};

static struct ar8327_platform_data ar8327_pdata = {
	.global_reset_done = false,
#ifdef CONFIG_ARCH_OPV5XC_CX4
	.giga = false,
#else
	.giga = true,
#endif
	.EEE_enable = false,
	.pad0_cfg = &ar8327_pad0_cfg,
	.pad6_cfg = &ar8327_pad6_cfg,
	.port0_cfg = {
		.force_link = 1,
		.speed = AR8327_PORT_SPEED_1000,
		.duplex = 1,
		.txpause = 1,
		.rxpause = 1,
	},
	.port6_cfg = {
		.force_link = 1,
		.speed = AR8327_PORT_SPEED_1000,
		.duplex = 1,
		.txpause = 1,
		.rxpause = 1,
	},
};

static inline bool ar8327_has_giga(void)
{
	struct ar8327_platform_data *pdata = &ar8327_pdata;
	return pdata->giga;
}

static inline bool ar8327_has_eee(void)
{
	struct ar8327_platform_data *pdata = &ar8327_pdata;
	return pdata->EEE_enable;
}



static inline void
split_addr(u32 regaddr, u16 *r1, u16 *r2, u16 *page)
{
	regaddr >>= 1;
	*r1 = regaddr & 0x1e;

	regaddr >>= 5;
	*r2 = regaddr & 0x7;

	regaddr >>= 3;
	*page = regaddr & 0x1ff;
}

static u32
ar8327_mii_read(struct ar8327_priv *priv, int reg)
{
	struct phy_device *phy = priv->phy;
	struct mii_bus *bus = phy->bus;
	u16 r1, r2, page;
	u16 lo, hi;

	split_addr((u32) reg, &r1, &r2, &page);

	mutex_lock(&bus->mdio_lock);

	bus->write(bus, 0x18, 0, page);
	usleep_range(1000, 2000); /* wait for the page switch to propagate */
	lo = bus->read(bus, 0x10 | r2, r1);
	hi = bus->read(bus, 0x10 | r2, r1 + 1);

	mutex_unlock(&bus->mdio_lock);

	return (hi << 16) | lo;
}

static void
ar8327_mii_write(struct ar8327_priv *priv, int reg, u32 val)
{
	struct phy_device *phy = priv->phy;
	struct mii_bus *bus = phy->bus;
	u16 r1, r2, r3;
	u16 lo, hi;

	split_addr((u32) reg, &r1, &r2, &r3);
	lo = val & 0xffff;
	hi = (u16) (val >> 16);

	mutex_lock(&bus->mdio_lock);

	bus->write(bus, 0x18, 0, r3);
	usleep_range(1000, 2000); /* wait for the page switch to propagate */
	bus->write(bus, 0x10 | r2, r1, lo);
	bus->write(bus, 0x10 | r2, r1 + 1, hi);

	mutex_unlock(&bus->mdio_lock);
}

static u32
ar8327_rmw(struct ar8327_priv *priv, int reg, u32 mask, u32 val)
{
	u32 v;

	v = priv->read(priv, reg);
	v &= ~mask;
	v |= val;
	priv->write(priv, reg, v);

	return v;
}

static u32
ar8327_get_pad_cfg(struct ar8327_pad_cfg *cfg)
{
	u32 t;

	if (!cfg)
		return 0;

	t = 0;
	switch (cfg->mode) {
	case AR8327_PAD_NC:
		break;

	case AR8327_PAD_MAC2MAC_MII:
		t = AR8327_PAD_MAC_MII_EN;
		if (cfg->rxclk_sel)
			t |= AR8327_PAD_MAC_MII_RXCLK_SEL;
		if (cfg->txclk_sel)
			t |= AR8327_PAD_MAC_MII_TXCLK_SEL;
		break;

	case AR8327_PAD_MAC2MAC_GMII:
		t = AR8327_PAD_MAC_GMII_EN;
		if (cfg->rxclk_sel)
			t |= AR8327_PAD_MAC_GMII_RXCLK_SEL;
		if (cfg->txclk_sel)
			t |= AR8327_PAD_MAC_GMII_TXCLK_SEL;
		break;

	case AR8327_PAD_MAC_SGMII:
		t = AR8327_PAD_SGMII_EN;
		break;

	case AR8327_PAD_MAC2PHY_MII:
		t = AR8327_PAD_PHY_MII_EN;
		if (cfg->rxclk_sel)
			t |= AR8327_PAD_PHY_MII_RXCLK_SEL;
		if (cfg->txclk_sel)
			t |= AR8327_PAD_PHY_MII_TXCLK_SEL;
		break;

	case AR8327_PAD_MAC2PHY_GMII:
		t = AR8327_PAD_PHY_GMII_EN;
		if (cfg->pipe_rxclk_sel)
			t |= AR8327_PAD_PHY_GMII_PIPE_RXCLK_SEL;
		if (cfg->rxclk_sel)
			t |= AR8327_PAD_PHY_GMII_RXCLK_SEL;
		if (cfg->txclk_sel)
			t |= AR8327_PAD_PHY_GMII_TXCLK_SEL;
		break;

	case AR8327_PAD_MAC_RGMII:
		t = AR8327_PAD_RGMII_EN;
		t |= cfg->txclk_delay_sel << AR8327_PAD_RGMII_TXCLK_DELAY_SEL_S;
		t |= cfg->rxclk_delay_sel << AR8327_PAD_RGMII_RXCLK_DELAY_SEL_S;
		if (cfg->rxclk_delay_en)
			t |= AR8327_PAD_RGMII_RXCLK_DELAY_EN;
		if (cfg->txclk_delay_en)
			t |= AR8327_PAD_RGMII_TXCLK_DELAY_EN;
		break;

	case AR8327_PAD_PHY_GMII:
		t = AR8327_PAD_PHYX_GMII_EN;
		break;

	case AR8327_PAD_PHY_RGMII:
		t = AR8327_PAD_PHYX_RGMII_EN;
		break;

	case AR8327_PAD_PHY_MII:
		t = AR8327_PAD_PHYX_MII_EN;
		break;
	}

	return t;
}

static int
ar8327_hw_init(struct ar8327_priv *priv)
{
	struct ar8327_platform_data *pdata = &ar8327_pdata;
	u32 t;
	int i;

	if (pdata->pad0_cfg) {
		t = ar8327_get_pad_cfg(pdata->pad0_cfg);
#if defined(CONFIG_MACH_OPV5XC_RG_BOARD) || defined(CONFIG_MACH_OPV5XC_NANA_VALIDATION)
		t |=  (0x1 << 31);
#endif
		priv->write(priv, AR8327_REG_PAD0_MODE, t);
	}

	if (pdata->pad5_cfg) {
		t = ar8327_get_pad_cfg(pdata->pad5_cfg);
		priv->write(priv, AR8327_REG_PAD5_MODE, t);
	}

	if (pdata->pad6_cfg) {
		t = ar8327_get_pad_cfg(pdata->pad6_cfg);
		priv->write(priv, AR8327_REG_PAD6_MODE, t);
	}
	priv->write(priv, AR8327_REG_POWER_ON_STRIP, 0x40000000);

	for (i = 0; i < 5; i++) {
		if (ar8327_has_giga()) {
			mdiobus_write(priv->phy->bus, i, MII_CTRL1000, ADVERTISE_1000FULL);
			mdiobus_write(priv->phy->bus, i, MII_BMCR, BMCR_RESET | BMCR_ANENABLE);

		} else {
			mdiobus_write(priv->phy->bus, i, MII_CTRL1000, 0);
			mdiobus_write(priv->phy->bus, i, MII_BMCR, BMCR_RESET | BMCR_ANENABLE);
		}
	}
	return 0;
}

static void
ar8327_init_globals(struct ar8327_priv *priv)
{
	u32 t;
	int i;

	/* enable CPU port and disable mirror port */
	t = AR8327_FWD_CTRL0_CPU_PORT_EN |
	    AR8327_FWD_CTRL0_MIRROR_PORT;
	priv->write(priv, AR8327_REG_FWD_CTRL0, t);

	/* forward unicast, multicast and broadcast frames to CPU */
	t = (AR8327_PORTS_ALL << AR8327_FWD_CTRL1_UC_FLOOD_S) |
	    (AR8327_PORTS_ALL << AR8327_FWD_CTRL1_MC_FLOOD_S) |
	    (AR8327_PORTS_ALL << AR8327_FWD_CTRL1_BC_FLOOD_S);
	priv->write(priv, AR8327_REG_FWD_CTRL1, t);

	if (!ar8327_has_eee()) {
		/* Disable EEE */
		t = (1 << AR8327_LPI_EN_1) |
			(1 << AR8327_LPI_EN_2) |
			(1 << AR8327_LPI_EN_3) |
			(1 << AR8327_LPI_EN_4) |
			(1 << AR8327_LPI_EN_5);
		priv->write(priv, AR8327_EEE_CTRL, t);
	}

#ifdef ENABLE_JUMBO_FRAME
	/* set max frame size to support jumbo frame */
	priv->rmw(priv, AR8327_REG_MAX_FRAME_SIZE,
		  AR8327_MAX_FRAME_SIZE_MTU, 0x2400);
#endif

#ifdef AR8327_SUPPORT_INSERT_STAG
	priv->write(priv, AR8327_REG_SERVICE_TAG, 0x20000 | STAG_HEADER); /* S-TAG mode and Header */
#endif

	/* in order to solve dead lock issue
	   FC ON                          FC OFF
	   MAC0 ---- AR8337 PORT 0 --- PORT 1 -------- IXIA
	   MAC1 ---- AR8337 PORT 6 --- PORT 5 -------- IXIA
	*/
	for (i = 0; i < MAX_AR8327_PORTS; i++) {
		if (i == 0 || i == 5 || i == 6) {
			/* PORT0, PORT5, PORT6 */
			priv->write(priv, AR8327_REG_PORT_HOL_CTRL0(i), 0x22864200);
		} else {
			/* PORT1, PORT2, PORT3, PORT4 */
			priv->write(priv, AR8327_REG_PORT_HOL_CTRL0(i), 0x22008642);
		}
		priv->write(priv, AR8327_REG_PORT_HOL_CTRL1(i), 0x000001c2);
	}
}

static void
ar8327_config_port(struct ar8327_priv *priv, int port, struct ar8327_port_cfg *cfg)
{
	u32 t;

	if (!cfg || !cfg->force_link) {
		t = priv->read(priv, AR8327_REG_PORT_STATUS(port));
		t |= (AR8216_PORT_STATUS_FLOW_LINK | AR8216_PORT_STATUS_LINK_AUTO);
		priv->write(priv, AR8327_REG_PORT_STATUS(port), t);
		return;
	}

	t = AR8216_PORT_STATUS_TXMAC | AR8216_PORT_STATUS_RXMAC;
	t |= cfg->duplex ? AR8216_PORT_STATUS_DUPLEX : 0;
	t |= cfg->rxpause ? AR8216_PORT_STATUS_RXFLOW : 0;
	t |= cfg->txpause ? AR8216_PORT_STATUS_TXFLOW : 0;

	switch (cfg->speed) {
	case AR8327_PORT_SPEED_10:
		t |= AR8216_PORT_SPEED_10M;
		break;
	case AR8327_PORT_SPEED_100:
		t |= AR8216_PORT_SPEED_100M;
		break;
	case AR8327_PORT_SPEED_1000:
		if (ar8327_has_giga())
			t |= AR8216_PORT_SPEED_1000M;
		else
			t |= AR8216_PORT_SPEED_100M;
		break;
	}
	priv->write(priv, AR8327_REG_PORT_STATUS(port), t);
}

static void
ar8327_init_port(struct ar8327_priv *priv, int port)
{
	u32 t;
	struct ar8327_platform_data *pdata = &ar8327_pdata;
	struct ar8327_port_cfg *cfg;

	if (port == AR8216_PORT_CPU)
		cfg = &pdata->port0_cfg;
	else if (6 == port)
		cfg = &pdata->port6_cfg;
	else
		cfg = NULL;

	ar8327_config_port(priv, port, cfg);

	priv->write(priv, AR8327_REG_PORT_HEADER(port), 0);

	priv->write(priv, AR8327_REG_PORT_VLAN0(port), 0);

	t = AR8327_PORT_VLAN1_OUT_MODE_UNTOUCH << AR8327_PORT_VLAN1_OUT_MODE_S;
	priv->write(priv, AR8327_REG_PORT_VLAN1(port), t);
}

static u32
ar8327_read_port_status(struct ar8327_priv *priv, int port)
{
	return priv->read(priv, AR8327_REG_PORT_STATUS(port));
}

static int
ar8327_id_chip(struct ar8327_priv *priv)
{
	u32 val;
	u16 id;

	val = priv->read(priv, AR8216_REG_CTRL);
	id = val & (AR8216_CTRL_REVISION | AR8216_CTRL_VERSION);

	switch (id >> AR8216_CTRL_VERSION_S) {
	case S17_CHIPID_VERSION:
	case S17C_CHIPID_VERSION:
		pr_info("ar8327: Atheros phy device [ver=%d, rev=%d, phy_id=%04x%04x]\n",
			(int)(id >> AR8216_CTRL_VERSION_S),
			(int)(id & AR8216_CTRL_REVISION),
			mdiobus_read(priv->phy->bus, priv->phy->addr, 2),
			mdiobus_read(priv->phy->bus, priv->phy->addr, 3));
		break;
	default:
		pr_debug("ar8216: Unknown Atheros device [ver=%d, rev=%d, phy_id=%04x%04x]\n",
			 (int)(id >> AR8216_CTRL_VERSION_S),
			 (int)(id & AR8216_CTRL_REVISION),
			 mdiobus_read(priv->phy->bus, priv->phy->addr, 2),
			 mdiobus_read(priv->phy->bus, priv->phy->addr, 3));

		return -ENODEV;
	}

	return 0;
}


/* FIXME */
static void ar8327_vlan_config(struct ar8327_priv *priv)
{
	priv->write(priv, 0x0660, 0x0014001e);
	priv->write(priv, 0x066c, 0x0014001d);
	priv->write(priv, 0x0678, 0x0014001b);
	priv->write(priv, 0x0684, 0x00140017);
	priv->write(priv, 0x0690, 0x0014000f);
	priv->write(priv, 0x0420, 0x00010001);
	priv->write(priv, 0x0428, 0x00010001);
	priv->write(priv, 0x0430, 0x00010001);
	priv->write(priv, 0x0438, 0x00010001);
	priv->write(priv, 0x0440, 0x00010001);

	priv->write(priv, 0x069c, 0x00140040);
	priv->write(priv, 0x06a8, 0x00140020);
	priv->write(priv, 0x0448, 0x00020002);
	priv->write(priv, 0x0450, 0x00020002);
}

static void ar8327_fixup(struct ar8327_priv *priv)
{
	u32 val;
	u16 id;

	val = priv->read(priv, AR8216_REG_CTRL);
	id = val & (AR8216_CTRL_REVISION | AR8216_CTRL_VERSION);

	/* S17 v1.0 workaround at 1000M mode */
	if (S17C_CHIPID_V1_0 == id) {
		int i;
		for (i = 0; i < 5; i++) {
			mdiobus_write(priv->phy->bus, i, MII_ATH_DBG_ADDR, 0x3d);
			mdiobus_write(priv->phy->bus, i, MII_ATH_DBG_DATA, 0x6820);
		}
	}
}
static void ar8327_resume(struct ar8327_priv *priv)
{
	if ((priv->read(priv, AR8327_REG_PORT_STATUS(0))) == (0x1080) || (priv->read(priv, AR8327_REG_PORT_STATUS(6))) == (0x1080)) {
		ar8327_pdata.global_reset_done = false;
		if (ar8327_gpio_check == 0) {
			gpio_free(GPIOA(0));
			ar8327_gpio_check = -1;
		}
	}
}


static int
ar8327_config_init(struct phy_device *phy)
{
	struct ar8327_priv *priv = phy->priv;
	int ret;
	int i;

	if (!priv) {
		priv = kzalloc(sizeof(struct ar8327_priv), GFP_KERNEL);
		if (priv == NULL)
			return -ENOMEM;
	}
	priv->phy = phy;
	priv->read = ar8327_mii_read;
	priv->write = ar8327_mii_write;
	priv->rmw = ar8327_rmw;
	phy->priv = priv;
	ar8327_resume(priv);

	if (false == ar8327_pdata.global_reset_done) {
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
		if (gpio_is_valid(0)) {
			ar8327_gpio_check = gpio_request(GPIOA(0), "switch_rst");
			if (ar8327_gpio_check)
				pr_err("Can't get gpio for switch reset.\n");
			else {
				gpio_direction_output(GPIOA(0), 0);
				mdelay(100);
				gpio_set_value(GPIOA(0), 1);
			}
		}
#endif
		priv->write(priv, AR8216_REG_CTRL, AR8216_CTRL_RESET);

		while (AR8216_CTRL_RESET & priv->read(priv, AR8216_REG_CTRL))
			;

		ret = ar8327_id_chip(priv);

		if (ret)
			return ret;

		ar8327_hw_init(priv);

		/* Configure all ports */
		for (i = 0; i < MAX_AR8327_PORTS; i++)
			ar8327_init_port(priv, i);

		ar8327_init_globals(priv);

	#ifdef ENABLE_PROC_MIB
		priv->write(priv, 0x30, 0x01); /* enable mib count */
	#endif

		ar8327_vlan_config(priv);
		ar8327_fixup(priv);
		ar8327_pdata.global_reset_done = true;
	}

	/* update supported features for the phydev */
	if (phy->addr == AR8216_PORT_CPU) {
		struct ar8327_port_cfg *cfg = &(ar8327_pdata.port0_cfg);

		if (!cfg || !cfg->force_link)
			phy->supported = (PHY_GBIT_FEATURES | SUPPORTED_Pause);
		else {
			switch (cfg->speed) {
			case AR8327_PORT_SPEED_10:
				phy->supported = (cfg->duplex) ? SUPPORTED_10baseT_Full : SUPPORTED_10baseT_Half;
				break;

			case AR8327_PORT_SPEED_100:
				phy->supported = (cfg->duplex) ? SUPPORTED_100baseT_Full : SUPPORTED_100baseT_Half;
				break;

			case AR8327_PORT_SPEED_1000:
				if (ar8327_has_giga())
					phy->supported = (cfg->duplex) ? SUPPORTED_1000baseT_Full : SUPPORTED_1000baseT_Half;
				else
					phy->supported = (cfg->duplex) ? SUPPORTED_100baseT_Full : SUPPORTED_100baseT_Half;
				break;
			}
			phy->supported |= (SUPPORTED_TP | SUPPORTED_MII | SUPPORTED_Pause);
		}
	} else {
		phy->supported = (PHY_GBIT_FEATURES | SUPPORTED_Pause);
	}

	phy->advertising = phy->supported;
	return 0;
}

int ar8327_read_status(struct phy_device *phy)
{
	u32 status;
	u32 speed;
	if (phy->addr != 0)
		return genphy_read_status(phy);

	status = ar8327_read_port_status(phy->priv, AR8216_PORT_CPU);

	phy->autoneg = !!(status & AR8216_PORT_STATUS_LINK_AUTO);
	if (phy->autoneg)
		phy->link = !!(status & AR8216_PORT_STATUS_LINK_UP);
	else
		phy->link = true;

	phy->duplex = !!(status & AR8216_PORT_STATUS_DUPLEX);

	speed = (status & AR8216_PORT_STATUS_SPEED) >>
		AR8216_PORT_STATUS_SPEED_S;

	switch (speed) {
	case AR8216_PORT_SPEED_10M:
		phy->speed = SPEED_10;
		break;
	case AR8216_PORT_SPEED_100M:
		phy->speed = SPEED_100;
		break;
	case AR8216_PORT_SPEED_1000M:
		phy->speed = SPEED_1000;
		break;
	default:
		phy->speed = SPEED_UNKNOWN;
		break;
	}

	phy->state = PHY_RUNNING;
	netif_carrier_on(phy->attached_dev);
	phy->adjust_link(phy->attached_dev);
	return 0;
}

static int ar8327_update_link(struct phy_device *pdev)
{
	int status;
	if (pdev->addr == 0)
		pdev->link = 1;
	else {
		/* Do a fake read */
		status = mdiobus_read(pdev->bus, pdev->addr, MII_BMSR);
		if (status < 0)
			return status;

		/* Read link and autonegotiation status */
		status = mdiobus_read(pdev->bus, pdev->addr, MII_BMSR);
		if (status < 0)
			return status;

		if ((status & BMSR_LSTATUS) == 0)
			pdev->link = 0;
		else
			pdev->link = 1;
	}

	return 0;
}

static int
ar8327_config_aneg(struct phy_device *phydev)
{
	if (phydev->addr == 0)
		return 0;
	return genphy_config_aneg(phydev);
}

static void ar8327_remove(struct phy_device *phydev)
{
	struct ar8327_priv *priv = phydev->priv;
	if (priv) {
#ifdef ENABLE_PROC_MIB
		priv->write(priv, 0x30, 0x00); /* disable mib count */
#endif
		kfree(priv);
	}
}

static struct phy_driver ar8327_driver = {
	.phy_id		= 0x004dd033,
	.name		= "Atheros AR8327",
	.phy_id_mask	= 0xfffffff0,
	.features   = PHY_GBIT_FEATURES | SUPPORTED_Pause | SUPPORTED_Asym_Pause,
	.config_init	= &ar8327_config_init,
	.config_aneg	= &ar8327_config_aneg,
	.read_status	= &ar8327_read_status,
	.update_link    = &ar8327_update_link,
	.remove		= &ar8327_remove,
	.driver		= { .owner = THIS_MODULE },
};

int __init
ar8327_init(void)
{
	return phy_driver_register(&ar8327_driver);
}

void __exit
ar8327_exit(void)
{
	phy_driver_unregister(&ar8327_driver);
}
module_init(ar8327_init);
module_exit(ar8327_exit);
MODULE_LICENSE("GPL");
