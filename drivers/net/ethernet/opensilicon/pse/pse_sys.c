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

#include "pse.h"

/* VLAN Configuration */
struct pse_vlan default_vlan = {
	.pmap = PSE_VLAN_PMAP_ALL,
	.vid = DEFAULT_VID,
	.wan = 0,
	.valid = 1,
};

/* MAC check configuration */
struct pse_mac_table_data default_mac = {
	.mac[0] = {
		.index  = 0,
		.priority = 0,
		.port = OPV5XC_PSE_PORT_MAC0,
		.mac = DEFAULT_MAC_0,
	},
#if (1 < OPV5XC_MAC_MAX)
	.mac[1] = {
		.index  = 0,
		.priority = 0,
		.port = OPV5XC_PSE_PORT_MAC1,
		.mac = DEFAULT_MAC_1,
	},
#endif
#if (2 < OPV5XC_MAC_MAX)
	.mac[2] = {
		.index  = 0,
		.priority = 0,
		.port = OPV5XC_PSE_PORT_MAC2,
		.mac = DEFAULT_MAC_2,
	},
#endif
};


void pse_sys_reset(void)
{
	u32 reg;
#ifndef CONFIG_ARCH_OPV5XC_CX4
	void __iomem *addr;

	/* software reset */
	addr = OPV5XC_CR_PMU_BASE_VIRT + 0x4;
	reg = readl(addr);
	reg &= ~(0x1 << 11);
	writel(reg, addr);
	reg = readl(addr);
	reg |= (0x1 << 11);
	writel(reg, addr);
#endif

}

static void pse_sys_init_misc(void)
{
}

static void pse_sys_init_clock(void)
{
	struct completion pse_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;

#ifndef CONFIG_ARCH_OPV5XC_CX4
	u32 reg;
	void __iomem *addr;

#endif
	init_completion(&pse_complete);
	/* clock disable */
	addr = OPV5XC_CR_PMU_BASE_VIRT;
	reg = readl(addr);
	reg &= ~(0x1 << 11);
	writel(reg, addr);

	/* */
	pse_sys_reset();

	/* FIXME set fast clock*/
	addr = OPV5XC_CR_PMU_BASE_VIRT + 0x30;
	reg = readl(addr);
	reg &= ~(0x3 << 4); /* it should be 250M to meet gigabit bandwidth*/
	writel(reg, addr);

	/* clock enable */
	addr = OPV5XC_CR_PMU_BASE_VIRT;
	reg = readl(addr);
	reg |= (0x1 << 11);
	writel(reg, addr);

	do {
		wait_for_completion_timeout(&pse_complete, timeout);
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1 << 11)) {
			val = 1;
			break;
		}
	} while (counter-- != 0);
	if ((counter == 0) && (val == 0)) {
		pr_err("Timeout while enabling power for PSE\n");
		return;
	}

	/* must wait for memory test done */
	do {
		reg = rd32(SRAM_TEST);
	} while (!(reg & (0x1 << 20)));
}

static void pse_sys_init_global(void)
{
	wr32(0, DMA_RING_CFG);
	pse_fs_ring_multipe_cfg(true);
	pse_ts_ring_multipe_cfg(true);

#ifdef PSE_LSO_SUPPORT
	pse_lso_init();
#endif
}

static void pse_sys_init_vlan(void)
{
	pse_vlan_reset();
#if 0
	pse_vlan_write(&default_vlan, 0);
#endif
}

static bool parse_mac_addr(char *str, u8 *res)
{
	int i, a, b;
	char *p;

	for (i = 0, p = str; i < ETH_ALEN; i++, p++) {
		a = hex_to_bin(*p++);
		if (a < 0)
			goto bad;
		b = hex_to_bin(*p++);
		if (b < 0)
			goto bad;
		res[i] = (a << 4) | b;
		if (i == ETH_ALEN - 1) {
			if (*p)
				goto bad;
		} else {
			if (*p != ':' && *p != '-')
				goto bad;
		}
	}

	if (is_valid_ether_addr(res))
		return true;

	pr_err("pse: ethaddr %pM is not valid, ignoring\n", res);
	return false;

bad:
	pr_err("pse: could not parse ethaddr from \'%s\'\n", str);
	return false;
}

char *pse_mac_ethaddr[OPV5XC_MAC_MAX];

static void update_default_mac(int port)
{
	struct pse_mac pse_mac;

	if (pse_mac_ethaddr[port] &&
			parse_mac_addr(pse_mac_ethaddr[port], pse_mac.mac)) {
		pr_info("pse: setting ethaddr %pM for MAC%d\n",
				pse_mac.mac, port);
		memcpy(default_mac.mac[port].mac, pse_mac.mac, ETH_ALEN);
		return;
	}

	pr_info("pse: setting default ethaddr %pM for MAC%d\n",
			default_mac.mac[port].mac, port);
}

static void pse_sys_init_mac(struct pse_platform_data *pdata)
{
	u32 val;
	int i;
	struct pse_mac_data *mac;

	pse_mac_hash(PSE_MAC_HASH_CRC16);

	for (i = 0; i < OPV5XC_MAC_MAX; i++) {
		mac = pdata->port + i;
		if (mac->enable) {
			update_default_mac(i);
			pse_mac_write(&default_mac.mac[i]);
		}
	}

	val = rd32(MAC_CHECK_CFG);
	val |= (0x1 << 7); /* CPU is promiscous mode */
	wr32(val, MAC_CHECK_CFG);
}

static void pse_sys_init_cpu_port(void)
{
	u32 val, addr = CPU_CFG;

	val = rd32(addr);
	val &= ~(0x1 << 30); /* 4N + 2 mode */
	val |= (0x1 << 24); /* VLAN ingress check */
	val &= ~(0x1 << 18); /* port disable: 0 => enable*/
	wr32(val, addr);

	/* set maximum packet length: 9.6 kbytes for CPU port */
	val = rd32(PHY_AUTO_ADDR);
	val &= ~(0x3 << 30);
	val |= (0x3 << 30);
	wr32(val, PHY_AUTO_ADDR);
}


static int pse_mac_port_lnk(struct pse_mac_data *macd)
{
	u32 val, offset;

	switch (macd->sp) {
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


	if (macd->giga_mode)
		val |= (0x1 << 16);
	else
		val &= ~(0x1 << 16);

	if (macd->rgmii)
		val |= (0x1 << 15);
	else
		val &= ~(0x1 << 15);

	if (macd->has_phy) {
		val |= (0x1 << 7);
	} else {
		/* AN_EN = 0 */
		val &= ~(0x1 << 7);
		/* force speed */
		val &= ~(0x3 << 8);
		val |= (macd->force_speed << 8);
		/* force duplex */
		val &= ~(0x1 << 10);
		val |= (macd->force_duplex << 10);
		/* force tx flow control */
		val &= ~(0x1 << 11);
		val |= (macd->force_fc_rx << 11);
		/* force rx flow control */
		val &= ~(0x1 << 12);
		val |= (macd->force_fc_tx << 12);
	}

	wr32(val, offset);

	return PSE_OK;
}

static void pse_sys_init_mac_port(struct pse_platform_data *pdata)
{
	struct pse_mac_data *macd;
	u32 reg0x4, val;
	int i;

	val = rd32(TC_CTRL);
#if 1
	val |= (0x1 << 30);
#else
	val &= ~(0x1 << 30);
#endif
	wr32(val, TC_CTRL);

	reg0x4 = rd32(PHY_AUTO_ADDR);
	for (i = 0; i < OPV5XC_MAC_MAX; i++) {
		P_TRACE("<%s> MAC port %d\n", __func__, i);
		macd = pdata->port + i;

		if (macd->enable) {
			/* enable clock */
			reg0x4 |= (0x1 << (7 + i * 8));
			/* config phy addr and then enable auto-polling as connected to phy */
			if (macd->has_phy) {
				reg0x4 &= ~(0x1f << (i * 8));
				reg0x4 |= (macd->phy_addr << (i * 8));
				reg0x4 |= (0x1 << (5 + i * 8));
			}

			pse_mac_port_lnk(macd);

			if (macd->rgmii) {
				val = rd32(CLK_SKEW_CTRL);
				val &= ~(0x03 << (6 + (i << 3))); /* clear mac_txc_dly */
				val &= ~(0x03 << (4 + (i << 3))); /* clear mac_rxc_dly */

				val |= (macd->txc_dly << (6 + (i << 3)));
				val |= (macd->rxc_dly << (4 + (i << 3)));

				wr32(val, CLK_SKEW_CTRL);
			}

			if (macd->wan_port) {
				val = rd32(VLAN_CFG);
				val |= (1 << i) << 8;
				wr32(val, VLAN_CFG);
			}
		}
	}
	wr32(reg0x4, PHY_AUTO_ADDR);
}

static void pse_sys_init_police(void)
{
	police_global_min_th_write(960);
}

int pse_sys_init(struct pse_platform_data *pdata)
{
	/* misc. configuration: share pin*/
	pse_sys_init_misc();

	/* clock configuration, clock enable, software reset */
	pse_sys_init_clock();

	/* global configuration */
	pse_sys_init_global();

	/* default VLAN configuration */
	pse_sys_init_vlan();

	/* default MAC check configuration */
	pse_sys_init_mac(pdata);

	/* CPU port configuration */
	pse_sys_init_cpu_port();

	/* each MAC port configuration */
	pse_sys_init_mac_port(pdata);

	pse_sys_init_police();

	return 0;
}

void pse_status_intr_cfg(u32 mask)
{

	fwr32(mask, STATUS_INTR_MASK);
}

void pse_ts_intr_mask(u8 ring_id)
{
	u32 val, mask;

	if (ring_id >= PSE_MAX_TS_RING_NUM) {
		P_WARN("<%s> Incorrect TS ring id %d\n", __func__, ring_id);
		return;
	}

	mask = (0x3 << (ring_id << 1));
	val = frd32(TS_STATUS_INTR_MASK);
	val |= mask;
	fwr32(val, TS_STATUS_INTR_MASK);
}

void pse_ts_intr_unmask(u8 ring_id)
{
	u32 val, mask;

	if (ring_id >= PSE_MAX_TS_RING_NUM) {
		P_WARN("<%s> Incorrect TS ring id %d\n", __func__, ring_id);
		return;
	}

	mask = (0x3 << (ring_id << 1));
	val = frd32(TS_STATUS_INTR_MASK);
	val &= ~mask;
	fwr32(val, TS_STATUS_INTR_MASK);
}

void pse_fs_intr_mask(u8 ring_id)
{
	u32 val, mask;

	if (ring_id >= PSE_MAX_FS_RING_NUM) {
		P_WARN("<%s> Incorrect FS ring id %d\n", __func__, ring_id);
		return;
	}

	mask = (0x3 << (ring_id << 1));
	val = frd32(FS_STATUS_INTR_MASK);
	val |= mask;
	fwr32(val, FS_STATUS_INTR_MASK);
}

void pse_fs_intr_unmask(u8 ring_id)
{
	u32 val, mask;

	if (ring_id >= PSE_MAX_FS_RING_NUM) {
		P_WARN("<%s> Incorrect FS ring id %d\n", __func__, ring_id);
		return;
	}

	mask = (0x3 << (ring_id << 1));
	val = frd32(FS_STATUS_INTR_MASK);
	val &= ~mask;
	fwr32(val, FS_STATUS_INTR_MASK);
}
EXPORT_SYMBOL(pse_fs_intr_unmask);

void pse_fs_dma_enable(u16 mask)
{
	P_TRACE("<%s> mask 0x%.4x\n", __func__, mask);
	wr32(mask, FS_DMA_CTRL);
}
EXPORT_SYMBOL(pse_fs_dma_enable);

void pse_ts_dma_enable(u16 mask)
{
	P_TRACE("<%s> mask 0x%.4x\n", __func__, mask);

	wr32(mask, TS_DMA_CTRL);
}

#define PSE_PORT_CFG_MASK_BCS_RATE_CONTROL	(0x1 << 30)
#define PSE_PORT_CFG_MASK_INGRESS_CHECK		(0x1 << 24)
#define PSE_PORT_CFG_MASK_BLOCK_MODE		(0x1 << 21)
#define PSE_PORT_CFG_MASK_BLOCKING_STATE	(0x1 << 20)
#define PSE_PORT_CFG_MASK_DISABLE			(0x1 << 18)
#define PSE_PORT_CFG_MASK_BP_EN				(0x1 << 17)

void pse_port_cfg(u8 port, bool enable)
{
	u32 val, offset;

	switch (port) {
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
		P_WARN("<%s> Unsupported MAC port %d\n", __func__, port);
		return;
	}


	val = rd32(offset);

	if (enable)
		val &= ~PSE_PORT_CFG_MASK_DISABLE; /* port enable */
	else
		val |= PSE_PORT_CFG_MASK_DISABLE;

	wr32(val, offset);
}


void pse_port_ingress_check(u8 port, bool enable)
{
	u32 val, offset;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0:
		offset = MAC0_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		offset = MAC1_CFG;
		break;
	case OPV5XC_PSE_PORT_CPU:
		offset = CPU_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		offset = MAC2_CFG;
		break;
	default:
		P_WARN("<%s> Unsupported MAC port %d\n", __func__, port);
		return;
	}

	val = rd32(offset);

	if (enable)
		val |= PSE_PORT_CFG_MASK_INGRESS_CHECK;
	else
		val &= ~PSE_PORT_CFG_MASK_INGRESS_CHECK;

	wr32(val, offset);

}

void pse_port_blocking_state(u8 port, bool enable)
{
	u32 val, offset;

	switch (port) {
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
		P_WARN("<%s> Unsupported MAC port %d\n", __func__, port);
		return;
	}
	val = rd32(offset);

	if (enable)
		val |= PSE_PORT_CFG_MASK_BLOCKING_STATE;
	else
		val &= ~PSE_PORT_CFG_MASK_BLOCKING_STATE;

	wr32(val, offset);
}

void pse_port_block_mode(u8 port, bool enable)
{
	u32 val, offset;

	switch (port) {
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
		P_WARN("<%s> Unsupported MAC port %d\n", __func__, port);
		return;
	}
	val = rd32(offset);

	if (enable)
		val |= PSE_PORT_CFG_MASK_BLOCK_MODE;
	else
		val &= ~PSE_PORT_CFG_MASK_BLOCK_MODE;

	wr32(val, offset);
}

void pse_port_bp_enable(u8 port, bool enable)
{
	u32 val, offset;

	switch (port) {
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
		P_WARN("<%s> Unsupported MAC port %d\n", __func__, port);
		return;
	}

	val = rd32(offset);
	if (enable)
		val |= PSE_PORT_CFG_MASK_BP_EN;
	else
		val &= ~PSE_PORT_CFG_MASK_BP_EN;

	wr32(val, offset);
}

void pse_port_broadcast_storm_rate_control(u8 port, bool enable)
{
	u32 val, offset;

	switch (port) {
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
		P_WARN("<%s> Unsupported MAC port %d\n", __func__, port);
		return;
	}
	val = rd32(offset);

	if (enable)
		val |= PSE_PORT_CFG_MASK_BCS_RATE_CONTROL;
	else
		val &= ~PSE_PORT_CFG_MASK_BCS_RATE_CONTROL;

	wr32(val, offset);
}

void pse_rx_broadcast_storm_rate(u8 rate)
{
	u32 val;

	if (rate > 10) {
		P_WARN("<%s> value out of range %d\n", __func__, rate);
		return;
	}
	val = rd32(TC_CTRL);
	val &= ~(0xF << 24); /* RX_BCS_RATE */
	val |= (rate << 24);
	wr32(val, TC_CTRL);
}


void pse_port_skip_l2_lookup(u8 port, bool enable)
{
	u32 val;

	val = rd32(MAC_GLOB_CFG);
	switch (port) {
	case PSE_MAC0_PORT:
		if (enable)
			val |= (0x1 << 29);
		else
			val &= ~(0x1 << 29);
		break;
	case PSE_MAC1_PORT:
		if (enable)
			val |= (0x1 << 30);
		else
			val &= ~(0x1 << 30);
		break;
	default:
		P_WARN("<%s> Unsupported MAC port %d\n", __func__, port);
		return;
	}

	wr32(val, MAC_GLOB_CFG);
}

void pse_res_mc_flt(bool enable)
{
	u32 val;

	val = rd32(MAC_GLOB_CFG);
	if (enable)
		val |= (0x1 << 28);
	else
		val &= ~(0x1 << 28);
	wr32(val, MAC_GLOB_CFG);
}

void pse_unknown_vlan_tocpu(bool enable)
{
	u32 val;

	val = rd32(MAC_GLOB_CFG);
	if (enable)
		val |= (0x1 << 25);
	else
		val &= ~(0x1 << 25);
	wr32(val, MAC_GLOB_CFG);
}

void pse_accept_crc_pkt(bool enable)
{
	u32 val;

	val = rd32(MAC_GLOB_CFG);
	if (enable)
		val |= (0x1 << 21);
	else
		val &= ~(0x1 << 21);
	wr32(val, MAC_GLOB_CFG);
}

void pse_col_mode(u8 mode)
{
	u32 val;

	val = rd32(MAC_GLOB_CFG);
	val &= ~(0x3 << 18);
	val |= (mode << 18);
	wr32(val, MAC_GLOB_CFG);
}

void pse_bp_mode(u8 mode)
{
	u32 val;

	val = rd32(MAC_GLOB_CFG);
	val &= ~(0x3 << 16);
	val |= (mode << 16);
	wr32(val, MAC_GLOB_CFG);
}

void pse_jam_no(u8 num)
{
	u32 val;

	val = rd32(MAC_GLOB_CFG);
	val &= ~(0xf << 12);
	val |= (num << 12);
	wr32(val, MAC_GLOB_CFG);
}

void pse_bkoff_mode(u8 mode)
{
	u32 val;

	val = rd32(MAC_GLOB_CFG);
	val &= ~(0x7 << 9);
	val |= (mode << 9);
	wr32(val, MAC_GLOB_CFG);
}

void pse_promisc_mode(u8 port, bool enable)
{
	u32 val;
	val = rd32(MAC_CHECK_CFG);

	switch (port) {
	case PSE_MAC0_PORT:
		if (enable)
			val |= (1 << 3);
		else
			val &= ~(1 << 3);
		break;

	case PSE_MAC1_PORT:
		if (enable)
			val |= (1 << 5);
		else
			val &= ~(1 << 5);
		break;

	case PSE_CPU_PORT:
		if (enable)
			val |= (1 << 7);
		else
			val &= ~(1 << 7);
		break;

	}
	wr32(val, MAC_CHECK_CFG);
}

void pse_my_mac_only(u8 port, bool enable)
{
	u32 val;
	val = rd32(MAC_CHECK_CFG);

	switch (port) {
	case PSE_MAC0_PORT:
		if (enable)
			val |= (1 << 2);
		else
			val &= ~(1 << 2);
		break;

	case PSE_MAC1_PORT:
		if (enable)
			val |= (1 << 4);
		else
			val &= ~(1 << 4);
		break;

	case PSE_CPU_PORT:
		if (enable)
			val |= (1 << 6);
		else
			val &= ~(1 << 6);
		break;

	}
	wr32(val, MAC_CHECK_CFG);
}

void pse_set_max_frame_len(u8 port, u32 max_frame)
{
	int max_len[] = {1518, 1522, 1536, 9600};
	u32 i, val;

	for (i = 0; i < 4; i++) {
		if (max_frame <= max_len[i])
			break;
	}

	val = rd32(PHY_AUTO_ADDR);
	val &= ~(0x3 << (26 + port*2));
	val |= (i << (26 + port*2));
	wr32(val, PHY_AUTO_ADDR);
}

void pse_tso_enable(bool enable)
{
	u32 val;

	val = rd32(LSO_CFG);
	if (enable)
		val |= 0x1;
	else
		val &= ~0x1;
	wr32(val, LSO_CFG);
}

void pse_ufo_enable(bool enable)
{
	u32 val;

	val = rd32(LSO_CFG);
	if (enable)
		val |= 0x2;
	else
		val &= ~0x2;
	wr32(val, LSO_CFG);
}

void pse_ufo_df_enable(bool enable)
{
	u32 val;

	val = rd32(LSO_CFG);
	if (enable)
		val |= 0x4;
	else
		val &= ~0x4;
	wr32(val, LSO_CFG);
}

void pse_ufo_check_df_enable(bool enable)
{
	u32 val;

	val = rd32(LSO_CFG);
	if (enable)
		val |= 0x8;
	else
		val &= ~0x8;
	wr32(val, LSO_CFG);
}

void pse_lso_init(void)
{
#ifdef PSE_TSO_SUPPORT
	pse_tso_enable(PSE_TSO_EN_DEFAULT);
#endif

#ifdef PSE_UFO_SUPPORT
	pse_ufo_enable(PSE_UFO_EN_DEFAULT);
	pse_ufo_df_enable(false);
	pse_ufo_check_df_enable(false);
#endif
}

/* */
#define PSE_PORT_DISABLE_MASK (0x1 << 18)
void pse_ppe_port_cfg(bool en)
{
	u32 val;

	val = rd32(PPE_PORT_CFG);

	if (en)
		val &= ~PSE_PORT_DISABLE_MASK;
	else
		val |= PSE_PORT_DISABLE_MASK;

	wr32(val, PPE_PORT_CFG);
};
EXPORT_SYMBOL(pse_ppe_port_cfg);

bool pse_ppe_port_en(void)
{
	return (PSE_PORT_DISABLE_MASK !=
		(rd32(PPE_PORT_CFG) & PSE_PORT_DISABLE_MASK));
};
EXPORT_SYMBOL(pse_ppe_port_en);

void pse_cfp_port_cfg(bool en)
{
	u32 val;
	val = rd32(CFP_CFG);
	if (en)
		val &= ~PSE_PORT_DISABLE_MASK;
	else
		val |= PSE_PORT_DISABLE_MASK;
	wr32(val, CFP_CFG);
};
EXPORT_SYMBOL(pse_cfp_port_cfg);

bool pse_cfp_port_en(void)
{
	return (PSE_PORT_DISABLE_MASK !=
		(rd32(CFP_CFG) & PSE_PORT_DISABLE_MASK));
};
EXPORT_SYMBOL(pse_cfp_port_en);

u32 pse_func_status(void)
{
	return rd32(FUNC_STA);
}
EXPORT_SYMBOL(pse_func_status);

#define PSE_ACP_DESC_CACHE_TYPE		(0x7)
#define PSE_ACP_HEADER_CACHE_TYPE	(0x7)
#define PSE_ACP_PAYLOAD_CACHE_TYPE	(0x3)
#define PSE_ACP_TABLE_CACHE_TYPE	(0x7)

void pse_acp_desc_cfg(bool en)
{
	u32 reg;
	reg = rd32(DMA_RING_CFG);

	if (en)
		reg |= ((0x1 << 15) | (PSE_ACP_DESC_CACHE_TYPE << 28));
	else
		reg &= ~((0x1 << 15) | (PSE_ACP_DESC_CACHE_TYPE << 28));

	wr32(reg, DMA_RING_CFG);
}

void pse_acp_header_cfg(bool en)
{
	u32 reg;
	reg = rd32(DMA_RING_CFG);

	if (en)
		reg |= ((0x1 << 14) | (PSE_ACP_HEADER_CACHE_TYPE << 24));
	else
		reg &= ~((0x1 << 14) | (PSE_ACP_HEADER_CACHE_TYPE << 24));

	wr32(reg, DMA_RING_CFG);
}

void pse_acp_payload_cfg(bool en)
{
	u32 reg;
	reg = rd32(DMA_RING_CFG);

	if (en)
		reg |= ((0x1 << 13) | (PSE_ACP_PAYLOAD_CACHE_TYPE << 20));
	else
		reg &= ~((0x1 << 13) | (PSE_ACP_PAYLOAD_CACHE_TYPE << 20));

	wr32(reg, DMA_RING_CFG);
}

void pse_acp_table_cfg(bool en)
{
	u32 reg;
	reg = rd32(DMA_RING_CFG);

	if (en)
		reg |= ((0x1 << 12) | (PSE_ACP_TABLE_CACHE_TYPE << 16));
	else
		reg &= ~((0x1 << 12) | (PSE_ACP_TABLE_CACHE_TYPE << 16));

	wr32(reg, DMA_RING_CFG);
}
EXPORT_SYMBOL(pse_acp_table_cfg);

void pse_acp_cfg(bool en)
{
#if defined(ACP_DESC)
	pse_acp_desc_cfg(en);
#endif
#if defined(ACP_HEADER)
	pse_acp_header_cfg(en);
#endif
#if defined(ACP_PAYLOAD)
	pse_acp_payload_cfg(en);
#endif
}

#define PSE_TS_SUSPEND_MASK (0x1 << 4)
#define PSE_FS_SUSPEND_MASK (0x1 << 0)
void pse_ts_suspend_cfg(bool en)
{
	u32 reg;
	reg = rd32(DMA_RING_CFG);

	if (en)
		reg |= PSE_TS_SUSPEND_MASK;
	else
		reg &= ~PSE_TS_SUSPEND_MASK;

	wr32(reg, DMA_RING_CFG);
}

void pse_fs_suspend_cfg(bool en)
{
	u32 reg;
	reg = rd32(DMA_RING_CFG);

	if (en)
		reg |= PSE_FS_SUSPEND_MASK;
	else
		reg &= ~PSE_FS_SUSPEND_MASK;

	wr32(reg, DMA_RING_CFG);
}
