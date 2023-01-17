/**
 * AppliedMicro APM862xx SoC Ethernet Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Keyur Chudgar <kchudgar@apm.com>
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
 * @file apm_enet_mac.c
 *
 * This file implements driver for RGMII, MAC and statistics blocks of
 * APM862xx SoC Ethernet subsystem
 *
 */
#include "apm_enet_access.h"
#include "apm_enet_mac.h"
#include "apm_enet_csr.h"

#undef APM_ENET_MAC_LOOPBACK

#define MAX_LOOP_POLL_TIMEMS	500
#define MAX_LOOP_POLL_CNT	10
#define ACCESS_DELAY_TIMEMS	(MAX_LOOP_POLL_TIMEMS / MAX_LOOP_POLL_CNT)

/* No need to poll CSR faster than 1 ms */
#if defined(PHY_CSR_ACCESS_NO_DELAY)
#define PHY_CSR_POLL_DELAY
#else
#define PHY_CSR_POLL_DELAY	msleep(1);
#endif

int apm_genericmiiphy_write(struct apm_data_priv *priv, u8 phy_id,
			   unsigned char reg, u32 data)
{
	u32 value;
	u32 blockid = BLOCK_ETH_EXTPHY;

	/* All PHYs lie on MII bus of Port0 MAC due to this
	 * each port should access its PHY through Port0 MAC.
	 * Hence we allow access to PHY_ID associated with this
	 * port only.
	 */
	if (priv->phy_addr != phy_id) {
#if !defined(CONFIG_APM862xx)
		/* INT_PHY_ADDR is a hack for SGMII
		 * If the phy id is of the internal phy id, we need to
		 * access accordingly. Otherwise, the incorrect register
		 * will be read.
		 */
		if (phy_id == INT_PHY_ADDR) {
			blockid = BLOCK_ETH_INTPHY;
		} else {
			return 0;
		}
#else
		return 0;
#endif
	}

	/* Write PHY number and address in MII Mgmt Address */
	value = PHY_ADDR_WR(phy_id) | REG_ADDR_WR(reg);
	apm_emac_write32(priv, blockid,
			MII_MGMT_ADDRESS_ADDR,value);

	/* Write 16 bit data to MII MGMT CONTROL */
	value = PHY_CONTROL_WR(data);
	apm_emac_write32(priv, blockid,
			MII_MGMT_CONTROL_ADDR, value);

	/* wait until the write is complete */
	while (1) {
		apm_emac_read32(priv, blockid,
			       MII_MGMT_INDICATORS_ADDR, &value);
		if (!(value & BUSY_F14_MASK))
			break;
		PHY_CSR_POLL_DELAY
	}
	PHY_PRINT("PHY WR ID %d reg %d ctrl 0x%X data 0x%X\n",
		phy_id, reg, PHY_CONTROL_WR(data), data);

	/* Wait for sometime.
	 * This will give reliable writes on flicky boards.
	 */
/*	udelay(1000); */

	return 0;
}

int apm_genericmiiphy_read(struct apm_data_priv *priv, u8 phy_id,
			  unsigned char reg, u32 *data)
{
	u32 value;
	u32 blockid = BLOCK_ETH_EXTPHY;
	u32 timeout = 10;

	/* Wait for sometime.
	 * This will give reliable reads on flicky boards.
	 */
/*	udelay(1000); */

	/* All PHYs lie on MII bus of Port0 MAC due to this
	 * each port should access its PHY through Port0 MAC.
	 * Hence we allow access to PHY_ID associated with this
	 * port only.
	 */
	if (priv->phy_addr != phy_id) {
#if !defined(CONFIG_APM862xx)
		/* INT_PHY_ADDR is a hack for SGMII
		 * If the phy id is of the internal phy id, we need to
		 * access accordingly. Otherwise, the incorrect register
		 * will be read.
		 */
		if (phy_id == INT_PHY_ADDR) {
			blockid = BLOCK_ETH_INTPHY;
		} else {
			*data = 0xFFFF;
			return 0;
		}
#else
		*data = 0xFFFF;
		return 0;
#endif
	}

read_again:

	/* Write PHY number and address in MII Mgmt Address */
	value = PHY_ADDR_WR(phy_id) | REG_ADDR_WR(reg);
	apm_emac_write32(priv, blockid, MII_MGMT_ADDRESS_ADDR, value);

	/* Write read command */
	apm_emac_write32(priv, blockid, MII_MGMT_COMMAND_ADDR,
			READ_CYCLE_MASK);

	/* wait until the write is complete */
	while (1) {
		apm_emac_read32(priv, blockid,
			       MII_MGMT_INDICATORS_ADDR, &value);
		if (!(value & BUSY_F14_MASK))
			break;
		PHY_CSR_POLL_DELAY
	}

	apm_emac_read32(priv, blockid, MII_MGMT_STATUS_ADDR, data);
	PHY_PRINT("PHY RD ID %d reg %d cmd 0x%X data 0x%X\n",
		phy_id, reg, READ_CYCLE_MASK, *data);

	/* reset mii_mgmt_command register */
	apm_emac_write32(priv, blockid, MII_MGMT_COMMAND_ADDR, 0);

	/* if invalid value detected then read again */
	if ((((*data) & 0xFFFF) == 0xFFFF) && (timeout-- > 0))
		goto read_again;

	return 0;
}

void apm_gmac_loopback(struct apm_data_priv *priv, u8 loopback)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	/* Modify value to set or remove loopback mode */
	if (loopback)
		data |= LOOP_BACK1_MASK;
	else
		data &= ~LOOP_BACK1_MASK;

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC,MAC_CONFIG_1_ADDR, data);
}

void apm_gmac_rgmii_loopback(struct apm_data_priv *priv, u8 loopback)
{
	u32 data;

	/* Read current value of the RGMII register */
	apm_emac_read32(priv, BLOCK_ETH_MAC_GBL,
		       RGMII_REG_0_ADDR, &data);

	/* Modify value to set or remove RGMII loopback mode */
	if (loopback)
		data |= CFG_LOOPBACK_TX2RX0_MASK;
	else
		data &= ~ CFG_LOOPBACK_TX2RX0_MASK;

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
			RGMII_REG_0_ADDR, data);
}

/* Start MAC related functions */
void apm_gmac_set_gmac_addr(struct apm_data_priv *priv,
			unsigned char *dev_addr)
{
	u32 a_hi;
	u32 a_lo;

	a_hi = *(u32 *) &dev_addr[0];
	a_lo = (u32) *(u16 *) &dev_addr[4];

	/* Write higher 4 octects to station register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, STATION_ADDR0_ADDR, a_hi);

	a_lo <<= 16;
	a_lo |= (priv->phy_addr & 0xFFFF);

	/* Write lower 2 octects to station register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, STATION_ADDR1_ADDR, a_lo);
}

int apm_gmac_is_rx_flow_control(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	return RX_FLOW_EN1_RD(data);
}

void apm_gmac_rx_flow_control(struct apm_data_priv *priv, u8 enable)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	/* Modify value to set or reset rx flow control */
	if (enable)
		data |= RX_FLOW_EN1_MASK;
	else
		data &= ~RX_FLOW_EN1_MASK;

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC,MAC_CONFIG_1_ADDR, data);
}

int apm_gmac_is_tx_flow_control(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	return TX_FLOW_EN1_RD(data);
}

void apm_gmac_tx_flow_control(struct apm_data_priv *priv, u8 enable)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	/* Modify value to set or reset tx flow control */
	if (enable)
		data |= TX_FLOW_EN1_MASK;
	else
		data &= ~TX_FLOW_EN1_MASK;

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC,MAC_CONFIG_1_ADDR, data);
}

int apm_gmac_is_rx_enable(struct apm_data_priv *priv)
{
	u32 data;
	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);
	return RX_EN1_RD(data) ? 1 : 0;
}

void apm_gmac_rx_enable(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC,
		       MAC_CONFIG_1_ADDR, &data);

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC,
			MAC_CONFIG_1_ADDR,RX_EN1_SET(data, 1));
}

void apm_gmac_rx_disable(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC,
			MAC_CONFIG_1_ADDR, RX_EN1_SET(data, 0));
}

void apm_gmac_tx_enable(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC,
			MAC_CONFIG_1_ADDR, TX_EN1_SET(data, 1));
}

void apm_gmac_tx_disable(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC,
			MAC_CONFIG_1_ADDR, TX_EN1_SET(data, 0));
}

void apm_gmac_set_preamble_length(struct apm_data_priv *priv, u8 length)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	/* Write value back to config 2 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR,
			PREAMBLE_LENGTH2_SET(data, length));
}

void apm_gmac_set_intf_mode(struct apm_data_priv *priv, u8 intf_mode)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	/* Write value back to config 2 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR,
			INTERFACE_MODE2_SET(data, intf_mode));
}

int  apm_gmac_get_intf_mode(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);
	return INTERFACE_MODE2_RD(data);
}

void apm_gmac_huge_frame_enable(struct apm_data_priv *priv, u8 enable)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	/* Modify value to set or reset huge frame enable bit */
	if (enable)
		data |= HUGE_FRAME_EN2_MASK;
	else
		data &= ~HUGE_FRAME_EN2_MASK;

	/* Write value back to config 2 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, data);
}

void apm_gmac_len_field_check_enable(struct apm_data_priv *priv, u8 enable)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	/* Modify value to set or reset length field check enable bit */
	if (enable)
		data |= LENGTH_CHECK2_MASK;
	else
		data &= ~LENGTH_CHECK2_MASK;

	/* Write value back to config 2 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, data);
}

void apm_gmac_pad_crc_enable(struct apm_data_priv *priv, u8 enable)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	/* Modify value to set or reset pad and crc check enable bit */
	if (enable)
		data |= PAD_CRC2_MASK;
	else
		data &= ~PAD_CRC2_MASK;

	/* Write value back to config 2 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, data);
}

int  apm_gmac_get_pad_crc_mode(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	return  PAD_CRC2_RD(data);
}

void apm_gmac_crc_enable(struct apm_data_priv *priv, u8 enable)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	/* Modify value to set or reset crc check enable bit */
	if (enable)
		data |= CRC_EN2_MASK;
	else
		data &= ~CRC_EN2_MASK;

	/* Write value back to config 2 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, data);
}

int  apm_gmac_get_crc_mode(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	return  CRC_EN2_RD(data);
}

int apm_gmac_get_full_duplex_mode(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the MAC Interface Status register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, INTERFACE_STATUS_ADDR, &data);

	return ((data & FULL_DUPLEX_MASK) ? 1 : 0);
}

void apm_gmac_full_duplex_enable(struct apm_data_priv *priv, u8 enable)
{
	u32 data;

	/* Read current value of the MAC config 2 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &data);

	/* Modify value to set or reset full duplex enable bit */
	if (enable)
		data |= FULL_DUPLEX2_MASK;
	else
		data &= ~FULL_DUPLEX2_MASK;

	/* Write value back to MAC config 2 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, data);
}

void apm_gmac_set_min_ipg(struct apm_data_priv *priv, u16 min_ifg)
{
	u32 data;

	/* Read current value of the IPG IFG register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, IPG_IFG_ADDR, &data);

	/* Write value back to IPG IFG register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, IPG_IFG_ADDR,
			MIN_IFG_ENFORCE_SET(data, min_ifg));
}

void apm_gmac_set_ipg(struct apm_data_priv *priv, u16 ipg)
{
	u32 data;

	/* Read current value of the IPG IFG register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, IPG_IFG_ADDR, &data);

	/* Write value back to IPG IFG register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, IPG_IFG_ADDR,
			B2B_IPG_SET(data, ipg));

	ENET_DEBUG("Setting IPG to %d bits", ipg);
}

void apm_gmac_set_mgnt_clock(struct apm_data_priv *priv, u8 clk)
{
	u32 data;

	/* Read current value of the mii_mgmt_config register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MII_MGMT_CONFIG_ADDR, &data);

	/* Write value back to	mii_mgmt_config	 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MII_MGMT_CONFIG_ADDR,
			MGMT_CLOCK_SEL_SET(data, clk));
}

void apm_gmac_change_mtu(struct apm_data_priv *priv, u32 new_mtu)
{
	u32 data;

	/* Read current value of the Maximum Frame Length register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAX_FRAME_LEN_ADDR, &data);

	/* Write value back to Maximum Frame Length register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAX_FRAME_LEN_ADDR,
			MAX_FRAME_LEN_SET(data, new_mtu));
}

void apm_gmac_tx_reset(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	/* Perform MAC TX Reset */
	data |= (RESET_TX_MC1_MASK | RESET_TX_FUN1_MASK);
	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, data);
}

void apm_gmac_rx_reset(struct apm_data_priv *priv)
{
	u32 data;

	/* Read current value of the config 1 register */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &data);

	/* Perform MAC TX Reset */
	data |= (RESET_RX_MC1_MASK | RESET_RX_FUN1_MASK);

	/* Write value back to config 1 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, data);
}

int apm_gmac_link_status(struct apm_data_priv *priv)
{
	u32 data;

	apm_emac_read32(priv, BLOCK_ETH_MAC, INTERFACE_STATUS_ADDR, &data);
	return (data & LINK_OK_MASK) ? 1 : 0;
}

void apm_gmac_phy_link_mode(struct apm_data_priv *priv, u32 *speed, u32 *state)
{
	u32 sts, ctl, anar, lpar, anlpar;
	u32 ganar = 0, glpar = 0;

	/* Link status is latched in PHY so read it twice */
	sts = 0x0;
	apm_genericmiiphy_read(priv, priv->phy_addr, MII_STAT_REG, &sts);
	apm_genericmiiphy_read(priv, priv->phy_addr, MII_STAT_REG, &sts);
	PHY_PRINT("MII_STAT_REG: 0x%x 0x%x\n", sts, (sts & MII_SR_LINK_STATUS));
	*state = (sts & MII_SR_LINK_STATUS) ? 1 : 0;

	/* If no link then return SPEED_0 */
	if (!(sts & MII_SR_LINK_STATUS)) {
		*speed = SPEED_0;
		return;
	}

	apm_genericmiiphy_read(priv, priv->phy_addr, MII_CTRL_REG, &ctl);
	PHY_PRINT("MII_CTRL_REG: 0x%x \n", ctl);
	apm_genericmiiphy_read(priv, priv->phy_addr, MII_AN_ADS_REG, &anar);
	PHY_PRINT("MII_AN_ADS_REG: 0x%x \n", anar);
	apm_genericmiiphy_read(priv, priv->phy_addr, MII_AN_PRTN_REG, &lpar);
	PHY_PRINT("MII_AN_PRTN_REG: 0x%x \n", lpar);
	if (sts & MII_SR_EXT_STS) {
		apm_genericmiiphy_read(priv, priv->phy_addr, MII_MASSLA_CTRL_REG, &ganar);
		PHY_PRINT("MII_MASSLA_CTRL_REG: 0x%x \n", ganar);
		apm_genericmiiphy_read(priv, priv->phy_addr, MII_MASSLA_STAT_REG, &glpar);
		PHY_PRINT("MII_MASSLA_STAT_REG: 0x%x \n", glpar);
	}

	/*
	 * If autoneg is on, figure out the link speed from the
	 * advertisement and partner ability registers. If autoneg is
	 * off, use the settings in the control register.
	 */
	*speed = SPEED_0;
	if (ctl & MII_CR_AUTO_EN) {
		anlpar = anar & lpar;
		if ((ganar & MII_MASSLA_CTRL_1000T_FD) &&
		    (glpar & MII_MASSLA_STAT_LP1000T_FD)) {
			*speed = SPEED_1000;
		} else if ((ganar & MII_MASSLA_CTRL_1000T_HD) &&
			   (glpar & MII_MASSLA_STAT_LP1000T_HD)) {
			*speed = SPEED_1000;
		} else if (anlpar & MII_ANAR_100TX_FD) {
			*speed = SPEED_100;
		} else if (anlpar & MII_ANAR_100TX_HD) {
			*speed = SPEED_100;
		} else if (anlpar & MII_ANAR_10TX_FD) {
			*speed = SPEED_10;
		} else if (anlpar & MII_ANAR_10TX_HD) {
			*speed = SPEED_10;
		}
	} else {
		if ((ctl & (MII_CR_100 | MII_CR_1000)) ==
					(MII_CR_100 | MII_CR_1000)) {
			*speed = SPEED_1000;
		} else if (ctl & MII_CR_100) {
			*speed = SPEED_100;
		} else {
			*speed = SPEED_10;
		}
	}
}

int apm_gmac_phy_enable_scan_cycle(struct apm_data_priv *priv, int enable)
{
#if !defined(CONFIG_APM862xx)
	u32 val;

	/* Enable scan cycle command for link scanning in MAC */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MII_MGMT_COMMAND_ADDR, &val);
	if (enable)
		val |= SCAN_CYCLE_MASK;
	else
		val &= ~SCAN_CYCLE_MASK;
	apm_emac_write32(priv, BLOCK_ETH_MAC, MII_MGMT_COMMAND_ADDR, val);

	/* Program phy address start scan from 0 and register at address 0x1 */
	apm_emac_read32(priv, BLOCK_ETH_MAC, MII_MGMT_ADDRESS_ADDR, &val);
	val = PHY_ADDR_SET(val, 0);
	val = REG_ADDR_SET(val, 1);
	apm_emac_write32(priv, BLOCK_ETH_MAC, MII_MGMT_ADDRESS_ADDR, val);
#endif
	return 0;
}

void apm_gmac_reset(struct apm_data_priv *priv)
{
	u32 value;
#if defined(CONFIG_APM862xx)
	u32 mac_base_addr_v = priv->mac_base_addr_v;
	static u32 apm_enet0_mac_init_done = 0;
#endif

	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &value);
	if (!(value & SOFT_RESET1_MASK)) {
		return;
	}

#if defined(CONFIG_APM862xx)
	if (priv->port && !apm_enet0_mac_init_done) {
		priv->mac_base_addr_v = priv->enet_mii_base_addr_v;
		apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &value);
		if (!(value & SOFT_RESET1_MASK)) {
			priv->mac_base_addr_v = mac_base_addr_v;
			apm_enet0_mac_init_done = 1;
		}
	}

_reset_gmac_access_phy:
#endif
	/* Reset MAC subsystem */
	value = RESET_TX_FUN1_WR(1) |
			RESET_RX_FUN1_WR(1) |
			RESET_TX_MC1_WR(1)  |
			RESET_RX_MC1_WR(1)  |
			SIM_RESET1_WR(1)    |
			SOFT_RESET1_WR(1);

	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, value);
	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &value);
	udelay(100);
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, 0);

#if defined(CONFIG_APM862xx)
	if (priv->port && !apm_enet0_mac_init_done) {
		priv->mac_base_addr_v = mac_base_addr_v;
		apm_enet0_mac_init_done = 1;
		goto _reset_gmac_access_phy;
	}
#endif
}

void apm_gmac_phy_reset(struct apm_data_priv *priv)
{
	int retry;
	u32 data;

	/* Reset PHY */
	data = 0x0;
	apm_genericmiiphy_read(priv, priv->phy_addr, MII_CTRL_REG, &data);
	data |= MII_CR_RESET;
	apm_genericmiiphy_write(priv, priv->phy_addr, MII_CTRL_REG, data);

	/* Wait till PHY reset completes */
	retry = 1000;
	while ((data & MII_CR_RESET) && (retry > 0)) {
		apm_genericmiiphy_read(priv, priv->phy_addr, MII_CTRL_REG, &data);
		retry--;
		PHY_CSR_POLL_DELAY
	}
}

int apm_gmac_phy_autoneg_done(struct apm_data_priv *priv)
{
	u32 ctl, sts, sts1;

	apm_genericmiiphy_read(priv, priv->phy_addr, MII_CTRL_REG, &ctl);

	if (!(ctl & MII_CR_AUTO_EN)) {
		/* Auto-neg disabled so, just return 1 */
		return 1;
	}

read_sts_again:
	sts = 0x0;
	apm_genericmiiphy_read(priv, priv->phy_addr, MII_STAT_REG, &sts);
	sts1 = 0x0;
	apm_genericmiiphy_read(priv, priv->phy_addr, MII_STAT_REG, &sts1);
	if (sts != sts1) {
		goto read_sts_again;
	}

	return (sts & MII_SR_AUTO_NEG) ? 1 : 0;
}

void apm_gmac_phy_init(struct apm_data_priv *priv,
			int force,
			int full_duplex,
			int speed)
{
	int retry;
	u32 data, sts;
	u32 anar, ganar, ctl;

	/* Get PHY status */
	sts = 0x0;
	apm_genericmiiphy_read(priv, priv->phy_addr, MII_STAT_REG, &sts);

	/* Set autoneg advertisement to advertise all modes. */
	anar = MII_ANAR_10TX_HD | MII_ANAR_10TX_FD |
		MII_ANAR_100TX_HD | MII_ANAR_100TX_FD;
	if (sts & MII_SR_EXT_STS)
		ganar = MII_MASSLA_CTRL_1000T_FD|MII_MASSLA_CTRL_1000T_HD;
	ctl = MII_CR_RESTART;
	if (force) {
		if (full_duplex) {
			ctl |= MII_CR_FDX;
		}
		switch(speed) {
		case SPEED_10:
			break;
		case SPEED_100:
			ctl |= MII_CR_100;
			break;
		case SPEED_1000:
			ctl |= MII_CR_1000;
			break;
		default:
			ctl |= MII_CR_AUTO_EN;
			break;
		};
	} else {
		ctl |= MII_CR_AUTO_EN;
	}

	/* Power-down PHY */
	data = MII_CR_POWER_DOWN;
	apm_genericmiiphy_write(priv, priv->phy_addr, MII_CTRL_REG, data);

	/* Power-up PHY */
	data = 0x0;
	apm_genericmiiphy_write(priv, priv->phy_addr, MII_CTRL_REG, data);

	/* Reset PHY */
	data = MII_CR_RESET;
	apm_genericmiiphy_write(priv, priv->phy_addr, MII_CTRL_REG, data);

	/* Wait till PHY reset completes */
	retry = 1000;
	while ((data & MII_CR_RESET) && (retry > 0)) {
		apm_genericmiiphy_read(priv, priv->phy_addr, MII_CTRL_REG, &data);
		retry--;
		PHY_CSR_POLL_DELAY
	}

	/* If the extended capabilities bit is set, this is a gigE
	 * PHY, so make sure we advertise gigE modes.
	 */
	if (sts & MII_SR_EXT_STS) {
		/* Enable advertisement of gigE modes. */
		data = MII_MASSLA_CTRL_1000T_FD|MII_MASSLA_CTRL_1000T_HD;
		apm_genericmiiphy_write(priv, priv->phy_addr, MII_MASSLA_CTRL_REG, data);
	}

	/* Enable auto-neg and restart PHY */
	data = MII_CR_AUTO_EN|MII_CR_RESTART;
	apm_genericmiiphy_write(priv, priv->phy_addr, MII_CTRL_REG, data);

	apm_genericmiiphy_read(priv, priv->phy_addr, MII_AN_ADS_REG, &data);
	data &= ~(MII_ANAR_10TX_HD|MII_ANAR_10TX_FD|
			MII_ANAR_100TX_HD|MII_ANAR_100TX_FD);
	data |= anar;
	apm_genericmiiphy_write(priv, priv->phy_addr, MII_AN_ADS_REG, data);

	if (sts & MII_SR_EXT_STS) {
		apm_genericmiiphy_read(priv, priv->phy_addr, MII_MASSLA_CTRL_REG, &data);
		data &= ~(MII_MASSLA_CTRL_1000T_HD|MII_MASSLA_CTRL_1000T_FD);
		data |= ganar;
		apm_genericmiiphy_write(priv, priv->phy_addr, MII_MASSLA_CTRL_REG, data);
	}

	apm_genericmiiphy_read(priv, priv->phy_addr, MII_CTRL_REG, &data);
	data &= ~(MII_CR_FDX|MII_CR_100|MII_CR_AUTO_EN|MII_CR_RESTART|MII_CR_RES_MASK);
	data |= ctl;
	apm_genericmiiphy_write(priv, priv->phy_addr, MII_CTRL_REG, data);
}

int apm_gmac_init(struct apm_data_priv *priv,
		unsigned char *dev_addr, int speed, int mtu, int crc, int reset_mac)
{
	u32 value;
	u32 temp;
	u32 addr_hi;
	u32 addr_lo;

	u32 interface_control;
	u32 mac_config_2;
	u32 rgmii;
	u32 icm_config0;
	u32 icm_config2;
#if !defined(CONFIG_APM862xx)
	u32 ecm_config0;
#endif
	u32 enet_spare_cfg;
	u8 port = priv->port;
	u32 socfreq;
	u32 rgmii_div;

	if (priv->phy_mode != PHY_MODE_RGMII)
		goto _skip_rgmii_clk_init;

	PHY_PRINT("Setting Port%d Link Speed %d Mbps \n", port, speed);
	apm86xxx_read_scu_reg(SCU_SOCDIV4_ADDR, &value);
	__apm86xxx_get_freq(APM86xxx_SOC_PLL_FREQ, &socfreq);

	switch (speed) {
	case SPEED_10:	/* We need a 2.5MHz clock */
		rgmii_div = 400;
		break;
	case SPEED_100: /* We need a 25MHz clock */
		rgmii_div = 40;
		break;
	default:	/* We need a 125Mhz clock */
		rgmii_div = 8;
		break;
	}
	rgmii_div /= (socfreq == 1000000000 ? 1 : 2);
#if defined(CONFIG_APM862xx)
	rgmii_div /= 2;		/* GMvA has one divider less */
#endif
	if (port == 0)
		value = RGMII0_CLK_FREQ_SEL4_SET(value, rgmii_div);
	else
		value = RGMII1_CLK_FREQ_SEL4_SET(value, rgmii_div);

	apm86xxx_write_scu_reg(SCU_SOCDIV4_ADDR, value);
_skip_rgmii_clk_init:

	apm_emac_read32(priv, BLOCK_ETH_GBL,
			ENET_SPARE_CFG_REG_ADDR, &enet_spare_cfg);

	if (speed == SPEED_10) {
		interface_control = LHD_MODE_WR(0) |
			GHD_MODE_WR(0);
		mac_config_2 = FULL_DUPLEX2_WR(1)  |
			LENGTH_CHECK2_WR(0)        |
			HUGE_FRAME_EN2_WR(0)       |
			INTERFACE_MODE2_WR(1)      | /* 10Mbps */
			PAD_CRC2_WR(crc)           |
			CRC_EN2_WR(crc)            |
			PREAMBLE_LENGTH2_WR(7);
#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
		rgmii = CFG_TXCLK_MUXSEL0_WR(4);
#else
		rgmii = 0;
#endif
		icm_config0 = 0x0000503f;
		icm_config2 = 0x000101f4;
#if !defined(CONFIG_APM862xx)
		ecm_config0 = 0x600032;
#endif
#if defined(CONFIG_APM862xx)
		if (port == 0)
			enet_spare_cfg = enet_spare_cfg | (0x0000c040);
		else
			enet_spare_cfg = enet_spare_cfg | (0x00030040);
#endif
	} else if (speed == SPEED_100) {
		interface_control = LHD_MODE_WR(1);
		mac_config_2 = FULL_DUPLEX2_WR(1)  |
			LENGTH_CHECK2_WR(0)        |
			HUGE_FRAME_EN2_WR(0)       |
			INTERFACE_MODE2_WR(1)      | /* 100Mbps */
			PAD_CRC2_WR(crc)           |
			CRC_EN2_WR(crc)            |
			PREAMBLE_LENGTH2_WR(7);
#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
		rgmii = CFG_TXCLK_MUXSEL0_WR(4);
#else
		rgmii = 0;
#endif
		icm_config0 = 0x0004503f;
		icm_config2 = 0x00010050;
#if !defined(CONFIG_APM862xx)
		ecm_config0 = 0x600032;
#endif
#if defined(CONFIG_APM862xx)
		if (port == 0)
			enet_spare_cfg = enet_spare_cfg | (0x0000c040);
		else
			enet_spare_cfg = enet_spare_cfg | (0x00030040);
#endif
	} else {
		interface_control = GHD_MODE_WR(1);
		mac_config_2 = FULL_DUPLEX2_WR(1)  |
			LENGTH_CHECK2_WR(0)        |
			HUGE_FRAME_EN2_WR(0)       |
			INTERFACE_MODE2_WR(2)      | /* 1Gbps */
			PAD_CRC2_WR(crc)           |
			CRC_EN2_WR(crc)            |
			PREAMBLE_LENGTH2_WR(5);
#if defined(CONFIG_APM862xx)
		rgmii = CFG_TXCLK_MUXSEL0_WR(4)    |
			CFG_SPEED_1250_WR(1);
#elif defined(CONFIG_APM867xx)
		if (port == 1)
			rgmii = CFG_TXCLK_MUXSEL0_WR(4)    |
				CFG_SPEED_1250_WR(1);
		else
			rgmii = CFG_SPEED_1250_WR(1);
#elif defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
		if (port == 1) {
#if defined(CONFIG_IE4000)
			rgmii = CFG_TXCLK_MUXSEL0_WR(0)    |
				CFG_SPEED_1250_WR(1) | CFG_RXCLK_MUXSEL0_WR(7);
#else
			rgmii = CFG_TXCLK_MUXSEL0_WR(7)    |
				CFG_SPEED_1250_WR(1) | CFG_RXCLK_MUXSEL0_WR(1);
#endif
		} else {
			rgmii = CFG_TXCLK_MUXSEL0_WR(1) | CFG_SPEED_1250_WR(1);
		}
#endif
		icm_config0 = 0x0008503f;
		icm_config2 = 0x0001000f;
#if !defined(CONFIG_APM862xx)
		ecm_config0 = 0x32;
#endif
#if defined(CONFIG_APM862xx)
		if (port == 0)
			enet_spare_cfg = (enet_spare_cfg & ~0x0000c000) | (0x00000040);
		else
			enet_spare_cfg = (enet_spare_cfg & ~0x00030000) | (0x00000040);
#endif
	}
#if !defined(CONFIG_APM862xx)
	enet_spare_cfg |= 0x00006040;
#endif

	if(reset_mac) {
		/* Reset subsystem */
		value = RESET_TX_FUN1_WR(1) |
			RESET_RX_FUN1_WR(1) |
			RESET_TX_MC1_WR(1)  |
			RESET_RX_MC1_WR(1)  |
			SIM_RESET1_WR(1)    |
			SOFT_RESET1_WR(1);

		ENET_DEBUG("MAC base addresses: 0x%X\n", priv->mac_base_addr_v);
		ENET_DEBUG("Stat base addresses: 0x%X\n",priv->stats_base_addr_v);

		apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, value);
		apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &temp);
		udelay(100);
		apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, 0);
	}

	/* Program the station MAC address */
	addr_hi = *(u32 *) &dev_addr[0];
	addr_lo = *(u16 *) &dev_addr[4];
	addr_lo <<= 16;

        if (priv->phy_mode == PHY_MODE_SGMII)
                addr_lo = (addr_lo & 0xFFFF0100) | 0x1e;
        else
                addr_lo |= (priv->phy_addr & 0xFFFF);

	ENET_DEBUG("MAC addr hi: %x\n", addr_hi);
	apm_emac_write32(priv, BLOCK_ETH_MAC, STATION_ADDR0_ADDR, addr_hi);
	ENET_DEBUG("MAC addr lo: %x\n", addr_lo);
	apm_emac_write32(priv, BLOCK_ETH_MAC, STATION_ADDR1_ADDR, addr_lo);

	/* Initialize the Interface Control Register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, INTERFACE_CONTROL_ADDR,
			interface_control);

	/* Initialize the Maximum Frame Length register */
	value = MAX_FRAME_LEN_WR(mtu);
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAX_FRAME_LEN_ADDR, value);

	/* Initialize the MAC configuration #2 register */
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, mac_config_2);

	/* Initialize the MAC configuration #1 register */
	value = TX_EN1_WR(1)	  |
		RX_EN1_WR(1)	  |
		TX_FLOW_EN1_WR(0) |
#ifdef APM_ENET_MAC_LOOPBACK
		LOOP_BACK1_WR(1)  |
#else
		LOOP_BACK1_WR(0)  |
#endif
		RX_FLOW_EN1_WR(0);
	apm_emac_write32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, value);

	/* Adjust MDC clock frequency */
        apm_enet_rd32(priv, BLOCK_ETH_MAC, MII_MGMT_CONFIG_ADDR, &value);
        value = MGMT_CLOCK_SEL_SET(value, 7);
#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
        value = MGMT_CLOCK_SEL_SET(value, 0);
	value = MDO_AT_NEGEDGE_EN_SET(value, 0);
        value = MDO_AFTER_4MGTCLKS_EN_SET(value, 1);
	value = MDO_AFTER_3MGTCLKS_EN_SET(value, 0);
#endif
        apm_enet_wr32(priv, BLOCK_ETH_MAC, MII_MGMT_CONFIG_ADDR, value);

	if ((port % 2) == 0) { /* For port0 and port2 */
		/* Initialize HdrPrs_Config2_reg_0 */
		value = CFG_IPV4_BYTES0_WR(IPV4_HDR_SIZE) |
			CFG_IPV6_BYTES0_WR(IPV6_HDR_SIZE);
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				HDRPRS_CONFIG2_REG_0_ADDR, value);
		/* Rtype should be copied from FP */
		value = 0;
		apm_emac_write32(priv, BLOCK_ETH_GBL,
				RSIF_RAM_DBG_REG0_ADDR, value);
		/* Enable drop if FP not available */
		apm_emac_read32(priv, BLOCK_ETH_GBL,
				RSIF_CONFIG_REG_ADDR, &value);
#if 1
		value |= CFG_RSIF_FPBUFF_DROP_EN_WR(1);
#endif
		apm_emac_write32(priv, BLOCK_ETH_GBL,
				RSIF_CONFIG_REG_ADDR, value);

		if (priv->phy_mode == PHY_MODE_RGMII) {
			/* Initialize RGMII PHY */
			apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
						RGMII_REG_0_ADDR, rgmii);
		}

		/* Enable HdrParser Timeout */
		value = CFG_PRS_EN_TIMEOUT0_WR(1) |
			CFG_PRS_MAX_HDR_SIZE0_WR(0x80);
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				HDRPRS_CONFIG3_REG_0_ADDR, value);

		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				ICM_CONFIG0_REG_0_ADDR, icm_config0);

		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				ICM_CONFIG2_REG_0_ADDR, icm_config2);

#if !defined(CONFIG_APM862xx)
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				ECM_CONFIG0_REG_0_ADDR, ecm_config0);
#endif

		apm_emac_write32(priv, BLOCK_ETH_GBL,
				ENET_SPARE_CFG_REG_ADDR, enet_spare_cfg);

		/* TCP MSS  */
		apm_emac_read32(priv, BLOCK_ETH_GBL,
				TSIF_MSS_REG0_0_ADDR, &value);
		apm_emac_write32(priv, BLOCK_ETH_GBL,
				 TSIF_MSS_REG0_0_ADDR,
			    CFG_TSIF_MSS_SZ00_SET(value, DEFAULT_TCP_MSS));
		apm_emac_read32(priv, BLOCK_ETH_GBL,
				TSIF_MSS_REG0_0_ADDR, &value);

#if !defined(CONFIG_APM862xx)
		/* Rx-Tx traffic resume */
		apm_emac_write32(priv, BLOCK_ETH_GBL,
				CFG_LINK_AGGR_RESUME_0_ADDR, TX_PORT0_WR(0x1));
#endif
	} else if ((port % 2) == 1) { /* For port1 and port3 */
		/* Initialize HdrPrs_Config2_reg_1 */
		value = CFG_IPV4_BYTES0_WR(IPV4_HDR_SIZE) |
			CFG_IPV6_BYTES0_WR(IPV6_HDR_SIZE);

		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				HDRPRS_CONFIG2_REG_1_ADDR, value);
		/* Rtype should be copied from FP */
		value = 0;
		apm_emac_write32(priv, BLOCK_ETH_GBL,
				RSIF_RAM_DBG_REG0_ADDR, value);
		/* Enable drop if FP not available */
		apm_emac_read32(priv, BLOCK_ETH_GBL,
				RSIF_CONFIG_REG_ADDR, &value);
#if 1
		value |= CFG_RSIF_FPBUFF_DROP_EN_WR(1);
#endif
		apm_emac_write32(priv, BLOCK_ETH_GBL,
				RSIF_CONFIG_REG_ADDR, value);

		if (priv->phy_mode == PHY_MODE_RGMII) {
			/* Initialize RGMII PHY */
			apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
						RGMII_REG_1_ADDR, rgmii);
		}

		/* Enable HdrParser Timeout */
		value = CFG_PRS_EN_TIMEOUT0_WR(1) |
			CFG_PRS_MAX_HDR_SIZE0_WR(0x80);
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				HDRPRS_CONFIG3_REG_1_ADDR, value);

		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				ICM_CONFIG0_REG_1_ADDR, icm_config0);

		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				ICM_CONFIG2_REG_1_ADDR, icm_config2);

#if !defined(CONFIG_APM862xx)
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL,
				ECM_CONFIG0_REG_1_ADDR, ecm_config0);
#endif

		apm_emac_write32(priv, BLOCK_ETH_GBL,
				ENET_SPARE_CFG_REG_ADDR, enet_spare_cfg);

		/* TCP MSS  */
		apm_emac_read32(priv, BLOCK_ETH_GBL,
				TSIF_MSS_REG0_1_ADDR, &value);

		apm_emac_write32(priv, BLOCK_ETH_GBL,
				TSIF_MSS_REG0_1_ADDR,
				CFG_TSIF_MSS_SZ10_SET(value, DEFAULT_TCP_MSS));

		apm_emac_read32(priv, BLOCK_ETH_GBL,
				TSIF_MSS_REG0_1_ADDR, &value);

#if !defined(CONFIG_APM862xx)
		/* Rx-Tx traffic resume */
		apm_emac_write32(priv, BLOCK_ETH_GBL,
				CFG_LINK_AGGR_RESUME_1_ADDR, TX_PORT1_WR(0x1));
#endif
	}

	if (speed != SPEED_10 && speed != SPEED_100) {
		apm_emac_read32(priv, BLOCK_ETH_GBL, DEBUG_REG_ADDR, &value);
		value |= CFG_BYPASS_UNISEC_TX_WR(1) |
			CFG_BYPASS_UNISEC_RX_WR(1);
		apm_emac_write32(priv, BLOCK_ETH_GBL, DEBUG_REG_ADDR, value);
	}

#ifdef PCM_LOOPBACK
	apm_emac_read32(priv, BLOCK_ETH_GBL, DEBUG_REG_ADDR, &value);
	value |= CFG_DEBUG_RXTSOTXBUF_LOOPBACK_WR(1);
	apm_emac_write32(priv, BLOCK_ETH_GBL, DEBUG_REG_ADDR, value);
	apm_gmac_crc_enable(priv, 0);
	apm_gmac_pad_crc_enable(priv, 0);
#endif

#if defined(CONFIG_APM867xx)
	/* Tx QMI gating Off */
	apm_emac_read32(priv, BLOCK_ETH_GBL, CFG_LINK_AGGR_ADDR, &value);
	value |= 0x400;
	apm_emac_write32(priv, BLOCK_ETH_GBL, CFG_LINK_AGGR_ADDR, value);

	apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, RX_DV_GATE_REG_ADDR, &value);
	/* Rx-Tx DV Gate Off */
	if ((port % 2) == 0) {    /* For port0 and port2 */
		value = TX_DV_GATE_EN_PORT0_SET(value, 0);
		value = RX_DV_GATE_EN_PORT0_SET(value, 0);
		value = RESUME_RX_PORT0_SET(value, 1);
	} else {                        /* For port1 and port3 */
		value = TX_DV_GATE_EN_PORT1_SET(value, 0);
		value = RX_DV_GATE_EN_PORT1_SET(value, 0);
		value = RESUME_RX_PORT1_SET(value, 1);
	}
	apm_emac_write32(priv, BLOCK_ETH_MAC_GBL, RX_DV_GATE_REG_ADDR, value);
#elif defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
	/* Tx QMI gating Off */
	apm_emac_read32(priv, BLOCK_ETH_GBL, CFG_LINK_AGGR_ADDR, &value);
	value |= 0x400;
	apm_emac_write32(priv, BLOCK_ETH_GBL, CFG_LINK_AGGR_ADDR, value);

	apm_emac_read32(priv, BLOCK_ETH_GBL, CFG_POLL_SGMII_PHY_ADDR, &value);
	value |= 0x3;
	apm_emac_write32(priv, BLOCK_ETH_GBL, CFG_POLL_SGMII_PHY_ADDR, value);

	/* Rx-Tx DV Gate Off */
	if ((port % 2) == 0) {    /* For port0 and port2 */
		apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, RX_DV_GATE_REG_0_ADDR, &value);
		value = TX_DV_GATE_EN0_SET(value, 0);
		value = RX_DV_GATE_EN0_SET(value, 0);
		value = RESUME_RX0_SET(value, 1);
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL, RX_DV_GATE_REG_0_ADDR, value);
		apm_emac_write32(priv, BLOCK_ETH_GBL, CFG_LINK_AGGR_RESUME_0_ADDR, 0x1);
		apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, CFG_LPBK_GATE_TX_ADDR, &value);
		value &= ~PORT0_F2_MASK;
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL, CFG_LPBK_GATE_TX_ADDR, value);
	} else {                 /* For port1 and port3 */
		apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, RX_DV_GATE_REG_1_ADDR, &value);
		value = TX_DV_GATE_EN1_SET(value, 0);
		value = RX_DV_GATE_EN1_SET(value, 0);
		value = RESUME_RX1_SET(value, 1);
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL, RX_DV_GATE_REG_1_ADDR, value);
		apm_emac_write32(priv, BLOCK_ETH_GBL, CFG_LINK_AGGR_RESUME_0_ADDR, 0x1);
		apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, CFG_LPBK_GATE_TX_ADDR, &value);
		value &= ~PORT1_F2_MASK;
		apm_emac_write32(priv, BLOCK_ETH_MAC_GBL, CFG_LPBK_GATE_TX_ADDR, value);
	}
#endif

#if !defined(CONFIG_APM862xx)
	/* Reset SGMII Port  */
	if (priv->phy_mode == PHY_MODE_SGMII) {
		/* Reset SGMII core */
		/* NOTE: All internal PHY addresses are shifted by 2 bits */
		apm_genericmiiphy_write(priv, INT_PHY_ADDR,
				SGMII_CONTROL_ADDR >> 2, RESET_PHY_MASK);
#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
		/* FIXME: Hack for BlackMamba */
		/* Use non-autoneg for SGMII core to get
		 * Marvel SGMII PHYs working
		 */
		apm_genericmiiphy_write(priv, INT_PHY_ADDR,
				SGMII_CONTROL_ADDR >> 2, 0x0000);
#else
		/* Use autoneg for SGMII core */
		apm_genericmiiphy_write(priv, INT_PHY_ADDR,
				SGMII_CONTROL_ADDR >> 2, ENABLE_AN_MASK);
#endif
		/* Soft-reset SGMII module */
                apm_genericmiiphy_write(priv, INT_PHY_ADDR,
                                SGMII_TBI_CONTROL_ADDR >> 2, 0x0000);

#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
		/* FIXME: Hack for BlackMamba */
		/* Disable auto neg between MAC and fabric phy side and
                   program speed */
		apm_genericmiiphy_write(priv, priv->phy_addr, 22, 1);
		apm_genericmiiphy_read(priv, priv->phy_addr, 22, &value);
		apm_genericmiiphy_read(priv, priv->phy_addr,
				MII_CTRL_REG, &value);
		value &= ~MII_CR_AUTO_EN;	/* Turn off MAC side auto neg */
		value |= MII_CR_FDX;
		switch (speed) {
		case SPEED_10:
			value &= ~(MII_CR_100 | MII_CR_1000);
			break;
		case SPEED_100:
			value &= ~MII_CR_1000;
			value |= MII_CR_100;
			break;
		default:
			value |= MII_CR_1000;
			value &= ~MII_CR_100;
			break;
		}
		apm_genericmiiphy_write(priv, priv->phy_addr,
				MII_CTRL_REG, value);
		apm_genericmiiphy_write(priv, priv->phy_addr, 22, 0);
#endif
	}
#endif
	return 0;
}

/* Start Statistics related functions */

void apm_enet_get_brief_stats(struct apm_data_priv *priv,
				struct eth_brief_stats *brief_stats)
{
	struct eth_detailed_stats detailed_stats;

	apm_enet_get_detailed_stats(priv, &detailed_stats);

	brief_stats->rx_byte_count = detailed_stats.rx_stats.rx_byte_count;
	brief_stats->rx_packet_count = detailed_stats.rx_stats.rx_packet_count;
	brief_stats->rx_drop_pkt_count =
		detailed_stats.rx_stats.rx_drop_pkt_count;
	brief_stats->tx_byte_count = detailed_stats.tx_stats.tx_byte_count;
	brief_stats->tx_pkt_count = detailed_stats.tx_stats.tx_pkt_count;
	brief_stats->tx_drop_frm_count =
		detailed_stats.tx_stats.tx_drop_frm_count;
}

void apm_enet_get_detailed_stats(struct apm_data_priv *priv,
					struct eth_detailed_stats *stats)
{
	apm_enet_get_tx_rx_stats(priv, &(stats->eth_combined_stats));
	apm_enet_get_rx_stats(priv, &(stats->rx_stats));
	apm_enet_get_tx_stats(priv, &(stats->tx_stats));
}

void apm_enet_get_tx_rx_stats(struct apm_data_priv *priv,
					struct eth_frame_stats *tx_rx_stats)
{
	/* Read Stats */
	apm_emac_read32(priv, BLOCK_ETH_STATS, TR64_ADDR,
				 &tx_rx_stats->c_64B_frames);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TR127_ADDR,
				 &tx_rx_stats->c_65_127B_frames);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TR255_ADDR,
				 &tx_rx_stats->c_128_255B_frames);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TR511_ADDR,
				 &tx_rx_stats->c_256_511B_frames);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TR1K_ADDR,
				 &tx_rx_stats->c_512_1023B_frames);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TRMAX_ADDR,
				 &tx_rx_stats->c_1024_1518B_frames);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TRMGV_ADDR,
				 &tx_rx_stats->c_1519_1522B_frames);

	/* Mask out unnecessary bits in all the fields */
	tx_rx_stats->c_64B_frames &= TX_RX_64B_FRAME_CNTR4_MASK;
	tx_rx_stats->c_65_127B_frames &= TX_RX_127B_FRAME_CNTR7_MASK;
	tx_rx_stats->c_128_255B_frames &= TX_RX_255B_FRAME_CNTR5_MASK;
	tx_rx_stats->c_256_511B_frames &= TX_RX_511B_FRAME_CNTR1_MASK;
	tx_rx_stats->c_512_1023B_frames &= TX_RX_1KB_FRAME_CNTR_MASK;
	tx_rx_stats->c_1024_1518B_frames &= TX_RX_MAXB_FRAME_CNTR_MASK;
	tx_rx_stats->c_1519_1522B_frames &= TRMGV_MASK;
}

void apm_enet_get_rx_stats(struct apm_data_priv *priv, struct eth_rx_stat *rx_stat)
{
	/* Read Stats */
	apm_emac_read32(priv, BLOCK_ETH_STATS, RBYT_ADDR,
				 &rx_stat->rx_byte_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RPKT_ADDR,
				 &rx_stat->rx_packet_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RFCS_ADDR,
				 &rx_stat->rx_fcs_err_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RMCA_ADDR,
				 &rx_stat->rx_multicast_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RBCA_ADDR,
				 &rx_stat->rx_broadcast_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RXCF_ADDR,
				 &rx_stat->rx_cntrl_frame_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RXPF_ADDR,
				 &rx_stat->rx_pause_frame_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RXUO_ADDR,
				 &rx_stat->rx_unknown_op_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RALN_ADDR,
				 &rx_stat->rx_alignment_err_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RFLR_ADDR,
				 &rx_stat->rx_frm_len_err_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RCDE_ADDR,
				 &rx_stat->rx_code_err_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RCSE_ADDR,
				 &rx_stat->rx_carrier_sense_err_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RUND_ADDR,
				 &rx_stat->rx_undersize_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, ROVR_ADDR,
				 &rx_stat->rx_oversize_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RFRG_ADDR,
				 &rx_stat->rx_fragment_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RJBR_ADDR,
				 &rx_stat->rx_jabber_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, RDRP_ADDR,
				 &rx_stat->rx_drop_pkt_count);

	/* Mask out unnecessary bits in all the fields */
	rx_stat->rx_byte_count &= RX_BYTE_CNTR_MASK;
	rx_stat->rx_packet_count &= RX_PKT_CNTR_MASK;
	rx_stat->rx_fcs_err_count &= RX_FCS_ERROR_CNTR_MASK;
	rx_stat->rx_multicast_pkt_count &= RX_MC_PKT_CNTR_MASK;
	rx_stat->rx_broadcast_pkt_count &= RX_BC_PKT_CNTR_MASK;
	rx_stat->rx_cntrl_frame_pkt_count &= RX_CTRL_PKT_CNTR_MASK;
	rx_stat->rx_pause_frame_pkt_count &= RX_PAUSE_PKT_CNTR_MASK;
	rx_stat->rx_unknown_op_pkt_count &= RX_UNK_OPCODE_CNTR_MASK;
	rx_stat->rx_alignment_err_pkt_count &= RX_ALIGN_ERR_CNTR_MASK;
	rx_stat->rx_frm_len_err_pkt_count &= RX_LEN_ERR_CNTR_MASK;
	rx_stat->rx_code_err_pkt_count &= RX_CODE_ERR_CNTR_MASK;
	rx_stat->rx_carrier_sense_err_pkt_count &= RX_FALSE_CARRIER_CNTR_MASK;
	rx_stat->rx_undersize_pkt_count &= RX_UNDRSIZE_PKT_CNTR_MASK;
	rx_stat->rx_oversize_pkt_count &= RX_OVRSIZE_PKT_CNTR_MASK;
	rx_stat->rx_fragment_count &= RX_FRAG_CNTR_MASK;
	rx_stat->rx_jabber_count &= RX_JABBER_CNTR_MASK;
	rx_stat->rx_drop_pkt_count &= RX_DROPPED_PKT_CNTR_MASK;
}

void apm_enet_get_tx_stats(struct apm_data_priv *priv,
			struct eth_tx_stats *tx_stats)
{
	/* Read Stats */
	apm_emac_read32(priv, BLOCK_ETH_STATS, TBYT_ADDR,
				 &tx_stats->tx_byte_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TPKT_ADDR,
				 &tx_stats->tx_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TMCA_ADDR,
				 &tx_stats->tx_multicast_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TBCA_ADDR,
				 &tx_stats->tx_broadcast_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TXPF_ADDR,
				 &tx_stats->tx_pause_frame_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TDFR_ADDR,
				 &tx_stats->tx_deferral_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TEDF_ADDR,
				 &tx_stats->tx_exesiv_def_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TSCL_ADDR,
				 &tx_stats->tx_single_coll_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TMCL_ADDR,
				 &tx_stats->tx_multi_coll_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TLCL_ADDR,
				 &tx_stats->tx_late_coll_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TXCL_ADDR,
				 &tx_stats->tx_exesiv_coll_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TNCL_ADDR,
				 &tx_stats->tx_toll_coll_pkt_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TPFH_ADDR,
				 &tx_stats->tx_pause_frm_hon_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TDRP_ADDR,
				 &tx_stats->tx_drop_frm_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TJBR_ADDR,
				 &tx_stats->tx_jabber_frm_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TFCS_ADDR,
				 &tx_stats->tx_fcs_err_frm_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TXCF_ADDR,
				 &tx_stats->tx_control_frm_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TOVR_ADDR,
				 &tx_stats->tx_oversize_frm_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TUND_ADDR,
				 &tx_stats->tx_undersize_frm_count);
	apm_emac_read32(priv, BLOCK_ETH_STATS, TFRG_ADDR,
				 &tx_stats->tx_fragments_frm_count);

	/* Mask values with appropriate width of the fields */
	tx_stats->tx_byte_count &= TX_BYTE_CNTR_MASK;
	tx_stats->tx_pkt_count &= TX_PKT_CNTR_MASK;
	tx_stats->tx_multicast_pkt_count &= TX_MC_PKT_CNTR_MASK;
	tx_stats->tx_broadcast_pkt_count &= TX_BC_PKT_CNTR_MASK;
	tx_stats->tx_pause_frame_count &= TX_PAUSE_PKT_CNTR_MASK;
	tx_stats->tx_deferral_pkt_count &= TX_DEFER_PKT_CNTR_MASK;
	tx_stats->tx_exesiv_def_pkt_count &= TX_EXC_DEFER_PKT_CNTR_MASK;
	tx_stats->tx_single_coll_pkt_count &= TX_COL_PKT_CNTR_MASK;
	tx_stats->tx_multi_coll_pkt_count &= TX_MUL_COL_PKT_CNTR_MASK;
	tx_stats->tx_late_coll_pkt_count &= TX_LATE_COL_PKT_CNTR_MASK;
	tx_stats->tx_exesiv_coll_pkt_count &= TX_EXC_COL_PKT_CNTR_MASK;
	tx_stats->tx_toll_coll_pkt_count &= TX_TOTAL_COL_CNTR_MASK;
	tx_stats->tx_pause_frm_hon_count &= TX_PAUSE_FRAME_CNTR_MASK;
	tx_stats->tx_drop_frm_count &= TX_DROP_FRAME_CNTR_MASK;
	tx_stats->tx_jabber_frm_count &= TX_JABBER_FRAME_CNTR_MASK;
	tx_stats->tx_fcs_err_frm_count &= TX_FCS_ERROR_CNTR_MASK;
	tx_stats->tx_control_frm_count &= TX_CTRL_FRAME_CNTR_MASK;
	tx_stats->tx_oversize_frm_count &= TX_OVRSIZE_FRAME_CNTR_MASK;
	tx_stats->tx_undersize_frm_count &= TX_UNDSIZE_FRAME_CNTR_MASK;
	tx_stats->tx_fragments_frm_count &= TX_FRAG_CNTR_MASK;
}

int apm_enet_change_mss(struct apm_data_priv *priv, int mss)
{
	u32 value;
	u32 offset;

	offset = (priv->port % 2) * 4; /* Select register for this port */
	offset += TSIF_MSS_REG0_0_ADDR;

	apm_enet_rd32(priv, BLOCK_ETH_GBL, offset, &value);
	value = CFG_TSIF_MSS_SZ00_SET(value, mss);
	apm_enet_wr32(priv, BLOCK_ETH_GBL, offset, value);
	return 0;
}
