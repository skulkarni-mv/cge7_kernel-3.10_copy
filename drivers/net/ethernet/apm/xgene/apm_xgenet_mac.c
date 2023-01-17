/**
 * AppliedMicro APM88xxxx Ethernet Driver
 *
 * Copyright (c) 2013 Applied Micro Circuits Corporation.
 * All rights reserved. Iyappan Subramanian <isubramanian@apm.com>
 *                      Ravi Patel <rapatel@apm.com>
 *                      Fushen Chen <fchen@apm.com>
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
 * @file apm_xgenet_mac.c
 *
 * This file implements driver for XGMII and statistics blocks of
 * APM88xxxx Ethernet subsystem
 *
 */

#include "apm_enet_access.h"
#include "apm_xgenet_mac.h"
#include "apm_xgenet_csr.h"

#define ENET_INTERFACE_MODE2_SET REGSPEC_INTERFACE_MODE2_SET /* same */
#define ENET_INTERFACE_MODE2_RD REGSPEC_INTERFACE_MODE2_RD /* same */
#define ENET_LHD_MODE_WR REGSPEC_LHD_MODE_WR /* same */
#define ENET_GHD_MODE_WR REGSPEC_GHD_MODE_WR
#define ENET_INTERFACE_MODE2_WR REGSPEC_INTERFACE_MODE2_WR

#ifdef CONFIG_STORM_VHP
#define COUNT_FOR_TIMEOUT 5
#else
#define COUNT_FOR_TIMEOUT 10000
#endif

static void apm_xgmac_rx_enable(struct apm_enet_priv *priv)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_XGMII) {
		apm_enet_read(priv, BLOCK_AXG_MAC, AXGMAC_CONFIG_1_ADDR, &data);
		apm_enet_write(priv, BLOCK_AXG_MAC,
				AXGMAC_CONFIG_1_ADDR, HSTRFEN1_SET(data, 1));

		apm_enet_read(priv, BLOCK_AXG_MAC_CSR,
				XGENET_RX_DV_GATE_REG_0_ADDR, &data);
		data = TX_DV_GATE_EN0_SET(data, 0);
		data = RX_DV_GATE_EN0_SET(data, 0);
		apm_enet_write(priv, BLOCK_AXG_MAC_CSR,
				XGENET_RX_DV_GATE_REG_0_ADDR, data);
	} else {
		apm_enet_read(priv, BLOCK_MCX_MAC,
				MAC_CONFIG_1_ADDR, &data);
		apm_enet_write(priv, BLOCK_MCX_MAC,
				MAC_CONFIG_1_ADDR, RX_EN1_SET(data, 1));
	}
}

static void apm_xgmac_rx_disable(struct apm_enet_priv *priv)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_XGMII) {
		apm_enet_read(priv, BLOCK_AXG_MAC_CSR,
				XGENET_RX_DV_GATE_REG_0_ADDR, &data);
		data = TX_DV_GATE_EN0_SET(data, 1);
		data = RX_DV_GATE_EN0_SET(data, 1);
		apm_enet_write(priv, BLOCK_AXG_MAC_CSR,
				XGENET_RX_DV_GATE_REG_0_ADDR, data);

		apm_enet_read(priv, BLOCK_AXG_MAC, AXGMAC_CONFIG_1_ADDR, &data);
		apm_enet_write(priv, BLOCK_AXG_MAC,
				AXGMAC_CONFIG_1_ADDR, HSTRFEN1_SET(data, 0));
	} else {
		apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_1_ADDR, &data);
		apm_enet_write(priv, BLOCK_MCX_MAC,
				MAC_CONFIG_1_ADDR, RX_EN1_SET(data, 0));
	}
}

static void apm_xgmac_tx_enable(struct apm_enet_priv *priv)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_XGMII) {
		apm_enet_read(priv, BLOCK_AXG_MAC, AXGMAC_CONFIG_1_ADDR, &data);
		apm_enet_write(priv, BLOCK_AXG_MAC,
				AXGMAC_CONFIG_1_ADDR, HSTTFEN1_SET(data, 1));
	} else {
		apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_1_ADDR, &data);
		apm_enet_write(priv, BLOCK_MCX_MAC,
				MAC_CONFIG_1_ADDR, TX_EN1_SET(data, 1));
	}
}

static void apm_xgmac_tx_disable(struct apm_enet_priv *priv)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_XGMII) {
		apm_enet_read(priv, BLOCK_AXG_MAC, AXGMAC_CONFIG_1_ADDR, &data);
		apm_enet_write(priv, BLOCK_AXG_MAC,
				AXGMAC_CONFIG_1_ADDR, HSTTFEN1_SET(data, 1));
	} else {
		apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_1_ADDR, &data);
		apm_enet_write(priv, BLOCK_MCX_MAC,
				MAC_CONFIG_1_ADDR, TX_EN1_SET(data, 0));
	}
}

static int apm_xgmac_link_status(struct apm_enet_priv *priv)
{
	u32 data, speed;

	if (!priv->mac_to_mac) {
		if (!priv->phyless) {
			apm_enet_read(priv, BLOCK_ETH_CSR, LINK_STATUS_ADDR, &data);
			priv->link_status = PORT_RD(data);
		} else {
			priv->link_status = 1;
		}
		if (!priv->link_status) {
			priv->speed = APM_ENET_SPEED_0;
			if (priv->phy_mode == PHY_MODE_XGMII) {
				apm_enet_write(priv, BLOCK_XGENET_PCS,
					PCS_CONTROL_1_ADDR, 0x8000 |
					PCS_CONTROL_1_DEFAULT);
				apm_enet_write(priv, BLOCK_XGENET_PCS,
					PCS_CONTROL_1_ADDR,
					PCS_CONTROL_1_DEFAULT);
			}
			PHY_PRINT("Port%d is down\n", priv->port);
			return 0;
		}
		if (priv->phy_mode == PHY_MODE_XGMII) {
			priv->speed = APM_ENET_SPEED_10000;
		} else {
			/* Get the final speed information from SGMII */
			apm_genericmiiphy_read(priv, INT_PHY_ADDR,
				SGMII_AN_SGMII_PARTNER_BASE_PAGE_ABILITY_ADDR >> 2, &data);
			speed = LINK_SPEED_F1_RD(data);
			switch(speed) {
			case PHY_SPEED_10:
				speed = APM_ENET_SPEED_10;
				break;
			case PHY_SPEED_100:
				speed = APM_ENET_SPEED_100;
				break;
			default:
				speed = APM_ENET_SPEED_1000;
				break;
			}
			PHY_PRINT("Phy Speed is :%d \n", speed);
			priv->speed = speed;
		}
	} else {
		priv->link_status = 1;
		priv->speed = priv->desired_speed;
	}
	return 1;
}

static void xgenet_config_qmi_assoc(struct apm_enet_priv *priv)
{
	/* Configure Ethernet QMI: WQ and FPQ association, QM_SOC for now */
	switch (priv->port) {
	case XGENET_0:
	case XGENET_1:
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIWQASSOC_ADDR, 0x0);
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIFPQASSOC_ADDR, 0x0);
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIQMLITEFPQASSOC_ADDR, 0x0);
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIQMLITEWQASSOC_ADDR, 0x0);
		break;
	case XGENET_2:
	case XGENET_3:
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIWQASSOC_ADDR, 0x0);
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIFPQASSOC_ADDR, 0x0);
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIQMLITEFPQASSOC_ADDR,
					0xffffffff);
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIQMLITEWQASSOC_ADDR,
					0xffffffff);
		apm_enet_write(priv, BLOCK_ETH_QMI, REGSPEC_CFGSSQMIQMHOLD_ADDR,
					REGSPEC_QMLITE_HOLD_EN_WR(1));
		break;
	default:
		break;
	}
}

void apm_xgmac_set_preamble_length(struct apm_enet_priv *priv, u8 length)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_SGMII) {
		apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR, &data);
		apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR,
				PREAMBLE_LENGTH2_SET(data, length));
	}
}

void apm_xgmac_set_intf_mode(struct apm_enet_priv *priv, u8 intf_mode)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_SGMII) {
		apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR, &data);
		apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR,
				ENET_INTERFACE_MODE2_SET(data, intf_mode));
	}
}

int apm_xgmac_get_intf_mode(struct apm_enet_priv *priv)
{
	u32 data = 0;

	if (priv->phy_mode == PHY_MODE_SGMII) {
		apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR, &data);
		data = ENET_INTERFACE_MODE2_RD(data);
	}

	return data;
}

void apm_xgmac_huge_frame_enable(struct apm_enet_priv *priv, u8 enable)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_SGMII) {
		apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR, &data);

		if (enable)
			data |= HUGE_FRAME_EN2_MASK;
		else
			data &= ~HUGE_FRAME_EN2_MASK;

		apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR, data);
	}
}

void apm_xgmac_len_field_check_enable(struct apm_enet_priv *priv, u8 enable)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_SGMII) {
		apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR, &data);

		if (enable)
			data |= LENGTH_CHECK2_MASK;
		else
			data &= ~LENGTH_CHECK2_MASK;

		apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR, data);
	}
}

static void module_xgenet_config_sgmii_autoneg(struct apm_enet_priv *priv, int autoneg)
{
	u32 data, speed;

	/* All internal PHY addresses are shifted by 2 bits */
	ENET_DEBUG("%s autoneg=%d\n", __func__, autoneg);
	apm_genericmiiphy_write(priv, INT_PHY_ADDR,
			SGMII_TBI_CONTROL_ADDR >> 2, 0x0);
	apm_genericmiiphy_read(priv, INT_PHY_ADDR,
			SGMII_TBI_CONTROL_ADDR >> 2, &data);
	if (!priv->mac_to_mac) {
		if (autoneg) {
			/* Bring PHY out of reset; Enable An, autonegotiation */
			PHY_PRINT(" Bring PHY out of reset; Enable An\n");
			apm_genericmiiphy_write(priv, INT_PHY_ADDR,
					SGMII_CONTROL_ADDR >> 2, 0x9140);
		}
		else {
			/* Bring PHY out of reset; No autonegotiation */
			PHY_PRINT(" Bring PHY out of reset; NO An\n");
			apm_genericmiiphy_write(priv, INT_PHY_ADDR,
					SGMII_CONTROL_ADDR >> 2, 0x8000);
		}
		udelay(1000);
		if (autoneg) {
			int loop = 50;

			/* Check autonegotiation status */
			apm_genericmiiphy_read(priv, INT_PHY_ADDR,
					SGMII_STATUS_ADDR >> 2, &data);
			PHY_PRINT(" autonegotiation status=0x%x\n", data);
			while  (AUTO_NEGOTIATION_COMPLETE_RD(data) == 0 ||
					LINK_STATUS_RD(data) == 0) {
				PHY_PRINT(" Autonegotiation status=0x%x\n", data);
				apm_genericmiiphy_read(priv, INT_PHY_ADDR,
						SGMII_STATUS_ADDR >> 2, &data);
				if (loop-- == 0)
					break;
				udelay(100);
				PHY_PRINT(" Autonegotiation status=0x%x %s\n", data, __func__);
			}
		} else {
			PHY_PRINT(" %s non-autoneg NOT supported\n", __func__);
		}
		if (!priv->phyless) {
			apm_enet_read(priv, BLOCK_ETH_CSR, LINK_STATUS_ADDR, &data);
			priv->link_status = PORT_RD(data);
		} else
			priv->link_status = 1;
		/* Get the final speed information from SGMII */
		apm_genericmiiphy_read(priv, INT_PHY_ADDR,
				SGMII_AN_SGMII_PARTNER_BASE_PAGE_ABILITY_ADDR >> 2, &data);
		speed = LINK_SPEED_F1_RD(data);
	} else {
		speed = priv->desired_speed;
		priv->link_status = 1;
	}

	switch(speed) {
	case PHY_SPEED_10:
		speed = APM_ENET_SPEED_10;
		break;
	case PHY_SPEED_100:
		speed = APM_ENET_SPEED_100;
		break;
	default:
		speed = APM_ENET_SPEED_1000;
		break;
	}

	if (priv->link_status)
		PHY_PRINT("Phy Speed is :%d \n", speed);
	else
		PHY_PRINT("Port%d is down\n", priv->port);

	priv->speed = speed;
}

static int apm_mcxmac_init(struct apm_enet_priv *priv,
		unsigned char *dev_addr, int speed, int crc)
{
	u32 value;
	u32 temp;
	u32 addr_hi;
	u32 addr_lo;

	u32 interface_control;
	u32 mac_config_2;
	u32 icm_config0 = 0x0008503f;
	u32 ecm_config0 = 0x00000032;
	u32 enet_spare_cfg = 0x00006040;

	ENET_DEBUG("%s priv->phy_mode=0x%x\n", __func__, priv->phy_mode);

	/*sm_xgenet_module_level_eee_init(priv); */
	value = RESET_TX_FUN1_WR(1) |
		RESET_RX_FUN1_WR(1) |
		RESET_TX_MC1_WR(1)  |
		RESET_RX_MC1_WR(1)  |
		SIM_RESET1_WR(1)    |
		SOFT_RESET1_WR(1);
	apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_1_ADDR, value);
	apm_enet_read(priv, BLOCK_MCX_MAC, MAC_CONFIG_1_ADDR, &temp);
	udelay(1);
	apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_1_ADDR, 0);

	/* Initialize the MAC configuration #1 register */
	value = TX_EN1_WR(1)	  |
		TX_FLOW_EN1_WR(0) |
		LOOP_BACK1_WR(0)  |
		RX_FLOW_EN1_WR(0);

	/* Need this? rd_phy_reg_per_port(port_id,0x1e,M_SGMII_SGMII_TBI_CONTROL__ADDR,&data); */

	apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_1_ADDR, value);

#ifdef APM_ENET_SERDES_LOOPBACK
	module_xgenet_config_sgmii_autoneg(priv, 0);
#else
	if (!priv->mac_to_mac) {
		if (priv->autoneg_set) {
			if (!priv->link_status || priv->phyless)
				module_xgenet_config_sgmii_autoneg(priv, 1);
		}
	} else {
		module_xgenet_config_sgmii_autoneg(priv, 0);
	}
#endif
	/* SGMII follows */
	apm_enet_read(priv, BLOCK_ETH_CSR,
			ENET_SPARE_CFG_REG_ADDR, &enet_spare_cfg);

	if (speed == APM_ENET_SPEED_10) {
		interface_control = ENET_LHD_MODE_WR(0) |
			ENET_GHD_MODE_WR(0);
		mac_config_2 = FULL_DUPLEX2_WR(1)  |
			LENGTH_CHECK2_WR(0)        |
			HUGE_FRAME_EN2_WR(0)       |
			ENET_INTERFACE_MODE2_WR(1) | /* 10Mbps */
			PAD_CRC2_WR(crc)           |
			CRC_EN2_WR(crc)            |
			PREAMBLE_LENGTH2_WR(7);
		icm_config0 = 0x0000503f;
		ecm_config0 = 0x600032;
	} else if (speed == APM_ENET_SPEED_100) {
		interface_control = ENET_LHD_MODE_WR(1);
		mac_config_2 = FULL_DUPLEX2_WR(1)  |
			LENGTH_CHECK2_WR(0)        |
			HUGE_FRAME_EN2_WR(0)       |
			ENET_INTERFACE_MODE2_WR(1) | /* 100Mbps */
			PAD_CRC2_WR(crc)           |
			CRC_EN2_WR(crc)            |
			PREAMBLE_LENGTH2_WR(7);
		icm_config0 = 0x0004503f;
		ecm_config0 = 0x600032;
	} else {
		interface_control = ENET_GHD_MODE_WR(1);
		mac_config_2 = FULL_DUPLEX2_WR(1)  |
			LENGTH_CHECK2_WR(0)        |
			HUGE_FRAME_EN2_WR(0)       |
			ENET_INTERFACE_MODE2_WR(2) | /* 1Gbps */
			PAD_CRC2_WR(crc)           |
			CRC_EN2_WR(crc)            |
			PREAMBLE_LENGTH2_WR(7);

		icm_config0 = 0x0008503f;
		ecm_config0 = 0x32;
	}
	enet_spare_cfg |= 0x00006040;

	/* Initialize the MAC configuration #2 register */
	apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_2_ADDR, mac_config_2);

	/* Initialize the Interface Control Register */
	//interface_control = 0x74521808;
	apm_enet_write(priv, BLOCK_MCX_MAC, INTERFACE_CONTROL_ADDR,
			interface_control);

	/* Initialize the Maximum Frame Length register */
	value = MAX_FRAME_LEN_WR(APM_ENET_FRAME_LEN);
	apm_enet_write(priv, BLOCK_MCX_MAC, MAX_FRAME_LEN_ADDR, value);

	/* Program the station MAC address */
	addr_hi = *(u32 *) &dev_addr[0];
	addr_lo = *(u16 *) &dev_addr[4];
	addr_lo <<= 16;

	if (priv->phy_mode == PHY_MODE_SGMII)
		addr_lo = (addr_lo & 0xFFFF0100) | 0x1e;
	else
		addr_lo |= (priv->phy_addr & 0xFFFF);

	ENET_DEBUG("MAC addr hi: %x\n", addr_hi);
	apm_enet_write(priv, BLOCK_MCX_MAC, STATION_ADDR0_ADDR, addr_hi);
	ENET_DEBUG("MAC addr lo: %x\n", addr_lo);
	apm_enet_write(priv, BLOCK_MCX_MAC, STATION_ADDR1_ADDR, addr_lo);

	/* Rtype should be copied from FP */
	value = 0;
	apm_enet_write(priv, BLOCK_ETH_CSR,
			RSIF_RAM_DBG_REG0_ADDR, value);

	apm_enet_write(priv, BLOCK_MCX_MAC_CSR,
			ICM_CONFIG0_REG_0_ADDR, icm_config0);

	apm_enet_write(priv, BLOCK_MCX_MAC_CSR,
			ECM_CONFIG0_REG_0_ADDR, ecm_config0);

	/* TCP MSS  */
	apm_enet_read(priv, BLOCK_ETH_CSR,
			TSIF_MSS_REG0_0_ADDR, &value);

	apm_enet_write(priv, BLOCK_ETH_CSR, TSIF_MSS_REG0_0_ADDR,
			CFG_TSIF_MSS_SZ00_SET(value, DEFAULT_TCP_MSS));

	apm_enet_read(priv, BLOCK_ETH_CSR,
			TSIF_MSS_REG0_0_ADDR, &value);

	if (speed != APM_ENET_SPEED_10 && speed != APM_ENET_SPEED_100) {
		apm_enet_read(priv, BLOCK_ETH_CSR, DEBUG_REG_ADDR, &value);
		value |= CFG_BYPASS_UNISEC_TX_WR(1) |
			CFG_BYPASS_UNISEC_RX_WR(1);
		apm_enet_write(priv, BLOCK_ETH_CSR, DEBUG_REG_ADDR, value);
	}
	apm_enet_read(priv, BLOCK_MCX_STATS, TBYT_ADDR, &value);
	ENET_DEBUG("XG MCX TBYT register: %x\n", value);
	apm_enet_read(priv, BLOCK_MCX_STATS, RBYT_ADDR, &value);
	ENET_DEBUG("XG MCX RBYT register: %x\n", value);
	return 0;
}

static void apm_xg_select_mode(struct apm_enet_priv *priv)
{
	if (priv->phy_mode == PHY_MODE_SGMII)
		apm_enet_write(priv, BLOCK_ETH_CLKRST_CSR, XGENET_CONFIG_REG_ADDR, 0x1);
	else
		/* XGMII mode, CLE clock same as AXI clock, 250 MHz */
		apm_enet_write(priv, BLOCK_ETH_CLKRST_CSR, XGENET_CONFIG_REG_ADDR, 0x02);
}

static void apm_xg_init_ecc(struct apm_enet_priv *priv)
{
	u32 wrdata, rddata;
	int i;

	ENET_DEBUG ("XG Waking up RAM\n");

	wrdata = 0;
	apm_enet_write( priv, BLOCK_ETH_DIAG_CSR, REGSPEC_CFG_MEM_RAM_SHUTDOWN_ADDR, wrdata);

	apm_enet_read( priv, BLOCK_ETH_DIAG_CSR, REGSPEC_BLOCK_MEM_RDY_ADDR, &rddata);
	while (REGSPEC_MEM_RDY_RD(rddata) != REGSPEC_BLOCK_MEM_RDY_DEFAULT) {
		apm_enet_read( priv, BLOCK_ETH_DIAG_CSR, REGSPEC_BLOCK_MEM_RDY_ADDR, &rddata);
	}

	for (i = 0 ; i < 5 ; i++)
		apm_enet_read( priv, BLOCK_ETH_DIAG_CSR, REGSPEC_BLOCK_MEM_RDY_ADDR, &rddata);
}

static void apm_xg_clk_rst_cfg(struct apm_enet_priv *priv)
{
	u32 wrdata;
	ENET_DEBUG ("XG CLK_RST configuration\n");

	wrdata = XGENET_RESET_WR(1) | CSR_RESET_WR(1);
	apm_enet_write( priv, BLOCK_ETH_CLKRST_CSR, XGENET_SRST_ADDR, wrdata );
	mdelay(10);

	apm_enet_write( priv, BLOCK_ETH_CLKRST_CSR, XGENET_CLKEN_ADDR, 0);
	mdelay(10);

	apm_xg_select_mode(priv);
	wrdata = CSR_CLKEN_WR(1)
		| XGENET_CLKEN_WR(1);
	apm_enet_write( priv, BLOCK_ETH_CLKRST_CSR, XGENET_CLKEN_ADDR, wrdata );
	udelay(1000);

	wrdata = XGENET_RESET_WR(1) | CSR_RESET_WR(1);
	apm_enet_write( priv, BLOCK_ETH_CLKRST_CSR, XGENET_SRST_ADDR, wrdata );
	udelay(10);

	wrdata = XGENET_RESET_WR(1) | CSR_RESET_WR(0);
	apm_enet_write( priv, BLOCK_ETH_CLKRST_CSR, XGENET_SRST_ADDR, wrdata );
	udelay(10);

	apm_enet_write( priv, BLOCK_XGENET_PCS , XGBASER_CONFIG_REG1_ADDR, 0 );

	wrdata = XGENET_RESET_WR(0) | CSR_RESET_WR(0);
	apm_enet_write( priv, BLOCK_ETH_CLKRST_CSR, XGENET_SRST_ADDR, wrdata );
	udelay(400);

	apm_xg_init_ecc( priv );
}

/* 10GBaseR TX to RX loopback */
static void apm_xg_loopback_cfg( struct apm_enet_priv *priv )
{
#ifdef APM_XG_AXGMAC_TX2RX_LOOPBACK
	u32 wrdata;
	ENET_DEBUG ("XG loopback (TX to RX) configuration\n");

	wrdata = CFG_XGBASER_TX2RX_LOOPBACK1_WR(1);
	apm_enet_write( priv, BLOCK_XGENET_PCS , XGBASER_CONFIG_REG1_ADDR, wrdata );

#endif

#ifdef APM_XGENET_XGMII_TX2RX_LOOPBACK
	u32 wrdata;
	ENET_DEBUG ("XG XGMII loopback (TX to RX) configuration\n");

	wrdata = CFG_I_TX_SER_LPBK0_WR(1);
	apm_enet_write( priv, BLOCK_ETH_SDS_CSR , XGENET_SDS_CTL0_ADDR, wrdata );
#endif
}

void apm_xgmac_reset(struct apm_enet_priv *priv)
{
	u32 data;

	if (priv->phy_mode == PHY_MODE_XGMII) {
		ENET_DEBUG ("XG reset AXGMAC\n");

		data = 0xe601;
		apm_enet_write(priv, BLOCK_AXG_MAC, AXGMAC_CONFIG_0_ADDR, data);
		udelay(1);

		ENET_DEBUG ("XG deassert AXGMAC reset\n");
		data = 0x0;
		apm_enet_write(priv, BLOCK_AXG_MAC, AXGMAC_CONFIG_0_ADDR, data);
		udelay(5);
	} else {
		data = (RESET_RX_MC1_MASK   |
				RESET_RX_FUN1_MASK  |
				RESET_TX_MC1_MASK   |
				RESET_TX_FUN1_MASK  |
				SIM_RESET1_MASK     |
				SOFT_RESET1_MASK);

		apm_enet_write(priv, BLOCK_MCX_MAC, MAC_CONFIG_1_ADDR, data);
	}
	apm_xg_loopback_cfg( priv );
}

static int apm_axgmac_init (struct apm_enet_priv *priv,
		unsigned char *dev_addr, int speed, int crc)
{
	u32 wrdata, data;
	u32 addr_hi, addr_lo;

	ENET_DEBUG("XG Initialize XG MAC\n");

	apm_xgmac_reset(priv);

	ENET_DEBUG ("XG configure AXGMAC\n");
	data = (HSTTCTLEN1_WR(1)
			| HSTTFEN1_WR(1)
			| HSTRCTLEN1_WR(1)
			| HSTRFEN1_WR(1)
#if !defined(BOOTLOADER)
			| HSTPPEN1_WR(1)
#endif
			| HSTLENCHK1_WR(1));
	if (crc)
		data |= (HSTGENFCS1_WR(1) | REGSPEC_HSTPADMODE1_WR(1));
	data = HSTDRPLT641_SET(data, 0);
	ENET_DEBUG ("XG AXGMAC config_1: %x\n", data);

	apm_enet_write( priv, BLOCK_AXG_MAC, AXGMAC_CONFIG_1_ADDR, data );
	udelay(1);

	wrdata = HSTMXFRMWCTX_WR(APM_ENET_FRAME_LEN)
		| HSTMXFRMBCRX_WR(APM_ENET_FRAME_LEN);
	apm_enet_write( priv, BLOCK_AXG_MAC, AXGMAC_MAXFRAME_LENGTH_ADDR, wrdata );
	apm_enet_read( priv, BLOCK_AXG_MAC, AXGMAC_MAXFRAME_LENGTH_ADDR, &data );
	ENET_DEBUG ("XG AXGMAC maxframe length: %x\n", data);

	addr_hi = *(u32 *) &dev_addr[0];
	addr_lo = *(u16 *) &dev_addr[4];
	ENET_DEBUG ("XG devaddr: %s\n", dev_addr);
	addr_lo <<= 16;
	apm_enet_write( priv, BLOCK_AXG_MAC, AXGMAC_HSTMACADR_LSW_ADDR, addr_hi );
	apm_enet_write( priv, BLOCK_AXG_MAC, AXGMAC_HSTMACADR_MSW_ADDR, addr_lo );

	apm_enet_read( priv, BLOCK_AXG_STATS, TBYT_ADDR, &data );
	ENET_DEBUG("XG TBYT register: %x\n", data);
	apm_enet_read( priv, BLOCK_AXG_STATS, RBYT_ADDR, &data );
	ENET_DEBUG("XG RBYT register: %x\n", data);

	return 0;
}


static void apm_xg_bypass_resume_cfg(struct apm_enet_priv *priv)
{
	u32 wrdata;
	ENET_DEBUG ("XG bypass resume configuration\n");

	wrdata = RESUME_TX_WR(1);
	apm_enet_write( priv, BLOCK_ETH_CSR, CFG_BYPASS_ADDR, wrdata);

	if (priv->phy_mode == PHY_MODE_SGMII)
		wrdata = 0x1;
	else
		wrdata = 0x0;
	apm_enet_write( priv, BLOCK_ETH_CSR, CFG_LINK_STS_ADDR, wrdata);

	wrdata = TX_PORT0_WR(1);
	apm_enet_write( priv, BLOCK_ETH_CSR, CFG_LINK_AGGR_RESUME_0_ADDR, wrdata);

	//wrdata = ENET_MPA_IDLE_WITH_QMI_EMPTY_WR(1);
	wrdata = 0x22407040;
	apm_enet_write( priv, BLOCK_ETH_CSR, ENET_SPARE_CFG_REG_ADDR, wrdata);

	if (priv->phy_mode == PHY_MODE_SGMII) {
		wrdata = 0x6; /* default value */
		wrdata = TX_DV_GATE_EN0_F2_SET(wrdata, 0);
		wrdata = RX_DV_GATE_EN0_F2_SET(wrdata, 0);
		wrdata = RESUME_RX0_F2_SET(wrdata, 1);
		ENET_DEBUG ("%s XGENET_RX_DV_GATE_REG_0_ADDR=0x%x\n", __func__,wrdata);
		apm_enet_write(priv, BLOCK_MCX_MAC_CSR,
				RX_DV_GATE_REG_0_ADDR, wrdata);

	} else
		apm_enet_write(priv, BLOCK_AXG_MAC_CSR,
				XGENET_RX_DV_GATE_REG_0_ADDR, 0);
}


static void apm_xg_cle_bypass_mode_cfg(struct apm_enet_priv *priv,
	u32 cle_dstqid, u32 cle_fpsel, u32 cle_nxtfpsel, bool bypass_en)
{
	u32 reg;
	int enable = bypass_en ? 1 : 0;

	ENET_DEBUG("XG Bypass CLE\n");

	apm_enet_read(priv, BLOCK_ETH_CSR, CLE_BYPASS_REG0_ADDR, &reg);
	reg = CFG_CLE_BYPASS_EN0_SET(reg, enable);
	reg = CFG_CLE_IP_PROTOCOL0_SET(reg, 3);
	apm_enet_write(priv, BLOCK_ETH_CSR, CLE_BYPASS_REG0_ADDR, reg);

	apm_enet_read(priv, BLOCK_ETH_CSR, CLE_BYPASS_REG1_ADDR, &reg);
	reg = CFG_CLE_DSTQID1_SET(reg, cle_dstqid);
	reg = CFG_CLE_FPSEL1_SET(reg, cle_fpsel);
	reg = CFG_CLE_NXTFPSEL1_SET(reg, cle_nxtfpsel);
	apm_enet_write(priv, BLOCK_ETH_CSR, CLE_BYPASS_REG1_ADDR, reg);
}

static void apm_xgmac_get_tx_rx_stats(struct apm_enet_priv *priv,
		struct eth_frame_stats *tx_rx_stats)
{
	u32 block_mac_stats;
	u32 counter;

	if (priv->phy_mode == PHY_MODE_XGMII)
		block_mac_stats = BLOCK_AXG_STATS;
	else
		block_mac_stats = BLOCK_MCX_STATS;

	/* Read Stats */
	apm_enet_read(priv, block_mac_stats, TR64_ADDR,
			&counter);
	tx_rx_stats->c_64B_frames += counter;

	apm_enet_read(priv, block_mac_stats, TR127_ADDR,
			&counter);
	tx_rx_stats->c_65_127B_frames += counter;

	apm_enet_read(priv, block_mac_stats, TR255_ADDR,
			&counter);
	tx_rx_stats->c_128_255B_frames += counter;

	apm_enet_read(priv, block_mac_stats, TR511_ADDR,
			&counter);
	tx_rx_stats->c_256_511B_frames += counter;

	apm_enet_read(priv, block_mac_stats, TR1K_ADDR,
			&counter);
	tx_rx_stats->c_512_1023B_frames += counter;

	apm_enet_read(priv, block_mac_stats, TRMAX_ADDR,
			&counter);
	tx_rx_stats->c_1024_1518B_frames += counter;

	apm_enet_read(priv, block_mac_stats, TRMGV_ADDR,
			&counter);
	tx_rx_stats->c_1519_1522B_frames += counter;

	/* Mask out unnecessary bits in all the fields */
	tx_rx_stats->c_64B_frames &= TX_RX_64B_FRAME_CNTR4_MASK;
	tx_rx_stats->c_65_127B_frames &= TX_RX_127B_FRAME_CNTR7_MASK;
	tx_rx_stats->c_128_255B_frames &= TX_RX_255B_FRAME_CNTR5_MASK;
	tx_rx_stats->c_256_511B_frames &= TX_RX_511B_FRAME_CNTR1_MASK;
	tx_rx_stats->c_512_1023B_frames &= TX_RX_1KB_FRAME_CNTR_MASK;
	tx_rx_stats->c_1024_1518B_frames &= TX_RX_MAXB_FRAME_CNTR_MASK;
	tx_rx_stats->c_1519_1522B_frames &= TRMGV_MASK;
}

static void apm_xgmac_get_rx_stats(struct apm_enet_priv *priv,
	struct eth_rx_stat *rx_stat)
{
	u32 block_mac_stats;
	u32 counter;

	if (priv->phy_mode == PHY_MODE_XGMII)
		block_mac_stats = BLOCK_AXG_STATS;
	else
		block_mac_stats = BLOCK_MCX_STATS;

	apm_enet_read(priv, block_mac_stats, RFCS_ADDR,
			&counter);
	rx_stat->rx_fcs_err_count += counter;

	apm_enet_read(priv, block_mac_stats, RMCA_ADDR,
			&counter);
	rx_stat->rx_multicast_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RBCA_ADDR,
			&counter);
	rx_stat->rx_broadcast_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RXCF_ADDR,
			&counter);
	rx_stat->rx_cntrl_frame_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RXPF_ADDR,
			&counter);
	rx_stat->rx_pause_frame_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RXUO_ADDR,
			&counter);
	rx_stat->rx_unknown_op_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RALN_ADDR,
			&counter);
	rx_stat->rx_alignment_err_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RFLR_ADDR,
			&counter);
	rx_stat->rx_frm_len_err_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RCDE_ADDR,
			&counter);
	rx_stat->rx_code_err_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RCSE_ADDR,
			&counter);
	rx_stat->rx_carrier_sense_err_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RUND_ADDR,
			&counter);
	rx_stat->rx_undersize_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, ROVR_ADDR,
			&counter);
	rx_stat->rx_oversize_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, RFRG_ADDR,
			&counter);
	rx_stat->rx_fragment_count += counter;

	apm_enet_read(priv, block_mac_stats, RJBR_ADDR,
			&counter);
	rx_stat->rx_jabber_count += counter;

	apm_enet_read(priv, block_mac_stats, RDRP_ADDR,
			&counter);
	rx_stat->rx_drop_pkt_count += counter;

	/* Mask out unnecessary bits in all the fields */
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

static void apm_xgmac_get_tx_stats(struct apm_enet_priv *priv,
		struct eth_tx_stats *tx_stats)
{
	u32 block_mac_stats;
	u32 counter;

	if (priv->phy_mode == PHY_MODE_XGMII)
		block_mac_stats = BLOCK_AXG_STATS;
	else
		block_mac_stats = BLOCK_MCX_STATS;

	/* Read Stats */
	apm_enet_read(priv, block_mac_stats, TMCA_ADDR,
			&counter);
	tx_stats->tx_multicast_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TBCA_ADDR,
			&counter);
	tx_stats->tx_broadcast_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TXPF_ADDR,
			&counter);
	tx_stats->tx_pause_frame_count += counter;

	apm_enet_read(priv, block_mac_stats, TDFR_ADDR,
			&counter);
	tx_stats->tx_deferral_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TEDF_ADDR,
			&counter);
	tx_stats->tx_exesiv_def_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TSCL_ADDR,
			&counter);
	tx_stats->tx_single_coll_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TMCL_ADDR,
			&counter);
	tx_stats->tx_multi_coll_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TLCL_ADDR,
			&counter);
	tx_stats->tx_late_coll_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TXCL_ADDR,
			&counter);
	tx_stats->tx_exesiv_coll_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TNCL_ADDR,
			&counter);
	tx_stats->tx_toll_coll_pkt_count += counter;

	apm_enet_read(priv, block_mac_stats, TPFH_ADDR,
			&counter);
	tx_stats->tx_pause_frm_hon_count += counter;

	apm_enet_read(priv, block_mac_stats, TDRP_ADDR,
			&counter);
	tx_stats->tx_drop_frm_count += counter;

	apm_enet_read(priv, block_mac_stats, TJBR_ADDR,
			&counter);
	tx_stats->tx_jabber_frm_count += counter;

	apm_enet_read(priv, block_mac_stats, TFCS_ADDR,
			&counter);
	tx_stats->tx_fcs_err_frm_count += counter;

	apm_enet_read(priv, block_mac_stats, TXCF_ADDR,
			&counter);
	tx_stats->tx_control_frm_count += counter;

	apm_enet_read(priv, block_mac_stats, TOVR_ADDR,
			&counter);
	tx_stats->tx_oversize_frm_count += counter;

	apm_enet_read(priv, block_mac_stats, TUND_ADDR,
			&counter);
	tx_stats->tx_undersize_frm_count += counter;

	apm_enet_read(priv, block_mac_stats, TFRG_ADDR,
			&counter);
	tx_stats->tx_fragments_frm_count += counter;

	/* Mask values with appropriate width of the fields */
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

static void apm_xgmac_get_detailed_stats(struct apm_enet_priv *priv,
		struct eth_detailed_stats *stats)
{
	apm_xgmac_get_tx_rx_stats(priv, &(stats->eth_combined_stats));
	apm_xgmac_get_rx_stats(priv, &(stats->rx_stats));
	apm_xgmac_get_tx_stats(priv, &(stats->tx_stats));
}

static int apm_xgmac_init(struct apm_enet_priv *priv,
		unsigned char *dev_addr, int speed, int crc)
{
	u32 ret;
	u32 value;

	if (priv->phy_mode == PHY_MODE_XGMII)
		ret = apm_axgmac_init(priv, dev_addr, APM_ENET_SPEED_10000, crc);
	else
		ret = apm_mcxmac_init(priv, dev_addr, speed, crc);

	/* Enable drop if FP not available */
	apm_enet_read(priv, BLOCK_ETH_CSR, RSIF_CONFIG_REG_ADDR, &value);
	value |= CFG_RSIF_FPBUFF_TIMEOUT_EN_WR(1);
	apm_enet_write(priv, BLOCK_ETH_CSR, RSIF_CONFIG_REG_ADDR, value);

	apm_enet_read(priv, BLOCK_ETH_CSR, AVB_PER_Q_CONFIG1_0_ADDR, &value);
	value = CFG_ETH_Q_ARB_TYPE0_SET(value, 0x5555);
	apm_enet_write(priv, BLOCK_ETH_CSR, AVB_PER_Q_CONFIG1_0_ADDR, value);

	apm_enet_write(priv, BLOCK_ETH_CSR, AVB_PER_Q_HI_CREDIT_0_ADDR, 0x44444444);

	apm_enet_read(priv, BLOCK_ETH_CSR, AVB_COMMON_CONFIG1_0_ADDR, &value);
	value = MAC_SPEED0_SET(value, 2);
	value = CFG_AVB_ADD_OVERHEAD0_SET(value, 1);
	value = CFG_AVB_OVERHEAD0_SET(value, 20);
	apm_enet_write(priv, BLOCK_ETH_CSR, AVB_COMMON_CONFIG1_0_ADDR, value);

	apm_enet_read(priv, BLOCK_ETH_CSR, AVB_COMMON_CONFIG2_0_ADDR, &value);
	value = CFG_WRR_CREDIT_RESET_EN0_SET(value, 1);
	value = CFG_AVB_CALC_INT_HUNDREDNSEC_CNT0_SET(value, 0x0004);
	apm_enet_write(priv, BLOCK_ETH_CSR, AVB_COMMON_CONFIG2_0_ADDR, value);

	return ret;
}

void apm_xgmac_rx_state(struct apm_enet_priv *priv, u32 enable)
{
	if (enable)
		apm_xgmac_rx_enable(priv);
	else
		apm_xgmac_rx_disable(priv);
}

void apm_xgmac_tx_state(struct apm_enet_priv *priv, u32 enable)
{
	if (enable)
		apm_xgmac_tx_enable(priv);
	else
		apm_xgmac_tx_disable(priv);
}

void apm_xgmac_set_ipg(struct apm_enet_priv *priv, u16 ipg)
{
	u32 data;

	if (priv->phy_mode != PHY_MODE_XGMII) {
		apm_enet_read(priv, BLOCK_MCX_MAC, IPG_IFG_ADDR, &data);
		apm_enet_write(priv, BLOCK_MCX_MAC, IPG_IFG_ADDR,
				B2B_IPG_SET(data, ipg));
	}

	ENET_DEBUG("Setting IPG to %d bits", ipg);
}

static void apm_xgmac_set_mac_addr(struct apm_enet_priv *priv,
		unsigned char *dev_addr)
{
	u32 a_hi;
	u32 a_lo;

	a_hi = *(u32 *) &dev_addr[0];
	a_lo = (u32) *(u16 *) &dev_addr[4];
	a_lo <<= 16;

	if (priv->phy_mode == PHY_MODE_XGMII) {
		apm_enet_write(priv, BLOCK_AXG_MAC, AXGMAC_HSTMACADR_LSW_ADDR, a_hi);
		apm_enet_write(priv, BLOCK_AXG_MAC, AXGMAC_HSTMACADR_MSW_ADDR, a_lo);
	} else {
		/* Write higher 4 octects to station register */
		apm_enet_write(priv, BLOCK_MCX_MAC, STATION_ADDR0_ADDR, a_hi);
		a_lo |= (priv->phy_addr & 0xFFFF);
		/* Write lower 2 octects to station register */
		apm_enet_write(priv, BLOCK_MCX_MAC, STATION_ADDR1_ADDR, a_lo);
	}
}

void apm_xgmac_tx_offload(struct apm_enet_priv *priv, u32 command, u32 value)
{
	u32 data;

	switch (command) {
	/* TCP MSS 0 */
	case APM_ENET_MSS0:
		apm_enet_read(priv, BLOCK_ETH_CSR,
				TSIF_MSS_REG0_0_ADDR, &data);
		apm_enet_write(priv, BLOCK_ETH_CSR,
				TSIF_MSS_REG0_0_ADDR,
				CFG_TSIF_MSS_SZ00_SET(data, value));
		break;
		/* TCP MSS 1 */
	case APM_ENET_MSS1:
		apm_enet_read(priv, BLOCK_ETH_CSR,
				TSIF_MSS_REG0_0_ADDR, &data);
		apm_enet_write(priv, BLOCK_ETH_CSR,
				TSIF_MSS_REG0_0_ADDR,
				CFG_TSIF_MSS_SZ10_SET(data, value));
		break;
		/* TCP MSS 2 */
	case APM_ENET_MSS2:
		apm_enet_read(priv, BLOCK_ETH_CSR,
				TSIF_MSS_REG1_0_ADDR, &data);
		apm_enet_write(priv, BLOCK_ETH_CSR,
				TSIF_MSS_REG1_0_ADDR,
				CFG_TSIF_MSS_SZ20_SET(data, value));
		break;
		/* TCP MSS 3 */
	case APM_ENET_MSS3:
		apm_enet_read(priv, BLOCK_ETH_CSR,
				TSIF_MSS_REG1_0_ADDR, &data);
		apm_enet_write(priv, BLOCK_ETH_CSR,
				TSIF_MSS_REG1_0_ADDR,
				CFG_TSIF_MSS_SZ30_SET(data, value));
		break;
		/* Program TSO config */
	case APM_ENET_TSO_CFG:
		apm_enet_write(priv, BLOCK_ETH_CSR, TSO_CFG_0_ADDR, value);
		break;
		/* Insert Inser tVLAN TAG */
	case APM_ENET_INSERT_VLAN:
		apm_enet_write(priv, BLOCK_ETH_CSR,
				TSO_CFG_INSERT_VLAN_0_ADDR, value);
		break;
	}
}

static void apm_xgport_reset(struct apm_enet_priv *priv, u32 mii_mode)
{
	priv->phy_mode = mii_mode;
	apm_xg_clk_rst_cfg(priv);
	xgenet_config_qmi_assoc(priv);
	apm_xg_bypass_resume_cfg(priv);
	msleep(500);
}

static void apm_xgport_shutdown(struct apm_enet_priv *priv)
{
	u32 val;

	/* reset serdes, csr and xgenet core */
	val = XGENET_RESET_WR(1) | CSR_RESET_WR(1) | XGENET_SDS_RESET_WR(1);
	apm_enet_write(priv, BLOCK_ETH_CLKRST_CSR, XGENET_SRST_ADDR, val);

	/* disable csr and xgenet clock */
	val = CSR_CLKEN_WR(0) | XGENET_CLKEN_WR(0);
	apm_enet_write(priv, BLOCK_ETH_CLKRST_CSR, XGENET_CLKEN_ADDR, val);
}

void apm_xgenet_init_priv(struct apm_enet_priv *priv, void *port_vaddr,
		void *gbl_vaddr, void *mii_vaddr)
{
	/* Setup the ethernet base address and mac address */
	priv->vaddr_base = gbl_vaddr;
	priv->vpaddr_base = port_vaddr;

	/* Initialize base addresses for direct access */
	priv->eth_csr_addr_v        = gbl_vaddr + BLOCK_ETH_CSR_OFFSET;
	priv->eth_cle_addr_v        = gbl_vaddr + BLOCK_ETH_CLE_OFFSET;
	priv->eth_qmi_addr_v        = gbl_vaddr + BLOCK_ETH_QMI_OFFSET;
	priv->eth_sds_csr_addr_v    = gbl_vaddr + BLOCK_ETH_SDS_CSR_OFFSET;
	priv->eth_clkrst_csr_addr_v = gbl_vaddr + BLOCK_ETH_CLKRST_CSR_OFFSET;
	priv->eth_diag_csr_addr_v   = gbl_vaddr + BLOCK_ETH_DIAG_CSR_OFFSET;

	/* Initialize base addresses for Per Port MII Indirect access */
	priv->mac_mii_addr_v = mii_vaddr;

	/* Initialize base addresses for Per Port indirect & direct MCX MAC access */
	priv->mcx_mac_addr_v       = port_vaddr + BLOCK_ETH_MAC_OFFSET;
	priv->mcx_stats_addr_v     = port_vaddr + BLOCK_ETH_STATS_OFFSET;
	priv->mcx_mac_csr_addr_v   = gbl_vaddr + BLOCK_MCX_MAC_CSR_OFFSET;

	/* Initialize base addresses for Per Port indirect & direct AXG MAC access */
	priv->axg_mac_addr_v         = gbl_vaddr + BLOCK_AXG_MAC_OFFSET;
	priv->axg_stats_addr_v       = gbl_vaddr + BLOCK_AXG_STATS_OFFSET;
	priv->axg_mac_csr_addr_v     = gbl_vaddr + BLOCK_ETH_MAC_CSR_OFFSET;
	priv->xgenet_pcs_addr_v      = gbl_vaddr + BLOCK_XGENET_PCS_OFFSET;
	priv->xgenet_mdio_csr_addr_v = gbl_vaddr + BLOCK_XGENET_MDIO_CSR_OFFSET;

	ENET_DEBUG("           ETH%d VADDR: 0x%p\n", priv->port, priv->vpaddr_base);
	ENET_DEBUG("            ETH VADDR: 0x%p\n", priv->vaddr_base);
	ENET_DEBUG("        ETH CSR VADDR: 0x%p\n", priv->eth_csr_addr_v);
	ENET_DEBUG("        ETH CLE VADDR: 0x%p\n", priv->eth_cle_addr_v);
	ENET_DEBUG("        ETH QMI VADDR: 0x%p\n", priv->eth_qmi_addr_v);
	ENET_DEBUG("    ETH SDS CSR VADDR: 0x%p\n", priv->eth_sds_csr_addr_v);
	ENET_DEBUG(" ETH CLKRST CSR VADDR: 0x%p\n", priv->eth_clkrst_csr_addr_v);
	ENET_DEBUG("       ETH DIAG VADDR: 0x%p\n", priv->eth_diag_csr_addr_v);
	ENET_DEBUG("        MAC MII VADDR: 0x%p\n", priv->mac_mii_addr_v);
	ENET_DEBUG("        MCX MAC VADDR: 0x%p\n", priv->mcx_mac_addr_v);
	ENET_DEBUG("       MCX STAT VADDR: 0x%p\n", priv->mcx_stats_addr_v);
	ENET_DEBUG("    MCX MAC CSR VADDR: 0x%p\n", priv->mcx_mac_csr_addr_v);
	ENET_DEBUG("        AXG MAC VADDR: 0x%p\n", priv->axg_mac_addr_v);
	ENET_DEBUG("       AXG STAT VADDR: 0x%p\n", priv->axg_stats_addr_v);
	ENET_DEBUG("    AXG MAC CSR VADDR: 0x%p\n", priv->axg_mac_csr_addr_v);
	ENET_DEBUG("     XGENET PCS VADDR: 0x%p\n", priv->xgenet_pcs_addr_v);
	ENET_DEBUG("XGENET MDIO CSR VADDR: 0x%p\n", priv->xgenet_mdio_csr_addr_v);

	/* Initialize priv handlers */
	priv->autoneg_set = 1;
	priv->port_reset = apm_xgport_reset;
	priv->mac_reset = apm_xgmac_reset;
	priv->get_link_status = apm_xgmac_link_status;
	priv->mac_init = apm_xgmac_init;
	priv->mac_rx_state = apm_xgmac_rx_state;
	priv->mac_tx_state = apm_xgmac_tx_state;
	priv->mac_set_ipg = apm_xgmac_set_ipg;
	priv->get_stats = apm_xgmac_get_detailed_stats;
	priv->set_mac_addr = apm_xgmac_set_mac_addr;
	priv->cle_bypass = apm_xg_cle_bypass_mode_cfg;
	priv->tx_offload = apm_xgmac_tx_offload;
	priv->port_shutdown = apm_xgport_shutdown;
}
