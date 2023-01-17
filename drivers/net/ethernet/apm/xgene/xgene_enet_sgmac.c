/* Applied Micro X-Gene SoC Ethernet Driver
 *
 * Copyright (c) 2014, Applied Micro Circuits Corporation
 * Authors: Iyappan Subramanian <isubramanian@apm.com>
 *	    Ravi Patel <rapatel@apm.com>
 *	    Keyur Chudgar <kchudgar@apm.com>
 *          Hrishikesh Karanjikar <hkaranjikar@apm.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "xgene_enet_main.h"

static void xgene_enet_wr_csr(struct xgene_enet_pdata *pdata,
			      u32 offset, u32 val)
{
	void *addr = pdata->eth_csr_addr + offset;
	iowrite32(val, addr);
}

static void xgene_xgenet_mdio_wr_csr(struct xgene_enet_pdata *pdata,
                              u32 offset, u32 val)
{
	void *addr = pdata->mdio_addr + offset;
	iowrite32(val, addr);
}

static void xgene_xgenet_mdio_rd_csr(struct xgene_enet_pdata *pdata,
				u32 offset, u32 *val)
{
	void *addr = pdata->mdio_addr + offset;
	*val = ioread32(addr);
}

static void xgene_enet_wr_clkrst_csr(struct xgene_enet_pdata *pdata,
				     u32 offset, u32 val)
{
	void *addr = pdata->base_addr + BLOCK_ETH_CLKRST_CSR_OFFSET + offset;
	iowrite32(val, addr);
}

static void xgene_enet_wr_ring_if(struct xgene_enet_pdata *pdata,
				  u32 offset, u32 val)
{
	void *addr = pdata->eth_ring_if_addr + offset;
	iowrite32(val, addr);
}

static void xgene_enet_wr_diag_csr(struct xgene_enet_pdata *pdata,
				   u32 offset, u32 val)
{
	void *addr = pdata->eth_diag_csr_addr + offset;
	iowrite32(val, addr);
}

static void xgene_enet_wr_mcx_csr(struct xgene_enet_pdata *pdata,
				  u32 offset, u32 val)
{
	void *addr = pdata->mcx_mac_csr_addr + offset;
	iowrite32(val, addr);
}

static u32 xgene_enet_wr_indirect(void *addr, void *wr, void *cmd,
				  void *cmd_done, u32 wr_addr,
				  u32 wr_data)
{
	u32 cmd_done_val;

	iowrite32(wr_addr, addr);
	iowrite32(wr_data, wr);
	iowrite32(XGENE_ENET_WR_CMD, cmd);
	udelay(5);		/* wait 5 us for completion */
	cmd_done_val = ioread32(cmd_done);
	iowrite32(0, cmd);
	return cmd_done_val;
}

static void xgene_enet_wr_mcx_mac(struct xgene_enet_pdata *pdata,
				  u32 wr_addr, u32 wr_data)
{
	void *addr, *wr, *cmd, *cmd_done;
	int ret;

	addr = pdata->mcx_mac_addr + MAC_ADDR_REG_OFFSET;
	wr = pdata->mcx_mac_addr + MAC_WRITE_REG_OFFSET;
	cmd = pdata->mcx_mac_addr + MAC_COMMAND_REG_OFFSET;
	cmd_done = pdata->mcx_mac_addr + MAC_COMMAND_DONE_REG_OFFSET;

	ret = xgene_enet_wr_indirect(addr, wr, cmd, cmd_done, wr_addr, wr_data);
	if (!ret)
		netdev_err(pdata->ndev, "MCX mac write failed, addr: %04x",
			   wr_addr);
}

static void xgene_enet_rd_csr(struct xgene_enet_pdata *pdata,
			      u32 offset, u32 *val)
{
	void *addr = pdata->eth_csr_addr + offset;
	*val = ioread32(addr);
}

static void xgene_enet_rd_clkrst_csr(struct xgene_enet_pdata *pdata,
				     u32 offset, u32 *val)
{
	void *addr = pdata->base_addr + BLOCK_ETH_CLKRST_CSR_OFFSET + offset;
	*val = ioread32(addr);
}

static void xgene_enet_rd_ring_if(struct xgene_enet_pdata *pdata,
				  u32 offset, u32 *val)
{
	void *addr = pdata->eth_ring_if_addr + offset;
	*val = ioread32(addr);
}

static void xgene_enet_rd_diag_csr(struct xgene_enet_pdata *pdata,
				   u32 offset, u32 *val)
{
	void *addr = pdata->eth_diag_csr_addr + offset;
	*val = ioread32(addr);
}

static void xgene_enet_rd_mcx_csr(struct xgene_enet_pdata *pdata,
				  u32 offset, u32 *val)
{
	void *addr = pdata->mcx_mac_csr_addr + offset;
	*val = ioread32(addr);
}

static u32 xgene_enet_rd_indirect(void *addr, void *rd, void *cmd,
				  void *cmd_done, u32 rd_addr,
				  u32 *rd_data)
{
	u32 cmd_done_val;

	iowrite32(rd_addr, addr);
	iowrite32(XGENE_ENET_RD_CMD, cmd);
	udelay(5);		/* wait 5 us for completion */
	cmd_done_val = ioread32(cmd_done);
	*rd_data = ioread32(rd);
	iowrite32(0, cmd);
	return cmd_done_val;
}

static void xgene_enet_rd_mcx_mac(struct xgene_enet_pdata *pdata,
				  u32 rd_addr, u32 *rd_data)
{
	void *addr, *rd, *cmd, *cmd_done;
	int ret;

	addr = pdata->mcx_mac_addr + MAC_ADDR_REG_OFFSET;
	rd = pdata->mcx_mac_addr + MAC_READ_REG_OFFSET;
	cmd = pdata->mcx_mac_addr + MAC_COMMAND_REG_OFFSET;
	cmd_done = pdata->mcx_mac_addr + MAC_COMMAND_DONE_REG_OFFSET;

	ret = xgene_enet_rd_indirect(addr, rd, cmd, cmd_done, rd_addr, rd_data);
	if (!ret)
		netdev_err(pdata->ndev, "MCX mac read failed, addr: %04x",
			   rd_addr);
}

static void xgene_enet_rd_mcx_stats(struct xgene_enet_pdata *pdata,
				    u32 rd_addr, u32 *rd_data)
{
	void *addr, *rd, *cmd, *cmd_done;
	int ret;

	addr = pdata->mcx_stats_addr + STAT_ADDR_REG_OFFSET;
	rd = pdata->mcx_stats_addr + STAT_READ_REG_OFFSET;
	cmd = pdata->mcx_stats_addr + STAT_COMMAND_REG_OFFSET;
	cmd_done = pdata->mcx_stats_addr + STAT_COMMAND_DONE_REG_OFFSET;

	ret = xgene_enet_rd_indirect(addr, rd, cmd, cmd_done, rd_addr, rd_data);
	if (!ret)
		netdev_err(pdata->ndev, "MCX stats read failed, addr: %04x",
			   rd_addr);
}

#define XG_PHY_ADDR_WR(src)                         (((u32)(src)<<8) & 0x00001f00)
#define XG_REG_ADDR_WR(src)                            (((u32)(src)) & 0x0000001f)

#define FIELD_MIIM_COMMAND_HSTLDCMD_WR(dst)	(0x00000008 & ((u32)(dst) << 0x3))
#define FIELD_MIIM_COMMAND_HSTMIIMCMD_WR(dst)	(0x00000007 & ((u32)(dst) << 0x0))
#define FIELD_MIIM_FIELD_HSTPHYADX_WR(dst)	(0x0f800000 & ((u32)(dst) << 0x17))
#define FIELD_MIIM_FIELD_HSTREGADX_MASK		0x007c0000
#define FIELD_MIIM_FIELD_HSTREGADX_SHIFT_MASK	0x12
#define FIELD_MIIM_FIELD_HSTREGADX_WR(dst)	(0x007c0000 & ((u32)(dst) << 0x12))
#define FIELD_MIIM_FIELD_HSTMIIMWRDAT_WR(dst)	(0x0000ffff & ((u32)(dst) << 0x0))
#define SM_XGENET_MDIO_CSR_MIIM_COMMAND_ADDR	0x0020
#define SM_XGENET_MDIO_CSR_MIIM_FIELD_ADDR	0x0024
#define SM_XGENET_MDIO_CSR_MIIM_INDICATOR_ADDR	0x0030
#define SM_XGENET_MDIO_CSR_MIIMRD_FIELD_ADDR	0x0034

typedef enum {
	MIIMCMD_IDLE,
	/* Legacy (10/100/1000 Mbs PHY) Write
	 */
	MIIMCMD_LEGACY_WRITE,
	/* Legacy (10/100/1000 Mbs PHY) Read
	 */
	MIIMCMD_LEGACY_READ,
	/* The AMIIM will continually read from a
	 * single PHY register specified by the contents of the hstphyadx and
	 * hstregadx fields
	 */
	MIIMCMD_SINGLE_PHY_MONITOR,
	/* Multiple-PHY
	 * Monitor operation The AMIIM will continually read from a set of PHYs
	 * of contiguous address space. The starting address of the PHY is
	 * specified by the content of the hstphyadx field, the very next PHY
	 * to be read will be hstphyadx + 1. The last PHY to be queried in this read
	 * sequence will be the one that resides at address 0x31, after which the read
	 * sequence will continue again for the PHY specified by the hstphyadx field
	 */
	MIIMCMD_MULTIPLE_PHY_MONITOR,
	/* The AMIIM will present the contents of the AMIIM field
	 * register to the MDIO pins in the order specified by the Management
	 * Frame Format in IEEE Standard 802.3 clause 45
	 */
	MIIMCMD_10GIGABIT_MMD,
	/* Will cause the Link Fail bit in
	 * the MIIM Indicators Register to be cleared. This value will also clear
	 * each bit in the AMIIM Link Fail Vector Register
	 */
	MIIMCMD_CLEAR_LINK_FAIL,
} MIIM_CMD;

static void xgene_xgenet_mdio_write(struct xgene_enet_pdata *pdata, u8 phy_id,
				u32 reg, u16 data)
{
	u32 mii_mgmt_field;
	u32 mii_mgmt_indi;
	u32 mii_cmd;
	int timeout = 100;

	mii_mgmt_field = 0;

	mii_mgmt_field = FIELD_MIIM_FIELD_HSTPHYADX_WR(phy_id) /* PHY address (or hardware address) */
		| FIELD_MIIM_FIELD_HSTREGADX_WR(reg) /* Register address, DEVAD */
		| FIELD_MIIM_FIELD_HSTMIIMWRDAT_WR(data);

	xgene_xgenet_mdio_wr_csr(pdata, SM_XGENET_MDIO_CSR_MIIM_FIELD_ADDR, mii_mgmt_field);

	mii_cmd = FIELD_MIIM_COMMAND_HSTLDCMD_WR(1)
		| FIELD_MIIM_COMMAND_HSTMIIMCMD_WR(MIIMCMD_LEGACY_WRITE);

	xgene_xgenet_mdio_wr_csr(pdata, SM_XGENET_MDIO_CSR_MIIM_COMMAND_ADDR, mii_cmd);

	usleep_range(20, 30);
	mii_mgmt_indi = 1;

	while (((mii_mgmt_indi & 0x00000001) == 1) && (timeout > 0)) {
		xgene_xgenet_mdio_rd_csr(pdata, SM_XGENET_MDIO_CSR_MIIM_INDICATOR_ADDR, &mii_mgmt_indi);
		timeout--;
	}

	xgene_xgenet_mdio_wr_csr(pdata, SM_XGENET_MDIO_CSR_MIIM_COMMAND_ADDR, 0x0);
}

static void xgene_xgenet_mdio_read(struct xgene_enet_pdata *pdata, u8 phy_id,
				u32 reg, u32 *data)
{
	u32 mii_mgmt_field;
	u32 mii_mgmt_indi;
	u32 mii_cmd;
	int timeout = 100;

	mii_mgmt_field = 0;
	*data = 0;

	mii_mgmt_field = FIELD_MIIM_FIELD_HSTPHYADX_WR(phy_id) /* PHY address (or hardware address) */
		| FIELD_MIIM_FIELD_HSTREGADX_WR(reg); /* Register address, DEVAD */

	xgene_xgenet_mdio_wr_csr(pdata, SM_XGENET_MDIO_CSR_MIIM_FIELD_ADDR, mii_mgmt_field);

	mii_cmd = FIELD_MIIM_COMMAND_HSTLDCMD_WR(1)
		| FIELD_MIIM_COMMAND_HSTMIIMCMD_WR(MIIMCMD_LEGACY_READ);
	xgene_xgenet_mdio_wr_csr(pdata, SM_XGENET_MDIO_CSR_MIIM_COMMAND_ADDR, mii_cmd);

	usleep_range(20, 30);
	mii_mgmt_indi = 1;

	while (((mii_mgmt_indi & 0x00000001) == 1) && (timeout > 0)) {
		xgene_xgenet_mdio_rd_csr(pdata, SM_XGENET_MDIO_CSR_MIIM_INDICATOR_ADDR, &mii_mgmt_indi);
		timeout--;
	}

	xgene_xgenet_mdio_rd_csr(pdata, SM_XGENET_MDIO_CSR_MIIMRD_FIELD_ADDR, data);

	xgene_xgenet_mdio_wr_csr(pdata, SM_XGENET_MDIO_CSR_MIIM_COMMAND_ADDR, 0x0);
}

static void xgene_mii_phy_write(struct xgene_enet_pdata *pdata, u8 phy_id,
			       u32 reg, u16 data)
{
	u32 addr, wr_data, done;

	addr = XG_PHY_ADDR_WR(phy_id) | XG_REG_ADDR_WR(reg);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_ADDRESS_ADDR, addr);

	wr_data = PHY_CONTROL_WR(data);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_CONTROL_ADDR, wr_data);

	usleep_range(20, 30);		/* wait 20 us for completion */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_INDICATORS_ADDR, &done);
	if (done & BUSY_MASK)
		netdev_err(pdata->ndev, "MII_MGMT write failed\n");
	xgene_xgenet_mdio_write(pdata, phy_id, reg, data);
}

static void xgene_mii_phy_read(struct xgene_enet_pdata *pdata, u8 phy_id,
			      u32 reg, u32 *data)
{
	u32 addr, done;

	addr = XG_PHY_ADDR_WR(phy_id) | XG_REG_ADDR_WR(reg);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_ADDRESS_ADDR, addr);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_COMMAND_ADDR, READ_CYCLE_MASK);

	usleep_range(20, 30);		/* wait 20 us for completion */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_INDICATORS_ADDR, &done);
	if (done & BUSY_MASK)
		netdev_err(pdata->ndev, "MII_MGMT read failed\n");

	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_STATUS_ADDR, data);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_COMMAND_ADDR, 0);
	xgene_xgenet_mdio_read(pdata, phy_id, reg, data);
}

static void xgene_sgmac_set_mac_addr(struct xgene_enet_pdata *pdata)
{
	u32 addr0, addr1;
	unsigned char *dev_addr = pdata->ndev->dev_addr;

	addr0 = (dev_addr[3] << 24) | (dev_addr[2] << 16) |
		(dev_addr[1] << 8) | dev_addr[0];
	addr1 = (dev_addr[5] << 24) | (dev_addr[4] << 16);
	addr1 |= pdata->phy_addr & 0xFFFF;

	xgene_enet_wr_mcx_mac(pdata, STATION_ADDR0_ADDR, addr0);
	xgene_enet_wr_mcx_mac(pdata, STATION_ADDR1_ADDR, addr1);
}

static void xgene_sgmac_set_mss(struct xgene_enet_pdata *pdata)
{
	if (pdata->intf == XGENE_SM_SGENET_0) {
		xgene_enet_wr_csr(pdata, TSIF_MSS_REG0_0_ADDR, pdata->mss);
	} else if (pdata->intf == XGENE_SM_SGENET_1) {
		xgene_enet_wr_csr(pdata, TSIF_MSS_REG0_1_ADDR, pdata->mss);
	} else {
		xgene_enet_wr_csr(pdata, XG_TSIF_MSS_REG0_ADDR, pdata->mss);
	}
}

static int xgene_enet_ecc_init(struct xgene_enet_pdata *pdata)
{
	struct net_device *ndev = pdata->ndev;
	u32 data;

	xgene_enet_wr_diag_csr(pdata, ENET_CFG_MEM_RAM_SHUTDOWN_ADDR, 0x0);
	usleep_range(1000, 1100);		/* wait 1 ms for completion */
	xgene_enet_rd_diag_csr(pdata, ENET_BLOCK_MEM_RDY_ADDR, &data);
	if (data != 0xffffffff) {
		netdev_err(ndev, "Failed to release memory from shutdown\n");
		return -ENODEV;
	}

	return 0;
}

static void xgene_sgmac_phy_enable_scan_cycle(struct xgene_enet_pdata *pdata)
{
	u32 val;

	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_COMMAND_ADDR, &val);
	val = SCAN_CYCLE_MASK_SET(val, 1);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_COMMAND_ADDR, val);

	/* Program phy address start scan from 0 and register at address 0x1 */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_ADDRESS_ADDR, &val);
	val = PHY_ADDR_SET(val, 0);
	val = REG_ADDR_SET(val, MII_BMSR);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_ADDRESS_ADDR, val);
}

static void xgene_xg_bypass_resume(struct xgene_enet_pdata *pdata)
{
	u32 data, timeout = 10;

	if (pdata->intf == XGENE_MN_SGENET_2) {
		/* disable auto-neg, force link */
		xgene_mii_phy_write(pdata, INT_PHY_ADDR, SGMII_TBI_CONTROL_ADDR >> 2, 0);
	#ifndef CONFIG_NET_XGENE_MAC_TO_MAC
		xgene_mii_phy_write(pdata, INT_PHY_ADDR, SGMII_CONTROL_ADDR >> 2, 0x8000);
		udelay(1000);
		/* force link up */
		#define SGMII_AN_ADVERTISEMENT_ADDR 0x00000010
		xgene_mii_phy_read(pdata, INT_PHY_ADDR, SGMII_AN_ADVERTISEMENT_ADDR >> 2, &data);
		xgene_mii_phy_write(pdata, INT_PHY_ADDR,SGMII_AN_ADVERTISEMENT_ADDR >> 2, data);
		xgene_mii_phy_read(pdata, INT_PHY_ADDR, SGMII_AN_ADVERTISEMENT_ADDR >> 2, &data);
	#endif
	} else {
		xgene_mii_phy_write(pdata, INT_PHY_ADDR,
		       	SGMII_TBI_CONTROL_ADDR >> 2, 0);
		xgene_mii_phy_write(pdata, INT_PHY_ADDR,
		       	SGMII_CONTROL_ADDR >> 2, 0x9140);
		udelay(1000);
		do {
			xgene_mii_phy_read(pdata, INT_PHY_ADDR,
			       	   SGMII_STATUS_ADDR >> 2, &data);
			if ((data & AUTO_NEG_COMPLETE) && (data & LINK_STATUS)) 
				break;
			udelay(1000);
		} while (--timeout);
		xgene_enet_rd_csr(pdata, XG_LINK_STATUS_ADDR, &data);
	}

	xgene_enet_rd_csr(pdata, XG_ENET_SPARE_CFG_REG_ADDR, &data);
	data |= BIT(12);
	xgene_enet_wr_csr(pdata, XG_ENET_SPARE_CFG_REG_ADDR, data);
	data = 0x44;
	xgene_enet_wr_csr(pdata, XG_ENET_SPARE_CFG_REG_1_ADDR, data);
}

static void xgene_bypass_resume(struct xgene_enet_pdata *pdata)
{
	u32 data, timeout = 10;

	xgene_mii_phy_write(pdata, INT_PHY_ADDR,
		       	SGMII_TBI_CONTROL_ADDR >> 2, 0);
	xgene_mii_phy_write(pdata, INT_PHY_ADDR,
		       	SGMII_CONTROL_ADDR >> 2, 0x9140);
	udelay(10);
	xgene_mii_phy_write(pdata, INT_PHY_ADDR,
		       	SGMII_CONTROL_ADDR >> 2, 0x1140);
	udelay(1000);
	do {
		xgene_mii_phy_read(pdata, INT_PHY_ADDR,
			       	   SGMII_STATUS_ADDR >> 2, &data);
		if ((data & AUTO_NEG_COMPLETE) && (data & LINK_STATUS)) 
			break;
		udelay(1000);
	} while (--timeout);

	xgene_enet_rd_csr(pdata, ENET_SPARE_CFG_REG_ADDR, &data);
	data |= BIT(12);
	xgene_enet_wr_csr(pdata, ENET_SPARE_CFG_REG_ADDR, data);
	data = 0x44;
	xgene_enet_wr_csr(pdata, ENET_SPARE_CFG_REG_1_ADDR, data);
}

static void xgene_sgmac_reset(struct xgene_enet_pdata *pdata)
{
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, SOFT_RESET);
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, 0);
}

static void xgene_sc_sgmac_init(struct xgene_enet_pdata *pdata)
{
	u32 value, mc2;
	u32 intf_ctl;
	u32 icm0, icm2;
	int speed = pdata->phy_speed;

	xgene_sgmac_reset(pdata);
	xgene_xg_bypass_resume(pdata);

	xgene_enet_rd_mcx_csr(pdata, XG_MCX_ICM_CONFIG0_REG_0_ADDR, &icm0);
	xgene_enet_rd_mcx_csr(pdata, XG_MCX_ICM_CONFIG2_REG_0_ADDR, &icm2);
	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_2_ADDR, &mc2);
	xgene_enet_rd_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, &intf_ctl);

	//TODO:
	// - sgmii_autoneg
	// - ecm0: read fifo threshold

	switch (speed) {
	case SPEED_10:
		ENET_INTERFACE_MODE2_SET(&mc2, 1);
		CFG_MACMODE_SET(&icm0, 0);
		CFG_WAITASYNCRD_SET(&icm2, 500);
		break;
	case SPEED_100:
		ENET_INTERFACE_MODE2_SET(&mc2, 1);
		intf_ctl |= ENET_LHD_MODE;
		CFG_MACMODE_SET(&icm0, 1);
		CFG_WAITASYNCRD_SET(&icm2, 80);
		break;
	default:
		ENET_INTERFACE_MODE2_SET(&mc2, 2);
		intf_ctl |= ENET_GHD_MODE;
		xgene_enet_rd_csr(pdata, XG_DEBUG_REG_ADDR, &value);
		value |= CFG_BYPASS_UNISEC_TX | CFG_BYPASS_UNISEC_RX;
		xgene_enet_wr_csr(pdata, XG_DEBUG_REG_ADDR, value);
		break;
	}

	mc2 |= FULL_DUPLEX;
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_2_ADDR, mc2);
	xgene_enet_wr_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, intf_ctl);

	xgene_sgmac_set_mac_addr(pdata);

	/* Adjust MDC clock frequency */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, &value);
	MGMT_CLOCK_SEL_SET(&value, 7);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, value);

	/* Enable drop if bufpool not available */
	xgene_enet_rd_csr(pdata, XG_RSIF_CONFIG_REG_ADDR, &value);
	value |= CFG_RSIF_FPBUFF_TIMEOUT_EN;
	xgene_enet_wr_csr(pdata, XG_RSIF_CONFIG_REG_ADDR, value);

	/* Rtype should be copied from FP */
	xgene_enet_wr_csr(pdata, XG_RSIF_RAM_DBG_REG0_ADDR, 0);

	/* Rx-Tx traffic resume */
	xgene_enet_wr_csr(pdata, XG_CFG_LINK_AGGR_RESUME_0_ADDR, TX_PORT);

	xgene_enet_wr_mcx_csr(pdata, XG_MCX_ICM_CONFIG0_REG_0_ADDR, icm0);
	xgene_enet_wr_mcx_csr(pdata, XG_MCX_ICM_CONFIG2_REG_0_ADDR, icm2);

	xgene_enet_rd_mcx_csr(pdata, XG_MCX_RX_DV_GATE_REG_0_ADDR, &value);
	value &= ~TX_DV_GATE_EN;
	value &= ~RX_DV_GATE_EN;
	value |= RESUME_RX;
	xgene_enet_wr_mcx_csr(pdata, XG_MCX_RX_DV_GATE_REG_0_ADDR, value);

	xgene_enet_wr_csr(pdata, XG_CFG_BYPASS_ADDR, RESUME_TX);
}

static void xgene_mn_sgmac_init(struct xgene_enet_pdata *pdata)
{
	u32 value, mc2;
	u32 intf_ctl;
	u32 icm0, icm2;
	int speed = pdata->phy_speed;

	xgene_sgmac_reset(pdata);
	xgene_bypass_resume(pdata);

	if (pdata->intf == XGENE_MN_SGENET_0) {
		xgene_enet_rd_mcx_csr(pdata, ICM_CONFIG0_REG_0_ADDR, &icm0);
		xgene_enet_rd_mcx_csr(pdata, ICM_CONFIG2_REG_0_ADDR, &icm2);
	} else {
		xgene_enet_rd_mcx_csr(pdata, ICM_CONFIG0_REG_1_ADDR, &icm0);
		xgene_enet_rd_mcx_csr(pdata, ICM_CONFIG2_REG_1_ADDR, &icm2);
	}
	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_2_ADDR, &mc2);
	xgene_enet_rd_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, &intf_ctl);

	switch (speed) {
	case SPEED_10:
		ENET_INTERFACE_MODE2_SET(&mc2, 1);
		intf_ctl &= !(ENET_LHD_MODE | ENET_GHD_MODE);
		CFG_MACMODE_SET(&icm0, 0);
		CFG_WAITASYNCRD_SET(&icm2, 500);
		break;
	case SPEED_100:
		ENET_INTERFACE_MODE2_SET(&mc2, 1);
		intf_ctl &= !ENET_GHD_MODE;
		intf_ctl |= ENET_LHD_MODE;
		CFG_MACMODE_SET(&icm0, 1);
		CFG_WAITASYNCRD_SET(&icm2, 80);
		break;
	default:
		ENET_INTERFACE_MODE2_SET(&mc2, 2);
		intf_ctl &= !ENET_LHD_MODE;
		intf_ctl |= ENET_GHD_MODE;
		CFG_MACMODE_SET(&icm0, 2);
		CFG_WAITASYNCRD_SET(&icm2, 0);
		xgene_enet_rd_csr(pdata, DEBUG_REG_ADDR, &value);
		value |= CFG_BYPASS_UNISEC_TX | CFG_BYPASS_UNISEC_RX;
		xgene_enet_wr_csr(pdata, DEBUG_REG_ADDR, value);
		break;
	}

	mc2 |= FULL_DUPLEX | CRC_EN | PAD_CRC;
	mc2 &= ~(0xf << 12);
	mc2 |= (0x5 << 12); /* set preamble to 6 bytes */

	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_2_ADDR, mc2);
	xgene_enet_wr_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, intf_ctl);

	xgene_sgmac_set_mac_addr(pdata);

	/* Adjust MDC clock frequency */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, &value);
	MGMT_CLOCK_SEL_SET(&value, 7);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, value);

	/* Enable drop if bufpool not available */
	xgene_enet_rd_csr(pdata, RSIF_CONFIG_REG_ADDR, &value);
	value |= CFG_RSIF_FPBUFF_TIMEOUT_EN;
	xgene_enet_wr_csr(pdata, RSIF_CONFIG_REG_ADDR, value);

	/* Rtype should be copied from FP */
	xgene_enet_wr_csr(pdata, RSIF_RAM_DBG_REG0_ADDR, 0);

	if (pdata->intf == XGENE_MN_SGENET_0) {
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG0_REG_0_ADDR, icm0);
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG2_REG_0_ADDR, icm2);
		/* Rx-Tx traffic resume */
		xgene_enet_wr_csr(pdata, CFG_LINK_AGGR_RESUME_0_ADDR, TX_PORT);
		xgene_enet_wr_mcx_csr(pdata, RX_DV_GATE_REG_0_ADDR, RESUME_RX);
	} else {
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG0_REG_1_ADDR, icm0);
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG2_REG_1_ADDR, icm2);
		/* Rx-Tx traffic resume */
		xgene_enet_wr_csr(pdata, CFG_LINK_AGGR_RESUME_1_ADDR, TX_PORT);
		xgene_enet_wr_mcx_csr(pdata, RX_DV_GATE_REG_1_ADDR, RESUME_RX);
	}

	xgene_enet_wr_csr(pdata, CFG_BYPASS_ADDR, RESUME_TX);
}

static void xgene_mn_sgmac_2500_init(struct xgene_enet_pdata *pdata)
{
	u32 value, mc2;
	u32 intf_ctl;
	u32 icm0, icm2;
	int speed = pdata->phy_speed;

	xgene_sgmac_reset(pdata);
	xgene_xg_bypass_resume(pdata);

	xgene_enet_rd_mcx_csr(pdata, XG_MCX_ICM_CONFIG0_REG_0_ADDR, &icm0);
	xgene_enet_rd_mcx_csr(pdata, XG_MCX_ICM_CONFIG2_REG_0_ADDR, &icm2);

	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_2_ADDR, &mc2);
	xgene_enet_rd_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, &intf_ctl);

	switch (speed) {
	case SPEED_10:
		ENET_INTERFACE_MODE2_SET(&mc2, 1);
		CFG_MACMODE_SET(&icm0, 0);
		CFG_WAITASYNCRD_SET(&icm2, 500);
		break;
	case SPEED_100:
		ENET_INTERFACE_MODE2_SET(&mc2, 1);
		intf_ctl |= ENET_LHD_MODE;
		CFG_MACMODE_SET(&icm0, 1);
		CFG_WAITASYNCRD_SET(&icm2, 80);
		break;
	default:
		ENET_INTERFACE_MODE2_SET(&mc2, 2);
		intf_ctl |= ENET_GHD_MODE;
		xgene_enet_rd_csr(pdata, XG_DEBUG_REG_ADDR, &value);
		value |= CFG_BYPASS_UNISEC_TX | CFG_BYPASS_UNISEC_RX;
		xgene_enet_wr_csr(pdata, XG_DEBUG_REG_ADDR, value);
		break;
	}

	mc2 |= FULL_DUPLEX;
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_2_ADDR, mc2);
	xgene_enet_wr_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, intf_ctl);

	xgene_sgmac_set_mac_addr(pdata);

	/* Adjust MDC clock frequency */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, &value);
	MGMT_CLOCK_SEL_SET(&value, 7);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, value);

	/* Enable drop if bufpool not available */
	xgene_enet_rd_csr(pdata, XG_RSIF_CONFIG_REG_ADDR, &value);
	value |= CFG_RSIF_FPBUFF_TIMEOUT_EN;
	xgene_enet_wr_csr(pdata, XG_RSIF_CONFIG_REG_ADDR, value);

	/* Rtype should be copied from FP */
	xgene_enet_wr_csr(pdata, XG_RSIF_RAM_DBG_REG0_ADDR, 0);

	/* Rx-Tx traffic resume */
	xgene_enet_wr_csr(pdata, XG_CFG_LINK_AGGR_RESUME_0_ADDR, TX_PORT);

	xgene_enet_wr_mcx_csr(pdata, XG_MCX_ICM_CONFIG0_REG_0_ADDR, icm0);
	xgene_enet_wr_mcx_csr(pdata, XG_MCX_ICM_CONFIG2_REG_0_ADDR, icm2);

	xgene_enet_rd_mcx_csr(pdata, XG_MCX_RX_DV_GATE_REG_0_ADDR, &value);
	value &= ~TX_DV_GATE_EN;
	value &= ~RX_DV_GATE_EN;
	value |= RESUME_RX;
	xgene_enet_wr_mcx_csr(pdata, XG_MCX_RX_DV_GATE_REG_0_ADDR, value);

	xgene_enet_wr_csr(pdata, XG_CFG_BYPASS_ADDR, RESUME_TX);
}

static void xgene_sm_sgmac_init(struct xgene_enet_pdata *pdata)
{
	u32 value, mc1, mc2, loop = 50;
	u32 intf_ctl;
	u32 icm0, icm2, ecm0, enet_spare_cfg, dv_gate = 0;

	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_1_ADDR, &mc1);
	/* Reset the sunsystem */
	mc1 = SOFT_RESET | SIM_RESET | RESET_RX_MC | RESET_TX_MC |
		RESET_RX_FUN | RESET_TX_FUN;

	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, mc1);
	udelay(100);
	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_1_ADDR, &mc1);
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, 0x0);
	udelay(100);

	/* Configure the mac */
	mc1 = TX_EN | RX_EN;
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, mc1);
	udelay(100);

	/* Configure SGMII autoneg */
	/* Reset PHY */
	xgene_mii_phy_write(pdata, INT_PHY_ADDR,
		       	SGMII_TBI_CONTROL_ADDR >> 2, 0);
	xgene_mii_phy_write(pdata, INT_PHY_ADDR,
		       	SGMII_CONTROL_ADDR >> 2, 0x9140);
	udelay(10);
	/* Bring PHY out of reset with autoneg enable */
	xgene_mii_phy_write(pdata, INT_PHY_ADDR,
		       	SGMII_CONTROL_ADDR >> 2, 0x1140);
	udelay(1000);

	/* Check autoneg status */
	do {
		xgene_mii_phy_read(pdata, INT_PHY_ADDR,
			       	   SGMII_STATUS_ADDR >> 2, &value);
		if ((value & AUTO_NEG_COMPLETE) && (value & LINK_STATUS)) {
			break;
		}
		udelay(100);
	} while (--loop);

	xgene_mii_phy_read(pdata, INT_PHY_ADDR,
		       	SGMII_TBI_CONTROL_ADDR >> 2, &value);

	xgene_mii_phy_read(pdata, INT_PHY_ADDR,
		       	SGMII_CONTROL_ADDR >> 2, &value);

	xgene_mii_phy_read(pdata, INT_PHY_ADDR,
		       	SGMII_STATUS_ADDR >> 2, &value);

	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_2_ADDR, &mc2);
	mc2 |= FULL_DUPLEX;
	ENET_INTERFACE_MODE2_SET(&mc2, 2);	
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_2_ADDR, mc2);
	
	xgene_enet_rd_csr(pdata, ENET_SPARE_CFG_REG_ADDR, &enet_spare_cfg);

	icm0 = 0x0008503f;
	icm2 = 0x0001000f;
	ecm0 = 0x00000032;

	dv_gate = RESUME_RX;
	dv_gate &= ~TX_DV_GATE_EN;
	dv_gate &= ~RX_DV_GATE_EN;

	if (pdata->intf == XGENE_SM_SGENET_0) {
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG0_REG_0_ADDR, icm0);
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG2_REG_0_ADDR, icm2);
		xgene_enet_wr_mcx_csr(pdata, ECM_CONFIG0_REG_0_ADDR, ecm0);
		/* Rx-Tx traffic resume */
		xgene_enet_wr_csr(pdata, CFG_LINK_AGGR_RESUME_0_ADDR, TX_PORT);
		xgene_enet_wr_mcx_csr(pdata, RX_DV_GATE_REG_0_ADDR, dv_gate);
		enet_spare_cfg = (enet_spare_cfg & ~0x0000c000) | (0x00000040);
	} else if (pdata->intf == XGENE_SM_SGENET_1) {
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG0_REG_1_ADDR, icm0);
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG2_REG_1_ADDR, icm2);
		xgene_enet_wr_mcx_csr(pdata, ECM_CONFIG0_REG_1_ADDR, ecm0);
		/* Rx-Tx traffic resume */
		xgene_enet_wr_csr(pdata, CFG_LINK_AGGR_RESUME_1_ADDR, TX_PORT);
		xgene_enet_wr_mcx_csr(pdata, RX_DV_GATE_REG_1_ADDR, dv_gate);
		enet_spare_cfg = (enet_spare_cfg & ~0x00030000) | (0x00000040);
	}

	enet_spare_cfg |= 0x00006040;
	xgene_enet_wr_csr(pdata, ENET_SPARE_CFG_REG_ADDR, enet_spare_cfg);

	intf_ctl = ENET_GHD_MODE;
	xgene_enet_wr_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, intf_ctl);
	
	xgene_enet_rd_csr(pdata, DEBUG_REG_ADDR, &value);
	value |= CFG_BYPASS_UNISEC_TX | CFG_BYPASS_UNISEC_RX;
	xgene_enet_wr_csr(pdata, DEBUG_REG_ADDR, value);

	xgene_sgmac_set_mac_addr(pdata);

	/* Adjust MDC clock frequency */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, &value);
	MGMT_CLOCK_SEL_SET(&value, 7);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, value);

	/* Enable drop if bufpool not available */
	xgene_enet_rd_csr(pdata, RSIF_CONFIG_REG_ADDR, &value);
	value |= CFG_RSIF_FPBUFF_TIMEOUT_EN;
	xgene_enet_wr_csr(pdata, RSIF_CONFIG_REG_ADDR, value);

	/* Rtype should be copied from FP */
	xgene_enet_wr_csr(pdata, RSIF_RAM_DBG_REG0_ADDR, 0);

	/* Bypass traffic gating */
	xgene_enet_wr_csr(pdata, CFG_BYPASS_ADDR, RESUME_TX);
}

static void xgene_sgmac_init(struct xgene_enet_pdata *pdata)
{
	if (pdata->intf == XGENE_SM_SGENET_0 || 
		pdata->intf == XGENE_SM_SGENET_1) {
		xgene_sm_sgmac_init(pdata);
	} else if (pdata->intf == XGENE_MN_SGENET_1 ||
		   pdata->intf == XGENE_MN_SGENET_0) {
		xgene_mn_sgmac_init(pdata);
	} else if (pdata->intf == XGENE_MN_SGENET_2) {
		xgene_mn_sgmac_2500_init(pdata);
	} else {
		xgene_sc_sgmac_init(pdata);
	}
}

/* Start Statistics related functions */
static void xgene_gmac_get_eth_combined_stats(struct xgene_enet_pdata *pdata,
				    struct xgene_enet_frame_stats *eth_combined_stats)
{
        u32 counter;

        /* Read Stats */
        xgene_enet_rd_mcx_stats(pdata, TR64_ADDR, &counter);
        eth_combined_stats->c_64B_frames += counter;

        xgene_enet_rd_mcx_stats(pdata, TR127_ADDR, &counter);
        eth_combined_stats->c_65_127B_frames += counter;

        xgene_enet_rd_mcx_stats(pdata, TR255_ADDR, &counter);
        eth_combined_stats->c_128_255B_frames += counter;

        xgene_enet_rd_mcx_stats(pdata, TR511_ADDR, &counter);
        eth_combined_stats->c_256_511B_frames += counter;

        xgene_enet_rd_mcx_stats(pdata, TR1K_ADDR, &counter);
        eth_combined_stats->c_512_1023B_frames += counter;

        xgene_enet_rd_mcx_stats(pdata, TRMAX_ADDR, &counter);
        eth_combined_stats->c_1024_1518B_frames += counter;

        xgene_enet_rd_mcx_stats(pdata, TRMGV_ADDR, &counter);
        eth_combined_stats->c_1519_1522B_frames += counter;

        /* Mask out unnecessary bits in all the fields */
        eth_combined_stats->c_64B_frames &= TX_RX_64B_FRAME_CNTR_MASK;
        eth_combined_stats->c_65_127B_frames &= TX_RX_127B_FRAME_CNTR_MASK;
        eth_combined_stats->c_128_255B_frames &= TX_RX_255B_FRAME_CNTR_MASK;
        eth_combined_stats->c_256_511B_frames &= TX_RX_511B_FRAME_CNTR_MASK;
        eth_combined_stats->c_512_1023B_frames &= TX_RX_1KB_FRAME_CNTR_MASK;
        eth_combined_stats->c_1024_1518B_frames &= TX_RX_MAXB_FRAME_CNTR_MASK;
        eth_combined_stats->c_1519_1522B_frames &= TRMGV_MASK;
}

static void xgene_gmac_get_rx_stats(struct xgene_enet_pdata *pdata,
				    struct xgene_enet_rx_stats *rx_stats)
{
	u32 counter;

	/* Read Stats */
	xgene_enet_rd_mcx_stats(pdata, RBYT_ADDR, &counter);
	rx_stats->rx_byte_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RPKT_ADDR, &counter);
	rx_stats->rx_packet_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RFCS_ADDR, &counter);
	rx_stats->rx_fcs_err_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RMCA_ADDR, &counter);
	rx_stats->rx_multicast_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RBCA_ADDR, &counter);
	rx_stats->rx_broadcast_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RXCF_ADDR, &counter);
	rx_stats->rx_cntrl_frame_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RXPF_ADDR, &counter);
	rx_stats->rx_pause_frame_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RXUO_ADDR, &counter);
	rx_stats->rx_unknown_op_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RALN_ADDR, &counter);
	rx_stats->rx_alignment_err_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RFLR_ADDR, &counter);
	rx_stats->rx_frm_len_err_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RCDE_ADDR, &counter);
	rx_stats->rx_code_err_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RCSE_ADDR, &counter);
	rx_stats->rx_false_carrier_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RUND_ADDR, &counter);
	rx_stats->rx_undersize_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, ROVR_ADDR, &counter);
	rx_stats->rx_oversize_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RFRG_ADDR, &counter);
	rx_stats->rx_fragment_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RJBR_ADDR, &counter);
	rx_stats->rx_jabber_count += counter;

	xgene_enet_rd_mcx_stats(pdata, RDRP_ADDR, &counter);
	rx_stats->rx_drop_pkt_count += counter;

	if ((pdata->intf == XGENE_MN_SGENET_1) ||
		(pdata->intf == XGENE_SC_SGENET_1) ||
		(pdata->intf == XGENE_SM_SGENET_1))
		xgene_enet_rd_mcx_csr(pdata, ICM_ECM_DROP_COUNT_REG1, &counter);
	else
		xgene_enet_rd_mcx_csr(pdata, ICM_ECM_DROP_COUNT_REG0, &counter);

	rx_stats->rx_icm_drop_count += ICM_DROP_COUNT(counter);

	/* Mask out unnecessary bits in all the fields */
	rx_stats->rx_byte_count &= RX_BYTE_CNTR_MASK;
	rx_stats->rx_packet_count &= RX_PKT_CNTR_MASK;
	rx_stats->rx_fcs_err_count &= RX_FCS_ERROR_CNTR_MASK;
	rx_stats->rx_multicast_pkt_count &= RX_MC_PKT_CNTR_MASK;
	rx_stats->rx_broadcast_pkt_count &= RX_BC_PKT_CNTR_MASK;
	rx_stats->rx_cntrl_frame_pkt_count &= RX_CTRL_PKT_CNTR_MASK;
	rx_stats->rx_pause_frame_pkt_count &= RX_PAUSE_PKT_CNTR_MASK;
	rx_stats->rx_unknown_op_pkt_count &= RX_UNK_OPCODE_CNTR_MASK;
	rx_stats->rx_alignment_err_pkt_count &= RX_ALIGN_ERR_CNTR_MASK;
	rx_stats->rx_frm_len_err_pkt_count &= RX_LEN_ERR_CNTR_MASK;
	rx_stats->rx_code_err_pkt_count &= RX_CODE_ERR_CNTR_MASK;
	rx_stats->rx_false_carrier_count &= RX_FALSE_CARRIER_CNTR_MASK;
	rx_stats->rx_undersize_pkt_count &= RX_UNDRSIZE_PKT_CNTR_MASK;
	rx_stats->rx_oversize_pkt_count &= RX_OVRSIZE_PKT_CNTR_MASK;
	rx_stats->rx_fragment_count &= RX_FRAG_CNTR_MASK;
	rx_stats->rx_jabber_count &= RX_JABBER_CNTR_MASK;
	rx_stats->rx_drop_pkt_count &= RX_DROPPED_PKT_CNTR_MASK;
	
	rx_stats->rx_total_err_count = rx_stats->rx_fcs_err_count +
					rx_stats->rx_alignment_err_pkt_count +
					rx_stats->rx_frm_len_err_pkt_count +
					rx_stats->rx_code_err_pkt_count;
}

static void xgene_gmac_get_tx_stats(struct xgene_enet_pdata *pdata,
				    struct xgene_enet_tx_stats *tx_stats)
{
	u32 counter;

	/* Read Stats */
	xgene_enet_rd_mcx_stats(pdata, TBYT_ADDR, &counter);
	tx_stats->tx_byte_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TPKT_ADDR, &counter);
	tx_stats->tx_packet_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TMCA_ADDR, &counter);
	tx_stats->tx_multicast_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TBCA_ADDR, &counter);
	tx_stats->tx_broadcast_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TXCF_ADDR, &counter);
	tx_stats->tx_cntrl_frame_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TXPF_ADDR, &counter);
	tx_stats->tx_pause_frame_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TDFR_ADDR, &counter);
	tx_stats->tx_deferral_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TEDF_ADDR, &counter);
	tx_stats->tx_exesiv_def_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TSCL_ADDR, &counter);
	tx_stats->tx_single_coll_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TMCL_ADDR, &counter);
	tx_stats->tx_multi_coll_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TLCL_ADDR, &counter);
	tx_stats->tx_late_coll_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TXCL_ADDR, &counter);
	tx_stats->tx_exesiv_coll_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TNCL_ADDR, &counter);
	tx_stats->tx_toll_coll_pkt_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TPFH_ADDR, &counter);
	tx_stats->tx_pause_frm_hon_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TDRP_ADDR, &counter);
	tx_stats->tx_drop_frm_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TJBR_ADDR, &counter);
	tx_stats->tx_jabber_frm_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TFCS_ADDR, &counter);
	tx_stats->tx_fcs_err_frm_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TXCF_ADDR, &counter);
	tx_stats->tx_control_frm_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TOVR_ADDR, &counter);
	tx_stats->tx_oversize_frm_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TUND_ADDR, &counter);
	tx_stats->tx_undersize_frm_count += counter;

	xgene_enet_rd_mcx_stats(pdata, TFRG_ADDR, &counter);
	tx_stats->tx_fragments_frm_count += counter;

	if ((pdata->intf == XGENE_MN_SGENET_1) ||
		(pdata->intf == XGENE_SC_SGENET_1) ||
		(pdata->intf == XGENE_SM_SGENET_1))
		xgene_enet_rd_mcx_csr(pdata, ICM_ECM_DROP_COUNT_REG1, &counter);
	else
		xgene_enet_rd_mcx_csr(pdata, ICM_ECM_DROP_COUNT_REG0, &counter);

	tx_stats->tx_ecm_drop_count += ECM_DROP_COUNT(counter);

	/* Mask values with appropriate width of the fields */
	tx_stats->tx_byte_count &= RX_BYTE_CNTR_MASK;
	tx_stats->tx_packet_count &= RX_PKT_CNTR_MASK;
	tx_stats->tx_multicast_pkt_count &= TX_MC_PKT_CNTR_MASK;
	tx_stats->tx_broadcast_pkt_count &= TX_BC_PKT_CNTR_MASK;
	tx_stats->tx_cntrl_frame_pkt_count &= TX_CTRL_FRAME_CNTR_MASK;
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

static void xgene_sgmac_get_stats(struct xgene_enet_pdata *pdata)
{
	xgene_gmac_get_eth_combined_stats(pdata,
					  &pdata->stats.eth_combined_stats);
	xgene_gmac_get_rx_stats(pdata, &pdata->stats.rx_stats);
	xgene_gmac_get_tx_stats(pdata, &pdata->stats.tx_stats);
}

static void xgene_enet_config_ring_if_assoc(struct xgene_enet_pdata *pdata)
{
	u32 val = 0x0;

	if (pdata->intf == XGENE_SM_SGENET_0 || 
		pdata->intf == XGENE_SM_SGENET_1)
		val = 0xffffffff;
	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIWQASSOC_ADDR, val);
	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIFPQASSOC_ADDR, val);
}

static void xgene_enet_cle_bypass(struct xgene_enet_pdata *pdata,
				  u32 dst_ring_num, u32 fpsel, bool enable)
{
	u32 cb, bypass_reg0, bypass_reg1;

	switch (pdata->intf) {
	case XGENE_SM_SGENET_0:
	case XGENE_MN_SGENET_0:
		bypass_reg0 = CLE_BYPASS_REG0_0_ADDR;
		bypass_reg1 = CLE_BYPASS_REG1_0_ADDR;
		break;
	case XGENE_SM_SGENET_1:
	case XGENE_MN_SGENET_1:
		bypass_reg0 = CLE_BYPASS_REG0_1_ADDR;
		bypass_reg1 = CLE_BYPASS_REG1_1_ADDR;
		break;
	default:
		bypass_reg0 = XCLE_BYPASS_REG0_ADDR;
		bypass_reg1 = XCLE_BYPASS_REG1_ADDR;
		break;
	}

	xgene_enet_rd_csr(pdata, bypass_reg0, &cb);

	if (enable)
		cb |= CFG_CLE_BYPASS_EN0;
	else
		cb &= (~CFG_CLE_BYPASS_EN0);

	CFG_CLE_IP_PROTOCOL0_SET(&cb, 3);
	xgene_enet_wr_csr(pdata, bypass_reg0, cb);

	xgene_enet_rd_csr(pdata, bypass_reg1, &cb);
	CFG_CLE_DSTQID0_SET(&cb, dst_ring_num);
	CFG_CLE_FPSEL0_SET(&cb, fpsel);
	xgene_enet_wr_csr(pdata, bypass_reg1, cb);
}

static void xgene_sgmac_enable(struct xgene_enet_pdata *pdata)
{
	u32 data;

	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_1_ADDR, &data);
	data |= BIT(2);
	data |= BIT(0);
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, data);
}

static void xgene_sgmac_disable(struct xgene_enet_pdata *pdata)
{
	u32 data;

	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_1_ADDR, &data);
	data &= ~BIT(2);
	data &= ~BIT(0);
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, data);
}

static void xgene_xg_clk_rst_cfg(struct xgene_enet_pdata *pdata)
{
	u32 clken = 0, srst = 0;

	// 0. rst and clk disable
	srst = 0x7b; /* Reset all blocks, except serdes */
	xgene_enet_wr_clkrst_csr(pdata, XGENET_SRST_ADDR, srst);
	xgene_enet_wr_clkrst_csr(pdata, XGENET_CLKEN_ADDR, 0x0);

	// 1. enable CSR and an ref clk
	clken |= CSR_CLK;
	clken |= AN_REF_CLK;
	xgene_enet_wr_clkrst_csr(pdata, XGENET_CLKEN_ADDR, clken);

	// 3. enable an and ad clk
	xgene_enet_rd_clkrst_csr(pdata, XGENET_CLKEN_ADDR, &clken);
	clken |= AN_CLK;
	clken |= AD_CLK;
	xgene_enet_wr_clkrst_csr(pdata, XGENET_CLKEN_ADDR, clken);

	// 4. disable an, ad and ref clk
	xgene_enet_rd_clkrst_csr(pdata, XGENET_CLKEN_ADDR, &clken);
	clken &= ~AN_CLK;
	clken &= ~AD_CLK;
	clken &= ~AN_REF_CLK;
	xgene_enet_wr_clkrst_csr(pdata, XGENET_CLKEN_ADDR, clken);

	// 6. de-assert csr reset
	xgene_enet_rd_clkrst_csr(pdata, XGENET_SRST_ADDR, &srst );
	srst &= ~CSR_RST;
	xgene_enet_wr_clkrst_csr(pdata, XGENET_SRST_ADDR, srst );

	// 7. enable pcs and core clk
	xgene_enet_rd_clkrst_csr(pdata, XGENET_CLKEN_ADDR, &clken);
	clken |= PCS_CLK;
	clken |= XGENET_CLK;
	xgene_enet_wr_clkrst_csr(pdata, XGENET_CLKEN_ADDR, clken);

	// 8. de-assert pcs and core reset
	xgene_enet_rd_clkrst_csr(pdata, XGENET_SRST_ADDR, &srst );
	srst &= ~PCS_RST;
	srst &= ~XGENET_RST;
	xgene_enet_wr_clkrst_csr(pdata, XGENET_SRST_ADDR, srst );
}

static void xgene_sc_enet_reset(struct xgene_enet_pdata *pdata)
{
	u32 data;

	switch (pdata->intf) {
	case XGENE_MN_SGENET_0:
		xgene_enet_rd_clkrst_csr(pdata, ENET_SRST_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, ENET_SRST_ADDR, data | 0x3);
		xgene_enet_rd_clkrst_csr(pdata, ENET_CLKEN_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, ENET_CLKEN_ADDR, data | 0x3);
		xgene_enet_rd_clkrst_csr(pdata, ENET_SRST_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, ENET_SRST_ADDR, data & ~0x3);
		xgene_enet_ecc_init(pdata);
		break;
	case XGENE_MN_SGENET_1:
		xgene_enet_rd_clkrst_csr(pdata, ENET_SRST_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, ENET_SRST_ADDR, data | 0xc);
		xgene_enet_rd_clkrst_csr(pdata, ENET_CLKEN_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, ENET_CLKEN_ADDR, data | 0xc);
		xgene_enet_rd_clkrst_csr(pdata, ENET_SRST_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, ENET_SRST_ADDR, data & ~0xc);
		xgene_enet_ecc_init(pdata);
		break;
	case XGENE_MN_SGENET_2:
		xgene_enet_rd_clkrst_csr(pdata, XGENET_SRST_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, XGENET_SRST_ADDR, data | 0x3);
		xgene_enet_rd_clkrst_csr(pdata, XGENET_CLKEN_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, XGENET_CLKEN_ADDR, data | 0x3);
		xgene_enet_wr_clkrst_csr(pdata, XGENET_CONFIG_REG_ADDR, 0x3); /* SGMII 2500 MHZ */
		xgene_enet_rd_clkrst_csr(pdata, XGENET_SRST_ADDR, &data);
		xgene_enet_wr_clkrst_csr(pdata, XGENET_SRST_ADDR, data & ~0x3);
		xgene_enet_ecc_init(pdata);
		break;
	default:
		xgene_enet_wr_clkrst_csr(pdata, XGENET_CONFIG_REG_ADDR, 0x1);
		xgene_xg_clk_rst_cfg(pdata);
		xgene_enet_ecc_init(pdata);
		xgene_enet_config_ring_if_assoc(pdata);
		break;
	}

}

static void xgene_sm_enet_reset(struct xgene_enet_pdata *pdata)
{
	u32 csr_clk, csr_rst, block_clk, block_rst;

	/* We are not doing serdes reset here since it is done in u-boot */
	if (pdata->intf == XGENE_SM_SGENET_0) {
		xgene_enet_rd_clkrst_csr(pdata, ENET_CLKEN_ADDR, &csr_clk);
		csr_clk |= 0x1;
		xgene_enet_wr_clkrst_csr(pdata, ENET_CLKEN_ADDR, csr_clk);
		udelay(1000);
		xgene_enet_rd_clkrst_csr(pdata, ENET_SRST_ADDR, &csr_rst);
		csr_rst &= ~(0x1);
		xgene_enet_wr_clkrst_csr(pdata, ENET_SRST_ADDR, csr_rst);
		udelay(1000);
		xgene_enet_rd_clkrst_csr(pdata, ENET_CLKEN_ADDR, &block_clk);
		block_clk |= 0x2;
		xgene_enet_wr_clkrst_csr(pdata, ENET_CLKEN_ADDR, block_clk);
		udelay(1000);
		xgene_enet_rd_clkrst_csr(pdata, ENET_SRST_ADDR, &block_rst);
		block_rst &= ~(0x2);
		xgene_enet_wr_clkrst_csr(pdata, ENET_SRST_ADDR, block_rst);
		udelay(1000);
	} else {
		xgene_enet_rd_clkrst_csr(pdata, ENET_CLKEN_ADDR, &csr_clk);
		csr_clk |= 0x4;
		xgene_enet_wr_clkrst_csr(pdata, ENET_CLKEN_ADDR, csr_clk);
		udelay(1000);
		xgene_enet_rd_clkrst_csr(pdata, ENET_SRST_ADDR, &csr_rst);
		csr_rst &= 0x4;
		xgene_enet_wr_clkrst_csr(pdata, ENET_SRST_ADDR, csr_rst);
		udelay(1000);
		xgene_enet_rd_clkrst_csr(pdata, ENET_CLKEN_ADDR, &block_clk);
		block_clk |= 0x8;
		xgene_enet_wr_clkrst_csr(pdata, ENET_CLKEN_ADDR, block_clk);
		udelay(1000);
		xgene_enet_rd_clkrst_csr(pdata, ENET_SRST_ADDR, &block_rst);
		block_rst &= ~(0x8);
		xgene_enet_wr_clkrst_csr(pdata, ENET_SRST_ADDR, block_rst);
		udelay(1000);
	}
	xgene_enet_ecc_init(pdata);
	xgene_enet_config_ring_if_assoc(pdata);
}

static void xgene_enet_reset(struct xgene_enet_pdata *pdata)
{

	if (pdata->intf == XGENE_SM_SGENET_0 || 
		pdata->intf == XGENE_SM_SGENET_1)
		xgene_sm_enet_reset(pdata);
	else
		xgene_sc_enet_reset(pdata);
}

static void xgene_enet_shutdown(struct xgene_enet_pdata *pdata)
{
	if (!IS_ERR(pdata->clk))
		clk_disable_unprepare(pdata->clk);
}

static int xgene_enet_mdio_read(struct mii_bus *bus, int mii_id, int regnum)
{
	struct xgene_enet_pdata *pdata = bus->priv;
	u32 val;

	xgene_mii_phy_read(pdata, mii_id, regnum, &val);
	netdev_dbg(pdata->ndev, "mdio_rd: bus=%d reg=%d val=%x\n",
		   mii_id, regnum, val);
	return val;
}

static int xgene_enet_mdio_write(struct mii_bus *bus, int mii_id, int regnum,
				 u16 val)
{
	struct xgene_enet_pdata *pdata = bus->priv;

	netdev_dbg(pdata->ndev, "mdio_wr: bus=%d reg=%d val=%x\n",
		   mii_id, regnum, val);
	xgene_mii_phy_write(pdata, mii_id, regnum, val);

	return 0;
}

static void xgene_enet_adjust_link(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct phy_device *phydev = pdata->phy_dev;
	bool status_change = false;

	if (phydev->link && pdata->phy_speed != phydev->speed) {
		pdata->phy_speed = phydev->speed;
		xgene_sgmac_init(pdata);
		status_change = true;
	}

	if (pdata->phy_link != phydev->link) {
		if (!phydev->link)
			pdata->phy_speed = 0;
		pdata->phy_link = phydev->link;
		status_change = true;
	}

	if (!status_change)
		return;

	if (phydev->link)
		xgene_sgmac_enable(pdata);
	else
		xgene_sgmac_disable(pdata);
	phy_print_status(phydev);
}

static int xgene_enet_phy_connect(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct device_node *phy_np;
	struct phy_device *phy_dev;
	struct device *dev = &pdata->pdev->dev;

	phy_np = of_parse_phandle(dev->of_node, "phy-handle", 0);
	if (!phy_np) {
		netdev_dbg(ndev, "No phy-handle found\n");
		return -ENODEV;
	}

	phy_dev = of_phy_connect(ndev, phy_np, &xgene_enet_adjust_link,
				0, PHY_INTERFACE_MODE_SGMII);
	if (!phy_dev) {
		netdev_err(ndev, "Could not connect to PHY\n");
		return  -ENODEV;
	}

	pdata->phy_link = 0;
	pdata->phy_speed = 0;
	pdata->phy_dev = phy_dev;

	return 0;
}

static int xgene_enet_mdio_config(struct xgene_enet_pdata *pdata)
{
	struct net_device *ndev = pdata->ndev;
	struct device *dev = &pdata->pdev->dev;
	struct device_node *child_np;
	struct device_node *mdio_np = NULL;
	struct mii_bus *mdio_bus;
	int ret;

	for_each_child_of_node(dev->of_node, child_np) {
		if (of_device_is_compatible(child_np, "apm,xgene-mdio")) {
			mdio_np = child_np;
			break;
		}
	}

	if (!mdio_np) {
		netdev_dbg(ndev, "No mdio node in the dts\n");
		return -1;
	}

	mdio_bus = mdiobus_alloc();
	if (!mdio_bus)
		return -ENOMEM;

	mdio_bus->name = "APM X-Gene MDIO bus";
	mdio_bus->read = xgene_enet_mdio_read;
	mdio_bus->write = xgene_enet_mdio_write;
	snprintf(mdio_bus->id, MII_BUS_ID_SIZE, "%s-%s", "xgene-mii", ndev->name);

	mdio_bus->irq = devm_kcalloc(dev, PHY_MAX_ADDR, sizeof(int),
				     GFP_KERNEL);
	if (!mdio_bus->irq) {
		ret = -ENOMEM;
		goto err;
	}

	mdio_bus->priv = pdata;
	mdio_bus->parent = &ndev->dev;

	ret = of_mdiobus_register(mdio_bus, mdio_np);
	if (ret) {
		netdev_err(ndev, "Failed to register MDIO bus\n");
		goto err;
	}
	pdata->mdio_bus = mdio_bus;

	ret = xgene_enet_phy_connect(ndev);
	if (ret) {
		mdiobus_unregister(mdio_bus);
		goto err;
	}
	xgene_sgmac_phy_enable_scan_cycle(pdata);

	return ret;
err:
	if (mdio_bus->irq)
		devm_kfree(dev, mdio_bus->irq);
	mdiobus_free(mdio_bus);
	pdata->mdio_bus = NULL;

	return ret;
}

static int xgene_enet_mdio_remove(struct xgene_enet_pdata *pdata)
{
	struct mii_bus *mdio_bus;

	mdio_bus = pdata->mdio_bus;
	mdiobus_unregister(mdio_bus);
	mdiobus_free(mdio_bus);
	pdata->mdio_bus = NULL;

	return 0;
}

struct xgene_mac_ops xgene_sgmac_ops = {
	.type = XGENE_SGMAC,
	.init = xgene_sgmac_init,
	.reset = xgene_sgmac_reset,
	.enable = xgene_sgmac_enable,
	.disable = xgene_sgmac_disable,
	.get_stats = xgene_sgmac_get_stats,
	.set_mac_addr = xgene_sgmac_set_mac_addr,
	.set_mss = xgene_sgmac_set_mss,
	.cle_bypass = xgene_enet_cle_bypass,
	.mdio_config = xgene_enet_mdio_config,
	.mdio_remove = xgene_enet_mdio_remove,
	.port_reset = xgene_enet_reset,
	.port_shutdown = xgene_enet_shutdown
};

struct xgene_enet_rd_wr_ops xgene_sgmac_rd_wr_ops = {
	.rd_stats = xgene_enet_rd_mcx_stats,
	.rd_mac = xgene_enet_rd_mcx_mac,
	.rd_mac_csr = xgene_enet_rd_mcx_csr,
	.rd_diag_csr = xgene_enet_rd_diag_csr,
	.rd_ring_if = xgene_enet_rd_ring_if,
	.rd_clkrst_csr = xgene_enet_rd_clkrst_csr,
	.rd_enet_csr = xgene_enet_rd_csr,
	.wr_mac = xgene_enet_wr_mcx_mac,
	.wr_mac_csr = xgene_enet_wr_mcx_csr,
	.wr_diag_csr = xgene_enet_wr_diag_csr,
	.wr_ring_if = xgene_enet_wr_ring_if,
	.wr_clkrst_csr = xgene_enet_wr_clkrst_csr,
	.wr_enet_csr = xgene_enet_wr_csr,
	.mii_phy_read = xgene_mii_phy_read,
	.mii_phy_write = xgene_mii_phy_write
};
