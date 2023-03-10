/* Applied Micro X-Gene SoC Ethernet Driver
 *
 * Copyright (c) 2014, Applied Micro Circuits Corporation
 * Authors: Iyappan Subramanian <isubramanian@apm.com>
 *	    Ravi Patel <rapatel@apm.com>
 *	    Keyur Chudgar <kchudgar@apm.com>
 *	    Hrishikesh Karanjikar <hkaranjikar@apm.com>
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
#include "xgene_enet_gmac.h"

static void xgene_enet_wr_csr(struct xgene_enet_pdata *pdata,
			      u32 offset, u32 val)
{
	void *addr = pdata->eth_csr_addr + offset;
	iowrite32(val, addr);
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

static void xgene_genericmiiphy_write(struct xgene_enet_pdata *pdata, u8 phy_id,
			       u32 reg, u16 data)
{
	u32 addr, wr_data, done;

	addr = PHY_ADDR_WR(phy_id) | REG_ADDR_WR(reg);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_ADDRESS_ADDR, addr);

	wr_data = PHY_CONTROL_WR(data);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_CONTROL_ADDR, wr_data);

	usleep_range(20, 30);		/* wait 20 us for completion */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_INDICATORS_ADDR, &done);
	if (done & BUSY_MASK)
		netdev_err(pdata->ndev, "MII_MGMT write failed\n");
}

static void xgene_genericmiiphy_read(struct xgene_enet_pdata *pdata, u8 phy_id,
			      u32 reg, u32 *data)
{
	u32 addr, done;

	addr = PHY_ADDR_WR(phy_id) | REG_ADDR_WR(reg);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_ADDRESS_ADDR, addr);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_COMMAND_ADDR, READ_CYCLE_MASK);

	usleep_range(20, 30);		/* wait 20 us for completion */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_INDICATORS_ADDR, &done);
	if (done & BUSY_MASK)
		netdev_err(pdata->ndev, "MII_MGMT read failed\n");

	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_STATUS_ADDR, data);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_COMMAND_ADDR, 0);
}

static void xgene_gmac_set_mss(struct xgene_enet_pdata *pdata)
{
	xgene_enet_wr_csr(pdata, TSIF_MSS_REG0_0_ADDR, pdata->mss);
}

static void xgene_gmac_set_mac_addr(struct xgene_enet_pdata *pdata)
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

static void xgene_gmac_phy_enable_scan_cycle(struct xgene_enet_pdata *pdata)
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

static void xgene_gmac_reset(struct xgene_enet_pdata *pdata)
{
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, SOFT_RESET);
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, 0);
}

static void rgmii_speed_set(struct xgene_enet_pdata *pdata)
{
	struct clk *parent = clk_get_parent(pdata->clk);

	switch (pdata->phy_speed) {
	case SPEED_1000:
		clk_set_rate(parent, 125000000);
		break;
	case SPEED_100:
		clk_set_rate(parent, 25000000);
		break;
	case SPEED_10:
		clk_set_rate(parent, 2500000);
		break;
	}
}

static void xgene_gmac_init(struct xgene_enet_pdata *pdata)
{
	u32 value, mc2;
	u32 intf_ctl, rgmii;
	u32 icm0, icm2;
	int speed = pdata->phy_speed;

	xgene_gmac_reset(pdata);

	if (pdata->intf == XGENE_MN_MENET) {
		xgene_enet_rd_mcx_csr(pdata, ICM_CONFIG0_REG_0_ADDR, &icm0);
		xgene_enet_rd_mcx_csr(pdata, ICM_CONFIG2_REG_0_ADDR, &icm2);
		xgene_enet_rd_csr(pdata, RGMII_REG_0_ADDR, &rgmii);
	} else {
		xgene_enet_rd_mcx_csr(pdata, ICM_CONFIG0_REG_1_ADDR, &icm0);
		xgene_enet_rd_mcx_csr(pdata, ICM_CONFIG2_REG_1_ADDR, &icm2);
		xgene_enet_rd_csr(pdata, RGMII_REG_1_ADDR, &rgmii);
	}
	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_2_ADDR, &mc2);
	xgene_enet_rd_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, &intf_ctl);

	rgmii_speed_set(pdata);
	switch (speed) {
	case SPEED_10:
		ENET_INTERFACE_MODE2_SET(&mc2, 1);
		intf_ctl &= !(ENET_LHD_MODE | ENET_GHD_MODE);
		CFG_MACMODE_SET(&icm0, 0);
		CFG_WAITASYNCRD_SET(&icm2, 500);
		rgmii &= ~CFG_SPEED_1250;
		break;
	case SPEED_100:
		ENET_INTERFACE_MODE2_SET(&mc2, 1);
		intf_ctl &= !ENET_GHD_MODE;
		intf_ctl |= ENET_LHD_MODE;
		CFG_MACMODE_SET(&icm0, 1);
		CFG_WAITASYNCRD_SET(&icm2, 80);
		rgmii &= ~CFG_SPEED_1250;
		break;
	default:
		ENET_INTERFACE_MODE2_SET(&mc2, 2);
		intf_ctl &= !ENET_LHD_MODE;
		intf_ctl |= ENET_GHD_MODE;
		CFG_MACMODE_SET(&icm0, 2);
		CFG_WAITASYNCRD_SET(&icm2, 0);
		CFG_TXCLK_MUXSEL0_SET(&rgmii, 1);
		CFG_RXCLK_MUXSEL0_SET(&rgmii, 1);
		rgmii |= CFG_SPEED_1250;
		xgene_enet_rd_csr(pdata, DEBUG_REG_ADDR, &value);
		value |= CFG_BYPASS_UNISEC_TX | CFG_BYPASS_UNISEC_RX;
		xgene_enet_wr_csr(pdata, DEBUG_REG_ADDR, value);
		break;
	}

	mc2 |= FULL_DUPLEX | CRC_EN | PAD_CRC;
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_2_ADDR, mc2);
	xgene_enet_wr_mcx_mac(pdata, INTERFACE_CONTROL_ADDR, intf_ctl);

	if (pdata->intf == XGENE_MN_MENET) {
		xgene_enet_wr_csr(pdata, RGMII_REG_0_ADDR, rgmii);
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG0_REG_0_ADDR, icm0);
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG2_REG_0_ADDR, icm2);
	} else {
		xgene_enet_wr_csr(pdata, RGMII_REG_1_ADDR, rgmii);
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG0_REG_1_ADDR, icm0);
		xgene_enet_wr_mcx_csr(pdata, ICM_CONFIG2_REG_1_ADDR, icm2);
	}

	xgene_gmac_set_mac_addr(pdata);

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

	if (pdata->intf == XGENE_MN_MENET) {
		/* Rx-Tx traffic resume */
		xgene_enet_wr_csr(pdata, CFG_LINK_AGGR_RESUME_0_ADDR, TX_PORT);
	} else {
		/* Rx-Tx traffic resume */
		xgene_enet_wr_csr(pdata, CFG_LINK_AGGR_RESUME_1_ADDR, TX_PORT);
	}
	if (pdata->intf == XGENE_MN_MENET)
		xgene_enet_rd_mcx_csr(pdata, RX_DV_GATE_REG_0_ADDR, &value);
	else
		xgene_enet_rd_mcx_csr(pdata, RX_DV_GATE_REG_1_ADDR, &value);
	value &= ~TX_DV_GATE_EN;
	value &= ~RX_DV_GATE_EN;
	value |= RESUME_RX;
	if (pdata->intf == XGENE_MN_MENET)
		xgene_enet_wr_mcx_csr(pdata, RX_DV_GATE_REG_0_ADDR, value);
	else
		xgene_enet_wr_mcx_csr(pdata, RX_DV_GATE_REG_1_ADDR, value);

	xgene_enet_wr_csr(pdata, CFG_BYPASS_ADDR, RESUME_TX);
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

static void xgene_gmac_get_stats(struct xgene_enet_pdata *pdata)
{
	xgene_gmac_get_eth_combined_stats(pdata,
					  &pdata->stats.eth_combined_stats);
	xgene_gmac_get_rx_stats(pdata, &pdata->stats.rx_stats);
	xgene_gmac_get_tx_stats(pdata, &pdata->stats.tx_stats);
}

static void xgene_enet_config_ring_if_assoc(struct xgene_enet_pdata *pdata)
{
	u32 val = 0xffffffff;

	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIWQASSOC_ADDR, val);
	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIFPQASSOC_ADDR, val);
	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIQMLITEWQASSOC_ADDR, val);
	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIQMLITEFPQASSOC_ADDR, val);
}

static void xgene_enet_cle_bypass(struct xgene_enet_pdata *pdata,
				  u32 dst_ring_num, u32 fpsel, bool enable)
{
	u32 cb;
	if (pdata->intf == XGENE_MN_MENET)
		xgene_enet_rd_csr(pdata, CLE_BYPASS_REG0_0_ADDR, &cb);
	else
		xgene_enet_rd_csr(pdata, CLE_BYPASS_REG0_1_ADDR, &cb);

	if (enable)
		cb |= CFG_CLE_BYPASS_EN0;
	else
		cb &= (~CFG_CLE_BYPASS_EN0);

	CFG_CLE_IP_PROTOCOL0_SET(&cb, 3);
	if (pdata->intf == XGENE_MN_MENET) {
		xgene_enet_wr_csr(pdata, CLE_BYPASS_REG0_0_ADDR, cb);
		xgene_enet_rd_csr(pdata, CLE_BYPASS_REG1_0_ADDR, &cb);
	} else {
		xgene_enet_wr_csr(pdata, CLE_BYPASS_REG0_1_ADDR, cb);
		xgene_enet_rd_csr(pdata, CLE_BYPASS_REG1_1_ADDR, &cb);
	}
	CFG_CLE_DSTQID0_SET(&cb, dst_ring_num);
	CFG_CLE_FPSEL0_SET(&cb, fpsel);
	if (pdata->intf == XGENE_MN_MENET)
		xgene_enet_wr_csr(pdata, CLE_BYPASS_REG1_0_ADDR, cb);
	else
		xgene_enet_wr_csr(pdata, CLE_BYPASS_REG1_1_ADDR, cb);
}

static void xgene_gmac_enable(struct xgene_enet_pdata *pdata)
{
	u32 data;

	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_1_ADDR, &data);
	data |= BIT(2);
	data |= BIT(0);
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, data | GENMASK(0, 0));
}

static void xgene_gmac_disable(struct xgene_enet_pdata *pdata)
{
	u32 data;

	xgene_enet_rd_mcx_mac(pdata, MAC_CONFIG_1_ADDR, &data);
	data &= ~BIT(2);
	data &= ~BIT(0);
	xgene_enet_wr_mcx_mac(pdata, MAC_CONFIG_1_ADDR, data & ~GENMASK(0, 0));
}

/* FIXME: move this to hw.c */
static void xgene_enet_reset(struct xgene_enet_pdata *pdata)
{
	u32 val;

	clk_prepare_enable(pdata->clk);
	clk_disable_unprepare(pdata->clk);
	clk_prepare_enable(pdata->clk);
	xgene_enet_ecc_init(pdata);
	if (pdata->intf != XGENE_MN_MENET && pdata->intf != XGENE_MN_RGMII1)
	       	xgene_enet_config_ring_if_assoc(pdata);

	/* Enable auto-incr for scanning */
	xgene_enet_rd_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, &val);
	val |= SCAN_AUTO_INCR_MASK;
	MGMT_CLOCK_SEL_SET(&val, 1);
	xgene_enet_wr_mcx_mac(pdata, MII_MGMT_CONFIG_ADDR, val);
}

/* FIXME: move this to hw.c */
static void xgene_enet_shutdown(struct xgene_enet_pdata *pdata)
{
	if (!IS_ERR(pdata->clk))
		clk_disable_unprepare(pdata->clk);
}

static int xgene_enet_mdio_read(struct mii_bus *bus, int mii_id, int regnum)
{
	struct xgene_enet_pdata *pdata = bus->priv;
	u32 val;

	xgene_genericmiiphy_read(pdata, mii_id, regnum, &val);
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
	xgene_genericmiiphy_write(pdata, mii_id, regnum, val);

	return 0;
}

static void xgene_enet_adjust_link(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct phy_device *phydev = pdata->phy_dev;
	bool status_change = false;

	if (phydev->link && pdata->phy_speed != phydev->speed) {
		pdata->phy_speed = phydev->speed;
		xgene_gmac_init(pdata);
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
		xgene_gmac_enable(pdata);
	else
		xgene_gmac_disable(pdata);
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
				 0, PHY_INTERFACE_MODE_RGMII_ID);
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
	xgene_gmac_phy_enable_scan_cycle(pdata);

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

struct xgene_mac_ops xgene_gmac_ops = {
	.type = XGENE_GMAC,
	.init = xgene_gmac_init,
	.reset = xgene_gmac_reset,
	.enable = xgene_gmac_enable,
	.disable = xgene_gmac_disable,
	.get_stats = xgene_gmac_get_stats,
	.set_mac_addr = xgene_gmac_set_mac_addr,
	.set_mss = xgene_gmac_set_mss,
	.cle_bypass = xgene_enet_cle_bypass,
	.mdio_config = xgene_enet_mdio_config,
	.mdio_remove = xgene_enet_mdio_remove,
	.port_reset = xgene_enet_reset,
	.port_shutdown = xgene_enet_shutdown
};

struct xgene_enet_rd_wr_ops xgene_gmac_rd_wr_ops = {
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
	.mii_phy_read = xgene_genericmiiphy_read,
	.mii_phy_write = xgene_genericmiiphy_write
};
