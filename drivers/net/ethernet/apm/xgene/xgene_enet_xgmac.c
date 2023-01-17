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
#include "xgene_enet_xgmac.h"

static inline void xgene_enet_wr_csr(struct xgene_enet_pdata *pdata,
				     u32 offset, u32 val)
{
	void *addr = pdata->eth_csr_addr + offset;
	iowrite32(val, addr);
}

static inline void xgene_enet_wr_clkrst_csr(struct xgene_enet_pdata *pdata,
				     u32 offset, u32 val)
{
	void *addr = pdata->base_addr + BLOCK_ETH_CLKRST_CSR_OFFSET + offset;
	iowrite32(val, addr);
}

static inline void xgene_enet_wr_ring_if(struct xgene_enet_pdata *pdata,
				     u32 offset, u32 val)
{
	void *addr = pdata->eth_ring_if_addr + offset;
	iowrite32(val, addr);
}

static inline void xgene_enet_wr_diag_csr(struct xgene_enet_pdata *pdata,
					  u32 offset, u32 val)
{
	void *addr = pdata->eth_diag_csr_addr + offset;
	iowrite32(val, addr);
}

static inline void xgene_enet_wr_axg_csr(struct xgene_enet_pdata *pdata,
					 u32 offset, u32 val)
{
	void *addr = pdata->axg_mac_csr_addr + offset;
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

static void xgene_enet_wr_axg_mac(struct xgene_enet_pdata *pdata,
					 u32 wr_addr, u32 wr_data)
{
	void *addr, *wr, *cmd, *cmd_done;
	int ret;

	addr = pdata->axg_mac_addr + MAC_ADDR_REG_OFFSET;
	wr = pdata->axg_mac_addr + MAC_WRITE_REG_OFFSET;
	cmd = pdata->axg_mac_addr + MAC_COMMAND_REG_OFFSET;
	cmd_done = pdata->axg_mac_addr + MAC_COMMAND_DONE_REG_OFFSET;

	ret = xgene_enet_wr_indirect(addr, wr, cmd, cmd_done, wr_addr, wr_data);
	if (!ret)
		netdev_err(pdata->ndev, "AXG mac write failed, addr: %04x",
			   wr_addr);
}

static inline void xgene_enet_rd_csr(struct xgene_enet_pdata *pdata,
				     u32 offset, u32 *val)
{
	void *addr = pdata->eth_csr_addr + offset;
	*val = ioread32(addr);
}

static inline void xgene_enet_rd_clkrst_csr(struct xgene_enet_pdata *pdata,
				     u32 offset, u32 *val)
{
	void *addr = pdata->base_addr + BLOCK_ETH_CLKRST_CSR_OFFSET + offset;
	*val = ioread32(addr);
}

static inline void xgene_enet_rd_ring_if(struct xgene_enet_pdata *pdata,
		u32 offset, u32 *val)
{
	void *addr = pdata->eth_ring_if_addr + offset;
	*val = ioread32(addr);
}

static inline void xgene_enet_rd_diag_csr(struct xgene_enet_pdata *pdata,
					  u32 offset, u32 *val)
{
	void *addr = pdata->eth_diag_csr_addr + offset;
	*val = ioread32(addr);
}

static inline void xgene_enet_rd_axg_csr(struct xgene_enet_pdata *pdata,
					 u32 offset, u32 *val)
{
	void *addr = pdata->axg_mac_csr_addr + offset;
	*val = ioread32(addr);
}

static inline u32 xgene_enet_rd_indirect(void *addr, void *rd, void *cmd,
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

static inline void xgene_enet_rd_axg_mac(struct xgene_enet_pdata *pdata,
					 u32 rd_addr, u32 *rd_data)
{
	void *addr, *rd, *cmd, *cmd_done;
	int ret;

	addr = pdata->axg_mac_addr + MAC_ADDR_REG_OFFSET;
	rd = pdata->axg_mac_addr + MAC_READ_REG_OFFSET;
	cmd = pdata->axg_mac_addr + MAC_COMMAND_REG_OFFSET;
	cmd_done = pdata->axg_mac_addr + MAC_COMMAND_DONE_REG_OFFSET;

	ret = xgene_enet_rd_indirect(addr, rd, cmd, cmd_done, rd_addr, rd_data);
	if (!ret)
		netdev_err(pdata->ndev, "AXG mac read failed, addr: %04x",
			   rd_addr);
}

static inline void xgene_enet_rd_axg_stats(struct xgene_enet_pdata *pdata,
					   u32 rd_addr, u32 *rd_data)
{
	void *addr, *rd, *cmd, *cmd_done;
	int ret;

	addr = pdata->axg_stats_addr + STAT_ADDR_REG_OFFSET;
	rd = pdata->axg_stats_addr + STAT_READ_REG_OFFSET;
	cmd = pdata->axg_stats_addr + STAT_COMMAND_REG_OFFSET;
	cmd_done = pdata->axg_stats_addr + STAT_COMMAND_DONE_REG_OFFSET;

	ret = xgene_enet_rd_indirect(addr, rd, cmd, cmd_done, rd_addr, rd_data);
	if (!ret)
		netdev_err(pdata->ndev, "AXG stats read failed, addr: %04x",
			   rd_addr);
}

static void xgene_xgmac_set_mac_addr(struct xgene_enet_pdata *pdata)
{
	u32 addr0, addr1;
	unsigned char *dev_addr = pdata->ndev->dev_addr;

	addr0 = (dev_addr[3] << 24) | (dev_addr[2] << 16) |
		(dev_addr[1] << 8) | dev_addr[0];
	addr1 = (dev_addr[5] << 24) | (dev_addr[4] << 16);

	xgene_enet_wr_axg_mac(pdata, HSTMACADR_LSW_ADDR, addr0);
	xgene_enet_wr_axg_mac(pdata, HSTMACADR_MSW_ADDR, addr1);
}

static void xgene_xgmac_set_mss(struct xgene_enet_pdata *pdata)
{
	xgene_enet_wr_csr(pdata, XG_TSIF_MSS_REG0_ADDR, pdata->mss);
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

static void xgene_xgmac_reset(struct xgene_enet_pdata *pdata)
{
	xgene_enet_wr_axg_mac(pdata, MAC_CONFIG_1_ADDR, BIT(31));
	xgene_enet_wr_axg_mac(pdata, MAC_CONFIG_1_ADDR, 0);
}

static void xgene_xgmac_init(struct xgene_enet_pdata *pdata)
{
	u32 data;

	xgene_xgmac_reset(pdata);

	data = HSTTCTLEN | HSTTFEN | HSTRFEN | HSTPPEN | HSTDRPLT64;
	xgene_enet_wr_axg_mac(pdata, AXGMAC_CONFIG_1, data);

	xgene_xgmac_set_mac_addr(pdata);

	/* Enable drop if FP not available */
	xgene_enet_rd_csr(pdata, XG_RSIF_CONFIG_REG_ADDR, &data);
	data |= CFG_RSIF_FPBUFF_TIMEOUT_EN;
	xgene_enet_wr_csr(pdata, XG_RSIF_CONFIG_REG_ADDR, data);
}

/* Start Statistics related functions */
static void xgene_gmac_get_eth_combined_stats(struct xgene_enet_pdata *pdata,
				    struct xgene_enet_frame_stats *eth_combined_stats)
{
        u32 counter;

        /* Read Stats */
        xgene_enet_rd_axg_stats(pdata, TR64_ADDR, &counter);
        eth_combined_stats->c_64B_frames += counter;

        xgene_enet_rd_axg_stats(pdata, TR127_ADDR, &counter);
        eth_combined_stats->c_65_127B_frames += counter;

        xgene_enet_rd_axg_stats(pdata, TR255_ADDR, &counter);
        eth_combined_stats->c_128_255B_frames += counter;

        xgene_enet_rd_axg_stats(pdata, TR511_ADDR, &counter);
        eth_combined_stats->c_256_511B_frames += counter;

        xgene_enet_rd_axg_stats(pdata, TR1K_ADDR, &counter);
        eth_combined_stats->c_512_1023B_frames += counter;

        xgene_enet_rd_axg_stats(pdata, TRMAX_ADDR, &counter);
        eth_combined_stats->c_1024_1518B_frames += counter;

        xgene_enet_rd_axg_stats(pdata, TRMGV_ADDR, &counter);
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
	xgene_enet_rd_axg_stats(pdata, RBYT_ADDR, &counter);
	rx_stats->rx_byte_count += counter;

	xgene_enet_rd_axg_stats(pdata, RPKT_ADDR, &counter);
	rx_stats->rx_packet_count += counter;

	xgene_enet_rd_axg_stats(pdata, RFCS_ADDR, &counter);
	rx_stats->rx_fcs_err_count += counter;

	xgene_enet_rd_axg_stats(pdata, RMCA_ADDR, &counter);
	rx_stats->rx_multicast_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RBCA_ADDR, &counter);
	rx_stats->rx_broadcast_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RXCF_ADDR, &counter);
	rx_stats->rx_cntrl_frame_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RXPF_ADDR, &counter);
	rx_stats->rx_pause_frame_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RXUO_ADDR, &counter);
	rx_stats->rx_unknown_op_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RALN_ADDR, &counter);
	rx_stats->rx_alignment_err_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RFLR_ADDR, &counter);
	rx_stats->rx_frm_len_err_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RCDE_ADDR, &counter);
	rx_stats->rx_code_err_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RCSE_ADDR, &counter);
	rx_stats->rx_false_carrier_count += counter;

	xgene_enet_rd_axg_stats(pdata, RUND_ADDR, &counter);
	rx_stats->rx_undersize_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, ROVR_ADDR, &counter);
	rx_stats->rx_oversize_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, RFRG_ADDR, &counter);
	rx_stats->rx_fragment_count += counter;

	xgene_enet_rd_axg_stats(pdata, RJBR_ADDR, &counter);
	rx_stats->rx_jabber_count += counter;

	xgene_enet_rd_axg_stats(pdata, RDRP_ADDR, &counter);
	rx_stats->rx_drop_pkt_count += counter;

	if ((pdata->intf == XGENE_SC_XGENET_1) ||
		(pdata->intf == XGENE_SM_XGENET_1))
		xgene_enet_rd_axg_csr(pdata, ICM_ECM_DROP_COUNT_REG1, &counter);
	else
		xgene_enet_rd_axg_csr(pdata, ICM_ECM_DROP_COUNT_REG0, &counter);

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
	xgene_enet_rd_axg_stats(pdata, TBYT_ADDR, &counter);
	tx_stats->tx_byte_count += counter;

	xgene_enet_rd_axg_stats(pdata, TPKT_ADDR, &counter);
	tx_stats->tx_packet_count += counter;

	xgene_enet_rd_axg_stats(pdata, TMCA_ADDR, &counter);
	tx_stats->tx_multicast_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TBCA_ADDR, &counter);
	tx_stats->tx_broadcast_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TXCF_ADDR, &counter);
	tx_stats->tx_cntrl_frame_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TXPF_ADDR, &counter);
	tx_stats->tx_pause_frame_count += counter;

	xgene_enet_rd_axg_stats(pdata, TDFR_ADDR, &counter);
	tx_stats->tx_deferral_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TEDF_ADDR, &counter);
	tx_stats->tx_exesiv_def_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TSCL_ADDR, &counter);
	tx_stats->tx_single_coll_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TMCL_ADDR, &counter);
	tx_stats->tx_multi_coll_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TLCL_ADDR, &counter);
	tx_stats->tx_late_coll_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TXCL_ADDR, &counter);
	tx_stats->tx_exesiv_coll_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TNCL_ADDR, &counter);
	tx_stats->tx_toll_coll_pkt_count += counter;

	xgene_enet_rd_axg_stats(pdata, TPFH_ADDR, &counter);
	tx_stats->tx_pause_frm_hon_count += counter;

	xgene_enet_rd_axg_stats(pdata, TDRP_ADDR, &counter);
	tx_stats->tx_drop_frm_count += counter;

	xgene_enet_rd_axg_stats(pdata, TJBR_ADDR, &counter);
	tx_stats->tx_jabber_frm_count += counter;

	xgene_enet_rd_axg_stats(pdata, TFCS_ADDR, &counter);
	tx_stats->tx_fcs_err_frm_count += counter;

	xgene_enet_rd_axg_stats(pdata, TXCF_ADDR, &counter);
	tx_stats->tx_control_frm_count += counter;

	xgene_enet_rd_axg_stats(pdata, TOVR_ADDR, &counter);
	tx_stats->tx_oversize_frm_count += counter;

	xgene_enet_rd_axg_stats(pdata, TUND_ADDR, &counter);
	tx_stats->tx_undersize_frm_count += counter;

	xgene_enet_rd_axg_stats(pdata, TFRG_ADDR, &counter);
	tx_stats->tx_fragments_frm_count += counter;

	if ((pdata->intf == XGENE_SC_XGENET_1) ||
		(pdata->intf == XGENE_SM_XGENET_1))
		xgene_enet_rd_axg_csr(pdata, ICM_ECM_DROP_COUNT_REG1, &counter);
	else
		xgene_enet_rd_axg_csr(pdata, ICM_ECM_DROP_COUNT_REG0, &counter);

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

static void xgene_xgmac_get_stats(struct xgene_enet_pdata *pdata)
{
	xgene_gmac_get_eth_combined_stats(pdata,
					  &pdata->stats.eth_combined_stats);
	xgene_gmac_get_rx_stats(pdata, &pdata->stats.rx_stats);
	xgene_gmac_get_tx_stats(pdata, &pdata->stats.tx_stats);
}

static void xgene_enet_config_ring_if_assoc(struct xgene_enet_pdata *pdata)
{
	u32 val = 0;

	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIWQASSOC_ADDR, val);
	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIFPQASSOC_ADDR, val);
	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIQMLITEWQASSOC_ADDR, val);
	xgene_enet_wr_ring_if(pdata, ENET_CFGSSQMIQMLITEFPQASSOC_ADDR, val);
}

static void xgene_enet_xgcle_bypass(struct xgene_enet_pdata *pdata,
				    u32 dst_ring_num, u32 fpsel,
				    bool enable)
{
	u32 cb;

	xgene_enet_rd_csr(pdata, XCLE_BYPASS_REG0_ADDR, &cb);
	
	if (enable)
    	cb |= CFG_CLE_BYPASS_EN0;
    else
		cb &= (~CFG_CLE_BYPASS_EN0);
	
	CFG_CLE_IP_PROTOCOL0_SET(&cb, 3);
	xgene_enet_wr_csr(pdata, XCLE_BYPASS_REG0_ADDR, cb);

	xgene_enet_rd_csr(pdata, XCLE_BYPASS_REG1_ADDR, &cb);
	cb = XCFG_CLE_DSTQID1_SET(cb, dst_ring_num);
	cb = XCFG_CLE_FPSEL1_SET(cb, fpsel);
	xgene_enet_wr_csr(pdata, XCLE_BYPASS_REG1_ADDR, cb);
}

static void xgene_xgmac_enable(struct xgene_enet_pdata *pdata)
{
	u32 data;

	xgene_enet_rd_axg_mac(pdata, AXGMAC_CONFIG_1, &data);
	data |= HSTRFEN;
	data |= HSTTFEN;
	xgene_enet_wr_axg_mac(pdata, AXGMAC_CONFIG_1, data);
}

static void xgene_xgmac_disable(struct xgene_enet_pdata *pdata)
{
	u32 data;

	xgene_enet_rd_axg_mac(pdata, AXGMAC_CONFIG_1, &data);
	data &= ~HSTRFEN;
	data &= ~HSTTFEN;
	xgene_enet_wr_axg_mac(pdata, AXGMAC_CONFIG_1, data);
}

static void xgene_xg_bypass_resume(struct xgene_enet_pdata *pdata)
{
	u32 data;

	xgene_enet_wr_csr(pdata, XG_CFG_BYPASS_ADDR, RESUME_TX);
	xgene_enet_wr_csr(pdata, XG_CFG_LINK_STS_ADDR, 0);
	xgene_enet_wr_csr(pdata, XG_CFG_LINK_AGGR_RESUME_0_ADDR, TX_PORT);

	xgene_enet_rd_csr(pdata, XG_ENET_SPARE_CFG_REG_ADDR, &data);
	data |= BIT(12);
	xgene_enet_wr_csr(pdata, XG_ENET_SPARE_CFG_REG_ADDR, data);
	data = 0x82;  /* Recommended value by hardware */
	xgene_enet_wr_csr(pdata, XG_ENET_SPARE_CFG_REG_1_ADDR, data);

	xgene_enet_wr_csr(pdata, XGENET_RX_DV_GATE_REG_0_ADDR, 0);
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

static void xgene_enet_xg_reset(struct xgene_enet_pdata *pdata)
{
	/* Reset QM */
	//FIXME: do this only for shadowcat
#if 0
	if (xgene_qmtm_enable(pdata))
		pr_err("+ QM reset failed\n");
#endif
	switch (pdata->intf) {
	case XGENE_SM_MENET:
		clk_prepare_enable(pdata->clk);
		clk_disable_unprepare(pdata->clk);
		clk_prepare_enable(pdata->clk);
		break;
	case XGENE_SC_XGENET_0:
	case XGENE_SC_XGENET_1:
	case XGENE_SM_XGENET_0:
	case XGENE_SM_XGENET_1:
	case XGENE_MN_XGENET_0:
		xgene_xg_clk_rst_cfg(pdata);
		break;
	default:
		break;
	}
	xgene_enet_ecc_init(pdata);
	xgene_enet_config_ring_if_assoc(pdata);
	xgene_xg_bypass_resume(pdata);
}

static void xgene_enet_xg_shutdown(struct xgene_enet_pdata *pdata)
{
	clk_disable_unprepare(pdata->clk);
}

struct xgene_mac_ops xgene_xgmac_ops = {
	.type = XGENE_XGMAC,
	.init = xgene_xgmac_init,
	.reset = xgene_xgmac_reset,
	.enable = xgene_xgmac_enable,
	.disable = xgene_xgmac_disable,
	.get_stats = xgene_xgmac_get_stats,
	.set_mac_addr = xgene_xgmac_set_mac_addr,
	.set_mss = xgene_xgmac_set_mss,
	.cle_bypass = xgene_enet_xgcle_bypass,
	.port_reset = xgene_enet_xg_reset,
	.port_shutdown = xgene_enet_xg_shutdown
};

struct xgene_enet_rd_wr_ops xgene_xgmac_rd_wr_ops = {
	.rd_stats = xgene_enet_rd_axg_stats,
	.rd_mac = xgene_enet_rd_axg_mac,
	.rd_mac_csr = xgene_enet_rd_axg_csr,
	.rd_diag_csr = xgene_enet_rd_diag_csr,
	.rd_ring_if = xgene_enet_rd_ring_if,
	.rd_clkrst_csr = xgene_enet_rd_clkrst_csr,
	.rd_enet_csr = xgene_enet_rd_csr,
	.wr_mac = xgene_enet_wr_axg_mac,
	.wr_mac_csr = xgene_enet_wr_axg_csr,
	.wr_diag_csr = xgene_enet_wr_diag_csr,
	.wr_ring_if = xgene_enet_wr_ring_if,
	.wr_clkrst_csr = xgene_enet_wr_clkrst_csr,
	.wr_enet_csr = xgene_enet_wr_csr,
	.mii_phy_read = NULL,
	.mii_phy_write = NULL
};

