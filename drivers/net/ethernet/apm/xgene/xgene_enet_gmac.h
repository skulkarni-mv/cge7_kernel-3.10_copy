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

#ifndef __XGENE_ENET_GMAC_H__
#define __XGENE_ENET_GMAC_H__

#include <linux/version.h>
#include <linux/of_mdio.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
/* Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
#define GENMASK(h, l)           (((U32_C(1) << ((h) - (l) + 1)) - 1) << (l))
#define GENMASK_ULL(h, l)       (((U64_C(1) << ((h) - (l) + 1)) - 1) << (l))

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0) */

#include "xgene_enet_main.h"

struct xgene_enet_pdata;
struct xgene_enet_stats;

/* clears and then set bits */
static inline void set_bits(u32 *dst, u32 val, u32 start, u32 len)
{
	u32 end = start + len - 1;
	u32 mask = GENMASK(end, start);

	*dst &= ~mask;
	*dst |= (val << start) & mask;
}

static inline u32 get_bits(u32 val, u32 start, u32 end)
{
	return (val & GENMASK(end, start)) >> start;
}

#define BUSY_MASK			BIT(0)
#define READ_CYCLE_MASK			BIT(0)
#define PHY_CONTROL_WR(src)		(((u32)(src)) & GENMASK(15, 0))

#define ENET_SRST_ADDR			0x0000
#define ENET_CLKEN_ADDR			0x0008
#define ENET_DSEN_ADDR			0x0010
#define ENET_SPARE_CFG_REG_ADDR		0x0750
#define ENET_SPARE_CFG_REG_1_ADDR	0x0190
#define RSIF_CONFIG_REG_ADDR		0x0010
#define RSIF_RAM_DBG_REG0_ADDR		0x0048
#define RGMII_REG_0_ADDR		0x07e0
#define RGMII_REG_1_ADDR		0x07e4
#define CFG_LINK_AGGR_RESUME_0_ADDR	0x07c8
#define CFG_LINK_AGGR_RESUME_1_ADDR	0x07cc
#define DEBUG_REG_ADDR			0x0700
#define TSIF_MSS_REG0_0_ADDR		0x0108
#define TSIF_MSS_REG0_1_ADDR		0x010c
#define CFG_BYPASS_ADDR			0x0294
#define CLE_BYPASS_REG0_0_ADDR		0x0490
#define CLE_BYPASS_REG1_0_ADDR		0x0494
#define CLE_BYPASS_REG0_1_ADDR		0x04c0
#define CLE_BYPASS_REG1_1_ADDR		0x04c4
#define CFG_RSIF_FPBUFF_TIMEOUT_EN	BIT(31)
#define RESUME_TX			BIT(0)
#define LINK_STS_SEL			BIT(0)
#define FORCE_EN			BIT(4)
#define LNKS				BIT(8)
#define CFG_SPEED_1250			BIT(24)
#define TX_PORT				BIT(0)
#define CFG_BYPASS_UNISEC_TX		BIT(2)
#define CFG_BYPASS_UNISEC_RX		BIT(1)
#define CFG_TXCLK_MUXSEL0_SET(dst, val)	set_bits(dst, val, 29, 3)
#define CFG_RXCLK_MUXSEL0_SET(dst, val)	set_bits(dst, val, 26, 3)
#define CFG_CLE_BYPASS_EN0		BIT(31)

#define CFG_CLE_IP_PROTOCOL0_SET(dst, val)	set_bits(dst, val, 16, 2)
#define CFG_CLE_DSTQID0_SET(dst, val)		set_bits(dst, val, 0, 12)
#define CFG_CLE_FPSEL0_SET(dst, val)		set_bits(dst, val, 16, 4)
#define CFG_MACMODE_SET(dst, val)		set_bits(dst, val, 18, 2)
#define CFG_WAITASYNCRD_SET(dst, val)		set_bits(dst, val, 0, 16)

#define ICM_CONFIG0_REG_0_ADDR		0x00000400
#define ICM_CONFIG0_REG_1_ADDR		0x00000408
#define ICM_CONFIG2_REG_0_ADDR		0x00000410
#define ICM_CONFIG2_REG_1_ADDR		0x00000414
#define ECM_CONFIG0_REG_0_ADDR		0x00000500
#define ECM_CONFIG0_REG_1_ADDR		0x00000504
#define ICM_ECM_DROP_COUNT_REG0		0x00000508
#define ICM_ECM_DROP_COUNT_REG1		0x0000050c
#define RX_DV_GATE_REG_0_ADDR		0x000005fc
#define RX_DV_GATE_REG_1_ADDR		0x00000600
#define TX_DV_GATE_EN			BIT(2)
#define RX_DV_GATE_EN			BIT(1)
#define RESUME_RX			BIT(0)

#define ENET_CFGSSQMIDBGCTRL_ADDR		0x000000c4
#define PBID(dst, val)			set_bits(dst, val, 12, 6)
#define POP				BIT(7)
#define NACK				BIT(11)
#define BUFFERADDR(dst, val)		set_bits(dst, val, 0, 6)
#define LAST				BIT(10)

#define ICM_DROP_COUNT(src)		get_bits(src, 0, 15)
#define ECM_DROP_COUNT(src)		get_bits(src, 16, 31)

#define ENET_CFGSSQMIDBGDATA_ADDR		0x000000d8
#define ENET_CFGSSQMIWQASSOC_ADDR		0x000000e0
#define ENET_CFGSSQMIFPQASSOC_ADDR		0x000000dc
#define ENET_CFGSSQMIQMLITEFPQASSOC_ADDR	0x000000f0
#define ENET_CFGSSQMIQMLITEWQASSOC_ADDR		0x000000f4
#define ENET_CFGSSQMIQMHOLD_ADDR		0x000000f8
#define QMLITE_HOLD_EN				BIT(31)
#define ENET_STSSSQMIFPNUMENTRIES0		0x00000030
#define ENET_STSSSQMIWQNUMENTRIES0		0x00000050

#define ENET_CFG_MEM_RAM_SHUTDOWN_ADDR		0x00000070
#define ENET_BLOCK_MEM_RDY_ADDR			0x00000074
#define MAC_CONFIG_1_ADDR			0x00000000
#define MAC_CONFIG_2_ADDR			0x00000004
#define MAX_FRAME_LEN_ADDR			0x00000010
#define INTERFACE_CONTROL_ADDR			0x00000038
#define STATION_ADDR0_ADDR			0x00000040
#define STATION_ADDR1_ADDR			0x00000044
#define ENET_INTERFACE_MODE2_SET(dst, val)	set_bits(dst, val, 8, 2)
#define SCAN_CYCLE_MASK_SET(dst, src) \
	(((dst) & ~BIT(1)) | (((u32)(src)) & BIT(1)))
#define SOFT_RESET_MASK			BIT(31)
#define SOFT_RESET			BIT(31)
#define SIM_RESET			BIT(30)
#define RESET_RX_MC			BIT(19)
#define RESET_TX_MC			BIT(18)
#define RESET_RX_FUN			BIT(17)
#define RESET_TX_FUN			BIT(16)
#define TX_EN				BIT(0)
#define RX_EN				BIT(2)
#define ENET_LHD_MODE			BIT(25)
#define ENET_GHD_MODE			BIT(26)
#define FULL_DUPLEX			BIT(0)
#define CRC_EN				BIT(1)
#define PAD_CRC				BIT(2)
#define SCAN_AUTO_INCR			BIT(5)
#define PHY_ADDR_WR(src)		(((u32) (src) < 8) & GENMASK(12, 8))
#define PHY_ADDR_SET(dst, src) \
	(((dst) & ~GENMASK(12, 8)) | (((u32) (src) << 8) & GENMASK(12, 8)))
#define REG_ADDR_WR(src)		(((u32) (src)) & GENMASK(4, 0))
#define REG_ADDR_SET(dst, src) \
	(((dst) & ~GENMASK(4, 0)) | (((u32)(src)) & GENMASK(4, 0)))
#define RESET_TX_FUN1_WR(src)		BIT(16)
#define RESET_RX_FUN1_WR(src)		BIT(17)
#define RESET_TX_MC1_WR(src)		BIT(18)
#define RESET_RX_MC1_WR(src)		BIT(19)
#define SIM_RESET1_WR(src)		BIT(30)
#define SOFT_RESET1_WR(src)		BIT(31)
#define TX_EN1_WR(src)			BIT(0)
#define RX_EN1_WR(src)			BIT(2)
#define ENET_LHD_MODE_WR(src)		BIT(25)
#define ENET_GHD_MODE_WR(src)		BIT(26)
#define FULL_DUPLEX2_WR(src)		BIT(0)
#define ENET_INTERFACE_MODE2_WR(src)	(((u32) (src) << 8) & GENMASK(9, 8))
#define PREAMBLE_LENGTH2_WR(src)	(((u32) (src) << 12) & GENMASK(15, 12))
#define MAX_FRAME_LEN_WR(src)		(((u32) (src)) & GENMASK(15, 0))
#define MGMT_CLOCK_SEL_SET(dst, val)		set_bits(dst, val, 0, 3)
#define SCAN_AUTO_INCR_MASK		0x00000020

#define TR64_ADDR			0x00000020
#define TR127_ADDR			0x00000021
#define TR255_ADDR			0x00000022
#define TR511_ADDR			0x00000023
#define TR1K_ADDR			0x00000024
#define TRMAX_ADDR			0x00000025
#define TRMGV_ADDR			0x00000026

#define RBYT_ADDR			0x00000027
#define RPKT_ADDR			0x00000028
#define RFCS_ADDR			0x00000029
#define RMCA_ADDR			0x0000002a
#define RBCA_ADDR			0x0000002b
#define RXCF_ADDR			0x0000002c
#define RXPF_ADDR			0x0000002d
#define RXUO_ADDR			0x0000002e
#define RALN_ADDR			0x0000002f
#define RFLR_ADDR			0x00000030
#define RCDE_ADDR			0x00000031
#define RCSE_ADDR			0x00000032
#define RUND_ADDR			0x00000033
#define ROVR_ADDR			0x00000034
#define RFRG_ADDR			0x00000035
#define RJBR_ADDR			0x00000036
#define RDRP_ADDR			0x00000037

#define TBYT_ADDR			0x00000038
#define TPKT_ADDR			0x00000039
#define TMCA_ADDR			0x0000003a
#define TBCA_ADDR			0x0000003b
#define TXPF_ADDR			0x0000003c
#define TDFR_ADDR			0x0000003d
#define TEDF_ADDR			0x0000003e
#define TSCL_ADDR			0x0000003f
#define TMCL_ADDR			0x00000040
#define TLCL_ADDR			0x00000041
#define TXCL_ADDR			0x00000042
#define TNCL_ADDR			0x00000043
#define TPFH_ADDR			0x00000044
#define TDRP_ADDR			0x00000045
#define TJBR_ADDR			0x00000046
#define TFCS_ADDR			0x00000047
#define TXCF_ADDR			0x00000048
#define TOVR_ADDR			0x00000049
#define TUND_ADDR			0x0000004a
#define TFRG_ADDR			0x0000004b

#define TX_RX_64B_FRAME_CNTR_MASK	0x7fffffff
#define TX_RX_127B_FRAME_CNTR_MASK	0x7fffffff
#define TX_RX_255B_FRAME_CNTR_MASK	0x7fffffff
#define TX_RX_511B_FRAME_CNTR_MASK	0x7fffffff
#define TX_RX_1KB_FRAME_CNTR_MASK	0x7fffffff
#define TX_RX_MAXB_FRAME_CNTR_MASK	0x7fffffff
#define TRMGV_MASK			0x7fffffff

#define RX_BYTE_CNTR_MASK		0x7fffffff
#define RX_PKT_CNTR_MASK		0x7fffffff
#define RX_FCS_ERROR_CNTR_MASK		0x0000ffff
#define RX_MC_PKT_CNTR_MASK		0x7fffffff
#define RX_BC_PKT_CNTR_MASK		0x7fffffff
#define RX_CTRL_PKT_CNTR_MASK		0x0000ffff
#define RX_PAUSE_PKT_CNTR_MASK		0x0000ffff
#define RX_UNK_OPCODE_CNTR_MASK		0x0000ffff
#define RX_ALIGN_ERR_CNTR_MASK		0x0000ffff
#define RX_LEN_ERR_CNTR_MASK		0x0000ffff
#define RX_CODE_ERR_CNTR_MASK		0x0000ffff
#define RX_FALSE_CARRIER_CNTR_MASK	0x0000ffff
#define RX_UNDRSIZE_PKT_CNTR_MASK	0x0000ffff
#define RX_OVRSIZE_PKT_CNTR_MASK	0x0000ffff
#define RX_FRAG_CNTR_MASK		0x0000ffff
#define RX_JABBER_CNTR_MASK		0x0000ffff
#define RX_DROPPED_PKT_CNTR_MASK	0x0000ffff

#define TX_BYTE_CNTR_MASK		0x7fffffff
#define TX_PKT_CNTR_MASK		0x7fffffff
#define TX_MC_PKT_CNTR_MASK		0x7fffffff
#define TX_BC_PKT_CNTR_MASK		0x7fffffff
#define TX_PAUSE_PKT_CNTR_MASK		0x0000ffff
#define TX_DEFER_PKT_CNTR_MASK		0x7fffffff
#define TX_EXC_DEFER_PKT_CNTR_MASK	0x7fffffff
#define TX_COL_PKT_CNTR_MASK		0x7fffffff
#define TX_MUL_COL_PKT_CNTR_MASK	0x7fffffff
#define TX_LATE_COL_PKT_CNTR_MASK	0x7fffffff
#define TX_EXC_COL_PKT_CNTR_MASK	0x7fffffff
#define TX_TOTAL_COL_CNTR_MASK		0x7fffffff
#define TX_PAUSE_FRAME_CNTR_MASK	0x0000ffff
#define TX_DROP_FRAME_CNTR_MASK		0x0000ffff
#define TX_JABBER_FRAME_CNTR_MASK	0x00000fff
#define TX_FCS_ERROR_CNTR_MASK		0x00000fff
#define TX_CTRL_FRAME_CNTR_MASK		0x00000fff
#define TX_OVRSIZE_FRAME_CNTR_MASK	0x00000fff
#define TX_UNDSIZE_FRAME_CNTR_MASK	0x00000fff
#define TX_FRAG_CNTR_MASK		0x00000fff

#define RX_FLOW_EN	BIT(5)
#define TX_FLOW_EN	BIT(4)

#define MCX_RD_RX_FLOW_EN(src)	((src & GENMASK(5, 5)) >> 5)
#define MCX_RD_TX_FLOW_EN(src)	((src & GENMASK(4, 4)) >> 4)

enum xgene_enet_cmd {
	XGENE_ENET_WR_CMD = 0x80000000,
	XGENE_ENET_RD_CMD = 0x40000000
};

extern struct xgene_mac_ops xgene_gmac_ops;
extern struct xgene_enet_rd_wr_ops xgene_gmac_rd_wr_ops;

#endif /* __XGENE_ENET_GMAC_H__ */
