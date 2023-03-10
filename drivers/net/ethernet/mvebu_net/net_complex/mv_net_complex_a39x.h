/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or on the worldwide web
at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.
*******************************************************************************/

#ifndef LINUX_MV_NETCOMPLEX_A39X_H
#define LINUX_MV_NETCOMPLEX_A39X_H

#define MV_NET_COMPLEX_NAME		"mv_net_complex"
#define MV_NET_COMPLEX_OFFSET		(mv_net_complex_vbase_addr)
#define MV_MISC_REGS_OFFSET             (mv_net_complex_misc_vbase_addr)
#define MV_COMMON_PHY_REGS_OFFSET       (mv_net_complex_phy_vbase_addr)
#define MV_IP_CONFIG_REGS_OFFSET        (mv_net_complex_phy_vbase_addr + 0x100)

#define MV_REG_READ(offset) \
				readl((void *)(offset))

#define MV_REG_WRITE(offset, val) \
				writel((val), (void *)(offset))

#define BIT0        0x00000001
#define BIT1        0x00000002
#define BIT2        0x00000004
#define BIT3        0x00000008
#define BIT4        0x00000010
#define BIT5        0x00000020
#define BIT6        0x00000040
#define BIT7        0x00000080
#define BIT8        0x00000100
#define BIT9        0x00000200
#define BIT10       0x00000400
#define BIT11       0x00000800
#define BIT12       0x00001000
#define BIT13       0x00002000
#define BIT14       0x00004000
#define BIT15       0x00008000
#define BIT16       0x00010000
#define BIT17       0x00020000
#define BIT18       0x00040000
#define BIT19       0x00080000
#define BIT20       0x00100000
#define BIT21       0x00200000
#define BIT22       0x00400000
#define BIT23       0x00800000
#define BIT24       0x01000000
#define BIT25       0x02000000
#define BIT26       0x04000000
#define BIT27       0x08000000
#define BIT28       0x10000000
#define BIT29       0x20000000
#define BIT30       0x40000000
#define BIT31       0x80000000

enum mvNetComplexTopology {
	MV_NETCOMP_GE_MAC0_2_RXAUI	=	BIT0,
	MV_NETCOMP_GE_MAC0_2_XAUI	=	BIT1,
	MV_NETCOMP_GE_MAC0_2_SGMII_L0	=	BIT2,
	MV_NETCOMP_GE_MAC0_2_SGMII_L1	=	BIT3,
	MV_NETCOMP_GE_MAC0_2_QSGMII	=	BIT4,
	MV_NETCOMP_GE_MAC1_2_SGMII_L1	=	BIT5,
	MV_NETCOMP_GE_MAC1_2_RGMII1	=	BIT6,
	MV_NETCOMP_GE_MAC1_2_SGMII_L2	=	BIT7,
	MV_NETCOMP_GE_MAC1_2_SGMII_L4	=	BIT8,
	MV_NETCOMP_GE_MAC1_2_QSGMII	=	BIT9,
	MV_NETCOMP_GE_MAC2_2_SGMII_L3	=	BIT10,
	MV_NETCOMP_GE_MAC2_2_SGMII_L5	=	BIT11,
	MV_NETCOMP_GE_MAC2_2_QSGMII	=	BIT12,
	MV_NETCOMP_GE_MAC3_2_SGMII_L4	=	BIT13,
	MV_NETCOMP_GE_MAC3_2_SGMII_L6	=	BIT14,
	MV_NETCOMP_GE_MAC3_2_QSGMII	=	BIT15
};

enum mvNetComplexPhase {
	MV_NETC_FIRST_PHASE,
	MV_NETC_SECOND_PHASE,
};

/******************************************************************************/
/* Power managment clock control1 */
#define MV_NETCOMP_CLOCK_GATING					(MV_NET_COMPLEX_OFFSET)

#define NETC_CLOCK_GATING_SRAM_X2_OFFSET			8
#define NETC_CLOCK_GATING_SRAM_X2_MASK				(0x1 << NETC_CLOCK_GATING_SRAM_X2_OFFSET)

#define NETC_CLOCK_GATING_SRAM_OFFSET				9
#define NETC_CLOCK_GATING_SRAM_MASK				(0x1 << NETC_CLOCK_GATING_SRAM_OFFSET)

#define NETC_CLOCK_GATING_PPC_CMAC_OFFSET			10
#define NETC_CLOCK_GATING_PPC_CMAC_MASK				(0x1 << NETC_CLOCK_GATING_PPC_CMAC_OFFSET)

#define NETC_CLOCK_GATING_PPC_PP_OFFSET				11
#define NETC_CLOCK_GATING_PPC_PP_MASK				(0x1 << NETC_CLOCK_GATING_PPC_PP_OFFSET)

#define NETC_CLOCK_GATING_PPC_NSS_OFFSET			12
#define NETC_CLOCK_GATING_PPC_NSS_MASK				(0x1 << NETC_CLOCK_GATING_PPC_NSS_OFFSET)

#define NETC_CLOCK_GATING_CMAC_OFFSET				13
#define NETC_CLOCK_GATING_CMAC_MASK				(0x1 << NETC_CLOCK_GATING_CMAC_OFFSET)

#define NETC_CLOCK_GATING_NSS_OFFSET				14
#define NETC_CLOCK_GATING_NSS_MASK				(0x1 << NETC_CLOCK_GATING_NSS_OFFSET)

#define NETC_CLOCK_GATING_QM2_OFFSET				15
#define NETC_CLOCK_GATING_QM2_MASK				(0x1 << NETC_CLOCK_GATING_QM2_OFFSET)

#define NETC_CLOCK_GATING_QM1_X2_OFFSET				16
#define NETC_CLOCK_GATING_QM1_X2_MASK				(0x1 << NETC_CLOCK_GATING_QM1_X2_OFFSET)

#define NETC_CLOCK_GATING_QM1_OFFSET				17
#define NETC_CLOCK_GATING_QM1_MASK				(0x1 << NETC_CLOCK_GATING_QM1_OFFSET)

/* System Soft Reset 1 */
#define MV_NETCOMP_SYSTEM_SOFT_RESET			(MV_NET_COMPLEX_OFFSET + 0x8)

#define NETC_GOP_SOFT_RESET_OFFSET				6
#define NETC_GOP_SOFT_RESET_MASK				(0x1 << NETC_GOP_SOFT_RESET_OFFSET)

#define NETC_NSS_SRAM_LOAD_CONF_OFFSET				10
#define NETC_NSS_SRAM_LOAD_CONF_MASK				(0x1 << NETC_NSS_SRAM_LOAD_CONF_OFFSET)

#define NETC_NSS_PPC_LOAD_CONF_OFFSET				12
#define NETC_NSS_PPC_LOAD_CONF_MASK				(0x1 << NETC_NSS_PPC_LOAD_CONF_OFFSET)

#define NETC_NSS_MACS_LOAD_CONF_OFFSET				14
#define NETC_NSS_MACS_LOAD_CONF_MASK				(0x1 << NETC_NSS_MACS_LOAD_CONF_OFFSET)

#define NETC_NSS_QM1_LOAD_CONF_OFFSET				17
#define NETC_NSS_QM1_LOAD_CONF_MASK				(0x1 << NETC_NSS_QM1_LOAD_CONF_OFFSET)

/* Ports Control 0 */
#define MV_NETCOMP_PORTS_CONTROL_0			(MV_NET_COMPLEX_OFFSET + 0x10)

#define NETC_CLK_DIV_PHASE_OFFSET			31
#define NETC_CLK_DIV_PHASE_MASK				(0x1 << NETC_CLK_DIV_PHASE_OFFSET)

#define NETC_GIG_RX_DATA_SAMPLE_OFFSET			29
#define NETC_GIG_RX_DATA_SAMPLE_MASK			(0x1 << NETC_GIG_RX_DATA_SAMPLE_OFFSET)

#define NETC_BUS_WIDTH_SELECT_OFFSET			1
#define NETC_BUS_WIDTH_SELECT_MASK			(0x1 << NETC_BUS_WIDTH_SELECT_OFFSET)

/* Ports Control 1 */
#define MV_NETCOMP_PORTS_CONTROL_1			(MV_NET_COMPLEX_OFFSET + 0x14)

#define NETC_PORT_GIG_RF_RESET_OFFSET(port)		(28 + port)
#define NETC_PORT_GIG_RF_RESET_MASK(port)		(0x1 << NETC_PORT_GIG_RF_RESET_OFFSET(port))

#define NETC_PORTS_ACTIVE_OFFSET(port)			(0 + port)
#define NETC_PORTS_ACTIVE_MASK(port)			(0x1 << NETC_PORTS_ACTIVE_OFFSET(port))

/* Networking Complex Control 0 */
#define MV_NETCOMP_CONTROL_0				(MV_NET_COMPLEX_OFFSET + 0x20)

#define NETC_CTRL_ENA_XAUI_OFFSET			11
#define NETC_CTRL_ENA_XAUI_MASK				(0x1 << NETC_CTRL_ENA_XAUI_OFFSET)

#define NETC_CTRL_ENA_RXAUI_OFFSET			10
#define NETC_CTRL_ENA_RXAUI_MASK			(0x1 << NETC_CTRL_ENA_RXAUI_OFFSET)

#define NETC_GBE_PORT1_MODE_OFFSET			1
#define NETC_GBE_PORT1_MODE_MASK			(0x1 << NETC_GBE_PORT1_MODE_OFFSET)

/* Networking Complex AMB Access Control 0 */
#define MV_NETCOMP_AMB_ACCESS_CTRL_0			(MV_NET_COMPLEX_OFFSET + 0xC0)

#define NETC_AMB_ACCESS_CTRL_OFFSET			24
#define NETC_AMB_ACCESS_CTRL_MASK			(0xff << NETC_AMB_ACCESS_CTRL_OFFSET)

/* QSGMII Control 1 */
#define MV_NETCOMP_QSGMII_CTRL_1			(MV_IP_CONFIG_REGS_OFFSET + 0x94)

#define NETC_QSGMII_CTRL_RSTN_OFFSET			31
#define NETC_QSGMII_CTRL_RSTN_MASK			(0x1 << NETC_QSGMII_CTRL_RSTN_OFFSET)

#define NETC_QSGMII_CTRL_V3ACTIVE_OFFSET		29
#define NETC_QSGMII_CTRL_V3ACTIVE_MASK			(0x1 << NETC_QSGMII_CTRL_V3ACTIVE_OFFSET)

#define NETC_QSGMII_CTRL_VERSION_OFFSET			28
#define NETC_QSGMII_CTRL_VERSION_MASK			(0x1 << NETC_QSGMII_CTRL_VERSION_OFFSET)

/* Function Enable Control 1 */
#define MV_NETCOMP_FUNCTION_ENABLE_CTRL_1			(MV_MISC_REGS_OFFSET + 0x88)

#define NETC_PACKET_PROCESS_OFFSET			1
#define NETC_PACKET_PROCESS_MASK			(0x1 << NETC_PACKET_PROCESS_OFFSET)

/* ComPhy Selector */
#define COMMON_PHYS_SELECTORS_REG			(MV_COMMON_PHY_REGS_OFFSET + 0xFC)

#define COMMON_PHYS_SELECTOR_LANE_OFFSET(lane)		(4 * lane)
#define COMMON_PHYS_SELECTOR_LANE_MASK(lane)		(0xF << COMMON_PHYS_SELECTOR_LANE_OFFSET(lane))

int mv_net_complex_dynamic_init(u32 net_comp_config);
int mv_net_complex_init(u32 net_comp_config, enum mvNetComplexPhase phase);
void mv_net_complex_nss_select(u32 val);

#endif /* LINUX_MV_NETCOMPLEX_A39X_H */
