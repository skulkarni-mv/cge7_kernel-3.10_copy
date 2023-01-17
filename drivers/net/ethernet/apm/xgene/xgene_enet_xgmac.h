#ifndef __XGENE_ENET_XGMAC_H__
#define __XGENE_ENET_XGMAC_H__

#define XGENET_SRST_ADDR		0x0000
#define XGENET_CLKEN_ADDR		0x0008

#define XGENET_CONFIG_REG_ADDR		0x0020
#define XG_ENET_SPARE_CFG_REG_ADDR	0x040c
#define XG_ENET_SPARE_CFG_REG_1_ADDR	0x0410
#define XG_RSIF_CONFIG_REG_ADDR		0x00a0
#define XG_RSIF_RAM_DBG_REG0_ADDR	0x00e8
#define XG_CFG_BYPASS_ADDR		0x0204
#define XG_CFG_LINK_STS_ADDR		0x0210
#define XG_CFG_LINK_AGGR_RESUME_0_ADDR	0x0214
#define XG_LINK_STATUS_ADDR		0x0228
#define XG_TSIF_MSS_REG0_ADDR		0x02a4
#define XCLE_BYPASS_REG0_ADDR           0x0160
#define XCLE_BYPASS_REG1_ADDR           0x0164
//#define XCLE_BYPASS_REG0_0_ADDR		0x0490
//#define XCLE_BYPASS_REG1_0_ADDR		0x0494
#define XG_CFG_LINK_STS_ADDR		0x0210
#define XG_DEBUG_REG_ADDR		0x0400
#define XGENET_RX_DV_GATE_REG_0_ADDR	0x0804
#define AXGMAC_CONFIG_0			0x0000
#define AXGMAC_CONFIG_1			0x0004
#define AXGMAC_CONFIG_2			0x0008
#define HSTMACRST			BIT(31)
#define HSTTCTLEN			BIT(31)
#define HSTTFEN				BIT(30)
#define HSTRCTLEN			BIT(29)
#define HSTRFEN				BIT(28)
#define HSTPPEN				BIT(7)
#define HSTDRPLT64			BIT(5)
#define HSTMACADR_LSW_ADDR		0x00000010
#define HSTMACADR_MSW_ADDR		0x00000014

#define XG_MCX_RX_DV_GATE_REG_0_ADDR	0x0004
#define XG_MCX_ICM_CONFIG0_REG_0_ADDR	0x00e0
#define XG_MCX_ICM_CONFIG2_REG_0_ADDR	0x00e8

#define XCFG_CLE_DSTQID1_SET(dst, src) \
	(((dst) & ~GENMASK(11, 0)) | (((u32) (src)) & GENMASK(11, 0)))
#define XCFG_CLE_FPSEL1_SET(dst, src) \
	(((dst) & ~GENMASK(19, 16)) | (((u32) (src) << 16) & GENMASK(19, 16)))
#define XCFG_CLE_NXTFPSEL1_SET(dst, src) \
	(((dst) & ~GENMASK(23, 20)) | (((u32) (src) << 20) & GENMASK(23, 20)))

#define XGENET_RESET_WR(src)                     (((u32)(src)<<1) & 0x00000002)
#define CSR_RESET_WR(src)                           (((u32)(src)) & 0x00000001)

#define XGENET_CLKEN_WR(src)                     (((u32)(src)<<1) & 0x00000002)
#define CSR_CLKEN_WR(src)                           (((u32)(src)) & 0x00000001)

#define CSR_CLK		BIT(0)
#define XGENET_CLK	BIT(1)
#define PCS_CLK		BIT(3)
#define AN_REF_CLK	BIT(4)
#define AN_CLK		BIT(5)
#define AD_CLK		BIT(6)

#define CSR_RST		BIT(0)
#define XGENET_RST	BIT(1)
#define PCS_RST		BIT(3)
#define AN_REF_RST	BIT(4)
#define AN_RST		BIT(5)
#define AD_RST		BIT(6)

#define AXG_RD_RX_FLOW_EN(src)	((src & GENMASK(29, 29)) >> 29)
#define AXG_RD_TX_FLOW_EN(src)	((src & GENMASK(31, 31)) >> 31)

#define INT_PHY_ADDR		0x1e
#define SGMII_TBI_CONTROL_ADDR	0x44
#define SGMII_CONTROL_ADDR	0x00
#define SGMII_STATUS_ADDR	0x04
#define AUTO_NEG_COMPLETE	BIT(5)
#define LINK_STATUS		BIT(2)

extern struct xgene_mac_ops xgene_xgmac_ops;
extern struct xgene_enet_rd_wr_ops xgene_xgmac_rd_wr_ops;

#endif /* __XGENE_ENET_XGMAC_H__ */
