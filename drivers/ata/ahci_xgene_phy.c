#include <linux/module.h>
#include <linux/version.h>
#include <linux/ahci_platform.h>
#include "ahci.h"

#define RXTX_REG7			0x00e
#define  RXTX_REG7_RESETB_RXD_MASK	0x00000100
#define  RXTX_REG7_RESETB_RXA_MASK	0x00000080
#define SATA_ENET_SDS_IND_CMD_REG	0x0000003c
#define  CFG_IND_WR_CMD_MASK		0x00000001
#define  CFG_IND_RD_CMD_MASK		0x00000002
#define  CFG_IND_CMD_DONE_MASK		0x00000004
#define  CFG_IND_ADDR_SET(dst, src) \
		(((dst) & ~0x003ffff0) | (((u32) (src) << 4) & 0x003ffff0))
#define SATA_ENET_SDS_IND_RDATA_REG	0x00000040
#define SATA_ENET_SDS_IND_WDATA_REG	0x00000044
#define SERDES_PLL_INDIRECT_OFFSET	0x0000
#define SERDES_PLL_REF_INDIRECT_OFFSET	0x20000
#define SERDES_INDIRECT_OFFSET		0x0400
#define SERDES_LANE_STRIDE		0x0200
#define SERDES_LANE_X4_STRIDE		0x30000

/* SATA host AHCI CSR */
#define PORTCFG				0x000000a4
#define  PORTADDR_SET(dst, src) \
		(((dst) & ~0x0000003f) | (((u32)(src)) & 0x0000003f))
#define PORTPHY1CFG		0x000000a8
#define PORTPHY1CFG_FRCPHYRDY_SET(dst, src) \
		(((dst) & ~0x00100000) | (((u32)(src) << 0x14) & 0x00100000))

static void ahci_sds_wr(void __iomem *csr_base, u32 indirect_cmd_reg,
		   	u32 indirect_data_reg, u32 addr, u32 data)
{
	unsigned long deadline = jiffies + HZ;
	u32 val;
	u32 cmd;

	cmd = CFG_IND_WR_CMD_MASK | CFG_IND_CMD_DONE_MASK;
	cmd = CFG_IND_ADDR_SET(cmd, addr);
	writel(data, csr_base + indirect_data_reg);
	readl(csr_base + indirect_data_reg); /* Force a barrier */
	writel(cmd, csr_base + indirect_cmd_reg);
	readl(csr_base + indirect_cmd_reg); /* Force a barrier */
	do {
		val = readl(csr_base + indirect_cmd_reg);
	} while (!(val & CFG_IND_CMD_DONE_MASK)&&
		 time_before(jiffies, deadline));
	if (!(val & CFG_IND_CMD_DONE_MASK))
		pr_err("SDS WR timeout at 0x%p offset 0x%08X value 0x%08X\n",
		       csr_base + indirect_cmd_reg, addr, data);
}

static void ahci_sds_rd(void __iomem *csr_base, u32 indirect_cmd_reg,
		   u32 indirect_data_reg, u32 addr, u32 *data)
{
	unsigned long deadline = jiffies + HZ;
	u32 val;
	u32 cmd;

	cmd = CFG_IND_RD_CMD_MASK | CFG_IND_CMD_DONE_MASK;
	cmd = CFG_IND_ADDR_SET(cmd, addr);
	writel(cmd, csr_base + indirect_cmd_reg);
	readl(csr_base + indirect_cmd_reg); /* Force a barrier */
	do {
		val = readl(csr_base + indirect_cmd_reg);
	} while (!(val & CFG_IND_CMD_DONE_MASK)&&
		 time_before(jiffies, deadline));
	*data = readl(csr_base + indirect_data_reg);
	if (!(val & CFG_IND_CMD_DONE_MASK))
		pr_err("SDS WR timeout at 0x%p offset 0x%08X value 0x%08X\n",
		       csr_base + indirect_cmd_reg, addr, *data);
}

static void ahci_serdes_wr(void __iomem *sds_base, 
			   int lane, u32 reg, u32 data)
{
	u32 cmd_reg;
	u32 wr_reg;
	u32 rd_reg;
	u32 val;
	
	cmd_reg = SATA_ENET_SDS_IND_CMD_REG;
	wr_reg = SATA_ENET_SDS_IND_WDATA_REG;
	rd_reg = SATA_ENET_SDS_IND_RDATA_REG;

	reg += (lane / 4) * SERDES_LANE_X4_STRIDE;
	reg += SERDES_INDIRECT_OFFSET;
	reg += (lane % 4) * SERDES_LANE_STRIDE;
	ahci_sds_wr(sds_base, cmd_reg, wr_reg, reg, data);
	ahci_sds_rd(sds_base, cmd_reg, rd_reg, reg, &val);
	pr_debug("SERDES WR addr 0x%X value 0x%08X <-> 0x%08X\n", reg, data,
		 val);
}

static void ahci_serdes_rd(void __iomem *sds_base, int lane, 
			   u32 reg, u32 *data)
{
	u32 cmd_reg;
	u32 rd_reg;

	cmd_reg = SATA_ENET_SDS_IND_CMD_REG;
	rd_reg = SATA_ENET_SDS_IND_RDATA_REG;

	reg += (lane / 4) * SERDES_LANE_X4_STRIDE;
	reg += SERDES_INDIRECT_OFFSET;
	reg += (lane % 4) * SERDES_LANE_STRIDE;
	ahci_sds_rd(sds_base, cmd_reg, rd_reg, reg, data);
	pr_debug("SERDES RD addr 0x%X value 0x%08X\n", reg, *data);
}

static void ahci_serdes_clrbits(void __iomem *sds_base, int lane, 
				u32 reg, u32 bits)
{
	u32 val;

	ahci_serdes_rd(sds_base, lane, reg, &val);
	val &= ~bits;
	ahci_serdes_wr(sds_base, lane, reg, val);
}

static void ahci_serdes_setbits(void __iomem *sds_base, int lane, 
				u32 reg, u32 bits)
{
	u32 val;

	ahci_serdes_rd(sds_base, lane, reg, &val);
	val |= bits;
	ahci_serdes_wr(sds_base, lane, reg, val);
}

static void xgene_ahci_force_port_phy_rdy(struct ahci_host_priv *hpriv,
				     	  int channel, int force)
{
	void __iomem *mmio = hpriv->mmio;
	u32 val;

	val = readl(mmio + PORTCFG);
	val = PORTADDR_SET(val, channel == 0 ? 2 : 3);
	writel(val, mmio + PORTCFG);
	readl(mmio + PORTCFG);	/* Force a barrier */
	val = readl(mmio + PORTPHY1CFG);
	val = PORTPHY1CFG_FRCPHYRDY_SET(val, force);
	writel(val, mmio + PORTPHY1CFG);
}

static void xgene_ahci_phy_reset_rxd(void __iomem *sds_base, int lane)
{
	/* Reset digital Rx */
	ahci_serdes_clrbits(sds_base, lane, 
			    RXTX_REG7, RXTX_REG7_RESETB_RXD_MASK);
	/* As per PHY design spec, the reset requires a minimum of 100us. */
	usleep_range(100, 150);
	ahci_serdes_setbits(sds_base, lane, 
			    RXTX_REG7, RXTX_REG7_RESETB_RXD_MASK);
}

void ahci_xgene_phy_clean_disparity(struct ata_port *ap, 
				   void __iomem *sds_base)
{
	int i;
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ahci_host_priv *hpriv = ap->host->private_data;
	int channel = ap->port_no;
	unsigned int val;

	for (i = 0; i < 5; i++) {
		/* Check if error bit set */
		val = readl(port_mmio + PORT_SCR_ERR);
		if (!(val & (SERR_DISPARITY | SERR_10B_8B_ERR)))
			break;
		/* Clear any error due to errata */
		xgene_ahci_force_port_phy_rdy(hpriv, channel, 1);
		/* Reset the PHY Rx path */
		xgene_ahci_phy_reset_rxd(sds_base, channel);	
		xgene_ahci_force_port_phy_rdy(hpriv, channel, 0);
		/* Clear all errors */
		val = readl(port_mmio + PORT_SCR_ERR);
		writel(val, port_mmio + PORT_SCR_ERR);
	}
}
EXPORT_SYMBOL_GPL(ahci_xgene_phy_clean_disparity);

