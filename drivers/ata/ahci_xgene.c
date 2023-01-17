/*
 * AppliedMicro X-Gene SoC SATA Host Controller Driver
 *
 * Copyright (c) 2014, Applied Micro Circuits Corporation
 * Author: Loc Ho <lho@apm.com>
 *         Tuan Phan <tphan@apm.com>
 *         Suman Tripathi <stripathi@apm.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include "ahci.h"

/* Max # of disk per a controller */
#define MAX_AHCI_CHN_PERCTR		2

/* SATA host AHCI CSR */
#define PORTCFG				0x000000a4
#define  PORTADDR_SET(dst, src) \
		(((dst) & ~0x0000003f) | (((u32)(src)) & 0x0000003f))
#define PORTAXICFG			0x000000bc
#define  PORTAXICFG_EN_CONTEXT_SET(dst, src) \
		(((dst) & ~0x01000000) | (((u32)(src) << 24) & 0x01000000))

/* MUX CSR */
#define SATA_ENET_CONFIG_REG		0x00000000
#define  CFG_SATA_ENET_SELECT_MASK	0x00000001

/* SATA diagnostic CSR */
#define CFG_MEM_RAM_SHUTDOWN		0x00000070
#define BLOCK_MEM_RDY			0x00000074

/* Max retry for link down */
#define MAX_LINK_DOWN_RETRY 3

extern void ahci_xgene_phy_clean_disparity(struct ata_port *ap, 
				   	void __iomem *sds_base);

struct xgene_ahci_context {
	struct ahci_host_priv  hpriv;
	struct device *dev;
	int irq;
	u8 last_cmd[MAX_AHCI_CHN_PERCTR]; /* tracking the last command issued*/
	u32 class[MAX_AHCI_CHN_PERCTR];
	void __iomem *csr_sds;		/* Serdes CSR address of IP */
	void __iomem *csr_diag;		/* Diag CSR address of IP */
	void __iomem *csr_axi;		/* Axi CSR address of IP */
	void __iomem *csr_mux;		/* MUX CSR address of IP */
	void __iomem *csr_core;         /* Core CSR address of IP */
};

static int xgene_is_storm(void)
{

	u32 val;

	#define MIDR_EL1_VARIANT_MASK 0x00f00000
	asm volatile("mrs %0, midr_el1" : "=r" (val));
	return (val & MIDR_EL1_VARIANT_MASK) == 0  ? 1 : 0;
}

static char *apm88xxx_chip_revision(void)
{
	#define MIDR_EL1_REV_MASK			0x0000000f 
	#define REVIDR_EL1_MINOR_REV_MASK	0x00000007 
	#define EFUSE0_SHADOW_VERSION_SHIFT	28
	#define EFUSE0_SHADOW_VERSION_MASK	0xF
	u32 val;
	void *efuse;
	void *jtag;

	efuse = ioremap(0x1054A000ULL, 0x100);
	jtag = ioremap(0x17000004ULL, 0x100);

	if (efuse == NULL || jtag == NULL) {
		if (efuse)
			iounmap(efuse);
		if (jtag)
			iounmap(jtag);
		return 0;
	}
	asm volatile("mrs %0, midr_el1" : "=r" (val));
	val &= MIDR_EL1_REV_MASK;
	if (val == 0){
		asm volatile("mrs %0, revidr_el1" : "=r" (val));
		val &= REVIDR_EL1_MINOR_REV_MASK;
		switch (val) {
			case 0:
				return "A0";
			case 1:
				return "A1";
			case 2:
				val = (readl(efuse) >> 
						EFUSE0_SHADOW_VERSION_SHIFT)
					& EFUSE0_SHADOW_VERSION_MASK;
				if (val == 0x1) 
					return "A2";
				else 
					return "A3";
		}
	} else if (val == 1)
		return "B0";

	return "Unknown";
}

static bool xgene_ahci_is_memram_inited(struct xgene_ahci_context *ctx)
{
	void __iomem *diagcsr = ctx->csr_diag;

	return (readl(diagcsr + CFG_MEM_RAM_SHUTDOWN) == 0 &&
	    readl(diagcsr + BLOCK_MEM_RDY) == 0xFFFFFFFF);
}

static int xgene_ahci_is_preB0(void)
{
	const char *revision = apm88xxx_chip_revision();
	if (!strcmp(revision, "B0"))
		return 0;
	else
		return 1;
}

/**
 * xgene_ahci_poll_reg_val- Poll a register on a specific value.
 * @ap : ATA port of interest
 * @reg : Register of interest
 * @val: Value to be attained
 * @interval : waiting interval for polling.
 * @timeout : timeout for achieving the value
 *
 * Restarts the dma engine inside the controller.
 */
static int xgene_ahci_poll_reg_val(struct ata_port *ap, 
                                    void __iomem *reg, unsigned
				    int val, unsigned long interval,
				    unsigned long timeout) 
{
	unsigned long deadline;
	unsigned int tmp;

	tmp = ioread32(reg);
	deadline = ata_deadline(jiffies, timeout);

	while ((tmp != val) && (time_before(jiffies, deadline))) {
		ata_msleep(ap, interval);
		tmp = ioread32(reg);
	}

	return tmp;
}
/**
 * xgene_ahci_restart_engine - Restart the dma engine.
 * @ap : ATA port of interest
 *
 * Restarts the dma engine inside the controller.
 */
static int xgene_ahci_restart_engine(struct ata_port *ap)
{
	struct ahci_port_priv *pp = ap->private_data;
	void __iomem *port_mmio = ahci_port_base(ap);
	u32 fbs;

	/* Poll PxCI to get clear */
	if (xgene_ahci_poll_reg_val(ap, port_mmio + 
				    PORT_CMD_ISSUE, 0x0, 1, 100))
		  return -EBUSY;

	ahci_stop_engine(ap);
	ahci_start_fis_rx(ap);
	/* Enable the PxFBS.FBS_EN bit as it
	 * gets cleared due to stop engine
	 */
	if (pp->fbs_supported) {
		fbs = readl(port_mmio + PORT_FBS);
		writel(fbs | PORT_FBS_EN, port_mmio + PORT_FBS);
		fbs = readl(port_mmio + PORT_FBS);
	}	

	ahci_start_engine(ap);

	return 0;
}

/**
 * xgene_ahci_qc_issue - Issue commands to the device
 * @qc: Command to issue
 *
 * Due to Hardware errata for IDENTIFY DEVICE command, the controller cannot
 * clear the BSY bit after receiving the PIO setup FIS. This results in the dma
 * state machine goes into the CMFatalErrorUpdate state and locks up. By
 * restarting the dma engine, it removes the controller out of lock up state.
 *
 * Due to H/W errata, the controller is unable to save the PMP 
 * field fetched from command header before sending the H2D FIS,
 * so when device returns the PMP port field in D2H FIS, there is
 * a mismatch resulting failure in command completion. So the 
 * workaround to this problem is to write the pmp value to PxFBS.DEV
 * field before issuing any command to PMP.
 */
static unsigned int xgene_ahci_qc_issue(struct ata_queued_cmd *qc)
{
	struct ata_port *ap = qc->ap;
	struct xgene_ahci_context *ctx = ap->host->private_data;
	int rc = 0;
	u32 port_fbs;
	void *port_mmio = ahci_port_base(ap);

	/*
	 * Write the pmp value to PxFBS.DEV
	 * for case Port Mulitplier.
	 */	
	if (ctx->class[ap->port_no] == ATA_DEV_PMP) {
		port_fbs = readl(port_mmio + PORT_FBS);
		port_fbs &= ~PORT_FBS_DEV_MASK;
		port_fbs |= qc->dev->link->pmp << PORT_FBS_DEV_OFFSET;
		writel(port_fbs, port_mmio + PORT_FBS);
	}	

	if ((unlikely(ctx->last_cmd[ap->port_no] == ATA_CMD_ID_ATA)) ||
	    (unlikely(ctx->last_cmd[ap->port_no] == ATA_CMD_PACKET))) {
		if (xgene_is_storm())
			xgene_ahci_restart_engine(ap);
	}
	rc = ahci_qc_issue(qc);

	/* Save the last command issued */
	ctx->last_cmd[ap->port_no] = qc->tf.command;

	return rc;
}

/**
 * xgene_ahci_read_id - Read ID data from the specified device
 * @dev: device
 * @tf: proposed taskfile
 * @id: data buffer
 *
 * This custom read ID function is required due to the fact that the HW
 * does not support DEVSLP.
 */
static unsigned int xgene_ahci_read_id(struct ata_device *dev,
				       struct ata_taskfile *tf, u16 *id)
{
	u32 err_mask;

	err_mask = ata_do_dev_read_id(dev, tf, id);
	if (err_mask)
		return err_mask;

	/*
	 * Mask reserved area. Word78 spec of Link Power Management
	 * bit15-8: reserved
	 * bit7: NCQ autosence
	 * bit6: Software settings preservation supported
	 * bit5: reserved
	 * bit4: In-order sata delivery supported
	 * bit3: DIPM requests supported
	 * bit2: DMA Setup FIS Auto-Activate optimization supported
	 * bit1: DMA Setup FIX non-Zero buffer offsets supported
	 * bit0: Reserved
	 *
	 * Clear reserved bit 8 (DEVSLP bit) as we don't support DEVSLP
	 */
	id[ATA_ID_FEATURE_SUPP] &= cpu_to_le16(~(1 << 8));

	return 0;
}

/**
 * xgene_ahci_do_hardreset - Issue the actual COMRESET
 * @link: link to reset
 * @deadline: deadline jiffies for the operation
 * @online: Return value to indicate if device online
 *
 * Due to the limitation of the hardware PHY, a difference set of setting is
 * required for each supported disk speed - Gen3 (6.0Gbps), Gen2 (3.0Gbps),
 * and Gen1 (1.5Gbps). Otherwise during long IO stress test, the PHY will
 * report disparity error and etc. In addition, during COMRESET, there can
 * be error reported in the register PORT_SCR_ERR. For SERR_DISPARITY and
 * SERR_10B_8B_ERR, the PHY receiver line must be reseted. Also during long
 * reboot cycle regression, sometimes the PHY reports link down even if the
 * device is present because of speed negotiation failure. so need to retry
 * the COMRESET to get the link up. The following algorithm is followed to
 * proper configure the hardware PHY during COMRESET:
 *
 * Alg Part 1:
 * 1. Start the PHY at Gen3 speed (default setting)
 * 2. Issue the COMRESET
 * 3. If no link, go to Alg Part 3
 * 4. If link up, determine if the negotiated speed matches the PHY
 *    configured speed
 * 5. If they matched, go to Alg Part 2
 * 6. If they do not matched and first time, configure the PHY for the linked
 *    up disk speed and repeat step 2
 * 7. Go to Alg Part 2
 *
 * Alg Part 2:
 * 1. On link up, if there are any SERR_DISPARITY and SERR_10B_8B_ERR error
 *    reported in the register PORT_SCR_ERR, then reset the PHY receiver line
 * 2. Go to Alg Part 4
 *
 * Alg Part 3:
 * 1. Check the PORT_SCR_STAT to see whether device presence detected but PHY
 *    communication establishment failed and maximum link down attempts are
 *    less than Max attempts 3 then goto Alg Part 1.
 * 2. Go to Alg Part 4.
 *
 * Alg Part 4:
 * 1. Clear any pending from register PORT_SCR_ERR.
 *
 * NOTE: For the initial version, we will NOT support Gen1/Gen2. In addition
 *       and until the underlying PHY supports an method to reset the receiver
 *       line, on detection of SERR_DISPARITY or SERR_10B_8B_ERR errors,
 *       an warning message will be printed.
 */
static int xgene_ahci_do_hardreset(struct ata_link *link,
				   unsigned long deadline, bool *online)
{
	const unsigned long *timing = sata_ehc_deb_timing(&link->eh_context);
	struct ata_port *ap = link->ap;
	struct xgene_ahci_context *ctx = ap->host->private_data;
	struct ahci_port_priv *pp = ap->private_data;
	u8 *d2h_fis = pp->rx_fis + RX_FIS_D2H_REG;
	void __iomem *port_mmio = ahci_port_base(ap);
	struct ata_taskfile tf;
	int link_down_retry = 0;
	int rc;
	u32 val, sstatus;

	do {
		/* clear D2H reception area to properly wait for D2H FIS */
		ata_tf_init(link->device, &tf);
		tf.command = ATA_BUSY;
		ata_tf_to_fis(&tf, 0, 0, d2h_fis);
		rc = sata_link_hardreset(link, timing, deadline, online,
				 ahci_check_ready);

		if (*online) {
			val = readl(port_mmio + PORT_SCR_ERR);
			if (val & (SERR_DISPARITY | SERR_10B_8B_ERR))
				dev_warn(ctx->dev, "link has error\n");
			break;
		}

		sata_scr_read(link, SCR_STATUS, &sstatus);
	} while (link_down_retry++ < MAX_LINK_DOWN_RETRY &&
		 (sstatus & 0xff) == 0x1);
	
	/* clear all errors if any pending */
	val = readl(port_mmio + PORT_SCR_ERR);
	writel(val, port_mmio + PORT_SCR_ERR);

	return rc;
}

/* Custom ahci_hardreset  
 *
 * Due to HW errata, the phy has different transmitt boost parameters for ssd 
 * drives and HDD drives. So we need to set the transmitt boost paramters for    
 * the ssd and hdd drives after the COMRESET sequence. We need to retry the
 * COMRESET sequence because the phy reports link down at one shot.
 */
static int xgene_ahci_hardreset(struct ata_link *link, unsigned int *class,
				unsigned long deadline)
{
	struct ata_port *ap = link->ap;
	void __iomem *port_mmio = ahci_port_base(ap);
	bool online;
	int rc;
	u32 portcmd_saved = 0;
	u32 portclb_saved = 0;
	u32 portclbhi_saved = 0;
	u32 portrxfis_saved = 0;
	u32 portrxfishi_saved = 0;

	if (xgene_ahci_is_preB0()) {
		/* As hardreset resets these CSR, save it to restore later */
		portcmd_saved = readl(port_mmio + PORT_CMD);
		portclb_saved = readl(port_mmio + PORT_LST_ADDR);
		portclbhi_saved = readl(port_mmio + PORT_LST_ADDR_HI);
		portrxfis_saved = readl(port_mmio + PORT_FIS_ADDR);
		portrxfishi_saved = readl(port_mmio + PORT_FIS_ADDR_HI);
	}	

	ahci_stop_engine(ap);

	rc = xgene_ahci_do_hardreset(link, deadline, &online);

	if (xgene_ahci_is_preB0()) {
		/* As controller hardreset clears them, restore them */
		writel(portcmd_saved, port_mmio + PORT_CMD);
		writel(portclb_saved, port_mmio + PORT_LST_ADDR);
		writel(portclbhi_saved, port_mmio + PORT_LST_ADDR_HI);
		writel(portrxfis_saved, port_mmio + PORT_FIS_ADDR);
		writel(portrxfishi_saved, port_mmio + PORT_FIS_ADDR_HI);
	}

	ahci_start_engine(ap);

	if (online)
		*class = ahci_dev_classify(ap);	

	return rc;
}

void xgene_ahci_disable_ctx(struct ahci_host_priv *hpriv, int channel) 
{
	void __iomem *mmio = hpriv->mmio;
	u32 val;

	val = readl(mmio + PORTCFG);
	val = PORTADDR_SET(val, channel == 0 ? 2 : 3);
	writel(val, mmio + PORTCFG);
	readl(mmio + PORTCFG);  
	val = readl(mmio + PORTAXICFG);
	val = PORTAXICFG_EN_CONTEXT_SET(val, 0x0); /* Disable context mgmt */
	writel(val, mmio + PORTAXICFG);
}

/**
 * xgene_ahci_pmp_softreset - Issue the softreset to the drives connected
 *                            to Port Multiplier
 * @link: link to reset
 * @class: Return value to indicate class of device
 * @deadline: deadline jiffies for the operation
 * 
 * Due to H/W errata, the controller is unable to save the PMP 
 * field fetched from command header before sending the H2D FIS,
 * so when device returns the PMP port field in D2H FIS, there is
 * a mismatch resulting failure in command completion. So the 
 * workaround to this problem is to write the pmp value to PxFBS.DEV
 * field before issuing any command to PMP.
 */
static int xgene_ahci_pmp_softreset(struct ata_link *link, unsigned int *class,
			  unsigned long deadline)
{
	int pmp = sata_srst_pmp(link);
	struct ata_port *ap = link->ap;
	u32 rc;
	void *port_mmio = ahci_port_base(ap);
	u32 port_fbs;
	
	port_fbs = readl(port_mmio + PORT_FBS);
	port_fbs &= ~PORT_FBS_DEV_MASK;
	port_fbs |= pmp << PORT_FBS_DEV_OFFSET;
	writel(port_fbs, port_mmio + PORT_FBS);
	
	rc = ahci_do_softreset(link, class, pmp, deadline, ahci_check_ready);
	
	return rc;
}

/**
 * xgene_ahci_softreset - Issue the softreset to the drive.
 * @link: link to reset
 * @class: Return value to indicate class of device
 * @deadline: deadline jiffies for the operation
 * 
 * Due to H/W errata, the controller is unable to save the PMP 
 * field fetched from command header before sending the H2D FIS,
 * so when device returns the PMP port field in D2H FIS, there is
 * a mismatch resulting failure in command completion. So the 
 * workaround to this problem is to write the pmp value to PxFBS.DEV
 * field before issuing any command to PMP. Here is the algorithm
 * to detect PMP :
 *
 * 1. Save the PxFBS value.
 * 2. Start with pmp = 0xF (with/without PMP)
 * 3. Issue softreset
 * 4. If class is PMP goto 6
 * 5. restore the original PxFBS and goto 2 
 * 6. return
 *
 */ 
static int xgene_ahci_softreset(struct ata_link *link, unsigned int *class,
			  unsigned long deadline)
{
	int pmp = sata_srst_pmp(link);
	struct ata_port *ap = link->ap;
	struct xgene_ahci_context *ctx = ap->host->private_data;
	u32 rc;

	void *port_mmio = ahci_port_base(ap);
	u32 port_fbs;
	u32 port_fbs_save;
	u32 retry = 1;

	port_fbs_save = readl(port_mmio + PORT_FBS);

	/* Set the DEV field of PXFBS with pmp
	 * value
	 */	
	port_fbs = readl(port_mmio + PORT_FBS);
	port_fbs &= ~PORT_FBS_DEV_MASK;
	port_fbs |= pmp << PORT_FBS_DEV_OFFSET;
	writel(port_fbs, port_mmio + PORT_FBS);
	
softreset_retry:
	rc = ahci_do_softreset(link, class, pmp, deadline, ahci_check_ready);

	ctx->class[ap->port_no] = *class;
	if (*class == ATA_DEV_PMP) {
		/* Disable context manager */
		xgene_ahci_disable_ctx(&ctx->hpriv, ap->port_no);
	} else {
		/* Retry for normal drives without
		 * setting DEV field with pmp value inside
		 * PORT_FBS register
		 */
		if (retry--) {
			writel(port_fbs_save, port_mmio + PORT_FBS);
			goto softreset_retry;
		}	
	}

	return rc;
}

static struct ata_port_operations xgene_ahci_ops = {
	.inherits = &ahci_ops,
	.hardreset = xgene_ahci_hardreset,
	.read_id = xgene_ahci_read_id,
};

static const struct ata_port_info xgene_ahci_port_info[] = {
	{
		.flags = AHCI_FLAG_COMMON | ATA_FLAG_PMP,	
		.pio_mask = ATA_PIO4,
		.udma_mask = ATA_UDMA6,
		.port_ops = &xgene_ahci_ops,
	}
};

static struct scsi_host_template xgene_ahci_sht = {
	AHCI_SHT("X-Gene-ahci"),
};

static int xgene_ahci_mux_select(struct xgene_ahci_context *ctx)
{
	u32 val;

	/* Check for optional MUX resource */
	if (!ctx->csr_mux)
		return 0;

	val = readl(ctx->csr_mux + SATA_ENET_CONFIG_REG);
	val &= ~CFG_SATA_ENET_SELECT_MASK;
	writel(val, ctx->csr_mux + SATA_ENET_CONFIG_REG);
	val = readl(ctx->csr_mux + SATA_ENET_CONFIG_REG);
	return val & CFG_SATA_ENET_SELECT_MASK ? -1 : 0;
}

static int xgene_ahci_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ahci_host_priv *hpriv;
	struct xgene_ahci_context *ctx;
	struct ata_port_info pi = xgene_ahci_port_info[0];
	const struct ata_port_info *ppi[] = { &pi, NULL };
	struct ata_host *host;
	struct resource *res;
	int n_ports;
	int rc = 0;
	int i;

	ctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		dev_err(dev, "can't allocate host context\n");
		return -ENOMEM;
	}

	hpriv = &ctx->hpriv;
	ctx->dev = dev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "no MMIO space\n");
		return -EINVAL;
	}

	ctx->hpriv.mmio = devm_ioremap_resource(dev, res);
	if (!ctx->hpriv.mmio) {
		dev_err(dev, "can't map %pR\n", res);
		return -ENOMEM;
	}

	/* Retrieve the IP core resource */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	ctx->csr_core = devm_ioremap_resource(dev, res);
	if (IS_ERR(ctx->csr_core))
		return PTR_ERR(ctx->csr_core);

	/* Retrieve the IP diagnostic resource */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	ctx->csr_diag = devm_ioremap_resource(dev, res);
	if (IS_ERR(ctx->csr_diag))
		return PTR_ERR(ctx->csr_diag);

	/* Retrieve the IP AXI resource */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 3);
	ctx->csr_axi = devm_ioremap_resource(dev, res);
	if (IS_ERR(ctx->csr_axi))
                return PTR_ERR(ctx->csr_axi);

	/* Retrieve the optional IP mux resource */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 4);
	if (res) {
		void __iomem *csr = devm_ioremap_resource(dev, res);
		if (IS_ERR(csr))
			return PTR_ERR(csr);

		ctx->csr_mux = csr;
	}

	if ((rc = xgene_ahci_mux_select(ctx))) {
		dev_err(dev, "SATA mux selection failed error %d\n", rc);
		return -ENODEV;
	}

	ctx->irq = platform_get_irq(pdev, 0);
	if (ctx->irq <= 0) {
		dev_err(dev, "no IRQ\n");
		return -EINVAL;
	}

	if (!xgene_ahci_is_memram_inited(ctx)) {
		dev_err(dev, "PHY and controller not initialised \n");
		return -ENODEV;
	}

	/* Setup AHCI host priv structure */
	ahci_save_initial_config(dev, &ctx->hpriv);

	/* prepare host */
	if (ctx->hpriv.cap & HOST_CAP_NCQ)
		pi.flags |= ATA_FLAG_NCQ;
	if (ctx->hpriv.cap & HOST_CAP_PMP) {
		pi.flags |= ATA_FLAG_PMP;
	}

	ahci_set_em_messages(&ctx->hpriv, &pi);

	/*
	 * CAP.NP sometimes indicate the index of the last enabled
	 * port, at other times, that of the last possible port, so
	 * determining the maximum port number requires looking at
	 * both CAP.NP and port_map.
	 */
	n_ports = max(ahci_nr_ports(ctx->hpriv.cap), fls(ctx->hpriv.port_map));

	host = ata_host_alloc_pinfo(dev, ppi, n_ports);
	if (!host) {
		return -ENOMEM;
	}

	host->private_data = ctx;

	if (!(ctx->hpriv.cap & HOST_CAP_SSS) || ahci_ignore_sss)
		host->flags |= ATA_HOST_PARALLEL_SCAN;
	else
		dev_warn(dev, "ahci: SSS flag set, parallel bus scan disabled\n");

	for (i = 0; i < host->n_ports; i++) {
		struct ata_port *ap = host->ports[i];

		ata_port_desc(ap, "port 0x%x", 0x100 + ap->port_no * 0x80);

		/* set enclosure management message type */
		if (ap->flags & ATA_FLAG_EM)
			ap->em_message_type = ctx->hpriv.em_msg_type;

		/* disabled/not-implemented port */
		if (!(ctx->hpriv.port_map & (1 << i)))
			ap->ops = &ata_dummy_port_ops;
	}

	rc = ahci_reset_controller(host);
	if (rc)
		return rc;

	ahci_init_controller(host);

	ahci_print_info(host, "X-Gene-AHCI\n");

	/*
 	 * Setup DMA mask. This is preliminary until the DMA range is sorted
	 * out.
	 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
	pdev->dev.dma_mask = &pdev->dev.coherent_dma_mask;
	pdev->dev.coherent_dma_mask = DMA_BIT_MASK(64);
#else
	/* Setup DMA mask - 32 for 32-bit system and 64 for 64-bit system */
	rc = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(8*sizeof(void *)));
	if (rc) {
		dev_err(dev, "Unable to set dma mask\n");
		return rc;
	}
#endif

	if (xgene_is_storm()) {
		/*
		 * Overrid teh callbacks for storm ERRATA
		 */
		hpriv->flags |= AHCI_HFLAG_NO_NCQ | AHCI_HFLAG_BROKEN_FIS_ON;
		xgene_ahci_ops.qc_issue = xgene_ahci_qc_issue;
		xgene_ahci_ops.softreset = xgene_ahci_softreset;
		xgene_ahci_ops.pmp_softreset = xgene_ahci_pmp_softreset;
	} else
		hpriv->flags |= AHCI_HFLAG_INTERRUPT_EDGE_TRIG | AHCI_HFLAG_YES_FBS;

	rc = ata_host_activate(host, ctx->irq, ahci_interrupt,
			       IRQF_SHARED, &xgene_ahci_sht);
	if (rc)
		return rc;

	dev_dbg(dev, "X-Gene SATA host controller initialized\n");
	return 0;
}

static const struct of_device_id xgene_ahci_of_match[] = {
	{.compatible = "apm,xgene-ahci"},
	{ }
};
MODULE_DEVICE_TABLE(of, xgene_ahci_of_match);

static struct platform_driver xgene_ahci_driver = {
	.probe = xgene_ahci_probe,
	.remove = ata_platform_remove_one,
	.driver = {
		.name = "xgene-ahci",
		.owner = THIS_MODULE,
		.of_match_table = xgene_ahci_of_match,
	},
};

module_platform_driver(xgene_ahci_driver);

MODULE_DESCRIPTION("APM X-Gene AHCI SATA driver");
MODULE_AUTHOR("Loc Ho <lho@apm.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.4");
