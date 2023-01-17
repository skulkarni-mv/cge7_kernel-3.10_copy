/*
 * Copyright (C) 2015, Broadcom Corporation. All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/clk.h>
#include <linux/phy/phy.h>
#include <linux/io.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/printk.h>

/*
 *  This driver initialises the SATA phy and other related hardware required
 *  before the AHCI host on NS2 can be accessed by Linux.
 *
 *  It requires two register resources:
 *    SATA IDM I/O control address (must be 0x1000 in length)
 *    SATA base address (must be 0x4000 in length)
 */

/*
 *  Device compatibility is put up here becuase it is referred to within the
 *  code so must be declared before the code.
 */
#define DEVICE_VENDOR_NAME "brcm"
#define DEVICE_COMPAT_NAME "phy-bcm-ns2-sata"
#define DEVICE_COMPAT_STRING "brcm,phy-bcm-ns2-sata"

/*
 *  The next block of lines was excerpted from the NS2 registers file.  We
 *  don't use the addresses directly, but we do use the offsets from the
 *  beginning of the particular regions.  The regions themselves are specified
 *  by the description in the device tree.
 */
/* IDM registers */
#define IDM_RES_INDEX 0
#define IDM_SIZE_MINIMUM 0x1000
#define SATA_M0_IDM_IDM_RESET_CONTROL_BASE 0x800
#define SMIIRC_R 0

/* SATA host registers */
#define SATA_RES_INDEX 1
#define SATA_SIZE_MINIMUM 0x4000
#define SATA_SATA_TOP_CTRL_BUS_CTRL 0x00000044
#define SSTCBC_OHR 16
#define SATA_SATA_TOP_CTRL_PHY_CTRL_1 0x0000004c
#define SSTCPC1_W1 0x00000001
#define SSTCPC1_W2 0x00000000
#define SATA_SATA_TOP_CTRL_PHY_CTRL_2 0x00000050
#define SSTCPC2_W1 0x0000000E
#define SSTCPC2_W2 0x00000000
#define SATA_SATA_TOP_CTRL_PHY_CTRL_3 0x00000054
#define SSTCPC3_W1 0x00000001
#define SSTCPC3_W2 0x00000000
#define SATA_SATA_TOP_CTRL_PHY_CTRL_4 0x00000058
#define SSTCPC4_W1 0x0000000E
#define SSTCPC4_W2 0x00000000
#define SATA_PORT0_SATA3_PCB_REG0 0x00000300
#define SP0SPR0_B150_W 0x0000C493
#define SATA_PORT0_SATA3_PCB_REG1 0x00000304
#define SP0SPR1_B150_W 0x00001B89
#define SP0SPR1_B000_R 12
#define SATA_PORT0_SATA3_PCB_REG2 0x00000308
#define SP0SPR2_B060_W 0x00001DF8
#define AEQ_CTRL2__RESERVED 15
#define AEQ_CTRL2__EQ_FORMAT 12
#define SATA_PORT0_SATA3_PCB_REG3 0x0000030c
#define SP0SPR3_B060_W 0x00002B00
#define AEQ_FRC_EQ__EQ_VAL_SHIFT 4
#define AEQ_FRC_EQ__EQ_OVERRIDE_ENABLE 3
#define SATA_PORT0_SATA3_PCB_REG4 0x00000310
#define SP0SPR4_B060_W 0x00008824
#define SATA_PORT0_SATA3_PCB_REG7 0x0000031C
#define RXPMD_RX_FREQ_MON_CTRL1__CLAMP_ENABLE 8
#define SATA_PORT0_SATA3_PCB_REG13 0x00000334
#define SP0SPR13_B000_W 0x00000001
#define SATA_PORT0_SATA3_PCB_BLOCK_ADDR 0x0000033c
#define SP0SPBA_B000 0x00000000
#define SP0SPBA_B060 0x00000060
#define SP0SPBA_B150 0x00000150
#define SATA_PCB_BLOCK_AEQ 0x000000D0
#define SATA_PCB_BLOCK_RXPMD 0x000001C0
#define SATA_PORT1_SATA3_PCB_REG0 0x00001300
#define SATA_PORT1_SATA3_PCB_REG1 0x00001304
#define SP1SPR1_B150_W 0x00001B89
#define SP1SPR1_B000_R 12
#define SATA_PORT1_SATA3_PCB_REG2 0x00001308
#define SP1SPR2_B060_W 0x00001DF8
#define SATA_PORT1_SATA3_PCB_REG3 0x0000130c
#define SP1SPR3_B060_W 0x00002B00
#define SATA_PORT1_SATA3_PCB_REG4 0x00001310
#define SP1SPR4_B060_W 0x00008824
#define SATA_PORT1_SATA3_PCB_REG7 0x0000131C
#define SATA_PORT1_SATA3_PCB_REG13 0x00001334
#define SP1SPR13_B000_W 0x00000001
#define SATA_PORT1_SATA3_PCB_BLOCK_ADDR 0x0000133c
#define SP1SPBA_B000  0x00000000
#define SP1SPBA_B060  0x00000060
#define SP1SPBA_AEQ   0x000000D0
#define SP1SPBA_B150  0x00000150
#define SP1SPBA_RXPMD 0x000001C0
#define SATA_SATA_AHCI_GHC_HBA_CAP 0x00002000
#define SSAGHC_SFIS 16
#define SATA_SATA_PORT0_AHCI_S3_PxFBS 0x00002140
#define SSP0AS_PxFBS_ADO 12
#define SSP0AS_PxFBS_ADO_MASK 0xF
#define SSP0AS_PxFBS_ADO_NV 2
#define SATA_SATA_PORT1_AHCI_S3_PxFBS 0x000021c0
#define SSP1AS_PxFBS_ADO 12
#define SSP1AS_PxFBS_ADO_MASK 0xF
#define SSP1AS_PxFBS_ADO_NV 2
#define SATA_SATA_PORT0_CTRL_PCTRL3 0x0000270c
#define SSP0CP3_AND 0xFFFF0000
#define SATA_SATA_PORT0_CTRL_PCTRL4 0x00002710
#define SSP0CP4_OR 0x01024000
#define SATA_SATA_PORT0_CTRL_PCTRL5 0x00002714
#define SSP0CP5_OR 0x01400810
#define SATA_SATA_PORT1_CTRL_PCTRL3 0x0000278c
#define SSP1CP3_AND 0xFFFF0000
#define SATA_SATA_PORT1_CTRL_PCTRL4 0x00002790
#define SSP1CP4_OR 0x01024000
#define SATA_SATA_PORT1_CTRL_PCTRL5 0x00002794
#define SSP1CP5_OR 0x01400810

/* some other constants */
#define PHY_LOOP_ITER 30
#define PHY_LOOP_DELAY 500
#define RESET_SET_DELAY 5
#define RESET_CLR_DELAY 50
#define PHY_RESET_DELAY 1

static const struct of_device_id phy_bcm_ns2_sata_of_match[] = {
	{.compatible = DEVICE_COMPAT_STRING},
	{},
};

inline void sata_mdelay(u32 time)
{
	while (time > 0) {
		udelay(1000);
		time--;
	}
}

inline void sata_write32(u32 value, u64 offset, void *base)
{
	void *addr = (u8 *) base;

	addr = (void *)&(((u8 *) base)[offset]);
	iowrite32(value, addr);
}

inline u32 sata_read32(u64 offset, void *base)
{
	u8 *addr = (u8 *) base;
	addr = &(addr[offset]);
	return ioread32((void *)addr);
}

static int phy_bcm_ns2_sata_probe(struct platform_device *pdev)
{
	struct resource sata_res;	/* SATA host and phy control space */
	struct resource idm_res;	/* SATA IDM I/O control space */
	struct device *dev = &pdev->dev;
	const struct of_device_id *match;
	void *sata_regs = NULL;
	void *idm_regs = NULL;
	struct resource *srp = NULL;
	struct resource *irp = NULL;
	u32 reg;
	unsigned int cnt;
	int aeq = -1;
	int cdrlim = -1;
	int result = 0;

	/* check device sanity */
	match = of_match_device(phy_bcm_ns2_sata_of_match, dev);
	if (!match) {
		/* driver not valid for this device */
		dev_err(dev, "mismatched device\n");
		result = -EINVAL;
		goto cleanup;
	}

	/* get resource information */
	result =
	    of_address_to_resource(pdev->dev.of_node, IDM_RES_INDEX, &idm_res);
	if (result) {
		/* unable to get resource information */
		dev_err(dev, "of_address_to_resource on IDM space failed\n");
		goto cleanup;
	}
	if (resource_size(&idm_res) < IDM_SIZE_MINIMUM) {
		/* the registers are spread across 4KiB of space */
		dev_err(dev, "IDM register space size must be >= 4KiB\n");
		result = -EINVAL;
		goto cleanup;
	}
	result =
	    of_address_to_resource(pdev->dev.of_node, SATA_RES_INDEX,
				   &sata_res);
	if (result) {
		/* unable to get resource information */
		dev_err(dev, "of_address_to_resource on phy space failed\n");
		goto cleanup;
	}
	if (resource_size(&sata_res) < SATA_SIZE_MINIMUM) {
		/* the registers are spread across 16KiB of space */
		dev_err(dev, "phy register space size must be >= 16KiB\n");
		result = -EINVAL;
		goto cleanup;
	}

	/* request the memory mapped I/O space */
	irp = request_mem_region(idm_res.start,
				 resource_size(&idm_res),
				 DEVICE_COMPAT_NAME ".IDM_regs");
	if (!irp) {
		/* unable to get the I/O memory space */
		dev_err(dev, "IDM request_mem_region failed\n");
		result = -ENOMEM;
		goto cleanup;
	}
	srp = request_mem_region(sata_res.start,
				 resource_size(&sata_res),
				 DEVICE_COMPAT_NAME ".SATA_regs");
	if (!srp) {
		/* unable to get the I/O memory space */
		dev_err(dev, "SATA request_mem_region failed\n");
		result = -ENOMEM;
		goto cleanup;
	}

	/* map the memory mapped I/O space, specifically as non-cacheable */
	idm_regs = ioremap_nocache(idm_res.start, resource_size(&idm_res));
	if (!idm_regs) {
		/* unable to map the I/O memory space */
		dev_err(dev, "idm ioremap_nocache failed\n");
		result = -ENOMEM;
		goto cleanup;
	}
	sata_regs = ioremap_nocache(sata_res.start, resource_size(&sata_res));
	if (!sata_regs) {
		/* unable to map the I/O memory space */
		dev_err(dev, "phy ioremap_nocache failed\n");
		result = -ENOMEM;
		goto cleanup;
	}

	if (!of_property_read_u32(pdev->dev.of_node,
				 "aeq_override",
				 &reg)) {
		aeq = reg;
		if ((aeq < 0) || (aeq > 15)) {
			/* not a valid setting; ignore it */
			dev_err(dev,
				"aeq_override setting %d invalid;"
				" ignoring it (not overriding)\n",
				aeq);
			aeq = -1;
		} else
			dev_info(dev, "Will override AEQ with %d\n", aeq);
	}

	if (!of_property_read_u32(pdev->dev.of_node,
				 "cdr_restrict",
				 &reg)) {
		cdrlim = reg;
		if ((cdrlim < 0) || (cdrlim > 255)) {
			dev_err(dev,
				"cdr_restrict setting %d invalid;"
				" ignoring it (not restricting)\n",
				cdrlim);
			cdrlim = -1;
		} else
			dev_err(dev,
				"Will limit CDR integral to +-%d"
				" (about %dppm)\n",
				cdrlim,
				(cdrlim * 61) >> 1);
	}

	/* reset the host (put it in reset, wait, take it out, wait) */
	reg = sata_read32(SATA_M0_IDM_IDM_RESET_CONTROL_BASE, idm_regs);
	reg |= (1 << SMIIRC_R);
	sata_write32(reg, SATA_M0_IDM_IDM_RESET_CONTROL_BASE, idm_regs);
	sata_mdelay(RESET_SET_DELAY);
	reg &= (~(1 << SMIIRC_R));
	sata_write32(reg, SATA_M0_IDM_IDM_RESET_CONTROL_BASE, idm_regs);
	sata_mdelay(RESET_CLR_DELAY);

	/* Change exposed parameters for the device */
	/* Allow override of hardware defaults */
	reg = sata_read32(SATA_SATA_TOP_CTRL_BUS_CTRL, sata_regs);
	reg |= (1 << SSTCBC_OHR);
	sata_write32(reg, SATA_SATA_TOP_CTRL_BUS_CTRL, sata_regs);
	/* Adjust some values in the capabilities */
	reg = sata_read32(SATA_SATA_AHCI_GHC_HBA_CAP, sata_regs);
	reg |= (1 << SSAGHC_SFIS);
	sata_write32(reg, SATA_SATA_AHCI_GHC_HBA_CAP, sata_regs);
	/* Adjsut some values in PxFBS, port 0 */
	reg = sata_read32(SATA_SATA_PORT0_AHCI_S3_PxFBS, sata_regs);
	reg &= (~(SSP0AS_PxFBS_ADO_MASK << SSP0AS_PxFBS_ADO));
	reg |= (SSP0AS_PxFBS_ADO_NV << SSP0AS_PxFBS_ADO);
	sata_write32(reg, SATA_SATA_PORT0_AHCI_S3_PxFBS, sata_regs);
	/* Adjsut some values in PxFBS, port 1 */
	reg = sata_read32(SATA_SATA_PORT1_AHCI_S3_PxFBS, sata_regs);
	reg &= (~(SSP1AS_PxFBS_ADO_MASK << SSP1AS_PxFBS_ADO));
	reg |= (SSP1AS_PxFBS_ADO_NV << SSP1AS_PxFBS_ADO);
	sata_write32(reg, SATA_SATA_PORT1_AHCI_S3_PxFBS, sata_regs);
	/* disable further changes and set endianness */
	/* FIXME: probably need to find core endiannes at compile/run time */
	reg = sata_read32(SATA_SATA_TOP_CTRL_BUS_CTRL, sata_regs);
	reg &= (~(1 << SSTCBC_OHR));
	sata_write32(reg, SATA_SATA_TOP_CTRL_BUS_CTRL, sata_regs);

	/* Set port 0 OOB control for 100MHz reference clock */
	sata_write32(SP0SPBA_B150, SATA_PORT0_SATA3_PCB_BLOCK_ADDR, sata_regs);
	sata_write32(SP0SPR0_B150_W, SATA_PORT0_SATA3_PCB_REG0, sata_regs);
	sata_write32(SP0SPR1_B150_W, SATA_PORT0_SATA3_PCB_REG1, sata_regs);

	reg = sata_read32(SATA_SATA_PORT0_CTRL_PCTRL5, sata_regs);
	reg |= SSP0CP5_OR;
	sata_write32(reg, SATA_SATA_PORT0_CTRL_PCTRL5, sata_regs);
	reg = sata_read32(SATA_SATA_PORT0_CTRL_PCTRL3, sata_regs);
	reg &= SSP0CP3_AND;
	sata_write32(reg, SATA_SATA_PORT0_CTRL_PCTRL3, sata_regs);
	reg = sata_read32(SATA_SATA_PORT0_CTRL_PCTRL4, sata_regs);
	reg |= SSP0CP4_OR;
	sata_write32(reg, SATA_SATA_PORT0_CTRL_PCTRL4, sata_regs);

	/* configure PLL */
	/* Access PLL register bank 1 */
	sata_write32(SP0SPBA_B060, SATA_PORT0_SATA3_PCB_BLOCK_ADDR, sata_regs);
	/* Set intN_fb_en bit */
	sata_write32(SP0SPR2_B060_W, SATA_PORT0_SATA3_PCB_REG2, sata_regs);
	/* Select integer divide mode (instead of fractional) */
	sata_write32(SP0SPR3_B060_W, SATA_PORT0_SATA3_PCB_REG3, sata_regs);
	/* Set PLL divider to 60 */
	sata_write32(SP0SPR4_B060_W, SATA_PORT0_SATA3_PCB_REG4, sata_regs);
	/* Access BLOCK_0 register bank */
	sata_write32(SP0SPBA_B000, SATA_PORT0_SATA3_PCB_BLOCK_ADDR, sata_regs);
	/* Set oob_clk_sel to refclk/2 */
	sata_write32(SP0SPR13_B000_W, SATA_PORT0_SATA3_PCB_REG13, sata_regs);
	if (aeq >= 0) {
		/* access AEQ register bank */
		sata_write32(SATA_PCB_BLOCK_AEQ,
			     SATA_PORT0_SATA3_PCB_BLOCK_ADDR,
			     sata_regs);
		/* set AEQ override format */
		reg = sata_read32(SATA_PORT0_SATA3_PCB_REG2, sata_regs);
		reg &= (~(1 << AEQ_CTRL2__RESERVED));
		reg |= (1 << AEQ_CTRL2__EQ_FORMAT);
		sata_write32(reg, SATA_PORT0_SATA3_PCB_REG2, sata_regs);
		/* set AEQ override and value */
		reg = ((aeq << AEQ_FRC_EQ__EQ_VAL_SHIFT) |
		       (AEQ_FRC_EQ__EQ_OVERRIDE_ENABLE));
		sata_write32(reg, SATA_PORT0_SATA3_PCB_REG3, sata_regs);
	}
	if (cdrlim >= 0) {
		/* access RXPMD registers */
		sata_write32(SATA_PCB_BLOCK_RXPMD,
			     SATA_PORT0_SATA3_PCB_BLOCK_ADDR,
			     sata_regs);
		/* set CDR integral limit and enable the limit */
		reg = ((1 << RXPMD_RX_FREQ_MON_CTRL1__CLAMP_ENABLE) |
		       cdrlim);
		sata_write32(reg, SATA_PORT0_SATA3_PCB_REG7, sata_regs);
	}

	/* strobe phy 0 reset */
	sata_write32(SSTCPC1_W1, SATA_SATA_TOP_CTRL_PHY_CTRL_1, sata_regs);
	sata_write32(SSTCPC2_W1, SATA_SATA_TOP_CTRL_PHY_CTRL_2, sata_regs);
	sata_mdelay(PHY_RESET_DELAY);
	sata_write32(SSTCPC1_W2, SATA_SATA_TOP_CTRL_PHY_CTRL_1, sata_regs);
	sata_write32(SSTCPC2_W2, SATA_SATA_TOP_CTRL_PHY_CTRL_2, sata_regs);
	sata_mdelay(PHY_RESET_DELAY);

	/* wait for PLL lock */
	/* Access BLOCK_0 register bank */
	sata_write32(SP0SPBA_B000, SATA_PORT0_SATA3_PCB_BLOCK_ADDR, sata_regs);
	/* poll pll_lock for the port */
	for (cnt = 0;
	     ((cnt < PHY_LOOP_ITER) &&
	      (0 ==
	       (sata_read32(SATA_PORT0_SATA3_PCB_REG1, sata_regs) &
		(1 << SP0SPR1_B000_R)))); cnt++)
		sata_mdelay(PHY_LOOP_DELAY);
	if (0 ==
	    (sata_read32(SATA_PORT0_SATA3_PCB_REG1, sata_regs) &
	     (1 << SP0SPR1_B000_R))) {
		/* PLL did not lock; give up */
		dev_err(dev, "SATA port 0 PLL did not lock\n");
		result = -EIO;
		goto cleanup;
	}

	/* Set port 1 OOB control for 100MHz reference clock */
	sata_write32(SP1SPBA_B150, SATA_PORT1_SATA3_PCB_BLOCK_ADDR, sata_regs);
	sata_write32(0x0000C493, SATA_PORT1_SATA3_PCB_REG0, sata_regs);
	sata_write32(SP1SPR1_B150_W, SATA_PORT1_SATA3_PCB_REG1, sata_regs);

	reg = sata_read32(SATA_SATA_PORT1_CTRL_PCTRL5, sata_regs);
	reg |= SSP1CP5_OR;
	sata_write32(reg, SATA_SATA_PORT1_CTRL_PCTRL5, sata_regs);
	reg = sata_read32(SATA_SATA_PORT1_CTRL_PCTRL3, sata_regs);
	reg &= SSP1CP3_AND;
	sata_write32(reg, SATA_SATA_PORT1_CTRL_PCTRL3, sata_regs);
	reg = sata_read32(SATA_SATA_PORT1_CTRL_PCTRL4, sata_regs);
	reg |= SSP1CP4_OR;
	sata_write32(reg, SATA_SATA_PORT1_CTRL_PCTRL4, sata_regs);

	/* Access PLL register bank 1 */
	sata_write32(SP1SPBA_B060, SATA_PORT1_SATA3_PCB_BLOCK_ADDR, sata_regs);
	/* Set intN_fb_en bit */
	sata_write32(SP1SPR2_B060_W, SATA_PORT1_SATA3_PCB_REG2, sata_regs);
	/* Select integer divide mode (instead of fractional) */
	sata_write32(SP1SPR3_B060_W, SATA_PORT1_SATA3_PCB_REG3, sata_regs);
	/* Set PLL divider to 60 */
	sata_write32(SP1SPR4_B060_W, SATA_PORT1_SATA3_PCB_REG4, sata_regs);
	/* Access BLOCK_0 register bank */
	sata_write32(SP1SPBA_B000, SATA_PORT1_SATA3_PCB_BLOCK_ADDR, sata_regs);
	/* Set oob_clk_sel to refclk/2 */
	sata_write32(SP1SPR13_B000_W, SATA_PORT1_SATA3_PCB_REG13, sata_regs);
	if (aeq >= 0) {
		/* access AEQ register bank */
		sata_write32(SATA_PCB_BLOCK_AEQ,
			     SATA_PORT1_SATA3_PCB_BLOCK_ADDR,
			     sata_regs);
		/* set AEQ override format */
		reg = sata_read32(SATA_PORT1_SATA3_PCB_REG2, sata_regs);
		reg &= (~(1 << AEQ_CTRL2__RESERVED));
		reg |= (1 << AEQ_CTRL2__EQ_FORMAT);
		sata_write32(reg, SATA_PORT1_SATA3_PCB_REG2, sata_regs);
		/* set AEQ override and value */
		reg = ((aeq << AEQ_FRC_EQ__EQ_VAL_SHIFT) |
		       (AEQ_FRC_EQ__EQ_OVERRIDE_ENABLE));
		sata_write32(reg, SATA_PORT1_SATA3_PCB_REG3, sata_regs);
	}
	if (cdrlim >= 0) {
		/* access RXPMD registers */
		sata_write32(SATA_PCB_BLOCK_RXPMD,
			     SATA_PORT1_SATA3_PCB_BLOCK_ADDR,
			     sata_regs);
		/* set CDR integral limit and enable the limit */
		reg = ((1 << RXPMD_RX_FREQ_MON_CTRL1__CLAMP_ENABLE) |
		       cdrlim);
		sata_write32(reg, SATA_PORT1_SATA3_PCB_REG7, sata_regs);
	}

	/* strobe phy 1 reset */
	sata_write32(SSTCPC3_W1, SATA_SATA_TOP_CTRL_PHY_CTRL_3, sata_regs);
	sata_write32(SSTCPC4_W1, SATA_SATA_TOP_CTRL_PHY_CTRL_4, sata_regs);
	sata_mdelay(PHY_RESET_DELAY);
	sata_write32(SSTCPC3_W2, SATA_SATA_TOP_CTRL_PHY_CTRL_3, sata_regs);
	sata_write32(SSTCPC4_W2, SATA_SATA_TOP_CTRL_PHY_CTRL_4, sata_regs);
	sata_mdelay(PHY_RESET_DELAY);

	/* Access BLOCK_0 register bank */
	sata_write32(SP1SPBA_B000, SATA_PORT1_SATA3_PCB_BLOCK_ADDR, sata_regs);
	/* poll pll_lock for the port */
	for (cnt = 0;
	     ((cnt < PHY_LOOP_ITER) &&
	      (0 ==
	       (sata_read32(SATA_PORT1_SATA3_PCB_REG1, sata_regs) &
		(1 << SP1SPR1_B000_R)))); cnt++)
		sata_mdelay(PHY_LOOP_DELAY);
	if (0 ==
	    (sata_read32(SATA_PORT1_SATA3_PCB_REG1, sata_regs) &
	     (1 << SP1SPR1_B000_R))) {
		/* PLL did not lock; give up */
		dev_err(dev, "SATA port 1 PLL did not lock\n");
		result = -EIO;
		goto cleanup;
	}

cleanup:
	if (idm_regs)
		iounmap(idm_regs);
	if (sata_regs)
		iounmap(sata_regs);
	if (srp)
		release_mem_region(sata_res.start, resource_size(&sata_res));
	if (irp)
		release_mem_region(idm_res.start, resource_size(&idm_res));
	return result;
}

/*
 *  Device compatibility is put up above the code becuase it is referred to
 *  within the code so must be declared before the code.
 */
MODULE_DEVICE_TABLE(of, phy_bcm_ns2_sata_of_match);

static struct platform_driver phy_bcm_ns2_sata_driver = {
	.probe = phy_bcm_ns2_sata_probe,
	.driver = {
		   .name = DEVICE_COMPAT_NAME,
		   .owner = THIS_MODULE,
		   .of_match_table = phy_bcm_ns2_sata_of_match,
		   }
};

module_platform_driver(phy_bcm_ns2_sata_driver);

MODULE_ALIAS("platform:phy-bcm-ns2-sata");
MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("Broadcom NS2 SATA phy driver");
MODULE_LICENSE("GPL");
