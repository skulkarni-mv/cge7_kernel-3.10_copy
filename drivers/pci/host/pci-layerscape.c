/*
 * PCIe host controller driver for Freescale Layerscape SoCs
 *
 * Copyright (C) 2014 Freescale Semiconductor.
 *
  * Author: Minghuan Lian <Minghuan.Lian@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include <linux/irqchip/arm-gic-v3.h>

#include "pcie-designware.h"

/* PEX1/2 Misc Ports Status Register */
#define SCFG_PEXMSCPORTSR(pex_idx)	(0x94 + (pex_idx) * 4)
#define LTSSM_STATE_SHIFT	20
#define LTSSM_STATE_MASK	0x3f
#define LTSSM_PCIE_L0		0x11 /* L0 state */

/* PEX internal configuration registers */
#define PCIE_STRFMR1		0x71c /* Symbol Timer & Filter Mask Register1 */
#define PCIE_DBI_RO_WR_EN	0x8bc /* DBI Read-Only Write Enable Register */

#define PCIE_SRIOV_OFFSET	0x178

#define PCIE_CS2_OFFSET		0x1000 /* For PCIe without SR-IOV */
#define PCIE_ENABLE_CS2		0x80000000 /* For PCIe with SR-IOV */

/* PEX LUT registers */
#define PCIE_LUT_BASE		0x80000
#define PCIE_LUT_DBG		0x7FC /* PEX LUT Debug register */
#define PCIE_LUT_CTRL0		0x7f8
#define PCIE_LUT_PEXLSR		0x020 /* PEX LUT Status Register */
#define PCIE_LUT_PEXLCR		0x024 /* PEX LUT Control Register */
#define PCIE_LUT_UDR(n)		(0x800 + (n) * 8)
#define PCIE_LUT_LDR(n)		(0x804 + (n) * 8)
#define PCIE_LUT_MASK_ALL	0xffff
#define PCIE_LUT_DR_NUM		32
#define PCIE_LUT_ENABLE		(1 << 31)

#define PCIE_LUT_LS1043A_BASE	0x10000 /* Finally it will be got from DTS */
#define LS1043A_LTSSM_STATE_SHIFT	24

struct ls_pcie {
	struct list_head node;
	struct device *dev;
	struct pci_bus *bus;
	void __iomem *dbi;
	void __iomem *lut;
	struct regmap *scfg;
	struct pcie_port pp;
	int index;
	int msi_irq;
	const u32 *avail_streamids;
	int streamid_index;
};

static u32 layerscape_pci_requester_id(struct pci_dev *dev, u16 alias)
{

#ifdef CONFIG_ARCH_LAYERSCAPE
	if (dev->dev_flags & PCI_DEV_FLAGS_DMA_ALIAS_DEVID)
		return dev->dma_alias_devid;
#endif
	return (u32) ((pci_domain_nr(dev->bus) << 16) |		\
		      ((dev)->bus->number << 8) | (dev)->devfn);
}

#define to_ls_pcie(x)	container_of(x, struct ls_pcie, pp)

static int ls1_pcie_link_up(struct pcie_port *pp)
{
	u32 state;
	struct ls_pcie *pcie = to_ls_pcie(pp);

	regmap_read(pcie->scfg, SCFG_PEXMSCPORTSR(pcie->index), &state);
	state = (state >> LTSSM_STATE_SHIFT) & LTSSM_STATE_MASK;

	if (state < LTSSM_PCIE_L0)
		return 0;

	return 1;
}

static void ls_pcie_disable_inbound_bar(struct ls_pcie *pcie)
{
	u32 header;

	header = ioread32(pcie->dbi + PCIE_SRIOV_OFFSET);
	if (PCI_EXT_CAP_ID(header) == PCI_EXT_CAP_ID_SRIOV) {
		iowrite32(PCIE_ENABLE_CS2, pcie->lut + PCIE_LUT_CTRL0);
		iowrite32(0, pcie->dbi + PCI_BASE_ADDRESS_0);
		iowrite32(0, pcie->dbi + PCI_BASE_ADDRESS_1);
		iowrite32(0, pcie->dbi + PCI_ROM_ADDRESS1);
		iowrite32(0, pcie->lut + PCIE_LUT_CTRL0);
	} else {
		iowrite32(0,
			  pcie->dbi + PCIE_CS2_OFFSET + PCI_BASE_ADDRESS_0);
		iowrite32(0,
			  pcie->dbi + PCIE_CS2_OFFSET + PCI_BASE_ADDRESS_1);
		iowrite32(0,
			  pcie->dbi + PCIE_CS2_OFFSET + PCI_ROM_ADDRESS1);
	}
}

static void ls1_pcie_host_init(struct pcie_port *pp)
{
	struct ls_pcie *pcie = to_ls_pcie(pp);
	int count = 0;
	u32 val;

	dw_pcie_setup_rc(pp);

	while (!ls1_pcie_link_up(pp)) {
		usleep_range(100, 1000);
		count++;
		if (count >= 200) {
			dev_err(pp->dev, "phy link never came up\n");
			return;
		}
	}

	/*
	 * LS1021A Workaround for internal TKT228622
	 * to fix the INTx hang issue
	 */
	val = ioread32(pcie->dbi + PCIE_STRFMR1);
	val &= 0xffff;
	iowrite32(val, pcie->dbi + PCIE_STRFMR1);

	ls_pcie_disable_inbound_bar(pcie);
}

static int ls1043a_pcie_link_up(struct pcie_port *pp)
{
	u32 state;
	struct ls_pcie *pcie = to_ls_pcie(pp);

	state = (ioread32(pcie->lut + PCIE_LUT_DBG) >>
		LS1043A_LTSSM_STATE_SHIFT) & LTSSM_STATE_MASK;

	if (state < LTSSM_PCIE_L0)
		return 0;

	return 1;
}

static void ls1043a_pcie_host_init(struct pcie_port *pp)
{
	int count = 0;
	struct ls_pcie *pcie = to_ls_pcie(pp);

	dw_pcie_setup_rc(pp);

	/* Fix class value and clean multi-func bit */
	writel(1, pcie->dbi + PCIE_DBI_RO_WR_EN);
	dw_pcie_cfg_write(pcie->dbi + (PCI_CLASS_DEVICE & ~0x3),
			  PCI_CLASS_DEVICE, 2,
			  PCI_CLASS_BRIDGE_PCI);
	dw_pcie_cfg_write(pcie->dbi + (PCI_HEADER_TYPE & ~0x3),
			  PCI_HEADER_TYPE, 1,
			  PCI_HEADER_TYPE_BRIDGE);
	writel(0, pcie->dbi + PCIE_DBI_RO_WR_EN);

	ls_pcie_disable_inbound_bar(pcie);

	while (!ls1043a_pcie_link_up(pp)) {
		usleep_range(100, 1000);
		count++;
		if (count >= 200) {
			dev_err(pp->dev, "phy link never came up\n");
			return;
		}
	}
}

static int ls2_pcie_link_up(struct pcie_port *pp)
{
	u32 state;
	struct ls_pcie *pcie = to_ls_pcie(pp);

	state = ioread32(pcie->lut + PCIE_LUT_DBG) & LTSSM_STATE_MASK;
	if (state < LTSSM_PCIE_L0)
		return 0;

	return 1;
}

static void ls2_pcie_host_init(struct pcie_port *pp)
{
	int count = 0;
	struct ls_pcie *pcie = to_ls_pcie(pp);

	dw_pcie_setup_rc(pp);

	/* Fix class value and clean multi-func bit */
	writel(1, pcie->dbi + PCIE_DBI_RO_WR_EN);
	dw_pcie_cfg_write(pcie->dbi + (PCI_CLASS_DEVICE & ~0x3),
			  PCI_CLASS_DEVICE, 2,
			  PCI_CLASS_BRIDGE_PCI);
	dw_pcie_cfg_write(pcie->dbi + (PCI_HEADER_TYPE & ~0x3),
			  PCI_HEADER_TYPE, 1,
			  PCI_HEADER_TYPE_BRIDGE);
	writel(0, pcie->dbi + PCIE_DBI_RO_WR_EN);

	ls_pcie_disable_inbound_bar(pcie);

	while (!ls2_pcie_link_up(pp)) {
		usleep_range(100, 1000);
		count++;
		if (count >= 200) {
			dev_err(pp->dev, "phy link never came up\n");
			return;
		}
	}
}

static struct pcie_host_ops ls_pcie_host_ops = {
	.link_up = ls2_pcie_link_up,
	.host_init = ls2_pcie_host_init,
};

static bool ls_pcie_is_bridge(struct ls_pcie *pcie)
{
	u32 header_type = 0;

	dw_pcie_cfg_read(pcie->dbi + (PCI_HEADER_TYPE & ~0x3),
			 PCI_HEADER_TYPE, 2, &header_type);

	return (header_type & 0x7f) == PCI_HEADER_TYPE_BRIDGE;
}

static int ls_add_pcie_port(struct ls_pcie *pcie)
{
	struct pcie_port *pp;
	int ret;

	pp = &pcie->pp;
	pp->dev = pcie->dev;
	pp->dbi_base = pcie->dbi;
	pp->root_bus_nr = -1;
	pp->ops = &ls_pcie_host_ops;

	ret = dw_pcie_host_init(pp);
	if (ret) {
		dev_err(pp->dev, "failed to initialize host\n");
		return ret;
	}

	return 0;
}

static inline struct pcie_port *sys_to_pcie(struct pci_sys_data *sys)
{
	BUG_ON(!sys->private_data);
	return sys->private_data;
}

static u32 set_pcie_streamid_translation(struct pci_dev *pdev, u32 devid)
{
	u32 index, streamid;
	struct pcie_port *pp = sys_to_pcie(pdev->bus->sysdata);
	struct ls_pcie *pcie = to_ls_pcie(pp);

	if (!pcie->avail_streamids || !pcie->streamid_index)
		return ~(u32)0;

	index = --pcie->streamid_index;
	/* mask is set as all zeroes, want to match all bits */
	iowrite32((devid << 16), pcie->lut + PCIE_LUT_UDR(index));
	streamid = be32_to_cpup(&pcie->avail_streamids[index]);
	iowrite32(streamid | PCIE_LUT_ENABLE, pcie->lut + PCIE_LUT_LDR(index));

	return streamid;
}

static int ls_pcibios_add_device(struct pci_dev *dev)
{
	u32 devid = PCI_DEVID(dev->bus->number, dev->devfn);
	u32 sid;

	sid = set_pcie_streamid_translation(dev, devid);
	if (sid == ~(u32)0)
		return -1;

	dev->dev_flags |= PCI_DEV_FLAGS_DMA_ALIAS_DEVID;
	dev->dma_alias_devid = sid;

	return 0;
}


static int __init ls_pcie_probe(struct platform_device *pdev)
{
	struct ls_pcie *pcie;
	struct resource *dbi_base;
	u32 index[2];
	int ret;

	pcie = devm_kzalloc(&pdev->dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	pcie->dev = &pdev->dev;

	dbi_base = platform_get_resource_byname(pdev, IORESOURCE_MEM, "regs");
	if (!dbi_base) {
		dev_err(&pdev->dev, "missing *regs* space\n");
		return -ENODEV;
	}

	set_its_pci_requester_id(layerscape_pci_requester_id);

	pcie->dbi = devm_ioremap_resource(&pdev->dev, dbi_base);
	if (IS_ERR(pcie->dbi))
		return PTR_ERR(pcie->dbi);

	if (of_device_is_compatible(pcie->dev->of_node, "fsl,ls1043a-pcie"))
		pcie->lut = pcie->dbi + PCIE_LUT_LS1043A_BASE;
	else
		pcie->lut = pcie->dbi + PCIE_LUT_BASE;

	/* Disable LDR zero */
	iowrite32(0, pcie->lut + PCIE_LUT_LDR(0));

	if (!ls_pcie_is_bridge(pcie))
		return 0;

	if (of_device_is_compatible(pcie->dev->of_node, "fsl,ls1021a-pcie")) {
		pcie->scfg = syscon_regmap_lookup_by_phandle(pdev->dev.of_node,
							     "fsl,pcie-scfg");
		if (IS_ERR(pcie->scfg)) {
			dev_err(&pdev->dev, "No syscfg phandle specified\n");
			return PTR_ERR(pcie->scfg);
		}

		ret = of_property_read_u32_array(pdev->dev.of_node,
						 "fsl,pcie-scfg", index, 2);
		if (ret)
			return ret;
		pcie->index = index[1];

		ls_pcie_host_ops.link_up = ls1_pcie_link_up;
		ls_pcie_host_ops.host_init = ls1_pcie_host_init;
	}

	if (of_device_is_compatible(pcie->dev->of_node, "fsl,ls1043a-pcie")) {
		ls_pcie_host_ops.link_up = ls1043a_pcie_link_up;
		ls_pcie_host_ops.host_init = ls1043a_pcie_host_init;
	}

	/*
	 * for LS208x the device id seen at the GIC ITS for MSIs is not
	 * the PCI device id, but rather the stream ID.  This mapping
	 * has to be programmed in the LUT table, and is done in
	 * ls_pcibios_add_device() as each device is added.
	 * The available stream IDs to choose from in making this mapping
	 * comes via a device tree property.
	 */
	if (of_device_is_compatible(pdev->dev.of_node, "fsl,ls2085a-pcie") ||
	    of_device_is_compatible(pdev->dev.of_node, "fsl,ls2080a-pcie")) {
		int len;
		const u32 *prop;
		struct device_node *np;

		np = pdev->dev.of_node;
		prop = (u32 *)of_get_property(np, "available-stream-ids", &len);
		if (prop) {
			pcie->avail_streamids = prop;
			pcie->streamid_index = len/sizeof(u32);
		} else
			dev_err(&pdev->dev, "PCIe endpoint partitioning not possible\n");

		set_pcibios_add_device(ls_pcibios_add_device);
	}

	ret = ls_add_pcie_port(pcie);
	if (ret < 0)
		return ret;

	platform_set_drvdata(pdev, pcie);

	return 0;
}

static const struct of_device_id ls_pcie_of_match[] = {
	{ .compatible = "fsl,ls1021a-pcie" },
	{ .compatible = "fsl,ls1043a-pcie" },
	{ .compatible = "fsl,ls2085a-pcie" },
	{ .compatible = "fsl,ls2080a-pcie" },
	{ },
};
MODULE_DEVICE_TABLE(of, ls_pcie_of_match);

static struct platform_driver ls_pcie_driver = {
	.driver = {
		.name = "layerscape-pcie",
		.owner = THIS_MODULE,
		.of_match_table = ls_pcie_of_match,
	},
};

module_platform_driver_probe(ls_pcie_driver, ls_pcie_probe);

MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@freescale.com>");
MODULE_DESCRIPTION("Freescale Layerscape PCIe host controller driver");
MODULE_LICENSE("GPL v2");
