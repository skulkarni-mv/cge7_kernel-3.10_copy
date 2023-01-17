/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2009-2012 Cavium, Inc.
 */

#include <linux/platform_device.h>
#include <linux/of_mdio.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/phy.h>
#include <linux/io.h>
#include <linux/pci.h>

#ifdef CONFIG_ARCH_THUNDER
#include <linux/of_address.h>
#include <linux/of.h>
#include "cvmx-smix-defs.h"
#else
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-smix-defs.h>
#endif

#define DRV_VERSION "1.0"
#define DRV_DESCRIPTION "Cavium Networks Octeon SMI/MDIO driver"

#define SMI_CMD		0x0
#define SMI_WR_DAT	0x8
#define SMI_RD_DAT	0x10
#define SMI_CLK		0x18
#define SMI_EN		0x20

enum octeon_mdiobus_mode {
	UNINIT = 0,
	C22,
	C45
};

struct octeon_mdiobus {
	struct mii_bus *mii_bus;
	u64 register_base;
	resource_size_t mdio_phys;
	resource_size_t regsize;
	enum octeon_mdiobus_mode mode;
	int phy_irq[PHY_MAX_ADDR];
};

#ifdef CONFIG_ARCH_THUNDER
static void cvmx_write_csr (uint64_t addr, uint64_t val)
{
	writeq_relaxed(val, (void *)addr);
}

static uint64_t cvmx_read_csr (uint64_t addr)
{
	return readq_relaxed((void *)addr);
}
#define oct_mdio_writeq(val, addr)	writeq(val, (void *)addr)
#define oct_mdio_readq(addr)		readq((void *)addr)
#endif

static void octeon_mdiobus_set_mode(struct octeon_mdiobus *p,
				    enum octeon_mdiobus_mode m)
{
	union cvmx_smix_clk smi_clk;

	if (m == p->mode)
		return;

	smi_clk.u64 = cvmx_read_csr(p->register_base + SMI_CLK);
	smi_clk.s.mode = (m == C45) ? 1 : 0;
	smi_clk.s.preamble = 1;
	cvmx_write_csr(p->register_base + SMI_CLK, smi_clk.u64);
	p->mode = m;
}

static int octeon_mdiobus_c45_addr(struct octeon_mdiobus *p,
				   int phy_id, int regnum)
{
	union cvmx_smix_cmd smi_cmd;
	union cvmx_smix_wr_dat smi_wr;
	int timeout = 1000;

	octeon_mdiobus_set_mode(p, C45);

	smi_wr.u64 = 0;
	smi_wr.s.dat = regnum & 0xffff;
	cvmx_write_csr(p->register_base + SMI_WR_DAT, smi_wr.u64);

	regnum = (regnum >> 16) & 0x1f;

	smi_cmd.u64 = 0;
	smi_cmd.s.phy_op = 0; /* MDIO_CLAUSE_45_ADDRESS */
	smi_cmd.s.phy_adr = phy_id;
	smi_cmd.s.reg_adr = regnum;
	cvmx_write_csr(p->register_base + SMI_CMD, smi_cmd.u64);

	do {
		/* Wait 1000 clocks so we don't saturate the RSL bus
		 * doing reads.
		 */
		__delay(1000);
		smi_wr.u64 = cvmx_read_csr(p->register_base + SMI_WR_DAT);
	} while (smi_wr.s.pending && --timeout);

	if (timeout <= 0)
		return -EIO;
	return 0;
}

static int octeon_mdiobus_read(struct mii_bus *bus, int phy_id, int regnum)
{
	struct octeon_mdiobus *p = bus->priv;
	union cvmx_smix_cmd smi_cmd;
	union cvmx_smix_rd_dat smi_rd;
	unsigned int op = 1; /* MDIO_CLAUSE_22_READ */
	int timeout = 1000;

	if (regnum & MII_ADDR_C45) {
		int r = octeon_mdiobus_c45_addr(p, phy_id, regnum);
		if (r < 0)
			return r;

		regnum = (regnum >> 16) & 0x1f;
		op = 3; /* MDIO_CLAUSE_45_READ */
	} else {
		octeon_mdiobus_set_mode(p, C22);
	}


	smi_cmd.u64 = 0;
	smi_cmd.s.phy_op = op;
	smi_cmd.s.phy_adr = phy_id;
	smi_cmd.s.reg_adr = regnum;
	cvmx_write_csr(p->register_base + SMI_CMD, smi_cmd.u64);

	do {
		/* Wait 1000 clocks so we don't saturate the RSL bus
		 * doing reads.
		 */
		__delay(1000);
		smi_rd.u64 = cvmx_read_csr(p->register_base + SMI_RD_DAT);
	} while (smi_rd.s.pending && --timeout);

	if (smi_rd.s.val)
		return smi_rd.s.dat;
	else
		return -EIO;
}

static int octeon_mdiobus_write(struct mii_bus *bus, int phy_id,
				int regnum, u16 val)
{
	struct octeon_mdiobus *p = bus->priv;
	union cvmx_smix_cmd smi_cmd;
	union cvmx_smix_wr_dat smi_wr;
	unsigned int op = 0; /* MDIO_CLAUSE_22_WRITE */
	int timeout = 1000;


	if (regnum & MII_ADDR_C45) {
		int r = octeon_mdiobus_c45_addr(p, phy_id, regnum);
		if (r < 0)
			return r;

		regnum = (regnum >> 16) & 0x1f;
		op = 1; /* MDIO_CLAUSE_45_WRITE */
	} else {
		octeon_mdiobus_set_mode(p, C22);
	}

	smi_wr.u64 = 0;
	smi_wr.s.dat = val;
	cvmx_write_csr(p->register_base + SMI_WR_DAT, smi_wr.u64);

	smi_cmd.u64 = 0;
	smi_cmd.s.phy_op = op;
	smi_cmd.s.phy_adr = phy_id;
	smi_cmd.s.reg_adr = regnum;
	cvmx_write_csr(p->register_base + SMI_CMD, smi_cmd.u64);

	do {
		/* Wait 1000 clocks so we don't saturate the RSL bus
		 * doing reads.
		 */
		__delay(1000);
		smi_wr.u64 = cvmx_read_csr(p->register_base + SMI_WR_DAT);
	} while (smi_wr.s.pending && --timeout);

	if (timeout <= 0)
		return -EIO;

	return 0;
}

static int octeon_mdiobus_probe(struct platform_device *pdev)
{
	struct octeon_mdiobus *bus;
#ifdef CONFIG_ARCH_THUNDER
	const __be32 *reg;
	uint64_t  addr, size;
#else
	struct resource *res_mem;
#endif
	union cvmx_smix_en smi_en;
	int err = -ENOENT;

	bus = devm_kzalloc(&pdev->dev, sizeof(*bus), GFP_KERNEL);
	if (!bus)
		return -ENOMEM;

#ifdef CONFIG_ARCH_THUNDER
	reg = of_get_property(pdev->dev.of_node, "reg", NULL);
	addr = of_translate_address(pdev->dev.of_node, reg);
	pr_err("%s: mdio addr 0x%llx\n",__func__, addr);
	size = of_read_number(reg + 2, 2);
	pr_err("%s: size 0x%llx\n",__func__, size);
	bus->register_base = (u64) devm_ioremap(&pdev->dev, addr, size);
#else
	res_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	if (res_mem == NULL) {
		dev_err(&pdev->dev, "found no memory resource\n");
		err = -ENXIO;
		goto fail;
	}
	bus->mdio_phys = res_mem->start;
	bus->regsize = resource_size(res_mem);
	if (!devm_request_mem_region(&pdev->dev, bus->mdio_phys, bus->regsize,
				     res_mem->name)) {
		dev_err(&pdev->dev, "request_mem_region failed\n");
		goto fail;
	}
	bus->register_base =
		(u64)devm_ioremap(&pdev->dev, bus->mdio_phys, bus->regsize);
#endif

	bus->mii_bus = mdiobus_alloc();

	if (!bus->mii_bus)
		goto fail;

	smi_en.u64 = 0;
	smi_en.s.en = 1;
	cvmx_write_csr(bus->register_base + SMI_EN, smi_en.u64);

	bus->mii_bus->priv = bus;
	bus->mii_bus->irq = bus->phy_irq;
	bus->mii_bus->name = "mdio-octeon";
	snprintf(bus->mii_bus->id, MII_BUS_ID_SIZE, "%llx", bus->register_base);
	bus->mii_bus->parent = &pdev->dev;

	bus->mii_bus->read = octeon_mdiobus_read;
	bus->mii_bus->write = octeon_mdiobus_write;

#ifdef CONFIG_ARCH_THUNDER
	platform_set_drvdata(pdev, bus);
#else
	dev_set_drvdata(&pdev->dev, bus);
#endif

	err = of_mdiobus_register(bus->mii_bus, pdev->dev.of_node);
	if (err)
		goto fail_register;

	dev_info(&pdev->dev, "Version " DRV_VERSION "\n");

	return 0;
fail_register:
	mdiobus_free(bus->mii_bus);
fail:
	smi_en.u64 = 0;
	cvmx_write_csr(bus->register_base + SMI_EN, smi_en.u64);
	return err;
}

static int octeon_mdiobus_remove(struct platform_device *pdev)
{
	struct octeon_mdiobus *bus;
	union cvmx_smix_en smi_en;

#ifdef CONFIG_ARCH_THUNDER
	bus = platform_get_drvdata(pdev);
#else
	bus = dev_get_drvdata(&pdev->dev);
#endif

	mdiobus_unregister(bus->mii_bus);
	mdiobus_free(bus->mii_bus);
	smi_en.u64 = 0;
	cvmx_write_csr(bus->register_base + SMI_EN, smi_en.u64);
	return 0;
}

static struct of_device_id octeon_mdiobus_match[] = {
	{
		.compatible = "cavium,octeon-3860-mdio",
	},
	{},
};
MODULE_DEVICE_TABLE(of, octeon_mdiobus_match);

static struct platform_driver octeon_mdiobus_driver = {
	.driver = {
		.name		= "mdio-octeon",
		.owner		= THIS_MODULE,
		.of_match_table = octeon_mdiobus_match,
	},
	.probe		= octeon_mdiobus_probe,
	.remove		= octeon_mdiobus_remove,
};

#ifndef CONFIG_ARCH_THUNDER
void octeon_mdiobus_force_mod_depencency(void)
{
	/* Let ethernet drivers force us to be loaded.  */
}
EXPORT_SYMBOL(octeon_mdiobus_force_mod_depencency);

module_platform_driver(octeon_mdiobus_driver);
#else

void thunderx_mdiobus_force_mod_depencency(void)
{
	/* Let ethernet drivers force us to be loaded.  */
}
EXPORT_SYMBOL(thunderx_mdiobus_force_mod_depencency);

#ifdef CONFIG_PCI

struct thunder_mdiobus_nexus {
	void __iomem *bar0;
	struct octeon_mdiobus *buses[4];
};

static int thunder_mdiobus_pci_probe(struct pci_dev *pdev,
				     const struct pci_device_id *ent)
{
	struct device_node *node;
	struct thunder_mdiobus_nexus *nexus;
	int err;
	int i;

	nexus = devm_kzalloc(&pdev->dev, sizeof(*nexus), GFP_KERNEL);
	if (!nexus)
		return -ENOMEM;

	pci_set_drvdata(pdev, nexus);

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, KBUILD_MODNAME);
	if (err) {
		dev_err(&pdev->dev, "pci_request_regions failed\n");
		goto err_disable_device;
	}

	nexus->bar0 = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!nexus->bar0) {
		dev_err(&pdev->dev, "pcim_iomap failed\n");
		err = -ENOMEM;
		goto err_release_regions;
	}

	i = 0;
	for_each_child_of_node(pdev->dev.of_node, node) {
		struct resource r;
		struct octeon_mdiobus *bus;
		union cvmx_smix_en smi_en;

		if (!node)
			break;
		
		err = of_address_to_resource(node, 0, &r);
		if (err) {
			dev_err(&pdev->dev,
				"Couldn't translate address for \"%s\"\n",
				node->name);
			break;
		}
		bus = devm_kzalloc(&pdev->dev, sizeof(struct octeon_mdiobus),
				   GFP_KERNEL);

		if (!bus)
			break;

		nexus->buses[i] = bus;
		i++;

		bus->register_base = (u64)nexus->bar0 +
			r.start - pci_resource_start(pdev, 0);

		bus->mii_bus = mdiobus_alloc();
		if (!bus->mii_bus)
			break;

		smi_en.u64 = 0;
		smi_en.s.en = 1;
		oct_mdio_writeq(smi_en.u64, bus->register_base + SMI_EN);
		bus->mii_bus->priv = bus;
		bus->mii_bus->irq = bus->phy_irq;
		bus->mii_bus->name = KBUILD_MODNAME;
		snprintf(bus->mii_bus->id, MII_BUS_ID_SIZE, "%llx", r.start);
		bus->mii_bus->parent = &pdev->dev;
		bus->mii_bus->read = octeon_mdiobus_read;
		bus->mii_bus->write = octeon_mdiobus_write;

		err = of_mdiobus_register(bus->mii_bus, node);
		if (err)
			dev_err(&pdev->dev, "of_mdiobus_register failed\n");

		dev_info(&pdev->dev, "Added bus at %llx\n", r.start);
		if (i >= ARRAY_SIZE(nexus->buses))
			break;
	}
	return 0;

err_release_regions:
	pci_release_regions(pdev);

err_disable_device:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void thunder_mdiobus_pci_remove(struct pci_dev *pdev)
{
	int i;
	union cvmx_smix_en smi_en;
	struct thunder_mdiobus_nexus *nexus = pci_get_drvdata(pdev);

	for (i = 0; i < ARRAY_SIZE(nexus->buses); i++) {
		struct octeon_mdiobus *bus = nexus->buses[i];

		if (!bus)
			continue;

		mdiobus_unregister(bus->mii_bus);
		mdiobus_free(bus->mii_bus);
		smi_en.u64 = 0;
		oct_mdio_writeq(smi_en.u64, bus->register_base + SMI_EN);
	}
	pci_set_drvdata(pdev, NULL);
}

static const struct pci_device_id thunder_mdiobus_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, 0xa02b) },
	{ 0, } /* End of table. */
};
MODULE_DEVICE_TABLE(pci, thunder_mdiobus_id_table);

static struct pci_driver thunder_mdiobus_driver = {
	.name = KBUILD_MODNAME,
	.id_table = thunder_mdiobus_id_table,
	.probe = thunder_mdiobus_pci_probe,
	.remove = thunder_mdiobus_pci_remove,
};
#endif /* CONFIG_PCI */

static int __init octeon_mdiobus_driver_init(void)
{
	int r = platform_driver_register(&octeon_mdiobus_driver);

#ifdef CONFIG_PCI
	if (r)
		return r;

	r = pci_register_driver(&thunder_mdiobus_driver);
#endif
	return r;
}
module_init(octeon_mdiobus_driver_init);

static void __exit octeon_mdiobus_driver_exit(void)
{
	platform_driver_unregister(&octeon_mdiobus_driver);
#ifdef CONFIG_PCI
	pci_unregister_driver(&thunder_mdiobus_driver);
#endif
}
module_exit(octeon_mdiobus_driver_exit);
#endif

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_VERSION(DRV_VERSION);
MODULE_AUTHOR("David Daney");
MODULE_LICENSE("GPL");
