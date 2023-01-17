/*
 * ARM GIC v2m MSI(-X) support
 * Support for Message Signaled Interrupts for systems that
 * implement ARM Generic Interrupt Controller: GICv2m.
 *
 * Copyright (C) 2014 Advanced Micro Devices, Inc.
 * Authors: Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>
 *	    Harish Kasiviswanathan <harish.kasiviswanathan@amd.com>
 *	    Brandon Anderson <brandon.anderson@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#define pr_fmt(fmt) "GICv2m: " fmt

#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/kernel.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/irqchip/arm-gic.h>

/*
* MSI_TYPER:
*     [31:26] Reserved
*     [25:16] lowest SPI assigned to MSI
*     [15:10] Reserved
*     [9:0]   Numer of SPIs assigned to MSI
*/
#define V2M_MSI_TYPER		       0x008
#define V2M_MSI_TYPER_BASE_SHIFT       16
#define V2M_MSI_TYPER_BASE_MASK	       0x3FF
#define V2M_MSI_TYPER_NUM_MASK	       0x3FF
#define V2M_MSI_SETSPI_NS	       0x040
#define V2M_MIN_SPI		       32
#define V2M_MAX_SPI		       1019

#define V2M_MSI_TYPER_BASE_SPI(x)      \
	       (((x) >> V2M_MSI_TYPER_BASE_SHIFT) & V2M_MSI_TYPER_BASE_MASK)

#define V2M_MSI_TYPER_NUM_SPI(x)       ((x) & V2M_MSI_TYPER_NUM_MASK)

LIST_HEAD(v2m_list);

struct v2m_data {
	spinlock_t msi_cnt_lock;
	struct list_head list;
	struct msi_controller mchip;
	struct resource res;	/* GICv2m resource */
	void __iomem *base;	/* GICv2m virt address */
	u32 spi_start;		/* The SPI number that MSIs start */
	u32 nr_spis;		/* The number of SPIs for MSIs */
	unsigned long *bm;	/* MSI vector bitmap */
	void *gic_chip_data;
};

inline void *irq_data_get_irq_chip_data_v2m(struct irq_data *d)
{
	void *gic_data;
	struct msi_controller *mchip;
	struct v2m_data *v2mdat;

	/*
	 * For MSI, irq_data.chip_data points to struct msi_chip.
	 * For non-MSI, irq_data.chip_data points to struct gic_chip_data.
	 */
	if (d->msi_desc) {
		mchip = irq_data_get_irq_chip_data(d);
		v2mdat = container_of(mchip, struct v2m_data, mchip);
		gic_data = v2mdat->gic_chip_data;
	} else {
		gic_data = irq_data_get_irq_chip_data(d);
	}
	return gic_data;
}

static void gicv2m_mask_irq(struct irq_data *d)
{
	gic_mask_irq(d);
	if (d->msi_desc)
		mask_msi_irq(d);
}

static void gicv2m_unmask_irq(struct irq_data *d)
{
	gic_unmask_irq(d);
	if (d->msi_desc)
		unmask_msi_irq(d);
}

bool gicv2m_check_msi_range(irq_hw_number_t hw)
{
	struct v2m_data *v2m = NULL;

	list_for_each_entry(v2m, &v2m_list, list) {
		if (hw >= v2m->spi_start &&
		    hw <  v2m->spi_start + v2m->nr_spis)
			return true;
	}
	return false;
}

static void gicv2m_teardown_msi_irq(struct msi_controller *chip, unsigned int hwirq)
{
	int pos;
	struct v2m_data *v2m = container_of(chip, struct v2m_data, mchip);

	pos = hwirq - v2m->spi_start;
	if (pos < 0 || pos >= v2m->nr_spis) {
		pr_err("Failed to teardown msi. Invalid hwirq %d\n", hwirq);
		return;
	}

	spin_lock(&v2m->msi_cnt_lock);
	__clear_bit(pos, v2m->bm);
	spin_unlock(&v2m->msi_cnt_lock);
}

static int gicv2m_setup_msi_irq(struct msi_controller *chip,
				struct pci_dev *pdev,
				struct msi_desc *desc)
{
	int hwirq, offset, err = 0;
	struct msi_msg msg;
	phys_addr_t addr;
	struct v2m_data *v2m = container_of(chip, struct v2m_data, mchip);

	if (!desc) {
		dev_err(&pdev->dev,
			"GICv2m: MSI setup failed. Invalid msi descriptor\n");
		return -EINVAL;
	}

	spin_lock(&v2m->msi_cnt_lock);
	offset = find_first_zero_bit(v2m->bm, v2m->nr_spis);
	if (offset < v2m->nr_spis)
		__set_bit(offset, v2m->bm);
	else
		err = -ENOSPC;
	spin_unlock(&v2m->msi_cnt_lock);

	if (err)
		return err;

	hwirq = v2m->spi_start + offset;

	irq_set_chip_data(hwirq, chip);
	irq_set_msi_desc(hwirq, desc);
	irq_set_irq_type(hwirq, IRQ_TYPE_EDGE_RISING);

	addr = v2m->res.start + V2M_MSI_SETSPI_NS;
	msg.address_hi = (u32)(addr >> 32);
	msg.address_lo = (u32)(addr);
	msg.data = hwirq;
	write_msi_msg(hwirq, &msg);

	return 0;
}

static bool is_msi_spi_valid(u32 base, u32 num)
{
	if (base < V2M_MIN_SPI) {
		pr_err("Invalid MSI base SPI (base:%u)\n", base);
		return false;
	}

	if ((num == 0) || (base + num > V2M_MAX_SPI)) {
		pr_err("Number of SPIs (%u) exceed maximum (%u)\n",
		       num, V2M_MAX_SPI - V2M_MIN_SPI + 1);
		return false;
	}

	return true;
}

static int __init gicv2m_init_one(struct device_node *node, void *gic_chip_data)
{
	int ret;
	struct v2m_data *v2m;

	v2m = kzalloc(sizeof(struct v2m_data), GFP_KERNEL);
	if (!v2m) {
		pr_err("Failed to allocate struct v2m_data.\n");
		return -ENOMEM;
	}

	ret = of_address_to_resource(node, 0, &v2m->res);
	if (ret) {
		pr_err("Failed to allocate v2m resource.\n");
		goto err_free_v2m;
	}

	v2m->base = ioremap(v2m->res.start, resource_size(&v2m->res));
	if (!v2m->base) {
		pr_err("Failed to map GICv2m resource\n");
		ret = -ENOMEM;
		goto err_free_v2m;
	}

	if (!of_property_read_u32(node, "arm,msi-base-spi", &v2m->spi_start) &&
	    !of_property_read_u32(node, "arm,msi-num-spis", &v2m->nr_spis)) {
		pr_info("Overriding V2M MSI_TYPER (base:%u, num:%u)\n",
			v2m->spi_start, v2m->nr_spis);
	} else {
		u32 typer = readl_relaxed(v2m->base + V2M_MSI_TYPER);

		v2m->spi_start = V2M_MSI_TYPER_BASE_SPI(typer);
		v2m->nr_spis = V2M_MSI_TYPER_NUM_SPI(typer);
	}

	if (!is_msi_spi_valid(v2m->spi_start, v2m->nr_spis)) {
		ret = -EINVAL;
		goto err_iounmap;
	}

	v2m->bm = kzalloc(sizeof(long) * BITS_TO_LONGS(v2m->nr_spis),
			  GFP_KERNEL);
	if (!v2m->bm) {
		ret = -ENOMEM;
		goto err_iounmap;
	}

	v2m->gic_chip_data = gic_chip_data;
	v2m->mchip.of_node = node;
	v2m->mchip.owner = THIS_MODULE;
	v2m->mchip.setup_irq = gicv2m_setup_msi_irq;
	v2m->mchip.teardown_irq = gicv2m_teardown_msi_irq;

	ret = of_pci_msi_chip_add(&v2m->mchip);
	if (ret) {
		pr_err("Failed to add msi_chip.\n");
		goto err_free_bm;
	}

	spin_lock_init(&v2m->msi_cnt_lock);
	list_add_tail(&v2m->list, &v2m_list);

	pr_info("Node %s: range[%#lx:%#lx], SPI[%d:%d]\n", node->name,
		(unsigned long)v2m->res.start, (unsigned long)v2m->res.end,
		v2m->spi_start, (v2m->spi_start + v2m->nr_spis));

	return 0;

err_free_bm:
	kfree(v2m->bm);
err_iounmap:
	iounmap(v2m->base);
err_free_v2m:
	kfree(v2m);
	return ret;
}

static struct of_device_id gicv2m_device_id[] = {
	{	.compatible	= "arm,gic-v2m-frame",	},
	{},
};

int __init gicv2m_of_init(struct device_node *node, void *gic_chip_data, struct irq_chip *v2m_chip)
{
	int ret = 0;
	struct device_node *child;

	v2m_chip->irq_mask = gicv2m_mask_irq;
	v2m_chip->irq_unmask = gicv2m_unmask_irq;

	for (child = of_find_matching_node(node, gicv2m_device_id); child;
	     child = of_find_matching_node(child, gicv2m_device_id)) {
		if (!of_find_property(child, "msi-controller", NULL))
			continue;

		ret = gicv2m_init_one(child, gic_chip_data);
		if (ret) {
			of_node_put(node);
			break;
		}
	}

	return ret;
}
