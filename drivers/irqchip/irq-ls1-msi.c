/*
 * Layerscape MSI(-X) support
 * Author: Arun Chandran <achandran@mvista.com>
 *
 * Based on drivers/irqchip/irq-ls1-msi.c from ls1043-mv-phase1
 * delivery from  Freescale Semiconductor.
 *
 * Credits for original drivers/irqchip/irq-ls1-msi.c from ls1043-mv-phase1:
 * Copyright (C) 2015 Freescale Semiconductor.
 * Author: Minghuan Lian <Minghuan.Lian@freescale.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>

#define MAX_MSI_IRQS	32

struct ls1_msi {
	char			name[32];
	struct device_node	*of_node;
	spinlock_t		lock;
	struct msi_controller	mchip;
	struct irq_chip		chip;
	struct irq_domain	*parent;
	void __iomem		*msir;
	phys_addr_t		msiir_addr;
	unsigned long		*bm;
	u32			nr_irqs;
	int			msi_irq;
};

static struct irq_chip ls1_msi_irq_chip = {
	.name		= "LS1-MSI",
	.irq_enable	= unmask_msi_irq,
	.irq_disable	= mask_msi_irq,
	.irq_mask	= mask_msi_irq,
	.irq_unmask	= unmask_msi_irq,
};

static int ls1_msi_host_map(struct irq_domain *domain, unsigned int virq,
			      irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(virq, &ls1_msi_irq_chip, handle_simple_irq);
	irq_set_chip_data(virq, domain->host_data);
	set_irq_flags(virq, IRQF_VALID);
	return 0;
}

static void ls1_msi_compose_msg(struct ls1_msi *msi_data, int hwirq, struct msi_msg *msg)
{
	phys_addr_t addr = msi_data->msiir_addr;

	msg->address_hi = (u32) (addr >> 32);
	msg->address_lo = (u32) (addr);
	msg->data = hwirq * 8;
}

static irqreturn_t ls1_msi_handler(int irq, void *arg)
{
	struct ls1_msi *msi_data = arg;
	unsigned long val;
	int pos, virq;
	irqreturn_t ret = IRQ_NONE;

	val = ioread32be(msi_data->msir);
	pos = 0;

	while ((pos = find_next_bit(&val, 32, pos)) != 32) {
		virq = irq_find_mapping(msi_data->parent, 31 - pos);
		if (virq > 0) {
			generic_handle_irq(virq);
			ret = IRQ_HANDLED;
		}
		pos++;
	}

	return ret;
}

static int ls1_msi_setup_irq(struct msi_controller *chip, struct pci_dev *pdev,
			struct msi_desc *desc)
{
	struct ls1_msi *msi_data = container_of(chip, struct ls1_msi, mchip);
	struct msi_msg msg;
	int hwirq = -1, virq, ret;

	spin_lock(&msi_data->lock);
	hwirq = bitmap_find_free_region(msi_data->bm, msi_data->nr_irqs,
				      order_base_2(1));
	spin_unlock(&msi_data->lock);

	if (hwirq < 0) {
		dev_err(&pdev->dev, "failed getting hwirq\n");
		ret = -ENOSPC;
		goto exit_2;
	}

	virq = irq_create_mapping(msi_data->parent, hwirq);
	if (virq == 0) {
		dev_err(&pdev->dev, "fail mapping hwirq %i\n", hwirq);
		ret = -ENOSPC;
		goto exit_1;
	}

	ret = irq_set_msi_desc(virq, desc);
	if (ret != 0) {
		dev_err(&pdev->dev, "failed setting MSI desc\n");
		goto exit_1;
	}

	ls1_msi_compose_msg(msi_data, hwirq, &msg);
	write_msi_msg(virq, &msg);

	return 0;
exit_1:
	spin_lock(&msi_data->lock);
	bitmap_release_region(msi_data->bm, hwirq, order_base_2(1));
	spin_unlock(&msi_data->lock);
exit_2:
	return ret;
}

static void ls1_msi_teardown_irq(struct msi_controller *chip, unsigned int virq)
{
	struct ls1_msi *msi_data = container_of(chip, struct ls1_msi, mchip);
	struct irq_data *d = irq_get_irq_data(virq);
	int pos;

	pos = d->hwirq;
	if (pos < 0 || pos >= msi_data->nr_irqs) {
		pr_err("Failed to teardown msi. Invalid hwirq %d\n", pos);
		return;
	}

	spin_lock(&msi_data->lock);
	bitmap_release_region(msi_data->bm, pos, order_base_2(1));
	spin_unlock(&msi_data->lock);

	irq_set_msi_desc(virq, NULL);
	irq_dispose_mapping(virq);
}

static const struct irq_domain_ops ls1_msi_host_ops = {
	.map = ls1_msi_host_map,
};

static int ls1_msi_chip_init(struct ls1_msi *msi_data)
{
	int ret;

	/* Initialize MSI domain parent */
	msi_data->parent = irq_domain_add_linear(msi_data->of_node,
						 msi_data->nr_irqs,
						 &ls1_msi_host_ops,
						 msi_data);
	if (!msi_data->parent) {
		pr_err("MSI domain %s parent init failed\n", msi_data->name);
		return -ENXIO;
	}

	/* Initialize MSI irq chip */
	msi_data->chip.name = msi_data->name;

	/* Initialize MSI controller */
	msi_data->mchip.of_node = msi_data->of_node;

	msi_data->mchip.setup_irq = ls1_msi_setup_irq;
	msi_data->mchip.teardown_irq = ls1_msi_teardown_irq;

	ret = of_pci_msi_chip_add(&msi_data->mchip);
	if (ret) {
		pr_err("Failed to add msi_chip %s\n", msi_data->name);
		goto _err;
	}

	return 0;
_err:
	if (msi_data->parent)
		irq_domain_remove(msi_data->parent);
	return ret;
}

static int __init ls1_msi_probe(struct platform_device *pdev)
{
	struct ls1_msi *msi_data;
	struct resource *res;
	static int ls1_msi_idx;
	int ret;

	msi_data = devm_kzalloc(&pdev->dev, sizeof(*msi_data), GFP_KERNEL);
	if (!msi_data) {
		dev_err(&pdev->dev, "Failed to allocate struct ls1_msi.\n");
		return -ENOMEM;
	}

	msi_data->of_node = pdev->dev.of_node;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "msiir");
	if (!res) {
		dev_err(&pdev->dev, "missing *msiir* space\n");
		return -ENODEV;
	}

	msi_data->msiir_addr = res->start;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "msir");
	if (!res) {
		dev_err(&pdev->dev, "missing *msir* space\n");
		return -ENODEV;
	}

	msi_data->msir = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(msi_data->msir))
		return PTR_ERR(msi_data->msir);

	msi_data->msi_irq = platform_get_irq(pdev, 0);
	if (msi_data->msi_irq <= 0) {
		dev_err(&pdev->dev, "failed to get MSI irq\n");
		return -ENODEV;
	}

	msi_data->nr_irqs = MAX_MSI_IRQS;

	msi_data->bm = devm_kzalloc(&pdev->dev, sizeof(long) *
				    BITS_TO_LONGS(msi_data->nr_irqs),
				    GFP_KERNEL);
	if (!msi_data->bm)
		ret = -ENOMEM;

	ls1_msi_idx++;
	snprintf(msi_data->name, sizeof(msi_data->name), "MSI%d", ls1_msi_idx);

	spin_lock_init(&msi_data->lock);

	ret = devm_request_irq(&pdev->dev, msi_data->msi_irq,
			       ls1_msi_handler, IRQF_SHARED,
			       msi_data->name, msi_data);
	if (ret) {
		dev_err(&pdev->dev, "failed to request MSI irq\n");
		return -ENODEV;
	}

	return ls1_msi_chip_init(msi_data);
}

static struct of_device_id ls1_msi_id[] = {
	{ .compatible = "fsl,1s1021a-msi", },
	{ .compatible = "fsl,1s1043a-msi", },
	{},
};

static struct platform_driver ls1_msi_driver = {
	.driver = {
		.name = "ls1-msi",
		.of_match_table = ls1_msi_id,
	},
};

module_platform_driver_probe(ls1_msi_driver, ls1_msi_probe);

MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@freescale.com>");
MODULE_AUTHOR("Arun Chandran <achandran@mvista.com>");
MODULE_DESCRIPTION("Freescale Layerscape 1 MSI controller driver");
MODULE_LICENSE("GPL v2");
