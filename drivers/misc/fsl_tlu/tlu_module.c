/*
 * Copyright (C) 2007-2008 Freescale Semiconductor, Inc. All rights reserved.
 *
 * Author: Zhichun Hua, zhichun.hua@freescale.com, Mon Mar 12 2007
 *
 * Description:
 * This file contains driver of the TLU software. It is able to load and unload
 * the driver module. The user space interface is not provided.
 *
 * This file is part of the Linux kernel
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/of.h>
#include <asm/tlu.h>

MODULE_AUTHOR("Zhichun Hua <zhichun.hua@freescale.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TLU driver");

#define TLU_DEVICE_NAME "tlu"
#define MAX_TLU 2
#define MAX_BANK 4

static unsigned int log_level;
module_param(log_level, int, 0);

struct tlu tlu_devices[MAX_TLU];
static int tlu_num;

struct tlu *tlu_get(int id)
{

	if ((id >= tlu_num) || !tlu_devices[id].handle)
		return NULL;

	return &tlu_devices[id];
}
EXPORT_SYMBOL(tlu_get);

static int fsl_tlu_init(struct device_node *node)
{
	struct tlu_bank_param banks[MAX_BANK];
	struct resource res;
	struct tlu *tlu = &tlu_devices[tlu_num];
	struct tlu_bank_param *bp = &banks[0];
	struct device_node *bnode;
	int /*irq, */ret, bp_num = 0;

	if (tlu_num >= MAX_TLU) {
		printk(KERN_ERR "Exceeded maximum tlus (%d) with '%s'\n",
			MAX_TLU, node->full_name);
		return -ENODEV;
	}
	ret = of_address_to_resource(node, 0, &res);
	if (ret) {
		printk(KERN_ERR "Can't get %s property '%s'\n",
			node->full_name, "reg");
		return ret;
	}
	for_each_child_of_node(node, bnode) {
		const u32 *bank;
		if (!of_device_is_compatible(bnode, "fsl,mpc8572-tlu-bank")) {
			printk(KERN_ERR "Invalid tlu subnode '%s'\n",
				bnode->full_name);
			return -EINVAL;
		}
		if (bp_num >= MAX_BANK) {
			printk(KERN_ERR "Exceeded maximum tlu-banks (%d) with "
				"'%s'\n", MAX_BANK, node->full_name);
			return -ENODEV;
		}
		bank = of_get_property(bnode, "fsl,tlu-bank", &ret);
		if (!bank || !ret || (ret & 3)) {
			printk(KERN_ERR "Can't get %s property '%s'\n",
				bnode->full_name, "fsl,tlu-bank");
			return -EINVAL;
		}
		if (ret == 4) {
			bp->addr = 0;
			bp->size = bank[0];
		} else if (ret == 8) {
			bp->addr = bank[0];
			bp->size = bank[1];
		} else if (ret == 12) {
			if (bank[0]) {
				printk(KERN_ERR "No support for bank memory "
					"above 32-bit addresses\n");
				return -ERANGE;
			}
			bp->addr = bank[1];
			bp->size = bank[2];
		} else {
			printk(KERN_ERR "Invalid %s property '%s'\n",
				bnode->full_name, "fsl,bank");
			return -EINVAL;
		}
		/* now use 'bank' as a boolean pointer, don't waste stack */
		bank = of_get_property(bnode, "fsl,tlu-local-bus", &ret);
		if (bank)
			bp->type = TLU_MEM_LOCAL_BUS;
		else
			bp->parity = TLU_MEM_SYSTEM_DDR;
		bank = (void *)of_get_property(bnode, "fsl,parity", &ret);
		if (bank)
			bp->parity = TLU_MEM_PARITY_ENABLE;
		else
			bp->parity = TLU_MEM_PARITY_DISABLE;
		bp_num++;
	}
	/*irq = irq_of_parse_and_map(node, 0);
	if (irq == NO_IRQ)
		printk(KERN_INFO "No %s property in '%s', continuing\n",
			"interrupts", node->full_name);*/
	ret = tlu_init(tlu, res.start, bp_num, banks/*, irq*/);
	if (ret) {
		printk(KERN_ERR "Failed to initialise TLU %s\n",
			node->full_name);
		/*if (irq != NO_IRQ)
			irq_dispose_mapping(irq);*/
		return ret;
	}
	tlu_num++;
	printk(KERN_INFO "Initialised TLU %s\n", node->full_name);
	return 0;
}

int tlu_driver_init(void)
{
	struct device_node *dn;

	tlu_log_level = log_level;
	for_each_compatible_node(dn, NULL, "fsl,mpc8572-tlu") {
		int ret = fsl_tlu_init(dn);
		if (ret)
			return ret;
	}
	return 0;
}

void tlu_driver_cleanup(void)
{
	int i;

	for (i = 0; i < tlu_num; i++) {
		tlu_free(&tlu_devices[i]);
		printk(KERN_INFO "Cleaned up TLU %d\n", i);
	}
}

/* Module load/unload handlers */
module_init(tlu_driver_init);
module_exit(tlu_driver_cleanup);
