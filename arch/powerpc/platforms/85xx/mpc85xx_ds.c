/*
 * MPC85xx DS Board Setup
 *
 * Author Xianghua Xiao (x.xiao@freescale.com)
 * Roy Zang <tie-fei.zang@freescale.com>
 * 	- Add PCI/PCI Exprees support
 * Copyright 2007 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/of_platform.h>

#include <asm/time.h>
#include <asm/machdep.h>
#include <asm/pci-bridge.h>
#include <mm/mmu_decl.h>
#include <asm/prom.h>
#include <asm/udbg.h>
#include <asm/mpic.h>
#include <asm/i8259.h>
#include <asm/swiotlb.h>

#include <sysdev/fsl_soc.h>
#include <sysdev/fsl_pci.h>
#include "smp.h"

#include "mpc85xx.h"

#undef DEBUG

#ifdef DEBUG
#define DBG(fmt, args...) printk(KERN_ERR "%s: " fmt, __func__, ## args)
#else
#define DBG(fmt, args...)
#endif

void __init mpc85xx_ds_pic_init(void)
{
	struct mpic *mpic;
	unsigned long root = of_get_flat_dt_root();

	if (of_flat_dt_is_compatible(root, "fsl,MPC8572DS-CAMP")) {
		mpic = mpic_alloc(NULL, 0,
			MPIC_NO_RESET |
			MPIC_BIG_ENDIAN |
			MPIC_SINGLE_DEST_CPU,
			0, 256, " OpenPIC  ");
	} else {
		mpic = mpic_alloc(NULL, 0,
			  MPIC_BIG_ENDIAN |
			  MPIC_SINGLE_DEST_CPU,
			0, 256, " OpenPIC  ");
	}

	BUG_ON(mpic == NULL);
	mpic_init(mpic);
}

#if defined(CONFIG_PPC_I8259) && defined(CONFIG_PCI)

static irqreturn_t mpc85xx_ds_8259_cascade_handler(int irq, void *unused)
{
	unsigned int nested_irq = i8259_irq();

	if (nested_irq == NO_IRQ)
		return IRQ_NONE;

	generic_handle_irq(nested_irq);
	return IRQ_HANDLED;
}

/* This is actually never called, but pointer to it is set in irqaction
 * to avoid forced threading of this handler, but at the same time allow
 * forced threading of any other handler that shares interrupt with this one */
static irqreturn_t mpc85xx_ds_8259_cascade_thread_fn(int irq, void *unused)
{
	return IRQ_NONE;
}

static struct irqaction mpc85xx_ds_8259_irqaction = {
	.handler = mpc85xx_ds_8259_cascade_handler,
	.thread_fn = mpc85xx_ds_8259_cascade_thread_fn,
	.flags = IRQF_SHARED,
	.name = "8259 cascade",
	.dev_id = &mpc85xx_ds_8259_irqaction, /* unused but must be non-zero */
};

/* This has to go to initcall because earlier kthreadd is not ready */
int __init mpc85xx_ds_8259_attach(void)
{
	struct device_node *np;
	struct device_node *cascade_node = NULL;
	int cascade_irq, ret;

	/* Initialize the i8259 controller */
	for_each_node_by_type(np, "interrupt-controller")
	    if (of_device_is_compatible(np, "chrp,iic")) {
		cascade_node = np;
		break;
	}

	if (cascade_node == NULL) {
		printk(KERN_DEBUG "Could not find i8259 PIC\n");
		return -ENODEV;
	}

	cascade_irq = irq_of_parse_and_map(cascade_node, 0);
	if (cascade_irq == NO_IRQ) {
		printk(KERN_ERR "Failed to map cascade interrupt\n");
		return -EINVAL;
	}

	i8259_init(cascade_node, 0);
	of_node_put(cascade_node);

	ret = setup_irq(cascade_irq, &mpc85xx_ds_8259_irqaction);
	if (unlikely(ret)) {
		printk(KERN_ERR "Failed to set i8259 IRQ handler\n");
		return ret;
	}

	return 0;
}
machine_arch_initcall(mpc8544_ds, mpc85xx_ds_8259_attach);
machine_arch_initcall(mpc8572_ds, mpc85xx_ds_8259_attach);
machine_arch_initcall(p2020_ds, mpc85xx_ds_8259_attach);

#endif	/* CONFIG_PPC_I8259 */

#ifdef CONFIG_PCI
extern int uli_exclude_device(struct pci_controller *hose,
				u_char bus, u_char devfn);

static struct device_node *pci_with_uli;

static int mpc85xx_exclude_device(struct pci_controller *hose,
				   u_char bus, u_char devfn)
{
	if (hose->dn == pci_with_uli)
		return uli_exclude_device(hose, bus, devfn);

	return PCIBIOS_SUCCESSFUL;
}
#endif	/* CONFIG_PCI */

static void __init mpc85xx_ds_uli_init(void)
{
#ifdef CONFIG_PCI
	struct device_node *node;

	/* See if we have a ULI under the primary */

	node = of_find_node_by_name(NULL, "uli1575");
	while ((pci_with_uli = of_get_parent(node))) {
		of_node_put(node);
		node = pci_with_uli;

		if (pci_with_uli == fsl_pci_primary) {
			ppc_md.pci_exclude_device = mpc85xx_exclude_device;
			break;
		}
	}
#endif
}

/*
 * Setup the architecture
 */
static void __init mpc85xx_ds_setup_arch(void)
{
	if (ppc_md.progress)
		ppc_md.progress("mpc85xx_ds_setup_arch()", 0);

	swiotlb_detect_4g();
	fsl_pci_assign_primary();
	mpc85xx_ds_uli_init();
	mpc85xx_smp_init();

	printk("MPC85xx DS board from Freescale Semiconductor\n");
}

/*
 * Called very early, device-tree isn't unflattened
 */
static int __init mpc8544_ds_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return !!of_flat_dt_is_compatible(root, "MPC8544DS");
}

machine_arch_initcall(mpc8544_ds, mpc85xx_common_publish_devices);
machine_arch_initcall(mpc8572_ds, mpc85xx_common_publish_devices);
machine_arch_initcall(p2020_ds, mpc85xx_common_publish_devices);

machine_arch_initcall(mpc8544_ds, swiotlb_setup_bus_notifier);
machine_arch_initcall(mpc8572_ds, swiotlb_setup_bus_notifier);
machine_arch_initcall(p2020_ds, swiotlb_setup_bus_notifier);

/*
 * Called very early, device-tree isn't unflattened
 */
static int __init mpc8572_ds_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return !!of_flat_dt_is_compatible(root, "fsl,MPC8572DS");
}

/*
 * Called very early, device-tree isn't unflattened
 */
static int __init p2020_ds_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return !!of_flat_dt_is_compatible(root, "fsl,P2020DS");
}

define_machine(mpc8544_ds) {
	.name			= "MPC8544 DS",
	.probe			= mpc8544_ds_probe,
	.setup_arch		= mpc85xx_ds_setup_arch,
	.init_IRQ		= mpc85xx_ds_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};

define_machine(mpc8572_ds) {
	.name			= "MPC8572 DS",
	.probe			= mpc8572_ds_probe,
	.setup_arch		= mpc85xx_ds_setup_arch,
	.init_IRQ		= mpc85xx_ds_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};

define_machine(p2020_ds) {
	.name			= "P2020 DS",
	.probe			= p2020_ds_probe,
	.setup_arch		= mpc85xx_ds_setup_arch,
	.init_IRQ		= mpc85xx_ds_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};
