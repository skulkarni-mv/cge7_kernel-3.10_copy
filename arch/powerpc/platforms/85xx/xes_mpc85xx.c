/*
 * Copyright (C) 2009 Extreme Engineering Solutions, Inc.
 *
 * X-ES board-specific functionality
 *
 * Based on mpc85xx_ds code from Freescale Semiconductor, Inc.
 *
 * Author: Nate Case <ncase@xes-inc.com>
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/kdev_t.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/interrupt.h>
#include <linux/memblock.h>
#include <linux/of_platform.h>

#include <asm/time.h>
#include <asm/machdep.h>
#include <asm/pci-bridge.h>
#include <mm/mmu_decl.h>
#include <asm/prom.h>
#include <asm/udbg.h>
#include <asm/mpic.h>
#include <asm/ehv_pic.h>

#include <sysdev/fsl_soc.h>
#include <sysdev/fsl_pci.h>
#include "smp.h"

#include "mpc85xx.h"
#include "corenet_ds.h"

/* A few bit definitions needed for fixups on some boards */
#define MPC85xx_L2CTL_L2E		0x80000000 /* L2 enable */
#define MPC85xx_L2CTL_L2I		0x40000000 /* L2 flash invalidate */
#define MPC85xx_L2CTL_L2SIZ_MASK	0x30000000 /* L2 SRAM size (R/O) */

void __init xes_mpc85xx_pic_init(void)
{
	struct mpic *mpic;
	unsigned int flags = MPIC_BIG_ENDIAN;

	if (ppc_md.get_irq == mpic_get_coreint_irq)
		flags |= MPIC_ENABLE_COREINT;
	mpic = mpic_alloc(NULL, 0, flags,
			0, 256, " OpenPIC  ");
	BUG_ON(mpic == NULL);
	mpic_init(mpic);
}

static void xes_mpc85xx_configure_l2(void __iomem *l2_base)
{
	volatile uint32_t ctl, tmp;

	asm volatile("msync; isync");
	tmp = in_be32(l2_base);

	/*
	 * xMon may have enabled part of L2 as SRAM, so we need to set it
	 * up for all cache mode just to be safe.
	 */
	printk(KERN_INFO "xes_mpc85xx: Enabling L2 as cache\n");

	ctl = MPC85xx_L2CTL_L2E | MPC85xx_L2CTL_L2I;
	if (of_machine_is_compatible("MPC8540") ||
	    of_machine_is_compatible("MPC8560"))
		/*
		 * Assume L2 SRAM is used fully for cache, so set
		 * L2BLKSZ (bits 4:5) to match L2SIZ (bits 2:3).
		 */
		ctl |= (tmp & MPC85xx_L2CTL_L2SIZ_MASK) >> 2;

	asm volatile("msync; isync");
	out_be32(l2_base, ctl);
	asm volatile("msync; isync");
}

static void xes_mpc85xx_fixups(void)
{
	struct device_node *np;
	int err;

	/*
	 * Legacy xMon firmware on some X-ES boards does not enable L2
	 * as cache.  We must ensure that they get enabled here.
	 */
	for_each_node_by_name(np, "l2-cache-controller") {
		struct resource r[2];
		void __iomem *l2_base;

		/* Only MPC8548, MPC8540, and MPC8560 boards are affected */
		if (!of_device_is_compatible(np,
				    "fsl,mpc8548-l2-cache-controller") &&
		    !of_device_is_compatible(np,
				    "fsl,mpc8540-l2-cache-controller") &&
		    !of_device_is_compatible(np,
				    "fsl,mpc8560-l2-cache-controller"))
			continue;

		err = of_address_to_resource(np, 0, &r[0]);
		if (err) {
			printk(KERN_WARNING "xes_mpc85xx: Could not get "
			       "resource for device tree node '%s'",
			       np->full_name);
			continue;
		}

		l2_base = ioremap(r[0].start, resource_size(&r[0]));

		xes_mpc85xx_configure_l2(l2_base);
	}
}

/*
 * Setup the architecture
 */
static void __init xes_mpc85xx_setup_arch(void)
{
	mpc85xx_smp_init();

#if defined(CONFIG_PCI) && defined(CONFIG_PPC64)
	pci_devs_phb_init();
#endif

	fsl_pci_assign_primary();

	swiotlb_detect_4g();

	pr_info("X-ES MPC85xx-based single-board computer: %s\n", ppc_md.name);

	xes_mpc85xx_fixups();
}

machine_arch_initcall(xes_mpc8572, mpc85xx_common_publish_devices);
machine_arch_initcall(xes_mpc8548, mpc85xx_common_publish_devices);
machine_arch_initcall(xes_mpc8540, mpc85xx_common_publish_devices);
machine_arch_initcall(xes_qoriq, corenet_ds_publish_devices);

/*
 * Called very early, device-tree isn't unflattened
 */
static int __init xes_mpc8572_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return of_flat_dt_is_compatible(root, "xes,MPC8572");
}

static int __init xes_mpc8548_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return of_flat_dt_is_compatible(root, "xes,MPC8548");
}

static int __init xes_mpc8540_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	return of_flat_dt_is_compatible(root, "xes,MPC8540");
}

static int __init xes_qoriq_probe(void)
{
	unsigned long root = of_get_flat_dt_root();
#ifdef CONFIG_SMP
	extern struct smp_ops_t smp_85xx_ops;
#endif

	if (of_flat_dt_is_compatible(root, "xes,qoriq")) {
		return 1;
	} else if (of_flat_dt_is_compatible(root, "xes,qoriq-hv")) {
		ppc_md.init_IRQ = ehv_pic_init;
		ppc_md.get_irq = ehv_pic_get_irq;
		ppc_md.restart = fsl_hv_restart;
		ppc_md.power_off = fsl_hv_halt;
		ppc_md.halt = fsl_hv_halt;
#ifdef CONFIG_SMP
		/*
		 * Disable the timebase sync operations because we can't write
		 * to the timebase registers under the hypervisor.
		  */
		smp_85xx_ops.give_timebase = NULL;
		smp_85xx_ops.take_timebase = NULL;
#endif
		return 1;
	}

	return 0;
}

define_machine(xes_mpc8572) {
	.name			= "X-ES MPC8572",
	.probe			= xes_mpc8572_probe,
	.setup_arch		= xes_mpc85xx_setup_arch,
	.init_IRQ		= xes_mpc85xx_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};

define_machine(xes_mpc8548) {
	.name			= "X-ES MPC8548",
	.probe			= xes_mpc8548_probe,
	.setup_arch		= xes_mpc85xx_setup_arch,
	.init_IRQ		= xes_mpc85xx_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};

define_machine(xes_mpc8540) {
	.name			= "X-ES MPC8540",
	.probe			= xes_mpc8540_probe,
	.setup_arch		= xes_mpc85xx_setup_arch,
	.init_IRQ		= xes_mpc85xx_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
};

define_machine(xes_qoriq) {
	.name			= "X-ES QORIQ",
	.probe			= xes_qoriq_probe,
	.setup_arch		= xes_mpc85xx_setup_arch,
	.init_IRQ		= corenet_ds_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
	.get_irq		= mpic_get_coreint_irq,
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
	.init_early		= corenet_ds_init_early,
};
