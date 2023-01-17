/*
 * CORENET T104xqds based SoC DS Setup
 *
 * Maintained by Kumar Gala (see MAINTAINERS for contact information)
 *
 * Copyright 2009-2011 Freescale Semiconductor Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/kernel.h>
#include <linux/pci.h>

#include <asm/machdep.h>
#include <asm/udbg.h>
#include <asm/mpic.h>

#include <linux/of_fdt.h>

#include <sysdev/fsl_soc.h>
#include <asm/ehv_pic.h>
#include <sysdev/fsl_pci.h>

#include "corenet_ds.h"

static const char * const boards[] __initconst = {
	"fsl,T1040RDB",
	"fsl,T1042RDB",
	"fsl,T1042D4RDB",
	"fsl,T1040QDS",
	"fsl,T1042QDS",
	NULL
};

static const char * const hv_boards[] __initconst = {
	"fsl,T1040RDB-hv",
	"fsl,T1042RDB-hv",
	"fsl,T1042D4RDB-hv",
	"fsl,T1040QDS-hv",
	"fsl,T1042QDS-hv",
	NULL
};

/*
 * Called very early, device-tree isn't unflattened
 */
static int __init t104x_probe(void)
{
	unsigned long root = of_get_flat_dt_root();

	if (of_flat_dt_match(root, boards))
		return 1;

	/* Check if we're running under the Freescale hypervisor */
	if (of_flat_dt_match(root, hv_boards)) {
		ppc_md.init_IRQ = ehv_pic_init;
		ppc_md.get_irq = ehv_pic_get_irq;
		ppc_md.restart = fsl_hv_restart;
		ppc_md.power_off = fsl_hv_halt;
		ppc_md.halt = fsl_hv_halt;
		return 1;
	}

	return 0;
}

define_machine(t104x) {
	.name			= "T104X",
	.probe			= t104x_probe,
	.setup_arch		= corenet_ds_setup_arch,
	.init_IRQ		= corenet_ds_pic_init,
#ifdef CONFIG_PCI
	.pcibios_fixup_bus	= fsl_pcibios_fixup_bus,
#endif
/*
 * Core reset may cause issue if using the proxy mode of MPIC.
 * Use the mixed mode of MPIC if enabling CPU hotplug.
 */
#ifdef CONFIG_HOTPLUG_CPU
	.get_irq		= mpic_get_irq,
#else
	.get_irq		= mpic_get_coreint_irq,
#endif
	.restart		= fsl_rstcr_restart,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= udbg_progress,
#ifdef CONFIG_PPC64
	.power_save		= book3e_idle,
#else
	.power_save		= e500_idle,
#endif
	.init_early		= corenet_ds_init_early,
};

machine_arch_initcall(t104x, corenet_ds_publish_devices);

#ifdef CONFIG_SWIOTLB
machine_arch_initcall(t104x, swiotlb_setup_bus_notifier);
#endif
