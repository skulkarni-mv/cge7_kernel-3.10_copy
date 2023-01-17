/*
 * Serengeti board specific routines
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Feng Kan <fkan@appliedmicro.com>.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <linux/init.h>
#include <linux/of_platform.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <asm/machdep.h>
#include <asm/ppc4xx.h>
#include <asm/prom.h>
#include <asm/udbg.h>
#include <asm/time.h>
#include <asm/io.h>
#include <asm/mpic.h>
#include <asm/pci-bridge.h>
#include <asm/ipp.h>
#include <asm/smp.h>

extern void __init smp_ppc44x_init(void);

static __initdata struct of_device_id apm86xxx_of_bus[] = {
	{ .compatible = "apm,hbf", },
	{ .compatible = "apm,ahb", },
        { .compatible = "apm,ufc", },
	{ .compatible = "apm,apb", },
	{ .compatible = "apm,apm86xxx-shm", },
	{},
};

extern void cpu_l2c_init(void);

static void __init apm862xx_setup_arch(void)
{
#ifdef CONFIG_SMP
	smp_ppc44x_init();
#endif
}

static void __init apm862xx_init_irq(void)
{
	struct mpic *mpic1;
	struct device_node *np;
	struct device_node *np_cpu;
	struct resource res;
	unsigned int flags;
	int cpu_in_dts = 1; /* Assume 1 CPU */
	u32 *ptr_val;
	u8   spv_eoi = 0;
	phys_addr_t paddr = 0;

	/* Determine PIC address. */
	np = of_find_node_by_type(NULL, "open-pic");
	if (np == NULL)
		return;
	of_address_to_resource(np, 1, &res);

	ptr_val = (u32 *) of_get_property(np, "spv-eoi", NULL);
	if (ptr_val != NULL)
		spv_eoi = *ptr_val;

	/* Determine if second CPU is available */
	np_cpu = of_find_node_by_type(NULL, "cpu");
	if (np_cpu != NULL) {
		struct device_node *parent;
		
		parent = of_get_parent(np_cpu);
		np_cpu = of_get_next_child(parent, np_cpu);
		if (np_cpu != NULL)
			cpu_in_dts++;
		
		of_node_put(parent);
		if (np_cpu)
			of_node_put(np_cpu);
	}
	
	/* Alloc mpic structure and per isu has 16 INT entries. */
	flags = MPIC_BIG_ENDIAN | MPIC_NO_PTHROU_DIS;
#ifndef CONFIG_SMP
	flags |= MPIC_SINGLE_DEST_CPU;
#endif
#if defined(CONFIG_APM862xx) || defined(CONFIG_APM867xx)
	ipp_init(1);	/* Initialize the SlimPRO module early stage */
	/* APM862xx/APM867xx Spurious EOI workaround. See errata MPIC_1 */
	if ((strcmp(apm86xxx_rev(), "A0") == 0 ||
	     strcmp(apm86xxx_rev(), "A1") == 0)
            && spv_eoi) {
		flags |= MPIC_SPV_EOI;
		printk(KERN_INFO "mpic: enable spurious EOI\n");
	}
#endif

 /* APM866xx support for Domain protection */
#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
        ipp_init(1);    /* Initialize the SlimPRO module early stage */
        if (apm86xxx_is_dp_mode() && hard_smp_processor_id() != 0 &&
            of_address_to_resource(np, 1, &res) == 0) {
                paddr = res.start;
                printk(KERN_INFO "mpic: resource 0x%02X.%08X\n",
                        (u32) (paddr >> 32), (u32) paddr);
        }
#endif
	mpic1 = mpic_alloc(np, paddr, flags, 0, 256, " MPIC     ");
	BUG_ON(mpic1 == NULL);

	mpic_init(mpic1);
	of_node_put(np);
}

static int __init apm862xx_device_probe(void)
{
	of_platform_bus_probe(NULL, apm86xxx_of_bus, NULL);

	return 0;
}
machine_device_initcall(serengeti, apm862xx_device_probe);

static int __init apm862xx_probe(void)
{
	unsigned long root = of_get_flat_dt_root();
	if (!of_flat_dt_is_compatible(root, "apm,apm862xx"))
		return 0;

#if 0 
	/* Disabled FKAN for 3.x porting */
	ppc_pci_set_flags(PPC_PCI_REASSIGN_ALL_RSRC);
#endif
	
	return 1;
}

define_machine(serengeti) {
#if defined(CONFIG_APM862xxvB)
	.name			= "APM862xx vB",
#elif defined(CONFIG_APM862xx)
	.name			= "APM862xx",
#elif defined(CONFIG_APM867xx)
	.name			= "APM867xx",
#else /* defined(CONFIG_APM866xx) */
	.name			= "APM866xx",
#endif
	.probe			= apm862xx_probe,
	.setup_arch		= apm862xx_setup_arch,
	.progress		= udbg_progress,
	.init_IRQ		= apm862xx_init_irq, 
	.get_irq		= mpic_get_irq,
	.restart		= ppc4xx_reset_system,
	.calibrate_decr		= generic_calibrate_decr,
};
