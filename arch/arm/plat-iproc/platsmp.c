/*
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
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

#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/delay.h>

#include <mach/memory.h>
#include <mach/smp.h>

#include <asm/cacheflush.h>
#include <asm/smp_scu.h>
#include <asm/smp_plat.h>
#include <asm/io.h>
#include <plat/platsmp.h>

/* Lookup table phys addr and offset */
#define SOC_ROM_BASE_PA    0xFFFF0000
#if defined(CONFIG_MACH_HX4)
#define SOC_ROM_LUT_OFF    0x42c
#elif defined(CONFIG_MACH_HR2)
#define SOC_ROM_LUT_OFF    0x400
#elif defined(CONFIG_MACH_KT2)
#define SOC_ROM_LUT_OFF    0x42c
#elif defined(CONFIG_MACH_GH) || defined(CONFIG_MACH_SB2) || defined(CONFIG_MACH_HR3) \
	|| defined(CONFIG_MACH_GH2)
#define SOC_ROM_LUT_OFF    0xfc0
#else
#error "SOC_ROM_LUT_OFF is not defined"
#endif

static void __iomem *scu_base=NULL;


static inline unsigned int get_core_count(void)
{
	if (!scu_base)
	   scu_base = ioremap(scu_a9_get_base(), 0x4); 

	if (scu_base)
		return scu_get_core_count(scu_base);	
	
	return 1;
}

/*
 * Initialise the CPU possible map early - this describes the CPUs
 * which may be present or become present in the system.
 */
void __init iproc_smp_init_cpus(void)
{
	unsigned int i, ncores = get_core_count();

	printk(KERN_DEBUG "iproc_smp_init_cpus: Enter ncores %d\n", ncores);

	for (i = 0; i < ncores; i++)
		set_cpu_present(i, true);

	printk(KERN_DEBUG "iproc_smp_init_cpus: Leave ncores %d\n", ncores);
}

static DEFINE_SPINLOCK(boot_lock);

void __cpuinit iproc_secondary_init(unsigned int cpu)
{
	printk(KERN_DEBUG "platform_secondary_init: Enter cpu %d\n", cpu);
	
	/*
	 * let the primary processor know we're out of the
	 * pen, then head off into the C entry point
	 */
	pen_release = -1;
	smp_wmb();

	/*
	 * Synchronise with the boot thread.
	 */
	raw_spin_lock(&boot_lock);
	raw_spin_unlock(&boot_lock);

	printk(KERN_DEBUG "platform_secondary_init: Leave pen_release %d\n", pen_release);
}

int __cpuinit iproc_boot_secondary(unsigned int cpu, struct task_struct *idle)
{
	unsigned long timeout;

	printk(KERN_DEBUG "boot_secondary: Enter CPU%d\n", cpu);

	/*
	 * Set synchronisation state between this boot processor
	 * and the secondary one
	 */
	spin_lock(&boot_lock);

	/*
	 * The secondary processor is waiting to be released from
	 * the holding pen - release it, then wait for it to flag
	 * that it has been released by resetting pen_release.
	 *
	 * Note that "pen_release" is the hardware CPU ID, whereas
	 * "cpu" is Linux's internal ID.
	 */

	pen_release = cpu_logical_map(cpu);
	smp_wmb();
	sync_cache_w(&pen_release);	

	/*
	 * Now the secondary CPU must start marching on its own.
	 */
	arch_send_wakeup_ipi_mask(cpumask_of(cpu)); 
	
	/* wait at most 1 second for the secondary to wake up */

	timeout = jiffies + (1 * HZ);
	while (time_before(jiffies, timeout)) {
		smp_rmb();
		sync_cache_r(&pen_release);
		if (pen_release == -1)
			break;

        udelay(10);
	}
	/*
	 * Now the secondary core is starting up let it run its
	 * calibrations, then wait for it to finish
	 */
	spin_unlock(&boot_lock);

	printk(KERN_DEBUG "boot_secondary: Leave pen-release %d\n", pen_release);

	return pen_release != -1 ? -ENOSYS : 0;
}

static void __init wakeup_secondary(unsigned cpu, void (* _sec_entry_va)(void))
{
	void __iomem * rombase = NULL;
	phys_addr_t lut_pa;
	u32 offset;
	u32 mask;
	u32 val;

	printk(KERN_DEBUG "wakeup_secondary: Enter cpu %d\n", cpu);

	mask = (1UL << PAGE_SHIFT) -1;

	lut_pa = SOC_ROM_BASE_PA & ~mask;
	offset = SOC_ROM_BASE_PA &  mask;
	offset += SOC_ROM_LUT_OFF;

	rombase = ioremap(lut_pa, PAGE_SIZE);
	if(rombase == NULL)
		return;
	val = virt_to_phys(_sec_entry_va);	

	writel(val, rombase + offset);

        smp_wmb();      /* probably not needed - io regs are not cached */

#ifdef  CONFIG_SMP
        dsb_sev();      /* Exit WFI */
#endif
	mb();

	iounmap(rombase);

	printk(KERN_DEBUG "wakeup_secondary: Leave cpu %d\n", cpu);
}

void __init iproc_smp_prepare_cpus(unsigned int max_cpus)
{
	int i;

	/*
	 * Initialise the present map, which describes the set of CPUs
	 * actually populated at the present time.
	 */
	for (i = 0; i < max_cpus; i++) 
		set_cpu_present(i, true);

	/*
	 * Initialise the SCU and wake up the secondary core using
	 * wakeup_secondary().
	 */
	if (!scu_base)
	   scu_base = ioremap(scu_a9_get_base(), 0x4); 
	
	if (scu_base)
	    scu_enable(scu_base);  
	wakeup_secondary(max_cpus, iproc_secondary_startup);
}


struct smp_operations iproc_smp_ops __initdata = {
	.smp_init_cpus = iproc_smp_init_cpus,
	.smp_prepare_cpus = iproc_smp_prepare_cpus,
	.smp_secondary_init = iproc_secondary_init,
	.smp_boot_secondary = iproc_boot_secondary,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_die		= iproc_cpu_die,
#endif
};
