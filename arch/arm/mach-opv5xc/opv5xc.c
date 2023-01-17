/*
 * Author: Open Silicon, Inc.
 * Contact: platform@open-silicon.com
 * This file is part of the Voledia SDK
 *
 * Copyright (c) 2012 Open-Silicon Inc.
 *
 * This file is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License, Version 2, as published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but AS-IS and WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE, TITLE, or NONINFRINGEMENT. See the GNU
 * General Public License for more details.
 *
 * This file may also be available under a different license from Open-Silicon.
 * Contact Open-Silicon for more information
 */

#include <linux/init.h>
#include <linux/irqchip/arm-gic.h>
#include <linux/delay.h>

#include <asm/hardware/cache-l2x0.h>
#include <asm/smp_scu.h>
#include <asm/smp_twd.h>
#include <asm/mach/map.h>

#include <mach/opv5xc.h>
#include <mach/motherboard.h>


static struct map_desc ct_ca9x4_io_desc[] __initdata = {
	{
		.virtual	= (unsigned long)OPV5XC_V2T_PERIPH,
		.pfn		= __phys_to_pfn(OPV5XC_CA9MP_BASE),
		.length		= SZ_8K,
		.type		= MT_DEVICE,
	},
};

static void __init ct_ca9x4_map_io(void)
{
	iotable_init(ct_ca9x4_io_desc, ARRAY_SIZE(ct_ca9x4_io_desc));
}

#ifdef CONFIG_HAVE_ARM_TWD
static DEFINE_TWD_LOCAL_TIMER(twd_local_timer, OPV5XC_CA9MP_PTIMER_BASE, IRQ_LOCALTIMER);

static void __init ca9x4_twd_init(void)
{
	int err = twd_local_timer_register(&twd_local_timer);
	if (err)
		pr_err("twd_local_timer_register failed %d\n", err);
}
#else
#define ca9x4_twd_init()        do {} while (0)
#endif

static void __init ct_ca9x4_init_irq(void)
{
	gic_init(0, 29, ioremap(OPV5XC_CA9MP_GIC_DIST_BASE, SZ_4K),
		ioremap(OPV5XC_CA9MP_GIC_CPU_BASE, SZ_256));
	ca9x4_twd_init();
}

static void __init ct_ca9x4_init(void)
{
#ifdef CONFIG_CACHE_L2X0
	void __iomem *l2x0_base = ioremap(OPV5XC_L2CC_BASE, SZ_4K);

	/* set RAM latencies to 1 cycle for this core tile. */
	writel(0, l2x0_base + L2X0_TAG_LATENCY_CTRL);
	writel(0, l2x0_base + L2X0_DATA_LATENCY_CTRL);

#if defined(CONFIG_ARCH_OPV5XC_ES1) && defined(CONFIG_PCIE_OPV5XC_ACP)
	l2x0_init(l2x0_base, 0x00000000, 0xfe0fffff);
#else
	l2x0_init(l2x0_base, 0x00400000, 0xfe0fffff);
#endif
#endif
}

#ifdef CONFIG_SMP
static void *ct_ca9x4_scu_base __initdata;

static __init void ct_ca9x4_init_cpu_map(void)
{
	int i, ncores;
	ct_ca9x4_scu_base = ioremap(OPV5XC_CA9MP_SCU_BASE, SZ_128);
	if (WARN_ON(!ct_ca9x4_scu_base))
		return;

	ncores = scu_get_core_count(ct_ca9x4_scu_base);

	if (ncores > nr_cpu_ids) {
		pr_warn("SMP: %u cores greater than maximum (%u), clipping\n",
			ncores, nr_cpu_ids);
		ncores = nr_cpu_ids;
	}

	for (i = 0; i < ncores; ++i)
		set_cpu_possible(i, true);
}

static __init void ct_ca9x4_smp_enable(unsigned int max_cpus)
{
	scu_enable(ct_ca9x4_scu_base);
}
#endif

struct ct_desc ct_ca9x4_desc __initdata = {
	.id		= OPV5XC_CT_ID_CA9,
	.name		= "CA9x4",
	.map_io		= ct_ca9x4_map_io,
	.init_irq	= ct_ca9x4_init_irq,
	.init_tile	= ct_ca9x4_init,
#ifdef CONFIG_SMP
	.init_cpu_map	= ct_ca9x4_init_cpu_map,
	.smp_enable	= ct_ca9x4_smp_enable,
#endif
};

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)

#define PMU_SYS_CLK_EN		(OPV5XC_CR_PMU_BASE_VIRT + 0x00)
#define PMU_SOFT_RST		(OPV5XC_CR_PMU_BASE_VIRT + 0x04)
#define PMU_PWR_STA		(OPV5XC_CR_PMU_BASE_VIRT + 0x10)

u8 peri_used[32];		/* zero-initialized */

static DEFINE_MUTEX(peri_mutex);

int opv5xc_enable_peri(enum opv5xc_peri peri)
{
	u32 bit = (1 << peri);
	int counter;

	mutex_lock(&peri_mutex);

	if (peri_used[peri])
		goto ok;

	/* Disable clock */
	writel(readl(PMU_SYS_CLK_EN) & ~bit, PMU_SYS_CLK_EN);

	/* Assert reset */
	writel(readl(PMU_SOFT_RST) & ~bit, PMU_SOFT_RST);

	/* De-assert reset */
	writel(readl(PMU_SOFT_RST) | bit, PMU_SOFT_RST);

	/* Enable clock */
	writel(readl(PMU_SYS_CLK_EN) | bit, PMU_SYS_CLK_EN);

	/* Wait for ack for hw */
	for (counter = 100; counter > 0; counter--) {
		usleep_range(1000, 2000);
		if (readl(PMU_PWR_STA) & bit)
			break;
	}
	if (!counter) {
		mutex_unlock(&peri_mutex);
		pr_err("opv5xc: failed to enable peri (bit %d)\n", peri);
		return -EIO;
	}

ok:
	peri_used[peri]++;
	mutex_unlock(&peri_mutex);
	return 0;
}
EXPORT_SYMBOL(opv5xc_enable_peri);

void opv5xc_disable_peri(enum opv5xc_peri peri)
{
	u32 bit = (1 << peri);

	mutex_lock(&peri_mutex);

	if (WARN_ON(!peri_used[peri]))
		goto out;

	peri_used[peri]--;
	if (peri_used[peri])
		goto out;

	/* Disable clock */
	writel(readl(PMU_SYS_CLK_EN) & ~bit, PMU_SYS_CLK_EN);

	/* Assert reset */
	writel(readl(PMU_SOFT_RST) & ~bit, PMU_SOFT_RST);

out:
	mutex_unlock(&peri_mutex);
}
EXPORT_SYMBOL(opv5xc_disable_peri);
#endif
