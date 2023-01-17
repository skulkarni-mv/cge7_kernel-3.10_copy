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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/clk.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/clkdev.h>

#include <mach/opv5xc.h>
#include <mach/clkdev.h>

static DEFINE_SPINLOCK(opv5xc_clkreg_lock);

#define CLK_LOOKUP(devid, clkref)		\
	{					\
		.dev_id = devid,		\
		.clk = clkref,			\
	}

#define CLK_LOOKUP_CON(devid, conid, clkref)	\
	{					\
		.dev_id = devid,		\
		.con_id = conid,		\
		.clk = clkref,			\
	}

void opv5xc_clk_set_rate_cpuclk(unsigned long rate)
{
	unsigned long flags;

	spin_lock_irqsave(&opv5xc_clkreg_lock, flags);

	spin_unlock_irqrestore(&opv5xc_clkreg_lock, flags);
}
EXPORT_SYMBOL(opv5xc_clk_set_rate_cpuclk);

int opv5xc_clk_get_rate_cpuclk(void)
{
	unsigned int val = 0;
	unsigned long flags;

	spin_lock_irqsave(&opv5xc_clkreg_lock, flags);
	val = ((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x20) & 0x0f) + 1) * 100 * 1000 * 1000;
	spin_unlock_irqrestore(&opv5xc_clkreg_lock, flags);

	return val;
}
EXPORT_SYMBOL(opv5xc_clk_get_rate_cpuclk);

static int clk_set_rate_cpuclk(struct clk *clk, unsigned long rate)
{
	opv5xc_clk_set_rate_cpuclk(clk_round_rate(clk, rate));
	return 0;
}

static unsigned long clk_get_rate_cpuclk(struct clk *clk)
{
	return opv5xc_clk_get_rate_cpuclk();
}

static unsigned long clk_round_rate_cpuclk(struct clk *clk, unsigned long rate)
{
	if (rate <= 800000000)
		return 800000000;
	return -EINVAL;
}

int clk_enable(struct clk *clk)
{
	int ret = 0;

	return ret;
}
EXPORT_SYMBOL(clk_enable);

void clk_disable(struct clk *clk)
{

}
EXPORT_SYMBOL(clk_disable);

long clk_round_rate(struct clk *clk, unsigned long rate)
{
	if (clk->round_rate)
		return (long) clk->round_rate(clk, rate);

	pr_err("clock: Failed to round rate of %s\n", clk->name);
	return (long) clk->rate;
}
EXPORT_SYMBOL(clk_round_rate);

int clk_set_rate(struct clk *clk, unsigned long rate)
{
	if (clk->set_rate) {
		return clk->set_rate(clk, rate);
	} else {
		pr_err("clock: Failed to set %s to %ld hz\n", clk->name, rate);
		return -EINVAL;
	}
}
EXPORT_SYMBOL(clk_set_rate);

unsigned long clk_get_rate(struct clk *clk)
{
	if (clk->get_rate)
		return clk->get_rate(clk);
	else
		return clk->rate;
}
EXPORT_SYMBOL(clk_get_rate);

static struct clk cpu_clk = {
	.name		= "CPU",
	.rate		= 800000000,
	.set_rate	= clk_set_rate_cpuclk,
	.get_rate	= clk_get_rate_cpuclk,
	.round_rate	= clk_round_rate_cpuclk,
};

static struct clk amba_clk = {
	.name		= "AMBA",
	.rate		= 250000000,
};

static struct clk dma_clk = {
	.name		= "DMA",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk sd_clk = {
	.name		= "MMCSD",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk i2s0_clk = {
	.name		= "I2S0",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk i2s1_clk = {
	.name		= "I2S1",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk i2c0_clk = {
	.name		= "I2C0",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk i2c1_clk = {
	.name		= "I2C1",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk spi_clk = {
	.name		= "SPI",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk uart0_clk = {
	.name		= "UART0",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk gpio_clk = {
	.name		= "GPIO",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk rtc_clk = {
	.name		= "RTC",
	.parent		= &amba_clk,
	.rate		= 250000000,
};

static struct clk_lookup lookups[] = {
	CLK_LOOKUP("cpu",	&cpu_clk),
	CLK_LOOKUP("amba",	&amba_clk),
	CLK_LOOKUP("dma",	&dma_clk),
	CLK_LOOKUP("sd",	&sd_clk),
	CLK_LOOKUP("i2s0",	&i2s0_clk),
	CLK_LOOKUP("i2s1",	&i2s1_clk),
	CLK_LOOKUP("i2c0",	&i2c0_clk),
	CLK_LOOKUP("i2c0",	&i2c1_clk),
	CLK_LOOKUP("spi",	&spi_clk),
	CLK_LOOKUP("uart0",	&uart0_clk),
	CLK_LOOKUP("gpio",	&gpio_clk),
	CLK_LOOKUP("rtc",	&rtc_clk),
};

#if defined(CONFIG_DEBUG_FS)
static struct clk *clks[] = {
	&cpu_clk,
	&amba_clk,
	&dma_clk,
	&sd_clk,
	&i2s0_clk,
	&i2s1_clk,
	&i2c0_clk,
	&i2c1_clk,
	&spi_clk,
	&uart0_clk,
	&gpio_clk,
	&rtc_clk,
};

static int opv5xc_clocks_show(struct seq_file *s, void *data)
{
	struct clk *clk;
	int i;

	seq_puts(s, "CLOCK           DEVICE                  FREQ\n");
	seq_puts(s, "-----------------------------------------------------\n");
	for (i = 0; i < ARRAY_SIZE(clks); i++) {
		clk = clks[i];
		if (clk != ERR_PTR(-ENOENT)) {
			char cdf[33];
			int chars = snprintf(&cdf[0], 17, "%s", clk->name);

			while (chars < 16) {
				cdf[chars] = ' ';
				chars++;
			}

			chars = snprintf(&cdf[16], 17, "%s", clk->dev ?
					 dev_name(clk->dev) : "N/A");
			while (chars < 16) {
				cdf[chars+16] = ' ';
				chars++;
			}
			cdf[32] = '\0';

			seq_printf(s, "%s\t%lu Hz\n",
					&cdf[0], clk_get_rate(clk));
		}
	}
	return 0;
}

static int opv5xc_clocks_open(struct inode *inode, struct file *file)
{
	return single_open(file, opv5xc_clocks_show, NULL);
}

static const struct file_operations opv5xc_clocks_ops = {
	.open		= opv5xc_clocks_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

int __init opv5xc_clock_init(void)
{
	clkdev_add_table(lookups, ARRAY_SIZE(lookups));

#if defined(CONFIG_DEBUG_FS)
	(void) debugfs_create_file("opv5xc_clocks", S_IFREG | S_IRUGO,
				   NULL, NULL, &opv5xc_clocks_ops);
#endif

	return 0;
}
