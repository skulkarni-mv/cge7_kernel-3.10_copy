/*
 * Marvell Armada AP806 System Controller
 *
 * Copyright (C) 2016 Marvell
 *
 * Thomas Petazzoni <thomas.petazzoni@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#define pr_fmt(fmt) "ap806-system-controller: " fmt

#include <linux/kernel.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/mfd/syscon.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/regmap.h>

#define AP806_SAR_REG			0x400
#define AP806_SAR_CLKFREQ_MODE_MASK	0x1f

#define AP806_CLK_NUM			6

static struct clk *ap806_clks[AP806_CLK_NUM];

static struct clk_onecell_data ap806_clk_data = {
	.clks = ap806_clks,
	.clk_num = AP806_CLK_NUM,
};

static void __init ap806_syscon_clk_init(struct device_node *np)
{
	unsigned int freq_mode, cpuclk_freq, dclk_freq;
	const char *name, *fixedclk_name;
	void __iomem *base;
	u32 reg;

	base = of_iomap(np, 0);
	if (WARN_ON(!base))
	    return;

	reg = readl(base);

	iounmap(base);

	freq_mode = reg & AP806_SAR_CLKFREQ_MODE_MASK;
	switch (freq_mode) {
	case 0x4:
	case 0xB ... 0x12:
		cpuclk_freq = 1600;
		break;
	case 0x1A:
		cpuclk_freq = 1400;
		break;
	case 0x14 ... 0x18:
		cpuclk_freq = 1300;
		break;
	case 0x19:
		cpuclk_freq = 1200;
		break;
	case 0x13:
	case 0x1D:
		cpuclk_freq = 1000;
		break;
	case 0x1C:
		cpuclk_freq = 800;
		break;
	case 0x1B:
		cpuclk_freq = 600;
		break;
	default:
		/* set cpuclk_freq as invalid value to continue and
		** configure the MSS clock (used to calculate the
		** baudrate of the UART
		*/
		cpuclk_freq = 0;
		pr_err("invalid SAR value\n");
	}

	/* Get DCLK frequency */
	switch (freq_mode) {
	case 0x4:
	case 0x10:
	case 0x14:
	case 0x19 ... 0x1D:
		dclk_freq = 400;
		break;
	case 0xC:
		dclk_freq = 600;
		break;
	case 0xD:
	case 0x16:
		dclk_freq = 525;
		break;
	case 0xB:
	case 0xE:
	case 0xF:
		dclk_freq = 450;
		break;
	case 0x12:
	case 0x13:
	case 0x17:
		dclk_freq = 325;
		break;
	case 0x11:
	case 0x15:
		dclk_freq = 800;
		break;
	case 0x18:
		dclk_freq = 650;
		break;
	default:
		dclk_freq = 0;
		pr_err("invalid SAR value\n");
	}

	/* Convert to hertz */
	cpuclk_freq *= 1000 * 1000;
	dclk_freq *= 1000 * 1000;

	/* CPU clocks depend on the Sample At Reset configuration */
	of_property_read_string_index(np, "clock-output-names",
				      0, &name);
	ap806_clks[0] = clk_register_fixed_rate(NULL, name, NULL,
						CLK_IS_ROOT, cpuclk_freq);

	of_property_read_string_index(np, "clock-output-names",
				      1, &name);
	ap806_clks[1] = clk_register_fixed_rate(NULL, name, NULL, CLK_IS_ROOT,
						cpuclk_freq);

	/* Fixed clock is always 1200 Mhz */
	of_property_read_string_index(np, "clock-output-names",
				      2, &fixedclk_name);
	ap806_clks[2] = clk_register_fixed_rate(NULL, fixedclk_name, NULL, CLK_IS_ROOT,
						1200 * 1000 * 1000);

	/* MSS Clock is fixed clock divided by 6 */
	of_property_read_string_index(np, "clock-output-names",
				      3, &name);
	ap806_clks[3] = clk_register_fixed_factor(NULL, name, fixedclk_name,
						  0, 1, 6);

	/* eMMC Clock is fixed clock divided by 3 */
	of_property_read_string_index(np, "clock-output-names",
				      4, &name);
	ap806_clks[4] = clk_register_fixed_factor(NULL, name, fixedclk_name,
						  0, 1, 3);

	of_property_read_string_index(np, "clock-output-names",
				      5, &name);
	ap806_clks[5] = clk_register_fixed_rate(NULL, name, NULL, CLK_IS_ROOT,
						dclk_freq);

	of_clk_add_provider(np, of_clk_src_onecell_get, &ap806_clk_data);
}

CLK_OF_DECLARE(ap806_syscon_clk, "marvell,ap806-system-controller",
	       ap806_syscon_clk_init);
