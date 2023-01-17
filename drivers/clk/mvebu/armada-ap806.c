/*
* ***************************************************************************
* Copyright (C) 2015 Marvell International Ltd.
* ***************************************************************************
* This program is free software: you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the Free
* Software Foundation, either version 2 of the License, or any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ***************************************************************************
*/

#include <linux/kernel.h>
#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>

#include "armada8k-common.h"

/* AP806 PLLs:
 *   0 - DDR
 *   1 - Ring
 *   2 - CPU
 *   3 - PIDI AP
 *   4 - PIDI CP
 */
#define AP806_PLL_NUM	5
#define AP806_PLL_FREQ  7

/* SAR parameters to get the PLL data */
struct apclk_sar {
	int mask;
	int offset;
	const char *name;
};

static const struct apclk_sar ap806_apclk_sar[AP806_PLL_NUM]  __initconst = {
	{ .mask = 0x7,	.offset = 21, .name = "ddr" },
	{ .mask = 0x7,	.offset = 18, .name = "ring" },
	{ .mask = 0x7,	.offset = 15, .name = "cpu" },
	{ .mask = 0x3,	.offset = 13, .name = "pidi ap" },
	{ .mask = 0x3,	.offset = 11, .name = "pidi cp" },
};

/* mapping between SAR value to MHz. Frequency */
static const u32 ap806_apclk_freq[AP806_PLL_NUM][AP806_PLL_FREQ] __initconst = {
	{ 2400000000, 2100000000, 1800000000,
		1600000000, 1300000000, 1300000000,
		1300000000 },
	{ 2000000000, 1800000000, 1600000000,
		1400000000, 1200000000, 1200000000,
		1200000000 },
	{ 2500000000, 2200000000, 2000000000,
		1700000000, 1600000000, 1200000000,
		1200000000 },
	{ 2000000000, 1000000000, 1000000000, 0, 0, 0, 0 },
	{ 2000000000, 1000000000, 1000000000, 0, 0, 0, 0 },
};

/* ring clock parameters */
#define AP806_RING_DIV_NUM	5
static const struct apclk_sar ap806_ringclk_sar[AP806_RING_DIV_NUM]  __initconst = {
	{ .mask = 0x3f,	.offset = 0, .name = "ring_0" },
	{ .mask = 0x3f,	.offset = 6, .name = "ring_2" },
	{ .mask = 0x3f,	.offset = 12,  .name = "ring_3" },
	{ .mask = 0x3f,	.offset = 18,  .name = "ring_4" },
	{ .mask = 0x3f,	.offset = 24,  .name = "ring_5" },
};


static u32 __init ap806_get_clk_freq(int clk_index, u32 reg_val)
{
	int freq_idx;

	freq_idx = ((reg_val >> ap806_apclk_sar[clk_index].offset) &
			ap806_apclk_sar[clk_index].mask);
	if (WARN_ON(freq_idx > AP806_PLL_FREQ))
		return 0;

	return ap806_apclk_freq[clk_index][freq_idx];

}

static const char *__init ap806_get_clk_name(int clk_index)
{
	return ap806_apclk_sar[clk_index].name;
}

static const struct a8k_clk_desc ap806_clk_desc = {
	.get_clk_freq = ap806_get_clk_freq,
	.get_clk_name = ap806_get_clk_name,
	.num_clks = AP806_PLL_NUM,
};

static void __init ap806_clk_init(struct device_node *np)
{
	armada8k_clk_setup(np, &ap806_clk_desc, false);
}

CLK_OF_DECLARE(ap806_clk, "marvell,armada-apn806-clock",
	       ap806_clk_init);

static u32 __init ap806_ring_get_clk_freq(int clk_index, u32 reg_val)
{
	/* get the ring clock divider */
	return ((reg_val >> ap806_ringclk_sar[clk_index].offset) &
				   ap806_ringclk_sar[clk_index].mask);
}

static const char *__init ap806_ring_get_clk_name(int clk_index)
{
	return ap806_ringclk_sar[clk_index].name;
}


static const struct a8k_clk_desc ap806_ring_clk_desc = {
	.get_clk_freq = ap806_ring_get_clk_freq,
	.get_clk_name = ap806_ring_get_clk_name,
	.num_clks = AP806_RING_DIV_NUM,
};

static void __init ap806_ring_clk_init(struct device_node *np)
{
	armada8k_clk_setup(np, &ap806_ring_clk_desc, true);
}

CLK_OF_DECLARE(ap806_ring_clk, "marvell,armada-apn806-ring-clock",
	       ap806_ring_clk_init);

