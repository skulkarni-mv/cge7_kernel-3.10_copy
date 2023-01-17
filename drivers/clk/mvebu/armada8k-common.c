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

static struct clk_onecell_data clk_data;

void __init armada8k_clk_setup(struct device_node *np,
				const struct a8k_clk_desc *desc, bool use_parent)
{
	void __iomem *base;
	unsigned long freq;
	struct clk *parent_clk = NULL;
	int reg_val, i;

	base = of_iomap(np, 0);
	if (WARN_ON(!base))
		return;

	reg_val = readl(base);

	/* SAR register isn't needed anymore */
	iounmap(base);

	if (use_parent) {
		/* get parent clock */
		parent_clk = of_clk_get(np, 0);
		if (WARN_ON(IS_ERR(parent_clk)))
			return;
	}

	/* Allocate struct for AP 806 clocks */
	clk_data.clk_num = desc->num_clks;
	clk_data.clks = kcalloc(clk_data.clk_num, sizeof(struct clk *),
				GFP_KERNEL);
	if (WARN_ON(!clk_data.clks))
		return;

	/* get clock frequency and register the clocks */
	for (i = 0; i < desc->num_clks; i++) {

		freq = desc->get_clk_freq(i, reg_val);

		if (use_parent) {
			/* add dividor of the parent clock */
			clk_data.clks[i] = clk_register_fixed_factor(NULL,
							desc->get_clk_name(i),
							__clk_get_name(parent_clk), 0, 1/* mult*/,
							freq/* div */);
		} else {
			/* add a new clock */
			clk_data.clks[i] = clk_register_fixed_rate(NULL,
								desc->get_clk_name(i), NULL,
								CLK_IS_ROOT, freq);
		}
	}

	of_clk_add_provider(np, of_clk_src_onecell_get, &clk_data);
}
