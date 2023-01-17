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

#ifndef __CLK_MVEBU_A8K_COMMON_H_
#define __CLK_MVEBU_A8K_COMMON_H_


struct a8k_clk_desc {
	u32 (*get_clk_freq)(int clk_index, u32 reg_val);
	const char* (*get_clk_name)(int clk_index);
	int num_clks;
};

void __init armada8k_clk_setup(struct device_node *np,
				const struct a8k_clk_desc *desc, bool use_parent);

#endif
