/* Copyright (C) 2014-2015 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This file contains the Northstar2 IOMUX driver that supports group based
 * PINMUX configuration. Although PINMUX configuration is mainly group
 * based, the Northstar2 IOMUX controller allows certain pins to be
 * individually muxed to GPIO function, and therefore be controlled by
 * the Northstar2 ASIU GPIO controller.
 */

#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/slab.h>

#include "../core.h"
#include "../pinctrl-utils.h"

#define NORTHSTAR2_NUM_IOMUX	15

/*
 * Northstar2 IOMUX register description
 *
 * @offset: register offset for mux configuration of a group
 * @shift: bit shift for mux configuration of a group
 * @alt: alternate function to set to
 */
struct northstar2_mux {
	unsigned int offset;
	unsigned int shift;
	unsigned int mask;
	unsigned int alt;
};

/*
 * Keep track of Northstar2 IOMUX configuration and prevent double configuration
 *
 * @northstar2_mux: Northstar2 IOMUX register description
 * @is_configured: flag to indicate whether a mux setting has already been
 * configured
 */
struct northstar2_mux_log {
	struct northstar2_mux mux;
	bool is_configured;
};

/*
 * Group based IOMUX configuration
 *
 * @name: name of the group
 * @pins: array of pins used by this group
 * @num_pins: total number of pins used by this group
 * @mux: Northstar2 group based IOMUX configuration
 */
struct northstar2_pin_group {
	const char *name;
	const unsigned *pins;
	const unsigned num_pins;
	const struct northstar2_mux mux;
};

/*
 * Northstar2 mux function and suppored pin groups
 *
 * @name: name of the function
 * @groups: array of groups that can be supported by this function
 * @num_groups: total number of groups that can be supported by this function
 */
struct northstar2_pin_function {
	const char *name;
	const char * const *groups;
	const unsigned num_groups;
};

/*
 * Northstar2 IOMUX pinctrl core
 *
 * @pctl: pointer to pinctrl_dev
 * @dev: pointer to device
 * @base0: first I/O register base of the Northstar2 IOMUX controller
 * @groups: pointer to array of groups
 * @num_groups: total number of groups
 * @functions: pointer to array of functions
 * @num_functions: total number of functions
 * @mux_log: pointer to the array of mux logs
 * @lock: lock to protect register access
 */
struct northstar2_pinctrl {
	struct pinctrl_dev *pctl;
	struct device *dev;
	void __iomem *base0;

	const struct northstar2_pin_group *groups;
	unsigned num_groups;

	const struct northstar2_pin_function *functions;
	unsigned num_functions;

	struct northstar2_mux_log *mux_log;

	spinlock_t lock;
};

/*
 * Description of a pin in Northstar2
 *
 * @pin: pin number
 * @name: pin name
 * @gpio_mux: GPIO override related information
 */
struct northstar2_pin {
	unsigned pin;
	char *name;
};

#define NORTHSTAR2_PIN_DESC(p, n)	\
{					\
	.pin = p,			\
	.name = n,			\
}

/*
 * List of pins in Northstar2
 */
static struct northstar2_pin northstar2_pins[] = {
	/* Group 0 */
	NORTHSTAR2_PIN_DESC(0,  "nand_we_n"),
	NORTHSTAR2_PIN_DESC(1,  "nand_ale"),
	NORTHSTAR2_PIN_DESC(2,  "nand_wp_n"),
	NORTHSTAR2_PIN_DESC(3,  "nand_cle"),
	NORTHSTAR2_PIN_DESC(4,  "nand_ce0_n"),
	NORTHSTAR2_PIN_DESC(5,  "nand_ce1_n"),
	NORTHSTAR2_PIN_DESC(6,  "nand_rb_n"),
	NORTHSTAR2_PIN_DESC(7,  "nand_re_n"),
	NORTHSTAR2_PIN_DESC(8,  "nand_dq00"),
	NORTHSTAR2_PIN_DESC(9,  "nand_dq01"),
	NORTHSTAR2_PIN_DESC(10, "nand_dq02"),
	NORTHSTAR2_PIN_DESC(11, "nand_dq03"),
	NORTHSTAR2_PIN_DESC(12, "nand_dq04"),
	NORTHSTAR2_PIN_DESC(13, "nand_dq05"),
	NORTHSTAR2_PIN_DESC(14, "nand_dq06"),
	NORTHSTAR2_PIN_DESC(15, "nand_dq07"),
	NORTHSTAR2_PIN_DESC(16, "nand_dq08"),
	NORTHSTAR2_PIN_DESC(17, "nand_dq09"),
	NORTHSTAR2_PIN_DESC(18, "nand_dq10"),
	NORTHSTAR2_PIN_DESC(19, "nand_dq11"),
	NORTHSTAR2_PIN_DESC(20, "nand_dq12"),
	NORTHSTAR2_PIN_DESC(21, "nand_dq13"),
	NORTHSTAR2_PIN_DESC(22, "nand_dq14"),
	NORTHSTAR2_PIN_DESC(23, "nand_dq15"),
	NORTHSTAR2_PIN_DESC(24, "gpio_0"),
	NORTHSTAR2_PIN_DESC(25, "gpio_1"),

	/* Group 1 */
	NORTHSTAR2_PIN_DESC(26, "uart1_ext_clk"),

	/* Group 2 */
	NORTHSTAR2_PIN_DESC(27, "gpio_2"),
	NORTHSTAR2_PIN_DESC(28, "gpio_3"),
	NORTHSTAR2_PIN_DESC(29, "gpio_4"),
	NORTHSTAR2_PIN_DESC(30, "gpio_5"),

	/* Group 3 */
	NORTHSTAR2_PIN_DESC(31, "gpio_6"),
	NORTHSTAR2_PIN_DESC(32, "gpio_7"),

	/* Group 4 */
	NORTHSTAR2_PIN_DESC(33, "gpio_8"),
	NORTHSTAR2_PIN_DESC(34, "gpio_9"),

	/* Group 5 */
	NORTHSTAR2_PIN_DESC(35, "gpio_10"),
	NORTHSTAR2_PIN_DESC(36, "gpio_11"),

	/* Group 6 */
	NORTHSTAR2_PIN_DESC(37, "gpio_12"),
	NORTHSTAR2_PIN_DESC(38, "gpio_13"),

	/* Group 7 */
	NORTHSTAR2_PIN_DESC(39, "gpio_14"),
	NORTHSTAR2_PIN_DESC(40, "gpio_15"),
	NORTHSTAR2_PIN_DESC(41, "gpio_16"),
	NORTHSTAR2_PIN_DESC(42, "gpio_17"),

	/* Group 8 */
	NORTHSTAR2_PIN_DESC(43, "gpio_18"),
	NORTHSTAR2_PIN_DESC(44, "gpio_19"),

	/* Group 9 */
	NORTHSTAR2_PIN_DESC(45, "gpio_20"),
	NORTHSTAR2_PIN_DESC(46, "gpio_21"),

	/* Group 10 */
	NORTHSTAR2_PIN_DESC(47, "gpio_22"),
	NORTHSTAR2_PIN_DESC(48, "gpio_23"),

	/* Group 11 */
	NORTHSTAR2_PIN_DESC(49, "gpio_24"),
	NORTHSTAR2_PIN_DESC(50, "gpio_25"),

	/* Group 12 */
	NORTHSTAR2_PIN_DESC(51, "gpio_26"),
	NORTHSTAR2_PIN_DESC(52, "gpio_27"),

	/* Group 13 */
	NORTHSTAR2_PIN_DESC(53, "gpio_28"),
	NORTHSTAR2_PIN_DESC(54, "gpio_29"),

	/* Group 14 */
	NORTHSTAR2_PIN_DESC(55, "gpio_30"),
	NORTHSTAR2_PIN_DESC(56, "gpio_31"),

	/* Group 15 */
	NORTHSTAR2_PIN_DESC(57, "uart2_sout"),
	NORTHSTAR2_PIN_DESC(58, "uart2_sin"),

	/* Group 16 */
	NORTHSTAR2_PIN_DESC(59, "pciea_0_clkreq"),
	NORTHSTAR2_PIN_DESC(60, "pciea_0_wake"),
	NORTHSTAR2_PIN_DESC(61, "pcieb_0_clkreq"),
	NORTHSTAR2_PIN_DESC(62, "pcieb_0_wake")
};

/*
 * List of groups of pins
 */

/* Group 0 */
static const unsigned nand_pins[] = { 0,  1,  2,  3,  4,  5,  6,  7,  8,
					9, 10, 11, 12, 13, 14, 15, 16,
					17, 18, 19, 20, 21, 22, 23, 24, 25};
static const unsigned nor_pins[] =  { 0,  1,  2,  3,  4,  5,  6,  7,  8,
					9, 10, 11, 12, 13, 14, 15, 16,
					17, 18, 19, 20, 21, 22, 23, 24, 25};

/* Group 1 */
static const unsigned uart1_ext_pins[] = {26};
static const unsigned nor_adv_pins[]   = {26};

/* Group 2 */
static const unsigned gpio_2_5_pins[] =     {27, 28, 29, 30};
static const unsigned pcie_1_pins[] =       {27, 28, 29, 30};
static const unsigned nor_addr_0_3_pins[] = {27, 28, 29, 30};

/* Group 3 */
static const unsigned gpio_6_7_pins[] =     {31, 32};
static const unsigned pcie_a3_pins[] =      {31, 32};
static const unsigned nor_addr_4_5_pins[] = {31, 32};

/* Group 4 */
static const unsigned gpio_8_9_pins[] =     {33, 34};
static const unsigned pcie_b3_pins[] =      {33, 34};
static const unsigned nor_addr_6_7_pins[] = {33, 34};

/* Group 5 */
static const unsigned gpio_10_11_pins[] =   {35, 36};
static const unsigned pcie_b2_pins[] =      {35, 36};
static const unsigned nor_addr_8_9_pins[] = {35, 36};

/* Group 6 */
static const unsigned gpio_12_13_pins[] =     {37, 38};
static const unsigned pcie_a2_pins[] =        {37, 38};
static const unsigned nor_addr_10_11_pins[] = {37, 38};

/* Group 7 */
static const unsigned gpio_14_17_pins[] =     {39, 40, 41, 42};
static const unsigned uart0_a_pins[] =        {39, 40, 41, 42};
static const unsigned nor_addr_12_15_pins[] = {39, 40, 41, 42};

/* Group 8 */
static const unsigned gpio_18_19_pins[] = {43, 44};
static const unsigned uart0_b_pins[]   =  {43, 44};

/* Group 9 */
static const unsigned gpio_20_21_pins[] = {45, 46};
static const unsigned uart0_c_pins[]   =  {45, 46};

/* Group 10 */
static const unsigned gpio_22_23_pins[] = {47, 48};
static const unsigned uart1_a_pins[]   =  {47, 48};

/* Group 11 */
static const unsigned gpio_24_25_pins[] = {49, 50};
static const unsigned uart1_b_pins[]   =  {49, 50};

/* Group 12 */
static const unsigned gpio_26_27_pins[] = {51, 52};
static const unsigned uart1_c_pins[]   =  {51, 52};

/* Group 13 */
static const unsigned gpio_28_29_pins[] = {53, 54};
static const unsigned uart1_d_pins[]   =  {53, 54};

/* Group 14 */
static const unsigned gpio_30_31_pins[] = {55, 56};
static const unsigned uart2_a_pins[]   =  {55, 56};

/* Group 15 */
static const unsigned uart2_b_pins[] =  {57, 58};

/* Group 16 */
static const unsigned pcie_ab0_pins[] =  {59, 60, 61, 62};


#define NORTHSTAR2_PIN_GROUP(group_name, off, sh, ma, al)	\
{							\
	.name = #group_name"""_grp",			\
	.pins = group_name ## _pins,			\
	.num_pins = ARRAY_SIZE(group_name ## _pins),	\
	.mux = {					\
		.offset = off,				\
		.shift = sh,				\
		.mask = ma,				\
		.alt = al,				\
	}						\
}

/*
 * List of Northstar2 pin groups
 */
static const struct northstar2_pin_group northstar2_pin_groups[] = {
	/* Group 0 */
	NORTHSTAR2_PIN_GROUP(nand,		0, 31, 1, 0),
	NORTHSTAR2_PIN_GROUP(nor,		0, 31, 1, 1),

	/* Group 1 */
	NORTHSTAR2_PIN_GROUP(uart1_ext,		4, 30, 3, 0),
	NORTHSTAR2_PIN_GROUP(nor_adv,		4, 30, 3, 2),

	/* Group 2 */
	NORTHSTAR2_PIN_GROUP(gpio_2_5,		4, 28, 3, 0),
	NORTHSTAR2_PIN_GROUP(pcie_1,		4, 28, 3, 1),
	NORTHSTAR2_PIN_GROUP(nor_addr_0_3,	4, 28, 3, 2),

	/* Group 3 */
	NORTHSTAR2_PIN_GROUP(gpio_6_7,		4, 26, 3, 0),
	NORTHSTAR2_PIN_GROUP(pcie_a3,		4, 26, 3, 1),
	NORTHSTAR2_PIN_GROUP(nor_addr_4_5,	4, 26, 3, 2),

	/* Group 4 */
	NORTHSTAR2_PIN_GROUP(gpio_8_9,		4, 24, 3, 0),
	NORTHSTAR2_PIN_GROUP(pcie_b3,		4, 24, 3, 1),
	NORTHSTAR2_PIN_GROUP(nor_addr_6_7,	4, 24, 3, 2),

	/* Group 5 */
	NORTHSTAR2_PIN_GROUP(gpio_10_11,	4, 22, 3, 0),
	NORTHSTAR2_PIN_GROUP(pcie_b2,		4, 22, 3, 1),
	NORTHSTAR2_PIN_GROUP(nor_addr_8_9,	4, 22, 3, 2),

	/* Group 6 */
	NORTHSTAR2_PIN_GROUP(gpio_12_13,	4, 20, 3, 0),
	NORTHSTAR2_PIN_GROUP(pcie_a2,		4, 20, 3, 1),
	NORTHSTAR2_PIN_GROUP(nor_addr_10_11,	4, 20, 3, 2),

	/* Group 7 */
	NORTHSTAR2_PIN_GROUP(gpio_14_17,	4, 18, 3, 0),
	NORTHSTAR2_PIN_GROUP(uart0_a,		4, 18, 3, 1),
	NORTHSTAR2_PIN_GROUP(nor_addr_12_15,	4, 18, 3, 2),

	/* Group 8 */
	NORTHSTAR2_PIN_GROUP(gpio_18_19,	4, 16, 3, 0),
	NORTHSTAR2_PIN_GROUP(uart0_b,		4, 16, 3, 1),

	/* Group 9 */
	NORTHSTAR2_PIN_GROUP(gpio_20_21,	4, 14, 3, 0),
	NORTHSTAR2_PIN_GROUP(uart0_c,		4, 14, 3, 1),

	/* Group 10 */
	NORTHSTAR2_PIN_GROUP(gpio_22_23,	4, 12, 3, 0),
	NORTHSTAR2_PIN_GROUP(uart1_a,		4, 12, 3, 1),

	/* Group 11 */
	NORTHSTAR2_PIN_GROUP(gpio_24_25,	4, 10, 3, 0),
	NORTHSTAR2_PIN_GROUP(uart1_b,		4, 10, 3, 1),

	/* Group 12 */
	NORTHSTAR2_PIN_GROUP(gpio_26_27,	4, 8, 3, 0),
	NORTHSTAR2_PIN_GROUP(uart1_c,		4, 8, 3, 1),

	/* Group 13 */
	NORTHSTAR2_PIN_GROUP(gpio_28_29,	4, 6, 3, 0),
	NORTHSTAR2_PIN_GROUP(uart1_d,		4, 6, 3, 1),

	/* Group 14 */
	NORTHSTAR2_PIN_GROUP(gpio_30_31,	4, 4, 3, 0),
	NORTHSTAR2_PIN_GROUP(uart2_a,		4, 4, 3, 1),

	/* Groups 15 and 16 are not controllabe so
	 * are not entered into this table.
	 */
};

/*
 * List of groups supported by functions
 */

static const char * const nand_grps[] = { "nand_grp"};
static const char * const nor_grps[] = { "nor_grp", "nor_adv_grp",
		"nor_addr_0_3_grp", "nor_addr_4_5_grp", "nor_addr_6_7_grp",
		"nor_addr_8_9_grp", "nor_addr_10_11_grp",
		"nor_addr_12_15_grp"};
static const char * const gpio_grps[] = { "gpio_2_5_grp", "gpio_6_7_grp",
		"gpio_8_9_grp", "gpio_10_11_grp", "gpio_12_13_grp",
		"gpio_14_17_grp", "gpio_18_19_grp", "gpio20_21_grp",
		"gpio_22_23_grp", "gpio_24_25_grp", "gpio_26_27_grp",
		"gpio_28_29_grp", "gpio_30_31_grp"};
static const char * const pcie_grps[] = { "pcie_1_grp", "pcie_a3_grp",
		"pcie_b3_grp", "pcie_b2_grp", "pcie_a2_grp"};
static const char * const uart0_grps[] = { "uart0_a_grp", "uart0_b_grp",
		"uart0_c_grp"};
static const char * const uart1_grps[] = { "uart1_ext_grp", "uart1_a_grp",
		"uart1_b_grp", "uart1_c_grp", "uart1_d_grp"};
static const char * const uart2_grps[] = { "uart2_a_grp"};

#define NORTHSTAR2_PIN_FUNCTION(func)				\
{								\
	.name = #func,						\
	.groups = func ## _grps,				\
	.num_groups = ARRAY_SIZE(func ## _grps),		\
}

/*
 * List of supported functions in Northstar2
 */
static const struct northstar2_pin_function northstar2_pin_functions[] = {
	NORTHSTAR2_PIN_FUNCTION(nand),
	NORTHSTAR2_PIN_FUNCTION(nor),
	NORTHSTAR2_PIN_FUNCTION(gpio),
	NORTHSTAR2_PIN_FUNCTION(pcie),
	NORTHSTAR2_PIN_FUNCTION(uart0),
	NORTHSTAR2_PIN_FUNCTION(uart1),
	NORTHSTAR2_PIN_FUNCTION(uart2),
};

static int northstar2_get_groups_count(struct pinctrl_dev *pctrl_dev)
{
	struct northstar2_pinctrl *pinctrl = pinctrl_dev_get_drvdata(pctrl_dev);

	return pinctrl->num_groups;
}

static const char *northstar2_get_group_name(struct pinctrl_dev *pctrl_dev,
					 unsigned selector)
{
	struct northstar2_pinctrl *pinctrl = pinctrl_dev_get_drvdata(pctrl_dev);

	return pinctrl->groups[selector].name;
}

static int northstar2_get_group_pins(struct pinctrl_dev *pctrl_dev,
				 unsigned selector, const unsigned **pins,
				 unsigned *num_pins)
{
	struct northstar2_pinctrl *pinctrl = pinctrl_dev_get_drvdata(pctrl_dev);

	*pins = pinctrl->groups[selector].pins;
	*num_pins = pinctrl->groups[selector].num_pins;

	return 0;
}

static void northstar2_pin_dbg_show(struct pinctrl_dev *pctrl_dev,
				struct seq_file *s, unsigned offset)
{
	seq_printf(s, " %s", dev_name(pctrl_dev->dev));
}

static bool northstar2_function_is_valid(const char *function_name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(northstar2_pin_functions); i++) {
		if (!strcmp(northstar2_pin_functions[i].name, function_name))
			return true;
	}

	return false;
}

static int northstar2_dt_node_to_map(struct pinctrl_dev *pctrl_dev,
				 struct device_node *np,
				 struct pinctrl_map **map,
				 unsigned *num_maps)
{
	int ret, num_groups;
	unsigned reserved_maps = 0;
	struct property *prop;
	const char *group_name, *function_name;

	*map = NULL;
	*num_maps = 0;

	num_groups = of_property_count_strings(np, "groups");
	if (num_groups < 0) {
		dev_err(pctrl_dev->dev, "could not parse property groups\n");
		return -EINVAL;
	}

	ret = of_property_read_string(np, "function", &function_name);
	if (ret < 0) {
		dev_err(pctrl_dev->dev,	"could not parse property function\n");
		return -EINVAL;
	}

	/* check if it's a valid function */
	if (!northstar2_function_is_valid(function_name)) {
		dev_warn(pctrl_dev->dev, "invalid function name: %s\n",
				function_name);
	}

	ret = pinctrl_utils_reserve_map(pctrl_dev, map, &reserved_maps,
			num_maps, num_groups);
	if (ret) {
		dev_err(pctrl_dev->dev, "unable to reserve map\n");
		return ret;
	}

	of_property_for_each_string(np, "groups", prop, group_name) {
		ret = pinctrl_utils_add_map_mux(pctrl_dev, map,
				&reserved_maps, num_maps, group_name,
				function_name);
		if (ret) {
			dev_err(pctrl_dev->dev, "can't add map: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static struct pinctrl_ops northstar2_pinctrl_ops = {
	.get_groups_count = northstar2_get_groups_count,
	.get_group_name = northstar2_get_group_name,
	.get_group_pins = northstar2_get_group_pins,
	.pin_dbg_show = northstar2_pin_dbg_show,
	.dt_node_to_map = northstar2_dt_node_to_map,
	.dt_free_map = pinctrl_utils_dt_free_map,
};

static int northstar2_get_functions_count(struct pinctrl_dev *pctrl_dev)
{
	struct northstar2_pinctrl *pinctrl = pinctrl_dev_get_drvdata(pctrl_dev);

	return pinctrl->num_functions;
}

static const char *northstar2_get_function_name(struct pinctrl_dev *pctrl_dev,
					    unsigned selector)
{
	struct northstar2_pinctrl *pinctrl = pinctrl_dev_get_drvdata(pctrl_dev);

	return pinctrl->functions[selector].name;
}

static int northstar2_get_function_groups(struct pinctrl_dev *pctrl_dev,
				      unsigned selector,
				      const char * const **groups,
				      unsigned * const num_groups)
{
	struct northstar2_pinctrl *pinctrl = pinctrl_dev_get_drvdata(pctrl_dev);

	*groups = pinctrl->functions[selector].groups;
	*num_groups = pinctrl->functions[selector].num_groups;

	return 0;
}

static int northstar2_pinmux_set(struct northstar2_pinctrl *pinctrl,
			     const struct northstar2_pin_function *func,
			     const struct northstar2_pin_group *grp,
			     struct northstar2_mux_log *mux_log)
{
	const struct northstar2_mux *mux = &grp->mux;
	int i;
	u32 val, mask;
	unsigned long flags;

	for (i = 0; i < NORTHSTAR2_NUM_IOMUX; i++) {
		if (mux->offset != mux_log[i].mux.offset ||
		    mux->shift != mux_log[i].mux.shift)
			continue;

		/* match found if we reach here */

		/* if this is a new configuration, just do it! */
		if (!mux_log[i].is_configured)
			break;

		/*
		 * IOMUX has been configured previously and one is trying to
		 * configure it to a different function
		 */
		if (mux_log[i].mux.alt != mux->alt) {
			dev_err(pinctrl->dev,
				"double configuration error detected!\n");
			dev_err(pinctrl->dev, "func:%s grp:%s\n",
				func->name, grp->name);
			return -EINVAL;
		} else {
			/*
			 * One tries to configure it to the same function.
			 * Just quit and don't bother
			 */
			return 0;
		}
	}

	mask = mux->mask;
	mux_log[i].mux.alt = mux->alt;
	mux_log[i].is_configured = true;

	spin_lock_irqsave(&pinctrl->lock, flags);

	val = readl(pinctrl->base0 + grp->mux.offset);
	val &= ~(mask << grp->mux.shift);
	val |= grp->mux.alt << grp->mux.shift;
	writel(val, pinctrl->base0 + grp->mux.offset);

	spin_unlock_irqrestore(&pinctrl->lock, flags);

	return 0;
}

static int northstar2_pinmux_enable(struct pinctrl_dev *pctrl_dev,
		unsigned func_select, unsigned grp_select)
{
	struct northstar2_pinctrl *pinctrl = pinctrl_dev_get_drvdata(pctrl_dev);
	const struct northstar2_pin_function *func;
	const struct northstar2_pin_group *grp;

	if (grp_select > pinctrl->num_groups ||
		func_select > pinctrl->num_functions)
		return -EINVAL;

	func = &pinctrl->functions[func_select];
	grp = &pinctrl->groups[grp_select];

	dev_dbg(pctrl_dev->dev, "func:%u name:%s grp:%u name:%s\n",
		func_select, func->name, grp_select, grp->name);

	dev_dbg(pctrl_dev->dev, "offset:0x%08x shift:%u alt:%u\n",
		grp->mux.offset, grp->mux.shift, grp->mux.alt);

	return northstar2_pinmux_set(pinctrl, func, grp, pinctrl->mux_log);
}

static struct pinmux_ops northstar2_pinmux_ops = {
	.get_functions_count = northstar2_get_functions_count,
	.get_function_name = northstar2_get_function_name,
	.get_function_groups = northstar2_get_function_groups,
	.enable = northstar2_pinmux_enable,
};

static struct pinctrl_desc northstar2_pinctrl_desc = {
	.name = "northstar2-pinmux",
	.pctlops = &northstar2_pinctrl_ops,
	.pmxops = &northstar2_pinmux_ops,
};

static int northstar2_mux_log_init(struct northstar2_pinctrl *pinctrl)
{
	struct northstar2_mux_log *log;
	unsigned int i;

	pinctrl->mux_log = devm_kcalloc(pinctrl->dev, NORTHSTAR2_NUM_IOMUX,
					sizeof(struct northstar2_mux_log),
					GFP_KERNEL);
	if (!pinctrl->mux_log)
		return -ENOMEM;

	/* Group 0 uses bit 31 in the IOMUX_PAD_FUNCTION_1 register */
	log = &pinctrl->mux_log[0];
	log->mux.offset = 0;
	log->mux.shift = 31;
	log->mux.alt = 0;
	log->is_configured = false;

	/* Groups 1 through 14 use two bits each in the
	 * IOMUX_PAD_FUNCTION_1 register starting with
	 * bit position 30.
	 */
	for (i = 1; i < NORTHSTAR2_NUM_IOMUX; i++) {
		log = &pinctrl->mux_log[i];
		log->mux.offset = 1;
		log->mux.shift = 32 - (i * 2);
		log->mux.alt = 0;
		log->is_configured = false;
	}

	return 0;
}

/* Find all the groups that are part of a named function and
 * set the groups in the PINCTRL hardware.
 */
static int northstar2_set_function(struct northstar2_pinctrl *pinctrl,
				    const char *function_name)
{
	int i, j;
	int function_number = -1;
	const char * const *groups;
	unsigned num_groups;
	int ret;
	int group_number;

	dev_dbg(pinctrl->dev, "Setting function %s\n", function_name);

	if (!northstar2_function_is_valid(function_name)) {
		dev_err(pinctrl->dev, "invalid function name: %s\n",
				function_name);
		return -EINVAL;
	}

	/* Get the function number */
	for (i = 0; i < ARRAY_SIZE(northstar2_pin_functions); i++) {
		if (!strcmp(northstar2_pin_functions[i].name, function_name)) {
			function_number = i;
			break;
		}
	}
	dev_dbg(pinctrl->dev, "function number %d\n", function_number);

	/* Get the number of groups in the function
	 * and a list of the group names
	 */
	ret = northstar2_get_function_groups(pinctrl->pctl, i,
					     &groups, &num_groups);

	/* Process each group of the function */
	for (i = 0; i < num_groups; i++) {

		/* Get the group number */
		group_number = -1;
		for (j = 0; j < ARRAY_SIZE(northstar2_pin_groups); j++) {
			if (!strcmp(northstar2_pin_groups[j].name, groups[i])) {
				group_number = j;
				break;
			}
		}
		if (group_number == -1) {
			dev_err(pinctrl->dev, "invalid group name: %s\n",
				groups[i]);
			return -EINVAL;
		}
		dev_dbg(pinctrl->dev, "group %s, number %d\n",
			groups[i], group_number);

		/* Set the function and group */
		ret = northstar2_pinmux_enable(pinctrl->pctl,
					       function_number, group_number);
		if (ret < 0) {
			dev_err(pinctrl->dev,
				"Failed to set group %s in function %s: %d\n",
				groups[i], function_name, ret);
		}
	}

	return 0;

}

static int northstar2_pinmux_probe(struct platform_device *pdev)
{
	struct northstar2_pinctrl *pinctrl;
	struct resource *res;
	int i, ret;
	struct pinctrl_pin_desc *pins;
	unsigned num_pins = ARRAY_SIZE(northstar2_pins);
	const char *function;

	pinctrl = devm_kzalloc(&pdev->dev, sizeof(*pinctrl), GFP_KERNEL);
	if (!pinctrl)
		return -ENOMEM;

	pinctrl->dev = &pdev->dev;
	platform_set_drvdata(pdev, pinctrl);
	spin_lock_init(&pinctrl->lock);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	pinctrl->base0 = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(pinctrl->base0)) {
		dev_err(&pdev->dev, "unable to map I/O space\n");
		return PTR_ERR(pinctrl->base0);
	}

	ret = northstar2_mux_log_init(pinctrl);
	if (ret) {
		dev_err(&pdev->dev, "unable to initialize IOMUX log\n");
		return ret;
	}

	pins = devm_kcalloc(&pdev->dev, num_pins, sizeof(*pins), GFP_KERNEL);
	if (!pins)
		return -ENOMEM;

	for (i = 0; i < num_pins; i++) {
		pins[i].number = northstar2_pins[i].pin;
		pins[i].name = northstar2_pins[i].name;
	}

	pinctrl->groups = northstar2_pin_groups;
	pinctrl->num_groups = ARRAY_SIZE(northstar2_pin_groups);
	pinctrl->functions = northstar2_pin_functions;
	pinctrl->num_functions = ARRAY_SIZE(northstar2_pin_functions);
	northstar2_pinctrl_desc.pins = pins;
	northstar2_pinctrl_desc.npins = num_pins;

	pinctrl->pctl = pinctrl_register(&northstar2_pinctrl_desc, &pdev->dev,
			pinctrl);
	if (!pinctrl->pctl) {
		dev_err(&pdev->dev, "unable to register Northstar2 IOMUX pinctrl\n");
		return -EINVAL;
	}

	/* Set any functions that are selected */
	for (i = 0; ret == 0; i++) {
		ret = of_property_read_string_index(pdev->dev.of_node,
			"function-select", i, &function);
		if (ret == 0)
			northstar2_set_function(pinctrl, function);
	}

	return 0;
}

static struct of_device_id northstar2_pinmux_of_match[] = {
	{ .compatible = "brcm,northstar2-pinmux" },
	{ }
};

static struct platform_driver northstar2_pinmux_driver = {
	.driver = {
		.name = "northstar2-pinmux",
		.of_match_table = northstar2_pinmux_of_match,
	},
	.probe = northstar2_pinmux_probe,
};

static int __init northstar2_pinmux_init(void)
{
	return platform_driver_register(&northstar2_pinmux_driver);
}
arch_initcall(northstar2_pinmux_init);

MODULE_DESCRIPTION("Broadcom Northstar2 IOMUX driver");
MODULE_LICENSE("GPL v2");
