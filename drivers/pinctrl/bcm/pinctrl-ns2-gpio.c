/*
 * Copyright (C) 2014-2015 Broadcom Corporation
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
 * This file contains the Broadcom Northstar2 GPIO driver that supports 3
 * GPIO controllers on Northstar2 including the ASIU GPIO controller, the
 * chipCommonG GPIO controller, and the always-on GPIO controller. Basic
 * PINCONF such as bias pull up/down, and drive strength are also supported
 * in this driver.
 *
 * Pins from the ASIU GPIO can be individually muxed to GPIO function,
 * through the interaction with the Northstar2 IOMUX controller
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/gpio.h>
#include <linux/ioport.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinconf-generic.h>

#include "../pinctrl-utils.h"

#define NORTHSTAR2_GPIO_DATA_IN_OFFSET   0x00
#define NORTHSTAR2_GPIO_DATA_OUT_OFFSET  0x04
#define NORTHSTAR2_GPIO_OUT_EN_OFFSET    0x08
#define NORTHSTAR2_GPIO_IN_TYPE_OFFSET   0x0c
#define NORTHSTAR2_GPIO_INT_DE_OFFSET    0x10
#define NORTHSTAR2_GPIO_INT_EDGE_OFFSET  0x14
#define NORTHSTAR2_GPIO_INT_MSK_OFFSET   0x18
#define NORTHSTAR2_GPIO_INT_STAT_OFFSET  0x1c
#define NORTHSTAR2_GPIO_INT_MSTAT_OFFSET 0x20
#define NORTHSTAR2_GPIO_AUX_SEL		 0x28
#define NORTHSTAR2_GPIO_INT_CLR_OFFSET   0x24
#define NORTHSTAR2_GPIO_PAD_RES_OFFSET   0x34
#define NORTHSTAR2_GPIO_RES_EN_OFFSET    0x38

/* drive strength control for ASIU GPIO */
#define NORTHSTAR2_GPIO_ASIU_DRV0_CTRL_OFFSET 0x58

/* drive strength control for CCM/CRMU (AON) GPIO */
#define NORTHSTAR2_GPIO_DRV0_CTRL_OFFSET  0x00

#define GPIO_BANK_SIZE 0x200
#define NGPIOS_PER_BANK 32
#define GPIO_BANK(pin) ((pin) / NGPIOS_PER_BANK)

#define NORTHSTAR2_GPIO_REG(pin, reg) (GPIO_BANK(pin) * GPIO_BANK_SIZE + (reg))
#define NORTHSTAR2_GPIO_SHIFT(pin) ((pin) % NGPIOS_PER_BANK)

#define GPIO_DRV_STRENGTH_BIT_SHIFT  20
#define GPIO_DRV_STRENGTH_BITS       3
#define GPIO_DRV_STRENGTH_BIT_MASK   ((1 << GPIO_DRV_STRENGTH_BITS) - 1)

/*
 * Northstar2 GPIO core
 *
 * @dev: pointer to device
 * @base: I/O register base for Northstar2 GPIO controller
 * @io_ctrl: I/O register base for certain type of Northstar2 GPIO controller
 * that has the PINCONF support implemented outside of the GPIO block
 * @lock: lock to protect access to I/O registers
 * @gc: GPIO chip
 * @num_banks: number of GPIO banks, each bank supports up to 32 GPIOs
 * @pinmux_is_supported: flag to indicate this GPIO controller contains pins
 * that can be individually muxed to GPIO
 * @pctl: pointer to pinctrl_dev
 * @pctldesc: pinctrl descriptor
 * @pins: pointer to array of pins
 * @irq: interrupt ID
 * @irq_domain: interrupt domain when configured as an interrupt controller
 */
struct northstar2_gpio {
	struct device *dev;

	void __iomem *base;
	void __iomem *io_ctrl;

	spinlock_t lock;

	struct gpio_chip gc;
	unsigned num_banks;

	int pinmux_is_supported;

	struct pinctrl_dev *pctl;
	struct pinctrl_desc pctldesc;
	struct pinctrl_pin_desc *pins;

	int irq;
	struct irq_domain *irq_domain;
};

static struct northstar2_gpio *to_northstar2_gpio(struct gpio_chip *gc)
{
	return container_of(gc, struct northstar2_gpio, gc);
}

/*
 * Mapping from PINCONF pins to GPIO pins is 1-to-1
 */
static unsigned northstar2_pin_to_gpio(unsigned pin)
{
	return pin;
}

static u32 northstar2_readl(struct northstar2_gpio *chip, unsigned int offset)
{
	return readl(chip->base + offset);
}

static void northstar2_writel(struct northstar2_gpio *chip, unsigned int offset,
			  u32 val)
{
	writel(val, chip->base + offset);
}

/**
 *  northstar2_set_bit - set or clear one bit (corresponding to the GPIO pin) in a
 *  Northstar2 GPIO register
 *
 *  @northstar2_gpio: Northstar2 GPIO device
 *  @reg: register offset
 *  @gpio: GPIO pin
 *  @set: set or clear. 1 - set; 0 -clear
 */
static void northstar2_set_bit(struct northstar2_gpio *chip, unsigned int reg,
			   unsigned gpio, int set)
{
	unsigned int offset = NORTHSTAR2_GPIO_REG(gpio, reg);
	unsigned int shift = NORTHSTAR2_GPIO_SHIFT(gpio);
	u32 val;

	val = northstar2_readl(chip, offset);
	if (set)
		val |= BIT(shift);
	else
		val &= ~BIT(shift);
	northstar2_writel(chip, offset, val);
}

static int northstar2_get_bit(struct northstar2_gpio *chip, unsigned int reg,
			  unsigned gpio)
{
	unsigned int offset = NORTHSTAR2_GPIO_REG(gpio, reg);
	unsigned int shift = NORTHSTAR2_GPIO_SHIFT(gpio);
	u32 val;

	val = northstar2_readl(chip, offset) & BIT(shift);
	if (val)
		return 1;
	else
		return 0;
}

static int northstar2_gpio_to_irq(struct gpio_chip *gc, unsigned offset)
{
	struct northstar2_gpio *chip = to_northstar2_gpio(gc);

	return irq_find_mapping(chip->irq_domain, offset);
}

static void northstar2_gpio_irq_handler(unsigned int irq, struct irq_desc *desc)
{
	struct northstar2_gpio *chip;
	struct irq_chip *irq_chip = irq_desc_get_chip(desc);
	int i, bit;

	chained_irq_enter(irq_chip, desc);

	chip = irq_get_handler_data(irq);

	/* go through the entire GPIO banks and handle all interrupts */
	for (i = 0; i < chip->num_banks; i++) {
		unsigned long val = northstar2_readl(chip,
				(i * GPIO_BANK_SIZE) +
				NORTHSTAR2_GPIO_INT_MSTAT_OFFSET);

		for_each_set_bit(bit, &val, NGPIOS_PER_BANK) {
			unsigned pin = NGPIOS_PER_BANK * i + bit;
			int child_irq = northstar2_gpio_to_irq(&chip->gc, pin);

			/*
			 * Handle the interrupt before clearing the hardware
			 * to prevent double interrupts with the handler is
			 * doing part of the hardware clearing.
			 */
			generic_handle_irq(child_irq);

			/* Clear the interrupt */
			northstar2_writel(chip, (i * GPIO_BANK_SIZE) +
				      NORTHSTAR2_GPIO_INT_CLR_OFFSET, BIT(bit));

		}
	}

	chained_irq_exit(irq_chip, desc);
}


static void northstar2_gpio_irq_ack(struct irq_data *d)
{
	struct northstar2_gpio *chip = irq_data_get_irq_chip_data(d);
	unsigned gpio = d->hwirq;
	unsigned int offset = NORTHSTAR2_GPIO_REG(gpio,
			NORTHSTAR2_GPIO_INT_CLR_OFFSET);
	unsigned int shift = NORTHSTAR2_GPIO_SHIFT(gpio);
	u32 val = BIT(shift);

	northstar2_writel(chip, offset, val);
}

/**
 *  northstar2_gpio_irq_set_mask - mask/unmask a GPIO interrupt
 *
 *  @d: IRQ chip data
 *  @mask: mask/unmask GPIO interrupt. 0 - mask (disable); 1 - unmask (enable)
 */
static void northstar2_gpio_irq_set_mask(struct irq_data *d, int mask)
{
	struct northstar2_gpio *chip = irq_data_get_irq_chip_data(d);
	unsigned gpio = d->hwirq;

	northstar2_set_bit(chip, NORTHSTAR2_GPIO_INT_MSK_OFFSET, gpio, mask);
}

static void northstar2_gpio_irq_mask(struct irq_data *d)
{
	struct northstar2_gpio *chip = irq_data_get_irq_chip_data(d);
	unsigned long flags;

	spin_lock_irqsave(&chip->lock, flags);
	northstar2_gpio_irq_set_mask(d, 0);
	spin_unlock_irqrestore(&chip->lock, flags);
}

static void northstar2_gpio_irq_unmask(struct irq_data *d)
{
	struct northstar2_gpio *chip = irq_data_get_irq_chip_data(d);
	unsigned long flags;

	spin_lock_irqsave(&chip->lock, flags);
	northstar2_gpio_irq_set_mask(d, 1);
	spin_unlock_irqrestore(&chip->lock, flags);
}

static int northstar2_gpio_irq_set_type(struct irq_data *d, unsigned int type)
{
	struct northstar2_gpio *chip = irq_data_get_irq_chip_data(d);
	unsigned gpio = d->hwirq;
	int int_type = 0, dual_edge = 0, edge_lvl = 0;
	unsigned long flags;

	switch (type & IRQ_TYPE_SENSE_MASK) {
	case IRQ_TYPE_EDGE_RISING:
		edge_lvl = 1;
		break;

	case IRQ_TYPE_EDGE_FALLING:
		break;

	case IRQ_TYPE_EDGE_BOTH:
		dual_edge = 1;
		break;

	case IRQ_TYPE_LEVEL_HIGH:
		int_type = 1;
		edge_lvl = 1;
		break;

	case IRQ_TYPE_LEVEL_LOW:
		int_type = 1;
		break;

	default:
		dev_err(chip->dev, "invalid GPIO IRQ type 0x%x\n",
			type);
		return -EINVAL;
	}

	spin_lock_irqsave(&chip->lock, flags);
	northstar2_set_bit(chip,
		NORTHSTAR2_GPIO_IN_TYPE_OFFSET, gpio, int_type);
	northstar2_set_bit(chip,
		NORTHSTAR2_GPIO_INT_DE_OFFSET, gpio, dual_edge);
	northstar2_set_bit(chip,
		NORTHSTAR2_GPIO_INT_EDGE_OFFSET, gpio, edge_lvl);
	spin_unlock_irqrestore(&chip->lock, flags);

	dev_dbg(chip->dev,
		"gpio:%u set int_type:%d dual_edge:%d edge_lvl:%d\n",
		gpio, int_type, dual_edge, edge_lvl);

	return 0;
}

static struct irq_chip northstar2_gpio_irq_chip = {
	.name = "bcm-northstar2-gpio",
	.irq_ack = northstar2_gpio_irq_ack,
	.irq_mask = northstar2_gpio_irq_mask,
	.irq_unmask = northstar2_gpio_irq_unmask,
	.irq_set_type = northstar2_gpio_irq_set_type,
};

/*
 * Request the Northstar2 IOMUX pinmux controller to mux individual pins to GPIO
 */
static int northstar2_gpio_request(struct gpio_chip *gc, unsigned offset)
{
	struct northstar2_gpio *chip = to_northstar2_gpio(gc);
	unsigned gpio = gc->base + offset;

	/* not all Northstar2 GPIO pins can be muxed individually */
	if (!chip->pinmux_is_supported)
		return 0;

	return pinctrl_request_gpio(gpio);
}

static void northstar2_gpio_free(struct gpio_chip *gc, unsigned offset)
{
	struct northstar2_gpio *chip = to_northstar2_gpio(gc);
	unsigned gpio = gc->base + offset;

	if (!chip->pinmux_is_supported)
		return;

	pinctrl_free_gpio(gpio);
}

static int northstar2_gpio_direction_input(struct gpio_chip *gc, unsigned gpio)
{
	struct northstar2_gpio *chip = to_northstar2_gpio(gc);
	unsigned long flags;

	spin_lock_irqsave(&chip->lock, flags);
	northstar2_set_bit(chip, NORTHSTAR2_GPIO_OUT_EN_OFFSET, gpio, 0);
	spin_unlock_irqrestore(&chip->lock, flags);

	dev_dbg(chip->dev, "gpio:%u set input\n", gpio);

	return 0;
}

static int northstar2_gpio_direction_output(struct gpio_chip *gc, unsigned gpio,
					int value)
{
	struct northstar2_gpio *chip = to_northstar2_gpio(gc);
	unsigned long flags;

	spin_lock_irqsave(&chip->lock, flags);
	northstar2_set_bit(chip, NORTHSTAR2_GPIO_OUT_EN_OFFSET, gpio, 1);
	northstar2_set_bit(chip, NORTHSTAR2_GPIO_DATA_OUT_OFFSET, gpio, value);
	spin_unlock_irqrestore(&chip->lock, flags);

	dev_dbg(chip->dev, "gpio:%u set output, value:%d\n", gpio, value);

	return 0;
}

static void northstar2_gpio_set(struct gpio_chip *gc, unsigned gpio, int value)
{
	struct northstar2_gpio *chip = to_northstar2_gpio(gc);
	unsigned long flags;

	spin_lock_irqsave(&chip->lock, flags);
	northstar2_set_bit(chip, NORTHSTAR2_GPIO_DATA_OUT_OFFSET, gpio, value);
	spin_unlock_irqrestore(&chip->lock, flags);

	dev_dbg(chip->dev, "gpio:%u set, value:%d\n", gpio, value);
}

static int northstar2_gpio_get(struct gpio_chip *gc, unsigned gpio)
{
	struct northstar2_gpio *chip = to_northstar2_gpio(gc);
	unsigned int offset = NORTHSTAR2_GPIO_REG(gpio,
					      NORTHSTAR2_GPIO_DATA_IN_OFFSET);
	unsigned int shift = NORTHSTAR2_GPIO_SHIFT(gpio);

	return !!(northstar2_readl(chip, offset) & BIT(shift));
}

/*
 * Comparator for gpiochip_find(). Match if pin falls between start and end pin
 * for a controller.
 *
 * @param chip A gpio chip in the list maintained by gpiolib.
 * @param data The gpio pin number to find.
 *
 * @return 1 = match found, 0 = no match
 */
static inline int northstar2_gpiolib_match(struct gpio_chip *chip, void *data)
{
	unsigned int pin = *((unsigned int *)data);
	int end_pin;

	end_pin = (chip->base + chip->ngpio) - 1;
	if (pin >= chip->base && pin <= end_pin)
		return 1;
	else
		return 0;
}

/*
 * Gets the gpio controller handling a gpio pin# using the list maintained by
 * gpiolib.
 *
 * @pin The gpio pin number to find.
 *
 * @return The gpio controller controlling the pin requested.
 */
static inline struct northstar2_gpio *northstar2_gpiolib_getchip(
	unsigned int pin)
{
	struct gpio_chip *chip =
		gpiochip_find((void *)&pin, northstar2_gpiolib_match);

	if (chip)
		return to_northstar2_gpio(chip);
	else
		return 0;
}

/*
 * Setting the bit for the GPIO pin in the AUX SEL register
 * routes the internal PWM signal to the GPIO pin. There
 * are four PWM signals that can route to GPIO 0...3.
 */
int iproc_gpiolib_pwm_set(unsigned gpio)
{
	struct northstar2_gpio *ourchip = northstar2_gpiolib_getchip(gpio);

	if (gpio > 3)
		return -EINVAL;

	pr_debug("%s: Setting pin %u to PWM\n", __func__, gpio);

	northstar2_set_bit(ourchip, NORTHSTAR2_GPIO_AUX_SEL, gpio, 1);

	return 0;
}
EXPORT_SYMBOL_GPL(iproc_gpiolib_pwm_set);

int iproc_gpiolib_pwm_clear(unsigned gpio)
{
	struct northstar2_gpio *ourchip = northstar2_gpiolib_getchip(gpio);

	if (gpio > 3)
		return -EINVAL;

	pr_debug("%s: Setting pin %u to non-PWM\n", __func__, gpio);

	northstar2_set_bit(ourchip, NORTHSTAR2_GPIO_AUX_SEL, gpio, 0);

	return 0;
}
EXPORT_SYMBOL_GPL(iproc_gpiolib_pwm_clear);

static struct lock_class_key gpio_lock_class;

static int northstar2_gpio_irq_map(struct irq_domain *d, unsigned int irq,
			       irq_hw_number_t hwirq)
{
	int ret;

	ret = irq_set_chip_data(irq, d->host_data);
	if (ret < 0)
		return ret;

	irq_set_lockdep_class(irq, &gpio_lock_class);
	irq_set_chip_and_handler(irq, &northstar2_gpio_irq_chip,
			handle_simple_irq);
	set_irq_flags(irq, IRQF_VALID);

	return 0;
}

static void northstar2_gpio_irq_unmap(struct irq_domain *d, unsigned int irq)
{
	irq_set_chip_and_handler(irq, NULL, NULL);
	irq_set_chip_data(irq, NULL);
}

static struct irq_domain_ops northstar2_irq_ops = {
	.map = northstar2_gpio_irq_map,
	.unmap = northstar2_gpio_irq_unmap,
	.xlate = irq_domain_xlate_twocell,
};

static int northstar2_get_groups_count(struct pinctrl_dev *pctldev)
{
	return 1;
}

/*
 * Only one group: "gpio_grp", since this pinctrl device only performs GPIO
 * specific PINCONF configurations
 */
static const char *northstar2_get_group_name(struct pinctrl_dev *pctldev,
					 unsigned selector)
{

	return "gpio_grp";
}

static int northstar2_get_group_pins(struct pinctrl_dev *pctldev,
				 unsigned selector, const unsigned **pins,
				 unsigned *npins)
{
	/*
	 * Simply return error here. This callback is for sysfs and not
	 * mandatory anymore in later verions of kernels
	 */
	return -EINVAL;
}

static const struct pinctrl_ops northstar2_pctrl_ops = {
	.get_groups_count = northstar2_get_groups_count,
	.get_group_name = northstar2_get_group_name,
	.get_group_pins = northstar2_get_group_pins,
	.dt_node_to_map = pinconf_generic_dt_node_to_map_pin,
	.dt_free_map = pinctrl_utils_dt_free_map,
};

static int northstar2_gpio_set_pull(struct northstar2_gpio *chip, unsigned gpio,
				int disable, int pull_up)
{
	unsigned long flags;

	spin_lock_irqsave(&chip->lock, flags);

	if (disable) {
		northstar2_set_bit(chip,
			NORTHSTAR2_GPIO_RES_EN_OFFSET, gpio, 0);
	} else {
		northstar2_set_bit(chip,
			NORTHSTAR2_GPIO_PAD_RES_OFFSET, gpio, pull_up);
		northstar2_set_bit(chip,
			NORTHSTAR2_GPIO_RES_EN_OFFSET, gpio, 1);
	}

	spin_unlock_irqrestore(&chip->lock, flags);

	dev_dbg(chip->dev, "gpio:%u set pullup:%d\n", gpio, pull_up);

	return 0;
}

static void northstar2_gpio_get_pull(struct northstar2_gpio *chip,
				unsigned gpio, int *disable, int *pull_up)
{
	unsigned long flags;

	spin_lock_irqsave(&chip->lock, flags);
	*disable =
		!northstar2_get_bit(chip, NORTHSTAR2_GPIO_RES_EN_OFFSET, gpio);
	*pull_up =
		northstar2_get_bit(chip, NORTHSTAR2_GPIO_PAD_RES_OFFSET, gpio);
	spin_unlock_irqrestore(&chip->lock, flags);
}

static int northstar2_gpio_set_strength(struct northstar2_gpio *chip,
					unsigned gpio, unsigned strength)
{
	void __iomem *base;
	unsigned int i, offset, shift;
	u32 val;
	unsigned long flags;

	/* make sure specific drive strength is supported */
	if (strength < 2 ||  strength > 16 || (strength % 2))
		return -ENOTSUPP;

	if (chip->io_ctrl) {
		base = chip->io_ctrl;
		offset = NORTHSTAR2_GPIO_DRV0_CTRL_OFFSET;
	} else {
		base = chip->base;
		offset = NORTHSTAR2_GPIO_REG(gpio,
				 NORTHSTAR2_GPIO_ASIU_DRV0_CTRL_OFFSET);
	}

	shift = NORTHSTAR2_GPIO_SHIFT(gpio);

	dev_dbg(chip->dev, "gpio:%u set drive strength:%d mA\n", gpio,
		strength);

	spin_lock_irqsave(&chip->lock, flags);
	strength = (strength / 2) - 1;
	for (i = 0; i < GPIO_DRV_STRENGTH_BITS; i++) {
		val = readl(base + offset);
		val &= ~BIT(shift);
		val |= ((strength >> i) & 0x1) << shift;
		writel(val, base + offset);
		offset += 4;
	}
	spin_unlock_irqrestore(&chip->lock, flags);

	return 0;
}

static int northstar2_gpio_get_strength(struct northstar2_gpio *chip,
					unsigned gpio, u16 *strength)
{
	void __iomem *base;
	unsigned int i, offset, shift;
	u32 val;
	unsigned long flags;

	if (chip->io_ctrl) {
		base = chip->io_ctrl;
		offset = NORTHSTAR2_GPIO_DRV0_CTRL_OFFSET;
	} else {
		base = chip->base;
		offset = NORTHSTAR2_GPIO_REG(gpio,
			 NORTHSTAR2_GPIO_ASIU_DRV0_CTRL_OFFSET);
	}

	shift = NORTHSTAR2_GPIO_SHIFT(gpio);

	spin_lock_irqsave(&chip->lock, flags);
	*strength = 0;
	for (i = 0; i < GPIO_DRV_STRENGTH_BITS; i++) {
		val = readl(base + offset) & BIT(shift);
		val >>= shift;
		*strength += (val << i);
		offset += 4;
	}

	/* convert to mA */
	*strength = (*strength + 1) * 2;
	spin_unlock_irqrestore(&chip->lock, flags);

	return 0;
}

static int northstar2_pin_config_get(struct pinctrl_dev *pctldev, unsigned pin,
				 unsigned long *config)
{
	struct northstar2_gpio *chip = pinctrl_dev_get_drvdata(pctldev);
	enum pin_config_param param = pinconf_to_config_param(*config);
	unsigned gpio = northstar2_pin_to_gpio(pin);
	u16 arg;
	int disable, pull_up, ret;

	switch (param) {
	case PIN_CONFIG_BIAS_DISABLE:
		northstar2_gpio_get_pull(chip, gpio, &disable, &pull_up);
		if (disable)
			return 0;
		else
			return -EINVAL;

	case PIN_CONFIG_BIAS_PULL_UP:
		northstar2_gpio_get_pull(chip, gpio, &disable, &pull_up);
		if (!disable && pull_up)
			return 0;
		else
			return -EINVAL;

	case PIN_CONFIG_BIAS_PULL_DOWN:
		northstar2_gpio_get_pull(chip, gpio, &disable, &pull_up);
		if (!disable && !pull_up)
			return 0;
		else
			return -EINVAL;

	case PIN_CONFIG_DRIVE_STRENGTH:
		ret = northstar2_gpio_get_strength(chip, gpio, &arg);
		if (ret)
			return ret;
		else
			*config = pinconf_to_config_packed(param, arg);
			return 0;
		break;

	default:
		return -ENOTSUPP;
	}

	return -ENOTSUPP;
}

static int northstar2_pin_config_set(struct pinctrl_dev *pctldev, unsigned pin,
				 unsigned long *configs, unsigned num_configs)
{
	struct northstar2_gpio *chip = pinctrl_dev_get_drvdata(pctldev);
	unsigned gpio = northstar2_pin_to_gpio(pin);
	int i;

	for (i = 0; i < num_configs; i++) {
		u16 arg = pinconf_to_config_argument(configs[i]);
		int ret;

		switch (pinconf_to_config_param(configs[i])) {
		case PIN_CONFIG_BIAS_DISABLE:
			ret = northstar2_gpio_set_pull(chip, gpio, 1, 0);
			if (ret)
				return ret;
			break;

		case PIN_CONFIG_BIAS_PULL_UP:
			ret = northstar2_gpio_set_pull(chip, gpio, 0, 1);
			if (ret)
				return ret;
			break;

		case PIN_CONFIG_BIAS_PULL_DOWN:
			ret = northstar2_gpio_set_pull(chip, gpio, 0, 0);
			if (ret)
				return ret;
			break;

		case PIN_CONFIG_DRIVE_STRENGTH:
			ret = northstar2_gpio_set_strength(chip, gpio, arg);
			if (ret)
				return ret;
			break;

		default:
			dev_err(chip->dev, "invalid configuration\n");
			return -ENOTSUPP;
		}
	}

	return 0;
}

static const struct pinconf_ops northstar2_pconf_ops = {
	.is_generic = true,
	.pin_config_get = northstar2_pin_config_get,
	.pin_config_set = northstar2_pin_config_set,
};

/*
 * Map a GPIO in the local gpio_chip pin space to a pin in the Northstar2 IOMUX
 * pinctrl pin space
 */
struct northstar2_gpio_pin_range {
	unsigned offset;
	unsigned pin_base;
	unsigned num_pins;
};

#define NORTHSTAR2_PINRANGE(o, p, n) \
	{ .offset = o, .pin_base = p, .num_pins = n }

/*
 * Pin mapping table for mapping local GPIO pins to IOMUX pinctrl pins
 */
static const struct northstar2_gpio_pin_range northstar2_gpio_pintable[] = {
	NORTHSTAR2_PINRANGE(0, 24, 2),
	NORTHSTAR2_PINRANGE(2, 27, 30)
};

/*
 * The Northstar2 IOMUX controller mainly supports group based mux
 * configuration, but certain pins can be muxed to GPIO individually.
 * Only the ASIU GPIO controller can support this, so it's an optional
 * configuration.
 *
 * Return -ENODEV means no support and that's fine
 */
static int northstar2_gpio_pinmux_add_range(struct northstar2_gpio *chip)
{
	struct device_node *node = chip->dev->of_node;
	struct device_node *pinmux_node;
	struct platform_device *pinmux_pdev;
	struct gpio_chip *gc = &chip->gc;
	int i, ret;

	/* parse DT to find the phandle to the pinmux controller */
	pinmux_node = of_parse_phandle(node, "pinmux", 0);
	if (!pinmux_node)
		return -ENODEV;

	pinmux_pdev = of_find_device_by_node(pinmux_node);
	if (!pinmux_pdev) {
		dev_err(chip->dev, "failed to get pinmux device\n");
		return -EINVAL;
	}

	/* now need to create the mapping between local GPIO and PINMUX pins */
	for (i = 0; i < ARRAY_SIZE(northstar2_gpio_pintable); i++) {
		ret = gpiochip_add_pin_range(gc, dev_name(&pinmux_pdev->dev),
				     northstar2_gpio_pintable[i].offset,
				     northstar2_gpio_pintable[i].pin_base,
				     northstar2_gpio_pintable[i].num_pins);
		if (ret) {
			dev_err(chip->dev, "unable to add GPIO pin range\n");
			goto err_rm_pin_range;
		}
	}

	chip->pinmux_is_supported = 1;
	return 0;

err_rm_pin_range:
	gpiochip_remove_pin_ranges(gc);
	return ret;
}

static void northstar2_gpio_pinmux_remove_range(struct northstar2_gpio *chip)
{
	struct gpio_chip *gc = &chip->gc;

	if (chip->pinmux_is_supported)
		gpiochip_remove_pin_ranges(gc);
}

/*
 * Northstar2 GPIO controller supports some PINCONF related configurations
 * such as pull up, pull down, and drive strength, when the pin is
 * configured as GPIO
 *
 * Here a pinctrl device is created with simple 1-to-1 pin mapping to the local
 * GPIO pins
 */
static int northstar2_gpio_register_pinconf(struct northstar2_gpio *chip)
{
	struct pinctrl_desc *pctldesc = &chip->pctldesc;
	struct pinctrl_pin_desc *pins;
	struct gpio_chip *gc = &chip->gc;
	int i, ret;

	pins = devm_kcalloc(chip->dev, gc->ngpio, sizeof(*pins), GFP_KERNEL);
	if (!pins)
		return -ENOMEM;
	chip->pins = pins;

	for (i = 0; i < gc->ngpio; i++) {
		pins[i].number = i;
		pins[i].name = kasprintf(GFP_KERNEL, "gpio-%d", i);
		if (!pins[i].name) {
			ret = -ENOMEM;
			goto err_kfree;
		}
	}

	pctldesc->name = dev_name(chip->dev);
	pctldesc->pctlops = &northstar2_pctrl_ops;
	pctldesc->pins = pins;
	pctldesc->npins = gc->ngpio;
	pctldesc->confops = &northstar2_pconf_ops;

	chip->pctl = pinctrl_register(pctldesc, chip->dev, chip);
	if (!chip->pctl) {
		dev_err(chip->dev, "unable to register pinctrl device\n");
		ret = -EINVAL;
		goto err_kfree;
	}

	return 0;

err_kfree:
	for (i = 0; i < gc->ngpio; i++)
		kfree(pins[i].name);

	return ret;
}

static void northstar2_gpio_unregister_pinconf(struct northstar2_gpio *chip)
{
	struct gpio_chip *gc = &chip->gc;
	int i;

	if (chip->pctl)
		pinctrl_unregister(chip->pctl);

	for (i = 0; i < gc->ngpio; i++)
		kfree(chip->pins[i].name);
}

static const struct of_device_id northstar2_gpio_of_match[] = {
	{ .compatible = "brcm,northstar2-gpio" },
	{ }
};
MODULE_DEVICE_TABLE(of, northstar2_gpio_of_match);

static int northstar2_gpio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	struct northstar2_gpio *chip;
	struct gpio_chip *gc;
	u32 i, ngpios, gpio_base;
	int ret;

	chip = devm_kzalloc(dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	chip->dev = dev;
	platform_set_drvdata(pdev, chip);

	if (of_property_read_u32(dev->of_node, "ngpios", &ngpios)) {
		dev_err(&pdev->dev, "missing ngpios DT property\n");
		return -ENODEV;
	}
	chip->num_banks = (ngpios + NGPIOS_PER_BANK - 1) / NGPIOS_PER_BANK;

	if (of_property_read_u32(dev->of_node, "linux,gpio-base",
				 &gpio_base)) {
		dev_err(&pdev->dev, "missing linux,gpio-base DT property\n");
		return -ENODEV;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	chip->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(chip->base)) {
		dev_err(&pdev->dev, "unable to map I/O memory\n");
		return PTR_ERR(chip->base);
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (res) {
		chip->io_ctrl = devm_ioremap_resource(dev, res);
		if (IS_ERR(chip->io_ctrl)) {
			dev_err(&pdev->dev, "unable to map I/O memory\n");
			return PTR_ERR(chip->io_ctrl);
		}
	}

	spin_lock_init(&chip->lock);

	gc = &chip->gc;
	gc->base = gpio_base;
	gc->ngpio = ngpios;
	gc->label = dev_name(dev);
	gc->dev = dev;
	gc->of_node = dev->of_node;
	gc->request = northstar2_gpio_request;
	gc->free = northstar2_gpio_free;
	gc->direction_input = northstar2_gpio_direction_input;
	gc->direction_output = northstar2_gpio_direction_output;
	gc->set = northstar2_gpio_set;
	gc->get = northstar2_gpio_get;
	gc->to_irq = northstar2_gpio_to_irq;

	ret = gpiochip_add(gc);
	if (ret < 0) {
		dev_err(&pdev->dev, "unable to add GPIO chip\n");
		return ret;
	}

	ret = northstar2_gpio_pinmux_add_range(chip);
	if (ret && ret != -ENODEV) {
		dev_err(&pdev->dev, "unable to add GPIO pin range\n");
		goto err_rm_gpiochip;
	}

	ret = northstar2_gpio_register_pinconf(chip);
	if (ret) {
		dev_err(&pdev->dev, "unable to register pinconf\n");
		goto err_rm_range;
	}

	chip->irq = irq_of_parse_and_map(dev->of_node, 0);
	if (!chip->irq) {
		dev_err(&pdev->dev, "unable to parse and map interrupt\n");
		ret = -ENXIO;
		goto err_unregister_pinconf;
	}

	chip->irq_domain = irq_domain_add_linear(dev->of_node, gc->ngpio,
						 &northstar2_irq_ops, chip);
	if (!chip->irq_domain) {
		dev_err(&pdev->dev, "unable to allocate IRQ domain\n");
		ret = -ENXIO;
		goto err_unregister_pinconf;
	}

	for (i = 0; i < gc->ngpio; i++) {
		int irq = irq_create_mapping(chip->irq_domain, i);

		irq_set_lockdep_class(irq, &gpio_lock_class);
		irq_set_chip_data(irq, chip);
		irq_set_chip_and_handler(irq, &northstar2_gpio_irq_chip,
				handle_simple_irq);
		set_irq_flags(irq, IRQF_VALID);
	}

	irq_set_chained_handler(chip->irq, northstar2_gpio_irq_handler);
	irq_set_handler_data(chip->irq, chip);

	return 0;

err_unregister_pinconf:
	northstar2_gpio_unregister_pinconf(chip);

err_rm_range:
	northstar2_gpio_pinmux_remove_range(chip);

err_rm_gpiochip:
	gpiochip_remove(gc);

	return ret;
}

static struct platform_driver northstar2_gpio_driver = {
	.driver = {
		.name = "northstar2-gpio",
		.of_match_table = northstar2_gpio_of_match,
	},
	.probe = northstar2_gpio_probe,
};

static int __init northstar2_gpio_init(void)
{
	return platform_driver_probe(&northstar2_gpio_driver,
			northstar2_gpio_probe);
}
arch_initcall_sync(northstar2_gpio_init);

MODULE_DESCRIPTION("Broadcom Northstar2 GPIO Driver");
MODULE_LICENSE("GPL v2");
