/*
 * AppliedMicro X-Gene SoC GPIO Driver
 *
 * Copyright (c) 2013, Applied Micro Circuits Corporation
 * Author: Rameshwar Prasad Sahu <rsahu@apm.com>.
 *         Victor Gallardo <vgallardo@apm.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/clk.h>

#define GPIO_MASK(x)	(1U << ((x) % 32))
#define GPIO_PORT(x)	((x) / 32)

#define GPIO_DIR_IN	0
#define GPIO_DIR_OUT	1

#define NGPIO_DEFAULT	32

struct xgene_gpio_data_regs {
	u32 dr;			/* Data Reg */
	u32 ddr;		/* Data direction  */
	u32 ctl;		/* Data Source Control */
};

struct xgene_gpio_regs {
	struct xgene_gpio_data_regs data[4];
	u32 inten;		/* Interrupt enable */
	u32 mask;		/* Interrupt mask */
	u32 int_type;		/* Interrupt level */
	u32 int_polarity;	/* Interrupt polarity */
	u32 int_stat;		/* Interrupt status */
	u32 raw_intstat;	/* Raw interrupt status */
	u32 dbc;		/* gpio_debounce */
	u32 eoi;		/* Clear interrupt */
	u32 ext_port[4];	/* External Port */
	u32 ls_sync;		/* Synchronization level */
	u32 id_code;		/* GPIO ID code */
	u32 pad2;
	u32 comp_version;	/* GPIO Component Version */
	u32 config_reg_1;	/* GPIO Configuration Register 1 */
	u32 config_reg_2;	/* GPIO Configuration Register 2 */
};

static DEFINE_SPINLOCK(xgene_gpio_lock);

static void xgene_gpio_set_bit(void __iomem *reg, unsigned int gpio, int val)
{
	u32 data;

	data = readl(reg);
	if (val)
		data |= GPIO_MASK(gpio);
	else
		data &= ~GPIO_MASK(gpio);
	writel(data, reg);
}

static int xgene_gpio_get(struct gpio_chip *gc, unsigned int gpio)
{
	struct xgene_gpio_regs __iomem *regs = to_of_mm_gpio_chip(gc)->regs;
	void __iomem *reg = &regs->ext_port[GPIO_PORT(gpio)];

	return !!(readl(reg) & GPIO_MASK(gpio));
}

static void xgene_gpio_set(struct gpio_chip *gc, unsigned int gpio, int val)
{
	struct xgene_gpio_regs __iomem *regs = to_of_mm_gpio_chip(gc)->regs;
	u32 gpio_port = GPIO_PORT(gpio);
	unsigned long flags;

	spin_lock_irqsave(&xgene_gpio_lock, flags);

	xgene_gpio_set_bit(&regs->data[gpio_port].dr, gpio, val);

	spin_unlock_irqrestore(&xgene_gpio_lock, flags);
}

static int xgene_gpio_dir_in(struct gpio_chip *gc, unsigned int gpio)
{
	struct xgene_gpio_regs __iomem *regs = to_of_mm_gpio_chip(gc)->regs;
	u32 gpio_port = GPIO_PORT(gpio);
	unsigned long flags;

	spin_lock_irqsave(&xgene_gpio_lock, flags);

	xgene_gpio_set_bit(&regs->data[gpio_port].ddr, gpio, GPIO_DIR_IN);

	spin_unlock_irqrestore(&xgene_gpio_lock, flags);

	return 0;
}

static int xgene_gpio_dir_out(struct gpio_chip *gc, unsigned int gpio, int val)
{
	struct xgene_gpio_regs __iomem *regs = to_of_mm_gpio_chip(gc)->regs;
	u32 gpio_port = GPIO_PORT(gpio);
	unsigned long flags;

	spin_lock_irqsave(&xgene_gpio_lock, flags);

	xgene_gpio_set_bit(&regs->data[gpio_port].ddr, gpio, GPIO_DIR_OUT);
	xgene_gpio_set_bit(&regs->data[gpio_port].dr, gpio, val);

	spin_unlock_irqrestore(&xgene_gpio_lock, flags);

	return 0;
}

static int xgene_gpio_of_probe(struct platform_device *pdev)
{
	struct of_mm_gpio_chip *mm;
	struct clk *clk;
	int ngpio;
	int ret;

	mm = devm_kzalloc(&pdev->dev, sizeof(*mm), GFP_KERNEL);
	if (!mm) {
		dev_err(&pdev->dev, "Unable to allocate structure\n");
		return -ENOMEM;
	}

	mm->gc.direction_input = xgene_gpio_dir_in;
	mm->gc.direction_output = xgene_gpio_dir_out;
	mm->gc.get = xgene_gpio_get;
	mm->gc.set = xgene_gpio_set;
	mm->gc.ngpio = NGPIO_DEFAULT;
	mm->gc.base = -1;
	mm->gc.label = dev_name(&pdev->dev);
	platform_set_drvdata(pdev, mm);

	if (!of_property_read_u32(pdev->dev.of_node, "ngpio", &ngpio))
		mm->gc.ngpio = ngpio;

	clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(clk)) {
		dev_err(&pdev->dev, "failed to get GPIO clock\n");
		return PTR_ERR(clk);
	}
	ret = clk_prepare_enable(clk);
	if (ret) {
		dev_err(&pdev->dev, "clock prepare enable failed");
		return ret;
	}

	ret = of_mm_gpiochip_add(pdev->dev.of_node, mm);
	if (ret)
		dev_err(&pdev->dev, "failed to add GPIO_DW chip");
	else
		dev_info(&pdev->dev, "X-Gene GPIO_DW driver registered\n");

	return ret;
}

static int xgene_gpio_probe(struct platform_device *pdev)
{
	if (pdev->dev.of_node)
		return xgene_gpio_of_probe(pdev);

	return -ENODEV;
}

static int xgene_gpio_remove(struct platform_device *pdev)
{
	struct of_mm_gpio_chip *mm = platform_get_drvdata(pdev);

	gpiochip_remove(&mm->gc);
	return 0;
}

static const struct of_device_id xgene_gpio_of_match[] = {
	{ .compatible = "apm,xgene-gpio-dw", },
	{},
};
MODULE_DEVICE_TABLE(of, xgene_gpio_of_match);

static struct platform_driver xgene_gpio_dw_driver = {
	.driver = {
		.name = "xgene-gpio-dw",
		.owner = THIS_MODULE,
		.of_match_table = xgene_gpio_of_match,
	},
	.probe = xgene_gpio_probe,
	.remove = xgene_gpio_remove,
};
module_platform_driver(xgene_gpio_dw_driver);

MODULE_AUTHOR("AppliedMicro");
MODULE_DESCRIPTION("APM X-Gene GPIO driver");
MODULE_LICENSE("GPL");
