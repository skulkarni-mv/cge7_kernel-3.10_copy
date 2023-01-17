/*
*   Author: Open Silicon, Inc.
*   Contact: platform@open-silicon.com
*   This file is part of the Voledia SDK
*
*   Copyright (c) 2012 Open-Silicon Inc.
*   This file is free software; you can redistribute it and/or modify it under the terms of the
*   GNU General Public License, Version 2, as published by the Free Software Foundation.
*
*   This file is distributed in the hope that it will be useful, but AS-IS and WITHOUT ANY
*   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
*   FOR A PARTICULAR PURPOSE, TITLE, or NONINFRINGEMENT. See the GNU
*   General Public License for more details.
*
*   This file may also be available under a different license from Open-Silicon.
*   Contact Open-Silicon for more information
*/
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/io.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#define GPIO_PROC_NAME		"gpio"

static DEFINE_SPINLOCK(gpio_lock);

struct chog_gpio_chip {
	struct gpio_chip chip;
	int irq;
	void __iomem *reg_sharepin_en;
	struct gpio_ctr_regs __iomem *regs;
};

#define INIT_CHOG_GPIO_CHIP(name, base_no, nr_gpio)			\
	{								\
		.chip = {						\
			.label			= name,			\
			.owner			= THIS_MODULE,		\
			.request		= opv5xc_request,	\
			.direction_input	= opv5xc_direction_in,	\
			.direction_output	= opv5xc_direction_out, \
			.get			= opv5xc_get,		\
			.set			= opv5xc_set,		\
			.to_irq			= opv5xc_to_irq,	\
			.base			= base_no,		\
			.ngpio			= nr_gpio,		\
			.can_sleep		= 0,			\
		},							\
	}

#define to_chog_gpio_chip(c)	container_of(c, struct chog_gpio_chip, chip)

#define nr_banks		ARRAY_SIZE(opv5xc_gc)

struct opv5xc_regs {
	const char *name;
	volatile unsigned int *addr;
	u32 offset;
};

struct opv5xc_regs gpio_regs[] = {
	{"Data Out",		     0, GPIO_OUTPUT_OFFSET},
	{"Data In",		     0, GPIO_INPUT_OFFSET},
	{"Direction",		     0, GPIO_DIR_OFFSET},
	{"Data Set",		     0, GPIO_BIT_SET_OFFSET},
	{"Data Clear",		     0, GPIO_BIT_CLEAR_OFFSET},
	{"Interrupt Enable",	     0, GPIO_INTR_ENABLE_OFFSET},
	{"Interrupt Raw Status",     0, GPIO_INTR_RAW_STATUS_OFFSET},
	{"Interrupt Masked Status",  0, GPIO_INTR_MASKED_STATUS_OFFSET},
	{"Interrupt Trigger Method", 0, GPIO_INTR_TRIGGER_METHOD_OFFSET},
	{"Interrupt Both Edge",	     0, GPIO_INTR_TRIGGER_BOTH_EDGES_OFFSET},
	{"Interrupt Falling Edge",   0, GPIO_INTR_TRIGGER_TYPE_OFFSET},
	{"Interrupt MASKED",	     0, GPIO_INTR_MASK_OFFSET},
	{"GPIO Bounce Enable",	     0, GPIO_BOUNCE_ENABLE_OFFSET},
	{"GPIO Bounce Prescale",     0, GPIO_BOUNCE_PRESCALE_OFFSET},
	{"GPIO implemented bits",    0, GPIO_BITS_OFFSET},
	{"Revision",		     0, GPIO_REV_OFFSET},
};

/*
 * The OPV5XC GPIO pins are shard with special functions which is described in
 * the following table. "none" in this table represent the corresponding pins
 * are dedicate GPIO.
 */
const char *sharepin_desc[] = {
	 /* GPIOA group */
/*  0 */ "pwm0",        "pwm1",        "pwm2",        "pwm3",
/*  4 */ "pwm4",        "Reserved",    "pwm6",        "pwm7",
/*  8 */ "pwm8",        "pwm9",        "pwm10",       "pwm11",
/* 12 */ "pwm12",       "pwm13",       "pwm14",       "pwm15",
/* 16 */ "tacho0",      "tacho1",      "smc_addr16",  "smc_addr17",
/* 20 */ "smc_addr18",  "smc_addr19",  "smc_addr20",  "smc_addr21",
/* 24 */ "smc_addr22",  "smc_addr23",  "smc_addr24",  "smc_addr25",
/* 28 */ "smc_addr26",  "spissn2",     "spissn3",     "smc_cs_n2",
	 /* GPIOB group */
/*  0 */ "smc_cs_n3",   "smc_oe_n",    "smc_we_n",    "smc_ready",
/*  4 */ "smc_adv_n",   "pcm0_dr",     "pcm0_dt",     "pcm0_sync",
/*  8 */ "pcm0_clk",    "pcm1_dr",     "pcm1_dt",     "pcm1_sync",
/* 12 */ "pcm1_clk",    "i2s0_eclk",   "i2s0_sclk",   "i2s0_sync",
/* 16 */ "i2s0_dt",     "i2s0_dr",     "i2s1_eclk",   "i2s1_sclk",
/* 20 */ "i2s1_sync",   "i2s1_dt",     "i2s1_dr",     "spdif_out",
/* 24 */ "jtag_ntrst",  "jtag_tms",    "jtag_tck",    "jtag_tdi",
/* 28 */ "jtag_tdo",    "clkout",      "uart1_sin",   "uart1_sout",
};

/*
 * Predefined OPV5XC SOC sharepin groups.
 */

struct gpio gpios_pcm0[] = {
	/* Pin no.  flags */
	{GPIOB(5),  GPIOF_IN},
	{GPIOB(6),  GPIOF_IN},
	{GPIOB(7),  GPIOF_IN},
	{GPIOB(8),  GPIOF_IN},
};
EXPORT_SYMBOL(gpios_pcm0);

struct gpio gpios_pcm1[] = {
	/* Pin no.  flags */
	{GPIOB(9),  GPIOF_IN},
	{GPIOB(10), GPIOF_IN},
	{GPIOB(11), GPIOF_IN},
	{GPIOB(12), GPIOF_IN},
};
EXPORT_SYMBOL(gpios_pcm1);

struct gpio gpios_i2s0[] = {
	/* Pin no.  flags */
	{GPIOB(13), GPIOF_IN},
	{GPIOB(14), GPIOF_IN},
	{GPIOB(15), GPIOF_IN},
	{GPIOB(16), GPIOF_IN},
	{GPIOB(17), GPIOF_IN},
};
EXPORT_SYMBOL(gpios_i2s0);

struct gpio gpios_i2s1[] = {
	/* Pin no.  flags */
	{GPIOB(18), GPIOF_IN},
	{GPIOB(19), GPIOF_IN},
	{GPIOB(20), GPIOF_IN},
	{GPIOB(21), GPIOF_IN},
	{GPIOB(22), GPIOF_IN},
};
EXPORT_SYMBOL(gpios_i2s1);

struct gpio gpios_clko[] = {
	/* Pin no.  flags */
	{GPIOB(29), GPIOF_IN},
};
EXPORT_SYMBOL(gpios_clko);

struct gpio gpios_uart1[] = {
	/* Pin no.  flags */
	{GPIOB(30), GPIOF_IN},
	{GPIOB(31), GPIOF_IN},
};
EXPORT_SYMBOL(gpios_uart1);

static int opv5xc_request(struct gpio_chip *chip, unsigned offset)
{
	/*
	 * GPIOA5 is reserved. Please don't use and configure GPIOA5.
	 */
	if ((strcmp(chip->label, "GPIOA") == 0) && (offset == 5))
		return -EINVAL;
	return 0;
}

/*
 * Configure the GPIO line as an input.
 */
static int opv5xc_direction_in(struct gpio_chip *chip, unsigned offset)
{
	struct chog_gpio_chip *cgc = to_chog_gpio_chip(chip);
	u32 reg;

	spin_lock(&gpio_lock);
	/* Clear corresponding register bit to set as input pin. */
	reg = readl(&cgc->regs->dir);
	reg &= ~(1 << offset);
	writel(reg, &cgc->regs->dir);
	spin_unlock(&gpio_lock);

	return 0;
}

/*
 * Set the state of an output GPIO line.
 */
static void opv5xc_set(struct gpio_chip *chip, unsigned offset, int value)
{
	struct chog_gpio_chip *cgc = to_chog_gpio_chip(chip);

	if (value)
		/*
		 * Write 1 to set corresponding bit output "HIGH"
		 * Multi-bit write is allowed. Write 0 makes no change.
		 */
		writel(1 << offset, &cgc->regs->data_set);
	else
		/*
		 * Write 1 to set corresponding bit output "LOW"
		 * Multi-bit write is allowed. Write 0 makes no change.
		 */
		writel(1 << offset, &cgc->regs->data_clr);
}

/*
 * Configure the GPIO line as an output, with default state.
 */
static int opv5xc_direction_out(struct gpio_chip *chip,
				 unsigned offset, int value)
{
	struct chog_gpio_chip *cgc = to_chog_gpio_chip(chip);
	u32 reg;

	opv5xc_set(chip, offset, value);

	spin_lock(&gpio_lock);
	/* Set corresponding register bit to set as output pin. */
	reg = readl(&cgc->regs->dir);
	reg |= 1 << offset;
	writel(reg, &cgc->regs->dir);
	spin_unlock(&gpio_lock);

	return 0;
}

/*
 * Read the state of a GPIO line.
 */
static int opv5xc_get(struct gpio_chip *chip, unsigned offset)
{
	struct chog_gpio_chip *cgc = to_chog_gpio_chip(chip);
	u32 reg;
	int ret;

	reg = readl(&cgc->regs->din);
	ret = (reg >> offset) & 0x1;
	return ret;
}

/*
 * GPIO interrtups are remapped to unused irq number.
 * The remapped GPIO IRQ number start from 128
 *  (IRQ_CA9MP_GIC_START + NR_IRQS_OPV5XC).
 * 0        32       64       96      128      160      192
 * |--------|--------|--------|--------|--------|--------|
 *          |<========================>|<===============>|
 *          | OPV5XC physical IRQs       Virtual GPIO IRQs
 *          | (NR_IRQS_OPV5XC)           (NR_IRQS_OPV5XC_GPIO_VIRT)
 *          |
 *          \ IRQ_CA9MP_GIC_START
 *
 * Here is the table of GPIO to irq number mapping table.
 *
 *	GPIOA	GPIOB	|	GPIOA	GPIOB
 * No.	IRQ	IRQ	|  No.	IRQ	IRQ
 * ===================  |  ===================
 *  0	128	160	|  16	144	176
 *  1	129	161	|  17	145	177
 *  2	130	162	|  18	146	178
 *  3	131	163	|  19	147	179
 *  4	132	164	|  20	148	180
 *  5	133	165	|  21	149	181
 *  6	134	166	|  22	150	182
 *  7	135	167	|  23	151	183
 *  8	136	168	|  24	152	184
 *  9	137	169	|  25	153	185
 * 10	138	170	|  26	154	186
 * 11	139	171	|  27	155	187
 * 12	140	172	|  28	156	188
 * 13	141	173	|  29	157	189
 * 14	142	174	|  30	158	190
 * 15	143	175	|  31	159	191
 */

static int opv5xc_to_irq(struct gpio_chip *chip, unsigned offset)
{
	return offset + IRQ_CA9MP_GIC_START + NR_IRQS_OPV5XC + chip->base;
}

static unsigned __irq_to_gpio_offset(struct gpio_chip *chip, int irq)
{
	return irq - (IRQ_CA9MP_GIC_START + NR_IRQS_OPV5XC) - chip->base;
}

static int opv5xc_gpio_irq_set_type(struct irq_data *d, unsigned int type)
{
	struct chog_gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct gpio_ctr_regs __iomem *regs = gc->regs;
	unsigned offset = __irq_to_gpio_offset(&gc->chip, d->irq);
	u32 reg, reg_level, reg_both, reg_low, index;

	index = 1 << offset;

	spin_lock(&gpio_lock);

	reg_level = readl(&regs->int_trig);
	reg_both = readl(&regs->int_both);
	reg_low = readl(&regs->int_edge);

	switch (type) {
	case IRQ_TYPE_EDGE_RISING:
		reg_level &= ~index;
		reg_both &= ~index;
		reg_low &= ~index;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		reg_level &= ~index;
		reg_both &= ~index;
		reg_low |= index;
		break;
	case IRQ_TYPE_EDGE_BOTH:
		reg_level &= ~index;
		reg_both |= index;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		reg_level |= index;
		reg_low |= index;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		reg_level |= index;
		reg_low &= ~index;
		break;
	default:
		return -EINVAL;

	}
	/* Clear corresponding register bit to set as input pin. */
	reg = readl(&regs->dir);
	reg &= ~(1 << offset);
	writel(reg, &regs->dir);
	writel(reg_level, &regs->int_trig);
	writel(reg_both, &regs->int_both);
	writel(reg_low, &regs->int_edge);

	spin_unlock(&gpio_lock);

	return 0;
}

static void opv5xc_gpio_irq_ack(struct irq_data *d)
{
	struct chog_gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct gpio_ctr_regs __iomem *regs = gc->regs;
	unsigned offset = __irq_to_gpio_offset(&gc->chip, d->irq);
	u32 val;

	spin_lock(&gpio_lock);
	val = readl(&regs->int_clr);
	val |= (1 << offset);
	writel(val, &regs->int_clr);
	spin_unlock(&gpio_lock);
}

static void opv5xc_gpio_irq_mask(struct irq_data *d)
{
	struct chog_gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct gpio_ctr_regs __iomem *regs = gc->regs;
	unsigned offset = __irq_to_gpio_offset(&gc->chip, d->irq);
	u32 val;

	spin_lock(&gpio_lock);
	val = readl(&regs->int_en);
	val &= ~(1 << offset);
	writel(val, &regs->int_en);
	spin_unlock(&gpio_lock);
}

static void opv5xc_gpio_irq_unmask(struct irq_data *d)
{
	struct chog_gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct gpio_ctr_regs __iomem *regs = gc->regs;
	unsigned offset = __irq_to_gpio_offset(&gc->chip, d->irq);
	u32 val;

	spin_lock(&gpio_lock);
	val = readl(&regs->int_en);
	val |= (1 << offset);
	writel(val, &regs->int_en);
	spin_unlock(&gpio_lock);
}

static struct irq_chip opv5xc_gpio_irq_chip = {
	.name = "GPIO",
	.irq_ack = opv5xc_gpio_irq_ack,
	.irq_mask = opv5xc_gpio_irq_mask,
	.irq_unmask = opv5xc_gpio_irq_unmask,
	.irq_set_type = opv5xc_gpio_irq_set_type,
};

static struct chog_gpio_chip opv5xc_gc[] = {
			  /* label,  base,	   ngpio */
	INIT_CHOG_GPIO_CHIP("GPIOA", 0x00,	   MAX_GPIOA_NO),
#if MAX_GPIOB_NO > 0
	INIT_CHOG_GPIO_CHIP("GPIOB", MAX_GPIOA_NO, MAX_GPIOB_NO),
#endif
};

struct bank_data opv5xc_get_gpio_bank(unsigned gpio)
{
	struct gpio_chip *chip;
	struct bank_data bd;
	int i;

	for (i = 0; i < nr_banks; i++) {
		chip = &opv5xc_gc[i].chip;
		if (gpio >= chip->ngpio) {
			gpio -= chip->ngpio;
			continue;
		}
		break;
	}

	bd.bank = i;
	bd.offset = gpio;
	return bd;
}
EXPORT_SYMBOL(opv5xc_get_gpio_bank);

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
/*
 * Turn on corresponding shared pin function.
 * Turn on shared pin function will also disable GPIO function. Related GPIO
 * control registers are still accessable but not reflect to pin.
 */
int opv5xc_sharepin_request(unsigned gpio, const char *label)
{
	struct bank_data bd = opv5xc_get_gpio_bank(gpio);
	int ret;
	u32 reg;

	if (!label)
		label = sharepin_desc[gpio];

	ret = gpio_request(gpio, label);
	if (ret) {
		pr_info("gpio-%d already in use! err=%d\n", gpio, ret);
		return ret;
	}

	spin_lock(&gpio_lock);

	reg = readl(opv5xc_gc[bd.bank].reg_sharepin_en);
	if (!(reg & (1 << bd.offset))) {
		reg |= (1 << bd.offset);
		writel(reg, opv5xc_gc[bd.bank].reg_sharepin_en);
	}

	spin_unlock(&gpio_lock);

	pr_debug("%s[%d] is used by %s function!\n",
		 opv5xc_gc[bd.bank].chip.label, bd.offset, label);

	return 0;
}
EXPORT_SYMBOL(opv5xc_sharepin_request);

/*
 * opv5xc_sharepin_request_array - request multiple GPIOs shared pin function
 *				    in a single call
 * @array:	array of the 'struct gpio'
 * @num:	how many GPIOs in the array
 */
int opv5xc_sharepin_request_array(struct gpio *array, size_t num)
{
	struct gpio *_gpio;
	int i, err;

	for (i = 0; i < num; i++, array++) {
		_gpio = array;
		err = opv5xc_sharepin_request(_gpio->gpio, _gpio->label);
		if (err)
			goto err_free;
		if (_gpio->flags & GPIOF_DIR_IN)
			err = gpio_direction_input(_gpio->gpio);
		else
			err = gpio_direction_output(_gpio->gpio,
					(_gpio->flags & GPIOF_INIT_HIGH) ? 1 : 0);
		if (err)
			goto err_free;
	}

	return 0;

err_free:
	while (i--)
		opv5xc_sharepin_free((--array)->gpio);
	return err;
}
EXPORT_SYMBOL_GPL(opv5xc_sharepin_request_array);

/*
 * Turn off corresponding share pin function.
 */
void opv5xc_sharepin_free(unsigned gpio)
{
	struct bank_data bd = opv5xc_get_gpio_bank(gpio);
	u32 reg;

	spin_lock(&gpio_lock);
	reg = readl(opv5xc_gc[bd.bank].reg_sharepin_en);
	reg &= ~(1 << bd.offset);
	writel(reg, opv5xc_gc[bd.bank].reg_sharepin_en);
	spin_unlock(&gpio_lock);

	gpio_free(gpio);

	pr_debug("%s[%d] share pin function (%s) disabled!\n",
		 opv5xc_gc[bd.bank].chip.label, bd.offset,
		 sharepin_desc[gpio]);
}
EXPORT_SYMBOL(opv5xc_sharepin_free);

/*
 * opv5xc_sharepin_free_array - release multiple GPIOs in a single call
 * @array:	array of the 'struct gpio'
 * @num:	how many GPIOs in the array
 */
void opv5xc_sharepin_free_array(struct gpio *array, size_t num)
{
	while (num--)
		opv5xc_sharepin_free((array++)->gpio);
}
EXPORT_SYMBOL_GPL(opv5xc_sharepin_free_array);
#endif

static int opv5xc_gpio_show(struct seq_file *s, void *v)
{
	int i, nr_regs;
	void __iomem *baseA = opv5xc_gc[0].regs;
	void __iomem *baseB = opv5xc_gc[1].regs;
	nr_regs = ARRAY_SIZE(gpio_regs);
	seq_printf(s, "Register Description        GPIOA     GPIOB\n"
		      "====================        =====     =====\n");
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	seq_printf(s, "%-26.26s: %08x  %08x\n\n", "GPIO Disable",
		       readl(opv5xc_gc[0].reg_sharepin_en),
		       readl(opv5xc_gc[1].reg_sharepin_en));
#endif
	for (i = 0; i < nr_regs; i++) {
		seq_printf(s, "%-26.26s: %08x  %08x\n",
			       gpio_regs[i].name,
			       readl(baseA + gpio_regs[i].offset),
			       readl(baseB + gpio_regs[i].offset));
	}
	seq_printf(s, "\n"
		      "* Please refer to /sys/kernel/debug/opv5xc/gpio for human readable data.\n"
		      "  Use following command to mount debug if it is not mounted:\n"
		      "  # mount -t debugfs debugfs /sys/kernel/debugfs\n"
		      "\n");
	return 0;
}

static int opv5xc_gpio_open(struct inode *inode, struct file *file)
{
	return single_open(file, opv5xc_gpio_show, PDE_DATA(inode));
}

static const struct file_operations opv5xc_gpio_fops = {
	.open		= opv5xc_gpio_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init opv5xc_gpio_proc_init(void)
{
	/*
	 * Prepare proc file for GPIO:
	 * [FILE] /proc/opv5xc/gpio
	 */
	if (opv5xc_proc_dir)
		proc_create_data(GPIO_PROC_NAME, S_IFREG | S_IRUGO,
				opv5xc_proc_dir, &opv5xc_gpio_fops, NULL);

	return 0;
}
late_initcall(opv5xc_gpio_proc_init);

#ifdef CONFIG_DEBUG_FS
#define header0	" Number    Label                 Mode  Dir Val\n"
#define header1	" =============================== ====  === ===\n"
#define format0	" %s%-3d [%-20.20s] %-6.6s%s %s\n"
static int opv5xc_dbg_gpio_show_all(struct seq_file *s, void *unused)
{
	int i, j, is_out, disabled;
	unsigned gpio;
	const char *gpio_label;
	struct gpio_chip *chip;
	for (j = 0; j < nr_banks; j++) {
		chip = &opv5xc_gc[j].chip;
		seq_printf(s, header0);
		seq_printf(s, header1);
		for (i = 0; i < chip->ngpio; i++) {
			gpio = chip->base + i;
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
			disabled = test_bit(i, opv5xc_gc[j].reg_sharepin_en);
#else
			disabled = false;
#endif
			gpio_label = gpiochip_is_requested(chip, i);
			if (!gpio_label) {
				if (disabled)
					gpio_label = sharepin_desc[gpio];
				else
					gpio_label = "";
			}
			is_out = test_bit(i, (void *)&opv5xc_gc[j].regs->dir);
			seq_printf(s, format0, chip->label, i, gpio_label,
				   disabled ? "Func" : "GPIO",
				   is_out ? "out" : "in ",
				   chip->get(chip, i) ? "hi" : "lo");
		}
		seq_printf(s, "\n");
	}
	return 0;
}

static int dbg_gpio_open(struct inode *inode, struct file *file)
{
	return single_open(file, opv5xc_dbg_gpio_show_all, &inode->i_private);

}
static const struct file_operations debug_fops = {
	.open = dbg_gpio_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init opv5xc_gpio_debuginit(void)
{
	/*
	 * Prepare debugfs file for GPIO:
	 * [FILE] /sys/kernel/debug/opv5xc/gpio
	 */
	if (opv5xc_debugfs_dir == NULL) {
		opv5xc_debugfs_dir = debugfs_create_dir("opv5xc", NULL);
		if (opv5xc_debugfs_dir == NULL)
			goto create_dir_fail;
	}
	debugfs_create_file("gpio", S_IRUGO, opv5xc_debugfs_dir, NULL,
			    &debug_fops);
	return 0;
create_dir_fail:
	pr_err("Create DebugFS directory /sys/kernel/debug/opv5xc"
	       "failed!\n");
	return -EIO;
}
late_initcall(opv5xc_gpio_debuginit);
#endif /* CONFIG_DEBUG_FS */

static void chained_gpio_isr(unsigned irq, struct irq_desc *desc)
{
	struct chog_gpio_chip *gc = irq_get_handler_data(irq);
	unsigned i;
	int target_irq;
	u32 status;
	struct irq_chip *chip = irq_desc_get_chip(desc);

	chained_irq_enter(chip, desc);
	
	spin_lock(&gpio_lock);
	status = readl(&gc->regs->int_stat);
	writel(status, &gc->regs->int_clr);
	spin_unlock(&gpio_lock);
	
	for (i = 0; i < gc->chip.ngpio; i++) {
		if (status & (1 << i)) {
			target_irq = opv5xc_to_irq(&gc->chip, i);
			pr_debug("Invoke cascaded irq %d from irq %d\n",
					target_irq, gc->irq);
			generic_handle_irq(target_irq);
		}
	}
	
	chained_irq_exit(chip, desc);
}

static void __iomem *gpio_map(struct platform_device *pdev,
			      const char *name, int *err)
{
	struct device *dev = &pdev->dev;
	struct resource *r;
	resource_size_t start;
	resource_size_t sz;
	void __iomem *ret;

	*err = 0;
	r = platform_get_resource_byname(pdev, IORESOURCE_MEM, name);
	if (!r)
		return NULL;

	sz = resource_size(r);
	start = r->start;
	if (!devm_request_mem_region(dev, start, sz, r->name)) {
		*err = -EBUSY;
		return NULL;
	}

	ret = devm_ioremap(dev, start, sz);
	if (!ret) {
		*err = -ENOMEM;
		return NULL;
	}

	return ret;
}

static int __init gpio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	int i, j, err, nr_gpios = 0, irq = 0;

	/* Scan and match GPIO resources */
	for (i = 0; i < nr_banks; i++) {

		/* Fetech GPIO base address */
		opv5xc_gc[i].regs = gpio_map(pdev, opv5xc_gc[i].chip.label,
				&err);
		if (!opv5xc_gc[i].regs) {
			dev_dbg(dev, "%s gpio_map %s failure! err=%d\n",
				__func__, opv5xc_gc[i].chip.label, err);
			return err;
		}

		/* Fetech GPIO interrupt number */
		res = platform_get_resource_byname(pdev, IORESOURCE_IRQ,
						   opv5xc_gc[i].chip.label);
		if (!res) {
			dev_err(&pdev->dev, "Missing IRQ resource\n");
			continue;
		
		}
		irq = res->start;
		opv5xc_gc[i].irq = irq;
		opv5xc_gc[i].chip.dev = &pdev->dev;
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
		opv5xc_gc[i].reg_sharepin_en =
			(void __iomem *)OPV5XC_CR_PMU_BASE_VIRT + i * 4 + 0x90;
#endif

		gpiochip_add(&opv5xc_gc[i].chip);

		/* Initial irq_chip to handle virtual GPIO irqs. */
		for (j = 0; j < opv5xc_gc[i].chip.ngpio; j++) {
			
			irq = opv5xc_to_irq(&opv5xc_gc[i].chip, j);
			irq_set_chip_and_handler(irq, &opv5xc_gpio_irq_chip,
						 handle_simple_irq);
			set_irq_flags(irq, IRQF_VALID);
			irq_set_chip_data(irq, &opv5xc_gc[i]);
		}
		irq_set_chained_handler(opv5xc_gc[i].irq, chained_gpio_isr);
		irq_set_irq_type(opv5xc_gc[i].irq, IRQ_TYPE_LEVEL_HIGH);
		irq_set_handler_data(opv5xc_gc[i].irq, &opv5xc_gc[i]);

		nr_gpios += opv5xc_gc[i].chip.ngpio;
		if (nr_gpios >= MAX_GPIO_NO)
			break;
	}
	return 0;
}

static struct platform_driver gpio_driver = {
	.probe = gpio_probe,
	.driver = {
		.owner = THIS_MODULE,
		.name = "opv5xc-gpio",
	},
};

int __init opv5xc_gpio_init(void)
{
	return platform_driver_register(&gpio_driver);
}
postcore_initcall(opv5xc_gpio_init);
