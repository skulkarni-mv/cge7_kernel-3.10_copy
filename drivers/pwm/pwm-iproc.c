/*
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/pwm.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#define IPROC_PWM_CHANNEL_CNT   4
#define PWM_PRESCALER_MAX       63 /* 6 bit field */

#define PWM_CTL_ENABLE_SHIFT     (0)
#define PWM_CTL_POLARITY_SHIFT   (8)

#define PWM_PRESCALE_PWM3_PRESCALE_SHIFT   (0)
#define PWM_PRESCALE_PWM3_PRESCALE_MASK    (0x0000003F)
#define PWM_PRESCALE_PWM2_PRESCALE_SHIFT   (6)
#define PWM_PRESCALE_PWM2_PRESCALE_MASK    (0x00000FC0)
#define PWM_PRESCALE_PWM1_PRESCALE_SHIFT   (12)
#define PWM_PRESCALE_PWM1_PRESCALE_MASK    (0x0003F000)
#define PWM_PRESCALE_PWM0_PRESCALE_SHIFT   (18)
#define PWM_PRESCALE_PWM0_PRESCALE_MASK    (0x00FC0000)

#define PWM_DUTY_HI_CNT0_SHIFT     (0)
#define PWM_DUTY_HI_CNT0_MASK      (0xFFFF)
#define PWM_DUTY_HI_CNT1_SHIFT     (0)
#define PWM_DUTY_HI_CNT1_MASK      (0xFFFF)
#define PWM_DUTY_HI_CNT2_SHIFT     (0)
#define PWM_DUTY_HI_CNT2_MASK      (0xFFFF)
#define PWM_DUTY_HI_CNT3_SHIFT     (0)
#define PWM_DUTY_HI_CNT3_MASK      (0xFFFF)

#define PWM_PERIOD_CNT0_SHIFT      (0)
#define PWM_PERIOD_CNT0_MASK       (0xFFFF)
#define PWM_PERIOD_CNT1_SHIFT      (0)
#define PWM_PERIOD_CNT1_MASK       (0xFFFF)
#define PWM_PERIOD_CNT2_SHIFT      (0)
#define PWM_PERIOD_CNT2_MASK       (0xFFFF)
#define PWM_PERIOD_CNT3_SHIFT      (0)
#define PWM_PERIOD_CNT3_MASK       (0xFFFF)

struct pwm_reg_def {
	u32 mask;
	u32 shift;
	u32 offset;
};

#define PWM_REG_DEF(c, m, s, o)	\
	[c] = {			\
		.mask	= m,	\
		.shift	= s,	\
		.offset	= o	\
	}

#if defined(CONFIG_ARCH_BCM_IPROC) || defined(CONFIG_ARCH_NORTHSTAR2)
#define ChipcommonB_PWMCTL_BASE 0x000
#define ChipcommonB_PWM_PRESCALE_BASE 0x024
#define ChipcommonB_PWM_PERIOD_COUNT0_BASE 0x004
#define ChipcommonB_PWM_PRESCALE_BASE 0x024
#define ChipcommonB_PWM_PERIOD_COUNT1_BASE 0x00c
#define ChipcommonB_PWM_PERIOD_COUNT2_BASE 0x014
#define ChipcommonB_PWM_PERIOD_COUNT3_BASE 0x01c
#define ChipcommonB_PWM_DUTYHI_COUNT0_BASE 0x008
#define ChipcommonB_PWM_DUTYHI_COUNT1_BASE 0x010
#define ChipcommonB_PWM_DUTYHI_COUNT2_BASE 0x018
#define ChipcommonB_PWM_DUTYHI_COUNT3_BASE 0x020

#define IPROC_CCB_PWM_CTL_BASE              (ChipcommonB_PWMCTL_BASE)
#define IPROC_CCB_PWM_PRESCALE_BASE         (ChipcommonB_PWM_PRESCALE_BASE)
#define IPROC_CCB_PWM_PERIOD_COUNT0_BASE    (ChipcommonB_PWM_PERIOD_COUNT0_BASE)
#define IPROC_CCB_PWM_PERIOD_COUNT1_BASE    (ChipcommonB_PWM_PERIOD_COUNT1_BASE)
#define IPROC_CCB_PWM_PERIOD_COUNT2_BASE    (ChipcommonB_PWM_PERIOD_COUNT2_BASE)
#define IPROC_CCB_PWM_PERIOD_COUNT3_BASE    (ChipcommonB_PWM_PERIOD_COUNT3_BASE)
#define IPROC_CCB_PWM_DUTY_HI_COUNT0_BASE   (ChipcommonB_PWM_DUTYHI_COUNT0_BASE)
#define IPROC_CCB_PWM_DUTY_HI_COUNT1_BASE   (ChipcommonB_PWM_DUTYHI_COUNT1_BASE)
#define IPROC_CCB_PWM_DUTY_HI_COUNT2_BASE   (ChipcommonB_PWM_DUTYHI_COUNT2_BASE)
#define IPROC_CCB_PWM_DUTY_HI_COUNT3_BASE   (ChipcommonB_PWM_DUTYHI_COUNT3_BASE)
#else
#error "Define registers for your chip"
#endif

static const struct
	pwm_reg_def pwm_chan_pre_scaler_info[IPROC_PWM_CHANNEL_CNT] = {
	PWM_REG_DEF(0, PWM_PRESCALE_PWM0_PRESCALE_MASK,
		PWM_PRESCALE_PWM0_PRESCALE_SHIFT, IPROC_CCB_PWM_PRESCALE_BASE),
	PWM_REG_DEF(1, PWM_PRESCALE_PWM1_PRESCALE_MASK,
		PWM_PRESCALE_PWM1_PRESCALE_SHIFT, IPROC_CCB_PWM_PRESCALE_BASE),
	PWM_REG_DEF(2, PWM_PRESCALE_PWM2_PRESCALE_MASK,
		PWM_PRESCALE_PWM2_PRESCALE_SHIFT, IPROC_CCB_PWM_PRESCALE_BASE),
	PWM_REG_DEF(3, PWM_PRESCALE_PWM3_PRESCALE_MASK,
		PWM_PRESCALE_PWM3_PRESCALE_SHIFT, IPROC_CCB_PWM_PRESCALE_BASE),
};

static const struct
	pwm_reg_def pwm_chan_period_cnt_info[IPROC_PWM_CHANNEL_CNT] = {
	PWM_REG_DEF(0, PWM_PERIOD_CNT0_MASK, PWM_PERIOD_CNT0_SHIFT,
		IPROC_CCB_PWM_PERIOD_COUNT0_BASE),
	PWM_REG_DEF(1, PWM_PERIOD_CNT1_MASK, PWM_PERIOD_CNT1_SHIFT,
		IPROC_CCB_PWM_PERIOD_COUNT1_BASE),
	PWM_REG_DEF(2, PWM_PERIOD_CNT2_MASK, PWM_PERIOD_CNT2_SHIFT,
		IPROC_CCB_PWM_PERIOD_COUNT2_BASE),
	PWM_REG_DEF(3, PWM_PERIOD_CNT3_MASK, PWM_PERIOD_CNT3_SHIFT,
		IPROC_CCB_PWM_PERIOD_COUNT3_BASE),
};

static const struct
	pwm_reg_def pwm_chan_duty_cycle_info[IPROC_PWM_CHANNEL_CNT] = {
	PWM_REG_DEF(0, PWM_DUTY_HI_CNT0_MASK, PWM_DUTY_HI_CNT0_SHIFT,
		IPROC_CCB_PWM_DUTY_HI_COUNT0_BASE),
	PWM_REG_DEF(1, PWM_DUTY_HI_CNT1_MASK, PWM_DUTY_HI_CNT1_SHIFT,
		IPROC_CCB_PWM_DUTY_HI_COUNT1_BASE),
	PWM_REG_DEF(2, PWM_DUTY_HI_CNT2_MASK, PWM_DUTY_HI_CNT2_SHIFT,
		IPROC_CCB_PWM_DUTY_HI_COUNT2_BASE),
	PWM_REG_DEF(3, PWM_DUTY_HI_CNT3_MASK, PWM_DUTY_HI_CNT3_SHIFT,
		IPROC_CCB_PWM_DUTY_HI_COUNT3_BASE),
};

#ifdef CONFIG_DEBUG_FS
struct iproc_pwm_config_debug_fs {
	struct dentry *period;
	struct dentry *duty;
	struct dentry *polarity;
	struct dentry *run;
};
#endif

/* An iproc pwm channel. */
struct iproc_pwm_channel {
	struct device *dev;
	/* Pointer to pwmlib allocated channel. */
	struct pwm_device *base_chan;
	int duty_ns;
	int period_ns;
	u32 duty_ticks;
	u32 period_ticks;
	u8  polarity;
	int running;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_entry;
	struct iproc_pwm_config_debug_fs config_entry;
#endif
};

/* An iproc pwm controller. */
struct iproc_pwmc {
	struct pwm_chip base_pwmc;
	void __iomem *iobase;
	unsigned long tick_hz;
	bool	use_aux_reg;
	struct iproc_pwm_channel *chan_list[IPROC_PWM_CHANNEL_CNT];
};

static struct __initconst of_device_id bcm_iproc_pwm_of_match[] = {
	{ .compatible = "brcm,iproc-pwm" },
	{}
};
MODULE_DEVICE_TABLE(of, bcm_iproc_pwm_of_match);

/* These functions are in the GPIO driver */
extern int iproc_gpiolib_pwm_set(unsigned gpio);
extern int iproc_gpiolib_pwm_clear(unsigned gpio);

/* Function prototypes. */
int iproc_pwmc_config_polarity(struct pwm_chip *chip, struct pwm_device *pwm,
			       enum pwm_polarity polarity);

#ifdef CONFIG_DEBUG_FS
static int __init iproc_pwmc_debugfs_init(void);
static void iproc_pwmc_debugfs_add_chan(struct iproc_pwmc *pwmc, int chan);

static struct dentry *debugfs_base;

static int _debug_pwm_config_set(void *data, u64 val)
{
	struct iproc_pwm_channel *iproc_chan = data;

	if (val) {
		iproc_pwmc_config_polarity(iproc_chan->base_chan->chip,
			iproc_chan->base_chan,
			(enum pwm_polarity) iproc_chan->polarity);
		pwm_config(iproc_chan->base_chan, iproc_chan->duty_ns,
				   iproc_chan->period_ns);
		pwm_enable(iproc_chan->base_chan);
		iproc_chan->running = 1;
	} else {
		pwm_disable(iproc_chan->base_chan);
		iproc_chan->running = 0;
	}
	return 0;
}

static int _debug_pwm_config_get(void *data, u64 *val)
{
	struct iproc_pwm_channel *iproc_chan = data;

	*val = iproc_chan->running;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(iproc_pwm_config_fop, _debug_pwm_config_get,
					_debug_pwm_config_set, "%llu\n");

static int _debug_pwm_export_set(void *data, u64 val)
{
	struct iproc_pwm_channel *iproc_chan = data;

	if (val) {
		iproc_chan->config_entry.polarity =
			debugfs_create_u8("polarity", S_IRUGO |
			S_IWUSR, iproc_chan->debugfs_entry,
			&iproc_chan->polarity);
		iproc_chan->config_entry.period =
			debugfs_create_u32("period_ns", S_IRUGO |
			S_IWUSR, iproc_chan->debugfs_entry,
			&iproc_chan->period_ns);
		iproc_chan->config_entry.duty =
			debugfs_create_u32("duty_ns", S_IRUGO |
			S_IWUSR, iproc_chan->debugfs_entry,
			&iproc_chan->duty_ns);
		iproc_chan->config_entry.run =
			debugfs_create_file("run", S_IRUGO | S_IWUSR,
			iproc_chan->debugfs_entry, data,
			&iproc_pwm_config_fop);
	} else {
		debugfs_remove(iproc_chan->config_entry.polarity);
		debugfs_remove(iproc_chan->config_entry.period);
		debugfs_remove(iproc_chan->config_entry.duty);
		debugfs_remove(iproc_chan->config_entry.run);
		pwm_disable(iproc_chan->base_chan);
	}

	return 0;
}

static int _debug_pwm_export_get(void *data, u64 *val)
{
	struct iproc_pwm_channel *iproc_chan = data;

	if (iproc_chan->base_chan)
		*val = 1;
	else
		*val = 0;

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(iproc_pwm_export_fop, _debug_pwm_export_get,
					_debug_pwm_export_set, "%llu\n");

void iproc_pwmc_debugfs_add_chan(struct iproc_pwmc *pwmc, int chan)
{
	char fname[16];

	if (!debugfs_base)
		return;

	sprintf(fname, "iproc-pwm%d", chan);
	pwmc->chan_list[chan]->debugfs_entry =
		debugfs_create_dir(fname, debugfs_base);

	debugfs_create_file("export", S_IRUGO | S_IWUSR,
				pwmc->chan_list[chan]->debugfs_entry,
				pwmc->chan_list[chan], &iproc_pwm_export_fop);
}

static int __init iproc_pwmc_debugfs_init(void)
{
	debugfs_base = debugfs_create_dir("iproc", NULL);
	if (!debugfs_base)
		return -ENOMEM;

	return 0;
}
#endif

static int iproc_get_chan(const struct pwm_device *pwm)
{
	int chan = pwm->hwpwm;
	return chan;
}

static void iproc_pwmc_clear_set_bit(const struct iproc_pwmc *pwmc,
		unsigned int offset, unsigned int shift, unsigned char enable)
{
	unsigned long val = readl(pwmc->iobase + offset);

	clear_bit(shift, &val);
	if (enable == 1)
		set_bit(shift, &val);

	writel(val, (pwmc->iobase + offset));
}

static void iproc_pwmc_set_field(const struct iproc_pwmc *pwmc,
		unsigned int offset, unsigned int mask, unsigned int shift,
		unsigned int wval)
{
	unsigned int val = readl(pwmc->iobase + offset);

	val = (val & ~mask) | (wval << shift);
	writel(val, (pwmc->iobase + offset));
}

static void iproc_pwmc_get_field(const struct iproc_pwmc *pwmc,
		unsigned int offset, unsigned int mask,
		unsigned int shift, unsigned int *val)
{
	*val = readl(pwmc->iobase + offset);
	*val = (*val & mask) >> shift;
}

static int iproc_pwmc_start(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct iproc_pwmc *pwmc =
		container_of(chip, struct iproc_pwmc, base_pwmc);
	int chan = iproc_get_chan(pwm);

	if (pwmc->use_aux_reg)
		iproc_gpiolib_pwm_set(chan);

	iproc_pwmc_clear_set_bit(pwmc, IPROC_CCB_PWM_CTL_BASE,
				 (PWM_CTL_ENABLE_SHIFT + chan), 1);

	return 0;
}

static void iproc_pwmc_stop(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct iproc_pwmc *pwmc =
		container_of(chip, struct iproc_pwmc, base_pwmc);
	int chan = iproc_get_chan(pwm);

	if (pwmc->use_aux_reg)
		iproc_gpiolib_pwm_clear(chan);

	iproc_pwmc_clear_set_bit(pwmc, IPROC_CCB_PWM_CTL_BASE,
				 (PWM_CTL_ENABLE_SHIFT + chan), 0);
}

static int iproc_pwmc_request(struct pwm_chip *chip, struct pwm_device *pwm)
{
	iproc_pwmc_stop(chip, pwm);
	return 0;
}

static void iproc_pwmc_config_duty_ticks(struct iproc_pwmc *pwmc, int chan,
		unsigned long duty_ticks)
{
	unsigned int pre_scaler = 0;
	unsigned int duty_cnt = 0;

	iproc_pwmc_get_field(pwmc, pwm_chan_pre_scaler_info[chan].offset,
			 pwm_chan_pre_scaler_info[chan].mask,
			 pwm_chan_pre_scaler_info[chan].shift,
			 &pre_scaler);

	/* Read prescaler value from register. */
	duty_cnt = duty_ticks / (pre_scaler + 1);

	/* Program duty cycle. */
	iproc_pwmc_set_field(pwmc, pwm_chan_duty_cycle_info[chan].offset,
			 pwm_chan_duty_cycle_info[chan].mask,
			 pwm_chan_duty_cycle_info[chan].shift, duty_cnt);

	if (BIT(chan) & (readl(pwmc->iobase + IPROC_CCB_PWM_CTL_BASE) & 0xf)) {
		/* Disable channel. */
		iproc_pwmc_stop(&pwmc->base_pwmc,
			pwmc->chan_list[chan]->base_chan);
		udelay(1);
		/* Enable channel. */
		iproc_pwmc_start(&pwmc->base_pwmc,
			pwmc->chan_list[chan]->base_chan);
	}
}

static int iproc_pwmc_config_period_ticks(struct iproc_pwmc *pwmc, int chan,
		unsigned long period_ticks)
{
	unsigned int pcnt;
	unsigned char pre_scaler = 0;

	pre_scaler = period_ticks / 0xFFFF;
	if (pre_scaler > PWM_PRESCALER_MAX)
		pre_scaler = PWM_PRESCALER_MAX;

	pcnt = period_ticks / (pre_scaler + 1);

	/* Program prescaler. */
	iproc_pwmc_set_field(pwmc, pwm_chan_pre_scaler_info[chan].offset,
			 pwm_chan_pre_scaler_info[chan].mask,
			 pwm_chan_pre_scaler_info[chan].shift, pre_scaler);

	/* Program period count. */
	iproc_pwmc_set_field(pwmc, pwm_chan_period_cnt_info[chan].offset,
			 pwm_chan_period_cnt_info[chan].mask,
			 pwm_chan_period_cnt_info[chan].shift, pcnt);

	if (BIT(chan) & (readl(pwmc->iobase + IPROC_CCB_PWM_CTL_BASE) & 0xf)) {
		/* Disable channel. */
		iproc_pwmc_stop(&pwmc->base_pwmc,
			pwmc->chan_list[chan]->base_chan);
		udelay(1);
		/* Enable channel. */
		iproc_pwmc_start(&pwmc->base_pwmc,
			pwmc->chan_list[chan]->base_chan);
	}

	return 0;
}

static unsigned long pwm_ns_to_ticks(struct iproc_pwmc *pwmc,
					unsigned long nsecs)
{
	unsigned long long ticks;

	ticks = nsecs;
	ticks *= pwmc->tick_hz;
	do_div(ticks, 1000000000UL);

	return ticks;
}

int iproc_pwmc_config_polarity(struct pwm_chip *chip, struct pwm_device *pwm,
			       enum pwm_polarity polarity)
{
	struct iproc_pwmc *pwmc = container_of(chip, struct iproc_pwmc,
						base_pwmc);
	int chan = iproc_get_chan(pwm);

	if (polarity) {
		iproc_pwmc_clear_set_bit(pwmc, IPROC_CCB_PWM_CTL_BASE,
					 (PWM_CTL_POLARITY_SHIFT + chan), 1);
	} else {
		iproc_pwmc_clear_set_bit(pwmc, IPROC_CCB_PWM_CTL_BASE,
					 (PWM_CTL_POLARITY_SHIFT + chan), 0);
	}

	if (BIT(chan) & (readl(pwmc->iobase + IPROC_CCB_PWM_CTL_BASE) & 0xf)) {
		/* Disable channel. */
		iproc_pwmc_stop(&pwmc->base_pwmc,
			pwmc->chan_list[chan]->base_chan);
		udelay(1);
		/* Enable channel. */
		iproc_pwmc_start(&pwmc->base_pwmc,
			pwmc->chan_list[chan]->base_chan);
	}
	pwmc->chan_list[chan]->polarity = polarity;

	return 0;
}
EXPORT_SYMBOL_GPL(iproc_pwmc_config_polarity);

static int iproc_pwmc_config(struct pwm_chip *chip, struct pwm_device *pwm,
				 int duty_ns, int period_ns)
{
	struct iproc_pwmc *pwmc = container_of(chip,
			struct iproc_pwmc, base_pwmc);
	int chan = iproc_get_chan(pwm);
	int ret;
	unsigned long period_ticks, duty_ticks;

	period_ticks = pwm_ns_to_ticks(pwmc, period_ns);
	ret = iproc_pwmc_config_period_ticks(pwmc, chan, period_ticks);
	if (ret)
		return ret;
	pwmc->chan_list[chan]->period_ticks = period_ticks;
	pwmc->chan_list[chan]->period_ns = period_ns;

	duty_ticks = pwm_ns_to_ticks(pwmc, duty_ns);
	iproc_pwmc_config_duty_ticks(pwmc, chan, duty_ticks);
	pwmc->chan_list[chan]->duty_ticks = duty_ticks;
	pwmc->chan_list[chan]->duty_ns = duty_ns;

	return 0;
}

static const struct pwm_ops iproc_pwm_ops = {
	.enable = iproc_pwmc_start,
	.disable = iproc_pwmc_stop,
	.request = iproc_pwmc_request,
	.free = iproc_pwmc_stop,
	.set_polarity = iproc_pwmc_config_polarity,
	.config = iproc_pwmc_config,
	.owner = THIS_MODULE,
};

#ifdef CONFIG_PHYS_ADDR_T_64BIT
#define PRINTF_RESOURCE "0x%llx"
#else
#define PRINTF_RESOURCE "0x%x"
#endif

static int iproc_pwmc_probe(struct platform_device *pdev)
{
	struct iproc_pwmc *pwmc;
	struct resource *res;
	int ret = 0;
	int chan;
	const struct of_device_id *match;

	match = of_match_device(bcm_iproc_pwm_of_match, &pdev->dev);
	if (!match) {
		dev_err(&pdev->dev, "Failed to find pwm controller in device tree\n");
		return -ENODEV;
	}

	/* Allocate a new iproc pwm controller. */
	pwmc = devm_kzalloc(&pdev->dev, sizeof(*pwmc), GFP_KERNEL);
	if (!pwmc) {
		dev_err(&pdev->dev, "failed to allocate memory\n");
		return -ENOMEM;
	}
	
	pwmc->use_aux_reg = of_property_read_bool(pdev->dev.of_node, "use_aux_reg");

#if defined(CONFIG_ARCH_BCM_NSP) || defined(CONFIG_ARCH_NORTHSTAR2)
	pwmc->tick_hz = 25000000UL;
#else
	pwmc->tick_hz = 1000000UL;
#endif
	pwmc->base_pwmc.ops = &iproc_pwm_ops;
	pwmc->base_pwmc.dev = &pdev->dev;
	pwmc->base_pwmc.base = -1;
	pwmc->base_pwmc.npwm = IPROC_PWM_CHANNEL_CNT;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		dev_err(&pdev->dev, "no memory resource defined\n");
		return -ENODEV;
	}

	pwmc->iobase = devm_request_and_ioremap(&pdev->dev, res);
	if (!pwmc->iobase)
		return -EADDRNOTAVAIL;
	dev_info(&pdev->dev, "iobase:0x%p phys:"PRINTF_RESOURCE"\n",
		pwmc->iobase, res->start);

	/* Register our pwm controller with pwmlib and allocate channels. */
	ret = pwmchip_add(&pwmc->base_pwmc);
	if (ret < 0)
		return ret;

	platform_set_drvdata(pdev, pwmc);

	/* Allocate iproc pwm channels. */
	for (chan = 0; chan < IPROC_PWM_CHANNEL_CNT; chan++) {
		pwmc->chan_list[chan] =
			kzalloc(sizeof(struct iproc_pwm_channel), GFP_KERNEL);
		pwmc->chan_list[chan]->dev = &pdev->dev;

		/* Channels are allocated by pwmlib. Save channel allocated
		 * during chip registration with this driver's channel data.
		 */
		pwmc->chan_list[chan]->base_chan = &pwmc->base_pwmc.pwms[chan];
	}

#ifdef CONFIG_DEBUG_FS
	iproc_pwmc_debugfs_init();
	for (chan = 0; chan < IPROC_PWM_CHANNEL_CNT; chan++)
		iproc_pwmc_debugfs_add_chan(pwmc, chan);
#endif

	return 0;
}

static int iproc_pwmc_remove(struct platform_device *pdev)
{
	struct iproc_pwmc *pwmc;
	int chan;

	pwmc = platform_get_drvdata(pdev);

#ifdef CONFIG_DEBUG_FS
	if (debugfs_base)
		debugfs_remove_recursive(debugfs_base);
#endif

	if (pwmc == NULL)
		return -ENODEV;

	for (chan = 0; chan < IPROC_PWM_CHANNEL_CNT; chan++)
		kfree(pwmc->chan_list[chan]);

	pwmchip_remove(&pwmc->base_pwmc);

	devm_iounmap(&pdev->dev, pwmc->iobase);
	kfree(pwmc);

	return 0;
}

static struct platform_driver iproc_pwmc_driver = {
	.driver = {
		.name = "iproc-pwm",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(bcm_iproc_pwm_of_match),
	},
	.probe = iproc_pwmc_probe,
	.remove = iproc_pwmc_remove,
};

module_platform_driver(iproc_pwmc_driver);

MODULE_AUTHOR("Broadcom Corporation");
MODULE_DESCRIPTION("Driver for iProc PWMC");
MODULE_LICENSE("GPL");
