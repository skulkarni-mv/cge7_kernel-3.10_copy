/*
 * OPV5XC I2S DAI driver
 *
 * Author: Nikita Yushchenko <nyoushchenko@mvista.com>
 *
 * 2010 (c) MontaVista Software, LLC. This file is licensed under
 * the terms of the GNU General Public License version 2. This program
 * is licensed "as is" without any warranty of any kind, whether express
 * or implied.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <sound/soc.h>
#include <sound/pcm_params.h>
#include <sound/dmaengine_pcm.h>
#include <mach/opv5xc.h>
#include <mach/dma.h>
#include "opv5xc-platform.h"

#define DRV_NAME	"opv5xc-i2s"

struct opv5xc_i2s_regs {
	u32 rx_data;			/* 0x00 */
	u32 rx_channel_id;		/* 0x04 */
	u32 rx_fifo_level;		/* 0x08 */
	u32 rx_fifo_size;		/* 0x0c */
	u32 rx_upper_limit;		/* 0x10 */
	u8 _pad1[12];
	u32 tx_data;			/* 0x20 */
	u32 tx_channel_id;		/* 0x24 */
	u32 tx_fifo_level;		/* 0x28 */
	u32 tx_fifo_size;		/* 0x2c */
	u32 tx_lower_limit;		/* 0x30 */
	u8 _pad2[12];
	u32 dfc;			/* 0x40 */
#define DFC_8bit		0
#define DFC_12bit		1
#define DFC_16bit		2
#define DFC_20bit		3
#define DFC_24bit		4
#define DFC_32bit		5
#define DFC_SSZ1(bits)		((bits) << 0)	/* bits per sample */
#define DFC_SSZ1_MASK		(7 << 0)
#define DFC_JST			BIT(3)		/* 1 = right-justified */
#define DFC_WDLEN1(bits)	((bits) << 5)	/* bits per channel (>= SSZ1) */
#define DFC_WDLEN1_MASK		(7 << 5)
#define DFC_FRLEN1(v)		(((v) - 1) << 8)/* channels in frame */
#define DFC_FRLEN1_MASK		(0x7f << 8)
#define DFC_SF			BIT(15)		/* 1 = TDM in I2S format */
#define DFC_SSZ2(bits)		((bits) << 16)	/* SSZ for channels in second field */
#define DFC_SSZ2_MASK		(7 << 16)
#define DFC_DATDLY_0		(0 << 19)	/* 0 bclk ticks from fclk activation to data start */
#define DFC_DATDLY_1		(1 << 19)	/* 1 bclk tick from fclk activation to data start (I2S default) */
#define DFC_DATDLY_2		(2 << 19)	/* 2 bclk ticks from fclk activation to data start */
#define DFC_DATDLY_MASK		(3 << 19)
#define DFC_WDLEN2(bits)	((bits) << 21)	/* WDLEN for channels in second field */
#define DFC_WDLEN2_MASK		(7 << 21)
#define DFC_FRLEN2(bits)	((bits) << 24)	/* FRLEN for second filed */
#define DFC_FRLEN2_MASK		(0x7f << 24)
#define DFC_PH			BIT(31)		/* 1 = two fields per period */
	u32 ssc;			/* 0x44 */
#define SSC_FPER(v)		(((v) - 1) << 4)/* bclk ticks per period */
#define SSC_FPER_MASK		(0xfff << 4)
#define SSC_FSP			BIT(16)		/* 1 = frame clock active low */
#define SSC_CLKP		BIT(17)		/* 1 = invered bclk (valid data on rising edge) */
#define SSC_MSL			BIT(18)		/* 1 = generate master and frame clocks */
#define SSC_FWID(v)		(((v) - 1) << 20) /* bclk ticks per fclk activation */
#define SSC_FWID_MASK		(0xff << 20)
	u32 control;			/* 0x48 */
#define CTRL_TX_EN		BIT(0)
#define CTRL_TX_RST		BIT(1)
#define CTRL_TX_FLUSH		BIT(2)
#define CTRL_RX_EN		BIT(4)
#define CTRL_RX_RST		BIT(5)
#define CTRL_RX_FLUSH		BIT(6)
#define CTRL_CLK_EN		BIT(8)
#define CTRL_CLK_RST		BIT(9)
	u32 interrupt;			/* 0x4c */
#define REQUEST_TX_DMA		BIT(5)
#define REQUEST_RX_DMA		BIT(4)
	u32 version;			/* 0x50 */
#define EXPECTED_VERSION	0xda1a0100
};

struct opv5xc_i2s {
	struct platform_device *pdev;
	struct opv5xc_i2s_regs __iomem *regs;
	struct snd_dmaengine_dai_dma_data playback_dma_data;
	struct snd_dmaengine_dai_dma_data capture_dma_data;

	u32 ssc, dfc;

	spinlock_t lock;
	bool tx_running, rx_running;
};

#define DEV_VALUE(i2s, val0, val1)	(i2s->pdev->id == 0 ? (val0) : (val1))

static DEFINE_MUTEX(opv5xc_i2s_mutex);

/* FIXME: misc register access should be implemented via syscon,
 *	  power management unit should be controlled via regulator,
 *	  clocks should be controlled via clk */

#define MISC_I2S_CFG		(OPV5XC_MISC_BASE_VIRT + 0x704)
#define I2S0_ENABLE		BIT(1)
#define I2S1_ENABLE		BIT(3)
#define I2S0_TX_SFT_SHIFT	16
#define I2S0_TX_SFT_MASK	(7 << I2S0_TX_SFT_SHIFT)
#define I2S0_RX_SFT_SHIFT	20
#define I2S0_RX_SFT_MASK	(7 << I2S0_RX_SFT_SHIFT)
#define I2S1_TX_SFT_SHIFT	24
#define I2S1_TX_SFT_MASK	(7 << I2S1_TX_SFT_SHIFT)
#define I2S1_RX_SFT_SHIFT	28
#define I2S1_RX_SFT_MASK	(7 << I2S1_RX_SFT_SHIFT)
#define SFT_NONE		0
#define SFT_LEFT_8		1
#define SFT_LEFT_16		2
#define SFT_LEFT_24		3
#define SFT_RIGHT_8		4
#define SFT_RIGHT_16		5
#define SFT_RIGHT_24		6

#define PMU_SYS_CLK_CTRL	(OPV5XC_CR_PMU_BASE_VIRT + 0x14)
#define I2S0_MCLK_OE		BIT(31)
#define I2S1_MCLK_OE		BIT(23)
#define I2S0_MCLK_SHIFT		6
#define I2S0_MCLK_MASK		(3 << I2S0_MCLK_SHIFT)
#define I2S1_MCLK_SHIFT		8
#define I2S1_MCLK_MASK		(3 << I2S1_MCLK_SHIFT)
#define MCLK_512fs		0
#define MCLK_256fs		1
#define MCLK_128fs		2
#define I2S0_FS_SHIFT		24
#define I2S0_FS_MASK		(0xf << I2S1_FS_SHIFT)
#define I2S1_FS_SHIFT		16
#define I2S1_FS_MASK		(0xf << I2S1_FS_SHIFT)
#define FS_8000			0
#define FS_11025		1
#define FS_16000		2
#define FS_22050		3
#define FS_24000		4
#define FS_32000		5
#define FS_44100		6
#define FS_48000		7
#define FS_88200		8
#define FS_96000		9
#define FS_176400		10
#define FS_192000		11
#define I2S0_CLKDIV_SHIFT	28
#define I2S0_CLKDIV_MASK	(7 << I2S0_CLKDIV_SHIFT)
#define I2S1_CLKDIV_SHIFT	28
#define I2S1_CLKDIV_MASK	(7 << I2S1_CLKDIV_SHIFT)
#define CLKDIV_1		0
#define CLKDIV_2		1
#define CLKDIV_4		2
#define CLKDIV_8		3
#define CLKDIV_16		4
#define CLKDIV_32		5

#define PMU_POWER_CTRL		(OPV5XC_CR_PMU_BASE_VIRT + 0x18)
#define PLL_I2S_PD		BIT(22)

static int pll_enable_count;

static int opv5xc_i2s_enable_peri(struct opv5xc_i2s *i2s)
{
	enum opv5xc_peri peri;
	u32 bit;
	int ret;

	peri = DEV_VALUE(i2s, OPV5XC_PERI_I2S0, OPV5XC_PERI_I2S1);
	ret = opv5xc_enable_peri(peri);
	if (ret)
		return ret;

	bit = DEV_VALUE(i2s, I2S0_ENABLE, I2S1_ENABLE);
	mutex_lock(&opv5xc_i2s_mutex);
	writel(readl(MISC_I2S_CFG) | bit, MISC_I2S_CFG);
	mutex_unlock(&opv5xc_i2s_mutex);

	return 0;
}

static void opv5xc_i2s_disable_peri(struct opv5xc_i2s *i2s)
{
	enum opv5xc_peri peri;
	u32 bit;

	bit = DEV_VALUE(i2s, I2S0_ENABLE, I2S1_ENABLE);
	mutex_lock(&opv5xc_i2s_mutex);
	writel(readl(MISC_I2S_CFG) & ~bit, MISC_I2S_CFG);
	mutex_unlock(&opv5xc_i2s_mutex);

	peri = DEV_VALUE(i2s, OPV5XC_PERI_I2S0, OPV5XC_PERI_I2S1);
	opv5xc_disable_peri(peri);
}

/* HW supports both external and internal MCLK source.
 *
 * Driver currently supports only internal MCLK:
 * - needed PLL is enabled at proble time (and disabled at remove time)
 * - MCLK_OE bit is set high between probe and remove
 *
 * FIXME: for lower power consumption, better to keep PLL on only when
 *        device is in use)
 */

static void opv5xc_i2s_set_mclk_master(struct opv5xc_i2s *i2s, bool enable)
{
	u32 val;

	mutex_lock(&opv5xc_i2s_mutex);

	if (enable) {

		if (!pll_enable_count) {
			val = readl(PMU_POWER_CTRL);
			val &= ~PLL_I2S_PD;
			writel(val, PMU_POWER_CTRL);
			/* FIXME: wait for PLL lock? */
		}

		pll_enable_count++;

		val = readl(PMU_SYS_CLK_CTRL);
		val |= DEV_VALUE(i2s, I2S0_MCLK_OE, I2S1_MCLK_OE);
		writel(val, PMU_SYS_CLK_CTRL);

	} else {

		val = readl(PMU_SYS_CLK_CTRL);
		val &= DEV_VALUE(i2s, I2S0_MCLK_OE, I2S1_MCLK_OE);
		writel(val, PMU_SYS_CLK_CTRL);

		pll_enable_count--;

		if (!pll_enable_count) {
			val = readl(PMU_POWER_CTRL);
			val |= PLL_I2S_PD;
			writel(val, PMU_POWER_CTRL);
		}
	}

	mutex_unlock(&opv5xc_i2s_mutex);
}

static void opv5xc_setup_mclk(struct opv5xc_i2s *i2s, int fs, int mclk, int div)
{
	u32 val;

	mutex_lock(&opv5xc_i2s_mutex);

	val = readl(PMU_SYS_CLK_CTRL);

	val &= ~DEV_VALUE(i2s, I2S0_FS_MASK, I2S1_FS_MASK);
	val |= fs << DEV_VALUE(i2s, I2S0_FS_SHIFT, I2S1_FS_SHIFT);

	val &= ~DEV_VALUE(i2s, I2S0_MCLK_MASK, I2S1_MCLK_MASK);
	val |= mclk << DEV_VALUE(i2s, I2S0_MCLK_SHIFT, I2S1_MCLK_SHIFT);

	val &= ~DEV_VALUE(i2s, I2S0_CLKDIV_MASK, I2S1_CLKDIV_MASK);
	val |= div << DEV_VALUE(i2s, I2S0_CLKDIV_SHIFT, I2S1_CLKDIV_SHIFT);

	writel(val, PMU_SYS_CLK_CTRL);

	mutex_unlock(&opv5xc_i2s_mutex);
}

static void opv5xc_setup_tx_data_shift(struct opv5xc_i2s *i2s, int shift)
{
	u32 val;

	mutex_lock(&opv5xc_i2s_mutex);

	val = readl(MISC_I2S_CFG);
	val &= ~DEV_VALUE(i2s, I2S0_TX_SFT_MASK, I2S1_TX_SFT_MASK);
	val |= shift << DEV_VALUE(i2s, I2S0_TX_SFT_SHIFT, I2S1_TX_SFT_SHIFT);
	writel(val, MISC_I2S_CFG);

	mutex_unlock(&opv5xc_i2s_mutex);
}

static void opv5xc_setup_rx_data_shift(struct opv5xc_i2s *i2s, int shift)
{
	u32 val;

	mutex_lock(&opv5xc_i2s_mutex);

	val = readl(MISC_I2S_CFG);
	val &= ~DEV_VALUE(i2s, I2S0_RX_SFT_MASK, I2S1_RX_SFT_MASK);
	val |= shift << DEV_VALUE(i2s, I2S0_RX_SFT_SHIFT, I2S1_RX_SFT_SHIFT);
	writel(val, MISC_I2S_CFG);

	mutex_unlock(&opv5xc_i2s_mutex);
}

static int opv5xc_i2s_dai_probe(struct snd_soc_dai *dai)
{
	struct opv5xc_i2s *i2s = dev_get_drvdata(dai->dev);

	dai->playback_dma_data = &i2s->playback_dma_data;
	dai->capture_dma_data = &i2s->capture_dma_data;

	return 0;
}

static int opv5xc_i2s_set_fmt(struct snd_soc_dai *dai, unsigned int fmt)
{
	struct opv5xc_i2s *i2s = dev_get_drvdata(dai->dev);

	/* bclk / fclk direction */
	switch (fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBS_CFS:
		/* codec is slave, opv5xc-i2s is master */
		i2s->ssc |= SSC_MSL;
		break;
	case SND_SOC_DAIFMT_CBM_CFM:
		/* codec is master, opv5xc-i2s is slave */
		i2s->ssc &= ~SSC_MSL;
		break;
	default:
		return -EINVAL;
	}

	/* bclk / fclk polarity */
	switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
	case SND_SOC_DAIFMT_NB_NF:
		/* sample at bclk falling edge, fclk active low */
		i2s->ssc |= (SSC_CLKP | SSC_FSP);
		break;
	case SND_SOC_DAIFMT_NB_IF:
		/* sample at bclk falling edge, fclk active high */
		i2s->ssc |= SSC_CLKP;
		i2s->ssc &= ~SSC_FSP;
		break;
	case SND_SOC_DAIFMT_IB_NF:
		/* sample at bclk rising edge, fclk active low */
		i2s->ssc &= ~(SSC_CLKP | SSC_FSP);
		break;
	case SND_SOC_DAIFMT_IB_IF:
		/* sample at bclk rising edge, fclk active high */
		i2s->ssc &= ~SSC_CLKP;
		i2s->ssc |= SSC_FSP;
		break;
	default:
		return -EINVAL;
	}

	/* format */
	switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
	case SND_SOC_DAIFMT_I2S:
		/* Currently driver just supports I2S, details configured in
		 * hw_params */
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int opv5xc_i2s_hw_params(struct snd_pcm_substream *substream,
				struct snd_pcm_hw_params *params,
				struct snd_soc_dai *dai)
{
	struct opv5xc_i2s *i2s = dev_get_drvdata(dai->dev);
	int fs, shift;

	/* Details on supported format:
	 * - 1 frame with 2 samples per period (2 channels)
	 * - field width for each sample is always 32 bclk ticks
	 *   - thus frame size is 64 bclk ticks
	 *   - thus bclk freq is 64*fs
	 * - fclk is active for 32 bclk ticks (i.e. 1/2 of period; actually
	 *   it is I2S channel select)
	 * - sample starts 1 bclk tick after fclk edge
	 * - sample is left-justified
	 */

	/* Details on clocking:
	 * - only internal mclk source is currently supported,
	 * - mclk is always configured to be 128*fs
	 * - to get 64*fs blck, 2x divider is configured
	 */

	i2s->ssc &= ~(SSC_FPER_MASK | SSC_FWID_MASK);
	i2s->dfc &= (DFC_PH | DFC_DATDLY_MASK | DFC_SF | DFC_JST |
		     DFC_SSZ1_MASK | DFC_WDLEN1_MASK | DFC_FRLEN1_MASK);

	switch (params_channels(params)) {
	case 2:
		i2s->ssc |= SSC_FPER(64);
		i2s->ssc |= SSC_FWID(32);
		i2s->dfc |= DFC_FRLEN1(2);
		i2s->dfc |= DFC_WDLEN1(DFC_32bit);
		i2s->dfc |= DFC_DATDLY_1;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S8:
		i2s->dfc |= DFC_SSZ1(DFC_8bit);
		shift = SFT_LEFT_24;
		break;
	case SNDRV_PCM_FORMAT_S16_LE:
		i2s->dfc |= DFC_SSZ1(DFC_16bit);
		shift = SFT_LEFT_16;
		break;
	case SNDRV_PCM_FORMAT_S24_LE:
		i2s->dfc |= DFC_SSZ1(DFC_24bit);
		shift = SFT_LEFT_8;
		break;
	case SNDRV_PCM_FORMAT_S32_LE:
		i2s->dfc |= DFC_SSZ1(DFC_32bit);
		shift = SFT_NONE;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		opv5xc_setup_tx_data_shift(i2s, shift);
	else
		opv5xc_setup_rx_data_shift(i2s, shift);

	switch (params_rate(params)) {
	case 8000:
		fs = FS_8000;
		break;
	case 11025:
		fs = FS_11025;
		break;
	case 16000:
		fs = FS_16000;
		break;
	case 22050:
		fs = FS_22050;
		break;
	case 32000:
		fs = FS_32000;
		break;
	case 44100:
		fs = FS_44100;
		break;
	case 48000:
		fs = FS_48000;
		break;
	case 88200:
		fs = FS_88200;
		break;
	case 96000:
		fs = FS_96000;
		break;
	case 176400:
		fs = FS_176400;
		break;
	case 192000:
		fs = FS_192000;
		break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}

	opv5xc_setup_mclk(i2s, fs, MCLK_128fs, CLKDIV_2);
	return 0;
}

static int opv5xc_i2s_trigger(struct snd_pcm_substream *substream, int cmd,
			      struct snd_soc_dai *dai)
{
	struct opv5xc_i2s *i2s = dev_get_drvdata(dai->dev);
	u32 val;
	int ret = 0;

	spin_lock(&i2s->lock);

	switch (cmd) {

	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:

		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {

			if (i2s->tx_running)
				break;

			writel(i2s->ssc, &i2s->regs->ssc);
			writel(i2s->dfc, &i2s->regs->dfc);

			writel(16, &i2s->regs->tx_lower_limit);

			val = readl(&i2s->regs->control);
			val &= ~(CTRL_TX_RST | CTRL_TX_FLUSH | CTRL_CLK_RST);
			val |= CTRL_TX_EN | CTRL_CLK_EN;
			writel(val, &i2s->regs->control);

			val = readl(&i2s->regs->interrupt);
			val |= REQUEST_TX_DMA;
			writel(val, &i2s->regs->interrupt);

			i2s->tx_running = true;

		} else {

			if (i2s->rx_running)
				break;

			writel(i2s->ssc, &i2s->regs->ssc);
			writel(i2s->dfc, &i2s->regs->dfc);

			writel(0, &i2s->regs->rx_upper_limit);

			val = readl(&i2s->regs->control);
			val &= ~(CTRL_RX_RST | CTRL_RX_FLUSH | CTRL_CLK_RST);
			val |= CTRL_RX_EN | CTRL_CLK_EN;
			writel(val, &i2s->regs->control);

			val = readl(&i2s->regs->interrupt);
			val |= REQUEST_RX_DMA;
			writel(val, &i2s->regs->interrupt);

			i2s->rx_running = true;
		}

		break;

	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:

		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {

			if (!i2s->tx_running)
				break;

			val = readl(&i2s->regs->interrupt);
			val &= ~REQUEST_TX_DMA;
			writel(val, &i2s->regs->interrupt);

			val = readl(&i2s->regs->control);
			val &= ~CTRL_TX_EN;
			val |= CTRL_TX_RST | CTRL_TX_FLUSH;
			if (!i2s->rx_running) {
				val &= ~CTRL_CLK_EN;
				val |= CTRL_CLK_RST;
			}
			writel(val, &i2s->regs->control);

			i2s->tx_running = false;

		} else {

			if (!i2s->rx_running)
				break;

			val = readl(&i2s->regs->interrupt);
			val &= ~REQUEST_RX_DMA;
			writel(val, &i2s->regs->interrupt);

			val = readl(&i2s->regs->control);
			val &= ~CTRL_RX_EN;
			val |= CTRL_RX_RST | CTRL_RX_FLUSH;
			if (!i2s->tx_running) {
				val &= ~CTRL_CLK_EN;
				val |= CTRL_CLK_RST;
			}
			writel(val, &i2s->regs->control);

			i2s->rx_running = false;
		}

		break;

	default:
		ret = -EINVAL;
	}

	spin_unlock(&i2s->lock);

	return ret;
}

static struct snd_soc_dai_ops opv5xc_i2s_dai_ops = {
	.set_fmt = opv5xc_i2s_set_fmt,
	.hw_params = opv5xc_i2s_hw_params,
	.trigger = opv5xc_i2s_trigger,
};

/* This is intersection of ALSA-supported rates and hw-supported rates */
#define OPV5XC_I2S_RATES	(SNDRV_PCM_RATE_8000 |		\
				 SNDRV_PCM_RATE_11025 |		\
				 SNDRV_PCM_RATE_16000 |		\
				 SNDRV_PCM_RATE_22050 |		\
				 SNDRV_PCM_RATE_32000 |		\
				 SNDRV_PCM_RATE_44100 |		\
				 SNDRV_PCM_RATE_48000 |		\
				 SNDRV_PCM_RATE_88200 |		\
				 SNDRV_PCM_RATE_96000 |		\
				 SNDRV_PCM_RATE_176400 |	\
				 SNDRV_PCM_RATE_192000)

static struct snd_soc_dai_driver opv5xc_i2s_dai_driver = {
	.probe = opv5xc_i2s_dai_probe,
	.playback = {
		.channels_min = 2,
		.channels_max = 2,
		.rates = OPV5XC_I2S_RATES,
		.formats = SNDRV_PCM_FMTBIT_S8 | SNDRV_PCM_FMTBIT_S16_LE |
			   SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE
	},
	.capture = {
		.channels_min = 2,
		.channels_max = 2,
		.rates = OPV5XC_I2S_RATES,
		.formats = SNDRV_PCM_FMTBIT_S8 | SNDRV_PCM_FMTBIT_S16_LE |
			   SNDRV_PCM_FMTBIT_S24_LE | SNDRV_PCM_FMTBIT_S32_LE
	},
	.symmetric_rates = 1,
	.ops = &opv5xc_i2s_dai_ops,
};

static const struct snd_soc_component_driver opv5xc_i2s_component = {
	.name		= DRV_NAME,
};

static int opv5xc_i2s_probe(struct platform_device *pdev)
{
	struct opv5xc_i2s *i2s;
	struct resource *res, *res_d;
	u32 val;
	int ret;

	if (pdev->id != 0 && pdev->id != 1) {
		dev_err(&pdev->dev, "unexpected dev id\n");
		return -EINVAL;
	}

	if (pdev->id == 0)
		ret = opv5xc_sharepin_request_array(gpios_i2s0,
						ARRAY_SIZE(gpios_i2s0));
	else
		ret = opv5xc_sharepin_request_array(gpios_i2s1,
						ARRAY_SIZE(gpios_i2s1));
	if (ret) {
		dev_err(&pdev->dev, "pins are busy\n");
		return -EBUSY;
	}

	i2s = devm_kzalloc(&pdev->dev, sizeof(*i2s), GFP_KERNEL);
	if (!i2s) {
		ret = -ENOMEM;
		goto err_alloc;
	}

	i2s->pdev = pdev;
	dev_set_drvdata(&pdev->dev, i2s);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	i2s->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(i2s->regs)) {
		ret = PTR_ERR(i2s->regs);
		goto err_remap;
	}

	res_d = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res_d) {
		dev_err(&pdev->dev, "data region not defined\n");
		ret = -EINVAL;
		goto err_data_get;
	}
	if (!devm_request_mem_region(&pdev->dev, res_d->start,
			resource_size(res_d), dev_name(&pdev->dev))) {
		dev_err(&pdev->dev, "could not request data region\n");
		ret = -EBUSY;
		goto err_data_request;
	}

	ret = opv5xc_i2s_enable_peri(i2s);
	if (ret)
		goto err_peri;
	opv5xc_i2s_set_mclk_master(i2s, true);

	val = readl(&i2s->regs->version);
	if (val != EXPECTED_VERSION) {
		dev_err(&pdev->dev,
			"hw version id register reads 0x%08x, expected 0x%08x\n",
			val, EXPECTED_VERSION);
		ret = -EIO;
		goto err_version;
	}

	spin_lock_init(&i2s->lock);

	/* reset/disable hw, to be sure */
	writel(CTRL_TX_RST | CTRL_TX_FLUSH | CTRL_RX_RST | CTRL_RX_FLUSH |
	       CTRL_CLK_RST, &i2s->regs->control);
	writel(0, &i2s->regs->interrupt);

	/* fetch hw defaults */
	i2s->ssc = readl(&i2s->regs->ssc);
	i2s->dfc = readl(&i2s->regs->dfc);

	i2s->playback_dma_data.addr =
		res_d->start + offsetof(struct opv5xc_i2s_regs, tx_data);
	i2s->playback_dma_data.maxburst = 1;
	i2s->playback_dma_data.filter_data =
		(void *) DEV_VALUE(i2s, DMACH_I2S0_TX, DMACH_I2S1_TX);

	i2s->capture_dma_data.addr =
		res_d->start + offsetof(struct opv5xc_i2s_regs, rx_data);
	i2s->capture_dma_data.maxburst = 1;
	i2s->capture_dma_data.filter_data =
		(void *) DEV_VALUE(i2s, DMACH_I2S0_RX, DMACH_I2S1_RX);

	ret = snd_soc_register_component(&pdev->dev, &opv5xc_i2s_component,
			&opv5xc_i2s_dai_driver, 1);
	if (ret) {
		dev_err(&pdev->dev, "could not register DAI\n");
		goto err_component;
	}

	ret = opv5xc_snd_pcm_register(&pdev->dev);
	if (ret) {
		dev_err(&pdev->dev, "cound not register PCM\n");
		goto err_pcm;
	}

	return 0;

err_pcm:
	snd_soc_unregister_component(&pdev->dev);
err_component:
err_version:
	opv5xc_i2s_set_mclk_master(i2s, false);
	opv5xc_i2s_disable_peri(i2s);
err_peri:
err_data_request:
err_data_get:
err_remap:
err_alloc:
	if (pdev->id == 0)
		opv5xc_sharepin_free_array(gpios_i2s0, ARRAY_SIZE(gpios_i2s0));
	else
		opv5xc_sharepin_free_array(gpios_i2s1, ARRAY_SIZE(gpios_i2s1));

	return ret;
}

static int opv5xc_i2s_remove(struct platform_device *pdev)
{
	struct opv5xc_i2s *i2s = dev_get_drvdata(&pdev->dev);

	/* disable/reset everything */
	writel(CTRL_TX_RST | CTRL_TX_FLUSH | CTRL_RX_RST | CTRL_RX_FLUSH |
	       CTRL_CLK_RST, &i2s->regs->control);
	writel(0, &i2s->regs->interrupt);

	opv5xc_snd_pcm_unregister(&pdev->dev);
	snd_soc_unregister_component(&pdev->dev);

	opv5xc_i2s_set_mclk_master(i2s, false);
	opv5xc_i2s_disable_peri(i2s);

	if (pdev->id == 0)
		opv5xc_sharepin_free_array(gpios_i2s0, ARRAY_SIZE(gpios_i2s0));
	else
		opv5xc_sharepin_free_array(gpios_i2s1, ARRAY_SIZE(gpios_i2s1));

	return 0;
}

static struct platform_driver opv5xc_i2s_driver = {
	.probe = opv5xc_i2s_probe,
	.remove = opv5xc_i2s_remove,
	.driver = {
		.name  = DRV_NAME,
		.owner = THIS_MODULE,
	},
};
module_platform_driver(opv5xc_i2s_driver);

MODULE_AUTHOR("Nikita Yushchenko <nyoushchenko@mvista.com>");
MODULE_DESCRIPTION("OPV5XC I2S ASoC driver");
MODULE_LICENSE("GPL");
