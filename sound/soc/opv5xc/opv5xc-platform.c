/*
 * OPV5XC ASoC platform driver
 *
 * Author: Nikita Yushchenko <nyoushchenko@mvista.com>
 *
 * 2010 (c) MontaVista Software, LLC. This file is licensed under
 * the terms of the GNU General Public License version 2. This program
 * is licensed "as is" without any warranty of any kind, whether express
 * or implied.
 */

#include <linux/module.h>
#include <sound/dmaengine_pcm.h>
#include <linux/amba/pl330.h>
#include "opv5xc-platform.h"

static const struct snd_pcm_hardware opv5xc_snd_hardware = {
	.info = SNDRV_PCM_INFO_MMAP |
		SNDRV_PCM_INFO_MMAP_VALID |
		SNDRV_PCM_INFO_PAUSE |
		SNDRV_PCM_INFO_RESUME |
		SNDRV_PCM_INFO_INTERLEAVED,
	.formats = SNDRV_PCM_FMTBIT_S8 |
		   SNDRV_PCM_FMTBIT_S16_LE |
		   SNDRV_PCM_FMTBIT_S24_LE |
		   SNDRV_PCM_FMTBIT_S32_LE,
	.channels_min = 2,
	.channels_max = 2,
	.period_bytes_min = 32,
	.period_bytes_max = 32 * 1024,
	.periods_min = 1,
	.periods_max = 32,
	.buffer_bytes_max = 128 * 1024,
};

bool opv5xc_snd_dma_filter(struct dma_chan *chan, void *data)
{
	struct snd_dmaengine_dai_dma_data *dma_data = data;

	return pl330_filter(chan, dma_data->filter_data);
}

static const struct snd_dmaengine_pcm_config opv5xc_dmaengine_pcm_config = {
	.prepare_slave_config = snd_dmaengine_pcm_prepare_slave_config,
	.compat_filter_fn = opv5xc_snd_dma_filter,
	.pcm_hardware = &opv5xc_snd_hardware,
	.prealloc_buffer_size = 128 * 1024,
};

int opv5xc_snd_pcm_register(struct device *dev)
{
	return snd_dmaengine_pcm_register(dev, &opv5xc_dmaengine_pcm_config,
		SND_DMAENGINE_PCM_FLAG_NO_RESIDUE |
		SND_DMAENGINE_PCM_FLAG_NO_DT |
		SND_DMAENGINE_PCM_FLAG_COMPAT);
}
EXPORT_SYMBOL(opv5xc_snd_pcm_register);

void opv5xc_snd_pcm_unregister(struct device *dev)
{
	snd_dmaengine_pcm_unregister(dev);
}
EXPORT_SYMBOL_GPL(opv5xc_snd_pcm_unregister);

MODULE_AUTHOR("Nikita Yushchenko <nyoushchenko@mvista.com>");
MODULE_DESCRIPTION("OPV5XC audio platform driver");
MODULE_LICENSE("GPL");
