/*
 * OPV5XC TLV320AIC23 ASoC machine driver
 *
 * Author: Nikita Yushchenko <nyoushchenko@mvista.com>
 *
 * 2010 (c) MontaVista Software, LLC. This file is licensed under
 * the terms of the GNU General Public License version 2. This program
 * is licensed "as is" without any warranty of any kind, whether express
 * or implied.
 */

#include <linux/module.h>
#include <sound/soc.h>

#define CODEC_CLOCK	12288000
#define AUDIO_FORMAT \
	(SND_SOC_DAIFMT_I2S | SND_SOC_DAIFMT_NB_NF | SND_SOC_DAIFMT_CBS_CFS)

static int opv5xc_tlv320aic23_init(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	int ret;

	ret = snd_soc_dai_set_sysclk(codec_dai, 0,
			CODEC_CLOCK, SND_SOC_CLOCK_IN);
	if (ret) {
		dev_err(rtd->dev, "can't set codec system clock\n");
		return ret;
	}

	ret = snd_soc_dai_set_fmt(codec_dai, AUDIO_FORMAT);
	if (ret) {
		dev_err(rtd->dev, "can't set codec dai format\n");
		return ret;
	}

	ret = snd_soc_dai_set_fmt(cpu_dai, AUDIO_FORMAT);
	if (ret < 0) {
		dev_err(rtd->dev, "can't set cpu dai format\n");
		return ret;
	}

	return 0;
}

static const struct snd_soc_dapm_widget tlv320aic23_dapm_widgets[] = {
	SND_SOC_DAPM_HP("Headphone Jack", NULL),
	SND_SOC_DAPM_MIC("Mic Jack", NULL),
};

static const struct snd_soc_dapm_route audio_map[] = {
	{"Headphone Jack", NULL, "LHPOUT"},
	{"Headphone Jack", NULL, "RHPOUT"},
	{"MICIN", NULL, "Mic Jack"},
};

static struct snd_soc_dai_link opv5xc_tlv320aic23_dai = {
	.name = "TLV320AIC23",
	.stream_name = "AIC23",
	.codec_name = "tlv320aic23-codec.0-001a",
	.codec_dai_name = "tlv320aic23-hifi",
	.cpu_dai_name = "opv5xc-i2s.0",
	.platform_name = "opv5xc-i2s.0",
	.init = opv5xc_tlv320aic23_init,
};

static struct snd_soc_card snd_soc_opv5xc_tlv320aic23 = {
	.name = "opv5xc-tlv320aic23",
	.owner = THIS_MODULE,
	.dai_link = &opv5xc_tlv320aic23_dai,
	.num_links = 1,
	.dapm_widgets = tlv320aic23_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(tlv320aic23_dapm_widgets),
	.dapm_routes = audio_map,
	.num_dapm_routes = ARRAY_SIZE(audio_map),
};

static int opv5xc_tlv320aic23_probe(struct platform_device *pdev)
{
	struct snd_soc_card *card = &snd_soc_opv5xc_tlv320aic23;
	int ret;

	card->dev = &pdev->dev;
	platform_set_drvdata(pdev, card);

	ret = snd_soc_register_card(card);
	if (ret) {
		dev_err(&pdev->dev, "snd_soc_register_card failed (%d)\n",
			ret);
		goto err_out;
	}

	return 0;

err_out:
	return ret;
}

static int opv5xc_tlv320aic23_remove(struct platform_device *pdev)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);

	snd_soc_unregister_card(card);

	return 0;
}

static struct platform_driver opv5xc_tlv320aic23_driver = {
	.driver = {
		.owner = THIS_MODULE,
		.name = "opv5xc-tlv320aic23"
	},
	.probe = opv5xc_tlv320aic23_probe,
	.remove = opv5xc_tlv320aic23_remove,
};

module_platform_driver(opv5xc_tlv320aic23_driver);

MODULE_AUTHOR("Nikita Yushchenko <nyoushchenko@mvista.com>");
MODULE_DESCRIPTION("OPV5XC TLV320AIC23 ASoC driver");
MODULE_LICENSE("GPL");
