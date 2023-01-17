#ifndef OPV5XC_SND_PLATFORM_H
#define OPV5XC_SND_PLATFORM_H

struct device;

extern int opv5xc_snd_pcm_register(struct device *dev);
extern void opv5xc_snd_pcm_unregister(struct device *dev);

#endif
