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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/delay.h>
#include <linux/mmc/host.h>
#include <linux/io.h>
#include <mach/memory.h>
#include <mach/io_map.h>
#include "sdhci.h"

#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_gpio.h>
#include <linux/of_net.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#endif /* CONFIG_OF */

#include <mach/iproc_regs.h>

#define DRIVER_NAME                 "iproc_sdhci"
#define SDHCI_MAX_DIV_SPEC_300      2046
#define SDHCI_DIVIDER_SHIFT         8
#define SDHCI_DIVIDER_HI_SHIFT      6
#define SDHCI_DIV_MASK              0xFF
#define SDHCI_DIV_MASK_LEN          8
#define SDHCI_DIV_HI_MASK           0x300
#define SDHCI_CLOCK_V3_BASE_MASK    0x0000FF00

struct sdhci_platform_data {
    struct sdhci_host *host;
    struct clk *clk;
    unsigned host_num;
};

struct iproc_sdhci_host {
    struct sdhci_host host;
    u32 shadow_cmd;
    u32 shadow_blk;
};

static inline void
iproc_sdhci_raw_writel(struct sdhci_host *host, u32 val, int reg)
{
    writel(val, host->ioaddr + reg);
}

static inline u32
iproc_sdhci_raw_readl(struct sdhci_host *host, int reg)
{
    return readl(host->ioaddr + reg);
}

static void
iproc_sdhci_writel(struct sdhci_host *host, u32 val, int reg)
{
    iproc_sdhci_raw_writel(host, val, reg);
}

static void
iproc_sdhci_writew(struct sdhci_host *host, u16 val, int reg)
{
    struct iproc_sdhci_host *iproc_host = (struct iproc_sdhci_host *)host;
    u32 oldval, newval;
    u32 word_num = (reg >> 1) & 1;
    u32 word_shift = word_num * 16;
    u32 mask = 0xffff << word_shift;

    if (reg == SDHCI_COMMAND) {
        if (iproc_host->shadow_blk != 0) {
            iproc_sdhci_raw_writel(host, iproc_host->shadow_blk, SDHCI_BLOCK_SIZE);
            iproc_host->shadow_blk = 0;
        }
        oldval = iproc_host->shadow_cmd;
    } else if (reg == SDHCI_BLOCK_SIZE || reg == SDHCI_BLOCK_COUNT) {
        oldval = iproc_host->shadow_blk;
    } else {
        oldval = iproc_sdhci_raw_readl(host, reg & ~3);
    }
    newval = (oldval & ~mask) | (val << word_shift);

    if (reg == SDHCI_TRANSFER_MODE) {
        iproc_host->shadow_cmd = newval;
    } else if (reg == SDHCI_BLOCK_SIZE || reg == SDHCI_BLOCK_COUNT) {
        iproc_host->shadow_blk = newval;
    } else {
        iproc_sdhci_raw_writel(host, newval, reg & ~3);
    }
}

static void
iproc_sdhci_writeb(struct sdhci_host *host, u8 val, int reg)
{
    u32 oldval, newval;
    u32 byte_num = reg & 3;
    u32 byte_shift = byte_num * 8;
    u32 mask = 0xff << byte_shift;

    oldval = iproc_sdhci_raw_readl(host, reg & ~3);
    newval = (oldval & ~mask) | (val << byte_shift);

    iproc_sdhci_raw_writel(host, newval, reg & ~3);
}

static u32
iproc_sdhci_readl(struct sdhci_host *host, int reg)
{
    return iproc_sdhci_raw_readl(host, reg);
}

static u16
iproc_sdhci_readw(struct sdhci_host *host, int reg)
{
    u32 val;
    u32 word_num = (reg >> 1) & 1;
    u32 word_shift = word_num * 16;

    val = iproc_sdhci_raw_readl(host, (reg & ~3));
    return (val >> word_shift) & 0xffff;
}

static u8
iproc_sdhci_readb(struct sdhci_host *host, int reg)
{
    u32 val;
    u32 byte_num = reg & 3;
    u32 byte_shift = byte_num * 8;

    val = iproc_sdhci_raw_readl(host, (reg & ~3));
    return (val >> byte_shift) & 0xff;
}

static void
iproc_sdhci_set_clock(struct sdhci_host *host, unsigned int clock)
{
    int div;
    u16 clk;
    unsigned long timeout;

    sdhci_writew(host, 0, SDHCI_CLOCK_CONTROL);

    if (clock == 0) {
        return;
    }

    if(clock > 100000000){
        printk(KERN_INFO "%s :could work @ max 100MHz down the clock %d to 100MHz\n",
               mmc_hostname(host->mmc), clock);
        clock = 100000000;
    }

    /* Version 3.00 divisors must be a multiple of 2. */
    if (host->max_clk <= clock) {
        div = 1;
    } else {
        for (div = 2; div < SDHCI_MAX_DIV_SPEC_300; div += 2) {
            if ((host->max_clk / div) <= clock)
                break;
        }
    }

    div >>= 1;

    clk = (div & SDHCI_DIV_MASK) << SDHCI_DIVIDER_SHIFT;
    clk |= ((div & SDHCI_DIV_HI_MASK) >> SDHCI_DIV_MASK_LEN)
        << SDHCI_DIVIDER_HI_SHIFT;

    clk |= SDHCI_CLOCK_INT_EN;
    sdhci_writew(host, clk, SDHCI_CLOCK_CONTROL);

    /* Wait max 20 ms */
    timeout = 20;
    while (!((clk = sdhci_readw(host, SDHCI_CLOCK_CONTROL))
        & SDHCI_CLOCK_INT_STABLE)) {
        if (timeout == 0) {
            printk(KERN_ERR "%s: Internal clock never "
                "stabilised.\n", mmc_hostname(host->mmc));
            return;
        }
        timeout--;
        mdelay(1);
    }

    clk |= SDHCI_CLOCK_CARD_EN;
    sdhci_writew(host, clk, SDHCI_CLOCK_CONTROL);
}

/*
 * Get the base clock
 */
unsigned int
iproc_sdhci_get_max_clock(struct sdhci_host *host)
{
    unsigned long max_clock;

    max_clock = (host->caps & SDHCI_CLOCK_V3_BASE_MASK)
                >> SDHCI_CLOCK_BASE_SHIFT;
    max_clock *= 1000000;

    return max_clock;
}

unsigned int
iproc_sdhci_get_min_clock(struct sdhci_host *host)
{
    return (host->max_clk / SDHCI_MAX_DIV_SPEC_300);
}

static struct sdhci_ops sdhci_platform_ops = {
#ifdef CONFIG_MMC_SDHCI_IO_ACCESSORS
    .write_l = iproc_sdhci_writel,
    .write_w = iproc_sdhci_writew,
    .write_b = iproc_sdhci_writeb,
    .read_l = iproc_sdhci_readl,
    .read_w = iproc_sdhci_readw,
    .read_b = iproc_sdhci_readb,
#else
#error The iproc SDHCI driver needs CONFIG_MMC_SDHCI_IO_ACCESSORS to be set
#endif
    .enable_dma = NULL,
    .set_clock = iproc_sdhci_set_clock,
    .get_max_clock = iproc_sdhci_get_max_clock,
    .get_min_clock = iproc_sdhci_get_min_clock,
};

static int
sdhci_platform_probe(struct platform_device *pdev)
{
    struct sdhci_host *host;
    struct sdhci_platform_data *data;
    int ret = 0;
    int irq;
#ifdef CONFIG_OF
    struct device_node *np = pdev->dev.of_node;
#else
    struct resource *res;
#endif /* CONFIG_OF */

#ifdef CONFIG_OF
	irq = (unsigned int)irq_of_parse_and_map(np, 0);
#else
    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    irq = platform_get_irq(pdev, 0);
    if (res == NULL || irq < 0) {
        printk(KERN_ERR "SDIO%d: Unable to get platform resource or IRQ\n",
          pdev->id);
        return -ENXIO;
    }

    res = request_mem_region(res->start, res->end - res->start + 1, pdev->name);
    if (res == NULL) {
        printk(KERN_ERR "SDIO%d: request_mem_region failed\n", pdev->id);
        return -EBUSY;
    }
#endif /* CONFIG_OF */

    /* allocate SDHCI host + platform data memory */
    host = sdhci_alloc_host(&pdev->dev, sizeof(struct sdhci_platform_data));
    if (IS_ERR(host)) {
        ret = PTR_ERR(host);
        printk(KERN_ERR "SDIO%d: Unable to allocate SDHCI host\n", pdev->id);
        goto err_free_mem_region;
    }

    /* set up data structure */
    data = sdhci_priv(host);
    data->host = host;
    data->host_num = pdev->id;
    host->hw_name = "IPROC-SDIO";
    host->quirks = SDHCI_QUIRK_DATA_TIMEOUT_USES_SDCLK |
                   SDHCI_QUIRK_MULTIBLOCK_READ_ACMD12;
    host->ops = &sdhci_platform_ops;
    host->irq = irq;
    /* Setting for 8 bit mode support */
    host->mmc->caps = MMC_CAP_8_BIT_DATA;
    host->mmc->ios.drv_type = MMC_SET_DRIVER_TYPE_A;

#ifdef CONFIG_OF
    host->ioaddr = (void *)of_iomap(np, 0);
#else
    host->ioaddr = ioremap_nocache(res->start, (res->end - res->start) + 1);
#endif /* CONFIG_OF */
    if (!host->ioaddr) {
        printk(KERN_ERR "SDIO%d: Unable to iomap SDIO registers\n", pdev->id);
        ret = -ENXIO;
        goto err_free_host;
    }

    platform_set_drvdata(pdev, data);

    ret = sdhci_add_host(host);
    if (ret) {
        printk(KERN_ERR "SDIO%d: Failed to add SDHCI host\n", pdev->id);
        goto err_iounmap;
    }

    return ret;

err_iounmap:
    iounmap(host->ioaddr);

err_free_host:
    sdhci_free_host(host);

err_free_mem_region:
#ifndef CONFIG_OF
    release_mem_region(res->start, res->end - res->start + 1);
#endif /* !CONFIG_OF */

    return ret;
}

static int __exit
sdhci_platform_remove(struct platform_device *pdev)
{
    struct sdhci_platform_data *data = platform_get_drvdata(pdev);
    struct sdhci_host *host = data->host;

    sdhci_remove_host(host, 0);
    platform_set_drvdata(pdev, NULL);
    iounmap(host->ioaddr);
    sdhci_free_host(host);
    release_mem_region(pdev->resource[0].start,
                       pdev->resource[0].end - pdev->resource[0].start + 1);
    return 0;
}

#ifdef CONFIG_PM
static int
sdhci_platform_suspend(struct platform_device *pdev, pm_message_t state)
{
   int ret=0;
   struct sdhci_platform_data *data = platform_get_drvdata(pdev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
   ret = sdhci_suspend_host(data->host);
#else
   ret = sdhci_suspend_host(data->host, state);
#endif
   if (ret < 0) {
        printk("%s: %d\n", __FILE__, __LINE__);
      return ret;
   }

   return 0;
}

static int
sdhci_platform_resume(struct platform_device *pdev)
{
    int ret =0;
    struct sdhci_platform_data *data = platform_get_drvdata(pdev);

    ret = sdhci_resume_host(data->host);
    if (ret < 0) {
        printk("%s: %d\n", __FILE__, __LINE__);
        return ret;
    }
    return 0;
}
#else /* CONFIG_PM */
#define sdhci_platform_suspend NULL
#define sdhci_platform_resume NULL
#endif /* CONFIG_PM */


#ifdef CONFIG_OF
static const struct of_device_id brcm_iproc_dt_ids[] = {
	{ .compatible = "brcm,iproc-sdio"},
	{ }
};
MODULE_DEVICE_TABLE(of, brcm_iproc_dt_ids);

static struct platform_driver sdhci_platform_driver = {
    .probe = sdhci_platform_probe,
    .remove = __exit_p(sdhci_platform_remove),
    .suspend = sdhci_platform_suspend,
    .resume = sdhci_platform_resume,
    .driver = {
        .name = "iproc-sdio",
        .owner = THIS_MODULE,
		.of_match_table = of_match_ptr(brcm_iproc_dt_ids),
    },
};
#else
static struct platform_driver sdhci_platform_driver = {
    .probe = sdhci_platform_probe,
    .remove = __exit_p(sdhci_platform_remove),
    .suspend = sdhci_platform_suspend,
    .resume = sdhci_platform_resume,
    .driver = {
        .name = "iproc_sdio",
        .owner = THIS_MODULE,
    },
};

static struct resource sdio_resources[] = {
    [0] = {
        .start      = IPROC_SDIO0_REG_BASE,
        .end        = IPROC_SDIO0_REG_BASE + SZ_4K - 1,
        .flags      = IORESOURCE_MEM,
    },
    [1] = {
        .start      = BCM_INT_ID_SDIO2CORE,
        .end        = BCM_INT_ID_SDIO2CORE,
        .flags      = IORESOURCE_IRQ,
    }
};

static struct platform_device board_sdio_device = {
    .name           = "iproc_sdio",
    .id             = 0,
    .resource       = sdio_resources,
    .num_resources  = ARRAY_SIZE(sdio_resources),
};

static int __init sdhci_platform_init(void)
{
    int ret;
    struct platform_device *board_devices[] = {
        &board_sdio_device,
    };

    platform_add_devices(board_devices, ARRAY_SIZE(board_devices));

    ret = platform_driver_register(&sdhci_platform_driver);
    if (ret) {
        printk(KERN_ERR DRIVER_NAME
            ": Unable to register the SDHCI Platform driver\n");
        return ret;
    }

    return 0;
}

static void __exit sdhci_platform_exit(void)
{
    platform_driver_unregister(&sdhci_platform_driver);
}
#endif /* CONFIG_OF */


#ifdef CONFIG_OF
module_platform_driver(sdhci_platform_driver);
#else
module_init(sdhci_platform_init);
module_exit(sdhci_platform_exit);
#endif /* CONFIG_OF */

MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("SDHCI Platform driver");
MODULE_LICENSE("GPL");
