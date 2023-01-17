/*
 * Author: Open Silicon, Inc.
 * Contact: platform@open-silicon.com
 * This file is part of the Voledia SDK
 *
 * Copyright (c) 2012 Open-Silicon Inc.
 *
 * This file is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License, Version 2, as published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but AS-IS and WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE, TITLE, or NONINFRINGEMENT. See the GNU
 * General Public License for more details.
 *
 * This file may also be available under a different license from Open-Silicon.
 * Contact Open-Silicon for more information
 */

#include <mach/opv5xc.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/interrupt.h>

#include "core.h"

struct dwc3_opv5xc_data {
	int phy_type;
	int (*phy_init)(struct platform_device *pdev, int type);
	int (*phy_exit)(struct platform_device *pdev, int type);
};

struct dwc3_opv5xc {
	struct platform_device	*dwc3;
	struct device		*dev;
};

#ifdef CONFIG_PM
static int dwc3_opv5xc_suspend(struct platform_device *pdev) {
	return 0;
}

static int dwc3_opv5xc_resume(struct platform_device *pdev) {

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	u32			reg;
	struct completion dwc3_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;

	init_completion(&dwc3_complete);
	/* Power up PLL_REF, 1:Power down */
	reg = readl(OPV5XC_CR_PMU_BASE_VIRT + 0x18);
	if ((1 << 23) & reg)
		writel((reg & ~(1 << 23)), OPV5XC_CR_PMU_BASE_VIRT + 0x18);

	/* Disable clock before software reset */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT)        & ~(1 << 15)), OPV5XC_CR_PMU_BASE_VIRT);

	/* Software reset, low active */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 15)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) |  (1 << 15)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);

	/* Clock enable, high active */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT)        |  (1 << 15)), OPV5XC_CR_PMU_BASE_VIRT);

	do {
		wait_for_completion_timeout(&dwc3_complete, timeout);
		if ( readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<15) ) {
			val = 1;
			break;
		}
	} while ( counter-- != 0 );
	if ( ( counter == 0 ) && ( val == 0 ) ) {
		printk("\n: Timeout while enabling power for DWC3-USB \n");
		return -ENODEV;
	}

	/*
	 * Configure the uSOF window
	 *  0: 123.9us
	 * 32: 125.0us
	 */
	reg = readl(OPV5XC_MISC_BASE_VIRT + 0x800);
	reg &= 0xFFFFF81F;
	reg |= 32 << 5;
	writel(reg,        OPV5XC_MISC_BASE_VIRT + 0x800);
	writel(0x999EC000, OPV5XC_MISC_BASE_VIRT + 0x804);
	writel(0x18E40072, OPV5XC_MISC_BASE_VIRT + 0x808);
#endif
	return 0;
}
#endif

static int dwc3_opv5xc_probe(struct platform_device *pdev)
{
	struct dwc3_opv5xc_data	*pdata = pdev->dev.platform_data;
	struct platform_device	*dwc3;
	struct dwc3_opv5xc	*opv5xc;

	int ret;
	struct completion dwc3_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	u32			reg;
	
	init_completion(&dwc3_complete);

	/* Power up PLL_REF, 1:Power down */
	reg = readl(OPV5XC_CR_PMU_BASE_VIRT + 0x18);
	if ((1 << 23) & reg)
		writel((reg & ~(1 << 23)), OPV5XC_CR_PMU_BASE_VIRT + 0x18);


	/* Disable clock before software reset */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT)        & ~(1 << 15)), OPV5XC_CR_PMU_BASE_VIRT);

	/* Software reset, low active */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 15)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) |  (1 << 15)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);

	/* Clock enable, high active */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT)        |  (1 << 15)), OPV5XC_CR_PMU_BASE_VIRT);
	do {
		wait_for_completion_timeout(&dwc3_complete, timeout);
		if ( readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<15) ) {
			val = 1;
			break;
		}
	} while ( counter-- != 0 );
	if ( ( counter == 0 ) && ( val == 0 ) ) {
		printk("\n: Timeout while enabling power for DWC3-USB \n");
		return -ENODEV;
	}

	/*
	 * Configure the uSOF window
	 *  0: 123.9us
	 * 32: 125.0us
	 */
	reg = readl(OPV5XC_MISC_BASE_VIRT + 0x800);
	reg &= 0xFFFFF81F;
	reg |= 32 << 5;
	writel(reg,        OPV5XC_MISC_BASE_VIRT + 0x800);
	writel(0x999EC000, OPV5XC_MISC_BASE_VIRT + 0x804);
	writel(0x18E40072, OPV5XC_MISC_BASE_VIRT + 0x808);
#endif

	opv5xc = kzalloc(sizeof(*opv5xc), GFP_KERNEL);
	if (!opv5xc) {
		dev_err(&pdev->dev, "not enough memory\n");
		goto err0;
	}


	platform_set_drvdata(pdev, opv5xc);


	dwc3 = platform_device_alloc("dwc3", PLATFORM_DEVID_AUTO);
	if (!dwc3) {
		dev_err(&pdev->dev, "couldn't allocate dwc3 device\n");
		goto err1;
	}

	dma_set_coherent_mask(&dwc3->dev, pdev->dev.coherent_dma_mask);

	dwc3->dev.parent = &pdev->dev;
	dwc3->dev.dma_mask = pdev->dev.dma_mask;
	dwc3->dev.dma_parms = pdev->dev.dma_parms;

#ifdef CONFIG_USB_OPV5XC_ACP
	dwc3->dev.archdata.dma_ops = pdev->dev.archdata.dma_ops;
#endif

	opv5xc->dwc3	= dwc3;
	opv5xc->dev	= &pdev->dev;

	/* PHY initialization */
	if (!pdata) {
		dev_dbg(&pdev->dev, "missing platform data\n");
	} else {
		if (pdata->phy_init)
			pdata->phy_init(pdev, pdata->phy_type);
	}

	ret = platform_device_add_resources(dwc3, pdev->resource,
			pdev->num_resources);
	if (ret) {
		dev_err(&pdev->dev, "couldn't add resources to dwc3 device\n");
		goto err3;
	}

	ret = platform_device_add(dwc3);
	if (ret) {
		dev_err(&pdev->dev, "failed to register dwc3 device\n");
		goto err3;
	}

	return 0;

err3:
	if (pdata && pdata->phy_exit)
		pdata->phy_exit(pdev, pdata->phy_type);

	platform_device_put(dwc3);
err1:
	kfree(opv5xc);
err0:
	return ret;
}

static int dwc3_opv5xc_remove(struct platform_device *pdev)
{
	struct dwc3_opv5xc	*opv5xc = platform_get_drvdata(pdev);
	struct dwc3_opv5xc_data *pdata = pdev->dev.platform_data;

	platform_device_del(opv5xc->dwc3);

	if (pdata && pdata->phy_exit)
		pdata->phy_exit(pdev, pdata->phy_type);

	kfree(opv5xc);

	return 0;
}

static struct platform_driver dwc3_opv5xc_driver = {
	.probe		= dwc3_opv5xc_probe,
	.remove		= dwc3_opv5xc_remove,
	.driver		= {
		.name	= "dwc3-opv5xc",
	},
#ifdef CONFIG_PM
	.suspend	= dwc3_opv5xc_suspend,
	.resume		= dwc3_opv5xc_resume,
#endif
};

module_platform_driver(dwc3_opv5xc_driver);

MODULE_ALIAS("platform:opv5xc-dwc3");
MODULE_AUTHOR("Tommy Lin <tommy.lin@open-silicon.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DesignWare USB3 OPV5XC Glue Layer");
