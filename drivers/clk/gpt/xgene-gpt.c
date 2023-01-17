/*
 * APM X-Gene SoC General Purpose Timer Driver
 *
 * Copyright (c) 2015, Applied Micro Circuits Corporation
 * Author: Balamurugan Shanmugam <bshanmugam@apm.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_irq.h> 
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/* GPT CSR Registers */
#define CTLBASE_CNTFRQ		0x0	/* Counter Frequency Register 			*/
#define CTLBASE_CNTTIDR		0x8     /* Counter Timer ID Register  			*/
#define CTLBASE_COUNTERID	0xFD    /* Counter ID Register        			*/
#define CNTP_CTLL		0x0     /* Physical Count Register Low 			*/
#define CNTP_CTH		0x4     /* Physical Count Register High 		*/
#define CNTP_FRQ		0x10    /* Counter Frequency Register   		*/
#define CNTP_CVALL		0x20    /* Physcial Timer Compare Value Register Low 	*/
#define	CNTP_CVALH		0x24    /* Physical Timer Compare Value Register High 	*/
#define CNTP_TVAL		0x28    /* Physical Timer Value Register 		*/
#define CNTP_CTL		0x2C    /* Physical Timer Control Register 		*/
#define COUNTERID		0xFD0   /* Counter ID Registers 			*/
#define TOTAL_GPT		4
#define DIVIDER         	1000000000

static int count = 0;
static int interrupt_count = 0;

/* GPT Data Structure */
struct xgene_gpt_dev {
        struct device *dev;
        struct resource *res;
        struct clk *clk;
        void __iomem *csr_base;
        void __iomem *csr_gpt;
        unsigned int irq;
        spinlock_t lock;
};

struct xgene_gpt_dev gpt[TOTAL_GPT];
EXPORT_SYMBOL(gpt);

static irqreturn_t xgene_gpt_interrupt(int irq, void *id)
{
	struct xgene_gpt_dev *pdata = (struct xgene_gpt_dev *) id;

	/* Masking timer output signal */
	writel(0x2, pdata->csr_gpt + CNTP_CTL);
	interrupt_count++;
        
	return IRQ_HANDLED;
}

static u64 xgene_gpt_ns2clocks(struct xgene_gpt_dev *gpt, u64 periodns)
{
        u64 clocks;
        u32 freq;

        /* 
	 * Determine the number of clocks in the requested period. Period 
         * is in nanosecond. Bus frequency is in Hz.
         * clocks = (period/1,000,000,000)*frequency 
         */
        freq   = readl(gpt->csr_base + CTLBASE_CNTFRQ);
        clocks = periodns * freq;
        clocks = div64_u64(clocks, DIVIDER);

        return clocks;
}

int xgene_gpt_start_timer(struct xgene_gpt_dev *gpt, u64 period, int continuous)
{
        unsigned long flags;
        u64 clocks;

        BUG_ON(!gpt);
	
        /* Do not support continuous running mode*/
        if (unlikely(continuous))
                return -EINVAL;

        clocks = xgene_gpt_ns2clocks(gpt, period);
        spin_lock_irqsave(&gpt->lock, flags);

        /* Load physical timer compare value */
	writel((unsigned int) clocks, gpt->csr_gpt + CNTP_CVALL); 
	writel(clocks >> 32, gpt->csr_gpt + CNTP_CVALH); 
	
	/* Enable timer */
	writel(0x1, gpt->csr_gpt + CNTP_CTL);

	if (interrupt_count == TOTAL_GPT)
		pr_info("Total Number of GPT passed :%d\n", interrupt_count);

        spin_unlock_irqrestore(&gpt->lock, flags);

        return 0;
}
EXPORT_SYMBOL(xgene_gpt_start_timer);

static int xgene_gpt_probe(struct platform_device *pdev)
{
	struct xgene_gpt_dev *pdata;
	struct resource *res;
	int ret;
        int irq;
	
	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
        if (!pdata)
                return -ENOMEM;
        
        platform_set_drvdata(pdev, pdata);
        
	pdata->dev = &pdev->dev;

        res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
        pdata->csr_gpt = devm_ioremap_resource(&pdev->dev, res);
        if (!pdata->csr_gpt)
                return -ENOMEM;
       
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
        pdata->csr_base = devm_ioremap(&pdev->dev, res->start, resource_size(res));
        if (!pdata->csr_base)
                return -ENOMEM;
 
	irq = platform_get_irq(pdev, 0);
        if (irq <= 0) {
                dev_err(&pdev->dev, "No IRQ resource\n");
                return irq;
        }

	pdata->irq = irq;

	/* Register IRQ for GPT Timer */
        ret = devm_request_irq(&pdev->dev, irq, xgene_gpt_interrupt, 0,
                               dev_name(&pdev->dev), pdata);
        if (ret) {
                dev_err(&pdev->dev, "Could not request IRQ\n");
                return ret;
        }

	pdata->clk = devm_clk_get(&pdev->dev, NULL);
        if (IS_ERR(pdata->clk)) {
                dev_err(&pdev->dev, "Couldn't get the clock for GPT\n");
                return -ENODEV;
        }

	/* Enable Clock before accessing GPT Registers */
        ret = clk_prepare_enable(pdata->clk);
        if (ret) {
        	dev_err(&pdev->dev, "Failed to enable clk error:%d\n", ret);
		return -ENODEV;
        }
	
	/* Configure Counter Frequency Register */
	writel(clk_get_rate(pdata->clk), pdata->csr_base + CTLBASE_CNTFRQ);
	gpt[count] = *pdata;
	count++;
	
        return 0;
}

static int xgene_gpt_remove(struct platform_device *pdev)
{
	struct xgene_gpt_dev *pdata = platform_get_drvdata(pdev);
	
	devm_free_irq(pdata->dev, pdata->irq, pdata);

	return 0;
}

static const struct of_device_id xgene_gpt_of_match[] = {
        {.compatible = "apm,xgene-gpt" },
        { }
};

static struct platform_driver xgene_gpt_driver = {
        .probe          = xgene_gpt_probe,
        .remove         = xgene_gpt_remove,
        .driver         = {
                .name   = "xgene-gpt",
                .of_match_table = xgene_gpt_of_match,
        },
};
module_platform_driver(xgene_gpt_driver);

MODULE_DESCRIPTION("XGENE General Purpose Timer");
MODULE_AUTHOR("Balamurugan Shanmugam <bshanmugam@apm.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
