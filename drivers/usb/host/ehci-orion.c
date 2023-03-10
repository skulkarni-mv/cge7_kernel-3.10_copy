/*
 * drivers/usb/host/ehci-orion.c
 *
 * Tzachi Perelstein <tzachi@marvell.com>
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/mbus.h>
#include <linux/clk.h>
#include <linux/platform_data/usb-ehci-orion.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/usb.h>
#include <linux/usb/hcd.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>

#include "ehci.h"

#define rdl(off)	readl_relaxed(hcd->regs + (off))
#define wrl(off, val)	writel_relaxed((val), hcd->regs + (off))

#define USB_CMD			0x140
#define USB_MODE		0x1a8
#define USB_CAUSE		0x310
#define USB_MASK		0x314
#define USB_WINDOW_CTRL(i)	(0x320 + ((i) << 4))
#define USB_WINDOW_BASE(i)	(0x324 + ((i) << 4))
#define USB_IPG			0x360
#define USB_PHY_PWR_CTRL	0x400
#define USB_PHY_TX_CTRL		0x420
#define USB_PHY_RX_CTRL		0x430
#define USB_PHY_IVREF_CTRL	0x440
#define USB_PHY_TST_GRP_CTRL	0x450

#define DRIVER_DESC "EHCI orion driver"

static const char hcd_name[] = "ehci-orion";

static struct hc_driver __read_mostly ehci_orion_hc_driver;

static u32 usb_save[(USB_IPG - USB_CAUSE) + (USB_PHY_TST_GRP_CTRL - USB_PHY_PWR_CTRL)];

/*
 * Implement Orion USB controller specification guidelines
 */
static void orion_usb_phy_v1_setup(struct usb_hcd *hcd)
{
	/* The below GLs are according to the Orion Errata document */
	/*
	 * Clear interrupt cause and mask
	 */
	wrl(USB_CAUSE, 0);
	wrl(USB_MASK, 0);

	/*
	 * Reset controller
	 */
	wrl(USB_CMD, rdl(USB_CMD) | 0x2);
	while (rdl(USB_CMD) & 0x2);

	/*
	 * GL# USB-10: Set IPG for non start of frame packets
	 * Bits[14:8]=0xc
	 */
	wrl(USB_IPG, (rdl(USB_IPG) & ~0x7f00) | 0xc00);

	/*
	 * GL# USB-9: USB 2.0 Power Control
	 * BG_VSEL[7:6]=0x1
	 */
	wrl(USB_PHY_PWR_CTRL, (rdl(USB_PHY_PWR_CTRL) & ~0xc0)| 0x40);

	/*
	 * GL# USB-1: USB PHY Tx Control - force calibration to '8'
	 * TXDATA_BLOCK_EN[21]=0x1, EXT_RCAL_EN[13]=0x1, IMP_CAL[6:3]=0x8
	 */
	wrl(USB_PHY_TX_CTRL, (rdl(USB_PHY_TX_CTRL) & ~0x78) | 0x202040);

	/*
	 * GL# USB-3 GL# USB-9: USB PHY Rx Control
	 * RXDATA_BLOCK_LENGHT[31:30]=0x3, EDGE_DET_SEL[27:26]=0,
	 * CDR_FASTLOCK_EN[21]=0, DISCON_THRESHOLD[9:8]=0, SQ_THRESH[7:4]=0x1
	 */
	wrl(USB_PHY_RX_CTRL, (rdl(USB_PHY_RX_CTRL) & ~0xc2003f0) | 0xc0000010);

	/*
	 * GL# USB-3 GL# USB-9: USB PHY IVREF Control
	 * PLLVDD12[1:0]=0x2, RXVDD[5:4]=0x3, Reserved[19]=0
	 */
	wrl(USB_PHY_IVREF_CTRL, (rdl(USB_PHY_IVREF_CTRL) & ~0x80003 ) | 0x32);

	/*
	 * GL# USB-3 GL# USB-9: USB PHY Test Group Control
	 * REG_FIFO_SQ_RST[15]=0
	 */
	wrl(USB_PHY_TST_GRP_CTRL, rdl(USB_PHY_TST_GRP_CTRL) & ~0x8000);

	/*
	 * Stop and reset controller
	 */
	wrl(USB_CMD, rdl(USB_CMD) & ~0x1);
	wrl(USB_CMD, rdl(USB_CMD) | 0x2);
	while (rdl(USB_CMD) & 0x2);

	/*
	 * GL# USB-5 Streaming disable REG_USB_MODE[4]=1
	 * TBD: This need to be done after each reset!
	 * GL# USB-4 Setup USB Host mode
	 */
	wrl(USB_MODE, 0x13);
}

static void
ehci_orion_conf_mbus_windows(struct usb_hcd *hcd,
			     const struct mbus_dram_target_info *dram)
{
	int i;

	for (i = 0; i < 4; i++) {
		wrl(USB_WINDOW_CTRL(i), 0);
		wrl(USB_WINDOW_BASE(i), 0);
	}

	for (i = 0; i < dram->num_cs; i++) {
		const struct mbus_dram_window *cs = dram->cs + i;

		wrl(USB_WINDOW_CTRL(i), ((cs->size - 1) & 0xffff0000) |
					(cs->mbus_attr << 8) |
					(dram->mbus_dram_target_id << 4) | 1);
		wrl(USB_WINDOW_BASE(i), cs->base);
	}
}

static int ehci_orion_drv_probe(struct platform_device *pdev)
{
	struct orion_ehci_data *pd = dev_get_platdata(&pdev->dev);
	const struct mbus_dram_target_info *dram;
	struct resource *res;
	struct usb_hcd *hcd;
	struct ehci_hcd *ehci;
	struct clk *clk;
	void __iomem *regs;
	int irq, err;
	enum orion_ehci_phy_ver phy_version;

	if (usb_disabled())
		return -ENODEV;

	pr_debug("Initializing Orion-SoC USB Host Controller\n");

	if (pdev->dev.of_node)
		irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	else
		irq = platform_get_irq(pdev, 0);
	if (irq <= 0) {
		dev_err(&pdev->dev,
			"Found HC with no IRQ. Check %s setup!\n",
			dev_name(&pdev->dev));
		err = -ENODEV;
		goto err1;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev,
			"Found HC with no register addr. Check %s setup!\n",
			dev_name(&pdev->dev));
		err = -ENODEV;
		goto err1;
	}

	/*
	 * Right now device-tree probed devices don't get dma_mask
	 * set. Since shared usb code relies on it, set it here for
	 * now. Once we have dma capability bindings this can go away.
	 */
	err = dma_coerce_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (err)
		goto err1;

	if (!request_mem_region(res->start, resource_size(res),
				ehci_orion_hc_driver.description)) {
		dev_dbg(&pdev->dev, "controller already in use\n");
		err = -EBUSY;
		goto err1;
	}

	regs = ioremap(res->start, resource_size(res));
	if (regs == NULL) {
		dev_dbg(&pdev->dev, "error mapping memory\n");
		err = -EFAULT;
		goto err2;
	}

	/* Not all platforms can gate the clock, so it is not
	   an error if the clock does not exists. */
	clk = clk_get(&pdev->dev, NULL);
	if (!IS_ERR(clk)) {
		clk_prepare_enable(clk);
		clk_put(clk);
	}

	hcd = usb_create_hcd(&ehci_orion_hc_driver,
			&pdev->dev, dev_name(&pdev->dev));
	if (!hcd) {
		err = -ENOMEM;
		goto err3;
	}

	hcd->rsrc_start = res->start;
	hcd->rsrc_len = resource_size(res);
	hcd->regs = regs;

	ehci = hcd_to_ehci(hcd);
	ehci->caps = hcd->regs + 0x100;
	hcd->has_tt = 1;

	/*
	 * (Re-)program MBUS remapping windows if we are asked to.
	 */
	dram = mv_mbus_dram_info();
	if (dram)
		ehci_orion_conf_mbus_windows(hcd, dram);

	/*
	 * setup Orion USB controller.
	 */
	if (pdev->dev.of_node)
		phy_version = EHCI_PHY_NA;
	else
		phy_version = pd->phy_version;

	switch (phy_version) {
	case EHCI_PHY_NA:	/* dont change USB phy settings */
		break;
	case EHCI_PHY_ORION:
		orion_usb_phy_v1_setup(hcd);
		break;
	case EHCI_PHY_DD:
	case EHCI_PHY_KW:
	default:
		printk(KERN_WARNING "Orion ehci -USB phy version isn't supported.\n");
	}

	err = usb_add_hcd(hcd, irq, IRQF_SHARED);
	if (err)
		goto err4;

	return 0;

err4:
	usb_put_hcd(hcd);
err3:
	if (!IS_ERR(clk)) {
		clk_disable_unprepare(clk);
		clk_put(clk);
	}
	iounmap(regs);
err2:
	release_mem_region(res->start, resource_size(res));
err1:
	dev_err(&pdev->dev, "init %s fail, %d\n",
		dev_name(&pdev->dev), err);

	return err;
}

static int ehci_orion_drv_remove(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	struct clk *clk;

	usb_remove_hcd(hcd);
	iounmap(hcd->regs);
	release_mem_region(hcd->rsrc_start, hcd->rsrc_len);
	usb_put_hcd(hcd);

	clk = clk_get(&pdev->dev, NULL);
	if (!IS_ERR(clk)) {
		clk_disable_unprepare(clk);
		clk_put(clk);
	}

	return 0;
}

static int ehci_orion_drv_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);

	int addr, i;

	for (addr = USB_CAUSE, i = 0; addr <= USB_IPG; addr += 0x4, i++)
		usb_save[i] = readl_relaxed(hcd->regs + addr);

	for (addr = USB_PHY_PWR_CTRL; addr <= USB_PHY_TST_GRP_CTRL; addr += 0x4, i++)
		usb_save[i] = readl_relaxed(hcd->regs + addr);

	return 0;
}

#define MV_USB_CORE_CMD_RESET_BIT           1
#define MV_USB_CORE_CMD_RESET_MASK          (1 << MV_USB_CORE_CMD_RESET_BIT)
#define MV_USB_CORE_MODE_OFFSET                 0
#define MV_USB_CORE_MODE_MASK                   (3 << MV_USB_CORE_MODE_OFFSET)
#define MV_USB_CORE_MODE_HOST                   (3 << MV_USB_CORE_MODE_OFFSET)
#define MV_USB_CORE_MODE_DEVICE                 (2 << MV_USB_CORE_MODE_OFFSET)
#define MV_USB_CORE_CMD_RUN_BIT             0
#define MV_USB_CORE_CMD_RUN_MASK            (1 << MV_USB_CORE_CMD_RUN_BIT)

static int ehci_orion_drv_resume(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	int addr, regVal, i;

	for (addr = USB_CAUSE, i = 0; addr <= USB_IPG; addr += 0x4, i++)
		writel_relaxed(usb_save[i], hcd->regs + addr);

	for (addr = USB_PHY_PWR_CTRL; addr <= USB_PHY_TST_GRP_CTRL; addr += 0x4, i++)
		writel_relaxed(usb_save[i], hcd->regs + addr);

	/* Clear Interrupt Cause and Mask registers */
	writel_relaxed(0, hcd->regs + 0x310);
	writel_relaxed(0, hcd->regs + 0x314);

	/* Reset controller */
	regVal = readl_relaxed(hcd->regs + 0x140);
	writel_relaxed(regVal | MV_USB_CORE_CMD_RESET_MASK, hcd->regs + 0x140);
	while (readl_relaxed(hcd->regs + 0x140) & MV_USB_CORE_CMD_RESET_MASK)
		;

	/* Set Mode register (Stop and Reset USB Core before) */
	/* Stop the controller */
	regVal = readl_relaxed(hcd->regs + 0x140);
	regVal &= ~MV_USB_CORE_CMD_RUN_MASK;
	writel_relaxed(regVal, hcd->regs + 0x140);

	/* Reset the controller to get default values */
	regVal = readl_relaxed(hcd->regs + 0x140);
	regVal |= MV_USB_CORE_CMD_RESET_MASK;
	writel_relaxed(regVal, hcd->regs + 0x140);

	/* Wait for the controller reset to complete */
	do {
		regVal = readl_relaxed(hcd->regs + 0x140);
	} while (regVal & MV_USB_CORE_CMD_RESET_MASK);

	/* Set USB_MODE register */
	regVal = MV_USB_CORE_MODE_HOST;
	writel_relaxed(regVal, hcd->regs + 0x1A8);

	return 0;
}

static void ehci_orion_drv_shutdown(struct platform_device *pdev)
{
	struct usb_hcd *hcd = platform_get_drvdata(pdev);
	static void __iomem *usb_pwr_ctrl_base;
	struct clk *clk;

	usb_hcd_platform_shutdown(pdev);

	usb_pwr_ctrl_base = hcd->regs + USB_PHY_PWR_CTRL;
	BUG_ON(!usb_pwr_ctrl_base);
	/* Power Down & PLL Power down */
	writel((readl(usb_pwr_ctrl_base) & ~(BIT(0) | BIT(1))), usb_pwr_ctrl_base);

	clk = clk_get(&pdev->dev, NULL);
	if (!IS_ERR(clk)) {
		clk_disable_unprepare(clk);
		clk_put(clk);
	}

}

static const struct of_device_id ehci_orion_dt_ids[] = {
	{ .compatible = "marvell,orion-ehci", },
	{},
};
MODULE_DEVICE_TABLE(of, ehci_orion_dt_ids);

static struct platform_driver ehci_orion_driver = {
	.probe		= ehci_orion_drv_probe,
	.remove		= ehci_orion_drv_remove,
#ifdef CONFIG_PM
	.suspend        = ehci_orion_drv_suspend,
	.resume         = ehci_orion_drv_resume,
#endif
	.shutdown	= ehci_orion_drv_shutdown,
	.driver = {
		.name	= "orion-ehci",
		.owner  = THIS_MODULE,
		.of_match_table = of_match_ptr(ehci_orion_dt_ids),
	},
};

static int __init ehci_orion_init(void)
{
	if (usb_disabled())
		return -ENODEV;

	pr_info("%s: " DRIVER_DESC "\n", hcd_name);

	ehci_init_driver(&ehci_orion_hc_driver, NULL);
	return platform_driver_register(&ehci_orion_driver);
}
module_init(ehci_orion_init);

static void __exit ehci_orion_cleanup(void)
{
	platform_driver_unregister(&ehci_orion_driver);
}
module_exit(ehci_orion_cleanup);

MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_ALIAS("platform:orion-ehci");
MODULE_AUTHOR("Tzachi Perelstein");
MODULE_LICENSE("GPL v2");
