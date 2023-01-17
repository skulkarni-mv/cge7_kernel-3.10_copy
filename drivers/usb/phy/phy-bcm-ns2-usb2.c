/*
 * Copyright (C) 2015, Broadcom Corporation. All Rights Reserved.
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

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/usb/otg.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>


#define USB2H_IDM_IDM_RESET_CONTROL__RESET 0
#define USB2H_IDM_IDM_IO_CONTROL_DIRECT__clk_enable 0
#define USB2H_Ohci_Ehci_Strap__ohci_app_port_ovrcur_polarity 11
#define USB2H_Ohci_Ehci_Strap__ppc_inversion 12
#define ICFG_USB2H_PHY_MISC_STATUS_PLLLOCK    0
#define USB2H_Phy_Ctrl_P0__Phy_Hard_Reset 9
#define USB2H_Phy_Ctrl_P0__Core_Reset 8
#define USB2H_Phy_Ctrl_P0__PHY_Soft_Reset 6
#define USB2H_Phy_Ctrl_P0__PHY_Test_port_Pwr_Dn 4
#define USB2H_Phy_Ctrl_P0__PHY_Test_port_UTMI_Pwr_Dn 2
#define USB2H_Phy_Ctrl_P0__PHY_PLL_Pwr_Dn 0
#define ICFG_FSM_MODE 2
#define ICFG_FSM_MODE_MASK 0x0000000C
#define ICFG_FSM_MODE_HOST 0x3


struct bcm_phy_ns2_usb2 {
	struct usb_phy phy;
	struct clk *clk;
	void __iomem *idm_reset_ctl;
	void __iomem *idm_io_ctl_direct;
	void __iomem *crmu_usb2_ctl;
	void __iomem *ohci_ehci_strap;
	void __iomem *phy_ctrl_p0;
	void __iomem *phy_misc_status;
	void __iomem *icfg_fsm;
};

static int bcm_phy_init(struct usb_phy *phy)
{
	return 0;
}

static void bcm_phy_shutdown(struct usb_phy *phy)
{
}

static int bcm_phy_probe(struct platform_device *pdev)
{
	struct bcm_phy_ns2_usb2 *phy;
	struct device *dev = &pdev->dev;
	struct device_node *node = pdev->dev.of_node;
	uint32_t i, count = 100, reg_data;
	uint32_t afe_corerdy_vddc;
	bool dual_role = false;
	int ret = -ENODEV;

	phy = devm_kzalloc(dev, sizeof(*phy), GFP_KERNEL);
	if (!phy) {
		dev_warn(dev, "Failed to allocate USB PHY structure!\n");
		ret = -ENOMEM;
		goto error1;
	}

	phy->idm_reset_ctl = of_iomap(node, 0);
	if (!phy->idm_reset_ctl) {
		dev_err(&pdev->dev, "can't iomap idm_reset_ctl\n");
		ret = -EIO;
		goto error2;
	}

	phy->idm_io_ctl_direct = of_iomap(node, 1);
	if (!phy->idm_io_ctl_direct) {
		dev_err(&pdev->dev, "can't iomap idm_io_ctl_direct\n");
		ret = -EIO;
		goto error3;
	}

	phy->crmu_usb2_ctl = of_iomap(node, 2);
	if (!phy->crmu_usb2_ctl) {
		dev_err(&pdev->dev, "can't iomap crmu_usb2_ctl\n");
		ret = -EIO;
		goto error4;
	}

	phy->ohci_ehci_strap = of_iomap(node, 3);
	if (!phy->ohci_ehci_strap) {
		dev_err(&pdev->dev, "can't iomap ohci_ehci_strap\n");
		ret = -EIO;
		goto error5;
	}

	phy->phy_ctrl_p0 = of_iomap(node, 4);
	if (!phy->phy_ctrl_p0) {
		dev_err(&pdev->dev, "can't iomap phy_ctrl_p0\n");
		ret = -EIO;
		goto error6;
	}

	phy->phy_misc_status = of_iomap(node, 5);
	if (!phy->phy_misc_status) {
		dev_err(&pdev->dev, "can't iomap phy_misc_status\n");
		ret = -EIO;
		goto error7;
	}

	phy->icfg_fsm = of_iomap(node, 6);
	if (!phy->icfg_fsm) {
		dev_err(&pdev->dev, "can't iomap icfg_fsm\n");
		ret = -EIO;
		goto error8;
	}

	ret = of_property_read_u32(node, "afe_corerdy_vddc",
				&afe_corerdy_vddc);
	if (ret != 0) {
		dev_err(&pdev->dev, "can't property_read afe_corerdy_vddc\n");
		ret = -EIO;
		goto error9;
	}

	if (of_property_read_bool(node, "enable-dual-role"))
		dual_role = true;

	if (dual_role) {
		/* Force host mode */
		reg_data = readl(phy->icfg_fsm);
		reg_data &= ~ICFG_FSM_MODE_MASK;
		reg_data |= ICFG_FSM_MODE_HOST << ICFG_FSM_MODE;
		writel(reg_data, (phy->icfg_fsm));
	}

	/* give hardware time to settle */
	udelay(100);

	/* reset USBH controller */
	reg_data = readl(phy->idm_reset_ctl);
	reg_data |= (1 << USB2H_IDM_IDM_RESET_CONTROL__RESET);
	writel(reg_data, phy->idm_reset_ctl);

	/* Disable USBH controller clock */
	reg_data = readl(phy->idm_io_ctl_direct);
	reg_data &= ~(1 << USB2H_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
	writel(reg_data, phy->idm_io_ctl_direct);

	/* Phy bring up is done with USBH controller in reset */
	reg_data = readl(phy->crmu_usb2_ctl);
	reg_data |= (1 << afe_corerdy_vddc);
	writel(reg_data, phy->crmu_usb2_ctl);

	i = 0;
	do {
		i++;
		reg_data = readl(phy->phy_misc_status);
		if (i >= count) {
			dev_err(&pdev->dev, "failed to get PLL lock\n");
			goto error8;
		}
		udelay(10);
	} while (!(reg_data & (1 << ICFG_USB2H_PHY_MISC_STATUS_PLLLOCK)));


	/* USB Host clock enable */
	reg_data = readl(phy->idm_io_ctl_direct);
	reg_data |= (1 << USB2H_IDM_IDM_IO_CONTROL_DIRECT__clk_enable);
	writel(reg_data, phy->idm_io_ctl_direct);

	/* Enter reset */
	reg_data = readl(phy->idm_reset_ctl);
	reg_data |= (1 << USB2H_IDM_IDM_RESET_CONTROL__RESET);
	writel(reg_data, phy->idm_reset_ctl);

	/* Give hardware time to settle */
	udelay(100);

	/* Exit reset */
	reg_data &= ~(1 << USB2H_IDM_IDM_RESET_CONTROL__RESET);
	writel(reg_data, phy->idm_reset_ctl);

	/* Give hardware time to settle */
	udelay(1000);

	/* Reverse over current polarity  */
	reg_data = readl(phy->ohci_ehci_strap);
	reg_data |= (1 << USB2H_Ohci_Ehci_Strap__ohci_app_port_ovrcur_polarity);
	if (!dual_role)
		reg_data |= (1 << USB2H_Ohci_Ehci_Strap__ppc_inversion);
	writel(reg_data, phy->ohci_ehci_strap);

	/* Pull these fields out of reset */
	writel(((1 << USB2H_Phy_Ctrl_P0__Phy_Hard_Reset) |
			(1 << USB2H_Phy_Ctrl_P0__Core_Reset) |
			(0x3 << USB2H_Phy_Ctrl_P0__PHY_Soft_Reset) |
			(0x3 << USB2H_Phy_Ctrl_P0__PHY_Test_port_Pwr_Dn) |
			(0x3 << USB2H_Phy_Ctrl_P0__PHY_Test_port_UTMI_Pwr_Dn) |
			(0x3 << USB2H_Phy_Ctrl_P0__PHY_PLL_Pwr_Dn)),
		phy->phy_ctrl_p0);

	phy->phy.dev = dev;
	phy->phy.init = bcm_phy_init;
	phy->phy.shutdown = bcm_phy_shutdown;
	phy->phy.type = USB_PHY_TYPE_USB2;

	platform_set_drvdata(pdev, phy);

	ret = usb_add_phy_dev(&phy->phy);
	if (ret) {
		dev_err(&pdev->dev, "usb_add_phy_dev failed\n");
		goto error8;
	}

	return 0;

error9:
	iounmap(phy->icfg_fsm);
error8:
	iounmap(phy->phy_misc_status);
error7:
	iounmap(phy->phy_ctrl_p0);
error6:
	iounmap(phy->ohci_ehci_strap);
error5:
	iounmap(phy->crmu_usb2_ctl);
error4:
	iounmap(phy->idm_io_ctl_direct);
error3:
	iounmap(phy->idm_reset_ctl);
error2:
	kfree(phy);
error1:
	return ret;


}
static int bcm_phy_remove(struct platform_device *pdev)
{
	struct bcm_phy_ns2_usb2 *phy = platform_get_drvdata(pdev);

	usb_remove_phy(&phy->phy);
	platform_set_drvdata(pdev, NULL);
	return 0;
}

static const struct of_device_id bcm_phy_dt_ids[] = {
	{ .compatible = "brcm,ns2-usb2-phy", },
	{ }
};
MODULE_DEVICE_TABLE(of, bcm_phy_dt_ids);

static struct platform_driver bcm_phy_driver = {
	.probe = bcm_phy_probe,
	.remove = bcm_phy_remove,
	.driver = {
		.name = "bcm-ns2-usb2phy",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(bcm_phy_dt_ids),
	},
};


static int __init bcm_usb_phy_init(void)
{
	return platform_driver_register(&bcm_phy_driver);
}
subsys_initcall(bcm_usb_phy_init);

static void __exit bcm_usb_phy_exit(void)
{
	platform_driver_unregister(&bcm_phy_driver);
}
module_exit(bcm_usb_phy_exit);

MODULE_ALIAS("platform:bcm-ns2-usb2phy");
MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("Broadcom USB2 PHY driver");
MODULE_LICENSE("GPL");

