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

#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "xhci.h"
#include "../dwc3/core.h"

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/seq_file.h>

static struct dentry	*root;
static struct hc_driver __read_mostly opv5xc_drd_driver;

struct regs_info {
	char *name;
	__le32 __iomem *addr;
};

static int opv5xc_regdump_show_all(struct seq_file *s, void *unused)
{
	struct usb_hcd	*hcd = s->private;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	int	i;
	struct regs_info xhci_cap_regs[] = {
		{"hc_capbase",		&xhci->cap_regs->hc_capbase},
		{"hcs_params1",		&xhci->cap_regs->hcs_params1},
		{"hcs_params2",		&xhci->cap_regs->hcs_params2},
		{"hcs_params3",		&xhci->cap_regs->hcs_params3},
		{"hcc_params",		&xhci->cap_regs->hcc_params},
		{"db_off",		&xhci->cap_regs->db_off},
		{"run_regs_off",	&xhci->cap_regs->run_regs_off},
	};
	struct regs_info xhci_op_regs[] = {
		{"command",		&xhci->op_regs->command},
		{"status",		&xhci->op_regs->status},
		{"page_size",		&xhci->op_regs->page_size},
		{"dev_notification",	&xhci->op_regs->dev_notification},
		{"config_reg",		&xhci->op_regs->config_reg},
		{"port1_status_base",	&xhci->op_regs->port_status_base},
		{"port1_power_base",	&xhci->op_regs->port_power_base},
		{"port1_link_base",	&xhci->op_regs->port_link_base},
		{"port2_status_base",	&xhci->op_regs->port_status_base + NUM_PORT_REGS},
		{"port2_power_base",	&xhci->op_regs->port_power_base + NUM_PORT_REGS},
		{"port2_link_base",	&xhci->op_regs->port_link_base + NUM_PORT_REGS},
	};
	struct regs_info dwc3_global_regs[] = {
		{"DWC3_GSBUSCFG0",	hcd->regs + DWC3_GSBUSCFG0},
		{"DWC3_GSBUSCFG1",	hcd->regs + DWC3_GSBUSCFG1},
		{"DWC3_GTXTHRCFG",	hcd->regs + DWC3_GTXTHRCFG},
		{"DWC3_GRXTHRCFG",	hcd->regs + DWC3_GRXTHRCFG},
		{"DWC3_GCTL",		hcd->regs + DWC3_GCTL},
		{"DWC3_GEVTEN",		hcd->regs + DWC3_GEVTEN},
		{"DWC3_GSTS",		hcd->regs + DWC3_GSTS},
		{"DWC3_GSNPSID",	hcd->regs + DWC3_GSNPSID},
		{"DWC3_GGPIO",		hcd->regs + DWC3_GGPIO},
		{"DWC3_GUID",		hcd->regs + DWC3_GUID},
		{"DWC3_GUCTL",		hcd->regs + DWC3_GUCTL},
		{"DWC3_GBUSERRADDR0",	hcd->regs + DWC3_GBUSERRADDR0},
		{"DWC3_GBUSERRADDR1",	hcd->regs + DWC3_GBUSERRADDR1},
		{"DWC3_GPRTBIMAP0",	hcd->regs + DWC3_GPRTBIMAP0},
		{"DWC3_GPRTBIMAP1",	hcd->regs + DWC3_GPRTBIMAP1},
		{"DWC3_GHWPARAMS0",	hcd->regs + DWC3_GHWPARAMS0},
		{"DWC3_GHWPARAMS1",	hcd->regs + DWC3_GHWPARAMS1},
		{"DWC3_GHWPARAMS2",	hcd->regs + DWC3_GHWPARAMS2},
		{"DWC3_GHWPARAMS3",	hcd->regs + DWC3_GHWPARAMS3},
		{"DWC3_GHWPARAMS4",	hcd->regs + DWC3_GHWPARAMS4},
		{"DWC3_GHWPARAMS5",	hcd->regs + DWC3_GHWPARAMS5},
		{"DWC3_GHWPARAMS6",	hcd->regs + DWC3_GHWPARAMS6},
		{"DWC3_GHWPARAMS7",	hcd->regs + DWC3_GHWPARAMS7},
		{"DWC3_GDBGFIFOSPACE",	hcd->regs + DWC3_GDBGFIFOSPACE},
		{"DWC3_GDBGLTSSM",	hcd->regs + DWC3_GDBGLTSSM},
		{"DWC3_GPRTBIMAP_HS0",	hcd->regs + DWC3_GPRTBIMAP_HS0},
		{"DWC3_GPRTBIMAP_HS1",	hcd->regs + DWC3_GPRTBIMAP_HS1},
		{"DWC3_GPRTBIMAP_FS0",	hcd->regs + DWC3_GPRTBIMAP_FS0},
		{"DWC3_GPRTBIMAP_FS1",	hcd->regs + DWC3_GPRTBIMAP_FS1},
	};
	struct regs_info dwc3_global_phy_regs[] = {
		{"DWC3_GUSB2PHYCFG(0)",	hcd->regs + DWC3_GUSB2PHYCFG(0)},
		{"DWC3_GUSB2I2CCTL(0)",	hcd->regs + DWC3_GUSB2I2CCTL(0)},
		{"DWC3_GUSB2PHYACC(0)",	hcd->regs + DWC3_GUSB2PHYACC(0)},
		{"DWC3_GUSB3PIPECTL(0)", hcd->regs + DWC3_GUSB3PIPECTL(0)},
		{"DWC3_GTXFIFOSIZ(0)",	hcd->regs + DWC3_GTXFIFOSIZ(0)},
		{"DWC3_GRXFIFOSIZ(0)",	hcd->regs + DWC3_GRXFIFOSIZ(0)},
		{"DWC3_GEVNTADRLO(0)",	hcd->regs + DWC3_GEVNTADRLO(0)},
		{"DWC3_GEVNTADRHI(0)",	hcd->regs + DWC3_GEVNTADRHI(0)},
		{"DWC3_GEVNTSIZ(0)",	hcd->regs + DWC3_GEVNTSIZ(0)},
		{"DWC3_GEVNTCOUNT(0)",	hcd->regs + DWC3_GEVNTCOUNT(0)},
		{"DWC3_GHWPARAMS8",	hcd->regs + DWC3_GHWPARAMS8},
	};
	struct regs_info dwc3_otg_regs[] = {
		{"DWC3_OCFG",		hcd->regs + DWC3_OCFG},
		{"DWC3_OCTL",		hcd->regs + DWC3_OCTL},
		{"DWC3_OEVTEN",		hcd->regs + DWC3_OEVTEN},
		{"DWC3_OSTS",		hcd->regs + DWC3_OSTS},
	};


	seq_printf(s, " Capability Reg       Value (base:0x%p)\n",
			&xhci->cap_regs->hc_capbase);
	for (i = 0; i < ARRAY_SIZE(xhci_cap_regs); i++) {
		seq_printf(s, " %-20.20s %08x\n", xhci_cap_regs[i].name,
				xhci_readl(xhci, xhci_cap_regs[i].addr));
	}

	seq_printf(s, "\n Operational Reg      Value (base:0x%p)\n",
			&xhci->op_regs->command);
	for (i = 0; i < ARRAY_SIZE(xhci_op_regs); i++) {
		seq_printf(s, " %-20.20s %08x\n", xhci_op_regs[i].name,
				xhci_readl(xhci, xhci_op_regs[i].addr));
	}

	seq_printf(s, "\n DWC3 Global Reg      Value (base:0x%p)\n",
			hcd->regs + DWC3_GSBUSCFG0);
	for (i = 0; i < ARRAY_SIZE(dwc3_global_regs); i++) {
		seq_printf(s, " %-20.20s %08x\n", dwc3_global_regs[i].name,
				readl(dwc3_global_regs[i].addr));
	}

	seq_printf(s, "\n DWC3 Global PHY Reg  Value (base:0x%p)\n",
			hcd->regs + DWC3_GUSB2PHYCFG(0));
	for (i = 0; i < ARRAY_SIZE(dwc3_global_phy_regs); i++) {
		seq_printf(s, " %-20.20s %08x\n", dwc3_global_phy_regs[i].name,
				readl(dwc3_global_phy_regs[i].addr));
	}

	seq_printf(s, "\n DWC3 OTG Reg         Value (base:0x%p)\n",
			hcd->regs + DWC3_OCFG);
	for (i = 0; i < ARRAY_SIZE(dwc3_otg_regs); i++) {
		seq_printf(s, " %-20.20s %08x\n", dwc3_otg_regs[i].name,
				readl(dwc3_otg_regs[i].addr));
	}

	return 0;
}

static int regdump_open(struct inode *inode, struct file *file)
{
	return single_open(file, opv5xc_regdump_show_all, inode->i_private);
}

static const struct file_operations regdump_fops = {
	.open = regdump_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int u2_testmode_show(struct seq_file *s, void *unused)
{
	struct usb_hcd	*hcd = s->private;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	u32		reg;

	reg = xhci_readl(xhci, &xhci->op_regs->port_power_base);
	reg >>= 28;

	switch (reg) {
	case 0:
		seq_printf(s, "no test\n");
		break;
	case TEST_J:
		seq_printf(s, "test_j\n");
		break;
	case TEST_K:
		seq_printf(s, "test_k\n");
		break;
	case TEST_SE0_NAK:
		seq_printf(s, "test_se0_nak\n");
		break;
	case TEST_PACKET:
		seq_printf(s, "test_packet\n");
		break;
	case TEST_FORCE_EN:
		seq_printf(s, "test_force_enable\n");
		break;
	default:
		seq_printf(s, "UNKNOWN %d\n", reg);
	}

	seq_printf(s, "(no test, test_j, test_k, test_se0_nak, test_packet, test_force_enable)\n");

	return 0;
}

static int u2_testmode_open(struct inode *inode, struct file *file)
{
	return single_open(file, u2_testmode_show, inode->i_private);
}

/*
 * How to force USB 2.0 controller enter test mode
 * Load USB DRD driver
 *   # modprobe xhci-opv5xc-drd
 * Check current mode:
 *   # cat /sys/kernel/debug/opv5xc/usb3drd/u2testmode
 *   no test
 *   # echo test_packet > /sys/kernel/debug/opv5xc/usb3drd/u2testmode
 * Check current mode:
 *   # cat /sys/kernel/debug/opv5xc/usb3drd/u2testmode
 *   test_packet
 */
static ssize_t u2_testmode_write(struct file *file,
		const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct seq_file	*s = file->private_data;
	struct usb_hcd	*hcd = s->private;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	char		buf[32];
	u32		testmode = 0;
	u32		reg;

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count)))
		return -EFAULT;

	if (!strncmp(buf, "test_j", 6))
		testmode = TEST_J;
	else if (!strncmp(buf, "test_k", 6))
		testmode = TEST_K;
	else if (!strncmp(buf, "test_se0_nak", 12))
		testmode = TEST_SE0_NAK;
	else if (!strncmp(buf, "test_packet", 11))
		testmode = TEST_PACKET;
	else if (!strncmp(buf, "test_force_enable", 17))
		testmode = TEST_FORCE_EN;
	else
		testmode = 0;

	reg = xhci_readl(xhci, &xhci->op_regs->port_power_base);
	reg &= 0x0FFFFFFF;
	reg |= testmode << 28;
	xhci_writel(xhci, reg, &xhci->op_regs->port_power_base);

	return count;
}

static const struct file_operations u2_testmode_fops = {
	.open			= u2_testmode_open,
	.write			= u2_testmode_write,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= single_release,
};

static char *link_state[] = {
	"U0",		"U1",		"U2",			"U3",
	"SS.Disabled",	"Rx.Detect",	"SS.Inactive",		"Polling",
	"Recovery",	"Hot Reset",	"Compliance Mode",	"Loopback",
};

static int advance_counter = 0;

static int u3_compliance_show(struct seq_file *s, void *unused)
{
	struct usb_hcd	*hcd = s->private;
	u32		reg, id, sub_state;

	reg = readl(hcd->regs + DWC3_GDBGLTSSM);
	/* Link state GDBGLTSSM bit 25:22 */
	id = reg >> 22;
	id &= 0x0F;

	/* Sub-state GDBGLTSSM bit 21:18 */
	sub_state = reg >> 18;
	sub_state &= 0x0F;

	if (id < ARRAY_SIZE(link_state))
		if (id == 10)
			/* Compliance mode */
			seq_printf(s, "%s (sub-state:%d) mode=cp%d\n",
				       link_state[id], sub_state, advance_counter);
		else
			seq_printf(s, "%s (sub-state:%d)\n", link_state[id], sub_state);
	else
		seq_printf(s, "Undefined state %d\n", id);

	return 0;
}

static int u3_compliance_open(struct inode *inode, struct file *file)
{
	return single_open(file, u3_compliance_show, inode->i_private);
}

/*
 * 6.2.5  Global USB3 PIPE Control Register (GUSB3PIPECTLn)
 * HstPrtCmpl
 * This feature tests the PIPE PHY compliance patterns without having
 * to have a test fixture on the USB 3.0 cable.
 * This bit enables placing the SS port link into a compliance state. By
 * default, this bit should be set to 1‘b0.
 * In compliance lab testing, the SS port link enters compliance after
 * failing the first polling sequence after power on. Set this bit to 0,
 * when you run compliance tests.
 * The sequence for using this functionality is as follows:
 *   1. Disconnect any plugged in devices.
 *   2. Perform USBCMD.HCRST or power-on-chip reset.
 *   3. Set PORTSC.PP=0.
 *   4. Set GUSB3PIPECTL.HstPrtCmpl=1. This places the link into
 * compliance state.
 * To advance the compliance pattern, follow this sequence (toggle the
 * set GUSB3PIPECTL. HstPrtCmpl):
 *   1. Set GUSB3PIPECTL.HstPrtCmpl=0.
 *   2. Set GUSB3PIPECTL.HstPrtCmpl=1. This advances the link to the
 * next compliance pattern.
 * To exit from the compliance state perform USBCMD.HCRST or
 * power-on-chip reset.
 */
static ssize_t u3_compliance_write(struct file *file,
		const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct seq_file	*s = file->private_data;
	struct usb_hcd	*hcd = s->private;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	char		buf[32];
	u32		reg, ret;

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count)))
		return -EFAULT;

	if (!strncmp(buf, "enable", 6)) {
		/* Clear GUSB3PIPECTL.HstPrtCmpl */
		reg = readl(hcd->regs + DWC3_GUSB3PIPECTL(0));
		reg &= ~DWC3_GUSB3PIPECTL_HSTPRTCMPL;
		writel(reg, hcd->regs + DWC3_GUSB3PIPECTL(0));

		/* 1. Disconnect any plugged in devices.
		 * 2. Perform USBCMD.HCRST or power-on-chip reset.  */
		reg = xhci_readl(xhci, &xhci->op_regs->command);
		reg |= CMD_RESET;
		xhci_writel(xhci, reg, &xhci->op_regs->command);
		ret = xhci_handshake(xhci, &xhci->op_regs->command,
				CMD_RESET, 0, 10 * 1000 * 1000);

		mdelay(200);

		/* 4. Set GUSB3PIPECTL.HstPrtCmpl=1. This places the link into
		 *    compliance state.  */
		reg = readl(hcd->regs + DWC3_GUSB3PIPECTL(0));
		reg |= DWC3_GUSB3PIPECTL_HSTPRTCMPL;
		writel(reg, hcd->regs + DWC3_GUSB3PIPECTL(0));

		advance_counter = 0;
	} else if (!strncmp(buf, "disable", 7)) {
		/* TODO: To make host controller work after disable compilance
		 * 	 mode, user need to re-initial host controller. */
		reg = readl(hcd->regs + DWC3_GUSB3PIPECTL(0));
		reg &= ~DWC3_GUSB3PIPECTL_HSTPRTCMPL;
		writel(reg, hcd->regs + DWC3_GUSB3PIPECTL(0));

		reg = xhci_readl(xhci, &xhci->op_regs->command);
		reg |= CMD_RESET;
		xhci_writel(xhci, reg, &xhci->op_regs->command);
		ret = xhci_handshake(xhci, &xhci->op_regs->command,
				CMD_RESET, 0, 10 * 1000 * 1000);

		advance_counter = 0;
	} else if (!strncmp(buf, "advance", 7)) {
		/* Advance the compliance pattern */
		reg = readl(hcd->regs + DWC3_GUSB3PIPECTL(0));
		if (reg & DWC3_GUSB3PIPECTL_HSTPRTCMPL) {
			reg &= ~DWC3_GUSB3PIPECTL_HSTPRTCMPL;
			writel(reg, hcd->regs + DWC3_GUSB3PIPECTL(0));
			reg |= DWC3_GUSB3PIPECTL_HSTPRTCMPL;
			writel(reg, hcd->regs + DWC3_GUSB3PIPECTL(0));
		}

		advance_counter++;
		if (advance_counter >= 8)
			advance_counter = 0;
	} else {
		printk(KERN_NOTICE
				"Usage: echo [OPTIONS] > u3compliance\n"
				"Option list:\n"
				"  enable  - Enable compliance state\n"
				"  disable - Disable compliance state\n"
				"  advance - Advance the compliance pattern\n");
	}

	return count;
}

static const struct file_operations u3_compliance_fops = {
	.open			= u3_compliance_open,
	.write			= u3_compliance_write,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= single_release,
};

static int u3_port_u1_timeout_show(struct seq_file *s, void *unused)
{
	struct usb_hcd	*hcd = s->private;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	u32		reg;

	reg = xhci_readl(xhci, xhci->usb3_ports[0] + 1);
	reg &= 0xFF;

	seq_printf(s, "%d\n", reg);

	return 0;
}

static int u3_port_u1_timeout_open(struct inode *inode, struct file *file)
{
	return single_open(file, u3_port_u1_timeout_show, inode->i_private);
}

static int get_value(const char __user *ubuf, size_t count)
{
	char		buf[32];
	long		timeout;

	if (copy_from_user(&buf, ubuf, min_t(size_t, sizeof(buf) - 1, count)))
		return -EFAULT;

	if (count < 32)
		buf[count] = 0;
	else
		return -EINVAL;

	if (strict_strtol(buf, 10, &timeout) != 0)
		return -EINVAL;

	if (timeout > 0xFF)
		timeout = 0xFF;

	return timeout;
}

static ssize_t u3_port_u1_timeout_write(struct file *file,
		const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct seq_file	*s = file->private_data;
	struct usb_hcd	*hcd = s->private;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	u32		reg;
	int		timeout;

	timeout = get_value(ubuf, count);

	if (timeout < 0)
		return timeout;

	reg = xhci_readl(xhci, xhci->usb3_ports[0] + 1);
	reg &= ~0xFF;
	reg |= PORT_U1_TIMEOUT(timeout);
	xhci_writel(xhci, reg, xhci->usb3_ports[0] + 1);

	return count;
}

static const struct file_operations u3_port_u1_timeout_fops = {
	.open			= u3_port_u1_timeout_open,
	.write			= u3_port_u1_timeout_write,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= single_release,
};

static int u3_port_u2_timeout_show(struct seq_file *s, void *unused)
{
	struct usb_hcd	*hcd = s->private;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	u32		reg;

	reg = xhci_readl(xhci, xhci->usb3_ports[0] + 1);
	reg >>= 8;
	reg &= 0xFF;

	seq_printf(s, "%d\n", reg);

	return 0;
}

static int u3_port_u2_timeout_open(struct inode *inode, struct file *file)
{
	return single_open(file, u3_port_u2_timeout_show, inode->i_private);
}

static ssize_t u3_port_u2_timeout_write(struct file *file,
		const char __user *ubuf, size_t count, loff_t *ppos)
{
	struct seq_file	*s = file->private_data;
	struct usb_hcd	*hcd = s->private;
	struct xhci_hcd *xhci = hcd_to_xhci(hcd);
	u32		reg;
	int		timeout;

	timeout = get_value(ubuf, count);

	if (timeout < 0)
		return timeout;

	reg = xhci_readl(xhci, xhci->usb3_ports[0] + 1);
	reg &= ~(0xFF << 8);
	reg |= PORT_U2_TIMEOUT(timeout);
	xhci_writel(xhci, reg, xhci->usb3_ports[0] + 1);

	return count;
}

static const struct file_operations u3_port_u2_timeout_fops = {
	.open			= u3_port_u2_timeout_open,
	.write			= u3_port_u2_timeout_write,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= single_release,
};

static int opv5xc_usb3drd_debug_init(struct usb_hcd *hcd)
{
	/*
	 * Prepare debugfs directory for USB 3.0 DRD controller:
	 */
	/* [DIR] /sys/kernel/debug/opv5xc */
	if (!opv5xc_debugfs_dir) {
		opv5xc_debugfs_dir = debugfs_create_dir("opv5xc", NULL);
		if (!opv5xc_debugfs_dir)
			goto err0;
	}

	/* [DIR] /sys/kernel/debug/opv5xc/usb3drd */
	root = debugfs_create_dir("usb3drd", opv5xc_debugfs_dir);
	if (!root)
		goto err0;

	/* [FILE] /sys/kernel/debug/opv5xc/usb3drd/regdump */
	if (!debugfs_create_file("regdump", S_IRUGO, root, hcd, &regdump_fops))
		goto err1;

	/* [FILE] /sys/kernel/debug/opv5xc/usb3drd/u2testmode */
	if (!debugfs_create_file("u2testmode", S_IRUGO | S_IWUSR, root, hcd, &u2_testmode_fops))
		goto err1;

	/* [FILE] /sys/kernel/debug/opv5xc/usb3drd/u3compliance */
	if (!debugfs_create_file("u3compliance", S_IRUGO | S_IWUSR, root, hcd, &u3_compliance_fops))
		goto err1;

	/* [FILE] /sys/kernel/debug/opv5xc/usb3h/port2_u1_timeout */
	if (!debugfs_create_file("port2_u1_timeout", S_IRUGO | S_IWUSR, root, hcd, &u3_port_u1_timeout_fops))
		goto err1;

	/* [FILE] /sys/kernel/debug/opv5xc/usb3h/port2_u2_timeout */
	if (!debugfs_create_file("port2_u2_timeout", S_IRUGO | S_IWUSR, root, hcd, &u3_port_u2_timeout_fops))
		goto err1;

	return 0;

err1:
	debugfs_remove_recursive(root);

err0:
	return -ENOMEM;
}

static void opv5xc_debugfs_exit(struct usb_hcd *hcd)
{
	if (root)
		debugfs_remove_recursive(root);
}
#endif /* CONFIG_DEBUG_FS */

static int  __init xhci_plat_probe(struct platform_device *pdev)
{
	const struct hc_driver	*driver;
	struct xhci_hcd		*xhci;
	struct resource		*res;
	struct usb_hcd		*hcd;
	int			ret;
	int			irq;
	struct completion xhci_hcd_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	u32			reg;
	
	init_completion(&xhci_hcd_complete);
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
		wait_for_completion_timeout(&xhci_hcd_complete, timeout);
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<15)) {
			val = 1;
			break;
		}
	} while (counter-- != 0);
	if ((counter == 0) && (val == 0)) {
		printk("\n: Timeout while enabling power for XHCI-DRD \n");
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
	writel(0x18E4000A, OPV5XC_MISC_BASE_VIRT + 0x808);
#endif

	if (usb_disabled())
		return -ENODEV;

	driver = &opv5xc_drd_driver;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return -ENODEV;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	hcd = usb_create_hcd(driver, &pdev->dev, dev_name(&pdev->dev));
	if (!hcd)
		return -ENOMEM;

	hcd->rsrc_start = res->start;
	hcd->rsrc_len = resource_size(res);

#if 1
	if (!request_mem_region(hcd->rsrc_start, hcd->rsrc_len,
				driver->description)) {
		dev_dbg(&pdev->dev, "controller already in use\n");
		ret = -EBUSY;
		goto put_hcd;
	}
#endif

	hcd->regs = ioremap_nocache(hcd->rsrc_start, hcd->rsrc_len);
	if (!hcd->regs) {
		dev_dbg(&pdev->dev, "error mapping memory\n");
		ret = -EFAULT;
		goto release_mem_region;
	}

	ret = usb_add_hcd(hcd, irq, IRQF_SHARED);
	if (ret)
		goto unmap_registers;

	/* USB 2.0 roothub is stored in the platform_device now. */
	hcd = dev_get_drvdata(&pdev->dev);
	xhci = hcd_to_xhci(hcd);
	xhci->shared_hcd = usb_create_shared_hcd(driver, &pdev->dev,
			dev_name(&pdev->dev), hcd);
	if (!xhci->shared_hcd) {
		ret = -ENOMEM;
		goto dealloc_usb2_hcd;
	}

	/*
	 * Set the xHCI pointer before xhci_plat_setup() (aka hcd_driver.reset)
	 * is called by usb_add_hcd().
	 */
	*((struct xhci_hcd **) xhci->shared_hcd->hcd_priv) = xhci;

	ret = usb_add_hcd(xhci->shared_hcd, irq, IRQF_SHARED);
	if (ret)
		goto put_usb3_hcd;

#ifdef CONFIG_DEBUG_FS
	opv5xc_usb3drd_debug_init(hcd);
#endif

	return 0;

put_usb3_hcd:
	usb_put_hcd(xhci->shared_hcd);

dealloc_usb2_hcd:
	usb_remove_hcd(hcd);

unmap_registers:
	iounmap(hcd->regs);

release_mem_region:
	release_mem_region(hcd->rsrc_start, hcd->rsrc_len);

put_hcd:
	usb_put_hcd(hcd);

	return ret;
}

static int xhci_plat_remove(struct platform_device *dev)
{
	struct usb_hcd	*hcd = platform_get_drvdata(dev);
	struct xhci_hcd	*xhci = hcd_to_xhci(hcd);

	usb_remove_hcd(xhci->shared_hcd);
	usb_put_hcd(xhci->shared_hcd);

	usb_remove_hcd(hcd);
	iounmap(hcd->regs);
	release_mem_region(hcd->rsrc_start, hcd->rsrc_len);
	usb_put_hcd(hcd);
	kfree(xhci);

#ifdef CONFIG_DEBUG_FS
	opv5xc_debugfs_exit(hcd);
#endif

	return 0;
}


#ifdef CONFIG_PM
static int xhci_plat_suspend(struct platform_device *pdev)
{
	struct xhci_hcd         *xhci;
	struct usb_hcd          *hcd;

	hcd = dev_get_drvdata(&pdev->dev);
	xhci = hcd_to_xhci(hcd);
	xhci_suspend(xhci);
	return 0;
}

static int xhci_plat_resume(struct platform_device *pdev)
{
	struct xhci_hcd         *xhci;
	struct usb_hcd          *hcd;
	uint32_t                 reg;
	struct completion xhci_hcd_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;
	
	init_completion(&xhci_hcd_complete);
	hcd = dev_get_drvdata(&pdev->dev);
	xhci = hcd_to_xhci(hcd);
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)

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
		wait_for_completion_timeout(&xhci_hcd_complete, timeout);
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<15)) {
			val = 1;
			break;
		}
	} while (counter-- != 0);
	if ((counter == 0) && (val == 0)) {
		printk("\n: Timeout while enabling power for XHCI-DRD \n");
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
	writel(0x18E4000A, OPV5XC_MISC_BASE_VIRT + 0x808);
#endif
	xhci_resume(xhci, 1);  /* 1 - denotes resumption from hibernation */
	return 0;
}
#endif

static struct platform_driver opv5xc_drd_xhci_driver = {
	.probe	= xhci_plat_probe,
	.remove	= xhci_plat_remove,
	.driver	= {
		.name = "opv5xc-drd-xhci",
	},
#ifdef CONFIG_PM
	.suspend = xhci_plat_suspend,
	.resume = xhci_plat_resume,
#endif
};

void opv5xc_drd_plat_quirks(struct device *dev, struct xhci_hcd *xhci)
{
	 /*
	  * As of now platform drivers don't provide MSI support so we ensure
	  * here that the generic code does not try to make a pci_dev from our
	  * dev struct in order to setup MSI
	  */
	xhci->quirks |= XHCI_PLAT;
}

/* called during probe() after chip reset completes */
int opv5xc_drd_plat_setup(struct usb_hcd *hcd)
{
	return xhci_gen_setup(hcd, opv5xc_drd_plat_quirks);
}

static const struct xhci_driver_overrides opv5xc_drd_xhci_overrides __initconst = {
	.extra_priv_size = sizeof(struct xhci_hcd),
	.reset = opv5xc_drd_plat_setup,
};

static int __init opv5xc_drd_xhci_register_init(void)
{
	xhci_init_driver(&opv5xc_drd_driver, &opv5xc_drd_xhci_overrides);
	return platform_driver_register(&opv5xc_drd_xhci_driver);
}

module_init(opv5xc_drd_xhci_register_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Open-Silicon OPV5XC USB3 DRD Host Glue Layer");
