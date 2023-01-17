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

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/export.h>
#include <asm/mach/map.h>

#include <mach/opv5xc.h>
#include <mach/motherboard.h>
#include <mach/ixc.h>
#include <linux/pci.h>

#if defined(CONFIG_ARCH_OPV5XC_ES1)
/* security */
static void opv5xc_sec_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_EN_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_EN_OFFSET);
}

static void opv5xc_sec_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_EN_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_EN_OFFSET);
}

/* sec mode */
static void opv5xc_sec_mod_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_MOD_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_MOD_OFFSET);
}

static void opv5xc_sec_mod_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_MOD_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_MOD_OFFSET);
}

/* cacheable */
static void opv5xc_cacheable_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_CACHEABLE_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_CACHEABLE_OFFSET);
}

static void opv5xc_cacheable_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_CACHEABLE_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_CACHEABLE_OFFSET);
}

/* bufferable */
static void opv5xc_bufferable_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_BUFFERABLE_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_BUFFERABLE_OFFSET);
}

static void opv5xc_bufferable_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_BUFFERABLE_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_BUFFERABLE_OFFSET);
}

/* buffer */
static void opv5xc_buffer_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_BUF_EN_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_BUF_EN_OFFSET);
}

static void opv5xc_buffer_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_BUF_EN_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_BUF_EN_OFFSET);
}

/*
 *
 */
int opv5xc_acp_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg;

	switch (peri_id) {
		case IXC_CRYPTO:
			opv5xc_cacheable_enable(peri_id);
			opv5xc_bufferable_enable(peri_id);
			opv5xc_buffer_enable(peri_id);
			break;

		case IXC_SATA:
			opv5xc_cacheable_enable(peri_id);
			break;
                case IXC_GDMA:
                        break;
		case IXC_USB3H:
			opv5xc_cacheable_enable(peri_id);
			opv5xc_bufferable_enable(peri_id);
			opv5xc_buffer_enable(peri_id);
			break;
		case IXC_USB3DRD:
			opv5xc_cacheable_enable(peri_id);
			opv5xc_bufferable_enable(peri_id);
			opv5xc_buffer_enable(peri_id);
			break;
		case IXC_PCIE_DM:
			opv5xc_cacheable_enable(peri_id);
			opv5xc_bufferable_enable(peri_id);
			opv5xc_buffer_enable(peri_id);
			break;
		case IXC_PCIE_RC:
			opv5xc_cacheable_enable(peri_id);
			opv5xc_bufferable_enable(peri_id);
			opv5xc_buffer_enable(peri_id);
			break;
		default:
			opv5xc_sec_enable(peri_id);
			opv5xc_sec_mod_enable(peri_id);
			opv5xc_cacheable_enable(peri_id);
			opv5xc_bufferable_enable(peri_id);
			opv5xc_buffer_enable(peri_id);
			break;
	}

	reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_ACP_EN_OFFSET);
	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_ACP_EN_OFFSET);

	return 0;
}
EXPORT_SYMBOL(opv5xc_acp_enable);

/*
 *
 */
int opv5xc_acp_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg;

	opv5xc_sec_disable(peri_id);
	opv5xc_sec_mod_disable(peri_id);
	opv5xc_cacheable_disable(peri_id);
	opv5xc_bufferable_disable(peri_id);
	opv5xc_buffer_disable(peri_id);

	reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_ACP_EN_OFFSET);
	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_ACP_EN_OFFSET);

	return 0;
}
EXPORT_SYMBOL(opv5xc_acp_disable);

#elif defined(CONFIG_ARCH_OPV5XC_ES2)

/* security */
static void opv5xc_sec_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_EN_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_EN_OFFSET);
}

static void opv5xc_sec_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_EN_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_SEC_EN_OFFSET);
}

/* prot override */
static void opv5xc_prot_override_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_PROT_OVRD_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_PROT_OVRD_OFFSET);
}

static void opv5xc_prot_override_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_PROT_OVRD_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_PROT_OVRD_OFFSET);
}

/* write allocate */
static void opv5xc_write_allocate_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_WA_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_WA_OFFSET);
}

static void opv5xc_write_allocate_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_WA_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_WA_OFFSET);
}

/* read allocate */
static void opv5xc_read_allocate_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_RA_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_RA_OFFSET);
}

static void opv5xc_read_allocate_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_RA_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_RA_OFFSET);
}

/* cacheable override */
static void opv5xc_cache_override_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_CACHE_OVRD_OFFSET);

	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_CACHE_OVRD_OFFSET);
}

static void opv5xc_cache_override_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_CACHE_OVRD_OFFSET);

	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_CACHE_OVRD_OFFSET);
}

/*
 *
 */
int opv5xc_acp_enable(enum cr_ixc_peripheral peri_id)
{
	u32 reg;

	switch (peri_id) {
		case IXC_CRYPTO:
			opv5xc_cache_override_enable(peri_id);
			opv5xc_write_allocate_enable(peri_id);
			opv5xc_read_allocate_enable(peri_id);
			break;

                case IXC_GDMA:
                        break;

		case IXC_PCIE_DM:
			opv5xc_write_allocate_enable(peri_id);
			opv5xc_read_allocate_enable(peri_id);
			opv5xc_cache_override_enable(peri_id);
			break;

		case IXC_PCIE_RC:
			opv5xc_write_allocate_enable(peri_id);
			opv5xc_read_allocate_enable(peri_id);
			opv5xc_cache_override_enable(peri_id);
			break;

		case IXC_USB3DRD:
			opv5xc_cache_override_enable(peri_id);
			opv5xc_write_allocate_enable(peri_id);
			opv5xc_read_allocate_enable(peri_id);
			break;

		case IXC_USB3H:
			opv5xc_cache_override_enable(peri_id);
			opv5xc_write_allocate_enable(peri_id);
			opv5xc_read_allocate_enable(peri_id);
			break;

		case IXC_NFMC:
			break;

		case IXC_SDIO:
			opv5xc_write_allocate_enable(peri_id);
			opv5xc_read_allocate_enable(peri_id);
			opv5xc_cache_override_enable(peri_id);
			break;

		default:
			opv5xc_sec_enable(peri_id);
			opv5xc_prot_override_enable(peri_id);
			opv5xc_write_allocate_enable(peri_id);
			opv5xc_read_allocate_enable(peri_id);
			opv5xc_cache_override_enable(peri_id);
			break;
	}

	reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_ACP_EN_OFFSET);
	reg |= 1 << peri_id;
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_ACP_EN_OFFSET);

	return 0;
}
EXPORT_SYMBOL(opv5xc_acp_enable);

/*
 *
 */
int opv5xc_acp_disable(enum cr_ixc_peripheral peri_id)
{
	u32 reg;

	opv5xc_sec_disable(peri_id);
	opv5xc_prot_override_disable(peri_id);
	opv5xc_write_allocate_disable(peri_id);
	opv5xc_read_allocate_disable(peri_id);
	opv5xc_cache_override_disable(peri_id);

	reg = __raw_readl(OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_ACP_EN_OFFSET);
	reg &= ~(1 << peri_id);
	__raw_writel(reg, OPV5XC_CR_IXC_BASE_VIRT + CR_IXC_ACP_EN_OFFSET);

	return 0;
}
EXPORT_SYMBOL(opv5xc_acp_disable);

#endif
/* To remove compilation warnings, if kernel PCI config option 'CONFIG_PCI'
   is not selected */
#ifdef CONFIG_PCI
static int pci_notify(struct notifier_block *nb, unsigned long action,
                      void *data)
{
        struct device *dev = data;

        if (action != BUS_NOTIFY_ADD_DEVICE)
                return NOTIFY_DONE;

        set_dma_ops(dev, &arm_coherent_dma_ops);

        return NOTIFY_OK;

}
static struct notifier_block pci_notifier = {
        .notifier_call = pci_notify,
};

void opv5xc_pcie_acp_init(void)
{
        bus_register_notifier(&pci_bus_type, &pci_notifier);
}
#endif
