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

#ifndef _OPV5XC_CR_IXC_H
#define _OPV5XC_CR_IXC_H

enum cr_ixc_peripheral;

#if defined(CONFIG_ARCH_OPV5XC_ES1)

#define CR_IXC_ACP_EN_OFFSET		0x00

#define CR_IXC_SEC_EN_OFFSET		0x08
#define CR_IXC_SEC_MOD_OFFSET		0x0C
#define CR_IXC_CACHEABLE_OFFSET		0x10
#define CR_IXC_BUFFERABLE_OFFSET	0x14
#define CR_IXC_BUF_EN_OFFSET		0x18

enum cr_ixc_peripheral {
	IXC_CRYPTO = 2,
	IXC_GDMA,
	IXC_PCIE_DM,
	IXC_PCIE_RC,
	IXC_PPE_PSE,
	IXC_RAID,
	IXC_SATA,
	IXC_USB3H,
	IXC_USB3DRD,
	IXC_SDIO,
	IXC_NFMC
};

#elif defined(CONFIG_ARCH_OPV5XC_ES2)

#define CR_IXC_ACP_EN_OFFSET		0x00

#define CR_IXC_SEC_EN_OFFSET		0x08
#define CR_IXC_PROT_OVRD_OFFSET		0x0C
#define CR_IXC_WA_OFFSET		0x10
#define CR_IXC_RA_OFFSET		0x14
#define CR_IXC_CACHE_OVRD_OFFSET	0x18

enum cr_ixc_peripheral {
	IXC_CRYPTO = 2,
	IXC_GDMA,
	IXC_PCIE_DM,
	IXC_PCIE_RC,
	IXC_PPE_PSE,
	IXC_USB3DRD,
	IXC_USB3H,
	IXC_NFMC,
	IXC_SDIO
};

#endif

extern int opv5xc_acp_enable(enum cr_ixc_peripheral peri_id);
extern int opv5xc_acp_disable(enum cr_ixc_peripheral peri_id);
extern void opv5xc_pcie_acp_init(void);
#endif /* _OPV5XC_CR_IXC_H */
