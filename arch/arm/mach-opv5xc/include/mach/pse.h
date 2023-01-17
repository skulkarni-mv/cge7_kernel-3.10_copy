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

#ifndef _MACH_PSE_H_
#define _MACH_PSE_H_

#include <linux/etherdevice.h>

#if defined(CONFIG_OPV5XC_PSE) || defined(CONFIG_OPV5XC_PSE_MODULE)
#define OPV5XC_MAC_MAX CONFIG_OPV5XC_PSE_NR_MAC_PORTS
#else
#define OPV5XC_MAC_MAX	0
#endif
#define OPV5XC_PSE_PORT_MAC0	(0)
#define OPV5XC_PSE_PORT_MAC1	(1)
#define OPV5XC_PSE_PORT_CPU	(2)
#define OPV5XC_PSE_PORT_PPE	(3)
#define OPV5XC_PSE_PORT_MAC2	(4)
#define OPV5XC_PSE_PORT_CFP	(5)

#define OPV5XC_PSE_PMAP_MAC0	(0x01)
#define OPV5XC_PSE_PMAP_MAC1	(0x02)
#define OPV5XC_PSE_PMAP_CPU	(0x04)
#define OPV5XC_PSE_PMAP_PPE	(0x08)
#define OPV5XC_PSE_PMAP_MAC2	(0x10)

#define OPV5XC_PSE_SPEED_1000	(2)
#define OPV5XC_PSE_SPEED_100	(1)
#define OPV5XC_PSE_SPEED_10	(0)

#define OPV5XC_PSE_DUPLEX_FULL	(1)
#define OPV5XC_PSE_DUPLEX_HALF	(0)

#define OPV5XC_PSE_NR_RING	(16)
#define OPV5XC_PSE_NR_TC	(8)

struct pse_mac_data {
	int sp;
	int enable;
	int giga_mode;
	int rgmii;
	int wan_port;
	int has_phy;
	int phy_addr;
	/* if rgmii */
	/* TBD delay for rgmii*/
	int txc_dly;
	int rxc_dly;

	/* if !has_phy */
	int force_speed;
	int force_duplex;
	int force_fc_tx;
	int force_fc_rx;
};

struct pse_platform_data {
	struct pse_mac_data port[OPV5XC_MAC_MAX];
};

#define SW_FP_RING_MAX (16 - OPV5XC_MAC_MAX)
#define SW_FP_RING_SZ (128)
#define SW_FP_PMAP (0x8)
#define SW_FP_DEV_MAX (16) /* PPE just support 16 id, DO NOT change this definition */

int is_pse_dev(struct net_device *dev);
void pse_cfp_port_cfg(bool en);
bool pse_cfp_port_en(void);
u32 pse_func_status(void);

#endif /* #ifndef _MACH_PSE_H_ */
