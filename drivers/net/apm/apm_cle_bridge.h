/**
 * AppliedMicro APM862xx SoC Ethernet Driver
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
 * All rights reserved. Pranavkumar Sawargaonkar <psawargaonkar@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * @file apm_cle_bridge.h
 *
 *
 */

#ifndef __APM_CLE_BRIDGE_H_
#define __APM_CLE_BRIDGE_H_

#include "apm_preclass_data.h"

#undef DBG_CLE_BR_ERR
#undef DBG_CLE_BR_PRINTS
#undef DBG_CLE_BR_FDB_PRINTS
#undef APM_CLE_TEST_BR

#if defined(DBG_CLE_BR_ERR)
#define CLE_BR_ERR(x, ...)       printk(KERN_ERR x, ##__VA_ARGS__)
#else
#define CLE_BR_ERR(x, ...)
#endif

#if defined(DBG_CLE_BR_PRINTS)
#define CLE_BR_DBG(x, ...)       printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define CLE_BR_DBG(x, ...)
#endif

#if defined(DBG_CLE_BR_FDB_PRINTS)
#define CLE_BR_FDB_DBG(x, ...)       printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define CLE_BR_FDB_DBG(x, ...)
#endif

#define	APM_CLE_BR_DRIVER_NAME	"apm_cle_bridge"

#define MAX_AVL_ENTRIES AVL_SSIZE8B_DPTH
//XXX: Review
/* #define IFF_BRIDGE_PORT 0x8000*/
#define DEFAULT_BR_PRI  0

#define CMD_DISABLE_CLE_BR	'0'
#define CMD_ENABLE_CLE_BR	'1'

int apm_addbr_port(struct net_device *dev);
int apm_delbr_port(struct net_device *dev);
int apm_addbr_fdb(struct net_device *dst_dev, struct net_device *src_dev, const unsigned char *dst_addr, const unsigned char *src_addr);
int apm_delbr_fdb(struct net_device *dev, const unsigned char *addr);
#endif /* __APM_CLE_BRIDGE_H_ */
