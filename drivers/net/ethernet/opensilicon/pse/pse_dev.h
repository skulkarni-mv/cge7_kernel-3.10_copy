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

#ifndef _PSE_DEV_H_
#define _PSE_DEV_H_

#include <linux/platform_device.h>
#include <linux/vmalloc.h>
#include <linux/etherdevice.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/if_vlan.h>
#include <mach/opv5xc.h>
#include <mach/pse.h>
#include <net/ip.h>
#include <net/udp.h>
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/ipv6.h>
#endif

#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#define PSE_VLAN_SUPPORT
#endif

#define PSE_CHECKSUM_OFFLOAD
#define PSE_LSO_SUPPORT

#ifdef PSE_LSO_SUPPORT
#define PSE_SG_SUPPORT
#define PSE_TSO_SUPPORT
#define PSE_UFO_SUPPORT
#ifdef CONFIG_ARCH_OPV5XC_CX4
#define PSE_TSO_EN_DEFAULT	(false)
#define PSE_UFO_EN_DEFAULT	(false)
#else
#define PSE_TSO_EN_DEFAULT	(true)
#define PSE_UFO_EN_DEFAULT	(true)
#endif
#endif

#ifdef PSE_UFO_SUPPORT
#undef UFO_IGNORE_UDP_CHECKSUM
#endif

#define PSE_MAX_DEV_NUM OPV5XC_MAC_MAX
#define PSE_MAX_FS_RING_NUM	(16)
#define PSE_MAX_TS_RING_NUM	(16)
#define PSE_INTR_GROUP_NUM     (4)

#define PSE_SUPPORT_MQ /* Note : Only PSE_ONLY_PROM support 16 ring */
#undef PSE_SUPPORT_MQ

#ifdef PSE_SUPPORT_MQ
/*
 * MAC0
 *  FS_RING
 *    Q0->Ring0 Q1->Ring1 Q2->Ring2  Q3->Ring3  Q4->Ring4  Q5->Ring5  Q6->Ring6  Q7->Ring7
 *  TS_RING
 *    Ring 0-7
 * MAC1
 *  FS_RING
 *    Q0->Ring8 Q1->Ring9 Q2->Ring10 Q3->Ring11 Q4->Ring12 Q5->Ring13 Q6->Ring14 Q7->Ring15
 *  TS_RING
 *    Ring 8-15
 */
#define PSE_MAX_RX_QUEUE	8
#define PSE_MAX_TX_QUEUE	8
#else
/*
 * MAC0
 *  FS_RING
 *    Q0->Ring0 Q1->Ring0 Q2->Ring0 Q3->Ring0 Q4->Ring0 Q5->Ring0 Q6->Ring0 Q7->Ring0
 *  TS_RING
 *    Ring 0
 * MAC1
 *  FS_RING
 *    Q0->Ring1 Q1->Ring1 Q2->Ring1 Q3->Ring1 Q4->Ring1 Q5->Ring1 Q6->Ring1 Q7->Ring1
 *  TS_RING
 *    Ring 1
 */
#define PSE_MAX_RX_QUEUE	1
#define PSE_MAX_TX_QUEUE	1
#endif

#if defined(CONFIG_SMP)
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
#define PSE_INTR_ASSIGN_CORE
#endif
#endif

struct pse_resource {
	struct platform_device *pdev;
	struct mii_bus *mii_bus;
	void __iomem *base;
	void __iomem *base_fast;
	u32 irq_start;
	u32 irq_end;
	struct net_device *ndev[PSE_MAX_DEV_NUM];
	struct net_device *fp_ndev;
	struct pse_ring *rx_ring[PSE_MAX_FS_RING_NUM];
	struct pse_ring *tx_ring[PSE_MAX_TS_RING_NUM];

	spinlock_t fs_intr_lock;
	spinlock_t ts_intr_lock;
	spinlock_t lro_intr_lock;
	u32 fs_intr_group[PSE_INTR_GROUP_NUM];
	u32 ts_intr_group[PSE_INTR_GROUP_NUM];
	u32 lro_intr_group[PSE_INTR_GROUP_NUM];
};

/* board specific private data structure */
struct pse_priv {
	struct pse_ring *rx_ring[PSE_MAX_RX_QUEUE];
	struct pse_ring *tx_ring[PSE_MAX_TX_QUEUE];
	struct net_device *netdev;
	struct net_device_stats net_stats;

	struct vlan_group *vlgrp;

	struct phy_device *phy_dev;

	u32 link;
	u32 link_speed;
	u32 link_duplex;

	u32 phy_addr;	/* PHY address */

	u8 sp;		/* source port */
	u8 index;	/* index of PSE device */

	struct pse_resource *res;
	u32 pse_flags;

	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];
	u32 wan_port;
};
#endif /* _PSE_DEV_H_ */
