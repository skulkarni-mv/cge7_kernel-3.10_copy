/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	gplcode.h
 * Description: IPv4 Options handling related function definations.
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
 * 22-Jul-2011  Sachin Saxena  Changes to introduce ASF tool kit support.
*/
/****************************************************************************/


#ifndef __ASF_GPL_CODE_H
#define __ASF_GPL_CODE_H
#include "asf.h"
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <dpa1p8/dpaa_eth_common.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define asfAllocPerCpu(size)	__alloc_percpu(size, 4)
#define asfFreePerCpu(ptr)	free_percpu(ptr)
#define asfPerCpuPtr(ptr, cpu)	per_cpu_ptr(ptr, cpu)

#ifdef CONFIG_DPA
#define devfp_register_hook(rx_hook, tx_hook) {				\
	struct dpaa_eth_hooks_s hooks = {};				\
	hooks.rx_default = (dpaa_eth_ingress_hook_t)rx_hook;		\
	hooks.tx =  (dpaa_eth_egress_hook_t)tx_hook;			\
	fsl_dpaa_eth_set_hooks(&hooks);					\
}

#define AS_FP_PROCEED	DPAA_ETH_CONTINUE
#define AS_FP_STOLEN	DPAA_ETH_STOLEN

#else
#define devfp_register_hook(rx_hook, tx_hook) {	\
	devfp_register_rx_hook(rx_hook);	\
	devfp_register_tx_hook(tx_hook);	\
}
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM) || defined(CONFIG_DPA)
#define asfDevHardXmit(dev, skb)	(dev->netdev_ops->ndo_start_xmit(skb, dev))
#else
extern int gfar_fast_xmit(struct sk_buff *skb, struct net_device *dev);
#define asfDevHardXmit(dev, skb)	(gfar_fast_xmit(skb, dev))
#endif

#else

#define asfAllocPerCpu(size)	percpu_alloc(size, GFP_KERNEL)
#define asfFreePerCpu(ptr)	percpu_free(ptr)
#define asfPerCpuPtr(ptr, cpu)	percpu_ptr(ptr, cpu)
#define asfDevHardXmit(dev, skb)	(dev->hard_start_xmit(skb, dev))
#endif



void asf_ip_options_fragment(struct sk_buff  *skb);
int asf_ip_options_compile(struct net *net,
				struct ip_options  *opt,
				struct sk_buff  *skb,
				struct iphdr *ipheader);


#ifdef ASF_TOOLKIT_SUPPORT
extern void gfar_config_afx(struct net_device *dev, unsigned int reg);

extern void gfar_config_filer(struct net_device *dev,
				unsigned int rqfar,
				unsigned int rqfcr,
				unsigned int rqfpr);

extern void gfar_get_filer(struct net_device *dev,
			unsigned int far,
			unsigned int *fcr,
			unsigned int *fpr);
#endif

#endif

