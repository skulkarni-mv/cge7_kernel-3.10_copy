/**************************************************************************
 * Copyright 2014, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfmcastnapi.c
 *
 * Description: NAPI infra for OSPF packet packet processing in ASF
 *
 * Authors:	Sridhar Pothuganti <sridhar.pothuganti@freescale.com>
 *
 */
/* History
 *  Version	Date		Author			Change Description
 *    1.0	04/04/2014	Sridhar Pothuganti	Initial Development
*/
/****************************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/spinlock_types.h>
#include <linux/netdevice.h>
#include <linux/cpumask.h>

#include "asfmcastnapi.h"
#include "asfmpool.h"
#include "asf.h"
#include "asfcmn.h"

struct napi_struct   napi;

LIST_HEAD(asf_mcast_napi_skb_list_head);

spinlock_t asf_mcast_napi_skb_list_lock;

static unsigned int mcast_napi_pool_id = -1;

int ASFProcessMcastPkts(struct sk_buff *skb);
int napi_schedule_cpu_any(struct napi_struct *napi);

/*#define ASF_MCAST_NAPI_DEBUG 1*/

#if defined(ASF_DEBUG) || defined(ASF_MCAST_NAPI_DEBUG)
#define asf_mcast_napi_debug(fmt, arg...)  \
	printk(KERN_INFO"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), __LINE__, __func__, ##arg)
#elif defined(ASF_DYNAMIC_DEBUG)
#define asf_mcast_napi_debug asf_debug
#else
#define asf_mcast_napi_debug(fmt, arg...)
#endif

struct cpumask cpumask;
extern cpumask_var_t cpu_isolated_map;

void asf_mcast_dplane_cpumask_init(void)
{
	asf_mcast_napi_debug("ENTRY\r\n");

	if (*(cpumask_bits(cpu_isolated_map))) {
		asf_mcast_napi_debug("Setting isolated cpumask\n");
		cpumask_copy(&cpumask, cpu_isolated_map);
	} else {
		asf_mcast_napi_debug("Setting online cpumask\n");
		cpumask_copy(&cpumask, cpu_online_mask);
	}

	asf_mcast_napi_debug("EXIT\r\n");
}

int asf_mcast_napi_init(void)
{
	struct net_device *dev;
	dev = dev_get_by_name(&init_net, "lo");

	netif_napi_add(dev, &napi, asf_mcast_napi_poll, ASF_MCAST_NAPI_BUDGET);
	napi_enable(&napi);

	asf_mcast_napi_debug("NAPI Initialized\r\n");

	spin_lock_init(&asf_mcast_napi_skb_list_lock);
	if (asfCreatePool("ospf_napi_pool", ASF_MAX_NAPI_SKB_NODES, ASF_MAX_NAPI_SKB_NODES, ASF_MAX_NAPI_SKB_NODES/2, \
			sizeof(asf_mcast_napi_skb_list_t), &mcast_napi_pool_id)) {
		asf_mcast_napi_debug("failed to initialize ospf_napi_pool\n");
		return -ENOMEM;
	}

	asf_mcast_dplane_cpumask_init();

	return 0;
}

void asf_mcast_napi_deinit(void)
{
	napi_disable(&napi);
	netif_napi_del(&napi);

	asf_mcast_napi_debug("DestroyPool ospf_napi_pool\n");
	if (asfDestroyPool(mcast_napi_pool_id) != 0)
		asf_mcast_napi_debug("failed to destroy flow mpool\n");

	asf_mcast_napi_debug("NAPI Deinitialized\r\n");
}

int asf_mcast_napi_poll(struct napi_struct *napi, int budget)
{
	asf_mcast_napi_skb_list_t *pNode, *tmp;
	struct sk_buff *skb;
	int pkts_processed = 0;

	asf_mcast_napi_debug("Entry\r\n");

	spin_lock_bh(&asf_mcast_napi_skb_list_lock);
	list_for_each_entry_safe(pNode, tmp, &asf_mcast_napi_skb_list_head, list) {

		list_del(&pNode->list);

		skb = pNode->skb;
		asfReleaseNode(mcast_napi_pool_id, pNode, pNode->bHeap);

		asf_mcast_napi_debug("Calling ASFProcessMcastPkts\r\n");
		ASFProcessMcastPkts(skb);
		pkts_processed++;

		if (unlikely(pkts_processed >= budget))
			break;
	}
	spin_unlock_bh(&asf_mcast_napi_skb_list_lock);

	asf_mcast_napi_debug("Number of Packets Pracessed %d\r\n", pkts_processed);

	if (pkts_processed < budget || list_empty(&asf_mcast_napi_skb_list_head)) {
		asf_mcast_napi_debug("NAPI Complete\r\n");
		napi_complete(napi);
	} else {
		asf_mcast_napi_debug("NAPI Reschedule\r\n");
		napi_reschedule(napi);
	}

	asf_mcast_napi_debug("EXIT\r\n");
	return pkts_processed;
}

int asf_mcast_napi_send_packet(struct sk_buff *skb)
{
	asf_mcast_napi_skb_list_t *pNode;
	char bHeap;

	asf_mcast_napi_debug("Entry\r\n");

	pNode = (asf_mcast_napi_skb_list_t *) asfGetNode(mcast_napi_pool_id, &bHeap);

	if (pNode && bHeap)
		pNode->bHeap = bHeap;

	pNode->skb = skb;

	INIT_LIST_HEAD(&pNode->list);

	asf_mcast_napi_debug("Putting skb in Q\r\n");

	spin_lock_bh(&asf_mcast_napi_skb_list_lock);
	list_add_tail(&pNode->list, &asf_mcast_napi_skb_list_head);
	spin_unlock_bh(&asf_mcast_napi_skb_list_lock);

	asf_mcast_napi_debug("Scheduling NAPI\r\n");

#if 0
	/*Scheduling NAPI on current core*/
	if (likely(napi_schedule_prep(&napi))) {
		__napi_schedule(&napi);
		asf_mcast_napi_debug("NAPI Scheduled\r\n");
		return 0;
	} else {
		asf_mcast_napi_debug("Unable to Schedule NAPI\r\n");
		return -EAGAIN;
	}
#endif

	/*Scheduling NAPI on perticular core core*/
	napi_schedule_cpu_any(&napi);
	asf_mcast_napi_debug("EXIT\r\n");
	return 0;
}
EXPORT_SYMBOL(asf_mcast_napi_send_packet);

static void net_napi_backlog(void *data)
{
	asf_mcast_napi_debug("ENTRY\r\n");
	struct napi_struct *napi = (struct napi_struct *)data;
	napi_schedule(napi);
	asf_mcast_napi_debug("EXIT\r\n");
}

int napi_schedule_cpu_any(struct napi_struct *napi)
{
	asf_mcast_napi_debug("ENTRY\r\n");

	asf_mcast_napi_debug("Scheduling NAPI on isolated cores\r\n");
	smp_call_function_any(&cpumask, net_napi_backlog, napi, 0);
	asf_mcast_napi_debug("EXIT\r\n");
	return 0;
}
