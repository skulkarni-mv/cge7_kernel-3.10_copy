/**
 * AppliedMicro APM86xxx SoC IPv4 Forward Offload Classifier Driver
 *
 * Copyright (c) 2012 Applied Micro Circuits Corporation.
 * All rights reserved. Ravi Patel <rapatel@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * @file apm_cle_ifo.c
 *
 * This file implements Classifier configurations in use by IPv4 Forward Offload driver.
 *
 */

#include <linux/etherdevice.h>
#include <net/route.h>

#include "apm_enet_offload.h"
#include "apm_cle_ifo.h"

static int ipv4fwd_offload_init_done[MAX_PORTS] = {0};
static struct list_head ipv4fwd_gateway = {0};
static struct list_head ipv4fwd_result_ptr_index[MAX_CLE_ENGINE] = {{0}};
static struct eth_queue_ids *iport_qm_queue[MAX_PORTS] = {0};
static u8 offloader_rx_qid[MAX_PORTS] = {0};

static inline void apm_ipv4fwd_offload_list_entry(void)
{
	static int ipv4fwd_offload_list_init_done = 0;

	/* First time access to gateway list */
	if (!ipv4fwd_offload_list_init_done) {
		INIT_LIST_HEAD(&ipv4fwd_gateway);
		INIT_LIST_HEAD(&ipv4fwd_result_ptr_index[0]);
#ifndef CONFIG_APM862xx
		INIT_LIST_HEAD(&ipv4fwd_result_ptr_index[1]);
#endif
		ipv4fwd_offload_list_init_done = 1;
	}
}

static struct apm_enet_offload_list *apm_get_arp(__be32 rt_gateway, int eport, int mk_entry)
{
	struct list_head *ipv4fwd_gw_head = &ipv4fwd_gateway;
	struct apm_enet_offload_list *ipv4fwd_gw_entry = NULL;
	u32 key[OFFLOAD_KEY_SIZE];

	/* Invalid gateway list */
	if (INVALID_LIST_HEAD(ipv4fwd_gw_head)) {
		ENET_ERROR_OFFLOAD("%s: invalid gateway list\n", __func__);
		goto _ret_get_arp;
	}

	/* Find gateway entry from gateway list */
	key[0] = rt_gateway; /* Gateway IP */
	key[1] = OFFLOAD_EPN(eport); /* Egress Port Number */
	key[2] = 0;
	ipv4fwd_gw_entry = apm_find_enet_offload_entry(ipv4fwd_gw_head, key);

	/* If gateway entry found, get route list from gateway entry */
	if (ipv4fwd_gw_entry) {
		/* If IPv4 Forward Egress Port number is not in Any Ethernet Port number range, update IPv4 Forward Egress Port number */
		if (ETH_ANY_PORT_ERR(ipv4fwd_gw_entry->ipv4fwd->eport))
			ipv4fwd_gw_entry->ipv4fwd->eport = eport;
	/* If gateway entry not found and mk_route, make gateway entry in gateway list & init route list */
	} else if (mk_entry) {
		struct list_head *ipv4fwd_rt_head;

		ipv4fwd_gw_entry = apm_add_enet_offload_entry(ipv4fwd_gw_head, key,
					sizeof(struct apm_ipv4fwd_info));
		/* If unable to make gateway entry in gateway list, return error */
		if (ipv4fwd_gw_entry == NULL) {
			ENET_ERROR_OFFLOAD("%s: unable to create arp entry\n", __func__);
			goto _ret_get_arp;
		}
		apm_ethoffload_ops.ifo_arp_unuse_entries++;
		ipv4fwd_rt_head = &ipv4fwd_gw_entry->ipv4fwd->rt_head;
		INIT_LIST_HEAD(ipv4fwd_rt_head);
		ipv4fwd_gw_entry->ipv4fwd->iport = INVALID_32BIT_INDEX;
		/* Update IPv4 Forward Egress Port number */
		ipv4fwd_gw_entry->ipv4fwd->eport = eport;
	}

_ret_get_arp:
	return ipv4fwd_gw_entry;
}

static int apm_add_route(int iport,
	struct apm_enet_offload_list *ipv4fwd_gw_entry,
	struct apm_enet_offload_list *ipv4fwd_rt_entry)
{
	int rc = APM_RC_OK;
	struct avl_node node;
	struct apm_ipv4fwd_info *ipv4fwd = ipv4fwd_gw_entry->ipv4fwd;
	int cid;

	cid = CID_INT_PORT(iport);
	/* If gateway index (dbptr index) invalid, skip adding route entry (avl entry) to CLE & return CLE_MISS indication */
	if (ipv4fwd_gw_entry->index_cle[cid] == INVALID_16BIT_INDEX) {
		ENET_DEBUG_OFFLOAD("dbptr index invalid, skipping avl_add_node\n");
		rc = APM_RC_CLE_MISS;
		goto _ret_add_route;
	}

	/* If route index (avl index) valid, skip adding route entry (avl entry) to CLE */
	if (ipv4fwd_rt_entry->index_cle[cid] != INVALID_16BIT_INDEX) {
		ENET_DEBUG_OFFLOAD("avl already added at index %d, skipping avl_add_node\n",
			ipv4fwd_rt_entry->index_cle[cid]);
		goto _ret_add_route;
	}

	/* If number of route entries (avl entries) programmed equal to MAX possible entries, skip add_route */
	if (apm_ethoffload_ops.ipv4_route_cache_entries_cle[cid] >= AVL_NODES_PER_SYSTEM) {
		ENET_ERROR_OFFLOAD("No AVL Nodes left to add !!\n");
		rc = APM_RC_ERROR;
		goto _ret_add_route;
	}

	memset(&node, 0, sizeof(node));
	node.search_key[0] = ipv4fwd_rt_entry->key[0];
	node.search_key[1] = ipv4fwd_rt_entry->key[1];
	node.priority = 0;
	node.result_pointer = ipv4fwd_gw_entry->index_cle[cid];
	if (apm_cle_avl_add_node(CLE_INT_PORT(iport), &node)) {
		ENET_ERROR_OFFLOAD("apm_cle_avl_add_node failed !!\n");
		rc = APM_RC_ERROR;
		goto _ret_add_route;
	}

	ENET_DEBUG_OFFLOAD("added AVL Entry at node %d using result pointer %d\n",
				node.index, node.result_pointer);
	/* Route entry (avl entry) is added to a CLE so increment route_cache_entries_cle count for that CLE */
	apm_ethoffload_ops.ifo_route_cache_entries_cle[cid]++;
	apm_ethoffload_ops.ipv4_route_cache_entries_cle[cid]++;
	/* Route entry (avl entry) is added to a CLE with referenced ARP entry, so increment ref_count_cle for that CLE */
	ipv4fwd->ref_count_cle[cid]++;

	/* If the route is being added first time to any CLE, decrement route_unuse_entries */
	if (ipv4fwd_rt_entry->index == INVALID_32BIT_INDEX)
		apm_ethoffload_ops.ifo_route_unuse_entries--;

	/* Save CLE route index (avl index) to indicate route entry added-present in that CLE  */
	ipv4fwd_rt_entry->index_cle[cid] = node.index;

_ret_add_route:
	return rc;
}

static int apm_del_route(int iport,
	struct apm_enet_offload_list *ipv4fwd_gw_entry,
	struct apm_enet_offload_list *ipv4fwd_rt_entry)
{
	int rc = APM_RC_OK;
	struct avl_node node;
	struct apm_ipv4fwd_info *ipv4fwd = ipv4fwd_gw_entry->ipv4fwd;
	int cid;

	cid = CID_INT_PORT(iport);
	/* If route index (avl index) invalid, skip deleting route entry (avl entry) from CLE */
	if (ipv4fwd_rt_entry->index_cle[cid] == INVALID_16BIT_INDEX) {
		ENET_DEBUG_OFFLOAD("avl already deleted, skipping avl_del_node\n");
		goto _skip_del_route;
	}

	memset(&node, 0, sizeof(node));
	node.search_key[0] = ipv4fwd_rt_entry->key[0];
	node.search_key[1] = ipv4fwd_rt_entry->key[1];
	if (apm_cle_avl_del_node(CLE_INT_PORT(iport), &node)) {
		ENET_ERROR_OFFLOAD("apm_cle_avl_del_node failed !!\n");
		rc = APM_RC_ERROR;
		goto _ret_del_route;
	}

	ENET_DEBUG_OFFLOAD("deleted AVL Entry at node %d\n", node.index);

	/* Route entry (avl entry) is deleted from a CLE so decrement route_cache_entries_cle count for that CLE if non-zero */
	if (apm_ethoffload_ops.ifo_route_cache_entries_cle[cid]) {
		apm_ethoffload_ops.ifo_route_cache_entries_cle[cid]--;
		apm_ethoffload_ops.ipv4_route_cache_entries_cle[cid]--;
	} else {
		ENET_ERROR_OFFLOAD("No AVL Nodes left to delete !!\n");
	}

	/* Route entry (avl entry) is deleted from a CLE with referenced ARP entry, so decrement ref_count_cle for that CLE if non-zero */
	if (ipv4fwd->ref_count_cle[cid]) {
		ipv4fwd->ref_count_cle[cid]--;
	} else {
		ENET_ERROR_OFFLOAD("No DBPTR reference left to decrement !!\n");
	}

	/* Clear/Invalidate CLE route index (avl index) to indicate route entry deleted-absent in that CLE  */
	ipv4fwd_rt_entry->index_cle[cid] = INVALID_16BIT_INDEX;

	/* If CLE route index (avl index) is already cleared/invalidated in other CLE, increment unuse entry counter */
	if (ipv4fwd_rt_entry->index_cle[(!cid)] == INVALID_16BIT_INDEX)
		apm_ethoffload_ops.ifo_route_unuse_entries++;

_skip_del_route:
	/* If route entry not present in any CLE, remove route entry from route list */
	if (ipv4fwd_rt_entry->index == INVALID_32BIT_INDEX) {
		apm_del_enet_offload_entry(ipv4fwd_rt_entry);
		apm_ethoffload_ops.ifo_route_unuse_entries--;
	}

	/* If route list empty, check ref_count */
	if (list_empty(&ipv4fwd->rt_head)) {
		/* If ref_count is non-zero, indicate error */
		if (ipv4fwd->ref_count) {
			printk("Gateway IPv4 Route list empty but Gateway ref_count is non zero !!\n");
			ipv4fwd->ref_count = 0;
		}
	}
_ret_del_route:
	return rc;
}

static int apm_update_route(__be32 rt_dst, __be32 rt_src, __be32 rt_gateway,
	int eport, int iport, int mk_entry)
{
	int rc = APM_RC_ERROR;
	struct list_head *ipv4fwd_rt_head = NULL;
	struct apm_enet_offload_list *ipv4fwd_gw_entry;
	struct apm_enet_offload_list *ipv4fwd_rt_entry;
	u32 key[OFFLOAD_KEY_SIZE];

	ipv4fwd_gw_entry = apm_get_arp(rt_gateway, eport, mk_entry);
	/* If unable to create/retrieve gateway entry from gateway list, return error */
	if (ipv4fwd_gw_entry == NULL) {
		rc = APM_RC_ERROR;
		ENET_DEBUG_OFFLOAD("%s: unable to retrieve arp entry\n", __func__);
		goto _ret_update_route;
	}

	/* If IPv4 Forward Ingress Port number is not in Internal APM Ethernet Port number range, update IPv4 Forward Ingress Port number */
	if (ETH_INT_PORT_ERR(ipv4fwd_gw_entry->ipv4fwd->iport_cle[CID_INT_PORT(iport)]))
		ipv4fwd_gw_entry->ipv4fwd->iport_cle[CID_INT_PORT(iport)] = iport;

	ipv4fwd_rt_head = &ipv4fwd_gw_entry->ipv4fwd->rt_head;

	/* If rm_route and route list empty, return error */
	if (!mk_entry && list_empty(ipv4fwd_rt_head)) {
		ENET_DEBUG_OFFLOAD("%s: route list empty\n", __func__);
		goto _ret_update_route;
	}

	/* Find route entry from route list */
	key[0] = rt_src;     /* SRC IP */
	key[1] = rt_dst;     /* DST IP */
	key[2] = 0;
	ipv4fwd_rt_entry = (void *)apm_find_enet_offload_entry(ipv4fwd_rt_head, key);

	/* mk_route */
	if (mk_entry) {
		/* If route entry not found, make route entry in route list */
		if (ipv4fwd_rt_entry == NULL) {
			ipv4fwd_rt_entry = apm_add_enet_offload_entry(ipv4fwd_rt_head, key, 0);
			/* If unable to make route entry in route list, return error */
			if (ipv4fwd_rt_entry == NULL) {
				rc = APM_RC_ERROR;
				ENET_ERROR_OFFLOAD("%s: unable to create route entry\n", __func__);
				goto _ret_update_route;
			}
			apm_ethoffload_ops.ifo_route_unuse_entries++;
		}

		ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
			iport, offload_ndev[iport]->name, eport, offload_ndev[eport]->name);
		rc = apm_add_route(iport, ipv4fwd_gw_entry, ipv4fwd_rt_entry);
	/* rm_route and route entry found, remove route entry (avl entry) in CLE */
	} else if (ipv4fwd_rt_entry) {
		ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
			iport, offload_ndev[iport]->name, eport, offload_ndev[eport]->name);
		rc = apm_del_route(iport, ipv4fwd_gw_entry, ipv4fwd_rt_entry);
	}

_ret_update_route:
	return rc;
}

static int apm_add_arp(struct apm_enet_offload_list *ipv4fwd_gw_entry, u8 *rt_mac)
{
	int rc = APM_RC_OK;
	struct apm_cle_dbptr dbptr;
	struct apm_ipv4fwd_info *ipv4fwd = ipv4fwd_gw_entry->ipv4fwd;
	u8  *rt_mac_cle;
	int eport = ipv4fwd->eport;
	int iport;
	int cid = 0;
	int flag;

	/* add arp entry (dbptr entry) for both CLE (any Internal APM Ethernet Port iport)  */
_start_add_arp:
	iport = ipv4fwd->iport_cle[cid];

	if (iport == INVALID_16BIT_INDEX)
		goto _skip_add_arp;

	/* If IPv4 Forward Ingress Port number is not in Internal APM Ethernet Port number range, skip add_arp for that iport */
	if (ETH_INT_PORT_ERR(iport)) {
		ENET_DEBUG_OFFLOAD("iport index %x invalid, skipping add_arp\n", iport);
		goto _skip_add_arp;
	}

	/* If number of arp entries (dbptr entries) programmed equal to MAX possible entries, skip add_arp */
	if (apm_ethoffload_ops.ipv4_arp_cache_entries_cle[cid] >= DBPTR_PER_SYSTEM) {
		ENET_ERROR_OFFLOAD("No DBPTR left to add !!\n");
		goto _skip_add_arp;
	}

	rt_mac_cle = ipv4fwd->rt_mac_cle[cid];

	/* This indicates arp/gateway entry in CLE is already programmed/added with same MAC address */
	if (compare_ether_addr(rt_mac_cle, rt_mac) == 0) {
		ENET_DEBUG_OFFLOAD("%s: rt_mac for rt_gateway %d.%d.%d.%d eport %d (%s) "
			"already added to CLE %d\n", __func__,
			(ipv4fwd_gw_entry->key[0] & 0xFF000000) >> 24,
			(ipv4fwd_gw_entry->key[0] & 0x00FF0000) >> 16,
			(ipv4fwd_gw_entry->key[0] & 0x0000FF00) >>  8,
			(ipv4fwd_gw_entry->key[0] & 0x000000FF) >>  0,
			eport, offload_ndev[eport]->name, cid);
		goto _skip_add_arp;
	}

	/* Set flag to indicate avl index (dbptr index) is not from un-used dbptr list */
	flag = APM_RC_ERROR;

	/* Configure dbptr */
	memset(&dbptr, 0, sizeof(dbptr));

	dbptr.index = ipv4fwd_gw_entry->index_cle[cid];

	/* If gateway index (dbptr index) invalid, try to get/alloc one */
	if (dbptr.index == INVALID_16BIT_INDEX) {
		/* Try to get previously allocated un-used dbptr from list */
		flag = apm_get_index(&ipv4fwd_result_ptr_index[cid], &dbptr.index);

		/* If all previously allocated dbptr are in use, allocate a new dbptr */
		if (flag != APM_RC_OK)
			dbptr.index = DBPTR_ALLOC(CLE_DB_INDEX);
	}

	/* offload enabled */
	dbptr.h0_en = 1;
	/* offload to perform */
	dbptr.h0_fpsel = APM_IPV4FWD_OFFLOAD;
	/* ingress Internal ENET port */
	dbptr.h1_hr = 1;
	/* H1DR:H1SZ (2 bits) specifies ingress Internal ENET port */
	dbptr.h1_dr = iport >> 1;
	dbptr.h1_sz = iport & 1;
	/* egress Internal ENET port */
	dbptr.h0_hr = 1;
	/* H1DR:H1SZ (2 bits) specifies egress Internal ENET port */
	dbptr.h0_dr = eport >> 1;
	dbptr.h0_sz = eport & 1;
	/*
	 * DST MAC Address (40 bits)
	 * byte 0 - h0_enqnum (8 bits)
	 * byte 1 - h0_info_msb (8 bits)
	 * bytes 2 to 5 - h0_info (32 bits)
	 */
	dbptr.h0_enqnum = rt_mac[0];
	dbptr.h0_info_msb = rt_mac[1];
	dbptr.h0_info = (rt_mac[2] << 24) |
			(rt_mac[3] << 16) |
			(rt_mac[4] <<  8) |
			(rt_mac[5] <<  0);

	dbptr.dstqid = offloader_rx_qid[CLE_INT_PORT(iport)];
	dbptr.fpsel  = iport_qm_queue[CLE_INT_PORT(iport)]->hw_fp_pbn - 0x20;

	ENET_DEBUG_OFFLOAD("%s: iport %d (%s) index %d dstqid %d fpsel %d "
			"h0_enqnum 0x%02x h0_info 0x%02x%08x\n",
			__func__, iport, offload_ndev[iport]->name,
			(dbptr.index == DBPTR_ALLOC(CLE_DB_INDEX) ? 0 : dbptr.index),
			dbptr.dstqid, dbptr.fpsel,
			dbptr.h0_enqnum, dbptr.h0_info_msb, dbptr.h0_info);

	if (apm_dbptr_alloc(CLE_INT_PORT(iport), 1, &dbptr)) {
		ENET_ERROR_OFFLOAD("%s: apm_dbptr_alloc failed !!\n", __func__);
		/* If arp index (dbptr index) allocated from un-used dbptr list, put it back */
		if (flag == APM_RC_OK)
			apm_put_index(&ipv4fwd_result_ptr_index[cid], dbptr.index);

		rc |= APM_RC_ERROR;
		goto _skip_add_arp;
	}

	/* Update the rt_mac_cle field to indicate rt_mac programmed/added in that CLE */
	memcpy(rt_mac_cle, rt_mac, IFHWADDRLEN);

	/* If the gateway is being added first time to any CLE, decrement arp_unuse_entries */
	if (ipv4fwd_gw_entry->index == INVALID_32BIT_INDEX)
		apm_ethoffload_ops.ifo_arp_unuse_entries--;

	/* ARP entry (dbptr entry) is added to a CLE so increment arp_cache_entries_cle count for that CLE */
	if (ipv4fwd_gw_entry->index_cle[cid] == INVALID_16BIT_INDEX) {
		apm_ethoffload_ops.ifo_arp_cache_entries_cle[cid]++;
		apm_ethoffload_ops.ipv4_arp_cache_entries_cle[cid]++;
	}

	/* Save CLE arp index (dbptr index) to indicate arp entry added-present in that CLE  */
	ipv4fwd_gw_entry->index_cle[cid] = dbptr.index;

	/*
	 * If ARP entry (dbptr entry) is not yet referenced by route entry (avl entry),
	 * add all route entries (avl entries) present in ipv4fwd_rt_head for the ipv4fwd_gw_entry
	 */
	if (!ipv4fwd->ref_count_cle[cid]) {

		struct apm_enet_offload_list *ipv4fwd_rt_entry;

		list_for_each_entry(ipv4fwd_rt_entry, &ipv4fwd->rt_head, node) {
			ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
				iport, offload_ndev[iport]->name, eport, offload_ndev[eport]->name);
			if (apm_add_route(iport, ipv4fwd_gw_entry, ipv4fwd_rt_entry)) {
				rc |= APM_RC_ERROR;
				goto _skip_add_arp;
			}
		}
	}

_skip_add_arp:
	cid++;

	/* Update for next CLE Engine */
	if (cid != MAX_CLE_ENGINE)
		goto _start_add_arp;

	return rc;
}

static int apm_del_arp(struct apm_enet_offload_list *ipv4fwd_gw_entry)
{
	int rc = APM_RC_OK;
	struct apm_cle_dbptr dbptr;
	struct apm_ipv4fwd_info *ipv4fwd = ipv4fwd_gw_entry->ipv4fwd;
	u8  *rt_mac_cle;
	int iport;
	int cid = 0;
	int flag;

	/* del arp entry (dbptr entry) for both CLE (any Internal APM Ethernet Port iport)  */
_start_del_arp:
	iport = ipv4fwd->iport_cle[cid];

	if (iport == INVALID_16BIT_INDEX)
		goto _skip_del_arp;

	/* If IPv4 Forward Ingress Port number is not in Internal APM Ethernet Port number range, skip del_arp for that iport */
	if (ETH_INT_PORT_ERR(iport)) {
		ENET_DEBUG_OFFLOAD("iport index %x invalid, skipping del_arp\n", iport);
		goto _skip_del_arp;
	}

	/* If arp index (dbptr index) invalid, skip deleting arp entry (route entry) from CLE */
	if (ipv4fwd_gw_entry->index_cle[cid] == INVALID_16BIT_INDEX) {
		ENET_DEBUG_OFFLOAD("dbptr already deleted, skipping del_arp\n");
		goto _skip_del_arp;
	}

	rt_mac_cle = ipv4fwd->rt_mac_cle[cid];

	/* This indicates arp/gateway entry in CLE is already un-programmed/deleted*/
	if (is_zero_ether_addr(rt_mac_cle)) {
		ENET_DEBUG_OFFLOAD("%s: rt_mac for rt_gateway %d.%d.%d.%d eport %d (%s) "
			"already deleted from CLE %d\n", __func__,
			(ipv4fwd_gw_entry->key[0] & 0xFF000000) >> 24,
			(ipv4fwd_gw_entry->key[0] & 0x00FF0000) >> 16,
			(ipv4fwd_gw_entry->key[0] & 0x0000FF00) >>  8,
			(ipv4fwd_gw_entry->key[0] & 0x000000FF) >>  0,
			ipv4fwd->eport, offload_ndev[ipv4fwd->eport]->name, cid);
		goto _skip_del_arp;
	}

	/* Set flag to indicate avl index (dbptr index) is not from un-used dbptr list */
	flag = APM_RC_ERROR;

	/* Configure dbptr */
	memset(&dbptr, 0, sizeof(dbptr));

	dbptr.index = ipv4fwd_gw_entry->index_cle[cid];

	/*
	 * If ARP entry (dbptr entry) is not yet referenced route entry (avl entry) or decremented to zero,
	 * put back arp index (dbptr index) to un-used dbptr list
	 */
	if (!ipv4fwd->ref_count_cle[cid]) {
		/* If arp index (dbptr index) de-allocation to un-used dbptr list failes, skip del_arp for that iport */
		if ((flag = apm_put_index(&ipv4fwd_result_ptr_index[cid], dbptr.index)) != APM_RC_OK) {
			ENET_ERROR_OFFLOAD("dbptr put_index %d failed for CLE %d, skipping del_arp\n",
				dbptr.index, cid);
			goto _skip_del_arp;
		}

		/* ARP entry (dbptr entry) will be deleted from a CLE so decrement arp_cache_entries_cle count for that CLE if non-zero */
		if (apm_ethoffload_ops.ifo_arp_cache_entries_cle[cid]) {
			apm_ethoffload_ops.ifo_arp_cache_entries_cle[cid]--;
			apm_ethoffload_ops.ipv4_arp_cache_entries_cle[cid]--;
		} else {
			ENET_ERROR_OFFLOAD("No DBPTR left to delete !!\n");
		}

		/* Clear/Invalidate CLE arp index (dbptr index) to indicate arp entry deleted-absent in that CLE  */
		ipv4fwd_gw_entry->index_cle[cid] = INVALID_16BIT_INDEX;

		/* If CLE arp index (dbptr index) is already cleared/invalidated in other CLE, increment unuse entry counter */
		if (ipv4fwd_gw_entry->index_cle[(!cid)] == INVALID_16BIT_INDEX)
			apm_ethoffload_ops.ifo_arp_unuse_entries++;

	/* If route list not empty, set dstqid to default_rx_qid */
	} else {
		dbptr.dstqid = iport_qm_queue[CLE_INT_PORT(iport)]->default_rx_qid;
		dbptr.fpsel  = iport_qm_queue[CLE_INT_PORT(iport)]->rx_fp_pbn - 0x20;
	}

	ENET_DEBUG_OFFLOAD("%s: iport %d (%s) index %d dstqid %d fpsel %d "
			"h0_enqnum 0x%02x h0_info 0x%02x%08x\n",
			__func__, iport, offload_ndev[iport]->name,
			dbptr.index, dbptr.dstqid, dbptr.fpsel,
			dbptr.h0_enqnum, dbptr.h0_info_msb, dbptr.h0_info);

	if (apm_dbptr_alloc(CLE_INT_PORT(iport), 1, &dbptr)) {
		ENET_ERROR_OFFLOAD("%s: apm_dbptr_alloc failed !!\n", __func__);
		/* If arp index (dbptr index) is not de-allocated to un-used dbptr list, skip del_arp for that iport */
		if (flag != APM_RC_OK) {
			rc |= APM_RC_ERROR;
			goto _skip_del_arp;
		}
	}

	/* Update the rt_mac_cle field to indicate its un-programmed/deleted in that CLE */
	memset(rt_mac_cle, 0, IFHWADDRLEN);

_skip_del_arp:
	cid++;

	/* Update for next CLE Engine */
	if (cid != MAX_CLE_ENGINE)
		goto _start_del_arp;

	/* If route list invalid or empty, check ref_count, index & delete arp entry */
	if (INVALID_LIST_HEAD(&ipv4fwd->rt_head) ||
			list_empty(&ipv4fwd->rt_head)) {
		/* If ref_count is non-zero, indicate error */
		if (ipv4fwd->ref_count)
			printk("Gateway IPv4 Route list empty but Gateway ref_count is non zero !!\n");

		/* If gateway entry index is valid in any CLE, indicate error */
		if (ipv4fwd_gw_entry->index != INVALID_32BIT_INDEX)
			printk("Gateway IPv4 Route list empty but Gateway index in CLE is valid !!\n");

		/* gateway entry not present in any CLE, remove gateway entry from gateway list */
		apm_del_enet_offload_entry(ipv4fwd_gw_entry);
		apm_ethoffload_ops.ifo_arp_unuse_entries--;
	}

	return rc;
}

static int apm_update_arp(__be32 rt_gateway, u8 *rt_mac, int eport, int mk_entry)
{
	int rc = APM_RC_OK;
	struct apm_enet_offload_list *ipv4fwd_gw_entry;

	ipv4fwd_gw_entry = apm_get_arp(rt_gateway, eport, mk_entry);
	/* If unable to create gateway entry from gateway list, return error */
	if (ipv4fwd_gw_entry == NULL) {
		ENET_DEBUG_OFFLOAD("%s: unable to retrieve arp entry\n", __func__);
		rc = APM_RC_ERROR;
		goto _ret_update_arp;
	}

	/* mk_arp */
	if (mk_entry) {
		memcpy(ipv4fwd_gw_entry->ipv4fwd->rt_mac, rt_mac, IFHWADDRLEN);
		rc = apm_add_arp(ipv4fwd_gw_entry, rt_mac);
	/* rm_arp */
	} else {
		memset(ipv4fwd_gw_entry->ipv4fwd->rt_mac, 0, IFHWADDRLEN);
		rc = apm_del_arp(ipv4fwd_gw_entry);
	}

_ret_update_arp:
	return rc;
}

static int apm_mk_arp(__be32 rt_gateway, u8 *rt_mac, int eport)
{
	int rc;
	unsigned long flags;

	apm_cle_lock(flags);
	rc = apm_update_arp(rt_gateway, rt_mac, eport, 1);
	apm_cle_unlock(flags);

	return rc;
}

static int apm_rm_arp(__be32 rt_gateway, u8 *rt_mac, int eport)
{
	int rc = APM_RC_OK;
	unsigned long flags;

	apm_cle_lock(flags);
	rc = apm_update_arp(rt_gateway, rt_mac, eport, 0);
	apm_cle_unlock(flags);

	return rc;
}

static int apm_fl_arps(int eport)
{
	int rc = APM_RC_OK;
	unsigned long flags;
	struct list_head *ipv4fwd_gw_head;
	struct apm_enet_offload_list *ipv4fwd_gw_entry, *ipv4fwd_gw_next;

	apm_cle_lock(flags);

	ipv4fwd_gw_head = &ipv4fwd_gateway;

	if (INVALID_LIST_HEAD(ipv4fwd_gw_head) || list_empty(ipv4fwd_gw_head))
		goto _ret_arp_routes;

	list_for_each_entry_safe(ipv4fwd_gw_entry, ipv4fwd_gw_next, ipv4fwd_gw_head, node) {
		if (ipv4fwd_gw_entry->key[1] != OFFLOAD_EPN(eport))
			continue;

		rc |= apm_del_arp(ipv4fwd_gw_entry);
	}

_ret_arp_routes:
	apm_cle_unlock(flags);

	return rc;
}

static void apm_show_arp(int eport)
{
	u32 unuse_result_ptr;
	int search_all_ports = 0;
	struct list_head *head;
	struct apm_enet_offload_list *entry;
	struct apm_index_list *r_entry;

	unuse_result_ptr = 0;
	head = &ipv4fwd_result_ptr_index[0];
	printk("Showing unuse allocated result pointer indices for CLE0\n");
	if (!(INVALID_LIST_HEAD(head))) {
		list_for_each_entry(r_entry, head, node) {
			printk("%4d ", r_entry->index);
			unuse_result_ptr++;
		}
		if (unuse_result_ptr)
			printk("\n");
	}
	printk("Total unuse allocated result pointer for CLE0 %d\n", unuse_result_ptr);
#ifndef CONFIG_APM862xx
	unuse_result_ptr = 0;
	head = &ipv4fwd_result_ptr_index[1];
	printk("Showing unuse allocated result pointer indices for CLE1\n");
	if (!(INVALID_LIST_HEAD(head))) {
		list_for_each_entry(r_entry, head, node) {
			printk("%4d ", r_entry->index);
			unuse_result_ptr++;
		}
		if (unuse_result_ptr)
			printk("\n");
	}
	printk("Total unuse allocated result pointer for CLE1 %d\n", unuse_result_ptr);
#endif
	printk("ARP Entries (result pointer) programmed in CLE0 %d\n",
		apm_ethoffload_ops.ifo_arp_cache_entries_cle[0]);
#ifndef CONFIG_APM862xx
	printk("ARP Entries (result pointer) programmed in CLE1 %d\n",
		apm_ethoffload_ops.ifo_arp_cache_entries_cle[1]);
#endif
	printk("ARP Entries unprogrammed %d\n",
		apm_ethoffload_ops.ifo_arp_unuse_entries);

	printk("Gateway         MAC Address        OutIf");
	printk(" | RefCnt   InIf ResPtr DstQID Offload");
#ifndef CONFIG_APM862xx
	printk(" | RefCnt   InIf ResPtr DstQID Offload");
#endif
	printk("\n");

	head = &ipv4fwd_gateway;

	if (INVALID_LIST_HEAD(head))
		return;

	if (eport == CLE_MAX_PORTS)
		search_all_ports = 1;

	list_for_each_entry(entry, head, node) {
		char gateway[16];
		struct apm_ipv4fwd_info *ipv4fwd;
		__be32 rt_gateway;
		u8 *rt_mac, *rt_mac_cle;
		int index;
		int iport;
		char *iport_devname;
		int dst_qid;
		int arp_offload;

		if (search_all_ports)
			eport = entry->key[1] & ~OFFLOAD_EPN(0);
		else if (entry->key[1] != OFFLOAD_EPN(eport))
			continue;

		ipv4fwd = entry->ipv4fwd;
		rt_gateway = entry->key[0];
		rt_mac = ipv4fwd->rt_mac;

		sprintf(gateway, "%pI4", &rt_gateway);
		printk("%-15s %02x:%02x:%02x:%02x:%02x:%02x %6s",
			gateway,
			rt_mac[0], rt_mac[1], rt_mac[2],
			rt_mac[3], rt_mac[4], rt_mac[5],
			offload_ndev[eport]->name);

		index = (((entry->index_cle[0] >= SYSTEM_START_DBPTR) &&
			(entry->index_cle[0] < SYSTEM_END_DBPTR)) ?
			entry->index_cle[0] : -1);
		/* Only APM Ethernet Ports (Internal) are valid/allowed Ingress Port */
		iport = (ETH_INT_PORT(ipv4fwd->iport_cle[0]) &&
			offload_ndev[ipv4fwd->iport_cle[0]] ?
			ipv4fwd->iport_cle[0] : -1);
		iport_devname = (iport != -1 ?
				offload_ndev[iport]->name :
				NULL);
		dst_qid = ((iport != -1 && index != -1) ?
				get_shadow_cle_dbptrs(CLE_INT_PORT(iport))[index].dstqid :
				-1);
		rt_mac_cle = ipv4fwd->rt_mac_cle[0];
		arp_offload = ((iport_devname && !is_zero_ether_addr(rt_mac_cle)) ? 1 : 0);

		printk(" | %6d %6s %6d %6d %7s",
			ipv4fwd->ref_count_cle[0],
			iport_devname,
			index,
			dst_qid,
			(arp_offload ? "On" : "Off"));
#ifndef CONFIG_APM862xx
		index = (((entry->index_cle[1] >= SYSTEM_START_DBPTR) &&
			(entry->index_cle[1] < SYSTEM_END_DBPTR)) ?
			entry->index_cle[1] : -1);
		/* Only APM Ethernet Ports (Internal) are valid/allowed Ingress Port */
		iport = (ETH_INT_PORT(ipv4fwd->iport_cle[1]) &&
			offload_ndev[ipv4fwd->iport_cle[1]] ?
			ipv4fwd->iport_cle[1] : -1);
		iport_devname = (iport != -1 ?
				offload_ndev[iport]->name :
				NULL);
		dst_qid = ((iport != -1 && index != -1) ?
				get_shadow_cle_dbptrs(CLE_INT_PORT(iport))[index].dstqid :
				-1);
		rt_mac_cle = ipv4fwd->rt_mac_cle[1];
		arp_offload = ((iport_devname && !is_zero_ether_addr(rt_mac_cle)) ? 1 : 0);

		printk(" | %6d %6s %6d %6d %7s",
			ipv4fwd->ref_count_cle[1],
			iport_devname,
			index,
			dst_qid,
			(arp_offload ? "On" : "Off"));
#endif
		printk("\n");
	}
}

static int apm_mk_route(__be32 rt_dst, __be32 rt_src, __be32 rt_gateway, int eport, int iport)
{
	int rc;
	unsigned long flags;

	apm_cle_lock(flags);
	rc = apm_update_route(rt_dst, rt_src, rt_gateway, eport, iport, 1);
	apm_cle_unlock(flags);

	return rc;
}

static int apm_rm_route(__be32 rt_dst, __be32 rt_src, __be32 rt_gateway, int eport, int iport)
{
	int rc = APM_RC_OK;
	unsigned long flags;

	apm_cle_lock(flags);
	rc = apm_update_route(rt_dst, rt_src, rt_gateway, eport, iport, 0);
	apm_cle_unlock(flags);

	return rc;
}

static int apm_fl_routes(void)
{
	int rc = APM_RC_OK;
	unsigned long flags;
	struct list_head *ipv4fwd_gw_head;
	struct apm_enet_offload_list *ipv4fwd_gw_entry, *ipv4fwd_gw_next;

	apm_cle_lock(flags);

	ipv4fwd_gw_head = &ipv4fwd_gateway;

	if (INVALID_LIST_HEAD(ipv4fwd_gw_head) || list_empty(ipv4fwd_gw_head))
		goto _ret_fl_routes;

	list_for_each_entry_safe(ipv4fwd_gw_entry, ipv4fwd_gw_next, ipv4fwd_gw_head, node) {
		struct apm_ipv4fwd_info *ipv4fwd = ipv4fwd_gw_entry->ipv4fwd;
		struct list_head *ipv4fwd_rt_head = &ipv4fwd->rt_head;
		struct apm_enet_offload_list *ipv4fwd_rt_entry, *ipv4fwd_rt_next;
		int iport = ipv4fwd->iport_cle[0];
		int eport;
#ifndef CONFIG_APM862xx
		int iport1 = ipv4fwd->iport_cle[1];
#endif
		if (INVALID_LIST_HEAD(ipv4fwd_rt_head) ||
				list_empty(ipv4fwd_rt_head))
			goto _skip_fl_routes;

		eport = ipv4fwd_gw_entry->key[1] & ~OFFLOAD_EPN(0);

		list_for_each_entry_safe(ipv4fwd_rt_entry, ipv4fwd_rt_next, ipv4fwd_rt_head, node) {
			int mask = 0;

			/* Route entry (avl entry) for CLE0 is valid & needs to be deleted */
			if (ipv4fwd_rt_entry->index_cle[0] != INVALID_16BIT_INDEX)
				mask |= 0x1;
			/* Route entry (avl entry) for CLE1 is valid & needs to be deleted */
			if (ipv4fwd_rt_entry->index_cle[1] != INVALID_16BIT_INDEX)
				mask |= 0x2;
			/* Route entry (avl entry) for CLE0/CLE1 both invalid & needs to be deleted only once */
			if (ipv4fwd_rt_entry->index == INVALID_32BIT_INDEX)
				mask |= 0x1;

			if (mask & 0x1) {
				ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
					iport, offload_ndev[iport]->name, eport, offload_ndev[eport]->name);
				rc |= apm_del_route(iport, ipv4fwd_gw_entry, ipv4fwd_rt_entry);
			}
#ifndef CONFIG_APM862xx
			if (mask & 0x2) {
				ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
					iport, offload_ndev[iport]->name, eport, offload_ndev[eport]->name);
				rc |= apm_del_route(iport1, ipv4fwd_gw_entry, ipv4fwd_rt_entry);
			}
#endif
		}

_skip_fl_routes:
		rc |= apm_del_arp(ipv4fwd_gw_entry);
	}

_ret_fl_routes:
	apm_cle_unlock(flags);

	return rc;
}

static void apm_show_route(int eport)
{
	int search_all_ports = 0;
	struct list_head *head;
	struct apm_enet_offload_list *entry;

	printk("Route Entries (avl node) programmed in CLE0 %d\n",
		apm_ethoffload_ops.ifo_route_cache_entries_cle[0]);
#ifndef CONFIG_APM862xx
	printk("Route Entries (avl node) programmed in CLE1 %d\n",
		apm_ethoffload_ops.ifo_route_cache_entries_cle[1]);
#endif
	printk("Route Entries unprogrammed %d\n",
		apm_ethoffload_ops.ifo_route_unuse_entries);

	printk("Source          Destination     Gateway          OutIf");
	printk(" | AVLNode Offload ->   InIf ResPtr DstQID Offload");
#ifndef CONFIG_APM862xx
	printk(" | AVLNode Offload ->   InIf ResPtr DstQID Offload");
#endif
	printk("\n");

	head = &ipv4fwd_gateway;

	if (INVALID_LIST_HEAD(head))
		return;

	if (eport == CLE_MAX_PORTS)
		search_all_ports = 1;

	list_for_each_entry(entry, head, node) {
		char gateway[16];
		struct apm_ipv4fwd_info *ipv4fwd;
		struct list_head *ipv4fwd_rt_head;
		struct apm_enet_offload_list *ipv4fwd_rt_entry;
		__be32 rt_gateway;
		u8 *rt_mac, *rt_mac_cle;
		int index;
		int iport;
		char *iport_devname;
		int dst_qid;
		int arp_offload;
#ifndef CONFIG_APM862xx
		int index1;
		int iport1;
		char *iport1_devname;
		int dst1_qid;
		int arp1_offload;
#endif

		if (search_all_ports)
			eport = entry->key[1] & ~OFFLOAD_EPN(0);
		else if (entry->key[1] != OFFLOAD_EPN(eport))
			continue;

		ipv4fwd = entry->ipv4fwd;
		ipv4fwd_rt_head = &ipv4fwd->rt_head;

		if (INVALID_LIST_HEAD(ipv4fwd_rt_head) ||
				list_empty(ipv4fwd_rt_head))
			continue;

		rt_gateway = entry->key[0];
		rt_mac = ipv4fwd->rt_mac;
		sprintf(gateway, "%pI4", &rt_gateway);

		index = (((entry->index_cle[0] >= SYSTEM_START_DBPTR) &&
			(entry->index_cle[0] < SYSTEM_END_DBPTR)) ?
			entry->index_cle[0] : -1);
		/* Only APM Ethernet Ports (Internal) are valid/allowed Ingress Port */
		iport = (ETH_INT_PORT(ipv4fwd->iport_cle[0]) &&
			offload_ndev[ipv4fwd->iport_cle[0]] ?
			ipv4fwd->iport_cle[0] : -1);
		iport_devname = (iport != -1 ?
				offload_ndev[iport]->name :
				NULL);
		dst_qid = ((iport != -1 && index != -1) ?
				get_shadow_cle_dbptrs(CLE_INT_PORT(iport))[index].dstqid :
				-1);
		rt_mac_cle = ipv4fwd->rt_mac_cle[0];
		arp_offload = ((iport_devname && !is_zero_ether_addr(rt_mac_cle)) ? 1 : 0);
#ifndef CONFIG_APM862xx
		index1 = (((entry->index_cle[1] >= SYSTEM_START_DBPTR) &&
			(entry->index_cle[1] < SYSTEM_END_DBPTR)) ?
			entry->index_cle[1] : -1);
		/* Only APM Ethernet Ports (Internal) are valid/allowed Ingress Port */
		iport1 = (ETH_INT_PORT(ipv4fwd->iport_cle[1]) &&
			offload_ndev[ipv4fwd->iport_cle[1]] ?
			ipv4fwd->iport_cle[1] : -1);
		iport1_devname = (iport1 != -1 ?
				offload_ndev[iport1]->name :
				NULL);
		dst1_qid = ((iport1 != -1 && index1 != -1) ?
				get_shadow_cle_dbptrs(CLE_INT_PORT(iport1))[index1].dstqid :
				-1);
		rt_mac_cle = ipv4fwd->rt_mac_cle[1];
		arp1_offload = ((iport1_devname && !is_zero_ether_addr(rt_mac_cle)) ? 1 : 0);
#endif
		list_for_each_entry(ipv4fwd_rt_entry, ipv4fwd_rt_head, node) {
			char src[16];
			char dst[16];
			__be32 rt_src = ipv4fwd_rt_entry->key[0];
			__be32 rt_dst = ipv4fwd_rt_entry->key[1];
			int avl_index;

			sprintf(src, "%pI4", &rt_src);
			sprintf(dst, "%pI4", &rt_dst);
			printk("%-15s %-15s %-15s %6s",
				src, dst, gateway,
				offload_ndev[eport]->name);

			avl_index = ((ipv4fwd_rt_entry->index_cle[0] != INVALID_16BIT_INDEX) ?
				ipv4fwd_rt_entry->index_cle[0] : -1);

			printk(" | %7d %7s -> %6s %6d %6d %7s",
				avl_index,
				(avl_index != -1 ? "On" : "Off"),
				iport_devname,
				index,
				dst_qid,
				(arp_offload ? "On" : "Off"));
#ifndef CONFIG_APM862xx
			avl_index = ((ipv4fwd_rt_entry->index_cle[1] != INVALID_16BIT_INDEX) ?
				ipv4fwd_rt_entry->index_cle[1] : -1);

			printk(" | %7d %7s -> %6s %6d %6d %7s",
				avl_index,
				(avl_index != -1 ? "On" : "Off"),
				iport1_devname,
				index1,
				dst1_qid,
				(arp1_offload ? "On" : "Off"));
#endif
			printk("\n");
		}
	}
}

int apm_mkarp_ipv4_forward(struct neighbour *n)
{
	__be32 rt_gateway = cpu_to_be32(*(u32 *)n->primary_key);
	u8 *rt_mac = n->ha;
	int eport = apm_inet_offload_ndev_to_index(n->dev);

	apm_ipv4fwd_offload_list_entry();
	ENET_DEBUG_OFFLOAD("%s: rt_gateway %d.%d.%d.%d "
		"rt_mac %02x:%02x:%02x:%02x:%02x:%02x "
		"eport %d (%s)\n", __func__,
		(rt_gateway & 0xFF000000) >> 24,
		(rt_gateway & 0x00FF0000) >> 16,
		(rt_gateway & 0x0000FF00) >>  8,
		(rt_gateway & 0x000000FF) >>  0,
		rt_mac[0], rt_mac[1], rt_mac[2],
		rt_mac[3], rt_mac[4], rt_mac[5],
		eport, n->dev->name);

	if (is_zero_ether_addr(rt_mac))
		goto _ret_mkarp_ipv4_forward;

	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_ANY_PORT(eport))
		apm_mk_arp(rt_gateway, rt_mac, eport);

_ret_mkarp_ipv4_forward:
	return 0;
}

void apm_rmarp_ipv4_forward(struct neighbour *n)
{
	__be32 rt_gateway = cpu_to_be32(*(u32 *)n->primary_key);
	u8 *rt_mac = n->ha;
	int eport = apm_inet_offload_ndev_to_index(n->dev);

	ENET_DEBUG_OFFLOAD("%s: rt_gateway %d.%d.%d.%d "
		"rt_mac %02x:%02x:%02x:%02x:%02x:%02x "
		"eport %d (%s)\n", __func__,
		(rt_gateway & 0xFF000000) >> 24,
		(rt_gateway & 0x00FF0000) >> 16,
		(rt_gateway & 0x0000FF00) >>  8,
		(rt_gateway & 0x000000FF) >>  0,
		rt_mac[0], rt_mac[1], rt_mac[2],
		rt_mac[3], rt_mac[4], rt_mac[5],
		eport, n->dev->name);

	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_ANY_PORT(eport))
		apm_rm_arp(rt_gateway, rt_mac, eport);
}

void apm_flarp_ipv4_forward(struct net_device *dev)
{
	int eport = apm_inet_offload_ndev_to_index(dev);

	ENET_DEBUG_OFFLOAD("%s: For eport %d (%s)\n", __func__, eport, dev->name);

	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_ANY_PORT(eport))
		apm_fl_arps(eport);
}

int apm_ipv4fwd_offload_init(int iport)
{
	struct net_device *dev;
	struct apm_enet_dev_base *ipriv_dev;
	int i, rc = APM_RC_OK;
	struct ptree_kn kn;
	struct apm_ptree_config *ptree_config;

	struct ptree_branch branch[] = {
	{      0, 0xffff,   EQT, PTREE_ALLOC(0), EW_BRANCH(1),  2, 0, 0, 0 },   /* 0-1 bytes of MAC Address */
	{      0, 0xffff,   EQT, PTREE_ALLOC(0), EW_BRANCH(2),  4, 0, 0, 0 },   /* 2-3 bytes of MAC Address */
	{      0, 0xffff,   EQT, PTREE_ALLOC(0), EW_BRANCH(3), 12, 0, 0, 0 },   /* 4-5 bytes of MAC Address */
	{      0, 0x0800,   EQT, PTREE_ALLOC(0), EW_BRANCH(4), 14, 0, 0, 0 },   /* Packet type IPv4 */
	{ 0x00ff, 0x4500,   EQT, PTREE_ALLOC(0), EW_BRANCH(5), 22, 0, 0, 0 },   /* IPv4 version and Header Length */
	{ 0x00ff, 0x0200, LTEQT, PTREE_ALLOC(1), EW_BRANCH(0), 26, 0, 0, 0 },   /* 2 <= TTL */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(1), EW_BRANCH(1), 28, 0, 0, 0 },   /* Src IP Address 0-1 */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(1), EW_BRANCH(2), 30, 0, 0, 0 },   /* Src IP Address 2-3 */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(1), EW_BRANCH(3), 32, 0, 0, 0 },   /* Dst IP Address 0-1 */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(2), EW_BRANCH(0),  0, 0, 0, 0 },   /* Dst IP Address 2-3 */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(3), KEY_INDEX(0),  0, 0, 0, 0 },   /* Allow all of the above */
	};

	struct ptree_dn dn[] = {
	{ START_NODE,   DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 6, &branch[0] },
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(BOTH_BYTES), 0, 0, 0, 4, &branch[6] },
	{ LAST_NODE,    DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 1, &branch[10] },
	};

	struct ptree_node node[] = {
	{ PTREE_ALLOC(0), EWDN, 0, (struct ptree_dn*)&dn[0] },
	{ PTREE_ALLOC(1), EWDN, 0, (struct ptree_dn*)&dn[1] },
	{ PTREE_ALLOC(2), EWDN, 0, (struct ptree_dn*)&dn[2] },
	{ PTREE_ALLOC(3),   KN, 0,    (struct ptree_kn*)&kn },
	};

	if (ipv4fwd_offload_init_done[iport])
		goto _ret_ipv4fwd_offload_init;

	dev = find_netdev(iport);
	ptree_config = apm_find_ptree_config(iport, CLE_PTREE_DEFAULT);

	if (ptree_config == NULL) {
		printk("%s interface is down\n", dev->name);
		rc = APM_RC_ERROR;
		goto _ret_ipv4fwd_offload_init;
	}

	ipriv_dev = netdev_priv(dev);
	ipriv_dev->in_poll_rx_msg_desc.is_msg16 = 0;
	iport_qm_queue[iport] = &ipriv_dev->qm_queues[apm_cle_system_id];
	if (!(ipriv_dev->offload.offload_available & IPP_IPV4FWD_OFFLOAD_FW_MASK))
		offloader_rx_qid[iport] = iport_qm_queue[iport]->default_rx_qid;

	/* Update Default Result Pointer in decision node */
	for (i = 0; i < ARRAY_SIZE(dn); i++)
		dn[i].result_pointer = ptree_config->start_dbptr;

	/* Update MAC Address in branch rule */
	for (i = 0; i < 3; i++)
		branch[i].data = (dev->dev_addr[i * 2] << 8) |
					dev->dev_addr[(i * 2) + 1];

	kn.priority = 1;
	kn.result_pointer = ptree_config->start_dbptr;

	ptree_config = apm_add_ptree_config(iport, CLE_PTREE_IPV4FWD);
	if ((rc = apm_ptree_alloc(iport, ARRAY_SIZE(node), 0, &node[0], NULL,
			ptree_config)) != APM_RC_OK) {
		ENET_ERROR_OFFLOAD("apm_ptree_alloc error %d for port %d\n", rc, iport);
		rc = APM_RC_ERROR;
		goto _ret_ipv4fwd_offload_init;
	}
	ptree_config->default_result = DFCLSRESDBPRIORITY0_WR(7) |
					DFCLSRESDBPTR0_WR(kn.result_pointer);

	ipv4fwd_offload_init_done[iport] = 1;

_ret_ipv4fwd_offload_init:
	return rc;
}

int apm_mkroute_ipv4_forward(struct sk_buff *skb, struct rtable *rth)
{
	int iport = apm_inet_offload_ndev_to_index(skb->dev);
	int eport = apm_inet_offload_ndev_to_index(rth->dst.dev);
	int rc = APM_RC_OK;
	__be32 rt_dst = rth->rt_dst;
	__be32 rt_src = rth->rt_src;
	__be32 rt_gateway = rth->rt_gateway;
	u8 *rt_mac = (rth->dst._neighbour) ? (rth->dst._neighbour->ha) : NULL;

	apm_ipv4fwd_offload_list_entry();
	ENET_DEBUG_OFFLOAD("%s: iport %d (%s) -> eport %d (%s): "
		"rt_dst %d.%d.%d.%d "
		"rt_src %d.%d.%d.%d "
		"rt_gateway %d.%d.%d.%d\n",
		__func__, iport, skb->dev->name, eport, rth->dst.dev->name,
		(rt_dst & 0xFF000000) >> 24,
		(rt_dst & 0x00FF0000) >> 16,
		(rt_dst & 0x0000FF00) >>  8,
		(rt_dst & 0x000000FF) >>  0,
		(rt_src & 0xFF000000) >> 24,
		(rt_src & 0x00FF0000) >> 16,
		(rt_src & 0x0000FF00) >>  8,
		(rt_src & 0x000000FF) >>  0,
		(rt_gateway & 0xFF000000) >> 24,
		(rt_gateway & 0x00FF0000) >> 16,
		(rt_gateway & 0x0000FF00) >>  8,
		(rt_gateway & 0x000000FF) >>  0);

	if (rth->dst._neighbour == NULL) {
		ENET_DEBUG_OFFLOAD("%s: neighbour is NULL, "
			"ignoring\n", __func__);
		goto _ret_mkroute_ipv4_forward;
	} else if (is_broadcast_ether_addr(rt_mac)) {
		ENET_DEBUG_OFFLOAD("%s: neighbour mac ff:ff:ff:ff:ff:ff, "
			"ignoring\n", __func__);
		goto _ret_mkroute_ipv4_forward;
	}

	ENET_DEBUG_OFFLOAD("%s: neighbour mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		__func__,
		rt_mac[0], rt_mac[1], rt_mac[2], rt_mac[3], rt_mac[4], rt_mac[5]);

	/* Allow Ingress Port to be APM Ethernet Ports (Internal) */
	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_INT_PORT_ERR(iport) || ETH_ANY_PORT_ERR(eport))
		goto _ret_mkroute_ipv4_forward;

	if (!ipv4fwd_offload_init_done[CLE_INT_PORT(iport)])
		if (apm_ipv4fwd_offload_init(CLE_INT_PORT(iport)))
			goto _ret_mkroute_ipv4_forward;

	rc = apm_mk_route(rt_dst, rt_src, rt_gateway, eport, iport);

	if (rc == APM_RC_CLE_MISS && (!is_zero_ether_addr(rt_mac)))
		apm_mk_arp(rt_gateway, rt_mac, eport);

_ret_mkroute_ipv4_forward:
	return 0;
}

void apm_rmroute_ipv4_forward(struct rtable *rth)
{
	int iport = apm_inet_offload_ifindex_to_index(rth->rt_iif);
	int eport = apm_inet_offload_ndev_to_index(rth->dst.dev);
	__be32 rt_dst = rth->rt_dst;
	__be32 rt_src = rth->rt_src;
	__be32 rt_gateway = rth->rt_gateway;
	u8 *rt_mac = (rth->dst._neighbour) ? (rth->dst._neighbour->ha) : NULL;

	ENET_DEBUG_OFFLOAD("%s: iport %d (%s) -> eport %d (%s): "
		"rt_dst %d.%d.%d.%d "
		"rt_src %d.%d.%d.%d "
		"rt_gateway %d.%d.%d.%d\n",
		__func__, iport,
		((ETH_INT_PORT(iport) && offload_ndev[iport]) ? offload_ndev[iport]->name : NULL),
		eport, rth->dst.dev->name,
		(rt_dst & 0xFF000000) >> 24,
		(rt_dst & 0x00FF0000) >> 16,
		(rt_dst & 0x0000FF00) >>  8,
		(rt_dst & 0x000000FF) >>  0,
		(rt_src & 0xFF000000) >> 24,
		(rt_src & 0x00FF0000) >> 16,
		(rt_src & 0x0000FF00) >>  8,
		(rt_src & 0x000000FF) >>  0,
		(rt_gateway & 0xFF000000) >> 24,
		(rt_gateway & 0x00FF0000) >> 16,
		(rt_gateway & 0x0000FF00) >>  8,
		(rt_gateway & 0x000000FF) >>  0);

	if (rth->dst._neighbour == NULL) {
		ENET_DEBUG_OFFLOAD("%s: neighbour is NULL, "
			"ignoring\n", __func__);
		goto _ret_rmroute_ipv4_forward;
	} else if (is_broadcast_ether_addr(rt_mac)) {
		ENET_DEBUG_OFFLOAD("%s: neighbour mac ff:ff:ff:ff:ff:ff, "
			"ignoring\n", __func__);
		goto _ret_rmroute_ipv4_forward;
	}

	ENET_DEBUG_OFFLOAD("%s: neighbour mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		__func__,
		rt_mac[0], rt_mac[1], rt_mac[2], rt_mac[3], rt_mac[4], rt_mac[5]);

	iport = apm_inet_offload_ifindex_to_index(rth->rt_iif);
	eport = apm_inet_offload_ndev_to_index(rth->dst.dev);

	/* Allow Ingress Port to be APM Ethernet Ports (Internal) */
	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_INT_PORT_ERR(iport) || ETH_ANY_PORT_ERR(eport))
		goto _ret_rmroute_ipv4_forward;

	apm_rm_route(rt_dst, rt_src, rt_gateway, eport, iport);

_ret_rmroute_ipv4_forward:
	return;
}

void apm_flroute_ipv4_forward(struct net_device *dev)
{
	int eport = apm_inet_offload_ndev_to_index(dev);

	ENET_DEBUG_OFFLOAD("%s: For eport %d (%s)\n", __func__, eport, dev->name);

	if (ETH_ANY_PORT(eport))
		apm_fl_routes();
}

int apm_ipv4fwd_offload_cmd(struct net_device *dev, char *cmdline, int update)
{
	int rc = APM_RC_ERROR;
	char cmdstr[8];
	char routestr[8];
	u8 src_ipv4[4], dst_ipv4[4], gwy_ipv4[4];
	__be32 rt_src, rt_dst, rt_gateway;
	char dev_name[IFNAMSIZ];
	int iport = apm_inet_offload_ndev_to_index(dev);
	int eport;

	apm_ipv4fwd_offload_list_entry();
	if (update) {
		if (ETH_INT_PORT(iport))
#ifdef CONFIG_APM_ENET_INO
			rc = apm_ipv4nat_offload_enable(dev);
#else
			rc = apm_ipv4fwd_offload_enable(dev);
#endif
		goto _ret_ipv4fwd_offload_cmd;
	}

	memset(routestr, 0, sizeof(routestr));
	memset(cmdstr, 0, sizeof(cmdstr));
	memset(dev_name, 0, sizeof(dev_name));

	if (strncmp(&cmdline[strlen(CLE_PTREE_IPV4FWD) + 1], "show", 4) == 0) {
		sscanf(cmdline, "%s show %s %s", routestr, cmdstr, dev_name);
		eport = apm_inet_offload_ndev_name_to_index(dev_name);

		if (ETH_ANY_PORT_ERR(eport))
			eport = CLE_MAX_PORTS;

		if (strncmp(cmdstr, "arp", 3) == 0)
			apm_show_arp(eport);
		else if (strncmp(cmdstr, "route", 5) == 0)
			apm_show_route(eport);

		rc = APM_RC_OK;
		goto _ret_ipv4fwd_offload_cmd;
	}

	sscanf(cmdline, "%s %s "
			"%hhu.%hhu.%hhu.%hhu "
			"%hhu.%hhu.%hhu.%hhu "
			"%hhu.%hhu.%hhu.%hhu "
			"%s",
			routestr, cmdstr,
			&src_ipv4[0], &src_ipv4[1],
			&src_ipv4[2], &src_ipv4[3],
			&dst_ipv4[0], &dst_ipv4[1],
			&dst_ipv4[2], &dst_ipv4[3],
			&gwy_ipv4[0], &gwy_ipv4[1],
			&gwy_ipv4[2], &gwy_ipv4[3],
			dev_name);

	eport = apm_inet_offload_ndev_name_to_index(dev_name);
	if (eport < 0)
		goto _ret_ipv4fwd_offload_cmd;

	if (strncmp(cmdstr, "add", 3) == 0)
		update = 1;
	else if (strncmp(cmdstr, "del", 3) == 0)
		update = 0;
	else
		goto _ret_ipv4fwd_offload_cmd;

	rt_src = (src_ipv4[0] << 24) |
		(src_ipv4[1] << 16) |
		(src_ipv4[2] <<  8) |
		(src_ipv4[3] <<  0);

	rt_dst = (dst_ipv4[0] << 24) |
		(dst_ipv4[1] << 16) |
		(dst_ipv4[2] <<  8) |
		(dst_ipv4[3] <<  0);

	rt_gateway = (gwy_ipv4[0] << 24) |
		(gwy_ipv4[1] << 16) |
		(gwy_ipv4[2] <<  8) |
		(gwy_ipv4[3] <<  0);

	ENET_DEBUG_OFFLOAD("%s: %sing to AVL search_string "
			"key[0] %08x key[1] %08x gateway %08x "
			"for out port %s (number %d)\n", __func__,
			update ? "Add" : "Delet",
			rt_src, rt_dst,
			rt_gateway, dev_name, eport);

	if (update)
		rc = apm_mk_route(rt_dst, rt_src, rt_gateway, eport, iport);
	else
		rc = apm_rm_route(rt_dst, rt_src, rt_gateway, eport, iport);

_ret_ipv4fwd_offload_cmd:
	return rc;
}

int apm_ipv4fwd_offload_enable(struct net_device *dev)
{
	int rc;
	struct apm_enet_dev_base *ipriv_dev;

	ipriv_dev = netdev_priv(dev);
	rc = apm_ipv4fwd_offload_init(ipriv_dev->port_id);

	if (rc == APM_RC_OK)
		rc = apm_inet_switch(ipriv_dev, ETHOFFLOAD_IPV4FWD);

	return rc;
}

void apm_ipv4fwd_offload_setqid(u8 iport, u8 qid)
{
	offloader_rx_qid[iport] = qid;
}
