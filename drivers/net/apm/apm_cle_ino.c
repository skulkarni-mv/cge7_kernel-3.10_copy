/**
 * AppliedMicro APM86xxx SoC IPv4 NAT Offload Classifier Driver
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
 * @file apm_cle_ino.c
 *
 * This file implements Classifier configurations in use by IPv4 NAT Offload driver.
 *
 */

#include <linux/etherdevice.h>
#include <net/route.h>

#include "apm_enet_offload.h"
#include "apm_cle_ino.h"

static int ipv4nat_offload_init_done[MAX_PORTS] = {0};
static struct list_head ipv4fwd_gateway = {0};
static struct list_head ipv4nat_pending = {0};
static struct list_head ipv4nat_nfilter = {0};
static struct list_head ipv4nat_result_ptr_index[MAX_CLE_ENGINE] = {{0}};
static struct eth_queue_ids *iport_qm_queue[MAX_PORTS] = {0};
static u8 offloader_rx_qid[MAX_PORTS] = {0};

static inline void apm_ipv4nat_offload_list_entry(void)
{
	static int ipv4nat_offload_list_init_done = 0;

	/* First time access to gateway list */
	if (!ipv4nat_offload_list_init_done) {
		INIT_LIST_HEAD(&ipv4fwd_gateway);
		INIT_LIST_HEAD(&ipv4nat_pending);
		INIT_LIST_HEAD(&ipv4nat_nfilter);
		INIT_LIST_HEAD(&ipv4nat_result_ptr_index[0]);
#ifndef CONFIG_APM862xx
		INIT_LIST_HEAD(&ipv4nat_result_ptr_index[1]);
#endif
		ipv4nat_offload_list_init_done = 1;
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
		apm_ethoffload_ops.ino_arp_unuse_entries++;
		ipv4fwd_rt_head = &ipv4fwd_gw_entry->ipv4fwd->rt_head;
		INIT_LIST_HEAD(ipv4fwd_rt_head);
		ipv4fwd_gw_entry->ipv4fwd->iport = INVALID_32BIT_INDEX;
		/* Update IPv4 Forward Egress Port number */
		ipv4fwd_gw_entry->ipv4fwd->eport = eport;
	}

_ret_get_arp:
	return ipv4fwd_gw_entry;
}

static int apm_add_pending_nat(struct apm_ipv4nat_info *ipv4nat)
{
	int rc = APM_RC_ERROR;
	struct avl_node node;
	struct apm_cle_dbptr dbptr;
	__be32 src_ip = ipv4nat->src_ip;
	__be32 dst_ip = ipv4nat->dst_ip;
	__be32 transport = (ipv4nat->src_l4 << 16) | ipv4nat->dst_l4;
	__be32 nf_l3 = ipv4nat->nf_l3;
	__be16 nf_l4 = ipv4nat->nf_l4;
	u8 *nf_mac = ipv4nat->rt_mac;
	u32 iport = ipv4nat->iport;
	u32 eport = ipv4nat->eport;
	enum apm_ipv4nat_offload_type type = ipv4nat->type;

	ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
		iport, offload_ndev[iport]->name, eport, offload_ndev[eport]->name);

	ENET_DEBUG_OFFLOAD("src_ip %08x dst_ip %08x src_l4 %d dst_l4 %d "
		"nf_l3 %08x nf_l4 %d "
		"nf_mac %02x:%02x:%02x:%02x:%02x:%02x nat_type %d\n",
		src_ip, dst_ip,
		ipv4nat->src_l4, ipv4nat->dst_l4, nf_l3, nf_l4,
		nf_mac[0], nf_mac[1], nf_mac[2],
		nf_mac[3], nf_mac[4], nf_mac[5],
		type);

	memset(&node, 0, sizeof(node));
	memset(&dbptr, 0, sizeof(dbptr));

	/* Configure AVL Node to Add */
	/* SRC IP, DST IP, Transport Layer */
	node.search_key[0] = src_ip; /* SRC IP Address */
	node.search_key[1] = dst_ip; /* DST IP Address */
	node.search_key[2] = transport; /* Transport Layer */

	/* Configure dbptr */
	/* Try to get previously allocated un-used dbptr from list */
	rc = apm_get_index(&ipv4nat_result_ptr_index[CID_INT_PORT(iport)], &dbptr.index);

	/* If all previously allocated dbptr are in use, allocate a new dbptr */
	if (rc != APM_RC_OK)
		dbptr.index = DBPTR_ALLOC(CLE_DB_INDEX);

	/* offload enabled */
	dbptr.h0_en = 1;
	/* offload to perform */
	dbptr.h0_fpsel = APM_IPV4NAT_OFFLOAD;
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
	 * NF MAC Address (40 bits)
	 * byte 0 - h0_enqnum (8 bits)
	 * byte 1 - h0_info_msb (8 bits)
	 * bytes 2 to 5 - h0_info (32 bits)
	 */
	dbptr.h0_enqnum = nf_mac[0];
	dbptr.h0_info_msb = nf_mac[1];
	dbptr.h0_info = (nf_mac[2] << 24) |
			(nf_mac[3] << 16) |
			(nf_mac[4] <<  8) |
			(nf_mac[5] <<  0);
	/*
	 * NF Port (16 bits)
	 * byte 0 - h1_enqnum (8 bits)
	 * byte 1 - h1_info_msb (8 bits)
	 */
	dbptr.h1_enqnum = (nf_l4 >> 8);
	dbptr.h1_info_msb = (nf_l4 & 0xFF);
	/*
	 * NF IP Address (32 bits)
	 * byte 0 to 3 - h1_info (32 bits)
	 */
	dbptr.h1_info = nf_l3;
	/* NAT offload to perform */
	dbptr.h1_fpsel = type;

	/* Work Queue and Free Pool Queue */
	dbptr.dstqid = offloader_rx_qid[CLE_INT_PORT(iport)];
	dbptr.fpsel  = iport_qm_queue[CLE_INT_PORT(iport)]->hw_fp_pbn - 0x20;

	ENET_DEBUG_OFFLOAD("%s: iport %d (%s) index %d dstqid %d fpsel %d "
			"h0_enqnum 0x%02x h0_info 0x%02x%08x "
			"h1_enqnum 0x%02x h1_info 0x%02x%08x h1_fpsel %d\n",
			__func__, iport, offload_ndev[iport]->name,
			(dbptr.index == DBPTR_ALLOC(CLE_DB_INDEX) ? 0 : dbptr.index),
			dbptr.dstqid, dbptr.fpsel,
			dbptr.h0_enqnum, dbptr.h0_info_msb, dbptr.h0_info,
			dbptr.h1_enqnum, dbptr.h1_info_msb, dbptr.h1_info,
			dbptr.h1_fpsel);

	node.priority = 0;
	node.result_pointer = dbptr.index;

	if ((rc = apm_avl_alloc(CLE_INT_PORT(iport), 1, 1, &node, &dbptr)) != APM_RC_OK) {
		ENET_DEBUG_OFFLOAD("apm_avl_alloc failed !!\n");

		if (node.index)
			apm_cle_avl_del_node(CLE_INT_PORT(iport), &node);
	} else {
		ipv4nat->avl_index = node.index;
		ipv4nat->dbptr_index = dbptr.index;
		apm_ethoffload_ops.ipv4_arp_cache_entries_cle[CID_INT_PORT(iport)]++;
		apm_ethoffload_ops.ipv4_route_cache_entries_cle[CID_INT_PORT(iport)]++;
		apm_ethoffload_ops.ino_arp_cache_entries_cle[CID_INT_PORT(iport)]++;
		apm_ethoffload_ops.ino_route_cache_entries_cle[CID_INT_PORT(iport)]++;
	}

	return rc;
}

static int apm_add_offload_nat(struct apm_ipv4nat_info *ipv4nat)
{
	int rc = APM_RC_ERROR;
	struct apm_cle_dbptr dbptr;
	__be32 nf_l3 = ipv4nat->nf_l3;
	__be16 nf_l4 = ipv4nat->nf_l4;
	u8 *nf_mac = ipv4nat->rt_mac;
	u32 iport = ipv4nat->iport;
	u32 eport = ipv4nat->eport;
	enum apm_ipv4nat_offload_type type = ipv4nat->type;

	ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
		iport, offload_ndev[iport]->name, eport, offload_ndev[eport]->name);

	ENET_DEBUG_OFFLOAD("src_ip %08x dst_ip %08x src_l4 %d dst_l4 %d "
		"nf_l3 %08x nf_l4 %d "
		"nf_mac %02x:%02x:%02x:%02x:%02x:%02x nat_type %d\n",
		ipv4nat->src_ip, ipv4nat->dst_ip,
		ipv4nat->src_l4, ipv4nat->dst_l4, nf_l3, nf_l4,
		nf_mac[0], nf_mac[1], nf_mac[2],
		nf_mac[3], nf_mac[4], nf_mac[5],
		type);

	memset(&dbptr, 0, sizeof(dbptr));

	/* Configure dbptr */
	dbptr.index = ipv4nat->dbptr_index;
	/* offload enabled */
	dbptr.h0_en = 1;
	/* offload to perform */
	dbptr.h0_fpsel = APM_IPV4NAT_OFFLOAD;
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
	 * NF MAC Address (40 bits)
	 * byte 0 - h0_enqnum (8 bits)
	 * byte 1 - h0_info_msb (8 bits)
	 * bytes 2 to 5 - h0_info (32 bits)
	 */
	dbptr.h0_enqnum = nf_mac[0];
	dbptr.h0_info_msb = nf_mac[1];
	dbptr.h0_info = (nf_mac[2] << 24) |
			(nf_mac[3] << 16) |
			(nf_mac[4] <<  8) |
			(nf_mac[5] <<  0);
	/*
	 * NF Port (16 bits)
	 * byte 0 - h1_enqnum (8 bits)
	 * byte 1 - h1_info_msb (8 bits)
	 */
	dbptr.h1_enqnum = (nf_l4 >> 8);
	dbptr.h1_info_msb = (nf_l4 & 0xFF);
	/*
	 * NF IP Address (32 bits)
	 * byte 0 to 3 - h1_info (32 bits)
	 */
	dbptr.h1_info = nf_l3;
	/* NAT offload to perform */
	dbptr.h1_fpsel = type;

	/* Work Queue and Free Pool Queue */
	dbptr.dstqid = offloader_rx_qid[CLE_INT_PORT(iport)];
	dbptr.fpsel  = iport_qm_queue[CLE_INT_PORT(iport)]->hw_fp_pbn - 0x20;

	ENET_DEBUG_OFFLOAD("%s: iport %d (%s) index %d dstqid %d fpsel %d "
			"h0_enqnum 0x%02x h0_info 0x%02x%08x "
			"h1_enqnum 0x%02x h1_info 0x%02x%08x h1_fpsel %d\n",
			__func__, iport, offload_ndev[iport]->name,
			dbptr.index, dbptr.dstqid, dbptr.fpsel,
			dbptr.h0_enqnum, dbptr.h0_info_msb, dbptr.h0_info,
			dbptr.h1_enqnum, dbptr.h1_info_msb, dbptr.h1_info,
			dbptr.h1_fpsel);

	if ((rc = apm_dbptr_alloc(CLE_INT_PORT(iport), 1, &dbptr)) != APM_RC_OK)
		ENET_ERROR_OFFLOAD("%s: apm_dbptr_alloc failed !!\n", __func__);

	return rc;
}

static int apm_del_nfilter_nat(struct apm_ipv4nat_info *ipv4nat)
{
	int rc = APM_RC_ERROR;
	struct avl_node node;
	struct apm_cle_dbptr dbptr;
	__be32 src_ip = ipv4nat->src_ip;
	__be32 dst_ip = ipv4nat->dst_ip;
	__be32 transport = (ipv4nat->src_l4 << 16) | ipv4nat->dst_l4;
	u32 iport = ipv4nat->iport;

	ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
		iport, offload_ndev[iport]->name,
		(ETH_ANY_PORT(ipv4nat->eport) ? ipv4nat->eport : -1),
		(ETH_ANY_PORT(ipv4nat->eport) ? offload_ndev[ipv4nat->eport]->name : NULL));

	ENET_DEBUG_OFFLOAD("src_ip %08x dst_ip %08x src_l4 %d dst_l4 %d nat_type %d\n",
		src_ip, dst_ip,
		ipv4nat->src_l4, ipv4nat->dst_l4,
		ipv4nat->type);

	memset(&node, 0, sizeof(node));
	memset(&dbptr, 0, sizeof(dbptr));

	/* Configure AVL Node to Delete */
	/* SRC IP, DST IP, Transport Layer */
	node.search_key[0] = src_ip; /* SRC IP Address */
	node.search_key[1] = dst_ip; /* DST IP Address */
	node.search_key[2] = transport; /* Transport Layer */

	if ((rc = apm_cle_avl_del_node(CLE_INT_PORT(iport), &node)) != APM_RC_OK)
		ENET_ERROR_OFFLOAD("apm_cle_avl_del_node failed !!\n");

	/* Unconfigure dbptr */
	dbptr.index = ipv4nat->dbptr_index;
	apm_dbptr_alloc(CLE_INT_PORT(iport), 1, &dbptr);
	/* Try to put the allocated un-used dbptr to list */
	if ((rc |= apm_put_index(&ipv4nat_result_ptr_index[CID_INT_PORT(iport)], dbptr.index)) != APM_RC_OK)
		ENET_ERROR_OFFLOAD("apm_put_index failed !!\n");

	if (rc == APM_RC_OK) {
		apm_ethoffload_ops.ipv4_arp_cache_entries_cle[CID_INT_PORT(iport)]--;
		apm_ethoffload_ops.ipv4_route_cache_entries_cle[CID_INT_PORT(iport)]--;
		apm_ethoffload_ops.ino_arp_cache_entries_cle[CID_INT_PORT(iport)]--;
		apm_ethoffload_ops.ino_route_cache_entries_cle[CID_INT_PORT(iport)]--;
	}

	return rc;
}

static int apm_del_offload_nat(struct apm_ipv4nat_info *ipv4nat)
{
	int rc = APM_RC_ERROR;
	struct apm_cle_dbptr dbptr;
	u32 iport = ipv4nat->iport;

	ENET_DEBUG_OFFLOAD("%s: For iport %d (%s) eport %d (%s) ", __func__,
		iport, offload_ndev[iport]->name,
		(ETH_ANY_PORT(ipv4nat->eport) ? ipv4nat->eport : -1),
		(ETH_ANY_PORT(ipv4nat->eport) ? offload_ndev[ipv4nat->eport]->name : NULL));

	ENET_DEBUG_OFFLOAD("src_ip %08x dst_ip %08x src_l4 %d dst_l4 %d nat_type %d\n",
		ipv4nat->src_ip, ipv4nat->dst_ip,
		ipv4nat->src_l4, ipv4nat->dst_l4,
		ipv4nat->type);

	memset(&dbptr, 0, sizeof(dbptr));

	/* Unconfigure dbptr */
	dbptr.index = ipv4nat->dbptr_index;
	/* Work Queue and Free Pool Queue */
	dbptr.dstqid = iport_qm_queue[CLE_INT_PORT(iport)]->default_rx_qid;
	dbptr.fpsel  = iport_qm_queue[CLE_INT_PORT(iport)]->rx_fp_pbn - 0x20;

	if ((rc = apm_dbptr_alloc(CLE_INT_PORT(iport), 1, &dbptr)) != APM_RC_OK)
		ENET_ERROR_OFFLOAD("%s: apm_dbptr_alloc failed !!\n", __func__);

	return rc;
}

static int apm_add_nat(struct apm_enet_offload_list *ipv4nat_pn_entry, int pn_type)
{
	struct apm_ipv4nat_info *ipv4nat = ipv4nat_pn_entry->ipv4nat;
	int rc = APM_RC_OK;
	int i;

	for (i = 0; i < IP_CT_DIR_MAX; i++) {
		if (!ipv4nat[i].rt_gateway || is_zero_ether_addr(ipv4nat[i].rt_mac) ||
				ipv4nat[i].eport == INVALID_32BIT_INDEX ||
				ipv4nat[i].iport == INVALID_32BIT_INDEX)
			rc |= APM_RC_ERROR;

		if (pn_type && rc == APM_RC_OK && ETH_INT_PORT(ipv4nat[i].iport)) {
			/* If number of arp entries (dbptr entries) programmed equal to MAX possible entries, skip add_nat */
			if (apm_ethoffload_ops.ipv4_arp_cache_entries_cle[CID_INT_PORT(ipv4nat[i].iport)] >= DBPTR_PER_SYSTEM) {
				ENET_ERROR_OFFLOAD("No DBPTR left to add !!\n");
				rc |= APM_RC_ERROR;
			}

			/* If number of route entries (avl entries) programmed equal to MAX possible entries, skip add_nat */
			if (apm_ethoffload_ops.ipv4_route_cache_entries_cle[CID_INT_PORT(ipv4nat[i].iport)] >= AVL_NODES_PER_SYSTEM) {
				ENET_ERROR_OFFLOAD("No AVL Nodes left to add !!\n");
				rc |= APM_RC_ERROR;
			}
		}
	}

	if (rc == APM_RC_OK && ETH_INT_PORT(ipv4nat[1].iport)) {
		if (pn_type)
			rc = apm_add_pending_nat(&ipv4nat[1]);
		else
			rc = apm_add_offload_nat(&ipv4nat[1]);

		if (rc == APM_RC_OK)
			--i;
	}

	if (rc == APM_RC_OK && ETH_INT_PORT(ipv4nat[0].iport)) {
		if (pn_type)
			rc = apm_add_pending_nat(&ipv4nat[0]);
		else
			rc = apm_add_offload_nat(&ipv4nat[0]);

		if (rc == APM_RC_OK)
			--i;
		else {
			if (pn_type)
				apm_del_nfilter_nat(&ipv4nat[1]);
			else
				apm_del_offload_nat(&ipv4nat[1]);
		}
	}

	if (rc == APM_RC_OK && i != IP_CT_DIR_MAX && pn_type) {
		struct list_head *ipv4nat_nf_head = &ipv4nat_nfilter;

		list_del(&ipv4nat_pn_entry->node);
		list_add(&ipv4nat_pn_entry->node, ipv4nat_nf_head);
		apm_ethoffload_ops.ino_nat_unuse_entries--;
	}

	return rc;
}

static int apm_del_nat(struct apm_enet_offload_list *ipv4nat_nf_entry, int nf_type)
{
	struct apm_ipv4nat_info *ipv4nat = ipv4nat_nf_entry->ipv4nat;
	int rc = APM_RC_OK;
	int i;

	for (i = 0; i < IP_CT_DIR_MAX; i++)
		if (ipv4nat[i].iport == INVALID_32BIT_INDEX)
			rc |= APM_RC_ERROR;

	if (rc == APM_RC_OK && ETH_INT_PORT(ipv4nat[1].iport)) {
		if (nf_type)
			rc = apm_del_nfilter_nat(&ipv4nat[1]);
		else
			rc = apm_del_offload_nat(&ipv4nat[1]);

		if (rc == APM_RC_OK)
			--i;
	}

	if (rc == APM_RC_OK && ETH_INT_PORT(ipv4nat[0].iport)) {
		if (nf_type)
			rc = apm_del_nfilter_nat(&ipv4nat[0]);
		else
			rc = apm_del_offload_nat(&ipv4nat[0]);

		if (rc == APM_RC_OK)
			--i;
	}

	if (rc == APM_RC_OK && i != IP_CT_DIR_MAX && nf_type)
		apm_del_enet_offload_entry(ipv4nat_nf_entry);

	return rc;
}

static int apm_update_nat_arp(struct apm_ipv4nat_info *ipv4nat, struct apm_ipv4fwd_info *ipv4fwd, int mk_entry)
{
	int rc = APM_RC_ERROR;

	/* mk_route && arp/gateway info absent in NAT entry */
	if (mk_entry && compare_ether_addr(ipv4nat->rt_mac, ipv4fwd->rt_mac)) {
		/* Update the rt_mac field to indicate valid rt_mac for pending NAT entry */
		memcpy(ipv4nat->rt_mac, ipv4fwd->rt_mac, IFHWADDRLEN);
		/*
		   If the gateway is being referenced first time by NAT,
		   decrement arp_unuse_entries, increment arp_cache_entries
		 */
		if (ipv4fwd->ref_count == 0)
			apm_ethoffload_ops.ino_arp_unuse_entries--;
		/* ARP entry is referenced by the NAT entry, so increment ref_count for the ARP entry */
		ipv4fwd->ref_count++;
		rc = APM_RC_OK;
	/* rm_route && arp/gateway info present in NAT entry */
	} else if (!mk_entry && !is_zero_ether_addr(ipv4nat->rt_mac)) {
		/* Update the rt_mac and other info to indicate zero rt_mac for pending NAT entry */
		memset(ipv4nat->rt_mac, 0, IFHWADDRLEN);
		ipv4nat->rt_gateway = 0;

		/* ARP entry is de-referenced by the NAT entry, so decrement ref_count for the ARP entry */
		ipv4fwd->ref_count--;
		/*
		   If the gateway is being de-referenced last time by NAT,
		   increment arp_unuse_entries, decrement arp_cache_entries
		 */
		if (ipv4fwd->ref_count == 0)
			apm_ethoffload_ops.ino_arp_unuse_entries++;
		rc = APM_RC_OK;
	}

	return rc;
}
static int apm_update_nat_route(struct apm_ipv4nat_info *ipv4nat, __be32 rt_gateway, struct apm_ipv4rth_info *ipv4rth, int mk_entry)
{
	int rc = APM_RC_ERROR;

	/* mk_route && route/gateway info absent in NAT entry */
	if (mk_entry && ipv4nat->eport == INVALID_32BIT_INDEX) {
		/* Update the eport and other info to indicate valid rt_gateway for pending NAT entry */
		ipv4nat->rt_gateway = rt_gateway;
		ipv4nat->iport = ipv4rth->iport;
		ipv4nat->eport = ipv4rth->eport;
		/*
		   If the route is being referenced first time by NAT,
		   decrement route_unuse_entries, increment route_cache_entries
		 */
		if (ipv4rth->ref_count == 0)
			apm_ethoffload_ops.ino_route_unuse_entries--;
		/* Route entry is referenced by the NAT entry, so increment ref_count for the route entry */
		ipv4rth->ref_count++;
		rc = APM_RC_OK;
	/* rm_route && route/gateway info present in NAT entry */
	} else if (!mk_entry && ipv4nat->eport != INVALID_32BIT_INDEX) {
		/* Update the eport to indicate invalid rt_gateway for pending NAT entry */
		ipv4nat->eport = INVALID_32BIT_INDEX;

		/* Route entry is de-referenced by the NAT entry, so decrement ref_count for the route entry */
		ipv4rth->ref_count--;
		/*
		   If the route is being de-referenced last time by NAT,
		   increment route_unuse_entries, decrement route_cache_entries
		 */
		if (ipv4rth->ref_count == 0)
			apm_ethoffload_ops.ino_route_unuse_entries++;
		rc = APM_RC_OK;
	}

	return rc;
}

static void apm_update_nat_route_arp(struct apm_enet_offload_list *nf, int mk_entry)
{
	struct list_head *ipv4fwd_gw_head = &ipv4fwd_gateway;
	int i;

	/* If invalid or empty gateway list, return error */
	if (INVALID_LIST_HEAD(ipv4fwd_gw_head) || list_empty(ipv4fwd_gw_head)) {
		ENET_DEBUG_OFFLOAD("%s: invalid or empty gateway list\n", __func__);
		return;
	}

	for (i = 0; i < IP_CT_DIR_MAX; i++) {
		__be32 rt_src = nf->key[0 ^ i];
		__be32 rt_dst = nf->key[1 ^ i];
		struct apm_enet_offload_list *gw = NULL;
		struct apm_enet_offload_list *rt = NULL;
		struct apm_enet_offload_list *ipv4fwd_gw_entry;

		/* Get gateway and route entry for netfilter entry for SNAT (i = 0) & DNAT (i = 1) */
		list_for_each_entry(ipv4fwd_gw_entry, ipv4fwd_gw_head, node) {
			struct apm_ipv4fwd_info *ipv4fwd = ipv4fwd_gw_entry->ipv4fwd;
			struct list_head *ipv4fwd_rt_head = NULL;
			struct apm_enet_offload_list *ipv4fwd_rt_entry;
			__be32 rt_gateway;

			rt_gateway = ipv4fwd_gw_entry->key[0];

			if (ipv4fwd)
				ipv4fwd_rt_head = &ipv4fwd->rt_head;

			if (!ipv4fwd || INVALID_LIST_HEAD(ipv4fwd_rt_head) ||
					list_empty(ipv4fwd_rt_head)) {

				ENET_DEBUG_OFFLOAD("%s: invalid or empty route list "
					"for gateway %d.%d.%d.%d\n", __func__,
					(rt_gateway & 0xFF000000) >> 24,
					(rt_gateway & 0x00FF0000) >> 16,
					(rt_gateway & 0x0000FF00) >>  8,
					(rt_gateway & 0x000000FF) >>  0);
				continue;
			}

			list_for_each_entry(ipv4fwd_rt_entry, ipv4fwd_rt_head, node) {
				if (ipv4fwd_rt_entry->key[0] != rt_src || ipv4fwd_rt_entry->key[1] != rt_dst)
					continue;

				ENET_DEBUG_OFFLOAD("%s: Found gateway %d.%d.%d.%d "
					"for src_ip %d.%d.%d.%d dst_ip %d.%d.%d.%d\n", __func__,
					(rt_gateway & 0xFF000000) >> 24,
					(rt_gateway & 0x00FF0000) >> 16,
					(rt_gateway & 0x0000FF00) >>  8,
					(rt_gateway & 0x000000FF) >>  0,
					(rt_src & 0xFF000000) >> 24,
					(rt_src & 0x00FF0000) >> 16,
					(rt_src & 0x0000FF00) >>  8,
					(rt_src & 0x000000FF) >>  0,
					(rt_dst & 0xFF000000) >> 24,
					(rt_dst & 0x00FF0000) >> 16,
					(rt_dst & 0x0000FF00) >>  8,
					(rt_dst & 0x000000FF) >>  0);

				rt = ipv4fwd_rt_entry;
				break;
			}

			if (rt) {
				gw = ipv4fwd_gw_entry;
				apm_update_nat_route(&nf->ipv4nat[i], gw->key[0], rt->ipv4rth, mk_entry);
				apm_update_nat_arp(&nf->ipv4nat[i], gw->ipv4fwd, mk_entry);
				break;
			}
		}
	}
}

static int apm_update_nat(__be32 src_ip, __be32 dst_ip, __be16 src_l4, __be16 dst_l4,
	__be32 r_src_ip, __be32 r_dst_ip, __be16 r_src_l4, __be16 r_dst_l4,
	enum apm_ipv4nat_offload_type type, int mk_entry)
{

	int rc = APM_RC_OK;
	struct apm_enet_offload_list *ipv4nat_pn_entry, *ipv4nat_nf_entry;
	struct list_head *ipv4nat_pn_head = &ipv4nat_pending;
	struct list_head *ipv4nat_nf_head = &ipv4nat_nfilter;
	struct apm_ipv4nat_info *ipv4nat;
	u32 key[OFFLOAD_KEY_SIZE];

	/* SNAT tuple has remote source & destination ip, so gateway, route & netfilter offload_list key entry will be based on it */
	if (type == APM_IPV4NAT_OFFLOAD_SNAT || type == APM_IPV4NAT_OFFLOAD_SNAT_IP) {
		/* For OFFLOAD_SNAT or OFFLOAD_SNAT_IP type, SNAT is in IP_CT_DIR_ORIGINAL tuple */
		key[0] = src_ip; /* SRC IP Address */
		key[1] = dst_ip; /* DST IP Address */
		key[2] = (src_l4 << 16) | dst_l4; /* L4-Transport Layer */
	} else if (type == APM_IPV4NAT_OFFLOAD_DNAT || type == APM_IPV4NAT_OFFLOAD_DNAT_IP) {
		/* For OFFLOAD_DNAT or OFFLOAD_DNAT_IP type, SNAT is in IP_CT_DIR_REPLY tuple */
		key[0] = r_src_ip; /* SRC IP Address */
		key[1] = r_dst_ip; /* DST IP Address */
		key[2] = (r_src_l4 << 16) | r_dst_l4; /* L4-Transport Layer */
	} else {
		rc = APM_RC_ERROR;
		ENET_ERROR_OFFLOAD("%s: unimplementated ipv4nat_offload_type %d\n", __func__, type);
		goto _ret_update_nat;
	}

	/* Find netfilter entry from netfilter list */
	ipv4nat_nf_entry = apm_find_enet_offload_entry(ipv4nat_nf_head, key);

	/* Find netfilter entry from pending netfilter list */
	ipv4nat_pn_entry = apm_find_enet_offload_entry(ipv4nat_pn_head, key);

	/* mk_nat, make netfilter entry (avl entry) in CLE */
	if (mk_entry) {
		if (ipv4nat_nf_entry) {
			ENET_DEBUG_OFFLOAD("%s: netfilter already created in nfilter netfilter list\n", __func__);
			goto _ret_update_nat;
		} else if (ipv4nat_pn_entry) {
			ENET_DEBUG_OFFLOAD("%s: netfilter already created in pending netfilter list\n", __func__);
			goto _ret_update_nat;
		}

		ipv4nat_pn_entry = apm_add_enet_offload_entry(ipv4nat_pn_head, key,
			sizeof(struct apm_ipv4nat_info) * IP_CT_DIR_MAX);

		/* If unable to make netfilter entry in pending netfilter list, return error */
		if (ipv4nat_pn_entry == NULL) {
			rc = APM_RC_ERROR;
			ENET_ERROR_OFFLOAD("%s: unable to create netfilter entry\n", __func__);
			goto _ret_update_nat;
		}

		apm_ethoffload_ops.ino_nat_unuse_entries++;

		ipv4nat = ipv4nat_pn_entry->ipv4nat;

		/* Invalidate all information to indicate new entry */
		ipv4nat[0].iport = INVALID_32BIT_INDEX;
		ipv4nat[0].eport = INVALID_32BIT_INDEX;
		ipv4nat[0].avl_index = INVALID_32BIT_INDEX;
		ipv4nat[0].dbptr_index = INVALID_32BIT_INDEX;
		ipv4nat[1].iport = INVALID_32BIT_INDEX;
		ipv4nat[1].eport = INVALID_32BIT_INDEX;
		ipv4nat[1].avl_index = INVALID_32BIT_INDEX;
		ipv4nat[1].dbptr_index = INVALID_32BIT_INDEX;

		/* For any apm_ipv4nat_offload_type, storing SNAT tuple in index 0 & DNAT tuple in index 1 */
		if (type == APM_IPV4NAT_OFFLOAD_SNAT || type == APM_IPV4NAT_OFFLOAD_SNAT_IP) {
			/* For OFFLOAD_SNAT or OFFLOAD_SNAT_IP type, SNAT is in IP_CT_DIR_ORIGINAL tuple */
			ipv4nat[0].dir = IP_CT_DIR_ORIGINAL;
			ipv4nat[0].src_ip = src_ip;
			ipv4nat[0].dst_ip = dst_ip;
			ipv4nat[0].src_l4 = src_l4;
			ipv4nat[0].dst_l4 = dst_l4;
			/* For OFFLOAD_SNAT or OFFLOAD_SNAT_IP type, SNAT is done by replacing source ip:l4 with IP_CT_DIR_REPLY's destination ip:l4 */
			ipv4nat[0].nf_l3 = r_dst_ip;
			/* For OFFLOAD_SNAT_IP type, SNAT is done by only replacing source ip and not source l4 */
			ipv4nat[0].nf_l4 = (type == APM_IPV4NAT_OFFLOAD_SNAT) ? r_dst_l4 : 0;

			/* For OFFLOAD_SNAT or OFFLOAD_SNAT_IP type, DNAT is in IP_CT_DIR_REPLY tuple */
			ipv4nat[1].dir = IP_CT_DIR_REPLY;
			ipv4nat[1].src_ip = r_src_ip;
			ipv4nat[1].dst_ip = r_dst_ip;
			ipv4nat[1].src_l4 = r_src_l4;
			ipv4nat[1].dst_l4 = r_dst_l4;
			/* For OFFLOAD_SNAT or OFFLOAD_SNAT_IP type, DNAT is done by replacing destination ip:l4 with IP_CT_DIR_ORIGINAL's source ip:l4 */
			ipv4nat[1].nf_l3 = src_ip;
			/* For OFFLOAD_SNAT_IP type, DNAT is done by only replacing destination ip and not destination l4 */
			ipv4nat[1].nf_l4 = (type == APM_IPV4NAT_OFFLOAD_SNAT) ? src_l4 : 0;
		} else {
			/* For OFFLOAD_DNAT or OFFLOAD_DNAT_IP type, SNAT is in IP_CT_DIR_REPLY tuple */
			ipv4nat[0].dir = IP_CT_DIR_REPLY;
			ipv4nat[0].src_ip = r_src_ip;
			ipv4nat[0].dst_ip = r_dst_ip;
			ipv4nat[0].src_l4 = r_src_l4;
			ipv4nat[0].dst_l4 = r_dst_l4;
			/* For OFFLOAD_DNAT or OFFLOAD_DNAT_IP type, SNAT is done by replacing source ip:l4 with IP_CT_DIR_ORIGINAL's destination ip:l4 */
			ipv4nat[0].nf_l3 = dst_ip;
			/* For OFFLOAD_DNAT_IP type, SNAT is done by only replacing source ip and not source l4 */
			ipv4nat[0].nf_l4 = (type == APM_IPV4NAT_OFFLOAD_DNAT) ? dst_l4 : 0;

			/* For OFFLOAD_DNAT or OFFLOAD_DNAT_IP type, DNAT is in IP_CT_DIR_ORIGINAL tuple */
			ipv4nat[1].dir = IP_CT_DIR_ORIGINAL;
			ipv4nat[1].src_ip = src_ip;
			ipv4nat[1].dst_ip = dst_ip;
			ipv4nat[1].src_l4 = src_l4;
			ipv4nat[1].dst_l4 = dst_l4;
			/* For OFFLOAD_DNAT or OFFLOAD_DNAT_IP type, DNAT is done by replacing destination ip:l4 with IP_CT_DIR_REPLY's source ip:l4 */
			ipv4nat[1].nf_l3 = r_src_ip;
			/* For OFFLOAD_DNAT_IP type, DNAT is done by only replacing destination ip and not destination l4 */
			ipv4nat[1].nf_l4 = (type == APM_IPV4NAT_OFFLOAD_DNAT) ? r_src_l4 : 0;
		}

		/* apm_ipv4nat_offload_type */
		ipv4nat[0].type = type ^ ipv4nat[0].dir;
		ipv4nat[1].type = type ^ ipv4nat[1].dir;

		apm_update_nat_route_arp(ipv4nat_pn_entry, 1);
		rc = apm_add_nat(ipv4nat_pn_entry, 1);
	/* rm_nat, remove netfilter entry (avl entry) in CLE */
	} else {
		if (ipv4nat_nf_entry) {
			apm_update_nat_route_arp(ipv4nat_nf_entry, 0);
			rc = apm_del_nat(ipv4nat_nf_entry, 1);
		} else if (ipv4nat_pn_entry) {
			apm_update_nat_route_arp(ipv4nat_pn_entry, 0);
			apm_del_enet_offload_entry(ipv4nat_pn_entry);
		}
	}

_ret_update_nat:
	return rc;
}

static int apm_add_route(int iport,
	struct apm_enet_offload_list *ipv4fwd_gw_entry,
	struct apm_enet_offload_list *ipv4fwd_rt_entry)
{
	int rc = APM_RC_OK;
	struct apm_ipv4rth_info *ipv4rth = ipv4fwd_rt_entry->ipv4rth;
	struct apm_enet_offload_list *ipv4nat_pn_entry, *ipv4nat_pn_next;
	struct apm_enet_offload_list *ipv4nat_nf_entry;
	struct list_head *ipv4nat_pn_head = &ipv4nat_pending;
	struct list_head *ipv4nat_nf_head = &ipv4nat_nfilter;
	int i, flag;

	/* check & add NAT entry for pending list NAT entries */
	list_for_each_entry_safe(ipv4nat_pn_entry, ipv4nat_pn_next, ipv4nat_pn_head, node) {
		flag = 0;

		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &ipv4nat_pn_entry->ipv4nat[i];

			if (ipv4nat_pn_entry->key[0 ^ i] != ipv4fwd_rt_entry->key[0] ||
				ipv4nat_pn_entry->key[1 ^ i] != ipv4fwd_rt_entry->key[1])
				continue;

			if (apm_update_nat_route(ipv4nat, ipv4fwd_gw_entry->key[0], ipv4rth, 1))
				continue;

			flag++;
		}

		if (flag)
			apm_add_nat(ipv4nat_pn_entry, 1);
	}

	/* check & update arp entry (dbptr entry) for nfilter list NAT entries */
	list_for_each_entry(ipv4nat_nf_entry, ipv4nat_nf_head, node) {
		flag = 0;

		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &ipv4nat_nf_entry->ipv4nat[i];

			if (ipv4nat_nf_entry->key[0 ^ i] != ipv4fwd_rt_entry->key[0] ||
				ipv4nat_nf_entry->key[1 ^ i] != ipv4fwd_rt_entry->key[1])
				continue;

			if (apm_update_nat_route(ipv4nat, ipv4fwd_gw_entry->key[0], ipv4rth, 1))
				continue;

			flag++;
		}

		/* Add offload details so that next packet does not go to Linux Kernel Network Stack */
		if (flag)
			apm_add_nat(ipv4nat_nf_entry, 0);
	}

	return rc;
}

static int apm_del_route(int iport,
	struct apm_enet_offload_list *ipv4fwd_gw_entry,
	struct apm_enet_offload_list *ipv4fwd_rt_entry)
{
	int rc = APM_RC_OK;
	struct apm_ipv4rth_info *ipv4rth = ipv4fwd_rt_entry->ipv4rth;
	struct apm_enet_offload_list *ipv4nat_pn_entry, *ipv4nat_nf_entry;
	struct list_head *ipv4nat_pn_head = &ipv4nat_pending;
	struct list_head *ipv4nat_nf_head = &ipv4nat_nfilter;
	int i, flag;

	/* check & update arp/route entry for pending list NAT entries */
	list_for_each_entry(ipv4nat_pn_entry, ipv4nat_pn_head, node) {
		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &ipv4nat_pn_entry->ipv4nat[i];

			if (ipv4nat_pn_entry->key[0 ^ i] != ipv4fwd_rt_entry->key[0] ||
				ipv4nat_pn_entry->key[1 ^ i] != ipv4fwd_rt_entry->key[1])
				continue;

			if (apm_update_nat_route(ipv4nat, 0, ipv4rth, 0))
				continue;
		}
	}

	/* check & update arp/route entry for nfilter list NAT entries */
	list_for_each_entry(ipv4nat_nf_entry, ipv4nat_nf_head, node) {
		flag = 0;

		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &ipv4nat_nf_entry->ipv4nat[i];

			if (ipv4nat_nf_entry->key[0 ^ i] != ipv4fwd_rt_entry->key[0] ||
				ipv4nat_nf_entry->key[1 ^ i] != ipv4fwd_rt_entry->key[1])
				continue;

			if (apm_update_nat_route(ipv4nat, 0, ipv4rth, 0))
				continue;

			flag++;
		}

		/* Remove offload details so that next packet goes to Linux Kernel Network Stack */
		if (flag)
			rc = apm_del_nat(ipv4nat_nf_entry, 0);
	}

	/* If route reference count is zero, remove route entry from route list */
	if (ipv4rth->ref_count == 0) {
		apm_del_enet_offload_entry(ipv4fwd_rt_entry);
		apm_ethoffload_ops.ino_route_unuse_entries--;
	} else {
		printk("Gateway IPv4 Route rt_dst %d.%d.%d.%d rt_src %d.%d.%d.%d "
			"rt_gateway %d.%d.%d.%d ref_count is non zero (%d) !!\n",
			(ipv4fwd_rt_entry->key[1] & 0xFF000000) >> 24,
			(ipv4fwd_rt_entry->key[1] & 0x00FF0000) >> 16,
			(ipv4fwd_rt_entry->key[1] & 0x0000FF00) >>  8,
			(ipv4fwd_rt_entry->key[1] & 0x000000FF) >>  0,
			(ipv4fwd_rt_entry->key[0] & 0xFF000000) >> 24,
			(ipv4fwd_rt_entry->key[0] & 0x00FF0000) >> 16,
			(ipv4fwd_rt_entry->key[0] & 0x0000FF00) >>  8,
			(ipv4fwd_rt_entry->key[0] & 0x000000FF) >>  0,
			(ipv4fwd_gw_entry->key[0] & 0xFF000000) >> 24,
			(ipv4fwd_gw_entry->key[0] & 0x00FF0000) >> 16,
			(ipv4fwd_gw_entry->key[0] & 0x0000FF00) >>  8,
			(ipv4fwd_gw_entry->key[0] & 0x000000FF) >>  0,
			ipv4rth->ref_count);
	}

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

	ipv4fwd_rt_head = &ipv4fwd_gw_entry->ipv4fwd->rt_head;

	/* If rm_route and route list empty, return error */
	if (!mk_entry && list_empty(ipv4fwd_rt_head)) {
		ENET_DEBUG_OFFLOAD("%s: route list empty\n", __func__);
		goto _ret_update_route;
	}

	/* Find route entry from route list */
	key[0] = rt_src;     /* SRC IP */
	key[1] = rt_dst;     /* DST IP */
	key[2] = OFFLOAD_IPN(iport); /* Ingress Port Number */
	ipv4fwd_rt_entry = (void *)apm_find_enet_offload_entry(ipv4fwd_rt_head, key);

	/* mk_route */
	if (mk_entry) {
		/* If route entry not found, make route entry in route list */
		if (ipv4fwd_rt_entry == NULL) {
			ipv4fwd_rt_entry = apm_add_enet_offload_entry(ipv4fwd_rt_head, key,
				sizeof(struct apm_ipv4rth_info));
			/* If unable to make route entry in route list, return error */
			if (ipv4fwd_rt_entry == NULL) {
				rc = APM_RC_ERROR;
				ENET_ERROR_OFFLOAD("%s: unable to create route entry\n", __func__);
				goto _ret_update_route;
			}

			apm_ethoffload_ops.ino_route_unuse_entries++;
			/* Update IPv4 Route Ingress & Egress Port number */
			ipv4fwd_rt_entry->ipv4rth->iport = iport;
			ipv4fwd_rt_entry->ipv4rth->eport = eport;
		}

		rc = apm_add_route(iport, ipv4fwd_gw_entry, ipv4fwd_rt_entry);
	/* rm_route and route entry found, remove route entry (avl entry) in CLE */
	} else if (ipv4fwd_rt_entry) {
		rc = apm_del_route(iport, ipv4fwd_gw_entry, ipv4fwd_rt_entry);
	}

_ret_update_route:
	return rc;
}

static int apm_add_arp(struct apm_enet_offload_list *ipv4fwd_gw_entry, u8 *rt_mac)
{
	int rc = APM_RC_OK;
	struct apm_ipv4fwd_info *ipv4fwd = ipv4fwd_gw_entry->ipv4fwd;
	struct apm_enet_offload_list *ipv4nat_pn_entry, *ipv4nat_pn_next;
	struct apm_enet_offload_list *ipv4nat_nf_entry;
	struct list_head *ipv4nat_pn_head = &ipv4nat_pending;
	struct list_head *ipv4nat_nf_head = &ipv4nat_nfilter;
	int i, flag;

	/* check & add NAT entry for pending list NAT entries */
	list_for_each_entry_safe(ipv4nat_pn_entry, ipv4nat_pn_next, ipv4nat_pn_head, node) {
		flag = 0;

		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &ipv4nat_pn_entry->ipv4nat[i];

			if (ipv4nat->rt_gateway != ipv4fwd_gw_entry->key[0])
				continue;

			if (apm_update_nat_arp(ipv4nat, ipv4fwd, 1))
				continue;

			flag++;
		}

		if (flag)
			apm_add_nat(ipv4nat_pn_entry, 1);
	}

	/* check & update arp entry (dbptr entry) for nfilter list NAT entries */
	list_for_each_entry(ipv4nat_nf_entry, ipv4nat_nf_head, node) {
		flag = 0;

		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &ipv4nat_nf_entry->ipv4nat[i];

			if (ipv4nat->rt_gateway != ipv4fwd_gw_entry->key[0])
				continue;

			if (apm_update_nat_arp(ipv4nat, ipv4fwd, 1))
				continue;

			flag++;
		}

		/* Add offload details so that next packet does not go to Linux Kernel Network Stack */
		if (flag)
			apm_add_nat(ipv4nat_nf_entry, 0);
	}

	return rc;
}

static int apm_del_arp(struct apm_enet_offload_list *ipv4fwd_gw_entry)
{
	int rc = APM_RC_OK;
	struct apm_ipv4fwd_info *ipv4fwd = ipv4fwd_gw_entry->ipv4fwd;
	struct apm_enet_offload_list *ipv4nat_pn_entry, *ipv4nat_nf_entry;
	struct list_head *ipv4nat_pn_head = &ipv4nat_pending;
	struct list_head *ipv4nat_nf_head = &ipv4nat_nfilter;
	int i, flag;

	/* check & update arp entry (dbptr entry) for pending list NAT entries */
	list_for_each_entry(ipv4nat_pn_entry, ipv4nat_pn_head, node) {
		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &ipv4nat_pn_entry->ipv4nat[i];

			if (ipv4nat->rt_gateway != ipv4fwd_gw_entry->key[0])
				continue;

			if (apm_update_nat_arp(ipv4nat, ipv4fwd, 0))
				continue;
		}
	}

	/* check & update arp entry (dbptr entry) for nfilter list NAT entries */
	list_for_each_entry(ipv4nat_nf_entry, ipv4nat_nf_head, node) {
		flag = 0;

		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &ipv4nat_nf_entry->ipv4nat[i];

			if (ipv4nat->rt_gateway != ipv4fwd_gw_entry->key[0])
				continue;

			if (apm_update_nat_arp(ipv4nat, ipv4fwd, 0))
				continue;

			flag++;
		}

		/* Remove offload details so that next packet goes to Linux Kernel Network Stack */
		if (flag)
			rc = apm_del_nat(ipv4nat_nf_entry, 0);
	}

	/* If route list invalid or empty, check ref_count, index & delete arp entry */
	if (INVALID_LIST_HEAD(&ipv4fwd->rt_head) ||
			list_empty(&ipv4fwd->rt_head)) {

		/* If arp reference count is zero, remove arp entry from arp list */
		if (ipv4fwd->ref_count == 0) {
			apm_del_enet_offload_entry(ipv4fwd_gw_entry);
			apm_ethoffload_ops.ino_arp_unuse_entries--;
		} else {
			printk("Gateway IPv4 ARP rt_gateway %d.%d.%d.%d "
				"ref_count is non zero (%d) !!\n",
				(ipv4fwd_gw_entry->key[0] & 0xFF000000) >> 24,
				(ipv4fwd_gw_entry->key[0] & 0x00FF0000) >> 16,
				(ipv4fwd_gw_entry->key[0] & 0x0000FF00) >>  8,
				(ipv4fwd_gw_entry->key[0] & 0x000000FF) >>  0,
				ipv4fwd->ref_count);
		}
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

		memset(ipv4fwd_gw_entry->ipv4fwd->rt_mac, 0, IFHWADDRLEN);
		rc |= apm_del_arp(ipv4fwd_gw_entry);
	}

_ret_arp_routes:
	apm_cle_unlock(flags);

	return rc;
}

static void apm_show_arp(int eport)
{
	int search_all_ports = 0;
	struct list_head *head;
	struct apm_enet_offload_list *entry;

	printk("ARP Entries unprogrammed %d\n",
		apm_ethoffload_ops.ino_arp_unuse_entries);

	printk("Gateway         MAC Address        OutIf RefCnt\n");
	head = &ipv4fwd_gateway;

	if (INVALID_LIST_HEAD(head))
		return;

	if (eport == CLE_MAX_PORTS)
		search_all_ports = 1;

	list_for_each_entry(entry, head, node) {
		char gateway[16];
		struct apm_ipv4fwd_info *ipv4fwd;
		__be32 rt_gateway;
		u8 *rt_mac;
		char *eport_devname;

		if (search_all_ports)
			eport = entry->key[1] & ~OFFLOAD_EPN(0);
		else if (entry->key[1] != OFFLOAD_EPN(eport))
			continue;

		ipv4fwd = entry->ipv4fwd;
		rt_gateway = entry->key[0];
		rt_mac = ipv4fwd->rt_mac;
		/* Any Ethernet Ports (Internal or External) are valid/allowed Ingress Port */
		eport_devname = (eport != -1 ?
			offload_ndev[eport]->name :
			NULL);

		sprintf(gateway, "%pI4", &rt_gateway);
		printk("%-15s %02x:%02x:%02x:%02x:%02x:%02x %6s %6d\n",
			gateway,
			rt_mac[0], rt_mac[1], rt_mac[2],
			rt_mac[3], rt_mac[4], rt_mac[5],
			eport_devname, ipv4fwd->ref_count);
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

		if (INVALID_LIST_HEAD(ipv4fwd_rt_head) ||
				list_empty(ipv4fwd_rt_head))
			goto _skip_fl_routes;

		list_for_each_entry_safe(ipv4fwd_rt_entry, ipv4fwd_rt_next, ipv4fwd_rt_head, node) {
			struct apm_ipv4rth_info *ipv4rth = ipv4fwd_rt_entry->ipv4rth;
			int iport = ipv4rth->iport;

			rc |= apm_del_route(iport, ipv4fwd_gw_entry, ipv4fwd_rt_entry);
		}

_skip_fl_routes:
		memset(ipv4fwd->rt_mac, 0, IFHWADDRLEN);
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

	printk("Route Entries unprogrammed %d\n",
		apm_ethoffload_ops.ino_route_unuse_entries);

	printk("Source          Destination     Gateway          OutIf   InIf RefCnt\n");

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
		u8 *rt_mac;

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

		list_for_each_entry(ipv4fwd_rt_entry, ipv4fwd_rt_head, node) {
			char src[16];
			char dst[16];
			struct apm_ipv4rth_info *ipv4rth = ipv4fwd_rt_entry->ipv4rth;
			__be32 rt_src = ipv4fwd_rt_entry->key[0];
			__be32 rt_dst = ipv4fwd_rt_entry->key[1];
			int iport, eport;
			char *iport_devname, *eport_devname;

			/* Only APM Ethernet Ports (Internal) are valid/allowed Ingress Port */
			iport = (ETH_INT_PORT(ipv4rth->iport) &&
				offload_ndev[ipv4rth->iport] ?
				ipv4rth->iport : -1);
			iport_devname = (iport != -1 ?
				offload_ndev[iport]->name :
				NULL);

			/* Any Ethernet Ports (Internal or External) are valid/allowed Ingress Port */
			eport = (ETH_ANY_PORT(ipv4rth->eport) &&
				offload_ndev[ipv4rth->eport] ?
				ipv4rth->eport : -1);
			eport_devname = (eport != -1 ?
				offload_ndev[eport]->name :
				NULL);

			sprintf(src, "%pI4", &rt_src);
			sprintf(dst, "%pI4", &rt_dst);
			printk("%-15s %-15s %-15s %6s %6s %6d\n",
				src, dst, gateway, iport_devname, eport_devname, ipv4rth->ref_count);
		}
	}
}

static int apm_mk_nat(__be32 src_ip, __be32 dst_ip, __be16 src_l4, __be16 dst_l4,
	__be32 r_src_ip, __be32 r_dst_ip, __be16 r_src_l4, __be16 r_dst_l4,
	enum apm_ipv4nat_offload_type type)
{
	int rc;
	unsigned long flags;

	apm_cle_lock(flags);
	rc = apm_update_nat(src_ip, dst_ip, src_l4, dst_l4, r_src_ip, r_dst_ip, r_src_l4, r_dst_l4, type, 1);
	apm_cle_unlock(flags);

	return rc;
}

static int apm_rm_nat(__be32 src_ip, __be32 dst_ip, __be16 src_l4, __be16 dst_l4,
	__be32 r_src_ip, __be32 r_dst_ip, __be16 r_src_l4, __be16 r_dst_l4,
	enum apm_ipv4nat_offload_type type)
{
	int rc;
	unsigned long flags;

	apm_cle_lock(flags);
	rc = apm_update_nat(src_ip, dst_ip, src_l4, dst_l4, r_src_ip, r_dst_ip, r_src_l4, r_dst_l4, type, 0);
	apm_cle_unlock(flags);

	return rc;
}

static void apm_show_nat_table(struct list_head *head)
{
	struct apm_enet_offload_list *entry;

	if (INVALID_LIST_HEAD(head))
		return;

	list_for_each_entry(entry, head, node) {
		int i;
		for (i = 0; i < IP_CT_DIR_MAX; i++) {
			struct apm_ipv4nat_info *ipv4nat = &entry->ipv4nat[i ^ entry->ipv4nat[0].dir];
			__be32 src_ip = ipv4nat->src_ip;
			__be32 dst_ip = ipv4nat->dst_ip;
			__be16 src_l4 = ipv4nat->src_l4;
			__be16 dst_l4 = ipv4nat->dst_l4;
			__be32 gateway_ip = ipv4nat->rt_gateway;
			__be32 nf_l3 = ipv4nat->nf_l3;
			__be16 nf_l4 = ipv4nat->nf_l4;
			u8 *nf_mac = ipv4nat->rt_mac;
			/* Only APM Ethernet Ports (Internal) are valid/allowed Ingress Port */
			u32 iport = (ETH_INT_PORT(ipv4nat->iport) &&
				offload_ndev[ipv4nat->iport] ?
				ipv4nat->iport : -1);
			char *iport_devname = (iport != -1 ?
				offload_ndev[iport]->name :
				NULL);
			/* ANY Ethernet Ports (Internal or External) are valid/allowed Egress Port */
			u32 eport = (ETH_ANY_PORT(ipv4nat->eport) &&
				offload_ndev[ipv4nat->eport] ?
				ipv4nat->eport : -1);
			char *eport_devname = (eport != -1 ?
				offload_ndev[eport]->name :
				NULL);
			int avl_index = ((ipv4nat->avl_index != INVALID_32BIT_INDEX) ?
				ipv4nat->avl_index : -1);
			int dbptr_index = (((ipv4nat->dbptr_index >= SYSTEM_START_DBPTR) &&
				(ipv4nat->dbptr_index < SYSTEM_END_DBPTR)) ?
				ipv4nat->dbptr_index : -1);
			int dst_qid = ((iport != -1 && dbptr_index != -1) ?
				get_shadow_cle_dbptrs(CLE_INT_PORT(iport))[dbptr_index].dstqid :
				-1);
			enum apm_ipv4nat_offload_type type = ipv4nat->type;
			char *type_str = (type == APM_IPV4NAT_OFFLOAD_SNAT ? "SNAT" :
					(type == APM_IPV4NAT_OFFLOAD_DNAT ? "DNAT" :
					(type == APM_IPV4NAT_OFFLOAD_SNAT_IP ? "SNAT_IP" :
					(type == APM_IPV4NAT_OFFLOAD_DNAT_IP ? "DNAT_IP" :
					"-------" ))));
			char *dir_str = (i == IP_CT_DIR_ORIGINAL ? "ORI" :
					(i == IP_CT_DIR_REPLY ? "REP" :
					"---"));
			char src[16], dst[16], nf[16], gateway[16];


			sprintf(src, "%pI4", &src_ip);
			sprintf(dst, "%pI4", &dst_ip);
			sprintf(nf, "%pI4", &nf_l3);
			sprintf(gateway, "%pI4", &gateway_ip);
			printk("%s %-7s %-15s %-15s %5d %5d %-15s "
				"%02x:%02x:%02x:%02x:%02x:%02x %6s %6s %7d %6d %6d "
				"%-15s %5d\n",
				dir_str, type_str, src, dst, src_l4, dst_l4, gateway,
				nf_mac[0], nf_mac[1], nf_mac[2],
				nf_mac[3], nf_mac[4], nf_mac[5],
				iport_devname, eport_devname,
				avl_index, dbptr_index, dst_qid,
				nf, nf_l4);
		}
		printk("\n");
	}
}

static void apm_show_nat(void)
{
	u32 unuse_result_ptr;
	struct list_head *head;
	struct apm_index_list *entry;

	unuse_result_ptr = 0;
	head = &ipv4nat_result_ptr_index[0];
	printk("Showing unuse allocated result pointer indices for CLE0\n");
	if (!(INVALID_LIST_HEAD(head))) {
		list_for_each_entry(entry, head, node) {
			printk("%4d ", entry->index);
			unuse_result_ptr++;
		}
		if (unuse_result_ptr)
			printk("\n");
	}
	printk("Total unuse allocated result pointer for CLE0 %d\n", unuse_result_ptr);
#ifndef CONFIG_APM862xx
	unuse_result_ptr = 0;
	head = &ipv4nat_result_ptr_index[1];
	printk("Showing unuse allocated result pointer indices for CLE1\n");
	if (!(INVALID_LIST_HEAD(head))) {
		list_for_each_entry(entry, head, node) {
			printk("%4d ", entry->index);
			unuse_result_ptr++;
		}
		if (unuse_result_ptr)
			printk("\n");
	}
	printk("Total unuse allocated result pointer for CLE1 %d\n", unuse_result_ptr);
#endif

	printk("NAT-ARP Entries (result pointer) programmed in CLE0 %d\n",
		apm_ethoffload_ops.ino_arp_cache_entries_cle[0]);
#ifndef CONFIG_APM862xx
	printk("NAT-ARP Entries (result pointer) programmed in CLE1 %d\n",
		apm_ethoffload_ops.ino_arp_cache_entries_cle[1]);
#endif

	printk("NAT-Route Entries (avl node) programmed in CLE0 %d\n",
		apm_ethoffload_ops.ino_route_cache_entries_cle[0]);
#ifndef CONFIG_APM862xx
	printk("NAT-Route Entries (avl node) programmed in CLE1 %d\n",
		apm_ethoffload_ops.ino_route_cache_entries_cle[1]);
#endif

	printk("Showing ipv4nat pending list\n");
	printk("Dir Type    Source          Destination     SRCL4 DSTL4 Gateway         MAC Address         InIf  OutIf AVLNode ResPtr DstQID NFL3             NFL4\n");
	apm_show_nat_table(&ipv4nat_pending);

	printk("Showing ipv4nat nfilter list\n");
	printk("Dir Type    Source          Destination     SRCL4 DSTL4 Gateway         MAC Address         InIf  OutIf AVLNode ResPtr DstQID NFL3             NFL4\n");
	apm_show_nat_table(&ipv4nat_nfilter);
}

int apm_mkarp_ipv4_nat(struct neighbour *n)
{
	__be32 rt_gateway = cpu_to_be32(*(u32 *)n->primary_key);
	u8 *rt_mac = n->ha;
	int eport = apm_inet_offload_ndev_to_index(n->dev);

	apm_ipv4nat_offload_list_entry();
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
		goto _ret_mkarp_ipv4_nat;

	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_ANY_PORT(eport))
		apm_mk_arp(rt_gateway, rt_mac, eport);

_ret_mkarp_ipv4_nat:
	return 0;
}

void apm_rmarp_ipv4_nat(struct neighbour *n)
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

void apm_flarp_ipv4_nat(struct net_device *dev)
{
	int eport = apm_inet_offload_ndev_to_index(dev);

	ENET_DEBUG_OFFLOAD("%s: For eport %d (%s)\n", __func__, eport, dev->name);

	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_ANY_PORT(eport))
		apm_fl_arps(eport);
}

int apm_ipv4nat_offload_init(int iport)
{
	struct net_device *dev;
	struct apm_enet_dev_base *ipriv_dev;
	int i, rc = APM_RC_OK;
	struct ptree_kn kn;
	struct apm_ptree_config *ptree_config;

	struct ptree_branch branch[] = {
	{      0, 0xffff,   EQT, PTREE_ALLOC(0), EW_BRANCH(1),  2, 0, JMP_REL, JMP_FW },   /* 0-1 bytes of MAC Address */
	{      0, 0xffff,   EQT, PTREE_ALLOC(0), EW_BRANCH(2),  2, 0, JMP_REL, JMP_FW },   /* 2-3 bytes of MAC Address */
	{      0, 0xffff,   EQT, PTREE_ALLOC(0), EW_BRANCH(3),  8, 0, JMP_REL, JMP_FW },   /* 4-5 bytes of MAC Address */
	{      0, 0x0800,   EQT, PTREE_ALLOC(0), EW_BRANCH(4),  2, 0, JMP_REL, JMP_FW },   /* Packet type IPv4 */
	{ 0x00ff, 0x4500,   EQT, PTREE_ALLOC(0), EW_BRANCH(5),  8, 0, JMP_REL, JMP_FW },   /* IPv4 version and Header Length */
	{ 0x00ff, 0x0200, LTEQT, PTREE_ALLOC(1), EW_BRANCH(0),  4, 0, JMP_REL, JMP_FW },   /* 2 <= TTL */

	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(1), EW_BRANCH(1),  2, 0, JMP_REL, JMP_FW },   /* Src IP Address 0-1 */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(1), EW_BRANCH(2),  2, 0, JMP_REL, JMP_FW },   /* Src IP Address 2-3 */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(1), EW_BRANCH(3),  2, 0, JMP_REL, JMP_FW },   /* Dst IP Address 0-1 */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(2), EW_BRANCH(0), 10, 0, JMP_REL, JMP_BW },   /* Dst IP Address 2-3 */

	{ 0xff00, 0x0006,   EQT, PTREE_ALLOC(4), EW_BRANCH(0), 12, 1, JMP_REL, JMP_FW },   /* IP Proto is TCP */
	{ 0xff00, 0x0011,   EQT, PTREE_ALLOC(4), EW_BRANCH(0), 12, 1, JMP_REL, JMP_FW },   /* IP Proto is UDP */
	{ 0xff00, 0x0021,   EQT, PTREE_ALLOC(4), EW_BRANCH(0), 12, 1, JMP_REL, JMP_FW },   /* IP Proto is DCCP */
	{ 0xff00, 0x0084,   EQT, PTREE_ALLOC(4), EW_BRANCH(0), 12, 1, JMP_REL, JMP_FW },   /* IP Proto is SCTP */
	{ 0xff00, 0x0001,   EQT, PTREE_ALLOC(4), EW_BRANCH(2), 16, 1, JMP_REL, JMP_FW },   /* IP Proto is ICMP */
	{ 0xff00, 0x002F,   EQT, PTREE_ALLOC(3), EW_BRANCH(0), 12, 1, JMP_REL, JMP_FW },   /* IP Proto is GRE */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(6), EW_BRANCH(0),  0, 0, 0, 0 },   /* Jump to Last Node */

	/* GRE version should be 1 for PPTP else send to Linux stack */
	{ 0xfff8, 0x0001,   EQT, PTREE_ALLOC(4), EW_BRANCH(3),  6, 1, JMP_REL, JMP_FW },   /* GRE version 1 for PPTP */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(6), EW_BRANCH(0),  0, 0, 0, 0 },   /* Jump to Last Node */

	/* AVL String capturing 16bit value */
	/* TUDS group i.e. TCP, UDP, DCCP, SCTP AVL string creation to include source port and destination port */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(4), EW_BRANCH(1),  2, 0, JMP_REL, JMP_FW },   /* Src Port */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(6), EW_BRANCH(0),  0, 0, 0, 0 },   /* Dst Port */
	/* ICMP AVL string creation to include 16bit identifier & 8bit ICMP proto ID and 8bit to zero */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(5), EW_BRANCH(0), 16, 0, JMP_REL, JMP_BW },   /* ICMP ID */
	/* GRE AVL string creation to include 16bit key & 8bit GRE proto ID and 8bit to zero */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(5), EW_BRANCH(0), 18, 0, JMP_REL, JMP_BW },   /* GRE Key ID */

	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(5), EW_BRANCH(1), 10, 0, JMP_REL, JMP_BW },   /* IP Proto */
	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(6), EW_BRANCH(0),  0, 0, 0, 0 },   /* 8bit 00 from EtherType 0x0800 */

	{ 0xffff, 0x0000,   EQT, PTREE_ALLOC(7), KEY_INDEX(0),  0, 0, 0, 0 },   /* Allow all of the above */
	};

	struct ptree_dn dn[] = {
	{ START_NODE,   DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 6, &branch[0]  },
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(BOTH_BYTES), 0, 0, 0, 4, &branch[6]  },
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 7, &branch[10] },
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 2, &branch[17] },
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(BOTH_BYTES), 0, 0, 0, 4, &branch[19] },
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(SECOND_BYTE),0, 0, 0, 2, &branch[23] },
	{ LAST_NODE,    DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 1, &branch[25] },
	};

	struct ptree_node node[] = {
	{ PTREE_ALLOC(0), EWDN, 0, (struct ptree_dn*)&dn[0] },
	{ PTREE_ALLOC(1), EWDN, 0, (struct ptree_dn*)&dn[1] },
	{ PTREE_ALLOC(2), EWDN, 0, (struct ptree_dn*)&dn[2] },
	{ PTREE_ALLOC(3), EWDN, 0, (struct ptree_dn*)&dn[3] },
	{ PTREE_ALLOC(4), EWDN, 0, (struct ptree_dn*)&dn[4] },
	{ PTREE_ALLOC(5), EWDN, 0, (struct ptree_dn*)&dn[5] },
	{ PTREE_ALLOC(6), EWDN, 0, (struct ptree_dn*)&dn[6] },
	{ PTREE_ALLOC(7),   KN, 0,    (struct ptree_kn*)&kn },
	};

	if (ipv4nat_offload_init_done[iport])
		goto _ret_ipv4nat_offload_init;

	dev = find_netdev(iport);
	ptree_config = apm_find_ptree_config(iport, CLE_PTREE_DEFAULT);

	if (ptree_config == NULL) {
		printk("%s interface is down\n", dev->name);
		rc = APM_RC_ERROR;
		goto _ret_ipv4nat_offload_init;
	}

	ipriv_dev = netdev_priv(dev);
	ipriv_dev->in_poll_rx_msg_desc.is_msg16 = 0;
	iport_qm_queue[iport] = &ipriv_dev->qm_queues[apm_cle_system_id];
	if (!(ipriv_dev->offload.offload_available & IPP_IPV4NAT_OFFLOAD_FW_MASK))
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

	ptree_config = apm_add_ptree_config(iport, CLE_PTREE_IPV4NAT);
	if ((rc = apm_ptree_alloc(iport, ARRAY_SIZE(node), 0, &node[0], NULL,
			ptree_config)) != APM_RC_OK) {
		ENET_ERROR_OFFLOAD("apm_ptree_alloc error %d for port %d\n", rc, iport);
		rc = APM_RC_ERROR;
		goto _ret_ipv4nat_offload_init;
	}
	ptree_config->default_result = DFCLSRESDBPRIORITY0_WR(7) |
					DFCLSRESDBPTR0_WR(kn.result_pointer);

	ipv4nat_offload_init_done[iport] = 1;

_ret_ipv4nat_offload_init:
	return rc;
}

int apm_mkroute_ipv4_nat(struct sk_buff *skb, struct rtable *rth)
{
	int iport = apm_inet_offload_ndev_to_index(skb->dev);
	int eport = apm_inet_offload_ndev_to_index(rth->u.dst.dev);
	int rc = APM_RC_OK;
	__be32 rt_dst = rth->rt_dst;
	__be32 rt_src = rth->rt_src;
	__be32 rt_gateway = rth->rt_gateway;
	u8 *rt_mac = (rth->u.dst.neighbour) ? (rth->u.dst.neighbour->ha) : NULL;

	apm_ipv4nat_offload_list_entry();
	ENET_DEBUG_OFFLOAD("%s: iport %d (%s) -> eport %d (%s): "
		"rt_dst %d.%d.%d.%d "
		"rt_src %d.%d.%d.%d "
		"rt_gateway %d.%d.%d.%d\n",
		__func__, iport, skb->dev->name, eport, rth->u.dst.dev->name,
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

	if (rth->u.dst.neighbour == NULL) {
		ENET_DEBUG_OFFLOAD("%s: neighbour is NULL, "
			"ignoring\n", __func__);
		goto _ret_mkroute_ipv4_nat;
	} else if (is_broadcast_ether_addr(rt_mac)) {
		ENET_DEBUG_OFFLOAD("%s: neighbour mac ff:ff:ff:ff:ff:ff, "
			"ignoring\n", __func__);
		goto _ret_mkroute_ipv4_nat;
	}

	ENET_DEBUG_OFFLOAD("%s: neighbour mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		__func__,
		rt_mac[0], rt_mac[1], rt_mac[2], rt_mac[3], rt_mac[4], rt_mac[5]);

	/* Allow Ingress Port to be APM Ethernet Ports (Internal) */
	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_INT_PORT_ERR(iport) || ETH_ANY_PORT_ERR(eport))
		goto _ret_mkroute_ipv4_nat;

	if (!ipv4nat_offload_init_done[CLE_INT_PORT(iport)])
		if (apm_ipv4nat_offload_init(CLE_INT_PORT(iport)))
			goto _ret_mkroute_ipv4_nat;

	rc = apm_mk_route(rt_dst, rt_src, rt_gateway, eport, iport);

	if (rc == APM_RC_CLE_MISS && (!is_zero_ether_addr(rt_mac)))
		apm_mk_arp(rt_gateway, rt_mac, eport);

_ret_mkroute_ipv4_nat:
	return 0;
}

void apm_rmroute_ipv4_nat(struct rtable *rth)
{
	int iport = apm_inet_offload_ifindex_to_index(rth->rt_iif);
	int eport = apm_inet_offload_ndev_to_index(rth->u.dst.dev);
	__be32 rt_dst = rth->rt_dst;
	__be32 rt_src = rth->rt_src;
	__be32 rt_gateway = rth->rt_gateway;
	u8 *rt_mac = (rth->u.dst.neighbour) ? (rth->u.dst.neighbour->ha) : NULL;

	ENET_DEBUG_OFFLOAD("%s: iport %d (%s) -> eport %d (%s): "
		"rt_dst %d.%d.%d.%d "
		"rt_src %d.%d.%d.%d "
		"rt_gateway %d.%d.%d.%d\n",
		__func__, iport,
		((ETH_INT_PORT(iport) && offload_ndev[iport]) ? offload_ndev[iport]->name : NULL),
		eport, rth->u.dst.dev->name,
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

	if (rth->u.dst.neighbour == NULL) {
		ENET_DEBUG_OFFLOAD("%s: neighbour is NULL, "
			"ignoring\n", __func__);
		goto _ret_rmroute_ipv4_nat;
	} else if (is_broadcast_ether_addr(rt_mac)) {
		ENET_DEBUG_OFFLOAD("%s: neighbour mac ff:ff:ff:ff:ff:ff, "
			"ignoring\n", __func__);
		goto _ret_rmroute_ipv4_nat;
	}

	ENET_DEBUG_OFFLOAD("%s: neighbour mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		__func__,
		rt_mac[0], rt_mac[1], rt_mac[2], rt_mac[3], rt_mac[4], rt_mac[5]);

	iport = apm_inet_offload_ifindex_to_index(rth->rt_iif);
	eport = apm_inet_offload_ndev_to_index(rth->u.dst.dev);

	/* Allow Ingress Port to be APM Ethernet Ports (Internal) */
	/* Allow Egress  Port to be Any Ethernet Ports (Internal or External) */
	if (ETH_INT_PORT_ERR(iport) || ETH_ANY_PORT_ERR(eport))
		goto _ret_rmroute_ipv4_nat;

	apm_rm_route(rt_dst, rt_src, rt_gateway, eport, iport);

_ret_rmroute_ipv4_nat:
	return;
}

void apm_flroute_ipv4_nat(struct net_device *dev)
{
	int eport = apm_inet_offload_ndev_to_index(dev);

	ENET_DEBUG_OFFLOAD("%s: For eport %d (%s)\n", __func__, eport, dev->name);

	if (ETH_ANY_PORT(eport))
		apm_fl_routes();
}

int apm_mknat_ipv4_nat(struct nf_conn *ct)
{
	int rc = APM_RC_OK;
	__be32 src_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	__be32 dst_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	__be32 r_src_ip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	__be32 r_dst_ip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;

	__be16 src_l4 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
	__be16 dst_l4 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
	__be16 r_src_l4 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
	__be16 r_dst_l4 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;

	__be16 src_l3num;
	__be16 r_src_l3num;
	u8 dst_protonum;
	u8 r_dst_protonum;

	enum apm_ipv4nat_offload_type type = ct->status & IPS_SRC_NAT ? APM_IPV4NAT_OFFLOAD_SNAT : APM_IPV4NAT_OFFLOAD_DNAT;

	src_l3num = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num;
	r_src_l3num = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.l3num;
	dst_protonum = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;
	r_dst_protonum = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.protonum;

	apm_ipv4nat_offload_list_entry();
	ENET_DEBUG_OFFLOAD("%s: "
		"src_ip %d.%d.%d.%d "
		"dst_ip %d.%d.%d.%d "
		"r_src_ip %d.%d.%d.%d "
		"r_dst_ip %d.%d.%d.%d "
		"ct %p status 0x%08lx master %p type %d\n", __func__,
		(src_ip & 0xFF000000) >> 24,
		(src_ip & 0x00FF0000) >> 16,
		(src_ip & 0x0000FF00) >>  8,
		(src_ip & 0x000000FF) >>  0,
		(dst_ip & 0xFF000000) >> 24,
		(dst_ip & 0x00FF0000) >> 16,
		(dst_ip & 0x0000FF00) >>  8,
		(dst_ip & 0x000000FF) >>  0,
		(r_src_ip & 0xFF000000) >> 24,
		(r_src_ip & 0x00FF0000) >> 16,
		(r_src_ip & 0x0000FF00) >>  8,
		(r_src_ip & 0x000000FF) >>  0,
		(r_dst_ip & 0xFF000000) >> 24,
		(r_dst_ip & 0x00FF0000) >> 16,
		(r_dst_ip & 0x0000FF00) >>  8,
		(r_dst_ip & 0x000000FF) >>  0,
		ct, ct->status, ct->master, type);

	ENET_DEBUG_OFFLOAD("%s: "
		"src_l3num %d dst_protonum %d "
		"r_src_l3num %d r_dst_protonum %d "
		"\n", __func__,
		src_l3num, dst_protonum,
		r_src_l3num, r_dst_protonum);

	ENET_DEBUG_OFFLOAD("%s: "
		"src_l4 %d dst_l4 %d "
		"r_src_l4 %d r_dst_l4 %d "
		"\n", __func__,
		src_l4, dst_l4,
		r_src_l4, r_dst_l4);

	/* L4 layer key-match is 16-bit for ICMP and PPtP GRE, so append 8-bit protocol field & pad 8-bit 0s to make 32-bit L4 string */
	if (dst_protonum == IPPROTO_ICMP || dst_protonum == IPPROTO_GRE) {
		dst_l4 = htons(dst_protonum << 8);
		r_dst_l4 = htons(dst_protonum << 8);
		type |= APM_IPV4NAT_OFFLOAD_XNAT_IP_MASK;
	}

	rc = apm_mk_nat(src_ip, dst_ip, src_l4, dst_l4, r_src_ip, r_dst_ip, r_src_l4, r_dst_l4, type);

	return rc;
}

void apm_rmnat_ipv4_nat(struct nf_conn *ct)
{
	__be32 src_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
	__be32 dst_ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
	__be32 r_src_ip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
	__be32 r_dst_ip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;

	__be16 src_l4 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
	__be16 dst_l4 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
	__be16 r_src_l4 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
	__be16 r_dst_l4 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;

	__be16 src_l3num;
	__be16 r_src_l3num;
	u8 dst_protonum;
	u8 r_dst_protonum;

	enum apm_ipv4nat_offload_type type = ct->status & IPS_SRC_NAT ? APM_IPV4NAT_OFFLOAD_SNAT : APM_IPV4NAT_OFFLOAD_DNAT;

	src_l3num = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num;
	r_src_l3num = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.l3num;
	dst_protonum = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;
	r_dst_protonum = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.protonum;

	ENET_DEBUG_OFFLOAD("%s: "
		"src_ip %d.%d.%d.%d "
		"dst_ip %d.%d.%d.%d "
		"r_src_ip %d.%d.%d.%d "
		"r_dst_ip %d.%d.%d.%d "
		"ct %p status 0x%08lx master %p type %d\n", __func__,
		(src_ip & 0xFF000000) >> 24,
		(src_ip & 0x00FF0000) >> 16,
		(src_ip & 0x0000FF00) >>  8,
		(src_ip & 0x000000FF) >>  0,
		(dst_ip & 0xFF000000) >> 24,
		(dst_ip & 0x00FF0000) >> 16,
		(dst_ip & 0x0000FF00) >>  8,
		(dst_ip & 0x000000FF) >>  0,
		(r_src_ip & 0xFF000000) >> 24,
		(r_src_ip & 0x00FF0000) >> 16,
		(r_src_ip & 0x0000FF00) >>  8,
		(r_src_ip & 0x000000FF) >>  0,
		(r_dst_ip & 0xFF000000) >> 24,
		(r_dst_ip & 0x00FF0000) >> 16,
		(r_dst_ip & 0x0000FF00) >>  8,
		(r_dst_ip & 0x000000FF) >>  0,
		ct, ct->status, ct->master, type);

	ENET_DEBUG_OFFLOAD("%s: "
		"src_l3num %d dst_protonum %d "
		"r_src_l3num %d r_dst_protonum %d "
		"\n", __func__,
		src_l3num, dst_protonum,
		r_src_l3num, r_dst_protonum);

	ENET_DEBUG_OFFLOAD("%s: "
		"src_l4 %d dst_l4 %d "
		"r_src_l4 %d r_dst_l4 %d "
		"\n", __func__,
		src_l4, dst_l4,
		r_src_l4, r_dst_l4);

	/* L4 layer key-match is 16-bit for ICMP and PPtP GRE, so append 8-bit protocol field & pad 8-bit 0s to make 32-bit L4 string */
	if (dst_protonum == IPPROTO_ICMP || dst_protonum == IPPROTO_GRE) {
		dst_l4 = htons(dst_protonum << 8);
		r_dst_l4 = htons(dst_protonum << 8);
		type |= APM_IPV4NAT_OFFLOAD_XNAT_IP_MASK;
	}

	apm_rm_nat(src_ip, dst_ip, src_l4, dst_l4, r_src_ip, r_dst_ip, r_src_l4, r_dst_l4, type);
}

int apm_ipv4nat_offload_cmd(struct net_device *dev, char *cmdline, int update)
{
	int rc = APM_RC_ERROR;
	char typstr[8];
	char cmdstr[8];
	char natstr[8];
	char dev_name[IFNAMSIZ];
	u8 src_ipv4[4], dst_ipv4[4], r_src_ipv4[4], r_dst_ipv4[4];
	__be32 src_ip, dst_ip, r_src_ip, r_dst_ip;
        __be16 src_l4, dst_l4, r_src_l4, r_dst_l4;
	int iport = apm_inet_offload_ndev_to_index(dev);
	int eport;
	enum apm_ipv4nat_offload_type type;

	apm_ipv4nat_offload_list_entry();
	if (update) {
		if (ETH_INT_PORT(iport))
			rc = apm_ipv4nat_offload_enable(dev);
		goto _ret_ipv4nat_offload_cmd;
	}

	memset(natstr, 0, sizeof(natstr));
	memset(cmdstr, 0, sizeof(cmdstr));
	memset(dev_name, 0, sizeof(dev_name));

	if (strncmp(&cmdline[strlen(CLE_PTREE_IPV4NAT) + 1], "show", 4) == 0) {
		sscanf(cmdline, "%s show %s %s", natstr, cmdstr, dev_name);
		eport = apm_inet_offload_ndev_name_to_index(dev_name);

		if (ETH_ANY_PORT_ERR(eport))
			eport = CLE_MAX_PORTS;

		if (strncmp(cmdstr, "arp", 3) == 0)
			apm_show_arp(eport);
		else if (strncmp(cmdstr, "route", 5) == 0)
			apm_show_route(eport);
		else if (strncmp(cmdstr, "nat", 3) == 0)
			apm_show_nat();

		rc = APM_RC_OK;
		goto _ret_ipv4nat_offload_cmd;
	}

        sscanf(cmdline, "%s %s %s "
                        "%hhu.%hhu.%hhu.%hhu "
                        "%hhu.%hhu.%hhu.%hhu %hu %hu "
                        "%hhu.%hhu.%hhu.%hhu "
                        "%hhu.%hhu.%hhu.%hhu %hu %hu",
                        natstr, cmdstr, typstr,
                        &src_ipv4[0], &src_ipv4[1],
                        &src_ipv4[2], &src_ipv4[3],
                        &dst_ipv4[0], &dst_ipv4[1],
                        &dst_ipv4[2], &dst_ipv4[3], &src_l4, &dst_l4,
                        &r_src_ipv4[0], &r_src_ipv4[1],
                        &r_src_ipv4[2], &r_src_ipv4[3],
                        &r_dst_ipv4[0], &r_dst_ipv4[1],
                        &r_dst_ipv4[2], &r_dst_ipv4[3], &r_src_l4, &r_dst_l4);

	if (strncmp(cmdstr, "add", 3) == 0)
		update = 1;
	else if (strncmp(cmdstr, "del", 3) == 0)
		update = 0;
	else
		goto _ret_ipv4nat_offload_cmd;

	if (strncmp(typstr, "snat", 4) == 0)
		type = APM_IPV4NAT_OFFLOAD_SNAT;
	else if (strncmp(typstr, "dnat", 4) == 0)
		type = APM_IPV4NAT_OFFLOAD_DNAT;
	else if (strncmp(typstr, "snat_ip", 7) == 0)
		type = APM_IPV4NAT_OFFLOAD_SNAT_IP;
	else if (strncmp(typstr, "dnat_ip", 7) == 0)
		type = APM_IPV4NAT_OFFLOAD_DNAT_IP;
	else
		goto _ret_ipv4nat_offload_cmd;

	src_ip = (src_ipv4[0] << 24) |
		(src_ipv4[1] << 16) |
		(src_ipv4[2] <<  8) |
		(src_ipv4[3] <<  0);

	dst_ip = (dst_ipv4[0] << 24) |
		(dst_ipv4[1] << 16) |
		(dst_ipv4[2] <<  8) |
		(dst_ipv4[3] <<  0);

	r_src_ip = (r_src_ipv4[0] << 24) |
		(r_src_ipv4[1] << 16) |
		(r_src_ipv4[2] <<  8) |
		(r_src_ipv4[3] <<  0);

	r_dst_ip = (r_dst_ipv4[0] << 24) |
		(r_dst_ipv4[1] << 16) |
		(r_dst_ipv4[2] <<  8) |
		(r_dst_ipv4[3] <<  0);

	ENET_DEBUG_OFFLOAD("%s: %sing %s for "
			"src_ip %08x dst_ip %08x src_l4 %d dst_l4 %d "
			"r_src_ip %08x r_dst_ip %08x r_src_l4 %d r_dst_l4 %d\n", __func__,
			(update ? "Add" : "Delet"), typstr,
			src_ip, dst_ip, src_l4, dst_l4,
			r_src_ip, r_dst_ip, r_src_l4, r_dst_l4);

	if (update)
		rc = apm_mk_nat(src_ip, dst_ip, src_l4, dst_l4, r_src_ip, r_dst_ip, r_src_l4, r_dst_l4, type);
	else
		rc = apm_rm_nat(src_ip, dst_ip, src_l4, dst_l4, r_src_ip, r_dst_ip, r_src_l4, r_dst_l4, type);

_ret_ipv4nat_offload_cmd:
	return rc;
}

int apm_ipv4nat_offload_enable(struct net_device *dev)
{
	int rc;
	struct apm_enet_dev_base *ipriv_dev;

	ipriv_dev = netdev_priv(dev);
	rc = apm_ipv4nat_offload_init(ipriv_dev->port_id);

	if (rc == APM_RC_OK)
		rc = apm_inet_switch(ipriv_dev, ETHOFFLOAD_IPV4NAT);

	return rc;
}

void apm_ipv4nat_offload_setqid(u8 iport, u8 qid)
{
	offloader_rx_qid[iport] = qid;
}
