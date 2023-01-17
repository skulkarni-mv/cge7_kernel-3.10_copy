/**
 * AppliedMicro APM86xxx SoC LRO Classifier Driver
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
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
 * @file apm_cle_lro.c
 *
 * This file implements Classifier configurations in use by LRO Ethernet driver.
 *
 */

#include <linux/tcp.h>
#include "apm_enet_offload.h"
#include "apm_cle_lro.h"

#define CIFS_PORT 445
#define RFC1001_PORT 139

static struct apm_cle_dbptr dbptr[LRO_MAX_CONN][LRO_DBPTR_PER_CONN] = {{{0}}};
static int ipp_lro_offload_init_done[MAX_PORTS] = {0};
static int ipp_lro_offload_entry_init_done = 0;
static struct list_head ipp_lro_base_dbptr_index[MAX_CLE_ENGINE] = {{0}};
static struct list_head ipp_lro_connection_index = {0};
static struct list_head ipp_lro_search_str_entry = {0};
static struct list_head ipp_lro_ipv4_tuples_list = {0};
static int lro_route_entries = 0;

static int apm_del_lro_entry(struct apm_enet_offload_list *search_str_entry)
{
	__be32 saddr = search_str_entry->key[0];
	__be32 daddr = search_str_entry->key[1];
	__be16 sport = search_str_entry->key[2] >> 16;
	__be16 dport = search_str_entry->key[2] & 0xFFFF;
	struct avl_node tuple;
	int rc = APM_RC_OK;
	u8 id = search_str_entry->index;
	u32 iport = dbptr[id][0].h0_info & MASK_LRO_ENET_PORT;
	u32 base_dbptr_index = dbptr[id][0].index;
	int i;

	memset(&tuple, 0, sizeof(tuple));

	/* SRC IP, DST IP, SRC Port, DST Port */
	tuple.search_key[0] = saddr; /* SRC IP */
	tuple.search_key[1] = daddr; /* DST IP */
	tuple.search_key[2] = (sport << 16) | dport; /* SRC and DST Port */

	for (i = 0; i < LRO_DBPTR_PER_CONN; i++) {
		/* Port number */
		tuple.search_key[3] = (PORTIDX[iport] << 16);
		if (i) {
			/* Store Key byte */
			tuple.search_key[3] |= ((0x4000 + (i * 0x1000)) << 16);
		}

		if (apm_cle_avl_del_node(iport, &tuple)) {
			ENET_ERROR_OFFLOAD("apm_cle_avl_del_node failed !!\n");
		}

		/* H0Info encoding for Connection ID, Port ID */
		dbptr[id][i].h0_info = MASK_LRO_ENET_PORT;
		/* Segment RX QID */
		dbptr[id][i].dstqid = 0;
		/* Ethernet MAC/IP/TCP Header FP queue PBN */
		dbptr[id][i].fpsel = 0;
		/* Ethernet TCP Data FP queue PBN */
		dbptr[id][i].nxtfpsel = 0;
		/* Split Header / Data */
		dbptr[id][i].hdr_data_split = 0;
		/* Split Boundary */
		dbptr[id][i].split_boundary = 0;
		apm_set_cle_dbptr(iport, &dbptr[id][i]);

		/* Clear index value */
		dbptr[id][i].index = 0;
	}

	if (apm_put_index(&ipp_lro_base_dbptr_index[PID2CID[iport]],
			base_dbptr_index)) {
		ENET_ERROR_OFFLOAD("Unable to put CLE index\n");
	}

	if (apm_put_index(&ipp_lro_connection_index, id)) {
		ENET_ERROR_OFFLOAD("Unable to put LRO index\n");
	}

	apm_del_enet_offload_entry(search_str_entry);
	apm_ethoffload_ops.tcp_connection_entries--;

	return rc;
}

static int apm_allow_entry_route_to_ipp(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct apm_enet_offload_list *ipv4_tuples;
	struct list_head *ipv4_tuples_head = &ipp_lro_ipv4_tuples_list;
	int rc = 0;

	if (INVALID_LIST_HEAD(ipv4_tuples_head))
		return rc;

	list_for_each_entry(ipv4_tuples, ipv4_tuples_head, node) {
		__be32 t_saddr = ipv4_tuples->key[0];
		__be32 t_daddr = ipv4_tuples->key[1];
		__be16 t_sport = ipv4_tuples->key[2] >> 16;
		__be16 t_dport = ipv4_tuples->key[2] & 0xFFFF;

		if ((t_saddr == 0 || t_saddr == saddr) &&
				(t_daddr == 0 || t_daddr == daddr) &&
				(t_sport == 0 || t_sport == sport) &&
				(t_dport == 0 || t_dport == dport)) {
			rc = 1;
			break;
		}
	}

	return rc;
}

static int apm_clean_entry_route_to_ipp(__be32 t_saddr, __be32 t_daddr, __be16 t_sport, __be16 t_dport)
{
	struct apm_enet_offload_list *search_str_entry, *next;
	struct list_head *search_str_head = &ipp_lro_search_str_entry;
	int rc = APM_RC_OK;
	unsigned long flags;

	if (INVALID_LIST_HEAD(search_str_head))
		return rc;

	apm_cle_lock(flags);
	if (apm_ethoffload_ops.tcp_connection_entries == 0)
		goto _ret_clean_entry_route_to_ipp;

	list_for_each_entry_safe(search_str_entry, next, search_str_head, node) {
		__be32 saddr = search_str_entry->key[0];
		__be32 daddr = search_str_entry->key[1];
		__be16 sport = search_str_entry->key[2] >> 16;
		__be16 dport = search_str_entry->key[2] & 0xFFFF;

		if (!((t_saddr == 0 || t_saddr == saddr) &&
				(t_daddr == 0 || t_daddr == daddr) &&
				(t_sport == 0 || t_sport == sport) &&
				(t_dport == 0 || t_dport == dport)))
			continue;

		rc |= apm_del_lro_entry(search_str_entry);
	}

_ret_clean_entry_route_to_ipp:
	apm_cle_unlock(flags);

	return rc;
}

static int apm_mk_lro_route(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct apm_enet_offload_list *ipv4_tuples = NULL;
	__be32 search_key[OFFLOAD_KEY_SIZE];
	int rc = APM_RC_OK;

	ENET_DEBUG_OFFLOAD("%s: %d: "
		"SAddr %d.%d.%d.%d DAddr %d.%d.%d.%d "
		"SPort %d DPort %d\n", __func__, __LINE__,
		(saddr & 0xFF000000) >> 24,
		(saddr & 0x00FF0000) >> 16,
		(saddr & 0x0000FF00) >>  8,
		(saddr & 0x000000FF) >>  0,
		(daddr & 0xFF000000) >> 24,
		(daddr & 0x00FF0000) >> 16,
		(daddr & 0x0000FF00) >>  8,
		(daddr & 0x000000FF) >>  0,
		sport, dport);

	if (lro_route_entries == LRO_MAX_CONN)
		goto _ret_mk_lro_route;

	/* SRC IP, DST IP, SRC Port, DST Port */
	search_key[0] = saddr; /* SRC IP */
	search_key[1] = daddr; /* DST IP */
	search_key[2] = (sport << 16) | dport; /* SRC and DST Port */

	if (apm_find_enet_offload_entry(&ipp_lro_ipv4_tuples_list,
				search_key)) {
		ENET_ERROR_OFFLOAD("LRO route already added\n");
		rc = APM_RC_ERROR;
		goto _ret_mk_lro_route;
	}

	ipv4_tuples = apm_add_enet_offload_entry(&ipp_lro_ipv4_tuples_list,
				search_key, 0);

	if (!ipv4_tuples) {
		ENET_ERROR_OFFLOAD("Unable to add LRO route\n");
		rc = APM_RC_ERROR;
		goto _ret_mk_lro_route;
	}

	lro_route_entries++;

_ret_mk_lro_route:

	return rc;
}

static int apm_rm_lro_route(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct apm_enet_offload_list *ipv4_tuples = NULL;
	__be32 search_key[OFFLOAD_KEY_SIZE];
	int rc = APM_RC_OK;

	ENET_DEBUG_OFFLOAD("%s: %d: "
		"SAddr %d.%d.%d.%d DAddr %d.%d.%d.%d "
		"SPort %d DPort %d\n", __func__, __LINE__,
		(saddr & 0xFF000000) >> 24,
		(saddr & 0x00FF0000) >> 16,
		(saddr & 0x0000FF00) >>  8,
		(saddr & 0x000000FF) >>  0,
		(daddr & 0xFF000000) >> 24,
		(daddr & 0x00FF0000) >> 16,
		(daddr & 0x0000FF00) >>  8,
		(daddr & 0x000000FF) >>  0,
		sport, dport);

	if (lro_route_entries == 0)
		goto _ret_rm_lro_route;

	/* SRC IP, DST IP, SRC Port, DST Port */
	search_key[0] = saddr; /* SRC IP */
	search_key[1] = daddr; /* DST IP */
	search_key[2] = (sport << 16) | dport; /* SRC and DST Port */

	ipv4_tuples = apm_find_enet_offload_entry(&ipp_lro_ipv4_tuples_list,
				search_key);

	if (!ipv4_tuples) {
		ENET_ERROR_OFFLOAD("Unable to find LRO route\n");
		rc = APM_RC_ERROR;
		goto _ret_rm_lro_route;
	}

	apm_clean_entry_route_to_ipp(saddr, daddr, sport, dport);
	apm_del_enet_offload_entry(ipv4_tuples);
	lro_route_entries--;

_ret_rm_lro_route:

	return rc;
}

static void apm_show_ipp_lro_route(void)
{
	struct apm_enet_offload_list *ipv4_tuples;
	struct list_head *ipv4_tuples_head = &ipp_lro_ipv4_tuples_list;

	printk("Source-IP       Destination-IP  S-Port D-Port\n");

	if (INVALID_LIST_HEAD(ipv4_tuples_head))
		return;

	list_for_each_entry(ipv4_tuples, ipv4_tuples_head, node) {
		char src[16];
		char dst[16];
		__be32 saddr = ipv4_tuples->key[0];
		__be32 daddr = ipv4_tuples->key[1];
		__be16 sport = ipv4_tuples->key[2] >> 16;
		__be16 dport = ipv4_tuples->key[2] & 0xFFFF;
		sprintf(src, "%pI4", &saddr);
		sprintf(dst, "%pI4", &daddr);
		printk("%-15s %-15s %6d %6d\n",
			src, dst, sport, dport);
	}
}

static int apm_mk_lro_entry(u32 iport, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct apm_enet_offload_list *search_str_entry = NULL;
	struct avl_node tuple;
	struct net_device *dev;
	struct apm_enet_dev_base *ipriv_dev;
	int rc = APM_RC_OK;
	u8 id;
	unsigned long flags;
	int i;

	ENET_DEBUG_OFFLOAD("%s: %d: "
		"LRO port %d SAddr %d.%d.%d.%d DAddr %d.%d.%d.%d "
		"SPort %d DPort %d\n", __func__, __LINE__, iport,
		(saddr & 0xFF000000) >> 24,
		(saddr & 0x00FF0000) >> 16,
		(saddr & 0x0000FF00) >>  8,
		(saddr & 0x000000FF) >>  0,
		(daddr & 0xFF000000) >> 24,
		(daddr & 0x00FF0000) >> 16,
		(daddr & 0x0000FF00) >>  8,
		(daddr & 0x000000FF) >>  0,
		sport, dport);

	if (!apm_allow_entry_route_to_ipp(saddr, daddr, sport, dport))
		return APM_RC_ERROR;

	memset(&tuple, 0, sizeof(tuple));

	/* SRC IP, DST IP, SRC Port, DST Port */
	tuple.search_key[0] = saddr; /* SRC IP */
	tuple.search_key[1] = daddr; /* DST IP */
	tuple.search_key[2] = (sport << 16) | dport; /* SRC and DST Port */

	apm_cle_lock(flags);
	if (apm_ethoffload_ops.tcp_connection_entries == LRO_MAX_CONN)
		goto _ret_mk_lro_entry;

	if (apm_find_enet_offload_entry(&ipp_lro_search_str_entry,
				tuple.search_key)) {
		ENET_ERROR_OFFLOAD("LRO entry already added\n");
		rc = APM_RC_ERROR;
		goto _ret_mk_lro_entry;
	}

	search_str_entry = apm_add_enet_offload_entry(&ipp_lro_search_str_entry,
				tuple.search_key, 0);

	if (!search_str_entry) {
		ENET_ERROR_OFFLOAD("Unable to add LRO entry\n");
		rc = APM_RC_ERROR;
		goto _ret_mk_lro_entry;
	}

	if (apm_get_index(&ipp_lro_connection_index,
			&search_str_entry->index)) {
		ENET_ERROR_OFFLOAD("Unable to get LRO index\n");
		rc = APM_RC_ERROR;
		goto _ret_mk_lro_entry;
	}

	id = search_str_entry->index;

	if (apm_get_index(&ipp_lro_base_dbptr_index[PID2CID[iport]],
			&dbptr[id][0].index)) {

		for (i = 0; i < LRO_DBPTR_PER_CONN; i++)
			dbptr[id][i].index = DBPTR_ALLOC(CLE_DB_INDEX) + i;

		if ((rc = apm_dbptr_alloc(0, LRO_DBPTR_PER_CONN, &dbptr[id][0])) !=
				APM_RC_OK) {

			if (apm_put_index(&ipp_lro_connection_index, id)) {
				ENET_ERROR_OFFLOAD("Unable to put LRO index\n");
			}

			apm_del_enet_offload_entry(search_str_entry);

			ENET_ERROR_OFFLOAD("apm_dbptr_alloc error %d\n", rc);
			rc = APM_RC_ERROR;
			goto _ret_mk_lro_entry;
		}
	} else {
		for (i = 1; i < LRO_DBPTR_PER_CONN; i++)
			dbptr[id][i].index = dbptr[id][i - 1].index + 1;
	}

	dev = find_netdev(iport);
	ipriv_dev = netdev_priv(dev);

	for (i = 0; i < LRO_DBPTR_PER_CONN; i++) {
		/*
		 * H0Info encoding for Connection ID, Port ID
		 * --------------------------------------------------
		 * | Un-used (16) | Connection ID (8) | Port Id (8) |
		 * --------------------------------------------------
		 */
		dbptr[id][i].h0_info = (id << 8) | iport;

		/* Segment RX QID */
		dbptr[id][i].dstqid = ipriv_dev->lro.qm_sys.seg_rx_qid;

		if (i) /* split logic */ {
			/* Ethernet MAC/IP/TCP Header FP queue PBN */
			dbptr[id][i].fpsel = ipriv_dev->lro.qm_src.seg_fp_pbn - 0x20;
			/* Ethernet TCP Data FP queue PBN */
			dbptr[id][i].nxtfpsel = ipriv_dev->lro.qm_src.seg_fp_pbn - 0x20;
			/* Split Header / Data */
			dbptr[id][i].hdr_data_split = 1;
			/* 12 possible Split Boundary values 0, 54, 58, 62, 66, ... , 96 */
			/* Depending on TCP Data present or not and TCP Header size */
			dbptr[id][i].split_boundary = 50 + (4 * i);
		} else {
			/* Use Ethernet TCP Data Segment FP queue PBN to receive packet less than MTU */
			dbptr[id][i].fpsel = ipriv_dev->lro.qm_src.seg_fp_pbn - 0x20;
		}

		apm_set_cle_dbptr(iport, &dbptr[id][i]);
		tuple.priority = 0;
		tuple.result_pointer = dbptr[id][i].index;

		/* Port number */
		tuple.search_key[3] = (PORTIDX[iport] << 16);
		if (i) {
			/* Store Key byte */
			tuple.search_key[3] |= ((0x4000 + (i * 0x1000)) << 16);
		}

		if (apm_cle_avl_add_node(iport, &tuple)) {
			int j = i;

			/* Clean up the allocated stuff */
			for (; i >= 0; i--) {
				/* Port number */
				tuple.search_key[3] = (PORTIDX[iport] << 16);
				if (i) {
					/* Store Key byte */
					tuple.search_key[3] |= ((0x4000 + (i * 0x1000)) << 16);
				}

				if ((j != i) && apm_cle_avl_del_node(iport, &tuple)) {
					ENET_ERROR_OFFLOAD("apm_cle_avl_del_node failed !!\n");
				}

				/* H0Info encoding for Connection ID, Port ID */
				dbptr[id][i].h0_info = MASK_LRO_ENET_PORT;
				/* Segment RX QID */
				dbptr[id][i].dstqid = 0;
				/* Ethernet MAC/IP/TCP Header FP queue PBN */
				dbptr[id][i].fpsel = 0;
				/* Ethernet TCP Data FP queue PBN */
				dbptr[id][i].nxtfpsel = 0;
				/* Split Header / Data */
				dbptr[id][i].hdr_data_split = 0;
				/* Split Boundary */
				dbptr[id][i].split_boundary = 0;
				apm_set_cle_dbptr(iport, &dbptr[id][i]);
			}

			if (apm_put_index(&ipp_lro_connection_index, id)) {
				ENET_ERROR_OFFLOAD("Unable to put LRO index\n");
			}

			apm_del_enet_offload_entry(search_str_entry);

			ENET_ERROR_OFFLOAD("apm_cle_avl_add_node failed !!\n");
			rc = APM_RC_ERROR;
			goto _ret_mk_lro_entry;
		}
	}

	apm_ethoffload_ops.tcp_connection_entries++;

_ret_mk_lro_entry:
	apm_cle_unlock(flags);
	return rc;
}

static int apm_rm_lro_entry(u32 iport, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct apm_enet_offload_list *search_str_entry = NULL;
	u32 search_key[OFFLOAD_KEY_SIZE];
	int rc = APM_RC_OK;
	unsigned long flags;

	ENET_DEBUG_OFFLOAD("%s: %d: "
		"LRO port %d SAddr %d.%d.%d.%d DAddr %d.%d.%d.%d "
		"SPort %d DPort %d\n", __func__, __LINE__, iport,
		(saddr & 0xFF000000) >> 24,
		(saddr & 0x00FF0000) >> 16,
		(saddr & 0x0000FF00) >>  8,
		(saddr & 0x000000FF) >>  0,
		(daddr & 0xFF000000) >> 24,
		(daddr & 0x00FF0000) >> 16,
		(daddr & 0x0000FF00) >>  8,
		(daddr & 0x000000FF) >>  0,
		sport, dport);

	if (!apm_allow_entry_route_to_ipp(saddr, daddr, sport, dport))
		return APM_RC_ERROR;

	apm_cle_lock(flags);
	if (apm_ethoffload_ops.tcp_connection_entries == 0)
		goto _ret_rm_lro_entry;

	/* SRC IP, DST IP, SRC Port, DST Port */
	search_key[0] = saddr; /* SRC IP */
	search_key[1] = daddr; /* DST IP */
	search_key[2] = (sport << 16) | dport; /* SRC and DST Port */

	search_str_entry = apm_find_enet_offload_entry(&ipp_lro_search_str_entry,
				search_key);

	if (!search_str_entry) {
		ENET_ERROR_OFFLOAD("Unable to find LRO entry\n");
		rc = APM_RC_ERROR;
		goto _ret_rm_lro_entry;
	}

	rc = apm_del_lro_entry(search_str_entry);

_ret_rm_lro_entry:
	apm_cle_unlock(flags);
	return rc;
}

static void apm_show_ipp_lro_entry(void)
{
	struct apm_enet_offload_list *entry;
	struct list_head *search_str_head = &ipp_lro_search_str_entry;

	printk("Source-IP       Destination-IP  S-Port D-Port Id InIf\n");

	if (INVALID_LIST_HEAD(search_str_head))
		return;

	list_for_each_entry(entry, search_str_head, node) {
		char src[16];
		char dst[16];
		__be32 saddr = entry->key[0];
		__be32 daddr = entry->key[1];
		__be16 sport = entry->key[2] >> 16;
		__be16 dport = entry->key[2] & 0xFFFF;
		u32 id = entry->index;
		u32 iport = dbptr[id][0].h0_info & MASK_LRO_ENET_PORT;
		char *iport_devname = (iport < MAX_PORTS) ?
				find_netdev(iport)->name :
				NULL;
		sprintf(src, "%pI4", &saddr);
		sprintf(dst, "%pI4", &daddr);
		printk("%-15s %-15s %6d %6d %2d %s\n",
			src, dst, sport, dport,
			id, iport_devname);
	}
}

static void apm_ipp_lro_offload_list_entry(void)
{
	int i, rc;

	if (ipp_lro_offload_entry_init_done)
		return;

	for (i = 0; i < MAX_CLE_ENGINE; i++)
		INIT_LIST_HEAD(&ipp_lro_base_dbptr_index[i]);
	INIT_LIST_HEAD(&ipp_lro_connection_index);
	INIT_LIST_HEAD(&ipp_lro_search_str_entry);
	INIT_LIST_HEAD(&ipp_lro_ipv4_tuples_list);
	memset(&dbptr, 0, sizeof(dbptr));

	for (i = 0; i < LRO_MAX_CONN; i++) {
		int j;

		if ((rc = apm_put_index(&ipp_lro_connection_index,
				(LRO_MAX_CONN - 1 - i))) != APM_RC_OK) {
			ENET_ERROR_OFFLOAD("Unable to put LRO index %d error %d\n",
				(LRO_MAX_CONN - 1 - i), rc);
			return;
		}

		for (j = 0; j < LRO_DBPTR_PER_CONN; j++) {
			/* H0Info encoding for Connection ID, Port ID */
			dbptr[i][j].h0_info = MASK_LRO_ENET_PORT;
		}
	}

	if ((rc = apm_mk_lro_route(0, 0, 0, RFC1001_PORT)) !=
				APM_RC_OK) {
		ENET_ERROR_OFFLOAD("apm_mk_lro_route error %d\n", rc);
	} else if ((rc = apm_mk_lro_route(0, 0, 0, CIFS_PORT)) !=
				APM_RC_OK) {
		ENET_ERROR_OFFLOAD("apm_mk_lro_route error %d\n", rc);
	} else {
		ipp_lro_offload_entry_init_done = 1;
	}
}

static int apm_ipp_lro_offload_init(u32 iport)
{
	struct net_device *dev;
	struct apm_enet_dev_base *ipriv_dev;
	int rc = APM_RC_OK;
	struct ptree_kn kn;
	struct apm_ptree_config *ptree_config;
	u32 start_dbptr;

	struct ptree_branch branch[] = {
	/* 0. SN - Check for Ethernet Protocol, IPv4 Version-Header Length and TCP */
	{      0, 0x86DD,  EQT, PTREE_ALLOC(4), EW_BRANCH(0), 0, 1, 0, 0 },              /* IPv6 */
	{      0, 0x8100,  EQT, PTREE_ALLOC(4), EW_BRANCH(0), 0, 1, 0, 0 },              /* VLAN */
	{      0, 0x0806,  EQT, PTREE_ALLOC(4), EW_BRANCH(0), 0, 1, 0, 0 },              /* ARP  */
	{      0, 0x0800,  EQT, PTREE_ALLOC(0), EW_BRANCH(4), 2, 0, JMP_REL, JMP_FW },   /* IPv4 */
	{ 0x00FF, 0x4500, NEQT, PTREE_ALLOC(4), EW_BRANCH(0), 0, 1, 0, 0 },              /* IPv4 Version-Header Length not 0x45 */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(0), EW_BRANCH(6), 8, 0, JMP_REL, JMP_FW },   /* IPv4 Version-Header Length is 0x45 */
	{ 0xFF00, 0x0006, NEQT, PTREE_ALLOC(4), EW_BRANCH(0), 0, 1, 0, 0 },              /* IP Proto not TCP */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(1), EW_BRANCH(0), 6, 0, JMP_REL, JMP_BW },   /* IP Proto is TCP */

	/* 1. Check IP Len, if 1500 then jmp to 2. and store key byte for splitting packet else jmp to 3 (continue) */
	{      0, 0x05DC, NEQT, PTREE_ALLOC(3), EW_BRANCH(0), 10, 1, JMP_REL, JMP_FW },  /* IP Len not 1500 */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(2), EW_BRANCH(0), 30, 0, JMP_REL, JMP_FW },  /* IP Len is 1500 */

	/* 2. IP Len is 1500 (0x05DC) so store TCP hdr len as key byte */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(3), EW_BRANCH(0), 20, 0, JMP_REL, JMP_BW },  /* IP Len is 1500 */

	/* 3. SRC IP (1-2 bytes) SRC IP (3-4 bytes) DST IP (1-2 bytes) DST IP (3-4 bytes) for 1st connection */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(3), EW_BRANCH(1), 2, 1, JMP_REL, JMP_FW },   /* Src IP (1-2 bytes) */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(3), EW_BRANCH(2), 2, 1, JMP_REL, JMP_FW },   /* Src IP (3-4 bytes) */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(3), EW_BRANCH(3), 2, 1, JMP_REL, JMP_FW },   /* Dst IP (1-2 bytes) */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(3), EW_BRANCH(4), 2, 1, JMP_REL, JMP_FW },   /* Dst IP (3-4 bytes) */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(3), EW_BRANCH(5), 2, 1, JMP_REL, JMP_FW },   /* Src Port */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(4), EW_BRANCH(0), 0, 0, JMP_REL, JMP_FW },   /* Dst Port */

	/* 4. Last Node to allow IPv6, VLAN, ARP, IPv4-HL not 0x45 and IP Proto not TCP */
	{ 0xFFFF, 0x0000,  EQT, PTREE_ALLOC(5), KEY_INDEX(0), 0, 0, 0, 0 },
	};

	struct ptree_dn dn[] = {
	{ START_NODE,   DBPTR_DROP(0), AVL_SEARCH(NO_BYTE), STORE_KEY(NO_BYTE), 0, 0, 8, &branch[0] },    /* Ethertype, IPv4-HL 0x45, IP Proto TCP */
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(NO_BYTE), STORE_KEY(NO_BYTE), 0, 0, 2, &branch[8] },    /* IP Len not 1500, jmp to node 3 */
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(NO_BYTE), STORE_KEY(FIRST_BYTE), 0, 0, 1, &branch[10] },/* IP Len is 1500, store TCP hdr len as key byte */
	{ INTERIM_NODE, DBPTR_DROP(0), AVL_SEARCH(BOTH_BYTES), STORE_KEY(NO_BYTE), 0, 0, 6, &branch[11] },/* SRC DST IP Port */
	{ LAST_NODE,    DBPTR_DROP(0), AVL_SEARCH(BOTH_BYTES), STORE_KEY(NO_BYTE), 0, 0, 1, &branch[17] },/* Last Node */
	};

	struct ptree_node node[] = {
	{ PTREE_ALLOC(0),  EWDN, 0,  (struct ptree_dn*)&dn[0] },  /* Ethertype, IPv4-HL 0x45, IP Proto TCP */
	{ PTREE_ALLOC(1),  EWDN, 0,  (struct ptree_dn*)&dn[1] },  /* IP Len not 1500, jmp to node 3 */
	{ PTREE_ALLOC(2),  EWDN, 0,  (struct ptree_dn*)&dn[2] },  /* IP Len is 1500, store TCP hdr len as key byte */
	{ PTREE_ALLOC(3),  EWDN, 0,  (struct ptree_dn*)&dn[3] },  /* SRC DST IP Port */
	{ PTREE_ALLOC(4),  EWDN, 0,  (struct ptree_dn*)&dn[4] },  /* Last Node */
	{ PTREE_ALLOC(5),    KN, 0,     (struct ptree_kn*)&kn },  /* Key Node */
	};

	if (ipp_lro_offload_init_done[iport])
		goto _ret_ipp_lro_offload_init;

	dev = find_netdev(iport);
	ptree_config = apm_find_ptree_config(iport, CLE_PTREE_DEFAULT);

	if (ptree_config == NULL) {
		printk("%s interface is down\n", dev->name);
		rc = APM_RC_ERROR;
		goto _ret_ipp_lro_offload_init;
	}

	start_dbptr = ptree_config->start_dbptr;
	ipriv_dev = netdev_priv(dev);

	kn.priority = 1;
	kn.result_pointer = start_dbptr;

	ptree_config = apm_add_ptree_config(iport, CLE_PTREE_IPP_LRO);

	if ((rc = apm_ptree_alloc(iport, ARRAY_SIZE(node), 0,
					&node[0], NULL,
					ptree_config)) != APM_RC_OK) {
		ENET_ERROR_OFFLOAD("%s: apm_ptree_alloc error %d "
				"for port %d\n", __func__, rc, iport);
		goto _ret_ipp_lro_offload_init;
	}

	ptree_config->start_pkt_ptr = 12;
	ptree_config->default_result = DFCLSRESDBPRIORITY0_WR(7) |
		DFCLSRESDBPTR0_WR(start_dbptr);

	ENET_DEBUG_OFFLOAD("CLE_DBPTR: Segment WQID %d "
			"TCPIPMAC Header FPPBN %d "
			"TCP DATA FPPBN %d\n",
			ipriv_dev->lro.qm_sys.seg_rx_qid,
			ipriv_dev->lro.qm_src.seg_fp_pbn,
			ipriv_dev->lro.qm_src.seg_fp_pbn);

	ipp_lro_offload_init_done[iport] = 1;
	apm_ipp_lro_offload_list_entry();

_ret_ipp_lro_offload_init:
	return rc;
}

int apm_mktcp_connection(struct sock *sk)
{
	struct net_device *dev = sk->sk_dst_cache->dev;
	struct inet_sock *inet = inet_sk(sk);
	int iport = apm_inet_offload_ndev_to_index(dev);
	struct apm_enet_dev_base *ipriv_dev = NULL;

	if (ETH_INT_PORT(iport))
		ipriv_dev = netdev_priv(dev);

	if (ipriv_dev == NULL ||
			ipriv_dev->ethoffload != ETHOFFLOAD_IPP_LRO ||
			!ipp_lro_offload_entry_init_done)
		return 0;

	/* Local IP Address/Port is Destination IP Address/Port in Ethernet Packet */
	/* vv. Remote IP Address/Port is Source IP Address/Port in Ethernet Packet */
	return apm_mk_lro_entry(CLE_INT_PORT(iport), inet->inet_daddr,
				inet->inet_saddr, inet->inet_dport, inet->inet_sport);
}

int apm_rmtcp_connection(struct sock *sk)
{
	struct net_device *dev = sk->sk_dst_cache->dev;
	struct inet_sock *inet = inet_sk(sk);
	int iport = apm_inet_offload_ndev_to_index(dev);
	struct apm_enet_dev_base *ipriv_dev = NULL;

	if (ETH_INT_PORT(iport))
		ipriv_dev = netdev_priv(dev);

	if (ipriv_dev == NULL ||
			ipriv_dev->ethoffload != ETHOFFLOAD_IPP_LRO ||
			!ipp_lro_offload_entry_init_done)
		return 0;

	/* Local IP Address/Port is Destination IP Address/Port in Ethernet Packet */
	/* vv. Remote IP Address/Port is Source IP Address/Port in Ethernet Packet */
	return apm_rm_lro_entry(CLE_INT_PORT(iport), inet->inet_daddr,
				inet->inet_saddr, inet->inet_dport, inet->inet_sport);
}

int apm_ipp_lro_offload_cmd(struct net_device *dev, char *cmdline, int update)
{
	int rc = APM_RC_ERROR;
	char cmdstr[8];
	char subcmdstr[8];
	char ipplrostr[8];
	u8 src_ipv4[4], dst_ipv4[4];
	__be32 saddr, daddr;
	__be16 sport, dport;
	struct apm_enet_dev_base *ipriv_dev = netdev_priv(dev);
	u32 iport = ipriv_dev->port_id;

	if (update) {
		if (ipriv_dev->lro.lro_available)
			rc = apm_ipp_lro_offload_enable(dev);
		else
			printk("LRO feature is disabled in SlimPRO firmware\n");
		goto _ret_ipp_lro_offload_cmd;
	}

	memset(ipplrostr, 0, sizeof(ipplrostr));
	memset(cmdstr, 0, sizeof(cmdstr));

	if (strncmp(&cmdline[strlen(CLE_PTREE_IPP_LRO) + 1], "show", 4) == 0) {
		sscanf(cmdline, "%s show %s", ipplrostr, subcmdstr);
		if (strncmp(subcmdstr, "route", 5) == 0) {
			apm_show_ipp_lro_route();
			rc = APM_RC_OK;
		} else if (strncmp(subcmdstr, "entry", 5) == 0) {
			apm_show_ipp_lro_entry();
			rc = APM_RC_OK;
		}
		goto _ret_ipp_lro_offload_cmd;
	}

	sscanf(cmdline, "%s %s %s"
			"%hhu.%hhu.%hhu.%hhu "
			"%hhu.%hhu.%hhu.%hhu "
			"%hu %hu",
			ipplrostr, cmdstr, subcmdstr,
			&src_ipv4[0], &src_ipv4[1],
			&src_ipv4[2], &src_ipv4[3],
			&dst_ipv4[0], &dst_ipv4[1],
			&dst_ipv4[2], &dst_ipv4[3],
			&sport, &dport);

	if (strncmp(cmdstr, "add", 3) == 0)
		update = 1;
	else if (strncmp(cmdstr, "del", 3) == 0)
		update = 0;
	else
		goto _ret_ipp_lro_offload_cmd;

	if (strncmp(subcmdstr, "route", 5) == 0)
		update |= 0x10;
	else if (strncmp(subcmdstr, "entry", 5) == 0)
		update |= 0x00;
	else
		goto _ret_ipp_lro_offload_cmd;

	saddr = (src_ipv4[0] << 24) |
		(src_ipv4[1] << 16) |
		(src_ipv4[2] <<  8) |
		(src_ipv4[3] <<  0);

	daddr = (dst_ipv4[0] << 24) |
		(dst_ipv4[1] << 16) |
		(dst_ipv4[2] <<  8) |
		(dst_ipv4[3] <<  0);

	if (ipriv_dev->ethoffload != ETHOFFLOAD_IPP_LRO) {
		printk("Enable ipp_lro for this interface\n");
		rc = APM_RC_OK;
		goto _ret_ipp_lro_offload_cmd;
	}

	ENET_DEBUG_OFFLOAD("%s: %sing iPP LRO %s "
			"src ip %08x dst ip %08x src port %04x "
			"dst port %04x\n", __func__,
			update & 0x01 ? "Add" : "Delet",
			update & 0x10 ? "route" : "entry",
			saddr, daddr, sport, dport);

	apm_ipp_lro_offload_list_entry();

	switch (update) {
	case 0x11:
		rc = apm_mk_lro_route(saddr, daddr, sport, dport);
		break;
	case 0x10:
		rc = apm_rm_lro_route(saddr, daddr, sport, dport);
		break;
	case 0x01:
		rc = apm_mk_lro_entry(iport, saddr, daddr, sport, dport);
		break;
	case 0x00:
		rc = apm_rm_lro_entry(iport, saddr, daddr, sport, dport);
	}

_ret_ipp_lro_offload_cmd:
	return rc;
}

int apm_ipp_lro_offload_enable(struct net_device *dev)
{
	struct apm_enet_dev_base *ipriv_dev;
	u32 iport;
	int rc;

	ipriv_dev = netdev_priv(dev);
	ipriv_dev->in_poll_rx_msg_desc.is_msg16 = 0;
	iport = ipriv_dev->port_id;
	rc = apm_ipp_lro_offload_init(iport);

	if (rc == APM_RC_OK)
		rc = apm_inet_switch(ipriv_dev, ETHOFFLOAD_IPP_LRO);

	return rc;
}
