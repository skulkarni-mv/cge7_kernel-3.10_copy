/**
 * AppliedMicro APM86xxx SoC QOS Classifier Driver
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
 * All rights reserved. Khuong Dinh <kdinh@apm.com>
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
 * @file apm_cle_qos.c
 *
 * This file implements Classifier configurations in use by QOS Ethernet driver.
 *
 */
#include <linux/tcp.h>
#include "apm_enet_offload.h"
#include "apm_cle_qos.h"

static int qos_init_done[MAX_PORTS] = {0};

static int apm_qos_init(u32 iport)
{
	struct net_device *dev;
	struct apm_enet_dev_base *priv;
	struct apm_enet_qos_ctx *qos_ctx;
	int rc = APM_RC_OK;
	int i;
	struct apm_ptree_config *ptree_config;
	struct ptree_kn kn;
	struct ptree_kn *kn_d;
	struct apm_cle_dbptr *dbptr_d;
	unsigned int default_dbptr;

	/* Declare the simple ptree for APM QoS. Note that ptree would be
	 * overridden later on S/W */
	struct ptree_branch branch_d_i[] = {
		{      0, 0x0806, EQT, PTREE_ALLOC(2), 0, 0,  1, 0, 0 },	/* ARP	*/
		{      0, 0x8100, EQT, PTREE_ALLOC(2), 0, 0,  1, 0, 0 },	/* VLAN */
		{      0, 0x0800, EQT, PTREE_ALLOC(1), 0, 22, 1, 0, 0 },	/* IPv4 */
		{      0, 0x86dd, EQT, PTREE_ALLOC(2), 0, 0,  0, 0, 0 },	/* IPv6 */
		{ 0xfff0, 0x0007, AND, PTREE_ALLOC(2), 0, 0,  1, 0, 0 },	/* Allow upto TCP */
		{      0, 0x0017, EQT, PTREE_ALLOC(2), 0, 0,  0, 0, 0 },	/* Allow UDP */
		{ 0xffff,      0, EQT, PTREE_ALLOC(3), 0, 0,  0, 0, 0 },
	};

	struct ptree_dn dn_d_i[] = {
		{ START_NODE,	DBPTR_DROP(0), 0, 0, 0, 0, 4, &branch_d_i[0] },
		{ INTERIM_NODE, DBPTR_DROP(0), 0, 0, 0, 0, 2, &branch_d_i[4] },
		{ LAST_NODE,	DBPTR_DROP(0), 0, 0, 0, 0, 1, &branch_d_i[6] },
	};

	struct ptree_node node_d_i[] = {
		{ PTREE_ALLOC(0), EWDN, 0, (struct ptree_dn*)&dn_d_i[0] },
		{ PTREE_ALLOC(1), EWDN, 0, (struct ptree_dn*)&dn_d_i[1] },
		{ PTREE_ALLOC(2), EWDN, 0, (struct ptree_dn*)&dn_d_i[2] },
		{ PTREE_ALLOC(3),   KN, 0, (struct ptree_kn*)&kn },
	};

	if (qos_init_done[iport]) {
		printk(KERN_INFO "QoS is already initialized for port: %d\n", iport);
		goto _ret_qos_init;
	} else {
		printk(KERN_INFO "QoS is going to be initialized for port: %d\n", iport);
	}

	dev = find_netdev(iport);

	/* Prepare ptree_config CLE_PTREE_QOS */
	ptree_config = apm_find_ptree_config(iport, CLE_PTREE_DEFAULT);

	if (ptree_config == NULL) {
		printk("%s interface is down\n", dev->name);
		rc = APM_RC_ERROR;
		goto _ret_qos_init;
	}
	default_dbptr = ptree_config->start_dbptr;
	dev = find_netdev(iport);
	priv = netdev_priv(dev);
	qos_ctx = &priv->qos;
	kn_d = qos_ctx->qos_cfg.kn_d;
	dbptr_d = qos_ctx->qos_cfg.dbptr_d;
	/* Allocate DBPTR before use */
	if (apm_dbptr_alloc(iport, MAX_QOS_CLASS, &dbptr_d[0])) {
		ENET_ERROR_OFFLOAD("apm_dbptr_alloc failed !!\n");
		return APM_RC_ERROR;
	}

	kn.priority = 0;
	kn.result_pointer = dbptr_d[0].index;
	for (i = 0; i < ARRAY_SIZE(dn_d_i); i++)
		dn_d_i[i].result_pointer = dbptr_d[0].index;

	ptree_config = apm_add_ptree_config(iport, CLE_PTREE_QOS);

	if ((rc = apm_ptree_alloc(iport, ARRAY_SIZE(node_d_i), 0,
						&node_d_i[0], NULL,
						ptree_config)) != APM_RC_OK) {
		ENET_ERROR_OFFLOAD("apm_ptree_alloc error %d "
				"for port %d\n", rc, iport);
		rc = APM_RC_ERROR;
		goto _ret_qos_init;
	}

	/* Correct ptree_config ... */
	ptree_config->start_pkt_ptr = 12;

	ptree_config->default_result = DFCLSRESDBPRIORITY0_WR(1) |
		DFCLSRESDBPTR0_WR(default_dbptr);

	qos_init_done[iport] = 1;

_ret_qos_init:
	return rc;
}

int apm_qos_enable(struct net_device *dev)
{
	struct apm_enet_dev_base *ipriv_dev;
	u32 iport;
	int rc;
	ipriv_dev = netdev_priv(dev);
	/* ipriv_dev->in_poll_rx_msg_desc.is_msg16 = 0; */
	iport = ipriv_dev->port_id;
	rc = apm_qos_init(iport);

	return rc;
}
