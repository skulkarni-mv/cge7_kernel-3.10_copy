/**
 * AppliedMicro APM86xxx SoC Ethernet QOS Driver
 *
 * Copyright (c) 2012 Applied Micro Circuits Corporation.
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
 * @file apm_enet_qos.c
 *
 * APM86xxx Ethernet QOS implementation for APM86xxx SoC.
 */
#include <asm/cacheflush.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <asm/ipp.h>
#include <asm/apm_slimpro_offload.h>
#include "apm_enet_access.h"
#include "apm_enet_qos.h"
#include "apm_cle_qos.h"
#include "apm_enet_offload.h"
#include <asm/apm_qm_cfg.h>

#ifdef CONFIG_APM_ENET_QOS

#define QOSID			"QOS: "
static unsigned long qos_work_domain = 0;

extern int apm_enet_rx_irq(struct apm_qm_msg_desc *rx_msg_desc);

static int apm_enet_qos_get_queue(struct apm_enet_dev_base *priv)
{
	int i = 0;
	struct qm_cfg_qconfig icfg;
	struct qm_cfg_qgroup group;
	u16 core = qos_work_domain;
	int rc = APM_RC_OK;
	u16 dev_port;

	dev_port = IP_ETH0 + priv->port_id;

	memset(&icfg, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
	icfg.ip = IP_BLK_QM;
	icfg.dev = dev_port;
	icfg.ppc = core;
	icfg.dir = QM_CFG_DIR_INGRESS;
	icfg.qsize = QM_CFG_QSIZE_16KB;
	icfg.thr = 1;
	icfg.qtype = QM_CFG_QTYPE_VQ;

	icfg.qcount = MAX_QOS_CLASS;
	for (i = 0; i < MAX_QOS_CLASS; i++) {
		icfg.qsel_arb[i] = QM_CFG_ARB_AVB;
		icfg.qsel_cfg[i] = DEFAULT_CLASS_RATE;
	}

	/* Add qconfig for INGRESS queue */
	if (qm_cfg_dev_add_qconfig(&icfg)!=0)
	{
		printk(KERN_INFO "qm_add_qconfig INGRESS failed\n");
		return (-1);
	}
	/* register irq to mailbox */
	apm_qm_mailbox_rx_register(icfg.mbox, apm_enet_rx_irq);

	strcpy(group.name, CLE_PTREE_DEFAULT);
	group.dev = dev_port;
	group.ppc = core;

	if (qm_cfg_get_qgroup(&group) != 0) {
		printk(KERN_INFO "qm_get_qgroup failed to get '%s'\n", CLE_PTREE_DEFAULT);
		return (-1);
	}

	/* new configuration is based on default configuration
	 * with ingress queue set to new created VQ
	 */
	strcpy(group.name, CLE_PTREE_QOS);
	group.iqid = icfg.qid;

	if (qm_cfg_add_qgroup(&group) !=0) {
		printk(KERN_INFO "qm_cfg_add_qgroup failed to add\n");
		return (-1);
	}
	return (rc);
}

static int apm_enet_qos_set_queue(struct apm_enet_dev_base *priv, struct qm_cfg_qconfig *queue_i, struct qm_cfg_qconfig *queue_f) {
	int j;
	struct qm_cfg_qgroup group;
	struct qm_cfg_qconfig icfg;
	struct qm_cfg_qconfig fcfg;
	u16 core = qos_work_domain;
	u16 dev_port;

	strcpy(group.name, CLE_PTREE_QOS);
	dev_port = IP_ETH0 + priv->port_id;
	group.dev = dev_port;
	group.ppc = core;

	if (qm_cfg_get_qgroup(&group) < 0) {
		printk(KERN_INFO "qm_cfg_get_qgroup failed to get '%s'\n", "CLE_PREE_QOS");
		return (-1);
	}

	memset(&icfg, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
	icfg.qid = group.iqid;
	if (qm_cfg_get_qconfig(&icfg) < 0) {
		printk(KERN_INFO "get qm_cfg_get_qconfig failed for QID = %d\n", icfg.qid);
		return (-1);
	}
	memset(&fcfg, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
	fcfg.qid = group.fqid;
	if (qm_cfg_get_qconfig(&fcfg) < 0) {
		printk(KERN_INFO "get qm_cfg_get_qconfig failed for QID = %d\n", fcfg.qid);
		return (-1);
	}

	queue_i->qtype = icfg.qtype;
	queue_i->qid   = icfg.qid;
	if (icfg.qtype == QM_CFG_QTYPE_VQ) {
		queue_i->qcount = icfg.qcount;
		for (j = 0; j < icfg.qcount; j++) {
			queue_i->qsel_qid[j] = icfg.qsel_qid[j];
		}
	}
	queue_f->pbn = fcfg.pbn;

	return (0);
}

static int dbptrs_init(struct apm_enet_dev_base *priv, struct qm_cfg_qconfig *icfg, struct qm_cfg_qconfig *fcfg) {
	int i;
	struct apm_cle_dbptr *qos_dbptr_d;
	struct apm_enet_qos_ctx *qos_ctx;

	/* initialize qos_ctx->qos_cfg.dbptr_d */
	qos_ctx = &priv->qos;
	qos_dbptr_d = qos_ctx->qos_cfg.dbptr_d;
	memset(qos_dbptr_d, 0, sizeof(struct apm_cle_dbptr) * MAX_QOS_CLASS);
	for (i = 0; i < MAX_QOS_CLASS; i++) {
		qos_dbptr_d[i].index = DBPTR_ALLOC(CLE_DB_INDEX + i);
		qos_dbptr_d[i].dstqid = icfg->qsel_qid[i];
		qos_dbptr_d[i].fpsel  = fcfg->pbn - 0x20;
		qos_dbptr_d[i].nxtfpsel  = fcfg->pbn - 0x20 /* + 1 */;
		/* Report Rx timestamp in H1Info */
		qos_dbptr_d[i].cle_insert_timestamp = 1;
	}
	return APM_RC_OK;
}

int apm_enet_qos_init(struct apm_enet_dev_base *priv)
{
	struct qm_cfg_qconfig icfg;
	struct qm_cfg_qconfig fcfg;
	struct apm_enet_qos_ctx *qos_ctx = &priv->qos;
	int rc = 0;

	if (qos_ctx->enable)
		goto _ret_enet_qos_init;

	if (qos_ctx->init_done) {
		apm_enet_qos_enable(priv, 1);
		goto _ret_enet_qos_init;
	}

#ifdef CONFIG_SMP
	qos_work_domain = 0;
#else
	qos_work_domain = apm_processor_id();
#endif

	/* Allocate QoS queues, dbptrs */
	if ((rc = apm_enet_qos_get_queue(priv)) != APM_RC_OK) {
		printk(KERN_ERR "Failed to allocate QoS VQ for %s interface\n",
			priv->ndev->name);
		return rc;
	}
	if ((rc = apm_enet_qos_set_queue(priv, &icfg, &fcfg)) != APM_RC_OK) {
		printk(KERN_ERR "Failed to setup QoS VQ for %s interface\n",
			priv->ndev->name);
		return rc;
	}
	dbptrs_init(priv, &icfg, &fcfg);

	/* Enalbe CLE config for QoS */
	apm_qos_enable(priv->ndev);
	qos_ctx->enable = 1;
	qos_ctx->init_done = 1;

	printk(KERN_INFO "APM86xxx QoS initialized for %s interface\n",
		priv->ndev->name);

_ret_enet_qos_init:
	return 0;
}

int apm_enet_qos_enable(struct apm_enet_dev_base *priv, u32 enable)
{
	int rc = APM_RC_OK;

	/* Enable or disable QOS */
	if (priv->qos.enable == enable)
		goto _ret_enet_qos_enable;

	priv->qos.enable = enable;
	if (enable) {
		ENET_DEBUG_QOS("QOS enabled\n");
		rc = apm_inet_switch(priv, ETHSUPPORT_QOS);
	} else {
		ENET_DEBUG_QOS("QOS disabled\n");
		apm_inet_switch(priv, ETHOFFLOAD_DEFAULT);
	}

_ret_enet_qos_enable:
	return rc;
}

#endif
