/**
 * AppliedMicro APM862xx SoC Ethernet Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Mahesh Pujara <mpujara@apm.com>
 *                      Ravi Patel <rapatel@apm.com>
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
 * @file apm_enet_ioctl.h
 *
 * This file defines IOCTL interface for APM862xx SoC Ethernet Driver
 *
 */

#ifndef	 __APM_ENET_IOCTL_H__
#define	 __APM_ENET_IOCTL_H__

#include "apm_cle_config.h"
#include "apm_cle_mgr.h"

/* Defines for register read/write */
#define READ_CMD	0
#define WRITE_CMD	1
#define QUEUE_CMD	2
#define REG_GBL_CMD	10

/* AMCC Ethernet Signature */
#define AMCC_ENET_SIGNATURE 0x414D4343

/* ioctl operation commands */
enum apm_enet_ioctl_op_cmds {
	SIOREGACCESS = 1,
	SIOCENETINFO,
	SIOCIPAUSETHR,
	SIOCESENDPAUSEFRAME,
	/* CLE Related commands */
	SIOCPRECLASSSTATE,
	SIOCPRECLASSHALT,
	SIOCPRECLASSTRACE,
	SIOCSSYSPTREECONFIG,
	SIOCGSYSPTREECONFIG,
	SIOCSPTREECONFIG,
	SIOCGPTREECONFIG,
	SIOCPTREEALLOC,
#ifdef ROLLBACK_MANAGER
	SIOCPTREEFREE,
	SIOCPTREEROLLBACK,
#endif
	SIOCQOSENABLE,
	SIOCQOSRXENABLE,
	SIOCQOSRXDISABLE,
	SIOCGQOSCONFIG,
	SIOCGETHOFFLOAD,
	SIOCPTREENODECONFIG,
	SIOCPTREENODECLEAR,
	SIOCSPTREENODE,
	SIOCGPTREENODE,
	SIOCSCLEDBPTR,
	SIOCGCLEDBPTR,
	SIOCCLEAVLINIT,
	SIOCCLEAVLADD,
	SIOCCLEAVLDEL,
	SIOCCLEAVLSRCH,
	SIOCCLEAVLSTATUS,
	SIOCAVLALLOC,
	SIOCAVLFREE,
	SIOCSQMMSG16,
	SIOLROENABLE,
	SIOLROTIMEOUT,
	SIOLROBYTECNT,
	SIOLROCTX,
	SIOSLIMPROIPFWENABLE,
	SIOSLIMPROIPFWIPADDR
};

enum apm_enet_lro_params {
	LRO_SEGMENT_WQID = 0,
	LRO_SEGMENT_FQPBN,
	MAX_LRO_PARAMS
};

struct apm_enet_reg_op {
	u8 cmd_id;		/* read/write reg */
	u8 block_id;		/* MAC, STATS, GLOBAL, QMI etc. */
	u32 reg_offset;
	u32 data[16];
};

struct apm_enet_info_op {
	u32 signature;		/* AMCC_ENET_SIGNATURE 'AMCC' 0x414D4343 */
	u32 port;
};

struct apm_ptree_config_param {
	u8 port;
	char ptree_id[CLE_PTREE_ID_SIZE];
	struct apm_ptree_config *ptree_config;
};

struct ptree_node_param {
	u8 port;
	struct ptree_node node;
};

struct apm_preclass_trace_param {
	u8 port;
	struct apm_preclass_trace preclass_trace;
};

struct apm_preclass_state_param {
	u8 port;
	struct apm_preclass_state preclass_state;
};

struct apm_ptree_alloc_param {
	u8 port;
	u8 ptnodes;
	u16 dbptrs;
	struct ptree_node *node;
	struct apm_cle_dbptr *dbptr;
	struct apm_ptree_config *ptree_config;
	char ptree_id[CLE_PTREE_ID_SIZE];
};

struct apm_avl_alloc_param {
	u8 port;
	u16 avlnodes;
	u16 dbptrs;
	struct avl_node *node;
	struct apm_cle_dbptr *dbptr;
};

enum apm_enet_qos_class {
	CLASS_0 ,  /* dedicated for default traffic */
	CLASS_1 ,  /* dedicated for LOWEST shared traffic */
	CLASS_2 ,  /* dedicated for LOW shared traffic */
	CLASS_3 ,  /* dedicated for MEDIUM shared traffic */
	CLASS_4 ,  /* dedicated for HIGH shared traffic */
	CLASS_5 ,  /* dedicated for HIGHEST shared traffic */
	CLASS_6 ,  /* do not access this class */
	MAX_QOS_CLASS
};

struct apm_qos_param {
	u8 port;
	/* dbptr_d: each dbptr_d, kn_d corresponds to 1 QoS CLASS */
	struct ptree_kn kn_d[MAX_QOS_CLASS];
	struct apm_cle_dbptr dbptr_d[MAX_QOS_CLASS];
};

union apm_enet_ioctl_ops {
	struct apm_enet_reg_op reg_ops;
	struct apm_enet_info_op info_ops;
	u32 pause_thr;
	/* CLE Related parameters */
	u8 port;
	u8 ptnode_index;
	u16 qm_msg16;
	enum apm_cle_avl_search_str_type key_size;
	struct apm_cle_avl_status avl_status;
	struct apm_ptree_config_param ptree_cfg;
	struct apm_cle_dbptr dbptr;
	struct ptree_node_param ptree_node_cfg;
	struct apm_preclass_trace_param trace_cfg;
	struct avl_node avl_node_cfg;
	struct apm_preclass_state_param status_cfg;
	struct apm_ptree_alloc_param ptree_alloc_cfg;
	struct apm_avl_alloc_param avl_alloc_cfg;
	/* LRO related parameters */
	u8  lro_enable;
	u32 lro_timeoutms;
	u32 lro_maxbytecnt;
	u32 *lro_ctx;
	/* SlimPRO IP forward */
	u8  slimpro_ipfw_enable;
	u32 slimpro_ipfw_ipaddr;
	/* QoS related parameters */
	u8 qos_enable;
	struct apm_qos_param qos_cfg;
	u32 ethoffload;
};

struct apm_enet_ioctl {
	u32 cmd;
	union apm_enet_ioctl_ops ioctl_ops;
};

struct apm_ptree_config *apm_find_ptree_config(u8 port, char *ptree_id);
struct apm_ptree_config *apm_add_ptree_config(u8 port, char *ptree_id);
int apm_del_ptree_config(u8 port, char *ptree_id);

#endif	 /* __APM_ENET_IOCTL_H__ */
