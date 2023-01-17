/*
 * AppliedMicro APM88xxxx CLE Engine Configuration Header
 *
 * Copyright (c) 2013 Applied Micro Circuits Corporation.
 * Ravi Patel <rapatel@apm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * @file apm_cle_config.h
 *
 * This header declares Configuration APIs and macros for
 * AppliedMicro APM88xxxx SoC Classifier module.
 */

#ifndef __APM_CLE_CONFIG_H_
#define __APM_CLE_CONFIG_H_

/* Classifier Configurations for Linux: Enet Port */ 
#define CLE_DB_INDEX		0
#include <net/ip.h>

/* String ID for CLE ptree_config */
#define CLE_PTREE_ID_SIZE 8
#define CLE_PTREE_DEFAULT "default"
#define MAX_RX_QUEUES 4
#define MAX_TX_QUEUES 4
enum apm_macaddr_type {
	TYPE_USR_MACADDR = 0,
	TYPE_SYS_MACADDR,
};

/* Reserved System MAC addresses to allow */
enum apm_sys_macaddr_index {
	ETHERNET_MACADDR,	/* EthernetN MACAddr */
	BROADCAST_MACADDR,	/* FF:FF:FF:FF:FF:FF */
	UNICAST_MACADDR,	/* xu:xx:xx:xx:xx:xx */ /* where u & 1 = 0 */
	MULTICAST_MACADDR,	/* xm:xx:xx:xx:xx:xx */ /* where m & 1 = 1 */
	APM_SYS_MACADDR,
};

extern const u8 apm_usr_macmask[ETH_ALEN + 2];
extern const u8 apm_sys_macmask[APM_SYS_MACADDR][ETH_ALEN + 2];
extern const u8 apm_sys_macaddr[APM_SYS_MACADDR][ETH_ALEN + 2];

/* software context of a classifier */
struct xgene_enet_cle {
	u32 port;
	struct xgene_enet_cle_ptree *ptree_cfg;
};

struct xgene_enet_cle_ptree {
	u32 enable;
	char name[CLE_PTREE_ID_SIZE];
};

/**
 * @brief   This function initialize Classifier Engine based on port_id.
 * @param   port_id - Inline-GE/LAC Port number
 * @return  cle handler - success or NULL - failure
 */
struct xgene_enet_cle *apm_cle_init(u32 port_id);

/**
 * @brief   This function switch pre classifier configuration specified ptree.
 * @param   port_id - Inline-GE/LAC Port number
 * @param   ptree_id - ptree ID CLE_PTREE_DEFAULT/CLE_PTREE_WOL
 * @return  0 - success or -1 - failure
 */
int apm_preclass_switch_tree(u8 port_id, char *ptree_id);

/**
 * @brief   This function searches for pre classifier configuration for
 *          specified ptree_id.
 * @param   port_id - Inline-GE/LAC Port number
 * @param   ptree_id - ptree ID of the classifier configuration
 * @return  apm_ptree_config - NULL or the apm_ptree_config found during search
 */
struct apm_ptree_config *apm_find_ptree_config(u8 port_id, char *ptree_id);

/**
 * @brief   This function adds new pre classifier configuration with
 *          specified ptree_id.
 * @param   port_id - Inline-GE/LAC Port number
 * @param   ptree_id - ptree ID of the classifier configuration to be added
 * @return  apm_ptree_config - NULL or the apm_ptree_config added
 */
struct apm_ptree_config *apm_add_ptree_config(u8 port_id, char *ptree_id);

/**
 * @brief   This function deletes new pre classifier configuration with
 *          specified ptree_id.
 * @param   port_id - Inline-GE/LAC Port number
 * @param   ptree_id - ptree ID of the classifier configuration to be deleted
 * @return  0 if deleted or -1 for not found
 */
int apm_del_ptree_config(u8 port_id, char *ptree_id);

#ifdef PTREE_MANAGER
/**
 * @brief   This function searches for system ptree_id configuration for
 *          specified port_id.
 * @param   port_id - Inline-GE/LAC Port number
 * @return  ptree_id of system ptree configuration or NULL
 */
char *apm_get_sys_ptree_id(u8 port);
#endif

struct xgene_enet_cle_ptree *apm_preclass_init(u8 port_id, 
			u16 *rx_dstqid, u16 *rx_fpsel);

int apm_preclass_update_mac(u8 port_id, enum apm_macaddr_type type,
			u8 index, const u8 *macmask, const u8 *macaddr);

#endif /* __APM_CLE_CONFIG_H_ */
