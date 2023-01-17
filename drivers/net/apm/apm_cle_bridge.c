/*
 * AppliedMicro APM862xx SoC Classifier Test code
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
 * All rights reserved. Pranavkumar Sawargaonkar <psawargaonkar@apm.com>
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
 * @file apm_cle_bridge.c
 *
 * Implementing software packet bridge functionality using Classifier.
 *
 */
#include "apm_enet_offload.h"
#include "apm_cle_bridge.h"
#include <net/net_namespace.h>
#include <linux/rtnetlink.h>
#include <linux/list.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/module.h>

struct cle_avl_entry_db {
	struct list_head        src_mac_list;
	struct list_head        dst_mac_list;
	unsigned char           addr[6];
	int fw_port;
};

struct cle_br_gbl_data {
	atomic_t avl_cnt; /* Number of entries in HW AVL tree */
	struct ptree_kn kn[MAX_PORTS];
	struct net_device *br_devs[MAX_PORTS];
	struct list_head cle_avl_entry_db_head[MAX_CLE_ENGINE];
	int cle_br_enabled; /* To enable/disable Cle bridge functionality dynamically */
	struct proc_dir_entry *entry;
	spinlock_t	cle_br_lock;
};

/* Global data for classifier */
struct cle_br_gbl_data *gbl_data = NULL;

struct cle_avl_entry_db *cle_allocate_avl_db_entry(unsigned char *mac_addr)
{
	struct cle_avl_entry_db *entry;

	entry = kzalloc(sizeof(struct cle_avl_entry_db), GFP_ATOMIC);

	if (!entry) {
		printk("%s Failed to allocate avl db entry\n", __func__);
		return NULL;
	}

	INIT_LIST_HEAD(&entry->src_mac_list);
	INIT_LIST_HEAD(&entry->dst_mac_list);
	memcpy(entry->addr, mac_addr, 6);

	return entry;
}

void cle_insert_src_avl_db_entry(int cle_id, struct list_head *new_entry)
{
	struct list_head *head = &(gbl_data->cle_avl_entry_db_head[cle_id]);

	list_add_tail(new_entry, head);
}

void cle_insert_dst_avl_db_entry(struct list_head *src_head,
				 struct list_head *new_dst_entry)
{
	list_add_tail(new_dst_entry, src_head);
}

void print_mac_addr(unsigned char *str, int len)
{
	int i = 0;

	for (i = 0; i < len; i++)
		printk("%02x ", str[i]);
	printk("\n");

}

struct cle_avl_entry_db *cle_find_src_avl_db_entry(int cle_id,
						   unsigned char *mac_addr)
{
	struct cle_avl_entry_db *entry, *temp;
	struct list_head *head = &(gbl_data->cle_avl_entry_db_head[cle_id]);

	list_for_each_entry_safe(entry, temp, head, src_mac_list) {
		if (!compare_ether_addr(entry->addr, mac_addr)) {
#if 0
			print_mac_addr(entry->addr, 6);
			print_mac_addr(mac_addr, 6);
#endif
			return entry;
		}
	}

	return NULL;
}

struct cle_avl_entry_db *cle_find_dst_avl_db_entry(struct list_head *head,
						   unsigned char *mac_addr)
{
	struct cle_avl_entry_db *entry, *temp;

	list_for_each_entry_safe(entry, temp, head, dst_mac_list) {
		if (!compare_ether_addr(entry->addr, mac_addr))
			return entry;
	}

	return NULL;
}

int cle_avl_add_entry(int cle_id, unsigned char *src_mac,
		      unsigned char *dst_mac, int fw_port)
{
	struct cle_avl_entry_db *src_entry, *dst_entry;
	int new_src = 0;

	if (!(src_entry = cle_find_src_avl_db_entry(cle_id, src_mac))) {
		src_entry = cle_allocate_avl_db_entry(src_mac);
		if (!src_entry) {
			printk("%s Failed to allocate source avl db entry\n",
				__func__);
			return -ENOMEM;
		}
		new_src = 1;
	}

	if (new_src) {
		cle_insert_src_avl_db_entry(cle_id, &src_entry->src_mac_list);
		dst_entry = NULL;
	} else {
		dst_entry = cle_find_dst_avl_db_entry(&src_entry->dst_mac_list,
						      dst_mac);
	}

	if (dst_entry)
		return -1;

	dst_entry = cle_allocate_avl_db_entry(dst_mac);
	if (!dst_entry) {
		printk("%s Failed to allocate destination avl db entry\n",
			__func__);
	}

	dst_entry->fw_port = fw_port;
	cle_insert_dst_avl_db_entry(&src_entry->dst_mac_list,
				    &dst_entry->dst_mac_list);

	return 0;
}

/* dbptr orginazation for APM862xx
 * Entry  0 --> Forward packet to Eth0 for TX
 * Entry  1 --> Forward packet to Eth1 for TX
 * Entry  2 --> Forward packet to CLE_EXT_PORT0
 * Entry  3 --> Forward packet to CLE_EXT_PORT1
 * Entry  4 --> Forward packet to CLE_EXT_PORT2
 * Entry  5 --> Forward packet to CLE_EXT_PORT3
 *
 * dbptr orginazation for Non APM862xx
 * Entry  0 --> Forward packet to Eth0 for TX from Eth0/Eth1 i.e. CLE0
 * Entry  1 --> Forward packet to Eth1 for TX from Eth0/Eth1 i.e. CLE0
 * Entry  2 --> Forward packet to Eth2 for TX from Eth0/Eth1 i.e. CLE0
 * Entry  3 --> Forward packet to Eth3 for TX from Eth0/Eth1 i.e. CLE0
 * Entry  4 --> Forward packet to CLE_EXT_PORT0 from Eth0/Eth1 i.e. CLE0
 * Entry  5 --> Forward packet to CLE_EXT_PORT1 from Eth0/Eth1 i.e. CLE0
 * Entry  6 --> Forward packet to CLE_EXT_PORT2 from Eth0/Eth1 i.e. CLE0
 * Entry  7 --> Forward packet to CLE_EXT_PORT3 from Eth0/Eth1 i.e. CLE0
 * Entry  8 --> Forward packet to Eth0 for TX from Eth2/Eth3 i.e. CLE1
 * Entry  9 --> Forward packet to Eth1 for TX from Eth2/Eth3 i.e. CLE1
 * Entry 10 --> Forward packet to Eth2 for TX from Eth2/Eth3 i.e. CLE1
 * Entry 11 --> Forward packet to Eth3 for TX from Eth2/Eth3 i.e. CLE1
 * Entry 12 --> Forward packet to CLE_EXT_PORT0 from Eth2/Eth3 i.e. CLE1
 * Entry 13 --> Forward packet to CLE_EXT_PORT1 from Eth2/Eth3 i.e. CLE1
 * Entry 14 --> Forward packet to CLE_EXT_PORT2 from Eth2/Eth3 i.e. CLE1
 * Entry 15 --> Forward packet to CLE_EXT_PORT3 from Eth2/Eth3 i.e. CLE1
 */
static struct apm_cle_dbptr dbptr[MAX_CLE_ENGINE][CLE_MAX_PORTS];

/*
 * Parser Node branches for EWDN/FWDN ,they defines actual
 * comparision data at each node
 *
 */
static struct ptree_branch branch[] = {
	{ 0xFFFF, 0x0000, EQT, PTREE_ALLOC(0), EW_BRANCH(1), 2, 0, JMP_REL, JMP_FW },
								/* MAC Address 0-1 bytes */
	{ 0xFFFF, 0x0000, EQT, PTREE_ALLOC(0), EW_BRANCH(2), 2, 0, JMP_REL, JMP_FW },
								/* MAC Address 2-3 bytes */
	{ 0xFFFF, 0x0000, EQT, PTREE_ALLOC(0), EW_BRANCH(3), 2, 0, JMP_REL, JMP_FW },
								/* MAC Address 4-5 bytes */
	{ 0xFFFF, 0x0000, EQT, PTREE_ALLOC(0), EW_BRANCH(4), 2, 0, JMP_REL, JMP_FW },
								/* MAC Address 6-7 bytes */
	{ 0xFFFF, 0x0000, EQT, PTREE_ALLOC(0), EW_BRANCH(5), 2, 0, JMP_REL, JMP_FW },
								/* MAC Address 8-9 bytes */
	{ 0xFFFF, 0x0000, EQT, PTREE_ALLOC(1), EW_BRANCH(0), 0, 0, 0, 0 },
								/* MAC Address 10-11 bytes */

	{ 0xFFFF, 0x0000, EQT, PTREE_ALLOC(2), KEY_INDEX(0), 0, 0, 0, 0 },
								/* Last Node */
};

static struct ptree_dn dn[] = {
	{ START_NODE, DBPTR_DROP(0), AVL_SEARCH(BOTH_BYTES), 0, 0, 0, 6, &branch[0] },
	{ LAST_NODE,  DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),   0, 0, 0, 1, &branch[6] },
};

struct ptree_node node[] = {
	{ PTREE_ALLOC(0), EWDN, 0, (struct ptree_dn*)&dn[0] },
	{ PTREE_ALLOC(1), EWDN, 0, (struct ptree_dn*)&dn[1] },
	{ PTREE_ALLOC(2), KN,   0, NULL },
};

/*
 * This function programs Classifier Parser nodes and starts the classifier
 * engine for given port. Parser walk forms the serach string for the Search
 * Engine lookup
 */
int apm_cle_br_config_parser_tree(u8 port_id)
{
	struct ptree_kn *kn = NULL;
	struct apm_ptree_config *def_ptree_config = NULL, *ptree_config = NULL;
	int rc = APM_RC_OK;

	if (port_id >= MAX_PORTS ||
		(def_ptree_config = apm_find_ptree_config(port_id,
			CLE_PTREE_DEFAULT)) == NULL) {
		rc = -ENODEV;
		goto exit_config;
	}

	ptree_config = apm_add_ptree_config(port_id, CLE_PTREE_BRIDGE);

	if (ptree_config == NULL) {
		rc = -ENOMEM;
		goto exit_config;
	}

	/*
	 * Assign the Parser Result Ptr to Key Node, its priority is assigned 1
	 * hence SEARCH_RES_PTR takes precedence
	 */
	kn = &gbl_data->kn[port_id];
	kn->result_pointer = def_ptree_config->start_dbptr;
	kn->priority = 1;
	/* Fixme: Define a macro for readablity */
	node[2].data = kn;
	ptree_config->default_result = DFCLSRESDBPRIORITY0_WR(7) |
					DFCLSRESDBPTR0_WR(kn->result_pointer);

	CLE_BR_DBG("Creating a Bridge mode Patricia Tree Nodes for "
						"port %d\n", port_id);

	if ((rc = apm_ptree_alloc(port_id, ARRAY_SIZE(node), 0,
			node, NULL, ptree_config)) !=
			APM_RC_OK) {
		PCLS_ERR("Preclass init error %d \n", rc);
		return rc;
	}

exit_config:
	return rc;
}

/*
 * This function programs given search key into Search Engine AVL database.
 */
static int apm_cle_add_search_key(u32 port, void *key, int pri, int *db_idx)
{
	int rc = APM_RC_OK;
	struct avl_node node_data;
	u32 *search_key = (u32 *) key;

	memset(&node_data, 0 , sizeof(node_data));

	/* Copy the search sting to add to Search Engien database */
	memcpy (node_data.search_key, search_key, sizeof(node_data.search_key));

	rc = apm_cle_avl_search_node(port, &node_data);

	if (rc != APM_RC_CLE_MISS) {
		CLE_BR_ERR("%s Entry search return unexpected value %d\n",
								__func__, rc);
		return rc;
	}

	memset(&node_data, 0 , sizeof(node_data));

	/* Copy the search sting to add to Search Engien database */
	memcpy (node_data.search_key, search_key, sizeof(node_data.search_key));

	/* Assign the Priority and Result Ptr */
	node_data.priority = pri;
	node_data.result_pointer = db_idx[0];

	if ((rc = apm_cle_avl_add_node(port, &node_data) !=  APM_RC_OK)) {
		CLE_BR_ERR("%s:%d - Error %d - In Ading sarch string to AVl \n",
			   __FUNCTION__, __LINE__, rc);
		return rc;
	}

	atomic_inc(&(gbl_data->avl_cnt));
	return rc;
}

/*
 * This function deletes given search key from Search Engine AVL database.
 */
static int apm_cle_delete_search_key(u32 port, void *key)
{
	int rc = APM_RC_OK;
	struct avl_node node_data;
	u32 node_addr = 0;

	memset(&node_data, 0 , sizeof(node_data));
	/* Copy the search sting to add to Search Engien database */
	memcpy (node_data.search_key, key, sizeof(node_data.search_key));

	if ((rc = apm_cle_avl_del_node(port, &node_data) !=  APM_RC_OK)) {
		CLE_BR_ERR("%s:%d - Error %d - In Ading sarch string to AVl \n",
			   __FUNCTION__, __LINE__, rc);
		return rc;
	}

	node_addr = node_data.index;
	CLE_BR_DBG("%s Node %d deleted from avl tree\n", __func__, node_addr);

	atomic_dec(&(gbl_data->avl_cnt));

	return rc;
}

/*
 * key -> Dest MAC address
 * fw_dst_port -> Port on which packets to be forwarded.
 */
static int apm_cle_add_fw_entry(u32 port, unsigned char *key, int fw_dst_port)
{
	int rc = APM_RC_OK;
	int db_index[2] = {0, 0};
	int pri = DEFAULT_BR_PRI;
	int cid;
	struct cle_avl_entry_db *src;
	struct cle_avl_entry_db *dst = NULL;
	unsigned long flags;

#if 0
	printk("Key: %02x.%02x.%02x.%02x.%02x.%02x %02x.%02x.%02x.%02x.%02x.%02x\n",
			key[0], key[1], key[2], key[3], key[4],key[5],
			key[6], key[7], key[8],key[9],  key[10], key[11]);
	printk("Dest port %d\n", fw_dst_port);
#endif

	if (atomic_read(&(gbl_data->avl_cnt)) >= MAX_AVL_ENTRIES)
		return -ENOMEM;

	if (fw_dst_port < 0 && fw_dst_port > CLE_MAX_PORTS) {
		printk("Unknown port %d for forwarding, assigning drop db!!\n",
				fw_dst_port);
	} else {
		db_index[0] = dbptr[CLE_0][fw_dst_port].index;
#ifndef CONFIG_APM862xx
		db_index[1] = dbptr[CLE_1][fw_dst_port].index;
#endif
	}

#if 0
	CLE_BR_DBG("Key 0 %x swapped key %x\n", key[0], cpu_to_le32(key[0]));
	CLE_BR_DBG("Key 1 %x swapped key %x\n", key[1],
					cpu_to_le32((key[1] & 0xffff0000)));
	printk("forward this to port %d\n", fw_dst_port);
#endif

	spin_lock_irqsave(&(gbl_data->cle_br_lock), flags);

	cid = PID2CID[CLE_ENET_0];
	src = cle_find_src_avl_db_entry(cid, &key[6]) ;
	if (src)
		dst = cle_find_dst_avl_db_entry(&src->dst_mac_list, key);

	if (!dst) {
		/* Add any number of serach entry to Search  Engine database */
		rc = apm_cle_add_search_key(CLE_ENET_0, key, pri, &db_index[0]);
		if (rc == APM_RC_OK)
			cle_avl_add_entry(cid, &key[6], key, fw_dst_port);
	}

#ifndef CONFIG_APM862xx
	cid = PID2CID[CLE_ENET_2];
	src = cle_find_src_avl_db_entry(cid, &key[6]) ;
	if (src)
		dst = cle_find_dst_avl_db_entry(&src->dst_mac_list, key);

	if (!dst) {
		/* Add any number of serach entry to Search  Engine database */
		rc = apm_cle_add_search_key(CLE_ENET_2, key, pri, &db_index[0]);
		if (rc == APM_RC_OK)
			cle_avl_add_entry(cid, &key[6], key, fw_dst_port);
	}
#endif
	spin_unlock_irqrestore(&(gbl_data->cle_br_lock), flags);

	return rc;
}

/*
 * key -> Dest MAC address
 */
static int apm_cle_delete_fw_entry(u32 port, u32 *key)
{
	int rc = APM_RC_OK;

#if 0
	CLE_BR_DBG("Key 0 %x swapped key %x\n", key[0], cpu_to_le32(key[0]));
	CLE_BR_DBG("Key 1 %x swapped key %x\n", key[1],
					cpu_to_le32((key[1] & 0xffff0000)));
#endif

	/* Add any number of serach entry to Search  Engine database */
	if ((rc = apm_cle_delete_search_key(port, key) !=  APM_RC_OK)) {
		CLE_BR_ERR("%s:%d - Error %d - In Classifier search"
			   "engine config\n",
			   __FUNCTION__, __LINE__, rc);
	}

	return rc;
}

#if defined(APM_CLE_TEST_BR)
static void apm_br_add_test_key(void)
{
	int rc = APM_RC_OK;
	u32 search_key[AVL_MAX_SEARCH_STRING] = {0};

	/* To compare MAC Address 00:01:73:01:F2:60 set as following */
	/* Prepare Search Key  */
	search_key[0] = 0x00017301;
	search_key[1] = 0xF2600000;
	rc = apm_cle_add_fw_entry(CLE_ENET_0, search_key, 0);

	memset(search_key, 0, sizeof(search_key));
	search_key[0] = 0x00017321;
	search_key[1] = 0xF2600000;
	rc = apm_cle_add_fw_entry(CLE_ENET_0, search_key, 0);

	memset(search_key, 0, sizeof(search_key));
	search_key[0] = 0x0000C0A8;
	search_key[1] = 0x05640000;
	rc = apm_cle_add_fw_entry(CLE_ENET_0, search_key, 1);
}
#endif

/*
 * Function adds a new forwarding entry in to CLE bridge.
 */
int apm_addbr_fdb(struct net_device *dst_dev, struct net_device *src_dev,
			  const unsigned char *dst_addr,
			  const unsigned char *src_addr)
{
	int rc = APM_RC_OK;
	u32 search_key[AVL_MAX_SEARCH_STRING] = {0};
	char *temp;

	if (!gbl_data || !gbl_data->cle_br_enabled ||
		ETH_INT_PORT_ERR(apm_inet_offload_ndev_to_index(src_dev)))
		return -1;

	if ((rc = apm_inet_offload_ndev_to_index(dst_dev)) == -1) {
		CLE_BR_ERR("%s: %s is not apm offload device\n",
			__func__, dst_dev->name);
		return rc;
	}

	CLE_BR_FDB_DBG("Dest MAC: %02x.%02x.%02x.%02x.%02x.%02x --> ",
			dst_addr[0],
			dst_addr[1],
			dst_addr[2],
			dst_addr[3],
			dst_addr[4],
			dst_addr[5]);
	CLE_BR_FDB_DBG("FWD Port: %d\n", rc);
	temp = (char *) search_key;
	memcpy(temp, dst_addr, 6);
	temp += 6;
	memcpy(temp, src_addr, 6);

	/* FIXME with correct port info */
	apm_cle_add_fw_entry(CLE_ENET_0, (unsigned char *) search_key, rc);

#ifndef CONFIG_APM862xx
	apm_cle_add_fw_entry(CLE_ENET_2, (unsigned char *) search_key, rc);
#endif

	return rc;
}

int cle_search_key(int cid, unsigned char *key)
{
	struct avl_node node_data;
	int rc;

	memset(&node_data, 0 , sizeof(node_data));
	/* Copy the search sting to add to Search Engien database */
	memcpy (node_data.search_key, key, sizeof(node_data.search_key));

	rc = 0;
	rc = apm_cle_avl_search_node(cid, &node_data);

	return rc;
}

int apm_cle_traverse_and_delete_fw_list(int cid,
	struct cle_avl_entry_db *src_entry)
{
	struct cle_avl_entry_db *entry, *temp;
	u32 search_key[AVL_MAX_SEARCH_STRING];
	struct list_head *head = &src_entry->dst_mac_list;
	unsigned char *cp_dst;

        list_for_each_entry_safe(entry, temp, head, dst_mac_list) {
		memset(search_key, 0, sizeof(search_key));
		cp_dst = (unsigned char *) search_key;
		cp_dst += 6;
		memcpy(cp_dst, src_entry->addr, 6);
		cp_dst = (unsigned char *) search_key;
		memcpy(cp_dst, entry->addr, 6);
		apm_cle_delete_fw_entry(cid, (u32 *) search_key);
		list_del(&entry->dst_mac_list);
		kfree(entry);
        }

	list_del(&src_entry->src_mac_list);
	kfree(src_entry);

	return 0;
}

int apm_cle_delete_all_fw_list_entries(int cid)
{
	struct cle_avl_entry_db *entry, *temp;
	struct list_head *head = &(gbl_data->cle_avl_entry_db_head[cid]);
	unsigned long flags;

	spin_lock_irqsave(&(gbl_data->cle_br_lock), flags);

	list_for_each_entry_safe(entry, temp, head, src_mac_list) {
		apm_cle_traverse_and_delete_fw_list(cid, entry);
	}

	spin_unlock_irqrestore(&(gbl_data->cle_br_lock), flags);

	return 0;
}

int apm_cle_traverse_and_print_fw_list(int cid,
	struct cle_avl_entry_db *src_entry)
{
	struct cle_avl_entry_db *entry, *temp;
	u32 search_key[AVL_MAX_SEARCH_STRING];
	struct list_head *head = &src_entry->dst_mac_list;
	unsigned char *cp_dst;

        list_for_each_entry_safe(entry, temp, head, dst_mac_list) {
		memset(search_key, 0, sizeof(search_key));
		cp_dst = (unsigned char *) search_key;
		cp_dst += 6;
		memcpy(cp_dst, src_entry->addr, 6);
		cp_dst = (unsigned char *) search_key;
		memcpy(cp_dst, entry->addr, 6);
		print_mac_addr((unsigned char *) search_key, 12);
		printk("--> Forwarded to port %d\n", entry->fw_port);
        }

	return 0;
}

int apm_cle_print_all_fw_list_entries(int cid)
{
	struct cle_avl_entry_db *entry, *temp;
	struct list_head *head = &(gbl_data->cle_avl_entry_db_head[cid]);
	unsigned long flags;

	spin_lock_irqsave(&(gbl_data->cle_br_lock), flags);

	printk("PRINTING FWD Entries\n");

	list_for_each_entry_safe(entry, temp, head, src_mac_list) {
		apm_cle_traverse_and_print_fw_list(cid, entry);
	}

	spin_unlock_irqrestore(&(gbl_data->cle_br_lock), flags);

	return 0;
}


/*
 * Function delets a forwarding mac entry from CLE bridge.
 */
int apm_delbr_fdb(struct net_device *dev,
			  const unsigned char *addr)
{
	int rc = APM_RC_OK;
	struct cle_avl_entry_db *src_db;
	unsigned long flags;

	if (!gbl_data)
		return -1;

	if ((rc = apm_inet_offload_ndev_to_index(dev)) == -1) {
		CLE_BR_ERR("%s: %s is not apm offload device\n",
			__func__, dev->name);
		return rc;
	}

	CLE_BR_FDB_DBG("MAC address to be deleted from AVL:"
			"%02x.%02x.%02x.%02x.%02x.%02x\n",
			addr[0],
			addr[1],
			addr[2],
			addr[3],
			addr[4],
			addr[5]);

	spin_lock_irqsave(&(gbl_data->cle_br_lock), flags);

	src_db = cle_find_src_avl_db_entry(0, (unsigned char *) addr);
	if (src_db) {
		apm_cle_traverse_and_delete_fw_list(0, src_db);
	}

#ifndef CONFIG_APM862xx
	src_db = cle_find_src_avl_db_entry(1, (unsigned char *) addr);
	if (src_db) {
		apm_cle_traverse_and_delete_fw_list(1, src_db);
	}
#endif
	spin_unlock_irqrestore(&(gbl_data->cle_br_lock), flags);

	return rc;
}

/*
 * Function adds an interface in CLE bridge.
 */
int apm_addbr_port(struct net_device *dev)
{
	int rc = APM_RC_OK;
	int port_id;
	char *ptree_id;

	if ((rc = apm_inet_offload_ndev_to_index(dev)) == -1) {
		CLE_BR_ERR("%s: %s is not apm offload device\n",
			__func__, dev->name);
		goto _ret_addbr_port;
	}

	if (rc < CLE_INT_PORT0)
		goto _ret_addbr_port;

	port_id = rc - CLE_INT_PORT0;
	if ((rc = apm_cle_br_config_parser_tree(port_id)) != APM_RC_OK)
		goto _ret_addbr_port;

	dev->priv_flags |= IFF_BRIDGE_PORT;
	gbl_data->br_devs[port_id] = dev;

	ptree_id = apm_get_sys_ptree_id(port_id);

	if (strncmp(ptree_id, CLE_PTREE_BRIDGE, CLE_PTREE_ID_SIZE))
		apm_preclass_switch_tree(port_id, CLE_PTREE_BRIDGE, 0);

_ret_addbr_port:
	return rc;
}

/*
 * Function deletes an interface fro CLE bridge.
 */
int apm_delbr_port(struct net_device *dev)
{
	int rc = APM_RC_OK;

	if ((rc = apm_inet_offload_ndev_to_index(dev)) == -1) {
		CLE_BR_ERR("%s: %s is not apm offload device\n",
			__func__, dev->name);
		goto _ret_delbr_port;
	}

	if (rc < CLE_INT_PORT0)
		goto _ret_delbr_port;

	rc -= CLE_INT_PORT0;
	dev->priv_flags &= ~IFF_BRIDGE_PORT;
	gbl_data->br_devs[rc] = NULL;
	rc = apm_preclass_switch_tree(rc, CLE_PTREE_DEFAULT, 0);

_ret_delbr_port:
	return rc;
}

static int apm_cle_br_driver_open(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t apm_cle_br_driver_read(struct file *file, char __user * buf,
		size_t count, loff_t *ppos)
{
	printk("\nClassifier based bridge module\n");
	if (gbl_data->cle_br_enabled)
		printk("Bridge optimization: Enable\n");
	else
		printk("Bridge optimization: Disable\n");

	apm_cle_print_all_fw_list_entries(0);

	return 0;
}

static ssize_t apm_cle_br_driver_write(struct file *file, const char __user *buf,
                                        size_t count, loff_t *ppos)
{
	int i = 0;

	switch(*buf) {
	case CMD_DISABLE_CLE_BR:
		printk("\nDisabling apm classifier Bridge\n");
		gbl_data->cle_br_enabled = 0;
		for (i = 0; i < MAX_PORTS; i++)
			if (gbl_data->br_devs[i])
				apm_preclass_switch_tree(i,
					CLE_PTREE_DEFAULT, 0);

		apm_cle_delete_all_fw_list_entries(0);
#ifndef CONFIG_APM862xx
		apm_cle_delete_all_fw_list_entries(1);
#endif
		atomic_set(&gbl_data->avl_cnt, 0);
		break;
	case CMD_ENABLE_CLE_BR:
		printk("\nEnabling apm classifier bridge\n");
		for (i = 0; i < MAX_PORTS; i++)
			apm_preclass_switch_tree(i, CLE_PTREE_BRIDGE, 0);

		gbl_data->cle_br_enabled = 1;
		break;
	}

	return count;
}

struct file_operations apm_cle_br_driver_fops = {
	.owner = THIS_MODULE,
	.open = apm_cle_br_driver_open,
	.read = apm_cle_br_driver_read,
	.write = apm_cle_br_driver_write,
};

static void apm_cle_br_set_db(void)
{
	struct net_device *dev;
	struct apm_enet_dev_base *priv_dev;
	int core_id = apm_cle_system_id;
	int i, cle;

	memset(dbptr, 0, sizeof(dbptr));

	/* Create Result RAM Entries */
	for (cle = CLE_0; cle < MAX_CLE_ENGINE; cle++) {
		for (i = CLE_EXT_PORT0; i < CLE_MAX_PORTS; i++) {
			switch (i) {
			case CLE_EXT_PORT0:
			case CLE_EXT_PORT1:
			case CLE_EXT_PORT2:
			case CLE_EXT_PORT3:
				/* TODO Also check whether dev is a bridge port */
				if (!(dev = find_netdev(CLEBASEPORTID[cle]))) {
					if (!(dev = find_netdev(CLEBASEPORTID[cle] + 1))) {
						dbptr[cle][i].drop = 1;
						break;
					}
				}
				priv_dev = netdev_priv(dev);
				dbptr[cle][i].dstqid =
					priv_dev->qm_queues[core_id].default_rx_qid;
				dbptr[cle][i].fpsel =
					(priv_dev->qm_queues[core_id].rx_fp_pbn - 0x20);
				/* offload enabled */
				dbptr[cle][i].h0_en = 1;
				/* offload to perform */
				dbptr[cle][i].h0_fpsel = APM_BRIDGE_OFFLOAD;
				/* ingress Internal ENET port */
				dbptr[cle][i].h1_hr = 1;
				/* H1DR:H1SZ (2 bits) specifies ingress Internal ENET port */
				dbptr[cle][i].h1_dr = priv_dev->port_id >> 1;
				dbptr[cle][i].h1_sz = priv_dev->port_id & 1;
				/* egress External Non-ENET port */
				dbptr[cle][i].h0_hr = 0;
				/* H0DR:H0SZ (2 bits) specifies egress External Non-ENET port */
				dbptr[cle][i].h0_dr = i >> 1;
				dbptr[cle][i].h0_sz = i & 1;
				dbptr[cle][i].index = DBPTR_ALLOC(i);
				break;
			case CLE_INT_PORT0:
			case CLE_INT_PORT1:
#ifndef CONFIG_APM862xx
			case CLE_INT_PORT2:
			case CLE_INT_PORT3:
#endif
				if (!(dev = find_netdev(i - CLE_INT_PORT0))) {
					dbptr[cle][i].drop = 1;
					break;
				}
				priv_dev = netdev_priv(dev);
				dbptr[cle][i].dstqid =
					priv_dev->qm_queues[core_id].hw_tx_qid;
				dbptr[cle][i].fpsel =
					(priv_dev->qm_queues[core_id].hw_fp_pbn - 0x20);
				dbptr[cle][i].h0_en = 1;
				dbptr[cle][i].h0_hr = 1;
				dbptr[cle][i].h0_enqnum = QM_RSV_UNCONFIG_COMP_Q;
				dbptr[cle][i].index = DBPTR_ALLOC(i);
			}
		}
	}

	/* Program the Result RAM entries */
	apm_dbptr_alloc(CLE_ENET_0, CLE_MAX_PORTS, &dbptr[CLE_0][0]);
#ifndef CONFIG_APM862xx
	/* Program the Result RAM entries */
	apm_dbptr_alloc(CLE_ENET_2, CLE_MAX_PORTS, &dbptr[CLE_1][0]);
#endif
}

static int apm_cle_init_br(void)
{
	int rc = 0;
	int i = 0;

	if (!(gbl_data = kmalloc(sizeof(struct cle_br_gbl_data), GFP_ATOMIC))) {
		rc = -ENOMEM;
		goto exit_init_br;
	}

	memset(gbl_data, 0, sizeof(struct cle_br_gbl_data));
	atomic_set(&(gbl_data->avl_cnt), 0);

	for (i = 0; i < MAX_CLE_ENGINE; i++) {
		INIT_LIST_HEAD(&(gbl_data->cle_avl_entry_db_head[i]));
	}

	spin_lock_init(&(gbl_data->cle_br_lock));

	apm_cle_br_set_db();
#if defined(APM_CLE_TEST_BR)
	apm_br_add_test_key();
#endif
#if 0
	gbl_data->entry = create_proc_entry(APM_CLE_BR_DRIVER_NAME, 0, NULL);
	gbl_data->entry->proc_fops = &apm_cle_br_driver_fops;
#endif
	gbl_data->cle_br_enabled = 1;
#if defined(CONFIG_CLE_BR_EXT_FWD)
	memset(ext_port, 0, sizeof(ext_port));
#endif

exit_init_br:
	return rc;
}

static int __init apm_cle_br_init(void)
{
	return apm_cle_init_br();
}

static void __exit apm_cle_br_exit(void)
{
	remove_proc_entry(APM_CLE_BR_DRIVER_NAME, NULL);
	kfree(gbl_data);
}

module_init(apm_cle_br_init);
module_exit(apm_cle_br_exit);

MODULE_AUTHOR("Pranavkumar Sawargaonkar <psawargaonkar@apm.com>");
MODULE_DESCRIPTION("APM862xx SoC Classifier Bridge Driver");
MODULE_LICENSE("GPL");
